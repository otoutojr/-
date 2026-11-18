#!/usr/bin/env python3
# sqljr の自動テスト。SQLite 版の脆弱アプリを 127.0.0.1 で起動して検査する（追加の準備は不要）。
#
#   python3 -m unittest discover -s tests -v
#
# 他の DBMS で同じテストを回す場合（アプリは別途起動しておく）:
#   SQLJR_TEST_URL=http://127.0.0.1:8104 SQLJR_TEST_DBMS=MSSQL python3 -m unittest discover -s tests -v
import argparse
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SQLJR = os.path.join(ROOT, "sqljr.py")
sys.path.insert(0, ROOT)
import sqljr  # noqa: E402

EXTERNAL = os.environ.get("SQLJR_TEST_URL")
DBMS = os.environ.get("SQLJR_TEST_DBMS", "SQLite")
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port):
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sqljr_test_")
        cls.proc = None
        if EXTERNAL:
            cls.url = EXTERNAL.rstrip("/")
            return
        port = free_port()
        env = dict(os.environ, VULN_SQLITE_PATH=os.path.join(cls.tmp, "vuln.db"))
        cls.proc = subprocess.Popen([sys.executable, os.path.join(HERE, "vuln_app.py"), "sqlite", str(port)], env=env)
        cls.url = "http://127.0.0.1:%d" % port
        wait_port(port)

    @classmethod
    def tearDownClass(cls):
        if cls.proc:
            cls.proc.terminate()
            cls.proc.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def get(self, path):
        return NO_PROXY.open(self.url + path, timeout=60).read().decode()

    def table(self, name):
        return json.loads(self.get("/dump?t=" + name))

    def scan(self, path, *args, env=None):
        """sqljr を実行し、-o の JSON と標準出力を返す。"""
        out = os.path.join(self.tmp, "out.json")
        cmd = [sys.executable, SQLJR, "-u", self.url + path, "-o", out, "--sleep", "2"] + list(args)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(out, encoding="utf-8") as f:
            return json.load(f), p.stdout

    def point(self, path, *args):
        res, _ = self.scan(path, *args)
        return res["points"][0]


class Detection(Base):
    def test_numeric_error_union(self):
        pt = self.point("/item?id=1", "-t", "EBU")
        self.assertEqual(pt["dbms"], DBMS)
        self.assertEqual(pt["confidence"], "confirmed")
        self.assertTrue({"ERROR", "BOOL", "UNION"} <= set(pt["techniques"]))
        self.assertEqual(pt["boundary"], {"prefix": "", "suffix": "", "op": "AND"})
        self.assertEqual(pt["union"]["cols"], 3)
        self.assertIsNotNone(pt["union"]["vis"])

    def test_string_without_error_text(self):
        pt = self.point("/user?name=alice", "-t", "EBU")
        self.assertEqual(pt["dbms"], DBMS)                 # エラー文が無くても固有の真式で特定できる
        self.assertTrue({"QUOTE", "BOOL", "UNION"} <= set(pt["techniques"]))
        self.assertEqual(pt["boundary"]["prefix"], "'")
        self.assertEqual(pt["union"]["cols"], 2)

    def test_parenthesis_context(self):
        pt = self.point("/search?q=a", "-t", "BU")
        self.assertEqual(pt["boundary"]["prefix"], "')")
        self.assertEqual(pt["union"]["cols"], 1)

    def test_blind_on_dynamic_page(self):
        pt = self.point("/blind?id=1", "-t", "B")
        self.assertIn("BOOL", pt["techniques"])

    def test_json_cookie_path_points(self):
        self.assertIn("BOOL", self.point("/api", "-d", '{"id":1}', "-t", "B", "--risk", "2")["techniques"])
        self.assertIn("BOOL", self.point("/cookie", "-c", "track=apple", "--level", "2", "-t", "B")["techniques"])
        pt = self.point("/path/1*", "-t", "B")
        self.assertEqual(pt["where"], "PATH")
        self.assertIn("BOOL", pt["techniques"])

    def test_numeric_post_without_bare_and(self):
        """POST の数値は、既定では「<値>-(CASE ... THEN 0 ...)」の形で調べる（素の AND は送らない）。"""
        pt = self.point("/api", "-d", '{"id":1}', "-t", "B")
        self.assertIn("BOOL", pt["techniques"])
        self.assertEqual(pt["boundary"]["op"], "")
        self.assertTrue(pt["boundary"]["prefix"].startswith("-(CASE"))

    def test_order_by_context(self):
        """ORDER BY 句への注入。SQLite は「複数行の副問い合わせ」がエラーにならないので専用の式が要る。"""
        pt = self.point("/sort?by=name", "-t", "B")
        self.assertIn("BOOL", pt["techniques"])
        self.assertEqual(pt["boundary"]["op"], "")

    def test_union_on_list_that_changes_order(self):
        """ORDER BY 2 で行の並びが変わる一覧。並びが変わっただけで「失敗」と数えると列数が 1 になる。"""
        pt = self.point("/list?cat=1", "-t", "BU")
        self.assertEqual(pt["union"]["cols"], 3)
        self.assertTrue(pt["union"]["verified"])
        self.assertIsNotNone(pt["union"]["vis"])

    def test_union_when_value_matches_no_row(self):
        """元の値が 1 行も返さない文字列。AND では真偽が分からないが、UNION までは進める。"""
        pt = self.point("/user?name=zzz", "-t", "EBU")
        self.assertIn("UNION", pt["techniques"])
        self.assertEqual(pt["union"]["cols"], 2)
        self.assertIsNotNone(pt["union"]["vis"])

    def test_cookie_that_is_not_url_decoded(self):
        pt = self.point("/rawcookie", "-c", "track=apple", "--level", "2", "-t", "EB")
        self.assertIn("BOOL", pt["techniques"])
        self.assertTrue(pt["cookie_raw"])

    def test_login_that_sets_a_session_cookie(self):
        """OR 型が通ると Set-Cookie が返る。それを持ち回すと以降が全部「ログイン済み」になり検出できなくなる。"""
        pt = self.point("/slogin", "-d", "user=a&pass=b", "-p", "user", "-t", "EB", "--risk", "2")
        self.assertIn("BOOL", pt["techniques"])
        self.assertEqual(pt["boundary"]["op"], "OR")

    def test_time_based(self):
        pt = self.point("/blind?id=1", "-t", "T")
        self.assertIn("TIME", pt["techniques"])
        self.assertEqual(pt["dbms"], DBMS)

    def test_insert_context_by_time(self):
        """INSERT の値に入る User-Agent。エラーも応答差も無いので time（連結で埋め込む形）だけが頼り。"""
        res, _ = self.scan("/log", "--level", "3", "-p", "User-Agent", "-t", "T")
        pt = res["points"][0]
        if DBMS == "MSSQL":
            self.skipTest("MSSQL は式の中で遅延できない")
        self.assertIn("TIME", pt["techniques"])
        self.assertEqual(pt["boundary"]["op"], "")       # 式コンテキスト
        # 提示された time blind のコマンドは、条件が真なら遅く、偽なら速い
        sug = [s for s in pt["suggestions"] if "time blind" in s["title"]]
        self.assertTrue(sug)
        if not shutil.which("curl"):
            return
        took = {}
        for name, cond in (("true", ">0"), ("false", ">1114110")):
            cmd = sug[0]["command"].replace(">77", cond)
            self.assertNotEqual(cmd, sug[0]["command"])
            t0 = time.time()
            subprocess.run(shlex.split(cmd) + ["--noproxy", "*"], capture_output=True, timeout=120)
            took[name] = time.time() - t0
        self.assertLess(took["false"], 0.4, took)
        self.assertGreater(took["true"], took["false"] + 0.4, took)

    def test_evidence_is_recorded(self):
        pt = self.point("/item?id=1", "-t", "E")
        ev = pt["hits"][0]["evidence"]
        self.assertIn("url", ev["request"])
        self.assertTrue(ev["snippet"])
        self.assertTrue(ev["time"])


class NoFalsePositive(Base):
    def test_parameterized_query(self):
        for path in ("/safe?id=1", "/safe?id=5"):         # 5 は「見つからない」ページで入力を反射する
            pt = self.point(path)
            self.assertFalse(pt["vulnerable"], path)

    def test_waf_block_is_not_a_finding(self):
        res, out = self.scan("/waf?id=1", "-t", "EBU")
        self.assertFalse(res["points"][0]["vulnerable"])
        self.assertIn("WAF", out)                          # 遮断されたことは知らせる

    def test_waf_that_blocks_only_tautologies(self):
        """1=1 だけ 403 にする WAF。「真が 403・偽が 200」は SQL の真偽による差ではない。"""
        self.assertFalse(self.point("/taut?id=1", "-t", "EB")["vulnerable"])

    def test_length_limit_is_not_union(self):
        """長い入力を 400 で弾くだけの安全なパラメータ。ORDER BY n の成否に見える挙動だけで UNION と言わない。"""
        self.assertFalse(self.point("/lookup?code=test", "-t", "U")["vulnerable"])

    def test_page_with_random_content(self):
        """入力を無視し、毎回ちがう内容を返すページ。"""
        for _ in range(4):
            self.assertFalse(self.point("/noise?id=1", "-t", "BU")["vulnerable"])

    def test_generic_error_text_is_only_tentative(self):
        res, out = self.scan("/parser?q=apple", "-t", "EB")
        pt = res["points"][0]
        self.assertEqual(pt["confidence"], "tentative")
        self.assertIn("未確定", out)
        self.assertNotIn("[+] 注入点あり", out)

    def test_rate_limited_from_the_start(self):
        res, out = self.scan("/always429?id=1", "-t", "E")
        self.assertFalse(res["points"][0]["vulnerable"])
        self.assertIn("元のリクエスト自体が HTTP 429", out)


class Safety(Base):
    """既定（--risk 1）で書き込み系のエンドポイントを検査しても、狙った行以外には触れない。"""

    def unchanged(self, table, before, allowed):
        after = {r[0]: r for r in self.table(table)}
        for r in before:
            if r[0] not in allowed:
                self.assertEqual(after.get(r[0]), r, "%s の行 %r が変わった" % (table, r[0]))
        self.assertEqual(set(after) - {r[0] for r in before}, set())

    def check(self, path, data, table, allowed, *args):
        self.get("/reset")
        before = self.table(table)
        res, out = self.scan(path, "-d", data, *args)
        self.unchanged(table, before, allowed)
        self.get("/reset")
        return res, out

    def test_login_needs_risk2_for_or(self):
        pt = self.point("/login", "-d", "user=a&pass=b", "-p", "user", "-t", "EB")
        self.assertNotIn("OR", [(pt["boundary"] or {}).get("op")])
        self.assertIn("QUOTE", pt["techniques"])
        pt = self.point("/login", "-d", "user=a&pass=b", "-p", "user", "-t", "EB", "--risk", "2")
        self.assertEqual(pt["boundary"]["op"], "OR")

    def test_update_set_value(self):
        res, _ = self.check("/upd", "note=hello", "notes", [2])
        self.assertTrue(res["points"][0]["vulnerable"])

    def test_update_on_multi_statement_driver(self):
        """「';」で文が切れると、複数文を実行する実装では WHERE の無い UPDATE が走る。"""
        self.check("/updmulti", "note=hello", "notes", [2])

    def test_update_where_string(self):
        """MySQL では || が OR、+ が加算。連結のつもりの式が「全行に一致」にならないこと。"""
        self.check("/resetpw", "user=alice&newpw=N3w", "users", [2])

    def test_delete_where_string(self):
        self.check("/logout", "token=tok-alice", "sessions", ["tok-alice"])

    def test_delete_in_list(self):
        """IN (<値> AND 1=1) は IN (1) になり、別の ID の行が消える。"""
        self.check("/delin", "ids=3", "notes", [3])

    def test_delete_where_number(self):
        self.check("/delnum", "id=3", "notes", [3])

    def test_no_tail_cutting_payloads_on_post_by_default(self):
        log = os.path.join(self.tmp, "req.jsonl")
        for path, data in (("/upd", "note=hello"), ("/delnum", "id=3"), ("/resetpw", "user=alice&newpw=x")):
            self.scan(path, "-d", data, "--log", log)
        self.get("/reset")
        with open(log, encoding="utf-8") as f:
            payloads = [json.loads(l)["payload"] for l in f]
        self.assertGreater(len(payloads), 100)
        for p in payloads:
            self.assertFalse(p.endswith("-- -") or p.endswith("#"), p)     # 後続を消すコメント
            self.assertNotIn(";", p)                                        # 文の区切り
            self.assertNotIn("UNION ALL SELECT NULL", p)
            self.assertNotIn(" OR ", p)
            self.assertNotIn("ORDER BY", p)
            self.assertFalse(p.startswith(" AND "), p)                      # 素の AND（IN の並びで別の ID になる）

    def test_no_tail_cutting_suggestions_on_post_by_default(self):
        """ツールが送らなかった種類のペイロード（' OR 1=1-- - など）を「次の一手」として勧めない。"""
        res, out = self.scan("/resetpw", "-d", "user=alice&newpw=x")
        self.get("/reset")
        for pt in res["points"]:
            self.assertTrue(pt["vulnerable"])
            for s in pt["suggestions"]:
                self.assertNotIn("認証バイパス", s["title"])
                self.assertNotIn("OR 1=1", s["value"])
                self.assertFalse(s["value"].endswith("-- -"), s["value"])
        self.assertIn("--risk 2 で再実行", out)


class Suggestions(Base):
    @unittest.skipUnless(shutil.which("curl"), "curl が必要")
    def test_suggested_command_really_works(self):
        res, _ = self.scan("/item?id=1", "-t", "EBU")
        sug = [s for s in res["points"][0]["suggestions"] if "テーブル一覧" in s["title"] and "UNION" in s["title"]]
        self.assertTrue(sug)
        out = subprocess.run(shlex.split(sug[0]["command"]) + ["--noproxy", "*"],
                             capture_output=True, text=True, timeout=30).stdout
        self.assertIn("users", out.lower())


class _Recorder(BaseHTTPRequestHandler):
    """絶対 URI の GET を中継し、通ったことを記録するだけの最小プロキシ。"""
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).seen.append(self.path)
        try:
            body = NO_PROXY.open(self.path, timeout=30).read()
            code = 200
        except urllib.error.HTTPError as e:
            body, code = e.read(), e.code
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Proxy(Base):
    def test_proxy_option_wins_over_environment(self):
        """環境変数 http_proxy があっても、--proxy で指定した方を通る。"""
        _Recorder.seen = []
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            env = {k: v for k, v in os.environ.items() if k.lower() not in ("no_proxy", "https_proxy", "all_proxy")}
            env["http_proxy"] = env["HTTP_PROXY"] = "http://127.0.0.1:9"       # 誰も待ち受けていない
            res, _ = self.scan("/item?id=1", "-t", "E", "--proxy", "http://127.0.0.1:%d" % srv.server_address[1],
                               env=env)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertTrue(res["points"][0]["vulnerable"])
        self.assertGreater(len(_Recorder.seen), 5)


class Units(unittest.TestCase):
    def target(self, url, level=1, marker="*", **kw):
        sqljr.CFG.marker, sqljr.CFG.level, sqljr.CFG.tamper = marker, level, []
        ns = argparse.Namespace(url=url, request=kw.get("request"), https=False, method=kw.get("method"),
                                data=kw.get("data"), cookie=kw.get("cookie"), header=kw.get("header"))
        sqljr.T = sqljr.build_target(ns)
        return sqljr.T, sqljr.build_points(sqljr.T, kw.get("param"))

    def test_marker_position(self):
        t, pts = self.target("http://x/a?id=1*abc&q=z", header=["Accept: */*"])   # */* をマーカーと誤認しない
        self.assertEqual(len(pts), 1)
        self.assertEqual((pts[0]["name"], pts[0]["pre"], pts[0]["post"]), ("id", "1", "abc"))
        self.assertEqual(sqljr.build(pts[0], "'")[1], "http://x/a?id=1%27abc&q=z")
        self.assertEqual(sqljr.build(pts[0], "'")[2]["Accept"], "*/*")

    def test_encoded_asterisk_is_data_not_marker(self):
        t, pts = self.target("http://x/i?id=1&glob=%2A.txt")
        self.assertFalse(t.marker_mode)
        self.assertEqual([p["name"] for p in pts], ["id", "glob"])
        self.assertEqual(sqljr.build(pts[0], "'")[1], "http://x/i?id=1%27&glob=%2A.txt")

    def test_other_parameters_are_sent_as_given(self):
        # ;jsessionid、UTF-8 でないバイト列（Shift_JIS）、値の無いパラメータを変えずに送る
        t, pts = self.target("http://x/app/page;jsessionid=ABC?q=%93%FA%96%7B&flag&id=1", param="id")
        self.assertEqual(sqljr.build(pts[0], "'")[1], "http://x/app/page;jsessionid=ABC?q=%93%FA%96%7B&flag&id=1%27")
        t, pts = self.target("http://x/i?q=%93%FA&id=1", param="q")             # 検査する値そのものが Shift_JIS
        self.assertEqual(sqljr.build(pts[0], "'")[1], "http://x/i?q=%93%FA%27&id=1")

    def test_header_names_are_case_insensitive(self):
        t, pts = self.target("http://x/i", level=3, header=["referer: http://x/from", "x-forwarded-for: 10.9.8.7"])
        names = sorted(k.lower() for k in t.headers)
        self.assertEqual(names, sorted(set(names)))                              # 大文字小文字違いで重複しない
        pt = [p for p in pts if p["name"] == "x-forwarded-for"][0]
        self.assertEqual(sqljr.build(pt, "'")[2]["x-forwarded-for"], "10.9.8.7'")

    def test_body_kinds(self):
        t, pts = self.target("http://x/", data='<?xml version="1.0" encoding="UTF-8"?><r><id>1*</id></r>')
        self.assertEqual(t.kind, "raw")                                          # '=' があるだけでフォーム扱いしない
        self.assertEqual(sqljr.build(pts[0], "'")[3], '<?xml version="1.0" encoding="UTF-8"?><r><id>1\'</id></r>')
        self.assertEqual(t.headers["Content-Type"], "application/xml")
        t, pts = self.target("http://x/", data='{"id":1*,"q":"a=b"}', header=["Content-Type: application/json"])
        self.assertEqual(t.kind, "raw")                                          # JSON として読めなくても崩さない
        self.assertEqual(sqljr.build(pts[0], "'")[3], '{"id":1\',"q":"a=b"}')
        t, pts = self.target("http://x/", data="user=a&pass=b")
        self.assertEqual((t.kind, t.method), ("form", "POST"))
        t, pts = self.target("http://x/", data='{"id":1,"fields":"x"}')
        self.assertEqual(t.kind, "json")

    def test_cookie_is_not_decoded(self):
        self.assertEqual(sqljr.parse_cookie("a=b+c%3D; t=x==")[0], ("a", "b+c%3D"))
        self.assertEqual(sqljr.parse_cookie("a=b+c%3D; t=x==")[1], ("t", "x=="))

    def test_cookie_payload_encodings(self):
        t, pts = self.target("http://x/", level=2, cookie="track=apple; s=a+b==")
        self.assertEqual(sqljr.build(pts[0], "' AND 1=1")[2]["Cookie"], "track=apple'%20AND%201=1; s=a+b==")
        self.assertEqual(sqljr.build(dict(pts[0], raw=True), "' AND 1=1;")[2]["Cookie"],
                         "track=apple' AND 1=1%3B; s=a+b==")

    def test_curl_command_matches_the_request(self):
        t, pts = self.target("http://x/v[1]/it em/{a}?id=1&sort by=name", param="id")
        cmd = shlex.split(sqljr.curl_cmd(pts[0], "' AND 1=1-- -"))
        self.assertIn("-g", cmd)                                                 # [1] を curl に展開させない
        self.assertIn("http://x/v[1]/it%20em/%7Ba%7D", cmd)                      # requests が送るのと同じ形
        self.assertIn("id=1' AND 1=1-- -", cmd)                                  # 値は編集しやすい形のまま
        self.assertIn("sort+by=name", cmd)                                       # 名前は先にエンコード
        self.assertEqual(cmd[cmd.index("-A") + 1], sqljr.DEFAULT_UA)             # 既定の UA も明示

    def test_reflection_is_stripped(self):
        self.assertEqual(sqljr.strip_reflect("not found: 1&#x27; AND 1=1", "' AND 1=1"), "not found: 1")

    def test_space2comment_keeps_string_literals(self):
        f = sqljr.TAMPERS["space2comment"]
        self.assertEqual(f("' AND 1=1-- -"), "'/**/AND/**/1=1-- -")
        self.assertEqual(f("1;EXEC sp_configure 'show advanced options',1-- -"),
                         "1;EXEC/**/sp_configure/**/'show advanced options',1-- -")

    def test_error_signatures(self):
        cases = {
            "MySQL": ["You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server",
                      "Subquery returns more than 1 row"],
            "MSSQL": ["Unclosed quotation mark after the character string ''.", "Invalid column name 'x'."],
            "PostgreSQL": ['ERROR:  syntax error at or near "\'"',
                           "ERROR:  more than one row returned by a subquery used as an expression"],
            "Oracle": ["ORA-01756: quoted string not properly terminated"],
            "SQLite": ['sqlite3.OperationalError: near "\'": syntax error', "no such column: nosuchcol"],
        }
        for db, texts in cases.items():
            for text in texts:
                self.assertEqual(sqljr.detect_dbs(text)[0], db, text)
        for text in ('<footer>Powered by PostgreSQL</footer><div class="error">Invalid e-mail address</div>',
                     "Warning: this page mentions mysql_real_escape_string() as deprecated", "Login failed"):
            self.assertEqual(sqljr.detect_dbs(text), [], text)

    def test_request_file(self):
        path = os.path.join(tempfile.gettempdir(), "sqljr_req_test.txt")
        with open(path, "wb") as f:
            f.write(b"POST /login HTTP/1.1\r\nHost: 127.0.0.1:9\r\nCookie: s=1\r\nContent-Length: 13\r\n\r\nuser=a&pass=b\r\n")
        try:
            method, url, headers, cookie, body = sqljr.parse_request_file(path, False)
        finally:
            os.remove(path)
        self.assertEqual((method, url, cookie, body), ("POST", "http://127.0.0.1:9/login", "s=1", "user=a&pass=b"))
        self.assertNotIn("Content-Length", headers)

    def test_request_file_keeps_multipart_line_endings(self):
        body = b'--B\r\nContent-Disposition: form-data; name="id"\r\n\r\n1*\r\n--B--\r\n'
        path = os.path.join(tempfile.gettempdir(), "sqljr_req_test_mp.txt")
        with open(path, "wb") as f:
            f.write(b"POST /up HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Type: multipart/form-data; boundary=B\r\n\r\n" + body)
        try:
            t, pts = self.target(None, request=path)
        finally:
            os.remove(path)
        self.assertEqual(t.kind, "raw")
        self.assertEqual(sqljr.build(pts[0], "'")[3].encode(), body.replace(b"1*", b"1'"))


if __name__ == "__main__":
    unittest.main()
