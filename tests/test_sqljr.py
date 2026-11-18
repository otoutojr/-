#!/usr/bin/env python3
# sqljr の自動テスト。SQLite 版の脆弱アプリを 127.0.0.1 で起動して検査する（追加の準備は不要）。
#
#   python3 -m unittest discover -s tests -v
#
# 他の DBMS で同じテストを回す場合（アプリは別途起動しておく）:
#   SQLJR_TEST_URL=http://127.0.0.1:8104 SQLJR_TEST_DBMS=MSSQL python3 -m unittest discover -s tests -v
import json
import os
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SQLJR = os.path.join(ROOT, "sqljr.py")
sys.path.insert(0, ROOT)
import sqljr  # noqa: E402

EXTERNAL = os.environ.get("SQLJR_TEST_URL")
DBMS = os.environ.get("SQLJR_TEST_DBMS", "SQLite")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sqljr_test_")
        cls.proc = None
        cls.db = None
        if EXTERNAL:
            cls.url = EXTERNAL.rstrip("/")
            return
        port = free_port()
        cls.db = os.path.join(cls.tmp, "vuln.db")
        env = dict(os.environ, VULN_SQLITE_PATH=cls.db)
        cls.proc = subprocess.Popen([sys.executable, os.path.join(HERE, "vuln_app.py"), "sqlite", str(port)], env=env)
        cls.url = "http://127.0.0.1:%d" % port
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        if cls.proc:
            cls.proc.terminate()
            cls.proc.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def scan(self, path, *args):
        """sqljr を実行し、-o の JSON と標準出力を返す。"""
        out = os.path.join(self.tmp, "out.json")
        cmd = [sys.executable, SQLJR, "-u", self.url + path, "-o", out, "--sleep", "2"] + list(args)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
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

    def test_time_based(self):
        pt = self.point("/blind?id=1", "-t", "T")
        self.assertIn("TIME", pt["techniques"])
        self.assertEqual(pt["dbms"], DBMS)

    def test_insert_context_by_time(self):
        """INSERT の値に入る User-Agent。エラーも応答差も無いので time（連結で埋め込む形）だけが頼り。"""
        pt = self.point("/log", "--level", "3", "-p", "User-Agent", "-t", "T")
        if DBMS == "MSSQL":
            self.skipTest("MSSQL は式の中で遅延できない")
        self.assertIn("TIME", pt["techniques"])
        self.assertEqual(pt["boundary"]["op"], "")       # 式コンテキスト

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


class Safety(Base):
    def test_login_needs_risk2_for_or(self):
        pt = self.point("/login", "-d", "user=a&pass=b", "-p", "user", "-t", "EB")
        self.assertNotIn("OR", [(pt["boundary"] or {}).get("op")])
        self.assertIn("QUOTE", pt["techniques"])
        pt = self.point("/login", "-d", "user=a&pass=b", "-p", "user", "-t", "EB", "--risk", "2")
        self.assertEqual(pt["boundary"]["op"], "OR")

    def test_update_endpoint_is_not_corrupted(self):
        """UPDATE ... SET body='<入力>' WHERE id=2 を既定の risk で検査しても、他の行を書き換えない。"""
        if not self.db:
            self.skipTest("SQLite のファイルを直接見るテスト")
        pt = self.point("/upd", "-d", "note=hello")
        self.assertTrue(pt["vulnerable"])
        con = sqlite3.connect(self.db)
        try:
            self.assertEqual(con.execute("SELECT body FROM notes WHERE id=1").fetchone()[0], "first")
        finally:
            con.close()

    def test_no_comment_payloads_on_post_by_default(self):
        log = os.path.join(self.tmp, "req.jsonl")
        self.scan("/upd", "-d", "note=hello", "--log", log)
        with open(log, encoding="utf-8") as f:
            bodies = [json.loads(l)["body"] or "" for l in f]
        self.assertTrue(bodies)
        for b in bodies:
            self.assertNotIn("--+-", b)                    # "-- -" を URL エンコードした形
            self.assertNotIn("UNION+ALL", b)
            self.assertNotIn("+OR+", b)


class Suggestions(Base):
    @unittest.skipUnless(shutil.which("curl"), "curl が必要")
    def test_suggested_command_really_works(self):
        res, _ = self.scan("/item?id=1", "-t", "EBU")
        sug = [s for s in res["points"][0]["suggestions"] if "テーブル一覧" in s["title"] and "UNION" in s["title"]]
        self.assertTrue(sug)
        out = subprocess.run(shlex.split(sug[0]["command"]), capture_output=True, text=True, timeout=30).stdout
        self.assertIn("users", out.lower())


class Units(unittest.TestCase):
    def test_marker_position(self):
        sqljr.CFG.marker, sqljr.CFG.level = "*", 1
        t = sqljr.Target()
        t.url, t.query = "http://x/a", [("id", "1*abc"), ("q", "z")]
        t.headers = {"Accept": "*/*"}                      # */* をマーカーと誤認しない
        pts = sqljr.build_points(t, None)
        self.assertEqual(len(pts), 1)
        self.assertEqual((pts[0]["name"], pts[0]["pre"], pts[0]["post"]), ("id", "1", "abc"))

    def test_cookie_is_not_decoded(self):
        self.assertEqual(sqljr.parse_cookie("a=b+c%3D; t=x==")[0], ("a", "b+c%3D"))
        self.assertEqual(sqljr.parse_cookie("a=b+c%3D; t=x==")[1], ("t", "x=="))

    def test_reflection_is_stripped(self):
        self.assertEqual(sqljr.strip_reflect("not found: 1&#x27; AND 1=1", "' AND 1=1"), "not found: 1")

    def test_error_signatures(self):
        cases = {
            "MySQL": "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server",
            "MSSQL": "Unclosed quotation mark after the character string ''.",
            "PostgreSQL": 'ERROR:  syntax error at or near "\'"',
            "Oracle": "ORA-01756: quoted string not properly terminated",
            "SQLite": 'sqlite3.OperationalError: near "\'": syntax error',
        }
        for db, text in cases.items():
            self.assertEqual(sqljr.detect_dbs(text)[0], db)

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


if __name__ == "__main__":
    unittest.main()
