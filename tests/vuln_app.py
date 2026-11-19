#!/usr/bin/env python3
# sqljr のテスト用に「わざと」SQL injection を作り込んだアプリ。
# 127.0.0.1 でのみ待ち受ける。検証以外の用途で公開しないこと。
#
#   python3 tests/vuln_app.py sqlite 8101          # 追加の準備なしで動く
#   python3 tests/vuln_app.py pg|mysql|mssql|oracle 8102
#
# sqlite 以外は接続先を環境変数で指定する（既定値は README を参照）:
#   VULN_PG_DSN / VULN_MYSQL_SOCKET / VULN_MSSQL_* / VULN_ORACLE_*
import html
import json
import os
import random
import re
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

KIND = sys.argv[1] if len(sys.argv) > 1 else "sqlite"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8101
SQLITE_PATH = os.environ.get("VULN_SQLITE_PATH") or os.path.join(tempfile.gettempdir(), "sqljr_vuln_%d.db" % PORT)

TABLES = ["items", "users", "logs", "notes", "products", "sessions"]
SETUP = ["DROP TABLE IF EXISTS %s" % t for t in TABLES] + [
    "CREATE TABLE items (id INT, name VARCHAR(50), price INT)",
    "CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50))",
    "CREATE TABLE logs (a VARCHAR(400), b VARCHAR(400))",
    "CREATE TABLE notes (id INT, body VARCHAR(400))",
    "CREATE TABLE products (id INT, name VARCHAR(50), price INT, cat INT)",
    "CREATE TABLE sessions (token VARCHAR(50), owner INT)",
    "INSERT INTO items VALUES (1,'apple',100),(2,'banana',200),(3,'cherry',300)",
    "INSERT INTO users VALUES (1,'admin','s3cret'),(2,'alice','pw'),(3,'bob','hunter2'),(4,'carol','qwerty')",
    "INSERT INTO notes VALUES (1,'first'),(2,'second'),(3,'third'),(4,'fourth'),(5,'fifth')",
    # 列ごとに並び順が違う一覧（ORDER BY 1 / 2 / 3 で行の順番が変わる）
    "INSERT INTO products VALUES (1,'pear',300,1),(2,'apple',100,1),(3,'melon',900,1),(4,'kiwi',50,2)",
    "INSERT INTO sessions VALUES ('tok-admin',1),('tok-alice',2),('tok-bob',3)",
]
ORDER = {"items": "id", "users": "id", "notes": "id", "products": "id", "sessions": "token", "logs": "a"}


def connect():
    if KIND == "sqlite":
        import sqlite3
        return sqlite3.connect(SQLITE_PATH)
    if KIND == "pg":
        import psycopg2
        c = psycopg2.connect(os.environ.get("VULN_PG_DSN", "host=127.0.0.1 port=5433 user=postgres dbname=postgres"))
        c.autocommit = True
        return c
    if KIND == "mysql":
        import pymysql
        return pymysql.connect(unix_socket=os.environ.get("VULN_MYSQL_SOCKET", "/run/mysqld/mysqld.sock"),
                               user=os.environ.get("VULN_MYSQL_USER", "root"),
                               password=os.environ.get("VULN_MYSQL_PASSWORD", ""),
                               database=os.environ.get("VULN_MYSQL_DB", "t"), autocommit=True)
    if KIND == "mssql":
        import pymssql
        return pymssql.connect(server=os.environ.get("VULN_MSSQL_HOST", "127.0.0.1"),
                               user=os.environ.get("VULN_MSSQL_USER", "sa"),
                               password=os.environ["VULN_MSSQL_PASSWORD"],
                               database=os.environ.get("VULN_MSSQL_DB", "tempdb"), autocommit=True)
    if KIND == "oracle":
        import oracledb
        c = oracledb.connect(user=os.environ.get("VULN_ORACLE_USER", "system"),
                             password=os.environ["VULN_ORACLE_PASSWORD"],
                             dsn=os.environ.get("VULN_ORACLE_DSN", "127.0.0.1:1521/FREEPDB1"))
        c.autocommit = True
        return c
    sys.exit("unknown backend: %s" % KIND)


PH = {"sqlite": "?", "oracle": ":1"}.get(KIND, "%s")      # プレースホルダ（安全なエンドポイント用）


def q(sql, args=None):
    c = connect()
    try:
        cur = c.cursor()
        if args is None:
            cur.execute(sql)
        else:
            cur.execute(sql, args)
        rows = cur.fetchall() if cur.description else []
        c.commit()
        return rows
    finally:
        c.close()


def q_multi(sql):
    """「; で区切った先頭の文は実行してしまう」実装のまね（PHP の PDO::query / SQLite3::exec、MySQL の multi_query）。
       sqlite と mysql だけ。ほかの DBMS は文全体を構文エラーとして拒否するので通常の実行と同じ。"""
    if KIND == "sqlite":
        c = connect()
        try:
            c.executescript(sql)
        finally:
            c.close()
        return []
    if KIND == "mysql":
        import pymysql
        from pymysql.constants import CLIENT
        c = pymysql.connect(unix_socket=os.environ.get("VULN_MYSQL_SOCKET", "/run/mysqld/mysqld.sock"),
                            user=os.environ.get("VULN_MYSQL_USER", "root"),
                            password=os.environ.get("VULN_MYSQL_PASSWORD", ""),
                            database=os.environ.get("VULN_MYSQL_DB", "t"), autocommit=True,
                            client_flag=CLIENT.MULTI_STATEMENTS)
        try:
            c.cursor().execute(sql)
        finally:
            c.close()
        return []
    return q(sql)


def setup():
    for stmt in SETUP:
        if KIND == "oracle" and stmt.startswith("DROP"):
            try:
                q(stmt.replace(" IF EXISTS", ""))
            except Exception:
                pass
        elif KIND == "oracle" and stmt.startswith("INSERT") and "),(" in stmt:
            head, _, vals = stmt.partition(" VALUES ")
            for v in vals[1:-1].split("),("):          # 古い Oracle は複数行の VALUES を書けない
                q("%s VALUES (%s)" % (head, v))
        else:
            q(stmt)


setup()
SESSIONS = set()            # /slogin が発行したセッション Cookie


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def out(self, code, body, loc=None, cookie=None, retry=None):
        b = body.encode()
        self.send_response(code)
        if loc:
            self.send_header("Location", loc)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if retry is not None:
            self.send_header("Retry-After", str(retry))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def page(self, inner):
        return "<html><body>\n<h1>shop</h1>\n<div>%s</div>\n<p>footer</p>\n</body></html>" % inner

    def handle_req(self, body=None):
        pr = urlparse(self.path)
        g = {k: v[0] for k, v in parse_qs(pr.query, keep_blank_values=True).items()}
        f = {k: v[0] for k, v in parse_qs(body or "", keep_blank_values=True).items()}
        p = pr.path
        try:
            if p == "/item":        # 数値・エラー文を表示
                try:
                    rows = q("SELECT id,name,price FROM items WHERE id=" + g.get("id", ""))
                except Exception as e:
                    return self.out(200, self.page("DB error: %s.%s: %s" % (type(e).__module__, type(e).__name__, e)))
                return self.out(200, self.page("".join("<p>%s: %s yen</p>" % (r[1], r[2]) for r in rows) or "no item"))
            if p == "/user":        # 文字列・エラーは 500 のみ
                rows = q("SELECT id,username FROM users WHERE username='%s'" % g.get("name", ""))
                return self.out(200, self.page("".join("<p>user %s</p>" % r[1] for r in rows) or "no user"))
            if p == "/search":      # 括弧付き・後ろに ORDER BY・エラー握り潰し
                try:
                    rows = q("SELECT name FROM items WHERE (name LIKE '%%%s%%') ORDER BY name" % g.get("q", ""))
                except Exception:
                    rows = []
                return self.out(200, self.page("".join("<li>%s</li>" % r[0] for r in rows) or "nothing"))
            if p == "/blind":       # 数値・エラー握り潰し・毎回変わるトークン
                try:
                    rows = q("SELECT id FROM items WHERE id=" + g.get("id", ""))
                except Exception:
                    rows = []
                tok = "%032x" % random.getrandbits(128)
                return self.out(200, self.page("<input name=csrf value=%s>\n<p>%s</p>"
                                               % (tok, "exists" if rows else "missing")))
            if p == "/multiline":   # 改行をまたぐ SQL: 行コメントでは後ろを消せない
                rows = q("SELECT id,username FROM users WHERE username='%s'\n AND id > 0" % g.get("name", ""))
                return self.out(200, self.page("".join("<p>user %s</p>" % r[1] for r in rows) or "no user"))
            if p == "/sort":        # ORDER BY 句への注入
                rows = q("SELECT name FROM items ORDER BY " + g.get("by", "name"))
                return self.out(200, self.page("".join("<li>%s</li>" % r[0] for r in rows)))
            if p == "/reg":         # INSERT の文字列値
                q("INSERT INTO logs (a,b) VALUES ('%s','%s')" % (f.get("name", ""), f.get("mail", "")))
                return self.out(200, self.page("registered"))
            if p == "/upd":         # UPDATE の文字列値
                q("UPDATE notes SET body='%s' WHERE id=2" % f.get("note", ""))
                return self.out(200, self.page("saved"))
            if p == "/log":         # User-Agent を INSERT。エラー握り潰し（time でしか分からない）
                try:
                    q("INSERT INTO logs (a,b) VALUES ('%s','x')" % self.headers.get("User-Agent", ""))
                except Exception:
                    pass
                return self.out(200, self.page("ok"))
            if p == "/safe":        # 安全（プレースホルダ）・入力を反射
                q("SELECT name FROM items WHERE name=" + PH, (g.get("id", ""),))
                if g.get("id") == "1":
                    return self.out(200, self.page("item one"))
                return self.out(200, self.page("not found: %s" % html.escape(g.get("id", ""))))
            if p == "/login":       # 302 で成功を返すログイン
                try:
                    rows = q("SELECT id FROM users WHERE username='%s' AND password='%s'"
                             % (f.get("user", ""), f.get("pass", "")))
                except Exception:
                    return self.out(500, "Internal Server Error")
                return self.out(302, "", "/home") if rows else self.out(200, self.page("Login failed"))
            if p == "/api":         # JSON ボディ
                j = json.loads(body or "{}")
                try:
                    rows = q("SELECT name FROM items WHERE id=%s" % j.get("id"))
                except Exception:
                    return self.out(500, '{"error":"internal"}')
                return self.out(200, json.dumps({"items": [r[0] for r in rows]}))
            if p == "/cookie":
                ck = dict(x.strip().split("=", 1) for x in self.headers.get("Cookie", "").split(";") if "=" in x)
                rows = q("SELECT name FROM items WHERE name='%s'" % unquote(ck.get("track", "")))
                return self.out(200, self.page("known" if rows else "unknown"))
            if p == "/ua":
                rows = q("SELECT name FROM items WHERE name='%s'" % self.headers.get("User-Agent", ""))
                return self.out(200, self.page("known" if rows else "unknown"))
            if p.startswith("/path/"):
                rows = q("SELECT name FROM items WHERE id=" + unquote(p[6:]))
                return self.out(200, self.page("".join("<p>%s</p>" % r[0] for r in rows) or "none"))
            # ── ここから下は、安全性と誤検知の回帰テスト用 ──
            if p == "/dump":        # テスト用: テーブルの中身を返す（注入点ではない）
                t = g.get("t", "")
                if t not in TABLES:
                    return self.out(404, "nope")
                rows = q("SELECT * FROM %s ORDER BY %s" % (t, ORDER[t]))
                return self.out(200, json.dumps([list(r) for r in rows]))
            if p == "/reset":       # テスト用: 初期データに戻す
                setup()
                SESSIONS.clear()
                return self.out(200, "reset")
            if p == "/list":        # 複数行・複数列の一覧（列によって並び順が変わる）
                rows = q("SELECT id,name,price FROM products WHERE cat=" + g.get("cat", "1"))
                return self.out(200, self.page("".join("<p>%s: %s yen</p>" % (r[1], r[2]) for r in rows) or "no item"))
            if p == "/group":       # GROUP BY 句への注入
                rows = q("SELECT name, COUNT(*) FROM items GROUP BY " + g.get("by", "name"))
                return self.out(200, self.page("".join("<li>%s</li>" % r[0] for r in sorted(str(x[0]) for x in rows))))
            if p == "/updmulti":    # UPDATE の文字列値。; で区切った先頭の文を実行してしまう実装
                q_multi("UPDATE notes SET body='%s' WHERE id=2" % f.get("note", ""))
                return self.out(200, self.page("saved"))
            if p == "/resetpw":     # UPDATE ... WHERE に文字列が入る
                q("UPDATE users SET password='%s' WHERE username='%s'" % (f.get("newpw", ""), f.get("user", "")))
                return self.out(200, self.page("changed"))
            if p == "/logout":      # DELETE ... WHERE に文字列。エラー握り潰し
                try:
                    q("DELETE FROM sessions WHERE token='%s'" % f.get("token", ""))
                except Exception:
                    pass
                return self.out(200, self.page("bye"))
            if p == "/delin":       # DELETE ... WHERE id IN (数値の並び)。エラー握り潰し
                try:
                    q("DELETE FROM notes WHERE id IN (%s)" % f.get("ids", ""))
                except Exception:
                    pass
                return self.out(200, self.page("deleted"))
            if p == "/delowner":    # 値の後ろに別の条件が続く（所有者での絞り込み）。元の値では 1 行も消えない
                q("DELETE FROM products WHERE name='%s' AND cat=2" % f.get("name", ""))
                return self.out(200, self.page("deleted"))
            if p == "/delsuffix":   # 値の後ろに文字が足される
                q("DELETE FROM sessions WHERE token='%s-old'" % f.get("token", ""))
                return self.out(200, self.page("deleted"))
            if p == "/delq":        # クォートされた値が IN (...) の中。エラー握り潰し
                try:
                    q("DELETE FROM notes WHERE id IN ('%s')" % f.get("ids", ""))
                except Exception:
                    pass
                return self.out(200, self.page("deleted"))
            if p == "/delfn":       # クォートされた値が関数の引数
                q("DELETE FROM sessions WHERE token=LOWER('%s')" % f.get("token", ""))
                return self.out(200, self.page("deleted"))
            if p == "/delnest":     # 数値が括弧と関数の中
                q("DELETE FROM notes WHERE id IN (ABS(%s))" % f.get("ids", ""))
                return self.out(200, self.page("deleted"))
            if p == "/delnum":      # DELETE ... WHERE id=数値
                q("DELETE FROM notes WHERE id=%s" % f.get("id", ""))
                return self.out(200, self.page("deleted"))
            if p == "/rawcookie":   # Cookie を URL デコードしない実装（Python / Go / Java など）
                ck = dict(x.strip().split("=", 1) for x in self.headers.get("Cookie", "").split(";") if "=" in x)
                rows = q("SELECT name FROM items WHERE name='%s'" % ck.get("track", ""))
                return self.out(200, self.page("known" if rows else "unknown"))
            if p == "/slogin":      # 成功するとセッション Cookie を出し、Cookie があれば常にログイン済み扱い
                ck = dict(x.strip().split("=", 1) for x in self.headers.get("Cookie", "").split(";") if "=" in x)
                if ck.get("sid") in SESSIONS:
                    return self.out(302, "", "/home")
                try:
                    rows = q("SELECT id FROM users WHERE username='%s' AND password='%s'"
                             % (f.get("user", ""), f.get("pass", "")))
                except Exception:
                    return self.out(500, "Internal Server Error")
                if not rows:
                    return self.out(200, self.page("Login failed"))
                sid = "%032x" % random.getrandbits(128)
                SESSIONS.add(sid)
                return self.out(302, "", "/home", cookie="sid=" + sid)
            if p == "/lookup":      # 安全（プレースホルダ）。20 文字を超える入力は 400
                if len(g.get("code", "")) > 20:
                    return self.out(400, "too long")
                q("SELECT name FROM items WHERE name=" + PH, (g.get("code", ""),))
                return self.out(200, self.page("code ok"))
            if p == "/noise":       # 安全。入力を無視し、毎回ちがう件数の項目を出す
                n = random.randint(0, 6)
                return self.out(200, self.page("".join("<li>related %d</li>" % random.randint(1, 9) for _ in range(n))))
            if p == "/taut":        # 安全。1=1 のような「同じ数字 = 同じ数字」を見たら 403（WAF のまね）
                if re.search(r"(\d+)\s*=\s*\1\b", g.get("id", "")):
                    return self.out(403, "Forbidden")
                q("SELECT name FROM items WHERE name=" + PH, (g.get("id", ""),))
                return self.out(200, self.page("item one"))
            if p == "/always429":   # 最初からレート制限されている対象
                return self.out(429, "Too Many Requests", retry=0)
            if p == "/parser":      # DB を使わない検索。クォートの数が合わないと「syntax error」と言うだけ
                v = g.get("q", "")
                if v.count("'") % 2 or v.count('"') % 2 or v.count("(") != v.count(")"):
                    return self.out(200, self.page("Your search query has a syntax error."))
                return self.out(200, self.page("0 results"))
            if p == "/waf":         # クォートを見たら 403 を返す（WAF のまね）
                if "'" in g.get("id", "") or " " in g.get("id", ""):
                    return self.out(403, "Forbidden")
                return self.out(200, self.page("item one"))
            return self.out(404, "nope")
        except Exception:
            return self.out(500, "Internal Server Error")

    def do_GET(self):
        self.handle_req()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.handle_req(self.rfile.read(n).decode())


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
