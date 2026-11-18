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
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

KIND = sys.argv[1] if len(sys.argv) > 1 else "sqlite"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8101
SQLITE_PATH = os.environ.get("VULN_SQLITE_PATH") or os.path.join(tempfile.gettempdir(), "sqljr_vuln_%d.db" % PORT)

SETUP = [
    "DROP TABLE IF EXISTS items", "DROP TABLE IF EXISTS users",
    "DROP TABLE IF EXISTS logs", "DROP TABLE IF EXISTS notes",
    "CREATE TABLE items (id INT, name VARCHAR(50), price INT)",
    "CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50))",
    "CREATE TABLE logs (a VARCHAR(400), b VARCHAR(400))",
    "CREATE TABLE notes (id INT, body VARCHAR(400))",
    "INSERT INTO items VALUES (1,'apple',100),(2,'banana',200),(3,'cherry',300)",
    "INSERT INTO users VALUES (1,'admin','s3cret'),(2,'alice','pw')",
    "INSERT INTO notes VALUES (1,'first'),(2,'second')",
]


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


for stmt in SETUP:
    q(stmt)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def out(self, code, body, loc=None):
        b = body.encode()
        self.send_response(code)
        if loc:
            self.send_header("Location", loc)
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
