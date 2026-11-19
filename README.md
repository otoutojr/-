# sqljr

SQL injection の注入点ファザーです。注入点・閉じ方・DBMS を特定し、見つかったら「もしかして これが刺さるかも？」として次に手で打つコマンドを表示します。データの抽出は自動では行いません。

正式に許可された診断と演習（自分の所有物、契約下の対象、HTB などのラボ）でのみ使ってください。OSCP 試験で使えるかは OffSec の判断です。事前に確認してください。

対応 DBMS: MySQL / MariaDB、MSSQL、PostgreSQL、Oracle、SQLite

## 使い方

```bash
pip install requests

python3 sqljr.py -u "http://victim/item?id=1"
python3 sqljr.py -u "http://victim/item?id=1*"                      # * の位置だけ狙う
python3 sqljr.py -u "http://victim/login" -d "user=a&pass=b" --risk 2
python3 sqljr.py -u "http://victim/api" -d '{"id":1}'               # JSON ボディ
python3 sqljr.py -r req.txt --proxy http://127.0.0.1:8080           # Burp のリクエストを Burp 経由で
python3 sqljr.py -u "http://victim/" -c "track=abc" --level 2       # Cookie も検査
python3 sqljr.py -u "http://victim/item?id=1" -o result.json --log req.jsonl
```

`python3 sqljr.py --help` で全オプションを表示します。URL は `-u`（従来の `-h` も可）です。

## --risk（どこまで送るか）

| | GET / HEAD | それ以外（POST など） |
|---|---|---|
| `--risk 1`（既定） | AND 型、値を変えない式、コメント（`-- -` / `#`）、`ORDER BY`、`UNION`、MSSQL の `WAITFOR` | **値を変えない式**だけ |
| `--risk 2` | 上に加えて OR 型、PostgreSQL のスタッククエリ、SQLite の `RANDOMBLOB` 負荷 | GET の `--risk 2` と同じものを全部 |

既定で GET 以外に送らないものと、その理由です。どれも、注入先が `UPDATE` / `DELETE` だったときに狙った行以外へ効きます。

| 送らないもの | 送るとどうなるか |
|---|---|
| コメント（`' AND 1=1-- -`）、`UNION`、`ORDER BY`、`WAITFOR` | `UPDATE … SET x='入力' WHERE id=2` の `WHERE` が消えて全行が書き換わる |
| `';` | PHP の PDO / SQLite3 のように `;` の手前までを実行する実装で、`WHERE` の無い `UPDATE` が走る |
| OR 型 | `WHERE` が常に真になり全行に効く |
| AND 型（`3 AND 1=1`、`') AND 1=1 AND ('a'='a` など） | 値が括弧の中にあると真偽値（0 / 1）に化ける。`DELETE … WHERE id IN (3 AND 1=1)` は `IN (1)` になり、別の ID の行が消える |

代わりに「値を変えない式」を使います。条件が真なら元の値のまま、偽なら SQL エラーになる形です。

```
数値   3*(CASE WHEN (条件) THEN 1 WHEN (エラーになる式) THEN 1 END)
列名   (CASE WHEN (条件) THEN name WHEN (エラーになる式) THEN name END)
文字列 abc'||(SELECT CASE WHEN pg_backend_pid()>0 AND (条件) THEN '' ELSE (複数行の副問い合わせ) END)||'
```

数値は 1 を掛ける形です。`3-(…0…)` のように引く形だと、`price > 入力*100` のように後ろに掛け算が続く文で `3-(0)*100 = 3` になり、対象の行が変わってしまいます。列名（ORDER BY など）は値ごと CASE で包みます。

先に `'` と `''` を送って、値が引用符の中か外かを見分けます。中だと分かれば文字列用の式だけ、外だと分かれば数値・列名用の式だけを送ります。

文字列の連結は DBMS ごとに書き方が違い、MySQL では `||` が OR になります（`WHERE name='v'||…||'' AND owner=7` の `AND owner=7` が外れ、他人の行に一致する）。そのため連結形には `pg_backend_pid()` / `sqlite_version()` / `ORA_HASH()` / `@@SPID` のようにその DBMS にしか無いものを入れ、ほかの DBMS では実行前のエラーで止まるようにしています。

MySQL / MariaDB には文字列の位置で値を変えない式が無いので、クォートを閉じたあと「比較の結果」に式をつなぎます。MySQL でしか動かない形です（time では、ほかの条件で行が残らない場合に備えて `' AND NOT @@sql_mode IS NULL AND 遅延 AND 'a'='a` も送ります）。

```
abc'=(SELECT '1' FROM DUAL WHERE @@sql_mode IS NOT NULL AND (条件)) AND 'a'='a
→ WHERE ((name='abc') = '1') AND 'a'='a' AND owner=7
  条件が真なら副問い合わせは '1' で、元の比較と同じ（後ろの条件も残る）。偽なら NULL で 0 行
```

boolean では「条件」の部分を、偽のとき SQL エラーになる式にします。エラーにする部分を副問い合わせの内側に置いてあるので、`DELETE IGNORE` / `UPDATE IGNORE` がエラーを握り潰しても、元と同じか 0 行にしかなりません。

この式は、値が括弧の中（`IN ('abc')`、`LOWER('abc')` など）にあると値の一部になってしまうので、括弧を 2 つ閉じる形、1 つ閉じる形、閉じない形の順に試し、構文として通った深さで打ち切ります。SQL エラーの文面が見える対象では、構文エラー以外の失敗（引数の数が合わない等）でも、それより浅い形には進みません。SQL エラーが応答から見分けられない対象には、この式を送りません（time だけで調べます）。

これで分かるのは「条件が偽のときにエラーになるか」なので、SQL エラーが画面にもステータスにも出ない対象では boolean を検出できません。time は同じ形に遅延を埋め込んで調べます。

注意点:

- ログインフォーム（元値が無効な入力）は、PostgreSQL / Oracle では OR 型でないと boolean を検出できません（既定だと QUOTE まで）。`--risk 2` を付けてください。MySQL / SQLite / MSSQL は、SQL エラーが 500 などで見える対象なら既定でも見つかります。
- 検索など参照系と分かっている POST も、`--risk 2` で UNION まで調べられます。
- GET で更新・削除する作りの対象には使わないでください。GET にはコメントも送るので、入力が `SET` 句に入る `UPDATE` だと全行が書き換わります。
- 登録・更新系のエンドポイントは、どの risk でも検査のたびに行が書き込まれます（狙った行は更新・削除されます）。
- 元のリクエスト自体が失敗している（HTTP 500、または DB エラーの文面が出ている）注入点は、GET 以外・`--risk 1` では検査しません。壊れた文にペイロードを足すと意図しない文になり得るためです。
- 既定でも残る危険（MySQL / MariaDB の文字列の値）。式が値の位置に入ってしまい、別の行に効くことがあります。書き込み系のエンドポイントは、壊れてもよい環境で検査してください。
  - 3 重以上の括弧・関数の中にある値（`IN (LOWER(TRIM('入力')))` など）
  - 後ろの引数を省けない関数の途中の引数（`IFNULL('入力',0)`、`LEFT('入力',3)` など）で、SQL エラーの文面が見えない対象
  - 副問い合わせの中で、値の後ろに条件が続くもの（`IN (SELECT id FROM t WHERE name='入力' AND …)`）
  - `REPLACE` / `INSERT … ON DUPLICATE KEY UPDATE` のキーになる値
  - 数値パラメータを空の値で検査した場合（元の SQL が構文エラーで、それが応答から分からないとき）
- DBMS を問わず残る危険:
  - 数値の直後に、掛け算より強く結び付く演算子が続く文（MySQL / PostgreSQL の `入力^2` など）
  - `ORDER BY 入力 DESC LIMIT 1` のように、ORDER BY に入る値で書き込み対象の行が決まる `UPDATE` / `DELETE`（`'` を足すだけで並びが変わり得る）
- 提示するコマンドも同じ基準です。GET 以外・`--risk 1` では、コメントで後続を消す形（UNION、スタッククエリ、認証バイパス）は提示しません。

## 検出できる文脈

- WHERE 句（数値、`'`、`"`、括弧付き、`IN (…)` の中の数値）
- ORDER BY の後ろ（5 種類の DBMS すべて）、GROUP BY の後ろ（MySQL / PostgreSQL / SQLite / Oracle。MSSQL は GET のときの time だけ）
- INSERT / UPDATE の文字列値（User-Agent をログに INSERT する作りなど。`--level 3`）
- 元の値が 1 行も返さない WHERE（検索語がヒットしない等）。boolean は式の形で調べ、GET なら UNION まで進みます
- 注入点: GET、POST フォーム、JSON、Cookie（`--level 2`）、ヘッダ（`--level 3`）、パス、`*` を置いた生ボディ（XML など）

time-based の遅延手段:

| DBMS | 手段 |
|---|---|
| MySQL / MariaDB | `SLEEP`（派生テーブルに入れて 1 文につき 1 回） |
| PostgreSQL | `PG_SLEEP` |
| MSSQL | `WAITFOR DELAY`（スタッククエリ。GET か `--risk 2` のときだけ） |
| Oracle | `DBMS_PIPE.RECEIVE_MESSAGE`。実行権限が無ければ重い問い合わせ（`ALL_USERS` の直積を数える）で代用 |
| SQLite | 再帰 CTE で数える（CPU のみ）。`--risk 2` では `RANDOMBLOB` も試す（100MB で対象のメモリを約 700MB 使う） |

Cookie は、まず URL エンコードした形で調べ、確定できなければエンコードせずにもう一度調べます（Cookie の値をデコードしない実装があるため）。

## 結果の確からしさ

- **確定**（`[+] 注入点あり`）: boolean / time / UNION のどれかが通った、または DBMS 固有のエラー文が出た。
- **未確定**（`[?] 注入の可能性あり`）: `'` で壊れて `''` で直る、あるいは `syntax error` のような DBMS を特定できない文言が出ただけ。SQL 以外の構文解析器でも同じ挙動になります。

UNION は、`UNION ALL SELECT NULL,…` の列数を変えると応答が変わること、または目印の文字列が画面に出ることを確かめてから報告します。`ORDER BY n` の挙動だけでは報告しません。

## 検出できないもの

「検出なし」は安全という意味ではありません。

- 二次 SQL injection（保存された値が後で使われる型）
- base64 などで包まれた値、multipart（`*` を置いた箇所のみ）
- SQL エラーが応答に一切影響せず、遅延もさせられない注入点
- 改行をまたぐ SQL での UNION と MSSQL の time（行コメントでは次の行を消せない）
- MSSQL の GROUP BY 句での boolean、Oracle の GROUP BY 句での time（どちらも副問い合わせを書けない場所）
- MSSQL の INSERT / UPDATE 値での time（式の中で遅延できない）
- ログインフォームの boolean は、PostgreSQL / Oracle では `--risk 2` が必要（元の値が 1 行にも一致しないと、埋め込んだ式が評価されない）
- Oracle / SQLite の time は「重い処理」なので、対象が速いと閾値（0.5 秒）に届かず見逃すことがあります
- WAF 越し。遮断（403 / 406 / 429 / 503）を検知したら警告しますが、回避は `--tamper` の最低限だけです

## 知っておくとよい挙動

- 応答の `Set-Cookie` は保持しません。検査の途中でログイン状態が変わると結果が狂うためです。セッションが要るページは `-c` で渡してください。
- `*`（`--marker` で変更可）がどこかにあると、その位置だけを検査します。`*` がデータの一部なら `--marker §` のように別の文字を指定してください。URL エンコードされた `%2A` はマーカー扱いしません。
- 検査しないパラメータは、受け取ったバイト列のまま送ります（UTF-8 以外でエンコードされた値や `;jsessionid=…` も変えません）。
- `--proxy` は環境変数 `http_proxy` / `https_proxy` より優先します。
- 提示する curl コマンドは、sqljr が送ったリクエストと同じになるようにしています（User-Agent も含む）。

## 出力

- `-o result.json`: 注入点ごとの手法、確からしさ（`confidence`）、DBMS、閉じ方、提示コマンド、検出の根拠になったリクエストと応答
- `--log req.jsonl`: 送った全リクエスト。1 回の送信につき 1 行（時刻、注入点、ペイロード、URL、ヘッダ、ボディ、ステータス、応答長、所要時間）

## テスト

```bash
python3 -m unittest discover -s tests -v
```

`tests/vuln_app.py`（わざと脆弱にしたアプリ）を SQLite で起動して検査します。追加の準備は要りません。書き込み系のエンドポイントを既定の risk で検査して、狙った行以外が変わらないことも確かめます。

他の DBMS で同じテストを回す場合は、アプリを起動してから URL と DBMS 名を渡します。

```bash
VULN_MSSQL_PASSWORD='...' python3 tests/vuln_app.py mssql 8104 &
SQLJR_TEST_URL=http://127.0.0.1:8104 SQLJR_TEST_DBMS=MSSQL python3 -m unittest discover -s tests -v
```

`vuln_app.py` のバックエンドは `sqlite` / `pg` / `mysql` / `mssql` / `oracle` です。接続先は `VULN_*` 環境変数で指定します（ファイル冒頭を参照）。MySQL は `VULN_MYSQL_HOST` / `VULN_MYSQL_PORT` を指定すると TCP で接続します。MariaDB と MySQL 8 では式の評価のされ方が違うので、両方で回してください。ドライバは `psycopg2-binary` / `pymysql` / `pymssql` / `oracledb` です。Oracle は DBA ではない一般ユーザ（`VULN_ORACLE_USER`）でも回してください。`DBMS_PIPE` を使えない状況になります。
