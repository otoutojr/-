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

| | 送るもの |
|---|---|
| `--risk 1`（既定） | AND 型と、式に埋め込む型だけ。GET 以外のリクエストでは、コメント（`-- -`）で後続の SQL を消すペイロード（UNION、MSSQL の `WAITFOR` を含む）を送らない |
| `--risk 2` | 上に加えて OR 型、スタッククエリ、GET 以外でのコメント、SQLite の大きい負荷 |

理由: 注入先が `UPDATE … SET x='入力' WHERE id=…` のとき、`' AND 1=1-- -` は `WHERE` を消して全行を書き換えます。`OR` も同じです。既定ではこれを避けます。

- ログインフォーム（元値が無効な入力）は OR 型でないと boolean では検出できません。`--risk 2` を付けてください。
- 検索など参照系と分かっている POST も `--risk 2` で UNION まで調べられます。
- GET は参照系とみなして全部送ります。GET で更新する作りの対象には注意してください。
- 登録・更新系のエンドポイントは、どの risk でも検査のたびに行が書き込まれます。

## 検出できる文脈

- WHERE 句（数値、`'`、`"`、括弧付き）
- ORDER BY / GROUP BY の後ろ
- INSERT / UPDATE の文字列値（User-Agent をログに INSERT する作りなど。`--level 3`）
- 注入点: GET、POST フォーム、JSON、Cookie（`--level 2`）、ヘッダ（`--level 3`）、パス、`*` を置いた生ボディ

## 検出できないもの

「検出なし」は安全という意味ではありません。

- 二次 SQL injection（保存された値が後で使われる型）
- base64 などで包まれた値、multipart（`*` を置いた箇所のみ）
- 改行をまたぐ SQL での UNION と MSSQL の time（行コメントでは次の行を消せない）
- MSSQL の ORDER BY 句での boolean、MSSQL の INSERT / UPDATE 値での time
- WAF 越し。遮断（403 / 406 / 429 / 503）を検知したら警告しますが、回避は `--tamper` の最低限だけです

## 出力

- `-o result.json`: 注入点ごとの手法、DBMS、閉じ方、提示コマンド、検出の根拠になったリクエストと応答
- `--log req.jsonl`: 送った全リクエスト（時刻、URL、ボディ、ステータス、応答長、所要時間）

## テスト

```bash
python3 -m unittest discover -s tests -v
```

`tests/vuln_app.py`（わざと脆弱にしたアプリ）を SQLite で起動して検査します。追加の準備は要りません。

他の DBMS で同じテストを回す場合は、アプリを起動してから URL と DBMS 名を渡します。

```bash
VULN_MSSQL_PASSWORD='...' python3 tests/vuln_app.py mssql 8104 &
SQLJR_TEST_URL=http://127.0.0.1:8104 SQLJR_TEST_DBMS=MSSQL python3 -m unittest discover -s tests -v
```

`vuln_app.py` のバックエンドは `sqlite` / `pg` / `mysql` / `mssql` / `oracle` です。接続先は `VULN_*` 環境変数で指定します（ファイル冒頭を参照）。ドライバは `psycopg2-binary` / `pymysql` / `pymssql` / `oracledb` です。
