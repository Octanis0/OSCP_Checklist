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
|Argus Surveillance|4.0.0|CVE-2018-15745|[exploitdb](https://www.exploit-db.com/exploits/45296)|LFI only|
|Argus Surveillance|4.0.0|CVE-2022-25012|[exploitdb](https://www.exploit-db.com/exploits/50130)|Consider creating new users to test passwords with special characters|
|xampp|<7.4.4|CVE-2020-11107|[exploitdb](https://nvd.nist.gov/vuln/detail/CVE-2020-11107)|Modify an appropriate executable to shellcode|
|Monstra|3.0.4||[exploitdb](https://www.exploit-db.com/exploits/52038)|Place your php payload into a new theme chunk|
|RemoteMouse|3.008||[github](https://github.com/p0dalirius/RemoteMouse-3.008-Exploit)|Execution may be finicky|
|Sonatype Nexus|3.21.1|CVE-2020-10199|[exploitdb](https://www.exploit-db.com/exploits/49385)|Post-auth RCE|
|Glassfish|4.1|CVE-2017-1000028|[exploitdb](https://www.exploit-db.com/exploits/39441)|Directory traversal|
|Synaman|4.0|CVE-2018-10814|[exploitdb](https://www.exploit-db.com/exploits/45387)|`C:/Synaman/config/AppConfig.xml`|

