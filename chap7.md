# 第七章、结束语

我希望你喜欢站在黑客的立场上，享受它带来的所有情绪：沮丧、快乐和兴奋。当然，这只是在我的实验室里搭建的一个仿真环境，用来模拟真实公司的网络，但它准确地突出了我们在现实生活中可以发现和利用的许多缺陷。传统上，像这样的入侵/渗透需要几天或几周的时间才能完成，但我们稍微加快了这个过程，主要集中在我们在开始时确定的目标上。

如果你刚接触道德黑客，我鼓励你阅读本书中引用的文章。请毫不犹豫地执行链接中提供的脚本和命令，尝试修改命令参数，弄清楚每个工具的使用场景和前置条件。

\[1\] P0wning让人快乐！

\[2\] Your browser has a unique fingerprint: OS version, plugins installed, patch level, etc. It is used by many social networks to identify users even if they change IP addresses.

\[3\] [http://www.imdb.com/title/tt4044364/](http://www.imdb.com/title/tt4044364/) and [https://www.theguardian.com/us-news/the-nsa-files](https://www.theguardian.com/us-news/the-nsa-files)

\[4\] [https://www.torproject.org/](https://www.torproject.org/)

\[5\] A layer of security used over HTTP to encrypt web content \(HTTPs\)

\[6\] Use Bitcoin or other cryptocurrencies to pay anonymously

\[7\] [https://www.bitcoin.com/](https://www.bitcoin.com/)

\[8\] [http://cryto.net/~joepie91/bitcoinvps.html](http://cryto.net/~joepie91/bitcoinvps.html)

\[9\] [https://www.kali.org/](https://www.kali.org/)

\[10\] [http://www.linuxliveusb.com/](http://www.linuxliveusb.com/) for a bootable USB Linux.

\[11\] [https://www.whonix.org/](https://www.whonix.org/)

\[12\] [https://tails.boum.org/](https://tails.boum.org/)

\[13\] [https://blog.barkly.com/phishing-statistics-2016](https://blog.barkly.com/phishing-statistics-2016)

\[14\] Using an anonymous email service, of course: protonmail.com, yopmail.com, etc.

\[15\] [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)

\[16\] [https://getgophish.com/](https://getgophish.com/)

\[17\] Although some hackers try to hide the file by adding a dummy extension: e.g., “image.jpg.exe”.

\[18\] [https://www.metasploit.com/](https://www.metasploit.com/)

\[19\] [http://www.freevbcode.com/ShowCode.asp?ID=3353](http://www.freevbcode.com/ShowCode.asp?ID=3353)

\[20\] [https://www.peerlyst.com/posts/resource-infosec-powershell-tools-](https://www.peerlyst.com/posts/resource-infosec-powershell-tools-) resources-and-authors

\[21\] [http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html](http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html)

\[22\] [http://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator](http://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)

\[23\] [https://www.powershellempire.com/](https://www.powershellempire.com/)

\[24\] [http://www.powershellempire.com/?page\_id=110](http://www.powershellempire.com/?page_id=110)

\[25\] [https://github.com/Veil-Framework/Veil-Evasion](https://github.com/Veil-Framework/Veil-Evasion)

\[26\] [http://www.consulting-bolte.de/index.php/9-ms-office-and-visual-basic-for-applications-vba/154-determine-architecture-64-or-32-bit-in-vba](http://www.consulting-bolte.de/index.php/9-ms-office-and-visual-basic-for-applications-vba/154-determine-architecture-64-or-32-bit-in-vba)

\[27\] The above scenario will work on any Windows computer, provided that the user opens the document and activates its macros. Some hackers go a step further and exploit a vulnerability either on Word/Excel or on the browser \(especially the plugins installed such as flash, adobe reader, etc.\) in order to execute code on the computer and automatically elevate their privileges. Such vulnerabilities that are not yet patched by the editor are called zero-days, and can easily be worth thousands of dollars, especially for Microsoft products.

\[28\] Check out this repository for inspiration on PowerShell obfuscation [https://github.com/danielbohannon/Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

\[29\] [https://github.com/darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon)

\[30\] [https://github.com/rbsec/dnscan](https://github.com/rbsec/dnscan)

\[31\] Another approach would be to directly query private databases for IP segments registered by SPH or its regular registrars, but many online tools request payment to perform such precise requests.

\[32\] I put a private range to avoid any potential legal issues when publishing the book

\[33\] How to configure Burp Suite: [https://portswigger.net/burp/help/suite\_gettingstarted.html](https://portswigger.net/burp/help/suite_gettingstarted.html)

\[34\] The ping command on Windows sends a packet with 32 bytes of data.

\[35\] More one-liners can be found here [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

\[36\] Check out the HTTP headers using ZAP or BURP to know which language the website is using.

\[37\] Check out fuzzdb for basic webshells in multiple languages [https://github.com/tennc/webshell/tree/master/fuzzdb-webshell](https://github.com/tennc/webshell/tree/master/fuzzdb-webshell)

\[38\] A helpful browser extension to get is ‘Wappalyzer’. It automatically fingerprints every component on the website.

\[39\] ‘+’ is URL encoded in the address bar to %2B

\[40\] Complete book about SQL injections: [https://www.amazon.com/SQL-Injection-Attacks-Defense-Second/dp/1597499633](https://www.amazon.com/SQL-Injection-Attacks-Defense-Second/dp/1597499633)

\[41\] [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)

\[42\] If you want to manually practice SQL injections, check out the following website [http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

\[43\] [https://www.drupal.org/project/drupal/releases/8.0.0](https://www.drupal.org/project/drupal/releases/8.0.0)

\[44\] [https://crackstation.net/](https://crackstation.net/)

\[45\] [http://www.netmux.com/blog/how-to-build-a-password-cracking-rig](http://www.netmux.com/blog/how-to-build-a-password-cracking-rig)

\[46\] [https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-keys--2](https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-keys--2)

\[47\] [https://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html](https://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html)

\[48\] RDP for Remote Desktop Protocol is a Windows protocol used to remotely control a machine. The service usually runs on port 3389.

\[49\] [https://nmap.org/](https://nmap.org/)

\[50\] www.shodan.io

\[51\] Interestingly, while editing this book, it became apparent that thousands of MongoDBs are currently being trapped by malicious users who encrypt data and demand a ransom. The scary thing is that the same ‘vulnerability’ affects Cassandra, ElasticSearch, and Redis databases.

\[52\] We can create efficient custom rules for John. Here are a few examples: [http://contest-2010.korelogic.com/rules.html](http://contest-2010.korelogic.com/rules.html)

\[53\] [https://github.com/lanjelot/patator](https://github.com/lanjelot/patator), [https://github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra), [https://github.com/galkan/crowbar](https://github.com/galkan/crowbar)

\[54\] We will stick with a compromised Linux server to show some nice pivoting techniques later on, otherwise it would be simple if we landed directly on Windows from the start.

\[55\] For Windows: [http://tim3warri0r.blogspot.fr/2012/09/windows-post-exploitation-command-list.html](http://tim3warri0r.blogspot.fr/2012/09/windows-post-exploitation-command-list.html).

For Linux: [https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List](https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List).

\[56\] There is always the MongoDB server we got earlier, but I want to show you how to attack one from the “inside”.

\[57\] [https://raw.githubusercontent.com/mfontanini/Programs-Scripts/master/socks5/socks5.cpp](https://raw.githubusercontent.com/mfontanini/Programs-Scripts/master/socks5/socks5.cpp)

\[58\] The firewall blocks every port other than 80 and 443, which are already used by the website.

\[59\] [http://proxychains.sourceforge.net/](http://proxychains.sourceforge.net/)

\[60\] I would never run an out of the box meterpreter file on a Windows machine. However, given that admins are so reluctant to equip Linux with an antivirus solution, we can be indulgent.

\[61\] Check out explot-db.com for publicly available exploit code.

\[62\] [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)

\[63\] [https://www.youtube.com/watch?v=-IMrNGPZTl0](https://www.youtube.com/watch?v=-IMrNGPZTl0)

\[64\] Remote Procedure Calls is a protocol used by Windows to interact remotely with a machine. A call is made to port 135, which instructs the client to contact a random port \(between 49152 and 65335\) to issue its commands.

\[65\] [https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz](https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz)

\[66\] Each domain can be further broken down into Organization Units.

\[67\] There are several other ways to achieve total control over a domain: write privilege on GPO, administrative delegation, etc.

\[68\] A term I just invented.

\[69\] This statement only applies to local users. As previously explained, a domain user authenticates to the domain controller. The lockout count is then held by the DC and does not take into account the targeted machine. E.g., if lockout = 5 and we fail authentication on 5 different machines, a domain account is effectively locked, whereas a local account is not.

\[70\] Admin may sometimes set up the LocalAccountTokenFilterPolicy registry key which effectively disables remote UAC.

\[71\] We will show later on how to target users who did not click on the malicious payload.

\[72\] [https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1)

\[73\] For this maneuver to work, we obviously need to set up a persistence scheme, using the run key for instance as detailed previously.

\[74\] First method of extracting NTDS: [https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-\(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM\)/](https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-%28VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM%29/)

Second method: [https://www.cyberis.co.uk/2014/02/obtaining-ntdsdit-using-in-built.html](https://www.cyberis.co.uk/2014/02/obtaining-ntdsdit-using-in-built.html)

\[75\] [https://github.com/samratashok/nishang/blob/master/Utility/Do-Exfiltration.ps1](https://github.com/samratashok/nishang/blob/master/Utility/Do-Exfiltration.ps1)

\[76\] [https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)

\[77\] We covered this part in the previous section: 5.6.2 Strategic files.

\[78\] Outlook client works well. Otherwise there are plenty that can be found on Google that do the job just fine.

\[79\] I cannot think of a greater book for cryptology than Bruce Schneier’s Applied Cryptography.

\[80\] If RDP port was not available, we could have gone with GPO like before, or WMI calls, which we will demonstrate later.

\[81\] [http://www.blackhillsinfosec.com/?p=5296](http://www.blackhillsinfosec.com/?p=5296)

\[82\] Thanks in great part to researchers like Soldier of Fortran, BigEndianSmalls and Singe.

\[83\] Job Control Language, a « scripting » language used on mainframes to execute programs

\[84\] [http://x3270.bgp.nu/download.html](http://x3270.bgp.nu/download.html)

\[85\] The proper way to do it would be to download a second socks proxy and run it on 10.10.20.118. Then, instruct proxychains to go through two proxies: one in the DMZ, then this second one. Since I already detailed how to put this in place, I would rather focus entirely on the Mainframe.

\[86\] We have to wait until users disconnect from the mainframe before using their credentials.

\[87\] [https://github.com/ayoul3/Privesc/blob/master/ELV.APF](https://github.com/ayoul3/Privesc/blob/master/ELV.APF)

\[88\] [https://github.com/magnumripper/JohnTheRipper](https://github.com/magnumripper/JohnTheRipper)

\[89\] For a talk about the actual hacking of a mainframe in Sweeden: [https://www.youtube.com/watch?v=SjtyifWTqmc](https://www.youtube.com/watch?v=SjtyifWTqmc)

\[90\] [https://github.com/ayoul3/Rexx\_scripts/blob/master/REXX.GETUSERS](https://github.com/ayoul3/Rexx_scripts/blob/master/REXX.GETUSERS)

\[91\] We run a second socks proxy on the 10.10.20.118 machine. That way our probes can avoid the DMZ firewall. We alter proxychain’s configuration file to take it into account.

\[92\] There are some amazing nmap scripts to brute force user accounts as well as passwords. I encourage you to check out Soldier of Fortran’s work on the subject.

\[93\] [https://github.com/zedsec390/NMAP](https://github.com/zedsec390/NMAP)

\[94\] Legally, of course.

> 翻译：Ryan 2019/8/16

