# 第三章、防火墙后面的世界

> 为什么当一个人建造一堵墙时，下一个人立刻需要知道另一边是什么？” -- *georges R.R. Martin*

利用SPH公司前端服务器上的一些漏洞，我们至少有一台服务器的控制权限了。[53]。我们现在在位于蓝色区域的服务器上拿到了一个shell。但是蓝色区域除了邮箱代理服务器，视频会议服务器和一些网站，没有任何我们正在寻找的数据。

![当前所处位置](./Chap3/1WhereWeAre.png)

蓝色区域只是我们通向绿色区域的入口。想一想。从互联网上我们是看不见绿色区域的（内部网络）;但是，通过蓝色区域，我们可以访问其中的一些服务器了。本章的目的是通过从Front Gun服务器通过蓝色区域，建立一个到绿色区域的可靠链接或隧道。

如果我们可以在途中拿下一两台服务器，那就更好了，但首先要做的事情是：我们正处在什么设备上？

## 3.1 知彼
无论是在Windows还是Linux上，首要工作就是收集所处环境的有效信息。但是，在执行任何命令之前，首先禁用 bash 的历史文件，避免我们的命令被记录下来。
```
www-data@CAREER$ unset HISTFILE
```

查看系统信息

```
www-data@CAREER$ uname -a
Linux CAREER 4.4.0-31-generic #50-Ubuntu SMP Wed Jul	13	00:06:14	UTC	2016	i686	i686	i686
GNY/Linux
www-data@CAREER$ cat /etc/passwd
[…]
redis:x:124:135::/var/lib/redis:/bin/false
redsocks:x:125:136::/var/run/redsocks:/bin/false rwhod:x:126:65534::/var/spool/rwho:/bin/false sslh:x:127:137::/nonexistent:/bin/false rtkit:x:128:138:RealtimeKit,,,:/proc:/bin/false saned:x:129:139::/var/lib/saned:/bin/false
usbmux:x:130:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
beef-xss:x:131:140::/var/lib/beef-xss:/bin/false
vboxadd:x:999:1::/var/run/vboxadd:/bin/false ftp:x:133:143:ftp daemon,,,:/srv/ftp:/bin/false
elasticsearch:x:134:144::/var/lib/elasticsearch:/bin/false debian-tor:x:135:145::/var/lib/tor:/bin/false mongodb:x:136:65534::/home/mongodb:/bin/false oinstall:x:1000:1001::/home/oinstall:/bin/sh oinstall2:x:1001:1002::/home/oinstall2:/bin/sh
[…]
```

看来我们位于一台Ubuntu服务器（使用32位架构）。当前用户是www- data，它通常对系统没有太多特权。

虽然系统上定义了许多用户，但只有我们的会话当前在计算机上处于活动状态：
```
www-data@CAREER:$ w
```
检查网络配置，可以看到在192.168.1.0/24 网段


最后，没有本地防火墙规则，不会干扰我们后续的数据传输技术：


提示：请记住，我们可以使用更高级的反向shell（例如，meterpreter）通过模块来自动执行这些检查。

