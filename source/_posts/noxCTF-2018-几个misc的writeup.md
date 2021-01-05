---
title: noxCTF 2018 几个misc的writeup
categories: technology
date: 2018-09-03 16:52:22
tags: [noxCTF,writeup,misc]
---

web做不动了，转去misc看一看，说是misc，其实感觉很多web放里面了，比如这两个python。

Ps：这个比赛的 `Forensics` 太可怕了，直到第一天快结束，题板都是这个样子的

![](/images/20180909093022.png)

大部分0解，一两个1解 Orz

# python for fun

这个其实没什么好说的，浏览一遍整个站会发现，在 `match_signature_to_body` 这个功能有用户交互，测试一下会发现这个地方可以任意注入命令，而且没什么过滤，就很简单了

直接 `a,b=(print(open('/usr/src/app/FLAG').read())` 就可以看到flag了

# python for fun 2

相较于`python for fun`，这个做了很多过滤，因为对py3较py2的改变并不怎么知情(至今没用过py3 Orz。自己把自己给坑哭了

虽然过滤了很多关键字，但其实测试一下不难发现，很多能用的东西并没有被过滤，只有python中的常见关键字被过滤掉了，仍然可以使用baseclass来按需获取

所以一个一个找，后面发现了有os，于是选择直接用system去执行系统命令读flag（后来发现whoami居然是root

![](/images/20180909094904.png)

# Read Between The Lin

file发现是`gzip compressed data`，解了之后打开首先看到一段jsfuck

看到这题有不少人解出来，还以为jsfuck解开就是flag，于是还装了个逼说这题已经成了，结果秒被打脸

![](/images/20180909100056.png)

这时发现jsfuck下还有一大堆的空白，感觉很奇怪，于是全选了下，发现并不简单

![](/images/20180909100343.png)

这看起来很像whitespace，队友找了个很屌的解释器，结果秒出flag

![](/images/20180909100458.png)

# Blind Date

这个题的附件是一张图片，但是打不开，用HexEditor打开后仔细看了看，发现了点端倪

![](/images/20180909100730.png)

首先下下来的图片后缀是jpeg，那么这个文件头应该是`JFIF`，而且确实看到有JFIF字样，但是位置很奇怪

正常图片的文件头应该是 `FFD8FFE0` ，而这个却是 `E0FFD8FF` 好像是反过来了？

于是写了个脚本验证猜测，将其中的顺序都倒序了一遍，得到了一张能正常打开的大红枣图片

![](/images/20180909101042.png)

其实看到戴着墨镜，题目名为Blind，就差不多猜到会不会是有盲文(以前有打过一个国内的susteam ctf，有个题叫盲人摸象)，binwalk可以分解出来一个zip包，但是密码是AES，除了爆破好像没办法，问了管理员说是不需要爆破，应该是忽略了什么信息，于是看到图片内容，会发现有一串奇怪的字符串

![](/images/20180909101319.png)

解base64发现就是盲文

![](/images/20180909101459.png)

对照着盲文表得到`f4c3p4lm`，作为解压密码解开分解出来的zip(解不开，把字母换成大写才能解开。。)，其中flag.txt内容是brainfuck，随便找个解释器得到flag

# Slippery Situation

页面上有很长一段话

```
ou upload a zip file, our servers extract the file using bash command "unzip -: file.zip"
the server scans the files inside and returns results!
We dont believe in containers, all zip files are uploaded to /files/ directory and get extracted there for maximum security!
```

可以得到两个有用的信息，第一个是会用`unzip -: file.zip`进行解压，其次是将文件都放在了`/files/`下

可以看到用了 `unzip -: ` ，没见过这个option，于是看了下unzip的帮助信息

![](/images/20180909102549.png)

然后就没有然后了。。 随便上传一个zip也只是返回一条信息，于是看了看网页源码，得到一个信息

`<!-- Note to self : admin page link : /admin-->`

访问admin后是一个登录，但是功能被禁用掉了，在admin的页面还能看到另外一个信息

`<!-- Note to self so i wont forget : if a file named key.txt containing the short ssid is found in the ./admin directory then you dont need to login with user and pass to save time -->`

可以发现cookie中带了一个shortssid，其实这时已经很明了了，前面unzip的`-:`就是为了这个地方开的便利。

将自己的shortssid放到key.txt中，然后压一个包

```bash
 4uuu Nya > ~/Desktop/admin > zip -r 1.zip ../admin/key.txt
  adding: ../admin/key.txt (stored 0%)
```

上传后访问admin会发现有一串base64

```bash
4uuu Nya > ~/Desktop/admin > echo 'VGhpcyBwYWdlIGlzIG9ubHkgYXZhaWxhYmxlIGZvciBBZG1pblBhbmVsIGJyb3dzZXIgdXNlcnMuDQoNCkFkbWluUGFuZWwvMC4xIGFnZW50IHVzZXJzIG9ubHkh' | base64 -D
This page is only available for AdminPanel browser users.

AdminPanel/0.1 agent users only!%
```

修改下ua再访问就可以看到flag了

![](/images/20180909103931.png)