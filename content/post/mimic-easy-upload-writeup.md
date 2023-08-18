---
title: "拟态防御赛easy_upload出题思路"
date: 2018-05-14T16:46:36+08:00
tags: ["拟态防御赛"]
---

## 一些题外话

Bendawang师傅帮忙测试交流后，把单引号和`like`也加进blacklist了，不然用户名截断注入那儿都用不上了

比赛开始后因为docker里nginx的配置没写好，导致DCUA队的师傅把Host改成localhost后可以直接下php的源码 Orz

因为疏忽，比较的地方 `strlen($name) > 20` 写成了 `strlen($name > 20)`。 因为测试的时候全都用的数字，所以根本没注意到这个地方，多亏了小陆师傅提醒，不然就凉凉了 ( 后来看LC↯BC的数据发现他们就是用的全字母。。

## 关于两个漏洞点

先说说上传吧，这里思路来源于ph老师在xdctf 2015中出的那道题 [https://www.leavesongs.com/PENETRATION/XDCTF-2015-WEB2-WRITEUP.html#004-getshell](https://www.leavesongs.com/PENETRATION/XDCTF-2015-WEB2-WRITEUP.html#004-getshell)， 对这道题getshell的方法印象特别深刻，当时一说到需要有上传漏洞一下子就想到这个点了

然后注入这里是在用户名处，有截断操作导致可以逃逸掉 `addslashes` 后的反斜线，这里因为怕黑盒变成脑洞，所以我在前台页面用户名处加了个 `maxlength=20`，并且在后面放了个 `数据库中用户名字段的长度为25` 的hint。这个点其实是来源于以前在一个CMS中见到过的真实案例

## 解题步骤

首先登录页面查看源码可以注意到用户名限定了20的长度

```html
 <input maxlength="20" type="text" name="username" id="inputUsername" class="form-control" placeholder="Username" required autofocus>
```

这里我是直接将值经过 `addslashes` 后就放到session里了，登录后可以发现打印了登录的用户名与IP，还有一个上传操作，以及一段话 `this is your files:`

我将这句话直接放在这里其实主要是想让做题的师傅知道，这里一定是可以将文件传上去的，而且会将这个用户上传的文件取出来，那么这里就能考虑到，上传后至少会将用户名与文件名这两个字段对应入库，以及登录后会将该用户名上传后的文件都查出来这两个数据库交互的操作

一般这里在登录的时候就会测试有没有注入了，很快就能测出来 `'` ， `"`， `\` 都被转义了，于是将目光转到ip上，这里我对IP做了去空操作，然后黑名单比较关键字，其实也没拦多少有用的函数，跑一遍关键字基本上就都知道了，这里将单引号过滤掉了，而且因为这里过滤了很多sql操作的关键字，所以可以考虑到，上传文件后，应该会将用户名，IP，文件名 一起入库。但是接下来基本上没有什么有用信息

然后看看上传的操作，这里很快会发现存在一个悖论般的检测，即文件内容为php代码，则会被拦截，而如果内容不为php代码则提示需要上传php文件，这里用的是 `mime_content_type` 取类型

![](/img/mimic-easy-upload-writeup/1.png)

![](/img/mimic-easy-upload-writeup/2.png)

这里后缀也有检测，但是使用空格或者tab就可以了，很典型的后缀绕过

这里文件内容通过测试会发现，文件开头为 `<?` 就会被拦截，那么这里需要绕过，预想思路为使用BOM头绕过

![](/img/mimic-easy-upload-writeup/3.png)

但是通过查看选手机器上的数据，发现几乎全都是使用的

```shell
#!/usr/bin/php
<?php phpinfo();?>
```

Orz

上传成功后，会发现只能显示10个不知道是什么的字符，也不知道文件传到哪里去了，这里随便扫一下就能看到有个uploads目录，于是这里考虑怎么去得到上传后的文件名

这里用户名截断就能用上了，通过 `a*19+'`形式的用户名，通过截断将最后的单引号截掉，逃逸出来一个 `\`，可以吃掉sql中用户名字段后的一个单引号，然后使用IP进行注入，这里只能显示10个字符，所以需要截断，这里是可以使用 `MID` 的 ( 首先将数据库，表，字段 查出来，这个很简单，filename长度255，随便注

```
库：challenge
表：picture
字段：id,name,ipaddr,filename
```

所以可以使用 a 用户上传一个shell，此时该用户下只有一个文件

![](/img/mimic-easy-upload-writeup/4.png)

再使用 aaaaaaaaaaaaaaaaaaa' 登录，上传时修改xff进行注入，将a用户的文件名分段注入出来，将这些与a用户下的10个字符拼起来就是完整文件名了。 ( Bendawang师傅这里用的是正则取文件名

![](/img/mimic-easy-upload-writeup/5.png)

访问得到webshell，flag在根目录下

![](/img/mimic-easy-upload-writeup/6.png)

## 其它writeup

[Bendawang师傅的writeup](http://bendawang.site/2018/05/12/%E5%BC%BA%E7%BD%91%E6%9D%AF%E7%B2%BE%E8%8B%B1%E8%B5%9Bweb%E9%A2%98%E9%A2%98%E8%A7%A3/)

[lorexxar师傅的writeup](https://xz.aliyun.com/t/2337)