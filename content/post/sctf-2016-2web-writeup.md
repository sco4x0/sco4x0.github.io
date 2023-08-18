---
title: "SCTF 2016 2个web Writeup"
date: 2016-05-12T14:35:06+08:00
tags: ["sctf", "writeup", "web"]
---

## homework

看到有注册，点击进去看看，一眼就看到了图片上传，脑洞大开猜会不会是ImageMagick，事实证明并没有这么简单，注册好以后各种试了一遍，发现都无果，但是点击登录进去之后的这个链接可以看到

![](/img/sctf-2016-2web-writeup/3062885335.jpg)

于是构造一发读到了4个文件

![](/img/sctf-2016-2web-writeup/2790498775.jpg)

看了半天代码没发现什么问题，然后看到上传代码

```php
<?php
if(move_uploaded_file($tmpname,$target_path)) {

}
$im =imagecreatefromjpeg($target_path);
srand(time());
$newfilename = strval(rand()).".png";
$newimagepath = $uploaddir.$newfilename;
imagejpeg($im,$newimagepath);
unlink($target_path);
```

这个imagecreatefromjpeg很是耐人寻味啊，找到这篇文章[http://www.freebuf.com/articles/web/54086.html](http://www.freebuf.com/articles/web/54086.html)

根据这篇文章所说的，下载提供的poc后开始修改，但是这里很猥琐啊，禁用了好多东西，结果我以为是代码问题没执行，一直在那儿试了老半天，后来我v师傅才弱弱地告诉我直接eval一句话不就好了。 然后又改图片，因为很多地方会被改动，所以又改了一下午的图片，然后终于构造成功一张上传之后GD也不会破坏代码的图片！  再然后用index.php中

```php
<?php
    session_start();
    include('./config.php');  
    @$username=$_POST['username'];
    @$password=$_POST['password'];
    @include($_GET['homework']);  //这个任意文件包含漏洞
    $username=intval($username);
    $password=md5($password);
```

将这张图片包含进来，成功getshell，在根目录下找到flag

![](/img/sctf-2016-2web-writeup/481476785.jpg)

## sycshell

打开访问，这个页面真的是整懵逼了，刚开始的时候页面源文件中存在一段"jsfuck"，解不开，总感觉是不是有什么秘密在里面，尝试了很久之后放弃，下面还有个提示：`<!-- 内部系统资料：http://sycshell.sycsec.com:61180/ -->`，直接访问也是打不开的，将题目给的那个ip地址和这个绑host就能打开辣

源码又是一大堆JSfuck，console运行弹窗然后undefine，找到了一篇文章,[http://joyhuang9473.github.io/post-ctf/2015/07/27/ais3-writeup-web2.html](http://joyhuang9473.github.io/post-ctf/2015/07/27/ais3-writeup-web2.html) 

![](/img/sctf-2016-2web-writeup/410527477.jpg)

搞不懂js，于是丢给 @王松_Striker 大傻逼解码去了 ，过了一会儿，丢给了我一个连接`http://sycshell.sycsec.com:61180//W0Ca1N1CaiBuDa0/read.php?f=index`

访问可以看到一段代码，代码审计来了

```php
<?php
    show_source(__FILE__);
    $pass = @$_GET['pass'];
    $a = "syclover";
    
    strlen($pass) > 15 ? die("Don't Hack me!") : "";
    
    if(!is_numeric($pass) || preg_match('/0(x)?|-|\+|\s|^(\.|\d).*$/i',$pass)){
        die('error');
    }
    
    if($pass == 1 &&  $a[$pass] === "s"){
        $file = isset($_GET['f']) ? $_GET['f'].'.php' : 'index.php';
        @include $file;
    }
```

首先绕过is_numeric

推荐阅读：[http://zone.wooyun.org/content/23961](http://zone.wooyun.org/content/23961)
[http://zone.wooyun.org/content/24075](http://zone.wooyun.org/content/24075)

这里php版本很重要，题目用的是5.3.29，本机用5.6的时候会测不出来，is_numeric用%0b绕过去就好了，然后避开正则绕过下面的判断

下面的判断很尴尬，基本上可以说成是，如何让$pass即等于1，又等于0，导致是始终只会有一个条件成立，这里需要用到几个姿势

0x01:

![](/img/sctf-2016-2web-writeup/3400918449.jpg)

在字符串转换成numeric的时候，如果不是numeric字符串，会直接将其转换成0

0x02:

![](/img/sctf-2016-2web-writeup/2258029289.jpg)

可以看到，在精度过大(16位)的时候，就开始神志不清分不清大小了，ph老师这个已经说的很详细了，详细见[http://zone.wooyun.org/content/23961](http://zone.wooyun.org/content/23961)

那么接下来第一步用%0b绕过is_numeric之后，要让$pass等于1，那么尝试%0b1，但是这样后面一个就满足不了了，因为正则的原因，这里很棘手，php中，0.1和.1是相等的，所以这里构造成%0b.1

![](/img/sctf-2016-2web-writeup/2586054672.jpg)

在然后考虑如何等于1，根据之前0x2中提到的，只要能让后面的精度足够大，会将其判断成1，这里是可以直接使用科学计数法，引入一个字母e，构造成%0b.1e1，而由于这个字符串是不符合is_numeric_string定义的，所以会直接将其置为0，这么一来，就完成了同时等于0和1的条件

![](/img/sctf-2016-2web-writeup/364658457.jpg)

bypass完成，问柠檬牛后得知是要getshell，这里有两个点，第一个是有文件包含漏洞，第二是有个phpinfo.php

看柠檬牛写的总结 http://www.cnblogs.com/iamstudy/articles/include_file.html

可以知道，这是要用LFI+phpinfo，去getshell，在phpinfo页面中可以找到一个waf.php，通过文件包含漏洞构造流可以读到源码

![](/img/sctf-2016-2web-writeup/3763720690.jpg)

这里是大小写敏感的，也就是说，可以用PHAR和ZIP 去进行绕过，关于zip或phar协议包含文件，可以看看番茄表哥的文章[http://bl4ck.in/index.php/tricks/use-zip-or-phar-to-include-file.html](http://bl4ck.in/index.php/tricks/use-zip-or-phar-to-include-file.html)

然后就可以直接从网上扒脚本下来跑辣，网上的脚本都是上传单个文本文件，这里是需要上传压缩包，所以需要rb然后放上去

`然后因为家里的辣鸡电信并没有跑出来`