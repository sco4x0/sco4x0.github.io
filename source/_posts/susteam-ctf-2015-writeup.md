---
title: susteam ctf 2015 writeup
date: 2015-05-24 16:04:08
categories: technology
tags: [susctf,ctf,writeup]
---

### 签到题

![123](http://www.secbox.cn/wp-content/uploads/2015/05/safsghtjkjhgggggrrrrrrrrrrrrr.png)

### Flag你在哪里？

![e6b47942c866a14d00854e25fcaf962b.jpg](/images/e6b47942c866a14d00854e25fcaf962b.jpg)

### 纯色

红色通道里可以直接看到

![9532ff739b513cafb58cd7c0b973fc47.jpg](/images/9532ff739b513cafb58cd7c0b973fc47.jpg)

### 源码中的乾坤

查看源码，可以看到

`flag is here<!--f6Yo34gH-->`

然后在notice中可以看到提示说。flag is后都是。。

### 大海捞针

社工题，一开始以为是需要搜集点信息，然后慢慢拼凑出号码，结果。。

![3f52e9eb1f42c6192f9eb7f677e2d577.jpg](/images/3f52e9eb1f42c6192f9eb7f677e2d577.jpg)

### 神奇的数字13

提示13 想到rot13,解开发现是base64编码后的图片，放到浏览器上就可以直接看到了

![ea7bcb6e82ff37f90be9fb81aa46efdd.jpg](/images/ea7bcb6e82ff37f90be9fb81aa46efdd.jpg)

### Fate!!!

发现pk文件头，用zip解压发现另外一张图片，但是红框中的部分被抹去了，识图之后找到了原本的图片

![c56dcf08a3d49288cc392ddee529739f.jpg](/images/c56dcf08a3d49288cc392ddee529739f.jpg)

按照英文书写就好了

### 困在栅栏中的凯撒

小黑发现了一段神奇的字符:`a\vEnZZpZ)ZgbZpo/ai++x`

根据题目可以看出是凯撒加密和栅栏加密，由于这两种算法都是可逆的，所以不存在先后顺

序问题，第一个字符应该是从 flag 的 f 变成了 a，那么所有的字符都减小了 5，然后再用
```
for i in range(x): 
    	print s[i::x]
```

对x枚举，得到flag{_Just_4_fun_0.0_}

### 盲人摸象

扫描二维码得到

![42a3fb19e9595be916c14f98acbbd2ac.jpg](/images/42a3fb19e9595be916c14f98acbbd2ac.jpg)

根据题目名字，联想到盲文，得到分享的文件，是一段音频，内容是滴答滴答的声音，然后记录一下解莫斯就好了

### 小黑的烦恼

是个wordpress的站，看了看，发现有一篇文章，里面有一句留言：

管理员会经常来看留言哦~

想到了前段时间刚出的那个评论xss

拿到cookie后登陆，就可以看到这么个文章

![52ee2b3ad8cf20e3560d7a7b4115b419.jpg](/images/52ee2b3ad8cf20e3560d7a7b4115b419.jpg)

然后?author=1得到管理员用户名是Admin

登陆后发现只有 wp-content/themes/twentyfifteen/author-bio.php 是有权限编辑的，写个shell就可以在目录下看到flag了

### 十万火急

给了个文件，下下来没有后缀，其实是个pyc，反编译pyc后拿到py源码

```python
if __name__ == '__main__': 
    	baseString = '1dnckajf' 
    	baseLen = len(baseString) 
    	flag = [87,8,15,4,16,4,94,21,72,59,60,6,29,4,24,21,84,59,95,13,52,17,19,5,76]
    	pwd = raw_input('Password:') 
    	wrongFlag = False
    	for i in range(len(pwd)):
    		if flag[i] != ord(pwd[i]) ^ ord(baseString[(i % baseLen)]):
    			wrongFlag = True 
    			break
    	if wrongFlag: 
    		print 'Wrong!'
    	else:
    		print 'Good, password is the flag.'
```

简单的异或，修改一下就可以了

### bright

给了一堆密文，然后拿去base64解一下，发现是MS SCRIPT ENCODE，解开后是一堆hex，转成ascii再解ms script encode