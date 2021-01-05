---
title: 两种破解迅捷pdf转换器的方法
categories: technology
date: 2016-09-08 16:21:21
tags: [c#,patch,keygen,破解]
---

这两天发现这个软件更新了，那么再来看一看，其实没什么太大更新，验证方法之类的也没改

### 0x01：实现keygen

这个版本很蠢，把实现注册的代码全都放到一个类库中去了，就是根目录下的 bllBase.dll，我们来看看其中的reg类里面有什么惊喜

![886b743c6400e913ff369bacd127751e.jpg](/images/886b743c6400e913ff369bacd127751e.jpg)

这些方法名熟悉吗，不熟悉的话，来看看哪个地方用到了

这是注册窗口，注册按钮点击的事件

![c84ff3dc40ef31e92ded177cd112b3f9.jpg](/images/c84ff3dc40ef31e92ded177cd112b3f9.jpg)

so，实现keygen的方法就是直接引用这个dll就好了

![e4d12717e81dc98a26f2dbe1ed27c6dd.jpg](/images/e4d12717e81dc98a26f2dbe1ed27c6dd.jpg)

### 0x02 简单粗暴改全局

在0x01中知道了，这个软件在这个版本中，把注册相关的方法都放到了bllBase.dll中，注意到其中有一个方法名字很敏感

```csharp
public bool Is_Reg()
{
	return ini_config.read_ini("RegCode", "App") == this.get_reg_code("");
}
```

这个软件是注册之后，会将注册码写入 config.ini 文件的 RegCode 键中，而this.get_reg_code("") 就是生成当前机器码对应注册码的方法，在主窗体载入的方法中我们可以看到这么一段代码

![d8edef4da947a5a2d81dbb47d4b9c8c3.jpg](/images/d8edef4da947a5a2d81dbb47d4b9c8c3.jpg)

那么可以尝试直接将Is_Reg()方法强制修改为每次返回必为True就好了，需要用到这个指令

![4bce22bbbfe05b4f8975b7977ca540bb.jpg](/images/4bce22bbbfe05b4f8975b7977ca540bb.jpg)

![2a64107606d52aaa4c7adf8448291362.jpg](/images/2a64107606d52aaa4c7adf8448291362.jpg)

然后直接打开软件，发现试用版已经去除了，而且RegCode为空

![91a775f839158e66c05a0f4d03fafe76.jpg](/images/91a775f839158e66c05a0f4d03fafe76.jpg)