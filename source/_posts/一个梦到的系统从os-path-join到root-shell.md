---
title: 一个梦到的系统从os.path.join误用到root shell
date: 2021-01-23 12:13:41
tags: [做梦，渗透]
---

昨晚做了一个梦，梦到了一个系统，对它做了下审计与利用，醒来后赶紧记录一下，如有雷同，纯属不可能

梦到的系统是用flask写的，整个web应用做成了python的包放到了virtualenv中

整个系统只有6个大功能

```python
from system.func1.views import func1_module
app.register_module(func1_module, url_prefix='/system/func1')

from system.func2.views import func2_module
app.register_module(func2_module, url_prefix='/system/func2')

from system.func3.views import func3_module
app.register_module(func3_module, url_prefix='/system/func3')

from system.func4.views import func4_module
app.register_module(func4_module, url_prefix='/system/func4')

from system.func5.views import func5_module
app.register_module(func5_module, url_prefix='/system/func5')

from system.func6.views import func6_module
app.register_module(func6_module, url_prefix='/system/func6')
```

几乎所有功能都是有登录校验，那么首先需要解决的是如何获得一个登录凭证

## 解决登录问题

登录操作在 `func1` 功能模块下的 `common` 中，有一个 `LoginManager` 的类，其中处理登录的函数是 `user_login`

```python
user = User.query.filter_by(username=username).first()
if not user:
    return False, lazy_gettext(u'用户名或密码错误'), user
if not password:
    return False, lazy_gettext(u'密码不能为空'), user
if user.password == hashlib.md5(password).hexdigest():
    # 登录成功添加session
else:
    # 登录失败加锁
```

这可就很犯愁了，正打算看看还有没有什么其他办法的时候看到下边还有一个处理SSO的 `SSOManager`，其中也有一个校验的操作

```python
def auth_certificate(cls, client_id, username):
    sso_manage = SSOManager(client_id, username)
    sso_manage.login(username)
    if True:
        access_token = sso_manage.access_token_gen()
        if access_token:
            return True, access_token
    return False, None
```

跟进login发现仅仅是判断是否存在这个用户名，如果存在的话直接就把这个用户的权限和信息取出来放session，而梦到的这个系统用来判断是否登录就是取的session信息，那么找找这里有啥地方调用了

幸运的是在 `views.py` 中找到了一个调用SSO里验证的函数

```python
@func1.route('/sso_auth', methods=['GET'])
@csrf
def sso_auth():
    if request.method == 'GET':
        try:
            username = request.args.get("username")
            if username:
                is_success, data = SSOManager.auth_certificate(SSO_CLIENT_ID,username)
                if is_success:
                    token = session.get('csrf_token', '')
                    return jsonify(status=200, access_token=data, csrf_token=token, message="Authenticate success!")
            else:
                return jsonify(status=401, message="Authenticate fail!")
        except Exception:
            return jsonify(status=201, message=lazy_gettext(u"后台异常")
```

那么直接请求 `http://host/func1/sso_auth?username=admin`，就可以在返回包中获得一个认证后的sessionid，继续接下来的操作

## 误用os.path.join导致的任意文件写入

在 `func6` 中，有一个导入数据的操作

```python
file = request.files.get('file', None)
if file:
    filename = file.filename
    file.save(os.path.join(IMPORT_DATA_DIR, filename))
    is_success, response = DataManager.ImportData(IMPORT_DATA_DIR+'/'+filename)
    os.remove(IMPORT_DATA_DIR+'/'+filename)
```

这里的filename是完全可控的， 并没有用 `secure_filename` 之类的操作去处理，然后放到了 `os.path.join` 中直接保存了这个文件，然后对文件做了一堆处理，再remove掉

但是这里存文件和删文件的处理却不一样，这里可以用到一个 `os.path.join` 的特性

![](/images/2021123-1.png)

处理完文件以后却使用了普通的字符串拼接来删除，那肯定是删不掉的，到此已经得到了一个任意文件写入，那么怎么该怎么利用呢

## nice啊supervisor

当我想着该怎么扩大这个任意文件写入的影响时，利用梦境GM权限开了一台部署这个系统的机器然后root登了上去翻了翻

这个时候我注意到这个当前web进程的用户组是 `web:web`, 那么问题来了，一个什么样的文件是web有权写入并且还能扩大影响的呢

突然我发现梦里这台机器上跑着supervisor，翻了翻配置文件，有一些配置是这样写的

```conf
[group:xxx]
;programs=xxx
programs=xxx

[program:xxx]
command=sh /work/service/run.sh
autostart=true
autorestart=true
; 省略
```

在服务器上看了一下这个文件惊喜的发现用户组刚好就是 `web:web`，所以如果我把这个shell给覆盖掉，然后再重启这个xxx服务不就可以实现任意命令执行了吗

回过头来在web程序中找找有没有操作supervisor的动作，没想到刚刚好有一个功能在做完一系列配置后会重启xxx

```python
@config.route('/xxxManage', methods=['GET', 'PUT'])
@login_required
@csrf
def xxxManage():
    if request.method == "GET":
        # 省略
    else:
        token = session.get('csrf_token', '')
        post_data = request.get_json()
        try:
            # 省略处理步骤 
            subprocess.Popen(['sudo', 'supervisorctl', 'restart', 'xxx'])
```

而supervisor又是root在跑，一切都是那么恰到好处

在我拿到root shell的那一瞬间，梦醒了