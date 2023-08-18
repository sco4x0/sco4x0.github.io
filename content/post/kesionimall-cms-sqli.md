---
title: "KesionImallCMS v4.0一处sql注入漏洞"
date: 2016-08-03T16:58:01+08:00
tags: ["asp.net", "kesion", "sqli"]
---

之前发在补天上的。搬过来

用户登录页面在 user/userlogin.aspx，看看点击登录按钮后的处理

```csharp
    protected void Button1_Click(object sender, EventArgs e)
    {
        string text = this.UserName.Text;
       string text2 = this.PassWord.Text;
       Utils.MD5(text2, 16);
       int int_ = 0;
       if (this.Cookies.Checked)
       {
            int_ = 3;
       }
        this.method_2(text, text2, this.VerifyCode.Text, int_, true);
    }
```

跟入method2，发现是一堆一堆的登录验证流程，非常繁琐，验证登录成功之后，会进入method3的方法中显示判断用户是否被锁定之类的，然后可以看到一句有意思的代码

```csharp
    CheckUserLogin.UpdateLoginInfo(username, password, lastlogintime, int_0, rndPassWord);
```

跟进去发现这是登录成功后，更新一些和当前用户相关的信息，看到这个地方

```csharp
    DataFactory.ExecuteNonQuery(string.Concat(new string[]
    {
        "Update KS_ProShoppingCart Set UserName='",
        username,
        "' Where userName='",
        BaseFun.GetTempUserName(),
        "'"
    }));
    DataFactory.ExecuteNonQuery(string.Concat(new string[]
    {
        "Update KS_ProAddress Set UserName='",
        username,
        "' Where userName='",
        BaseFun.GetTempUserName(),
        "'"
    }));
```

更新购物车和地址信息，跟入 BaseFun.GetTempUserName方法

```csharp
    public static string GetTempUserName()
    {
            string text = KSCMS.GetCookie("myShop", "userName");
            if (string.IsNullOrEmpty(text))
            {
                    text = Utils.RndNum(12).ToLower();
                    HttpCookie httpCookie = new HttpCookie("myShop" + KSCMS.SiteSN);
                    if (BaseConfigManage.AllowSubDomain.ToLower().Equals("true"))
                    {
                            httpCookie.Domain = BaseConfigManage.RootDomain;
                    }
                    httpCookie.Values.Add("userName", text);
                    httpCookie.Expires = DateTime.Now.AddDays(30.0);
                    HttpContext.Current.Response.AppendCookie(httpCookie);
            }
            return text;
    }
```

取cookie中myshop，如果不为null或者空就返回这个值，看看怎么取的

```csharp
    public static string GetCookie(string Key, string Name)
    {
        string result;
        try
        {
                result = HttpUtility.UrlDecode(Utils.GetCookie(Key, Name));
        }
        catch
        {
                result = string.Empty;
        }
        return result;
    }
```

做个UrlDecode就返回回来了，没有任何过滤措施，那么回过头来看看更新信息的地方，在登陆之前修改一条myshop的cookie，值为注入语句，然后去登录一个正常用户，登陆成功的时候就是注入成功的时候，demo演示

![354f164626194d0a2ac2cef34b2d60af.jpg](/img/kesionimall-cms-sqli/354f164626194d0a2ac2cef34b2d60af.jpg)

![7d31eb8398c8f606242fed9e854c126e.jpg](/img/kesionimall-cms-sqli/7d31eb8398c8f606242fed9e854c126e.jpg)