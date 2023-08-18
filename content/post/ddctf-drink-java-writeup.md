---
title: "ddctf 2018 - 喝杯Java冷静下 writeup"
date: 2018-04-23T16:55:22+08:00
tags: ["ddctf", "ctf", "writeup"]
---

R师傅在群里发DDCTF比赛地址的时候已经结束了 Orz，但是赛题仍然可以看，放假找时间看了看

---

PS: 粥师傅搞了点奇怪得东西

![](/img/ddctf-drink-java-writeup/photo_2018-04-30_23-59-09.jpg)

---

首页是个登录，没看到什么东西，看源码的时候发现 `LOGIN FORM` 里面有个注释

```html
<!-- YWRtaW46IGFkbWluX3Bhc3N3b3JkXzIzMzNfY2FpY2Fpa2Fu -->
```

解开base64是： `admin: admin_password_2333_caicaikan`

用这个账号密码可以直接登录进去，只有四个查看详情，全是下载文件 test啥的。后来发现这个下载链接看起来很厉害 `http://116.85.48.104:5036/gd5Jq3XoKvGKqu5tIH2p/rest/user/getInfomation?filename=informations/readme.txt`

像是一个任意文件下载，于是构造了一下发现能下载一些文件，但是这个目录结构不太清楚，不知道代码放在哪儿的。注意到版权里面写着 `Quick4j By Eliteams.`，看起来不像是DD自己的东西，于是搜了一下发现是一个开源项目 [https://github.com/Eliteams/quick4j](https://github.com/Eliteams/quick4j)

很尴尬，不太懂java，翻了翻资料，发现字节码都是放在 `WEB-INF/classes` 目录下，通过查看github上clone下来的quick4j发现结构为 `com/eliteams/quick4j/web/controller/xxx.java`，下载下来的源码中有一个 UserController.java 是其中唯一一个写了业务逻辑的控制器，于是构造将服务器上的 UserController.class 下载回来，然后就可以用 jd-gui 看看代码了，注意到其中有一个

```java
@RequestMapping(value={"/nicaicaikan_url_23333_secret"}, produces={"text/html;charset=UTF-8"})
  @ResponseBody
  @RequiresRoles({"super_admin"})
  public String xmlView(String xmlData)
  {
    if (xmlData.length() >= 1000) {
      return "Too long~~";
    }
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    factory.setExpandEntityReferences(true);
    try
    {
      DocumentBuilder builder = factory.newDocumentBuilder();
      
      InputStream xmlInputStream = new ByteArrayInputStream(xmlData.getBytes());
      
      Document localDocument = builder.parse(xmlInputStream);
    }
    catch (ParserConfigurationException e)
    {
      e.printStackTrace();
      return "ParserConfigurationException";
    }
    catch (SAXException e)
    {
      e.printStackTrace();
      return "SAXException";
    }
    catch (IOException e)
    {
      e.printStackTrace();
      return "IOException";
    }
    return "ok~ try to read /flag/hint.txt";
  }
```

这里很明显是存在一个XXE的，但是需要 `super_admin` 的权限，通过查看下载回来的quick4j项目可以发现权限判断在文件 `security/SecurityRealm.java` 文件中

```java
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
    throws AuthenticationException
  {
    String username = String.valueOf(token.getPrincipal());
    String password = new String((char[])token.getCredentials());
    
    User authentication = this.userService.authentication(new User(username, password));
    if ((username.equals("superadmin_hahaha_2333")) && (password.hashCode() == 0))
    {
      String wonderful = "you are wonderful,boy~";
      System.err.println(wonderful);
    }
    else if (authentication == null)
    {
      throw new AuthenticationException("用户名或密码错误.");
    }
    SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username, password, getName());
    return authenticationInfo;
  }
```

用户名已经限定为 `superadmin_hahaha_2333` ，但是密码的 hashCode 为 0 才可以通过，测试后发现空字符串的hashCode()是可以为零的，然而登录的时候已经判断过非空

```java
if ((user.getUsername().isEmpty()) || (user.getUsername() == null) || 
        (user.getPassword().isEmpty()) || (user.getPassword() == null)) {
        return "login";
      }
```

于是google了一下 `spring hashcode() not empty == 0`，在 stackoverflow 上找到 [https://stackoverflow.com/questions/18746394/can-a-non-empty-string-have-a-hashcode-of-zero?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa](https://stackoverflow.com/questions/18746394/can-a-non-empty-string-have-a-hashcode-of-zero?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa)

使用 `superadmin_hahaha_2333 : f5a5a608` 成功登录，在 `UserController` 中定义了一个 hintFile , `public static final String hintFile = "/flag/hint.txt";`，因为没有回显，所以利用oob读内容

![](/img/ddctf-drink-java-writeup/QQ20180423-132508@2x.jpg)

然后构造访问 tomcat_2:8080 后发现返回 `"GET /try%20to%20visit%20hello.action. HTTP/1.1"`，应该就是攻击内网里的struts2了，这时才反应过来题目一开始给的hint: `第二层关卡应用版本号为2.3.1`

再次访问 hello.action 后得到 `"GET /This%20is%20Struts2%20Demo%20APP,%20try%20to%20read%20/flag/flag.txt. HTTP/1.1"`

网上找到的payload都是命令执行的，这里打不到，得把payload改成直接读取flag文件才行

![](/img/ddctf-drink-java-writeup/QQ20180423-133802@1x.jpg)