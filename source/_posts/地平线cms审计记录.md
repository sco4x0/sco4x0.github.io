---
title: 地平线cms审计记录
date: 2015-01-11 15:59:55
categories: technology
tags: [deepcms,代码审计,asp.net]
---

版本可能不大一样

## 1：一处sql注入漏洞

漏洞文件：`SearchResult.aspx.cs`，查询结果，看处理代码

在 `Page_Load` 方法中，可以看到：

```csharp
	  string Key = Request.QueryString["Key"];      
    if( Key == null )Key = Request.Form["Key"];
    if( Key == null || Key == "")Key = "%";
          /*去除无关代码*/       
    this.keyWord.Text = Key;
          /*去除无关代码*/ 
         ///查询符合条件的记录总数：      
    countDt = mh.GetDatabysql("Select Count(*) As CountNum From Article4DeepSoon,Class4DeepSoon Where Title Like '%"+Key+"%' and ClassID in "+ChildIDSet+" and isDelete=false and Article4DeepSoon.ClassID=Class4DeepSoon.ID");     
    articlePageCount = Convert.ToInt32(countDt.Rows[0]["CountNum"]);
```

直接querystring获取参数key，判断了一下是不是为null，然后就没其他判断了，后面就直接带入了查询，注入产生

## 2.添加管理员

在安装程序的 `index.aspx.cs` 中的，`Page_Load` 方法中，完全没有任何代码

而安装程序是step1.aspx,step2.aspx…..   每个步骤都有不同的功能，因为安装之后这里不会覆盖安装，step2.aspx中是添加管理员账户的，这里直接添加直接入库

3.后台任意页面查看

后台登陆页面在基类PageBase中有判断是否登录的方法，方法代码如下

```csharp
    If(base.strUser.ToString().Trim() == “”){
            Respone.Redirect(“/admin/deepSoonLogin.aspx”)
    }
```

在PageBase中取基类strUser的值是否为空，那么直接找PageBase的基类ValidateBase

在ValidDateBase中有一个基类成员strUser ,看怎么取值的：

```csharp
    /*
    
    if (Session["strUser"] != null)
    
        return Session["strUser"].ToString();
    
    else
    
        return "";
    
    */
    
    if (Request.Cookies["strUser4Deepsoon"] != null){
    
        HttpCookie userCookie = Request.Cookies["strUser4Deepsoon"];
    
        return HttpUtility.UrlDecode(HttpUtility.UrlDecode(userCookie.Value, Encoding.GetEncoding("UTF-8")));
    
    }
    
    else
    
        return "";
```

获取cookie strUser4Deepsoon，判断其值是否为空，如果不为空就返回该值，那么在PageBase中的判断是如果不为空就不跳转到登陆页面，而且这里没有判断strUser的值是否正确，所以不论strUser是什么值都能访问，就不用担心不知道后台账户ID而不知道值是什么了

添加strUser4Deepsoon这个cookie值,然后就可以直接访问后台任意页面了

4.绕过后台登录

后台登录页面的代码中有这么一段：

```csharp
    if (Request.Cookies["strUser4Deepsoon"] != null)
    
    {
    
    HttpCookie userCookie = Request.Cookies["strUser4Deepsoon"];
    
    string loginName = HttpUtility.UrlDecode(HttpUtility.UrlDecode(userCookie.Value, Encoding.GetEncoding("UTF-8")));
    
    this.labelInfor.Text = "您当前状态为已登录，已登录账户:"+loginName+" <a href='deepsoonindex.aspx'>直接进入后台</a>
    
    或者更换一个登录账户:";
    
    this.txtLoginName.Text = loginName;
```

获取cookie，看是否为空，如果不为空的话，就判断是已经登陆，就会多出一个超链接：直接进入后台。新建一个strUser4Deepsoon键的cookie，然后刷新页面，点击进入后台，和正常登陆进入后台是一样一样的，这个时候使用上面那个漏洞可以查看到用户列表，那么就可以构造一个合法用户进入

5.任意文件读取修改

后台admin/Module.Document/Document/TxtEdit.aspx页面的作用是文档修改

逻辑处理代码在admin/Lib/Module.Document.cs中

看查看文件的代码：

```csharp
    string filePath; 
    string fileName; 
    protected void Page_Load(object sender, EventArgs e){ 
    	filePath = Request.QueryString["filePath"]; 
    	fileName = Request.QueryString["fileName"]; 
    	DeepSoonHelp dh = new DeepSoonHelp(); 
    	if (!IsPostBack && dh.notHasSQLInsertCode(filePath) && dh.notHasSQLInsertCode(fileName) )  {  
    		string fileAtServer = Server.MapPath("../"+filePath+fileName).ToString(); 
    		if(File.Exists(fileAtServer)) { 
    			string fileContent = ""; 
    			fileContent = File.ReadAllText(fileAtServer);  
    			this.labelFileFullPath.Text = filePath + fileName; 
    			this.textFileContent.Text = fileContent; 
    		} 
    		else{ 
    			this.labelSaveInfor.Text = "文件不存在"; 
    			Page.ClientScript.RegisterStartupScript(GetType(), "errorInfor", "<script language='JavaScript'>CxcDialog('提示框','文件爱呢不存在!','Warning')</script>"); 
    		} 
    	}
    }
```

Ps: 虽然后台有文件修改的功能，但是最能对txt,html,.htm这一类静态页面才能进行修改

文件名filename和文件路径filepath都是querystring获取到，然后用一个方法过滤了一下，其实没什么用，因为那个方法是过滤sql注入的，在这里没什么影响，判断了一下这个文件是不是存在，如果存在的话就直接读取文件并显示在文本框中，那么就可以进行构造了



修改文件需要权限
