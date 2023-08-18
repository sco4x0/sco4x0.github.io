---
title: "懒人OA 注入 & getshell "
date: 2016-09-12T16:00:53+08:00
tags: ["懒人OA", "sql注入", "文件上传"]
---

## 0x01 注入(好几处)

Ps:感觉这种问题出现的情况非常多啊，内部本来有写过滤，但就是在某些地方不用

在用户中心的地方，因为代码基本上都相同，所以拿一处来说就好了

manage/Common/Mail_List.aspx页面，会根据querystring传入的值来判断是收件箱/草稿箱还是xx箱

```csharp
    if (!base.IsPostBack)
    {
        if (!string.IsNullOrEmpty(base.Request.QueryString["fid"]) && !string.IsNullOrEmpty(this.Uid))
        {
            this.Show(base.Request.QueryString["fid"]);
         }
    }
```

跟入Show方法

```csharp
    private void Show(string string_2)
    {
        //xxxx
        string text = "FolderType=" + string_2 + " and ReceiverID=" + this.Uid;
        string text2 = base.Request.QueryString["keywords"];
        if (!string.IsNullOrEmpty(text2) && Utils.CheckSql(text2))
        {
            string text3 = text;
            text = string.Concat(new string[]{
                    text3,
                    " and (SenderRealName like '%",
                    text2,
                    "%' or SenderDepName like '%",
                    text2,
                    "%' or Subject like '%",
                    text2,
                    "%') "
            });
         }
    int num4 = Convert.ToInt32(MsSqlOperate.ExecuteScalar(CommandType.Text, "select count(*) from Mails where " + text, null));
    }
```

注意到有个CheckSql的方法，但是，他并没有处理传入的string2也就是querystring进来的fid，把他带入了text变量，然后下面判断什么鬼就直接不用管了，因为下面执行sql中直接就把text带进去了，注入产生，这个系统如果出错会跳转到自定义错误页面，但是直接用sqlmap跑就可以啦

![e8474b1ffdbff1c962cb849acee3063d.jpg](/img/lanren-oa-2vul/e8474b1ffdbff1c962cb849acee3063d.jpg)

## 0x02 getshell

Ps:这种判断方法也经常遇到，不仅是CTF，实战中也遇到过两次

在User_InfoEdit.aspx页面中，有个上传头像的操作，看看文件上传的处理

```csharp
    if (this.Fup.HasFile)
    {
            FileExtension[] fileEx = new FileExtension[]
            {
                    FileExtension.GIF,
                    FileExtension.JPG,
                    FileExtension.PNG,
                    FileExtension.BMP
            };
            if (FileSystemManager.IsAllowedExtension(this.Fup, fileEx))
            {
                    string userName = sys_UserInfo.UserName;
                    string text = base.Server.MapPath("~/Files/common/");
                    string text2 = userName + Path.GetExtension(this.Fup.FileName);
                    text += text2;
                    this.Fup.PostedFile.SaveAs(text);
                    sys_UserInfo.PerPic = text2;
                    this.Fup.Dispose();
            }
    }
```

跟进这个FileExtension发现是个枚举

```csharp
    public enum FileExtension
    {
            JPG = 255216,
            GIF = 7173,
            BMP = 6677,
            PNG = 13780
    }
```

这些数字很奇怪，那么来分析一下，以PNG文件举例，这个文件前两个字节是89 50，89转换为10进制为137,50转换为10进制为80，合起来刚好就是13780，再看看JPG图片，前两字节为FF D8，十进制分别为255，216，合起来刚好是255216，至于为什么会看前两个字节呢，往下走

跟进IsAllowedExtension，这里开始判断合法文件了，将整个fileupload控件和文件类型的数组传了进去，跟进去

```csharp
    public static bool IsAllowedExtension(FileUpload fileUpload_0, FileExtension[] fileEx)
    {
            int contentLength = fileUpload_0.PostedFile.ContentLength;
            byte[] buffer = new byte[contentLength];
            fileUpload_0.PostedFile.InputStream.Read(buffer, 0, contentLength);
            MemoryStream memoryStream = new MemoryStream(buffer);
            BinaryReader binaryReader = new BinaryReader(memoryStream);
            string text = "";
            try
            {
                    text = binaryReader.ReadByte().ToString();
                    text += binaryReader.ReadByte().ToString();
            }
            catch
            {
            }
            binaryReader.Close();
            memoryStream.Close();
            bool result;
            for (int i = 0; i < fileEx.Length; i++)
            {
                    FileExtension fileExtension = fileEx;
                    if (int.Parse(text) == (int)fileExtension)
                    {
                            result = true;
                            return result;
                    }
            }
            result = false;
            return result;
    }
```

这些操作完成的功能是，读了上传文件内容的前两个字节，然后转换成10进制依次和枚举值比较，相同则判断是合法能上传的文件

构造一个文件，将前两字节置为89 50，伪造成png

![772d928cc6f07ecc83017fb9119b964d.jpg](/img/lanren-oa-2vul/772d928cc6f07ecc83017fb9119b964d.jpg)

然后上传就行了

![21033b51f486817b0892f6aa41701c4f.jpg](/img/lanren-oa-2vul/21033b51f486817b0892f6aa41701c4f.jpg)