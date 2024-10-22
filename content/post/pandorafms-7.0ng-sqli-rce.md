---
title: "PandoraFMS <=7.0ng776 pre-auth SQLi->RCE"
date: 2024-10-22T16:25:41+08:00
tags: ['pandorafms']
---

> SQL注入很简单，这里主要记录一下在拥有了SQL注入的能力之后，如何在这个版本上继续利用完成RCE，在SQLi之后的利用有一定的系统前置条件

### SQLi

在PandoraFMS 7.0NG.776版本中，存在一个认证前SQL注入，位于 `include/api.php` 中获取token处

```php
$apiToken = (string) getBearerToken();
if (empty($apiToken) === true) {
    $api_password = get_parameter('apipass', '');
    $user = get_parameter('user', '');
    $password = get_parameter('pass', '');
} else {
    $apiTokenValid = (bool) api_token_check($apiToken);
}

function getBearerToken()
{
    $headers = getAuthorizationHeader();
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }

    return false;
}

function getAuthorizationHeader()
{
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER['Authorization']);
    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers = trim($_SERVER['HTTP_AUTHORIZATION']);
    } else if (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }

    return $headers;
}
```

在获取 `Authorization` 头时并没有做更多的过滤，导致这里是完全可控的值，之后调用 `api_token_check`，将可控的http头传入，跟入 `api_token_check` 函数

```php
function api_token_check(string $token)
{
    if (empty($token) === true) {
        return 0;
    } else {
        return db_get_value('id_user', 'tusuario', 'api_token', $token);
    }
}

function db_get_value(
    $field,
    $table,
    $field_search=1,
    $condition=1,
    $search_history_db=false,
    $cache=true
) {
    global $config;

    switch ($config['dbtype']) {
        case 'mysql':
        default:
        return mysql_db_get_value($field, $table, $field_search, $condition, $search_history_db, $cache);

        case 'postgresql':
        return postgresql_db_get_value($field, $table, $field_search, $condition, $search_history_db, $cache);

        case 'oracle':
        return oracle_db_get_value($field, $table, $field_search, $condition, $search_history_db, $cache);
    }
}
```

这里使用 `mysql` 数据库，继续跟入 `mysql_db_get_value`

```php
function mysql_db_get_value(
    $field,
    $table,
    $field_search=1,
    $condition=1,
    $search_history_db=false,
    $cache=true
) {
    if (is_int($condition)) {
        $sql = sprintf(
            'SELECT %s FROM %s WHERE %s = %d LIMIT 1',
            $field,
            $table,
            $field_search,
            $condition
        );
    } else if (is_float($condition) || is_double($condition)) {
        $sql = sprintf(
            'SELECT %s FROM %s WHERE %s = %f LIMIT 1',
            $field,
            $table,
            $field_search,
            $condition
        );
    } else {
        $sql = sprintf(
            "SELECT %s FROM %s WHERE %s = '%s' LIMIT 1",
            $field,
            $table,
            $field_search,
            $condition
        );
    }

    $result = db_get_all_rows_sql($sql, $search_history_db, $cache);

    if ($result === false) {
        return false;
    }

    $row = array_shift($result);
    $value = array_shift($row);

    if ($value === null) {
        return false;
    }

    return $value;
}
```

这里会发现对传入的值也并没有做更多的操作，仅仅是进行了简单的字符串拼接之后就传入了 `db_get_all_rows_sql`，在这个函数中也并没有继续做过滤操作，最终拼接后的 `$sql` 将会走到 `mysqli_query` 执行，导致SQL注入。


### SQLi利用

这个注入很难用的一个地方是，没有任何回显并且在注入完成之后，由于 `$correctLogin` 的值无法被我们影响，导致必定会走到else的分支中只会打印一个 `auth error`，从而让这个注入只能做延时，而延时又会因为其中硬编码了一个 `sleep(15)` 使利用变的非常恶心。

```php
if ($correctLogin === true) {
    /* ... */
} else {
    /*
     * //TODO: Implement a new switch in config to enable / disable
     * ACL auth failure: if enabled and have lots of traffic can produce
     * millions of records and a considerable OVERHEAD in the system :(
     * db_pandora_ audit("API access Failed", $no_login_msg, $user, $ipOrigin);
     */

    sleep(15);

    // Protection on DoS attacks.
    echo 'auth error';
}
```

后面考虑到使用正常延时会非常耗费时间，这个系统很多东西都是使用uuid，那么逐位跑完一条记录可能得1个小时成本非常高，如下所示

![](/img/pandorafms-7.0ng-sqli-rce/1.png)

后面考虑用二分法+控制每一位开单独的goroutine去跑，差不多可能将时间控制在15分钟左右

由于整个系统都使用session做认证，所以需要考虑如何通过这个注入来完成认证，首先由于用户密码在数据库中是bcrypt后的hash，没有办法走这一条路。注入点处由于后续会有一个ipacl的判断，这个acl中默认只有一个127.0.0.1，也没有办法利用。所以只能想办法看看有没有什么其他的方法。

万幸的是后续在系统中确实找到了一处有别于用户名密码的认证方式，在 `/ajax.php` 中，有一段代码

```php
// Hash login process.
if (isset($_GET['loginhash']) === true) {
    $loginhash_data = get_parameter('loginhash_data', '');
    $loginhash_user = str_rot13(get_parameter('loginhash_user', ''));

    if ($config['loginhash_pwd'] != ''
        && $loginhash_data == md5(
            $loginhash_user.io_output_password($config['loginhash_pwd'])
        )
    ) {
        db_logon($loginhash_user, $_SERVER['REMOTE_ADDR']);
        $_SESSION['id_usuario'] = $loginhash_user;
        $config['id_user'] = $loginhash_user;
    } else {
        include_once 'general/login_page.php';
        db_pandora_audit(
            AUDIT_LOG_USER_REGISTRATION,
            'Loginhash failed',
            'system'
        );
        while (ob_get_length() > 0) {
            ob_end_flush();
        }

        exit('</html>');
    }
}
```

这里的 `$config['loginhash_pwd']` 也就是数据库 `tconfig` 中对应的记录，如果能通过注入读到这个值，就可以通过构造一个对应的md5来对session赋值一个合法的用户名，从而跳过下面的 `check_login`，这里就是前置所在，因为这个值默认是空，而如果这个值为空就根本不会做判断

![](/img/pandorafms-7.0ng-sqli-rce/2.png)

### RCE

至此，完成了SQLi到认证的过程，之后找到了一个比较简单的文件上传绕过，在文件 `godmode\files_repo\files_repo.php` 中，如果有请求且为新增文件，则会调用 `files_repo_add_file` 进行处理

```php
if ($add_file === true || ($update_file === true && $file_id > 0)) {
    $groups = get_parameter('groups', []);
    $public = (bool) get_parameter('public');
    $description = io_safe_output((string) get_parameter('description'));
    if (mb_strlen($description, 'UTF-8') > 200) {
        $description = mb_substr($description, 0, 200, 'UTF-8');
    }

	    $description = io_safe_input($description);

    if ($add_file === true) {
        $result = files_repo_add_file('upfile', $description, $groups, $public);
```

函数定义在 `include\functions_files_repository.php` 中，去除其他业务代码后如下

```php
if ($upload_result === true) {
	$filename = $_FILES[$file_input_name]['name'];

	// Invalid extensions.
	$extension = pathinfo($filename, PATHINFO_EXTENSION);
	$invalid_extensions = '/^(php|php1|php2|php3|php4|php5|php7|php8|phar|phptml|phps)$/i';

	if (preg_match($invalid_extensions, $extension) === 0) {
		// Replace conflictive characters.
		$filename = str_replace([' ', '=', '?', '&'], '_', $filename);
		$filename = filter_var($filename, FILTER_SANITIZE_URL);
		// The filename should not be larger than 200 characters.
		if (mb_strlen($filename, 'UTF-8') > 200) {
			$filename = mb_substr($filename, 0, 200, 'UTF-8');
		}

		$hash = '';
		if ($public) {
			$hash = md5(time().$config['dbpass']);
			$hash = mb_substr($hash, 0, 8, 'UTF-8');
		}

		$values = [
			'name'        => $filename,
			'description' => $description,
			'hash'        => $hash,
		];
		$file_id = db_process_sql_insert('tfiles_repo', $values);

		if ($file_id) {
			$file_tmp = $_FILES[$file_input_name]['tmp_name'];
			$destination = $files_repo_path.'/'.$file_id.'_'.$filename;

			if (move_uploaded_file($file_tmp, $destination)) {
```

可以看到其中对文件名做了处理，而这里的正则界定了首尾，导致在文件末尾增加空白字符即可绕过判断，之后会有一次字符串替换，这里将空格替换为了下划线，但是仍然可以使用 `%0d` 这些字符进行绕过，之后计算了hash做入库处理，调用 `move_uploaded_file` 完成文件移动，真实文件名为 `入库ID_文件名.php`

但是这里由于 `.htaccess`，会导致及时成功上传了php文件也无法访问，当前docker环境中，只解析 `php` 这个后缀，所以无法通过上传 `phtml` 等后缀进行直接访问

```shell
root@9415a5c3eeac:/var/www/html/pandora_console/attachment# cat .htaccess
#Order deny,allow
#Deny from All
#Allow from localhost

#pandora disable phpexec
<FilesMatch "\.(txt|php)$">
Deny from all
Allow from localhost
```

但这里可以直接使用 `ajax.php` 中的文件包含来进行访问

```php

$page = (string) get_parameter('page');
$page = safe_url_extraclean($page);
$page .= '.php';
$page = realpath($page);
$public_hash = get_parameter('auth_hash', false);
$public_login = false;

# check login code ...

if (file_exists($page) === true) {
    include_once $page;
} else {
    echo '<br /><b class="error">Sorry! I can\'t find the page '.$page.'!</b>';
}
```

文件上传的请求包如下

![](/img/pandorafms-7.0ng-sqli-rce/3.png)

之后通过 `ajax.php` 进行包含，实现RCE

![](/img/pandorafms-7.0ng-sqli-rce/4.png)
