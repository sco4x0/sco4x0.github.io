---
title: "拟态防御赛2019 easy_web出题记录"
date: 2019-06-04T17:35:26+08:00
tags: ["拟态防御赛", "writeup"]
---

起因是在 `wargame.kr` 上有一道题 `DB is really GOOD`, 有一个点是如果输入 `/` 就会因为路径被分割掉无法访问到指定的sqlite数据库，导致报错，从而获得完整数据库名来下载到整个db文件

![](/img/mimic-2019-easy-web-writeup/1.png)

感觉这个点很有趣，刚好今年拟态需要出个常规的CTF题，干脆就想着在这个基础上来增加一些更有意思的做法，于是就有了这个题

---

题目打开后只有一个登录框，而且只有一个用户名的输入框

![](/img/mimic-2019-easy-web-writeup/2.png)

这里会发现不管输入什么东西都直接将用户名存入session，跳转了过去，并且会发现这里将输入用户名中的 `.` 替换成了 `_`，成功登录后会发现这里有一个提示，可以上传某些特定文件

![](/img/mimic-2019-easy-web-writeup/3.png)

如果随便上传一些文件的话，会在当前页面中将文件内容显示出来，而且可以访问到上传的文件本身

![](/img/mimic-2019-easy-web-writeup/5.png)

如果这里尝试上传zip文件的话就会发现不一样的地方，因为这个地方会尝试对zip做解压操作，处理上传的代码为

```php
 private function check_mime() {
    $info = array(
        'file_type' => 'text',
        'file_path' => './uploads/' . $this->filename,
        'file_size' => $this->get_size(filesize($this->file)),
        'file_hash' => md5($this->file),
    );
    $type = strtolower(mime_content_type($this->file));
    switch ($type){
        case 'text/php':
        case 'text/x-php':
            $this->status = 'failed';break;
        case 'text/plain':
            $this->info = @serialize($info);break;
        case 'image/png':
        case 'image/gif':
        case 'image/jpeg':
            $info['file_type'] = 'image';
            $this->info = @serialize($info);break;
        case 'application/zip':
            $info['file_type'] = 'zip';
            $info['file_list'] = $this->handle_ziparchive();
            $this->info = @serialize($info);
            $this->flag = false;break;
        default:
            $info['file_type'] = 'other';
            $this->info = @serialize($info);break;
            break;
    }
}

private function handle_ziparchive() {
    try{
        $file_list = array();
        $zip = new PclZip($this->file);
        $save_dir = './uploads/' . substr($this->filename, 0, strlen($this->filename) - 4);
        @mkdir($save_dir, 755);
        $res = $zip->extract(PCLZIP_OPT_PATH, $save_dir, PCLZIP_OPT_EXTRACT_DIR_RESTRICTION, '/var/www/html' , PCLZIP_OPT_BY_PREG,'/^(?!(.*)\.ph(.*)).*$/is');
        foreach ($res as $k => $v) {
            $file_list[$k] = array(
                'name' => $v['stored_filename'],
                'size' => $this->get_size($v['size'])
            );
        }
        return $file_list;
    }
    catch (Exception $ex) {
        print_r($ex);
        $this->status = 'failed';
    }
}
```

这里限制了解压出来php文件的可能，并且在apache中做了设置，所以上传 `.htaccess` 也不会正常解析到php

回到一开始的登录，这个地方就是在 `wargame.kr` 上提到的那个点，所以直接输入 `/` 可以得到一个报错信息

![](/img/mimic-2019-easy-web-writeup/4.png)

那么这里就可以直接访问 `http://xxx/dbs/mimic_{username}.db` 来下载当前用户的数据库了

![](/img/mimic-2019-easy-web-writeup/6.png)

这里可以发现，其中存的数据都是php序列化后的结果，而上传处的zip解压，其实是可以跨目录的

那么将数据库中的数据做一下修改，比如直接将txt类型的文件 `file_path` 改成flag文件地址，然后通过zip解压跨目录，将制定的db文件上传回dbs目录中，登录对应的用户名，访问目标txt文件，即可得到flag

这里在上传中放了一个反序列化的点，最开始其实是把flag名称随机字符串了，需要通过在数据库中构造一个反序列化的文件写入getshell去找flag，后来感觉有点多此一举，干脆就直接放根目录下了

```php
public function __destruct() {
    if($this->flag){
        file_put_contents('./uploads/' . $this->filename , file_get_contents($this->file));
    }
    $this->conn->insert($this->filename, $this->info);
    echo json_encode(array('status' => $this->status));
}
```