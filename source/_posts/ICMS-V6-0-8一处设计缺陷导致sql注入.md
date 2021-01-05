---
title: ICMS V6.0.8一处设计缺陷导致sql注入
categories: technology
date: 2015-08-31 16:07:28
tags: [icms, sql注入, 代码审计]
---

看到user.app.php文件中私信发送的方法

```php
<?php
    public function ACTION_pm(){
    
            $this->auth OR iPHP::code(0,'iCMS:!login',0,'json');
    
            $receiv_uid = (int)$_POST['uid'];
    
            $content    = iS::escapeStr($_POST['content']);
    
            $receiv_uid OR iPHP::code(0,'iCMS:error',0,'json');
    
            $content OR iPHP::code(0,'iCMS:pm:empty',0,'json');
    
            $receiv_name = iS::escapeStr($_POST['name']);
    
            $send_uid  = user::$userid;
    
            $send_name = user::$nickname;
    
            $fields = array('send_uid','send_name','receiv_uid','receiv_name','content');
    
            $data  = compact ($fields);
    
            msg::send($data,1);
    
            iPHP::code(1,'iCMS:pm:success',$id,'json');
    
        }
```

其中POST传入了Content和Name，跟入escapeStr方法

```php
<?php
    public static function escapeStr($string) {
    
            if(is_array($string)) {
    
                foreach($string as $key => $val) {
    
                    $string[$key] = iS::escapeStr($val);
    
                }
    
            } else {
    
                $string = str_replace(array('%00','\\0'), '', $string); //modified@2010-7-5
    
                $string = str_replace(array('&', '"',"'", '<', '>'), array('&', '"',''', '<', '>'), $string);
    
                $string = preg_replace('/&((#(\d{3,5}|x[a-fA-F0-9]{4})|[a-zA-Z][a-z0-9]{2,5});)/', '&\\1',$string);
    
            }
    
            return $string;
    
        }
```

可以看到特殊符号中过滤了几个常见，但是遗漏了一个 \ ，问题就出在这个地方，回到user.app.php中，往下走，可以看到所有参数都进入了msg::send方法，继续跟入这个方法

```php
<?php
    public static function send($a = array(
    
                "send_uid"    => 0,"send_name"  => NULL,
    
                "receiv_uid"  => 0,"receiv_name" => NULL,
    
                "content"    => NULL
    
            ),$type=1){
    
            // $userid = (int)$a['userid'];
    
            // $friend = (int)$a['friend'];
    
            $send_uid    = (int)$a['send_uid'];
    
            $send_name  = iS::escapeStr($a['send_name']);
    
            $receiv_uid  = (int)$a['receiv_uid'];
    
            $receiv_name = iS::escapeStr($a['receiv_name']);
    
            $content  = iS::escapeStr($a['content']);
    
            $sendtime = time();
    
            if($send_uid && $send_uid==$receiv_uid && !$a['self']){
    
                return;
    
            }
    
            $fields = array('userid', 'friend', 'send_uid', 'send_name', 'receiv_uid', 'receiv_name', 'content', 'type', 'sendtime', 'readtime', 'status');
    
            $data  = compact ($fields);
    
            $data['userid']  = $send_uid;
    
            $data['friend']  = $receiv_uid;
    
            $data['readtime'] = "0";
    
            $data['status']  = "1";
    
            iDB::insert('message',$data);
    
            if($type=="1"){
    
                $data['userid']  = $receiv_uid;
    
                $data['friend']  = $send_uid;
    
                iDB::insert('message',$data);
    
            }
    
        }
```

在这里面将id强转成了int类型，然后再次用escapeStr过滤了一下name和content,然后组合成数组传入了insert方法，跟入mysql中的insert方法

```php
<?php
    public static function insert($table, $data) {
    //      $data = add_magic_quotes($data);
    
            $fields = array_keys($data);
    
            self::query("INSERT INTO ".iPHP_DB_PREFIX_TAG."{$table} (`" . implode('`,`',$fields) . "`) VALUES ('".implode("','",$data)."')");
    
            return self::$insert_id;
    
        }
```

直接就query了，这么一来就可以用\吃掉单引号

私信这个地方结构是

```sql
    INSERT INTO icms_message (`send_uid`,`send_name`,`receiv_uid`,`receiv_name`,`content`,`type`,`sendtime`,`userid`,`friend`,`readtime`,`status`)
```

![b081309f816b389bb8b6309325cb023e.png](/images/b081309f816b389bb8b6309325cb023e.png)