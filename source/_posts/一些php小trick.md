---
title: 一些php小trick
date: 2015-04-09 16:01:49
categories: technology
tags: [php,trick]
---

== 比较运算，它不会去检查条件式的表达式的类型

=== 恒等，它会检查查表达式的值与类型是否相等

NULL,0,”0″,array()使用==和false比较时，都是会返回true的，而使用===却不会

数组

## 0x01

很多时候，PHP数组都发挥了至关重要的作用，先来看下BOSTEN KEYPARTY中的一道题：

```php
<?php
    if (isset($_GET['name']) and isset($_GET['password'])) {
        if ($_GET['name'] == $_GET['password'])
            print 'Your password can not be your name.';
        else if (sha1($_GET['name']) === sha1($_GET['password']))
            die('Flag: '.$flag);
        else
            print 'Invalid password';
    }
```

这道题，我们首先要确保name和password的值不能相同，其次，sha1加密之后的name和password的值又必须完全相同 我们知道，这时的a[0] = 1;所以name[] = 1和password[]= 2相比较，可以跳过第一个判断，而如果使用sha1对一个数组进行加密，返回的将是NULL，NULL===NULL，这是成立的，所以构造两个数组，成功拿到flag

## 0x02

再看bosten keyparty上的另外一道题：

```php
<?php
    if (isset($_GET['password'])) {  
        if (strcmp($_GET['password'], $flag) == 0)  
            die('Flag: '.$flag);  
        else  
            print 'Invalid password';  
    }
```

这里，使用strcmp去比较password和flag，如果==0的话，就给出flag，但是strcmp比较，如果相等才会返回0，如果不相等的话，要么大于0，要么小于0，但是strcmp只会处理字符串参数，如果给个数组的话呢，就会返回NULL,而判断使用的是==，NULL==0是bool(true)的，所以，这道题还是一如既往构造一个数组进去

## 0x03

bosten keyparty上的又又一道题：

```php
<?php
    if (isset ($_GET['password'])) {  
        if (ereg ("^[a-zA-Z0-9]+[        DISCUZ_CODE_2        ]quot;, $_GET['password']) === FALSE)  
            echo 'You password must be alphanumeric';  
        else if (strpos ($_GET['password'], '--') !== FALSE)  
            die('Flag: ' . $flag);  
        else  
            echo 'Invalid password';  
    }
```

这道题有两种做法，我们还是先说数组 ereg是处理字符串的，所以，按照原理，我们将password构造一个arr[]，传入之后，ereg是返回NULL的，===判断NULL和FALSE，是不相等的，所以可以进入第二个判断，而strpos处理数组，也是返回NULL，注意这里的是!==，NULL!==FALSE,条件成立，拿到flag， 第二种做法，ereg读到%00的时候，就截止了，所以可以构造s%00–，也能拿到flag

数字的比较

## 0x01

wechall上的一道题：

```php
<?php
    function noother_says_correct($number)
    {
            $one = ord('1');
            $nine = ord('9');
            // Check all the input characters!
            for ($i = 0; $i < strlen($number); $i++)
            { 
                    // Disallow all the digits!
                    $digit = ord($number{$i});
                    if ( ($digit >= $one) && ($digit <= $nine) )
                    {
                            // Aha, digit not allowed!
                            return false;
                    }
            }
           return $number == "3735929054";
    }
```

这里，它不让输入1到9的数字，但是后面却让比较一串数字，平常的方法肯定就不能行事了，大家都知道计算机中的进制转换，当然也是可以拿来比较的，0x开头则表示16进制，将这串数字转换成16进制之后发现，是deadc0de，在开头加上0x，代表这个是16进制的数字，然后再和十进制的3735929054比较，答案当然是相同的，返回true拿到flag

## 0x02

看安全宝约宝妹的一道题：

```php
<?php
    $flag = "THIS IS FLAG"; 
    if  ("POST" == $_SERVER['REQUEST_METHOD']) 
    { 
        $password = $_POST['password']; 
        if (0 >= preg_match('/^[[:graph:]]{12,}$/', $password)) 
        { 
            echo 'Wrong Format'; 
            exit; 
        } 
        while (TRUE) 
        { 
            $reg = '/([[:punct:]]+|[[:digit:]]+|[[:upper:]]+|[[:lower:]]+)/'; 
            if (6 > preg_match_all($reg, $password, $arr)) 
                break; 
            $c = 0; 
            $ps = array('punct', 'digit', 'upper', 'lower'); 
            foreach ($ps as $pt) 
            { 
                if (preg_match("/[[:$pt:]]+/", $password)) 
                    $c += 1; 
            } 
            if ($c < 3) break; 
            if ("42" == $password) echo $flag; 
            else echo 'Wrong password'; 
            exit; 
        } 
    }
```

在乌云zone上，X总已经对其进行分析了，http://zone.wooyun.org/content/18650

## switch没有break

在wechall上有一道题：

```php
<?php
    if (isset($_GET['which']))
    {
            $which = $_GET['which'];
            switch ($which)
            {
            case 0:
            case 1:
            case 2:
                    require_once $which.'.php';
                    break;
            default:
                    echo GWF_HTML::error('PHP-0817', 'Hacker NoNoNo!', false);
                    break;
            }
    }
```

让我们包含当前目录中的solution文件，这里会发现在case 0和case 1的时候，没有break，按照常规思维，应该是0比较不成功，进入比较1，然后比较2，再然后进入default，但是事实却不是这样，事实上，在case 0的时候，进入了case 0的方法体，但是却没有break，这个时候，默认判断已经比较成功了，而如果匹配成功之后，会继续执行后面的语句，这个时候，是不会再继续进行任何判断的。也就是说，我们which传入solution的时候，case 0比较进入了方法体，但是没有break，默认已经匹配成功，往下执行不再判断，进入2的时候，执行了require_once solution.php

查阅资料之后发现是继承于C语言，[http://stackoverflow.com/questions/252489/why-was-the-switch-statement-designed-to-need-a-break](http://stackoverflow.com/questions/252489/why-was-the-switch-statement-designed-to-need-a-break
)