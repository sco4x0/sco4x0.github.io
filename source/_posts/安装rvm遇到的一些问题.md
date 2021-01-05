---
title: 安装rvm遇到的一些问题
categories: technology
date: 2015-06-23 16:06:47
tags: [rvm]
---

捣鼓jekyll遇到的一些问题
用rvm官方推荐的方式安装
```
curl -L get.rvm.io | bash -s stable
```
但是会发现在安装过程中出现了gpg验证出错的问题
然后根据提示执行命令
```
curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -
```
这里可能会提示没安装gnupg2，` sudo apt-get install gnupg2 `

然后再安装RVM，看到其中的回显：`Installing RVM to /home/sco4x0/.rvm`

载入rvm的环境变量 `source ~/.rvm/scripts/rvm`

`rvm -v` 查看版本，是否正确安装，然后就可以rvm install xxx安装ruby了