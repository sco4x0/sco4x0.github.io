---
title: "Sciencelogic php代码还原"
date: 2025-03-05T11:15:11+08:00
tags: ["sciencelogic","php"]
---

一个加密后的文件内容hex如下

```
00000000  53 5f 00 f9 1f 08 00 00  6f 4c 69 53 1e b8 ef 08  |S_......oLiS....|
00000010  06 85 66 d2 12 1f e4 bb  93 c6 2a f6 7c 9d a9 7f  |..f.......*.|...|
00000020  49 95 5d 39 73 dd e6 55  30 2b f9 58 a4 16 00 00  |I.]9s..U0+.X....|
00000030  00 00 00 00 4c 43 3e 2b  f2 7f e6 45 30 8b 94 b0  |....LC>+...E0...|
```

逆向silo.so扩展，可以看到将`zend_compile_file`替换成了`compile_binary_file`

```c
if ( !silo_globals )
{
	silo_globals = 1;
	orig_compile_file = (__int64 (__fastcall *)(_QWORD, _QWORD))zend_compile_file;
	zend_compile_file = compile_binary_file;
}
```

在其中有一个判断和函数调用

```c
if ( v3 <= 0x33 || *((_DWORD *)v4 + 2) != 'SiLo' || *((unsigned int *)v4 + 1) > v3 || (int)silo_bin_load_file() < 0 )
	goto LABEL_3;
```

这里的 `SiLo` 是个可见的明文字符，应该是magic number，之后关注到函数 `silo_bin_load_file`，从函数名来看也比较像是一个解密文件的，在函数中一开始做了一个crc校验

```c
else
{
	v5 = a1 + 1;
	v6 = (__int64)a1 + v4;
	v7 = -1;
	do
	{
		v8 = v7;
		v9 = *v5++ ^ v7;
		v7 = crc32tab[v9] ^ (v8 >> 8);
	}
	while ( (_BYTE *)v6 != v5 );
	v10 = (unsigned int)~v7;
}
v11 = *a1;
if ( (_DWORD)v11 != (_DWORD)v10 )
{
	zend_error(2LL, "CRC mismatch: %d != %d", v10, v11);
	return 0xFFFFFFFFLL;
}
```

暂时不用管怎么校验，关注到下方的解密函数

```c
v20 = a1[1];
v12 = v20 - 52LL;
v13 = (char *)_emalloc(v12);
memcpy(v13, a1 + 13, v12);
v22 = a1[1] - 52;
v14 = EVP_CIPHER_CTX_new();
if ( !v14 )
	goto LABEL_21;
v15 = EVP_aes_256_cfb128();
if ( (unsigned int)EVP_DecryptInit_ex(v14, v15, 0LL, &silo_bin_key, a1 + 3) != 1
|| (unsigned int)EVP_DecryptUpdate(v14, v13, &v25, v13, v22) != 1
|| (unsigned int)EVP_DecryptFinal_ex(v14, &v13[v25], &v25) != 1 )
{
```

这里根据后续的解密函数参数可以知道，整个加密文件应该解密的长度应该`文件长度-52`，其次这里的`silo_bin_key`是一个硬编码的值，因为加密方式是 `EVP_aes_256_cfb128`，所以直接从0x20开始一共取32位即可获得decrypt key

![](/img/sciencelogic-php-decrypt/1.png)

之后需要关注到iv的值应该是多少，这里可以看到是 `a1+3` 看起来好像是直接从文件内容中取，但是不知道此时`a1`指向哪里

```c
.text:00000000000036F6                 call    _EVP_CIPHER_CTX_new
.text:00000000000036FB                 mov     r14, rax
.text:00000000000036FE                 test    rax, rax
.text:0000000000003701                 jz      loc_38D8
.text:0000000000003707                 call    _EVP_aes_256_cfb128
.text:000000000000370C                 xor     edx, edx
.text:000000000000370E                 mov     r8, r15
.text:0000000000003711                 mov     rdi, r14
.text:0000000000003714                 lea     rcx, silo_bin_key ; " �����ad.Q\x02$��z��XG�������0�}�\t�2"...
.text:000000000000371B                 mov     rsi, rax
.text:000000000000371E                 call    _EVP_DecryptInit_ex
```

根据函数传递规则可以知道各自参数的值如下

```
ctx = rdi => r14 => rax = _EVP_CIPHER_CTX_new()
cipher = rsi => rax => _EVP_aes_256_cfb128()
impl = rdx
key = rcx => silo_bin_key
iv = r8 => r15
```

向上寻找r15，可以发现这个值来源于 `rbx+0xc`

![](/img/sciencelogic-php-decrypt/2.png)

rbx的值就是 `silo_bin_load_file` 的第一个参数，也就是文件内容本身

![](/img/sciencelogic-php-decrypt/3.png)

所以iv的值其实就是文件内容 `0xc` 开始的地方取16长度

![](/img/sciencelogic-php-decrypt/4.png)

此时解密之后的内容为

```
gdb-peda$ x/10gx $rbp
0x7ffff3c64800: 0xfe1238db6f6d58d5      0xd854958c30315f9e
0x7ffff3c64810: 0xaf7ad822ce2777f1      0x821dc5d24836d205
0x7ffff3c64820: 0x7d2646e63a25a042      0x33dfbfe417db1522
0x7ffff3c64830: 0xba2ecdb389cb24a4      0xe179c536d6d15dc0
0x7ffff3c64840: 0xd1f3fa750ccf33cc      0xe490a07fa1fc3468
```

但是这明显不是明文，所以对解密后的内容还需要进行一次处理

```c
if ( (unsigned int)inflateInit2_(zlib_ctx, '\xFF\xFF\xFF\xF1', "1.2.11", 112LL) ) {
	zend_error(2LL, "Unable to init zlib for decompression.");
	return 0xFFFFFFFFLL;
}
// ......
memset(v16, 0, v22 + 16);
zlib_ctx[0] = (__int64)decrypt_buf;
LODWORD(zlib_ctx[4]) = v22;
zlib_ctx[3] = (__int64)v16;
LODWORD(zlib_ctx[1]) = v19 - 52;
v20 = inflate(zlib_ctx, 4LL);
inflateEnd(zlib_ctx);
memset(decrypt_buf, 0, size);
```

这里能发现主要使用了一下zlib解压缩，但是需要注意这里的 `inflateInit2_` 中第二个参数设置为 `\xff\xff\xff\xf1`，好像不太对，但是这里的值其实是-15

![](/img/sciencelogic-php-decrypt/5.png)

所以直接设置 `windowBits` 为 -15 将其作为无头的纯deflate流解压即可
 
![](/img/sciencelogic-php-decrypt/6.png)