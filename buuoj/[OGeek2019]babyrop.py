from pwn import *


def OGeek2019_babyrop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/[OGeek2019]babyrop'):
    print('[OGeek2019]babyrop start')
    target = process([file_name])
    # target = remote('node4.buuoj.cn', 25114)

    gdb.attach(target, 'b *0x08048748')
    target.interactive()

    print('[OGeek2019]babyrop end')


if __name__ == '__main__':
    OGeek2019_babyrop()
