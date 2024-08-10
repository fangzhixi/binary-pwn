from pwn import *


def springboard():
    file_name = r'/mnt/hgfs/CyberSecurity/reverse/CTF线上赛/buuoj DASCTF 2024暑期挑战赛 20240720/pwn/springboard/pwn'
    print("springboard start")
    target = process([file_name])
    # target = remote('node5.buuoj.cn', 26803)
    target_elf = ELF(file_name)

    payload = b'a' * 40
    print(target.recvuntil('Please enter a keyword'))
    target.sendline(payload)

    print("springboard end")


if __name__ == '__main__':
    springboard()
