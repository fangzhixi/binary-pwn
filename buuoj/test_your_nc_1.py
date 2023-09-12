from pwn import *

def test_your_nc_1(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/test_your_nc1'):
    print('test_your_nc1 start')
    target = remote('node4.buuoj.cn', 25525)
    target.interactive()
    print('test_your_nc1 end')


if __name__ == '__main__':
    test_your_nc_1()
