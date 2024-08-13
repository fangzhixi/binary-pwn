from pwn import *

def test(file_name = ''):
    print("test_your_nc start")
    target = remote('')