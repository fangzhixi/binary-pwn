from pwn import *

io = remote('pwn.challenge.ctf.show', 28285)
io.interactive()