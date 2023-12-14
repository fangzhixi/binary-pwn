from ret2_libc1_1 import ret2_libc1
from ret2_libc2_1 import ret2_libc2
from ret2_shellcode1 import ret2_shellcode
from ret2_syscall_1 import ret2_systemcall
from ret2_text1 import ret2_text1
from ret2_text2 import ret2_text2

'''
    常用工具提示:
        1、checksec './ELF文件'
        2、ROPgadget --binary './ELF文件' --only 'pop|ret|int'
        3、gdb -> vmmap
            gdb.attach(process) 监控process执行流
'''


class PwnAutomation:
    @staticmethod
    def start(file_name, interrupt_debug=True):
        # 非中断函数call（int 0x80）
        ret2_text1(file_name)
        ret2_text2(file_name)
        ret2_shellcode(file_name)
        ret2_libc1(file_name)
        ret2_libc2(file_name)

        # 方法涉及调用中断函数call（int 0x80）
        if interrupt_debug:
            ret2_systemcall(file_name)


if __name__ == '__main__':
    f_name = '/mnt/hgfs/CyberSecurity/PWN/ROP/ret2libc2'
    PwnAutomation().start(f_name, False)
