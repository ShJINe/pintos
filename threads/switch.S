#include "threads/switch.h"

#### struct thread *switch_threads (struct thread *cur, struct thread *next);
####
#### Switches from CUR, which must be the running thread, to NEXT,
#### which must also be running switch_threads(), returning CUR in
#### NEXT's context.
####
#### This function works by assuming that the thread we're switching
#### into is also running switch_threads().  Thus, all it has to do is
#### preserve a few registers on the stack, then switch stacks and
#### restore the registers.  As part of switching stacks we record the
#### current stack pointer in CUR's thread structure.

.globl switch_threads
.func switch_threads
switch_threads:
	# Save caller's register state.
	#
	# Note that the SVR4 ABI allows us to destroy %eax, %ecx, %edx,
	# but requires us to preserve %ebx, %ebp, %esi, %edi.  See
	# [SysV-ABI-386] pages 3-11 and 3-12 for details.
	#
	# This stack frame must match the one set up by thread_create()
	# in size.
	pushl %ebx
	pushl %ebp
	pushl %esi
	pushl %edi

	# Get offsetof (struct thread, stack). 
.globl thread_stack_ofs 
	mov thread_stack_ofs, %edx 

	# Save current stack pointer to old thread's stack, if any. # ED stack
	movl SWITCH_CUR(%esp), %eax   # %eax用作返回值
	movl %esp, (%eax,%edx,1)

	# 至此，cur线程的switch_thread_frame构建完成，但switch_thread函数调用没有完成
	# 下面将堆栈切换到next线程的堆栈，释放上次切换时创建的switch_thread_frame页帧，结束switch_thread的函数调用

	# Restore stack pointer from new thread's stack.
	movl SWITCH_NEXT(%esp), %ecx
	movl (%ecx,%edx,1), %esp

	# Restore caller's register state.
	popl %edi
	popl %esi
	popl %ebp
	popl %ebx
        ret
	# 返回时弹出eip并将esp继续上移越过参数cur*和next*，至此，next线程的switch_thread_frame页帧完全被释放，switch_thread的函数调用完成，接下来是激活当前线程的页表(thread_schedule_tail / switch_entry)
	# 返回%eax作为prev，其中是cur线程的地址。
.endfunc

.globl switch_entry
.func switch_entry
switch_entry:
	# Discard switch_threads() arguments.
	addl $8, %esp  # 因为第一次切换时next线程没有通过函数调用的方式运行switch_thread，因此页帧中的参数cur和next需要手动清除(函数调用返回时编译器会自动加入清除代码移动esp弹出参数)

	# Call thread_schedule_tail(prev).  # 第一次运行线程切换，除了前面一步这里和其他线程切换一样
	pushl %eax  # 手动将传递的参数入栈
.globl thread_schedule_tail
	call thread_schedule_tail  # 调用thread_schedule_tail函数
	addl $4, %esp  # 手动清除参数(这里手动的部分是用汇编语言模拟C语言的函数调用，c语言中编译器会完成这些手动的步骤)

	# Start thread proper.
	ret
.endfunc
