#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

typedef void syscall_server_func (struct intr_frame *);
static syscall_server_func* syscall_list[20];

/* 1 exit */
static void
syscall_exit_func (struct intr_frame *f)
{
  void *p = f->esp;
  p += sizeof(int);

  int status = *(int *)p;
  printf("\ndebugger:-------\nstatus: %d\n", status);
  thread_exit();
}

/* 9 write */
static void
syscall_write_func (struct intr_frame *f)
{
  void *p = f->esp;
  p += sizeof(int); /* skip Member*/
  
  int fd = *(int *)p;
  p += sizeof(int);
  
  const void* buf = *(const void **)p;
  p += sizeof(const void *);
  
  unsigned size = *(int *)p;
  *(char*)(buf + size) = '\0'; // 控制内部缓冲区
  printf("%s", (char *)buf);
  // printf ("\n debugger:-------\nfd: %d\nbuf ptr:%0p\nbuf: %s\nsize: %u\n\n", fd, buf, (char *)buf, size); // printf 内部含有缓冲区，每次的buf值都为bffffef4
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_list[SYS_EXIT] = syscall_exit_func;   /* 1 */
  syscall_list[SYS_WRITE] = syscall_write_func; /* 9 */
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("MEMBER: %d",*(int*)(f->esp));
  // printf ("system call!\n");
  syscall_server_func* func = syscall_list[*(int*)(f->esp)];
  func (f);
}

