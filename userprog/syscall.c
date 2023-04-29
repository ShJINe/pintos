#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "devices/input.h"
#include "lib/kernel/console.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "lib/user/syscall.h"
#include "devices/shutdown.h"
#include "process.h"

#define MEMBER 0
#define ARG_0  4
#define ARG_1  8
#define ARG_2 12
#define ARG_3 16
#define ARG_SIZE 4

#define ERROR_ADDR (void*)0xffffffff
#define ERROR_CODE -1
#define MAX_KERNEL_BUF 1024

#define MAX_NUM(a, b) ((a >= b)? a: b)
#define MIN_NUM(a, b) ((a <= b)? a: b)


static void syscall_handler (struct intr_frame *);

typedef void syscall_server_func (struct intr_frame *);
static syscall_server_func* syscall_list[20];

static bool 
access_ok (const void *addr, int size)
{
  // 第一项的作用是检查size是否大于0，同时检查addr+size是否会溢出
  // 第二项防止使用内核段
  if (addr + size < addr || addr + size >= thread_current()->limit_seg)
    return false;
  return true;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const char *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
  /* 若正确返回读取到的数据，若错误则返回page fault的返回值-1 */
}

static int
get_user_4 (const char *uaddr)
{
  int result;
  asm ("movl $1f, %0; movl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

static int
get_user_str (const char *uaddr, char *buf, int size)
{
  int i, c;
  for (i = 0; i < size; i ++)
  {
    c = get_user (uaddr + i);
    if (c == ERROR_CODE)
      break;
    buf[i] = (char)c;
  }
  return i;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (char *udst, char value)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (value));
  return error_code != -1;
  /* 将error code与eax绑定，并赋值0x1f，&表示不能与byte变量用同一个寄存器
     将第二个参数%2以byte的形式(%b2)放入第一个参数的位置%1。
     这里如果引发了缺页中断page fault，返回时会将错误码error code = -1作为
     返回值放在eax中，从而会覆盖掉原来赋值的0x1f，导致最后return false*/
}

static bool
put_user_4 (char *udst, int32_t value)
{
  int error_code;
  asm ("movl $1f, %0; movl %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (value));
  return error_code != -1;
}

static int 
put_user_str (char *udst, char *buf, int size)
{
  int i;
  bool s;
  for (i = 0; i < size; i ++)
  {
    s = put_user (udst + i, buf[i]);
    if (!s)
      break;
  }
  return i;
}

/* 0 halt: (void)->(void) */
static void
syscall_halt_func (struct intr_frame *f UNUSED)
{
  shutdown ();
}

/* 1 exit: (int status)->(void) */
static void
syscall_exit_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 1 * ARG_SIZE))
  {
    int status = get_user_4(f->esp + ARG_0);
    if (status != -1)
    {
      /* 写返回值*/
      thread_current()->exit_status = status;
    }
  }
  /* 出错直接退出，保留默认返回值-1 */
  /* 线程退出，保留struct thread */
  thread_exit (); // 外部中断才会yield on return，内部中断不用清除标志位，也不一定要iret
}

/* 2 exec: (const char *file)->(pid_t) */
static void
syscall_exec_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 1 * ARG_SIZE))
  {
    const char * file_name = (const char *)get_user_4(f->esp + ARG_0);
    if (file_name != ERROR_ADDR)
    {
      int name_len = strlen(file_name);
      // printf("file_name:%s", file_name);
      if (access_ok(file_name, name_len) && name_len < MAX_KERNEL_BUF)
      {
        char kernel_buf[MAX_KERNEL_BUF];
        int count = get_user_str (file_name, kernel_buf, name_len);
        kernel_buf[count] = '\0';
        if (count == name_len)
        {
          f->eax = process_execute(kernel_buf);
          return ;
        }
      } 
    }
  }
  f->eax = -1;
  return ;
}

/* 3 wait: (pid_t pid)->(pid_t) */
static void
syscall_wait_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 1 * ARG_SIZE))
  {
    tid_t pid = get_user_4(f->esp + ARG_0);
    if (pid != ERROR_CODE)
    {
      f->eax = process_wait (pid); 
      return ;
    }
  }
  f->eax = -1;
  return ;
}

/* 4 create: (const char *file, unsigned initial_size)->(bool) */
static void
syscall_create_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 2 * ARG_SIZE))
  {
    const char *file_name = (const char *)get_user_4(f->esp + ARG_0);
    int initial_size = get_user_4(f->esp + ARG_1);
    if (file_name != ERROR_ADDR && initial_size != ERROR_CODE)
    {
      int name_len = strlen(file_name);
      if (access_ok(file_name, name_len) && name_len < MAX_KERNEL_BUF)
      {
        char kernel_buf[MAX_KERNEL_BUF];
        int count = get_user_str(file_name, kernel_buf, name_len);
        kernel_buf[count] = '\0';
        if (count == name_len)
        {
          f->eax = filesys_create (kernel_buf, initial_size);
          return ;
        }
      }
    }
  }
  f->eax = 0;
  return ;
}

/* 5 remove: (const char *file)->(bool) */
static void
syscall_remove_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 1 * ARG_SIZE))
  {
    const char *file_name = (const char *)get_user_4(f->esp + ARG_0);
    if (file_name != ERROR_ADDR)
    {
      int name_len = strlen(file_name);
      if (access_ok(file_name, name_len) && name_len < MAX_KERNEL_BUF)
      {
        char kernel_buf[MAX_KERNEL_BUF];
        int count = get_user_str (file_name, kernel_buf, name_len);
        kernel_buf[count] = '\0';
        if (count == name_len)
        {
          f->eax = filesys_remove (kernel_buf);
          return ;
        }
      }
    }
  }
  f->eax = 0;
  return ;
}

/* 6 open: (const char *file)->(int) */
static void 
syscall_open_fun (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 1 * ARG_SIZE))
  {
    const char *file_name = (const char *)get_user_4(f->esp + ARG_0);
    if (file_name != ERROR_ADDR)
    {
      int name_len = strlen(file_name);
      if (access_ok(file_name, name_len) && name_len < MAX_KERNEL_BUF)
      {
        char kernel_buf[MAX_KERNEL_BUF];
        int count = get_user_str(file_name, kernel_buf, name_len);
        kernel_buf[count] = '\0';
        if (count == name_len)
        {
          // printf("open:%s\n",file_name);
          struct file* file = filesys_open(kernel_buf);
          if (file != NULL)
          {
            // protect_exec (file); /* 将可执行文件设置为拒绝写入 */
            f->eax = file_set_fd(file);
            return ;
          }
        }
      }
    }
  }
  f->eax = -1;
  return ;
}

/* 7 filesize: (int fd)->(int) */
static void
syscall_filesize_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 1 * ARG_SIZE))
  {
    int fd = get_user_4(f->esp + ARG_0);
    if (fd != ERROR_CODE)
    {
      struct file* file = fd_get_file (fd);
      if (file != NULL)
      {
        f->eax = file_length (file);
        return ;
      }
    }
  }
  f->eax = -1;
  return ;
}

/* 8 read: (int fd, void *buffer, unsigned size)->(int) */
static void 
syscall_read_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 3 * ARG_SIZE))
  {
    int fd = get_user_4(f->esp + ARG_0);
    char *buf = (char *)get_user_4(f->esp + ARG_1);
    int size = get_user_4(f->esp + ARG_2);
    if (fd != ERROR_CODE && size != ERROR_CODE && buf != ERROR_ADDR && access_ok(buf, size))
    {
      int read_count, write_count, all_read_count = 0;
      char kernel_buf [MAX_KERNEL_BUF];
      if (fd == 0)
      {
        read_count = MIN_NUM(size-all_read_count, MAX_KERNEL_BUF);
        int i;
        while (read_count != 0)
        {
          for (i = 0; i < read_count; i ++)
            kernel_buf[i] = input_getc();
          write_count = put_user_str(buf + all_read_count, kernel_buf, read_count);
          all_read_count += write_count;
          read_count = MIN_NUM(size - all_read_count, MAX_KERNEL_BUF);
        }
        f->eax = all_read_count;
        return ;
      }
      else
      {
        struct file *file = fd_get_file(fd);
        if (file != NULL)
        {
          read_count = MIN_NUM(size-all_read_count, MAX_KERNEL_BUF);
          while (read_count != 0)
          {
            write_count = file_read(file, kernel_buf, read_count);
            write_count = put_user_str(buf + all_read_count, kernel_buf, write_count);
            all_read_count += write_count;
            if (write_count < read_count)
              break;
            read_count = MIN_NUM(size-all_read_count, MAX_KERNEL_BUF);
          }
          f->eax = all_read_count;
          return ;
        }
      }
    }
  }
  thread_exit();
  f->eax = -1;
  return ;
}

/* 9 write: (int fd, const void *buffer, unsigned size)->(int) */
static void
syscall_write_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 3 * ARG_SIZE))
  {
    int fd = get_user_4(f->esp + ARG_0);
    const char *buf = (const char*)get_user_4(f->esp + ARG_1);
    int size = get_user_4(f->esp + ARG_2);
    if (fd != ERROR_CODE && size != ERROR_CODE && buf != ERROR_ADDR && access_ok(buf, size))
    {
      int read_count, write_count, all_write_count = 0;
      char kernel_buf[MAX_KERNEL_BUF];
      if (fd == 1)
      {
        read_count = MIN_NUM(size - all_write_count, MAX_KERNEL_BUF);
        while (read_count != 0)
        {
          write_count = get_user_str (buf + all_write_count, kernel_buf, read_count);
          putbuf(kernel_buf, write_count);
          all_write_count += write_count;
          if (write_count < read_count)
            break ;
          read_count = MIN_NUM(size - all_write_count, MAX_KERNEL_BUF);
        }
        f->eax = all_write_count;
        return ;
      }
      else
      {
        struct file *file = fd_get_file(fd);
        if (file != NULL)
        {
          read_count = MIN_NUM(size - all_write_count, MAX_KERNEL_BUF);
          while (read_count != 0 )
          {
            write_count = get_user_str (buf + all_write_count, kernel_buf, read_count); /* 读失败 page fault*/
            write_count = file_write(file, kernel_buf, write_count); /* 写拒绝 or 超过文件大小 */
            all_write_count += write_count;
            if (write_count < read_count)
              break ;
            read_count = MIN_NUM(size - all_write_count, MAX_KERNEL_BUF);
          }
          // printf("\nall_write_count = %d\n", all_write_count);
          f->eax = all_write_count;
          return ;
        }
      }
    }
  }
  f->eax = -1;
  return ;
}

/* 10 seek: (int fd, unsigned position)->(void) */
static void
syscall_seek_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 2 * ARG_SIZE))
  {
    int fd = get_user_4(f->esp + ARG_0);
    int position = *(int *)(f->esp + ARG_1);
    if (fd != ERROR_CODE && position != ERROR_CODE)
    {
      struct file* file = fd_get_file (fd);
      if (file != NULL && position <= file_length (file))
      {
        file_seek (file, position);
        return ;
      }
    }
  }
  return ;
}

/* 11 tell: (int fd)->(unsigned) */
static void
syscall_tell_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 1 * ARG_SIZE))
  {
    int fd = get_user_4(f->esp + ARG_0);
    if (fd != ERROR_CODE)
    {
      struct file* file = fd_get_file (fd);
      if (file != NULL)
      {
        f->eax = file_tell (file);
        return ;
      }
    }
  }
  f->eax = -1;
  return ;
}

/* 12 close: (int fd)->(void) */
static void
syscall_close_func (struct intr_frame *f)
{
  if (access_ok(f->esp + ARG_SIZE, 1 * ARG_SIZE))
  {
    int fd = get_user_4(f->esp + ARG_0);
    if (fd != ERROR_CODE)
    {
      struct file* file = fd_remove_file (fd);
      if (file != NULL)
      {
        file_close (file);
        return ;
      }
    }
  }
  return ;
}

/* 13 mmap: ()->() */
static void
syscall_mmap_func (struct intr_frame *f UNUSED)
{

}

/* 14 munmap: ()->() */
static void
syscall_munmap_func (struct intr_frame *f UNUSED)
{

}

/* 15 chdir: ()->() */
static void
syscall_chdir_func (struct intr_frame *f UNUSED)
{

}

/* 16 mkdir: ()->() */
static void
syscall_mkdir_func (struct intr_frame *f UNUSED)
{

}

/* 17 readdir: ()->() */
static void
syscall_readdir_func (struct intr_frame *f UNUSED)
{

}

/* 18 isdir: ()->() */
static void
syscall_isdir_func (struct intr_frame *f UNUSED)
{

}

/* 19 inumber: ()->() */
static void
syscall_inumber_func (struct intr_frame *f UNUSED)
{

}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_list[SYS_HALT] = syscall_halt_func;          /* 0 */
  syscall_list[SYS_EXIT] = syscall_exit_func;          /* 1 */
  syscall_list[SYS_EXEC] = syscall_exec_func;          /* 2 */
  syscall_list[SYS_WAIT] = syscall_wait_func;          /* 3 */
  syscall_list[SYS_CREATE] = syscall_create_func;      /* 4 */
  syscall_list[SYS_REMOVE] = syscall_remove_func;      /* 5 */
  syscall_list[SYS_OPEN] = syscall_open_fun;           /* 6 */
  syscall_list[SYS_FILESIZE] = syscall_filesize_func;  /* 7 */
  syscall_list[SYS_READ] = syscall_read_func;          /* 8 */
  syscall_list[SYS_WRITE] = syscall_write_func;        /* 9 */
  syscall_list[SYS_SEEK] = syscall_seek_func;          /* 10 */
  syscall_list[SYS_TELL] = syscall_tell_func;          /* 11 */
  syscall_list[SYS_CLOSE] = syscall_close_func;        /* 12 */
  syscall_list[SYS_MMAP] = syscall_mmap_func;          /* 13 */
  syscall_list[SYS_MUNMAP] = syscall_munmap_func;      /* 14 */
  syscall_list[SYS_CHDIR] = syscall_chdir_func;        /* 15 */
  syscall_list[SYS_MKDIR] = syscall_mkdir_func;        /* 16 */
  syscall_list[SYS_READDIR] = syscall_readdir_func;    /* 17 */
  syscall_list[SYS_ISDIR] = syscall_isdir_func;        /* 18 */
  syscall_list[SYS_INUMBER] = syscall_inumber_func;    /* 19 */
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (access_ok(f->esp, 1 * ARG_SIZE))
  {
    int member = get_user_4(f->esp + MEMBER);
    // printf("nnnn:%d\n",member);
    /* 检查系统调用号 */
    if (member != ERROR_CODE && member >= 0 && member < 20)
    {
      /* 执行系统调用 */
      syscall_server_func* func = syscall_list[member];
      func (f);
      return ;
    }
  }
  f->eax = -1;
  return ;
}

