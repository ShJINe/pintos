#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list[64];

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;


/* load average*/
static fixed_point load_avg;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);



/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);
  
  load_avg = 0;
  
  lock_init (&tid_lock);
  if (thread_mlfqs)
  {
    for (int i = 0; i <= 63 ; i++)
    {
      list_init(&ready_list[i]);
    }
  }
  else
  {
    list_init (&ready_list[0]);
  }
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  // 进入start时esp指向0xf000，page_round_down后esp指向0xe000，原来在栈底（高地址），将栈顶（低地址）的一部分用作放置struct_thread
  initial_thread = running_thread (); 
  // printf("((((%u))))",initial_thread); // 3221282816 0xc000 e000 物理地址0xe000
  init_thread (initial_thread, "main", PRI_DEFAULT); // init线程的初始优先级是default 31
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
  init_finished = true;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started); 

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. 
   这是一个嵌入在中断处理框架中的中断处理程序，每个tick被时钟中断处理程序调用*/
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  if (++thread_ticks >= TIME_SLICE)
  {
    intr_yield_on_return (); // 当当前线程超过时间片TIME_SLICE时，调用该函数，将yield_return置为True，中断框架返回时检查yield_return标志，并执行抢占
  }
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called（开启抢占式进程调度）, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO); //在内核空间分配一个页面，得到的是低地址 这里拿到的是逻辑地址，不是虚拟地址也不是物理地址
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread.初始化struct_thread */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();
  
  // 该函数用于创建线程，区别于从ELF中创建线程映像
  // 该函数创建的线程的代码来自已经载入的kernel
  // 因此不需要有将ELF载入的这一步

  // 以下是通过写栈帧来完成函数的执行的
  // 1. eip设置返回到的函数
  // 2. 给函数传递的参数直接写在上一个栈帧中
  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);  //在线程t的struct_thread的stack中创建一个函数栈帧，并将该栈帧的地址返回
  kf->eip = NULL;           // 栈顶
  kf->function = function;  // 栈中低地址，最后一个入栈的参数，对应函数的第一个形参
  kf->aux = aux;            // 栈中高地址，第一个入栈的参数，对应函数的最后一个形参

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread; //将switch_entry函数对应的栈帧的返回值设为kernel_thread函数的开始地址：switch_entry将返回到kernel_thread的开头

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry; //将switch_threads函数对应的栈帧的返回值设为switch_entry函数的开始地址：switch_threads将返回到switch_entry的开头
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock (t); //在init_thread中将此线程block，但不加入任何block队列，此函数将此线程t取消阻塞并加入就绪队列
  thread_yield();
  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  // printf("curname:%s", thread_current()->name);
  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  if (t != idle_thread)
  {
    if (thread_mlfqs)
    {
      list_push_back (&ready_list[t->priority], &t->elem);
      // list_insert_ordered(&ready_list[t->priority], &t->elem, list_less_priority, NULL);
    }
    else
    {
      // list_push_back (&ready_list[0], &t->elem);
      list_insert_ordered(&ready_list[0], &t->elem, list_less_priority, NULL);    
    }
  }
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. 
   让出CPU，将自身插入ready_list中，并进行调度*/
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ()); //非外部中断

  old_level = intr_disable ();
  if (cur != idle_thread) 
  {
    if (thread_mlfqs)
    {
      list_push_back (&ready_list[cur->priority], &cur->elem);
      // list_insert_ordered(&ready_list[cur->priority], &cur->elem, list_less_priority, NULL);
    }
    else
    {
      // list_push_back (&ready_list[0], &cur->elem);    
      list_insert_ordered(&ready_list[0], &cur->elem, list_less_priority, NULL);
    }
  }
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. 
   运行此代码时，对所有的线程的struct_thread结构执行输入的函数func*/
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  if (thread_mlfqs) //多级反馈队列禁止自己设置优先级
    return ;
  struct thread *cur = thread_current();
  // printf("\ns---dp:%d, p:%d\n",cur->donate_priority, cur->priority);
  cur->priority = new_priority;
  if (cur->donate_priority < new_priority)
    thread_yield();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  struct thread* cur = thread_current();
  if (thread_mlfqs)
    return cur->priority;
  // printf("\ng---dp:%d, p:%d\n",cur->donate_priority, cur->priority);
  // printf("return:%d",(cur->donate_priority > cur->priority));
  // printf("\ng---dp:%d, p:%d\n",cur->donate_priority, cur->priority);
  return thread_get_max_priority(cur);
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  struct thread *cur = thread_current();
  cur->nice = nice;   
  timer_cal_priority(cur, NULL);
  thread_yield();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  struct thread *cur = thread_current();
  return cur->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void)
{
  return TO_INT_NEAREST(load_avg * 100);
}

void 
thread_set_load_avg(void) // 四舍五入
{
  size_t ready_thread = 0; // 自身不在ready_list中
  if (thread_current() != idle_thread)
    ready_thread++;

  if (thread_mlfqs)
  {
    for (int i = 0; i < 64; i++)
    {
      ready_thread += list_size(&ready_list[i]);
    }
  }
  else
  {
    ready_thread = list_size(&ready_list[0]);
  }
  load_avg = FP_DIV(FP_ADD(FP_MUL(TO_FP(59), load_avg), TO_FP(ready_thread)), TO_FP(60));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  struct thread *cur = thread_current();
  return TO_INT_NEAREST(cur->recent_cpu * 100);
}

void 
thread_set_recent_cpu (void)
{
  struct thread *cur = thread_current();
  
  if (cur == idle_thread)
    return ;
  
  cur->recent_cpu = FP_ADD(cur->recent_cpu, TO_FP(1));
}


/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. 
   初始化线程的struct_thread，并将线程加入all_list队列*/
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->donate_priority = PRI_MIN;
  t->recent_cpu = 0;
  t->lock_wait = NULL;
  list_init(&t->lock_list);
  t->time_blocked = 0;
  t->nice = 0;
  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}



/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (thread_mlfqs)
  {
    for (int i = 63; i >= 0; i--)
      if (!list_empty(&ready_list[i]))
        return list_entry(list_pop_front(&ready_list[i]), struct thread, elem);
    return idle_thread;
  }
  else
  {
    if (list_empty (&ready_list[0]))
      return idle_thread;
    else
      return list_entry (list_pop_front (&ready_list[0]), struct thread, elem);
  }
}



/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. 
   设置新线程的状态和ticks，并激活页表，如果上一个线程终止了则将内存释放（释放每个页面）*/
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. 
   选择ready_list中第一个或优先级最高的一个放入CPU运行
   在thread_yield,thread_exit,thread_block中含有*/
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

//----------------------------------------------------------------------------------------------

/*增加的函数：对t*中的time_blocked进行减一的操作，同时检查是否为0
             若为0则将线程加入ready_list。作为thread_action_func
             的参数
  输入：t*和aux
  输出：none*/

void 
timer_check_block(struct thread *t, void *aux UNUSED)
{
  ASSERT(is_thread(t))
  if (t == idle_thread)
    return ;
  if (t->status != THREAD_BLOCKED || t->time_blocked == 0)
    return ;
  // printf("----------------------");
  // printf("%lld",t->time_blocked);
  ASSERT(t->time_blocked > 0);

  t->time_blocked--;
  
  if (t->time_blocked == 0)
  {
    thread_unblock(t);
  }
}

bool
list_less_priority(const struct list_elem* a, const struct list_elem* b, void* aux UNUSED)
{
  struct thread *t_a = list_entry(a, struct thread, elem);
  struct thread *t_b = list_entry(b, struct thread, elem);
  ASSERT(is_thread(t_a));
  ASSERT(is_thread(t_b));
  if (thread_mlfqs)
    return t_a->priority > t_b->priority;
  
  int p_a = thread_get_max_priority(t_a);
  int p_b = thread_get_max_priority(t_b);
  
  return p_a > p_b;
}

void 
timer_cal_recent_cpu(struct thread *t, void *aux UNUSED)
{
  if (t == idle_thread)
    return ;
  int64_t coe = FP_DIV (FP_MUL (TO_FP (2), load_avg),FP_ADD (FP_MUL (TO_FP (2), load_avg), TO_FP (1)));
  t->recent_cpu = FP_ADD (FP_MUL (coe, t->recent_cpu), TO_FP(t->nice));
}

void 
timer_cal_priority(struct thread *t, void *aux UNUSED)
{
  if (t == idle_thread)
    return ;
  int priority = PRI_MAX - TO_INT_DOWN(FP_DIV(t->recent_cpu, TO_FP(4))) - (t->nice * 2); 
  if (priority > PRI_MAX)
    priority = PRI_MAX;
  else if (priority < PRI_MIN)
    priority = PRI_MIN;
  // if (t->priority == priority)
  //   return ;
  t->priority = priority;
  // if (t->status == THREAD_READY)
  // {
  //   list_remove(&t->elem);
  //   list_push_back(&ready_list[t->priority], &t->elem);
  // }
}

int 
thread_get_max_priority(struct thread *t)
{
  return (t->donate_priority > t->priority)? t->donate_priority: t->priority;
}