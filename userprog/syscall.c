#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "process.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "devices/input.h"


static void syscall_handler (struct intr_frame *);
static void syscall_write(struct intr_frame *f);
static void syscall_halt (void);
static void syscall_exit(struct intr_frame *f);
static void syscall_wait(struct intr_frame *f);
static void syscall_exec(struct intr_frame *f);
static inline bool is_mapped_user_vaddr (const void *vaddr);

static inline bool
is_mapped_user_vaddr (const void *vaddr)
{
  //Will I need to see if vaddr + 7 is in the kernel space?
  //Or if vaddr is a kernel address, would pagedir_get_page
  //just return NULL for vaddr?
  if (!is_user_vaddr (vaddr) || !is_user_vaddr (vaddr + 3))
    return false;
  
  //top                                   bot
  //1111 1111 1111 1111   1111 1111 1111 1111
  //esp   +1   +2   +3     +4   +5   +6   +7
  struct thread *t = thread_current ();
  void* top = pagedir_get_page (t->pagedir, vaddr);
  void* bot = pagedir_get_page (t->pagedir, vaddr + 3);
  return (top && bot);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  int* stack_ptr = f->esp;

  if ((uint8_t *) stack_ptr <= pg_round_up(f->eip)) {
    exit_p(-1);
  }

  // check the stack pointer is in user space
  if(!is_user_vaddr(stack_ptr)) {
    exit_p(-1);
  }

  /* get the syscall number */
  int sys_num = *stack_ptr; 

  /* handle system call */
  switch (sys_num)
  {
  case SYS_HALT:
    syscall_halt();
    break;
  case SYS_EXIT:
    syscall_exit(f);
    break;
  case SYS_WRITE:
    syscall_write(f);
     break;
  case SYS_EXEC:
    syscall_exec(f);
    break;

  case SYS_WAIT:
    syscall_wait(f);
  default:
    break;
  }


}

/* the exit method with exit_status, use this method instead of thread_exit() to
*  exit a process
*/
void exit_p(int status)    
{
    struct thread *cur = thread_current();
    struct child_data *child;
    
    enum intr_level old_level = intr_disable();

    /* tell the parent this process is exit 
      if the parent wait this exited process, end wait correctly use the child data
    */
    for (struct list_elem *e = list_begin(&cur->parent->children); e != list_end(&cur->parent->children); e = list_next(e))
    {
      child = list_entry(e, struct child_data, child_elem);

      if (child->tid == cur->tid)
      {
        child->is_exited = true;
        child->exit_status = status;
      }
    }

    /* check whether the exiting process is waited by its parent 
       if true, UP the wait_sema
    */
    if (thread_current()->parent->waiting_child != NULL)
    {
      if (thread_current()->parent->waiting_child->tid == thread_current()->tid)
        sema_up(&thread_current()->parent->waiting_child->wait_sema);
    }
    intr_set_level(old_level);
    cur->exit_status = status;

    // free the allocation
    thread_exit();
}

static void syscall_halt (void) {
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f) {
  if(!is_user_vaddr(((int *)f->esp)+2))
    exit_p(-1);
  struct thread *cur = thread_current();
  int *esp = f->esp;
  int exit_status = *(esp+1);
  exit_p(exit_status);
}

static void syscall_wait(struct intr_frame *f) {
  if(!is_user_vaddr(((int *)f->esp)+2))
    exit_p(-1);

  tid_t tid=*((int *)f->esp+1);
    if(tid!=-1)
    {
      f->eax=process_wait(tid);
    }
    else
      f->eax=-1;
}

static void syscall_exec(struct intr_frame *f) {
  
  int *esp = f->esp;
  
  char *file_name = (char *)*(esp+1);

  int * name_st = esp + 1;
  int * name_end = esp + 1 + 14;


  if (!is_user_vaddr(name_st) || !is_user_vaddr(name_end)) {
    exit_p(-1);
  }


  if (file_name == NULL || file_name[1] == '\0')
    exit_p(-1);

  f->eax = process_execute(file_name);
}

static void syscall_write(struct intr_frame *f) {
  int *esp = f->esp;

  if(!is_user_vaddr(esp+7))
      exit_p(-1);
  int fd = *(esp + 1);
  char *buffer=(char *)*(esp+2); 
  unsigned size=*(esp+3);       


  if(fd==1) // stdout
    {
        putbuf (buffer, size);
        f->eax=size;
    }
    else                        //file
    {
      // enum intr_level old_level = intr_disable();
      // struct process_file *pf = search_fd(&thread_current()->opened_files, fd);
      // intr_set_level (old_level);

      // if (pf == NULL)
      //   f->eax = -1;
      // else
      // {
      //   lock_acquire(&filesys_lock);
      //   ret = file_write(pf->ptr, buffer, size);
      //   lock_release(&filesys_lock);
      // }

    }
}

