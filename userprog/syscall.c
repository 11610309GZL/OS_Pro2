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
static int syscall_argc (int sys_number);

int syscall_practice(struct intr_frame *f);


static int
syscall_argc (int sys_number) {
  
  switch (sys_number) {
    case SYS_HALT:
      return 0;
    
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
    case SYS_PRACTICE:
      return 1;
    
    case SYS_CREATE:
    case SYS_SEEK:
      return 2;
    
    case SYS_READ:
    case SYS_WRITE:
      return 3;
    
    default:
      return -1;
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int* stack_ptr = f->esp;

  /* test <sc-bad-sp> just check the case where the stack pointer is 
  *  below the PC. And the page allocated for f->eip is at the very
  *  bottom of the the user's space. So it's clear that no pointer 
  *  should be lower than it. 
  * */
  uint8_t* tmp =  f->esp;
  void * a = (void *)tmp;
  void * b = pg_round_up(f->eip);
  if ((void *)tmp <= pg_round_up(f->eip)) {
    exit_p(-1);
  }

  

  // check the stack pointer is in user space
  if(!is_user_vaddr(stack_ptr)) {
    exit_p(-1);
  }

  

  /* get the syscall number */
  int sys_num = *stack_ptr; 

  int argc = syscall_argc(sys_num);
  /* check the paramenter pointer */
  if (argc > 0 && !is_user_vaddr(stack_ptr + argc)) {
    exit_p(-1);
  }




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
  case SYS_PRACTICE:
    f->eax = syscall_practice(f);

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

int syscall_practice(struct intr_frame *f) {
  int *esp = f->esp;
  int arg = *(esp + 1);
  return arg + 1;
}

static void syscall_exit(struct intr_frame *f) {
  if(!is_user_vaddr(((int *)f->esp)+1))
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


  if (!is_user_vaddr(file_name)) {
    exit_p(-1);
  }


  if (file_name == NULL || file_name[1] == '\0')
    exit_p(-1);

  f->eax = process_execute(file_name);
}

static void syscall_write(struct intr_frame *f) {
  int *esp = f->esp;

  
  int fd = *(esp + 1);
  char *buffer=(char *)*(esp+2); 
  unsigned size=*(esp+3);       

  int length = strlen(buffer);
  if (! is_user_vaddr(esp + 4) || ! is_user_vaddr(esp + 2 + length)) {
    exit_p(-1);
  }


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

