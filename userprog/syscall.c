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


void ExitStatus(int status);
static void syscall_handler (struct intr_frame *);
static void syscall_write(struct intr_frame *f);
static void syscall_halt (void);
static void syscall_exit(struct intr_frame *f);

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

  // check the stack pointer is in user space
  if(!is_user_vaddr(stack_ptr)) {
    ExitStatus(-1);
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

  case SYS_WAIT:
    syscall_wait(f);
  default:
    break;
  }





  thread_exit ();
}

void ExitStatus(int status)      //????????
{
    struct thread *cur = thread_current();
    cur->exit_status = status;
    thread_exit();
}

static void syscall_halt (void) {
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f) {
  
  thread_exit();

}


static void syscall_write(struct intr_frame *f) {
  int *esp = f->esp;

  if(!is_user_vaddr(esp+7))
      ExitStatus(-1);
  int fd = *(esp + 2);
  char *buffer=(char *)*(esp+6); 
  unsigned size=*(esp+3);       


  if(fd==1) // stdout
    {
        putbuf (buffer, size);
        f->eax=0;
    }
    else                        //??
    {
        // struct thread *cur=thread_current();
        // struct file_node *fn=GetFile(cur,fd); //??????
        // if(fn==NULL)
        // {
        //     f->eax=0;
        //     return;
        // }

        // f->eax=file_write(fn->ptr,buffer,size);//???

    }
}

