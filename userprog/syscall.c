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
// int syscall_write(struct intr_frame *f);
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

static inline bool is_mapped_user_vaddr (const void *vaddr);
struct occupy_file* search_occupy_file(int fd, struct list* opened_files);
bool syscall_create(struct intr_frame *f);
bool syscall_remove(struct intr_frame *f);
int  syscall_open(struct intr_frame *f);
int  syscall_filesize(struct intr_frame *f);
int  syscall_read(struct intr_frame *f);
int  syscall_write(struct intr_frame *f);
void syscall_seek(struct intr_frame *f);
unsigned syscall_tell(struct intr_frame *f);
void syscall_close(struct intr_frame *f);


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
  case SYS_HALT:    syscall_halt();      break;
  case SYS_EXIT:    syscall_exit(f);     break;
  // case SYS_WRITE: syscall_write(f); break;
  case SYS_EXEC:    syscall_exec(f);     break;
  case SYS_WAIT:    syscall_wait(f);     break;
  case SYS_CREATE:  f->eax=syscall_create(f);   break;
  case SYS_REMOVE:  f->eax=syscall_remove(f);   break;
  case SYS_OPEN:    f->eax=syscall_open(f);     break;
  case SYS_CLOSE:   syscall_close(f);    break;
  case SYS_FILESIZE:f->eax=syscall_filesize(f); break;
  case SYS_READ:    f->eax=syscall_read(f);     break;
  case SYS_WRITE:   f->eax=syscall_write(f);    break;
  case SYS_SEEK:    syscall_seek(f);     break;
  case SYS_TELL:    f->eax=syscall_tell(f);     break;
  default:          exit_p(-1);                break;
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

bool
is_mapped_user_vaddr(const void *vaddr){
  if(!is_user_vaddr(vaddr))
    return false;
  if(pagedir_get_page(thread_current()->pagedir, vaddr)==NULL)
    return false;
  
  return true;
}

// void
// get_stack(int *esp, int *val, int offset){ 
//   int *tmp_esp = esp + offset;
//   if(!is_mapped_user_vaddr(tmp_esp))
//     exit_p(-1);
//   *val = *((int *)pagedir_get_page(thread_current()->pagedir, tmp_esp));
// }

struct occupy_file* 
search_occupy_file(int fd, struct list* opened_files){
  struct occupy_file* occufile;
  for(struct list_elem *e = list_begin(opened_files); e != list_end(opened_files); e = list_next(e)){
    occufile = list_entry(e, struct occupy_file, file_elem);
    if(occufile->fd == fd)
      return occufile;
  }
  return NULL;
}


bool
syscall_create(struct intr_frame *f){
  int *esp = f->esp;
  bool res;

  if( (!is_mapped_user_vaddr(esp + 1)) || (!is_mapped_user_vaddr(esp + 2)) )
    exit_p(-1);

  char* file = (char *)*(esp + 1);
  unsigned initial_size = *(esp + 2);
  // get_stack(f->esp, &file, 1);
  // get_stack(f->esp, &initial_size, 2);

  if(!is_mapped_user_vaddr(file))
    exit_p(-1);

  if(file == NULL || file[0] == '\0')
    exit_p(-1);

  lock_acquire(&filesys_lock);
  res = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return res;
}

bool
syscall_remove(struct intr_frame *f){
  int *esp = f->esp;
  bool res;
  if( !is_mapped_user_vaddr(esp + 1) )
    exit_p(-1);
  char* file = (char *)*(esp + 1);
  // get_stack(f->esp, &file, 1);

  if(!is_mapped_user_vaddr(file))
    return false;
  
  lock_acquire(&filesys_lock);
  res = (filesys_remove(file)==NULL);
  lock_release(&filesys_lock);
  return res;
}

int
syscall_open(struct intr_frame *f){
  int *esp = f->esp;
  int res;

  if( !is_mapped_user_vaddr(esp + 1) )
    exit_p(-1);

  char *file = (char *)*(esp + 1);
  if(file == NULL)
    exit_p(-1);
  // get_stack(f->esp, &file, 1);

  // if(!is_valid_addr(file))
  //   return -1;

  lock_acquire(&filesys_lock);
  struct file *fileptr = filesys_open(file);
  lock_release(&filesys_lock);

  if(fileptr == NULL) return -1;
  else{
    struct thread* cur = thread_current();
    struct occupy_file *occufile = malloc(sizeof(*occufile));
    occufile->file_ptr = fileptr;
    occufile->fd = cur->fd_count;
    cur->fd_count += 1;
    list_push_back(&cur->opened_files, &occufile->file_elem);
    res = occufile->fd;
  }
  return res;
}

int
syscall_filesize(struct intr_frame *f){
  int *esp = f->esp;
  int res;

  if( !is_mapped_user_vaddr(esp + 1) )
    exit_p(-1);
  int fd = *(esp + 1);

  // get_stack(f->esp, &fd, 1);
  struct thread* cur = thread_current();
  struct occupy_file* file = search_occupy_file(fd, &cur->opened_files); 
  if(file == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  res = file_length(file->file_ptr);
  lock_release(&filesys_lock);
  return res;
}

int 
syscall_read(struct intr_frame *f){
  int *esp = f->esp;
  int res;
  if( (!is_mapped_user_vaddr(esp + 1)) || (!is_mapped_user_vaddr(esp + 2)) || (!is_mapped_user_vaddr(esp + 3)) )
    exit_p(-1);

  int fd = *(esp + 1);
  void *buffer = (void *) *(esp + 2);
  unsigned size = *(esp + 3);
  // pop_stack(f->esp, &size, 7);
	// pop_stack(f->esp, &buffer, 6);
	// pop_stack(f->esp, &fd, 5);

 if (!is_mapped_user_vaddr(buffer))
		 return res = -1;

  if(fd == 0)
  {
    uint8_t *buffer = buffer;
    for(int i = 0; i < size; i++){
      buffer[i] = input_getc();
    }
    res = size;
  }else{
    struct thread* cur = thread_current();
    struct occupy_file* occufile = search_occupy_file( fd,&cur->opened_files);
    if(occufile == NULL)
      return res = -1;
    else{
      
      if (occufile->file_ptr == NULL)
      {
        return res = -1;
      }
       lock_acquire(&filesys_lock);
			 res = file_read(occufile->file_ptr, buffer, size);
			 lock_release(&filesys_lock);
    }
  }
  return res;
  // get_stack(f->esp, &size, 3)
}


int
syscall_write(struct intr_frame *f){
  int *esp = f->esp;
  int res;

  if(!is_user_vaddr(esp+7))
      exit_p(-1);
  if( (!is_mapped_user_vaddr(esp + 1)) || (!is_mapped_user_vaddr(esp + 2)) || (!is_mapped_user_vaddr(esp + 3)) )
    exit_p(-1);
  int fd = *(esp + 1);
  char *buffer=(char *)*(esp + 2); 
  unsigned size=*(esp + 3);       

  int length = strlen(buffer);
  if (! is_user_vaddr(esp + 4) || ! is_user_vaddr(esp + 2 + length)) {
    exit_p(-1);
  }


  if(fd == 1) // stdout
  {
        putbuf (buffer, size);
        res = size;
    }
    else                        //file
    {
      enum intr_level old_level = intr_disable();
      struct thread* cur = thread_current();
      struct occupy_file* occufile = search_occupy_file(fd, &cur->opened_files);
      intr_set_level (old_level);
      if (occufile == NULL)
        res = -1;
      else
      {
        lock_acquire(&filesys_lock);
        res = file_write(occufile->file_ptr, buffer, size);
        lock_release(&filesys_lock);
      }
    }
    return res;
}

void
syscall_seek(struct intr_frame *f){
  int * esp = f->esp;
  if( (!is_mapped_user_vaddr(esp + 1)) || (!is_mapped_user_vaddr(esp + 2)))
    exit_p(-1);
  int fd = *(esp + 1);
  unsigned position = *(esp + 2);
  struct thread* cur = thread_current();
  struct occupy_file* occufile = search_occupy_file(fd, &cur->opened_files);

  lock_acquire(&filesys_lock);
	file_seek(occufile->file_ptr, position);
	lock_release(&filesys_lock);
}

unsigned
syscall_tell(struct intr_frame *f){
  int *esp = f->esp;
  if( (!is_mapped_user_vaddr(esp + 1)) )
    exit_p(-1);

  int fd = *(esp + 1);
  struct thread* cur = thread_current();
  struct occupy_file* occufile = search_occupy_file(fd, &cur->opened_files);
  int res;

  lock_acquire(&filesys_lock);
	res = file_tell(occufile->file_ptr);
	lock_release(&filesys_lock);

  return res;
}

void
syscall_close(struct intr_frame *f){
  int * esp = f->esp;
  if( (!is_mapped_user_vaddr(esp + 1)) )
    exit_p(-1);
  int fd = *(esp + 1);
  struct thread* cur = thread_current();
  struct occupy_file* occufile = search_occupy_file(fd ,&cur->opened_files);

  if(occufile != NULL){
    lock_acquire(&filesys_lock);
    list_remove(&occufile->file_elem);
	  file_close(occufile->file_ptr);
    free(occufile);
	  lock_release(&filesys_lock);
  }
}
