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

/**/
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  if (f==NULL)
    exit_p(-1);

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
  case SYS_HALT:    syscall_halt();      break;
  case SYS_EXIT:    syscall_exit(f);     break;
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
      if the parent wait this exited process, end wait correctly use the child data */
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

/* Shutdown the system using function shutdown_power_off()*/
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

/*Check if this is a vaild address in user memory space*/
bool
is_mapped_user_vaddr(const void *vaddr){
  if(!is_user_vaddr(vaddr))
    return false;
  if(pagedir_get_page(thread_current()->pagedir, vaddr)==NULL)
    return false;
  
  return true;
}

/* Search a spacific file occupied by a thread, using file descriptor (fd) */
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

/* Creat a new file with specific initial positon */
bool
syscall_create(struct intr_frame *f){
  int *esp = f->esp;
  bool res;
  //Check if parameter are vaild.
  if( (!is_mapped_user_vaddr(esp + 1)) || (!is_mapped_user_vaddr(esp + 2)) )
    exit_p(-1);

  char* file = (char *)*(esp + 1);
  unsigned initial_size = *(esp + 2);

  if(!is_mapped_user_vaddr(file))
    exit_p(-1);
  //If file name is NULL or empty, exit with -1
  if(file == NULL || file[1] == '\0')
    exit_p(-1);
  //Aquire for the file system lock
  lock_acquire(&filesys_lock);
  res = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return res;
}

/* Remove a file with specific name, if name is ilegal or remove 
fail, return false*/
bool
syscall_remove(struct intr_frame *f){
  int *esp = f->esp;
  bool res;
  if( !is_mapped_user_vaddr(esp + 1) )
    exit_p(-1);
  char* file = (char *)*(esp + 1);

  if(!is_mapped_user_vaddr(file))
    return false;
  
  if(file == NULL || file[1] == '\0')
    return false;

  lock_acquire(&filesys_lock);
  res = (filesys_remove(file)==NULL);
  lock_release(&filesys_lock);
  return res;
}

/* Open a file with specific name, if name is NULL exit with -1,
Once the file is open, create a occupy_file to put in opened_files
list in current thread, also refresh the fd_count for current thread.*/
int
syscall_open(struct intr_frame *f){
  int *esp = f->esp;
  int res;

  if( !is_mapped_user_vaddr(esp + 1) )
    exit_p(-1);

  char *file = (char *)*(esp + 1);
  //Check NULL file name.
  if(file == NULL)
    exit_p(-1);

  //Try to open the file.
  lock_acquire(&filesys_lock);
  struct file *fileptr = filesys_open(file);
  lock_release(&filesys_lock);
  //If Open fail, return -1
  if(fileptr == NULL) return -1;
  //Once Open success, record the file in opened_files list
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

/* Return the file size for an OPENED file, which is 
already in the opened_files list of CURRENT thread, find 
the specific file using file discriptor*/
int
syscall_filesize(struct intr_frame *f){
  int *esp = f->esp;
  int res;

  if( !is_mapped_user_vaddr(esp + 1) )
    exit_p(-1);
  int fd = *(esp + 1);
  //Get the opened_files list of current thread
  struct thread* cur = thread_current();
  //Search the file using file discriptor
  struct occupy_file* file = search_occupy_file(fd, &cur->opened_files); 
  //If No file is found, return -1
  if(file == NULL)
    return -1;
  //If found, aquire the lock and call file_length funtion
  lock_acquire(&filesys_lock);
  res = file_length(file->file_ptr);
  lock_release(&filesys_lock);
  return res;
}

/* Read data from STDIN or files, fd = 0 for STDIN
and other fd value for files, */
int 
syscall_read(struct intr_frame *f){
  int *esp = f->esp;
  int res;
  if( (!is_mapped_user_vaddr(esp + 1)) || (!is_mapped_user_vaddr(esp + 2)) || (!is_mapped_user_vaddr(esp + 3)) )
    exit_p(-1);

  int fd = *(esp + 1);
  void *buffer = (void *) *(esp + 2);
  unsigned size = *(esp + 3);

 if (!is_mapped_user_vaddr(buffer))
		 return res = -1;
  //If read from STDIN
  if(fd == 0)
  {
    uint8_t *buffer = buffer;
    //STDIN using input_getc
    for(int i = 0; i < size; i++){
      buffer[i] = input_getc();
    }
    res = size;
  //If read from FILE
  }else{
    //Get the file pointer
    struct thread* cur = thread_current();
    struct occupy_file* occufile = search_occupy_file( fd,&cur->opened_files);
    //If NOT find a file
    if(occufile == NULL)
      return res = -1;
    else{
      //If find the file but NULL file pointer
      if (occufile->file_ptr == NULL)
      {
        return res = -1;
      }
      //Read
       lock_acquire(&filesys_lock);
			 res = file_read(occufile->file_ptr, buffer, size);
			 lock_release(&filesys_lock);
    }
  }
  return res;
}

/* Read data from STDOUT or files, fd = 1 for STDOUT
and other fd value for files, */
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

  //STDOUT, using putbuf
  if(fd == 1)
  {
    putbuf (buffer, size);
    res = size;
  }
  else{
    //Find the file to write
    enum intr_level old_level = intr_disable();
    struct thread* cur = thread_current();
    struct occupy_file* occufile = search_occupy_file(fd, &cur->opened_files);
    intr_set_level (old_level);
    //If NO file was found
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

/*Get to a spacific position of a OPENED file*/
void
syscall_seek(struct intr_frame *f){
  int * esp = f->esp;
  if( (!is_mapped_user_vaddr(esp + 1)) || (!is_mapped_user_vaddr(esp + 2)))
    exit_p(-1);
  int fd = *(esp + 1);
  unsigned position = *(esp + 2);
  //Find the file in the opened_list of current thread
  struct thread* cur = thread_current();
  struct occupy_file* occufile = search_occupy_file(fd, &cur->opened_files);
  if(occufile == NULL)
    exit_p(-1);
  //Call file_seek 
  lock_acquire(&filesys_lock);
	file_seek(occufile->file_ptr, position);
	lock_release(&filesys_lock);
}

/*Returns the position of the next byte to be reador written in open 
file fd, expressed in bytes from the beginning of the file.*/
unsigned
syscall_tell(struct intr_frame *f){
  int *esp = f->esp;
  if( (!is_mapped_user_vaddr(esp + 1)) )
    exit_p(-1);
  int fd = *(esp + 1);
  //Search the file in the opened_files list
  struct thread* cur = thread_current();
  struct occupy_file* occufile = search_occupy_file(fd, &cur->opened_files);
  int res;
  if(occufile == NULL)
    exit_p(-1);
  //Call file_tell function in filesys.c
  lock_acquire(&filesys_lock);
	res = file_tell(occufile->file_ptr);
	lock_release(&filesys_lock);

  return res;
}

/*Close an opening file of the current thread*/
void
syscall_close(struct intr_frame *f){
  int * esp = f->esp;
  if( (!is_mapped_user_vaddr(esp + 1)) )
    exit_p(-1);
  int fd = *(esp + 1);
  //Search the file in opened_files list 
  struct thread* cur = thread_current();
  struct occupy_file* occufile = search_occupy_file(fd ,&cur->opened_files);
  //If the file is found
  if(occufile != NULL){
    lock_acquire(&filesys_lock);
    //Remove the file from opened_files list
    list_remove(&occufile->file_elem);
	  file_close(occufile->file_ptr);
    //Destory the list element
    free(occufile);
	  lock_release(&filesys_lock);
  }
}
