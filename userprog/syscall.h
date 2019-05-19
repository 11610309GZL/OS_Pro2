#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "kernel/list.h"

void syscall_init (void);

void exit_p(int status);

struct occupy_file{
    struct file* file_ptr;
    struct list_elem file_elem;
	int fd;
};

#endif /* userprog/syscall.h */
