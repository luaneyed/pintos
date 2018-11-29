#include "filesys/file.h"
#include "lib/user/syscall.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct fd;
int mk_fd(struct file *);
struct fd *fd_by_val(int);
struct file *file_by_fd(int);

struct mmf;
mapid_t mk_mapid(struct file* f);
struct mmf* mmf_by_mapid(int val);
struct file* file_by_mapid(int val);

#endif /* userprog/syscall.h */
