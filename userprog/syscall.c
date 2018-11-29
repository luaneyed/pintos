#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "vm/page.h"
#include "lib/kernel/hash.h"

static void syscall_handler (struct intr_frame *);

void _halt(void);
int _exit(int status);
pid_t _exec(const char *cmd_line);
int _wait(pid_t pid);
bool _create(const char *file, unsigned initial_size);
bool _remove(const char*file);
int _open(const char *file);
int _filesize(int fd);
int _read(int fd, void *buffer, unsigned size);
int _write(int fd, const void *buffer, unsigned size);
void _seek(int fd, unsigned position);
unsigned _tell(int fd);
void _close(int fd);
mapid_t _mmap(int fd, void *addr);
void _munmap(mapid_t mapid);

bool _chdir(const char *dir);
bool _mkdir(const char *dir);
bool _readdir(int fd, char *name);
bool _isdir(int fd);
int _inumber(int fd);

struct fd	//	file descripter
{
  struct file* file;
  struct list_elem elem;
  int val;	//	file descripter value
};

struct mmf
{
  struct file* file;
  struct list_elem elem;
  mapid_t mapid;
};

static struct lock file_lock;

void
syscall_init (void) 
{
  lock_init(&file_lock);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int* esp = f->esp;
  thread_current()->esp = f->esp;

  /* check esp is valid addr */
  if(!is_user_vaddr(esp))
  {
	_exit(-1);
	return;
  }

  int call_num = *esp;

  /* check arguments */
  switch(call_num) {
	/* one argument call */
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
	case SYS_REMOVE:
	case SYS_OPEN:
	case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
	case SYS_MUNMAP:
	case SYS_CHDIR:
	case SYS_MKDIR:
	case SYS_ISDIR:
	case SYS_INUMBER:
      if(!is_user_vaddr(esp + 1))
	  {
		_exit(-1);
		return;
	  }
	  break;
    /* two arguments call */
    case SYS_CREATE:
    case SYS_SEEK:
	case SYS_MMAP:
	case SYS_READDIR:
      if(!is_user_vaddr(esp + 2))
	  {
		_exit(-1);
	    return;
	  }
      break;
	case SYS_READ:
	case SYS_WRITE:
      if(!is_user_vaddr(esp + 3))
	  {
		_exit(-1);
	    return;
	  }
      break;
  }

  /* Map system calls */
  switch(call_num) {
    case SYS_HALT:
	  _halt();
	  NOT_REACHED();
	case SYS_EXIT:
	  _exit(*(int*)(esp+1));
	  NOT_REACHED();
	case SYS_EXEC:
	  f->eax = _exec(*(char**)(esp+1));
	  break;
	case SYS_WAIT:
	  f->eax = _wait(*(pid_t*)(esp+1));
	  break;
	case SYS_CREATE:
	  f->eax = _create(*(char**)(esp+1), *(unsigned*)(esp+2));
	  break;
	case SYS_REMOVE:
	  f->eax = _remove(*(char**)(esp+1));
	  break;
	case SYS_OPEN:
	  f->eax = _open(*(char**)(esp+1));
	  break;
	case SYS_FILESIZE:
	  f->eax = _filesize(*(int*)(esp+1));
	  break;
	case SYS_READ:
	  f->eax = _read(*(int*)(esp+1), *(void**)(esp+2), *(unsigned*)(esp+3));
	  break;
	case SYS_WRITE:
	  f->eax = _write(*(int*)(esp+1), *(void**)(esp+2), *(unsigned*)(esp+3));
	  break;
	case SYS_SEEK:
	  _seek(*(int*)(esp+1), *(unsigned*)(esp+2));
	  break;
	case SYS_TELL:
	  f->eax = _tell(*(int*)(esp+1));
	  break;
	case SYS_CLOSE:
	  _close(*(int*)(esp+1));
	  break;
	case SYS_MMAP:
	  f->eax = _mmap(*(int*)(esp+1), *(void**)(esp+2));
	  break;
	case SYS_MUNMAP:
	  _munmap(*(mapid_t*)(esp+1));
	  break;
	case SYS_CHDIR:
	  f->eax = _chdir(*(const char **)(esp+1));
	  break;
	case SYS_MKDIR:
	  f->eax = _mkdir(*(const char **)(esp+1));
	  break;
	case SYS_READDIR:
	  f->eax = _readdir(*(int *)(esp+1), *(const char**)(esp+2));
	  break;
	case SYS_ISDIR:
	  f->eax = _isdir(*(int *)(esp+1));
	  break;
	case SYS_INUMBER:
	  f->eax = _inumber(*(int *)(esp+1));
	  break;
	default:
	  _exit(-1);
	  break;
  }  
}

bool _chdir(const char *dir)
{
  return filesys_chdir(dir);
}
bool _mkdir(const char *dir)
{
  return filesys_create_dir(dir, 0);
}
bool _readdir(int fd, char *name)
{
  struct file *file = file_by_fd(fd);
  struct inode *inode = file_get_inode(file);

  if(!inode_is_dir(inode))
	return false;
  return dir_readdir((struct dir *) file, name);
}
bool _isdir(int fd)
{
  struct file *file = file_by_fd(fd);
  struct inode *inode = file_get_inode(file);

  return inode_is_dir(inode);
}
int _inumber(int fd)
{
  struct file *file = file_by_fd(fd);
  struct inode *inode = file_get_inode(file);

  return inode_get_inumber(inode);
}
void
_halt (void)
{
  power_off();
}

int _exit (int status)
{
  struct thread *curr = thread_current();
  curr->exit_status = status;
  struct list *l = &curr->fds;
  struct list_elem *e, *f;

  for(e = list_begin(l); e != list_end(l); e = f)
  {
	f = list_next(e);
	_close(list_entry(e, struct fd, elem)->val);
  }
  ASSERT(list_empty(l));

  l = &curr->mmfs;
  for(e = list_begin(l); e != list_end(l); e = f)
  {
	f = list_next(e);
	_munmap(list_entry(e, struct mmf, elem)->mapid);
  }
  ASSERT(list_empty(l));

  thread_exit();

  return -1;
}

pid_t _exec(const char *cmd_line)
{
  pid_t excuted_pid = process_execute(cmd_line);
  return excuted_pid;
}

int _wait(pid_t pid)
{
  return process_wait(pid);
}

bool _create (const char *file, unsigned initial_size)
{
  if(!file)
	return _exit(-1);
  return filesys_create(file, initial_size);
}

bool _remove (const char *file)
{
  if(!is_user_vaddr(file))
	return _exit(-1);
  return filesys_remove(file);
}

int _open (const char *file)
{
 
  if(!file)
	return -1;
  return mk_fd(filesys_open(file));
}

int _filesize (int fd) 
{
  return (int)file_length(file_by_fd(fd));
}

int _read (int fd, void *buffer, unsigned size)
{
  if(!is_user_vaddr(buffer))
	return _exit(-1);
 
  if(fd == STDIN_FILENO)
  {
	int i = -1;
	uint8_t *buf = (uint8_t*)buffer;
	while(++i < (int)size)
	  *(buf+i) = input_getc();
	return size;
  }
  if(fd == STDOUT_FILENO)
	return -1;
  
  struct file* f = file_by_fd(fd);
  if(!f || !buffer)
	return -1;
  lock_acquire(&file_lock);
  int size_readed = (int)file_read(f, buffer, size);
  lock_release(&file_lock);
  return size_readed;
}

int _write (int fd, const void *buffer, unsigned size)
{
  if(!is_user_vaddr(buffer))
	return _exit(-1);
  if(fd == STDIN_FILENO)
	return -1;
  if(fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
	return size;
  }
  if(_isdir(fd))
	return -1;
  struct file* f = file_by_fd(fd);
  if(!f || !buffer)
	return -1;
  lock_acquire(&file_lock);
  int written_size = (int)file_write(f, buffer, size); 
  lock_release(&file_lock);
  return written_size;
}

void _seek (int fd, unsigned position) 
{
  struct file* f = file_by_fd(fd);
  if(!f)
  {
	_exit(-1);
	return;
  }
  file_seek(f, position);
}

unsigned _tell (int fd) 
{
  struct file* f = file_by_fd(fd);
  if(!f)
	return _exit(-1);
  return file_tell(f);
}

void _close (int fd)
{
  struct fd* d = fd_by_val(fd);
  if(!d)
  {
	_exit(-1);
	return;
  }

  struct file* f = d->file;
  if(!f)
  {
	palloc_free_page(d);
	_exit(-1);
	return;
  }
  if(_isdir(fd))
  {
    dir_close((struct dir *) f);
  }
  else
    file_close(f);
  list_remove(&d->elem);
  palloc_free_page(d);
//  free(d);
}

mapid_t _mmap(int fd, void *addr)
{
  uint32_t vaddr = (uint32_t)addr;
  if(!addr || (vaddr % (uint32_t)PGSIZE))
	return -1;

  struct fd* d = fd_by_val(fd);
  if(!d)
	return -1;

  struct file* f = d->file;
  if(!f)
  {
	palloc_free_page(d);
	return -1;
  }

  int size = file_length(f);
  if(size == 0)
  {
	return -1;
  }
  uint32_t last_page = vaddr + (size / PGSIZE) * PGSIZE;
  if(size % PGSIZE == 0)
	last_page -= PGSIZE;
  struct hash_iterator i;
  hash_first(&i, thread_current()->sup_pt);
  uint32_t temp;
  while(hash_next(&i))
  {
	temp = hash_entry(hash_cur(&i), struct pt_entry, hash_elem)->vaddr;
	if(temp >= vaddr && temp <= last_page)
	  return -1;	//	virtual address is using
  }

  for(temp = vaddr; temp < last_page; temp += PGSIZE)
	insert_mmap_pt(temp, f, (off_t)(temp - vaddr), 8);
  int last_sec = size % PGSIZE;
  if(last_sec == 0)
	last_sec = PGSIZE;
  last_sec = (last_sec - 1)/DISK_SECTOR_SIZE + 1;
  insert_mmap_pt(temp, f, (off_t)(last_page - vaddr), last_sec);
  
  return mk_mapid(f);
}

void _munmap(mapid_t mapid)
{
  struct mmf* mmf = mmf_by_mapid(mapid);
  if(!mmf)
	return;
  
  struct file* f = mmf->file;
  ASSERT(f);

  struct hash_iterator i;
  struct thread *curr = thread_current();
  struct hash *h = curr->sup_pt;
  hash_first(&i, h);
  struct hash_elem *cur_elem = hash_next(&i);
  while(cur_elem)
  {
	struct pt_entry *ent = hash_entry(hash_cur(&i), struct pt_entry, hash_elem);
	cur_elem = hash_next(&i);
	if(ent->file != f)
	  continue;
	hash_delete(h, &ent->hash_elem);
	pagedir_clear_page(curr->pagedir, ent->vaddr);
	rm_pt_entry(ent);
  }
  rehash(h);

  list_remove(&mmf->elem);
  free(mmf);
}

int mk_fd(struct file* f)
{
  if(!f)
	return -1;

  struct list *l = &thread_current()->fds;
  struct fd* fd = (struct fd*) palloc_get_page(0);
  if(!fd) 
  {
	file_close(f);
	return -1;
  }

  fd->file = f;

  struct list_elem *e;
  int preval = 0;
  int curval = 1;
  int fdval = 0;

  if(list_empty(l))
  {
	fd->val = 2;
	list_push_back(l, &fd->elem);
	return fd->val;
  }

  for(e = list_begin(l); e != list_end(l) ; e = list_next(e) )
  {
	preval = curval;
	curval = list_entry(e, struct fd, elem)->val;

	if(curval > preval + 1)
	{
	  fdval = preval + 1;
	  break;
	}
  }
  if(!fdval)
  {
	fd->val = curval + 1;
	list_push_back(l, &fd->elem);
  }
  else
  {
	fd->val = fdval;
    list_insert(e->prev, &fd->elem);
  }

    
  return fd->val;
}

struct fd* fd_by_val(int val)
{
  struct list *l = &thread_current()->fds;
  struct list_elem *e;
  for(e = list_begin(l); e != list_end(l) ; e = list_next(e) )
  {
	struct fd* fd = list_entry(e, struct fd, elem);
	if(fd->val == val)
	  return fd;
  }
  return NULL;
}

struct file* file_by_fd(int val)
{
  struct fd* fd = fd_by_val(val);
  if(!fd)
	return NULL;
  return fd->file;
}

mapid_t mk_mapid(struct file* f)
{
  if(!f)
	return -1;

  struct list *l = &thread_current()->mmfs;
  struct mmf* fd = (struct mmf*)malloc(sizeof(struct mmf));
  if(!fd) 
	return -1;

  fd->file = f;

  struct list_elem *e;
  int preval = 0;
  int curval = 1;
  int fdval = 0;

  if(list_empty(l))
  {
	fd->mapid = 2;
	list_push_back(l, &fd->elem);
	return fd->mapid;
  }

  for(e = list_begin(l); e != list_end(l) ; e = list_next(e) )
  {
	preval = curval;
	curval = list_entry(e, struct mmf, elem)->mapid;

	if(curval > preval + 1)
	{
	  fdval = preval + 1;
	  break;
	}
  }
  if(!fdval)
  {
	fd->mapid = curval + 1;
	list_push_back(l, &fd->elem);
  }
  else
  {
	fd->mapid = fdval;
    list_insert(e->prev, &fd->elem);
  }

    
  return fd->mapid;
}

struct mmf* mmf_by_mapid(int val)
{
  struct list *l = &thread_current()->mmfs;
  struct list_elem *e;
  for(e = list_begin(l); e != list_end(l) ; e = list_next(e) )
  {
	struct mmf* fd = list_entry(e, struct mmf, elem);
	if(fd->mapid == val)
	  return fd;
  }
  return NULL;
}

struct file* file_by_mapid(int val)
{
  struct mmf* fd = mmf_by_mapid(val);
  if(!fd)
	return NULL;
  return fd->file;
}
