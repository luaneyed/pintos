#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/cache.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  inode_init ();
  cache_init();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

struct dir *
filesys_parse_path(char **file_name)
{
  char *path = (char *) malloc (strlen(*file_name) + 1);
  char *token;
  char *saveptr;
  struct dir *dir;
  struct dir *working_dir = thread_current()->working_dir;
  struct inode *inode;

  memcpy(path, *file_name, strlen(*file_name) + 1);
  token = strtok_r(path, "/", &saveptr);
  if(path[0] == '/')
	*file_name += 1;
  /* absolute or relative */
  if(path[0] == '/' || !working_dir) // absolute or working directory is root
  {
    dir = dir_open_root();
  }
  else
  {
	inode_reopen(dir_get_inode(working_dir));
	dir = dir_open(dir_get_inode(working_dir));
  }

  while(saveptr[0] != NULL)
  {
 	if(strcmp(token, "."))         // not . : something to do
	{
	  if(strcmp(token, ".."))      // not .. : name of dir
	  {
		if(!dir_lookup(dir, token, &inode))
		  return NULL;
		dir_close(dir);
		dir = dir_open(inode);
	  }
	  else                         // .. : parent directory
	  {
		struct dir *parent_dir = dir_open_parent(dir);
		dir_close(dir);
		dir = parent_dir;
	  }
	}
	*file_name += strlen(token) + 1;
	token = strtok_r(NULL, "/", &saveptr);
  }

  free(path);
  return dir;
}


bool
filesys_chdir (const char *name)
{
  struct dir *dir;
  struct inode *inode;

  if(!strcmp(name, "/"))
	dir = dir_open_root();
  else
  {
    dir = filesys_parse_path(&name);
  /* one more parse is necessary              *
   * ex) a/b/c -> dir = "a/b", name = "c" now */
 	if(strcmp(name, "."))         // not . : something to do
	{
	  if(strcmp(name, ".."))      // not .. : name of dir
	  {
		if(!dir_lookup(dir, name, &inode))
		  return false;
		dir_close(dir);
		dir = dir_open(inode);
	  }
	  else                         // .. : parent directory
	  {
		struct dir *pdir = dir_open_parent(dir);
		dir_close(dir);
		dir = pdir;
	  }
	}
  }
  if(!dir)
	return false;

  struct dir *working_dir = thread_current()->working_dir;
  if(working_dir)
    dir_close(working_dir);
  thread_current()->working_dir = dir;

  return true;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  disk_sector_t inode_sector = 0;
//  struct dir *dir = dir_open_root ();

  struct dir *dir = filesys_parse_path(&name);

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (dir, name, inode_sector));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

bool
filesys_create_dir (const char *name, off_t initial_size) 
{
  disk_sector_t inode_sector = 0;
  struct dir *dir = filesys_parse_path(&name);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, true)
                  && dir_add (dir, name, inode_sector));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir;
  struct inode *inode = NULL;
  if(strcmp(name, "/") == 0)
  {
	dir = dir_open_root();
    inode = dir_get_inode(dir);	
  }
  else
  {
    dir = filesys_parse_path(&name);
    if (!strcmp(name, "."))
	{
	  inode = dir_get_inode(dir);
	}
	else if(!strcmp(name, ".."))
	{
		dir = dir_open_parent(dir);
		dir_close(dir);
	}	
	else if (dir != NULL)
	{
  	  dir_lookup (dir, name, &inode);
	}
  }

  dir_close (dir);
  if(inode && inode_is_dir(inode))
  {
	inode_reopen(inode);
	return (struct file*) dir_open(inode);  // i don't want to use union
  }
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
//  struct dir *dir = dir_open_root ();
  struct dir *dir = filesys_parse_path(&name);
  struct inode *inode;
 	if(strcmp(name, "."))         // not . : something to do
	{
	  if(!strcmp(name, ".."))
		return false;           // parent of sth? get lost
	}

  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
