#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

struct indirect_inode	//	single or double indirect inode
{
  disk_sector_t sector[128];
};

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
	disk_sector_t direct[12];
	disk_sector_t single;
	disk_sector_t doubly;
	off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t unused[110];               /* Not used. */
	disk_sector_t parent;
	bool is_dir;
	bool unused_[3];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
  {
	if(pos < 12 * DISK_SECTOR_SIZE)
	  return inode->data.direct[pos / DISK_SECTOR_SIZE];
	struct indirect_inode tmp;
	if(pos < (12 + 128) * DISK_SECTOR_SIZE)
    {
	  disk_read(filesys_disk, inode->data.single, &tmp);
	  return tmp.sector[(pos / DISK_SECTOR_SIZE) - 12];
	}
    ASSERT(pos < (12 + 128 + 128*128) * DISK_SECTOR_SIZE);
	disk_read(filesys_disk, inode->data.doubly, &tmp);
	disk_read(filesys_disk, tmp.sector[((pos / DISK_SECTOR_SIZE) - 12 - 128) / 128], &tmp);
	return tmp.sector[((pos / DISK_SECTOR_SIZE) - 12 - 128) % 128];
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
	  disk_inode->is_dir = is_dir;

      static char zeros[DISK_SECTOR_SIZE];
	  int n = (sectors <= 12)?sectors:12, i;
	  ASSERT(free_map_allocate_advanced (n, disk_inode->direct));
	  for(i = 0; i < n; i ++)
		disk_write(filesys_disk, disk_inode->direct[i], zeros);

	  if(sectors > 12)
	  {
		ASSERT(free_map_allocate(1, &disk_inode->single));
		struct indirect_inode tmp;	//	for child inode
		n = (sectors <= 12 + 128)?(sectors - 12):128;
		ASSERT(free_map_allocate_advanced (n, tmp.sector));
		for(i = 0; i < n; i ++)
		  disk_write(filesys_disk, tmp.sector[i], zeros);
		disk_write(filesys_disk, disk_inode->single, &tmp);
		if(sectors > 12 + 128)
		{
		  ASSERT(sectors < (12 + 128 + 128*128));
		  ASSERT(free_map_allocate(1, &disk_inode->doubly));
		  struct indirect_inode tmp2;	//	for grandchild inode
		  int sin_num = (sectors - 12 - 128 - 1) / 128 + 1;
		  ASSERT(free_map_allocate_advanced (sin_num, tmp.sector));
		  for(i = 0; i < sin_num; i ++)
			disk_write(filesys_disk, tmp.sector[i], zeros);
		  int j;
		  for(i = 0; i < sin_num - 1 ; i++)
		  {
			ASSERT(free_map_allocate_advanced (128, tmp2.sector));
			for(j = 0; j < 128; j ++)
			  disk_write(filesys_disk, tmp2.sector[j], zeros);
			disk_write(filesys_disk, tmp.sector[i], &tmp2);
		  }
		  int last_num = (sectors - 12 - 128) % 128;
		  if(last_num == 0)
			last_num = 128;
		  ASSERT(free_map_allocate_advanced (last_num, tmp2.sector));
		  for(i = 0; i < last_num; i ++)
			disk_write(filesys_disk, tmp2.sector[i], zeros);

		  disk_write(filesys_disk, tmp.sector[sin_num - 1], &tmp2);
		  disk_write(filesys_disk, disk_inode->doubly, &tmp);
		}
	  }
	  disk_write(filesys_disk, sector, disk_inode);
	  
	  success = true;
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  disk_read (filesys_disk, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
		  size_t len = bytes_to_sectors (inode->data.length);

		  free_map_release_advanced(inode->data.direct, (len <= 12)?len:12);
		  if(len > 12)
		  {
			struct indirect_inode tmp;
			disk_read(filesys_disk, inode->data.single, &tmp);
			free_map_release(inode->data.single, 1);
			free_map_release_advanced(tmp.sector, (len <= 12 + 128)?(len - 12):128);
			if(len > 12 + 128)
			{
			  ASSERT(len < 12 + 128 + 128*128);
			  disk_read(filesys_disk, inode->data.doubly, &tmp);
			  free_map_release(inode->data.doubly, 1);
			  struct indirect_inode tmp2;
			  int i, a = (len - 12 - 128 - 1) / 128 + 1, b = (len - 12 - 128) % 128;
			  if(b == 0)
				b = 128;
			  for(i = 0 ; i < a - 1 ; i ++)
			  {
				disk_read(filesys_disk, tmp.sector[i], &tmp2);
				free_map_release(tmp.sector[i], 1);
				free_map_release_advanced(tmp2.sector, 128);
			  }
			  disk_read(filesys_disk, tmp.sector[a - 1], &tmp2);
			  free_map_release(tmp.sector[a - 1], 1);
			  free_map_release_advanced(tmp2.sector, b);
			}
		  }
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Read full sector directly into caller's buffer. */
		  cache_read(sector_idx, buffer + bytes_read);
          //disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
		  cache_read(sector_idx, bounce);
          //disk_read (filesys_disk, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

//	extend file by maximum one disk block
void extend_file(struct inode *inode, off_t len)
{
  ASSERT(len <= DISK_SECTOR_SIZE);
  struct inode_disk *disk_inode = &inode->data;
  off_t cur_len = inode_length(inode);
  off_t sectors = 0;
  if(cur_len > 0)
	sectors = (cur_len - 1)/ DISK_SECTOR_SIZE + 1;
  off_t aim = (cur_len + len - 1) / DISK_SECTOR_SIZE + 1;
  
  if(aim > sectors)	//	allocate one more block
  {
	ASSERT(aim == sectors + 1);
	static char zeros[DISK_SECTOR_SIZE];
	struct indirect_inode tmp, tmp2;
    if(sectors < 12)
	{
	  free_map_allocate(1, &disk_inode->direct[sectors]);
	  disk_write(filesys_disk, disk_inode->direct[sectors], zeros);
	}
	else if(sectors == 12)
	{
	  free_map_allocate(1, &disk_inode->single);
	  free_map_allocate(1, &tmp.sector[0]);
	  disk_write(filesys_disk, tmp.sector[0], zeros);
	  disk_write(filesys_disk, disk_inode->single, &tmp);
	}
	else if(sectors < 12 + 128)
	{
	  disk_read(filesys_disk, disk_inode->single, &tmp);
	  free_map_allocate(1, &tmp.sector[sectors - 12]);
	  disk_write(filesys_disk, tmp.sector[sectors - 12], zeros);
	  disk_write(filesys_disk, disk_inode->single, &tmp);
	}
	else if(sectors == 12 + 128)
	{
	  free_map_allocate(1, &disk_inode->doubly);
	  free_map_allocate(1, &tmp.sector[0]);
	  free_map_allocate(1, &tmp2.sector[0]);
	  disk_write(filesys_disk, tmp2.sector[0], zeros);
	  disk_write(filesys_disk, tmp.sector[0], &tmp2);
	  disk_write(filesys_disk, disk_inode->doubly, &tmp);
	}
	else if(sectors >= 12 + 128 + 128*128)
	{
	  printf("inode is using (12 + 128 + 128*128) sectors\n");
	  NOT_REACHED();
	}
	else if((sectors - 12 - 128) % 128 == 0)
	{
	  int loc = (sectors - 12 - 128) / 128;
	  disk_read(filesys_disk, disk_inode->doubly, &tmp);
	  free_map_allocate(1, &tmp.sector[loc]);
	  free_map_allocate(1, &tmp2.sector[0]);
	  disk_write(filesys_disk, tmp2.sector[0], zeros);
	  disk_write(filesys_disk, tmp.sector[loc], &tmp2);
	  disk_write(filesys_disk, disk_inode->doubly, &tmp);
	}
	else
	{
	  int loc1 = (sectors - 12 - 128) / 128 , loc2 = (sectors - 12 - 128) % 128;
	  disk_read(filesys_disk, disk_inode->doubly, &tmp);
	  disk_read(filesys_disk, tmp.sector[loc1], &tmp2);
	  free_map_allocate(1, &tmp2.sector[loc2]);
	  disk_write(filesys_disk, tmp2.sector[loc2], zeros);
	  disk_write(filesys_disk, tmp.sector[loc1], &tmp2);
	}
  }
  else
	ASSERT(aim == sectors);

  disk_inode->length += len;
  disk_write(filesys_disk, inode->sector, disk_inode);
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  //	extend file
  while(offset + size > inode_length(inode))
  {
	off_t piece = (offset + size) - inode_length(inode);
	extend_file(inode, (piece < DISK_SECTOR_SIZE)?piece:DISK_SECTOR_SIZE);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Write full sector directly to disk. */
			cache_write(sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
			  cache_read(sector_idx, bounce);
          else
            memset (bounce, 0, DISK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
		  cache_write(sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

disk_sector_t inode_get_sector(struct inode *inode, off_t off)
{
  return byte_to_sector(inode, off);
}

bool inode_is_dir(struct inode *inode)
{
  return inode->data.is_dir;
}

int inode_open_cnt(struct inode *inode)
{
  return inode->open_cnt;
}

void inode_set_parent(struct inode *parent, disk_sector_t child_sector)
{
  struct inode *child = inode_open(child_sector);
  child->data.parent = parent->sector;
  disk_write(filesys_disk, child_sector, &child->data);
  inode_close(child);
}

struct inode *
inode_open_parent(struct inode *child)
{
  return inode_open(child->data.parent);
}
