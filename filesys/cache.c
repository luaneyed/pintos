#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "lib/kernel/list.h"
#include "threads/palloc.h"
#include "threads/synch.h"

static struct list cache_table;
static void* buffer_cache[64];
static struct lock ct_lock;

struct ct_entry
{
  struct list_elem elem;
  void *addr;
  disk_sector_t sector;
  bool dirty;
};

void cache_init(void)
{
  int i, j;
  struct ct_entry *tmp;

  list_init(&cache_table);
  lock_init(&ct_lock);

  /* Set all 64 slots for convenience */
  for(i = 0; i < 8; i++)
  {
	buffer_cache[8*i] = palloc_get_page(0);
	for(j = 1; j < 8; j++)
	{
	  buffer_cache[8*i + j] = buffer_cache[8*i] + j*DISK_SECTOR_SIZE; // pointer operation
	}
  }

  for(i = 0; i < 64; i++)
  {
    tmp =  (struct ct_entry *)malloc(sizeof(struct ct_entry));
	list_push_back(&cache_table, &tmp->elem);
    tmp->addr = buffer_cache[i];
	tmp->sector = -1;
	tmp->dirty = false;
  }
}

/* cache given disk sector to last cache slot */
struct ct_entry *
cache_insert(disk_sector_t sector, bool read)
{
  struct list_elem *elem = list_back(&cache_table);
  struct ct_entry *ent = list_entry(elem, struct ct_entry, elem);

  /* update sector if someone use it */
  if(ent->sector != -1 && ent->dirty == true)
    disk_write(filesys_disk, ent->sector, ent->addr);

  /* replace */
  if(read)
	disk_read(filesys_disk, sector, ent->addr);
  list_remove(elem);
  list_push_front(&cache_table, elem);
  ent->sector = sector;
  ent->dirty = false;

  return ent;
}

struct ct_entry *
cache_access (disk_sector_t sector)
{
  struct list_elem *iter;
  struct ct_entry *tmp;

  for(iter = list_begin(&cache_table);
	  iter != list_end(&cache_table);
	  iter = list_next(iter))
  {
	  tmp = list_entry(iter, struct ct_entry, elem);
	  /* CACHE HIT */
	  if(sector == tmp->sector)
	  {
		/* move to front for LRU evicting */
		list_remove(iter);
		list_push_front(&cache_table, iter);

	    return tmp;
	  }
  }
  return NULL;
}


void cache_write (disk_sector_t sector, void* buffer)
{
  lock_acquire(&ct_lock);

  struct ct_entry *cache = cache_access(sector);

  if(!cache)
	cache = cache_insert(sector, false);
  cache->dirty = true;

  memcpy(cache->addr, buffer, DISK_SECTOR_SIZE);
  lock_release(&ct_lock);
}

void cache_read (disk_sector_t sector, void* buffer)
{
  lock_acquire(&ct_lock);
  struct ct_entry *cache = cache_access(sector);

  if(!cache)
	cache = cache_insert(sector, true);

  memcpy(buffer, cache->addr, DISK_SECTOR_SIZE);
  lock_release(&ct_lock);
}



/*
void cache_insert

delete

evict

allocate
*/

  

/* READ
 * lookup -> if success : return addr
 *			 if   fail  : allocate -> full -> evict(+set table) return its addr
*/
