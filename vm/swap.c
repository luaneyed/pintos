#include <bitmap.h>
#include "devices/disk.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"

static struct lock swap_lock;
static struct disk *swap_disk;
static struct disk *file_disk;
static struct bitmap *swap_table;

void init_swap_table(void)
{
  lock_init(&swap_lock);
  swap_disk = disk_get(1,1);
  file_disk = disk_get(0,1);
  ASSERT(swap_disk);
  swap_table = bitmap_create(disk_size(swap_disk)/8);
  ASSERT(swap_table);
}

size_t swap_out(struct pt_entry* spte)
{
  lock_acquire(&swap_lock);
  spte->on_memory = false;
  int i;
  if(spte->file)
  {
	if(pagedir_is_dirty(thread_current()->pagedir, spte->vaddr))
	{
	  for(i = 0; i < spte->sec_num; i ++)
	  {
		cache_write(spte->sectors[i], spte->paddr + DISK_SECTOR_SIZE * i);
		//disk_write(file_disk, spte->sectors[i], spte->paddr + DISK_SECTOR_SIZE * i);
	  }	
	}
	lock_release(&swap_lock);
	return spte->swap_idx;	//	= -1
  }
  else
  {
	size_t idx = bitmap_scan_and_flip(swap_table, 0, 1, false);
	ASSERT(idx != BITMAP_ERROR);
	for(i = 0; i < 8; i++)
	  disk_write(swap_disk, 8*idx + i, spte->paddr + DISK_SECTOR_SIZE*i);
	lock_release(&swap_lock);
	return idx;
  }
}

void swap_in(size_t idx, struct pt_entry* spte)
{
  lock_acquire(&swap_lock);
  int i;
  if(spte->file)	//	only for mmf. lazy loaded pages are dealt with in lazy_load
  {
	for(i = 0; i < spte->sec_num; i ++)
	  cache_read(spte->sectors[i], spte->paddr + DISK_SECTOR_SIZE * i);
      //disk_read(file_disk, spte->sectors[i], spte->paddr + DISK_SECTOR_SIZE * i);
  }
  else{
	for(i = 0; i < 8; i++)
	  disk_read(swap_disk,  8*idx + i, spte->paddr + DISK_SECTOR_SIZE*i);
	bitmap_flip(swap_table, idx);
  }
  spte->on_memory = true;
  lock_release(&swap_lock);
}

void delete_swap(size_t idx)
{
  ASSERT(bitmap_test(swap_table, idx));
  bitmap_reset(swap_table, idx);
}

bool swap(struct pt_entry *spte)
{
  ASSERT(spte);
  ASSERT(!spte->on_memory);

  size_t idx = spte->swap_idx;
  void *frame = vm_palloc(spte->vaddr, PAL_USER);
  uint32_t *pd = thread_current()->pagedir;
  bool writable = ((*lookup_page(pd, spte->vaddr, false) & PTE_W) != 0);

  spte->paddr = frame;
  swap_in(idx, spte);
  
  if (!pagedir_set_page (pd, spte->vaddr, frame, writable))
  {
    vm_free (frame);
    return false;
  }
  return true;
}

