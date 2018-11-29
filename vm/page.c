#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "filesys/file.h"

struct pt_entry* mk_pt_entry(uint32_t vaddr, uint32_t pte)
{
  struct pt_entry* ent = (struct pt_entry*)malloc(sizeof(struct pt_entry));
  
  ent->vaddr = vaddr;
  ent->paddr = pte;
  ent->on_memory = true;
  ent->file = NULL;
  ent->mmf = false;
  ent->writable = false;	//	maybe not? temp init

  return ent;
}

void rm_pt_entry(struct pt_entry* ent)
{
  if(ent->file)
  {
	if(ent->on_memory)	//	mmf => on_memory
	{
	  swap_out(ent);
	  delete_ft_entry(ent->paddr);
	  palloc_free_page(ent->paddr);
	}
  }
  else
  {
	if(ent->on_memory)
	{
	  delete_ft_entry(ent->paddr);
	  palloc_free_page(ent->paddr);
	}
	else
	  delete_swap(ent->swap_idx);
  }
  free(ent);
}

struct pt_entry *insert_pt(uint32_t vaddr, uint32_t pte)
{
  struct pt_entry* ent = mk_pt_entry(vaddr, pte);
  hash_replace(thread_current()->sup_pt, &ent->hash_elem);
  return ent;
}

struct pt_entry *insert_mmap_pt(uint32_t vaddr, struct file* f, off_t off, int sec_num)
{
  acq_ft_lock();
  struct pt_entry *ent = (struct pt_entry *) malloc (sizeof(struct pt_entry));

  ent->vaddr = vaddr;
  ent->paddr = 0;
  ent->on_memory = false;
  ent->file = f;
  ent->off = off;
  ent->sec_num = sec_num;
  int i;
  for(i = 0; i < sec_num ; i ++)
	ent->sectors[i] = file_get_sector(f, off + i * DISK_SECTOR_SIZE);
  ent->swap_idx = -1;
  ent->mmf = true;
  ent->sector = file_get_sector(f, off);
  if(file_denied_write(f))
	ent->writable = false;
  else
	ent->writable = true;

  pagedir_clear_page_advanced(thread_current()->pagedir, vaddr, ent->writable);

  hash_replace(thread_current()->sup_pt, &ent->hash_elem);
  rel_ft_lock();

  swap(ent);

  return ent;
}

struct pt_entry *insert_lazy_pt(uint32_t vaddr, struct file* f, off_t off)
{
  acq_ft_lock();
  struct pt_entry *ent = (struct pt_entry *) malloc (sizeof(struct pt_entry));

  ent->vaddr = vaddr;
  ent->paddr = 0;
  ent->on_memory = false;
  ent->file = f;
  ent->off = off;
  ent->swap_idx = -1;
  ent->mmf = false;

  hash_replace(thread_current()->sup_pt, &ent->hash_elem);
  rel_ft_lock();
  return ent;
}

struct pt_entry* find_pt_entry(uint32_t vaddr)
{
  struct pt_entry temp;
  temp.vaddr = vaddr;
  struct hash_elem *e = hash_find(thread_current()->sup_pt, &temp.hash_elem);
  return e!=NULL ? hash_entry(e, struct pt_entry, hash_elem) : NULL;
}

void delete_pt(uint32_t vaddr)
{
  struct pt_entry* ent = find_pt_entry(vaddr);
  if(!ent)
	return;
  hash_delete(thread_current()->sup_pt, &ent->hash_elem);
  rm_pt_entry(ent);
}

unsigned pt_hash(const struct hash_elem *e, void *aux UNUSED)
{
  const struct pt_entry *ent = hash_entry(e, struct pt_entry, hash_elem);
  return hash_bytes(&ent->vaddr, sizeof(ent->vaddr));
}

bool pt_less(const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED)	
{
  const struct pt_entry *ent1 = hash_entry(e1, struct pt_entry, hash_elem);
  const struct pt_entry *ent2 = hash_entry(e2, struct pt_entry, hash_elem);
  bool ret = ent1->vaddr < ent2->vaddr;
  return ret;
}

void pt_destroy_actfun(struct hash_elem *elem, void *aux UNUSED)
{
  struct pt_entry* ent = hash_entry(elem, struct pt_entry, hash_elem);
  rm_pt_entry(ent);
}
