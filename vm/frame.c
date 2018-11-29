#include <devices/timer.h>
#include "lib/kernel/list.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/frame.h"

static struct lock ft_lock;

static struct list frame_table;

void init_frame_table(void)
{
  lock_init(&ft_lock);
  list_init(&frame_table);
}

void acq_ft_lock()
{
  lock_acquire(&ft_lock);
}

void rel_ft_lock()
{
  lock_release(&ft_lock);
}

void insert_ft_entry(void *page, void *frame)
{
  struct ft_entry *fte;
  struct pt_entry *spte;

  fte = (struct ft_entry *) malloc(sizeof(struct ft_entry));

  if(!(spte = find_pt_entry(page)))
	spte = insert_pt(page, frame);

  spte->on_memory = true;
  spte->swap_idx = -1;
  spte->paddr = frame;
  if(spte->mmf == false)
  {
	spte->file = NULL;
    spte->off = -1;
  }

  fte->frame = frame;
  fte->spte = spte;
  fte->owner = thread_current();

  list_push_back(&frame_table, &fte->elem);
}

void delete_ft_entry(void *frame)
{
  struct list_elem *e;
  struct ft_entry *fte;

  for(e = list_begin(&frame_table);
  	e != list_tail(&frame_table);
  	e = list_next(e))
  {
	fte = list_entry(e, struct ft_entry, elem);
	if(fte->frame == frame)
	{
	  list_remove(e);
	  free(fte);
	  break;
	}
  }
}

struct ft_entry
*select_victim_frame(void)
{
  struct list_elem *trav = list_begin(&frame_table);

  while(trav != list_end(&frame_table))
  {
	struct ft_entry *fte = list_entry(trav, struct ft_entry, elem);
	uint32_t *pd = fte->owner->pagedir;

	struct list_elem *next = list_next(trav);
	bool is_one_elem = (next == list_end(&frame_table));
	if(!is_one_elem)
	{
	  list_remove(trav);
	  list_push_back(&frame_table, trav);
	}

	if(!fte->spte->mmf)
	{
	  if(pagedir_is_accessed(pd, fte->spte->vaddr))
		pagedir_set_accessed(pd, fte->spte->vaddr, false);
	  else
		return fte;
	}

	if(!is_one_elem)
	  trav = next;
  }
  NOT_REACHED();
}

void *evict_frame(void *upage)
{
  struct ft_entry *fte;
  struct pt_entry *spte;
  struct pt_entry *new_spte;
  size_t idx;
  
  fte = select_victim_frame();
  spte = fte->spte;

  idx = swap_out(spte);

  pagedir_clear_page(fte->owner->pagedir, spte->vaddr);
  
  /* update victim's info */
  //spte->on_memory = false;
  spte->swap_idx = idx;
  spte->paddr = NULL;

  /* set new page's spte */
  if(new_spte = find_pt_entry(upage))  // already in spt -> swap case
	new_spte->paddr = fte->frame;
  else
    new_spte = insert_pt(upage, fte->frame);

  new_spte->on_memory = true;
  new_spte->swap_idx = -1;

  /* update frame table */
  fte->owner = thread_current();
  fte->spte = new_spte;
  
  return fte->frame;
}

void *vm_palloc(uint8_t *upage, enum palloc_flags flag)
{
  lock_acquire(&ft_lock);
  ASSERT(flag & PAL_USER);
  ASSERT(!(flag & PAL_ASSERT));

  void* frame = palloc_get_page(flag);
  if(frame)
	insert_ft_entry(upage, frame);
  else
	frame = evict_frame(upage);

  ASSERT(frame);
  lock_release(&ft_lock);
  return frame;
}

void vm_free(void *upage)
{
  lock_acquire(&ft_lock);
  
  struct pt_entry* spte = find_pt_entry(upage);
  if(spte)
	delete_pt(spte);

  lock_release(&ft_lock);
}
