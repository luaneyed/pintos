#include "threads/thread.h"
#include <stdint.h>

struct ft_entry
{
  struct list_elem elem;
  void *frame;
  struct pt_entry *spte;
  struct thread *owner;
};

void acq_ft_lock(void);
void rel_ft_lock(void);

void init_frame_table(void);
void insert_ft_entry(void *, void *);
void delete_ft_entry(void *);
void *vm_palloc(uint8_t *upage, enum palloc_flags);
void vm_free(void *);
