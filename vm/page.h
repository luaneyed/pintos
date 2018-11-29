#include <stdint.h>
#include <hash.h>
#include "filesys/off_t.h"
#include "devices/disk.h"

struct pt_entry
{
  uint32_t vaddr;
  struct hash_elem hash_elem;

  uint32_t paddr;	//	pte
  size_t swap_idx;
  
  struct file* file;
  off_t off;
  int sec_num;	//	used sector number on filesys_disk
  disk_sector_t sectors[8];
  disk_sector_t sector;
  
  bool on_memory;
  bool mmf;
  bool writable;
};

struct pt_entry* mk_pt_entry(uint32_t vaddr, uint32_t pte);
void rm_pt_entry(struct pt_entry* ent);

struct pt_entry *insert_mmap_pt(uint32_t vaddr, struct file* file, off_t off, int sec_num);
struct pt_entry *insert_lazy_pt(uint32_t vaddr, struct file* file, off_t off);
struct pt_entry *insert_pt(uint32_t vaddr, uint32_t pte);
struct pt_entry* find_pt_entry(uint32_t vaddr);
void delete_pt(uint32_t vaddr);

unsigned pt_hash(const struct hash_elem *e, void *aux);
bool pt_less(const struct hash_elem *e1, const struct hash_elem *e2, void *aux);
void pt_destroy_actfun(struct hash_elem *elem, void *aux);
