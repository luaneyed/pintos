#ifndef USERPROG_PAGEDIR_H
#define USERPROG_PAGEDIR_H

#include <stdbool.h>
#include <stdint.h>

uint32_t *pagedir_create (void);
void pagedir_destroy (uint32_t *pd);
uint32_t *lookup_page(uint32_t *, const void *, bool);
bool pagedir_set_page (uint32_t *pd, void *upage, void *kpage, bool rw);
void *pagedir_get_page (uint32_t *pd, const void *upage);
uint32_t *pagedir_get_pte (uint32_t *pd, const void *uaddr);
void pagedir_clear_page (uint32_t *pd, void *upage);
void pagedir_clear_page_advanced (uint32_t *pd, void *upage, bool writable);
bool pagedir_is_dirty (uint32_t *pd, const void *upage);
void pagedir_set_dirty (uint32_t *pd, const void *upage, bool dirty);
bool pagedir_is_accessed (uint32_t *pd, const void *upage);
void pagedir_set_accessed (uint32_t *pd, const void *upage, bool accessed);
void pagedir_activate (uint32_t *pd);

#endif /* userprog/pagedir.h */
