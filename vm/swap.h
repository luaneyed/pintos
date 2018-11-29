#include <stddef.h>
#include "vm/page.h"

void init_swap_table(void);
size_t swap_out(struct pt_entry *);
void swap_in(size_t, struct pt_entry *);
void delete_swap(size_t);
bool swap(struct pt_entry *);
