#include <devices/disk.h>

void cache_init(void);
void cache_read(disk_sector_t, void*);
void cache_write(disk_sector_t, void*);
