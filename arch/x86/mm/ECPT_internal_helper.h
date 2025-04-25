#ifndef _ECPT_INTERNAL_HELPER_H
#define _ECPT_INTERNAL_HELPER_H

#include "linux/types.h"
#include <linux/mm_types.h>
uint64_t gen_hash_64(uint64_t vpn, uint64_t size, uint32_t way);
uint64_t early_gen_hash_64(uint64_t vpn, uint64_t size, uint32_t way,
			   uint64_t kernel_start, uint64_t physaddr);

uint32_t get_rand_way(uint32_t n_way);

void *fixup_pointer(void *ptr, uint64_t kernel_start, uint64_t physaddr);

uint64_t alloc_way_default(uint32_t n_entries);
void free_one_way(uint64_t cr);

inline void add_pgtable_bytes(struct mm_struct *mm, uint64_t table_desc);
inline void sub_pgtable_bytes(struct mm_struct *mm, uint64_t table_desc);
#endif /* _ECPT_INTERNAL_HELPER_H */