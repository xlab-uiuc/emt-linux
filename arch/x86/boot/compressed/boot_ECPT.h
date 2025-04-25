#ifndef BOOT_COMPRESSED_ECPT_H
#define BOOT_COMPRESSED_ECPT_H

#include <asm/ECPT.h>
#include <asm/pgtable.h>

#define HPT_SIZE_HIDDEN_BITS (4)
#define GET_HPT_SIZE_WITH_HIDDEN(cr3) ((((uint64_t) cr3) & HPT_SIZE_MASK ) << HPT_SIZE_HIDDEN_BITS)
#define HPT_NUM_ENTRIES_TO_CR3_WITH_HIDDEN(size) (((uint64_t) size ) >> HPT_SIZE_HIDDEN_BITS)

/* used in compressed kernel, will be replaced in the future */
int hpt_insert(uint64_t cr3, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, uint32_t override);


#endif /* BOOT_COMPRESSED_ECPT_H */
