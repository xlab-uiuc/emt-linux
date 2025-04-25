#ifndef _ASM_X86_FPT_DEFS_H
#define _ASM_X86_FPT_DEFS_H

#include <asm/pgtable_types.h>
#define FPT_L4_L3_FOLD_FLAG (1ULL << 0)
#define FPT_L3_L2_FOLD_FLAG (1ULL << 1)
#define FPT_L2_L1_FOLD_FLAG (1ULL << 2)

#define FPT_REGULAR_ALLOC_ORDER 0
#define FPT_FLATTENED_ALLOC_ORDER 9

#define CR3_L4_L3_FOLDED_SHIFT (63)
#define CR3_L4_L3_FOLDED_BIT (1ULL << CR3_L4_L3_FOLDED_SHIFT)
#define L4_L3_IS_FOLDED(pte) (pte & CR3_L4_L3_FOLDED_BIT)

#define NEXT_LEVEL_FOLDED_BIT 58
#define NEXT_LEVEL_FOLDED_MASK (1ULL << NEXT_LEVEL_FOLDED_BIT)
#define NEXT_LEVEL_IS_FOLDED(pte) (pte & NEXT_LEVEL_FOLDED_MASK)

struct fpt_desc {
    pgd_t *pgd;
    uint32_t attr_flags;
    
    bool pgd_folded;
};


#define __HAVE_ARCH_CREATE_CONTEXT
#define __HAVE_ARCH_READ_TENTRY
#define __HAVE_ARCH_INSERT_TENTRY
#define __ARCH_HAS_TENTRY_ITER_N_NEXT
#define __HAVE_ARCH_FREE_PGD_RANGE

#endif /* _ASM_X86_FPT_DEFS_H */