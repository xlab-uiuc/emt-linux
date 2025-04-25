#ifndef _ASM_X86_FPT_H
#define _ASM_X86_FPT_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/pgtable.h>
#include "asm/fpt_defs.h"

void free_pgd_range(struct mmu_gather *tlb, unsigned long addr, unsigned long end,
                    unsigned long floor, unsigned long ceiling);

static inline unsigned long acquire_pgtable_index(unsigned long address,
						  uint32_t shift,
						  uint32_t ptrs_per_entry)
{
	return (address >> shift) & (ptrs_per_entry - 1);
}

static inline pud_t *fpt_pud_offset(struct mm_struct *mm, p4d_t *p4d,
				    unsigned long addr)
{
	bool pgd_folded = ((struct fpt_desc *)mm->map_desc)->pgd_folded;
	uint32_t n_ptrs = PTRS_PER_PUD;
	if (pgd_folded) {
		/* Folded then p4d is already the pointer to L4L3 table */
		n_ptrs = PTRS_PER_PGD * PTRS_PER_P4D * PTRS_PER_PUD;
		uint32_t idx = acquire_pgtable_index(addr, PUD_SHIFT, n_ptrs);
		// pr_info_verbose("p4d=%llx, idx=%d\n", (uint64_t)p4d, idx);
		return ((pud_t *)p4d) + idx;
	}

	return p4d_pgtable(*p4d) +
	       acquire_pgtable_index(addr, PUD_SHIFT, n_ptrs);
}

static inline pmd_t *fpt_pmd_offset(struct mm_struct *mm, pud_t *pud,
				    unsigned long addr)
{
	bool pud_folded = NEXT_LEVEL_IS_FOLDED(pud->pud);
	uint32_t n_ptrs = PTRS_PER_PMD;
	if (pud_folded) {
		n_ptrs = PTRS_PER_PUD * PTRS_PER_PMD;
	}
	// pr_info_verbose("pud_pgtable(*pud)=%llx, shift=%d, n_ptrs=%d\n", (uint64_t) pud_pgtable(*pud), PMD_SHIFT, n_ptrs);
	return pud_pgtable(*pud) +
	       acquire_pgtable_index(addr, PMD_SHIFT, n_ptrs);
}

static inline pte_t *fpt_pte_offset(struct mm_struct *mm, pmd_t *pmd,
				    unsigned long addr)
{
	bool pmd_folded = NEXT_LEVEL_IS_FOLDED(pmd->pmd);
	uint32_t n_ptrs = PTRS_PER_PTE;
	if (pmd_folded) {
		n_ptrs = PTRS_PER_PMD * PTRS_PER_PTE;
	}
	// pr_info_verbose("pmd_pgtable(*pmd)=%llx, shift=%d, n_ptrs=%d\n", (uint64_t) pmd_pgtable(*pmd), PAGE_SHIFT, n_ptrs);
	return ((pte_t *)pmd_page_vaddr(*pmd)) +
	       acquire_pgtable_index(addr, PAGE_SHIFT, n_ptrs);
}

static inline uint32_t get_fpt_attr_flags(struct mm_struct *mm)
{
	return ((struct fpt_desc *)mm->map_desc)->attr_flags;
}

static inline int should_skip_pgd(struct mm_struct *mm)
{
	return !!(get_fpt_attr_flags(mm) & FPT_L4_L3_FOLD_FLAG);
}

static inline int should_skip_p4d(struct mm_struct *mm)
{
	return 1;
}

static inline int should_skip_pud(struct mm_struct *mm, p4d_t *p4d)
{
	return !!(get_fpt_attr_flags(mm) & FPT_L3_L2_FOLD_FLAG)&&NEXT_LEVEL_IS_FOLDED(p4d->p4d);
}

static inline int should_skip_pmd(struct mm_struct *mm, pud_t *pud)
{
	return !!(get_fpt_attr_flags(mm) & FPT_L2_L1_FOLD_FLAG)&&NEXT_LEVEL_IS_FOLDED(pud->pud);
}

static inline int should_skip_pte(struct mm_struct *mm, pmd_t *pmd)
{
	return 0;
}

static inline pte_t *fpt_pte_offset_map_with_mm(struct mm_struct *mm, pmd_t *pmd,
    unsigned long addr)
{
    if (should_skip_pte(mm, pmd))
        return (pte_t *)pmd;
    // return pte_offset_kernel((pmd), (addr));
    return fpt_pte_offset(mm, pmd, addr);
}

static inline pmd_t *fpt_pmd_offset_map_with_mm(struct mm_struct *mm, pud_t *pud,
                     unsigned long addr)
{
    if (should_skip_pmd(mm, pud))
        return ((pmd_t *)pud);
    // return pmd_offset((pud), (addr));
    return fpt_pmd_offset(mm, pud, addr);
}

static inline pud_t *fpt_pud_offset_map_with_mm(struct mm_struct *mm, p4d_t *p4d,
                     unsigned long addr)
{
    if (should_skip_pud(mm, p4d))
        return ((pud_t *)p4d);
    // return pud_offset((p4d), (addr));
    return fpt_pud_offset(mm, p4d, addr);
}

static inline p4d_t *fpt_p4d_offset_map_with_mm(struct mm_struct *mm, pgd_t *pgd,
                     unsigned long addr)
{
    if (should_skip_p4d(mm))
        return ((p4d_t *)pgd);
    return p4d_offset((pgd), (addr));
}

static inline pgd_t *fpt_pgd_offset_map_with_mm(struct mm_struct *mm, unsigned long addr)
{
    if (should_skip_pgd(mm))
        return ((mm)->pgd);

    return pgd_offset((mm), (addr));
}

#define __ARCH_HAS_PTE_OFFSET_MAP_WITH_MM
#define pte_offset_map_with_mm(mm, pmd, addr) fpt_pte_offset_map_with_mm((mm), (pmd), (addr))

#define __ARCH_HAS_PMD_OFFSET_MAP_WITH_MM
#define pmd_offset_map_with_mm(mm, pud, addr) fpt_pmd_offset_map_with_mm((mm), (pud), (addr))

#define __ARCH_HAS_PUD_OFFSET_MAP_WITH_MM
#define pud_offset_map_with_mm(mm, p4d, addr) fpt_pud_offset_map_with_mm((mm), (p4d), (addr))

#define __ARCH_HAS_P4D_OFFSET_MAP_WITH_MM
#define p4d_offset_map_with_mm(mm, pgd, addr) fpt_p4d_offset_map_with_mm((mm), (pgd), (addr))

#define __ARCH_HAS_PGD_OFFSET_MAP_WITH_MM
#define pgd_offset_map_with_mm(mm, addr) fpt_pgd_offset_map_with_mm((mm), (addr))

#endif
