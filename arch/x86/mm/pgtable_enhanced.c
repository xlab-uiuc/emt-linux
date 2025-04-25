#include "asm-generic/rwonce.h"

#include "asm/fpt_defs.h"
#include "asm/processor.h"
#include "linux/pgtable.h"
#include "linux/printk.h"
#include "linux/spinlock.h"
#include "linux/spinlock_types.h"
#include <asm/pgtable.h>
#include "asm/pgtable_types.h"
#include "linux/compiler.h"
#include "linux/hugetlb.h"
#include "linux/types.h"
#include <linux/mm.h>
#include <asm/pgalloc.h>
#include <linux/pgtable_enhanced.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/pgtable_64.h>

#ifndef __HAVE_ARCH_MK_P4D_ACCESSSIBLE
inline void pgd_mk_p4d_accessible(struct mm_struct *mm, pgd_t *pgd, unsigned long addr, p4d_t *p4d)
{
	pgd_populate(mm, pgd, p4d);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PUD_ACCESSSIBLE
inline void p4d_mk_pud_accessible(struct mm_struct *mm, p4d_t *p4d, unsigned long addr, pud_t *pud)
{
	p4d_populate(mm, p4d, pud);
}
#endif /* __HAVE_ARCH_MK_PUD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PMD_ACCESSSIBLE
inline void pud_mk_pmd_accessible(struct mm_struct *mm, pud_t *pud,
	unsigned long addr, pmd_t *pmd)
{
	pud_populate(mm, pud, pmd);
}
#endif /* __HAVE_ARCH_MK_PMD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE
inline void pmd_mk_pte_accessible(struct mm_struct *mm, pmd_t *pmd,
	unsigned long addr, struct page *pte)
{
	pmd_populate(mm, pmd, pte);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL
inline void pmd_mk_pte_accessible_kernel(struct mm_struct *mm, pmd_t *pmd,
	unsigned long addr, pte_t *pte)
{
	pmd_populate_kernel(mm, pmd, pte);
}
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL  */

#ifndef	 __ARCH_HAS_PTE_OFFSET_MAP_WITH_MM
inline pte_t *pte_offset_map_with_mm(struct mm_struct *mm, pmd_t *pmd, unsigned long addr)
{
	return pte_offset_kernel((pmd), (addr));
}
#endif

#ifndef	 __ARCH_HAS_PMD_OFFSET_MAP_WITH_MM
inline pmd_t *pmd_offset_map_with_mm(struct mm_struct *mm, pud_t *pud, unsigned long addr)
{
	return pmd_offset((pud), (addr));
}
#endif

#ifndef	 __ARCH_HAS_PUD_OFFSET_MAP_WITH_MM
inline pud_t *pud_offset_map_with_mm(struct mm_struct *mm, p4d_t *p4d, unsigned long addr)
{
	return pud_offset((p4d), (addr));
}
#endif

#ifndef	 __ARCH_HAS_P4D_OFFSET_MAP_WITH_MM
inline p4d_t *p4d_offset_map_with_mm(struct mm_struct *mm, pgd_t *pgd, unsigned long addr)
{
	return p4d_offset((pgd), (addr));
}
#endif

#ifndef	 __ARCH_HAS_PGD_OFFSET_MAP_WITH_MM
inline pgd_t *pgd_offset_map_with_mm(struct mm_struct *mm, unsigned long addr)
{
	return pgd_offset((mm), (addr));
}
#endif

#ifndef	 __ARCH_HAS_PTEP_GET_NEXT
inline pte_t * ptep_get_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr)
{
	return ptep + 1;
}
#endif

#ifndef	 __ARCH_HAS_PTEP_GET_PREV
inline pte_t * ptep_get_prev(struct mm_struct *mm, pte_t * ptep, unsigned long addr)
{
	return ptep - 1;
}
#endif

#ifndef	 __ARCH_HAS_PTEP_GET_N_NEXT
inline pte_t * ptep_get_n_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr, unsigned int n)
{
	return ptep + n;
}
#endif


#ifndef	 __ARCH_HAS_PMDP_GET_NEXT
inline pmd_t * pmdp_get_next(struct mm_struct *mm, pmd_t *pmdp, unsigned long addr)
{
	return pmdp + 1;
}
#endif

#ifndef	 __ARCH_HAS_PUDP_GET_NEXT
inline pud_t * pudp_get_next(struct mm_struct *mm, pud_t *pudp, unsigned long addr)
{
	return pudp + 1;
}
#endif

#ifndef	 __ARCH_HAS_P4DP_GET_NEXT
inline p4d_t * p4dp_get_next(struct mm_struct *mm, p4d_t *p4dp, unsigned long addr)
{
	return p4dp + 1;
}
#endif

#ifndef	 __ARCH_HAS_PGDP_GET_NEXT
inline pgd_t * pgdp_get_next(struct mm_struct *mm, pgd_t *pgdp, unsigned long addr)
{
	WARN(1, "pgdp_get_next old routine\n");
	return pgdp + 1;
}
#endif


#ifndef __HAVE_ARCH_NO_P4D_PGTABLE
inline int no_p4d_and_lower_pgtable(pgd_t pgd)
{
	return pgd_none(pgd);
}
#endif

#ifndef __HAVE_ARCH_NO_PUD_PGTABLE
inline int no_pud_and_lower_pgtable(p4d_t p4d)
{
	return p4d_none(p4d);
}
#endif

#ifndef __HAVE_ARCH_NO_PMD_PGTABLE
inline int no_pmd_and_lower_pgtable(pud_t pud)
{
	return pud_none(pud);
}
#endif

#ifndef __HAVE_ARCH_NO_PTE_PGTABLE
inline int no_pte_pgtable(pmd_t pmd)
{
	return pmd_none(pmd);
}
#endif

#ifndef __HAVE_ARCH_NO_PGD_HUGE_PAGE
inline int no_pgd_huge_page(pgd_t pgd)
{
	return 1; 	/* most arch don't have pgd page support */
}
#endif

#ifndef __HAVE_ARCH_NO_P4D_HUGE_PAGE
inline int no_p4d_huge_page(p4d_t p4d)
{
	return 1;	/* most arch don't have p4d page support */
}
#endif

#ifndef __HAVE_ARCH_NO_PUD_HUGE_PAGE
inline int no_pud_huge_page(pud_t pud)
{
	return pud_none(pud);
}
#endif

#ifndef __HAVE_ARCH_NO_PMD_HUGE_PAGE
inline int no_pmd_huge_page(pmd_t pmd)
{
	return pmd_none(pmd);
}
#endif

#ifndef __HAVE_ARCH_NO_PGD_HUGE_AND_P4D_PGTABLE
inline int no_pgd_huge_and_p4d_pgtable(pgd_t pgd)
{
	return no_pgd_huge_page(pgd) && no_p4d_and_lower_pgtable(pgd);
}
#endif

#ifndef __HAVE_ARCH_NO_P4D_HUGE_AND_PUD_PGTABLE
inline int no_p4d_huge_and_pud_pgtable(p4d_t p4d)
{
	return no_p4d_huge_page(p4d) && no_pud_and_lower_pgtable(p4d);
}
#endif

#ifndef __HAVE_ARCH_NO_PUD_HUGE_AND_PMD_PGTABLE
inline int no_pud_huge_and_pmd_pgtable(pud_t pud)
{
	return no_pud_huge_page(pud) && no_pmd_and_lower_pgtable(pud);
}
#endif

static inline int radix_pte_is_data_page(pte_t pte)
{
	return !pte_none(pte);
}

static inline int radix_pmd_is_data_page(pmd_t pmd)
{
	return !pmd_none(pmd) && pmd_trans_huge(pmd);
}

static inline int radix_pud_is_data_page(pud_t pud)
{
	return !pud_none(pud) && pud_trans_huge(pud);
}

static inline int radix_p4d_is_data_page(p4d_t p4d)
{
	return p4d_huge(p4d);
}

static inline int radix_pgd_is_data_page(pgd_t pgd)
{
	return pgd_huge(pgd);
}

#ifndef __HAVE_ARCH_GEN_PTE_IS_DATA_PAGE
inline int gen_pte_is_data_page(gen_pte_t gen_pte, pgtable_level level)
{
	switch (level) {
		case PG_LEVEL_PTE:
			return radix_pte_is_data_page(gen_pte.pte);
			break;
		case PG_LEVEL_PMD:
			return radix_pmd_is_data_page(gen_pte.pmd);
			break;
		case PG_LEVEL_PUD:
			return radix_pud_is_data_page(gen_pte.pud);
			break;
		case PG_LEVEL_P4D:
			return radix_p4d_is_data_page(gen_pte.p4d);
			break;
		case PG_LEVEL_PGD:
			return radix_pgd_is_data_page(gen_pte.pgd);
			break;
		default:
			WARN(1, "Unknown page table level\n");
			return 0;
	}
}
#endif

static inline int radix_pte_is_directory(pte_t pte)
{
	/* PTE never a directory */
	return 0;
}

static inline int radix_pmd_is_directory(pmd_t pmd)
{
	return !pmd_none(pmd) && !radix_pmd_is_data_page(pmd);
}

static inline int radix_pud_is_directory(pud_t pud)
{
	return !pud_none(pud) && !radix_pud_is_data_page(pud);
}

static inline int radix_p4d_is_directory(p4d_t p4d)
{
	return !p4d_none(p4d) && !radix_p4d_is_data_page(p4d);
}

static inline int radix_pgd_is_directory(pgd_t pgd)
{
	return !pgd_none(pgd) && !radix_pgd_is_data_page(pgd);
}

#ifndef __HAVE_ARCH_GEN_PTE_IS_DIRECTORY
inline int gen_pte_is_directory(gen_pte_t gen_pte, pgtable_level level)
{
	switch (level) {
		case PG_LEVEL_PTE:
			return radix_pte_is_directory(gen_pte.pte);
			break;
		case PG_LEVEL_PMD:
			return radix_pmd_is_directory(gen_pte.pmd);
			break;
		case PG_LEVEL_PUD:
			return radix_pud_is_directory(gen_pte.pud);
			break;
		case PG_LEVEL_P4D:
			return radix_p4d_is_directory(gen_pte.p4d);
			break;
		case PG_LEVEL_PGD:
			return radix_pgd_is_directory(gen_pte.pgd);
			break;
		default:
			WARN(1, "Unknown page table level\n");
			return 0;
	}
}
#endif

static inline int radix_pte_is_partially_built(pte_t pte)
{
	return 0;
}

static inline int radix_pmd_is_partially_built(pmd_t pmd)
{
	return 0;
}

static inline int radix_pud_is_partially_built(pud_t pud)
{
	return 0;
}

static inline int radix_p4d_is_partially_built(p4d_t p4d)
{
	return 0;
}

static inline int radix_pgd_is_partially_built(pgd_t pgd)
{
	return 0;
}

#ifndef __HAVE_ARCH_GEN_PTE_IS_PARTIALLY_BUILT
inline int gen_pte_is_partially_built(gen_pte_t gen_pte, pgtable_level level,
				      struct mm_struct *mm, unsigned long addr)
{
	switch (level) {
		case PG_LEVEL_PTE:
			return radix_pte_is_partially_built(gen_pte.pte);
			break;
		case PG_LEVEL_PMD:
			return radix_pmd_is_partially_built(gen_pte.pmd);
			break;
		case PG_LEVEL_PUD:
			return radix_pud_is_partially_built(gen_pte.pud);
			break;
		case PG_LEVEL_P4D:
			return radix_p4d_is_partially_built(gen_pte.p4d);
			break;
		case PG_LEVEL_PGD:
			return radix_pgd_is_partially_built(gen_pte.pgd);
			break;
		default:
			WARN(1, "Unknown page table level\n");
			return 0;
	}
}
#endif

#ifndef __HAVE_ARCH_GEN_PTE_VOID
int gen_pte_void(gen_pte_t gen_pte, pgtable_level level, struct mm_struct *mm,
		 unsigned long addr, int is_partial_built_hint)
{
	return !gen_pte_is_data_page(gen_pte, level) &&
	       !gen_pte_is_directory(gen_pte, level) &&
	       !gen_pte_is_partially_built(gen_pte, level, mm, addr);
}
#endif

#ifndef __ARCH_HAS_PGD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pgd_next_level_not_accessible(pgd_t *pgd)
{
	return pgd_none_or_clear_bad(pgd);
}
#endif

#ifndef __ARCH_HAS_P4D_NEXT_LEVEL_NOT_ACCESSIBLE
inline int p4d_next_level_not_accessible(p4d_t *p4d)
{
	return p4d_none_or_clear_bad(p4d);
}
#endif

#ifndef __ARCH_HAS_PUD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pud_next_level_not_accessible(pud_t *pud)
{
	return pud_none_or_clear_bad(pud);
}
#endif

// #ifndef __ARCH_HAS_PMD_NEXT_LEVEL_NOT_ACCESSIBLE
// inline int pmd_next_level_not_accessible(pmd_t *pmd)
// {
// 	return pmd_none_or_trans_huge_or_clear_bad(pmd);
// }
// #endif

#define __DEFINE_GEN_PTE_READ_OP_WRAPPER(op)                                     \
	static unsigned long gen_pte_##op##_wrapper(gen_pte_t gen_pte,           \
						  pgtable_level level)         \
	{                                                                      \
			switch (level) {                                       \
			case PG_LEVEL_PTE:                                     \
				return gen_pte_read(gen_pte.pte, LEVEL_PTE,    \
						    op);                       \
			case PG_LEVEL_PMD:                                     \
				return gen_pte_read(gen_pte.pmd, LEVEL_PMD,    \
						    op);                       \
			case PG_LEVEL_PUD:                                     \
				return gen_pte_read(gen_pte.pud, LEVEL_PUD,    \
						    op);                       \
			case PG_LEVEL_P4D:                                     \
				return gen_pte_read(gen_pte.p4d, LEVEL_P4D,    \
						    op);                       \
			case PG_LEVEL_PGD:                                     \
				return gen_pte_read(gen_pte.pgd, LEVEL_PGD,    \
						    op);                       \
			default:                                               \
				WARN(1, "Unknown page table level=%d\n",       \
				     level);                                   \
				return 0;                                      \
			}                                                      \
	}

#define DEFINE_GEN_PTE_READ_OP_WRAPPER(op) __DEFINE_GEN_PTE_READ_OP_WRAPPER(op)

#define __DEFINE_EMPTY_READ_OP_HELPER(level, op, argtype)                      \
	static inline int native_##level##_##op(argtype pte)                   \
	{                                                                      \
			WARN(1, "not supported operation!\n");                 \
			return 0;                                              \
	}

#define DEFINE_EMPTY_READ_OP_HELPER(level, op, argtype)                        \
	__DEFINE_EMPTY_READ_OP_HELPER(level, op, argtype)

DEFINE_EMPTY_READ_OP_HELPER(LEVEL_PTE, PTE_ATTR_BAD, pte_t)

DEFINE_EMPTY_READ_OP_HELPER(LEVEL_PTE, PTE_ATTR_TRANS_HUGE, pte_t)
DEFINE_EMPTY_READ_OP_HELPER(LEVEL_P4D, PTE_ATTR_TRANS_HUGE, p4d_t)
DEFINE_EMPTY_READ_OP_HELPER(LEVEL_PGD, PTE_ATTR_TRANS_HUGE, pgd_t)

DEFINE_GEN_PTE_READ_OP_WRAPPER(PTE_ATTR_TRANS_HUGE)
DEFINE_GEN_PTE_READ_OP_WRAPPER(PTE_ATTR_BAD)

int pmd_next_level_not_accessible_gen(pmd_t *pmd, struct mm_struct *mm,
				      unsigned long addr,
				      int is_partial_built_hint, int check_trans_huge)
{
	pmd_t pmd_val = READ_ONCE(*pmd);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (check_trans_huge) {
		barrier();
	}
#endif
	if (gen_pte_void((gen_pte_t) {.pmd = pmd_val}, PG_LEVEL_PMD, mm, addr, is_partial_built_hint))
		return 1;
	
	if (check_trans_huge && pmd_trans_huge(pmd_val))
			return 1;
	
	if (unlikely(pmd_bad(pmd_val))) {
			/* TODO fix pte write after this */
			// pmd_clear_bad(pmd);
			WARN(1, "bad page table entry\n");
			return 1;
	}
	return 0;

}

inline int next_level_not_accessible(gen_pte_t *gen_pte, pgtable_level level,
				     struct mm_struct *mm, unsigned long addr,
				     int is_partial_built_hint,
				     int check_trans_huge)
{
	gen_pte_t gen_pte_val = READ_ONCE(*gen_pte);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (check_trans_huge) {
		barrier();
	}
#endif

	if (gen_pte_void(gen_pte_val, level, mm, addr, is_partial_built_hint))
			return 1;

	if (check_trans_huge && (gen_pte_trans_huge_wrapper(gen_pte_val, level)))
			return 1;

	if (unlikely(gen_pte_bad_wrapper(gen_pte_val, level))) {
			/* TODO fix pte write after this */
			// pud_clear_bad(pud);
			WARN(1, "bad page table entry\n");
			return 1;
	}

	return 0;
}

#ifndef __HAVE_ARCH_PTE_LOCKPTR_WITH_ADDR

#if USE_SPLIT_PTE_PTLOCKS
spinlock_t *pte_lockptr_with_addr(struct mm_struct *mm, pmd_t *pmd, unsigned long addr)
{
	return ptlock_ptr(pmd_page(*pmd));
}
#else
spinlock_t *pte_lockptr_with_addr(struct mm_struct *mm, pmd_t *pmd, unsigned long addr)
{
	return &mm->page_table_lock;
}
#endif	/* USE_SPLIT_PTE_PTLOCKS */

#endif	/* __HAVE_ARCH_PTE_LOCKPTR_WITH_ADDR */

#ifndef __HAVE_ARCH_P4D_CLEAR_HUGE_WITH_ADDR
int p4d_clear_huge_with_addr(p4d_t *p4d, unsigned long addr) 
{
	return p4d_clear_huge(p4d);
}
#endif	/* __HAVE_ARCH_P4D_CLEAR_HUGE_WITH_ADDR */

#ifndef __HAVE_ARCH_PUD_CLEAR_HUGE_WITH_ADDR
int pud_clear_huge_with_addr(pud_t *pud, unsigned long addr) 
{
	return pud_clear_huge(pud);
}
#endif	/* __HAVE_ARCH_PUD_CLEAR_HUGE_WITH_ADDR */

#ifndef __HAVE_ARCH_PMD_CLEAR_HUGE_WITH_ADDR
int pmd_clear_huge_with_addr(pmd_t *pmd, unsigned long addr) 
{
	return pmd_clear_huge(pmd);
}
#endif	/* __HAVE_ARCH_PMD_CLEAR_HUGE_WITH_ADDR */

#ifndef CONFIG_X86_64_ECPT
SYSCALL_DEFINE0(show_pgtable) 
{
	// ref: chatGPT
	struct task_struct *task = current; 
	struct mm_struct *mm = task->mm; 
	if(!mm)
		return -EINVAL; 

	// output the info 
	pr_info("Page table size (B): %lld", (int64_t)atomic_long_read(&mm->pgtables_bytes)); 

    return 0;
}
#endif


#ifndef __HAVE_ARCH_READ_TENTRY
/**
	 * read_tentry - read the page table entry at the given address
	 * @mm: the memory descriptor of the process
	 * @addr: the virtual address of the page table entry
	 * @pg_size: the page table level of the entry

	 return NULL if not mapped.

	TODO: how can we optimize with generalization?
	if ret value 0, then mapped. pg_size is the level of the page table entry, and tentry stored the all the page table entries queried. 
	if ret value -1, then not mapped, t_entry stored the last queried page table entry. 
	For example, if we query the page table entries for three times, and found mapping not exist,
	then the tentry[PG_LEVEL_PGD, PG_LEVEL_P4D, PG_LEVEL_PUD] stored the last queried page table entries.
 */


// gen_pte_t * read_tentry(struct mm_struct *mm, uint64_t addr, pgtable_level * pg_size)
int read_tentry(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level * pg_size)
{
	pgd_t *pgd = NULL;
	p4d_t *p4d = NULL;
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;


	if (tentry->ptep[PG_LEVEL_PTE] != NULL) {
		pte = GENPTEP_TO_PTEP(tentry->ptep[PG_LEVEL_PTE]);
		goto pte_ready;
	} else if (tentry->ptep[PG_LEVEL_PMD] != NULL) {
		pmd = GENPTEP_TO_PMDP(tentry->ptep[PG_LEVEL_PMD]);
		goto pmd_ready;
	} else if (tentry->ptep[PG_LEVEL_PUD] != NULL) {
		pud = GENPTEP_TO_PUDP(tentry->ptep[PG_LEVEL_PUD]);
		goto pud_ready;
	}

	pgd = pgd_offset_map_with_mm(mm, addr);
	
	tentry->ptep[PG_LEVEL_PGD] = PGDP_TO_GENPTEP(pgd);
	*pg_size = PG_LEVEL_PGD;

	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		return E_PAGE_NOT_MAPPED;
	}

	if (unlikely(pgd_large(*pgd))) {
		return 0;
	}

	p4d = p4d_offset_map_with_mm(mm, pgd, addr);

	tentry->ptep[PG_LEVEL_P4D] = P4DP_TO_GENPTEP(p4d);
	*pg_size = PG_LEVEL_P4D;

	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d))) {
		return E_PAGE_NOT_MAPPED;
	}

	if (unlikely(p4d_large(*p4d))) {
		return 0;
	}
	
	pud = pud_offset_map_with_mm(mm, p4d, addr);

	tentry->ptep[PG_LEVEL_PUD] = PUDP_TO_GENPTEP(pud);

pud_ready:
	*pg_size = PG_LEVEL_PUD;

	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		return E_PAGE_NOT_MAPPED;
	}

	if (unlikely(pud_trans_huge(*pud))) {
		return 0;
	}

	pmd = pmd_offset_map_with_mm(mm, pud, addr);

	tentry->ptep[PG_LEVEL_PMD] = PMDP_TO_GENPTEP(pmd);

pmd_ready:
	*pg_size = PG_LEVEL_PMD;
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		return E_PAGE_NOT_MAPPED;
	}

	if (pmd_trans_huge(*pmd)) {
		return 0;
	}

	pte = pte_offset_map_with_mm(mm, pmd, addr);

	tentry->ptep[PG_LEVEL_PTE] = PTEP_TO_GENPTEP(pte);

pte_ready:
	*pg_size = PG_LEVEL_PTE;

	if (pte_none(*pte)) {
		return E_PAGE_NOT_MAPPED;
	}
	
	return 0;

}
#endif



static int __p4d_alloc_nolock(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	p4d_t * new;
	if (!pgtable_l5_enabled()) {
		return 0;
	}

	new = p4d_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	// spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd)){ /* Another has populated it */
		p4d_free(mm, new);
	} else {
// #ifdef CONFIG_PGTABLE_OP_GENERALIZABLE		
// 		pgd_mk_p4d_accessible(mm, pgd, address, new);
// #else	
		pgd_populate(mm, pgd, new);
// #endif	
	}
	// spin_unlock(&mm->page_table_lock);
	return 0;
}

static int __pud_alloc_nolock(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	// spin_lock(&mm->page_table_lock);
	if (!p4d_present(*p4d)) {
		mm_inc_nr_puds(mm);
// #ifdef CONFIG_PGTABLE_OP_GENERALIZABLE		
// 		p4d_mk_pud_accessible(mm, p4d, address, new);
// #else	
		p4d_populate(mm, p4d, new);
// #endif
	} else	/* Another has populated it */
		pud_free(mm, new);
	// spin_unlock(&mm->page_table_lock);
	return 0;
}

/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
static int __pmd_alloc_nolock(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	// spinlock_t *ptl;
	pmd_t *new = pmd_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	// ptl = pud_lock(mm, pud);
	if (!pud_present(*pud)) {
		mm_inc_nr_pmds(mm);
// #ifdef CONFIG_PGTABLE_OP_GENERALIZABLE		
// 		pud_mk_pmd_accessible(mm, pud, address, new);
// #else	
		pud_populate(mm, pud, new);
// #endif
	} else	/* Another has populated it */
		pmd_free(mm, new);
	// spin_unlock(ptl);
	return 0;
}

static int __pte_alloc_nolock(struct mm_struct *mm, pmd_t *pmd, unsigned long addr)
{
	// spinlock_t *ptl;
	pgtable_t new = pte_alloc_one(mm);
	gen_pte_t gen_pte;
	if (!new)
		return -ENOMEM;

	/*
	 * Ensure all pte setup (eg. pte page lock and page clearing) are
	 * visible before the pte is made visible to other CPUs by being
	 * put into page tables.
	 *
	 * The other side of the story is the pointer chasing in the page
	 * table walking code (when walking the page table without locking;
	 * ie. most of the time). Fortunately, these data accesses consist
	 * of a chain of data-dependent loads, meaning most CPUs (alpha
	 * being the notable exception) will already guarantee loads are
	 * seen in-order. See the alpha page table accessors for the
	 * smp_rmb() barriers in page table walking code.
	 */
	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */

	// ptl = pmd_lock(mm, pmd);
	gen_pte.pmd = *pmd;
	if (likely(gen_pte_void(gen_pte, PG_LEVEL_PMD, mm, addr, 0))) {	/* Has another populated it ? */
		mm_inc_nr_ptes(mm);
		/* original code */
		pmd_mk_pte_accessible(mm, pmd, addr, new);
		// pmd_populate(mm, pmd, new);
		new = NULL;
	}
	// spin_unlock(ptl);
	if (new)
		pte_free(mm, new);
	return 0;
}

static inline p4d_t *p4d_alloc_nolock(struct mm_struct *mm, pgd_t *pgd,
		unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && __p4d_alloc_nolock(mm, pgd, address)) ?
		NULL : p4d_offset(pgd, address);
}

static inline pud_t *pud_alloc_nolock(struct mm_struct *mm, p4d_t *p4d,
		unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) && __pud_alloc_nolock(mm, p4d, address)) ?
		NULL : pud_offset(p4d, address);
}

static inline pmd_t *pmd_alloc_nolock(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __pmd_alloc_nolock(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}


static inline pte_t *pte_alloc_nolock(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	return (unlikely(pmd_none(*pmd)) && __pte_alloc_nolock(mm, pmd, address))?
		NULL: pte_offset_map(pmd, address);
}

#ifndef __HAVE_ARCH_INSERT_TENTRY
int insert_tentry(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level pg_size, gen_pte_t gen_pte)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pr_info_verbose("Inserting page table entry at addr=%llx, pg_size=%d gen_pte=%lx\n", 
		addr, pg_size, gen_pte.pte.pte);

	if (pg_size >= PG_LEVEL_P4D) {
		WARN(1, "Invalid page table level pg_size=%d\n", pg_size);
		return -1;
	}

	pgd = GENPTEP_TO_PGDP(tentry->ptep[PG_LEVEL_PGD]);
	if (pgd == NULL) {
		pgd = pgd_offset_map_with_mm(mm, addr);
		tentry->ptep[PG_LEVEL_PGD] = PGDP_TO_GENPTEP(pgd);
	}

	p4d = GENPTEP_TO_P4DP(tentry->ptep[PG_LEVEL_P4D]);
	if (p4d == NULL) {
		p4d = p4d_alloc_nolock(mm, pgd, addr);
		if (!p4d)
			return -ENOMEM;
		tentry->ptep[PG_LEVEL_P4D] = P4DP_TO_GENPTEP(p4d);
	}

	pud = GENPTEP_TO_PUDP(tentry->ptep[PG_LEVEL_PUD]);
	if (pud == NULL) {
		pud = pud_alloc_nolock(mm, p4d, addr);
		if (!pud)
			return -ENOMEM;
		tentry->ptep[PG_LEVEL_PUD] = PUDP_TO_GENPTEP(pud);
	}

	if (pg_size == PG_LEVEL_PUD) {
		set_pud_at(mm, addr, pud, gen_pte.pud);
		pr_info_verbose("set_pud_at addr=%llx, pmd=%lx\n", addr, pud->pud);
		return 0;
	}
	
	pmd = GENPTEP_TO_PMDP(tentry->ptep[PG_LEVEL_PMD]);
	if (pmd == NULL) {
		pmd = pmd_alloc_nolock(mm, pud, addr);
		if (!pmd)
			return -ENOMEM;
		tentry->ptep[PG_LEVEL_PMD] = PMDP_TO_GENPTEP(pmd);
	}

	if (pg_size == PG_LEVEL_PMD) {
		set_pmd_at(mm, addr, pmd, gen_pte.pmd);
		pr_info_verbose("set_pmd_at addr=%llx, pmd=%lx\n", addr, pmd->pmd);
		return 0;
	}

	pte = GENPTEP_TO_PTEP(tentry->ptep[PG_LEVEL_PTE]);
	if (pte == NULL) {
		pte = pte_alloc_nolock(mm, pmd, addr);
		if (!pte)
			return -ENOMEM;
		tentry->ptep[PG_LEVEL_PTE] = PTEP_TO_GENPTEP(pte);
	}
	
	if (pg_size == PG_LEVEL_PTE) {
		set_pte_at(mm, addr, pte, gen_pte.pte);
		pr_info_verbose("set_pte_at addr=%llx, pte=%lx\n", addr, pte->pte);
	}

	return 0;
}

#endif /* __HAVE_ARCH_INSERT_TENTRY */
/**
 * preallocate upper levels until pg_size (inclusive).
 * This function is not supposed to set date page.
 * If this function returns successfully, tentry[lv] for all lv >= pg_size are valid. 
 */
static int preallocate_upper_levels(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level pg_size)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pr_info_verbose("preallocate_upper_levels page table entry at addr=%llx, pg_size=%d\n", 
		addr, pg_size);

	if (pg_size >= PG_LEVEL_P4D) {
		WARN(1, "Invalid page table level pg_size=%d\n", pg_size);
		return -1;
	}

	pgd = GENPTEP_TO_PGDP(tentry->ptep[PG_LEVEL_PGD]);
	if (pgd == NULL) {
		pgd = pgd_offset_map_with_mm(mm, addr);
		tentry->ptep[PG_LEVEL_PGD] = PGDP_TO_GENPTEP(pgd);
	}

	p4d = GENPTEP_TO_P4DP(tentry->ptep[PG_LEVEL_P4D]);
	if (p4d == NULL) {
		p4d = p4d_alloc_nolock(mm, pgd, addr);
		if (!p4d)
			return -ENOMEM;
		tentry->ptep[PG_LEVEL_P4D] = P4DP_TO_GENPTEP(p4d);
	}

	pud = GENPTEP_TO_PUDP(tentry->ptep[PG_LEVEL_PUD]);
	if (pud == NULL) {
		pud = pud_alloc_nolock(mm, p4d, addr);
		if (!pud)
			return -ENOMEM;
		tentry->ptep[PG_LEVEL_PUD] = PUDP_TO_GENPTEP(pud);
	}

	if (pg_size == PG_LEVEL_PUD) {
		return 0;
	}
	
	pmd = GENPTEP_TO_PMDP(tentry->ptep[PG_LEVEL_PMD]);
	if (pmd == NULL) {
		pmd = pmd_alloc_nolock(mm, pud, addr);
		if (!pmd)
			return -ENOMEM;
		tentry->ptep[PG_LEVEL_PMD] = PMDP_TO_GENPTEP(pmd);
	}

	if (pg_size == PG_LEVEL_PMD) {
		return 0;
	}

	pte = GENPTEP_TO_PTEP(tentry->ptep[PG_LEVEL_PTE]);
	if (pte == NULL) {
		pte = pte_alloc_nolock(mm, pmd, addr);
		if (!pte)
			return -ENOMEM;
		tentry->ptep[PG_LEVEL_PTE] = PTEP_TO_GENPTEP(pte);
	}
	
	if (pg_size == PG_LEVEL_PTE) {
		return 0;
	}

	WARN(1,"Shouldn't hit here. pg_size=%d\n", pg_size);
	return 0;
}



int update_tentry(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level pg_size, gen_pte_t gen_pte, int dirty)
{
	int changed;
	pte_t * ptep;
	pmd_t * pmdp;
	pud_t * pudp;
	pr_tentry_verbose(tentry);
	switch (pg_size) {
		case PG_LEVEL_PTE:
			ptep = GENPTEP_TO_PTEP(tentry->ptep[pg_size]);
			changed = !pte_same(*ptep, gen_pte.pte);


			if (changed) {
				pr_info_verbose("update_tentry: update_tentry addr=%llx, ptep at %llx pte=%lx\n",
					addr, (uint64_t) ptep, gen_pte.pte.pte);
				set_pte(ptep, gen_pte.pte);
			}
			// set_pte_at(mm, addr, GENPTEP_TO_PTEP(tentry->ptep[PG_LEVEL_PTE]), gen_pte.pte);
			break;
		case PG_LEVEL_PMD:
			pmdp = GENPTEP_TO_PMDP(tentry->ptep[pg_size]);
			changed = !pmd_same(*pmdp, gen_pte.pmd);
			// set_pmd_at(mm, addr, GENPTEP_TO_PMDP(tentry->ptep[PG_LEVEL_PMD]), gen_pte.pmd);
			break;
		
		case PG_LEVEL_PUD:
			pudp = GENPTEP_TO_PUDP(tentry->ptep[pg_size]);
			changed = !pud_same(*pudp, gen_pte.pud);
			// set_pud_at(mm, addr, GENPTEP_TO_PUDP(tentry->ptep[PG_LEVEL_PUD]), gen_pte.pud);
			break;
		
		case PG_LEVEL_P4D:
		case PG_LEVEL_PGD:
			pr_info("WARN: update_tentry not support for pg_size=%d\n", pg_size);
			changed = 0;
			break;
	}

	return changed;
}

int aspace_trans_unstable(struct mm_struct *mm, tentry_t * tentry, unsigned long addr, pgtable_level pg_size)
{
	pmd_t * pmd = GENPTEP_TO_PMDP(tentry->ptep[PG_LEVEL_PMD]);
	pmd_t pmdval;

	if (pmd == NULL) {
		return 0;
	}
	
	pmdval = pmd_read_atomic(pmd);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	barrier();
#endif
	pr_info_verbose("pmd=%llx pmdval=%lx\n", (uint64_t) pmd, pmdval.pmd);
	if ( pmd_trans_huge(pmdval) ||
	    (!pmd_none(pmdval) && ( IS_ENABLED(CONFIG_ARCH_ENABLE_THP_MIGRATION) && !pmd_present(pmdval)))
	)
		return 1;

	return 0;
}


spinlock_t * aspace_lockptr(struct mm_struct *mm, tentry_t * tentry, unsigned long addr, pgtable_level pg_size)
{	
	pmd_t * pmd;
	if (pg_size >= PG_LEVEL_PUD) {
		return &mm->page_table_lock;
	}

	pmd = GENPTEP_TO_PMDP(tentry->ptep[PG_LEVEL_PMD]);
	if (pmd == NULL) {
		return &mm->page_table_lock;
	}

	if(pg_size == PG_LEVEL_PTE) {
		return pte_lockptr_with_addr(mm, pmd, addr);
	} else if (pg_size == PG_LEVEL_PMD) {
		return pmd_lockptr(mm, pmd);
	}

	BUG();
	return NULL;
}

static inline uint64_t pgtable_level_to_size(pgtable_level pg_size)
{
	if (pg_size == PG_LEVEL_PGD) {
		pg_size -= 1;
	}
	return (1ULL << ((pg_size * 9) + 12));
}




int tentry_iter_init(struct mm_struct *mm, uint64_t start, uint64_t end, tentry_iter_t * iter)
{
	iter->mm = mm;

	iter->start = start;
	iter->end = end;

	iter->addr = start;

	memset((void *) &iter->tentry, 0, sizeof(tentry_t));
	// iter->tentry = {0};
	iter->maperr = read_tentry(mm, iter->addr, &iter->tentry, &iter->pg_level);

	return 0;
}

int tentry_iter_has_next(tentry_iter_t * iter) 
{
	int res = 0;
	res = tentry_iter_has_next_step(iter, pgtable_level_to_size(iter->pg_level));
	pr_info_verbose("addr=%llx, end=%llx step_size=%llx res=%d\n", 
		iter->addr, iter->end, pgtable_level_to_size(iter->pg_level), res);
	return res;
}


/**
 * consider the case when iter->addr = 1G + 1M + 4K * 511, and step_size = 4K
 * then the next address should be 1G + 1M + 4K * 512 = 1G + 2M.
 * In this case, iter->tentry.ptep[PG_LEVEL_PTE] -> NULL, iter->tentry.ptep[PG_LEVEL_PMD] increment by one.
 * and then read the next pte entry.
 */ 
static inline int __tentry_iter_next(tentry_iter_t * iter, pgtable_level pg_lv, int n_step)
{
	/* n_step < 512 */
	uint64_t boundary = 0;
	uint64_t next = iter->addr + pgtable_level_to_size(pg_lv) * n_step;
	gen_pte_t * gen_ptep = NULL;
	pte_t * ptep = NULL;
	
	pr_tentry_verbose(&iter->tentry);
	pr_info_verbose("addr=%llx, pg_lv=%d, n_step=%d\n", iter->addr, pg_lv, n_step);


	if (next >= iter->end) {
		return -1;
	}

	for (; pg_lv <= PG_LEVEL_PGD; pg_lv++) {

		boundary = get_boundary(iter->addr, pgtable_level_to_size(pg_lv + 1));
		if (next < boundary) {
			iter->addr = next;
			gen_ptep = iter->tentry.ptep[pg_lv];
			if (gen_ptep != NULL) {
				iter->tentry.ptep[pg_lv] = gen_ptep + n_step;
			}

			if (pg_lv == PG_LEVEL_PTE) {
				ptep = GENPTEP_TO_PTEP(iter->tentry.ptep[pg_lv]);
				if (ptep != NULL && !pte_none(*ptep)) {
					pr_info_verbose("ptep at %llx= %lx\n", (uint64_t) ptep, ptep->pte);
					iter->maperr = 0;
				} else {
					if (ptep == NULL) {
						iter->maperr = read_tentry(iter->mm, iter->addr, &iter->tentry, &iter->pg_level);
					} else {
						/* pte_none */
						iter->maperr = E_PAGE_NOT_MAPPED;
					}
				}
				return 0;
			} else {
				iter->maperr =  read_tentry(iter->mm, iter->addr, &iter->tentry, &iter->pg_level);
				return 0;
			}

		} else {
			iter->tentry.ptep[pg_lv] = NULL;
		}
	}

	return 0;
};


// int tentry_iter_next(tentry_iter_t * iter, pgtable_level pg_lv)
// {
// 	return __tentry_iter_next(iter, pg_lv, 1);
// }

// int tentry_iter_prev(tentry_iter * iter);`

#ifndef __ARCH_HAS_TENTRY_ITER_N_NEXT

int tentry_iter_n_next(tentry_iter_t * iter, pgtable_level pg_lv, int n_step)	
{
	// uint64_t pg_size = pgtable_level_to_size(iter->pg_level);
	return __tentry_iter_next(iter, pg_lv, n_step);
}

#endif

int thp_eligible(struct vm_area_struct *vma, tentry_t *tentry, unsigned long addr, pgtable_level pg_size)
{	
	pmd_t * pmd = GENPTEP_TO_PMDP(tentry->ptep[PG_LEVEL_PMD]);
	if (pg_size != PG_LEVEL_PMD) {
		return 0;
	}
	pr_tentry_verbose(tentry);
	pr_info_verbose("addr=%lx pg_sze=%d enabled=%d\n",
		addr, pg_size, __transparent_hugepage_enabled(vma));
	return (pmd == NULL || pmd_none(*pmd)) && __transparent_hugepage_enabled(vma);
}

void pgtable_trans_huge_deposit_enhanced(struct mm_struct *mm, 
	tentry_t * tentry, 
	pgtable_level pg_level, 
	unsigned long addr, 
	pgtable_t pgtable)
{	
	pmd_t * pmdp = GENPTEP_TO_PMDP(tentry->ptep[pg_level]);
	int alloc_res = 0;
	WARN(pg_level != PG_LEVEL_PMD, "pg_level=%d\n", pg_level);

	// assert_spin_locked(pmd_lockptr(mm, pmdp));
	assert_spin_locked(aspace_lockptr(mm, tentry, addr, pg_level));

	if (pmdp == NULL) {
		alloc_res = preallocate_upper_levels(mm, addr, tentry, PG_LEVEL_PMD);
		if (alloc_res) {
			BUG();
		}
		
		pmdp = GENPTEP_TO_PMDP(tentry->ptep[PG_LEVEL_PMD]);
		pr_info_verbose("preallocate_upper_levels done\n");
		pr_tentry_verbose(tentry);
	}


	/* FIFO */
	if (!pmd_huge_pte(mm, pmdp))
		INIT_LIST_HEAD(&pgtable->lru);
	else
		list_add(&pgtable->lru, &pmd_huge_pte(mm, pmdp)->lru);
	pmd_huge_pte(mm, pmdp) = pgtable;
}

pgtable_t pgtable_trans_huge_withdraw_enhanced(struct mm_struct *mm, 
	tentry_t * tentry, 
	pgtable_level pg_level, 
	unsigned long addr)
{
	pgtable_t pgtable;
	
	pmd_t * pmdp = GENPTEP_TO_PMDP(tentry->ptep[pg_level]);

	WARN(pg_level != PG_LEVEL_PMD, "pg_level=%d\n", pg_level);
	assert_spin_locked(aspace_lockptr(mm, tentry, addr, pg_level));

	/* FIFO */
	pgtable = pmd_huge_pte(mm, pmdp);
	pmd_huge_pte(mm, pmdp) = list_first_entry_or_null(&pgtable->lru,
							  struct page, lru);
	if (pmd_huge_pte(mm, pmdp))
		list_del(&pgtable->lru);
	return pgtable;
}

gen_pte_t clear_tentry(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level pg_size)
{
	pte_t pte;
	pmd_t pmd;
	pud_t pud;
	gen_pte_t gen_pte = {};

	pr_info_verbose("addr=%llx, pg_size=%d\n", addr, pg_size);
	pr_tentry_verbose(tentry);
	switch(pg_size) {
		case PG_LEVEL_PTE:
			pte = native_ptep_get_and_clear(GENPTEP_TO_PTEP(tentry->ptep[pg_size]));		
			gen_pte = (gen_pte_t) {.pte = pte};
			return gen_pte;
		case PG_LEVEL_PMD:
			pmd = native_pmdp_get_and_clear(GENPTEP_TO_PMDP(tentry->ptep[pg_size]));
			gen_pte = (gen_pte_t) {.pmd = pmd};
			return gen_pte;
		case PG_LEVEL_PUD:
			pud = native_pudp_get_and_clear(GENPTEP_TO_PUDP(tentry->ptep[pg_size]));
			gen_pte = (gen_pte_t) {.pud = pud};
			return gen_pte;
		default:
			WARN(1, "Invalid page table level pg_size=%d\n", pg_size);
			return gen_pte;
	}
	return gen_pte;
}


pte_t tentry_ptep_clear_flush(struct vm_area_struct *vma, unsigned long address, tentry_t * tentry)
{
	struct mm_struct *mm = (vma)->vm_mm;
	pte_t pte;

	pte = clear_tentry(mm, address, tentry, PG_LEVEL_PTE).pte;
	if (pte_accessible(mm, pte))
		flush_tlb_page(vma, address);
	return pte;
}
