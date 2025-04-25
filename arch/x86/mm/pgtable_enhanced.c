#include "asm-generic/rwonce.h"
#include "asm/processor.h"
#include "linux/pgtable.h"
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