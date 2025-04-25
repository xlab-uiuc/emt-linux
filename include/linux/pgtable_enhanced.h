#ifndef _LINUX_PGTABLE_ENHANCED_H
#define _LINUX_PGTABLE_ENHANCED_H


#include "linux/types.h"
#ifndef __ASSEMBLY__
#include <linux/spinlock_types.h>
// #include <linux/pgtable.h>
// #include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <linux/mm_types.h>


#ifdef CONFIG_X86_64_ECPT
#include <asm/ECPT_interface.h>
#endif

#ifdef CONFIG_X86_64_FPT
#include <asm/fpt_defs.h>
#endif

typedef enum {
	PG_LEVEL_PTE = 0,
	PG_LEVEL_PMD = 1,
	PG_LEVEL_PUD = 2,
	PG_LEVEL_P4D = 3,
	PG_LEVEL_PGD = 4,
} pgtable_level;

#ifndef __HAVE_ARCH_MAX_PAGE_LEVEL
#define MAX_PAGE_LEVEL PG_LEVEL_PGD
#endif

#ifndef __HAVE_ARCH_MIN_PAGE_LEVEL
#define BASE_PAGE_SIZE PG_LEVEL_PTE
#endif

typedef union {
	pte_t pte;
	pmd_t pmd;
	pud_t pud;
	p4d_t p4d;
	pgd_t pgd;
} gen_pte_t;

typedef struct {
	gen_pte_t * ptep[PG_LEVEL_PGD + 1];
} tentry_t;

#define pr_tentry_verbose(tentry) \
	pr_info_verbose("tentry: pgd= at %llx = %llx, p4d= at %llx = %llx, pud= at %llx = %llx, pmd= at %llx = %llx, pte= at %llx = %llx\n", \
			(uint64_t) (tentry)->ptep[PG_LEVEL_PGD], (tentry)->ptep[PG_LEVEL_PGD] != NULL ? (uint64_t) (tentry)->ptep[PG_LEVEL_PGD]->pgd.pgd : 0, \
			(uint64_t) (tentry)->ptep[PG_LEVEL_P4D], (tentry)->ptep[PG_LEVEL_P4D] != NULL ? (uint64_t) (tentry)->ptep[PG_LEVEL_P4D]->p4d.p4d : 0, \
			(uint64_t) (tentry)->ptep[PG_LEVEL_PUD], (tentry)->ptep[PG_LEVEL_PUD] != NULL ? (uint64_t) (tentry)->ptep[PG_LEVEL_PUD]->pud.pud : 0, \
			(uint64_t) (tentry)->ptep[PG_LEVEL_PMD], (tentry)->ptep[PG_LEVEL_PMD] != NULL ? (uint64_t) (tentry)->ptep[PG_LEVEL_PMD]->pmd.pmd : 0, \
			(uint64_t) (tentry)->ptep[PG_LEVEL_PTE], (tentry)->ptep[PG_LEVEL_PTE] != NULL ? (uint64_t) (tentry)->ptep[PG_LEVEL_PTE]->pte.pte : 0)



#define E_PAGE_NOT_MAPPED -1

#define PTEP_TO_GENPTEP(ptep) ((gen_pte_t *)ptep)
#define PMDP_TO_GENPTEP(pmdp) ((gen_pte_t *)pmdp)
#define PUDP_TO_GENPTEP(pudp) ((gen_pte_t *)pudp)
#define P4DP_TO_GENPTEP(p4dp) ((gen_pte_t *)p4dp)
#define PGDP_TO_GENPTEP(pgdp) ((gen_pte_t *)pgdp)

#define GENPTEP_TO_PTEP(gen_ptep) ((pte_t *)gen_ptep)
#define GENPTEP_TO_PMDP(gen_ptep) ((pmd_t *)gen_ptep)
#define GENPTEP_TO_PUDP(gen_ptep) ((pud_t *)gen_ptep)
#define GENPTEP_TO_P4DP(gen_ptep) ((p4d_t *)gen_ptep)
#define GENPTEP_TO_PGDP(gen_ptep) ((pgd_t *)gen_ptep)


typedef enum {
	PTE_DIRTY,
	PTE_YOUNG,
	PTE_WRITE,
	PTE_HUGE,
	PTE_TRANS_HUGE,
	PTE_LARGE,
	PTE_PRESENT,
	PTE_GLOBAL,
	PTE_EXEC,
	PTE_SPECIAL,
	PTE_SAME, /* TODO: this takes two PTEs a simple interface is not going to work */
	PTE_PROTNONE,
	PTE_UFFD_WP,
	PTE_SWP_UFFD_WP,
	PTE_SOFT_DIRTY,
	PTE_SWP_SOFT_DIRTY,
	PTE_ACCESSILBE,
	PTE_ACCESS_PERMITTED,
	PTE_PFN,
	PTE_BAD,
} pte_attr_t;

typedef enum {
	PTE_MK, 
	PTE_CLEAR
} pte_action_t;

/* redefine this set of macro to  */
#define PTE_ATTR_DIRTY dirty
#define PTE_ATTR_YOUNG young
#define PTE_ATTR_WRITE write
#define PTE_ATTR_HUGE huge
#define PTE_ATTR_TRANS_HUGE trans_huge
#define PTE_ATTR_LARGE large
#define PTE_ATTR_LEAF leaf
#define PTE_ATTR_PRESENT present
#define PTE_ATTR_GLOBAL global
#define PTE_ATTR_EXEC exec
#define PTE_ATTR_SPECIAL special
#define PTE_ATTR_SAME same
#define PTE_ATTR_PROTNONE protnone
#define PTE_ATTR_LARGE large
#define PTE_ATTR_UFFD_WP uffd_wp
#define PTE_ATTR_SWP_UFFD_WP swp_uffd_wp
#define PTE_ATTR_SOFT_DIRTY soft_dirty
#define PTE_ATTR_SWP_SOFT_DIRTY swp_soft_dirty
#define PTE_ATTR_ACCESSIBLE accessible
#define PTE_ATTR_ACCESS_PERMITTED access_permitted
#define PTE_ATTR_PFN pfn
#define PTE_ATTR_BAD bad
#define PTE_ATTR_DEVMAP devmap
#define PTE_ATTR_PAGE_VADDR page_vaddr
#define PTE_ATTR_PGTABLE pgtable
#define PTE_ATTR_PGPROT pgprot
#define PTE_ATTR_INVALID invalid
#define PTE_ATTR_MODIFY modify
#define PTE_ATTR_FROM_PFN_PROT from_pfn_prot
#define PTE_ATTR_PGPROT_MODIFY pgprot_modify


#define LEVEL_PTE pte
#define LEVEL_PMD pmd
#define LEVEL_PUD pud
#define LEVEL_P4D p4d
#define LEVEL_PGD pgd

#define ACTION_MK mk
#define ACTION_CLEAR clear

// gen_pte_read(pte, LEVEL_PTE, PTE_ATTR_PRESENT) -> native_pte_present(pte)
/* the redundancy matters here for double macro expansion */
/* ## in front of __VA_ARGS__ can help omit the comma */
/* and variadic arguments to support multiple pte inputs */
/* gen_pte_read(pte1, LEVEL_PTE, PTE_ATTR_SAME, pte2) -> native_pte_same(pte1, pte2)  */
#define __gen_pte_read(pte, lvl, type, ...) native_##lvl##_##type(pte, ##__VA_ARGS__)
#define gen_pte_read(pte, lvl, type, ...) __gen_pte_read(pte, lvl, type, ##__VA_ARGS__)

#define __gen_pte_update(pte, lvl, action, type, ...)                          \
	native_##lvl##_##action##_##type(pte, ##__VA_ARGS__)
#define gen_pte_update(pte, lvl, action, type, ...)                            \
	__gen_pte_update(pte, lvl, action, type, ##__VA_ARGS__)

#ifndef	 __ARCH_HAS_PTEP_GET_NEXT
inline pte_t * ptep_get_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PTEP_GET_PREV
inline pte_t * ptep_get_prev(struct mm_struct *mm, pte_t * ptep, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PTEP_GET_N_NEXT
inline pte_t * ptep_get_n_next(struct mm_struct *mm, pte_t * ptep, unsigned long addr, unsigned int n);
#endif

#ifndef	 __ARCH_HAS_PMDP_GET_NEXT
inline pmd_t * pmdp_get_next(struct mm_struct *mm, pmd_t *pmdp, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PUDP_GET_NEXT
inline pud_t * pudp_get_next(struct mm_struct *mm, pud_t *pudp, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_P4DP_GET_NEXT
inline p4d_t * p4dp_get_next(struct mm_struct *mm, p4d_t *p4dp, unsigned long addr);
#endif

#ifndef	 __ARCH_HAS_PGDP_GET_NEXT
inline pgd_t * pgdp_get_next(struct mm_struct *mm, pgd_t *pgdp, unsigned long addr);
#endif

inline int gen_pte_is_data_page(gen_pte_t gen_pte, pgtable_level level);

inline int gen_pte_is_directory(gen_pte_t gen_pte, pgtable_level level);

inline int gen_pte_is_partially_built(gen_pte_t gen_pte, pgtable_level level,
				      struct mm_struct *mm, unsigned long addr);

/* The is_partial_built_hint is an optimization which enables the user of this API 
 * to skip the partial check. To garantee the correctness of the result, the
 * we assume the page table contains lower page table entries is_partial_built_hint = 1.
 * (Don't go aheand to build huge page).
 */
inline int gen_pte_void(gen_pte_t gen_pte, pgtable_level level,
			struct mm_struct *mm, unsigned long addr, int is_partial_built_hint);


#ifndef __HAVE_ARCH_NO_P4D_PGTABLE
inline int no_p4d_and_lower_pgtable(pgd_t pgd);
#endif

#ifndef __HAVE_ARCH_NO_PUD_PGTABLE
inline int no_pud_and_lower_pgtable(p4d_t p4d);
#endif

#ifndef __HAVE_ARCH_NO_PMD_PGTABLE
inline int no_pmd_and_lower_pgtable(pud_t pud);
#endif

#ifndef __HAVE_ARCH_NO_PTE_PGTABLE
inline int no_pte_pgtable(pmd_t pmd);
#endif

#ifndef __HAVE_ARCH_NO_PGD_HUGE_PAGE
inline int no_pgd_huge_page(pgd_t pgd);
#endif

#ifndef __HAVE_ARCH_NO_P4D_HUGE_PAGE
inline int no_p4d_huge_page(p4d_t p4d);
#endif

#ifndef __HAVE_ARCH_NO_PUD_HUGE_PAGE
inline int no_pud_huge_page(pud_t pud);
#endif

#ifndef __HAVE_ARCH_NO_PMD_HUGE_PAGE
inline int no_pmd_huge_page(pmd_t pmd);
#endif

#ifndef __HAVE_ARCH_NO_PGD_HUGE_AND_P4D_PGTABLE
inline int no_pgd_huge_and_p4d_pgtable(pgd_t pgd);
#endif

#ifndef __HAVE_ARCH_NO_P4D_HUGE_AND_PUD_PGTABLE
inline int no_p4d_huge_and_pud_pgtable(p4d_t p4d);
#endif

#ifndef __HAVE_ARCH_NO_PUD_HUGE_AND_PMD_PGTABLE
inline int no_pud_huge_and_pmd_pgtable(pud_t pud);
#endif

#ifndef __ARCH_HAS_PGD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pgd_next_level_not_accessible(pgd_t *pgd);
#endif

#ifndef __ARCH_HAS_P4D_NEXT_LEVEL_NOT_ACCESSIBLE
inline int p4d_next_level_not_accessible(p4d_t *p4d);
#endif

#ifndef __ARCH_HAS_PUD_NEXT_LEVEL_NOT_ACCESSIBLE
inline int pud_next_level_not_accessible(pud_t *pud);
#endif

// #ifndef __ARCH_HAS_PMD_NEXT_LEVEL_NOT_ACCESSIBLE
// inline int pmd_next_level_not_accessible(pmd_t *pmd);
// #endif

/* replacement for pmd_none_or_clear_bad */
#define pmd_next_level_not_accessible_regular(pmdp, mm, addr,                  \
					      is_partial_built_hint)           \
	pmd_next_level_not_accessible_gen(pmdp, mm, addr,                      \
					  is_partial_built_hint, 0)

/* replacement for pmd_none_or_clear_bad */
#define pmd_next_level_not_accessible_trans_huge(pmdp, mm, addr,               \
						 is_partial_built_hint)        \
	pmd_next_level_not_accessible_gen(pmdp, mm, addr,                      \
					  is_partial_built_hint, 1)

inline int next_level_not_accessible(gen_pte_t *gen_pte, pgtable_level level,
				     struct mm_struct *mm, unsigned long addr,
				     int is_partial_built_hint,
				     int check_trans_huge);

int pmd_next_level_not_accessible_gen(pmd_t *pmd, struct mm_struct *mm,
				      unsigned long addr,
				      int is_partial_built_hint, int check_trans_huge);





#ifndef __HAVE_ARCH_MK_P4D_ACCESSSIBLE
inline void pgd_mk_p4d_accessible(struct mm_struct *mm, pgd_t *pgd, unsigned long addr, p4d_t *p4d);
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PUD_ACCESSSIBLE
inline void p4d_mk_pud_accessible(struct mm_struct *mm, p4d_t *p4d, unsigned long addr, pud_t *pud);
#endif /* __HAVE_ARCH_MK_PUD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PMD_ACCESSSIBLE
inline void pud_mk_pmd_accessible(struct mm_struct *mm, pud_t *pud, unsigned long addr, pmd_t *pmd);
#endif /* __HAVE_ARCH_MK_PMD_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE
inline void pmd_mk_pte_accessible(struct mm_struct *mm, pmd_t *pmd, unsigned long addr, struct page *pte);
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE  */

#ifndef __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL
inline void pmd_mk_pte_accessible_kernel(struct mm_struct *mm, pmd_t *pmd, unsigned long addr, pte_t *pte);
#endif /* __HAVE_ARCH_MK_PTE_ACCESSSIBLE_KERNEL  */

// #ifndef	 __ARCH_HAS_PTE_OFFSET_MAP_WITH_MM
inline pte_t *pte_offset_map_with_mm(struct mm_struct *mm, pmd_t *pmd, unsigned long addr);
// #endif

// #ifndef	 __ARCH_HAS_PMD_OFFSET_MAP_WITH_MM
inline pmd_t *pmd_offset_map_with_mm(struct mm_struct *mm, pud_t *pud, unsigned long addr);
// #endif

// #ifndef	 __ARCH_HAS_PUD_OFFSET_MAP_WITH_MM
inline pud_t *pud_offset_map_with_mm(struct mm_struct *mm, p4d_t *p4d, unsigned long addr);
// #endif

// #ifndef	 __ARCH_HAS_P4D_OFFSET_MAP_WITH_MM
inline p4d_t *p4d_offset_map_with_mm(struct mm_struct *mm, pgd_t *pgd, unsigned long addr);
// #endif

// #ifndef	 __ARCH_HAS_PGD_OFFSET_MAP_WITH_MM
inline pgd_t *pgd_offset_map_with_mm(struct mm_struct *mm, unsigned long addr);
// #endif


#ifdef CONFIG_HAVE_ARCH_HUGE_VMAP

int p4d_clear_huge_with_addr(p4d_t *p4d, unsigned long addr);
int pud_clear_huge_with_addr(pud_t *pud, unsigned long addr);
int pmd_clear_huge_with_addr(pmd_t *pmd, unsigned long addr);
#else
static inline int p4d_clear_huge_with_addr(p4d_t *p4d, unsigned long addr)
{
	return 0;
}

static inline int pud_clear_huge_with_addr(p4d_t *p4d, unsigned long addr)
{
	return 0;
}

static inline int pmd_clear_huge_with_addr(p4d_t *p4d, unsigned long addr)
{
	return 0;
}
#endif

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long addr);
int __pte_alloc_kernel(pmd_t *pmd, unsigned long addr);


#ifndef __HAVE_ARCH_CREATE_CONTEXT
static void * create_context(struct mm_struct *mm, uint32_t attr_flags)
{
	return (void *) pgd_alloc(mm);
}
#else

void * create_context(struct mm_struct *mm, uint32_t attr_flags);
#endif


spinlock_t *pte_lockptr_with_addr(struct mm_struct *mm, pmd_t *pmd, unsigned long addr);

int read_tentry(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level * pg_size);

int insert_tentry(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level pg_size, gen_pte_t gen_pte);

int update_tentry(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level pg_size, gen_pte_t gen_pte, int dirty);

gen_pte_t clear_tentry(struct mm_struct *mm, uint64_t addr, tentry_t * tentry, pgtable_level pg_size);

static inline pte_t tentry_get_and_clear_full(struct mm_struct *mm,
	unsigned long addr, tentry_t * tentry,
	int full) 
{
	return clear_tentry(mm, addr, tentry, PG_LEVEL_PTE).pte;
}

static inline void tentry_clear_not_present_full(struct mm_struct *mm,
	unsigned long address,
	tentry_t * tentry,
	int full)
{
	clear_tentry(mm, address, tentry, PG_LEVEL_PTE);
}

pte_t tentry_ptep_clear_flush(struct vm_area_struct *vma,
			      unsigned long address,
			      tentry_t * tentry);

pmd_t tentry_pmdp_clear_flush(struct mm_struct *mm,
				       unsigned long address,
				       tentry_t *tentry);

pud_t tentry_pudp_clear_flush(struct mm_struct *mm, unsigned long address, tentry_t *tentry);

typedef struct tentry_it{
	struct mm_struct *mm;
	
	uint64_t start;
	uint64_t end;

	uint64_t addr;

	tentry_t tentry;
	pgtable_level pg_level;
	int maperr;

} tentry_iter_t;

// int tentry_iter_init_with_tentry(struct mm_struct *mm, uint64_t start, uint64_t end, tentry_t * tentry, tentry_iter_t * iter);
int tentry_iter_init(struct mm_struct *mm, uint64_t start, uint64_t end, tentry_iter_t * iter);

#define get_boundary(addr, page_size) ( (addr + page_size) & ~(page_size - 1) )

int tentry_iter_n_next(tentry_iter_t * iter, pgtable_level pg_lv, int n_step);
// int tentry_iter_next(tentry_iter_t * iter, pgtable_level pg_lv);

static inline int tentry_iter_next(tentry_iter_t * iter)
{
	return tentry_iter_n_next(iter, iter->pg_level, 1);
}

static inline int tentry_iter_has_next_step(tentry_iter_t * iter, unsigned long step_size)
{
	unsigned long next = (iter->addr + step_size) & ~(step_size - 1);
	return next < iter->end;
}

int tentry_iter_has_next(tentry_iter_t * iter);
/**
 * similar to pmd_none_or_trans_huge_or_clear_bad but remove none check
 */ 
int aspace_trans_unstable(struct mm_struct *mm, tentry_t * tentry, unsigned long addr, pgtable_level pg_size);




/* THP related */

int thp_eligible(struct vm_area_struct *vma, tentry_t * tentry, unsigned long addr, pgtable_level pg_size);

static inline pgtable_level dec_page_size(struct mm_struct *mm, pgtable_level pg_size) {
	pgtable_level res = pg_size - 1;
	if (res == PG_LEVEL_P4D) {
		res = PG_LEVEL_PUD;
	}
	return res;
}

__attribute__((unused)) static inline pgtable_level inc_page_size(struct mm_struct *mm, pgtable_level pg_size) {
	pgtable_level res = pg_size + 1;
	if (res == PG_LEVEL_P4D) {
		res = PG_LEVEL_PGD;
	}
	return res;
}

spinlock_t * aspace_lockptr(struct mm_struct *mm, tentry_t * tentry, unsigned long addr, pgtable_level pg_size);

void pgtable_trans_huge_deposit_enhanced(struct mm_struct *mm, 
	tentry_t * tentry, 
	pgtable_level pg_level, 
	unsigned long addr, 
	pgtable_t pgtable);

pgtable_t pgtable_trans_huge_withdraw_enhanced(struct mm_struct *mm, 
	tentry_t * tentry, 
	pgtable_level pg_level, 
	unsigned long addr);

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_PGTABLE_ENHANCED_H */
