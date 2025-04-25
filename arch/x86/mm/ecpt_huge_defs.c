#include "asm/pgtable.h"
#include "asm/pgtable_64_types.h"
#include "linux/pgtable.h"
#include "linux/printk.h"
#include <asm/ECPT.h>
#include <asm/ECPT_defs.h>
#include <asm/ECPT_interface.h>

#include <asm/page.h>
#include <asm/pgalloc.h>
#include <linux/spinlock.h>
#include <linux/panic.h>

inline int pgd_next_level_not_accessible(pgd_t *pgd) 
{	
	if ((pgd == (pgd_t *) &pmd_default) || pgd_none(*pgd))
		return 0;
	if (unlikely(pgd_bad(*pgd))) {
		pgd_clear_bad(pgd);
		return 1;
	}
	return 0;
}

inline int p4d_next_level_not_accessible(p4d_t *p4d) 
{
	if (p4d == (p4d_t *) &pmd_default || p4d_none(*p4d))
		return 0;
	if (unlikely(p4d_bad(*p4d))) {
		p4d_clear_bad(p4d);
		return 1;
	}
	return 0;
}

inline int pud_next_level_not_accessible(pud_t *pud) 
{
	pud_t pudval = READ_ONCE(*pud);

	if (pud == ((pud_t *) &pmd_default) || pud_none(pudval))  {
		/* pmd actually not in ECPT */
		return 0;
	}

	/**
	 * copied from pud_none_or_trans_huge_or_dev_or_clear_bad 
	 * but allow pud to be none since default case is none
	 * */
	if (pud_trans_huge(pudval) || pud_devmap(pudval))
		return 1;
	if (unlikely(pud_bad(pudval))) {
		pud_clear_bad(pud);
		return 1;
	}
	return 0;
}

inline int pmd_next_level_not_accessible(pmd_t *pmd) 
{
	pmd_t pmdval = pmd_read_atomic(pmd);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE	
	barrier();
#endif
	// if (pmd == ((pmd_t *) &pmd_default) || pmd_none(pmdval))  {
	if (no_pmd_huge_page((pmdval))) {
		/* pmd actually not in ECPT */
		return 0;
	}

	/* For ECPT case, it's unstable if it's trans_huge or bad */
	if (pmd_trans_huge(*pmd)) {
		return 1;
	}

	if (unlikely(pmd_bad(pmdval))) {
		pmd_clear_bad(pmd);
		return 1;
	}

	return 0;
}
/* TODO: fix pmd_trans_unstable and pud_trans_unstable */
inline int pmd_trans_unstable(pmd_t *pmd)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	return pmd_next_level_not_accessible(pmd);
	// pmd_t pmdval = pmd_read_atomic(pmd);
	// barrier();
	
	// if (pmd == ((pmd_t *) &pmd_default) || pmd_none(pmdval))  {
	// 	/* pmd actually not in ECPT */
	// 	return 0;
	// }

	// /* For ECPT case, it's unstable if it's trans_huge or bad */
	// if (pmd_trans_huge(*pmd)) {
	// 	return 1;
	// }

	// if (unlikely(pmd_bad(pmdval))) {
	// 	pmd_clear_bad(pmd);
	// 	return 1;
	// }

	// return 0;
#else
	return 0;
#endif
}

inline int pud_trans_unstable(pud_t *pud)
{
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) &&			\
	defined(CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD)
	pud_t pudval = READ_ONCE(*pud);

	if (pud == ((pud_t *) &pmd_default) || pud_none(pudval))  {
		/* pmd actually not in ECPT */
		return 0;
	}

	/**
	 * copied from pud_none_or_trans_huge_or_dev_or_clear_bad 
	 * but allow pud to be none since default case is none
	 * */
	if (pud_trans_huge(pudval) || pud_devmap(pudval))
		return 1;
	if (unlikely(pud_bad(pudval))) {
		pud_clear_bad(pud);
		return 1;
	}
	return 0;
#else
	return 0;
#endif
}

void pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				pgtable_t pgtable)
{
	assert_spin_locked(pmd_lockptr(mm, pmdp));

	pr_info_verbose("deposit pmdp at %llx pgtable at %llx pte_page_default at %llx\n",
	 	(uint64_t) pmdp, (uint64_t) pgtable, (uint64_t) pte_page_default);

	/* no need to deposit for ECPT */
	// if (!pmd_huge_pte(mm, pmdp))
	// 	INIT_LIST_HEAD(&pgtable->lru);
	// else
	// 	list_add(&pgtable->lru, &pmd_huge_pte(mm, pmdp)->lru);
	// pmd_huge_pte(mm, pmdp) = pgtable;
}

pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp)
{
	return pte_page_default;
}

inline void pud_mk_pmd_accessible(struct mm_struct *mm, pud_t *pud, 
	unsigned long addr, pmd_t *pmd)
{
	pr_info_verbose("make accessible pud at %llx addr= %lx\n",
	 	(uint64_t) pud, addr);
	
#if ECPT_1G_WAY > 0 || ECPT_1G_USER_WAY > 0
	if (!no_pud_huge_page(*pud)) {
		WARN(1, "Clean pud at %llx addr=%lx\n", (uint64_t) pud, addr);
		ecpt_native_pudp_get_and_clear(mm, addr, pud);
	}
#else
	/* do nothing */
#endif
}

inline void pmd_mk_pte_accessible(struct mm_struct *mm, pmd_t *pmd, 
	unsigned long addr, struct page *pte)
{
	pr_info_verbose("make accessible pmdp at %llx addr= %lx\n",
	 	(uint64_t) pmd, addr);
#if ECPT_2M_WAY > 0 || ECPT_2M_USER_WAY > 0
	if (!no_pmd_huge_page(*pmd)) {
		// WARN(1, "Clean pmd at %llx = %lx addr=%lx\n", 
		// 	(uint64_t) pmd, pmd->pmd, addr);
		if (ptep_is_in_ecpt((ECPT_desc_t *) mm->map_desc, (pte_t *) pmd,
			 		addr, page_2MB)) 
		{
			ecpt_native_pmdp_get_and_clear(mm, addr, pmd);
		}
	}
#else
	/* do nothing */
#endif
}

inline void pmd_mk_pte_accessible_kernel(struct mm_struct *mm, pmd_t *pmd, 
	unsigned long addr, pte_t *pte) 
{
	pmd_mk_pte_accessible(mm, pmd, addr, virt_to_page((void *) pte));
}

/* VMAP specific functions. By default with &init_mm */
int p4d_clear_huge_with_addr(p4d_t *p4d, unsigned long addr) 
{
	return 0;
}

int pud_clear_huge_with_addr(pud_t *pud, unsigned long addr) 
{
	if (pud_large(*pud)) {
		pudp_huge_get_and_clear(&init_mm, addr, pud);
		return 1;
	}

	return 0;
}

int pmd_clear_huge_with_addr(pmd_t *pmd, unsigned long addr) 
{
	if (pmd_large(*pmd)) {
		pmdp_huge_get_and_clear(&init_mm, addr, pmd);
		return 1;
	}
	
	return 0;
}

static inline int ecpt_pte_is_data_page(pte_t pte)
{
	return !pte_none(pte);
}

static inline int ecpt_pmd_is_data_page(pmd_t pmd)
{
#if ECPT_2M_WAY + ECPT_2M_USER_WAY > 0
	return pmd.pmd != pmd_default.pmd && !ecpt_pmd_none(pmd);
#else
	return 0;
#endif
	
}

static inline int ecpt_pud_is_data_page(pud_t pud)
{
#if ECPT_1G_WAY + ECPT_1G_USER_WAY > 0
	return !ecpt_pud_none(pud);
#else
	return 0;
#endif
}

static inline int ecpt_p4d_is_data_page(p4d_t p4d)
{
	/* ECPT doesn't support p4d level page */
	return 0;
}

static inline int ecpt_pgd_is_data_page(pgd_t pgd)
{
	/* ECPT doesn't support pgd level page */
	return 0;
}


inline int gen_pte_is_data_page(gen_pte_t gen_pte, pgtable_level level)
{
	switch (level) {
		case PG_LEVEL_PTE:
			return ecpt_pte_is_data_page(gen_pte.pte);
			break;
		case PG_LEVEL_PMD:
			return ecpt_pmd_is_data_page(gen_pte.pmd);
			break;
		case PG_LEVEL_PUD:
			return ecpt_pud_is_data_page(gen_pte.pud);
			break;
		case PG_LEVEL_P4D:
			return ecpt_p4d_is_data_page(gen_pte.p4d);
			break;
		case PG_LEVEL_PGD:
			return ecpt_pgd_is_data_page(gen_pte.pgd);
			break;
		default:
			WARN(1, "Unknown page table level\n");
			return 0;
	}
}

/* ECPT entry is never a directory */
static inline int ecpt_pte_is_directory(pte_t pte)
{
	/* PTE never a directory */
	return 0;
}

static inline int ecpt_pmd_is_directory(pmd_t pmd)
{
	return 0;
}

static inline int ecpt_pud_is_directory(pud_t pud)
{
	return 0;
}

static inline int ecpt_p4d_is_directory(p4d_t p4d)
{
	/* ECPT doesn't support p4d level page */
	return 0;
}

static inline int ecpt_pgd_is_directory(pgd_t pgd)
{
	/* ECPT doesn't support pgd level page */
	return 0;
}

inline int gen_pte_is_directory(gen_pte_t gen_pte, pgtable_level level)
{
	switch (level) {
		case PG_LEVEL_PTE:
			return ecpt_pte_is_directory(gen_pte.pte);
			break;
		case PG_LEVEL_PMD:
			return ecpt_pmd_is_directory(gen_pte.pmd);
			break;
		case PG_LEVEL_PUD:
			return ecpt_pud_is_directory(gen_pte.pud);
			break;
		case PG_LEVEL_P4D:
			return ecpt_p4d_is_directory(gen_pte.p4d);
			break;
		case PG_LEVEL_PGD:
			return ecpt_pgd_is_directory(gen_pte.pgd);
			break;
		default:
			WARN(1, "Unknown page table level\n");
			return 0;
	}
}

static inline unsigned long ecpt_pmd_get_lower_bound(unsigned long addr)
{
	return (addr >> PAGE_SHIFT_2MB) << PAGE_SHIFT_2MB;
}

static inline unsigned long ecpt_pmd_get_upper_bound(unsigned long addr)
{
	return ((addr + PAGE_SIZE_2MB) >> PAGE_SHIFT_2MB) << PAGE_SHIFT_2MB;
}

static inline int ecpt_is_partially_built_in_2M_range(struct mm_struct *mm, unsigned long addr)
{
	unsigned long start = ecpt_pmd_get_lower_bound(addr);
	unsigned long end =  ecpt_pmd_get_upper_bound(addr);
	unsigned long addr_it = start;
	
	int res = 0;
	pte_t * pte = pte_offset_ecpt(mm, addr_it);

	pr_info_verbose("start=0x%lx end=0x%lx\n", start, end);
	do {
		if (ecpt_pte_is_data_page(*pte)) {
			res = 1;
			break;
		}
	} while((addr_it += PAGE_SIZE, addr_it != end) 
		&& (pte = ptep_get_next(mm, pte, addr_it - PAGE_SIZE)));
	pr_info_verbose("addr = 0x%lx start=0x%lx end=0x%lx res = %d\n", 
		addr, start, end, res);
	return res;
}

static inline int ecpt_pte_is_partially_built(pte_t pte, unsigned long addr)
{
	/* PTE never partially built */
	return 0;
}

static inline int ecpt_pmd_is_partially_built(pmd_t pmd, struct mm_struct *mm, unsigned long addr)
{
#if ECPT_2M_WAY + ECPT_2M_USER_WAY > 0
	return !ecpt_pmd_is_data_page(pmd) &&
	       ecpt_is_partially_built_in_2M_range(mm, addr);
#else
	return 0;
#endif
}

static inline int ecpt_pud_is_partially_built(pud_t pud,  unsigned long addr)
{
#if ECPT_1G_WAY + ECPT_1G_USER_WAY > 0
	return !ecpt_pud_is_data_page(pud)
#else
	return 1;
#endif
}

static inline int ecpt_p4d_is_partially_built(p4d_t p4d,  unsigned long addr)
{
	return 0;
}

static inline int ecpt_pgd_is_partially_built(pgd_t pgd,  unsigned long addr)
{
	return 0;
}

inline int gen_pte_is_partially_built(gen_pte_t gen_pte, pgtable_level level,
				      struct mm_struct *mm, unsigned long addr)
{
	switch (level) {
		case PG_LEVEL_PTE:
			return ecpt_pte_is_partially_built(gen_pte.pte, addr);
			break;
		case PG_LEVEL_PMD:
			return ecpt_pmd_is_partially_built(gen_pte.pmd, mm, addr);
			break;
		case PG_LEVEL_PUD:
			return ecpt_pud_is_partially_built(gen_pte.pud, addr);
			break;
		case PG_LEVEL_P4D:
			return ecpt_p4d_is_partially_built(gen_pte.p4d, addr);
			break;
		case PG_LEVEL_PGD:
			return ecpt_pgd_is_partially_built(gen_pte.pgd, addr);
			break;
		default:
			WARN(1, "Unknown page table level\n");
			return 0;
	}
}

inline int gen_pte_void(gen_pte_t gen_pte, pgtable_level level,
			struct mm_struct *mm, unsigned long addr, int is_partial_built_hint)
{
	int res = 0;
	int is_data_page = gen_pte_is_data_page(gen_pte, level);
	int is_directory = gen_pte_is_directory(gen_pte, level);
	int is_partially_built = 1;
	if (!is_partial_built_hint) {
		is_partially_built = gen_pte_is_partially_built(
			gen_pte, level, mm, addr);
	}

	pr_info_verbose("gen_pte=%lx level=%d addr=%lx\n", gen_pte.pmd.pmd,
			level, addr);
	pr_info_verbose(
		"!gen_pte_is_data_page(gen_pte, level)=%d !gen_pte_is_directory(gen_pte, level)=%d !gen_pte_is_partially_built(gen_pte, level, mm, addr)=%d\n",
		!gen_pte_is_data_page(gen_pte, level),
		!gen_pte_is_directory(gen_pte, level),
		!gen_pte_is_partially_built(gen_pte, level, mm, addr));

	res =  !is_data_page && !is_directory && !is_partially_built;

	// if (res) {
	// 		pr_info("gen_pte=%lx level=%d addr=%lx is void is_data_page=%d is_directory=%d is_partially_built=%d\n",
	// 			gen_pte.pmd.pmd, level, addr, is_data_page,
	// 			is_directory, is_partially_built);
	// }

	return res;	
}