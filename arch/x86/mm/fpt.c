#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pgtable_enhanced.h>
#include <asm/pgalloc.h>
#include <asm/pgtable_64_types.h>
#include <asm/pgtable_types.h>

#include <asm/fpt_defs.h>
#include <asm/fpt.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

#define PAGE_SIZE_512GB (1ULL << ((3 * 9) + 12))
#define PAGE_SIZE_1GB (1ULL << ((2 * 9) + 12))
#define PAGE_SIZE_2MB (1ULL << ((1 * 9) + 12))
#define PAGE_SIZE_4KB (1ULL << ((0 * 9) + 12))

static inline pgd_t *__pgd_alloc_fpt(uint32_t attr_flags, struct fpt_desc *fpt_desc)
{
	uint32_t alloc_orders = FPT_REGULAR_ALLOC_ORDER;
	bool pgd_folded = false;

	if (attr_flags & FPT_L4_L3_FOLD_FLAG) {
		alloc_orders = FPT_FLATTENED_ALLOC_ORDER;
		pgd_folded = true;
	}
	pr_info_verbose("order=%d\n", alloc_orders);
	WARN(alloc_orders > MAX_ORDER, "alloc_orders > MAX_ORDER\n");
	//return (pgd_t *)__get_free_pages(GFP_PGTABLE_USER,
	//				 alloc_orders);
	pgd_t * pgd=(pgd_t *)__get_free_pages(GFP_PGTABLE_USER, alloc_orders);

	if(!pgd){
		pgd=(pgd_t *)__get_free_pages(GFP_PGTABLE_USER, FPT_REGULAR_ALLOC_ORDER);
		pgd_folded = false;
	}

	fpt_desc->pgd_folded = pgd_folded;
	return pgd;
}

static inline void pgd_list_add(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);

	list_add(&page->lru, &pgd_list);
}

static inline void pgd_list_del(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);

	list_del(&page->lru);
}

static void pgd_set_mm(pgd_t *pgd, struct mm_struct *mm)
{
	virt_to_page(pgd)->pt_mm = mm;
}

static inline void clone_pud_range(pud_t *dst, pud_t *src, int count)
{
	memcpy(dst, src, count * sizeof(pud_t));
#ifdef CONFIG_PAGE_TABLE_ISOLATION
	WARN(1, "clone_pud_range is not implemented for PTI!\n");
	if (!static_cpu_has(X86_FEATURE_PTI))
		return;
	/* Clone the user space pgd as well */
	memcpy(kernel_to_user_pgdp(dst), kernel_to_user_pgdp(src),
	       count * sizeof(pgd_t));
#endif
}

static void pgd_ctor(struct mm_struct *mm, pgd_t *pgd, uint32_t attr_flags);


void *create_context(struct mm_struct *mm, uint32_t attr_flags)
{
	pgd_t *pgd;
	struct fpt_desc *fpt_desc;
	// pmd_t *u_pmds[MAX_PREALLOCATED_USER_PMDS];
	// pmd_t *pmds[MAX_PREALLOCATED_PMDS];

	/* Save this for now.  */
	#if defined(CONFIG_X86_64_FPT_L3L2)
		attr_flags = FPT_L3_L2_FOLD_FLAG;
	#endif
	#if defined(CONFIG_X86_64_FPT_L4L3)
		attr_flags = FPT_L4_L3_FOLD_FLAG;
	#endif
	#if defined(CONFIG_X86_64_FPT_L4L3L2L1)
		attr_flags = FPT_L4_L3_FOLD_FLAG | FPT_L2_L1_FOLD_FLAG;
	#endif

	fpt_desc = kzalloc(sizeof(struct fpt_desc), GFP_PGTABLE_USER);
	if (!fpt_desc) {
		goto out;
	}

	pgd = __pgd_alloc_fpt(attr_flags, fpt_desc);

	if (pgd == NULL){
		kfree(fpt_desc);
		goto out;
	}

	fpt_desc->pgd = pgd;
	fpt_desc->attr_flags = attr_flags;

	//if (attr_flags & FPT_L4_L3_FOLD_FLAG) {
	//	fpt_desc->pgd_folded = true;
	//} else {
	//	fpt_desc->pgd_folded = false;
	//}

	pr_info_verbose("allocating pgd at %llx attr_flags=%x\n", (uint64_t)pgd,
			attr_flags);

	mm->pgd = pgd;

	// if (preallocate_pmds(mm, pmds, PREALLOCATED_PMDS) != 0)
	// 	goto out_free_pgd;

	// if (preallocate_pmds(mm, u_pmds, PREALLOCATED_USER_PMDS) != 0)
	// 	goto out_free_pmds;

	// if (paravirt_pgd_alloc(mm) != 0)
	// 	goto out_free_user_pmds;

	/*
	 * Make sure that pre-populating the pmds is atomic with
	 * respect to anything walking the pgd_list, so that they
	 * never see a partially populated pgd.
	 */
	spin_lock(&pgd_lock);
	mm->map_desc = fpt_desc;
	pgd_ctor(mm, pgd, attr_flags);
	// pgd_prepopulate_pmd(mm, pgd, pmds);
	// pgd_prepopulate_user_pmd(mm, pgd, u_pmds);

	spin_unlock(&pgd_lock);

	return fpt_desc;

out:
	return NULL;
}
static inline void fpt_mm_inc_nr_ptes(struct mm_struct *mm, bool pmd_folded)
{
	if(pmd_folded)
		atomic_long_add(PTRS_PER_PMD * PTRS_PER_PTE * sizeof(pte_t), &mm->pgtables_bytes);
	else
		atomic_long_add(PTRS_PER_PTE * sizeof(pte_t), &mm->pgtables_bytes);
}

static inline void fpt_mm_inc_nr_pmds(struct mm_struct *mm, bool pud_folded)
{
	if(pud_folded)
		atomic_long_add(PTRS_PER_PUD * PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
	else
		atomic_long_add(PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
}

static inline void fpt_mm_inc_nr_puds(struct mm_struct *mm, bool pgd_folded)
{
	if(pgd_folded)
		atomic_long_add(PTRS_PER_P4D * PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
	else
		atomic_long_add(PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
}

static inline void fpt_mm_dec_nr_ptes(struct mm_struct *mm, bool pmd_folded)
{
	if(pmd_folded)
		atomic_long_sub(PTRS_PER_PMD * PTRS_PER_PTE * sizeof(pte_t), &mm->pgtables_bytes);
	else
		atomic_long_sub(PTRS_PER_PTE * sizeof(pte_t), &mm->pgtables_bytes);
}

static inline void fpt_mm_dec_nr_pmds(struct mm_struct *mm, bool pud_folded)
{
	if(pud_folded)
		atomic_long_sub(PTRS_PER_PUD * PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
	else
		atomic_long_sub(PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
}

static inline void fpt_mm_dec_nr_puds(struct mm_struct *mm, bool pgd_folded)
{
	if(pgd_folded)
		atomic_long_sub(PTRS_PER_P4D * PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
	else
		atomic_long_sub(PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
}

static void pgd_ctor(struct mm_struct *mm, pgd_t *pgd, uint32_t attr_flags)
{
	/* If the pgd points to a shared pagetable level (either the
	   ptes in non-PAE, or shared PMD in PAE), then just copy the
	   references from swapper_pg_dir. */
	pgd_t *src_pgd;
	pgd_t *dst_pgd;
	p4d_t * src_p4d;
	p4d_t * dst_p4d;
	pud_t *src_pud;
	pud_t *dst_pud;

	uint64_t addr = PAGE_OFFSET;
	uint32_t i = 0;
	if (CONFIG_PGTABLE_LEVELS == 2 ||
	    (CONFIG_PGTABLE_LEVELS == 3 && SHARED_KERNEL_PMD) ||
	    CONFIG_PGTABLE_LEVELS >= 4) {
		pr_info_verbose("KERNEL_PGD_BOUNDARY=%lx KERNEL_PGD_PTRS=%lx\n",
				KERNEL_PGD_BOUNDARY, KERNEL_PGD_PTRS);

		// if (attr_flags & FPT_L4_L3_FOLD_FLAG) {
		// 	WARN(1, "Folding needs attention!!\n");
		// }
		if (attr_flags & FPT_L4_L3_FOLD_FLAG) {
			for (i = 0; i < KERNEL_PGD_PTRS; i++) {
				src_pgd = swapper_pg_dir + KERNEL_PGD_BOUNDARY + i;
				src_p4d = p4d_offset(src_pgd, addr);
				src_pud = pud_offset(src_p4d, addr);
				
				dst_p4d = fpt_p4d_offset_map_with_mm(mm, pgd, addr);
				dst_pud = fpt_pud_offset_map_with_mm(mm, dst_p4d, addr);
				
				pr_info_verbose("addr=%llx src_pgd at %llx = %lx src_pud at %llx dst_p4d at %llx dst_pud at %llx\n",
					addr, (uint64_t) src_pgd, src_pgd->pgd, (uint64_t)src_pud, (uint64_t)dst_p4d, (uint64_t)dst_pud);
				clone_pud_range(dst_pud, src_pud, 512);
	
				addr += PAGE_SIZE_512GB;
			}
		} else {
			clone_pgd_range(pgd + KERNEL_PGD_BOUNDARY,
			swapper_pg_dir + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);
		}

		// clone_pgd_range(pgd + KERNEL_PGD_BOUNDARY,
		// 		swapper_pg_dir + KERNEL_PGD_BOUNDARY,
		// 		KERNEL_PGD_PTRS);
	}

	/* list required to sync kernel mapping updates */
	if (!SHARED_KERNEL_PMD) {
		pgd_set_mm(pgd, mm);
		pgd_list_add(pgd);
	}
}

int read_tentry(struct mm_struct *mm, uint64_t addr, tentry_t *tentry,
		pgtable_level *pg_size)
{
	pgd_t *pgd = NULL;
	p4d_t *p4d = NULL;
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	bool pgd_folded = ((struct fpt_desc *)mm->map_desc)->pgd_folded;

	pr_info_verbose("read_tentry addr=%llx\n", addr);
	
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

	pgd = fpt_pgd_offset_map_with_mm(mm, addr);

	// pr_info_verbose("pgd at %llx = %lx\n", (uint64_t)pgd, pgd->pgd);
	tentry->ptep[PG_LEVEL_PGD] = PGDP_TO_GENPTEP(pgd);
	*pg_size = PG_LEVEL_PGD;

	if (!pgd_folded && (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))) {
		return E_PAGE_NOT_MAPPED;
	}

	if (unlikely(pgd_large(*pgd))) {
		return 0;
	}

	p4d = fpt_p4d_offset_map_with_mm(mm, pgd, addr);

	// pr_info_verbose("p4d at %llx = %lx\n", (uint64_t)p4d, p4d->p4d);
	tentry->ptep[PG_LEVEL_P4D] = P4DP_TO_GENPTEP(p4d);
	*pg_size = PG_LEVEL_P4D;

	if (!pgd_folded && (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))) {
		return E_PAGE_NOT_MAPPED;
	}

	if (unlikely(p4d_large(*p4d))) {
		return 0;
	}

	pud = fpt_pud_offset_map_with_mm(mm, p4d, addr);

	// pr_info_verbose("pud at %llx = %lx\n", (uint64_t)pud, pud->pud);
	tentry->ptep[PG_LEVEL_PUD] = PUDP_TO_GENPTEP(pud);

pud_ready:
	*pg_size = PG_LEVEL_PUD;

	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		return E_PAGE_NOT_MAPPED;
	}

	if (unlikely(pud_trans_huge(*pud))) {
		return 0;
	}

	pmd = fpt_pmd_offset_map_with_mm(mm, pud, addr);

	tentry->ptep[PG_LEVEL_PMD] = PMDP_TO_GENPTEP(pmd);

	// pr_info_verbose("pmd at %llx = %lx\n", (uint64_t)pmd, pmd->pmd);
pmd_ready:
	*pg_size = PG_LEVEL_PMD;
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		return E_PAGE_NOT_MAPPED;
	}

	if (pmd_trans_huge(*pmd)) {
		return 0;
	}

	pte = fpt_pte_offset_map_with_mm(mm, pmd, addr);

	// pr_info_verbose("pte at %llx = %lx\n", (uint64_t)pte, pte->pte);
	tentry->ptep[PG_LEVEL_PTE] = PTEP_TO_GENPTEP(pte);

pte_ready:
	*pg_size = PG_LEVEL_PTE;

	if (pte_none(*pte)) {
		return E_PAGE_NOT_MAPPED;
	}

	return 0;
}

static int __p4d_alloc_nolock(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	return 0;
}

static inline void *__alloc_flattened_page(struct mm_struct *mm, unsigned long addr)
{
	gfp_t gfp = GFP_PGTABLE_USER;
	
	pr_info_verbose("try to allocate flattened page order=%d\n", FPT_FLATTENED_ALLOC_ORDER);
	if (mm == &init_mm)
		gfp = GFP_PGTABLE_KERNEL;
	return (void *) __get_free_pages(gfp, FPT_FLATTENED_ALLOC_ORDER);
}

static inline void set_fpt_parent_bit(pmd_t *pmd)
{
	pmd->pmd |= NEXT_LEVEL_FOLDED_MASK;
}


static int __pud_alloc_nolock(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
{
	pud_t *new = NULL;
	struct page *page = NULL;
	int i = 0;
	bool flattened_allocated;

	if (get_fpt_attr_flags(mm) & FPT_L4_L3_FOLD_FLAG) {
		/* no allocation at PUD level for L4L3 folding */
		return 0;
	}

	if (get_fpt_attr_flags(mm) & FPT_L3_L2_FOLD_FLAG) {
		if (new = __alloc_flattened_page(mm, address)) {
			page = virt_to_page(new);
			for (i = 0; i < PTRS_PER_PUD; ++i, ++page) {
				pgtable_pmd_page_ctor(page);
			}
		}
	}
	
	flattened_allocated = true;
	if (!new){
		pr_info_verbose("No allocation made\n");
		new = pud_alloc_one(mm, address);
		flattened_allocated = false;
		if (!new)
			return -ENOMEM;
	}
	
	smp_wmb(); /* See comment in __pte_alloc */

	// spin_lock(&mm->page_table_lock);
	if (!p4d_present(*p4d)) {
// #ifdef CONFIG_PGTABLE_OP_GENERALIZABLE		
// 		p4d_mk_pud_accessible(mm, p4d, address, new);
// #else	
		p4d_populate(mm, p4d, new);
		if (flattened_allocated) {
			set_fpt_parent_bit((pmd_t *)p4d);
			fpt_mm_inc_nr_pmds(mm, true);
		} else {
			fpt_mm_inc_nr_puds(mm, false);
		}
		pr_info_verbose("p4d at %llx p4d=%lx new at %llx\n", (uint64_t) p4d,  p4d->p4d, (uint64_t)new);
// #endif
	} else {
		if (flattened_allocated) {
			free_pages((unsigned long )new, FPT_FLATTENED_ALLOC_ORDER);
		} else {
			pud_free(mm, new);
		}
		
	}	/* Another has populated it */
		
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
	bool flattened_allocated;
	pmd_t * new = NULL;
	struct page *page = NULL;
	int i = 0;
	if (get_fpt_attr_flags(mm) & FPT_L2_L1_FOLD_FLAG) {
		if (new = __alloc_flattened_page(mm, address)) {
			page = virt_to_page(new);
			for (i = 0; i < PTRS_PER_PMD; ++i, ++page) {
				pgtable_pte_page_ctor(page);
			}
		}
	}
	
	flattened_allocated = true;
	if (!new){
		pr_info_verbose("No allocation made\n");
		new = pmd_alloc_one(mm, address);
		flattened_allocated = false;
		if (!new)
			return -ENOMEM;
	}

	

	smp_wmb(); /* See comment in __pte_alloc */

	// ptl = pud_lock(mm, pud);
	if (!pud_present(*pud)) {
// #ifdef CONFIG_PGTABLE_OP_GENERALIZABLE		
// 		pud_mk_pmd_accessible(mm, pud, address, new);
// #else	
		pud_populate(mm, pud, new);
		if (flattened_allocated) {
			set_fpt_parent_bit((pmd_t *)pud);
			fpt_mm_inc_nr_ptes(mm, true);
		} else {
			fpt_mm_inc_nr_pmds(mm, false);
		}
		// #endif
		pr_info_verbose("pud at %llx pud=%lx new at %llx\n", (uint64_t) pud,  pud->pud, (uint64_t)new);
	} else {	/* Another has populated it */
		pmd_free(mm, new);
	}// spin_unlock(ptl);
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
		NULL : fpt_p4d_offset_map_with_mm(mm, pgd, address);
}

static inline pud_t *pud_alloc_nolock(struct mm_struct *mm, p4d_t *p4d,
		unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) && __pud_alloc_nolock(mm, p4d, address)) ?
		NULL : fpt_pud_offset_map_with_mm(mm, p4d, address);
}

static inline pmd_t *pmd_alloc_nolock(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __pmd_alloc_nolock(mm, pud, address))?
		NULL: fpt_pmd_offset_map_with_mm(mm, pud, address);
}

static inline pte_t *pte_alloc_nolock(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	return (unlikely(pmd_none(*pmd)) && __pte_alloc_nolock(mm, pmd, address))?
		NULL: fpt_pte_offset_map_with_mm(mm, pmd, address);
}


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
		pgd = fpt_pgd_offset_map_with_mm(mm, addr);
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
		set_pte(pte, gen_pte.pte);
		// set_pte_at(mm, addr, pte, gen_pte.pte);
		pr_info_verbose("set_pte_at addr=%llx, pte=%lx\n", addr, pte->pte);
		pr_tentry_verbose(tentry);
	}

	return 0;
}

static inline uint64_t get_parent_page_size(struct mm_struct *mm, tentry_t * entry, pgtable_level pg_size)
{
	if (pg_size == PG_LEVEL_PTE) {
		// if (entry->ptep[pg_size] == entry->ptep[pg_size + 1]) {
		// 	/* L2 + L1 folded */
		// 	return PAGE_SIZE_1GB;
		// } else {
		// 	return PAGE_SIZE_2MB;
		// }
		pmd_t * parent = GENPTEP_TO_PMDP(entry->ptep[pg_size + 1]);
		if (parent && NEXT_LEVEL_IS_FOLDED(parent->pmd)) {
			/* L2 + L1 folded */
			return PAGE_SIZE_1GB;
		} else {
			return PAGE_SIZE_2MB;
		}

	} else if (pg_size == PG_LEVEL_PMD) {
		// if (entry->ptep[pg_size] == entry->ptep[pg_size + 1]) {
		// 	/* L3 + L2 folded */
		// 	return PAGE_SIZE_512GB;
		// } else {
		// 	return PAGE_SIZE_1GB;
		// }
		pud_t * parent = GENPTEP_TO_PUDP(entry->ptep[pg_size + 1]);
		if (parent && NEXT_LEVEL_IS_FOLDED(parent->pud)) {
			/* L3 + L2 folded */
			return PAGE_SIZE_512GB;
		} else {
			return PAGE_SIZE_1GB;
		}
	} else if (pg_size == PG_LEVEL_PUD) {
		bool pgd_folded = ((struct fpt_desc *)mm->map_desc)->pgd_folded;
		if (pgd_folded) {
			/* L4 + L3 folded */
			return PAGE_SIZE_512GB * 512;
		} else {
			/* L4 + L3 not folded */
			return PAGE_SIZE_512GB;
		}
		// if (entry->ptep[pg_size] == entry->ptep[pg_size + 1]) {
		// 	/* L4 + L3 folded */
		// 	return PAGE_SIZE_512GB * 512;
		// } else {
		// 	return PAGE_SIZE_512GB;
		// }

	} else {
		return PAGE_SIZE_512GB * 512;
	}
}

static inline uint64_t pgtable_level_to_size_fpt(struct mm_struct *mm, pgtable_level pg_size)
{
	if (pg_size == PG_LEVEL_PGD) {
		pg_size -= 1;
	}
	return (1ULL << ((pg_size * 9) + 12));
}

int tentry_iter_n_next(tentry_iter_t * iter, pgtable_level pg_lv, int n_step)
{
	/* n_step < 512 */
	uint64_t boundary = 0;
	// uint64_t next = iter->addr + pgtable_level_to_size_fpt(iter->mm, pg_lv, iter->tentry.ptep[pg_lv + 1]) * n_step;
	uint64_t pg_size = pgtable_level_to_size_fpt(iter->mm, pg_lv);
	uint64_t next = (iter->addr + pg_size * n_step) & ~(pg_size - 1);
	gen_pte_t * gen_ptep = NULL;
	pte_t * ptep = NULL;
	
	pr_tentry_verbose(&iter->tentry);
	pr_info_verbose("addr=%llx, pg_lv=%d, n_step=%d next=%llx\n", iter->addr, pg_lv, n_step, next);


	if (next >= iter->end) {
		return -1;
	}

	for (; pg_lv <= PG_LEVEL_PGD; pg_lv++) {
		uint64_t parent_page_size = 0;
		parent_page_size = get_parent_page_size(iter->mm, &iter->tentry, pg_lv);

		boundary = get_boundary(iter->addr, parent_page_size);
		pr_info_verbose("boundary=%llx, parent_page_size=%llx\n", boundary, parent_page_size);
		if (next < boundary) {
			iter->addr = next;
			gen_ptep = iter->tentry.ptep[pg_lv];
			pr_info_verbose("gen_ptep at %llx\n", (uint64_t)gen_ptep);
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
					// pr_info_verbose("ptep at %llx\n", (uint64_t) ptep);
					// iter->maperr = E_PAGE_NOT_MAPPED;
					
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

// #ifndef pte_free_tlb
// #define pte_free_tlb(tlb, ptep, address)			\
// 	do {							\
// 		tlb_flush_pmd_range(tlb, address, PAGE_SIZE);	\
// 		tlb->freed_tables = 1;				\
// 		__pte_free_tlb(tlb, ptep, address);		\
// 	} while (0)
// #endif

static inline void fpt_pte_free_tlb(struct mmu_gather *tlb, pgtable_t token, unsigned long addr, bool pmd_folded) {
	unsigned long pte_page_addr;													/* starting 2MB address of PTE page */
	struct page *page = token;
	int i = 0;

	if (pmd_folded) {
		pte_page_addr = (unsigned long)page_to_virt(token);

		tlb_flush_pmd_range(tlb, addr, PAGE_SIZE);									/* these two statements are from pte_free_tlb, we left it here */
		tlb->freed_tables = 1;
		
		for (i = 0; i < PTRS_PER_PTE; ++i, ++page) {
			pgtable_pte_page_dtor(page);
		}

		free_pages(pte_page_addr, 9);												/* free pages manually */
		tlb_flush(tlb);
		/* flush tlb address range appropriately*/
		// if (flush_tlb_mm_range(tlb->mm, pte_page_addr, pte_page_addr + PAGE_SIZE_2MB,
		// 						tlb_get_unmap_shift(tlb), tlb->freed_tables)) {
		// 	tlb_flush_mmu_free(tlb);												/* if flushed all, we free batched list */
		// }
	} else {
		pte_free_tlb(tlb, token, addr);
	}
}

static inline void fpt_pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd, unsigned long addr, bool pmd_folded) {
	unsigned long pmd_page_addr;													/* starting 2MB address of PTE page */
	struct page *page = NULL;
	int i = 0;

	if (pmd_folded) {
		pmd_page_addr = (unsigned long)pmd & PMD_MASK;

		tlb_flush_pud_range(tlb, addr, PAGE_SIZE);									/* these two statements are from pte_free_tlb, we left it here */
		tlb->freed_tables = 1;

		page = virt_to_page(pmd_page_addr);
		for (i = 0; i < PTRS_PER_PMD; ++i, ++page) {
			pgtable_pmd_page_dtor(page);
		}
		
		free_pages(pmd_page_addr, 9);												/* free pages manually */
		tlb_flush(tlb);
		// if (flush_tlb_mm_range(tlb->mm, pmd_page_addr, pmd_page_addr + PAGE_SIZE_2MB,/* flush tlb address range appropriately*/
		// 					tlb_get_unmap_shift(tlb), tlb->freed_tables)) {			/* if flushed all, we free batched list */
		// 	tlb_flush_mmu_free(tlb);
		// }
	} else {
		pmd_free_tlb(tlb, pmd, addr);
	}
}

static void free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
	unsigned long addr)
{
	pgtable_t token = pmd_pgtable(*pmd);	// bound checking has been performed in free_pgd_range, so none is needed here
	pmd_clear(pmd);
	pte_free_tlb(tlb, token, addr);
	mm_dec_nr_ptes(tlb->mm);				// pte can't be folded (otherwise it is a hugepage), so no additional parameter is needed
}

static inline void free_pmd_range(struct mmu_gather *tlb, pud_t *pud, p4d_t *p4d,
	 unsigned long addr, unsigned long end,
	 unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;

	if(should_skip_pmd(tlb->mm, pud)){
		start &= PUD_MASK;
		if (start < floor)
			return;
		if (ceiling) {
			ceiling &= PUD_MASK;
		if (!ceiling)
			 return;
		}
		if (end - 1 > ceiling - 1)
			return;
	
		pgtable_t token = pmd_pgtable(*(pmd_t*)pud);
		// pmd = pmd_offset(pud, start);
		pud_clear(pud);
		fpt_pte_free_tlb(tlb, token, addr, true);
		fpt_mm_dec_nr_ptes(tlb->mm, true);

		return;
	}

	pmd = fpt_pmd_offset_map_with_mm(tlb->mm, pud, addr);
	// pmd = pmd_offset(pud, addr);
	
	do {
		next = pmd_addr_end(addr, end);

		/* cannot skip partial_built check here since later operations will modify pgtable */
		//if (pmd_next_level_not_accessible_regular(pmd, tlb->mm, addr, 0))
		// 	continue;
		if (pmd_none_or_clear_bad(pmd))
		 	continue;
		free_pte_range(tlb, pmd, addr);
	} while(next != end ? 
	(pmd = pmdp_get_next(tlb->mm, pmd, addr), addr = next) : 
	(addr = next, 0));

	if(should_skip_pud(tlb->mm, p4d)){
		start &= P4D_MASK;
		if (start < floor)
			return;
		if (ceiling) {
			ceiling &= P4D_MASK;
		if (!ceiling)
		 	return;
		}
		if (end - 1 > ceiling - 1)
			return;


		pmd = fpt_pmd_offset_map_with_mm(tlb->mm, pud, addr);
		// pud = pud_offset(p4d, start);

		p4d_clear(p4d);
		fpt_pmd_free_tlb(tlb, pmd, start, true);
		fpt_mm_dec_nr_pmds(tlb->mm, true);
	} else {
		start &= PUD_MASK;
		if (start < floor)
			return;
		if (ceiling) {
			ceiling &= PUD_MASK;
		if (!ceiling)
		 	return;
		}
		if (end - 1 > ceiling - 1)
			return;

		pmd = fpt_pmd_offset_map_with_mm(tlb->mm, pud, addr);
		// pmd = pmd_offset(pud, start);
		pud_clear(pud);
		fpt_pmd_free_tlb(tlb, pmd, start, false);
		fpt_mm_dec_nr_pmds(tlb->mm, false);
	}
}

static inline void free_pud_range(struct mmu_gather *tlb, p4d_t *p4d,
	 unsigned long addr, unsigned long end,
	 unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	
	if(should_skip_pud(tlb->mm, p4d)){
		free_pmd_range(tlb, (pud_t*)p4d, p4d, addr, end, floor, ceiling);
		return;
	}

	pud = fpt_pud_offset_map_with_mm(tlb->mm, p4d, addr);
	// pud = pud_offset(p4d, addr);
	
	do {
		next = pud_addr_end(addr, end);
		//if (pud_next_level_not_accessible(pud))
		// 	continue;
		if (pud_none_or_clear_bad(pud))
			continue;
		free_pmd_range(tlb, pud, p4d, addr, next, floor, ceiling);
	} while(next != end ? 
	 (pud = pudp_get_next(tlb->mm, pud, addr), addr = next) : 
	 (addr = next, 0));
	// while (pud++, addr = next, addr != end);

	if(should_skip_pgd(tlb->mm)&&should_skip_p4d(tlb->mm)){
		return;	// nothing should be done as $cr3 shouldn't be freed
	} else {
		start &= P4D_MASK;
		if (start < floor)
			return;
		if (ceiling) {
			ceiling &= P4D_MASK;
		if (!ceiling)
		 	return;
		}
		if (end - 1 > ceiling - 1)
			return;


		pud = fpt_pud_offset_map_with_mm(tlb->mm, p4d, addr);
		// pud = pud_offset(p4d, start);

		p4d_clear(p4d);
		pud_free_tlb(tlb, pud, start);
		fpt_mm_dec_nr_puds(tlb->mm, false);
	}

}

static inline void free_p4d_range(struct mmu_gather *tlb, pgd_t *pgd,
	 unsigned long addr, unsigned long end,
	 unsigned long floor, unsigned long ceiling)
{
	p4d_t *p4d;
	unsigned long next;
	unsigned long start;

	start = addr;
	// p4d = p4d_offset(pgd, addr);

	if(should_skip_pgd(tlb->mm)){
			free_pud_range(tlb, (p4d_t*)pgd, addr, end, floor, ceiling);
			return;
	}

	p4d = fpt_p4d_offset_map_with_mm(tlb->mm, pgd, addr);

	do {
		next = p4d_addr_end(addr, end);

	//if (p4d_next_level_not_accessible(p4d))
	// 	continue;
		if (p4d_none_or_clear_bad(p4d))
		 	continue; 
		free_pud_range(tlb, p4d, addr, next, floor, ceiling);
	} while(next != end ? 
	 (p4d = p4dp_get_next(tlb->mm, p4d, addr), addr = next) : 
	 (addr = next, 0));
	// while (p4d++, addr = next, addr != end);

	// 	As p4d folding means it is non existent and is handled in provided function, so no additional check is needed
	//	if(should_skip_pgd(tlb->mm))
	//		return;

	start &= PGDIR_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
	if (!ceiling)
	 	return;
	}
	if (end - 1 > ceiling - 1)
		return;


	p4d = fpt_p4d_offset_map_with_mm(tlb->mm, pgd, addr);
	// p4d = p4d_offset(pgd, start);

	pgd_clear(pgd);
	p4d_free_tlb(tlb, p4d, start);
}

/*
* This function frees user-level page tables of a process.
*/
void free_pgd_range(struct mmu_gather *tlb,
 unsigned long addr, unsigned long end,
 unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next;

	pr_info_verbose("addr=%lx end=%lx floor=%lx ceiling=%lx\n", addr, end, floor, ceiling);

	//#ifdef CONFIG_X86_64_FPT
	///* Hack */
	//return;
	//#endif
	/*
	* The next few lines have given us lots of grief...
	*
	* Why are we testing PMD* at this top level?  Because often
	* there will be no work to do at all, and we'd prefer not to
	* go all the way down to the bottom just to discover that.
	*
	* Why all these "- 1"s?  Because 0 represents both the bottom
	* of the address space and the top of it (using -1 for the
	* top wouldn't help much: the masks would do the wrong thing).
	* The rule is that addr 0 and floor 0 refer to the bottom of
	* the address space, but end 0 and ceiling 0 refer to the top
	* Comparisons need to use "end - 1" and "ceiling - 1" (though
	* that end 0 case should be mythical).
	*
	* Wherever addr is brought up or ceiling brought down, we must
	* be careful to reject "the opposite 0" before it confuses the
	* subsequent tests.  But what about where end is brought down
	* by PMD_SIZE below? no, end can't go down to 0 there.
	*
	* Whereas we round start (addr) and ceiling down, by different
	* masks at different levels, in order to test whether a table
	* now has no other vmas using it, so can be freed, we don't
	* bother to round floor or end up - the tests don't need that.
	*/

	addr &= PMD_MASK;
	if (addr < floor) {
		addr += PMD_SIZE;
	if (!addr)
	 	return;
	}
	if (ceiling) {
		ceiling &= PMD_MASK;
	if (!ceiling)
	 	return;
	}
	if (end - 1 > ceiling - 1)
		end -= PMD_SIZE;
	if (addr > end - 1)
		return;
	/*
	* We add page table cache pages with PAGE_SIZE,
	* (see pte_free_tlb()), flush the tlb if we need
	*/
	tlb_change_page_size(tlb, PAGE_SIZE);

	pgd = fpt_pgd_offset_map_with_mm(tlb->mm, addr);
	// pgd = pgd_offset(tlb->mm, addr);

	
	if(should_skip_pgd(tlb->mm)){
		free_p4d_range(tlb, pgd, addr, end, floor, ceiling);
		addr=end;
	} else {
		do {
			next = pgd_addr_end(addr, end);
			//if (pgd_next_level_not_accessible(pgd))
			// 	continue;
			if (pgd_none_or_clear_bad(pgd))
				continue;
			free_p4d_range(tlb, pgd, addr, next, floor, ceiling);
		} while(next != end ? 
		(pgd = pgdp_get_next(tlb->mm, pgd, addr), addr = next) : 
		(addr = next, 0));
		// while (pgd++, addr = next, addr != end);
	}
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (SHARED_KERNEL_PMD)
		return;

	spin_lock(&pgd_lock);
	struct page *page = virt_to_page(pgd);
	list_del(&page->lru);
	spin_unlock(&pgd_lock);
	if(should_skip_pgd(mm))
		free_pages((unsigned long)pgd, FPT_FLATTENED_ALLOC_ORDER);
	else
		free_pages((unsigned long)pgd, FPT_REGULAR_ALLOC_ORDER);
}
