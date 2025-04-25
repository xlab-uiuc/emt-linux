// SPDX-License-Identifier: GPL-2.0
/*
 * Helper routines for building identity mapping page tables. This is
 * included by both the compressed kernel and the regular kernel.
 */

#include "asm/pgtable.h"

#ifdef CONFIG_X86_64_ECPT

/* each entry is 8 (2**3) bytes long */
#define PAGE_SIZE_TO_PAGE_NUM_MASK(x) (~((x) - 1))

#include <asm/ECPT.h>

int kernel_ident_mapping_init_ecpt(struct x86_mapping_info *info, ECPT_desc_t * ecpt,
			      unsigned long pstart, unsigned long pend)
{
	unsigned long addr = pstart + info->offset;
	unsigned long end = pend + info->offset;
	// unsigned long next;
	// int result;

	/* Set the default pagetable flags if not supplied */
	if (!info->kernpg_flag)
		info->kernpg_flag = _KERNPG_TABLE;

	/* Filter out unsupported __PAGE_KERNEL_* bits: */
	info->kernpg_flag &= __default_kernel_pte_mask;

    addr &= PAGE_SIZE_TO_PAGE_NUM_MASK(info->hpt_page_size);

	for (; addr < end; addr += info->hpt_page_size) {

		int res = ecpt_insert(ecpt, addr, addr, __ecpt_pgprot(info->kernpg_flag), 1);

		if (res) {
			// panic("error from hpt_inerst!\n");
			// error("Error: hpt_inerst failed!\n");
			return res;
		}

        pstart += info->hpt_page_size;

	}

	return 0;
}
#endif

/**
 * kernel_ident_mapping_init is arch specific code
 * it is included in the compressed kernel which dosn't contain gen_pte_code symbol.
 * Thus, we redefine the following macros to its native version.
 * Such definition will not be used in the regular kernel.
 */
#undef pmd_present
#undef pud_present
#undef p4d_present
#undef pgd_present

#define pmd_present(pmd) native_pmd_present(pmd)
#define pud_present(pud) native_pud_present(pud)
#define p4d_present(p4d) native_p4d_present(p4d)
#define pgd_present(pgd) native_pgd_present(pgd)

static void ident_pmd_init(struct x86_mapping_info *info, pmd_t *pmd_page,
			   unsigned long addr, unsigned long end)
{
	addr &= PMD_MASK;
	for (; addr < end; addr += PMD_SIZE) {
		pmd_t *pmd = pmd_page + pmd_index(addr);

		if (pmd_present(*pmd))
			continue;

		set_pmd(pmd, __pmd((addr - info->offset) | info->page_flag));
	}
}

static int ident_pud_init(struct x86_mapping_info *info, pud_t *pud_page,
			  unsigned long addr, unsigned long end)
{
	unsigned long next;

	for (; addr < end; addr = next) {
		pud_t *pud = pud_page + pud_index(addr);
		pmd_t *pmd;

		next = (addr & PUD_MASK) + PUD_SIZE;
		if (next > end)
			next = end;

		if (info->direct_gbpages) {
			pud_t pudval;

			if (pud_present(*pud))
				continue;

			addr &= PUD_MASK;
			pudval = __pud((addr - info->offset) | info->page_flag);
			set_pud(pud, pudval);
			continue;
		}

		if (pud_present(*pud)) {
			pmd = pmd_offset(pud, 0);
			ident_pmd_init(info, pmd, addr, next);
			continue;
		}
		pmd = (pmd_t *)info->alloc_pgt_page(info->context);
		if (!pmd)
			return -ENOMEM;
		ident_pmd_init(info, pmd, addr, next);
		set_pud(pud, __pud(__pa(pmd) | info->kernpg_flag));
	}

	return 0;
}

static int ident_p4d_init(struct x86_mapping_info *info, p4d_t *p4d_page,
			  unsigned long addr, unsigned long end)
{
	unsigned long next;
	int result;

	for (; addr < end; addr = next) {
		p4d_t *p4d = p4d_page + p4d_index(addr);
		pud_t *pud;

		next = (addr & P4D_MASK) + P4D_SIZE;
		if (next > end)
			next = end;

		if (p4d_present(*p4d)) {
			pud = pud_offset(p4d, 0);
			result = ident_pud_init(info, pud, addr, next);
			if (result)
				return result;

			continue;
		}
		pud = (pud_t *)info->alloc_pgt_page(info->context);
		if (!pud)
			return -ENOMEM;

		result = ident_pud_init(info, pud, addr, next);
		if (result)
			return result;

		set_p4d(p4d, __p4d(__pa(pud) | info->kernpg_flag));
	}

	return 0;
}


int kernel_ident_mapping_init(struct x86_mapping_info *info, pgd_t *pgd_page,
			      unsigned long pstart, unsigned long pend)
{
	unsigned long addr = pstart + info->offset;
	unsigned long end = pend + info->offset;
	unsigned long next;
	int result;
	/* WARN(1, "kernel_ident_mapping_init not implemented\n"); */
	/* Set the default pagetable flags if not supplied */
	if (!info->kernpg_flag)
		info->kernpg_flag = _KERNPG_TABLE;

	/* Filter out unsupported __PAGE_KERNEL_* bits: */
	info->kernpg_flag &= __default_kernel_pte_mask;

	for (; addr < end; addr = next) {
		pgd_t *pgd = pgd_page + pgd_index(addr);
		p4d_t *p4d;

		next = (addr & PGDIR_MASK) + PGDIR_SIZE;
		if (next > end)
			next = end;

		if (pgd_present(*pgd)) {
			p4d = p4d_offset(pgd, 0);
			result = ident_p4d_init(info, p4d, addr, next);
			if (result)
				return result;
			continue;
		}

		p4d = (p4d_t *)info->alloc_pgt_page(info->context);
		if (!p4d)
			return -ENOMEM;
		result = ident_p4d_init(info, p4d, addr, next);
		if (result)
			return result;
		if (pgtable_l5_enabled()) {
			set_pgd(pgd, __pgd(__pa(p4d) | info->kernpg_flag));
		} else {
			/*
			 * With p4d folded, pgd is equal to p4d.
			 * The pgd entry has to point to the pud page table in this case.
			 */
			pud_t *pud = pud_offset(p4d, 0);
			set_pgd(pgd, __pgd(__pa(pud) | info->kernpg_flag));
		}
	}

	return 0;
}



