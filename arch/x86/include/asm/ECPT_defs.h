#ifndef _ASM_X86_ECPT_DEFS_H
#define _ASM_X86_ECPT_DEFS_H


#define LOG_1(n) (((n) >= 1ULL << 1) ? 1 : 0)
#define LOG_2(n) (((n) >= 1ULL << 2) ? (2 + LOG_1((n) >> 2)) : LOG_1(n))
#define LOG_4(n) (((n) >= 1ULL << 4) ? (4 + LOG_2((n) >> 4)) : LOG_2(n))
#define LOG_8(n) (((n) >= 1ULL << 8) ? (8 + LOG_4((n) >> 8)) : LOG_4(n))
#define LOG_16(n) (((n) >= 1ULL << 16) ? (16 + LOG_8((n) >> 16)) : LOG_8(n))
#define LOG_32(n) (((n) >= 1ULL << 32) ? (32 + LOG_16((n) >> 32)) : LOG_16(n))
#define LOG(n) LOG_32(n)

#define HPT_SIZE_MASK (0xfff)      	/* 2 ^ cr3[0:11] for number of entries */

#define GET_HPT_SIZE(cr3) ( (((uint64_t) cr3) & HPT_SIZE_MASK) ? 1ULL << (((uint64_t) cr3) & HPT_SIZE_MASK) : 0)
#define HPT_NUM_ENTRIES_TO_CR3(size) (LOG(size))

#define HPT_BASE_MASK (0x000ffffffffff000UL)
#define GET_HPT_BASE(cr3) (((uint64_t) cr3) & HPT_BASE_MASK )


/* we should use GET_HPT_BASE_VIRT after kernel transitions to virtual address space */
#define HPT_BASE_MASK_VIRT (0xfffffffffffff000UL)
#define GET_HPT_BASE_VIRT(cr3) (((uint64_t) cr3) & HPT_BASE_MASK_VIRT )
/**
 * @brief cr in virtual
 * 		virtual address + hpt_size
 * 	cr in physical
 * 		physical address + hpt_size + ecpt_enabled_bit (for cr3)
 */

#define PG_ADDRESS_MASK   (0x000ffffffffff000LL)
#define VIRTUAL_ADDR_MASK (0x0000fffffffff000LL)

#define PAGE_TAIL_MASK_4KB (0xfff)
#define PAGE_TAIL_MASK_2MB (0x1fffff)
#define PAGE_TAIL_MASK_1GB (0x3fffffff)
#define PAGE_TAIL_MASK_512GB (0x7fffffffff)


#define PAGE_SHIFT_4KB (12)
#define PAGE_SHIFT_2MB (21)
#define PAGE_SHIFT_1GB (30)
#define PAGE_SHIFT_512GB (39)

#define ECPT_CLUSTER_NBITS 3
#define ECPT_CLUSTER_FACTOR (1 << ECPT_CLUSTER_NBITS)


/**
 *  Here we use available bits in pte from 52-58.
 *  Note that Bit 58 already taken by Linux as _PAGE_BIT_DEVMAP
 */
#define PTE_REPROPOSE_VPN_BITS 5

#if (PTE_REPROPOSE_VPN_BITS * ECPT_CLUSTER_FACTOR) < (48 - PAGE_SHIFT_4KB - ECPT_CLUSTER_NBITS)
#error Insufficient PTE_REPROPOSE_VPN_BITS
#endif

#if PTE_REPROPOSE_VPN_BITS > 6
#error PTE_REPROPOSE_VPN_BITS overflow
#endif

#if PTE_REPROPOSE_VPN_BITS > 0

#if PTE_REPROPOSE_VPN_BITS == 5
	#define PTE_VPN_MASK (0x01f0000000000000LL)
	#define SWP_VPN_EXTRA_SHFIT (7)
	#define SWP_VPN_MASK (0x07f0000000000000LL)
	#define VPN_TAIL_MASK (0x000000000000001fLL)
	#define PTE_VPN_SHIFT (52)

	/* start from e->pte[PTE_IDX_FOR_COUNT] to e->pte[ECPT_CLUSTER_FACTOR] 
		will be used to count how many valid ptes are in the entry*/
	#define PTE_IDX_FOR_COUNT (7)
#endif	


#define GET_PARTIAL_VPN_BASE(pte) ( ((pte) & PTE_VPN_MASK) >> PTE_VPN_SHIFT )
#define GET_PARTIAL_VPN_SHIFTED(pte, idx) (GET_PARTIAL_VPN_BASE(pte) << (idx * PTE_REPROPOSE_VPN_BITS))
#define GET_VALID_PTE_COUNT(pte) GET_PARTIAL_VPN_BASE(pte)

#define PARTIAL_VPN_OF_IDX(vpn, idx) ((vpn >> (idx * PTE_REPROPOSE_VPN_BITS)) & VPN_TAIL_MASK)
#define PARTIAL_VPN_IN_PTE(vpn, idx) (PARTIAL_VPN_OF_IDX(vpn, idx) << PTE_VPN_SHIFT)
#define PTE_WITH_VPN_CLEARED(pte) (pte & ~PTE_VPN_MASK)
#define VALID_NUM_IN_PTE(num) ((num & VPN_TAIL_MASK) << PTE_VPN_SHIFT)

#define CLEAR_PTE_BUT_NOT_VPN(pte) ((pte) & PTE_VPN_MASK)
#endif


#define PAGE_SIZE_4KB (1UL << PAGE_SHIFT_4KB)
#define PAGE_SIZE_2MB (1UL << PAGE_SHIFT_2MB)
#define PAGE_SIZE_1GB (1UL << PAGE_SHIFT_1GB)
#define PAGE_SIZE_512GB (1UL << PAGE_SHIFT_512GB)

#define VADDR_TO_PAGE_NUM_NO_CLUSTER_4KB(x)   (((x) & VIRTUAL_ADDR_MASK) >> (PAGE_SHIFT_4KB))
#define VADDR_TO_PAGE_NUM_NO_CLUSTER_2MB(x)   (((x) & VIRTUAL_ADDR_MASK) >> (PAGE_SHIFT_2MB))
#define VADDR_TO_PAGE_NUM_NO_CLUSTER_1GB(x)   (((x) & VIRTUAL_ADDR_MASK) >> (PAGE_SHIFT_1GB))

#define VADDR_TO_PAGE_NUM_4KB(x)   (VADDR_TO_PAGE_NUM_NO_CLUSTER_4KB(x) >> ECPT_CLUSTER_NBITS)
#define VADDR_TO_PAGE_NUM_2MB(x)   (VADDR_TO_PAGE_NUM_NO_CLUSTER_2MB(x) >> ECPT_CLUSTER_NBITS)
#define VADDR_TO_PAGE_NUM_1GB(x)   (VADDR_TO_PAGE_NUM_NO_CLUSTER_1GB(x) >> ECPT_CLUSTER_NBITS)

#define PTE_TO_PADDR(pte)   ((pte) & PG_ADDRESS_MASK)

#define PADDR_TO_PTE_4KB(x)   (((x) & ~PAGE_TAIL_MASK_4KB) & PG_ADDRESS_MASK)
#define PADDR_TO_PTE_2MB(x)   (((x) & ~PAGE_TAIL_MASK_2MB) & PG_ADDRESS_MASK)
#define PADDR_TO_PTE_1GB(x)   (((x) & ~PAGE_TAIL_MASK_1GB) & PG_ADDRESS_MASK)

#define SHIFT_TO_ADDR_4KB(x)   (((uint64_t) x) << (PAGE_SHIFT_4KB))
#define SHIFT_TO_ADDR_2MB(x)   (((uint64_t) x) << (PAGE_SHIFT_2MB))
#define SHIFT_TO_ADDR_1GB(x)   (((uint64_t) x) << (PAGE_SHIFT_1GB))

#define VPN_TO_VADDR_4KB(x)   (SHIFT_TO_ADDR_4KB(x) << ECPT_CLUSTER_NBITS)
#define VPN_TO_VADDR_2MB(x)   (SHIFT_TO_ADDR_2MB(x) << ECPT_CLUSTER_NBITS)
#define VPN_TO_VADDR_1GB(x)   (SHIFT_TO_ADDR_1GB(x) << ECPT_CLUSTER_NBITS)

#define ADDR_ROUND_DOWN_4KB(x)   ((((uint64_t) x) >> PAGE_SHIFT_4KB) << (PAGE_SHIFT_4KB))
#define ADDR_ROUND_DOWN_2MB(x)   ((((uint64_t) x) >> PAGE_SHIFT_2MB) << (PAGE_SHIFT_2MB))

#define PTE_CLUSTERED_SIZE (ECPT_CLUSTER_FACTOR * PAGE_SIZE_4KB)
#define PMD_CLUSTERED_SIZE (ECPT_CLUSTER_FACTOR * PAGE_SIZE_2MB)
#define PUD_CLUSTERED_SIZE (ECPT_CLUSTER_FACTOR * PAGE_SIZE_1GB)

#define cluster_pte_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PTE_CLUSTERED_SIZE) & (~(PTE_CLUSTERED_SIZE - 1));	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

#define cluster_pmd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PMD_CLUSTERED_SIZE) & (~(PMD_CLUSTERED_SIZE - 1));	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

#define cluster_pud_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PUD_CLUSTERED_SIZE) & (~(PUD_CLUSTERED_SIZE - 1));	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

#define ENTRY_TO_PROT(x) ((x) & ~PG_ADDRESS_MASK)
#define ENTRY_TO_ADDR(x) ((x) & PG_ADDRESS_MASK)

#define EARLY_HPT_ENTRIES (512 * 8 * 4)
#define EARLY_HPT_CR3_SIZE_VAL (14) /* force to use constant here since this will be used in head_64.S */
#define EARLY_HPT_ENTRY_SIZE (64) /* TODO: change this whenever ecpt_entry_t changed its size */
#define EARLY_HPT_ENTRY_QUAD_CNT (EARLY_HPT_ENTRY_SIZE / 8)
#define EARLY_HPT_SIZE (EARLY_HPT_ENTRIES * EARLY_HPT_ENTRY_SIZE)
#define EARLY_HPT_OFFSET_MASK (EARLY_HPT_ENTRIES - 1)         /* the trailing 12 */


#define CR3_TRANSITION_SHIFT (63)
#define CR3_TRANSITION_BIT (0x8000000000000000ULL)
/* Note: technically we eat one bit of available physical address
	This can be avoided by define ECPT_DESC_SHIFT to (12 - 3)
	where 2^3 is the size of long long int, which is the minimum alignment from kmalloc.
 */
#define ECPT_DESC_SHIFT (PAGE_SHIFT_4KB)
#define ECPT_DESC_PA_TO_CR3_FORMAT(x)                                          \
	(((x) << ECPT_DESC_SHIFT) | CR3_TRANSITION_BIT)

#define REHASH_PTR_MAX __UINT32_MAX__



#define ECPT_4K_WAY 3
#define ECPT_2M_WAY 3
#define ECPT_1G_WAY 0

#define ECPT_4K_USER_WAY 3
#define ECPT_2M_USER_WAY 3
#define ECPT_1G_USER_WAY 0

#define ECPT_KERNEL_WAY (ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY)
#define ECPT_USER_WAY (ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY)

#define ECPT_TOTAL_WAY (ECPT_KERNEL_WAY + ECPT_USER_WAY)
/* ECPT_TOTAL_WAY <= ECPT_MAX_WAY*/
/* gcc 11.3 only supports cr up to cr15. 
	among them, cr0, cr2, cr4, cr8 are used for other purppose in AMD64
*/

#define ECPT_MAX_WAY 24

#define ECPT_REHASH_WAY 3
#define ECPT_SCALE_FACTOR 4
#define ECPT_REHASH_GRANULARITY (16)
#define ECPT_REHASH_N_BATCH (1)

#define IS_REHASH_WAY(w) ((w) >= ECPT_TOTAL_WAY && (w) < ECPT_TOTAL_WAY + ECPT_REHASH_WAY)

#if ECPT_MAX_WAY < ECPT_TOTAL_WAY + ECPT_REHASH_WAY 
	#error "ECPT_MAX_WAY exceeded"
#endif

#define MSR_ECPT_START             	0x00004000
#define MSR_ECPT_END               	(MSR_ECPT_START + ECPT_MAX_WAY)
#define WAY_TO_ECPT_MSR(w) 			(MSR_ECPT_START + (w))

#define MSR_ECPT_REHASH_START         	0x00004020
#define MSR_ECPT_REHASH_END           	(MSR_ECPT_REHASH_START + ECPT_MAX_WAY)
#define WAY_TO_ECPT_REHASH_MSR(w) 		(MSR_ECPT_REHASH_START + (w))

#define MSR_KERNEL_START           0x00004100

#if ECPT_4K_USER_WAY > 0
	#define ECPT_4K_PER_WAY_ENTRIES (512 * 8 * 4)
	
	/* TODO: this is more than what we need. shifted by 3 is divided by 8 */
	#define ECPT_4K_PER_WAY_REHASH_THRESH_SHIFT 1
	#define GET_ECPT_4K_REHASH_THRESH(cr) \
		(GET_HPT_SIZE(cr) * 6 / 10)
#else
	#define ECPT_4K_PER_WAY_ENTRIES (0)
#endif

#if ECPT_2M_USER_WAY > 0
	#define ECPT_2M_PER_WAY_ENTRIES (512 * 8 * 4)
	#define ECPT_2M_PER_WAY_REHASH_THRESH_SHIFT 2
	#define GET_ECPT_2M_REHASH_THRESH(cr) \
		(GET_HPT_SIZE(cr) * 6 / 10)
#else
	#define ECPT_2M_PER_WAY_ENTRIES (0)
#endif

#if ECPT_1G_USER_WAY > 0
	#define ECPT_1G_PER_WAY_ENTRIES (512 * 8)
#else
	#define ECPT_1G_PER_WAY_ENTRIES (0)
#endif


#define EPCT_NUM_ENTRY_TO_NR_PAGES(num) ((num * sizeof(ecpt_entry_t)) >> PAGE_SHIFT)

/* eager = 1, allocate such when map_desc_alloc is called, ow. wait until it is needed */
#define ECPT_4K_WAY_EAGER 1
#define ECPT_2M_WAY_EAGER 0
#define ECPT_1G_WAY_EAGER 0

#define ECPT_WAY_TO_CR_SEQ 3,1,5,6,7,9,10,11,12,13,14,15


#define EARLY_PF_MAX 16
#endif /* _ASM_X86_ECPT_DEFS_H */