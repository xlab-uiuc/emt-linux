/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_BOOT_H
#define _ASM_X86_BOOT_H


#include <asm/pgtable_types.h>
#include <uapi/asm/boot.h>

/* Physical address where kernel should be loaded. */
#define LOAD_PHYSICAL_ADDR ((CONFIG_PHYSICAL_START \
				+ (CONFIG_PHYSICAL_ALIGN - 1)) \
				& ~(CONFIG_PHYSICAL_ALIGN - 1))

/* Minimum kernel alignment, as a power of two */
#ifdef CONFIG_X86_64
# define MIN_KERNEL_ALIGN_LG2	PMD_SHIFT
#else
# define MIN_KERNEL_ALIGN_LG2	(PAGE_SHIFT + THREAD_SIZE_ORDER)
#endif
#define MIN_KERNEL_ALIGN	(_AC(1, UL) << MIN_KERNEL_ALIGN_LG2)

#if (CONFIG_PHYSICAL_ALIGN & (CONFIG_PHYSICAL_ALIGN-1)) || \
	(CONFIG_PHYSICAL_ALIGN < MIN_KERNEL_ALIGN)
# error "Invalid value for CONFIG_PHYSICAL_ALIGN"
#endif

#if defined(CONFIG_KERNEL_BZIP2)
# define BOOT_HEAP_SIZE		0x400000
#elif defined(CONFIG_KERNEL_ZSTD)
/*
 * Zstd needs to allocate the ZSTD_DCtx in order to decompress the kernel.
 * The ZSTD_DCtx is ~160KB, so set the heap size to 192KB because it is a
 * round number and to allow some slack.
 */
# define BOOT_HEAP_SIZE		 0x30000
#else
# define BOOT_HEAP_SIZE		 0x10000
#endif

#ifdef CONFIG_X86_64

#define BOOT_STACK_SIZE	0x4000


#ifdef CONFIG_X86_64_ECPT
	/**
	 * Init with 1GB hash page table
	 * 	4096 bytes can allocate 512 entries.
	 * 	Sufficient for 4 entries (4GB init memory)
	 */
	// #define BOOT_INIT_PGT_SIZE	4096
	// #define BOOT_PGT_SIZE BOOT_INIT_PGT_SIZE

	// #define BOOT_HPT_ENTRIES 512
	// #define BOOT_HPT_OFFSET_MASK (BOOT_HPT_ENTRIES - 1) /* the trailing 9 bits*/
	
	// #define BOOT_PAGE_SHIFT 30
	// #define BOOT_PAGE_SIZE (1 << BOOT_PAGE_SHIFT)
	// #define BOOT_ADDR_TO_OFFSET(x)   ((x) &   (BOOT_PAGE_SIZE - 1))		
	// #define BOOT_ADDR_TO_PAGE_NUM (((x) >> BOOT_PAGE_SHIFT) << BOOT_PAGE_SHIFT)	/* everything in front of bit 29 */

	#define BOOT_HPT_ENTRIES (512 * 8)
	#define BOOT_HPT_ENTRY_SIZE (8)
    #define BOOT_INIT_PGT_SIZE (BOOT_HPT_ENTRIES * BOOT_HPT_ENTRY_SIZE)
    #define BOOT_PGT_SIZE BOOT_INIT_PGT_SIZE
    #define BOOT_HPT_OFFSET_MASK (BOOT_HPT_ENTRIES - 1)         /* the trailing 12 */

	#define HPT_SIZE_MASK (0xfff)      /* 16 * cr3[0:11] for number of entries */
	#define HPT_SIZE_HIDDEN_BITS (4)    
	#define BOOT_CR3_NUM_ENTRIES_VAL (BOOT_HPT_ENTRIES >> HPT_SIZE_HIDDEN_BITS)		/* 16 * cr3[0:11] for number of entries */
    #define BOOT_HPT_ENTRIES_MAX (HPT_SIZE_MASK << HPT_SIZE_HIDDEN_BITS)
	
	#define BOOT_PAGE_SHIFT (21)
    #define BOOT_PAGE_SIZE (1 << BOOT_PAGE_SHIFT)
#else

	# define BOOT_INIT_PGT_SIZE	(6*4096)


	# ifdef CONFIG_RANDOMIZE_BASE
	/*
	* Assuming all cross the 512GB boundary:
	* 1 page for level4
	* (2+2)*4 pages for kernel, param, cmd_line, and randomized kernel
	* 2 pages for first 2M (video RAM: CONFIG_X86_VERBOSE_BOOTUP).
	* Total is 19 pages.
	*/
	#  ifdef CONFIG_X86_VERBOSE_BOOTUP
	#   define BOOT_PGT_SIZE	(19*4096)
	#  else /* !CONFIG_X86_VERBOSE_BOOTUP */
	#   define BOOT_PGT_SIZE	(17*4096)
	#  endif
	# else /* !CONFIG_RANDOMIZE_BASE */
	#  define BOOT_PGT_SIZE		BOOT_INIT_PGT_SIZE
	# endif

#endif


#else /* !CONFIG_X86_64 */
# define BOOT_STACK_SIZE	0x1000
#endif

#endif /* _ASM_X86_BOOT_H */
