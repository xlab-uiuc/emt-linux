# SPDX-License-Identifier: GPL-2.0
# Kernel does not boot with instrumentation of tlb.c and mem_encrypt*.c
KCOV_INSTRUMENT_tlb.o			:= n
KCOV_INSTRUMENT_mem_encrypt.o		:= n
KCOV_INSTRUMENT_mem_encrypt_identity.o	:= n

KASAN_SANITIZE_mem_encrypt.o		:= n
KASAN_SANITIZE_mem_encrypt_identity.o	:= n

# Disable KCSAN entirely, because otherwise we get warnings that some functions
# reference __initdata sections.
KCSAN_SANITIZE := n

ifdef CONFIG_FUNCTION_TRACER
CFLAGS_REMOVE_mem_encrypt.o		= -pg
CFLAGS_REMOVE_mem_encrypt_identity.o	= -pg
endif

obj-y				:=  init.o init_$(BITS).o fault.o ioremap.o extable.o mmap.o \
				    pgtable.o physaddr.o setup_nx.o tlb.o cpu_entry_area.o maccess.o

obj-y				+= pat/

# Make sure __phys_addr has no stackprotector
CFLAGS_physaddr.o		:= -fno-stack-protector
CFLAGS_setup_nx.o		:= -fno-stack-protector
CFLAGS_mem_encrypt_identity.o	:= -fno-stack-protector

CFLAGS_fault.o := -I $(srctree)/$(src)/../include/asm/trace

obj-$(CONFIG_X86_32)		+= pgtable_32.o iomap_32.o

obj-$(CONFIG_HUGETLB_PAGE)	+= hugetlbpage.o
obj-$(CONFIG_PTDUMP_CORE)	+= dump_pagetables.o
obj-$(CONFIG_PTDUMP_DEBUGFS)	+= debug_pagetables.o

obj-$(CONFIG_HIGHMEM)		+= highmem_32.o

KASAN_SANITIZE_kasan_init_$(BITS).o := n
obj-$(CONFIG_KASAN)		+= kasan_init_$(BITS).o

obj-$(CONFIG_MMIOTRACE)		+= mmiotrace.o
mmiotrace-y			:= kmmio.o pf_in.o mmio-mod.o
obj-$(CONFIG_MMIOTRACE_TEST)	+= testmmiotrace.o

obj-$(CONFIG_NUMA)		+= numa.o numa_$(BITS).o
obj-$(CONFIG_AMD_NUMA)		+= amdtopology.o
obj-$(CONFIG_ACPI_NUMA)		+= srat.o
obj-$(CONFIG_NUMA_EMU)		+= numa_emulation.o

obj-$(CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS)	+= pkeys.o
obj-$(CONFIG_RANDOMIZE_MEMORY)			+= kaslr.o
obj-$(CONFIG_PAGE_TABLE_ISOLATION)		+= pti.o

obj-$(CONFIG_AMD_MEM_ENCRYPT)	+= mem_encrypt.o
obj-$(CONFIG_AMD_MEM_ENCRYPT)	+= mem_encrypt_identity.o
obj-$(CONFIG_AMD_MEM_ENCRYPT)	+= mem_encrypt_boot.o

obj-$(CONFIG_X86_64_ECPT)	+= ECPT.o
obj-$(CONFIG_X86_64_ECPT)	+= ecpt_huge_defs.o
obj-$(CONFIG_X86_64_ECPT)	+= ECPT_CWT.o
obj-$(CONFIG_PGTABLE_OP_GENERALIZABLE)	+= pgtable_enhanced.o
obj-$(CONFIG_X86_64_ECPT_MURMUR64)	+= ecpt_murmur64.o
obj-$(CONFIG_X86_64_ECPT_CRC64)	+= ecpt_crc.o

hostprogs		:= ecpt_gen_crc64table
clean-files		:= ecpt_crc64table.h
clean-files		+= ecpt_gen_crc64table

$(obj)/ecpt_crc.o: $(obj)/ecpt_crc64table.h

cmd_ecpt_crc64 = $< > $@

$(obj)/ecpt_crc64table.h: $(obj)/ecpt_gen_crc64table
	$(call cmd,ecpt_crc64)

CFLAGS_init_$(BITS).o := -DDEBUG
