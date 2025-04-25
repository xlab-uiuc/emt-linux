#include "asm/bug.h"
#include "linux/compiler_types.h"
#include "linux/printk.h"
#include <asm/ECPT.h>
#include <asm/ECPT_CWT.h>
#include <linux/types.h>
#include <asm/early_debug.h>

#include "ECPT_internal_helper.h"
#define IS_KERNEL_MAP(vaddr) (vaddr >= __PAGE_OFFSET)

#define ECPT_CWT_verbose(fmt, ...)
// #define ECPT_CWT_verbose(fmt, ...) printk(KERN_INFO "%s:%d %s " pr_fmt(fmt), __FILE__ , __LINE__ , __func__, ##__VA_ARGS__)

// #define DEBUG_CHECK_CWT_DETAIL

#ifdef DEBUG_CHECK_CWT_DETAIL
static void check_cwt_detail(ECPT_desc_t *ecpt, uint32_t way_start, uint32_t way_end, bool print_entry);
static uint32_t check_cwt_detail_way (ECPT_desc_t *ecpt, uint32_t way);
#endif

static inline uint64_t cwt_entry_get_vpn(cwt_entry_t * e) 
{
	uint64_t vpn = 0;
	uint16_t i = 0;
	cwt_header_t * header;
	for (; i < CWT_N_BYTES_FOR_VPN; i++) {
		header = &e->sec_headers[i];
		vpn |= (header->partial_vpn << (i * CWT_VPN_BITS_PER_BYTE));
	}
	return vpn;
}

static inline void cwt_entry_set_vpn(cwt_entry_t * e, uint64_t VPN) 
{
	uint16_t i = 0;
	cwt_header_t * header;
	for (; i < CWT_N_BYTES_FOR_VPN; i++) {
		header = &e->sec_headers[i];
		header->partial_vpn = CWT_GET_PARTIAL_VPN(VPN, i);
	}
}

static inline void cwt_entry_clear_vpn(cwt_entry_t * e) 
{
	cwt_entry_set_vpn(e, 0);
}

static inline uint64_t cwt_get_vpn(uint64_t vaddr, CWTGranularity cwt_gran) {
	if (cwt_gran == CWT_2MB) {
		return VADDR_TO_CWT_VPN_2MB(vaddr);
	} else if (cwt_gran == CWT_1GB) {
		return VADDR_TO_CWT_VPN_1GB(vaddr);
	} else {
		WARN(1, "cwt_get_vpn doesn't support cwt_gran=%d", cwt_gran);
		return 0;
	}
}

static inline int cwt_entry_match_vpn(cwt_entry_t *entry, uint64_t vpn)
{
	return cwt_entry_get_vpn(entry) == vpn;
}

static inline int cwt_header_empty_data(cwt_header_t * header) 
{
	return GET_CWT_HEADER_DATA(header->byte) == 0;
}

static noinline int cwt_empty_entry(cwt_entry_t *entry)
{
	uint16_t i = 0;
	uint16_t step = sizeof(uint64_t) / sizeof(cwt_header_t);
	uint64_t * chunk_ptr;
	for (; i < CWT_N_SECTION_HEADERS; i += step) {
		chunk_ptr = (uint64_t *) &entry->sec_headers[i];
		if (*chunk_ptr != 0) {
			return 0;
		}
	}
	return 1;
}


static inline uint16_t cwt_entry_get_valid_header_num(cwt_entry_t *e)
{
	uint32_t valid_num = 0;
	uint16_t i = 0;
	cwt_header_t * header;
	for (; i < CWT_N_SECTION_VALID_NUM_LEN; i++) {
		header = &e->sec_headers[i + CWT_N_SECTION_VALID_NUM_START];
		valid_num |= (header->partial_vpn << (i * CWT_VALID_NUM_BITS_PER_BYTE));
	}
	return valid_num;
}

static inline void cwt_entry_set_valid_header_num(cwt_entry_t *e, uint16_t num)
{
	uint16_t i = 0;
	cwt_header_t * header;

	WARN(num > CWT_N_SECTION_HEADERS, "invalid num =%d", num);

	for (; i < CWT_N_SECTION_VALID_NUM_LEN; i++) {
		header = &e->sec_headers[i + CWT_N_SECTION_VALID_NUM_START];
		header->partial_vpn = CWT_GET_PARTIAL_VALID_NUM(num, i);
	}
}

static inline uint32_t cwt_entry_inc_valid_header_num(cwt_entry_t *e)
{
	uint32_t num = cwt_entry_get_valid_header_num(e) + 1;
	cwt_entry_set_valid_header_num(e, num);
	return num;
}

static inline uint32_t cwt_entry_dec_valid_header_num(cwt_entry_t *e)
{
	uint32_t num = cwt_entry_get_valid_header_num(e) - 1;
	cwt_entry_set_valid_header_num(e, num);
	return num;
}

static inline int cwt_entry_empty_vpn(cwt_entry_t *e)
{
	return cwt_entry_get_valid_header_num(e) == 0 &&
	       cwt_entry_get_vpn(e) == 0;
}

static inline uint16_t cwt_entry_count_valid_header_num(cwt_entry_t *e)
{
	uint16_t i = 0;
	uint16_t n_empty_headers = 0;
	cwt_header_t * header;
	for (; i < CWT_N_SECTION_HEADERS; i++) {
		header = &e->sec_headers[i];
		if (!cwt_header_empty_data(header)) {
			n_empty_headers++;
		}
	}
	return n_empty_headers;
}


void print_cwt(ECPT_desc_t *ecpt, bool kernel_table_detail,
		bool user_table_detail, bool print_entry)
{
	/* TODO: implement print_cwt function */
}

#define REP0(X)
#define REP1(X) X
#define REP2(X) REP1(X) X
#define REP3(X) REP2(X) X
#define REP4(X) REP3(X) X
#define REP5(X) REP4(X) X
#define REP6(X) REP5(X) X
#define REP7(X) REP6(X) X
#define REP8(X) REP7(X) X
#define REP9(X) REP8(X) X
#define REP10(X) REP9(X) X

#define HEADER_0(e) (e)[0].byte
#define HEADER_1(e) HEADER_0(e), (e)[1].byte
#define HEADER_2(e) HEADER_1(e), (e)[2].byte
#define HEADER_3(e) HEADER_2(e), (e)[3].byte
#define HEADER_4(e) HEADER_3(e), (e)[4].byte
#define HEADER_5(e) HEADER_4(e), (e)[5].byte
#define HEADER_6(e) HEADER_5(e), (e)[6].byte
#define HEADER_7(e) HEADER_6(e), (e)[7].byte

#define CWT_HEADER_FMT REP8("%x ")
#define HEADER_ARRAY_PRINT(e) HEADER_7(e)

static inline void print_cwt_entry_helper(cwt_entry_t * e)
{
	uint16_t i = 0, ii = 0;
	uint16_t group = 8;
	bool all_empty = true;
	cwt_header_t *header;
	for (; i < CWT_N_SECTION_HEADERS; i += group) {
		all_empty = true;
		for (ii = 0; ii < group; ii++) {
			header = &e->sec_headers[i + ii];
			all_empty = all_empty && cwt_header_empty_data(header);
		}

		if (!all_empty) {
			header = &e->sec_headers[i];
			ECPT_CWT_verbose("i=%d " CWT_HEADER_FMT "\n", i, HEADER_ARRAY_PRINT(header));
		}
	}
}

#define PRINT_CWT_ENTRY_BASE(e, func) \
	do { \
    	func("entry at %llx  {.vpn=%llx valid_num=%x}\n",\
			(uint64_t) e, cwt_entry_get_vpn(e), cwt_entry_get_valid_header_num(e) \
		); \
		print_cwt_entry_helper(e); \
  	} while (0)

#define PRINT_CWT_ENTRY_INFO(e) PRINT_CWT_ENTRY_BASE(e, ECPT_CWT_verbose)

static int cwt_entry_do_merge_1GB(cwt_header_t *dest_header, cwt_header_t *src_header)
{	
	if (dest_header->present_1GB && src_header->present_1GB) {
		if (dest_header->way_in_ecpt != src_header->way_in_ecpt) {
			WARN(1, "inconsistent way_in_ecpt\n");
			return -1;
		}
	} else if (!dest_header->present_1GB && src_header->present_1GB) {
		dest_header->way_in_ecpt = src_header->way_in_ecpt;
	} else if (dest_header->present_1GB && !src_header->present_1GB) {
		/* nothing to do */	
	} else {
		/* nothing to do */	
	}

	dest_header->present_1GB = dest_header->present_1GB || src_header->present_1GB;
	dest_header->present_2MB = dest_header->present_2MB || src_header->present_2MB;
	dest_header->present_4KB = dest_header->present_4KB || src_header->present_4KB;

	return 0;
}

static int cwt_entry_do_merge_2MB(cwt_header_t *dest_header, cwt_header_t *src_header)
{
	pr_info_verbose("cwt_entry_do_merge_2MB: dest_header=%x 1G=%d 2M=%d 4K=%d way_in_ecpt=%d\n",
		dest_header->byte, dest_header->present_1GB, dest_header->present_2MB, dest_header->present_4KB, dest_header->way_in_ecpt);
	pr_info_verbose("cwt_entry_do_merge_2MB: src_header=%x 1G=%d 2M=%d 4K=%d way_in_ecpt=%d\n",
		src_header->byte, src_header->present_1GB, src_header->present_2MB, src_header->present_4KB, src_header->way_in_ecpt);

	if (dest_header->present_2MB && src_header->present_2MB) {
		/* This should also update since kick can happen */
		dest_header->way_in_ecpt = src_header->way_in_ecpt;
	} else if (!dest_header->present_2MB && src_header->present_2MB) {
		dest_header->way_in_ecpt = src_header->way_in_ecpt;
	} else if (dest_header->present_2MB && !src_header->present_2MB) {
		/* nothing to do */	
	} else {
		/* nothing to do */	
	}

	dest_header->present_2MB = dest_header->present_2MB || src_header->present_2MB;
	dest_header->present_4KB = dest_header->present_4KB || src_header->present_4KB;
	return 0;
}

static inline uint64_t cwt_get_idx_from_vaddr(uint64_t vaddr, CWTGranularity cwt_gran)
{
	if (cwt_gran == CWT_1GB) {
		return VADDR_TO_CWT_1G_HEADER_IDX(vaddr);
	} else if (cwt_gran == CWT_2MB) {
		return VADDR_TO_CWT_2M_HEADER_IDX(vaddr);
	} else {
		BUG();
		return -1;
	}
}

/* 
	Update header of destination entry corresponding to vaddr
 */
static int cwt_entry_update_header(cwt_entry_t *dest, cwt_header_t src_header,
				   uint64_t vaddr, CWTGranularity cwt_gran)
{
	unsigned int idx = 0;
	cwt_header_t *dest_header;
	int src_empty, dest_empty;
	int merge_err = 0;

	if (cwt_entry_empty_vpn(dest)) {
		/**
		 * set destination vpn if empty
		 */
		uint64_t VPN = cwt_get_vpn(vaddr, cwt_gran);
		cwt_entry_set_vpn(dest, VPN);
	}

	idx = cwt_get_idx_from_vaddr(vaddr, cwt_gran);
	ECPT_CWT_verbose("idx=%d\n", idx);
	dest_header = &dest->sec_headers[idx];
	
	dest_empty = cwt_header_empty_data(dest_header);
	src_empty = cwt_header_empty_data(&src_header);
		
	if (!src_empty) {
		if (cwt_gran == CWT_2MB) {
			merge_err = cwt_entry_do_merge_2MB(dest_header, &src_header);
		} else if (cwt_gran == CWT_1GB) {
			merge_err = cwt_entry_do_merge_1GB(dest_header, &src_header);
		} else {
			WARN(1, "unacceptable cwt_gran=%d\n", cwt_gran);
			merge_err = -1;
		}
			
		WARN(merge_err, "Error merge result\n");
		if (merge_err) {
			return -1;
		} else {
			if (dest_empty){
				cwt_entry_inc_valid_header_num(dest);
			}
		}
	}
	return 0;
}

/* clear mask and return if data section after cleared is 0 */
static int cwt_header_do_clear(cwt_header_t * target, cwt_header_t mask)
{
	uint8_t target_data = GET_CWT_HEADER_DATA(target->byte);
	uint8_t target_partial = target->partial_vpn;
	uint8_t mask_data = GET_CWT_HEADER_DATA(mask.byte);
	uint8_t data_cleared = target_data & (~mask_data);
	
	/* This byte doesn't involve partial_vpn information */
	target->byte = data_cleared;
	target->partial_vpn = target_partial;

	return target_data != 0 && data_cleared == 0;
}

/* return true if the entire cwt entry is cleared */
static int cwt_entry_do_clear(cwt_entry_t *dest, cwt_header_t mask, uint64_t vaddr, CWTGranularity cwt_gran) 
{
	uint32_t idx = 0, header_cleared = 0, valid_num = 0;
	cwt_header_t * header;

	idx = cwt_get_idx_from_vaddr(vaddr, cwt_gran);

	header = &dest->sec_headers[idx];
	header_cleared = cwt_header_do_clear(header, mask);

	if (header_cleared) {
		valid_num = cwt_entry_dec_valid_header_num(dest);
		if (valid_num == 0) {
			cwt_entry_clear_vpn(dest);
			return 1;
		}
	}

	return 0;
}

static inline void cwt_entry_set_header(cwt_entry_t * e, cwt_header_t header, uint64_t vaddr, CWTGranularity cwt_gran) 
{
	uint32_t idx = 0;
	cwt_header_t * target_header;
	if (cwt_gran == CWT_2MB) 
	{
		idx = VADDR_TO_CWT_2M_HEADER_IDX(vaddr);
		target_header = &e->sec_headers[idx];
		cwt_entry_do_merge_2MB(target_header, &header);
	} 
	else if (cwt_gran == CWT_1GB) 
	{
		idx = VADDR_TO_CWT_1G_HEADER_IDX(vaddr);
		target_header = &e->sec_headers[idx]; 
		cwt_entry_do_merge_1GB(target_header, &header);
	} else {
		WARN(1, "cwt_get_vpn doesn't support cwt_gran=%d", cwt_gran);
	}
}

/*
 * We don't do the check at the early stage
 * since it's not easy to fix up the cwt pointer
 */
static inline void cwt_inc_occupancy_early(ECPT_desc_t *ecpt, uint32_t cwt_way)
{
	ecpt->cwt_occupied[cwt_way]++;
}

static inline void cwt_inc_occupancy(ECPT_desc_t *ecpt, uint32_t cwt_way) 
{
	ecpt->cwt_occupied[cwt_way]++;
	/*
	 * We can not just check the cwt_way only
	 * since CWT may kick entry into other ways
	 */
#ifdef DEBUG_CHECK_CWT_DETAIL
	if (cwt_way < CWT_2MB_N_WAY)
		check_cwt_detail(ecpt, 0, CWT_2MB_N_WAY, false);
	else
		check_cwt_detail(ecpt, CWT_2MB_N_WAY, CWT_TOTAL_N_WAY, false);
#endif
}

static inline void cwt_dec_occupancy(ECPT_desc_t *ecpt, uint32_t cwt_way)
{
	ecpt->cwt_occupied[cwt_way]--;
	// ECPT_info_verbose("occupied[%d]=%d\n", way, ecpt->occupied[way]);

	/*
	 * We can not just check the cwt_way only
	 * since CWT may kick entry into other ways
	 */
#ifdef DEBUG_CHECK_CWT_DETAIL
	if (cwt_way < CWT_2MB_N_WAY)
		check_cwt_detail(ecpt, 0, CWT_2MB_N_WAY, false);
	else
		check_cwt_detail(ecpt, CWT_2MB_N_WAY, CWT_TOTAL_N_WAY, false);
#endif
}

static void cwt_select_way(uint64_t vaddr, CWTGranularity cwt_gran, /* input */
		       uint32_t *way_start, uint32_t *way_end,
		       uint64_t *vpn /* output */) 
{
	*vpn = cwt_get_vpn(vaddr, cwt_gran);

	if (cwt_gran == CWT_2MB) {
		*way_start = 0;
		*way_end = CWT_2MB_N_WAY;

	} else if (cwt_gran == CWT_1GB) {
		*way_start = CWT_2MB_N_WAY;
		*way_end = CWT_2MB_N_WAY + CWT_1GB_N_WAY;

	} else {
		WARN(1, "cwt_select_way doesn't support cwt_gran=%d", cwt_gran);
	} 
}

static cwt_entry_t *cwt_search_fit_entry(ECPT_desc_t *ecpt, uint64_t vaddr,
					   bool is_insert, bool rand_way, CWTGranularity *cwt_gran,
					   enum search_entry_status *status,
					   uint32_t *way_found,
					   int early, uint64_t kernel_start, uint64_t physaddr)
{
	uint64_t size, hash, vpn, cwt;
	uint64_t rehash_ptr = 0, rehash_cr, rehash_size, rehash_hash;
	uint32_t w = 0, way_start, way_end, picked_way, w_to_hash;
	
	
	cwt_entry_t *cwt_base;
	cwt_entry_t *entry_ptr = NULL;
	
	cwt_entry_t *empty_slots[CWT_TOTAL_N_WAY];
	uint32_t empty_slots_ways[CWT_TOTAL_N_WAY];
	cwt_entry_t *evict_slots[CWT_TOTAL_N_WAY];
	uint32_t evict_slots_ways[CWT_TOTAL_N_WAY];
	uint16_t empty_i = 0, evict_i = 0, pick_i = 0;

	uint16_t is_kernel_vaddr = IS_KERNEL_MAP(vaddr);
	
	if (is_kernel_vaddr && init_mm.map_desc != ecpt) {
		WARN(1, "updating kernel cwt with user ecpt");
	}

	cwt_select_way(vaddr, *cwt_gran, /* input */
		   &way_start, &way_end, &vpn /* output */
	);
	
	if (early) {
		ecpt = (ECPT_desc_t *)fixup_pointer(ecpt, kernel_start, physaddr);
	}

	for (w = way_start; w < way_end; w++) {
		rehash_ptr = 0;
		rehash_cr = 0;
		rehash_size = 0;
		rehash_hash = 0;
		picked_way = w;

		cwt = ecpt->cwt[w];
		size = GET_HPT_SIZE(cwt);
		
		w_to_hash = w;
		if (!is_kernel_vaddr) {
			w_to_hash += CWT_KERNEL_WAY;
		}

		if (!early) {
			hash = gen_hash_64(vpn, size, w_to_hash);
		} else {
			cwt = (uint64_t)fixup_pointer((void *)cwt, kernel_start,
					     physaddr);
			hash = early_gen_hash_64(vpn, size, w_to_hash, kernel_start, physaddr);
		}

		/* TODO: fix rehash ptr */
		rehash_ptr = 0;
		
		if (hash < rehash_ptr) {
			/* not supported for resizing now */
			WARN(1, "cwt rehash not yet supported\n");

			// rehash_way = find_rehash_way(w);
			// rehash_cr = ecpt->table[rehash_way];
			// rehash_size = GET_HPT_SIZE(rehash_cr);

			// /* we use the original way's hash function now */
			// /* NOTE: we keep w as seed here because after 
			// 	we put the rehash way in place, it will be treated as way w
			//  */
			// rehash_hash = gen_hash_64(vpn, rehash_size, w);

			// ecpt_base =
			// 	(ecpt_entry_t *)GET_HPT_BASE_VIRT(rehash_cr);
			// entry_ptr = &ecpt_base[rehash_hash];

			// picked_way = rehash_way;
		} else {
			/* stay with current hash table */
			cwt_base = (cwt_entry_t *) GET_HPT_BASE_VIRT(cwt);
			entry_ptr = &cwt_base[hash];
		}
		// entry = *entry_ptr;

		if (cwt_entry_match_vpn(entry_ptr, vpn) &&
		    !cwt_empty_entry(entry_ptr)) {
				/* we consider non empty entry as matched entry */
			*status = ENTRY_MATCHED;
			*way_found = picked_way;
			return entry_ptr;
		} else if (cwt_empty_entry(entry_ptr)) {
			/* not found, but entry empty */
			empty_slots[empty_i] = entry_ptr;
			empty_slots_ways[empty_i] = picked_way;
			empty_i++;
			entry_ptr = NULL;
		} else {
			evict_slots[evict_i] = entry_ptr;
			evict_slots_ways[evict_i] = picked_way;
			evict_i++;
			entry_ptr = NULL;
		}
	}

	/**
	 *  keep gran unchanged after this.
	 * 	If cwt_gran == 4K, 2M, or 1G.
	 * 		is_insert == false, same as previous case
	 * 		is_insert == true, cwt_gran already been specified by the user
	 * */
	if (!is_insert) {
		/* not an insert but no matched entry found */
		*status = ENTRY_NOT_FOUND;
		*way_found = -1;
		return NULL;
	}

	if (empty_i > 0) {
		/* no matched entry found return a random empty entry */
		if (rand_way) {
			pick_i = get_rand_way(empty_i);
		} else {
			pick_i = 0;
		}
		
		entry_ptr = empty_slots[pick_i];
		*way_found = empty_slots_ways[pick_i];
		*status = ENTRY_EMPTY;
		return entry_ptr;
	}

	if (evict_i > 0) {
		if (rand_way) {
			pick_i = get_rand_way(evict_i);
		} else {
			pick_i = 0;
		}

		entry_ptr = evict_slots[pick_i];
		*way_found = evict_slots_ways[pick_i];
		*status = ENTRY_OCCUPIED;
		return entry_ptr;
	}
	/* nothing empty and no where to kick.*/

	entry_ptr = NULL;
	*status = ENTRY_NOT_FOUND;
	*way_found = -1;
	return entry_ptr;
}

#define puthexln(num)                                                          \
	{                                                                      \
		debug_puthex(num);                                             \
		debug_putstr(line_break);                                      \
	}

#define puthex_tabln(num)                                                      \
	{                                                                      \
		debug_putstr(tab);                                             \
		debug_puthex(num);                                             \
		debug_putstr(line_break);                                      \
	}

#define TOTAL_GRAN_CNT 2
/* The function insert entry for 2M ECPT entr  */
int early_cwt_insert(ECPT_desc_t *ecpt, uint64_t vaddr, uint16_t way_in_ecpt,
		      uint64_t kernel_start, uint64_t physaddr)
{
	uint32_t i = 0, idx = 0;
	uint64_t *ptr;
	char tab[2] = "\t";
	char line_break[2] = "\n";
	char err[11] = "Error!!!!\n";
	// char occupied_plus[11] = "occupied++";

	enum search_entry_status status = ENTRY_NOT_FOUND;
	uint32_t way_found = 0;
	cwt_entry_t * entry_ptr = NULL;
	CWTGranularity cwt_gran;
	CWTGranularity grans[TOTAL_GRAN_CNT] = {CWT_1GB, CWT_2MB};
	ECPT_desc_t * ecpt_fixed = (ECPT_desc_t *)fixup_pointer(ecpt, kernel_start, physaddr);
	
	cwt_header_t header_PUD, header_PMD;
	header_PMD.byte = 0;
	header_PMD.present_2MB = 1;
	header_PMD.way_in_ecpt = way_in_ecpt;

	header_PUD.byte = 0;
	header_PUD.present_2MB = 1;

	for (idx = 0; idx < TOTAL_GRAN_CNT; idx++) {
		cwt_gran = grans[idx];
		entry_ptr = cwt_search_fit_entry(ecpt, vaddr, 1, 0,
	 		&cwt_gran, &status, &way_found, 1,
			     kernel_start, physaddr);

		if (status == ENTRY_EMPTY || status == ENTRY_MATCHED) {
			/* match or empty entry we can just insert */
			if (cwt_gran == CWT_1GB) {
				cwt_entry_update_header(entry_ptr, header_PUD, vaddr, cwt_gran);
			} else {
				cwt_entry_update_header(entry_ptr, header_PMD, vaddr, cwt_gran);
			}
			puthex_tabln((uint64_t)entry_ptr);
			ptr = (uint64_t *)entry_ptr;
			for (i = 0; i * sizeof(uint64_t) < sizeof(ecpt_entry_t); i++) {
				puthex_tabln(ptr[i]);
			}

			/* TODO: track CWT occupancy */
			if (status == ENTRY_EMPTY) {
				cwt_inc_occupancy_early(ecpt_fixed, way_found);
			}
		} else {
			/* should not be here */
			debug_putstr(err);
			BUG();
		}
	}
	
	return 0;
}

static int cwt_insert(ECPT_desc_t *ecpt, uint64_t vaddr, cwt_header_t header, CWTGranularity cwt_gran)
{
	uint64_t vpn;
	uint32_t way_start = 0, way_end = 0, entry_way = -1;
	
	cwt_entry_t *entry_ptr;
	enum search_entry_status status = ENTRY_NOT_FOUND;

	pr_info_verbose(
		"cwt_insert: ecpt at %llx vaddr=%llx header=%x cwt_gran=%d 1G=%d 2M=%d 4K=%d way_in_ecpt=%d\n",
		(uint64_t)ecpt, vaddr, header.byte, cwt_gran,
		header.present_1GB, header.present_2MB, header.present_4KB,
		header.way_in_ecpt);

	/* calculate PPN */
	cwt_select_way(vaddr, cwt_gran, /* input */
		   &way_start, &way_end, &vpn /* output */
	);

	entry_ptr = cwt_search_fit_entry(ecpt, vaddr, 1 /* is_insert */, 1 /* rand_way */, &cwt_gran,
					  &status, &entry_way, 
					  0, 0, 0 
					  /* non early option no need for kernel_start and physaddr */);
	
	if (status == ENTRY_EMPTY || status == ENTRY_MATCHED) {
		/* match or empty entry we can just insert */
		WARN(entry_ptr == NULL,
		     "Invalid entry_ptr=%llx returned from ecpt_search_fit_entry\n",
		     (uint64_t)entry_ptr);
		cwt_entry_update_header(entry_ptr, header, vaddr, cwt_gran);
		
		PRINT_CWT_ENTRY_INFO(entry_ptr);
		
		/* TODO: track CWT occupancy */
		if (status == ENTRY_EMPTY) {
			cwt_inc_occupancy(ecpt, entry_way);
		}
	} else if (status == ENTRY_OCCUPIED || status == ENTRY_NOT_FOUND) {
		WARN(1, "cwt_kick_to_insert needs rework\n");
		// ret = kick_to_insert(ecpt, &entry, way_start, way_end);
		// if (ret) {
		// 	WARN(1,
		// 	     KERN_WARNING
		// 	     "Hash Collision unresolved:\n ecpt at %llx vaddr=%llx paddr=%llx prot=%lx gran=%d\n",
		// 	     (uint64_t)ecpt, vaddr, paddr, prot.pgprot, gran);
		// 	print_ecpt(ecpt, 0 /* kernel */, 1 /* user */,
		// 		   1 /* print_entry */);
		// 	return ret;
		// }
		return -1;
	} else {
		/* should not be here */
		BUG();
	}

	return 0;
}

static int cwt_insert_4K_ECPT(ECPT_desc_t *ecpt, uint64_t vaddr) 
{
	cwt_header_t header;
	int res_2M, res_1G;
	header.byte = 0;
	header.present_4KB = 1;

	/* insert into PUD-CWT */
	res_1G = cwt_insert(ecpt, vaddr, header, CWT_1GB);
	WARN(res_1G, "PUD-CWT insertion failure for vaddr=%llx\n", vaddr);

	/* insert into PMD-CWT */
	res_2M = cwt_insert(ecpt, vaddr, header, CWT_2MB);
	WARN(res_2M, "PMD-CWT insertion failure for vaddr=%llx\n", vaddr);

	return res_1G && res_2M;
}

static int cwt_insert_2M_ECPT(ECPT_desc_t *ecpt, uint64_t vaddr, uint32_t way) 
{
	cwt_header_t header;
	int res_2M, res_1G;

	header.byte = 0;
	header.present_2MB = 1;
	
	/* insert into PUD-CWT */
	res_1G = cwt_insert(ecpt, vaddr, header, CWT_1GB);
	WARN(res_1G, "PUD-CWT insertion failure for vaddr=%llx\n", vaddr);

	WARN(way >= ECPT_2M_USER_WAY, "illegal way=%d\n", way);
	header.way_in_ecpt = way;
	/* insert into PMD-CWT */
	res_2M = cwt_insert(ecpt, vaddr, header, CWT_2MB);
	WARN(res_2M, "PMD-CWT insertion failure for vaddr=%llx\n", vaddr);

	return res_1G && res_2M;
}

static int cwt_insert_1G_ECPT(ECPT_desc_t *ecpt, uint64_t vaddr, uint32_t way) 
{
	cwt_header_t header;
	int res_1G = 0;

	header.byte = 0;
	header.present_1GB = 1;
	
	WARN(way >= ECPT_1G_USER_WAY, "illegal way=%d\n", way);
	header.way_in_ecpt = way;

	/* insert into PUD-CWT */
	res_1G = cwt_insert(ecpt, vaddr, header, CWT_1GB);
	WARN(res_1G, "PUD-CWT insertion failure for vaddr=%llx\n", vaddr);

	return res_1G ;
}

/* 
	Note: gran here is the granularity of ECPT entry
	gran in cwt_insert refers to CWT-PMD 
 */
int cwt_insert_with_gran(ECPT_desc_t *ecpt, uint64_t vaddr, uint32_t rel_way, Granularity gran) 
{	
	int res = 0;
	ECPT_CWT_verbose("gran=%d vaddr=%llx rel_way=%x\n", gran, vaddr, rel_way);
	
	if (gran == page_4KB) {
		res = cwt_insert_4K_ECPT(ecpt, vaddr);
	} else if (gran == page_2MB) {
		res = cwt_insert_2M_ECPT(ecpt, vaddr, rel_way);
	} else if (gran == page_1GB) {
		res = cwt_insert_1G_ECPT(ecpt, vaddr, rel_way);
	} else {
		BUG();
	}
	return res;
}

/**
	Clear bits specified in header
 */
static int cwt_clear_bits(ECPT_desc_t *ecpt, uint64_t vaddr, cwt_header_t header, CWTGranularity cwt_gran, int early)
{
	uint32_t entry_way = -1, prev_valid_cnt = 0;
	int all_cleared = 0;

	cwt_entry_t *entry_ptr;
	enum search_entry_status status = ENTRY_NOT_FOUND;
	int i = 0;
	uint64_t *ptr;


	if (!early) {
		ECPT_CWT_verbose(
			"ecpt at %llx vaddr=%llx header=%x cwt_gran=%d\n",
			(uint64_t)ecpt, vaddr, header.byte , cwt_gran);
	} else {
		DEBUG_VAR(vaddr);
	}
	

	/* calculate */
	// cwt_select_way(vaddr, cwt_gran, /* input */
	// 	   &way_start, &way_end, &vpn /* output */
	// );

	entry_ptr = cwt_search_fit_entry(ecpt, vaddr, 1 /* is_insert */,
					 1 /* rand_way */, &cwt_gran, &status,
					 &entry_way, 0, 0, 0 
					  /* non early option no need for kernel_start and physaddr */);
	
	if (status == ENTRY_MATCHED) {
		/* entry found clear entry */

		prev_valid_cnt = cwt_entry_get_valid_header_num(entry_ptr);
		all_cleared = cwt_entry_do_clear(entry_ptr, header, vaddr, cwt_gran);
	
		if (!early) {
			PRINT_CWT_ENTRY_INFO(entry_ptr);
		} else {
			ptr = (uint64_t *)entry_ptr;
			DEBUG_VAR((uint64_t) entry_ptr);
			for (i = 0; i * sizeof(uint64_t) < sizeof(ecpt_entry_t); i++) {
				DEBUG_VAR(ptr[i]);
			}
		}

		/* valid_cnt decrement from 1 -> 0 */
		if (prev_valid_cnt > 0 && all_cleared) {
			cwt_dec_occupancy(ecpt, entry_way);
		}
	} else {
		WARN(1, "Attempt to clear not existed CWT entry\n");
		return -1;
	}

	return 0;
}

static int cwt_clear_4K_ECPT(ECPT_desc_t *ecpt, uint64_t vaddr) 
{
	cwt_header_t header;
	int res_2M, res_1G;
	int early = 0;

	header.byte = 0;
	header.present_4KB = 1;

	/* insert into PUD-CWT */
	res_1G = cwt_clear_bits(ecpt, vaddr, header, CWT_1GB, early);
	WARN(res_1G, "PUD-CWT insertion failure for vaddr=%llx\n", vaddr);

	/* insert into PMD-CWT */
	res_2M = cwt_clear_bits(ecpt, vaddr, header, CWT_2MB, early);
	WARN(res_2M, "PMD-CWT insertion failure for vaddr=%llx\n", vaddr);

	return res_1G || res_2M;
}

static int cwt_clear_2M_ECPT(ECPT_desc_t *ecpt, uint64_t vaddr, int early) 
{
	cwt_header_t header;
	int res_2M;
	

	header.byte = 0;
	header.present_2MB = 1;
	
	/* insert into PUD-CWT */
	/* This is very tricky for CWT-PUD. 
		one cluster of 2M ecpt entries been cleared doesn't mean CWT-PUD has to be cleared */
	// res_1G = cwt_clear_bits(ecpt, vaddr, header, CWT_1GB, early);
	// WARN(res_1G, "PUD-CWT clear failure for vaddr=%llx\n", vaddr);

	/* way_in_ecpt would be 11 in binary. Clear those fields */
	header.way_in_ecpt = 0x3;
	/* insert into PMD-CWT */
	res_2M = cwt_clear_bits(ecpt, vaddr, header, CWT_2MB, early);
	WARN(res_2M, "PMD-CWT clear failure for vaddr=%llx\n", vaddr);

	return res_2M;
}

static int cwt_clear_1G_ECPT(ECPT_desc_t *ecpt, uint64_t vaddr) 
{
	cwt_header_t header;
	int res_1G;
	int early = 0;

	header.byte = 0;
	header.present_1GB = 1;
	/* way_in_ecpt would be 11 in binary. Clear those fields */
	header.way_in_ecpt = 0x3;

	/* insert into PUD-CWT */
	res_1G = cwt_clear_bits(ecpt, vaddr, header, CWT_1GB, early);
	WARN(res_1G, "PUD-CWT clear failure for vaddr=%llx\n", vaddr);

	return res_1G;
}

int cwt_clear_with_gran(ECPT_desc_t *ecpt, uint64_t vaddr, Granularity gran)
{
	int res = 0;
	if (gran == page_4KB) {
		/* Right now, not sure with page_4KB  */
		// res = cwt_clear_4K_ECPT(ecpt, vaddr);
	} else if (gran == page_2MB) {
		res = cwt_clear_2M_ECPT(ecpt, vaddr, 0);
	} else if (gran == page_1GB) {
		res = cwt_clear_1G_ECPT(ecpt, vaddr);
	} else {
		BUG();
	}

	return res;
}

int cwt_clear_2M_early(ECPT_desc_t *ecpt, uint64_t vaddr)
{
	return cwt_clear_2M_ECPT(ecpt, vaddr, 1);
}

static inline uint64_t alloc_cwt_2M_way_default(void)
{	
	uint64_t cr;
	WARN(sizeof(cwt_entry_t) != sizeof(ecpt_entry_t), 
		"may not use default ECPT allocator!");
	cr = alloc_way_default(CWT_2MB_WAY_N_ENTRIES);
	WARN(!cr, "cannot allocate %x entries total size=%lx\n",
	     ECPT_4K_PER_WAY_ENTRIES,
	     ECPT_4K_PER_WAY_ENTRIES * sizeof(ecpt_entry_t));
	return cr;
}

static inline uint64_t alloc_cwt_1G_way_default(void)
{
	uint64_t cr;
	WARN(sizeof(cwt_entry_t) != sizeof(ecpt_entry_t), 
		"may not use default ECPT allocator!");
	cr = alloc_way_default(CWT_1GB_WAY_N_ENTRIES);
	WARN(!cr, "cannot allocate %x entries total size=%lx\n",
	     ECPT_4K_PER_WAY_ENTRIES,
	     ECPT_4K_PER_WAY_ENTRIES * sizeof(ecpt_entry_t));
	return cr;
}

/* TODO: potentially we can allocate these ways lazily */
int ecpt_cwt_alloc(struct mm_struct *mm)
{
	uint16_t way = 0;
	ECPT_desc_t *desc = mm->map_desc;

	for (; way < CWT_TOTAL_N_WAY; way++) {
		if (way < CWT_2MB_N_WAY) {
			desc->cwt[way] = alloc_cwt_2M_way_default();
		} else {
			desc->cwt[way] = alloc_cwt_1G_way_default();
		}

		add_pgtable_bytes(mm, desc->cwt[way]);
	}

	return 0;
}

int ecpt_cwt_free(struct mm_struct *mm)
{
	uint16_t way = 0;
	ECPT_desc_t *desc = mm->map_desc;

	for (; way < CWT_TOTAL_N_WAY; way++) {
		free_one_way(desc->cwt[way]);

		sub_pgtable_bytes(mm, desc->cwt[way]);
	}

	return 0;
}


static inline void cwt_entry_check_valid_header_num(cwt_entry_t *e)
{
	uint16_t count = cwt_entry_count_valid_header_num(e);
	uint16_t stats = cwt_entry_get_valid_header_num(e);

	if (count != stats) {
		WARN(1, "Inconsistent count=%d and stats=%d!\n", count, stats);
	}
}

#ifdef DEBUG_CHECK_CWT_DETAIL
static uint32_t check_cwt_detail_way (ECPT_desc_t *ecpt, uint32_t way)
{
	uint64_t cwt, n_entries;
	uint32_t valid_entries_cnt = 0;
	uint32_t j;
	cwt_entry_t *cwt_base, *c;

	cwt = ecpt->cwt[way];
	n_entries = GET_HPT_SIZE(cwt);

	cwt_base = (cwt_entry_t *)GET_HPT_BASE_VIRT(cwt);

	for (j = 0; j < n_entries; j++) {
		c = &cwt_base[j];
		cwt_entry_check_valid_header_num(c);
		if (!cwt_empty_entry(c)) {
			valid_entries_cnt++;
		}
	}
	return valid_entries_cnt;
}

static void check_cwt_detail(ECPT_desc_t *ecpt, uint32_t way_start, uint32_t way_end, bool print_entry)
{
	uint64_t cwt, n_entries;
	uint32_t valid_entries_cnt;
	uint32_t i, j;
	cwt_entry_t *cwt_base, *c;

	for (i = way_start; i < way_end; i++) {
		valid_entries_cnt = 0;
		if (print_entry) {
			pr_info("\t 0x%x/0x%llx %llx -> msr %x \n",
				ecpt->cwt_occupied[i], GET_HPT_SIZE(ecpt->cwt[i]),
				ecpt->cwt[i], WAY_TO_ECPT_CWT_MSR(i));
		}


		cwt = ecpt->cwt[i];
		n_entries = GET_HPT_SIZE(cwt);

		cwt_base = (cwt_entry_t *)GET_HPT_BASE_VIRT(cwt);

		for (j = 0; j < n_entries; j++) {
			c = &cwt_base[j];
			cwt_entry_check_valid_header_num(c);
			if (!cwt_empty_entry(c)) {
				if (print_entry) {
					PRINT_CWT_ENTRY_INFO(c);
				}
				valid_entries_cnt++;
			}
		}


		if (valid_entries_cnt != ecpt->cwt_occupied[i]) {
			for (j = 0; j < n_entries; j++) {
				c = &cwt_base[j];
				if (print_entry && !cwt_empty_entry(c)) {
					PRINT_CWT_ENTRY_INFO(c);
				}
			}
		}
	}
}

#endif
