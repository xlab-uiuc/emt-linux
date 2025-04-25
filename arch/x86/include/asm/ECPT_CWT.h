#ifndef _ASM_X86_ECPT_CWT_H
#define _ASM_X86_ECPT_CWT_H

#include <asm/ECPT_defs.h>
/* at most 18 bits for PMD and PUD */
#define CWT_N_SECTION_HEADERS 64

#define CWT_VPN_2MB_BITS 18
#define CWT_VPN_1GB_BITS 9
#define CWT_CLUSTER_NBITS 6

#define VADDR_TO_CWT_VPN_2MB(x)  (VADDR_TO_PAGE_NUM_2MB(x) >> CWT_CLUSTER_NBITS)
#define VADDR_TO_CWT_VPN_1GB(x)  (VADDR_TO_PAGE_NUM_1GB(x) >> CWT_CLUSTER_NBITS)

#define CWT_SECTION_HEADERS_IDX_MASK (CWT_N_SECTION_HEADERS - 1)
#define VADDR_TO_CWT_2M_HEADER_IDX(x) (VADDR_TO_PAGE_NUM_2MB(x) & CWT_SECTION_HEADERS_IDX_MASK)
#define VADDR_TO_CWT_1G_HEADER_IDX(x) (VADDR_TO_PAGE_NUM_1GB(x) & CWT_SECTION_HEADERS_IDX_MASK)

/* Each byte of a section: first 5 bits for section header, later three for VPN */
#define CWT_HEADER_BITS 5
#define CWT_VPN_BITS_PER_BYTE 3

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* Round up division */
#define CWT_N_BYTES_FOR_VPN \
    ((MAX(CWT_VPN_2MB_BITS, CWT_VPN_1GB_BITS) + (CWT_VPN_BITS_PER_BYTE - 1)) / CWT_VPN_BITS_PER_BYTE)

/* utilize vpn bits of  */
#define CWT_N_SECTION_VALID_NUM_START 61 
#define CWT_N_SECTION_VALID_NUM_LEN 3
#define CWT_VALID_NUM_BITS_PER_BYTE 3

#if CWT_N_SECTION_VALID_NUM_START + CWT_N_SECTION_VALID_NUM_LEN > CWT_N_SECTION_HEADERS
    #error Wrong Config of CWT_N_SECTION_VALID_NUM_START/END
#endif

/* TODO:
 *  this now assumes, kernel and user space have the same number of CWT 
 *  remove in the future. change load_ecpt_cwt_specific functions as well
 */
#define CWT_2MB_WAY_N_ENTRIES 4096
#define CWT_2MB_QUAD_CNT (CWT_N_SECTION_HEADERS / 4)
#define CWT_2MB_N_WAY 2

#define CWT_1GB_WAY_N_ENTRIES 2048
#define CWT_1GB_QUAD_CNT (CWT_N_SECTION_HEADERS / 4)
#define CWT_1GB_N_WAY 2

#define CWT_TOTAL_N_WAY (CWT_2MB_N_WAY + CWT_1GB_N_WAY)
#define CWT_KERNEL_WAY (CWT_2MB_N_WAY + CWT_1GB_N_WAY)

#define CWT_2MB_WAY_CR_SIZE_VAL (12)
#define CWT_1GB_WAY_CR_SIZE_VAL (11)

#define CWT_MAX_WAY 10
#if CWT_MAX_WAY < CWT_TOTAL_N_WAY
#error "CWT_MAX_WAY exceeded"
#endif

#define MSR_CWT_START               0x00004040
#define MSR_CWT_END                (MSR_CWT_START + CWT_MAX_WAY)

#define WAY_TO_ECPT_CWT_MSR(w) (MSR_CWT_START + (w))

#ifndef __ASSEMBLY__
typedef union cwt_header_byte
{
    struct  {
        /* header info */
        unsigned int present_1GB : 1;
        unsigned int present_2MB : 1;
        unsigned int present_4KB : 1;
        unsigned int way_in_ecpt : 2;

        /* bits for partial info */
        unsigned int partial_vpn : 3;
    } __attribute__((packed));
    unsigned char byte;
} cwt_header_t;

typedef struct cwt_entry {
	cwt_header_t sec_headers[CWT_N_SECTION_HEADERS];
} __attribute__((packed)) cwt_entry_t;

typedef enum {
	CWT_2MB,
	CWT_1GB
} CWTGranularity; 

#define CWT_PARTIAL_VPN_MASK ((1UL << CWT_VPN_BITS_PER_BYTE) - 1)
#define CWT_GET_PARTIAL_VPN(vpn, idx) ((vpn >> (idx * CWT_VPN_BITS_PER_BYTE)) & CWT_PARTIAL_VPN_MASK)

#define CWT_PARTIAL_VALID_NUM_MASK ((1UL << CWT_VALID_NUM_BITS_PER_BYTE) - 1)
#define CWT_GET_PARTIAL_VALID_NUM(vpn, idx) \
    ((vpn >> (idx * CWT_VALID_NUM_BITS_PER_BYTE)) & CWT_PARTIAL_VALID_NUM_MASK)

#define CWT_HEADER_MASK (0x1f)
#define CWT_HEADER_PARTIAL_MASK (0xe0)
#define GET_CWT_HEADER_DATA(byte) ((byte) & CWT_HEADER_MASK)
#define GET_CWT_HEADER_PARTIAL_DATA(byte) ((byte) & CWT_HEADER_PARTIAL_MASK)


#endif /* !__ASSEMBLY__ */


#endif /* _ASM_X86_ECPT_CWT_H */