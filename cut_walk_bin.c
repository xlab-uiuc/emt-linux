#include "linux/types.h"
#include <stdio.h>
#include <stdint.h>

// #define PAGE_TABLE_LEAVES 6
// #define CWT_LEAVES 4
// #define PAGE_TABLE_LEAVES 4

#define BIN_RECORD_TYPE_MEM 'M' // User memory access, use MemRecord
#define BIN_RECORD_TYPE_FEC 'F' // InsFetcher memory access, use MemRecord
#define BIN_RECORD_TYPE_INS 'I' // InsDecoder record, use InsRecord

// #define TARGET_X86_64_ECPT

#ifdef TARGET_X86_64_ECPT
#define PAGE_TABLE_LEAVES 6
#define CWT_LEAVES 4
#endif

#ifndef PAGE_TABLE_LEAVES
#define PAGE_TABLE_LEAVES 4
#endif

typedef struct MemRecord
{
	uint8_t header;
	uint8_t access_rw;
	uint16_t access_cpu;
	uint32_t access_sz;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t pte;
	uint64_t leaves[PAGE_TABLE_LEAVES];
    /* 64 bytes if ECPT not defined */
#ifdef TARGET_X86_64_ECPT
    uint64_t cwt_leaves[CWT_LEAVES];
    uint16_t selected_ecpt_way;
    uint8_t pmd_cwt_header;
    uint8_t pud_cwt_header;
    /* 120 bytes if ECPT defined */
#endif
} MemRecord;

// typedef struct InsRecord
// {
// 	uint8_t header;
// 	uint8_t cpu;
// 	uint16_t length;
// 	uint32_t opcode;
// 	uint64_t vaddr;
// 	uint64_t counter;
// 	// char disassembly[length];
// } InsRecord;

// typedef union BinaryRecord
// {
// 	InsRecord ins;
// 	MemRecord mem;
// } BinaryRecord;

// char* open_read(char* path)
// {
//     // 
// }

static void print_leaves_helper(uint64_t* leaves, int n) {
    printf("[");
    for (int i = 0; i < n; i++) {
        printf(" %016lx ", leaves[i]);
    }
    printf("]");
}

struct stat {
    uint64_t n_fetch;
    uint64_t n_load;
    uint64_t n_store;
};


#define IS_KERNEL_ADDR(addr) ((addr) >= 0xffff800000000000UL)
#define LIMIT 1000


/**
 * Example: gcc cut_walk_bin.c -o cut_walk
 * ./cut_walk /data1/collect_trace_fast/radix/radix_never_graphbig_bfs_walk_log.bin 1k.bin
 * 
 *  */ 

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <in_path> <out_path>\n", argv[0]);
        return 1;
    }

    char* path = argv[1];
    char* output_path = argv[2];
    int count = 0;



    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        printf("Error opening file %s\n", path);
        return 1;
    }


    FILE* output_fp = fopen(output_path, "wb");
    if (output_fp == NULL) {
        printf("Error opening file %s\n", output_path);
        fclose(fp);
        return 1;
    }

    struct stat kernel_stat = {0};
    struct stat user_stat = {0};


    MemRecord record;
    while (fread(&record, sizeof(MemRecord), 1, fp) == 1) {
        fwrite(&record, sizeof(MemRecord), 1, output_fp);
        count++;


        if (record.header == BIN_RECORD_TYPE_MEM) {
            // printf("%s: access_cpu=%04x, access_sz=%02x, vaddr=%016lx, paddr=%016lx, pte=%016lx, leaves=",
            //     record.access_rw ? "Load " : "Store", record.access_cpu, record.access_sz, record.vaddr, record.paddr, record.pte);
            
            // printf("\n");

            if (record.access_rw) {
                if (IS_KERNEL_ADDR(record.vaddr)) {
                    kernel_stat.n_load++;
                } else {
                    user_stat.n_load++;
                }
            } else {
                if (IS_KERNEL_ADDR(record.vaddr)) {
                    kernel_stat.n_store++;
                } else {
                    user_stat.n_store++;
                }
            }

        } else if (record.header == BIN_RECORD_TYPE_FEC) {
            // printf("Fetch: access_cpu=%04x, access_sz=%02x, vaddr=%016lx, paddr=%016lx, pte=%016lx, leaves=",
            //     record.access_cpu, record.access_sz, record.vaddr, record.paddr, record.pte);
            
            // printf("\n");

            printf("Fetch: access_cpu=%04x, access_sz=%02x, vaddr=%016lx, paddr=%016lx, pte=%016lx, leaves=",
                    record.access_cpu, record.access_sz, record.vaddr, record.paddr, record.pte);
                
            printf("\n");
            if (IS_KERNEL_ADDR(record.vaddr)) {
                kernel_stat.n_fetch++;
                
            } else {
                user_stat.n_fetch++;
            }

        } else {
            printf("Unknown record type: %d\n", record.header);
        }

        if (count >= LIMIT) {
            break;
        }
    }

    fclose(fp);
    fclose(output_fp);

    printf("Kernel: n_fetch=%lu, n_load=%lu, n_store=%lu\n", kernel_stat.n_fetch, kernel_stat.n_load, kernel_stat.n_store);
    printf("User: n_fetch=%lu, n_load=%lu, n_store=%lu\n", user_stat.n_fetch, user_stat.n_load, user_stat.n_store);

    return 0;
}