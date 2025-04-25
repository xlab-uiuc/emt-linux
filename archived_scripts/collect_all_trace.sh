#!/bin/bash

BENCHS=("sysbench" "graphbig_bc" "graphbig_bfs" "graphbig_cc" "graphbig_dc" "graphbig_dfs" "graphbig_pagerank" "graphbig_sssp" "graphbig_tc" "mummer" )

ARCH="x86"
OUTPUT_DIR="logs_${ARCH}"
mkdir -p $OUTPUT_DIR

for bench in "${BENCHS[@]}"
do
    echo "Acquiring log for $bench"
    ./collect_trace.exp $bench
    grep "Radix Translate" mmu.log > ${OUTPUT_DIR}/${bench}_${ARCH}_mmu.log
    mv ${ARCH}.log  ${OUTPUT_DIR}/${bench}_${ARCH}_run.log
    # Add your commands here to process each file
done

