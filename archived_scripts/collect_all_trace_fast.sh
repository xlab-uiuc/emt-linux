#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <thp_config>"
    exit 1
fi

BENCHS=(
    "graphbig_bfs" 
    "graphbig_cc" 
    "graphbig_dc" 
    "graphbig_dfs" 
    "graphbig_pagerank" 
    "graphbig_sssp" 
    "graphbig_tc" 
    # "gups"
    # "sysbench"   
)

ARCH="ecpt"
OUTPUT_DIR="/hdd/collect_trace_fast/${ARCH}"
# OUTPUT_DIR="/data1/collect_trace_fast/${ARCH}"
mkdir -p $OUTPUT_DIR

IMAGE_PATH_PREFIX="/home/siyuan/small_image_reps/image.ext4_rep"


thp_config=$1

rep=0


do_task() {
    local id=$1
    echo "Starting task $id"
    sleep $((RANDOM % 5 + 1)) # Simulate task by sleeping for a random duration between 1 and 5 seconds
    echo "Completed task $id"
}

N_REP=4
for bench in "${BENCHS[@]}"
do
    echo "Acquiring log for $bench" 
    
    image_path="${IMAGE_PATH_PREFIX}${rep}"
    FILE_PREFIX="${ARCH}_${thp_config}_${bench}"
    # log saved to ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin.log"
    # echo "collect_trace_fast.exp $thp_config $bench ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin $image_path"
    # ./trace_utils/collect_trace_fast.exp $thp_config $bench ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin $image_path &

    echo "run_ECPT_execlog --thp $thp_config --bench $bench --out ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin --image $image_path"
    do_task $bench &
    ./run_ECPT_execlog --thp $thp_config --bench $bench --out ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin --image $image_path &
    # ((rep++))
    rep=$(( (rep + 1) % N_REP ))
    # leave time to sync
    sleep 1
    
    # mv x86.log ${OUTPUT_DIR}/${FILE_PREFIX}_x86.log
    # mv walk_log.bin ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin

    # grep "Radix Translate" mmu.log > ${OUTPUT_DIR}/${bench}_${ARCH}_mmu.log
    # mv ${ARCH}.log  ${OUTPUT_DIR}/${bench}_${ARCH}_run.log
    # Add your commands here to process each file
    if [ $((rep % N_REP)) -eq 0 ]; then
        wait
    fi
done

wait

sleep 10

echo "Done"
