#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 --thp <thp_config> [--dry]"
    exit 1
fi

thp_config=""
dry_run="false"
while [[ $# -gt 0 ]]; do
	key="$1"

	case $key in
	--thp)
		if [[ $# -gt 1 ]]; then
			thp_config="$2"
			shift 2
		else
			echo "option for arch: radix ecpt"
			exit 1
		fi
		;;
	--dry)
		dry_run="true"
        shift 1
		;;
	--default)
		DEFAULT=YES
		shift # past argument
		;;
	*)                  # unknown option
		POSITIONAL+=("$1") # save it in an array for later
		shift              # past argument
		;;
	esac
done

BENCHS=(
    "graphbig_bfs" 
    "graphbig_cc" 
    # "graphbig_dc" 
    # "graphbig_dfs" 
    # "graphbig_pagerank" 
    # "graphbig_sssp" 
    # "graphbig_tc" 
    # "gups_8G"
    # "sysbench_8G"  
    # "gups"
    # "sysbench"
)

ARCH="ecpt"
# OUTPUT_DIR="/hdd/collect_trace_fast/${ARCH}"
OUTPUT_DIR="/data2/collect_trace_fast/${ARCH}"
mkdir -p $OUTPUT_DIR

IMAGE_PATH_PREFIX=$(realpath ../small_image_reps/image.ext4_rep)


if [[ "$thp_config" != "never" && "$thp_config" != "always" ]]; then
    echo "invalid thp config"
    exit 1
else
    echo "thp = $thp_config"
fi

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
    
    echo "run_ECPT_execlog --thp $thp_config --bench ${bench}.sh --out ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin --image $image_path"
    # do_task $bench &
    if [ "$dry_run" = "false" ]; then
        ./run_ECPT_execlog --thp $thp_config --bench ${bench}.sh --out ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin --image $image_path &
    fi
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
