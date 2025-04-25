#!/usr/bin/env bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 [--dry]"
    exit 1
fi

ARCH=""
dry_run="false"

tag=""
while [[ $# -gt 0 ]]; do
	key="$1"

	case $key in
    --arch)
        if [[ $# -gt 1 ]]; then
			ARCH="$2"
			shift 2
		else
			echo "Option --arch requires an argument"
			exit 1
		fi
		;;
    --tag)
        if [[ $# -gt 1 ]]; then
			tag="$2"
			shift 2
		else
			echo "Option --arch requires an argument"
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
    "graphbig_dc" 
    "graphbig_dfs" 
    "graphbig_pagerank" 
    "graphbig_sssp" 
    "graphbig_tc" 
    # "gups_8G"
    # "sysbench_8G"  
    "gups"
    "sysbench"  
 
)

THP_CONFGS=(
    # "never"
    "always"
)


# OUTPUT_DIR="/hdd/collect_trace_fast/${ARCH}"
OUTPUT_DIR="/disk/bak1/kexec_${run_tag}/${ARCH}"
mkdir -p $OUTPUT_DIR

IMAGE_PATH_PREFIX=$(realpath ../small_image_reps/image_record_loading.ext4_rep)

rep=0

launch_script="run_linux_free_cmd"
rep_offset=0
if [ "$ARCH" = "ecpt" ]; then
    rep_offset=4
    # launch_script="run_ECPT_execlog"
fi


do_task() {
    local id=$1
    echo "Starting task $id"
    sleep $((RANDOM % 5 + 1)) # Simulate task by sleeping for a random duration between 1 and 5 seconds
    echo "Completed task $id"
}

# Although each workload's working set is pretty big
# in loading stage, we won't have that many memory requirement
N_REP=16
# N_REP=4
for bench in "${BENCHS[@]}"
do
    echo "Acquiring log for $bench" 

    for thp_config in "${THP_CONFGS[@]}"
    do
        real_rep=$((rep + rep_offset))
        image_path="${IMAGE_PATH_PREFIX}${real_rep}"
        FILE_PREFIX="${ARCH}_${thp_config}_${bench}"
        # log saved to ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin.log"

        echo "${launch_script} --arch $ARCH --thp $thp_config --bench "simulation/${bench}.sh 1" --out ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin --image $image_path --k_exec_only"
        # do_task $bench &
        if [ "$dry_run" = "false" ]; then
            ./${launch_script} --arch $ARCH --thp $thp_config --bench "simulation/${bench}.sh 1" --out ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin --image $image_path --k_exec_only &
        fi
        
        rep=$(( (rep + 1) % N_REP ))
        # leave time to sync
        sleep 1
        
        if [ $((rep % N_REP)) -eq 0 ]; then
            wait
        fi
    done
    
done

wait

sleep 10

echo "Done"
