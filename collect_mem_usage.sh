#!/usr/bin/env bash

launch_script="run_hda" 
dry_run="false"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
OUTPUT_DIR="${SCRIPT_DIR}/mem_usage"
mkdir -p $OUTPUT_DIR
while [[ $# -gt 0 ]]; do
	key="$1"

	case $key in
	--dry)
		dry_run="true"
        shift 1
		;;
    --arch)
        if [[ $# -gt 1 ]]; then
			ARCH="$2"
			shift 2
		else
			echo "Option --arch requires an argument"
			exit 1
		fi
		;;
	*)                  # unknown option
        shift 1
        ;; 
	esac
done

# To run 
BENCHS=(
    "graphbig_bfs" 
    "graphbig_cc" 
    "graphbig_dc" 
    "graphbig_dfs" 
    "graphbig_pagerank" 
    "graphbig_sssp" 
    "graphbig_tc" 
    #"gups_8G"
    #"sysbench_8G"  
    "gups"
    "sysbench"
)
THP_CONFGS=(
    "never"
    "always"
)

# Image 
IMAGE_PATH_PREFIX=$(realpath ../small_image_reps/image_record_loading.ext4_rep)

# Launch 
rep=0 
rep_offset=0
for bench in "${BENCHS[@]}"
do
    echo "Acquiring log for $bench" 
    for thp_config in "${THP_CONFGS[@]}"
    do
        real_rep=$((rep + rep_offsets))
        image_path="${IMAGE_PATH_PREFIX}${real_rep}"
        FILE_PREFIX="${ARCH}_${thp_config}_${bench}"

        echo "./${launch_script} ${ARCH} ${bench} ${thp_config} ${image_path} ${OUTPUT_DIR}/${FILE_PREFIX}.log ${dry_run}" 
        if [ "$dry_run" == "false" ]; then
            ./${launch_script} ${ARCH} ${bench} ${thp_config} ${image_path} ${OUTPUT_DIR}/${FILE_PREFIX}.log ${dry_run} &
        else 
            ./${launch_script} ${ARCH} ${bench} ${thp_config} ${image_path} ${OUTPUT_DIR}/${FILE_PREFIX}.log ${dry_run}
            echo ""
        fi 

        rep=$((rep+1))
    done
    
done
