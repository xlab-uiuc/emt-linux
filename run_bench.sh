#!/usr/bin/env bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 --thp <thp_config> [--dry]"
    exit 1
fi

thp_config=""
dry_run="false"

LOADING_PHASE=false
OUTPUT_DIR="benchmark_output"
ARCH="radix"
FLAVOR=""
while [[ $# -gt 0 ]]; do
	key="$1"

	case $key in
    --arch)
        if [[ $# -gt 1 ]]; then
            ARCH="$2"
            shift 2
        else
            echo "Need a value for --arch"
            exit 1
        fi
        ;;
    --flavor)
        if [[ $# -gt 1 ]]; then
            FLAVOR="$2"
            shift 2
        else
            echo "Need a value for --flavor"
            exit 1
        fi
        ;;
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
    --out)
        if [[ $# -gt 1 ]]; then
            OUTPUT_DIR="$2"
            shift 2
        else
            echo "Need a value for --out"
            exit 1
        fi
        ;;
    --loading-phase)
        LOADING_PHASE=true
        shift # past argument
        ;;
    --loading-phase-end)
        LOADING_PHASE_END=true
        shift # past argument
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
    # "graphbig_cc" 
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

# ARCH="radix"
# OUTPUT_DIR="/hdd/collect_trace_fast/${ARCH}"
# OUTPUT_DIR="/data1/collect_trace_fast/${ARCH}"


IMAGE_PATH_PREFIX=$(realpath ../image_record_loading.ext4)

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

# by default, we are recording loading stage.
recording_stage=1
stage_str="running"

if [ $LOADING_PHASE == true ]; then 
    recording_stage=3
    stage_str="loading_end"
fi 

if [ $LOADING_PHASE_END == true ]; then 
    recording_stage=3
    stage_str="loading_end"
fi

OUTPUT_DIR=${OUTPUT_DIR}/${ARCH}_${FLAVOR}/${stage_str}
sudo mkdir -p $OUTPUT_DIR
sudo chmod 777 $OUTPUT_DIR

N_REP=1
for bench in "${BENCHS[@]}"
do
    echo "Acquiring log for $bench" 
    
    image_path="${IMAGE_PATH_PREFIX}"
    FILE_PREFIX="${ARCH}_${thp_config}_${bench}_${stage_str}"
    # log saved to ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin.log"


    COMMAND="cd rethinkVM_bench; ./run_scripts/simulation/${bench}.sh ${recording_stage}; /shutdown;"
    echo "run_linux_free_cmd --arch $ARCH --thp $thp_config --cmd ${COMMAND} --out ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin --image $image_path --run-dynamorio"
    # do_task $bench &
    if [ "$dry_run" = "false" ]; then
        ./run_linux_free_cmd --arch $ARCH --thp $thp_config --cmd "${COMMAND}" --out ${OUTPUT_DIR}/${FILE_PREFIX}_walk_log.bin --image $image_path --run-dynamorio &
    fi
    
    rep=$(( (rep + 1) % N_REP ))
    # leave time to sync
    sleep 1
    
    if [ $((rep % N_REP)) -eq 0 ]; then
        wait
    fi
done

wait

sleep 10

echo "Done"
