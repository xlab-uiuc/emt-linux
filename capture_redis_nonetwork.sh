#!/bin/bash
# set -x

POSITIONAL=()

ARCH=""
record_stage=1
THP="never"

DRY_RUN_STR=""
while [[ $# -gt 0 ]]; do
  	key="$1"

  	case $key in
    	--arch)
      		ARCH="$2"
      		shift # past value
      		;;
		--thp)
			THP="$2"
			shift # past value
			;;
		--dry)
			DRY_RUN_STR="--dry"
			shift # past argument
			;;
    	--default)
      		DEFAULT=YES
      		shift # past argument
      		;;
		--record-stage)
			record_stage=$2
			shift # past argument
			;;
    	*)    # unknown option
      		POSITIONAL+=("$1") # save it in an array for later
      		shift # past argument
      		;;
    esac
done

if [ -z $ARCH ]; then
    echo "ARCH is not set"
    exit 1
fi

stage_str="running"
if [ $record_stage -eq 2 ]; then 
    stage_str="loading"
    rep=0
elif [ $record_stage -eq 3 ]; then 
    stage_str="loading_end_phase"
    rep=0
fi 

# Configuration
workload=jiyuan_redis_run_128G
REDIS_COMMAND="cd /rethinkVM_bench/workloads; ./bin/bench_redis_st -- --recording-stage ${record_stage}"



# EXTRA_COMMAND="ps aux | grep memcached; netstat -tuln | grep $VM_SERVER_PORT"
# START_LOGGING_COMMAND="cd rethinkVM_bench; ./listen_and_start.sh $VM_LOGGING_CTL_PORT"
# OUT_BIN=$(realpath walk_log.bin)

# run profiling only: --k_exec_only
flavor="L3L2"
OUT_BIN="/siyuan_data/fpt_${flavor}/${ARCH}_${flavor}_${THP}_${stage_str}_${workload}.bin"
./run_linux_free_cmd --arch $ARCH --image /disk/ssd1/image_record_loading.ext4 ${DRY_RUN_STR}  \
    --out ${OUT_BIN} \
	--thp ${THP} \
    --cmd "${REDIS_COMMAND}; /shutdown;"

