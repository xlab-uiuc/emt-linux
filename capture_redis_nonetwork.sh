#!/bin/bash
# set -x

POSITIONAL=()

ARCH=""
LOADING_PHASE=false
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
		--loading-phase)
			LOADING_PHASE=true
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

# Configuration
workload=jiyuan_redis_run_128G
if [ $LOADING_PHASE == true ]; then 
	REDIS_COMMAND="cd /rethinkVM_bench/workloads; ./bin/bench_redis_st -- --loading-phase"
else 
	REDIS_COMMAND="cd /rethinkVM_bench/workloads; ./bin/bench_redis_st"
fi 

# EXTRA_COMMAND="ps aux | grep memcached; netstat -tuln | grep $VM_SERVER_PORT"
# START_LOGGING_COMMAND="cd rethinkVM_bench; ./listen_and_start.sh $VM_LOGGING_CTL_PORT"
# OUT_BIN=$(realpath walk_log.bin)

# run profiling only: --k_exec_only

OUT_BIN="/siyuan_data/${ARCH}_${THP}_run_${workload}.bin"
./run_linux_free_cmd --arch $ARCH --image /disk/ssd1/image_with_redis.ext4 ${DRY_RUN_STR}  \
    --out ${OUT_BIN} \
	--thp ${THP} \
    --cmd "${REDIS_COMMAND}; /shutdown;"  --run-dynamorio 

