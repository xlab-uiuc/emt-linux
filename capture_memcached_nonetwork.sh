#!/bin/bash
set -x

POSITIONAL=()

ARCH=""
LOADING_PHASE=false

DRY_RUN_STR=""
THP="never"
while [[ $# -gt 0 ]]; do
  	key="$1"

  	case $key in
    	--arch)
      		ARCH="$2"
      		shift # past value
      		;;
    	--default)
      		DEFAULT=YES
      		shift # past argument
      		;;
		--thp)
			THP="$2"
			shift # past value
			;;
		--dry)
			DRY_RUN_STR="--dry"
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

# VM_SERVER_PORT=2024
# HOST_SERVER_PORT=12024

# VM_LOGGING_CTL_PORT=2025
# HOST_LOGGING_CTL_PORT=12025

# Experiment configuration
workload=Memcached64Gpure_20insertion_enablelarge

if [ $LOADING_PHASE == true ]; then 
	recording_stage_str="loading"
	MEMCACHED_COMMAND="cd /rethinkVM_bench/memcached_rethinkvm; ./memcached --user=root --memory-limit=85000 --key-max 56000000 --running-insertion 20 --record-stage=2"
else 
	MEMCACHED_COMMAND="cd /rethinkVM_bench/memcached_rethinkvm; ./memcached --user=root --memory-limit=85000 --key-max 56000000 --running-insertion 20"
	recording_stage_str="running"
fi 

if [ $THP == "always" ]; then 
	MEMCACHED_COMMAND="${MEMCACHED_COMMAND} --enable-largepages"
fi

OUT_FOLDER="/data1/memcached_nonetwork/${workload}"
mkdir -p $OUT_FOLDER
OUT_BIN="${OUT_FOLDER}/${ARCH}_${THP}_run_${workload}_${recording_stage_str}.bin"
# OUT_BIN="/data1/memcached_nonetwork/${workload}/${ARCH}_${THP}_run_${workload}_${recording_stage_str}.bin"
# Launch Experiment
./run_linux_free_cmd --arch $ARCH --image /data1/image_custom_post_120G.ext4 ${DRY_RUN_STR} \
    --out ${OUT_BIN} \
	--thp ${THP} \
    --cmd "${MEMCACHED_COMMAND}; /shutdown;" --run-dynamorio



# EXTRA_COMMAND="ps aux | grep memcached; netstat -tuln | grep $VM_SERVER_PORT"
# START_LOGGING_COMMAND="cd rethinkVM_bench; ./listen_and_start.sh $VM_LOGGING_CTL_PORT"

# qemu_script_pid=$!

# sleep 40 # wait for the memcached to start

# YCSB_FOLDER=$(realpath ../rethinkVM_bench/ycsb)
# cd $YCSB_FOLDER


# # loading phase
# ./bin/ycsb load memcached -s -P "workloads/workload${workload}" -p "memcached.hosts=127.0.0.1:${HOST_SERVER_PORT}" 2>&1 | tee ${OUT_BIN}.ycsb_LOAD.txt

# sleep 2

# # -q 0 means close the connection after sending the data
# echo "start" |  nc 127.0.0.1 $HOST_LOGGING_CTL_PORT -q 0


# # running phase
# ./bin/ycsb run memcached -s -P "workloads/workload${workload}" -p "memcached.hosts=127.0.0.1:${HOST_SERVER_PORT}" 2>&1 | tee ${OUT_BIN}.ycsb_RUN.txt

# echo "end" |  nc 127.0.0.1 $HOST_LOGGING_CTL_PORT -q 0

# sleep 20

# kill -9 $qemu_script_pid
# pgrep -f qemu-system-x86_64 | xargs kill

# pkill ../qemu_x86/build/qemu-system-x86_64
# pkill ../qemu_ECPT/build/qemu-system-x86_64
