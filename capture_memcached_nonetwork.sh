#!/bin/bash
set -x

POSITIONAL=()

ARCH=""
recording_stage=1

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
		--record-stage)
			recording_stage=$2
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

# set the stage str 
stage_str="running"
if [ $recording_stage -eq 2 ]; then 
    stage_str="loading"
    rep=8
elif [ $recording_stage -eq 3 ]; then 
    stage_str="loading_end"
    rep=8
fi 
FLAVOR="L3L2"
# Experiment configuration
workload=Memcached64Gpure_20insertion

MEMCACHED_COMMAND="cd /rethinkVM_bench/memcached_rethinkvm; ./memcached --user=root --memory-limit=85000 --key-max 56000000 --running-insertion 20"

if [ $recording_stage -eq 1 ]; then 
	stage_str="running"
elif [ $recording_stage -eq 2 ]; then 
    stage_str="loading"
	MEMCACHED_COMMAND="${MEMCACHED_COMMAND} --record-stage=${recording_stage}"
elif [ $recording_stage -eq 3 ]; then 
    stage_str="loading_end"
	MEMCACHED_COMMAND="${MEMCACHED_COMMAND} --record-stage=${recording_stage}"
fi

if [ $THP == "always" ]; then 
	MEMCACHED_COMMAND="${MEMCACHED_COMMAND} --enable-largepages"
fi

OUT_FOLDER="/data1/fpt_kexec/${workload}"
mkdir -p $OUT_FOLDER
OUT_BIN="${OUT_FOLDER}/${ARCH}_${FLAVOR}_${THP}_run_${workload}_${stage_str}.bin"

while ps -p 1172981 > /dev/null; do
    sleep 20
done
# OUT_BIN="/data1/memcached_nonetwork/${workload}/${ARCH}_${THP}_run_${workload}_${recording_stage_str}.bin"
# Launch Experiment
./run_linux_free_cmd --arch $ARCH --image /home/siyuan/image_record_loading.ext4 ${DRY_RUN_STR} \
    --out ${OUT_BIN} \
	--thp ${THP} \
    --cmd "${MEMCACHED_COMMAND}; /shutdown;" --k_exec_only
