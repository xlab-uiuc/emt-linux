#!/bin/bash
set -x

POSITIONAL=()

ARCH=""
THP=never
record_stage=1

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

# Experiment configuration
workload=postgres64G_sequential_load
# run_flag="--run-dynamorio" 
POSTGRES_COMMAND="cd /rethinkVM_bench/postgresql-14.13; cd build_dir/bin; su postgres -c './postgres --single -D /data1/siyuan_pgsql/data/ postgres -R 21000000 -a ${record_stage}'"
if [ $record_stage -eq 1 ]; then 
	recording_stage_str="running"
elif [ $record_stage -eq 2 ]; then 
	recording_stage_str="loading"
elif [ $record_stage -eq 3 ]; then 
	recording_stage_str="loading_end"
else 	
	echo "unsupported record_stage int"
	exit 1 
fi 

# Launch experiment
flavor="L3L2"
OUT_FOLDER="/disk/bak1/siyuan/${workload}"
mkdir -p $OUT_FOLDER
OUT_BIN="${OUT_FOLDER}/${ARCH}_${flavor}_${THP}_run_${workload}_${recording_stage_str}.bin"

# CSL image path
# /disk/ssd1/image_custom_post_120G.ext4

./run_linux_free_cmd --arch $ARCH --image /disk/ssd1/image_custom_post_120G.ext4 ${DRY_RUN_STR} \
	--out ${OUT_BIN} \
	--thp ${THP} \
	--cmd "${POSTGRES_COMMAND}; /shutdown;" ${run_flag}