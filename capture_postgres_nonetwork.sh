#!/bin/bash
set -x

POSITIONAL=()

ARCH=""
THP=never
LOADING_PHASE=false

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

# Experiment configuration
workload=postgres64G_sequential_load

run_flag=""
if [ $LOADING_PHASE == true ]; then 
	# POSTGRES_COMMAND="cd /rethinkVM_bench/postgresql-14.13; cd build_dir/bin; su postgres -c './postgres --single -D /data1/siyuan_pgsql/data/ postgres -R 12000000 -a'"
	POSTGRES_COMMAND="cd /rethinkVM_bench/postgresql-14.13; cd build_dir/bin; su postgres -c './postgres --single -D /data1/siyuan_pgsql/data/ postgres -R 21000000 -a'"
	run_flag="--k_exec_only"
	recording_stage_str="loading"
else
	# POSTGRES_COMMAND="cd /rethinkVM_bench/postgresql-14.13; cd build_dir/bin; su postgres -c './postgres --single -D /data1/siyuan_pgsql/data/ postgres -R 12000000'"
	POSTGRES_COMMAND="cd /rethinkVM_bench/postgresql-14.13; cd build_dir/bin; su postgres -c './postgres --single -D /data1/siyuan_pgsql/data/ postgres -R 21000000'"
	run_flag="--run-dynamorio"
	recording_stage_str="running"
fi 

# Launch experiment
OUT_FOLDER="/hdd/alan_loading_phase/${workload}"
mkdir -p $OUT_FOLDER
OUT_BIN="${OUT_FOLDER}/${ARCH}_${THP}_run_${workload}_${recording_stage_str}.bin"

# CSL image path
# /disk/ssd1/image_custom_post_120G.ext4

./run_linux_free_cmd --arch $ARCH --image /data1/image_custom_post_120G.ext4 ${DRY_RUN_STR} \
	--out ${OUT_BIN} \
	--thp ${THP} \
	--cmd "${POSTGRES_COMMAND}; /shutdown;" ${run_flag}

