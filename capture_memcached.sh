#!/bin/bash
set -x

POSITIONAL=()

ARCH=""
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

workload=Memcached64G

VM_SERVER_PORT=2024
HOST_SERVER_PORT=12024

VM_LOGGING_CTL_PORT=2025
HOST_LOGGING_CTL_PORT=12025

MEMCACHED_COMMAND="/usr/bin/memcached --user=root --memory-limit=131000 --port=$VM_SERVER_PORT --listen=0.0.0.0 --daemon"
EXTRA_COMMAND="ps aux | grep memcached; netstat -tuln | grep $VM_SERVER_PORT"
START_LOGGING_COMMAND="cd rethinkVM_bench; ./listen_and_start.sh"

OUT_BIN="/data1/memcached/${ARCH}_never_run_${workload}.bin"
./run_linux_free_cmd --arch $ARCH --image /data1/image_with_redis_loading.ext4_1 \
    --out ${OUT_BIN} \
    --cmd "${MEMCACHED_COMMAND}; ${EXTRA_COMMAND}; ${START_LOGGING_COMMAND}" &

qemu_script_pid=$!

sleep 40 # wait for the memcached to start

YCSB_FOLDER=$(realpath ../rethinkVM_bench/ycsb)
cd $YCSB_FOLDER


# loading phase
./bin/ycsb load memcached -s -P "workloads/workload${workload}" -p "memcached.hosts=127.0.0.1:${HOST_SERVER_PORT}" 2>&1 | tee ${OUT_BIN}.ycsb_LOAD.txt

sleep 2

# -q 0 means close the connection after sending the data
echo "start" |  nc 127.0.0.1 $HOST_LOGGING_CTL_PORT -q 0


# running phase
./bin/ycsb run memcached -s -P "workloads/workload${workload}" -p "memcached.hosts=127.0.0.1:${HOST_SERVER_PORT}" 2>&1 | tee ${OUT_BIN}.ycsb_RUN.txt

echo "end" |  nc 127.0.0.1 $HOST_LOGGING_CTL_PORT -q 0

sleep 20

kill -9 $qemu_script_pid
pgrep -f qemu-system-x86_64 | xargs kill

# pkill ../qemu_x86/build/qemu-system-x86_64
# pkill ../qemu_ECPT/build/qemu-system-x86_64