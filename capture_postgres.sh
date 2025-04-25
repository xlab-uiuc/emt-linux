#!/bin/bash
# set -x

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

workload=postgres26G

# PostgreSQL, by default, listens on port 5432 .
VM_SERVER_PORT=5432
HOST_SERVER_PORT=12024

VM_LOGGING_CTL_PORT=2025
HOST_LOGGING_CTL_PORT=12025

POSTGRESS_DIR="/pgsql/data"
POSTGRES_COMMAND="echo hello; \
su postgres -c 'cd ~; \
PATH=\$PATH:/usr/lib/postgresql/14/bin/; \
pwd; \
pg_ctl start -D $POSTGRESS_DIR -l $POSTGRESS_DIR/serverlog; \
cat $POSTGRESS_DIR/serverlog'"

EXTRA_COMMAND="ps aux | grep postgres; netstat -tuln | grep $VM_SERVER_PORT"
START_LOGGING_COMMAND="cd rethinkVM_bench; ./listen_and_start.sh ${VM_LOGGING_CTL_PORT}"



OUT_BIN="/data2/postgres/radix_never_run_${workload}.bin"
IMAGE_PATH="/data1/image_with_post_memcached_redis_50G.ext4"

# e2fsck -y $IMAGE_PATH

./run_linux_free_cmd --arch $ARCH --image $IMAGE_PATH \
    --out ${OUT_BIN} \
    --cmd "${POSTGRES_COMMAND}; ${EXTRA_COMMAND}; ${START_LOGGING_COMMAND}" \
    --vm_server_port ${VM_SERVER_PORT} \
    --host_server_port ${HOST_SERVER_PORT} \
    --vm_logging_ctl_port ${VM_LOGGING_CTL_PORT} \
    --host_logging_ctl_port ${HOST_LOGGING_CTL_PORT} &

qemu_script_pid=$!

sleep 120
qemu_pid=$(ps aux | grep qemu-system-x86_64 | grep 'build/qemu' | awk '{print $2}')
echo "qemu_pid: $qemu_pid"

# loading phase
# laoding phase should be 6672.153065/60.041583 * 800 
LOADING_TIME=40000
RUNNING_TIME=100
pgbench --client=10 --time=$LOADING_TIME -h 127.0.0.1 -p 12024 --username=postgres postgres 2>&1 | tee ${OUT_BIN}.pgbench_LOAD.txt

sleep 2

# # # -q 0 means close the connection after sending the data
echo "start" |  nc 127.0.0.1 $HOST_LOGGING_CTL_PORT -q 0
pgbench --client=10 --time=$RUNNING_TIME -h 127.0.0.1 -p 12024 --username=postgres postgres 2>&1 | tee ${OUT_BIN}.pgbench_RUN.txt
# PG_BENCH_PID=$!

# is_process_running() {
#     pgrep -x "$1" > /dev/null
# }

# # Loop to continuously check the status of the monitored process
# while true; do
#     if ! is_process_running "$qemu_pid"; then
#         echo "$qemu_pid is not running. Killing $PG_BENCH_PID."
#         pkill -x "$PG_BENCH_PID"
#         break
#     fi
#     sleep 5  # Adjust the sleep interval as needed
# done


# # # running phase
# # ./bin/ycsb run memcached -s -P "workloads/workload${workload}" -p "memcached.hosts=127.0.0.1:${HOST_SERVER_PORT}" 2>&1 | tee ${OUT_BIN}.ycsb_RUN.txt

echo "end" |  nc 127.0.0.1 $HOST_LOGGING_CTL_PORT -q 0

sleep 20

kill -9 $qemu_script_pid
pgrep -f qemu-system-x86_64 | xargs kill

# pkill ../qemu_x86/build/qemu-system-x86_64
# pkill ../qemu_ECPT/build/qemu-system-x86_64


# export POSTGRESS_DIR="/pgsql/data" PATH=$PATH:/usr/lib/postgresql/14/bin/