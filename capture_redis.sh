#!/bin/bash
set -x

# workload=4G
# ./run_radix_execlog_redis --image /data1/images/image.ext4 --redis_workload $workload --out /data1/redis_run_data/redis_run_${workload}.bin &

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

workload=20G
./run_linux_free_cmd --arch $ARCH --image /data1/images/image_1.ext4 --redis_workload $workload \
    --out /data1/redis_run_data/${ARCH}_never_redis_run_${workload}.bin \
    --cmd "cd YCSB_CXL_Test; ./run_redis.sh ${workload} local 120000 output_experiment3/output_remote;" &
wait
# workload=tiny
# ./run_ECPT_execlog_redis --image /data1/images/image_2.ext4 --redis_workload $workload --out /data1/redis_run_data/ecpt_never_redis_run_${workload}.bin &


# workload=20G
# ./run_ECPT_execlog_redis --image /data1/images/image_3.ext4 --redis_workload $workload --out /data1/redis_run_data/ecpt_never_redis_run_${workload}.bin &

# wait

# [#1] 0xffffffff81222e61 → walk_pud_range(p4d=<optimized out>, walk=0xffffc90000c0fcf0, end=0x7fcc17178000, addr=0x7fcc17177000)
# [#2] 0xffffffff81222e61 → walk_p4d_range(pgd=<optimized out>, walk=0xffffc90000c0fcf0, end=0x7fcc17178000, addr=0x7fcc17177000)
# [#3] 0xffffffff81222e61 → walk_pgd_range(walk=0xffffc90000c0fcf0, end=0x7fcc17178000, addr=0x7fcc17177000)
# [#4] 0xffffffff81222e61 → __walk_page_range(start=0x7fcc17177000, end=0x7fcc17178000, walk=0xffffc90000c0fcf0)
# [#5] 0xffffffff812234c8 → walk_page_range(mm=<optimized out>, start=0x7fcc17177000, end=0x7fcc17178000, ops=0xffffffff8244c420 <madvise_free_walk_ops>, private=0xffffc90000c0fd80)
# [#6] 0xffffffff812361ec → madvise_free_single_vma(vma=0xffff888104fecd80, start_addr=0x7fcc17177000, end_addr=0x7fcc17178000)
# [#7] 0xffffffff81236a31 → madvise_dontneed_free(behavior=0x8, end=<optimized out>, start=0x7fcc17177000, prev=0xffffc90000c0fe68, vma=0xffff888104fecd80)
# [#8] 0xffffffff81236a31 → madvise_vma(behavior=0x8, end=<optimized out>, start=0x7fcc17177000, prev=0xffffc90000c0fe68, vma=0xffff888104fecd80)
# [#9] 0xffffffff81236a31 → do_madvise(mm=0xffff888100289100, start=0x7fcc17177000, len_in=<optimized out>, behavior=0x8)
