import glob
import os
import shutil
import subprocess
import numpy as np
import pandas as pd

syscalls=[
    "abort",
    "accept",
    "accept4",
    "access",
    "acct",
    "add_key",
    "adjtimex",
    "alarm",
    "bind",
    "bpf",
    "brk",
    "cacheflush",
    "capget",
    "capset",
    "chdir",
    "chmod",
    "chown",
    "chroot",
    "clock_adjtime",
    "clock_getres",
    "clock_gettime",
    "clock_nanosleep",
    "clock_settime",
    "clone",
    "clone3",
    "close",
    "close_range",
    "process_vm_readv",
    "process_vm_writev",
    "confstr",
    "connect",
    "copy_file_range",
    "creat",
    "delete_module",
    "dup",
    "dup2",
    "dup3",
    "epoll",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_wait",
    "eventfd",
    "eventfd2",
    "execl",
    "execle",
    "execlp",
    "execv",
    "execve",
    "execveat",
    "execvp",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fadvise",
    "fallocate",
    "fanotify",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fchown",
    "fchownat",
    "fcntl",
    "fdatasync",
    "fgetxattr",
    "finit_module",
    "flistxattr",
    "flock",
    "fmtmsg",
    "fork",
    "fpathconf",
    "fremovexattr",
    "fsconfig",
    "fsetxattr",
    "fsmount",
    "fsopen",
    "fspick",
    "fstat",
    "fstatat",
    "fstatfs",
    "fsync",
    "ftruncate",
    "futex",
    "futimesat",
    "getcontext",
    "getcpu",
    "getcwd",
    "getdents",
    "getdomainname",
    "getdtablesize",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "gethostbyname_r",
    "gethostid",
    "gethostname",
    "getitimer",
    "get_mempolicy",
    "getpagesize",
    "getpeername",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getpriority",
    "getrandom",
    "getresgid",
    "getresuid",
    "getrlimit",
    "get_robust_list",
    "getrusage",
    "getsid",
    "getsockname",
    "getsockopt",
    "gettid",
    "gettimeofday",
    "getuid",
    "getxattr",
    "init_module",
    "inotify",
    "inotify_init",
    "io_cancel",
    "ioctl",
    "io_destroy",
    "io_getevents",
    "ioperm",
    "io_pgetevents",
    "iopl",
    "ioprio",
    "io_setup",
    "io_submit",
    "io_uring",
    "msgctl",
    "msgget",
    "msgrcv",
    "msgsnd",
    "msgstress",
    "semctl",
    "semget",
    "semop",
    "shmat",
    "shmctl",
    "shmdt",
    "shmget",
    "kcmp",
    "keyctl",
    "kill",
    "lchown",
    "lgetxattr",
    "link",
    "linkat",
    "listen",
    "listxattr",
    "llistxattr",
    "llseek",
    "lremovexattr",
    "lseek",
    "lstat",
    "madvise",
    "mallinfo",
    "mallinfo2",
    "mallopt",
    "mbind",
    "membarrier",
    "memcmp",
    "memcpy",
    "memfd_create",
    "memset",
    "migrate_pages",
    "mincore",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "mlock",
    "mlock2",
    "mlockall",
    "mmap",
    "modify_ldt",
    "mount",
    "mount_setattr",
    "move_mount",
    "move_pages",
    "mprotect",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedsend",
    "mq_unlink",
    "mremap",
    "msync",
    "munlock",
    "munlockall",
    "munmap",
    "name_to_handle_at",
    "nanosleep",
    "newuname",
    "nftw",
    "nice",
    "open",
    "openat",
    "openat2",
    "open_by_handle_at",
    "open_tree",
    "pathconf",
    "pause",
    "perf_event_open",
    "personality",
    "pidfd_getfd",
    "pidfd_open",
    "pidfd_send_signal",
    "pipe",
    "pipe2",
    "pivot_root",
    "pkeys",
    "poll",
    "ppoll",
    "prctl",
    "pread",
    "preadv",
    "preadv2",
    "process_madvise",
    "profil",
    "pselect",
    "ptrace",
    "pwrite",
    "pwritev",
    "pwritev2",
    "quotactl",
    "read",
    "readahead",
    "readdir",
    "readlink",
    "readlinkat",
    "readv",
    "realpath",
    "reboot",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmsg",
    "remap_file_pages",
    "removexattr",
    "rename",
    "renameat",
    "renameat2",
    "request_key",
    "rmdir",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigqueueinfo",
    "rt_sigsuspend",
    "rt_sigtimedwait",
    "rt_tgsigqueueinfo",
    "sbrk",
    "sched_getaffinity",
    "sched_getattr",
    "sched_getparam",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_getscheduler",
    "sched_rr_get_interval",
    "sched_setaffinity",
    "sched_setattr",
    "sched_setparam",
    "sched_setscheduler",
    "sched_yield",
    "select",
    "send",
    "sendfile",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "setdomainname",
    "setegid",
    "setfsgid",
    "setfsuid",
    "setgid",
    "setgroups",
    "sethostname",
    "setitimer",
    "set_mempolicy",
    "setns",
    "setpgid",
    "setpgrp",
    "setpriority",
    "setregid",
    "setresgid",
    "setresuid",
    "setreuid",
    "setrlimit",
    "set_robust_list",
    "setsid",
    "setsockopt",
    "set_thread_area",
    "set_tid_address",
    "settimeofday",
    "setuid",
    "setxattr",
    "sgetmask",
    "sigaction",
    "sigaltstack",
    "sighold",
    "signal",
    "signalfd",
    "signalfd4",
    "sigpending",
    "sigprocmask",
    "sigrelse",
    "sigsuspend",
    "sigtimedwait",
    "sigwait",
    "sigwaitinfo",
    "socket",
    "socketcall",
    "socketpair",
    "sockioctl",
    "splice",
    "ssetmask",
    "stat",
    "statfs",
    "statvfs",
    "statx",
    "stime",
    "string",
    "swapoff",
    "swapon",
    "switch",
    "symlink",
    "symlinkat",
    "sync",
    "sync_file_range",
    "syncfs",
    "syscall",
    "sysconf",
    "sysctl",
    "sysfs",
    "sysinfo",
    "syslog",
    "tee",
    "tgkill",
    "time",
    "timer_create",
    "timer_delete",
    "timerfd",
    "timer_getoverrun",
    "timer_gettime",
    "timer_settime",
    "times",
    "tkill",
    "truncate",
    "ulimit",
    "umask",
    "umount",
    "umount2",
    "uname",
    "unlink",
    "unlinkat",
    "unshare",
    "userfaultfd",
    "ustat",
    "utime",
    "utimensat",
    "utimes",
    "vfork",
    "vhangup",
    "vmsplice",
    "wait",
    "wait4",
    "waitid",
    "waitpid",
    "write",
    "writev",
]

def mount_image(image_name, mount_path):
    # WARNING: Image format was not specified for '/home/siyuan/small_image_reps/image.ext4_rep2' and probing guessed raw.
    # extract image in quote
    # image_path = image_name.split("'")[1]
    # mount image to mount_path
    # os.system(f"mount -o loop {image_path} {mount_path}")
    command = f'mount -o loop {image_name} {mount_path}'
    try:
    # Execute the mount command
        subprocess.run(command, shell=True, check=True)
        print(f"Image '{image_name}' mounted at '{mount_path}' successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error mounting image: {e}")

def mount_all_images(folder_path):
    # mount all images in image_folder
    file_list = glob.glob(os.path.join(folder_path, '*'))
    image_to_mount = {}
    for file in file_list:
        image_name = os.path.join(folder_path, file)
        image_idx = file.split('_')[-1]
        mount_path = f'/mnt/image_{image_idx}'
        mount_image(image_name, mount_path)
        image_to_mount[image_name] = mount_path
    return image_to_mount

def umount_all_images(image_to_mount):
    for mount_path in image_to_mount.values():
        command = f'umount {mount_path}'
        try:
            subprocess.run(command, shell=True, check=True)
            print(f"Image at '{mount_path}' unmounted successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error unmounting image: {e}")

def get_image_path(first_line):
    # WARNING: Image format was not specified for '/home/siyuan/small_image_reps/image.ext4_rep2' and probing guessed raw.
    # extract image in quote
    image_path = first_line.split("'")[1]
    return image_path

def get_mount_path(log_path, image_to_mount):
    first_line = ""
    with open(log_path, 'r') as file:
    # Read the first line
        first_line = file.readline()

    image_path = get_image_path(first_line)

    if image_path in image_to_mount:
        return image_to_mount[image_path]
    else:
        print(f"Image not found: {image_path}")
        return "No Image Found"

def get_breakdown_path(syscall, log_path, image_to_mount):
    mount_path = get_mount_path(log_path, image_to_mount)
    return os.path.join(mount_path, 'opt', 'ltp', 'results', f'{syscall}-result.log')

def get_breakdown(breakdown_path, test_to_result, duplicates):
    total_tests = None
    total_skipped_tests = None
    total_failures = None
    
    pass_count = 0
    fail_count = 0
    conf_count = 0

    with open(breakdown_path, 'r') as file:
        lines = file.readlines()

    # only account for the last test result
    for line in reversed(lines):
        if 'Testcase' in line:
            break

        if line.startswith("Total Tests:"):
            total_tests = int(line.split()[-1])
        elif line.startswith("Total Skipped Tests:"):
            total_skipped_tests = int(line.split()[-1])
        elif line.startswith("Total Failures:"):
            total_failures = int(line.split()[-1])

        if 'PASS' in line or 'FAIL' in line or 'CONF' in line:
            # Split the line into columns
            columns = line.split()
            # Extract test name (first column) and result (second column)
            test_name = columns[0].strip()
            test_result = columns[1].strip()
            # Append test name and result to the respective lists

            if test_result == 'PASS':
                pass_count += 1
            elif test_result == 'FAIL':
                fail_count += 1
            elif test_result == 'CONF':
                conf_count += 1

            if test_name in test_to_result:
                duplicates.append(test_name)
                print(f"Duplicate test name: {test_name}")

            test_to_result[test_name] = test_result

    if total_tests is None:
        print(f"{breakdown_path}: Total Tests not found")
        total_tests = 0
    
    if total_skipped_tests is None:
        print(f"{breakdown_path}: Total Skipped Tests not found")
        total_skipped_tests = 0
    
    if total_failures is None:
        print(f"{breakdown_path}: Total Failures not found")
        total_failures = 0

    total_passed = total_tests - total_skipped_tests - total_failures
    total_run = total_passed + total_failures
    
    # warning if the total number of tests does not match the sum of the test results
    if pass_count != total_passed:
        print(f"Pass count mismatch {syscall}: {pass_count} != {total_passed}")
    if fail_count != total_failures:
        print(f"Fail count mismatch {syscall}: {fail_count} != {total_failures}")
    if conf_count != total_skipped_tests:
        print(f"Conf count mismatch {syscall}: {conf_count} != {total_skipped_tests}")

    return total_run, total_passed, total_failures, total_skipped_tests

def parse_syscall_log(log_path):
    allpass = "all tests PASS"
    somefail = "some tests FAIL"
    wrongTestMatching = "Must supply a file collection or a command"
    panic = "Kernel panic"
    try:
        with open(log_path, 'r') as file:
            for line in file:
                if allpass in line:
                    return "All Pass"
                if wrongTestMatching in line:
                    return "No Test Matched" 
                if somefail in line:
                    return "Some Fail"
                if panic in line:
                    return "Fail: Kernel Panic"
            return "No Info"
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return "No Log File"

def delete_non_classic_syscalls(df):
    indices_to_delete = ["prot_hsymlinks", "dirtyc0w", "dirtyc0w_shmem", "dirtypipe"] # Replace with the indices you want to delete
    return df.drop(indices_to_delete)

def get_difference(ecpt_result, vanilla_result):
    ecpt = pd.DataFrame(ecpt_result.values(), index=ecpt_result.keys())
    ecpt = ecpt.sort_index()
    vanilla = pd.DataFrame(vanilla_result.values(), index=vanilla_result.keys())
    vanilla = vanilla.sort_index()
    # print(ecpt.head(10))
    # print(vanilla.head(10))

    df_merged = pd.concat([ecpt, vanilla], axis=1)
    df_merged.columns = ['ecpt', 'vanilla']
    df_merged['Need Fix'] = (df_merged['ecpt'] != df_merged['vanilla']) & (df_merged['vanilla'] != 'FAIL')
    df_merged['Urgent Attention'] = ((df_merged['ecpt'] == 'FAIL') | (df_merged['ecpt'] == '')) & (df_merged['vanilla'] != 'FAIL')

    df_merged = delete_non_classic_syscalls(df_merged)

    

    saved_path = "syscall_logs/syscall_diff.csv"
    print("save to ", saved_path)
    df_merged.to_csv(saved_path)

    print(df_merged[df_merged['Urgent Attention'] == True].to_csv('syscall_logs/urgent_attention.csv'))
if __name__ == "__main__":
    
    results = []
    data = {
        'syscalls': [],
        'result': [],
        'n_run': [],
        'n_passed': [],
        'n_failed': [],
        'n_skipped': [],
    }

    local_folder = 'syscall_logs/ltp'

    test_to_result = {}
    duplicates = []
    for syscall in syscalls:
        file_path = f"syscall_logs/{syscall}_ecpt.log"
        
        local_breakdown_path = os.path.join(local_folder, f'{syscall}-result.log')

        # print(f'Parsing {syscall} {breakdown_path}')
        result = parse_syscall_log(file_path)
        # print(f'{syscall}: {result}')
        # if "Panic" in result or "No Info" in result:
        #     n_run, n_passed, n_failed, n_skipped = 0, 0, 0, 0
        #     print(f"no breakdown {syscall} {result}")
        # else:
        n_run, n_passed, n_failed, n_skipped = get_breakdown(local_breakdown_path, test_to_result, duplicates)
            

        data['syscalls'].append(syscall)
        data['result'].append(result)
        data['n_run'].append(n_run)
        data['n_passed'].append(n_passed)
        data['n_failed'].append(n_failed)
        data['n_skipped'].append(n_skipped)

    
    print("n test cases: ", len(test_to_result))
    print("n ran: ", len([result for result in test_to_result.values() if result != 'CONF']))
    print("n passed: ", len([result for result in test_to_result.values() if result == 'PASS']))
    print("n failed: ", len([result for result in test_to_result.values() if result == 'FAIL']))
    print("n skipped: ", len([result for result in test_to_result.values() if result == 'CONF']))

    print("n duplicates: ", len(duplicates))

    df = pd.DataFrame(data)
    columns_to_sum = ['n_run', 'n_passed', 'n_failed', 'n_skipped']
    sums = np.array(df[columns_to_sum].sum())
    # df.loc['Total'] = np.append('Total', sums)
    total_stats = np.array(['Total', '', *sums])
    print(total_stats)
    
    df.loc[len(df)] = total_stats

    # print(df.tail())
    df.to_csv("syscall_logs/syscall_results.csv", index=False)

    vanilla_path = "/home/siyuan/linux_vanilla_sim/vanilla-result.log"
    vanilla_test_to_result = {}
    get_breakdown(vanilla_path, vanilla_test_to_result, [])

    get_difference(test_to_result, vanilla_test_to_result)

    
    