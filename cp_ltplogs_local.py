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

def get_breakdown(breakdown_path):
    total_tests = None
    total_skipped_tests = None
    total_failures = None
    with open(breakdown_path, 'r') as file:
        for line in file:
            if line.startswith("Total Tests:"):
                total_tests = int(line.split()[-1])
            elif line.startswith("Total Skipped Tests:"):
                total_skipped_tests = int(line.split()[-1])
            elif line.startswith("Total Failures:"):
                total_failures = int(line.split()[-1])

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

if __name__ == "__main__":
    
    # syscalls=[
    #     "abort",
    #     "accept",
    #     "shmdt",
    #     "shmget",
    #     "kcmp",
    #     "keyctl",
    # ]

    image_to_mount = mount_all_images('/home/siyuan/small_image_reps')

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
    if not os.path.exists(local_folder):
        os.mkdir(local_folder)

    print("# of syscalls: ", len(syscalls))

    for syscall in syscalls:
        file_path = f"syscall_logs/{syscall}_ecpt.log"
        breakdown_path = get_breakdown_path(syscall, file_path, image_to_mount)
        
        shutil.copy(breakdown_path, local_folder)
        local_breakdown_path = os.path.join(local_folder, f'{syscall}-result.log')

        if not os.path.exists(local_breakdown_path):
            print(f'The file {local_breakdown_path} does not exist.')

    umount_all_images(image_to_mount)

    
    