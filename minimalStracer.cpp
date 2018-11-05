#include <assert.h>
#include <sys/ptrace.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/user.h>

#include <unordered_map>

using namespace std;

void handle_fork(pid_t pid);

const int SYSTEM_CALL_COUNT = 326;
/**
  * A list of system calls. This was compiled from the header file:
  * /usr/include/x86_64-linux-gnu/bits/syscall.h on Ubuntu 16.04 LTS,
  * Kernel version: 4.4.0-93-generic
  */
const char* systemCallMappings[SYSTEM_CALL_COUNT] = {
  "read",
  "write",
  "open",
  "close",
  "stat",
  "fstat",
  "lstat",
  "poll",
  "lseek",
  "mmap",
  "mprotect",
  "munmap",
  "brk",
  "rt_sigaction",
  "rt_sigprocmask",
  "rt_sigreturn",
  "ioctl",
  "pread64",
  "pwrite64",
  "readv",
  "writev",
  "access",
  "pipe",
  "select",
  "sched_yield",
  "mremap",
  "msync",
  "mincore",
  "madvise",
  "shmget",
  "shmat",
  "shmctl",
  "dup",
  "dup2",
  "pause",
  "nanosleep",
  "getitimer",
  "alarm",
  "setitimer",
  "getpid",
  "sendfile",
  "socket",
  "connect",
  "accept",
  "sendto",
  "recvfrom",
  "sendmsg",
  "recvmsg",
  "shutdown",
  "bind",
  "listen",
  "getsockname",
  "getpeername",
  "socketpair",
  "setsockopt",
  "getsockopt",
  "clone",
  "fork",
  "vfork",
  "execve",
  "exit",
  "wait4",
  "kill",
  "uname",
  "semget",
  "semop",
  "semctl",
  "shmdt",
  "msgget",
  "msgsnd",
  "msgrcv",
  "msgctl",
  "fcntl",
  "flock",
  "fsync",
  "fdatasync",
  "truncate",
  "ftruncate",
  "getdents",
  "getcwd",
  "chdir",
  "fchdir",
  "rename",
  "mkdir",
  "rmdir",
  "creat",
  "link",
  "unlink",
  "symlink",
  "readlink",
  "chmod",
  "fchmod",
  "chown",
  "fchown",
  "lchown",
  "umask",
  "gettimeofday",
  "getrlimit",
  "getrusage",
  "sysinfo",
  "times",
  "ptrace",
  "getuid",
  "syslog",
  "getgid",
  "setuid",
  "setgid",
  "geteuid",
  "getegid",
  "setpgid",
  "getppid",
  "getpgrp",
  "setsid",
  "setreuid",
  "setregid",
  "getgroups",
  "setgroups",
  "setresuid",
  "getresuid",
  "setresgid",
  "getresgid",
  "getpgid",
  "setfsuid",
  "setfsgid",
  "getsid",
  "capget",
  "capset",
  "rt_sigpending",
  "rt_sigtimedwait",
  "rt_sigqueueinfo",
  "rt_sigsuspend",
  "sigaltstack",
  "utime",
  "mknod",
  "uselib",
  "personality",
  "ustat",
  "statfs",
  "fstatfs",
  "sysfs",
  "getpriority",
  "setpriority",
  "sched_setparam",
  "sched_getparam",
  "sched_setscheduler",
  "sched_getscheduler",
  "sched_get_priority_max",
  "sched_get_priority_min",
  "sched_rr_get_interval",
  "mlock",
  "munlock",
  "mlockall",
  "munlockall",
  "vhangup",
  "modify_ldt",
  "pivot_root",
  "_sysctl",
  "prctl",
  "arch_prctl",
  "adjtimex",
  "setrlimit",
  "chroot",
  "sync",
  "acct",
  "settimeofday",
  "mount",
  "umount2",
  "swapon",
  "swapoff",
  "reboot",
  "sethostname",
  "setdomainname",
  "iopl",
  "ioperm",
  "create_module",
  "init_module",
  "delete_module",
  "get_kernel_syms",
  "query_module",
  "quotactl",
  "nfsservctl",
  "getpmsg",
  "putpmsg",
  "afs_syscall",
  "tuxcall",
  "security",
  "gettid",
  "readahead",
  "setxattr",
  "lsetxattr",
  "fsetxattr",
  "getxattr",
  "lgetxattr",
  "fgetxattr",
  "listxattr",
  "llistxattr",
  "flistxattr",
  "removexattr",
  "lremovexattr",
  "fremovexattr",
  "tkill",
  "time",
  "futex",
  "sched_setaffinity",
  "sched_getaffinity",
  "set_thread_area",
  "io_setup",
  "io_destroy",
  "io_getevents",
  "io_submit",
  "io_cancel",
  "get_thread_area",
  "lookup_dcookie",
  "epoll_create",
  "epoll_ctl_old",
  "epoll_wait_old",
  "remap_file_pages",
  "getdents64",
  "set_tid_address",
  "restart_syscall",
  "semtimedop",
  "fadvise64",
  "timer_create",
  "timer_settime",
  "timer_gettime",
  "timer_getoverrun",
  "timer_delete",
  "clock_settime",
  "clock_gettime",
  "clock_getres",
  "clock_nanosleep",
  "exit_group",
  "epoll_wait",
  "epoll_ctl",
  "tgkill",
  "utimes",
  "vserver",
  "mbind",
  "set_mempolicy",
  "get_mempolicy",
  "mq_open",
  "mq_unlink",
  "mq_timedsend",
  "mq_timedreceive",
  "mq_notify",
  "mq_getsetattr",
  "kexec_load",
  "waitid",
  "add_key",
  "request_key",
  "keyctl",
  "ioprio_set",
  "ioprio_get",
  "inotify_init",
  "inotify_add_watch",
  "inotify_rm_watch",
  "migrate_pages",
  "openat",
  "mkdirat",
  "mknodat",
  "fchownat",
  "futimesat",
  "newfstatat",
  "unlinkat",
  "renameat",
  "linkat",
  "symlinkat",
  "readlinkat",
  "fchmodat",
  "faccessat",
  "pselect6",
  "ppoll",
  "unshare",
  "set_robust_list",
  "get_robust_list",
  "splice",
  "tee",
  "sync_file_range",
  "vmsplice",
  "move_pages",
  "utimensat",
  "epoll_pwait",
  "signalfd",
  "timerfd_create",
  "eventfd",
  "fallocate",
  "timerfd_settime",
  "timerfd_gettime",
  "accept4",
  "signalfd4",
  "eventfd2",
  "epoll_create1",
  "dup3",
  "pipe2",
  "inotify_init1",
  "preadv",
  "pwritev",
  "rt_tgsigqueueinfo",
  "perf_event_open",
  "recvmmsg",
  "fanotify_init",
  "fanotify_mark",
  "prlimit64",
  "name_to_handle_at",
  "open_by_handle_at",
  "clock_adjtime",
  "syncfs",
  "sendmmsg",
  "setns",
  "getcpu",
  "process_vm_readv",
  "process_vm_writev",
  "kcmp",
  "finit_module",
  "sched_setattr",
  "sched_getattr",
  "renameat2",
  "seccomp",
  "getrandom",
  "memfd_create",
  "kexec_file_load",
  "bpf",
  "execveat",
  "userfaultfd",
  "membarrier",
  "mlock2"};


int isPtraceEvent(int status, enum __ptrace_eventcodes event){
  return (status >> 8) == (SIGTRAP | (event << 8));
}

int check(char* name, int retval){
  if(retval == -1){
    fprintf(stderr, "%s check error: %s\n", name, strerror(errno));
    exit(1);
  }
  return retval;
}

int main(){

  pid_t childPid = check("fork", fork());
  if(childPid == 0){
    // Child
    check("ptraceme", ptrace(PTRACE_TRACEME, 0, NULL, NULL) );

    // Wait for parent
    check("raise", raise(SIGSTOP) );
    char* argv[] = {"./forkBug", NULL};
    check("execvp", execvp(argv[0], argv) );
  }else{

    unordered_map<pid_t, bool> prehook_status;
    prehook_status.insert(make_pair(childPid, true));

    // Parent
    check("initial waitpid", waitpid(childPid, NULL, 0) );
    check("ptrace options", ptrace(PTRACE_SETOPTIONS, childPid, NULL, (void*)
              (PTRACE_O_EXITKILL | // If Tracer exits. Send SIGKIll signal to all tracees.
               PTRACE_O_TRACECLONE | // enroll child of tracee when clone is called.
               // We don't really need to catch execves, but we get a spurious signal 5
               // from ptrace if we don't.
               PTRACE_O_TRACEEXEC |
               PTRACE_O_TRACEFORK |
               PTRACE_O_TRACEVFORK |
               // Stop tracee right as it is about to exit. This is needed as we cannot
               // assume WIFEXITED will work, see man ptrace 2.
               PTRACE_O_TRACEEXIT |
               PTRACE_O_TRACESYSGOOD
               )) );

    // Start off loop with initial event.
    check("init ptrace", ptrace(PTRACE_SYSCALL, childPid, 0, NULL) );

    // Seen processes:
    int seenProcs = 1;

    // Number of live processes...
    int liveProcs = 1;


    while(1){
      int64_t signalToDeliver = 0;
      int status;
      pid_t currentChild = check("waitpid any process/no more children",
                                 waitpid(-1, &status, 0) );

      // Tracee has exited.
      if (WIFEXITED(status)){
        printf("[%d] True exit!\n", currentChild);
        liveProcs--;
        if(liveProcs == 0){
          printf("All done!\n");
          break;
        }else{
          continue;
        }
      } else

      // Condition for PTRACE_O_TRACEEXEC
      if( isPtraceEvent(status, PTRACE_EVENT_EXEC) ){
        printf("[%d] Saw exec event!\n", currentChild);
      } else

      // Even though fork() is clone under the hood, any time that clone is used with
      // SIGCHLD, ptrace calls that event a fork *sigh*.
      // Also requires PTRACE_O_FORK flag.
      if( isPtraceEvent(status, PTRACE_EVENT_VFORK) ||
          isPtraceEvent(status, PTRACE_EVENT_FORK)  ||
          isPtraceEvent(status, PTRACE_EVENT_CLONE)){
        printf("[%d] Should never see event out here!\n", currentChild);
        exit(1);
      } else

      if( isPtraceEvent(status, PTRACE_EVENT_EXIT) ){
        printf("[%d] Exit event!\n", currentChild);
      } else

      // This is a stop caused by a system call exit-pre/exit-post.
      // Check if WIFSTOPPED return true,
      // if yes, compare signal number to SIGTRAP | 0x80 (see ptrace(2)).
      if(WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80)) ){

        if (prehook_status.at(currentChild)){
          user_regs_struct regs;
          check("get regs", ptrace(PTRACE_GETREGS, currentChild, NULL, & regs));
          int syscall = regs.orig_rax;

          const char* syscallName = systemCallMappings[syscall];
          printf("[%d] Intercepted: %s!\n", currentChild, syscallName);

          if(syscallName == "fork" || syscallName == "clone" || syscallName == "vfork"){
            handle_fork(currentChild);
          }
        }else{
          printf("[%d] Post-hook...\n", currentChild);
        }

        prehook_status.at(currentChild) = ! prehook_status.at(currentChild);
      } else

      // Check if we intercepted a signal before it was delivered to the child.
      if(WIFSTOPPED(status)){
        signalToDeliver = WSTOPSIG(status);
        printf("[%d] Saw signal %ld\n", currentChild, signalToDeliver);
      } else

      // Check if the child was terminated by a signal. This can happen after when we,
      //the tracer, intercept a signal of the tracee and deliver it.
      if(WIFSIGNALED(status)){

      } else {
        fprintf(stderr, "Uknown event %d\n", status);
        exit(1);
      }


      check("ptrace systecall",
            ptrace(PTRACE_SYSCALL, currentChild, 0, (void*) signalToDeliver) );
    }

    printf("Total seen procs: %d\n", seenProcs);
  }


  return 0;
}

void handle_fork(pid_t pid){
  printf("Handle for event!\n");
  // Let this process continue.
  check("ptrace systecall", ptrace(PTRACE_SYSCALL, pid, 0, 0 ));

  // We expect a ptrace clone/fork/vfork event from parent, and a singal from child.
  int status;
  pid_t newPid = check( "wait for fork event", waitpid(pid, &status, 0) );
  assert(newPid == pid);

  if( isPtraceEvent(status, PTRACE_EVENT_VFORK) ||
      isPtraceEvent(status, PTRACE_EVENT_FORK)  ||
      isPtraceEvent(status, PTRACE_EVENT_CLONE)){
    printf("Got forking ptrace event!\n");

    // Get pid and wait for child signal.
    long event;
    check( "get ptrace message", ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &event) );

    pid_t newChild = event;
    printf("New child spawned w/ pid: %d\n", newChild);

    // Wait for signal from child.

    pid_t ch = check("wait for signal", waitpid(newChild, &status, 0) );
    assert(ch == newChild);

    // Expect a singal event!
      if(WIFSTOPPED(status)){
        int signal = WSTOPSIG(status);
        printf("[%d] Saw signal %d\n", newChild, signal);
      }
  }else{
    printf("Unkown event!\n");
    exit(1);
  }
}
