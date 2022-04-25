#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
    int fd = creat("/home/kelly/research/IOTracker/multi_syscall_examples/openat.txt", S_IRWXU | S_IRWXG | S_IRWXO);
    struct stat buf;
    int ret_val; 
        ret_val = stat("/home/kelly/research/IOTracker/multi_syscall_examples/openat.txt", &buf);

    int fd2 = openat(AT_FDCWD, "/home/kelly/research/IOTracker/multi_syscall_examples/openat.txt", O_CREAT | O_WRONLY | O_TRUNC);
}