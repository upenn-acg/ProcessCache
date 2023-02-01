#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
    // int fd = openat(AT_FDCWD, "/home/kelly/research/IOTracker/multi_syscall_examples/openat.txt", O_CREAT | O_WRONLY | O_TRUNC);
    int fd = creat("/home/kelly/research/IOTracker/multi_syscall_examples/creat_file.txt", S_IRWXU | S_IRWXG | S_IRWXO);
    close(fd);
    struct stat buf;
    int ret_val; 
    ret_val = stat("/home/kelly/research/IOTracker/multi_syscall_examples/creat_file.txt", &buf);
}