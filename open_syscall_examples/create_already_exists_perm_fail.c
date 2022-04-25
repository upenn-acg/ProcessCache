#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = openat(AT_FDCWD, "/home/kelly/research/IOTracker/open_syscall_examples/you_shall_not_pass/file.txt", O_WRONLY | O_APPEND);
    printf("fd is: %d\n", fd);
}