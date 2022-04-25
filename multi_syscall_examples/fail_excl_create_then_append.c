#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = openat(AT_FDCWD, "/home/kelly/research/IOTracker/open_syscall_examples/excl.txt", O_WRONLY | O_CREAT | O_EXCL);
    int fd2 = openat(AT_FDCWD, "/home/kelly/research/IOTracker/open_syscall_examples/excl.txt", O_WRONLY | O_APPEND);
}