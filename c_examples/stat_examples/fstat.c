#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
    struct stat buf;
    int fd, status;

    fd = openat(AT_FDCWD, "fstat.txt", O_RDONLY);
    // int fd = open("/home/kelly/research/IOTracker/open.txt", O_RDONLY);
    status = fstat(fd, &buf);
    printf("status is %d\n", status);
}