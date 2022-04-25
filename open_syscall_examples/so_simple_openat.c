#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = openat(AT_FDCWD, "yeah.txt", O_RDWR);
    // printf("fd is: %d\n", fd);

    int fd2 = openat(AT_FDCWD, "yeah2.txt", O_RDONLY);
    // printf("fd is: %d\n", fd2);
    
    int fd3 = openat(AT_FDCWD, "yeah3.txt", O_WRONLY);
    // printf("fd is: %d\n", fd3);
}