#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = openat(AT_FDCWD, "openat.txt", O_CREAT | O_WRONLY | O_TRUNC | O_EXCL);
    printf("fd is: %d\n", fd);
}