#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    // int fd = openat(AT_FDCWD, "file_does_not_exist.txt", O_WRONLY | O_APPEND);
    int fd = openat(AT_FDCWD, "file_does_not_exist.txt", O_WRONLY | O_TRUNC);

    printf("fd is: %d\n", fd);
}