#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = openat(AT_FDCWD, "created_file.txt", O_WRONLY | O_TRUNC | O_CREAT);
    printf("fd is: %d\n", fd);
}