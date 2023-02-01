#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = openat(AT_FDCWD, "no_access.txt", O_WRONLY | O_APPEND);
    printf("fd is: %d\n", fd);
}