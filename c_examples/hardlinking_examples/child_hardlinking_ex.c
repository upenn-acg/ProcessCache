#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>


int main() {
    int fd1 = openat(AT_FDCWD, "bar.txt", O_CREAT| O_WRONLY | O_TRUNC);
    printf("child\n");
    return 0;
}