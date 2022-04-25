#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    int bytes, fd, fd2;
    char* buf;
    fd = open("yeah.txt", O_RDONLY);

    bytes = read(fd, &buf, 6);
    fd2 = openat(AT_FDCWD, "new.txt", O_CREAT | O_WRONLY | O_TRUNC);
    return 0;
}