#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd1, fd2, bytes_read, bytes_written;
    // Program opens file for reading.
    fd1 = openat(AT_FDCWD, "file1.txt", O_RDONLY);
    char buf[7];
    // Program reads some crap in.
    bytes_read = read(fd1, &buf, 7);
    return 0;
}