#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    // int bytes, fd;
    // fd = open("yeah.txt", O_RDWR);
    // bytes = write(fd, "I'm just writing stuff to this file right here  lalala\n", 56);

    int fd1, fd2, bytes_read, bytes_written;
    // Program opens file for reading.
    fd1 = openat(AT_FDCWD, "file1.txt", O_RDONLY);
    char buf[7];
    // Program reads some crap in.
    bytes_read = read(fd1, &buf, 7);


    // These flags match a creat() call
    fd2 = openat(AT_FDCWD, "file2.txt", O_CREAT | O_WRONLY | O_TRUNC);
    bytes_written = write(fd2, "hello\n", 7);
} 