#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd1, bytes;
    // Program opens file for reading.
    fd1 = openat(AT_FDCWD, "/home/kelly/research/IOTracker/misc_c_examples/file3.txt", O_WRONLY | O_APPEND);
    char buf[7];
    // Program reads some crap in.
    bytes = write(fd1, "I'm just writing stuff to this file right here  lalala\n", 56);
    return 0;
}