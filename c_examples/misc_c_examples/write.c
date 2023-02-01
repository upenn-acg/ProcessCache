#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    int bytes, fd;
    fd = open("yeah.txt", O_RDWR);
    bytes = write(fd, "I'm just writing stuff to this file right here  lalala\n", 56);
}