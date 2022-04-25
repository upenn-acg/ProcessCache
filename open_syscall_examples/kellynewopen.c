#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main() {
    int fd = open("/home/kelly/research/IOTracker/open.txt", O_CREAT | O_WRONLY | O_TRUNC);
    // printf("fd is: %d\n", fd);

    // int errnum;
    // errnum = errno;
    // fprintf(stderr, "Value of errno: %d\n", errno);
    // perror("Error printed by perror");
    // fprintf(stderr, "Error opening file: %s\n", strerror( errnum ));
}