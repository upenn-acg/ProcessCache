#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
int main() {
    int fd1, fd2, bytes_read, bytes_written;
    // Program opens file for reading.
    fd1 = openat(AT_FDCWD, "file1.txt", O_RDONLY);
    char buf[7];
    // Program reads some crap in.
    bytes_read = read(fd1, &buf, 7);

    if (fork() == 0) {
        char* args[] = {"./IOTracker/misc_c_examples/write_file2", NULL};
        if (fork() == 0) {
            char* args[] = {"./IOTracker/misc_c_examples/write_file3", NULL};
            execvp("./IOTracker/misc_c_examples/write_file3", args);
            exit(EXIT_SUCCESS);
        }
        execvp("./IOTracker/misc_c_examples/write_file2", args);
        int st;
        wait(&st);
        exit(EXIT_SUCCESS);
    } 
    int status;
    wait(&status);
    return 0;
}