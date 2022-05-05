#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    if (fork() == 0) {
        // int fd = openat(AT_FDCWD, "yeah.txt", O_RDONLY);
        char* args[] = {"./garbage", NULL};
        execvp("./garbage", args);
        char* args2[] = {"./IOTracker/c_examples/empty_c", NULL};
        execvp("./IOTracker/c_examples/empty_c", args2);
        exit(EXIT_SUCCESS);
    } 
    int status;
    wait(&status);


    return 0;
}