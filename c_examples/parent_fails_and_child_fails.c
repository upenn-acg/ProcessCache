#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    // char* args[] = {"./hot_garbage", NULL};
    // execvp("./hot_garbage", args);
    if (fork() == 0) {
        // int fd = openat(AT_FDCWD, "yeah.txt", O_RDONLY);
        char* args[] = {"./garbage", NULL};
        execvp("./garbage", args);
        exit(EXIT_SUCCESS);
    } 
    int status;
    wait(&status);


    return 0;
}