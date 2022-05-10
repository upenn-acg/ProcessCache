#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    if (fork() == 0) {
        char* args[] = {"./IOTracker/c_examples/empty_c", NULL};
        execvp("./IOTracker/c_examples/empty_c", args);
        exit(EXIT_SUCCESS);
    } 
    int status;
    wait(&status);


    return 0;
}