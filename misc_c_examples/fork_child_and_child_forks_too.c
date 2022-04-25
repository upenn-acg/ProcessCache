#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int main() {
    char* args[] = {"./empty_c", NULL};
    if (fork() == 0) {
        // This calls a program that forks a process
        // which calls the empty C program. N E S T E D.
        execvp("./fork_child_empty_c", args); 
    } else {
        printf("Hello from parent\n");
        int status;
        wait(&status);
    }

    return 0;
}