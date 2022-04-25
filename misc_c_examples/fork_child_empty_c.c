#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    if (fork() == 0) {
        // Child
        char* args[] = {"./buttz", NULL};
        // char* args2[] = {"./empty_c", NULL};
        // execvp("./empty_c", args);
        execvp("./buttz", args);
        char* args2[] = {"./empty_c", NULL};
        execvp("./empty_c", args2);
        // execvp("./empty_c", args);
        exit(EXIT_SUCCESS);
    } else {
        printf("Hello from child parent\n");
        int status;
        wait(&status);
    }

    return 0;
}