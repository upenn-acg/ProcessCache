#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    if (fork() == 0) { 
        char* args[] = {"./write_file2", NULL};
        execvp("./write_file2", args);
        exit(EXIT_SUCCESS);
    } else {
        if (fork() == 0) {
            char* args[] = {"./write_file3", NULL};
            execvp("./write_file3", args);
            exit(EXIT_SUCCESS);
        } else {
            printf("Hello from parent\n");
            int status;
            wait(&status);
        }
    }

    return 0;
}