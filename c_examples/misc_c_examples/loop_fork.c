#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    int i;
    
    for (i = 0, i < 3, i++) {
        if (fork() == 0) { 
            char* args[] = {"./empty_c", NULL};
            execvp("./empty_c", args);
            exit(EXIT_SUCCESS);
        } else {
            printf("Hello from parent\n");
            int status;
            wait(&status);
        }
    }


    return 0;
}