#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {

    if (fork() == 0) {
        // Child
        char* args[] = {"./buttz", NULL};
        char* args2[] = {"./booty", NULL};
        // char* args2[] = {"./no", NULL};
        char* args3[] = {"./empty_c", NULL};
        execvp("./buttz", args);
        execvp("./booty", args2);
        // execvp("./no", args2);
        execvp("./empty_c", args3);
        exit(EXIT_SUCCESS);
    } else {
        int status;
        wait(&status);
    }

    return 0;
}