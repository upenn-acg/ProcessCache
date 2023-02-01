#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    if (fork() == 0) {
        // Child
        char* args[] = {"./misc_c_examples/empty_c", NULL};
        execvp("./misc_c_examples/empty_c", args);
        exit(EXIT_SUCCESS);
    } else {
        int status;
        wait(&status);
    }

    return 0;
}