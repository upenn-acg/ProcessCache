#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>


int main() {
    if (fork() == 0) {
        char* args[] = {"./read_file1", NULL};
        execvp("./read_file1", args);
        exit(0);
    } else {
        int status;
        wait(&status);
    }
}