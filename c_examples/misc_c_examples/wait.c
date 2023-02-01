#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

int main() {
    int pid;
    int status;

    pid = fork();
    if (pid == 0) {
        printf("hello from child\n");
        exit(EXIT_SUCCESS);
    }

    int p;
    p = wait(&status);
    printf("Child pid: %d\n", p);
    printf("Status: %d\n", status);

    return 0;
}