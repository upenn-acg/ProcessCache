#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>


int main() {
    int fd1 = openat(AT_FDCWD, "foo.txt", O_CREAT| O_WRONLY | O_TRUNC);
    printf("parent\n");
    if (fork() == 0) {
        char* args[] = {"./hardlinking_examples/child_hardlinking_ex", NULL};
        execvp("./hardlinking_examples/child_hardlinking_ex", args);
        exit(0);
    } else {
        int status;
        wait(&status);
    }
    return 0;
}