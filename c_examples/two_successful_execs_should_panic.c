#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    char* args[] = {"./c_examples/empty_c", NULL};
    execvp("./c_examples/empty_c", args);
    return 0;
}