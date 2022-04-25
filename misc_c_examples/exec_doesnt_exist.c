#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int main() {
    char* args[] = {"./aint_here", NULL};
    execvp("./aint_here", args); 

    return 0;
}