#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    char* args[] = {"./ajsdk", NULL};
    execvp("./ajsdk", args);
    exit(1);


    return 0;
}