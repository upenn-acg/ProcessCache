#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int main() {
    if (fork() == 0) { 
        printf("Hello from child\n");
    };
    
    printf("Hello from parent\n");
    wait(NULL);
}