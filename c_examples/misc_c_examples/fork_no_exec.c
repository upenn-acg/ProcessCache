#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <wait.h>

int main() {
    if (fork() == 0) { 
        // int ret = open("heyhihello.wht", O_CREAT|O_WRONLY|O_TRUNC);
    }    
    int status;
    wait(&status);
}