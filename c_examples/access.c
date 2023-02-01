#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    int ret;

    // Relative path access example
    // ret = access("file.txt", R_OK);
    // Absolute path access example
    ret = access("/home/kelly/research/IOTracker/file.txt", R_OK);

    printf("Return value: %d\n", ret);
}