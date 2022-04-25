#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    int ret;

    // Relative path example of file didn't exist
    // ret = access("idk1.txt", R_OK);
    // Absolute path example of file didn't exist
    ret = access("/home/kelly/research/IOTracker/idk.txt", F_OK);

    printf("Return value: %d\n", ret);
}