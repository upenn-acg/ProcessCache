#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    int ret;

    // Relative path no access
    ret = access("no_access.txt", R_OK);
    // Absolute path no access
    ret = access("/home/kelly/research/IOTracker/access_syscall_examples/no_access.txt", R_OK);

    printf("Return value: %d\n", ret);
}