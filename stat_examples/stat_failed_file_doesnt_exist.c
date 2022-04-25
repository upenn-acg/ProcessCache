#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    struct stat buf;
    int ret_val; 

    ret_val = stat("/home/kelly/research/IOTracker/stat_examples/file_not_here.txt", &buf);

    return 0;
}
