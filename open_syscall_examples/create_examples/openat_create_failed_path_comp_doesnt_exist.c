#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("/home/kelly/research/IOTracker/open_syscall_examples/create_examples/can't_touch_this_dir/created_file.txt", O_WRONLY | O_TRUNC | O_CREAT);
    printf("fd is: %d\n", fd);
}