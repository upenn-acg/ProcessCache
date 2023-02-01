#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = unlink("/home/kelly/research/IOTracker/multi_syscall_examples/unlink_me.txt");
}