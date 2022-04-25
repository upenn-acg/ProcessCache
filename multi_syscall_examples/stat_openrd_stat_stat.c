#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
    struct stat buf;
    int ret_val; 
        ret_val = stat("/home/kelly/research/IOTracker/multi_syscall_examples/creat_file.txt", &buf);

    int fd = open("/home/kelly/research/IOTracker/multi_syscall_examples/creat_file.txt", O_RDONLY, 0);

    struct stat buf2;
    int ret_val2; 
    ret_val2 = stat("/home/kelly/research/IOTracker/multi_syscall_examples/creat_file.txt", &buf2);

    struct stat buf3;
    int ret_val3; 
    ret_val3 = stat("/home/kelly/research/IOTracker/multi_syscall_examples/creat_file.txt", &buf3);
}