#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <wait.h>

// SUCCESS:
// If the file doesn't exist, creates it.
// If the file existed, overwrites it.
int main() {
    int fd;
    fd = creat("creat_file.txt", S_IRWXU | S_IRWXG | S_IRWXO);
    
    return 0;
}