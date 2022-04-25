#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    struct stat buf;
    int ret;
    struct stat buffer;
    int ret_val;
    ret = lstat("junklink", &buf);
    ret_val = stat("jasdjajsd", &buffer);

    // int ino;
    // ino = buf.st_ino;
    printf("Stat says ret: %d\n", ret);

    struct stat buf2;
    int ret2;

    ret2 = lstat("junk",  &buf2);
    // int ino2;
    // ino2 = buf2.st_ino;
    printf("Stat says ret: %d\n", ret2);

    return 0; 
}