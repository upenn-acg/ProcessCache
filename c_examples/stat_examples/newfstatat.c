#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    struct stat buf;
    int ret;

    // Success = 0
    ret = fstatat(AT_FDCWD, "junklink", &buf, AT_SYMLINK_NOFOLLOW);

    printf("Fstatat says ret: %d\n", ret);
    return 0; 
}