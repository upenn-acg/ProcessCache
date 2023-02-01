#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
   mkdir("blah", 0700);
   chdir("blah");
   // int fd = openat(AT_FDCWD, "hi.txt", O_CREAT | O_WRONLY | O_TRUNC);
   int fd = creat("hi.txt", S_IRWXU | S_IRWXG | S_IRWXO);
   // int fd2 = openat(AT_FDCWD, "hello.txt", O_CREAT | O_WRONLY | O_TRUNC);
   int fd2 = creat("hello.txt", S_IRWXU | S_IRWXG | S_IRWXO);
   chdir("..");
   rename("blah", "boo");
   return 0;
}