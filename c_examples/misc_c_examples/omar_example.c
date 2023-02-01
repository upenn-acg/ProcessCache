#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(){
  struct stat buf;
  int status;
  status = stat("some file", &buf);
  char* args[] = {"garbage", NULL};
  execvp("garbage", args);
  return 0;
}