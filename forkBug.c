#include<stdio.h>
#include<unistd.h>
#include<signal.h>

int main() {

  while(1) {
    kill(getpid(), SIGCHLD);
    int pid = fork();
    // Child
    if (pid == 0) {
      return 0;
    }
  }

  return 0;
}
