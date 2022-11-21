
#include <sys/stat.h>
#include <stdio.h>

int main() {
  mode_t u = umask(0);
  //printf("sizeof(mode_t) == %ld bytes\n", sizeof(mode_t));
  return u | S_IWOTH;
}
