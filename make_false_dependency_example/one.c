#include <stdlib.h>
#include <stdio.h>

#define TEN(x) x; x; x; x; x; x; x; x; x; x;

int main(int argc, char** argv) {
  printf("I received %d commandline arguments\n", argc);

  TEN(TEN(TEN(TEN(TEN(printf("."))))))
  
  return 0;
}
