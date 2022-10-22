#include <stdio.h>
#include <string.h>


int main(int argc, char** argv){
  unsigned int x = 0x54354054;
  char k = (char)x;
  unsigned int j = (unsigned int)k;
  char kk = (char)(x>>2);

  char buf[4];
  int i;
  for ( i = 0 ; i<4; i++){
    buf[i] = argv[1][i];
    
  }
  for ( i = 0 ; i<4; i++){
    printf("%c ",buf[3-i]);
  }
  printf("\n");
  for ( i = 0 ; i<4; i++){
    printf("%u ",buf[i]);
  }
  printf("\n");
  return 0;
}
