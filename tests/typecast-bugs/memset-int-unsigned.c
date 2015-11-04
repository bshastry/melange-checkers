#include <string.h>

void f() {
   int size = 10;
   char src[10];
   memset(src, 0, size);
}

void g(int size) {
   char src[10];
   memset(src, 0, (unsigned)size);
}
