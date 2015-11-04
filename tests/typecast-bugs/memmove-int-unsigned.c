#include <string.h>

void f() {
   int size = 10;
   char src[10] = "helloworld";
   char dest[10];
   memcpy(src, dest, (unsigned)size);
}

void g(int size) {
   char src[10] = "helloworld";
   char dest[10];
   memcpy(src, dest, (unsigned)size);
}
