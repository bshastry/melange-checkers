#include <string.h>

void f1() {
   int size = 12;
   char src[12] = "helloworld";
   char dest[12];
   memmove(dest, src, (unsigned)size);
}

void f2(int size) {
   char src[12] = "helloworld";
   char dest[12];
   memmove(dest, src, (unsigned)size);
}

void f3(int size) {
   char src[12] = "helloworld";
   char dest[12];
   if (size < 0)
     memmove(dest, src, (unsigned)size);
}

void f4(int size) {
   char src[12] = "helloworld";
   char dest[12];
   if (size > 0)
     memmove(dest, src, (unsigned)size);
}
