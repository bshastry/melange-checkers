#include <string.h>

void f1() {
   int size = 12;
   char src[12] = "helloworld";
   char dest[12];
   memcpy(dest, src, size);
}

void f2(int size) {
   char src[12] = "helloworld";
   char dest[12];
   memcpy(dest, src, size);
}

void f3(int size) {
   char src[12] = "helloworld";
   char dest[12];
   if (size < 0)
     memcpy(dest, src, size);
}

void f4(int size) {
   char src[12] = "helloworld";
   char dest[12];
   if (size > 0)
     memcpy(dest, src, size);
}
