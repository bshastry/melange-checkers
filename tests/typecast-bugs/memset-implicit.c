#include <string.h>

void f1() {
   int size = 10;
   char src[10];
   memset(src, 0, size);
}

void f2(int size) {
   char src[10];
   memset(src, 0, size);
}

void f3(int size) {
   char src[10];
   if (size < 0)
     memset(src, 0, size);
}

void f4(int size) {
   char src[10];
   if (size > 0)
     memset(src, 0, size);
}
