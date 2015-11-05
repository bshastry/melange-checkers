#include <stdlib.h>

void f1() {
   int i;
   unsigned long j;
   i = j = 10;
   void *ptr = calloc((unsigned)i, j);
   free(ptr);
}

void f2(int i) {
   unsigned long j = 10;
   void *ptr = calloc(j, (unsigned)i);
   free(ptr);
}

void f3(int i) {
   unsigned long j;
   j = 10;
   if (i < 0) {
        void *ptr = calloc(j, (unsigned)i);
        free(ptr);
   }
}

void f4(int i) {
   unsigned long j;
   j = 10;
   if (i > 0) {
        void *ptr = calloc(j, (unsigned)i);
        free(ptr);
   }
}
