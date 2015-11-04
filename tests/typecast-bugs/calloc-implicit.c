#include <stdlib.h>

void f() {
   int i;
   unsigned long j;
   i = j = 10;
   void *ptr = calloc(i, j);
   free(ptr);
}

void g() {
   int i;
   unsigned long j;
   void *ptr = calloc(j, i);
   free(ptr);
}

