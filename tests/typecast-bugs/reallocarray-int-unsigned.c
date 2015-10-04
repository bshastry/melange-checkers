#include <stdlib.h>

void f() {
   int i;
   unsigned long j;
   i = j = 10;
   void *ptr = malloc(j);
   ptr = reallocarray(ptr, (unsigned)i, j);
   free(ptr);
}

void g() {
   int i;
   unsigned long j;
   i = j = 10;
   void *ptr = malloc(j);
   ptr = reallocarray(ptr, j, (unsigned)i);
   free(ptr);
}

