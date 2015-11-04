#include <stdlib.h>

void f() {
   int i;
   unsigned long j;
   i = j = 10;
   void *ptr = malloc(j);
   ptr = realloc(ptr, (unsigned)i);
   free(ptr);
}

void g(int i) {
   unsigned long j = 10;
   void *ptr = malloc(j);
   ptr = realloc(ptr, (unsigned)i);
   free(ptr);
}
