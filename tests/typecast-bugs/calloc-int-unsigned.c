#include <stdlib.h>

void f() {
   int i;
   unsigned j;
   i = j = 10;
   void *ptr = calloc((unsigned)i, j);
   free(ptr);
}

void g() {
   int i;
   unsigned j;
   i = j = 10;
   void *ptr = calloc(j, (unsigned)i);
   free(ptr);
}

