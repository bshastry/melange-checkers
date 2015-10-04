#include <stdlib.h>

void f() {
   int i;
   unsigned long j;
   i = j = 10;
   void *ptr = malloc(j);
   ptr = realloc(ptr, i);
   free(ptr);
}
