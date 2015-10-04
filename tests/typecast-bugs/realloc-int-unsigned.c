#include <stdlib.h>

void f() {
   int i;
   unsigned j;
   i = j = 10;
   void *ptr = malloc(j);
   ptr = realloc(ptr, (unsigned)i);
   free(ptr);
}
