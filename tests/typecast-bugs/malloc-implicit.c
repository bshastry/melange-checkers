#include <stdlib.h>

void f() {
   int size = 10;
   void *ptr = malloc(size);
   free(ptr);
}
