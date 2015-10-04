#include <stdlib.h>

void f() {
   int size = 10;
   void *ptr = malloc((unsigned)size);
   free(ptr);
}
