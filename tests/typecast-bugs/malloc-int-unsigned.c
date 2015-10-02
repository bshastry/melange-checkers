#include <stdlib.h>

void f() {
   int size;
   void *ptr = malloc((unsigned)size);
   free(ptr);
}
