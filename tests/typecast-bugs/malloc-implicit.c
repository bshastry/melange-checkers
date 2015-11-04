#include <stdlib.h>

void f() {
   int size = 10;
   void *ptr = malloc(size);
   free(ptr);
}

void g(int size) {
   void *ptr = malloc(size);
   free(ptr);
}  
