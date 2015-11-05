#include <stdlib.h>

void f1() {
   int i;
   unsigned long j;
   i = j = 10;
   void *ptr = malloc(j);
   ptr = realloc(ptr, (unsigned)i);
   free(ptr);
}

void f2(int i) {
   unsigned long j = 10;
   void *ptr = malloc(j);
   ptr = realloc(ptr, (unsigned)i);
   free(ptr);
}

void f3(int i) {
   unsigned long j = 10;
   void *ptr = malloc(j);
   if (i < 0)
     ptr = realloc(ptr, (unsigned)i);
   free(ptr);
}

void f4(int i) {
   unsigned long j = 10;
   void *ptr = malloc(j);
   if (i > 0)
     ptr = realloc(ptr, (unsigned)i);
   free(ptr);
}
