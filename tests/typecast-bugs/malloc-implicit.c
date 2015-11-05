#include <stdlib.h>

void f1() {
   int size = 10;
   void *ptr = malloc(size);
   free(ptr);
}

void f2(int size) {
   void *ptr = malloc(size);
   free(ptr);
}

void f3(int size) {
   if (size < 0) {
        void *ptr = malloc(size);
        free(ptr);
   }
}

void f4(int size) {
   if (size > 0) {
        void *ptr = malloc(size);
        free(ptr);
   }
}
