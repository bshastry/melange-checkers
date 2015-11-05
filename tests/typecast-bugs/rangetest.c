#include <stdlib.h>

void f1() {
   int i;
   unsigned long j;
   i = j = 10;
   void *ptr = calloc(i, j);
   free(ptr);
}

void f2(int i) {
   unsigned long j;
   void *ptr = calloc(j, i);
   free(ptr);
}

void f3(int i) {
   unsigned long j;
   j = 10;
   i = -1;
   if (i < 0) {
	void *ptr = calloc(j, i);
	free(ptr);
   }
}

void f4(int i) {
   unsigned long j;
   j = 10;
   if (i < 0) {
	void *ptr = calloc(j, i);
	free(ptr);
   }
}

void f5(int i) {
   unsigned long j;
   j = 10;
   if (i > 0) {
	void *ptr = calloc(j, i);
	free(ptr);
   }
}

void f6(int i) {
   unsigned long j;
   j = 10;
   i = -1;
   void *ptr = calloc(j, i);
   free(ptr);
}
