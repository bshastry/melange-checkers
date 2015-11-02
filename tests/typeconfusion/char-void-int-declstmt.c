void f() {
   char a;
   int b;
   void *data1 = &a;
   void *data2 = data1;
   b = *(int *)(data2);
}


