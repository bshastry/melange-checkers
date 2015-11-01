void f() {
   void *data1, *data2;
   char a;
   int b;
   data1 = &a;
   data2 = data1;
   b = *(int *)(data2);
}


