/* This file tests if clang analyzer flags the following scenario
 * a) instantiated cxx object 
 * b) member function of object takes in passed argument by reference
 * c) uninitialized var is passed to the member function
 * Result: Fail
*/ 
#include "include/cxx-function-arg-by-reference.h"

void func() {
	foo fooobj;
	int b;
	fooobj.bar(b);
}
