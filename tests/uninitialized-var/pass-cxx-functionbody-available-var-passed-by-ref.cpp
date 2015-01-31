/* This file tests if clang analyzer flags the following scenario
 * a) instantiated cxx object 
 * b) member function of object takes in passed argument by reference
 * c) uninitialized var is passed to the member function
 * d) implementation of member function in same translation unit
 * Result: Pass
*/ 
#include "include/cxx-function-arg-by-reference.h"

void foo::bar(int &a) {
	if(a > 10) // warning: The left operand of '>' is a garbage value
		a = 0;
}


void func() {
	foo fooobj;
	int b;
	fooobj.bar(b);
}
