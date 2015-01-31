/* crbug.com/411163
 * This file tests if clang analyzer flags
 * a) when an uninitialized variable passed by reference to a class' member function AND
 * b) a pointer to the class instance is passed as an argument
 * Implementation of member function is in a different source file
 * Class declaration is in the included header
 * 
 * Result: Fail
*/

#include "./include/cxx-function-arg-by-reference.h"

void func(foo *fooptr) {
	int x;
	fooptr->bar(x);
}
