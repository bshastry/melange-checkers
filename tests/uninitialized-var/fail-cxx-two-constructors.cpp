/* crbug.com/393981 and 411161
 * This file tests if clang analyzer flags a warning in the following scenario:
 * a) there are two constructors for an object
 * b) the default constructor does not initialize member field
 * c) defaut constructor is used to instantiate a class object
 * d) the class object is passed by reference/pointer to a function call
 * e) function call reads uninitialized variable
 * Result: Fail
*/

#include "include/cxx-two-constructors.h"

void call(foo *fooptr) {
	fooptr->m_x;		// No warning!
}

void func() {
	foo fooobj;		// Calls default constructor
	call(&fooobj);
}
