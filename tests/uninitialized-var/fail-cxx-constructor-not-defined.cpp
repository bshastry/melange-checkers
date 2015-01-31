/* This file tests if clang analyzer flags
 * uninitialized use of member fields of cxx objects in function calls when the
 * constructor of the object is declared but not defined.
 * Note: It is possible that the definition of constructor is in a different source
 * file and this file simply makes use of class foo.
 * Result: Fail
*/
#include "include/cxx-obj-declaration.h"

void call(int a) {}

void func() {
    foo a;
    call(a.x); // No warning
}
