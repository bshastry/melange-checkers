/* This file tests if clang analyzer flags
 * uninitialized use of member fields of cxx objects in function calls when the
 * constructor of the object is declared but not defined. Note that this is
 * an unrealistic test case.
 * Result: Fail
*/

class foo
{
public:
        int x;
        foo();
};

void call(int a) {}

void func() {
    foo a;
    call(a.x); // No warning
}
