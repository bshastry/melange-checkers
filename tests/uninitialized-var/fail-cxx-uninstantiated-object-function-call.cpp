/* This file tests if clang analyzer flags
 * a) uninitialized use of member fields of cxx objects in function calls when
 * the object has not been instantiated
 * Result: Fail
*/ 

class foo {
public:
	foo();
	void bar();
	int x;
};

foo::foo() {}

void call(int a) {}

void foo::bar() {
	call(x); // No warning!
}

