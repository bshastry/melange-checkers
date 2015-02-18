/* This file tests if clang analyzer flags
 * a) uninitialized use of member fields of cxx objects used in unary LNot operation
 * the object has not been instantiated
 * Result: Fail
*/
class foo {
public:
	int x;
	bool m_b;
	foo();
	void bar();
};

foo::foo(): x(0) { }

void foo::bar() {
	// Our checker flags this
	// Clang SA doesn't
	if(!m_b)
	  x = 1;
}
