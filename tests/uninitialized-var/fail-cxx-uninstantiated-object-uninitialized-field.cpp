/* crbug.com/411177 and 411167
 * This file tests if clang analyzer flags a warning in the following scenario
 * a) Constructor fails to initialize member field
 * b) member field is defined in one member function
 * c) same member field is used in another member function
 * Developers might assume a certain call order between member functions of a
 * class and overlook lack of initialization. This is not concocted but a real
 * bug from Chromium source code. Read the bug report and patches.
 * Result: Fail
 * ----------------------------
 * Update: 12.02.15
 * Checker-v2.0 flags a sub-set of undefined use of cxx object fields
 * a) Definition in ctor initializer, in-class, or in method definition is
 *	recorded
 *	TODO: Record definition in ctor body as well
 * b) Use is checked for binary operator ``=" i.e., being on the rhs
 *    of assignment qualifies as use
*/

class foo {
public:
        foo() {}
        void init_member();
	void read_member();
        int m_x;
	int m_y;
};

void foo::init_member() {
	/* Clang SA: No warning here
	 * Our checker flags this
	 */
	m_x = m_y;
}

void foo::read_member() {
	if(!m_x) 		// Clang SA: No warning!
		m_x = 10;
}
