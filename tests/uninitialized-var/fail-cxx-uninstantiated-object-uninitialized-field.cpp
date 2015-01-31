/* crbug.com/411177 and 411167
 * This file tests if clang analyzer flags a warning in the following scenario
 * a) Constructor fails to initialize member field
 * b) member field is defined in one member function
 * c) same member field is used in another member function
 * Developers might assume a certain call order between member functions of a
 * class and overlook lack of initialization. This is not concocted but a real
 * bug from Chromium source code. Read the bug report and patches.
 * Result: Fail
*/

class foo {
public:
        foo() {}
        void init_member();
	void read_member();
        int m_x;
};

void foo::init_member() {
	m_x = 0;
}

void foo::read_member() {
	if(!m_x) 		// No warning!
		m_x = 10;
}

