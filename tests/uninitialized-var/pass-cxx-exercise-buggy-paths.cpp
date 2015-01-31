/* This file runs clang against a hypothetical scenario
 * where we have an executable that captures conditional
 * initialization bugs at the core of most crbugs scavenged so far
*/

#include "include/cxx-exercise-buggy-paths.h"

void foo::do_something() {
        foo::m_x = 1;
}

void foo::do_something_else() {
        foo::m_y = foo::m_x;
}

int main(int argc, char **argv) {
	foo fooobj;
	if(argc > 1)
		fooobj.do_something();
	fooobj.do_something_else();
	return fooobj.m_x;
}
