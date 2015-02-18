/* crbug.com/419428
 * This test is a simplified version of crbug 419428
 * Essentially, it tests if calls across class definitions
 * is sufficient to confuse clang. tl;dr: yes, it is!
 * Result: Fail
*/

#include "include/cxx-calls-across-object-definitions.h"

void bar::call(bool cond) {
	/* isTrue is initialized if cond is true */
	if(cond)
		fooInstance.isTrue = true;

	/* Member field isTrue is read in function updateX() */
	fooInstance.updateX(); // No warning!
	return;
}

/* This is what is missing for clang analyzer to flag a warning.
 * Without this function that actually instantiates object of
 * type `bar`, the analyzer doesn't do anything interesting
 * Uncomment to see clang flag a warning
 */
/*
void func(bool cond) {
	bar b;
	// warning: Branch condition evaluates to a garbage value in
	// include/cxx-calls-across-object-definitions.h:17:5
	b.call(cond);
}
*/
