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
