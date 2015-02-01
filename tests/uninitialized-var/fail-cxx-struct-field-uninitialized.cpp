/* crbug.com/419428
   This file tests if clang flags a warning in the following scenario:
 * a) There are two distinct cxx object definitions available
 * b) One object (bar) has an object of the other type (foo)
 * c) Object bar has a member function that calls a member function of foo
 *    through its own instance of foo (fooInstance)
 * d) Member field of foo is uninitialized when a condition (cond) is false
 * Result: Fail
*/

#include "include/cxx-struct-field-uninitialized.h"

/* crbug 419428: bar is equivalent to class MediaQueryData.
 * bar::call is equivalent to MediaQueryData::addParserValue()
 */
void bar::call(bool cond) {

	/* crbug 419428: foostruct is equivalent to struct CSSParserValue */
	foostruct fs;
	if(cond)
		fs.isTrue = true;

	/* If cond == false, the branch is not taken
	 * and fs.isTrue is not initialized.
	 * Clang is expected to flag a warning here.
	*/
	/* crbug 419428: foo is equivalent to class CSSParserValueList.
	 * fooInstance is equivalent to field m_valueList in MediaQueryData.
	 * addFooStructInstance() is equivalent to CSSParserValueList::addValue().
	 */
	fooInstance.addFooStructInstance(fs); // No warning!
	return;
}
