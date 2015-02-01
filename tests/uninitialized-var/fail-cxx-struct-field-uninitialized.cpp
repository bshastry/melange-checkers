#include "include/cxx-struct-field-uninitialized.h"

void bar::call(bool cond) {
	foostruct fs;
	foo fooobj;
	if(cond)
		fs.isTrue = true;
	fooobj.addFooStructInstance(fs);
	return;
}
