#include "include/cxx-calls-across-object-definitions.h"

void bar::call(bool cond) {
	if(cond)
		fooInstance.isTrue = true;

	fooInstance.updateX();
	return;
}
