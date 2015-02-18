struct foostruct {
	bool isTrue;
	int x;
};

class foo {
public:
	foo() {}
	void addFooStructInstance(foostruct fs);  
};

class bar {
public:
	foo fooInstance;
	void call(bool cond);
};

void foo::addFooStructInstance(foostruct fs) {
	if(fs.isTrue)
		fs.x = 10;
	return;
}
