class foo {
public:
	foo() {}
	void updateX(); 
	int x;
	bool isTrue; 
};

class bar {
public:
	foo fooInstance;
	void call(bool cond);
};

void foo::updateX() {
	if(isTrue)
		x = 10;
	return;
}
