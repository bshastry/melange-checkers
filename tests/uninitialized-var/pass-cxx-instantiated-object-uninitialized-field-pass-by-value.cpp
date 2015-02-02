/* This file tests if clang analyzer flags
 * uninitialized use of member fields of cxx objects in function calls when
 * the object has been instantiated and is passed by value
 * Result: Pass
*/


class foo {
public:
        int y;
        void bar(foo a);
        foo();
};

foo::foo() {}

void foo::bar(foo a) { if(a.y == 5) a.y = 0;}

void func() {
        // Object instantiation
        foo a;
        a.bar(a); // warning: Function call argument is an uninitialized value
}
