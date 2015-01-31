#### Tests

Directory for tests that clang analyzer fails; might optionally contain tests that pass but are interesting nonetheless:

- `uninitialized-var` contains test cases for use of uninitialized variable

#### Naming convention of test files

(pass/fail)-cxx-(description-of-test).cpp

pass == Test passes i.e., clang analyzer flags warning as expected
fail == Test fails => Stuff that is interesting!
cxx == Pertaining to cxx feature e.g., objects

#### Command line

Clang analyzer exercises all the default checkers e.g., use of uninitialized var, use-after-free etc. So just do this:

```bash
clang --analyze $TEST.cpp
```
