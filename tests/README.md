#### Tests

Directory for tests for which clang analyzer fails; might optionally contain tests that pass are interesting nonetheless:

- `uninitialized-var` contains test cases for use of uninitialized variable

#### Naming convention

(pass/fail)-cxx-(description-of-test).cpp

pass == Test passes i.e., clang analyzer flags warning as expected
fail == NOT pass => Stuff that is interesting!
cxx == Pertaining to cxx feature e.g., objects

#### Command line

Clang analyzer exercises all the default checkers e.g., use of uninitialized var, use-after-free etc. So just do this:

```bash
clang --analyze $TEST.cpp
```
