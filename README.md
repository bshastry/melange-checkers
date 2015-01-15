#### Directory structure

- checker-code: Source and build dirs for the checker plug-in
 -- Contains source code and a `cmake` file for the checker
 -- Build directory needs to be created

- demo: Code and script for demo
 -- demo.c is a conjured up test file for the checker

#### Pre-requisites

- LLVM source code
- LLVM binaries built from source code
- GCC >= 4.7 (Tested with 4.8.x)

#### Build instructions

```bash
cd checker-code
mkdir -p build
cd build
cmake ..; make
```

#### Running the demo

```bash
cd demo
./demo.sh ../checker-code/build/libmy-first-checker.so alpha.security.myfirstchecker
```

#### Credits

- A template created out of [awruef's find-heartbleed plugin][1]
- CXX_FLAGS borrowed and adjusted from [AlexDenisov's ToyClang plugin][2]

[1]: https://github.com/awruef/find-heartbleed
[2]: https://github.com/AlexDenisov/ToyClangPlugin
