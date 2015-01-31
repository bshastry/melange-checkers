#### Directory structure

- checker-code: Source and build dirs for the checker plug-in
 -- Contains source code and a `cmake` file for the checker
 -- Build directory needs to be created

- demo: Code and script for demo
 -- demo.c is a conjured up test file for the checker

#### Pre-requisites

- LLVM source code
- Clang binary built from LLVM source code
- Prebuilt scan-build and scan-view binaries that are present in LLVM source tree
- GCC >= 4.7 (Tested with 4.8.x)

#### Patching cmake file

LLVM Source tree (from trunk) is missing a file called FindLLVM.cmake that the plugin project references. Copy file to $LLVM_SRC/cmake/modules if cmake complains during build.

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

FIXME: 

- Binary paths in `demo.sh` are hard-coded.

#### Optional

It's always nice to have an IDE setup to make checker development enjoyable. To set one up, do the following *instead* of doing a `cmake` as mentioned in the build instructions:

```bash
cmake -D_ECLIPSE_VERSION=4.3 -DCMAKE_BUILD_TYPE=Debug -G "Eclipse CDT4 - Ninja" ../
```

Then, in Eclipse, File->Import->Existing Project-> <BUILD_DIR>. You can then build project in eclipse to compile the shared library in the build folder.

#### Credits

- A template created out of [awruef's find-heartbleed plugin][1]
- CXX_FLAGS borrowed and adjusted from [AlexDenisov's ToyClang plugin][2]

[1]: https://github.com/awruef/find-heartbleed
[2]: https://github.com/AlexDenisov/ToyClangPlugin
