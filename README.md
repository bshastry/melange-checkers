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
./demo.sh ../checker-code/build/libusedef-checker.so alpha.security.UseDefChecker
```

FIXME: 

- Binary paths in `demo.sh` are hard-coded.

#### Optional

It's always nice to have an IDE setup to make checker development enjoyable. To set one up, do the following *instead* of doing a `cmake` as mentioned in the build instructions:

```bash
cmake -D_ECLIPSE_VERSION=4.3 -DCMAKE_BUILD_TYPE=Debug -G "Eclipse CDT4 - Ninja" ../
```

Then, in Eclipse, File->Import->Existing Project-> <BUILD_DIR>. You can then build project in eclipse to compile the shared library in the build folder.

**Running checker against different code-bases**

__Pdfium: A Pdf reader for Chromium__

*Configure using gyp*

```bash
time /home/bhargava/work/clang-analyzer/git-mirror-test/llvm/tools/clang/tools/scan-build/scan-build --use-analyzer /home/bhargava/workspace/llvm/bin/clang -load-plugin /home/bhargava/work/gitlab/checkers/checker-code/build/libusedef-checker.so -enable-checker alpha.security.UseDefChecker build/gyp_pdfium -Goutput_dir=out_analyze
```

*Make*

```bash
time /home/bhargava/work/clang-analyzer/git-mirror-test/llvm/tools/clang/tools/scan-build/scan-build -Xanalyzer -analyzer-output=html -o checkerv2.9post-clang-diag -analyze-headers --use-analyzer /home/bhargava/workspace/llvm/bin/clang -load-plugin /home/bhargava/work/gitlab/checkers/checker-code/build/libusedef-checker.so -enable-checker alpha.security.UseDefChecker make
```

__Chromium: Browser__

This is what worked finally. I think the problem was that scan-build was hooking gcc on to chromium build and this was a problem because the gyp files generated configure chrome for a clang build. One needs to turn clang OFF. Here's how you'd do it with GYP and scan-build

```bash
GYP_GENERATORS=ninja GYP_DEFINES=clang=0 $HOME/work/clang-analyzer/git-mirror-test/llvm/tools/clang/tools/scan-build/scan-build \
-o scan-build-out/pdfium-checkerv2.9-clang-diag -analyze-headers --use-analyzer $HOME/workspace/llvm/bin/clang -load-plugin \
/home/bhargava/work/gitlab/checkers/checker-code/build/libusedef-checker.so -enable-checker alpha.security.UseDefChecker \
build/gyp_chromium -Goutput_dir=out_analyze
```

And then, you build with ninja. Note that, the command below only builds base subdir of chromium. I have copied this from google's clang SA page. I am guessing the reason they choose to do it on base is because doing a full analysis of chrome is too damn expensive.

```bash
$HOME/work/clang-analyzer/git-mirror-test/llvm/tools/clang/tools/scan-build/scan-build -o scan-build-out/skia-checkerv2.9-clang-diag \
 -analyze-headers --use-analyzer $HOME/workspace/llvm/bin/clang -load-plugin \
/home/bhargava/work/gitlab/checkers/checker-code/build/libusedef-checker.so -enable-checker alpha.security.UseDefChecker \
ninja -C out_analyze/Debug skia
```

Optionally, one could do analyze declarations in headers in addition to those in source files. This will take *much* longer.

```bash
$HOME/work/clang-analyzer/git-mirror-test/llvm/tools/clang/tools/scan-build/scan-build -analyze-headers --use-analyzer $HOME/workspace/llvm/bin/clang -load-plugin /home/bhargava/work/gitlab/checkers/checker-code/build/libusedef-checker.so -enable-checker alpha.security.UseDefChecker ninja -C out_analyze/Debug base
```
Haven't been able to figure out hooking scan-build with ninja. Here is what I tried

*Configure using Gyp*

```bash
time GYP_GENERATORS=ninja GYP_DEFINES=clang=1 /home/bhargava/work/clang-analyzer/git-mirror-test/llvm/tools/clang/tools/scan-build/scan-build --use-analyzer /home/bhargava/workspace/llvm/bin/clang -load-plugin /home/bhargava/work/gitlab/checkers/checker-code/build/libusedef-checker.so -enable-checker alpha.security.UseDefChecker build/gyp_chromium -Goutput_dir=out_analyze
```

OR

```bash
time GYP_GENERATORS=ninja GYP_DEFINES='component=shared_library clang_use_chrome_plugins=0 mac_strip_release=0 dcheck_always_on=1 clang=1' /home/bhargava/work/clang-analyzer/git-mirror-test/llvm/tools/clang/tools/scan-build/scan-build --use-analyzer /home/bhargava/workspace/llvm/bin/clang -load-plugin /home/bhargava/work/gitlab/checkers/checker-code/build/libusedef-checker.so -enable-checker alpha.security.UseDefChecker build/gyp_chromium -Goutput_dir=out_analyze
```

*Build with ninja*

```bash
time /home/bhargava/work/clang-analyzer/git-mirror-test/llvm/tools/clang/tools/scan-build/scan-build --use-analyzer /home/bhargava/workspace/llvm/bin/clang -load-plugin /home/bhargava/work/gitlab/checkers/checker-code/build/libusedef-checker.so -enable-checker alpha.security.UseDefChecker ninja -C out_analyze/Release/ base
```

#### Credits

- A template created out of [awruef's find-heartbleed plugin][1]
- CXX_FLAGS borrowed and adjusted from [AlexDenisov's ToyClang plugin][2]

[1]: https://github.com/awruef/find-heartbleed
[2]: https://github.com/AlexDenisov/ToyClangPlugin
