#!/bin/bash

LLVM_SOURCE=$HOME/work/clang-analyzer/git-mirror-test/llvm
LLVM_BIN=$HOME/workspace/llvm/bin

make clean
sbuild=$LLVM_SOURCE/tools/clang/tools/scan-build/scan-build
$sbuild --use-analyzer $LLVM_BIN/clang -load-plugin $1 -enable-checker $2 make
