#!/bin/bash

LLVM_SOURCE=$HOME/work/clang-analyzer/git-mirror-test/llvm
LLVM_BIN=$HOME/workspace/llvm/bin

alias scan-build='$LLVM_SOURCE/tools/clang/tools/scan-build'

make clean
scan-build --use-analyzer $LLVM_BIN/clang -load-plugin $1 -enable-checker $2 make
