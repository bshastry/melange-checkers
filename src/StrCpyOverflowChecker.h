#ifndef MELANGE_STRCPYOVERFLOW_CHECKER_H
#define MELANGE_STRCPYOVERFLOW_CHECKER_H

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "Diagnostics.h"

#ifdef _DEBUG
#define DEBUG_PRINT(x) llvm::errs() << x << "\n"
#else
#define DEBUG_PRINT(x)
#endif

namespace Melange {

  class Diagnostics;

class StrCpyOverflowChecker : public clang::ento::Checker<clang::ento::check::PreStmt<clang::CallExpr>> {

  mutable Diagnostics Diag;

public:
  void checkPreStmt(const clang::CallExpr *CE, clang::ento::CheckerContext &C) const;
private:
  mutable std::unique_ptr<clang::ento::BugType> BT;
  void reportBug(clang::ento::CheckerContext &C, clang::SourceRange SR,
                 llvm::StringRef Message, llvm::StringRef declName) const;
  void handleStrArgs(const clang::Expr *E1, const clang::Expr *E2,
                     clang::ento::CheckerContext &C) const;

  const std::vector<std::string> callNames =
      {"strcpy", "strcat"};
//  enum ALLOC_API : unsigned {
//    MALLOC_START = 0,
//    MALLOC_END = 4,
//    CALLOC_START = 5,
//    CALLOC_END = 7,
//    REALLOC_START = 8,
//    REALLOC_END = 10,
//    REALLOCARRAY_START = 11,
//    REALLOCARRAY_END = 12,
//    MEMCPY_START = 13,
//    MEMCPY_END = 14
//  };
};
} // end of Melange namespace

#endif
