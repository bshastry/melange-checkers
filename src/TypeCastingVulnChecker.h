#ifndef MELANGE_TYPECASTINGVULN_CHECKER_H
#define MELANGE_TYPECASTINGVULN_CHECKER_H

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "Diagnostics.h"

#ifdef _DEBUG
#define DEBUG_PRINT(x) llvm::errs() << x << "\n"
#else
#define DEBUG_PRINT(x)
#endif

namespace Melange {

  class Diagnostics;

class TypeCastingVulnChecker : public clang::ento::Checker<clang::ento::check::PreCall> {

  mutable Diagnostics Diag;

public:
  void checkPreCall(const clang::ento::CallEvent &Call, clang::ento::CheckerContext &C) const;
private:
  mutable std::unique_ptr<clang::ento::BugType> BT;
  void reportBug(clang::ento::CheckerContext &C, clang::SourceRange SR,
                 llvm::StringRef Message, llvm::StringRef declName) const;
  void handleAllocArg(const clang::Expr *E, clang::ento::SVal sval,
                      clang::ento::CheckerContext &C) const;
  void reportUnsafeExpCasts(const clang::Expr *ECE, clang::ento::SVal sval,
                            clang::ento::CheckerContext &C) const;
  void reportUnsafeImpCasts(const clang::ImplicitCastExpr *ICE,
                            clang::ento::SVal sval,
                            clang::ento::CheckerContext &C) const;

  const std::vector<std::string> callNames =
      {"malloc", "xmalloc", "av_malloc", "av_mallocz", "srslte_vec_malloc",
	"calloc", "xcalloc", "av_calloc",
	"realloc", "xrealloc", "av_realloc",
	"reallocarray", "xreallocarray",
	"memcpy", "memset", "memmove",
	"strncpy"
      };
  enum ALLOC_API : unsigned {
    MALLOC_START = 0,
    MALLOC_END = MALLOC_START + 4,
    CALLOC_START = 5,
    CALLOC_END = CALLOC_START + 2,
    REALLOC_START = 8,
    REALLOC_END = REALLOC_START + 2,
    REALLOCARRAY_START = 11,
    REALLOCARRAY_END = REALLOCARRAY_START + 1,
    MEMCPY_START = 13,
    MEMCPY_END = MEMCPY_START + 2,
    STRCPY_START = 16,
    STRCPY_END = STRCPY_START
  };
};
} // end of Melange namespace

#endif
