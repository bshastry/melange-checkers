#ifndef MELANGE_TYPECASTINGVULN_CHECKER_H
#define MELANGE_TYPECASTINGVULN_CHECKER_H

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"

#ifdef _DEBUG
#define DEBUG_PRINT(x) llvm::errs() << x << "\n"
#else
#define DEBUG_PRINT(x)
#endif

namespace Melange {

class TypeCastingVulnChecker : public clang::ento::Checker<clang::ento::check::PreStmt<clang::ExplicitCastExpr>,
							   clang::ento::check::PreStmt<clang::CallExpr>> {
public:
  void checkPreStmt(const clang::ExplicitCastExpr *ECE, clang::ento::CheckerContext &C) const;
  void checkPreStmt(const clang::CallExpr *CE, clang::ento::CheckerContext &C) const;
private:
  mutable std::unique_ptr<clang::ento::BugType> BT;
  void reportBug(clang::ento::CheckerContext &C, clang::SourceRange SR,
                 llvm::StringRef Message) const;
  void handleAllocArg(const clang::Expr *E, clang::ento::CheckerContext &C) const;
  void reportUnsafeExpCasts(const clang::ExplicitCastExpr *ECE,
                            clang::ento::CheckerContext &C) const;
  void reportUnsafeImpCasts(const clang::ImplicitCastExpr *ICE,
                            clang::ento::CheckerContext &C) const;

  const std::vector<std::string> callNames =
      {"malloc", "xmalloc", "av_malloc", "av_mallocz", "srslte_vec_malloc",
	"calloc", "xcalloc", "av_calloc",
	"realloc", "xrealloc", "av_realloc",
	"reallocarray", "xreallocarray",
	"memcpy"
      };
  enum ALLOC_API : unsigned {
    MALLOC_START = 0,
    MALLOC_END = 4,
    CALLOC_START = 5,
    CALLOC_END = 7,
    REALLOC_START = 8,
    REALLOC_END = 10,
    REALLOCARRAY_START = 11,
    REALLOCARRAY_END = 12,
    MEMCPY_START = 13,
    MEMCPY_END = 13
  };
};
} // end of Melange namespace

#endif
