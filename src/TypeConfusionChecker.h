#ifndef MELANGE_TYPECONFUSION_CHECKER_H
#define MELANGE_TYPECONFUSION_CHECKER_H

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

class TypeConfusionChecker : public clang::ento::Checker<clang::ento::check::PreStmt<clang::CastExpr>,
							 clang::ento::check::PreStmt<clang::CallExpr>,
							 clang::ento::check::PreStmt<clang::BinaryOperator>> {

  mutable Diagnostics Diag;

public:
  void checkPreStmt(const clang::CastExpr *CE, clang::ento::CheckerContext &C) const;
  void checkPreStmt(const clang::CallExpr *CaE, clang::ento::CheckerContext &C) const;
  void checkPreStmt(const clang::BinaryOperator *BO, clang::ento::CheckerContext &C) const;
  void reportBug(clang::ento::CheckerContext &C, clang::SourceRange SR,
                 llvm::StringRef Message, llvm::StringRef declName) const;

private:
  mutable std::unique_ptr<clang::ento::BugType> BT;
};
} // end of Melange namespace


#endif
