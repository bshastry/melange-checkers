#ifndef MELANGE_TYPECASTINGVULN_CHECKER_H
#define MELANGE_TYPECASTINGVULN_CHECKER_H

#include "clang/StaticAnalyzer/Core/Checker.h"

namespace Melange {

class TypeCastingVulnChecker : public clang::ento::Checker<clang::ento::check::PreStmt<clang::ExplicitCastExpr>> {
public:
  void checkPreStmt(const clang::ExplicitCastExpr *ECE, clang::ento::CheckerContext &C) const;
};
} // end of Melange namespace

#endif
