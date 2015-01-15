/*
 * Myfirstchecker.cpp
 *
 *  Created on: Jan 12, 2015
 *      Author: bhargava
 *
//===----------------------------------------------------------------------===//
//
// This files defines Myfirstchecker, a custom checker that checks for
// integer overflows on variables.
//
//===----------------------------------------------------------------------===//
 */

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class Myfirstchecker : public Checker<check::PreStmt<BinaryOperator> > {
  mutable std::unique_ptr<BuiltinBug> BT;

public:
  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;
};
}

void Myfirstchecker::checkPreStmt(const BinaryOperator *B,
                                     CheckerContext &C) const {


  /* We would need to catch stuff like:
   * var += exp;
   */
  if(B->getOpcode() != BO_AddAssign)
     return;

  /* Evaluate
   * r = Range of data type of var
   * if var + exp > r
   */


  if (ExplodedNode *N = C.addTransition()) {
    if (!BT)
      BT.reset(
          new BuiltinBug(this, "Add assign operator",
                         "Simply flagging add assign at the moment"));
    BugReport *R = new BugReport(*BT, BT->getDescription(), N);
    R->addRange(B->getSourceRange());
    C.emitReport(R);
  }
}

// Register plugin!
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<Myfirstchecker>("alpha.security.myfirstchecker", "My first checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
