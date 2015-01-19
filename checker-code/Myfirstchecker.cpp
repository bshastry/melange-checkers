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

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
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


  /* Insert checker logic here */

  /* I intended my first checker to catch integer overflows. We need to:
   * - Examine statements with the add assign operator
   * - Check if the addition results in an overflow (Not sure if this is the best way to look for overflows)
   * e.g., var += exp; Is var+exp > Range of var's data-type
   */

  /* Return if binop is not addassign */
  if(B->getOpcode() != BO_AddAssign)
     return;

  /* Evaluate
   * r = Range of data type of var
   * if var + exp > r
   */
  Expr exp = B->getRHS();
  
  // TODO : Write the checker!

  /* This is useless at the moment
   * Retained sink code for template's sake
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
