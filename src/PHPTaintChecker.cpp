//== PHPTaintChecker.cpp ----------------------------------- -*- C++ -*--=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This checker defines the attack surface for PHP taint propagation.
//
// The taint information produced by it might be useful to other checkers. For
// example, checkers should report errors which involve tainted data more
// aggressively, even if the involved symbols are under constrained.
//
//===----------------------------------------------------------------------===//
#include "PHPTaintChecker.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;
using namespace ento;
using namespace Melange;

/// A set which is used to pass information from call pre-visit instruction
/// to the call post-visit. The values are unsigned integers, which are either
/// ReturnValueIndex, or indexes of the pointer/reference argument, which
/// points to data, which should be tainted on return.
REGISTER_SET_WITH_PROGRAMSTATE(TaintArgsOnPostVisit, unsigned)

static const char MsgZendTaint[] =
  "Untrusted data in Zend macro ";

PHPTaintChecker::TaintPropagationRule
PHPTaintChecker::TaintPropagationRule::getTaintPropagationRule(StringRef Name,
                                              CheckerContext &C) {
  // TODO: Currently, we might loose precision here: we always mark a return
  // value as tainted even if it's just a pointer, pointing to tainted data.

  // Check for exact name match for functions without builtin substitutes.
  TaintPropagationRule Rule = llvm::StringSwitch<TaintPropagationRule>(Name)
//    .Case("zend_hash_find", TaintPropagationRule(InvalidArgIndex, 3))
//    .Case("zend_hash_quick_find", TaintPropagationRule(InvalidArgIndex, 4))
//    .Case("zend_hash_index_find", TaintPropagationRule(InvalidArgIndex, 2))
//    .Case("zend_read_property", TaintPropagationRule(InvalidArgIndex, ReturnValueIndex))
//    .Case("zend_read_static_property", TaintPropagationRule(InvalidArgIndex, ReturnValueIndex))
    .Default(TaintPropagationRule());

  if (!Rule.isNull())
    return Rule;

  return TaintPropagationRule();
}

void PHPTaintChecker::checkPreStmt(const CallExpr *CE,
                                   CheckerContext &C) const {
  // Check for errors first.
  if (checkPre(CE, C))
    return;

  // Add taint second.
  addSourcesPre(CE, C);
}

void PHPTaintChecker::checkPostStmt(const CallExpr *CE,
                                    CheckerContext &C) const {
  if (propagateFromPre(CE, C))
    return;
  addSourcesPost(CE, C);
}

void PHPTaintChecker::addSourcesPre(const CallExpr *CE,
                                        CheckerContext &C) const {
  ProgramStateRef State = nullptr;
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl || FDecl->getKind() != Decl::Function)
    return;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return;

  // First, try generating a propagation rule for this function.
  TaintPropagationRule Rule =
    TaintPropagationRule::getTaintPropagationRule(Name, C);
  if (!Rule.isNull()) {
    State = Rule.process(CE, C);
    if (!State)
      return;
    C.addTransition(State);
    return;
  }

  // Otherwise, check if we have custom pre-processing implemented.
  FnCheck evalFunction = llvm::StringSwitch<FnCheck>(Name)
    .Case("zend_hash_find", &PHPTaintChecker::prePHPTaintSources)
    .Case("zend_hash_quick_find", &PHPTaintChecker::prePHPTaintSources)
    .Case("zend_hash_index_find", &PHPTaintChecker::prePHPTaintSources)
    .Default(nullptr);
  // Check and evaluate the call.
  if (evalFunction)
    State = (this->*evalFunction)(CE, C);
  if (!State)
    return;
  C.addTransition(State);
}

bool PHPTaintChecker::propagateFromPre(const CallExpr *CE,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Depending on what was tainted at pre-visit, we determined a set of
  // arguments which should be tainted after the function returns. These are
  // stored in the state as TaintArgsOnPostVisit set.
  TaintArgsOnPostVisitTy TaintArgs = State->get<TaintArgsOnPostVisit>();
  if (TaintArgs.isEmpty())
    return false;

  for (llvm::ImmutableSet<unsigned>::iterator
         I = TaintArgs.begin(), E = TaintArgs.end(); I != E; ++I) {
    unsigned ArgNum  = *I;

    // Special handling for the tainted return value.
    if (ArgNum == ReturnValueIndex) {
      State = State->addTaint(CE, C.getLocationContext());
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (CE->getNumArgs() < (ArgNum + 1))
      return false;
    const Expr* Arg = CE->getArg(ArgNum);
    SymbolRef Sym = getPointedToSymbol(C, Arg);
    if (Sym)
      State = State->addTaint(Sym);
  }

  // Clear up the taint info from the state.
  State = State->remove<TaintArgsOnPostVisit>();

  if (State != C.getState()) {
    C.addTransition(State);
    return true;
  }
  return false;
}

void PHPTaintChecker::addSourcesPost(const CallExpr *CE,
                                         CheckerContext &C) const {
  // Define the attack surface.
  // Set the evaluation function by switching on the callee name.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl || FDecl->getKind() != Decl::Function)
    return;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return;
  FnCheck evalFunction = llvm::StringSwitch<FnCheck>(Name)
    .Case("zend_read_property", &PHPTaintChecker::postRetTaint)
    .Case("zend_read_static_property", &PHPTaintChecker::postRetTaint)
    .Default(nullptr);

  // If the callee isn't defined, it is not of security concern.
  // Check and evaluate the call.
  ProgramStateRef State = nullptr;
  if (evalFunction)
    State = (this->*evalFunction)(CE, C);
  if (!State)
    return;

  C.addTransition(State);
}

/// Check taint before processing function call
bool PHPTaintChecker::checkPre(const CallExpr *CE, CheckerContext &C) const{

  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl || FDecl->getKind() != Decl::Function)
    return false;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return false;

  if (checkPHPSinks(CE, Name, C))
    return true;

  return false;
}

SymbolRef PHPTaintChecker::getPointedToSymbol(CheckerContext &C,
                                                  const Expr* Arg) {
  ProgramStateRef State = C.getState();
  SVal AddrVal = State->getSVal(Arg->IgnoreParens(), C.getLocationContext());
  if (AddrVal.isUnknownOrUndef())
    return nullptr;

  Optional<Loc> AddrLoc = AddrVal.getAs<Loc>();
  if (!AddrLoc)
    return nullptr;

  const PointerType *ArgTy =
    dyn_cast<PointerType>(Arg->getType().getCanonicalType().getTypePtr());
  SVal Val = State->getSVal(*AddrLoc,
                            ArgTy ? ArgTy->getPointeeType(): QualType());
  return Val.getAsSymbol();
}

ProgramStateRef
PHPTaintChecker::TaintPropagationRule::process(const CallExpr *CE,
                                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Check for taint in arguments.
  bool IsTainted = false;
  for (ArgVector::const_iterator I = SrcArgs.begin(),
                                 E = SrcArgs.end(); I != E; ++I) {
    unsigned ArgNum = *I;

    if (ArgNum == InvalidArgIndex) {
      // Check if any of the arguments is tainted, but skip the
      // destination arguments.
      for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
        if (isDestinationArgument(i))
          continue;
        if ((IsTainted = isTaintedOrPointsToTainted(CE->getArg(i), State, C)))
          break;
      }
      break;
    }

    if (CE->getNumArgs() < (ArgNum + 1))
      return State;
    if ((IsTainted = isTaintedOrPointsToTainted(CE->getArg(ArgNum), State, C)))
      break;
  }
  if (!IsTainted)
    return State;

  // Mark the arguments which should be tainted after the function returns.
  for (ArgVector::const_iterator I = DstArgs.begin(),
                                 E = DstArgs.end(); I != E; ++I) {
    unsigned ArgNum = *I;

    // Should we mark all arguments as tainted?
    if (ArgNum == InvalidArgIndex) {
      // For all pointer and references that were passed in:
      //   If they are not pointing to const data, mark data as tainted.
      //   TODO: So far we are just going one level down; ideally we'd need to
      //         recurse here.
      for (unsigned int i = 0; i < CE->getNumArgs(); ++i) {
        const Expr *Arg = CE->getArg(i);
        // Process pointer argument.
        const Type *ArgTy = Arg->getType().getTypePtr();
        QualType PType = ArgTy->getPointeeType();
        if ((!PType.isNull() && !PType.isConstQualified())
            || (ArgTy->isReferenceType() && !Arg->getType().isConstQualified()))
          State = State->add<TaintArgsOnPostVisit>(i);
      }
      continue;
    }

    // Should mark the return value?
    if (ArgNum == ReturnValueIndex) {
      State = State->add<TaintArgsOnPostVisit>(ReturnValueIndex);
      continue;
    }

    // Mark the given argument.
    assert(ArgNum < CE->getNumArgs());
    State = State->add<TaintArgsOnPostVisit>(ArgNum);
  }

  return State;
}


// If argument 0 (file descriptor) is tainted, all arguments except for arg 0
// and arg 1 should get taint.
ProgramStateRef PHPTaintChecker::prePHPTaintSources(const CallExpr *CE,
                                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl || FDecl->getKind() != Decl::Function)
    return State;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return State;

  unsigned taintArgNum = llvm::StringSwitch<unsigned>(Name)
      .Case("zend_hash_find", 3)
      .Case("zend_hash_quick_find", 4)
      .Case("zend_hash_index_find", 2)
      .Default(InvalidArgIndex);

  if (taintArgNum == InvalidArgIndex)
    return State;

  /// Sanity check
  assert((taintArgNum < CE->getNumArgs() || taintArgNum == ReturnValueIndex) &&
         "Taint generation rule invalid");

  return State->add<TaintArgsOnPostVisit>(taintArgNum);
}

ProgramStateRef PHPTaintChecker::postRetTaint(const CallExpr *CE,
                                                  CheckerContext &C) const {
  return C.getState()->addTaint(CE, C.getLocationContext());
}

bool PHPTaintChecker::generateReportIfTainted(const Expr *E,
                                                  const char Msg[],
                                                  CheckerContext &C) const {
  assert(E);

  // Check for taint.
  ProgramStateRef State = C.getState();
  if (!State->isTainted(getPointedToSymbol(C, E)) &&
      !State->isTainted(E, C.getLocationContext()))
    return false;

  // Generate diagnostic.
  if (ExplodedNode *N = C.addTransition()) {
    initBugType();
    BugReport *report = new BugReport(*BT, Msg, N);
    report->addRange(E->getSourceRange());

    {
      Diag.encodeBugInfo("", C);
      for (auto &i : Diag.getBugInfoDiag())
	report->addExtraText(i);
    }

    C.emitReport(report);
    return true;
  }
  return false;
}

bool PHPTaintChecker::checkPHPSinks(const CallExpr *CE, StringRef Name,
                                    CheckerContext &C) const {
  // TODO: It might make sense to run this check on demand. In some cases,
  // we should check if the environment has been cleansed here. We also might
  // need to know if the user was reset before these calls(seteuid).
  unsigned ArgNum = llvm::StringSwitch<unsigned>(Name)
    .Case("ZF_STRVAL", 0)
    .Case("ZF_STRVAL_P", 0)
    .Case("ZF_STRVAL_PP", 0)
    .Case("ZF_ARRVAL", 0)
    .Case("ZF_ARRVAL_P", 0)
    .Case("ZF_ARRVAL_PP", 0)
    .Default(UINT_MAX);

  if (ArgNum == UINT_MAX || CE->getNumArgs() < (ArgNum + 1))
    return false;

  if (generateReportIfTainted(CE->getArg(ArgNum),
                              MsgZendTaint, C))
    return true;

  return false;
}
