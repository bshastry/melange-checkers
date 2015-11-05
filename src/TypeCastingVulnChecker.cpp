#include "TypeCastingVulnChecker.h"

using namespace clang;
using namespace ento;
using Melange::TypeCastingVulnChecker;

bool isStrictlyPositive(SVal symVal) {
  if (symVal.isConstant() &&
      ((symVal.getBaseKind() == SVal::NonLocKind) &&
	(symVal.getSubKind() == nonloc::ConcreteIntKind))) {

    const nonloc::ConcreteInt& C = symVal.castAs<nonloc::ConcreteInt>();
    const llvm::APInt &value = C.getValue();

    if (value.isStrictlyPositive())
      return true;

    return false;
  }

  // Symval is not a concrete int => may not be strictly positive
  return false;
}

bool isAssumedStrictlyPositive(Optional<NonLoc> symVal, CheckerContext &C) {

  if (!symVal)
    return false;

  ProgramStateRef State = C.getState();
  SValBuilder &SB = C.getSValBuilder();

  llvm::APInt IntMax(32, 2147483647);
  NonLoc IntMaxVal = SB.makeIntVal(IntMax, false);
  llvm::APInt Zero(32, 0);
  NonLoc ZeroVal = SB.makeIntVal(Zero, false);

  SVal condUpper = SB.evalBinOpNN(State, BO_LT, *symVal, IntMaxVal,
                               SB.getConditionType());

  Optional<NonLoc> NLCondUpper = condUpper.getAs<NonLoc>();

  if(!NLCondUpper)
    return false;

  ProgramStateRef stateUT, stateUF;
  std::tie(stateUT, stateUF) = State->assume(*NLCondUpper);

  SVal condLower = SB.evalBinOpNN(State, BO_GT, *symVal, ZeroVal,
                                SB.getConditionType());

  Optional<NonLoc> NLCondLower = condLower.getAs<NonLoc>();

  if(!NLCondLower)
    return false;

  ProgramStateRef stateLT, stateLF;
  std::tie(stateLT, stateLF) = State->assume(*NLCondLower);

  // (0, INT_MAX)
  if ((stateUT && stateLT) && (!stateUF && !stateLF)) {
    DEBUG_PRINT("0 < size < INT_MAX");
    return true;
  }
  // (INT_MAX, UINT64_MAX)
  if (!stateUT && stateUF) {
    DEBUG_PRINT("size > INT_MAX");
    return false;
  }
  // (0,
  if (stateLT && !stateLF) {
    DEBUG_PRINT("size > 0");
    return true;
  }
  // , 0)
  if (!stateLT && stateLF) {
    DEBUG_PRINT("size < 0");
    return false;
  }
  // , INT_MAX)
  DEBUG_PRINT("size is unconstrained");
  return false;
}

bool isUnsafeExpCast(CheckerContext &C, const Expr *E, SVal sym,
                     std::string &Message, std::string &declName) {

  assert(isa<ExplicitCastExpr>(E->IgnoreParenImpCasts()) && "Expr is not explicit cast");

  const ExplicitCastExpr *ECE = cast<ExplicitCastExpr>(E->IgnoreParenImpCasts());

  const auto *ICE = dyn_cast<ImplicitCastExpr>(ECE->getSubExpr());

  if (!ICE)
    return false;

  DEBUG_PRINT("Is implicit cast");

  // Implicitcastexpr

  if (ICE->getCastKind() != CK_LValueToRValue)
    return false;

  DEBUG_PRINT("Involves lvaltorval conv");

  // lvaltorval
  const auto *castDRE = dyn_cast<DeclRefExpr>(ECE->getSubExpr()->IgnoreParenImpCasts());

  if (!castDRE)
    return false;

  if (isStrictlyPositive(sym))
    return false;

  Optional<NonLoc> NL = sym.getAs<NonLoc>();
  if (isAssumedStrictlyPositive(NL, C))
    return false;

  DEBUG_PRINT("castee is declrefexpr and may evaluate to neg int");
  // declrefexpr
  const auto *VD = castDRE->getDecl();
  auto castFromType = VD->getType();
  auto castToType = ECE->getTypeAsWritten();

  if (castFromType == castToType)
    return false;

  if (isa<NamedDecl>(VD))
    declName = cast<NamedDecl>(VD)->getQualifiedNameAsString();

  DEBUG_PRINT("declName: " + declName);
  DEBUG_PRINT("castfrom type: " + castFromType.getAsString());
  DEBUG_PRINT("castto type: " + castToType.getAsString());

  Message = declName + " is explicitly cast from " + castFromType.getAsString() + " to " +
			castToType.getAsString() + ". This may be unsafe.";

  return true;
}

bool isUnsafeImpCast(CheckerContext &C, const ImplicitCastExpr *ICE, SVal sym,
                     std::string &Message, std::string &declName) {
  if (ICE->getCastKind() != CK_IntegralCast)
    return false;

  DEBUG_PRINT("Is integral cast");

  const auto *lvalRvalCast = dyn_cast<ImplicitCastExpr>(ICE->getSubExpr());

  if (!lvalRvalCast)
    return false;

  DEBUG_PRINT("Involves lvaltorval conv");

  const auto *castDRE = dyn_cast<DeclRefExpr>(ICE->IgnoreParenImpCasts());

  if (!castDRE)
    return false;

  if (isStrictlyPositive(sym))
    return false;

  Optional<NonLoc> NL = sym.getAs<NonLoc>();
  if (isAssumedStrictlyPositive(NL, C))
    return false;

  DEBUG_PRINT("castee is declrefexpr and may evaluate to neg int");
  // declrefexpr
  const auto *VD = castDRE->getDecl();
  auto castFromType = VD->getType();
  auto castToType = cast<Expr>(ICE)->getType();

  if (castFromType == castToType)
    return false;

  if (isa<NamedDecl>(VD))
    declName = cast<NamedDecl>(VD)->getQualifiedNameAsString();

  DEBUG_PRINT("declName: " + declName);
  DEBUG_PRINT("castfrom type: " + castFromType.getAsString());
  DEBUG_PRINT("castto type: " + castToType.getAsString());

  Message = declName + " is implicitly cast from " + castFromType.getAsString() + " to " +
			castToType.getAsString() + ". This may be unsafe.";

  return true;
}

void TypeCastingVulnChecker::reportUnsafeExpCasts(const Expr *ECE, SVal sym,
                                                  CheckerContext &C) const {
  std::string Message = "";
  std::string declName = "";
  if (isUnsafeExpCast(C, ECE, sym, Message, declName))
    reportBug(C, ECE->getSourceRange(), Message, declName);
}

void TypeCastingVulnChecker::reportUnsafeImpCasts(const ImplicitCastExpr *ICE,
                                                  SVal sym,
                                                  CheckerContext &C) const {
  std::string Message = "";
  std::string declName = "";
  if (isUnsafeImpCast(C, ICE, sym, Message, declName))
    reportBug(C, ICE->getSourceRange(), Message, declName);
}

void TypeCastingVulnChecker::handleAllocArg(const Expr *E, SVal sym,
                                            CheckerContext &C) const {

  const auto *ECE = dyn_cast<ExplicitCastExpr>(E->IgnoreParenImpCasts());
  const auto *ICE = dyn_cast<ImplicitCastExpr>(E);

  if (ECE)
    reportUnsafeExpCasts(E, sym, C);
  else if (ICE)
    reportUnsafeImpCasts(ICE, sym, C);
}

void TypeCastingVulnChecker::checkPreCall(const CallEvent &CE,
                                          CheckerContext &C) const {

  std::vector<IdentifierInfo *> IIvec;
  for (auto &i : callNames)
    IIvec.push_back(&C.getASTContext().Idents.get(i));

  const auto *funI = CE.getCalleeIdentifier();
  auto iter = std::find(IIvec.begin(), IIvec.end(), funI);

  if (iter == IIvec.end())
    return;

  auto index = std::distance(IIvec.begin(), iter);

  DEBUG_PRINT("Index is: " + std::to_string(index));

  if ((index >= MALLOC_START) && (index <= MALLOC_END))
    handleAllocArg(CE.getArgExpr(0), CE.getArgSVal(0), C);
  else if ((index >= CALLOC_START) && (index <= CALLOC_END)) {
    handleAllocArg(CE.getArgExpr(0), CE.getArgSVal(0), C);
    handleAllocArg(CE.getArgExpr(1), CE.getArgSVal(1), C);
  }
  else if ((index >= REALLOC_START) && (index <= REALLOC_END))
    handleAllocArg(CE.getArgExpr(1), CE.getArgSVal(1), C);
  else if ((index >= REALLOCARRAY_START) && (index <= REALLOCARRAY_END)) {
    handleAllocArg(CE.getArgExpr(1), CE.getArgSVal(1), C);
    handleAllocArg(CE.getArgExpr(2), CE.getArgSVal(2), C);
  }
  else if ((index >= MEMCPY_START) && (index <= STRCPY_END))
    handleAllocArg(CE.getArgExpr(2), CE.getArgSVal(2), C);
}

//ProgramStateRef TypeCastingVulnChecker::evalAssume(ProgramStateRef S, SVal cond,
//                                                   bool assumption) const {
//  SymbolRef sym = cond.getAsSymbol();
//  ConstraintManager &CM = S->getConstraintManager();
//  if (sym) {
//    SymExpr::Kind K = sym->getKind();
//    if ((K >= SymExpr::Kind::BEGIN_BINARYSYMEXPRS) && (K <= SymExpr::Kind::END_BINARYSYMEXPRS)) {
////	sym->dump();
//	ProgramStateRef stateT, stateF;
//	Optional<Loc> loc = cond.getAs<Loc>();
//	Optional<NonLoc> nonloc = cond.getAs<NonLoc>();
//	if (loc)
//	  std::tie(stateT, stateF) = CM.assumeDual(S, *loc);
//	else if (nonloc)
//	  std::tie(stateT, stateF) = CM.assumeDual(S, *nonloc);
//
//	if (stateT && !stateF)
//	  llvm::errs() << "Assertion of condition\n";
//    }
//  }
//  return S;
//}

void TypeCastingVulnChecker::reportBug(CheckerContext &C, SourceRange SR,
                                       StringRef Message, StringRef declName) const {
  const char *name = "Type casting vulnerability checker";
  const char *desc = "Flags potential unsafe casts";

  ExplodedNode *EN = C.generateSink();
  if (!EN)
    return;

  if (!BT)
    BT.reset(new BuiltinBug(this, name, desc));

  BugReport *R = new BugReport(*BT, Message, EN);
  R->addRange(SR);

  Diag.encodeBugInfo(declName, C);
  for (auto &i : Diag.getBugInfoDiag()) {
      R->addExtraText(i);
   }

  C.emitReport(R);
}
