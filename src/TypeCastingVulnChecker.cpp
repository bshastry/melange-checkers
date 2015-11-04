#include "TypeCastingVulnChecker.h"

using namespace clang;
using namespace ento;
using Melange::TypeCastingVulnChecker;

//bool canConstantFold(const DeclRefExpr *DRE, CheckerContext &C) {
//  ASTContext &ASTC = C.getASTContext();
//
//  // Don't know <=> (number <= 0)
//  if (!DRE->isEvaluatable(ASTC))
//    return false;
//
//  DEBUG_PRINT("Can be constant folded");
//
//  llvm::APSInt result;
//  DRE->EvaluateAsInt(result, ASTC);
//
//  if (cast<llvm::APInt>(result).isStrictlyPositive())
//    return true;
//
//  return false;
//}

bool isStrictlyPositive(const Expr *E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  SVal symVal = State->getSVal(E, C.getLocationContext());
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

bool isUnsafeExpCast(CheckerContext &C, const Expr *E,
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

  if (isStrictlyPositive(E, C))
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

bool isUnsafeImpCast(CheckerContext &C, const ImplicitCastExpr *ICE,
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

  if (isStrictlyPositive(ICE, C))
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

void TypeCastingVulnChecker::reportUnsafeExpCasts(const Expr *ECE,
                                                  CheckerContext &C) const {
  std::string Message = "";
  std::string declName = "";
  if (isUnsafeExpCast(C, ECE, Message, declName))
    reportBug(C, ECE->getSourceRange(), Message, declName);
}

void TypeCastingVulnChecker::reportUnsafeImpCasts(const ImplicitCastExpr *ICE,
                                                  CheckerContext &C) const {
  std::string Message = "";
  std::string declName = "";
  if (isUnsafeImpCast(C, ICE, Message, declName))
    reportBug(C, ICE->getSourceRange(), Message, declName);
}

void TypeCastingVulnChecker::handleAllocArg(const Expr *E, CheckerContext &C) const {

  const auto *ECE = dyn_cast<ExplicitCastExpr>(E->IgnoreParenImpCasts());
  const auto *ICE = dyn_cast<ImplicitCastExpr>(E);

  if (ECE)
    reportUnsafeExpCasts(E, C);
  else if (ICE)
    reportUnsafeImpCasts(ICE, C);
}

void TypeCastingVulnChecker::checkPreStmt(const CallExpr *CE, CheckerContext &C) const {

  const FunctionDecl *FD = C.getCalleeDecl(CE);
  if (!FD)
    return;

  std::vector<IdentifierInfo *> IIvec;
  for (auto &i : callNames)
    IIvec.push_back(&C.getASTContext().Idents.get(i));

  const auto *funI = FD->getIdentifier();
  auto iter = std::find(IIvec.begin(), IIvec.end(), funI);

  if (iter == IIvec.end())
    return;

  auto index = std::distance(IIvec.begin(), iter);

  DEBUG_PRINT("Index is: " + std::to_string(index));

  if ((index >= MALLOC_START) && (index <= MALLOC_END))
    handleAllocArg(CE->getArg(0),C);
  else if ((index >= CALLOC_START) && (index <= CALLOC_END)) {
    handleAllocArg(CE->getArg(0), C);
    handleAllocArg(CE->getArg(1), C);
  }
  else if ((index >= REALLOC_START) && (index <= REALLOC_END))
    handleAllocArg(CE->getArg(1), C);
  else if ((index >= REALLOCARRAY_START) && (index <= REALLOCARRAY_END)) {
    handleAllocArg(CE->getArg(1), C);
    handleAllocArg(CE->getArg(2), C);
  }
  else if ((index >= MEMCPY_START) && (index <= STRCPY_END))
    handleAllocArg(CE->getArg(2), C);
}

void TypeCastingVulnChecker::checkPreStmt(const ExplicitCastExpr *ECE, CheckerContext &C) const {

//  const auto *CE = static_cast<const CastExpr *>(ECE);
//  const auto *castSE = CE->getSubExpr();
//  const auto *ICE = dyn_cast<ImplicitCastExpr>(castSE);
//
//  if (!ICE)
//    return;
//
//  DEBUG_PRINT("Is implicit cast");
//
//  // Implicitcastexpr
//
//  if (ICE->getCastKind() != CK_LValueToRValue)
//    return;
//
//  DEBUG_PRINT("Involves lvaltorval conv");
//
//  // lvaltorval
//
//  const auto *castCore = castSE->IgnoreParenImpCasts();
//  const auto *castDRE = dyn_cast<DeclRefExpr>(castCore);
//  if (!castDRE)
//      return;
//
//  DEBUG_PRINT("castee is declrefexpr");
//  // declrefexpr
//  const auto *VD = castDRE->getDecl();
//  auto castFromType = VD->getType();
//  auto castToType = ECE->getTypeAsWritten();

  // Check if cast is on a parmvardecl in a memory allocation function
//  {
//    if (isa<ParmVarDecl>(VD)) {
//	const auto &parentArray = C.getASTContext().getParents(*VD);
//	if (!parentArray.empty()) {
//	    for (auto &i : parentArray) {
//		if (const auto *decl = i.get<Decl>()) {
//		    if (isa<FunctionDecl>(decl)) {
//			const auto *fDecl = cast<FunctionDecl>(decl);
//			const auto *funI = fDecl->getIdentifier();
//			IdentifierInfo *II_malloc = &C.getASTContext().Idents.get("malloc");
//			IdentifierInfo *II_calloc = &C.getASTContext().Idents.get("calloc");
//			if ((funI == II_malloc) || (funI == II_calloc)) {
//			    if (castFromType != castToType) {
//				std::string Message = "Unsafe cast from " + castFromType.getAsString() +
//				    " to " + castToType.getAsString() + " inside a memory allocator";
//				reportBug(C, ECE->getSourceRange(), Message);
//				return;
//			    }
//			}
//		    }
//		}
//	    }
//	}
//    }
//  }

//  if (castFromType == castToType)
//    return;
//
//  DEBUG_PRINT("castfrom type: " + castFromType.getAsString());
//  DEBUG_PRINT("castto type: " + castToType.getAsString());
//
//  std::string Message = "Cast From " + castFromType.getAsString() + " to " +
//			castToType.getAsString() + " may be unsafe.";
//
//  // Report bug
//  reportBug(C, ECE->getSourceRange(), Message);
}

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
