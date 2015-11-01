#include "TypeConfusionChecker.h"


using namespace clang;
using namespace ento;
using Melange::TypeConfusionChecker;

REGISTER_MAP_WITH_PROGRAMSTATE(TypeMap, const ValueDecl*, QualType)

const QualType *isVoidPtr(CheckerContext &C, const Expr* E) {
  if (!isa<DeclRefExpr>(E))
    return nullptr;

  const auto *VD = cast<DeclRefExpr>(E)->getDecl();

  ProgramStateRef State = C.getState();
  const QualType *T = State->get<TypeMap>(VD);
  return T;
}

void TypeConfusionChecker::checkPreStmt(const clang::CastExpr *CE,
                                        clang::ento::CheckerContext &C) const {
  if (isa<ImplicitCastExpr>(CE))
    return;

  DEBUG_PRINT("Explicit cast expression");

  const auto *E = CE->getSubExpr()->IgnoreParenImpCasts();
  if (!isa<DeclRefExpr>(E))
    return;

  DEBUG_PRINT("Found declref expr");

  ProgramStateRef State = C.getState();
  const ValueDecl *VD = cast<DeclRefExpr>(E)->getDecl();
  const QualType *QT = State->get<TypeMap>(VD);

  if (!QT)
    return;

  DEBUG_PRINT("Obtained value from key");

  // Compare Cast To type to T
  if (!isa<ExplicitCastExpr>(CE))
    return;

  const Type *castTo = cast<ExplicitCastExpr>(CE)->getTypeAsWritten().getTypePtr();

  std::string declName, Message, castFromTyString, castToTyString;
  castToTyString = castTo->getCanonicalTypeInternal().getAsString();
  castFromTyString = QT->getAsString();

  if (castToTyString.compare(castFromTyString) == 0)
    return;

  DEBUG_PRINT("Type comparison failed");

  if (isa<NamedDecl>(VD))
      declName = cast<NamedDecl>(VD)->getQualifiedNameAsString();

  Message = declName + " is unsafely cast from " + castFromTyString + " to " +
			castToTyString;

  reportBug(C, CE->getSourceRange(), Message, declName);
}

void TypeConfusionChecker::checkPreStmt(const clang::CallExpr *CaE,
                                        clang::ento::CheckerContext &C) const {
  return;
}

void TypeConfusionChecker::checkPreStmt(const clang::BinaryOperator *BO,
                                        clang::ento::CheckerContext &C) const {

  if (BO->getOpcode() != BO_Assign)
    return;

  DEBUG_PRINT("Assignment");

  const auto *LHS = BO->getLHS()->IgnoreParenImpCasts();

  if (!isa<DeclRefExpr>(LHS))
    return;

  DEBUG_PRINT("DeclRefExpr");

  const auto *LDecl = cast<DeclRefExpr>(LHS)->getDecl();

  if (!(LDecl->getType().getTypePtr()->isVoidPointerType()))
    return;

  DEBUG_PRINT("LHS is void ptr");

  const auto *RHS = BO->getRHS()->IgnoreParens();

  if (!isa<ImplicitCastExpr>(RHS))
    return;

  ProgramStateRef State = C.getState();

  if (cast<CastExpr>(RHS)->getCastKind() != CK_BitCast) {
    const QualType *RT = isVoidPtr(C, RHS->IgnoreImpCasts());
    if (!RT)
      return;

    DEBUG_PRINT("RHS is void ptr that has been cast to " + RT->getAsString());

    State = State->set<TypeMap>(LDecl, *(const_cast<QualType *>(RT)));
    if(State != C.getState()) {
      DEBUG_PRINT("Value is " + State->get<TypeMap>(LDecl)->getAsString());
      C.addTransition(State);
    }
    return;
  }

  DEBUG_PRINT("RHS is being bitcast");

  State = State->set<TypeMap>(LDecl, RHS->IgnoreImpCasts()->getType());
  if(State != C.getState()) {
    DEBUG_PRINT("Value is " + State->get<TypeMap>(LDecl)->getAsString());
    C.addTransition(State);
  }
}

void TypeConfusionChecker::reportBug(CheckerContext &C, SourceRange SR,
                                       StringRef Message, StringRef declName) const {
  const char *name = "Type confusion checker";
  const char *desc = "Flags unsafe casts";

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
