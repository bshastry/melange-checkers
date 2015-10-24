#include "StrCpyOverflowChecker.h"

using namespace clang;
using namespace ento;
using Melange::StrCpyOverflowChecker;

void StrCpyOverflowChecker::checkPreStmt(const CallExpr *CE, CheckerContext &C) const {

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

//  auto index = std::distance(IIvec.begin(), iter);
//
//  DEBUG_PRINT("Index is: " + std::to_string(index));

  handleStrArgs(CE->getArg(0), CE->getArg(1), C);
}

void StrCpyOverflowChecker::handleStrArgs(const clang::Expr *E1,
                                          const clang::Expr *E2,
                                          clang::ento::CheckerContext &C) const {

  // Strip arguments of imp casts and parentheses
  const auto dest = E1->IgnoreParenImpCasts();
  const auto src = E2->IgnoreParenImpCasts();

  // Keep it simple and look for declrefexpr's only
  if (!isa<DeclRefExpr>(dest))
    return;

  const DeclRefExpr *DREDest = cast<DeclRefExpr>(dest);

  if (!isa<DeclRefExpr>(src))
    return;

  const DeclRefExpr *DRESrc = cast<DeclRefExpr>(src);

  // Destination must be fixed size buffer
  if (!isa<ConstantArrayType>(DREDest->getDecl()->getType()))
    return;

  // Source must be a pointer type
  if (!DRESrc->getDecl()->getType().getTypePtr()->isPointerType())
    return;

  // Source must be an input parameter to function
  if (!isa<ParmVarDecl>(DRESrc->getDecl()))
    return;

  std::string Message = "Destination of str* call is a fixed size buffer that can potentially overflow";

  // Report bug
  reportBug(C, DREDest->getSourceRange(), Message, DREDest->getDecl()->getQualifiedNameAsString());
}

void StrCpyOverflowChecker::reportBug(CheckerContext &C, SourceRange SR,
                                       StringRef Message, StringRef declName) const {
  const char *name = "Strcpy overflow checker";
  const char *desc = "Flags potential overflows due to strcpy";

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
