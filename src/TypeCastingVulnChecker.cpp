#include "TypeCastingVulnChecker.h"

using namespace clang;
using namespace ento;
using namespace Melange;

bool isBadCast(const ExplicitCastExpr *ECE, std::string &Message) {

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

  DEBUG_PRINT("castee is declrefexpr");
  // declrefexpr
  const auto *VD = castDRE->getDecl();
  auto castFromType = VD->getType();
  auto castToType = ECE->getTypeAsWritten();

  if (castFromType == castToType)
    return false;

  DEBUG_PRINT("castfrom type: " + castFromType.getAsString());
  DEBUG_PRINT("castto type: " + castToType.getAsString());

  Message = "Cast From " + castFromType.getAsString() + " to " +
			castToType.getAsString() + " may be unsafe.";

  return true;
}

void TypeCastingVulnChecker::handleAllocArg(const Expr *E, CheckerContext &C) const {
  std::string Message = "";
  const auto *ECE = dyn_cast<ExplicitCastExpr>(E->IgnoreParenImpCasts());
  if (ECE && isBadCast(ECE, Message))
    reportBug(C, ECE->getSourceRange(), Message);
}

void TypeCastingVulnChecker::checkPreStmt(const CallExpr *CE, CheckerContext &C) const {

  const FunctionDecl *FD = C.getCalleeDecl(CE);
  if (!FD)
    return;

  // stdlib calls
  IdentifierInfo *II_malloc = &C.getASTContext().Idents.get("malloc");
  IdentifierInfo *II_calloc = &C.getASTContext().Idents.get("calloc");
  IdentifierInfo *II_realloc = &C.getASTContext().Idents.get("realloc");
  IdentifierInfo *II_reallocarray = &C.getASTContext().Idents.get("reallocarray");
  IdentifierInfo *II_memcpy = &C.getASTContext().Idents.get("memcpy");

  // openssh wrappers
  IdentifierInfo *II_xmalloc = &C.getASTContext().Idents.get("xmalloc");
  IdentifierInfo *II_xcalloc = &C.getASTContext().Idents.get("xcalloc");
  IdentifierInfo *II_xrealloc = &C.getASTContext().Idents.get("xrealloc");
  IdentifierInfo *II_xreallocarray = &C.getASTContext().Idents.get("xreallocarray");

  const auto *funI = FD->getIdentifier();

  if ((funI != II_malloc) && (funI != II_calloc) && (funI != II_xmalloc) && (funI != II_xcalloc)
      && (funI != II_realloc) && (funI != II_reallocarray) && (funI != II_xrealloc)
      && (funI != II_xreallocarray) && (funI != II_memcpy))
      return;

  if ((funI == II_malloc) || (funI == II_xmalloc))
    handleAllocArg(CE->getArg(0), C);
  else if ((funI == II_calloc) || (funI == II_xcalloc)) {
    handleAllocArg(CE->getArg(0), C);
    handleAllocArg(CE->getArg(1), C);
  }
  else if ((funI == II_realloc) || (funI == II_xrealloc))
    handleAllocArg(CE->getArg(1), C);
  else if ((funI == II_reallocarray) || (funI == II_xreallocarray)) {
    handleAllocArg(CE->getArg(1), C);
    handleAllocArg(CE->getArg(2), C);
  }
  else
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
                                       StringRef Message) const {
  const char *name = "Type casting vulnerability checker";
  const char *desc = "Flags potential unsafe casts";

  ExplodedNode *EN = C.generateSink();
  if (!EN)
    return;

  if (!BT)
    BT.reset(new BuiltinBug(this, name, desc));

  BugReport *R = new BugReport(*BT, Message, EN);
  R->addRange(SR);

  C.emitReport(R);
}
