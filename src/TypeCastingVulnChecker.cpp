#include "TypeCastingVulnChecker.h"

using namespace clang;
using namespace ento;
using namespace Melange;

void TypeCastingVulnChecker::checkPreStmt(const ExplicitCastExpr *ECE, CheckerContext &C) const {

  const auto *CE = static_cast<const CastExpr *>(ECE);
  const auto *castSE = CE->getSubExpr();
  const auto *ICE = dyn_cast<ImplicitCastExpr>(castSE);

  if (!ICE)
    return;

  DEBUG_PRINT("Is implicit cast");

  // Implicitcastexpr

  if (ICE->getCastKind() != CK_LValueToRValue)
    return;

  DEBUG_PRINT("Involves lvaltorval conv");

  // lvaltorval

  const auto *castCore = castSE->IgnoreParenImpCasts();
  const auto *castDRE = dyn_cast<DeclRefExpr>(castCore);
  if (!castDRE)
      return;

  DEBUG_PRINT("castee is declrefexpr");
  // declrefexpr
  const auto *VD = castDRE->getDecl();
  auto castFromType = VD->getType();
  auto castToType = ECE->getTypeAsWritten();

  if (castFromType == castToType)
    return;

  DEBUG_PRINT("castfrom type: " + castFromType.getAsString());
  DEBUG_PRINT("castto type: " + castToType.getAsString());

  std::string Message = "Cast From " + castFromType.getAsString() + " to " +
			castToType.getAsString() + " may be unsafe.";

  // Report bug
  reportBug(C, ECE->getSourceRange(), Message);
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
