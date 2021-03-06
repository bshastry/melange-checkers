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

StringRef getCallName(const CallExpr *CE, CheckerContext &C) {
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl || FDecl->getKind() != Decl::Function)
    return StringRef();

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return StringRef();

  return Name;
}

StringRef getCallNameFromArgExpr(const Stmt *S, CheckerContext &C) {
  const auto &parents = C.getASTContext().getParents(*S);

  if (parents.empty())
    return StringRef();

  const Stmt *parent = parents.front().get<Stmt>();
  if (!parent)
    return StringRef();

  const CallExpr *CE = dyn_cast<CallExpr>(parent);
  if (!CE)
    return StringRef();

  return getCallName(CE, C);
}

PHPTaintChecker::TaintPropagationRule
PHPTaintChecker::TaintPropagationRule::getTaintPropagationRule(StringRef Name,
                                              CheckerContext &C) {
  // TODO: Currently, we might loose precision here: we always mark a return
  // value as tainted even if it's just a pointer, pointing to tainted data.

  // Check for exact name match for functions without builtin substitutes.
  TaintPropagationRule Rule = llvm::StringSwitch<TaintPropagationRule>(Name)
    .Case("convert_to_string", TaintPropagationRule(0, 0, false, true))
    .Case("convert_to_array", TaintPropagationRule(0, 0, false, true))
    .Case("convert_to_long", TaintPropagationRule(0, 0, false, true))
    .Default(TaintPropagationRule());

  if (!Rule.isNull())
    return Rule;

  return TaintPropagationRule();
}

void PHPTaintChecker::checkPreStmt(const CallExpr *CE,
                                   CheckerContext &C) const {
  DEBUG_PRINT("In PreStmt<CallExpr>");
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

void PHPTaintChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  /// Bail if we are not loading/storing a tainted value
  if (!State->isTainted(Loc))
    return;

  /// Taint is flowing either into a sanitizer or a sink macro
  /// First, check for former, then latter
  StringRef SanName;
  SourceLocation MacroLoc = cast<Expr>(S)->getExprLoc();

  if (MacroLoc.isMacroID())
    SanName = C.getMacroNameOrSpelling(MacroLoc);
  else
    SanName = getCallNameFromArgExpr(S, C);

  if (SanName.empty())
    return;

  SanHandler evalSanitized = llvm::StringSwitch<SanHandler>(SanName)
	  .Case("Z_TYPE", &PHPTaintChecker::postSanTaint)
	  .Case("convert_to_string", &PHPTaintChecker::postSanTaint)
	  .Case("convert_to_long", &PHPTaintChecker::postSanTaint)
	  .Case("convert_to_array", &PHPTaintChecker::postSanTaint)
	  .Default(nullptr);

  if (evalSanitized) {
    DEBUG_PRINT("In san");
    assert(isa<Expr>(S) && "A non-expr statement seen in sanitizer macro");
    State = (this->*evalSanitized)(Loc, C);
    if (State != C.getState())
      C.addTransition(State);
    return;
  }

  /// Check if we are in a sink
  bool isSink = llvm::StringSwitch<bool>(SanName)
	  .Case("Z_STRVAL", true)
	  .Case("Z_ARRVAL", true)
	  .Default(false);

  if (isSink) {
    DEBUG_PRINT("In sink");
    assert(isa<Expr>(S) && "A non-expr statement seen in sink macro");
    generateReport(cast<Expr>(S), MsgZendTaint, C);
  }
}

ProgramStateRef PHPTaintChecker::postSanTaint(SVal sval, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  SymbolRef Sym = sval.getAsSymbol();
  if (!Sym)
    return State;

  DEBUG_PRINT("Removing taint");

  State = State->removeTaint(Sym);
  assert(State && "State corruption post taint removal");
  return State;
}

void PHPTaintChecker::addSourcesPre(const CallExpr *CE,
                                        CheckerContext &C) const {
  ProgramStateRef State = nullptr;

  StringRef Name = getCallName(CE, C);
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

  DEBUG_PRINT("Generating taint on vulnerable source APIs");

  // Otherwise, check if we have custom pre-processing implemented.
  FnCheck evalFunction = llvm::StringSwitch<FnCheck>(Name)
    .Case("zend_hash_find", &PHPTaintChecker::prePHPTaintSources)
    .Case("zend_hash_quick_find", &PHPTaintChecker::prePHPTaintSources)
    .Case("zend_hash_index_find", &PHPTaintChecker::prePHPTaintSources)
    .Case("_ldap_hash_fetch", &PHPTaintChecker::prePHPTaintSources)
    .Case("php_stream_context_get_option", &PHPTaintChecker::prePHPTaintSources)
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
  StringRef Name = getCallName(CE, C);

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
      DEBUG_PRINT("Adding taint on return value");
      State = State->addTaint(CE, C.getLocationContext());
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (CE->getNumArgs() < (ArgNum + 1))
      return false;
    const Expr* Arg = CE->getArg(ArgNum);
    DEBUG_PRINT("Getting pointed to symbol");
    SymbolRef Sym = getPointedToSymbol(C, Arg);

    PHPTaintChecker::TaintPropagationRule Rule = getRule(Name, C);
    DEBUG_PRINT(Name);
    if (Sym) {
      std::string info;
      (Rule.isSanRule() ? (info = "Removing taint in post call") :
			  (info = "Adding taint in post call"));
      DEBUG_PRINT(info);
      if (Rule.isSanRule())
	State = State->removeTaint(Sym);
      else
	State = State->addTaint(Sym);
    }
    else
      DEBUG_PRINT("Sym null");
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

  DEBUG_PRINT("Checking taint pre call");
  StringRef Name = getCallName(CE, C);
  if (Name.empty())
    return false;

  if (checkPHPSinks(CE, Name, C))
    return true;

  return false;
}

SymbolRef PHPTaintChecker::getPointedToSymbol(CheckerContext &C,
                                                  const Expr* Arg) {

  DEBUG_PRINT("Unknown or undefined address");
  ProgramStateRef State = C.getState();
  SVal AddrVal = State->getSVal(Arg->IgnoreParens(), C.getLocationContext());
  if (AddrVal.isUnknownOrUndef())
    return nullptr;

  DEBUG_PRINT("Address not an lvalue");
  Optional<Loc> AddrLoc = AddrVal.getAs<Loc>();
  if (!AddrLoc)
    return nullptr;

  DEBUG_PRINT("Obtaining symbolref of address");
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

ProgramStateRef PHPTaintChecker::prePHPTaintSources(const CallExpr *CE,
                                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  StringRef Name = getCallName(CE, C);
  if (Name.empty())
    return State;

  unsigned taintArgNum = llvm::StringSwitch<unsigned>(Name)
      .Case("zend_hash_find", 3)
      .Case("zend_hash_quick_find", 4)
      .Case("zend_hash_index_find", 2)
      .Case("_ldap_hash_fetch", 2)
      .Case("php_stream_context_get_option", 3)
      .Default(InvalidArgIndex);

  if (taintArgNum == InvalidArgIndex)
    return State;

  /// Sanity check
  assert((taintArgNum < CE->getNumArgs() || taintArgNum == ReturnValueIndex) &&
         "Taint generation rule invalid");

  DEBUG_PRINT("Add taint arg info to checker state");

  return State->add<TaintArgsOnPostVisit>(taintArgNum);
}

ProgramStateRef PHPTaintChecker::postRetTaint(const CallExpr *CE,
                                                  CheckerContext &C) const {
  DEBUG_PRINT("Adding taint on return value post call");
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

void PHPTaintChecker::generateReport(const Expr *E, const char Msg[],
                                     CheckerContext &C) const {
  assert(E);

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
  }
}

bool PHPTaintChecker::checkPHPSinks(const CallExpr *CE, StringRef Name,
                                    CheckerContext &C) const {
  // TODO: Populate this with PHP sink functions if any

//  unsigned ArgNum = llvm::StringSwitch<unsigned>(Name)
//    .Case("ZF_STRVAL", 0)
//    .Case("ZF_STRVAL_P", 0)
//    .Case("ZF_STRVAL_PP", 0)
//    .Case("ZF_ARRVAL", 0)
//    .Case("ZF_ARRVAL_P", 0)
//    .Case("ZF_ARRVAL_PP", 0)
//    .Default(UINT_MAX);
//
//  if (ArgNum == UINT_MAX || CE->getNumArgs() < (ArgNum + 1))
//    return false;
//
//  if (generateReportIfTainted(CE->getArg(ArgNum),
//                              MsgZendTaint, C))
//    return true;

  return false;
}
