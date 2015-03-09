/*
 * UseDefChecker.cpp
 *
 *  Created on: Jan 12, 2015
 *      Author: Bhargava Shastry
 *
//===----------------------------------------------------------------------===//
//
// This files defines UseDefChecker, a custom checker that looks for
// CXX field initialization and use patterns that tend to be buggy.
//
//===----------------------------------------------------------------------===//
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/Mangle.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/DenseSet.h"

using namespace clang;
using namespace ento;

typedef llvm::DenseSet<const NamedDecl *> InitializedFieldsSetTy;

namespace {

class UseDefChecker : public Checker< check::ASTDecl<CXXConstructorDecl>,
				      check::PreStmt<UnaryOperator>,
				      check::PreStmt<BinaryOperator>,
				      check::Location,
				      check::EndFunction> {
  typedef StackFrameContext const SFC_const_t;
  mutable std::unique_ptr<BugType> BT;
  mutable SFC_const_t *pSFC = nullptr;
  enum SetKind { Ctor, Context };

  /* Definitions of cxx member fields of this* object are recorded
   * in two sets
   * 	1. ctorInitializedFieldsSet: Fields initialized in ctor
   * 		initializer list or in-class
   * 	2. contextInitializedFieldsSet: Fields initialized in
   * 		this->method() body
   */
  mutable InitializedFieldsSetTy ctorTaintSet;
  mutable InitializedFieldsSetTy contextTaintSet;

  // Encode Bug info
  mutable BugReport::ExtraTextList EncodedBugInfo;
  typedef BugReport::ExtraTextList::const_iterator EBIIteratorTy;

  mutable bool CtorVisited = false;

public:
  void checkASTDecl(const CXXConstructorDecl *CtorDecl,
                    AnalysisManager &Mgr, BugReporter &BR) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
  void checkEndFunction(CheckerContext &C) const;

private:
  void addNDToTaintSet(SetKind Set, const NamedDecl *ND) const;
  bool findElementInSet(const NamedDecl *ND, SetKind S) const;
  bool isElementUndefined(const NamedDecl *ND) const;

  void reportBug(StringRef Message, SourceRange SR, CheckerContext &C) const;
  bool trackMembersInAssign(const BinaryOperator *BO, SetKind S, ASTContext &ASTC) const;
  void clearContextIfRequired(CheckerContext &C) const;
  void encodeBugInfoAndReportBug(const MemberExpr *ME, CheckerContext &C) const;
  void dumpCallsOnStack(CheckerContext &C) const;
  bool terminatePathIfCtorNotVisited(CheckerContext &C) const;

  // Static utility functions
  static bool isCXXThisExpr(const Expr *E, ASTContext &ASTC);
  static const StackFrameContext* getTopStackFrame(CheckerContext &C);
  static bool isCtorOnStack(CheckerContext &C);
  static bool isLCCtorDecl(const LocationContext *LC);
  static std::string getADCQualifiedNameAsStringRef(const LocationContext *LC);
  static std::string getMangledNameAsString(const NamedDecl *ND, ASTContext &ASTC);
};
} // end of anonymous namespace

/* We visit endfunction to make sure we update CtorVisited if necessary.
 * Note that even an empty ctor body, like so:
 * 	foo() {}
 * is going to end up here and update CtorVisited to true.
 */
void UseDefChecker::checkEndFunction(CheckerContext &C) const {
  if(isCtorOnStack(C) && !CtorVisited)
      CtorVisited = true;
}

bool UseDefChecker::terminatePathIfCtorNotVisited(CheckerContext &C) const {
  /* If Ctor is not on the stack and we haven't visited Ctor at least
   * once, terminate path. Update CtorVisited flag if it is false and
   * we have Ctor on stack.
   */
  if(!isCtorOnStack(C) && !CtorVisited){
      ExplodedNode *N = C.generateSink();
      if(!N)
	llvm::errs() << "Generate sink led to an empty node\n";
      return true;
  }
  else if(isCtorOnStack(C) && !CtorVisited)
    CtorVisited = true;

  return false;
}

void UseDefChecker::encodeBugInfoAndReportBug(const MemberExpr *ME,
                                              CheckerContext &C) const {

  /* Get the FQ field name */
  const NamedDecl *ND = dyn_cast<NamedDecl>(ME->getMemberDecl());
  const std::string FieldName = ND->getQualifiedNameAsString();

  // Report bug
  /* This is used by reportBug to sneak in name of the undefined field
   * Note: We don't mangle Fieldname because it's not a VarDecl and non
   * VarDecls cannot be mangled.
   */

  /* Clear DS before populating to avoid rewrites in case of multiple
   * undefs being detected.
   */
  EncodedBugInfo.clear();

  EncodedBugInfo.push_back(FieldName);
  // Call stack is written to EncodedBugInfo
  dumpCallsOnStack(C);

  StringRef Message = "Potentially uninitialized object field";
  reportBug(Message, ME->getSourceRange(), C);

  return;
}

void UseDefChecker::clearContextIfRequired(CheckerContext &C) const {

  /* We store the top most stack frame context (sfc) in the checker state.
   * Context is equal to the sfc at the tail of the stack i.e., the outer
   * most caller. Definitions in the context are preserved till
   * the tail sfc changes. This prunes false positives
   * in cases where the call leading to a member field definition
   * preceeds use of that field.
   *
   * Note: This does not affect false positives arising out of
   * path visitation logic of the PS engine in clang SA. What are
   * pruned out are false positives that are flagged when both use
   * and def are triggered in the same procedure but might actually happen
   * interprocedurally. In the example below, def happens in a different
   * procedure than where def is actually triggered. Earlier, we weren't
   * taking care of this. Now we do.
   * e.g.
   *
   * foo::def() { x = 0; }
   * foo::use() { def(); if(!x) do_something() }
   */

   const StackFrameContext *cSFC = getTopStackFrame(C);
   if(pSFC != cSFC){
       pSFC = cSFC;
       contextTaintSet.clear();
   }

  return;
}

const StackFrameContext* UseDefChecker::getTopStackFrame(CheckerContext &C) {

  /* getStackFrame returns the current stack frame context i.e.,
   * the stack frame context of the procedure we are in at this
   * point.
   */
  const StackFrameContext *SFC = C.getStackFrame();
  assert(SFC && "Checker context getStackFrame returned null!");

  // If already in top frame simply return current stack frame
  if(C.inTopFrame())
    return SFC;

  /* Nested retrieval of top most stack frame. The logic
   * for this has been borrowed from dumpStack() impl.
   * There is a little twist here. We assume that Stack
   * frame contexts are always layered one on top of another.
   * There are three kinds of contexts: (1) block (2) scope
   * and (3) stackframe. We make an assertion if there is a
   * non-stackframe kind Parent of a stackframe kind Child.
   * Hope the expectation here is aligned with reality.
   */
  for (const LocationContext *LCtx = C.getLocationContext();
      LCtx; LCtx = LCtx->getParent()) {
      if(LCtx->getKind() == LocationContext::ContextKind::StackFrame)
         SFC = cast<StackFrameContext>(LCtx);
      /* It doesn't make sense to continue if parent is
       * not a stack frame. I imagine stack frames stacked
       * together and not interspersed between other frame types
       * like Scope or Block.
       */
      else
	  llvm_unreachable("This can't be! We are not in the top most"
	      " stack frame but parent of location context is not a StackFrame kind.");
  }

  return SFC;
}

// This can be a private static function
bool UseDefChecker::isCXXThisExpr(const Expr *E,
                                   ASTContext &ASTC) {
  /* Remove clang inserted implicit casts before
   * continuing. Otherwise, statements like this
   *     int x = this->member
   * bail out because casting (this->member) to
   * MemberExpr before removing casts returns
   * null. This shouldn't affect LHS with no
   * implicit casts
   */
  const MemberExpr *ME =
      dyn_cast<MemberExpr>(E->IgnoreImpCasts());

  if(!ME)
    return false;

  const Expr *BaseExpr = ME->getBase();
  if(!BaseExpr)
    return false;

  const CXXThisExpr *CTE = dyn_cast<CXXThisExpr>(BaseExpr);
  if(!CTE)
    return false;

  return true;
}

void UseDefChecker::reportBug(StringRef Message,
                               SourceRange SR,
                               CheckerContext &C) const {
  ExplodedNode *N = C.generateSink();
  const char *name = "Undefined CXX object checker";
  const char *desc = "Flags potential uses of undefined CXX object fields";

  if (!N)
    return;

  if (!BT)
    BT.reset(new BuiltinBug(this, name, desc));

  BugReport *R = new BugReport(*BT, Message, N);

  /* We use BugReport's addExtraText(std::string S) to
   * pass meta data to bug report. We can possibly hijack
   * this to encode <Undef Field, Call Stack>
   * Note that only HTML report consumers are able to deal
   * with this meta data. Plist probably won't do anything
   * about it.
   */

  /* Iterate through EncodedBugInfo adding Extra text with
   * each iteration.
   */
  for (EBIIteratorTy i = EncodedBugInfo.begin(),
      e = EncodedBugInfo.end(); i != e; ++i) {
      R->addExtraText(*i);
   }

  R->addRange(SR);
  C.emitReport(R);

  return;
}

void UseDefChecker::checkPreStmt(const UnaryOperator *UO,
                                  CheckerContext &C) const {

  /* Return if not a logical NOT operator */
  if(UO->getOpcode() != UO_LNot)
    return;

  /* Ignore implicit casts */
  Expr *E = UO->getSubExpr()->IgnoreImpCasts();
  ASTContext &ASTC = C.getASTContext();

  if(!isCXXThisExpr(E, ASTC))
    return;

  /* This is serious: Clang SA PS path hack should force visit Ctor before
   * visiting anything else.
   */
  if(terminatePathIfCtorNotVisited(C))
    return;

  clearContextIfRequired(C);


  /* Bail if possible
   * We check if
   * 	1. Expr is a this expr AND
   * 	2. If (1) is true
   * 	   a. If there is no body for ctor
   * 	   of class to which member expr belongs
   */

  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  assert(ME && "UDC: ME can't be null here");

  const NamedDecl *ND = dyn_cast<NamedDecl>(ME->getMemberDecl());
  assert(ND && "UDC: ND can't be null here");

  if(isElementUndefined(ND))
    encodeBugInfoAndReportBug(ME, C);

  return;
}

void UseDefChecker::checkPreStmt(const BinaryOperator *BO,
                                  CheckerContext &C) const {

  /* Return if binop is not eq. assignment */
  if((BO->getOpcode() != BO_Assign))
    return;

  ASTContext &ASTC = C.getASTContext();

  if(!isCXXThisExpr(BO->getRHS(), ASTC) && !isCXXThisExpr(BO->getLHS(), ASTC))
    return;

  if(terminatePathIfCtorNotVisited(C))
    return;

  clearContextIfRequired(C);

  bool isDef = true;
  if(isCtorOnStack(C))
    isDef = trackMembersInAssign(BO, Ctor, ASTC);
  else
    isDef = trackMembersInAssign(BO, Context, ASTC);

  // Report bug
  if(!isDef){
      const Expr *rhs = BO->getRHS();
      const MemberExpr *MeRHS = dyn_cast<MemberExpr>(rhs->IgnoreImpCasts());
      encodeBugInfoAndReportBug(MeRHS, C);
  }

  return;
}

/* Utility function to track uses and defs in assignment
 * statements.
 * Returns false if RHS is not in defs set. When this
 * happens, onus is on caller to report bug
 */
bool UseDefChecker::trackMembersInAssign(const BinaryOperator *BO,
                                          SetKind S,
                                          ASTContext &ASTC) const {
  /* Check if LHS/RHS is a member expression */
  const Expr *lhs = BO->getLHS();
  const Expr *rhs = BO->getRHS();

  const MemberExpr *MeLHS = dyn_cast<MemberExpr>(lhs->IgnoreImpCasts());
  const MemberExpr *MeRHS = dyn_cast<MemberExpr>(rhs->IgnoreImpCasts());

  /* Return if neither lhs nor rhs is a member expression */
  if(!MeLHS && !MeRHS)
    return true;

  /* If we are here, it means that a member expression definition/use is taking place.
   * Note: ATM, we only care about fields of this* object i.e., fields belonging to class
   * object in whose method we are in.
   */
  // FIXME: Should we care about non this* objects. Use cases?

  CXXThisExpr *CTERHS = nullptr, *CTELHS = nullptr;

  // Filter out non this* fields
  if(MeLHS){
      Expr *BaseLHS = MeLHS->getBase();
      CTELHS = dyn_cast<CXXThisExpr>(BaseLHS);
  }
  if(MeRHS){
      Expr *BaseRHS = MeRHS->getBase();
      CTERHS = dyn_cast<CXXThisExpr>(BaseRHS);
  }

  // Return if neither lhs nor rhs is a this->member_expr
  if(!CTELHS && !CTERHS)
    return true;

  /* If we are here, we can be sure that the member field
   * being defined/used belongs to this* object
   */

  /* Check use first because this->rhs may be uninitialized
   * and we would want to report the bug and exit before
   * anything else
   */
  if(CTERHS){
      // Get FQN
      const NamedDecl *NDR = dyn_cast<NamedDecl>(MeRHS->getMemberDecl());
      if(isElementUndefined(NDR))
	  return false;
  }

  // Add lhs to set if it is a this* member
  if(CTELHS){
      const NamedDecl *NDL = dyn_cast<NamedDecl>(MeLHS->getMemberDecl());
      addNDToTaintSet(S, NDL);
  }
  return true;
}

void UseDefChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {

}

/* Visit AST nodes for method definitions : CXXMethodDecl is a misnomer
 * This visitor is not path sensitive
 */
void UseDefChecker::checkASTDecl(const CXXConstructorDecl *CtorDecl,
                                  AnalysisManager &Mgr,
                                  BugReporter &BR) const {

  /* We don't need to check if Ctor has a body because Clang SA
   * has been patched to not do PS analysis if Ctor body is missing.
   */
  for(auto *I : CtorDecl->inits()){
      CXXCtorInitializer *CtorInitializer = I;
      /* FIXME: Choose the right variant(s) of
       * is*MemberInitializer call
       */
      if(!CtorInitializer->isMemberInitializer())
	continue;

      /* Turns out isMemberInitializer() also returns
       * member fields initialized in class decl
       */

      // Update state map
      const FieldDecl *FD = CtorInitializer->getMember();

      const NamedDecl *ND = dyn_cast<NamedDecl>(FD);
      assert(ND && "UDC: ND can't be null here");

      addNDToTaintSet(Ctor, ND);
  }

  return;
}

/* Utility function for inserting fields into a given set */
void UseDefChecker::addNDToTaintSet(SetKind Set,
				const NamedDecl *ND) const {
      Set ? contextTaintSet.insert(ND) : ctorTaintSet.insert(ND);
}

/* Utility function for finding a field in a given set */
bool UseDefChecker::findElementInSet(const NamedDecl *ND,
                           SetKind S) const {
  InitializedFieldsSetTy Set = (S ? contextTaintSet : ctorTaintSet);
  return (Set.find(ND) != Set.end());
}

bool UseDefChecker::isElementUndefined(const NamedDecl *ND) const {
  /* If element is in neither Ctor not context
   * sets, it's undefined
   */
  if(!(findElementInSet(ND, Ctor)) &&
      !(findElementInSet(ND, Context)))
      return true;

  return false;
}

/* This utility function must be called from reportBug before
 * populating the ExtraData portion of the bug report.
 * dumpCallsOnStack pushes the call stack as a list of strings
 * to EncodedBugInfo. EncodedBugInfo is copied on to the bug
 * report's ExtraText field.
 *
 * Finally, the HTML Diagnostics client picks up ExtraText and
 * populates the HTML report with the call stack.
 */

void UseDefChecker::dumpCallsOnStack(CheckerContext &C) const {

  const LocationContext *LC = C.getLocationContext();

  if(C.inTopFrame()){
      EncodedBugInfo.push_back(getADCQualifiedNameAsStringRef(LC));
      return;
  }

  for (const LocationContext *LCtx = C.getLocationContext();
      LCtx; LCtx = LCtx->getParent()) {
      if(LCtx->getKind() == LocationContext::ContextKind::StackFrame)
	EncodedBugInfo.push_back(getADCQualifiedNameAsStringRef(LCtx));
      /* It doesn't make sense to continue if parent is
       * not a stack frame. I imagine stack frames stacked
       * together and not interspersed between other frame types
       * like Scope or Block.
       */
      else
	  llvm_unreachable("dumpCallsOnStack says this is not a stack frame!");
  }

  return;
}

std::string UseDefChecker::getADCQualifiedNameAsStringRef(const LocationContext *LC) {

  if(LC->getKind() != LocationContext::ContextKind::StackFrame)
    llvm_unreachable("getADC says we are not in a stack frame!");

  const AnalysisDeclContext *ADC = LC->getAnalysisDeclContext();
  assert(ADC && "getAnalysisDecl returned null while dumping"
         " calls on stack");

  // This gives us the function declaration being visited
  const Decl *D = ADC->getDecl();
  assert(D && "ADC getDecl returned null while dumping"
         " calls on stack");

  const NamedDecl *ND = dyn_cast<NamedDecl>(D);
  assert(ND && "Named declaration null while dumping"
         " calls on stack");

  return getMangledNameAsString(ND, ADC->getASTContext());
}

std::string UseDefChecker::getMangledNameAsString(const NamedDecl *ND,
                                                  ASTContext &ASTC) {
  // Create Mangle context
  MangleContext *MC = ASTC.createMangleContext();

  // We need raw string stream so we can return std::string
  std::string MangledName;
  llvm::raw_string_ostream raw_stream(MangledName);

  if(!MC->shouldMangleDeclName(ND))
    return ND->getQualifiedNameAsString();

  /* Assertion deep within mangleName */
  if(!isa<CXXConstructorDecl>(ND) && !isa<CXXDestructorDecl>(ND)){
    MC->mangleName(ND, raw_stream);
    return raw_stream.str();
  }

  return ND->getQualifiedNameAsString();
}

bool UseDefChecker::isLCCtorDecl(const LocationContext *LC) {

  if(LC->getKind() != LocationContext::ContextKind::StackFrame)
    llvm_unreachable("getADC says we are not in a stack frame!");

  const AnalysisDeclContext *ADC = LC->getAnalysisDeclContext();
  assert(ADC && "getAnalysisDecl returned null while dumping"
         " calls on stack");

  // This gives us the function declaration being visited
  const Decl *D = ADC->getDecl();
  assert(D && "ADC getDecl returned null while dumping"
         " calls on stack");

  const CXXConstructorDecl *CDecl = dyn_cast<CXXConstructorDecl>(D);
  if(!CDecl)
    return false;

  return true;
}

bool UseDefChecker::isCtorOnStack(CheckerContext &C) {

  const LocationContext *LC = C.getLocationContext();

  if(C.inTopFrame())
    return isLCCtorDecl(LC);

  for (const LocationContext *LCtx = C.getLocationContext();
      LCtx; LCtx = LCtx->getParent()) {
      if(LCtx->getKind() == LocationContext::ContextKind::StackFrame){
	if(isLCCtorDecl(LCtx))
	  return true;
      }
      /* It doesn't make sense to continue if parent is
       * not a stack frame. I imagine stack frames stacked
       * together and not interspersed between other frame types
       * like Scope or Block.
       */
      else
	  llvm_unreachable("dumpCallsOnStack says this is not a stack frame!");
  }

  return false;
}

// Register plugin!
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<UseDefChecker>("alpha.security.UseDefChecker", "CXX UseDef Checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
