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


#define DEBUG_PRINTS		0
#define DEBUG_PRINTS_VERBOSE	0

/* The heuristics we employ in pruning false positives are the following:
 * 	a. Don't flag undefined uses in direct calls (stack depth = 1) to virtual
 * 	functions.
 * 		e.g. if PS engine is exploring root->VirtualFunc()
 *
 * 	b. Don't flag undefined uses in direct calls (stack depth = 1) to a private
 * 	functions.
 *	 	e.g. if PS engine is exploring root->PrivateFunc()
 *
 * (b) is a more precise heuristic. In fact, afaik it's a fact. Private functions
 * may only be called within the translation unit
 *
 * Important: We terminate path exploration in cases (a) and (b) by registering for
 * the PreCall visitor. Paths like root->VirtualFunc and root->PrivateFunc are not
 * explored at all.
 */
#define EMPLOY_HEURISTICS
#define ENCODE_BUG_INFO
#define MANGLE_NAMES

using namespace clang;
using namespace ento;

/* We track usedefs by fully qualified field names, like so
 * foo::m_x or mynamespace::foo::m_x
 */
typedef std::set<std::string> InitializedFieldsSetTy;

namespace {
#ifdef EMPLOY_HEURISTICS
class UseDefChecker : public Checker< check::ASTDecl<CXXConstructorDecl>,
					check::PreStmt<BinaryOperator>,
					check::PreStmt<UnaryOperator>> {
#else
class UseDefChecker : public Checker< check::ASTDecl<CXXConstructorDecl>,
					check::PreStmt<BinaryOperator>,
					check::PreStmt<UnaryOperator>> {
#endif

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
   * ATM, we basically insert fieldnames (strings) of initialized
   * fields in these sets. To check state of a field at the time
   * of use, we simply look for the field in these sets. If the
   * field is in neither set, we flag a warning (Bug Report)
   */
  mutable InitializedFieldsSetTy ctorInitializedFieldsSet;
  mutable InitializedFieldsSetTy contextInitializedFieldsSet;

  /* If the constructor decl being visited has no body in
   * the translation unit, we insert the constructor decl's
   * fully qualified name into this set
   *
   * Later, when visiting statements, if the base object of
   * member expression is in this set, we return from the
   * prestmt visitor. In fact, we can even generate a sink
   * to stop further path exploration. Note that the type
   * of this set is the same as the sets where defs are
   * tracked
   */
  mutable InitializedFieldsSetTy ctorHasNoBodyInTUSet;

#ifdef ENCODE_BUG_INFO
  mutable BugReport::ExtraTextList EncodedBugInfo;
  typedef BugReport::ExtraTextList::const_iterator EBIIteratorTy;
#endif

#ifdef EMPLOY_HEURISTICS
  mutable bool CtorVisited = false;
#endif

  /* Have aggressively registered for checkers here but
   * won't be using non AST visitors for the time being
   *
   * The basic idea is the following:
   * 1. AST* visitors allow us to
   * 	a. Do stuff with CXX records and fields there-in
   * 	b. Do stuff with CXX functions
   * 2. Therefore, using AST* visitors, we can
   * 	a. Create an internal map of
   * 		field members <-> initialization state
   * 	E.g., x <-> false, y <-> true
   * 	where x, and y are fields in a CXX record
   * 	and, the boolean values indicate if they are initialized
   * 	or not.
   *    These are tiny steps towards building a heuristics driven
   *    checker for use of uninitialized variables.
   * 3. We also register for EOF visitor, so we can spit out warnings
   * 	at the end of analysis. Since we are dealing with AST*
   * 	visitors, we don't need to navigate the exploded graph.
   * 	At the moment, we are only printing contents of the internal
   * 	map. Warnings are going to replace the debug prints eventually.
   */


public:
  void checkASTDecl(const CXXConstructorDecl *CtorDecl,
                    AnalysisManager &Mgr, BugReporter &BR) const;
  void checkPreStmt(const BinaryOperator *BO,
                    CheckerContext &C) const;
  void checkPreStmt(const UnaryOperator *UO,
                      CheckerContext &C) const;
#ifdef EMPLOY_HEURISTICS
  bool terminatePathIfCtorNotVisited(CheckerContext &C) const;
#endif
private:
  void printSetInternal(InitializedFieldsSetTy *Set) const;

  void updateSetInternal(InitializedFieldsSetTy *Set,
                             const std::string FName) const;
  bool findElementInSet(const std::string FName,
                        SetKind S) const;
  bool isElementUndefined(const std::string Fname) const;

  void reportBug(StringRef Message, SourceRange SR,
                                 CheckerContext &C) const;
  bool trackMembersInAssign(const BinaryOperator *BO,
                            SetKind S, ASTContext &ASTC) const;
  bool skipExpr(const Expr *E, ASTContext &ASTC) const;
  void clearContextIfRequired(CheckerContext &C) const;
  void encodeBugInfoAndReportBug(const MemberExpr *ME,
					CheckerContext &C) const;
  // Static utility functions
  static bool isCXXThisExpr(const Expr *E, ASTContext &ASTC);

  static void prettyPrintE(StringRef S, const Expr *E,
		     ASTContext &ASTC);
  static void prettyPrintD(StringRef S, const Decl *D);
  static const StackFrameContext* getTopStackFrame(CheckerContext &C);
  static bool isCtorOnStack(CheckerContext &C);
  static bool isLCCtorDecl(const LocationContext *LC);

#ifdef EMPLOY_HEURISTICS
  static bool isMethodVirtual(CheckerContext &C);
  static bool isASPrivate(CheckerContext &C);
  static unsigned getDepthOfCurrentStack(CheckerContext &C);
#endif

#ifdef ENCODE_BUG_INFO
  // FIXME: Move dumpCallsOnStack to list of non-static functions
  void dumpCallsOnStack(CheckerContext &C) const;
  static std::string getADCQualifiedNameAsStringRef(const LocationContext *LC);
#endif

#ifdef MANGLE_NAMES
  static std::string getMangledNameAsString(const NamedDecl *ND, ASTContext &ASTC);
#endif

};
} // end of anonymous namespace

#ifdef EMPLOY_HEURISTICS
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
#endif

void UseDefChecker::checkPreStmt(const UnaryOperator *UO,
                                  CheckerContext &C) const {

#if DEBUG_PRINTS_VERBOSE
  llvm::errs() << "Visiting UnaryOp\n";
#endif

  /* Return if not a logical NOT operator */
  if(UO->getOpcode() != UO_LNot)
    return;

#ifdef EMPLOY_HEURISTICS
  /* Terminate path if Ctor has not been visited. This is a conservative
   * approach to deal with potential false positives due to Ctor call
   * stacks not being taken into account.
   * Consider:
   * class foo{
   * public:
   *    bool m_b;
   * 	foo() { init(); }
   * 	void bar() { if(!m_b) print "hello"; }
   * 	void init() { m_b = true; }
   * If we don't terminate paths when Ctor has not been visited, our checker
   * is going to flag if(!m_b) as a use before def warning.
   * The downside to this is that we may miss true warnings.
   */
  if(terminatePathIfCtorNotVisited(C))
    return;
#endif

  /* Bugfix: We should be clearing context Set if we are not in the procedure
   * we were in the last time we visited PreStmt<BinaryOp>.
   * Otherwise, old entries from BinaryOp visitor will
   * persist and lead to false negatives
   */
  clearContextIfRequired(C);

  ASTContext &ASTC = C.getASTContext();

  /* Ignore implicit casts */
  Expr *E = UO->getSubExpr()->IgnoreImpCasts();

  /* Bail if possible
   * We check if
   * 	1. Expr is a this expr AND
   * 	2. If (1) is true
   * 	   a. If there is no body for ctor
   * 	   of class to which member expr belongs
   */
#if DEBUG_PRINTS_VERBOSE
  E->dumpPretty(ASTC);
  llvm::errs() << "\n";
#endif
  if(skipExpr(E, ASTC))
    return;

  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  const NamedDecl *ND = dyn_cast<NamedDecl>(ME->getMemberDecl());
  const std::string FieldName = ND->getQualifiedNameAsString();

  /* Find Fieldname in ctor and context sets and flag
   * a warning only if we know for sure that ctor does not
   * have a body in this translation unit
   */
#if DEBUG_PRINTS
  llvm::errs() << "Element in unary lnot is: " << FieldName << "\n";
#endif
  if(isElementUndefined(FieldName))
    encodeBugInfoAndReportBug(ME, C);

  return;
}

void UseDefChecker::encodeBugInfoAndReportBug(const MemberExpr *ME,
                                              CheckerContext &C) const {

  /* Get the FQ field name */
  const NamedDecl *ND = dyn_cast<NamedDecl>(ME->getMemberDecl());
  const std::string FieldName = ND->getQualifiedNameAsString();

  // Report bug
#if DEBUG_PRINTS
  llvm::errs() << "Report bug here\n";
#endif

#ifdef ENCODE_BUG_INFO
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
#endif // ENCODE_BUG_INFO

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
       contextInitializedFieldsSet.clear();
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
#if DEBUG_PRINTS_VERBOSE
  prettyPrintE("Is this expr", E, ASTC);
  prettyPrintE("Is this expr (ignore imp casts)",
               E->IgnoreImpCasts(), ASTC);

  llvm::errs() << "Is a member expr: " <<
      (isa<MemberExpr>(E->IgnoreImpCasts()) ? "Yes" : "No") << "\n";
#endif
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

/* This must be called post isCXXThisExpr() defined
 * above.
 */
bool UseDefChecker::skipExpr(const Expr *E,
                              ASTContext &ASTC) const {

  /* Additional check although isCXXThisExpr() is
   * called once before in checkPreStmt<BO>
   * This is because either LHS or RHS may still
   * be a non this expr in which case we can bail
   * early
   */
  if(!isCXXThisExpr(E, ASTC))
    return true;

  /* Check if base of Expr is in ctorHasNoBodyInTU Set
   * bailing if true
   * Remove clang inserted implicit casts before
   * continuing.
   */
  const MemberExpr *ME =
      dyn_cast<MemberExpr>(E->IgnoreImpCasts());

  // Get Fully Qualified Name
  const NamedDecl *ND = dyn_cast<NamedDecl>(ME->getMemberDecl());
  std::string FQFieldName = ND->getQualifiedNameAsString();

  /* string magic, shitty magic at that
   * What we are basically doing here is:
   * "ns::foo::field" (FQFieldName), "field" (FieldName)
   * <------>  NSQCtorName
   * "ns::foo" is what we have inserted in the AST* visitor
   * for Ctors that don't have a body
   */
  std::string FieldName = ND->getNameAsString();
  /* We should be careful to filter out the field name and the
   * two colons "::" before field name
   */
  std::string NSQCtorName =
      FQFieldName.substr(0,(FQFieldName.length() - FieldName.length() - 2));

//  std::string BaseName = FQFieldName.substr(0,FQFieldName.find(FieldName));
//  std::string CtorName = BaseName.substr(0, BaseName.length() -2);
  bool canSkip =
      (ctorHasNoBodyInTUSet.find(NSQCtorName) != ctorHasNoBodyInTUSet.end());

#if DEBUG_PRINTS
  llvm::errs() << "Ctor Name from Expr is: " << NSQCtorName << "\n";
  llvm::errs() << "Match "
     << (canSkip ? "found. Skipping expression\n" : "not found. Continuing\n");
#endif

  return canSkip;
}

#ifdef EMPLOY_HEURISTICS
bool UseDefChecker::isASPrivate(CheckerContext &C) {

  const LocationContext *LC = C.getLocationContext();
  const AnalysisDeclContext *ADC = LC->getAnalysisDeclContext();

  // This gives us the function declaration being visited
  const Decl *D = ADC->getDecl();
  assert(D && "getDecl in isASPrivate returned null");

  /* FIXME: Is the assumption that only CXXMethodDecl
   * can have access specifiers valid?
   */
  const CXXMethodDecl *CMD = dyn_cast<CXXMethodDecl>(D);

  if(!CMD)
    return false;

  // We now obtain the access specifier enum for this decl
  clang::AccessSpecifier AS = D->getAccess();
  if(AS != clang::AccessSpecifier::AS_private)
    return false;

  return true;
}

bool UseDefChecker::isMethodVirtual(CheckerContext &C) {
  const LocationContext *LC = C.getLocationContext();
  const AnalysisDeclContext *ADC = LC->getAnalysisDeclContext();

  // This gives us the function declaration being visited
  const Decl *D = ADC->getDecl();
  assert(D && "getDecl in isMethodVirtual returned null");

  /* Only CXXMethodDecls i.e., member functions (per c++ standard)
   * can be virtual
   */
  const CXXMethodDecl *CMD = dyn_cast<CXXMethodDecl>(D);

  if(!CMD)
    return false;

  if(!CMD->isVirtual())
    return false;

  return true;
}
#endif

void UseDefChecker::checkPreStmt(const BinaryOperator *BO,
                                  CheckerContext &C) const {

#if DEBUG_PRINTS_VERBOSE
  llvm::errs() << "Visiting BinaryOp\n";
#endif

  /* Return if binop is not eq. assignment */
  if((BO->getOpcode() != BO_Assign))
    return;

#ifdef EMPLOY_HEURISTICS
  /* Terminate path if Ctor has not been visited. This is a conservative
   * approach to deal with potential false positives due to Ctor call
   * stacks not being taken into account.
   * Consider:
   * class foo{
   * public:
   *    bool m_b;
   * 	foo() { init(); }
   * 	void bar() { if(!m_b) print "hello"; }
   * 	void init() { m_b = true; }
   * If we don't terminate paths when Ctor has not been visited, our checker
   * is going to flag if(!m_b) as a use before def warning.
   * The downside to this is that we may miss true warnings.
   */
  if(terminatePathIfCtorNotVisited(C))
    return;
#endif

  ASTContext &ASTC = C.getASTContext();

  /* We can return if neither LHS nor RHS is a CXXThisExpr
   * This is because we are only tracking usedef for
   * this->member fields
   * */
   if(!isCXXThisExpr(BO->getRHS(), ASTC)
       && !isCXXThisExpr(BO->getLHS(), ASTC))
     return;

   /* We can skip BO if both LHS and RHS are member expressions
    * of object that does not have a body in TU
    * This is done to prune false positives
    */
   if(skipExpr(BO->getLHS(), ASTC) && skipExpr(BO->getRHS(), ASTC))
     return;

  /* AnalysisDeclarationContext tells us which function
   * declaration (definition) is being visited. We maintain
   * two sets of initdata:
   * 	1. Ctor [Inter-procedural]
   * 	2. Tail of present stack frame context i.e., the outermost
   * 	caller.
   */

  /* Check if stack frame context has changed. If so,
   * update pSFC and reset context.
   */
   clearContextIfRequired(C);

  /* If we are here, we are analyzing an assignment
   * statement in a function definition.
   * FIXME: We shouldn't be hard-coding Context as second argument.
   * Rather, it should be based on checking if we are (or came here)
   * via the object's ctor.
   */
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

  const MemberExpr *MeLHS =
      dyn_cast<MemberExpr>(lhs->IgnoreImpCasts());
  /* Magic to get to RHS member expr
   * Turns out rhs of ``equal to" is an expression
   * of an ImplicitCastExpr type because there is
   * an implicit type conversion involved
   * Took me a full evening's debugging to figure
   * this out.
   *
   * Tip: Use Expr's IgnoreImpCasts to simplify this:
   * bool isImplicitCast = isa<ImplicitCastExpr>(rhs);
   * const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(rhs);
   * const MemberExpr *MeRHS = isImplicitCast ?
   *			    cast<MemberExpr>(ICE->getSubExpr()) :
   *			    nullptr;
   */
  const MemberExpr *MeRHS = dyn_cast<MemberExpr>(rhs->IgnoreImpCasts());
#if DEBUG_PRINTS_VERBOSE
  prettyPrintE("RHS ignore imp casts", rhs->IgnoreImpCasts(), ASTC);
  prettyPrintE("RHS ignore parens", rhs->IgnoreParens(), ASTC);
  prettyPrintE("RHS ignore parencasts", rhs->IgnoreParenCasts(), ASTC);
  if(MeLHS)
      prettyPrintE("LHS member exp is", MeLHS, ASTC);

  if(MeRHS)
      prettyPrintE("RHS member exp is", MeRHS, ASTC);
#endif

  /* Return if neither lhs nor rhs is a member expression */
  if(!MeLHS && !MeRHS)
    return true;

#if DEBUG_PRINTS_VERBOSE
  llvm::errs() << "Stage 1\n";
#endif

  /* If we are here, it means that a member expression
   * definition/use is taking place.
   * Note:
   * ATM, we only care about fields of this* object i.e.,
   * fields belonging to class object in whose method
   * we are in
   */
  // FIXME: Should we care about non this* objects. Use cases?

  CXXThisExpr *CTERHS = nullptr, *CTELHS = nullptr;

  // Filter out non this* fields
  if(MeLHS){
      Expr *BaseLHS = MeLHS->getBase();
      CTELHS = dyn_cast<CXXThisExpr>(BaseLHS);
#if DEBUG_PRINTS
      if(CTELHS)
	  prettyPrintE("Lhs this expr is", CTELHS, ASTC);
#endif
  }
  if(MeRHS){
      Expr *BaseRHS = MeRHS->getBase();
      CTERHS = dyn_cast<CXXThisExpr>(BaseRHS);
#if DEBUG_PRINTS
      if(CTERHS)
  	  prettyPrintE("Rhs this expr is", CTERHS, ASTC);
#endif
  }

  // Return if neither lhs nor rhs is a this->member_expr
  if(!CTELHS && !CTERHS)
    return true;

#if DEBUG_PRINTS_VERBOSE
  llvm::errs() << "Stage 2\n";
#endif

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
      const std::string FieldNameRHS =
		NDR->getQualifiedNameAsString();

      /* If RHS is not defined, report to caller */
      if(isElementUndefined(FieldNameRHS))
	  return false;
  }

  // Add lhs to set if it is a this* member
  if(CTELHS){
      // Add FQN for unique resolution of fields
      const NamedDecl *NDL = dyn_cast<NamedDecl>(MeLHS->getMemberDecl());
      const std::string FieldNameLHS =
	  NDL->getQualifiedNameAsString();
#if DEBUG_PRINTS
      llvm::errs() << "Adding Field to " << (S ? "context set: " : "ctor set: ")
	  << FieldNameLHS << "\n";
#endif
      updateSetInternal(S ? &contextInitializedFieldsSet :
	  &ctorInitializedFieldsSet, FieldNameLHS);
#if DEBUG_PRINTS
      llvm::errs() << (S ? "Printing context set: ": "Printing ctor set: ") << "\n";
      if(S)
	printSetInternal(&contextInitializedFieldsSet);
      else
	printSetInternal(&ctorInitializedFieldsSet);
#endif
  }
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
#ifdef ENCODE_BUG_INFO

  /* Iterate through EncodedBugInfo adding Extra text with
   * each iteration.
   */
  for (EBIIteratorTy i = EncodedBugInfo.begin(),
      e = EncodedBugInfo.end(); i != e; ++i) {
      R->addExtraText(*i);
   }
#endif

  R->addRange(SR);
  C.emitReport(R);

  return;
}

/* Visit AST nodes for method definitions : CXXMethodDecl is a misnomer
 * This visitor is not path sensitive
 */
void UseDefChecker::checkASTDecl(const CXXConstructorDecl *CtorDecl,
                                  AnalysisManager &Mgr,
                                  BugReporter &BR) const {

  /* Do the following things:
   *  1. Check if ctor has body in TU.
   *  	a. If not, add class decl to ctorHasNoBodyInTU and return
   *  	b. If there is a body, continue to Step (2)
   *  2. Check if ctor has member fields. If yes:
   *	 	a. Update ctorInitializedFieldsSet
   */
  if(!CtorDecl->hasBody()){
    const NamedDecl *NDC = dyn_cast<NamedDecl>(CtorDecl);
    /* FIXME: This should be fully qualified name
     * The reason we insert non fully qualified name of
     * Ctor is because we don't know how to get the same
     * string for comparison at the time of checkPreStmt.
     */

    /* FQName == ns::classname::classname
     * CtorName == classname
     * NSQCtorName == ns::classname
     */
    std::string FQName = NDC->getQualifiedNameAsString();
    std::string CtorName = NDC->getNameAsString();
    std::string NSQCtorName =
      FQName.substr(0,(FQName.length() - CtorName.length() - 2));
#if DEBUG_PRINTS
  llvm::errs() << "Ctor Name from Decl is: " << NSQCtorName << "\n";
#endif
    updateSetInternal(&ctorHasNoBodyInTUSet,
                      NSQCtorName);
    return;
  }

  /* CtorDecl has this magical range-based iterator function */
  for(auto *I : CtorDecl->inits()){
      CXXCtorInitializer *CtorInitializer = I;
      /* FIXME: Choose the right variant(s) of
       * is*MemberInitializer call
       */
      // Check if Ctorinitializer is a member initializer
      if(!CtorInitializer->isMemberInitializer())
	continue;

      /* Member field is initialized (in the ctor)
       * Turns out isMemberInitializer() also returns
       * member fields initialized in class decl
       */
      // Update state map
      const FieldDecl *FD = CtorInitializer->getMember();
      // Get FQN for unique entry
      const NamedDecl *ND = dyn_cast<NamedDecl>(FD);
      const std::string FName = ND->getQualifiedNameAsString();
#if DEBUG_PRINTS
      llvm::errs() << "Adding field to ctor set: " << FName << "\n";
#endif
      updateSetInternal(&ctorInitializedFieldsSet, FName);
  }

  /* After looking for member initializers in class and in the
   * initializer list of ctor, we move on to the ctor body
   * itself if there is one in this translation unit
   */
  if(CtorDecl->hasTrivialBody())
    return;

  /* Process body for Bin ops and assignments */
  const Stmt *CS = CtorDecl->getBody();

  /* Chromium code crashed for some reason at
   * at CS->children(). Turns out getBody is not
   * guaranteed to return a Stmt. Could also be
   * a Decl
   */
  if(!CS)
      return;

  /* Iterate over statements in body. Note that we
   * are processing assignments in Ctors twice
   * 	1. Once here, while visiting AST nodes
   * 	2. Again, when statements in Function
   * 	defintion of ctor are being visited
   * 	during PreStmt<BinaryOperator>
   */
  for(auto *it : CS->children()){
      /* Bail if statement is not binary op */
      const BinaryOperator *BO =
	  dyn_cast<BinaryOperator>(it);

      if(!BO)
	continue;

      /* Bail if binop is not eq. assignment */
      if((BO->getOpcode() != BO_Assign))
        continue;

      /* Build up def chain
       * Note:
       * 1. We don't do anything about
       * undefined uses of fields in Ctor. The
       * assumption is that assignments in ctors
       * are valid.
       */
      bool isDef = trackMembersInAssign(BO, Ctor,
                           Mgr.getASTContext());

      /* We can creepily add LHS here assuming that
       * it's us who don't understand what RHS not
       * being defined in a Ctor statement means.
       */
      if(!isDef){
	  llvm::errs() << "Undefined object field in ctor\n";
	  BO->getRHS()->dumpPretty(Mgr.getASTContext());
	  llvm::errs() << "\n";
	  /* Refactor code for taking an expression
	   * and adding it to set
	   */
//
//	  // Add LHS to ctorInitializedFieldsSet
//	  const Expr *E = BO->getLHS();
//	  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
//	  if(!ME)
//	    continue;
//	  const NamedDecl *NDLHS =
//
//	  updateSetInternal(&ctorInitializedFieldsSet,
//	                    FieldNameLHS);
      }
  }

  return;
}

/* Utility function for inserting fields into a given set */
void UseDefChecker::updateSetInternal(InitializedFieldsSetTy *Set,
				const std::string FName) const {
      Set->insert(FName);
}

/* Utility function for finding a field in a given set */
bool UseDefChecker::findElementInSet(const std::string FName,
                           SetKind S) const {
  InitializedFieldsSetTy Set =
      (S ? contextInitializedFieldsSet : ctorInitializedFieldsSet);
  return (Set.find(FName) != Set.end());
}

bool UseDefChecker::isElementUndefined(const std::string FName) const {
  /* If element is in neither Ctor not context
   * sets, it's undefined
   */
  if(!(findElementInSet(FName, Ctor)) &&
      !(findElementInSet(FName, Context)))
      return true;

  return false;
}

#ifdef EMPLOY_HEURISTICS
unsigned UseDefChecker::getDepthOfCurrentStack(CheckerContext &C) {

  // Default StackDepth is one i.e., call being explored by PS engine
  unsigned StackDepth = 1;

  if(C.inTopFrame())
    return StackDepth;

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
         StackDepth += 1;
      /* It doesn't make sense to continue if parent is
       * not a stack frame. I imagine stack frames stacked
       * together and not interspersed between other frame types
       * like Scope or Block.
       */
      else
	  llvm_unreachable("This can't be! We are not in the top most"
	      " stack frame but parent of location context is not a StackFrame kind.");
  }

  return StackDepth;
}
#endif

/* This utility function must be called from reportBug before
 * populating the ExtraData portion of the bug report.
 * dumpCallsOnStack pushes the call stack as a list of strings
 * to EncodedBugInfo. EncodedBugInfo is copied on to the bug
 * report's ExtraText field.
 *
 * Finally, the HTML Diagnostics client picks up ExtraText and
 * populates the HTML report with the call stack.
 */
#ifdef ENCODE_BUG_INFO
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

#ifdef MANGLE_NAMES
  return getMangledNameAsString(ND, ADC->getASTContext());
#else
  return ND->getQualifiedNameAsString();
#endif
}
#endif

#ifdef MANGLE_NAMES
std::string UseDefChecker::getMangledNameAsString(const NamedDecl *ND,
                                                  ASTContext &ASTC) {
  // Create Mangle context
  MangleContext *MC = ASTC.createMangleContext();

  // We need raw string stream so we can return std::string
  std::string MangledName;
  llvm::raw_string_ostream raw_stream(MangledName);

  if(!MC->shouldMangleDeclName(ND)){
#ifdef DEBUG_PRINTS
    llvm::errs() << "Name mangling not needed\n";
#endif
    return ND->getQualifiedNameAsString();
  }

  /* Assertion deep within mangleName */
  if(!isa<CXXConstructorDecl>(ND) && !isa<CXXDestructorDecl>(ND)){
    MC->mangleName(ND, raw_stream);
    return raw_stream.str();
  }

  return ND->getQualifiedNameAsString();
}
#endif

/* Used to be EOF visitor. Can be used for debugging purposes
 * Spits out the state of the internal map at the end of analysis
 */
#if 0
void UseDefChecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
				   AnalysisManager &Mgr,
				   BugReporter &BR) const {
#if DEBUG_PRINTS
  printSetInternal(&ctorInitializedFieldsSet);
#endif
  return;
}
#endif

void UseDefChecker::printSetInternal(InitializedFieldsSetTy *Set) const {

  InitializedFieldsSetTy::iterator it;

  for(it = Set->begin();
      it != Set->end(); ++it)
    llvm::errs() << (*it) << "\n";

  return;
}

void UseDefChecker::prettyPrintE(StringRef S, const Expr *E,
                                 ASTContext &ASTC) {
  llvm::errs() << S << ": ";
  E->dumpPretty(ASTC);
  llvm::errs() << "\n";
  return;
}

void UseDefChecker::prettyPrintD(StringRef S,
                                  const Decl *D) {
  llvm::errs() << S << ": ";
  D->dump();
  llvm::errs() << "\n";
  return;
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

  for (const LocationContext *LCtx = LC->getParent();
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
