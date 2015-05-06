// UseDefChecker.cpp - Heuristics based checker for uses of potentially undef vals -*- C++ -*-
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This files defines UseDefChecker, a custom checker that looks for
// CXX field initialization and use patterns that tend to be buggy.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/FunctionSummary.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Mangle.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/DenseSet.h"

using namespace clang;
using namespace ento;

typedef llvm::DenseSet<const CXXRecordDecl *>				CtorsVisitedTy;
typedef llvm::DenseSet<const Decl *>					CtorsDeclSetTy;
typedef BugReport::ExtraTextList					ETLTy;
typedef ETLTy::const_iterator 						EBIIteratorTy;
typedef std::pair<ETLTy, SourceLocation>				DiagPairTy;
typedef llvm::DenseMap<const Decl *, DiagPairTy>			DiagnosticsInfoTy;
typedef const FunctionSummariesTy::MapTy				FSMapTy;
typedef const FunctionSummariesTy::FunctionSummary::TLDTaintMapTy	TLDTMTy;
typedef const FunctionSummariesTy::FunctionSummary::DTPair	 	DTPairTy;


namespace {

class UseDefChecker : public Checker< check::PreStmt<UnaryOperator>,
				      check::PreStmt<BinaryOperator>,
				      check::EndFunction,
				      check::PreCall,
				      check::EndOfTranslationUnit> {
  mutable std::unique_ptr<BugType> BT;
  enum SetKind { Ctor, Context };

  mutable CtorsVisitedTy 	 	ctorsVisited;
  mutable ETLTy 			EncodedBugInfo;
  mutable DiagnosticsInfoTy		DiagnosticsInfo;

public:
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
  void checkEndFunction(CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager &Mgr,
                                  BugReporter &BR) const;

private:
  void addNDToTaintSet(const NamedDecl *ND, CheckerContext &C) const;
  bool isTaintedInContext(const NamedDecl *ND, CheckerContext &C) const;
  void reportBug(AnalysisManager &Mgr, BugReporter &BR, const Decl *D) const;
//  void reportBug(SourceRange SR, CheckerContext &C) const;
  bool trackMembersInAssign(const BinaryOperator *BO, CheckerContext &C) const;
  void encodeBugInfo(const MemberExpr *ME, CheckerContext &C) const;
  void dumpCallsOnStack(CheckerContext &C) const;
  void storeDiagnostics(const Decl *D, SourceLocation SL) const;
  void taintCtorInits(const CXXConstructorDecl *CCD, CheckerContext &C) const;

  // Static utility functions
  static bool isCXXFieldDecl(const Expr *E);
  static std::string getADCQualifiedNameAsStringRef(const LocationContext *LC);
  static std::string getMangledNameAsString(const NamedDecl *ND, ASTContext &ASTC);
};
} // end of anonymous namespace

REGISTER_SET_WITH_PROGRAMSTATE(TaintDeclsInContext, const Decl*)

void UseDefChecker::taintCtorInits(const CXXConstructorDecl *CCD,
                                   CheckerContext &C) const {

  for(auto *I : CCD->inits()){
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

      addNDToTaintSet(ND, C);

      // Add init expressions to taint set if necessary
      const Expr *E = CtorInitializer->getInit()->IgnoreImpCasts();
      if(isCXXFieldDecl(E)){
	const MemberExpr *MEI = dyn_cast<MemberExpr>(E);
	const NamedDecl *NDI = dyn_cast<NamedDecl>(MEI->getMemberDecl());
	addNDToTaintSet(NDI, C);
      }
  }
}

/* We visit endfunction to make sure we update CtorVisited if necessary.
 * Note that even an empty ctor body, like so:
 * 	foo() {}
 * is going to end up here and update CtorVisited to true.
 */
void UseDefChecker::checkEndFunction(CheckerContext &C) const {

  const AnalysisDeclContext *ADC = C.getLocationContext()->getAnalysisDeclContext();
  const CXXMethodDecl *CMD = dyn_cast<CXXMethodDecl>(ADC->getDecl());

  if(!CMD || CMD->isStatic())
    return;

  if(!isa<CXXConstructorDecl>(CMD))
    return;

  /* Absent AST visitor, we postpone tainting of Ctor inits
   * to the fag end of Ctor analysis. This will increase
   * false negatives in theory but not likely in practice because
   * use of uninitialized class members during object creation is
   * rare and pretty fucked up to be honest.
   */
  taintCtorInits(dyn_cast<CXXConstructorDecl>(CMD), C);

  const Decl *TLD = C.getTopLevelDecl();

  if (isa<CXXConstructorDecl>(TLD)) {
      const CXXMethodDecl *TLDCMD = cast<CXXMethodDecl>(TLD);
      const CXXRecordDecl *CRD = TLDCMD->getParent();
      assert(CRD && "UDC: CXXRecordDecl can't be null");

      if(ctorsVisited.find(CRD) == ctorsVisited.end())
	  ctorsVisited.insert(CRD);
  }

}

void UseDefChecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                              AnalysisManager &Mgr,
                                              BugReporter &BR) const {

  const FunctionSummariesTy::MapTy &Map = Mgr.FunctionSummary->getMap();
  CtorsDeclSetTy TaintedClassMembers;

  /// 0. Find Ctor taints
  for(FSMapTy::const_iterator I = Map.begin(), E = Map.end(); I != E; ++I){
    if(!isa<CXXConstructorDecl>(I->first))
      continue;

    const TLDTMTy &CtorTaintMap = I->second.getTaintMap();
    for(TLDTMTy::const_iterator II = CtorTaintMap.begin(), EE = CtorTaintMap.end();
	II != EE; ++II)
	TaintedClassMembers.insert(II->first);
  } // end of ctor taint for loop

  /// 1. Iterate through FS Map
  for(FSMapTy::const_iterator I = Map.begin(), E = Map.end(); I != E ; ++I){

    if(isa<CXXConstructorDecl>(I->first))
      continue;

    /// 2. Get taint map of FS
    const TLDTMTy &TaintMap = I->second.getTaintMap();

    /// 3. Iterate through Taint map
    for(TLDTMTy::const_iterator II = TaintMap.begin(), EE = TaintMap.end();
	II != EE; ++II) {

	/// 4. For each tainted decl, check if it is tainted in Ctor
	if(TaintedClassMembers.find(II->first) != TaintedClassMembers.end())
	  continue;

	const Decl *BuggyDecl = cast<const Decl>(II->first);

	const FieldDecl *FD = cast<const FieldDecl>(BuggyDecl);
	assert(FD && "UDC: BuggyDecl is not a FieldDecl");
	const RecordDecl *RD = FD->getParent();
	assert(RD && "UDC: BuggyDecl has no RecordDecl");
	const CXXRecordDecl *CRD = cast<const CXXRecordDecl>(RD);
	assert(CRD && "UDC: BuggyDecl has no CXXRecordDecl");

	// There is a user declared Ctor that we haven't visited.
	// So don't flag warning.
	if(CRD->hasUserDeclaredConstructor() && (ctorsVisited.find(CRD) == ctorsVisited.end()))
	  continue;

	DiagnosticsInfoTy::iterator I = DiagnosticsInfo.find(BuggyDecl);
	SourceLocation SL = std::get<1>(I->second);
	SourceManager &SM = Mgr.getSourceManager();

	// FIXME: Warnings in header files are potential false positives
	// Genesis is Crbug 411177.
	if(!SM.isWrittenInMainFile(SL))
	  continue;

	/// Report bug!
	reportBug(Mgr, BR, BuggyDecl);
    } // end of taint map for loop
  } // end of function summary for loop
}

void UseDefChecker::checkPreCall(const CallEvent &Call,
                                 CheckerContext &C) const {

  if (isa<CXXConstructorDecl>(C.getTopLevelDecl()))
    return;

  const Decl *D = Call.getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);

  for (unsigned i = 0, e = Call.getNumArgs(); i != e; ++i) {

      if (!isCXXFieldDecl(Call.getArgExpr(i)->IgnoreImpCasts()))
	continue;

      const ParmVarDecl *ParamDecl = nullptr;
      const MemberExpr *CAE = dyn_cast<const MemberExpr>(Call.getArgExpr(i)->IgnoreImpCasts());

      if (FD && i < FD->getNumParams())
	ParamDecl = FD->getParamDecl(i);

      if (ParamDecl && CAE) {
	  const FieldDecl *FiD = dyn_cast<FieldDecl>(CAE->getMemberDecl());

	  if (FiD && isa<CXXRecordDecl>(FiD->getParent())) {
	      const NamedDecl *ND = dyn_cast<NamedDecl>(CAE->getMemberDecl());
	      if (ND && !isTaintedInContext(ND, C))
		  encodeBugInfo(CAE, C);
	  }
      }
  }

  return;
}

void UseDefChecker::encodeBugInfo(const MemberExpr *ME,
                                  CheckerContext &C) const {
  /* Get the FQ field name */
  const NamedDecl *ND = dyn_cast<NamedDecl>(ME->getMemberDecl());
  const std::string FieldName = ND->getQualifiedNameAsString();

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

  const Decl *FD = C.getTopLevelDecl();

  if (!isa<CXXConstructorDecl>(FD)){
    storeDiagnostics(cast<const Decl>(ND), ME->getMemberLoc());
    /// This taint means we found a potentially undefined class member
    C.addCSTaint(cast<const Decl>(ND));
  }

  return;
}

void UseDefChecker::storeDiagnostics(const Decl *D, SourceLocation SL) const {
  DiagnosticsInfoTy::iterator I = DiagnosticsInfo.find(D);
  if (I != DiagnosticsInfo.end())
    return;

  typedef std::pair<const Decl *, DiagPairTy> KVPair;
  I = DiagnosticsInfo.insert(KVPair(D, DiagPairTy(EncodedBugInfo, SL))).first;
  assert(I != DiagnosticsInfo.end());
  return;
}

bool UseDefChecker::isCXXFieldDecl(const Expr *E) {
  const MemberExpr *ME = dyn_cast<MemberExpr>(E->IgnoreImpCasts());

  if (!ME)
      return false;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());

  if (!FD)
      return false;

  if (!isa<CXXRecordDecl>(FD->getParent()))
      return false;

  const CXXRecordDecl *CRD = dyn_cast<CXXRecordDecl>(FD->getParent());

  // We don't want to be dealing with struct/union fields
  if (CRD->isCLike())
      return false;

  return true;
}

void UseDefChecker::reportBug(AnalysisManager &Mgr, BugReporter &BR,
                              const Decl *D) const {

  const char *name = "Undefined CXX object checker";
  const char *desc = "Flags potential uses of undefined CXX object fields";

  StringRef Message = "Potentially uninitialized object field";

  DiagnosticsInfoTy::iterator I = DiagnosticsInfo.find(D);

  ETLTy EBI = std::get<0>(I->second);
  SourceLocation SL = std::get<1>(I->second);

  PathDiagnosticLocation l(SL, Mgr.getSourceManager());

  if (!BT)
    BT.reset(new BuiltinBug(this, name, desc));

  BugReport *R = new BugReport(*BT, Message, l);

  for (EBIIteratorTy i = EBI.begin(),
      e = EBI.end(); i != e; ++i) {
      R->addExtraText(*i);
   }

  BR.emitReport(R);
}

void UseDefChecker::checkPreStmt(const UnaryOperator *UO,
                                  CheckerContext &C) const {

  /* Return if not a logical NOT operator */
  if (UO->getOpcode() != UO_LNot)
    return;

  if (isa<CXXConstructorDecl>(C.getTopLevelDecl()))
    return;

  /* Ignore implicit casts */
  Expr *E = UO->getSubExpr()->IgnoreImpCasts();

  if (!isCXXFieldDecl(E))
    return;

  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  assert(ME && "UDC: ME can't be null here");

  const NamedDecl *ND = dyn_cast<NamedDecl>(ME->getMemberDecl());
  assert(ND && "UDC: ND can't be null here");

  if (!isTaintedInContext(ND, C))
    encodeBugInfo(ME, C);

  return;
}

void UseDefChecker::checkPreStmt(const BinaryOperator *BO,
                                  CheckerContext &C) const {

  const Expr *RHS = BO->getRHS()->IgnoreImpCasts();
  const Expr *LHS = BO->getLHS()->IgnoreImpCasts();

  // FIXME: Should we care about non this* objects. Use cases?
  if(!isCXXFieldDecl(RHS) && !isCXXFieldDecl(LHS))
    return;

  bool isDef = true;
  switch(BO->getOpcode()){
    case BO_Assign:
      isDef = trackMembersInAssign(BO, C);
      // Report bug.
      if(!isDef){
          /* The predicate C.getTopLevelDecl() is meant to weed out false warnings
           * of fields being used in Ctor being undefined. I am not sure why this happens but
           * I am pretty sure these are false alerts.
           */
          assert(!isa<CXXConstructorDecl>(C.getTopLevelDecl())
                 && "Undefined RHS in Ctor stack should not be flagged.");
          const MemberExpr *MeRHS = dyn_cast<MemberExpr>(RHS);
          encodeBugInfo(MeRHS, C);
      }
      break;
    case BO_Mul:
    case BO_Div:
    case BO_Rem:
    case BO_Add:
    case BO_Sub:
    case BO_Shl:
    case BO_Shr:
    case BO_LT:
    case BO_GT:
    case BO_LE:
    case BO_GE:
    case BO_EQ:
    case BO_NE:
    case BO_And:
    case BO_Xor:
    case BO_Or:
    case BO_LAnd:
    case BO_LOr:
      /* In taintclient-checkerv1.7, we permitted warnings in the Ctor
       * analysis context with the added logic that we only flag
       * undefined use if we know for sure that all initializations
       * in Ctor context have been tainted.
       * It turns out this decision is prone to Toctou flaw. Suppose that
       * at the time of check, Ctor is not visited but it gets visited
       * during the course of emitting bug report.
       * To counter this, we disable checking for undefined use
       * in Ctor analysis decl contexts altogether.
       */
      if (isa<CXXConstructorDecl>(C.getTopLevelDecl()))
	return;

      if(isCXXFieldDecl(LHS)){
	const MemberExpr *MELHS = dyn_cast<MemberExpr>(LHS);
	const NamedDecl *NDLHS = dyn_cast<NamedDecl>(MELHS->getMemberDecl());
	if(!isTaintedInContext(NDLHS, C))
	  encodeBugInfo(MELHS, C);
      }
      if(isCXXFieldDecl(RHS)){
	const MemberExpr *MERHS = dyn_cast<MemberExpr>(RHS);
	const NamedDecl *NDRHS = dyn_cast<NamedDecl>(MERHS->getMemberDecl());
	if(!isTaintedInContext(NDRHS, C))
	  encodeBugInfo(MERHS, C);
      }
      break;

    default:
      break;
  }

  return;
}

/* Utility function to track uses and defs in assignment
 * statements. Returns false if RHS is not in defs set. When this
 * happens, onus is on caller to report bug.
 */
bool UseDefChecker::trackMembersInAssign(const BinaryOperator *BO,
                                          CheckerContext &C) const {

  /* Check if LHS/RHS is a member expression */
  const Expr *lhs = BO->getLHS()->IgnoreImpCasts();
  const Expr *rhs = BO->getRHS()->IgnoreImpCasts();

  const MemberExpr *MeLHS = dyn_cast<MemberExpr>(lhs);
  const MemberExpr *MeRHS = dyn_cast<MemberExpr>(rhs);

  /* Assert because wrapper takes care of ensuring we get here only if
   * one of Binop expressions is a member expression.
   */
  assert((MeLHS || MeRHS) && "Neither LHS nor RHS is a member expression");

  /* If we are here, we can be sure that the member field
   * being defined/used belongs to this* object
   */

  /* Check use first because this->rhs may be uninitialized
   * and we would want to report the bug and exit before
   * anything else. Exception being this->rhs in ctor being undefined.
   * See comment in checkPreStmt.
   */
  if(MeRHS && isCXXFieldDecl(rhs)){
    const NamedDecl *NDR = dyn_cast<NamedDecl>(MeRHS->getMemberDecl());
    if(!isTaintedInContext(NDR, C) && !isa<CXXConstructorDecl>(C.getTopLevelDecl()))
	return false;
  }

  /* Add lhs to set if it is a this* member. We silently add LHS exprs
   * while exploring Ctor path even if we find that RHS is undefined. The
   * expectation is that it is abnormal to have uninitialized RHS in the
   * process of object creation.
   */
  if(MeLHS && isCXXFieldDecl(lhs)){
    const NamedDecl *NDL = dyn_cast<NamedDecl>(MeLHS->getMemberDecl());
    addNDToTaintSet(NDL, C);
  }
  return true;
}

/* Utility function for inserting fields into a given set */
void UseDefChecker::addNDToTaintSet(const NamedDecl *ND,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Decl *TLD = C.getTopLevelDecl();

  if (isa<CXXConstructorDecl>(TLD)) {
    /* This taints definitions in top level ctor function summary */
    C.addCSTaint(cast<const Decl>(ND));
  }

  /* This taints definitions in analysis decl context */
  State = State->add<TaintDeclsInContext>(cast<const Decl>(ND));
  if(State != C.getState())
    C.addTransition(State);
}

bool UseDefChecker::isTaintedInContext(const NamedDecl *ND,
                                       CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Decl *D = cast<const Decl>(ND);
  return State->contains<TaintDeclsInContext>(D);
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

// Register plugin!
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<UseDefChecker>("alpha.security.UseDefChecker", "CXX UseDef Checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
