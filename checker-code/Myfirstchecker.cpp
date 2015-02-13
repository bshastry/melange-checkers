/*
 * Myfirstchecker.cpp
 *
 *  Created on: Jan 12, 2015
 *      Author: bhargava
 *
//===----------------------------------------------------------------------===//
//
// This files defines Myfirstchecker, a custom checker that looks for
// variable initialization patterns that tend to be buggy
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
#include "llvm/Support/raw_ostream.h"

#define DEBUG_PRINTS	0

using namespace clang;
using namespace ento;

/* We track usedefs by fully qualified field names, like so
 * foo::m_x or mynamespace::foo::m_x
 */
typedef std::set<std::string> InitializedFieldsSetTy;

namespace {
class Myfirstchecker : public Checker< check::ASTDecl<CXXConstructorDecl>,
					check::PreStmt<BinaryOperator>,
					check::PreStmt<UnaryOperator>,
					check::EndOfTranslationUnit>
					{
  typedef Decl const Decl_const_t;
  mutable std::unique_ptr<BugType> BT;
  mutable Decl_const_t *pDecl = nullptr;
  raw_ostream &os = llvm::errs();
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

  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                    AnalysisManager &Mgr,
                                    BugReporter &BR) const;

private:
  void printSetInternal(InitializedFieldsSetTy *Set) const;

  void updateSetInternal(InitializedFieldsSetTy *Set,
                             const std::string FName) const;
  bool findElementInSet(const std::string FName,
                        SetKind S) const;
  bool isElementUndefined(const std::string Fname) const;

  void prettyPrintE(StringRef S, const Expr *E,
		     ASTContext &ASTC) const;
  void prettyPrintD(StringRef S, const Decl *D) const;

  void reportBug(StringRef Message, SourceRange SR,
                                 CheckerContext &C) const;
  bool trackMembersInAssign(const BinaryOperator *BO,
                            SetKind S, ASTContext &ASTC) const;
};
} // end of anonymous namespace

void Myfirstchecker::checkPreStmt(const UnaryOperator *UO,
                                  CheckerContext &C) const {

  /* Return if not a logical NOT operator */
  if(UO->getOpcode() != UO_LNot)
    return;

  /* Return if not member expression */
  Expr *E = UO->getSubExpr()->IgnoreImpCasts();
  MemberExpr *ME = dyn_cast<MemberExpr>(E);
  if(!ME)
    return;

  /* Return if member expression has no base
   * Wonder what this implies
   */
  Expr *Base = ME->getBase();
  if(!Base)
    return;


  /* Return if not cxx this* expression */
  CXXThisExpr *CTE = dyn_cast<CXXThisExpr>(Base);
  if(!CTE)
    return;

  /* Get the FQ field name */
  const NamedDecl *ND = dyn_cast<NamedDecl>(ME->getMemberDecl());
  const std::string FieldName =
		ND->getQualifiedNameAsString();
//  const std::string FieldName =
//	ME->getMemberDecl()->getDeclName().getAsString();
  /* Find Fieldname in ctor and context sets and flag
   * a warning only if we know for sure that ctor does not
   * have a body in this translation unit
   */
  if(isElementUndefined(FieldName))
  {
	// Report bug
#if DEBUG_PRINTS
	os << "Report bug here\n";
#endif
	StringRef Message = "Potentially uninitialized object field";
	reportBug(Message, ME->getSourceRange(), C);
  }
  return;

}

void Myfirstchecker::checkPreStmt(const BinaryOperator *BO,
                                  CheckerContext &C) const {

  /* Return if binop is not eq. assignment */
  if((BO->getOpcode() != BO_Assign))
    return;

  /* AnalysisDeclarationContext tells us which function
   * declaration (definition) is being visited. We maintain
   * two sets of initdata:
   * 	1. Ctor [Inter-procedural]
   * 	2. Present decl context [Intra-procedural]
   */

  /* Check if current analysis declaration context has changed
   * updating pContext if necessary. Also, clear context
   * specific set
   */
  /* FIXME: Pointer to decl may not be a unique value for all
   * funtion decls in TU. IOW, using decl is flaky
   */

  ASTContext &ASTC = C.getASTContext();
  AnalysisDeclContext *cContext = C.getCurrentAnalysisDeclContext();
  const Decl *cDecl = cContext->getDecl();

  if(pDecl != cDecl){
    pDecl = cDecl;
    contextInitializedFieldsSet.clear();
  }

  /* If we are here, we are analyzing an assignment
   * statement in a function definition.
   */
  bool isDef = trackMembersInAssign(BO, Context, ASTC);

  // Report bug
  if(!isDef){
      const Expr *rhs = BO->getRHS();
      const MemberExpr *MeRHS =
	  dyn_cast<MemberExpr>(rhs->IgnoreImpCasts());
      	  StringRef Message = "Potentially uninitialized object field";
      	  reportBug(Message, MeRHS->getSourceRange(), C);
  }

  return;
}

/* Utility function to track uses and defs in assignment
 * statements.
 * Returns false if RHS is not in defs set. When this
 * happens, onus is on caller to report bug
 */
bool Myfirstchecker::trackMembersInAssign(const BinaryOperator *BO,
                                          SetKind S,
                                          ASTContext &ASTC) const {
  /* Check if LHS/RHS is a member expression */
  const Expr *lhs = BO->getLHS();
  const Expr *rhs = BO->getRHS();

  const MemberExpr *MeLHS = dyn_cast<MemberExpr>(lhs);
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

#if DEBUG_PRINTS
  if(MeLHS)
      prettyPrintE("LHS member exp is", MeLHS, ASTC);

  if(MeRHS)
      prettyPrintE("RHS member exp is", MeRHS, ASTC);
#endif

  /* Return if neither lhs nor rhs is a member expression */
  if(!MeLHS && !MeRHS)
    return true;

#if DEBUG_PRINTS
  os << "Stage 1\n";
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

#if DEBUG_PRINTS
  os << "Stage 2\n";
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
      // MeRHS->getMemberDecl()->getDeclName().getAsString();

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
//  	MeLHS->getMemberDecl()->getDeclName().getAsString();
#if DEBUG_PRINTS
      os << "Adding Field to " << (S ? "context set: " : "ctor set: ")
	  << FieldNameLHS << "\n";
#endif
      updateSetInternal(S ? &contextInitializedFieldsSet :
	  &ctorInitializedFieldsSet, FieldNameLHS);
  }
  return true;
}

void Myfirstchecker::reportBug(StringRef Message,
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
  R->addRange(SR);
  C.emitReport(R);

  return;
}

/* Visit AST nodes for method definitions : CXXMethodDecl is a misnomer
 * This visitor is not path sensitive
 */
void Myfirstchecker::checkASTDecl(const CXXConstructorDecl *CtorDecl,
                                  AnalysisManager &Mgr,
                                  BugReporter &BR) const {

  /* Do the following things:
   * 1. Check if fdecl is a ctor of a cxx object. If yes:
   *	 a. Check if ctor has member fields. If yes:
   *	 	i. Update state map with initialization
   *	 		status of member fields
   */

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
      os << "Adding field to ctor set: " << FName << "\n";
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

  /* Iterate over statements in body. Note that we
   * are processing assignments in Ctors twice
   * 	1. Once here, while visiting AST nodes
   * 	2. Again, when statements in Function
   * 	defintion of ctor are being visited
   * 	during PreStmt<BinaryOperator>
   */
  for(auto *it : CS->children()){
      /* Bail if statement is not assignment */
      const BinaryOperator *BO =
	  dyn_cast<BinaryOperator>(it);

      if(!BO)
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

      if(!isDef)
	  os << "Undefined object field in ctor\n";
  }

  return;
}

/* Utility function for inserting fields into a given set */
void Myfirstchecker::updateSetInternal(InitializedFieldsSetTy *Set,
				const std::string FName) const {
      Set->insert(FName);
}

/* Utility function for finding a field in a given set */
bool Myfirstchecker::findElementInSet(const std::string FName,
                           SetKind S) const {
  InitializedFieldsSetTy Set =
      (S ? contextInitializedFieldsSet : ctorInitializedFieldsSet);
  return (Set.find(FName) != Set.end());
}

bool Myfirstchecker::isElementUndefined(const std::string FName) const {
  /* If element is in neither Ctor not context
   * sets, it's undefined
   */
  if(!(findElementInSet(FName, Ctor)) &&
      !(findElementInSet(FName, Context)))
      return true;

  return false;
}

/* EOF visitor. Spits out the state of the internal map
 * at the end of analysis
 */
void Myfirstchecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
				   AnalysisManager &Mgr,
				   BugReporter &BR) const {
#if DEBUG_PRINTS
  printSetInternal(&ctorInitializedFieldsSet);
#endif
  return;
}

void Myfirstchecker::printSetInternal(InitializedFieldsSetTy *Set) const {

  InitializedFieldsSetTy::iterator it;

  os << "Printing set of field members that are initialized "
      << "either in ctor or in class\n";

  for(it = Set->begin();
      it != Set->end(); ++it)
    os << (*it) << "\n";

  return;
}

void Myfirstchecker::prettyPrintE(StringRef S, const Expr *E,
                                 ASTContext &ASTC) const {
  os << S << ": ";
  E->dumpPretty(ASTC);
  os << "\n";
  return;
}

void Myfirstchecker::prettyPrintD(StringRef S,
                                  const Decl *D) const {
  os << S << ": ";
  D->dump();
  os << "\n";
  return;
}

// Register plugin!
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<Myfirstchecker>("alpha.security.myfirstchecker", "My first checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
