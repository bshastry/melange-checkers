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



using namespace clang;
using namespace ento;

// FIXME: Use a unique id instead of Fieldname aka std::string
typedef std::set<std::string> InitializedFieldsSetTy;

namespace {
class Myfirstchecker : public Checker< check::ASTDecl<CXXConstructorDecl>,
					check::PreStmt<BinaryOperator>,
					check::EndOfTranslationUnit>
					{
  mutable std::unique_ptr<BugType> BT;
  mutable const Decl *pDecl = nullptr;
  raw_ostream &os = llvm::errs();

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
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                    AnalysisManager &Mgr,
                                    BugReporter &BR) const;

private:
  void printSetInternal(InitializedFieldsSetTy *Set) const;

  void updateSetInternal(InitializedFieldsSetTy *Set,
                             const std::string FName) const;
  bool findElementInSet(const std::string FName,
                        InitializedFieldsSetTy *Set) const;

  void prettyPrintE(StringRef S, const Expr *E,
		     ASTContext &ASTC) const;
  void prettyPrintD(StringRef S, const Decl *D) const;

  void reportBug(StringRef Message, SourceRange SR,
                                 CheckerContext &C) const;
};
} // end of anonymous namespace

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
   */
  bool isImplicitCast = isa<ImplicitCastExpr>(rhs);
  const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(rhs);
  const MemberExpr *MeRHS = isImplicitCast ?
			    cast<MemberExpr>(ICE->getSubExpr()) :
			    nullptr;

  if(MeLHS)
      prettyPrintE("LHS member exp is", MeLHS, ASTC);


  if(MeRHS)
      prettyPrintE("RHS member exp is", MeRHS, ASTC);


  /* Return if neither lhs nor rhs is a member expression */
  if(!MeLHS && !MeRHS)
    return;

  os << "Stage 1\n";

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
//      prettyPrintE("Lhs base is", BaseLHS, ASTC);
      CTELHS = dyn_cast<CXXThisExpr>(BaseLHS);
      if(CTELHS){
//	  prettyPrintE("Lhs this expr is", CTELHS, ASTC);
      }
  }
  if(MeRHS){
      Expr *BaseRHS = MeRHS->getBase();
//      prettyPrintE("Rhs base is", BaseRHS, ASTC);
      CTERHS = dyn_cast<CXXThisExpr>(BaseRHS);
      if(CTERHS){
//  	  prettyPrintE("Rhs this expr is", CTERHS, ASTC);
      }
  }

  // Return if neither lhs nor rhs is a this->member_expr
  if(!CTELHS && !CTERHS)
    return;

  os << "Stage 2\n";

  /* If we are here, we can be sure that the member field
   * being defined/used belongs to this* object
   */

  /* Check use first because this->rhs may be uninitialized
   * and we would want to report the bug and exit before
   * anything else
   */
  if(CTERHS){
    const std::string FieldNameRHS =
	MeRHS->getMemberDecl()->getDeclName().getAsString();
    // Check for FieldDeclRHS in ctor and context sets
    if((!findElementInSet(FieldNameRHS, &ctorInitializedFieldsSet))
	&& (!findElementInSet(FieldNameRHS, &contextInitializedFieldsSet)))
    {
	// Report bug
	os << "Report bug here\n";
	StringRef Message = "Potentially uninitialized object field";
	reportBug(Message, MeRHS->getSourceRange(), C);
    }
  }

  // Add lhs to set if it is a this* member
  if(CTELHS){
      const std::string FieldNameLHS =
  	MeLHS->getMemberDecl()->getDeclName().getAsString();
      os << "Adding Field to context set: " << FieldNameLHS << "\n";
      updateSetInternal(&contextInitializedFieldsSet, FieldNameLHS);
  }

  return;
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
      const std::string FName = FD->getDeclName().getAsString();
      os << "Adding field to ctor set: " << FName << "\n";
      updateSetInternal(&ctorInitializedFieldsSet, FName);
  }

  return;
}

/* Visit record declarations to create an initial map
 * of the initialization state of record fields
 */
//void Myfirstchecker::checkASTDecl(const RecordDecl *RD,
//                                  AnalysisManager &Mgr,
//                                  BugReporter &BR) const {
//
//  /* FIXME: It makes sense to filter out RecordDecls that
//   * don't have a bearing on the file being analyzed
//   */
//
//  /* We visit RecordDecl in addtion to CXXCtordecl because
//   * the former visits records within records.
//   * This takes care of visiting nested records
//   */
//  const CXXRecordDecl *ObjDecl = dyn_cast<CXXRecordDecl>(RD);
//
//  /* Return if not a CXX object declaration */
//  if(!ObjDecl)
//    return;
//
//  /* Return if CXX object has no definition */
//  if(!ObjDecl->hasDefinition())
//    return;
//
//  /* Iterate over member fields of CXX object */
//  RecordDecl::field_iterator fib = ObjDecl->field_begin();
//  RecordDecl::field_iterator fie = ObjDecl->field_end();
//
//  /* Return if CXX object has no member fields */
//  if(fib == fie)
//    return;
//
////  printFieldsInRecord(fib, fie);
//  updateStateMap(fib, fie);
//
//  return;
//}

/* Utility function for debugging purposes */
//void Myfirstchecker::printFieldsInRecord(RecordDecl::field_iterator start,
//                                   RecordDecl::field_iterator end) const {
//
//  /* Iterate over and print member fields of CXX object */
//  for( ;start != end; start++) {
//      FieldDecl *FDecl = *start;
//      os << FDecl->getDeclName().getAsString()
//	  << " has in-class initializer?\t"
//	  << (FDecl->hasInClassInitializer() ? "yes" : "no")
//	  << "\n";
//  }
//  return;
//}

/* Function to iterate over member fields of an object
 * creating an internal representation of their initialization
 * state.
 */
//void Myfirstchecker::updateStateMap(RecordDecl::field_iterator start,
//                                   RecordDecl::field_iterator end) const {
//
//  /* Iterate over and map member fields of CXX object to internal
//   * state map */
//  for( ;start != end; start++) {
//      const FieldDecl *FDecl = *start;
//      if(FDecl->hasInClassInitializer())
//	updateStateMapInternal(FDecl);
//  }
//  return;
//}

/* Utility function for inserting fields into a given set */
void Myfirstchecker::updateSetInternal(InitializedFieldsSetTy *Set,
				const std::string FName) const {
      Set->insert(FName);
}

/* Utility function for finding a field in a given set */
bool Myfirstchecker::findElementInSet(const std::string FName,
                           InitializedFieldsSetTy *Set) const {
  return (Set->find(FName) != Set->end());
}

/* EOF visitor. Spits out the state of the internal map
 * at the end of analysis
 */
void Myfirstchecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
				   AnalysisManager &Mgr,
				   BugReporter &BR) const {

  os << "Printing ctor set\n";
  printSetInternal(&ctorInitializedFieldsSet);

//  /* Iterate over state map and report error
//   * on first uninitialized field member
//   */
//  for(InitializationStateMapTy::iterator it=InitializationStateMap.begin();
//      it!=InitializationStateMap.end(); ++it){
//      // Check if fielddecl is uninitialized
//      if(!it->second){
//	  // FDecl is uninitialized
//	  const FieldDecl *FDecl = it->first;
//	  PathDiagnosticLocation PDL =
//	      PathDiagnosticLocation::create(FDecl,
//	                                     Mgr.getSourceManager());
//
//	  StringRef Message = "Object member is uninitialized in Ctor";
//	  StringRef Name = "Uninitialized field";
//	  StringRef Category = " Custom Security ";
//	  SourceRange Sr = FDecl->getSourceRange();
//
//	  BR.EmitBasicReport(FDecl, this, Name, Category,
//	                     Message, PDL, Sr);
//
//	  continue;
//      }
//  }
//
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
