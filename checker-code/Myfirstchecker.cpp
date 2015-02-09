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

typedef std::map<const FieldDecl *, bool> InitializationStateMapTy;

namespace {
class Myfirstchecker : public Checker< check::ASTDecl<RecordDecl>,
					check::ASTDecl<FunctionDecl>,
					check::PreCall,
					check::PreStmt<CallExpr>,
					check::EndOfTranslationUnit> {
  mutable std::unique_ptr<BuiltinBug> BT;
  raw_ostream &os = llvm::errs();
  /* Registering a map with Program State is useless if we are
   * working with AST* visitors only.
   * We create an STL map. LLVM has its own map implementation
   * called DenseMap that I got to know about later.
   */
  mutable InitializationStateMapTy InitializationStateMap;

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
  /* FIXME: Clean up unused visitors
   */
public:
  void checkASTDecl(const RecordDecl *RD, AnalysisManager &Mgr,
                      BugReporter &BR) const;
  void checkASTDecl(const FunctionDecl *FD, AnalysisManager &Mgr,
                    BugReporter &BR) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
				   AnalysisManager &Mgr,
				   BugReporter &BR) const;

private:
  void printFieldsInRecord(RecordDecl::field_iterator start,
                     RecordDecl::field_iterator end) const;

  void printStateMap() const;

  void updateStateMap(RecordDecl::field_iterator start,
                      RecordDecl::field_iterator end) const;

  void updateStateMapInternal(const FieldDecl *FDecl,
                              const bool value) const;
};
}

/* Visits the call expression. In the case of CXX object member
 * functions, the member function call is the call expression.
 */
void Myfirstchecker::checkPreStmt(const CallExpr *CE,
                                  CheckerContext &C) const {
#if 0
  os << "\nVisiting Call Expression\n";
  CE->dump();
#endif

  return;
}

/* A call back on a call event. Not very useful for us */
void Myfirstchecker::checkPreCall(const CallEvent &Call,
				   CheckerContext &C) const {

#if 0
  os << "\nVisiting Call Event\n";
  Call.dump();
#endif
  return;

}

/* Visit AST nodes for method definitions : CXXMethodDecl is a misnomer
 * This visitor is not path sensitive
 */
void Myfirstchecker::checkASTDecl(const FunctionDecl *FD,
                                  AnalysisManager &Mgr,
                                  BugReporter &BR) const {

  /* Do the following things:
   * 1. Check if fdecl is a ctor of a cxx object. If yes:
   *	 a. Check if ctor has member fields. If yes:
   *	 	i. Update state map with initialization
   *	 		status of member fields
   */

  const CXXConstructorDecl *CtorDecl = dyn_cast<CXXConstructorDecl>(FD);

  if(!CtorDecl)
    return;

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
      updateStateMapInternal(FD, (const bool)true);
  }

  return;
}

/* Visit record declarations to create an initial map
 * of the initialization state of record fields
 */
void Myfirstchecker::checkASTDecl(const RecordDecl *RD,
                                  AnalysisManager &Mgr,
                                  BugReporter &BR) const {

  /* We visit RecordDecl in addtion to CXXCtordecl because
   * the former visits records within records.
   * This takes care of visiting nested records
   */
  const CXXRecordDecl *ObjDecl = dyn_cast<CXXRecordDecl>(RD);

  /* Return if not a CXX object declaration */
  if(!ObjDecl)
    return;

  /* Return if CXX object has no definition */
  if(!ObjDecl->hasDefinition())
    return;

  /* Iterate over member fields of CXX object */
  RecordDecl::field_iterator fib = ObjDecl->field_begin();
  RecordDecl::field_iterator fie = ObjDecl->field_end();

  /* Return if CXX object has no member fields */
  if(fib == fie)
    return;

//  printFieldsInRecord(fib, fie);
  updateStateMap(fib, fie);

  return;
}

/* Utility function for debugging purposes */
void Myfirstchecker::printFieldsInRecord(RecordDecl::field_iterator start,
                                   RecordDecl::field_iterator end) const {

  /* Iterate over and print member fields of CXX object */
  for( ;start != end; start++) {
      FieldDecl *FDecl = *start;
      os << FDecl->getDeclName().getAsString()
	  << " has in-class initializer?\t"
	  << (FDecl->hasInClassInitializer() ? "yes" : "no")
	  << "\n";
  }
  return;
}

/* Function to iterate over member fields of an object
 * creating an internal representation of their initialization
 * state.
 */
void Myfirstchecker::updateStateMap(RecordDecl::field_iterator start,
                                   RecordDecl::field_iterator end) const {

  /* Iterate over and map member fields of CXX object to internal
   * state map */
  for( ;start != end; start++) {
      const FieldDecl *FDecl = *start;
      const bool isFieldInit = (const bool)FDecl->hasInClassInitializer();
      updateStateMapInternal(FDecl, isFieldInit);
  }
  return;
}

/* Utility function used by updateStateMap */
void Myfirstchecker::updateStateMapInternal(const FieldDecl *FDecl,
                                    const bool value) const {
      InitializationStateMap[FDecl] = value;
}

/* EOF visitor. Spits out the state of the internal map
 * at the end of analysis
 */
void Myfirstchecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
				   AnalysisManager &Mgr,
				   BugReporter &BR) const {

//  printStateMap();
  /* Iterate over state map and report error
   * on first uninitialized field member
   */
  for(InitializationStateMapTy::iterator it=InitializationStateMap.begin();
      it!=InitializationStateMap.end(); ++it){
      // Check if fielddecl is uninitialized
      if(!it->second){
	  // FDecl is uninitialized
	  const FieldDecl *FDecl = it->first;
	  PathDiagnosticLocation PDL =
	      PathDiagnosticLocation::create(FDecl,
	                                     Mgr.getSourceManager());

	  StringRef Message = "Object member is uninitialized in Ctor";
	  StringRef Name = "Uninitialized field";
	  StringRef Category = " Custom Security ";
	  SourceRange Sr = FDecl->getSourceRange();

	  BR.EmitBasicReport(FDecl, this, Name, Category,
	                     Message, PDL, Sr);

	  continue;
      }
  }

  return;
}



void Myfirstchecker::printStateMap() const {
  os << "Printing state map\n";
  for(InitializationStateMapTy::iterator
      it = InitializationStateMap.begin();
      it != InitializationStateMap.end(); ++it)
   {
    os << it->first->getDeclName().getAsString()
	   << ": "
	   << (*it).second
	   << "\n";
   }
  return;
}

// Register plugin!
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<Myfirstchecker>("alpha.security.myfirstchecker", "My first checker");
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
