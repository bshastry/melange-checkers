#ifndef MELANGE_USEDEFCHECKER_H
#define MELANGE_USEDEFCHECKER_H

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DenseMap.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/FunctionSummary.h"

namespace Melange {

class UseDefChecker : public clang::ento::Checker< clang::ento::check::EndFunction,
				      clang::ento::check::BranchCondition,
				      clang::ento::check::PreStmt<clang::BinaryOperator>,
				      clang::ento::check::EndOfTranslationUnit> {

  typedef llvm::DenseSet<const clang::CXXRecordDecl *>					CtorsVisitedTy;
  typedef llvm::DenseSet<const clang::Decl *>						CtorsDeclSetTy;
  typedef clang::ento::BugReport::ExtraTextList						ETLTy;
  typedef ETLTy::const_iterator		 						EBIIteratorTy;
  typedef std::pair<ETLTy, clang::SourceLocation>					DiagPairTy;
  typedef llvm::DenseMap<const clang::Decl *, DiagPairTy>				DiagnosticsInfoTy;
  typedef const clang::ento::FunctionSummariesTy::MapTy					FSMapTy;
  typedef const clang::ento::FunctionSummariesTy::FunctionSummary::TLDTaintMapTy	TLDTMTy;
  typedef const clang::ento::FunctionSummariesTy::FunctionSummary::DTPair	 	DTPairTy;

  mutable std::unique_ptr<clang::ento::BugType> BT;
  enum SetKind { Ctor, Context };

  mutable CtorsVisitedTy 	 	ctorsVisited;
  mutable ETLTy 			EncodedBugInfo;
  mutable DiagnosticsInfoTy		DiagnosticsInfo;

public:
  void checkPreStmt(const clang::BinaryOperator *BO, clang::ento::CheckerContext &C) const;
  void checkEndFunction(clang::ento::CheckerContext &C) const;
  void checkBranchCondition(const clang::Stmt *Condition, clang::ento::CheckerContext &Ctx) const;
  void checkEndOfTranslationUnit(const clang::TranslationUnitDecl *TU, clang::ento::AnalysisManager &Mgr,
                                  clang::ento::BugReporter &BR) const;

private:
  void addNDToTaintSet(const clang::NamedDecl *ND, clang::ento::CheckerContext &C) const;
  bool isTaintedInContext(const clang::NamedDecl *ND, clang::ento::CheckerContext &C) const;
  void reportBug(clang::ento::AnalysisManager &Mgr, clang::ento::BugReporter &BR, const clang::Decl *D) const;
  void checkUnaryOp(const clang::UnaryOperator *UO, clang::ento::CheckerContext &C) const;
  void checkBinaryOp(const clang::BinaryOperator *BO, clang::ento::CheckerContext &C) const;
  void checkUseIfMemberExpr(const clang::Expr *E, clang::ento::CheckerContext &C) const;
  void trackMembersInAssign(const clang::BinaryOperator *BO, clang::ento::CheckerContext &C) const;
  void branchStmtChecker(const clang::Stmt *Condition, clang::ento::CheckerContext &C) const;
  void encodeBugInfo(const clang::MemberExpr *ME, clang::ento::CheckerContext &C) const;
  void dumpCallsOnStack(clang::ento::CheckerContext &C) const;
  void storeDiagnostics(const clang::Decl *D, clang::SourceLocation SL) const;
  void taintCtorInits(const clang::CXXConstructorDecl *CCD, clang::ento::CheckerContext &C) const;

  // Static utility functions
  static bool isCXXFieldDecl(const clang::Expr *E);
  static std::string getADCQualifiedNameAsStringRef(const clang::LocationContext *LC);
  static std::string getMangledNameAsString(const clang::NamedDecl *ND, clang::ASTContext &ASTC);
};
} // end of Melange namespace

#endif // MELANGE_USEDEFCHECKER_H
