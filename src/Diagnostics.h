#ifndef MELANGE_DIAGNOSTICS_H
#define MELANGE_DIAGNOSTICS_H

#include "clang/AST/ASTContext.h"
#include "clang/Analysis/AnalysisContext.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

namespace Melange {

class Diagnostics {

  typedef clang::ento::BugReport::ExtraTextList						ETLTy;
  typedef ETLTy::const_iterator		 						EBIIteratorTy;
  typedef std::pair<ETLTy, clang::SourceLocation>					DiagPairTy;
  typedef llvm::DenseMap<const clang::Decl *, DiagPairTy>				DiagnosticsInfoTy;


  ETLTy 			EncodedBugInfo;
  DiagnosticsInfoTy		DiagnosticsInfo;

public:
  void encodeBugInfo(std::string Node, clang::ento::CheckerContext &C);
  void storeDiagnostics(const clang::Decl *D, clang::SourceLocation SL);
  void dumpCallsOnStack(clang::ento::CheckerContext &C);
  ETLTy &getBugInfoDiag();

  // utility
  static std::string getADCQualifiedNameAsStringRef(const clang::LocationContext *LC);
  static std::string getMangledNameAsString(const clang::NamedDecl *ND, clang::ASTContext &ASTC);
};

} // end of Melange namespace
#endif
