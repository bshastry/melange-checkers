#include "Diagnostics.h"
#include "clang/AST/Mangle.h"
#include "clang/AST/DeclCXX.h"

using Melange::Diagnostics;
using namespace clang;
using namespace clang::ento;

void Diagnostics::storeDiagnostics(const Decl *D, SourceLocation SL) {
  DiagnosticsInfoTy::iterator I = DiagnosticsInfo.find(D);
  if (I != DiagnosticsInfo.end())
    return;

  typedef std::pair<const Decl *, DiagPairTy> KVPair;
  I = DiagnosticsInfo.insert(KVPair(D, DiagPairTy(EncodedBugInfo, SL))).first;
  assert(I != DiagnosticsInfo.end());
  return;
}

void Diagnostics::encodeBugInfo(std::string Node, CheckerContext &C) {
  EncodedBugInfo.clear();

  EncodedBugInfo.push_back(Node);
  // Call stack is written to EncodedBugInfo
  dumpCallsOnStack(C);
}

Diagnostics::ETLTy &Diagnostics::getBugInfoDiag() {
  return EncodedBugInfo;
}

void Diagnostics::dumpCallsOnStack(CheckerContext &C) {
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

std::string Diagnostics::getADCQualifiedNameAsStringRef(const LocationContext *LC) {

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

std::string Diagnostics::getMangledNameAsString(const NamedDecl *ND,
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
