#ifndef MELANGE_PHPTAINT_CHECKER_H
#define MELANGE_PHPTAINT_CHECKER_H

#include "clang/Basic/Builtins.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "Diagnostics.h"

#ifdef _DEBUG
#define DEBUG_PRINT(x) llvm::errs() << x << "\n"
#else
#define DEBUG_PRINT(x)
#endif

static const unsigned InvalidArgIndex = UINT_MAX;
static const unsigned ReturnValueIndex	= UINT_MAX-1;

namespace Melange {

  class Diagnostics;

class PHPTaintChecker : public clang::ento::Checker<clang::ento::check::PreStmt<clang::CallExpr>,
						    clang::ento::check::PostStmt<clang::CallExpr>> {

  mutable Diagnostics Diag;

public:
  void checkPreStmt(const clang::CallExpr *Call, clang::ento::CheckerContext &C) const;
  void checkPostStmt(const clang::CallExpr *Call, clang::ento::CheckerContext &C) const;

  static void *getTag() { static int Tag; return &Tag; }

private:
  mutable std::unique_ptr<clang::ento::BugType> BT;
  void reportBug(clang::ento::CheckerContext &C, clang::SourceRange SR,
                 llvm::StringRef Message, llvm::StringRef declName) const;

  inline void initBugType() const {
    if (!BT)
      BT.reset(new clang::ento::BugType(this, "Use of Tainted Data", "Tainted Data"));
  }

  /// \brief Catch taint related bugs. Check if tainted data is passed to a
  /// system call etc.
  bool checkPre(const clang::CallExpr *CE, clang::ento::CheckerContext &C) const;

  /// \brief Add taint sources on a pre-visit.
  void addSourcesPre(const clang::CallExpr *CE, clang::ento::CheckerContext &C) const;

  /// \brief Propagate taint generated at pre-visit.
  bool propagateFromPre(const clang::CallExpr *CE, clang::ento::CheckerContext &C) const;

  /// \brief Add taint sources on a post visit.
  void addSourcesPost(const clang::CallExpr *CE, clang::ento::CheckerContext &C) const;

  /// \brief Given a pointer argument, get the symbol of the value it contains
  /// (points to).
  static clang::ento::SymbolRef getPointedToSymbol(clang::ento::CheckerContext &C,
                                                   const clang::Expr *Arg);

  /// Functions defining the attack surface.
  typedef clang::ento::ProgramStateRef (PHPTaintChecker::*FnCheck)(const clang::CallExpr *,
                                                       clang::ento::CheckerContext &C) const;
  clang::ento::ProgramStateRef postRetTaint(const clang::CallExpr *CE,
                                            clang::ento::CheckerContext &C) const;

  clang::ento::ProgramStateRef prePHPTaintSources(const clang::CallExpr *CE,
                                                  clang::ento::CheckerContext &C) const;

  bool checkPHPSinks(const clang::CallExpr *CE, llvm::StringRef Name,
                     clang::ento::CheckerContext &C) const;

  /// Generate a report if the expression is tainted or points to tainted data.
  bool generateReportIfTainted(const clang::Expr *E, const char Msg[],
                               clang::ento::CheckerContext &C) const;


  typedef llvm::SmallVector<unsigned, 2> ArgVector;

  /// \brief A struct used to specify taint propagation rules for a function.
  ///
  /// If any of the possible taint source arguments is tainted, all of the
  /// destination arguments should also be tainted. Use InvalidArgIndex in the
  /// src list to specify that all of the arguments can introduce taint. Use
  /// InvalidArgIndex in the dst arguments to signify that all the non-const
  /// pointer and reference arguments might be tainted on return. If
  /// ReturnValueIndex is added to the dst list, the return value will be
  /// tainted.
  struct TaintPropagationRule {
    /// List of arguments which can be taint sources and should be checked.
    ArgVector SrcArgs;
    /// List of arguments which should be tainted on function return.
    ArgVector DstArgs;
    // TODO: Check if using other data structures would be more optimal.

    TaintPropagationRule() {}

    TaintPropagationRule(unsigned SArg,
                         unsigned DArg, bool TaintRet = false) {
      SrcArgs.push_back(SArg);
      DstArgs.push_back(DArg);
      if (TaintRet)
        DstArgs.push_back(ReturnValueIndex);
    }

    TaintPropagationRule(unsigned SArg1, unsigned SArg2,
                         unsigned DArg, bool TaintRet = false) {
      SrcArgs.push_back(SArg1);
      SrcArgs.push_back(SArg2);
      DstArgs.push_back(DArg);
      if (TaintRet)
        DstArgs.push_back(ReturnValueIndex);
    }

    /// Get the propagation rule for a given function.
    static TaintPropagationRule
      getTaintPropagationRule(llvm::StringRef Name,
                              clang::ento::CheckerContext &C);

    inline void addSrcArg(unsigned A) { SrcArgs.push_back(A); }
    inline void addDstArg(unsigned A)  { DstArgs.push_back(A); }

    inline bool isNull() const { return SrcArgs.empty(); }

    inline bool isDestinationArgument(unsigned ArgNum) const {
      return (std::find(DstArgs.begin(),
                        DstArgs.end(), ArgNum) != DstArgs.end());
    }

    static inline bool isTaintedOrPointsToTainted(const clang::Expr *E,
                                                  clang::ento::ProgramStateRef State,
                                                  clang::ento::CheckerContext &C) {
      return (State->isTainted(E, C.getLocationContext()) ||
              (E->getType().getTypePtr()->isPointerType() &&
               State->isTainted(getPointedToSymbol(C, E))));
    }

    /// \brief Pre-process a function which propagates taint according to the
    /// taint rule.
    clang::ento::ProgramStateRef process(const clang::CallExpr *CE,
                                         clang::ento::CheckerContext &C) const;

  };
};

} // end of Melange namespace

#endif
