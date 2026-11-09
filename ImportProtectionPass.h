#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct ImportProtectionPass : llvm::PassInfoMixin<ImportProtectionPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunImportProtection(llvm::Module& m);

extern llvm::cl::opt<bool> ImportProtectionEnable;