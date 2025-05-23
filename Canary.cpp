#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;

struct CanaryPass : public PassInfoMixin<CanaryPass>
{
    static Function *createStackChkFunc(Module &M, GlobalVariable *canary_const)
    {
        LLVMContext &Context = M.getContext();

        // Create stack check function
        Type *Int32Ty = Type::getInt32Ty(Context);
        std::vector<Type *> Args = {Int32Ty};
        FunctionType *stack_chk_type = FunctionType::get(Type::getVoidTy(Context), Args, false);
        Function *stack_chk_func = Function::Create(
            stack_chk_type,              // function type
            Function::ExternalLinkage, // linkage type
            "stack_check",             // function name
            M                          // module to insert into
        );
        for (auto &Arg : stack_chk_func->args())
            Arg.setName("exit_canary");

        // Compare global canary with given
        IRBuilder<> Builder(Context);
        BasicBlock *entry_bb = BasicBlock::Create(Context, "entry", stack_chk_func);
        BasicBlock *fail_bb = BasicBlock::Create(Context, "chk_fail", stack_chk_func);
        BasicBlock *success_bb = BasicBlock::Create(Context, "chk_success", stack_chk_func);

        Builder.SetInsertPoint(entry_bb, entry_bb->begin()); // insert *before* the return
        Argument *exit_canary = stack_chk_func->getArg(0);
        Value *canary_val = Builder.CreateLoad(Type::getInt32Ty(Context), canary_const, "canary_val");
        Value *is_equal = Builder.CreateICmpEQ(canary_val, exit_canary, "stack_check");
        Builder.CreateCondBr(is_equal, success_bb, fail_bb);

        // Equal(correct) branch
        Builder.SetInsertPoint(success_bb, success_bb->begin()); // insert *before* the return
        Builder.CreateRetVoid();

        // Unequal(incorrect) Branch
        Builder.SetInsertPoint(fail_bb, fail_bb->begin());
        // Generate SIGABRT
        FunctionCallee AbortFunc = M.getOrInsertFunction(
            "abort",
            FunctionType::get(Type::getVoidTy(Context), false));
        Builder.CreateCall(AbortFunc);
        Builder.CreateUnreachable();

        if (llvm::verifyFunction(*stack_chk_func, &llvm::errs()))
        {
            llvm::errs() << "Function verification failed!\n";
            // Handle error
        }
        return stack_chk_func;
    }

    // Creates global canary and initializes with rand()
    static GlobalVariable *createCanaryConstructor(Module &M)
    {
        LLVMContext &Context = M.getContext();
        FunctionType *canary_init = FunctionType::get(Type::getVoidTy(Context), false);
        Function *canary_init_func = Function::Create(canary_init, Function::InternalLinkage, "canary_init", M);

        // Create canary
        GlobalVariable *canary_global = new GlobalVariable(
            M,                                // Module where it will be inserted
            Type::getInt32Ty(M.getContext()), // Type of the global (e.g., int32)
            false,                            // isConstant (false = mutable)
            GlobalValue::PrivateLinkage,      // Linkage
            ConstantInt::get(Type::getInt32Ty(M.getContext()), 0),
            "canary" // Name
        );

        // Insert srand(), time() and rand() definition for linking
        FunctionCallee external_rand_func = M.getOrInsertFunction("rand", FunctionType::get(Type::getInt32Ty(Context), {}));
        FunctionCallee external_srand_func = M.getOrInsertFunction("srand", FunctionType::get(Type::getVoidTy(Context), {Type::getInt32Ty(Context)}, false));
        FunctionCallee external_time_func = M.getOrInsertFunction("time", FunctionType::get(Type::getInt32Ty(Context), {PointerType::get(Context, 0)}, false));

        IRBuilder<> Builder(Context);
        BasicBlock *entry_bb = BasicBlock::Create(Context, "entry", canary_init_func);
        Builder.SetInsertPoint(entry_bb, entry_bb->begin());

        // Call srand(time(NULL))
        std::vector<Value *> args = {ConstantPointerNull::get(PointerType::get(Type::getInt32Ty(Context), 0))};
        CallInst *time_val = Builder.CreateCall(external_time_func, args);
        args = {time_val};
        Builder.CreateCall(external_srand_func, args);

        // Call rand(), bind result to 0-100 and store to canary
        CallInst *rand_val = Builder.CreateCall(external_rand_func);
        Value *mod_value = ConstantInt::get(Type::getInt32Ty(M.getContext()), 101);
        Value *mod_result = Builder.CreateSRem(rand_val, mod_value, "mod101");
        Builder.CreateStore(mod_result, canary_global);
        Builder.CreateRetVoid();

        if (llvm::verifyFunction(*canary_init_func, &llvm::errs()))
        {
            llvm::errs() << "Function verification failed!\n";
            // Handle error
        }
        return canary_global;
    }

    PreservedAnalyses
    run(Module &M, ModuleAnalysisManager &)
    {
        LLVMContext &Context = M.getContext();

        GlobalVariable *canary_global = createCanaryConstructor(M);
        Function *stack_chk_func = createStackChkFunc(M, canary_global);

        IRBuilder<> Builder(Context);
        for (Function &F : M.getFunctionList())
        {
            // Skip external and my defined functions
            if (F.isDeclaration() || F.getName() == "stack_check" || F.getName() == "canary_init")
                continue;

            BasicBlock &entry_bb = F.getEntryBlock();
            Builder.SetInsertPoint(&*entry_bb.begin());

            // Store canary value in stack at function beginning
            AllocaInst *stack_canary = Builder.CreateAlloca(Type::getInt32Ty(Context), nullptr, "canary");
            Value *canary_val = Builder.CreateLoad(Type::getInt32Ty(Context), canary_global, "canary_val");
            Builder.CreateStore(canary_val, stack_canary);

            // Find exit block and check canary
            for (BasicBlock &BB : F)
            {
                // If last instruction of block is a ret then it is the exit block
                if (isa<ReturnInst>(BB.getTerminator()))
                {
                    // Insert canary check just before ret
                    Instruction *Ret = BB.getTerminator();
                    Builder.SetInsertPoint(Ret);
                    Value *exit_canary_val = Builder.CreateLoad(Type::getInt32Ty(Context), stack_canary, "exit_canary_val");
                    std::vector<Value *> args = {exit_canary_val};
                    Builder.CreateCall(stack_chk_func, args);
                }
            }

            // In main insert canary_init call before canary prologue
            if (F.getName() == "main")
            {
                FunctionCallee canary_init = M.getOrInsertFunction("canary_init", FunctionType::get(Type::getVoidTy(Context), false));
                BasicBlock &entry_bb = F.getEntryBlock();
                Builder.SetInsertPoint(&*entry_bb.begin());
                Builder.CreateCall(canary_init);
            }
        }
        if (llvm::verifyModule(M, &llvm::errs()))
            llvm::errs() << "Module verification failed!\n";

        return PreservedAnalyses::all();
    }
};

// Register pass with new pass manager
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "CanaryPass", LLVM_VERSION_STRING,
        [](PassBuilder &PB)
        {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>)
                {
                    if (Name == "canary")
                    {
                        MPM.addPass(CanaryPass());
                        return true;
                    }
                    return false;
                });
        }};
}