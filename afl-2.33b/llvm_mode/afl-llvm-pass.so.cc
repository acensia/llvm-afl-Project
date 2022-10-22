/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/raw_ostream.h"

#define TW 
#define PRE_AFL
//#define debug 0

using namespace llvm;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      const char *getPassName() const override {
        return "American Fuzzy Lop Instrumentation";
      }

  };

}


char AFLCoverage::ID = 0;


/*  Wrong
#ifdef TW
void branch_mod (BranchInst *BR, bool swt){
  Instruction *cond = cast<Instruction>(BR->getCondition());
  ConstantInt *strong_c = cast<ConstantInt>(cond->getOperand(1));
  unsigned int s_c = strong_c->getZExtValue();
  ConstantInt *ff = ConstantInt::get(strong_c->getType(), 0xff);
  IRBuilder<> builder(BR);
  if (swt) {
    s_c = s_c & 0xff;
    strong_c = ConstantInt::get(strong_c->getType(), s_c);
    Value *andInst = builder.CreateAnd(cond->getOperand(0), ff);
    Value *eqInst = builder.CreateICmpEQ(andInst, cast<Value>(strong_c));
    BR->setCondition(eqInst);
  }
  else {
    s_c = s_c >> 8;
    strong_c = ConstantInt::get(strong_c->getType(), s_c);
    Value *lshrInst = builder.CreateLShr(cond->getOperand(0), 8);
    Value *eqInst = builder.CreateICmpEQ(lshrInst, (strong_c));
    BR->setCondition(eqInst);
  }
}
#endif
*/

bool AFLCoverage::runOnModule(Module &M) {



  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)

  {

    errs()<<"Starting Function----------------------------------------\n\n"<<F;

#ifdef TW
#ifdef PRE_AFL
    for(auto &BB : F)
      for (auto &I : BB) {
	if (auto icmp = dyn_cast<ICmpInst>(&I)) {
	  if (!icmp->isEquality()) continue;
	  if (!isa<ConstantInt>(I.getOperand(1))) continue;	
	  ConstantInt *num = cast<ConstantInt>(I.getOperand(1));
	  unsigned int bits = num->getZExtValue();
	  if (bits < 0x100) continue;
	  Value *target = I.getOperand(0);
	  int byte = target->getType()->getIntegerBitWidth() / 8;
	  BranchInst *old_br = cast<BranchInst>(I.getNextNode());

	  BasicBlock *BB_true = old_br->getSuccessor(0);
	  BasicBlock *BB_false = old_br->getSuccessor(1);

	  BranchInst *old_it = old_br;
	  if (byte > 1) {
	    IRBuilder<> build(old_it);
	    Value *bit = build.CreateTrunc(target, Type::getInt8Ty(C));
	    ConstantInt *seg = ConstantInt::get(Type::getInt8Ty(C), (bits & 0xff));
	    Value *new_icmp = build.CreateICmpEQ(bit, seg);
	    old_br->setCondition(new_icmp);
	  }

	  for (int i=1; i < byte ; ++i) {
	    BasicBlock *new_BB = BasicBlock::Create(C, "Split", &F);
	    BranchInst *new_br = BranchInst::Create(BB_true, BB_false, &I, new_BB);
	    
	    IRBuilder<> build(new_br);
	    ConstantInt *shf = ConstantInt::get(Type::getInt8Ty(C), i*8);
	    Value *sh = build.CreateLShr(target, shf);
	    Value *bit = build.CreateTrunc(sh, Type::getInt8Ty(C));
	    unsigned int bit_seg = bits >> i*8;
	    ConstantInt *seg = ConstantInt::get(Type::getInt8Ty(C), (bit_seg & 0xff));
	    Value *new_icmp = build.CreateICmpEQ(bit, seg);
	    new_br->setCondition(new_icmp);

	    old_it->setSuccessor(0, new_BB);
	    old_it = new_br;

	  }
	}
      }
    errs() << "Modified Func------------------------------\n"<<F;
#endif
#endif

    for (auto &BB : F) {

#ifdef TW
#ifndef PRE_AFL
      for (auto &I : BB) {
	if (auto icmp = dyn_cast<ICmpInst>(&I)) {
	  if (!icmp->isEquality()) continue;
	  if (!isa<ConstantInt>(I.getOperand(1))) continue;	
	  ConstantInt *num = cast<ConstantInt>(I.getOperand(1));
	  unsigned int bits = num->getZExtValue();
//	  if (bits < 0x100) continue;
	  Value *target = I.getOperand(0);
	  int bite = target->getType()->getIntegerBitWidth() / 4;
	  BranchInst *old_br = cast<BranchInst>(I.getNextNode());

	  BasicBlock *BB_true = old_br->getSuccessor(0);
	  BasicBlock *BB_false = old_br->getSuccessor(1);

	  BranchInst *old_it = old_br;
	  if (bite > 2) {
	    IRBuilder<> build(old_it);
	    Value *bit = build.CreateTrunc(target, Type::getInt8Ty(C), "name");
	    ConstantInt *seg = ConstantInt::get(Type::getInt8Ty(C), (bits & 0xff));
	    Value *new_icmp = build.CreateICmpEQ(bit, seg);
	    old_br->setCondition(new_icmp);
	  }

	  while (bite > 2) {
	    IRBuilder<> build(old_it);
	    ConstantInt *shf = ConstantInt::get(Type::getInt8Ty(C), (bite-2)*4);
	    Value *sh = build.CreateLShr(target, shf);
	    Value *bit = build.CreateTrunc(sh, Type::getInt8Ty(C), "name");
	    unsigned int bit_seg = bits >> (bite-2)*4;
	    ConstantInt *seg = ConstantInt::get(Type::getInt8Ty(C), (bit_seg & 0xff));
	    Value *new_icmp = build.CreateICmpEQ(bit, seg);

	    BasicBlock *new_BB = BasicBlock::Create(C, "created", &F);
	    BranchInst *new_br = BranchInst::Create(BB_true, BB_false, new_icmp, new_BB);
	    old_it->setSuccessor(0, new_BB);
	    old_it = new_br;

	    bite -= 2;
	  }
	}
      }



/*
//  for (auto &F : M) {
    
//    for (auto &BB : F) {
      BranchInst *br;	
      bool split = false;
      for (auto &I : BB) {
	if (auto *icmp = dyn_cast<ICmpInst>(&I)) {
	  if (!icmp->isEquality()) continue;
	  if (!isa<ConstantInt>(icmp->getOperand(1))) continue;
	  if (cast<ConstantInt>(icmp->getOperand(1))->getZExtValue() < 0x100) continue;
	  br = cast<BranchInst>(icmp->getNextNode());
	  (&BB)->splitBasicBlock(br);
	  split = true;
	  break;    
	} 
      }
      if (split) {
	Instruction *o_br = (&BB)->getTerminator();
	Value *o_cond = br->getCondition();
	BranchInst *n_br = BranchInst::Create(br->getParent(), (br)->getSuccessor(1), o_cond, &BB);
	o_br->eraseFromParent();
	branch_mod(n_br, true);
	branch_mod(br, false);
      }
//    }
rs()<<"For here !! ------------------------------------------------\n"<<F;
//  }
*/  //Wrong
#endif
#endif

//      errs()<<"Modified BB------------------------------------\n"<<BB;

#ifndef debug

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      unsigned int cur_loc = R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;

#endif
    }


  }   //for made gwal ho


  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
             inst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);


