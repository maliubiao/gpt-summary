Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is a part of the V8 JavaScript engine, specifically the code generator for the PowerPC (PPC) architecture.

Here's a plan to generate the response:

1. **Identify the main purpose:** The code is responsible for generating machine code for PPC based on higher-level intermediate representation.
2. **Break down the functionalities:** Analyze the functions and their roles, focusing on actions like assembling instructions, handling tail calls, managing the stack frame, and dealing with specific PPC instructions.
3. **Address specific user questions:** Go through each of the user's requests and see if the provided code snippet relates to them.
4. **Synthesize the summary:** Combine the identified functionalities into a concise summary, keeping in mind that this is part 2 of a 5-part series.
这段代码是 `v8/src/compiler/backend/ppc/code-generator-ppc.cc` 文件的一部分，主要负责以下功能：

1. **尾调用（Tail Call）优化相关的汇编生成:**
   - `AssemblePrepareTailCall()`:  准备进行尾调用。如果当前存在帧，则恢复调用前的帧状态。将帧访问状态设置为基于栈指针（SP）。
   - `FlushPendingPushRegisters()`:  将待压栈的寄存器刷新到栈上。这个函数用于优化连续压栈操作。
   - `AdjustStackPointerForTailCall()`:  调整栈指针，为尾调用准备合适的栈布局。可以增加或减少栈的大小。
   - `AssembleTailCallBeforeGap()`:  在尾调用之前的“间隙”中进行汇编操作，例如将参数推入栈中。它会检查是否有可以合并的 `push` 操作来优化栈空间。
   - `AssembleTailCallAfterGap()`:  在尾调用之后的“间隙”中进行汇编操作，主要用于调整栈指针。

2. **代码起始寄存器检查:**
   - `AssembleCodeStartRegisterCheck()`:  检查 `kJavaScriptCallCodeStartRegister` 寄存器中的值是否正确，确保函数调用目标的正确性。

3. **处理反优化（Deoptimization）:**
   - `BailoutIfDeoptimized()`:  如果发生反优化，则跳转到相应的处理代码。

4. **架构相关的指令汇编:**
   - `AssembleArchInstruction(Instruction* instr)`:  根据给定的 `Instruction` 对象，生成对应的 PPC 汇编代码。这是一个大的 `switch` 语句，处理各种架构相关的操作码（opcode）。

**针对用户提出的问题：**

* **`.tq` 结尾：**  代码以 `.cc` 结尾，因此不是 Torque 源代码。
* **与 JavaScript 功能的关系：**  这段代码直接参与了将 JavaScript 代码编译成机器码的过程，因此与 JavaScript 功能关系密切。

**JavaScript 示例：**

尾调用优化在 JavaScript 中并不常见，因为 JavaScript 引擎会自动处理栈溢出的情况。但是，在严格模式下，符合特定条件的函数调用可以被优化为尾调用。

```javascript
"use strict";

function a(n) {
  if (n <= 0) {
    return "done";
  }
  return b(n - 1); // 尾调用，函数 a 的最后一步是调用函数 b
}

function b(n) {
  return a(n); // 尾调用
}

console.log(a(5));
```

在这个例子中，函数 `a` 和 `b` 互相调用，并且最后的操作是函数调用自身或另一个函数。在支持尾调用优化的 JavaScript 引擎中，这种情况下不会产生新的栈帧，从而避免栈溢出。`AssemblePrepareTailCall` 等函数就是在编译这种尾调用时发挥作用的。

**代码逻辑推理（假设输入与输出）：**

假设 `AssembleTailCallBeforeGap` 函数接收到一个 `Instruction` 对象，该对象表示一个函数调用，并且需要将一些寄存器中的参数压入栈中。

**假设输入：**

* `instr`: 一个表示函数调用的 `Instruction` 对象，其中包含需要压栈的源操作数信息（例如，寄存器 `r3` 和 `r4`）。
* `first_unused_slot_offset`:  表示栈上第一个未使用槽位的偏移量。

**预期输出：**

函数会生成相应的汇编代码，将寄存器 `r3` 和 `r4` 的值压入栈中，并更新 `frame_access_state` 以反映栈的变化。例如，可能会生成以下汇编指令：

```assembly
push r3
push r4
```

同时，`frame_access_state` 的栈指针偏移量会增加 2（假设每个寄存器占用一个栈槽）。

**用户常见的编程错误（与此代码相关性较低，更侧重于编译器内部）：**

这段代码是编译器的一部分，与直接的用户编程错误关联性不高。常见的编程错误可能发生在编写编译器优化或底层代码生成逻辑时，例如：

* **栈指针管理错误:**  错误地计算或更新栈指针可能导致程序崩溃或数据损坏。例如，在 `AdjustStackPointerForTailCall` 中，如果 `stack_slot_delta` 计算错误，可能会导致栈溢出或访问无效内存。
* **寄存器使用冲突:**  错误地假设某个寄存器是空闲的，导致数据被覆盖。编译器需要进行寄存器分配来避免这种情况。
* **指令编码错误:**  生成了错误的机器码指令，导致程序行为异常。

**功能归纳（第 2 部分）：**

这部分代码主要负责 **为 PowerPC 架构生成与函数调用（特别是尾调用）相关的汇编代码，并进行必要的栈帧管理和代码起始地址校验。**  它处理了尾调用前的参数压栈、栈指针调整，以及确保函数调用目标的正确性。 这部分是代码生成器中处理函数调用逻辑的关键组成部分。

### 提示词
```
这是目录为v8/src/compiler/backend/ppc/code-generator-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ppc/code-generator-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ed(__ pc_offset());
}

void CodeGenerator::AssemblePrepareTailCall() {
  if (frame_access_state()->has_frame()) {
    __ RestoreFrameStateForTailCall();
  }
  frame_access_state()->SetFrameAccessToSP();
}

namespace {

void FlushPendingPushRegisters(MacroAssembler* masm,
                               FrameAccessState* frame_access_state,
                               ZoneVector<Register>* pending_pushes) {
  switch (pending_pushes->size()) {
    case 0:
      break;
    case 1:
      masm->Push((*pending_pushes)[0]);
      break;
    case 2:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1]);
      break;
    case 3:
      masm->Push((*pending_pushes)[0], (*pending_pushes)[1],
                 (*pending_pushes)[2]);
      break;
    default:
      UNREACHABLE();
  }
  frame_access_state->IncreaseSPDelta(pending_pushes->size());
  pending_pushes->clear();
}

void AdjustStackPointerForTailCall(
    MacroAssembler* masm, FrameAccessState* state, int new_slot_above_sp,
    ZoneVector<Register>* pending_pushes = nullptr,
    bool allow_shrinkage = true) {
  int current_sp_offset = state->GetSPToFPSlotCount() +
                          StandardFrameConstants::kFixedSlotCountAboveFp;
  int stack_slot_delta = new_slot_above_sp - current_sp_offset;
  if (stack_slot_delta > 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AddS64(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize), r0);
    state->IncreaseSPDelta(stack_slot_delta);
  } else if (allow_shrinkage && stack_slot_delta < 0) {
    if (pending_pushes != nullptr) {
      FlushPendingPushRegisters(masm, state, pending_pushes);
    }
    masm->AddS64(sp, sp, Operand(-stack_slot_delta * kSystemPointerSize), r0);
    state->IncreaseSPDelta(stack_slot_delta);
  }
}

}  // namespace

void CodeGenerator::AssembleTailCallBeforeGap(Instruction* instr,
                                              int first_unused_slot_offset) {
  ZoneVector<MoveOperands*> pushes(zone());
  GetPushCompatibleMoves(instr, kRegisterPush, &pushes);

  if (!pushes.empty() &&
      (LocationOperand::cast(pushes.back()->destination()).index() + 1 ==
       first_unused_slot_offset)) {
    PPCOperandConverter g(this, instr);
    ZoneVector<Register> pending_pushes(zone());
    for (auto move : pushes) {
      LocationOperand destination_location(
          LocationOperand::cast(move->destination()));
      InstructionOperand source(move->source());
      AdjustStackPointerForTailCall(
          masm(), frame_access_state(),
          destination_location.index() - pending_pushes.size(),
          &pending_pushes);
      // Pushes of non-register data types are not supported.
      DCHECK(source.IsRegister());
      LocationOperand source_location(LocationOperand::cast(source));
      pending_pushes.push_back(source_location.GetRegister());
      // TODO(arm): We can push more than 3 registers at once. Add support in
      // the macro-assembler for pushing a list of registers.
      if (pending_pushes.size() == 3) {
        FlushPendingPushRegisters(masm(), frame_access_state(),
                                  &pending_pushes);
      }
      move->Eliminate();
    }
    FlushPendingPushRegisters(masm(), frame_access_state(), &pending_pushes);
  }
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset, nullptr, false);
}

void CodeGenerator::AssembleTailCallAfterGap(Instruction* instr,
                                             int first_unused_slot_offset) {
  AdjustStackPointerForTailCall(masm(), frame_access_state(),
                                first_unused_slot_offset);
}

// Check that {kJavaScriptCallCodeStartRegister} is correct.
void CodeGenerator::AssembleCodeStartRegisterCheck() {
  Register scratch = kScratchReg;
  __ ComputeCodeStartAddress(scratch);
  __ CmpS64(scratch, kJavaScriptCallCodeStartRegister);
  __ Assert(eq, AbortReason::kWrongFunctionCodeStart);
}

void CodeGenerator::BailoutIfDeoptimized() { __ BailoutIfDeoptimized(); }

// Assembles an instruction after register allocation, producing machine code.
CodeGenerator::CodeGenResult CodeGenerator::AssembleArchInstruction(
    Instruction* instr) {
  PPCOperandConverter i(this, instr);
  ArchOpcode opcode = ArchOpcodeField::decode(instr->opcode());

  switch (opcode) {
    case kArchCallCodeObject: {
      v8::internal::Assembler::BlockTrampolinePoolScope block_trampoline_pool(
          masm());
      if (HasRegisterInput(instr, 0)) {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ CallCodeObject(reg);
      } else {
        __ Call(i.InputCode(0), RelocInfo::CODE_TARGET);
      }
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchCallBuiltinPointer: {
      DCHECK(!instr->InputAt(0)->IsImmediate());
      Register builtin_index = i.InputRegister(0);
      Register target =
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister)
              ? kJavaScriptCallCodeStartRegister
              : builtin_index;
      __ CallBuiltinByIndex(builtin_index, target);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction: {
      // We must not share code targets for calls to builtins for wasm code, as
      // they might need to be patched individually.
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Call(wasm_code, constant.rmode());
      } else {
        __ Call(i.InputRegister(0));
      }
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      // We must not share code targets for calls to builtins for wasm code, as
      // they might need to be patched individually.
      if (instr->InputAt(0)->IsImmediate()) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        __ Jump(wasm_code, constant.rmode());
      } else {
        __ Jump(i.InputRegister(0));
      }
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallCodeObject: {
      if (HasRegisterInput(instr, 0)) {
        Register reg = i.InputRegister(0);
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ JumpCodeObject(reg);
      } else {
        // We cannot use the constant pool to load the target since
        // we've already restored the caller's frame.
        ConstantPoolUnavailableScope constant_pool_unavailable(masm());
        __ Jump(i.InputCode(0), RelocInfo::CODE_TARGET);
      }
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallAddress: {
      CHECK(!instr->InputAt(0)->IsImmediate());
      Register reg = i.InputRegister(0);
      DCHECK_IMPLIES(
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
          reg == kJavaScriptCallCodeStartRegister);
      __ Jump(reg);
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      v8::internal::Assembler::BlockTrampolinePoolScope block_trampoline_pool(
          masm());
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        // Check the function's context matches the context argument.
        __ LoadTaggedField(
            kScratchReg, FieldMemOperand(func, JSFunction::kContextOffset), r0);
        __ CmpS64(cp, kScratchReg);
        __ Assert(eq, AbortReason::kWrongFunctionContext);
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments, kScratchReg);
      RecordCallPosition(instr);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters + num_fp_parameters,
                              kScratchReg);
      // Frame alignment requires using FP-relative frame addressing.
      frame_access_state()->SetFrameAccessToFP();
      break;
    }
    case kArchSaveCallerRegisters: {
      fp_mode_ =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // kReturnRegister0 should have been saved before entering the stub.
      int bytes = __ PushCallerSaved(fp_mode_, ip, r0, kReturnRegister0);
      DCHECK(IsAligned(bytes, kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      DCHECK(!caller_registers_saved_);
      caller_registers_saved_ = true;
      break;
    }
    case kArchRestoreCallerRegisters: {
      DCHECK(fp_mode_ ==
             static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode())));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // Don't overwrite the returned value.
      int bytes = __ PopCallerSaved(fp_mode_, ip, r0, kReturnRegister0);
      frame_access_state()->IncreaseSPDelta(-(bytes / kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      DCHECK(caller_registers_saved_);
      caller_registers_saved_ = false;
      break;
    }
    case kArchPrepareTailCall:
      AssemblePrepareTailCall();
      break;
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt64(0)),
                       SourceLocation());
      break;
    case kArchCallCFunctionWithFrameState:
    case kArchCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const fp_param_field = FPParamField::decode(instr->opcode());
      int num_fp_parameters = fp_param_field;
      bool has_function_descriptor = false;
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
#if ABI_USES_FUNCTION_DESCRIPTORS
      // AIX/PPC64BE Linux uses a function descriptor
      int kNumFPParametersMask = kHasFunctionDescriptorBitMask - 1;
      num_fp_parameters = kNumFPParametersMask & fp_param_field;
      has_function_descriptor =
          (fp_param_field & kHasFunctionDescriptorBitMask) != 0;
#endif
#if V8_ENABLE_WEBASSEMBLY
      Label start_call;
      int start_pc_offset = 0;
      bool isWasmCapiFunction =
          linkage()->GetIncomingDescriptor()->IsWasmCapiFunction();
      if (isWasmCapiFunction) {
        __ mflr(r0);
        __ LoadPC(kScratchReg);
        __ bind(&start_call);
        start_pc_offset = __ pc_offset();
        // We are going to patch this instruction after emitting
        // CallCFunction, using a zero offset here as placeholder for now.
        // patch_pc_address assumes `addi` is used here to
        // add the offset to pc.
        __ addi(kScratchReg, kScratchReg, Operand::Zero());
        __ StoreU64(kScratchReg,
                    MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
        __ mtlr(r0);
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (instr->InputAt(0)->IsImmediate()) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset =
            __ CallCFunction(ref, num_gp_parameters, num_fp_parameters,
                             set_isolate_data_slots, has_function_descriptor);
      } else {
        Register func = i.InputRegister(0);
        pc_offset =
            __ CallCFunction(func, num_gp_parameters, num_fp_parameters,
                             set_isolate_data_slots, has_function_descriptor);
      }
#if V8_ENABLE_WEBASSEMBLY
      if (isWasmCapiFunction) {
        int offset_since_start_call = pc_offset - start_pc_offset;
        // Here we are going to patch the `addi` instruction above to use the
        // correct offset.
        // LoadPC emits two instructions and pc is the address of its second
        // emitted instruction. Add one more to the offset to point to after the
        // Call.
        offset_since_start_call += kInstrSize;
        __ patch_pc_address(kScratchReg, start_pc_offset,
                            offset_since_start_call);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      RecordSafepoint(instr->reference_map(), pc_offset);

      bool const needs_frame_state =
          (opcode == kArchCallCFunctionWithFrameState);
      if (needs_frame_state) {
        RecordDeoptInfo(instr, pc_offset);
      }

      frame_access_state()->SetFrameAccessToDefault();
      // Ideally, we should decrement SP delta to match the change of stack
      // pointer in CallCFunction. However, for certain architectures (e.g.
      // ARM), there may be more strict alignment requirement, causing old SP
      // to be saved on the stack. In those cases, we can not calculate the SP
      // delta statically.
      frame_access_state()->ClearSPDelta();
      if (caller_registers_saved_) {
        // Need to re-sync SP delta introduced in kArchSaveCallerRegisters.
        // Here, we assume the sequence to be:
        //   kArchSaveCallerRegisters;
        //   kArchCallCFunction;
        //   kArchRestoreCallerRegisters;
        int bytes =
            __ RequiredStackSizeForCallerSaved(fp_mode_, kReturnRegister0);
        frame_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
      }
      break;
    }
    case kArchJmp:
      AssembleArchJump(i.InputRpo(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == r4);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ stop();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchNop:
    case kArchThrowTerminator:
      // don't emit code for nops.
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ b(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchFramePointer:
      __ mr(i.OutputRegister(), fp);
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ LoadU64(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mr(i.OutputRegister(), fp);
      }
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      __ mr(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer: {
      DCHECK(instr->InputAt(0)->IsRegister());
      __ mr(sp, i.InputRegister(0));
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchStackPointerGreaterThan: {
      // Potentially apply an offset to the current stack pointer before the
      // comparison to consider the size difference of an optimized frame versus
      // the contained unoptimized frames.

      Register lhs_register = sp;
      uint32_t offset;

      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = i.TempRegister(0);
        __ SubS64(lhs_register, sp, Operand(offset), kScratchReg);
      }

      constexpr size_t kValueIndex = 0;
      DCHECK(instr->InputAt(kValueIndex)->IsRegister());
      __ CmpU64(lhs_register, i.InputRegister(kValueIndex), cr0);
      break;
    }
    case kArchStackCheckOffset:
      __ LoadSmiLiteral(i.OutputRegister(),
                        Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kArchStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);
      OutOfLineRecordWrite* ool;

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ CmpS64(value, Operand(kClearedWeakHeapObjectLower32), kScratchReg);
        __ Check(ne, AbortReason::kOperandIsCleared);
      }

      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      if (addressing_mode == kMode_MRI) {
        int32_t offset = i.InputInt32(1);
        ool = zone()->New<OutOfLineRecordWrite>(
            this, object, offset, value, scratch0, scratch1, mode,
            DetermineStubCallMode(), &unwinding_info_writer_);
        __ StoreTaggedField(value, MemOperand(object, offset), r0);
      } else {
        DCHECK_EQ(kMode_MRR, addressing_mode);
        Register offset(i.InputRegister(1));
        ool = zone()->New<OutOfLineRecordWrite>(
            this, object, offset, value, scratch0, scratch1, mode,
            DetermineStubCallMode(), &unwinding_info_writer_);
        __ StoreTaggedField(value, MemOperand(object, offset), r0);
      }
      // Skip the write barrier if the value is a Smi. However, this is only
      // valid if the value isn't an indirect pointer. Otherwise the value will
      // be a pointer table index, which will always look like a Smi (but
      // actually reference a pointer in the pointer table).
      if (mode > RecordWriteMode::kValueIsIndirectPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                       ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);
      OutOfLineRecordWrite* ool;
      DCHECK_EQ(mode, RecordWriteMode::kValueIsIndirectPointer);
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);
      IndirectPointerTag tag = static_cast<IndirectPointerTag>(i.InputInt64(3));
      DCHECK(IsValidIndirectPointerTag(tag));
      if (addressing_mode == kMode_MRI) {
        uint64_t offset = i.InputInt64(1);
        ool = zone()->New<OutOfLineRecordWrite>(
            this, object, offset, value, scratch0, scratch1, mode,
            DetermineStubCallMode(), &unwinding_info_writer_, tag);
        __ StoreIndirectPointerField(value, MemOperand(object, offset), r0);
      } else {
        DCHECK_EQ(addressing_mode, kMode_MRR);
        Register offset(i.InputRegister(1));
        ool = zone()->New<OutOfLineRecordWrite>(
            this, object, offset, value, scratch0, scratch1, mode,
            DetermineStubCallMode(), &unwinding_info_writer_, tag);
        __ StoreIndirectPointerField(value, MemOperand(object, offset), r0);
      }
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                       ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      __ AddS64(i.OutputRegister(), offset.from_stack_pointer() ? sp : fp,
                Operand(offset.offset()), r0);
      break;
    }
    case kPPC_Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ LoadF64(i.OutputDoubleRegister(), MemOperand(fp, offset), r0);
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ LoadF32(i.OutputFloatRegister(), MemOperand(fp, offset), r0);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          __ LoadSimd128(i.OutputSimd128Register(), MemOperand(fp, offset),
                         kScratchReg);
        }
      } else {
        __ LoadU64(i.OutputRegister(), MemOperand(fp, offset), r0);
      }
      break;
    }
    case kPPC_Sync: {
      __ sync();
      break;
    }
    case kPPC_And:
      if (HasRegisterInput(instr, 1)) {
        __ and_(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.OutputRCBit());
      } else {
        __ andi(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1));
      }
      break;
    case kPPC_AndComplement:
      __ andc(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
              i.OutputRCBit());
      break;
    case kPPC_Or:
      if (HasRegisterInput(instr, 1)) {
        __ orx(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.OutputRCBit());
      } else {
        __ ori(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1));
        DCHECK_EQ(LeaveRC, i.OutputRCBit());
      }
      break;
    case kPPC_OrComplement:
      __ orc(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.OutputRCBit());
      break;
    case kPPC_Xor:
      if (HasRegisterInput(instr, 1)) {
        __ xor_(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.OutputRCBit());
      } else {
        __ xori(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1));
        DCHECK_EQ(LeaveRC, i.OutputRCBit());
      }
      break;
    case kPPC_ShiftLeft32:
      ASSEMBLE_BINOP_RC(ShiftLeftU32, ShiftLeftU32);
      break;
    case kPPC_ShiftLeft64:
      ASSEMBLE_BINOP_RC(ShiftLeftU64, ShiftLeftU64);
      break;
    case kPPC_ShiftRight32:
      ASSEMBLE_BINOP_RC(ShiftRightU32, ShiftRightU32);
      break;
    case kPPC_ShiftRight64:
      ASSEMBLE_BINOP_RC(ShiftRightU64, ShiftRightU64);
      break;
    case kPPC_ShiftRightAlg32:
      ASSEMBLE_BINOP_INT_RC(ShiftRightS32, ShiftRightS32);
      break;
    case kPPC_ShiftRightAlg64:
      ASSEMBLE_BINOP_INT_RC(ShiftRightS64, ShiftRightS64);
      break;
    case kPPC_RotRight32:
      if (HasRegisterInput(instr, 1)) {
        __ subfic(kScratchReg, i.InputRegister(1), Operand(32));
        __ rotlw(i.OutputRegister(), i.InputRegister(0), kScratchReg,
                 i.OutputRCBit());
      } else {
        int sh = i.InputInt32(1);
        __ rotrwi(i.OutputRegister(), i.InputRegister(0), sh, i.OutputRCBit());
      }
      break;
    case kPPC_RotRight64:
      if (HasRegisterInput(instr, 1)) {
        __ subfic(kScratchReg, i.InputRegister(1), Operand(64));
        __ rotld(i.OutputRegister(), i.InputRegister(0), kScratchReg,
                 i.OutputRCBit());
      } else {
        int sh = i.InputInt32(1);
        __ rotrdi(i.OutputRegister(), i.InputRegister(0), sh, i.OutputRCBit());
      }
      break;
    case kPPC_Not:
      __ notx(i.OutputRegister(), i.InputRegister(0), i.OutputRCBit());
      break;
    case kPPC_RotLeftAndMask32:
      __ rlwinm(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1),
                31 - i.InputInt32(2), 31 - i.InputInt32(3), i.OutputRCBit());
      break;
    case kPPC_RotLeftAndClear64:
      __ rldic(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1),
               63 - i.InputInt32(2), i.OutputRCBit());
      break;
    case kPPC_RotLeftAndClearLeft64:
      __ rldicl(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1),
                63 - i.InputInt32(2), i.OutputRCBit());
      break;
    case kPPC_RotLeftAndClearRight64:
      __ rldicr(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1),
                63 - i.InputInt32(2), i.OutputRCBit());
      break;
    case kPPC_Add32:
      if (FlagsModeField::decode(instr->opcode()) != kFlags_none) {
        ASSEMBLE_ADD_WITH_OVERFLOW();
      } else {
        if (HasRegisterInput(instr, 1)) {
          __ add(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                 LeaveOE, i.OutputRCBit());
        } else {
          __ AddS64(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1),
                    r0, LeaveOE, i.OutputRCBit());
        }
        __ extsw(i.OutputRegister(), i.OutputRegister());
      }
      break;
    case kPPC_Add64:
      if (FlagsModeField::decode(instr->opcode()) != kFlags_none) {
        ASSEMBLE_ADD_WITH_OVERFLOW();
      } else {
        if (HasRegisterInput(instr, 1)) {
          __ add(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                 LeaveOE, i.OutputRCBit());
        } else {
          __ AddS64(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1),
                    r0, LeaveOE, i.OutputRCBit());
        }
      }
      break;
    case kPPC_AddWithOverflow32:
      ASSEMBLE_ADD_WITH_OVERFLOW32();
      break;
    case kPPC_AddDouble:
      ASSEMBLE_FLOAT_BINOP_RC(fadd, MiscField::decode(instr->opcode()));
      break;
    case kPPC_Sub:
      if (FlagsModeField::decode(instr->opcode()) != kFlags_none) {
        ASSEMBLE_SUB_WITH_OVERFLOW();
      } else {
        if (HasRegisterInput(instr, 1)) {
          __ sub(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                 LeaveOE, i.OutputRCBit());
        } else {
          __ SubS64(i.OutputRegister(), i.InputRegister(0), i.InputImmediate(1),
                    r0, LeaveOE, i.OutputRCBit());
        }
      }
      break;
    case kPPC_SubWithOverflow32:
      ASSEMBLE_SUB_WITH_OVERFLOW32();
      break;
    case kPPC_SubDouble:
      ASSEMBLE_FLOAT_BINOP_RC(fsub, MiscField::decode(instr->opcode()));
      break;
    case kPPC_Mul32:
      __ mullw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               LeaveOE, i.OutputRCBit());
      break;
    case kPPC_Mul64:
      __ mulld(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               LeaveOE, i.OutputRCBit());
      break;
    case kPPC_Mul32WithHigh32:
      if (i.OutputRegister(0) == i.InputRegister(0) ||
          i.OutputRegister(0) == i.InputRegister(1) ||
          i.OutputRegister(1) == i.InputRegister(0) ||
          i.OutputRegister(1) == i.InputRegister(1)) {
        __ mullw(kScratchReg, i.InputRegister(0), i.InputRegister(1));  // low
        __ mulhw(i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1));  // high
        __ mr(i.OutputRegister(0), kScratchReg);
      } else {
        __ mullw(i.OutputRegister(0), i.InputRegister(0),
                 i.InputRegister(1));  // low
        __ mulhw(i.OutputRegister(1), i.InputRegister(0),
                 i.InputRegister(1));  // high
      }
      break;
    case kPPC_MulHighS64:
      __ mulhd(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.OutputRCBit());
      break;
    case kPPC_MulHighU64:
      __ mulhdu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.OutputRCBit());
      break;
    case kPPC_MulHigh32:
      __ mulhw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.OutputRCBit());
      // High 32 bits are undefined and need to be cleared.
      CleanUInt32(i.OutputRegister());
      break;
    case kPPC_MulHighU32:
      __ mulhwu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.OutputRCBit());
      // High 32 bits are undefined and need to be cleared.
      CleanUInt32(i.OutputRegister());
      break;
    case kPPC_MulDouble:
      ASSEMBLE_FLOAT_BINOP_RC(fmul, MiscField::decode(instr->opcode()));
      break;
    case kPPC_Div32:
      __ divw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_Div64:
      __ divd(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DivU32:
      __ divwu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DivU64:
      __ divdu(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveRC, i.OutputRCBit());
      break;
    case kPPC_DivDouble:
      ASSEMBLE_FLOAT_BINOP_RC(fdiv, MiscField::decode(instr->opcode()));
      break;
    case kPPC_Mod32:
      if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
        __ modsw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        ASSEMBLE_MODULO(divw, mullw);
      }
      break;
    case kPPC_Mod64:
      if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
        __ modsd(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        ASSEMBLE_MODULO(divd, mulld);
      }
      break;
    case kPPC_ModU32:
      if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
        __ moduw(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        ASSEMBLE_MODULO(divwu, mullw);
      }
      break;
    case kPPC_ModU64:
      if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
        __ modud(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        ASSEMBLE_MODULO(divdu, mulld);
      }
      break;
    case kPPC_ModDouble:
      // TODO(bmeurer): We should really get rid of this special instruction,
      // and generate a CallAddress instruction instead.
      ASSEMBLE_FLOAT_MODULO();
      break;
    case kIeee754Float64Acos:
      ASSEMBLE_IEEE754_UNOP(acos);
      break;
    case kIeee754Float64Acosh:
      ASSEMBLE_IEEE754_UNOP(acosh);
      break;
    case kIeee754Float64Asin:
      ASSEMBLE_IEEE754_UNOP(asin);
      break;
    case kIeee754Float64Asinh:
      ASSEMBLE_IEEE754_UNOP(asinh);
      break;
    case kIeee754Float64Atan:
      ASSEMBLE_IEEE754_UNOP(atan);
      break;
    case kIeee754Float64Atan2:
      ASSEMBLE_IEEE754_BINOP(atan2);
      break;
    case kIeee754Float64Atanh:
      ASSEMBLE_IEEE754_UNOP(atanh);
      break;
    case kIeee754Float64Tan:
      ASSEMBLE_IEEE754_UNOP(tan);
      break;
    case kIeee754Float64Tanh:
      ASSEMBLE_IEEE754_UNOP(tanh);
      break;
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
      break;
    case kIeee754Float64Sin:
      ASSEMBLE_IEEE754_UNOP(sin);
      break;
    case kIeee754Float64Sinh:
      ASSEMBLE_IEEE754_UNOP(sinh);
      break;
    case kIeee754Float64Cos:
      ASSEMBLE_IEEE754_UNOP(cos);
      break;
    case kIeee754Float64Cosh:
      ASSEMBLE_IEEE754_UNOP(cosh);
      break;
    case kIeee754Float64Exp:
      ASSEMBLE_IEEE754_UNOP(exp);
      break;
    case kIeee754Float64Expm1:
      ASSEMBLE_IEEE754_UNOP(expm1);
      break;
    case kIeee754Float64Log:
      ASSEMBLE_IEEE754_UNOP(log);
      break;
    case kIeee754Float64Log1p:
      ASSEMBLE_IEEE754_UNOP(log1p);
      break;
    case kIeee754Float64Log2:
      ASSEMBLE_IEEE754_UNOP(log2);
      break;
```