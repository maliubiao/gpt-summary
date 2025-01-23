Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Identify the Core Function:** The code is within a `switch` statement based on `instr->opcode()`. This immediately tells me the code is processing different types of instructions. The context "v8/src/compiler/backend/x64/code-generator-x64.cc" strongly suggests this code is responsible for generating x64 assembly instructions for the V8 JavaScript engine's optimizing compiler.

2. **Break Down by `case`:**  The most effective way to understand the functionality is to go through each `case` within the `switch`. For each case, I try to understand:
    * **What instruction is being handled?** (e.g., `kArchTailCallWasm`, `kArchCallJSFunction`, `kX64Add`, `kSSEFloat64Cmp`). The `kArch` prefix often indicates architectural instructions, while prefixes like `kX64` or `kSSE` indicate specific x64 or SSE instructions.
    * **What are the inputs?**  The code uses `instr->InputAt()`, `i.InputRegister()`, `i.InputOperand()`, etc., to access input values. I pay attention to the data types (register, immediate, memory operand, etc.).
    * **What assembly instructions are being generated?**  The code uses `__` followed by assembly mnemonics (e.g., `__ jmp`, `__ call`, `__ movq`, `__ addl`).
    * **What is the purpose of this instruction?**  Based on the assembly generated and the instruction name, I infer the high-level operation (e.g., tail call, function call, arithmetic operation, floating-point comparison).
    * **Are there any special considerations?**  Look for `if` statements, flags like `v8_flags.debug_code`, calls to helper functions (like `RecordCallPosition`, `BuildTranslation`), and comments that provide extra context.

3. **Group Similar Functionality:** After reviewing several cases, I start to see patterns. For instance, there are many cases for arithmetic operations (`kX64Add`, `kX64Sub`, etc.), logical operations (`kX64And`, `kX64Or`, etc.), and floating-point operations (`kSSEFloat32Add`, `kSSEFloat64Cmp`, etc.). Grouping these together helps in summarizing the overall functionality.

4. **Look for High-Level Concepts:** I identify broader concepts being implemented, such as:
    * **Function calls:**  `kArchCallJSFunction`, `kArchTailCall*`, `kArchCallCFunction`.
    * **Control flow:** `kArchJmp`, `kArchBinarySearchSwitch`, `kArchTableSwitch`, `kArchRet`.
    * **Stack management:** `kArchPrepareCallCFunction`, `kArchSaveCallerRegisters`, `kArchRestoreCallerRegisters`, `kArchStackSlot`.
    * **Deoptimization:** `kArchDeoptimize`.
    * **Write barriers:** `kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`, `kArchStoreIndirectWithWriteBarrier`.
    * **Floating-point operations:** The various `kIeee754Float64*` and `kSSEFloat*` instructions.

5. **Address Specific Questions:**  Once I have a good understanding of the code's function, I can address the specific points in the request:
    * **Listing Functionality:** This involves summarizing the grouped functionalities and specific instruction handling.
    * **Torque Source:**  The code clearly ends in `.cc`, so it's not a Torque source.
    * **Relationship to JavaScript:**  Instructions like `kArchCallJSFunction` directly relate to executing JavaScript functions. Many of the other instructions (arithmetic, logic, memory access, floating-point) are the low-level operations needed to implement JavaScript semantics. I look for examples of how these low-level operations might correspond to JavaScript code.
    * **Code Logic Reasoning:** I pick a simple case (like `kX64Add`) and provide a basic example of input registers and the resulting output.
    * **Common Programming Errors:**  I consider how the handled instructions relate to common errors, such as integer overflow (related to arithmetic operations) or incorrect function calls.
    * **Summarizing Functionality (Part 3 of 10):** This requires synthesizing the information gathered to provide a concise description of the code's role within the larger compilation process. Given that this is part 3 and focuses on instruction emission, I emphasize that aspect.

6. **Refine and Organize:**  Finally, I organize the information logically, using clear headings and bullet points to make it easy to read and understand. I ensure the language is precise and avoids jargon where possible, while still being technically accurate. I double-check that I've addressed all parts of the original request.

By following these steps, I can effectively analyze the C++ code snippet and provide a comprehensive answer to the user's request. The key is to break down the code into manageable parts, understand the purpose of each part, and then synthesize that information into a coherent summary.
这是提供的v8源代码文件 `v8/src/compiler/backend/x64/code-generator-x64.cc` 的第三部分，主要负责将**架构无关的中间表示 (Instruction)** 翻译成 **特定于 x64 架构的机器码**。

以下是根据提供的代码片段归纳出的功能点：

**核心功能：生成 x64 汇编代码**

*   **处理多种指令类型:**  `switch (instr->opcode())` 结构表明代码可以处理多种不同的中间表示指令 (`kArch...`, `kX64...`, `kSSE...`, `kIeee754Float64...`)。
*   **生成控制流指令:**  处理如 `kArchTailCallWasm`, `kArchTailCallCodeObject`, `kArchTailCallAddress`, `kArchJmp`, `kArchRet` 等指令，生成跳转、尾调用和返回等控制流相关的汇编代码。
*   **生成函数调用指令:**  处理 `kArchCallJSFunction`, `kArchPrepareCallCFunction`, `kArchCallCFunction`, `kArchCallCFunctionWithFrameState` 等指令，生成 JavaScript 函数调用和 C 函数调用的汇编代码，并进行参数准备和寄存器保存/恢复。
*   **处理栈帧操作:**  处理 `kArchFramePointer`, `kArchStackPointer`, `kArchSetStackPointer`, `kArchParentFramePointer`, `kArchStackSlot` 等指令，生成与栈帧管理相关的汇编代码，例如获取帧指针、栈指针、设置栈指针等。
*   **生成算术和逻辑运算指令:**  处理如 `kX64Add`, `kX64Sub`, `kX64And`, `kX64Or`, `kX64Xor`, `kX64Shl`, `kX64Shr`, `kX64Sar`, `kX64Mul`, `kX64Div`, `kX64Not`, `kX64Neg` 等指令，生成相应的 x64 算术和逻辑运算指令。
*   **生成比较和测试指令:**  处理如 `kX64Cmp8`, `kX64Cmp16`, `kX64Cmp32`, `kX64Cmp`, `kX64Test8`, `kX64Test16`, `kX64Test32`, `kX64Test` 等指令，生成比较和测试指令。
*   **生成浮点运算指令:**  处理 `kSSEFloat32...` 和 `kSSEFloat64...` 以及 `kIeee754Float64...` 系列的指令，生成 SSE 和 IEEE 754 标准的浮点运算指令，包括加减乘除、平方根、三角函数、比较、类型转换等。
*   **处理内存访问指令:**  处理 `kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`, `kArchStoreIndirectWithWriteBarrier` 等指令，生成带有写屏障的内存存储指令，用于垃圾回收。
*   **生成位操作指令:**  处理如 `kX64Lzcnt`, `kX64Tzcnt`, `kX64Popcnt`, `kX64Bswap` 等指令，生成计算前导零、尾随零、人口计数和字节序反转等位操作指令。
*   **处理 Deoptimization:**  处理 `kArchDeoptimize` 指令，生成用于代码去优化的跳转代码。
*   **生成调试和辅助指令:**  处理如 `kArchComment`, `kArchAbortCSADcheck`, `kArchDebugBreak`, `kArchThrowTerminator`, `kArchNop` 等指令，生成注释、断言、调试断点和空操作等辅助指令。
*   **支持尾调用优化:** 处理 `kArchTailCall...` 和 `kArchPrepareTailCall` 指令，生成尾调用优化的汇编代码，避免不必要的栈帧。
*   **处理 WebAssembly 相关指令 (条件编译):**  在 `V8_ENABLE_WEBASSEMBLY` 宏定义下，处理 `kArchTailCallWasm`, `kArchStackPointer`, `kArchSetStackPointer` 等 WebAssembly 相关的指令。
*   **处理内存屏障:** 生成 `mfence` 和 `lfence` 指令来确保内存操作的顺序性。

**与 JavaScript 的关系 (举例):**

很多指令都直接或间接地与 JavaScript 的功能相关。例如：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 编译 `add(5, 10)` 这行 JavaScript 代码时，`code-generator-x64.cc` 中处理 `kX64Add` 指令的部分就会生成 x64 的 `addl` 或 `addq` 指令，将 `a` 和 `b` 的值（可能存储在寄存器中）相加，并将结果存储到另一个寄存器中。

再比如，JavaScript 中的函数调用会对应到 `kArchCallJSFunction` 指令的处理。

**代码逻辑推理 (假设输入与输出):**

假设输入指令 `instr` 的 `opcode` 是 `kX64Add`，并且：

*   `instr->InputRegister(0)` 返回寄存器 `rax`
*   `instr->InputRegister(1)` 返回寄存器 `rbx`
*   `instr->OutputRegister()` 返回寄存器 `rcx`

那么，`ASSEMBLE_BINOP(addq)` 宏会展开生成 x64 汇编指令：

```assembly
  addq rcx, rbx  // 将 rbx 的值加到 rcx 上
```

**用户常见的编程错误 (举例):**

虽然这个代码生成器本身不直接处理用户的编程错误，但它生成的代码会暴露或导致一些常见的错误：

*   **整数溢出:** JavaScript 的数值是双精度浮点数，但在某些内部操作中可能会使用整数。如果生成的算术运算指令（如 `kX64Add`）导致整数溢出，可能会产生意想不到的结果。
*   **类型错误:** 如果 JavaScript 代码尝试对不兼容的类型执行操作（例如，将数字与字符串相加），编译器可能会生成一些类型转换的代码。如果转换失败，可能会导致运行时错误。
*   **堆栈溢出:** 递归过深的 JavaScript 函数调用可能导致栈溢出。`code-generator-x64.cc` 中处理函数调用和栈帧管理的逻辑与此相关。

**总结 (第 3 部分功能):**

作为编译过程的一部分，`v8/src/compiler/backend/x64/code-generator-x64.cc` 的这部分代码（第三部分）专注于将中间表示的指令具体化为 x64 架构的机器码。它涵盖了各种指令类型，包括控制流、函数调用、算术运算、逻辑运算、浮点运算、内存访问和位操作等，是生成可执行代码的关键步骤。它负责将高级的、与平台无关的操作转化为处理器可以直接理解和执行的指令序列。

**关于 `.tq` 结尾:**

正如代码所示，`v8/src/compiler/backend/x64/code-generator-x64.cc` 的后缀是 `.cc`，这意味着它是一个 C++ 源代码文件，而不是 Torque 源代码。Torque 文件通常以 `.tq` 结尾。

### 提示词
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/x64/code-generator-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
rLazyDeopt(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchTailCallWasm: {
      if (HasImmediateInput(instr, 0)) {
        Constant constant = i.ToConstant(instr->InputAt(0));
        Address wasm_code = static_cast<Address>(constant.ToInt64());
        if (DetermineStubCallMode() == StubCallMode::kCallWasmRuntimeStub) {
          __ near_jmp(wasm_code, constant.rmode());
        } else {
          __ Move(kScratchRegister, wasm_code, constant.rmode());
          __ jmp(kScratchRegister);
        }
      } else {
        __ jmp(i.InputRegister(0));
      }
      unwinding_info_writer_.MarkBlockWillExit();
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallCodeObject: {
      if (HasImmediateInput(instr, 0)) {
        Handle<Code> code = i.InputCode(0);
        __ Jump(code, RelocInfo::CODE_TARGET);
      } else {
        Register reg = i.InputRegister(0);
        CodeEntrypointTag tag =
            i.InputCodeEntrypointTag(instr->CodeEnrypointTagInputIndex());
        DCHECK_IMPLIES(
            instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
            reg == kJavaScriptCallCodeStartRegister);
        __ LoadCodeInstructionStart(reg, reg, tag);
        __ jmp(reg);
      }
      unwinding_info_writer_.MarkBlockWillExit();
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchTailCallAddress: {
      CHECK(!HasImmediateInput(instr, 0));
      Register reg = i.InputRegister(0);
      DCHECK_IMPLIES(
          instr->HasCallDescriptorFlag(CallDescriptor::kFixedTargetRegister),
          reg == kJavaScriptCallCodeStartRegister);
      __ jmp(reg);
      unwinding_info_writer_.MarkBlockWillExit();
      frame_access_state()->ClearSPDelta();
      frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        // Check the function's context matches the context argument.
        __ cmp_tagged(rsi, FieldOperand(func, JSFunction::kContextOffset));
        __ Assert(equal, AbortReason::kWrongFunctionContext);
      }
      static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      frame_access_state()->ClearSPDelta();
      RecordCallPosition(instr);
      AssemblePlaceHolderForLazyDeopt(instr);
      break;
    }
    case kArchPrepareCallCFunction: {
      // Frame alignment requires using FP-relative frame addressing.
      frame_access_state()->SetFrameAccessToFP();
      int const num_parameters = MiscField::decode(instr->opcode());
      __ PrepareCallCFunction(num_parameters);
      break;
    }
    case kArchSaveCallerRegisters: {
      fp_mode_ =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      DCHECK(fp_mode_ == SaveFPRegsMode::kIgnore ||
             fp_mode_ == SaveFPRegsMode::kSave);
      // kReturnRegister0 should have been saved before entering the stub.
      int bytes = __ PushCallerSaved(fp_mode_, kReturnRegister0);
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
      int bytes = __ PopCallerSaved(fp_mode_, kReturnRegister0);
      frame_access_state()->IncreaseSPDelta(-(bytes / kSystemPointerSize));
      DCHECK_EQ(0, frame_access_state()->sp_delta());
      DCHECK(caller_registers_saved_);
      caller_registers_saved_ = false;
      break;
    }
    case kArchPrepareTailCall:
      AssemblePrepareTailCall();
      break;
    case kArchCallCFunctionWithFrameState:
    case kArchCallCFunction: {
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      Label return_location;
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
#if V8_ENABLE_WEBASSEMBLY
      if (linkage()->GetIncomingDescriptor()->IsWasmCapiFunction()) {
        // Put the return address in a stack slot.
        __ leaq(kScratchRegister, Operand(&return_location, 0));
        __ movq(MemOperand(rbp, WasmExitFrameConstants::kCallingPCOffset),
                kScratchRegister);
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (HasImmediateInput(instr, 0)) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset = __ CallCFunction(ref, num_gp_parameters + num_fp_parameters,
                                     set_isolate_data_slots, &return_location);
      } else {
        Register func = i.InputRegister(0);
        pc_offset =
            __ CallCFunction(func, num_gp_parameters + num_fp_parameters,
                             set_isolate_data_slots, &return_location);
      }

      RecordSafepoint(instr->reference_map(), pc_offset);

      bool const needs_frame_state =
          (arch_opcode == kArchCallCFunctionWithFrameState);
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
      // TODO(turbofan): Do we need an lfence here?
      break;
    }
    case kArchJmp:
      AssembleArchJump(i.InputRpo(0));
      break;
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      break;
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt64(0)),
                       SourceLocation());
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == rdx);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ int3();
      unwinding_info_writer_.MarkBlockWillExit();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchThrowTerminator:
      unwinding_info_writer_.MarkBlockWillExit();
      break;
    case kArchNop:
      // don't emit code for nops.
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ jmp(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      break;
    case kArchFramePointer:
      __ movq(i.OutputRegister(), rbp);
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      __ movq(i.OutputRegister(), rsp);
      break;
    case kArchSetStackPointer:
      if (instr->InputAt(0)->IsRegister()) {
        __ movq(rsp, i.InputRegister(0));
      } else {
        __ movq(rsp, i.InputOperand(0));
      }
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ movq(i.OutputRegister(), Operand(rbp, 0));
      } else {
        __ movq(i.OutputRegister(), rbp);
      }
      break;
    case kArchStackPointerGreaterThan: {
      // Potentially apply an offset to the current stack pointer before the
      // comparison to consider the size difference of an optimized frame versus
      // the contained unoptimized frames.

      Register lhs_register = rsp;
      uint32_t offset;

      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = kScratchRegister;
        __ leaq(lhs_register, Operand(rsp, static_cast<int32_t>(offset) * -1));
      }

      constexpr size_t kValueIndex = 0;
      if (HasAddressingMode(instr)) {
        __ cmpq(lhs_register, i.MemoryOperand(kValueIndex));
      } else {
        __ cmpq(lhs_register, i.InputRegister(kValueIndex));
      }
      break;
    }
    case kArchStackCheckOffset:
      __ Move(i.OutputRegister(), Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchTruncateDoubleToI: {
      auto result = i.OutputRegister();
      auto input = i.InputDoubleRegister(0);
      auto ool = zone()->New<OutOfLineTruncateDoubleToI>(
          this, result, input, DetermineStubCallMode(),
          &unwinding_info_writer_);
      // We use Cvttsd2siq instead of Cvttsd2si due to performance reasons. The
      // use of Cvttsd2siq requires the movl below to avoid sign extension.
      __ Cvttsd2siq(result, input);
      __ cmpq(result, Immediate(1));
      __ j(overflow, ool->entry());
      __ bind(ool->exit());
      __ movl(result, result);
      break;
    }
    case kArchStoreWithWriteBarrier:  // Fall through.
    case kArchAtomicStoreWithWriteBarrier: {
      // {EmitTSANAwareStore} calls RecordTrapInfoIfNeeded. No need to do it
      // here.
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      Register value = i.InputRegister(index);
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ Cmp(value, kClearedWeakHeapObjectLower32);
        __ Check(not_equal, AbortReason::kOperandIsCleared);
      }

      auto ool = zone()->New<OutOfLineRecordWrite>(this, object, operand, value,
                                                   scratch0, scratch1, mode,
                                                   DetermineStubCallMode());
      if (arch_opcode == kArchStoreWithWriteBarrier) {
        EmitTSANAwareStore<std::memory_order_relaxed>(
            zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
            MachineRepresentation::kTagged, instr);
      } else {
        DCHECK_EQ(arch_opcode, kArchAtomicStoreWithWriteBarrier);
        EmitTSANAwareStore<std::memory_order_seq_cst>(
            zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
            MachineRepresentation::kTagged, instr);
      }
      if (mode > RecordWriteMode::kValueIsPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
#if V8_ENABLE_STICKY_MARK_BITS_BOOL
      __ CheckPageFlag(object, scratch0, MemoryChunk::kIncrementalMarking,
                       not_zero, ool->stub_call());
      __ CheckMarkBit(object, scratch0, scratch1, carry, ool->entry());
#else   // !V8_ENABLE_STICKY_MARK_BITS_BOOL
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask,
                       not_zero, ool->entry());
#endif  // !V8_ENABLE_STICKY_MARK_BITS_BOOL
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      DCHECK_EQ(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      Register value = i.InputRegister(index++);
      IndirectPointerTag tag =
          static_cast<IndirectPointerTag>(i.InputInt64(index));
      DCHECK(IsValidIndirectPointerTag(tag));
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);

      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, operand, value, scratch0, scratch1, mode,
          DetermineStubCallMode(), tag);
      EmitTSANAwareStore<std::memory_order_relaxed>(
          zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
          MachineRepresentation::kIndirectPointer, instr);
      __ JumpIfMarking(ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kX64MFence:
      __ mfence();
      break;
    case kX64LFence:
      __ lfence();
      break;
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base = offset.from_stack_pointer() ? rsp : rbp;
      __ leaq(i.OutputRegister(), Operand(base, offset.offset()));
      break;
    }
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
    case kIeee754Float64Atanh:
      ASSEMBLE_IEEE754_UNOP(atanh);
      break;
    case kIeee754Float64Atan2:
      ASSEMBLE_IEEE754_BINOP(atan2);
      break;
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
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
    case kIeee754Float64Log10:
      ASSEMBLE_IEEE754_UNOP(log10);
      break;
    case kIeee754Float64Pow:
      ASSEMBLE_IEEE754_BINOP(pow);
      break;
    case kIeee754Float64Sin:
      ASSEMBLE_IEEE754_UNOP(sin);
      break;
    case kIeee754Float64Sinh:
      ASSEMBLE_IEEE754_UNOP(sinh);
      break;
    case kIeee754Float64Tan:
      ASSEMBLE_IEEE754_UNOP(tan);
      break;
    case kIeee754Float64Tanh:
      ASSEMBLE_IEEE754_UNOP(tanh);
      break;
    case kX64Add32:
      ASSEMBLE_BINOP(addl);
      break;
    case kX64Add:
      ASSEMBLE_BINOP(addq);
      break;
    case kX64Sub32:
      ASSEMBLE_BINOP(subl);
      break;
    case kX64Sub:
      ASSEMBLE_BINOP(subq);
      break;
    case kX64And32:
      ASSEMBLE_BINOP(andl);
      break;
    case kX64And:
      ASSEMBLE_BINOP(andq);
      break;
    case kX64Cmp8:
      if (ShouldAlignForJCCErratum(instr, FirstMacroFusionInstKind::kCmp)) {
        ASSEMBLE_COMPARE(aligned_cmpb, aligned_testb);
      } else {
        ASSEMBLE_COMPARE(cmpb, testb);
      }
      break;
    case kX64Cmp16:
      if (ShouldAlignForJCCErratum(instr, FirstMacroFusionInstKind::kCmp)) {
        ASSEMBLE_COMPARE(aligned_cmpw, aligned_testw);
      } else {
        ASSEMBLE_COMPARE(cmpw, testw);
      }
      break;
    case kX64Cmp32:
      if (ShouldAlignForJCCErratum(instr, FirstMacroFusionInstKind::kCmp)) {
        ASSEMBLE_COMPARE(aligned_cmpl, aligned_testl);
      } else {
        ASSEMBLE_COMPARE(cmpl, testl);
      }
      break;
    case kX64Cmp:
      if (ShouldAlignForJCCErratum(instr, FirstMacroFusionInstKind::kCmp)) {
        ASSEMBLE_COMPARE(aligned_cmpq, aligned_testq);
      } else {
        ASSEMBLE_COMPARE(cmpq, testq);
      }
      break;
    case kX64Test8:
      if (ShouldAlignForJCCErratum(instr, FirstMacroFusionInstKind::kTest)) {
        ASSEMBLE_TEST(aligned_testb);
      } else {
        ASSEMBLE_TEST(testb);
      }
      break;
    case kX64Test16:
      if (ShouldAlignForJCCErratum(instr, FirstMacroFusionInstKind::kTest)) {
        ASSEMBLE_TEST(aligned_testw);
      } else {
        ASSEMBLE_TEST(testw);
      }
      break;
    case kX64Test32:
      if (ShouldAlignForJCCErratum(instr, FirstMacroFusionInstKind::kTest)) {
        ASSEMBLE_TEST(aligned_testl);
      } else {
        ASSEMBLE_TEST(testl);
      }
      break;
    case kX64Test:
      if (ShouldAlignForJCCErratum(instr, FirstMacroFusionInstKind::kTest)) {
        ASSEMBLE_TEST(aligned_testq);
      } else {
        ASSEMBLE_TEST(testq);
      }
      break;
    case kX64Imul32:
      ASSEMBLE_MULT(imull);
      break;
    case kX64Imul:
      ASSEMBLE_MULT(imulq);
      break;
    case kX64ImulHigh32:
      if (HasRegisterInput(instr, 1)) {
        __ imull(i.InputRegister(1));
      } else {
        __ imull(i.InputOperand(1));
      }
      break;
    case kX64UmulHigh32:
      if (HasRegisterInput(instr, 1)) {
        __ mull(i.InputRegister(1));
      } else {
        __ mull(i.InputOperand(1));
      }
      break;
    case kX64ImulHigh64:
      if (HasRegisterInput(instr, 1)) {
        __ imulq(i.InputRegister(1));
      } else {
        __ imulq(i.InputOperand(1));
      }
      break;
    case kX64UmulHigh64:
      if (HasRegisterInput(instr, 1)) {
        __ mulq(i.InputRegister(1));
      } else {
        __ mulq(i.InputOperand(1));
      }
      break;
    case kX64Idiv32:
      __ cdq();
      __ idivl(i.InputRegister(1));
      break;
    case kX64Idiv:
      __ cqo();
      __ idivq(i.InputRegister(1));
      break;
    case kX64Udiv32:
      __ xorl(rdx, rdx);
      __ divl(i.InputRegister(1));
      break;
    case kX64Udiv:
      __ xorq(rdx, rdx);
      __ divq(i.InputRegister(1));
      break;
    case kX64Not:
      ASSEMBLE_UNOP(notq);
      break;
    case kX64Not32:
      ASSEMBLE_UNOP(notl);
      break;
    case kX64Neg:
      ASSEMBLE_UNOP(negq);
      break;
    case kX64Neg32:
      ASSEMBLE_UNOP(negl);
      break;
    case kX64Or32:
      ASSEMBLE_BINOP(orl);
      break;
    case kX64Or:
      ASSEMBLE_BINOP(orq);
      break;
    case kX64Xor32:
      ASSEMBLE_BINOP(xorl);
      break;
    case kX64Xor:
      ASSEMBLE_BINOP(xorq);
      break;
    case kX64Shl32:
      ASSEMBLE_SHIFT(shll, 5);
      break;
    case kX64Shl:
      ASSEMBLE_SHIFT(shlq, 6);
      break;
    case kX64Shr32:
      ASSEMBLE_SHIFT(shrl, 5);
      break;
    case kX64Shr:
      ASSEMBLE_SHIFT(shrq, 6);
      break;
    case kX64Sar32:
      ASSEMBLE_SHIFT(sarl, 5);
      break;
    case kX64Sar:
      ASSEMBLE_SHIFT(sarq, 6);
      break;
    case kX64Rol32:
      ASSEMBLE_SHIFT(roll, 5);
      break;
    case kX64Rol:
      ASSEMBLE_SHIFT(rolq, 6);
      break;
    case kX64Ror32:
      ASSEMBLE_SHIFT(rorl, 5);
      break;
    case kX64Ror:
      ASSEMBLE_SHIFT(rorq, 6);
      break;
    case kX64Lzcnt:
      if (HasRegisterInput(instr, 0)) {
        __ Lzcntq(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ Lzcntq(i.OutputRegister(), i.InputOperand(0));
      }
      break;
    case kX64Lzcnt32:
      if (HasRegisterInput(instr, 0)) {
        __ Lzcntl(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ Lzcntl(i.OutputRegister(), i.InputOperand(0));
      }
      break;
    case kX64Tzcnt:
      if (HasRegisterInput(instr, 0)) {
        __ Tzcntq(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ Tzcntq(i.OutputRegister(), i.InputOperand(0));
      }
      break;
    case kX64Tzcnt32:
      if (HasRegisterInput(instr, 0)) {
        __ Tzcntl(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ Tzcntl(i.OutputRegister(), i.InputOperand(0));
      }
      break;
    case kX64Popcnt:
      if (HasRegisterInput(instr, 0)) {
        __ Popcntq(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ Popcntq(i.OutputRegister(), i.InputOperand(0));
      }
      break;
    case kX64Popcnt32:
      if (HasRegisterInput(instr, 0)) {
        __ Popcntl(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ Popcntl(i.OutputRegister(), i.InputOperand(0));
      }
      break;
    case kX64Bswap:
      __ bswapq(i.OutputRegister());
      break;
    case kX64Bswap32:
      __ bswapl(i.OutputRegister());
      break;
    case kSSEFloat32Cmp:
      ASSEMBLE_SSE_BINOP(Ucomiss);
      break;
    case kSSEFloat32Add:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_SSE_BINOP(addss);
      break;
    case kSSEFloat32Sub:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_SSE_BINOP(subss);
      break;
    case kSSEFloat32Mul:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_SSE_BINOP(mulss);
      break;
    case kSSEFloat32Div:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_SSE_BINOP(divss);
      // Don't delete this mov. It may improve performance on some CPUs,
      // when there is a (v)mulss depending on the result.
      __ movaps(i.OutputDoubleRegister(), i.OutputDoubleRegister());
      break;
    case kSSEFloat32Sqrt:
      ASSEMBLE_SSE_UNOP(sqrtss);
      break;
    case kSSEFloat32ToFloat64:
      ASSEMBLE_SSE_UNOP(Cvtss2sd);
      break;
    case kSSEFloat32Round: {
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundss(i.OutputDoubleRegister(), i.InputDoubleRegister(0), mode);
      break;
    }
    case kSSEFloat32ToInt32:
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Cvttss2si(i.OutputRegister(), i.InputDoubleRegister(0));
      } else {
        __ Cvttss2si(i.OutputRegister(), i.InputOperand(0));
      }
      break;
    case kSSEFloat32ToUint32: {
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Cvttss2siq(i.OutputRegister(), i.InputDoubleRegister(0));
      } else {
        __ Cvttss2siq(i.OutputRegister(), i.InputOperand(0));
      }
      break;
    }
    case kSSEFloat64Cmp:
      ASSEMBLE_SSE_BINOP(Ucomisd);
      break;
    case kSSEFloat64Add:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_SSE_BINOP(addsd);
      break;
    case kSSEFloat64Sub:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_SSE_BINOP(subsd);
      break;
    case kSSEFloat64Mul:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_SSE_BINOP(mulsd);
      break;
    case kSSEFloat64Div:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_SSE_BINOP(divsd);
      // Don't delete this mov. It may improve performance on some CPUs,
      // when there is a (v)mulsd depending on the result.
      __ Movapd(i.OutputDoubleRegister(), i.OutputDoubleRegister());
      break;
    case kSSEFloat64Mod: {
      __ AllocateStackSpace(kDoubleSize);
      unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                       kDoubleSize);
      // Move values to st(0) and st(1).
      __ Movsd(Operand(rsp, 0), i.InputDoubleRegister(1));
      __ fld_d(Operand(rsp, 0));
      __ Movsd(Operand(rsp, 0), i.InputDoubleRegister(0));
      __ fld_d(Operand(rsp, 0));
      // Loop while fprem isn't done.
      Label mod_loop;
      __ bind(&mod_loop);
      // This instructions traps on all kinds inputs, but we are assuming the
      // floating point control word is set to ignore them all.
      __ fprem();
      // The following 2 instruction implicitly use rax.
      __ fnstsw_ax();
      if (CpuFeatures::IsSupported(SAHF)) {
        CpuFeatureScope sahf_scope(masm(), SAHF);
        __ sahf();
      } else {
        __ shrl(rax, Immediate(8));
        __ andl(rax, Immediate(0xFF));
        __ pushq(rax);
        unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                         kSystemPointerSize);
        __ popfq();
        unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                         -kSystemPointerSize);
      }
      __ j(parity_even, &mod_loop);
      // Move output to stack and clean up.
      __ fstp(1);
      __ fstp_d(Operand(rsp, 0));
      __ Movsd(i.OutputDoubleRegister(), Operand(rsp, 0));
      __ addq(rsp, Immediate(kDoubleSize));
      unwinding_info_writer_.MaybeIncreaseBaseOffsetAt(__ pc_offset(),
                                                       -kDoubleSize);
      break;
    }
    case kSSEFloat32Max: {
      Label compare_swap, done_compare;
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Ucomiss(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Ucomiss(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      auto ool =
          zone()->New<OutOfLineLoadFloat32NaN>(this, i.OutputDoubleRegister());
      __ j(parity_even, ool->entry());
      __ j(above, &done_compare, Label::kNear);
      __ j(below, &compare_swap, Label::kNear);
      __ Movmskps(kScratchRegister, i.InputDoubleRegister(0));
      __ testl(kScratchRegister, Immediate(1));
      __ j(zero, &done_compare, Label::kNear);
      __ bind(&compare_swap);
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Movss(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Movss(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      __ bind(&done_compare);
      __ bind(ool->exit());
      break;
    }
    case kSSEFloat32Min: {
      Label compare_swap, done_compare;
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Ucomiss(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Ucomiss(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      auto ool =
          zone()->New<OutOfLineLoadFloat32NaN>(this, i.OutputDoubleRegister());
      __ j(parity_even, ool->entry());
      __ j(below, &done_compare, Label::kNear);
      __ j(above, &compare_swap, Label::kNear);
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Movmskps(kScratchRegister, i.InputDoubleRegister(1));
      } else {
        __ Movss(kScratchDoubleReg, i.InputOperand(1));
        __ Movmskps(kScratchRegister, kScratchDoubleReg);
      }
      __ testl(kScratchRegister, Immediate(1));
      __ j(zero, &done_compare, Label::kNear);
      __ bind(&compare_swap);
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Movss(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Movss(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      __ bind(&done_compare);
      __ bind(ool->exit());
      break;
    }
    case kSSEFloat64Max: {
      Label compare_swap, done_compare;
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Ucomisd(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Ucomisd(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      auto ool =
          zone()->New<OutOfLineLoadFloat64NaN>(this, i.OutputDoubleRegister());
      __ j(parity_even, ool->entry());
      __ j(above, &done_compare, Label::kNear);
      __ j(below, &compare_swap, Label::kNear);
      __ Movmskpd(kScratchRegister, i.InputDoubleRegister(0));
      __ testl(kScratchRegister, Immediate(1));
      __ j(zero, &done_compare, Label::kNear);
      __ bind(&compare_swap);
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Movsd(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Movsd(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      __ bind(&done_compare);
      __ bind(ool->exit());
      break;
    }
    case kSSEFloat64Min: {
      Label compare_swap, done_compare;
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Ucomisd(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Ucomisd(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      auto ool =
          zone()->New<OutOfLineLoadFloat64NaN>(this, i.OutputDoubleRegister());
      __ j(parity_even, ool->entry());
      __ j(below, &done_compare, Label::kNear);
      __ j(above, &compare_swap, Label::kNear);
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Movmskpd(kScratchRegister, i.InputDoubleRegister(1));
      } else {
        __ Movsd(kScratchDoubleReg, i.InputOperand(1));
        __ Movmskpd(kScratchRegister, kScratchDoubleReg);
      }
      __ testl(kScratchRegister, Immediate(1));
      __ j(zero, &done_compare, Label::kNear);
      __ bind(&compare_swap);
      if (instr->InputAt(1)->IsFPRegister()) {
        __ Movsd(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Movsd(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      __ bind(&done_compare);
      __ bind(ool->exit());
      break;
    }
    case kSSEFloat64Sqrt:
      ASSEMBLE_SSE_UNOP(Sqrtsd);
      break;
    case kSSEFloat64Round: {
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundsd(i.OutputDoubleRegister(), i.InputDoubleRegister(0), mode);
      break;
    }
    case kSSEFloat64ToFloat16RawBits: {
      XMMRegister tmp_dst = i.TempDoubleRegister(0);
      __ Cvtpd2ph(tmp_dst, i.InputDoubleRegister(0), i.TempRegister(1));
      __ Pextrw(i.OutputRegister(), tmp_dst, static_cast<uint8_t>(0));
      break;
    }
    case kSSEFloat64ToFloat32:
      ASSEMBLE_SSE_UNOP(Cvtsd2ss);
      break;
    case kSSEFloat64ToInt32: {
      Register output_reg = i.OutputRegister(0);
      if (instr->OutputCount() == 1) {
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Cvttsd2si(i.OutputRegister(), i.InputDoubleRegister(0));
        } else {
          __ Cvttsd2si(i.OutputRegister(), i.InputOperand(0));
        }
        break;
      }
      DCHECK_EQ(2, instr->OutputCount());
      Register success_reg = i.OutputRegister(1);
      if (CpuFeatures::IsSupported(SSE4_1) || CpuFeatures::IsSupported(AVX)) {
        DoubleRegister rounded = kScratchDoubleReg;
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Roundsd(rounded, i.InputDoubleRegister(0), kRoundToZero);
          __ Cvttsd2si(output_reg, i.InputDoubleRegister(0));
        } else {
          __ Roundsd(rounded, i.InputOperand(0), kRoundToZero);
          // Convert {rounded} instead of the input operand, to avoid another
          // load.
          __ Cvttsd2si(output_reg, rounded);
        }
        DoubleRegister converted_back = i.TempSimd128Register(0);
        __ Cvtlsi2sd(converted_back, output_reg);
        // Compare the converted back value to the rounded value, set
        // success_reg to 0 if they differ, or 1 on success.
        __ Cmpeqsd(converted_back, rounded);
        __ Movq(success_reg, converted_back);
        __ And(success_reg, Immediate(1));
      } else {
        // Less efficient code for non-AVX and non-SSE4_1 CPUs.
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Cvttsd2si(i.OutputRegister(0), i.InputDoubleRegister(0));
        } else {
          __ Cvttsd2si(i.OutputRegister(0), i.InputOperand(0));
        }
        __ Move(success_reg, 1);
        Label done;
        Label fail;
        __ Move(kScratchDoubleReg, double{INT32_MIN});
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Ucomisd(kScratchDoubleReg, i.InputDoubleRegister(0));
        } else {
          __ Ucomisd(kScratchDoubleReg, i.InputOperand(0));
        }
        // If the input is NaN, then the conversion fails.
        __ j(parity_even, &fail, Label::kNear);
        // If the input is INT32_MIN, then the conversion succeeds.
        __ j(equal, &done, Labe
```