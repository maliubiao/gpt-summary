Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a larger file, implying that the first part likely handles the initial setup and other core functionalities. This part seems to focus on the code generation for specific architecture instructions (x64).

Here's a breakdown of the thought process to summarize the functionality:

1. **Identify the core purpose:** The code is within a `switch` statement based on the `arch_opcode`. This strongly suggests that the code handles the generation of machine code for different architectural instructions. The surrounding context, including `CodeGeneratorX64`, confirms this.

2. **Analyze the cases:**  Go through each `case` in the `switch` statement and understand what it does. Look for patterns and group similar instructions.

    * **Control Flow:** Instructions like `kArchTailCallWasm`, `kArchTailCallCodeObject`, `kArchTailCallAddress`, `kArchCallJSFunction`, `kArchPrepareCallCFunction`, `kArchCallCFunction`, `kArchJmp`, `kArchBinarySearchSwitch`, `kArchTableSwitch`, `kArchRet`, `kArchDeoptimize` clearly deal with program control flow (calls, jumps, returns, deoptimization).

    * **Stack Manipulation:** `kArchPrepareCallCFunction`, `kArchSaveCallerRegisters`, `kArchRestoreCallerRegisters`, `kArchPrepareTailCall`, `kArchStackPointer`, `kArchSetStackPointer`, `kArchFramePointer`, `kArchParentFramePointer`, `kArchStackSlot`, `kArchStackPointerGreaterThan`, `kArchStackCheckOffset`, `kX64Push` deal with managing the call stack and accessing data within it.

    * **Memory Operations:**  Instructions like `kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`, `kArchStoreIndirectWithWriteBarrier`, `kX64Movb`, `kX64Movw`, `kX64Movl`, `kX64Movq`, `kX64Movss`, `kX64Movsd`, `kX64Movdqu` handle moving data to and from memory. The "WriteBarrier" instructions are specifically for garbage collection.

    * **Arithmetic and Logical Operations:** Instructions prefixed with `kX64` like `kX64Add`, `kX64Sub`, `kX64And`, `kX64Or`, `kX64Xor`, `kX64Shl`, `kX64Shr`, `kX64Sar`, `kX64Imul`, `kX64Idiv`, `kX64Not`, `kX64Neg` are standard integer arithmetic and logical operations.

    * **Floating-Point Operations:** Instructions starting with `kSSEFloat` and `kAVXFloat` handle floating-point arithmetic, comparisons, conversions, and other operations using SSE and AVX instruction sets. Instructions like `kIeee754Float64Acos` also fall into this category, likely using library functions.

    * **Conversions and Bit Manipulation:** Instructions like `kArchTruncateDoubleToI`, `kX64Movsxbl`, `kX64Movzxbl`, `kX64Bswap`, `kX64BitcastFI`, `kX64BitcastDL` deal with converting between data types and manipulating bits.

    * **Special Instructions:**  Instructions like `kArchComment`, `kArchAbortCSADcheck`, `kArchDebugBreak`, `kArchThrowTerminator`, `kArchNop`, `kX64MFence`, `kX64LFence`, `kX64Lea` serve specific purposes like adding comments, debugging, memory barriers, and address calculation.

3. **Identify JavaScript relevance:**  Many of these low-level operations are fundamental to how JavaScript code is executed. Function calls, memory allocation (handled by the write barriers), arithmetic operations, and type conversions are all part of the JavaScript runtime. Focus on a few clear examples.

4. **Formulate the summary:** Combine the observations into a concise description of the code's function. Emphasize that it's responsible for generating machine code for the x64 architecture based on higher-level instructions.

5. **Create JavaScript examples:**  Choose simple JavaScript snippets that would necessitate the execution of some of the identified instruction types. Function calls, basic arithmetic, and type conversions are good candidates. Explain *why* these examples relate to the generated code.

6. **Review and refine:** Ensure the summary is accurate, clear, and addresses the user's request. Check for any missing key functionalities. Make sure the JavaScript examples are relevant and easy to understand.
This C++代码片段是 `CodeGeneratorX64` 类中处理指令生成逻辑的一部分，具体负责将中间表示（IR）的指令转换为 x64 架构的机器码。 这是第二部分，它涵盖了各种架构特定的指令的处理。

**功能归纳：**

这段代码的主要功能是：

* **处理各种架构相关的操作码 (ArchOpcode):**  通过一个巨大的 `switch` 语句，针对不同的 `arch_opcode`，生成相应的 x64 汇编指令。
* **控制流指令生成:**  处理函数调用（包括 JavaScript 函数和 C 函数）、尾调用、跳转（包括直接跳转、基于表的跳转和二分查找跳转）、返回和异常处理（如 deoptimization）。
* **栈帧管理:**  生成用于准备和清理函数调用栈帧的代码，包括保存和恢复寄存器、调整栈指针等。
* **内存操作:**  生成用于加载和存储数据的指令，包括带写屏障的内存写入操作，以支持垃圾回收机制。
* **算术和逻辑运算:**  生成各种整数和浮点数的算术运算（加、减、乘、除等）、位运算（与、或、异或、移位等）和比较运算的指令。
* **浮点数运算 (SSE/AVX):**  生成使用 SSE 和 AVX 指令集的浮点数运算指令，包括加、减、乘、除、平方根、三角函数、类型转换等。
* **类型转换:**  生成用于在不同数据类型之间进行转换的指令，例如整数和浮点数之间的转换。
* **位操作和字节序操作:**  生成用于位操作（例如，计算前导零、尾随零、 population count）和字节序转换的指令。
* **调试和断言:**  生成用于调试和断言的指令。
* **内联汇编:**  对于某些操作，直接嵌入汇编指令。
* **支持 WebAssembly (条件编译):**  包含一些用于处理 WebAssembly 相关尾调用的代码（通过 `#ifdef V8_ENABLE_WEBASSEMBLY` 控制）。

**与 JavaScript 的关系及 JavaScript 示例:**

这段代码直接参与了 V8 引擎执行 JavaScript 代码的过程。当 V8 编译 JavaScript 代码时，Turbofan 或 Crankshaft 等优化编译器会生成中间表示 (IR)。然后，`CodeGeneratorX64` 的这个部分会将这些 IR 指令转换成可以在 x64 架构的 CPU 上执行的实际机器码。

以下是一些 JavaScript 示例，以及它们如何与这段代码中生成的一些指令相关联：

**1. 函数调用:**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当调用 `add(5, 10)` 时，`kArchCallJSFunction` 或 `kArchTailCallCodeObject` 等指令会被使用，生成类似 `call` 或 `jmp` 的汇编指令，跳转到 `add` 函数的代码入口。`kArchPrepareCallCFunction` 和 `kArchCallCFunction` 则用于调用内置的 C++ 函数或运行时函数。

**2. 算术运算:**

```javascript
let x = 5;
let y = 10;
let sum = x + y;
```

对于 `x + y`，会生成 `kX64Add` 指令，对应 x64 的 `addq` 或 `addl` 指令，执行加法运算。

**3. 浮点数运算:**

```javascript
let pi = Math.PI;
let sin_pi = Math.sin(pi);
```

`Math.sin(pi)` 会导致生成 `kIeee754Float64Sin` 指令，该指令可能会调用底层的 C 库函数来计算正弦值。对于更底层的浮点数操作，例如两个浮点数相加，可能会生成 `kSSEFloat64Add` 或 `kAVXFloat64Add` 指令，使用 `addsd` 或 `vaddsd` 等 SSE/AVX 指令。

**4. 类型转换:**

```javascript
let num_str = "123.45";
let num = parseFloat(num_str);
let int_num = parseInt(num_str);
```

`parseFloat` 可能会涉及到将字符串转换为浮点数，这可能涉及到调用 C 库函数。`parseInt` 则需要将字符串转换为整数，可能会生成诸如 `kArchTruncateDoubleToI` 或 `kSSEFloat64ToInt32` 等指令，将浮点数或字符串表示的数字转换为整数，并处理可能的溢出情况。

**5. 内存访问和对象属性访问:**

```javascript
let obj = { a: 1, b: 2 };
let value = obj.a;
obj.c = 3;
```

访问 `obj.a` 可能会生成 `kX64Movq` 指令，从对象在内存中的特定偏移量加载属性值。给 `obj.c` 赋值可能会生成 `kX64Movq` 指令进行存储，并可能伴随 `kArchStoreWithWriteBarrier` 指令，确保垃圾回收器能正确追踪对象的变化。

**总结:**

这段代码是 V8 引擎将高级 JavaScript 代码转化为可在 x64 架构上执行的低级机器码的关键组成部分。 它处理了各种不同的操作，从基本的算术运算到复杂的函数调用和内存管理，所有这些都是为了高效地执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/compiler/backend/x64/code-generator-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
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
        __ j(equal, &done, Label::kNear);
        __ cmpl(output_reg, Immediate(1));
        // If the conversion results in INT32_MIN, but the input was not
        // INT32_MIN, then the conversion fails.
        __ j(no_overflow, &done, Label::kNear);
        __ bind(&fail);
        __ Move(success_reg, 0);
        __ bind(&done);
      }
      break;
    }
    case kSSEFloat64ToUint32: {
      Label fail;
      // Set Projection(1) to 0, denoting value out of range.
      if (instr->OutputCount() > 1) __ Move(i.OutputRegister(1), 0);
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Cvttsd2ui(i.OutputRegister(), i.InputDoubleRegister(0), &fail);
      } else {
        __ Cvttsd2ui(i.OutputRegister(), i.InputOperand(0), &fail);
      }
      // Set Projection(1) to 1, denoting value in range (otherwise the
      // conversion above would have jumped to `fail`), which is the success
      // case.
      if (instr->OutputCount() > 1) __ Move(i.OutputRegister(1), 1);
      __ bind(&fail);
      break;
    }
    case kSSEFloat32ToInt64: {
      Register output_reg = i.OutputRegister(0);
      if (instr->OutputCount() == 1) {
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Cvttss2siq(output_reg, i.InputDoubleRegister(0));
        } else {
          __ Cvttss2siq(output_reg, i.InputOperand(0));
        }
        break;
      }
      DCHECK_EQ(2, instr->OutputCount());
      Register success_reg = i.OutputRegister(1);
      if (CpuFeatures::IsSupported(SSE4_1) || CpuFeatures::IsSupported(AVX)) {
        DoubleRegister rounded = kScratchDoubleReg;
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Roundss(rounded, i.InputDoubleRegister(0), kRoundToZero);
          __ Cvttss2siq(output_reg, i.InputDoubleRegister(0));
        } else {
          __ Roundss(rounded, i.InputOperand(0), kRoundToZero);
          // Convert {rounded} instead of the input operand, to avoid another
          // load.
          __ Cvttss2siq(output_reg, rounded);
        }
        DoubleRegister converted_back = i.TempSimd128Register(0);
        __ Cvtqsi2ss(converted_back, output_reg);
        // Compare the converted back value to the rounded value, set
        // success_reg to 0 if they differ, or 1 on success.
        __ Cmpeqss(converted_back, rounded);
        __ Movq(success_reg, converted_back);
        __ And(success_reg, Immediate(1));
      } else {
        // Less efficient code for non-AVX and non-SSE4_1 CPUs.
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Cvttss2siq(i.OutputRegister(), i.InputDoubleRegister(0));
        } else {
          __ Cvttss2siq(i.OutputRegister(), i.InputOperand(0));
        }
        __ Move(success_reg, 1);
        Label done;
        Label fail;
        __ Move(kScratchDoubleReg, float{INT64_MIN});
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Ucomiss(kScratchDoubleReg, i.InputDoubleRegister(0));
        } else {
          __ Ucomiss(kScratchDoubleReg, i.InputOperand(0));
        }
        // If the input is NaN, then the conversion fails.
        __ j(parity_even, &fail, Label::kNear);
        // If the input is INT64_MIN, then the conversion succeeds.
        __ j(equal, &done, Label::kNear);
        __ cmpq(output_reg, Immediate(1));
        // If the conversion results in INT64_MIN, but the input was not
        // INT64_MIN, then the conversion fails.
        __ j(no_overflow, &done, Label::kNear);
        __ bind(&fail);
        __ Move(success_reg, 0);
        __ bind(&done);
      }
      break;
    }
    case kSSEFloat64ToInt64: {
      Register output_reg = i.OutputRegister(0);
      if (instr->OutputCount() == 1) {
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Cvttsd2siq(output_reg, i.InputDoubleRegister(0));
        } else {
          __ Cvttsd2siq(output_reg, i.InputOperand(0));
        }
        break;
      }
      DCHECK_EQ(2, instr->OutputCount());
      Register success_reg = i.OutputRegister(1);
      if (CpuFeatures::IsSupported(SSE4_1) || CpuFeatures::IsSupported(AVX)) {
        DoubleRegister rounded = kScratchDoubleReg;
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Roundsd(rounded, i.InputDoubleRegister(0), kRoundToZero);
          __ Cvttsd2siq(output_reg, i.InputDoubleRegister(0));
        } else {
          __ Roundsd(rounded, i.InputOperand(0), kRoundToZero);
          // Convert {rounded} instead of the input operand, to avoid another
          // load.
          __ Cvttsd2siq(output_reg, rounded);
        }
        DoubleRegister converted_back = i.TempSimd128Register(0);
        __ Cvtqsi2sd(converted_back, output_reg);
        // Compare the converted back value to the rounded value, set
        // success_reg to 0 if they differ, or 1 on success.
        __ Cmpeqsd(converted_back, rounded);
        __ Movq(success_reg, converted_back);
        __ And(success_reg, Immediate(1));
      } else {
        // Less efficient code for non-AVX and non-SSE4_1 CPUs.
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Cvttsd2siq(i.OutputRegister(0), i.InputDoubleRegister(0));
        } else {
          __ Cvttsd2siq(i.OutputRegister(0), i.InputOperand(0));
        }
        __ Move(success_reg, 1);
        Label done;
        Label fail;
        __ Move(kScratchDoubleReg, double{INT64_MIN});
        if (instr->InputAt(0)->IsFPRegister()) {
          __ Ucomisd(kScratchDoubleReg, i.InputDoubleRegister(0));
        } else {
          __ Ucomisd(kScratchDoubleReg, i.InputOperand(0));
        }
        // If the input is NaN, then the conversion fails.
        __ j(parity_even, &fail, Label::kNear);
        // If the input is INT64_MIN, then the conversion succeeds.
        __ j(equal, &done, Label::kNear);
        __ cmpq(output_reg, Immediate(1));
        // If the conversion results in INT64_MIN, but the input was not
        // INT64_MIN, then the conversion fails.
        __ j(no_overflow, &done, Label::kNear);
        __ bind(&fail);
        __ Move(success_reg, 0);
        __ bind(&done);
      }
      break;
    }
    case kSSEFloat32ToUint64: {
      // See kSSEFloat64ToUint32 for explanation.
      Label fail;
      if (instr->OutputCount() > 1) __ Move(i.OutputRegister(1), 0);
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Cvttss2uiq(i.OutputRegister(), i.InputDoubleRegister(0), &fail);
      } else {
        __ Cvttss2uiq(i.OutputRegister(), i.InputOperand(0), &fail);
      }
      if (instr->OutputCount() > 1) __ Move(i.OutputRegister(1), 1);
      __ bind(&fail);
      break;
    }
    case kSSEFloat64ToUint64: {
      // See kSSEFloat64ToUint32 for explanation.
      Label fail;
      if (instr->OutputCount() > 1) __ Move(i.OutputRegister(1), 0);
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Cvttsd2uiq(i.OutputRegister(), i.InputDoubleRegister(0), &fail);
      } else {
        __ Cvttsd2uiq(i.OutputRegister(), i.InputOperand(0), &fail);
      }
      if (instr->OutputCount() > 1) __ Move(i.OutputRegister(1), 1);
      __ bind(&fail);
      break;
    }
    case kSSEInt32ToFloat64:
      if (HasRegisterInput(instr, 0)) {
        __ Cvtlsi2sd(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Cvtlsi2sd(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kSSEInt32ToFloat32:
      if (HasRegisterInput(instr, 0)) {
        __ Cvtlsi2ss(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Cvtlsi2ss(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kSSEInt64ToFloat32:
      if (HasRegisterInput(instr, 0)) {
        __ Cvtqsi2ss(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Cvtqsi2ss(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kSSEInt64ToFloat64:
      if (HasRegisterInput(instr, 0)) {
        __ Cvtqsi2sd(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Cvtqsi2sd(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kSSEUint64ToFloat32:
      if (HasRegisterInput(instr, 0)) {
        __ Cvtqui2ss(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Cvtqui2ss(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kSSEUint64ToFloat64:
      if (HasRegisterInput(instr, 0)) {
        __ Cvtqui2sd(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Cvtqui2sd(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kSSEUint32ToFloat64:
      if (HasRegisterInput(instr, 0)) {
        __ Cvtlui2sd(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Cvtlui2sd(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kSSEUint32ToFloat32:
      if (HasRegisterInput(instr, 0)) {
        __ Cvtlui2ss(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Cvtlui2ss(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kSSEFloat64ExtractLowWord32:
      if (instr->InputAt(0)->IsFPStackSlot()) {
        __ movl(i.OutputRegister(), i.InputOperand(0));
      } else {
        __ Movd(i.OutputRegister(), i.InputDoubleRegister(0));
      }
      break;
    case kSSEFloat64ExtractHighWord32:
      if (instr->InputAt(0)->IsFPStackSlot()) {
        __ movl(i.OutputRegister(), i.InputOperand(0, kDoubleSize / 2));
      } else {
        __ Pextrd(i.OutputRegister(), i.InputDoubleRegister(0), 1);
      }
      break;
    case kSSEFloat64InsertLowWord32:
      if (HasRegisterInput(instr, 1)) {
        __ Pinsrd(i.OutputDoubleRegister(), i.InputRegister(1), 0);
      } else {
        __ Pinsrd(i.OutputDoubleRegister(), i.InputOperand(1), 0);
      }
      break;
    case kSSEFloat64InsertHighWord32:
      if (HasRegisterInput(instr, 1)) {
        __ Pinsrd(i.OutputDoubleRegister(), i.InputRegister(1), 1);
      } else {
        __ Pinsrd(i.OutputDoubleRegister(), i.InputOperand(1), 1);
      }
      break;
    case kSSEFloat64LoadLowWord32:
      if (HasRegisterInput(instr, 0)) {
        __ Movd(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Movd(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kAVXFloat32Cmp: {
      CpuFeatureScope avx_scope(masm(), AVX);
      if (instr->InputAt(1)->IsFPRegister()) {
        __ vucomiss(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ vucomiss(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      break;
    }
    case kAVXFloat32Add:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_AVX_BINOP(vaddss);
      break;
    case kAVXFloat32Sub:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_AVX_BINOP(vsubss);
      break;
    case kAVXFloat32Mul:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_AVX_BINOP(vmulss);
      break;
    case kAVXFloat32Div:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_AVX_BINOP(vdivss);
      // Don't delete this mov. It may improve performance on some CPUs,
      // when there is a (v)mulss depending on the result.
      __ Movaps(i.OutputDoubleRegister(), i.OutputDoubleRegister());
      break;
    case kAVXFloat64Cmp: {
      CpuFeatureScope avx_scope(masm(), AVX);
      if (instr->InputAt(1)->IsFPRegister()) {
        __ vucomisd(i.InputDoubleRegister(0), i.InputDoubleRegister(1));
      } else {
        __ vucomisd(i.InputDoubleRegister(0), i.InputOperand(1));
      }
      break;
    }
    case kAVXFloat64Add:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_AVX_BINOP(vaddsd);
      break;
    case kAVXFloat64Sub:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_AVX_BINOP(vsubsd);
      break;
    case kAVXFloat64Mul:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_AVX_BINOP(vmulsd);
      break;
    case kAVXFloat64Div:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_AVX_BINOP(vdivsd);
      // Don't delete this mov. It may improve performance on some CPUs,
      // when there is a (v)mulsd depending on the result.
      __ Movapd(i.OutputDoubleRegister(), i.OutputDoubleRegister());
      break;
    case kX64Float32Abs: {
      __ Absps(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               kScratchRegister);
      break;
    }
    case kX64Float32Neg: {
      __ Negps(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               kScratchRegister);
      break;
    }
    case kX64FAbs: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8Abs
            CpuFeatureScope avx_scope(masm(), AVX);
            __ Absph(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchRegister);
            break;
          }
          case kL32: {
            // F32x4Abs
            __ Absps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchRegister);
            break;
          }
          case kL64: {
            // F64x2Abs
            __ Abspd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                     kScratchRegister);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Abs
            YMMRegister dst = i.OutputSimd256Register();
            YMMRegister src = i.InputSimd256Register(0);
            CpuFeatureScope avx_scope(masm(), AVX2);
            if (dst == src) {
              __ vpcmpeqd(kScratchSimd256Reg, kScratchSimd256Reg,
                          kScratchSimd256Reg);
              __ vpsrld(kScratchSimd256Reg, kScratchSimd256Reg, uint8_t{1});
              __ vpand(dst, dst, kScratchSimd256Reg);
            } else {
              __ vpcmpeqd(dst, dst, dst);
              __ vpsrld(dst, dst, uint8_t{1});
              __ vpand(dst, dst, src);
            }
            break;
          }
          case kL64: {
            // F64x4Abs
            YMMRegister dst = i.OutputSimd256Register();
            YMMRegister src = i.InputSimd256Register(0);
            CpuFeatureScope avx_scope(masm(), AVX2);
            if (dst == src) {
              __ vpcmpeqq(kScratchSimd256Reg, kScratchSimd256Reg,
                          kScratchSimd256Reg);
              __ vpsrlq(kScratchSimd256Reg, kScratchSimd256Reg, uint8_t{1});
              __ vpand(dst, dst, kScratchSimd256Reg);
            } else {
              __ vpcmpeqq(dst, dst, dst);
              __ vpsrlq(dst, dst, uint8_t{1});
              __ vpand(dst, dst, src);
            }
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64Float64Abs: {
      __ Abspd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               kScratchRegister);
      break;
    }
    case kX64FNeg: {
      LaneSize lane_size = LaneSizeField::decode(opcode);
      VectorLength vec_len = VectorLengthField::decode(opcode);
      if (vec_len == kV128) {
        switch (lane_size) {
          case kL16: {
            // F16x8Neg
            CpuFeatureScope avx_scope(masm(), AVX);
            __ Negph(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchRegister);
            break;
          }
          case kL32: {
            // F32x4Neg
            __ Negps(i.OutputSimd128Register(), i.InputSimd128Register(0),
                     kScratchRegister);
            break;
          }
          case kL64: {
            // F64x2Neg
            __ Negpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                     kScratchRegister);
            break;
          }
          default:
            UNREACHABLE();
        }
      } else if (vec_len == kV256) {
        switch (lane_size) {
          case kL32: {
            // F32x8Neg
            YMMRegister dst = i.OutputSimd256Register();
            YMMRegister src = i.InputSimd256Register(0);
            CpuFeatureScope avx_scope(masm(), AVX2);
            if (dst == src) {
              __ vpcmpeqd(kScratchSimd256Reg, kScratchSimd256Reg,
                          kScratchSimd256Reg);
              __ vpslld(kScratchSimd256Reg, kScratchSimd256Reg, uint8_t{31});
              __ vpxor(dst, dst, kScratchSimd256Reg);
            } else {
              __ vpcmpeqd(dst, dst, dst);
              __ vpslld(dst, dst, uint8_t{31});
              __ vxorps(dst, dst, src);
            }
            break;
          }
          case kL64: {
            // F64x4Neg
            YMMRegister dst = i.OutputSimd256Register();
            YMMRegister src = i.InputSimd256Register(0);
            CpuFeatureScope avx_scope(masm(), AVX2);
            if (dst == src) {
              __ vpcmpeqq(kScratchSimd256Reg, kScratchSimd256Reg,
                          kScratchSimd256Reg);
              __ vpsllq(kScratchSimd256Reg, kScratchSimd256Reg, uint8_t{63});
              __ vpxor(dst, dst, kScratchSimd256Reg);
            } else {
              __ vpcmpeqq(dst, dst, dst);
              __ vpsllq(dst, dst, uint8_t{31});
              __ vxorpd(dst, dst, src);
            }
            break;
          }
          default:
            UNREACHABLE();
        }
      } else {
        UNREACHABLE();
      }
      break;
    }
    case kX64Float64Neg: {
      __ Negpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               kScratchRegister);
      break;
    }
    case kSSEFloat64SilenceNaN:
      __ Xorpd(kScratchDoubleReg, kScratchDoubleReg);
      __ Subsd(i.InputDoubleRegister(0), kScratchDoubleReg);
      break;
    case kX64Movsxbl:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movsxbl);
      __ AssertZeroExtended(i.OutputRegister());
      break;
    case kX64Movzxbl:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movzxbl);
      __ AssertZeroExtended(i.OutputRegister());
      break;
    case kX64Movsxbq:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movsxbq);
      break;
    case kX64Movzxbq:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movzxbq);
      __ AssertZeroExtended(i.OutputRegister());
      break;
    case kX64Movb: {
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      if (HasImmediateInput(instr, index)) {
        Immediate value(Immediate(i.InputInt8(index)));
        EmitTSANAwareStore<std::memory_order_relaxed>(
            zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
            MachineRepresentation::kWord8, instr);
      } else {
        Register value(i.InputRegister(index));
        EmitTSANAwareStore<std::memory_order_relaxed>(
            zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
            MachineRepresentation::kWord8, instr);
      }
      break;
    }
    case kX64Movsxwl:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movsxwl);
      __ AssertZeroExtended(i.OutputRegister());
      break;
    case kX64Movzxwl:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movzxwl);
      __ AssertZeroExtended(i.OutputRegister());
      break;
    case kX64Movsxwq:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movsxwq);
      break;
    case kX64Movzxwq:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movzxwq);
      __ AssertZeroExtended(i.OutputRegister());
      break;
    case kX64Movw: {
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      if (HasImmediateInput(instr, index)) {
        Immediate value(Immediate(i.InputInt16(index)));
        EmitTSANAwareStore<std::memory_order_relaxed>(
            zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
            MachineRepresentation::kWord16, instr);
      } else {
        Register value(i.InputRegister(index));
        EmitTSANAwareStore<std::memory_order_relaxed>(
            zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
            MachineRepresentation::kWord16, instr);
      }
      break;
    }
    case kX64Movl:
      if (instr->HasOutput()) {
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        if (HasAddressingMode(instr)) {
          Operand address(i.MemoryOperand());
          __ movl(i.OutputRegister(), address);
          EmitTSANRelaxedLoadOOLIfNeeded(zone(), this, masm(), address, i,
                                         DetermineStubCallMode(), kInt32Size);
        } else {
          if (HasRegisterInput(instr, 0)) {
            __ movl(i.OutputRegister(), i.InputRegister(0));
          } else {
            __ movl(i.OutputRegister(), i.InputOperand(0));
          }
        }
        __ AssertZeroExtended(i.OutputRegister());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        if (HasImmediateInput(instr, index)) {
          Immediate value(i.InputImmediate(index));
          EmitTSANAwareStore<std::memory_order_relaxed>(
              zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
              MachineRepresentation::kWord32, instr);
        } else {
          Register value(i.InputRegister(index));
          EmitTSANAwareStore<std::memory_order_relaxed>(
              zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
              MachineRepresentation::kWord32, instr);
        }
      }
      break;
    case kX64Movsxlq:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      ASSEMBLE_MOVX(movsxlq);
      break;
    case kX64MovqDecompressTaggedSigned: {
      CHECK(instr->HasOutput());
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      Operand address(i.MemoryOperand());
      __ DecompressTaggedSigned(i.OutputRegister(), address);
      EmitTSANRelaxedLoadOOLIfNeeded(zone(), this, masm(), address, i,
                                     DetermineStubCallMode(), kTaggedSize);
      break;
    }
    case kX64MovqDecompressTagged: {
      CHECK(instr->HasOutput());
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      Operand address(i.MemoryOperand());
      __ DecompressTagged(i.OutputRegister(), address);
      EmitTSANRelaxedLoadOOLIfNeeded(zone(), this, masm(), address, i,
                                     DetermineStubCallMode(), kTaggedSize);
      break;
    }
    case kX64MovqCompressTagged: {
      // {EmitTSANAwareStore} calls RecordTrapInfoIfNeeded. No need to do it
      // here.
      CHECK(!instr->HasOutput());
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      if (HasImmediateInput(instr, index)) {
        Immediate value(i.InputImmediate(index));
        EmitTSANAwareStore<std::memory_order_relaxed>(
            zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
            MachineRepresentation::kTagged, instr);
      } else {
        Register value(i.InputRegister(index));
        EmitTSANAwareStore<std::memory_order_relaxed>(
            zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
            MachineRepresentation::kTagged, instr);
      }
      break;
    }
    case kX64MovqDecompressProtected: {
      CHECK(instr->HasOutput());
      Operand address(i.MemoryOperand());
      __ DecompressProtected(i.OutputRegister(), address);
      EmitTSANRelaxedLoadOOLIfNeeded(zone(), this, masm(), address, i,
                                     DetermineStubCallMode(), kTaggedSize);
      break;
    }
    case kX64MovqStoreIndirectPointer: {
      CHECK(!instr->HasOutput());
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      CHECK(!HasImmediateInput(instr, index));
      Register value(i.InputRegister(index));
      EmitTSANAwareStore<std::memory_order_relaxed>(
          zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
          MachineRepresentation::kIndirectPointer, instr);
      break;
    }
    case kX64MovqDecodeSandboxedPointer: {
      CHECK(instr->HasOutput());
      Operand address(i.MemoryOperand());
      Register dst = i.OutputRegister();
      __ movq(dst, address);
      __ DecodeSandboxedPointer(dst);
      EmitTSANRelaxedLoadOOLIfNeeded(zone(), this, masm(), address, i,
                                     DetermineStubCallMode(),
                                     kSystemPointerSize);
      break;
    }
    case kX64MovqEncodeSandboxedPointer: {
      CHECK(!instr->HasOutput());
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      CHECK(!HasImmediateInput(instr, index));
      Register value(i.InputRegister(index));
      EmitTSANAwareStore<std::memory_order_relaxed>(
          zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
          MachineRepresentation::kSandboxedPointer, instr);
      break;
    }
    case kX64Movq:
      if (instr->HasOutput()) {
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        Operand address(i.MemoryOperand());
        __ movq(i.OutputRegister(), address);
        EmitTSANRelaxedLoadOOLIfNeeded(zone(), this, masm(), address, i,
                                       DetermineStubCallMode(), kInt64Size);
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        if (HasImmediateInput(instr, index)) {
          Immediate value(i.InputImmediate(index));
          EmitTSANAwareStore<std::memory_order_relaxed>(
              zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
              MachineRepresentation::kWord64, instr);
        } else {
          Register value(i.InputRegister(index));
          EmitTSANAwareStore<std::memory_order_relaxed>(
              zone(), this, masm(), operand, value, i, DetermineStubCallMode(),
              MachineRepresentation::kWord64, instr);
        }
      }
      break;
    case kX64Movsh:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      if (instr->HasOutput()) {
        CpuFeatureScope f16c_scope(masm(), F16C);
        CpuFeatureScope avx2_scope(masm(), AVX2);
        __ vpbroadcastw(i.OutputDoubleRegister(), i.MemoryOperand());
        __ vcvtph2ps(i.OutputDoubleRegister(), i.OutputDoubleRegister());
      } else {
        CpuFeatureScope f16c_scope(masm(), F16C);
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ vcvtps2ph(kScratchDoubleReg, i.InputDoubleRegister(index), 0);
        __ Pextrw(operand, kScratchDoubleReg, static_cast<uint8_t>(0));
      }
      break;
    case kX64Movss:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      if (instr->HasOutput()) {
        __ Movss(i.OutputDoubleRegister(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ Movss(operand, i.InputDoubleRegister(index));
      }
      break;
    case kX64Movsd: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      if (instr->HasOutput()) {
        __ Movsd(i.OutputDoubleRegister(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ Movsd(operand, i.InputDoubleRegister(index));
      }
      break;
    }
    case kX64Movdqu: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      if (instr->HasOutput()) {
        __ Movdqu(i.OutputSimd128Register(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ Movdqu(operand, i.InputSimd128Register(index));
      }
      break;
    }
    case kX64BitcastFI:
      if (instr->InputAt(0)->IsFPStackSlot()) {
        __ movl(i.OutputRegister(), i.InputOperand(0));
      } else {
        __ Movd(i.OutputRegister(), i.InputDoubleRegister(0));
      }
      break;
    case kX64BitcastDL:
      if (instr->InputAt(0)->IsFPStackSlot()) {
        __ movq(i.OutputRegister(), i.InputOperand(0));
      } else {
        __ Movq(i.OutputRegister(), i.InputDoubleRegister(0));
      }
      break;
    case kX64BitcastIF:
      if (HasRegisterInput(instr, 0)) {
        __ Movd(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Movss(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kX64BitcastLD:
      if (HasRegisterInput(instr, 0)) {
        __ Movq(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Movsd(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kX64Lea32: {
      AddressingMode mode = AddressingModeField::decode(instr->opcode());
      // Shorten "leal" to "addl", "subl" or "shll" if the register allocation
      // and addressing mode just happens to work out. The "addl"/"subl" forms
      // in these cases are faster based on measurements.
      if (i.InputRegister(0) == i.OutputRegister()) {
        if (mode == kMode_MRI) {
          int32_t constant_summand = i.InputInt32(1);
          DCHECK_NE(0, constant_summand);
          if (constant_summand > 0) {
            __ addl(i.OutputRegister(), Immediate(constant_summand));
          } else {
            __ subl(i.OutputRegister(),
                    Immediate(base::NegateWithWraparound(constant_summand)));
          }
        } else if (mode == kMode_MR1) {
          if (i.InputRegister(1) == i.OutputRegister()) {
            __ shll(i.OutputRegister(), Immediate(1));
          } else {
            __ addl(i.OutputRegister(), i.InputRegister(1));
          }
        } else if (mode == kMode_M2) {
          __ shll(i.OutputRegister(), Immediate(1));
        } else if (mode == kMode_M4) {
          __ shll(i.OutputRegister(), Immediate(2));
        } else if (mode == kMode_M8) {
          __ shll(i.OutputRegister(), Immediate(3));
        } else {
          __ leal(i.OutputRegister(), i.MemoryOperand());
        }
      } else if (mode == kMode_MR1 &&
                 i.InputRegister(1) == i.OutputRegister()) {
        __ addl(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ leal(i.OutputRegister(), i.MemoryOperand());
      }
      __ AssertZeroExtended(i.OutputRegister());
      break;
    }
    case kX64Lea: {
      AddressingMode mode = AddressingModeField::decode(instr->opcode());
      // Shorten "leaq" to "addq", "subq" or "shlq" if the register allocation
      // and addressing mode just happens to work out. The "addq"/"subq" forms
      // in these cases are faster based on measurements.
      if (i.InputRegister(0) == i.OutputRegister()) {
        if (mode == kMode_MRI) {
          int32_t constant_summand = i.InputInt32(1);
          if (constant_summand > 0) {
            __ addq(i.OutputRegister(), Immediate(constant_summand));
          } else if (constant_summand < 0) {
            __ subq(i.OutputRegister(), Immediate(-constant_summand));
          }
        } else if (mode == kMode_MR1) {
          if (i.InputRegister(1) == i.OutputRegister()) {
            __ shlq(i.OutputRegister(), Immediate(1));
          } else {
            __ addq(i.OutputRegister(), i.InputRegister(1));
          }
        } else if (mode == kMode_M2) {
          __ shlq(i.OutputRegister(), Immediate(1));
        } else if (mode == kMode_M4) {
          __ shlq(i.OutputRegister(), Immediate(2));
        } else if (mode == kMode_M8) {
          __ shlq(i.OutputRegister(), Immediate(3));
        } else {
          __ leaq(i.OutputRegister(), i.MemoryOperand());
        }
      } else if (mode == kMode_MR1 &&
                 i.InputRegister(1) == i.OutputRegister()) {
        __ addq(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ leaq(i.OutputRegister(), i.MemoryOperand());
      }
      break;
    }
    case kX64Dec32:
      __ decl(i.OutputRegister());
      break;
    case kX64Inc32:
      __ incl(i.OutputRegister());
      break;
    case kX64Push: {
      int stack_decrement = i.InputInt32(0);
      int slots = stack_decrement / kSystemPointerSize;
      // Whenever codegen uses pushq, we need to check if stack
"""


```