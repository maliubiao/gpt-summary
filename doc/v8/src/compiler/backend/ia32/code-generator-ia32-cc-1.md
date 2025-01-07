Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the File:** The file is `v8/src/compiler/backend/ia32/code-generator-ia32.cc`. The path suggests it's responsible for generating IA-32 (x86) assembly code during the compilation process in V8's backend.

2. **Examine the Structure:** The code is a large `switch` statement. The `case` labels correspond to different instruction kinds (e.g., `kArchSaveCallerRegisters`, `kArchCallCFunction`, `kIA32Add`, `kFloat64Cmp`). This immediately tells us the code is handling the translation of high-level instructions into low-level IA-32 assembly.

3. **Analyze Individual Cases:** Go through some of the representative cases to understand the specific actions being performed:
    * `kArchSaveCallerRegisters`: Increases the stack pointer and likely saves registers.
    * `kArchRestoreCallerRegisters`: Decreases the stack pointer and restores registers.
    * `kArchCallCFunction`: Handles calling C functions, managing parameters, and recording safepoints for garbage collection.
    * `kArchJmp`: Generates an unconditional jump.
    * `kIA32Add`, `kIA32Sub`, etc.: These are basic arithmetic and logical operations. The `ASSEMBLE_BINOP` macro suggests a pattern for handling binary operations.
    * `kIA32Cmp`: Handles comparisons. The `ASSEMBLE_COMPARE` macro indicates a pattern for comparison instructions.
    * `kFloat64Cmp`, `kFloat32Add`, etc.:  These deal with floating-point operations, using specific IA-32 instructions like `Ucomisd`, `Addss`, etc.
    * `kIA32Movl`, `kIA32Movsd`:  These handle moving data between registers and memory.

4. **Look for Patterns and Common Themes:**
    * **Stack Management:** Several cases deal with manipulating the stack pointer (`esp`, `ebp`), saving and restoring registers, and allocating stack space.
    * **Function Calls:**  The `kArchCallCFunction` case is a key example, but the save/restore register cases also relate to function calling conventions.
    * **Arithmetic and Logical Operations:** A large number of cases handle basic CPU operations.
    * **Floating-Point Operations:**  A significant portion of the code is dedicated to handling various floating-point instructions.
    * **Memory Access:**  Cases like `kIA32Movl`, `kIA32Movsd`, and `kArchStoreWithWriteBarrier` deal with reading from and writing to memory. The write barrier is related to garbage collection.
    * **Control Flow:** Cases like `kArchJmp`, `kArchBinarySearchSwitch`, and `kArchTableSwitch` handle branching and control flow.
    * **Deoptimization:** The `kArchDeoptimize` case handles the process of switching from optimized code back to interpreted code.

5. **Address Specific Questions from the Prompt:**
    * **`.tq` extension:** The code snippet is `.cc`, so it's not a Torque file.
    * **JavaScript Relationship:** The generated assembly code directly implements the functionality of JavaScript code. Think about a simple JavaScript addition (`a + b`). This code generator would produce the IA-32 instructions to perform that addition.
    * **Code Logic and Examples:**  Simple arithmetic operations are the easiest to illustrate. The provided examples in the prompt are good starting points.
    * **Common Programming Errors:** Focus on errors related to memory management, type mismatches (especially with floating-point), and incorrect function calls.

6. **Synthesize the Summary:** Combine the observations into a concise description of the code's purpose. Emphasize the core responsibility of translating high-level instructions into assembly.

7. **Structure the Output:** Organize the summary into logical points, addressing the user's specific questions. Use clear and understandable language. Avoid overly technical jargon where possible.

By following these steps, we can effectively analyze the code snippet and generate a comprehensive and accurate summary of its functionality. The iterative process of looking at individual cases and then identifying broader patterns is key to understanding large code blocks like this.
Based on the provided C++ code snippet from `v8/src/compiler/backend/ia32/code-generator-ia32.cc`, here's a summary of its functionality:

**Functionality Summary (Part 2):**

This part of the `code-generator-ia32.cc` file primarily focuses on **generating IA-32 assembly code for a wide range of instructions**. It acts as a translator, taking high-level, architecture-independent instructions and emitting the corresponding low-level IA-32 machine code.

Here's a breakdown of the key functionalities covered in this section:

* **Stack Frame Management:** It handles instructions related to saving and restoring caller-saved registers (`kArchSaveCallerRegisters`, `kArchRestoreCallerRegisters`) and preparing for tail calls (`kArchPrepareTailCall`).
* **Calling C Functions:** It deals with generating code to call C functions (`kArchCallCFunction`, `kArchCallCFunctionWithFrameState`), including setting up parameters and recording safepoints for garbage collection. It also considers WebAssembly C API function calls.
* **Control Flow:** It implements instructions for unconditional jumps (`kArchJmp`) and various switch statement implementations (`kArchBinarySearchSwitch`, `kArchTableSwitch`).
* **Debugging and Diagnostics:** It includes support for inserting comments (`kArchComment`), aborting with a CSA check (`kArchAbortCSADcheck`), and triggering debug breaks (`kArchDebugBreak`).
* **No-Operation and Termination:** It handles no-op instructions (`kArchNop`) and instructions indicating termination (`kArchThrowTerminator`).
* **Deoptimization:** It generates code for deoptimizing, transitioning from optimized code back to interpreted code (`kArchDeoptimize`).
* **Returning from Functions:** It implements the return instruction (`kArchRet`).
* **Accessing Frame Pointers:** It provides instructions to access the current frame pointer (`kArchFramePointer`) and the parent frame pointer (`kArchParentFramePointer`).
* **Stack Pointer Manipulation:**  For WebAssembly, it includes instructions to get (`kArchStackPointer`) and set (`kArchSetStackPointer`) the stack pointer.
* **Stack Overflow Checks:** It generates code for checking if the stack pointer exceeds a certain limit (`kArchStackPointerGreaterThan`) and calculating the stack check offset (`kArchStackCheckOffset`).
* **Type Conversion:** It handles instructions for truncating doubles to integers (`kArchTruncateDoubleToI`).
* **Memory Operations with Write Barriers:** It generates code for storing values in memory, including handling write barriers for garbage collection (`kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`).
* **Stack Slot Access:** It calculates the address of a specific stack slot (`kArchStackSlot`).
* **IEEE 754 Floating-Point Operations:** This section contains a large number of cases for implementing various floating-point operations like `acos`, `acosh`, `asin`, `asinh`, `atan`, `atanh`, `atan2`, `cbrt`, `cos`, `cosh`, `exp`, `expm1`, `log`, `log1p`, `log2`, `log10`, `pow`, `sin`, `sinh`, `tan`, `tanh`, `sqrt`, and `mod`.
* **Integer Arithmetic and Logic Operations:**  It implements a wide range of integer operations like addition (`kIA32Add`), subtraction (`kIA32Sub`), multiplication (`kIA32Imul`, `kIA32UmulHigh`), division (`kIA32Idiv`, `kIA32Udiv`), bitwise operations (`kIA32And`, `kIA32Or`, `kIA32Xor`, `kIA32Not`), shifts (`kIA32Shl`, `kIA32Shr`, `kIA32Sar`), and others. It also handles operations on pairs of registers for wider integers.
* **Bit Manipulation Instructions:**  It includes instructions for counting leading zeros (`kIA32Lzcnt`), counting trailing zeros (`kIA32Tzcnt`), and counting set bits (`kIA32Popcnt`), as well as byte swapping (`kIA32Bswap`).
* **Memory Barriers:** It includes instructions for memory barriers (`kIA32MFence`, `kIA32LFence`).
* **Floating-Point Comparisons:** It generates code for comparing single-precision (`kIA32Float32Cmp`) and double-precision (`kIA32Float64Cmp`) floating-point numbers.
* **Floating-Point Min/Max:** It implements instructions for finding the minimum (`kIA32Float32Min`, `kIA32Float64Min`) and maximum (`kIA32Float32Max`, `kIA32Float64Max`) of two floating-point numbers, handling NaN cases correctly.
* **Floating-Point Conversions:** It includes instructions for converting between different floating-point types (`kIA32Float32ToFloat64`, `kIA32Float64ToFloat32`) and between floating-point and integer types (`kIA32Float32ToInt32`, `kIA32Float32ToUint32`, `kIA32Float64ToInt32`, `kIA32Float64ToUint32`, `kSSEInt32ToFloat32`, `kIA32Uint32ToFloat32`, `kSSEInt32ToFloat64`, `kIA32Uint32ToFloat64`).
* **Floating-Point Register Manipulation:** It provides instructions for extracting and inserting the low and high 32-bit words of a 64-bit floating-point number (`kIA32Float64ExtractLowWord32`, `kIA32Float64ExtractHighWord32`, `kIA32Float64InsertLowWord32`, `kIA32Float64InsertHighWord32`, `kIA32Float64FromWord32Pair`, `kIA32Float64LoadLowWord32`).
* **Basic Floating-Point Arithmetic:** It implements basic arithmetic operations for single-precision (`kFloat32Add`, `kFloat32Sub`, `kFloat32Mul`, `kFloat32Div`) and double-precision (`kFloat64Add`, `kFloat64Sub`, `kFloat64Mul`, `kFloat64Div`) floating-point numbers.
* **Floating-Point Absolute Value and Negation:** It includes instructions for calculating the absolute value (`kFloat32Abs`, `kFloat64Abs`) and negation (`kFloat32Neg`, `kFloat64Neg`) of floating-point numbers.
* **Silencing NaN:** It provides an instruction to silence NaN values (`kIA32Float64SilenceNaN`).
* **Move with Sign/Zero Extension:** It implements instructions for moving byte and word values to a larger register with sign extension (`kIA32Movsxbl`, `kIA32Movsxwl`) or zero extension (`kIA32Movzxbl`, `kIA32Movzxwl`).
* **Move Instructions (General):** It handles various move instructions for bytes (`kIA32Movb`), words (`kIA32Movw`), 32-bit integers (`kIA32Movl`), single-precision floats (`kIA32Movss`), double-precision floats (`kIA32Movsd`), and 128-bit SIMD registers (`kIA32Movdqu`).
* **Bitcast Instructions:** It allows reinterpreting the bits of a floating-point value as an integer and vice-versa (`kIA32BitcastFI`, `kIA32BitcastIF`).
* **Load Effective Address (LEA):** It implements the `lea` instruction for calculating memory addresses (`kIA32Lea`). It also attempts to optimize `lea` instructions into simpler `add`, `sub`, or `shl` instructions when possible.
* **Push Instruction:** It handles the `push` instruction, including allocating stack space and pushing various data types onto the stack (`kIA32Push`).

**In summary, this part of the code generator is a core component responsible for the low-level details of translating high-level operations into executable IA-32 assembly code within the V8 JavaScript engine.** It covers a vast array of instructions needed for executing JavaScript code efficiently on IA-32 architectures.

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/code-generator-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/code-generator-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
me_access_state()->IncreaseSPDelta(bytes / kSystemPointerSize);
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
      int const num_parameters = ParamField::decode(instr->opcode()) +
                                 FPParamField::decode(instr->opcode());

      Label return_location;
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
#if V8_ENABLE_WEBASSEMBLY
      if (linkage()->GetIncomingDescriptor()->IsWasmCapiFunction()) {
        // Put the return address in a stack slot.
        Register scratch = eax;
        __ push(scratch);
        __ LoadLabelAddress(scratch, &return_location);
        __ mov(MemOperand(ebp, WasmExitFrameConstants::kCallingPCOffset),
               scratch);
        __ pop(scratch);
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (HasImmediateInput(instr, 0)) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset = __ CallCFunction(ref, num_parameters,
                                     set_isolate_data_slots, &return_location);
      } else {
        Register func = i.InputRegister(0);
        pc_offset = __ CallCFunction(func, num_parameters,
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
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt32(0)),
                       SourceLocation());
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == edx);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ int3();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchNop:
    case kArchThrowTerminator:
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
      __ mov(i.OutputRegister(), ebp);
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ mov(i.OutputRegister(), Operand(ebp, 0));
      } else {
        __ mov(i.OutputRegister(), ebp);
      }
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      __ mov(i.OutputRegister(), esp);
      break;
    case kArchSetStackPointer:
      if (instr->InputAt(0)->IsRegister()) {
        __ mov(esp, i.InputRegister(0));
      } else {
        __ mov(esp, i.InputOperand(0));
      }
      break;
#endif
    case kArchStackPointerGreaterThan: {
      // Potentially apply an offset to the current stack pointer before the
      // comparison to consider the size difference of an optimized frame versus
      // the contained unoptimized frames.
      Register lhs_register = esp;
      uint32_t offset;

      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = i.TempRegister(0);
        __ lea(lhs_register, Operand(esp, -1 * static_cast<int32_t>(offset)));
      }

      constexpr size_t kValueIndex = 0;
      if (HasAddressingMode(instr)) {
        __ cmp(lhs_register, i.MemoryOperand(kValueIndex));
      } else {
        __ cmp(lhs_register, i.InputRegister(kValueIndex));
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
          this, result, input, DetermineStubCallMode());
      __ cvttsd2si(result, Operand(input));
      __ cmp(result, 1);
      __ j(overflow, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreWithWriteBarrier:  // Fall thrugh.
    case kArchAtomicStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      Register value = i.InputRegister(index);
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ cmp(value, Immediate(kClearedWeakHeapObjectLower32));
        __ Check(not_equal, AbortReason::kOperandIsCleared);
      }

      auto ool = zone()->New<OutOfLineRecordWrite>(this, object, operand, value,
                                                   scratch0, scratch1, mode,
                                                   DetermineStubCallMode());
      if (arch_opcode == kArchStoreWithWriteBarrier) {
        __ mov(operand, value);
      } else {
        __ mov(scratch0, value);
        __ xchg(scratch0, operand);
      }
      if (mode > RecordWriteMode::kValueIsPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask,
                       not_zero, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier:
      UNREACHABLE();
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base = offset.from_stack_pointer() ? esp : ebp;
      __ lea(i.OutputRegister(), Operand(base, offset.offset()));
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
    case kIeee754Float64Expm1:
      ASSEMBLE_IEEE754_UNOP(expm1);
      break;
    case kIeee754Float64Exp:
      ASSEMBLE_IEEE754_UNOP(exp);
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
    case kIA32Add:
      ASSEMBLE_BINOP(add);
      break;
    case kIA32And:
      ASSEMBLE_BINOP(and_);
      break;
    case kIA32Cmp:
      ASSEMBLE_COMPARE(cmp);
      break;
    case kIA32Cmp16:
      ASSEMBLE_COMPARE(cmpw);
      break;
    case kIA32Cmp8:
      ASSEMBLE_COMPARE(cmpb);
      break;
    case kIA32Test:
      ASSEMBLE_COMPARE(test);
      break;
    case kIA32Test16:
      ASSEMBLE_COMPARE(test_w);
      break;
    case kIA32Test8:
      ASSEMBLE_COMPARE(test_b);
      break;
    case kIA32Imul:
      if (HasImmediateInput(instr, 1)) {
        __ imul(i.OutputRegister(), i.InputOperand(0), i.InputInt32(1));
      } else {
        __ imul(i.OutputRegister(), i.InputOperand(1));
      }
      break;
    case kIA32ImulHigh:
      __ imul(i.InputRegister(1));
      break;
    case kIA32UmulHigh:
      __ mul(i.InputRegister(1));
      break;
    case kIA32Idiv:
      __ cdq();
      __ idiv(i.InputOperand(1));
      break;
    case kIA32Udiv:
      __ Move(edx, Immediate(0));
      __ div(i.InputOperand(1));
      break;
    case kIA32Not:
      __ not_(i.OutputOperand());
      break;
    case kIA32Neg:
      __ neg(i.OutputOperand());
      break;
    case kIA32Or:
      ASSEMBLE_BINOP(or_);
      break;
    case kIA32Xor:
      ASSEMBLE_BINOP(xor_);
      break;
    case kIA32Sub:
      ASSEMBLE_BINOP(sub);
      break;
    case kIA32Shl:
      if (HasImmediateInput(instr, 1)) {
        __ shl(i.OutputOperand(), i.InputInt5(1));
      } else {
        __ shl_cl(i.OutputOperand());
      }
      break;
    case kIA32Shr:
      if (HasImmediateInput(instr, 1)) {
        __ shr(i.OutputOperand(), i.InputInt5(1));
      } else {
        __ shr_cl(i.OutputOperand());
      }
      break;
    case kIA32Sar:
      if (HasImmediateInput(instr, 1)) {
        __ sar(i.OutputOperand(), i.InputInt5(1));
      } else {
        __ sar_cl(i.OutputOperand());
      }
      break;
    case kIA32AddPair: {
      // i.OutputRegister(0) == i.InputRegister(0) ... left low word.
      // i.InputRegister(1) ... left high word.
      // i.InputRegister(2) ... right low word.
      // i.InputRegister(3) ... right high word.
      bool use_temp = false;
      if ((HasRegisterInput(instr, 1) &&
           i.OutputRegister(0).code() == i.InputRegister(1).code()) ||
          i.OutputRegister(0).code() == i.InputRegister(3).code()) {
        // We cannot write to the output register directly, because it would
        // overwrite an input for adc. We have to use the temp register.
        use_temp = true;
        __ Move(i.TempRegister(0), i.InputRegister(0));
        __ add(i.TempRegister(0), i.InputRegister(2));
      } else {
        __ add(i.OutputRegister(0), i.InputRegister(2));
      }
      i.MoveInstructionOperandToRegister(i.OutputRegister(1),
                                         instr->InputAt(1));
      __ adc(i.OutputRegister(1), Operand(i.InputRegister(3)));
      if (use_temp) {
        __ Move(i.OutputRegister(0), i.TempRegister(0));
      }
      break;
    }
    case kIA32SubPair: {
      // i.OutputRegister(0) == i.InputRegister(0) ... left low word.
      // i.InputRegister(1) ... left high word.
      // i.InputRegister(2) ... right low word.
      // i.InputRegister(3) ... right high word.
      bool use_temp = false;
      if ((HasRegisterInput(instr, 1) &&
           i.OutputRegister(0).code() == i.InputRegister(1).code()) ||
          i.OutputRegister(0).code() == i.InputRegister(3).code()) {
        // We cannot write to the output register directly, because it would
        // overwrite an input for adc. We have to use the temp register.
        use_temp = true;
        __ Move(i.TempRegister(0), i.InputRegister(0));
        __ sub(i.TempRegister(0), i.InputRegister(2));
      } else {
        __ sub(i.OutputRegister(0), i.InputRegister(2));
      }
      i.MoveInstructionOperandToRegister(i.OutputRegister(1),
                                         instr->InputAt(1));
      __ sbb(i.OutputRegister(1), Operand(i.InputRegister(3)));
      if (use_temp) {
        __ Move(i.OutputRegister(0), i.TempRegister(0));
      }
      break;
    }
    case kIA32MulPair: {
      __ imul(i.OutputRegister(1), i.InputOperand(0));
      i.MoveInstructionOperandToRegister(i.TempRegister(0), instr->InputAt(1));
      __ imul(i.TempRegister(0), i.InputOperand(2));
      __ add(i.OutputRegister(1), i.TempRegister(0));
      __ mov(i.OutputRegister(0), i.InputOperand(0));
      // Multiplies the low words and stores them in eax and edx.
      __ mul(i.InputRegister(2));
      __ add(i.OutputRegister(1), i.TempRegister(0));

      break;
    }
    case kIA32ShlPair:
      if (HasImmediateInput(instr, 2)) {
        __ ShlPair(i.InputRegister(1), i.InputRegister(0), i.InputInt6(2));
      } else {
        // Shift has been loaded into CL by the register allocator.
        __ ShlPair_cl(i.InputRegister(1), i.InputRegister(0));
      }
      break;
    case kIA32ShrPair:
      if (HasImmediateInput(instr, 2)) {
        __ ShrPair(i.InputRegister(1), i.InputRegister(0), i.InputInt6(2));
      } else {
        // Shift has been loaded into CL by the register allocator.
        __ ShrPair_cl(i.InputRegister(1), i.InputRegister(0));
      }
      break;
    case kIA32SarPair:
      if (HasImmediateInput(instr, 2)) {
        __ SarPair(i.InputRegister(1), i.InputRegister(0), i.InputInt6(2));
      } else {
        // Shift has been loaded into CL by the register allocator.
        __ SarPair_cl(i.InputRegister(1), i.InputRegister(0));
      }
      break;
    case kIA32Rol:
      if (HasImmediateInput(instr, 1)) {
        __ rol(i.OutputOperand(), i.InputInt5(1));
      } else {
        __ rol_cl(i.OutputOperand());
      }
      break;
    case kIA32Ror:
      if (HasImmediateInput(instr, 1)) {
        __ ror(i.OutputOperand(), i.InputInt5(1));
      } else {
        __ ror_cl(i.OutputOperand());
      }
      break;
    case kIA32Lzcnt:
      __ Lzcnt(i.OutputRegister(), i.InputOperand(0));
      break;
    case kIA32Tzcnt:
      __ Tzcnt(i.OutputRegister(), i.InputOperand(0));
      break;
    case kIA32Popcnt:
      __ Popcnt(i.OutputRegister(), i.InputOperand(0));
      break;
    case kIA32Bswap:
      __ bswap(i.OutputRegister());
      break;
    case kIA32MFence:
      __ mfence();
      break;
    case kIA32LFence:
      __ lfence();
      break;
    case kIA32Float32Cmp:
      __ Ucomiss(i.InputDoubleRegister(0), i.InputOperand(1));
      break;
    case kIA32Float32Sqrt:
      __ Sqrtss(i.OutputDoubleRegister(), i.InputOperand(0));
      break;
    case kIA32Float32Round: {
      CpuFeatureScope sse_scope(masm(), SSE4_1);
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundss(i.OutputDoubleRegister(), i.InputDoubleRegister(0), mode);
      break;
    }
    case kIA32Float64Cmp:
      __ Ucomisd(i.InputDoubleRegister(0), i.InputOperand(1));
      break;
    case kIA32Float32Max: {
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
      __ Movmskps(i.TempRegister(0), i.InputDoubleRegister(0));
      __ test(i.TempRegister(0), Immediate(1));
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

    case kIA32Float64Max: {
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
      __ Movmskpd(i.TempRegister(0), i.InputDoubleRegister(0));
      __ test(i.TempRegister(0), Immediate(1));
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
    case kIA32Float32Min: {
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
        __ Movmskps(i.TempRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Movss(kScratchDoubleReg, i.InputOperand(1));
        __ Movmskps(i.TempRegister(0), kScratchDoubleReg);
      }
      __ test(i.TempRegister(0), Immediate(1));
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
    case kIA32Float64Min: {
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
        __ Movmskpd(i.TempRegister(0), i.InputDoubleRegister(1));
      } else {
        __ Movsd(kScratchDoubleReg, i.InputOperand(1));
        __ Movmskpd(i.TempRegister(0), kScratchDoubleReg);
      }
      __ test(i.TempRegister(0), Immediate(1));
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
    case kIA32Float64Mod: {
      Register tmp = i.TempRegister(1);
      __ mov(tmp, esp);
      __ AllocateStackSpace(kDoubleSize);
      __ and_(esp, -8);  // align to 8 byte boundary.
      // Move values to st(0) and st(1).
      __ Movsd(Operand(esp, 0), i.InputDoubleRegister(1));
      __ fld_d(Operand(esp, 0));
      __ Movsd(Operand(esp, 0), i.InputDoubleRegister(0));
      __ fld_d(Operand(esp, 0));
      // Loop while fprem isn't done.
      Label mod_loop;
      __ bind(&mod_loop);
      // This instruction traps on all kinds of inputs, but we are assuming the
      // floating point control word is set to ignore them all.
      __ fprem();
      // fnstsw_ax clobbers eax.
      DCHECK_EQ(eax, i.TempRegister(0));
      __ fnstsw_ax();
      __ sahf();
      __ j(parity_even, &mod_loop);
      // Move output to stack and clean up.
      __ fstp(1);
      __ fstp_d(Operand(esp, 0));
      __ Movsd(i.OutputDoubleRegister(), Operand(esp, 0));
      __ mov(esp, tmp);
      break;
    }
    case kIA32Float64Sqrt:
      __ Sqrtsd(i.OutputDoubleRegister(), i.InputOperand(0));
      break;
    case kIA32Float64Round: {
      RoundingMode const mode =
          static_cast<RoundingMode>(MiscField::decode(instr->opcode()));
      __ Roundsd(i.OutputDoubleRegister(), i.InputDoubleRegister(0), mode);
      break;
    }
    case kIA32Float32ToFloat64:
      __ Cvtss2sd(i.OutputDoubleRegister(), i.InputOperand(0));
      break;
    case kIA32Float64ToFloat32:
      __ Cvtsd2ss(i.OutputDoubleRegister(), i.InputOperand(0));
      break;
    case kIA32Float32ToInt32:
      __ Cvttss2si(i.OutputRegister(), i.InputOperand(0));
      break;
    case kIA32Float32ToUint32:
      __ Cvttss2ui(i.OutputRegister(), i.InputOperand(0),
                   i.TempSimd128Register(0));
      break;
    case kIA32Float64ToInt32:
      __ Cvttsd2si(i.OutputRegister(), i.InputOperand(0));
      break;
    case kIA32Float64ToUint32:
      __ Cvttsd2ui(i.OutputRegister(), i.InputOperand(0),
                   i.TempSimd128Register(0));
      break;
    case kSSEInt32ToFloat32:
      // Calling Cvtsi2ss (which does a xor) regresses some benchmarks.
      __ cvtsi2ss(i.OutputDoubleRegister(), i.InputOperand(0));
      break;
    case kIA32Uint32ToFloat32:
      __ Cvtui2ss(i.OutputDoubleRegister(), i.InputOperand(0),
                  i.TempRegister(0));
      break;
    case kSSEInt32ToFloat64:
      // Calling Cvtsi2sd (which does a xor) regresses some benchmarks.
      __ cvtsi2sd(i.OutputDoubleRegister(), i.InputOperand(0));
      break;
    case kIA32Uint32ToFloat64:
      __ Cvtui2sd(i.OutputDoubleRegister(), i.InputOperand(0),
                  i.TempRegister(0));
      break;
    case kIA32Float64ExtractLowWord32:
      if (instr->InputAt(0)->IsFPStackSlot()) {
        __ mov(i.OutputRegister(), i.InputOperand(0));
      } else {
        __ Movd(i.OutputRegister(), i.InputDoubleRegister(0));
      }
      break;
    case kIA32Float64ExtractHighWord32:
      if (instr->InputAt(0)->IsFPStackSlot()) {
        __ mov(i.OutputRegister(), i.InputOperand(0, kDoubleSize / 2));
      } else {
        __ Pextrd(i.OutputRegister(), i.InputDoubleRegister(0), 1);
      }
      break;
    case kIA32Float64InsertLowWord32:
      __ Pinsrd(i.OutputDoubleRegister(), i.InputOperand(1), 0);
      break;
    case kIA32Float64InsertHighWord32:
      __ Pinsrd(i.OutputDoubleRegister(), i.InputOperand(1), 1);
      break;
    case kIA32Float64FromWord32Pair:
      __ Pinsrd(i.OutputDoubleRegister(), i.InputOperand(0), 0);
      __ Pinsrd(i.OutputDoubleRegister(), i.InputOperand(1), 1);
      break;
    case kIA32Float64LoadLowWord32:
      __ Movd(i.OutputDoubleRegister(), i.InputOperand(0));
      break;
    case kFloat32Add: {
      __ Addss(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kFloat32Sub: {
      __ Subss(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kFloat32Mul: {
      __ Mulss(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kFloat32Div: {
      __ Divss(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      // Don't delete this mov. It may improve performance on some CPUs,
      // when there is a (v)mulss depending on the result.
      __ movaps(i.OutputDoubleRegister(), i.OutputDoubleRegister());
      break;
    }
    case kFloat64Add: {
      __ Addsd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kFloat64Sub: {
      __ Subsd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kFloat64Mul: {
      __ Mulsd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      break;
    }
    case kFloat64Div: {
      __ Divsd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputOperand(1));
      // Don't delete this mov. It may improve performance on some CPUs,
      // when there is a (v)mulsd depending on the result.
      __ movaps(i.OutputDoubleRegister(), i.OutputDoubleRegister());
      break;
    }
    case kFloat32Abs: {
      __ Absps(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.TempRegister(0));
      break;
    }
    case kFloat32Neg: {
      __ Negps(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.TempRegister(0));
      break;
    }
    case kFloat64Abs: {
      __ Abspd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.TempRegister(0));
      break;
    }
    case kFloat64Neg: {
      __ Negpd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.TempRegister(0));
      break;
    }
    case kIA32Float64SilenceNaN:
      __ Xorps(kScratchDoubleReg, kScratchDoubleReg);
      __ Subsd(i.InputDoubleRegister(0), kScratchDoubleReg);
      break;
    case kIA32Movsxbl:
      ASSEMBLE_MOVX(movsx_b);
      break;
    case kIA32Movzxbl:
      ASSEMBLE_MOVX(movzx_b);
      break;
    case kIA32Movb: {
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      if (HasImmediateInput(instr, index)) {
        __ mov_b(operand, i.InputInt8(index));
      } else {
        __ mov_b(operand, i.InputRegister(index));
      }
      break;
    }
    case kIA32Movsxwl:
      ASSEMBLE_MOVX(movsx_w);
      break;
    case kIA32Movzxwl:
      ASSEMBLE_MOVX(movzx_w);
      break;
    case kIA32Movw: {
      size_t index = 0;
      Operand operand = i.MemoryOperand(&index);
      if (HasImmediateInput(instr, index)) {
        __ mov_w(operand, i.InputInt16(index));
      } else {
        __ mov_w(operand, i.InputRegister(index));
      }
      break;
    }
    case kIA32Movl:
      if (instr->HasOutput()) {
        __ mov(i.OutputRegister(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        if (HasImmediateInput(instr, index)) {
          __ Move(operand, i.InputImmediate(index));
        } else {
          __ mov(operand, i.InputRegister(index));
        }
      }
      break;
    case kIA32Movsd:
      if (instr->HasOutput()) {
        __ Movsd(i.OutputDoubleRegister(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ Movsd(operand, i.InputDoubleRegister(index));
      }
      break;
    case kIA32Movss:
      if (instr->HasOutput()) {
        __ Movss(i.OutputDoubleRegister(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ Movss(operand, i.InputDoubleRegister(index));
      }
      break;
    case kIA32Movdqu:
      if (instr->HasOutput()) {
        __ Movdqu(i.OutputSimd128Register(), i.MemoryOperand());
      } else {
        size_t index = 0;
        Operand operand = i.MemoryOperand(&index);
        __ Movdqu(operand, i.InputSimd128Register(index));
      }
      break;
    case kIA32BitcastFI:
      if (instr->InputAt(0)->IsFPStackSlot()) {
        __ mov(i.OutputRegister(), i.InputOperand(0));
      } else {
        __ Movd(i.OutputRegister(), i.InputDoubleRegister(0));
      }
      break;
    case kIA32BitcastIF:
      if (HasRegisterInput(instr, 0)) {
        __ Movd(i.OutputDoubleRegister(), i.InputRegister(0));
      } else {
        __ Movss(i.OutputDoubleRegister(), i.InputOperand(0));
      }
      break;
    case kIA32Lea: {
      AddressingMode mode = AddressingModeField::decode(instr->opcode());
      // Shorten "leal" to "addl", "subl" or "shll" if the register allocation
      // and addressing mode just happens to work out. The "addl"/"subl" forms
      // in these cases are faster based on measurements.
      if (mode == kMode_MI) {
        __ Move(i.OutputRegister(), Immediate(i.InputInt32(0)));
      } else if (i.InputRegister(0) == i.OutputRegister()) {
        if (mode == kMode_MRI) {
          int32_t constant_summand = i.InputInt32(1);
          if (constant_summand > 0) {
            __ add(i.OutputRegister(), Immediate(constant_summand));
          } else if (constant_summand < 0) {
            __ sub(i.OutputRegister(),
                   Immediate(base::NegateWithWraparound(constant_summand)));
          }
        } else if (mode == kMode_MR1) {
          if (i.InputRegister(1) == i.OutputRegister()) {
            __ shl(i.OutputRegister(), 1);
          } else {
            __ add(i.OutputRegister(), i.InputRegister(1));
          }
        } else if (mode == kMode_M2) {
          __ shl(i.OutputRegister(), 1);
        } else if (mode == kMode_M4) {
          __ shl(i.OutputRegister(), 2);
        } else if (mode == kMode_M8) {
          __ shl(i.OutputRegister(), 3);
        } else {
          __ lea(i.OutputRegister(), i.MemoryOperand());
        }
      } else if (mode == kMode_MR1 &&
                 i.InputRegister(1) == i.OutputRegister()) {
        __ add(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ lea(i.OutputRegister(), i.MemoryOperand());
      }
      break;
    }
    case kIA32Push: {
      int stack_decrement = i.InputInt32(0);
      int slots = stack_decrement / kSystemPointerSize;
      // Whenever codegen uses push, we need to check if stack_decrement
      // contains any extra padding and adjust the stack before the push.
      if (HasAddressingMode(instr)) {
        // Only single slot pushes from memory are supported.
        __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
        size_t index = 1;
        Operand operand = i.MemoryOperand(&index);
        __ push(operand);
      } else if (HasImmediateInput(instr, 1)) {
        __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
        __ push(i.InputImmediate(1));
      } else {
        InstructionOperand* input = instr->InputAt(1);
        if (input->IsRegister()) {
          __ AllocateStackSpace(stack_decrement - kSystemPointerSize);
          __ push(i.InputRegister(1));
        } else if (input->IsFloatRegister()) {
          DCHECK_GE(stack_decrement, kFloatSize);
          __ AllocateStackSpace(stack_decrement);
          __ Movss(Operand(esp, 0), i.InputDoubleRegister(1));
        } else if (input->IsDoubleRegister()) {
          DCHECK_GE(stack_decrement, kDoubleSize);
          __ AllocateStackSpace(stack_decrement);
          __ Movsd(Operand(esp, 0), i.InputDoubleRegister(1));
        } else if (input->IsSimd128Register()) {
          DCHECK_GE(stack_decrement, kSimd128Size);
          __ AllocateStackSpace(stack_decrement);
          // TODO(bbudge) Use Movaps when slots are aligned.
          __ Movups(Operand(esp, 0), i.InputSimd128Register(1));
        } else if (input->IsSta
"""


```