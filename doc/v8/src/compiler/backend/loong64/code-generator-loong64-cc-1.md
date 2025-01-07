Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code appears to be part of a code generator for the LoongArch64 architecture within the V8 JavaScript engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The code is within `code-generator-loong64.cc` and handles different instruction opcodes (`case k...`). This strongly suggests it's responsible for translating higher-level instructions into LoongArch64 assembly code.

2. **Categorize the handled opcodes:**  Look for patterns in the `case` statements. We see:
    * Control flow (`kArchCallJSFunction`, `kArchPrepareCallCFunction`, `kArchRet`, `kArchJmp`, etc.)
    * Stack manipulation (`kArchStackPointer`, `kArchSetStackPointer`, `kArchStackSlot`)
    * Data movement (`kLoong64Mov`)
    * Integer arithmetic and logic (`kLoong64Add_w`, `kLoong64Sub_d`, `kLoong64And`, etc.)
    * Floating-point operations (`kLoong64Float32Add`, `kLoong64Float64Cmp`, `kIeee754Float64Acos`, etc.)
    * Memory access with write barriers (`kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`, `kArchStoreIndirectWithWriteBarrier`)
    * Conversions between data types (`kLoong64Float64ToInt32`, `kLoong64Int32ToFloat64`, etc.)
    * Debugging and assertions (`kArchAbortCSADcheck`, `kArchDebugBreak`)

3. **Infer the high-level functionality:** Based on the categories, the code generator is responsible for taking abstract instructions and emitting the corresponding LoongArch64 machine code to perform various tasks like function calls, arithmetic operations, memory manipulation, and type conversions. The write barriers suggest it's involved in garbage collection.

4. **Address the specific questions:**
    * **.tq extension:** The code is `.cc`, not `.tq`, so it's not Torque.
    * **Relationship to JavaScript:** The presence of `kArchCallJSFunction` and handling of JS function calls clearly links it to executing JavaScript. Provide a simple JavaScript example of a function call.
    * **Code logic reasoning:** Choose a simple operation like integer addition. Show how the inputs map to registers and the output to another register.
    * **Common programming errors:**  Consider errors related to function calls (wrong arguments) or type conversions (overflow).

5. **Summarize the overall function:** Combine the identified functionalities into a concise summary. Emphasize the code generation role for the LoongArch64 architecture within V8.
这段代码是V8 JavaScript 引擎中针对 LoongArch64 架构的代码生成器的部分实现。它负责将中间表示（Intermediate Representation, IR）的指令转换为 LoongArch64 汇编代码。

**功能归纳:**

这段代码的主要功能是处理各种架构相关的操作码（`case k...:`），并生成相应的 LoongArch64 汇编指令。具体来说，它涵盖了以下几个方面的功能：

1. **函数调用:**
   - `kArchCallJSFunction`:  生成调用 JavaScript 函数的代码，包括检查函数上下文。
   - `kArchPrepareCallCFunction`:  准备调用 C 函数的代码，包括设置参数和对齐栈帧。
   - `kArchCallCFunctionWithFrameState`, `kArchCallCFunction`: 生成调用 C 函数的代码，可能包含帧状态记录和安全点信息。
   - `kArchPrepareTailCall`: 准备尾调用的代码。
   - `kArchSaveCallerRegisters`, `kArchRestoreCallerRegisters`: 保存和恢复调用者保存的寄存器。
   - `kArchRet`: 生成函数返回指令。

2. **控制流:**
   - `kArchJmp`: 生成跳转指令。
   - `kArchBinarySearchSwitch`, `kArchTableSwitch`: 生成用于实现 `switch` 语句的代码。
   - `kArchDeoptimize`: 生成用于去优化的代码。

3. **栈操作:**
   - `kArchStackPointer`, `kArchSetStackPointer`: 获取和设置栈指针。
   - `kArchStackPointerGreaterThan`: 比较栈指针与寄存器值。
   - `kArchStackCheckOffset`: 获取栈检查偏移量。
   - `kArchFramePointer`, `kArchParentFramePointer`: 获取帧指针和父帧指针。
   - `kArchStackSlot`: 计算栈槽地址。

4. **算术和逻辑运算:**
   - 包括各种 LoongArch64 的整数和浮点数运算指令，如加法 (`kLoong64Add_w`, `kLoong64Add_d`)、减法、乘法、除法、取模、位运算（与、或、异或、非）、移位、循环移位等。

5. **浮点数运算 (IEEE 754):**
   - 实现了各种 IEEE 754 标准的浮点数运算，如 `acos`, `acosh`, `asin`, `asinh`, `atan`, `atanh`, `atan2`, `cos`, `cosh`, `cbrt`, `exp`, `expm1`, `log`, `log1p`, `log2`, `log10`, `pow`, `sin`, `sinh`, `tan`, `tanh`。

6. **内存操作和写屏障:**
   - `kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`, `kArchStoreIndirectWithWriteBarrier`: 生成带有写屏障的存储指令，用于支持垃圾回收。

7. **类型转换:**
   - 提供了各种数据类型之间的转换指令，如浮点数到整数、整数到浮点数、单精度浮点数到双精度浮点数等。

8. **调试和辅助功能:**
   - `kArchAbortCSADcheck`: 用于 CSA (Canonical Stack Addressing) 检查的断言。
   - `kArchDebugBreak`: 生成断点指令。
   - `kArchComment`: 记录注释信息。
   - `kArchNop`, `kArchThrowTerminator`: 空操作。

**关于源代码类型和 JavaScript 关联:**

* **文件扩展名:** `v8/src/compiler/backend/loong64/code-generator-loong64.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码（通常以 `.tq` 结尾）。
* **与 JavaScript 的关系:**  这个文件是 V8 引擎的一部分，而 V8 是一个用于执行 JavaScript 代码的虚拟机。因此，这个代码生成器的核心功能就是将 JavaScript 代码编译成可以在 LoongArch64 架构上运行的机器码。`kArchCallJSFunction` 这个 case 就是直接处理 JavaScript 函数调用的。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

当 V8 执行这段 JavaScript 代码时，`kArchCallJSFunction` 对应的代码生成逻辑会被触发，生成 LoongArch64 汇编指令来调用 `add` 函数。

**代码逻辑推理示例:**

假设输入指令是 `kLoong64Add_w`，表示执行 32 位整数加法，输入寄存器分别为 `r10` 和 `r11`，输出寄存器为 `r12`。

**假设输入:**
- `instr->opcode()`: `kLoong64Add_w`
- `i.InputRegister(0)`: `r10`
- `i.InputOperand(1)`:  表示第二个操作数，可以是寄存器或立即数。假设是寄存器 `r11`。
- `i.OutputRegister()`: `r12`

**输出 (生成的汇编代码):**
```assembly
  add.w  r12, r10, r11  //  r12 = r10 + r11
```

如果 `i.InputOperand(1)` 是一个立即数，比如 `5`，那么生成的汇编代码可能是：
```assembly
  addi.w r12, r10, 5   // r12 = r10 + 5
```

**用户常见的编程错误示例:**

在与函数调用相关的部分，一个常见的错误是 **传递错误的参数数量或类型**。

**C++ 代码示例 (假设 `CallJSFunction` 函数期望两个参数):**

```c++
// ...
case kArchCallJSFunction: {
  Register func = i.InputRegister(0);
  uint32_t num_arguments =
      i.InputUint32(instr->JSCallArgumentCountInputIndex());
  __ CallJSFunction(func, num_arguments);
  // ...
}
// ...
```

**JavaScript 错误示例:**

```javascript
function myFunction(a, b) {
  console.log(a, b);
}

myFunction(1); // 传递的参数数量不足，缺少第二个参数
myFunction(1, "hello", true); // 传递的参数数量过多
```

在这些情况下，V8 的代码生成器会根据 IR 指令生成相应的调用代码，但如果在 JavaScript 层面传递的参数与函数定义不符，可能会导致运行时错误或意外行为。V8 的运行时检查和优化的机制会尝试捕获这些错误，但理解代码生成器的工作原理有助于理解这些错误的根本原因。

**总结:**

这段代码是 V8 引擎中 LoongArch64 架构代码生成器的核心部分，负责将中间表示的指令转换为实际的机器码，涵盖了函数调用、控制流、算术运算、内存操作和类型转换等多个关键方面，是连接 JavaScript 代码和底层硬件的关键桥梁。

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/code-generator-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/code-generator-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
 frame_access_state()->SetFrameAccessToDefault();
      break;
    }
    case kArchCallJSFunction: {
      Register func = i.InputRegister(0);
      if (v8_flags.debug_code) {
        UseScratchRegisterScope temps(masm());
        Register scratch = temps.Acquire();
        // Check the function's context matches the context argument.
        __ LoadTaggedField(scratch,
                           FieldMemOperand(func, JSFunction::kContextOffset));
        __ Assert(eq, AbortReason::kWrongFunctionContext, cp, Operand(scratch));
      }
      uint32_t num_arguments =
          i.InputUint32(instr->JSCallArgumentCountInputIndex());
      __ CallJSFunction(func, num_arguments);
      RecordCallPosition(instr);
      frame_access_state()->ClearSPDelta();
      break;
    }
    case kArchPrepareCallCFunction: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      int const num_gp_parameters = ParamField::decode(instr->opcode());
      int const num_fp_parameters = FPParamField::decode(instr->opcode());
      __ PrepareCallCFunction(num_gp_parameters, num_fp_parameters, scratch);
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
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
      Label return_location;
#if V8_ENABLE_WEBASSEMBLY
      bool isWasmCapiFunction =
          linkage()->GetIncomingDescriptor()->IsWasmCapiFunction();
      if (isWasmCapiFunction) {
        __ LoadLabelRelative(t7, &return_location);
        __ St_d(t7, MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (instr->InputAt(0)->IsImmediate()) {
        ExternalReference ref = i.InputExternalReference(0);
        pc_offset = __ CallCFunction(ref, num_gp_parameters, num_fp_parameters,
                                     set_isolate_data_slots, &return_location);
      } else {
        Register func = i.InputRegister(0);
        pc_offset = __ CallCFunction(func, num_gp_parameters, num_fp_parameters,
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
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == a0);
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
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt64(0)),
                       SourceLocation());
      break;
    case kArchNop:
    case kArchThrowTerminator:
      // don't emit code for nops.
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ Branch(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      // The register allocator expects an allocatable register for the output,
      // we cannot use sp directly.
      __ mov(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer: {
      DCHECK(instr->InputAt(0)->IsRegister());
      __ mov(sp, i.InputRegister(0));
      break;
    }
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchStackPointerGreaterThan: {
      Register lhs_register = sp;
      uint32_t offset;
      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = i.TempRegister(1);
        __ Sub_d(lhs_register, sp, offset);
      }
      __ Sltu(i.TempRegister(0), i.InputRegister(0), lhs_register);
      break;
    }
    case kArchStackCheckOffset:
      __ Move(i.OutputRegister(), Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchFramePointer:
      __ mov(i.OutputRegister(), fp);
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ Ld_d(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mov(i.OutputRegister(), fp);
      }
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      break;
    case kArchStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);

      if (addressing_mode == kMode_MRI) {
        auto ool = zone()->New<OutOfLineRecordWrite>(
            this, object, Operand(i.InputInt64(1)), value, mode,
            DetermineStubCallMode());
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ StoreTaggedField(value, MemOperand(object, i.InputInt64(1)));
        if (mode > RecordWriteMode::kValueIsPointer) {
          __ JumpIfSmi(value, ool->exit());
        }
        __ CheckPageFlag(object,
                         MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                         ool->entry());
        __ bind(ool->exit());
      } else {
        DCHECK_EQ(addressing_mode, kMode_MRR);
        auto ool = zone()->New<OutOfLineRecordWrite>(
            this, object, Operand(i.InputRegister(1)), value, mode,
            DetermineStubCallMode());
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ StoreTaggedField(value, MemOperand(object, i.InputRegister(1)));
        if (mode > RecordWriteMode::kValueIsIndirectPointer) {
          __ JumpIfSmi(value, ool->exit());
        }
        __ CheckPageFlag(object,
                         MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                         ool->entry());
        __ bind(ool->exit());
      }
      break;
    }
    case kArchAtomicStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      // Indirect pointer writes must use a different opcode.
      DCHECK_NE(mode, RecordWriteMode::kValueIsIndirectPointer);
      Register object = i.InputRegister(0);
      int64_t offset = i.InputInt64(1);
      Register value = i.InputRegister(2);

      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, Operand(offset), value, mode, DetermineStubCallMode());
      __ AtomicStoreTaggedField(value, MemOperand(object, offset));
      // Skip the write barrier if the value is a Smi. However, this is only
      // valid if the value isn't an indirect pointer. Otherwise the value will
      // be a pointer table index, which will always look like a Smi (but
      // actually reference a pointer in the pointer table).
      if (mode > RecordWriteMode::kValueIsIndirectPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      DCHECK_EQ(mode, RecordWriteMode::kValueIsIndirectPointer);
      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      IndirectPointerTag tag = static_cast<IndirectPointerTag>(i.InputInt64(3));
      DCHECK(IsValidIndirectPointerTag(tag));
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);

      if (addressing_mode == kMode_MRI) {
        auto ool = zone()->New<OutOfLineRecordWrite>(
            this, object, Operand(i.InputInt32(1)), value, mode,
            DetermineStubCallMode(), tag);
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ StoreIndirectPointerField(value,
                                     MemOperand(object, i.InputInt32(1)));
        __ CheckPageFlag(object,
                         MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                         ool->entry());
        __ bind(ool->exit());
      } else {
        DCHECK_EQ(addressing_mode, kMode_MRR);
        auto ool = zone()->New<OutOfLineRecordWrite>(
            this, object, Operand(i.InputRegister(1)), value, mode,
            DetermineStubCallMode(), tag);
        RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
        __ StoreIndirectPointerField(value,
                                     MemOperand(object, i.InputRegister(1)));
        __ CheckPageFlag(object,
                         MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                         ool->entry());
        __ bind(ool->exit());
      }
      break;
    }
    case kArchStackSlot: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base_reg = offset.from_stack_pointer() ? sp : fp;
      __ Add_d(i.OutputRegister(), base_reg, Operand(offset.offset()));
      if (v8_flags.debug_code) {
        // Verify that the output_register is properly aligned
        __ And(scratch, i.OutputRegister(), Operand(kSystemPointerSize - 1));
        __ Assert(eq, AbortReason::kAllocationIsNotDoubleAligned, scratch,
                  Operand(zero_reg));
      }
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
    case kIeee754Float64Cos:
      ASSEMBLE_IEEE754_UNOP(cos);
      break;
    case kIeee754Float64Cosh:
      ASSEMBLE_IEEE754_UNOP(cosh);
      break;
    case kIeee754Float64Cbrt:
      ASSEMBLE_IEEE754_UNOP(cbrt);
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
    case kLoong64Add_w:
      __ Add_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Add_d:
      __ Add_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64AddOvf_d:
      __ AddOverflow_d(i.OutputRegister(), i.InputRegister(0),
                       i.InputOperand(1), t8);
      break;
    case kLoong64Sub_w:
      __ Sub_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Sub_d:
      __ Sub_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64SubOvf_d:
      __ SubOverflow_d(i.OutputRegister(), i.InputRegister(0),
                       i.InputOperand(1), t8);
      break;
    case kLoong64Mul_w:
      __ Mul_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64MulOvf_w:
      __ MulOverflow_w(i.OutputRegister(), i.InputRegister(0),
                       i.InputOperand(1), t8);
      break;
    case kLoong64MulOvf_d:
      __ MulOverflow_d(i.OutputRegister(), i.InputRegister(0),
                       i.InputOperand(1), t8);
      break;
    case kLoong64Mulh_w:
      __ Mulh_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mulh_wu:
      __ Mulh_wu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mulh_d:
      __ Mulh_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mulh_du:
      __ Mulh_du(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Div_w:
      __ Div_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      __ maskeqz(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kLoong64Div_wu:
      __ Div_wu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      __ maskeqz(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kLoong64Mod_w:
      __ Mod_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mod_wu:
      __ Mod_wu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mul_d:
      __ Mul_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Div_d:
      __ Div_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      __ maskeqz(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kLoong64Div_du:
      __ Div_du(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      __ maskeqz(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      break;
    case kLoong64Mod_d:
      __ Mod_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Mod_du:
      __ Mod_du(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Alsl_d:
      DCHECK(instr->InputAt(2)->IsImmediate());
      __ Alsl_d(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.InputInt8(2), t7);
      break;
    case kLoong64Alsl_w:
      DCHECK(instr->InputAt(2)->IsImmediate());
      __ Alsl_w(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
                i.InputInt8(2), t7);
      break;
    case kLoong64And:
    case kLoong64And32:
      __ And(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Or:
    case kLoong64Or32:
      __ Or(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Nor:
    case kLoong64Nor32:
      if (instr->InputAt(1)->IsRegister()) {
        __ Nor(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      } else {
        DCHECK_EQ(0, i.InputOperand(1).immediate());
        __ Nor(i.OutputRegister(), i.InputRegister(0), zero_reg);
      }
      break;
    case kLoong64Xor:
    case kLoong64Xor32:
      __ Xor(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Clz_w:
      __ clz_w(i.OutputRegister(), i.InputRegister(0));
      break;
    case kLoong64Clz_d:
      __ clz_d(i.OutputRegister(), i.InputRegister(0));
      break;
    case kLoong64Sll_w:
      if (instr->InputAt(1)->IsRegister()) {
        __ sll_w(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ slli_w(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Srl_w:
      if (instr->InputAt(1)->IsRegister()) {
        __ srl_w(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srli_w(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Sra_w:
      if (instr->InputAt(1)->IsRegister()) {
        __ sra_w(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srai_w(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Bstrpick_w:
      __ bstrpick_w(i.OutputRegister(), i.InputRegister(0),
                    i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      break;
    case kLoong64Bstrins_w:
      if (instr->InputAt(1)->IsImmediate() && i.InputInt8(1) == 0) {
        __ bstrins_w(i.OutputRegister(), zero_reg,
                     i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      } else {
        __ bstrins_w(i.OutputRegister(), i.InputRegister(0),
                     i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      }
      break;
    case kLoong64Bstrpick_d: {
      __ bstrpick_d(i.OutputRegister(), i.InputRegister(0),
                    i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      break;
    }
    case kLoong64Bstrins_d:
      if (instr->InputAt(1)->IsImmediate() && i.InputInt8(1) == 0) {
        __ bstrins_d(i.OutputRegister(), zero_reg,
                     i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      } else {
        __ bstrins_d(i.OutputRegister(), i.InputRegister(0),
                     i.InputInt8(1) + i.InputInt8(2) - 1, i.InputInt8(1));
      }
      break;
    case kLoong64Sll_d:
      if (instr->InputAt(1)->IsRegister()) {
        __ sll_d(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ slli_d(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Srl_d:
      if (instr->InputAt(1)->IsRegister()) {
        __ srl_d(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srli_d(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
      }
      break;
    case kLoong64Sra_d:
      if (instr->InputAt(1)->IsRegister()) {
        __ sra_d(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srai_d(i.OutputRegister(), i.InputRegister(0), imm);
      }
      break;
    case kLoong64Rotr_w:
      __ Rotr_w(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Rotr_d:
      __ Rotr_d(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kLoong64Tst:
      __ And(t8, i.InputRegister(0), i.InputOperand(1));
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kLoong64Cmp32:
    case kLoong64Cmp64:
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kLoong64Mov:
      // TODO(LOONG_dev): Should we combine mov/li, or use separate instr?
      //    - Also see x64 ASSEMBLE_BINOP & RegisterOrOperandType
      if (HasRegisterInput(instr, 0)) {
        __ mov(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ li(i.OutputRegister(), i.InputOperand(0));
      }
      break;

    case kLoong64Float32Cmp: {
      FPURegister left = i.InputOrZeroSingleRegister(0);
      FPURegister right = i.InputOrZeroSingleRegister(1);
      bool predicate;
      FPUCondition cc =
          FlagsConditionToConditionCmpFPU(&predicate, instr->flags_condition());

      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }

      __ CompareF32(left, right, cc);
    } break;
    case kLoong64Float32Add:
      __ fadd_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float32Sub:
      __ fsub_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float32Mul:
      __ fmul_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float32Div:
      __ fdiv_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float32Abs:
      __ fabs_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    case kLoong64Float32Neg:
      __ Neg_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    case kLoong64Float32Sqrt: {
      __ fsqrt_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32Min: {
      FPURegister dst = i.OutputSingleRegister();
      FPURegister src1 = i.InputSingleRegister(0);
      FPURegister src2 = i.InputSingleRegister(1);
      auto ool = zone()->New<OutOfLineFloat32Min>(this, dst, src1, src2);
      __ Float32Min(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kLoong64Float32Max: {
      FPURegister dst = i.OutputSingleRegister();
      FPURegister src1 = i.InputSingleRegister(0);
      FPURegister src2 = i.InputSingleRegister(1);
      auto ool = zone()->New<OutOfLineFloat32Max>(this, dst, src1, src2);
      __ Float32Max(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kLoong64Float64Cmp: {
      FPURegister left = i.InputOrZeroDoubleRegister(0);
      FPURegister right = i.InputOrZeroDoubleRegister(1);
      bool predicate;
      FPUCondition cc =
          FlagsConditionToConditionCmpFPU(&predicate, instr->flags_condition());
      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }

      __ CompareF64(left, right, cc);
    } break;
    case kLoong64Float64Add:
      __ fadd_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float64Sub:
      __ fsub_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float64Mul:
      // TODO(LOONG_dev): LOONG64 add special case: right op is -1.0, see arm
      // port.
      __ fmul_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float64Div:
      __ fdiv_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
                i.InputDoubleRegister(1));
      break;
    case kLoong64Float64Mod: {
      // TODO(turbofan): implement directly.
      FrameScope scope(masm(), StackFrame::MANUAL);
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ PrepareCallCFunction(0, 2, scratch);
      __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
      break;
    }
    case kLoong64Float64Abs:
      __ fabs_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64Neg:
      __ Neg_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64Sqrt: {
      __ fsqrt_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float64Min: {
      FPURegister dst = i.OutputDoubleRegister();
      FPURegister src1 = i.InputDoubleRegister(0);
      FPURegister src2 = i.InputDoubleRegister(1);
      auto ool = zone()->New<OutOfLineFloat64Min>(this, dst, src1, src2);
      __ Float64Min(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kLoong64Float64Max: {
      FPURegister dst = i.OutputDoubleRegister();
      FPURegister src1 = i.InputDoubleRegister(0);
      FPURegister src2 = i.InputDoubleRegister(1);
      auto ool = zone()->New<OutOfLineFloat64Max>(this, dst, src1, src2);
      __ Float64Max(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kLoong64Float64RoundDown: {
      __ Floor_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32RoundDown: {
      __ Floor_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kLoong64Float64RoundTruncate: {
      __ Trunc_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32RoundTruncate: {
      __ Trunc_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kLoong64Float64RoundUp: {
      __ Ceil_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32RoundUp: {
      __ Ceil_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kLoong64Float64RoundTiesEven: {
      __ Round_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kLoong64Float32RoundTiesEven: {
      __ Round_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kLoong64Float64SilenceNaN:
      __ FPUCanonicalizeNaN(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64ToFloat32:
      __ fcvt_s_d(i.OutputSingleRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float32ToFloat64:
      __ fcvt_d_s(i.OutputDoubleRegister(), i.InputSingleRegister(0));
      break;
    case kLoong64Int32ToFloat64: {
      FPURegister scratch = kScratchDoubleReg;
      __ movgr2fr_w(scratch, i.InputRegister(0));
      __ ffint_d_w(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kLoong64Int32ToFloat32: {
      FPURegister scratch = kScratchDoubleReg;
      __ movgr2fr_w(scratch, i.InputRegister(0));
      __ ffint_s_w(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kLoong64Uint32ToFloat32: {
      __ Ffint_s_uw(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kLoong64Int64ToFloat32: {
      FPURegister scratch = kScratchDoubleReg;
      __ movgr2fr_d(scratch, i.InputRegister(0));
      __ ffint_s_l(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kLoong64Int64ToFloat64: {
      FPURegister scratch = kScratchDoubleReg;
      __ movgr2fr_d(scratch, i.InputRegister(0));
      __ ffint_d_l(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kLoong64Uint32ToFloat64: {
      __ Ffint_d_uw(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kLoong64Uint64ToFloat64: {
      __ Ffint_d_ul(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kLoong64Uint64ToFloat32: {
      __ Ffint_s_ul(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kLoong64Float64ToInt32: {
      FPURegister scratch = kScratchDoubleReg;
      __ ftintrz_w_d(scratch, i.InputDoubleRegister(0));
      __ movfr2gr_s(i.OutputRegister(), scratch);
      if (instr->OutputCount() > 1) {
        // Check for inputs below INT32_MIN and NaN.
        __ li(i.OutputRegister(1), 1);
        __ Move(scratch, static_cast<double>(INT32_MIN));
        __ CompareF64(scratch, i.InputDoubleRegister(0), CLE);
        __ LoadZeroIfNotFPUCondition(i.OutputRegister(1));
        __ Move(scratch, static_cast<double>(INT32_MAX) + 1);
        __ CompareF64(scratch, i.InputDoubleRegister(0), CLE);
        __ LoadZeroIfFPUCondition(i.OutputRegister(1));
      }
      break;
    }
    case kLoong64Float32ToInt32: {
      FPURegister scratch_d = kScratchDoubleReg;
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      __ ftintrz_w_s(scratch_d, i.InputDoubleRegister(0));
      __ movfr2gr_s(i.OutputRegister(), scratch_d);
      if (set_overflow_to_min_i32) {
        UseScratchRegisterScope temps(masm());
        Register scratch = temps.Acquire();
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        __ addi_w(scratch, i.OutputRegister(), 1);
        __ slt(scratch, scratch, i.OutputRegister());
        __ add_w(i.OutputRegister(), i.OutputRegister(), scratch);
      }
      break;
    }
    case kLoong64Float32ToInt64: {
      FPURegister scratch_d = kScratchDoubleReg;

      bool load_status = instr->OutputCount() > 1;
      // Other arches use round to zero here, so we follow.
      __ ftintrz_l_s(scratch_d, i.InputDoubleRegister(0));
      __ movfr2gr_d(i.OutputRegister(), scratch_d);
      if (load_status) {
        Register output2 = i.OutputRegister(1);
        __ movfcsr2gr(output2, FCSR2);
        // Check for overflow and NaNs.
        __ And(output2, output2,
               kFCSROverflowCauseMask | kFCSRInvalidOpCauseMask);
        __ Slt(output2, zero_reg, output2);
        __ xori(output2, output2, 1);
      }
      break;
    }
    case kLoong64Float64ToInt64: {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      FPURegister scratch_d = kScratchDoubleReg;

      bool set_overflow_to_min_i64 = MiscField::decode(instr->opcode());
      bool load_status = instr->OutputCount() > 1;
      // Other arches use round to zero here, so we follow.
      __ ftintrz_l_d(scratch_d, i.InputDoubleRegister(0));
      __ movfr2gr_d(i.OutputRegister(0), scratch_d);
      if (load_status) {
        Register output2 = i.OutputRegister(1);
   
"""


```