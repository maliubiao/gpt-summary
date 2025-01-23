Response:
The user wants a summary of the functionalities present in the provided C++ code snippet. This is the second part of a larger file. I need to go through each `case` in the `switch` statement and describe what it does.

Specifically, I need to:
1. List the functionalities.
2. Confirm it's not a Torque file (based on the `.cc` extension).
3. Identify if any functionality is related to JavaScript and provide a JavaScript example if it is.
4. For any code logic, provide example input and output.
5. If any part relates to common programming errors, provide an example.
6. Since this is part 2 of 6, summarize the functionality of *this part* of the code.

Let's break down the `switch` cases and analyze them:

- **`kArchPopCallerSaved`**:  Deals with restoring caller-saved registers from the stack.
- **`kArchPrepareTailCall`**: Sets up for a tail call optimization.
- **`kArchCallCFunctionWithFrameState`, `kArchCallCFunction`**: Handles calling C functions, including managing stack frames and saving return addresses.
- **`kArchJmp`**: Unconditional jump to another block of code.
- **`kArchBinarySearchSwitch`, `kArchTableSwitch`**: Implement switch statements using binary search or a jump table.
- **`kArchAbortCSADcheck`**: Calls a built-in function for checking something related to CodeStubAssembler (CSA) debugging.
- **`kArchDebugBreak`**: Inserts a breakpoint for debugging.
- **`kArchComment`**: Adds a comment to the generated assembly code.
- **`kArchThrowTerminator`**: Indicates a point where execution will terminate with an exception.
- **`kArchNop`**: Does nothing (no operation).
- **`kArchDeoptimize`**: Initiates the deoptimization process.
- **`kArchRet`**: Returns from a function.
- **`kArchFramePointer`**: Moves the frame pointer to a register.
- **`kArchParentFramePointer`**: Loads the parent frame pointer.
- **`kArchStackPointer`, `kArchSetStackPointer`**:  Get and set the stack pointer (related to WebAssembly).
- **`kArchStackPointerGreaterThan`**: Compares the stack pointer to a value.
- **`kArchStackCheckOffset`**: Loads the stack check offset.
- **`kArchTruncateDoubleToI`**: Converts a double to an integer.
- **`kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`**: Stores a value in memory and ensures the garbage collector is aware of the pointer write.
- **`kArchStoreIndirectWithWriteBarrier`**:  Similar to the above but the address is indirect (UNREACHABLE in this code).
- **`kArchStackSlot`**: Calculates the address of a stack slot.
- **`kIeee754Float64...`**: A large set of cases for IEEE 754 floating-point operations (arithmetic, trigonometric, etc.). These are likely related to JavaScript's `Math` object.
- **`kArmAdd`, `kArmAnd`, `kArmBic`, `kArmMul`, `kArmMla`, `kArmMls`, `kArmSmull`, `kArmSmmul`, `kArmSmmla`, `kArmUmull`, `kArmSdiv`, `kArmUdiv`, `kArmMov`, `kArmMvn`, `kArmOrr`, `kArmEor`, `kArmSub`, `kArmRsb`, `kArmBfc`, `kArmUbfx`, `kArmSbfx`, `kArmSxtb`, `kArmSxth`, `kArmSxtab`, `kArmSxtah`, `kArmUxtb`, `kArmUxth`, `kArmUxtab`, `kArmUxtah`, `kArmRbit`, `kArmRev`, `kArmClz`, `kArmCmp`, `kArmCmn`, `kArmTst`, `kArmTeq`**:  A series of ARM assembly instructions for arithmetic, logical, and bitwise operations.
- **`kArmAddPair`, `kArmSubPair`, `kArmMulPair`, `kArmLslPair`, `kArmLsrPair`, `kArmAsrPair`**: Operations on pairs of registers, likely for handling 64-bit values.
- **`kArmVcmpF32`, `kArmVaddF32`, `kArmVsubF32`, `kArmVmulF32`, `kArmVmlaF32`, `kArmVmlsF32`, `kArmVdivF32`, `kArmVsqrtF32`, `kArmVabsF32`, `kArmVnegF32`, `kArmVcmpF64`, `kArmVaddF64`, `kArmVsubF64`, `kArmVmulF64`, `kArmVmlaF64`, `kArmVmlsF64`, `kArmVdivF64`, `kArmVmodF64`, `kArmVsqrtF64`, `kArmVabsF64`, `kArmVnegF64`, `kArmVrintmF32`, `kArmVrintmF64`, `kArmVrintpF32`, `kArmVrintpF64`, `kArmVrintzF32`, `kArmVrintzF64`, `kArmVrintaF64`, `kArmVrintnF32`, `kArmVrintnF64`, `kArmVcvtF32F64`, `kArmVcvtF64F32`, `kArmVcvtF32S32`, `kArmVcvtF32U32`, `kArmVcvtF64S32`, `kArmVcvtF64U32`, `kArmVcvtS32F32`, `kArmVcvtU32F32`, `kArmVcvtS32F64`, `kArmVcvtU32F64`, `kArmVmovU32F32`, `kArmVmovF32U32`, `kArmVmovLowU32F64`, `kArmVmovLowF64U32`, `kArmVmovHighU32F64`, `kArmVmovHighF64U32`, `kArmVmovF64U32U32`, `kArmVmovU32U32F64`, `kArmVcnt`**:  ARM Vector Floating Point (VFP) instructions for single-precision and double-precision floating-point operations, and some NEON (SIMD) instructions.
- **`kArmLdrb`, `kArmLdrsb`, `kArmStrb`, `kArmLdrh`, `kArmLdrsh`, `kArmStrh`, `kArmLdr`, `kArmStr`, `kArmVldrF32`, `kArmVstrF32`, `kArmVld1F64`, `kArmVst1F64`, `kArmVld1S128`, `kArmVst1S128`, `kArmVldrF64`, `kArmVstrF64`**: ARM load and store instructions for bytes, half-words, words, and floating-point values.
- **`kArmFloat32Max`, `kArmFloat64Max`, `kArmFloat32Min`**:  Find the maximum or minimum of two floating-point numbers.
这是v8/src/compiler/backend/arm/code-generator-arm.cc的第二部分代码，它主要负责**生成ARM架构的机器码**，具体功能包括：

1. **处理函数调用和返回:**
   - `kArchPopCallerSaved`: 从栈中恢复被调用者保存的寄存器。
   - `kArchPrepareTailCall`:  准备进行尾调用优化。
   - `kArchCallCFunctionWithFrameState`, `kArchCallCFunction`: 调用C函数，包括设置参数、保存返回地址，并可能记录帧状态以支持反优化。
   - `kArchRet`: 生成函数返回的汇编代码。

2. **控制流操作:**
   - `kArchJmp`: 生成无条件跳转指令。
   - `kArchBinarySearchSwitch`, `kArchTableSwitch`:  实现 `switch` 语句的汇编代码生成，分别使用二分查找和跳转表。
   - `kArchAbortCSADcheck`:  调用内置函数 `Builtin::kAbortCSADcheck`，用于 CodeStubAssembler 的调试检查。
   - `kArchDebugBreak`: 插入断点指令，用于调试。
   - `kArchThrowTerminator`: 标记代码块将抛出异常而终止。
   - `kArchDeoptimize`:  生成用于反优化的跳转指令。

3. **栈帧管理:**
   - `kArchFramePointer`: 将帧指针 (fp) 移动到指定的寄存器。
   - `kArchParentFramePointer`:  将父帧指针加载到指定的寄存器。
   - `kArchStackPointer`, `kArchSetStackPointer`: （主要用于WebAssembly）获取和设置栈指针 (sp)。
   - `kArchStackPointerGreaterThan`: 比较栈指针是否大于某个值，用于栈溢出检查。
   - `kArchStackCheckOffset`:  获取栈检查偏移量。
   - `kArchStackSlot`: 计算栈上特定偏移量的地址。

4. **数据操作:**
   - `kArchMov`:  生成数据移动指令。
   - `kArchNop`: 生成空操作指令。
   - `kArchComment`: 在生成的汇编代码中添加注释。
   - `kArchTruncateDoubleToI`: 将双精度浮点数截断为整数。
   - `kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`:  生成带有写屏障的存储指令，用于更新堆中的对象指针，确保垃圾回收器的正确性。
   - `kArmAdd`, `kArmAnd`, `kArmBic`, `kArmMul`, `kArmMla`, `kArmMls`, `kArmSmull`, `kArmSmmul`, `kArmSmmla`, `kArmUmull`, `kArmSdiv`, `kArmUdiv`, `kArmMvn`, `kArmOrr`, `kArmEor`, `kArmSub`, `kArmRsb`, `kArmBfc`, `kArmUbfx`, `kArmSbfx`, `kArmSxtb`, `kArmSxth`, `kArmSxtab`, `kArmSxtah`, `kArmUxtb`, `kArmUxth`, `kArmUxtab`, `kArmUxtah`, `kArmRbit`, `kArmRev`, `kArmClz`, `kArmCmp`, `kArmCmn`, `kArmTst`, `kArmTeq`:  生成各种ARM算术、逻辑和位操作指令。
   - `kArmAddPair`, `kArmSubPair`, `kArmMulPair`, `kArmLslPair`, `kArmLsrPair`, `kArmAsrPair`:  生成操作寄存器对的指令，通常用于处理64位整数。
   - `kArmLdrb`, `kArmLdrsb`, `kArmStrb`, `kArmLdrh`, `kArmLdrsh`, `kArmStrh`, `kArmLdr`, `kArmStr`:  生成加载和存储字节、半字和字的指令。

5. **浮点数操作:**
   - `kIeee754Float64Acos` 等一系列 `kIeee754Float64...`: 生成各种IEEE 754双精度浮点数运算的指令 (三角函数、指数、对数等)。
   - `kArmVcmpF32`, `kArmVaddF32` 等一系列 `kArmV...F32` 和 `kArmV...F64`: 生成ARM VFP (Vector Floating Point) 单元的单精度和双精度浮点数运算指令。
   - `kArmVcvtF32F64` 等一系列 `kArmVcvt...`: 生成浮点数类型转换指令。
   - `kArmVmovU32F32` 等一系列 `kArmVmov...`: 生成浮点数和整数之间数据移动的指令。
   - `kArmVld1F64`, `kArmVst1F64`, `kArmVldrF64`, `kArmVstrF64`, `kArmVld1S128`, `kArmVst1S128`, `kArmVldrF32`, `kArmVstrF32`: 生成加载和存储浮点数的指令。
   - `kArmFloat32Max`, `kArmFloat64Max`, `kArmFloat32Min`: 生成计算两个浮点数最大值或最小值的指令。

**关于代码的属性：**

* **不是Torque源代码:**  `v8/src/compiler/backend/arm/code-generator-arm.cc` 以 `.cc` 结尾，因此它是C++源代码，而不是Torque源代码（Torque源代码以 `.tq` 结尾）。

**与JavaScript的关系及示例：**

很多功能都与JavaScript的功能有关系，特别是浮点数运算和一些基础的算术运算。

**JavaScript 示例 (浮点数运算):**

```javascript
let x = 1.0;
let y = 2.0;
let sum = x + y; // 对应 kArmVaddF64 或类似指令
let sqrt_x = Math.sqrt(x); // 对应 kArmVsqrtF64
let sin_y = Math.sin(y);   // 对应 kIeee754Float64Sin
```

当V8执行这些JavaScript代码时，`code-generator-arm.cc` 会生成相应的ARM汇编指令来完成这些操作。

**代码逻辑推理及示例：**

**假设输入：** 一个 `kArmAdd` 指令，输入寄存器 `r1 = 5`, 输入操作数2 是立即数 `3`。

**输出：** 生成的汇编代码会将 `r1` 和 `3` 相加，结果存储在输出寄存器中 (假设是 `r0`)。  生成的汇编可能是 `add r0, r1, #3`。

**用户常见的编程错误示例：**

在涉及到写屏障的 `kArchStoreWithWriteBarrier` 中，一个常见的错误是 **忘记在存储指针类型的属性后执行写屏障**。如果一个对象包含了指向其他堆对象的指针，并且这个指针被更新了，但没有执行写屏障，那么垃圾回收器可能无法正确追踪到这个新的指针，导致过早回收对象，引发程序崩溃或数据损坏。

**例如 (C++ 模拟，概念上与 JavaScript 垃圾回收相关):**

```c++
class Object {
public:
  Object* child;
};

Object* parent = new Object();
Object* child1 = new Object();
Object* child2 = new Object();

parent->child = child1; // 假设这里对应一次带写屏障的存储

parent->child = child2; // 如果这里没有对应的写屏障，垃圾回收器可能仍然认为 parent 指向 child1
```

**功能归纳 (第2部分):**

这部分 `code-generator-arm.cc` 的代码主要负责**生成ARM架构下用于函数调用、控制流、栈帧管理、基本数据操作以及浮点数运算的机器码指令**。它涵盖了从简单的算术运算到复杂的浮点数运算，以及与垃圾回收机制相关的写屏障操作。  这部分代码是V8将高级语言（如JavaScript）编译成可执行机器码的关键组成部分。

### 提示词
```
这是目录为v8/src/compiler/backend/arm/code-generator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/code-generator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
the returned value.
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
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes;
      Label return_location;
#if V8_ENABLE_WEBASSEMBLY
      if (linkage()->GetIncomingDescriptor()->IsWasmCapiFunction()) {
        // Put the return address in a stack slot.
        Register pc_scratch = r5;
        __ Push(pc_scratch);
        __ GetLabelAddress(pc_scratch, &return_location);
        __ str(pc_scratch,
               MemOperand(fp, WasmExitFrameConstants::kCallingPCOffset));
        __ Pop(pc_scratch);
        set_isolate_data_slots = SetIsolateDataSlots::kNo;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
      int pc_offset;
      if (instr->InputAt(0)->IsImmediate()) {
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
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchBinarySearchSwitch:
      AssembleArchBinarySearchSwitch(instr);
      break;
    case kArchTableSwitch:
      AssembleArchTableSwitch(instr);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchAbortCSADcheck:
      DCHECK(i.InputRegister(0) == r1);
      {
        // We don't actually want to generate a pile of code for this, so just
        // claim there is a stack frame, without generating one.
        FrameScope scope(masm(), StackFrame::NO_FRAME_TYPE);
        __ CallBuiltin(Builtin::kAbortCSADcheck);
      }
      __ stop();
      unwinding_info_writer_.MarkBlockWillExit();
      break;
    case kArchDebugBreak:
      __ DebugBreak();
      break;
    case kArchComment:
      __ RecordComment(reinterpret_cast<const char*>(i.InputInt32(0)),
                       SourceLocation());
      break;
    case kArchThrowTerminator:
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      unwinding_info_writer_.MarkBlockWillExit();
      break;
    case kArchNop:
      // don't emit code for nops.
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchDeoptimize: {
      DeoptimizationExit* exit =
          BuildTranslation(instr, -1, 0, 0, OutputFrameStateCombine::Ignore());
      __ b(exit->label());
      break;
    }
    case kArchRet:
      AssembleReturn(instr->InputAt(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchFramePointer:
      __ mov(i.OutputRegister(), fp);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchParentFramePointer:
      if (frame_access_state()->has_frame()) {
        __ ldr(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mov(i.OutputRegister(), fp);
      }
      break;
#if V8_ENABLE_WEBASSEMBLY
    case kArchStackPointer:
      // The register allocator expects an allocatable register for the output,
      // we cannot use sp directly.
      __ mov(i.OutputRegister(), sp);
      break;
    case kArchSetStackPointer:
      DCHECK(instr->InputAt(0)->IsRegister());
      __ mov(sp, i.InputRegister(0));
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchStackPointerGreaterThan: {
      // Potentially apply an offset to the current stack pointer before the
      // comparison to consider the size difference of an optimized frame versus
      // the contained unoptimized frames.

      Register lhs_register = sp;
      uint32_t offset;

      if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
        lhs_register = i.TempRegister(0);
        __ sub(lhs_register, sp, Operand(offset));
      }

      constexpr size_t kValueIndex = 0;
      DCHECK(instr->InputAt(kValueIndex)->IsRegister());
      __ cmp(lhs_register, i.InputRegister(kValueIndex));
      break;
    }
    case kArchStackCheckOffset:
      __ Move(i.OutputRegister(), Smi::FromInt(GetStackCheckOffset()));
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArchStoreWithWriteBarrier:  // Fall through.
    case kArchAtomicStoreWithWriteBarrier: {
      RecordWriteMode mode;
      if (arch_opcode == kArchStoreWithWriteBarrier) {
        mode = RecordWriteModeField::decode(instr->opcode());
      } else {
        mode = AtomicStoreRecordWriteModeField::decode(instr->opcode());
      }
      Register object = i.InputRegister(0);
      Register value = i.InputRegister(2);

      if (v8_flags.debug_code) {
        // Checking that |value| is not a cleared weakref: our write barrier
        // does not support that for now.
        __ cmp(value, Operand(kClearedWeakHeapObjectLower32));
        __ Check(ne, AbortReason::kOperandIsCleared);
      }

      AddressingMode addressing_mode =
          AddressingModeField::decode(instr->opcode());
      Operand offset(0);

      if (arch_opcode == kArchAtomicStoreWithWriteBarrier) {
        __ dmb(ISH);
      }
      if (addressing_mode == kMode_Offset_RI) {
        int32_t immediate = i.InputInt32(1);
        offset = Operand(immediate);
        __ str(value, MemOperand(object, immediate));
      } else {
        DCHECK_EQ(kMode_Offset_RR, addressing_mode);
        Register reg = i.InputRegister(1);
        offset = Operand(reg);
        __ str(value, MemOperand(object, reg));
      }
      if (arch_opcode == kArchAtomicStoreWithWriteBarrier &&
          AtomicMemoryOrderField::decode(instr->opcode()) ==
              AtomicMemoryOrder::kSeqCst) {
        __ dmb(ISH);
      }

      auto ool = zone()->New<OutOfLineRecordWrite>(
          this, object, offset, value, mode, DetermineStubCallMode(),
          &unwinding_info_writer_);
      if (mode > RecordWriteMode::kValueIsPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, MemoryChunk::kPointersFromHereAreInterestingMask,
                       ne, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier:
      UNREACHABLE();
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base = offset.from_stack_pointer() ? sp : fp;
      __ add(i.OutputRegister(0), base, Operand(offset.offset()));
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
    case kArmAdd:
      __ add(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmAnd:
      __ and_(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
              i.OutputSBit());
      break;
    case kArmBic:
      __ bic(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmMul:
      __ mul(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.OutputSBit());
      break;
    case kArmMla:
      __ mla(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.InputRegister(2), i.OutputSBit());
      break;
    case kArmMls: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ mls(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.InputRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmSmull:
      __ smull(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
               i.InputRegister(1));
      break;
    case kArmSmmul:
      __ smmul(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSmmla:
      __ smmla(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUmull:
      __ umull(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
               i.InputRegister(1), i.OutputSBit());
      break;
    case kArmSdiv: {
      CpuFeatureScope scope(masm(), SUDIV);
      __ sdiv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmUdiv: {
      CpuFeatureScope scope(masm(), SUDIV);
      __ udiv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmMov:
      __ Move(i.OutputRegister(), i.InputOperand2(0), i.OutputSBit());
      break;
    case kArmMvn:
      __ mvn(i.OutputRegister(), i.InputOperand2(0), i.OutputSBit());
      break;
    case kArmOrr:
      __ orr(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmEor:
      __ eor(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmSub:
      __ sub(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmRsb:
      __ rsb(i.OutputRegister(), i.InputRegister(0), i.InputOperand2(1),
             i.OutputSBit());
      break;
    case kArmBfc: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ bfc(i.OutputRegister(), i.InputInt8(1), i.InputInt8(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmUbfx: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ ubfx(i.OutputRegister(), i.InputRegister(0), i.InputInt8(1),
              i.InputInt8(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmSbfx: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ sbfx(i.OutputRegister(), i.InputRegister(0), i.InputInt8(1),
              i.InputInt8(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmSxtb:
      __ sxtb(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSxth:
      __ sxth(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSxtab:
      __ sxtab(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputInt32(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSxtah:
      __ sxtah(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputInt32(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUxtb:
      __ uxtb(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUxth:
      __ uxth(i.OutputRegister(), i.InputRegister(0), i.InputInt32(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUxtab:
      __ uxtab(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputInt32(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmUxtah:
      __ uxtah(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
               i.InputInt32(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmRbit: {
      CpuFeatureScope scope(masm(), ARMv7);
      __ rbit(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmRev:
      __ rev(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmClz:
      __ clz(i.OutputRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmCmp:
      __ cmp(i.InputRegister(0), i.InputOperand2(1));
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmCmn:
      __ cmn(i.InputRegister(0), i.InputOperand2(1));
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmTst:
      __ tst(i.InputRegister(0), i.InputOperand2(1));
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmTeq:
      __ teq(i.InputRegister(0), i.InputOperand2(1));
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmAddPair:
      // i.InputRegister(0) ... left low word.
      // i.InputRegister(1) ... left high word.
      // i.InputRegister(2) ... right low word.
      // i.InputRegister(3) ... right high word.
      __ add(i.OutputRegister(0), i.InputRegister(0), i.InputRegister(2),
             SetCC);
      __ adc(i.OutputRegister(1), i.InputRegister(1),
             Operand(i.InputRegister(3)));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmSubPair:
      // i.InputRegister(0) ... left low word.
      // i.InputRegister(1) ... left high word.
      // i.InputRegister(2) ... right low word.
      // i.InputRegister(3) ... right high word.
      __ sub(i.OutputRegister(0), i.InputRegister(0), i.InputRegister(2),
             SetCC);
      __ sbc(i.OutputRegister(1), i.InputRegister(1),
             Operand(i.InputRegister(3)));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmMulPair:
      // i.InputRegister(0) ... left low word.
      // i.InputRegister(1) ... left high word.
      // i.InputRegister(2) ... right low word.
      // i.InputRegister(3) ... right high word.
      __ umull(i.OutputRegister(0), i.OutputRegister(1), i.InputRegister(0),
               i.InputRegister(2));
      __ mla(i.OutputRegister(1), i.InputRegister(0), i.InputRegister(3),
             i.OutputRegister(1));
      __ mla(i.OutputRegister(1), i.InputRegister(2), i.InputRegister(1),
             i.OutputRegister(1));
      break;
    case kArmLslPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsImmediate()) {
        __ LslPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputInt32(2));
      } else {
        __ LslPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2));
      }
      break;
    }
    case kArmLsrPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsImmediate()) {
        __ LsrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputInt32(2));
      } else {
        __ LsrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2));
      }
      break;
    }
    case kArmAsrPair: {
      Register second_output =
          instr->OutputCount() >= 2 ? i.OutputRegister(1) : i.TempRegister(0);
      if (instr->InputAt(2)->IsImmediate()) {
        __ AsrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputInt32(2));
      } else {
        __ AsrPair(i.OutputRegister(0), second_output, i.InputRegister(0),
                   i.InputRegister(1), i.InputRegister(2));
      }
      break;
    }
    case kArmVcmpF32:
      if (instr->InputAt(1)->IsFPRegister()) {
        __ VFPCompareAndSetFlags(i.InputFloatRegister(0),
                                 i.InputFloatRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        // 0.0 is the only immediate supported by vcmp instructions.
        DCHECK_EQ(0.0f, i.InputFloat32(1));
        __ VFPCompareAndSetFlags(i.InputFloatRegister(0), i.InputFloat32(1));
      }
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmVaddF32:
      __ vadd(i.OutputFloatRegister(), i.InputFloatRegister(0),
              i.InputFloatRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVsubF32:
      __ vsub(i.OutputFloatRegister(), i.InputFloatRegister(0),
              i.InputFloatRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmulF32:
      __ vmul(i.OutputFloatRegister(), i.InputFloatRegister(0),
              i.InputFloatRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmlaF32:
      __ vmla(i.OutputFloatRegister(), i.InputFloatRegister(1),
              i.InputFloatRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmlsF32:
      __ vmls(i.OutputFloatRegister(), i.InputFloatRegister(1),
              i.InputFloatRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVdivF32:
      __ vdiv(i.OutputFloatRegister(), i.InputFloatRegister(0),
              i.InputFloatRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVsqrtF32:
      __ vsqrt(i.OutputFloatRegister(), i.InputFloatRegister(0));
      break;
    case kArmVabsF32:
      __ vabs(i.OutputFloatRegister(), i.InputFloatRegister(0));
      break;
    case kArmVnegF32:
      __ vneg(i.OutputFloatRegister(), i.InputFloatRegister(0));
      break;
    case kArmVcmpF64:
      if (instr->InputAt(1)->IsFPRegister()) {
        __ VFPCompareAndSetFlags(i.InputDoubleRegister(0),
                                 i.InputDoubleRegister(1));
      } else {
        DCHECK(instr->InputAt(1)->IsImmediate());
        // 0.0 is the only immediate supported by vcmp instructions.
        DCHECK_EQ(0.0, i.InputDouble(1));
        __ VFPCompareAndSetFlags(i.InputDoubleRegister(0), i.InputDouble(1));
      }
      DCHECK_EQ(SetCC, i.OutputSBit());
      break;
    case kArmVaddF64:
      __ vadd(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVsubF64:
      __ vsub(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmulF64:
      __ vmul(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmlaF64:
      __ vmla(i.OutputDoubleRegister(), i.InputDoubleRegister(1),
              i.InputDoubleRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmlsF64:
      __ vmls(i.OutputDoubleRegister(), i.InputDoubleRegister(1),
              i.InputDoubleRegister(2));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVdivF64:
      __ vdiv(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
              i.InputDoubleRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmodF64: {
      // TODO(bmeurer): We should really get rid of this special instruction,
      // and generate a CallAddress instruction instead.
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ PrepareCallCFunction(0, 2);
      __ MovToFloatParameters(i.InputDoubleRegister(0),
                              i.InputDoubleRegister(1));
      __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
      // Move the result in the double result register.
      __ MovFromFloatResult(i.OutputDoubleRegister());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVsqrtF64:
      __ vsqrt(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArmVabsF64:
      __ vabs(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArmVnegF64:
      __ vneg(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kArmVrintmF32: {
      CpuFeatureScope scope(masm(), ARMv8);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vrintm(NeonS32, i.OutputSimd128Register(),
                  i.InputSimd128Register(0));
      } else {
        __ vrintm(i.OutputFloatRegister(), i.InputFloatRegister(0));
      }
      break;
    }
    case kArmVrintmF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrintm(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVrintpF32: {
      CpuFeatureScope scope(masm(), ARMv8);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vrintp(NeonS32, i.OutputSimd128Register(),
                  i.InputSimd128Register(0));
      } else {
        __ vrintp(i.OutputFloatRegister(), i.InputFloatRegister(0));
      }
      break;
    }
    case kArmVrintpF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrintp(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVrintzF32: {
      CpuFeatureScope scope(masm(), ARMv8);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vrintz(NeonS32, i.OutputSimd128Register(),
                  i.InputSimd128Register(0));
      } else {
        __ vrintz(i.OutputFloatRegister(), i.InputFloatRegister(0));
      }
      break;
    }
    case kArmVrintzF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrintz(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVrintaF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrinta(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVrintnF32: {
      CpuFeatureScope scope(masm(), ARMv8);
      if (instr->InputAt(0)->IsSimd128Register()) {
        __ vrintn(NeonS32, i.OutputSimd128Register(),
                  i.InputSimd128Register(0));
      } else {
        __ vrintn(i.OutputFloatRegister(), i.InputFloatRegister(0));
      }
      break;
    }
    case kArmVrintnF64: {
      CpuFeatureScope scope(masm(), ARMv8);
      __ vrintn(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kArmVcvtF32F64: {
      __ vcvt_f32_f64(i.OutputFloatRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF64F32: {
      __ vcvt_f64_f32(i.OutputDoubleRegister(), i.InputFloatRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF32S32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vmov(scratch, i.InputRegister(0));
      __ vcvt_f32_s32(i.OutputFloatRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF32U32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vmov(scratch, i.InputRegister(0));
      __ vcvt_f32_u32(i.OutputFloatRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF64S32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vmov(scratch, i.InputRegister(0));
      __ vcvt_f64_s32(i.OutputDoubleRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtF64U32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vmov(scratch, i.InputRegister(0));
      __ vcvt_f64_u32(i.OutputDoubleRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtS32F32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vcvt_s32_f32(scratch, i.InputFloatRegister(0));
      __ vmov(i.OutputRegister(), scratch);
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_i32) {
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        __ cmn(i.OutputRegister(), Operand(1));
        __ mov(i.OutputRegister(), Operand(INT32_MIN), LeaveCC, vs);
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtU32F32: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vcvt_u32_f32(scratch, i.InputFloatRegister(0));
      __ vmov(i.OutputRegister(), scratch);
      bool set_overflow_to_min_u32 = MiscField::decode(instr->opcode());
      if (set_overflow_to_min_u32) {
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        __ cmn(i.OutputRegister(), Operand(1));
        __ adc(i.OutputRegister(), i.OutputRegister(), Operand::Zero());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtS32F64: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vcvt_s32_f64(scratch, i.InputDoubleRegister(0));
      __ vmov(i.OutputRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVcvtU32F64: {
      UseScratchRegisterScope temps(masm());
      SwVfpRegister scratch = temps.AcquireS();
      __ vcvt_u32_f64(scratch, i.InputDoubleRegister(0));
      __ vmov(i.OutputRegister(), scratch);
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVmovU32F32:
      __ vmov(i.OutputRegister(), i.InputFloatRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovF32U32:
      __ vmov(i.OutputFloatRegister(), i.InputRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovLowU32F64:
      __ VmovLow(i.OutputRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovLowF64U32:
      __ VmovLow(i.OutputDoubleRegister(), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovHighU32F64:
      __ VmovHigh(i.OutputRegister(), i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovHighF64U32:
      __ VmovHigh(i.OutputDoubleRegister(), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovF64U32U32:
      __ vmov(i.OutputDoubleRegister(), i.InputRegister(0), i.InputRegister(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVmovU32U32F64:
      __ vmov(i.OutputRegister(0), i.OutputRegister(1),
              i.InputDoubleRegister(0));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVcnt: {
      __ vcnt(i.OutputSimd128Register(), i.InputSimd128Register(0));
      break;
    }
    case kArmLdrb:
      __ ldrb(i.OutputRegister(), i.InputOffset());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmLdrsb:
      __ ldrsb(i.OutputRegister(), i.InputOffset());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmStrb:
      __ strb(i.InputRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmLdrh:
      __ ldrh(i.OutputRegister(), i.InputOffset());
      break;
    case kArmLdrsh:
      __ ldrsh(i.OutputRegister(), i.InputOffset());
      break;
    case kArmStrh:
      __ strh(i.InputRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmLdr:
      __ ldr(i.OutputRegister(), i.InputOffset());
      break;
    case kArmStr:
      __ str(i.InputRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVldrF32: {
      __ vldr(i.OutputFloatRegister(), i.InputOffset());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVstrF32:
      __ vstr(i.InputFloatRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmVld1F64: {
      __ vld1(Neon8, NeonListOperand(i.OutputDoubleRegister()),
              i.NeonInputOperand(0));
      break;
    }
    case kArmVst1F64: {
      __ vst1(Neon8, NeonListOperand(i.InputDoubleRegister(0)),
              i.NeonInputOperand(1));
      break;
    }
    case kArmVld1S128: {
      __ vld1(Neon8, NeonListOperand(i.OutputSimd128Register()),
              i.NeonInputOperand(0));
      break;
    }
    case kArmVst1S128: {
      __ vst1(Neon8, NeonListOperand(i.InputSimd128Register(0)),
              i.NeonInputOperand(1));
      break;
    }
    case kArmVldrF64: {
      __ vldr(i.OutputDoubleRegister(), i.InputOffset());
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmVstrF64:
      __ vstr(i.InputDoubleRegister(0), i.InputOffset(1));
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    case kArmFloat32Max: {
      SwVfpRegister result = i.OutputFloatRegister();
      SwVfpRegister left = i.InputFloatRegister(0);
      SwVfpRegister right = i.InputFloatRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat32Max>(this, result, left, right);
        __ FloatMax(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat64Max: {
      DwVfpRegister result = i.OutputDoubleRegister();
      DwVfpRegister left = i.InputDoubleRegister(0);
      DwVfpRegister right = i.InputDoubleRegister(1);
      if (left == right) {
        __ Move(result, left);
      } else {
        auto ool = zone()->New<OutOfLineFloat64Max>(this, result, left, right);
        __ FloatMax(result, left, right, ool->entry());
        __ bind(ool->exit());
      }
      DCHECK_EQ(LeaveCC, i.OutputSBit());
      break;
    }
    case kArmFloat32Min: {
      SwVfpRegister result = i.Out
```