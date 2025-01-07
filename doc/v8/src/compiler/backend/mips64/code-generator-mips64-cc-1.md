Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/backend/mips64/code-generator-mips64.cc`. This file seems to be responsible for generating MIPS64 assembly code from a higher-level intermediate representation within the V8 JavaScript engine.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Purpose:** The file name `code-generator-mips64.cc` strongly suggests its primary function is to translate instructions into MIPS64 machine code. The presence of a `switch` statement handling different `kArch*` and `kMips64*` cases confirms this. Each case corresponds to a specific operation or instruction.

2. **Categorize Functionality:** The different `case` statements within the `switch` block represent various categories of operations. These categories include:
    * **Stack Management:** Operations like `kArchStackPointer`, `kArchSetStackPointer`, `kArchStackSlot`, `kArchFramePointer`, `kArchParentFramePointer`, `kArchPush`, `kArchPop`.
    * **Control Flow:** Instructions like `kArchCallCodeObject`, `kArchCallJSFunction`, `kArchCallBuiltin`, `kArchJmp`, `kArchBinarySearchSwitch`, `kArchTableSwitch`, `kArchRet`, `kArchDeoptimize`.
    * **Debugging and Assertions:**  `kArchAbortCSADcheck`, `kArchDebugBreak`, `kArchComment`.
    * **Basic Arithmetic and Logic:** `kMips64Add`, `kMips64Sub`, `kMips64Mul`, `kMips64Div`, `kMips64And`, `kMips64Or`, `kMips64Xor`, `kMips64Shl`, `kMips64Shr`, etc.
    * **Floating-Point Operations:** Instructions starting with `kIeee754Float64` and `kMips64` followed by `S` or `D` (single or double precision).
    * **Memory Access:** `kMips64Lbu`, `kMips64Lb`, `kMips64Sb`, `kMips64Lhu`, etc., and the write barrier related instructions.
    * **Conversions:** Instructions like `kMips64CvtSD`, `kMips64CvtDS`, etc.
    * **Bit Manipulation:** `kMips64Clz`, `kMips64Ctz`, `kMips64Popcnt`, `kMips64Ext`, `kMips64Ins`.
    * **Moves and Loads:** `kMips64Mov`.
    * **Write Barriers:** `kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`.

3. **Address Specific Questions:**

    * **`.tq` extension:**  The code is C++, so it's not a Torque file.
    * **Relationship to JavaScript:**  The code generator is a crucial part of the V8 engine that takes JavaScript code (after parsing and optimization) and transforms it into executable machine code. Many of the operations directly correspond to JavaScript concepts.
    * **JavaScript Examples:**  For arithmetic, logical, and floating-point operations, simple JavaScript examples can be given that would trigger these low-level MIPS64 instructions. For example, `a + b` might use `kMips64Add`, `Math.sqrt(x)` might use `kIeee754Float64Sqrt`.
    * **Code Logic Reasoning (Hypothetical):**  Consider a simple addition. Assume input registers hold two numbers. The output register will hold their sum after the `__ Addu(...)` instruction.
    * **Common Programming Errors:**  Focus on errors that could relate to the generated assembly, such as integer overflow (handled by `kMips64DaddOvf`), type errors leading to incorrect float operations, or memory errors that might be related to write barriers.

4. **Structure the Output:** Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * List the key functionalities with brief descriptions.
    * Address each specific question from the prompt.
    * Provide JavaScript examples where relevant.
    * Offer hypothetical input/output scenarios for code logic.
    * Illustrate common programming errors related to the generated code.
    * Conclude with a concise summary of the extracted functionality.

5. **Refine and Elaborate:** Review the generated output for clarity and accuracy. Ensure the JavaScript examples are simple and directly related to the listed functionality. Expand on the explanations where necessary, but avoid excessive technical jargon. For instance, explain what a write barrier is in the context of memory management.

By following these steps, a comprehensive and informative answer can be generated that addresses all aspects of the user's request.
`v8/src/compiler/backend/mips64/code-generator-mips64.cc` 是 V8 JavaScript 引擎中负责将平台无关的中间代码（Instruction）转换为 MIPS64 架构的汇编代码的组件。这是代码生成器的核心部分，针对 MIPS64 架构实现了各种指令的处理逻辑。

**功能归纳 (针对提供的代码片段):**

这部分代码主要负责处理各种架构相关的指令 (`kArch*`) 和 MIPS64 特定的指令 (`kMips64*`)，并生成相应的 MIPS64 汇编代码。 它的功能可以归纳为以下几点：

1. **处理函数调用和返回:**
   - `kArchCallCodeObject`, `kArchCallJSFunction`, `kArchCallBuiltin`: 生成调用代码对象、JavaScript 函数或内置函数的汇编代码，包括参数传递和寄存器保存。
   - `kArchRestoreCallerRegisters`:  恢复被调用者保存的调用者寄存器。
   - `kArchRet`: 生成函数返回的汇编代码。

2. **处理跳转和分支:**
   - `kArchJmp`: 生成无条件跳转指令。
   - `kArchBinarySearchSwitch`, `kArchTableSwitch`:  生成用于实现 `switch` 语句的二进制搜索或跳转表。
   - `kArchDeoptimize`:  生成用于执行反优化的跳转指令。

3. **处理栈操作:**
   - `kArchStackPointer`, `kArchSetStackPointer`: 获取和设置栈指针。
   - `kArchStackPointerGreaterThan`: 比较栈指针与给定值。
   - `kArchStackCheckOffset`: 获取栈检查偏移量。
   - `kArchFramePointer`, `kArchParentFramePointer`: 获取帧指针和父帧指针。
   - `kArchStackSlot`: 计算栈槽的地址。
   - `kArchPush`, `kArchPop`:  模拟压栈和出栈操作（在某些情况下可能是宏）。

4. **处理调试和错误处理:**
   - `kArchAbortCSADcheck`: 调用内置函数 `kAbortCSADcheck` 用于 CSA (Canonical Stack Addressing) 检查失败时中止执行。
   - `kArchDebugBreak`: 生成断点指令。
   - `kArchComment`: 插入注释到生成的汇编代码中。
   - `kArchThrowTerminator`:  不生成代码，可能用于标记代码块的结束。

5. **处理浮点数运算 (使用 IEEE754 标准和 MIPS64 指令):**
   - `kIeee754Float64Acos`, `kIeee754Float64Acosh`, ..., `kIeee754Float64Tanh`:  处理各种 IEEE754 标准的浮点数单目运算 (如 acos, acosh, 等)。
   - `kIeee754Float64Atan2`, `kIeee754Float64Pow`: 处理 IEEE754 标准的浮点数双目运算。
   - `kMips64AddS`, `kMips64SubS`, `kMips64MulS`, `kMips64DivS`, `kMips64AbsS`, `kMips64NegS`, `kMips64SqrtS`, `kMips64MaxS`, `kMips64MinS`: 处理单精度浮点数算术运算。
   - `kMips64AddD`, `kMips64SubD`, `kMips64MulD`, `kMips64DivD`, `kMips64ModD`, `kMips64AbsD`, `kMips64NegD`, `kMips64SqrtD`, `kMips64MaxD`, `kMips64MinD`: 处理双精度浮点数算术运算。
   - `kMips64Float64RoundDown`, `kMips64Float32RoundDown`, ..., `kMips64Float32RoundTiesEven`: 处理浮点数舍入操作。
   - `kMips64CvtSD`, `kMips64CvtDS`, `kMips64CvtDW`, `kMips64CvtSW`, `kMips64CvtSUw`, `kMips64CvtSL`, `kMips64CvtDL`, `kMips64CvtDUw`, `kMips64CvtDUl`, `kMips64CvtSUl`: 处理不同浮点数和整数类型之间的转换。
   - `kMips64FloorWD`, `kMips64CeilWD`, `kMips64RoundWD`, `kMips64TruncWD`, `kMips64FloorWS`, `kMips64CeilWS`, `kMips64RoundWS`, `kMips64TruncWS`, `kMips64TruncLS`, `kMips64TruncLD`, `kMips64TruncUwD`, `kMips64TruncUwS`, `kMips64TruncUlS`, `kMips64TruncUlD`: 处理浮点数到整数的转换，并可能检查溢出。
   - `kMips64BitcastDL`, `kMips64BitcastLD`:  在双精度浮点数和 64 位整数之间进行位级别的类型转换。
   - `kMips64Float64ExtractLowWord32`, `kMips64Float64ExtractHighWord32`, `kMips64Float64FromWord32Pair`, `kMips64Float64InsertLowWord32`, `kMips64Float64InsertHighWord32`: 处理双精度浮点数的低 32 位和高 32 位。
   - `kMips64Float32Max`, `kMips64Float64Max`, `kMips64Float32Min`, `kMips64Float64Min`: 计算两个浮点数的最大值或最小值，可能需要处理 NaN 的情况。
   - `kMips64Float64SilenceNaN`: 将 NaN 值规范化。

6. **处理整数运算和位操作 (使用 MIPS64 指令):**
   - `kMips64Add`, `kMips64Dadd`, `kMips64DaddOvf`, `kMips64Sub`, `kMips64Dsub`, `kMips64DsubOvf`, `kMips64Mul`, `kMips64MulOvf`, `kMips64DMulOvf`, `kMips64MulHigh`, `kMips64MulHighU`, `kMips64DMulHigh`, `kMips64DMulHighU`, `kMips64Div`, `kMips64DivU`, `kMips64Mod`, `kMips64ModU`, `kMips64Dmul`, `kMips64Ddiv`, `kMips64DdivU`, `kMips64Dmod`, `kMips64DmodU`: 处理各种 32 位和 64 位整数的加减乘除和取模运算，包括溢出检查。
   - `kMips64Dlsa`, `kMips64Lsa`: 处理带符号左移位操作。
   - `kMips64And`, `kMips64And32`, `kMips64Or`, `kMips64Or32`, `kMips64Nor`, `kMips64Nor32`, `kMips64Xor`, `kMips64Xor32`: 处理位与、或、异或和非或运算。
   - `kMips64Clz`, `kMips64Dclz`, `kMips64Ctz`, `kMips64Dctz`, `kMips64Popcnt`, `kMips64Dpopcnt`: 处理前导零计数、尾随零计数和人口计数。
   - `kMips64Shl`, `kMips64Shr`, `kMips64Sar`, `kMips64Dshl`, `kMips64Dshr`, `kMips64Dsar`: 处理左移、逻辑右移和算术右移操作。
   - `kMips64Ext`, `kMips64Ins`, `kMips64Dext`, `kMips64Dins`: 处理位提取和插入操作。
   - `kMips64Ror`, `kMips64Dror`: 处理循环右移操作。
   - `kMips64Tst`, `kMips64Cmp`:  伪指令，用于比较并设置标志位，通常与分支指令配合使用。
   - `kMips64Mov`: 移动数据到寄存器，可以是从立即数或另一个寄存器。

7. **处理内存访问和写屏障:**
   - `kMips64Lbu`, `kMips64Lb`, `kMips64Sb`, `kMips64Lhu`, ... : 处理各种大小和类型的内存加载和存储指令。
   - `kArchStoreWithWriteBarrier`, `kArchAtomicStoreWithWriteBarrier`: 生成带有写屏障的存储指令，用于垃圾回收的堆内存管理。
   - `kArchStoreIndirectWithWriteBarrier`:  （当前代码中 `UNREACHABLE()`） 表示间接存储写屏障尚未实现。

8. **WebAssembly 支持 (部分):**
   - `kArchStackPointer`, `kArchSetStackPointer`:  在 WebAssembly 上下文中管理栈指针。

**关于 `.tq` 结尾：**

如果 `v8/src/compiler/backend/mips64/code-generator-mips64.cc` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用于定义内置函数和运行时函数的 DSL (Domain Specific Language)。当前的 `.cc` 后缀表明这是 C++ 源代码。

**与 JavaScript 的关系和示例：**

`code-generator-mips64.cc` 的核心功能是将 JavaScript 代码编译成机器码。许多操作都直接对应 JavaScript 的语法和语义。

**JavaScript 示例：**

```javascript
let a = 10;
let b = 5;
let sum = a + b; // 可能会对应 kMips64Add 指令

let x = 3.14;
let y = Math.sqrt(x); // 可能会对应 kIeee754Float64Sqrt 指令

function myFunction(p1, p2) {
  return p1 * p2;
}
myFunction(2, 3); // 函数调用会涉及 kArchCallJSFunction 等指令
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:** 一个 `kMips64Add` 指令，指定将寄存器 `r1` 和立即数 `5` 相加，结果存储到寄存器 `r0`。

**输出的 MIPS64 汇编代码:** `add r0, r1, 5`

在这个例子中，`__ Addu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1))` 这行代码会生成相应的 MIPS64 `add` 指令。

**用户常见的编程错误举例：**

1. **整数溢出:**  在 JavaScript 中，数值类型可以表示很大的整数，但在底层硬件层面，整数运算有大小限制。如果 JavaScript 代码执行的整数运算超出了 MIPS64 整数寄存器的表示范围，可能会导致意外的结果。V8 会尝试处理这种情况，但了解底层的限制有助于理解某些行为。
   ```javascript
   let maxInt = 9007199254740991; // JavaScript 的 Number 类型可以表示的大整数
   let result = maxInt + 1; // 在 JavaScript 中不会溢出，会得到一个更大的 Number
   // 但如果涉及到底层的整数运算，需要注意潜在的溢出。
   ```
   在 MIPS64 中，如果使用 `kMips64DaddOvf` 这样的指令，可以捕获溢出。

2. **浮点数精度问题:** 浮点数在计算机中以近似值存储，进行运算时可能存在精度损失。
   ```javascript
   let a = 0.1;
   let b = 0.2;
   let sum = a + b;
   console.log(sum); // 输出可能不是精确的 0.3
   ```
   相关的 `kIeee754Float64*` 指令在执行这些浮点数运算时，会受到浮点数表示的固有限制。

**总结这部分代码的功能：**

总而言之，提供的代码片段是 `v8/src/compiler/backend/mips64/code-generator-mips64.cc` 文件的一部分，它负责 **将 V8 内部的中间表示指令翻译成实际的 MIPS64 汇编指令**。 这包括处理函数调用、控制流、栈操作、基本运算（整数和浮点数）、内存访问以及一些架构特定的指令。 这是 V8 引擎将 JavaScript 代码转换为可在 MIPS64 架构上执行的机器码的关键步骤。

Prompt: 
```
这是目录为v8/src/compiler/backend/mips64/code-generator-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/code-generator-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
a statically.
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
        __ Dsubu(lhs_register, sp, offset);
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
        __ Ld(i.OutputRegister(), MemOperand(fp, 0));
      } else {
        __ mov(i.OutputRegister(), fp);
      }
      break;
    case kArchTruncateDoubleToI:
      __ TruncateDoubleToI(isolate(), zone(), i.OutputRegister(),
                           i.InputDoubleRegister(0), DetermineStubCallMode());
      break;
    case kArchStoreWithWriteBarrier:  // Fall through.
    case kArchAtomicStoreWithWriteBarrier: {
      RecordWriteMode mode = RecordWriteModeField::decode(instr->opcode());
      Register object = i.InputRegister(0);
      Register index = i.InputRegister(1);
      Register value = i.InputRegister(2);
      Register scratch0 = i.TempRegister(0);
      Register scratch1 = i.TempRegister(1);
      auto ool = zone()->New<OutOfLineRecordWrite>(this, object, index, value,
                                                   scratch0, scratch1, mode,
                                                   DetermineStubCallMode());
      __ Daddu(kScratchReg, object, index);
      if (arch_opcode == kArchStoreWithWriteBarrier) {
        __ Sd(value, MemOperand(kScratchReg));
      } else {
        DCHECK_EQ(kArchAtomicStoreWithWriteBarrier, arch_opcode);
        __ sync();
        __ Sd(value, MemOperand(kScratchReg));
        __ sync();
      }
      if (mode > RecordWriteMode::kValueIsPointer) {
        __ JumpIfSmi(value, ool->exit());
      }
      __ CheckPageFlag(object, scratch0,
                       MemoryChunk::kPointersFromHereAreInterestingMask, ne,
                       ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kArchStoreIndirectWithWriteBarrier:
      UNREACHABLE();
    case kArchStackSlot: {
      FrameOffset offset =
          frame_access_state()->GetFrameOffset(i.InputInt32(0));
      Register base_reg = offset.from_stack_pointer() ? sp : fp;
      __ Daddu(i.OutputRegister(), base_reg, Operand(offset.offset()));
      if (v8_flags.debug_code) {
        // Verify that the output_register is properly aligned
        __ And(kScratchReg, i.OutputRegister(),
               Operand(kSystemPointerSize - 1));
        __ Assert(eq, AbortReason::kAllocationIsNotDoubleAligned, kScratchReg,
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
    case kMips64Add:
      __ Addu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Dadd:
      __ Daddu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64DaddOvf:
      __ DaddOverflow(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1),
                      kScratchReg);
      break;
    case kMips64Sub:
      __ Subu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Dsub:
      __ Dsubu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64DsubOvf:
      __ DsubOverflow(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1),
                      kScratchReg);
      break;
    case kMips64Mul:
      __ Mul(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64MulOvf:
      __ MulOverflow(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1),
                     kScratchReg);
      break;
    case kMips64DMulOvf:
      __ DMulOverflow(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1),
                      kScratchReg);
      break;
    case kMips64MulHigh:
      __ Mulh(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64MulHighU:
      __ Mulhu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64DMulHigh:
      __ Dmulh(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64DMulHighU:
      __ Dmulhu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Div:
      __ Div(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      if (kArchVariant == kMips64r6) {
        __ selnez(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        __ Movz(i.OutputRegister(), i.InputRegister(1), i.InputRegister(1));
      }
      break;
    case kMips64DivU:
      __ Divu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      if (kArchVariant == kMips64r6) {
        __ selnez(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        __ Movz(i.OutputRegister(), i.InputRegister(1), i.InputRegister(1));
      }
      break;
    case kMips64Mod:
      __ Mod(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64ModU:
      __ Modu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Dmul:
      __ Dmul(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Ddiv:
      __ Ddiv(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      if (kArchVariant == kMips64r6) {
        __ selnez(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        __ Movz(i.OutputRegister(), i.InputRegister(1), i.InputRegister(1));
      }
      break;
    case kMips64DdivU:
      __ Ddivu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      if (kArchVariant == kMips64r6) {
        __ selnez(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        __ Movz(i.OutputRegister(), i.InputRegister(1), i.InputRegister(1));
      }
      break;
    case kMips64Dmod:
      __ Dmod(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64DmodU:
      __ Dmodu(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Dlsa:
      DCHECK(instr->InputAt(2)->IsImmediate());
      __ Dlsa(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
              i.InputInt8(2));
      break;
    case kMips64Lsa:
      DCHECK(instr->InputAt(2)->IsImmediate());
      __ Lsa(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1),
             i.InputInt8(2));
      break;
    case kMips64And:
      __ And(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64And32:
        __ And(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Or:
      __ Or(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Or32:
        __ Or(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Nor:
      if (instr->InputAt(1)->IsRegister()) {
        __ Nor(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      } else {
        DCHECK_EQ(0, i.InputOperand(1).immediate());
        __ Nor(i.OutputRegister(), i.InputRegister(0), zero_reg);
      }
      break;
    case kMips64Nor32:
      if (instr->InputAt(1)->IsRegister()) {
        __ Nor(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      } else {
        DCHECK_EQ(0, i.InputOperand(1).immediate());
        __ Nor(i.OutputRegister(), i.InputRegister(0), zero_reg);
      }
      break;
    case kMips64Xor:
      __ Xor(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Xor32:
        __ Xor(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
        __ sll(i.OutputRegister(), i.OutputRegister(), 0x0);
      break;
    case kMips64Clz:
      __ Clz(i.OutputRegister(), i.InputRegister(0));
      break;
    case kMips64Dclz:
      __ dclz(i.OutputRegister(), i.InputRegister(0));
      break;
    case kMips64Ctz: {
      Register src = i.InputRegister(0);
      Register dst = i.OutputRegister();
      __ Ctz(dst, src);
    } break;
    case kMips64Dctz: {
      Register src = i.InputRegister(0);
      Register dst = i.OutputRegister();
      __ Dctz(dst, src);
    } break;
    case kMips64Popcnt: {
      Register src = i.InputRegister(0);
      Register dst = i.OutputRegister();
      __ Popcnt(dst, src);
    } break;
    case kMips64Dpopcnt: {
      Register src = i.InputRegister(0);
      Register dst = i.OutputRegister();
      __ Dpopcnt(dst, src);
    } break;
    case kMips64Shl:
      if (instr->InputAt(1)->IsRegister()) {
        __ sllv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ sll(i.OutputRegister(), i.InputRegister(0),
               static_cast<uint16_t>(imm));
      }
      break;
    case kMips64Shr:
      if (instr->InputAt(1)->IsRegister()) {
        __ srlv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ srl(i.OutputRegister(), i.InputRegister(0),
               static_cast<uint16_t>(imm));
      }
      break;
    case kMips64Sar:
      if (instr->InputAt(1)->IsRegister()) {
        __ srav(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        __ sra(i.OutputRegister(), i.InputRegister(0),
               static_cast<uint16_t>(imm));
      }
      break;
    case kMips64Ext:
      __ Ext(i.OutputRegister(), i.InputRegister(0), i.InputInt8(1),
             i.InputInt8(2));
      break;
    case kMips64Ins:
      if (instr->InputAt(1)->IsImmediate() && i.InputInt8(1) == 0) {
        __ Ins(i.OutputRegister(), zero_reg, i.InputInt8(1), i.InputInt8(2));
      } else {
        __ Ins(i.OutputRegister(), i.InputRegister(0), i.InputInt8(1),
               i.InputInt8(2));
      }
      break;
    case kMips64Dext: {
      __ Dext(i.OutputRegister(), i.InputRegister(0), i.InputInt8(1),
              i.InputInt8(2));
      break;
    }
    case kMips64Dins:
      if (instr->InputAt(1)->IsImmediate() && i.InputInt8(1) == 0) {
        __ Dins(i.OutputRegister(), zero_reg, i.InputInt8(1), i.InputInt8(2));
      } else {
        __ Dins(i.OutputRegister(), i.InputRegister(0), i.InputInt8(1),
                i.InputInt8(2));
      }
      break;
    case kMips64Dshl:
      if (instr->InputAt(1)->IsRegister()) {
        __ dsllv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        if (imm < 32) {
          __ dsll(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
        } else {
          __ dsll32(i.OutputRegister(), i.InputRegister(0),
                    static_cast<uint16_t>(imm - 32));
        }
      }
      break;
    case kMips64Dshr:
      if (instr->InputAt(1)->IsRegister()) {
        __ dsrlv(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        if (imm < 32) {
          __ dsrl(i.OutputRegister(), i.InputRegister(0),
                  static_cast<uint16_t>(imm));
        } else {
          __ dsrl32(i.OutputRegister(), i.InputRegister(0),
                    static_cast<uint16_t>(imm - 32));
        }
      }
      break;
    case kMips64Dsar:
      if (instr->InputAt(1)->IsRegister()) {
        __ dsrav(i.OutputRegister(), i.InputRegister(0), i.InputRegister(1));
      } else {
        int64_t imm = i.InputOperand(1).immediate();
        if (imm < 32) {
          __ dsra(i.OutputRegister(), i.InputRegister(0), imm);
        } else {
          __ dsra32(i.OutputRegister(), i.InputRegister(0), imm - 32);
        }
      }
      break;
    case kMips64Ror:
      __ Ror(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Dror:
      __ Dror(i.OutputRegister(), i.InputRegister(0), i.InputOperand(1));
      break;
    case kMips64Tst:
      __ And(kScratchReg, i.InputRegister(0), i.InputOperand(1));
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kMips64Cmp:
      // Pseudo-instruction used for cmp/branch. No opcode emitted here.
      break;
    case kMips64Mov:
      // TODO(plind): Should we combine mov/li like this, or use separate instr?
      //    - Also see x64 ASSEMBLE_BINOP & RegisterOrOperandType
      if (HasRegisterInput(instr, 0)) {
        __ mov(i.OutputRegister(), i.InputRegister(0));
      } else {
        __ li(i.OutputRegister(), i.InputOperand(0));
      }
      break;

    case kMips64CmpS: {
      FPURegister left = i.InputOrZeroSingleRegister(0);
      FPURegister right = i.InputOrZeroSingleRegister(1);
      bool predicate;
      FPUCondition cc =
          FlagsConditionToConditionCmpFPU(&predicate, instr->flags_condition());

      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }

      __ CompareF32(cc, left, right);
    } break;
    case kMips64AddS:
      // TODO(plind): add special case: combine mult & add.
      __ add_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64SubS:
      __ sub_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64MulS:
      // TODO(plind): add special case: right op is -1.0, see arm port.
      __ mul_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64DivS:
      __ div_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64AbsS:
      if (kArchVariant == kMips64r6) {
        __ abs_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      } else {
        __ mfc1(kScratchReg, i.InputSingleRegister(0));
        __ Dins(kScratchReg, zero_reg, 31, 1);
        __ mtc1(kScratchReg, i.OutputSingleRegister());
      }
      break;
    case kMips64NegS:
      __ Neg_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    case kMips64SqrtS: {
      __ sqrt_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kMips64MaxS:
      __ max_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64MinS:
      __ min_s(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64CmpD: {
      FPURegister left = i.InputOrZeroDoubleRegister(0);
      FPURegister right = i.InputOrZeroDoubleRegister(1);
      bool predicate;
      FPUCondition cc =
          FlagsConditionToConditionCmpFPU(&predicate, instr->flags_condition());
      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      __ CompareF64(cc, left, right);
    } break;
    case kMips64AddD:
      // TODO(plind): add special case: combine mult & add.
      __ add_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64SubD:
      __ sub_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64MulD:
      // TODO(plind): add special case: right op is -1.0, see arm port.
      __ mul_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64DivD:
      __ div_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64ModD: {
      // TODO(bmeurer): We should really get rid of this special instruction,
      // and generate a CallAddress instruction instead.
      FrameScope scope(masm(), StackFrame::MANUAL);
      __ PrepareCallCFunction(0, 2, kScratchReg);
      __ MovToFloatParameters(i.InputDoubleRegister(0),
                              i.InputDoubleRegister(1));
      __ CallCFunction(ExternalReference::mod_two_doubles_operation(), 0, 2);
      // Move the result in the double result register.
      __ MovFromFloatResult(i.OutputDoubleRegister());
      break;
    }
    case kMips64AbsD:
      if (kArchVariant == kMips64r6) {
        __ abs_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      } else {
        __ dmfc1(kScratchReg, i.InputDoubleRegister(0));
        __ Dins(kScratchReg, zero_reg, 63, 1);
        __ dmtc1(kScratchReg, i.OutputDoubleRegister());
      }
      break;
    case kMips64NegD:
      __ Neg_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kMips64SqrtD: {
      __ sqrt_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kMips64MaxD:
      __ max_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64MinD:
      __ min_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0),
               i.InputDoubleRegister(1));
      break;
    case kMips64Float64RoundDown: {
      __ Floor_d_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kMips64Float32RoundDown: {
      __ Floor_s_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kMips64Float64RoundTruncate: {
      __ Trunc_d_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kMips64Float32RoundTruncate: {
      __ Trunc_s_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kMips64Float64RoundUp: {
      __ Ceil_d_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kMips64Float32RoundUp: {
      __ Ceil_s_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kMips64Float64RoundTiesEven: {
      __ Round_d_d(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    }
    case kMips64Float32RoundTiesEven: {
      __ Round_s_s(i.OutputSingleRegister(), i.InputSingleRegister(0));
      break;
    }
    case kMips64Float32Max: {
      FPURegister dst = i.OutputSingleRegister();
      FPURegister src1 = i.InputSingleRegister(0);
      FPURegister src2 = i.InputSingleRegister(1);
      auto ool = zone()->New<OutOfLineFloat32Max>(this, dst, src1, src2);
      __ Float32Max(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kMips64Float64Max: {
      FPURegister dst = i.OutputDoubleRegister();
      FPURegister src1 = i.InputDoubleRegister(0);
      FPURegister src2 = i.InputDoubleRegister(1);
      auto ool = zone()->New<OutOfLineFloat64Max>(this, dst, src1, src2);
      __ Float64Max(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kMips64Float32Min: {
      FPURegister dst = i.OutputSingleRegister();
      FPURegister src1 = i.InputSingleRegister(0);
      FPURegister src2 = i.InputSingleRegister(1);
      auto ool = zone()->New<OutOfLineFloat32Min>(this, dst, src1, src2);
      __ Float32Min(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kMips64Float64Min: {
      FPURegister dst = i.OutputDoubleRegister();
      FPURegister src1 = i.InputDoubleRegister(0);
      FPURegister src2 = i.InputDoubleRegister(1);
      auto ool = zone()->New<OutOfLineFloat64Min>(this, dst, src1, src2);
      __ Float64Min(dst, src1, src2, ool->entry());
      __ bind(ool->exit());
      break;
    }
    case kMips64Float64SilenceNaN:
      __ FPUCanonicalizeNaN(i.OutputDoubleRegister(), i.InputDoubleRegister(0));
      break;
    case kMips64CvtSD:
      __ cvt_s_d(i.OutputSingleRegister(), i.InputDoubleRegister(0));
      break;
    case kMips64CvtDS:
      __ cvt_d_s(i.OutputDoubleRegister(), i.InputSingleRegister(0));
      break;
    case kMips64CvtDW: {
      FPURegister scratch = kScratchDoubleReg;
      __ mtc1(i.InputRegister(0), scratch);
      __ cvt_d_w(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kMips64CvtSW: {
      FPURegister scratch = kScratchDoubleReg;
      __ mtc1(i.InputRegister(0), scratch);
      __ cvt_s_w(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kMips64CvtSUw: {
      __ Cvt_s_uw(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kMips64CvtSL: {
      FPURegister scratch = kScratchDoubleReg;
      __ dmtc1(i.InputRegister(0), scratch);
      __ cvt_s_l(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kMips64CvtDL: {
      FPURegister scratch = kScratchDoubleReg;
      __ dmtc1(i.InputRegister(0), scratch);
      __ cvt_d_l(i.OutputDoubleRegister(), scratch);
      break;
    }
    case kMips64CvtDUw: {
      __ Cvt_d_uw(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kMips64CvtDUl: {
      __ Cvt_d_ul(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kMips64CvtSUl: {
      __ Cvt_s_ul(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    }
    case kMips64FloorWD: {
      FPURegister scratch = kScratchDoubleReg;
      __ floor_w_d(scratch, i.InputDoubleRegister(0));
      __ mfc1(i.OutputRegister(), scratch);
      break;
    }
    case kMips64CeilWD: {
      FPURegister scratch = kScratchDoubleReg;
      __ ceil_w_d(scratch, i.InputDoubleRegister(0));
      __ mfc1(i.OutputRegister(), scratch);
      break;
    }
    case kMips64RoundWD: {
      FPURegister scratch = kScratchDoubleReg;
      __ round_w_d(scratch, i.InputDoubleRegister(0));
      __ mfc1(i.OutputRegister(), scratch);
      break;
    }
    case kMips64TruncWD: {
      FPURegister scratch = kScratchDoubleReg;
      // Other arches use round to zero here, so we follow.
      __ trunc_w_d(scratch, i.InputDoubleRegister(0));
      __ mfc1(i.OutputRegister(), scratch);
      if (instr->OutputCount() > 1) {
        // Check for inputs below INT32_MIN and NaN.
        __ li(i.OutputRegister(1), 1);
        __ Move(scratch, static_cast<double>(INT32_MIN));
        __ CompareF64(LE, scratch, i.InputDoubleRegister(0));
        __ LoadZeroIfNotFPUCondition(i.OutputRegister(1));
        __ Move(scratch, static_cast<double>(INT32_MAX) + 1);
        __ CompareF64(LE, scratch, i.InputDoubleRegister(0));
        __ LoadZeroIfFPUCondition(i.OutputRegister(1));
      }
      break;
    }
    case kMips64FloorWS: {
      FPURegister scratch = kScratchDoubleReg;
      __ floor_w_s(scratch, i.InputDoubleRegister(0));
      __ mfc1(i.OutputRegister(), scratch);
      break;
    }
    case kMips64CeilWS: {
      FPURegister scratch = kScratchDoubleReg;
      __ ceil_w_s(scratch, i.InputDoubleRegister(0));
      __ mfc1(i.OutputRegister(), scratch);
      break;
    }
    case kMips64RoundWS: {
      FPURegister scratch = kScratchDoubleReg;
      __ round_w_s(scratch, i.InputDoubleRegister(0));
      __ mfc1(i.OutputRegister(), scratch);
      break;
    }
    case kMips64TruncWS: {
      FPURegister scratch = kScratchDoubleReg;
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      __ trunc_w_s(scratch, i.InputDoubleRegister(0));
      __ mfc1(i.OutputRegister(), scratch);
      if (set_overflow_to_min_i32) {
        // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
        // because INT32_MIN allows easier out-of-bounds detection.
        __ addiu(kScratchReg, i.OutputRegister(), 1);
        __ slt(kScratchReg2, kScratchReg, i.OutputRegister());
        __ Movn(i.OutputRegister(), kScratchReg, kScratchReg2);
      }
      break;
    }
    case kMips64TruncLS: {
      FPURegister scratch = kScratchDoubleReg;
      Register result = kScratchReg;

      bool load_status = instr->OutputCount() > 1;
      // Other arches use round to zero here, so we follow.
      __ trunc_l_s(scratch, i.InputDoubleRegister(0));
      __ dmfc1(i.OutputRegister(), scratch);
      if (load_status) {
        __ cfc1(result, FCSR);
        // Check for overflow and NaNs.
        __ And(result, result,
               (kFCSROverflowCauseMask | kFCSRInvalidOpCauseMask));
        __ Slt(result, zero_reg, result);
        __ xori(result, result, 1);
        __ mov(i.OutputRegister(1), result);
      }
      break;
    }
    case kMips64TruncLD: {
      FPURegister scratch = kScratchDoubleReg;
      Register result = kScratchReg;

      bool set_overflow_to_min_i64 = MiscField::decode(instr->opcode());
      bool load_status = instr->OutputCount() > 1;
      DCHECK_IMPLIES(set_overflow_to_min_i64, instr->OutputCount() == 1);
      // Other arches use round to zero here, so we follow.
      __ trunc_l_d(scratch, i.InputDoubleRegister(0));
      __ dmfc1(i.OutputRegister(0), scratch);
      if (load_status) {
        __ cfc1(result, FCSR);
        // Check for overflow and NaNs.
        __ And(result, result,
               (kFCSROverflowCauseMask | kFCSRInvalidOpCauseMask));
        __ Slt(result, zero_reg, result);
        __ xori(result, result, 1);
        __ mov(i.OutputRegister(1), result);
      }
      if (set_overflow_to_min_i64) {
        // Avoid INT64_MAX as an overflow indicator and use INT64_MIN instead,
        // because INT64_MIN allows easier out-of-bounds detection.
        __ Daddu(kScratchReg, i.OutputRegister(), 1);
        __ slt(kScratchReg2, kScratchReg, i.OutputRegister());
        __ Movn(i.OutputRegister(), kScratchReg, kScratchReg2);
      }
      break;
    }
    case kMips64TruncUwD: {
      FPURegister scratch = kScratchDoubleReg;
      __ Trunc_uw_d(i.OutputRegister(), i.InputDoubleRegister(0), scratch);
      if (instr->OutputCount() > 1) {
        __ li(i.OutputRegister(1), 1);
        __ Move(scratch, static_cast<double>(-1.0));
        __ CompareF64(LT, scratch, i.InputDoubleRegister(0));
        __ LoadZeroIfNotFPUCondition(i.OutputRegister(1));
        __ Move(scratch, static_cast<double>(UINT32_MAX) + 1);
        __ CompareF64(LE, scratch, i.InputDoubleRegister(0));
        __ LoadZeroIfFPUCondition(i.OutputRegister(1));
      }
      break;
    }
    case kMips64TruncUwS: {
      FPURegister scratch = kScratchDoubleReg;
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      __ Trunc_uw_s(i.OutputRegister(), i.InputDoubleRegister(0), scratch);
      if (set_overflow_to_min_i32) {
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        __ addiu(kScratchReg, i.OutputRegister(), 1);
        __ Movz(i.OutputRegister(), zero_reg, kScratchReg);
      }
      break;
    }
    case kMips64TruncUlS: {
      FPURegister scratch = kScratchDoubleReg;
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Trunc_ul_s(i.OutputRegister(), i.InputDoubleRegister(0), scratch,
                    result);
      break;
    }
    case kMips64TruncUlD: {
      FPURegister scratch = kScratchDoubleReg;
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Trunc_ul_d(i.OutputRegister(0), i.InputDoubleRegister(0), scratch,
                    result);
      break;
    }
    case kMips64BitcastDL:
      __ dmfc1(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kMips64BitcastLD:
      __ dmtc1(i.InputRegister(0), i.OutputDoubleRegister());
      break;
    case kMips64Float64ExtractLowWord32:
      __ FmoveLow(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kMips64Float64ExtractHighWord32:
      __ FmoveHigh(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kMips64Float64FromWord32Pair:
      __ Move(i.OutputDoubleRegister(), i.InputRegister(1), i.InputRegister(0));
      break;
    case kMips64Float64InsertLowWord32:
      __ FmoveLow(i.OutputDoubleRegister(), i.InputRegister(1));
      break;
    case kMips64Float64InsertHighWord32:
      __ FmoveHigh(i.OutputDoubleRegister(), i.InputRegister(1));
      break;
    // ... more basic instructions ...

    case kMips64Seb:
      __ seb(i.OutputRegister(), i.InputRegister(0));
      break;
    case kMips64Seh:
      __ seh(i.OutputRegister(), i.InputRegister(0));
      break;
    case kMips64Lbu:
      __ Lbu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Lb:
      __ Lb(i.OutputRegister(), i.MemoryOperand());
      break;
    case kMips64Sb: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ Sb(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kMips64Lhu:
      __ Lhu(i.OutputRegister(), i.Mem
"""


```