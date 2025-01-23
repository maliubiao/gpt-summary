Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/s390/macro-assembler-s390.h`.

Here's a breakdown of the thought process:

1. **Identify the file type:** The `.h` extension indicates a header file, typically containing declarations of classes, functions, and constants. The path `v8/src/codegen/s390/` suggests it's part of V8's code generation module, specifically for the s390 architecture. The name `macro-assembler-s390.h` strongly implies that it defines a class for generating s390 assembly instructions.

2. **Scan for class definition:** Look for the `class` keyword. The code snippet clearly belongs to the `MacroAssembler` class.

3. **Analyze member functions:** Go through the member functions and group them by functionality. Look for patterns in their names and parameters.

4. **Group related functions:**  Based on their names and parameters, group the functions into logical categories:
    * **Stack manipulation:** Functions like `Push`, `Pop`, `PushCommonFrame`, `PushStandardFrame`, `PopCommonFrame`.
    * **Frame management:** Functions related to setting up and tearing down function call frames (`Prologue`, `StubPrologue`, `EnterFrame`, `LeaveFrame`).
    * **Data loading/storing:** Functions for loading and storing various data types (integers, doubles, pointers) from memory (`LoadU64`, `Store`).
    * **Data conversion:** Functions for converting between different data types (integers to doubles, doubles to integers, etc.).
    * **Floating-point operations:** Functions dealing with NaN canonicalization and setting rounding modes.
    * **Literal loading:** Functions for loading constant values.
    * **Comparisons:** Functions for comparing values.
    * **Bit manipulation:** Functions for extracting and testing bits.
    * **Smi manipulation:** Functions for tagging and untagging Small Integers (Smis).
    * **Control flow:** Functions for calls, jumps, and returns (`CallJSFunction`, `JumpJSFunction`, `StoreReturnAddressAndCall`).
    * **Debugging/Assertions:** Functions for asserting conditions and aborting execution.
    * **C function calls:** Functions for preparing and calling C functions.
    * **SIMD (Single Instruction Multiple Data) operations:** A large group of functions starting with `F64x2`, `F32x4`, `I64x2`, etc., indicating SIMD instruction support.
    * **Pointer compression:** Functions related to handling compressed pointers.

5. **Look for keywords and patterns:** Pay attention to keywords like `static`, `inline`, `template`, and macros like `DCHECK`, `NOOP_UNLESS_DEBUG_CODE`. These provide clues about the function's behavior and intended use.

6. **Infer purpose from function names:** Even without knowing the exact details of V8's internals, the names of many functions are self-explanatory (e.g., `LoadSmiLiteral`, `ConvertIntToDouble`, `AllocateStackSpace`).

7. **Check for relevant information in comments:** Although not explicitly present in the provided snippet, in real-world scenarios, comments can provide valuable context.

8. **Address specific user questions:**
    * **.tq extension:** The code snippet is `.h`, not `.tq`, so it's C++, not Torque.
    * **Relationship to JavaScript:** The functions relate to the low-level execution of JavaScript code. Examples can be constructed based on common JavaScript operations.
    * **Code logic and examples:**  Provide simple examples for functions like `Push` and `Pop`.
    * **Common programming errors:** Relate errors to stack corruption due to mismatched `Push` and `Pop` operations.

9. **Synthesize a summary:** Combine the categorized functionalities into a concise summary, highlighting the core purpose of the `MacroAssembler` class.

10. **Review and refine:**  Ensure the summary is accurate, clear, and addresses all aspects of the provided code snippet. Make sure the language is accessible and avoids overly technical jargon where possible. For instance, initially, I might think of describing "stack manipulation" as "managing the call stack," but "stack manipulation" is more direct given the function names.

This iterative process of scanning, grouping, inferring, and synthesizing helps to build a comprehensive understanding of the code's functionality even without complete knowledge of the surrounding codebase.
这是对C++头文件 `v8/src/codegen/s390/macro-assembler-s390.h` 的第二部分代码的功能归纳。

**功能归纳：**

这部分代码主要定义了 `v8::internal::compiler::s390::MacroAssembler` 类中用于执行以下操作的成员函数：

**1. 栈操作 (Stack Manipulation):**

* **批量压栈和弹栈:** 提供了 `Push` 和 `Pop` 函数，可以一次性压入或弹出多个通用寄存器。这是常见的函数调用约定的一部分，用于保存和恢复寄存器状态。

**2. 帧 (Frame) 管理:**

* **压入通用帧:** `PushCommonFrame` 用于压入包含返回地址 (lr)、帧指针 (fp) 和常量池指针的固定大小的帧。
* **压入标准帧:** `PushStandardFrame` 用于压入包含返回地址、帧指针、常量池指针、上下文和 JS 函数对象的标准帧。这是 JavaScript 函数调用的标准帧结构。
* **弹出通用帧:** `PopCommonFrame` 用于弹出之前压入的通用帧。
* **恢复尾调用状态:** `RestoreFrameStateForTailCall` 用于在尾调用优化中恢复调用者的帧状态。

**3. 根寄存器初始化:**

* **初始化根寄存器:** `InitializeRootRegister` 用于将全局根对象 (isolate root) 的地址加载到特定的寄存器 (`kRootRegister`) 中。这为访问全局对象提供了基础。

**4. NaN (非数字) 规范化:**

* **规范化 NaN:** `CanonicalizeNaN` 函数用于将 NaN 值转换为其规范形式。

**5. 数据类型转换 (Type Conversion):**

* **整数到浮点数转换:** 提供了一系列函数 (`ConvertIntToDouble`, `ConvertUnsignedIntToDouble`, `ConvertIntToFloat`, `ConvertUnsignedIntToFloat`) 将带符号和无符号的整数 (通常是 Smi) 转换为双精度和单精度浮点数。
* **64位整数到浮点数转换:**  `ConvertInt64ToFloat`, `ConvertInt64ToDouble`, `ConvertUnsignedInt64ToFloat`, `ConvertUnsignedInt64ToDouble` 用于将 64 位整数转换为浮点数。
* **浮点数到整数转换:**  `ConvertFloat32ToInt64`, `ConvertDoubleToInt64`, `ConvertDoubleToInt32`, `ConvertFloat32ToInt32`, `ConvertFloat32ToUnsignedInt32`, `ConvertDoubleToUnsignedInt64`, `ConvertDoubleToUnsignedInt32`, `ConvertFloat32ToUnsignedInt64` 等函数用于将浮点数转换为整数，并允许指定舍入模式。
* **寄存器间数据移动和转换:** `MovIntToFloat`, `MovFloatToInt`, `MovDoubleToInt64`, `MovInt64ToDouble`  在寄存器之间移动和转换数据类型。

**6. 函数序言 (Prologue) 和结尾 (Epilogue):**

* **Stub 序言:** `StubPrologue` 用于生成 Stub (通常是运行时函数的快速路径) 的序言代码。
* **标准序言:** `Prologue` 用于生成标准 JavaScript 函数的序言代码.
* **丢弃参数:** `DropArguments` 和 `DropArgumentsAndPushNewReceiver` 用于在调用过程中调整栈上的参数。

**7. 栈帧对齐:**

* **获取栈帧对齐:** `ActivationFrameAlignment` 返回目标环境的实际栈帧对齐要求。

**8. 加载字面量:**

* **加载 Smi 字面量:** `LoadSmiLiteral` 用于将 Smi 类型的字面量加载到通用寄存器。
* **加载浮点数 (双精度和单精度) 字面量:**  `LoadF64` 和 `LoadF32` 模板函数用于将双精度和单精度浮点数字面量加载到浮点寄存器。

**9. 比较 Smi 字面量:**

* **比较 Smi 字面量:** `CmpSmiLiteral` 用于将通用寄存器中的值与 Smi 字面量进行比较。

**10. 浮点数舍入模式控制:**

* **设置舍入模式:** `SetRoundingMode` 用于设置浮点运算的舍入模式。
* **重置舍入模式:** `ResetRoundingMode` 用于将舍入模式重置为默认值 (kRoundToNearest)。

**11. 不同字长的数据加载和存储:**

* **加载和存储多字:** `LoadMultipleP`, `StoreMultipleP`, `LoadMultipleW`, `StoreMultipleW` 用于加载和存储多个指针大小或字大小的数据。

**12. 数据交换 (Swap):**

* **交换寄存器和内存中的数据:** 提供了一系列 `Swap` 函数，用于交换通用寄存器、浮点寄存器、SIMD 寄存器以及内存位置中的数据。

**13. C 函数调用支持:**

* **准备调用 C 函数:** `PrepareCallCFunction` 用于在调用 C 函数之前进行栈对齐和参数准备。
* **移动浮点参数和结果:** `MovToFloatParameter`, `MovToFloatParameters`, `MovToFloatResult`, `MovFromFloatParameter`, `MovFromFloatResult` 用于在调用 C 函数时处理浮点参数和返回值。
* **调用 C 函数:** `CallCFunction` 用于实际调用 C 函数，并处理参数传递和栈清理。

**14. 调试和断点:**

* **触发陷阱指令:** `Trap` 用于生成一个导致程序停止执行的陷阱指令。
* **触发调试断点:** `DebugBreak` 用于触发一个调试断点。

**15. 截断浮点数到整数:**

* **截断双精度浮点数到整数:** `TruncateDoubleToI` 和 `TryInlineTruncateDoubleToI` 用于将双精度浮点数截断为整数。

**如果 `v8/src/codegen/s390/macro-assembler-s390.h` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码**。Torque 是一种用于定义 V8 运行时的类型化中间语言。`.tq` 文件包含用 Torque 编写的代码，这些代码会被编译成 C++ 代码，最终用于生成机器码。

**与 JavaScript 的功能关系 (示例):**

这些底层的汇编器功能直接支撑着 JavaScript 的执行。例如：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 执行 `add(1, 2)` 时，`MacroAssembler` 中类似以下的功能会被使用：

* **`PushStandardFrame`:**  在调用 `add` 函数时，会创建一个新的栈帧。
* **`LoadSmiLiteral`:** 加载整数 `1` 和 `2` (作为 Smi 字面量)。
* **可能使用某种加法指令** (虽然代码中未直接展示加法，但 `MacroAssembler` 肯定有算术运算指令)。
* **`SmiTag`:** 将计算结果 (可能是整数 `3`) 标记为 Smi。
* **`PopStandardFrame`:** 在函数返回时，弹出栈帧。

**代码逻辑推理 (示例):**

**假设输入:**

```c++
Register reg1 = r3;
Register reg2 = r4;
Register reg3 = r5;
Register sp = r1; // 假设栈指针是 r1
```

**执行代码:**

```c++
Push(reg1, reg2, reg3);
// ... 一些操作 ...
Pop(reg3, reg2, reg1);
```

**输出:**

* **`Push(reg1, reg2, reg3)`:**  会将 `reg1`, `reg2`, `reg3` 中的 64 位值依次压入栈中（`sp` 指向的地址先存储 `reg1` 的值，然后 `sp + kSystemPointerSize` 存储 `reg2` 的值，以此类推）。`sp` 的值会减小 `3 * kSystemPointerSize`。
* **`Pop(reg3, reg2, reg1)`:**  会将栈顶的三个 64 位值依次弹出到 `reg3`, `reg2`, `reg1` 中。注意弹出的顺序与压入的顺序相反。`sp` 的值会增加 `3 * kSystemPointerSize`。

**用户常见的编程错误 (示例):**

一个常见的错误是 **`Push` 和 `Pop` 的不匹配**。例如，压入了三个寄存器，但只弹出了两个：

```c++
Push(r3, r4, r5);
// ...
Pop(r5, r4); // 错误：少弹出一个寄存器
```

这会导致栈指针 `sp` 的错位，后续的栈操作可能会覆盖不应该被覆盖的数据，最终导致程序崩溃或产生不可预测的行为。这是一种典型的**栈溢出**或**栈损坏**问题。

**总结这部分的功能:**

这部分 `MacroAssembler` 类的代码主要提供了用于**管理函数调用栈**、**执行基本的数据操作和类型转换**、**支持 C 函数调用**以及提供**底层调试功能**的接口。它是 V8 代码生成器的核心组件，负责将高级的中间表示转换为底层的 s390 汇编指令，从而驱动 JavaScript 代码的执行。

### 提示词
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
LoadU64(src3, MemOperand(sp, kSystemPointerSize));
    LoadU64(src2, MemOperand(sp, 2 * kSystemPointerSize));
    LoadU64(src1, MemOperand(sp, 3 * kSystemPointerSize));
    la(sp, MemOperand(sp, 4 * kSystemPointerSize));
  }

  // Pop five registers.  Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2, Register src3, Register src4,
           Register src5) {
    LoadU64(src5, MemOperand(sp, 0));
    LoadU64(src4, MemOperand(sp, kSystemPointerSize));
    LoadU64(src3, MemOperand(sp, 2 * kSystemPointerSize));
    LoadU64(src2, MemOperand(sp, 3 * kSystemPointerSize));
    LoadU64(src1, MemOperand(sp, 4 * kSystemPointerSize));
    la(sp, MemOperand(sp, 5 * kSystemPointerSize));
  }

  // Push a fixed frame, consisting of lr, fp, constant pool.
  void PushCommonFrame(Register marker_reg = no_reg);

  // Push a standard frame, consisting of lr, fp, constant pool,
  // context and JS function
  void PushStandardFrame(Register function_reg);

  void PopCommonFrame(Register marker_reg = no_reg);

  // Restore caller's frame pointer and return address prior to being
  // overwritten by tail call stack preparation.
  void RestoreFrameStateForTailCall();

  void InitializeRootRegister() {
    ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
    mov(kRootRegister, Operand(isolate_root));
#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE
    LoadRootRelative(kPtrComprCageBaseRegister,
                     IsolateData::cage_base_offset());
#endif
  }

  // If the value is a NaN, canonicalize the value else, do nothing.
  void CanonicalizeNaN(const DoubleRegister dst, const DoubleRegister src);
  void CanonicalizeNaN(const DoubleRegister value) {
    CanonicalizeNaN(value, value);
  }

  // Converts the integer (untagged smi) in |src| to a double, storing
  // the result to |dst|
  void ConvertIntToDouble(DoubleRegister dst, Register src);

  // Converts the unsigned integer (untagged smi) in |src| to
  // a double, storing the result to |dst|
  void ConvertUnsignedIntToDouble(DoubleRegister dst, Register src);

  // Converts the integer (untagged smi) in |src| to
  // a float, storing the result in |dst|
  void ConvertIntToFloat(DoubleRegister dst, Register src);

  // Converts the unsigned integer (untagged smi) in |src| to
  // a float, storing the result in |dst|
  void ConvertUnsignedIntToFloat(DoubleRegister dst, Register src);

  void ConvertInt64ToFloat(DoubleRegister double_dst, Register src);
  void ConvertInt64ToDouble(DoubleRegister double_dst, Register src);
  void ConvertUnsignedInt64ToFloat(DoubleRegister double_dst, Register src);
  void ConvertUnsignedInt64ToDouble(DoubleRegister double_dst, Register src);

  void MovIntToFloat(DoubleRegister dst, Register src);
  void MovFloatToInt(Register dst, DoubleRegister src);
  void MovDoubleToInt64(Register dst, DoubleRegister src);
  void MovInt64ToDouble(DoubleRegister dst, Register src);
  // Converts the double_input to an integer.  Note that, upon return,
  // the contents of double_dst will also hold the fixed point representation.
  void ConvertFloat32ToInt64(const Register dst,
                             const DoubleRegister double_input,
                             FPRoundingMode rounding_mode = kRoundToZero);

  // Converts the double_input to an integer.  Note that, upon return,
  // the contents of double_dst will also hold the fixed point representation.
  void ConvertDoubleToInt64(const Register dst,
                            const DoubleRegister double_input,
                            FPRoundingMode rounding_mode = kRoundToZero);
  void ConvertDoubleToInt32(const Register dst,
                            const DoubleRegister double_input,
                            FPRoundingMode rounding_mode = kRoundToZero);

  void ConvertFloat32ToInt32(const Register result,
                             const DoubleRegister double_input,
                             FPRoundingMode rounding_mode);
  void ConvertFloat32ToUnsignedInt32(
      const Register result, const DoubleRegister double_input,
      FPRoundingMode rounding_mode = kRoundToZero);
  // Converts the double_input to an unsigned integer.  Note that, upon return,
  // the contents of double_dst will also hold the fixed point representation.
  void ConvertDoubleToUnsignedInt64(
      const Register dst, const DoubleRegister double_input,
      FPRoundingMode rounding_mode = kRoundToZero);
  void ConvertDoubleToUnsignedInt32(
      const Register dst, const DoubleRegister double_input,
      FPRoundingMode rounding_mode = kRoundToZero);
  void ConvertFloat32ToUnsignedInt64(
      const Register result, const DoubleRegister double_input,
      FPRoundingMode rounding_mode = kRoundToZero);

  // Generates function and stub prologue code.
  void StubPrologue(StackFrame::Type type, Register base = no_reg,
                    int prologue_offset = 0);
  void Prologue(Register base, int prologue_offset = 0);

  void DropArguments(Register count);
  void DropArgumentsAndPushNewReceiver(Register argc, Register receiver);

  // Get the actual activation frame alignment for target environment.
  static int ActivationFrameAlignment();
  // ----------------------------------------------------------------
  // new S390 macro-assembler interfaces that are slightly higher level
  // than assembler-s390 and may generate variable length sequences

  // load an SMI value <value> to GPR <dst>
  void LoadSmiLiteral(Register dst, Tagged<Smi> smi);

  // load a literal double value <value> to FPR <result>
  template <class T>
  void LoadF64(DoubleRegister result, T value, Register scratch) {
    static_assert(sizeof(T) == kDoubleSize, "Expect input size to be 8");
    uint64_t int_val = base::bit_cast<uint64_t, T>(value);
    // Load the 64-bit value into a GPR, then transfer it to FPR via LDGR
    uint32_t hi_32 = int_val >> 32;
    uint32_t lo_32 = static_cast<uint32_t>(int_val);

    if (int_val == 0) {
      lzdr(result);
    } else if (lo_32 == 0) {
      llihf(scratch, Operand(hi_32));
      ldgr(result, scratch);
    } else {
      iihf(scratch, Operand(hi_32));
      iilf(scratch, Operand(lo_32));
      ldgr(result, scratch);
    }
  }

  template <class T>
  void LoadF32(DoubleRegister result, T value, Register scratch) {
    static_assert(sizeof(T) == kFloatSize, "Expect input size to be 4");
    uint32_t int_val = base::bit_cast<uint32_t, T>(value);
    LoadF64(result, static_cast<uint64_t>(int_val) << 32, scratch);
  }

  void CmpSmiLiteral(Register src1, Tagged<Smi> smi, Register scratch);

  // Set new rounding mode RN to FPSCR
  void SetRoundingMode(FPRoundingMode RN);

  // reset rounding mode to default (kRoundToNearest)
  void ResetRoundingMode();

  // These exist to provide portability between 32 and 64bit
  void LoadMultipleP(Register dst1, Register dst2, const MemOperand& mem);
  void StoreMultipleP(Register dst1, Register dst2, const MemOperand& mem);
  void LoadMultipleW(Register dst1, Register dst2, const MemOperand& mem);
  void StoreMultipleW(Register dst1, Register dst2, const MemOperand& mem);

  void SwapP(Register src, Register dst, Register scratch);
  void SwapP(Register src, MemOperand dst, Register scratch);
  void SwapP(MemOperand src, MemOperand dst, Register scratch_0,
             Register scratch_1);
  void SwapFloat32(DoubleRegister src, DoubleRegister dst,
                   DoubleRegister scratch);
  void SwapFloat32(DoubleRegister src, MemOperand dst, DoubleRegister scratch);
  void SwapFloat32(MemOperand src, MemOperand dst, DoubleRegister scratch);
  void SwapDouble(DoubleRegister src, DoubleRegister dst,
                  DoubleRegister scratch);
  void SwapDouble(DoubleRegister src, MemOperand dst, DoubleRegister scratch);
  void SwapDouble(MemOperand src, MemOperand dst, DoubleRegister scratch);
  void SwapSimd128(Simd128Register src, Simd128Register dst,
                   Simd128Register scratch);
  void SwapSimd128(Simd128Register src, MemOperand dst,
                   Simd128Register scratch);
  void SwapSimd128(MemOperand src, MemOperand dst, Simd128Register scratch);

  // ---------------------------------------------------------------------------
  // Runtime calls

  // Before calling a C-function from generated code, align arguments on stack.
  // After aligning the frame, non-register arguments must be stored in
  // sp[0], sp[4], etc., not pushed. The argument count assumes all arguments
  // are word sized. If double arguments are used, this function assumes that
  // all double arguments are stored before core registers; otherwise the
  // correct alignment of the double values is not guaranteed.
  // Some compilers/platforms require the stack to be aligned when calling
  // C++ code.
  // Needs a scratch register to do some arithmetic. This register will be
  // trashed.
  void PrepareCallCFunction(int num_reg_arguments, int num_double_registers,
                            Register scratch);
  void PrepareCallCFunction(int num_reg_arguments, Register scratch);

  // There are two ways of passing double arguments on ARM, depending on
  // whether soft or hard floating point ABI is used. These functions
  // abstract parameter passing for the three different ways we call
  // C functions from generated code.
  void MovToFloatParameter(DoubleRegister src);
  void MovToFloatParameters(DoubleRegister src1, DoubleRegister src2);
  void MovToFloatResult(DoubleRegister src);

  // Calls a C function and cleans up the space for arguments allocated
  // by PrepareCallCFunction. The called function is not allowed to trigger a
  // garbage collection, since that might move the code and invalidate the
  // return address (unless this is somehow accounted for by the called
  // function).
  int CallCFunction(
      ExternalReference function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      bool has_function_descriptor = ABI_USES_FUNCTION_DESCRIPTORS,
      Label* return_label = nullptr);
  int CallCFunction(
      Register function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      bool has_function_descriptor = ABI_USES_FUNCTION_DESCRIPTORS,
      Label* return_label = nullptr);
  int CallCFunction(
      ExternalReference function, int num_reg_arguments,
      int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      bool has_function_descriptor = ABI_USES_FUNCTION_DESCRIPTORS,
      Label* return_label = nullptr);
  int CallCFunction(
      Register function, int num_reg_arguments, int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      bool has_function_descriptor = ABI_USES_FUNCTION_DESCRIPTORS,
      Label* return_label = nullptr);

  void MovFromFloatParameter(DoubleRegister dst);
  void MovFromFloatResult(DoubleRegister dst);

  void Trap();
  void DebugBreak();

  // Emit code for a truncating division by a constant. The dividend register is
  // unchanged and ip gets clobbered. Dividend and result must be different.
  void TruncateDoubleToI(Isolate* isolate, Zone* zone, Register result,
                         DoubleRegister double_input, StubCallMode stub_mode);
  void TryInlineTruncateDoubleToI(Register result, DoubleRegister double_input,
                                  Label* done);

  // ---------------------------------------------------------------------------
  // Debugging

  // Calls Abort(msg) if the condition cond is not satisfied.
  // Use --debug_code to enable.
  void Assert(Condition cond, AbortReason reason,
              CRegister cr = cr7) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but without condition.
  // Use --debug-code to enable.
  void AssertUnreachable(AbortReason reason) NOOP_UNLESS_DEBUG_CODE;
  void AssertZeroExtended(Register reg) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but always enabled.
  void Check(Condition cond, AbortReason reason, CRegister cr = cr7);

  // Print a message to stdout and abort execution.
  void Abort(AbortReason reason);

  // ---------------------------------------------------------------------------
  // Bit testing/extraction
  //
  // Bit numbering is such that the least significant bit is bit 0
  // (for consistency between 32/64-bit).

  // Extract consecutive bits (defined by rangeStart - rangeEnd) from src
  // and place them into the least significant bits of dst.
  inline void ExtractBitRange(Register dst, Register src, int rangeStart,
                              int rangeEnd) {
    DCHECK(rangeStart >= rangeEnd && rangeStart < kBitsPerSystemPointer);

    // Try to use RISBG if possible.
    if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
      int shiftAmount = (64 - rangeEnd) % 64;  // Convert to shift left.
      int endBit = 63;  // End is always LSB after shifting.
      int startBit = 63 - rangeStart + rangeEnd;
      RotateInsertSelectBits(dst, src, Operand(startBit), Operand(endBit),
                             Operand(shiftAmount), true);
    } else {
      if (rangeEnd > 0)  // Don't need to shift if rangeEnd is zero.
        ShiftRightU64(dst, src, Operand(rangeEnd));
      else if (dst != src)  // If we didn't shift, we might need to copy
        mov(dst, src);
      int width = rangeStart - rangeEnd + 1;
      uint64_t mask = (static_cast<uint64_t>(1) << width) - 1;
      nihf(dst, Operand(mask >> 32));
      nilf(dst, Operand(mask & 0xFFFFFFFF));
      ltgr(dst, dst);
    }
  }

  inline void ExtractBit(Register dst, Register src, uint32_t bitNumber) {
    ExtractBitRange(dst, src, bitNumber, bitNumber);
  }

  // Extract consecutive bits (defined by mask) from src and place them
  // into the least significant bits of dst.
  inline void ExtractBitMask(Register dst, Register src, uintptr_t mask,
                             RCBit rc = LeaveRC) {
    int start = kBitsPerSystemPointer - 1;
    int end;
    uintptr_t bit = (1L << start);

    while (bit && (mask & bit) == 0) {
      start--;
      bit >>= 1;
    }
    end = start;
    bit >>= 1;

    while (bit && (mask & bit)) {
      end--;
      bit >>= 1;
    }

    // 1-bits in mask must be contiguous
    DCHECK(bit == 0 || (mask & ((bit << 1) - 1)) == 0);

    ExtractBitRange(dst, src, start, end);
  }

  // Test single bit in value.
  inline void TestBit(Register value, int bitNumber, Register scratch = r0) {
    ExtractBitRange(scratch, value, bitNumber, bitNumber);
  }

  // Test consecutive bit range in value.  Range is defined by
  // rangeStart - rangeEnd.
  inline void TestBitRange(Register value, int rangeStart, int rangeEnd,
                           Register scratch = r0) {
    ExtractBitRange(scratch, value, rangeStart, rangeEnd);
  }

  // Test consecutive bit range in value.  Range is defined by mask.
  inline void TestBitMask(Register value, uintptr_t mask,
                          Register scratch = r0) {
    ExtractBitMask(scratch, value, mask, SetRC);
  }
  inline void TestIfSmi(Register value) { tmll(value, Operand(1)); }

  inline void TestIfSmi(MemOperand value) {
    if (is_uint12(value.offset())) {
      tm(value, Operand(1));
    } else if (is_int20(value.offset())) {
      tmy(value, Operand(1));
    } else {
      LoadS8(r0, value);
      tmll(r0, Operand(1));
    }
  }

  inline void TestIfInt32(Register value) {
    // High bits must be identical to fit into an 32-bit integer
    cgfr(value, value);
  }
  void SmiUntag(Register reg) { SmiUntag(reg, reg); }

  void SmiUntag(Register dst, const MemOperand& src);
  void SmiUntag(Register dst, Register src) {
    if (SmiValuesAre31Bits()) {
      ShiftRightS32(dst, src, Operand(kSmiShift));
    } else {
      ShiftRightS64(dst, src, Operand(kSmiShift));
    }
    lgfr(dst, dst);
  }
  void SmiToInt32(Register smi) {
    if (v8_flags.enable_slow_asserts) {
      AssertSmi(smi);
    }
    DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
    SmiUntag(smi);
  }
  void SmiToInt32(Register dst, Register src) {
    DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
    mov(dst, src);
    SmiUntag(dst);
  }

  // Shift left by kSmiShift
  void SmiTag(Register reg) { SmiTag(reg, reg); }
  void SmiTag(Register dst, Register src) {
    ShiftLeftU64(dst, src, Operand(kSmiShift));
  }

  // Abort execution if argument is a smi, enabled via --debug-code.
  void AssertNotSmi(Register object) NOOP_UNLESS_DEBUG_CODE;
  void AssertSmi(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Abort execution if argument is not a Map, enabled via
  // --debug-code.
  void AssertMap(Register object) NOOP_UNLESS_DEBUG_CODE;

  // Activation support.
  void EnterFrame(StackFrame::Type type,
                  bool load_constant_pool_pointer_reg = false);
  // Returns the pc offset at which the frame ends.
  int LeaveFrame(StackFrame::Type type, int stack_adjustment = 0);

  void AllocateStackSpace(int bytes) {
    DCHECK_GE(bytes, 0);
    if (bytes == 0) return;
    lay(sp, MemOperand(sp, -bytes));
  }

  void AllocateStackSpace(Register bytes) { SubS64(sp, sp, bytes); }

  void CheckPageFlag(Register object, Register scratch, int mask, Condition cc,
                     Label* condition_met);

  void ComputeCodeStartAddress(Register dst);
  void LoadPC(Register dst);

  // Control-flow integrity:

  // Define a function entrypoint. This doesn't emit any code for this
  // architecture, as control-flow integrity is not supported for it.
  void CodeEntry() {}
  // Define an exception handler.
  void ExceptionHandler() {}
  // Define an exception handler and bind a label.
  void BindExceptionHandler(Label* label) { bind(label); }

  // Convenience functions to call/jmp to the code of a JSFunction object.
  void CallJSFunction(Register function_object, uint16_t argument_count);
  void JumpJSFunction(Register function_object,
                      JumpMode jump_mode = JumpMode::kJump);

  // Generates an instruction sequence s.t. the return address points to the
  // instruction following the call.
  // The return address on the stack is used by frame iteration.
  void StoreReturnAddressAndCall(Register target);
#if V8_OS_ZOS
  void zosStoreReturnAddressAndCall(Register target, Register scratch);
#endif

  // ---------------------------------------------------------------------------
  // Simd Support.
  void F64x2Splat(Simd128Register dst, Simd128Register src);
  void F32x4Splat(Simd128Register dst, Simd128Register src);
  void I64x2Splat(Simd128Register dst, Register src);
  void I32x4Splat(Simd128Register dst, Register src);
  void I16x8Splat(Simd128Register dst, Register src);
  void I8x16Splat(Simd128Register dst, Register src);
  void F64x2ExtractLane(DoubleRegister dst, Simd128Register src,
                        uint8_t imm_lane_idx, Register = r0);
  void F32x4ExtractLane(DoubleRegister dst, Simd128Register src,
                        uint8_t imm_lane_idx, Register = r0);
  void I64x2ExtractLane(Register dst, Simd128Register src, uint8_t imm_lane_idx,
                        Register = r0);
  void I32x4ExtractLane(Register dst, Simd128Register src, uint8_t imm_lane_idx,
                        Register = r0);
  void I16x8ExtractLaneU(Register dst, Simd128Register src,
                         uint8_t imm_lane_idx, Register = r0);
  void I16x8ExtractLaneS(Register dst, Simd128Register src,
                         uint8_t imm_lane_idx, Register scratch);
  void I8x16ExtractLaneU(Register dst, Simd128Register src,
                         uint8_t imm_lane_idx, Register = r0);
  void I8x16ExtractLaneS(Register dst, Simd128Register src,
                         uint8_t imm_lane_idx, Register scratch);
  void F64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                        DoubleRegister src2, uint8_t imm_lane_idx,
                        Register scratch);
  void F32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                        DoubleRegister src2, uint8_t imm_lane_idx,
                        Register scratch);
  void I64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                        Register src2, uint8_t imm_lane_idx, Register = r0);
  void I32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                        Register src2, uint8_t imm_lane_idx, Register = r0);
  void I16x8ReplaceLane(Simd128Register dst, Simd128Register src1,
                        Register src2, uint8_t imm_lane_idx, Register = r0);
  void I8x16ReplaceLane(Simd128Register dst, Simd128Register src1,
                        Register src2, uint8_t imm_lane_idx, Register = r0);
  void I64x2Mul(Simd128Register dst, Simd128Register src1, Simd128Register src2,
                Register scratch1, Register scratch2, Register scratch3);
  void I32x4GeU(Simd128Register dst, Simd128Register src1, Simd128Register src2,
                Simd128Register scratch);
  void I16x8GeU(Simd128Register dst, Simd128Register src1, Simd128Register src2,
                Simd128Register scratch);
  void I8x16GeU(Simd128Register dst, Simd128Register src1, Simd128Register src2,
                Simd128Register scratch);
  void I64x2BitMask(Register dst, Simd128Register src, Register scratch1,
                    Simd128Register scratch2);
  void I32x4BitMask(Register dst, Simd128Register src, Register scratch1,
                    Simd128Register scratch2);
  void I16x8BitMask(Register dst, Simd128Register src, Register scratch1,
                    Simd128Register scratch2);
  void I8x16BitMask(Register dst, Simd128Register src, Register scratch1,
                    Register scratch2, Simd128Register scratch3);
  void V128AnyTrue(Register dst, Simd128Register src, Register scratch);
  void I32x4SConvertF32x4(Simd128Register dst, Simd128Register src,
                          Simd128Register scratch1, Register scratch2);
  void I32x4UConvertF32x4(Simd128Register dst, Simd128Register src,
                          Simd128Register scratch1, Register scratch2);
  void F32x4SConvertI32x4(Simd128Register dst, Simd128Register src,
                          Simd128Register scratch1, Register scratch2);
  void F32x4UConvertI32x4(Simd128Register dst, Simd128Register src,
                          Simd128Register scratch1, Register scratch2);
  void I16x8SConvertI32x4(Simd128Register dst, Simd128Register src1,
                          Simd128Register src2);
  void I8x16SConvertI16x8(Simd128Register dst, Simd128Register src1,
                          Simd128Register src2);
  void I16x8UConvertI32x4(Simd128Register dst, Simd128Register src1,
                          Simd128Register src2, Simd128Register scratch);
  void I8x16UConvertI16x8(Simd128Register dst, Simd128Register src1,
                          Simd128Register src2, Simd128Register scratch);
  void F64x2PromoteLowF32x4(Simd128Register dst, Simd128Register src,
                            Simd128Register scratch1, Register scratch2,
                            Register scratch3, Register scratch4);
  void F32x4DemoteF64x2Zero(Simd128Register dst, Simd128Register src,
                            Simd128Register scratch1, Register scratch2,
                            Register scratch3, Register scratch4);
  void I32x4TruncSatF64x2SZero(Simd128Register dst, Simd128Register src,
                               Simd128Register scratch);
  void I32x4TruncSatF64x2UZero(Simd128Register dst, Simd128Register src,
                               Simd128Register scratch);
  void I8x16Swizzle(Simd128Register dst, Simd128Register src1,
                    Simd128Register src2, Register scratch1, Register scratch2,
                    Simd128Register scratch3);
  void S128Const(Simd128Register dst, uint64_t high, uint64_t low,
                 Register scratch1, Register scratch2);
  void I8x16Shuffle(Simd128Register dst, Simd128Register src1,
                    Simd128Register src2, uint64_t high, uint64_t low,
                    Register scratch1, Register scratch2,
                    Simd128Register scratch3);
  void I32x4DotI16x8S(Simd128Register dst, Simd128Register src1,
                      Simd128Register src2, Simd128Register scratch);
  void I16x8DotI8x16S(Simd128Register dst, Simd128Register src1,
                      Simd128Register src2, Simd128Register scratch);
  void I32x4DotI8x16AddS(Simd128Register dst, Simd128Register src1,
                         Simd128Register src2, Simd128Register src3,
                         Simd128Register scratch1, Simd128Register scratch2);
  void I16x8Q15MulRSatS(Simd128Register dst, Simd128Register src1,
                        Simd128Register src2, Simd128Register scratch1,
                        Simd128Register scratch2, Simd128Register scratch3);
  void S128Select(Simd128Register dst, Simd128Register src1,
                  Simd128Register src2, Simd128Register mask);

#define SIMD_SHIFT_LIST(V) \
  V(I64x2Shl)              \
  V(I64x2ShrS)             \
  V(I64x2ShrU)             \
  V(I32x4Shl)              \
  V(I32x4ShrS)             \
  V(I32x4ShrU)             \
  V(I16x8Shl)              \
  V(I16x8ShrS)             \
  V(I16x8ShrU)             \
  V(I8x16Shl)              \
  V(I8x16ShrS)             \
  V(I8x16ShrU)

#define PROTOTYPE_SIMD_SHIFT(name)                                          \
  void name(Simd128Register dst, Simd128Register src1, Register src2,       \
            Simd128Register scratch);                                       \
  void name(Simd128Register dst, Simd128Register src1, const Operand& src2, \
            Register scratch1, Simd128Register scratch2);
  SIMD_SHIFT_LIST(PROTOTYPE_SIMD_SHIFT)
#undef PROTOTYPE_SIMD_SHIFT
#undef SIMD_SHIFT_LIST

#define SIMD_UNOP_LIST(V)   \
  V(F64x2Abs)               \
  V(F64x2Neg)               \
  V(F64x2Sqrt)              \
  V(F64x2Ceil)              \
  V(F64x2Floor)             \
  V(F64x2Trunc)             \
  V(F64x2NearestInt)        \
  V(F64x2ConvertLowI32x4S)  \
  V(F64x2ConvertLowI32x4U)  \
  V(F32x4Abs)               \
  V(F32x4Neg)               \
  V(F32x4Sqrt)              \
  V(F32x4Ceil)              \
  V(F32x4Floor)             \
  V(F32x4Trunc)             \
  V(F32x4NearestInt)        \
  V(I64x2Abs)               \
  V(I64x2SConvertI32x4Low)  \
  V(I64x2SConvertI32x4High) \
  V(I64x2UConvertI32x4Low)  \
  V(I64x2UConvertI32x4High) \
  V(I64x2Neg)               \
  V(I32x4Abs)               \
  V(I32x4Neg)               \
  V(I32x4SConvertI16x8Low)  \
  V(I32x4SConvertI16x8High) \
  V(I32x4UConvertI16x8Low)  \
  V(I32x4UConvertI16x8High) \
  V(I16x8Abs)               \
  V(I16x8Neg)               \
  V(I16x8SConvertI8x16Low)  \
  V(I16x8SConvertI8x16High) \
  V(I16x8UConvertI8x16Low)  \
  V(I16x8UConvertI8x16High) \
  V(I8x16Abs)               \
  V(I8x16Neg)               \
  V(I8x16Popcnt)            \
  V(S128Not)                \
  V(S128Zero)               \
  V(S128AllOnes)

#define PROTOTYPE_SIMD_UNOP(name) \
  void name(Simd128Register dst, Simd128Register src);
  SIMD_UNOP_LIST(PROTOTYPE_SIMD_UNOP)
#undef PROTOTYPE_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_BINOP_LIST(V) \
  V(F64x2Add)              \
  V(F64x2Sub)              \
  V(F64x2Mul)              \
  V(F64x2Div)              \
  V(F64x2Min)              \
  V(F64x2Max)              \
  V(F64x2Eq)               \
  V(F64x2Ne)               \
  V(F64x2Lt)               \
  V(F64x2Le)               \
  V(F64x2Pmin)             \
  V(F64x2Pmax)             \
  V(F32x4Add)              \
  V(F32x4Sub)              \
  V(F32x4Mul)              \
  V(F32x4Div)              \
  V(F32x4Min)              \
  V(F32x4Max)              \
  V(F32x4Eq)               \
  V(F32x4Ne)               \
  V(F32x4Lt)               \
  V(F32x4Le)               \
  V(F32x4Pmin)             \
  V(F32x4Pmax)             \
  V(I64x2Add)              \
  V(I64x2Sub)              \
  V(I64x2Eq)               \
  V(I64x2Ne)               \
  V(I64x2GtS)              \
  V(I64x2GeS)              \
  V(I32x4Add)              \
  V(I32x4Sub)              \
  V(I32x4Mul)              \
  V(I32x4Eq)               \
  V(I32x4Ne)               \
  V(I32x4GtS)              \
  V(I32x4GeS)              \
  V(I32x4GtU)              \
  V(I32x4MinS)             \
  V(I32x4MinU)             \
  V(I32x4MaxS)             \
  V(I32x4MaxU)             \
  V(I16x8Add)              \
  V(I16x8Sub)              \
  V(I16x8Mul)              \
  V(I16x8Eq)               \
  V(I16x8Ne)               \
  V(I16x8GtS)              \
  V(I16x8GeS)              \
  V(I16x8GtU)              \
  V(I16x8MinS)             \
  V(I16x8MinU)             \
  V(I16x8MaxS)             \
  V(I16x8MaxU)             \
  V(I16x8RoundingAverageU) \
  V(I8x16Add)              \
  V(I8x16Sub)              \
  V(I8x16Eq)               \
  V(I8x16Ne)               \
  V(I8x16GtS)              \
  V(I8x16GeS)              \
  V(I8x16GtU)              \
  V(I8x16MinS)             \
  V(I8x16MinU)             \
  V(I8x16MaxS)             \
  V(I8x16MaxU)             \
  V(I8x16RoundingAverageU) \
  V(S128And)               \
  V(S128Or)                \
  V(S128Xor)               \
  V(S128AndNot)

#define PROTOTYPE_SIMD_BINOP(name) \
  void name(Simd128Register dst, Simd128Register src1, Simd128Register src2);
  SIMD_BINOP_LIST(PROTOTYPE_SIMD_BINOP)
#undef PROTOTYPE_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_EXT_MUL_LIST(V) \
  V(I64x2ExtMulLowI32x4S)    \
  V(I64x2ExtMulHighI32x4S)   \
  V(I64x2ExtMulLowI32x4U)    \
  V(I64x2ExtMulHighI32x4U)   \
  V(I32x4ExtMulLowI16x8S)    \
  V(I32x4ExtMulHighI16x8S)   \
  V(I32x4ExtMulLowI16x8U)    \
  V(I32x4ExtMulHighI16x8U)   \
  V(I16x8ExtMulLowI8x16S)    \
  V(I16x8ExtMulHighI8x16S)   \
  V(I16x8ExtMulLowI8x16U)    \
  V(I16x8ExtMulHighI8x16U)

#define PROTOTYPE_SIMD_EXT_MUL(name)                                         \
  void name(Simd128Register dst, Simd128Register src1, Simd128Register src2, \
            Simd128Register scratch);
  SIMD_EXT_MUL_LIST(PROTOTYPE_SIMD_EXT_MUL)
#undef PROTOTYPE_SIMD_EXT_MUL
#undef SIMD_EXT_MUL_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue)             \
  V(I32x4AllTrue)             \
  V(I16x8AllTrue)             \
  V(I8x16AllTrue)

#define PROTOTYPE_SIMD_ALL_TRUE(name)                             \
  void name(Register dst, Simd128Register src, Register scratch1, \
            Simd128Register scratch2);
  SIMD_ALL_TRUE_LIST(PROTOTYPE_SIMD_ALL_TRUE)
#undef PROTOTYPE_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_QFM_LIST(V) \
  V(F64x2Qfma)           \
  V(F64x2Qfms)           \
  V(F32x4Qfma)           \
  V(F32x4Qfms)

#define PROTOTYPE_SIMD_QFM(name)                                             \
  void name(Simd128Register dst, Simd128Register src1, Simd128Register src2, \
            Simd128Register src3);
  SIMD_QFM_LIST(PROTOTYPE_SIMD_QFM)
#undef PROTOTYPE_SIMD_QFM
#undef SIMD_QFM_LIST

#define SIMD_ADD_SUB_SAT_LIST(V) \
  V(I16x8AddSatS)                \
  V(I16x8SubSatS)                \
  V(I16x8AddSatU)                \
  V(I16x8SubSatU)                \
  V(I8x16AddSatS)                \
  V(I8x16SubSatS)                \
  V(I8x16AddSatU)                \
  V(I8x16SubSatU)

#define PROTOTYPE_SIMD_ADD_SUB_SAT(name)                                     \
  void name(Simd128Register dst, Simd128Register src1, Simd128Register src2, \
            Simd128Register scratch1, Simd128Register scratch2);
  SIMD_ADD_SUB_SAT_LIST(PROTOTYPE_SIMD_ADD_SUB_SAT)
#undef PROTOTYPE_SIMD_ADD_SUB_SAT
#undef SIMD_ADD_SUB_SAT_LIST

#define SIMD_EXT_ADD_PAIRWISE_LIST(V) \
  V(I32x4ExtAddPairwiseI16x8S)        \
  V(I32x4ExtAddPairwiseI16x8U)        \
  V(I16x8ExtAddPairwiseI8x16S)        \
  V(I16x8ExtAddPairwiseI8x16U)

#define PROTOTYPE_SIMD_EXT_ADD_PAIRWISE(name)         \
  void name(Simd128Register dst, Simd128Register src, \
            Simd128Register scratch1, Simd128Register scratch2);
  SIMD_EXT_ADD_PAIRWISE_LIST(PROTOTYPE_SIMD_EXT_ADD_PAIRWISE)
#undef PROTOTYPE_SIMD_EXT_ADD_PAIRWISE
#undef SIMD_EXT_ADD_PAIRWISE_LIST

  // ---------------------------------------------------------------------------
  // Pointer compression Support

  void SmiToPtrArrayOffset(Register dst, Register src) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
    static_assert(kSmiTag == 0 && kSmiShift < kSystemPointerSizeLog2);
    ShiftLeftU64(dst, src, Operand(kSystemPointerSizeLog2 - kSmiShift));
#else
    static_assert(kSmiTag == 0 && kSmiShift > kSystemPointerSizeLog2);
    ShiftRightS64(dst, src, Operand(kSmiShift - kSystemPointerSizeLog2));
#endif
  }

  // Loads a field containing any tagged value and decompresses it if necessary.
  void LoadTaggedField(const Register& destination,
                       const Me
```