Response:
The user wants a summary of the C++ header file `v8/src/codegen/ppc/macro-assembler-ppc.h`. I need to identify the main functionalities exposed by this header. It appears to define a `MacroAssembler` class for the PowerPC architecture within the V8 JavaScript engine.

Here's a breakdown of the apparent features:

1. **Code Generation Primitives:** The header defines methods that correspond to assembly instructions (e.g., `AddS64`, `MulF64`, `ShiftLeftU32`). These are the building blocks for generating machine code.
2. **High-Level Code Generation Constructs:**  Beyond individual instructions, there are methods for common code sequences, like function prologues (`Prologue`, `StubPrologue`), frame management (`EnterFrame`, `LeaveFrame`), and calling conventions (`CallBuiltin`, `CallCFunction`).
3. **Memory Operations:**  Methods for loading and storing data to and from memory are present (e.g., `LoadU64`, `StoreU64`, `FieldMemOperand`). Atomic operations are also included (`AtomicCompareExchange`, `AtomicExchange`).
4. **Data Handling:** Functions for manipulating different data types (integers, floats, doubles, Smis) and converting between them (e.g., `ConvertIntToDouble`, `MovIntToDouble`, `SmiUntag`).
5. **Control Flow:**  Methods for branching and calling (e.g., `Jump`, `Call`, `Ret`).
6. **Stack Management:**  Functions to manipulate the stack (e.g., `Push`, `Pop`, `AllocateStackSpace`).
7. **Runtime Integration:**  Methods for interacting with the V8 runtime (e.g., `LoadRoot`, `CallBuiltin`).
8. **Debugging and Assertions:**  Functions for debugging and adding assertions in generated code (`Assert`, `Check`, `DebugBreak`).

The user also asks about the `.tq` extension and JavaScript relation. This file is a C++ header (`.h`), so it's not a Torque file. However, the functionality it provides is crucial for implementing JavaScript features on the PowerPC architecture.

Regarding hypothetical input/output, this is about code *generation*. So, the "input" is the sequence of `MacroAssembler` method calls, and the "output" is the generated machine code. It's difficult to give a specific example without a larger context.

Common programming errors related to this kind of code would involve incorrect register usage, stack pointer mismanagement, and misinterpreting instruction semantics.
这是 `v8/src/codegen/ppc/macro-assembler-ppc.h` 文件的功能归纳：

**主要功能:**

`v8/src/codegen/ppc/macro-assembler-ppc.h` 定义了一个 `MacroAssembler` 类，它是 V8 JavaScript 引擎在 PowerPC 架构上生成机器码的核心工具。它提供了一系列高级接口，用于生成 PowerPC 汇编指令，并封装了底层的 `Assembler` 类。

**详细功能点:**

1. **生成 PowerPC 汇编指令:**  `MacroAssembler` 提供了大量的方法，对应于各种 PowerPC 汇编指令，例如：
    * **算术运算:** `AddS64`, `SubS64`, `MulS64`, `DivS64` 等用于加减乘除。
    * **逻辑运算:** `AndU64`, `OrU64`, `XorU64` 等用于按位与或异或。
    * **移位操作:** `ShiftLeftU64`, `ShiftRightU64`, `ShiftRightS64` 等用于移位。
    * **比较操作:** `CmpS64`, `CmpU64`, `CompareTagged` 等用于比较。
    * **浮点运算:** `AddF64`, `SubF64`, `MulF64`, `DivF64` 等用于浮点数运算。
    * **加载和存储:** `LoadU64`, `StoreU64` 等用于在寄存器和内存之间移动数据。
    * **类型转换:** `ConvertIntToDouble`, `ConvertDoubleToInt64` 等用于不同数据类型之间的转换。
    * **原子操作:** `AtomicCompareExchange`, `AtomicExchange`, `AtomicOps` 等用于实现原子级别的内存操作。

2. **函数调用和返回:**  提供了用于生成函数调用和返回相关代码的方法：
    * `CallBuiltin`, `TailCallBuiltin`: 调用内置函数。
    * `CallCFunction`: 调用 C 函数。
    * `EnterFrame`, `LeaveFrame`:  管理函数调用栈帧的创建和销毁。
    * `PushStandardFrame`: 创建标准的 JavaScript 函数栈帧。
    * `Ret`:  函数返回。

3. **栈管理:**  提供操作栈的方法：
    * `Push`: 将数据压入栈。
    * `Pop`: 从栈中弹出数据。
    * `AllocateStackSpace`:  在栈上分配空间。
    * `DropArguments`:  从栈上移除参数。

4. **常量加载:**  提供加载常量的方法：
    * `LoadDoubleLiteral`: 加载双精度浮点数常量。
    * `LoadIntLiteral`: 加载整数常量。
    * `LoadSmiLiteral`: 加载小整数 (Smi) 常量。
    * `LoadRoot`:  加载根对象表中的对象。
    * `LoadFromConstantsTable`: 加载常量表中的常量。

5. **条件控制流:**  支持基于条件的指令执行：
    * `Condition` 枚举表示各种条件码。
    * 许多指令方法接受 `Condition` 参数，例如 `Jump(target, rmode, cond)`.
    * `Assert`, `Check`:  用于添加断言，在条件不满足时触发错误。

6. **与其他 V8 组件交互:**
    * 可以加载内置函数 (`LoadEntryFromBuiltin`, `CallBuiltinByIndex`).
    * 可以加载和存储 V8 堆对象 (`FieldMemOperand`).
    * 可以与垃圾回收器交互 (`CallEphemeronKeyBarrier`, `CallRecordWriteStub`).
    * 可以处理去优化 (`CallForDeoptimization`).

7. **调试支持:**
    * `Trap`:  产生一个中断。
    * `DebugBreak`:  触发调试断点。

8. **辅助功能:**
    * `GetRegisterThatIsNotOneOf`: 获取一个不属于指定寄存器列表的寄存器。
    * `ClearLeftImm`, `ClearRightImm`:  用于清除寄存器中的位。
    * `ByteReverseU16`, `ByteReverseU32`, `ByteReverseU64`:  字节序反转。

**关于 .tq 扩展和 JavaScript 关系:**

* 你提供的文件 `v8/src/codegen/ppc/macro-assembler-ppc.h` 以 `.h` 结尾，这是一个 C++ 头文件。因此，它**不是**一个 Torque 源代码文件。
* Torque 是 V8 中用于生成 TurboFan 编译器节点和辅助函数的领域特定语言。
* **与 JavaScript 的关系:**  `macro-assembler-ppc.h` 中定义的功能直接服务于 JavaScript 的执行。当 V8 需要在 PowerPC 架构上执行 JavaScript 代码时，它会使用 `MacroAssembler` 类来生成相应的机器码。例如，执行一个加法运算的 JavaScript 代码，V8 可能会使用 `AddS64` 或 `AddF64` 等方法生成对应的 PowerPC 加法指令。

**JavaScript 示例 (假设):**

虽然 `macro-assembler-ppc.h` 是 C++ 代码，但它的功能是为了支持 JavaScript。例如，考虑以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10); // 假设 a 和 b 都是小整数 (Smi)
```

当 V8 执行 `add(5, 10)` 时，在 PowerPC 架构上，`MacroAssembler` 可能会生成类似以下的汇编指令 (简化示例)：

```assembly
// ... 函数序言 ...
  addi r3, r_参数a, r_参数b  // 将参数 a 和 b 相加，结果存入 r3
  blr                      // 返回
// ... 函数尾声 ...
```

这里的 `addi` 指令就可能通过 `MacroAssembler` 的某个方法 (比如内部调用的 `Assembler::addi`) 生成。

**代码逻辑推理示例 (假设):**

假设 `MacroAssembler` 中有一个方法 `LoadTaggedField(Register destination, Register object, int offset)` 用于加载对象的带标记字段。

* **假设输入:**
    * `destination`:  寄存器 `r5`
    * `object`: 寄存器 `r4` (假设 `r4` 中存储着一个对象的地址)
    * `offset`:  整数 `16` (表示字段相对于对象起始地址的偏移量)

* **输出 (生成的汇编代码片段):**

   ```assembly
   ld r5, 16(r4)  // 从 r4 偏移 16 字节处加载数据到 r5
   ```

   这个指令会将 `r4` 指向的对象的第 16 字节开始的数据加载到 `r5` 寄存器中。

**用户常见的编程错误 (在使用 MacroAssembler 的 V8 代码中):**

1. **寄存器分配错误:**  错误地使用了被其他操作占用的寄存器，导致数据被覆盖。
2. **栈操作错误:**  `Push` 和 `Pop` 的数量不匹配，导致栈指针错乱。
3. **条件码使用错误:**  基于错误的条件码进行跳转，导致程序逻辑错误。
4. **内存访问错误:**  使用了错误的内存偏移量，访问了不应该访问的内存区域。
5. **指令语义理解错误:**  对 PowerPC 指令的功能理解有偏差，导致生成的代码不符合预期。

**功能归纳 (第 1 部分):**

`v8/src/codegen/ppc/macro-assembler-ppc.h` 定义了 PowerPC 架构的 `MacroAssembler` 类，它是一个用于生成 PowerPC 汇编代码的高级接口。它提供了封装了底层汇编指令的方法，以及用于处理函数调用、栈管理、常量加载和控制流等常见代码模式的辅助功能。这个类是 V8 引擎在 PowerPC 架构上执行 JavaScript 代码的关键组成部分。

### 提示词
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/macro-assembler-ppc.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDED_FROM_MACRO_ASSEMBLER_H
#error This header must be included via macro-assembler.h
#endif

#ifndef V8_CODEGEN_PPC_MACRO_ASSEMBLER_PPC_H_
#define V8_CODEGEN_PPC_MACRO_ASSEMBLER_PPC_H_

#include "src/base/numbers/double.h"
#include "src/base/platform/platform.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/ppc/assembler-ppc.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/execution/isolate-data.h"
#include "src/objects/contexts.h"

namespace v8 {
namespace internal {

enum class StackLimitKind { kInterruptStackLimit, kRealStackLimit };

// ----------------------------------------------------------------------------
// Static helper functions

// Generate a MemOperand for loading a field from an object.
inline MemOperand FieldMemOperand(Register object, int offset) {
  return MemOperand(object, offset - kHeapObjectTag);
}

enum LinkRegisterStatus { kLRHasNotBeenSaved, kLRHasBeenSaved };

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2 = no_reg,
                                   Register reg3 = no_reg,
                                   Register reg4 = no_reg,
                                   Register reg5 = no_reg,
                                   Register reg6 = no_reg);

// These exist to provide portability between 32 and 64bit
#define ClearLeftImm clrldi
#define ClearRightImm clrrdi

class V8_EXPORT_PRIVATE MacroAssembler : public MacroAssemblerBase {
 public:
  using MacroAssemblerBase::MacroAssemblerBase;

  void CallBuiltin(Builtin builtin, Condition cond = al);
  void TailCallBuiltin(Builtin builtin, Condition cond = al,
                       CRegister cr = cr7);
  void Popcnt32(Register dst, Register src);
  void Popcnt64(Register dst, Register src);
  // Converts the integer (untagged smi) in |src| to a double, storing
  // the result to |dst|
  void ConvertIntToDouble(Register src, DoubleRegister dst);

  // Converts the unsigned integer (untagged smi) in |src| to
  // a double, storing the result to |dst|
  void ConvertUnsignedIntToDouble(Register src, DoubleRegister dst);

  // Converts the integer (untagged smi) in |src| to
  // a float, storing the result in |dst|
  void ConvertIntToFloat(Register src, DoubleRegister dst);

  // Converts the unsigned integer (untagged smi) in |src| to
  // a float, storing the result in |dst|
  void ConvertUnsignedIntToFloat(Register src, DoubleRegister dst);

  void ConvertInt64ToFloat(Register src, DoubleRegister double_dst);
  void ConvertInt64ToDouble(Register src, DoubleRegister double_dst);
  void ConvertUnsignedInt64ToFloat(Register src, DoubleRegister double_dst);
  void ConvertUnsignedInt64ToDouble(Register src, DoubleRegister double_dst);

  // Converts the double_input to an integer.  Note that, upon return,
  // the contents of double_dst will also hold the fixed point representation.
  void ConvertDoubleToInt64(const DoubleRegister double_input,
                            const Register dst, const DoubleRegister double_dst,
                            FPRoundingMode rounding_mode = kRoundToZero);

  // Converts the double_input to an unsigned integer.  Note that, upon return,
  // the contents of double_dst will also hold the fixed point representation.
  void ConvertDoubleToUnsignedInt64(
      const DoubleRegister double_input, const Register dst,
      const DoubleRegister double_dst,
      FPRoundingMode rounding_mode = kRoundToZero);

  // Activation support.
  void EnterFrame(StackFrame::Type type,
                  bool load_constant_pool_pointer_reg = false);

  // Returns the pc offset at which the frame ends.
  int LeaveFrame(StackFrame::Type type, int stack_adjustment = 0);

  void AllocateStackSpace(int bytes) {
    DCHECK_GE(bytes, 0);
    if (bytes == 0) return;
    AddS64(sp, sp, Operand(-bytes), r0);
  }

  void AllocateStackSpace(Register bytes) { sub(sp, sp, bytes); }

  // Push a fixed frame, consisting of lr, fp, constant pool.
  void PushCommonFrame(Register marker_reg = no_reg);

  // Generates function and stub prologue code.
  void StubPrologue(StackFrame::Type type);
  void Prologue();

  void DropArguments(Register count);
  void DropArgumentsAndPushNewReceiver(Register argc, Register receiver);

  // Push a standard frame, consisting of lr, fp, constant pool,
  // context and JS function
  void PushStandardFrame(Register function_reg);

  // Restore caller's frame pointer and return address prior to being
  // overwritten by tail call stack preparation.
  void RestoreFrameStateForTailCall();

  // Get the actual activation frame alignment for target environment.
  static int ActivationFrameAlignment();

  void InitializeRootRegister() {
    ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
    mov(kRootRegister, Operand(isolate_root));
#ifdef V8_COMPRESS_POINTERS
    LoadRootRelative(kPtrComprCageBaseRegister,
                     IsolateData::cage_base_offset());
#endif
  }

  void LoadDoubleLiteral(DoubleRegister result, base::Double value,
                         Register scratch);

  // load a literal signed int value <value> to GPR <dst>
  void LoadIntLiteral(Register dst, int value);
  // load an SMI value <value> to GPR <dst>
  void LoadSmiLiteral(Register dst, Tagged<Smi> smi);

  void LoadPC(Register dst);
  void ComputeCodeStartAddress(Register dst);

  void CmpS64(Register src1, const Operand& src2, Register scratch,
              CRegister cr = cr7);
  void CmpS64(Register src1, Register src2, CRegister cr = cr7);
  void CmpU64(Register src1, const Operand& src2, Register scratch,
              CRegister cr = cr7);
  void CmpU64(Register src1, Register src2, CRegister cr = cr7);
  void CmpS32(Register src1, const Operand& src2, Register scratch,
              CRegister cr = cr7);
  void CmpS32(Register src1, Register src2, CRegister cr = cr7);
  void CmpU32(Register src1, const Operand& src2, Register scratch,
              CRegister cr = cr7);
  void CmpU32(Register src1, Register src2, CRegister cr = cr7);
  void CompareTagged(Register src1, Register src2, CRegister cr = cr7) {
    if (COMPRESS_POINTERS_BOOL) {
      CmpS32(src1, src2, cr);
    } else {
      CmpS64(src1, src2, cr);
    }
  }

  void MinF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              DoubleRegister scratch = kScratchDoubleReg);
  void MaxF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              DoubleRegister scratch = kScratchDoubleReg);

  // Set new rounding mode RN to FPSCR
  void SetRoundingMode(FPRoundingMode RN);

  // reset rounding mode to default (kRoundToNearest)
  void ResetRoundingMode();

  void AddS64(Register dst, Register src, const Operand& value,
              Register scratch = r0, OEBit s = LeaveOE, RCBit r = LeaveRC);
  void AddS64(Register dst, Register src, Register value, OEBit s = LeaveOE,
              RCBit r = LeaveRC);
  void SubS64(Register dst, Register src, const Operand& value,
              Register scratch = r0, OEBit s = LeaveOE, RCBit r = LeaveRC);
  void SubS64(Register dst, Register src, Register value, OEBit s = LeaveOE,
              RCBit r = LeaveRC);
  void AddS32(Register dst, Register src, const Operand& value,
              Register scratch = r0, RCBit r = LeaveRC);
  void AddS32(Register dst, Register src, Register value, RCBit r = LeaveRC);
  void SubS32(Register dst, Register src, const Operand& value,
              Register scratch = r0, RCBit r = LeaveRC);
  void SubS32(Register dst, Register src, Register value, RCBit r = LeaveRC);
  void MulS64(Register dst, Register src, const Operand& value,
              Register scratch = r0, OEBit s = LeaveOE, RCBit r = LeaveRC);
  void MulS64(Register dst, Register src, Register value, OEBit s = LeaveOE,
              RCBit r = LeaveRC);
  void MulS32(Register dst, Register src, const Operand& value,
              Register scratch = r0, OEBit s = LeaveOE, RCBit r = LeaveRC);
  void MulS32(Register dst, Register src, Register value, OEBit s = LeaveOE,
              RCBit r = LeaveRC);
  void DivS64(Register dst, Register src, Register value, OEBit s = LeaveOE,
              RCBit r = LeaveRC);
  void DivU64(Register dst, Register src, Register value, OEBit s = LeaveOE,
              RCBit r = LeaveRC);
  void DivS32(Register dst, Register src, Register value, OEBit s = LeaveOE,
              RCBit r = LeaveRC);
  void DivU32(Register dst, Register src, Register value, OEBit s = LeaveOE,
              RCBit r = LeaveRC);
  void ModS64(Register dst, Register src, Register value);
  void ModU64(Register dst, Register src, Register value);
  void ModS32(Register dst, Register src, Register value);
  void ModU32(Register dst, Register src, Register value);

  void AndU64(Register dst, Register src, const Operand& value,
              Register scratch = r0, RCBit r = SetRC);
  void AndU64(Register dst, Register src, Register value, RCBit r = SetRC);
  void OrU64(Register dst, Register src, const Operand& value,
             Register scratch = r0, RCBit r = SetRC);
  void OrU64(Register dst, Register src, Register value, RCBit r = LeaveRC);
  void XorU64(Register dst, Register src, const Operand& value,
              Register scratch = r0, RCBit r = SetRC);
  void XorU64(Register dst, Register src, Register value, RCBit r = LeaveRC);
  void AndU32(Register dst, Register src, const Operand& value,
              Register scratch = r0, RCBit r = SetRC);
  void AndU32(Register dst, Register src, Register value, RCBit r = SetRC);
  void OrU32(Register dst, Register src, const Operand& value,
             Register scratch = r0, RCBit r = SetRC);
  void OrU32(Register dst, Register src, Register value, RCBit r = LeaveRC);
  void XorU32(Register dst, Register src, const Operand& value,
              Register scratch = r0, RCBit r = SetRC);
  void XorU32(Register dst, Register src, Register value, RCBit r = LeaveRC);

  void ShiftLeftU64(Register dst, Register src, const Operand& value,
                    RCBit r = LeaveRC);
  void ShiftRightU64(Register dst, Register src, const Operand& value,
                     RCBit r = LeaveRC);
  void ShiftRightS64(Register dst, Register src, const Operand& value,
                     RCBit r = LeaveRC);
  void ShiftLeftU32(Register dst, Register src, const Operand& value,
                    RCBit r = LeaveRC);
  void ShiftRightU32(Register dst, Register src, const Operand& value,
                     RCBit r = LeaveRC);
  void ShiftRightS32(Register dst, Register src, const Operand& value,
                     RCBit r = LeaveRC);
  void ShiftLeftU64(Register dst, Register src, Register value,
                    RCBit r = LeaveRC);
  void ShiftRightU64(Register dst, Register src, Register value,
                     RCBit r = LeaveRC);
  void ShiftRightS64(Register dst, Register src, Register value,
                     RCBit r = LeaveRC);
  void ShiftLeftU32(Register dst, Register src, Register value,
                    RCBit r = LeaveRC);
  void ShiftRightU32(Register dst, Register src, Register value,
                     RCBit r = LeaveRC);
  void ShiftRightS32(Register dst, Register src, Register value,
                     RCBit r = LeaveRC);

  void CountLeadingZerosU32(Register dst, Register src, RCBit r = LeaveRC);
  void CountLeadingZerosU64(Register dst, Register src, RCBit r = LeaveRC);
  void CountTrailingZerosU32(Register dst, Register src, Register scratch1 = ip,
                             Register scratch2 = r0, RCBit r = LeaveRC);
  void CountTrailingZerosU64(Register dst, Register src, Register scratch1 = ip,
                             Register scratch2 = r0, RCBit r = LeaveRC);

  void ClearByteU64(Register dst, int byte_idx);
  void ReverseBitsU64(Register dst, Register src, Register scratch1,
                      Register scratch2);
  void ReverseBitsU32(Register dst, Register src, Register scratch1,
                      Register scratch2);
  void ReverseBitsInSingleByteU64(Register dst, Register src,
                                  Register scratch1, Register scratch2,
                                  int byte_idx);

  void AddF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              RCBit r = LeaveRC);
  void SubF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              RCBit r = LeaveRC);
  void MulF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              RCBit r = LeaveRC);
  void DivF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              RCBit r = LeaveRC);
  void AddF32(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              RCBit r = LeaveRC);
  void SubF32(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              RCBit r = LeaveRC);
  void MulF32(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              RCBit r = LeaveRC);
  void DivF32(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
              RCBit r = LeaveRC);
  void CopySignF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs,
                   RCBit r = LeaveRC);

  template <class _type>
  void SignedExtend(Register dst, Register value) {
    switch (sizeof(_type)) {
      case 1:
        extsb(dst, value);
        break;
      case 2:
        extsh(dst, value);
        break;
      case 4:
        extsw(dst, value);
        break;
      case 8:
        if (dst != value) mr(dst, value);
        break;
      default:
        UNREACHABLE();
    }
  }

  template <class _type>
  void ZeroExtend(Register dst, Register value) {
    switch (sizeof(_type)) {
      case 1:
        ZeroExtByte(dst, value);
        break;
      case 2:
        ZeroExtHalfWord(dst, value);
        break;
      case 4:
        ZeroExtWord32(dst, value);
        break;
      case 8:
        if (dst != value) mr(dst, value);
        break;
      default:
        UNREACHABLE();
    }
  }
  template <class _type>
  void ExtendValue(Register dst, Register value) {
    if (std::is_signed<_type>::value) {
      SignedExtend<_type>(dst, value);
    } else {
      ZeroExtend<_type>(dst, value);
    }
  }

  template <class _type>
  void LoadReserve(Register output, MemOperand dst) {
    switch (sizeof(_type)) {
      case 1:
        lbarx(output, dst);
        break;
      case 2:
        lharx(output, dst);
        break;
      case 4:
        lwarx(output, dst);
        break;
      case 8:
        ldarx(output, dst);
        break;
      default:
        UNREACHABLE();
    }
    if (std::is_signed<_type>::value) {
      SignedExtend<_type>(output, output);
    }
  }

  template <class _type>
  void StoreConditional(Register value, MemOperand dst) {
    switch (sizeof(_type)) {
      case 1:
        stbcx(value, dst);
        break;
      case 2:
        sthcx(value, dst);
        break;
      case 4:
        stwcx(value, dst);
        break;
      case 8:
        stdcx(value, dst);
        break;
      default:
        UNREACHABLE();
    }
  }

  template <class _type>
  void AtomicCompareExchange(MemOperand dst, Register old_value,
                             Register new_value, Register output,
                             Register scratch) {
    Label loop;
    Label exit;
    if (sizeof(_type) != 8) {
      ExtendValue<_type>(scratch, old_value);
      old_value = scratch;
    }
    lwsync();
    bind(&loop);
    LoadReserve<_type>(output, dst);
    cmp(output, old_value, cr0);
    bne(&exit, cr0);
    StoreConditional<_type>(new_value, dst);
    bne(&loop, cr0);
    bind(&exit);
    sync();
  }

  template <class _type>
  void AtomicExchange(MemOperand dst, Register new_value, Register output) {
    Label exchange;
    lwsync();
    bind(&exchange);
    LoadReserve<_type>(output, dst);
    StoreConditional<_type>(new_value, dst);
    bne(&exchange, cr0);
    sync();
  }

  template <class _type, class bin_op>
  void AtomicOps(MemOperand dst, Register value, Register output,
                 Register result, bin_op op) {
    Label binop;
    lwsync();
    bind(&binop);
    switch (sizeof(_type)) {
      case 1:
        lbarx(output, dst);
        break;
      case 2:
        lharx(output, dst);
        break;
      case 4:
        lwarx(output, dst);
        break;
      case 8:
        ldarx(output, dst);
        break;
      default:
        UNREACHABLE();
    }
    op(result, output, value);
    switch (sizeof(_type)) {
      case 1:
        stbcx(result, dst);
        break;
      case 2:
        sthcx(result, dst);
        break;
      case 4:
        stwcx(result, dst);
        break;
      case 8:
        stdcx(result, dst);
        break;
      default:
        UNREACHABLE();
    }
    bne(&binop, cr0);
    sync();
  }

  void Push(Register src) { push(src); }
  // Push a handle.
  void Push(Handle<HeapObject> handle);
  void Push(Tagged<Smi> smi);

  // Push two registers.  Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2) {
    StoreU64WithUpdate(src2, MemOperand(sp, -2 * kSystemPointerSize));
    StoreU64(src1, MemOperand(sp, kSystemPointerSize));
  }

  // Push three registers.  Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3) {
    StoreU64WithUpdate(src3, MemOperand(sp, -3 * kSystemPointerSize));
    StoreU64(src2, MemOperand(sp, kSystemPointerSize));
    StoreU64(src1, MemOperand(sp, 2 * kSystemPointerSize));
  }

  // Push four registers.  Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3, Register src4) {
    StoreU64WithUpdate(src4, MemOperand(sp, -4 * kSystemPointerSize));
    StoreU64(src3, MemOperand(sp, kSystemPointerSize));
    StoreU64(src2, MemOperand(sp, 2 * kSystemPointerSize));
    StoreU64(src1, MemOperand(sp, 3 * kSystemPointerSize));
  }

  // Push five registers.  Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3, Register src4,
            Register src5) {
    StoreU64WithUpdate(src5, MemOperand(sp, -5 * kSystemPointerSize));
    StoreU64(src4, MemOperand(sp, kSystemPointerSize));
    StoreU64(src3, MemOperand(sp, 2 * kSystemPointerSize));
    StoreU64(src2, MemOperand(sp, 3 * kSystemPointerSize));
    StoreU64(src1, MemOperand(sp, 4 * kSystemPointerSize));
  }

  enum PushArrayOrder { kNormal, kReverse };
  void PushArray(Register array, Register size, Register scratch,
                 Register scratch2, PushArrayOrder order = kNormal);

  void Pop(Register dst) { pop(dst); }

  // Pop two registers. Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2) {
    LoadU64(src2, MemOperand(sp, 0));
    LoadU64(src1, MemOperand(sp, kSystemPointerSize));
    addi(sp, sp, Operand(2 * kSystemPointerSize));
  }

  // Pop three registers.  Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2, Register src3) {
    LoadU64(src3, MemOperand(sp, 0));
    LoadU64(src2, MemOperand(sp, kSystemPointerSize));
    LoadU64(src1, MemOperand(sp, 2 * kSystemPointerSize));
    addi(sp, sp, Operand(3 * kSystemPointerSize));
  }

  // Pop four registers.  Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2, Register src3, Register src4) {
    LoadU64(src4, MemOperand(sp, 0));
    LoadU64(src3, MemOperand(sp, kSystemPointerSize));
    LoadU64(src2, MemOperand(sp, 2 * kSystemPointerSize));
    LoadU64(src1, MemOperand(sp, 3 * kSystemPointerSize));
    addi(sp, sp, Operand(4 * kSystemPointerSize));
  }

  // Pop five registers.  Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2, Register src3, Register src4,
           Register src5) {
    LoadU64(src5, MemOperand(sp, 0));
    LoadU64(src4, MemOperand(sp, kSystemPointerSize));
    LoadU64(src3, MemOperand(sp, 2 * kSystemPointerSize));
    LoadU64(src2, MemOperand(sp, 3 * kSystemPointerSize));
    LoadU64(src1, MemOperand(sp, 4 * kSystemPointerSize));
    addi(sp, sp, Operand(5 * kSystemPointerSize));
  }

  void MaybeSaveRegisters(RegList registers);
  void MaybeRestoreRegisters(RegList registers);

  void CallEphemeronKeyBarrier(Register object, Register slot_address,
                               SaveFPRegsMode fp_mode);

  void CallIndirectPointerBarrier(Register object, Register slot_address,
                                  SaveFPRegsMode fp_mode,
                                  IndirectPointerTag tag);

  void CallRecordWriteStubSaveRegisters(
      Register object, Register slot_address, SaveFPRegsMode fp_mode,
      StubCallMode mode = StubCallMode::kCallBuiltinPointer);
  void CallRecordWriteStub(
      Register object, Register slot_address, SaveFPRegsMode fp_mode,
      StubCallMode mode = StubCallMode::kCallBuiltinPointer);

  void MultiPush(RegList regs, Register location = sp);
  void MultiPop(RegList regs, Register location = sp);

  void MultiPushDoubles(DoubleRegList dregs, Register location = sp);
  void MultiPopDoubles(DoubleRegList dregs, Register location = sp);

  void MultiPushV128(Simd128RegList dregs, Register scratch,
                     Register location = sp);
  void MultiPopV128(Simd128RegList dregs, Register scratch,
                    Register location = sp);

  void MultiPushF64AndV128(DoubleRegList dregs, Simd128RegList simd_regs,
                           Register scratch1, Register scratch2,
                           Register location = sp);
  void MultiPopF64AndV128(DoubleRegList dregs, Simd128RegList simd_regs,
                          Register scratch1, Register scratch2,
                          Register location = sp);

  // Calculate how much stack space (in bytes) are required to store caller
  // registers excluding those specified in the arguments.
  int RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                      Register exclusion1 = no_reg,
                                      Register exclusion2 = no_reg,
                                      Register exclusion3 = no_reg) const;

  // Push caller saved registers on the stack, and return the number of bytes
  // stack pointer is adjusted.
  int PushCallerSaved(SaveFPRegsMode fp_mode, Register scratch1,
                      Register scratch2, Register exclusion1 = no_reg,
                      Register exclusion2 = no_reg,
                      Register exclusion3 = no_reg);
  // Restore caller saved registers from the stack, and return the number of
  // bytes stack pointer is adjusted.
  int PopCallerSaved(SaveFPRegsMode fp_mode, Register scratch1,
                     Register scratch2, Register exclusion1 = no_reg,
                     Register exclusion2 = no_reg,
                     Register exclusion3 = no_reg);

  // Load an object from the root table.
  void LoadRoot(Register destination, RootIndex index) final {
    LoadRoot(destination, index, al);
  }
  void LoadRoot(Register destination, RootIndex index, Condition cond);
  void LoadTaggedRoot(Register destination, RootIndex index);

  void SwapP(Register src, Register dst, Register scratch);
  void SwapP(Register src, MemOperand dst, Register scratch);
  void SwapP(MemOperand src, MemOperand dst, Register scratch_0,
             Register scratch_1);
  void SwapFloat32(DoubleRegister src, DoubleRegister dst,
                   DoubleRegister scratch);
  void SwapFloat32(DoubleRegister src, MemOperand dst, DoubleRegister scratch);
  void SwapFloat32(MemOperand src, MemOperand dst, DoubleRegister scratch_0,
                   DoubleRegister scratch_1);
  void SwapDouble(DoubleRegister src, DoubleRegister dst,
                  DoubleRegister scratch);
  void SwapDouble(DoubleRegister src, MemOperand dst, DoubleRegister scratch);
  void SwapDouble(MemOperand src, MemOperand dst, DoubleRegister scratch_0,
                  DoubleRegister scratch_1);
  void SwapSimd128(Simd128Register src, Simd128Register dst,
                   Simd128Register scratch);
  void SwapSimd128(Simd128Register src, MemOperand dst,
                   Simd128Register scratch1, Register scratch2);
  void SwapSimd128(MemOperand src, MemOperand dst, Simd128Register scratch1,
                   Simd128Register scratch2, Register scratch3);

  void ByteReverseU16(Register dst, Register val, Register scratch);
  void ByteReverseU32(Register dst, Register val, Register scratch);
  void ByteReverseU64(Register dst, Register val, Register = r0);

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
      bool has_function_descriptor = true);
  int CallCFunction(
      Register function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      bool has_function_descriptor = true);
  int CallCFunction(
      ExternalReference function, int num_reg_arguments,
      int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      bool has_function_descriptor = true);
  int CallCFunction(
      Register function, int num_reg_arguments, int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      bool has_function_descriptor = true);

  void MovFromFloatParameter(DoubleRegister dst);
  void MovFromFloatResult(DoubleRegister dst);

  void Trap();
  void DebugBreak();

  // Calls Abort(msg) if the condition cond is not satisfied.
  // Use --debug_code to enable.
  void Assert(Condition cond, AbortReason reason,
              CRegister cr = cr7) NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but always enabled.
  void Check(Condition cond, AbortReason reason, CRegister cr = cr7);

  // Print a message to stdout and abort execution.
  void Abort(AbortReason reason);

  void LoadFromConstantsTable(Register destination, int constant_index) final;
  void LoadRootRegisterOffset(Register destination, intptr_t offset) final;
  void LoadRootRelative(Register destination, int32_t offset) final;
  void StoreRootRelative(int32_t offset, Register value) final;

  // Operand pointing to an external reference.
  // May emit code to set up the scratch register. The operand is
  // only guaranteed to be correct as long as the scratch register
  // isn't changed.
  // If the operand is used more than once, use a scratch register
  // that is guaranteed not to be clobbered.
  MemOperand ExternalReferenceAsOperand(ExternalReference reference,
                                        Register scratch);
  MemOperand ExternalReferenceAsOperand(IsolateFieldId id) {
    return ExternalReferenceAsOperand(ExternalReference::Create(id), no_reg);
  }

  // Jump, Call, and Ret pseudo instructions implementing inter-working.
  void Jump(Register target);
  void Jump(Address target, RelocInfo::Mode rmode, Condition cond = al,
            CRegister cr = cr7);
  void Jump(Handle<Code> code, RelocInfo::Mode rmode, Condition cond = al,
            CRegister cr = cr7);
  void Jump(const ExternalReference& reference);
  void Jump(intptr_t target, RelocInfo::Mode rmode, Condition cond = al,
            CRegister cr = cr7);
  void Call(Register target);
  void Call(Address target, RelocInfo::Mode rmode, Condition cond = al);
  void Call(Handle<Code> code, RelocInfo::Mode rmode = RelocInfo::CODE_TARGET,
            Condition cond = al);
  void Call(Label* target);

  // Load the builtin given by the Smi in |builtin_index| into |target|.
  void LoadEntryFromBuiltinIndex(Register builtin_index, Register target);
  void LoadEntryFromBuiltin(Builtin builtin, Register destination);
  MemOperand EntryFromBuiltinAsOperand(Builtin builtin);

  // Load the code entry point from the Code object.
  void LoadCodeInstructionStart(
      Register destination, Register code_object,
      CodeEntrypointTag tag = kDefaultCodeEntrypointTag);
  void CallCodeObject(Register code_object);
  void JumpCodeObject(Register code_object,
                      JumpMode jump_mode = JumpMode::kJump);

  void CallBuiltinByIndex(Register builtin_index, Register target);
  void BailoutIfDeoptimized();
  void CallForDeoptimization(Builtin target, int deopt_id, Label* exit,
                             DeoptimizeKind kind, Label* ret,
                             Label* jump_deoptimization_entry_label);

  // Emit code to discard a non-negative number of pointer-sized elements
  // from the stack, clobbering only the sp register.
  void Drop(int count);
  void Drop(Register count, Register scratch = r0);

  void Ret() { blr(); }
  void Ret(Condition cond, CRegister cr = cr7) { bclr(cond, cr); }
  void Ret(int drop) {
    Drop(drop);
    blr();
  }

  // If the value is a NaN, canonicalize the value else, do nothing.
  void CanonicalizeNaN(const DoubleRegister dst, const DoubleRegister src);
  void CanonicalizeNaN(const DoubleRegister value) {
    CanonicalizeNaN(value, value);
  }
  void CheckPageFlag(Register object, Register scratch, int mask, Condition cc,
                     Label* condition_met);

  // Move values between integer and floating point registers.
  void MovIntToDouble(DoubleRegister dst, Register src, Register scratch);
  void MovUnsignedIntToDouble(DoubleRegister dst, Register src,
                              Register scratch);
  void MovInt64ToDouble(DoubleRegister dst,
                        Register src);
  void MovInt64ComponentsToDouble(DoubleRegister dst, Register src_hi,
                                  Register src_lo, Register scratch);
  void InsertDoubleLow(DoubleRegister dst, Register src, Register scratch);
  void InsertDoubleHigh(DoubleRegister dst, Register src, Register scratch);
  void MovDoubleLowToInt(Register dst, DoubleRegister src);
  void MovDoubleHighToInt(Register dst, DoubleRegister src);
  void MovDoubleToInt64(
      Register dst, DoubleRegister src);
  void MovIntToFloat(DoubleRegister dst, Register src, Register scratch);
  void MovFloatToInt(Register dst, DoubleRegister src, DoubleRegister scratch);
  // Register move. May do nothing if the registers are identical.
  void Move(Register dst, Tagged<Smi> smi) { LoadSmiLiteral(dst, smi); }
  void Move(Register dst, Handle<HeapObject> value,
            RelocInfo::Mode rmode = RelocInfo::FULL_EMBEDDED_OBJECT);
  void Move(Register dst, ExternalReference reference);
  void LoadIsolateField(Register dst, IsolateFieldId id);
  void Move(Register dst, Register src, Condition cond = al);
  void Move(DoubleRegister dst, DoubleRegister src);
  void Move(Register dst, const MemOperand& src) {
    // TODO: use scratch register scope instead of r0
    LoadU64(dst, src, r0);
  }

  void SmiUntag(Register dst, const MemOperand& src, RCBit rc = LeaveRC,
                Register scratch = no_reg);
  void SmiUntag(Register reg, RCBit rc = LeaveRC) { SmiUntag(reg, reg, rc); }

  void SmiUntag(Register dst, Register src, RCBit rc = LeaveRC) {
    if (COMPRESS_POINTERS_BOOL) {
      srawi(dst, src, kSmiShift, rc);
    } else {
      ShiftRightS64(
```