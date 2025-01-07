Response:
Let's break down the thought process for analyzing this C++ header file and generating the summary.

**1. Initial Scan and Identification of Key Areas:**

My first step is to quickly skim the entire file, looking for structural elements and keywords. I noticed:

* **Copyright and License:** Standard boilerplate, indicating open-source.
* **Include Guards:** `#ifndef` and `#define` for preventing multiple inclusions.
* **Includes:**  A list of other V8 headers, giving clues about dependencies and the overall purpose (e.g., `assembler-arch.h`, `assembler.h`, `codegen`).
* **Namespace:**  `v8::internal`, indicating internal V8 functionality.
* **Macros:**  `xlen`, `SmiWordOffset`, `FieldMemOperand`, `CFunctionArgumentOperand`, `DECLARE_...`, `DEFINE_...`. These suggest code generation and platform-specific details.
* **Enums:** `LiFlags`, `RAStatus`, `StackLimitKind`. These define sets of related constants.
* **Forward Declarations:** `enum class AbortReason`.
* **Class Declaration:** `class V8_EXPORT_PRIVATE MacroAssembler : public MacroAssemblerBase`. This is the core of the file.
* **Public and Private Members:**  Methods for various assembly operations, function calls, stack manipulation, debugging, and floating-point operations.
* **Conditional Compilation:** `#ifdef`, `#ifndef`.
* **Comments:**  Provide valuable information about register usage, optimization flags, and specific instructions.

**2. Understanding the Core Purpose (MacroAssembler):**

The class name `MacroAssembler` is a strong indicator. It's an abstraction layer on top of the raw assembly instructions for the RISC-V architecture. The goal is to provide higher-level, more convenient methods for generating assembly code.

**3. Grouping Functionality:**

As I reread the code more carefully, I start grouping the methods into functional categories:

* **Frame Management:**  `EnterFrame`, `LeaveFrame`, `StubPrologue`, `Prologue`.
* **Register Operations:** `li`, `Move`, `Push`, `Pop`, `MultiPush`, `MultiPop`, `Mv`.
* **Arithmetic/Logic:** `AddWord`, `SubWord`, `SllWord`, `And`, `Or`, `Xor`, etc.
* **Comparisons/Branches:** `Branch`, `BranchAndLink`, `CompareF32`, `CompareF64`, `CompareTaggedAndBranch`.
* **Function Calls (C and JavaScript):** `CallCFunction`, `CallJSFunction`, `CallCodeObject`, `CallBuiltin`, `TailCallBuiltin`.
* **Stack Manipulation:** `AllocateStackSpace`, `Drop`.
* **Debugging/Assertions:** `Trap`, `DebugBreak`, `Assert`, `Check`, `Abort`.
* **Floating-Point Operations:**  Methods with `F32` and `F64` in their names.
* **Memory Access:** `LoadWord`, `StoreWord`, `FieldMemOperand`, `ExternalReferenceAsOperand`.
* **Root Register and Isolate Access:** `InitializeRootRegister`, `LoadIsolateField`, `LoadRootRelative`, `StoreRootRelative`.
* **Smi Handling:** `SmiUntag`, `SmiToInt32`.
* **Bit Manipulation:** `Clz32`, `Ctz32`, `Popcnt32`, `SignExtendByte`, `SignExtendShort`.
* **Conditional Execution (Emulated):** Using `Branch` for conditional `Push`.

**4. Identifying Key Concepts and Implications:**

* **RISC-V Specifics:** The presence of RISC-V registers (e.g., `t5`, `t6`, `t3`, `sp`) and instructions (e.g., `auipc`, `jalr`, `amoadd_w`, `sextb`) confirms this is for the RISC-V architecture. The comments about the ABI and indirect function calls using `t6` are important details.
* **V8 Integration:**  The inclusion of V8-specific headers and the use of concepts like "Isolate," "HeapObject," "Smi," "Builtin," and "RelocInfo" clearly indicate this code is deeply integrated with the V8 JavaScript engine.
* **Code Generation:** The methods primarily focus on emitting sequences of assembly instructions. The `LiFlags` enum highlights optimizations related to code size and patchability.
* **Low-Level Operations:** This code works at a very low level, directly manipulating registers and memory.
* **Performance Considerations:**  The optimization flags and the presence of specialized instructions suggest a focus on generating efficient code.
* **Debugging and Safety:** The `Assert` and `Check` methods indicate mechanisms for verifying assumptions and catching errors during development.

**5. Addressing Specific Questions in the Prompt:**

* **".tq" extension:**  The prompt asks about `.tq`. The file ends with `.h`, so it's a standard C++ header. If it were `.tq`, it would be Torque code.
* **Relationship to JavaScript:**  The methods for calling JavaScript functions (`CallJSFunction`), handling Smis (JavaScript integers), and accessing heap objects clearly link it to JavaScript execution.
* **Code Logic Inference:** I looked for examples of operations with clear inputs and outputs, like `SmiUntag` (Smi -> integer) or stack operations (pushing and popping registers).
* **Common Programming Errors:**  I considered errors related to stack management (e.g., pushing/popping mismatches) and incorrect assumptions about register contents, especially with the reserved registers.

**6. Structuring the Summary:**

Finally, I organized the findings into a coherent summary, using bullet points and clear language. I focused on the key functionalities and their purpose within the V8 engine. I tried to keep the language accessible while still being technically accurate. I also specifically addressed the questions raised in the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial Overgeneralization:**  I might initially describe it as "low-level code generation." I would then refine this to be more specific about the RISC-V architecture and the purpose of a `MacroAssembler`.
* **Missing Details:**  I might overlook some of the more specialized methods on the first pass. Rereading and grouping helps identify these.
* **Clarity and Conciseness:** I would review the summary to ensure it's easy to understand and avoids unnecessary jargon. I tried to connect the technical details to the broader context of JavaScript execution.

This iterative process of scanning, understanding, grouping, connecting, and refining allowed me to create a comprehensive summary of the provided C++ header file.
好的，让我们来分析一下 `v8/src/codegen/riscv/macro-assembler-riscv.h` 这个 V8 源代码文件。

**功能归纳:**

`v8/src/codegen/riscv/macro-assembler-riscv.h` 是 V8 JavaScript 引擎中用于 RISC-V 架构的代码生成器（codegen）的核心头文件。它定义了 `MacroAssembler` 类，这个类提供了一组高级的接口，用于生成 RISC-V 汇编指令。 它的主要功能可以归纳为：

1. **提供 RISC-V 汇编指令的抽象:**  `MacroAssembler` 类封装了底层的 RISC-V 汇编指令，并提供了更易于使用的 C++ 方法来生成这些指令。这使得 V8 的代码生成器可以不必直接处理复杂的指令编码细节，提高了开发效率和代码可读性。

2. **支持常见的代码生成模式:**  它包含了用于执行常见代码生成任务的方法，例如：
    * **函数调用和返回:** `Call`, `Ret`, `TailCallBuiltin` 等。
    * **栈帧管理:** `EnterFrame`, `LeaveFrame`, `Push`, `Pop`, `AllocateStackSpace` 等。
    * **数据加载和存储:** `li` (加载立即数), `LoadWord`, `StoreWord`, `LoadRootRelative` 等。
    * **算术和逻辑运算:** `AddWord`, `SubWord`, `And`, `Or`, `Xor` 等。
    * **比较和分支:** `Branch`, `CompareI`, `CompareF32`, `CompareF64` 等。
    * **浮点运算支持:** 提供了 `CompareF32`, `CompareF64` 以及相关的分支指令。
    * **调试支持:** `Trap`, `DebugBreak`, `Assert`, `Check`, `Abort` 等。
    * **Smi (Small Integer) 处理:**  提供了 `SmiUntag`, `SmiToInt32` 等方法，用于在 Smi 和机器字之间转换。
    * **调用 C++ 函数:** `CallCFunction`, `PrepareCallCFunction` 等。

3. **处理平台相关的细节:**  `MacroAssembler` 针对 RISC-V 架构进行了定制，考虑了 RISC-V 的寄存器约定、指令格式和调用约定等。

4. **提供代码优化的辅助功能:**  例如 `LiFlags` 枚举用于控制 `li` 指令的生成方式，以优化代码大小或支持后续的打补丁操作。

5. **支持 V8 内部数据结构的访问:**  例如，`LoadRootRegisterOffset`, `LoadIsolateField` 用于访问 V8 内部的根对象和 Isolate 数据。

**关于 .tq 结尾:**

如果 `v8/src/codegen/riscv/macro-assembler-riscv.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是 V8 自己开发的一种用于定义内置函数和运行时代码的领域特定语言 (DSL)。 Torque 代码会被编译成 C++ 代码，最终生成机器码。 然而，根据你提供的文件名，它以 `.h` 结尾，所以它是一个标准的 C++ 头文件。

**与 JavaScript 功能的关系 (举例):**

`MacroAssembler` 生成的汇编代码是 JavaScript 代码执行的核心。 许多 JavaScript 操作最终都会被翻译成一系列汇编指令来执行。以下是一些 JavaScript 功能与 `MacroAssembler` 中方法的关联示例：

```javascript
// 简单的加法运算
let a = 10;
let b = 5;
let sum = a + b;
```

当 V8 执行这段代码时，它的代码生成器可能会使用 `MacroAssembler` 的方法，例如：

* `li(rd, 10)`: 将立即数 10 加载到寄存器 `rd` 中 (对应变量 `a`)。
* `li(rs, 5)`: 将立即数 5 加载到寄存器 `rs` 中 (对应变量 `b`)。
* `AddWord(result_reg, rd, Operand(rs))`: 将寄存器 `rd` 和 `rs` 的值相加，结果存储到 `result_reg` 中 (对应变量 `sum`)。

```javascript
// 调用一个 JavaScript 函数
function myFunction(x) {
  return x * 2;
}
myFunction(7);
```

当调用 `myFunction` 时，代码生成器可能会使用 `MacroAssembler` 的方法：

* **栈帧设置:**  使用 `EnterFrame` 创建新的栈帧。
* **参数传递:** 将参数 `7` 移动到特定的寄存器或栈位置。
* **函数调用:**  使用 `CallCodeObject` 或 `CallJSFunction` 调用 `myFunction` 对应的代码对象。
* **返回值处理:**  将函数的返回值从特定的寄存器移动到需要的地方。
* **栈帧清理:**  使用 `LeaveFrame` 清理栈帧。

```javascript
// 访问对象属性
const obj = { value: 42 };
console.log(obj.value);
```

访问对象属性时，代码生成器可能会使用：

* **加载对象地址:** 使用 `li` 或其他加载指令将 `obj` 对象的地址加载到寄存器。
* **计算属性偏移:** 根据属性名 "value" 计算其在对象中的偏移量。
* **加载属性值:** 使用 `LoadWord` 和计算出的偏移量从对象内存中加载属性值。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下代码片段使用 `MacroAssembler`：

```c++
MacroAssembler masm(isolate, CodeObjectRequired::kYes);
Register a0 = riscv::a0;
Register t0 = riscv::t0;

// 假设输入：寄存器 a0 中存储着一个 Smi 值 10
masm.SmiUntag(t0, a0);
// 输出：寄存器 t0 中存储着整数 10 (去除 Smi 标签)
```

在这个例子中：

* **假设输入:**  寄存器 `a0` 存储着一个 V8 的 Smi (Small Integer) 值 10。在 V8 中，Smi 为了区分于指针，会进行位操作，例如左移一位。所以 `a0` 的实际二进制表示可能是 `0x0000000000000014` (假设是 64 位架构)。
* **`masm.SmiUntag(t0, a0)`:**  `SmiUntag` 方法会去除 Smi 的标签。对于 RISC-V 64 位架构，这通常是一个右移操作。
* **输出:** 寄存器 `t0` 将存储着整数 10，其二进制表示为 `0x000000000000000a`。

**用户常见的编程错误 (使用 MacroAssembler 时):**

由于 `MacroAssembler` 涉及到直接生成汇编代码，因此容易出现一些低级错误：

1. **栈不平衡:**  `Push` 和 `Pop` 的数量不匹配会导致栈指针 `sp` 错乱，可能导致程序崩溃或数据损坏。
   ```c++
   // 错误示例：Push 多了，Pop 少了
   masm.Push(riscv::ra);
   masm.Push(riscv::fp);
   // ... 一些操作 ...
   masm.Pop(riscv::fp);
   // 没有 Pop(ra)，导致栈不平衡
   ```

2. **寄存器使用冲突:** 错误地使用了 `MacroAssembler` 保留的寄存器 (例如 `t5`, `t6`, `t3`)，或者在某个操作中覆盖了之后还需要使用的寄存器的值。
   ```c++
   // 错误示例：假设 t5 是 MacroAssembler 保留的寄存器
   masm.li(riscv::t5, 10);
   // ... MacroAssembler 内部可能也使用了 t5 ...
   // 此时 t5 的值可能被意外修改
   masm.AddWord(riscv::a0, riscv::a0, Operand(riscv::t5));
   ```

3. **条件分支错误:**  条件码设置不正确或分支目标错误会导致程序执行流程错误。
   ```c++
   // 错误示例：比较后使用了错误的反条件分支
   masm.CompareI(riscv::zero_reg, riscv::a0, Operand(0), riscv::eq);
   masm.Branch(label_not_zero, riscv::eq); // 应该使用 riscv::ne
   ```

4. **内存访问错误:**  使用了无效的内存地址或偏移量进行加载和存储操作，可能导致段错误。

5. **类型假设错误:**  例如，假设某个寄存器中存储的是 Smi，但实际上是指针，然后直接进行 Smi 操作。

**总结一下它的功能:**

`v8/src/codegen/riscv/macro-assembler-riscv.h` 定义了 V8 引擎中用于生成 RISC-V 架构机器码的 `MacroAssembler` 类。它提供了一组高级接口，封装了底层的汇编指令，使得代码生成过程更加方便和可维护。这个类包含了处理函数调用、栈帧管理、数据操作、算术运算、比较分支等各种代码生成所需的工具，并且考虑了 RISC-V 架构的特定细节。它是 V8 将 JavaScript 代码转化为可执行机器码的关键组成部分。

希望这个详细的解释能够帮助你理解 `v8/src/codegen/riscv/macro-assembler-riscv.h` 的功能。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDED_FROM_MACRO_ASSEMBLER_H
#error This header must be included via macro-assembler.h
#endif

#ifndef V8_CODEGEN_RISCV_MACRO_ASSEMBLER_RISCV_H_
#define V8_CODEGEN_RISCV_MACRO_ASSEMBLER_RISCV_H_

#include <optional>

#include "src/codegen/assembler-arch.h"
#include "src/codegen/assembler.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/register.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/execution/isolate-data.h"
#include "src/objects/tagged-index.h"

namespace v8 {
namespace internal {

#define xlen (uint8_t(sizeof(void*) * 8))
// Forward declarations.
enum class AbortReason : uint8_t;

// Reserved Register Usage Summary.
//
// Registers t5, t6, and t3 are reserved for use by the MacroAssembler.
//
// The programmer should know that the MacroAssembler may clobber these three,
// but won't touch other registers except in special cases.
//
// TODO(RISCV): Cannot find info about this ABI. We chose t6 for now.
// Per the RISC-V ABI, register t6 must be used for indirect function call
// via 'jalr t6' or 'jr t6' instructions. This is relied upon by gcc when
// trying to update gp register for position-independent-code. Whenever
// RISC-V generated code calls C code, it must be via t6 register.


// Flags used for the li macro-assembler function.
enum LiFlags {
  // If the constant value can be represented in just 16 bits, then
  // optimize the li to use a single instruction, rather than lui/ori/slli
  // sequence. A number of other optimizations that emits less than
  // maximum number of instructions exists.
  OPTIMIZE_SIZE = 0,
  // Always use 8 instructions (lui/addi/slliw sequence), even if the
  // constant
  // could be loaded with just one, so that this value is patchable later.
  CONSTANT_SIZE = 1,
  // For address loads 8 instruction are required. Used to mark
  // constant load that will be used as address without relocation
  // information. It ensures predictable code size, so specific sites
  // in code are patchable.
  ADDRESS_LOAD = 2
};

enum RAStatus { kRAHasNotBeenSaved, kRAHasBeenSaved };

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2 = no_reg,
                                   Register reg3 = no_reg,
                                   Register reg4 = no_reg,
                                   Register reg5 = no_reg,
                                   Register reg6 = no_reg);

// -----------------------------------------------------------------------------
// Static helper functions.

#if defined(V8_TARGET_LITTLE_ENDIAN)
#define SmiWordOffset(offset) (offset + kSystemPointerSize / 2)
#else
#define SmiWordOffset(offset) offset
#endif

// Generate a MemOperand for loading a field from an object.
inline MemOperand FieldMemOperand(Register object, int offset) {
  return MemOperand(object, offset - kHeapObjectTag);
}

// Generate a MemOperand for storing arguments 5..N on the stack
// when calling CallCFunction().
// TODO(plind): Currently ONLY used for O32. Should be fixed for
//              n64, and used in RegExp code, and other places
//              with more than 8 arguments.
inline MemOperand CFunctionArgumentOperand(int index) {
  DCHECK_GT(index, kCArgSlotCount);
  // Argument 5 takes the slot just past the four Arg-slots.
  int offset = (index - 5) * kSystemPointerSize + kCArgsSlotsSize;
  return MemOperand(sp, offset);
}

enum StackLimitKind { kInterruptStackLimit, kRealStackLimit };

class V8_EXPORT_PRIVATE MacroAssembler : public MacroAssemblerBase {
 public:
  using MacroAssemblerBase::MacroAssemblerBase;

  // Activation support.
  void EnterFrame(StackFrame::Type type);
  void EnterFrame(StackFrame::Type type, bool load_constant_pool_pointer_reg) {
    // Out-of-line constant pool not implemented on RISC-V.
    UNREACHABLE();
  }
  void LeaveFrame(StackFrame::Type type);

  // Generates function and stub prologue code.
  void StubPrologue(StackFrame::Type type);
  void Prologue();

  void InitializeRootRegister() {
    ExternalReference isolate_root = ExternalReference::isolate_root(isolate());
    li(kRootRegister, Operand(isolate_root));
#ifdef V8_COMPRESS_POINTERS
    LoadRootRelative(kPtrComprCageBaseRegister,
                     IsolateData::cage_base_offset());
#endif
  }

  void LoadIsolateField(const Register& rd, IsolateFieldId id);

  // Jump unconditionally to given label.
  void jmp(Label* L, Label::Distance distance = Label::kFar) {
    Branch(L, distance);
  }

  // -------------------------------------------------------------------------
  // Debugging.

  void Trap();
  void DebugBreak();
#ifdef USE_SIMULATOR
  // See src/codegen/riscv/base-constants-riscv.h DebugParameters.
  void Debug(uint32_t parameters) { break_(parameters, false); }
#endif
  // Calls Abort(msg) if the condition cc is not satisfied.
  // Use --debug_code to enable.
  void Assert(Condition cc, AbortReason reason, Register rs, Operand rt);

  void AssertJSAny(Register object, Register map_tmp, Register tmp,
                   AbortReason abort_reason);

  // Abort execution if argument is not smi nor in the main pointer
  // compression cage, enabled via --debug-code.
  void AssertSmiOrHeapObjectInMainCompressionCage(Register object)
      NOOP_UNLESS_DEBUG_CODE;

  // Like Assert(), but always enabled.
  void Check(Condition cond, AbortReason reason);

  // Like Assert(), but always enabled.
  void Check(Condition cc, AbortReason reason, Register rs, Operand rt);

  // Print a message to stdout and abort execution.
  void Abort(AbortReason msg);

  // Arguments macros.
#define COND_TYPED_ARGS Condition cond, Register r1, const Operand &r2
#define COND_ARGS cond, r1, r2

  // Cases when relocation is not needed.
#define DECLARE_NORELOC_PROTOTYPE(Name, target_type) \
  void Name(target_type target);                     \
  void Name(target_type target, COND_TYPED_ARGS);

#define DECLARE_BRANCH_PROTOTYPES(Name)   \
  DECLARE_NORELOC_PROTOTYPE(Name, Label*) \
  DECLARE_NORELOC_PROTOTYPE(Name, int32_t)

  DECLARE_BRANCH_PROTOTYPES(BranchAndLink)
  DECLARE_BRANCH_PROTOTYPES(BranchShort)

  void Branch(Label* target);
  void Branch(int32_t target);
  void BranchLong(Label* L);
  void Branch(Label* target, Condition cond, Register r1, const Operand& r2,
              Label::Distance distance = Label::kFar);
  void Branch(Label* target, Label::Distance distance) {
    Branch(target, cc_always, zero_reg, Operand(zero_reg), distance);
  }
  void Branch(int32_t target, Condition cond, Register r1, const Operand& r2,
              Label::Distance distance = Label::kFar);
  void Branch(Label* L, Condition cond, Register rj, RootIndex index,
              Label::Distance distance = Label::kFar);
#undef DECLARE_BRANCH_PROTOTYPES
#undef COND_TYPED_ARGS
#undef COND_ARGS

  void AllocateStackSpace(Register bytes) { SubWord(sp, sp, bytes); }

  void AllocateStackSpace(int bytes) {
    DCHECK_GE(bytes, 0);
    if (bytes == 0) return;
    SubWord(sp, sp, Operand(bytes));
  }

  inline void NegateBool(Register rd, Register rs) { Xor(rd, rs, 1); }

  // Compare float, if any operand is NaN, result is false except for NE
  void CompareF32(Register rd, FPUCondition cc, FPURegister cmp1,
                  FPURegister cmp2);
  // Compare double, if any operand is NaN, result is false except for NE
  void CompareF64(Register rd, FPUCondition cc, FPURegister cmp1,
                  FPURegister cmp2);
  void CompareIsNotNanF32(Register rd, FPURegister cmp1, FPURegister cmp2);
  void CompareIsNotNanF64(Register rd, FPURegister cmp1, FPURegister cmp2);
  void CompareIsNanF32(Register rd, FPURegister cmp1, FPURegister cmp2);
  void CompareIsNanF64(Register rd, FPURegister cmp1, FPURegister cmp2);

  // Floating point branches
  void BranchTrueShortF(Register rs, Label* target);
  void BranchFalseShortF(Register rs, Label* target);

  void BranchTrueF(Register rs, Label* target);
  void BranchFalseF(Register rs, Label* target);

  void CompareTaggedAndBranch(Label* label, Condition cond, Register r1,
                              const Operand& r2, bool need_link = false);
  static int InstrCountForLi64Bit(int64_t value);
  inline void LiLower32BitHelper(Register rd, Operand j);
  void li_optimized(Register rd, Operand j, LiFlags mode = OPTIMIZE_SIZE);
  // Load int32 in the rd register.
  void li(Register rd, Operand j, LiFlags mode = OPTIMIZE_SIZE);
  inline void li(Register rd, intptr_t j, LiFlags mode = OPTIMIZE_SIZE) {
    li(rd, Operand(j), mode);
  }

  inline void Move(Register output, MemOperand operand) {
    LoadWord(output, operand);
  }
  void li(Register dst, Handle<HeapObject> value,
          RelocInfo::Mode rmode = RelocInfo::FULL_EMBEDDED_OBJECT);
  void li(Register dst, ExternalReference value, LiFlags mode = OPTIMIZE_SIZE);

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
  inline void GenPCRelativeJump(Register rd, int32_t imm32) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    DCHECK(is_int32(imm32 + 0x800));
    int32_t Hi20 = ((imm32 + 0x800) >> 12);
    int32_t Lo12 = imm32 << 20 >> 20;
    auipc(rd, Hi20);  // Read PC + Hi20 into scratch.
    jr(rd, Lo12);     // jump PC + Hi20 + Lo12
  }

  inline void GenPCRelativeJumpAndLink(Register rd, int32_t imm32) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    DCHECK(is_int32(imm32 + 0x800));
    int32_t Hi20 = ((imm32 + 0x800) >> 12);
    int32_t Lo12 = imm32 << 20 >> 20;
    auipc(rd, Hi20);  // Read PC + Hi20 into scratch.
    jalr(rd, Lo12);   // jump PC + Hi20 + Lo12
  }

  // Generate a B immediate instruction with the corresponding relocation info.
  // 'offset' is the immediate to encode in the B instruction (so it is the
  // difference between the target and the PC of the instruction, divided by
  // the instruction size).
  void near_jump(int offset, RelocInfo::Mode rmode) {
    UseScratchRegisterScope temps(this);
    Register temp = temps.Acquire();
    if (!RelocInfo::IsNoInfo(rmode)) RecordRelocInfo(rmode, offset);
    GenPCRelativeJump(temp, offset);
  }
  // Generate a auipc+jalr instruction with the corresponding relocation info.
  // As for near_jump, 'offset' is the immediate to encode in the auipc+jalr
  // instruction.
  void near_call(int offset, RelocInfo::Mode rmode) {
    UseScratchRegisterScope temps(this);
    Register temp = temps.Acquire();
    if (!RelocInfo::IsNoInfo(rmode)) RecordRelocInfo(rmode, offset);
    GenPCRelativeJumpAndLink(temp, offset);
  }
  // Generate a BL immediate instruction with the corresponding relocation info
  // for the input HeapNumberRequest.
  void near_call(HeapNumberRequest request) { UNIMPLEMENTED(); }

// Jump, Call, and Ret pseudo instructions implementing inter-working.
#define COND_ARGS                              \
  Condition cond = al, Register rs = zero_reg, \
            const Operand &rt = Operand(zero_reg)

  void Jump(Register target, COND_ARGS);
  void Jump(intptr_t target, RelocInfo::Mode rmode, COND_ARGS);
  void Jump(Address target, RelocInfo::Mode rmode, COND_ARGS);
  // Deffer from li, this method save target to the memory, and then load
  // it to register use ld, it can be used in wasm jump table for concurrent
  // patching.

  // We should not use near calls or jumps for calls to external references,
  // since the code spaces are not guaranteed to be close to each other.
  bool CanUseNearCallOrJump(RelocInfo::Mode rmode) {
    return rmode != RelocInfo::EXTERNAL_REFERENCE;
  }
  static int64_t CalculateTargetOffset(Address target, RelocInfo::Mode rmode,
                                       uint8_t* pc);
  void PatchAndJump(Address target);
  void Jump(Handle<Code> code, RelocInfo::Mode rmode, COND_ARGS);
  void Jump(const ExternalReference& reference);
  void Call(Register target, COND_ARGS);
  void Call(Address target, RelocInfo::Mode rmode, COND_ARGS);
  void Call(Handle<Code> code, RelocInfo::Mode rmode = RelocInfo::CODE_TARGET,
            COND_ARGS);
  void Call(Label* target);
  void LoadAddress(
      Register dst, Label* target,
      RelocInfo::Mode rmode = RelocInfo::INTERNAL_REFERENCE_ENCODED);

  // Load the code entry point from the Code object.
  void LoadCodeInstructionStart(
      Register destination, Register code_object,
      CodeEntrypointTag tag = kDefaultCodeEntrypointTag);
  void CallCodeObject(Register code_object, CodeEntrypointTag tag);
  void JumpCodeObject(Register code_object, CodeEntrypointTag tag,
                      JumpMode jump_mode = JumpMode::kJump);

  // Convenience functions to call/jmp to the code of a JSFunction object.
  void CallJSFunction(Register function_object, uint16_t argument_count);
  void JumpJSFunction(Register function_object,
                      JumpMode jump_mode = JumpMode::kJump);

  // Load the builtin given by the Smi in |builtin| into the same
  // register.
  // Load the builtin given by the Smi in |builtin_index| into |target|.
  void LoadEntryFromBuiltinIndex(Register builtin_index, Register target);
  void LoadEntryFromBuiltin(Builtin builtin, Register destination);
  MemOperand EntryFromBuiltinAsOperand(Builtin builtin);
  void CallBuiltinByIndex(Register builtin_index, Register target);
  void CallBuiltin(Builtin builtin);
  void TailCallBuiltin(Builtin builtin);
  void TailCallBuiltin(Builtin builtin, Condition cond, Register type,
                       Operand range);

  // Generates an instruction sequence s.t. the return address points to the
  // instruction following the call.
  // The return address on the stack is used by frame iteration.
  void StoreReturnAddressAndCall(Register target);

  void BailoutIfDeoptimized();
  void CallForDeoptimization(Builtin target, int deopt_id, Label* exit,
                             DeoptimizeKind kind, Label* ret,
                             Label* jump_deoptimization_entry_label);

  void Ret(COND_ARGS);

  // Emit code to discard a non-negative number of pointer-sized elements
  // from the stack, clobbering only the sp register.
  void Drop(int count, Condition cond = cc_always, Register reg = no_reg,
            const Operand& op = Operand(no_reg));

  // Trivial case of DropAndRet that only emits 2 instructions.
  void DropAndRet(int drop);

  void DropAndRet(int drop, Condition cond, Register reg, const Operand& op);

  void push(Register src) {
    AddWord(sp, sp, Operand(-kSystemPointerSize));
    StoreWord(src, MemOperand(sp, 0));
  }
  void Push(Register src) { push(src); }
  void Push(Handle<HeapObject> handle);
  void Push(Tagged<Smi> smi);
  void Push(Tagged<TaggedIndex> index);

 private:
  template <typename... Rs>
  void push_helper(Register r, Rs... rs) {
    StoreWord(r, MemOperand(sp, sizeof...(rs) * kSystemPointerSize));
    push_helper(rs...);
  }

  template <>
  void push_helper(Register r) {
    StoreWord(r, MemOperand(sp, 0));
  }

 public:
  // Push a number of registers. The leftmost register first (to the highest
  // address).
  template <typename... Rs>
  void Push(Register r, Rs... rs) {
    SubWord(sp, sp, (sizeof...(rs) + 1) * kSystemPointerSize);
    push_helper(r, rs...);
  }

  void Push(Register src, Condition cond, Register tst1, Register tst2) {
    // Since we don't have conditional execution we use a Branch.
    Branch(3, cond, tst1, Operand(tst2));
    SubWord(sp, sp, Operand(kSystemPointerSize));
    StoreWord(src, MemOperand(sp, 0));
  }

  enum PushArrayOrder { kNormal, kReverse };
  void PushArray(Register array, Register size, PushArrayOrder order = kNormal);

  // Caution: if {value} is a 32-bit negative int, it should be sign-extended
  // to 64-bit before calling this function.
  void Switch(Register scratch, Register value, int case_value_base,
              Label** labels, int num_labels);

  void MaybeSaveRegisters(RegList registers);
  void MaybeRestoreRegisters(RegList registers);

  void CallEphemeronKeyBarrier(Register object, Operand offset,
                               SaveFPRegsMode fp_mode);
  void CallIndirectPointerBarrier(Register object, Operand offset,
                                  SaveFPRegsMode fp_mode,
                                  IndirectPointerTag tag);
  void CallRecordWriteStubSaveRegisters(
      Register object, Operand offset, SaveFPRegsMode fp_mode,
      StubCallMode mode = StubCallMode::kCallBuiltinPointer);
  void CallRecordWriteStub(
      Register object, Register slot_address, SaveFPRegsMode fp_mode,
      StubCallMode mode = StubCallMode::kCallBuiltinPointer);

  // For a given |object| and |offset|:
  //   - Move |object| to |dst_object|.
  //   - Compute the address of the slot pointed to by |offset| in |object| and
  //     write it to |dst_slot|.
  // This method makes sure |object| and |offset| are allowed to overlap with
  // the destination registers.
  void MoveObjectAndSlot(Register dst_object, Register dst_slot,
                         Register object, Operand offset);

  // These PushAll/PopAll respect the order of the registers in the stack from
  // low index to high.
  void PushAll(RegList registers) {
    if (registers.is_empty()) return;
    ASM_CODE_COMMENT(this);
    // TODO(victorgomes): pushes/pops registers in the opposite order
    // as expected by Maglev frame. Consider massaging Maglev to accept this
    // order instead.
    int16_t num_to_push = registers.Count();
    int16_t stack_offset = num_to_push * kSystemPointerSize;

    SubWord(sp, sp, Operand(stack_offset));
    for (int16_t i = 0; i < kNumRegisters; i++) {
      if ((registers.bits() & (1 << i)) != 0) {
        stack_offset -= kSystemPointerSize;
        StoreWord(Register::from_code(i), MemOperand(sp, stack_offset));
      }
    }
  }

  void PopAll(RegList registers) {
    if (registers.is_empty()) return;
    int16_t stack_offset = 0;
    for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
      if ((registers.bits() & (1 << i)) != 0) {
        LoadWord(Register::from_code(i), MemOperand(sp, stack_offset));
        stack_offset += kSystemPointerSize;
      }
    }
    addi(sp, sp, stack_offset);
  }

  void PushAll(DoubleRegList registers, int stack_slot_size = kDoubleSize) {
    DCHECK_EQ(stack_slot_size, kDoubleSize);
    int16_t num_to_push = registers.Count();
    int16_t stack_offset = num_to_push * kDoubleSize;

    SubWord(sp, sp, Operand(stack_offset));
    for (int16_t i = 0; i < kNumRegisters; i++) {
      if ((registers.bits() & (1 << i)) != 0) {
        stack_offset -= kDoubleSize;
        StoreDouble(FPURegister::from_code(i), MemOperand(sp, stack_offset));
      }
    }
  }

  void PopAll(DoubleRegList registers, int stack_slot_size = kDoubleSize) {
    DCHECK_EQ(stack_slot_size, kDoubleSize);
    int16_t stack_offset = 0;
    for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
      if ((registers.bits() & (1 << i)) != 0) {
        LoadDouble(FPURegister::from_code(i), MemOperand(sp, stack_offset));
        stack_offset += kDoubleSize;
      }
    }
    addi(sp, sp, stack_offset);
  }

  // Push multiple registers on the stack.
  // Registers are saved in numerical order, with higher numbered registers
  // saved in higher memory addresses.
  void MultiPush(RegList regs);
  void MultiPushFPU(DoubleRegList regs);

  // Calculate how much stack space (in bytes) are required to store caller
  // registers excluding those specified in the arguments.
  int RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                      Register exclusion1 = no_reg,
                                      Register exclusion2 = no_reg,
                                      Register exclusion3 = no_reg) const;

  // Push caller saved registers on the stack, and return the number of bytes
  // stack pointer is adjusted.
  int PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1 = no_reg,
                      Register exclusion2 = no_reg,
                      Register exclusion3 = no_reg);
  // Restore caller saved registers from the stack, and return the number of
  // bytes stack pointer is adjusted.
  int PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1 = no_reg,
                     Register exclusion2 = no_reg,
                     Register exclusion3 = no_reg);

  void pop(Register dst) {
    LoadWord(dst, MemOperand(sp, 0));
    AddWord(sp, sp, Operand(kSystemPointerSize));
  }
  void Pop(Register dst) { pop(dst); }

 private:
  template <typename... Rs>
  void pop_helper(Register r, Rs... rs) {
    pop_helper(rs...);
    LoadWord(r, MemOperand(sp, sizeof...(rs) * kSystemPointerSize));
  }

  template <>
  void pop_helper(Register r) {
    LoadWord(r, MemOperand(sp, 0));
  }

 public:
  // Pop a number of registers. The leftmost register last (from the highest
  // address).
  template <typename... Rs>
  void Pop(Register r, Rs... rs) {
    pop_helper(r, rs...);
    AddWord(sp, sp, (sizeof...(rs) + 1) * kSystemPointerSize);
  }

  void Pop(uint32_t count = 1) {
    AddWord(sp, sp, Operand(count * kSystemPointerSize));
  }

  // Pops multiple values from the stack and load them in the
  // registers specified in regs. Pop order is the opposite as in MultiPush.
  void MultiPop(RegList regs);
  void MultiPopFPU(DoubleRegList regs);

#define DEFINE_INSTRUCTION(instr)                          \
  void instr(Register rd, Register rs, const Operand& rt); \
  void instr(Register rd, Register rs, Register rt) {      \
    instr(rd, rs, Operand(rt));                            \
  }                                                        \
  void instr(Register rs, Register rt, int32_t j) { instr(rs, rt, Operand(j)); }

#define DEFINE_INSTRUCTION2(instr)                                 \
  void instr(Register rs, const Operand& rt);                      \
  void instr(Register rs, Register rt) { instr(rs, Operand(rt)); } \
  void instr(Register rs, int32_t j) { instr(rs, Operand(j)); }

#define DEFINE_INSTRUCTION3(instr) void instr(Register rd, intptr_t imm);

  DEFINE_INSTRUCTION(AddWord)
  DEFINE_INSTRUCTION(SubWord)
  DEFINE_INSTRUCTION(SllWord)
  DEFINE_INSTRUCTION(SrlWord)
  DEFINE_INSTRUCTION(SraWord)
#if V8_TARGET_ARCH_RISCV64
  DEFINE_INSTRUCTION(Add32)
  DEFINE_INSTRUCTION(Add64)
  DEFINE_INSTRUCTION(Div32)
  DEFINE_INSTRUCTION(Divu32)
  DEFINE_INSTRUCTION(Divu64)
  DEFINE_INSTRUCTION(Mod32)
  DEFINE_INSTRUCTION(Modu32)
  DEFINE_INSTRUCTION(Div64)
  DEFINE_INSTRUCTION(Sub32)
  DEFINE_INSTRUCTION(Sub64)
  DEFINE_INSTRUCTION(Mod64)
  DEFINE_INSTRUCTION(Modu64)
  DEFINE_INSTRUCTION(Mul32)
  DEFINE_INSTRUCTION(Mulh32)
  DEFINE_INSTRUCTION(Mul64)
  DEFINE_INSTRUCTION(Mulh64)
  DEFINE_INSTRUCTION(Mulhu64)
  DEFINE_INSTRUCTION2(Div32)
  DEFINE_INSTRUCTION2(Div64)
  DEFINE_INSTRUCTION2(Divu32)
  DEFINE_INSTRUCTION2(Divu64)
  DEFINE_INSTRUCTION(Sll64)
  DEFINE_INSTRUCTION(Sra64)
  DEFINE_INSTRUCTION(Srl64)
  DEFINE_INSTRUCTION(Dror)
#elif V8_TARGET_ARCH_RISCV32
  DEFINE_INSTRUCTION(Add32)
  DEFINE_INSTRUCTION(Div)
  DEFINE_INSTRUCTION(Divu)
  DEFINE_INSTRUCTION(Mod)
  DEFINE_INSTRUCTION(Modu)
  DEFINE_INSTRUCTION(Sub32)
  DEFINE_INSTRUCTION(Mul)
  DEFINE_INSTRUCTION(Mul32)
  DEFINE_INSTRUCTION(Mulh)
  DEFINE_INSTRUCTION2(Div)
  DEFINE_INSTRUCTION2(Divu)
#endif
  DEFINE_INSTRUCTION(And)
  DEFINE_INSTRUCTION(Or)
  DEFINE_INSTRUCTION(Xor)
  DEFINE_INSTRUCTION(Nor)
  DEFINE_INSTRUCTION2(Neg)

  DEFINE_INSTRUCTION(Slt)
  DEFINE_INSTRUCTION(Sltu)
  DEFINE_INSTRUCTION(Sle)
  DEFINE_INSTRUCTION(Sleu)
  DEFINE_INSTRUCTION(Sgt)
  DEFINE_INSTRUCTION(Sgtu)
  DEFINE_INSTRUCTION(Sge)
  DEFINE_INSTRUCTION(Sgeu)
  DEFINE_INSTRUCTION(Seq)
  DEFINE_INSTRUCTION(Sne)
  DEFINE_INSTRUCTION(Sll32)
  DEFINE_INSTRUCTION(Sra32)
  DEFINE_INSTRUCTION(Srl32)

  DEFINE_INSTRUCTION2(Seqz)
  DEFINE_INSTRUCTION2(Snez)

  DEFINE_INSTRUCTION(Ror)

  DEFINE_INSTRUCTION3(Li)
  DEFINE_INSTRUCTION2(Mv)

#undef DEFINE_INSTRUCTION
#undef DEFINE_INSTRUCTION2
#undef DEFINE_INSTRUCTION3

  void Amosub_w(bool aq, bool rl, Register rd, Register rs1, Register rs2) {
    UseScratchRegisterScope temps(this);
    Register temp = temps.Acquire();
    sub(temp, zero_reg, rs2);
    amoadd_w(aq, rl, rd, rs1, temp);
  }

  // Convert smi to word-size sign-extended value.
  void SmiUntag(Register dst, const MemOperand& src);
  void SmiUntag(Register dst, Register src) {
#if V8_TARGET_ARCH_RISCV64
    DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      sraiw(dst, src, kSmiShift);
    } else {
      srai(dst, src, kSmiShift);
    }
#elif V8_TARGET_ARCH_RISCV32
    DCHECK(SmiValuesAre31Bits());
    srai(dst, src, kSmiShift);
#endif
  }

  void SmiUntag(Register reg) { SmiUntag(reg, reg); }
  // Convert smi to 32-bit value.
  void SmiToInt32(Register smi);
  void SmiToInt32(Register dst, Register smi);

  // Enabled via --debug-code.
  void AssertNotSmi(Register object,
                    AbortReason reason = AbortReason::kOperandIsASmi);
  void AssertSmi(Register object,
                 AbortReason reason = AbortReason::kOperandIsASmi);

  // Abort execution if a 64 bit register containing a 32 bit payload does
  // not have zeros in the top 32 bits, enabled via --debug-code.
  void AssertZeroExtended(Register int32_register) NOOP_UNLESS_DEBUG_CODE;

  int CalculateStackPassedDWords(int num_gp_arguments, int num_fp_arguments);

  // Before calling a C-function from generated code, align arguments on stack.
  // After aligning the frame, non-register arguments must be stored on the
  // stack, using helper: CFunctionArgumentOperand().
  // The argument count assumes all arguments are word sized.
  // Some compilers/platforms require the stack to be aligned when calling
  // C++ code.
  // Needs a scratch register to do some arithmetic. This register will be
  // trashed.
  void PrepareCallCFunction(int num_reg_arguments, int num_double_registers,
                            Register scratch);
  void PrepareCallCFunction(int num_reg_arguments, Register scratch);

  // Arguments 1-8 are placed in registers a0 through a7 respectively.
  // Arguments 9..n are stored to stack

  // Calls a C function and cleans up the space for arguments allocated
  // by PrepareCallCFunction. The called function is not allowed to trigger a
  // garbage collection, since that might move the code and invalidate the
  // return address (unless this is somehow accounted for by the called
  // function).
  int CallCFunction(
      ExternalReference function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  int CallCFunction(
      Register function, int num_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  int CallCFunction(
      ExternalReference function, int num_reg_arguments,
      int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  int CallCFunction(
      Register function, int num_reg_arguments, int num_double_arguments,
      SetIsolateDataSlots set_isolate_data_slots = SetIsolateDataSlots::kYes,
      Label* return_location = nullptr);
  void MovFromFloatResult(DoubleRegister dst);
  void MovFromFloatParameter(DoubleRegister dst);

  // These functions abstract parameter passing for the three different ways
  // we call C functions from generated code.
  void MovToFloatParameter(DoubleRegister src);
  void MovToFloatParameters(DoubleRegister src1, DoubleRegister src2);
  void MovToFloatResult(DoubleRegister src);

  // See comments at the beginning of Builtins::Generate_CEntry.
  inline void PrepareCEntryArgs(int num_args) { li(a0, num_args); }
  inline void PrepareCEntryFunction(const ExternalReference& ref) {
    li(a1, ref);
  }

  void CheckPageFlag(Register object, int mask, Condition cc,
                     Label* condition_met);

  void CheckPageFlag(const Register& object, Register scratch, int mask,
                     Condition cc, Label* condition_met) {
    CheckPageFlag(object, mask, cc, condition_met);
  }
#undef COND_ARGS

  // Performs a truncating conversion of a floating point number as used by
  // the JS bitwise operations. See ECMA-262 9.5: ToInt32.
  // Exits with 'result' holding the answer.
  void TruncateDoubleToI(Isolate* isolate, Zone* zone, Register result,
                         DoubleRegister double_input, StubCallMode stub_mode);

  void CompareI(Register rd, Register rs, const Operand& rt, Condition cond);

  void LoadZeroIfConditionNotZero(Register dest, Register condition);
  void LoadZeroIfConditionZero(Register dest, Register condition);

  void SignExtendByte(Register rd, Register rs) {
    if (CpuFeatures::IsSupported(ZBB)) {
      sextb(rd, rs);
    } else {
      slli(rd, rs, xlen - 8);
      srai(rd, rd, xlen - 8);
    }
  }

  void SignExtendShort(Register rd, Register rs) {
    if (CpuFeatures::IsSupported(ZBB)) {
      sexth(rd, rs);
    } else {
      slli(rd, rs, xlen - 16);
      srai(rd, rd, xlen - 16);
    }
  }

  void Clz32(Register rd, Register rs);
  void Ctz32(Register rd, Register rs);
  void Popcnt32(Register rd, Register rs, Register scratch);

#if V8_TARGET_ARCH_RISCV64
  void SignExtendWord(Register rd, Register rs) { sext_w(rd, rs); }
  void ZeroExtendWord(Register rd, Register rs) {
    if (CpuFeatures::IsSupported(ZBA)) {
      zextw(rd, rs);
    } else {
      slli(rd, rs, 32);
      srli(rd, rd, 32);
    }
  }
  void Popcnt64(Register rd, Register rs, Register scratch);
  void Ctz64(Register rd, Register rs);
  void Clz64(Register rd, Register rs);
#elif V8_TARGET_ARCH_RISCV32
  void AddPair(Register dst_low, Register dst_high, Register left_low,
               Register left_high, Register right_low, Register right_high,
               Register scratch1, Register scratch2);

  void SubPair(Register dst_low, Register dst_high, Register left_low,
               Register left_high, Register right_low, Register right_high,
               Register scratch1, Register scratch2);

  void AndPair(Register dst_low, Register dst_high, Register left_low,
               Register left_high, Register right_low, Register right_high);

  void OrPair(Register dst_low, Register dst_high, Register left_low,
              Register left_high, Register right_low, Register right_high);

  void XorPair(Register dst_low, Register dst_high, Register left_low,
               Register left_high, Register right_low, Register right_high);

  void MulPair(Register dst_low, Register dst_high, Register left_low,
               Register left_high, Register right_low, Register right_high,
               Register scratch1, Register scratch2);

  void ShlPair(Register dst_low, Register dst_high, Register src_low,
               Register src_high, Register shift, Register scratch1,
               Register scratch2);
  void ShlPair(Register dst_low, Register dst_high, Register src_low,
               Register src_high, int32_t shift, Register scratch1,
               Register scratch2);

  void ShrPair(Register dst_low, Register dst_high, Register src_low,
               Register src_high, Register shift, Register scratch1,
               Register scratch2);

  void ShrPair(Register dst_low, Register dst_high, Register src_low,
               Register src_high, int32_t shift, Register scratch1,
               Register scratch2);

  void SarPair(Register dst_low, Register dst_high, Register src_low,
               Register src_high, Register shift, Register scratch1,
               Register scratch2);
  void SarPair(Register dst_low, Register dst_high, Register src_low,
               Register src_high, int32_t shift, Register scratch1,
               Register scratch2);
#endif

  // Bit field starts at bit pos and extending for size bits is extracted from
  // rs and stored zero/sign-extended and right-justifi
"""


```