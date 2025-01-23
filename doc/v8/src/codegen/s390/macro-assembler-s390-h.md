Response:
The user wants a summary of the functionality of the C++ header file `v8/src/codegen/s390/macro-assembler-s390.h`.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The filename `macro-assembler-s390.h` strongly suggests that this file defines a macro assembler for the s390 architecture. Macro assemblers provide higher-level abstractions over raw assembly instructions.

2. **Scan for key classes and functions:** Look for class declarations and prominent function names. The `MacroAssembler` class is the central element. Its public methods likely represent the available macro instructions.

3. **Categorize functionalities:** Group the identified methods into logical categories based on their names and parameters. Common categories for assemblers include:
    * Arithmetic operations (add, subtract, multiply, divide)
    * Logical operations (and, or, xor, not, shifts)
    * Comparison operations (cmp)
    * Memory access (load, store)
    * Control flow (jump, call, return, branch)
    * Stack manipulation (push, pop, drop)
    * Function calls (builtins, code objects)
    * Floating-point operations
    * Atomic operations
    * SIMD (vector) operations
    * Utilities (like loading constants or roots)

4. **Elaborate on each category:** Briefly explain what each category of functions does. For instance, "Arithmetic Operations" involve adding, subtracting, multiplying, and dividing values in registers or memory.

5. **Check for architecture-specific details:** Notice the "s390" in the filename. This implies the macros are tailored for the IBM z/Architecture. Highlight this.

6. **Address the `.tq` check:** The prompt specifically asks about the `.tq` extension and Torque. Confirm that since the file ends in `.h`, it's a C++ header and not a Torque file. Explain the role of Torque in V8 for context.

7. **Relate to JavaScript (if applicable):**  Consider if the operations exposed by the macro assembler have direct counterparts in JavaScript. Operations like arithmetic, comparisons, and function calls are fundamental and have clear relationships. Provide JavaScript examples for these core functionalities.

8. **Consider code logic and examples:** The prompt asks for code logic推理. While this header doesn't contain *implementation* logic, the *interface* it defines dictates how code can be generated. Illustrate with a simple example of adding two numbers, showing the hypothetical input (register values) and the expected output (result in a register).

9. **Think about common programming errors:**  Relate the assembler functions to common errors. For example, incorrect stack management (push/pop imbalances) or type mismatches when loading/storing data are common low-level issues.

10. **Formulate the summary:** Combine the categorized functionalities, architectural details, and responses to specific prompt questions into a concise summary. Emphasize that it provides a higher-level interface for generating s390 assembly code within the V8 engine.

11. **Review and refine:** Ensure the summary is clear, accurate, and addresses all parts of the prompt. Check for any technical jargon that needs clarification. For example, explaining what "builtins" and "code objects" are in the V8 context can be helpful.
这是 `v8/src/codegen/s390/macro-assembler-s390.h` 文件的第一部分，它是一个 V8 引擎中用于 s390 架构的**宏汇编器**的头文件。

**功能归纳：**

这个头文件定义了 `MacroAssembler` 类，它为在 s390 架构上生成机器码提供了一组高级抽象和便捷方法，简化了直接编写底层汇编代码的过程。 它的主要功能可以归纳为以下几点：

1. **提供了一系列宏指令：**  `MacroAssembler` 类封装了常用的 s390 汇编指令，并提供更高级的接口，例如 `CallBuiltin`、`TailCallBuiltin`、`Move`、`AddS32` 等。这些宏指令隐藏了底层指令的复杂性，使代码生成更加简洁和易读。

2. **支持常见操作：**  它包含了执行各种操作的方法，涵盖了算术运算（加减乘除）、逻辑运算（与或非异或）、位操作（移位、旋转）、比较、加载和存储数据、浮点数操作、调用内置函数、跳转和返回等。

3. **处理 V8 内部概念：**  该文件中的宏指令也与 V8 引擎的内部概念紧密相关，例如加载 Root 对象、访问外部引用、处理 Smi (Small Integer) 和 HeapObject、加载 Map 等。

4. **管理栈帧：**  提供 `Push` 和 `Pop` 等方法来管理栈上的数据，方便函数调用和局部变量的管理。同时，也提供了批量压栈和出栈的指令 (`MultiPush`, `MultiPop`)。

5. **支持原子操作：**  包含了原子比较交换和原子交换等操作，用于实现多线程环境下的同步。

6. **支持 SIMD 指令：**  提供加载和存储 SIMD 寄存器 (`V128`) 的指令，以及一些 SIMD 操作的宏。

7. **提供辅助函数：**  包含一些静态辅助函数，如 `FieldMemOperand` 用于生成访问对象字段的内存操作数。

**关于 .tq 结尾：**

因为 `v8/src/codegen/s390/macro-assembler-s390.h` 以 `.h` 结尾，所以它是一个 C++ 头文件，而不是 V8 Torque 源代码。 Torque 文件通常以 `.tq` 结尾，用于定义类型和生成底层的 C++ 代码。

**与 JavaScript 的关系：**

`MacroAssembler` 生成的机器码最终会执行 JavaScript 代码。V8 引擎在编译和执行 JavaScript 代码的过程中，会使用 `MacroAssembler` 来生成特定于 s390 架构的机器指令。 例如，JavaScript 中的算术运算、函数调用、对象属性访问等操作，在底层都会通过 `MacroAssembler` 生成相应的 s390 汇编指令。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当 V8 编译执行上述 JavaScript 代码时，对于 `a + b` 这个加法操作，`MacroAssembler` (在 s390 架构上) 可能会生成类似以下的汇编指令（这是一个简化的例子）：

```assembly
// 假设 a 的值在寄存器 r3，b 的值在寄存器 r4
  adds r5, r3, r4  // 将 r3 和 r4 的值相加，结果存入 r5
  // ... 其他指令，例如将 r5 的值作为返回值处理
```

`MacroAssembler` 提供的 `AddS32` 或类似的宏指令，就在 V8 内部被用来生成 `adds` 这样的底层汇编指令。

**代码逻辑推理示例：**

**假设输入：**

* 寄存器 `r3` 的值为整数 5。
* 寄存器 `r4` 的值为整数 3。

**`MacroAssembler` 代码片段 (伪代码)：**

```c++
  // ...
  Register result_reg = r5;
  Register input_reg1 = r3;
  Register input_reg2 = r4;

  masm->AddS32(result_reg, input_reg1, input_reg2);
  // ...
```

**输出：**

* 执行 `masm->AddS32(result_reg, input_reg1, input_reg2);` 后，寄存器 `r5` 的值将变为 8 (5 + 3)。

**用户常见的编程错误：**

在使用宏汇编器时，用户可能犯的编程错误包括：

1. **栈不平衡：** `Push` 和 `Pop` 的数量不匹配，导致栈指针错误，可能引起程序崩溃。

   ```c++
   // 错误示例：Push 多于 Pop
   masm->Push(r3);
   masm->Push(r4);
   masm->Pop(r3);
   // 缺少一个 Pop
   ```

2. **寄存器分配错误：**  错误地使用了被其他操作占用的寄存器，导致数据被覆盖。虽然 `MacroAssembler` 提供了 `GetRegisterThatIsNotOneOf` 等辅助函数来避免这种情况，但开发者仍然需要注意寄存器的使用。

3. **内存操作错误：**  访问了错误的内存地址，例如使用了错误的偏移量或基址寄存器，导致数据读取或写入错误。

4. **条件码使用错误：**  在条件跳转或条件执行指令中，使用了错误的条件码，导致程序执行流程错误。

总而言之，`v8/src/codegen/s390/macro-assembler-s390.h` 是 V8 引擎中负责为 s390 架构生成高效机器码的关键组件，它提供了一组高级接口来简化汇编代码的编写，并与 V8 的内部机制紧密结合。

### 提示词
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.h以.tq结尾，那它是个v8 torque源代码，
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

#ifndef V8_CODEGEN_S390_MACRO_ASSEMBLER_S390_H_
#define V8_CODEGEN_S390_MACRO_ASSEMBLER_S390_H_

#include "src/base/platform/platform.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/s390/assembler-s390.h"
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

// Generate a MemOperand for loading a field from an object.
inline MemOperand FieldMemOperand(Register object, Register index, int offset) {
  return MemOperand(object, index, offset - kHeapObjectTag);
}

enum LinkRegisterStatus { kLRHasNotBeenSaved, kLRHasBeenSaved };

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2 = no_reg,
                                   Register reg3 = no_reg,
                                   Register reg4 = no_reg,
                                   Register reg5 = no_reg,
                                   Register reg6 = no_reg);

class V8_EXPORT_PRIVATE MacroAssembler : public MacroAssemblerBase {
 public:
  using MacroAssemblerBase::MacroAssemblerBase;

  void CallBuiltin(Builtin builtin, Condition cond = al);
  void TailCallBuiltin(Builtin builtin, Condition cond = al);
  void AtomicCmpExchangeHelper(Register addr, Register output,
                               Register old_value, Register new_value,
                               int start, int end, int shift_amount, int offset,
                               Register temp0, Register temp1);
  void AtomicCmpExchangeU8(Register addr, Register output, Register old_value,
                           Register new_value, Register temp0, Register temp1);
  void AtomicCmpExchangeU16(Register addr, Register output, Register old_value,
                            Register new_value, Register temp0, Register temp1);
  void AtomicExchangeHelper(Register addr, Register value, Register output,
                            int start, int end, int shift_amount, int offset,
                            Register scratch);
  void AtomicExchangeU8(Register addr, Register value, Register output,
                        Register scratch);
  void AtomicExchangeU16(Register addr, Register value, Register output,
                         Register scratch);

  void DoubleMax(DoubleRegister result_reg, DoubleRegister left_reg,
                 DoubleRegister right_reg);
  void DoubleMin(DoubleRegister result_reg, DoubleRegister left_reg,
                 DoubleRegister right_reg);
  void FloatMax(DoubleRegister result_reg, DoubleRegister left_reg,
                DoubleRegister right_reg);
  void FloatMin(DoubleRegister result_reg, DoubleRegister left_reg,
                DoubleRegister right_reg);
  void CeilF32(DoubleRegister dst, DoubleRegister src);
  void CeilF64(DoubleRegister dst, DoubleRegister src);
  void FloorF32(DoubleRegister dst, DoubleRegister src);
  void FloorF64(DoubleRegister dst, DoubleRegister src);
  void TruncF32(DoubleRegister dst, DoubleRegister src);
  void TruncF64(DoubleRegister dst, DoubleRegister src);
  void NearestIntF32(DoubleRegister dst, DoubleRegister src);
  void NearestIntF64(DoubleRegister dst, DoubleRegister src);

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
  void Jump(Register target, Condition cond = al);
  void Jump(Address target, RelocInfo::Mode rmode, Condition cond = al);
  void Jump(Handle<Code> code, RelocInfo::Mode rmode, Condition cond = al);
  void Jump(const ExternalReference& reference);
  // Jump the register contains a smi.
  inline void JumpIfSmi(Register value, Label* smi_label) {
    TestIfSmi(value);
    beq(smi_label /*, cr0*/);  // branch if SMI
  }
  Condition CheckSmi(Register src) {
    TestIfSmi(src);
    return eq;
  }

  void JumpIfEqual(Register x, int32_t y, Label* dest);
  void JumpIfLessThan(Register x, int32_t y, Label* dest);

  // Caution: if {reg} is a 32-bit negative int, it should be sign-extended to
  // 64-bit before calling this function.
  void Switch(Register scrach, Register reg, int case_base_value,
              Label** labels, int num_labels);

  void JumpIfCodeIsMarkedForDeoptimization(Register code, Register scratch,
                                           Label* if_marked_for_deoptimization);

  void JumpIfCodeIsTurbofanned(Register code, Register scratch,
                               Label* if_turbofanned);
  void LoadMap(Register destination, Register object);
  void LoadCompressedMap(Register destination, Register object);

  void LoadFeedbackVector(Register dst, Register closure, Register scratch,
                          Label* fbv_undef);

  void Call(Register target);
  void Call(Address target, RelocInfo::Mode rmode, Condition cond = al);
  void Call(Handle<Code> code, RelocInfo::Mode rmode = RelocInfo::CODE_TARGET,
            Condition cond = al);
  void Ret() { b(r14); }
  void Ret(Condition cond) { b(cond, r14); }

  void BailoutIfDeoptimized(Register scratch);
  void CallForDeoptimization(Builtin target, int deopt_id, Label* exit,
                             DeoptimizeKind kind, Label* ret,
                             Label* jump_deoptimization_entry_label);

  // Emit code to discard a non-negative number of pointer-sized elements
  // from the stack, clobbering only the sp register.
  void Drop(int count);
  void Drop(Register count, Register scratch = r0);

  void Ret(int drop) {
    Drop(drop);
    Ret();
  }

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

  // Register move. May do nothing if the registers are identical.
  void Move(Register dst, Tagged<Smi> smi) { LoadSmiLiteral(dst, smi); }
  void Move(Register dst, Handle<HeapObject> source,
            RelocInfo::Mode rmode = RelocInfo::FULL_EMBEDDED_OBJECT);
  void Move(Register dst, ExternalReference reference);
  void LoadIsolateField(Register dst, IsolateFieldId id);
  void Move(Register dst, const MemOperand& src);
  void Move(Register dst, Register src, Condition cond = al);
  void Move(DoubleRegister dst, DoubleRegister src);

  void MoveChar(const MemOperand& opnd1, const MemOperand& opnd2,
                const Operand& length);

  void CompareLogicalChar(const MemOperand& opnd1, const MemOperand& opnd2,
                          const Operand& length);

  void ExclusiveOrChar(const MemOperand& opnd1, const MemOperand& opnd2,
                       const Operand& length);

  void RotateInsertSelectBits(Register dst, Register src,
                              const Operand& startBit, const Operand& endBit,
                              const Operand& shiftAmt, bool zeroBits);

  void BranchRelativeOnIdxHighP(Register dst, Register inc, Label* L);

  void MaybeSaveRegisters(RegList registers);
  void MaybeRestoreRegisters(RegList registers);

  void CallEphemeronKeyBarrier(Register object, Register slot_address,
                               SaveFPRegsMode fp_mode);

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

  void MultiPushV128(DoubleRegList dregs, Register scratch,
                     Register location = sp);
  void MultiPopV128(DoubleRegList dregs, Register scratch,
                    Register location = sp);

  void MultiPushF64OrV128(DoubleRegList dregs, Register scratch,
                          Register location = sp);
  void MultiPopF64OrV128(DoubleRegList dregs, Register scratch,
                         Register location = sp);
  void PushAll(RegList registers);
  void PopAll(RegList registers);
  void PushAll(DoubleRegList registers, int stack_slot_size = kDoubleSize);
  void PopAll(DoubleRegList registers, int stack_slot_size = kDoubleSize);

  // Calculate how much stack space (in bytes) are required to store caller
  // registers excluding those specified in the arguments.
  int RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                      Register exclusion1 = no_reg,
                                      Register exclusion2 = no_reg,
                                      Register exclusion3 = no_reg) const;

  // Push caller saved registers on the stack, and return the number of bytes
  // stack pointer is adjusted.
  int PushCallerSaved(SaveFPRegsMode fp_mode, Register scratch,
                      Register exclusion1 = no_reg,
                      Register exclusion2 = no_reg,
                      Register exclusion3 = no_reg);
  // Restore caller saved registers from the stack, and return the number of
  // bytes stack pointer is adjusted.
  int PopCallerSaved(SaveFPRegsMode fp_mode, Register scratch,
                     Register exclusion1 = no_reg, Register exclusion2 = no_reg,
                     Register exclusion3 = no_reg);

  // Load an object from the root table.
  void LoadRoot(Register destination, RootIndex index) override {
    LoadRoot(destination, index, al);
  }
  void LoadRoot(Register destination, RootIndex index, Condition cond);
  void LoadTaggedRoot(Register destination, RootIndex index);
  //--------------------------------------------------------------------------
  // S390 Macro Assemblers for Instructions
  //--------------------------------------------------------------------------

  // Arithmetic Operations

  // Add (Register - Immediate)
  void AddS32(Register dst, const Operand& imm);
  void AddS64(Register dst, const Operand& imm);
  void AddS32(Register dst, Register src, const Operand& imm);
  void AddS64(Register dst, Register src, const Operand& imm);
  void AddS32(Register dst, Register src, int32_t imm);
  void AddS64(Register dst, Register src, int32_t imm);

  // Add (Register - Register)
  void AddS32(Register dst, Register src);
  void AddS64(Register dst, Register src);
  void AddS32(Register dst, Register src1, Register src2);
  void AddS64(Register dst, Register src1, Register src2);

  // Add (Register - Mem)
  void AddS32(Register dst, const MemOperand& opnd);
  void AddS64(Register dst, const MemOperand& opnd);

  // Add (Mem - Immediate)
  void AddS32(const MemOperand& opnd, const Operand& imm);
  void AddS64(const MemOperand& opnd, const Operand& imm);

  // Add Logical (Register - Register)
  void AddU32(Register dst, Register src1, Register src2);

  // Add Logical (Register - Immediate)
  void AddU32(Register dst, const Operand& imm);
  void AddU64(Register dst, const Operand& imm);
  void AddU64(Register dst, int imm) { AddU64(dst, Operand(imm)); }
  void AddU64(Register dst, Register src1, Register src2);
  void AddU64(Register dst, Register src) { algr(dst, src); }

  // Add Logical (Register - Mem)
  void AddU32(Register dst, const MemOperand& opnd);
  void AddU64(Register dst, const MemOperand& opnd);

  // Subtract (Register - Immediate)
  void SubS32(Register dst, const Operand& imm);
  void SubS64(Register dst, const Operand& imm);
  void SubS32(Register dst, Register src, const Operand& imm);
  void SubS64(Register dst, Register src, const Operand& imm);
  void SubS32(Register dst, Register src, int32_t imm);
  void SubS64(Register dst, Register src, int32_t imm);

  // Subtract (Register - Register)
  void SubS32(Register dst, Register src);
  void SubS64(Register dst, Register src);
  void SubS32(Register dst, Register src1, Register src2);
  void SubS64(Register dst, Register src1, Register src2);

  // Subtract (Register - Mem)
  void SubS32(Register dst, const MemOperand& opnd);
  void SubS64(Register dst, const MemOperand& opnd);
  void LoadAndSub32(Register dst, Register src, const MemOperand& opnd);
  void LoadAndSub64(Register dst, Register src, const MemOperand& opnd);

  // Subtract Logical (Register - Mem)
  void SubU32(Register dst, const MemOperand& opnd);
  void SubU64(Register dst, const MemOperand& opnd);
  // Subtract Logical 32-bit
  void SubU32(Register dst, Register src1, Register src2);

  // Multiply
  void MulS64(Register dst, const Operand& opnd);
  void MulS64(Register dst, Register src);
  void MulS64(Register dst, const MemOperand& opnd);
  void MulS64(Register dst, Register src1, Register src2) {
    if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
      msgrkc(dst, src1, src2);
    } else {
      if (dst == src2) {
        MulS64(dst, src1);
      } else if (dst == src1) {
        MulS64(dst, src2);
      } else {
        mov(dst, src1);
        MulS64(dst, src2);
      }
    }
  }

  void MulS32(Register dst, const MemOperand& src1);
  void MulS32(Register dst, Register src1);
  void MulS32(Register dst, const Operand& src1);
  void MulS32(Register dst, Register src1, Register src2) {
    if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
      msrkc(dst, src1, src2);
    } else {
      if (dst == src2) {
        MulS32(dst, src1);
      } else if (dst == src1) {
        MulS32(dst, src2);
      } else {
        mov(dst, src1);
        MulS32(dst, src2);
      }
    }
  }
  void MulHighS64(Register dst, Register src1, Register src2);
  void MulHighS64(Register dst, Register src1, const MemOperand& src2);
  void MulHighU64(Register dst, Register src1, Register src2);
  void MulHighU64(Register dst, Register src1, const MemOperand& src2);

  void MulHighS32(Register dst, Register src1, const MemOperand& src2);
  void MulHighS32(Register dst, Register src1, Register src2);
  void MulHighS32(Register dst, Register src1, const Operand& src2);
  void MulHighU32(Register dst, Register src1, const MemOperand& src2);
  void MulHighU32(Register dst, Register src1, Register src2);
  void MulHighU32(Register dst, Register src1, const Operand& src2);
  void Mul32WithOverflowIfCCUnequal(Register dst, Register src1,
                                    const MemOperand& src2);
  void Mul32WithOverflowIfCCUnequal(Register dst, Register src1, Register src2);
  void Mul32WithOverflowIfCCUnequal(Register dst, Register src1,
                                    const Operand& src2);
  // Divide
  void DivS32(Register dst, Register src1, const MemOperand& src2);
  void DivS32(Register dst, Register src1, Register src2);
  void DivU32(Register dst, Register src1, const MemOperand& src2);
  void DivU32(Register dst, Register src1, Register src2);
  void DivS64(Register dst, Register src1, const MemOperand& src2);
  void DivS64(Register dst, Register src1, Register src2);
  void DivU64(Register dst, Register src1, const MemOperand& src2);
  void DivU64(Register dst, Register src1, Register src2);

  // Mod
  void ModS32(Register dst, Register src1, const MemOperand& src2);
  void ModS32(Register dst, Register src1, Register src2);
  void ModU32(Register dst, Register src1, const MemOperand& src2);
  void ModU32(Register dst, Register src1, Register src2);
  void ModS64(Register dst, Register src1, const MemOperand& src2);
  void ModS64(Register dst, Register src1, Register src2);
  void ModU64(Register dst, Register src1, const MemOperand& src2);
  void ModU64(Register dst, Register src1, Register src2);

  // Square root
  void Sqrt(DoubleRegister result, DoubleRegister input);
  void Sqrt(DoubleRegister result, const MemOperand& input);

  // Compare
  void CmpS32(Register src1, Register src2);
  void CmpS64(Register src1, Register src2);
  void CmpS32(Register dst, const Operand& opnd);
  void CmpS64(Register dst, const Operand& opnd);
  void CmpS32(Register dst, const MemOperand& opnd);
  void CmpS64(Register dst, const MemOperand& opnd);
  void CmpAndSwap(Register old_val, Register new_val, const MemOperand& opnd);
  void CmpAndSwap64(Register old_val, Register new_val, const MemOperand& opnd);
  // TODO(john.yan): remove this
  template <class T>
  void CmpP(Register src1, T src2) {
    CmpS64(src1, src2);
  }

  // Compare Logical
  void CmpU32(Register src1, Register src2);
  void CmpU64(Register src1, Register src2);
  void CmpU32(Register src1, const Operand& opnd);
  void CmpU64(Register src1, const Operand& opnd);
  void CmpU32(Register dst, const MemOperand& opnd);
  void CmpU64(Register dst, const MemOperand& opnd);

  // Compare Floats
  void CmpF32(DoubleRegister src1, DoubleRegister src2);
  void CmpF64(DoubleRegister src1, DoubleRegister src2);
  void CmpF32(DoubleRegister src1, const MemOperand& src2);
  void CmpF64(DoubleRegister src1, const MemOperand& src2);

  // Load
  void LoadU64(Register dst, const MemOperand& mem, Register scratch = no_reg);
  void LoadS32(Register dst, const MemOperand& opnd, Register scratch = no_reg);
  void LoadS32(Register dst, Register src);
  void LoadU32(Register dst, const MemOperand& opnd, Register scratch = no_reg);
  void LoadU32(Register dst, Register src);
  void LoadU16(Register dst, const MemOperand& opnd);
  void LoadU16(Register dst, Register src);
  void LoadS16(Register dst, Register src);
  void LoadS16(Register dst, const MemOperand& mem, Register scratch = no_reg);
  void LoadS8(Register dst, const MemOperand& opnd);
  void LoadS8(Register dst, Register src);
  void LoadU8(Register dst, const MemOperand& opnd);
  void LoadU8(Register dst, Register src);
  void LoadV128(Simd128Register dst, const MemOperand& mem, Register scratch);
  void LoadF64(DoubleRegister dst, const MemOperand& opnd);
  void LoadF32(DoubleRegister dst, const MemOperand& opnd);
  // LE Load
  void LoadU64LE(Register dst, const MemOperand& mem,
                 Register scratch = no_reg);
  void LoadS32LE(Register dst, const MemOperand& opnd,
                 Register scratch = no_reg);
  void LoadU32LE(Register dst, const MemOperand& opnd,
                 Register scratch = no_reg);
  void LoadU16LE(Register dst, const MemOperand& opnd);
  void LoadS16LE(Register dst, const MemOperand& opnd);
  void LoadV128LE(DoubleRegister dst, const MemOperand& mem, Register scratch0,
                  Register scratch1);
  void LoadF64LE(DoubleRegister dst, const MemOperand& opnd, Register scratch);
  void LoadF32LE(DoubleRegister dst, const MemOperand& opnd, Register scratch);
  // Vector LE Load and Transform instructions.
  void LoadAndSplat64x2LE(Simd128Register dst, const MemOperand& mem,
                          Register scratch);
  void LoadAndSplat32x4LE(Simd128Register dst, const MemOperand& mem,
                          Register scratch);
  void LoadAndSplat16x8LE(Simd128Register dst, const MemOperand& me,
                          Register scratch);
  void LoadAndSplat8x16LE(Simd128Register dst, const MemOperand& mem,
                          Register scratch);
  void LoadAndExtend8x8ULE(Simd128Register dst, const MemOperand& mem,
                           Register scratch);
  void LoadAndExtend8x8SLE(Simd128Register dst, const MemOperand& mem,
                           Register scratch);
  void LoadAndExtend16x4ULE(Simd128Register dst, const MemOperand& mem,
                            Register scratch);
  void LoadAndExtend16x4SLE(Simd128Register dst, const MemOperand& mem,
                            Register scratch);
  void LoadAndExtend32x2ULE(Simd128Register dst, const MemOperand& mem,
                            Register scratch);
  void LoadAndExtend32x2SLE(Simd128Register dst, const MemOperand& mem,
                            Register scratch);
  void LoadV32ZeroLE(Simd128Register dst, const MemOperand& mem,
                     Register scratch);
  void LoadV64ZeroLE(Simd128Register dst, const MemOperand& mem,
                     Register scratch);
  void LoadLane8LE(Simd128Register dst, const MemOperand& mem, int lane,
                   Register scratch);
  void LoadLane16LE(Simd128Register dst, const MemOperand& mem, int lane,
                    Register scratch);
  void LoadLane32LE(Simd128Register dst, const MemOperand& mem, int lane,
                    Register scratch);
  void LoadLane64LE(Simd128Register dst, const MemOperand& mem, int lane,
                    Register scratch);
  void StoreLane8LE(Simd128Register src, const MemOperand& mem, int lane,
                    Register scratch);
  void StoreLane16LE(Simd128Register src, const MemOperand& mem, int lane,
                     Register scratch);
  void StoreLane32LE(Simd128Register src, const MemOperand& mem, int lane,
                     Register scratch);
  void StoreLane64LE(Simd128Register src, const MemOperand& mem, int lane,
                     Register scratch);

  // Load And Test
  void LoadAndTest32(Register dst, Register src);
  void LoadAndTestP(Register dst, Register src);

  void LoadAndTest32(Register dst, const MemOperand& opnd);
  void LoadAndTestP(Register dst, const MemOperand& opnd);

  // Store
  void StoreU64(const MemOperand& mem, const Operand& opnd,
                Register scratch = no_reg);
  void StoreU64(Register src, const MemOperand& mem, Register scratch = no_reg);
  void StoreU32(Register src, const MemOperand& mem, Register scratch = no_reg);

  void StoreU16(Register src, const MemOperand& mem, Register scratch = r0);
  void StoreU8(Register src, const MemOperand& mem, Register scratch = r0);
  void StoreF64(DoubleRegister dst, const MemOperand& opnd);
  void StoreF32(DoubleRegister dst, const MemOperand& opnd);
  void StoreV128(Simd128Register src, const MemOperand& mem, Register scratch);

  // Store LE
  void StoreU64LE(Register src, const MemOperand& mem,
                  Register scratch = no_reg);
  void StoreU32LE(Register src, const MemOperand& mem,
                  Register scratch = no_reg);

  void StoreU16LE(Register src, const MemOperand& mem, Register scratch = r0);
  void StoreF64LE(DoubleRegister src, const MemOperand& opnd, Register scratch);
  void StoreF32LE(DoubleRegister src, const MemOperand& opnd, Register scratch);
  void StoreV128LE(Simd128Register src, const MemOperand& mem,
                   Register scratch1, Register scratch2);

  void AddF32(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs);
  void SubF32(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs);
  void MulF32(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs);
  void DivF32(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs);

  void AddF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs);
  void SubF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs);
  void MulF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs);
  void DivF64(DoubleRegister dst, DoubleRegister lhs, DoubleRegister rhs);

  void AddFloat32(DoubleRegister dst, const MemOperand& opnd,
                  DoubleRegister scratch);
  void AddFloat64(DoubleRegister dst, const MemOperand& opnd,
                  DoubleRegister scratch);
  void SubFloat32(DoubleRegister dst, const MemOperand& opnd,
                  DoubleRegister scratch);
  void SubFloat64(DoubleRegister dst, const MemOperand& opnd,
                  DoubleRegister scratch);
  void MulFloat32(DoubleRegister dst, const MemOperand& opnd,
                  DoubleRegister scratch);
  void MulFloat64(DoubleRegister dst, const MemOperand& opnd,
                  DoubleRegister scratch);
  void DivFloat32(DoubleRegister dst, const MemOperand& opnd,
                  DoubleRegister scratch);
  void DivFloat64(DoubleRegister dst, const MemOperand& opnd,
                  DoubleRegister scratch);
  void LoadF32AsF64(DoubleRegister dst, const MemOperand& opnd);

  // Load On Condition
  void LoadOnConditionP(Condition cond, Register dst, Register src);

  void LoadPositiveP(Register result, Register input);
  void LoadPositive32(Register result, Register input);

  void Branch(Condition c, const Operand& opnd);
  void BranchOnCount(Register r1, Label* l);

  // Shifts
  void ShiftLeftU32(Register dst, Register src, Register val,
                    const Operand& val2 = Operand::Zero());
  void ShiftLeftU32(Register dst, Register src, const Operand& val);
  void ShiftLeftU64(Register dst, Register src, Register val,
                    const Operand& val2 = Operand::Zero());
  void ShiftLeftU64(Register dst, Register src, const Operand& val);
  void ShiftRightU32(Register dst, Register src, Register val,
                     const Operand& val2 = Operand::Zero());
  void ShiftRightU32(Register dst, Register src, const Operand& val);
  void ShiftRightU64(Register dst, Register src, Register val,
                     const Operand& val2 = Operand::Zero());
  void ShiftRightU64(Register dst, Register src, const Operand& val);
  void ShiftRightS32(Register dst, Register src, Register shift,
                     const Operand& val2 = Operand::Zero());
  void ShiftRightS32(Register dst, Register src, const Operand& val);
  void ShiftRightS64(Register dst, Register src, Register shift,
                     const Operand& val2 = Operand::Zero());
  void ShiftRightS64(Register dst, Register src, const Operand& val);

  void ClearRightImm(Register dst, Register src, const Operand& val);

  // Bitwise operations
  void And(Register dst, Register src);
  void AndP(Register dst, Register src);
  void And(Register dst, Register src1, Register src2);
  void AndP(Register dst, Register src1, Register src2);
  void And(Register dst, const MemOperand& opnd);
  void AndP(Register dst, const MemOperand& opnd);
  void And(Register dst, const Operand& opnd);
  void AndP(Register dst, const Operand& opnd);
  void And(Register dst, Register src, const Operand& opnd);
  void AndP(Register dst, Register src, const Operand& opnd);
  void Or(Register dst, Register src);
  void OrP(Register dst, Register src);
  void Or(Register dst, Register src1, Register src2);
  void OrP(Register dst, Register src1, Register src2);
  void Or(Register dst, const MemOperand& opnd);
  void OrP(Register dst, const MemOperand& opnd);
  void Or(Register dst, const Operand& opnd);
  void OrP(Register dst, const Operand& opnd);
  void Or(Register dst, Register src, const Operand& opnd);
  void OrP(Register dst, Register src, const Operand& opnd);
  void Xor(Register dst, Register src);
  void XorP(Register dst, Register src);
  void Xor(Register dst, Register src1, Register src2);
  void XorP(Register dst, Register src1, Register src2);
  void Xor(Register dst, const MemOperand& opnd);
  void XorP(Register dst, const MemOperand& opnd);
  void Xor(Register dst, const Operand& opnd);
  void XorP(Register dst, const Operand& opnd);
  void Xor(Register dst, Register src, const Operand& opnd);
  void XorP(Register dst, Register src, const Operand& opnd);
  void Popcnt32(Register dst, Register src);
  void Not32(Register dst, Register src = no_reg);
  void Not64(Register dst, Register src = no_reg);
  void NotP(Register dst, Register src = no_reg);

  void Popcnt64(Register dst, Register src);

  void mov(Register dst, const Operand& src);
  void mov(Register dst, Register src);

  void push(DoubleRegister src) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreF64(src, MemOperand(sp));
  }

  void push(Register src) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreU64(src, MemOperand(sp));
  }

  void pop(DoubleRegister dst) {
    LoadF64(dst, MemOperand(sp));
    la(sp, MemOperand(sp, kSystemPointerSize));
  }

  void pop(Register dst) {
    LoadU64(dst, MemOperand(sp));
    la(sp, MemOperand(sp, kSystemPointerSize));
  }

  void pop() { la(sp, MemOperand(sp, kSystemPointerSize)); }

  void Push(Register src) { push(src); }

  // Push a handle.
  void Push(Handle<HeapObject> handle);
  void Push(Tagged<Smi> smi);
  void Push(Tagged<TaggedIndex> index);

  // Push two registers.  Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2) {
    lay(sp, MemOperand(sp, -kSystemPointerSize * 2));
    StoreU64(src1, MemOperand(sp, kSystemPointerSize));
    StoreU64(src2, MemOperand(sp, 0));
  }

  // Push three registers.  Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3) {
    lay(sp, MemOperand(sp, -kSystemPointerSize * 3));
    StoreU64(src1, MemOperand(sp, kSystemPointerSize * 2));
    StoreU64(src2, MemOperand(sp, kSystemPointerSize));
    StoreU64(src3, MemOperand(sp, 0));
  }

  // Push four registers.  Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3, Register src4) {
    lay(sp, MemOperand(sp, -kSystemPointerSize * 4));
    StoreU64(src1, MemOperand(sp, kSystemPointerSize * 3));
    StoreU64(src2, MemOperand(sp, kSystemPointerSize * 2));
    StoreU64(src3, MemOperand(sp, kSystemPointerSize));
    StoreU64(src4, MemOperand(sp, 0));
  }

  // Push five registers.  Pushes leftmost register first (to highest address).
  void Push(Register src1, Register src2, Register src3, Register src4,
            Register src5) {
    DCHECK(src1 != src2);
    DCHECK(src1 != src3);
    DCHECK(src2 != src3);
    DCHECK(src1 != src4);
    DCHECK(src2 != src4);
    DCHECK(src3 != src4);
    DCHECK(src1 != src5);
    DCHECK(src2 != src5);
    DCHECK(src3 != src5);
    DCHECK(src4 != src5);

    lay(sp, MemOperand(sp, -kSystemPointerSize * 5));
    StoreU64(src1, MemOperand(sp, kSystemPointerSize * 4));
    StoreU64(src2, MemOperand(sp, kSystemPointerSize * 3));
    StoreU64(src3, MemOperand(sp, kSystemPointerSize * 2));
    StoreU64(src4, MemOperand(sp, kSystemPointerSize));
    StoreU64(src5, MemOperand(sp, 0));
  }

  enum PushArrayOrder { kNormal, kReverse };
  void PushArray(Register array, Register size, Register scratch,
                 Register scratch2, PushArrayOrder order = kNormal);

  void Pop(Register dst) { pop(dst); }

  // Pop two registers. Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2) {
    LoadU64(src2, MemOperand(sp, 0));
    LoadU64(src1, MemOperand(sp, kSystemPointerSize));
    la(sp, MemOperand(sp, 2 * kSystemPointerSize));
  }

  // Pop three registers.  Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2, Register src3) {
    LoadU64(src3, MemOperand(sp, 0));
    LoadU64(src2, MemOperand(sp, kSystemPointerSize));
    LoadU64(src1, MemOperand(sp, 2 * kSystemPointerSize));
    la(sp, MemOperand(sp, 3 * kSystemPointerSize));
  }

  // Pop four registers.  Pops rightmost register first (from lower address).
  void Pop(Register src1, Register src2, Register src3, Register src4) {
    LoadU64(src4, MemOperand(sp, 0));
```