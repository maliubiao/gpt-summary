Response: The user wants me to summarize the functionality of the C++ code in the file `v8/src/codegen/arm64/macro-assembler-arm64.cc`.
This is the first part of a three-part file.

The code seems to define a `MacroAssembler` class for the ARM64 architecture within the V8 JavaScript engine.
MacroAssemblers are typically used to generate machine code instructions programmatically.

I should focus on the functionalities present in this first part of the file. Looking through the code, I see functions for:
- Pushing and popping CPU and FP registers.
- Moving data between registers and memory, including handling immediate values and different addressing modes.
- Performing logical and arithmetic operations.
- Implementing conditional operations.
- Defining pseudo-instructions for common tasks.
- Abstracted stack operations.
- Assertions for debugging.
- Copying memory blocks.

The code interacts heavily with the underlying ARM64 instruction set.

Regarding the relation to JavaScript, this code is part of the V8 engine, which executes JavaScript. The `MacroAssembler` is used to generate the low-level machine code that corresponds to the execution of JavaScript code.

I can provide JavaScript examples that illustrate how certain functionalities in this C++ code would be used when executing that JavaScript.
这个C++源代码文件 `v8/src/codegen/arm64/macro-assembler-arm64.cc` 的第1部分定义了V8 JavaScript引擎在ARM64架构上的`MacroAssembler`类的部分功能。`MacroAssembler`是一个用于生成ARM64汇编指令的工具类，它提供了一系列高级接口来简化生成机器码的过程。

**主要功能归纳:**

1. **寄存器操作:**
   - 提供了批量压栈 (`PushCPURegList`, `PushAll`) 和弹栈 (`PopCPURegList`, `PopAll`) CPU通用寄存器的功能。
   - 提供了保存和恢复调用者保存寄存器 (`PushCallerSaved`, `PopCallerSaved`) 的功能，这在函数调用时用于保护寄存器中的值。

2. **逻辑运算:**
   - 封装了各种逻辑运算指令 (`LogicalMacro`)，能够处理立即数、寄存器以及移位寄存器等操作数，并能处理立即数无法直接编码的情况。

3. **数据移动:**
   - 提供了将立即数 (`Mov(const Register& rd, uint64_t imm)`)、外部引用 (`Mov(const Register& rd, ExternalReference reference)`) 以及各种类型的操作数 (`Mov(const Register& rd, const Operand& operand, DiscardMoveMode discard_mode)`) 移动到寄存器的功能。
   - 针对向量寄存器提供了移动立即数 (`Movi`) 的多种辅助方法，以优化不同位宽立即数的移动。
   - 提供了按位取反移动 (`Mvn`) 的功能。

4. **条件比较和选择:**
   - 提供了条件比较宏 (`ConditionalCompareMacro`)，用于根据条件码比较寄存器和操作数。
   - 提供了条件选择指令 (`Csel`)，根据条件码选择将一个寄存器或操作数的值赋给目标寄存器。

5. **算术运算:**
   - 提供了加减运算宏 (`AddSubMacro`)，能够处理需要重定位的立即数以及各种操作数类型。
   - 提供了带进位的加减运算宏 (`AddSubWithCarryMacro`)。

6. **加载和存储:**
   - 提供了加载 (`LoadStoreMacro`) 和存储 (`LoadStoreMacro`) 单个寄存器的功能，能够处理立即数偏移和寄存器偏移等多种寻址模式。
   - 提供了加载和存储寄存器对 (`LoadStorePairMacro`) 的功能。

7. **地址加载:**
   - 提供了加载程序相对地址 (`Adr`) 的功能，可以加载近距离和远距离的标签地址。

8. **分支跳转:**
   - 提供了各种类型的分支跳转指令 (`B`)，包括无条件跳转、条件跳转、比较零跳转、比较非零跳转以及测试位跳转等。

9. **伪指令:**
   - 提供了一些方便的伪指令，例如计算绝对值 (`Abs`) 和实现 `switch` 语句 (`Switch`)。

10. **抽象的栈操作:**
    - 提供了同时压入 (`Push`) 和弹出 (`Pop`) 多个寄存器的功能。
    - 提供了将一个寄存器多次压入栈的功能 (`PushMultipleTimes`)。
    - 提供了在栈上“窥视” (`PeekPair`) 和“探入” (`PokePair`) 寄存器对的功能。

11. **函数调用约定:**
    - 提供了保存 (`PushCalleeSavedRegisters`) 和恢复 (`PopCalleeSavedRegisters`) 被调用者保存寄存器的功能，这是符合ARM64调用约定的。

12. **调试辅助:**
    - 提供了一系列断言宏 (`AssertFeedbackCell`, `AssertFeedbackVector`, `AssertSpAligned` 等)，用于在开发和调试阶段检查代码的正确性。

13. **内存拷贝:**
    - 提供了拷贝内存块的功能 (`CopySlots`, `CopyDoubleWords`)。

**与JavaScript的关系及JavaScript示例:**

`MacroAssembler` 生成的机器码直接对应JavaScript代码的执行。例如，当V8编译JavaScript代码时，会使用`MacroAssembler` 将高级的JavaScript操作转换为底层的ARM64指令。

以下是一些概念性的JavaScript示例，来说明`macro-assembler-arm64.cc`中部分功能在执行JavaScript时可能的作用：

**示例 1: 变量赋值 (数据移动)**

```javascript
let x = 10;
let y = x;
```

在底层，`MacroAssembler` 可能会生成类似以下的指令（简化表示）：

```assembly
// 将立即数 10 移动到寄存器，假设是 x1
Mov(x1, 10);

// 将寄存器 x1 的值移动到另一个寄存器，假设是 x2，用于表示 y
Mov(x2, x1);
```

**示例 2: 加法运算 (算术运算)**

```javascript
let a = 5;
let b = 3;
let sum = a + b;
```

`MacroAssembler` 可能会生成：

```assembly
// 将 5 加载到寄存器，例如 x1
Mov(x1, 5);

// 将 3 加载到寄存器，例如 x2
Mov(x2, 3);

// 执行加法运算，将结果存储到寄存器，例如 x3
AddSubMacro(x3, x1, Operand(x2), LeaveFlags, ADD);
```

**示例 3: 函数调用 (栈操作和分支跳转)**

```javascript
function add(x, y) {
  return x + y;
}

add(2, 4);
```

在调用 `add(2, 4)` 时，`MacroAssembler` 可能会生成指令来：

1. **压栈参数:** 将参数 `2` 和 `4` 压入栈中 (`Push`)。
2. **保存寄存器:** 保存调用者保存的寄存器 (`PushCallerSaved`)。
3. **跳转到函数:** 执行分支跳转到 `add` 函数的入口地址 (`B`)。
4. **在函数内部:**
   - 保存被调用者保存的寄存器 (`PushCalleeSavedRegisters`)。
   - 执行加法操作 (`AddSubMacro`)。
   - 恢复被调用者保存的寄存器 (`PopCalleeSavedRegisters`)。
   - 将结果移动到返回寄存器。
   - 执行返回指令。
5. **在调用者:** 恢复调用者保存的寄存器 (`PopCallerSaved`)。
6. **清理栈:** 调整栈指针以移除参数。

**示例 4: 条件语句 (条件比较和分支跳转)**

```javascript
let num = 10;
if (num > 5) {
  console.log("Greater than 5");
}
```

`MacroAssembler` 可能会生成：

```assembly
// 将 num 的值加载到寄存器，例如 x1
Mov(x1, 10);

// 将 5 加载到另一个寄存器或作为立即数
Mov(x2, 5);

// 执行比较操作
Cmp(x1, x2);

// 如果 num 不大于 5，则跳转到 if 语句块之后
B(le, &else_block);

// ... 执行 "Greater than 5" 的代码 ...

// 跳转到 if 语句块结束
B(&if_end);

bind(&else_block);
// ... 如果有 else 块，则执行 else 块的代码 ...

bind(&if_end);
```

总而言之，`v8/src/codegen/arm64/macro-assembler-arm64.cc` 的第1部分为V8引擎在ARM64架构上生成高效的机器码提供了基础的构建模块，这些模块直接服务于JavaScript代码的执行。

Prompt: 
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if V8_TARGET_ARCH_ARM64

#include <optional>

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/reloc-info.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/arm64/macro-assembler-arm64.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

CPURegList MacroAssembler::DefaultTmpList() { return CPURegList(ip0, ip1); }

CPURegList MacroAssembler::DefaultFPTmpList() {
  return CPURegList(fp_scratch1, fp_scratch2);
}

namespace {

// For WebAssembly we care about the full floating point register. If we are not
// running Wasm, we can get away with saving half of those registers.
#if V8_ENABLE_WEBASSEMBLY
constexpr int kStackSavedSavedFPSizeInBits = kQRegSizeInBits;
#else
constexpr int kStackSavedSavedFPSizeInBits = kDRegSizeInBits;
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

void MacroAssembler::PushCPURegList(CPURegList registers) {
  // If LR was stored here, we would need to sign it if
  // V8_ENABLE_CONTROL_FLOW_INTEGRITY is on.
  DCHECK(!registers.IncludesAliasOf(lr));

  int size = registers.RegisterSizeInBytes();
  DCHECK_EQ(0, (size * registers.Count()) % 16);

  // Push up to four registers at a time.
  while (!registers.IsEmpty()) {
    int count_before = registers.Count();
    const CPURegister& src0 = registers.PopHighestIndex();
    const CPURegister& src1 = registers.PopHighestIndex();
    const CPURegister& src2 = registers.PopHighestIndex();
    const CPURegister& src3 = registers.PopHighestIndex();
    int count = count_before - registers.Count();
    PushHelper(count, size, src0, src1, src2, src3);
  }
}

void MacroAssembler::PopCPURegList(CPURegList registers) {
  int size = registers.RegisterSizeInBytes();
  DCHECK_EQ(0, (size * registers.Count()) % 16);

  // If LR was loaded here, we would need to authenticate it if
  // V8_ENABLE_CONTROL_FLOW_INTEGRITY is on.
  DCHECK(!registers.IncludesAliasOf(lr));

  // Pop up to four registers at a time.
  while (!registers.IsEmpty()) {
    int count_before = registers.Count();
    const CPURegister& dst0 = registers.PopLowestIndex();
    const CPURegister& dst1 = registers.PopLowestIndex();
    const CPURegister& dst2 = registers.PopLowestIndex();
    const CPURegister& dst3 = registers.PopLowestIndex();
    int count = count_before - registers.Count();
    PopHelper(count, size, dst0, dst1, dst2, dst3);
  }
}

void MacroAssembler::PushAll(RegList reglist) {
  if (reglist.Count() % 2 != 0) {
    DCHECK(!reglist.has(xzr));
    reglist.set(xzr);
  }

  CPURegList registers(kXRegSizeInBits, reglist);
  int size = registers.RegisterSizeInBytes();
  DCHECK_EQ(0, (size * registers.Count()) % 16);

  // If LR was stored here, we would need to sign it if
  // V8_ENABLE_CONTROL_FLOW_INTEGRITY is on.
  DCHECK(!registers.IncludesAliasOf(lr));

  while (!registers.IsEmpty()) {
    const CPURegister& src0 = registers.PopLowestIndex();
    const CPURegister& src1 = registers.PopLowestIndex();
    stp(src1, src0, MemOperand(sp, -2 * size, PreIndex));
  }
}

void MacroAssembler::PopAll(RegList reglist) {
  if (reglist.Count() % 2 != 0) {
    DCHECK(!reglist.has(xzr));
    reglist.set(xzr);
  }

  CPURegList registers(kXRegSizeInBits, reglist);
  int size = registers.RegisterSizeInBytes();
  DCHECK_EQ(0, (size * registers.Count()) % 16);

  // If LR was loaded here, we would need to authenticate it if
  // V8_ENABLE_CONTROL_FLOW_INTEGRITY is on.
  DCHECK(!registers.IncludesAliasOf(lr));

  while (!registers.IsEmpty()) {
    const CPURegister& dst0 = registers.PopHighestIndex();
    const CPURegister& dst1 = registers.PopHighestIndex();
    ldp(dst0, dst1, MemOperand(sp, 2 * size, PostIndex));
  }
}

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion) const {
  auto list = kCallerSaved;
  list.Remove(exclusion);
  list.Align();

  int bytes = list.TotalSizeInBytes();

  if (fp_mode == SaveFPRegsMode::kSave) {
    auto fp_list = CPURegList::GetCallerSavedV(kStackSavedSavedFPSizeInBits);
    DCHECK_EQ(fp_list.Count() % 2, 0);
    bytes += fp_list.TotalSizeInBytes();
  }
  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode,
                                    Register exclusion) {
  ASM_CODE_COMMENT(this);
  auto list = kCallerSaved;
  list.Remove(exclusion);
  list.Align();

  PushCPURegList(list);

  int bytes = list.TotalSizeInBytes();

  if (fp_mode == SaveFPRegsMode::kSave) {
    auto fp_list = CPURegList::GetCallerSavedV(kStackSavedSavedFPSizeInBits);
    DCHECK_EQ(fp_list.Count() % 2, 0);
    PushCPURegList(fp_list);
    bytes += fp_list.TotalSizeInBytes();
  }
  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    auto fp_list = CPURegList::GetCallerSavedV(kStackSavedSavedFPSizeInBits);
    DCHECK_EQ(fp_list.Count() % 2, 0);
    PopCPURegList(fp_list);
    bytes += fp_list.TotalSizeInBytes();
  }

  auto list = kCallerSaved;
  list.Remove(exclusion);
  list.Align();

  PopCPURegList(list);
  bytes += list.TotalSizeInBytes();

  return bytes;
}

void MacroAssembler::LogicalMacro(const Register& rd, const Register& rn,
                                  const Operand& operand, LogicalOp op) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);

  if (operand.NeedsRelocation(this)) {
    Register temp = temps.AcquireX();
    Ldr(temp, operand.immediate());
    Logical(rd, rn, temp, op);

  } else if (operand.IsImmediate()) {
    int64_t immediate = operand.ImmediateValue();
    unsigned reg_size = rd.SizeInBits();

    // If the operation is NOT, invert the operation and immediate.
    if ((op & NOT) == NOT) {
      op = static_cast<LogicalOp>(op & ~NOT);
      immediate = ~immediate;
    }

    // Ignore the top 32 bits of an immediate if we're moving to a W register.
    if (rd.Is32Bits()) {
      immediate &= kWRegMask;
    }

    DCHECK(rd.Is64Bits() || is_uint32(immediate));

    // Special cases for all set or all clear immediates.
    if (immediate == 0) {
      switch (op) {
        case AND:
          Mov(rd, 0);
          return;
        case ORR:  // Fall through.
        case EOR:
          Mov(rd, rn);
          return;
        case ANDS:  // Fall through.
        case BICS:
          break;
        default:
          UNREACHABLE();
      }
    } else if ((rd.Is64Bits() && (immediate == -1L)) ||
               (rd.Is32Bits() && (immediate == 0xFFFFFFFFL))) {
      switch (op) {
        case AND:
          Mov(rd, rn);
          return;
        case ORR:
          Mov(rd, immediate);
          return;
        case EOR:
          Mvn(rd, rn);
          return;
        case ANDS:  // Fall through.
        case BICS:
          break;
        default:
          UNREACHABLE();
      }
    }

    unsigned n, imm_s, imm_r;
    if (IsImmLogical(immediate, reg_size, &n, &imm_s, &imm_r)) {
      // Immediate can be encoded in the instruction.
      LogicalImmediate(rd, rn, n, imm_s, imm_r, op);
    } else {
      // Immediate can't be encoded: synthesize using move immediate.
      Register temp = temps.AcquireSameSizeAs(rn);

      // If the left-hand input is the stack pointer, we can't pre-shift the
      // immediate, as the encoding won't allow the subsequent post shift.
      PreShiftImmMode mode = rn == sp ? kNoShift : kAnyShift;
      Operand imm_operand = MoveImmediateForShiftedOp(temp, immediate, mode);

      if (rd.IsSP()) {
        // If rd is the stack pointer we cannot use it as the destination
        // register so we use the temp register as an intermediate again.
        Logical(temp, rn, imm_operand, op);
        Mov(sp, temp);
      } else {
        Logical(rd, rn, imm_operand, op);
      }
    }

  } else if (operand.IsExtendedRegister()) {
    DCHECK(operand.reg().SizeInBits() <= rd.SizeInBits());
    // Add/sub extended supports shift <= 4. We want to support exactly the
    // same modes here.
    DCHECK_LE(operand.shift_amount(), 4);
    DCHECK(operand.reg().Is64Bits() ||
           ((operand.extend() != UXTX) && (operand.extend() != SXTX)));
    Register temp = temps.AcquireSameSizeAs(rn);
    EmitExtendShift(temp, operand.reg(), operand.extend(),
                    operand.shift_amount());
    Logical(rd, rn, temp, op);

  } else {
    // The operand can be encoded in the instruction.
    DCHECK(operand.IsShiftedRegister());
    Logical(rd, rn, operand, op);
  }
}

void MacroAssembler::Mov(const Register& rd, uint64_t imm) {
  DCHECK(allow_macro_instructions());
  DCHECK(is_uint32(imm) || is_int32(imm) || rd.Is64Bits());
  DCHECK(!rd.IsZero());

  // TODO(all) extend to support more immediates.
  //
  // Immediates on Aarch64 can be produced using an initial value, and zero to
  // three move keep operations.
  //
  // Initial values can be generated with:
  //  1. 64-bit move zero (movz).
  //  2. 32-bit move inverted (movn).
  //  3. 64-bit move inverted.
  //  4. 32-bit orr immediate.
  //  5. 64-bit orr immediate.
  // Move-keep may then be used to modify each of the 16-bit half-words.
  //
  // The code below supports all five initial value generators, and
  // applying move-keep operations to move-zero and move-inverted initial
  // values.

  // Try to move the immediate in one instruction, and if that fails, switch to
  // using multiple instructions.
  if (!TryOneInstrMoveImmediate(rd, imm)) {
    unsigned reg_size = rd.SizeInBits();

    // Generic immediate case. Imm will be represented by
    //   [imm3, imm2, imm1, imm0], where each imm is 16 bits.
    // A move-zero or move-inverted is generated for the first non-zero or
    // non-0xFFFF immX, and a move-keep for subsequent non-zero immX.

    uint64_t ignored_halfword = 0;
    bool invert_move = false;
    // If the number of 0xFFFF halfwords is greater than the number of 0x0000
    // halfwords, it's more efficient to use move-inverted.
    if (CountSetHalfWords(imm, reg_size) > CountSetHalfWords(~imm, reg_size)) {
      ignored_halfword = 0xFFFFL;
      invert_move = true;
    }

    // Mov instructions can't move immediate values into the stack pointer, so
    // set up a temporary register, if needed.
    UseScratchRegisterScope temps(this);
    Register temp = rd.IsSP() ? temps.AcquireSameSizeAs(rd) : rd;

    // Iterate through the halfwords. Use movn/movz for the first non-ignored
    // halfword, and movk for subsequent halfwords.
    DCHECK_EQ(reg_size % 16, 0);
    bool first_mov_done = false;
    for (int i = 0; i < (rd.SizeInBits() / 16); i++) {
      uint64_t imm16 = (imm >> (16 * i)) & 0xFFFFL;
      if (imm16 != ignored_halfword) {
        if (!first_mov_done) {
          if (invert_move) {
            movn(temp, (~imm16) & 0xFFFFL, 16 * i);
          } else {
            movz(temp, imm16, 16 * i);
          }
          first_mov_done = true;
        } else {
          // Construct a wider constant.
          movk(temp, imm16, 16 * i);
        }
      }
    }
    DCHECK(first_mov_done);

    // Move the temporary if the original destination register was the stack
    // pointer.
    if (rd.IsSP()) {
      mov(rd, temp);
    }
  }
}

void MacroAssembler::Mov(const Register& rd, ExternalReference reference) {
  if (root_array_available_) {
    if (reference.IsIsolateFieldId()) {
      Add(rd, kRootRegister, Operand(reference.offset_from_root_register()));
      return;
    }
  }
  // External references should not get created with IDs if
  // `!root_array_available()`.
  CHECK(!reference.IsIsolateFieldId());
  Mov(rd, Operand(reference));
}

void MacroAssembler::LoadIsolateField(const Register& rd, IsolateFieldId id) {
  Mov(rd, ExternalReference::Create(id));
}

void MacroAssembler::Mov(const Register& rd, const Operand& operand,
                         DiscardMoveMode discard_mode) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());

  // Provide a swap register for instructions that need to write into the
  // system stack pointer (and can't do this inherently).
  UseScratchRegisterScope temps(this);
  Register dst = (rd.IsSP()) ? temps.AcquireSameSizeAs(rd) : rd;

  if (operand.NeedsRelocation(this)) {
    // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
    // non-isolate-independent code. In many cases it might be cheaper than
    // embedding the relocatable value.
    if (root_array_available_ && options().isolate_independent_code) {
      if (operand.ImmediateRMode() == RelocInfo::EXTERNAL_REFERENCE) {
        Address addr = static_cast<Address>(operand.ImmediateValue());
        ExternalReference reference = base::bit_cast<ExternalReference>(addr);
        IndirectLoadExternalReference(rd, reference);
        return;
      } else if (RelocInfo::IsEmbeddedObjectMode(operand.ImmediateRMode())) {
        Handle<HeapObject> x(
            reinterpret_cast<Address*>(operand.ImmediateValue()));
        // TODO(v8:9706): Fix-it! This load will always uncompress the value
        // even when we are loading a compressed embedded object.
        IndirectLoadConstant(rd.X(), x);
        return;
      }
    }
    Ldr(dst, operand);
  } else if (operand.IsImmediate()) {
    // Call the macro assembler for generic immediates.
    Mov(dst, operand.ImmediateValue());
  } else if (operand.IsShiftedRegister() && (operand.shift_amount() != 0)) {
    // Emit a shift instruction if moving a shifted register. This operation
    // could also be achieved using an orr instruction (like orn used by Mvn),
    // but using a shift instruction makes the disassembly clearer.
    EmitShift(dst, operand.reg(), operand.shift(), operand.shift_amount());
  } else if (operand.IsExtendedRegister()) {
    // Emit an extend instruction if moving an extended register. This handles
    // extend with post-shift operations, too.
    EmitExtendShift(dst, operand.reg(), operand.extend(),
                    operand.shift_amount());
  } else {
    // Otherwise, emit a register move only if the registers are distinct, or
    // if they are not X registers.
    //
    // Note that mov(w0, w0) is not a no-op because it clears the top word of
    // x0. A flag is provided (kDiscardForSameWReg) if a move between the same W
    // registers is not required to clear the top word of the X register. In
    // this case, the instruction is discarded.
    //
    // If sp is an operand, add #0 is emitted, otherwise, orr #0.
    if (rd != operand.reg() ||
        (rd.Is32Bits() && (discard_mode == kDontDiscardForSameWReg))) {
      Assembler::mov(rd, operand.reg());
    }
    // This case can handle writes into the system stack pointer directly.
    dst = rd;
  }

  // Copy the result to the system stack pointer.
  if (dst != rd) {
    DCHECK(rd.IsSP());
    Assembler::mov(rd, dst);
  }
}

void MacroAssembler::Mov(const Register& rd, Tagged<Smi> smi) {
  return Mov(rd, Operand(smi));
}

void MacroAssembler::Movi16bitHelper(const VRegister& vd, uint64_t imm) {
  DCHECK(is_uint16(imm));
  int byte1 = (imm & 0xFF);
  int byte2 = ((imm >> 8) & 0xFF);
  if (byte1 == byte2) {
    movi(vd.Is64Bits() ? vd.V8B() : vd.V16B(), byte1);
  } else if (byte1 == 0) {
    movi(vd, byte2, LSL, 8);
  } else if (byte2 == 0) {
    movi(vd, byte1);
  } else if (byte1 == 0xFF) {
    mvni(vd, ~byte2 & 0xFF, LSL, 8);
  } else if (byte2 == 0xFF) {
    mvni(vd, ~byte1 & 0xFF);
  } else {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireW();
    movz(temp, imm);
    dup(vd, temp);
  }
}

void MacroAssembler::Movi32bitHelper(const VRegister& vd, uint64_t imm) {
  DCHECK(is_uint32(imm));

  uint8_t bytes[sizeof(imm)];
  memcpy(bytes, &imm, sizeof(imm));

  // All bytes are either 0x00 or 0xFF.
  {
    bool all0orff = true;
    for (int i = 0; i < 4; ++i) {
      if ((bytes[i] != 0) && (bytes[i] != 0xFF)) {
        all0orff = false;
        break;
      }
    }

    if (all0orff == true) {
      movi(vd.Is64Bits() ? vd.V1D() : vd.V2D(), ((imm << 32) | imm));
      return;
    }
  }

  // Of the 4 bytes, only one byte is non-zero.
  for (int i = 0; i < 4; i++) {
    if ((imm & (0xFF << (i * 8))) == imm) {
      movi(vd, bytes[i], LSL, i * 8);
      return;
    }
  }

  // Of the 4 bytes, only one byte is not 0xFF.
  for (int i = 0; i < 4; i++) {
    uint32_t mask = ~(0xFF << (i * 8));
    if ((imm & mask) == mask) {
      mvni(vd, ~bytes[i] & 0xFF, LSL, i * 8);
      return;
    }
  }

  // Immediate is of the form 0x00MMFFFF.
  if ((imm & 0xFF00FFFF) == 0x0000FFFF) {
    movi(vd, bytes[2], MSL, 16);
    return;
  }

  // Immediate is of the form 0x0000MMFF.
  if ((imm & 0xFFFF00FF) == 0x000000FF) {
    movi(vd, bytes[1], MSL, 8);
    return;
  }

  // Immediate is of the form 0xFFMM0000.
  if ((imm & 0xFF00FFFF) == 0xFF000000) {
    mvni(vd, ~bytes[2] & 0xFF, MSL, 16);
    return;
  }
  // Immediate is of the form 0xFFFFMM00.
  if ((imm & 0xFFFF00FF) == 0xFFFF0000) {
    mvni(vd, ~bytes[1] & 0xFF, MSL, 8);
    return;
  }

  // Top and bottom 16-bits are equal.
  if (((imm >> 16) & 0xFFFF) == (imm & 0xFFFF)) {
    Movi16bitHelper(vd.Is64Bits() ? vd.V4H() : vd.V8H(), imm & 0xFFFF);
    return;
  }

  // Default case.
  {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireW();
    Mov(temp, imm);
    dup(vd, temp);
  }
}

void MacroAssembler::Movi64bitHelper(const VRegister& vd, uint64_t imm) {
  // All bytes are either 0x00 or 0xFF.
  {
    bool all0orff = true;
    for (int i = 0; i < 8; ++i) {
      int byteval = (imm >> (i * 8)) & 0xFF;
      if (byteval != 0 && byteval != 0xFF) {
        all0orff = false;
        break;
      }
    }
    if (all0orff == true) {
      movi(vd, imm);
      return;
    }
  }

  // Top and bottom 32-bits are equal.
  if (((imm >> 32) & 0xFFFFFFFF) == (imm & 0xFFFFFFFF)) {
    Movi32bitHelper(vd.Is64Bits() ? vd.V2S() : vd.V4S(), imm & 0xFFFFFFFF);
    return;
  }

  // Default case.
  {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    Mov(temp, imm);
    if (vd.Is1D()) {
      fmov(vd.D(), temp);
    } else {
      dup(vd.V2D(), temp);
    }
  }
}

void MacroAssembler::Movi(const VRegister& vd, uint64_t imm, Shift shift,
                          int shift_amount) {
  DCHECK(allow_macro_instructions());
  if (shift_amount != 0 || shift != LSL) {
    movi(vd, imm, shift, shift_amount);
  } else if (vd.Is8B() || vd.Is16B()) {
    // 8-bit immediate.
    DCHECK(is_uint8(imm));
    movi(vd, imm);
  } else if (vd.Is4H() || vd.Is8H()) {
    // 16-bit immediate.
    Movi16bitHelper(vd, imm);
  } else if (vd.Is2S() || vd.Is4S()) {
    // 32-bit immediate.
    Movi32bitHelper(vd, imm);
  } else {
    // 64-bit immediate.
    Movi64bitHelper(vd, imm);
  }
}

void MacroAssembler::Movi(const VRegister& vd, uint64_t hi, uint64_t lo) {
  // TODO(v8:11033): Move 128-bit values in a more efficient way.
  DCHECK(vd.Is128Bits());
  if (hi == lo) {
    Movi(vd.V2D(), lo);
    return;
  }

  Movi(vd.V1D(), lo);

  if (hi != 0) {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    Mov(temp, hi);
    Ins(vd.V2D(), 1, temp);
  }
}

void MacroAssembler::Mvn(const Register& rd, const Operand& operand) {
  DCHECK(allow_macro_instructions());

  if (operand.NeedsRelocation(this)) {
    Ldr(rd, operand.immediate());
    mvn(rd, rd);

  } else if (operand.IsImmediate()) {
    // Call the macro assembler for generic immediates.
    Mov(rd, ~operand.ImmediateValue());

  } else if (operand.IsExtendedRegister()) {
    // Emit two instructions for the extend case. This differs from Mov, as
    // the extend and invert can't be achieved in one instruction.
    EmitExtendShift(rd, operand.reg(), operand.extend(),
                    operand.shift_amount());
    mvn(rd, rd);

  } else {
    mvn(rd, operand);
  }
}

unsigned MacroAssembler::CountSetHalfWords(uint64_t imm, unsigned reg_size) {
  DCHECK_EQ(reg_size % 16, 0);

#define HALFWORD(idx) (((imm >> ((idx)*16)) & 0xFFFF) ? 1u : 0u)
  switch (reg_size / 16) {
    case 1:
      return HALFWORD(0);
    case 2:
      return HALFWORD(0) + HALFWORD(1);
    case 4:
      return HALFWORD(0) + HALFWORD(1) + HALFWORD(2) + HALFWORD(3);
  }
#undef HALFWORD
  UNREACHABLE();
}

// The movz instruction can generate immediates containing an arbitrary 16-bit
// half-word, with remaining bits clear, eg. 0x00001234, 0x0000123400000000.
bool MacroAssembler::IsImmMovz(uint64_t imm, unsigned reg_size) {
  DCHECK((reg_size == kXRegSizeInBits) || (reg_size == kWRegSizeInBits));
  return CountSetHalfWords(imm, reg_size) <= 1;
}

// The movn instruction can generate immediates containing an arbitrary 16-bit
// half-word, with remaining bits set, eg. 0xFFFF1234, 0xFFFF1234FFFFFFFF.
bool MacroAssembler::IsImmMovn(uint64_t imm, unsigned reg_size) {
  return IsImmMovz(~imm, reg_size);
}

void MacroAssembler::ConditionalCompareMacro(const Register& rn,
                                             const Operand& operand,
                                             StatusFlags nzcv, Condition cond,
                                             ConditionalCompareOp op) {
  DCHECK((cond != al) && (cond != nv));
  if (operand.NeedsRelocation(this)) {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireX();
    Ldr(temp, operand.immediate());
    ConditionalCompareMacro(rn, temp, nzcv, cond, op);

  } else if ((operand.IsShiftedRegister() && (operand.shift_amount() == 0)) ||
             (operand.IsImmediate() &&
              IsImmConditionalCompare(operand.ImmediateValue()))) {
    // The immediate can be encoded in the instruction, or the operand is an
    // unshifted register: call the assembler.
    ConditionalCompare(rn, operand, nzcv, cond, op);

  } else {
    // The operand isn't directly supported by the instruction: perform the
    // operation on a temporary register.
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireSameSizeAs(rn);
    Mov(temp, operand);
    ConditionalCompare(rn, temp, nzcv, cond, op);
  }
}

void MacroAssembler::Csel(const Register& rd, const Register& rn,
                          const Operand& operand, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());
  DCHECK((cond != al) && (cond != nv));
  if (operand.IsImmediate()) {
    // Immediate argument. Handle special cases of 0, 1 and -1 using zero
    // register.
    int64_t imm = operand.ImmediateValue();
    Register zr = AppropriateZeroRegFor(rn);
    if (imm == 0) {
      csel(rd, rn, zr, cond);
    } else if (imm == 1) {
      csinc(rd, rn, zr, cond);
    } else if (imm == -1) {
      csinv(rd, rn, zr, cond);
    } else {
      UseScratchRegisterScope temps(this);
      Register temp = temps.AcquireSameSizeAs(rn);
      Mov(temp, imm);
      csel(rd, rn, temp, cond);
    }
  } else if (operand.IsShiftedRegister() && (operand.shift_amount() == 0)) {
    // Unshifted register argument.
    csel(rd, rn, operand.reg(), cond);
  } else {
    // All other arguments.
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireSameSizeAs(rn);
    Mov(temp, operand);
    csel(rd, rn, temp, cond);
  }
}

bool MacroAssembler::TryOneInstrMoveImmediate(const Register& dst,
                                              int64_t imm) {
  unsigned n, imm_s, imm_r;
  int reg_size = dst.SizeInBits();
  if (IsImmMovz(imm, reg_size) && !dst.IsSP()) {
    // Immediate can be represented in a move zero instruction. Movz can't write
    // to the stack pointer.
    movz(dst, imm);
    return true;
  } else if (IsImmMovn(imm, reg_size) && !dst.IsSP()) {
    // Immediate can be represented in a move not instruction. Movn can't write
    // to the stack pointer.
    movn(dst, dst.Is64Bits() ? ~imm : (~imm & kWRegMask));
    return true;
  } else if (IsImmLogical(imm, reg_size, &n, &imm_s, &imm_r)) {
    // Immediate can be represented in a logical orr instruction.
    LogicalImmediate(dst, AppropriateZeroRegFor(dst), n, imm_s, imm_r, ORR);
    return true;
  }
  return false;
}

Operand MacroAssembler::MoveImmediateForShiftedOp(const Register& dst,
                                                  int64_t imm,
                                                  PreShiftImmMode mode) {
  int reg_size = dst.SizeInBits();
  // Encode the immediate in a single move instruction, if possible.
  if (TryOneInstrMoveImmediate(dst, imm)) {
    // The move was successful; nothing to do here.
  } else {
    // Pre-shift the immediate to the least-significant bits of the register.
    int shift_low;
    if (reg_size == 64) {
      shift_low = base::bits::CountTrailingZeros(imm);
    } else {
      DCHECK_EQ(reg_size, 32);
      shift_low = base::bits::CountTrailingZeros(static_cast<uint32_t>(imm));
    }

    if (mode == kLimitShiftForSP) {
      // When applied to the stack pointer, the subsequent arithmetic operation
      // can use the extend form to shift left by a maximum of four bits. Right
      // shifts are not allowed, so we filter them out later before the new
      // immediate is tested.
      shift_low = std::min(shift_low, 4);
    }
    int64_t imm_low = imm >> shift_low;

    // Pre-shift the immediate to the most-significant bits of the register. We
    // insert set bits in the least-significant bits, as this creates a
    // different immediate that may be encodable using movn or orr-immediate.
    // If this new immediate is encodable, the set bits will be eliminated by
    // the post shift on the following instruction.
    int shift_high = CountLeadingZeros(imm, reg_size);
    int64_t imm_high = (imm << shift_high) | ((INT64_C(1) << shift_high) - 1);

    if ((mode != kNoShift) && TryOneInstrMoveImmediate(dst, imm_low)) {
      // The new immediate has been moved into the destination's low bits:
      // return a new leftward-shifting operand.
      return Operand(dst, LSL, shift_low);
    } else if ((mode == kAnyShift) && TryOneInstrMoveImmediate(dst, imm_high)) {
      // The new immediate has been moved into the destination's high bits:
      // return a new rightward-shifting operand.
      return Operand(dst, LSR, shift_high);
    } else {
      // Use the generic move operation to set up the immediate.
      Mov(dst, imm);
    }
  }
  return Operand(dst);
}

void MacroAssembler::AddSubMacro(const Register& rd, const Register& rn,
                                 const Operand& operand, FlagsUpdate S,
                                 AddSubOp op) {
  if (operand.IsZero() && rd == rn && rd.Is64Bits() && rn.Is64Bits() &&
      !operand.NeedsRelocation(this) && (S == LeaveFlags)) {
    // The instruction would be a nop. Avoid generating useless code.
    return;
  }

  if (operand.NeedsRelocation(this)) {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireSameSizeAs(rn);
    DCHECK_IMPLIES(temp.IsW(), RelocInfo::IsCompressedEmbeddedObject(
                                   operand.ImmediateRMode()));
    Ldr(temp, operand.immediate());
    AddSubMacro(rd, rn, temp, S, op);
  } else if ((operand.IsImmediate() &&
              !IsImmAddSub(operand.ImmediateValue())) ||
             (rn.IsZero() && !operand.IsShiftedRegister()) ||
             (operand.IsShiftedRegister() && (operand.shift() == ROR))) {
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireSameSizeAs(rn);
    if (operand.IsImmediate()) {
      PreShiftImmMode mode = kAnyShift;

      // If the destination or source register is the stack pointer, we can
      // only pre-shift the immediate right by values supported in the add/sub
      // extend encoding.
      if (rd == sp) {
        // If the destination is SP and flags will be set, we can't pre-shift
        // the immediate at all.
        mode = (S == SetFlags) ? kNoShift : kLimitShiftForSP;
      } else if (rn == sp) {
        mode = kLimitShiftForSP;
      }

      Operand imm_operand =
          MoveImmediateForShiftedOp(temp, operand.ImmediateValue(), mode);
      AddSub(rd, rn, imm_operand, S, op);
    } else {
      Mov(temp, operand);
      AddSub(rd, rn, temp, S, op);
    }
  } else {
    AddSub(rd, rn, operand, S, op);
  }
}

void MacroAssembler::AddSubWithCarryMacro(const Register& rd,
                                          const Register& rn,
                                          const Operand& operand, FlagsUpdate S,
                                          AddSubWithCarryOp op) {
  DCHECK(rd.SizeInBits() == rn.SizeInBits());
  UseScratchRegisterScope temps(this);

  if (operand.NeedsRelocation(this)) {
    Register temp = temps.AcquireX();
    Ldr(temp, operand.immediate());
    AddSubWithCarryMacro(rd, rn, temp, S, op);

  } else if (operand.IsImmediate() ||
             (operand.IsShiftedRegister() && (operand.shift() == ROR))) {
    // Add/sub with carry (immediate or ROR shifted register.)
    Register temp = temps.AcquireSameSizeAs(rn);
    Mov(temp, operand);
    AddSubWithCarry(rd, rn, temp, S, op);

  } else if (operand.IsShiftedRegister() && (operand.shift_amount() != 0)) {
    // Add/sub with carry (shifted register).
    DCHECK(operand.reg().SizeInBits() == rd.SizeInBits());
    DCHECK(operand.shift() != ROR);
    DCHECK(is_uintn(operand.shift_amount(), rd.SizeInBits() == kXRegSizeInBits
                                                ? kXRegSizeInBitsLog2
                                                : kWRegSizeInBitsLog2));
    Register temp = temps.AcquireSameSizeAs(rn);
    EmitShift(temp, operand.reg(), operand.shift(), operand.shift_amount());
    AddSubWithCarry(rd, rn, temp, S, op);

  } else if (operand.IsExtendedRegister()) {
    // Add/sub with carry (extended register).
    DCHECK(operand.reg().SizeInBits() <= rd.SizeInBits());
    // Add/sub extended supports a shift <= 4. We want to support exactly the
    // same modes.
    DCHECK_LE(operand.shift_amount(), 4);
    DCHECK(operand.reg().Is64Bits() ||
           ((operand.extend() != UXTX) && (operand.extend() != SXTX)));
    Register temp = temps.AcquireSameSizeAs(rn);
    EmitExtendShift(temp, operand.reg(), operand.extend(),
                    operand.shift_amount());
    AddSubWithCarry(rd, rn, temp, S, op);

  } else {
    // The addressing mode is directly supported by the instruction.
    AddSubWithCarry(rd, rn, operand, S, op);
  }
}

void MacroAssembler::LoadStoreMacro(const CPURegister& rt,
                                    const MemOperand& addr, LoadStoreOp op) {
  // Call the most common addressing modes used by Liftoff directly for improved
  // compilation performance: X register + immediate, X register + W register.
  Instr memop = op | Rt(rt) | RnSP(addr.base());
  if (addr.IsImmediateOffset()) {
    int64_t offset = addr.offset();
    unsigned size_log2 = CalcLSDataSizeLog2(op);
    if (IsImmLSScaled(offset, size_log2)) {
      LoadStoreScaledImmOffset(memop, static_cast<int>(offset), size_log2);
      return;
    } else if (IsImmLSUnscaled(offset)) {
      LoadStoreUnscaledImmOffset(memop, static_cast<int>(offset));
      return;
    }
  } else if (addr.IsRegisterOffset() && (addr.extend() == UXTW) &&
             (addr.shift_amount() == 0)) {
    LoadStoreWRegOffset(memop, addr.regoffset());
    return;
  }

  // Remaining complex cases handled in sub-function.
  LoadStoreMacroComplex(rt, addr, op);
}

void MacroAssembler::LoadStoreMacroComplex(const CPURegister& rt,
                                           const MemOperand& addr,
                                           LoadStoreOp op) {
  int64_t offset = addr.offset();
  bool is_imm_unscaled = IsImmLSUnscaled(offset);
  if (addr.IsRegisterOffset() ||
      (is_imm_unscaled && (addr.IsPostIndex() || addr.IsPreIndex()))) {
    // Load/store encodable in one instruction.
    LoadStore(rt, addr, op);
  } else if (addr.IsImmediateOffset()) {
    // Load/stores with immediate offset addressing should have been handled by
    // the caller.
    DCHECK(!IsImmLSScaled(offset, CalcLSDataSizeLog2(op)) && !is_imm_unscaled);
    UseScratchRegisterScope temps(this);
    Register temp = temps.AcquireSameSizeAs(addr.base());
    Mov(temp, offset);
    LoadStore(rt, MemOperand(addr.base(), temp), op);
  } else if (addr.IsPostIndex()) {
    // Post-index beyond unscaled addressing range.
    DCHECK(!is_imm_unscaled);
    LoadStore(rt, MemOperand(addr.base()), op);
    add(addr.base(), addr.base(), offset);
  } else {
    // Pre-index beyond unscaled addressing range.
    DCHECK(!is_imm_unscaled && addr.IsPreIndex());
    add(addr.base(), addr.base(), offset);
    LoadStore(rt, MemOperand(addr.base()), op);
  }
}

void MacroAssembler::LoadStorePairMacro(const CPURegister& rt,
                                        const CPURegister& rt2,
                                        const MemOperand& addr,
                                        LoadStorePairOp op) {
  if (addr.IsRegisterOffset()) {
    UseScratchRegisterScope temps(this);
    Register base = addr.base();
    Register temp = temps.AcquireSameSizeAs(base);
    Add(temp, base, addr.regoffset());
    LoadStorePair(rt, rt2, MemOperand(temp), op);
    return;
  }

  int64_t offset = addr.offset();
  unsigned size = CalcLSPairDataSize(op);

  // Check if the offset fits in the immediate field of the appropriate
  // instruction. If not, emit two instructions to perform the operation.
  if (IsImmLSPair(offset, size)) {
    // Encodable in one load/store pair instruction.
    LoadStorePair(rt, rt2, addr, op);
  } else {
    Register base = addr.base();
    if (addr.IsImmediateOffset()) {
      UseScratchRegisterScope temps(this);
      Register temp = temps.AcquireSameSizeAs(base);
      Add(temp, base, offset);
      LoadStorePair(rt, rt2, MemOperand(temp), op);
    } else if (addr.IsPostIndex()) {
      LoadStorePair(rt, rt2, MemOperand(base), op);
      Add(base, base, offset);
    } else {
      DCHECK(addr.IsPreIndex());
      Add(base, base, offset);
      LoadStorePair(rt, rt2, MemOperand(base), op);
    }
  }
}

void MacroAssembler::Adr(const Register& rd, Label* label, AdrHint hint) {
  DCHECK(allow_macro_instructions());
  DCHECK(!rd.IsZero());

  if (hint == kAdrNear) {
    adr(rd, label);
    return;
  }

  DCHECK_EQ(hint, kAdrFar);
  if (label->is_bound()) {
    int label_offset = label->pos() - pc_offset();
    if (Instruction::IsValidPCRelOffset(label_offset)) {
      adr(rd, label);
    } else {
      DCHECK_LE(label_offset, 0);
      int min_adr_offset = -(1 << (Instruction::ImmPCRelRangeBitwidth - 1));
      adr(rd, min_adr_offset);
      Add(rd, rd, label_offset - min_adr_offset);
    }
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.AcquireX();

    InstructionAccurateScope scope(this,
                                   PatchingAssembler::kAdrFarPatchableNInstrs);
    adr(rd, label);
    for (int i = 0; i < PatchingAssembler::kAdrFarPatchableNNops; ++i) {
      nop(ADR_FAR_NOP);
    }
    movz(scratch, 0);
  }
}

void MacroAssembler::B(Label* label, BranchType type, Register reg, int bit) {
  DCHECK((reg == NoReg || type >= kBranchTypeFirstUsingReg) &&
         (bit == -1 || type >= kBranchTypeFirstUsingBit));
  if (kBranchTypeFirstCondition <= type && type <= kBranchTypeLastCondition) {
    B(static_cast<Condition>(type), label);
  } else {
    switch (type) {
      case always:
        B(label);
        break;
      case never:
        break;
      case reg_zero:
        Cbz(reg, label);
        break;
      case reg_not_zero:
        Cbnz(reg, label);
        break;
      case reg_bit_clear:
        Tbz(reg, bit, label);
        break;
      case reg_bit_set:
        Tbnz(reg, bit, label);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void MacroAssembler::B(Label* label, Condition cond) {
  DCHECK(allow_macro_instructions());
  DCHECK((cond != al) && (cond != nv));

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CondBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    b(&done, NegateCondition(cond));
    B(label);
    bind(&done);
  } else {
    b(label, cond);
  }
}

void MacroAssembler::Tbnz(const Register& rt, unsigned bit_pos, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<TestBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    tbz(rt, bit_pos, &done);
    B(label);
    bind(&done);
  } else {
    tbnz(rt, bit_pos, label);
  }
}

void MacroAssembler::Tbz(const Register& rt, unsigned bit_pos, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<TestBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    tbnz(rt, bit_pos, &done);
    B(label);
    bind(&done);
  } else {
    tbz(rt, bit_pos, label);
  }
}

void MacroAssembler::Cbnz(const Register& rt, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CompareBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    cbz(rt, &done);
    B(label);
    bind(&done);
  } else {
    cbnz(rt, label);
  }
}

void MacroAssembler::Cbz(const Register& rt, Label* label) {
  DCHECK(allow_macro_instructions());

  bool need_extra_instructions =
      NeedExtraInstructionsOrRegisterBranch<CompareBranchType>(label);

  if (V8_UNLIKELY(need_extra_instructions)) {
    Label done;
    cbnz(rt, &done);
    B(label);
    bind(&done);
  } else {
    cbz(rt, label);
  }
}

// Pseudo-instructions.

void MacroAssembler::Abs(const Register& rd, const Register& rm,
                         Label* is_not_representable, Label* is_representable) {
  DCHECK(allow_macro_instructions());
  DCHECK(AreSameSizeAndType(rd, rm));

  Cmp(rm, 1);
  Cneg(rd, rm, lt);

  // If the comparison sets the v flag, the input was the smallest value
  // representable by rm, and the mathematical result of abs(rm) is not
  // representable using two's complement.
  if ((is_not_representable != nullptr) && (is_representable != nullptr)) {
    B(is_not_representable, vs);
    B(is_representable);
  } else if (is_not_representable != nullptr) {
    B(is_not_representable, vs);
  } else if (is_representable != nullptr) {
    B(is_representable, vc);
  }
}

void MacroAssembler::Switch(Register scratch, Register value,
                            int case_value_base, Label** labels,
                            int num_labels) {
  Register table = scratch;
  Label fallthrough, jump_table;
  if (case_value_base != 0) {
    Sub(value, value, case_value_base);
  }
  Cmp(value, Immediate(num_labels));
  B(&fallthrough, hs);
  Adr(table, &jump_table);
  Ldr(table, MemOperand(table, value, LSL, kSystemPointerSizeLog2));
  Br(table);
  // Emit the jump table inline, under the assumption that it's not too big.
  // Make sure there are no veneer pool entries in the middle of the table.
  const int jump_table_size = num_labels * kSystemPointerSize;
  CheckVeneerPool(false, false, jump_table_size);
  BlockPoolsScope no_pool_inbetween(this, jump_table_size);
  Align(kSystemPointerSize);
  bind(&jump_table);
  for (int i = 0; i < num_labels; ++i) {
    dcptr(labels[i]);
  }
  bind(&fallthrough);
}

// Abstracted stack operations.

void MacroAssembler::Push(const CPURegister& src0, const CPURegister& src1,
                          const CPURegister& src2, const CPURegister& src3,
                          const CPURegister& src4, const CPURegister& src5,
                          const CPURegister& src6, const CPURegister& src7) {
  DCHECK(AreSameSizeAndType(src0, src1, src2, src3, src4, src5, src6, src7));

  int count = 5 + src5.is_valid() + src6.is_valid() + src6.is_valid();
  int size = src0.SizeInBytes();
  DCHECK_EQ(0, (size * count) % 16);

  PushHelper(4, size, src0, src1, src2, src3);
  PushHelper(count - 4, size, src4, src5, src6, src7);
}

void MacroAssembler::Pop(const CPURegister& dst0, const CPURegister& dst1,
                         const CPURegister& dst2, const CPURegister& dst3,
                         const CPURegister& dst4, const CPURegister& dst5,
                         const CPURegister& dst6, const CPURegister& dst7) {
  // It is not valid to pop into the same register more than once in one
  // instruction, not even into the zero register.
  DCHECK(!AreAliased(dst0, dst1, dst2, dst3, dst4, dst5, dst6, dst7));
  DCHECK(AreSameSizeAndType(dst0, dst1, dst2, dst3, dst4, dst5, dst6, dst7));
  DCHECK(dst0.is_valid());

  int count = 5 + dst5.is_valid() + dst6.is_valid() + dst7.is_valid();
  int size = dst0.SizeInBytes();
  DCHECK_EQ(0, (size * count) % 16);

  PopHelper(4, size, dst0, dst1, dst2, dst3);
  PopHelper(count - 4, size, dst4, dst5, dst6, dst7);
}

void MacroAssembler::PushMultipleTimes(CPURegister src, Register count) {
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireSameSizeAs(count);

  Label loop, leftover2, leftover1, done;

  Subs(temp, count, 4);
  B(mi, &leftover2);

  // Push groups of four first.
  Bind(&loop);
  Subs(temp, temp, 4);
  PushHelper(4, src.SizeInBytes(), src, src, src, src);
  B(pl, &loop);

  // Push groups of two.
  Bind(&leftover2);
  Tbz(count, 1, &leftover1);
  PushHelper(2, src.SizeInBytes(), src, src, NoReg, NoReg);

  // Push the last one (if required).
  Bind(&leftover1);
  Tbz(count, 0, &done);
  PushHelper(1, src.SizeInBytes(), src, NoReg, NoReg, NoReg);

  Bind(&done);
}

void MacroAssembler::PushHelper(int count, int size, const CPURegister& src0,
                                const CPURegister& src1,
                                const CPURegister& src2,
                                const CPURegister& src3) {
  // Ensure that we don't unintentially modify scratch or debug registers.
  InstructionAccurateScope scope(this);

  DCHECK(AreSameSizeAndType(src0, src1, src2, src3));
  DCHECK(size == src0.SizeInBytes());

  // When pushing multiple registers, the store order is chosen such that
  // Push(a, b) is equivalent to Push(a) followed by Push(b).
  switch (count) {
    case 1:
      DCHECK(src1.IsNone() && src2.IsNone() && src3.IsNone());
      str(src0, MemOperand(sp, -1 * size, PreIndex));
      break;
    case 2:
      DCHECK(src2.IsNone() && src3.IsNone());
      stp(src1, src0, MemOperand(sp, -2 * size, PreIndex));
      break;
    case 3:
      DCHECK(src3.IsNone());
      stp(src2, src1, MemOperand(sp, -3 * size, PreIndex));
      str(src0, MemOperand(sp, 2 * size));
      break;
    case 4:
      // Skip over 4 * size, then fill in the gap. This allows four W registers
      // to be pushed using sp, whilst maintaining 16-byte alignment for sp
      // at all times.
      stp(src3, src2, MemOperand(sp, -4 * size, PreIndex));
      stp(src1, src0, MemOperand(sp, 2 * size));
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::PopHelper(int count, int size, const CPURegister& dst0,
                               const CPURegister& dst1, const CPURegister& dst2,
                               const CPURegister& dst3) {
  // Ensure that we don't unintentially modify scratch or debug registers.
  InstructionAccurateScope scope(this);

  DCHECK(AreSameSizeAndType(dst0, dst1, dst2, dst3));
  DCHECK(size == dst0.SizeInBytes());

  // When popping multiple registers, the load order is chosen such that
  // Pop(a, b) is equivalent to Pop(a) followed by Pop(b).
  switch (count) {
    case 1:
      DCHECK(dst1.IsNone() && dst2.IsNone() && dst3.IsNone());
      ldr(dst0, MemOperand(sp, 1 * size, PostIndex));
      break;
    case 2:
      DCHECK(dst2.IsNone() && dst3.IsNone());
      ldp(dst0, dst1, MemOperand(sp, 2 * size, PostIndex));
      break;
    case 3:
      DCHECK(dst3.IsNone());
      ldr(dst2, MemOperand(sp, 2 * size));
      ldp(dst0, dst1, MemOperand(sp, 3 * size, PostIndex));
      break;
    case 4:
      // Load the higher addresses first, then load the lower addresses and
      // skip the whole block in the second instruction. This allows four W
      // registers to be popped using sp, whilst maintaining 16-byte alignment
      // for sp at all times.
      ldp(dst2, dst3, MemOperand(sp, 2 * size));
      ldp(dst0, dst1, MemOperand(sp, 4 * size, PostIndex));
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::PokePair(const CPURegister& src1, const CPURegister& src2,
                              int offset) {
  DCHECK(AreSameSizeAndType(src1, src2));
  DCHECK((offset >= 0) && ((offset % src1.SizeInBytes()) == 0));
  Stp(src1, src2, MemOperand(sp, offset));
}

void MacroAssembler::PeekPair(const CPURegister& dst1, const CPURegister& dst2,
                              int offset) {
  DCHECK(AreSameSizeAndType(dst1, dst2));
  DCHECK((offset >= 0) && ((offset % dst1.SizeInBytes()) == 0));
  Ldp(dst1, dst2, MemOperand(sp, offset));
}

void MacroAssembler::PushCalleeSavedRegisters() {
  ASM_CODE_COMMENT(this);
  // Ensure that the macro-assembler doesn't use any scratch registers.
  InstructionAccurateScope scope(this);

  MemOperand tos(sp, -2 * static_cast<int>(kXRegSize), PreIndex);

  stp(d14, d15, tos);
  stp(d12, d13, tos);
  stp(d10, d11, tos);
  stp(d8, d9, tos);

  stp(x27, x28, tos);
  stp(x25, x26, tos);
  stp(x23, x24, tos);
  stp(x21, x22, tos);
  stp(x19, x20, tos);

  static_assert(
      EntryFrameConstants::kCalleeSavedRegisterBytesPushedBeforeFpLrPair ==
      18 * kSystemPointerSize);

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
    // Use the stack pointer's value immediately before pushing the LR as the
    // context for signing it. This is what the StackFrameIterator expects.
    pacibsp();
#endif

    stp(x29, x30, tos);  // fp, lr

    static_assert(
        EntryFrameConstants::kCalleeSavedRegisterBytesPushedAfterFpLrPair == 0);
}

void MacroAssembler::PopCalleeSavedRegisters() {
  ASM_CODE_COMMENT(this);
  // Ensure that the macro-assembler doesn't use any scratch registers.
  InstructionAccurateScope scope(this);

  MemOperand tos(sp, 2 * kXRegSize, PostIndex);

  ldp(x29, x30, tos);  // fp, lr

#ifdef V8_ENABLE_CONTROL_FLOW_INTEGRITY
  // The context (stack pointer value) for authenticating the LR here must
  // match the one used for signing it (see `PushCalleeSavedRegisters`).
  autibsp();
#endif

    ldp(x19, x20, tos);
    ldp(x21, x22, tos);
    ldp(x23, x24, tos);
    ldp(x25, x26, tos);
    ldp(x27, x28, tos);

    ldp(d8, d9, tos);
    ldp(d10, d11, tos);
    ldp(d12, d13, tos);
    ldp(d14, d15, tos);
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
// Only used when leaptiering is disabled.
void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry,
                               Register scratch) {
  // ----------- S t a t e -------------
  //  -- x0 : actual argument count
  //  -- x3 : new target (preserved for callee if needed, and caller)
  //  -- x1 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  ASM_CODE_COMMENT(masm);
  DCHECK(!AreAliased(x1, x3, optimized_code_entry, scratch));

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  __ AssertCode(optimized_code_entry);
  __ JumpIfCodeIsMarkedForDeoptimization(optimized_code_entry, scratch,
                                         &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure into
  // the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, x1);
  static_assert(kJavaScriptCallCodeStartRegister == x2, "ABI mismatch");
  __ Move(x2, optimized_code_entry);
  __ JumpCodeObject(x2, kJSEntrypointTag);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}
#endif  // V8_ENABLE_LEAPTIERING

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, scratch, scratch, FEEDBACK_CELL_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    IsObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure));

#ifdef V8_ENABLE_LEAPTIERING
  UNREACHABLE();
#else
  // Store code entry in the closure.
  AssertCode(optimized_code);
  StoreCodePointerField(optimized_code,
                        FieldMemOperand(closure, JSFunction::kCodeOffset));
  RecordWriteField(closure, JSFunction::kCodeOffset, optimized_code,
                   kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   ReadOnlyCheck::kOmit, SlotDescriptor::ForCodePointerSlot());
#endif  // V8_ENABLE_LEAPTIERING
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  ASM_CODE_COMMENT(this);
  // ----------- S t a t e -------------
  //  -- x0 : actual argument count (preserved for callee)
  //  -- x1 : target function (preserved for callee)
  //  -- x3 : new target (preserved for callee)
  //  -- x4 : dispatch handle (preserved for callee)
  // -----------------------------------
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target, the actual
    // argument count, and the dispatch handle.
    Register lastreg = V8_ENABLE_LEAPTIERING_BOOL
                           ? kJavaScriptCallDispatchHandleRegister
                           : padreg;
    SmiTag(kJavaScriptCallArgCountRegister);
    // No need to SmiTag the dispatch handle as it always looks like a Smi.
    static_assert(kJSDispatchHandleShift > 0);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister, lastreg);
    // Push another copy as a parameter to the runtime call.
    PushArgument(kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    Mov(x2, x0);

    // Restore target function, new target, actual argument count, and dispatch
    // handle.
    Pop(lastreg, kJavaScriptCallArgCountRegister,
        kJavaScriptCallNewTargetRegister, kJavaScriptCallTargetRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }

  static_assert(kJavaScriptCallCodeStartRegister == x2, "ABI mismatch");
  JumpCodeObject(x2, kJSEntrypointTag);
}

#ifndef V8_ENABLE_LEAPTIERING

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
Condition MacroAssembler::LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  uint32_t flag_mask =
      FeedbackVector::FlagMaskForNeedsProcessingCheckFrom(current_code_kind);
  Ldrh(flags, FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  Tst(flags, flag_mask);
  return ne;
}

void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  B(LoadFeedbackVectorFlagsAndCheckIfNeedsProcessing(flags, feedback_vector,
                                                     current_code_kind),
    flags_need_processing);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available.
  TestAndBranchIfAllClear(flags,
                          FeedbackVector::kFlagsTieringStateIsAnyRequested,
                          &maybe_needs_logging);
  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  TestAndBranchIfAllClear(flags, FeedbackVector::LogNextExecutionBit::kMask,
                          &maybe_has_optimized_code);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  // This tiering logic is only needed if leaptiering is disabled. Otherwise
  // we'll automatically tier up through the dispatch table.
  Register optimized_code_entry = x7;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset));
  TailCallOptimizedCodeSlot(this, optimized_code_entry, x4);
}

#endif  // !V8_ENABLE_LEAPTIERING

Condition MacroAssembler::CheckSmi(Register object) {
  static_assert(kSmiTag == 0);
  Tst(object, kSmiTagMask);
  return eq;
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertSpAligned() {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  HardAbortScope hard_abort(this);  // Avoid calls to Abort.
  // Arm64 requires the stack pointer to be 16-byte aligned prior to address
  // calculation.
  UseScratchRegisterScope scope(this);
  Register temp = scope.AcquireX();
  Mov(temp, sp);
  Tst(temp, 15);
  Check(eq, AbortReason::kUnexpectedStackPointer);
}

void MacroAssembler::AssertFPCRState(Register fpcr) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label unexpected_mode, done;
  UseScratchRegisterScope temps(this);
  if (fpcr.IsNone()) {
    fpcr = temps.AcquireX();
    Mrs(fpcr, FPCR);
  }

  // Settings left to their default values:
  //   - Assert that flush-to-zero is not set.
  Tbnz(fpcr, FZ_offset, &unexpected_mode);
  //   - Assert that the rounding mode is nearest-with-ties-to-even.
  static_assert(FPTieEven == 0);
  Tst(fpcr, RMode_mask);
  B(eq, &done);

  Bind(&unexpected_mode);
  Abort(AbortReason::kUnexpectedFPCRMode);

  Bind(&done);
}

void MacroAssembler::AssertSmi(Register object, AbortReason reason) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  Tst(object, kSmiTagMask);
  Check(eq, reason);
}

void MacroAssembler::AssertNotSmi(Register object, AbortReason reason) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  Tst(object, kSmiTagMask);
  Check(ne, reason);
}

void MacroAssembler::AssertZeroExtended(Register int32_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Tst(int32_register.X(), kMaxUInt32);
  Check(ls, AbortReason::k32BitValueInRegisterIsNotZeroExtended);
}

void MacroAssembler::AssertMap(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsNotAMap);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();

  IsObjectType(object, temp, temp, MAP_TYPE);
  Check(eq, AbortReason::kOperandIsNotAMap);
}

void MacroAssembler::AssertCode(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsNotACode);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();

  IsObjectType(object, temp, temp, CODE_TYPE);
  Check(eq, AbortReason::kOperandIsNotACode);
}

void MacroAssembler::AssertConstructor(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAConstructor);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();

  LoadMap(temp, object);
  Ldrb(temp, FieldMemOperand(temp, Map::kBitFieldOffset));
  Tst(temp, Operand(Map::Bits1::IsConstructorBit::kMask));

  Check(ne, AbortReason::kOperandIsNotAConstructor);
}

void MacroAssembler::AssertFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAFunction);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  LoadMap(temp, object);
  CompareInstanceTypeRange(temp, temp, FIRST_JS_FUNCTION_TYPE,
                           LAST_JS_FUNCTION_TYPE);
  Check(ls, AbortReason::kOperandIsNotAFunction);
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAFunction);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  LoadMap(temp, object);
  CompareInstanceTypeRange(temp, temp, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                           LAST_CALLABLE_JS_FUNCTION_TYPE);
  Check(ls, AbortReason::kOperandIsNotACallableFunction);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotABoundFunction);

  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();

  IsObjectType(object, temp, temp, JS_BOUND_FUNCTION_TYPE);
  Check(eq, AbortReason::kOperandIsNotABoundFunction);
}

void MacroAssembler::AssertSmiOrHeapObjectInMainCompressionCage(
    Register object) {
  if (!PointerCompressionIsEnabled()) return;
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  // We may not have any scratch registers so we preserve our input register.
  Push(object, xzr);
  Label ok;
  B(&ok, CheckSmi(object));
  Mov(object, Operand(object, LSR, 32));
  // Either the value is now equal to the right-shifted pointer compression
  // cage base or it's zero if we got a compressed pointer register as input.
  Cmp(object, 0);
  B(kEqual, &ok);
  Cmp(object, Operand(kPtrComprCageBaseRegister, LSR, 32));
  Check(kEqual, AbortReason::kObjectNotTagged);
  bind(&ok);
  Pop(xzr, object);
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAGeneratorObject);

  // Load map
  UseScratchRegisterScope temps(this);
  Register temp = temps.AcquireX();
  LoadMap(temp, object);

  // Load instance type and check if JSGeneratorObject
  CompareInstanceTypeRange(temp, temp, FIRST_JS_GENERATOR_OBJECT_TYPE,
                           LAST_JS_GENERATOR_OBJECT_TYPE);
  // Restore generator object to register and perform assertion
  Check(ls, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Label done_checking;
  AssertNotSmi(object);
  JumpIfRoot(object, RootIndex::kUndefinedValue, &done_checking);
  LoadMap(scratch, object);
  CompareInstanceType(scratch, scratch, ALLOCATION_SITE_TYPE);
  Assert(eq, AbortReason::kExpectedUndefinedOrCell);
  Bind(&done_checking);
}

void MacroAssembler::AssertPositiveOrZero(Register value) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label done;
  int sign_bit = value.Is64Bits() ? kXSignBit : kWSignBit;
  Tbz(value, sign_bit, &done);
  Abort(AbortReason::kUnexpectedNegativeValue);
  Bind(&done);
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  LoadMap(map_tmp, object);
  CompareInstanceType(map_tmp, tmp, LAST_NAME_TYPE);
  B(kUnsignedLessThanEqual, &ok);

  CompareInstanceType(map_tmp, tmp, FIRST_JS_RECEIVER_TYPE);
  B(kUnsignedGreaterThanEqual, &ok);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  B(kEqual, &ok);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  B(kEqual, &ok);

  CompareRoot(object, RootIndex::kUndefinedValue);
  B(kEqual, &ok);

  CompareRoot(object, RootIndex::kTrueValue);
  B(kEqual, &ok);

  CompareRoot(object, RootIndex::kFalseValue);
  B(kEqual, &ok);

  CompareRoot(object, RootIndex::kNullValue);
  B(kEqual, &ok);

  Abort(abort_reason);

  bind(&ok);
}

void MacroAssembler::Assert(Condition cond, AbortReason reason) {
  if (v8_flags.debug_code) {
    Check(cond, reason);
  }
}

void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::CopySlots(int dst, Register src, Register slot_count) {
  DCHECK(!src.IsZero());
  UseScratchRegisterScope scope(this);
  Register dst_reg = scope.AcquireX();
  SlotAddress(dst_reg, dst);
  SlotAddress(src, src);
  CopyDoubleWords(dst_reg, src, slot_count);
}

void MacroAssembler::CopySlots(Register dst, Register src,
                               Register slot_count) {
  DCHECK(!dst.IsZero() && !src.IsZero());
  SlotAddress(dst, dst);
  SlotAddress(src, src);
  CopyDoubleWords(dst, src, slot_count);
}

void MacroAssembler::CopyDoubleWords(Register dst, Register src, Register count,
                                     CopyDoubleWordsMode mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(dst, src, count));

  if (v8_flags.debug_code) {
    Register pointer1 = dst;
    Register pointer2 = src;
    if (mode == kSrcLessThanDst) {
      pointer1 = src;
      pointer2 = dst;
    }
    // Copy requires pointer1 < pointer2 || (pointer1 - pointer2) >= count.
    Label pointer1_below_pointer2;
    Subs(pointer1, pointer1, pointer2);
    B(lt, &pointer1_below_pointer2);
    Cmp(pointer1, count);
    Check(ge, AbortReason::kOffsetOutOfRange);
    Bind(&pointer1_below_pointer2);
    Add(pointer1, pointer1, pointer2);
  }
  static_assert(kSystemPointerSize == kDRegSize,
                "pointers must be the same size as doubles");

  if (mode == kDstLessThanSrcAndReverse) {
    Add(src, src, Operand(count, LSL, kSystemPointerSizeLog2));
    Sub(src, src, kSystemPointerSize);
  }

  int src_direction = (mode == kDstLessThanSrc) ? 1 : -1;
  int dst_direction = (mode == kSrcLessThanDst) ? -1 : 1;

  UseScratchRegisterScope scope(this);
  VRegister temp0 = scope.AcquireD();
  VRegister temp1 = scope.AcquireD();

  Label pairs, loop, done;

  Tbz(count, 0, &pairs);
  Ldr(temp0, MemOperand(src, src_direction * kSystemPointerSize, PostIndex));
  Sub(count, count, 1);
  Str(temp0, MemOperand(dst, dst_direction * kSystemPointerSize, PostIndex));

  Bind(&pairs);
  if (mode == kSrcLessThanDst) {
    // Adjust pointers for post-index ldp/stp with negative offset:
    Sub(dst, dst, kSystemPointerSize);
    Sub(src, src, kSystemPointerSize);
  } else if (mode == kDstLessThanSrcAndReverse) {
    Sub(src, src, kSystemPointerSize);
  }
  Bind(&loop);
  Cbz(count, &done);
  Ldp(temp0, temp1,
      MemOperand(src, 2 * src_direction * kSystemPointerSize, PostIndex));
  Sub(count, count, 2);
  if (mode == kDstLessThanSrcAndReverse) {
    Stp(temp1, temp0,
        MemOperand(dst, 2 * dst_direction * kSystemPointerSize, PostIndex));
  } else {
    Stp(temp0, temp1,
        MemOperand(dst, 2 * dst_direction * kSystemPointerSize, PostIndex));
  }
  B(&loop);

  // TODO(all): large copies may benefit from using temporary Q registers
  // to copy four double words per iteration.

  Bind(&done);
}

void MacroAssembler::SlotAddress(Register dst, int slot_offset) {
  Add(dst, sp, slot_offset << kSystemPointerSizeLog2);
}

void MacroAssembler::SlotAddress(Register dst, Register slot_offset) {
  Add(dst, sp, Operand(slot_offset, LSL, kSystemPointerSizeLog2));
}

void MacroAssembler::CanonicalizeNaN(const VRegister& dst,
                                     const VRegister& src) {
  AssertFPCRState();

  // Subtra
"""


```