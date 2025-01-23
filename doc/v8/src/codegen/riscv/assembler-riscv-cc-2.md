Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code, specifically focusing on its role in V8's RISC-V code generation. It also has specific constraints about `.tq` files, JavaScript relationships, logical inference, common errors, and finally, a concise summary of the functionality.

2. **Initial Scan and Identification:** The first step is to quickly read through the code to identify key components and patterns. Keywords like `Assembler`, `emit`, `ConstantPool`, `instr_at_put`, and register names (e.g., `zero_reg`, `t3`, `t5`) jump out. The presence of `#if V8_TARGET_ARCH_RISCV64` and `#elif V8_TARGET_ARCH_RISCV32` immediately indicates architecture-specific code. The LLVM code block further reinforces the idea of instruction generation.

3. **Categorize Functionality:** Based on the initial scan, we can start grouping the code into logical sections:

    * **Instruction Emission:**  The `emit()` functions are clearly responsible for adding raw instruction data to the buffer. The different overloads for `Instr`, `ShortInstr`, and `uint64_t` suggest handling different instruction formats or data types.

    * **Instruction Modification:** The `instr_at_put()` functions are for writing instructions at specific locations in the buffer, which is crucial for patching and code modification.

    * **Constant Pool Management:** The `ConstantPool` class is a significant part, responsible for managing and emitting constant values used by the generated code. Its methods (`EmitPrologue`, `SetLoadOffsetToConstPoolEntry`, `Check`, `ComputeSize`) point to a sophisticated system for handling constants.

    * **Immediate Loading (LLVM Code):** The section labeled "LLVM Code" and containing functions like `RecursiveLi` and `RecursiveLiCount` deals with efficiently loading large immediate values into registers, a common task in assembly programming.

    * **Utility Functions:** `DefaultTmpList` and `DefaultFPTmpList` seem to provide default sets of temporary registers, likely used internally by the assembler.

4. **Analyze Key Sections in Detail:**  Now, dive deeper into the important parts:

    * **`emit()`:** Notice the `CheckBuffer()` call – this suggests dynamic buffer management. The `disassembleInstr()` call is for debugging purposes.

    * **`instr_at_put()`:** The `WritableJitAllocation` parameter indicates the ability to write to different memory locations, possibly for dynamic code generation.

    * **`ConstantPool`:**  Understand the purpose of the prologue (setting up the constant pool), how entries are accessed (PC-relative), and the checking mechanism (`Check()`) to ensure the pool is emitted when needed. The constants like `kMaxDistToPool` and `kCheckInterval` provide context on the pool's behavior.

    * **`RecursiveLi`:**  Recognize this as a common optimization technique in RISC-V for loading large immediates, breaking them down into smaller instructions. The logic involves checking the number of instructions needed and potentially using shifts to optimize the sequence.

5. **Address the Specific Constraints:**

    * **`.tq` Files:** The code is `.cc`, so it's C++, not Torque. This is a direct check.

    * **JavaScript Relationship:** Think about how this assembler code relates to JavaScript. The key connection is *code generation*. The assembler is used by V8 to translate JavaScript code into machine instructions that the CPU can execute. A simple example would be generating code for an addition operation.

    * **Code Logic Inference:** Choose a relevant function, like `SetLoadOffsetToConstPoolEntry`, and trace its logic. Hypothesize inputs (instruction values, addresses) and determine the expected output (modified instruction values). This demonstrates an understanding of how the function works.

    * **Common Programming Errors:** Consider typical mistakes when working with assemblers or low-level code. Buffer overflows (related to `CheckBuffer`) and incorrect immediate loading (addressed by the LLVM code) are good examples.

6. **Synthesize the Summary:** Combine the detailed analysis into a concise summary of the file's purpose. Focus on the key functionalities identified in step 3.

7. **Review and Refine:**  Read through the entire response to ensure accuracy, clarity, and completeness. Check that all the constraints of the request have been addressed. Make sure the language is precise and avoids jargon where possible. For instance, initially, I might have just said "emits instructions," but refining it to "provides functionalities for emitting RISC-V machine code instructions" is more precise.

**Self-Correction Example During the Process:**  Initially, when looking at the LLVM code, I might have just thought, "It loads immediates."  However, the prompt asks for *functionality*. Realizing that the *optimization* of loading large immediates using sequences of smaller instructions is the core functionality leads to a more accurate description. Similarly, connecting the assembler directly to *JavaScript code generation* is a crucial step beyond just saying "it generates assembly."
这是对 `v8/src/codegen/riscv/assembler-riscv.cc` 源代码的功能归纳，它是第 3 部分，也是最后一部分。基于前两部分的分析，我们可以更全面地理解其功能。

**功能归纳:**

`v8/src/codegen/riscv/assembler-riscv.cc` 文件是 V8 JavaScript 引擎中用于 RISC-V 架构的代码生成器（Assembler）的实现。它提供了构建 RISC-V 机器码指令的核心功能。

**具体功能点（基于提供的代码片段和前两部分的推断）：**

1. **指令发射 (Instruction Emission):**
   - 提供了 `emit()` 方法的不同重载，用于将不同类型的 RISC-V 指令 (如 `Instr`, `ShortInstr`) 和原始数据 (`uint64_t`) 写入到代码缓冲区中。
   - `EmitHelper()` 可能是实际执行写入操作的底层函数。
   - 在发射指令前后进行调试输出 (`DEBUG_PRINTF`) 和快速检查跳转池 (`CheckTrampolinePoolQuick`)。
   - 在发射指令前会检查缓冲区空间 (`CheckBuffer()`)，并在需要时进行动态扩容，除非缓冲区增长被阻止 (`is_buffer_growth_blocked()`)。

2. **指令修改 (Instruction Modification):**
   - 提供了 `instr_at_put()` 方法的不同重载，允许在代码缓冲区的指定位置 (偏移量或绝对地址) 写入或修改 RISC-V 指令。
   - 可以选择性地使用 `WritableJitAllocation` 对象进行写入，这可能用于管理可写的 JIT 代码内存区域。

3. **常量池管理 (Constant Pool Management):**
   - 实现了 `ConstantPool` 类，用于管理和发射常量池。常量池存储了代码中使用的常量值，例如立即数、字面量等。
   - `EmitPrologue()` 方法用于在常量池的开头生成序言代码，包括对齐和大小记录。
   - `PrologueSize()` 计算序言的大小。
   - `SetLoadOffsetToConstPoolEntry()` 用于调整加载指令的偏移量，使其指向常量池中的特定条目。这涉及修改 `auipc` 和 `load` 指令。
   - `Check()` 方法用于判断何时需要发射常量池，并处理分支超出范围的情况（可能通过插入跳转指令，即veneers）。
   - 定义了常量池相关的常量，如最大距离 (`kMaxDistToPool32`, `kMaxDistToPool64`)、检查间隔 (`kCheckInterval`) 和近似距离 (`kApproxDistToPool32`, `kApproxDistToPool64`)，用于优化常量池的布局和发射时机。

4. **高效的立即数加载 (Efficient Immediate Loading - LLVM Code):**
   - 包含了一段从 LLVM 项目中借鉴的代码，用于高效地将 64 位立即数加载到寄存器中 (`RecursiveLi`, `RecursiveLiImpl`)。
   - 通过递归地构建指令序列，利用 `lui`, `addi`, `slli` 等指令的组合，尽可能减少所需的指令数量。
   - `RecursiveLiCount` 和 `RecursiveLiImplCount` 用于计算加载特定立即数所需的指令数量，用于优化指令选择。
   - `GeneralLiCount` 提供了更通用的计算加载立即数指令数量的方法，并考虑了临时寄存器的使用。

5. **默认临时寄存器列表 (Default Temporary Register Lists):**
   - 提供了 `DefaultTmpList()` 和 `DefaultFPTmpList()` 方法，返回默认的通用寄存器和浮点寄存器列表，用作临时寄存器。

**关于 .tq 结尾的文件：**

如果 `v8/src/codegen/riscv/assembler-riscv.cc` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。Torque 是一种 V8 自研的类型化的中间语言，用于生成高效的 C++ 代码，包括汇编代码生成器。然而，根据您提供的信息，文件名是 `.cc`，因此它是 C++ 源代码。

**与 JavaScript 功能的关系及示例：**

`v8/src/codegen/riscv/assembler-riscv.cc` 与 JavaScript 的执行有着直接的关系。当 V8 引擎需要执行一段 JavaScript 代码时，它会将其编译成机器码。这个 `assembler-riscv.cc` 文件中的代码就是负责生成 RISC-V 架构的机器码指令的。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 执行 `add(5, 10)` 时，`assembler-riscv.cc` 中的代码会被调用，生成类似于以下的 RISC-V 指令序列 (简化示例)：

```assembly
# 假设 a 和 b 的值分别在寄存器 x10 和 x11 中
lw  t0, 0(x10)  # 将 a 的值加载到临时寄存器 t0
lw  t1, 0(x11)  # 将 b 的值加载到临时寄存器 t1
add t2, t0, t1  # 将 t0 和 t1 的值相加，结果存储在 t2 中
sw  t2, 0(sp)   # 将结果存储到栈中 (作为返回值)
ret             # 返回
```

`assembler-riscv.cc` 负责生成像 `lw`, `add`, `sw`, `ret` 这样的 RISC-V 指令。

**代码逻辑推理示例：**

**假设输入：**

- `load_offset` (加载指令的地址偏移): 100
- `instr_auipc` (要修改的 auipc 指令):  0x00000537  (lui a0, 0)
- `instr_load` (要修改的 load 指令): 0x00a58583  (lw a1, 0(a1))
- `entry_offset` (常量池条目的地址): 200

**输出：**

`SetLoadOffsetToConstPoolEntry` 函数会计算 `entry_offset` 和 `load_offset` 之间的距离，并将该距离编码到 `instr_auipc` 和 `instr_load` 指令中。

1. **计算距离:** `distance = 200 - (base_address + 100)`，假设 `base_address` 是代码段的起始地址。为了简化，我们假设 `base_address` 为 0，则 `distance = 100`。

2. **计算 Hi20 和 Lo12:**
   - `Hi20 = ((100 + 0x800) >> 12) = (2148 >> 12) = 0`
   - `Lo12 = 100 << 20 >> 20 = 100`

3. **修改指令:**
   - `SetAuipcOffset(0, 0x00000537)` 结果仍然是 `0x00000537` (因为偏移已经是 0)。
   - `SetLoadOffset(100, 0x00a58583)` 会将 `lw` 指令的立即数字段修改为 100，得到例如 `0x06458583` (实际编码会更复杂，取决于 RISC-V 指令格式)。

**用户常见的编程错误（在手写汇编或理解汇编代码时）：**

1. **错误的立即数范围:** RISC-V 的指令中立即数的位数是有限的。尝试使用超出范围的立即数会导致错误。
   ```c++
   // 错误示例：尝试将一个超出 12 位有符号数范围的立即数加载到寄存器
   // 假设 addi 指令的立即数范围是 -2048 到 2047
   // assm_->addi(t0, zero_reg, 3000); // 这可能会生成错误的代码或需要更复杂的指令序列
   ```

2. **对齐错误:**  某些 RISC-V 指令（如加载双字）需要特定的内存对齐。未对齐的访问会导致异常。
   ```c++
   // 错误示例：尝试从一个奇数地址加载双字
   // Address odd_address = ...;
   // assm_->ld(t0, odd_address); // 这会导致对齐错误
   ```

3. **寄存器使用错误:** 错误地使用了保留寄存器或覆盖了不应该覆盖的寄存器。
   ```c++
   // 错误示例：错误地修改了栈指针 sp 而没有正确恢复
   // assm_->addi(sp, sp, 8); // 移动栈指针
   // ... 一些操作 ...
   // 如果没有相应的恢复操作，可能会导致栈溢出或程序崩溃
   ```

4. **条件分支目标错误:**  条件分支指令的目标地址计算错误，导致跳转到错误的位置。

**总结 `v8/src/codegen/riscv/assembler-riscv.cc` 的功能：**

总而言之，`v8/src/codegen/riscv/assembler-riscv.cc` 是 V8 引擎中 RISC-V 架构的核心汇编器，它提供了生成、修改和管理 RISC-V 机器码指令以及相关数据结构（如常量池）的功能。它是将 JavaScript 代码转化为可执行机器码的关键组件，并包含了优化立即数加载的策略。

### 提示词
```
这是目录为v8/src/codegen/riscv/assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
) {
  if (!is_buffer_growth_blocked()) {
    CheckBuffer();
  }
  DEBUG_PRINTF("%p(%d): ", pc_, pc_offset());
  EmitHelper(x);
  disassembleInstr(pc_ - sizeof(x));
  CheckTrampolinePoolQuick();
}

void Assembler::emit(ShortInstr x) {
  if (!is_buffer_growth_blocked()) {
    CheckBuffer();
  }
  DEBUG_PRINTF("%p(%d): ", pc_, pc_offset());
  EmitHelper(x);
  disassembleInstr(pc_ - sizeof(x));
  CheckTrampolinePoolQuick();
}

void Assembler::emit(uint64_t data) {
  DEBUG_PRINTF("%p(%d): ", pc_, pc_offset());
  if (!is_buffer_growth_blocked()) CheckBuffer();
  EmitHelper(data);
}

void Assembler::instr_at_put(int pos, Instr instr,
                             WritableJitAllocation* jit_allocation) {
  if (jit_allocation) {
    jit_allocation->WriteUnalignedValue(
        reinterpret_cast<Address>(buffer_start_ + pos), instr);
  } else {
    *reinterpret_cast<Instr*>(buffer_start_ + pos) = instr;
  }
}

void Assembler::instr_at_put(int pos, ShortInstr instr,
                             WritableJitAllocation* jit_allocation) {
  if (jit_allocation) {
    jit_allocation->WriteUnalignedValue(
        reinterpret_cast<Address>(buffer_start_ + pos), instr);
  } else {
    *reinterpret_cast<ShortInstr*>(buffer_start_ + pos) = instr;
  }
}

void Assembler::instr_at_put(Address pc, Instr instr,
                             WritableJitAllocation* jit_allocation) {
  if (jit_allocation) {
    jit_allocation->WriteUnalignedValue(pc, instr);
  } else {
    *reinterpret_cast<Instr*>(pc) = instr;
  }
}

// Constant Pool

void ConstantPool::EmitPrologue(Alignment require_alignment) {
  // Recorded constant pool size is expressed in number of 32-bits words,
  // and includes prologue and alignment, but not the jump around the pool
  // and the size of the marker itself.
  const int marker_size = 1;
  int word_count =
      ComputeSize(Jump::kOmitted, require_alignment) / kInt32Size - marker_size;
#if V8_TARGET_ARCH_RISCV64
  assm_->ld(zero_reg, zero_reg, word_count);
#elif V8_TARGET_ARCH_RISCV32
  assm_->lw(zero_reg, zero_reg, word_count);
#endif
  assm_->EmitPoolGuard();
}

int ConstantPool::PrologueSize(Jump require_jump) const {
  // Prologue is:
  //   j over  ;; if require_jump
  //   ld x0, x0, #pool_size
  //   j 0x0
  int prologue_size = require_jump == Jump::kRequired ? kInstrSize : 0;
  prologue_size += 2 * kInstrSize;
  return prologue_size;
}

void ConstantPool::SetLoadOffsetToConstPoolEntry(int load_offset,
                                                 Instruction* entry_offset,
                                                 const ConstantPoolKey& key) {
  Instr instr_auipc = assm_->instr_at(load_offset);
  Instr instr_load = assm_->instr_at(load_offset + 4);
  // Instruction to patch must be 'ld/lw rd, offset(rd)' with 'offset == 0'.
  DCHECK(assm_->IsAuipc(instr_auipc));
#if V8_TARGET_ARCH_RISCV64
  DCHECK(assm_->IsLd(instr_load));
#elif V8_TARGET_ARCH_RISCV32
  DCHECK(assm_->IsLw(instr_load));
#endif
  DCHECK_EQ(assm_->LoadOffset(instr_load), 1);
  DCHECK_EQ(assm_->AuipcOffset(instr_auipc), 0);
  int32_t distance = static_cast<int32_t>(
      reinterpret_cast<Address>(entry_offset) -
      reinterpret_cast<Address>(assm_->toAddress(load_offset)));
  CHECK(is_int32(distance + 0x800));
  int32_t Hi20 = (((int32_t)distance + 0x800) >> 12);
  int32_t Lo12 = (int32_t)distance << 20 >> 20;
  assm_->instr_at_put(load_offset, SetAuipcOffset(Hi20, instr_auipc));
  assm_->instr_at_put(load_offset + 4, SetLoadOffset(Lo12, instr_load));
}

void ConstantPool::Check(Emission force_emit, Jump require_jump,
                         size_t margin) {
  // Some short sequence of instruction must not be broken up by constant pool
  // emission, such sequences are protected by a ConstPool::BlockScope.
  if (IsBlocked()) {
    // Something is wrong if emission is forced and blocked at the same time.
    DCHECK_EQ(force_emit, Emission::kIfNeeded);
    return;
  }

  // We emit a constant pool only if :
  //  * it is not empty
  //  * emission is forced by parameter force_emit (e.g. at function end).
  //  * emission is mandatory or opportune according to {ShouldEmitNow}.
  if (!IsEmpty() && (force_emit == Emission::kForced ||
                     ShouldEmitNow(require_jump, margin))) {
    // Emit veneers for branches that would go out of range during emission of
    // the constant pool.
    int worst_case_size = ComputeSize(Jump::kRequired, Alignment::kRequired);

    // Check that the code buffer is large enough before emitting the constant
    // pool (this includes the gap to the relocation information).
    int needed_space = worst_case_size + assm_->kGap;
    while (assm_->buffer_space() <= needed_space) {
      assm_->GrowBuffer();
    }

    EmitAndClear(require_jump);
  }
  // Since a constant pool is (now) empty, move the check offset forward by
  // the standard interval.
  SetNextCheckIn(ConstantPool::kCheckInterval);
}

// Pool entries are accessed with pc relative load therefore this cannot be more
// than 1 * MB. Since constant pool emission checks are interval based, and we
// want to keep entries close to the code, we try to emit every 64KB.
const size_t ConstantPool::kMaxDistToPool32 = 1 * MB;
const size_t ConstantPool::kMaxDistToPool64 = 1 * MB;
const size_t ConstantPool::kCheckInterval = 128 * kInstrSize;
const size_t ConstantPool::kApproxDistToPool32 = 64 * KB;
const size_t ConstantPool::kApproxDistToPool64 = kApproxDistToPool32;

const size_t ConstantPool::kOpportunityDistToPool32 = 64 * KB;
const size_t ConstantPool::kOpportunityDistToPool64 = 64 * KB;
const size_t ConstantPool::kApproxMaxEntryCount = 512;

#if defined(V8_TARGET_ARCH_RISCV64)
// LLVM Code
//===- RISCVMatInt.cpp - Immediate materialisation -------------*- C++
//-*--===//
//
//  Part of the LLVM Project, under the Apache License v2.0 with LLVM
//  Exceptions. See https://llvm.org/LICENSE.txt for license information.
//  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
void Assembler::RecursiveLi(Register rd, int64_t val) {
  if (val > 0 && RecursiveLiImplCount(val) > 2) {
    unsigned LeadingZeros = base::bits::CountLeadingZeros((uint64_t)val);
    uint64_t ShiftedVal = (uint64_t)val << LeadingZeros;
    int countFillZero = RecursiveLiImplCount(ShiftedVal) + 1;
    if (countFillZero < RecursiveLiImplCount(val)) {
      RecursiveLiImpl(rd, ShiftedVal);
      srli(rd, rd, LeadingZeros);
      return;
    }
  }
  RecursiveLiImpl(rd, val);
}

int Assembler::RecursiveLiCount(int64_t val) {
  if (val > 0 && RecursiveLiImplCount(val) > 2) {
    unsigned LeadingZeros = base::bits::CountLeadingZeros((uint64_t)val);
    uint64_t ShiftedVal = (uint64_t)val << LeadingZeros;
    // Fill in the bits that will be shifted out with 1s. An example where
    // this helps is trailing one masks with 32 or more ones. This will
    // generate ADDI -1 and an SRLI.
    int countFillZero = RecursiveLiImplCount(ShiftedVal) + 1;
    if (countFillZero < RecursiveLiImplCount(val)) {
      return countFillZero;
    }
  }
  return RecursiveLiImplCount(val);
}

void Assembler::RecursiveLiImpl(Register rd, int64_t Val) {
  if (is_int32(Val)) {
    // Depending on the active bits in the immediate Value v, the following
    // instruction sequences are emitted:
    //
    // v == 0                        : ADDI
    // v[0,12) != 0 && v[12,32) == 0 : ADDI
    // v[0,12) == 0 && v[12,32) != 0 : LUI
    // v[0,32) != 0                  : LUI+ADDI(W)
    int64_t Hi20 = ((Val + 0x800) >> 12) & 0xFFFFF;
    int64_t Lo12 = Val << 52 >> 52;

    if (Hi20) {
      lui(rd, (int32_t)Hi20);
    }

    if (Lo12 || Hi20 == 0) {
      if (Hi20) {
        addiw(rd, rd, Lo12);
      } else {
        addi(rd, zero_reg, Lo12);
      }
    }
    return;
  }

  // In the worst case, for a full 64-bit constant, a sequence of 8
  // instructions (i.e., LUI+ADDIW+SLLI+ADDI+SLLI+ADDI+SLLI+ADDI) has to be
  // emitted. Note that the first two instructions (LUI+ADDIW) can contribute
  // up to 32 bits while the following ADDI instructions contribute up to 12
  // bits each.
  //
  // On the first glance, implementing this seems to be possible by simply
  // emitting the most significant 32 bits (LUI+ADDIW) followed by as many
  // left shift (SLLI) and immediate additions (ADDI) as needed. However, due
  // to the fact that ADDI performs a sign extended addition, doing it like
  // that would only be possible when at most 11 bits of the ADDI instructions
  // are used. Using all 12 bits of the ADDI instructions, like done by GAS,
  // actually requires that the constant is processed starting with the least
  // significant bit.
  //
  // In the following, constants are processed from LSB to MSB but instruction
  // emission is performed from MSB to LSB by recursively calling
  // generateInstSeq. In each recursion, first the lowest 12 bits are removed
  // from the constant and the optimal shift amount, which can be greater than
  // 12 bits if the constant is sparse, is determined. Then, the shifted
  // remaining constant is processed recursively and gets emitted as soon as
  // it fits into 32 bits. The emission of the shifts and additions is
  // subsequently performed when the recursion returns.

  int64_t Lo12 = Val << 52 >> 52;
  int64_t Hi52 = ((uint64_t)Val + 0x800ull) >> 12;
  int ShiftAmount = 12 + base::bits::CountTrailingZeros((uint64_t)Hi52);
  Hi52 = signExtend(Hi52 >> (ShiftAmount - 12), 64 - ShiftAmount);

  // If the remaining bits don't fit in 12 bits, we might be able to reduce
  // the shift amount in order to use LUI which will zero the lower 12 bits.
  bool Unsigned = false;
  if (ShiftAmount > 12 && !is_int12(Hi52)) {
    if (is_int32((uint64_t)Hi52 << 12)) {
      // Reduce the shift amount and add zeros to the LSBs so it will match
      // LUI.
      ShiftAmount -= 12;
      Hi52 = (uint64_t)Hi52 << 12;
    }
  }
  RecursiveLi(rd, Hi52);

  if (Unsigned) {
  } else {
    slli(rd, rd, ShiftAmount);
  }
  if (Lo12) {
    addi(rd, rd, Lo12);
  }
}

int Assembler::RecursiveLiImplCount(int64_t Val) {
  int count = 0;
  if (is_int32(Val)) {
    // Depending on the active bits in the immediate Value v, the following
    // instruction sequences are emitted:
    //
    // v == 0                        : ADDI
    // v[0,12) != 0 && v[12,32) == 0 : ADDI
    // v[0,12) == 0 && v[12,32) != 0 : LUI
    // v[0,32) != 0                  : LUI+ADDI(W)
    int64_t Hi20 = ((Val + 0x800) >> 12) & 0xFFFFF;
    int64_t Lo12 = Val << 52 >> 52;

    if (Hi20) {
      // lui(rd, (int32_t)Hi20);
      count++;
    }

    if (Lo12 || Hi20 == 0) {
      //   unsigned AddiOpc = (IsRV64 && Hi20) ? RISCV::ADDIW : RISCV::ADDI;
      //   Res.push_back(RISCVMatInt::Inst(AddiOpc, Lo12));
      count++;
    }
    return count;
  }

  // In the worst case, for a full 64-bit constant, a sequence of 8
  // instructions (i.e., LUI+ADDIW+SLLI+ADDI+SLLI+ADDI+SLLI+ADDI) has to be
  // emitted. Note that the first two instructions (LUI+ADDIW) can contribute
  // up to 32 bits while the following ADDI instructions contribute up to 12
  // bits each.
  //
  // On the first glance, implementing this seems to be possible by simply
  // emitting the most significant 32 bits (LUI+ADDIW) followed by as many
  // left shift (SLLI) and immediate additions (ADDI) as needed. However, due
  // to the fact that ADDI performs a sign extended addition, doing it like
  // that would only be possible when at most 11 bits of the ADDI instructions
  // are used. Using all 12 bits of the ADDI instructions, like done by GAS,
  // actually requires that the constant is processed starting with the least
  // significant bit.
  //
  // In the following, constants are processed from LSB to MSB but instruction
  // emission is performed from MSB to LSB by recursively calling
  // generateInstSeq. In each recursion, first the lowest 12 bits are removed
  // from the constant and the optimal shift amount, which can be greater than
  // 12 bits if the constant is sparse, is determined. Then, the shifted
  // remaining constant is processed recursively and gets emitted as soon as
  // it fits into 32 bits. The emission of the shifts and additions is
  // subsequently performed when the recursion returns.

  int64_t Lo12 = Val << 52 >> 52;
  int64_t Hi52 = ((uint64_t)Val + 0x800ull) >> 12;
  int ShiftAmount = 12 + base::bits::CountTrailingZeros((uint64_t)Hi52);
  Hi52 = signExtend(Hi52 >> (ShiftAmount - 12), 64 - ShiftAmount);

  // If the remaining bits don't fit in 12 bits, we might be able to reduce
  // the shift amount in order to use LUI which will zero the lower 12 bits.
  bool Unsigned = false;
  if (ShiftAmount > 12 && !is_int12(Hi52)) {
    if (is_int32((uint64_t)Hi52 << 12)) {
      // Reduce the shift amount and add zeros to the LSBs so it will match
      // LUI.
      ShiftAmount -= 12;
      Hi52 = (uint64_t)Hi52 << 12;
    }
  }

  count += RecursiveLiImplCount(Hi52);

  if (Unsigned) {
  } else {
    // slli(rd, rd, ShiftAmount);
    count++;
  }
  if (Lo12) {
    // addi(rd, rd, Lo12);
    count++;
  }
  return count;
}

int Assembler::GeneralLiCount(int64_t imm, bool is_get_temp_reg) {
  int count = 0;
  // imitate Assembler::RV_li
  if (is_int32(imm + 0x800)) {
    // 32-bit case. Maximum of 2 instructions generated
    int64_t high_20 = ((imm + 0x800) >> 12);
    int64_t low_12 = imm << 52 >> 52;
    if (high_20) {
      count++;
      if (low_12) {
        count++;
      }
    } else {
      count++;
    }
    return count;
  } else {
    // 64-bit case: divide imm into two 32-bit parts, upper and lower
    int64_t up_32 = imm >> 32;
    int64_t low_32 = imm & 0xffffffffull;
    // Check if a temporary register is available
    if (is_get_temp_reg) {
      // keep track of hardware behavior for lower part in sim_low
      int64_t sim_low = 0;
      // Build lower part
      if (low_32 != 0) {
        int64_t high_20 = ((low_32 + 0x800) >> 12);
        int64_t low_12 = low_32 & 0xfff;
        if (high_20) {
          // Adjust to 20 bits for the case of overflow
          high_20 &= 0xfffff;
          sim_low = ((high_20 << 12) << 32) >> 32;
          count++;
          if (low_12) {
            sim_low += (low_12 << 52 >> 52) | low_12;
            count++;
          }
        } else {
          sim_low = low_12;
          count++;
        }
      }
      if (sim_low & 0x100000000) {
        // Bit 31 is 1. Either an overflow or a negative 64 bit
        if (up_32 == 0) {
          // Positive number, but overflow because of the add 0x800
          count++;
          count++;
          return count;
        }
        // low_32 is a negative 64 bit after the build
        up_32 = (up_32 - 0xffffffff) & 0xffffffff;
      }
      if (up_32 == 0) {
        return count;
      }
      int64_t high_20 = (up_32 + 0x800) >> 12;
      int64_t low_12 = up_32 & 0xfff;
      if (high_20) {
        // Adjust to 20 bits for the case of overflow
        high_20 &= 0xfffff;
        count++;
        if (low_12) {
          count++;
        }
      } else {
        count++;
      }
      // Put it at the bgining of register
      count++;
      if (low_32 != 0) {
        count++;
      }
      return count;
    }
    // No temp register. Build imm in rd.
    // Build upper 32 bits first in rd. Divide lower 32 bits parts and add
    // parts to the upper part by doing shift and add.
    // First build upper part in rd.
    int64_t high_20 = (up_32 + 0x800) >> 12;
    int64_t low_12 = up_32 & 0xfff;
    if (high_20) {
      // Adjust to 20 bits for the case of overflow
      high_20 &= 0xfffff;
      count++;
      if (low_12) {
        count++;
      }
    } else {
      count++;
    }
    // upper part already in rd. Each part to be added to rd, has maximum of
    // 11 bits, and always starts with a 1. rd is shifted by the size of the
    // part plus the number of zeros between the parts. Each part is added
    // after the left shift.
    uint32_t mask = 0x80000000;
    int32_t i;
    for (i = 0; i < 32; i++) {
      if ((low_32 & mask) == 0) {
        mask >>= 1;
        if (i == 31) {
          // rest is zero
          count++;
        }
        continue;
      }
      // The first 1 seen
      if ((i + 11) < 32) {
        // Pick 11 bits
        count++;
        count++;
        i += 10;
        mask >>= 11;
      } else {
        count++;
        count++;
        break;
      }
    }
  }
  return count;
}
#endif

RegList Assembler::DefaultTmpList() { return {t3, t5}; }
DoubleRegList Assembler::DefaultFPTmpList() { return {kScratchDoubleReg}; }
}  // namespace internal
}  // namespace v8
```