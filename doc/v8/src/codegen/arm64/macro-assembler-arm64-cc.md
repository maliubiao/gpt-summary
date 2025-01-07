Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The filename `macro-assembler-arm64.cc` and the `#include "src/codegen/macro-assembler-inl.h"` strongly suggest this code defines a macro assembler for the ARM64 architecture within the V8 JavaScript engine. A macro assembler provides higher-level abstractions over raw assembly instructions, making code generation easier.

2. **Scan for Key Concepts and Data Structures:** I look for recurring patterns, class names, and keywords. I notice:
    * `MacroAssembler`: The central class.
    * `CPURegList`, `RegList`, `VRegister`:  Representing CPU registers (general-purpose and floating-point).
    * `Operand`, `MemOperand`:  Representing operands to instructions (registers, immediates, memory locations).
    * `Condition`, `LogicalOp`, `AddSubOp`, `LoadStoreOp`: Enums for instruction modifiers.
    * `PushCPURegList`, `PopCPURegList`, `PushAll`, `PopAll`: Functions related to stack manipulation.
    * `Mov`, `LogicalMacro`, `AddSubMacro`, `LoadStoreMacro`: Functions that seem to generate sequences of assembly instructions for common operations.
    * Comments like `ASM_CODE_COMMENT(this)`: Indicate the purpose of the code being generated.
    * `#if V8_TARGET_ARCH_ARM64`: Confirms the target architecture.

3. **Analyze Function Signatures and Logic (Even Without Full Code):** I examine the function names and parameter types to infer their functionality. For example:
    * `PushCPURegList(CPURegList registers)`:  Pushes a list of CPU registers onto the stack.
    * `Mov(const Register& rd, uint64_t imm)`: Moves an immediate value into a register. The code within this function, even partially shown, discusses handling various immediate sizes and using `movz`, `movn`, and `movk` instructions.
    * `LogicalMacro(const Register& rd, const Register& rn, const Operand& operand, LogicalOp op)`: Performs a logical operation between two operands. The code handles different operand types (immediate, register, shifted register) and special cases.
    * `AddSubMacro(...)`: Performs addition or subtraction. It handles immediates that might not fit directly into the instruction.
    * `LoadStoreMacro(...)`: Handles loading and storing data from memory.

4. **Look for Interactions with JavaScript Concepts:** I consider how these low-level operations relate to JavaScript:
    * **Stack Management:** JavaScript function calls and local variables rely on stack management (pushing and popping registers).
    * **Data Manipulation:**  `Mov`, `LogicalMacro`, `AddSubMacro` are fundamental for performing JavaScript operations on numbers, strings, and objects.
    * **Memory Access:** `LoadStoreMacro` is crucial for accessing object properties and array elements.
    * **Function Calls:** The inclusion of headers like `"src/codegen/callable.h"` and `"src/builtins/builtins-inl.h"` suggests involvement in calling JavaScript functions and built-in methods.
    * **Optimization:** Macro assemblers are used in optimizing compilers (like V8's Crankshaft or Turbofan) to generate efficient machine code.

5. **Consider Potential User Errors:**  Based on my understanding of assembly programming and the functions exposed, I can think about common errors:
    * **Incorrect register usage:**  Using the wrong register for an operation.
    * **Stack overflow/underflow:**  Incorrectly pushing or popping values from the stack.
    * **Misaligned memory access:** Attempting to access memory at an address that isn't a multiple of the required size.
    * **Incorrect operand types:** Providing an invalid operand for an instruction.

6. **Address the Specific Questions:**
    * **Listing Functionality:** Based on the analysis above, I list the core functions.
    * **`.tq` Extension:**  The code explicitly states it's a C++ file (`.cc`), so it's not a Torque file.
    * **Relationship to JavaScript:** Explain how the assembler's operations are foundational for executing JavaScript.
    * **JavaScript Examples:** Provide simple JavaScript snippets that would rely on the types of operations the assembler supports (arithmetic, variable assignment, function calls).
    * **Code Logic Inference:**  Choose a function like `Mov` or `LogicalMacro` and explain how it handles different input types and the expected output (generating assembly instructions). Give simple examples.
    * **Common Programming Errors:** Provide examples as discussed in step 5.
    * **Summary of Functionality (Part 1):** Synthesize the key takeaways from the analysis of the provided code.

7. **Structure the Response:** Organize the information logically with clear headings and bullet points. Start with a high-level overview and then delve into specifics.

By following these steps, even with an incomplete code snippet, I can make reasonable inferences about its purpose and functionality within the V8 engine. The key is to leverage the available information (filename, included headers, function names) and my understanding of compiler architecture and assembly programming.
好的，根据你提供的 V8 源代码片段 `v8/src/codegen/arm64/macro-assembler-arm64.cc` 的内容，以下是它的功能归纳：

**核心功能：**

`v8/src/codegen/arm64/macro-assembler-arm64.cc` 是 V8 JavaScript 引擎中为 ARM64 架构提供宏汇编器 (MacroAssembler) 功能的 C++ 源代码文件。  宏汇编器是汇编器的抽象层，它提供了一组更高级的接口（C++ 函数），允许开发者以更简洁、更易懂的方式生成 ARM64 汇编代码。

**主要功能点：**

1. **寄存器操作:**
   - 提供了方便的接口来操作 ARM64 的通用寄存器 (X/W) 和浮点寄存器 (V)。
   - 包括移动数据 (`Mov`),  加载和存储 (`Ldr`, `Str`),  批量压栈和出栈 (`PushCPURegList`, `PopCPURegList`, `PushAll`, `PopAll`) 等操作。
   - 提供了保存和恢复调用者保存寄存器的功能 (`PushCallerSaved`, `PopCallerSaved`)，这对于函数调用约定至关重要。

2. **算术和逻辑运算:**
   - 封装了 ARM64 的算术运算指令（加法 `AddSubMacro`，带进位的加减法 `AddSubWithCarryMacro`）和逻辑运算指令 (`LogicalMacro`)。
   - 能够处理立即数、寄存器以及移位/扩展的寄存器作为操作数。
   - 针对不同的立即数值，会选择最优的指令序列来生成代码（例如使用 `movz`, `movn`, `movk` 来加载 64 位立即数）。

3. **条件操作:**
   - 提供了条件比较指令的封装 (`ConditionalCompareMacro`)。
   - 提供了条件选择指令 (`Csel`)，允许基于条件码选择不同的值。

4. **内存操作:**
   - 提供了加载和存储指令的更高级抽象 (`LoadStoreMacro`, `LoadStoreMacroComplex`)，可以处理不同的寻址模式（立即数偏移，寄存器偏移，预/后索引等）。

5. **宏指令:**
   - 核心是提供“宏”的概念，这意味着一个 C++ 函数调用可能会生成多个底层的 ARM64 汇编指令。这提高了代码生成效率和可读性。

6. **对齐和填充:**
   - 确保生成的代码符合 ARM64 的指令对齐要求。

7. **支持 WebAssembly (部分):**
   - 代码中可以看到对 `V8_ENABLE_WEBASSEMBLY` 的条件编译，表明这个宏汇编器也服务于 WebAssembly 的代码生成，并且在 WebAssembly 环境下会保存完整的浮点寄存器。

8. **与 V8 内部机制集成:**
   - 代码中包含了对 V8 内部其他模块的引用，例如 `CodeFactory`, `ExternalReferenceTable`, `RelocInfo` 等，表明它与 V8 的代码生成和运行时机制紧密集成。

**关于 .tq 结尾：**

你提到如果文件名以 `.tq` 结尾，那么它是一个 V8 Torque 源代码。 你的观察是正确的。 Torque 是 V8 用于定义内置函数和运行时函数的领域特定语言。  然而，`macro-assembler-arm64.cc` 的文件名以 `.cc` 结尾，这明确表明它是一个 C++ 源代码文件，而不是 Torque 文件。

**与 JavaScript 的关系和示例：**

`macro-assembler-arm64.cc` 生成的 ARM64 汇编代码是 JavaScript 代码最终执行的形式。 当 V8 执行 JavaScript 代码时，它会经过编译或解释的过程，其中一个关键步骤是将 JavaScript 代码转换为目标平台的机器码。  `MacroAssembler` 在这个过程中扮演着重要的角色。

**JavaScript 示例：**

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 执行这段代码时，对于 `add` 函数中的 `a + b` 操作，`macro-assembler-arm64.cc` 中的相关函数（例如 `AddSubMacro`）会被调用，生成相应的 ARM64 加法指令，大致如下（简化）：

```assembly
// 假设 a 在寄存器 x0，b 在寄存器 x1
add x0, x0, x1  // 将 x0 和 x1 的值相加，结果存储在 x0 中
ret             // 返回
```

对于 `let result = add(5, 10);`  调用 `add` 函数的过程，宏汇编器也会生成代码来传递参数、跳转到函数入口、处理返回值等。

**代码逻辑推理（假设输入与输出）：**

假设调用 `MacroAssembler::Mov(x0, 10);`  （将立即数 10 移动到寄存器 `x0`）：

- **输入：**
    - 目标寄存器 `rd`: `x0`
    - 立即数 `imm`: 10 (uint64_t)
- **代码逻辑（简化）：**
    - `TryOneInstrMoveImmediate(x0, 10)` 会尝试用单个 `movz` 指令来移动立即数。
    - 由于 10 可以用 `movz` 指令表示，该函数会返回 `true`。
    - 最终会生成 ARM64 汇编指令： `movz x0, #0xa` (0xa 是 10 的十六进制表示)。
- **输出：**  生成对应的 ARM64 机器码，当 CPU 执行到这段代码时，寄存器 `x0` 的值将被设置为 10。

假设调用 `MacroAssembler::AddSubMacro(x2, x0, Operand(x1), MacroAssembler::LeaveFlags, MacroAssembler::kAdd);` （将寄存器 `x0` 和 `x1` 的值相加，结果存储到 `x2`，不更新标志位）：

- **输入：**
    - 目标寄存器 `rd`: `x2`
    - 源寄存器 `rn`: `x0`
    - 操作数 `operand`: 寄存器 `x1`
    - 标志位更新 `S`: `MacroAssembler::LeaveFlags`
    - 操作类型 `op`: `MacroAssembler::kAdd`
- **代码逻辑（简化）：**
    - 由于操作数是寄存器，可以直接生成 `add` 指令。
    - 由于 `S` 是 `LeaveFlags`，生成的 `add` 指令不会影响标志位。
- **输出：** 生成 ARM64 汇编指令： `add x2, x0, x1`。

**用户常见的编程错误示例（与宏汇编器使用相关）：**

用户通常不会直接编写或修改 `macro-assembler-arm64.cc` 的代码。 这里的“用户”指的是 V8 的开发者或编译器开发者，他们在 V8 的代码生成阶段可能会遇到以下错误：

1. **寄存器分配错误：**  错误地使用或覆盖了已被使用的寄存器，导致数据损坏。例如，在一个函数调用前后，没有正确保存和恢复调用者保存的寄存器。

   ```c++
   // 错误示例（伪代码）
   void generate_code_for_addition(MacroAssembler& masm, Register a, Register b) {
     masm.Mov(x0, a);  // 假设 x0 用于其他目的
     masm.Add(x0, x0, b);
     // ...
   }
   ```

2. **栈操作错误：**  不正确地压栈或出栈，导致栈指针错乱，最终可能导致崩溃。例如，压入的寄存器数量与弹出的数量不一致。

   ```c++
   // 错误示例（伪代码）
   void generate_code_for_function_call(MacroAssembler& masm) {
     masm.Push(x0);
     masm.Push(x1);
     // ... 函数调用 ...
     masm.Pop(x0); // 忘记 pop x1
   }
   ```

3. **立即数处理错误：**  没有正确处理超出指令编码范围的立即数，导致生成的代码不正确或无法执行。

   ```c++
   // 错误示例（伪代码）
   void load_large_immediate(MacroAssembler& masm) {
     masm.Mov(x0, 0xFFFFFFFFFFFFFFFF); // 可能直接使用 mov 指令无法加载
   }
   ```

4. **条件码使用错误：**  在条件分支或条件选择指令中使用了错误的条件码，导致程序逻辑错误。

5. **内存寻址错误：**  计算的内存地址不正确，或者访问了未分配或不允许访问的内存区域。

**总结 (Part 1 的功能归纳):**

总而言之，`v8/src/codegen/arm64/macro-assembler-arm64.cc` 是 V8 引擎中针对 ARM64 架构的核心组件，它提供了一组 C++ 接口，用于方便高效地生成 ARM64 汇编代码，涵盖了寄存器操作、算术逻辑运算、条件操作和内存操作等关键功能，是 V8 将 JavaScript 代码转化为可执行机器码的关键环节。它不是 Torque 文件，而是用 C++ 实现的。

Prompt: 
```
这是目录为v8/src/codegen/arm64/macro-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/macro-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

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
"""


```