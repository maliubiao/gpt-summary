Response:
My goal is to analyze the provided C++ code snippet and summarize its functionality. Here's a breakdown of the thought process:

1. **Identify the Language and Context:** The code starts with `// Copyright` and includes standard C++ headers (`<limits.h>`). The `#if V8_TARGET_ARCH_MIPS64` clearly indicates this is architecture-specific code for the MIPS64 architecture within the V8 JavaScript engine. The filename `macro-assembler-mips64.cc` also strongly suggests this is about assembly code generation.

2. **High-Level Understanding:**  The term "MacroAssembler" is key. It means this code provides a higher-level interface for generating MIPS64 assembly instructions. Instead of writing raw assembly, developers can use functions in this class that abstract away some of the complexities.

3. **Examine Key Sections:** I'll go through the code block by block, noting the purpose of each section:

    * **Includes:** Standard V8 headers related to code generation, memory management, debugging, etc. These provide the necessary building blocks for the `MacroAssembler`.
    * **`IsZero` function:** A simple helper to check if an `Operand` represents zero.
    * **`RequiredStackSizeForCallerSaved`:**  Calculates the stack space needed to save registers that the *caller* is responsible for saving before calling a function. This is crucial for maintaining the calling convention.
    * **`PushCallerSaved` and `PopCallerSaved`:**  These functions physically push and pop the caller-saved registers onto/from the stack. They utilize `MultiPush` and `MultiPop` which are likely lower-level assembly emission functions. The `SaveFPRegsMode` parameter suggests handling of floating-point registers as well.
    * **`LoadRoot`:** Loads a value from the "root table" of the V8 heap. This table contains frequently used objects and values. The conditional version is interesting and suggests optimization.
    * **`PushCommonFrame` and `PushStandardFrame`:** Functions to set up stack frames. Frames are essential for managing function calls, local variables, and return addresses. The "standard" frame likely includes arguments and context.
    * **`RecordWriteField` and `RecordWrite`:** These are crucial for implementing V8's garbage collector. When a pointer within a managed object is updated, the garbage collector needs to be notified. These functions implement the "write barrier."  The `SmiCheck` parameter handles optimizations for small integers (Smis).
    * **`MaybeSaveRegisters` and `MaybeRestoreRegisters`:** Convenience functions for conditionally saving/restoring register sets.
    * **`CallEphemeronKeyBarrier` and `CallRecordWriteStub...`:** More specialized write barrier functions, likely for different object types or scenarios. They involve calling built-in functions or stubs.
    * **Instruction Macros (e.g., `Addu`, `Daddu`, `Subu`, etc.):** This is a significant part. These functions provide higher-level abstractions for common MIPS64 instructions. They handle details like immediate operand encoding and register allocation (using `UseScratchRegisterScope`). The naming convention (e.g., `Addu` for "Add Unsigned") reflects the underlying assembly instructions. The code handles both register and immediate operands. It also deals with potential relocation needs when loading large immediates.
    * **Pseudo-instructions (e.g., `ByteSwapSigned`, `ByteSwapUnsigned`, `Ulw`):** These are not single MIPS64 instructions but are sequences of instructions that perform a specific higher-level operation. Byte swapping is important for handling different endianness. The `Ulw` (Unaligned Load Word) handles memory accesses that are not aligned to word boundaries.

4. **Identify Key Features and Concepts:** Based on the above examination, the core functionalities are:

    * **Assembly Code Generation:** The primary purpose.
    * **Register Management:** Saving, restoring, and allocating registers.
    * **Stack Frame Management:** Setting up and tearing down function call stacks.
    * **Garbage Collection Support (Write Barriers):**  Crucial for memory safety.
    * **Instruction Abstraction:** Providing easier-to-use functions for common assembly operations.
    * **Optimization:**  Conditional execution and handling of Smis.
    * **Architecture Specificity:**  Tailored for MIPS64.

5. **Address Specific Instructions:**

    * **`.tq` Extension:** The code clearly states that if the filename ended in `.tq`, it would be a Torque source file. Since it ends in `.cc`, it's C++.
    * **Relationship to JavaScript:**  This code *directly* enables JavaScript execution. V8 compiles JavaScript code into machine code, and this `MacroAssembler` is a key component of that compilation process for the MIPS64 architecture. It's responsible for generating the actual assembly instructions that the processor will execute. The "caller saved" register logic is part of the calling convention that allows JavaScript functions to call native (C++) functions and vice versa. The write barrier is directly related to how the garbage collector manages JavaScript objects in memory.
    * **JavaScript Example:** The simplest example would be a basic arithmetic operation. When V8 compiles `1 + 2`, this code would be involved in generating the MIPS64 instructions to load the values 1 and 2 into registers, perform the addition, and store the result.
    * **Code Logic and Assumptions:** Many functions have implicit assumptions about register usage and calling conventions. For example, `PushCommonFrame` assumes that `ra` (return address) and `fp` (frame pointer) hold specific values. The write barrier functions assume the `object` register contains a tagged heap object pointer. Input/output examples are difficult without a specific function in mind, but for `Addu(r1, r2, 5)`, the input is registers `r1` and `r2` with some values, and the output is `r1` containing the sum of the value in `r2` and 5.
    * **Common Programming Errors:** A common error when working with assembly (or code generators like this) is incorrect register usage, leading to data corruption. For example, using a register that is supposed to hold a specific value for a different purpose. Another error is miscalculating stack frame sizes, leading to stack overflows or corruption. The write barrier logic is complex, and errors there could lead to memory corruption and crashes.
    * **Overall Functionality (for Part 1):**  The first part focuses on core functionalities like register saving/restoring, stack frame management, basic arithmetic and logical operations, and the crucial write barrier mechanism for garbage collection. It sets the foundation for more complex assembly generation.

6. **Structure the Summary:** Finally, I organize the findings into a concise summary covering the key aspects requested in the prompt. This involves grouping related functionalities and providing clear explanations. I also make sure to address each specific point raised in the original request (e.g., `.tq` extension, JavaScript relationship).这是v8 JavaScript引擎中用于MIPS64架构的代码生成器的一部分。具体来说，`v8/src/codegen/mips64/macro-assembler-mips64.cc` 文件定义了一个 `MacroAssembler` 类，它提供了一组高级接口（宏指令）来生成底层的MIPS64汇编代码。

以下是它的主要功能归纳：

**核心功能：MIPS64汇编代码生成**

* **提供宏指令:** `MacroAssembler` 封装了常见的MIPS64指令序列，使其更容易生成代码，而无需手动编写所有底层的汇编指令。例如，`Addu`, `Daddu`, `Ld`, `Sd`, `Branch` 等方法对应于MIPS64的加法、加载、存储、分支等操作。
* **寄存器管理:**  它负责管理MIPS64架构中的寄存器，包括通用寄存器和浮点寄存器。提供了保存和恢复寄存器的功能 (`PushCallerSaved`, `PopCallerSaved`)，这对于函数调用和避免寄存器冲突至关重要。
* **栈帧管理:** 提供了设置和管理函数调用栈帧的功能 (`PushCommonFrame`, `PushStandardFrame`)，包括保存返回地址、帧指针等。
* **内存操作:** 提供了加载和存储数据到内存的功能 (`Ld`, `Sd`)，并支持不同的寻址模式。
* **分支控制:** 提供了条件和无条件分支指令 (`Branch`, `Beq`, `Bne` 等)。
* **内置函数调用:** 提供了调用V8内置函数 (`CallBuiltin`) 的机制。
* **根对象加载:** 提供了加载V8堆中根对象的功能 (`LoadRoot`)。
* **写屏障 (Write Barrier):**  实现了垃圾回收所需的写屏障机制 (`RecordWriteField`, `RecordWrite`, `CallRecordWriteStub`)。当修改堆中对象的指针时，需要通知垃圾回收器，以确保内存管理的正确性。

**关于文件名和Torque:**

* 代码明确指出 `v8/src/codegen/mips64/macro-assembler-mips64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件的扩展名是 `.tq`。

**与JavaScript的关系和示例:**

`macro-assembler-mips64.cc` 是 V8 引擎将 JavaScript 代码编译成机器码的关键部分。当 V8 执行 JavaScript 代码时，它会将 JavaScript 代码编译成针对目标架构（这里是 MIPS64）的机器码。`MacroAssembler` 类就是用来生成这些机器码的工具。

**JavaScript 示例:**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 编译 `add` 函数时，`macro-assembler-mips64.cc` 中的方法会被调用来生成类似以下的 MIPS64 汇编指令（简化示例）：

1. **函数入口:**
   - 设置栈帧 (`PushStandardFrame`)
   - 将参数 `a` 和 `b` 加载到寄存器中。

2. **执行加法:**
   - 使用 `Addu` 或 `Daddu` 指令将两个寄存器中的值相加。

3. **返回结果:**
   - 将结果存储到指定寄存器。
   - 恢复栈帧。
   - 返回。

4. **调用函数和存储结果:**
   - 当调用 `add(5, 10)` 时，将参数 `5` 和 `10` 传递给函数。
   - 将函数返回的结果存储到变量 `result` 对应的内存位置。

**代码逻辑推理和假设输入/输出:**

以 `Addu(rd, rs, rt)` 为例：

* **假设输入:**
    * `rd`: 目标寄存器 (例如 `t0`)
    * `rs`: 源寄存器 1 (例如 `t1`)，假设其值为 5
    * `rt`: 源操作数，可以是寄存器 (例如 `t2`，假设其值为 10) 或立即数 (例如 `Operand(10)`)

* **输出:**
    * 寄存器 `rd` (`t0`) 的值将变为 `rs` 的值加上 `rt` 的值，即 `5 + 10 = 15`。

**涉及用户常见的编程错误:**

虽然这个文件是 V8 内部代码，但它生成的汇编代码可能会暴露一些用户编程错误，例如：

* **类型错误:** 如果 JavaScript 代码中尝试对非数字类型进行加法操作，V8 生成的代码可能需要进行类型检查和转换，这部分逻辑也会涉及到 `MacroAssembler`。
* **内存访问错误:** JavaScript 中如果访问了未定义的属性或越界访问数组，V8 生成的代码会进行边界检查，如果超出范围，可能会抛出异常。`MacroAssembler` 负责生成这些检查的代码。
* **栈溢出:**  如果 JavaScript 代码导致过深的递归调用，生成的汇编代码可能会超出栈空间，导致栈溢出错误。

**总结 (针对第1部分):**

`v8/src/codegen/mips64/macro-assembler-mips64.cc` 的主要功能是提供一个用于生成 MIPS64 汇编代码的高级接口，它是 V8 引擎将 JavaScript 代码编译成可执行机器码的关键组成部分。它封装了寄存器管理、栈帧操作、内存访问、分支控制以及垃圾回收所需的写屏障等功能。

Prompt: 
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>  // For LONG_MIN, LONG_MAX.

#if V8_TARGET_ARCH_MIPS64

#include "src/base/bits.h"
#include "src/base/division-by-constant.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/code-factory.h"
#include "src/codegen/external-reference-table.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/register-configuration.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/objects/heap-number.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/snapshot.h"

// Satisfy cpplint check, but don't include platform-specific header. It is
// included recursively via macro-assembler.h.
#if 0
#include "src/codegen/mips64/macro-assembler-mips64.h"
#endif

#define __ ACCESS_MASM(masm)

namespace v8 {
namespace internal {

static inline bool IsZero(const Operand& rt) {
  if (rt.is_reg()) {
    return rt.rm() == zero_reg;
  } else {
    return rt.immediate() == 0;
  }
}

int MacroAssembler::RequiredStackSizeForCallerSaved(SaveFPRegsMode fp_mode,
                                                    Register exclusion1,
                                                    Register exclusion2,
                                                    Register exclusion3) const {
  int bytes = 0;
  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  bytes += list.Count() * kPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PushCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                    Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPush(list);
  bytes += list.Count() * kPointerSize;

  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPushFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  return bytes;
}

int MacroAssembler::PopCallerSaved(SaveFPRegsMode fp_mode, Register exclusion1,
                                   Register exclusion2, Register exclusion3) {
  ASM_CODE_COMMENT(this);
  int bytes = 0;
  if (fp_mode == SaveFPRegsMode::kSave) {
    MultiPopFPU(kCallerSavedFPU);
    bytes += kCallerSavedFPU.Count() * kDoubleSize;
  }

  RegList exclusions = {exclusion1, exclusion2, exclusion3};
  RegList list = kJSCallerSaved - exclusions;
  MultiPop(list);
  bytes += list.Count() * kPointerSize;

  return bytes;
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index) {
  Ld(destination, MemOperand(s6, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::LoadRoot(Register destination, RootIndex index,
                              Condition cond, Register src1,
                              const Operand& src2) {
  Branch(2, NegateCondition(cond), src1, src2);
  Ld(destination, MemOperand(s6, RootRegisterOffsetForRootIndex(index)));
}

void MacroAssembler::PushCommonFrame(Register marker_reg) {
  if (marker_reg.is_valid()) {
    Push(ra, fp, marker_reg);
    Daddu(fp, sp, Operand(kPointerSize));
  } else {
    Push(ra, fp);
    mov(fp, sp);
  }
}

void MacroAssembler::PushStandardFrame(Register function_reg) {
  int offset = -StandardFrameConstants::kContextOffset;
  if (function_reg.is_valid()) {
    Push(ra, fp, cp, function_reg, kJavaScriptCallArgCountRegister);
    offset += 2 * kPointerSize;
  } else {
    Push(ra, fp, cp, kJavaScriptCallArgCountRegister);
    offset += kPointerSize;
  }
  Daddu(fp, sp, Operand(offset));
}

// Clobbers object, dst, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWriteField(Register object, int offset,
                                      Register value, Register dst,
                                      RAStatus ra_status,
                                      SaveFPRegsMode save_fp,
                                      SmiCheck smi_check) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(value, dst, t8, object));
  // First, check if a write barrier is even needed. The tests below
  // catch stores of Smis.
  Label done;

  // Skip barrier if writing a smi.
  if (smi_check == SmiCheck::kInline) {
    JumpIfSmi(value, &done);
  }

  // Although the object register is tagged, the offset is relative to the start
  // of the object, so offset must be a multiple of kPointerSize.
  DCHECK(IsAligned(offset, kPointerSize));

  Daddu(dst, object, Operand(offset - kHeapObjectTag));
  if (v8_flags.debug_code) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Label ok;
    And(t8, dst, Operand(kPointerSize - 1));
    Branch(&ok, eq, t8, Operand(zero_reg));
    stop();
    bind(&ok);
  }

  RecordWrite(object, dst, value, ra_status, save_fp, SmiCheck::kOmit);

  bind(&done);

  // Clobber clobbered input registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    li(value, Operand(base::bit_cast<int64_t>(kZapValue + 4)));
    li(dst, Operand(base::bit_cast<int64_t>(kZapValue + 8)));
  }
}

void MacroAssembler::MaybeSaveRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPush(registers);
}

void MacroAssembler::MaybeRestoreRegisters(RegList registers) {
  if (registers.is_empty()) return;
  MultiPop(registers);
}

void MacroAssembler::CallEphemeronKeyBarrier(Register object,
                                             Register slot_address,
                                             SaveFPRegsMode fp_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  Push(object);
  Push(slot_address);
  Pop(slot_address_parameter);
  Pop(object_parameter);

  CallBuiltin(Builtins::EphemeronKeyBarrier(fp_mode));
  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStubSaveRegisters(Register object,
                                                      Register slot_address,
                                                      SaveFPRegsMode fp_mode,
                                                      StubCallMode mode) {
  DCHECK(!AreAliased(object, slot_address));
  RegList registers =
      WriteBarrierDescriptor::ComputeSavedRegisters(object, slot_address);
  MaybeSaveRegisters(registers);

  Register object_parameter = WriteBarrierDescriptor::ObjectRegister();
  Register slot_address_parameter =
      WriteBarrierDescriptor::SlotAddressRegister();

  Push(object);
  Push(slot_address);
  Pop(slot_address_parameter);
  Pop(object_parameter);

  CallRecordWriteStub(object_parameter, slot_address_parameter, fp_mode, mode);

  MaybeRestoreRegisters(registers);
}

void MacroAssembler::CallRecordWriteStub(Register object, Register slot_address,
                                         SaveFPRegsMode fp_mode,
                                         StubCallMode mode) {
  // Use CallRecordWriteStubSaveRegisters if the object and slot registers
  // need to be caller saved.
  DCHECK_EQ(WriteBarrierDescriptor::ObjectRegister(), object);
  DCHECK_EQ(WriteBarrierDescriptor::SlotAddressRegister(), slot_address);
#if V8_ENABLE_WEBASSEMBLY
  if (mode == StubCallMode::kCallWasmRuntimeStub) {
    auto wasm_target =
        static_cast<Address>(wasm::WasmCode::GetRecordWriteBuiltin(fp_mode));
    Call(wasm_target, RelocInfo::WASM_STUB_CALL);
#else
  if (false) {
#endif
  } else {
    CallBuiltin(Builtins::RecordWrite(fp_mode));
  }
}

// Clobbers object, address, value, and ra, if (ra_status == kRAHasBeenSaved)
// The register 'object' contains a heap object pointer.  The heap object
// tag is shifted away.
void MacroAssembler::RecordWrite(Register object, Register address,
                                 Register value, RAStatus ra_status,
                                 SaveFPRegsMode fp_mode, SmiCheck smi_check) {
  DCHECK(!AreAliased(object, address, value, t8));
  DCHECK(!AreAliased(object, address, value, t9));

  if (v8_flags.debug_code) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(!AreAliased(object, value, scratch));
    Ld(scratch, MemOperand(address));
    Assert(eq, AbortReason::kWrongAddressOrValuePassedToRecordWrite, scratch,
           Operand(value));
  }

  if (v8_flags.disable_write_barriers) {
    return;
  }

  // First, check if a write barrier is even needed. The tests below
  // catch stores of smis and stores into the young generation.
  Label done;

  if (smi_check == SmiCheck::kInline) {
    DCHECK_EQ(0, kSmiTag);
    JumpIfSmi(value, &done);
  }

  CheckPageFlag(value,
                value,  // Used as scratch.
                MemoryChunk::kPointersToHereAreInterestingMask, eq, &done);
  CheckPageFlag(object,
                value,  // Used as scratch.
                MemoryChunk::kPointersFromHereAreInterestingMask, eq, &done);

  // Record the actual write.
  if (ra_status == kRAHasNotBeenSaved) {
    push(ra);
  }

  Register slot_address = WriteBarrierDescriptor::SlotAddressRegister();
  DCHECK(!AreAliased(object, slot_address, value));
  mov(slot_address, address);
  CallRecordWriteStub(object, slot_address, fp_mode);

  if (ra_status == kRAHasNotBeenSaved) {
    pop(ra);
  }

  bind(&done);

  // Clobber clobbered registers when running with the debug-code flag
  // turned on to provoke errors.
  if (v8_flags.debug_code) {
    li(address, Operand(base::bit_cast<int64_t>(kZapValue + 12)));
    li(value, Operand(base::bit_cast<int64_t>(kZapValue + 16)));
    li(slot_address, Operand(base::bit_cast<int64_t>(kZapValue + 20)));
  }
}

// ---------------------------------------------------------------------------
// Instruction macros.

void MacroAssembler::Addu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    addu(rd, rs, rt.rm());
  } else {
    if (is_int16(rt.immediate()) && !MustUseReg(rt.rmode())) {
      addiu(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      addu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Daddu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    daddu(rd, rs, rt.rm());
  } else {
    if (is_int16(rt.immediate()) && !MustUseReg(rt.rmode())) {
      daddiu(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      daddu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Subu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    subu(rd, rs, rt.rm());
  } else {
    DCHECK(is_int32(rt.immediate()));
    if (is_int16(-rt.immediate()) && !MustUseReg(rt.rmode())) {
      addiu(rd, rs,
            static_cast<int32_t>(
                -rt.immediate()));  // No subiu instr, use addiu(x, y, -imm).
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      if (-rt.immediate() >> 16 == 0 && !MustUseReg(rt.rmode())) {
        // Use load -imm and addu when loading -imm generates one instruction.
        li(scratch, -rt.immediate());
        addu(rd, rs, scratch);
      } else {
        // li handles the relocation.
        li(scratch, rt);
        subu(rd, rs, scratch);
      }
    }
  }
}

void MacroAssembler::Dsubu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    dsubu(rd, rs, rt.rm());
  } else if (is_int16(-rt.immediate()) && !MustUseReg(rt.rmode())) {
    daddiu(rd, rs,
           static_cast<int32_t>(
               -rt.immediate()));  // No dsubiu instr, use daddiu(x, y, -imm).
  } else {
    DCHECK(rs != at);
    int li_count = InstrCountForLi64Bit(rt.immediate());
    int li_neg_count = InstrCountForLi64Bit(-rt.immediate());
    if (li_neg_count < li_count && !MustUseReg(rt.rmode())) {
      // Use load -imm and daddu when loading -imm generates one instruction.
      DCHECK(rt.immediate() != std::numeric_limits<int32_t>::min());
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(-rt.immediate()));
      Daddu(rd, rs, scratch);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, rt);
      dsubu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Mul(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mul(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    mul(rd, rs, scratch);
  }
}

void MacroAssembler::Mulh(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant != kMips64r6) {
      mult(rs, rt.rm());
      mfhi(rd);
    } else {
      muh(rd, rs, rt.rm());
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant != kMips64r6) {
      mult(rs, scratch);
      mfhi(rd);
    } else {
      muh(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Mulhu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant != kMips64r6) {
      multu(rs, rt.rm());
      mfhi(rd);
    } else {
      muhu(rd, rs, rt.rm());
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant != kMips64r6) {
      multu(rs, scratch);
      mfhi(rd);
    } else {
      muhu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Dmul(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant == kMips64r6) {
      dmul(rd, rs, rt.rm());
    } else {
      dmult(rs, rt.rm());
      mflo(rd);
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant == kMips64r6) {
      dmul(rd, rs, scratch);
    } else {
      dmult(rs, scratch);
      mflo(rd);
    }
  }
}

void MacroAssembler::Dmulh(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant == kMips64r6) {
      dmuh(rd, rs, rt.rm());
    } else {
      dmult(rs, rt.rm());
      mfhi(rd);
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant == kMips64r6) {
      dmuh(rd, rs, scratch);
    } else {
      dmult(rs, scratch);
      mfhi(rd);
    }
  }
}

void MacroAssembler::Dmulhu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant == kMips64r6) {
      dmuhu(rd, rs, rt.rm());
    } else {
      dmultu(rs, rt.rm());
      mfhi(rd);
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant == kMips64r6) {
      dmuhu(rd, rs, scratch);
    } else {
      dmultu(rs, scratch);
      mfhi(rd);
    }
  }
}

void MacroAssembler::Mult(Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    mult(rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    mult(rs, scratch);
  }
}

void MacroAssembler::Dmult(Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    dmult(rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    dmult(rs, scratch);
  }
}

void MacroAssembler::Multu(Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    multu(rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    multu(rs, scratch);
  }
}

void MacroAssembler::Dmultu(Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    dmultu(rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    dmultu(rs, scratch);
  }
}

void MacroAssembler::Div(Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    div(rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    div(rs, scratch);
  }
}

void MacroAssembler::Div(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant != kMips64r6) {
      div(rs, rt.rm());
      mflo(res);
    } else {
      div(res, rs, rt.rm());
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant != kMips64r6) {
      div(rs, scratch);
      mflo(res);
    } else {
      div(res, rs, scratch);
    }
  }
}

void MacroAssembler::Mod(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant != kMips64r6) {
      div(rs, rt.rm());
      mfhi(rd);
    } else {
      mod(rd, rs, rt.rm());
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant != kMips64r6) {
      div(rs, scratch);
      mfhi(rd);
    } else {
      mod(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Modu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant != kMips64r6) {
      divu(rs, rt.rm());
      mfhi(rd);
    } else {
      modu(rd, rs, rt.rm());
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant != kMips64r6) {
      divu(rs, scratch);
      mfhi(rd);
    } else {
      modu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Ddiv(Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    ddiv(rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    ddiv(rs, scratch);
  }
}

void MacroAssembler::Ddiv(Register rd, Register rs, const Operand& rt) {
  if (kArchVariant != kMips64r6) {
    if (rt.is_reg()) {
      ddiv(rs, rt.rm());
      mflo(rd);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      ddiv(rs, scratch);
      mflo(rd);
    }
  } else {
    if (rt.is_reg()) {
      ddiv(rd, rs, rt.rm());
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      ddiv(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Divu(Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    divu(rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    divu(rs, scratch);
  }
}

void MacroAssembler::Divu(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant != kMips64r6) {
      divu(rs, rt.rm());
      mflo(res);
    } else {
      divu(res, rs, rt.rm());
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant != kMips64r6) {
      divu(rs, scratch);
      mflo(res);
    } else {
      divu(res, rs, scratch);
    }
  }
}

void MacroAssembler::Ddivu(Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    ddivu(rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    ddivu(rs, scratch);
  }
}

void MacroAssembler::Ddivu(Register res, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    if (kArchVariant != kMips64r6) {
      ddivu(rs, rt.rm());
      mflo(res);
    } else {
      ddivu(res, rs, rt.rm());
    }
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    if (kArchVariant != kMips64r6) {
      ddivu(rs, scratch);
      mflo(res);
    } else {
      ddivu(res, rs, scratch);
    }
  }
}

void MacroAssembler::Dmod(Register rd, Register rs, const Operand& rt) {
  if (kArchVariant != kMips64r6) {
    if (rt.is_reg()) {
      ddiv(rs, rt.rm());
      mfhi(rd);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      ddiv(rs, scratch);
      mfhi(rd);
    }
  } else {
    if (rt.is_reg()) {
      dmod(rd, rs, rt.rm());
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      dmod(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Dmodu(Register rd, Register rs, const Operand& rt) {
  if (kArchVariant != kMips64r6) {
    if (rt.is_reg()) {
      ddivu(rs, rt.rm());
      mfhi(rd);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      ddivu(rs, scratch);
      mfhi(rd);
    }
  } else {
    if (rt.is_reg()) {
      dmodu(rd, rs, rt.rm());
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      dmodu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::And(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    and_(rd, rs, rt.rm());
  } else {
    if (is_uint16(rt.immediate()) && !MustUseReg(rt.rmode())) {
      andi(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      and_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Or(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    or_(rd, rs, rt.rm());
  } else {
    if (is_uint16(rt.immediate()) && !MustUseReg(rt.rmode())) {
      ori(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      or_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Xor(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    xor_(rd, rs, rt.rm());
  } else {
    if (is_uint16(rt.immediate()) && !MustUseReg(rt.rmode())) {
      xori(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      DCHECK(rs != scratch);
      li(scratch, rt);
      xor_(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Nor(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    nor(rd, rs, rt.rm());
  } else {
    // li handles the relocation.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(rs != scratch);
    li(scratch, rt);
    nor(rd, rs, scratch);
  }
}

void MacroAssembler::Neg(Register rs, const Operand& rt) {
  dsubu(rs, zero_reg, rt.rm());
}

void MacroAssembler::Slt(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rs, rt.rm());
  } else {
    if (is_int16(rt.immediate()) && !MustUseReg(rt.rmode())) {
      slti(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rs != scratch);
      li(scratch, rt);
      slt(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Sltu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rs, rt.rm());
  } else {
    const uint64_t int16_min = std::numeric_limits<int16_t>::min();
    if (is_uint15(rt.immediate()) && !MustUseReg(rt.rmode())) {
      // Imm range is: [0, 32767].
      sltiu(rd, rs, static_cast<int32_t>(rt.immediate()));
    } else if (is_uint15(rt.immediate() - int16_min) &&
               !MustUseReg(rt.rmode())) {
      // Imm range is: [max_unsigned-32767,max_unsigned].
      sltiu(rd, rs, static_cast<uint16_t>(rt.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rs != scratch);
      li(scratch, rt);
      sltu(rd, rs, scratch);
    }
  }
}

void MacroAssembler::Sle(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rt.rm(), rs);
  } else {
    if (rt.immediate() == 0 && !MustUseReg(rt.rmode())) {
      slt(rd, zero_reg, rs);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rs != scratch);
      li(scratch, rt);
      slt(rd, scratch, rs);
    }
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sleu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rt.rm(), rs);
  } else {
    if (rt.immediate() == 0 && !MustUseReg(rt.rmode())) {
      sltu(rd, zero_reg, rs);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rs != scratch);
      li(scratch, rt);
      sltu(rd, scratch, rs);
    }
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sge(Register rd, Register rs, const Operand& rt) {
  Slt(rd, rs, rt);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgeu(Register rd, Register rs, const Operand& rt) {
  Sltu(rd, rs, rt);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgt(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    slt(rd, rt.rm(), rs);
  } else {
    if (rt.immediate() == 0 && !MustUseReg(rt.rmode())) {
      slt(rd, zero_reg, rs);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rs != scratch);
      li(scratch, rt);
      slt(rd, scratch, rs);
    }
  }
}

void MacroAssembler::Sgtu(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    sltu(rd, rt.rm(), rs);
  } else {
    if (rt.immediate() == 0 && !MustUseReg(rt.rmode())) {
      sltu(rd, zero_reg, rs);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rs != scratch);
      li(scratch, rt);
      sltu(rd, scratch, rs);
    }
  }
}

void MacroAssembler::Ror(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    rotrv(rd, rs, rt.rm());
  } else {
    int64_t ror_value = rt.immediate() % 32;
    if (ror_value < 0) {
      ror_value += 32;
    }
    rotr(rd, rs, ror_value);
  }
}

void MacroAssembler::Dror(Register rd, Register rs, const Operand& rt) {
  if (rt.is_reg()) {
    drotrv(rd, rs, rt.rm());
  } else {
    int64_t dror_value = rt.immediate() % 64;
    if (dror_value < 0) dror_value += 64;
    if (dror_value <= 31) {
      drotr(rd, rs, dror_value);
    } else {
      drotr32(rd, rs, dror_value - 32);
    }
  }
}

void MacroAssembler::Pref(int32_t hint, const MemOperand& rs) {
  pref(hint, rs);
}

void MacroAssembler::Lsa(Register rd, Register rt, Register rs, uint8_t sa,
                         Register scratch) {
  DCHECK(sa >= 1 && sa <= 31);
  if (kArchVariant == kMips64r6 && sa <= 4) {
    lsa(rd, rt, rs, sa - 1);
  } else {
    Register tmp = rd == rt ? scratch : rd;
    DCHECK(tmp != rt);
    sll(tmp, rs, sa);
    Addu(rd, rt, tmp);
  }
}

void MacroAssembler::Dlsa(Register rd, Register rt, Register rs, uint8_t sa,
                          Register scratch) {
  DCHECK(sa >= 1 && sa <= 63);
  if (kArchVariant == kMips64r6 && sa <= 4) {
    dlsa(rd, rt, rs, sa - 1);
  } else {
    Register tmp = rd == rt ? scratch : rd;
    DCHECK(tmp != rt);
    if (sa <= 31)
      dsll(tmp, rs, sa);
    else
      dsll32(tmp, rs, sa - 32);
    Daddu(rd, rt, tmp);
  }
}

void MacroAssembler::Bovc(Register rs, Register rt, Label* L) {
  if (is_trampoline_emitted()) {
    Label skip;
    bnvc(rs, rt, &skip);
    BranchLong(L, PROTECT);
    bind(&skip);
  } else {
    bovc(rs, rt, L);
  }
}

void MacroAssembler::Bnvc(Register rs, Register rt, Label* L) {
  if (is_trampoline_emitted()) {
    Label skip;
    bovc(rs, rt, &skip);
    BranchLong(L, PROTECT);
    bind(&skip);
  } else {
    bnvc(rs, rt, L);
  }
}

// ------------Pseudo-instructions-------------

// Change endianness
void MacroAssembler::ByteSwapSigned(Register dest, Register src,
                                    int operand_size) {
  DCHECK(operand_size == 2 || operand_size == 4 || operand_size == 8);
  DCHECK(kArchVariant == kMips64r6 || kArchVariant == kMips64r2);
  if (operand_size == 2) {
    wsbh(dest, src);
    seh(dest, dest);
  } else if (operand_size == 4) {
    wsbh(dest, src);
    rotr(dest, dest, 16);
  } else {
    dsbh(dest, src);
    dshd(dest, dest);
  }
}

void MacroAssembler::ByteSwapUnsigned(Register dest, Register src,
                                      int operand_size) {
  DCHECK(operand_size == 2 || operand_size == 4);
  if (operand_size == 2) {
    wsbh(dest, src);
    andi(dest, dest, 0xFFFF);
  } else {
    wsbh(dest, src);
    rotr(dest, dest, 16);
    dinsu_(dest, zero_reg, 32, 32);
  }
}

void MacroAssembler::Ulw(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Lw(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(kMipsLwrOffset <= 3 && kMipsLwlOffset <= 3);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 3 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 3);
    if (rd != source.rm()) {
      lwr(rd, MemOperand(source.rm(), source.offset() + kMipsLwrOffset));
      lwl(rd, MemOperand(source.rm(), source.offset() + kMipsLwlOffset));
    } else {
      UseScra
"""


```