Response: The user wants a summary of the provided C++ code file, specifically the first part.
The file is part of the V8 JavaScript engine and seems to define a `MacroAssembler` for the MIPS64 architecture.
This suggests it provides a high-level interface for generating MIPS64 assembly instructions.

Key functionalities observed in the first part:
- Handling of caller-saved registers (pushing and popping).
- Loading constants and roots.
- Managing stack frames (common and standard).
- Implementing write barriers for garbage collection.
- Providing macros for common MIPS64 instructions (arithmetic, logical, memory access).
- Supporting both MIPS64r2 and MIPS64r6 instruction sets.

Relationship with JavaScript:
This code is fundamental for the V8 engine's ability to execute JavaScript code on MIPS64. It's the layer that translates higher-level operations into the actual machine instructions the CPU understands.
这个C++代码文件是V8 JavaScript引擎中用于MIPS64架构的宏汇编器（MacroAssembler）的实现。它的主要功能是提供一个高级接口，用于生成MIPS64汇编指令序列。通过这个宏汇编器，V8引擎可以在运行时动态地生成执行JavaScript代码所需的机器码。

具体来说，在这第一部分的代码中，我们可以看到以下功能：

1. **管理调用者保存的寄存器 (Caller-saved registers):** 提供了 `PushCallerSaved` 和 `PopCallerSaved` 函数，用于在函数调用前后保存和恢复那些由被调用者负责保存的寄存器。这确保了函数调用不会意外地修改调用者的寄存器状态。

2. **加载根对象 (Load Root Objects):**  提供了 `LoadRoot` 函数，用于加载预定义的根对象（例如，`undefined`, `null` 等）到寄存器中。这些根对象在V8引擎的运行中扮演着重要的角色。

3. **管理栈帧 (Stack Frame Management):**  提供了 `PushCommonFrame` 和 `PushStandardFrame` 函数，用于设置函数调用的栈帧结构。栈帧用于存储函数的局部变量、返回地址和其他必要的上下文信息。

4. **记录写屏障 (Record Write Barrier):**  提供了 `RecordWriteField` 和 `RecordWrite` 函数，用于在修改堆对象时插入写屏障。写屏障是垃圾回收机制的关键组成部分，用于跟踪堆对象的引用关系，确保垃圾回收的正确性。

5. **调用内置函数和桩代码 (Call Builtins and Stubs):** 提供了 `CallBuiltin` 和 `CallRecordWriteStub` 函数，用于调用V8引擎预定义的内置函数和一些常用的代码片段（桩代码）。

6. **提供常用的MIPS64指令宏 (Instruction Macros):**  定义了许多以大写字母开头的函数（例如 `Addu`, `Daddu`, `Subu`, `Dsubu` 等），这些函数是对底层MIPS64汇编指令的封装，使得生成汇编代码更加方便和易读。这些宏考虑了不同的操作数类型（寄存器和立即数），并根据情况选择最优的指令序列。

7. **处理立即数加载 (Load Immediate):** 提供了 `li` 函数的多种重载形式，用于将立即数加载到寄存器中。这个函数会根据立即数的大小和架构特性选择最优的指令序列，并处理重定位信息。

8. **批量压栈和出栈 (Multi-Push and Multi-Pop):** 提供了 `MultiPush` 和 `MultiPop` 函数，用于批量地将多个通用寄存器或浮点寄存器压入或弹出栈。

9. **位操作指令 (Bit Manipulation Instructions):** 提供了 `Ext`, `Dext`, `Ins`, `Dins` 等函数，用于执行位提取和插入操作。

**与JavaScript功能的关系及JavaScript示例:**

这个文件中的代码是V8引擎将JavaScript代码转换成机器码的关键部分。当V8执行JavaScript代码时，它会使用这个宏汇编器生成对应的MIPS64指令。

例如，考虑以下简单的JavaScript代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当V8引擎执行这段代码时，`MacroAssemblerMIPS64` 中的相关功能会被调用，大致过程如下：

1. **函数调用 `add(5, 10)`:**
   -  `PushStandardFrame` 可能被用来建立 `add` 函数的栈帧。
   -  参数 `5` 和 `10` 会被加载到寄存器中。
   -  `Addu` 或 `Daddu` 宏会被用来生成加法指令，将两个寄存器中的值相加。
   -  返回值会被存储到指定的寄存器中。
   -  `Pop` 操作可能会用来清理栈帧。

2. **变量赋值 `let result = ...`:**
   - 如果 `result` 是一个堆对象，并且加法的结果也需要存储到堆中，那么 `RecordWriteField` 或 `RecordWrite` 可能会被调用，以确保垃圾回收机制能够正确跟踪这个新的引用关系。

3. **加载常量:**
   - 当需要使用数字字面量 `5` 和 `10` 时，`li` 宏会被用来将这些立即数加载到寄存器中。

**更具体的JavaScript示例和可能生成的MIPS64汇编代码片段（简化）：**

假设 `a` 在寄存器 `r0`， `b` 在寄存器 `r1`， `result` 最终存储在 `r2`:

```assembly
// ... 函数栈帧设置 ...
daddu r2, r0, r1  //  对应 JavaScript 的 a + b
// ... 函数返回 ...
```

再比如，如果涉及堆对象的写入：

```javascript
let obj = {};
obj.value = 100;
```

生成的汇编代码中可能会包含 `RecordWrite` 的调用，确保垃圾回收器知道 `obj` 指向了一个包含值 `100` 的堆对象。

总而言之，`macro-assembler-mips64.cc` 文件是V8引擎在MIPS64架构上生成和优化机器码的核心组件，它直接影响着JavaScript代码的执行效率和内存管理。

### 提示词
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      lwr(scratch, MemOperand(rs.rm(), rs.offset() + kMipsLwrOffset));
      lwl(scratch, MemOperand(rs.rm(), rs.offset() + kMipsLwlOffset));
      mov(rd, scratch);
    }
  }
}

void MacroAssembler::Ulwu(Register rd, const MemOperand& rs) {
  if (kArchVariant == kMips64r6) {
    Lwu(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    Ulw(rd, rs);
    Dext(rd, rd, 0, 32);
  }
}

void MacroAssembler::Usw(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  DCHECK(rd != rs.rm());
  if (kArchVariant == kMips64r6) {
    Sw(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(kMipsSwrOffset <= 3 && kMipsSwlOffset <= 3);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 3 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 3);
    swr(rd, MemOperand(source.rm(), source.offset() + kMipsSwrOffset));
    swl(rd, MemOperand(source.rm(), source.offset() + kMipsSwlOffset));
  }
}

void MacroAssembler::Ulh(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Lh(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 1 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 1);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    if (source.rm() == scratch) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      Lb(rd, MemOperand(source.rm(), source.offset() + 1));
      Lbu(scratch, source);
#elif defined(V8_TARGET_BIG_ENDIAN)
      Lb(rd, source);
      Lbu(scratch, MemOperand(source.rm(), source.offset() + 1));
#endif
    } else {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      Lbu(scratch, source);
      Lb(rd, MemOperand(source.rm(), source.offset() + 1));
#elif defined(V8_TARGET_BIG_ENDIAN)
      Lbu(scratch, MemOperand(source.rm(), source.offset() + 1));
      Lb(rd, source);
#endif
    }
    dsll(rd, rd, 8);
    or_(rd, rd, scratch);
  }
}

void MacroAssembler::Ulhu(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Lhu(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 1 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 1);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    if (source.rm() == scratch) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      Lbu(rd, MemOperand(source.rm(), source.offset() + 1));
      Lbu(scratch, source);
#elif defined(V8_TARGET_BIG_ENDIAN)
      Lbu(rd, source);
      Lbu(scratch, MemOperand(source.rm(), source.offset() + 1));
#endif
    } else {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      Lbu(scratch, source);
      Lbu(rd, MemOperand(source.rm(), source.offset() + 1));
#elif defined(V8_TARGET_BIG_ENDIAN)
      Lbu(scratch, MemOperand(source.rm(), source.offset() + 1));
      Lbu(rd, source);
#endif
    }
    dsll(rd, rd, 8);
    or_(rd, rd, scratch);
  }
}

void MacroAssembler::Ush(Register rd, const MemOperand& rs, Register scratch) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  DCHECK(rs.rm() != scratch);
  DCHECK(scratch != at);
  if (kArchVariant == kMips64r6) {
    Sh(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 1 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 1);

    if (scratch != rd) {
      mov(scratch, rd);
    }

#if defined(V8_TARGET_LITTLE_ENDIAN)
    Sb(scratch, source);
    srl(scratch, scratch, 8);
    Sb(scratch, MemOperand(source.rm(), source.offset() + 1));
#elif defined(V8_TARGET_BIG_ENDIAN)
    Sb(scratch, MemOperand(source.rm(), source.offset() + 1));
    srl(scratch, scratch, 8);
    Sb(scratch, source);
#endif
  }
}

void MacroAssembler::Uld(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Ld(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(kMipsLdrOffset <= 7 && kMipsLdlOffset <= 7);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 7 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 7);
    if (rd != source.rm()) {
      ldr(rd, MemOperand(source.rm(), source.offset() + kMipsLdrOffset));
      ldl(rd, MemOperand(source.rm(), source.offset() + kMipsLdlOffset));
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      ldr(scratch, MemOperand(rs.rm(), rs.offset() + kMipsLdrOffset));
      ldl(scratch, MemOperand(rs.rm(), rs.offset() + kMipsLdlOffset));
      mov(rd, scratch);
    }
  }
}

// Load consequent 32-bit word pair in 64-bit reg. and put first word in low
// bits,
// second word in high bits.
void MacroAssembler::LoadWordPair(Register rd, const MemOperand& rs,
                                  Register scratch) {
  Lwu(rd, rs);
  Lw(scratch, MemOperand(rs.rm(), rs.offset() + kPointerSize / 2));
  dsll32(scratch, scratch, 0);
  Daddu(rd, rd, scratch);
}

void MacroAssembler::Usd(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Sd(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(kMipsSdrOffset <= 7 && kMipsSdlOffset <= 7);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 7 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 7);
    sdr(rd, MemOperand(source.rm(), source.offset() + kMipsSdrOffset));
    sdl(rd, MemOperand(source.rm(), source.offset() + kMipsSdlOffset));
  }
}

// Do 64-bit store as two consequent 32-bit stores to unaligned address.
void MacroAssembler::StoreWordPair(Register rd, const MemOperand& rs,
                                   Register scratch) {
  Sw(rd, rs);
  dsrl32(scratch, rd, 0);
  Sw(scratch, MemOperand(rs.rm(), rs.offset() + kPointerSize / 2));
}

void MacroAssembler::Ulwc1(FPURegister fd, const MemOperand& rs,
                           Register scratch) {
  if (kArchVariant == kMips64r6) {
    Lwc1(fd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    Ulw(scratch, rs);
    mtc1(scratch, fd);
  }
}

void MacroAssembler::Uswc1(FPURegister fd, const MemOperand& rs,
                           Register scratch) {
  if (kArchVariant == kMips64r6) {
    Swc1(fd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    mfc1(scratch, fd);
    Usw(scratch, rs);
  }
}

void MacroAssembler::Uldc1(FPURegister fd, const MemOperand& rs,
                           Register scratch) {
  DCHECK(scratch != at);
  if (kArchVariant == kMips64r6) {
    Ldc1(fd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    Uld(scratch, rs);
    dmtc1(scratch, fd);
  }
}

void MacroAssembler::Usdc1(FPURegister fd, const MemOperand& rs,
                           Register scratch) {
  DCHECK(scratch != at);
  if (kArchVariant == kMips64r6) {
    Sdc1(fd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    dmfc1(scratch, fd);
    Usd(scratch, rs);
  }
}

void MacroAssembler::Lb(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lb(rd, source);
}

void MacroAssembler::Lbu(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lbu(rd, source);
}

void MacroAssembler::Sb(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  sb(rd, source);
}

void MacroAssembler::Lh(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lh(rd, source);
}

void MacroAssembler::Lhu(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lhu(rd, source);
}

void MacroAssembler::Sh(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  sh(rd, source);
}

void MacroAssembler::Lw(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lw(rd, source);
}

void MacroAssembler::Lwu(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lwu(rd, source);
}

void MacroAssembler::Sw(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  sw(rd, source);
}

void MacroAssembler::Ld(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  ld(rd, source);
}

void MacroAssembler::Sd(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  sd(rd, source);
}

void MacroAssembler::Lwc1(FPURegister fd, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  lwc1(fd, tmp);
}

void MacroAssembler::Swc1(FPURegister fs, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  swc1(fs, tmp);
}

void MacroAssembler::Ldc1(FPURegister fd, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  ldc1(fd, tmp);
}

void MacroAssembler::Sdc1(FPURegister fs, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  sdc1(fs, tmp);
}

void MacroAssembler::Ll(Register rd, const MemOperand& rs) {
  bool is_one_instruction = (kArchVariant == kMips64r6) ? is_int9(rs.offset())
                                                        : is_int16(rs.offset());
  if (is_one_instruction) {
    ll(rd, rs);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rs.offset());
    daddu(scratch, scratch, rs.rm());
    ll(rd, MemOperand(scratch, 0));
  }
}

void MacroAssembler::Lld(Register rd, const MemOperand& rs) {
  bool is_one_instruction = (kArchVariant == kMips64r6) ? is_int9(rs.offset())
                                                        : is_int16(rs.offset());
  if (is_one_instruction) {
    lld(rd, rs);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rs.offset());
    daddu(scratch, scratch, rs.rm());
    lld(rd, MemOperand(scratch, 0));
  }
}

void MacroAssembler::Sc(Register rd, const MemOperand& rs) {
  bool is_one_instruction = (kArchVariant == kMips64r6) ? is_int9(rs.offset())
                                                        : is_int16(rs.offset());
  if (is_one_instruction) {
    sc(rd, rs);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rs.offset());
    daddu(scratch, scratch, rs.rm());
    sc(rd, MemOperand(scratch, 0));
  }
}

void MacroAssembler::Scd(Register rd, const MemOperand& rs) {
  bool is_one_instruction = (kArchVariant == kMips64r6) ? is_int9(rs.offset())
                                                        : is_int16(rs.offset());
  if (is_one_instruction) {
    scd(rd, rs);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rs.offset());
    daddu(scratch, scratch, rs.rm());
    scd(rd, MemOperand(scratch, 0));
  }
}

void MacroAssembler::li(Register dst, Handle<HeapObject> value, LiFlags mode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  }
  li(dst, Operand(value), mode);
}

void MacroAssembler::li(Register dst, ExternalReference reference,
                        LiFlags mode) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      Daddu(dst, kRootRegister, Operand(reference.offset_from_root_register()));
      return;
    }
    if (options().isolate_independent_code) {
      IndirectLoadExternalReference(dst, reference);
      return;
    }
  }

  // External references should not get created with IDs if
  // `!root_array_available()`.
  CHECK(!reference.IsIsolateFieldId());
  li(dst, Operand(reference), mode);
}

static inline int InstrCountForLiLower32Bit(int64_t value) {
  if (!is_int16(static_cast<int32_t>(value)) && (value & kUpper16MaskOf64) &&
      (value & kImm16Mask)) {
    return 2;
  } else {
    return 1;
  }
}

void MacroAssembler::LiLower32BitHelper(Register rd, Operand j) {
  if (is_int16(static_cast<int32_t>(j.immediate()))) {
    daddiu(rd, zero_reg, (j.immediate() & kImm16Mask));
  } else if (!(j.immediate() & kUpper16MaskOf64)) {
    ori(rd, zero_reg, j.immediate() & kImm16Mask);
  } else {
    lui(rd, j.immediate() >> kLuiShift & kImm16Mask);
    if (j.immediate() & kImm16Mask) {
      ori(rd, rd, j.immediate() & kImm16Mask);
    }
  }
}

static inline int InstrCountForLoadReplicatedConst32(int64_t value) {
  uint32_t x = static_cast<uint32_t>(value);
  uint32_t y = static_cast<uint32_t>(value >> 32);

  if (x == y) {
    return (is_uint16(x) || is_int16(x) || (x & kImm16Mask) == 0) ? 2 : 3;
  }

  return INT_MAX;
}

int MacroAssembler::InstrCountForLi64Bit(int64_t value) {
  if (is_int32(value)) {
    return InstrCountForLiLower32Bit(value);
  } else {
    int bit31 = value >> 31 & 0x1;
    if ((value & kUpper16MaskOf64) == 0 && is_int16(value >> 32) &&
        kArchVariant == kMips64r6) {
      return 2;
    } else if ((value & (kHigher16MaskOf64 | kUpper16MaskOf64)) == 0 &&
               kArchVariant == kMips64r6) {
      return 2;
    } else if ((value & kImm16Mask) == 0 && is_int16((value >> 32) + bit31) &&
               kArchVariant == kMips64r6) {
      return 2;
    } else if ((value & kImm16Mask) == 0 &&
               ((value >> 31) & 0x1FFFF) == ((0x20000 - bit31) & 0x1FFFF) &&
               kArchVariant == kMips64r6) {
      return 2;
    } else if (is_int16(static_cast<int32_t>(value)) &&
               is_int16((value >> 32) + bit31) && kArchVariant == kMips64r6) {
      return 2;
    } else if (is_int16(static_cast<int32_t>(value)) &&
               ((value >> 31) & 0x1FFFF) == ((0x20000 - bit31) & 0x1FFFF) &&
               kArchVariant == kMips64r6) {
      return 2;
    } else if (base::bits::IsPowerOfTwo(value + 1) ||
               value == std::numeric_limits<int64_t>::max()) {
      return 2;
    } else {
      int shift_cnt = base::bits::CountTrailingZeros64(value);
      int rep32_count = InstrCountForLoadReplicatedConst32(value);
      int64_t tmp = value >> shift_cnt;
      if (is_uint16(tmp)) {
        return 2;
      } else if (is_int16(tmp)) {
        return 2;
      } else if (rep32_count < 3) {
        return 2;
      } else if (is_int32(tmp)) {
        return 3;
      } else {
        shift_cnt = 16 + base::bits::CountTrailingZeros64(value >> 16);
        tmp = value >> shift_cnt;
        if (is_uint16(tmp)) {
          return 3;
        } else if (is_int16(tmp)) {
          return 3;
        } else if (rep32_count < 4) {
          return 3;
        } else if (kArchVariant == kMips64r6) {
          int64_t imm = value;
          int count = InstrCountForLiLower32Bit(imm);
          imm = (imm >> 32) + bit31;
          if (imm & kImm16Mask) {
            count++;
          }
          imm = (imm >> 16) + (imm >> 15 & 0x1);
          if (imm & kImm16Mask) {
            count++;
          }
          return count;
        } else {
          if (is_int48(value)) {
            int64_t k = value >> 16;
            int count = InstrCountForLiLower32Bit(k) + 1;
            if (value & kImm16Mask) {
              count++;
            }
            return count;
          } else {
            int64_t k = value >> 32;
            int count = InstrCountForLiLower32Bit(k);
            if ((value >> 16) & kImm16Mask) {
              count += 3;
              if (value & kImm16Mask) {
                count++;
              }
            } else {
              count++;
              if (value & kImm16Mask) {
                count++;
              }
            }
            return count;
          }
        }
      }
    }
  }
  UNREACHABLE();
  return INT_MAX;
}

// All changes to if...else conditions here must be added to
// InstrCountForLi64Bit as well.
void MacroAssembler::li_optimized(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  DCHECK(!MustUseReg(j.rmode()));
  DCHECK(mode == OPTIMIZE_SIZE);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Normal load of an immediate value which does not need Relocation Info.
  if (is_int32(j.immediate())) {
    LiLower32BitHelper(rd, j);
  } else {
    int bit31 = j.immediate() >> 31 & 0x1;
    if ((j.immediate() & kUpper16MaskOf64) == 0 &&
        is_int16(j.immediate() >> 32) && kArchVariant == kMips64r6) {
      // 64-bit value which consists of an unsigned 16-bit value in its
      // least significant 32-bits, and a signed 16-bit value in its
      // most significant 32-bits.
      ori(rd, zero_reg, j.immediate() & kImm16Mask);
      dahi(rd, j.immediate() >> 32 & kImm16Mask);
    } else if ((j.immediate() & (kHigher16MaskOf64 | kUpper16MaskOf64)) == 0 &&
               kArchVariant == kMips64r6) {
      // 64-bit value which consists of an unsigned 16-bit value in its
      // least significant 48-bits, and a signed 16-bit value in its
      // most significant 16-bits.
      ori(rd, zero_reg, j.immediate() & kImm16Mask);
      dati(rd, j.immediate() >> 48 & kImm16Mask);
    } else if ((j.immediate() & kImm16Mask) == 0 &&
               is_int16((j.immediate() >> 32) + bit31) &&
               kArchVariant == kMips64r6) {
      // 16 LSBs (Least Significant Bits) all set to zero.
      // 48 MSBs (Most Significant Bits) hold a signed 32-bit value.
      lui(rd, j.immediate() >> kLuiShift & kImm16Mask);
      dahi(rd, ((j.immediate() >> 32) + bit31) & kImm16Mask);
    } else if ((j.immediate() & kImm16Mask) == 0 &&
               ((j.immediate() >> 31) & 0x1FFFF) ==
                   ((0x20000 - bit31) & 0x1FFFF) &&
               kArchVariant == kMips64r6) {
      // 16 LSBs all set to zero.
      // 48 MSBs hold a signed value which can't be represented by signed
      // 32-bit number, and the middle 16 bits are all zero, or all one.
      lui(rd, j.immediate() >> kLuiShift & kImm16Mask);
      dati(rd, ((j.immediate() >> 48) + bit31) & kImm16Mask);
    } else if (is_int16(static_cast<int32_t>(j.immediate())) &&
               is_int16((j.immediate() >> 32) + bit31) &&
               kArchVariant == kMips64r6) {
      // 32 LSBs contain a signed 16-bit number.
      // 32 MSBs contain a signed 16-bit number.
      daddiu(rd, zero_reg, j.immediate() & kImm16Mask);
      dahi(rd, ((j.immediate() >> 32) + bit31) & kImm16Mask);
    } else if (is_int16(static_cast<int32_t>(j.immediate())) &&
               ((j.immediate() >> 31) & 0x1FFFF) ==
                   ((0x20000 - bit31) & 0x1FFFF) &&
               kArchVariant == kMips64r6) {
      // 48 LSBs contain an unsigned 16-bit number.
      // 16 MSBs contain a signed 16-bit number.
      daddiu(rd, zero_reg, j.immediate() & kImm16Mask);
      dati(rd, ((j.immediate() >> 48) + bit31) & kImm16Mask);
    } else if (base::bits::IsPowerOfTwo(j.immediate() + 1) ||
               j.immediate() == std::numeric_limits<int64_t>::max()) {
      // 64-bit values which have their "n" LSBs set to one, and their
      // "64-n" MSBs set to zero. "n" must meet the restrictions 0 < n < 64.
      int shift_cnt = 64 - base::bits::CountTrailingZeros64(j.immediate() + 1);
      daddiu(rd, zero_reg, -1);
      if (shift_cnt < 32) {
        dsrl(rd, rd, shift_cnt);
      } else {
        dsrl32(rd, rd, shift_cnt & 31);
      }
    } else {
      int shift_cnt = base::bits::CountTrailingZeros64(j.immediate());
      int rep32_count = InstrCountForLoadReplicatedConst32(j.immediate());
      int64_t tmp = j.immediate() >> shift_cnt;
      if (is_uint16(tmp)) {
        // Value can be computed by loading a 16-bit unsigned value, and
        // then shifting left.
        ori(rd, zero_reg, tmp & kImm16Mask);
        if (shift_cnt < 32) {
          dsll(rd, rd, shift_cnt);
        } else {
          dsll32(rd, rd, shift_cnt & 31);
        }
      } else if (is_int16(tmp)) {
        // Value can be computed by loading a 16-bit signed value, and
        // then shifting left.
        daddiu(rd, zero_reg, static_cast<int32_t>(tmp));
        if (shift_cnt < 32) {
          dsll(rd, rd, shift_cnt);
        } else {
          dsll32(rd, rd, shift_cnt & 31);
        }
      } else if (rep32_count < 3) {
        // Value being loaded has 32 LSBs equal to the 32 MSBs, and the
        // value loaded into the 32 LSBs can be loaded with a single
        // MIPS instruction.
        LiLower32BitHelper(rd, j);
        Dins(rd, rd, 32, 32);
      } else if (is_int32(tmp)) {
        // Loads with 3 instructions.
        // Value can be computed by loading a 32-bit signed value, and
        // then shifting left.
        lui(rd, tmp >> kLuiShift & kImm16Mask);
        ori(rd, rd, tmp & kImm16Mask);
        if (shift_cnt < 32) {
          dsll(rd, rd, shift_cnt);
        } else {
          dsll32(rd, rd, shift_cnt & 31);
        }
      } else {
        shift_cnt = 16 + base::bits::CountTrailingZeros64(j.immediate() >> 16);
        tmp = j.immediate() >> shift_cnt;
        if (is_uint16(tmp)) {
          // Value can be computed by loading a 16-bit unsigned value,
          // shifting left, and "or"ing in another 16-bit unsigned value.
          ori(rd, zero_reg, tmp & kImm16Mask);
          if (shift_cnt < 32) {
            dsll(rd, rd, shift_cnt);
          } else {
            dsll32(rd, rd, shift_cnt & 31);
          }
          ori(rd, rd, j.immediate() & kImm16Mask);
        } else if (is_int16(tmp)) {
          // Value can be computed by loading a 16-bit signed value,
          // shifting left, and "or"ing in a 16-bit unsigned value.
          daddiu(rd, zero_reg, static_cast<int32_t>(tmp));
          if (shift_cnt < 32) {
            dsll(rd, rd, shift_cnt);
          } else {
            dsll32(rd, rd, shift_cnt & 31);
          }
          ori(rd, rd, j.immediate() & kImm16Mask);
        } else if (rep32_count < 4) {
          // Value being loaded has 32 LSBs equal to the 32 MSBs, and the
          // value in the 32 LSBs requires 2 MIPS instructions to load.
          LiLower32BitHelper(rd, j);
          Dins(rd, rd, 32, 32);
        } else if (kArchVariant == kMips64r6) {
          // Loads with 3-4 instructions.
          // Catch-all case to get any other 64-bit values which aren't
          // handled by special cases above.
          int64_t imm = j.immediate();
          LiLower32BitHelper(rd, j);
          imm = (imm >> 32) + bit31;
          if (imm & kImm16Mask) {
            dahi(rd, imm & kImm16Mask);
          }
          imm = (imm >> 16) + (imm >> 15 & 0x1);
          if (imm & kImm16Mask) {
            dati(rd, imm & kImm16Mask);
          }
        } else {
          if (is_int48(j.immediate())) {
            Operand k = Operand(j.immediate() >> 16);
            LiLower32BitHelper(rd, k);
            dsll(rd, rd, 16);
            if (j.immediate() & kImm16Mask) {
              ori(rd, rd, j.immediate() & kImm16Mask);
            }
          } else {
            Operand k = Operand(j.immediate() >> 32);
            LiLower32BitHelper(rd, k);
            if ((j.immediate() >> 16) & kImm16Mask) {
              dsll(rd, rd, 16);
              ori(rd, rd, (j.immediate() >> 16) & kImm16Mask);
              dsll(rd, rd, 16);
              if (j.immediate() & kImm16Mask) {
                ori(rd, rd, j.immediate() & kImm16Mask);
              }
            } else {
              dsll32(rd, rd, 0);
              if (j.immediate() & kImm16Mask) {
                ori(rd, rd, j.immediate() & kImm16Mask);
              }
            }
          }
        }
      }
    }
  }
}

void MacroAssembler::li(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (!MustUseReg(j.rmode()) && mode == OPTIMIZE_SIZE) {
    int li_count = InstrCountForLi64Bit(j.immediate());
    int li_neg_count = InstrCountForLi64Bit(-j.immediate());
    int li_not_count = InstrCountForLi64Bit(~j.immediate());
    // Loading -MIN_INT64 could cause problems, but loading MIN_INT64 takes only
    // two instructions so no need to check for this.
    if (li_neg_count <= li_not_count && li_neg_count < li_count - 1) {
      DCHECK(j.immediate() != std::numeric_limits<int64_t>::min());
      li_optimized(rd, Operand(-j.immediate()), mode);
      Dsubu(rd, zero_reg, rd);
    } else if (li_neg_count > li_not_count && li_not_count < li_count - 1) {
      DCHECK(j.immediate() != std::numeric_limits<int64_t>::min());
      li_optimized(rd, Operand(~j.immediate()), mode);
      nor(rd, rd, rd);
    } else {
      li_optimized(rd, j, mode);
    }
  } else if (MustUseReg(j.rmode())) {
    int64_t immediate;
    if (j.IsHeapNumberRequest()) {
      RequestHeapNumber(j.heap_number_request());
      immediate = 0;
    } else {
      immediate = j.immediate();
    }

    RecordRelocInfo(j.rmode(), immediate);
    if (RelocInfo::IsWasmCanonicalSigId(j.rmode())) {
      // wasm_canonical_sig_id is 32-bit value.
      DCHECK(is_int32(immediate));
      lui(rd, (immediate >> 16) & kImm16Mask);
      ori(rd, rd, immediate & kImm16Mask);
      return;
    }
    lui(rd, (immediate >> 32) & kImm16Mask);
    ori(rd, rd, (immediate >> 16) & kImm16Mask);
    dsll(rd, rd, 16);
    ori(rd, rd, immediate & kImm16Mask);
  } else if (mode == ADDRESS_LOAD) {
    // We always need the same number of instructions as we may need to patch
    // this code to load another value which may need all 4 instructions.
    lui(rd, (j.immediate() >> 32) & kImm16Mask);
    ori(rd, rd, (j.immediate() >> 16) & kImm16Mask);
    dsll(rd, rd, 16);
    ori(rd, rd, j.immediate() & kImm16Mask);
  } else {  // mode == CONSTANT_SIZE - always emit the same instruction
            // sequence.
    if (kArchVariant == kMips64r6) {
      int64_t imm = j.immediate();
      lui(rd, imm >> kLuiShift & kImm16Mask);
      ori(rd, rd, (imm & kImm16Mask));
      imm = (imm >> 32) + ((imm >> 31) & 0x1);
      dahi(rd, imm & kImm16Mask & kImm16Mask);
      imm = (imm >> 16) + ((imm >> 15) & 0x1);
      dati(rd, imm & kImm16Mask & kImm16Mask);
    } else {
      lui(rd, (j.immediate() >> 48) & kImm16Mask);
      ori(rd, rd, (j.immediate() >> 32) & kImm16Mask);
      dsll(rd, rd, 16);
      ori(rd, rd, (j.immediate() >> 16) & kImm16Mask);
      dsll(rd, rd, 16);
      ori(rd, rd, j.immediate() & kImm16Mask);
    }
  }
}

void MacroAssembler::LoadIsolateField(Register dst, IsolateFieldId id) {
  li(dst, ExternalReference::Create(id));
}

void MacroAssembler::MultiPush(RegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kPointerSize;

  Dsubu(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kPointerSize;
      Sd(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPop(RegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      Ld(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kPointerSize;
    }
  }
  daddiu(sp, sp, stack_offset);
}

void MacroAssembler::MultiPushFPU(DoubleRegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  Dsubu(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kDoubleSize;
      Sdc1(FPURegister::from_code(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPopFPU(DoubleRegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      Ldc1(FPURegister::from_code(i), MemOperand(sp, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  daddiu(sp, sp, stack_offset);
}

void MacroAssembler::MultiPushMSA(DoubleRegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kSimd128Size;

  Dsubu(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kSimd128Size;
      st_d(MSARegister::from_code(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPopMSA(DoubleRegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      ld_d(MSARegister::from_code(i), MemOperand(sp, stack_offset));
      stack_offset += kSimd128Size;
    }
  }
  daddiu(sp, sp, stack_offset);
}

void MacroAssembler::Ext(Register rt, Register rs, uint16_t pos,
                         uint16_t size) {
  DCHECK_LT(pos, 32);
  DCHECK_LT(pos + size, 33);
  ext_(rt, rs, pos, size);
}

void MacroAssembler::Dext(Register rt, Register rs, uint16_t pos,
                          uint16_t size) {
  DCHECK(pos < 64 && 0 < size && size <= 64 && 0 < pos + size &&
         pos + size <= 64);
  if (size > 32) {
    dextm_(rt, rs, pos, size);
  } else if (pos >= 32) {
    dextu_(rt, rs, pos, size);
  } else {
    dext_(rt, rs, pos, size);
  }
}

void MacroAssembler::Ins(Register rt, Register rs, uint16_t pos,
                         uint16_t size) {
  DCHECK_LT(pos, 32);
  DCHECK_LE(pos + size, 32);
  DCHECK_NE(size, 0);
  ins_(rt, rs, pos, size);
}

void MacroAssembler::Dins(Register rt, Register rs, uint16_t pos,
                          uint16_t size) {
  DCHECK(pos < 64 && 0 < size && size <= 64 && 0 < pos + size &&
         pos + size <= 64);
  if (pos + size <= 32) {
    dins_(rt, rs, pos, size);
  } else if (pos < 32) {
    dinsm_(rt, rs, pos, size);
  } else {
    dinsu_(rt, rs, pos, size);
  }
}

void MacroAssembler::ExtractBits(Register dest, Register source, Register pos,
                                 int size, bool sign_extend) {
  dsrav(dest, source, pos);
  Dext(dest, dest, 0, size);
  if (sign_extend) {
    switch (size) {
      case 8:
        seb(dest, dest);
        break;
      case 16:
        seh(dest, dest);
        break;
      case 32:
        // sign-extend word
        sll(dest, dest, 0);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void MacroAssembler::InsertBits(Register dest, Register source, Register pos,
                                int size) {
  Dror(dest, dest, pos);
  Dins(dest, source, 0, size);
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Dsubu(scratch, zero_reg, pos);
    Dror(dest, dest, scratch);
  }
}

void MacroAssembler::Neg_s(FPURegister fd, FPURegister fs) {
  if (kArchVariant == kMips64r6) {
    // r6 neg_s changes the sign for NaN-like operands as well.
    neg_s(fd, fs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Label is_nan, done;
    Register scratch1 = t8;
    Register scratch2 = t9;
    CompareIsNanF32(fs, fs);
    BranchTrueShortF(&is_nan);
    Branch(USE_DELAY_SLOT, &done);
    // For NaN input, neg_s will return the same NaN value,
    // while the sign has to be changed separately.
    neg_s(fd, fs);  // In delay slot.
    bind(&is_nan);
    mfc1(scratch1, fs);
    li(scratch2, kBinary32SignMask);
    Xor(scratch1, scratch1, scratch2);
    mtc1(scratch1, fd);
    bind(&done);
  }
}

void MacroAssembler::Neg_d(FPURegister fd, FPURegister fs) {
  if (kArchVariant == kMips64r6) {
    // r6 neg_d changes the sign for NaN-like operands as well.
    neg_d(fd, fs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Label is_nan, done;
    Register scratch1 = t8;
    Register scratch2 = t9;
    CompareIsNanF64(fs, fs);
    BranchTrueShortF(&is_nan);
    Branch(USE_DELAY_SLOT, &done);
    // For NaN input, neg_d will return the same NaN value,
    // while the sign has to be changed separately.
    neg_d(fd, fs);  // In delay slot.
    bind(&is_nan);
    dmfc1(scratch1, fs);
    li(scratch2, base::Double::kSignMask);
    Xor(scratch1, scratch1, scratch2);
    dmtc1(scratch1, fd);
    bind(&done);
  }
}

void MacroAssembler::Cvt_d_uw(FPURegister fd, FPURegister fs) {
  // Move the data from fs to t8.
  BlockTrampolinePoolScope
```