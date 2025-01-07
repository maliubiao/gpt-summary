Response:
The user wants a summary of the functionality of the provided C++ code snippet.

Here's a breakdown of how to arrive at the summary:

1. **Identify the file's purpose:** The filename `instruction-scheduler-riscv.cc` strongly suggests this code is related to instruction scheduling for the RISC-V architecture within the V8 JavaScript engine.

2. **Analyze the includes:** The included headers `macro-assembler.h` and `instruction-scheduler.h` confirm this. `macro-assembler.h` deals with low-level code generation, and `instruction-scheduler.h` likely defines the base class for instruction scheduling.

3. **Examine the `namespace`:**  The code resides within `v8::internal::compiler`, indicating it's part of the compiler pipeline in V8.

4. **Inspect the `SchedulerSupported()` function:** This simple function returning `true` implies that instruction scheduling is supported for the RISC-V architecture in V8.

5. **Focus on `GetTargetInstructionFlags()`:** This function is crucial. It takes an `Instruction` pointer as input and returns an integer representing flags. The `switch` statement examines the `arch_opcode()` of the instruction. This strongly suggests the function's purpose is to determine specific characteristics or flags for various RISC-V instructions, which are likely used by the scheduler. The `#if V8_TARGET_ARCH_RISCV64` and `#elif V8_TARGET_ARCH_RISCV32` sections show it handles both 32-bit and 64-bit RISC-V variants. The `kIsLoadOperation` and `kHasSideEffect` return values point to the types of flags being identified.

6. **Analyze the `Latency` enum and related functions:**  The `Latency` enum defines latency values for various RISC-V instructions. The numerous functions like `Add64Latency`, `Mul32Latency`, `LoadFloatLatency`, etc., calculate the latency of specific instructions, potentially taking into account whether operands are registers or immediate values. This is a key aspect of instruction scheduling, as it aims to optimize execution by considering instruction execution times.

7. **Connect the pieces:** The `GetTargetInstructionFlags()` function provides information *about* instructions, and the `Latency` calculations provide information *about the cost* of instructions. Both are essential for an instruction scheduler.

8. **Consider the "Torque" mention:** The prompt specifically asks about `.tq` files. Since this file is `.cc`, it's C++, not Torque.

9. **Consider the JavaScript relationship:**  The code directly relates to how JavaScript code is compiled and executed on RISC-V. Instruction scheduling is a performance optimization step in the compilation process.

10. **Think about examples and errors:** While the C++ code itself isn't directly user-facing, the *impact* of instruction scheduling is on the performance of JavaScript code. Common programming errors that could be *affected* by scheduling (though not caused by it) might involve performance-sensitive code where instruction order matters.

11. **Synthesize the summary:** Combine the observations to formulate a concise description of the file's role.
Based on the provided C++ code snippet from `v8/src/compiler/backend/riscv/instruction-scheduler-riscv.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This C++ file defines the **RISC-V specific implementation of the instruction scheduler** within the V8 JavaScript engine's compiler backend. Its primary responsibilities are:

1. **Declare Scheduler Support:** The `SchedulerSupported()` function simply returns `true`, indicating that instruction scheduling is enabled and supported for the RISC-V architecture within V8.

2. **Determine Instruction Flags:** The `GetTargetInstructionFlags()` function analyzes individual RISC-V instructions (represented by the `Instruction` class) and returns flags that describe their characteristics. These flags are used by the generic instruction scheduler to make informed scheduling decisions. The code uses a large `switch` statement based on the `arch_opcode()` of the instruction to identify specific instruction types and assign appropriate flags. Examples of flags identified include:
    * `kIsLoadOperation`: Indicates if the instruction is a memory load.
    * `kHasSideEffect`: Indicates if the instruction has side effects beyond writing to its output registers (e.g., memory stores, calls).
    * `kNoOpcodeFlags`:  Indicates the instruction doesn't have any special flags relevant to scheduling.

3. **Estimate Instruction Latency:** The code defines an `enum Latency` which provides estimated execution latencies (in CPU cycles) for various RISC-V instructions. Several helper functions (e.g., `Add64Latency`, `Mul32Latency`, `LoadFloatLatency`) calculate the latency of specific instruction types, potentially considering factors like whether an operand is a register or an immediate value. These latency estimates are crucial for the scheduler to order instructions to minimize pipeline stalls and improve performance.

**Regarding your specific questions:**

* **`.tq` extension:** The file ends with `.cc`, so it is a **C++ source file**, not a V8 Torque source file. Torque files would have a `.tq` extension.

* **Relationship with JavaScript:** This code directly impacts the performance of JavaScript code executed on RISC-V architectures. The instruction scheduler optimizes the low-level machine code generated by the V8 compiler for RISC-V. When V8 compiles JavaScript, it eventually generates a sequence of RISC-V instructions. The instruction scheduler reorders these instructions to potentially improve execution speed by taking advantage of the processor's pipelined architecture and reducing dependencies between instructions.

* **JavaScript example:**  While this code doesn't directly execute JavaScript, consider this simple JavaScript code:

   ```javascript
   function addMultiply(a, b, c) {
     const sum = a + b;
     const product = sum * c;
     return product;
   }
   ```

   The V8 compiler will translate this into RISC-V assembly instructions. The instruction scheduler would then analyze the dependencies between the instructions for the addition and multiplication and potentially reorder them or other surrounding instructions to optimize execution on the RISC-V processor. For example, if the result of the addition isn't immediately needed, the scheduler might move other independent instructions in between the addition and multiplication.

* **Code logic inference (with assumptions):**

   **Assumption:** Consider the RISC-V instruction `kRiscvAdd32` (32-bit addition).

   **Input to `GetTargetInstructionFlags()`:** An `Instruction` object where `instr->arch_opcode()` returns `kRiscvAdd32`.

   **Output of `GetTargetInstructionFlags()`:** `kNoOpcodeFlags` (based on the `switch` statement). This implies that a simple 32-bit addition doesn't have any special flags that the scheduler needs to be aware of for its scheduling decisions.

   **Input to `GetInstructionLatency()`:** An `Instruction` object where `instr->arch_opcode()` returns `kRiscvAdd32` and assuming the second operand is a register (`instr->InputAt(1)->IsRegister()` is true).

   **Output of `GetInstructionLatency()`:** The function would call `Add64Latency(true)` (note the function name is a bit of a misnomer here, likely for consistency). `Add64Latency(true)` would return `Latency::ADD`, which is defined as `1`. So the estimated latency for this instruction is 1 cycle.

* **User programming errors:** This C++ code itself is part of the V8 engine and not directly written by typical JavaScript users. However, the *benefit* of the instruction scheduler is to mitigate performance impacts from certain coding patterns. For example, consider a series of calculations with tight dependencies:

   ```javascript
   let x = a + b;
   let y = x * c;
   let z = y - d;
   ```

   Without instruction scheduling, the generated assembly might execute these operations sequentially, causing pipeline stalls as each instruction waits for the result of the previous one. The scheduler can identify opportunities to interleave independent instructions (if any are present in the surrounding code) to keep the processor's execution units busy.

**Summary of Functionality (Part 1):**

The primary function of `v8/src/compiler/backend/riscv/instruction-scheduler-riscv.cc` is to provide **RISC-V architecture-specific information and support for the V8 instruction scheduler**. This includes:

* **Enabling the scheduler for RISC-V.**
* **Defining flags for different RISC-V instructions to inform scheduling decisions.**
* **Providing estimated execution latencies for various RISC-V instructions, which the scheduler uses to optimize instruction order for better performance.**

This file is a crucial component in ensuring that JavaScript code runs efficiently on RISC-V processors by optimizing the order in which machine instructions are executed.

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/instruction-scheduler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-scheduler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/macro-assembler.h"
#include "src/compiler/backend/instruction-scheduler.h"

namespace v8 {
namespace internal {
namespace compiler {

bool InstructionScheduler::SchedulerSupported() { return true; }

int InstructionScheduler::GetTargetInstructionFlags(
    const Instruction* instr) const {
  switch (instr->arch_opcode()) {
    case kRiscvEnableDebugTrace:
    case kRiscvDisableDebugTrace:
#if V8_TARGET_ARCH_RISCV64
    case kRiscvAdd32:
    case kRiscvBitcastDL:
    case kRiscvBitcastLD:
    case kRiscvByteSwap64:
    case kRiscvCvtDL:
    case kRiscvCvtDUl:
    case kRiscvCvtSL:
    case kRiscvCvtSUl:
    case kRiscvMulHigh64:
    case kRiscvMulHighU64:
    case kRiscvAdd64:
    case kRiscvAddOvf64:
    case kRiscvClz64:
    case kRiscvCtz64:
    case kRiscvDiv64:
    case kRiscvDivU64:
    case kRiscvZeroExtendWord:
    case kRiscvSignExtendWord:
    case kRiscvMod64:
    case kRiscvModU64:
    case kRiscvMul64:
    case kRiscvMulOvf64:
    case kRiscvPopcnt64:
    case kRiscvRor64:
    case kRiscvSar64:
    case kRiscvShl64:
    case kRiscvShr64:
    case kRiscvSub64:
    case kRiscvSubOvf64:
    case kRiscvFloat64RoundDown:
    case kRiscvFloat64RoundTiesEven:
    case kRiscvFloat64RoundTruncate:
    case kRiscvFloat64RoundUp:
    case kRiscvSub32:
    case kRiscvTruncLD:
    case kRiscvTruncLS:
    case kRiscvTruncUlD:
    case kRiscvTruncUlS:
    case kRiscvCmp32:
    case kRiscvCmpZero32:
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvAdd32:
    case kRiscvAddPair:
    case kRiscvSubPair:
    case kRiscvMulPair:
    case kRiscvAndPair:
    case kRiscvOrPair:
    case kRiscvXorPair:
    case kRiscvShlPair:
    case kRiscvShrPair:
    case kRiscvSarPair:
    case kRiscvAddOvf:
    case kRiscvSubOvf:
    case kRiscvSub32:
#endif
    case kRiscvSh1add:
    case kRiscvSh2add:
    case kRiscvSh3add:
#if V8_TARGET_ARCH_RISCV64
    case kRiscvAdduw:
    case kRiscvSh1adduw:
    case kRiscvSh2adduw:
    case kRiscvSh3adduw:
    case kRiscvSlliuw:
#endif
    case kRiscvAndn:
    case kRiscvOrn:
    case kRiscvXnor:
    case kRiscvClz:
    case kRiscvCtz:
    case kRiscvCpop:
#if V8_TARGET_ARCH_RISCV64
    case kRiscvClzw:
    case kRiscvCtzw:
    case kRiscvCpopw:
#endif
    case kRiscvMax:
    case kRiscvMaxu:
    case kRiscvMin:
    case kRiscvMinu:
    case kRiscvSextb:
    case kRiscvSexth:
    case kRiscvZexth:
    case kRiscvRev8:
    case kRiscvBclr:
    case kRiscvBclri:
    case kRiscvBext:
    case kRiscvBexti:
    case kRiscvBinv:
    case kRiscvBinvi:
    case kRiscvBset:
    case kRiscvBseti:
    case kRiscvAbsD:
    case kRiscvAbsS:
    case kRiscvAddD:
    case kRiscvAddS:
    case kRiscvAnd:
    case kRiscvAnd32:
    case kRiscvAssertEqual:
    case kRiscvBitcastInt32ToFloat32:
    case kRiscvBitcastFloat32ToInt32:
    case kRiscvByteSwap32:
    case kRiscvCeilWD:
    case kRiscvCeilWS:
    case kRiscvClz32:
    case kRiscvCmp:
    case kRiscvCmpZero:
    case kRiscvCmpD:
    case kRiscvCmpS:
    case kRiscvCtz32:
    case kRiscvCvtDS:
    case kRiscvCvtDUw:
    case kRiscvCvtDW:
    case kRiscvCvtSD:
    case kRiscvCvtSUw:
    case kRiscvCvtSW:
    case kRiscvMulHighU32:
    case kRiscvDiv32:
    case kRiscvDivD:
    case kRiscvDivS:
    case kRiscvDivU32:
    case kRiscvF64x2Abs:
    case kRiscvF64x2Sqrt:
    case kRiscvF64x2Pmin:
    case kRiscvF64x2Pmax:
    case kRiscvF64x2ConvertLowI32x4S:
    case kRiscvF64x2ConvertLowI32x4U:
    case kRiscvF64x2PromoteLowF32x4:
    case kRiscvF64x2Ceil:
    case kRiscvF64x2Floor:
    case kRiscvF64x2Trunc:
    case kRiscvF64x2NearestInt:
    case kRiscvI64x2SplatI32Pair:
    case kRiscvI64x2ExtractLane:
    case kRiscvI64x2ReplaceLane:
    case kRiscvI64x2ReplaceLaneI32Pair:
    case kRiscvI64x2Shl:
    case kRiscvI64x2ShrS:
    case kRiscvI64x2ShrU:
    case kRiscvF32x4Abs:
    case kRiscvF32x4ExtractLane:
    case kRiscvF32x4Sqrt:
    case kRiscvF64x2Qfma:
    case kRiscvF64x2Qfms:
    case kRiscvF32x4Qfma:
    case kRiscvF32x4Qfms:
    case kRiscvF32x4ReplaceLane:
    case kRiscvF32x4SConvertI32x4:
    case kRiscvF32x4UConvertI32x4:
    case kRiscvF32x4Pmin:
    case kRiscvF32x4Pmax:
    case kRiscvF32x4DemoteF64x2Zero:
    case kRiscvF32x4Ceil:
    case kRiscvF32x4Floor:
    case kRiscvF32x4Trunc:
    case kRiscvF32x4NearestInt:
    case kRiscvF64x2ExtractLane:
    case kRiscvF64x2ReplaceLane:
    case kRiscvFloat32Max:
    case kRiscvFloat32Min:
    case kRiscvFloat32RoundDown:
    case kRiscvFloat32RoundTiesEven:
    case kRiscvFloat32RoundTruncate:
    case kRiscvFloat32RoundUp:
    case kRiscvFloat64ExtractLowWord32:
    case kRiscvFloat64ExtractHighWord32:
    case kRiscvFloat64InsertLowWord32:
    case kRiscvFloat64InsertHighWord32:
    case kRiscvFloat64Max:
    case kRiscvFloat64Min:
    case kRiscvFloat64SilenceNaN:
    case kRiscvFloorWD:
    case kRiscvFloorWS:
    case kRiscvI64x2SConvertI32x4Low:
    case kRiscvI64x2SConvertI32x4High:
    case kRiscvI64x2UConvertI32x4Low:
    case kRiscvI64x2UConvertI32x4High:
    case kRiscvI16x8ExtractLaneU:
    case kRiscvI16x8ExtractLaneS:
    case kRiscvI16x8ReplaceLane:
    case kRiscvI16x8Shl:
    case kRiscvI16x8ShrS:
    case kRiscvI16x8ShrU:
    case kRiscvI32x4TruncSatF64x2SZero:
    case kRiscvI32x4TruncSatF64x2UZero:
    case kRiscvI32x4ExtractLane:
    case kRiscvI32x4ReplaceLane:
    case kRiscvI32x4SConvertF32x4:
    case kRiscvI32x4Shl:
    case kRiscvI32x4ShrS:
    case kRiscvI32x4ShrU:
    case kRiscvI32x4UConvertF32x4:
    case kRiscvI8x16ExtractLaneU:
    case kRiscvI8x16ExtractLaneS:
    case kRiscvI8x16ReplaceLane:
    case kRiscvI8x16Shl:
    case kRiscvI8x16ShrS:
    case kRiscvI8x16ShrU:
    case kRiscvI8x16RoundingAverageU:
    case kRiscvI8x16Popcnt:
    case kRiscvMaxD:
    case kRiscvMaxS:
    case kRiscvMinD:
    case kRiscvMinS:
    case kRiscvMod32:
    case kRiscvModU32:
    case kRiscvMov:
    case kRiscvMul32:
    case kRiscvMulD:
    case kRiscvMulHigh32:
    case kRiscvMulOvf32:
    case kRiscvMulS:
    case kRiscvNegD:
    case kRiscvNegS:
    case kRiscvOr:
    case kRiscvOr32:
    case kRiscvPopcnt32:
    case kRiscvRor32:
    case kRiscvRoundWD:
    case kRiscvRoundWS:
    case kRiscvVnot:
    case kRiscvS128Select:
    case kRiscvS128Const:
    case kRiscvS128Zero:
    case kRiscvS128Load32Zero:
    case kRiscvS128Load64Zero:
    case kRiscvS128AllOnes:
    case kRiscvV128AnyTrue:
    case kRiscvI8x16Shuffle:
    case kRiscvVwmul:
    case kRiscvVwmulu:
    case kRiscvVmv:
    case kRiscvVandVv:
    case kRiscvVorVv:
    case kRiscvVnotVv:
    case kRiscvVxorVv:
    case kRiscvVmvSx:
    case kRiscvVmvXs:
    case kRiscvVfmvVf:
    case kRiscvVcompress:
    case kRiscvVaddVv:
    case kRiscvVwaddVv:
    case kRiscvVwadduVv:
    case kRiscvVwadduWx:
    case kRiscvVsubVv:
    case kRiscvVnegVv:
    case kRiscvVfnegVv:
    case kRiscvVmaxuVv:
    case kRiscvVmax:
    case kRiscvVminsVv:
    case kRiscvVminuVv:
    case kRiscvVmulVv:
    case kRiscvVdivu:
    case kRiscvVsmulVv:
    case kRiscvVmslt:
    case kRiscvVgtsVv:
    case kRiscvVgesVv:
    case kRiscvVgeuVv:
    case kRiscvVgtuVv:
    case kRiscvVeqVv:
    case kRiscvVneVv:
    case kRiscvVAbs:
    case kRiscvVaddSatUVv:
    case kRiscvVaddSatSVv:
    case kRiscvVsubSatUVv:
    case kRiscvVsubSatSVv:
    case kRiscvVrgather:
    case kRiscvVslidedown:
    case kRiscvVredminuVs:
    case kRiscvVAllTrue:
    case kRiscvVnclipu:
    case kRiscvVnclip:
    case kRiscvVsll:
    case kRiscvVfaddVv:
    case kRiscvVfsubVv:
    case kRiscvVfmulVv:
    case kRiscvVfdivVv:
    case kRiscvVfminVv:
    case kRiscvVfmaxVv:
    case kRiscvVmfeqVv:
    case kRiscvVmfneVv:
    case kRiscvVmfltVv:
    case kRiscvVmfleVv:
    case kRiscvVmergeVx:
    case kRiscvVzextVf2:
    case kRiscvVsextVf2:
    case kRiscvSar32:
    case kRiscvSignExtendByte:
    case kRiscvSignExtendShort:
    case kRiscvShl32:
    case kRiscvShr32:
    case kRiscvSqrtD:
    case kRiscvSqrtS:
    case kRiscvSubD:
    case kRiscvSubS:
    case kRiscvTruncUwD:
    case kRiscvTruncUwS:
    case kRiscvTruncWD:
    case kRiscvTruncWS:
    case kRiscvTst32:
    case kRiscvXor:
    case kRiscvXor32:
      return kNoOpcodeFlags;
#if V8_TARGET_ARCH_RISCV64
    case kRiscvTst64:
    case kRiscvLd:
    case kRiscvLwu:
    case kRiscvUlwu:
    case kRiscvWord64AtomicLoadUint64:
    case kRiscvLoadDecompressTaggedSigned:
    case kRiscvLoadDecompressTagged:
    case kRiscvLoadDecodeSandboxedPointer:
    case kRiscvAtomicLoadDecompressTaggedSigned:
    case kRiscvAtomicLoadDecompressTagged:
    case kRiscvAtomicStoreCompressTagged:
    case kRiscvLoadDecompressProtected:
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvWord32AtomicPairLoad:
#endif
    case kRiscvLb:
    case kRiscvLbu:
    case kRiscvLoadDouble:
    case kRiscvLh:
    case kRiscvLhu:
    case kRiscvLw:
    case kRiscvLoadFloat:
    case kRiscvRvvLd:
    case kRiscvPeek:
    case kRiscvUld:
    case kRiscvULoadDouble:
    case kRiscvUlh:
    case kRiscvUlhu:
    case kRiscvUlw:
    case kRiscvULoadFloat:
    case kRiscvS128LoadSplat:
    case kRiscvS128Load64ExtendU:
    case kRiscvS128Load64ExtendS:
    case kRiscvS128LoadLane:
      return kIsLoadOperation;

#if V8_TARGET_ARCH_RISCV64
    case kRiscvSd:
    case kRiscvUsd:
    case kRiscvWord64AtomicStoreWord64:
    case kRiscvWord64AtomicAddUint64:
    case kRiscvWord64AtomicSubUint64:
    case kRiscvWord64AtomicAndUint64:
    case kRiscvWord64AtomicOrUint64:
    case kRiscvWord64AtomicXorUint64:
    case kRiscvWord64AtomicExchangeUint64:
    case kRiscvWord64AtomicCompareExchangeUint64:
    case kRiscvStoreCompressTagged:
    case kRiscvStoreEncodeSandboxedPointer:
    case kRiscvStoreIndirectPointer:
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvWord32AtomicPairStore:
    case kRiscvWord32AtomicPairAdd:
    case kRiscvWord32AtomicPairSub:
    case kRiscvWord32AtomicPairAnd:
    case kRiscvWord32AtomicPairOr:
    case kRiscvWord32AtomicPairXor:
    case kRiscvWord32AtomicPairExchange:
    case kRiscvWord32AtomicPairCompareExchange:
#endif
    case kRiscvModD:
    case kRiscvModS:
    case kRiscvRvvSt:
    case kRiscvPush:
    case kRiscvSb:
    case kRiscvStoreDouble:
    case kRiscvSh:
    case kRiscvStackClaim:
    case kRiscvStoreToStackSlot:
    case kRiscvSw:
    case kRiscvStoreFloat:
    case kRiscvUStoreDouble:
    case kRiscvUsh:
    case kRiscvUsw:
    case kRiscvUStoreFloat:
    case kRiscvSync:
    case kRiscvS128StoreLane:
      return kHasSideEffect;

#define CASE(Name) case k##Name:
      COMMON_ARCH_OPCODE_LIST(CASE)
#undef CASE
      // Already covered in architecture independent code.
      UNREACHABLE();
  }

  UNREACHABLE();
}

enum Latency {
  ADD = 1,

  BRANCH = 4,  // Estimated max.
  RINT_S = 4,  // Estimated.
  RINT_D = 4,  // Estimated.

  // TODO(RISCV): remove MULT instructions (MIPS legacy).
  MUL = 4,
  MULW = 4,
  MULH = 4,
  MULHS = 4,
  MULHU = 4,

  DIVW = 50,  // Min:11 Max:50
  DIV = 50,
  DIVU = 50,
  DIVUW = 50,

  FSGNJ_S = 4,
  FSGNJ_D = 4,
  ABS_S = FSGNJ_S,
  ABS_D = FSGNJ_S,
  NEG_S = FSGNJ_S,
  NEG_D = FSGNJ_S,
  ADD_S = 4,
  ADD_D = 4,
  SUB_S = 4,
  SUB_D = 4,
  MAX_S = 4,  // Estimated.
  MIN_S = 4,
  MAX_D = 4,  // Estimated.
  MIN_D = 4,
  C_cond_S = 4,
  C_cond_D = 4,
  MUL_S = 4,

  MADD_S = 4,
  MSUB_S = 4,
  NMADD_S = 4,
  NMSUB_S = 4,

  CABS_cond_S = 4,
  CABS_cond_D = 4,

  CVT_D_S = 4,
  CVT_PS_PW = 4,

  CVT_S_W = 4,
  CVT_S_L = 4,
  CVT_D_W = 4,
  CVT_D_L = 4,

  CVT_S_D = 4,

  CVT_W_S = 4,
  CVT_W_D = 4,
  CVT_L_S = 4,
  CVT_L_D = 4,

  CEIL_W_S = 4,
  CEIL_W_D = 4,
  CEIL_L_S = 4,
  CEIL_L_D = 4,

  FLOOR_W_S = 4,
  FLOOR_W_D = 4,
  FLOOR_L_S = 4,
  FLOOR_L_D = 4,

  ROUND_W_S = 4,
  ROUND_W_D = 4,
  ROUND_L_S = 4,
  ROUND_L_D = 4,

  TRUNC_W_S = 4,
  TRUNC_W_D = 4,
  TRUNC_L_S = 4,
  TRUNC_L_D = 4,

  MOV_S = 4,
  MOV_D = 4,

  MOVF_S = 4,
  MOVF_D = 4,

  MOVN_S = 4,
  MOVN_D = 4,

  MOVT_S = 4,
  MOVT_D = 4,

  MOVZ_S = 4,
  MOVZ_D = 4,

  MUL_D = 5,
  MADD_D = 5,
  MSUB_D = 5,
  NMADD_D = 5,
  NMSUB_D = 5,

  RECIP_S = 13,
  RECIP_D = 26,

  RSQRT_S = 17,
  RSQRT_D = 36,

  DIV_S = 17,
  SQRT_S = 17,

  DIV_D = 32,
  SQRT_D = 32,

  MOVT_FREG = 4,
  MOVT_HIGH_FREG = 4,
  MOVT_DREG = 4,
  LOAD_FLOAT = 4,
  LOAD_DOUBLE = 4,

  MOVF_FREG = 1,
  MOVF_HIGH_FREG = 1,
  MOVF_HIGH_DREG = 1,
  MOVF_HIGH = 1,
  MOVF_LOW = 1,
  STORE_FLOAT = 1,
  STORE_DOUBLE = 1,
};

inline int LoadConstantLatency() {
  return 1;
  // #if V8_TARGET_ARCH_RISCV32
  //   return 2; //lui+aii Estimated max.
  // #elif V8_TARGET_ARCH_RISCV64
  //   return 4;
  // #endif
}

inline int Add64Latency(bool is_operand_register = true) {
  int latency = Latency::ADD;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Sub64Latency(bool is_operand_register = true) {
  return Add64Latency(is_operand_register);
}

int ShiftLatency(bool is_operand_register = true) {
  return Add64Latency(is_operand_register);
}
int AndLatency(bool is_operand_register = true) {
  return Add64Latency(is_operand_register);
}

int OrLatency(bool is_operand_register = true) {
  return Add64Latency(is_operand_register);
}

int NorLatency(bool is_operand_register = true) {
  if (is_operand_register) {
    return 1;
  } else {
    return 1 + LoadConstantLatency();  // Estimated max.
  }
}

int XorLatency(bool is_operand_register = true) {
  return Add64Latency(is_operand_register);
}

int Mul32Latency(bool is_operand_register = true) {
  if (is_operand_register) {
    return Latency::MULW;
  } else {
    return Latency::MULW + 1;
  }
}

int Mul64Latency(bool is_operand_register = true) {
  int latency = Latency::MUL;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Mulh32Latency(bool is_operand_register = true) {
  int latency = Latency::MULH + ShiftLatency(true);
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Mulhu32Latency(bool is_operand_register = true) {
  int latency = Latency::MULHU + ShiftLatency(true) * 2;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  } else {
    latency += 1;
  }
  return latency;
}

int Mulh64Latency(bool is_operand_register = true) {
  int latency = Latency::MULH;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Div32Latency(bool is_operand_register = true) {
  if (is_operand_register) {
    return Latency::DIVW;
  } else {
    return Latency::DIVW + 1;
  }
}

int Divu32Latency(bool is_operand_register = true) {
  if (is_operand_register) {
    return Latency::DIVUW;
  } else {
    return Latency::DIVUW + LoadConstantLatency();
  }
}

int Div64Latency(bool is_operand_register = true) {
  int latency = Latency::DIV;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Divu64Latency(bool is_operand_register = true) {
  int latency = Latency::DIVU;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Mod32Latency(bool is_operand_register = true) {
  int latency = Latency::DIVW;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Modu32Latency(bool is_operand_register = true) {
  int latency = Latency::DIVUW;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Mod64Latency(bool is_operand_register = true) {
  int latency = Latency::DIV;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int Modu64Latency(bool is_operand_register = true) {
  int latency = Latency::DIV;
  if (!is_operand_register) {
    latency += LoadConstantLatency();
  }
  return latency;
}

int MovzLatency() { return 1; }

int MovnLatency() { return 1; }

int CallLatency() {
  // Estimated.
  return Add64Latency(false) + Latency::BRANCH + 5;
}

int JumpLatency() {
  // Estimated max.
  return 1 + Add64Latency() + Latency::BRANCH + 2;
}

int SmiUntagLatency() { return 1; }

int PrepareForTailCallLatency() {
  // Estimated max.
  return 2 * (Add64Latency() + 1 + Add64Latency(false)) + 2 + Latency::BRANCH +
         Latency::BRANCH + 2 * Sub64Latency(false) + 2 + Latency::BRANCH + 1;
}

int AssemblePopArgumentsAdoptFrameLatency() {
  return 1 + Latency::BRANCH + 1 + SmiUntagLatency() +
         PrepareForTailCallLatency();
}

int AssertLatency() { return 1; }

int PrepareCallCFunctionLatency() {
  int frame_alignment = MacroAssembler::ActivationFrameAlignment();
  if (frame_alignment > kSystemPointerSize) {
    return 1 + Sub64Latency(false) + AndLatency(false) + 1;
  } else {
    return Sub64Latency(false);
  }
}

int AdjustBaseAndOffsetLatency() {
  return 3;  // Estimated max.
}

int AlignedMemoryLatency() { return AdjustBaseAndOffsetLatency() + 1; }

int UlhuLatency() {
  return AdjustBaseAndOffsetLatency() + 2 * AlignedMemoryLatency() + 2;
}

int UlwLatency() {
  // Estimated max.
  return AdjustBaseAndOffsetLatency() + 3;
}

int UlwuLatency() { return UlwLatency() + 1; }

int UldLatency() {
  // Estimated max.
  return AdjustBaseAndOffsetLatency() + 3;
}

int ULoadFloatLatency() { return UlwLatency() + Latency::MOVT_FREG; }

int ULoadDoubleLatency() { return UldLatency() + Latency::MOVT_DREG; }

int UshLatency() {
  // Estimated max.
  return AdjustBaseAndOffsetLatency() + 2 + 2 * AlignedMemoryLatency();
}

int UswLatency() { return AdjustBaseAndOffsetLatency() + 2; }

int UsdLatency() { return AdjustBaseAndOffsetLatency() + 2; }

int UStoreFloatLatency() { return Latency::MOVF_FREG + UswLatency(); }

int UStoreDoubleLatency() { return Latency::MOVF_HIGH_DREG + UsdLatency(); }

int LoadFloatLatency() {
  return AdjustBaseAndOffsetLatency() + Latency::LOAD_FLOAT;
}

int StoreFloatLatency() {
  return AdjustBaseAndOffsetLatency() + Latency::STORE_FLOAT;
}

int StoreDoubleLatency() {
  return AdjustBaseAndOffsetLatency() + Latency::STORE_DOUBLE;
}

int LoadDoubleLatency() {
  return AdjustBaseAndOffsetLatency() + Latency::LOAD_DOUBLE;
}

int MultiPushLatency() {
  int latency = Sub64Latency(false);
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    latency++;
  }
  return latency;
}

int MultiPushFPULatency() {
  int latency = Sub64Latency(false);
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    latency += StoreDoubleLatency();
  }
  return latency;
}

int PushCallerSavedLatency(SaveFPRegsMode fp_mode) {
  int latency = MultiPushLatency();
  if (fp_mode == SaveFPRegsMode::kSave) {
    latency += MultiPushFPULatency();
  }
  return latency;
}

int MultiPopLatency() {
  int latency = Add64Latency(false);
  for (int16_t i = 0; i < kNumRegisters; i++) {
    latency++;
  }
  return latency;
}

int MultiPopFPULatency() {
  int latency = Add64Latency(false);
  for (int16_t i = 0; i < kNumRegisters; i++) {
    latency += LoadDoubleLatency();
  }
  return latency;
}

int PopCallerSavedLatency(SaveFPRegsMode fp_mode) {
  int latency = MultiPopLatency();
  if (fp_mode == SaveFPRegsMode::kSave) {
    latency += MultiPopFPULatency();
  }
  return latency;
}

int CallCFunctionHelperLatency() {
  // Estimated.
  int latency = AndLatency(false) + Latency::BRANCH + 2 + CallLatency();
  if (base::OS::ActivationFrameAlignment() > kSystemPointerSize) {
    latency++;
  } else {
    latency += Add64Latency(false);
  }
  return latency;
}

int CallCFunctionLatency() { return 1 + CallCFunctionHelperLatency(); }

int AssembleArchJumpLatency() {
  // Estimated max.
  return Latency::BRANCH;
}

int GenerateSwitchTableLatency() {
  int latency = 6;
  latency += 2;
  return latency;
}

int AssembleArchTableSwitchLatency() {
  return Latency::BRANCH + GenerateSwitchTableLatency();
}

int DropAndRetLatency() {
  // Estimated max.
  return Add64Latency(false) + JumpLatency();
}

int AssemblerReturnLatency() {
  // Estimated max.
  return Add64Latency(false) + MultiPopLatency() + MultiPopFPULatency() +
         Latency::BRANCH + Add64Latency() + 1 + DropAndRetLatency();
}

int TryInlineTruncateDoubleToILatency() {
  return 2 + Latency::TRUNC_W_D + Latency::MOVF_FREG + 2 + AndLatency(false) +
         Latency::BRANCH;
}

int CallStubDelayedLatency() { return 1 + CallLatency(); }

int TruncateDoubleToIDelayedLatency() {
  // TODO(riscv): This no longer reflects how TruncateDoubleToI is called.
  return TryInlineTruncateDoubleToILatency() + 1 + Sub64Latency(false) +
         StoreDoubleLatency() + CallStubDelayedLatency() + Add64Latency(false) +
         1;
}

int CheckPageFlagLatency() {
  return AndLatency(false) + AlignedMemoryLatency() + AndLatency(false) +
         Latency::BRANCH;
}

int SltuLatency(bool is_operand_register = true) {
  if (is_operand_register) {
    return 1;
  } else {
    return 2;  // Estimated max.
  }
}

int BranchShortHelperLatency() {
  return SltuLatency() + 2;  // Estimated max.
}

int BranchShortLatency() { return BranchShortHelperLatency(); }

int MoveLatency() { return 1; }

int MovToFloatParametersLatency() { return 2 * MoveLatency(); }

int MovFromFloatResultLatency() { return MoveLatency(); }

int AddOverflow64Latency() {
  // Estimated max.
  return 6;
}

int SubOverflow64Latency() {
  // Estimated max.
  return 6;
}

int MulOverflow32Latency() {
  // Estimated max.
  return Mul32Latency() + Mulh32Latency() + 2;
}

int MulOverflow64Latency() {
  // Estimated max.
  return Mul64Latency() + Mulh64Latency() + 2;
}

// TODO(RISCV): This is incorrect for RISC-V.
int Clz64Latency() { return 1; }

int Ctz32Latency() {
  return Add64Latency(false) + XorLatency() + AndLatency() + Clz64Latency() +
         1 + Sub64Latency();
}

int Ctz64Latency() {
  return Add64Latency(false) + XorLatency() + AndLatency() + 1 + Sub64Latency();
}

int Popcnt32Latency() {
  return 2 + AndLatency() + Sub64Latency() + 1 + AndLatency() + 1 +
         AndLatency() + Add64Latency() + 1 + Add64Latency() + 1 + AndLatency() +
         1 + Mul32Latency() + 1;
}

#if V8_TARGET_ARCH_RISCV64
int Popcnt64Latency() {
  return 2 + AndLatency() + Sub64Latency() + 1 + AndLatency() + 1 +
         AndLatency() + Add64Latency() + 1 + Add64Latency() + 1 + AndLatency() +
         1 + Mul64Latency() + 1;
}
#endif
int CompareFLatency() { return Latency::C_cond_S; }

int CompareF32Latency() { return CompareFLatency(); }

int CompareF64Latency() { return CompareFLatency(); }

int CompareIsNanFLatency() { return CompareFLatency(); }

int CompareIsNanF32Latency() { return CompareIsNanFLatency(); }

int CompareIsNanF64Latency() { return CompareIsNanFLatency(); }

int NegsLatency() {
  // Estimated.
  return CompareIsNanF32Latency() + 2 * Latency::BRANCH + Latency::NEG_S +
         Latency::MOVF_FREG + 1 + XorLatency() + Latency::MOVT_FREG;
}

int NegdLatency() {
  // Estimated.
  return CompareIsNanF64Latency() + 2 * Latency::BRANCH + Latency::NEG_D +
         Latency::MOVF_HIGH_DREG + 1 + XorLatency() + Latency::MOVT_DREG;
}

#if V8_TARGET_ARCH_RISCV64
int Float64RoundLatency() {
  // For ceil_l_d, floor_l_d, round_l_d, trunc_l_d latency is 4.
  return Latency::MOVF_HIGH_DREG + 1 + Latency::BRANCH + Latency::MOV_D + 4 +
         Latency::MOVF_HIGH_DREG + Latency::BRANCH + Latency::CVT_D_L + 2 +
         Latency::MOVT_HIGH_FREG;
}
#endif
int Float32RoundLatency() {
  // For ceil_w_s, floor_w_s, round_w_s, trunc_w_s latency is 4.
  return Latency::MOVF_FREG + 1 + Latency::BRANCH + Latency::MOV_S + 4 +
         Latency::MOVF_FREG + Latency::BRANCH + Latency::CVT_S_W + 2 +
         Latency::MOVT_FREG;
}

int Float32MaxLatency() {
  // Estimated max.
  int latency = CompareIsNanF32Latency() + Latency::BRANCH;
  return latency + 5 * Latency::BRANCH + 2 * CompareF32Latency() +
         Latency::MOVF_FREG + 1 + Latency::MOV_S;
}

int Float64MaxLatency() {
  // Estimated max.
  int latency = CompareIsNanF64Latency() + Latency::BRANCH;
  return latency + 5 * Latency::BRANCH + 2 * CompareF64Latency() +
         Latency::MOVF_HIGH_DREG + Latency::MOV_D;
}

int Float32MinLatency() {
  // Estimated max.
  int latency = CompareIsNanF32Latency() + Latency::BRANCH;
  return latency + 5 * Latency::BRANCH + 2 * CompareF32Latency() +
         Latency::MOVF_FREG + 1 + Latency::MOV_S;
}

int Float64MinLatency() {
  // Estimated max.
  int latency = CompareIsNanF64Latency() + Latency::BRANCH;
  return latency + 5 * Latency::BRANCH + 2 * CompareF32Latency() +
         Latency::MOVF_HIGH_DREG + Latency::MOV_D;
}

int TruncLSLatency(bool load_status) {
  int latency = Latency::TRUNC_L_S + Latency::MOVF_HIGH_DREG;
  if (load_status) {
    latency += SltuLatency() + 7;
  }
  return latency;
}

int TruncLDLatency(bool load_status) {
  int latency = Latency::TRUNC_L_D + Latency::MOVF_HIGH_DREG;
  if (load_status) {
    latency += SltuLatency() + 7;
  }
  return latency;
}

int TruncUlSLatency() {
  // Estimated max.
  return 2 * CompareF32Latency() + CompareIsNanF32Latency() +
         4 * Latency::BRANCH + Latency::SUB_S + 2 * Latency::TRUNC_L_S +
         3 * Latency::MOVF_HIGH_DREG + OrLatency() + Latency::MOVT_FREG +
         Latency::MOV_S + SltuLatency() + 4;
}

int TruncUlDLatency() {
  // Estimated max.
  return 2 * CompareF64Latency() + CompareIsNanF64Latency() +
         4 * Latency::BRANCH + Latency::SUB_D + 2 * Latency::TRUNC_L_D +
         3 * Latency::MOVF_HIGH_DREG + OrLatency() + Latency::MOVT_DREG +
         Latency::MOV_D + SltuLatency() + 4;
}

int PushLatency() { return Add64Latency() + AlignedMemoryLatency(); }

int ByteSwapSignedLatency() { return 2; }

int LlLatency(int offset) {
  bool is_one_instruction = is_int12(offset);
  if (is_one_instruction) {
    return 1;
  } else {
    return 3;
  }
}

int ExtractBitsLatency(bool sign_extend, int size) {
  int latency = 2;
  if (sign_extend) {
    switch (size) {
      case 8:
      case 16:
      case 32:
        latency += 1;
        break;
      default:
        UNREACHABLE();
    }
  }
  return latency;
}

int InsertBitsLatency() { return 2 + Sub64Latency(false) + 2; }

int ScLatency(int offset) { return 3; }

int Word32AtomicExchangeLatency(bool sign_extend, int size) {
  return Add64Latency(false) + 1 + Sub64Latency() + 2 + LlLatency(0) +
         ExtractBitsLatency(sign_extend, size) + InsertBitsLatency() +
         ScLatency(0) + BranchShortLatency() + 1;
}

int Word32AtomicCompareExchangeLatency(bool sign_extend, int size) {
  return 2 + Sub64Latency() + 2 + LlLatency(0) +
         ExtractBitsLatency(sign_extend, size) + InsertBitsLatency() +
         ScLatency(0) + BranchShortLatency() + 1;
}

int InstructionScheduler::GetInstructionLatency(const Instruction* instr) {
  // TODO(RISCV): Verify these latencies for RISC-V (currently using MIPS
  // numbers).
  switch (instr->arch_opcode()) {
    case kArchCallCodeObject:
    case kArchCallWasmFunction:
      return CallLatency();
    case kArchTailCallCodeObject:
    case kArchTailCallWasm:
    case kArchTailCallAddress:
      return JumpLatency();
    case kArchCallJSFunction: {
      int latency = 0;
      if (v8_flags.debug_code) {
        latency = 1 + AssertLatency();
      }
      return latency + 1 + Add64Latency(false) + CallLatency();
    }
    case kArchPrepareCallCFunction:
      return PrepareCallCFunctionLatency();
    case kArchSaveCallerRegisters: {
      auto fp_mode =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      return PushCallerSavedLatency(fp_mode);
    }
    case kArchRestoreCallerRegisters: {
      auto fp_mode =
          static_cast<SaveFPRegsMode>(MiscField::decode(instr->opcode()));
      return PopCallerSavedLatency(fp_mode);
    }
    case kArchPrepareTailCall:
      return 2;
    case kArchCallCFunction:
      return CallCFunctionLatency();
    case kArchJmp:
      return AssembleArchJumpLatency();
    case kArchTableSwitch:
      return AssembleArchTableSwitchLatency();
    case kArchAbortCSADcheck:
      return CallLatency() + 1;
    case kArchDebugBreak:
      return 1;
    case kArchComment:
    case kArchNop:
    case kArchThrowTerminator:
    case kArchDeoptimize:
      return 0;
    case kArchRet:
      return AssemblerReturnLatency();
    case kArchFramePointer:
      return 1;
    case kArchParentFramePointer:
      // Estimated max.
      return AlignedMemoryLatency();
    case kArchTruncateDoubleToI:
      return TruncateDoubleToIDelayedLatency();
    case kArchStoreWithWriteBarrier:
      return Add64Latency() + 1 + CheckPageFlagLatency();
    case kArchStackSlot:
      // Estimated max.
      return Add64Latency(false) + AndLatency(false) + AssertLatency() +
             Add64Latency(false) + AndLatency(false) + BranchShortLatency() +
             1 + Sub64Latency() + Add64Latency();
    case kIeee754Float64Acos:
    case kIeee754Float64Acosh:
    case kIeee754Float64Asin:
    case kIeee754Float64Asinh:
    case kIeee754Float64Atan:
    case kIeee754Float64Atanh:
    case kIeee754Float64Atan2:
    case kIeee754Float64Cos:
    case kIeee754Float64Cosh:
    case kIeee754Float64Cbrt:
    case kIeee754Float64Exp:
    case kIeee754Float64Expm1:
    case kIeee754Float64Log:
    case kIeee754Float64Log1p:
    case kIeee754Float64Log10:
    case kIeee754Float64Log2:
    case kIeee754Float64Pow:
    case kIeee754Float64Sin:
    case kIeee754Float64Sinh:
    case kIeee754Float64Tan:
    case kIeee754Float64Tanh:
      return PrepareCallCFunctionLatency() + MovToFloatParametersLatency() +
             CallCFunctionLatency() + MovFromFloatResultLatency();
#if V8_TARGET_ARCH_RISCV64
    case kRiscvAdd32:
    case kRiscvAdd64:
      return Add64Latency(instr->InputAt(1)->IsRegister());
    case kRiscvAddOvf64:
      return AddOverflow64Latency();
    case kRiscvSub32:
    case kRiscvSub64:
      return Sub64Latency(instr->InputAt(1)->IsRegister());
    case kRiscvSubOvf64:
      return SubOverflow64Latency();
    case kRiscvMulHigh64:
      return Mulh64Latency();
    case kRiscvMul64:
      return Mul64Latency();
    case kRiscvMulOvf64:
      return MulOverflow64Latency();
    case kRiscvDiv64: {
      int latency = Div64Latency();
      return latency + MovzLatency();
    }
    case kRiscvDivU64: {
      int latency = Divu64Latency();
      return latency + MovzLatency();
    }
    case kRiscvMod64:
      return Mod64Latency();
    case kRiscvModU64:
      return Modu64Latency();
#elif V8_TARGET_ARCH_RISCV32
    case kRiscvAdd32:
      return Add64Latency(instr->InputAt(1)->IsRegister());
    case kRiscvAddOvf:
      return AddOverflow64Latency();
    case kRiscvSub32:
      return Sub64Latency(instr->InputAt(1)->IsRegister());
    case kRiscvSubOvf:
      return SubOverflow64Latency();
#endif
    case kRiscvMul32:
      return Mul32Latency();
    case kRiscvMulOvf32:
      return MulOverflow32Latency();
    case kRiscvMulHigh32:
      return Mulh32Latency();
    case kRiscvMulHighU32:
      return Mulhu32Latency();
    case kRiscvDiv32: {
      int latency = Div32Latency(instr->InputAt(1)->IsRegister());
      return latency + MovzLatency();
    }
    case kRiscvDivU32: {
      int latency = Divu32Latency(instr->InputAt(1)->IsRegister());
      return latency + MovzLatency();
    }
    case kRiscvMod32:
      return Mod32Latency();
    case kRiscvModU32:
      return Modu32Latency();
    case kRiscvAnd:
      return AndLatency(instr->InputAt(1)->IsRegister());
    case kRiscvAnd32: {
      bool is_operand_register = instr->InputAt(1)->IsRegister();
      int latency = AndLatency(is_operand_register);
      if (is_operand_register) {
        return latency + 2;
      } else {
        return latency + 1;
      }
    }
    case kRiscvOr:
      return OrLatency(instr->InputAt(1)->IsRegister());
    case kRiscvOr32: {
      bool is_operand_register = instr->InputAt(1)->IsRegister();
      int latency = OrLatency(is_operand_register);
      if (is_operand_register) {
        return latency + 2;
      } else {
        return latency + 1;
      }
    }
    case kRiscvXor:
      return XorLatency(instr->InputAt(1)->IsRegister());
    case kRiscvXor32: {
      bool is_operand_register = instr->InputAt(1)->IsRegister();
      int latency = XorLatency(is_operand_register);
      if (is_operand_register) {
        return latency + 2;
      } else {
        return latency + 1;
      }
    }
    case kRiscvClz32:
#if V8_TARGET_ARCH_RISCV64
    case kRiscvClz64:
#endif
      return Clz64Latency();
#if V8_TARGET_ARCH_RISCV64
    case kRiscvCtz64:
      return Ctz64Latency();
    case kRiscvPopcnt64:
      return Popcnt64Latency();
#endif
    case kRiscvCtz32:
      return Ctz32Latency();
    case kRiscvPopcnt32:
      return Popcnt32Latency();
    case kRiscvShl32:
      return 1;
    case kRiscvShr32:
    case kRiscvSar32:
#if V8_TARGET_ARCH_RISCV64
    case kRis
"""


```