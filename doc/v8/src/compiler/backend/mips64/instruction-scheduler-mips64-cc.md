Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Initial Understanding:** The first thing to recognize is that this is a C++ source file for V8, specifically within the MIPS64 architecture's compiler backend. The name "instruction-scheduler-mips64.cc" strongly suggests its primary function is related to scheduling instructions.

2. **Scanning for Keywords:**  A quick scan for relevant keywords confirms this suspicion. "InstructionScheduler", "SchedulerSupported", "GetTargetInstructionFlags", and "GetInstructionLatency" are key indicators.

3. **High-Level Purpose:** Based on the filename and keywords, the code's overall goal is to provide the instruction scheduling logic specific to the MIPS64 architecture within the V8 compiler.

4. **`SchedulerSupported()`:**  This simple function immediately tells us that instruction scheduling *is* supported for MIPS64. This is a configuration flag.

5. **`GetTargetInstructionFlags()`:** This function is more complex.
    * **Purpose:**  It examines an `Instruction` object and returns flags related to its characteristics.
    * **Mechanism:** A large `switch` statement based on `instr->arch_opcode()`. This means it handles different MIPS64 instructions individually.
    * **Flags:** The function returns either `kNoOpcodeFlags`, `kIsLoadOperation`, or `kHasSideEffect`. This indicates the types of information the scheduler uses about each instruction.
    * **Implication:** The scheduler needs to know if an instruction is a load (for potential data dependencies) or has side effects (which might restrict reordering).

6. **`GetInstructionLatency()`:** This function is also a large `switch` statement.
    * **Purpose:**  It determines the latency (execution time) of a given MIPS64 instruction.
    * **Mechanism:** Another `switch` statement on `instr->arch_opcode()`.
    * **Latency Values:**  The code defines an `enum Latency` and several helper functions (like `DadduLatency`, `DmulLatency`, etc.) to calculate or provide latency values.
    * **Factors Affecting Latency:** Notice that some latencies depend on whether an operand is a register or an immediate value. This shows the scheduler takes micro-architectural details into account.
    * **Implication:** The scheduler uses latency information to optimize instruction order for better performance by avoiding stalls. Instructions with longer latencies are likely scheduled earlier.

7. **`.tq` Check:** The prompt explicitly asks about the `.tq` extension. The code is `.cc`, so it's *not* a Torque file. Torque is a different language used within V8 for generating code.

8. **JavaScript Relationship:**  Since this code is part of V8's compiler, it *directly* impacts how JavaScript code is compiled and executed. The instruction scheduler tries to arrange the low-level MIPS64 instructions generated from JavaScript for optimal performance.

9. **Code Logic Inference and Examples:** The `switch` statements themselves are the core logic. We can infer:
    * **Input:** An `Instruction` object representing a MIPS64 instruction.
    * **Output of `GetTargetInstructionFlags`:**  One of the flags (`kNoOpcodeFlags`, `kIsLoadOperation`, `kHasSideEffect`).
    * **Output of `GetInstructionLatency`:** An integer representing the instruction's latency in some unit (likely CPU cycles).

    To make this concrete, pick a few instructions:
    * `kMips64Add`:  `GetTargetInstructionFlags` returns `kNoOpcodeFlags`. `GetInstructionLatency` calls `DadduLatency`.
    * `kMips64Lb`: `GetTargetInstructionFlags` returns `kIsLoadOperation`. `GetInstructionLatency` likely calls `AlignedMemoryLatency`.
    * `kMips64Sd`: `GetTargetInstructionFlags` returns `kHasSideEffect`. `GetInstructionLatency` likely calls `AdjustBaseAndOffsetLatency` and `Latency::SDC1`.

10. **Common Programming Errors (Relating to Scheduling):** While this code doesn't *directly* cause user programming errors, understanding its purpose helps explain *why* certain optimizations are important. For instance, if a user writes code with many data dependencies (one instruction relying on the result of the previous), the scheduler will have less freedom to reorder and optimize, potentially leading to slower execution. Another example is computationally intensive code; the scheduler will try to overlap the execution of independent instructions to maximize throughput.

11. **Summarization (Part 1):**  The key is to consolidate the findings into a concise summary, focusing on the main functionalities revealed by the code. Emphasize the role of the instruction scheduler in optimizing MIPS64 code generation within V8.

By following this structured approach, analyzing the code snippet becomes more systematic and leads to a comprehensive understanding of its function and purpose. The process involves identifying key components, understanding their individual roles, and then synthesizing this information to grasp the bigger picture.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
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
    case kMips64AbsD:
    case kMips64AbsS:
    case kMips64Add:
    // ... (many more cases)
    case kMips64Xor32:
      return kNoOpcodeFlags;

    case kMips64Lb:
    case kMips64Lbu:
    // ... (many more load cases)
    case kMips64Word64AtomicLoadUint64:
      return kIsLoadOperation;

    case kMips64ModD:
    case kMips64MsaSt:
    // ... (many more side-effect cases)
    case kMips64Word64AtomicCompareExchangeUint64:
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
  BRANCH = 4,  // Estimated max.
  RINT_S = 4,  // Estimated.
  RINT_D = 4,  // Estimated.

  MULT = 4,
  MULTU = 4,
  DMULT = 4,
  DMULTU = 4,

  MUL = 7,
  DMUL = 7,
  MUH = 7,
  MUHU = 7,
  DMUH = 7,
  DMUHU = 7,

  DIV = 50,  // Min:11 Max:50
  DDIV = 50,
  DIVU = 50,
  DDIVU = 50,

  // ... (many more latency definitions)
};

int DadduLatency(bool is_operand_register = true) {
  if (is_operand_register) {
    return 1;
  } else {
    return 2;  // Estimated max.
  }
}

// ... (many more latency calculation functions)

int InstructionScheduler::GetInstructionLatency(const Instruction* instr) {
  // Basic latency modeling for MIPS64 instructions. They have been determined
  // in empirical way.
  switch (instr->arch_opcode()) {
    case kArchCallCodeObject:
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction:
#endif  // V8_ENABLE_WEBASSEMBLY
      return CallLatency();
    case kArchTailCallCodeObject:
#if V8_ENABLE_WEBASSEMBLY
    case kArchTailCallWasm:
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallAddress:
      return JumpLatency();
    case kArchCallJSFunction: {
      int latency = 0;
      if (v8_flags.debug_code) {
        latency = 1 + AssertLatency();
      }
      return latency + 1 + DadduLatency(false) + CallLatency();
    }
    // ... (many more instruction latency cases)
    case kMips64Add:
    case kMips64Dadd:
      return DadduLatency(instr->InputAt(1)->IsRegister());
    // ... (even more cases)
  }
  UNREACHABLE();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```

## 功能归纳 (第 1 部分)

这个 C++ 源代码文件 `instruction-scheduler-mips64.cc` 的主要功能是为 V8 JavaScript 引擎的 **MIPS64 架构**实现 **指令调度器 (Instruction Scheduler)** 的一部分。  更具体地说，它提供了以下关键功能：

1. **声明 MIPS64 架构支持指令调度:**  `InstructionScheduler::SchedulerSupported()` 函数返回 `true`，表明 V8 针对 MIPS64 架构启用了指令调度优化。

2. **定义 MIPS64 指令的特性标志:** `InstructionScheduler::GetTargetInstructionFlags()` 函数根据给定的 MIPS64 指令的 `arch_opcode()` 返回指令的特性标志。这些标志包括：
   - `kNoOpcodeFlags`:  表示该指令没有特殊的调度影响。
   - `kIsLoadOperation`: 表示该指令是从内存中加载数据的操作。
   - `kHasSideEffect`: 表示该指令会产生副作用，例如修改内存或 CPU 状态。

3. **定义 MIPS64 指令的延迟:** 通过 `enum Latency` 定义了各种 MIPS64 指令的基本延迟值（执行所需的时间，通常以 CPU 周期为单位）。  同时，提供了一系列辅助函数（例如 `DadduLatency`, `DmulLatency` 等）来更精确地计算不同指令的延迟，这些计算可能考虑到操作数类型（寄存器或立即数）和具体的处理器变体。

4. **计算 MIPS64 指令的延迟:** `InstructionScheduler::GetInstructionLatency()` 函数根据给定的 `Instruction` 对象的 `arch_opcode()` 返回该指令的估计延迟。这个函数使用 `Latency` 枚举和辅助函数来确定不同 MIPS64 指令的延迟值。

**总结来说，这个文件的核心功能是提供 MIPS64 架构下指令调度器所需的基础信息：哪些指令是加载操作，哪些指令有副作用，以及每条指令大概需要执行多长时间。**  这些信息是指令调度器进行指令重排优化的关键依据，旨在提高生成的机器码的执行效率。

**关于其他问题：**

* **`.tq` 结尾:**  文件 `instruction-scheduler-mips64.cc` 的确是以 `.cc` 结尾，这意味着它是 **C++ 源代码文件**，而不是 Torque 源代码文件。如果以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

* **与 JavaScript 的关系:**  这个文件直接影响 JavaScript 代码的执行效率。当 V8 编译 JavaScript 代码时，它会将 JavaScript 代码转换为底层的机器码（对于 MIPS64 架构来说就是 MIPS64 指令）。指令调度器在这个过程中会分析生成的指令序列，并尝试重新排列指令的执行顺序，以便更好地利用 CPU 的流水线和减少指令之间的依赖关系，从而提升 JavaScript 代码的执行速度。

* **JavaScript 举例:** 考虑以下简单的 JavaScript 代码：

   ```javascript
   function add(a, b) {
     const x = a + 1;
     const y = b + 2;
     return x + y;
   }
   ```

   在编译成 MIPS64 指令后，指令调度器可能会注意到 `a + 1` 和 `b + 2` 的计算是相互独立的。因此，即使在源代码中 `x` 的计算在前，调度器也可能将 `b + 2` 的计算指令提前执行，因为它不依赖于 `a + 1` 的结果，从而实现指令级的并行。

* **代码逻辑推理:**
   - **假设输入:** 一个 `Instruction` 对象，其 `arch_opcode()` 为 `kMips64Add`，并且第二个输入操作数是一个寄存器。
   - **输出:** `InstructionScheduler::GetTargetInstructionFlags()` 将返回 `kNoOpcodeFlags`。 `InstructionScheduler::GetInstructionLatency()` 将调用 `DadduLatency(true)` 并返回 `1`。

   - **假设输入:** 一个 `Instruction` 对象，其 `arch_opcode()` 为 `kMips64Lb`。
   - **输出:** `InstructionScheduler::GetTargetInstructionFlags()` 将返回 `kIsLoadOperation`。  `InstructionScheduler::GetInstructionLatency()` 的具体返回值需要查看 `AlignedMemoryLatency()` 函数的实现，但它会返回一个表示加载操作延迟的整数。

* **用户常见的编程错误:** 这个文件本身是 V8 引擎的内部实现，用户编写 JavaScript 代码的错误不会直接体现在这个文件的逻辑中。然而，理解指令调度的概念可以帮助理解一些性能优化的思路。例如，如果用户编写了大量存在数据依赖的代码，指令调度器可能无法进行有效的优化。例如：

   ```javascript
   let a = 1;
   let b = a + 2;
   let c = b * 3;
   let d = c - 4;
   ```

   在这个例子中，每一行代码都依赖于前一行的结果，指令调度器能做的优化就会相对有限。

这部分代码是 V8 引擎性能优化的重要组成部分，它为 MIPS64 架构的指令调度提供了必要的指令信息和延迟模型。

### 提示词
```
这是目录为v8/src/compiler/backend/mips64/instruction-scheduler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/instruction-scheduler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
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
    case kMips64AbsD:
    case kMips64AbsS:
    case kMips64Add:
    case kMips64AddD:
    case kMips64AddS:
    case kMips64And:
    case kMips64And32:
    case kMips64AssertEqual:
    case kMips64BitcastDL:
    case kMips64BitcastLD:
    case kMips64ByteSwap32:
    case kMips64ByteSwap64:
    case kMips64CeilWD:
    case kMips64CeilWS:
    case kMips64Clz:
    case kMips64Cmp:
    case kMips64CmpD:
    case kMips64CmpS:
    case kMips64Ctz:
    case kMips64CvtDL:
    case kMips64CvtDS:
    case kMips64CvtDUl:
    case kMips64CvtDUw:
    case kMips64CvtDW:
    case kMips64CvtSD:
    case kMips64CvtSL:
    case kMips64CvtSUl:
    case kMips64CvtSUw:
    case kMips64CvtSW:
    case kMips64DMulHigh:
    case kMips64DMulHighU:
    case kMips64DMulOvf:
    case kMips64MulHighU:
    case kMips64Dadd:
    case kMips64DaddOvf:
    case kMips64Dclz:
    case kMips64Dctz:
    case kMips64Ddiv:
    case kMips64DdivU:
    case kMips64Dext:
    case kMips64Dins:
    case kMips64Div:
    case kMips64DivD:
    case kMips64DivS:
    case kMips64DivU:
    case kMips64Dlsa:
    case kMips64Dmod:
    case kMips64DmodU:
    case kMips64Dmul:
    case kMips64Dpopcnt:
    case kMips64Dror:
    case kMips64Dsar:
    case kMips64Dshl:
    case kMips64Dshr:
    case kMips64Dsub:
    case kMips64DsubOvf:
    case kMips64Ext:
    case kMips64F64x2Abs:
    case kMips64F64x2Neg:
    case kMips64F64x2Sqrt:
    case kMips64F64x2Add:
    case kMips64F64x2Sub:
    case kMips64F64x2Mul:
    case kMips64F64x2Div:
    case kMips64F64x2Min:
    case kMips64F64x2Max:
    case kMips64F64x2Eq:
    case kMips64F64x2Ne:
    case kMips64F64x2Lt:
    case kMips64F64x2Le:
    case kMips64F64x2Pmin:
    case kMips64F64x2Pmax:
    case kMips64F64x2Ceil:
    case kMips64F64x2Floor:
    case kMips64F64x2Trunc:
    case kMips64F64x2NearestInt:
    case kMips64F64x2ConvertLowI32x4S:
    case kMips64F64x2ConvertLowI32x4U:
    case kMips64F64x2PromoteLowF32x4:
    case kMips64I64x2Splat:
    case kMips64I64x2ExtractLane:
    case kMips64I64x2ReplaceLane:
    case kMips64I64x2Add:
    case kMips64I64x2Sub:
    case kMips64I64x2Mul:
    case kMips64I64x2Neg:
    case kMips64I64x2Shl:
    case kMips64I64x2ShrS:
    case kMips64I64x2ShrU:
    case kMips64I64x2BitMask:
    case kMips64I64x2Eq:
    case kMips64I64x2Ne:
    case kMips64I64x2GtS:
    case kMips64I64x2GeS:
    case kMips64I64x2Abs:
    case kMips64I64x2SConvertI32x4Low:
    case kMips64I64x2SConvertI32x4High:
    case kMips64I64x2UConvertI32x4Low:
    case kMips64I64x2UConvertI32x4High:
    case kMips64ExtMulLow:
    case kMips64ExtMulHigh:
    case kMips64ExtAddPairwise:
    case kMips64F32x4Abs:
    case kMips64F32x4Add:
    case kMips64F32x4Eq:
    case kMips64F32x4ExtractLane:
    case kMips64F32x4Lt:
    case kMips64F32x4Le:
    case kMips64F32x4Max:
    case kMips64F32x4Min:
    case kMips64F32x4Mul:
    case kMips64F32x4Div:
    case kMips64F32x4Ne:
    case kMips64F32x4Neg:
    case kMips64F32x4Sqrt:
    case kMips64F32x4ReplaceLane:
    case kMips64F32x4SConvertI32x4:
    case kMips64F32x4Splat:
    case kMips64F32x4Sub:
    case kMips64F32x4UConvertI32x4:
    case kMips64F32x4Pmin:
    case kMips64F32x4Pmax:
    case kMips64F32x4Ceil:
    case kMips64F32x4Floor:
    case kMips64F32x4Trunc:
    case kMips64F32x4NearestInt:
    case kMips64F32x4DemoteF64x2Zero:
    case kMips64F64x2Splat:
    case kMips64F64x2ExtractLane:
    case kMips64F64x2ReplaceLane:
    case kMips64Float32Max:
    case kMips64Float32Min:
    case kMips64Float32RoundDown:
    case kMips64Float32RoundTiesEven:
    case kMips64Float32RoundTruncate:
    case kMips64Float32RoundUp:
    case kMips64Float64ExtractLowWord32:
    case kMips64Float64ExtractHighWord32:
    case kMips64Float64FromWord32Pair:
    case kMips64Float64InsertLowWord32:
    case kMips64Float64InsertHighWord32:
    case kMips64Float64Max:
    case kMips64Float64Min:
    case kMips64Float64RoundDown:
    case kMips64Float64RoundTiesEven:
    case kMips64Float64RoundTruncate:
    case kMips64Float64RoundUp:
    case kMips64Float64SilenceNaN:
    case kMips64FloorWD:
    case kMips64FloorWS:
    case kMips64I16x8Add:
    case kMips64I16x8AddSatS:
    case kMips64I16x8AddSatU:
    case kMips64I16x8Eq:
    case kMips64I16x8ExtractLaneU:
    case kMips64I16x8ExtractLaneS:
    case kMips64I16x8GeS:
    case kMips64I16x8GeU:
    case kMips64I16x8GtS:
    case kMips64I16x8GtU:
    case kMips64I16x8MaxS:
    case kMips64I16x8MaxU:
    case kMips64I16x8MinS:
    case kMips64I16x8MinU:
    case kMips64I16x8Mul:
    case kMips64I16x8Ne:
    case kMips64I16x8Neg:
    case kMips64I16x8ReplaceLane:
    case kMips64I8x16SConvertI16x8:
    case kMips64I16x8SConvertI32x4:
    case kMips64I16x8SConvertI8x16High:
    case kMips64I16x8SConvertI8x16Low:
    case kMips64I16x8Shl:
    case kMips64I16x8ShrS:
    case kMips64I16x8ShrU:
    case kMips64I16x8Splat:
    case kMips64I16x8Sub:
    case kMips64I16x8SubSatS:
    case kMips64I16x8SubSatU:
    case kMips64I8x16UConvertI16x8:
    case kMips64I16x8UConvertI32x4:
    case kMips64I16x8UConvertI8x16High:
    case kMips64I16x8UConvertI8x16Low:
    case kMips64I16x8RoundingAverageU:
    case kMips64I16x8Abs:
    case kMips64I16x8BitMask:
    case kMips64I16x8Q15MulRSatS:
    case kMips64I32x4Add:
    case kMips64I32x4Eq:
    case kMips64I32x4ExtractLane:
    case kMips64I32x4GeS:
    case kMips64I32x4GeU:
    case kMips64I32x4GtS:
    case kMips64I32x4GtU:
    case kMips64I32x4MaxS:
    case kMips64I32x4MaxU:
    case kMips64I32x4MinS:
    case kMips64I32x4MinU:
    case kMips64I32x4Mul:
    case kMips64I32x4Ne:
    case kMips64I32x4Neg:
    case kMips64I32x4ReplaceLane:
    case kMips64I32x4SConvertF32x4:
    case kMips64I32x4SConvertI16x8High:
    case kMips64I32x4SConvertI16x8Low:
    case kMips64I32x4Shl:
    case kMips64I32x4ShrS:
    case kMips64I32x4ShrU:
    case kMips64I32x4Splat:
    case kMips64I32x4Sub:
    case kMips64I32x4UConvertF32x4:
    case kMips64I32x4UConvertI16x8High:
    case kMips64I32x4UConvertI16x8Low:
    case kMips64I32x4Abs:
    case kMips64I32x4BitMask:
    case kMips64I32x4DotI16x8S:
    case kMips64I32x4TruncSatF64x2SZero:
    case kMips64I32x4TruncSatF64x2UZero:
    case kMips64I8x16Add:
    case kMips64I8x16AddSatS:
    case kMips64I8x16AddSatU:
    case kMips64I8x16Eq:
    case kMips64I8x16ExtractLaneU:
    case kMips64I8x16ExtractLaneS:
    case kMips64I8x16GeS:
    case kMips64I8x16GeU:
    case kMips64I8x16GtS:
    case kMips64I8x16GtU:
    case kMips64I8x16MaxS:
    case kMips64I8x16MaxU:
    case kMips64I8x16MinS:
    case kMips64I8x16MinU:
    case kMips64I8x16Ne:
    case kMips64I8x16Neg:
    case kMips64I8x16ReplaceLane:
    case kMips64I8x16Shl:
    case kMips64I8x16ShrS:
    case kMips64I8x16ShrU:
    case kMips64I8x16Splat:
    case kMips64I8x16Sub:
    case kMips64I8x16SubSatS:
    case kMips64I8x16SubSatU:
    case kMips64I8x16RoundingAverageU:
    case kMips64I8x16Abs:
    case kMips64I8x16Popcnt:
    case kMips64I8x16BitMask:
    case kMips64Ins:
    case kMips64Lsa:
    case kMips64MaxD:
    case kMips64MaxS:
    case kMips64MinD:
    case kMips64MinS:
    case kMips64Mod:
    case kMips64ModU:
    case kMips64Mov:
    case kMips64Mul:
    case kMips64MulD:
    case kMips64MulHigh:
    case kMips64MulOvf:
    case kMips64MulS:
    case kMips64NegD:
    case kMips64NegS:
    case kMips64Nor:
    case kMips64Nor32:
    case kMips64Or:
    case kMips64Or32:
    case kMips64Popcnt:
    case kMips64Ror:
    case kMips64RoundWD:
    case kMips64RoundWS:
    case kMips64S128And:
    case kMips64S128Or:
    case kMips64S128Not:
    case kMips64S128Select:
    case kMips64S128AndNot:
    case kMips64S128Xor:
    case kMips64S128Const:
    case kMips64S128Zero:
    case kMips64S128AllOnes:
    case kMips64S16x8InterleaveEven:
    case kMips64S16x8InterleaveOdd:
    case kMips64S16x8InterleaveLeft:
    case kMips64S16x8InterleaveRight:
    case kMips64S16x8PackEven:
    case kMips64S16x8PackOdd:
    case kMips64S16x2Reverse:
    case kMips64S16x4Reverse:
    case kMips64I64x2AllTrue:
    case kMips64I32x4AllTrue:
    case kMips64I16x8AllTrue:
    case kMips64I8x16AllTrue:
    case kMips64V128AnyTrue:
    case kMips64S32x4InterleaveEven:
    case kMips64S32x4InterleaveOdd:
    case kMips64S32x4InterleaveLeft:
    case kMips64S32x4InterleaveRight:
    case kMips64S32x4PackEven:
    case kMips64S32x4PackOdd:
    case kMips64S32x4Shuffle:
    case kMips64S8x16Concat:
    case kMips64S8x16InterleaveEven:
    case kMips64S8x16InterleaveOdd:
    case kMips64S8x16InterleaveLeft:
    case kMips64S8x16InterleaveRight:
    case kMips64S8x16PackEven:
    case kMips64S8x16PackOdd:
    case kMips64S8x2Reverse:
    case kMips64S8x4Reverse:
    case kMips64S8x8Reverse:
    case kMips64I8x16Shuffle:
    case kMips64I8x16Swizzle:
    case kMips64Sar:
    case kMips64Seb:
    case kMips64Seh:
    case kMips64Shl:
    case kMips64Shr:
    case kMips64SqrtD:
    case kMips64SqrtS:
    case kMips64Sub:
    case kMips64SubD:
    case kMips64SubS:
    case kMips64TruncLD:
    case kMips64TruncLS:
    case kMips64TruncUlD:
    case kMips64TruncUlS:
    case kMips64TruncUwD:
    case kMips64TruncUwS:
    case kMips64TruncWD:
    case kMips64TruncWS:
    case kMips64Tst:
    case kMips64Xor:
    case kMips64Xor32:
      return kNoOpcodeFlags;

    case kMips64Lb:
    case kMips64Lbu:
    case kMips64Ld:
    case kMips64Ldc1:
    case kMips64Lh:
    case kMips64Lhu:
    case kMips64Lw:
    case kMips64Lwc1:
    case kMips64Lwu:
    case kMips64MsaLd:
    case kMips64Peek:
    case kMips64Uld:
    case kMips64Uldc1:
    case kMips64Ulh:
    case kMips64Ulhu:
    case kMips64Ulw:
    case kMips64Ulwu:
    case kMips64Ulwc1:
    case kMips64S128LoadSplat:
    case kMips64S128Load8x8S:
    case kMips64S128Load8x8U:
    case kMips64S128Load16x4S:
    case kMips64S128Load16x4U:
    case kMips64S128Load32x2S:
    case kMips64S128Load32x2U:
    case kMips64S128Load32Zero:
    case kMips64S128Load64Zero:
    case kMips64S128LoadLane:
    case kMips64Word64AtomicLoadUint64:

      return kIsLoadOperation;

    case kMips64ModD:
    case kMips64MsaSt:
    case kMips64Push:
    case kMips64Sb:
    case kMips64Sd:
    case kMips64Sdc1:
    case kMips64Sh:
    case kMips64StackClaim:
    case kMips64StoreToStackSlot:
    case kMips64Sw:
    case kMips64Swc1:
    case kMips64Usd:
    case kMips64Usdc1:
    case kMips64Ush:
    case kMips64Usw:
    case kMips64Uswc1:
    case kMips64Sync:
    case kMips64S128StoreLane:
    case kMips64StoreCompressTagged:
    case kMips64Word64AtomicStoreWord64:
    case kMips64Word64AtomicAddUint64:
    case kMips64Word64AtomicSubUint64:
    case kMips64Word64AtomicAndUint64:
    case kMips64Word64AtomicOrUint64:
    case kMips64Word64AtomicXorUint64:
    case kMips64Word64AtomicExchangeUint64:
    case kMips64Word64AtomicCompareExchangeUint64:
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
  BRANCH = 4,  // Estimated max.
  RINT_S = 4,  // Estimated.
  RINT_D = 4,  // Estimated.

  MULT = 4,
  MULTU = 4,
  DMULT = 4,
  DMULTU = 4,

  MUL = 7,
  DMUL = 7,
  MUH = 7,
  MUHU = 7,
  DMUH = 7,
  DMUHU = 7,

  DIV = 50,  // Min:11 Max:50
  DDIV = 50,
  DIVU = 50,
  DDIVU = 50,

  ABS_S = 4,
  ABS_D = 4,
  NEG_S = 4,
  NEG_D = 4,
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

  MTC1 = 4,
  MTHC1 = 4,
  DMTC1 = 4,
  LWC1 = 4,
  LDC1 = 4,

  MFC1 = 1,
  MFHC1 = 1,
  DMFC1 = 1,
  MFHI = 1,
  MFLO = 1,
  SWC1 = 1,
  SDC1 = 1,
};

int DadduLatency(bool is_operand_register = true) {
  if (is_operand_register) {
    return 1;
  } else {
    return 2;  // Estimated max.
  }
}

int DsubuLatency(bool is_operand_register = true) {
  return DadduLatency(is_operand_register);
}

int AndLatency(bool is_operand_register = true) {
  return DadduLatency(is_operand_register);
}

int OrLatency(bool is_operand_register = true) {
  return DadduLatency(is_operand_register);
}

int NorLatency(bool is_operand_register = true) {
  if (is_operand_register) {
    return 1;
  } else {
    return 2;  // Estimated max.
  }
}

int XorLatency(bool is_operand_register = true) {
  return DadduLatency(is_operand_register);
}

int MulLatency(bool is_operand_register = true) {
  if (is_operand_register) {
    return Latency::MUL;
  } else {
    return Latency::MUL + 1;
  }
}

int DmulLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = Latency::DMUL;
  } else {
    latency = Latency::DMULT + Latency::MFLO;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int MulhLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = Latency::MUH;
  } else {
    latency = Latency::MULT + Latency::MFHI;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int MulhuLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = Latency::MUH;
  } else {
    latency = Latency::MULTU + Latency::MFHI;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int DMulhLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = Latency::DMUH;
  } else {
    latency = Latency::DMULT + Latency::MFHI;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int DivLatency(bool is_operand_register = true) {
  if (is_operand_register) {
    return Latency::DIV;
  } else {
    return Latency::DIV + 1;
  }
}

int DivuLatency(bool is_operand_register = true) {
  if (is_operand_register) {
    return Latency::DIVU;
  } else {
    return Latency::DIVU + 1;
  }
}

int DdivLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = Latency::DDIV;
  } else {
    latency = Latency::DDIV + Latency::MFLO;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int DdivuLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = Latency::DDIVU;
  } else {
    latency = Latency::DDIVU + Latency::MFLO;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int ModLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = 1;
  } else {
    latency = Latency::DIV + Latency::MFHI;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int ModuLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = 1;
  } else {
    latency = Latency::DIVU + Latency::MFHI;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int DmodLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = 1;
  } else {
    latency = Latency::DDIV + Latency::MFHI;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int DmoduLatency(bool is_operand_register = true) {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = 1;
  } else {
    latency = Latency::DDIV + Latency::MFHI;
  }
  if (!is_operand_register) {
    latency += 1;
  }
  return latency;
}

int MovzLatency() {
  if (kArchVariant >= kMips64r6) {
    return Latency::BRANCH + 1;
  } else {
    return 1;
  }
}

int MovnLatency() {
  if (kArchVariant >= kMips64r6) {
    return Latency::BRANCH + 1;
  } else {
    return 1;
  }
}

int DlsaLatency() {
  // Estimated max.
  return DadduLatency() + 1;
}

int CallLatency() {
  // Estimated.
  return DadduLatency(false) + Latency::BRANCH + 5;
}

int JumpLatency() {
  // Estimated max.
  return 1 + DadduLatency() + Latency::BRANCH + 2;
}

int SmiUntagLatency() { return 1; }

int PrepareForTailCallLatency() {
  // Estimated max.
  return 2 * (DlsaLatency() + DadduLatency(false)) + 2 + Latency::BRANCH +
         Latency::BRANCH + 2 * DsubuLatency(false) + 2 + Latency::BRANCH + 1;
}

int AssertLatency() { return 1; }

int PrepareCallCFunctionLatency() {
  int frame_alignment = MacroAssembler::ActivationFrameAlignment();
  if (frame_alignment > kSystemPointerSize) {
    return 1 + DsubuLatency(false) + AndLatency(false) + 1;
  } else {
    return DsubuLatency(false);
  }
}

int AdjustBaseAndOffsetLatency() {
  return 3;  // Estimated max.
}

int AlignedMemoryLatency() { return AdjustBaseAndOffsetLatency() + 1; }

int UlhuLatency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    return AdjustBaseAndOffsetLatency() + 2 * AlignedMemoryLatency() + 2;
  }
}

int UlwLatency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    // Estimated max.
    return AdjustBaseAndOffsetLatency() + 3;
  }
}

int UlwuLatency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    return UlwLatency() + 1;
  }
}

int UldLatency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    // Estimated max.
    return AdjustBaseAndOffsetLatency() + 3;
  }
}

int Ulwc1Latency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    return UlwLatency() + Latency::MTC1;
  }
}

int Uldc1Latency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    return UldLatency() + Latency::DMTC1;
  }
}

int UshLatency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    // Estimated max.
    return AdjustBaseAndOffsetLatency() + 2 + 2 * AlignedMemoryLatency();
  }
}

int UswLatency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    return AdjustBaseAndOffsetLatency() + 2;
  }
}

int UsdLatency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    return AdjustBaseAndOffsetLatency() + 2;
  }
}

int Uswc1Latency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    return Latency::MFC1 + UswLatency();
  }
}

int Usdc1Latency() {
  if (kArchVariant >= kMips64r6) {
    return AlignedMemoryLatency();
  } else {
    return Latency::DMFC1 + UsdLatency();
  }
}

int Lwc1Latency() { return AdjustBaseAndOffsetLatency() + Latency::LWC1; }

int Swc1Latency() { return AdjustBaseAndOffsetLatency() + Latency::SWC1; }

int Sdc1Latency() { return AdjustBaseAndOffsetLatency() + Latency::SDC1; }

int Ldc1Latency() { return AdjustBaseAndOffsetLatency() + Latency::LDC1; }

int MultiPushLatency() {
  int latency = DsubuLatency(false);
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    latency++;
  }
  return latency;
}

int MultiPushFPULatency() {
  int latency = DsubuLatency(false);
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    latency += Sdc1Latency();
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
  int latency = DadduLatency(false);
  for (int16_t i = 0; i < kNumRegisters; i++) {
    latency++;
  }
  return latency;
}

int MultiPopFPULatency() {
  int latency = DadduLatency(false);
  for (int16_t i = 0; i < kNumRegisters; i++) {
    latency += Ldc1Latency();
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
    latency += DadduLatency(false);
  }
  return latency;
}

int CallCFunctionLatency() { return 1 + CallCFunctionHelperLatency(); }

int AssembleArchJumpLatency() {
  // Estimated max.
  return Latency::BRANCH;
}

int GenerateSwitchTableLatency() {
  int latency = 0;
  if (kArchVariant >= kMips64r6) {
    latency = DlsaLatency() + 2;
  } else {
    latency = 6;
  }
  latency += 2;
  return latency;
}

int AssembleArchTableSwitchLatency() {
  return Latency::BRANCH + GenerateSwitchTableLatency();
}

int DropAndRetLatency() {
  // Estimated max.
  return DadduLatency(false) + JumpLatency();
}

int AssemblerReturnLatency() {
  // Estimated max.
  return DadduLatency(false) + MultiPopLatency() + MultiPopFPULatency() +
         Latency::BRANCH + DadduLatency() + 1 + DropAndRetLatency();
}

int TryInlineTruncateDoubleToILatency() {
  return 2 + Latency::TRUNC_W_D + Latency::MFC1 + 2 + AndLatency(false) +
         Latency::BRANCH;
}

int CallStubDelayedLatency() { return 1 + CallLatency(); }

int TruncateDoubleToIDelayedLatency() {
  // TODO(mips): This no longer reflects how TruncateDoubleToI is called.
  return TryInlineTruncateDoubleToILatency() + 1 + DsubuLatency(false) +
         Sdc1Latency() + CallStubDelayedLatency() + DadduLatency(false) + 1;
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

int BranchShortHelperR6Latency() {
  return 2;  // Estimated max.
}

int BranchShortHelperLatency() {
  return SltuLatency() + 2;  // Estimated max.
}

int BranchShortLatency(BranchDelaySlot bdslot = PROTECT) {
  if (kArchVariant >= kMips64r6 && bdslot == PROTECT) {
    return BranchShortHelperR6Latency();
  } else {
    return BranchShortHelperLatency();
  }
}

int MoveLatency() { return 1; }

int MovToFloatParametersLatency() { return 2 * MoveLatency(); }

int MovFromFloatResultLatency() { return MoveLatency(); }

int DaddOverflowLatency() {
  // Estimated max.
  return 6;
}

int DsubOverflowLatency() {
  // Estimated max.
  return 6;
}

int MulOverflowLatency() {
  // Estimated max.
  return MulLatency() + MulhLatency() + 2;
}

int DclzLatency() { return 1; }

int CtzLatency() {
  if (kArchVariant >= kMips64r6) {
    return 3 + DclzLatency();
  } else {
    return DadduLatency(false) + XorLatency() + AndLatency() + DclzLatency() +
           1 + DsubuLatency();
  }
}

int DctzLatency() {
  if (kArchVariant >= kMips64r6) {
    return 4;
  } else {
    return DadduLatency(false) + XorLatency() + AndLatency() + 1 +
           DsubuLatency();
  }
}

int PopcntLatency() {
  return 2 + AndLatency() + DsubuLatency() + 1 + AndLatency() + 1 +
         AndLatency() + DadduLatency() + 1 + DadduLatency() + 1 + AndLatency() +
         1 + MulLatency() + 1;
}

int DpopcntLatency() {
  return 2 + AndLatency() + DsubuLatency() + 1 + AndLatency() + 1 +
         AndLatency() + DadduLatency() + 1 + DadduLatency() + 1 + AndLatency() +
         1 + DmulLatency() + 1;
}

int CompareFLatency() { return Latency::C_cond_S; }

int CompareF32Latency() { return CompareFLatency(); }

int CompareF64Latency() { return CompareFLatency(); }

int CompareIsNanFLatency() { return CompareFLatency(); }

int CompareIsNanF32Latency() { return CompareIsNanFLatency(); }

int CompareIsNanF64Latency() { return CompareIsNanFLatency(); }

int NegsLatency() {
  if (kArchVariant >= kMips64r6) {
    return Latency::NEG_S;
  } else {
    // Estimated.
    return CompareIsNanF32Latency() + 2 * Latency::BRANCH + Latency::NEG_S +
           Latency::MFC1 + 1 + XorLatency() + Latency::MTC1;
  }
}

int NegdLatency() {
  if (kArchVariant >= kMips64r6) {
    return Latency::NEG_D;
  } else {
    // Estimated.
    return CompareIsNanF64Latency() + 2 * Latency::BRANCH + Latency::NEG_D +
           Latency::DMFC1 + 1 + XorLatency() + Latency::DMTC1;
  }
}

int Float64RoundLatency() {
  if (kArchVariant >= kMips64r6) {
    return Latency::RINT_D + 4;
  } else {
    // For ceil_l_d, floor_l_d, round_l_d, trunc_l_d latency is 4.
    return Latency::DMFC1 + 1 + Latency::BRANCH + Latency::MOV_D + 4 +
           Latency::DMFC1 + Latency::BRANCH + Latency::CVT_D_L + 2 +
           Latency::MTHC1;
  }
}

int Float32RoundLatency() {
  if (kArchVariant >= kMips64r6) {
    return Latency::RINT_S + 4;
  } else {
    // For ceil_w_s, floor_w_s, round_w_s, trunc_w_s latency is 4.
    return Latency::MFC1 + 1 + Latency::BRANCH + Latency::MOV_S + 4 +
           Latency::MFC1 + Latency::BRANCH + Latency::CVT_S_W + 2 +
           Latency::MTC1;
  }
}

int Float32MaxLatency() {
  // Estimated max.
  int latency = CompareIsNanF32Latency() + Latency::BRANCH;
  if (kArchVariant >= kMips64r6) {
    return latency + Latency::MAX_S;
  } else {
    return latency + 5 * Latency::BRANCH + 2 * CompareF32Latency() +
           Latency::MFC1 + 1 + Latency::MOV_S;
  }
}

int Float64MaxLatency() {
  // Estimated max.
  int latency = CompareIsNanF64Latency() + Latency::BRANCH;
  if (kArchVariant >= kMips64r6) {
    return latency + Latency::MAX_D;
  } else {
    return latency + 5 * Latency::BRANCH + 2 * CompareF64Latency() +
           Latency::DMFC1 + Latency::MOV_D;
  }
}

int Float32MinLatency() {
  // Estimated max.
  int latency = CompareIsNanF32Latency() + Latency::BRANCH;
  if (kArchVariant >= kMips64r6) {
    return latency + Latency::MIN_S;
  } else {
    return latency + 5 * Latency::BRANCH + 2 * CompareF32Latency() +
           Latency::MFC1 + 1 + Latency::MOV_S;
  }
}

int Float64MinLatency() {
  // Estimated max.
  int latency = CompareIsNanF64Latency() + Latency::BRANCH;
  if (kArchVariant >= kMips64r6) {
    return latency + Latency::MIN_D;
  } else {
    return latency + 5 * Latency::BRANCH + 2 * CompareF32Latency() +
           Latency::DMFC1 + Latency::MOV_D;
  }
}

int TruncLSLatency(bool load_status) {
  int latency = Latency::TRUNC_L_S + Latency::DMFC1;
  if (load_status) {
    latency += SltuLatency() + 7;
  }
  return latency;
}

int TruncLDLatency(bool load_status) {
  int latency = Latency::TRUNC_L_D + Latency::DMFC1;
  if (load_status) {
    latency += SltuLatency() + 7;
  }
  return latency;
}

int TruncUlSLatency() {
  // Estimated max.
  return 2 * CompareF32Latency() + CompareIsNanF32Latency() +
         4 * Latency::BRANCH + Latency::SUB_S + 2 * Latency::TRUNC_L_S +
         3 * Latency::DMFC1 + OrLatency() + Latency::MTC1 + Latency::MOV_S +
         SltuLatency() + 4;
}

int TruncUlDLatency() {
  // Estimated max.
  return 2 * CompareF64Latency() + CompareIsNanF64Latency() +
         4 * Latency::BRANCH + Latency::SUB_D + 2 * Latency::TRUNC_L_D +
         3 * Latency::DMFC1 + OrLatency() + Latency::DMTC1 + Latency::MOV_D +
         SltuLatency() + 4;
}

int PushLatency() { return DadduLatency() + AlignedMemoryLatency(); }

int ByteSwapSignedLatency() { return 2; }

int LlLatency(int offset) {
  bool is_one_instruction =
      (kArchVariant == kMips64r6) ? is_int9(offset) : is_int16(offset);
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

int InsertBitsLatency() { return 2 + DsubuLatency(false) + 2; }

int ScLatency(int offset) {
  bool is_one_instruction =
      (kArchVariant == kMips64r6) ? is_int9(offset) : is_int16(offset);
  if (is_one_instruction) {
    return 1;
  } else {
    return 3;
  }
}

int Word32AtomicExchangeLatency(bool sign_extend, int size) {
  return DadduLatency(false) + 1 + DsubuLatency() + 2 + LlLatency(0) +
         ExtractBitsLatency(sign_extend, size) + InsertBitsLatency() +
         ScLatency(0) + BranchShortLatency() + 1;
}

int Word32AtomicCompareExchangeLatency(bool sign_extend, int size) {
  return 2 + DsubuLatency() + 2 + LlLatency(0) +
         ExtractBitsLatency(sign_extend, size) + InsertBitsLatency() +
         ScLatency(0) + BranchShortLatency() + 1;
}

int InstructionScheduler::GetInstructionLatency(const Instruction* instr) {
  // Basic latency modeling for MIPS64 instructions. They have been determined
  // in empirical way.
  switch (instr->arch_opcode()) {
    case kArchCallCodeObject:
#if V8_ENABLE_WEBASSEMBLY
    case kArchCallWasmFunction:
#endif  // V8_ENABLE_WEBASSEMBLY
      return CallLatency();
    case kArchTailCallCodeObject:
#if V8_ENABLE_WEBASSEMBLY
    case kArchTailCallWasm:
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArchTailCallAddress:
      return JumpLatency();
    case kArchCallJSFunction: {
      int latency = 0;
      if (v8_flags.debug_code) {
        latency = 1 + AssertLatency();
      }
      return latency + 1 + DadduLatency(false) + CallLatency();
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
      return DadduLatency() + 1 + CheckPageFlagLatency();
    case kArchStackSlot:
      // Estimated max.
      return DadduLatency(false) + AndLatency(false) + AssertLatency() +
             DadduLatency(false) + AndLatency(false) + BranchShortLatency() +
             1 + DsubuLatency() + DadduLatency();
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
    case kMips64Add:
    case kMips64Dadd:
      return DadduLatency(instr->InputAt(1)->IsRe
```