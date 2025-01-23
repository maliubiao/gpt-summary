Response: Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The request asks for a summary of the C++ code's function and its relation to JavaScript, with a JavaScript example if applicable.

2. **Initial Code Scan:**  Quickly look through the code for keywords and structure. Notice the header comment, `#include`, namespaces (`v8`, `internal`, `compiler`), function definitions (`SchedulerSupported`, `GetTargetInstructionFlags`, `GetInstructionLatency`), and the large `switch` statement.

3. **Identify the Core Class:** The code is within the `InstructionScheduler` class. The filename and the class name strongly suggest its purpose: scheduling instructions. The `s390` in the filename indicates this is for the IBM z/Architecture (System/390).

4. **Analyze Key Functions:**

   * **`SchedulerSupported()`:** This simply returns `true`. This immediately tells us that instruction scheduling *is* supported for the S390 architecture in V8.

   * **`GetTargetInstructionFlags(const Instruction* instr)`:**  This is the most complex part. The `switch` statement operates on `instr->arch_opcode()`. This suggests that the function determines certain properties (flags) of a given machine instruction based on its opcode. The cases list various S390 assembly instructions (e.g., `kS390_Add32`, `kS390_LoadWord64`). The `return` values (`kNoOpcodeFlags`, `kIsLoadOperation`, `kHasSideEffect`) indicate categories of instruction behavior. This is about classifying instructions for the scheduler.

   * **`GetInstructionLatency(const Instruction* instr)`:** This currently just returns `1`. The comment `// TODO(all): Add instruction cost modeling.` is a crucial hint. It signifies that this function *should* eventually provide a more accurate estimate of how long an instruction takes to execute, but for now, it's a placeholder.

5. **Connect to Instruction Scheduling:**  Based on the class name and the analysis of the functions, the core function of this code is to provide the V8 instruction scheduler with target-architecture-specific information for the S390. This information helps the scheduler make informed decisions about the order in which instructions should be executed to optimize performance.

6. **Consider the JavaScript Connection:** V8 is the JavaScript engine in Chrome and Node.js. It compiles JavaScript code into machine code. The instruction scheduler is a component of this compilation process. Therefore, this C++ code directly influences how efficiently JavaScript runs on S390 systems.

7. **Develop the Summary:** Based on the above, formulate a concise summary highlighting the key functions and their purpose. Emphasize that it's about providing architecture-specific details for instruction scheduling on S390.

8. **Create the JavaScript Example (the trickiest part):** This requires understanding *why* instruction scheduling is important. The goal is to show how different orderings of JavaScript operations can lead to different underlying machine instructions and potentially different performance.

   * **Think about instruction dependencies:**  The scheduler tries to avoid stalls by ordering instructions so that data needed by one instruction is available when it executes.
   * **Consider simple arithmetic:**  Basic arithmetic operations in JavaScript translate to machine instructions like `add`, `subtract`, etc.
   * **Focus on side effects (though not directly demonstrated by the example):** The `kHasSideEffect` flag is important. Instructions with side effects (like writing to memory) often have ordering constraints.
   * **Create an example with potential ordering variations:** The provided example `let a = 1 + 2; let b = 3 * 4; console.log(a + b);` is good because the calculations for `a` and `b` are independent. The scheduler could potentially calculate `a` or `b` first.
   * **Explain the connection:**  Clearly state that the C++ code helps the scheduler decide the *optimal order* of the underlying S390 instructions corresponding to the JavaScript. Mentioning load operations and side effects gives more context, even if the example doesn't explicitly trigger those flags.

9. **Refine and Review:** Read through the summary and example to ensure clarity, accuracy, and conciseness. Check for any technical jargon that needs explanation. For example, explicitly stating that V8 compiles JavaScript to machine code is helpful.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus on specific optimization techniques the scheduler uses. **Correction:** The code doesn't reveal the scheduling *algorithm*, only the *input* data it uses. Focus on the purpose of the data.
* **Considering the JavaScript example:**  Should the example directly demonstrate load/store operations? **Correction:**  While important, complex memory access patterns might obscure the basic idea. A simple arithmetic example is easier to understand, and the explanation can connect it to load/store and side effects conceptually.
* **Latency:** Initially might overlook the comment about TODO. **Correction:** Include that the latency function is currently basic but intended to be more sophisticated. This adds valuable context.

By following these steps, combining code analysis with an understanding of the purpose of instruction scheduling within a JavaScript engine, we can arrive at a comprehensive and informative explanation.
这个C++源代码文件 `instruction-scheduler-s390.cc` 是 V8 JavaScript 引擎中针对 **s390 (IBM System/z)** 架构的 **指令调度器 (Instruction Scheduler)** 的一部分。

**它的主要功能是：**

1. **声明对 s390 架构的支持:** `InstructionScheduler::SchedulerSupported()` 函数返回 `true`，表明 V8 的指令调度器功能可以在 s390 架构上使用。

2. **为 s390 指令提供目标相关的标志 (Flags):**  `InstructionScheduler::GetTargetInstructionFlags(const Instruction* instr)` 函数根据给定的机器指令 (`Instruction* instr`) 的操作码 (`instr->arch_opcode()`)，返回该指令的目标架构相关的标志。这些标志用于指导指令调度器做出更优的调度决策。

   - **`kNoOpcodeFlags`:** 表示指令没有特殊的调度考量。
   - **`kIsLoadOperation`:** 表示指令是一个加载操作，可能需要考虑延迟和依赖关系。
   - **`kHasSideEffect`:** 表示指令有副作用 (例如，修改内存)，调度时需要注意顺序。

   这个函数通过一个大的 `switch` 语句，列出了大量的 s390 指令，并根据其类型返回相应的标志。例如，加载指令 (如 `kS390_LoadWord64`) 被标记为 `kIsLoadOperation`，而存储指令 (如 `kS390_StoreWord32`) 被标记为 `kHasSideEffect`。算术和逻辑运算指令通常被标记为 `kNoOpcodeFlags`。

3. **为 s390 指令提供延迟信息 (目前是简化的):** `InstructionScheduler::GetInstructionLatency(const Instruction* instr)` 函数旨在返回给定指令的执行延迟。 然而，目前的实现只是简单地返回 `1`，并且代码中有一个 `TODO` 注释表明未来会加入更精确的指令延迟模型。

**与 JavaScript 的关系：**

这个文件是 V8 引擎编译 JavaScript 代码到 s390 机器码过程中的一个重要组成部分。

1. **JavaScript 代码的编译:** 当 V8 编译 JavaScript 代码时，它会生成一系列的中间表示 (IR)。最终，这些 IR 会被转换成目标架构 (在这个例子中是 s390) 的机器指令。

2. **指令调度器的作用:**  指令调度器的目标是优化生成的机器指令的执行顺序，以提高性能。它会考虑指令之间的依赖关系、指令的延迟以及目标架构的特性。

3. **`GetTargetInstructionFlags` 的重要性:**  `GetTargetInstructionFlags` 函数提供的标志信息是指令调度器做出正确决策的关键。例如，如果一个指令被标记为 `kIsLoadOperation`，调度器可能会尝试将其提前执行，以隐藏加载延迟。如果一个指令被标记为 `kHasSideEffect`，调度器会确保它在有依赖的指令之前执行。

**JavaScript 示例：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它影响着 JavaScript 代码在 s390 架构上的执行效率。 考虑以下简单的 JavaScript 代码：

```javascript
let a = 1 + 2;
let b = 3 * 4;
console.log(a + b);
```

当 V8 编译这段 JavaScript 代码到 s390 机器码时，会生成一系列的 s390 指令，例如：

- 加载常量 1 到寄存器
- 加载常量 2 到寄存器
- 执行加法操作 (对应 `kS390_Add32` 或 `kS390_Add64`)
- 将结果存储到 `a` 对应的内存位置
- 加载常量 3 到寄存器
- 加载常量 4 到寄存器
- 执行乘法操作 (对应 `kS390_Mul32` 或 `kS390_Mul64`)
- 将结果存储到 `b` 对应的内存位置
- 加载 `a` 的值到寄存器 (对应 `kS390_LoadWord32` 或 `kS390_LoadWord64`)
- 加载 `b` 的值到寄存器
- 执行加法操作
- 调用 `console.log` 函数

**指令调度器的影响:**

指令调度器会分析这些生成的 s390 指令，并根据目标架构的特性 (例如，通过 `GetTargetInstructionFlags` 获取的信息) 决定一个最优的执行顺序。 例如：

- 如果加载操作的延迟较高，调度器可能会尝试将加载 `a` 或 `b` 的操作提前，与其他独立的计算并行执行。
- 如果乘法操作的延迟比加法操作高，调度器可能会考虑先执行加法操作，如果后续有依赖于加法结果的指令。
- 带有 `kHasSideEffect` 标记的指令 (例如，存储操作) 的顺序通常需要严格遵守。

**总结:**

`instruction-scheduler-s390.cc` 文件是 V8 引擎中针对 s390 架构的指令调度器的核心组成部分。它负责提供关于 s390 机器指令的架构相关信息，帮助指令调度器优化 JavaScript 代码编译后生成的机器指令的执行顺序，从而提升 JavaScript 代码在 s390 平台上的性能。它通过 `GetTargetInstructionFlags` 函数为不同的 s390 指令设置不同的标志，以指导调度器进行更精细的优化。

### 提示词
```
这是目录为v8/src/compiler/backend/s390/instruction-scheduler-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/backend/instruction-scheduler.h"

namespace v8 {
namespace internal {
namespace compiler {

bool InstructionScheduler::SchedulerSupported() { return true; }

int InstructionScheduler::GetTargetInstructionFlags(
    const Instruction* instr) const {
  switch (instr->arch_opcode()) {
    case kS390_Abs32:
    case kS390_Abs64:
    case kS390_And32:
    case kS390_And64:
    case kS390_Or32:
    case kS390_Or64:
    case kS390_Xor32:
    case kS390_Xor64:
    case kS390_ShiftLeft32:
    case kS390_ShiftLeft64:
    case kS390_ShiftRight32:
    case kS390_ShiftRight64:
    case kS390_ShiftRightArith32:
    case kS390_ShiftRightArith64:
    case kS390_RotRight32:
    case kS390_RotRight64:
    case kS390_Not32:
    case kS390_Not64:
    case kS390_RotLeftAndClear64:
    case kS390_RotLeftAndClearLeft64:
    case kS390_RotLeftAndClearRight64:
    case kS390_Lay:
    case kS390_Add32:
    case kS390_Add64:
    case kS390_AddFloat:
    case kS390_AddDouble:
    case kS390_Sub32:
    case kS390_Sub64:
    case kS390_SubFloat:
    case kS390_SubDouble:
    case kS390_Mul32:
    case kS390_Mul32WithOverflow:
    case kS390_Mul64:
    case kS390_Mul64WithOverflow:
    case kS390_MulHighS64:
    case kS390_MulHighU64:
    case kS390_MulHigh32:
    case kS390_MulHighU32:
    case kS390_MulFloat:
    case kS390_MulDouble:
    case kS390_Div32:
    case kS390_Div64:
    case kS390_DivU32:
    case kS390_DivU64:
    case kS390_DivFloat:
    case kS390_DivDouble:
    case kS390_Mod32:
    case kS390_Mod64:
    case kS390_ModU32:
    case kS390_ModU64:
    case kS390_ModDouble:
    case kS390_Neg32:
    case kS390_Neg64:
    case kS390_NegDouble:
    case kS390_NegFloat:
    case kS390_SqrtFloat:
    case kS390_FloorFloat:
    case kS390_CeilFloat:
    case kS390_TruncateFloat:
    case kS390_FloatNearestInt:
    case kS390_AbsFloat:
    case kS390_SqrtDouble:
    case kS390_FloorDouble:
    case kS390_CeilDouble:
    case kS390_TruncateDouble:
    case kS390_RoundDouble:
    case kS390_DoubleNearestInt:
    case kS390_MaxFloat:
    case kS390_MaxDouble:
    case kS390_MinFloat:
    case kS390_MinDouble:
    case kS390_AbsDouble:
    case kS390_Cntlz32:
    case kS390_Cntlz64:
    case kS390_Popcnt32:
    case kS390_Popcnt64:
    case kS390_Cmp32:
    case kS390_Cmp64:
    case kS390_CmpFloat:
    case kS390_CmpDouble:
    case kS390_Tst32:
    case kS390_Tst64:
    case kS390_SignExtendWord8ToInt32:
    case kS390_SignExtendWord16ToInt32:
    case kS390_SignExtendWord8ToInt64:
    case kS390_SignExtendWord16ToInt64:
    case kS390_SignExtendWord32ToInt64:
    case kS390_Uint32ToUint64:
    case kS390_Int64ToInt32:
    case kS390_Int64ToFloat32:
    case kS390_Int64ToDouble:
    case kS390_Uint64ToFloat32:
    case kS390_Uint64ToDouble:
    case kS390_Int32ToFloat32:
    case kS390_Int32ToDouble:
    case kS390_Uint32ToFloat32:
    case kS390_Uint32ToDouble:
    case kS390_Float32ToInt32:
    case kS390_Float32ToUint32:
    case kS390_Float32ToUint64:
    case kS390_Float32ToDouble:
    case kS390_Float64SilenceNaN:
    case kS390_DoubleToInt32:
    case kS390_DoubleToUint32:
    case kS390_Float32ToInt64:
    case kS390_DoubleToInt64:
    case kS390_DoubleToUint64:
    case kS390_DoubleToFloat32:
    case kS390_DoubleExtractLowWord32:
    case kS390_DoubleExtractHighWord32:
    case kS390_DoubleFromWord32Pair:
    case kS390_DoubleInsertLowWord32:
    case kS390_DoubleInsertHighWord32:
    case kS390_DoubleConstruct:
    case kS390_BitcastInt32ToFloat32:
    case kS390_BitcastFloat32ToInt32:
    case kS390_BitcastInt64ToDouble:
    case kS390_BitcastDoubleToInt64:
    case kS390_LoadReverse16RR:
    case kS390_LoadReverse32RR:
    case kS390_LoadReverse64RR:
    case kS390_LoadReverseSimd128RR:
    case kS390_LoadAndTestWord32:
    case kS390_LoadAndTestWord64:
    case kS390_LoadAndTestFloat32:
    case kS390_LoadAndTestFloat64:
    case kS390_F64x2Splat:
    case kS390_F64x2ReplaceLane:
    case kS390_F64x2Abs:
    case kS390_F64x2Neg:
    case kS390_F64x2Sqrt:
    case kS390_F64x2Add:
    case kS390_F64x2Sub:
    case kS390_F64x2Mul:
    case kS390_F64x2Div:
    case kS390_F64x2Eq:
    case kS390_F64x2Ne:
    case kS390_F64x2Lt:
    case kS390_F64x2Le:
    case kS390_F64x2Min:
    case kS390_F64x2Max:
    case kS390_F64x2ExtractLane:
    case kS390_F64x2Qfma:
    case kS390_F64x2Qfms:
    case kS390_F64x2Pmin:
    case kS390_F64x2Pmax:
    case kS390_F64x2Ceil:
    case kS390_F64x2Floor:
    case kS390_F64x2Trunc:
    case kS390_F64x2NearestInt:
    case kS390_F64x2ConvertLowI32x4S:
    case kS390_F64x2ConvertLowI32x4U:
    case kS390_F64x2PromoteLowF32x4:
    case kS390_F32x4Splat:
    case kS390_F32x4ExtractLane:
    case kS390_F32x4ReplaceLane:
    case kS390_F32x4Add:
    case kS390_F32x4Sub:
    case kS390_F32x4Mul:
    case kS390_F32x4Eq:
    case kS390_F32x4Ne:
    case kS390_F32x4Lt:
    case kS390_F32x4Le:
    case kS390_F32x4Abs:
    case kS390_F32x4Neg:
    case kS390_F32x4SConvertI32x4:
    case kS390_F32x4UConvertI32x4:
    case kS390_F32x4Sqrt:
    case kS390_F32x4Div:
    case kS390_F32x4Min:
    case kS390_F32x4Max:
    case kS390_F32x4Qfma:
    case kS390_F32x4Qfms:
    case kS390_F32x4Pmin:
    case kS390_F32x4Pmax:
    case kS390_F32x4Ceil:
    case kS390_F32x4Floor:
    case kS390_F32x4Trunc:
    case kS390_F32x4NearestInt:
    case kS390_F32x4DemoteF64x2Zero:
    case kS390_I64x2Neg:
    case kS390_I64x2Add:
    case kS390_I64x2Sub:
    case kS390_I64x2Shl:
    case kS390_I64x2ShrS:
    case kS390_I64x2ShrU:
    case kS390_I64x2Mul:
    case kS390_I64x2Splat:
    case kS390_I64x2ReplaceLane:
    case kS390_I64x2ExtractLane:
    case kS390_I64x2Eq:
    case kS390_I64x2BitMask:
    case kS390_I64x2ExtMulLowI32x4S:
    case kS390_I64x2ExtMulHighI32x4S:
    case kS390_I64x2ExtMulLowI32x4U:
    case kS390_I64x2ExtMulHighI32x4U:
    case kS390_I64x2SConvertI32x4Low:
    case kS390_I64x2SConvertI32x4High:
    case kS390_I64x2UConvertI32x4Low:
    case kS390_I64x2UConvertI32x4High:
    case kS390_I64x2Ne:
    case kS390_I64x2GtS:
    case kS390_I64x2GeS:
    case kS390_I64x2Abs:
    case kS390_I32x4Splat:
    case kS390_I32x4ExtractLane:
    case kS390_I32x4ReplaceLane:
    case kS390_I32x4Add:
    case kS390_I32x4Sub:
    case kS390_I32x4Mul:
    case kS390_I32x4MinS:
    case kS390_I32x4MinU:
    case kS390_I32x4MaxS:
    case kS390_I32x4MaxU:
    case kS390_I32x4Eq:
    case kS390_I32x4Ne:
    case kS390_I32x4GtS:
    case kS390_I32x4GeS:
    case kS390_I32x4GtU:
    case kS390_I32x4GeU:
    case kS390_I32x4Shl:
    case kS390_I32x4ShrS:
    case kS390_I32x4ShrU:
    case kS390_I32x4Neg:
    case kS390_I32x4SConvertF32x4:
    case kS390_I32x4UConvertF32x4:
    case kS390_I32x4SConvertI16x8Low:
    case kS390_I32x4SConvertI16x8High:
    case kS390_I32x4UConvertI16x8Low:
    case kS390_I32x4UConvertI16x8High:
    case kS390_I32x4Abs:
    case kS390_I32x4BitMask:
    case kS390_I32x4DotI16x8S:
    case kS390_I32x4ExtMulLowI16x8S:
    case kS390_I32x4ExtMulHighI16x8S:
    case kS390_I32x4ExtMulLowI16x8U:
    case kS390_I32x4ExtMulHighI16x8U:
    case kS390_I32x4ExtAddPairwiseI16x8S:
    case kS390_I32x4ExtAddPairwiseI16x8U:
    case kS390_I32x4TruncSatF64x2SZero:
    case kS390_I32x4TruncSatF64x2UZero:
    case kS390_I32x4DotI8x16AddS:
    case kS390_I16x8Splat:
    case kS390_I16x8ExtractLaneU:
    case kS390_I16x8ExtractLaneS:
    case kS390_I16x8ReplaceLane:
    case kS390_I16x8Add:
    case kS390_I16x8Sub:
    case kS390_I16x8Mul:
    case kS390_I16x8MinS:
    case kS390_I16x8MinU:
    case kS390_I16x8MaxS:
    case kS390_I16x8MaxU:
    case kS390_I16x8Eq:
    case kS390_I16x8Ne:
    case kS390_I16x8GtS:
    case kS390_I16x8GeS:
    case kS390_I16x8GtU:
    case kS390_I16x8GeU:
    case kS390_I16x8Shl:
    case kS390_I16x8ShrS:
    case kS390_I16x8ShrU:
    case kS390_I16x8Neg:
    case kS390_I16x8SConvertI32x4:
    case kS390_I16x8UConvertI32x4:
    case kS390_I16x8SConvertI8x16Low:
    case kS390_I16x8SConvertI8x16High:
    case kS390_I16x8UConvertI8x16Low:
    case kS390_I16x8UConvertI8x16High:
    case kS390_I16x8AddSatS:
    case kS390_I16x8SubSatS:
    case kS390_I16x8AddSatU:
    case kS390_I16x8SubSatU:
    case kS390_I16x8RoundingAverageU:
    case kS390_I16x8Abs:
    case kS390_I16x8BitMask:
    case kS390_I16x8ExtMulLowI8x16S:
    case kS390_I16x8ExtMulHighI8x16S:
    case kS390_I16x8ExtMulLowI8x16U:
    case kS390_I16x8ExtMulHighI8x16U:
    case kS390_I16x8ExtAddPairwiseI8x16S:
    case kS390_I16x8ExtAddPairwiseI8x16U:
    case kS390_I16x8Q15MulRSatS:
    case kS390_I16x8DotI8x16S:
    case kS390_I8x16Splat:
    case kS390_I8x16ExtractLaneU:
    case kS390_I8x16ExtractLaneS:
    case kS390_I8x16ReplaceLane:
    case kS390_I8x16Add:
    case kS390_I8x16Sub:
    case kS390_I8x16MinS:
    case kS390_I8x16MinU:
    case kS390_I8x16MaxS:
    case kS390_I8x16MaxU:
    case kS390_I8x16Eq:
    case kS390_I8x16Ne:
    case kS390_I8x16GtS:
    case kS390_I8x16GeS:
    case kS390_I8x16GtU:
    case kS390_I8x16GeU:
    case kS390_I8x16Shl:
    case kS390_I8x16ShrS:
    case kS390_I8x16ShrU:
    case kS390_I8x16Neg:
    case kS390_I8x16SConvertI16x8:
    case kS390_I8x16UConvertI16x8:
    case kS390_I8x16AddSatS:
    case kS390_I8x16SubSatS:
    case kS390_I8x16AddSatU:
    case kS390_I8x16SubSatU:
    case kS390_I8x16RoundingAverageU:
    case kS390_I8x16Abs:
    case kS390_I8x16BitMask:
    case kS390_I8x16Shuffle:
    case kS390_I8x16Swizzle:
    case kS390_I8x16Popcnt:
    case kS390_I64x2AllTrue:
    case kS390_I32x4AllTrue:
    case kS390_I16x8AllTrue:
    case kS390_I8x16AllTrue:
    case kS390_V128AnyTrue:
    case kS390_S128And:
    case kS390_S128Or:
    case kS390_S128Xor:
    case kS390_S128Const:
    case kS390_S128Zero:
    case kS390_S128AllOnes:
    case kS390_S128Not:
    case kS390_S128Select:
    case kS390_S128AndNot:
      return kNoOpcodeFlags;

    case kS390_LoadWordS8:
    case kS390_LoadWordU8:
    case kS390_LoadWordS16:
    case kS390_LoadWordU16:
    case kS390_LoadWordS32:
    case kS390_LoadWordU32:
    case kS390_LoadWord64:
    case kS390_LoadFloat32:
    case kS390_LoadDouble:
    case kS390_LoadSimd128:
    case kS390_LoadReverse16:
    case kS390_LoadReverse32:
    case kS390_LoadReverse64:
    case kS390_LoadReverseSimd128:
    case kS390_Peek:
    case kS390_LoadDecompressTaggedSigned:
    case kS390_LoadDecompressTagged:
    case kS390_S128Load8Splat:
    case kS390_S128Load16Splat:
    case kS390_S128Load32Splat:
    case kS390_S128Load64Splat:
    case kS390_S128Load8x8S:
    case kS390_S128Load8x8U:
    case kS390_S128Load16x4S:
    case kS390_S128Load16x4U:
    case kS390_S128Load32x2S:
    case kS390_S128Load32x2U:
    case kS390_S128Load32Zero:
    case kS390_S128Load64Zero:
    case kS390_S128Load8Lane:
    case kS390_S128Load16Lane:
    case kS390_S128Load32Lane:
    case kS390_S128Load64Lane:
      return kIsLoadOperation;

    case kS390_StoreWord8:
    case kS390_StoreWord16:
    case kS390_StoreWord32:
    case kS390_StoreWord64:
    case kS390_StoreReverseSimd128:
    case kS390_StoreReverse16:
    case kS390_StoreReverse32:
    case kS390_StoreReverse64:
    case kS390_StoreFloat32:
    case kS390_StoreDouble:
    case kS390_StoreSimd128:
    case kS390_StoreCompressTagged:
    case kS390_Push:
    case kS390_PushFrame:
    case kS390_StoreToStackSlot:
    case kS390_S128Store8Lane:
    case kS390_S128Store16Lane:
    case kS390_S128Store32Lane:
    case kS390_S128Store64Lane:
      return kHasSideEffect;

    case kS390_Word64AtomicExchangeUint64:
    case kS390_Word64AtomicCompareExchangeUint64:
    case kS390_Word64AtomicAddUint64:
    case kS390_Word64AtomicSubUint64:
    case kS390_Word64AtomicAndUint64:
    case kS390_Word64AtomicOrUint64:
    case kS390_Word64AtomicXorUint64:
      return kHasSideEffect;

#define CASE(Name) case k##Name:
      COMMON_ARCH_OPCODE_LIST(CASE)
#undef CASE
      // Already covered in architecture independent code.
      UNREACHABLE();
  }

  UNREACHABLE();
}

int InstructionScheduler::GetInstructionLatency(const Instruction* instr) {
  // TODO(all): Add instruction cost modeling.
  return 1;
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```