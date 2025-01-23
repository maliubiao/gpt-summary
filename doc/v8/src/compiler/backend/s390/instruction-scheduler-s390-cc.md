Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Identify the Core Purpose:** The filename `instruction-scheduler-s390.cc` and the enclosing namespace `v8::internal::compiler` strongly suggest this code is part of V8's compiler, specifically dealing with instruction scheduling for the s390 architecture.

2. **High-Level Understanding of Instruction Scheduling:** Recall (or quickly look up) what instruction scheduling is. It's a compiler optimization technique that reorders instructions to improve performance, primarily by reducing pipeline stalls. The goal is to execute instructions as efficiently as possible on the target processor.

3. **Examine the `SchedulerSupported()` Function:** This is a simple function that returns `true`. This immediately tells us that instruction scheduling *is* supported for the s390 architecture in V8.

4. **Analyze the `GetTargetInstructionFlags()` Function:** This is the most complex and informative part.

    * **Purpose:**  The function takes an `Instruction` pointer as input and returns an integer representing flags related to that instruction. The name `GetTargetInstructionFlags` implies it's specific to the target architecture (s390).

    * **The `switch` Statement:**  The core of the function is a large `switch` statement based on `instr->arch_opcode()`. This means the function is analyzing the *type* of the s390 instruction.

    * **The `case` Labels:** Each `case` corresponds to a specific s390 instruction opcode (e.g., `kS390_Abs32`, `kS390_LoadWord64`). This gives us a concrete list of the instructions this scheduler is aware of.

    * **Return Values:**  Most `case` labels return `kNoOpcodeFlags`. This suggests that the majority of the listed instructions don't have special scheduling considerations (at least in terms of the flags this function is concerned with).

    * **`kIsLoadOperation`:** A group of `case` labels (starting with `kS390_LoadWordS8`) returns `kIsLoadOperation`. This indicates that these instructions are memory load operations. This is important for scheduling because load operations often have higher latency and can introduce dependencies.

    * **`kHasSideEffect`:** Another group (starting with `kS390_StoreWord8`) returns `kHasSideEffect`. This indicates instructions that modify memory or have other observable effects (like I/O). These instructions are also crucial for scheduling because their order might be critical for correctness. The inclusion of `kS390_Push` and `kS390_PushFrame` is notable, indicating stack manipulation is considered a side effect. Atomic operations are also flagged here.

    * **`COMMON_ARCH_OPCODE_LIST(CASE)`:** This macro suggests there's a shared list of opcodes, and those are handled elsewhere or have default behavior (hence the `UNREACHABLE()` comment).

    * **`UNREACHABLE()`:** These lines are important. They indicate that all possible `arch_opcode()` values *should* be handled in the `switch`. If execution reaches these lines, it means there's a bug or an unhandled instruction.

5. **Examine the `GetInstructionLatency()` Function:** This function is simpler. It takes an `Instruction` and returns a latency value. The current implementation always returns `1`, with a comment indicating that more sophisticated cost modeling is a future goal. This means the current scheduler treats all instructions as having the same latency for scheduling purposes.

6. **Address the Specific Questions:** Now, systematically answer each part of the prompt.

    * **Functionality:** Summarize the purpose of the file based on the code analysis. Focus on instruction scheduling for s390, identifying instruction properties like load operations and side effects.

    * **`.tq` Extension:**  The code uses `.cc`, not `.tq`, so it's C++, not Torque.

    * **Relationship to JavaScript:** Instruction scheduling is an optimization *performed by the compiler*. It doesn't directly correspond to specific JavaScript code constructs. However, the *result* of this scheduling makes JavaScript run faster. Provide a simple JavaScript example and explain how the scheduler optimizes the underlying machine code.

    * **Code Logic and Assumptions:**  Focus on the `GetTargetInstructionFlags` function. Assume a specific input instruction (e.g., `kS390_Add32`) and trace the execution through the `switch` to determine the output (`kNoOpcodeFlags`). Similarly, do this for a load instruction and a store instruction.

    * **Common Programming Errors:** Instruction scheduling is a compiler-level optimization, so typical *user* programming errors aren't directly related. However, *incorrect* instruction scheduling in the compiler itself could lead to performance bugs or, in rare cases, functional errors. Focus on how seemingly simple code reordering can have unintended consequences if dependencies are not correctly handled. A good example is reordering memory accesses.

7. **Review and Refine:** Read through the entire analysis to ensure clarity, accuracy, and completeness. Make sure the explanations are easy to understand, even for someone who might not be deeply familiar with compiler internals. Ensure the JavaScript example is simple and illustrative.

This structured approach ensures that all aspects of the code are considered and the questions are answered thoroughly and accurately. The key is to start with the big picture and then dive into the details of each function.

根据提供的C++源代码文件 `v8/src/compiler/backend/s390/instruction-scheduler-s390.cc`，我们可以分析出以下功能：

**1. 指令调度支持声明:**

* `bool InstructionScheduler::SchedulerSupported() { return true; }`
  这个函数表明，V8 的指令调度器是支持 s390 架构的。这意味着 V8 可以在编译 JavaScript 代码到 s390 机器码时，对生成的指令进行重新排序，以优化执行效率。

**2. 获取目标指令的标志 (Flags):**

* `int InstructionScheduler::GetTargetInstructionFlags(const Instruction* instr) const`
  这个函数是指令调度器的核心部分。它的作用是根据给定的 `Instruction` 对象（代表一条 s390 架构的指令），返回该指令特定的标志信息。这些标志信息可以帮助调度器更好地理解指令的特性，例如是否为加载操作，是否具有副作用等。

* **指令分类和标志:**  `switch (instr->arch_opcode())` 语句根据指令的 `arch_opcode()` (架构相关的操作码) 对指令进行分类。
    * **`kNoOpcodeFlags`:**  对于大量的算术运算、逻辑运算、位操作、比较操作、类型转换以及一些 SIMD 指令，该函数返回 `kNoOpcodeFlags`。这表示这些指令在指令调度方面没有特殊的标志需要考虑。
    * **`kIsLoadOperation`:**  对于所有以 `kS390_Load...` 开头的指令，例如 `kS390_LoadWordS8`, `kS390_LoadDouble` 等，该函数返回 `kIsLoadOperation`。这表明这些指令是从内存中加载数据的操作。调度器通常会考虑加载指令的延迟，并尽量将不依赖于加载结果的指令安排在加载指令之后执行。
    * **`kHasSideEffect`:** 对于所有以 `kS390_Store...` 开头的指令（例如 `kS390_StoreWord8`, `kS390_StoreDouble`），以及 `kS390_Push`, `kS390_PushFrame` 和原子操作指令，该函数返回 `kHasSideEffect`。这表明这些指令会修改内存状态或者有其他可见的副作用。调度器在安排指令顺序时必须小心处理具有副作用的指令，以保证程序的正确性。

**3. 获取指令延迟 (Latency):**

* `int InstructionScheduler::GetInstructionLatency(const Instruction* instr)`
  这个函数用于获取给定指令的执行延迟。在当前的实现中，它总是返回 `1`，并注释说明 "TODO(all): Add instruction cost modeling."。这意味着目前 V8 对 s390 指令的延迟建模还比较简单，未来可能会加入更精确的指令延迟信息。指令延迟是指令调度器进行优化的重要依据，调度器会尽量减少由于指令延迟导致的处理器流水线停顿。

**关于文件扩展名和 Torque:**

文件以 `.cc` 结尾，这表明它是 **C++ 源代码**文件，而不是 Torque 源代码。Torque 文件的扩展名通常是 `.tq`。

**与 JavaScript 的关系及示例:**

`v8/src/compiler/backend/s390/instruction-scheduler-s390.cc`  直接参与将 JavaScript 代码编译成高效的 s390 机器码的过程。指令调度是一种编译器优化，它对用户编写的 JavaScript 代码是透明的。用户不需要显式地编写针对特定指令调度的代码。

**JavaScript 示例:**

```javascript
function add(a, b) {
  const x = a + 1;
  const y = b + 2;
  return x + y;
}

const result = add(5, 10);
console.log(result);
```

当 V8 编译 `add` 函数时，指令调度器可能会对生成的 s390 机器码指令进行重新排序。例如，假设原始生成的指令顺序如下（这只是一个简化的例子，实际情况更复杂）：

1. 加载 `a` 的值到寄存器 R1
2. 将常量 1 加到 R1
3. 将 R1 的值存储到代表 `x` 的内存位置
4. 加载 `b` 的值到寄存器 R2
5. 将常量 2 加到 R2
6. 将 R2 的值存储到代表 `y` 的内存位置
7. 加载 `x` 的值到寄存器 R3
8. 加载 `y` 的值到寄存器 R4
9. 将 R3 和 R4 的值相加
10. 返回结果

指令调度器可能会发现，步骤 4 和步骤 1-3 之间没有依赖关系，步骤 7 和步骤 8 也是可以并行加载的。因此，它可以将指令重新排序，例如：

1. 加载 `a` 的值到寄存器 R1
2. 将常量 1 加到 R1
3. 加载 `b` 的值到寄存器 R2  // 提前加载，与步骤1-3并行
4. 将 R1 的值存储到代表 `x` 的内存位置
5. 将常量 2 加到 R2
6. 将 R2 的值存储到代表 `y` 的内存位置
7. 加载 `x` 的值到寄存器 R3
8. 加载 `y` 的值到寄存器 R4
9. 将 R3 和 R4 的值相加
10. 返回结果

通过这样的重新排序，可以减少处理器等待数据加载完成的时间，从而提高代码的执行效率。

**代码逻辑推理 (假设输入与输出):**

假设有一个 `Instruction` 对象 `instr`，其 `arch_opcode()` 为 `kS390_Add32`。

* **输入:** `instr`，其中 `instr->arch_opcode() == kS390_Add32`
* **执行 `GetTargetInstructionFlags(instr)`:**
    * `switch (instr->arch_opcode())` 进入 `case kS390_Add32:`
    * 返回 `kNoOpcodeFlags`
* **输出:** `kNoOpcodeFlags`

假设另一个 `Instruction` 对象 `instr2`，其 `arch_opcode()` 为 `kS390_LoadWord64`。

* **输入:** `instr2`，其中 `instr2->arch_opcode() == kS390_LoadWord64`
* **执行 `GetTargetInstructionFlags(instr2)`:**
    * `switch (instr2->arch_opcode())` 进入 `case kS390_LoadWord64:`
    * 返回 `kIsLoadOperation`
* **输出:** `kIsLoadOperation`

假设第三个 `Instruction` 对象 `instr3`，其 `arch_opcode()` 为 `kS390_StoreWord32`。

* **输入:** `instr3`，其中 `instr3->arch_opcode() == kS390_StoreWord32`
* **执行 `GetTargetInstructionFlags(instr3)`:**
    * `switch (instr3->arch_opcode())` 进入 `case kS390_StoreWord32:`
    * 返回 `kHasSideEffect`
* **输出:** `kHasSideEffect`

**涉及用户常见的编程错误:**

指令调度器是编译器内部的优化，它不会直接暴露给用户，因此用户常见的编程错误通常与指令调度器本身无关。然而，理解指令调度可以帮助理解一些性能优化的概念，从而避免一些可能导致性能下降的编程习惯。

一个间接相关的例子是 **不必要的内存访问**:

```javascript
function processData(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    const value = arr[i]; // 每次循环都从内存加载 arr[i]
    sum += value;
  }
  return sum;
}
```

在这个例子中，每次循环都会从内存中加载 `arr[i]` 的值。指令调度器可能会尝试优化加载操作，但如果循环体内部对加载的值有复杂的依赖，优化空间可能会受限。

如果我们将加载的值存储在一个局部变量中，可能会帮助编译器更好地进行优化，包括指令调度：

```javascript
function processDataOptimized(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    const value = arr[i];
    sum += value;
  }
  return sum;
}
```

虽然用户不会直接控制指令调度，但编写更简洁、更符合逻辑的代码，减少不必要的内存访问和依赖，通常有助于编译器生成更高效的机器码。

**总结:**

`v8/src/compiler/backend/s390/instruction-scheduler-s390.cc` 文件的主要功能是为 s390 架构实现指令调度器。它负责判断指令是否为加载操作或具有副作用，并提供指令延迟信息（目前较为简单）。指令调度器是 V8 编译器中优化代码性能的关键组件，它通过重新排列指令执行顺序来减少处理器流水线的停顿，从而提高 JavaScript 代码的执行效率。 该文件是 C++ 源代码，与用户编写的 JavaScript 代码间接相关，用户无需直接关心指令调度，但编写高质量的代码有助于编译器进行更好的优化。

### 提示词
```
这是目录为v8/src/compiler/backend/s390/instruction-scheduler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/s390/instruction-scheduler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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