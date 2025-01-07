Response:
Let's break down the thought process to answer the request about the `instruction-scheduler-arm64.cc` file.

1. **Understand the Core Request:** The user wants to know the functionality of this specific V8 source code file. They also have some specific constraints and questions related to file extensions, JavaScript relevance, logic examples, and common errors.

2. **Initial Analysis of the Code:**

   * **Headers:** The file starts with standard copyright information and includes `"src/compiler/backend/instruction-scheduler.h"`. This immediately tells us this file is part of the V8 compiler, specifically the backend, and deals with instruction scheduling.
   * **Namespace:**  The code is within `v8::internal::compiler`. This reinforces the V8 compiler context.
   * **`InstructionScheduler::SchedulerSupported()`:** This function simply returns `true`. This is a quick indicator that instruction scheduling *is* supported for the ARM64 architecture.
   * **`InstructionScheduler::GetTargetInstructionFlags()`:** This function is a large `switch` statement based on `instr->arch_opcode()`. The `case` labels are all `kArm64...`. This confirms it's specific to the ARM64 architecture and maps instruction opcodes to flags. The flags being returned (`kNoOpcodeFlags`, `kIsLoadOperation`, `kHasSideEffect`) suggest it's categorizing instructions.
   * **`InstructionScheduler::GetInstructionLatency()`:** Another `switch` statement based on `instr->arch_opcode()`. The `return` values are integers. This strongly suggests it's assigning latencies (execution times) to different ARM64 instructions.

3. **Formulate the Core Functionality:** Based on the analysis above, the primary function of this file is to provide ARM64-specific information needed for instruction scheduling within the V8 compiler. This includes:
    * Confirming scheduler support.
    * Determining instruction flags (properties like being a load or having side effects).
    * Estimating the latency of instructions.

4. **Address Specific Constraints and Questions:**

   * **`.tq` Extension:** The request asks about the `.tq` extension. A quick search (or prior knowledge of V8 development) reveals that `.tq` files are related to Torque, V8's internal type system and code generation language. Since this file ends in `.cc`, it's C++, not Torque.

   * **JavaScript Relevance:** Instruction scheduling is an optimization that happens *behind the scenes* during JavaScript execution. It doesn't directly change the *behavior* of JavaScript code, but it affects performance. To illustrate, a simple JavaScript example can be given, and then the explanation can focus on *why* instruction scheduling is important for performance. The key is to connect the concept to the user's domain (JavaScript) without implying this file is directly *writing* JavaScript.

   * **Logic Examples (Input/Output):**  The `GetTargetInstructionFlags` and `GetInstructionLatency` functions are perfect for this. Choose a few representative opcodes as input and then state the corresponding output. For `GetTargetInstructionFlags`, show the opcode and its associated flag. For `GetInstructionLatency`, show the opcode and its latency value. This makes the abstract concept more concrete.

   * **Common Programming Errors:** This requires thinking about what kinds of errors might arise if instruction scheduling is not optimal or if there are dependencies between instructions. A common error related to performance is writing code that leads to pipeline stalls or inefficient instruction ordering. Provide a simple JavaScript example where the order of operations matters for performance (even if the *functional* outcome is the same).

5. **Structure the Answer:** Organize the information logically to address all parts of the request:

   * **Summary of Functionality:** Start with a concise overview of the file's purpose.
   * **Detailed Explanation of Functions:** Describe what each of the key functions (`SchedulerSupported`, `GetTargetInstructionFlags`, `GetInstructionLatency`) does.
   * **File Extension:** Address the `.tq` question directly and confirm it's C++.
   * **JavaScript Relevance and Example:** Explain the connection to JavaScript performance and provide a simple illustrative example.
   * **Logic Examples (Input/Output):**  Present concrete examples for `GetTargetInstructionFlags` and `GetInstructionLatency`.
   * **Common Programming Errors:** Explain how suboptimal code can hinder the benefits of instruction scheduling, and provide an example.

6. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Make sure the examples are easy to understand and that the language is precise. For instance, explicitly state that instruction scheduling is an *optimization* and doesn't change the *functional behavior* of the JavaScript code.

By following these steps, we can generate a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to break down the code, understand its purpose within the larger V8 context, and then connect it to the specific questions asked by the user.
好的，让我们来分析一下 `v8/src/compiler/backend/arm64/instruction-scheduler-arm64.cc` 这个文件。

**功能总结：**

`instruction-scheduler-arm64.cc` 文件的主要功能是为 **ARM64 架构**的处理器提供 **指令调度** 的特定实现。指令调度是编译器后端优化的一个重要环节，它的目标是重新排列指令的执行顺序，以提高处理器的执行效率，例如减少流水线停顿、更好地利用处理器资源等。

更具体地说，这个文件实现了 `InstructionScheduler` 类的特定于 ARM64 架构的方法，用于：

1. **判断是否支持调度：** `SchedulerSupported()` 方法返回 `true`，表明 ARM64 架构是支持指令调度的。
2. **获取目标指令的标志：** `GetTargetInstructionFlags(const Instruction* instr)` 方法根据给定的 `Instruction` 对象（代表一条 ARM64 指令），返回一些与调度相关的标志。这些标志用于描述指令的特性，例如是否为加载操作、是否具有副作用等。
3. **获取指令的延迟：** `GetInstructionLatency(const Instruction* instr)` 方法根据给定的 `Instruction` 对象，返回该指令在 ARM64 架构上的估计执行延迟（以处理器周期为单位）。这个延迟信息对于指令调度器决定如何安排指令顺序至关重要。

**关于文件扩展名 `.tq`：**

你提出的关于 `.tq` 结尾的问题是正确的。如果 `v8/src/compiler/backend/arm64/instruction-scheduler-arm64.cc` 文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是 V8 用于定义运行时内置函数和类型系统的领域特定语言。然而，根据你提供的文件名，该文件以 `.cc` 结尾，这意味着它是一个 **C++ 源代码** 文件。

**与 JavaScript 的功能关系：**

虽然 `instruction-scheduler-arm64.cc` 是一个 C++ 文件，并且处于编译器的后端，但它与 JavaScript 的执行性能息息相关。当 V8 编译 JavaScript 代码时，它会经历多个阶段，最终生成特定于目标架构的机器码。指令调度器在这个过程中起着关键作用，它优化了生成的 ARM64 指令序列，从而使 JavaScript 代码在 ARM64 处理器上运行得更快。

**JavaScript 例子说明：**

以下是一个简单的 JavaScript 例子，虽然这个例子本身不会直接触发指令调度，但指令调度器会在 V8 编译这段代码时发挥作用：

```javascript
function add(a, b, c) {
  const sum1 = a + b;
  const sum2 = sum1 + c;
  return sum2;
}

const result = add(1, 2, 3);
console.log(result); // 输出 6
```

当 V8 编译 `add` 函数时，指令调度器会分析生成的中间表示，并尽可能地重新排列加法指令，以便更有效地利用 ARM64 处理器的执行单元。例如，如果处理器有多个加法器，调度器可能会尝试并行执行独立的加法操作。

**代码逻辑推理（假设输入与输出）：**

假设我们有一个代表 ARM64 加法指令的 `Instruction` 对象 `instr`，例如 `kArm64Add`：

* **对于 `GetTargetInstructionFlags(instr)`：**
    * **假设输入：** `instr` 代表一个 `kArm64Add` 指令。
    * **预期输出：** 根据代码，`kArm64Add` 的 case 返回 `kNoOpcodeFlags`。这意味着该指令没有被标记为特殊的加载操作或具有副作用的操作。

* **对于 `GetInstructionLatency(instr)`：**
    * **假设输入：** `instr` 代表一个简单的 `kArm64Add` 指令（假设没有复杂的寻址模式）。
    * **预期输出：** 根据代码，`kArm64Add` 的 case 会检查寻址模式，如果不是 `kMode_None`，返回 3，否则返回 1。如果是一个简单的加法，预期输出是 `1`。

    * **假设输入：** `instr` 代表一个带有复杂寻址模式的 `kArm64Add` 指令。
    * **预期输出：** 预期输出是 `3`。

**涉及用户常见的编程错误：**

虽然指令调度是编译器后端的工作，用户通常不会直接与之交互，但一些编程模式可能会影响编译器优化的效果，间接地与指令调度相关。

**例子：过度依赖顺序，导致不必要的依赖性**

考虑以下 JavaScript 代码：

```javascript
function processData(data) {
  const step1 = data.map(x => x * 2);
  const step2 = step1.filter(x => x > 10);
  const step3 = step2.reduce((acc, x) => acc + x, 0);
  return step3;
}

const numbers = [1, 2, 3, 4, 5, 6];
const result = processData(numbers);
console.log(result); // 输出 30
```

在这个例子中，`map`、`filter` 和 `reduce` 操作是顺序执行的，后面的步骤依赖于前一步的结果。虽然这种写法在逻辑上很清晰，但在某些情况下，编译器可能难以进行大幅度的并行优化或指令重排。

**潜在问题：** 如果这些步骤之间存在不必要的依赖性，指令调度器可能无法最大化处理器的并行能力。

**改进方向（并非直接与 `instruction-scheduler-arm64.cc` 相关，而是关于如何编写更易于优化的代码）：**

有时，可以通过改变代码结构来减少依赖性，例如：

```javascript
function processDataOptimized(data) {
  return data
    .map(x => x * 2)
    .filter(x => x > 10)
    .reduce((acc, x) => acc + x, 0);
}
```

虽然这两个版本的 JavaScript 代码在语义上是相同的，但编译器在处理后者时可能更容易进行某些优化。

**总结：**

`v8/src/compiler/backend/arm64/instruction-scheduler-arm64.cc` 是 V8 编译器中一个关键的 C++ 文件，它为 ARM64 架构提供了指令调度的具体实现。它通过分析指令的特性（标志）和估计执行延迟来优化生成的机器码，从而提高 JavaScript 在 ARM64 处理器上的运行效率。虽然用户通常不直接与指令调度器交互，但编写出编译器更容易优化的代码仍然很重要。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm64/instruction-scheduler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-scheduler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
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
    case kArm64Add:
    case kArm64Add32:
    case kArm64And:
    case kArm64And32:
    case kArm64Bic:
    case kArm64Bic32:
    case kArm64Clz:
    case kArm64Clz32:
    case kArm64Cmp:
    case kArm64Cmp32:
    case kArm64Cmn:
    case kArm64Cmn32:
    case kArm64Cnt:
    case kArm64Cnt32:
    case kArm64Cnt64:
    case kArm64Tst:
    case kArm64Tst32:
    case kArm64Or:
    case kArm64Or32:
    case kArm64Orn:
    case kArm64Orn32:
    case kArm64Eor:
    case kArm64Eor32:
    case kArm64Eon:
    case kArm64Eon32:
    case kArm64Sub:
    case kArm64Sub32:
    case kArm64Mul:
    case kArm64Mul32:
    case kArm64Smulh:
    case kArm64Smull:
    case kArm64Smull2:
    case kArm64Umulh:
    case kArm64Umull:
    case kArm64Umull2:
    case kArm64Madd:
    case kArm64Madd32:
    case kArm64Msub:
    case kArm64Msub32:
    case kArm64Mneg:
    case kArm64Mneg32:
    case kArm64Idiv:
    case kArm64Idiv32:
    case kArm64Udiv:
    case kArm64Udiv32:
    case kArm64Imod:
    case kArm64Imod32:
    case kArm64Umod:
    case kArm64Umod32:
    case kArm64Not:
    case kArm64Not32:
    case kArm64Lsl:
    case kArm64Lsl32:
    case kArm64Lsr:
    case kArm64Lsr32:
    case kArm64Asr:
    case kArm64Asr32:
    case kArm64Ror:
    case kArm64Ror32:
    case kArm64Mov32:
    case kArm64Sxtb:
    case kArm64Sxtb32:
    case kArm64Sxth:
    case kArm64Sxth32:
    case kArm64Sxtw:
    case kArm64Sbfx:
    case kArm64Sbfx32:
    case kArm64Ubfx:
    case kArm64Ubfx32:
    case kArm64Ubfiz32:
    case kArm64Sbfiz:
    case kArm64Bfi:
    case kArm64Rbit:
    case kArm64Rbit32:
    case kArm64Rev:
    case kArm64Rev32:
    case kArm64Float16RoundDown:
    case kArm64Float16RoundTiesEven:
    case kArm64Float16RoundTruncate:
    case kArm64Float16RoundUp:
    case kArm64Float32Cmp:
    case kArm64Float32Add:
    case kArm64Float32Sub:
    case kArm64Float32Mul:
    case kArm64Float32Div:
    case kArm64Float32Abs:
    case kArm64Float32Abd:
    case kArm64Float32Neg:
    case kArm64Float32Sqrt:
    case kArm64Float32Fnmul:
    case kArm64Float32RoundDown:
    case kArm64Float32Max:
    case kArm64Float32Min:
    case kArm64Float64Cmp:
    case kArm64Float64Add:
    case kArm64Float64Sub:
    case kArm64Float64Mul:
    case kArm64Float64Div:
    case kArm64Float64Max:
    case kArm64Float64Min:
    case kArm64Float64Abs:
    case kArm64Float64Abd:
    case kArm64Float64Neg:
    case kArm64Float64Sqrt:
    case kArm64Float64Fnmul:
    case kArm64Float64RoundDown:
    case kArm64Float64RoundTiesAway:
    case kArm64Float64RoundTruncate:
    case kArm64Float64RoundTiesEven:
    case kArm64Float64RoundUp:
    case kArm64Float32RoundTiesEven:
    case kArm64Float32RoundTruncate:
    case kArm64Float32RoundUp:
    case kArm64Float32ToFloat64:
    case kArm64Float64ToFloat32:
    case kArm64Float64ToFloat16RawBits:
    case kArm64Float32ToInt32:
    case kArm64Float64ToInt32:
    case kArm64Float32ToUint32:
    case kArm64Float64ToUint32:
    case kArm64Float32ToInt64:
    case kArm64Float64ToInt64:
    case kArm64Float32ToUint64:
    case kArm64Float64ToUint64:
    case kArm64Int32ToFloat32:
    case kArm64Int32ToFloat64:
    case kArm64Int64ToFloat32:
    case kArm64Int64ToFloat64:
    case kArm64Uint32ToFloat32:
    case kArm64Uint32ToFloat64:
    case kArm64Uint64ToFloat32:
    case kArm64Uint64ToFloat64:
    case kArm64Float64ExtractLowWord32:
    case kArm64Float64ExtractHighWord32:
    case kArm64Float64InsertLowWord32:
    case kArm64Float64InsertHighWord32:
    case kArm64Float64Mod:
    case kArm64Float64MoveU64:
    case kArm64U64MoveFloat64:
    case kArm64Float64SilenceNaN:
#if V8_ENABLE_WEBASSEMBLY
    case kArm64Sadalp:
    case kArm64Saddlp:
    case kArm64Uadalp:
    case kArm64Uaddlp:
    case kArm64Smlal:
    case kArm64Smlal2:
    case kArm64Umlal:
    case kArm64Umlal2:
    case kArm64FAdd:
    case kArm64FSub:
    case kArm64FMul:
    case kArm64FMulElement:
    case kArm64FDiv:
    case kArm64FMin:
    case kArm64FMax:
    case kArm64FEq:
    case kArm64FNe:
    case kArm64FLt:
    case kArm64FLe:
    case kArm64FGt:
    case kArm64FGe:
    case kArm64FExtractLane:
    case kArm64FReplaceLane:
    case kArm64FSplat:
    case kArm64FAbs:
    case kArm64FNeg:
    case kArm64FSqrt:
    case kArm64F64x2Qfma:
    case kArm64F64x2Qfms:
    case kArm64F64x2Pmin:
    case kArm64F64x2Pmax:
    case kArm64F64x2ConvertLowI32x4S:
    case kArm64F64x2ConvertLowI32x4U:
    case kArm64F64x2PromoteLowF32x4:
    case kArm64F32x4SConvertI32x4:
    case kArm64F32x4UConvertI32x4:
    case kArm64F32x4Qfma:
    case kArm64F32x4Qfms:
    case kArm64F32x4Pmin:
    case kArm64F32x4Pmax:
    case kArm64F32x4DemoteF64x2Zero:
    case kArm64F16x8Pmin:
    case kArm64F16x8Pmax:
    case kArm64F32x4PromoteLowF16x8:
    case kArm64F16x8SConvertI16x8:
    case kArm64F16x8UConvertI16x8:
    case kArm64F16x8DemoteF32x4Zero:
    case kArm64F16x8DemoteF64x2Zero:
    case kArm64I16x8SConvertF16x8:
    case kArm64I16x8UConvertF16x8:
    case kArm64F16x8Qfma:
    case kArm64F16x8Qfms:
    case kArm64IExtractLane:
    case kArm64IReplaceLane:
    case kArm64ISplat:
    case kArm64IAbs:
    case kArm64INeg:
    case kArm64Mla:
    case kArm64Mls:
    case kArm64I64x2Shl:
    case kArm64I64x2ShrS:
    case kArm64I64x2Mul:
    case kArm64I64x2ShrU:
    case kArm64I64x2BitMask:
    case kArm64I32x4SConvertF32x4:
    case kArm64Sxtl:
    case kArm64Sxtl2:
    case kArm64Uxtl:
    case kArm64Uxtl2:
    case kArm64I32x4Shl:
    case kArm64I32x4ShrS:
    case kArm64I32x4Mul:
    case kArm64I32x4UConvertF32x4:
    case kArm64I32x4ShrU:
    case kArm64I32x4BitMask:
    case kArm64I32x4DotI16x8S:
    case kArm64I16x8DotI8x16S:
    case kArm64I32x4DotI8x16AddS:
    case kArm64I8x16Addv:
    case kArm64I16x8Addv:
    case kArm64I32x4Addv:
    case kArm64I64x2AddPair:
    case kArm64F32x4AddReducePairwise:
    case kArm64F64x2AddPair:
    case kArm64I32x4TruncSatF64x2SZero:
    case kArm64I32x4TruncSatF64x2UZero:
    case kArm64IExtractLaneU:
    case kArm64IExtractLaneS:
    case kArm64I16x8Shl:
    case kArm64I16x8ShrS:
    case kArm64I16x8SConvertI32x4:
    case kArm64I16x8Mul:
    case kArm64I16x8ShrU:
    case kArm64I16x8UConvertI32x4:
    case kArm64I16x8Q15MulRSatS:
    case kArm64I16x8BitMask:
    case kArm64I8x16Shl:
    case kArm64I8x16ShrS:
    case kArm64I8x16SConvertI16x8:
    case kArm64I8x16UConvertI16x8:
    case kArm64I8x16ShrU:
    case kArm64I8x16BitMask:
    case kArm64S128Const:
    case kArm64S128Dup:
    case kArm64S128And:
    case kArm64S128Or:
    case kArm64S128Xor:
    case kArm64S128Not:
    case kArm64S128Select:
    case kArm64S128AndNot:
    case kArm64Ssra:
    case kArm64Usra:
    case kArm64S32x4ZipLeft:
    case kArm64S32x4ZipRight:
    case kArm64S32x4UnzipLeft:
    case kArm64S32x4UnzipRight:
    case kArm64S32x4TransposeLeft:
    case kArm64S32x4TransposeRight:
    case kArm64S32x4OneLaneSwizzle:
    case kArm64S32x4Shuffle:
    case kArm64S16x8ZipLeft:
    case kArm64S16x8ZipRight:
    case kArm64S16x8UnzipLeft:
    case kArm64S16x8UnzipRight:
    case kArm64S16x8TransposeLeft:
    case kArm64S16x8TransposeRight:
    case kArm64S8x16ZipLeft:
    case kArm64S8x16ZipRight:
    case kArm64S8x16UnzipLeft:
    case kArm64S8x16UnzipRight:
    case kArm64S8x16TransposeLeft:
    case kArm64S8x16TransposeRight:
    case kArm64S8x16Concat:
    case kArm64I8x16Swizzle:
    case kArm64I8x16Shuffle:
    case kArm64S32x4Reverse:
    case kArm64S32x2Reverse:
    case kArm64S16x4Reverse:
    case kArm64S16x2Reverse:
    case kArm64S8x8Reverse:
    case kArm64S8x4Reverse:
    case kArm64S8x2Reverse:
    case kArm64V128AnyTrue:
    case kArm64I64x2AllTrue:
    case kArm64I32x4AllTrue:
    case kArm64I16x8AllTrue:
    case kArm64I8x16AllTrue:
    case kArm64RoundingAverageU:
    case kArm64IAdd:
    case kArm64ISub:
    case kArm64IEq:
    case kArm64INe:
    case kArm64IGtS:
    case kArm64IGeS:
    case kArm64ILtS:
    case kArm64ILeS:
    case kArm64IMinS:
    case kArm64IMaxS:
    case kArm64IMinU:
    case kArm64IMaxU:
    case kArm64IGtU:
    case kArm64IGeU:
    case kArm64IAddSatS:
    case kArm64ISubSatS:
    case kArm64IAddSatU:
    case kArm64ISubSatU:
#endif  // V8_ENABLE_WEBASSEMBLY
    case kArm64TestAndBranch32:
    case kArm64TestAndBranch:
    case kArm64CompareAndBranch32:
    case kArm64CompareAndBranch:
      return kNoOpcodeFlags;

    case kArm64LdrH:
    case kArm64LdrS:
    case kArm64LdrD:
    case kArm64LdrQ:
    case kArm64Ldrb:
    case kArm64Ldrsb:
    case kArm64LdrsbW:
    case kArm64Ldrh:
    case kArm64Ldrsh:
    case kArm64LdrshW:
    case kArm64Ldrsw:
    case kArm64LdrW:
    case kArm64Ldr:
    case kArm64LdrDecompressTaggedSigned:
    case kArm64LdrDecompressTagged:
    case kArm64LdrDecompressProtected:
    case kArm64LdarDecompressTaggedSigned:
    case kArm64LdarDecompressTagged:
    case kArm64LdrDecodeSandboxedPointer:
    case kArm64Peek:
#if V8_ENABLE_WEBASSEMBLY
    case kArm64LoadSplat:
    case kArm64LoadLane:
    case kArm64S128Load8x8S:
    case kArm64S128Load8x8U:
    case kArm64S128Load16x4S:
    case kArm64S128Load16x4U:
    case kArm64S128Load32x2S:
    case kArm64S128Load32x2U:
#endif  // V8_ENABLE_WEBASSEMBLY
      return kIsLoadOperation;

    case kArm64Claim:
    case kArm64Poke:
    case kArm64PokePair:
    case kArm64StrH:
    case kArm64StrS:
    case kArm64StrD:
    case kArm64StrQ:
    case kArm64Strb:
    case kArm64Strh:
    case kArm64StrW:
    case kArm64StrWPair:
    case kArm64Str:
    case kArm64StrPair:
    case kArm64StrCompressTagged:
    case kArm64StlrCompressTagged:
    case kArm64StrIndirectPointer:
    case kArm64StrEncodeSandboxedPointer:
    case kArm64DmbIsh:
    case kArm64DsbIsb:
#if V8_ENABLE_WEBASSEMBLY
    case kArm64StoreLane:
#endif  // V8_ENABLE_WEBASSEMBLY
      return kHasSideEffect;

    case kArm64Word64AtomicLoadUint64:
      return kIsLoadOperation;

    case kArm64Word64AtomicStoreWord64:
    case kArm64Word64AtomicAddUint64:
    case kArm64Word64AtomicSubUint64:
    case kArm64Word64AtomicAndUint64:
    case kArm64Word64AtomicOrUint64:
    case kArm64Word64AtomicXorUint64:
    case kArm64Word64AtomicExchangeUint64:
    case kArm64Word64AtomicCompareExchangeUint64:
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
  // Basic latency modeling for arm64 instructions. They have been determined
  // in an empirical way.
  switch (instr->arch_opcode()) {
    case kArm64Add:
    case kArm64Add32:
    case kArm64And:
    case kArm64And32:
    case kArm64Bic:
    case kArm64Bic32:
    case kArm64Cmn:
    case kArm64Cmn32:
    case kArm64Cmp:
    case kArm64Cmp32:
    case kArm64Eon:
    case kArm64Eon32:
    case kArm64Eor:
    case kArm64Eor32:
    case kArm64Not:
    case kArm64Not32:
    case kArm64Or:
    case kArm64Or32:
    case kArm64Orn:
    case kArm64Orn32:
    case kArm64Sub:
    case kArm64Sub32:
    case kArm64Tst:
    case kArm64Tst32:
      if (instr->addressing_mode() != kMode_None) {
        return 3;
      } else {
        return 1;
      }

    case kArm64Clz:
    case kArm64Clz32:
    case kArm64Sbfx:
    case kArm64Sbfx32:
    case kArm64Sxtb32:
    case kArm64Sxth32:
    case kArm64Sxtw:
    case kArm64Ubfiz32:
    case kArm64Sbfiz:
    case kArm64Ubfx:
    case kArm64Ubfx32:
      return 1;

    case kArm64Lsl:
    case kArm64Lsl32:
    case kArm64Lsr:
    case kArm64Lsr32:
    case kArm64Asr:
    case kArm64Asr32:
    case kArm64Ror:
    case kArm64Ror32:
      return 1;

    case kArm64LdrDecompressTaggedSigned:
    case kArm64LdrDecompressTagged:
    case kArm64LdrDecompressProtected:
    case kArm64Ldr:
    case kArm64LdrD:
    case kArm64LdrS:
    case kArm64LdrW:
    case kArm64Ldrb:
    case kArm64Ldrh:
    case kArm64Ldrsb:
    case kArm64Ldrsh:
    case kArm64Ldrsw:
      return 11;

    case kArm64Str:
    case kArm64StrD:
    case kArm64StrS:
    case kArm64StrW:
    case kArm64Strb:
    case kArm64Strh:
      return 1;

    case kArm64Madd32:
    case kArm64Mneg32:
    case kArm64Msub32:
    case kArm64Mul32:
      return 3;

    case kArm64Madd:
    case kArm64Mneg:
    case kArm64Msub:
    case kArm64Mul:
      return 5;

    case kArm64Idiv32:
    case kArm64Udiv32:
      return 12;

    case kArm64Idiv:
    case kArm64Udiv:
      return 20;

    case kArm64Float32Add:
    case kArm64Float32Sub:
    case kArm64Float64Add:
    case kArm64Float64Sub:
      return 5;

    case kArm64Float32Abs:
    case kArm64Float32Cmp:
    case kArm64Float32Neg:
    case kArm64Float64Abs:
    case kArm64Float64Cmp:
    case kArm64Float64Neg:
      return 3;

    case kArm64Float32Div:
    case kArm64Float32Sqrt:
      return 12;

    case kArm64Float64Div:
    case kArm64Float64Sqrt:
      return 19;

    case kArm64Float32RoundDown:
    case kArm64Float32RoundTiesEven:
    case kArm64Float32RoundTruncate:
    case kArm64Float32RoundUp:
    case kArm64Float64RoundDown:
    case kArm64Float64RoundTiesAway:
    case kArm64Float64RoundTiesEven:
    case kArm64Float64RoundTruncate:
    case kArm64Float64RoundUp:
      return 5;

    case kArm64Float32ToFloat64:
    case kArm64Float64ToFloat32:
    case kArm64Float64ToFloat16RawBits:
    case kArm64Float64ToInt32:
    case kArm64Float64ToUint32:
    case kArm64Float32ToInt64:
    case kArm64Float64ToInt64:
    case kArm64Float32ToUint64:
    case kArm64Float64ToUint64:
    case kArm64Int32ToFloat64:
    case kArm64Int64ToFloat32:
    case kArm64Int64ToFloat64:
    case kArm64Uint32ToFloat64:
    case kArm64Uint64ToFloat32:
    case kArm64Uint64ToFloat64:
      return 5;

    default:
      return 2;
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```