Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Goal:**

The request asks for the "functionality" of the code, along with specific checks related to file extensions, JavaScript relevance, logic inference, and common programming errors. This means we need to analyze the code's purpose within the V8 project and its potential interactions with JavaScript.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for recognizable keywords and structures. I see:

* `#include`: Indicates this is C++ code and includes header files for logging, instruction codes, instruction scheduling, and instructions themselves. This strongly suggests the code is involved in the compilation process within V8.
* `namespace v8`, `namespace internal`, `namespace compiler`:  Confirms this is part of the V8 compiler infrastructure.
* `InstructionScheduler`: This is the central class, and its name immediately suggests it's responsible for scheduling instructions.
* `SchedulerSupported()`: A simple function returning `true`, hinting at the availability of the scheduler for the IA-32 architecture.
* `GetTargetInstructionFlags()`:  A key function with a large `switch` statement. This is likely mapping IA-32 opcodes to certain flags.
* `GetInstructionLatency()`: Another `switch` statement, this time mapping opcodes to numerical values. This suggests modeling the execution time of instructions.
* `case kIA32...`:  Numerous cases within the `switch` statements clearly point to IA-32 specific instructions.
* `kIsLoadOperation`, `kHasSideEffect`, `kMayNeedDeoptOrTrapCheck`: These constants are used as return values in `GetTargetInstructionFlags()`, suggesting they represent properties of the instructions.

**3. Deductions about Functionality:**

Based on the keywords and structure, I can deduce the primary function:

* **Instruction Scheduling for IA-32:** The filename and the class name make this the most obvious conclusion. The code is specific to the IA-32 (x86) architecture.
* **Instruction Properties:** `GetTargetInstructionFlags()` is used to determine properties of each IA-32 instruction, such as whether it's a load operation or has side effects. These properties are crucial for the scheduler to make informed decisions.
* **Latency Modeling:** `GetInstructionLatency()` provides estimated execution times (latencies) for different IA-32 instructions. This information helps the scheduler optimize the order of instructions to minimize execution time.

**4. Addressing Specific Requirements:**

* **File Extension (.tq):** The code is clearly C++, as indicated by `#include`. Therefore, it's not a Torque file.
* **JavaScript Relevance:** Instruction scheduling is a core part of the JavaScript compilation process. The V8 compiler takes JavaScript code and translates it into machine code (in this case, IA-32). Instruction scheduling optimizes the order of these machine code instructions. A simple example of JavaScript that would eventually lead to these IA-32 instructions would be any arithmetic operation or memory access.
* **Logic Inference (Input/Output for `GetTargetInstructionFlags`):** To illustrate the logic, I need to pick a few cases from the `switch` statement. For example:
    * **Input:** `instr` with `arch_opcode() == kIA32Add`
    * **Output:** `kIsLoadOperation | kHasSideEffect` (assuming `instr->addressing_mode() != kMode_None`)
    * **Input:** `instr` with `arch_opcode() == kIA32Push`
    * **Output:** `kHasSideEffect`
* **Logic Inference (Input/Output for `GetInstructionLatency`):**  Similarly, I can pick cases:
    * **Input:** `instr` with `arch_opcode() == kFloat64Mul`
    * **Output:** `5`
    * **Input:** `instr` with `arch_opcode() == kIA32Idiv`
    * **Output:** `33`
* **Common Programming Errors (Indirectly related):** While this specific code doesn't *directly* cause user programming errors, understanding instruction scheduling can help explain performance issues. For example, seemingly simple JavaScript code might result in a sequence of instructions where poor scheduling leads to pipeline stalls and slower execution. This isn't a *direct* error in the JavaScript code but a consequence of how it's compiled.

**5. Structuring the Answer:**

Finally, I organize the findings into a clear and structured answer, addressing each point in the request. I use headings and bullet points for better readability. I provide the JavaScript example and the input/output examples as requested. I also clarify the connection to potential performance issues (though not direct programming errors).
This C++ source code file, `instruction-scheduler-ia32.cc`, located within the V8 JavaScript engine's compiler backend for the IA-32 architecture, plays a crucial role in **optimizing the execution speed of generated machine code**. Specifically, it implements the **instruction scheduling** phase for IA-32 instructions.

Here's a breakdown of its functionalities:

**1. Determining Scheduler Support:**

* The function `SchedulerSupported()` simply returns `true`. This indicates that instruction scheduling is supported for the IA-32 architecture within V8.

**2. Classifying Instructions and Their Properties (`GetTargetInstructionFlags`):**

* The core functionality lies in the `GetTargetInstructionFlags()` method. This method takes an `Instruction` object as input and returns a set of flags (an integer) that describe important characteristics of that instruction for scheduling purposes.
* It uses a large `switch` statement based on the `arch_opcode()` (architecture-specific opcode) of the instruction.
* For various IA-32 instructions, it determines and returns flags like:
    * `kIsLoadOperation`:  Indicates if the instruction reads data from memory.
    * `kHasSideEffect`:  Indicates if the instruction modifies the processor state beyond just producing a result (e.g., writing to memory, setting flags).
    * `kMayNeedDeoptOrTrapCheck`: Indicates instructions that might need deoptimization or trap checks (important for handling exceptions and dynamic code optimization).
    * `kNoOpcodeFlags`:  Indicates the instruction doesn't have any special flags for scheduling when the addressing mode is none.
* This information is vital for the instruction scheduler to understand the dependencies between instructions and potential hazards (e.g., reading from a memory location before it's written to).

**3. Estimating Instruction Latency (`GetInstructionLatency`):**

* The `GetInstructionLatency()` method estimates the execution time (latency) of different IA-32 instructions.
* It uses another `switch` statement based on the `arch_opcode()`.
* For various instructions (especially floating-point and division operations which are typically slower), it returns an integer representing the estimated number of cycles the instruction takes to execute.
* This latency information is used by the scheduler to prioritize instructions that take longer, potentially scheduling other independent instructions while waiting for a long-latency instruction to complete.

**If `v8/src/compiler/backend/ia32/instruction-scheduler-ia32.cc` ended with `.tq`:**

It would be a **V8 Torque source code file**. Torque is V8's domain-specific language for writing compiler intrinsics and runtime functions. Torque code is statically typed and generates highly optimized C++ code. Since the given file ends with `.cc`, it's standard C++.

**Relationship to JavaScript (with examples):**

This code is deeply connected to JavaScript performance. When V8 compiles JavaScript code, it goes through several stages, including generating machine code for the target architecture (IA-32 in this case). The instruction scheduler, using the information provided by this file, rearranges the order of these IA-32 instructions to improve execution speed.

Here's a simplified conceptual example in JavaScript:

```javascript
function addMultiply(a, b, c) {
  const sum = a + b;
  const product = sum * c;
  return product;
}

const result = addMultiply(5, 10, 2);
console.log(result); // Output: 30
```

When V8 compiles this JavaScript function for IA-32, it will generate a sequence of IA-32 instructions. The instruction scheduler, guided by `instruction-scheduler-ia32.cc`, might reorder these instructions. For instance, if the multiplication operation (`IMUL`) has a higher latency than the addition (`ADD`), the scheduler might try to schedule an independent instruction between them to avoid the processor idling while waiting for the multiplication to finish.

**Code Logic Inference (Hypothetical Input and Output):**

**For `GetTargetInstructionFlags`:**

* **Hypothetical Input:** An `Instruction` object where `instr->arch_opcode()` is `kIA32Add` and `instr->addressing_mode()` is not `kMode_None`.
* **Hypothetical Output:** `kIsLoadOperation | kHasSideEffect` (because `kIA32Add` is in the list and the addressing mode implies potential memory access).

* **Hypothetical Input:** An `Instruction` object where `instr->arch_opcode()` is `kIA32Push`.
* **Hypothetical Output:** `kHasSideEffect` (because `kIA32Push` modifies the stack pointer).

**For `GetInstructionLatency`:**

* **Hypothetical Input:** An `Instruction` object where `instr->arch_opcode()` is `kFloat64Mul`.
* **Hypothetical Output:** `5` (representing an estimated latency of 5 cycles for a double-precision floating-point multiplication).

* **Hypothetical Input:** An `Instruction` object where `instr->arch_opcode()` is `kIA32Idiv`.
* **Hypothetical Output:** `33` (representing a significantly higher latency for integer division).

**User-Common Programming Errors (Indirectly Related):**

While this specific code doesn't directly *cause* user programming errors, understanding instruction scheduling can help explain why certain JavaScript code patterns might perform better than others, even if they achieve the same result.

* **Example:** Performing a complex calculation inside a tight loop where intermediate results are immediately used. The instruction scheduler tries to optimize, but dependencies might limit its effectiveness.

```javascript
// Less performant due to potential data dependencies slowing down scheduling
function processData(data) {
  for (let i = 0; i < data.length; i++) {
    const step1 = data[i] * 2;
    const step2 = step1 + 5;
    const step3 = Math.sqrt(step2);
    // ... more dependent calculations using step3
    console.log(step3);
  }
}
```

* **Optimization Consideration (though not a direct error):** In some cases, breaking down complex calculations or introducing temporary variables might give the instruction scheduler more opportunities to find independent instructions to execute in parallel. However, this is a micro-optimization and might not always be beneficial.

**In summary, `instruction-scheduler-ia32.cc` is a vital component of V8's IA-32 code generation pipeline. It provides the necessary information about instruction properties and latencies that allows the instruction scheduler to effectively rearrange instructions for better performance, ultimately leading to faster execution of JavaScript code on IA-32 architectures.**

### 提示词
```
这是目录为v8/src/compiler/backend/ia32/instruction-scheduler-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/instruction-scheduler-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/backend/instruction-scheduler.h"
#include "src/compiler/backend/instruction.h"

namespace v8 {
namespace internal {
namespace compiler {

bool InstructionScheduler::SchedulerSupported() { return true; }

int InstructionScheduler::GetTargetInstructionFlags(
    const Instruction* instr) const {
  switch (instr->arch_opcode()) {
    case kIA32Add:
    case kIA32And:
    case kIA32Cmp:
    case kIA32Cmp16:
    case kIA32Cmp8:
    case kIA32Test:
    case kIA32Test16:
    case kIA32Test8:
    case kIA32Or:
    case kIA32Xor:
    case kIA32Sub:
    case kIA32Imul:
    case kIA32ImulHigh:
    case kIA32UmulHigh:
    case kIA32Not:
    case kIA32Neg:
    case kIA32Shl:
    case kIA32Shr:
    case kIA32Sar:
    case kIA32AddPair:
    case kIA32SubPair:
    case kIA32MulPair:
    case kIA32ShlPair:
    case kIA32ShrPair:
    case kIA32SarPair:
    case kIA32Rol:
    case kIA32Ror:
    case kIA32Lzcnt:
    case kIA32Tzcnt:
    case kIA32Popcnt:
    case kIA32Bswap:
    case kIA32Lea:
    case kIA32Float32Cmp:
    case kIA32Float32Sqrt:
    case kIA32Float32Round:
    case kIA32Float64Cmp:
    case kIA32Float64Mod:
    case kIA32Float32Max:
    case kIA32Float64Max:
    case kIA32Float32Min:
    case kIA32Float64Min:
    case kIA32Float64Sqrt:
    case kIA32Float64Round:
    case kIA32Float32ToFloat64:
    case kIA32Float64ToFloat32:
    case kIA32Float32ToInt32:
    case kIA32Float32ToUint32:
    case kIA32Float64ToInt32:
    case kIA32Float64ToUint32:
    case kSSEInt32ToFloat32:
    case kIA32Uint32ToFloat32:
    case kSSEInt32ToFloat64:
    case kIA32Uint32ToFloat64:
    case kIA32Float64ExtractLowWord32:
    case kIA32Float64ExtractHighWord32:
    case kIA32Float64InsertLowWord32:
    case kIA32Float64InsertHighWord32:
    case kIA32Float64FromWord32Pair:
    case kIA32Float64LoadLowWord32:
    case kIA32Float64SilenceNaN:
    case kFloat32Add:
    case kFloat32Sub:
    case kFloat64Add:
    case kFloat64Sub:
    case kFloat32Mul:
    case kFloat32Div:
    case kFloat64Mul:
    case kFloat64Div:
    case kFloat64Abs:
    case kFloat64Neg:
    case kFloat32Abs:
    case kFloat32Neg:
    case kIA32BitcastFI:
    case kIA32BitcastIF:
    case kIA32Blendvpd:
    case kIA32Blendvps:
    case kIA32Pblendvb:
    case kIA32Cvttps2dq:
    case kIA32Cvttpd2dq:
    case kIA32I32x4TruncF32x4U:
    case kIA32I32x4TruncF64x2UZero:
    case kIA32F64x2Splat:
    case kIA32F64x2ExtractLane:
    case kIA32F64x2ReplaceLane:
    case kIA32F64x2Sqrt:
    case kIA32F64x2Add:
    case kIA32F64x2Sub:
    case kIA32F64x2Mul:
    case kIA32F64x2Div:
    case kIA32F64x2Min:
    case kIA32F64x2Max:
    case kIA32F64x2Eq:
    case kIA32F64x2Ne:
    case kIA32F64x2Lt:
    case kIA32F64x2Le:
    case kIA32F64x2Qfma:
    case kIA32F64x2Qfms:
    case kIA32Minpd:
    case kIA32Maxpd:
    case kIA32F64x2Round:
    case kIA32F64x2ConvertLowI32x4S:
    case kIA32F64x2ConvertLowI32x4U:
    case kIA32F64x2PromoteLowF32x4:
    case kIA32I64x2SplatI32Pair:
    case kIA32I64x2ReplaceLaneI32Pair:
    case kIA32I64x2Abs:
    case kIA32I64x2Neg:
    case kIA32I64x2Shl:
    case kIA32I64x2ShrS:
    case kIA32I64x2Add:
    case kIA32I64x2Sub:
    case kIA32I64x2Mul:
    case kIA32I64x2ShrU:
    case kIA32I64x2BitMask:
    case kIA32I64x2Eq:
    case kIA32I64x2Ne:
    case kIA32I64x2GtS:
    case kIA32I64x2GeS:
    case kIA32I64x2ExtMulLowI32x4S:
    case kIA32I64x2ExtMulHighI32x4S:
    case kIA32I64x2ExtMulLowI32x4U:
    case kIA32I64x2ExtMulHighI32x4U:
    case kIA32I64x2SConvertI32x4Low:
    case kIA32I64x2SConvertI32x4High:
    case kIA32I64x2UConvertI32x4Low:
    case kIA32I64x2UConvertI32x4High:
    case kIA32F32x4Splat:
    case kIA32F32x4ExtractLane:
    case kIA32Insertps:
    case kIA32F32x4SConvertI32x4:
    case kIA32F32x4UConvertI32x4:
    case kIA32F32x4Sqrt:
    case kIA32F32x4Add:
    case kIA32F32x4Sub:
    case kIA32F32x4Mul:
    case kIA32F32x4Div:
    case kIA32F32x4Min:
    case kIA32F32x4Max:
    case kIA32F32x4Eq:
    case kIA32F32x4Ne:
    case kIA32F32x4Lt:
    case kIA32F32x4Le:
    case kIA32F32x4Qfma:
    case kIA32F32x4Qfms:
    case kIA32Minps:
    case kIA32Maxps:
    case kIA32F32x4Round:
    case kIA32F32x4DemoteF64x2Zero:
    case kIA32I32x4Splat:
    case kIA32I32x4ExtractLane:
    case kIA32I32x4SConvertF32x4:
    case kIA32I32x4SConvertI16x8Low:
    case kIA32I32x4SConvertI16x8High:
    case kIA32I32x4Neg:
    case kIA32I32x4Shl:
    case kIA32I32x4ShrS:
    case kIA32I32x4Add:
    case kIA32I32x4Sub:
    case kIA32I32x4Mul:
    case kIA32I32x4MinS:
    case kIA32I32x4MaxS:
    case kIA32I32x4Eq:
    case kIA32I32x4Ne:
    case kIA32I32x4GtS:
    case kIA32I32x4GeS:
    case kSSEI32x4UConvertF32x4:
    case kAVXI32x4UConvertF32x4:
    case kIA32I32x4UConvertI16x8Low:
    case kIA32I32x4UConvertI16x8High:
    case kIA32I32x4ShrU:
    case kIA32I32x4MinU:
    case kIA32I32x4MaxU:
    case kSSEI32x4GtU:
    case kAVXI32x4GtU:
    case kSSEI32x4GeU:
    case kAVXI32x4GeU:
    case kIA32I32x4Abs:
    case kIA32I32x4BitMask:
    case kIA32I32x4DotI16x8S:
    case kIA32I32x4DotI8x16I7x16AddS:
    case kIA32I32x4ExtMulLowI16x8S:
    case kIA32I32x4ExtMulHighI16x8S:
    case kIA32I32x4ExtMulLowI16x8U:
    case kIA32I32x4ExtMulHighI16x8U:
    case kIA32I32x4ExtAddPairwiseI16x8S:
    case kIA32I32x4ExtAddPairwiseI16x8U:
    case kIA32I32x4TruncSatF64x2SZero:
    case kIA32I32x4TruncSatF64x2UZero:
    case kIA32I16x8Splat:
    case kIA32I16x8ExtractLaneS:
    case kIA32I16x8SConvertI8x16Low:
    case kIA32I16x8SConvertI8x16High:
    case kIA32I16x8Neg:
    case kIA32I16x8Shl:
    case kIA32I16x8ShrS:
    case kIA32I16x8SConvertI32x4:
    case kIA32I16x8Add:
    case kIA32I16x8AddSatS:
    case kIA32I16x8Sub:
    case kIA32I16x8SubSatS:
    case kIA32I16x8Mul:
    case kIA32I16x8MinS:
    case kIA32I16x8MaxS:
    case kIA32I16x8Eq:
    case kSSEI16x8Ne:
    case kAVXI16x8Ne:
    case kIA32I16x8GtS:
    case kSSEI16x8GeS:
    case kAVXI16x8GeS:
    case kIA32I16x8UConvertI8x16Low:
    case kIA32I16x8UConvertI8x16High:
    case kIA32I16x8ShrU:
    case kIA32I16x8UConvertI32x4:
    case kIA32I16x8AddSatU:
    case kIA32I16x8SubSatU:
    case kIA32I16x8MinU:
    case kIA32I16x8MaxU:
    case kSSEI16x8GtU:
    case kAVXI16x8GtU:
    case kSSEI16x8GeU:
    case kAVXI16x8GeU:
    case kIA32I16x8RoundingAverageU:
    case kIA32I16x8Abs:
    case kIA32I16x8BitMask:
    case kIA32I16x8ExtMulLowI8x16S:
    case kIA32I16x8ExtMulHighI8x16S:
    case kIA32I16x8ExtMulLowI8x16U:
    case kIA32I16x8ExtMulHighI8x16U:
    case kIA32I16x8ExtAddPairwiseI8x16S:
    case kIA32I16x8ExtAddPairwiseI8x16U:
    case kIA32I16x8Q15MulRSatS:
    case kIA32I16x8RelaxedQ15MulRS:
    case kIA32I16x8DotI8x16I7x16S:
    case kIA32I8x16Splat:
    case kIA32I8x16ExtractLaneS:
    case kIA32Pinsrb:
    case kIA32Pinsrw:
    case kIA32Pinsrd:
    case kIA32Pextrb:
    case kIA32Pextrw:
    case kIA32S128Store32Lane:
    case kIA32I8x16SConvertI16x8:
    case kIA32I8x16Neg:
    case kIA32I8x16Shl:
    case kIA32I8x16ShrS:
    case kIA32I8x16Add:
    case kIA32I8x16AddSatS:
    case kIA32I8x16Sub:
    case kIA32I8x16SubSatS:
    case kIA32I8x16MinS:
    case kIA32I8x16MaxS:
    case kIA32I8x16Eq:
    case kSSEI8x16Ne:
    case kAVXI8x16Ne:
    case kIA32I8x16GtS:
    case kSSEI8x16GeS:
    case kAVXI8x16GeS:
    case kIA32I8x16UConvertI16x8:
    case kIA32I8x16AddSatU:
    case kIA32I8x16SubSatU:
    case kIA32I8x16ShrU:
    case kIA32I8x16MinU:
    case kIA32I8x16MaxU:
    case kSSEI8x16GtU:
    case kAVXI8x16GtU:
    case kSSEI8x16GeU:
    case kAVXI8x16GeU:
    case kIA32I8x16RoundingAverageU:
    case kIA32I8x16Abs:
    case kIA32I8x16BitMask:
    case kIA32I8x16Popcnt:
    case kIA32S128Const:
    case kIA32S128Zero:
    case kIA32S128AllOnes:
    case kIA32S128Not:
    case kIA32S128And:
    case kIA32S128Or:
    case kIA32S128Xor:
    case kIA32S128Select:
    case kIA32S128AndNot:
    case kIA32I8x16Swizzle:
    case kIA32I8x16Shuffle:
    case kIA32S32x4Rotate:
    case kIA32S32x4Swizzle:
    case kIA32S32x4Shuffle:
    case kIA32S16x8Blend:
    case kIA32S16x8HalfShuffle1:
    case kIA32S16x8HalfShuffle2:
    case kIA32S8x16Alignr:
    case kIA32S16x8Dup:
    case kIA32S8x16Dup:
    case kSSES16x8UnzipHigh:
    case kAVXS16x8UnzipHigh:
    case kSSES16x8UnzipLow:
    case kAVXS16x8UnzipLow:
    case kSSES8x16UnzipHigh:
    case kAVXS8x16UnzipHigh:
    case kSSES8x16UnzipLow:
    case kAVXS8x16UnzipLow:
    case kIA32S64x2UnpackHigh:
    case kIA32S32x4UnpackHigh:
    case kIA32S16x8UnpackHigh:
    case kIA32S8x16UnpackHigh:
    case kIA32S64x2UnpackLow:
    case kIA32S32x4UnpackLow:
    case kIA32S16x8UnpackLow:
    case kIA32S8x16UnpackLow:
    case kSSES8x16TransposeLow:
    case kAVXS8x16TransposeLow:
    case kSSES8x16TransposeHigh:
    case kAVXS8x16TransposeHigh:
    case kSSES8x8Reverse:
    case kAVXS8x8Reverse:
    case kSSES8x4Reverse:
    case kAVXS8x4Reverse:
    case kSSES8x2Reverse:
    case kAVXS8x2Reverse:
    case kIA32S128AnyTrue:
    case kIA32I64x2AllTrue:
    case kIA32I32x4AllTrue:
    case kIA32I16x8AllTrue:
    case kIA32I8x16AllTrue:
      return (instr->addressing_mode() == kMode_None)
                 ? kNoOpcodeFlags
                 : kIsLoadOperation | kHasSideEffect;

    case kIA32Idiv:
    case kIA32Udiv:
      return (instr->addressing_mode() == kMode_None)
                 ? kMayNeedDeoptOrTrapCheck
                 : kMayNeedDeoptOrTrapCheck | kIsLoadOperation | kHasSideEffect;

    case kIA32Movsxbl:
    case kIA32Movzxbl:
    case kIA32Movb:
    case kIA32Movsxwl:
    case kIA32Movzxwl:
    case kIA32Movw:
    case kIA32Movl:
    case kIA32Movss:
    case kIA32Movsd:
    case kIA32Movdqu:
    case kIA32Movlps:
    case kIA32Movhps:
    // Moves are used for memory load/store operations.
    case kIA32S128Load8Splat:
    case kIA32S128Load16Splat:
    case kIA32S128Load32Splat:
    case kIA32S128Load64Splat:
    case kIA32S128Load8x8S:
    case kIA32S128Load8x8U:
    case kIA32S128Load16x4S:
    case kIA32S128Load16x4U:
    case kIA32S128Load32x2S:
    case kIA32S128Load32x2U:
      return instr->HasOutput() ? kIsLoadOperation : kHasSideEffect;

    case kIA32Peek:
      return kIsLoadOperation;

    case kIA32Push:
    case kIA32Poke:
    case kIA32MFence:
    case kIA32LFence:
      return kHasSideEffect;

    case kIA32Word32AtomicPairLoad:
      return kIsLoadOperation;

    case kIA32Word32ReleasePairStore:
    case kIA32Word32SeqCstPairStore:
    case kIA32Word32AtomicPairAdd:
    case kIA32Word32AtomicPairSub:
    case kIA32Word32AtomicPairAnd:
    case kIA32Word32AtomicPairOr:
    case kIA32Word32AtomicPairXor:
    case kIA32Word32AtomicPairExchange:
    case kIA32Word32AtomicPairCompareExchange:
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
  // Basic latency modeling for ia32 instructions. They have been determined
  // in an empirical way.
  switch (instr->arch_opcode()) {
    case kFloat64Mul:
      return 5;
    case kIA32Imul:
    case kIA32ImulHigh:
      return 5;
    case kIA32Float32Cmp:
    case kIA32Float64Cmp:
      return 9;
    case kFloat32Add:
    case kFloat32Sub:
    case kFloat64Add:
    case kFloat64Sub:
    case kFloat32Abs:
    case kFloat32Neg:
    case kIA32Float64Max:
    case kIA32Float64Min:
    case kFloat64Abs:
    case kFloat64Neg:
      return 5;
    case kFloat32Mul:
      return 4;
    case kIA32Float32ToFloat64:
    case kIA32Float64ToFloat32:
      return 6;
    case kIA32Float32Round:
    case kIA32Float64Round:
    case kIA32Float32ToInt32:
    case kIA32Float64ToInt32:
      return 8;
    case kIA32Float32ToUint32:
      return 21;
    case kIA32Float64ToUint32:
      return 15;
    case kIA32Idiv:
      return 33;
    case kIA32Udiv:
      return 26;
    case kFloat32Div:
      return 35;
    case kFloat64Div:
      return 63;
    case kIA32Float32Sqrt:
    case kIA32Float64Sqrt:
      return 25;
    case kIA32Float64Mod:
      return 50;
    case kArchTruncateDoubleToI:
      return 9;
    default:
      return 1;
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```