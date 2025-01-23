Response: Let's break down the thought process for analyzing this C++ unit test file and connecting it to JavaScript concepts.

1. **Understand the Goal:** The filename itself, "turboshaft-instruction-selector-riscv64-unittest.cc," gives us the core purpose. It's testing the *instruction selector* within the *Turboshaft* compiler pipeline for the *RISC-V 64-bit* architecture. "unittest" confirms it's focused on isolated component testing.

2. **Identify Key Components:** Scan the `#include` directives and the namespace declarations (`v8`, `internal`, `compiler`, `turboshaft`). This tells us we are deep within the V8 JavaScript engine's compilation process. The included headers like `"src/codegen/machine-type.h"`, `"src/compiler/turboshaft/assembler.h"`, and `"src/compiler/turboshaft/operations.h"` hint at the core functionalities being tested: how high-level compiler operations are translated into low-level machine instructions.

3. **Look for Patterns and Data Structures:** Notice the repeated use of templates like `MachInst`, `IntCmp`, and `FPCmp`. These structures hold information about:
    * **`op`:**  A compiler operation (e.g., `TSBinop::kWord32BitwiseAnd`).
    * **`constructor_name`:**  A human-readable name for the operation.
    * **`arch_opcode`:** The specific RISC-V instruction code (e.g., `kRiscvAnd32`).
    * **`machine_type`:** The data type involved (e.g., `MachineType::Int32()`).
    * **`expected_size` (for `IntCmp`):**  The expected number of RISC-V instructions generated.
    * **`cond` (for `FPCmp`):**  The CPU flags condition after the comparison.

    The arrays of these structs (`kLogicalInstructions`, `kShiftInstructions`, etc.) are the test cases. Each element represents an operation that the instruction selector should handle correctly.

4. **Analyze the Test Structure:** The `TEST_P` macro indicates parameterized tests. This means the same test logic is run multiple times with different input data (the elements of the arrays). The core test logic generally follows this pattern:
    * **`StreamBuilder m(...)`:**  Creates a sequence of compiler operations.
    * **`m.Emit(...)`:**  Adds a specific compiler operation to the sequence, potentially using parameters or constants.
    * **`m.Return(...)`:**  Specifies the final result of the operation sequence.
    * **`Stream s = m.Build()`:**  Runs the instruction selection process.
    * **`ASSERT_EQ(...)` and `EXPECT_EQ(...)`:**  Verification steps. They check if the generated RISC-V instructions (`s`) match the expected opcodes, input/output counts, flags, and other properties defined in the `MachInst` structs.

5. **Connect to JavaScript (The "Aha!" Moment):**  The compiler operations (`TSBinop`, `TSUnop`) are the bridge to JavaScript. These operations represent the internal workings of how V8 handles JavaScript code. Consider an example:  `TSBinop::kWord32Add` clearly corresponds to a 32-bit integer addition in JavaScript. The test verifies that when V8 encounters this operation during compilation for RISC-V, it correctly selects the `kRiscvAdd32` instruction.

6. **Formulate JavaScript Examples:**  Based on the identified operations, create simple JavaScript code snippets that would trigger those operations during compilation:
    * `TSBinop::kWord32BitwiseAnd`:  `let result = a & b;` (where `a` and `b` are likely treated as 32-bit integers internally).
    * `TSBinop::kFloat64Add`: `let sum = x + y;` (where `x` and `y` are floating-point numbers).
    * `TSUnop::kChangeInt32ToFloat64`:  This is a bit more abstract, but could be triggered by a type conversion: `let floatVal = Number(intValue);`

7. **Explain the Connection:**  Articulate how the C++ code relates to the JavaScript examples. Emphasize that the unit tests ensure the *correct translation* of JavaScript semantics into efficient RISC-V machine code. Highlight that the `Turboshaft` compiler is responsible for this process.

8. **Refine and Organize:** Structure the explanation clearly, starting with the general purpose of the file and then diving into specific details with examples. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just testing RISC-V instructions."
* **Correction:** "No, it's testing the *compiler's choice* of RISC-V instructions for higher-level operations. The `TSBinop` and `TSUnop` are key."
* **Initial thought (for JS examples):**  Overly complex JavaScript code.
* **Correction:**  Keep the JavaScript examples simple and directly related to the C++ operations being tested. Focus on basic arithmetic, bitwise operations, and type conversions.
* **Considering edge cases:**  Why are some test cases commented out?  This might be due to incomplete implementation, features not yet supported on RISC-V, or work in progress. Mentioning this adds nuance.

By following these steps, one can effectively analyze even complex C++ unit test files and relate them to the higher-level concepts of the software they are testing, in this case, JavaScript execution within the V8 engine.
这个C++源代码文件 `turboshaft-instruction-selector-riscv64-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 **Turboshaft 编译器** 中 **RISC-V 64 位架构** 的 **指令选择器 (Instruction Selector)** 的功能。

**核心功能归纳:**

1. **测试指令选择的正确性:** 该文件包含了大量的单元测试，用于验证 Turboshaft 编译器在将中间表示 (IR) 的操作转换为 RISC-V 64 位机器指令时，是否选择了正确的指令。

2. **覆盖各种操作类型:**  测试用例涵盖了各种常见的操作，包括：
    * **算术运算:** 加法、减法、乘法、除法、取模等（针对整数和浮点数）。
    * **位运算:** 与、或、异或、左移、右移、循环右移等。
    * **比较运算:** 等于、不等于、小于、大于等（针对整数和浮点数）。
    * **类型转换:**  整数与浮点数之间的转换。
    * **内存访问:**  加载 (Load) 和存储 (Store) 不同大小的数据。
    * **其他操作:**  例如，浮点数的绝对值、最大值、最小值等。

3. **针对 RISC-V 64 位架构的特定指令:** 测试用例中明确地断言 (assert) 生成的机器指令的 `arch_opcode` 是否为预期的 RISC-V 指令，例如 `kRiscvAdd64` (64位加法), `kRiscvShl32` (32位左移) 等。

4. **参数化测试:**  使用了 Google Test 框架的参数化测试特性 (`TEST_P`)，可以方便地使用不同的输入数据（例如不同的操作类型、不同的机器类型）来运行相同的测试逻辑，提高了测试的覆盖率和效率。

5. **模拟编译过程:**  测试用例通过 `StreamBuilder` 创建一个操作序列，模拟 Turboshaft 编译器的中间表示，然后调用指令选择器将其转换为机器指令流 (Stream)。

6. **断言指令属性:**  测试用例不仅检查了生成的指令类型，还检查了指令的其他属性，例如：
    * **输入和输出操作数的数量 (`InputCount()`, `OutputCount()`):**  确保指令接收和产生正确数量的操作数。
    * **操作数的类型 (`IsImmediate()`, `ToInt32()`):**  验证操作数是否为立即数以及其值。
    * **寻址模式 (`addressing_mode()`):**  检查内存访问指令的寻址模式。
    * **标志位设置 (`flags_mode()`, `flags_condition()`):**  验证比较指令是否正确设置了 CPU 的标志位。

**与 JavaScript 的关系及示例:**

该文件直接关系到 V8 引擎如何将 JavaScript 代码编译成高效的 RISC-V 64 位机器码。  Turboshaft 是 V8 的一个新的优化编译器，指令选择器是其关键组成部分。

**JavaScript 示例:**

假设以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(10, 20);
```

当 V8 的 Turboshaft 编译器编译 `add` 函数时，它会经历以下 (简化的) 过程：

1. **生成中间表示 (IR):**  编译器会将 `a + b` 这个加法操作表示为中间表示的一种形式，例如 `TSBinop::kWord32Add` (如果 `a` 和 `b` 被推断为 32 位整数)。

2. **指令选择:**  `turboshaft-instruction-selector-riscv64-unittest.cc` 中的测试用例，例如：

   ```c++
   TEST_P(TurboshaftInstructionSelectorIntArithTwoTest, Parameter) {
     const MachInst2 intpa = GetParam();
     StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
                     intpa.machine_type);
     m.Return(m.Emit(intpa.op, m.Parameter(0), m.Parameter(1)));
     Stream s = m.Build();
     ASSERT_EQ(1U, s.size());
     EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
     // ...
   }

   INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                            TurboshaftInstructionSelectorIntArithTwoTest,
                            ::testing::ValuesIn(kAddSubInstructions));

   const MachInst2 kAddSubInstructions[] = {
       {TSBinop::kWord32Add, "Word32Add", kRiscvAdd32, MachineType::Int32()},
       // ...
   };
   ```

   会测试当遇到 `TSBinop::kWord32Add` 操作时，指令选择器是否会选择 RISC-V 64 位的 `kRiscvAdd32` 指令。

3. **生成机器码:**  最终，RISC-V 64 位的 `add` 函数可能会被编译成类似以下的汇编指令：

   ```assembly
   addw  a0, a0, a1  // 将 a0 和 a1 寄存器的值相加，结果存储到 a0 (假设 a 和 b 在 a0 和 a1 中)
   ret             // 返回
   ```

**其他 JavaScript 示例:**

* **位运算:**  JavaScript 的 `&`, `|`, `^`, `<<`, `>>`, `>>>` 等位运算符，在 Turboshaft 编译器中会被表示为 `TSBinop::kWord32BitwiseAnd`, `TSBinop::kWord32BitwiseOr` 等操作，并由该文件中的相应测试用例进行验证，确保生成正确的 RISC-V 位运算指令 (例如 `andw`, `orw`, `sllw` 等)。

* **浮点数运算:** JavaScript 中的浮点数加法 `+` (例如 `let f = 1.5 + 2.5;`) 会对应到 `TSBinop::kFloat64Add` 操作，该文件中的 `TurboshaftInstructionSelectorFPArithTest` 会确保生成正确的 RISC-V 浮点数加法指令 (`fadd.d`)。

* **类型转换:** 当 JavaScript 中发生类型转换 (例如将数字转换为字符串) 时，Turboshaft 编译器会生成相应的类型转换操作，该文件中的 `TurboshaftInstructionSelectorConversionTest` 会测试这些转换操作是否被正确地映射到 RISC-V 的转换指令 (`fcvt.d.w`, `fcvt.w.d` 等)。

**总结:**

`turboshaft-instruction-selector-riscv64-unittest.cc` 是 V8 引擎中至关重要的测试文件，它保证了 Turboshaft 编译器能够正确地将 JavaScript 的各种操作转换为高效的 RISC-V 64 位机器码，从而确保了 JavaScript 代码在 RISC-V 架构上的性能和正确性。它通过大量的单元测试覆盖了各种可能的 JavaScript 操作，并验证了指令选择器在不同场景下的行为。

### 提示词
```
这是目录为v8/test/unittests/compiler/riscv64/turboshaft-instruction-selector-riscv64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/machine-type.h"
#include "src/common/globals.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h"

namespace v8 {
namespace internal {
namespace compiler {
namespace turboshaft {

namespace {
template <typename Op>
struct MachInst {
  Op op;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  MachineType machine_type;
};

template <typename T>
std::ostream& operator<<(std::ostream& os, const MachInst<T>& mi) {
  return os << mi.constructor_name;
}

using MachInst1 = MachInst<TSUnop>;
using MachInst2 = MachInst<TSBinop>;

// To avoid duplicated code IntCmp helper structure
// is created. It contains MachInst2 with two nodes and expected_size
// because different cmp instructions have different size.
struct IntCmp {
  MachInst2 mi;
  uint32_t expected_size;
};

struct FPCmp {
  MachInst2 mi;
  FlagsCondition cond;
};

const FPCmp kFPCmpInstructions[] = {
    {{TSBinop::kFloat64Equal, "Float64Equal", kRiscvCmpD,
      MachineType::Float64()},
     kEqual},
    {{TSBinop::kFloat64LessThan, "Float64LessThan", kRiscvCmpD,
      MachineType::Float64()},
     kUnsignedLessThan},
    {{TSBinop::kFloat64LessThanOrEqual, "Float64LessThanOrEqual", kRiscvCmpD,
      MachineType::Float64()},
     kUnsignedLessThanOrEqual},
    // {{TSBinop::kFloat64GreaterThan, "Float64GreaterThan",
    //   kRiscvCmpD, MachineType::Float64()},
    //  kUnsignedLessThan},
    // {{TSBinop::kFloat64GreaterThanOrEqual,
    //   "Float64GreaterThanOrEqual", kRiscvCmpD, MachineType::Float64()},
    //  kUnsignedLessThanOrEqual}
};

struct Conversion {
  // The machine_type field in MachInst1 represents the destination type.
  MachInst1 mi;
  MachineType src_machine_type;
};

// ----------------------------------------------------------------------------
// Logical instructions.
// ----------------------------------------------------------------------------

const MachInst2 kLogicalInstructions[] = {
    {TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd", kRiscvAnd32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseAnd, "Word64BitwiseAnd", kRiscvAnd,
     MachineType::Int64()},
    {TSBinop::kWord32BitwiseOr, "Word32BitwiseOr", kRiscvOr32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseOr, "Word64BitwiseOr", kRiscvOr,
     MachineType::Int64()},
    {TSBinop::kWord32BitwiseXor, "Word32BitwiseXor", kRiscvXor32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseXor, "Word64BitwiseXor", kRiscvXor,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------

const MachInst2 kShiftInstructions[] = {
    {TSBinop::kWord32ShiftLeft, "Word32ShiftLeft", kRiscvShl32,
     MachineType::Int32()},
    {TSBinop::kWord64ShiftLeft, "Word64ShiftLeft", kRiscvShl64,
     MachineType::Int64()},
    // {TSBinop::kWord32BitwiseShr, "Word32Shr", kRiscvShr32,
    //  MachineType::Int32()},
    // {TSBinop::kWord64BitwiseShr, "Word64Shr", kRiscvShr64,
    //  MachineType::Int64()},
    {TSBinop::kWord32ShiftRightLogical, "Word32ShiftRightLogical", kRiscvShr32,
     MachineType::Int32()},
    {TSBinop::kWord64ShiftRightLogical, "Word64ShiftRightLogical", kRiscvShr64,
     MachineType::Int64()},
    {TSBinop::kWord32ShiftRightArithmetic, "Word32ShiftRightArithmetic",
     kRiscvSar32, MachineType::Int32()},
    {TSBinop::kWord64ShiftRightArithmetic, "Word64ShiftRightArithmetic",
     kRiscvSar64, MachineType::Int64()},
    {TSBinop::kWord32RotateRight, "Word32Ror", kRiscvRor32,
     MachineType::Int32()},
    {TSBinop::kWord64RotateRight, "Word64Ror", kRiscvRor64,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------

const MachInst2 kMulDivInstructions[] = {
    {TSBinop::kWord32Mul, "Word32Mul", kRiscvMul32, MachineType::Int32()},
    {TSBinop::kInt32Div, "Int32Div", kRiscvDiv32, MachineType::Int32()},
    {TSBinop::kUint32Div, "Uint32Div", kRiscvDivU32, MachineType::Uint32()},
    {TSBinop::kWord64Mul, "Word64Mul", kRiscvMul64, MachineType::Int64()},
    {TSBinop::kInt64Div, "Int64Div", kRiscvDiv64, MachineType::Int64()},
    {TSBinop::kUint64Div, "Uint64Div", kRiscvDivU64, MachineType::Uint64()},
    {TSBinop::kFloat64Mul, "Float64Mul", kRiscvMulD, MachineType::Float64()},
    {TSBinop::kFloat64Div, "Float64Div", kRiscvDivD, MachineType::Float64()}};

// ----------------------------------------------------------------------------
// MOD instructions.
// ----------------------------------------------------------------------------

const MachInst2 kModInstructions[] = {
    {TSBinop::kInt32Mod, "Int32Mod", kRiscvMod32, MachineType::Int32()},
    {TSBinop::kUint32Mod, "Uint32Mod", kRiscvModU32, MachineType::Int32()},
    // {TSBinop::kFloat64Mod, "Float64Mod", kRiscvModD,
    //  MachineType::Float64()}
};

// ----------------------------------------------------------------------------
// Arithmetic FPU instructions.
// ----------------------------------------------------------------------------

const MachInst2 kFPArithInstructions[] = {
    {TSBinop::kFloat64Add, "Float64Add", kRiscvAddD, MachineType::Float64()},
    {TSBinop::kFloat64Sub, "Float64Sub", kRiscvSubD, MachineType::Float64()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, two nodes.
// ----------------------------------------------------------------------------

const MachInst2 kAddSubInstructions[] = {
    {TSBinop::kWord32Add, "Word32Add", kRiscvAdd32, MachineType::Int32()},
    {TSBinop::kWord64Add, "Word64Add", kRiscvAdd64, MachineType::Int64()},
    {TSBinop::kWord32Sub, "Int32Sub", kRiscvSub32, MachineType::Int32()},
    {TSBinop::kWord64Sub, "Word64Sub", kRiscvSub64, MachineType::Int64()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, one node.
// ----------------------------------------------------------------------------

const MachInst1 kAddSubOneInstructions[] = {
    // {TSBinop::kInt32Neg, "Int32Neg", kRiscvSub32,
    //  MachineType::Int32()},
    // {TSBinop::kInt64Neg, "Int64Neg", kRiscvSub64,
    //  MachineType::Int64()}
};

// ----------------------------------------------------------------------------
// Arithmetic compare instructions.
// ----------------------------------------------------------------------------

const IntCmp kCmpInstructions[] = {
    // {{TSBinop::kWordEqual, "WordEqual", kRiscvCmp,
    //   MachineType::Int64()},
    //  1U},
    // {{TSBinop::kWordNotEqual, "WordNotEqual", kRiscvCmp,
    //   MachineType::Int64()},
    //  1U},
    // {{TSBinop::kWord32BitwiseEqual, "Word32Equal", kRiscvCmp,
    //   MachineType::Int32()},
    //  COMPRESS_POINTERS_BOOL ? 3U : 1U},
    // {{TSBinop::kWord32BitwiseNotEqual, "Word32NotEqual", kRiscvCmp,
    //   MachineType::Int32()},
    //  COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kInt32LessThan, "Int32LessThan", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kInt32LessThanOrEqual, "Int32LessThanOrEqual", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kInt32GreaterThan, "Int32GreaterThan", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kInt32GreaterThanOrEqual, "Int32GreaterThanOrEqual", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kUint32LessThan, "Uint32LessThan", kRiscvCmp,
      MachineType::Uint32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kUint32LessThanOrEqual, "Uint32LessThanOrEqual", kRiscvCmp,
      MachineType::Uint32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U}};

// ----------------------------------------------------------------------------
// Conversion instructions.
// ----------------------------------------------------------------------------

const Conversion kConversionInstructions[] = {
    // Conversion instructions are related to machine_operator.h:
    // FPU conversions:
    // Convert representation of integers between float64 and int32/uint32.
    // The precise rounding mode and handling of out of range inputs are *not*
    // defined for these operators, since they are intended only for use with
    // integers.
    {{TSUnop::kChangeInt32ToFloat64, "ChangeInt32ToFloat64", kRiscvCvtDW,
      MachineType::Float64()},
     MachineType::Int32()},

    {{TSUnop::kChangeUint32ToFloat64, "ChangeUint32ToFloat64", kRiscvCvtDUw,
      MachineType::Float64()},
     MachineType::Int32()},

    // {{TSUnop::kChangeFloat64ToInt32, "ChangeFloat64ToInt32",
    //   kRiscvTruncWD, MachineType::Float64()},
    //  MachineType::Int32()},

    // {{TSUnop::kChangeFloat64ToUint32, "ChangeFloat64ToUint32",
    //   kRiscvTruncUwD, MachineType::Float64()},
    //  MachineType::Int32()}
};

const Conversion kFloat64RoundInstructions[] = {
    // {{TSBinop::kFloat64RoundUp, "Float64RoundUp", kRiscvCeilWD,
    //   MachineType::Int32()},
    //  MachineType::Float64()},
    // {{TSBinop::kFloat64RoundDown, "Float64RoundDown", kRiscvFloorWD,
    //   MachineType::Int32()},
    //  MachineType::Float64()},
    // {{TSBinop::kFloat64RoundTiesEven, "Float64RoundTiesEven",
    //   kRiscvRoundWD, MachineType::Int32()},
    //  MachineType::Float64()},
    // {{TSBinop::kFloat64RoundTruncate, "Float64RoundTruncate",
    //   kRiscvTruncWD, MachineType::Int32()},
    //  MachineType::Float64()}
};

const Conversion kFloat32RoundInstructions[] = {
    // {{TSBinop::kFloat32RoundUp, "Float32RoundUp", kRiscvCeilWS,
    //   MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSBinop::kFloat32RoundDown, "Float32RoundDown", kRiscvFloorWS,
    //   MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSBinop::kFloat32RoundTiesEven, "Float32RoundTiesEven",
    //   kRiscvRoundWS, MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSBinop::kFloat32RoundTruncate, "Float32RoundTruncate",
    //   kRiscvTruncWS, MachineType::Int32()},
    //  MachineType::Float32()}
};

// RISCV64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {TSBinop::kUint32Div, "Uint32Div", kRiscvDivU32, MachineType::Uint32()},
    {TSBinop::kUint32Mod, "Uint32Mod", kRiscvModU32, MachineType::Uint32()},
    // {TSBinop::kUint32MulHigh, "Uint32MulHigh", kRiscvMulHighU32,
    //  MachineType::Uint32()}
};

}  // namespace

using TurboshaftInstructionSelectorFPCmpTest =
    TurboshaftInstructionSelectorTestWithParam<FPCmp>;

TEST_P(TurboshaftInstructionSelectorFPCmpTest, Parameter) {
  const FPCmp cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), cmp.mi.machine_type,
                  cmp.mi.machine_type);
  m.Return(m.Emit(cmp.mi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.cond, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorFPCmpTest,
                         ::testing::ValuesIn(kFPCmpInstructions));

// ----------------------------------------------------------------------------
// Arithmetic compare instructions integers
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorCmpTest =
    TurboshaftInstructionSelectorTestWithParam<IntCmp>;

TEST_P(TurboshaftInstructionSelectorCmpTest, Parameter) {
  const IntCmp cmp = GetParam();
  const MachineType type = cmp.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(cmp.mi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  if (v8_flags.debug_code &&
      type.representation() == MachineRepresentation::kWord32 &&
      cmp.expected_size == 1) {
    ASSERT_EQ(6U, s.size());

    EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());

    EXPECT_EQ(kRiscvShl64, s[1]->arch_opcode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());

    EXPECT_EQ(kRiscvShl64, s[2]->arch_opcode());
    EXPECT_EQ(2U, s[2]->InputCount());
    EXPECT_EQ(1U, s[2]->OutputCount());

    EXPECT_EQ(cmp.mi.arch_opcode, s[3]->arch_opcode());
    EXPECT_EQ(2U, s[3]->InputCount());
    EXPECT_EQ(1U, s[3]->OutputCount());

    EXPECT_EQ(kRiscvAssertEqual, s[4]->arch_opcode());

    EXPECT_EQ(cmp.mi.arch_opcode, s[5]->arch_opcode());
    EXPECT_EQ(2U, s[5]->InputCount());
    EXPECT_EQ(1U, s[5]->OutputCount());
  } else {
    ASSERT_EQ(cmp.expected_size, s.size());
    if (cmp.expected_size == 3) {
      EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
      EXPECT_EQ(2U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());

      EXPECT_EQ(kRiscvShl64, s[1]->arch_opcode());
      EXPECT_EQ(2U, s[1]->InputCount());
      EXPECT_EQ(1U, s[1]->OutputCount());
    }
    EXPECT_EQ(cmp.mi.arch_opcode, s[cmp.expected_size - 1]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorCmpTest,
                         ::testing::ValuesIn(kCmpInstructions));

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorShiftTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorShiftTest, Immediate) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FORRANGE(int32_t, imm, 0,
                  ((1 << ElementSizeLog2Of(type.representation())) * 8) - 1) {
    StreamBuilder m(this, type, type);
    m.Return(m.Emit(dpi.op, m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorShiftTest,
                         ::testing::ValuesIn(kShiftInstructions));

// ----------------------------------------------------------------------------
// Logical instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorLogicalTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorLogicalTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorLogicalTest,
                         ::testing::ValuesIn(kLogicalInstructions));

// TEST_F(TurboshaftInstructionSelectorTest, Word32ShlWithWord32And) {
//   TRACED_FORRANGE(int32_t, shift, 0, 30) {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     auto r =
//         m.Emit(TSBinop::kWord32ShiftLeft,
//               m.Emit(TSBinop::kWord32BitwiseAnd,  m.Parameter(0),
//               m.Int32Constant((1 << (31 - shift)) - 1)),
//               m.Int32Constant(shift + 1));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvShl32, s[0]->arch_opcode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word64ShlWithWord64And) {
//   TRACED_FORRANGE(int32_t, shift, 0, 62) {
//     StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
//     auto p0 = m.Parameter(0);
//     auto r = m.Emit(TSBinop::kWord64ShiftLeft,
//                            m.Emit(TSBinop::kWord64BitwiseAnd, p0,
//                                   m.Int64Constant((1L << (63 - shift)) - 1)),
//                            m.Int64Constant(shift + 1));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word32SarWithWord32Shl) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     auto p0 = m.Parameter(0);
//     auto r =
//         m.Emit(TSBinop::kWord32ShiftRightLogical,
//           m.Emit(TSBinop::kWord32ShiftLeft, p0, m.Int32Constant(24)),
//           m.Int32Constant(24));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvSignExtendByte, s[0]->arch_opcode());
//     ASSERT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     auto p0 = m.Parameter(0);
//     auto r =
//         m.Emit(TSBinop::kWord32ShiftRightLogical,
//           m.Emit(TSBinop::kWord32ShiftLeft, p0, m.Int32Constant(16)),
//           m.Int32Constant(16));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvSignExtendShort, s[0]->arch_opcode());
//     ASSERT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     auto p0 = m.Parameter(0);
//     auto r =
//         m.Emit(TSBinop::kWord32ShiftRightLogical,
//           m.Emit(TSBinop::kWord32ShiftLeft, p0, m.Int32Constant(32)),
//           m.Int32Constant(32));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvShl32, s[0]->arch_opcode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
// }

// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorMulDivTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorMulDivTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMulDivTest,
                         ::testing::ValuesIn(kMulDivInstructions));

// ----------------------------------------------------------------------------
// MOD instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorModTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorModTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorModTest,
                         ::testing::ValuesIn(kModInstructions));

// ----------------------------------------------------------------------------
// Floating point instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorFPArithTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorFPArithTest, Parameter) {
  const MachInst2 fpa = GetParam();
  StreamBuilder m(this, fpa.machine_type, fpa.machine_type, fpa.machine_type);
  m.Return(m.Emit(fpa.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(fpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorFPArithTest,
                         ::testing::ValuesIn(kFPArithInstructions));
// ----------------------------------------------------------------------------
// Integer arithmetic
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorIntArithTwoTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorIntArithTwoTest, Parameter) {
  const MachInst2 intpa = GetParam();
  StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
                  intpa.machine_type);
  m.Return(m.Emit(intpa.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorIntArithTwoTest,
                         ::testing::ValuesIn(kAddSubInstructions));

// ----------------------------------------------------------------------------
// One node.
// ----------------------------------------------------------------------------

// using TurboshaftInstructionSelectorIntArithOneTest =
//     TurboshaftInstructionSelectorTestWithParam<MachInst1>;

// TEST_P(TurboshaftInstructionSelectorIntArithOneTest, Parameter) {
//   const MachInst1 intpa = GetParam();
//   StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
//                   intpa.machine_type);
//   m.Return(m.Emit(intpa.op, m.Parameter(0)));
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
//   EXPECT_EQ(2U, s[0]->InputCount());
//   EXPECT_EQ(1U, s[0]->OutputCount());
// }

// INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
//                          TurboshaftInstructionSelectorIntArithOneTest,
//                          ::testing::ValuesIn(kAddSubOneInstructions));

// ----------------------------------------------------------------------------
// Conversions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorConversionTest =
    TurboshaftInstructionSelectorTestWithParam<Conversion>;

TEST_P(TurboshaftInstructionSelectorConversionTest, Parameter) {
  const Conversion conv = GetParam();
  StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
  m.Return(m.Emit(conv.mi.op, (m.Parameter(0))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorConversionTest,
                         ::testing::ValuesIn(kConversionInstructions));

TEST_F(TurboshaftInstructionSelectorTest, ChangesFromToSmi) {
  // {
  //   StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  //   m.Return(m.Emit(TSUnop::kTruncateInt64ToInt32,
  //       m.Emit(TSBinop::kWord64ShiftRightArithmetic, m.Parameter(0),
  //       m.Int32Constant(32))));
  //   Stream s = m.Build();
  //   ASSERT_EQ(1U, s.size());
  //   EXPECT_EQ(kRiscvSar64, s[0]->arch_opcode());
  //   EXPECT_EQ(kMode_None, s[0]->addressing_mode());
  //   ASSERT_EQ(2U, s[0]->InputCount());
  //   EXPECT_EQ(1U, s[0]->OutputCount());
  // }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Emit(TSBinop::kWord64ShiftLeft,
                    m.Emit(TSUnop::kChangeInt32ToInt64, m.Parameter(0)),
                    m.Int32Constant(32)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

using CombineChangeFloat64ToInt32WithRoundFloat64 =
    TurboshaftInstructionSelectorTestWithParam<Conversion>;

// TEST_P(CombineChangeFloat64ToInt32WithRoundFloat64, Parameter) {
//   {
//     const Conversion conv = GetParam();
//     StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
//     m.Return(m.Emit(TSUnop::kReversibleFloat64ToInt32,
//                     (m.Emit(conv.mi.op, m.Parameter(0)))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
//     EXPECT_EQ(kMode_None, s[0]->addressing_mode());
//     ASSERT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

// INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
//                          CombineChangeFloat64ToInt32WithRoundFloat64,
//                          ::testing::ValuesIn(kFloat64RoundInstructions));

using CombineChangeFloat32ToInt32WithRoundFloat32 =
    TurboshaftInstructionSelectorTestWithParam<Conversion>;

// TEST_P(CombineChangeFloat32ToInt32WithRoundFloat32, Parameter) {
//   {
//     const Conversion conv = GetParam();
//     StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
//     m.Return(m.Emit(TSUnop::kReversibleFloat64ToInt32,
//                     m.Emit(TSUnop::kChangeFloat32ToFloat64,
//                            (m.Emit(conv.mi.op, m.Parameter(0))))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
//     EXPECT_EQ(kMode_None, s[0]->addressing_mode());
//     ASSERT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

// INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
//                          CombineChangeFloat32ToInt32WithRoundFloat32,
//                          ::testing::ValuesIn(kFloat32RoundInstructions));

TEST_F(TurboshaftInstructionSelectorTest,
       ChangeFloat64ToInt32OfChangeFloat32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
    m.Return(m.Emit(TSUnop::kReversibleFloat64ToInt32,
                    m.Emit(TSUnop::kChangeFloat32ToFloat64, m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvTruncWS, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       TruncateFloat64ToFloat32OfChangeInt32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Int32());
    m.Return(m.Emit(TSUnop::kTruncateFloat64ToFloat32,
                    m.Emit(TSUnop::kChangeInt32ToFloat64, m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCvtSW, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

// TEST_F(TurboshaftInstructionSelectorTest, CombineShiftsWithDivMod) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Emit(TSBinop::kInt32Div,
//       m.Emit(TSBinop::kWord64ShiftRightLogical, m.Parameter(0),
//       m.Int32Constant(32)), m.Emit(TSBinop::kWord64ShiftRightLogical,
//       m.Parameter(0), m.Int32Constant(32))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvDiv64, s[0]->arch_opcode());
//     EXPECT_EQ(kMode_None, s[0]->addressing_mode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Emit(TSBinop::kInt32Mod,
//       m.Emit(TSBinop::kWord64ShiftRightLogical, m.Parameter(0),
//       m.Int32Constant(32)), m.Emit(TSBinop::kWord64ShiftRightLogical,
//       m.Parameter(0), m.Int32Constant(32))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvMod64, s[0]->arch_opcode());
//     EXPECT_EQ(kMode_None, s[0]->addressing_mode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

TEST_F(TurboshaftInstructionSelectorTest, ChangeWord32ToWord64AfterLoad) {
  // For each case, test that the conversion is merged into the load
  // operation.
  // ChangeUint32ToUint64(Load_Uint8) -> Lbu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLbu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int8) -> Lb
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLb, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeUint32ToUint64(Load_Uint16) -> Lhu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLhu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int16) -> Lh
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Int16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLh, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint32) -> Lw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int32) -> Lw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

using TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test, Parameter) {
  const MachInst2 binop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), binop.machine_type,
                  binop.machine_type);
  m.Return(m.Emit(TSUnop::kChangeUint32ToUint64,
                  (m.Emit(binop.op, m.Parameter(0), m.Parameter(1)))));
  Stream s = m.Build();
  // Make sure the `ChangeUint32ToUint64` node turned into two op(sli 32 and sri
  // 32).
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test,
    ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

TEST_F(TurboshaftInstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // Lbu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLbu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // Lhu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLhu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // Lwu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLwu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(kRiscvZeroExtendWord, s[2]->arch_opcode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

// ----------------------------------------------------------------------------
// Loads and stores.
// ----------------------------------------------------------------------------

namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
};

static const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(), kRiscvLb, kRiscvSb},
    {MachineType::Uint8(), kRiscvLbu, kRiscvSb},
    {MachineType::Int16(), kRiscvLh, kRiscvSh},
    {MachineType::Uint16(), kRiscvLhu, kRiscvSh},
    {MachineType::Int32(), kRiscvLw, kRiscvSw},
    {MachineType::Float32(), kRiscvLoadFloat, kRiscvStoreFloat},
    {MachineType::Float64(), kRiscvLoadDouble, kRiscvStoreDouble},
    {MachineType::Int64(), kRiscvLd, kRiscvSd}};

struct MemoryAccessImm {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm& acc) {
  return os << acc.type;
}

struct MemoryAccessImm1 {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[5];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm1& acc) {
  return os << acc.type;
}

// ----------------------------------------------------------------------------
// Loads and stores immediate values
// ----------------------------------------------------------------------------

const MemoryAccessImm kMemoryAccessesImm[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}}};

#ifdef RISCV_HAS_NO_UNALIGNED
struct MemoryAccessImm2 {
  MachineType type;
  ArchOpcode store_opcode;
  ArchOpcode store_opcode_unaligned;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm2& acc) {
  return os << acc.type;
}

const MemoryAccessImm2 kMemoryAccessesImmUnaligned[] = {
    {MachineType::Int16(),
     kRiscvUsh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvUsw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvUsd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvUStoreFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvUStoreDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};
#endif
}  // namespace

using TurboshaftInstructionSelectorMemoryAccessTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                  memacc.type, memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Int32Constant(0),
          m.Parameter(1), kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// ----------------------------------------------------------------------------
// Load immediate.
// ----------------------------------------------------------------------------

using TurboshaftInstructionSelectorMemoryAccessImmTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccessImm>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmTest,
       LoadWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int64Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
  }
}

// ----------------------------------------------------------------------------
// Store immediate.
// ----------------------------------------------------------------------------

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmTest,
       StoreWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int64Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmTest, StoreZero) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    OpIndex zero;
    if (memacc.type.representation() >= MachineRepresentation::kWord8 &&
        memacc.type.representation() <= MachineRepresentation::kWord64) {
      zero = m.WordConstant(
          0, memacc.type.representation() <= MachineRepresentation::kWord32
                 ? WordRepresentation::Word32()
                 : WordRepresentation::Word64());
    } else {
      zero = m.FloatConstant(
          0, memacc.type.representation() == MachineRepresentation::kFloat32
                 ? FloatRepresentation::Float32()
                 : FloatRepresentation::Float64());
    }
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int64Constant(index), zero, kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(0)->kind());
    EXPECT_EQ(0,
              memacc.type.representation() < MachineRepresentation::kFloat32
                  ? s.ToInt64(s[0]->InputAt(0))
              : memacc.type.representation() == MachineRepresentation::kFloat32
                  ? s.ToFloat32(s[0]->InputAt(0))
                  : s.ToFloat64(s[0]->InputAt(0)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMemoryAccessImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImm));

#ifdef RISCV_HAS_NO_UNALIGNED
using TurboshaftInstructionSelectorMemoryAccessUnalignedImmTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccessImm2>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessUnalignedImmTest, StoreZero) {
  const MemoryAccessImm2 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    bool unaligned_store_supported =
        m.machine()->UnalignedStoreSupported(memacc.type.representation());
    m.UnalignedStore(memacc.type.representation(), m.Parameter(0),
                     m.Int32Constant(index), m.Int32Constant(0));
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    uint32_t i = is_int12(index) ? 0 : 1;
    ASSERT_EQ(i + 1, s.size());
    EXPECT_EQ(unaligned_store_supported ? memacc.store_opcode_unaligned
                                        : memacc.store_opcode,
              s[i]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[i]->addressing_mode());
    ASSERT_EQ(3U, s[i]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[i]->InputAt(1)->kind());
    EXPECT_EQ(i == 0 ? index : 0, s.ToInt32(s[i]->InputAt(1)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[i]->InputAt(2)->kind());
    EXPECT_EQ(0, s.ToInt64(s[i]->InputAt(2)));
    EXPECT_EQ(0U, s[i]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorMemoryAccessUnalignedImmTest,
    ::testing::ValuesIn(kMemoryAccessesImmUnaligned));
#endif
// ----------------------------------------------------------------------------
// Load/store offsets more than 16 bits.
// ----------------------------------------------------------------------------

using TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccessImm1>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest,
       LoadWithImmediateIndex) {
  const MemoryAccessImm1 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int64Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest,
       StoreWithImmediateIndex) {
  const MemoryAccessImm1 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int64Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest,
    ::testing::ValuesIn(kMemoryAccessImmMoreThan16bit));

// ----------------------------------------------------------------------------
// kRiscvCmp with zero testing.
// ----------------------------------------------------------------------------

TEST_F(TurboshaftInstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Emit(TSBinop::kWord32Equal, m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCmpZero32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Emit(TSBinop::kWord32Equal, m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCmpZero32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Emit(TSBinop::kWord64Equal, m.Parameter(0), m.Int64Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCmpZero, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Emit(TSBinop::kWord64Equal, m.Int64Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCmpZero, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

// TEST_F(TurboshaftInstructionSelectorTest, Word32Clz) {
//   StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
//   auto p0 = m.Parameter(0);
//   auto n = m.Word32Clz(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvClz32, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word64Clz) {
//   StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint64());
//   auto p0 = m.Parameter(0);
//   auto n = m.Word64Clz(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvClz64, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float32Abs) {
//   StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
//   auto p0 = m.Parameter(0);
//   auto n = m.Float32Abs(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvAbsS, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float64Abs) {
//   StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
//   auto p0 = m.Parameter(0);
//   auto n = m.Float64Abs(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvAbsD, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float64Max) {
//   StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
//                   MachineType::Float64());
//   auto p0 = m.Parameter(0);
//   auto p1 = m.Parameter(1);
//   auto n = m.Float64Max(p0, p1);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvFloat64Max, s[0]->arch_opcode());
//   ASSERT_EQ(2U, s[0]->InputCount());
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float64Min) {
//   StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
//                   MachineType::Float64());
//   auto p0 = m.Parameter(0);
//   auto p1 = m.Parameter(1);
//   auto n = m.Float64Min(p0, p1);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvFloat64Min, s[0]->arch_opcode());
//   ASSERT_EQ(2U, s[0]->InputCount());
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

TEST_F(TurboshaftInstructionSelectorTest, LoadAndShiftRight) {
  {
    int32_t immediates[] = {-256, -255, -3,   -2,   -1,    0,    1,
                            2,    3,    255,  256,  260,   4096, 4100,
                            8192, 8196, 3276, 3280, 16376, 16380};
    TRACED_FOREACH(int32_t, index, immediates) {
      StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer());
      auto load =
          m.Load(MachineType::Uint64(), m.Parameter(0), m.Int64Constant(index));
      auto sar = m.Emit(TSBinop::kWord64ShiftRightArithmetic, load,
                        m.Int32Constant(32));
      // Make sure we don't fold the shift into the following add:
      m.Return(m.Emit(TSBinop::kWord64Add, sar, m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kRiscvLw, s[0]->arch_opcode());
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      EXPECT_EQ(2U, s[0]->InputCount());
      EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
#if defined(V8_TARGET_LITTLE_ENDIAN)
      EXPECT_EQ(index + 4, s.ToInt32(s[0]->InputAt(1)));
#elif defined(V8_TARGET_BIG_ENDIAN)
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
#endif

      ASSERT_EQ(1U, s[0]->OutputCount());
    }
  }
}

// TEST_F(TurboshaftInstructionSelectorTest, Word32ReverseBytes) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Word32ReverseBytes(m.Parameter(0)));
//     Stream s = m.Build();
//     if (CpuFeatures::IsSupported(ZBB)) {
//       ASSERT_EQ(2U, s.size());
//       EXPECT_EQ(kRiscvRev8, s[0]->arch_opcode());
//       EXPECT_EQ(kRiscvShr64, s[1]->arch_opcode());
//       EXPECT_EQ(1U, s[0]->InputCount());
//       EXPECT_EQ(1U, s[0]->OutputCount());
//     } else {
//       ASSERT_EQ(1U, s.size());
//       EXPECT_EQ(kRiscvByteSwap32, s[0]->arch_opcode());
//       EXPECT_EQ(1U, s[0]->InputCount());
//       EXPECT_EQ(1U, s[0]->OutputCount());
//     }
//   }
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word64ReverseBytes) {
//   {
//     StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
//     m.Return(m.Word64ReverseBytes(m.Parameter(0)));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     if (CpuFeatures::IsSupported(ZBB)) {
//       EXPECT_EQ(kRiscvRev8, s[0]->arch_opcode());
//     } else {
//       EXPECT_EQ(kRiscvByteSwap64, s[0]->arch_opcode());
//     }
//     EXPECT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

TEST_F(TurboshaftInstructionSelectorTest, ExternalReferenceLoad1) {
  // Test offsets we can use kMode_Root for.
  const int64_t kOffsets[] = {0, 1, 4, INT32_MIN, INT32_MAX};
  TRACED_FOREACH(int64_t, offset, kOffsets) {
    StreamBuilder m(this, MachineType::Int64());
    ExternalReference reference =
        base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
    auto value = m.Load(MachineType::Int64(), m.ExternalConstant(reference));
    m.Return(value);

    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvLd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Root, s[0]->addressing_mode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToInt64(s[0]->InputAt(0)), offset);
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, ExternalReferenceLoad2) {
  // Offset too large, we cannot use kMode_Root.
  StreamBuilder m(this, MachineType::Int64());
  int64_t offset = 0x100000000;
  ExternalReference reference =
      base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
  auto value = m.Load(MachineType::Int64(), m.ExternalConstant(reference));
  m.Return(value);

  Stream s = m.Build();

  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kRiscvLd, s[0]->arch_opcode());
  EXPECT_NE(kMode_Root, s[0]->addressing_mode());
}

}  // namespace turboshaft
}  // namespace compiler
}  // namespace internal
}  // namespace v8
```