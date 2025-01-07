Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding and Goal:**

The immediate goal is to understand the functionality of the C++ code within the context of V8's compilation process, specifically for the MIPS64 architecture. The request asks for a summary of its function, consideration of Torque, JavaScript relevance, code logic reasoning with examples, common programming errors, and a final归纳.

**2. High-Level Overview and File Path:**

The file path `v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc` strongly suggests that this is a unit test file for the instruction selector component for the MIPS64 architecture in V8's compiler. The "unittest" part is a key indicator.

**3. Core Functionality - Unit Testing:**

The inclusion of `<#include "test/unittests/compiler/backend/instruction-selector-unittest.h">` confirms that this code is part of V8's testing infrastructure. The primary purpose is to test the `InstructionSelector`.

**4. What does the Instruction Selector do?**

The Instruction Selector is a crucial part of the compiler backend. It takes a platform-independent intermediate representation (likely the `RawMachineAssembler` used here) and translates it into machine-specific instructions for the target architecture (MIPS64 in this case).

**5. Examining the Code Structure - Test Cases:**

The code defines various test cases using the `TEST_P` and `TEST_F` macros. These are standard Google Test framework constructs. Each test case focuses on verifying the correct instruction selection for a specific operation or a group of related operations.

**6. Analyzing Specific Test Cases (Iterative Process):**

* **`InstructionSelectorFPCmpTest`:**  This tests floating-point comparison instructions (`Float64Equal`, `Float64LessThan`, etc.). It checks if the correct MIPS64 opcode (`kMips64CmpD`) is generated and if the flags are set correctly (`kFlags_set`). The `INSTANTIATE_TEST_SUITE_P` line provides the input values for the parameterized test.

* **`InstructionSelectorCmpTest`:** Similar to the above, but for integer comparisons (`WordEqual`, `Int32LessThan`, etc.). It checks the generated opcode (`kMips64Cmp`). There's a special check for `v8_flags.debug_code` and 32-bit words, suggesting extra debugging assertions are present in that case.

* **`InstructionSelectorShiftTest`:** Tests shift instructions (`Word32Shl`, `Word64Shr`, etc.) with immediate operands. It verifies the correct opcode (`kMips64Shl`, `kMips64Dshl`, etc.) and that the immediate value is correctly encoded.

* **More Complex Shift Tests (`Word32ShrWithWord32AndWithImmediate`, etc.):** These test combinations of operations (shift and AND) to see if specific MIPS64 instructions like `kMips64Ext` (extract bits) are generated when optimizations are possible.

* **`InstructionSelectorLogicalTest`:** Tests logical instructions (AND, OR, XOR).

* **Other Test Suites (`InstructionSelectorMulDivTest`, `InstructionSelectorModTest`):**  These follow the same pattern, testing multiplication, division, and modulo operations.

* **Conversion Tests (`kConversionInstructions`, `kFloat64RoundInstructions`, etc.):**  These focus on testing how type conversions are translated to MIPS64 instructions.

**7. Identifying Key Data Structures:**

The `MachInst` struct is fundamental. It holds information about a machine instruction: the C++ method in `RawMachineAssembler` that represents it, its name, the corresponding MIPS64 opcode, and the machine type it operates on. The `IntCmp`, `FPCmp`, and `Conversion` structs are variations tailored for specific instruction categories.

**8. Recognizing the Role of `RawMachineAssembler`:**

The `RawMachineAssembler` is used to construct the intermediate representation of the code being tested. The tests essentially create a small sequence of operations using `RawMachineAssembler` and then check if the `InstructionSelector` produces the expected MIPS64 instructions.

**9. Thinking about Torque and JavaScript:**

* **Torque:** The request specifically asks about `.tq` files. Since this file is `.cc`, it's standard C++, not Torque.
* **JavaScript:**  The connection to JavaScript lies in the fact that the instruction selector is responsible for generating machine code that *executes* JavaScript code. The operations being tested (addition, comparison, bitwise operations, etc.) are all fundamental to JavaScript's semantics. The examples generated illustrate these relationships.

**10. Code Logic Reasoning and Examples:**

For each test case, the logic is relatively straightforward:  create an IR snippet and assert that the generated assembly matches expectations. The examples generated show how the C++ code translates to underlying machine instructions for common operations.

**11. Common Programming Errors:**

The tests themselves implicitly reveal potential errors the instruction selector could make (wrong opcode, incorrect operand encoding). The generated examples highlight common JavaScript errors that could lead to certain machine instructions being executed.

**12. Synthesizing the Summary:**

Finally, the information gathered from the detailed analysis is synthesized into a concise summary covering the key functionalities of the code. This includes the purpose of unit testing, the role of the instruction selector, the architecture being tested, the use of the testing framework, and the connection to JavaScript.

**Self-Correction/Refinement during the process:**

* Initially, one might focus too much on the specific instructions. It's important to step back and understand the broader context of *why* these instructions are being tested.
* Recognizing the purpose of the `MachInst` struct is crucial for understanding how the tests are structured.
* The connection to JavaScript might not be immediately obvious. Connecting the tested operations to their JavaScript counterparts requires some knowledge of JavaScript semantics and how they are implemented at a lower level.
好的，这是对提供的V8源代码片段的功能归纳：

**功能归纳：**

这段C++代码是V8 JavaScript引擎中 **MIPS64架构** 的 **指令选择器（Instruction Selector）** 的 **单元测试（Unit Test）** 文件。  它的主要功能是验证指令选择器在将中间代码（由 `RawMachineAssembler` 构建）转换为 MIPS64 汇编指令时是否正确。

**具体来说，这个文件测试了以下几个方面的功能：**

1. **各种MIPS64指令的正确生成：**  针对不同的操作（例如：算术运算、逻辑运算、位移运算、比较运算、类型转换等），测试指令选择器是否能够生成预期的MIPS64机器指令。

2. **操作码（Opcode）的正确性：**  验证生成的机器指令的操作码是否与预期的MIPS64操作码一致。例如，`Word32And` 操作是否生成 `kMips64And32` 指令。

3. **操作数（Operand）的正确性：** 检查生成的机器指令的操作数数量和类型是否正确。例如，二元操作通常应该有两个输入操作数和一个输出操作数。

4. **标志位（Flags）的设置：** 对于会影响处理器标志位的指令（如比较指令），验证标志位的设置方式是否正确。

5. **特定优化模式下的指令生成：**  例如，测试在特定模式下（如涉及立即数或特定常量时）是否生成了更优化的MIPS64指令（例如，使用 `kMips64Ext` 或 `kMips64Ins` 指令进行位域操作）。

**关于文件后缀和 Torque：**

根据您提供的描述，`v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc` 的文件后缀是 `.cc`，这表明它是一个 **C++源代码文件**，而不是 Torque 源代码文件（Torque 文件的后缀通常是 `.tq`）。

**与 JavaScript 的关系：**

指令选择器是编译器后端的核心组件之一。它的作用是将高级的、平台无关的中间表示（Intermediate Representation, IR）转换为特定目标架构的机器指令。  对于 V8 引擎来说，它负责将 JavaScript 代码编译成可以在 MIPS64 架构上执行的机器码。

**JavaScript 示例说明：**

虽然这个文件本身不是 JavaScript 代码，但它测试的代码最终会用于执行 JavaScript。 例如，测试 `RawMachineAssembler::Int32Add` 和 `kMips64Add` 的对应关系，意味着当 JavaScript 中执行整数加法时，V8 的编译器会利用指令选择器生成 `kMips64Add` 这样的 MIPS64 指令。

```javascript
// JavaScript 代码示例
let a = 10;
let b = 5;
let sum = a + b; // 这行代码在编译后可能会用到 MIPS64 的加法指令
```

在这个简单的 JavaScript 例子中，`a + b` 这个操作会在 V8 的编译过程中，经过指令选择器，最终生成 MIPS64 的加法指令来完成计算。

**代码逻辑推理和假设输入输出：**

以 `InstructionSelectorCmpTest` 中的一个测试用例 `Word32Equal` 为例：

**假设输入（使用 `RawMachineAssembler` 构建的中间代码）：**

```c++
StreamBuilder m(this, type, type, type);
m.Return((m.*cmp.mi.constructor)(m.Parameter(0), m.Parameter(1)));
// 这里的 cmp.mi.constructor 指向的是 &RawMachineAssembler::Word32Equal
// m.Parameter(0) 和 m.Parameter(1) 代表两个 32 位的输入参数
```

**预期输出（生成的 MIPS64 汇编指令）：**

如果 `v8_flags.debug_code` 为真且类型为 `MachineType::Int32()`，则预期会生成包含 `kMips64Cmp` 和一些辅助指令（如 `kMips64Dshl` 和 `kMips64AssertEqual`）的指令序列。
否则，预期会生成一个 `kMips64Cmp` 指令。

**用户常见的编程错误（与测试内容相关）：**

这个测试文件关注的是编译器内部的正确性，但与用户编程错误也有间接关系。 例如，如果指令选择器在处理位运算时出现错误，可能会导致 JavaScript 中位运算的结果不正确。

**示例：**

```javascript
// JavaScript 代码
let x = 0b1010;
let y = 0b0101;
let result = x & y; // 位与运算

// 如果指令选择器对 Word32And 的处理有误，那么 result 的值可能不正确。
```

**总结 (针对第 1 部分)：**

这段 `v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc` 文件的主要功能是 **测试 V8 引擎中 MIPS64 架构的指令选择器是否能够正确地将中间代码转换为对应的 MIPS64 机器指令**。 它通过一系列的单元测试用例，针对不同的操作和场景，验证生成的指令的操作码、操作数和标志位设置是否符合预期，从而保证 V8 引擎在 MIPS64 架构上的代码生成质量和正确性。 它与 JavaScript 的关系在于，它测试的代码最终会被用来执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file

#include "test/unittests/compiler/backend/instruction-selector-unittest.h"

#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {
template <typename T>
struct MachInst {
  T constructor;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  MachineType machine_type;
};

template <typename T>
std::ostream& operator<<(std::ostream& os, const MachInst<T>& mi) {
  return os << mi.constructor_name;
}

using MachInst1 = MachInst<Node* (RawMachineAssembler::*)(Node*)>;
using MachInst2 = MachInst<Node* (RawMachineAssembler::*)(Node*, Node*)>;

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
    {{&RawMachineAssembler::Float64Equal, "Float64Equal", kMips64CmpD,
      MachineType::Float64()},
     kEqual},
    {{&RawMachineAssembler::Float64LessThan, "Float64LessThan", kMips64CmpD,
      MachineType::Float64()},
     kUnsignedLessThan},
    {{&RawMachineAssembler::Float64LessThanOrEqual, "Float64LessThanOrEqual",
      kMips64CmpD, MachineType::Float64()},
     kUnsignedLessThanOrEqual},
    {{&RawMachineAssembler::Float64GreaterThan, "Float64GreaterThan",
      kMips64CmpD, MachineType::Float64()},
     kUnsignedLessThan},
    {{&RawMachineAssembler::Float64GreaterThanOrEqual,
      "Float64GreaterThanOrEqual", kMips64CmpD, MachineType::Float64()},
     kUnsignedLessThanOrEqual}};

struct Conversion {
  // The machine_type field in MachInst1 represents the destination type.
  MachInst1 mi;
  MachineType src_machine_type;
};


// ----------------------------------------------------------------------------
// Logical instructions.
// ----------------------------------------------------------------------------

const MachInst2 kLogicalInstructions[] = {
    {&RawMachineAssembler::Word32And, "Word32And", kMips64And32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64And, "Word64And", kMips64And,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kMips64Or32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Or, "Word64Or", kMips64Or,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kMips64Xor32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Xor, "Word64Xor", kMips64Xor,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------


const MachInst2 kShiftInstructions[] = {
    {&RawMachineAssembler::Word32Shl, "Word32Shl", kMips64Shl,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Shl, "Word64Shl", kMips64Dshl,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Shr, "Word32Shr", kMips64Shr,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Shr, "Word64Shr", kMips64Dshr,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Sar, "Word32Sar", kMips64Sar,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Sar, "Word64Sar", kMips64Dsar,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Ror, "Word32Ror", kMips64Ror,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Ror, "Word64Ror", kMips64Dror,
     MachineType::Int64()}};


// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------


const MachInst2 kMulDivInstructions[] = {
    {&RawMachineAssembler::Int32Mul, "Int32Mul", kMips64Mul,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Div, "Int32Div", kMips64Div,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kMips64DivU,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int64Mul, "Int64Mul", kMips64Dmul,
     MachineType::Int64()},
    {&RawMachineAssembler::Int64Div, "Int64Div", kMips64Ddiv,
     MachineType::Int64()},
    {&RawMachineAssembler::Uint64Div, "Uint64Div", kMips64DdivU,
     MachineType::Uint64()},
    {&RawMachineAssembler::Float64Mul, "Float64Mul", kMips64MulD,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Div, "Float64Div", kMips64DivD,
     MachineType::Float64()}};


// ----------------------------------------------------------------------------
// MOD instructions.
// ----------------------------------------------------------------------------


const MachInst2 kModInstructions[] = {
    {&RawMachineAssembler::Int32Mod, "Int32Mod", kMips64Mod,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint32Mod, "Uint32Mod", kMips64ModU,
     MachineType::Int32()},
    {&RawMachineAssembler::Float64Mod, "Float64Mod", kMips64ModD,
     MachineType::Float64()}};


// ----------------------------------------------------------------------------
// Arithmetic FPU instructions.
// ----------------------------------------------------------------------------


const MachInst2 kFPArithInstructions[] = {
    {&RawMachineAssembler::Float64Add, "Float64Add", kMips64AddD,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Sub, "Float64Sub", kMips64SubD,
     MachineType::Float64()}};


// ----------------------------------------------------------------------------
// IntArithTest instructions, two nodes.
// ----------------------------------------------------------------------------


const MachInst2 kAddSubInstructions[] = {
    {&RawMachineAssembler::Int32Add, "Int32Add", kMips64Add,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Add, "Int64Add", kMips64Dadd,
     MachineType::Int64()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kMips64Sub,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Sub, "Int64Sub", kMips64Dsub,
     MachineType::Int64()}};


// ----------------------------------------------------------------------------
// IntArithTest instructions, one node.
// ----------------------------------------------------------------------------


const MachInst1 kAddSubOneInstructions[] = {
    {&RawMachineAssembler::Int32Neg, "Int32Neg", kMips64Sub,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Neg, "Int64Neg", kMips64Dsub,
     MachineType::Int64()}};


// ----------------------------------------------------------------------------
// Arithmetic compare instructions.
// ----------------------------------------------------------------------------


const IntCmp kCmpInstructions[] = {
    {{&RawMachineAssembler::WordEqual, "WordEqual", kMips64Cmp,
      MachineType::Int64()},
     1U},
    {{&RawMachineAssembler::WordNotEqual, "WordNotEqual", kMips64Cmp,
      MachineType::Int64()},
     1U},
    {{&RawMachineAssembler::Word32Equal, "Word32Equal", kMips64Cmp,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kMips64Cmp,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32LessThan, "Int32LessThan", kMips64Cmp,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
      kMips64Cmp, MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32GreaterThan, "Int32GreaterThan", kMips64Cmp,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32GreaterThanOrEqual, "Int32GreaterThanOrEqual",
      kMips64Cmp, MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kMips64Cmp,
      MachineType::Uint32()},
     1U},
    {{&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
      kMips64Cmp, MachineType::Uint32()},
     1U}};


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
    // mips instructions:
    // mtc1, cvt.d.w
    {{&RawMachineAssembler::ChangeInt32ToFloat64, "ChangeInt32ToFloat64",
      kMips64CvtDW, MachineType::Float64()},
     MachineType::Int32()},

    // mips instructions:
    // cvt.d.uw
    {{&RawMachineAssembler::ChangeUint32ToFloat64, "ChangeUint32ToFloat64",
      kMips64CvtDUw, MachineType::Float64()},
     MachineType::Int32()},

    // mips instructions:
    // mfc1, trunc double to word, for more details look at mips macro
    // asm and mips asm file
    {{&RawMachineAssembler::ChangeFloat64ToInt32, "ChangeFloat64ToInt32",
      kMips64TruncWD, MachineType::Float64()},
     MachineType::Int32()},

    // mips instructions:
    // trunc double to unsigned word, for more details look at mips macro
    // asm and mips asm file
    {{&RawMachineAssembler::ChangeFloat64ToUint32, "ChangeFloat64ToUint32",
      kMips64TruncUwD, MachineType::Float64()},
     MachineType::Int32()}};

const Conversion kFloat64RoundInstructions[] = {
    {{&RawMachineAssembler::Float64RoundUp, "Float64RoundUp", kMips64CeilWD,
      MachineType::Int32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::Float64RoundDown, "Float64RoundDown",
      kMips64FloorWD, MachineType::Int32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::Float64RoundTiesEven, "Float64RoundTiesEven",
      kMips64RoundWD, MachineType::Int32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::Float64RoundTruncate, "Float64RoundTruncate",
      kMips64TruncWD, MachineType::Int32()},
     MachineType::Float64()}};

const Conversion kFloat32RoundInstructions[] = {
    {{&RawMachineAssembler::Float32RoundUp, "Float32RoundUp", kMips64CeilWS,
      MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundDown, "Float32RoundDown",
      kMips64FloorWS, MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundTiesEven, "Float32RoundTiesEven",
      kMips64RoundWS, MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundTruncate, "Float32RoundTruncate",
      kMips64TruncWS, MachineType::Int32()},
     MachineType::Float32()}};

// MIPS64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kMips64Cmp,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan", kMips64Cmp,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
     kMips64Cmp, MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kMips64Cmp,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
     kMips64Cmp, MachineType::Uint32()},
};

}  // namespace

using InstructionSelectorFPCmpTest = InstructionSelectorTestWithParam<FPCmp>;

TEST_P(InstructionSelectorFPCmpTest, Parameter) {
  const FPCmp cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), cmp.mi.machine_type,
                  cmp.mi.machine_type);
  m.Return((m.*cmp.mi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.cond, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorFPCmpTest,
                         ::testing::ValuesIn(kFPCmpInstructions));

// ----------------------------------------------------------------------------
// Arithmetic compare instructions integers
// ----------------------------------------------------------------------------
using InstructionSelectorCmpTest = InstructionSelectorTestWithParam<IntCmp>;

TEST_P(InstructionSelectorCmpTest, Parameter) {
  const IntCmp cmp = GetParam();
  const MachineType type = cmp.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*cmp.mi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();

  if (v8_flags.debug_code &&
      type.representation() == MachineRepresentation::kWord32) {
    ASSERT_EQ(6U, s.size());

    EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());

    EXPECT_EQ(kMips64Dshl, s[1]->arch_opcode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());

    EXPECT_EQ(kMips64Dshl, s[2]->arch_opcode());
    EXPECT_EQ(2U, s[2]->InputCount());
    EXPECT_EQ(1U, s[2]->OutputCount());

    EXPECT_EQ(cmp.mi.arch_opcode, s[3]->arch_opcode());
    EXPECT_EQ(2U, s[3]->InputCount());
    EXPECT_EQ(1U, s[3]->OutputCount());

    EXPECT_EQ(kMips64AssertEqual, s[4]->arch_opcode());
    EXPECT_EQ(3U, s[4]->InputCount());
    EXPECT_EQ(0U, s[4]->OutputCount());

    EXPECT_EQ(cmp.mi.arch_opcode, s[5]->arch_opcode());
    EXPECT_EQ(2U, s[5]->InputCount());
    EXPECT_EQ(1U, s[5]->OutputCount());
  } else {
    ASSERT_EQ(cmp.expected_size, s.size());
    EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorCmpTest,
                         ::testing::ValuesIn(kCmpInstructions));

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------
using InstructionSelectorShiftTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorShiftTest, Immediate) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FORRANGE(int32_t, imm, 0,
                  ((1 << ElementSizeLog2Of(type.representation())) * 8) - 1) {
    StreamBuilder m(this, type, type);
    m.Return((m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorShiftTest,
                         ::testing::ValuesIn(kShiftInstructions));

TEST_F(InstructionSelectorTest, Word32ShrWithWord32AndWithImmediate) {
  // The available shift operand range is `0 <= imm < 32`, but we also test
  // that immediates outside this range are handled properly (modulo-32).
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t jnk = rng()->NextInt();
      jnk = (lsb > 0) ? (jnk >> (32 - lsb)) : 0;
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Shr(m.Word32And(m.Parameter(0), m.Int32Constant(msk)),
                           m.Int32Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kMips64Ext, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t jnk = rng()->NextInt();
      jnk = (lsb > 0) ? (jnk >> (32 - lsb)) : 0;
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Shr(m.Word32And(m.Int32Constant(msk), m.Parameter(0)),
                           m.Int32Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kMips64Ext, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}


TEST_F(InstructionSelectorTest, Word64ShrWithWord64AndWithImmediate) {
  // The available shift operand range is `0 <= imm < 64`, but we also test
  // that immediates outside this range are handled properly (modulo-64).
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int32_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int32_t, width, 1, 64 - lsb) {
      uint64_t jnk = rng()->NextInt64();
      jnk = (lsb > 0) ? (jnk >> (64 - lsb)) : 0;
      uint64_t msk =
          ((uint64_t{0xFFFFFFFFFFFFFFFF} >> (64 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64Shr(m.Word64And(m.Parameter(0), m.Int64Constant(msk)),
                           m.Int64Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kMips64Dext, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int32_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int32_t, width, 1, 64 - lsb) {
      uint64_t jnk = rng()->NextInt64();
      jnk = (lsb > 0) ? (jnk >> (64 - lsb)) : 0;
      uint64_t msk =
          ((uint64_t{0xFFFFFFFFFFFFFFFF} >> (64 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64Shr(m.Word64And(m.Int64Constant(msk), m.Parameter(0)),
                           m.Int64Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kMips64Dext, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
}


TEST_F(InstructionSelectorTest, Word32AndToClearBits) {
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    int32_t mask = ~((1 << shift) - 1);
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32And(m.Parameter(0), m.Int32Constant(mask)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Ins, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(shift, s.ToInt32(s[0]->InputAt(2)));
  }
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    int32_t mask = ~((1 << shift) - 1);
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32And(m.Int32Constant(mask), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Ins, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(shift, s.ToInt32(s[0]->InputAt(2)));
  }
}


TEST_F(InstructionSelectorTest, Word64AndToClearBits) {
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    int64_t mask = ~((1 << shift) - 1);
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64And(m.Parameter(0), m.Int64Constant(mask)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Dins, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(shift, s.ToInt32(s[0]->InputAt(2)));
  }
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    int64_t mask = ~((1 << shift) - 1);
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64And(m.Int64Constant(mask), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Dins, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(shift, s.ToInt32(s[0]->InputAt(2)));
  }
}


// ----------------------------------------------------------------------------
// Logical instructions.
// ----------------------------------------------------------------------------
using InstructionSelectorLogicalTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorLogicalTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorLogicalTest,
                         ::testing::ValuesIn(kLogicalInstructions));

TEST_F(InstructionSelectorTest, Word64XorMinusOneWithParameter) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Xor(m.Parameter(0), m.Int64Constant(-1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Nor, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Xor(m.Int64Constant(-1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Nor, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, Word32XorMinusOneWithParameter) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Xor(m.Parameter(0), m.Int32Constant(-1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Nor32, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Xor(m.Int32Constant(-1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Nor32, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, Word64XorMinusOneWithWord64Or) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Xor(m.Word64Or(m.Parameter(0), m.Parameter(0)),
                         m.Int64Constant(-1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Nor, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Xor(m.Int64Constant(-1),
                         m.Word64Or(m.Parameter(0), m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Nor, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, Word32XorMinusOneWithWord32Or) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Xor(m.Word32Or(m.Parameter(0), m.Parameter(0)),
                         m.Int32Constant(-1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Nor32, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Xor(m.Int32Constant(-1),
                         m.Word32Or(m.Parameter(0), m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Nor32, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, Word32AndWithImmediateWithWord32Shr) {
  // The available shift operand range is `0 <= imm < 32`, but we also test
  // that immediates outside this range are handled properly (modulo-32).
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 31) {
      uint32_t msk = (1 << width) - 1;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32And(m.Word32Shr(m.Parameter(0), m.Int32Constant(shift)),
                           m.Int32Constant(msk)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kMips64Ext, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      int32_t actual_width = (lsb + width > 32) ? (32 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 31) {
      uint32_t msk = (1 << width) - 1;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(
          m.Word32And(m.Int32Constant(msk),
                      m.Word32Shr(m.Parameter(0), m.Int32Constant(shift))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kMips64Ext, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      int32_t actual_width = (lsb + width > 32) ? (32 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}


TEST_F(InstructionSelectorTest, Word64AndWithImmediateWithWord64Shr) {
  // The available shift operand range is `0 <= imm < 64`, but we also test
  // that immediates outside this range are handled properly (modulo-64).
  TRACED_FORRANGE(int64_t, shift, -64, 127) {
    int64_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int64_t, width, 1, 63) {
      uint64_t msk = (uint64_t{1} << width) - 1;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64And(m.Word64Shr(m.Parameter(0), m.Int64Constant(shift)),
                           m.Int64Constant(msk)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kMips64Dext, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      int64_t actual_width = (lsb + width > 64) ? (64 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int64_t, shift, -64, 127) {
    int64_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int64_t, width, 1, 63) {
      uint64_t msk = (uint64_t{1} << width) - 1;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(
          m.Word64And(m.Int64Constant(msk),
                      m.Word64Shr(m.Parameter(0), m.Int64Constant(shift))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kMips64Dext, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      int64_t actual_width = (lsb + width > 64) ? (64 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
}


TEST_F(InstructionSelectorTest, Word32ShlWithWord32And) {
  TRACED_FORRANGE(int32_t, shift, 0, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Shl(m.Word32And(p0, m.Int32Constant((1 << (31 - shift)) - 1)),
                    m.Int32Constant(shift + 1));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Shl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Word64ShlWithWord64And) {
  TRACED_FORRANGE(int32_t, shift, 0, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word64Shl(m.Word64And(p0, m.Int64Constant((1L << (63 - shift)) - 1)),
                    m.Int64Constant(shift + 1));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Dshl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word32SarWithWord32Shl) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(24)), m.Int32Constant(24));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Seb, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(16)), m.Int32Constant(16));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Seh, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(32)), m.Int32Constant(32));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Shl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}

// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------
using InstructionSelectorMulDivTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorMulDivTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorMulDivTest,
                         ::testing::ValuesIn(kMulDivInstructions));

// ----------------------------------------------------------------------------
// MOD instructions.
// ----------------------------------------------------------------------------
using InstructionSelectorModTest = InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorModTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorModTest,
                         ::testing::ValuesIn(kModInstructions));

// ----------------------------------------------------------------------------
// Floating point instructions.
// ------------------------------------------------------
"""


```