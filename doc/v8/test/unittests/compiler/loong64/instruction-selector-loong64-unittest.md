Response: Let's break down the thought process for analyzing this C++ file and relating it to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the file's functionality and a connection to JavaScript with an example. This means we need to identify the core purpose of the code and how it relates to the broader V8 project and, specifically, JavaScript execution.

2. **Initial Scan for Keywords and Structure:** A quick scan reveals keywords like "test," "unittest," "compiler," "instruction-selector," "loong64," and architecture-specific instructions (e.g., `kLoong64Add_w`). The file structure includes `#include` directives, namespaces (`v8`, `internal`, `compiler`), template structures (`MachInst`, `IntCmp`, `FPCmp`, `Conversion`), and `TEST_P` and `TEST_F` macros, which are strong indicators of a unit testing framework.

3. **Identify the Core Functionality:** Based on the keywords and structure, the primary function of this file is **unit testing the instruction selector for the LoongArch64 architecture within the V8 JavaScript engine's compiler**. The "instruction selector" is the component responsible for translating high-level intermediate representations of code (likely from the V8 compiler's *Turbofan* phase) into low-level machine instructions.

4. **Deconstruct the Test Structure:** The file defines various test structures (`MachInst`, `IntCmp`, etc.) that encapsulate information about individual machine instructions:
    * `MachInst`: Stores the C++ function pointer to generate the instruction, its name, the corresponding architecture opcode (`arch_opcode`), and the data type it operates on (`machine_type`).
    * `IntCmp`, `FPCmp`, `Conversion`:  Specializations of `MachInst` to represent comparison and conversion instructions, respectively, often including additional relevant information like flags conditions.

5. **Analyze the Test Cases:** The `TEST_P` and `TEST_F` macros define individual test cases.
    * `TEST_P` (parameterized tests):  These tests iterate over collections of instruction data defined by the `k...Instructions` arrays. The test logic generally involves:
        * Building a code snippet using `RawMachineAssembler` (a low-level interface for constructing intermediate code).
        * Returning the instruction under test.
        * Building a "stream" representing the generated machine instructions.
        * Asserting that the generated stream has the expected size and contains the correct opcode, input/output counts, and flags settings.
    * `TEST_F` (fixture tests): These tests are more specific and test particular combinations or optimizations (e.g., combining `Word32Shr` and `Word32And`).

6. **Connect to JavaScript:** The core relationship lies in the **compilation process**. When JavaScript code is executed by V8, it goes through several stages, including parsing, bytecode generation, and *optimization compilation* by Turbofan. The instruction selector is a crucial part of the optimization compilation phase. It takes the optimized intermediate representation of the JavaScript code and translates it into the actual machine instructions that the processor will execute.

7. **Formulate the JavaScript Example:** To illustrate the connection, we need a JavaScript snippet that, when compiled by V8 on a LoongArch64 system, would likely involve some of the instructions tested in the C++ file. Good candidates are:
    * **Arithmetic operations:** `+`, `-`, `*`, `/`, `%`, bitwise operators (`&`, `|`, `^`, `<<`, `>>`, `>>>`).
    * **Comparisons:** `==`, `!=`, `<`, `>`, `<=`, `>=`.
    * **Type conversions:** Explicit conversions like `Number()`, `parseInt()`, or implicit conversions.
    * **Math functions:** `Math.floor()`, `Math.ceil()`, etc.

    The example `let a = 10; let b = 5; let c = a + b;` is simple and directly involves an addition operation, which would likely be translated to a LoongArch64 addition instruction (like `kLoong64Add_w` or `kLoong64Add_d` depending on the data types).

8. **Refine and Structure the Answer:** Organize the findings into a clear and concise summary. Start with the main purpose of the file, then elaborate on the testing mechanism, and finally, explain the connection to JavaScript with a concrete example. Emphasize the role of the instruction selector in the compilation pipeline.

9. **Review and Verify:**  Read through the generated answer to ensure accuracy and clarity. Check if the JavaScript example effectively illustrates the concept. Make sure the technical terms are explained adequately.

Self-Correction/Refinement during the process:

* **Initial thought:**  Focus heavily on the C++ details of the test framework.
* **Correction:**  Shift focus to *why* this C++ code exists – to test a core component of V8's compilation process for a specific architecture.
* **Initial thought:** The JavaScript example could be very complex to demonstrate a specific instruction.
* **Correction:** A simple, common JavaScript operation like addition is sufficient to illustrate the general principle of compilation down to machine instructions. The specifics of *which* instruction is less important than showing the link between JavaScript and the machine code.
* **Initial thought:**  Oversimplify the instruction selector's role.
* **Correction:**  Emphasize that it translates *optimized* intermediate representations, highlighting its place in the *optimization compilation* phase.
这个 C++ 源代码文件 `instruction-selector-loong64-unittest.cc` 的主要功能是**对 V8 JavaScript 引擎中针对 LoongArch64 架构的指令选择器 (instruction selector) 进行单元测试。**

更具体地说，这个文件通过一系列的测试用例来验证指令选择器是否能够为各种高级的中间表示 (IR) 操作正确地生成对应的 LoongArch64 汇编指令。

**以下是该文件的一些关键特点和功能点：**

* **测试指令选择器的正确性:**  它通过模拟编译器后端的部分流程，构造一些 IR 节点 (例如，表示加法、位运算、比较等操作)，然后调用指令选择器来生成对应的 LoongArch64 指令。
* **覆盖多种指令类型:**  文件中定义了多种测试用例，覆盖了 LoongArch64 架构中常见的算术运算、逻辑运算、移位操作、乘除法、浮点运算、比较操作、类型转换以及内存访问指令。
* **使用 `RawMachineAssembler`:**  测试用例使用 `RawMachineAssembler` 来创建底层的机器码表示，这允许精确地控制生成的 IR 结构。
* **断言 (Assertions):**  每个测试用例都使用断言 (`ASSERT_EQ`, `EXPECT_EQ`) 来验证生成的指令是否符合预期，例如指令的操作码 (`arch_opcode`)、输入/输出数量、寻址模式、标志位设置等。
* **参数化测试 (`TEST_P`):**  为了减少代码重复，许多测试用例使用了参数化测试，可以针对同一类指令的不同变体进行批量测试。例如，`kLogicalInstructions` 数组包含了多种逻辑运算指令，`InstructionSelectorLogicalTest` 可以遍历这个数组进行测试。
* **针对特定优化场景的测试 (`TEST_F`):**  一些测试用例 (`TEST_F`) 针对特定的指令选择优化场景进行测试，例如，测试指令选择器是否能将一些特定的 IR 模式识别并转换为更高效的 LoongArch64 指令 (例如，将 `Word32Shr` 和 `Word32And` 的特定组合优化为 `kLoong64Bstrpick_w`)。
* **内存访问测试:**  文件中还包含了对内存加载 (`Load`) 和存储 (`Store`) 指令的测试，包括带有立即数偏移的寻址模式。
* **类型转换测试:**  测试了各种数据类型之间的转换指令的生成。

**与 JavaScript 功能的关系：**

该文件直接关系到 V8 引擎执行 JavaScript 代码的性能和正确性。当 V8 编译 JavaScript 代码时，会将其转换为一种中间表示。然后，指令选择器负责将这种中间表示翻译成目标架构 (在这里是 LoongArch64) 的机器指令。

如果指令选择器工作不正确，可能会导致以下问题：

* **性能下降:** 生成了低效的机器指令，导致 JavaScript 代码执行速度变慢。
* **错误的结果:** 生成了错误的机器指令，导致 JavaScript 代码产生错误的结果。
* **崩溃或不稳定:** 在某些情况下，错误的指令生成甚至可能导致程序崩溃。

**JavaScript 举例说明：**

以下是一些简单的 JavaScript 代码示例，当 V8 引擎在 LoongArch64 架构上编译执行时，可能会涉及到该测试文件中测试的某些 LoongArch64 指令：

```javascript
// 算术运算 (可能涉及到 kLoong64Add_w, kLoong64Sub_w, kLoong64Mul_w, 等)
let a = 10;
let b = 5;
let c = a + b;
let d = a * b;

// 位运算 (可能涉及到 kLoong64And32, kLoong64Or32, kLoong64Sll_w, 等)
let x = 0b1010;
let y = 0b0101;
let z = x & y;
let w = x << 2;

// 比较运算 (可能涉及到 kLoong64Cmp32, 并影响条件分支指令)
if (c > d) {
  console.log("c is greater than d");
}

// 浮点运算 (可能涉及到 kLoong64Float64Add, kLoong64Float64Mul, 等)
let pi = 3.14159;
let radius = 5.0;
let area = pi * radius * radius;

// 类型转换 (可能涉及到 kLoong64Int32ToFloat64, kLoong64Float64ToInt32, 等)
let intValue = 42;
let floatValue = Number(intValue);
let anotherIntValue = parseInt("100");

// 内存访问 (例如访问数组元素或对象属性，可能涉及到 kLoong64Ld_w, kLoong64St_w, 等)
let arr = [1, 2, 3];
let firstElement = arr[0];
arr[1] = 4;
```

当 V8 编译这些 JavaScript 代码时，指令选择器会根据代码中的操作，选择合适的 LoongArch64 指令来实现这些功能。例如，`a + b` 可能会被翻译成 `kLoong64Add_w` 指令，`x & y` 可能会被翻译成 `kLoong64And32` 指令，依此类推。  `instruction-selector-loong64-unittest.cc` 这个文件正是用来确保这个翻译过程的正确性。

总而言之，`instruction-selector-loong64-unittest.cc` 是 V8 引擎针对 LoongArch64 架构的关键测试文件，它保证了 JavaScript 代码在该架构上能够高效且正确地执行。

### 提示词
```
这是目录为v8/test/unittests/compiler/loong64/instruction-selector-loong64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file

#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/backend/instruction-selector-unittest.h"

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
    {{&RawMachineAssembler::Float64Equal, "Float64Equal", kLoong64Float64Cmp,
      MachineType::Float64()},
     kEqual},
    {{&RawMachineAssembler::Float64LessThan, "Float64LessThan",
      kLoong64Float64Cmp, MachineType::Float64()},
     kUnsignedLessThan},
    {{&RawMachineAssembler::Float64LessThanOrEqual, "Float64LessThanOrEqual",
      kLoong64Float64Cmp, MachineType::Float64()},
     kUnsignedLessThanOrEqual},
    {{&RawMachineAssembler::Float64GreaterThan, "Float64GreaterThan",
      kLoong64Float64Cmp, MachineType::Float64()},
     kUnsignedLessThan},
    {{&RawMachineAssembler::Float64GreaterThanOrEqual,
      "Float64GreaterThanOrEqual", kLoong64Float64Cmp, MachineType::Float64()},
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
    {&RawMachineAssembler::Word32And, "Word32And", kLoong64And32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64And, "Word64And", kLoong64And,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kLoong64Or32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Or, "Word64Or", kLoong64Or,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kLoong64Xor32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Xor, "Word64Xor", kLoong64Xor,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------

const MachInst2 kShiftInstructions[] = {
    {&RawMachineAssembler::Word32Shl, "Word32Shl", kLoong64Sll_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Shl, "Word64Shl", kLoong64Sll_d,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Shr, "Word32Shr", kLoong64Srl_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Shr, "Word64Shr", kLoong64Srl_d,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Sar, "Word32Sar", kLoong64Sra_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Sar, "Word64Sar", kLoong64Sra_d,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Ror, "Word32Ror", kLoong64Rotr_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Ror, "Word64Ror", kLoong64Rotr_d,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------

const MachInst2 kMulDivInstructions[] = {
    {&RawMachineAssembler::Int32Mul, "Int32Mul", kLoong64Mul_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Div, "Int32Div", kLoong64Div_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kLoong64Div_wu,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int64Mul, "Int64Mul", kLoong64Mul_d,
     MachineType::Int64()},
    {&RawMachineAssembler::Int64Div, "Int64Div", kLoong64Div_d,
     MachineType::Int64()},
    {&RawMachineAssembler::Uint64Div, "Uint64Div", kLoong64Div_du,
     MachineType::Uint64()},
    {&RawMachineAssembler::Float64Mul, "Float64Mul", kLoong64Float64Mul,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Div, "Float64Div", kLoong64Float64Div,
     MachineType::Float64()}};

// ----------------------------------------------------------------------------
// MOD instructions.
// ----------------------------------------------------------------------------

const MachInst2 kModInstructions[] = {
    {&RawMachineAssembler::Int32Mod, "Int32Mod", kLoong64Mod_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint32Mod, "Uint32Mod", kLoong64Mod_wu,
     MachineType::Int32()},
    {&RawMachineAssembler::Float64Mod, "Float64Mod", kLoong64Float64Mod,
     MachineType::Float64()}};

// ----------------------------------------------------------------------------
// Arithmetic FPU instructions.
// ----------------------------------------------------------------------------

const MachInst2 kFPArithInstructions[] = {
    {&RawMachineAssembler::Float64Add, "Float64Add", kLoong64Float64Add,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Sub, "Float64Sub", kLoong64Float64Sub,
     MachineType::Float64()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, two nodes.
// ----------------------------------------------------------------------------

const MachInst2 kAddSubInstructions[] = {
    {&RawMachineAssembler::Int32Add, "Int32Add", kLoong64Add_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Add, "Int64Add", kLoong64Add_d,
     MachineType::Int64()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kLoong64Sub_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Sub, "Int64Sub", kLoong64Sub_d,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, one node.
// ----------------------------------------------------------------------------

const MachInst1 kAddSubOneInstructions[] = {
    {&RawMachineAssembler::Int32Neg, "Int32Neg", kLoong64Sub_w,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Neg, "Int64Neg", kLoong64Sub_d,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// Arithmetic compare instructions.
// ----------------------------------------------------------------------------

const IntCmp kCmpInstructions[] = {
    {{&RawMachineAssembler::WordEqual, "WordEqual", kLoong64Cmp64,
      MachineType::Int64()},
     1U},
    {{&RawMachineAssembler::WordNotEqual, "WordNotEqual", kLoong64Cmp64,
      MachineType::Int64()},
     1U},
    {{&RawMachineAssembler::Word32Equal, "Word32Equal", kLoong64Cmp32,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kLoong64Cmp32,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32LessThan, "Int32LessThan", kLoong64Cmp32,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
      kLoong64Cmp32, MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32GreaterThan, "Int32GreaterThan", kLoong64Cmp32,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32GreaterThanOrEqual, "Int32GreaterThanOrEqual",
      kLoong64Cmp32, MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kLoong64Cmp32,
      MachineType::Uint32()},
     1U},
    {{&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
      kLoong64Cmp32, MachineType::Uint32()},
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
    {{&RawMachineAssembler::ChangeInt32ToFloat64, "ChangeInt32ToFloat64",
      kLoong64Int32ToFloat64, MachineType::Float64()},
     MachineType::Int32()},

    {{&RawMachineAssembler::ChangeUint32ToFloat64, "ChangeUint32ToFloat64",
      kLoong64Uint32ToFloat64, MachineType::Float64()},
     MachineType::Int32()},

    {{&RawMachineAssembler::ChangeFloat64ToInt32, "ChangeFloat64ToInt32",
      kLoong64Float64ToInt32, MachineType::Float64()},
     MachineType::Int32()},

    {{&RawMachineAssembler::ChangeFloat64ToUint32, "ChangeFloat64ToUint32",
      kLoong64Float64ToUint32, MachineType::Float64()},
     MachineType::Int32()}};

// LOONG64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kLoong64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan", kLoong64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
     kLoong64Cmp32, MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kLoong64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
     kLoong64Cmp32, MachineType::Uint32()},
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

  ASSERT_EQ(cmp.expected_size, s.size());
  EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
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
      EXPECT_EQ(kLoong64Bstrpick_w, s[0]->arch_opcode());
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
      EXPECT_EQ(kLoong64Bstrpick_w, s[0]->arch_opcode());
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
      EXPECT_EQ(kLoong64Bstrpick_d, s[0]->arch_opcode());
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
      EXPECT_EQ(kLoong64Bstrpick_d, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Bstrins_w, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Bstrins_w, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Bstrins_d, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Bstrins_d, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Nor, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Xor(m.Int64Constant(-1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Nor, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Nor32, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Xor(m.Int32Constant(-1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Nor32, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Nor, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Xor(m.Int64Constant(-1),
                         m.Word64Or(m.Parameter(0), m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Nor, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Nor32, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Xor(m.Int32Constant(-1),
                         m.Word32Or(m.Parameter(0), m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Nor32, s[0]->arch_opcode());
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
      EXPECT_EQ(kLoong64Bstrpick_w, s[0]->arch_opcode());
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
      EXPECT_EQ(kLoong64Bstrpick_w, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      int32_t actual_width = (lsb + width > 32) ? (32 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt32(s[0]->InputAt(2)));
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
    EXPECT_EQ(kLoong64Sll_w, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Sll_d, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Ext_w_b, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Ext_w_h, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Sll_w, s[0]->arch_opcode());
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
// ----------------------------------------------------------------------------

using InstructionSelectorFPArithTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorFPArithTest, Parameter) {
  const MachInst2 fpa = GetParam();
  StreamBuilder m(this, fpa.machine_type, fpa.machine_type, fpa.machine_type);
  m.Return((m.*fpa.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(fpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorFPArithTest,
                         ::testing::ValuesIn(kFPArithInstructions));

// ----------------------------------------------------------------------------
// Integer arithmetic
// ----------------------------------------------------------------------------
using InstructionSelectorIntArithTwoTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorIntArithTwoTest, Parameter) {
  const MachInst2 intpa = GetParam();
  StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
                  intpa.machine_type);
  m.Return((m.*intpa.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorIntArithTwoTest,
                         ::testing::ValuesIn(kAddSubInstructions));

// ----------------------------------------------------------------------------
// One node.
// ----------------------------------------------------------------------------

using InstructionSelectorIntArithOneTest =
    InstructionSelectorTestWithParam<MachInst1>;

TEST_P(InstructionSelectorIntArithOneTest, Parameter) {
  const MachInst1 intpa = GetParam();
  StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
                  intpa.machine_type);
  m.Return((m.*intpa.constructor)(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorIntArithOneTest,
                         ::testing::ValuesIn(kAddSubOneInstructions));

// ----------------------------------------------------------------------------
// Conversions.
// ----------------------------------------------------------------------------

using InstructionSelectorConversionTest =
    InstructionSelectorTestWithParam<Conversion>;

TEST_P(InstructionSelectorConversionTest, Parameter) {
  const Conversion conv = GetParam();
  StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
  m.Return((m.*conv.mi.constructor)(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorConversionTest,
                         ::testing::ValuesIn(kConversionInstructions));

TEST_F(InstructionSelectorTest, ChangesFromToSmi) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.TruncateInt64ToInt32(
        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Sra_d, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Word64Shl(m.ChangeInt32ToInt64(m.Parameter(0)), m.Int32Constant(32)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Sll_d, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ChangeFloat64ToInt32OfChangeFloat32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
    m.Return(m.ChangeFloat64ToInt32(m.ChangeFloat32ToFloat64(m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kLoong64Float32ToFloat64, s[0]->arch_opcode());
    EXPECT_EQ(kLoong64Float64ToInt32, s[1]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest,
       TruncateFloat64ToFloat32OfChangeInt32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Int32());
    m.Return(
        m.TruncateFloat64ToFloat32(m.ChangeInt32ToFloat64(m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Int32ToFloat32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, CombineShiftsWithMul) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Word64Sar(m.Parameter(0), m.Int32Constant(32)),
                        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Mulh_d, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, CombineShiftsWithDivMod) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Div(m.Word64Sar(m.Parameter(0), m.Int32Constant(32)),
                        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Div_d, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mod(m.Word64Sar(m.Parameter(0), m.Int32Constant(32)),
                        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Mod_d, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ChangeInt32ToInt64AfterLoad) {
  // For each case, test that the conversion is merged into the load
  // operation.
  // ChangeInt32ToInt64(Load_Uint8) -> Ld_bu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_bu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int8) -> Ld_b
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_b, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint16) -> Ld_hu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_hu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int16) -> Ld_h
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_h, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint32) -> Ld_w
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_w, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int32) -> Ld_w
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_w, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

using InstructionSelectorElidedChangeUint32ToUint64Test =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorElidedChangeUint32ToUint64Test, Parameter) {
  const MachInst2 binop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), binop.machine_type,
                  binop.machine_type);
  m.Return(m.ChangeUint32ToUint64(
      (m.*binop.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  // Make sure the `ChangeUint32ToUint64` node turned into a no-op.
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorElidedChangeUint32ToUint64Test,
                         ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

TEST_F(InstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // Ld_bu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_bu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // Ld_hu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_hu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // Ld_wu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_wu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
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
    {MachineType::Int8(), kLoong64Ld_b, kLoong64St_b},
    {MachineType::Uint8(), kLoong64Ld_bu, kLoong64St_b},
    {MachineType::Int16(), kLoong64Ld_h, kLoong64St_h},
    {MachineType::Uint16(), kLoong64Ld_hu, kLoong64St_h},
    {MachineType::Int32(), kLoong64Ld_w, kLoong64St_w},
    {MachineType::Float32(), kLoong64Fld_s, kLoong64Fst_s},
    {MachineType::Float64(), kLoong64Fld_d, kLoong64Fst_d},
    {MachineType::Int64(), kLoong64Ld_d, kLoong64St_d}};

struct MemoryAccessImm {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
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
  bool (InstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[5];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm1& acc) {
  return os << acc.type;
}

struct MemoryAccessImm2 {
  MachineType type;
  ArchOpcode store_opcode;
  ArchOpcode store_opcode_unaligned;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};

// ----------------------------------------------------------------------------
// Loads and stores immediate values
// ----------------------------------------------------------------------------

const MemoryAccessImm kMemoryAccessesImm[] = {
    {MachineType::Int8(),
     kLoong64Ld_b,
     kLoong64St_b,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint8(),
     kLoong64Ld_bu,
     kLoong64St_b,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int16(),
     kLoong64Ld_h,
     kLoong64St_h,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint16(),
     kLoong64Ld_hu,
     kLoong64St_h,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kLoong64Ld_w,
     kLoong64St_w,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kLoong64Fld_s,
     kLoong64Fst_s,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kLoong64Fld_d,
     kLoong64Fst_d,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kLoong64Ld_d,
     kLoong64St_d,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kLoong64Ld_b,
     kLoong64St_b,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kLoong64Ld_bu,
     kLoong64St_b,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kLoong64Ld_h,
     kLoong64St_h,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kLoong64Ld_hu,
     kLoong64St_h,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kLoong64Ld_w,
     kLoong64St_w,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kLoong64Fld_s,
     kLoong64Fst_s,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kLoong64Fld_d,
     kLoong64Fst_d,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kLoong64Ld_d,
     kLoong64St_d,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}}};

}  // namespace

using InstructionSelectorMemoryAccessTest =
    InstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

TEST_P(InstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                  MachineType::Int32(), memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Parameter(1),
          kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// ----------------------------------------------------------------------------
// Load immediate.
// ----------------------------------------------------------------------------

using InstructionSelectorMemoryAccessImmTest =
    InstructionSelectorTestWithParam<MemoryAccessImm>;

TEST_P(InstructionSelectorMemoryAccessImmTest, LoadWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
    Stream s = m.Build();
    MachineRepresentation rep_type = memacc.type.representation();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    if (((rep_type == MachineRepresentation::kWord64 ||
          rep_type == MachineRepresentation::kWord32) &&
         is_int16(index) && ((index & 0b11) == 0)) ||
        is_int12(index)) {
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    } else {
      EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
      ASSERT_EQ(InstructionOperand::UNALLOCATED, s[0]->InputAt(1)->kind());
    }
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
  }
}

// ----------------------------------------------------------------------------
// Store immediate.
// ----------------------------------------------------------------------------

TEST_P(InstructionSelectorMemoryAccessImmTest, StoreWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    MachineRepresentation rep_type = memacc.type.representation();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    if (((rep_type == MachineRepresentation::kWord64 ||
          rep_type == MachineRepresentation::kWord32) &&
         is_int16(index) && ((index & 0b11) == 0)) ||
        is_int12(index)) {
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    } else {
      EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
      ASSERT_EQ(InstructionOperand::UNALLOCATED, s[0]->InputAt(1)->kind());
    }
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorMemoryAccessImmTest, StoreZero) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Int32Constant(0), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    MachineRepresentation rep_type = memacc.type.representation();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    if (((rep_type == MachineRepresentation::kWord64 ||
          rep_type == MachineRepresentation::kWord32) &&
         is_int16(index) && ((index & 0b11) == 0)) ||
        is_int12(index)) {
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    } else {
      ASSERT_EQ(InstructionOperand::UNALLOCATED, s[0]->InputAt(1)->kind());
      EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    }
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImm));

// ----------------------------------------------------------------------------
// Load/store offsets more than 16 bits.
// ----------------------------------------------------------------------------

using InstructionSelectorMemoryAccessImmMoreThan16bitTest =
    InstructionSelectorTestWithParam<MemoryAccessImm1>;

TEST_P(InstructionSelectorMemoryAccessImmMoreThan16bitTest,
       LoadWithImmediateIndex) {
  const MemoryAccessImm1 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorMemoryAccessImmMoreThan16bitTest,
       StoreWithImmediateIndex) {
  const MemoryAccessImm1 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmMoreThan16bitTest,
                         ::testing::ValuesIn(kMemoryAccessImmMoreThan16bit));

// ----------------------------------------------------------------------------
// kLoong64Cmp with zero testing.
// ----------------------------------------------------------------------------

TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word64EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Equal(m.Parameter(0), m.Int64Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Cmp64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Equal(m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Cmp64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Clz_w, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Word64Clz) {
  StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint64());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word64Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Clz_d, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float32Abs) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Float32Abs(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Float32Abs, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float64Abs) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Float64Abs(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Float64Abs, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float64Max) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Float64Max(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Float64Max, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float64Min) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Float64Min(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Float64Min, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, LoadAndShiftRight) {
  {
    int32_t immediates[] = {-256, -255, -3,   -2,   -1,    0,    1,
                            2,    3,    255,  256,  260,   4096, 4100,
                            8192, 8196, 3276, 3280, 16376, 16380};
    TRACED_FOREACH(int32_t, index, immediates) {
      StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer());
      Node* const load =
          m.Load(MachineType::Uint64(), m.Parameter(0), m.Int32Constant(index));
      Node* const sar = m.Word64Sar(load, m.Int32Constant(32));
      // Make sure we don't fold the shift into the following add:
      m.Return(m.Int64Add(sar, m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kLoong64Ld_w, s[0]->arch_opcode());
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      EXPECT_EQ(2U, s[0]->InputCount());
      EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index + 4, s.ToInt32(s[0]->InputAt(1)));
      ASSERT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(InstructionSelectorTest, Word32ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64ByteSwap32, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, Word64ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64ByteSwap64, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```