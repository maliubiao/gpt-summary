Response: Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The file name itself, `instruction-selector-riscv32-unittest.cc`, is a huge clue. It strongly suggests this file tests the instruction selector component of the V8 compiler specifically for the RISC-V 32-bit architecture. The "unittest" part confirms it's about isolated testing of this component.

2. **Scan for Key V8 Concepts:**  Look for familiar terms and namespaces related to V8's internal workings:
    * `v8::internal::compiler`:  This clearly indicates the code is within the compiler pipeline.
    * `RawMachineAssembler`: This class is used to build machine code instructions in a platform-independent way during compiler testing.
    * `Node`:  Represents nodes in the compiler's intermediate representation (IR) graph.
    * `MachineType`: Specifies the data type being operated on (e.g., `Int32`, `Float64`).
    * `ArchOpcode`: Represents the specific machine instruction (e.g., `kRiscvAdd32`).
    * `InstructionSelectorTest`:  A base class likely providing utilities for setting up and running instruction selector tests.
    * `StreamBuilder` and `Stream`: Classes used for constructing and inspecting the generated instruction stream.

3. **Recognize the Test Structure:** The file uses the Google Test framework (`TEST_P`, `TEST_F`, `INSTANTIATE_TEST_SUITE_P`). This immediately tells you the tests are organized into test cases and parameterized tests.

4. **Analyze the Helper Structures:** The `MachInst`, `IntCmp`, `FPCmp`, and `Conversion` structs are crucial. They define data structures to represent machine instructions and related information (like opcode, data types, flags conditions). These are used to drive the parameterized tests. The templates (`MachInst1`, `MachInst2`) indicate different instruction arities (number of operands).

5. **Categorize the Tests:**  Observe how the tests are grouped by functionality: logical instructions, shift instructions, MUL/DIV, MOD, FP arithmetic, integer arithmetic, comparisons, conversions, and memory access (loads/stores). This provides a high-level understanding of what aspects of the instruction selector are being tested.

6. **Examine Individual Test Cases:** Pick a few representative test cases (e.g., `InstructionSelectorFPCmpTest`, `InstructionSelectorLogicalTest`, `InstructionSelectorMemoryAccessImmTest`). Understand the pattern:
    * They often take a parameter (from the helper structs).
    * They use `StreamBuilder` to create a simple code snippet with the operation being tested.
    * They use `m.Return()` or `m.Store()` to define the operation.
    * They use `m.Parameter()`, `m.Int32Constant()`, etc., to create operands.
    * They use `m.Build()` to generate the instruction stream.
    * They use `ASSERT_EQ` and `EXPECT_EQ` to verify the generated instruction's properties (opcode, number of inputs/outputs, addressing mode, immediate values, etc.).

7. **Identify Javascript Relevance (The "Aha!" Moment):**  Realize that the instruction selector's job is to translate higher-level operations (represented by `Node`s in the compiler IR) into actual machine instructions for a specific architecture (RISC-V in this case). Think about what kinds of Javascript operations would need these RISC-V instructions. For instance:
    * Arithmetic operators (`+`, `-`, `*`, `/`, `%`) would map to instructions like `kRiscvAdd32`, `kRiscvSub32`, `kRiscvMul32`, `kRiscvDivD`, `kRiscvMod32`.
    * Bitwise operators (`&`, `|`, `^`, `<<`, `>>`, `>>>`) would map to `kRiscvAnd`, `kRiscvOr`, `kRiscvXor`, `kRiscvShl32`, etc.
    * Comparisons (`==`, `!=`, `<`, `>`, `<=`, `>=`) would use instructions like `kRiscvCmp`.
    * Type conversions (number to float, float to integer) would involve instructions like `kRiscvCvtDW`, `kRiscvTruncWD`.
    * Accessing properties of objects or array elements would involve load and store instructions (`kRiscvLw`, `kRiscvSw`).

8. **Construct Javascript Examples:** Once the connection to Javascript operations is clear, create simple Javascript code snippets that would trigger the corresponding machine instructions being tested. The examples should be basic and clearly demonstrate the link. Focus on the *semantics* of the Javascript operation that would lead to the specific machine instruction.

9. **Summarize and Explain:**  Combine the findings into a concise summary that covers:
    * The file's purpose (testing the RISC-V 32-bit instruction selector).
    * How it achieves this (using Google Test and a test infrastructure).
    * What it tests (various arithmetic, logical, comparison, conversion, and memory access operations).
    * The connection to Javascript (how Javascript language features are translated into these low-level instructions).
    * Provide illustrative Javascript examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just compiler internal stuff, probably no direct link to Javascript."  **Correction:** Realize that the compiler's job *is* to translate Javascript, so there *must* be a connection, even if it's not immediately obvious.
* **Focusing too much on the C++ details:** Get bogged down in the specifics of the `StreamBuilder` and `InstructionOperand`. **Refocus:**  Remember the high-level goal is to understand what *functionality* is being tested and how it relates to Javascript semantics. The C++ is just the *testing mechanism*.
* **Struggling with a specific instruction:**  If unsure about a particular RISC-V instruction, a quick web search for "RISC-V instruction set manual" can provide clarification. Or, infer its purpose from the C++ code and the Javascript operation it likely corresponds to.

By following this structured approach, you can effectively analyze complex C++ code like this and bridge the gap to its higher-level purpose and relevance to languages like Javascript.
这个C++源代码文件 `instruction-selector-riscv32-unittest.cc` 的主要功能是 **测试 V8 JavaScript 引擎中针对 RISC-V 32位架构的指令选择器 (Instruction Selector) 组件**。

具体来说，它做了以下几点：

1. **定义了用于测试的数据结构:**  文件中定义了多个结构体，如 `MachInst`, `IntCmp`, `FPCmp`, `Conversion`, `MemoryAccess` 等，用于表示不同的 RISC-V 指令及其相关的属性，例如：
    * `constructor`:  指向 `RawMachineAssembler` 中生成对应指令的成员函数的指针。
    * `constructor_name`: 指令构造函数的名称。
    * `arch_opcode`:  RISC-V 架构的操作码。
    * `machine_type`:  操作数的数据类型 (例如 `Int32`, `Float64`)。
    * `expected_size`:  预期生成的指令大小。
    * `cond`:  浮点比较指令的条件码。
    * `load_opcode`, `store_opcode`:  加载和存储指令的操作码。

2. **创建了一系列单元测试用例:**  使用了 Google Test 框架 (`TEST_P`, `TEST_F`, `INSTANTIATE_TEST_SUITE_P`) 创建了大量的测试用例，覆盖了 RISC-V 32位架构下各种指令的选择情况，包括：
    * **算术运算指令:** 加法、减法、乘法、除法、取模等（整数和浮点数）。
    * **逻辑运算指令:** 与、或、异或。
    * **位移指令:** 左移、右移（逻辑和算术）、循环右移。
    * **比较指令:** 等于、不等于、小于、大于等（整数和浮点数）。
    * **类型转换指令:** 整数与浮点数之间的转换。
    * **内存访问指令:** 加载和存储不同数据类型的数值 (包括立即数偏移)。
    * **其他指令:**  绝对值、最大值、最小值、计数前导零等。

3. **测试指令选择器的输出:** 每个测试用例都会使用 `RawMachineAssembler` 构建一个简单的操作序列，然后调用指令选择器进行指令选择，并检查生成的指令流 (`Stream`) 是否符合预期，包括：
    * **指令数量:** 预期生成多少条指令。
    * **指令的操作码:** 生成的指令是否是预期的 RISC-V 指令。
    * **操作数的数量:** 指令的输入和输出操作数是否正确。
    * **操作数的类型:** 操作数是寄存器还是立即数，以及立即数的值。
    * **寻址模式:** 内存访问指令的寻址模式是否正确。
    * **标志位设置:** 比较指令是否设置了正确的标志位。

**与 JavaScript 的关系:**

这个单元测试文件直接测试了 V8 引擎中将 JavaScript 代码转换成 RISC-V 32位机器码的关键环节。当 V8 执行 JavaScript 代码时，它会经历一个编译过程，其中一个重要的步骤就是**指令选择**。指令选择器的任务是将中间代码 (通常是平台无关的) 转换成目标架构 (这里是 RISC-V 32位)  能够执行的机器指令。

**JavaScript 例子:**

以下是一些 JavaScript 代码示例，以及它们在 RISC-V 32位架构下可能会对应到测试文件中测试的指令类型：

* **算术运算:**
   ```javascript
   let a = 10;
   let b = 5;
   let sum = a + b; // 可能对应 kRiscvAdd32 测试
   let product = a * b; // 可能对应 kRiscvMul32 测试
   let quotient = a / b; // 可能对应 kRiscvDiv32 或 kRiscvDivD 测试 (取决于数据类型)
   ```

* **逻辑运算:**
   ```javascript
   let x = 0b1010;
   let y = 0b0110;
   let andResult = x & y; // 可能对应 kRiscvAnd 测试
   let orResult = x | y;  // 可能对应 kRiscvOr 测试
   ```

* **位移运算:**
   ```javascript
   let num = 8;
   let shiftedLeft = num << 2; // 可能对应 kRiscvShl32 测试
   let shiftedRight = num >> 1; // 可能对应 kRiscvSar32 或 kRiscvShr32 测试
   ```

* **比较运算:**
   ```javascript
   let p = 10;
   let q = 10;
   if (p === q) { // 可能对应 kRiscvCmp (Word32Equal) 测试
       console.log("Equal");
   }
   if (p < q) { // 可能对应 kRiscvCmp (Int32LessThan) 测试
       console.log("Less than");
   }
   ```

* **类型转换:**
   ```javascript
   let intValue = 10;
   let floatValue = parseFloat(intValue); // 可能对应 kRiscvCvtDW 测试
   let roundedInt = parseInt(floatValue); // 可能对应 kRiscvTruncWD 测试
   ```

* **访问对象属性/数组元素:**
   ```javascript
   let obj = { value: 42 };
   let x = obj.value; // 可能对应 kRiscvLw (加载内存) 测试

   let arr = [1, 2, 3];
   let y = arr[1]; // 可能对应 kRiscvLw (加载内存) 测试
   ```

**总结:**

`instruction-selector-riscv32-unittest.cc` 文件是 V8 引擎针对 RISC-V 32位架构进行质量保证的关键组成部分。它通过大量的单元测试，确保指令选择器能够正确地将各种 JavaScript 操作转换为高效且正确的 RISC-V 机器指令，从而保证 JavaScript 代码在 RISC-V 32位平台上的性能和正确性。

Prompt: 
```
这是目录为v8/test/unittests/compiler/riscv32/instruction-selector-riscv32-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
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
    {{&RawMachineAssembler::Float64Equal, "Float64Equal", kRiscvCmpD,
      MachineType::Float64()},
     kEqual},
    {{&RawMachineAssembler::Float64LessThan, "Float64LessThan", kRiscvCmpD,
      MachineType::Float64()},
     kUnsignedLessThan},
    {{&RawMachineAssembler::Float64LessThanOrEqual, "Float64LessThanOrEqual",
      kRiscvCmpD, MachineType::Float64()},
     kUnsignedLessThanOrEqual},
    {{&RawMachineAssembler::Float64GreaterThan, "Float64GreaterThan",
      kRiscvCmpD, MachineType::Float64()},
     kUnsignedLessThan},
    {{&RawMachineAssembler::Float64GreaterThanOrEqual,
      "Float64GreaterThanOrEqual", kRiscvCmpD, MachineType::Float64()},
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
    {&RawMachineAssembler::Word32And, "Word32And", kRiscvAnd,
     MachineType::Int32()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kRiscvOr,
     MachineType::Int32()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kRiscvXor,
     MachineType::Int32()}};

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------

const MachInst2 kShiftInstructions[] = {
    {&RawMachineAssembler::Word32Shl, "Word32Shl", kRiscvShl32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word32Shr, "Word32Shr", kRiscvShr32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word32Sar, "Word32Sar", kRiscvSar32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word32Ror, "Word32Ror", kRiscvRor32,
     MachineType::Int32()}};

// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------

const MachInst2 kMulDivInstructions[] = {
    {&RawMachineAssembler::Int32Mul, "Int32Mul", kRiscvMul32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Div, "Int32Div", kRiscvDiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kRiscvDivU32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Float64Mul, "Float64Mul", kRiscvMulD,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Div, "Float64Div", kRiscvDivD,
     MachineType::Float64()}};

// ----------------------------------------------------------------------------
// MOD instructions.
// ----------------------------------------------------------------------------

const MachInst2 kModInstructions[] = {
    {&RawMachineAssembler::Int32Mod, "Int32Mod", kRiscvMod32,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint32Mod, "Uint32Mod", kRiscvModU32,
     MachineType::Int32()},
    {&RawMachineAssembler::Float64Mod, "Float64Mod", kRiscvModD,
     MachineType::Float64()}};

// ----------------------------------------------------------------------------
// Arithmetic FPU instructions.
// ----------------------------------------------------------------------------

const MachInst2 kFPArithInstructions[] = {
    {&RawMachineAssembler::Float64Add, "Float64Add", kRiscvAddD,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Sub, "Float64Sub", kRiscvSubD,
     MachineType::Float64()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, two nodes.
// ----------------------------------------------------------------------------

const MachInst2 kAddSubInstructions[] = {
    {&RawMachineAssembler::Int32Add, "Int32Add", kRiscvAdd32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kRiscvSub32,
     MachineType::Int32()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, one node.
// ----------------------------------------------------------------------------

const MachInst1 kAddSubOneInstructions[] = {{&RawMachineAssembler::Int32Neg,
                                             "Int32Neg", kRiscvSub32,
                                             MachineType::Int32()}};

// ----------------------------------------------------------------------------
// Arithmetic compare instructions.
// ----------------------------------------------------------------------------

const IntCmp kCmpInstructions[] = {
    {{&RawMachineAssembler::WordEqual, "WordEqual", kRiscvCmp,
      MachineType::Int64()},
     1U},
    {{&RawMachineAssembler::WordNotEqual, "WordNotEqual", kRiscvCmp,
      MachineType::Int64()},
     1U},
    {{&RawMachineAssembler::Word32Equal, "Word32Equal", kRiscvCmp,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kRiscvCmp,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32LessThan, "Int32LessThan", kRiscvCmp,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
      kRiscvCmp, MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32GreaterThan, "Int32GreaterThan", kRiscvCmp,
      MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Int32GreaterThanOrEqual, "Int32GreaterThanOrEqual",
      kRiscvCmp, MachineType::Int32()},
     1U},
    {{&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kRiscvCmp,
      MachineType::Uint32()},
     1U},
    {{&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
      kRiscvCmp, MachineType::Uint32()},
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
      kRiscvCvtDW, MachineType::Float64()},
     MachineType::Int32()},

    // mips instructions:
    // cvt.d.uw
    {{&RawMachineAssembler::ChangeUint32ToFloat64, "ChangeUint32ToFloat64",
      kRiscvCvtDUw, MachineType::Float64()},
     MachineType::Int32()},

    // mips instructions:
    // mfc1, trunc double to word, for more details look at mips macro
    // asm and mips asm file
    {{&RawMachineAssembler::ChangeFloat64ToInt32, "ChangeFloat64ToInt32",
      kRiscvTruncWD, MachineType::Float64()},
     MachineType::Int32()},

    // mips instructions:
    // trunc double to unsigned word, for more details look at mips macro
    // asm and mips asm file
    {{&RawMachineAssembler::ChangeFloat64ToUint32, "ChangeFloat64ToUint32",
      kRiscvTruncUwD, MachineType::Float64()},
     MachineType::Int32()}};

const Conversion kFloat32RoundInstructions[] = {
    {{&RawMachineAssembler::Float32RoundUp, "Float32RoundUp",
      kRiscvFloat32RoundUp, MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundDown, "Float32RoundDown",
      kRiscvFloat32RoundDown, MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundTiesEven, "Float32RoundTiesEven",
      kRiscvFloat32RoundTiesEven, MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundTruncate, "Float32RoundTruncate",
      kRiscvFloat32RoundTruncate, MachineType::Int32()},
     MachineType::Float32()}};

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
    ASSERT_EQ(1U, s.size());

    EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
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
    EXPECT_EQ(kRiscvShl32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}

// TEST_F(InstructionSelectorTest, Word64ShlWithWord64And) {
//   TRACED_FORRANGE(int32_t, shift, 0, 62) {
//     StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
//     Node* const p0 = m.Parameter(0);
//     Node* const r =
//         m.Word64Shl(m.Word64And(p0, m.Int64Constant((1L << (63 - shift)) -
//         1)),
//                     m.Int64Constant(shift + 1));
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

TEST_F(InstructionSelectorTest, Word32SarWithWord32Shl) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(24)), m.Int32Constant(24));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvSignExtendByte, s[0]->arch_opcode());
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
    EXPECT_EQ(kRiscvSignExtendShort, s[0]->arch_opcode());
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
    EXPECT_EQ(kRiscvShl32, s[0]->arch_opcode());
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

using CombineChangeFloat32ToInt32WithRoundFloat32 =
    InstructionSelectorTestWithParam<Conversion>;

TEST_P(CombineChangeFloat32ToInt32WithRoundFloat32, Parameter) {
  {
    const Conversion conv = GetParam();
    StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
    m.Return(m.ChangeFloat64ToInt32(
        m.ChangeFloat32ToFloat64((m.*conv.mi.constructor)(m.Parameter(0)))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kRiscvTruncWS, s[1]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         CombineChangeFloat32ToInt32WithRoundFloat32,
                         ::testing::ValuesIn(kFloat32RoundInstructions));

TEST_F(InstructionSelectorTest, ChangeFloat64ToInt32OfChangeFloat32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
    m.Return(m.ChangeFloat64ToInt32(m.ChangeFloat32ToFloat64(m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvTruncWS, s[0]->arch_opcode());
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
    EXPECT_EQ(kRiscvCvtSW, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
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
    {MachineType::Int8(), kRiscvLb, kRiscvSb},
    {MachineType::Uint8(), kRiscvLbu, kRiscvSb},
    {MachineType::Int16(), kRiscvLh, kRiscvSh},
    {MachineType::Uint16(), kRiscvLhu, kRiscvSh},
    {MachineType::Int32(), kRiscvLw, kRiscvSw},
    {MachineType::Float32(), kRiscvLoadFloat, kRiscvStoreFloat},
    {MachineType::Float64(), kRiscvLoadDouble, kRiscvStoreDouble}};

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

// ----------------------------------------------------------------------------
// Loads and stores immediate values
// ----------------------------------------------------------------------------

const MemoryAccessImm kMemoryAccessesImm[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}}};

#ifdef RISCV_HAS_NO_UNALIGNED
struct MemoryAccessImm2 {
  MachineType type;
  ArchOpcode store_opcode;
  ArchOpcode store_opcode_unaligned;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
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
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvUsw,
     kRiscvSw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvUsd,
     kRiscvSd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvUStoreFloat,
     kRiscvStoreFloat,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvUStoreDouble,
     kRiscvStoreDouble,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};
#endif
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

TEST_P(InstructionSelectorMemoryAccessImmTest, StoreWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
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

TEST_P(InstructionSelectorMemoryAccessImmTest, StoreZero) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Int32Constant(0), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(0)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(0)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImm));

#ifdef RISCV_HAS_NO_UNALIGNED
using InstructionSelectorMemoryAccessUnalignedImmTest =
    InstructionSelectorTestWithParam<MemoryAccessImm2>;

TEST_P(InstructionSelectorMemoryAccessUnalignedImmTest, StoreZero) {
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessUnalignedImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImmUnaligned));
#endif
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
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
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
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmMoreThan16bitTest,
                         ::testing::ValuesIn(kMemoryAccessImmMoreThan16bit));

// ----------------------------------------------------------------------------
// kRiscvCmp with zero testing.
// ----------------------------------------------------------------------------

TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
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
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Int32Constant(0), m.Parameter(0)));
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

TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kRiscvClz32, s[0]->arch_opcode());
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
  EXPECT_EQ(kRiscvAbsS, s[0]->arch_opcode());
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
  EXPECT_EQ(kRiscvAbsD, s[0]->arch_opcode());
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
  EXPECT_EQ(kRiscvFloat64Max, s[0]->arch_opcode());
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
  EXPECT_EQ(kRiscvFloat64Min, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Word32ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    // EXPECT_EQ(kRiscvByteSwap32, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ExternalReferenceLoad1) {
  // Test offsets we can use kMode_Root for.
  const int32_t kOffsets[] = {0, 1, 4, INT32_MIN, INT32_MAX};
  TRACED_FOREACH(int64_t, offset, kOffsets) {
    StreamBuilder m(this, MachineType::Int32());
    ExternalReference reference = base::bit_cast<ExternalReference>(
        (int32_t)(isolate()->isolate_root() + offset));
    Node* const value =
        m.Load(MachineType::Int32(), m.ExternalConstant(reference));
    m.Return(value);

    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvLw, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Root, s[0]->addressing_mode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToInt64(s[0]->InputAt(0)), offset);
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```