Response: The user wants a summary of the C++ code provided and an example of its relation to JavaScript.

**Plan:**

1. **Identify the core functionality:** The code appears to be testing the instruction selection phase of the V8 compiler for the RISC-V 64-bit architecture. It verifies that high-level operations are correctly translated into low-level RISC-V instructions.
2. **Summarize the testing approach:**  The code defines various test cases using parameterized tests. Each test case focuses on a specific instruction or a combination of instructions. It builds a small code snippet using `RawMachineAssembler`, compiles it, and then asserts that the generated assembly instructions match the expected ones.
3. **Explain the connection to JavaScript:** The instruction selector is a crucial part of the JavaScript compilation process in V8. It takes the intermediate representation of JavaScript code and converts it into machine code for the target architecture (RISC-V 64 in this case).
4. **Provide a JavaScript example:**  Demonstrate how a simple JavaScript operation might be translated to the tested RISC-V instructions. Focus on operations covered in the C++ code, like addition, comparison, or bitwise operations.
这个C++源代码文件 `instruction-selector-riscv64-unittest.cc` 是V8 JavaScript引擎中，用于RISC-V 64位架构的**指令选择器 (Instruction Selector) 的单元测试文件**。

**功能归纳:**

该文件的主要功能是测试V8编译器在将中间表示 (Intermediate Representation - IR) 的代码转换为 RISC-V 64 位机器码的过程中，指令选择器是否能够正确地为各种操作选择合适的RISC-V指令。

具体来说，它通过以下方式进行测试：

1. **定义了各种测试用例:**  每个测试用例针对一个或一组特定的操作，例如：
    * 算术运算 (加法、减法、乘法、除法、取模)
    * 逻辑运算 (与、或、异或)
    * 位移操作 (左移、右移、算术右移、循环右移)
    * 比较操作 (相等、不等、小于、大于等)
    * 浮点数运算和比较
    * 类型转换
    * 加载和存储操作
    * 特殊指令 (例如，计算前导零)
2. **使用了 `RawMachineAssembler`:**  这是一个用于在测试中构建IR代码的工具。测试用例会使用 `RawMachineAssembler` 创建代表特定操作的IR节点。
3. **执行指令选择:**  V8的编译流程会自动对构建的IR代码执行指令选择过程。
4. **断言生成的机器码:**  测试用例会检查指令选择器生成的机器码 (以 `Stream` 对象表示) 是否符合预期，包括：
    * 指令的数量
    * 指令的操作码 (`arch_opcode`)
    * 指令的寻址模式 (`addressing_mode`)
    * 输入和输出操作数的数量和类型
    * 指令的标志位设置 (`flags_mode`) 和条件 (`flags_condition`)
5. **参数化测试:**  为了覆盖同类操作的不同情况 (例如，不同类型的比较操作符)，使用了参数化测试 (`InstructionSelectorTestWithParam`)。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

指令选择器是 V8 编译器将 JavaScript 代码转换为机器码的关键步骤。它将高级的 JavaScript 操作转换为底层硬件可以执行的指令。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个 `add` 函数时，指令选择器会负责将 `a + b` 这个加法操作转换为 RISC-V 64 位的加法指令。

**C++ 代码中针对加法操作的测试用例 (对应 `kAddSubInstructions`):**

```c++
const MachInst2 kAddSubInstructions[] = {
    {&RawMachineAssembler::Int32Add, "Int32Add", kRiscvAdd32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Add, "Int64Add", kRiscvAdd64,
     MachineType::Int64()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kRiscvSub32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Sub, "Int64Sub", kRiscvSub64,
     MachineType::Int64()}
};
```

以及相应的测试函数:

```c++
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
```

这个测试用例会针对 `Int32Add` 和 `Int64Add` 检查是否生成了 `kRiscvAdd32` 和 `kRiscvAdd64` 指令。

**JavaScript 示例的机器码推测:**

如果 `a` 和 `b` 在运行时被确定为 32 位整数，指令选择器可能会生成类似以下的 RISC-V 64 位指令 (由于 V8 内部表示可能使用 64 位寄存器)：

```assembly
# 假设 a 在寄存器 x10， b 在寄存器 x11
addw  x12, x10, x11  # 将 x10 和 x11 的低 32 位相加，结果放入 x12
```

或者，如果 `a` 和 `b` 被视为需要 64 位精度，则可能生成：

```assembly
# 假设 a 在寄存器 x10， b 在寄存器 x11
add  x12, x10, x11   # 将 x10 和 x11 相加，结果放入 x12
```

**总结:**

`instruction-selector-riscv64-unittest.cc` 这个文件通过大量的单元测试，确保了 V8 编译器在 RISC-V 64 位架构下能够正确地将各种 JavaScript 操作转换为高效的机器码，从而保证 JavaScript 代码在该架构上的性能和正确性。 这些测试覆盖了 JavaScript 中常见的算术、逻辑、比较、类型转换以及内存访问等操作。

### 提示词
```
这是目录为v8/test/unittests/compiler/riscv64/instruction-selector-riscv64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
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
    {&RawMachineAssembler::Word32And, "Word32And", kRiscvAnd32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64And, "Word64And", kRiscvAnd,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kRiscvOr32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Or, "Word64Or", kRiscvOr,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kRiscvXor32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Xor, "Word64Xor", kRiscvXor,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------

const MachInst2 kShiftInstructions[] = {
    {&RawMachineAssembler::Word32Shl, "Word32Shl", kRiscvShl32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Shl, "Word64Shl", kRiscvShl64,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Shr, "Word32Shr", kRiscvShr32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Shr, "Word64Shr", kRiscvShr64,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Sar, "Word32Sar", kRiscvSar32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Sar, "Word64Sar", kRiscvSar64,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Ror, "Word32Ror", kRiscvRor32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Ror, "Word64Ror", kRiscvRor64,
     MachineType::Int64()}};

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
    {&RawMachineAssembler::Int64Mul, "Int64Mul", kRiscvMul64,
     MachineType::Int64()},
    {&RawMachineAssembler::Int64Div, "Int64Div", kRiscvDiv64,
     MachineType::Int64()},
    {&RawMachineAssembler::Uint64Div, "Uint64Div", kRiscvDivU64,
     MachineType::Uint64()},
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
    {&RawMachineAssembler::Int64Add, "Int64Add", kRiscvAdd64,
     MachineType::Int64()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kRiscvSub32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Sub, "Int64Sub", kRiscvSub64,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, one node.
// ----------------------------------------------------------------------------

const MachInst1 kAddSubOneInstructions[] = {
    {&RawMachineAssembler::Int32Neg, "Int32Neg", kRiscvSub32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Neg, "Int64Neg", kRiscvSub64,
     MachineType::Int64()}};

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
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{&RawMachineAssembler::Int32LessThan, "Int32LessThan", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
      kRiscvCmp, MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{&RawMachineAssembler::Int32GreaterThan, "Int32GreaterThan", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{&RawMachineAssembler::Int32GreaterThanOrEqual, "Int32GreaterThanOrEqual",
      kRiscvCmp, MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kRiscvCmp,
      MachineType::Uint32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
      kRiscvCmp, MachineType::Uint32()},
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

const Conversion kFloat64RoundInstructions[] = {
    {{&RawMachineAssembler::Float64RoundUp, "Float64RoundUp", kRiscvCeilWD,
      MachineType::Int32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::Float64RoundDown, "Float64RoundDown", kRiscvFloorWD,
      MachineType::Int32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::Float64RoundTiesEven, "Float64RoundTiesEven",
      kRiscvRoundWD, MachineType::Int32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::Float64RoundTruncate, "Float64RoundTruncate",
      kRiscvTruncWD, MachineType::Int32()},
     MachineType::Float64()}};

const Conversion kFloat32RoundInstructions[] = {
    {{&RawMachineAssembler::Float32RoundUp, "Float32RoundUp", kRiscvCeilWS,
      MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundDown, "Float32RoundDown", kRiscvFloorWS,
      MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundTiesEven, "Float32RoundTiesEven",
      kRiscvRoundWS, MachineType::Int32()},
     MachineType::Float32()},
    {{&RawMachineAssembler::Float32RoundTruncate, "Float32RoundTruncate",
      kRiscvTruncWS, MachineType::Int32()},
     MachineType::Float32()}};

// MIPS64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kRiscvDivU32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32Mod, "Uint32Mod", kRiscvModU32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32MulHigh, "Uint32MulHigh", kRiscvMulHighU32,
     MachineType::Uint32()}};

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
#ifndef V8_COMPRESS_POINTERS
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
    EXPECT_EQ(3U, s[4]->InputCount());
    EXPECT_EQ(0U, s[4]->OutputCount());

    EXPECT_EQ(cmp.mi.arch_opcode, s[5]->arch_opcode());
    EXPECT_EQ(2U, s[5]->InputCount());
    EXPECT_EQ(1U, s[5]->OutputCount());
#else
    ASSERT_EQ(3U, s.size());

    EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());

    EXPECT_EQ(kRiscvShl64, s[1]->arch_opcode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());

    EXPECT_EQ(cmp.mi.arch_opcode, s[2]->arch_opcode());
    EXPECT_EQ(2U, s[2]->InputCount());
    EXPECT_EQ(1U, s[2]->OutputCount());
#endif
  } else {
    ASSERT_EQ(cmp.expected_size, s.size());
    EXPECT_EQ(cmp.mi.arch_opcode, s[cmp.expected_size - 1]->arch_opcode());
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
    EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
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

TEST_F(InstructionSelectorTest, ChangesFromToSmi) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.TruncateInt64ToInt32(
        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvSar64, s[0]->arch_opcode());
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
    EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

using CombineChangeFloat64ToInt32WithRoundFloat64 =
    InstructionSelectorTestWithParam<Conversion>;

TEST_P(CombineChangeFloat64ToInt32WithRoundFloat64, Parameter) {
  {
    const Conversion conv = GetParam();
    StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
    m.Return(m.ChangeFloat64ToInt32((m.*conv.mi.constructor)(m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         CombineChangeFloat64ToInt32WithRoundFloat64,
                         ::testing::ValuesIn(kFloat64RoundInstructions));

using CombineChangeFloat32ToInt32WithRoundFloat32 =
    InstructionSelectorTestWithParam<Conversion>;

TEST_P(CombineChangeFloat32ToInt32WithRoundFloat32, Parameter) {
  {
    const Conversion conv = GetParam();
    StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
    m.Return(m.ChangeFloat64ToInt32(
        m.ChangeFloat32ToFloat64((m.*conv.mi.constructor)(m.Parameter(0)))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
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

TEST_F(InstructionSelectorTest, CombineShiftsWithMul) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Word64Sar(m.Parameter(0), m.Int32Constant(32)),
                        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvMulHigh64, s[0]->arch_opcode());
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
    EXPECT_EQ(kRiscvDiv64, s[0]->arch_opcode());
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
    EXPECT_EQ(kRiscvMod64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ChangeInt32ToInt64AfterLoad) {
  // For each case, test that the conversion is merged into the load
  // operation.
  // ChangeInt32ToInt64(Load_Uint8) -> Lbu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
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
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLb, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint16) -> Lhu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
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
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
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
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
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
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
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
  // Make sure the `ChangeUint32ToUint64` node turned into two op(sli 32 and sri
  // 32).
  ASSERT_EQ(2U, s.size());
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

  // Lbu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
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
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
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
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
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
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &InstructionSelectorTest::Stream::IsInteger,
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
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &InstructionSelectorTest::Stream::IsInteger,
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
    EXPECT_EQ(kRiscvCmpZero32, s[0]->arch_opcode());
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
    EXPECT_EQ(kRiscvCmpZero32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
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
    EXPECT_EQ(kRiscvCmpZero, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Equal(m.Int64Constant(0), m.Parameter(0)));
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

TEST_F(InstructionSelectorTest, Word64Clz) {
  StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint64());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word64Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kRiscvClz64, s[0]->arch_opcode());
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

TEST_F(InstructionSelectorTest, Word32ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    if (CpuFeatures::IsSupported(ZBB)) {
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kRiscvRev8, s[0]->arch_opcode());
      EXPECT_EQ(kRiscvShr64, s[1]->arch_opcode());
      EXPECT_EQ(1U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
    } else {
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kRiscvByteSwap32, s[0]->arch_opcode());
      EXPECT_EQ(1U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(InstructionSelectorTest, Word64ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    if (CpuFeatures::IsSupported(ZBB)) {
      EXPECT_EQ(kRiscvRev8, s[0]->arch_opcode());
    } else {
      EXPECT_EQ(kRiscvByteSwap64, s[0]->arch_opcode());
    }
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ExternalReferenceLoad1) {
  // Test offsets we can use kMode_Root for.
  const int64_t kOffsets[] = {0, 1, 4, INT32_MIN, INT32_MAX};
  TRACED_FOREACH(int64_t, offset, kOffsets) {
    StreamBuilder m(this, MachineType::Int64());
    ExternalReference reference =
        base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
    Node* const value =
        m.Load(MachineType::Int64(), m.ExternalConstant(reference));
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

TEST_F(InstructionSelectorTest, ExternalReferenceLoad2) {
  // Offset too large, we cannot use kMode_Root.
  StreamBuilder m(this, MachineType::Int64());
  int64_t offset = 0x100000000;
  ExternalReference reference =
      base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
  Node* const value =
      m.Load(MachineType::Int64(), m.ExternalConstant(reference));
  m.Return(value);

  Stream s = m.Build();

  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kRiscvLd, s[0]->arch_opcode());
  EXPECT_NE(kMode_Root, s[0]->addressing_mode());
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```