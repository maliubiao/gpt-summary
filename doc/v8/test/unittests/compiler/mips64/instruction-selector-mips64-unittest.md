Response: The user wants a summary of the C++ code provided.
The code seems to be a unit test file for the instruction selector of the V8 JavaScript engine, specifically for the MIPS64 architecture.
It defines various test cases for different MIPS64 instructions by comparing the generated assembly code with the expected instructions.
The tests cover a range of operations including:
- Arithmetic operations (add, subtract, multiply, divide, modulo, negate)
- Logical operations (AND, OR, XOR)
- Shift operations (left shift, right shift, arithmetic right shift, rotate right)
- Comparison operations (equal, not equal, less than, less than or equal to, greater than, greater than or equal to) for both integers and floating-point numbers
- Conversion operations between different data types (integer to float, float to integer)
- Memory access operations (load, store) with immediate offsets.

The connection to JavaScript lies in the fact that this code tests the part of the V8 engine responsible for translating high-level intermediate representation of JavaScript code into low-level machine instructions for the MIPS64 architecture.

To demonstrate the connection with JavaScript, I can create examples where JavaScript code would trigger some of the tested MIPS64 instructions.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于测试MIPS64架构的指令选择器（Instruction Selector）。指令选择器的作用是将高级的、平台无关的中间代码（Intermediate Representation, IR）转换为特定目标架构（这里是MIPS64）的机器指令。

**功能归纳:**

这个文件的主要功能是定义了一系列的单元测试，用于验证指令选择器是否能够为各种IR操作生成正确的MIPS64机器指令。  它通过以下方式实现：

1. **定义测试用例:**  文件中定义了许多测试用例，每个测试用例针对一种或多种MIPS64指令。这些测试用例使用`TEST_P`和`TEST_F`宏来组织。
2. **模拟IR操作:** 每个测试用例内部使用 `RawMachineAssembler` 类来模拟不同的IR操作，例如加法、减法、逻辑运算、位移操作、比较操作、类型转换和内存访问等。
3. **生成机器码:**  `StreamBuilder` 类用于构建一个指令流，模拟指令选择器生成的机器码。
4. **断言验证:**  每个测试用例通过 `ASSERT_EQ` 和 `EXPECT_EQ` 等断言宏来检查生成的机器码是否符合预期：
    - 检查生成的指令数量是否正确。
    - 检查生成的每条指令的 `arch_opcode()` (架构操作码) 是否是预期的 MIPS64 指令。
    - 检查指令的输入和输出操作数数量是否正确。
    - 检查指令的寻址模式和标志位设置是否符合预期。
5. **参数化测试:**  许多测试用例使用 `InstructionSelectorTestWithParam` 和 `INSTANTIATE_TEST_SUITE_P` 来实现参数化测试，这意味着可以使用不同的输入参数（例如不同的操作数类型或立即数）来运行相同的测试逻辑，从而提高测试覆盖率。

**与JavaScript的关系及举例说明:**

指令选择器是V8引擎中将JavaScript代码编译成机器码的关键组件。当V8编译JavaScript代码时，它首先将JavaScript代码解析成抽象语法树（AST），然后将其转换为中间代码（IR）。最后，指令选择器根据目标架构将这些IR操作转换为具体的机器指令。

以下是一些JavaScript代码示例，以及它们在MIPS64架构上可能触发的指令选择器测试用例：

**1. 算术运算:**

```javascript
function add(a, b) {
  return a + b;
}
```

这个简单的加法函数可能会触发 `kAddSubInstructions` 测试套件中的 `Int32Add` 或 `Int64Add` 测试用例，具体取决于 `a` 和 `b` 的类型。例如，如果 V8 推断 `a` 和 `b` 是32位整数，指令选择器可能会生成 `kMips64Add` 指令。

**2. 逻辑运算:**

```javascript
function logicalAnd(a, b) {
  return a & b;
}
```

这个按位与运算函数可能会触发 `kLogicalInstructions` 测试套件中的 `Word32And` 或 `Word64And` 测试用例，生成 `kMips64And32` 或 `kMips64And` 指令。

**3. 位移运算:**

```javascript
function shiftLeft(a, count) {
  return a << count;
}
```

这个左移运算函数可能会触发 `kShiftInstructions` 测试套件中的 `Word32Shl` 或 `Word64Shl` 测试用例，生成 `kMips64Shl` 或 `kMips64Dshl` 指令。  文件中的 `TEST_P(InstructionSelectorShiftTest, Immediate)` 测试用例就是为了验证当位移量是立即数时，指令选择器是否能正确生成指令。

**4. 比较运算:**

```javascript
function isEqual(a, b) {
  return a === b;
}
```

这个相等比较函数可能会触发 `kCmpInstructions` 测试套件中的 `WordEqual` 或 `Word32Equal` 测试用例，生成 `kMips64Cmp` 指令，并设置相应的条件码。

**5. 类型转换:**

```javascript
function floatToInt(f) {
  return parseInt(f);
}
```

这个将浮点数转换为整数的函数可能会触发 `kConversionInstructions` 测试套件中的 `ChangeFloat64ToInt32` 测试用例，生成例如 `kMips64TruncWD` 指令。

**6. 内存访问:**

```javascript
let arr = [1, 2, 3];
let first = arr[0];
```

访问数组元素的操作可能会触发与内存加载相关的测试用例，例如 `InstructionSelectorMemoryAccessTest` 中的 `LoadWithParameters`，生成像 `kMips64Lw` 这样的加载指令。

总而言之，这个测试文件确保了V8引擎在MIPS64架构上能够正确地将各种JavaScript操作转换为高效的机器指令，这是保证JavaScript代码在该架构上正确且快速执行的关键。

### 提示词
```
这是目录为v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
    EXPECT_EQ(kMips64Dsar, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64Dshl, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64TruncWS, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64CvtSW, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64DMulHigh, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64Ddiv, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64Dmod, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64Lbu, s[1]->arch_opcode());
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
    EXPECT_EQ(kMips64Lb, s[1]->arch_opcode());
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
    EXPECT_EQ(kMips64Lhu, s[1]->arch_opcode());
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
    EXPECT_EQ(kMips64Lh, s[1]->arch_opcode());
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
    EXPECT_EQ(kMips64Lw, s[1]->arch_opcode());
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
    EXPECT_EQ(kMips64Lw, s[1]->arch_opcode());
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
  // Make sure the `ChangeUint32ToUint64` node turned into a no-op.
  if (v8_flags.debug_code && binop.arch_opcode == kMips64Cmp) {
    ASSERT_EQ(6U, s.size());
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kMips64Dshl, s[1]->arch_opcode());
    EXPECT_EQ(kMips64Dshl, s[2]->arch_opcode());
    EXPECT_EQ(kMips64Cmp, s[3]->arch_opcode());
    EXPECT_EQ(kMips64AssertEqual, s[4]->arch_opcode());
    EXPECT_EQ(kMips64Cmp, s[5]->arch_opcode());
    EXPECT_EQ(2U, s[5]->InputCount());
    EXPECT_EQ(1U, s[5]->OutputCount());
  } else {
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
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
    EXPECT_EQ(kMips64Dadd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kMips64Lbu, s[1]->arch_opcode());
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
    EXPECT_EQ(kMips64Dadd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kMips64Lhu, s[1]->arch_opcode());
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
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Dadd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kMips64Lwu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
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
    {MachineType::Int8(), kMips64Lb, kMips64Sb},
    {MachineType::Uint8(), kMips64Lbu, kMips64Sb},
    {MachineType::Int16(), kMips64Lh, kMips64Sh},
    {MachineType::Uint16(), kMips64Lhu, kMips64Sh},
    {MachineType::Int32(), kMips64Lw, kMips64Sw},
    {MachineType::Float32(), kMips64Lwc1, kMips64Swc1},
    {MachineType::Float64(), kMips64Ldc1, kMips64Sdc1},
    {MachineType::Int64(), kMips64Ld, kMips64Sd}};


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

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm2& acc) {
  return os << acc.type;
}

// ----------------------------------------------------------------------------
// Loads and stores immediate values
// ----------------------------------------------------------------------------


const MemoryAccessImm kMemoryAccessesImm[] = {
    {MachineType::Int8(),
     kMips64Lb,
     kMips64Sb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Uint8(),
     kMips64Lbu,
     kMips64Sb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Int16(),
     kMips64Lh,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Uint16(),
     kMips64Lhu,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Int32(),
     kMips64Lw,
     kMips64Sw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Float32(),
     kMips64Lwc1,
     kMips64Swc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Float64(),
     kMips64Ldc1,
     kMips64Sdc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Int64(),
     kMips64Ld,
     kMips64Sd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kMips64Lb,
     kMips64Sb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kMips64Lbu,
     kMips64Sb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kMips64Lh,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kMips64Lhu,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kMips64Lw,
     kMips64Sw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kMips64Lwc1,
     kMips64Swc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kMips64Ldc1,
     kMips64Sdc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kMips64Ld,
     kMips64Sd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}}};

const MemoryAccessImm2 kMemoryAccessesImmUnaligned[] = {
    {MachineType::Int16(),
     kMips64Ush,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kMips64Usw,
     kMips64Sw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kMips64Usd,
     kMips64Sd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kMips64Uswc1,
     kMips64Swc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kMips64Usdc1,
     kMips64Sdc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

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
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
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
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImm));

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
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(unaligned_store_supported ? memacc.store_opcode_unaligned
                                        : memacc.store_opcode,
              s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessUnalignedImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImmUnaligned));

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
// kMips64Cmp with zero testing.
// ----------------------------------------------------------------------------


TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
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
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount()
```