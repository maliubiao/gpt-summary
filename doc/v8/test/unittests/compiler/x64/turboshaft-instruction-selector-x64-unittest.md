Response: The user wants a summary of the C++ code provided.
The code is a unit test file for the Turboshaft instruction selector on the x64 architecture in V8.
It tests the selection of specific x64 instructions for different Turboshaft operations.
The tests cover various operations like:
- Conversions between different data types (float32 to float64, int32 to int64, etc.)
- Truncations (float64 to float32, int64 to int32)
- Select operations based on conditions
- Loads and stores from memory
- Binary operations (bitwise, shifts, arithmetic, comparisons)
- Optimization of `ChangeUint32ToUint64` operations
- Specific optimizations for `TruncateInt64ToInt32`
- Different forms of integer addition (using `LEA` or `ADD`) based on operand usage and constants
- Integer multiplication and its optimization using `LEA` for multiplications by constants
- Bitwise shift operations and their optimization using `LEA`
- Binary operations with memory operands
- Floating-point operations (abs, arithmetic)

If the code has a relationship with Javascript, it's in the sense that these are the low-level instructions that the Javascript code eventually gets compiled down to by the V8 engine.

Let's think about how to illustrate this with a Javascript example.
A simple arithmetic operation in Javascript can be a good starting point.

```javascript
function add(a, b) {
  return a + b;
}
```
When V8 compiles this function for the x64 architecture, it might use instructions like `LEA` or `ADD` as tested in the provided C++ code.

Another example could involve type conversions.

```javascript
function convert(x) {
  return Number(x);
}
```
If `x` is a 32-bit integer, and the return type needs to be a 64-bit float, the compiler might use instructions similar to those tested in `ChangeInt32ToFloat64WithParameter`.

Now, let's formulate the summary.
这个C++源代码文件是V8 JavaScript引擎中Turboshaft编译器的x64架构指令选择器的单元测试。它的主要功能是测试指令选择器能否为各种Turboshaft中间表示（IR）操作正确地选择合适的x64汇编指令。

具体来说，这个文件中的每个`TEST_F`宏定义了一个独立的测试用例，用于验证特定IR操作到x64指令的转换是否符合预期。这些测试覆盖了以下几个方面：

1. **类型转换 (Conversions):** 测试了不同数据类型之间的转换操作，例如将 `float32` 转换为 `float64`，`int32` 转换为 `int64`，`uint32` 转换为 `float64` 等。
2. **截断 (Truncations):** 测试了将高精度类型截断为低精度类型的操作，例如将 `float64` 截断为 `float32`，将 `int64` 截断为 `int32`。
3. **选择 (Select):** 测试了基于条件选择不同值的操作。
4. **加载和存储 (Loads and stores):** 测试了从内存加载数据和将数据存储到内存的操作，涵盖了不同的数据类型。
5. **无符号32位到无符号64位转换的优化 (ChangeUint32ToUint64):** 测试了在某些情况下可以省略显式的 `ChangeUint32ToUint64` 操作，因为后续的指令会自动处理。
6. **截断 int64 到 int32 的优化 (TruncateInt64ToInt32):**  测试了当 `int64` 值是通过移位操作得到时，如何优化截断操作。
7. **算术运算 (Addition):**  详细测试了整数加法操作，包括使用 `LEA` 指令进行优化的情况，例如当操作数被多次使用或与常量相加时。
8. **乘法运算 (Multiplication):** 测试了整数乘法操作，以及当乘以小常量时使用 `LEA` 指令进行优化的场景。
9. **移位运算 (Word32ShiftLeft):** 测试了左移操作，以及当移位量为小常量时使用 `LEA` 指令进行优化的场景。
10. **带有内存操作数的二元运算 (Binops with a memory operand):** 测试了二元运算的一个操作数直接从内存加载的情况。
11. **浮点运算 (Floating point operations):** 测试了浮点数的绝对值运算和基本的算术运算。

**与 JavaScript 的关系以及示例:**

这个文件直接测试的是 V8 引擎的内部组件，负责将 JavaScript 代码编译成机器码。因此，它与 JavaScript 的功能息息相关。当 JavaScript 代码执行到需要进行类型转换、算术运算等操作时，V8 的编译器就会使用指令选择器来生成相应的机器指令。

**JavaScript 示例:**

```javascript
function example(a) {
  let b = a + 10; // 整数加法，可能对应测试中的 Int32Add 相关测试
  let c = a * 2;  // 乘以小常量，可能对应测试中的 Int32Mul2BecomesLea 测试
  let d = a << 2; // 左移操作，可能对应测试中的 Int32Shl2BecomesLea 测试
  let e = parseFloat(a); // 类型转换，可能对应测试中的 ChangeInt32ToFloat64WithParameter 等测试
  return b + c + d + e;
}

console.log(example(5));
```

在这个 JavaScript 示例中：

- `a + 10`：执行整数加法，V8 的编译器可能会选择类似 `LEA` 或 `ADD` 的 x64 指令，这与 `TurboshaftInstructionSelectorTest` 中的 `Int32Add` 相关测试用例的功能对应。根据 `a` 的使用情况，指令选择器可能会选择 `LEA` 进行优化。
- `a * 2`：执行乘以 2 的操作，编译器很可能会选择 `LEA` 指令进行优化，正如 `TurboshaftInstructionSelectorTest` 中的 `Int32Mul2BecomesLea` 测试所验证的那样。
- `a << 2`：执行左移 2 位的操作，编译器也可能选择 `LEA` 指令进行优化，这对应于 `TurboshaftInstructionSelectorTest` 中的 `Int32Shl2BecomesLea` 测试。
- `parseFloat(a)`：执行将整数转换为浮点数的操作，编译器会生成相应的类型转换指令，这与 `TurboshaftInstructionSelectorTest` 中的 `ChangeInt32ToFloat64WithParameter` 等测试用例的目标一致。

总结来说，这个单元测试文件确保了 Turboshaft 编译器在 x64 架构下能够为各种 JavaScript 操作生成高效且正确的机器码，从而保证 JavaScript 代码的性能。

Prompt: 
```
这是目录为v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "src/codegen/assembler.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/simd-shuffle.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8::internal::compiler::turboshaft {

// -----------------------------------------------------------------------------
// Conversions.

TEST_F(TurboshaftInstructionSelectorTest, ChangeFloat32ToFloat64WithParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float32());
  m.Return(m.ChangeFloat32ToFloat64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kSSEFloat32ToFloat64, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(TurboshaftInstructionSelectorTest, ChangeInt32ToInt64WithParameter) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
  m.Return(m.ChangeInt32ToInt64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Movsxlq, s[0]->arch_opcode());
}

TEST_F(TurboshaftInstructionSelectorTest, ChangeUint32ToFloat64WithParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Uint32());
  m.Return(m.ChangeUint32ToFloat64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kSSEUint32ToFloat64, s[0]->arch_opcode());
}

TEST_F(TurboshaftInstructionSelectorTest, ChangeUint32ToUint64WithParameter) {
  StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint32());
  m.Return(m.ChangeUint32ToUint64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
}

TEST_F(TurboshaftInstructionSelectorTest,
       TruncateFloat64ToFloat32WithParameter) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float64());
  m.Return(m.TruncateFloat64ToFloat32(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kSSEFloat64ToFloat32, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(TurboshaftInstructionSelectorTest, TruncateInt64ToInt32WithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  m.Return(m.TruncateWord64ToWord32(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
}

TEST_F(TurboshaftInstructionSelectorTest, SelectWord32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex cond = m.Int32Constant(1);
  m.Return(m.Word32Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  EXPECT_EQ(kX64Cmp32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  EXPECT_TRUE(s.IsSameAsInput(s[0]->Output(), 2));
}

TEST_F(TurboshaftInstructionSelectorTest, SelectWord64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex cond = m.Int32Constant(1);
  m.Return(m.Word64Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  EXPECT_EQ(kX64Cmp32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  EXPECT_TRUE(s.IsSameAsInput(s[0]->Output(), 2));
}

namespace {
struct LoadWithToInt64Extension {
  MachineType type;
  ArchOpcode expected_opcode;
};

std::ostream& operator<<(std::ostream& os,
                         const LoadWithToInt64Extension& i32toi64) {
  return os << i32toi64.type;
}

static const LoadWithToInt64Extension kLoadWithToInt64Extensions[] = {
    {MachineType::Int8(), kX64Movsxbq},
    {MachineType::Uint8(), kX64Movzxbq},
    {MachineType::Int16(), kX64Movsxwq},
    {MachineType::Uint16(), kX64Movzxwq},
    {MachineType::Int32(), kX64Movsxlq}};

// The parameterized test that use the following type are intentionally part
// of the anonymous namespace. The issue here is that the type parameter is
// using a type that is in the anonymous namespace, but the class generated by
// TEST_P is not. This will cause GCC to generate a -Wsubobject-linkage warning.
//
// In this case there will only be single translation unit and the warning
// about subobject-linkage can be avoided by placing the class generated
// by TEST_P in the anoynmous namespace as well.
using TurboshaftInstructionSelectorChangeInt32ToInt64Test =
    TurboshaftInstructionSelectorTestWithParam<LoadWithToInt64Extension>;

TEST_P(TurboshaftInstructionSelectorChangeInt32ToInt64Test,
       ChangeInt32ToInt64WithLoad) {
  const LoadWithToInt64Extension extension = GetParam();
  StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer());
  m.Return(m.ChangeInt32ToInt64(m.Load(extension.type, m.Parameter(0))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(extension.expected_opcode, s[0]->arch_opcode());
}

}  // namespace

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorChangeInt32ToInt64Test,
                         ::testing::ValuesIn(kLoadWithToInt64Extensions));

// -----------------------------------------------------------------------------
// Loads and stores

namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
};

std::ostream& operator<<(std::ostream& os, const MemoryAccess& memacc) {
  return os << memacc.type;
}

static const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(), kX64Movsxbl, kX64Movb},
    {MachineType::Uint8(), kX64Movzxbl, kX64Movb},
    {MachineType::Int16(), kX64Movsxwl, kX64Movw},
    {MachineType::Uint16(), kX64Movzxwl, kX64Movw},
    {MachineType::Int32(), kX64Movl, kX64Movl},
    {MachineType::Uint32(), kX64Movl, kX64Movl},
    {MachineType::Int64(), kX64Movq, kX64Movq},
    {MachineType::Uint64(), kX64Movq, kX64Movq},
    {MachineType::Float32(), kX64Movss, kX64Movss},
    {MachineType::Float64(), kX64Movsd, kX64Movsd}};

// The parameterized test that use the following type are intentionally part
// of the anonymous namespace. The issue here is that the type parameter is
// using a type that is in the anonymous namespace, but the class generated by
// TEST_P is not. This will cause GCC to generate a -Wsubobject-linkage warning.
//
// In this case there will only be single translation unit and the warning
// about subobject-linkage can be avoided by placing the class generated
// by TEST_P in the anoynmous namespace as well.
using TurboshaftInstructionSelectorMemoryAccessTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Pointer());
  m.Return(m.Load(memacc.type, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                  MachineType::Pointer(), memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Parameter(1),
          m.Parameter(2), kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
  EXPECT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(0U, s[0]->OutputCount());
}

}  // namespace

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// -----------------------------------------------------------------------------
// ChangeUint32ToUint64.

namespace {

struct BinaryOperation {
  TSBinop constructor;
  const char* constructor_name;
};

std::ostream& operator<<(std::ostream& os, const BinaryOperation& bop) {
  return os << bop.constructor_name;
}

const BinaryOperation kWord32BinaryOperations[] = {
    {TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd"},
    {TSBinop::kWord32BitwiseOr, "Word32BitwiseOr"},
    {TSBinop::kWord32BitwiseXor, "Word32BitwiseXor"},
    {TSBinop::kWord32ShiftLeft, "Word32ShiftLeft"},
    {TSBinop::kWord32ShiftRightLogical, "Word32Shr"},
    {TSBinop::kWord32ShiftRightArithmetic, "Word32Sar"},
    {TSBinop::kWord32RotateRight, "Word32Ror"},
    {TSBinop::kWord32Equal, "Word32Equal"},
    {TSBinop::kWord32Add, "Int32Add"},
    {TSBinop::kWord32Sub, "Int32Sub"},
    {TSBinop::kWord32Mul, "Int32Mul"},
    {TSBinop::kInt32MulOverflownBits, "Int32MulOverflownBits"},
    {TSBinop::kInt32Div, "Int32Div"},
    {TSBinop::kInt32LessThan, "Int32LessThan"},
    {TSBinop::kInt32LessThanOrEqual, "Int32LessThanOrEqual"},
    {TSBinop::kInt32Mod, "Int32Mod"},
    {TSBinop::kUint32Div, "Uint32Div"},
    {TSBinop::kUint32LessThan, "Uint32LessThan"},
    {TSBinop::kUint32LessThanOrEqual, "Uint32LessThanOrEqual"},
    {TSBinop::kUint32Mod, "Uint32Mod"}};

// The parameterized test that use the following type are intentionally part
// of the anonymous namespace. The issue here is that the type parameter is
// using a type that is in the anonymous namespace, but the class generated by
// TEST_P is not. This will cause GCC to generate a -Wsubobject-linkage warning.
//
// In this case there will only be single translation unit and the warning
// about subobject-linkage can be avoided by placing the class generated
// by TEST_P in the anoynmous namespace as well.
using TurboshaftInstructionSelectorChangeUint32ToUint64Test =
    TurboshaftInstructionSelectorTestWithParam<BinaryOperation>;

TEST_P(TurboshaftInstructionSelectorChangeUint32ToUint64Test,
       ChangeUint32ToUint64) {
  const BinaryOperation& bop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex p0 = m.Parameter(0);
  OpIndex p1 = m.Parameter(1);
  m.Return(m.ChangeUint32ToUint64(m.Emit(bop.constructor, p0, p1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
}

}  // namespace

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorChangeUint32ToUint64Test,
                         ::testing::ValuesIn(kWord32BinaryOperations));

// -----------------------------------------------------------------------------
// CanElideChangeUint32ToUint64

namespace {

template <typename Op>
struct MachInst {
  Op op;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  MachineType machine_type;
};

using MachInst2 = MachInst<TSBinop>;

// X64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd", kX64And32,
     MachineType::Uint32()},
    {TSBinop::kWord32BitwiseOr, "Word32BitwiseOr", kX64Or32,
     MachineType::Uint32()},
    {TSBinop::kWord32BitwiseXor, "Word32BitwiseXor", kX64Xor32,
     MachineType::Uint32()},
    {TSBinop::kWord32ShiftLeft, "Word32ShiftLeft", kX64Shl32,
     MachineType::Uint32()},
    {TSBinop::kWord32ShiftRightLogical, "Word32Shr", kX64Shr32,
     MachineType::Uint32()},
    {TSBinop::kWord32ShiftRightArithmetic, "Word32Sar", kX64Sar32,
     MachineType::Uint32()},
    {TSBinop::kWord32RotateRight, "Word32Ror", kX64Ror32,
     MachineType::Uint32()},
    {TSBinop::kWord32Equal, "Word32Equal", kX64Cmp32, MachineType::Uint32()},
    {TSBinop::kWord32Add, "Int32Add", kX64Lea32, MachineType::Int32()},
    {TSBinop::kWord32Sub, "Int32Sub", kX64Sub32, MachineType::Int32()},
    {TSBinop::kWord32Mul, "Int32Mul", kX64Imul32, MachineType::Int32()},
    {TSBinop::kInt32MulOverflownBits, "Int32MulOverflownBits", kX64ImulHigh32,
     MachineType::Int32()},
    {TSBinop::kInt32Div, "Int32Div", kX64Idiv32, MachineType::Int32()},
    {TSBinop::kInt32LessThan, "Int32LessThan", kX64Cmp32, MachineType::Int32()},
    {TSBinop::kInt32LessThanOrEqual, "Int32LessThanOrEqual", kX64Cmp32,
     MachineType::Int32()},
    {TSBinop::kInt32Mod, "Int32Mod", kX64Idiv32, MachineType::Int32()},
    {TSBinop::kUint32Div, "Uint32Div", kX64Udiv32, MachineType::Uint32()},
    {TSBinop::kUint32LessThan, "Uint32LessThan", kX64Cmp32,
     MachineType::Uint32()},
    {TSBinop::kUint32LessThanOrEqual, "Uint32LessThanOrEqual", kX64Cmp32,
     MachineType::Uint32()},
    {TSBinop::kUint32Mod, "Uint32Mod", kX64Udiv32, MachineType::Uint32()},
};

// The parameterized test that use the following type are intentionally part
// of the anonymous namespace. The issue here is that the type parameter is
// using a type that is in the anonymous namespace, but the class generated by
// TEST_P is not. This will cause GCC to generate a -Wsubobject-linkage warning.
//
// In this case there will only be single translation unit and the warning
// about subobject-linkage can be avoided by placing the class generated
// by TEST_P in the anoynmous namespace as well.
using TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test, Parameter) {
  const MachInst2 binop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), binop.machine_type,
                  binop.machine_type);
  m.Return(
      m.ChangeUint32ToUint64(m.Emit(binop.op, m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  // Make sure the `ChangeUint32ToUint64` node turned into a no-op.
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

}  // namespace

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test,
    ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

// ChangeUint32ToUint64AfterLoad
TEST_F(TurboshaftInstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // movzxbl
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxbl, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // movsxbl
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movsxbl, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // movzxwl
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxwl, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // movsxwl
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Int16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movsxwl, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

// -----------------------------------------------------------------------------
// TruncateInt64ToInt32.

TEST_F(TurboshaftInstructionSelectorTest, TruncateInt64ToInt32WithWord64Sar) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  OpIndex const p = m.Parameter(0);
  OpIndex const t = m.TruncateWord64ToWord32(
      m.Word64ShiftRightArithmetic(p, m.Int32Constant(32)));
  m.Return(t);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Shr, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(32, s.ToInt32(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE(s.IsSameAsFirst(s[0]->OutputAt(0)));
  EXPECT_EQ(s.ToVreg(t), s.ToVreg(s[0]->OutputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, TruncateInt64ToInt32WithWord64Shr) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  OpIndex const p = m.Parameter(0);
  OpIndex const t = m.TruncateWord64ToWord32(
      m.Word64ShiftRightLogical(p, m.Int32Constant(32)));
  m.Return(t);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Shr, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(32, s.ToInt32(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE(s.IsSameAsFirst(s[0]->OutputAt(0)));
  EXPECT_EQ(s.ToVreg(t), s.ToVreg(s[0]->OutputAt(0)));
}

// -----------------------------------------------------------------------------
// Addition.

TEST_F(TurboshaftInstructionSelectorTest, Int32AddWithInt32ParametersLea) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const a0 = m.Word32Add(p0, p1);
  // Additional uses of input to add chooses lea
  OpIndex const a1 = m.Int32Div(p0, p1);
  m.Return(m.Int32Div(a0, a1));
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddConstantAsLeaSingle) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c0 = m.Int32Constant(15);
  // If one of the add's operands is only used once, use an "leal", even though
  // an "addl" could be used. The "leal" has proven faster--out best guess is
  // that it gives the register allocation more freedom and it doesn't set
  // flags, reducing pressure in the CPU's pipeline. If we're lucky with
  // register allocation, then code generation will select an "addl" later for
  // the cases that have been measured to be faster.
  OpIndex const v0 = m.Word32Add(p0, c0);
  m.Return(v0);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddConstantAsAdd) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c0 = m.Int32Constant(1);
  // If there is only a single use of an add's input and the immediate constant
  // for the add is 1, don't use an inc. It is much slower on modern Intel
  // architectures.
  m.Return(m.Word32Add(p0, c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddConstantAsLeaDouble) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c0 = m.Int32Constant(15);
  // A second use of an add's input uses lea
  OpIndex const a0 = m.Word32Add(p0, c0);
  m.Return(m.Int32Div(a0, p0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddSimpleAsAdd) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  // If one of the add's operands is only used once, use an "leal", even though
  // an "addl" could be used. The "leal" has proven faster--out best guess is
  // that it gives the register allocation more freedom and it doesn't set
  // flags, reducing pressure in the CPU's pipeline. If we're lucky with
  // register allocation, then code generation will select an "addl" later for
  // the cases that have been measured to be faster.
  m.Return(m.Word32Add(p0, p1));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddSimpleAsLea) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  // If all of of the add's operands are used multiple times, use an "leal".
  OpIndex const v1 = m.Word32Add(p0, p1);
  m.Return(m.Word32Add(m.Word32Add(v1, p1), p0));
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled2Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  m.Return(m.Word32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddCommutedScaled2Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  m.Return(m.Word32Add(s0, p0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled2Shl) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  m.Return(m.Word32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddCommutedScaled2Shl) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  m.Return(m.Word32Add(s0, p0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled4Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 2);
  m.Return(m.Word32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled4Shl) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, m.Int32Constant(2));
  m.Return(m.Word32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled8Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 3);
  m.Return(m.Word32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled8Shl) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 3);
  m.Return(m.Word32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled2MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest,
       Int32AddScaled2MulWithConstantShuffle1) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(p0, m.Word32Add(s0, c0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest,
       Int32AddScaled2MulWithConstantShuffle2) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(s0, m.Word32Add(c0, p0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest,
       Int32AddScaled2MulWithConstantShuffle3) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(s0, c0), p0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest,
       Int32AddScaled2MulWithConstantShuffle4) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(c0, p0), s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest,
       Int32AddScaled2MulWithConstantShuffle5) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled2ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, m.Int32Constant(1));
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled4MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 2);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled4ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, m.Int32Constant(2));
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled8MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 3);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled8ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 3);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32SubConstantAsSub) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c0 = m.Int32Constant(-1);
  // If there is only a single use of on of the sub's non-constant input, use a
  // "subl" instruction.
  m.Return(m.Word32Sub(p0, c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32SubConstantAsLea) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c0 = m.Int32Constant(-1);
  // If there are multiple uses of on of the sub's non-constant input, use a
  // "leal" instruction.
  OpIndex const v0 = m.Word32Sub(p0, c0);
  m.Return(m.Int32Div(p0, v0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled2Other) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const p2 = m.Parameter(2);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  OpIndex const a0 = m.Word32Add(s0, p2);
  OpIndex const a1 = m.Word32Add(p0, a0);
  m.Return(a1);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[0]->OutputAt(0)));
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(kX64Lea32, s[1]->arch_opcode());
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a1), s.ToVreg(s[1]->OutputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddMinNegativeDisplacement) {
  // This test case is simplified from a Wasm fuzz test in
  // https://crbug.com/1091892. The key here is that we match on a
  // sequence like: Word32Add(Word32Sub(-524288, -2147483648), -26048), which
  // matches on an EmitLea, with -2147483648 as the displacement. Since we
  // have an Int32Sub node, it sets kNegativeDisplacement, and later we try to
  // negate -2147483648, which overflows.
  StreamBuilder m(this, MachineType::Int32());
  OpIndex const c0 = m.Int32Constant(-524288);
  OpIndex const c1 = m.Int32Constant(std::numeric_limits<int32_t>::min());
  OpIndex const c2 = m.Int32Constant(-26048);
  OpIndex const a0 = m.Word32Sub(c0, c1);
  OpIndex const a1 = m.Word32Add(a0, c2);
  m.Return(a1);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());

  EXPECT_EQ(kX64Sub32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kMode_None, s[0]->addressing_mode());
  EXPECT_EQ(s.ToVreg(c0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(c1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[0]->OutputAt(0)));

  EXPECT_EQ(kX64Lea32, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_TRUE(s[1]->InputAt(1)->IsImmediate());
  EXPECT_EQ(s.ToVreg(a1), s.ToVreg(s[1]->OutputAt(0)));
}

// -----------------------------------------------------------------------------
// Multiplication.

TEST_F(TurboshaftInstructionSelectorTest, Int32MulWithInt32MulWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const m0 = m.Word32Mul(p0, p1);
  m.Return(m.Word32Mul(m0, p0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Imul32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(m0), s.ToVreg(s[0]->OutputAt(0)));
  EXPECT_EQ(kX64Imul32, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(m0), s.ToVreg(s[1]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32MulOverflownBits) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Int32MulOverflownBits(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64ImulHigh32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s.IsFixed(s[0]->InputAt(0), rax));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(!s.IsUsedAtStart(s[0]->InputAt(1)));
  ASSERT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_TRUE(s.IsFixed(s[0]->OutputAt(0), rdx));
}

TEST_F(TurboshaftInstructionSelectorTest, Uint32MulOverflownBits) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Uint32MulOverflownBits(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64UmulHigh32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s.IsFixed(s[0]->InputAt(0), rax));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(!s.IsUsedAtStart(s[0]->InputAt(1)));
  ASSERT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_TRUE(s.IsFixed(s[0]->OutputAt(0), rdx));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul2BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(2);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul3BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(3);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul4BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(4);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M4, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul5BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(5);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul8BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(8);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M8, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul9BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(9);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

// -----------------------------------------------------------------------------
// Word32ShiftLeft.

TEST_F(TurboshaftInstructionSelectorTest, Int32Shl1BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(1);
  OpIndex const n = m.Word32ShiftLeft(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Shl2BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(2);
  OpIndex const n = m.Word32ShiftLeft(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M4, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Shl4BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(3);
  OpIndex const n = m.Word32ShiftLeft(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M8, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}

// -----------------------------------------------------------------------------
// Binops with a memory operand.

TEST_F(TurboshaftInstructionSelectorTest, LoadCmp32) {
  {
    // Word32Equal(Load[Int8](p0, p1), Int32Constant(0)) -> cmpb [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(
        m.Word32Equal(m.Load(MachineType::Int8(), p0, p1), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp8, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(LoadImmutable[Int8](p0, p1), Int32Constant(0)) ->
    //  cmpb [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.LoadImmutable(MachineType::Int8(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp8, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Uint8](p0, p1), Int32Constant(0)) -> cmpb [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Uint8(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp8, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Int16](p0, p1), Int32Constant(0)) -> cmpw [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Int16(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp16, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Uint16](p0, p1), Int32Constant(0)) -> cmpw [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Uint16(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp16, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Int32](p0, p1), Int32Constant(0)) -> cmpl [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Int32(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Uint32](p0, p1), Int32Constant(0)) -> cmpl [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Uint32(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAnd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word32BitwiseAnd(
      p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64And32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadOr32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word32BitwiseOr(
      p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Or32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadXor32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word32BitwiseXor(
      p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Xor32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAdd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(
      m.Word32Add(p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  // Use lea instead of add, so memory operand is invalid.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
  EXPECT_EQ(kX64Lea32, s[1]->arch_opcode());
}

TEST_F(TurboshaftInstructionSelectorTest, LoadSub32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(
      m.Word32Sub(p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Sub32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAnd64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word64BitwiseAnd(
      p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64And, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadOr64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word64BitwiseOr(
      p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Or, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadXor64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word64BitwiseXor(
      p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Xor, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAdd64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(
      m.Word64Add(p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  // Use lea instead of add, so memory operand is invalid.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Movq, s[0]->arch_opcode());
  EXPECT_EQ(kX64Lea, s[1]->arch_opcode());
}

TEST_F(TurboshaftInstructionSelectorTest, LoadSub64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(
      m.Word64Sub(p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Sub, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

// -----------------------------------------------------------------------------
// Floating point operations.

TEST_F(TurboshaftInstructionSelectorTest, Float32Abs) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Float32Abs(p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Float32Abs, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(s.IsSameAsFirst(s[0]->Output()));
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Float32Abs(p0);
    m.Return(n);
    Stream s = m.Build(AVX);
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Float32Abs, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Abs) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Float64Abs(p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Float64Abs, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(s.IsSameAsFirst(s[0]->Output()));
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Float64Abs(p0);
    m.Return(n);
    Stream s = m.Build(AVX);
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Float64Abs, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Float64BinopArithmetic) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Float64());
    OpIndex add = m.Float64Add(m.Parameter(0), m.Parameter(1));
    OpIndex mul = m.Float64Mul(add, m.Parameter(1));
    OpIndex sub = m.Float64Sub(mul, add);
    OpIndex ret = m.Float64Div(mul, sub);
    m.Return(ret);
    Stream s = m.Build(AVX);
    ASSERT_EQ(4U, s.size());
    EXPECT_EQ(kAVXFloat64Add, s[0]->arch_opcode());
    EXPECT_EQ(kAVXFloat64Mul, s[1]->arch_opcode());
    EXPECT_EQ(kAVXFloat64Sub, s[2]->arch_opcode());
    EXPECT_EQ(kAVXFloat64Div, s[3]->arch_opcode());
  }
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Float64());
    OpIndex add = m.Float64Add(m.Parameter(0), m.Parameter(1));
    OpIndex mul = m.Float64Mul(add, m.Parameter(1));
    OpIndex sub = m.Float64Sub(mul, add);
    OpIndex ret = m.Float64Div(mul, sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(4U, s.size());
    EXPECT_EQ(kSSEFloat64Add, s[0]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Mul, s[1]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Sub, s[2]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Div, s[3]->arch_opcode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Float32BinopArithmeticWithLoad) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const p2 = m.Parameter(2);
    OpIndex add = m.Float32Add(
        p0, m.Load(MachineType::Float32(), p1, m.Int64Constant(127)));
    OpIndex sub = m.Float32Sub(
        add, m.Load(MachineType::Float32(), p1, m.Int64Constant(127)));
    OpIndex ret = m.Float32Mul(
        m.Load(MachineType::Float32(), p2, m.Int64Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build(AVX);
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kAVXFloat32Add, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kAVXFloat32Sub, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[1]->InputCount());
    EXPECT_EQ(kAVXFloat32Mul, s[2]->arch_opcode());
    ASSERT_EQ(3U, s[2]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[2]->InputAt(1)));
  }
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const p2 = m.Parameter(2);
    OpIndex add = m.Float32Add(
        p0, m.Load(MachineType::Float32(), p1, m.Int64Constant(127)));
    OpIndex sub = m.Float32Sub(
        add, m.Load(MachineType::Float32(), p1, m.Int64Constant(127)));
    OpIndex ret = m.Float32Mul(
        m.Load(MachineType::Float32(), p2, m.Int64Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kSSEFloat32Add, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kSSEFloat32Sub, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[1]->InputCount());
    EXPECT_EQ(kSSEFloat32Mul, s[2]->arch_opcode());
    ASSERT_EQ(3U, s[2]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[2]->InputAt(1)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Float64BinopArithmeticWithLoad) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const p2 = m.Parameter(2);
    OpIndex add = m.Float64Add(
        p0, m.Load
"""


```