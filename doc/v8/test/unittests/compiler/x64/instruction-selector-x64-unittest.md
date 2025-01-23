Response: The user wants a summary of the functionality of the C++ source code file `v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc`. This is part 1 of 2.

The file appears to contain unit tests for the instruction selector in the V8 JavaScript engine, specifically targeting the x64 architecture. The tests verify that the instruction selector correctly translates high-level operations into specific x64 machine instructions.

The code defines various test cases using the `TEST_F` macro, which indicates tests within a fixture class (likely `InstructionSelectorTest`). Each test case sets up a small computation graph using `StreamBuilder`, performs instruction selection, and then asserts that the resulting instruction stream (`Stream`) contains the expected x64 opcodes.

Based on the names of the test cases, the file focuses on testing instruction selection for:

- **Conversions:** Converting between different numeric types (e.g., float32 to float64, int32 to int64).
- **Selections:** Conditional selection of values based on a condition.
- **Loads and Stores:** Accessing memory with different data types.
- **Arithmetic Operations:** Addition, subtraction, multiplication, division, bitwise operations. It also tests how these operations are optimized, such as using `lea` for certain addition and multiplication patterns.
- **Floating-Point Operations:**  Basic arithmetic operations (add, subtract, multiply, divide, absolute value).
- **Optimization Patterns:**  Specific sequences of operations and how the instruction selector combines or optimizes them. For example, it checks if `ChangeUint32ToUint64` can be elided in certain contexts.
- **Memory Operands:**  Testing if operations can directly use memory operands.

The tests use assertions like `ASSERT_EQ` and `EXPECT_EQ` to verify the correctness of the generated instructions, checking the opcode, input/output counts, and addressing modes.

The code also utilizes parameterized tests (`TEST_P`) to test a range of similar scenarios, like loading different sized integers and then converting them to int64.

If this code is related to JavaScript functionality, it's at a very low level. The instruction selector is a component that takes the optimized intermediate representation of JavaScript code and translates it into machine code. So, while it doesn't directly implement JavaScript features, its correctness is crucial for the performance and correctness of JavaScript execution in V8 on x64.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于测试在x64架构上的**指令选择器 (Instruction Selector)** 的功能。

**功能归纳:**

这个文件的主要目的是验证指令选择器是否能够正确地将高级的、平台无关的中间表示 (Intermediate Representation - IR) 的操作 **映射 (select)** 到特定的x64汇编指令。

具体来说，这个文件包含了大量的单元测试，每个测试都针对一个或一组特定的IR操作，并断言指令选择器会生成预期的x64机器码指令序列。  测试覆盖了各种场景，包括：

* **类型转换 (Conversions):** 测试不同数据类型之间的转换，例如 `float32` 到 `float64`，`int32` 到 `int64` 等。
* **选择 (Select):** 测试基于条件选择不同值的操作。
* **加载和存储 (Loads and Stores):** 测试从内存加载数据和将数据存储到内存的操作，涵盖了不同大小的数据类型。
* **算术运算 (Arithmetic Operations):** 测试加、减、乘、除、位运算等基本算术操作，并验证是否选择了合适的x64指令，例如 `lea` 指令在某些加法场景下的优化。
* **浮点运算 (Floating point operations):** 测试浮点数的绝对值、加、减、乘、除等运算。
* **特定指令的生成:** 验证是否生成了特定的x64指令，例如 `movsxlq`, `movzxbl`, `kX64Lea32` 等。
* **指令的属性验证:** 检查生成指令的输入、输出数量，寻址模式，以及标志位设置等属性是否符合预期。
* **优化路径的测试:** 验证指令选择器是否能够识别并应用特定的优化模式，例如在某些情况下省略 `ChangeUint32ToUint64` 操作。

**与JavaScript功能的关联及JavaScript示例:**

指令选择器是V8编译流水线中的一个重要环节。当V8执行JavaScript代码时，它会将JavaScript源代码编译成字节码，然后将字节码进一步优化成更底层的中间表示。指令选择器则负责将这些中间表示的操作转换为目标机器（这里是x64）的机器码指令。

因此，这个文件中的测试实际上是在验证V8的编译器后端是否能够针对x64架构生成高效且正确的机器码，从而保证JavaScript代码在该架构上的正确执行和性能。

以下是一些与测试用例相关的JavaScript示例，它们最终会通过V8的编译流程，并由指令选择器转换成x64指令：

1. **类型转换 (例如 `ChangeFloat32ToFloat64`):**

   ```javascript
   function convertFloat(x) {
     return Number(x); // 将一个单精度浮点数转换为双精度浮点数
   }

   convertFloat(3.14);
   ```

   在这个例子中，如果 `x` 在V8内部以单精度浮点数表示，`Number(x)` 的操作就需要将其转换为双精度浮点数，这对应于测试中的 `ChangeFloat32ToFloat64`。指令选择器会选择 `kSSEFloat32ToFloat64` 指令来完成这个转换。

2. **算术运算 (例如 `Int32Add`):**

   ```javascript
   function addNumbers(a, b) {
     return a + b; // 两个整数相加
   }

   addNumbers(5, 10);
   ```

   这里的 `a + b` 操作会对应于测试中的 `Int32Add`。指令选择器可能会选择 `kX64Lea32` 或 `kX64Add32` 等指令来实现加法。

3. **加载和存储 (例如 `Load` 和 `Store`):**

   ```javascript
   let arr = [1, 2, 3];
   let first = arr[0]; // 从数组中加载元素
   arr[1] = 4;        // 将值存储到数组中
   ```

   访问数组元素 `arr[0]` 会对应于测试中的 `Load` 操作，而给数组元素赋值 `arr[1] = 4` 则对应于 `Store` 操作。指令选择器会选择相应的 `kX64Mov` 指令来执行内存的读写。

4. **位运算 (例如 `Word32And`):**

   ```javascript
   function bitwiseAnd(a, b) {
     return a & b; // 两个整数进行按位与运算
   }

   bitwiseAnd(10, 5);
   ```

   `a & b` 操作会对应于测试中的 `Word32And`，指令选择器会选择 `kX64And32` 指令。

总而言之，这个单元测试文件确保了V8 JavaScript引擎在x64架构下能够正确地将各种高级操作转换为底层的机器指令，这是保证JavaScript代码高效执行的基础。每个测试用例都像是一个小型的JavaScript代码片段在机器码层面的“投影”。

### 提示词
```
这是目录为v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "src/codegen/assembler.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/backend/instruction-selector-unittest.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/simd-shuffle.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

// -----------------------------------------------------------------------------
// Conversions.


TEST_F(InstructionSelectorTest, ChangeFloat32ToFloat64WithParameter) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float64());
  m.Return(m.ChangeFloat32ToFloat64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kSSEFloat32ToFloat64, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, ChangeInt32ToInt64WithParameter) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
  m.Return(m.ChangeInt32ToInt64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Movsxlq, s[0]->arch_opcode());
}

TEST_F(InstructionSelectorTest, ChangeUint32ToFloat64WithParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Uint32());
  m.Return(m.ChangeUint32ToFloat64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kSSEUint32ToFloat64, s[0]->arch_opcode());
}


TEST_F(InstructionSelectorTest, ChangeUint32ToUint64WithParameter) {
  StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint32());
  m.Return(m.ChangeUint32ToUint64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
}


TEST_F(InstructionSelectorTest, TruncateFloat64ToFloat32WithParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float32());
  m.Return(m.TruncateFloat64ToFloat32(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kSSEFloat64ToFloat32, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, TruncateInt64ToInt32WithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  m.Return(m.TruncateInt64ToInt32(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
}

TEST_F(InstructionSelectorTest, SelectWord32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Word32Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  EXPECT_EQ(kX64Cmp32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  EXPECT_TRUE(s.IsSameAsInput(s[0]->Output(), 2));
}

TEST_F(InstructionSelectorTest, SelectWord64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* cond = m.Int32Constant(1);
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
using InstructionSelectorChangeInt32ToInt64Test =
    InstructionSelectorTestWithParam<LoadWithToInt64Extension>;

TEST_P(InstructionSelectorChangeInt32ToInt64Test, ChangeInt32ToInt64WithLoad) {
  const LoadWithToInt64Extension extension = GetParam();
  StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer());
  m.Return(m.ChangeInt32ToInt64(m.Load(extension.type, m.Parameter(0))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(extension.expected_opcode, s[0]->arch_opcode());
}

}  // namespace

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorChangeInt32ToInt64Test,
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
using InstructionSelectorMemoryAccessTest =
    InstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_P(InstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                  MachineType::Int32(), memacc.type);
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// -----------------------------------------------------------------------------
// ChangeUint32ToUint64.


namespace {

using Constructor = Node* (RawMachineAssembler::*)(Node*, Node*);

struct BinaryOperation {
  Constructor constructor;
  const char* constructor_name;
};


std::ostream& operator<<(std::ostream& os, const BinaryOperation& bop) {
  return os << bop.constructor_name;
}


const BinaryOperation kWord32BinaryOperations[] = {
    {&RawMachineAssembler::Word32And, "Word32And"},
    {&RawMachineAssembler::Word32Or, "Word32Or"},
    {&RawMachineAssembler::Word32Xor, "Word32Xor"},
    {&RawMachineAssembler::Word32Shl, "Word32Shl"},
    {&RawMachineAssembler::Word32Shr, "Word32Shr"},
    {&RawMachineAssembler::Word32Sar, "Word32Sar"},
    {&RawMachineAssembler::Word32Ror, "Word32Ror"},
    {&RawMachineAssembler::Word32Equal, "Word32Equal"},
    {&RawMachineAssembler::Int32Add, "Int32Add"},
    {&RawMachineAssembler::Int32Sub, "Int32Sub"},
    {&RawMachineAssembler::Int32Mul, "Int32Mul"},
    {&RawMachineAssembler::Int32MulHigh, "Int32MulHigh"},
    {&RawMachineAssembler::Int32Div, "Int32Div"},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan"},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual"},
    {&RawMachineAssembler::Int32Mod, "Int32Mod"},
    {&RawMachineAssembler::Uint32Div, "Uint32Div"},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan"},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual"},
    {&RawMachineAssembler::Uint32Mod, "Uint32Mod"}};

// The parameterized test that use the following type are intentionally part
// of the anonymous namespace. The issue here is that the type parameter is
// using a type that is in the anonymous namespace, but the class generated by
// TEST_P is not. This will cause GCC to generate a -Wsubobject-linkage warning.
//
// In this case there will only be single translation unit and the warning
// about subobject-linkage can be avoided by placing the class generated
// by TEST_P in the anoynmous namespace as well.
using InstructionSelectorChangeUint32ToUint64Test =
    InstructionSelectorTestWithParam<BinaryOperation>;

TEST_P(InstructionSelectorChangeUint32ToUint64Test, ChangeUint32ToUint64) {
  const BinaryOperation& bop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(m.ChangeUint32ToUint64((m.*bop.constructor)(p0, p1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
}

}  // namespace

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorChangeUint32ToUint64Test,
                         ::testing::ValuesIn(kWord32BinaryOperations));

// -----------------------------------------------------------------------------
// CanElideChangeUint32ToUint64

namespace {

template <typename T>
struct MachInst {
  T constructor;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  MachineType machine_type;
};

using MachInst2 = MachInst<Node* (RawMachineAssembler::*)(Node*, Node*)>;

// X64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {&RawMachineAssembler::Word32And, "Word32And", kX64And32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kX64Or32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kX64Xor32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Shl, "Word32Shl", kX64Shl32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Shr, "Word32Shr", kX64Shr32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Sar, "Word32Sar", kX64Sar32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Ror, "Word32Ror", kX64Ror32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kX64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int32Add, "Int32Add", kX64Lea32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kX64Sub32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Mul, "Int32Mul", kX64Imul32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32MulHigh, "Int32MulHigh", kX64ImulHigh32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Div, "Int32Div", kX64Idiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan", kX64Cmp32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
     kX64Cmp32, MachineType::Int32()},
    {&RawMachineAssembler::Int32Mod, "Int32Mod", kX64Idiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kX64Udiv32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kX64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
     kX64Cmp32, MachineType::Uint32()},
    {&RawMachineAssembler::Uint32Mod, "Uint32Mod", kX64Udiv32,
     MachineType::Uint32()},
};

// The parameterized test that use the following type are intentionally part
// of the anonymous namespace. The issue here is that the type parameter is
// using a type that is in the anonymous namespace, but the class generated by
// TEST_P is not. This will cause GCC to generate a -Wsubobject-linkage warning.
//
// In this case there will only be single translation unit and the warning
// about subobject-linkage can be avoided by placing the class generated
// by TEST_P in the anoynmous namespace as well.
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

}  // namespace

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorElidedChangeUint32ToUint64Test,
                         ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

// ChangeUint32ToUint64AfterLoad
TEST_F(InstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // movzxbl
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
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
                    MachineType::Int32());
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
                    MachineType::Int32());
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
                    MachineType::Int32());
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


TEST_F(InstructionSelectorTest, TruncateInt64ToInt32WithWord64Sar) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  Node* const p = m.Parameter(0);
  Node* const t = m.TruncateInt64ToInt32(m.Word64Sar(p, m.Int64Constant(32)));
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


TEST_F(InstructionSelectorTest, TruncateInt64ToInt32WithWord64Shr) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  Node* const p = m.Parameter(0);
  Node* const t = m.TruncateInt64ToInt32(m.Word64Shr(p, m.Int64Constant(32)));
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


TEST_F(InstructionSelectorTest, Int32AddWithInt32ParametersLea) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const a0 = m.Int32Add(p0, p1);
  // Additional uses of input to add chooses lea
  Node* const a1 = m.Int32Div(p0, p1);
  m.Return(m.Int32Div(a0, a1));
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Int32AddConstantAsLeaSingle) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(15);
  // If one of the add's operands is only used once, use an "leal", even though
  // an "addl" could be used. The "leal" has proven faster--out best guess is
  // that it gives the register allocation more freedom and it doesn't set
  // flags, reducing pressure in the CPU's pipeline. If we're lucky with
  // register allocation, then code generation will select an "addl" later for
  // the cases that have been measured to be faster.
  Node* const v0 = m.Int32Add(p0, c0);
  m.Return(v0);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddConstantAsAdd) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(1);
  // If there is only a single use of an add's input and the immediate constant
  // for the add is 1, don't use an inc. It is much slower on modern Intel
  // architectures.
  m.Return(m.Int32Add(p0, c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddConstantAsLeaDouble) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(15);
  // A second use of an add's input uses lea
  Node* const a0 = m.Int32Add(p0, c0);
  m.Return(m.Int32Div(a0, p0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddCommutedConstantAsLeaSingle) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(15);
  // If one of the add's operands is only used once, use an "leal", even though
  // an "addl" could be used. The "leal" has proven faster--out best guess is
  // that it gives the register allocation more freedom and it doesn't set
  // flags, reducing pressure in the CPU's pipeline. If we're lucky with
  // register allocation, then code generation will select an "addl" later for
  // the cases that have been measured to be faster.
  m.Return(m.Int32Add(c0, p0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddCommutedConstantAsLeaDouble) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(15);
  // A second use of an add's input uses lea
  Node* const a0 = m.Int32Add(c0, p0);
  USE(a0);
  m.Return(m.Int32Div(a0, p0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddSimpleAsAdd) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  // If one of the add's operands is only used once, use an "leal", even though
  // an "addl" could be used. The "leal" has proven faster--out best guess is
  // that it gives the register allocation more freedom and it doesn't set
  // flags, reducing pressure in the CPU's pipeline. If we're lucky with
  // register allocation, then code generation will select an "addl" later for
  // the cases that have been measured to be faster.
  m.Return(m.Int32Add(p0, p1));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddSimpleAsLea) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  // If all of of the add's operands are used multiple times, use an "leal".
  Node* const v1 = m.Int32Add(p0, p1);
  m.Return(m.Int32Add(m.Int32Add(v1, p1), p0));
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddScaled2Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  m.Return(m.Int32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddCommutedScaled2Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  m.Return(m.Int32Add(s0, p0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddScaled2Shl) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(1));
  m.Return(m.Int32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddCommutedScaled2Shl) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(1));
  m.Return(m.Int32Add(s0, p0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddScaled4Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(4));
  m.Return(m.Int32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddScaled4Shl) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(2));
  m.Return(m.Int32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddScaled8Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(8));
  m.Return(m.Int32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddScaled8Shl) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(3));
  m.Return(m.Int32Add(p0, s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32AddScaled2MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2MulWithConstantShuffle1) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(p0, m.Int32Add(s0, c0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2MulWithConstantShuffle2) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(s0, m.Int32Add(c0, p0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2MulWithConstantShuffle3) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(m.Int32Add(s0, c0), p0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2MulWithConstantShuffle4) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(m.Int32Add(c0, p0), s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2MulWithConstantShuffle5) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(m.Int32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(1));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled4MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(4));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled4ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled8MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(8));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled8ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(3));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32SubConstantAsSub) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(-1);
  // If there is only a single use of on of the sub's non-constant input, use a
  // "subl" instruction.
  m.Return(m.Int32Sub(p0, c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32SubConstantAsLea) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(-1);
  // If there are multiple uses of on of the sub's non-constant input, use a
  // "leal" instruction.
  Node* const v0 = m.Int32Sub(p0, c0);
  m.Return(m.Int32Div(p0, v0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2Other) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const p2 = m.Parameter(2);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const a0 = m.Int32Add(s0, p2);
  Node* const a1 = m.Int32Add(p0, a0);
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
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a1), s.ToVreg(s[1]->OutputAt(0)));
}

TEST_F(InstructionSelectorTest, Int32AddMinNegativeDisplacement) {
  // This test case is simplified from a Wasm fuzz test in
  // https://crbug.com/1091892. The key here is that we match on a
  // sequence like: Int32Add(Int32Sub(-524288, -2147483648), -26048), which
  // matches on an EmitLea, with -2147483648 as the displacement. Since we
  // have an Int32Sub node, it sets kNegativeDisplacement, and later we try to
  // negate -2147483648, which overflows.
  StreamBuilder m(this, MachineType::Int32());
  Node* const c0 = m.Int32Constant(-524288);
  Node* const c1 = m.Int32Constant(std::numeric_limits<int32_t>::min());
  Node* const c2 = m.Int32Constant(-26048);
  Node* const a0 = m.Int32Sub(c0, c1);
  Node* const a1 = m.Int32Add(a0, c2);
  m.Return(a1);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());

  EXPECT_EQ(kX64Sub32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kMode_None, s[0]->addressing_mode());
  EXPECT_EQ(s.ToVreg(c0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(c1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[0]->OutputAt(0)));

  EXPECT_EQ(kX64Add32, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(kMode_None, s[1]->addressing_mode());
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_TRUE(s[1]->InputAt(1)->IsImmediate());
  EXPECT_EQ(s.ToVreg(a1), s.ToVreg(s[1]->OutputAt(0)));
}

// -----------------------------------------------------------------------------
// Multiplication.


TEST_F(InstructionSelectorTest, Int32MulWithInt32MulWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const m0 = m.Int32Mul(p0, p1);
  m.Return(m.Int32Mul(m0, p0));
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


TEST_F(InstructionSelectorTest, Int32MulHigh) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Int32MulHigh(p0, p1);
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


TEST_F(InstructionSelectorTest, Uint32MulHigh) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Uint32MulHigh(p0, p1);
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


TEST_F(InstructionSelectorTest, Int32Mul2BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(2);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32Mul3BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(3);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32Mul4BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(4);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M4, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Int32Mul5BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(5);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32Mul8BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(8);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M8, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Int32Mul9BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(9);
  Node* const n = m.Int32Mul(p0, c1);
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
// Word32Shl.


TEST_F(InstructionSelectorTest, Int32Shl1BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(1);
  Node* const n = m.Word32Shl(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32Shl2BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(2);
  Node* const n = m.Word32Shl(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M4, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Int32Shl4BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(3);
  Node* const n = m.Word32Shl(p0, c1);
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

TEST_F(InstructionSelectorTest, LoadCmp32) {
  {
    // Word32Equal(Load[Int8](p0, p1), Int32Constant(0)) -> cmpb [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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

TEST_F(InstructionSelectorTest, LoadAnd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word32And(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64And32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadOr32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word32Or(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Or32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadXor32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word32Xor(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Xor32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadAdd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Int32Add(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  // Use lea instead of add, so memory operand is invalid.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
  EXPECT_EQ(kX64Lea32, s[1]->arch_opcode());
}

TEST_F(InstructionSelectorTest, LoadSub32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Int32Sub(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Sub32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadAnd64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word64And(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64And, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadOr64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word64Or(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Or, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadXor64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word64Xor(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Xor, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadAdd64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Int64Add(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  // Use lea instead of add, so memory operand is invalid.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Movq, s[0]->arch_opcode());
  EXPECT_EQ(kX64Lea, s[1]->arch_opcode());
}

TEST_F(InstructionSelectorTest, LoadSub64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Int64Sub(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Sub, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

// -----------------------------------------------------------------------------
// Floating point operations.

TEST_F(InstructionSelectorTest, Float32Abs) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Float32Abs(p0);
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
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Float32Abs(p0);
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


TEST_F(InstructionSelectorTest, Float64Abs) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Float64Abs(p0);
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
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Float64Abs(p0);
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


TEST_F(InstructionSelectorTest, Float64BinopArithmetic) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Float64());
    Node* add = m.Float64Add(m.Parameter(0), m.Parameter(1));
    Node* mul = m.Float64Mul(add, m.Parameter(1));
    Node* sub = m.Float64Sub(mul, add);
    Node* ret = m.Float64Div(mul, sub);
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
    Node* add = m.Float64Add(m.Parameter(0), m.Parameter(1));
    Node* mul = m.Float64Mul(add, m.Parameter(1));
    Node* sub = m.Float64Sub(mul, add);
    Node* ret = m.Float64Div(mul, sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(4U, s.size());
    EXPECT_EQ(kSSEFloat64Add, s[0]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Mul, s[1]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Sub, s[2]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Div, s[3]->arch_opcode());
  }
}

TEST_F(InstructionSelectorTest, Float32BinopArithmeticWithLoad) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                    MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* add = m.Float32Add(
        p0, m.Load(MachineType::Float32(), p1, m.Int32Constant(127)));
    Node* sub = m.Float32Sub(
        add, m.Load(MachineType::Float32(), p1, m.Int32Constant(127)));
    Node* ret = m.Float32Mul(
        m.Load(MachineType::Float32(), p2, m.Int32Constant(127)), sub);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* add = m.Float32Add(
        p0, m.Load(MachineType::Float32(), p1, m.Int32Constant(127)));
    Node* sub = m.Float32Sub(
        add, m.Load(MachineType::Float32(), p1, m.Int32Constant(127)));
    Node* ret = m.Float32Mul(
        m.Load(MachineType::Float32(), p2, m.Int32Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kSSEFloat32Add, s[0]->arch_opc
```