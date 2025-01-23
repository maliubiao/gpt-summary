Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is a unit test file for the instruction selector on the x64 architecture in V8.

Here's a breakdown of the code's functionality:
1. **Includes:** It includes necessary headers for V8's compiler, code generation, and testing frameworks.
2. **Namespace:** It's within the `v8::internal::compiler` namespace.
3. **Test Fixture:** It uses `InstructionSelectorTest`, a test fixture for instruction selector unit tests.
4. **Conversion Tests:** It tests the selection of instructions for various type conversion operations like `ChangeFloat32ToFloat64`, `ChangeInt32ToInt64`, `TruncateFloat64ToFloat32`, etc. It checks if the correct x64 opcode is selected.
5. **Select Tests:** It tests instruction selection for conditional selection (`Word32Select`, `Word64Select`).
6. **Load/Store Tests:** It tests instruction selection for memory access operations (`Load`, `Store`) for different data types.
7. **Binary Operation Tests:** It tests instruction selection for various binary operations like `Word32And`, `Word32Or`, `Int32Add`, etc., and how they interact with `ChangeUint32ToUint64`.
8. **Elision Tests:** It checks if the `ChangeUint32ToUint64` operation can be elided (optimized away) in certain contexts, especially after 32-bit operations that inherently clear the upper 32 bits of a 64-bit register.
9. **Truncate Tests:** It tests instruction selection for truncating 64-bit integers to 32-bit integers, specifically when combined with shift operations.
10. **Addition Tests:** It extensively tests different scenarios for 32-bit integer addition (`Int32Add`), focusing on when the `lea` instruction (load effective address) is chosen over `add`, especially with constants and scaled operands.

Regarding the additional questions:
- **.tq extension:** The file does not end with `.tq`, so it's not a Torque file.
- **JavaScript relation:** The code tests the *backend* of the compiler, which generates machine code. While it doesn't directly contain JavaScript code, the operations it tests (like type conversions, arithmetic, memory access) are fundamental to how JavaScript code is executed.
- **Code logic inference:** The tests often construct simple computational graphs and verify the selected instructions.
- **Common programming errors:**  While the test code itself doesn't demonstrate user errors, the functionalities being tested are related to potential issues like integer overflows, incorrect type conversions, or inefficient code patterns that the compiler aims to optimize.
这个C++源代码文件 `v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 **x64 架构下的指令选择器 (instruction selector)** 的功能。

以下是它的功能归纳：

1. **测试类型转换指令的选择:**
   -  测试各种类型之间的转换操作，例如：
      - 将 `float32` 转换为 `float64` (`ChangeFloat32ToFloat64`).
      - 将 `int32` 转换为 `int64` (`ChangeInt32ToInt64`).
      - 将 `uint32` 转换为 `float64` (`ChangeUint32ToFloat64`).
      - 将 `uint32` 转换为 `uint64` (`ChangeUint32ToUint64`).
      - 将 `float64` 截断为 `float32` (`TruncateFloat64ToFloat32`).
      - 将 `int64` 截断为 `int32` (`TruncateInt64ToInt32`).
   -  它会构建一个简单的计算图，模拟这些转换操作，并断言生成的机器指令 (opcode) 是否符合预期。

2. **测试条件选择指令的选择:**
   -  测试 `Word32Select` 和 `Word64Select` 操作，用于根据条件选择不同的值。
   -  验证是否生成了正确的比较指令 (`kX64Cmp32`) 以及相关的标志位设置。

3. **测试加载和存储指令的选择:**
   -  测试从内存加载不同类型数据 (`Load`) 和将不同类型数据存储到内存 (`Store`) 的指令选择。
   -  它会针对不同的数据类型（`Int8`, `Uint8`, `Int16`, `Uint16`, `Int32`, `Uint32`, `Int64`, `Uint64`, `Float32`, `Float64`）进行测试，并验证是否选择了正确的加载和存储指令 (例如 `kX64Movsxbl`, `kX64Movb`, `kX64Movl`, `kX64Movq`, `kX64Movss`, `kX64Movsd`)。

4. **测试 `ChangeUint32ToUint64` 指令的优化:**
   -  测试在某些情况下，`ChangeUint32ToUint64` 操作是否可以被优化掉 (elided)。
   -  例如，当一个 32 位操作（如 `Word32And`, `Word32Or`, `Int32Add` 等）的结果被转换为 `uint64` 时，由于 32 位操作本身会清空高 32 位，因此显式的转换操作可能是多余的。测试会验证在这种情况下是否会生成更精简的指令。

5. **测试 `TruncateInt64ToInt32` 指令与移位操作的结合:**
   -  测试当 `TruncateInt64ToInt32` 操作应用于 64 位有符号右移 (`Word64Sar`) 或无符号右移 (`Word64Shr`) 32 位的结果时，是否能优化为更有效的 32 位移位指令 (`kX64Shr`)。

6. **测试加法指令的选择:**
   -  对 32 位整数加法 (`Int32Add`) 进行了大量的测试，涵盖了各种情况：
      - 两个参数都是寄存器。
      - 其中一个参数是常量。
      - 加法结果被多次使用。
      - 加法与乘法或移位操作结合（用于地址计算，例如 `lea` 指令）。
   -  测试会验证在不同情况下是否选择了最优的加法指令，例如 `kX64Lea32`（load effective address，常用于地址计算和简单的加法）或其他的加法指令。

**关于其他问题的回答：**

* **`.tq` 结尾：** 该文件名为 `instruction-selector-x64-unittest.cc`，不是以 `.tq` 结尾，因此它是一个 **C++** 源代码文件，而不是 V8 Torque 源代码。

* **与 JavaScript 的功能关系：**  `instruction-selector-x64-unittest.cc`  直接关系到 JavaScript 代码的执行效率。指令选择器是编译器后端的重要组成部分，它的职责是将中间表示 (IR) 的操作转换为目标架构 (这里是 x64) 的机器指令。  **指令选择器的好坏直接影响生成的机器码的性能。** 例如，对加法操作选择 `lea` 指令在某些情况下比 `add` 指令更高效，这个测试文件就在验证这种选择是否正确。

* **JavaScript 举例说明：**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   let result = add(10, 5);
   ```

   当 V8 编译 `add` 函数时，指令选择器会负责将 `a + b` 这个操作转换为 x64 机器码。这个测试文件中的 `TEST_F(InstructionSelectorTest, Int32AddSimpleAsAdd)` 等测试用例，就是在验证当编译类似这样的 JavaScript 加法操作时，指令选择器是否能够正确地选择合适的 x64 加法指令。

* **代码逻辑推理（假设输入与输出）：**

   以 `TEST_F(InstructionSelectorTest, ChangeInt32ToInt64WithParameter)` 为例：

   **假设输入：**  一个表示 `int32` 类型的参数节点。
   **操作：**  执行 `ChangeInt32ToInt64` 将该参数转换为 `int64` 类型。
   **预期输出：**  生成的机器指令应该是 `kX64Movsxlq` (将 32 位有符号数移动并扩展到 64 位)。

* **涉及用户常见的编程错误：**

   虽然这个测试文件本身不直接演示用户的编程错误，但它测试的 **类型转换** 是用户经常出错的地方。例如：

   ```javascript
   let smallNumber = 10;
   let largeNumber = 1000000000000; // 大于 32 位整数的最大值

   // 错误的类型转换可能导致数据丢失或溢出
   let convertedSmall = parseInt(smallNumber);
   let convertedLarge = parseInt(largeNumber); // 可能截断或产生意外结果

   console.log(convertedSmall);
   console.log(convertedLarge);
   ```

   指令选择器需要正确处理这些类型转换，确保即使在 JavaScript 中发生隐式或显式类型转换时，生成的机器码也能按照预期工作，避免数据丢失或错误。

**总结：**

`v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc` 的主要功能是 **细致地测试 V8 引擎在 x64 架构下指令选择器的正确性，确保它能为各种中间表示的操作选择最优的机器指令，从而保证生成的机器码的性能和正确性。** 它涵盖了类型转换、条件选择、内存访问和算术运算等关键操作的指令选择测试。

### 提示词
```
这是目录为v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  Node*
```