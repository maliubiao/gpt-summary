Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Scan and Understanding the Purpose:**

The filename `turboshaft-instruction-selector-x64-unittest.cc` immediately suggests this file tests the instruction selection phase of the Turboshaft compiler for the x64 architecture. "Instruction selection" means choosing the specific machine instructions (like `mov`, `add`, etc.) to implement higher-level operations. The "unittest" part signifies focused testing of individual units or functionalities.

**2. Identifying Key Components and Patterns:**

As I read through the code, I notice several recurring elements:

* **`TEST_F(TurboshaftInstructionSelectorTest, ...)`:** This is the standard Google Test macro for defining test cases within a fixture. The fixture `TurboshaftInstructionSelectorTest` (and its parameterized variants) provides setup for the tests.
* **`StreamBuilder m(this, ...)`:** This class is central. It appears to be a helper for constructing a sequence of operations or "instructions" in a way that mirrors the intermediate representation used by the compiler. The arguments to the constructor likely specify the return type and parameter types of the code being tested.
* **`m.Return(...)`:**  This indicates the final result or output of the sequence of operations.
* **`m.ChangeFloat32ToFloat64(...)`, `m.ChangeInt32ToInt64(...)`, etc.:** These `m.` method calls represent various operations that the Turboshaft compiler needs to translate into x64 instructions. They act as the input to the instruction selector.
* **`Stream s = m.Build();`:** This step finalizes the sequence of operations built by `StreamBuilder` and likely triggers the instruction selection process.
* **`ASSERT_EQ(...)`, `EXPECT_EQ(...)`:** These are Google Test assertions used to verify the correctness of the instruction selection. They check properties of the generated instruction stream `s`.
* **`s.size()`, `s[0]->arch_opcode()`, `s[0]->InputCount()`, `s[0]->OutputCount()`, `s.IsSameAsInput(...)`, etc.:** These methods are used to inspect the properties of the selected instructions, such as the number of instructions, the specific x64 opcode, and the inputs and outputs.
* **`kSSEFloat32ToFloat64`, `kX64Movsxlq`, etc.:** These are constants likely representing the expected x64 instruction opcodes.
* **Parameterized Tests (`TEST_P`, `INSTANTIATE_TEST_SUITE_P`):**  The code uses parameterized tests to run the same test logic with different input values (e.g., different `MachineType` values for loads and stores). This is efficient for testing variations of a similar operation.

**3. Inferring Functionality from Test Names and Code:**

By combining the test names and the code within each test, I can infer the functionality being tested:

* **Conversions:** Tests like `ChangeFloat32ToFloat64WithParameter` check that the Turboshaft instruction selector correctly translates type conversion operations into the appropriate x64 instructions (e.g., `kSSEFloat32ToFloat64`).
* **Selections:** `SelectWord32` and `SelectWord64` test the selection of instructions for conditional logic (using the `kFlags_select` and `kNotEqual` flags).
* **Loads and Stores:** The `LoadWithParameters` and `StoreWithParameters` tests verify the generation of `mov` instructions for different data types and memory access patterns.
* **Binary Operations:** Tests under the `ChangeUint32ToUint64` and `CanElideChangeUint32ToUint64` sections check how 32-bit binary operations are handled, sometimes optimizing away unnecessary 32-to-64-bit conversions.
* **Truncation:** `TruncateInt64ToInt32WithWord64Sar` and `TruncateInt64ToInt32WithWord64Shr` test how 64-bit to 32-bit truncations are optimized, potentially by using shift operations.
* **Addition:** The numerous `Int32Add...` tests explore different scenarios for generating addition instructions, including using `lea` for address calculations and optimizing for constants and scaled operands.

**4. Addressing Specific Instructions:**

* **`.tq` extension:** The code explicitly checks for this, indicating that the file *is not* a Torque file.
* **JavaScript relation:**  I consider where these low-level operations might be relevant to JavaScript. Type conversions, arithmetic operations, and memory accesses are all fundamental to JavaScript execution.
* **Code logic reasoning:** For tests like the `SelectWord` tests, I can deduce the logic: if the condition is true (non-zero), one value is selected; otherwise, the other is. The generated x64 code uses a comparison and conditional move (implicitly through the flags mechanism).
* **Common programming errors:** I think about errors related to type mismatches, integer overflow/underflow, and incorrect memory access. While these specific tests don't directly *cause* those errors, they ensure the compiler handles the underlying operations correctly, which is essential for avoiding such errors in the larger JavaScript runtime.

**5. Structuring the Summary:**

Finally, I organize my observations into a concise summary, covering the main functionalities, the negative confirmation about Torque, the link to JavaScript, and the aspects of code logic and potential errors. I also ensure to note that this is "part 1" and there will be more functionality covered in subsequent parts.
这是一个C++的单元测试文件，用于测试V8 JavaScript引擎中Turboshaft编译器的x64架构的指令选择器（instruction selector）。指令选择器的作用是将高级的、平台无关的中间表示（IR）转换成特定的目标架构（这里是x64）的机器指令。

**功能归纳:**

这个文件的主要功能是针对x64架构，测试Turboshaft编译器在进行指令选择时，对于各种操作（例如类型转换、算术运算、内存访问等）是否能生成正确的x64汇编指令。

更具体地说，从代码中可以看出，它测试了以下几个方面的指令选择：

1. **类型转换指令选择:**
   - `ChangeFloat32ToFloat64`: 将32位浮点数转换为64位浮点数。
   - `ChangeInt32ToInt64`: 将32位有符号整数转换为64位有符号整数。
   - `ChangeUint32ToFloat64`: 将32位无符号整数转换为64位浮点数。
   - `ChangeUint32ToUint64`: 将32位无符号整数转换为64位无符号整数。
   - `TruncateFloat64ToFloat32`: 将64位浮点数截断为32位浮点数。
   - `TruncateInt64ToInt32`: 将64位整数截断为32位整数。

2. **条件选择指令选择:**
   - `SelectWord32`: 基于条件选择32位的值。
   - `SelectWord64`: 基于条件选择64位的值。

3. **带符号扩展的加载指令选择:**
   - 测试从内存加载不同大小的整数（8位、16位、32位），并将其符号扩展为64位整数。

4. **加载和存储指令选择:**
   - 测试从内存加载不同数据类型（整数、浮点数）的值。
   - 测试将不同数据类型的值存储到内存中。

5. **32位二进制运算指令选择:**
   - 测试各种32位二进制运算（按位与、或、异或、移位、旋转、比较、加减乘除模等）的指令选择，并验证在将其结果转换为64位无符号整数时，是否会生成额外的转换指令。

6. **优化 `ChangeUint32ToUint64` 指令:**
   - 测试某些32位运算指令（例如加法、按位运算等）在x64架构上会自动清零高32位，因此后续的 `ChangeUint32ToUint64` 操作可以被优化掉。
   - 测试从内存加载小于64位的值（8位、16位、32位）时，`ChangeUint32ToUint64` 是否能被优化掉，因为加载指令本身会进行零扩展或符号扩展。

7. **优化 `TruncateInt64ToInt32` 指令:**
   - 测试当一个64位整数通过右移32位得到低32位时，`TruncateInt64ToInt32` 操作是否能被优化。

8. **加法指令选择的多种情况:**
   - 测试在不同情况下，32位整数加法会选择哪种x64指令（例如 `lea` 用于地址计算或多操作数加法，`add` 用于简单的加法）。涵盖了操作数是寄存器、常量以及 scaled 寻址的情况。

**关于文件后缀和 Torque:**

根据描述，`v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 的功能关系:**

这个文件测试的指令选择器是编译器的一部分，而编译器负责将 JavaScript 代码转换成机器代码。因此，这里测试的每一种指令选择都与 JavaScript 的功能息息相关。例如：

- **类型转换:** JavaScript 是一种动态类型语言，运行时会进行大量的类型转换。例如，将一个数字隐式转换为字符串，或者进行不同数值类型之间的运算。这些操作最终会由编译器生成相应的类型转换指令。
- **算术运算:** JavaScript 中的加减乘除、位运算等都需要通过底层的机器指令来实现。
- **内存访问:**  访问 JavaScript 对象的属性、数组元素等都需要进行内存加载和存储操作。

**JavaScript 示例:**

```javascript
// 类型转换
let float32Value = 1.0;
let float64Value = float32Value; // 隐式将 float32 转换为 float64

let int32Value = 10;
let int64Value = BigInt(int32Value); // 显式将 int32 转换为 BigInt (实际上是 64 位整数)

// 算术运算
let a = 5;
let b = 10;
let sum = a + b; // 对应 Int32Add 指令

// 条件选择
let condition = true;
let result = condition ? a : b; // 对应 SelectWord32 指令

// 内存访问 (底层实现)
let obj = { x: 1 };
let value = obj.x; // 底层对应 Load 指令
obj.x = 2;        // 底层对应 Store 指令
```

**代码逻辑推理和假设输入输出:**

以 `TEST_F(TurboshaftInstructionSelectorTest, ChangeFloat32ToFloat64WithParameter)` 为例：

**假设输入（Turboshaft IR）：** 一个将输入参数（类型为 `Float32`）转换为 `Float64` 的操作。

**预期输出（x64汇编指令）：**  生成 `kSSEFloat32ToFloat64` 指令（这是一个用于将单精度浮点数转换为双精度浮点数的 SSE 指令）。

**代码逻辑:**  `StreamBuilder` 用于构建表示操作的中间表示，`m.ChangeFloat32ToFloat64(m.Parameter(0))` 表示将第一个参数进行类型转换。`s.Build()` 触发指令选择过程。`ASSERT_EQ` 和 `EXPECT_EQ` 用于验证生成的指令流的大小、指令类型、输入输出数量是否符合预期。

**用户常见的编程错误示例:**

虽然这个单元测试关注的是编译器行为，但与用户编程错误也有间接联系。例如：

- **类型不匹配导致的隐式转换问题:**  在 JavaScript 中，进行不同类型之间的运算时，会发生隐式类型转换。如果用户不理解这些转换规则，可能会导致意想不到的结果。例如，字符串和数字相加的行为。编译器需要正确地为这些隐式转换生成指令。

```javascript
let num = 10;
let str = "5";
let result = num + str; // JavaScript 会将 num 转换为字符串，结果是 "105"
```

- **整数溢出/下溢:**  在进行大整数运算时，如果超出 JavaScript 的 `Number` 类型的安全范围，可能会导致精度丢失或不正确的计算。虽然 JavaScript 自身有 BigInt 类型来处理大整数，但在某些情况下仍然可能涉及到 32 位或 64 位整数运算。

**总结 - 第1部分功能归纳:**

这个 C++ 单元测试文件的第一部分主要针对 x64 架构下的 Turboshaft 指令选择器进行测试，涵盖了基本的类型转换、条件选择、带符号扩展的加载、基本的加载和存储操作，以及部分 32 位二进制运算的指令选择。此外，它还测试了在特定情况下优化 `ChangeUint32ToUint64` 和 `TruncateInt64ToInt32` 指令的能力，以及针对不同场景下的 32 位整数加法指令选择。这些测试确保了编译器能够为 JavaScript 中常见的操作生成正确的、优化的 x64 机器码。

Prompt: 
```
这是目录为v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

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
  OpIndex const p0 = m.Pa
"""


```