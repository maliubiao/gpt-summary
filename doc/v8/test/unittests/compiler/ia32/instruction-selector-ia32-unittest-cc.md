Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The primary goal is to figure out what this code *does*. It's a unittest, so it's testing some specific functionality. The filename `instruction-selector-ia32-unittest.cc` strongly suggests it's testing the IA-32 instruction selector in the V8 compiler.

2. **High-Level Structure Scan:** Quickly read through the file, paying attention to key elements:
    * **Includes:**  `instruction-selector-unittest.h` and `objects-inl.h`. This tells us it's part of the compiler's backend testing framework and likely interacts with V8's object model.
    * **Namespaces:** `v8`, `internal`, `compiler`. This confirms the context within the V8 project.
    * **Constants:** `kImmediates`. This looks like a set of test values.
    * **`TEST_F` Macros:** These are the core of the unit tests. Each `TEST_F` likely focuses on a specific instruction selection scenario. The names of the tests are very descriptive (e.g., `Int32AddWithParameter`, `Int32SubWithImmediate`).
    * **`StreamBuilder`:** This class seems central to the tests. It probably helps construct the intermediate representation of the code being tested. The arguments to its constructor (`this`, `MachineType::Int32()`, etc.) hint at the data types involved.
    * **`m.Return`, `m.Int32Add`, `m.Int32Sub`, `m.Load`, `m.Store`:** These look like methods of `StreamBuilder` for generating IR nodes.
    * **`Stream s = m.Build()`:** This likely finalizes the IR construction.
    * **`ASSERT_EQ`, `EXPECT_EQ`:** Standard testing assertions. They compare expected and actual values (like the opcode or input counts).
    * **`kIA32Lea`, `kIA32Sub`, etc.:**  These are likely IA-32 instruction opcodes (enumerated values).
    * **`TRACED_FOREACH`:**  A macro for iterating over the `kImmediates` array.
    * **`AddressingModeUnitTest`:** A separate test fixture for testing addressing modes.
    * **`InstructionSelectorMemoryAccessTest`:** A parameterized test for different memory access types.
    * **`InstructionSelectorMultTest`:** A parameterized test for multiplication.
    * **SIMD-related tests (if `V8_ENABLE_WEBASSEMBLY` is defined):**  Testing instruction selection for SIMD operations.

3. **Analyze Individual Tests (Pattern Recognition):**  Once the high-level structure is understood, examine a few individual tests in detail. Notice the common pattern:
    * Create a `StreamBuilder`.
    * Define input parameters (using `m.Parameter`).
    * Construct an operation using `m.Int32Add`, `m.Int32Sub`, etc.
    * Return the result.
    * Build the stream (`m.Build()`).
    * Assertions on the generated instruction (`s[0]->arch_opcode()`, `s[0]->InputCount()`, etc.).

4. **Infer Functionality from Test Names and Operations:**  Based on the test names and the `StreamBuilder` methods used, deduce the functionality being tested:
    * **`Int32AddWithParameter`:** Tests instruction selection for adding two parameters.
    * **`Int32AddWithImmediate`:** Tests adding a parameter with an immediate value.
    * **`Int32SubWithParameter`:** Tests subtracting two parameters.
    * **`Int32SubWithImmediate`:** Tests subtracting an immediate value from a parameter.
    * **`ChangeFloat32ToFloat64WithParameter`:** Tests float conversions.
    * **`LoadWithParameters` / `StoreWithParameters`:** Test loading and storing values from memory.
    * **`BetterLeftOperandTest...`:** Tests how the instruction selector optimizes commutative operations.
    * **`AddressingModeUnitTest`:** Tests different addressing modes for memory access.
    * **`InstructionSelectorMultTest`:** Tests how multiplication is translated into instructions (using LEA for some constant multiples).
    * **`LoadAnd32`, `LoadOr32`, etc.:** Test combining load operations with bitwise operations.
    * **`Float32Abs`, `Float64Abs`:** Test absolute value operations for floats.
    * **`Word32Clz`:** Tests the "count leading zeros" instruction.
    * **SIMD tests:** Test instruction selection for SIMD (vector) operations.

5. **Address Specific Questions:** Now, go through each part of the original request:

    * **Functionality:** Summarize the overall purpose (testing the IA-32 instruction selector). List the specific instruction selection scenarios being tested (arithmetic, conversions, memory access, etc.).

    * **Torque:** Check if the filename ends in `.tq`. It doesn't, so state that it's not a Torque file.

    * **JavaScript Relationship:**  Connect the tested functionality to how JavaScript code is compiled. Explain that these tests ensure that JavaScript operations are translated correctly into efficient IA-32 assembly. Provide a simple JavaScript example that would involve integer addition, which is covered by some of the tests.

    * **Code Logic Inference (Hypothetical Input/Output):** Choose a simple test case (like `Int32AddWithParameter`). Describe what the `StreamBuilder` is set up to do (add two parameters). Explain what the expected output is (a `kIA32Lea` instruction). Mention the input registers and the output register (even though they are symbolic in the test).

    * **Common Programming Errors:**  Think about programming mistakes that might lead to incorrect instruction selection. A classic example is integer overflow. Explain how the compiler needs to handle this and how the instruction selector plays a role. Provide a JavaScript example that could lead to overflow.

6. **Review and Refine:** Read through the entire analysis to ensure it's clear, accurate, and addresses all parts of the request. Correct any misunderstandings or omissions. For instance, initially, one might overlook the significance of `kIA32Lea` in the addition tests, but recognizing it as a "load effective address" instruction used for optimized addition with immediates is crucial. Similarly, understanding the parameterized tests with `kMemoryAccesses` helps in summarizing the memory access testing.

This systematic approach, moving from a high-level overview to detailed analysis of individual components, allows for a comprehensive understanding of the code's purpose and functionality.
### 功能列表

`v8/test/unittests/compiler/ia32/instruction-selector-ia32-unittest.cc` 文件的主要功能是 **测试 V8 JavaScript 引擎在 IA-32 架构下的指令选择器 (Instruction Selector) 组件**。

更具体地说，它通过一系列单元测试来验证：

1. **基本算术运算的指令选择:**
   - `Int32AddWithParameter`: 测试两个参数相加时，是否选择了正确的指令 (`kIA32Lea`)。
   - `Int32AddWithImmediate`: 测试参数与立即数相加时，是否选择了正确的指令 (`kIA32Lea`)。
   - `Int32SubWithParameter`: 测试两个参数相减时，是否选择了正确的指令 (`kIA32Sub`)。
   - `Int32SubWithImmediate`: 测试参数减去立即数时，是否选择了正确的指令 (`kIA32Sub`)。

2. **类型转换的指令选择:**
   - `ChangeFloat32ToFloat64WithParameter`: 测试 `float32` 转换为 `float64` 时，是否选择了正确的指令 (`kIA32Float32ToFloat64`)。
   - `TruncateFloat64ToFloat32WithParameter`: 测试 `float64` 截断为 `float32` 时，是否选择了正确的指令 (`kIA32Float64ToFloat32`)。
   - `ChangeUint32ToFloat64WithParameter`: 测试 `uint32` 转换为 `float64` 时，是否选择了正确的指令 (`kIA32Uint32ToFloat64`)。

3. **优化策略的指令选择:**
   - `BetterLeftOperandTestAddBinop`, `BetterLeftOperandTestMulBinop`: 测试在可交换的二元运算中，指令选择器是否选择了更优的左操作数，以提高效率。

4. **内存访问的指令选择 (Load 和 Store):**
   - `LoadWithParameters`, `LoadWithImmediateBase`, `LoadWithImmediateIndex`: 测试从内存加载不同类型数据时，是否选择了正确的指令 (例如 `kIA32Movsxbl`, `kIA32Movl`, `kIA32Movss`, `kIA32Movsd`) 以及是否正确处理立即数偏移。
   - `StoreWithParameters`, `StoreWithImmediateBase`, `StoreWithImmediateIndex`: 测试向内存存储不同类型数据时，是否选择了正确的指令 (例如 `kIA32Movb`, `kIA32Movw`, `kIA32Movl`, `kIA32Movss`, `kIA32Movsd`) 以及是否正确处理立即数偏移。

5. **寻址模式 (Addressing Mode) 的测试:**
   - `AddressingModeUnitTest`: 测试指令选择器在生成加载和存储指令时，是否选择了正确的 IA-32 寻址模式 (例如 `kMode_MR`, `kMode_MRI`, `kMode_MR1`, `kMode_MI` 等)。

6. **乘法运算的指令选择:**
   - `InstructionSelectorMultTest`: 测试 `Int32Mul` 操作在不同立即数乘数下，是否选择了 `kIA32Imul` (乘法指令) 或 `kIA32Lea` (加载有效地址指令，用于优化某些常数乘法)。
   - `Int32MulHigh`: 测试有符号 32 位乘法高位结果的指令选择 (`kIA32ImulHigh`)。

7. **与其他运算结合的指令选择:**
   - `LoadAnd32`, `LoadImmutableAnd32`, `LoadOr32`, `LoadXor32`, `LoadAdd32`, `LoadSub32`: 测试加载操作与位运算、加法、减法结合时，指令选择器是否生成了正确的指令序列。

8. **浮点运算的指令选择:**
   - `Float32Abs`, `Float64Abs`: 测试浮点数绝对值运算的指令选择 (`kFloat32Abs`, `kFloat64Abs`)。
   - `Float64BinopArithmetic`: 测试浮点数基本算术运算 (`Add`, `Mul`, `Sub`, `Div`) 的指令选择 (`kFloat64Add`, `kFloat64Mul`, `kFloat64Sub`, `kFloat64Div`)。

9. **其他杂项指令的测试:**
   - `Word32Clz`: 测试计算前导零个数的指令选择 (`kIA32Lzcnt`)。
   - `Int32AddMinNegativeDisplacement`:  测试一种特定的 `Int32Add` 场景，涉及到负的位移量，确保不会发生溢出。

10. **WebAssembly SIMD 指令的测试 (如果 `V8_ENABLE_WEBASSEMBLY` 宏定义):**
    - `SIMDSplatZero`: 测试将 SIMD 向量所有元素设置为零的指令选择 (`kIA32S128Zero`)。
    - `InstructionSelectorSIMDSwizzleConstantTest`: 测试使用常量索引进行 SIMD 向量元素混洗的指令选择 (`kIA32I8x16Swizzle`)。

**关于文件后缀 `.tq`：**

`v8/test/unittests/compiler/ia32/instruction-selector-ia32-unittest.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。 如果它以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种用于定义 V8 内部实现的领域特定语言。

**与 JavaScript 功能的关系及举例：**

这个测试文件直接关系到 V8 引擎将 JavaScript 代码编译成高效的 IA-32 机器码的过程。  指令选择器负责将中间表示 (IR) 的操作符转换为具体的 IA-32 指令。

例如，`Int32AddWithParameter` 测试了 JavaScript 中的整数加法操作：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译 `add` 函数时，`a + b` 这个操作会生成一个 IR 节点，指令选择器会针对 IA-32 架构选择合适的指令来实现这个加法。 从测试代码来看，期望选择的指令是 `kIA32Lea`。 `LEA` (Load Effective Address) 指令在 IA-32 中可以用于执行加法操作，尤其是在涉及地址计算时。

再比如，`Int32AddWithImmediate` 测试了 JavaScript 中变量与常量的加法：

```javascript
function addConstant(a) {
  return a + 5;
}
```

这里的 `a + 5` 也会经过指令选择，测试确保对于 IA-32 架构，选择了合适的 `kIA32Lea` 指令，并且正确地将常量 `5` 作为立即数处理。

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(InstructionSelectorTest, Int32AddWithParameter)` 为例：

**假设输入:**

- 两个 `MachineType::Int32()` 类型的参数传递给被测试的代码。

**输出:**

- 生成一个 `Stream` 对象，其中包含一个指令。
- 该指令的 `arch_opcode()` 应该等于 `kIA32Lea`。

**更详细的推理:**

1. `StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(), MachineType::Int32());` 创建一个 `StreamBuilder`，模拟一个接收两个 `Int32` 参数并返回 `Int32` 结果的函数。
2. `m.Return(m.Int32Add(m.Parameter(0), m.Parameter(1)));`  构建 IR，表示返回第一个参数和第二个参数的 `Int32` 加法结果。
3. `Stream s = m.Build();` 触发指令选择过程。
4. `ASSERT_EQ(1U, s.size());` 断言生成了一个指令。
5. `EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());` 断言该指令的架构操作码是 `kIA32Lea`。

**涉及用户常见的编程错误及举例：**

虽然这个测试文件主要关注编译器内部的指令选择，但它所测试的功能与用户常见的编程错误间接相关。 例如：

1. **整数溢出:**
   ```javascript
   let maxInt = 2147483647;
   let result = maxInt + 1; // 期望得到 -2147483648 (溢出)
   ```
   测试文件中的 `Int32AddWithParameter` 和 `Int32AddWithImmediate` 等测试确保了编译器对于整数加法的正确指令选择。 虽然这些测试不直接测试溢出处理，但正确的指令选择是实现正确的溢出行为的前提。 错误的指令选择可能导致不可预测的结果。

2. **类型错误导致的隐式转换:**
   ```javascript
   let a = 10;
   let b = "20";
   let result = a + b; // 字符串拼接，结果是 "1020"
   ```
   虽然此示例与字符串拼接有关，但类似的，如果由于类型错误导致了意外的数值类型，指令选择器会根据实际的 IR 节点类型进行指令选择。 如果指令选择器有 bug，可能会为错误的类型选择不合适的指令，导致程序行为异常。 测试文件中的类型转换测试 (如 `ChangeFloat32ToFloat64WithParameter`) 确保了在类型转换场景下的正确指令选择。

3. **不恰当的位运算:**
   ```javascript
   let flags = 0b0001;
   let mask = 0b0010;
   if (flags & mask) { // 结果为 0，条件不成立
     console.log("Flag is set");
   }
   ```
   测试文件中的 `LoadAnd32`, `LoadOr32`, `LoadXor32` 等测试确保了在涉及位运算时，编译器选择了正确的 IA-32 位运算指令 (`kIA32And`, `kIA32Or`, `kIA32Xor`)。 如果指令选择错误，会导致位运算的结果不符合预期，从而引发程序逻辑错误。

总的来说，这个单元测试文件通过详尽地测试指令选择器的各种场景，确保 V8 编译器能够为 IA-32 架构生成正确且高效的机器码，从而保证 JavaScript 代码的正确执行。 尽管它不直接检测用户的编程错误，但它验证了编译器正确处理这些错误产生的影响 (例如，溢出后的数值表示) 所需的基础功能。

### 提示词
```
这是目录为v8/test/unittests/compiler/ia32/instruction-selector-ia32-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/ia32/instruction-selector-ia32-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/unittests/compiler/backend/instruction-selector-unittest.h"

#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {

// Immediates (random subset).
const int32_t kImmediates[] = {kMinInt, -42, -1,   0,      1,          2,
                               3,       4,   5,    6,      7,          8,
                               16,      42,  0xFF, 0xFFFF, 0x0F0F0F0F, kMaxInt};

}  // namespace


TEST_F(InstructionSelectorTest, Int32AddWithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Add(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());
}


TEST_F(InstructionSelectorTest, Int32AddWithImmediate) {
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Int32Add(m.Parameter(0), m.Int32Constant(imm)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());
      if (imm == 0) {
        ASSERT_EQ(1U, s[0]->InputCount());
      } else {
        ASSERT_EQ(2U, s[0]->InputCount());
        EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
      }
    }
    {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Int32Add(m.Int32Constant(imm), m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());
      if (imm == 0) {
        ASSERT_EQ(1U, s[0]->InputCount());
      } else {
        ASSERT_EQ(2U, s[0]->InputCount());
        EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
      }
    }
  }
}


TEST_F(InstructionSelectorTest, Int32SubWithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Sub(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32Sub, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, Int32SubWithImmediate) {
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Sub(m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kIA32Sub, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
  }
}


// -----------------------------------------------------------------------------
// Conversions.


TEST_F(InstructionSelectorTest, ChangeFloat32ToFloat64WithParameter) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float64());
  m.Return(m.ChangeFloat32ToFloat64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32Float32ToFloat64, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, TruncateFloat64ToFloat32WithParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float32());
  m.Return(m.TruncateFloat64ToFloat32(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32Float64ToFloat32, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


// -----------------------------------------------------------------------------
// Better left operand for commutative binops


TEST_F(InstructionSelectorTest, BetterLeftOperandTestAddBinop) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* param1 = m.Parameter(0);
  Node* param2 = m.Parameter(1);
  Node* add = m.Int32Add(param1, param2);
  m.Return(m.Int32Add(add, param1));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_TRUE(s[0]->InputAt(0)->IsUnallocated());
  EXPECT_EQ(s.ToVreg(param1), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(param2), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(param1), s.ToVreg(s[0]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, BetterLeftOperandTestMulBinop) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* param1 = m.Parameter(0);
  Node* param2 = m.Parameter(1);
  Node* mul = m.Int32Mul(param1, param2);
  m.Return(m.Int32Mul(mul, param1));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kIA32Imul, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_TRUE(s[0]->InputAt(0)->IsUnallocated());
  EXPECT_EQ(s.ToVreg(param2), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(param1), s.ToVreg(s[0]->InputAt(1)));
}


// -----------------------------------------------------------------------------
// Conversions.


TEST_F(InstructionSelectorTest, ChangeUint32ToFloat64WithParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Uint32());
  m.Return(m.ChangeUint32ToFloat64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32Uint32ToFloat64, s[0]->arch_opcode());
}


// -----------------------------------------------------------------------------
// Loads and stores

struct MemoryAccess {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
};


std::ostream& operator<<(std::ostream& os, const MemoryAccess& memacc) {
  return os << memacc.type;
}


static const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(), kIA32Movsxbl, kIA32Movb},
    {MachineType::Uint8(), kIA32Movzxbl, kIA32Movb},
    {MachineType::Int16(), kIA32Movsxwl, kIA32Movw},
    {MachineType::Uint16(), kIA32Movzxwl, kIA32Movw},
    {MachineType::Int32(), kIA32Movl, kIA32Movl},
    {MachineType::Uint32(), kIA32Movl, kIA32Movl},
    {MachineType::Float32(), kIA32Movss, kIA32Movss},
    {MachineType::Float64(), kIA32Movsd, kIA32Movsd}};

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


TEST_P(InstructionSelectorMemoryAccessTest, LoadWithImmediateBase) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, base, kImmediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Int32Constant(base), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    if (base == 0) {
      ASSERT_EQ(1U, s[0]->InputCount());
    } else {
      ASSERT_EQ(2U, s[0]->InputCount());
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(base, s.ToInt32(s[0]->InputAt(1)));
    }
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_P(InstructionSelectorMemoryAccessTest, LoadWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, kImmediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    if (index == 0) {
      ASSERT_EQ(1U, s[0]->InputCount());
    } else {
      ASSERT_EQ(2U, s[0]->InputCount());
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    }
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
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


TEST_P(InstructionSelectorMemoryAccessTest, StoreWithImmediateBase) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, base, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Int32Constant(base), m.Parameter(0),
            m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    if (base == 0) {
      ASSERT_EQ(2U, s[0]->InputCount());
    } else {
      ASSERT_EQ(3U, s[0]->InputCount());
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(base, s.ToInt32(s[0]->InputAt(1)));
    }
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}


TEST_P(InstructionSelectorMemoryAccessTest, StoreWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    if (index == 0) {
      ASSERT_EQ(2U, s[0]->InputCount());
    } else {
      ASSERT_EQ(3U, s[0]->InputCount());
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    }
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// -----------------------------------------------------------------------------
// AddressingMode for loads and stores.


class AddressingModeUnitTest : public InstructionSelectorTest {
 public:
  AddressingModeUnitTest() : m(nullptr) { Reset(); }
  ~AddressingModeUnitTest() override { delete m; }

  void Run(Node* base, Node* load_index, Node* store_index,
           AddressingMode mode) {
    Node* load = m->Load(MachineType::Int32(), base, load_index);
    m->Store(MachineRepresentation::kWord32, base, store_index, load,
             kNoWriteBarrier);
    m->Return(m->Int32Constant(0));
    Stream s = m->Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(mode, s[0]->addressing_mode());
    EXPECT_EQ(mode, s[1]->addressing_mode());
  }

  Node* zero;
  Node* null_ptr;
  Node* non_zero;
  Node* base_reg;   // opaque value to generate base as register
  Node* index_reg;  // opaque value to generate index as register
  Node* scales[4];
  StreamBuilder* m;

  void Reset() {
    delete m;
    m = new StreamBuilder(this, MachineType::Int32(), MachineType::Int32(),
                          MachineType::Int32());
    zero = m->Int32Constant(0);
    null_ptr = m->Int32Constant(0);
    non_zero = m->Int32Constant(127);
    base_reg = m->Parameter(0);
    index_reg = m->Parameter(0);

    scales[0] = m->Int32Constant(1);
    scales[1] = m->Int32Constant(2);
    scales[2] = m->Int32Constant(4);
    scales[3] = m->Int32Constant(8);
  }
};


TEST_F(AddressingModeUnitTest, AddressingMode_MR) {
  Node* base = base_reg;
  Node* index = zero;
  Run(base, index, index, kMode_MR);
}


TEST_F(AddressingModeUnitTest, AddressingMode_MRI) {
  Node* base = base_reg;
  Node* index = non_zero;
  Run(base, index, index, kMode_MRI);
}


TEST_F(AddressingModeUnitTest, AddressingMode_MR1) {
  Node* base = base_reg;
  Node* index = index_reg;
  Run(base, index, index, kMode_MR1);
}


TEST_F(AddressingModeUnitTest, AddressingMode_MRN) {
  AddressingMode expected[] = {kMode_MR1, kMode_MR2, kMode_MR4, kMode_MR8};
  for (size_t i = 0; i < arraysize(scales); ++i) {
    Reset();
    Node* base = base_reg;
    Node* load_index = m->Int32Mul(index_reg, scales[i]);
    Node* store_index = m->Int32Mul(index_reg, scales[i]);
    Run(base, load_index, store_index, expected[i]);
  }
}


TEST_F(AddressingModeUnitTest, AddressingMode_MR1I) {
  Node* base = base_reg;
  Node* load_index = m->Int32Add(index_reg, non_zero);
  Node* store_index = m->Int32Add(index_reg, non_zero);
  Run(base, load_index, store_index, kMode_MR1I);
}


TEST_F(AddressingModeUnitTest, AddressingMode_MRNI) {
  AddressingMode expected[] = {kMode_MR1I, kMode_MR2I, kMode_MR4I, kMode_MR8I};
  for (size_t i = 0; i < arraysize(scales); ++i) {
    Reset();
    Node* base = base_reg;
    Node* load_index = m->Int32Add(m->Int32Mul(index_reg, scales[i]), non_zero);
    Node* store_index =
        m->Int32Add(m->Int32Mul(index_reg, scales[i]), non_zero);
    Run(base, load_index, store_index, expected[i]);
  }
}


TEST_F(AddressingModeUnitTest, AddressingMode_M1ToMR) {
  Node* base = null_ptr;
  Node* index = index_reg;
  // M1 maps to MR
  Run(base, index, index, kMode_MR);
}


TEST_F(AddressingModeUnitTest, AddressingMode_MN) {
  AddressingMode expected[] = {kMode_MR, kMode_M2, kMode_M4, kMode_M8};
  for (size_t i = 0; i < arraysize(scales); ++i) {
    Reset();
    Node* base = null_ptr;
    Node* load_index = m->Int32Mul(index_reg, scales[i]);
    Node* store_index = m->Int32Mul(index_reg, scales[i]);
    Run(base, load_index, store_index, expected[i]);
  }
}


TEST_F(AddressingModeUnitTest, AddressingMode_M1IToMRI) {
  Node* base = null_ptr;
  Node* load_index = m->Int32Add(index_reg, non_zero);
  Node* store_index = m->Int32Add(index_reg, non_zero);
  // M1I maps to MRI
  Run(base, load_index, store_index, kMode_MRI);
}


TEST_F(AddressingModeUnitTest, AddressingMode_MNI) {
  AddressingMode expected[] = {kMode_MRI, kMode_M2I, kMode_M4I, kMode_M8I};
  for (size_t i = 0; i < arraysize(scales); ++i) {
    Reset();
    Node* base = null_ptr;
    Node* load_index = m->Int32Add(m->Int32Mul(index_reg, scales[i]), non_zero);
    Node* store_index =
        m->Int32Add(m->Int32Mul(index_reg, scales[i]), non_zero);
    Run(base, load_index, store_index, expected[i]);
  }
}


TEST_F(AddressingModeUnitTest, AddressingMode_MI) {
  Node* bases[] = {null_ptr, non_zero};
  Node* indices[] = {zero, non_zero};
  for (size_t i = 0; i < arraysize(bases); ++i) {
    for (size_t j = 0; j < arraysize(indices); ++j) {
      Reset();
      Node* base = bases[i];
      Node* index = indices[j];
      Run(base, index, index, kMode_MI);
    }
  }
}


// -----------------------------------------------------------------------------
// Multiplication.

struct MultParam {
  int value;
  bool lea_expected;
  AddressingMode addressing_mode;
};


std::ostream& operator<<(std::ostream& os, const MultParam& m) {
  return os << m.value << "." << m.lea_expected << "." << m.addressing_mode;
}


const MultParam kMultParams[] = {{-1, false, kMode_None},
                                 {0, false, kMode_None},
                                 {1, true, kMode_MR},
                                 {2, true, kMode_M2},
                                 {3, true, kMode_MR2},
                                 {4, true, kMode_M4},
                                 {5, true, kMode_MR4},
                                 {6, false, kMode_None},
                                 {7, false, kMode_None},
                                 {8, true, kMode_M8},
                                 {9, true, kMode_MR8},
                                 {10, false, kMode_None},
                                 {11, false, kMode_None}};

using InstructionSelectorMultTest = InstructionSelectorTestWithParam<MultParam>;

static unsigned InputCountForLea(AddressingMode mode) {
  switch (mode) {
    case kMode_MR1I:
    case kMode_MR2I:
    case kMode_MR4I:
    case kMode_MR8I:
      return 3U;
    case kMode_M1I:
    case kMode_M2I:
    case kMode_M4I:
    case kMode_M8I:
      return 2U;
    case kMode_MR1:
    case kMode_MR2:
    case kMode_MR4:
    case kMode_MR8:
    case kMode_MRI:
      return 2U;
    case kMode_M1:
    case kMode_M2:
    case kMode_M4:
    case kMode_M8:
    case kMode_MI:
    case kMode_MR:
      return 1U;
    default:
      UNREACHABLE();
  }
}


static AddressingMode AddressingModeForAddMult(int32_t imm,
                                               const MultParam& m) {
  if (imm == 0) return m.addressing_mode;
  switch (m.addressing_mode) {
    case kMode_MR1:
      return kMode_MR1I;
    case kMode_MR2:
      return kMode_MR2I;
    case kMode_MR4:
      return kMode_MR4I;
    case kMode_MR8:
      return kMode_MR8I;
    case kMode_M1:
      return kMode_M1I;
    case kMode_M2:
      return kMode_M2I;
    case kMode_M4:
      return kMode_M4I;
    case kMode_M8:
      return kMode_M8I;
    case kMode_MR:
      return kMode_MRI;
    default:
      UNREACHABLE();
  }
}


TEST_P(InstructionSelectorMultTest, Mult32) {
  const MultParam m_param = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* param = m.Parameter(0);
  Node* mult = m.Int32Mul(param, m.Int32Constant(m_param.value));
  m.Return(mult);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(m_param.addressing_mode, s[0]->addressing_mode());
  if (m_param.lea_expected) {
    EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());
    ASSERT_EQ(InputCountForLea(s[0]->addressing_mode()), s[0]->InputCount());
  } else {
    EXPECT_EQ(kIA32Imul, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
  }
  EXPECT_EQ(s.ToVreg(param), s.ToVreg(s[0]->InputAt(0)));
}


TEST_P(InstructionSelectorMultTest, MultAdd32) {
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    const MultParam m_param = GetParam();
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* param = m.Parameter(0);
    Node* mult = m.Int32Add(m.Int32Mul(param, m.Int32Constant(m_param.value)),
                            m.Int32Constant(imm));
    m.Return(mult);
    Stream s = m.Build();
    if (m_param.lea_expected) {
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());
      EXPECT_EQ(AddressingModeForAddMult(imm, m_param),
                s[0]->addressing_mode());
      unsigned input_count = InputCountForLea(s[0]->addressing_mode());
      ASSERT_EQ(input_count, s[0]->InputCount());
      if (imm != 0) {
        ASSERT_EQ(InstructionOperand::IMMEDIATE,
                  s[0]->InputAt(input_count - 1)->kind());
        EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(input_count - 1)));
      }
    } else {
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kIA32Imul, s[0]->arch_opcode());
      EXPECT_EQ(kIA32Lea, s[1]->arch_opcode());
    }
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorMultTest,
                         ::testing::ValuesIn(kMultParams));

TEST_F(InstructionSelectorTest, Int32MulHigh) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Int32MulHigh(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32ImulHigh, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s.IsFixed(s[0]->InputAt(0), eax));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(!s.IsUsedAtStart(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_TRUE(s.IsFixed(s[0]->OutputAt(0), edx));
}


// -----------------------------------------------------------------------------
// Binops with a memory operand.

TEST_F(InstructionSelectorTest, LoadAnd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word32And(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32And, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadImmutableAnd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(m.Word32And(
      p0, m.LoadImmutable(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32And, s[0]->arch_opcode());
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
  EXPECT_EQ(kIA32Or, s[0]->arch_opcode());
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
  EXPECT_EQ(kIA32Xor, s[0]->arch_opcode());
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
  EXPECT_EQ(kIA32Movl, s[0]->arch_opcode());
  EXPECT_EQ(kIA32Lea, s[1]->arch_opcode());
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
  EXPECT_EQ(kIA32Sub, s[0]->arch_opcode());
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
    EXPECT_EQ(kFloat32Abs, s[0]->arch_opcode());
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
    EXPECT_EQ(kFloat32Abs, s[0]->arch_opcode());
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
    EXPECT_EQ(kFloat64Abs, s[0]->arch_opcode());
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
    EXPECT_EQ(kFloat64Abs, s[0]->arch_opcode());
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
    EXPECT_EQ(kFloat64Add, s[0]->arch_opcode());
    EXPECT_EQ(kFloat64Mul, s[1]->arch_opcode());
    EXPECT_EQ(kFloat64Sub, s[2]->arch_opcode());
    EXPECT_EQ(kFloat64Div, s[3]->arch_opcode());
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
    EXPECT_EQ(kFloat64Add, s[0]->arch_opcode());
    EXPECT_EQ(kFloat64Mul, s[1]->arch_opcode());
    EXPECT_EQ(kFloat64Sub, s[2]->arch_opcode());
    EXPECT_EQ(kFloat64Div, s[3]->arch_opcode());
  }
}

// -----------------------------------------------------------------------------
// Miscellaneous.

TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32Lzcnt, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
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
  ASSERT_EQ(1U, s.size());

  EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  EXPECT_EQ(2147457600,
            ImmediateOperand::cast(s[0]->InputAt(1))->inline_int32_value());
}

#if V8_ENABLE_WEBASSEMBLY
// SIMD.

TEST_F(InstructionSelectorTest, SIMDSplatZero) {
  // Test optimization for splat of contant 0.
  // {i8x16,i16x8,i32x4,i64x2}.splat(const(0)) -> v128.zero().
  // Optimizations for f32x4.splat and f64x2.splat not implemented since it
  // doesn't improve the codegen as much (same number of instructions).
  {
    StreamBuilder m(this, MachineType::Simd128());
    Node* const splat =
        m.I64x2SplatI32Pair(m.Int32Constant(0), m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kIA32S128Zero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    Node* const splat = m.I32x4Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kIA32S128Zero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    Node* const splat = m.I16x8Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kIA32S128Zero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    Node* const splat = m.I8x16Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kIA32S128Zero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

struct SwizzleConstants {
  uint8_t shuffle[kSimd128Size];
  bool omit_add;
};

static constexpr SwizzleConstants kSwizzleConstants[] = {
    {
        // all lanes < kSimd128Size
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
        true,
    },
    {
        // lanes that are >= kSimd128Size have top bit set
        {12, 13, 14, 15, 0x90, 0x91, 0x92, 0x93, 0xA0, 0xA1, 0xA2, 0xA3, 0xFC,
         0xFD, 0xFE, 0xFF},
        true,
    },
    {
        {12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27},
        false,
    },
};

using InstructionSelectorSIMDSwizzleConstantTest =
    InstructionSelectorTestWithParam<SwizzleConstants>;

TEST_P(InstructionSelectorSIMDSwizzleConstantTest, SimdSwizzleConstant) {
  // Test optimization of swizzle with constant indices.
  auto param = GetParam();
  StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
  Node* const c = m.S128Const(param.shuffle);
  Node* swizzle = m.AddNode(m.machine()->I8x16Swizzle(), m.Parameter(0), c);
  m.Return(swizzle);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  ASSERT_EQ(kIA32I8x16Swizzle, s[1]->arch_opcode());
  ASSERT_EQ(param.omit_add, s[1]->misc());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDSwizzleConstantTest,
                         ::testing::ValuesIn(kSwizzleConstants));
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```