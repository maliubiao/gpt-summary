Response: Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Purpose of Unit Tests:**  The core idea is that unit tests verify small, isolated units of code. In this context, "instruction-selector-ia32-unittest.cc" strongly suggests this tests the *instruction selection* phase of a compiler, specifically targeting the IA-32 (x86) architecture. Instruction selection is about mapping high-level operations (like addition, subtraction, memory access) to specific machine instructions.

2. **Identify the Testing Framework:**  The presence of `#include "test/unittests/compiler/backend/instruction-selector-unittest.h"` and `TEST_F(InstructionSelectorTest, ...)` immediately points to a testing framework, likely Google Test (though the exact framework isn't critical for summarizing functionality). The `TEST_F` macro indicates that these tests are methods within a class derived from `InstructionSelectorTest`.

3. **Examine the Test Structure:** The code is organized into individual test cases, each named descriptively (e.g., `Int32AddWithParameter`, `Int32SubWithImmediate`). This structure is crucial. Each test focuses on a specific scenario.

4. **Analyze Individual Test Cases:**  For each test case, do the following:
    * **Identify the Operation Being Tested:** The test name usually gives a strong hint (e.g., "Int32Add", "Int32Sub", "Load", "Store").
    * **Look for the `StreamBuilder`:** This class is used to construct a sequence of operations. The arguments to the `StreamBuilder` constructor tell you the input and output types of the function being simulated.
    * **Examine the Operations Within the Test:** Pay close attention to calls like `m.Int32Add()`, `m.Int32Sub()`, `m.Load()`, `m.Store()`, `m.Return()`. These represent the high-level operations being tested.
    * **Check the Assertions (`ASSERT_EQ`, `EXPECT_EQ`):**  These are the heart of the test. They verify expectations about the generated machine code.
        * `s.size()`:  Checks the number of generated instructions.
        * `s[0]->arch_opcode()`: Checks the specific IA-32 instruction opcode (e.g., `kIA32Lea`, `kIA32Sub`, `kIA32Movl`).
        * `s[0]->InputCount()`, `s[0]->OutputCount()`: Checks the number of inputs and outputs of the instruction.
        * `s.ToInt32(s[0]->InputAt(1))`: Checks the value of an immediate operand.
        * `s[0]->addressing_mode()`: Checks the addressing mode used for memory access.
    * **Pay attention to Loops (`TRACED_FOREACH`):**  These often indicate testing with a variety of inputs, like the `kImmediates` array.

5. **Identify Key Concepts and Patterns:** As you analyze multiple test cases, look for recurring themes:
    * **Handling of Parameters and Constants:** How are function arguments and constant values represented in the generated instructions?
    * **Use of `LEA` (Load Effective Address):** Notice its frequent use for addition, especially with immediates. This is an optimization on x86.
    * **Different Instruction Opcodes:**  See how different high-level operations map to distinct IA-32 instructions.
    * **Memory Access (Loads and Stores):**  Note the different opcodes for loading and storing different data types (`Movb`, `Movw`, `Movl`, `Movss`, `Movsd`). Observe how base and index registers/immediates are handled.
    * **Addressing Modes:** Understand the different addressing modes being tested and how they are constructed.
    * **Floating-Point Operations:** Identify the opcodes for floating-point arithmetic (`Float64Add`, `Float64Sub`, etc.).
    * **SIMD Instructions (if present):**  Note tests for SIMD splat and swizzle operations.

6. **Infer the Relationship to JavaScript (if any):**  The file is part of the V8 project, which is the JavaScript engine for Chrome and Node.js. The compiler's job is to translate JavaScript code into machine code. Therefore, these unit tests are verifying that the instruction selector correctly translates JavaScript operations (like addition, subtraction, etc.) into efficient IA-32 instructions. This involves understanding how JavaScript's data types (numbers, floats) are handled at the machine level.

7. **Formulate the Summary:** Based on the analysis, summarize the key functionalities being tested. Focus on:
    * The core purpose (testing instruction selection for IA-32).
    * The types of operations covered (arithmetic, memory access, conversions, floating-point, SIMD).
    * How parameters, constants, and immediates are handled.
    * Any observed optimizations (like using `LEA` for addition).

8. **Create JavaScript Examples (if relevant):** If a test relates to a common JavaScript operation, provide a simple JavaScript snippet to illustrate. For example, integer addition in JavaScript corresponds to the `Int32Add` tests. Memory access in JavaScript corresponds to object property access or array access.

**Self-Correction/Refinement during the Process:**

* **Initial Misinterpretations:**  You might initially misunderstand the purpose of `LEA`. Further reading or looking at more tests would reveal its role in optimizing arithmetic operations.
* **Missing Details:** If a test uses unfamiliar terminology (like "write barrier" or specific SIMD instructions), you might need to do some quick research to understand the context.
* **Overgeneralization:** Be careful not to overstate the scope of the tests. This file focuses specifically on IA-32 instruction selection, not the entire compilation process.

By following this systematic approach, you can effectively analyze and summarize the functionality of complex C++ unit test files, even without being an expert in the specific codebase.
这个C++源代码文件 `instruction-selector-ia32-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 **IA-32 (x86) 架构的指令选择器 (Instruction Selector)** 组件的功能。

**功能归纳:**

该文件的主要功能是：

1. **测试将中间表示 (Intermediate Representation - IR) 的操作转换为 IA-32 汇编指令的过程。**  编译器在将高级语言（如 JavaScript）编译成机器码的过程中，会先生成一种中间表示，然后指令选择器负责将这些 IR 操作映射到目标架构（这里是 IA-32）的实际机器指令。

2. **针对不同的 IR 操作，验证指令选择器是否生成了正确的 IA-32 指令。**  文件中包含了大量的 `TEST_F` 宏定义的测试用例，每个测试用例都针对一个或一组特定的 IR 操作进行测试，例如：
    * **算术运算:** 加法 (`Int32Add`)，减法 (`Int32Sub`)，乘法 (`Int32Mul`)，带进位的乘法 (`Int32MulHigh`)
    * **类型转换:**  浮点数类型转换 (`ChangeFloat32ToFloat64`, `TruncateFloat64ToFloat32`)，无符号整数转浮点数 (`ChangeUint32ToFloat64`)
    * **内存访问:** 加载 (`Load`)，存储 (`Store`) 不同大小和类型的内存数据。
    * **按位运算:**  与 (`Word32And`)，或 (`Word32Or`)，异或 (`Word32Xor`)，计算前导零 (`Word32Clz`)
    * **浮点运算:** 绝对值 (`Float32Abs`, `Float64Abs`)，加减乘除。
    * **寻址模式:** 测试不同的内存寻址方式 (`AddressingMode`)，例如基址寄存器，基址加偏移，基址加索引等。
    * **乘法优化:**  测试将乘以小的常数转换为 `LEA` 指令的优化。
    * **SIMD 指令 (如果启用了 WebAssembly):** 测试 SIMD 向量操作的指令选择，例如向量置零 (`SIMDSplatZero`) 和向量混洗 (`SimdSwizzleConstant`)。

3. **验证生成的指令的操作码 (`arch_opcode`)、输入/输出数量、以及操作数的类型和值是否符合预期。** 每个测试用例都会构建一个简单的 IR 操作序列，然后调用指令选择器进行处理，最后通过断言 (`ASSERT_EQ`, `EXPECT_EQ`) 来检查生成的指令的各种属性。

**与 JavaScript 的关系 (举例说明):**

指令选择器是 V8 引擎编译 JavaScript 代码的关键环节。当 V8 编译一段 JavaScript 代码时，例如：

```javascript
function add(a, b) {
  return a + b;
}
```

V8 的编译器会将这个加法操作 `a + b` 转换成一个 IR 节点。 `instruction-selector-ia32-unittest.cc` 中的 `Int32AddWithParameter` 测试用例就模拟了这个过程：

```c++
TEST_F(InstructionSelectorTest, Int32AddWithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Add(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kIA32Lea, s[0]->arch_opcode());
}
```

这个测试用例创建了一个 IR 加法操作，其两个操作数是函数的参数 (`m.Parameter(0)`, `m.Parameter(1)`)。然后断言指令选择器会为此生成一个 `kIA32Lea` 指令。  在 IA-32 架构上，`LEA` (Load Effective Address) 指令经常被用来高效地执行加法操作，特别是当其中一个操作数是内存地址时，或者用于计算地址。

**JavaScript 示例说明不同测试用例的关联:**

* **`Int32SubWithImmediate`:**

  ```javascript
  function subtract(a) {
    return a - 5;
  }
  ```
  指令选择器会将 `a - 5` 映射到 IA-32 的 `SUB` 指令。

* **`LoadWithParameters`:**

  ```javascript
  function getProperty(obj) {
    return obj.value;
  }
  ```
  访问对象的属性 `obj.value` 会涉及到内存加载操作，指令选择器会生成相应的 `MOV` 指令（例如 `kIA32Movl`）。

* **`ChangeFloat32ToFloat64WithParameter`:**

  ```javascript
  function convertFloat(f) {
    return +f; // 将单精度浮点数转换为双精度
  }
  ```
  JavaScript 中将单精度浮点数转换为双精度浮点数的操作，指令选择器会生成 `kIA32Float32ToFloat64` 指令。

* **`Int32MulWithConstant` (通过 `AddressingModeUnitTest` 和 `InstructionSelectorMultTest` 间接测试):**

  ```javascript
  function multiplyBy3(x) {
    return x * 3;
  }
  ```
  对于乘以小的常数（如 3），指令选择器可能会优化成使用 `LEA` 指令，例如 `lea eax, [ecx + ecx*2]`。

**总结:**

`instruction-selector-ia32-unittest.cc` 文件是 V8 引擎中一个至关重要的测试文件，它通过大量的单元测试确保了指令选择器能够正确地将 JavaScript 代码的中间表示转换为高效的 IA-32 机器码，这是保证 JavaScript 代码执行效率的关键因素之一。 这些测试覆盖了各种常见的 JavaScript 操作，并通过断言验证了生成的 IA-32 指令的正确性。

Prompt: 
```
这是目录为v8/test/unittests/compiler/ia32/instruction-selector-ia32-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```