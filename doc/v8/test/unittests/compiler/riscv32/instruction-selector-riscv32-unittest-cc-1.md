Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Understand the Context:** The filename `instruction-selector-riscv32-unittest.cc` immediately tells us this is a unit test for the instruction selector on the RISC-V 32-bit architecture within the V8 compiler. The `.cc` extension confirms it's C++ code. The directory path points to compiler-specific tests.

2. **Identify the Core Functionality:** The code uses the `TEST_P` and `TEST_F` macros, which are strong indicators of Google Test framework usage. This means the code is defining individual test cases. The names of the test cases (e.g., `LoadWithImmediateIndex`, `StoreZero`, `Word32EqualWithZero`, `Float64Abs`) provide clues about the specific functionalities being tested.

3. **Analyze `TEST_P` (Parameterized Tests):**
   - `TEST_P(InstructionSelectorMemoryAccessImmTest, ...)` suggests testing memory access with immediate offsets. The `GetParam()` likely retrieves test parameters (different memory access types and immediate values).
   - Inside these tests, a `StreamBuilder` is used to construct sequences of machine instructions. The calls to `m.Load()`, `m.Store()`, and related methods are key.
   - `ASSERT_EQ` and `EXPECT_EQ` are assertions verifying the generated instruction sequence matches expectations (opcode, addressing mode, input/output counts, immediate values).
   - The `TRACED_FOREACH` loop iterates through different immediate offset values.
   - The code seems to be verifying that for different data types and immediate offsets, the correct RISC-V load (`lw`, `lb`, `lh`, etc.) and store (`sw`, `sb`, `sh`, etc.) instructions are generated, using the `kMode_MRI` (Memory with Register and Immediate) addressing mode.

4. **Analyze `TEST_F` (Non-Parameterized Tests):**
   - These tests focus on specific instructions or scenarios.
   - `Word32EqualWithZero`: Checks if comparing a 32-bit word with zero is optimized to a `kRiscvCmpZero` instruction.
   - `Word32Clz`, `Float32Abs`, `Float64Abs`, `Float64Max`, `Float64Min`, `Word32ReverseBytes`: These test the emission of specific RISC-V instructions (`kRiscvClz32`, `kRiscvAbsS`, `kRiscvAbsD`, `kRiscvFloat64Max`, `kRiscvFloat64Min`).
   - `ExternalReferenceLoad1`: Tests loading from memory locations based on `ExternalReference` with various offsets, verifying the use of `kMode_Root` addressing for certain offsets.

5. **Infer Functionality:** Based on the test cases, the overall functionality of `instruction-selector-riscv32-unittest.cc` is to verify that the instruction selector for the RISC-V 32-bit architecture correctly translates intermediate representation (IR) operations (like loading, storing, comparisons, bit manipulation, floating-point operations) into the corresponding RISC-V machine instructions with the appropriate addressing modes.

6. **Check for `.tq` Extension:** The prompt specifically asks about `.tq`. The provided code snippet is `.cc`, so it's C++, not Torque.

7. **Consider JavaScript Relevance:**  The compiler's job is to take JavaScript code and generate machine code. The tests here directly relate to how JavaScript operations on numbers, memory access, and comparisons are translated into RISC-V instructions. Therefore, the tests indirectly validate the correctness of the compiled JavaScript code.

8. **Provide JavaScript Examples:** To illustrate the connection to JavaScript, think about what JavaScript code would trigger the operations being tested. For example:
   - `array[i]`:  Could lead to a load instruction being tested.
   - `array[i] = value`: Could lead to a store instruction being tested.
   - `x === 0`: Could lead to the `Word32EqualWithZero` test scenario.
   - `Math.abs(y)`: Could lead to the `Float32Abs` or `Float64Abs` tests.

9. **Consider Code Logic and Assumptions:** The tests assume the existence of a `StreamBuilder` and the ability to inspect the generated instruction stream (`Stream s`). The parameterized tests rely on data structures like `MemoryAccessImm` (not shown in the snippet). The success of the tests hinges on the correctness of the instruction selector implementation itself.

10. **Identify Potential Programming Errors:**  Relate the tests to common mistakes:
    - Incorrectly calculating memory offsets.
    - Assuming aligned memory access when it's not guaranteed.
    - Not handling edge cases (like comparing with zero).
    - Performance issues if the compiler doesn't optimize certain operations (like the zero comparison).

11. **Synthesize the Summary:** Combine the findings into a concise description of the file's purpose, emphasizing its role in testing the RISC-V 32-bit instruction selector in the V8 compiler, and its connection to translating JavaScript into machine code. Specifically mention the types of operations being tested (loads, stores, comparisons, etc.).

By following these steps, we can systematically analyze the code snippet and arrive at a comprehensive understanding of its functionality and its significance within the V8 project.
好的，我们来归纳一下 `v8/test/unittests/compiler/riscv32/instruction-selector-riscv32-unittest.cc` 这个文件的功能，这是第二部分。

**整体功能归纳**

结合第一部分，`v8/test/unittests/compiler/riscv32/instruction-selector-riscv32-unittest.cc` 文件的主要功能是：**对 V8 JavaScript 引擎中 RISC-V 32 位架构的指令选择器进行单元测试。**

具体来说，它通过一系列的测试用例来验证指令选择器在将中间表示 (IR) 转换为 RISC-V 32 位机器码的过程中，对于各种不同的操作和场景，是否生成了正确的指令序列。

**第二部分的功能细化**

在第二部分中，测试用例覆盖了以下几个主要的方面：

1. **加载和存储操作（偏移量大于 16 位）：**
   - 测试了当内存访问的立即数偏移量大于 16 位时，指令选择器是否能正确生成加载和存储指令。
   - 关注了这种情况下是否仍然使用了 `kMode_MRI` 寻址模式。

2. **与零比较的指令选择 (`kRiscvCmpZero`)：**
   - 专门测试了当一个 32 位的值与零进行相等比较时，指令选择器是否能够优化并生成 `kRiscvCmpZero` 指令。
   - 验证了在两种参数顺序下（`value == 0` 和 `0 == value`）都能正确选择该指令。

3. **其他特定的 RISC-V 指令的生成：**
   - 测试了 `Word32Clz` (计算前导零个数) 操作是否生成了 `kRiscvClz32` 指令。
   - 测试了 `Float32Abs` 和 `Float64Abs` (绝对值) 操作是否分别生成了 `kRiscvAbsS` 和 `kRiscvAbsD` 指令。
   - 测试了 `Float64Max` 和 `Float64Min` 操作是否生成了 `kRiscvFloat64Max` 和 `kRiscvFloat64Min` 指令。
   - 测试了 `Word32ReverseBytes` (字节序反转) 操作是否生成了预期的指令（注释掉的代码 `// EXPECT_EQ(kRiscvByteSwap32, s[0]->arch_opcode());` 表明可能在测试或期望生成字节交换指令）。

4. **外部引用加载：**
   - 测试了从外部引用加载数据的情况。
   - 验证了对于某些特定的偏移量，指令选择器能够使用 `kMode_Root` 寻址模式进行优化。

**总结**

这部分代码延续了第一部分的功能，继续细致地测试了指令选择器在处理不同类型的操作和数据时，是否能够正确地映射到 RISC-V 32 位的指令。 它特别关注了：

* **偏移量超出指令直接寻址范围的情况**
* **特定指令的优化选择 (例如与零比较)**
* **浮点数操作指令的选择**
* **外部引用的处理**

通过这些测试，可以确保 V8 在 RISC-V 32 位架构上能够生成高效且正确的机器码。

**关于 .tq 结尾和 JavaScript 关系**

正如第一部分所述，如果 `instruction-selector-riscv32-unittest.cc` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件，Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

由于当前文件是 `.cc` 结尾，因此它是 C++ 代码编写的单元测试，直接测试指令选择器的 C++ 实现。

尽管这个文件本身不是 JavaScript 代码，但它直接关系到 JavaScript 的功能，因为它验证了将 JavaScript 代码编译到 RISC-V 32 位架构时，关键的指令选择步骤是否正确。

**JavaScript 示例 (与测试内容相关)**

以下是一些与测试用例相关的 JavaScript 代码示例：

* **加载和存储 (偏移量大于 16 位):**
  ```javascript
  function test(arr, index, value) {
    return arr[index] + value; //  可能涉及到加载
    arr[index + 65536] = value; // 索引偏移量可能导致超出 16 位
  }
  ```

* **与零比较:**
  ```javascript
  function isZero(x) {
    return x === 0;
  }
  ```

* **计算前导零个数:** (JavaScript 没有直接对应的操作，但内部实现可能用到)

* **绝对值:**
  ```javascript
  function absValue(x) {
    return Math.abs(x);
  }
  ```

* **最大值/最小值:**
  ```javascript
  function findMax(a, b) {
    return Math.max(a, b);
  }

  function findMin(a, b) {
    return Math.min(a, b);
  }
  ```

* **字节序反转:** (JavaScript 没有直接对应的操作，但在处理二进制数据时可能涉及)

* **外部引用加载:**  这在 JavaScript 中没有直接的语法对应，通常是 V8 内部处理的，比如访问全局对象或内置函数。

**假设输入与输出 (代码逻辑推理)**

由于这是单元测试代码，它的逻辑是设定特定的输入 (通过 `StreamBuilder` 构建 IR 操作)，然后断言输出 (生成的机器码指令) 是否符合预期。

例如，对于 `Word32EqualWithZero` 测试：

**假设输入 (IR):**  一个 `Word32Equal` 节点，其一个输入是参数，另一个输入是常量 0。

**预期输出 (机器码):**  一个 `kRiscvCmpZero` 指令，设置了标志位，用于后续的条件跳转或条件移动。

**用户常见的编程错误**

与这些测试相关的用户常见编程错误可能包括：

* **内存访问越界:**  虽然指令选择器本身不直接防止越界，但它生成的加载/存储指令如果使用了错误的偏移量，会导致运行时错误。
* **对浮点数进行不正确的比较:**  例如，直接使用 `==` 比较浮点数可能由于精度问题而出错。`Float64Max` 和 `Float64Min` 的测试确保了 V8 能够正确处理这些操作。
* **不理解字节序:**  在处理二进制数据时，如果假设了错误的字节序，会导致数据解析错误。 `Word32ReverseBytes` 相关的测试确保了 V8 能够进行正确的字节序转换（如果实现了）。

总而言之，这部分代码是 V8 保证其在 RISC-V 32 位平台上正确高效运行的重要组成部分，它通过详尽的测试覆盖了指令选择器的关键功能。

Prompt: 
```
这是目录为v8/test/unittests/compiler/riscv32/instruction-selector-riscv32-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/riscv32/instruction-selector-riscv32-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ndex) {
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