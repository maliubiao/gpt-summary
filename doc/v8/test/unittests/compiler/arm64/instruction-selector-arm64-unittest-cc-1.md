Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc`.

Here's a breakdown of the thought process to achieve the desired output:

1. **Identify the core purpose:** The filename suggests this code tests the instruction selector for the ARM64 architecture within the V8 compiler. The tests use a `StreamBuilder` to create sequences of machine instructions and verify their properties.

2. **Analyze individual TEST_F blocks:** Each `TEST_F` block represents a distinct test case. Examine the operations performed within each block:
    * **`AddImmRight32` and `AddImmRight64`:** These tests check if the instruction selector correctly generates `kArm64Add32` and `kArm64Add` instructions when adding an immediate value to a register. The addressing mode `kMode_Operand2_I` indicates the immediate operand. The tests verify the immediate value is correctly encoded.
    * **`AddUnsignedExtendByteOnLeft` and similar extension tests:** These tests focus on scenarios where one operand of an addition is being extended (unsigned or signed byte/halfword). The `Word32And`, `Word32Sar`, and `Word32Shl` operations are used to simulate these extensions. The tests verify the correct `kArm64Add32`/`kArm64Add` instruction and the appropriate addressing mode (`kMode_Operand2_R_UXTB`, `kMode_Operand2_R_UXTH`, `kMode_Operand2_R_SXTB`, `kMode_Operand2_R_SXTH`).
    * **`AddWithPairwiseAdd` (within `#if V8_ENABLE_WEBASSEMBLY`):** This test is specific to WebAssembly. It checks if a pattern of pairwise addition followed by a regular addition can be fused into a single instruction (`kArm64Sadalp` or `kArm64Uadalp`).
    * **DPFlagSet tests (`BranchWithParameters`):** These tests examine how the instruction selector handles conditional branches based on the result of data processing instructions. They ensure the `flags_mode()` and `flags_condition()` are set correctly.
    * **Branch tests with immediates (`Word32AndBranchWithImmediateOnRight` and similar):** These tests check conditional branches after performing bitwise AND or addition/subtraction with an immediate value. They verify the correct instruction (`kArm64Tst32`, `kArm64Tst`, `kArm64Cmn32`, `kArm64Cmp32`, `kArm64CompareAndBranch32`) and the `flags_mode()` and `flags_condition()`.
    * **Test and Branch tests (`TestAndBranchTest`, `TestAndBranchTest64`):** These are more complex tests focusing on the optimization of branching based on the result of bitwise AND operations with a mask. They verify the use of `kArm64TestAndBranch32` and `kArm64TestAndBranch` instructions for checking specific bits.
    * **Compare against zero and Equal zero tests (`CompareAgainstZeroAndBranch`, `EqualZeroAndBranch`):** These tests check if the instruction selector can optimize branches when comparing against zero, using instructions like `kArm64CompareAndBranch32` and `kArm64CompareAndBranch`.

3. **Identify common themes and functionalities:**  After analyzing the individual tests, group them into broader categories:
    * **Basic Arithmetic Operations:** Testing the generation of ADD instructions with different operand types (immediate, extended registers).
    * **Instruction Fusion (WebAssembly):** Testing the merging of pairwise and regular addition.
    * **Conditional Branching:**  Testing branches based on the results of data processing operations, especially bitwise AND and comparisons.
    * **Immediate Operands:**  Ensuring immediate values are correctly handled in arithmetic and logical operations.
    * **Bit Manipulation:** Specifically testing the efficient handling of bitwise AND operations for branching.

4. **Address specific user questions:**
    * **File type:** The user correctly identified that `.cc` signifies a C++ source file, not Torque.
    * **Relationship to JavaScript:** While these tests are low-level, they directly impact how JavaScript code is translated into efficient machine code on ARM64. Provide a simple JavaScript example where integer addition and bitwise operations occur.
    * **Code logic reasoning:** For a few representative tests (like `AddImmRight32` and a `TestAndBranch` example), demonstrate the input (parameters to `StreamBuilder`) and the expected output (the generated instruction and its properties).
    * **Common programming errors:** Relate the tested scenarios to potential programmer mistakes, such as incorrect assumptions about integer overflow or not optimizing for bitwise checks.

5. **Synthesize a concise summary:** Based on the identified themes, summarize the main functions of the code. Emphasize that it's testing the instruction selector's ability to choose the most efficient ARM64 instructions for various code patterns.

6. **Structure the output:** Organize the information clearly with headings and bullet points to address each part of the user's request. Use code blocks for the C++ snippets and JavaScript examples.

7. **Refine and review:** Ensure the explanations are accurate, easy to understand, and directly address the user's questions about the specific code snippet provided. For instance, explicitly mention that the tests use a mock instruction stream. Also, make sure to address the "part 2 of 8" aspect by indicating this is a specific section focusing on particular optimizations.
这是目录为 `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 的 V8 源代码的第二部分。根据之前对第一部分的分析，我们可以继续归纳它的功能：

**功能归纳 (基于提供的第二部分代码):**

这部分代码延续了对 ARM64 架构指令选择器的单元测试。它主要关注以下几个方面的功能测试：

1. **更复杂的加法指令选择:**
   - 测试了将立即数作为右操作数添加到寄存器的场景，并验证了生成的 `ADD` 指令的寻址模式 (`kMode_Operand2_I`) 和立即数值。
   - 测试了在加法操作中，对左操作数进行不同类型的扩展（无符号字节、无符号半字、有符号字节、有符号半字）的情况，并验证了生成的 `ADD` 指令的寻址模式 (`kMode_Operand2_R_UXTB`, `kMode_Operand2_R_UXTH`, `kMode_Operand2_R_SXTB`, `kMode_Operand2_R_SXTH`)。这旨在测试指令选择器是否能利用 ARM64 架构提供的灵活的第二操作数格式。

2. **WebAssembly 特定的指令融合 (如果启用了 WebAssembly):**
   - 测试了当存在一个成对加法操作（例如，将 SIMD 向量中的相邻元素相加）后跟一个普通的加法操作时，指令选择器是否能够将其融合为单个更高效的指令 (`kArm64Sadalp` 或 `kArm64Uadalp`)。

3. **基于数据处理指令结果的条件分支:**
   - 测试了基于数据处理指令（如 `Int32Add`, `Word32And` 等）的结果进行条件分支的情况。它验证了生成的跳转指令 (`kArm64Tst32`, `kArm64Tst`, `kArm64Cmn32`, `kArm64Cmp32`, `kArm64CompareAndBranch32`, `kArm64TestAndBranch32`, `kArm64TestAndBranch`) 的操作码 (`arch_opcode`)、标志模式 (`flags_mode`) 和条件码 (`flags_condition`) 是否正确。
   - 特别关注了当分支条件涉及到与立即数进行 `AND` 操作的场景，测试了指令选择器是否能够利用 `TBZ`/`TBNZ` 指令（虽然在代码中显式跳过了一些可以优化为 `TBZ`/`TBNZ` 的情况，但整体测试目标是覆盖这类模式）。
   - 详细测试了当 `Word32And` 或 `Word64And` 操作的结果用于分支条件时，指令选择器能否识别并使用 `kArm64TestAndBranch32` 和 `kArm64TestAndBranch` 指令，这些指令可以同时执行测试和分支，提高效率。涵盖了各种 `AND` 操作的变体，包括操作数的顺序以及与常量的比较。
   - 测试了直接基于寄存器值或其取反值进行分支的场景，验证了 `kArm64CompareAndBranch32` 和 `kArm64CompareAndBranch` 指令的正确生成。
   - 测试了与零比较后进行分支的各种形式 (`Word32Equal(x, 0)`, `Word32NotEqual(x, 0)` 等)，确保指令选择器能够生成最优的比较和分支指令。

**总结第二部分的功能:**

这部分单元测试主要集中在验证 ARM64 指令选择器在以下方面的正确性：

- **处理带有立即数和寄存器扩展的加法运算。**
- **在 WebAssembly 代码中进行指令融合以提高性能。**
- **基于各种数据处理指令的结果生成正确的条件分支指令，特别是针对位测试和与零比较的优化。**

这些测试用例旨在确保编译器能够为常见的代码模式生成高效且正确的 ARM64 指令序列。与第一部分类似，它通过构建模拟的指令流并断言生成的指令的属性来完成测试。

**与 JavaScript 的关系 (延续第一部分的解释):**

这部分测试仍然与 JavaScript 的执行性能息息相关。例如：

- **加法和扩展操作：**  JavaScript 中的数字运算，特别是涉及到类型转换和低位提取时，会产生需要进行扩展的加法操作。指令选择器的优化直接影响这些运算的速度。
- **WebAssembly 指令融合：** 如果 JavaScript 代码使用了 WebAssembly，这部分的测试确保了 WebAssembly 的 SIMD 指令能够被有效地翻译成 ARM64 指令。
- **条件分支：**  JavaScript 中的 `if` 语句、循环等控制流结构都需要转化为条件分支指令。指令选择器能否为这些结构生成最优的分支指令对性能至关重要。特别是针对位操作的优化，例如检查一个变量的某个位是否被设置，在 JavaScript 中也很常见。

**代码逻辑推理示例 (选取一个 `TEST_F`):**

以 `TEST_F(InstructionSelectorTest, AddImmRight32)` 中的一个子测试为例：

**假设输入:**

- `StreamBuilder` 配置为返回 `Int32` 类型的值，接收一个 `Int32` 类型的参数。
- 代码构建了一个加法操作：将参数 0 (`m.Parameter(0)`) 与立即数 15 (`m.Int32Constant(15)`) 相加。

**预期输出:**

- 生成的指令流 `s` 应该只包含一条指令。
- 该指令的架构操作码 (`arch_opcode`) 应该是 `kArm64Add32` (32位加法)。
- 该指令的寻址模式 (`addressing_mode`) 应该是 `kMode_Operand2_I` (表示第二个操作数是立即数)。
- 该指令应该有两个输入：一个寄存器 (参数 0) 和一个立即数。
- 该指令应该有一个输出：存储加法结果的寄存器。
- 并且，通过 `s.ToInt64(s[0]->InputAt(1))` 获得的立即数的值应该等于 15。

**用户常见的编程错误示例 (延续第一部分的解释):**

这部分的代码测试覆盖了一些与性能相关的优化。用户可能不会直接犯导致这些特定指令无法生成的错误，但了解这些优化有助于编写更高效的 JavaScript 代码，或者至少理解 V8 引擎是如何优化代码的。

例如，虽然用户不太可能直接写出需要进行“成对加法后跟普通加法”的模式，但如果他们使用的库或框架内部产生了这样的模式（尤其是在处理 SIMD 数据时），V8 的指令选择器能够进行融合优化就显得很重要。

此外，了解 V8 如何优化基于位运算的条件分支，可以帮助开发者在需要进行高效位测试时选择合适的 JavaScript 操作，虽然现代 JavaScript 引擎通常能进行很好的优化。

在 C++ 层面，如果开发者直接操作位，可能会因为不熟悉 ARM64 架构的特性而写出 suboptimal 的代码，而 V8 的指令选择器则负责将高级语言的概念映射到最优的底层指令。

请继续提供后续部分的代码，以便进行更全面的分析。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(InstructionSelectorTest, AddUnsignedExtendByteOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Int32Add(m.Word32And(m.Parameter(0), m.Int32Constant(0xFF)),
                        m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int64());
    m.Return(m.Int64Add(m.Word32And(m.Parameter(0), m.Int32Constant(0xFF)),
                        m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, AddUnsignedExtendHalfwordOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Int32Add(m.Word32And(m.Parameter(0), m.Int32Constant(0xFFFF)),
                        m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int64());
    m.Return(m.Int64Add(m.Word32And(m.Parameter(0), m.Int32Constant(0xFFFF)),
                        m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, AddSignedExtendByteOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Add(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(24)),
                               m.Int32Constant(24)),
                   m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int64());
    m.Return(
        m.Int64Add(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(24)),
                               m.Int32Constant(24)),
                   m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, AddSignedExtendHalfwordOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Add(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(16)),
                               m.Int32Constant(16)),
                   m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int64());
    m.Return(
        m.Int64Add(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(16)),
                               m.Int32Constant(16)),
                   m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

#if V8_ENABLE_WEBASSEMBLY
enum PairwiseAddSide { LEFT, RIGHT };

std::ostream& operator<<(std::ostream& os, const PairwiseAddSide& side) {
  switch (side) {
    case LEFT:
      return os << "LEFT";
    case RIGHT:
      return os << "RIGHT";
  }
}

struct AddWithPairwiseAddSideAndWidth {
  PairwiseAddSide side;
  int32_t width;
  bool isSigned;
};

std::ostream& operator<<(std::ostream& os,
                         const AddWithPairwiseAddSideAndWidth& sw) {
  return os << "{ side: " << sw.side << ", width: " << sw.width
            << ", isSigned: " << sw.isSigned << " }";
}

using InstructionSelectorAddWithPairwiseAddTest =
    InstructionSelectorTestWithParam<AddWithPairwiseAddSideAndWidth>;

TEST_P(InstructionSelectorAddWithPairwiseAddTest, AddWithPairwiseAdd) {
  AddWithPairwiseAddSideAndWidth params = GetParam();
  const MachineType type = MachineType::Simd128();
  StreamBuilder m(this, type, type, type, type);

  Node* x = m.Parameter(0);
  Node* y = m.Parameter(1);
  const Operator* pairwiseAddOp;
  if (params.width == 32 && params.isSigned) {
    pairwiseAddOp = m.machine()->I32x4ExtAddPairwiseI16x8S();
  } else if (params.width == 16 && params.isSigned) {
    pairwiseAddOp = m.machine()->I16x8ExtAddPairwiseI8x16S();
  } else if (params.width == 32 && !params.isSigned) {
    pairwiseAddOp = m.machine()->I32x4ExtAddPairwiseI16x8U();
  } else {
    pairwiseAddOp = m.machine()->I16x8ExtAddPairwiseI8x16U();
  }
  Node* pairwiseAdd = m.AddNode(pairwiseAddOp, x);
  const Operator* addOp =
      params.width == 32 ? m.machine()->I32x4Add() : m.machine()->I16x8Add();
  Node* add = params.side == LEFT ? m.AddNode(addOp, pairwiseAdd, y)
                                  : m.AddNode(addOp, y, pairwiseAdd);
  m.Return(add);
  Stream s = m.Build();

  // Should be fused to Sadalp/Uadalp
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(params.isSigned ? kArm64Sadalp : kArm64Uadalp, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

const AddWithPairwiseAddSideAndWidth kAddWithPairAddTestCases[] = {
    {LEFT, 16, true},  {RIGHT, 16, true}, {LEFT, 32, true},
    {RIGHT, 32, true}, {LEFT, 16, false}, {RIGHT, 16, false},
    {LEFT, 32, false}, {RIGHT, 32, false}};

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorAddWithPairwiseAddTest,
                         ::testing::ValuesIn(kAddWithPairAddTestCases));
#endif  // V8_ENABLE_WEBASSEMBLY

// -----------------------------------------------------------------------------
// Data processing controlled branches.

using InstructionSelectorDPFlagSetTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorDPFlagSetTest, BranchWithParameters) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  RawMachineLabel a, b;
  m.Branch((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)), &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(1));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorDPFlagSetTest,
                         ::testing::ValuesIn(kDPFlagSetInstructions));

TEST_F(InstructionSelectorTest, Word32AndBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint32_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32And(m.Parameter(0), m.Int32Constant(imm)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word64AndBranchWithImmediateOnRight) {
  TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint64_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64And(m.Parameter(0), m.Int64Constant(imm)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst, s[0]->arch_opcode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, AddBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Int32Add(m.Parameter(0), m.Int32Constant(imm)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, SubBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Int32Sub(m.Parameter(0), m.Int32Constant(imm)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ((imm == 0) ? kArm64CompareAndBranch32 : kArm64Cmp32,
              s[0]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word32AndBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint32_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32And(m.Int32Constant(imm), m.Parameter(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    ASSERT_LE(1U, s[0]->InputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word64AndBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint64_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64And(m.Int64Constant(imm), m.Parameter(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst, s[0]->arch_opcode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    ASSERT_LE(1U, s[0]->InputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, AddBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Int32Add(m.Int32Constant(imm), m.Parameter(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    ASSERT_LE(1U, s[0]->InputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

struct TestAndBranch {
  MachInst<std::function<Node*(InstructionSelectorTest::StreamBuilder&, Node*,
                               uint64_t mask)>>
      mi;
  FlagsCondition cond;
};

std::ostream& operator<<(std::ostream& os, const TestAndBranch& tb) {
  return os << tb.mi;
}

const TestAndBranch kTestAndBranchMatchers32[] = {
    // Branch on the result of Word32And directly.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x, uint32_t mask)
          -> Node* { return m.Word32And(x, m.Int32Constant(mask)); },
      "if (x and mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32And(x, m.Int32Constant(mask)));
      },
      "if not (x and mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x, uint32_t mask)
          -> Node* { return m.Word32And(m.Int32Constant(mask), x); },
      "if (mask and x)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32And(m.Int32Constant(mask), x));
      },
      "if not (mask and x)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    // Branch on the result of '(x and mask) == mask'. This tests that a bit is
    // set rather than cleared which is why conditions are inverted.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32Equal(m.Word32And(x, m.Int32Constant(mask)),
                             m.Int32Constant(mask));
      },
      "if ((x and mask) == mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32Equal(
            m.Word32And(x, m.Int32Constant(mask)), m.Int32Constant(mask)));
      },
      "if ((x and mask) != mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32Equal(m.Int32Constant(mask),
                             m.Word32And(x, m.Int32Constant(mask)));
      },
      "if (mask == (x and mask))", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32Equal(
            m.Int32Constant(mask), m.Word32And(x, m.Int32Constant(mask))));
      },
      "if (mask != (x and mask))", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    // Same as above but swap 'mask' and 'x'.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32Equal(m.Word32And(m.Int32Constant(mask), x),
                             m.Int32Constant(mask));
      },
      "if ((mask and x) == mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32Equal(
            m.Word32And(m.Int32Constant(mask), x), m.Int32Constant(mask)));
      },
      "if ((mask and x) != mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32Equal(m.Int32Constant(mask),
                             m.Word32And(m.Int32Constant(mask), x));
      },
      "if (mask == (mask and x))", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32Equal(
            m.Int32Constant(mask), m.Word32And(m.Int32Constant(mask), x)));
      },
      "if (mask != (mask and x))", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual}};

using InstructionSelectorTestAndBranchTest =
    InstructionSelectorTestWithParam<TestAndBranch>;

TEST_P(InstructionSelectorTestAndBranchTest, TestAndBranch32) {
  const TestAndBranch inst = GetParam();
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(inst.mi.constructor(m, m.Parameter(0), mask), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(inst.cond, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt32(s[0]->InputAt(1)));
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorTestAndBranchTest,
                         ::testing::ValuesIn(kTestAndBranchMatchers32));

// TODO(arm64): Add the missing Word32BinaryNot test cases from the 32-bit
// version.
const TestAndBranch kTestAndBranchMatchers64[] = {
    // Branch on the result of Word64And directly.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x, uint64_t mask)
          -> Node* { return m.Word64And(x, m.Int64Constant(mask)); },
      "if (x and mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Word64And(x, m.Int64Constant(mask)),
                             m.Int64Constant(0));
      },
      "if not (x and mask)", kArm64TestAndBranch, MachineType::Int64()},
     kEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x, uint64_t mask)
          -> Node* { return m.Word64And(m.Int64Constant(mask), x); },
      "if (mask and x)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Word64And(m.Int64Constant(mask), x),
                             m.Int64Constant(0));
      },
      "if not (mask and x)", kArm64TestAndBranch, MachineType::Int64()},
     kEqual},
    // Branch on the result of '(x and mask) == mask'. This tests that a bit is
    // set rather than cleared which is why conditions are inverted.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Word64And(x, m.Int64Constant(mask)),
                             m.Int64Constant(mask));
      },
      "if ((x and mask) == mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Int64Constant(mask),
                             m.Word64And(x, m.Int64Constant(mask)));
      },
      "if (mask == (x and mask))", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    // Same as above but swap 'mask' and 'x'.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Word64And(m.Int64Constant(mask), x),
                             m.Int64Constant(mask));
      },
      "if ((mask and x) == mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Int64Constant(mask),
                             m.Word64And(m.Int64Constant(mask), x));
      },
      "if (mask == (mask and x))", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual}};

using InstructionSelectorTestAndBranchTest64 =
    InstructionSelectorTestWithParam<TestAndBranch>;

TEST_P(InstructionSelectorTestAndBranchTest64, TestAndBranch64) {
  const TestAndBranch inst = GetParam();
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(inst.mi.constructor(m, m.Parameter(0), mask), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(inst.cond, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorTestAndBranchTest64,
                         ::testing::ValuesIn(kTestAndBranchMatchers64));

TEST_F(InstructionSelectorTest, Word64AndBranchWithOneBitMaskOnRight) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64And(m.Parameter(0), m.Int64Constant(mask)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }
}

TEST_F(InstructionSelectorTest, Word64AndBranchWithOneBitMaskOnLeft) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64And(m.Int64Constant(mask), m.Parameter(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }
}

TEST_F(InstructionSelectorTest, TestAndBranch64EqualWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b, c;
    Node* n = m.Word64And(m.Parameter(0), m.Int64Constant(mask));
    m.Branch(m.Word64Equal(n, m.Int64Constant(0)), &a, &b);
    m.Bind(&a);
    m.Branch(m.Word64Equal(n, m.Int64Constant(3)), &b, &c);
    m.Bind(&c);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kArm64And, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(kArm64TestAndBranch, s[1]->arch_opcode());
    EXPECT_EQ(kEqual, s[1]->flags_condition());
    EXPECT_EQ(kArm64Cmp, s[2]->arch_opcode());
    EXPECT_EQ(kEqual, s[2]->flags_condition());
    EXPECT_EQ(2U, s[0]->InputCount());
  }
}

TEST_F(InstructionSelectorTest, TestAndBranch64AndWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b, c;
    m.Branch(m.Word64And(m.Parameter(0), m.Int64Constant(mask)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(4U, s[0]->InputCount());
  }
}

TEST_F(InstructionSelectorTest, TestAndBranch32AndWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = uint32_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b, c;
    m.Branch(m.Word32And(m.Parameter(0), m.Int32Constant(mask)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(4U, s[0]->InputCount());
  }
}

TEST_F(InstructionSelectorTest, Word32EqualZeroAndBranchWithOneBitMask) {
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32Equal(m.Word32And(m.Int32Constant(mask), m.Parameter(0)),
                           m.Int32Constant(0)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt32(s[0]->InputAt(1)));
  }

  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(
        m.Word32NotEqual(m.Word32And(m.Int32Constant(mask), m.Parameter(0)),
                         m.Int32Constant(0)),
        &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt32(s[0]->InputAt(1)));
  }
}

TEST_F(InstructionSelectorTest, Word64EqualZeroAndBranchWithOneBitMask) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64Equal(m.Word64And(m.Int64Constant(mask), m.Parameter(0)),
                           m.Int64Constant(0)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }

  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(
        m.Word64NotEqual(m.Word64And(m.Int64Constant(mask), m.Parameter(0)),
                         m.Int64Constant(0)),
        &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }
}

TEST_F(InstructionSelectorTest, CompareAgainstZeroAndBranch) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(p0, &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }

  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word32BinaryNot(p0), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }
}

TEST_F(InstructionSelectorTest, EqualZeroAndBranch) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word32Equal(p0, m.Int32Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }

  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word32NotEqual(p0, m.Int32Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }

  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word64Equal(p0, m.Int64Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }

  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word64NotEqual(p0, m.Int64Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPEC
```