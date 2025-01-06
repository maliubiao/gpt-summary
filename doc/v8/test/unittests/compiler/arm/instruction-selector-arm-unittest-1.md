Response: The user wants a summary of the functionality of the provided C++ code, which is the second part of a larger file. The file appears to be a unit test for the ARM instruction selector in the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name `instruction-selector-arm-unittest.cc` and the numerous `TEST_F` and `TEST_P` macros clearly indicate this is a unit test file. The "arm" part specifies the target architecture, and "instruction-selector" points to the component being tested.

2. **Recognize the Context (Part 2):** The prompt explicitly mentions this is "part 2". This suggests the file likely continues testing functionalities started in "part 1". It's important to keep this in mind, as some tests might depend on concepts introduced earlier.

3. **Analyze the Test Structure:** The code is organized into `TEST_F` and `TEST_P` blocks. `TEST_F` indicates a test fixture, and `TEST_P` indicates a parameterized test. This means the tests cover various scenarios and input combinations.

4. **Categorize the Tested Instructions/Operations:** Scan the test names and the operations being performed within each test. Look for patterns and groupings. In this part of the file, several categories emerge:
    * **Floating-point arithmetic:** Tests for `Float32Abs`, `Float64Abs`, `Float32AddWithFloat32Mul`, `Float64AddWithFloat64Mul`, `Float32SubWithFloat32Mul`, `Float64SubWithFloat64Mul`, `Float32Sqrt`, `Float64Sqrt`, `Float64Max`, `Float64Min`, `Float32Neg`, `Float64Neg`.
    * **Flag-setting instructions:** Tests involving comparisons and binary operations that set processor flags, including `Int32Add`, `Word32And`, `Word32Or`, `Word32Xor`. These tests often involve branching based on the flags.
    * **Integer arithmetic and logic:** Tests for various integer operations like `Int32AddWithInt32Mul`, `Int32AddWithInt32MulHigh`, `Int32AddWithWord32And`, `Int32AddWithWord32SarWithWord32Shl`, `Int32SubWithInt32Mul`, `Int32DivWithParameters`, `Int32ModWithParameters`, `Int32MulWithParameters`, `Int32MulHighWithParameters`, `Uint32MulHighWithParameters`, `Uint32DivWithParameters`, `Uint32ModWithParameters`, `Word32ShlWord32SarForSbfx`, `Word32AndWithUbfxImmediateForARMv7`, `Word32AndWithBfcImmediateForARMv7`, `Word32AndWith0xFFFF`, `Word32SarWithWord32Shl`, `Word32ShrWithWord32AndWithImmediateForARMv7`, `Word32AndWithWord32BitwiseNot`, `Word32EqualWithParameters`, `Word32BitwiseNotWithParameter`, `Word32Clz`.
    * **SIMD operations:** Tests for `AddWithPairwiseAdd`.

5. **Identify Key Testing Aspects:** Within each category, note what specific aspects are being tested. For instance:
    * Correct opcode selection (`EXPECT_EQ(kArmVcmpF64, s[0]->arch_opcode())`).
    * Handling of immediate values (`EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate())`).
    * Correct input and output registers.
    * Flag setting behavior (`EXPECT_EQ(kFlags_set, s[0]->flags_mode())`).
    * Optimization opportunities (e.g., fusing add and multiply into `MLA`).
    * Correctness for different ARM architecture versions (e.g., `ARMv7`, `ARMv8`, `SUDIV`).
    * Handling of commutative operations with immediates or shifted operands.
    * Specific instruction encodings for bitfield manipulation (`Ubfx`, `Bfc`).

6. **Connect to JavaScript (If Applicable):**  The tests cover low-level instruction selection, which is crucial for efficient execution of JavaScript code. Provide examples of JavaScript code that would likely trigger the tested instructions. Focus on operations like:
    * Arithmetic operations (+, -, *, /, %).
    * Bitwise operations (&, |, ^, ~, <<, >>).
    * Comparisons (==, !=, <, >, <=, >=).
    * Math functions (e.g., `Math.abs`, `Math.sqrt`, `Math.max`, `Math.min`).
    * SIMD operations (using `Float32x4`, `Int32x4`, etc.).

7. **Structure the Summary:** Organize the findings into a clear and concise summary. Start with the overall purpose, then list the tested categories, and provide brief explanations and JavaScript examples where relevant.

8. **Review and Refine:** Check the summary for accuracy, clarity, and completeness. Ensure the JavaScript examples are appropriate and illustrate the connection to the C++ code. Make sure to address the "part 2" aspect by noting that it's a continuation of testing.
这是文件 `v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc` 的第二部分，延续了第一部分的功能，主要用于测试 **V8 JavaScript 引擎** 在 **ARM 架构** 下的代码生成器（Instruction Selector）的正确性。

具体来说，这部分代码的功能可以归纳为：

**1. 继续测试浮点数比较操作 (Float64 Comparisons):**

*   测试了 `Float64` 类型的比较操作，例如 `Float64Equal`、`Float64NotEqual`、`Float64LessThan` 等。
*   验证了当比较操作数包含立即数 0.0 时，生成的 ARM 汇编指令 (`kArmVcmpF64`) 是否正确，以及标志位设置是否符合预期。

**2. 测试浮点数算术运算 (Floating point arithmetic):**

*   测试了各种 `Float32` 和 `Float64` 类型的算术运算，包括加法、减法、乘法、绝对值、平方根等。
*   重点测试了 **融合乘加/减 (Fused Multiply-Add/Subtract)** 的优化，例如 `Float32Add(Float32Mul(a, b), c)` 是否能生成 `kArmVmlaF32` 指令。

**3. 测试设置标志位的指令 (Flag-setting instructions):**

*   测试了一些会影响 ARM 处理器标志位 (flags) 的整数运算指令，例如 `Int32Add`、`Word32And`、`Word32Or`、`Word32Xor`。
*   验证了当这些指令的结果直接用于条件分支时，是否能优化成不产生结果寄存器的指令（例如 `kArmCmn`、`kArmTst`、`kArmTeq`），并正确设置分支条件。
*   测试了立即数和移位操作数对标志位设置指令的影响。

**4. 测试其他各种整数运算和位操作 (Miscellaneous):**

*   测试了更广泛的整数运算，包括：
    *   **乘法相关:**  `Int32Add` 与 `Int32Mul`、`Int32MulHigh` 的组合，验证是否能生成 `kArmMla`、`kArmSmmla` 等指令。
    *   **位运算优化:** `Int32Add` 与 `Word32And` 的组合，验证是否能生成 `kArmUxtab`、`kArmUxtah` 等指令；`Int32Add` 与带移位的 `Word32Sar` 的组合，验证是否能生成 `kArmSxtab`、`kArmSxtah` 等指令。
    *   **除法和取模:** `Int32Div`、`Int32Mod`、`Uint32Div`、`Uint32Mod` 的测试，验证在不同架构特性 (如 `SUDIV`) 下是否能生成合适的指令。
    *   **移位和位域操作:** 测试了 `Word32Shl`、`Word32Sar`、`Word32Shr` 以及与 `Word32And` 结合的位域提取 (`kArmSbfx`、`kArmUbfx`) 和位域清除 (`kArmBfc`) 指令的生成。
    *   **逻辑运算:** `Word32And`、`Word32BitwiseNot`、`Word32Equal` 的测试。
    *   **前导零计数:** `Word32Clz` 的测试。

**5. 测试 SIMD 操作 (针对 ARMv8):**

*   测试了部分 SIMD (Single Instruction, Multiple Data) 操作，例如 `Float64Max`、`Float64Min`、`Float32Neg`、`Float64Neg`。
*   还测试了带有 Pairwise Add 的 SIMD 操作，例如 `I32x4ExtAddPairwiseI16x8S` 和 `I16x8ExtAddPairwiseI8x16S`，验证是否能融合生成 `kArmVpadal` 指令。

**与 JavaScript 的关系及示例:**

这些测试直接关系到 V8 引擎如何将 JavaScript 代码编译成高效的 ARM 汇编指令。以下是一些 JavaScript 示例，可能会触发测试中涉及的指令：

*   **浮点数比较:**
    ```javascript
    let a = 1.5;
    let b = 0.0;
    if (a > b) { // 可能触发 kArmVcmpF64 等比较指令
      console.log("a is greater than b");
    }
    ```

*   **浮点数算术运算:**
    ```javascript
    let x = 2.0;
    let y = 3.0;
    let z = 4.0;
    let result = x * y + z; // 可能触发 kArmVmlaF64 等融合乘加指令
    let abs_val = Math.abs(-5.2); // 可能触发 kArmVabsF64 指令
    let sqrt_val = Math.sqrt(9.0); // 可能触发 kArmVsqrtF64 指令
    ```

*   **整数运算和位操作:**
    ```javascript
    let i = 10;
    let j = 5;
    let sum = i + j; // 可能触发 kArmAdd 或 kArmCmn 指令 (取决于上下文)
    let and_result = i & j; // 可能触发 kArmAnd 或 kArmTst 指令
    let shifted = i << 2;
    let masked = i & 0xFF; // 可能触发 kArmAnd 或 kArmUxtb 指令
    let quotient = Math.floor(i / j); // 可能触发调用除法例程，或在特定情况下生成 kArmSdiv 等指令
    let remainder = i % j; // 可能触发调用取模例程，或在特定情况下生成 kArmMls 等指令
    ```

*   **SIMD 操作 (需要启用 SIMD 支持):**
    ```javascript
    let a = Float64x2(1.0, 2.0);
    let b = Float64x2(3.0, 4.0);
    let max_val = Math.max(a.x, b.x); // 可能触发 kArmFloat64Max 指令 (在标量上下文中)
    // 或者使用 SIMD 类型进行操作
    let c = Float64x2.max(a, b); // 可能触发 kArmFloat64Max 等 SIMD 指令
    ```

**总结:**

这部分测试文件是 V8 引擎代码生成器在 ARM 架构上的一个关键测试组件。它通过构造各种代码模式来验证 Instruction Selector 是否能正确地将 V8 的中间表示 (IR) 转换成最优的 ARM 汇编指令，包括浮点数操作、整数运算、位操作以及 SIMD 指令的生成，确保生成的代码在 ARM 平台上能够高效且正确地执行。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
);
}


TEST_P(InstructionSelectorF64ComparisonTest, WithImmediateZeroOnLeft) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  m.Return((m.*cmp.constructor)(m.Float64Constant(0.0), m.Parameter(0)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF64, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.commuted_flags_condition, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorF64ComparisonTest,
                         ::testing::ValuesIn(kF64Comparisons));

// -----------------------------------------------------------------------------
// Floating point arithmetic.

using InstructionSelectorFAITest = InstructionSelectorTestWithParam<FAI>;

TEST_P(InstructionSelectorFAITest, Parameters) {
  const FAI& fai = GetParam();
  StreamBuilder m(this, fai.machine_type, fai.machine_type, fai.machine_type);
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const r = (m.*fai.constructor)(p0, p1);
  m.Return(r);
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(fai.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_None, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->OutputAt(0)));
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorFAITest,
                         ::testing::ValuesIn(kFAIs));

TEST_F(InstructionSelectorTest, Float32Abs) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Float32Abs(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVabsF32, s[0]->arch_opcode());
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
  EXPECT_EQ(kArmVabsF64, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}


TEST_F(InstructionSelectorTest, Float32AddWithFloat32Mul) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                    MachineType::Float32(), MachineType::Float32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* const n = m.Float32Add(m.Float32Mul(p0, p1), p2);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmVmlaF32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(
        UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                    MachineType::Float32(), MachineType::Float32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* const n = m.Float32Add(p0, m.Float32Mul(p1, p2));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmVmlaF32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(
        UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}


TEST_F(InstructionSelectorTest, Float64AddWithFloat64Mul) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Float64(), MachineType::Float64());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* const n = m.Float64Add(m.Float64Mul(p0, p1), p2);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmVmlaF64, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(
        UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Float64(), MachineType::Float64());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* const n = m.Float64Add(p0, m.Float64Mul(p1, p2));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmVmlaF64, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(
        UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}


TEST_F(InstructionSelectorTest, Float32SubWithFloat32Mul) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32(), MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const p2 = m.Parameter(2);
  Node* const n = m.Float32Sub(p0, m.Float32Mul(p1, p2));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVmlsF32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(2)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE(UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}


TEST_F(InstructionSelectorTest, Float64SubWithFloat64Mul) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64(), MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const p2 = m.Parameter(2);
  Node* const n = m.Float64Sub(p0, m.Float64Mul(p1, p2));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVmlsF64, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(2)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE(UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}


TEST_F(InstructionSelectorTest, Float32Sqrt) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Float32Sqrt(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVsqrtF32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}


TEST_F(InstructionSelectorTest, Float64Sqrt) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Float64Sqrt(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVsqrtF64, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}

// -----------------------------------------------------------------------------
// Flag-setting instructions.

const Comparison kBinopCmpZeroRightInstructions[] = {
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kEqual, kNotEqual,
     kEqual},
    {&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kNotEqual, kEqual,
     kNotEqual},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan", kNegative,
     kPositiveOrZero, kNegative},
    {&RawMachineAssembler::Int32GreaterThanOrEqual, "Int32GreaterThanOrEqual",
     kPositiveOrZero, kNegative, kPositiveOrZero},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
     kEqual, kNotEqual, kEqual},
    {&RawMachineAssembler::Uint32GreaterThan, "Uint32GreaterThan", kNotEqual,
     kEqual, kNotEqual}};

const Comparison kBinopCmpZeroLeftInstructions[] = {
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kEqual, kNotEqual,
     kEqual},
    {&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kNotEqual, kEqual,
     kNotEqual},
    {&RawMachineAssembler::Int32GreaterThan, "Int32GreaterThan", kNegative,
     kPositiveOrZero, kNegative},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
     kPositiveOrZero, kNegative, kPositiveOrZero},
    {&RawMachineAssembler::Uint32GreaterThanOrEqual, "Uint32GreaterThanOrEqual",
     kEqual, kNotEqual, kEqual},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kNotEqual, kEqual,
     kNotEqual}};

struct FlagSettingInst {
  Constructor constructor;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  ArchOpcode no_output_opcode;
};

std::ostream& operator<<(std::ostream& os, const FlagSettingInst& inst) {
  return os << inst.constructor_name;
}

const FlagSettingInst kFlagSettingInstructions[] = {
    {&RawMachineAssembler::Int32Add, "Int32Add", kArmAdd, kArmCmn},
    {&RawMachineAssembler::Word32And, "Word32And", kArmAnd, kArmTst},
    {&RawMachineAssembler::Word32Or, "Word32Or", kArmOrr, kArmOrr},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kArmEor, kArmTeq}};

using InstructionSelectorFlagSettingTest =
    InstructionSelectorTestWithParam<FlagSettingInst>;

TEST_P(InstructionSelectorFlagSettingTest, CmpZeroRight) {
  const FlagSettingInst inst = GetParam();
  // Binop with single user : a cmp instruction.
  TRACED_FOREACH(Comparison, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    RawMachineLabel a, b;
    Node* binop = (m.*inst.constructor)(m.Parameter(0), m.Parameter(1));
    Node* comp = (m.*cmp.constructor)(binop, m.Int32Constant(0));
    m.Branch(comp, &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(4U, s[0]->InputCount());  // The labels are also inputs.
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, CmpZeroLeft) {
  const FlagSettingInst inst = GetParam();
  // Test a cmp with zero on the left-hand side.
  TRACED_FOREACH(Comparison, cmp, kBinopCmpZeroLeftInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    RawMachineLabel a, b;
    Node* binop = (m.*inst.constructor)(m.Parameter(0), m.Parameter(1));
    Node* comp = (m.*cmp.constructor)(m.Int32Constant(0), binop);
    m.Branch(comp, &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(4U, s[0]->InputCount());  // The labels are also inputs.
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, CmpZeroOnlyUserInBasicBlock) {
  const FlagSettingInst inst = GetParam();
  // Binop with additional users, but in a different basic block.
  TRACED_FOREACH(Comparison, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    RawMachineLabel a, b;
    Node* binop = (m.*inst.constructor)(m.Parameter(0), m.Parameter(1));
    Node* comp = (m.*cmp.constructor)(binop, m.Int32Constant(0));
    m.Branch(comp, &a, &b);
    m.Bind(&a);
    m.Return(binop);
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(4U, s[0]->InputCount());  // The labels are also inputs.
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, ShiftedOperand) {
  const FlagSettingInst inst = GetParam();
  // Like the test above, but with a shifted input to the binary operator.
  TRACED_FOREACH(Comparison, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    RawMachineLabel a, b;
    Node* imm = m.Int32Constant(5);
    Node* shift = m.Word32Shl(m.Parameter(1), imm);
    Node* binop = (m.*inst.constructor)(m.Parameter(0), shift);
    Node* comp = (m.*cmp.constructor)(binop, m.Int32Constant(0));
    m.Branch(comp, &a, &b);
    m.Bind(&a);
    m.Return(binop);
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(5U, s[0]->InputCount());  // The labels are also inputs.
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(5, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, UsersInSameBasicBlock) {
  const FlagSettingInst inst = GetParam();
  // Binop with additional users, in the same basic block. We need to make sure
  // we don't try to optimise this case.
  TRACED_FOREACH(Comparison, cmp, kComparisons) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    RawMachineLabel a, b;
    Node* binop = (m.*inst.constructor)(m.Parameter(0), m.Parameter(1));
    Node* mul = m.Int32Mul(m.Parameter(0), binop);
    Node* comp = (m.*cmp.constructor)(binop, m.Int32Constant(0));
    m.Branch(comp, &a, &b);
    m.Bind(&a);
    m.Return(mul);
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_NE(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kArmMul, s[1]->arch_opcode());
    EXPECT_EQ(kArmCmp, s[2]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[2]->flags_mode());
    EXPECT_EQ(cmp.flags_condition, s[2]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, CommuteImmediate) {
  const FlagSettingInst inst = GetParam();
  // Immediate on left hand side of the binary operator.
  TRACED_FOREACH(Comparison, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* imm = m.Int32Constant(3);
    Node* binop = (m.*inst.constructor)(imm, m.Parameter(0));
    Node* comp = (m.*cmp.constructor)(binop, m.Int32Constant(0));
    m.Branch(comp, &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(4U, s[0]->InputCount());  // The labels are also inputs.
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(3, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, CommuteShift) {
  const FlagSettingInst inst = GetParam();
  // Left-hand side operand shifted by immediate.
  TRACED_FOREACH(Comparison, cmp, kBinopCmpZeroRightInstructions) {
    TRACED_FOREACH(Shift, shift, kShifts) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      Node* imm = m.Int32Constant(5);
      Node* shifted_operand = (m.*shift.constructor)(m.Parameter(0), imm);
      Node* binop = (m.*inst.constructor)(shifted_operand, m.Parameter(1));
      Node* comp = (m.*cmp.constructor)(binop, m.Int32Constant(0));
      m.Return(comp);
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(5, s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(inst.arch_opcode == kArmOrr ? 2U : 1U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
    }
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorFlagSettingTest,
                         ::testing::ValuesIn(kFlagSettingInstructions));

// -----------------------------------------------------------------------------
// Miscellaneous.


TEST_F(InstructionSelectorTest, Int32AddWithInt32Mul) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* const n = m.Int32Add(p0, m.Int32Mul(p1, p2));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmMla, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* const n = m.Int32Add(m.Int32Mul(p1, p2), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmMla, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Int32AddWithInt32MulHigh) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* const n = m.Int32Add(p0, m.Int32MulHigh(p1, p2));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmSmmla, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* const n = m.Int32Add(m.Int32MulHigh(p1, p2), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmSmmla, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Int32AddWithWord32And) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r = m.Int32Add(m.Word32And(p0, m.Int32Constant(0xFF)), p1);
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxtab, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r = m.Int32Add(p1, m.Word32And(p0, m.Int32Constant(0xFF)));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxtab, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r = m.Int32Add(m.Word32And(p0, m.Int32Constant(0xFFFF)), p1);
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxtah, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r = m.Int32Add(p1, m.Word32And(p0, m.Int32Constant(0xFFFF)));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxtah, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Int32AddWithWord32SarWithWord32Shl) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r = m.Int32Add(
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(24)), m.Int32Constant(24)),
        p1);
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmSxtab, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r = m.Int32Add(
        p1,
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(24)), m.Int32Constant(24)));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmSxtab, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r = m.Int32Add(
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(16)), m.Int32Constant(16)),
        p1);
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmSxtah, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r = m.Int32Add(
        p1,
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(16)), m.Int32Constant(16)));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmSxtah, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Int32SubWithInt32Mul) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32(), MachineType::Int32());
  m.Return(
      m.Int32Sub(m.Parameter(0), m.Int32Mul(m.Parameter(1), m.Parameter(2))));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArmMul, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArmSub, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32SubWithInt32MulForMLS) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32(), MachineType::Int32());
  m.Return(
      m.Int32Sub(m.Parameter(0), m.Int32Mul(m.Parameter(1), m.Parameter(2))));
  Stream s = m.Build(ARMv7);
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMls, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(3U, s[0]->InputCount());
}


TEST_F(InstructionSelectorTest, Int32DivWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Div(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(4U, s.size());
  EXPECT_EQ(kArmVcvtF64S32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArmVcvtF64S32, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArmVdivF64, s[2]->arch_opcode());
  ASSERT_EQ(2U, s[2]->InputCount());
  ASSERT_EQ(1U, s[2]->OutputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
  EXPECT_EQ(kArmVcvtS32F64, s[3]->arch_opcode());
  ASSERT_EQ(1U, s[3]->InputCount());
  EXPECT_EQ(s.ToVreg(s[2]->Output()), s.ToVreg(s[3]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Int32DivWithParametersForSUDIV) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Div(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(SUDIV);
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmSdiv, s[0]->arch_opcode());
}


TEST_F(InstructionSelectorTest, Int32ModWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(6U, s.size());
  EXPECT_EQ(kArmVcvtF64S32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArmVcvtF64S32, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArmVdivF64, s[2]->arch_opcode());
  ASSERT_EQ(2U, s[2]->InputCount());
  ASSERT_EQ(1U, s[2]->OutputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
  EXPECT_EQ(kArmVcvtS32F64, s[3]->arch_opcode());
  ASSERT_EQ(1U, s[3]->InputCount());
  EXPECT_EQ(s.ToVreg(s[2]->Output()), s.ToVreg(s[3]->InputAt(0)));
  EXPECT_EQ(kArmMul, s[4]->arch_opcode());
  ASSERT_EQ(1U, s[4]->OutputCount());
  ASSERT_EQ(2U, s[4]->InputCount());
  EXPECT_EQ(s.ToVreg(s[3]->Output()), s.ToVreg(s[4]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->InputAt(0)), s.ToVreg(s[4]->InputAt(1)));
  EXPECT_EQ(kArmSub, s[5]->arch_opcode());
  ASSERT_EQ(1U, s[5]->OutputCount());
  ASSERT_EQ(2U, s[5]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[5]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[4]->Output()), s.ToVreg(s[5]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32ModWithParametersForSUDIV) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(SUDIV);
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArmSdiv, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kArmMul, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(kArmSub, s[2]->arch_opcode());
  ASSERT_EQ(1U, s[2]->OutputCount());
  ASSERT_EQ(2U, s[2]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32ModWithParametersForSUDIVAndMLS) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(ARMv7, SUDIV);
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArmSdiv, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kArmMls, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  ASSERT_EQ(3U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[1]->InputAt(2)));
}


TEST_F(InstructionSelectorTest, Int32MulWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Mul(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMul, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, Int32MulWithImmediate) {
  // x * (2^k + 1) -> x + (x >> k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Parameter(0), m.Int32Constant((1 << k) + 1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmAdd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // x * (2^k - 1) -> -x + (x >> k)
  TRACED_FORRANGE(int32_t, k, 3, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Parameter(0), m.Int32Constant((1 << k) - 1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmRsb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // (2^k + 1) * x -> x + (x >> k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmAdd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // x * (2^k - 1) -> -x + (x >> k)
  TRACED_FORRANGE(int32_t, k, 3, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Int32Constant((1 << k) - 1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmRsb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, Int32MulHighWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Int32MulHigh(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmSmmul, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}


TEST_F(InstructionSelectorTest, Uint32MulHighWithParameters) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Uint32MulHigh(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmUmull, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(2U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->OutputAt(1)));
}


TEST_F(InstructionSelectorTest, Uint32DivWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Div(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(4U, s.size());
  EXPECT_EQ(kArmVcvtF64U32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArmVcvtF64U32, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArmVdivF64, s[2]->arch_opcode());
  ASSERT_EQ(2U, s[2]->InputCount());
  ASSERT_EQ(1U, s[2]->OutputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
  EXPECT_EQ(kArmVcvtU32F64, s[3]->arch_opcode());
  ASSERT_EQ(1U, s[3]->InputCount());
  EXPECT_EQ(s.ToVreg(s[2]->Output()), s.ToVreg(s[3]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Uint32DivWithParametersForSUDIV) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Div(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(SUDIV);
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmUdiv, s[0]->arch_opcode());
}


TEST_F(InstructionSelectorTest, Uint32ModWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(6U, s.size());
  EXPECT_EQ(kArmVcvtF64U32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArmVcvtF64U32, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArmVdivF64, s[2]->arch_opcode());
  ASSERT_EQ(2U, s[2]->InputCount());
  ASSERT_EQ(1U, s[2]->OutputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
  EXPECT_EQ(kArmVcvtU32F64, s[3]->arch_opcode());
  ASSERT_EQ(1U, s[3]->InputCount());
  EXPECT_EQ(s.ToVreg(s[2]->Output()), s.ToVreg(s[3]->InputAt(0)));
  EXPECT_EQ(kArmMul, s[4]->arch_opcode());
  ASSERT_EQ(1U, s[4]->OutputCount());
  ASSERT_EQ(2U, s[4]->InputCount());
  EXPECT_EQ(s.ToVreg(s[3]->Output()), s.ToVreg(s[4]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->InputAt(0)), s.ToVreg(s[4]->InputAt(1)));
  EXPECT_EQ(kArmSub, s[5]->arch_opcode());
  ASSERT_EQ(1U, s[5]->OutputCount());
  ASSERT_EQ(2U, s[5]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[5]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[4]->Output()), s.ToVreg(s[5]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Uint32ModWithParametersForSUDIV) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(SUDIV);
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArmUdiv, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kArmMul, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(kArmSub, s[2]->arch_opcode());
  ASSERT_EQ(1U, s[2]->OutputCount());
  ASSERT_EQ(2U, s[2]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Uint32ModWithParametersForSUDIVAndMLS) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(ARMv7, SUDIV);
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArmUdiv, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kArmMls, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  ASSERT_EQ(3U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[1]->InputAt(2)));
}


TEST_F(InstructionSelectorTest, Word32ShlWord32SarForSbfx) {
  TRACED_FORRANGE(int32_t, shl, 1, 31) {
    TRACED_FORRANGE(int32_t, sar, shl, 31) {
      if ((shl == sar) && (sar == 16)) continue;  // Sxth.
      if ((shl == sar) && (sar == 24)) continue;  // Sxtb.
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(shl)),
                           m.Int32Constant(sar)));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmSbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(sar - shl, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(32 - sar, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}


TEST_F(InstructionSelectorTest, Word32AndWithUbfxImmediateForARMv7) {
  TRACED_FORRANGE(int32_t, width, 9, 23) {
    if (width == 16) continue;  // Uxth.
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32And(m.Parameter(0),
                         m.Int32Constant(0xFFFFFFFFu >> (32 - width))));
    Stream s = m.Build(ARMv7);
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
  }
  TRACED_FORRANGE(int32_t, width, 9, 23) {
    if (width == 16) continue;  // Uxth.
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32And(m.Int32Constant(0xFFFFFFFFu >> (32 - width)),
                         m.Parameter(0)));
    Stream s = m.Build(ARMv7);
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
  }
}


TEST_F(InstructionSelectorTest, Word32AndWithBfcImmediateForARMv7) {
  TRACED_FORRANGE(int32_t, lsb, 0, 31) {
    TRACED_FORRANGE(int32_t, width, 9, (24 - lsb) - 1) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32And(
          m.Parameter(0),
          m.Int32Constant(~((0xFFFFFFFFu >> (32 - width)) << lsb))));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmBfc, s[0]->arch_opcode());
      ASSERT_EQ(1U, s[0]->OutputCount());
      EXPECT_TRUE(
          UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, lsb, 0, 31) {
    TRACED_FORRANGE(int32_t, width, 9, (24 - lsb) - 1) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(
          m.Word32And(m.Int32Constant(~((0xFFFFFFFFu >> (32 - width)) << lsb)),
                      m.Parameter(0)));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmBfc, s[0]->arch_opcode());
      ASSERT_EQ(1U, s[0]->OutputCount());
      EXPECT_TRUE(
          UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word32AndWith0xFFFF) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(p0, m.Int32Constant(0xFFFF));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Int32Constant(0xFFFF), p0);
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
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
    EXPECT_EQ(kArmSxtb, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
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
    EXPECT_EQ(kArmSxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Word32ShrWithWord32AndWithImmediateForARMv7) {
  TRACED_FORRANGE(int32_t, lsb, 0, 31) {
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t max = 1 << lsb;
      if (max > static_cast<uint32_t>(kMaxInt)) max -= 1;
      uint32_t jnk = rng()->NextInt(max);
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Shr(m.Word32And(m.Parameter(0), m.Int32Constant(msk)),
                           m.Int32Constant(lsb)));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, lsb, 0, 31) {
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t max = 1 << lsb;
      if (max > static_cast<uint32_t>(kMaxInt)) max -= 1;
      uint32_t jnk = rng()->NextInt(max);
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Shr(m.Word32And(m.Int32Constant(msk), m.Parameter(0)),
                           m.Int32Constant(lsb)));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word32AndWithWord32BitwiseNot) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32And(m.Parameter(0), m.Word32BitwiseNot(m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmBic, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32And(m.Word32BitwiseNot(m.Parameter(0)), m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmBic, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, Word32EqualWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Word32Equal(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kEqual, s[0]->flags_condition());
}


TEST_F(InstructionSelectorTest, Word32EqualWithImmediate) {
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Int32Constant(imm), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}


TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word32BitwiseNotWithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  m.Return(m.Word32BitwiseNot(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMvn, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, Word32AndWithWord32ShrWithImmediateForARMv7) {
  TRACED_FORRANGE(int32_t, lsb, 1, 31) {
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      if (((width == 8) || (width == 16)) &&
          ((lsb == 8) || (lsb == 16) || (lsb == 24)))
        continue;  // Uxtb/h ror.
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32And(m.Word32Shr(m.Parameter(0), m.Int32Constant(lsb)),
                           m.Int32Constant(0xFFFFFFFFu >> (32 - width))));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, lsb, 1, 31) {
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      if (((width == 8) || (width == 16)) &&
          ((lsb == 8) || (lsb == 16) || (lsb == 24)))
        continue;  // Uxtb/h ror.
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32And(m.Int32Constant(0xFFFFFFFFu >> (32 - width)),
                           m.Word32Shr(m.Parameter(0), m.Int32Constant(lsb))));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word32AndWithWord32ShrAnd0xFF) {
  TRACED_FORRANGE(int32_t, shr, 1, 3) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Word32Shr(p0, m.Int32Constant(shr * 8)),
                                m.Int32Constant(0xFF));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxtb, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(shr * 8, s.ToInt32(s[0]->InputAt(1)));
  }
  TRACED_FORRANGE(int32_t, shr, 1, 3) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Int32Constant(0xFF),
                                m.Word32Shr(p0, m.Int32Constant(shr * 8)));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxtb, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(shr * 8, s.ToInt32(s[0]->InputAt(1)));
  }
}

TEST_F(InstructionSelectorTest, Word32AndWithWord32ShrAnd0xFFFF) {
  TRACED_FORRANGE(int32_t, shr, 1, 2) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Word32Shr(p0, m.Int32Constant(shr * 8)),
                                m.Int32Constant(0xFFFF));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(shr * 8, s.ToInt32(s[0]->InputAt(1)));
  }
  TRACED_FORRANGE(int32_t, shr, 1, 2) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Int32Constant(0xFFFF),
                                m.Word32Shr(p0, m.Int32Constant(shr * 8)));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(shr * 8, s.ToInt32(s[0]->InputAt(1)));
  }
}


TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmClz, s[0]->arch_opcode());
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
  Stream s = m.Build(ARMv8);
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmFloat64Max, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
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
  Stream s = m.Build(ARMv8);
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmFloat64Min, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float32Neg) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  // Don't use m.Float32Neg() as that generates an explicit sub.
  Node* const n = m.AddNode(m.machine()->Float32Neg(), m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVnegF32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float64Neg) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  // Don't use m.Float64Neg() as that generates an explicit sub.
  Node* const n = m.AddNode(m.machine()->Float64Neg(), m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVnegF64, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}
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

  // Should be fused to Vpadal
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVpadal, s[0]->arch_opcode());
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

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```