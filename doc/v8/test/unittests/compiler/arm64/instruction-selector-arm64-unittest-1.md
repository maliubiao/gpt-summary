Response: The user wants a summary of the C++ code provided. This is the second part of a four-part file. The code seems to be testing the instruction selector for the ARM64 architecture in the V8 JavaScript engine. It focuses on testing how certain arithmetic and logical operations are translated into ARM64 assembly instructions.

Here's a breakdown of the code's functionality:

1. **Overflow Arithmetic Tests:**  It checks how addition and subtraction operations that can result in overflow are handled. It tests scenarios where both operands are registers, or one operand is an immediate value. It verifies that the correct ARM64 instructions are selected, including those that set the overflow flag.

2. **Shift Instruction Tests:** It tests different shift operations (left shift, right shift, arithmetic right shift) with register and immediate operands.

3. **Multiplication and Division Tests:** It tests the selection of multiplication and division instructions. It also includes tests for combined multiply-add and multiply-subtract instructions.

4. **SIMD Instruction Tests (WebAssembly specific):** If WebAssembly is enabled, it tests the selection of SIMD (Single Instruction, Multiple Data) instructions, specifically focusing on multiplication, addition, subtraction, and shift-add operations. It also examines optimizations related to `f32x4.mul` and `f64x2.mul` when one operand is a lane duplication.

5. **Multiplication with Immediate Optimization:** It checks for optimizations when multiplying by constants of the form 2<sup>k</sup> + 1. This optimization often translates the multiplication into an addition and a left shift.

6. **Floating-Point Instruction Tests:** It covers floating-point arithmetic operations (addition, subtraction, multiplication, division) and comparisons. It also tests the `select` operation (similar to a ternary operator) for floating-point values.

7. **Type Conversion Tests:** It tests how different type conversion operations are translated into ARM64 instructions. It also looks at eliding unnecessary conversions in certain scenarios, such as after a load operation.

8. **Memory Access Tests (Partial in this snippet):** It starts testing memory load and store instructions for different data types.
这是针对V8 JavaScript引擎中ARM64架构的指令选择器单元测试的第二部分。 这部分主要测试了以下功能：

**1. 带溢出的加法和减法指令 (Add and subtract instructions with overflow):**

* **功能:**  测试指令选择器对于可能产生溢出的加法和减法操作的处理。
* **测试用例:**
    * 两个操作数都是寄存器。
    * 右操作数是立即数。
    * 检查生成的ARM64指令是否正确设置了标志位 (flags_mode) 和溢出条件 (flags_condition)。
    * 针对不同的使用场景（仅返回值、仅溢出标志、两者都用、用于分支条件）进行测试。
* **与JavaScript的关系:** JavaScript中的数值运算也可能发生溢出。虽然JavaScript自身不会抛出溢出错误，但V8引擎在底层需要正确处理这些操作，以确保数值的正确性。

**2. 移位指令 (Shift instructions):**

* **功能:** 测试指令选择器对于各种移位操作（左移、右移、算术右移）的处理。
* **测试用例:**
    * 移位量是寄存器。
    * 移位量是立即数。
* **与JavaScript的关系:** JavaScript中的位运算操作符 (`<<`, `>>`, `>>>`) 对应于这些移位指令。

**3. 乘法和除法指令 (Mul and Div instructions):**

* **功能:** 测试指令选择器对于乘法和除法操作的处理。
* **测试用例:** 两个操作数都是寄存器。
* **与JavaScript的关系:** JavaScript中的乘法 (`*`) 和除法 (`/`) 运算符对应于这些指令。

**4. 乘加和乘减指令的优化 (InstructionSelectorIntDPWithIntMulTest):**

* **功能:** 测试指令选择器是否能将乘法和加法/减法操作组合成单个的乘加 (Madd) 或乘减 (Msub) ARM64指令，以提高效率。
* **测试用例:** 测试 `a + (b * c)` 和 `a - (b * c)` 的模式。
* **与JavaScript的关系:** JavaScript中的算术表达式经常包含乘法和加法/减法的组合，这种优化可以提高这些表达式的执行速度。

**5. SIMD指令的乘加和乘减优化 (InstructionSelectorSIMDDPWithSIMDMulTest - 如果启用了WebAssembly):**

* **功能:** 如果启用了WebAssembly，则测试指令选择器是否能将SIMD乘法和加法/减法操作组合成单个的乘加 (MLA) 或乘减 (MLS) ARM64指令。
* **测试用例:** 针对 SIMD Int32x4 和 Int16x8 类型测试 `a + (b * c)` 和 `a - (b * c)` 的模式。
* **与JavaScript的关系:**  WebAssembly 允许 JavaScript 代码以接近原生的速度执行。SIMD 指令可以并行处理多个数据，提高性能。

**6. SIMD移位加指令的优化 (InstructionSelectorSIMDShrAddTest - 如果启用了WebAssembly):**

* **功能:** 如果启用了WebAssembly，则测试指令选择器是否能将 SIMD 移位和加法操作组合成单个的指令。
* **测试用例:** 针对不同的 SIMD 类型测试移位后加法的优化。
* **与JavaScript的关系:**  WebAssembly 中的 SIMD 操作可以利用这种优化来提高性能。

**7. SIMD扩展乘加指令的优化 (InstructionSelectorSIMDAddExtMulTest - 如果启用了WebAssembly):**

* **功能:** 如果启用了WebAssembly，则测试指令选择器是否能将 SIMD 扩展乘法和加法操作组合成单个的扩展乘加指令 (SMLAL/UMLAL)。
* **测试用例:** 针对不同的 SIMD 类型测试扩展乘法后加法的优化。
* **与JavaScript的关系:**  WebAssembly 中的 SIMD 操作可以利用这种优化来提高性能。

**8. SIMD乘法与车道复制的优化 (InstructionSelectorSimdF32x4MulWithDupTest 和 InstructionSelectorSimdF64x2MulWithDupTest - 如果启用了WebAssembly):**

* **功能:** 如果启用了WebAssembly，测试当 SIMD 乘法的一个操作数是通过车道复制得到的时，指令选择器是否能使用更高效的 `FMulElement` 指令。
* **测试用例:** 针对 Float32x4 和 Float64x2 类型测试这种优化。
* **与JavaScript的关系:**  WebAssembly 中的 SIMD 操作可以利用这种优化来提高性能。

**9. SIMD反向混洗指令 (ReverseShuffle32x4Test - 如果启用了WebAssembly):**

* **功能:** 如果启用了WebAssembly，测试对于特定的 SIMD 混洗模式，指令选择器是否能识别并使用 `S32x4Reverse` 指令。
* **与JavaScript的关系:** WebAssembly 中的 SIMD 操作可以利用这种优化来提高性能。

**10. SIMD单车道混洗指令 (OneLaneSwizzle32x4Test - 如果启用了WebAssembly):**

* **功能:** 如果启用了WebAssembly，测试对于特定的 SIMD 混洗模式，指令选择器是否能识别并使用 `S32x4OneLaneSwizzle` 指令。
* **与JavaScript的关系:** WebAssembly 中的 SIMD 操作可以利用这种优化来提高性能。

**11. 乘法与立即数的优化 (Int32MulWithImmediate 和 Int64MulWithImmediate):**

* **功能:** 测试当乘法的一个操作数是形如 2<sup>k</sup> + 1 的立即数时，指令选择器是否能将其优化为移位和加法操作。
* **测试用例:** 测试 `x * (2^k + 1)` 和 `(2^k + 1) * x` 的模式，以及与加法和减法的组合。
* **与JavaScript的关系:** JavaScript中的数值运算可能涉及与这类常数的乘法，这种优化可以提高性能。

**简单来说，这部分代码主要关注V8引擎在将高级语言操作（特别是JavaScript和WebAssembly中的算术和位运算）转换为底层ARM64汇编指令时，如何选择最优的指令，并进行一些常见的优化，以提高代码执行效率。**

### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
T_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }
}

// -----------------------------------------------------------------------------
// Add and subtract instructions with overflow.

using InstructionSelectorOvfAddSubTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorOvfAddSubTest, OvfParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(
      m.Projection(1, (m.*dpi.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(InstructionSelectorOvfAddSubTest, OvfImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    m.Return(m.Projection(
        1, (m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorOvfAddSubTest, ValParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(
      m.Projection(0, (m.*dpi.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}

TEST_P(InstructionSelectorOvfAddSubTest, ValImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    m.Return(m.Projection(
        0, (m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_P(InstructionSelectorOvfAddSubTest, BothParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  Node* n = (m.*dpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
  Stream s = m.Build();
  ASSERT_LE(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(2U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(InstructionSelectorOvfAddSubTest, BothImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    Node* n = (m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm));
    m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
    Stream s = m.Build();
    ASSERT_LE(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorOvfAddSubTest, BranchWithParameters) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  RawMachineLabel a, b;
  Node* n = (m.*dpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Branch(m.Projection(1, n), &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(0));
  m.Bind(&b);
  m.Return(m.Projection(0, n));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(InstructionSelectorOvfAddSubTest, BranchWithImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    RawMachineLabel a, b;
    Node* n = (m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm));
    m.Branch(m.Projection(1, n), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(0));
    m.Bind(&b);
    m.Return(m.Projection(0, n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorOvfAddSubTest, RORShift) {
  // ADD and SUB do not support ROR shifts, make sure we do not try
  // to merge them into the ADD/SUB instruction.
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  auto rotate = &RawMachineAssembler::Word64Ror;
  ArchOpcode rotate_opcode = kArm64Ror;
  if (type == MachineType::Int32()) {
    rotate = &RawMachineAssembler::Word32Ror;
    rotate_opcode = kArm64Ror32;
  }
  TRACED_FORRANGE(int32_t, imm, -32, 63) {
    StreamBuilder m(this, type, type, type);
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r = (m.*rotate)(p1, m.Int32Constant(imm));
    m.Return((m.*dpi.constructor)(p0, r));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(rotate_opcode, s[0]->arch_opcode());
    EXPECT_EQ(dpi.arch_opcode, s[1]->arch_opcode());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorOvfAddSubTest,
                         ::testing::ValuesIn(kOvfAddSubInstructions));

TEST_F(InstructionSelectorTest, OvfFlagAddImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        1, m.Int32AddWithOverflow(m.Int32Constant(imm), m.Parameter(0))));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, OvfValAddImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        0, m.Int32AddWithOverflow(m.Int32Constant(imm), m.Parameter(0))));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_F(InstructionSelectorTest, OvfBothAddImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* n = m.Int32AddWithOverflow(m.Int32Constant(imm), m.Parameter(0));
    m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
    Stream s = m.Build();

    ASSERT_LE(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, OvfBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* n = m.Int32AddWithOverflow(m.Int32Constant(imm), m.Parameter(0));
    m.Branch(m.Projection(1, n), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(0));
    m.Bind(&b);
    m.Return(m.Projection(0, n));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    ASSERT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, OvfValMulImmediateOnRight) {
  TRACED_FORRANGE(int32_t, shift, 0, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(0, m.Int32MulWithOverflow(m.Int32Constant(1 << shift),
                                                    m.Parameter(0))));
    Stream s = m.Build();

    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Sbfiz, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Cmp, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(shift, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(32, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

// -----------------------------------------------------------------------------
// Shift instructions.

using InstructionSelectorShiftTest = InstructionSelectorTestWithParam<Shift>;

TEST_P(InstructionSelectorShiftTest, Parameter) {
  const Shift shift = GetParam();
  const MachineType type = shift.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*shift.mi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(shift.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorShiftTest, Immediate) {
  const Shift shift = GetParam();
  const MachineType type = shift.mi.machine_type;
  TRACED_FORRANGE(int32_t, imm, 0,
                  ((1 << ElementSizeLog2Of(type.representation())) * 8) - 1) {
    StreamBuilder m(this, type, type);
    m.Return((m.*shift.mi.constructor)(m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(shift.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorShiftTest,
                         ::testing::ValuesIn(kShiftInstructions));

TEST_F(InstructionSelectorTest, Word64ShlWithChangeInt32ToInt64) {
  TRACED_FORRANGE(int64_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64Shl(m.ChangeInt32ToInt64(p0), m.Int64Constant(x));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Lsl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(x, s.ToInt64(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word64ShlWithChangeUint32ToUint64) {
  TRACED_FORRANGE(int64_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Uint32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64Shl(m.ChangeUint32ToUint64(p0), m.Int64Constant(x));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Lsl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(x, s.ToInt64(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, TruncateInt64ToInt32WithWord64Sar) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  Node* const p = m.Parameter(0);
  Node* const t = m.TruncateInt64ToInt32(m.Word64Sar(p, m.Int64Constant(32)));
  m.Return(t);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Asr, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(32, s.ToInt64(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_F(InstructionSelectorTest, TruncateInt64ToInt32WithWord64Shr) {
  TRACED_FORRANGE(int64_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
    Node* const p = m.Parameter(0);
    Node* const t = m.TruncateInt64ToInt32(m.Word64Shr(p, m.Int64Constant(x)));
    m.Return(t);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Lsr, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(x, s.ToInt64(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

// -----------------------------------------------------------------------------
// Mul and Div instructions.

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

namespace {

struct MulDPInst {
  const char* mul_constructor_name;
  Node* (RawMachineAssembler::*mul_constructor)(Node*, Node*);
  Node* (RawMachineAssembler::*add_constructor)(Node*, Node*);
  Node* (RawMachineAssembler::*sub_constructor)(Node*, Node*);
  ArchOpcode multiply_add_arch_opcode;
  ArchOpcode multiply_sub_arch_opcode;
  ArchOpcode multiply_neg_arch_opcode;
  MachineType machine_type;
};

std::ostream& operator<<(std::ostream& os, const MulDPInst& inst) {
  return os << inst.mul_constructor_name;
}

}  // namespace

static const MulDPInst kMulDPInstructions[] = {
    {"Int32Mul", &RawMachineAssembler::Int32Mul, &RawMachineAssembler::Int32Add,
     &RawMachineAssembler::Int32Sub, kArm64Madd32, kArm64Msub32, kArm64Mneg32,
     MachineType::Int32()},
    {"Int64Mul", &RawMachineAssembler::Int64Mul, &RawMachineAssembler::Int64Add,
     &RawMachineAssembler::Int64Sub, kArm64Madd, kArm64Msub, kArm64Mneg,
     MachineType::Int64()}};

using InstructionSelectorIntDPWithIntMulTest =
    InstructionSelectorTestWithParam<MulDPInst>;

TEST_P(InstructionSelectorIntDPWithIntMulTest, AddWithMul) {
  const MulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type, type);
    Node* n = (m.*mdpi.mul_constructor)(m.Parameter(1), m.Parameter(2));
    m.Return((m.*mdpi.add_constructor)(m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type, type);
    Node* n = (m.*mdpi.mul_constructor)(m.Parameter(0), m.Parameter(1));
    m.Return((m.*mdpi.add_constructor)(n, m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorIntDPWithIntMulTest, SubWithMul) {
  const MulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type, type);
    Node* n = (m.*mdpi.mul_constructor)(m.Parameter(1), m.Parameter(2));
    m.Return((m.*mdpi.sub_constructor)(m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_sub_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorIntDPWithIntMulTest, NegativeMul) {
  const MulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type);
    Node* n =
        (m.*mdpi.sub_constructor)(BuildConstant(&m, type, 0), m.Parameter(0));
    m.Return((m.*mdpi.mul_constructor)(n, m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_neg_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    Node* n =
        (m.*mdpi.sub_constructor)(BuildConstant(&m, type, 0), m.Parameter(1));
    m.Return((m.*mdpi.mul_constructor)(m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_neg_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorIntDPWithIntMulTest,
                         ::testing::ValuesIn(kMulDPInstructions));

#if V8_ENABLE_WEBASSEMBLY
namespace {

struct SIMDMulDPInst {
  const char* mul_constructor_name;
  const Operator* (MachineOperatorBuilder::*mul_operator)(void);
  const Operator* (MachineOperatorBuilder::*add_operator)(void);
  const Operator* (MachineOperatorBuilder::*sub_operator)(void);
  ArchOpcode multiply_add_arch_opcode;
  ArchOpcode multiply_sub_arch_opcode;
  MachineType machine_type;
  const int lane_size;
};

std::ostream& operator<<(std::ostream& os, const SIMDMulDPInst& inst) {
  return os << inst.mul_constructor_name;
}

}  // namespace

static const SIMDMulDPInst kSIMDMulDPInstructions[] = {
    {"I32x4Mul", &MachineOperatorBuilder::I32x4Mul,
     &MachineOperatorBuilder::I32x4Add, &MachineOperatorBuilder::I32x4Sub,
     kArm64Mla, kArm64Mls, MachineType::Simd128(), 32},
    {"I16x8Mul", &MachineOperatorBuilder::I16x8Mul,
     &MachineOperatorBuilder::I16x8Add, &MachineOperatorBuilder::I16x8Sub,
     kArm64Mla, kArm64Mls, MachineType::Simd128(), 16}};

using InstructionSelectorSIMDDPWithSIMDMulTest =
    InstructionSelectorTestWithParam<SIMDMulDPInst>;

TEST_P(InstructionSelectorSIMDDPWithSIMDMulTest, AddWithMul) {
  const SIMDMulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type, type);
    Node* n = m.AddNode((m.machine()->*mdpi.mul_operator)(), m.Parameter(1),
                        m.Parameter(2));
    m.Return(m.AddNode((m.machine()->*mdpi.add_operator)(), m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type, type);
    Node* n = m.AddNode((m.machine()->*mdpi.mul_operator)(), m.Parameter(0),
                        m.Parameter(1));
    m.Return(m.AddNode((m.machine()->*mdpi.add_operator)(), n, m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorSIMDDPWithSIMDMulTest, SubWithMul) {
  const SIMDMulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type, type);
    Node* n = m.AddNode((m.machine()->*mdpi.mul_operator)(), m.Parameter(1),
                        m.Parameter(2));
    m.Return(m.AddNode((m.machine()->*mdpi.sub_operator)(), m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_sub_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDDPWithSIMDMulTest,
                         ::testing::ValuesIn(kSIMDMulDPInstructions));

namespace {

struct SIMDShrAddInst {
  const char* shradd_constructor_name;
  const Operator* (MachineOperatorBuilder::*shr_s_operator)();
  const Operator* (MachineOperatorBuilder::*shr_u_operator)();
  const Operator* (MachineOperatorBuilder::*add_operator)();
  const int laneSize;
};

std::ostream& operator<<(std::ostream& os, const SIMDShrAddInst& inst) {
  return os << inst.shradd_constructor_name;
}

}  // namespace

static const SIMDShrAddInst kSIMDShrAddInstructions[] = {
    {"I64x2ShrAdd", &MachineOperatorBuilder::I64x2ShrS,
     &MachineOperatorBuilder::I64x2ShrU, &MachineOperatorBuilder::I64x2Add, 64},
    {"I32x4ShrAdd", &MachineOperatorBuilder::I32x4ShrS,
     &MachineOperatorBuilder::I32x4ShrU, &MachineOperatorBuilder::I32x4Add, 32},
    {"I16x8ShrAdd", &MachineOperatorBuilder::I16x8ShrS,
     &MachineOperatorBuilder::I16x8ShrU, &MachineOperatorBuilder::I16x8Add, 16},
    {"I8x16ShrAdd", &MachineOperatorBuilder::I8x16ShrS,
     &MachineOperatorBuilder::I8x16ShrU, &MachineOperatorBuilder::I8x16Add, 8}};

using InstructionSelectorSIMDShrAddTest =
    InstructionSelectorTestWithParam<SIMDShrAddInst>;

TEST_P(InstructionSelectorSIMDShrAddTest, ShrAddS) {
  const SIMDShrAddInst param = GetParam();
  const MachineType type = MachineType::Simd128();
  {
    StreamBuilder m(this, type, type, type);
    Node* n = m.AddNode((m.machine()->*param.shr_s_operator)(), m.Parameter(1),
                        m.Int32Constant(1));
    m.Return(
        m.AddNode((m.machine()->*param.add_operator)(), m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ssra, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.laneSize, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    Node* n = m.AddNode((m.machine()->*param.shr_s_operator)(), m.Parameter(0),
                        m.Int32Constant(1));
    m.Return(
        m.AddNode((m.machine()->*param.add_operator)(), n, m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ssra, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.laneSize, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorSIMDShrAddTest, ShrAddU) {
  const SIMDShrAddInst param = GetParam();
  const MachineType type = MachineType::Simd128();
  {
    StreamBuilder m(this, type, type, type);
    Node* n = m.AddNode((m.machine()->*param.shr_u_operator)(), m.Parameter(1),
                        m.Int32Constant(1));
    m.Return(
        m.AddNode((m.machine()->*param.add_operator)(), m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Usra, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.laneSize, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    Node* n = m.AddNode((m.machine()->*param.shr_u_operator)(), m.Parameter(0),
                        m.Int32Constant(1));
    m.Return(
        m.AddNode((m.machine()->*param.add_operator)(), n, m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Usra, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.laneSize, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDShrAddTest,
                         ::testing::ValuesIn(kSIMDShrAddInstructions));

namespace {
struct SIMDAddExtMulInst {
  const char* mul_constructor_name;
  const Operator* (MachineOperatorBuilder::*mul_operator)();
  const Operator* (MachineOperatorBuilder::*add_operator)();
  ArchOpcode multiply_add_arch_opcode;
  MachineType machine_type;
  int lane_size;
};
}  // namespace

static const SIMDAddExtMulInst kSimdAddExtMulInstructions[] = {
    {"I16x8ExtMulLowI8x16S", &MachineOperatorBuilder::I16x8ExtMulLowI8x16S,
     &MachineOperatorBuilder::I16x8Add, kArm64Smlal, MachineType::Simd128(),
     16},
    {"I16x8ExtMulHighI8x16S", &MachineOperatorBuilder::I16x8ExtMulHighI8x16S,
     &MachineOperatorBuilder::I16x8Add, kArm64Smlal2, MachineType::Simd128(),
     16},
    {"I16x8ExtMulLowI8x16U", &MachineOperatorBuilder::I16x8ExtMulLowI8x16U,
     &MachineOperatorBuilder::I16x8Add, kArm64Umlal, MachineType::Simd128(),
     16},
    {"I16x8ExtMulHighI8x16U", &MachineOperatorBuilder::I16x8ExtMulHighI8x16U,
     &MachineOperatorBuilder::I16x8Add, kArm64Umlal2, MachineType::Simd128(),
     16},
    {"I32x4ExtMulLowI16x8S", &MachineOperatorBuilder::I32x4ExtMulLowI16x8S,
     &MachineOperatorBuilder::I32x4Add, kArm64Smlal, MachineType::Simd128(),
     32},
    {"I32x4ExtMulHighI16x8S", &MachineOperatorBuilder::I32x4ExtMulHighI16x8S,
     &MachineOperatorBuilder::I32x4Add, kArm64Smlal2, MachineType::Simd128(),
     32},
    {"I32x4ExtMulLowI16x8U", &MachineOperatorBuilder::I32x4ExtMulLowI16x8U,
     &MachineOperatorBuilder::I32x4Add, kArm64Umlal, MachineType::Simd128(),
     32},
    {"I32x4ExtMulHighI16x8U", &MachineOperatorBuilder::I32x4ExtMulHighI16x8U,
     &MachineOperatorBuilder::I32x4Add, kArm64Umlal2, MachineType::Simd128(),
     32}};

using InstructionSelectorSIMDAddExtMulTest =
    InstructionSelectorTestWithParam<SIMDAddExtMulInst>;

// TODO(zhin): This can be merged with InstructionSelectorSIMDDPWithSIMDMulTest
// once sub+extmul matching is implemented.
TEST_P(InstructionSelectorSIMDAddExtMulTest, AddExtMul) {
  const SIMDAddExtMulInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    // Test Add(x, ExtMul(y, z)).
    StreamBuilder m(this, type, type, type, type);
    Node* n = m.AddNode((m.machine()->*mdpi.mul_operator)(), m.Parameter(1),
                        m.Parameter(2));
    m.Return(m.AddNode((m.machine()->*mdpi.add_operator)(), m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    // Test Add(ExtMul(y, z), x), making sure it's commutative.
    StreamBuilder m(this, type, type, type, type);
    Node* n = m.AddNode((m.machine()->*mdpi.mul_operator)(), m.Parameter(0),
                        m.Parameter(1));
    m.Return(m.AddNode((m.machine()->*mdpi.add_operator)(), n, m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDAddExtMulTest,
                         ::testing::ValuesIn(kSimdAddExtMulInstructions));

struct SIMDMulDupInst {
  const uint8_t shuffle[16];
  int32_t lane;
  int shuffle_input_index;
};

const SIMDMulDupInst kSIMDF32x4MulDuplInstructions[] = {
    {
        {0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3},
        0,
        0,
    },
    {
        {4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7},
        1,
        0,
    },
    {
        {8, 9, 10, 11, 8, 9, 10, 11, 8, 9, 10, 11, 8, 9, 10, 11},
        2,
        0,
    },
    {
        {12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15},
        3,
        0,
    },
    {
        {16, 17, 18, 19, 16, 17, 18, 19, 16, 17, 18, 19, 16, 17, 18, 19},
        0,
        1,
    },
    {
        {20, 21, 22, 23, 20, 21, 22, 23, 20, 21, 22, 23, 20, 21, 22, 23},
        1,
        1,
    },
    {
        {24, 25, 26, 27, 24, 25, 26, 27, 24, 25, 26, 27, 24, 25, 26, 27},
        2,
        1,
    },
    {
        {28, 29, 30, 31, 28, 29, 30, 31, 28, 29, 30, 31, 28, 29, 30, 31},
        3,
        1,
    },
};

using InstructionSelectorSimdF32x4MulWithDupTest =
    InstructionSelectorTestWithParam<SIMDMulDupInst>;

TEST_P(InstructionSelectorSimdF32x4MulWithDupTest, MulWithDup) {
  const SIMDMulDupInst param = GetParam();
  const MachineType type = MachineType::Simd128();
  {
    StreamBuilder m(this, type, type, type, type);
    Node* shuffle = m.AddNode(m.machine()->I8x16Shuffle(param.shuffle),
                              m.Parameter(0), m.Parameter(1));
    m.Return(m.AddNode(m.machine()->F32x4Mul(), m.Parameter(2), shuffle));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64FMulElement, s[0]->arch_opcode());
    EXPECT_EQ(32, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.lane, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(m.Parameter(param.shuffle_input_index)),
              s.ToVreg(s[0]->InputAt(1)));
  }

  // Multiplication operator should be commutative, so test shuffle op as lhs.
  {
    StreamBuilder m(this, type, type, type, type);
    Node* shuffle = m.AddNode(m.machine()->I8x16Shuffle(param.shuffle),
                              m.Parameter(0), m.Parameter(1));
    m.Return(m.AddNode(m.machine()->F32x4Mul(), shuffle, m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64FMulElement, s[0]->arch_opcode());
    EXPECT_EQ(32, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.lane, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(m.Parameter(param.shuffle_input_index)),
              s.ToVreg(s[0]->InputAt(1)));
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSimdF32x4MulWithDupTest,
                         ::testing::ValuesIn(kSIMDF32x4MulDuplInstructions));

TEST_F(InstructionSelectorTest, SimdF32x4MulWithDupNegativeTest) {
  const MachineType type = MachineType::Simd128();
  // Check that optimization does not match when the shuffle is not a f32x4.dup.
  const uint8_t mask[kSimd128Size] = {0};
  {
    StreamBuilder m(this, type, type, type, type);
    Node* shuffle = m.AddNode((m.machine()->I8x16Shuffle(mask)), m.Parameter(0),
                              m.Parameter(1));
    m.Return(m.AddNode(m.machine()->F32x4Mul(), m.Parameter(2), shuffle));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    // The shuffle is an i8x16.dup of lane 0.
    EXPECT_EQ(kArm64S128Dup, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kArm64FMul, s[1]->arch_opcode());
    EXPECT_EQ(32, LaneSizeField::decode(s[1]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

const SIMDMulDupInst kSIMDF64x2MulDuplInstructions[] = {
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
        0,
        0,
    },
    {
        {8, 9, 10, 11, 12, 13, 14, 15, 8, 9, 10, 11, 12, 13, 14, 15},
        1,
        0,
    },
    {
        {16, 17, 18, 19, 20, 21, 22, 23, 16, 17, 18, 19, 20, 21, 22, 23},
        0,
        1,
    },
    {
        {24, 25, 26, 27, 28, 29, 30, 31, 24, 25, 26, 27, 28, 29, 30, 31},
        1,
        1,
    },
};

using InstructionSelectorSimdF64x2MulWithDupTest =
    InstructionSelectorTestWithParam<SIMDMulDupInst>;

TEST_P(InstructionSelectorSimdF64x2MulWithDupTest, MulWithDup) {
  const SIMDMulDupInst param = GetParam();
  const MachineType type = MachineType::Simd128();
  {
    StreamBuilder m(this, type, type, type, type);
    Node* shuffle = m.AddNode(m.machine()->I8x16Shuffle(param.shuffle),
                              m.Parameter(0), m.Parameter(1));
    m.Return(m.AddNode(m.machine()->F64x2Mul(), m.Parameter(2), shuffle));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64FMulElement, s[0]->arch_opcode());
    EXPECT_EQ(64, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.lane, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(m.Parameter(param.shuffle_input_index)),
              s.ToVreg(s[0]->InputAt(1)));
  }

  // Multiplication operator should be commutative, so test shuffle op as lhs.
  {
    StreamBuilder m(this, type, type, type, type);
    Node* shuffle = m.AddNode(m.machine()->I8x16Shuffle(param.shuffle),
                              m.Parameter(0), m.Parameter(1));
    m.Return(m.AddNode(m.machine()->F64x2Mul(), shuffle, m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64FMulElement, s[0]->arch_opcode());
    EXPECT_EQ(64, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.lane, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(m.Parameter(param.shuffle_input_index)),
              s.ToVreg(s[0]->InputAt(1)));
  }
}

TEST_F(InstructionSelectorTest, ReverseShuffle32x4Test) {
  const MachineType type = MachineType::Simd128();
  {
    const uint8_t shuffle[] = {12, 13, 14, 15, 8, 9, 10, 11,
                               4,  5,  6,  7,  0, 1, 2,  3};
    StreamBuilder m(this, type, type, type);
    m.Return(m.AddNode(m.machine()->I8x16Shuffle(shuffle), m.Parameter(0),
                       m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64S32x4Reverse, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    const uint8_t shuffle[] = {28, 29, 30, 31, 24, 25, 26, 27,
                               20, 21, 22, 23, 16, 17, 18, 19};
    StreamBuilder m(this, type, type, type);
    m.Return(m.AddNode(m.machine()->I8x16Shuffle(shuffle), m.Parameter(0),
                       m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64S32x4Reverse, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSimdF64x2MulWithDupTest,
                         ::testing::ValuesIn(kSIMDF64x2MulDuplInstructions));

TEST_F(InstructionSelectorTest, SimdF64x2MulWithDupNegativeTest) {
  const MachineType type = MachineType::Simd128();
  // Check that optimization does not match when the shuffle is not a f64x2.dup.
  const uint8_t mask[kSimd128Size] = {0};
  {
    StreamBuilder m(this, type, type, type, type);
    Node* shuffle = m.AddNode((m.machine()->I8x16Shuffle(mask)), m.Parameter(0),
                              m.Parameter(1));
    m.Return(m.AddNode(m.machine()->F64x2Mul(), m.Parameter(2), shuffle));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    // The shuffle is an i8x16.dup of lane 0.
    EXPECT_EQ(kArm64S128Dup, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kArm64FMul, s[1]->arch_opcode());
    EXPECT_EQ(64, LaneSizeField::decode(s[1]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, OneLaneSwizzle32x4Test) {
  const MachineType type = MachineType::Simd128();
  {
    const uint8_t shuffle[] = {0, 1, 2, 3, 4,  5,  6,  7,
                               4, 5, 6, 7, 12, 13, 14, 15};
    StreamBuilder m(this, type, type, type, type);
    m.Return(m.AddNode(m.machine()->I8x16Shuffle(shuffle), m.Parameter(0),
                       m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64S32x4OneLaneSwizzle, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    const uint8_t shuffle[] = {16, 17, 18, 19, 20, 21, 22, 23,
                               24, 25, 26, 27, 16, 17, 18, 19};
    StreamBuilder m(this, type, type, type, type);
    m.Return(m.AddNode(m.machine()->I8x16Shuffle(shuffle), m.Parameter(0),
                       m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64S32x4OneLaneSwizzle, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

TEST_F(InstructionSelectorTest, Int32MulWithImmediate) {
  // x * (2^k + 1) -> x + (x << k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Parameter(0), m.Int32Constant((1 << k) + 1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // (2^k + 1) * x -> x + (x << k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // x * (2^k + 1) + c -> x + (x << k) + c
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Add(m.Int32Mul(m.Parameter(0), m.Int32Constant((1 << k) + 1)),
                   m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Add32, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // (2^k + 1) * x + c -> x + (x << k) + c
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Add(m.Int32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(0)),
                   m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Add32, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // c + x * (2^k + 1) -> c + x + (x << k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Add(m.Parameter(0),
                   m.Int32Mul(m.Parameter(1), m.Int32Constant((1 << k) + 1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Add32, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // c + (2^k + 1) * x -> c + x + (x << k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Add(m.Parameter(0),
                   m.Int32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Add32, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // c - x * (2^k + 1) -> c - x + (x << k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Sub(m.Parameter(0),
                   m.Int32Mul(m.Parameter(1), m.Int32Constant((1 << k) + 1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Sub32, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // c - (2^k + 1) * x -> c - x + (x << k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Sub(m.Parameter(0),
                   m.Int32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Sub32, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, Int64MulWithImmediate) {
  // x * (2^k + 1) -> x + (x << k)
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(
        m.Int64Mul(m.Parameter(0), m.Int64Constant((int64_t{1} << k) + 1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // (2^k + 1) * x -> x + (x << k)
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(
        m.Int64Mul(m.Int64Constant((int64_t{1} << k) + 1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // x * (2^k + 1) + c -> x + (x << k) + c
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64());
    m.Return(m.Int64Add(
        m.Int64Mul(m.Parameter(0), m.Int64Constant((int64_t{1} << k) + 1)),
        m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Add, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // (2^k + 1) * x + c -> x + (x << k) + c
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64());
    m.Return(m.Int64Add(
        m.Int64Mul(m.Int64Constant((int64_t{1} << k) + 1), m.Parameter(0)),
        m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Add, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // c + x * (2^k + 1) -> c + x + (x << k)
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64());
    m.Return(m.Int64Add(
        m.Parameter(0),
        m.Int64Mul(m.Parameter(1), m.Int64Constant((int64_t{1} << k) + 1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Add, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // c + (2^k + 1) * x -> c + x + (x << k)
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64());
    m.Return(m.Int64Add(
        m.Parameter(0),
        m.Int64Mul(m.Int64Constant((int64_t{1} << k) + 1), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Add, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // c - x * (2^k + 1) -> c - x + (x << k)
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64());
    m.Return(m.Int64Sub(
        m.Parameter(0),
        m.Int64Mul(m.Parameter(1), m.Int64Constant((int64_t{1} << k) + 1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Sub, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // c - (2^k + 1) * x -> c - x + (x << k)
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64());
    m.Return(m.Int64Sub(
        m.Parameter(0),
        m.Int64Mul(m.Int64Constant((int64_t{1} << k) + 1), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kArm64Sub, s[1]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

// -----------------------------------------------------------------------------
// Floating point instructions.

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

TEST_P(InstructionSelectorFPCmpTest, WithImmediateZeroOnRight) {
  const FPCmp cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), cmp.mi.machine_type);
  if (cmp.mi.machine_type == MachineType::Float64()) {
    m.Return((m.*cmp.mi.constructor)(m.Parameter(0), m.Float64Constant(0.0)));
  } else {
    m.Return((m.*cmp.mi.constructor)(m.Parameter(0), m.Float32Constant(0.0f)));
  }
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.cond, s[0]->flags_condition());
}

TEST_P(InstructionSelectorFPCmpTest, WithImmediateZeroOnLeft) {
  const FPCmp cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), cmp.mi.machine_type);
  if (cmp.mi.machine_type == MachineType::Float64()) {
    m.Return((m.*cmp.mi.constructor)(m.Float64Constant(0.0), m.Parameter(0)));
  } else {
    m.Return((m.*cmp.mi.constructor)(m.Float32Constant(0.0f), m.Parameter(0)));
  }
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.commuted_cond, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorFPCmpTest,
                         ::testing::ValuesIn(kFPCmpInstructions));

TEST_F(InstructionSelectorTest, Float32SelectWithRegisters) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Float32Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(InstructionSelectorTest, Float32SelectWithZero) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Float32Select(cond, m.Parameter(0), m.Float32Constant(0.0f)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE(s[0]->InputAt(3)->IsImmediate());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(InstructionSelectorTest, Float64SelectWithRegisters) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Float64Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(InstructionSelectorTest, Float64SelectWithZero) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Float64Select(cond, m.Parameter(0), m.Float64Constant(0.0f)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE(s[0]->InputAt(3)->IsImmediate());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(InstructionSelectorTest, Word32SelectWithRegisters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Word32Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(InstructionSelectorTest, Word32SelectWithZero) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Word32Select(cond, m.Parameter(0), m.Int32Constant(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE(s[0]->InputAt(3)->IsImmediate());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(InstructionSelectorTest, Word64SelectWithRegisters) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Word64Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(InstructionSelectorTest, Word64SelectWithZero) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
  Node* cond = m.Int32Constant(1);
  m.Return(m.Word64Select(cond, m.Parameter(0), m.Int64Constant(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE(s[0]->InputAt(3)->IsImmediate());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

// -----------------------------------------------------------------------------
// Conversions.

using InstructionSelectorConversionTest =
    InstructionSelectorTestWithParam<Conversion>;

TEST_P(InstructionSelectorConversionTest, Parameter) {
  const Conversion conv = GetParam();
  StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
  m.Return((m.*conv.mi.constructor)(m.Parameter(0)));
  Stream s = m.Build();
  if (conv.mi.arch_opcode == kArchNop) {
    ASSERT_EQ(0U, s.size());
    return;
  }
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorConversionTest,
                         ::testing::ValuesIn(kConversionInstructions));

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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorElidedChangeUint32ToUint64Test,
                         ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

TEST_F(InstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // Ldrb
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // Ldrh
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrh, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // LdrW
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64LdrW, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ChangeInt32ToInt64AfterLoad) {
  // For each case, test that the conversion is merged into the load
  // operation.
  // ChangeInt32ToInt64(Load_Uint8) -> Ldrb
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int8) -> Ldrsb
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrsb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint16) -> Ldrh
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrh, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int16) -> Ldrsh
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrsh, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint32) -> Ldrsw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrsw, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int32) -> Ldrsw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrsw, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ChangeInt32ToInt64WithWord32Sar) {
  // Test the mod 32 behaviour of Word32Sar by iterating up to 33.
  TRACED_FORRANGE(int32_t, imm, 0, 33) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Word32Sar(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sbfx, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(imm & 0x1f, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(32 - (imm & 0x1f), s.ToInt32(s[0]->InputAt(2)));
  }
}

TEST_F(InstructionSelectorTest, Word64SarWithChangeInt32ToInt64) {
  TRACED_FORRANGE(int64_t, imm, -31, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Sar(m.ChangeInt32ToInt64(m.Parameter(0)),
                         m.Int64Constant(imm)));
    Stream s = m.Build();
    // Optimization should only be applied when 0 <= imm < 32
    if (0 <= imm && imm < 32) {
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Sbfx, s[0]->arch_opcode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(32 - imm, s.ToInt64(s[0]->InputAt(2)));
    } else {
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kArm64Sxtw, s[0]->arch_opcode());
      EXPECT_EQ(1U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(kArm64Asr, s[1]->arch_opcode());
      EXPECT_EQ(2U, s[1]->InputCount());
      EXPECT_EQ(1U, s[1]->OutputCount());
      EXPECT_EQ(imm, s.ToInt64(s[1]->InputAt(1)));
    }
  }
}

// -----------------------------------------------------------------------------
// Memory access instructions.

namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode ldr_opcode;
  ArchOpcode str_opcode;
  const int32_t immediates[20];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccess& memacc) {
  return os << memacc.type;
}

}  // namespace

static const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(),
     kArm64LdrsbW,
     kArm64Strb,
     {-256, -255, -3,  -2,   -1,   0,    1,    2,    3,    255,
      256,  257,  258, 1000, 1001, 2121, 2442, 4093,
```