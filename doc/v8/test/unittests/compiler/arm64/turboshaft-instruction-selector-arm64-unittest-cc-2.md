Response:
The user wants to understand the functionality of a C++ source code file for V8's Turboshaft instruction selector on the ARM64 architecture.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The file name `turboshaft-instruction-selector-arm64-unittest.cc` strongly suggests this file contains unit tests for the Turboshaft instruction selector for ARM64. Instruction selectors are responsible for translating high-level intermediate representations (IR) of code into low-level machine instructions for a specific architecture.

2. **Analyze the Code Structure:** The code is organized into `TEST_F` and `TEST_P` macros, which are common in Google Test (gtest) frameworks. These indicate individual test cases. Each test case typically sets up some input (using `StreamBuilder`), performs an action (generating instructions), and then asserts the expected output (using `EXPECT_EQ`, `ASSERT_EQ`, etc.).

3. **Examine Individual Test Cases (High-Level):**  Read through the test names and the operations performed within each test. Look for patterns and recurring themes:
    * Comparisons (`Word64Equal`, `Int64LessThan`, `Branch`) and their corresponding ARM64 instructions (`kArm64Cmp`, `kArm64Cmp32`).
    * Arithmetic operations with overflow checks (`Int32AddCheckOverflow`) and their corresponding instructions with flag setting.
    * Shift operations (`Word64ShiftLeft`, `Word64ShiftRightArithmetic`) and their ARM64 equivalents (`kArm64Lsl`, `kArm64Asr`).
    * Multiplication and division operations and the use of fused multiply-add/subtract instructions (`kArm64Madd`, `kArm64Msub`).
    * SIMD (Single Instruction, Multiple Data) operations (prefixed with `I` or `F` and often involving `Simd128`) and their specific ARM64 SIMD instructions.

4. **Categorize the Functionality:** Based on the examined test cases, group the functionalities:
    * **Comparison Instructions:** Tests how different comparison operations are translated to ARM64 compare instructions.
    * **Arithmetic Instructions with Overflow:**  Focuses on addition, subtraction, and multiplication with overflow detection and the corresponding flag settings.
    * **Shift Instructions:**  Covers various shift operations (left, right logical, right arithmetic) and their immediate and register operands.
    * **Multiplication and Division Instructions:** Tests the selection of basic multiplication and division instructions.
    * **Fused Multiply-Add/Subtract Instructions:**  Specifically checks if the instruction selector correctly combines multiplication with addition or subtraction into a single instruction for efficiency.
    * **SIMD Instructions:**  A large section dedicated to testing the selection of various SIMD instructions for different data types (integers and floats) and operations (addition, multiplication, shifts, reductions, etc.).

5. **Address Specific Instructions:** The prompt asks about `.tq` files and JavaScript relevance.
    * **`.tq` files:** The provided code is C++, not Torque, so this part of the condition is false.
    * **JavaScript relevance:**  While this is a low-level compiler test, it's fundamentally linked to JavaScript because V8 is the JavaScript engine. The compiler's job is to efficiently execute JavaScript code.

6. **Provide Examples:**  The prompt requests JavaScript examples. For each functional category, create simple JavaScript snippets that would trigger the corresponding IR and eventually the tested ARM64 instructions. Keep these examples concise and illustrative.

7. **Address Code Logic and Assumptions:**
    * **Assumptions:** Note the key assumption that the input to the instruction selector is a valid Turboshaft IR.
    * **Logic:**  For a specific test case (like the comparison example), simulate a possible input and the expected output instruction.

8. **Discuss Common Programming Errors:**  Relate the tested functionalities to common programming errors in JavaScript:
    * Incorrect comparisons leading to bugs.
    * Integer overflows causing unexpected behavior.
    * Incorrect bitwise operations.
    * Performance issues due to inefficient code patterns (which the instruction selector helps optimize).

9. **Summarize the Functionality (for Part 3):** Concisely summarize the functionalities covered in the provided code snippet (which is part 3 of 8). Focus on the key areas like comparisons, overflow checks, and basic arithmetic.

10. **Review and Refine:**  Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or missing information. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. For example, explain what "instruction selector" means in this context.
```cpp
.Word64Equal(m.Parameter(0), m.Parameter(2));
    OpIndex c = m.Word64NotEqual(m.Parameter(0), m.Int64Constant(42));
    m.Return(m.Word32BitwiseOr(m.Word32BitwiseOr(a, b), c));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_conditional_set, s[0]->flags_mode());
    EXPECT_EQ(14U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex a = m.Word64Equal(m.Parameter(0), m.Int64Constant(30));
    OpIndex b = m.Word64Equal(m.Parameter(0), m.Int64Constant(50));
    OpIndex c = m.Uint64LessThanOrEqual(m.Parameter(0), m.Parameter(1));
    OpIndex d = m.Int64LessThan(m.Parameter(0), m.Parameter(2));
    m.Return(
        m.Word32BitwiseAnd(m.Word32BitwiseAnd(m.Word32BitwiseOr(a, b), c), d));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(50, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_conditional_set, s[0]->flags_mode());
    EXPECT_EQ(19U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex cond_a = m.Int64LessThan(m.Parameter(0), m.Parameter(1));
    OpIndex cond_b = m.Int64LessThan(m.Parameter(0), m.Parameter(2));
    m.Branch(m.Word32BitwiseAnd(cond_a, cond_b), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_conditional_branch, s[0]->flags_mode());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex cond_a = m.Int32LessThan(m.Parameter(0), m.Parameter(1));
    OpIndex cond_b = m.Int32LessThan(m.Parameter(0), m.Parameter(2));
    m.Branch(m.Word32BitwiseOr(cond_a, cond_b), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_conditional_branch, s[0]->flags_mode());
  }
}

// -----------------------------------------------------------------------------
// Add and subtract instructions with overflow.

using TurboshaftInstructionSelectorOvfAddSubTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, OvfParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Projection(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)), 1));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, OvfImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    OpIndex cst = dpi.machine_type == MachineType::Int32()
                      ? OpIndex{m.Int32Constant(imm)}
                      : OpIndex{m.Int64Constant(imm)};
    m.Return(m.Projection(m.Emit(dpi.op, m.Parameter(0), cst), 1));
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

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, ValParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Projection(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)), 0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, ValImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    OpIndex cst = dpi.machine_type == MachineType::Int32()
                      ? OpIndex{m.Int32Constant(imm)}
                      : OpIndex{m.Int64Constant(imm)};
    m.Return(m.Projection(m.Emit(dpi.op, m.Parameter(0), cst), 0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, BothParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  OpIndex n = m.Emit(dpi.op, m.Parameter(0), m.Parameter(1));
  OpIndex proj0 = type == MachineType::Int64()
                      ? m.TruncateWord64ToWord32(m.Projection(n, 0))
                      : m.Projection(n, 0);
  m.Return(m.Word32Equal(proj0, m.Projection(n, 1)));
  Stream s = m.Build();
  ASSERT_LE(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(2U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, BothImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    OpIndex cst = dpi.machine_type == MachineType::Int32()
                      ? OpIndex{m.Int32Constant(imm)}
                      : OpIndex{m.Int64Constant(imm)};
    OpIndex n = m.Emit(dpi.op, m.Parameter(0), cst);
    OpIndex proj0 = type == MachineType::Int64()
                        ? m.TruncateWord64ToWord32(m.Projection(n, 0))
                        : m.Projection(n, 0);
    m.Return(m.Word32Equal(proj0, m.Projection(n, 1)));
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

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, BranchWithParameters) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  Block *a = m.NewBlock(), *b = m.NewBlock();
  OpIndex n = m.Emit(dpi.op, m.Parameter(0), m.Parameter(1));
  m.Branch(V<Word32>::Cast(m.Projection(n, 1)), a, b);
  m.Bind(a);
  m.Return(m.Int32Constant(0));
  m.Bind(b);
  m.Return(m.Projection(n, 0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, BranchWithImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex cst = dpi.machine_type == MachineType::Int32()
                      ? OpIndex{m.Int32Constant(imm)}
                      : OpIndex{m.Int64Constant(imm)};
    OpIndex n = m.Emit(dpi.op, m.Parameter(0), cst);
    m.Branch(V<Word32>::Cast(m.Projection(n, 1)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(0));
    m.Bind(b);
    m.Return(m.Projection(n, 0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, RORShift) {
  // ADD and SUB do not support ROR shifts, make sure we do not try
  // to merge them into the ADD/SUB instruction.
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  auto rotate = TSBinop::kWord64RotateRight;
  ArchOpcode rotate_opcode = kArm64Ror;
  if (type == MachineType::Int32()) {
    rotate = TSBinop::kWord32RotateRight;
    rotate_opcode = kArm64Ror32;
  }
  TRACED_FORRANGE(int32_t, imm, -32, 63) {
    StreamBuilder m(this, type, type, type);
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Emit(rotate, p1, m.Int32Constant(imm));
    m.Return(m.Projection(m.Emit(dpi.op, p0, r), 0));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(rotate_opcode, s[0]->arch_opcode());
    EXPECT_EQ(dpi.arch_opcode, s[1]->arch_opcode());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorOvfAddSubTest,
                         ::testing::ValuesIn(kOvfAddSubInstructions));

TEST_F(TurboshaftInstructionSelectorTest, OvfFlagAddImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        m.Int32AddCheckOverflow(m.Parameter(0), m.Int32Constant(imm)), 1));
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

TEST_F(TurboshaftInstructionSelectorTest, OvfValAddImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        m.Int32AddCheckOverflow(m.Parameter(0), m.Int32Constant(imm)), 0));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, OvfBothAddImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex n = m.Int32AddCheckOverflow(m.Parameter(0), m.Int32Constant(imm));
    m.Return(m.Word32Equal(m.Projection(n, 0), m.Projection(n, 1)));
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

TEST_F(TurboshaftInstructionSelectorTest, OvfBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex n = m.Int32AddCheckOverflow(m.Parameter(0), m.Int32Constant(imm));
    m.Branch(V<Word32>::Cast(m.Projection(n, 1)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(0));
    m.Bind(b);
    m.Return(m.Projection(n, 0));
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

TEST_F(TurboshaftInstructionSelectorTest, OvfValMulImmediateOnRight) {
  TRACED_FORRANGE(int32_t, shift, 0, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        m.Int32MulCheckOverflow(m.Parameter(0), m.Int32Constant(1 << shift)),
        0));
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

using TurboshaftInstructionSelectorShiftTest =
    TurboshaftInstructionSelectorTestWithParam<Shift>;

TEST_P(TurboshaftInstructionSelectorShiftTest, Parameter) {
  const Shift shift = GetParam();
  const MachineType type = shift.mi.machine_type;
  StreamBuilder m(this, type, type, MachineType::Int32());
  m.Return(m.Emit(shift.mi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(shift.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorShiftTest, Immediate) {
  const Shift shift = GetParam();
  const MachineType type = shift.mi.machine_type;
  TRACED_FORRANGE(int32_t, imm, 0,
                  ((1 << ElementSizeLog2Of(type.representation())) * 8) - 1) {
    StreamBuilder m(this, type, type);
    m.Return(m.Emit(shift.mi.op, m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(shift.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorShiftTest,
                         ::testing::ValuesIn(kShiftInstructions));

TEST_F(TurboshaftInstructionSelectorTest, Word64ShlWithChangeInt32ToInt64) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n =
        m.Word64ShiftLeft(m.ChangeInt32ToInt64(p0), m.Int32Constant(x));
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

TEST_F(TurboshaftInstructionSelectorTest, Word64ShlWithChangeUint32ToUint64) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Uint32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n =
        m.Word64ShiftLeft(m.ChangeUint32ToUint64(p0), m.Int32Constant(x));
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

TEST_F(TurboshaftInstructionSelectorTest, TruncateWord64ToWord32WithWord64Sar) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  OpIndex const p = m.Parameter(0);
  OpIndex const t = m.TruncateWord64ToWord32(
      m.Word64ShiftRightArithmetic(p, m.Int32Constant(32)));
  m.Return(t);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Asr, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(32, s.ToInt64(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_F(TurboshaftInstructionSelectorTest,
       TruncateWord64ToWord32WithWord64ShiftRightLogical) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
    OpIndex const p = m.Parameter(0);
    OpIndex const t = m.TruncateWord64ToWord32(
        m.Word64ShiftRightLogical(p, m.Int32Constant(x)));
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

using TurboshaftInstructionSelectorMulDivTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorMulDivTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMulDivTest,
                         ::testing::ValuesIn(kMulDivInstructions));

namespace {

struct MulDPInst {
  const char* mul_constructor_name;
  TSBinop mul_op;
  TSBinop add_op;
  TSBinop sub_op;
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
    {"Word32Mul", TSBinop::kWord32Mul, TSBinop::kWord32Add, TSBinop::kWord32Sub,
     kArm64Madd32, kArm64Msub32, kArm64Mneg32, MachineType::Int32()},
    {"Word64Mul", TSBinop::kWord64Mul, TSBinop::kWord64Add, TSBinop::kWord64Sub,
     kArm64Madd, kArm64Msub, kArm64Mneg, MachineType::Int64()}};

using TurboshaftInstructionSelectorIntDPWithIntMulTest =
    
### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
.Word64Equal(m.Parameter(0), m.Parameter(2));
    OpIndex c = m.Word64NotEqual(m.Parameter(0), m.Int64Constant(42));
    m.Return(m.Word32BitwiseOr(m.Word32BitwiseOr(a, b), c));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_conditional_set, s[0]->flags_mode());
    EXPECT_EQ(14U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex a = m.Word64Equal(m.Parameter(0), m.Int64Constant(30));
    OpIndex b = m.Word64Equal(m.Parameter(0), m.Int64Constant(50));
    OpIndex c = m.Uint64LessThanOrEqual(m.Parameter(0), m.Parameter(1));
    OpIndex d = m.Int64LessThan(m.Parameter(0), m.Parameter(2));
    m.Return(
        m.Word32BitwiseAnd(m.Word32BitwiseAnd(m.Word32BitwiseOr(a, b), c), d));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(50, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_conditional_set, s[0]->flags_mode());
    EXPECT_EQ(19U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex cond_a = m.Int64LessThan(m.Parameter(0), m.Parameter(1));
    OpIndex cond_b = m.Int64LessThan(m.Parameter(0), m.Parameter(2));
    m.Branch(m.Word32BitwiseAnd(cond_a, cond_b), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_conditional_branch, s[0]->flags_mode());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex cond_a = m.Int32LessThan(m.Parameter(0), m.Parameter(1));
    OpIndex cond_b = m.Int32LessThan(m.Parameter(0), m.Parameter(2));
    m.Branch(m.Word32BitwiseOr(cond_a, cond_b), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_conditional_branch, s[0]->flags_mode());
  }
}

// -----------------------------------------------------------------------------
// Add and subtract instructions with overflow.

using TurboshaftInstructionSelectorOvfAddSubTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, OvfParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Projection(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)), 1));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, OvfImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    OpIndex cst = dpi.machine_type == MachineType::Int32()
                      ? OpIndex{m.Int32Constant(imm)}
                      : OpIndex{m.Int64Constant(imm)};
    m.Return(m.Projection(m.Emit(dpi.op, m.Parameter(0), cst), 1));
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

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, ValParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Projection(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)), 0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, ValImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    OpIndex cst = dpi.machine_type == MachineType::Int32()
                      ? OpIndex{m.Int32Constant(imm)}
                      : OpIndex{m.Int64Constant(imm)};
    m.Return(m.Projection(m.Emit(dpi.op, m.Parameter(0), cst), 0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, BothParameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  OpIndex n = m.Emit(dpi.op, m.Parameter(0), m.Parameter(1));
  OpIndex proj0 = type == MachineType::Int64()
                      ? m.TruncateWord64ToWord32(m.Projection(n, 0))
                      : m.Projection(n, 0);
  m.Return(m.Word32Equal(proj0, m.Projection(n, 1)));
  Stream s = m.Build();
  ASSERT_LE(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(2U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, BothImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    OpIndex cst = dpi.machine_type == MachineType::Int32()
                      ? OpIndex{m.Int32Constant(imm)}
                      : OpIndex{m.Int64Constant(imm)};
    OpIndex n = m.Emit(dpi.op, m.Parameter(0), cst);
    OpIndex proj0 = type == MachineType::Int64()
                        ? m.TruncateWord64ToWord32(m.Projection(n, 0))
                        : m.Projection(n, 0);
    m.Return(m.Word32Equal(proj0, m.Projection(n, 1)));
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

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, BranchWithParameters) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  Block *a = m.NewBlock(), *b = m.NewBlock();
  OpIndex n = m.Emit(dpi.op, m.Parameter(0), m.Parameter(1));
  m.Branch(V<Word32>::Cast(m.Projection(n, 1)), a, b);
  m.Bind(a);
  m.Return(m.Int32Constant(0));
  m.Bind(b);
  m.Return(m.Projection(n, 0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, BranchWithImmediateOnRight) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex cst = dpi.machine_type == MachineType::Int32()
                      ? OpIndex{m.Int32Constant(imm)}
                      : OpIndex{m.Int64Constant(imm)};
    OpIndex n = m.Emit(dpi.op, m.Parameter(0), cst);
    m.Branch(V<Word32>::Cast(m.Projection(n, 1)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(0));
    m.Bind(b);
    m.Return(m.Projection(n, 0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}

TEST_P(TurboshaftInstructionSelectorOvfAddSubTest, RORShift) {
  // ADD and SUB do not support ROR shifts, make sure we do not try
  // to merge them into the ADD/SUB instruction.
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  auto rotate = TSBinop::kWord64RotateRight;
  ArchOpcode rotate_opcode = kArm64Ror;
  if (type == MachineType::Int32()) {
    rotate = TSBinop::kWord32RotateRight;
    rotate_opcode = kArm64Ror32;
  }
  TRACED_FORRANGE(int32_t, imm, -32, 63) {
    StreamBuilder m(this, type, type, type);
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Emit(rotate, p1, m.Int32Constant(imm));
    m.Return(m.Projection(m.Emit(dpi.op, p0, r), 0));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(rotate_opcode, s[0]->arch_opcode());
    EXPECT_EQ(dpi.arch_opcode, s[1]->arch_opcode());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorOvfAddSubTest,
                         ::testing::ValuesIn(kOvfAddSubInstructions));

TEST_F(TurboshaftInstructionSelectorTest, OvfFlagAddImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        m.Int32AddCheckOverflow(m.Parameter(0), m.Int32Constant(imm)), 1));
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

TEST_F(TurboshaftInstructionSelectorTest, OvfValAddImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        m.Int32AddCheckOverflow(m.Parameter(0), m.Int32Constant(imm)), 0));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, OvfBothAddImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex n = m.Int32AddCheckOverflow(m.Parameter(0), m.Int32Constant(imm));
    m.Return(m.Word32Equal(m.Projection(n, 0), m.Projection(n, 1)));
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

TEST_F(TurboshaftInstructionSelectorTest, OvfBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex n = m.Int32AddCheckOverflow(m.Parameter(0), m.Int32Constant(imm));
    m.Branch(V<Word32>::Cast(m.Projection(n, 1)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(0));
    m.Bind(b);
    m.Return(m.Projection(n, 0));
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

TEST_F(TurboshaftInstructionSelectorTest, OvfValMulImmediateOnRight) {
  TRACED_FORRANGE(int32_t, shift, 0, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        m.Int32MulCheckOverflow(m.Parameter(0), m.Int32Constant(1 << shift)),
        0));
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

using TurboshaftInstructionSelectorShiftTest =
    TurboshaftInstructionSelectorTestWithParam<Shift>;

TEST_P(TurboshaftInstructionSelectorShiftTest, Parameter) {
  const Shift shift = GetParam();
  const MachineType type = shift.mi.machine_type;
  StreamBuilder m(this, type, type, MachineType::Int32());
  m.Return(m.Emit(shift.mi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(shift.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorShiftTest, Immediate) {
  const Shift shift = GetParam();
  const MachineType type = shift.mi.machine_type;
  TRACED_FORRANGE(int32_t, imm, 0,
                  ((1 << ElementSizeLog2Of(type.representation())) * 8) - 1) {
    StreamBuilder m(this, type, type);
    m.Return(m.Emit(shift.mi.op, m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(shift.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorShiftTest,
                         ::testing::ValuesIn(kShiftInstructions));

TEST_F(TurboshaftInstructionSelectorTest, Word64ShlWithChangeInt32ToInt64) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n =
        m.Word64ShiftLeft(m.ChangeInt32ToInt64(p0), m.Int32Constant(x));
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

TEST_F(TurboshaftInstructionSelectorTest, Word64ShlWithChangeUint32ToUint64) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Uint32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n =
        m.Word64ShiftLeft(m.ChangeUint32ToUint64(p0), m.Int32Constant(x));
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

TEST_F(TurboshaftInstructionSelectorTest, TruncateWord64ToWord32WithWord64Sar) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
  OpIndex const p = m.Parameter(0);
  OpIndex const t = m.TruncateWord64ToWord32(
      m.Word64ShiftRightArithmetic(p, m.Int32Constant(32)));
  m.Return(t);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Asr, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(32, s.ToInt64(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_F(TurboshaftInstructionSelectorTest,
       TruncateWord64ToWord32WithWord64ShiftRightLogical) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64());
    OpIndex const p = m.Parameter(0);
    OpIndex const t = m.TruncateWord64ToWord32(
        m.Word64ShiftRightLogical(p, m.Int32Constant(x)));
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

using TurboshaftInstructionSelectorMulDivTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorMulDivTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMulDivTest,
                         ::testing::ValuesIn(kMulDivInstructions));

namespace {

struct MulDPInst {
  const char* mul_constructor_name;
  TSBinop mul_op;
  TSBinop add_op;
  TSBinop sub_op;
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
    {"Word32Mul", TSBinop::kWord32Mul, TSBinop::kWord32Add, TSBinop::kWord32Sub,
     kArm64Madd32, kArm64Msub32, kArm64Mneg32, MachineType::Int32()},
    {"Word64Mul", TSBinop::kWord64Mul, TSBinop::kWord64Add, TSBinop::kWord64Sub,
     kArm64Madd, kArm64Msub, kArm64Mneg, MachineType::Int64()}};

using TurboshaftInstructionSelectorIntDPWithIntMulTest =
    TurboshaftInstructionSelectorTestWithParam<MulDPInst>;

TEST_P(TurboshaftInstructionSelectorIntDPWithIntMulTest, AddWithMul) {
  const MulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex n = m.Emit(mdpi.mul_op, m.Parameter(1), m.Parameter(2));
    m.Return(m.Emit(mdpi.add_op, m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex n = m.Emit(mdpi.mul_op, m.Parameter(0), m.Parameter(1));
    m.Return(m.Emit(mdpi.add_op, n, m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorIntDPWithIntMulTest, SubWithMul) {
  const MulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex n = m.Emit(mdpi.mul_op, m.Parameter(1), m.Parameter(2));
    m.Return(m.Emit(mdpi.sub_op, m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_sub_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorIntDPWithIntMulTest, NegativeMul) {
  const MulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type);
    OpIndex n = m.Emit(mdpi.sub_op, BuildConstant(&m, type, 0), m.Parameter(0));
    m.Return(m.Emit(mdpi.mul_op, n, m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_neg_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    OpIndex n = m.Emit(mdpi.sub_op, BuildConstant(&m, type, 0), m.Parameter(1));
    m.Return(m.Emit(mdpi.mul_op, m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_neg_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorIntDPWithIntMulTest,
                         ::testing::ValuesIn(kMulDPInstructions));

#if V8_ENABLE_WEBASSEMBLY

TEST_F(TurboshaftInstructionSelectorTest, AddReduce) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Simd128());
    V<Simd128> reduce = m.I8x16AddReduce(m.Parameter(0));
    m.Return(reduce);
    Stream s = m.Build();
    EXPECT_EQ(kArm64I8x16Addv, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Simd128());
    V<Simd128> reduce = m.I16x8AddReduce(m.Parameter(0));
    m.Return(reduce);
    Stream s = m.Build();
    EXPECT_EQ(kArm64I16x8Addv, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Simd128());
    V<Simd128> reduce = m.I32x4AddReduce(m.Parameter(0));
    m.Return(reduce);
    Stream s = m.Build();
    EXPECT_EQ(kArm64I32x4Addv, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Simd128());
    V<Simd128> reduce = m.I64x2AddReduce(m.Parameter(0));
    m.Return(reduce);
    Stream s = m.Build();
    EXPECT_EQ(kArm64I64x2AddPair, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Simd128());
    V<Simd128> reduce = m.F32x4AddReduce(m.Parameter(0));
    m.Return(reduce);
    Stream s = m.Build();
    EXPECT_EQ(kArm64F32x4AddReducePairwise, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Simd128());
    V<Simd128> reduce = m.F64x2AddReduce(m.Parameter(0));
    m.Return(reduce);
    Stream s = m.Build();
    EXPECT_EQ(kArm64F64x2AddPair, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

namespace {

struct SIMDMulDPInst {
  const char* mul_constructor_name;
  TSBinop mul_operator;
  TSBinop add_operator;
  TSBinop sub_operator;
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
    {"I32x4Mul", TSBinop::kI32x4Mul, TSBinop::kI32x4Add, TSBinop::kI32x4Sub,
     kArm64Mla, kArm64Mls, MachineType::Simd128(), 32},
    {"I16x8Mul", TSBinop::kI16x8Mul, TSBinop::kI16x8Add, TSBinop::kI16x8Sub,
     kArm64Mla, kArm64Mls, MachineType::Simd128(), 16}};

using TurboshaftInstructionSelectorSIMDDPWithSIMDMulTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDMulDPInst>;

TEST_P(TurboshaftInstructionSelectorSIMDDPWithSIMDMulTest, AddWithMul) {
  const SIMDMulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex n = m.Emit(mdpi.mul_operator, m.Parameter(1), m.Parameter(2));
    m.Return(m.Emit(mdpi.add_operator, m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex n = m.Emit(mdpi.mul_operator, m.Parameter(0), m.Parameter(1));
    m.Return(m.Emit(mdpi.add_operator, n, m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorSIMDDPWithSIMDMulTest, SubWithMul) {
  const SIMDMulDPInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex n = m.Emit(mdpi.mul_operator, m.Parameter(1), m.Parameter(2));
    m.Return(m.Emit(mdpi.sub_operator, m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_sub_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDDPWithSIMDMulTest,
                         ::testing::ValuesIn(kSIMDMulDPInstructions));

namespace {

struct SIMDShrAddInst {
  const char* shradd_constructor_name;
  TSBinop shr_s_operator;
  TSBinop shr_u_operator;
  TSBinop add_operator;
  const int laneSize;
};

std::ostream& operator<<(std::ostream& os, const SIMDShrAddInst& inst) {
  return os << inst.shradd_constructor_name;
}

}  // namespace

static const SIMDShrAddInst kSIMDShrAddInstructions[] = {
    {"I64x2ShrAdd", TSBinop::kI64x2ShrS, TSBinop::kI64x2ShrU,
     TSBinop::kI64x2Add, 64},
    {"I32x4ShrAdd", TSBinop::kI32x4ShrS, TSBinop::kI32x4ShrU,
     TSBinop::kI32x4Add, 32},
    {"I16x8ShrAdd", TSBinop::kI16x8ShrS, TSBinop::kI16x8ShrU,
     TSBinop::kI16x8Add, 16},
    {"I8x16ShrAdd", TSBinop::kI8x16ShrS, TSBinop::kI8x16ShrU,
     TSBinop::kI8x16Add, 8}};

using TurboshaftInstructionSelectorSIMDShrAddTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDShrAddInst>;

TEST_P(TurboshaftInstructionSelectorSIMDShrAddTest, ShrAddS) {
  const SIMDShrAddInst param = GetParam();
  const MachineType type = MachineType::Simd128();
  {
    StreamBuilder m(this, type, type, type);
    OpIndex n =
        m.Emit(param.shr_s_operator, m.Parameter(1), m.Int32Constant(1));
    m.Return(m.Emit(param.add_operator, m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ssra, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.laneSize, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    OpIndex n =
        m.Emit(param.shr_s_operator, m.Parameter(0), m.Int32Constant(1));
    m.Return(m.Emit(param.add_operator, n, m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ssra, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.laneSize, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorSIMDShrAddTest, ShrAddU) {
  const SIMDShrAddInst param = GetParam();
  const MachineType type = MachineType::Simd128();
  {
    StreamBuilder m(this, type, type, type);
    OpIndex n =
        m.Emit(param.shr_u_operator, m.Parameter(1), m.Int32Constant(1));
    m.Return(m.Emit(param.add_operator, m.Parameter(0), n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Usra, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.laneSize, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    OpIndex n =
        m.Emit(param.shr_u_operator, m.Parameter(0), m.Int32Constant(1));
    m.Return(m.Emit(param.add_operator, n, m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Usra, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(param.laneSize, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDShrAddTest,
                         ::testing::ValuesIn(kSIMDShrAddInstructions));

namespace {
struct SIMDAddExtMulInst {
  const char* mul_constructor_name;
  TSBinop mul_operator;
  TSBinop add_operator;
  ArchOpcode multiply_add_arch_opcode;
  MachineType machine_type;
  int lane_size;
};
}  // namespace

static const SIMDAddExtMulInst kSimdAddExtMulInstructions[] = {
    {"I16x8ExtMulLowI8x16S", TSBinop::kI16x8ExtMulLowI8x16S, TSBinop::kI16x8Add,
     kArm64Smlal, MachineType::Simd128(), 16},
    {"I16x8ExtMulHighI8x16S", TSBinop::kI16x8ExtMulHighI8x16S,
     TSBinop::kI16x8Add, kArm64Smlal2, MachineType::Simd128(), 16},
    {"I16x8ExtMulLowI8x16U", TSBinop::kI16x8ExtMulLowI8x16U, TSBinop::kI16x8Add,
     kArm64Umlal, MachineType::Simd128(), 16},
    {"I16x8ExtMulHighI8x16U", TSBinop::kI16x8ExtMulHighI8x16U,
     TSBinop::kI16x8Add, kArm64Umlal2, MachineType::Simd128(), 16},
    {"I32x4ExtMulLowI16x8S", TSBinop::kI32x4ExtMulLowI16x8S, TSBinop::kI32x4Add,
     kArm64Smlal, MachineType::Simd128(), 32},
    {"I32x4ExtMulHighI16x8S", TSBinop::kI32x4ExtMulHighI16x8S,
     TSBinop::kI32x4Add, kArm64Smlal2, MachineType::Simd128(), 32},
    {"I32x4ExtMulLowI16x8U", TSBinop::kI32x4ExtMulLowI16x8U, TSBinop::kI32x4Add,
     kArm64Umlal, MachineType::Simd128(), 32},
    {"I32x4ExtMulHighI16x8U", TSBinop::kI32x4ExtMulHighI16x8U,
     TSBinop::kI32x4Add, kArm64Umlal2, MachineType::Simd128(), 32}};

using TurboshaftInstructionSelectorSIMDAddExtMulTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDAddExtMulInst>;

// TODO(zhin): This can be merged with InstructionSelectorSIMDDPWithSIMDMulTest
// once sub+extmul matching is implemented.
TEST_P(TurboshaftInstructionSelectorSIMDAddExtMulTest, AddExtMul) {
  const SIMDAddExtMulInst mdpi = GetParam();
  const MachineType type = mdpi.machine_type;
  {
    // Test Add(x, ExtMul(y, z)).
    StreamBuilder m(this, type, type, type, type);
    OpIndex n = m.Emit(mdpi.mul_operator, m.Parameter(1), m.Parameter(2));
    m.Return(m.Emit(mdpi.add_operator, m.Parameter(0), n));
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
    OpIndex n = m.Emit(mdpi.mul_operator, m.Parameter(0), m.Parameter(1));
    m.Return(m.Emit(mdpi.add_operator, n, m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(mdpi.multiply_add_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(mdpi.lane_size, LaneSizeField::decode(s[0]->opcode()));
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDAddExtMulTest,
                         ::testing::ValuesIn(kSimdAddExtMulInstructions));

struct SIMDMulDupInst {
  const uint8_t shuffle[16]
```