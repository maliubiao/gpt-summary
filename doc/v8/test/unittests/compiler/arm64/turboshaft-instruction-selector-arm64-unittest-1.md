Response: The user wants a summary of the C++ source code file `v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc`.
This is the second part of a four-part file.

The file seems to contain unit tests for the Turboshaft instruction selector on the ARM64 architecture. It tests how different intermediate representation (IR) operations are translated into ARM64 assembly instructions.

The tests cover various categories of instructions:
- Comparisons (including conditional sets and branches)
- Addition and subtraction with overflow detection
- Shift operations
- Multiplication and division
- Floating-point arithmetic and comparisons
- Conversions between different data types
- SIMD (Single Instruction, Multiple Data) operations for WebAssembly (if enabled)

The tests are structured using Google Test framework and utilize a `StreamBuilder` to construct sequences of IR operations. The generated instruction streams (`Stream`) are then inspected to ensure the correct ARM64 opcodes, addressing modes, input/output counts, and flag settings are produced.

Let's summarize the functionality of this specific part.

**Part 2 Functionality:**

This section of the test file primarily focuses on testing the instruction selection for the following operations on ARM64:

1. **Comparison Instructions:**  Tests the generation of `kArm64Cmp` and `kArm64Cmp32` instructions for various comparison operations (equal, not equal, less than, less than or equal) and their combinations in conditional statements and branches. It checks the correct flags mode (`kFlags_conditional_set`, `kFlags_conditional_branch`).

2. **Add and Subtract with Overflow:**  Tests the instruction selection for addition and subtraction operations that check for overflow. It verifies the generation of the correct ARM64 opcodes, flags mode (`kFlags_set`, `kFlags_branch`), and the `kOverflow` flag condition. It also tests different operand combinations (register-register, register-immediate).

3. **Shift Instructions:** Tests the selection of appropriate ARM64 shift instructions (`kArm64Lsl`, `kArm64Lsr`, `kArm64Asr`, `kArm64Ror`, `kArm64Ror32`) for various shift operations (left shift, right shift logical, right shift arithmetic, rotate right) with register and immediate operands. It also tests scenarios where shifts are combined with type conversions like `ChangeInt32ToInt64` and `TruncateWord64ToWord32`.
这个C++源代码文件（`v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc`）的第2部分主要功能是测试 **ARM64 架构下 Turboshaft 编译器的指令选择器** 对于以下几种操作的正确性：

1. **比较指令 (Comparison Instructions):**
   - 测试了 `Word64Equal`, `Word64NotEqual`, `Uint64LessThanOrEqual`, `Int64LessThan`, `Int32LessThan` 等比较操作如何被转换为 ARM64 的 `kArm64Cmp` 和 `kArm64Cmp32` 指令。
   - 重点测试了比较结果如何用于条件设置 (`kFlags_conditional_set`) 和条件分支 (`kFlags_conditional_branch`)。
   - 验证了比较指令的输入和输出数量是否正确。

2. **带溢出检查的加法和减法指令 (Add and subtract instructions with overflow):**
   - 测试了 `Int32AddCheckOverflow` 和 `Int64AddCheckOverflow` 等带溢出检查的加减法操作如何被转换为 ARM64 的加减法指令。
   - 验证了指令是否正确设置了标志位 (`kFlags_set`, `kFlags_branch`) 以及溢出条件 (`kOverflow`)。
   - 测试了操作数是寄存器和立即数的不同情况。
   - 特别测试了与右移操作（ROR）的组合，确保不会错误地将不支持 ROR 移位的加减法指令进行合并。

3. **移位指令 (Shift instructions):**
   - 测试了各种移位操作 (`Word64ShiftLeft`, `Word64ShiftRightArithmetic`, `Word64ShiftRightLogical`, `Word32ShiftLeft`, 等) 如何被转换为对应的 ARM64 移位指令 (`kArm64Lsl`, `kArm64Lsr`, `kArm64Asr`)。
   - 测试了操作数是寄存器和立即数的情况。
   - 验证了在移位操作后进行类型转换 (`TruncateWord64ToWord32`, `ChangeInt32ToInt64`, `ChangeUint32ToUint64`) 时指令选择器的行为。

**与 Javascript 的关系：**

Turboshaft 是 V8 JavaScript 引擎的下一代编译器。这个测试文件验证了 Turboshaft 如何将 JavaScript 代码中涉及到比较、加减法（可能导致溢出）和位移操作的部分，正确地转换为高效的 ARM64 机器码。

**JavaScript 例子：**

* **比较操作：**

```javascript
function compare(a, b) {
  if (a < b) {
    return 1;
  } else {
    return 0;
  }
}
```
Turboshaft 会将 `a < b` 这个 JavaScript 比较操作转换为 ARM64 的比较指令，并根据比较结果进行条件分支。

* **带溢出检查的加法：**

虽然 JavaScript 的 Number 类型可以表示很大的整数，但在某些特定的场景（比如使用 `TypedArray` 操作整数时），可能会涉及到需要考虑溢出的整数运算。

```javascript
function addWithOverflow(a, b) {
  const result = a + b;
  // 模拟溢出检查，实际 JavaScript 中不会直接抛出溢出错误
  if (result < a || result < b) {
    console.log("溢出发生了！");
  }
  return result;
}
```
虽然 JavaScript 本身不提供原生的溢出检查，但 Turboshaft 在编译一些特定的操作（例如 TypedArray 的运算）时，可能会生成带有溢出检测的指令。测试文件中的这部分就是为了验证这种指令生成是否正确。

* **移位操作：**

```javascript
function shift(x, amount) {
  return x << amount;
}
```
JavaScript 的位移操作符 `<<` 会被 Turboshaft 转换为 ARM64 的移位指令。测试文件验证了不同类型的位移操作和移位量是否能正确生成对应的机器码。

总而言之，这个代码片段专注于测试 Turboshaft 编译器在 ARM64 架构下处理基本的算术和逻辑运算的指令选择能力，确保 JavaScript 代码能够被正确且高效地编译成目标平台的机器码。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
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

using TurboshaftInstructionSelectorSimdF32x4MulWithDupTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDMulDupInst>;

TEST_P(TurboshaftInstructionSelectorSimdF32x4MulWithDupTest, MulWithDup) {
  const SIMDMulDupInst param = GetParam();
  const MachineType type = MachineType::Simd128();
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex shuffle =
        m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), param.shuffle);
    m.Return(m.F32x4Mul(m.Parameter(2), shuffle));
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
    OpIndex shuffle =
        m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), param.shuffle);
    m.Return(m.F32x4Mul(shuffle, m.Parameter(2)));
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSimdF32x4MulWithDupTest,
                         ::testing::ValuesIn(kSIMDF32x4MulDuplInstructions));

TEST_F(TurboshaftInstructionSelectorTest, SimdF32x4MulWithDupNegativeTest) {
  const MachineType type = MachineType::Simd128();
  // Check that optimization does not match when the shuffle is not a f32x4.dup.
  const uint8_t mask[kSimd128Size] = {0};
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex shuffle = m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), mask);
    m.Return(m.F32x4Mul(m.Parameter(2), shuffle));
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

using TurboshaftInstructionSelectorSimdF64x2MulWithDupTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDMulDupInst>;

TEST_P(TurboshaftInstructionSelectorSimdF64x2MulWithDupTest, MulWithDup) {
  const SIMDMulDupInst param = GetParam();
  const MachineType type = MachineType::Simd128();
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex shuffle =
        m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), param.shuffle);
    m.Return(m.F64x2Mul(m.Parameter(2), shuffle));
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
    OpIndex shuffle =
        m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), param.shuffle);
    m.Return(m.F64x2Mul(shuffle, m.Parameter(2)));
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

TEST_F(TurboshaftInstructionSelectorTest, ReverseShuffle32x4Test) {
  const MachineType type = MachineType::Simd128();
  {
    const uint8_t shuffle[] = {
      12, 13, 14, 15,
      8, 9, 10, 11,
      4, 5, 6, 7,
      0, 1, 2, 3
    };
    StreamBuilder m(this, type, type, type, type);
    m.Return(m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), shuffle));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64S32x4Reverse, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    const uint8_t shuffle[] = {
      28, 29, 30, 31,
      24, 25, 26, 27,
      20, 21, 22, 23,
      16, 17, 18, 19
    };
    StreamBuilder m(this, type, type, type, type);
    m.Return(m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), shuffle));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64S32x4Reverse, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSimdF64x2MulWithDupTest,
                         ::testing::ValuesIn(kSIMDF64x2MulDuplInstructions));

TEST_F(TurboshaftInstructionSelectorTest, SimdF64x2MulWithDupNegativeTest) {
  const MachineType type = MachineType::Simd128();
  // Check that optimization does not match when the shuffle is not a f64x2.dup.
  const uint8_t mask[kSimd128Size] = {0};
  {
    StreamBuilder m(this, type, type, type, type);
    OpIndex shuffle = m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), mask);
    m.Return(m.F64x2Mul(m.Parameter(2), shuffle));
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

TEST_F(TurboshaftInstructionSelectorTest, OneLaneSwizzle32x4Test) {
  const MachineType type = MachineType::Simd128();
  {
    const uint8_t shuffle[] = {
      0, 1, 2, 3,
      4, 5, 6, 7,
      4, 5, 6, 7,
      12, 13, 14, 15
    };
    StreamBuilder m(this, type, type, type, type);
    m.Return(m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), shuffle));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64S32x4OneLaneSwizzle, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    const uint8_t shuffle[] = {
      16, 17, 18, 19,
      20, 21, 22, 23,
      24, 25, 26, 27,
      16, 17, 18, 19
    };
    StreamBuilder m(this, type, type, type, type);
    m.Return(m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), shuffle));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64S32x4OneLaneSwizzle, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

#endif  // V8_ENABLE_WEBASSEMBLY

TEST_F(TurboshaftInstructionSelectorTest, Word32MulWithImmediate) {
  // x * (2^k + 1) -> x + (x << k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Mul(m.Parameter(0), m.Int32Constant((1 << k) + 1)));
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
    m.Return(m.Word32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(0)));
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
        m.Word32Add(m.Word32Mul(m.Parameter(0), m.Int32Constant((1 << k) + 1)),
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
        m.Word32Add(m.Word32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(0)),
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
    m.Return(m.Word32Add(
        m.Parameter(0),
        m.Word32Mul(m.Parameter(1), m.Int32Constant((1 << k) + 1))));
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
    m.Return(m.Word32Add(
        m.Parameter(0),
        m.Word32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(1))));
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
    m.Return(m.Word32Sub(
        m.Parameter(0),
        m.Word32Mul(m.Parameter(1), m.Int32Constant((1 << k) + 1))));
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
    m.Return(m.Word32Sub(
        m.Parameter(0),
        m.Word32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(1))));
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

TEST_F(TurboshaftInstructionSelectorTest, Word64MulWithImmediate) {
  // x * (2^k + 1) -> x + (x << k)
  TRACED_FORRANGE(int64_t, k, 1, 62) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(
        m.Word64Mul(m.Parameter(0), m.Int64Constant((int64_t{1} << k) + 1)));
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
        m.Word64Mul(m.Int64Constant((int64_t{1} << k) + 1), m.Parameter(0)));
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
    m.Return(m.Word64Add(
        m.Word64Mul(m.Parameter(0), m.Int64Constant((int64_t{1} << k) + 1)),
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
    m.Return(m.Word64Add(
        m.Word64Mul(m.Int64Constant((int64_t{1} << k) + 1), m.Parameter(0)),
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
    m.Return(m.Word64Add(
        m.Parameter(0),
        m.Word64Mul(m.Parameter(1), m.Int64Constant((int64_t{1} << k) + 1))));
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
    m.Return(m.Word64Add(
        m.Parameter(0),
        m.Word64Mul(m.Int64Constant((int64_t{1} << k) + 1), m.Parameter(1))));
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
    m.Return(m.Word64Sub(
        m.Parameter(0),
        m.Word64Mul(m.Parameter(1), m.Int64Constant((int64_t{1} << k) + 1))));
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
    m.Return(m.Word64Sub(
        m.Parameter(0),
        m.Word64Mul(m.Int64Constant((int64_t{1} << k) + 1), m.Parameter(1))));
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

using TurboshaftInstructionSelectorFPArithTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorFPArithTest, Parameter) {
  const MachInst2 fpa = GetParam();
  StreamBuilder m(this, fpa.machine_type, fpa.machine_type, fpa.machine_type);
  m.Return(m.Emit(fpa.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(fpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorFPArithTest,
                         ::testing::ValuesIn(kFPArithInstructions));

using TurboshaftInstructionSelectorFPCmpTest =
    TurboshaftInstructionSelectorTestWithParam<FPCmp>;

TEST_P(TurboshaftInstructionSelectorFPCmpTest, Parameter) {
  const FPCmp cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), cmp.mi.machine_type,
                  cmp.mi.machine_type);
  m.Return(m.Emit(cmp.mi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.cond, s[0]->flags_condition());
}

TEST_P(TurboshaftInstructionSelectorFPCmpTest, WithImmediateZeroOnRight) {
  const FPCmp cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), cmp.mi.machine_type);
  if (cmp.mi.machine_type == MachineType::Float64()) {
    m.Return(m.Emit(cmp.mi.op, m.Parameter(0), m.Float64Constant(0.0)));
  } else {
    m.Return(m.Emit(cmp.mi.op, m.Parameter(0), m.Float32Constant(0.0f)));
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

TEST_P(TurboshaftInstructionSelectorFPCmpTest, WithImmediateZeroOnLeft) {
  const FPCmp cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), cmp.mi.machine_type);
  if (cmp.mi.machine_type == MachineType::Float64()) {
    m.Return(m.Emit(cmp.mi.op, m.Float64Constant(0.0), m.Parameter(0)));
  } else {
    m.Return(m.Emit(cmp.mi.op, m.Float32Constant(0.0f), m.Parameter(0)));
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorFPCmpTest,
                         ::testing::ValuesIn(kFPCmpInstructions));

TEST_F(TurboshaftInstructionSelectorTest, Float32SelectWithRegisters) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  OpIndex cond = m.Int32Constant(1);
  m.Return(m.Float32Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(TurboshaftInstructionSelectorTest, Float32SelectWithZero) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  OpIndex cond = m.Int32Constant(1);
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

TEST_F(TurboshaftInstructionSelectorTest, Float64SelectWithRegisters) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex cond = m.Int32Constant(1);
  m.Return(m.Float64Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(TurboshaftInstructionSelectorTest, Float64SelectWithZero) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  OpIndex cond = m.Int32Constant(1);
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

TEST_F(TurboshaftInstructionSelectorTest, Word32SelectWithRegisters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex cond = m.Int32Constant(1);
  m.Return(m.Word32Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(TurboshaftInstructionSelectorTest, Word32SelectWithZero) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  OpIndex cond = m.Int32Constant(1);
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

TEST_F(TurboshaftInstructionSelectorTest, Word64SelectWithRegisters) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex cond = m.Int32Constant(1);
  m.Return(m.Word64Select(cond, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_select, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

TEST_F(TurboshaftInstructionSelectorTest, Word64SelectWithZero) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
  OpIndex cond = m.Int32Constant(1);
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

using TurboshaftInstructionSelectorConversionTest =
    TurboshaftInstructionSelectorTestWithParam<Conversion>;

TEST_P(TurboshaftInstructionSelectorConversionTest, Parameter) {
  const Conversion conv = GetParam();
  StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
  m.Return(m.Emit(conv.mi.op, m.Parameter(0)));
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorConversionTest,
                         ::testing::ValuesIn(kConversionInstructions));

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

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test,
    ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

using TurboshaftInstructionSelectorElidedChangeUint32ToUint64MultiOutputTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorElidedChangeUint32ToUint64MultiOutputTest,
       Parameter) {
  const MachInst2 binop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), binop.machine_type,
                  binop.machine_type);
  m.Return(m.ChangeUint32ToUint64(
      m.Projection(m.Emit(binop.op, m.Parameter(0), m.Parameter(1)), 0)));
  Stream s = m.Build();
  // Make sure the `ChangeUint32ToUint64` node turned into a no-op.
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorElidedChangeUint32ToUint64MultiOutputTest,
    ::testing::ValuesIn(kCanElideChangeUint32ToUint64MultiOutput));

TEST_F(TurboshaftInstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // Ldrb
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Pointer());
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
                    MachineType::Pointer());
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
                    MachineType::Pointer());
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

TEST_F(TurboshaftInstructionSelectorTest, ChangeInt32ToInt64AfterLoad) {
  // For each case, test that the conversion is merged into the load
  // operation.
  // ChangeInt32ToInt64(Load_Uint8) -> Ldrb
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build()
"""


```