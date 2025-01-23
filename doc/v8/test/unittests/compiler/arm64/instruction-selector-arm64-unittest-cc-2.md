Response:
My thinking process to arrive at the summary goes like this:

1. **Identify the Core Purpose:** The filename `instruction-selector-arm64-unittest.cc` immediately signals that this code is about testing the instruction selector for the ARM64 architecture within the V8 compiler. Unit tests verify individual components.

2. **Scan for Key Test Structures:** I look for recurring patterns like `TEST_F`, `TEST_P`, `INSTANTIATE_TEST_SUITE_P`, and the use of `StreamBuilder` and `Stream`. These indicate different types of unit tests being performed. `TEST_F` is for tests within a single class, while `TEST_P` is for parameterized tests. `INSTANTIATE_TEST_SUITE_P` sets up the parameters for those tests. `StreamBuilder` seems to be a way to construct sequences of machine instructions, and `Stream` represents the resulting sequence.

3. **Categorize the Tests:** I start grouping tests based on the operations they are verifying. The names of the tests and the types they use (`OvfAddSubTest`, `ShiftTest`, `MulDivTest`, `IntDPWithIntMulTest`, `SIMD...`) provide strong clues.

4. **Analyze Individual Test Cases:** I examine the logic within each test. For example, the `OvfParameter` tests check how the instruction selector handles overflow flags when adding or subtracting parameters. The `OvfImmediateOnRight` tests focus on cases where one operand is an immediate value. The `ShiftTest` checks different shift operations with parameters and immediate values.

5. **Look for Parameterized Testing:** I pay attention to `TEST_P` and the corresponding `INSTANTIATE_TEST_SUITE_P`. This tells me that certain operations (like add/subtract with overflow, shifts, and multiply/divide) are being tested with various configurations of input types and opcodes. The `kOvfAddSubInstructions`, `kShiftInstructions`, `kMulDivInstructions`, etc., are arrays defining the parameter sets.

6. **Identify Specific Instruction Features:** I note details like "overflow flags," "immediate operands," "ROR shift," "left shift," "right shift," "multiply-add," "multiply-subtract," and the various SIMD operations. These pinpoint specific ARM64 instructions and their variations being tested.

7. **Recognize SIMD Testing:** The presence of `SIMDMulDPInst`, `SIMDShrAddInst`, `SIMDAddExtMulInst`, and the use of `MachineOperatorBuilder` methods like `I32x4Mul`, `I16x8Add`, etc., clearly indicates testing of SIMD (Single Instruction, Multiple Data) instructions. I identify different SIMD operation categories like multiply-accumulate, shift-add, and extended multiply.

8. **Observe Shuffle Operations:** The `I8x16Shuffle` node and tests like `SimdF32x4MulWithDupTest` highlight testing of SIMD shuffle operations, particularly in the context of optimization (e.g., combining multiplication with a duplicate lane operation).

9. **Infer the Purpose of the Tests:** Based on the above observations, I conclude that the primary function of this code is to ensure that the instruction selector correctly translates high-level operations into the appropriate ARM64 machine instructions. It covers various arithmetic, logical, and SIMD operations, paying attention to flags, immediate operands, and potential optimizations.

10. **Formulate the Summary:** I synthesize my findings into a concise summary, highlighting the key functionalities and the types of tests performed. I emphasize the focus on verifying the correct instruction selection for different scenarios, including overflow handling, immediate values, shifts, multiplications, divisions, and various SIMD instructions. I also mention the optimization aspects related to SIMD shuffle operations.

Essentially, I'm "reading" the code like a detective, looking for clues about its purpose and the techniques it employs. The naming conventions, test structures, and the specific operations being tested all contribute to building a comprehensive understanding.
这是 `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 源代码的第 3 部分，主要关注以下功能：

**总体功能（结合前两部分推断）：**

这个 C++ 文件包含了针对 V8 JavaScript 引擎中 ARM64 架构的指令选择器（Instruction Selector）的单元测试。指令选择器的作用是将中间表示（IR）的操作转换成具体的 ARM64 机器指令。

**第 3 部分的具体功能归纳：**

这部分主要测试了以下 ARM64 指令的选择和生成：

1. **带溢出检查的加法和减法指令 (`InstructionSelectorOvfAddSubTest`)：**
   - 测试了当进行加法或减法运算时，如何设置和使用溢出标志。
   - 涵盖了操作数是寄存器参数和立即数的情况。
   - 测试了溢出标志的不同使用场景：
     - 仅设置标志 (`kFlags_set`)
     - 不设置标志，只返回值 (`kFlags_none`)
     - 同时返回值和设置标志
     - 用于条件分支 (`kFlags_branch`)
   - 验证了当右操作数是立即数时，能否正确生成指令。
   - 特别测试了当使用不支持 ROR 移位的 ADD/SUB 指令时，指令选择器是否会避免合并 ROR 移位操作。

2. **移位指令 (`InstructionSelectorShiftTest`)：**
   - 测试了各种移位操作（左移、右移等）。
   - 涵盖了移位量是寄存器参数和立即数的情况。
   - 验证了移位指令的正确生成，包括操作码、输入和输出。

3. **特殊的 64 位移位和截断场景：**
   - 测试了将 32 位整数或无符号整数转换为 64 位整数后进行左移操作的情况，确保指令选择器能正确处理。
   - 测试了先进行 64 位算术右移或逻辑右移，然后截断为 32 位整数的情况，验证是否能生成优化的指令。

4. **乘法和除法指令 (`InstructionSelectorMulDivTest`)：**
   - 测试了基本的乘法和除法指令。
   - 验证了操作数是寄存器参数时指令的正确生成。

5. **带有乘法累加/减法操作的指令 (`InstructionSelectorIntDPWithIntMulTest`, `InstructionSelectorSIMDDPWithSIMDMulTest`, `InstructionSelectorSIMDAddExtMulTest`)：**
   - 测试了将乘法运算的结果与另一个操作数进行加法或减法的复合指令（如 `Madd`, `Msub`, `Mneg`）。
   - 涵盖了标量整数和 SIMD 向量的情况。
   - 测试了乘法累加的不同形式，例如 `Add(x, Mul(y, z))` 和 `Add(Mul(y, z), x)`。
   - 验证了指令选择器能够识别并生成这些优化的复合指令。
   - 对于 SIMD 指令，还测试了 lane size 的正确设置。
   - 特别测试了带有扩展乘法的 SIMD 指令 (e.g., `Smlal`, `Umlal`)。

6. **SIMD 向量的移位后加法指令 (`InstructionSelectorSIMDShrAddTest`)：**
   - 测试了 SIMD 向量的带符号和无符号右移后与另一个向量相加的指令 (`Ssra`, `Usra`)。
   - 验证了指令选择器能够正确生成这些指令。

7. **SIMD 向量与重复元素的乘法优化 (`InstructionSelectorSimdF32x4MulWithDupTest`)：**
   - 测试了一种优化场景：当进行 SIMD 乘法时，如果其中一个操作数可以通过 shuffle 操作从另一个操作数中重复某个元素得到（相当于乘以一个标量），指令选择器是否能生成更高效的 `FMulElement` 指令。
   - 测试了不同的 lane 和输入索引组合。
   - 同时提供了一个反例测试 (`SimdF32x4MulWithDupNegativeTest`)，确保当 shuffle 操作不是简单的重复元素时，不会错误地应用这种优化。

**与 Javascript 的关系：**

这些测试直接关系到 V8 如何执行 JavaScript 代码中的算术和位运算。例如：

```javascript
let a = 10;
let b = 20;
let c = a + b; // 这会触发加法指令的选择
let d = a * b; // 这会触发乘法指令的选择
let e = a << 2; // 这会触发左移指令的选择

// 带溢出的加法（在某些特定场景下，例如使用 Typed Arrays）
let ua = new Uint32Array([0xFFFFFFFF]);
let ub = new Uint32Array([1]);
let sum = ua[0] + ub[0]; // 可能会触发带溢出检查的加法指令
```

当 V8 编译这些 JavaScript 代码时，指令选择器会根据操作和数据类型选择合适的 ARM64 指令。这些单元测试确保了指令选择器在各种情况下都能做出正确的选择，从而保证生成的机器码的正确性和效率。

**代码逻辑推理示例：**

**假设输入：**

有一个 IR 节点表示 `Int32AddWithOverflow(a, b)`，其中 `a` 和 `b` 是两个 32 位整数类型的参数。

**预期输出（基于 `OvfParameter` 测试）：**

指令选择器应该生成一个 `kArm64Add32` 指令，其：
- `arch_opcode()` 返回 `kArm64Add32`。
- `InputCount()` 为 2。
- 输入分别是表示 `a` 和 `b` 的虚拟寄存器。
- `OutputCount()` 至少为 1。
- `flags_mode()` 为 `kFlags_set`。
- `flags_condition()` 为 `kOverflow`。

**用户常见的编程错误（可能导致溢出相关问题）：**

```javascript
// 整数溢出，但 JavaScript 通常不会抛出错误，而是返回不正确的结果
let maxInt = 2147483647;
let result = maxInt + 1; // result 会变成 -2147483648

// 在使用 Typed Arrays 时，溢出行为可能会有所不同
let uintArray = new Uint8Array([255]);
uintArray[0] += 1; // uintArray[0] 会变成 0，发生回绕
```

这些测试确保了 V8 在处理这些运算时，即使在可能发生溢出的情况下，也能生成正确的指令，以便在需要时检查和处理溢出。

**总结第 3 部分的功能：**

这部分主要测试了 ARM64 指令选择器对于**带溢出检查的加减法、移位操作、乘法除法以及各种形式的乘法累加/减法指令（包括标量和 SIMD）**的正确选择和生成。它还涵盖了 SIMD 向量的移位后加法以及特定 SIMD 乘法优化场景的测试。这些测试对于保证 V8 在 ARM64 架构上高效且正确地执行 JavaScript 代码至关重要。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
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

using Instru
```