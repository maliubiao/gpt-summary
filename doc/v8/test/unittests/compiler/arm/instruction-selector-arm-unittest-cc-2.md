Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is a unit test file for the instruction selector of the V8 JavaScript engine, specifically targeting the ARM architecture.

Here's a plan:
1. Identify the main purpose of the code: testing the instruction selection for ARM.
2. Identify the types of tests being performed: floating-point comparisons, floating-point arithmetic, flag-setting instructions, and other miscellaneous instructions.
3. Explain the structure of the tests using `TEST_P` and `TEST_F`.
4. For each category of tests, describe the functionality being tested and provide a simple example if possible.
5. Address the user's specific questions about file extensions, JavaScript relevance, code logic, and common programming errors.
这是v8 JavaScript引擎中用于测试ARM架构指令选择器的单元测试代码。它主要验证了在将高级的、平台无关的中间表示（IR）转换成底层的ARM机器码时，指令选择器是否能够正确地选择合适的ARM指令。

**功能列表:**

1. **浮点数比较指令测试 (`InstructionSelectorF64ComparisonTest`):**
   - 测试各种浮点数（双精度）比较操作 (`Float64Equal`, `Float64NotEqual`, `Float64LessThan` 等) 是否能被正确地转换为相应的ARM比较指令 (`kArmVcmpF64`)。
   - 测试当比较操作符的左操作数为立即数0.0时，指令选择器是否能够正确处理。

2. **浮点数算术指令测试 (`InstructionSelectorFAITest`):**
   - 测试基本的浮点数算术运算（加法、减法、乘法、除法等，通过 `kFAIs` 定义）是否能被正确地转换为相应的ARM浮点运算指令 (如 `kArmVaddF32`, `kArmVsubF64` 等)。
   - 测试带有参数的浮点运算指令的输入和输出是否正确对应。

3. **特定的浮点数运算指令测试 (`Float32Abs`, `Float64Abs`, `Float32Sqrt`, `Float64Sqrt`):**
   - 测试浮点数的绝对值和平方根运算是否能被正确地转换为相应的ARM指令 (`kArmVabsF32`, `kArmVabsF64`, `kArmVsqrtF32`, `kArmVsqrtF64`)。

4. **融合乘加/减指令测试 (`Float32AddWithFloat32Mul`, `Float64AddWithFloat64Mul`, `Float32SubWithFloat32Mul`, `Float64SubWithFloat64Mul`):**
   - 测试形如 `a + b * c` 和 `a - b * c` 的浮点数运算是否能被优化为ARM的融合乘加/减指令 (`kArmVmlaF32`, `kArmVmlaF64`, `kArmVmlsF32`, `kArmVmlsF64`)。

5. **标志位设置指令测试 (`InstructionSelectorFlagSettingTest`):**
   - 测试一些会设置处理器标志位的算术和逻辑运算指令 (如 `Int32Add`, `Word32And`, `Word32Or`, `Word32Xor`)，在与比较指令结合使用时，是否能够被优化为不产生额外输出的标志位设置指令 (如 `kArmCmn`, `kArmTst`, `kArmTeq`)，并直接用于条件分支。
   - 测试比较指令（例如与0比较）在不同的操作数位置（左侧或右侧）时，指令选择器是否能够正确处理。
   - 测试当标志位设置指令的结果在同一个基本块中还有其他用途时，是否会避免这种优化。
   - 测试标志位设置指令与移位操作结合使用时的情况。

6. **其他算术和逻辑指令测试:**
   - 测试一些其他的整数算术和逻辑指令，例如带乘法累加的加法 (`Int32AddWithInt32Mul`, `Int32AddWithInt32MulHigh`)，以及与位运算结合的加法 (`Int32AddWithWord32And`, `Int32AddWithWord32SarWithWord32Shl`)。
   - 测试整数减法与乘法的组合 (`Int32SubWithInt32Mul`) 是否能利用 ARMv7 的 `kArmMls` 指令。
   - 测试整数除法 (`Int32DivWithParameters`) 和取模 (`Int32ModWithParameters`) 操作的指令选择，以及在支持硬件除法指令 (`SUDIV`) 的情况下 (`Int32DivWithParametersForSUDIV`, `Int32ModWithParametersForSUDIV`) 的指令选择。

**关于文件扩展名和 Torque：**

`v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc` 的后缀是 `.cc`，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 文件。如果以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 的关系：**

这段代码直接测试了 V8 编译器的代码生成部分，而 V8 编译器负责将 JavaScript 代码转换成机器码。因此，这段代码的功能与 JavaScript 的性能和执行息息相关。指令选择器选择的指令越高效，生成的机器码执行效率就越高，JavaScript 程序的运行速度也就越快。

**JavaScript 示例：**

以下 JavaScript 代码的执行会涉及到这里测试的一些指令选择逻辑：

```javascript
function test(a, b, c) {
  // 浮点数比较
  if (a > 0.0) {
    // 浮点数算术运算和融合乘加
    return a + b * c;
  } else {
    // 整数算术运算和标志位设置（可能用于 if 条件判断）
    return (b & 0xFF) + c;
  }
}

console.log(test(1.5, 2, 3));  // 输出 7.5
console.log(test(-0.5, 5, 10)); // 输出 15
```

当 V8 编译执行 `test` 函数时，`instruction-selector-arm-unittest.cc` 中测试的逻辑会确保编译器为浮点数比较、浮点数加法和乘法，以及整数的位运算和加法等操作选择最优的 ARM 指令。

**代码逻辑推理和假设输入输出：**

以 `TEST_P(InstructionSelectorF64ComparisonTest, WithImmediateZeroOnLeft)` 为例：

**假设输入:**  一个双精度浮点数参数 (例如 3.14)。

**代码逻辑:**  将立即数 0.0 与该参数进行比较（具体的比较类型由 `GetParam()` 提供，例如 `Float64LessThan`）。

**预期输出:** 生成一个 ARM 的浮点数比较指令 (`kArmVcmpF64`)，其中左操作数为立即数 0.0，右操作数为输入的参数。指令会设置标志位，以便后续的条件跳转。

**用户常见的编程错误：**

这段代码主要测试编译器内部逻辑，与用户直接编写 JavaScript 代码时遇到的错误关联较少。然而，理解指令选择器的工作方式可以帮助开发者理解一些性能相关的概念。例如，在进行复杂的数学运算时，某些组合可能会被编译器优化为更高效的指令（如融合乘加），了解这些优化有助于编写更高效的 JavaScript 代码。

一个可能的关联是，当开发者在 JavaScript 中进行大量的浮点数运算时，可能会因为精度问题而导致意想不到的结果。虽然这与指令选择器本身的关系不大，但理解浮点数在底层的表示和运算方式有助于避免这类错误。

**归纳功能 (第3部分):**

这部分代码主要关注 **浮点数算术运算** 和 **标志位设置指令** 的指令选择测试。它验证了在 ARM 架构下，V8 编译器能够正确地将 JavaScript 中的浮点数运算和需要设置处理器标志位的操作转换为高效的 ARM 指令，并能进行一些优化，例如将乘法和加/减法组合成融合指令，以及在特定情况下将算术/逻辑运算与比较操作合并。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

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
  ASSE
"""


```