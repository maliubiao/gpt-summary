Response:
The user wants a summary of the functionalities present in the provided C++ code snippet. The code is a unit test file for the ARM instruction selector in the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `instruction-selector-arm-unittest.cc` and the presence of `TEST_P`, `EXPECT_EQ`, and `ASSERT_LE` clearly indicate that this is a unit test file. The "instruction-selector" part tells us it's testing how V8 translates higher-level operations into ARM assembly instructions.

2. **Analyze the test categories:** The code is structured into several test suites using `TEST_P` and `TEST_F`. Each suite focuses on testing a specific category of ARM instructions:
    * `InstructionSelectorODPITest`: Tests instructions with two operands and potentially setting flags (like addition, subtraction, bitwise operations). "ODPI" likely stands for "Operand Destination Parameter Immediate".
    * `InstructionSelectorShiftTest`: Tests shift operations (left shift, right shift, etc.).
    * `InstructionSelectorMemoryAccessTest`: Tests memory access operations (loads and stores).
    * Individual tests like `ChangeFloat32ToFloat64WithParameter` and `TruncateFloat64ToFloat32WithParameter`: Tests type conversion instructions.
    * `InstructionSelectorComparisonTest` and `InstructionSelectorF32ComparisonTest`, `InstructionSelectorF64ComparisonTest`: Tests comparison instructions.

3. **Examine individual tests within categories:**  Within each test suite, the tests explore different scenarios:
    * **Operands:** Tests with register operands (`m.Parameter(0)`, `m.Parameter(1)`).
    * **Immediates:** Tests with immediate values (`m.Int32Constant(imm)`).
    * **Combinations:** Tests combining registers and immediates, and sometimes nested operations (like shifts within arithmetic operations).
    * **Flags:** Tests whether instructions correctly set and use processor flags (e.g., for conditional branching).
    * **Addressing modes:** Tests different ARM addressing modes.
    * **Data types:** Tests with various data types (int32, float32, float64).

4. **Look for patterns and common assertions:**  The tests generally follow a pattern:
    * **Setup:** Create a `StreamBuilder` to construct a sequence of instructions.
    * **Operation:**  Perform an operation using V8's intermediate representation nodes (e.g., `m.Word32Equal`, `m.Add`, `m.Load`).
    * **Return/Branch:**  Define the control flow (return a value or branch to a label).
    * **Build:** Call `m.Build()` to generate the instruction stream.
    * **Assertions:** Use `ASSERT_EQ`, `EXPECT_EQ`, `ASSERT_LE` to verify the generated instruction:
        * `arch_opcode()`: Checks the generated ARM instruction opcode.
        * `addressing_mode()`: Checks the addressing mode used.
        * `InputCount()`, `OutputCount()`: Checks the number of input and output operands.
        * `flags_mode()`, `flags_condition()`: Checks how flags are set and used.
        * `ToInt32()`: Checks the value of immediate operands.

5. **Consider specific test names:** Test names like `BothWithShift`, `BothWithShiftByImmediate`, `BranchWithParameters`, `BranchWithImmediate`, etc., provide hints about the specific scenarios being tested.

6. **Address the specific questions:**
    * **Functionality:** The code tests the ARM instruction selector.
    * **Torque:** The filename does *not* end in `.tq`, so it's C++.
    * **JavaScript relation:** The tests verify that higher-level operations (which could originate from JavaScript) are correctly translated to ARM instructions. Provide JavaScript examples of operations like addition, subtraction, bitwise operations, comparisons, and memory access that these tests indirectly cover.
    * **Code logic reasoning:**  Give a simple example of a test case (e.g., adding two parameters) and explain the expected input and output in terms of the generated ARM instruction.
    * **Common programming errors:** Relate the tests to potential errors in manual assembly programming, such as using incorrect opcodes, addressing modes, or handling of flags.
    * **Summary of functionality (for Part 2):**  Focus on the categories covered in this specific snippet: arithmetic/logical operations with flags, shift operations, and memory access.

7. **Structure the answer:** Organize the information logically, starting with the overall purpose and then detailing the individual test categories and their functionalities. Provide clear examples and explanations for each point.
这是对V8 JavaScript引擎中ARM架构的指令选择器进行单元测试的C++代码片段。它主要关注以下几个方面的功能：

**1. 算术和逻辑运算指令 (ODPI - Operand Destination Parameter Immediate):**

   -  **功能:** 测试各种需要两个操作数的算术和逻辑运算指令（例如加法、减法、按位与、按位或、按位异或等）的指令选择是否正确。
   -  **测试场景:**
      -  两个操作数都是寄存器参数。
      -  一个操作数是寄存器参数，另一个是立即数。
      -  两个操作数都是经过移位操作的寄存器参数。
      -  一个操作数是寄存器参数，另一个是经过立即数移位的寄存器参数。
   -  **验证点:**
      -  生成的指令的 `arch_opcode()` (机器码) 是否正确。
      -  生成的指令的 `addressing_mode()` (寻址模式) 是否正确。
      -  生成的指令的输入和输出数量是否正确。
      -  如果指令会设置标志位，`flags_mode()` 和 `flags_condition()` 是否正确。
   -  **代码逻辑推理 (假设输入与输出):**
      假设输入是两个 MachineType::Int32 类型的参数，并且要执行一个加法操作 (对应某个 `odpi.constructor`)。
      ```c++
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1));
      m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
      Stream s = m.Build();
      ```
      **假设输入:** 两个 Int32 类型的参数。
      **预期输出 (简化):** 生成一条 ARM 加法指令，其 `arch_opcode` 是预期的加法指令的机器码，`addressing_mode` 是寄存器寻址，输入是两个寄存器，输出是结果寄存器，并且设置了溢出标志。具体的机器码和寻址模式会根据 `odpi` 的具体值而定。

**2. 移位指令:**

   -  **功能:** 测试各种移位操作指令（例如逻辑左移、逻辑右移、算术右移、循环右移等）的指令选择是否正确。
   -  **测试场景:**
      -  移位量是寄存器参数。
      -  移位量是立即数。
      -  移位操作的结果用于比较（例如 `Word32Equal`）。
      -  移位操作的结果用于按位取反 (`Word32BitwiseNot`)。
      -  移位操作的结果用于按位与 (`Word32And`) 与按位取反的组合。
   -  **验证点:**  与算术和逻辑运算指令类似，验证机器码、寻址模式、输入输出数量和标志位设置。

**3. 分支指令:**

   -  **功能:** 测试基于算术和逻辑运算结果进行条件分支的指令选择是否正确。
   -  **测试场景:**
      -  基于 ODPI 指令的结果进行分支，分支条件是溢出 (`kOverflow`)。
      -  分支目标是不同的代码块 (`RawMachineLabel a`, `RawMachineLabel b`)。
   -  **验证点:**  验证生成的 ODPI 指令的机器码、寻址模式、输入输出数量和标志位设置 (`kFlags_branch`)。

**如果 v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc 以 .tq 结尾:**

那么它将是一个用 V8 的 Torque 语言编写的源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它会自动生成 C++ 代码。在这种情况下，该文件将包含 Torque 代码，用于声明和定义 ARM 指令选择器的逻辑。

**与 JavaScript 的功能关系:**

这段 C++ 代码测试的是 V8 引擎的底层组件，负责将 JavaScript 代码编译成机器码。当 JavaScript 代码执行算术运算、逻辑运算、移位操作或基于条件进行分支时，V8 的编译器会使用指令选择器来选择合适的 ARM 指令来实现这些操作。

**JavaScript 举例说明:**

```javascript
function test(a, b, c) {
  let sum = a + b; // 对应 ODPI 测试
  let shifted = a << c; // 对应移位测试
  if (sum > 10) { // 对应分支测试
    return shifted;
  } else {
    return sum;
  }
}
```

当 V8 编译 `test` 函数时，`instruction-selector-arm-unittest.cc` 中测试的逻辑会确保 `a + b` 被正确地翻译成 ARM 加法指令，`a << c` 被正确地翻译成 ARM 左移指令，并且 `sum > 10` 的条件判断会被翻译成正确的 ARM 比较和分支指令。

**用户常见的编程错误 (可能间接相关):**

虽然这段代码不直接处理用户代码错误，但它确保了 V8 引擎在处理这些操作时不会引入错误。与这段代码功能相关的常见编程错误包括：

- **整数溢出:**  用户进行大整数运算时可能发生溢出，这段代码测试了溢出标志的设置，确保 V8 能够正确处理这些情况。
- **位运算错误:** 用户在进行位运算时可能因为不理解移位操作的特性而导致错误的结果。这段代码测试了各种移位操作的指令选择，确保 V8 生成的指令能够正确执行位运算。
- **条件判断错误:** 用户在编写 `if` 语句等条件判断时，可能由于逻辑错误导致程序行为不符合预期。这段代码测试了条件分支指令的选择，确保 V8 能够正确地根据条件跳转。

**功能归纳 (第2部分):**

这部分代码主要测试了 **ARM 指令选择器对于算术和逻辑运算指令 (包括带标志位设置)、移位指令以及基于运算结果进行分支指令的选择是否正确**。它涵盖了操作数是寄存器、立即数以及移位操作的不同组合情况，并验证了生成的 ARM 指令的机器码、寻址模式、输入输出数量以及标志位设置是否符合预期。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Node* n = (m.*odpi.constructor)(
        (m.*shift.constructor)(m.Parameter(0), m.Parameter(1)), m.Parameter(2));
    m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
    Stream s = m.Build();
    ASSERT_LE(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorODPITest, BothWithShiftByImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      Node* n = (m.*odpi.constructor)(
          m.Parameter(0),
          (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm)));
      m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
      Stream s = m.Build();
      ASSERT_LE(1U, s.size());
      EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(2U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(kOverflow, s[0]->flags_condition());
    }
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      Node* n = (m.*odpi.constructor)(
          (m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm)),
          m.Parameter(1));
      m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
      Stream s = m.Build();
      ASSERT_LE(1U, s.size());
      EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(2U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(kOverflow, s[0]->flags_condition());
    }
  }
}


TEST_P(InstructionSelectorODPITest, BranchWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Branch(m.Projection(1, n), &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(0));
  m.Bind(&b);
  m.Return(m.Projection(0, n));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}


TEST_P(InstructionSelectorODPITest, BranchWithImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Int32Constant(imm));
    m.Branch(m.Projection(1, n), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(0));
    m.Bind(&b);
    m.Return(m.Projection(0, n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* n = (m.*odpi.constructor)(m.Int32Constant(imm), m.Parameter(0));
    m.Branch(m.Projection(1, n), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(0));
    m.Bind(&b);
    m.Return(m.Projection(0, n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorODPITest, BranchIfZeroWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Branch(m.Word32Equal(m.Projection(1, n), m.Int32Constant(0)), &a, &b);
  m.Bind(&a);
  m.Return(m.Projection(0, n));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kNotOverflow, s[0]->flags_condition());
}


TEST_P(InstructionSelectorODPITest, BranchIfNotZeroWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Branch(m.Word32NotEqual(m.Projection(1, n), m.Int32Constant(0)), &a, &b);
  m.Bind(&a);
  m.Return(m.Projection(0, n));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorODPITest,
                         ::testing::ValuesIn(kODPIs));

// -----------------------------------------------------------------------------
// Shifts.

using InstructionSelectorShiftTest = InstructionSelectorTestWithParam<Shift>;

TEST_P(InstructionSelectorShiftTest, Parameters) {
  const Shift shift = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return((m.*shift.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMov, s[0]->arch_opcode());
  EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_P(InstructionSelectorShiftTest, Immediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return((m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmMov, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_P(InstructionSelectorShiftTest, Word32EqualWithParameter) {
  const Shift shift = GetParam();
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Word32Equal(m.Parameter(0),
                      (m.*shift.constructor)(m.Parameter(1), m.Parameter(2))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Word32Equal((m.*shift.constructor)(m.Parameter(1), m.Parameter(2)),
                      m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorShiftTest, Word32EqualWithParameterAndImmediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32Equal(
        (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm)),
        m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32Equal(
        m.Parameter(0),
        (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorShiftTest, Word32EqualToZeroWithParameters) {
  const Shift shift = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(
      m.Word32Equal(m.Int32Constant(0),
                    (m.*shift.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMov, s[0]->arch_opcode());
  EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(2U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kEqual, s[0]->flags_condition());
}


TEST_P(InstructionSelectorShiftTest, Word32EqualToZeroWithImmediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32Equal(
        m.Int32Constant(0),
        (m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmMov, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorShiftTest, Word32BitwiseNotWithParameters) {
  const Shift shift = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Word32BitwiseNot(
      (m.*shift.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMvn, s[0]->arch_opcode());
  EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorShiftTest, Word32BitwiseNotWithImmediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32BitwiseNot(
        (m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmMvn, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorShiftTest,
       Word32AndWithWord32BitwiseNotWithParameters) {
  const Shift shift = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32(), MachineType::Int32());
  m.Return(
      m.Word32And(m.Parameter(0), m.Word32BitwiseNot((m.*shift.constructor)(
                                      m.Parameter(1), m.Parameter(2)))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmBic, s[0]->arch_opcode());
  EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
  EXPECT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorShiftTest,
       Word32AndWithWord32BitwiseNotWithImmediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32And(m.Parameter(0),
                         m.Word32BitwiseNot((m.*shift.constructor)(
                             m.Parameter(1), m.Int32Constant(imm)))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmBic, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorShiftTest,
                         ::testing::ValuesIn(kShifts));

// -----------------------------------------------------------------------------
// Memory access instructions.


namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode ldr_opcode;
  ArchOpcode str_opcode;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};


std::ostream& operator<<(std::ostream& os, const MemoryAccess& memacc) {
  return os << memacc.type;
}


const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(),
     kArmLdrsb,
     kArmStrb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Uint8(),
     kArmLdrb,
     kArmStrb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3914, -3536, -3234, -3185, -3169, -1073, -990, -859, -720, -434,
      -127, -124, -122, -105, -91, -86, -64, -55, -53, -30, -10, -3, 0, 20, 28,
      39, 58, 64, 73, 75, 100, 108, 121, 686, 963, 1363, 2759, 3449, 4095}},
    {MachineType::Int16(),
     kArmLdrsh,
     kArmStrh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-255, -251, -232, -220, -144, -138, -130, -126, -116, -115, -102, -101,
      -98, -69, -59, -56, -39, -35, -23, -19, -7, 0, 22, 26, 37, 68, 83, 87, 98,
      102, 108, 111, 117, 171, 195, 203, 204, 245, 246, 255}},
    {MachineType::Uint16(),
     kArmLdrh,
     kArmStrh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-255, -230, -201, -172, -125, -119, -118, -105, -98, -79, -54, -42, -41,
      -32, -12, -11, -5, -4, 0, 5, 9, 25, 28, 51, 58, 60, 89, 104, 108, 109,
      114, 116, 120, 138, 150, 161, 166, 172, 228, 255}},
    {MachineType::Int32(),
     kArmLdr,
     kArmStr,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -1898, -1685, -1562, -1408, -1313, -344, -128, -116, -100, -92,
      -80, -72, -71, -56, -25, -21, -11, -9, 0, 3, 5, 27, 28, 42, 52, 63, 88,
      93, 97, 125, 846, 1037, 2102, 2403, 2597, 2632, 2997, 3935, 4095}},
    {MachineType::Float32(),
     kArmVldrF32,
     kArmVstrF32,
     &InstructionSelectorTest::Stream::IsDouble,
     {-1020, -928, -896, -772, -728, -680, -660, -488, -372, -112, -100, -92,
      -84, -80, -72, -64, -60, -56, -52, -48, -36, -32, -20, -8, -4, 0, 8, 20,
      24, 40, 64, 112, 204, 388, 516, 852, 856, 976, 988, 1020}},
    {MachineType::Float64(),
     kArmVldrF64,
     kArmVstrF64,
     &InstructionSelectorTest::Stream::IsDouble,
     {-1020, -948, -796, -696, -612, -364, -320, -308, -128, -112, -108, -104,
      -96, -84, -80, -56, -48, -40, -20, 0, 24, 28, 36, 48, 64, 84, 96, 100,
      108, 116, 120, 140, 156, 408, 432, 444, 772, 832, 940, 1020}}};

}  // namespace

using InstructionSelectorMemoryAccessTest =
    InstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Offset_RR, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
}


TEST_P(InstructionSelectorMemoryAccessTest, LoadWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Offset_RI, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
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
  EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Offset_RR, s[0]->addressing_mode());
  EXPECT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(0U, s[0]->OutputCount());
}


TEST_P(InstructionSelectorMemoryAccessTest, StoreWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Offset_RI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

TEST_F(InstructionSelectorMemoryAccessTest, LoadWithShiftedIndex) {
  TRACED_FORRANGE(int, immediate_shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    MachineType::Int32());
    Node* const index =
        m.Word32Shl(m.Parameter(1), m.Int32Constant(immediate_shift));
    m.Return(m.Load(MachineType::Int32(), m.Parameter(0), index));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmLdr, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorMemoryAccessTest, StoreWithShiftedIndex) {
  TRACED_FORRANGE(int, immediate_shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    MachineType::Int32(), MachineType::Int32());
    Node* const index =
        m.Word32Shl(m.Parameter(1), m.Int32Constant(immediate_shift));
    m.Store(MachineRepresentation::kWord32, m.Parameter(0), index,
            m.Parameter(2), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmStr, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

// -----------------------------------------------------------------------------
// Conversions.


TEST_F(InstructionSelectorTest, ChangeFloat32ToFloat64WithParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float32());
  m.Return(m.ChangeFloat32ToFloat64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcvtF64F32, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, TruncateFloat64ToFloat32WithParameter) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float64());
  m.Return(m.TruncateFloat64ToFloat32(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcvtF32F64, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


// -----------------------------------------------------------------------------
// Comparisons.


namespace {

struct Comparison {
  Constructor constructor;
  const char* constructor_name;
  FlagsCondition flags_condition;
  FlagsCondition negated_flags_condition;
  FlagsCondition commuted_flags_condition;
};


std::ostream& operator<<(std::ostream& os, const Comparison& cmp) {
  return os << cmp.constructor_name;
}


const Comparison kComparisons[] = {
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kEqual, kNotEqual,
     kEqual},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan", kSignedLessThan,
     kSignedGreaterThanOrEqual, kSignedGreaterThan},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
     kSignedLessThanOrEqual, kSignedGreaterThan, kSignedGreaterThanOrEqual},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kUnsignedLessThan,
     kUnsignedGreaterThanOrEqual, kUnsignedGreaterThan},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
     kUnsignedLessThanOrEqual, kUnsignedGreaterThan,
     kUnsignedGreaterThanOrEqual}};

}  // namespace

using InstructionSelectorComparisonTest =
    InstructionSelectorTestWithParam<Comparison>;

TEST_P(InstructionSelectorComparisonTest, Parameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const r = (m.*cmp.constructor)(p0, p1);
  m.Return(r);
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->OutputAt(0)));
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorComparisonTest, Word32EqualWithZero) {
  {
    const Comparison& cmp = GetParam();
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r =
        m.Word32Equal((m.*cmp.constructor)(p0, p1), m.Int32Constant(0));
    m.Return(r);
    Stream const s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->OutputAt(0)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.negated_flags_condition, s[0]->flags_condition());
  }
  {
    const Comparison& cmp = GetParam();
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r =
        m.Word32Equal(m.Int32Constant(0), (m.*cmp.constructor)(p0, p1));
    m.Return(r);
    Stream const s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->OutputAt(0)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.negated_flags_condition, s[0]->flags_condition());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorComparisonTest,
                         ::testing::ValuesIn(kComparisons));

// -----------------------------------------------------------------------------
// Floating point comparisons.


namespace {

const Comparison kF32Comparisons[] = {
    {&RawMachineAssembler::Float32Equal, "Float32Equal", kEqual, kNotEqual,
     kEqual},
    {&RawMachineAssembler::Float32LessThan, "Float32LessThan",
     kFloatLessThan, kFloatGreaterThanOrEqualOrUnordered, kFloatGreaterThan},
    {&RawMachineAssembler::Float32LessThanOrEqual, "Float32LessThanOrEqual",
     kFloatLessThanOrEqual, kFloatGreaterThanOrUnordered,
     kFloatGreaterThanOrEqual}};

}  // namespace

using InstructionSelectorF32ComparisonTest =
    InstructionSelectorTestWithParam<Comparison>;

TEST_P(InstructionSelectorF32ComparisonTest, WithParameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float32(),
                  MachineType::Float32());
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF32ComparisonTest, NegatedWithParameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float32(),
                  MachineType::Float32());
  m.Return(
      m.Word32BinaryNot((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.negated_flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF32ComparisonTest, WithImmediateZeroOnRight) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Float32Constant(0.0)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF32ComparisonTest, WithImmediateZeroOnLeft) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
  m.Return((m.*cmp.constructor)(m.Float32Constant(0.0f), m.Parameter(0)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.commuted_flags_condition, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorF32ComparisonTest,
                         ::testing::ValuesIn(kF32Comparisons));

namespace {

const Comparison kF64Comparisons[] = {
    {&RawMachineAssembler::Float64Equal, "Float64Equal", kEqual, kNotEqual,
     kEqual},
    {&RawMachineAssembler::Float64LessThan, "Float64LessThan",
     kFloatLessThan, kFloatGreaterThanOrEqualOrUnordered, kFloatGreaterThan},
    {&RawMachineAssembler::Float64LessThanOrEqual, "Float64LessThanOrEqual",
     kFloatLessThanOrEqual, kFloatGreaterThanOrUnordered,
     kFloatGreaterThanOrEqual}};

}  // namespace

using InstructionSelectorF64ComparisonTest =
    InstructionSelectorTestWithParam<Comparison>;

TEST_P(InstructionSelectorF64ComparisonTest, WithParameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64(),
                  MachineType::Float64());
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF64, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF64ComparisonTest, NegatedWithParameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64(),
                  MachineType::Float64());
  m.Return(
      m.Word32BinaryNot((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF64, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.negated_flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF64ComparisonTest, WithImmediateZeroOnRight) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Float64Constant(0.0)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF64, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition()
```