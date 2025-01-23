Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the response.

1. **Understanding the Goal:** The core request is to understand the *functionality* of the given C++ code. Specifically, it asks about its purpose within the V8 project and how it relates to instruction selection for the ARM64 architecture. The prompt also has specific sub-questions about Torque, JavaScript relationships, logic, and common errors.

2. **Initial Scan and Keywords:** Quickly scan the code for recognizable keywords and patterns. Terms like `TEST_F`, `ASSERT_EQ`, `EXPECT_EQ`, `StreamBuilder`, `Node*`, `m.Int32Add`, `m.Word32Shl`, `kArm64Cmp32`, `kArm64Add`, etc., immediately stand out. These strongly suggest unit tests. The `kArm64...` prefixes point to ARM64 specific instructions. The `InstructionSelectorTest` class name is a huge clue.

3. **Identifying the Core Functionality:** The presence of `TEST_F(InstructionSelectorTest, ...)` clearly indicates that this code defines a suite of unit tests for something related to instruction selection. The tests manipulate `Node` objects and use `StreamBuilder` to generate instruction streams, then assert that the generated instructions have the expected opcodes, addressing modes, inputs, and outputs. This confirms the code's role in verifying the correctness of the instruction selector.

4. **Answering Specific Questions:**

   * **Functionality Listing:**  Based on the identified core functionality, the first step is to list the main purposes: verifying instruction selection for arithmetic, logical, and comparison operations on ARM64. Mentioning the testing of different operand combinations (registers, immediates, shifted registers) is crucial.

   * **Torque Check:** The prompt asks about `.tq` files. A quick search within the provided code shows no `.tq` extension. Therefore, it's C++ and not Torque.

   * **JavaScript Relationship:**  Instruction selection is a core part of the compiler pipeline, which directly translates JavaScript code into machine code. Provide a simple JavaScript example and explain how the instruction selector would handle the addition operation.

   * **Code Logic Reasoning (Hypothetical Input/Output):** Choose a simple test case (e.g., `CmpImmediateOnRight`). Trace the code with a concrete example (like comparing a parameter with the immediate 5). Describe the expected ARM64 instruction (`CMP`) and its operands based on the code's assertions.

   * **Common Programming Errors:**  Instruction selection aims to prevent the generation of invalid machine code. Focus on errors the *instruction selector* prevents, such as using invalid immediate values for certain instructions. Give an example of trying to use an out-of-range immediate for a bitwise operation.

   * **Part Summary:** Since this is part 6 of 8, and the entire file seems dedicated to testing instruction selection, the summary should reiterate this and mention the specific categories of tests covered in *this* part (comparisons, flag-setting instructions, logical operations with NOT, and bitfield extraction).

5. **Structuring the Response:** Organize the information logically to make it easy to understand. Start with the main functionalities, then address the specific questions in order. Use clear headings and bullet points. For code examples, use proper formatting.

6. **Refining and Adding Detail:** After the initial draft, review and add more specific details. For instance, when discussing instruction selection, mention that it's a phase within the compiler. When giving the JavaScript example, briefly explain how the compiler processes it. For the hypothetical input/output, be precise about the register assignments (even if they are placeholders like `r0`, `r1`).

7. **Self-Correction/Refinement During the Process:**

   * **Initial thought:**  Maybe this code tests the *execution* of ARM64 instructions.
   * **Correction:**  No, the assertions are about the *generated instructions* (opcodes, operands), not their runtime behavior. This is about the *instruction selection* phase.

   * **Initial thought:**  Just list all the test cases.
   * **Refinement:**  Instead of listing every test, group them by functionality (comparisons, flag settings, etc.) for better clarity.

   * **Initial thought:** The JavaScript example should be very complex.
   * **Refinement:** Keep it simple and focused on the relevant operation (addition) to illustrate the connection to instruction selection.

By following these steps – understanding the goal, scanning for clues, identifying the core function, addressing specific questions, structuring the response, and refining the details – we can arrive at a comprehensive and accurate explanation of the provided C++ code snippet.
好的，让我们来分析一下 `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 这个文件的功能。

**主要功能归纳:**

这个 C++ 文件是 V8 JavaScript 引擎中 **ARM64 架构的指令选择器 (Instruction Selector)** 的单元测试文件。它的主要功能是 **验证指令选择器在将中间表示 (IR) 转换为 ARM64 汇编指令时的正确性。**

更具体地说，它通过编写各种测试用例来模拟不同的 IR 结构和操作，然后断言指令选择器生成的 ARM64 指令是否符合预期，包括：

* **生成的指令类型 (opcode):** 例如 `kArm64Cmp32`, `kArm64Add`, `kArm64Lsr` 等。
* **寻址模式 (addressing mode):**  例如立即数寻址，寄存器寻址，移位寄存器寻址等。
* **输入和输出操作数的数量和类型:**  例如输入是寄存器还是立即数，输出是哪个寄存器。
* **标志位设置 (flags_mode) 和条件码 (flags_condition):**  例如比较指令是否设置了标志位，以及设置了哪个条件码。

**文件中的具体测试功能:**

从代码片段中，我们可以看到以下一些测试的功能：

* **`CmpImmediateOnRight` 和 `CmpShiftByImmediateOnLeft`:** 测试比较指令 (`Cmp`, `Cmn`) 与立即数和移位操作数的组合。
* **`CmnShiftByImmediateOnLeft`:**  测试带立即数移位的负比较指令 (`Cmn`)。
* **`CmpZeroRight` 和 `CmpZeroLeft` (在 `InstructionSelectorFlagSettingTest` 中):** 测试二元运算指令（如 `Add`, `And`）结果与零进行比较的情况，验证是否可以优化为不产生结果的指令 (例如 `Cmn`, `Tst`)。
* **`ShiftedOperand`, `UsersInSameBasicBlock`, `CommuteImmediate`, `CommuteShift` (在 `InstructionSelectorFlagSettingTest` 中):**  测试当二元运算指令的结果被多个地方使用时，指令选择器的处理方式，以及立即数和移位操作数在不同位置时的处理。
* **`TstInvalidImmediate`:** 确保对于 `Tst` 指令，不会生成无效的立即数。
* **`CommuteAddsExtend`:** 测试带有扩展操作的加法指令的优化。
* **`Parameter` (在 `InstructionSelectorLogicalWithNotRHSTest` 中):** 测试逻辑运算指令 (`And`, `Or`, `Xor`) 的右操作数是 `Not` 运算结果时的优化，例如 `a & ~b` 可以优化为 `Bic` 指令。
* **`Word32BitwiseNotWithParameter`, `Word64NotWithParameter`, `Word32XorMinusOneWithParameter`, `Word64XorMinusOneWithParameter`:** 测试位取反操作的指令选择。
* **`Word32ShrWithWord32AndWithImmediate`, `Word64ShrWithWord64AndWithImmediate`, `Word32AndWithImmediateWithWord32Shr`, `Word64AndWithImmediateWithWord64Shr`:** 测试位域提取 (BitField Extract) 相关的指令选择优化，例如 `(x & mask) >> shift` 可以优化为 `Ubfx` 指令。
* **`Int32MulHighWithParameters`, `Int32MulHighWithSar`, `Int32MulHighWithAdd`, `Uint32MulHighWithShr`:** 测试 32 位有符号和无符号乘法高位结果的指令选择，以及与移位和加法操作的组合。
* **`Word32SarWithWord32Shl`:** 测试带符号位域提取指令 (`Sbfx`) 的优化。

**关于文件类型和 JavaScript 功能的关系:**

* **文件类型:**  `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是以 `.tq` 结尾的 Torque 源代码文件。

* **与 JavaScript 的功能关系:**  指令选择器是 V8 编译器（通常是 Crankshaft 或 Turbofan）的关键组成部分。它的作用是将 JavaScript 代码经过一系列编译优化后得到的中间表示 (IR) 转换成特定目标架构（这里是 ARM64）的机器码指令。

**JavaScript 例子:**

以下是一个简单的 JavaScript 例子，说明了指令选择器可能需要处理的情况：

```javascript
function addAndCompare(a, b) {
  const sum = a + b;
  return sum > 5;
}
```

当 V8 编译这个函数时，指令选择器会将 `a + b` 这个操作转换成 ARM64 的加法指令（例如 `ADD`）。然后，将 `sum > 5` 这个比较操作转换成比较指令（例如 `CMP`）以及后续的条件跳转指令。

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(InstructionSelectorTest, CmpImmediateOnRight)` 中的一个迭代为例，假设：

* `cmp.mi.arch_opcode` 是 `kArm64Cmp32` (32位比较指令)
* `imm` 是 `5`

```c++
StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
m.Return((m.*cmp.mi.constructor)(m.Parameter(0), m.Int32Constant(imm)));
Stream s = m.Build();
ASSERT_EQ(1U, s.size());
EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
EXPECT_EQ(2U, s[0]->InputCount());
EXPECT_EQ(5, s.ToInt32(s[0]->InputAt(1)));
EXPECT_EQ(1U, s[0]->OutputCount());
EXPECT_EQ(kFlags_set, s[0]->flags_mode());
EXPECT_EQ(cmp.cond, s[0]->flags_condition());
```

**假设输入:**  一个接受一个 32 位整数参数的简单函数，返回参数是否大于 5。

**预期输出 (生成的 ARM64 指令):**

1. 一个 `CMP` 指令，比较寄存器中的参数值和一个立即数 5。
    *   `opcode`: `kArm64Cmp32`
    *   `addressing_mode`: `kMode_Operand2_I` (立即数寻址)
    *   `InputCount`: 2 (寄存器中的参数，立即数 5)
    *   `InputAt(1)` (立即数): 5
    *   `flags_mode`: `kFlags_set` (设置标志位)
    *   `flags_condition`:  取决于 `cmp.cond` 的值，例如 `kGreaterThan`。

**涉及用户常见的编程错误:**

这个测试文件主要关注编译器内部的正确性，而不是直接处理用户的编程错误。但是，指令选择器的正确性对于确保用户编写的 JavaScript 代码能够被正确地编译和执行至关重要。

如果指令选择器有错误，可能会导致：

* **生成非法的 ARM64 指令:**  这会导致程序崩溃。
* **生成错误的 ARM64 指令:**  这会导致程序逻辑错误，产生意想不到的结果。
* **性能下降:**  指令选择器可能会错过一些优化机会，导致生成的代码效率低下。

**例如，一个潜在的（虽然这个测试文件可能不会直接测试）与立即数相关的编程错误是使用了超出指令允许范围的立即数。**  指令选择器的职责之一就是确保生成的指令使用的立即数是合法的，如果 JavaScript 代码中存在这样的操作，编译器需要将其转换为一系列合法的指令。

**总结第 6 部分的功能:**

这是该单元测试文件的第六部分，主要集中在以下几个方面的指令选择测试：

* **比较指令 (Cmp, Cmn) 与立即数和移位操作数的各种组合。**
* **对可以优化为不产生结果的二元运算指令进行测试，例如 `Add` 和 `And` 与零的比较。**
* **测试了当二元运算指令的结果被多个地方使用时的情况。**
* **验证了立即数和移位操作数在不同位置时的处理。**
* **确保了 `Tst` 指令不会生成无效的立即数。**
* **测试了带有扩展操作的加法指令的优化。**

总而言之，这个代码片段展示了对 ARM64 指令选择器进行细致的单元测试，以确保 V8 能够为 ARM64 架构生成正确且高效的机器码。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
arameter(0)));
        Stream s = m.Build();
        // Cmp does not support ROR shifts.
        if (shift.mi.arch_opcode == kArm64Ror32) {
          ASSERT_EQ(2U, s.size());
          continue;
        }
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
        EXPECT_EQ(shift.mode, s[0]->addressing_mode());
        EXPECT_EQ(3U, s[0]->InputCount());
        EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
        EXPECT_EQ(1U, s[0]->OutputCount());
        EXPECT_EQ(kFlags_set, s[0]->flags_mode());
        EXPECT_EQ(cmp.commuted_cond, s[0]->flags_condition());
      }
    }
  }
}

TEST_F(InstructionSelectorTest, CmnShiftByImmediateOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpEqualityInstructions) {
    TRACED_FOREACH(Shift, shift, kShiftInstructions) {
      // Only test relevant shifted operands.
      if (shift.mi.machine_type != MachineType::Int32()) continue;

      // The available shift operand range is `0 <= imm < 32`, but we also test
      // that immediates outside this range are handled properly (modulo-32).
      TRACED_FORRANGE(int, imm, -32, 63) {
        StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                        MachineType::Int32());
        Node* sub = m.Int32Sub(m.Int32Constant(0), m.Parameter(0));
        m.Return((m.*cmp.mi.constructor)(
            (m.*shift.mi.constructor)(m.Parameter(1), m.Int32Constant(imm)),
            sub));
        Stream s = m.Build();
        // Cmn does not support ROR shifts.
        if (shift.mi.arch_opcode == kArm64Ror32) {
          ASSERT_EQ(2U, s.size());
          continue;
        }
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
        EXPECT_EQ(shift.mode, s[0]->addressing_mode());
        EXPECT_EQ(3U, s[0]->InputCount());
        EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
        EXPECT_EQ(1U, s[0]->OutputCount());
        EXPECT_EQ(kFlags_set, s[0]->flags_mode());
        EXPECT_EQ(cmp.cond, s[0]->flags_condition());
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Flag-setting add and and instructions.

const IntegerCmp kBinopCmpZeroRightInstructions[] = {
    {{&RawMachineAssembler::Word32Equal, "Word32Equal", kArm64Cmp32,
      MachineType::Int32()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual},
    {{&RawMachineAssembler::Int32LessThan, "Int32LessThan", kArm64Cmp32,
      MachineType::Int32()},
     kNegative,
     kNegative},
    {{&RawMachineAssembler::Int32GreaterThanOrEqual, "Int32GreaterThanOrEqual",
      kArm64Cmp32, MachineType::Int32()},
     kPositiveOrZero,
     kPositiveOrZero},
    {{&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
      kArm64Cmp32, MachineType::Int32()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Uint32GreaterThan, "Uint32GreaterThan", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual}};

const IntegerCmp kBinop64CmpZeroRightInstructions[] = {
    {{&RawMachineAssembler::Word64Equal, "Word64Equal", kArm64Cmp,
      MachineType::Int64()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Word64NotEqual, "Word64NotEqual", kArm64Cmp,
      MachineType::Int64()},
     kNotEqual,
     kNotEqual},
    {{&RawMachineAssembler::Int64LessThan, "Int64LessThan", kArm64Cmp,
      MachineType::Int64()},
     kNegative,
     kNegative},
    {{&RawMachineAssembler::Int64GreaterThanOrEqual, "Int64GreaterThanOrEqual",
      kArm64Cmp, MachineType::Int64()},
     kPositiveOrZero,
     kPositiveOrZero},
    {{&RawMachineAssembler::Uint64LessThanOrEqual, "Uint64LessThanOrEqual",
      kArm64Cmp, MachineType::Int64()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Uint64GreaterThan, "Uint64GreaterThan", kArm64Cmp,
      MachineType::Int64()},
     kNotEqual,
     kNotEqual},
};

const IntegerCmp kBinopCmpZeroLeftInstructions[] = {
    {{&RawMachineAssembler::Word32Equal, "Word32Equal", kArm64Cmp32,
      MachineType::Int32()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual},
    {{&RawMachineAssembler::Int32GreaterThan, "Int32GreaterThan", kArm64Cmp32,
      MachineType::Int32()},
     kNegative,
     kNegative},
    {{&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
      kArm64Cmp32, MachineType::Int32()},
     kPositiveOrZero,
     kPositiveOrZero},
    {{&RawMachineAssembler::Uint32GreaterThanOrEqual,
      "Uint32GreaterThanOrEqual", kArm64Cmp32, MachineType::Int32()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual}};

struct FlagSettingInst {
  MachInst2 mi;
  ArchOpcode no_output_opcode;
};

std::ostream& operator<<(std::ostream& os, const FlagSettingInst& inst) {
  return os << inst.mi.constructor_name;
}

const FlagSettingInst kFlagSettingInstructions[] = {
    {{&RawMachineAssembler::Int32Add, "Int32Add", kArm64Add32,
      MachineType::Int32()},
     kArm64Cmn32},
    {{&RawMachineAssembler::Word32And, "Word32And", kArm64And32,
      MachineType::Int32()},
     kArm64Tst32}};

using InstructionSelectorFlagSettingTest =
    InstructionSelectorTestWithParam<FlagSettingInst>;

TEST_P(InstructionSelectorFlagSettingTest, CmpZeroRight) {
  const FlagSettingInst inst = GetParam();
  // Add with single user : a cmp instruction.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* binop = (m.*inst.mi.constructor)(m.Parameter(0), m.Parameter(1));
    m.Return((m.*cmp.mi.constructor)(binop, m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, CmpZeroLeft) {
  const FlagSettingInst inst = GetParam();
  // Test a cmp with zero on the left-hand side.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroLeftInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* binop = (m.*inst.mi.constructor)(m.Parameter(0), m.Parameter(1));
    m.Return((m.*cmp.mi.constructor)(m.Int32Constant(0), binop));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, CmpZeroOnlyUserInBasicBlock) {
  const FlagSettingInst inst = GetParam();
  // Binop with additional users, but in a different basic block.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    RawMachineLabel a, b;
    Node* binop = (m.*inst.mi.constructor)(m.Parameter(0), m.Parameter(1));
    Node* comp = (m.*cmp.mi.constructor)(binop, m.Int32Constant(0));
    m.Branch(m.Parameter(0), &a, &b);
    m.Bind(&a);
    m.Return(binop);
    m.Bind(&b);
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());  // Flag-setting instruction and branch.
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, ShiftedOperand) {
  const FlagSettingInst inst = GetParam();
  // Like the test above, but with a shifted input to the binary operator.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    RawMachineLabel a, b;
    Node* imm = m.Int32Constant(5);
    Node* shift = m.Word32Shl(m.Parameter(1), imm);
    Node* binop = (m.*inst.mi.constructor)(m.Parameter(0), shift);
    Node* comp = (m.*cmp.mi.constructor)(binop, m.Int32Constant(0));
    m.Branch(m.Parameter(0), &a, &b);
    m.Bind(&a);
    m.Return(binop);
    m.Bind(&b);
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());  // Flag-setting instruction and branch.
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(5, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, UsersInSameBasicBlock) {
  const FlagSettingInst inst = GetParam();
  // Binop with additional users, in the same basic block. We need to make sure
  // we don't try to optimise this case.
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    RawMachineLabel a, b;
    Node* binop = (m.*inst.mi.constructor)(m.Parameter(0), m.Parameter(1));
    Node* mul = m.Int32Mul(m.Parameter(0), binop);
    Node* comp = (m.*cmp.mi.constructor)(binop, m.Int32Constant(0));
    m.Branch(m.Parameter(0), &a, &b);
    m.Bind(&a);
    m.Return(mul);
    m.Bind(&b);
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(4U, s.size());  // Includes the compare and branch instruction.
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
    EXPECT_EQ(kArm64Mul32, s[1]->arch_opcode());
    EXPECT_EQ(kArm64Cmp32, s[2]->arch_opcode());
    EXPECT_EQ(kFlags_set, s[2]->flags_mode());
    EXPECT_EQ(cmp.cond, s[2]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, CommuteImmediate) {
  const FlagSettingInst inst = GetParam();
  // Immediate on left hand side of the binary operator.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    // 3 can be an immediate on both arithmetic and logical instructions.
    Node* imm = m.Int32Constant(3);
    Node* binop = (m.*inst.mi.constructor)(imm, m.Parameter(0));
    Node* comp = (m.*cmp.mi.constructor)(binop, m.Int32Constant(0));
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(3, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorFlagSettingTest, CommuteShift) {
  const FlagSettingInst inst = GetParam();
  // Left-hand side operand shifted by immediate.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    TRACED_FOREACH(Shift, shift, kShiftInstructions) {
      // Only test relevant shifted operands.
      if (shift.mi.machine_type != MachineType::Int32()) continue;

      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      Node* imm = m.Int32Constant(5);
      Node* shifted_operand = (m.*shift.mi.constructor)(m.Parameter(0), imm);
      Node* binop = (m.*inst.mi.constructor)(shifted_operand, m.Parameter(1));
      Node* comp = (m.*cmp.mi.constructor)(binop, m.Int32Constant(0));
      m.Return(comp);
      Stream s = m.Build();
      // Cmn does not support ROR shifts.
      if (inst.no_output_opcode == kArm64Cmn32 &&
          shift.mi.arch_opcode == kArm64Ror32) {
        ASSERT_EQ(2U, s.size());
        continue;
      }
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(5, s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(cmp.cond, s[0]->flags_condition());
    }
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorFlagSettingTest,
                         ::testing::ValuesIn(kFlagSettingInstructions));

TEST_F(InstructionSelectorTest, TstInvalidImmediate) {
  // Make sure we do not generate an invalid immediate for TST.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    // 5 is not a valid constant for TST.
    Node* imm = m.Int32Constant(5);
    Node* binop = m.Word32And(imm, m.Parameter(0));
    Node* comp = (m.*cmp.mi.constructor)(binop, m.Int32Constant(0));
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
    EXPECT_NE(InstructionOperand::IMMEDIATE, s[0]->InputAt(0)->kind());
    EXPECT_NE(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, CommuteAddsExtend) {
  // Extended left-hand side operand.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* extend = m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(24)),
                               m.Int32Constant(24));
    Node* binop = m.Int32Add(extend, m.Parameter(1));
    m.Return((m.*cmp.mi.constructor)(binop, m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
  }
}

// -----------------------------------------------------------------------------
// Miscellaneous

static const MachInst2 kLogicalWithNotRHSs[] = {
    {&RawMachineAssembler::Word32And, "Word32And", kArm64Bic32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64And, "Word64And", kArm64Bic,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kArm64Orn32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Or, "Word64Or", kArm64Orn,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kArm64Eon32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Xor, "Word64Xor", kArm64Eon,
     MachineType::Int64()}};

using InstructionSelectorLogicalWithNotRHSTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorLogicalWithNotRHSTest, Parameter) {
  const MachInst2 inst = GetParam();
  const MachineType type = inst.machine_type;
  // Test cases where RHS is Xor(x, -1).
  {
    StreamBuilder m(this, type, type, type);
    if (type == MachineType::Int32()) {
      m.Return((m.*inst.constructor)(
          m.Parameter(0), m.Word32Xor(m.Parameter(1), m.Int32Constant(-1))));
    } else {
      ASSERT_EQ(MachineType::Int64(), type);
      m.Return((m.*inst.constructor)(
          m.Parameter(0), m.Word64Xor(m.Parameter(1), m.Int64Constant(-1))));
    }
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    if (type == MachineType::Int32()) {
      m.Return((m.*inst.constructor)(
          m.Word32Xor(m.Parameter(0), m.Int32Constant(-1)), m.Parameter(1)));
    } else {
      ASSERT_EQ(MachineType::Int64(), type);
      m.Return((m.*inst.constructor)(
          m.Word64Xor(m.Parameter(0), m.Int64Constant(-1)), m.Parameter(1)));
    }
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // Test cases where RHS is Not(x).
  {
    StreamBuilder m(this, type, type, type);
    if (type == MachineType::Int32()) {
      m.Return((m.*inst.constructor)(m.Parameter(0),
                                     m.Word32BitwiseNot(m.Parameter(1))));
    } else {
      ASSERT_EQ(MachineType::Int64(), type);
      m.Return(
          (m.*inst.constructor)(m.Parameter(0), m.Word64Not(m.Parameter(1))));
    }
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    if (type == MachineType::Int32()) {
      m.Return((m.*inst.constructor)(m.Word32BitwiseNot(m.Parameter(0)),
                                     m.Parameter(1)));
    } else {
      ASSERT_EQ(MachineType::Int64(), type);
      m.Return(
          (m.*inst.constructor)(m.Word64Not(m.Parameter(0)), m.Parameter(1)));
    }
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorLogicalWithNotRHSTest,
                         ::testing::ValuesIn(kLogicalWithNotRHSs));

TEST_F(InstructionSelectorTest, Word32BitwiseNotWithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  m.Return(m.Word32BitwiseNot(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Not32, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(InstructionSelectorTest, Word64NotWithParameter) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
  m.Return(m.Word64Not(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Not, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(InstructionSelectorTest, Word32XorMinusOneWithParameter) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Xor(m.Parameter(0), m.Int32Constant(-1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Not32, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Xor(m.Int32Constant(-1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Not32, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, Word64XorMinusOneWithParameter) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Xor(m.Parameter(0), m.Int64Constant(-1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Not, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Xor(m.Int64Constant(-1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Not, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, Word32ShrWithWord32AndWithImmediate) {
  // The available shift operand range is `0 <= imm < 32`, but we also test
  // that immediates outside this range are handled properly (modulo-32).
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t jnk = rng()->NextInt();
      jnk = (lsb > 0) ? (jnk >> (32 - lsb)) : 0;
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Shr(m.Word32And(m.Parameter(0), m.Int32Constant(msk)),
                           m.Int32Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t jnk = rng()->NextInt();
      jnk = (lsb > 0) ? (jnk >> (32 - lsb)) : 0;
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Shr(m.Word32And(m.Int32Constant(msk), m.Parameter(0)),
                           m.Int32Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word64ShrWithWord64AndWithImmediate) {
  // The available shift operand range is `0 <= imm < 64`, but we also test
  // that immediates outside this range are handled properly (modulo-64).
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int32_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int32_t, width, 1, 64 - lsb) {
      uint64_t jnk = rng()->NextInt64();
      jnk = (lsb > 0) ? (jnk >> (64 - lsb)) : 0;
      uint64_t msk =
          ((uint64_t{0xFFFFFFFFFFFFFFFF} >> (64 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64Shr(m.Word64And(m.Parameter(0), m.Int64Constant(msk)),
                           m.Int64Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int32_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int32_t, width, 1, 64 - lsb) {
      uint64_t jnk = rng()->NextInt64();
      jnk = (lsb > 0) ? (jnk >> (64 - lsb)) : 0;
      uint64_t msk =
          ((uint64_t{0xFFFFFFFFFFFFFFFF} >> (64 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64Shr(m.Word64And(m.Int64Constant(msk), m.Parameter(0)),
                           m.Int64Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word32AndWithImmediateWithWord32Shr) {
  // The available shift operand range is `0 <= imm < 32`, but we also test
  // that immediates outside this range are handled properly (modulo-32).
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 31) {
      uint32_t msk = (1u << width) - 1;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32And(m.Word32Shr(m.Parameter(0), m.Int32Constant(shift)),
                           m.Int32Constant(msk)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      int32_t actual_width = (lsb + width > 32) ? (32 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 31) {
      uint32_t msk = (1u << width) - 1;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(
          m.Word32And(m.Int32Constant(msk),
                      m.Word32Shr(m.Parameter(0), m.Int32Constant(shift))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      int32_t actual_width = (lsb + width > 32) ? (32 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word64AndWithImmediateWithWord64Shr) {
  // The available shift operand range is `0 <= imm < 64`, but we also test
  // that immediates outside this range are handled properly (modulo-64).
  TRACED_FORRANGE(int64_t, shift, -64, 127) {
    int64_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int64_t, width, 1, 63) {
      uint64_t msk = (uint64_t{1} << width) - 1;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64And(m.Word64Shr(m.Parameter(0), m.Int64Constant(shift)),
                           m.Int64Constant(msk)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      int64_t actual_width = (lsb + width > 64) ? (64 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int64_t, shift, -64, 127) {
    int64_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int64_t, width, 1, 63) {
      uint64_t msk = (uint64_t{1} << width) - 1;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(
          m.Word64And(m.Int64Constant(msk),
                      m.Word64Shr(m.Parameter(0), m.Int64Constant(shift))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      int64_t actual_width = (lsb + width > 64) ? (64 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt64(s[0]->InputAt(2)));
    }
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
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArm64Smull, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArm64Asr, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(32, s.ToInt64(s[1]->InputAt(1)));
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[1]->Output()));
}

TEST_F(InstructionSelectorTest, Int32MulHighWithSar) {
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const n = m.Word32Sar(m.Int32MulHigh(p0, p1), m.Int32Constant(shift));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Smull, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kArm64Asr, s[1]->arch_opcode());
    ASSERT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
    EXPECT_EQ((shift & 0x1F) + 32, s.ToInt64(s[1]->InputAt(1)));
    ASSERT_EQ(1U, s[1]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[1]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Int32MulHighWithAdd) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const a = m.Int32Add(m.Int32MulHigh(p0, p1), p0);
  // Test only one shift constant here, as we're only interested in it being a
  // 32-bit operation; the shift amount is irrelevant.
  Node* const n = m.Word32Sar(a, m.Int32Constant(1));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArm64Smull, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArm64Add, s[1]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_ASR_I, s[1]->addressing_mode());
  ASSERT_EQ(3U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(32, s.ToInt64(s[1]->InputAt(2)));
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArm64Asr32, s[2]->arch_opcode());
  ASSERT_EQ(2U, s[2]->InputCount());
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(1, s.ToInt64(s[2]->InputAt(1)));
  ASSERT_EQ(1U, s[2]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[2]->Output()));
}

TEST_F(InstructionSelectorTest, Uint32MulHighWithShr) {
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const n =
        m.Word32Shr(m.Uint32MulHigh(p0, p1), m.Int32Constant(shift));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Umull, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kArm64Lsr, s[1]->arch_opcode());
    ASSERT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
    EXPECT_EQ((shift & 0x1F) + 32, s.ToInt64(s[1]->InputAt(1)));
    ASSERT_EQ(1U, s[1]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[1]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word32SarWithWord32Shl) {
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(shift)),
                                m.Int32Constant(shift));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sbfx32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(shift + 32)),
                                m.Int32Constant(shift + 64));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sbfx32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]
```