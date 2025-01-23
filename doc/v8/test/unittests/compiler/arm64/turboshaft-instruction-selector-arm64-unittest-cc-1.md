Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of V8's turboshaft instruction selector for the ARM64 architecture.

Here's a breakdown of how to analyze the code:

1. **Identify the test fixture:** The code uses `TEST_F(TurboshaftInstructionSelectorTest, ...)` which indicates these are unit tests for the `TurboshaftInstructionSelectorTest` class. This class likely sets up the environment for testing instruction selection.

2. **Focus on individual test cases:** Each `TEST_F` block represents a specific scenario being tested. The test names often hint at the functionality being verified.

3. **Analyze `StreamBuilder` usage:**  The `StreamBuilder` class is used to construct a sequence of machine instructions. Pay attention to the methods called on it (e.g., `Word32Add`, `Word64Add`, `Branch`, `Return`, `Emit`). These represent the IR (Intermediate Representation) operations.

4. **Examine the generated `Stream`:** After building the stream with `m.Build()`, the tests make assertions about the generated instructions (`s`). Key aspects to look for are:
    - `arch_opcode()`: The specific ARM64 instruction generated (e.g., `kArm64Add`, `kArm64Tst`).
    - `addressing_mode()`: The addressing mode used by the instruction.
    - `InputCount()` and `OutputCount()`: The number of inputs and outputs of the instruction.
    - `InputAt()`:  The kind and value of the inputs (e.g., register, immediate).
    - `flags_mode()` and `flags_condition()`:  For instructions that set flags, what flags are affected and the condition code.

5. **Look for loops and ranges:** The code uses `TRACED_FOREACH` and `TRACED_FORRANGE` to test various combinations of inputs (e.g., different shift amounts, immediate values). This indicates testing the instruction selector's handling of different operand variations.

6. **Identify patterns and common themes:** Notice recurring patterns in the tests, such as testing addition with shifted operands, addition with extended operands (byte/halfword), and testing branching based on the results of logical and arithmetic operations.

7. **Consider conditional compilation (`#if V8_ENABLE_WEBASSEMBLY`):**  Some tests are specific to WebAssembly.

8. **Infer the purpose of the instruction selector:** Based on the tests, the instruction selector's goal is to translate high-level IR operations into specific ARM64 machine instructions, optimizing for factors like addressing modes and immediate values.

9. **Relate to JavaScript (if applicable):**  Think about what JavaScript operations might lead to the tested IR patterns. For example, bitwise AND in JavaScript can correspond to the `Word32BitwiseAnd` IR operation.

10. **Identify potential programming errors:** Some tests might implicitly reveal common errors. For instance, testing the modulo behavior of shift immediates highlights that programmers might use values outside the valid range.

**Applying the analysis to the provided snippet:**

- **Shifted Adds:** The code tests the selection of ARM64 `ADD` instructions with various shift operations on one of the operands. It checks if the immediate shift amount is correctly handled (modulo 64).
- **Extended Adds:**  Tests verify the selection of `ADD` instructions with byte (`UXTB`, `SXTB`) and halfword (`UXTH`, `SXTH`) extensions of one of the operands. This likely corresponds to cases where smaller integer types are used in JavaScript.
- **Fused Pairwise Adds (Wasm):** The code includes tests (under `#if V8_ENABLE_WEBASSEMBLY`) for fusing a pairwise addition operation followed by a regular addition into a single ARM64 instruction (`Sadalp`, `Uadalp`).
- **Data Processing and Flags:** Tests examine how the instruction selector handles data processing instructions that set flags, ensuring the correct flags are set for subsequent conditional branches.
- **Conditional Branches:** A significant portion of the code tests different ways to generate conditional branches based on the results of logical (`AND`), arithmetic (`ADD`, `SUB`), and comparison operations. It specifically checks for the correct ARM64 branch instructions (`Tst`, `Cmn`, `Cmp`, `CompareAndBranch`) and condition codes.
- **Test-and-Branch Optimization:**  The tests extensively cover the optimization where a bitwise AND operation followed by a branch can be combined into a single `TBZ` (Test Bit and Branch if Zero) or `TBNZ` (Test Bit and Branch if Non-Zero) instruction. It verifies different patterns of AND and comparison that can lead to this optimization.
- **Comparison with Zero:** Tests ensure that comparisons with zero are correctly translated into `CompareAndBranch` instructions when possible.
这是V8 JavaScript引擎中用于测试ARM64架构下Turboshaft编译器指令选择器的单元测试代码的第二部分。它的主要功能是**验证Turboshaft编译器能否为各种算术和逻辑运算以及条件分支生成正确的ARM64指令序列**。

具体来说，这部分代码延续了第一部分的功能，主要集中在以下几个方面：

1. **测试带有移位操作的加法指令选择:**
   - 针对32位和64位加法，测试了与移位操作（LSL, LSR, ASR, ROR）结合的情况。
   - 验证了指令选择器是否能够正确识别并生成带有移位操作数的`ADD`指令，并确保移位立即数被正确编码（取模 64）。

2. **测试带有扩展操作的加法指令选择:**
   - 针对32位和64位加法，测试了将一个操作数进行无符号字节（UXTB）、无符号半字（UXTH）、有符号字节（SXTB）、有符号半字（SXTH）扩展的情况。
   - 验证了指令选择器能够识别这些模式，并生成带有相应扩展修饰符的`ADD`指令。

3. **测试WebAssembly的成对加法（Pairwise Add）与普通加法的融合 (如果启用了WebAssembly):**
   -  针对SIMD128类型，测试了成对加法操作 (`I32x4ExtAddPairwiseI16x8S/U`, `I16x8ExtAddPairwiseI8x16S/U`) 的结果与另一个SIMD值相加的情况。
   -  验证了指令选择器可以将这两个操作融合为单个 `Sadalp` 或 `Uadalp` 指令。

4. **测试基于数据处理指令结果的条件分支:**
   - 针对可以设置标志位的指令（例如，加法、减法、位运算），测试了基于这些指令结果进行分支的情况。
   - 验证了指令选择器能够识别这种模式，并生成相应的指令，并将标志位模式设置为 `kFlags_branch`，并设置正确的条件码。

5. **测试带有立即数的按位与操作后进行条件分支:**
   - 针对32位和64位的按位与操作，其中一个操作数为立即数，测试了基于结果进行分支的情况。
   - 验证了指令选择器能够识别这种模式，并生成 `TST` 指令，并将标志位模式设置为 `kFlags_branch`。

6. **测试带有立即数的加法和减法操作后进行条件分支:**
   - 针对32位加法和减法操作，其中一个操作数为立即数，测试了基于结果进行分支的情况。
   - 验证了指令选择器能够生成 `CMN` (比较负数) 或 `CMP` (比较) 指令，并将标志位模式设置为 `kFlags_branch`。

7. **测试更复杂的按位与操作后进行条件分支的模式（Test-and-Branch优化）:**
   -  详细测试了多种形式的按位与操作（包括与操作结果的取反，以及与掩码比较），然后进行条件分支的情况。
   -  验证了指令选择器能够识别这些可以优化为 `TBZ` (Test Bit and Branch if Zero) 或 `TBNZ` (Test Bit and Branch if Non-Zero) 指令的模式。这些指令可以直接测试特定位，提高效率。

8. **测试与零比较后进行条件分支:**
   - 测试了直接基于一个Word32/Word64值进行分支（隐式与零比较）的情况。
   - 测试了显式地将一个Word32/Word64值与零进行相等或不等比较后进行分支的情况。
   - 验证了指令选择器能够生成 `CBZ` (Compare and Branch if Zero) 或 `CBNZ` (Compare and Branch if Non-Zero) 指令。

9. **测试条件比较指令:**
   -  测试了多个条件比较操作的结果进行位运算的情况。
   -  验证了指令选择器能够为第一个比较操作设置 `kFlags_conditional_set` 标志，以便后续的比较可以利用其结果。

**如果 `v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc` 以 `.tq` 结尾**

那么它是一个 V8 Torque 源代码。Torque 是一种用于定义 V8 内部函数和操作的领域特定语言。在这种情况下，该文件将包含用 Torque 编写的指令选择器的逻辑定义，而不是像当前提供的 C++ 文件那样是测试代码。

**与 JavaScript 的功能关系**

这些测试用例直接关系到 JavaScript 的底层实现。许多 JavaScript 操作最终会被编译成机器码。例如：

- **加法和移位操作:** JavaScript 的 `+` 运算符和位移运算符 (`<<`, `>>`, `>>>`) 会用到这里测试的加法和移位指令。
  ```javascript
  let a = 10;
  let b = 5;
  let sum = a + b;
  let shifted = a << 2;
  ```
- **位运算:** JavaScript 的按位与 (`&`), 按位或 (`|`), 按位异或 (`^`), 按位取反 (`~`) 等运算符会用到这里测试的位运算指令。
  ```javascript
  let mask = 0xFF;
  let result = a & mask;
  ```
- **条件语句:** JavaScript 的 `if`, `else if`, `else` 语句和三元运算符 `? :` 会用到这里测试的条件分支指令。
  ```javascript
  let x = 5;
  if (x > 0) {
    console.log("Positive");
  } else {
    console.log("Non-positive");
  }
  ```
- **WebAssembly SIMD 操作:** 如果启用了 WebAssembly，JavaScript 调用 WebAssembly 的 SIMD 指令会涉及到 `Sadalp` 和 `Uadalp` 这样的指令。

**代码逻辑推理示例**

**假设输入:**

一个包含以下中间表示（IR）操作的流：

```
Parameter(0) : Int32
Int32Constant(5)
Word32BitwiseAnd(Parameter(0), Int32Constant(5))
Block a
Block b
Branch(Word32BitwiseAnd 的结果, a, b)
Bind(a)
Int32Constant(1)
Return(Int32Constant(1))
Bind(b)
Int32Constant(0)
Return(Int32Constant(0))
```

**预期输出 (生成的 ARM64 指令流):**

```assembly
tst w[reg_of_Parameter0], #0x5  // kArm64Tst32
b.ne <address_of_block_a>      // Conditional branch if not equal to zero
b <address_of_block_b>       // Unconditional branch to block b
<address_of_block_a>:
mov w0, #1
ret
<address_of_block_b>:
mov w0, #0
ret
```

**解释:**  `Word32BitwiseAnd` 操作和随后的 `Branch` 操作被优化成一个 `tst` 指令（按位与测试）和一个条件分支指令 `b.ne`。

**用户常见的编程错误示例**

- **位运算的误用导致非预期的条件分支:**
  ```javascript
  let flags = 0b00010010;
  if (flags & 0b00000001) { // 用户可能想检查最低位是否为1
    console.log("Flag 1 is set");
  } else {
    console.log("Flag 1 is not set");
  }
  ```
  在指令选择器层面，这会涉及到测试按位与结果是否为零。如果用户错误地使用了掩码，条件分支的结果可能不是预期的。

- **整数溢出导致的错误假设:**
  ```javascript
  let maxInt32 = 2147483647;
  let result = maxInt32 + 1;
  if (result > maxInt32) { // 用户可能期望这里为真
    console.log("Overflow occurred");
  }
  ```
  在底层，整数溢出可能不会像用户期望的那样触发某些条件，指令选择器会根据实际的运算结果生成指令。

**功能归纳**

这部分 `turboshaft-instruction-selector-arm64-unittest.cc` 代码的功能是**系统地测试 Turboshaft 编译器在 ARM64 架构下指令选择的关键逻辑，特别是针对各种算术、逻辑运算以及条件分支的指令生成能力，并验证其是否能够进行有效的指令融合和优化（例如 Test-and-Branch）。** 它确保了编译器能够将高级的中间表示正确且高效地转换为底层的 ARM64 机器码，从而保证 JavaScript 代码在 ARM64 平台上能够正确、快速地执行。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
Q(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }

  // 64-bit add.
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    // Only test relevant shifted operands.
    if (shift.mi.machine_type != MachineType::Int64()) continue;
    if (shift.mi.arch_opcode == kArm64Ror) continue;

    // The available shift operand range is `0 <= imm < 64`, but we also test
    // that immediates outside this range are handled properly (modulo-64).
    TRACED_FORRANGE(int, imm, -64, 127) {
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                      MachineType::Int64());
      m.Return(
          m.Word64Add(m.Emit(shift.mi.op, m.Parameter(1), m.Int32Constant(imm)),
                      m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddUnsignedExtendByteOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Word32Add(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(0xFF)),
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
    m.Return(m.Word64Add(m.ChangeInt32ToInt64(m.Word32BitwiseAnd(
                             m.Parameter(0), m.Int32Constant(0xFF))),
                         m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddUnsignedExtendHalfwordOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Word32Add(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(0xFFFF)),
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
    m.Return(m.Word64Add(m.ChangeInt32ToInt64(m.Word32BitwiseAnd(
                             m.Parameter(0), m.Int32Constant(0xFFFF))),
                         m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddSignedExtendByteOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Word32Add(m.Word32ShiftRightArithmetic(
                        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(24)),
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
        m.Word64Add(m.ChangeInt32ToInt64(m.Word32ShiftRightArithmetic(
                        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(24)),
                        m.Int32Constant(24))),
                    m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddSignedExtendHalfwordOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Word32Add(m.Word32ShiftRightArithmetic(
                        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(16)),
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
        m.Word64Add(m.ChangeInt32ToInt64(m.Word32ShiftRightArithmetic(
                        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(16)),
                        m.Int32Constant(16))),
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

using TurboshaftInstructionSelectorAddWithPairwiseAddTest =
    TurboshaftInstructionSelectorTestWithParam<AddWithPairwiseAddSideAndWidth>;

TEST_P(TurboshaftInstructionSelectorAddWithPairwiseAddTest,
       AddWithPairwiseAdd) {
  AddWithPairwiseAddSideAndWidth params = GetParam();
  const MachineType type = MachineType::Simd128();
  StreamBuilder m(this, type, type, type, type);

  OpIndex x = m.Parameter(0);
  OpIndex y = m.Parameter(1);
  OpIndex pairwiseAdd;
  if (params.width == 32 && params.isSigned) {
    pairwiseAdd = m.I32x4ExtAddPairwiseI16x8S(x);
  } else if (params.width == 16 && params.isSigned) {
    pairwiseAdd = m.I16x8ExtAddPairwiseI8x16S(x);
  } else if (params.width == 32 && !params.isSigned) {
    pairwiseAdd = m.I32x4ExtAddPairwiseI16x8U(x);
  } else {
    pairwiseAdd = m.I16x8ExtAddPairwiseI8x16U(x);
  }

  OpIndex add;
  if (params.width == 32) {
    add = params.side == LEFT ? m.I32x4Add(pairwiseAdd, y)
                              : m.I32x4Add(y, pairwiseAdd);
  } else {
    add = params.side == LEFT ? m.I16x8Add(pairwiseAdd, y)
                              : m.I16x8Add(y, pairwiseAdd);
  }

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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorAddWithPairwiseAddTest,
                         ::testing::ValuesIn(kAddWithPairAddTestCases));
#endif  // V8_ENABLE_WEBASSEMBLY

// -----------------------------------------------------------------------------
// Data processing controlled branches.

using TurboshaftInstructionSelectorDPFlagSetTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorDPFlagSetTest, BranchWithParameters) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  Block *a = m.NewBlock(), *b = m.NewBlock();
  OpIndex cond = m.Emit(dpi.op, m.Parameter(0), m.Parameter(1));
  if (type == MachineType::Int64()) cond = m.TruncateWord64ToWord32(cond);
  m.Branch(V<Word32>::Cast(cond), a, b);
  m.Bind(a);
  m.Return(m.Int32Constant(1));
  m.Bind(b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorDPFlagSetTest,
                         ::testing::ValuesIn(kDPFlagSetInstructions));

TEST_F(TurboshaftInstructionSelectorTest, Word32AndBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint32_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(imm)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, Word64AndBranchWithImmediateOnRight) {
  TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint64_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.TruncateWord64ToWord32(
                 m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(imm))),
             a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, AddBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32Add(m.Parameter(0), m.Int32Constant(imm)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, SubBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32Sub(m.Parameter(0), m.Int32Constant(imm)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ((imm == 0) ? kArm64CompareAndBranch32 : kArm64Cmp32,
              s[0]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32AndBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint32_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32BitwiseAnd(m.Int32Constant(imm), m.Parameter(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, Word64AndBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint64_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.TruncateWord64ToWord32(
                 m.Word64BitwiseAnd(m.Int64Constant(imm), m.Parameter(0))),
             a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, AddBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32Add(m.Int32Constant(imm), m.Parameter(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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
  MachInst<
      std::function<V<Word32>(TurboshaftInstructionSelectorTest::StreamBuilder&,
                              OpIndex, uint64_t mask)>>
      mi;
  FlagsCondition cond;
};

std::ostream& operator<<(std::ostream& os, const TestAndBranch& tb) {
  return os << tb.mi;
}

const TestAndBranch kTestAndBranchMatchers32[] = {
    // Branch on the result of Word32BitwiseAnd directly.
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32BitwiseAnd(x, m.Int32Constant(mask));
      },
      "if (x and mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32BinaryNot(m.Word32BitwiseAnd(x, m.Int32Constant(mask)));
      },
      "if not (x and mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    // Branch on the result of '(x and mask) == mask'. This tests that a bit is
    // set rather than cleared which is why conditions are inverted.
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32Equal(m.Word32BitwiseAnd(x, m.Int32Constant(mask)),
                             m.Int32Constant(mask));
      },
      "if ((x and mask) == mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32BinaryNot(
            m.Word32Equal(m.Word32BitwiseAnd(x, m.Int32Constant(mask)),
                          m.Int32Constant(mask)));
      },
      "if ((x and mask) != mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32Equal(m.Int32Constant(mask),
                             m.Word32BitwiseAnd(x, m.Int32Constant(mask)));
      },
      "if (mask == (x and mask))", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32BinaryNot(
            m.Word32Equal(m.Int32Constant(mask),
                          m.Word32BitwiseAnd(x, m.Int32Constant(mask))));
      },
      "if (mask != (x and mask))", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual}};

using TurboshaftInstructionSelectorTestAndBranchTest =
    TurboshaftInstructionSelectorTestWithParam<TestAndBranch>;

TEST_P(TurboshaftInstructionSelectorTestAndBranchTest, TestAndBranch32) {
  const TestAndBranch inst = GetParam();
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(inst.mi.op(m, m.Parameter(0), mask), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorTestAndBranchTest,
                         ::testing::ValuesIn(kTestAndBranchMatchers32));

// TODO(arm64): Add the missing Word32BinaryNot test cases from the 32-bit
// version.
const TestAndBranch kTestAndBranchMatchers64[] = {
    // Branch on the result of Word64BitwiseAnd directly.
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint64_t mask) -> V<Word32> {
        return m.TruncateWord64ToWord32(
            m.Word64BitwiseAnd(x, m.Int64Constant(mask)));
      },
      "if (x and mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint64_t mask) -> V<Word32> {
        return m.Word64Equal(m.Word64BitwiseAnd(x, m.Int64Constant(mask)),
                             m.Int64Constant(0));
      },
      "if not (x and mask)", kArm64TestAndBranch, MachineType::Int64()},
     kEqual},
    // Branch on the result of '(x and mask) == mask'. This tests that a bit is
    // set rather than cleared which is why conditions are inverted.
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint64_t mask) -> V<Word32> {
        return m.Word64Equal(m.Word64BitwiseAnd(x, m.Int64Constant(mask)),
                             m.Int64Constant(mask));
      },
      "if ((x and mask) == mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint64_t mask) -> V<Word32> {
        return m.Word64Equal(m.Int64Constant(mask),
                             m.Word64BitwiseAnd(x, m.Int64Constant(mask)));
      },
      "if (mask == (x and mask))", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual}};

using TurboshaftInstructionSelectorTestAndBranchTest64 =
    TurboshaftInstructionSelectorTestWithParam<TestAndBranch>;

TEST_P(TurboshaftInstructionSelectorTestAndBranchTest64, TestAndBranch64) {
  const TestAndBranch inst = GetParam();
  // TRACED_FORRANGE(int, bit, 0, 63) {
  int bit = 0;
  uint64_t mask = uint64_t{1} << bit;
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
  Block *a = m.NewBlock(), *b = m.NewBlock();
  m.Branch(inst.mi.op(m, m.Parameter(0), mask), a, b);
  m.Bind(a);
  m.Return(m.Int64Constant(1));
  m.Bind(b);
  m.Return(m.Int64Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(inst.cond, s[0]->flags_condition());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
  EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  // }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorTestAndBranchTest64,
                         ::testing::ValuesIn(kTestAndBranchMatchers64));

TEST_F(TurboshaftInstructionSelectorTest,
       Word64AndBranchWithOneBitMaskOnRight) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.TruncateWord64ToWord32(
                 m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask))),
             a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest,
       TestAndBranch64EqualWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock(), *c = m.NewBlock();
    OpIndex n = m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask));
    m.Branch(m.Word64Equal(n, m.Int64Constant(0)), a, b);
    m.Bind(a);
    m.Branch(m.Word64Equal(n, m.Int64Constant(3)), b, c);
    m.Bind(c);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, TestAndBranch64AndWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.TruncateWord64ToWord32(
                 m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask))),
             a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(4U, s[0]->InputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, TestAndBranch32AndWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = uint32_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(mask)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(4U, s[0]->InputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word32EqualZeroAndBranchWithOneBitMask) {
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(
        m.Word32Equal(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(mask)),
                      m.Int32Constant(0)),
        a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32NotEqual(
                 m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(mask)),
                 m.Int32Constant(0)),
             a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest,
       Word64EqualZeroAndBranchWithOneBitMask) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(
        m.Word64Equal(m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask)),
                      m.Int64Constant(0)),
        a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
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
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word64NotEqual(
                 m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask)),
                 m.Int64Constant(0)),
             a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, CompareAgainstZeroAndBranch) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    V<Word32> p0 = m.Parameter(0);
    m.Branch(p0, a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word32BinaryNot(p0), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, EqualZeroAndBranch) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word32Equal(p0, m.Int32Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word32NotEqual(p0, m.Int32Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word64Equal(p0, m.Int64Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
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
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word64NotEqual(p0, m.Int64Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, ConditionalCompares) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    OpIndex a = m.Int32LessThan(m.Parameter(0), m.Parameter(1));
    OpIndex b = m.Int32LessThan(m.Parameter(0), m.Parameter(2));
    m.Return(m.Word32BitwiseAnd(a, b));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_conditional_set, s[0]->flags_mode());
    EXPECT_EQ(9U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex a = m.Word64Equal(m.Parameter(0), m.Parameter(1));
    OpIndex b = m
```