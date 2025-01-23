Response:
The user wants to understand the functionality of the provided C++ code snippet. This code is part of the V8 JavaScript engine and seems to be a unit test file for the Turboshaft instruction selector on the ARM64 architecture.

Here's a breakdown of the thought process:

1. **Identify the file type and purpose:** The file name `turboshaft-instruction-selector-arm64-unittest.cc` strongly suggests it's a unit test for the instruction selector component of Turboshaft (V8's new compiler pipeline) targeting ARM64. The `.cc` extension confirms it's C++ code.

2. **Analyze the code structure:** The code consists of multiple `TEST_F` blocks. This is a common pattern in Google Test, indicating individual test cases. Each test case appears to focus on verifying the instruction selection for a specific operation or a combination of operations.

3. **Understand the test setup:** Each `TEST_F` block typically starts by creating a `StreamBuilder` object. This object seems to be a helper class for constructing a sequence of intermediate operations. The `MachineType` arguments to the `StreamBuilder` likely define the input and output types of the code being tested. `OpIndex` represents an index to an operation within the stream.

4. **Decipher the operations being tested:** The code uses methods like `Word64BitwiseAnd`, `Word64ShiftRightLogical`, `Int32Constant`, `Word32MulOverflownBits`, `Word32ShiftRightArithmetic`, `Word32Add`, `Uint32MulOverflownBits`, `Word32ShiftLeft`, `Word32CountLeadingZeros`, `Float32Abs`, `Float64Abs`, `Float32Sub`, `Float64Sub`, `Float64Max`, `Float64Min`, `Float32Negate`, `Float64Negate`, `Float32Mul`, `Float64Mul`, `Load`, `Branch`, `Emit`, `Float64ExtractHighWord32`, `ExternalConstant`, `Call`, `UndefinedConstant`, `Simd128Splat`. These methods correspond to different intermediate representation (IR) operations in V8's compiler.

5. **Interpret the assertions:** The `ASSERT_EQ` and `EXPECT_EQ` statements are standard Google Test assertions. They check if the generated instruction stream (`Stream s`) matches the expected output. The assertions check properties like the number of instructions (`s.size()`), the generated ARM64 opcode (`s[0]->arch_opcode()`), the number of inputs (`s[0]->InputCount()`), and the values of the operands (`s.ToInt64(s[0]->InputAt(1))`, `s.ToVreg(...)`).

6. **Infer the functionality of individual tests:** By looking at the operations and the assertions, we can deduce the purpose of each test. For instance, the `Word64ShiftRightLogicalAndMasking` tests verify that the instruction selector correctly translates a right shift followed by a bitwise AND (masking) into a single `kArm64Ubfx` instruction (unsigned bitfield extract).

7. **Address specific user questions:**

    * **File type:**  The code ends with `.cc`, so it's a C++ source file, not a Torque file.
    * **Relationship to JavaScript:** While this C++ code isn't directly JavaScript, it tests the compilation of JavaScript code. V8 compiles JavaScript into machine code, and this test file verifies the correctness of the instruction selection phase during that compilation for specific ARM64 instructions.
    * **JavaScript example:** We need to find a JavaScript snippet that would result in the IR operations being tested. For example, the `Word64ShiftRightLogicalAndMasking` test involves a right shift and a bitwise AND.
    * **Code logic inference:** We can analyze a test case, like `Word64ShiftRightLogicalAndMasking`, and determine the expected input and output based on the operations and assertions.
    * **Common programming errors:** The tests often cover scenarios where the compiler might optimize or combine operations. A common mistake could be manually implementing such optimizations in JavaScript, which might hinder the compiler's ability to generate efficient code.
    * **Overall functionality:** Based on the individual tests, the file's overall purpose is to ensure the Turboshaft instruction selector correctly translates various IR operations into efficient ARM64 machine code sequences.

8. **Structure the answer:**  Organize the findings into clear sections addressing each of the user's requests. Start with the general functionality and then provide specific examples and explanations.

9. **Review and refine:** Double-check the interpretations and examples for accuracy and clarity. Ensure the explanation of common programming errors is relevant to the tested scenarios.
好的，让我们来分析一下这个V8源代码文件的功能。

**文件功能概要**

`v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc` 是 V8 JavaScript 引擎中 Turboshaft 编译器管道针对 ARM64 架构的指令选择器组件的单元测试文件。

**详细功能分解**

该文件包含了一系列独立的测试用例（通过 `TEST_F` 宏定义），每个测试用例旨在验证指令选择器对于特定中间表示 (IR) 操作或操作组合是否能生成正确的 ARM64 汇编指令。

以下是代码片段中涵盖的一些主要功能和测试点：

1. **位域提取 (Bitfield Extract):**
   - 测试 `Word64ShiftRightLogical` 后跟 `Word64BitwiseAnd` 是否能被优化为 `kArm64Ubfx` 指令。
   - 涵盖了不同的移位量和位域宽度，包括边界情况和超出正常范围的值（验证是否按模 64 处理）。

2. **带符号和无符号 32 位乘法高位 (Mul High):**
   - 测试 `Int32MulOverflownBits` (带符号乘法高位) 是否生成 `kArm64Smull` 和 `kArm64Asr` 指令序列。
   - 测试 `Uint32MulOverflownBits` (无符号乘法高位) 是否生成 `kArm64Umull` 和 `kArm64Lsr` 指令序列。
   - 验证了与算术右移 (`Word32ShiftRightArithmetic`) 和加法 (`Word32Add`) 结合使用时的指令选择。

3. **位移操作的组合优化:**
   - 测试算术右移 (`Word32ShiftRightArithmetic`) 紧跟逻辑左移 (`Word32ShiftLeft`) 是否能被优化为 `kArm64Sbfx32` (带符号位域提取) 指令。
   - 测试逻辑右移 (`Word32ShiftRightLogical`) 紧跟逻辑左移 (`Word32ShiftLeft`) 是否能被优化为 `kArm64Ubfx32` (无符号位域提取) 指令。
   - 测试逻辑左移 (`Word32ShiftLeft`) 紧跟按位与 (`Word32BitwiseAnd`) 是否能被优化为 `kArm64Ubfiz32` 指令。

4. **其他整数运算:**
   - 测试 `Word32CountLeadingZeros` 是否生成 `kArm64Clz32` 指令。

5. **浮点运算:**
   - 测试绝对值 (`Float32Abs`, `Float64Abs`) 是否生成 `kArm64Float32Abs`, `kArm64Float64Abs` 指令。
   - 测试绝对差 (`Float32Abd`, `Float64Abd`) 是否生成 `kArm64Float32Abd`, `kArm64Float64Abd` 指令。
   - 测试最大值 (`Float64Max`) 和最小值 (`Float64Min`) 是否生成 `kArm64Float64Max`, `kArm64Float64Min` 指令。
   - 测试取反 (`Float32Negate`, `Float64Negate`) 是否生成 `kArm64Float32Neg`, `kArm64Float64Neg` 指令。
   - 测试带取反的乘法 (`Float32Negate` + `Float32Mul` 或 `Float32Mul` + `Float32Negate`) 是否能优化为 `kArm64Float32Fnmul` 指令。
   - 测试双精度浮点数的符号位提取和比较。

6. **加载和移位:**
   - 测试从内存加载 64 位值后进行算术右移 (`Word64ShiftRightArithmetic`) 是否生成 `kArm64Ldrsw` 指令。

7. **与零比较:**
   - 测试各种与零比较的条件 (`kBinopCmpZeroRightInstructions`, `kBinop64CmpZeroRightInstructions`) 是否生成 `kArm64TestAndBranch32`/`kArm64TestAndBranch` 或 `kArm64CompareAndBranch32`/`kArm64CompareAndBranch` 指令。

8. **外部引用加载:**
   - 测试从外部引用加载值是否生成 `kArm64Ldr` 指令，并验证是否能使用 `kMode_Root` 寻址模式进行优化。

9. **函数调用参数准备 (`PokePair`):**
   - 测试在函数调用前准备参数时，是否能正确生成 `kArm64PokePair` 和 `kArm64Poke` 指令，特别是对于不同类型的参数（整数、浮点数、混合类型）。

10. **SIMD (WebAssembly):**
    - 测试 SIMD 向量与零比较的指令选择。

**关于文件类型和 JavaScript 关系**

该文件以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 文件。

虽然它是 C++ 代码，但它直接关系到 JavaScript 的功能。V8 引擎负责执行 JavaScript 代码，而 Turboshaft 是其编译管道的一部分。这个单元测试文件确保了 Turboshaft 编译器能够将某些 JavaScript 操作（或者更准确地说，这些操作在编译过程中生成的中间表示）正确地转换为高效的 ARM64 机器码指令。

**JavaScript 示例**

以下是一些 JavaScript 代码示例，它们可能导致测试用例中涉及的 IR 操作：

* **位域提取:**
  ```javascript
  function bitfieldExtract(x, shift, width) {
    return (x >>> shift) & ((1 << width) - 1);
  }
  ```

* **带符号和无符号 32 位乘法高位:**
  ```javascript
  function signedMulHigh(a, b) {
    return Math.imul(a, b); // Math.imul returns the lower 32 bits, so the high bits are implicitly involved
  }

  function unsignedMulHigh(a, b) {
    const low = (a & 0xFFFF) * (b & 0xFFFF);
    const high = (a >>> 16) * (b >>> 16);
    const mid = (a & 0xFFFF) * (b >>> 16) + (a >>> 16) * (b & 0xFFFF);
    return (high + (mid >>> 16)) >>> 0;
  }
  ```

* **浮点运算:**
  ```javascript
  function floatOps(a, b) {
    return {
      absA: Math.abs(a),
      abd: Math.abs(a - b),
      max: Math.max(a, b),
      min: Math.min(a, b),
      negA: -a,
      negMul: -(a * b)
    };
  }
  ```

* **与零比较:**
  ```javascript
  function compareZero(x) {
    if (x > 0) return 1;
    if (x < 0) return -1;
    if (x >= 0) return 2;
    if (x <= 0) return -2;
    if (x == 0) return 0;
    if (x != 0) return 3;
  }
  ```

**代码逻辑推理 - `Word64ShiftRightLogicalAndMasking` 示例**

**假设输入:**

* `Parameter(0)` (输入值): 一个 64 位整数，例如 `0xFFFFFFFFFFFFFFFF`
* `shift`: 一个 32 位整数，例如 `5`
* `width`: 一个 64 位整数，例如 `10`

**操作序列:**

1. `m.Word64ShiftRightLogical(m.Parameter(0), m.Int32Constant(shift))`：将输入值右移 `shift` 位。例如，`0xFFFFFFFFFFFFFFFF >>> 5` 结果为 `0x7FFFFFFFFFFFFFFF`.
2. `m.Word64BitwiseAnd(..., m.Int64Constant(msk))`：将移位后的结果与掩码 `msk` 进行按位与操作。 `msk` 的计算是 `(uint64_t{1} << width) - 1`，例如，如果 `width` 是 10，则 `msk` 是 `0x3FF`。

**预期输出:**

生成的 ARM64 指令应该是 `kArm64Ubfx` (unsigned bitfield extract)。

* `s[0]->InputAt(0)` (源寄存器): 对应于 `Parameter(0)`。
* `s.ToInt64(s[0]->InputAt(1))` (起始位): 应该等于 `shift & 0x3F`，即 `5`。
* `s.ToInt64(s[0]->InputAt(2))` (宽度): 应该等于 `width`，即 `10`。

**涉及用户常见的编程错误**

* **手动进行位域提取的优化:** 开发者可能会尝试手动使用位运算来提取位域，例如 `(x >>> shift) & mask`。Turboshaft 的指令选择器会尝试将这种模式识别并优化为更高效的 `ubfx` 指令。如果开发者过度优化，可能会使代码难以理解，并且可能阻止编译器进行进一步的优化。

* **不理解移位操作的边界行为:** ARM64 的移位操作只使用移位量的低 6 位（对于 64 位值）或低 5 位（对于 32 位值）。测试用例中使用了超出正常范围的移位值（例如 `-64`, `127`）来验证编译器是否正确处理了模 64 的行为。程序员可能会错误地假设移位操作会产生不同的结果，导致逻辑错误。

* **在浮点数比较中忽略 NaN:** 浮点数的比较需要特别注意 `NaN` (Not a Number)。例如，`NaN` 不等于自身。测试用例中对浮点数最大值和最小值进行了测试，这些操作需要正确处理 `NaN` 的情况。用户可能会编写不处理 `NaN` 的比较代码，导致意外行为。

**第7部分功能归纳**

作为 8 个部分中的第 7 部分，此代码片段主要关注以下指令选择的测试：

* **更复杂的位运算组合的优化**，特别是涉及位移和掩码操作，旨在利用 ARM64 架构提供的位域提取指令。
* **带符号和无符号乘法高位的指令选择**，确保在需要获取乘法结果的高位时能生成正确的指令序列。
* **与其他算术运算结合时的指令选择**，例如乘法高位与移位或加法操作的组合。
* **持续覆盖各种数据类型的运算**，包括整数和浮点数，并针对不同的操作（绝对值、绝对差、最大值、最小值、取反等）进行测试。
* **开始涉及更底层的操作**，例如内存加载和与外部引用的交互。
* **初步涉及函数调用参数准备的指令选择**，这是生成正确函数调用序列的关键部分。
* **开始测试 WebAssembly 特有的 SIMD 指令的指令选择**。

总的来说，这部分测试更加深入和具体，涵盖了编译器优化的一些关键场景，并开始触及与内存交互和函数调用相关的指令选择。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
htLogical) {
  // The available shift operand range is `0 <= imm < 64`, but we also test
  // that immediates outside this range are handled properly (modulo-64).
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int64_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int64_t, width, 1, 63) {
      uint64_t msk = (uint64_t{1} << width) - 1;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64BitwiseAnd(
          m.Word64ShiftRightLogical(m.Parameter(0), m.Int32Constant(shift)),
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
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int64_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int64_t, width, 1, 63) {
      uint64_t msk = (uint64_t{1} << width) - 1;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64BitwiseAnd(
          m.Int64Constant(msk),
          m.Word64ShiftRightLogical(m.Parameter(0), m.Int32Constant(shift))));
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

TEST_F(TurboshaftInstructionSelectorTest, Word32MulHighWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Int32MulOverflownBits(p0, p1);
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

TEST_F(TurboshaftInstructionSelectorTest, Word32MulHighWithSar) {
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const n = m.Word32ShiftRightArithmetic(
        m.Int32MulOverflownBits(p0, p1), m.Int32Constant(shift));
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

TEST_F(TurboshaftInstructionSelectorTest, Word32MulHighWithAdd) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const a = m.Word32Add(m.Int32MulOverflownBits(p0, p1), p0);
  // Test only one shift constant here, as we're only interested in it being a
  // 32-bit operation; the shift amount is irrelevant.
  OpIndex const n = m.Word32ShiftRightArithmetic(a, m.Int32Constant(1));
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

TEST_F(TurboshaftInstructionSelectorTest, Uint32MulHighWithShr) {
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const n = m.Word32ShiftRightLogical(
        m.Uint32MulOverflownBits(p0, p1), m.Int32Constant(shift));
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

TEST_F(TurboshaftInstructionSelectorTest, Word32SarWithWord32Shl) {
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(p0, m.Int32Constant(shift)), m.Int32Constant(shift));
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
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(p0, m.Int32Constant(shift + 32)),
        m.Int32Constant(shift + 64));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sbfx32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word32ShiftRightLogicalWithWord32Shl) {
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftRightLogical(
        m.Word32ShiftLeft(p0, m.Int32Constant(shift)), m.Int32Constant(shift));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftRightLogical(
        m.Word32ShiftLeft(p0, m.Int32Constant(shift + 32)),
        m.Int32Constant(shift + 64));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32ShlWithWord32And) {
  TRACED_FORRANGE(int32_t, shift, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftLeft(
        m.Word32BitwiseAnd(p0, m.Int32Constant((1 << (31 - shift)) - 1)),
        m.Int32Constant(shift));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ubfiz32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  TRACED_FORRANGE(int32_t, shift, 0, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftLeft(
        m.Word32BitwiseAnd(p0, m.Int32Constant((1u << (31 - shift)) - 1)),
        m.Int32Constant(shift + 1));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Lsl32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Word32CountLeadingZeros(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Clz32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float32Abs) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Float32Abs(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float32Abs, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Abs) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Float64Abs(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Abs, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float32Abd) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const fsub = m.Float32Sub(p0, p1);
  OpIndex const fabs = m.Float32Abs(fsub);
  m.Return(fabs);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float32Abd, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(fabs), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Abd) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const fsub = m.Float64Sub(p0, p1);
  OpIndex const fabs = m.Float64Abs(fsub);
  m.Return(fabs);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Abd, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(fabs), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Max) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Float64Max(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Max, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Min) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Float64Min(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Min, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float32Neg) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Float32Negate(m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float32Neg, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Neg) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Float64Negate(m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Neg, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float32NegWithMul) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n1 = m.Float32Mul(p0, p1);
  OpIndex const n2 = m.Float32Negate(n1);
  m.Return(n2);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float32Fnmul, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n2), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64NegWithMul) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n1 = m.Float64Mul(p0, p1);
  OpIndex const n2 = m.Float64Negate(n1);
  m.Return(n2);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Fnmul, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n2), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float32MulWithNeg) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n1 = m.Float32Negate(p0);
  OpIndex const n2 = m.Float32Mul(n1, p1);
  m.Return(n2);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float32Fnmul, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n2), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64MulWithNeg) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n1 = m.Float64Negate(p0);
  OpIndex const n2 = m.Float64Mul(n1, p1);
  m.Return(n2);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Fnmul, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n2), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAndShiftRight) {
  {
    int32_t immediates[] = {-256, -255, -3,   -2,   -1,    0,    1,
                            2,    3,    255,  256,  260,   4096, 4100,
                            8192, 8196, 3276, 3280, 16376, 16380};
    TRACED_FOREACH(int32_t, index, immediates) {
      StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer());
      OpIndex const load = m.Load(MachineType::Uint64(), m.Parameter(0),
                                  m.Int64Constant(index - 4));
      OpIndex const sar =
          m.Word64ShiftRightArithmetic(load, m.Int32Constant(32));
      // Make sure we don't fold the shift into the following add:
      m.Return(m.Word64Add(sar, m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kArm64Ldrsw, s[0]->arch_opcode());
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      EXPECT_EQ(2U, s[0]->InputCount());
      EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
      ASSERT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CompareAgainstZero32) {
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const param = m.Parameter(0);
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Emit<Word32>(cmp.mi.op, param, m.Int32Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(s.ToVreg(param), s.ToVreg(s[0]->InputAt(0)));
    if (cmp.cond == kNegative || cmp.cond == kPositiveOrZero) {
      EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
      EXPECT_EQ(4U, s[0]->InputCount());  // The labels are also inputs.
      EXPECT_EQ((cmp.cond == kNegative) ? kNotEqual : kEqual,
                s[0]->flags_condition());
      EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(31, s.ToInt32(s[0]->InputAt(1)));
    } else {
      EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
      EXPECT_EQ(3U, s[0]->InputCount());  // The labels are also inputs.
      EXPECT_EQ(cmp.cond, s[0]->flags_condition());
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CompareAgainstZero64) {
  TRACED_FOREACH(IntegerCmp, cmp, kBinop64CmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const param = m.Parameter(0);
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Emit<Word32>(cmp.mi.op, param, m.Int64Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(s.ToVreg(param), s.ToVreg(s[0]->InputAt(0)));
    if (cmp.cond == kNegative || cmp.cond == kPositiveOrZero) {
      EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
      EXPECT_EQ(4U, s[0]->InputCount());  // The labels are also inputs.
      EXPECT_EQ((cmp.cond == kNegative) ? kNotEqual : kEqual,
                s[0]->flags_condition());
      EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(63, s.ToInt32(s[0]->InputAt(1)));
    } else {
      EXPECT_EQ(kArm64CompareAndBranch, s[0]->arch_opcode());
      EXPECT_EQ(3U, s[0]->InputCount());  // The labels are also inputs.
      EXPECT_EQ(cmp.cond, s[0]->flags_condition());
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CompareFloat64HighLessThanZero64) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  OpIndex const param = m.Parameter(0);
  OpIndex const high = m.Float64ExtractHighWord32(param);
  Block *a = m.NewBlock(), *b = m.NewBlock();
  m.Branch(m.Int32LessThan(high, m.Int32Constant(0)), a, b);
  m.Bind(a);
  m.Return(m.Int32Constant(1));
  m.Bind(b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArm64U64MoveFloat64, s[0]->arch_opcode());
  EXPECT_EQ(kArm64TestAndBranch, s[1]->arch_opcode());
  EXPECT_EQ(kNotEqual, s[1]->flags_condition());
  EXPECT_EQ(4U, s[1]->InputCount());
  EXPECT_EQ(InstructionOperand::IMMEDIATE, s[1]->InputAt(1)->kind());
  EXPECT_EQ(63, s.ToInt32(s[1]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest,
       CompareFloat64HighGreaterThanOrEqualZero64) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  OpIndex const param = m.Parameter(0);
  OpIndex const high = m.Float64ExtractHighWord32(param);
  Block *a = m.NewBlock(), *b = m.NewBlock();
  m.Branch(m.Int32GreaterThanOrEqual(high, m.Int32Constant(0)), a, b);
  m.Bind(a);
  m.Return(m.Int32Constant(1));
  m.Bind(b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArm64U64MoveFloat64, s[0]->arch_opcode());
  EXPECT_EQ(kArm64TestAndBranch, s[1]->arch_opcode());
  EXPECT_EQ(kEqual, s[1]->flags_condition());
  EXPECT_EQ(4U, s[1]->InputCount());
  EXPECT_EQ(InstructionOperand::IMMEDIATE, s[1]->InputAt(1)->kind());
  EXPECT_EQ(63, s.ToInt32(s[1]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, ExternalReferenceLoad1) {
  // Test offsets we can use kMode_Root for.
  const int64_t kOffsets[] = {0, 1, 4, INT32_MIN, INT32_MAX};
  TRACED_FOREACH(int64_t, offset, kOffsets) {
    StreamBuilder m(this, MachineType::Int64());
    ExternalReference reference =
        base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
    OpIndex const value =
        m.Load(MachineType::Int64(), m.ExternalConstant(reference));
    m.Return(value);

    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldr, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Root, s[0]->addressing_mode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToInt64(s[0]->InputAt(0)), offset);
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, ExternalReferenceLoad2) {
  // Offset too large, we cannot use kMode_Root.
  StreamBuilder m(this, MachineType::Int64());
  int64_t offset = 0x100000000;
  ExternalReference reference =
      base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
  OpIndex const value =
      m.Load(MachineType::Int64(), m.ExternalConstant(reference));
  m.Return(value);

  Stream s = m.Build();

  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Ldr, s[0]->arch_opcode());
  EXPECT_NE(kMode_Root, s[0]->addressing_mode());
}

namespace {
// Builds a call with the specified signature and nodes as arguments.
// Then checks that the correct number of kArm64Poke and kArm64PokePair were
// generated.
void TestPokePair(TurboshaftInstructionSelectorTest::StreamBuilder* m,
                  Zone* zone, MachineSignature::Builder* builder,
                  base::Vector<const OpIndex> args, int expected_poke_pair,
                  int expected_poke) {
  auto call_descriptor = TurboshaftInstructionSelectorTest::StreamBuilder::
      MakeSimpleTSCallDescriptor(zone, builder->Get());

  OpIndex callee = m->Int64Constant(0);
  m->Call(callee, OpIndex::Invalid(), args, call_descriptor);
  m->Return(m->UndefinedConstant());

  auto s = m->Build();
  int num_poke_pair = 0;
  int num_poke = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i]->arch_opcode() == kArm64PokePair) {
      num_poke_pair++;
    }

    if (s[i]->arch_opcode() == kArm64Poke) {
      num_poke++;
    }
  }

  EXPECT_EQ(expected_poke_pair, num_poke_pair);
  EXPECT_EQ(expected_poke, num_poke);
}
}  // namespace

TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsInt32) {
  {
    MachineSignature::Builder builder(zone(), 0, 3);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());

    StreamBuilder m(this, MachineType::AnyTagged());
    OpIndex nodes[] = {
        m.Int32Constant(0),
        m.Int32Constant(0),
        m.Int32Constant(0),
    };

    const int expected_poke_pair = 1;
    // Note: The `+ 1` here comes from the padding Poke in
    // EmitPrepareArguments.
    const int expected_poke = 1 + 1;

    TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
                 expected_poke_pair, expected_poke);
  }

  {
    MachineSignature::Builder builder(zone(), 0, 4);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());

    StreamBuilder m(this, MachineType::AnyTagged());
    OpIndex nodes[] = {
        m.Int32Constant(0),
        m.Int32Constant(0),
        m.Int32Constant(0),
        m.Int32Constant(0),
    };

    const int expected_poke_pair = 2;
    const int expected_poke = 0;

    TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
                 expected_poke_pair, expected_poke);
  }
}

TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsInt64) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());

  StreamBuilder m(this, MachineType::AnyTagged());
  OpIndex nodes[] = {
      m.Int64Constant(0),
      m.Int64Constant(0),
      m.Int64Constant(0),
      m.Int64Constant(0),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
               expected_poke_pair, expected_poke);
}

TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsFloat32) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());

  StreamBuilder m(this, MachineType::AnyTagged());
  OpIndex nodes[] = {
      m.Float32Constant(0.0f),
      m.Float32Constant(0.0f),
      m.Float32Constant(0.0f),
      m.Float32Constant(0.0f),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
               expected_poke_pair, expected_poke);
}

TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsFloat64) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());

  StreamBuilder m(this, MachineType::AnyTagged());
  OpIndex nodes[] = {
      m.Float64Constant(0.0f),
      m.Float64Constant(0.0f),
      m.Float64Constant(0.0f),
      m.Float64Constant(0.0f),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
               expected_poke_pair, expected_poke);
}

TEST_F(TurboshaftInstructionSelectorTest,
       PokePairPrepareArgumentsIntFloatMixed) {
  {
    MachineSignature::Builder builder(zone(), 0, 4);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Float32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Float32());

    StreamBuilder m(this, MachineType::AnyTagged());
    OpIndex nodes[] = {
        m.Int32Constant(0),
        m.Float32Constant(0.0f),
        m.Int32Constant(0),
        m.Float32Constant(0.0f),
    };

    const int expected_poke_pair = 0;
    const int expected_poke = 4;

    TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
                 expected_poke_pair, expected_poke);
  }

  {
    MachineSignature::Builder builder(zone(), 0, 7);
    builder.AddParam(MachineType::Float32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Float64());
    builder.AddParam(MachineType::Int64());
    builder.AddParam(MachineType::Float64());
    builder.AddParam(MachineType::Float64());

    StreamBuilder m(this, MachineType::AnyTagged());
    OpIndex nodes[] = {m.Float32Constant(0.0f), m.Int32Constant(0),
                       m.Int32Constant(0),      m.Float64Constant(0.0f),
                       m.Int64Constant(0),      m.Float64Constant(0.0f),
                       m.Float64Constant(0.0f)};

    const int expected_poke_pair = 2;

    // Note: The `+ 1` here comes from the padding Poke in
    // EmitPrepareArguments.
    const int expected_poke = 3 + 1;

    TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
                 expected_poke_pair, expected_poke);
  }
}

#if V8_ENABLE_WEBASSEMBLY
TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsSimd128) {
  MachineSignature::Builder builder(zone(), 0, 2);
  builder.AddParam(MachineType::Simd128());
  builder.AddParam(MachineType::Simd128());

  StreamBuilder m(this, MachineType::AnyTagged());
  OpIndex nodes[] = {
      m.Simd128Splat(m.Int32Constant(0), Simd128SplatOp::Kind::kI32x4),
      m.Simd128Splat(m.Int32Constant(0), Simd128SplatOp::Kind::kI32x4)};

  const int expected_poke_pair = 0;
  const int expected_poke = 2;

  // Using kArm64PokePair is not currently supported for Simd128.
  TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
               expected_poke_pair, expected_poke);
}

struct SIMDConstZeroCmTest {
  const bool is_zero;
  const uint8_t lane_size;
  TSBinop cm_operator;
  const ArchOpcode expected_op_left;
  const ArchOpcode expected_op_right;
  const size_t size;
};

static const SIMDConstZeroCmTest SIMDConstZeroCmTests[] = {
    {true, 8, TSBinop::kI8x16Eq, kArm64IEq, kArm64IEq, 1},
    {true, 8, TSBinop::kI8x16Ne, kArm64INe, kArm64INe, 1},
    {true, 8, TSBinop::kI8x16GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 8, TSBinop::kI8x16GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 8, TSBinop::kI8x16Eq, kArm64IEq, kArm64IEq, 2},
    {false, 8, TSBinop::kI8x16Ne, kArm64INe, kArm64INe, 2},
    {false, 8, TSBinop::kI8x16GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 8, TSBinop::kI8x16GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 16, TSBinop::kI16x8Eq, kArm64IEq, kArm64IEq, 1},
    {true, 16, TSBinop::kI16x8Ne, kArm64INe, kArm64INe, 1},
    {true, 16, TSBinop::kI16x8GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 16, TSBinop::kI16x8GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 16, TSBinop::kI16x8Eq, kArm64IEq, kArm64IEq, 2},
```