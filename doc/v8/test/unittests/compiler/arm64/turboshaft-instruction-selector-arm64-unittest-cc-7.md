Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understanding the Context:** The first step is to recognize the file path: `v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc`. This immediately tells us:
    * It's a *test* file.
    * Specifically, it's a *unit test*.
    * It targets the *compiler* component of V8.
    * It focuses on the *ARM64* architecture.
    * It tests the *instruction selector* within the *Turboshaft* compiler pipeline.

2. **Identifying the Core Functionality:**  The file name itself provides strong hints. An "instruction selector" takes high-level intermediate representations of code and translates them into low-level machine instructions for a specific architecture (ARM64 in this case). The "unittest" part means this code is designed to verify that the instruction selector works correctly for various input scenarios.

3. **Analyzing the Code Structure:**  Scanning the code reveals a few key patterns:
    * **Data Structures (Arrays of Structs):**  We see arrays like `SIMDBinaryCmTests`, `SIMDConstZeroCmTests`, and `SIMDConstAndTests`. These arrays contain test cases. Each element of the array likely represents a specific scenario the instruction selector needs to handle.
    * **Test Fixtures (using `TEST_P` and `INSTANTIATE_TEST_SUITE_P`):**  The presence of `TEST_P` indicates parameterized tests. This means the same test function (`ConstZero`, `ConstAnd`) will be run multiple times with different input parameters defined in the arrays. `INSTANTIATE_TEST_SUITE_P` is used to set up these parameterized tests.
    * **Helper Classes (`StreamBuilder` and `Stream`):**  These suggest a mechanism for building and inspecting the output of the instruction selector. `StreamBuilder` probably helps construct the input to the selector, and `Stream` represents the resulting sequence of machine instructions.
    * **Assertions (`ASSERT_EQ`, `EXPECT_EQ`):** These are standard testing macros used to check if the actual output of the instruction selector matches the expected output.

4. **Deciphering the Test Case Structure:**  Let's take `SIMDBinaryCmTests` as an example:
    * `{true, 8, TSBinop::kI8x16Eq, kArm64IEq, kArm64IEq, 1}`:
        * `true`:  Likely a boolean flag (maybe indicating signedness or a specific optimization).
        * `8`:  A size value (perhaps the size of the data being compared in bits).
        * `TSBinop::kI8x16Eq`:  An enumeration representing a binary operation (likely "integer 8-bit by 16, equal"). This tells us what kind of operation is being tested.
        * `kArm64IEq`, `kArm64IEq`: Enumerations representing ARM64 machine instructions. This suggests the *expected* output instructions when the input is the `TSBinop`. The two values might represent different cases (e.g., when the inputs are registers vs. immediates).
        * `1`: Another size value (potentially related to the size of the result or a flag).

5. **Understanding the Test Logic:**  The `ConstZero` and `ConstAnd` test functions follow a similar pattern:
    * **Setup:**  Create a `StreamBuilder`.
    * **Input Generation:** Use `m.Simd128Constant()` and `m.Parameter(0)` to create input operands. This suggests testing cases where one operand is a constant and the other is a parameter (representing a register or memory location).
    * **Operation Execution:** `m.Emit(param.cm_operator, ...)` simulates applying the operation being tested.
    * **Output Inspection:** `m.Build()` gets the generated instruction stream. The assertions (`ASSERT_EQ`, `EXPECT_EQ`) verify:
        * The number of generated instructions (`s.size()`).
        * The type of the generated instruction (`s[0]->arch_opcode()`).
        * The number of inputs and outputs of the instruction.
        * Specific attributes of the instruction (e.g., `LaneSizeField::decode`, immediate values).

6. **Connecting to JavaScript (if applicable):** The prompt asks if the code relates to JavaScript. Given that V8 is the JavaScript engine for Chrome, and this is a compiler test, the connection is strong. These tests verify the correct compilation of JavaScript operations, especially those involving SIMD (Single Instruction, Multiple Data) operations, which are exposed in JavaScript through the WebAssembly API and SIMD.js (though SIMD.js is less common now). A JavaScript example would involve using SIMD operations.

7. **Identifying Potential Programming Errors:**  By understanding what the tests are verifying, we can infer potential errors the instruction selector might have:
    * Incorrect instruction selection for a given high-level operation.
    * Incorrect handling of constant operands.
    * Incorrect instruction encoding (e.g., wrong lane size, immediate values).
    * Missing optimizations (e.g., not using the `kArm64S128AndNot` instruction when it's beneficial).
    * Incorrect handling of symmetrical vs. non-symmetrical operations.

8. **Summarization (as requested in part 8):** The final step is to synthesize the information gathered into a concise summary of the code's purpose and function. This involves restating the key findings: it's a unit test for the ARM64 Turboshaft instruction selector, focusing on SIMD operations with constant operands, and verifying the correct instruction selection and encoding.

By following these steps, we can effectively analyze and understand the purpose and functionality of this C++ code snippet. The process involves understanding the context, dissecting the code structure, and inferring the testing logic and potential error scenarios.
这是一个V8 JavaScript引擎的源代码文件，位于`v8/test/unittests/compiler/arm64/`目录下，名为`turboshaft-instruction-selector-arm64-unittest.cc`。从文件名和目录结构可以推断，这个文件是用于测试 **Turboshaft编译器** 中 **针对ARM64架构的指令选择器** 的单元测试。

**功能列举:**

1. **测试指令选择的正确性:**  该文件包含了一系列的单元测试，用于验证Turboshaft编译器在将中间表示（IR）转换为ARM64机器码时，是否选择了正确的ARM64指令。

2. **针对特定指令模式的测试:** 从代码片段来看，测试重点似乎集中在 **SIMD (Single Instruction, Multiple Data)** 操作和 **常量操作数** 的处理上。 例如：
    * `SIMDBinaryCmTests`:  测试 SIMD 二元比较操作 (Compare)。
    * `TurboshaftInstructionSelectorSIMDConstZeroCmTest`: 测试 SIMD 操作中一个操作数为零常量的情况。
    * `TurboshaftInstructionSelectorSIMDConstAndTest`: 测试 SIMD "与" 操作 (`kS128And`, `kS128AndNot`) 中一个操作数为特定常量的情况。

3. **测试不同数据类型和操作:**  测试覆盖了不同的 SIMD 数据类型（如 I8x16, I16x8, I32x4, I64x2, F32x4, F64x2）和不同的比较操作（Eq, Ne, GeS, GtS, Lt, Le）。

4. **验证生成的机器码:** 测试用例会构造特定的中间表示，然后运行指令选择器，并断言生成的机器码指令和预期指令是否一致。 这包括：
    * 验证生成的指令操作码 (`arch_opcode()`).
    * 验证指令的输入和输出数量 (`InputCount()`, `OutputCount()`).
    * 验证指令中编码的 lane size (`LaneSizeField::decode()`).
    * 验证指令中使用的立即数 (`s.ToInt32(s[0]->InputAt(1))`).

**它不是 Torque 源代码:**

该文件以 `.cc` 结尾，因此是 C++ 源代码，而不是以 `.tq` 结尾的 V8 Torque 源代码。

**与 JavaScript 的关系:**

该文件测试的是 V8 引擎的编译器部分，而编译器负责将 JavaScript 代码转换为机器码。 因此，这些测试直接关系到 V8 如何执行 JavaScript 代码，特别是涉及到 SIMD 操作的部分。

**JavaScript 示例 (与 SIMD 相关):**

```javascript
// 需要启用 SIMD 支持的环境
const a = SIMD.float32x4(1, 2, 3, 4);
const b = SIMD.float32x4(5, 6, 7, 8);

// 模拟测试用例中的比较操作 (例如 F32x4Eq)
const equalResult = SIMD.float32x4.equal(a, b);
console.log(equalResult); // 输出类似: Bool32x4 [ false, false, false, false ]

// 模拟测试用例中的 "与" 操作
const mask = SIMD.int32x4(0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000000);
const andResult = SIMD.int32x4.and(a, mask);
console.log(andResult);
```

这段 JavaScript 代码使用了 `SIMD` API，展示了浮点数和整数的 SIMD 操作。  `turboshaft-instruction-selector-arm64-unittest.cc` 中的测试用例就是为了确保当 V8 编译类似这样的 JavaScript SIMD 代码时，能够正确地选择 ARM64 平台的 SIMD 指令。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  一个表示 `SIMD.int32x4.equal(a, b)` 的 Turboshaft 中间表示，其中 `a` 和 `b` 是两个 `int32x4` 类型的操作数。

**可能输出 (取决于具体的测试用例):**

* **如果 `a` 和 `b` 都不是常量:** 指令选择器可能会选择 ARM64 的 `CMEQ.4S` 指令 (具体指令格式可能有所不同)。
* **如果其中一个操作数是常量 (例如全零):** 测试用例 `TurboshaftInstructionSelectorSIMDConstZeroCmTest` 会验证是否选择了针对常量零优化的指令。

**用户常见的编程错误 (可能导致编译器生成错误代码，从而被这些测试发现):**

1. **类型不匹配的 SIMD 操作:**  例如，尝试对 `float32x4` 和 `int32x4` 进行按位与操作，这在某些情况下可能导致未定义的行为或错误的结果。编译器需要能够正确处理这些情况，或者生成错误信息。

2. **错误的 SIMD 数据对齐:** 尽管在高级 JavaScript 中不太可能直接遇到，但在底层的指令选择阶段，需要确保 SIMD 操作的数据在内存中是对齐的。 错误的对齐可能导致性能下降或硬件错误。

3. **对 SIMD 结果的错误假设:** 例如，假设 SIMD 比较操作返回一个简单的布尔值，而实际上它返回一个布尔向量 (如 `Bool32x4`)。

**归纳其功能 (作为第 8 部分):**

作为整个测试套件的第八部分，`v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc` 的功能是 **专门针对 ARM64 架构，详细测试 Turboshaft 编译器的指令选择器在处理 SIMD 操作和常量操作数时的正确性**。它通过构造各种中间表示的场景，并断言生成的 ARM64 机器码指令是否符合预期，来确保编译器能够为 JavaScript SIMD 代码生成高效且正确的机器码。 这部分测试是保证 V8 引擎在 ARM64 平台上运行 WebAssembly 和使用 SIMD API 的 JavaScript 代码时性能和可靠性的关键环节。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共8部分，请归纳一下它的功能

"""
   {false, 16, TSBinop::kI16x8Ne, kArm64INe, kArm64INe, 2},
    {false, 16, TSBinop::kI16x8GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 16, TSBinop::kI16x8GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 32, TSBinop::kI32x4Eq, kArm64IEq, kArm64IEq, 1},
    {true, 32, TSBinop::kI32x4Ne, kArm64INe, kArm64INe, 1},
    {true, 32, TSBinop::kI32x4GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 32, TSBinop::kI32x4GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 32, TSBinop::kI32x4Eq, kArm64IEq, kArm64IEq, 2},
    {false, 32, TSBinop::kI32x4Ne, kArm64INe, kArm64INe, 2},
    {false, 32, TSBinop::kI32x4GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 32, TSBinop::kI32x4GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 64, TSBinop::kI64x2Eq, kArm64IEq, kArm64IEq, 1},
    {true, 64, TSBinop::kI64x2Ne, kArm64INe, kArm64INe, 1},
    {true, 64, TSBinop::kI64x2GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 64, TSBinop::kI64x2GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 64, TSBinop::kI64x2Eq, kArm64IEq, kArm64IEq, 2},
    {false, 64, TSBinop::kI64x2Ne, kArm64INe, kArm64INe, 2},
    {false, 64, TSBinop::kI64x2GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 64, TSBinop::kI64x2GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 64, TSBinop::kF64x2Eq, kArm64FEq, kArm64FEq, 1},
    {true, 64, TSBinop::kF64x2Ne, kArm64FNe, kArm64FNe, 1},
    {true, 64, TSBinop::kF64x2Lt, kArm64FGt, kArm64FLt, 1},
    {true, 64, TSBinop::kF64x2Le, kArm64FGe, kArm64FLe, 1},
    {false, 64, TSBinop::kF64x2Eq, kArm64FEq, kArm64FEq, 2},
    {false, 64, TSBinop::kF64x2Ne, kArm64FNe, kArm64FNe, 2},
    {false, 64, TSBinop::kF64x2Lt, kArm64FLt, kArm64FLt, 2},
    {false, 64, TSBinop::kF64x2Le, kArm64FLe, kArm64FLe, 2},
    {true, 32, TSBinop::kF32x4Eq, kArm64FEq, kArm64FEq, 1},
    {true, 32, TSBinop::kF32x4Ne, kArm64FNe, kArm64FNe, 1},
    {true, 32, TSBinop::kF32x4Lt, kArm64FGt, kArm64FLt, 1},
    {true, 32, TSBinop::kF32x4Le, kArm64FGe, kArm64FLe, 1},
    {false, 32, TSBinop::kF32x4Eq, kArm64FEq, kArm64FEq, 2},
    {false, 32, TSBinop::kF32x4Ne, kArm64FNe, kArm64FNe, 2},
    {false, 32, TSBinop::kF32x4Lt, kArm64FLt, kArm64FLt, 2},
    {false, 32, TSBinop::kF32x4Le, kArm64FLe, kArm64FLe, 2},
};

using TurboshaftInstructionSelectorSIMDConstZeroCmTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDConstZeroCmTest>;

TEST_P(TurboshaftInstructionSelectorSIMDConstZeroCmTest, ConstZero) {
  const SIMDConstZeroCmTest param = GetParam();
  uint8_t data[16] = {};
  if (!param.is_zero) data[0] = 0xff;
  // Const node on the left
  {
    StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
    OpIndex cnst = m.Simd128Constant(data);
    OpIndex fcm = m.Emit(param.cm_operator, cnst, m.Parameter(0));
    m.Return(fcm);
    Stream s = m.Build();
    ASSERT_EQ(param.size, s.size());
    if (param.size == 1) {
      EXPECT_EQ(param.expected_op_left, s[0]->arch_opcode());
      EXPECT_EQ(1U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(param.lane_size, LaneSizeField::decode(s[0]->opcode()));
    } else {
      EXPECT_EQ(kArm64S128Const, s[0]->arch_opcode());
      EXPECT_EQ(param.expected_op_left, s[1]->arch_opcode());
      EXPECT_EQ(2U, s[1]->InputCount());
      EXPECT_EQ(1U, s[1]->OutputCount());
      EXPECT_EQ(param.lane_size, LaneSizeField::decode(s[1]->opcode()));
    }
  }
  //  Const node on the right
  {
    StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
    OpIndex cnst = m.Simd128Constant(data);
    OpIndex fcm = m.Emit(param.cm_operator, m.Parameter(0), cnst);
    m.Return(fcm);
    Stream s = m.Build();
    ASSERT_EQ(param.size, s.size());
    if (param.size == 1) {
      EXPECT_EQ(param.expected_op_right, s[0]->arch_opcode());
      EXPECT_EQ(1U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(param.lane_size, LaneSizeField::decode(s[0]->opcode()));
    } else {
      EXPECT_EQ(kArm64S128Const, s[0]->arch_opcode());
      EXPECT_EQ(param.expected_op_right, s[1]->arch_opcode());
      EXPECT_EQ(2U, s[1]->InputCount());
      EXPECT_EQ(1U, s[1]->OutputCount());
      EXPECT_EQ(param.lane_size, LaneSizeField::decode(s[1]->opcode()));
    }
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDConstZeroCmTest,
                         ::testing::ValuesIn(SIMDConstZeroCmTests));

struct SIMDConstAndTest {
  const uint8_t data[16];
  TSBinop simd_op;
  const ArchOpcode expected_op;
  const bool symmetrical;
  const uint8_t lane_size;
  const uint8_t shift_amount;
  const int32_t expected_imm;
  const size_t size;
};

static const SIMDConstAndTest SIMDConstAndTests[] = {
    {{0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE,
      0xFF, 0xFE, 0xFF, 0xFE},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     16,
     8,
     0x01,
     1},
    {{0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF,
      0xFE, 0xFF, 0xFE, 0xFF},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     16,
     0,
     0x01,
     1},

    {{0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE,
      0xFF, 0xFF, 0xFF, 0xFE},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     32,
     24,
     0x01,
     1},
    {{0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF,
      0xFF, 0xFF, 0xFE, 0xFF},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     32,
     16,
     0x01,
     1},
    {{0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
      0xFF, 0xFE, 0xFF, 0xFF},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     32,
     8,
     0x01,
     1},
    {{0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
      0xFE, 0xFF, 0xFF, 0xFF},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     32,
     0,
     0x01,
     1},

    {{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
      0xEE, 0xEE, 0xEE, 0xEE},
     TSBinop::kS128And,
     kArm64S128And,
     true,
     0,
     0,
     0x00,
     2},

    {{0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x01, 0x00, 0x01},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     16,
     8,
     0x01,
     1},
    {{0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x01, 0x00},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     16,
     0,
     0x01,
     1},

    {{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     32,
     24,
     0x01,
     1},
    {{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x01, 0x00},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     32,
     16,
     0x01,
     1},
    {{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x00},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     32,
     8,
     0x01,
     1},
    {{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     32,
     0,
     0x01,
     1},

    {{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
      0xEE, 0xEE, 0xEE, 0xEE},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     0,
     0,
     0x00,
     2},
};

using TurboshaftInstructionSelectorSIMDConstAndTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDConstAndTest>;

TEST_P(TurboshaftInstructionSelectorSIMDConstAndTest, ConstAnd) {
  const SIMDConstAndTest param = GetParam();
  // Const node on the left
  {
    StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
    OpIndex cnst = m.Simd128Constant(param.data);
    OpIndex op = m.Emit(param.simd_op, cnst, m.Parameter(0));
    m.Return(op);
    Stream s = m.Build();

    // Bic cannot always be applied when the immediate is on the left
    size_t expected_size = param.symmetrical ? param.size : 2;
    ASSERT_EQ(expected_size, s.size());
    if (expected_size == 1) {
      EXPECT_EQ(param.expected_op, s[0]->arch_opcode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(param.lane_size, LaneSizeField::decode(s[0]->opcode()));
      EXPECT_EQ(param.shift_amount, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(param.expected_imm, s.ToInt32(s[0]->InputAt(1)));
    } else {
      EXPECT_EQ(kArm64S128Const, s[0]->arch_opcode());
      EXPECT_EQ(param.expected_op, s[1]->arch_opcode());
      EXPECT_EQ(2U, s[1]->InputCount());
      EXPECT_EQ(1U, s[1]->OutputCount());
    }
  }
  //  Const node on the right
  {
    StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
    OpIndex cnst = m.Simd128Constant(param.data);
    OpIndex op = m.Emit(param.simd_op, m.Parameter(0), cnst);
    m.Return(op);
    Stream s = m.Build();
    ASSERT_EQ(param.size, s.size());
    if (param.size == 1) {
      EXPECT_EQ(param.expected_op, s[0]->arch_opcode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(param.lane_size, LaneSizeField::decode(s[0]->opcode()));
      EXPECT_EQ(param.shift_amount, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(param.expected_imm, s.ToInt32(s[0]->InputAt(1)));
    } else {
      EXPECT_EQ(kArm64S128Const, s[0]->arch_opcode());
      EXPECT_EQ(param.expected_op, s[1]->arch_opcode());
      EXPECT_EQ(2U, s[1]->InputCount());
      EXPECT_EQ(1U, s[1]->OutputCount());
    }
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDConstAndTest,
                         ::testing::ValuesIn(SIMDConstAndTests));
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace v8::internal::compiler::turboshaft

"""


```