Response:
The user wants a summary of the functionality of the provided C++ code snippet. This snippet is a part of the V8 JavaScript engine's unit tests, specifically for the ARM64 instruction selector.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename and the `TEST_F` and `TEST_P` macros clearly indicate this is a unit test file. The specific focus is the "instruction selector" for the ARM64 architecture.

2. **Examine individual test cases:**  Go through each `TEST_F` and `TEST_P` block. Note the operations being tested (e.g., `SimdF64x2MulWithDupTest`, `ReverseShuffle32x4Test`, `Int32MulWithImmediate`).

3. **Categorize the tests:** Group the tests based on the type of operations they are verifying. From the names, we see tests for:
    * SIMD (Single Instruction, Multiple Data) operations with floating-point numbers.
    * Integer multiplication with immediates (constant values).
    * Floating-point arithmetic operations.
    * Floating-point comparison operations.
    * Conditional selection (select based on a condition).
    * Type conversions.
    * Memory access (load).

4. **Infer the goal of each category:**
    * **SIMD:** Verify the correct instruction selection for SIMD operations, including optimizations like using a "dup" (duplicate) instruction.
    * **Integer Multiplication with Immediates:** Check for optimizations where multiplication by certain constants is replaced by cheaper operations like shifts and additions.
    * **Floating-point Arithmetic/Comparison:** Ensure the correct ARM64 instructions are generated for basic floating-point operations and comparisons.
    * **Conditional Selection:** Verify the correct instruction selection for conditional moves or selections.
    * **Type Conversions:**  Confirm that type conversions are handled correctly, sometimes being folded into other instructions like loads.
    * **Memory Access:** Check the instruction selection for loading data from memory.

5. **Look for patterns and common themes:**  Notice the use of `StreamBuilder` and `Stream` to construct and analyze the generated instruction sequences. The assertions (`ASSERT_EQ`, `EXPECT_EQ`) are used to check the generated instructions against expected outcomes.

6. **Address specific questions from the prompt:**
    * **`.tq` extension:** The code is `.cc`, not `.tq`, so it's not Torque.
    * **Javascript relation:** These tests verify the low-level code generation that makes Javascript execution possible on ARM64. Examples can be constructed by imagining the Javascript operations these instructions would implement.
    * **Code logic inference:**  For the immediate multiplication tests, we can see the input being a multiplication with a specific constant and the output being an addition and shift.
    * **Common programming errors:** The immediate multiplication tests implicitly guard against inefficient code generation if these optimizations weren't in place.

7. **Synthesize the summary:** Combine the observations into a concise description of the code's functionality.

**Self-Correction/Refinement:**

* Initially, I might have just listed the test names. However, the prompt asks for *functionality*, so grouping the tests by operation type provides a more meaningful summary.
* The prompt specifically mentions looking for `.tq`. I need to explicitly state that this file is `.cc` and therefore not a Torque file.
*  I need to connect the C++ code to the higher-level Javascript it supports.

By following these steps, I can arrive at a comprehensive and accurate summary that addresses all aspects of the user's request.
目录 `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 是 V8 JavaScript 引擎中用于测试 ARM64 架构指令选择器的单元测试代码。这是该系列测试的第 4 部分，意味着还有其他相关的测试文件。

**这个代码片段的主要功能是测试指令选择器在处理特定场景时是否能生成正确的 ARM64 指令。**  它针对各种操作进行测试，包括但不限于：

1. **SIMD (Single Instruction, Multiple Data) 浮点运算优化:**
   - 测试 `F64x2Mul` (双精度浮点数乘法) 操作与 `I8x16Shuffle` (SIMD 数据重排) 操作的结合使用，特别是当 `shuffle` 操作实际上是一个元素的复制 (`dup`) 时，指令选择器是否能优化为更高效的 `FMulElement` 指令。
   - 验证乘法操作的交换律在这种优化下是否仍然成立。
   - 测试当 `shuffle` 操作不是简单的元素复制时，优化是否不会被错误地应用。

2. **SIMD 数据重排指令:**
   - 测试特定的 `I8x16Shuffle` 模式，例如将低 64 位和高 64 位进行反转，指令选择器是否能正确选择 `S32x4Reverse` 指令。
   - 测试 `S32x4OneLaneSwizzle` 指令的选择，用于从两个 128 位 SIMD 寄存器中选择特定的 32 位通道并组合成一个新的寄存器。

3. **整数乘法与立即数的优化:**
   - 测试当一个整数乘以 `2^k + 1` 形式的立即数时，指令选择器是否能将其优化为移位和加法操作，例如 `x * (2^k + 1)` 优化为 `x + (x << k)`。
   - 测试这种优化在加法和减法运算中如何结合使用，例如 `x * (2^k + 1) + c` 优化为 `x + (x << k) + c`。
   - 测试乘法操作的交换律对这种优化的影响。

4. **浮点算术运算指令:**
   - 测试各种基本的双精度和单精度浮点算术运算（例如加法、减法、乘法、除法），确保指令选择器能为这些操作生成正确的 ARM64 指令。

5. **浮点比较运算指令:**
   - 测试各种浮点比较操作，确保指令选择器能生成正确的比较指令并设置相应的条件标志。
   - 特别测试了与立即数零进行比较的情况，指令选择器可能进行特定的优化。

6. **条件选择指令:**
   - 测试基于条件选择浮点数 (`Float32Select`, `Float64Select`) 和整数 (`Word32Select`, `Word64Select`) 的指令生成。
   - 验证了当选择的其中一个值是零时的处理。

7. **类型转换指令:**
   - 测试各种类型转换操作，确保指令选择器能生成正确的转换指令。
   - 对于无操作的转换（例如，将一个类型转换为它自身），测试是否不会生成任何指令。

8. **优化 `ChangeUint32ToUint64` 操作:**
   - 测试在某些情况下，例如当 `ChangeUint32ToUint64` 操作紧跟在某些 32 位整数运算之后时，该转换操作可以被省略，因为 32 位运算的结果可以直接作为 64 位寄存器的低 32 位使用。
   - 测试当 `ChangeUint32ToUint64` 操作紧跟在加载 8 位、16 位或 32 位无符号整数之后时，该转换操作会被合并到加载指令中，例如 `Load(Uint32)` 后面跟着 `ChangeUint32ToUint64` 会生成 `LdrW` 指令。

9. **优化 `ChangeInt32ToInt64` 操作:**
   - 测试 `ChangeInt32ToInt64` 操作与加载指令的合并，例如加载各种大小的有符号和无符号整数后进行符号扩展到 64 位。
   - 测试 `ChangeInt32ToInt64` 与 `Word32Sar` (32 位算术右移) 的结合，指令选择器会选择 `Sbfx` (Signed Bit Field Extract) 指令。
   - 测试 `Word64Sar` (64 位算术右移) 与 `ChangeInt32ToInt64` 的结合，当移位量在 0-31 之间时，可以优化为 `Sbfx` 指令。

**如果 `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码:**  当前的这个文件是以 `.cc` 结尾，所以它是 C++ 源代码，而不是 Torque 源代码。Torque 是一种用于 V8 内部实现的类型化的领域特定语言。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

是的，这个文件中的测试直接关系到 JavaScript 的功能。指令选择器的目标是将高级的、平台无关的中间表示 (IR) 转换为特定架构 (这里是 ARM64) 的机器指令。  以下是一些与代码片段中的测试相关的 JavaScript 示例：

```javascript
// SIMD 浮点乘法与复制
let a = SIMD.float64x2(1.0, 2.0);
let b = SIMD.float64x2(3.0, 3.0); // 相当于将 3.0 复制到两个通道
let c = SIMD.mul(a, b); // 测试会验证是否生成了 FMulElement 指令

// SIMD 数据重排
let d = SIMD.int32x4(1, 2, 3, 4);
let e = SIMD.int32x4(5, 6, 7, 8);
// 假设有某种方式可以表达 shuffle 操作，
// 测试会验证特定的 shuffle 模式是否生成了 S32x4Reverse 或 S32x4OneLaneSwizzle

// 整数乘法与立即数
function multiply(x) {
  return x * 9; // 9 是 2^3 + 1，测试会验证是否优化为移位和加法
}

function multiplyAndAdd(x, c) {
  return x * 9 + c;
}

// 浮点比较
function compare(x, y) {
  return x > y; // 测试会验证是否生成了适当的浮点比较指令并设置标志
}

// 条件选择
function select(condition, a, b) {
  return condition ? a : b; // 测试会验证是否生成了条件选择指令
}

// 类型转换 (在 JavaScript 中通常是隐式的)
let intValue = 10;
let longValue = intValue; // 测试会验证在底层如何处理 32 位到 64 位的转换

// 从内存加载 (JavaScript 中通过数组访问或对象属性访问发生)
let array = new Uint32Array([100]);
let value = array[0]; // 测试会验证加载操作和可能的类型转换

```

**如果有代码逻辑推理，请给出假设输入与输出:**

**示例 1: `Int32MulWithImmediate` 测试中 `x * (2^k + 1)` 的情况**

* **假设输入 (V8 IR 节点):**
    * 一个代表 32 位整数乘法的节点，其中一个输入是参数 `x`，另一个输入是立即数 `(1 << k) + 1`，例如 `k = 3`，立即数为 9。
* **预期输出 (ARM64 指令流):**
    * 一个 `Add32` 指令，使用带移位的操作数：`ADD Wd, Ws, Wm, LSL #k`，其中 `Ws` 和 `Wm` 是相同的寄存器，都代表 `x`。

**示例 2: `ReverseShuffle32x4Test` 中第一个 shuffle 模式**

* **假设输入 (V8 IR 节点):**
    * 一个 `I8x16Shuffle` 节点，指定了 `{12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3}` 的重排模式，输入是两个 128 位 SIMD 寄存器。
* **预期输出 (ARM64 指令流):**
    * 一个 `S32x4Reverse` 指令，作用于第一个输入寄存器。

**如果涉及用户常见的编程错误，请举例说明:**

虽然这个测试文件本身不直接涉及用户编写 JavaScript 代码时的错误，但它验证了 V8 引擎在处理某些模式时是否能生成高效的代码。如果指令选择器没有正确实现这些优化，可能会导致生成的机器码效率低下，从而影响 JavaScript 程序的性能。

例如，如果 `Int32MulWithImmediate` 的优化没有实现，那么 `x * 9` 可能会被编译成一个完整的乘法指令，而不是更快的移位和加法操作。这虽然不会导致程序出错，但会降低性能。

**这是第 4 部分，共 8 部分，请归纳一下它的功能:**

作为 `instruction-selector-arm64-unittest.cc` 系列的第 4 部分，这个代码片段的功能是 **专门测试 ARM64 指令选择器在处理 SIMD 浮点运算的特定优化、SIMD 数据重排、整数乘法与特定立即数的优化、基本的浮点算术和比较运算、条件选择、类型转换以及一些针对 `ChangeUint32ToUint64` 和 `ChangeInt32ToInt64` 转换的优化**。 它深入测试了指令选择器在各种不同场景下的正确性和优化能力，确保 V8 引擎在 ARM64 架构上能生成高效的机器码。  考虑到这是系列的一部分，可以推断其他部分可能涵盖了指令选择器的其他方面，例如内存访问、控制流、函数调用等等。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ctionSelectorSimdF64x2MulWithDupTest =
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