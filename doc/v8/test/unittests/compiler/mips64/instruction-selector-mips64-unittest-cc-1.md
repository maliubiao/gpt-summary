Response:
The user wants me to analyze a C++ file related to V8's instruction selector for the MIPS64 architecture. This is part 2 of a 3-part analysis. I need to:

1. **List the functionalities** demonstrated in the provided code snippet.
2. **Confirm if it's a Torque file:** Check if the filename ends with `.tq`.
3. **Relate to JavaScript (if applicable):** If the code interacts with JavaScript concepts, provide a JavaScript example.
4. **Illustrate code logic:** If there are logical operations, provide hypothetical inputs and outputs.
5. **Highlight common programming errors:** If the code touches upon potential errors, give examples.
6. **Summarize the functionalities:** Provide a concise summary based on the analyzed code.

Based on the code, it seems to be a series of unit tests for the instruction selector. Each `TEST_P` or `TEST_F` function sets up a small code snippet using `StreamBuilder` and then checks if the generated instruction sequence (`Stream s`) matches the expected output (opcode, input/output counts, addressing mode, etc.). The tests cover different kinds of operations: floating-point arithmetic, integer arithmetic, type conversions, and memory access (loads and stores).

Let's break down each section:

*   **`InstructionSelectorFPArithTest`**: Tests floating-point arithmetic operations.
*   **`InstructionSelectorIntArithTwoTest`**: Tests integer arithmetic operations with two input parameters.
*   **`InstructionSelectorIntArithOneTest`**: Tests integer arithmetic operations with one input parameter.
*   **`InstructionSelectorConversionTest`**: Tests type conversion operations.
*   **`ChangesFromToSmi`**: Tests specific sequences involving SMI (Small Integer) conversions.
*   **`CombineChangeFloat64ToInt32WithRoundFloat64`**: Tests combining float64 rounding with integer conversion.
*   **`CombineChangeFloat32ToInt32WithRoundFloat32`**: Tests combining float32 rounding with integer conversion (via float64).
*   **`ChangeFloat64ToInt32OfChangeFloat32ToFloat64`**: Tests a specific float32 to float64 then to int32 conversion.
*   **`TruncateFloat64ToFloat32OfChangeInt32ToFloat64`**: Tests a specific int32 to float64 then to float32 conversion.
*   **`CombineShiftsWithMul`**: Tests combining shift operations with multiplication.
*   **`CombineShiftsWithDivMod`**: Tests combining shift operations with division and modulo.
*   **`ChangeInt32ToInt64AfterLoad`**: Tests that `ChangeInt32ToInt64` is optimized into load instructions.
*   **`InstructionSelectorElidedChangeUint32ToUint64Test`**: Tests that `ChangeUint32ToUint64` can be elided (removed) in certain contexts.
*   **`ChangeUint32ToUint64AfterLoad`**: Tests that `ChangeUint32ToUint64` is optimized after load instructions.
*   **`InstructionSelectorMemoryAccessTest`**: Tests basic load and store operations.
*   **`InstructionSelectorMemoryAccessImmTest`**: Tests load and store operations with immediate offsets.
*   **`InstructionSelectorMemoryAccessUnalignedImmTest`**: Tests unaligned store operations with immediate offsets.
*   **`InstructionSelectorMemoryAccessImmMoreThan16bitTest`**: Tests load and store operations with large immediate offsets.
*   **`Word32EqualWithZero` and `Word64EqualWithZero`**: Tests comparisons with zero.
这是 V8 源代码文件 `v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc` 的第二部分，它主要包含了一系列针对 MIPS64 架构的指令选择器单元测试。这些测试旨在验证指令选择器在将高级的、平台无关的中间表示（IR）转换成特定的 MIPS64 机器指令时是否能够正确工作。

以下是此部分代码的具体功能分解：

1. **浮点运算指令选择测试 (`InstructionSelectorFPArithTest`)**:
    *   **功能**: 测试对于浮点数算术运算（例如加法、减法、乘法、除法等），指令选择器是否选择了正确的 MIPS64 浮点运算指令。
    *   **测试逻辑**:
        *   使用 `InstructionSelectorTestWithParam` 创建参数化的测试，参数是 `MachInst2` 结构体，它包含了机器指令的类型和构造函数。
        *   `TEST_P` 定义了一个测试用例，它接收一个 `MachInst2` 参数。
        *   `StreamBuilder` 用于构建一个简单的代码流，其中包含两个参数的浮点运算。
        *   `m.Return((m.\*fpa.constructor)(m.Parameter(0), m.Parameter(1)))`  模拟了一个返回两个参数浮点运算结果的操作。
        *   `Stream s = m.Build()` 构建指令流。
        *   `ASSERT_EQ(1U, s.size())` 断言生成了单个指令。
        *   `EXPECT_EQ(fpa.arch_opcode, s[0]->arch_opcode())` 断言生成的指令的机器码与预期的浮点运算指令码匹配。
        *   `EXPECT_EQ(2U, s[0]->InputCount())` 和 `EXPECT_EQ(1U, s[0]->OutputCount())` 断言指令的输入和输出数量正确。
    *   `INSTANTIATE_TEST_SUITE_P` 使用 `kFPArithInstructions` 中的值实例化测试套件，这意味着会对 `kFPArithInstructions` 中定义的每种浮点运算指令都进行测试。

2. **整数运算指令选择测试 (两个操作数) (`InstructionSelectorIntArithTwoTest`)**:
    *   **功能**: 测试对于需要两个操作数的整数算术运算（例如加法、减法），指令选择器是否选择了正确的 MIPS64 整数运算指令。
    *   **测试逻辑**: 类似于浮点运算测试，但使用了 `MachInst2` 结构体和 `kAddSubInstructions` 来测试整数的加减运算。

3. **整数运算指令选择测试 (一个操作数) (`InstructionSelectorIntArithOneTest`)**:
    *   **功能**: 测试对于需要一个操作数的整数运算，指令选择器是否选择了正确的 MIPS64 整数运算指令。
    *   **测试逻辑**: 类似于前两个测试，但使用了 `MachInst1` 结构体和 `kAddSubOneInstructions` 来测试只需要一个操作数的整数运算。请注意，这里 `EXPECT_EQ(2U, s[0]->InputCount())` 可能存在疑问，因为理论上一个操作数的运算应该只有一个输入。这可能与 V8 内部表示有关，例如，有些一元运算可能隐含着一个默认的输入。

4. **类型转换指令选择测试 (`InstructionSelectorConversionTest`)**:
    *   **功能**: 测试对于各种类型转换操作，指令选择器是否选择了正确的 MIPS64 转换指令。
    *   **测试逻辑**:
        *   使用 `Conversion` 结构体作为参数，该结构体包含了源类型、目标类型和相应的机器指令信息。
        *   测试用例构建一个将参数从源类型转换为目标类型的操作，并断言生成的指令是预期的转换指令。
        *   `INSTANTIATE_TEST_SUITE_P` 使用 `kConversionInstructions` 中的值实例化测试套件，测试各种类型转换。

5. **SMI 类型转换测试 (`ChangesFromToSmi`)**:
    *   **功能**: 测试涉及 SMI (Small Integer) 类型的转换操作，例如将 64 位整数截断为 32 位整数，或者将 32 位整数转换为 64 位整数并进行位移。
    *   **测试逻辑**:  构建特定的操作序列，例如右移 64 位整数并截断为 32 位，然后断言生成的指令是 MIPS64 的 `kMips64Dsar` (算术右移)。另一个测试用例是左移转换后的 32 位整数，并断言生成 `kMips64Dshl`。

6. **浮点数舍入和类型转换组合测试 (`CombineChangeFloat64ToInt32WithRoundFloat64`, `CombineChangeFloat32ToInt32WithRoundFloat32`)**:
    *   **功能**: 测试当浮点数舍入操作（例如截断、floor、ceil 等）与转换为整数操作组合时，指令选择器是否能够进行优化，选择直接执行舍入并转换为整数的指令。
    *   **测试逻辑**: 构建将浮点数舍入后转换为 32 位整数的操作，并断言生成的指令是直接进行舍入的指令 (`conv.mi.arch_opcode`)，而不是先舍入再转换。

7. **特定浮点数转换序列测试 (`ChangeFloat64ToInt32OfChangeFloat32ToFloat64`, `TruncateFloat64ToFloat32OfChangeInt32ToFloat64`)**:
    *   **功能**: 测试特定的浮点数转换序列，验证指令选择器是否选择了最优的 MIPS64 指令。
    *   **测试逻辑**: 构建 `float32` 到 `float64` 再到 `int32` 的转换，断言生成 `kMips64TruncWS` 指令。构建 `int32` 到 `float64` 再到 `float32` 的转换，断言生成 `kMips64CvtSW` 指令。

8. **移位与乘除法组合测试 (`CombineShiftsWithMul`, `CombineShiftsWithDivMod`)**:
    *   **功能**: 测试当移位操作与乘法、除法、取模运算组合时，指令选择器是否能够识别并选择更高效的 MIPS64 指令。
    *   **测试逻辑**: 构建将一个 64 位整数右移后进行乘法/除法/取模的操作，断言生成了相应的 MIPS64 高位乘法 (`kMips64DMulHigh`)、除法 (`kMips64Ddiv`) 或取模 (`kMips64Dmod`) 指令。

9. **加载后进行类型转换测试 (`ChangeInt32ToInt64AfterLoad`)**:
    *   **功能**: 测试当从内存加载数据后立即将其从 32 位整数转换为 64 位整数时，指令选择器是否能够将转换操作融合到加载指令中，使用带有符号扩展或零扩展的加载指令。
    *   **测试逻辑**:  构建从不同类型的内存位置加载数据（`Uint8`, `Int8`, `Uint16`, `Int16`, `Uint32`, `Int32`）并转换为 `Int64` 的操作，断言生成的指令是相应的 MIPS64 加载指令 (`kMips64Lbu`, `kMips64Lb`, `kMips64Lhu`, `kMips64Lh`, `kMips64Lw`)，而不是先加载再转换。

10. **`ChangeUint32ToUint64` 指令消除测试 (`InstructionSelectorElidedChangeUint32ToUint64Test`)**:
    *   **功能**: 测试在某些情况下，将 `uint32` 转换为 `uint64` 的操作是否可以被指令选择器优化掉，因为它在 MIPS64 架构上是隐式发生的。
    *   **测试逻辑**:  构建将 `uint32` 类型的参数进行二元运算（由 `kCanElideChangeUint32ToUint64` 提供）并将结果转换为 `uint64` 的操作。断言如果启用了调试代码并且是比较操作，则会生成包含比较和断言的多个指令；否则，会生成单个二元运算指令，表明类型转换被优化掉了。

11. **加载后进行 `ChangeUint32ToUint64` 测试 (`ChangeUint32ToUint64AfterLoad`)**:
    *   **功能**: 测试当从内存加载 `uint8`、`uint16` 或 `uint32` 类型的数据后立即将其转换为 `uint64` 时，指令选择器是否能够优化掉转换操作。
    *   **测试逻辑**: 构建从内存加载无符号整数并转换为 `uint64` 的操作，断言生成了加载指令 (`kMips64Lbu`, `kMips64Lhu`, `kMips64Lwu`)，并且可能在加载之前有一个 `kMips64Dadd` 指令，这可能与处理立即数或地址计算有关，但关键在于 `ChangeUint32ToUint64` 本身没有生成额外的指令。

12. **加载和存储指令测试 (`InstructionSelectorMemoryAccessTest`)**:
    *   **功能**: 测试基本的加载和存储操作，验证指令选择器是否为不同数据类型选择了正确的 MIPS64 加载和存储指令。
    *   **测试逻辑**:
        *   使用 `MemoryAccess` 结构体作为参数，包含数据类型和对应的加载/存储指令码。
        *   `LoadWithParameters` 测试从内存加载指定类型的数据，断言生成了正确的加载指令。
        *   `StoreWithParameters` 测试将指定类型的数据存储到内存，断言生成了正确的存储指令。
        *   `INSTANTIATE_TEST_SUITE_P` 使用 `kMemoryAccesses` 中的值实例化测试套件，覆盖各种数据类型的加载和存储。

13. **带立即数偏移的加载和存储指令测试 (`InstructionSelectorMemoryAccessImmTest`)**:
    *   **功能**: 测试使用立即数偏移量进行加载和存储操作，验证指令选择器是否为不同数据类型和不同的立即数偏移量选择了正确的 MIPS64 加载和存储指令。
    *   **测试逻辑**:
        *   使用 `MemoryAccessImm` 结构体作为参数，包含数据类型、加载/存储指令码和一个包含多个立即数偏移量的数组。
        *   `LoadWithImmediateIndex` 测试使用不同的立即数偏移量加载数据，断言生成了正确的加载指令，并且立即数被正确编码到指令中。
        *   `StoreWithImmediateIndex` 测试使用不同的立即数偏移量存储数据，断言生成了正确的存储指令，并且立即数被正确编码。
        *   `StoreZero` 测试存储零值到不同的立即数偏移地址，断言生成了正确的存储指令。
        *   `INSTANTIATE_TEST_SUITE_P` 使用 `kMemoryAccessesImm` 中的值实例化测试套件。

14. **非对齐存储指令测试 (`InstructionSelectorMemoryAccessUnalignedImmTest`)**:
    *   **功能**: 测试非对齐的存储操作，验证指令选择器在需要非对齐访问时是否选择了正确的 MIPS64 指令。
    *   **测试逻辑**:
        *   使用 `MemoryAccessImm2` 结构体，包含数据类型、对齐和非对齐的存储指令码，以及立即数偏移量。
        *   `StoreZero` 测试存储零值到非对齐的立即数偏移地址，断言根据平台是否支持非对齐存储，生成了相应的对齐或非对齐存储指令。
        *   `INSTANTIATE_TEST_SUITE_P` 使用 `kMemoryAccessesImmUnaligned` 中的值实例化测试套件。

15. **大于 16 位偏移的加载/存储指令测试 (`InstructionSelectorMemoryAccessImmMoreThan16bitTest`)**:
    *   **功能**: 测试当加载和存储操作的立即数偏移量大于 16 位时，指令选择器是否能够正确处理，通常这可能需要使用不同的指令或者将立即数加载到寄存器中。
    *   **测试逻辑**:
        *   使用 `MemoryAccessImm1` 结构体，包含数据类型、加载/存储指令码和大于 16 位的立即数偏移量。
        *   `LoadWithImmediateIndex` 和 `StoreWithImmediateIndex` 测试使用这些大的立即数偏移量进行加载和存储，断言生成了正确的指令。
        *   `INSTANTIATE_TEST_SUITE_P` 使用 `kMemoryAccessImmMoreThan16bit` 中的值实例化测试套件。

16. **与零比较的测试 (`Word32EqualWithZero`, `Word64EqualWithZero`)**:
    *   **功能**: 测试当将 32 位或 64 位的值与零进行相等比较时，指令选择器是否选择了正确的 MIPS64 比较指令。
    *   **测试逻辑**: 构建与零进行相等比较的操作，断言生成了 `kMips64Cmp` 指令，并且标志位被设置为 `kFlags_set`，条件码为 `kEqual`。

**关于文件类型：**

`v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 文件（`.tq`）。

**与 JavaScript 的关系：**

这个 C++ 文件是 V8 引擎的一部分，V8 是执行 JavaScript 代码的引擎。指令选择器是将 JavaScript 代码编译成机器码的关键步骤。虽然这个文件本身不是 JavaScript 代码，但它直接影响 JavaScript 代码的执行效率。

**JavaScript 示例 (说明指令选择器的作用):**

假设有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 编译 `add` 函数时，指令选择器会负责将加法操作 `a + b` 转换成 MIPS64 的加法指令，例如 `ADDU` 或 `DADD`。  这个单元测试中 `InstructionSelectorIntArithTwoTest` 的部分就是在验证这种转换是否正确。

**代码逻辑推理示例：**

对于 `InstructionSelectorFPArithTest` 中的一个测试用例，假设 `fpa` 是一个表示浮点加法的 `MachInst2` 结构体，其 `arch_opcode` 为 `kMips64AddD`。

*   **假设输入**: 两个表示浮点数的参数。
*   **预期输出**: 生成一个 MIPS64 的双精度浮点加法指令 (`kMips64AddD`)，该指令接收这两个浮点数作为输入，并产生一个浮点数结果。

**用户常见的编程错误 (可能与指令选择器相关):**

虽然用户通常不会直接与指令选择器交互，但指令选择器的错误可能会导致生成的机器码不正确，从而导致 JavaScript 代码的运行时错误。例如：

*   **类型转换错误**: 如果指令选择器在处理类型转换时出现错误，可能会导致数据被错误地解释，从而产生意想不到的结果。 例如，将浮点数错误地转换为整数，导致精度丢失或值不正确。
*   **算术运算溢出**: 虽然指令选择器本身不负责处理溢出，但它选择的指令可能会影响溢出的行为。 如果指令选择器错误地选择了截断的整数运算而不是饱和运算，可能会导致溢出被忽略，从而产生错误的结果。

**此部分的功能归纳：**

这部分 `instruction-selector-mips64-unittest.cc` 的主要功能是 **系统地测试 V8 引擎中 MIPS64 架构的指令选择器**。 它通过创建各种模拟的中间表示操作，并断言指令选择器为这些操作生成了预期的 MIPS64 机器指令。 这些测试覆盖了浮点运算、整数运算、类型转换、内存加载和存储等多种场景，包括对立即数偏移和非对齐访问的处理。 其目的是确保指令选择器在将高级代码转换为 MIPS64 汇编代码时的正确性和效率。

Prompt: 
```
这是目录为v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/mips64/instruction-selector-mips64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
----------------------
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
// ----------------------------------------------------------------------------
// Integer arithmetic
// ----------------------------------------------------------------------------
using InstructionSelectorIntArithTwoTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorIntArithTwoTest, Parameter) {
  const MachInst2 intpa = GetParam();
  StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
                  intpa.machine_type);
  m.Return((m.*intpa.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorIntArithTwoTest,
                         ::testing::ValuesIn(kAddSubInstructions));

// ----------------------------------------------------------------------------
// One node.
// ----------------------------------------------------------------------------

using InstructionSelectorIntArithOneTest =
    InstructionSelectorTestWithParam<MachInst1>;

TEST_P(InstructionSelectorIntArithOneTest, Parameter) {
  const MachInst1 intpa = GetParam();
  StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
                  intpa.machine_type);
  m.Return((m.*intpa.constructor)(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorIntArithOneTest,
                         ::testing::ValuesIn(kAddSubOneInstructions));
// ----------------------------------------------------------------------------
// Conversions.
// ----------------------------------------------------------------------------
using InstructionSelectorConversionTest =
    InstructionSelectorTestWithParam<Conversion>;

TEST_P(InstructionSelectorConversionTest, Parameter) {
  const Conversion conv = GetParam();
  StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
  m.Return((m.*conv.mi.constructor)(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorConversionTest,
                         ::testing::ValuesIn(kConversionInstructions));

TEST_F(InstructionSelectorTest, ChangesFromToSmi) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.TruncateInt64ToInt32(
        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Dsar, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Word64Shl(m.ChangeInt32ToInt64(m.Parameter(0)), m.Int32Constant(32)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Dshl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

using CombineChangeFloat64ToInt32WithRoundFloat64 =
    InstructionSelectorTestWithParam<Conversion>;

TEST_P(CombineChangeFloat64ToInt32WithRoundFloat64, Parameter) {
  {
    const Conversion conv = GetParam();
    StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
    m.Return(m.ChangeFloat64ToInt32((m.*conv.mi.constructor)(m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         CombineChangeFloat64ToInt32WithRoundFloat64,
                         ::testing::ValuesIn(kFloat64RoundInstructions));

using CombineChangeFloat32ToInt32WithRoundFloat32 =
    InstructionSelectorTestWithParam<Conversion>;

TEST_P(CombineChangeFloat32ToInt32WithRoundFloat32, Parameter) {
  {
    const Conversion conv = GetParam();
    StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
    m.Return(m.ChangeFloat64ToInt32(
        m.ChangeFloat32ToFloat64((m.*conv.mi.constructor)(m.Parameter(0)))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         CombineChangeFloat32ToInt32WithRoundFloat32,
                         ::testing::ValuesIn(kFloat32RoundInstructions));

TEST_F(InstructionSelectorTest, ChangeFloat64ToInt32OfChangeFloat32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
    m.Return(m.ChangeFloat64ToInt32(m.ChangeFloat32ToFloat64(m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64TruncWS, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest,
       TruncateFloat64ToFloat32OfChangeInt32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Int32());
    m.Return(
        m.TruncateFloat64ToFloat32(m.ChangeInt32ToFloat64(m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64CvtSW, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, CombineShiftsWithMul) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Word64Sar(m.Parameter(0), m.Int32Constant(32)),
                        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64DMulHigh, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, CombineShiftsWithDivMod) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Div(m.Word64Sar(m.Parameter(0), m.Int32Constant(32)),
                        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Ddiv, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mod(m.Word64Sar(m.Parameter(0), m.Int32Constant(32)),
                        m.Word64Sar(m.Parameter(0), m.Int32Constant(32))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Dmod, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ChangeInt32ToInt64AfterLoad) {
  // For each case, test that the conversion is merged into the load
  // operation.
  // ChangeInt32ToInt64(Load_Uint8) -> Lbu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Lbu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int8) -> Lb
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Lb, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint16) -> Lhu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Lhu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int16) -> Lh
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Lh, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint32) -> Lw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Lw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int32) -> Lw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Lw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

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
  if (v8_flags.debug_code && binop.arch_opcode == kMips64Cmp) {
    ASSERT_EQ(6U, s.size());
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kMips64Dshl, s[1]->arch_opcode());
    EXPECT_EQ(kMips64Dshl, s[2]->arch_opcode());
    EXPECT_EQ(kMips64Cmp, s[3]->arch_opcode());
    EXPECT_EQ(kMips64AssertEqual, s[4]->arch_opcode());
    EXPECT_EQ(kMips64Cmp, s[5]->arch_opcode());
    EXPECT_EQ(2U, s[5]->InputCount());
    EXPECT_EQ(1U, s[5]->OutputCount());
  } else {
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorElidedChangeUint32ToUint64Test,
                         ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

TEST_F(InstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // Lbu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Dadd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kMips64Lbu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // Lhu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Dadd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kMips64Lhu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // Lwu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kMips64Dadd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kMips64Lwu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

// ----------------------------------------------------------------------------
// Loads and stores.
// ----------------------------------------------------------------------------


namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
};

static const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(), kMips64Lb, kMips64Sb},
    {MachineType::Uint8(), kMips64Lbu, kMips64Sb},
    {MachineType::Int16(), kMips64Lh, kMips64Sh},
    {MachineType::Uint16(), kMips64Lhu, kMips64Sh},
    {MachineType::Int32(), kMips64Lw, kMips64Sw},
    {MachineType::Float32(), kMips64Lwc1, kMips64Swc1},
    {MachineType::Float64(), kMips64Ldc1, kMips64Sdc1},
    {MachineType::Int64(), kMips64Ld, kMips64Sd}};


struct MemoryAccessImm {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};


std::ostream& operator<<(std::ostream& os, const MemoryAccessImm& acc) {
  return os << acc.type;
}


struct MemoryAccessImm1 {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[5];
};


std::ostream& operator<<(std::ostream& os, const MemoryAccessImm1& acc) {
  return os << acc.type;
}

struct MemoryAccessImm2 {
  MachineType type;
  ArchOpcode store_opcode;
  ArchOpcode store_opcode_unaligned;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm2& acc) {
  return os << acc.type;
}

// ----------------------------------------------------------------------------
// Loads and stores immediate values
// ----------------------------------------------------------------------------


const MemoryAccessImm kMemoryAccessesImm[] = {
    {MachineType::Int8(),
     kMips64Lb,
     kMips64Sb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Uint8(),
     kMips64Lbu,
     kMips64Sb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Int16(),
     kMips64Lh,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Uint16(),
     kMips64Lhu,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Int32(),
     kMips64Lw,
     kMips64Sw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Float32(),
     kMips64Lwc1,
     kMips64Swc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Float64(),
     kMips64Ldc1,
     kMips64Sdc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Int64(),
     kMips64Ld,
     kMips64Sd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kMips64Lb,
     kMips64Sb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kMips64Lbu,
     kMips64Sb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kMips64Lh,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kMips64Lhu,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kMips64Lw,
     kMips64Sw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kMips64Lwc1,
     kMips64Swc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kMips64Ldc1,
     kMips64Sdc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kMips64Ld,
     kMips64Sd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}}};

const MemoryAccessImm2 kMemoryAccessesImmUnaligned[] = {
    {MachineType::Int16(),
     kMips64Ush,
     kMips64Sh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kMips64Usw,
     kMips64Sw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kMips64Usd,
     kMips64Sd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kMips64Uswc1,
     kMips64Swc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kMips64Usdc1,
     kMips64Sdc1,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

}  // namespace

using InstructionSelectorMemoryAccessTest =
    InstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}


TEST_P(InstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                  MachineType::Int32(), memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Parameter(1),
          kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// ----------------------------------------------------------------------------
// Load immediate.
// ----------------------------------------------------------------------------

using InstructionSelectorMemoryAccessImmTest =
    InstructionSelectorTestWithParam<MemoryAccessImm>;

TEST_P(InstructionSelectorMemoryAccessImmTest, LoadWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
  }
}


// ----------------------------------------------------------------------------
// Store immediate.
// ----------------------------------------------------------------------------


TEST_P(InstructionSelectorMemoryAccessImmTest, StoreWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorMemoryAccessImmTest, StoreZero) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Int32Constant(0), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImm));

using InstructionSelectorMemoryAccessUnalignedImmTest =
    InstructionSelectorTestWithParam<MemoryAccessImm2>;

TEST_P(InstructionSelectorMemoryAccessUnalignedImmTest, StoreZero) {
  const MemoryAccessImm2 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    bool unaligned_store_supported =
        m.machine()->UnalignedStoreSupported(memacc.type.representation());
    m.UnalignedStore(memacc.type.representation(), m.Parameter(0),
                     m.Int32Constant(index), m.Int32Constant(0));
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(unaligned_store_supported ? memacc.store_opcode_unaligned
                                        : memacc.store_opcode,
              s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessUnalignedImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImmUnaligned));

// ----------------------------------------------------------------------------
// Load/store offsets more than 16 bits.
// ----------------------------------------------------------------------------

using InstructionSelectorMemoryAccessImmMoreThan16bitTest =
    InstructionSelectorTestWithParam<MemoryAccessImm1>;

TEST_P(InstructionSelectorMemoryAccessImmMoreThan16bitTest,
       LoadWithImmediateIndex) {
  const MemoryAccessImm1 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorMemoryAccessImmMoreThan16bitTest,
       StoreWithImmediateIndex) {
  const MemoryAccessImm1 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmMoreThan16bitTest,
                         ::testing::ValuesIn(kMemoryAccessImmMoreThan16bit));

// ----------------------------------------------------------------------------
// kMips64Cmp with zero testing.
// ----------------------------------------------------------------------------


TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}


TEST_F(InstructionSelectorTest, Word64EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Equal(m.Parameter(0), m.Int64Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Equal(m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kMips64Cmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount()
"""


```