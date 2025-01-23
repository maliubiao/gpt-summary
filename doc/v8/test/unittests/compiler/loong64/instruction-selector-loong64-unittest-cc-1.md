Response:
The user wants me to analyze a C++ source code file for V8 related to instruction selection on the LoongArch64 architecture. I need to identify its functionality based on the provided code snippets and address the specific points raised in the prompt.

Here's a breakdown of my thought process:

1. **Identify the core functionality:** The file name `instruction-selector-loong64-unittest.cc` strongly suggests that it contains unit tests for the instruction selector component of the V8 compiler, specifically for the LoongArch64 architecture. The code itself confirms this through the use of `TEST_F` macros and `StreamBuilder` which are typical patterns in V8's testing infrastructure for instruction selection.

2. **Analyze individual test cases:** I will iterate through the `TEST_F` blocks to understand what specific aspects of instruction selection are being tested. Key observations include:
    * **Type conversions:** Tests for `ChangeInt32ToInt64`, `ChangeFloat64ToInt32`, `ChangeFloat32ToFloat64`, `TruncateFloat64ToFloat32`, `ChangeInt32ToFloat64`, `ChangeUint32ToUint64`. These tests verify that the instruction selector generates the correct লোongArch64 instructions for different type conversions.
    * **Shift operations:** Tests for `Word64Sar`, `Word64Shl`, confirming the selection of shift instructions (`kLoong64Sra_d`, `kLoong64Sll_d`).
    * **Combined operations:** Tests for combining shifts with multiplication and division/modulo, indicating optimizations where single LoongArch64 instructions like `kLoong64Mulh_d`, `kLoong64Div_d`, `kLoong64Mod_d` are used.
    * **Loads after conversions:** Tests like `ChangeInt32ToInt64AfterLoad` and `ChangeUint32ToUint64AfterLoad` are crucial. They check if the instruction selector can optimize by directly loading data into the target register type (e.g., loading a byte into a 64-bit register with zero-extension).
    * **Loads and Stores:**  Extensive tests cover various load (`Ld_b`, `Ld_bu`, `Ld_h`, `Ld_hu`, `Ld_w`, `Fld_s`, `Fld_d`, `Ld_d`) and store (`St_b`, `St_h`, `St_w`, `Fst_s`, `Fst_d`, `St_d`) instructions for different data types and addressing modes (immediate offsets).
    * **Comparisons with Zero:** Tests for `Word32EqualWithZero` and `Word64EqualWithZero` check if the instruction selector generates efficient comparison instructions against zero.
    * **Bit manipulation:** Tests for `Word32Clz` and `Word64Clz` verify the generation of count leading zeros instructions.
    * **Floating-point operations:** Tests for `Float32Abs`, `Float64Abs`, `Float64Max`, `Float64Min` confirm correct instruction selection for basic floating-point operations.
    * **Load and Shift Right combination:** A test case specifically checks if a load followed by a right shift can be optimized, and if not, that the instructions are generated correctly.
    * **Byte swapping:** Tests for `Word32ReverseBytes` and `Word64ReverseBytes` ensure the correct byte swap instructions are selected.

3. **Address specific points from the prompt:**
    * **Functionality listing:**  Based on the analysis of the test cases, I can create a comprehensive list of functionalities.
    * **Torque source:** The file extension is `.cc`, not `.tq`, so it's a C++ source file.
    * **Relationship to JavaScript:**  Instruction selection is a crucial step in the V8 compilation pipeline that translates the intermediate representation of JavaScript code into machine code. I can provide a simple JavaScript example that would trigger some of the tested operations.
    * **Code logic inference (input/output):**  The tests are structured around a `StreamBuilder` that constructs a sequence of operations. The `ASSERT_EQ` and `EXPECT_EQ` macros verify that the generated instruction stream matches the expected output for the given input sequence. I can provide an example based on one of the test cases.
    * **Common programming errors:**  The optimizations performed by the instruction selector can sometimes mask inefficiencies in the generated intermediate representation. I can provide an example of a potential JavaScript coding style that might lead to redundant operations, which the instruction selector might or might not be able to fully optimize away.
    * **Summary of functionality (part 2):** This requires consolidating the findings from analyzing the second part of the code.

4. **Structure the response:** I will organize the information logically, starting with the general functionality and then addressing each point in the prompt systematically. I will use clear and concise language and provide code examples where appropriate. For the input/output examples, I will focus on the structure of the `StreamBuilder` and the expected resulting machine instructions. For common errors, I'll illustrate with a simple JavaScript scenario.
这是对V8 JavaScript 引擎中针对 LoongArch64 架构的指令选择器进行单元测试的代码的第二部分。结合第一部分，我们可以归纳出以下功能：

**总体功能:**

`v8/test/unittests/compiler/loong64/instruction-selector-loong64-unittest.cc` 这个文件包含了针对 V8 引擎中 LoongArch64 架构的指令选择器 (`InstructionSelector`) 的各种单元测试。指令选择器的主要任务是将中间表示 (IR) 的操作转换为目标架构（这里是 LoongArch64）的机器指令。 这些测试旨在验证指令选择器是否能够为各种 IR 操作生成正确且优化的 LoongArch64 指令序列。

**具体功能 (基于第二部分代码):**

* **测试类型转换指令的选择:**
    * `ChangeInt32ToInt64`: 测试将 32 位整数转换为 64 位整数的操作是否生成 `kLoong64Sll_d` (逻辑左移) 指令。这表明在某些情况下，V8 的指令选择器可能会使用移位来实现类型扩展。
    * `ChangeFloat64ToInt32OfChangeFloat32ToFloat64`: 测试先将 32 位浮点数转换为 64 位浮点数，再将 64 位浮点数转换为 32 位整数的操作，是否生成 `kLoong64Float32ToFloat64` 和 `kLoong64Float64ToInt32` 指令。
    * `TruncateFloat64ToFloat32OfChangeInt32ToFloat64`: 测试先将 32 位整数转换为 64 位浮点数，再将 64 位浮点数截断为 32 位浮点数的操作，是否生成 `kLoong64Int32ToFloat32` 指令。这表明某些组合操作可以被优化为更直接的指令。
* **测试移位操作与乘法/除法/取模的组合优化:**
    * `CombineShiftsWithMul`: 测试当两个操作数都是对同一个 64 位值进行算术右移 32 位的结果时，乘法操作是否被优化为 `kLoong64Mulh_d` (乘法高位) 指令。这是一种常见的优化，因为将一个 64 位整数算术右移 32 位相当于取其高 32 位。
    * `CombineShiftsWithDivMod`: 类似地，测试除法和取模操作是否在相同移位情况下被优化为 `kLoong64Div_d` 和 `kLoong64Mod_d` 指令。
* **测试在加载操作后进行类型转换的优化:**
    * `ChangeInt32ToInt64AfterLoad`:  测试在加载不同大小的整数 (8 位、16 位、32 位，有符号和无符号) 后立即进行 `ChangeInt32ToInt64` 操作时，指令选择器是否能将类型转换合并到加载指令中，例如 `Load_Uint8` + `ChangeInt32ToInt64` 被优化为 `kLoong64Ld_bu` (加载字节并零扩展)。这能减少指令数量和提高效率。
* **测试 `ChangeUint32ToUint64` 的省略优化:**
    * `InstructionSelectorElidedChangeUint32ToUint64Test` 和 `ChangeUint32ToUint64AfterLoad`:  测试在某些情况下，将 32 位无符号整数转换为 64 位无符号整数的操作可以被省略，例如在进行某些算术运算或加载操作后。因为 LoongArch64 上寄存器是 64 位的，所以无符号 32 位值可以自然地放入 64 位寄存器中，无需额外的转换指令。
* **测试各种加载和存储指令的选择:**
    * `InstructionSelectorMemoryAccessTest`:  测试针对不同数据类型 (Int8, Uint8, Int16, Uint16, Int32, Float32, Float64, Int64) 的加载 (`kLoong64Ld_b`, `kLoong64Ld_bu`, ..., `kLoong64Fld_d`, `kLoong64Ld_d`) 和存储 (`kLoong64St_b`, ..., `kLoong64Fst_d`, `kLoong64St_d`) 指令的选择，包括使用参数作为地址的情况。
    * `InstructionSelectorMemoryAccessImmTest`: 测试带立即数偏移的加载和存储指令的选择。涵盖了不同的数据类型和一系列立即数偏移值，验证指令选择器是否能正确处理不同大小的立即数偏移，并选择合适的寻址模式 (`kMode_MRI` 表示立即数寻址，`kMode_MRR` 表示寄存器偏移寻址)。
    * `InstructionSelectorMemoryAccessImmMoreThan16bitTest`:  特别测试了偏移量超过 16 位的加载和存储，在这种情况下，通常需要使用寄存器偏移寻址。
* **测试与零比较指令的选择:**
    * `Word32EqualWithZero` 和 `Word64EqualWithZero`: 测试与零进行相等比较的操作是否生成 `kLoong64Cmp32` 和 `kLoong64Cmp64` 指令，并设置相应的标志位和条件码 (`kFlags_set`, `kEqual`)。
* **测试位操作指令的选择:**
    * `Word32Clz` 和 `Word64Clz`: 测试计算前导零位数的指令 (`kLoong64Clz_w`, `kLoong64Clz_d`)。
* **测试浮点运算指令的选择:**
    * `Float32Abs`, `Float64Abs`, `Float64Max`, `Float64Min`: 测试浮点数的绝对值、最大值和最小值运算指令 (`kLoong64Float32Abs`, `kLoong64Float64Abs`, `kLoong64Float64Max`, `kLoong64Float64Min`)。
* **测试加载后进行右移操作的情况:**
    * `LoadAndShiftRight`: 测试在加载一个 64 位无符号整数后进行算术右移 32 位的操作，并确保移位操作不会与后续的操作（例如加法）错误地合并。
* **测试字节序反转指令的选择:**
    * `Word32ReverseBytes` 和 `Word64ReverseBytes`: 测试 32 位和 64 位整数的字节序反转指令 (`kLoong64ByteSwap32`, `kLoong64ByteSwap64`)。

**总结:**

总而言之，这个文件的第二部分继续深入测试了 LoongArch64 指令选择器的各种功能，包括类型转换的优化、复杂运算的组合优化、加载和存储操作的不同寻址模式、以及其他常见的算术、逻辑和浮点运算指令的选择。这些测试确保了 V8 引擎能够在 LoongArch64 架构上生成高效且正确的机器代码。

**关于 JavaScript 功能的关系:**

指令选择器是 V8 编译流水线的一部分，它将 JavaScript 代码的抽象语法树转换为机器码。虽然这个文件本身是 C++ 代码，用于测试编译过程的一个特定阶段，但它直接影响了 JavaScript 代码在 LoongArch64 架构上的执行效率。

**JavaScript 示例:**

```javascript
function test(a) {
  let b = a | 0; // 将 a 转换为 32 位整数
  let c = b * 2; // 32 位整数乘法
  let d = c >>> 0; // 将结果转换为无符号 32 位整数
  return d;
}

// 或者涉及浮点数的操作
function floatTest(x) {
  return Math.abs(x);
}
```

在编译 `test(a)` 函数时，指令选择器需要为 `a | 0` 选择合适的指令将 `a` 转换为 32 位整数，为乘法操作选择合适的 32 位乘法指令，并为无符号右移选择合适的指令。对于 `floatTest(x)`，指令选择器需要为 `Math.abs(x)` 选择 LoongArch64 的浮点绝对值指令。

**代码逻辑推理 (假设输入与输出):**

假设有以下 C++ 代码片段（来自 `TEST_F(InstructionSelectorTest, ChangeInt32ToInt64)`）：

```c++
StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
m.Return(m.ChangeInt32ToInt64(m.Parameter(0)));
Stream s = m.Build();
```

**假设输入:**  一个类型为 `MachineType::Int32()` 的参数 (例如，在 JavaScript 中传递一个整数)。

**预期输出:**  生成的指令流 `s` 应该包含一个指令，其架构操作码是 `kLoong64Sll_d`。

```
ASSERT_EQ(1U, s.size()); // 预期只有一个指令
EXPECT_EQ(kLoong64Sll_d, s[0]->arch_opcode()); // 验证是逻辑左移指令
```

**涉及用户常见的编程错误 (举例说明):**

在 JavaScript 中，不注意数值类型可能会导致性能问题，而指令选择器可能会尝试优化这些情况，但不一定能完全消除开销。

**示例:**

```javascript
function multiply(a, b) {
  return a * b;
}

let x = 10;
let y = 20;
let result1 = multiply(x, y); // V8 可能会推断为整数乘法

let p = 10.5;
let q = 20.7;
let result2 = multiply(p, q); // V8 需要处理浮点数乘法
```

如果用户在同一个函数中混合使用整数和浮点数进行运算，指令选择器可能需要生成额外的转换指令，或者选择更通用的浮点数运算指令。 虽然指令选择器会尽力优化，但避免不必要的类型转换仍然是编写高效 JavaScript 代码的关键。例如，在明确知道是整数运算的场景下，使用位运算符 `| 0`  (如上面的 `test` 函数) 可以帮助 V8 更早地确定类型，从而可能生成更优化的代码。

总结来说，这个文件的第二部分深入测试了 V8 引擎在 LoongArch64 架构上的指令选择能力，确保了 JavaScript 代码能够被高效地编译和执行。

### 提示词
```
这是目录为v8/test/unittests/compiler/loong64/instruction-selector-loong64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/loong64/instruction-selector-loong64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
angeInt32ToInt64(m.Parameter(0)), m.Int32Constant(32)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Sll_d, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ChangeFloat64ToInt32OfChangeFloat32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
    m.Return(m.ChangeFloat64ToInt32(m.ChangeFloat32ToFloat64(m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kLoong64Float32ToFloat64, s[0]->arch_opcode());
    EXPECT_EQ(kLoong64Float64ToInt32, s[1]->arch_opcode());
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
    EXPECT_EQ(kLoong64Int32ToFloat32, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Mulh_d, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Div_d, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Mod_d, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, ChangeInt32ToInt64AfterLoad) {
  // For each case, test that the conversion is merged into the load
  // operation.
  // ChangeInt32ToInt64(Load_Uint8) -> Ld_bu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_bu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int8) -> Ld_b
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_b, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint16) -> Ld_hu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_hu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int16) -> Ld_h
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_h, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint32) -> Ld_w
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_w, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int32) -> Ld_w
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_w, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
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

  // Ld_bu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_bu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // Ld_hu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_hu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // Ld_wu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Ld_wu, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
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
    {MachineType::Int8(), kLoong64Ld_b, kLoong64St_b},
    {MachineType::Uint8(), kLoong64Ld_bu, kLoong64St_b},
    {MachineType::Int16(), kLoong64Ld_h, kLoong64St_h},
    {MachineType::Uint16(), kLoong64Ld_hu, kLoong64St_h},
    {MachineType::Int32(), kLoong64Ld_w, kLoong64St_w},
    {MachineType::Float32(), kLoong64Fld_s, kLoong64Fst_s},
    {MachineType::Float64(), kLoong64Fld_d, kLoong64Fst_d},
    {MachineType::Int64(), kLoong64Ld_d, kLoong64St_d}};

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

// ----------------------------------------------------------------------------
// Loads and stores immediate values
// ----------------------------------------------------------------------------

const MemoryAccessImm kMemoryAccessesImm[] = {
    {MachineType::Int8(),
     kLoong64Ld_b,
     kLoong64St_b,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint8(),
     kLoong64Ld_bu,
     kLoong64St_b,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int16(),
     kLoong64Ld_h,
     kLoong64St_h,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint16(),
     kLoong64Ld_hu,
     kLoong64St_h,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kLoong64Ld_w,
     kLoong64St_w,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kLoong64Fld_s,
     kLoong64Fst_s,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kLoong64Fld_d,
     kLoong64Fst_d,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kLoong64Ld_d,
     kLoong64St_d,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kLoong64Ld_b,
     kLoong64St_b,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kLoong64Ld_bu,
     kLoong64St_b,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kLoong64Ld_h,
     kLoong64St_h,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kLoong64Ld_hu,
     kLoong64St_h,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kLoong64Ld_w,
     kLoong64St_w,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kLoong64Fld_s,
     kLoong64Fst_s,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kLoong64Fld_d,
     kLoong64Fst_d,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kLoong64Ld_d,
     kLoong64St_d,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}}};

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
    MachineRepresentation rep_type = memacc.type.representation();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    if (((rep_type == MachineRepresentation::kWord64 ||
          rep_type == MachineRepresentation::kWord32) &&
         is_int16(index) && ((index & 0b11) == 0)) ||
        is_int12(index)) {
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    } else {
      EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
      ASSERT_EQ(InstructionOperand::UNALLOCATED, s[0]->InputAt(1)->kind());
    }
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
    MachineRepresentation rep_type = memacc.type.representation();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    if (((rep_type == MachineRepresentation::kWord64 ||
          rep_type == MachineRepresentation::kWord32) &&
         is_int16(index) && ((index & 0b11) == 0)) ||
        is_int12(index)) {
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    } else {
      EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
      ASSERT_EQ(InstructionOperand::UNALLOCATED, s[0]->InputAt(1)->kind());
    }
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
    MachineRepresentation rep_type = memacc.type.representation();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    if (((rep_type == MachineRepresentation::kWord64 ||
          rep_type == MachineRepresentation::kWord32) &&
         is_int16(index) && ((index & 0b11) == 0)) ||
        is_int12(index)) {
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    } else {
      ASSERT_EQ(InstructionOperand::UNALLOCATED, s[0]->InputAt(1)->kind());
      EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    }
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImm));

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
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
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
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmMoreThan16bitTest,
                         ::testing::ValuesIn(kMemoryAccessImmMoreThan16bit));

// ----------------------------------------------------------------------------
// kLoong64Cmp with zero testing.
// ----------------------------------------------------------------------------

TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64Cmp32, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Cmp32, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Cmp64, s[0]->arch_opcode());
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
    EXPECT_EQ(kLoong64Cmp64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Clz_w, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Word64Clz) {
  StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint64());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word64Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Clz_d, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float32Abs) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Float32Abs(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Float32Abs, s[0]->arch_opcode());
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
  EXPECT_EQ(kLoong64Float64Abs, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float64Max) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Float64Max(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Float64Max, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float64Min) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Float64Min(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kLoong64Float64Min, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, LoadAndShiftRight) {
  {
    int32_t immediates[] = {-256, -255, -3,   -2,   -1,    0,    1,
                            2,    3,    255,  256,  260,   4096, 4100,
                            8192, 8196, 3276, 3280, 16376, 16380};
    TRACED_FOREACH(int32_t, index, immediates) {
      StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer());
      Node* const load =
          m.Load(MachineType::Uint64(), m.Parameter(0), m.Int32Constant(index));
      Node* const sar = m.Word64Sar(load, m.Int32Constant(32));
      // Make sure we don't fold the shift into the following add:
      m.Return(m.Int64Add(sar, m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kLoong64Ld_w, s[0]->arch_opcode());
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      EXPECT_EQ(2U, s[0]->InputCount());
      EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
      EXPECT_EQ(index + 4, s.ToInt32(s[0]->InputAt(1)));
      ASSERT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(InstructionSelectorTest, Word32ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64ByteSwap32, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, Word64ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kLoong64ByteSwap64, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```