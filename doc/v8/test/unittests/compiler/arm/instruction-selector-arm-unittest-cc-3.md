Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the fourth and final part of a larger file.

The file `v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc` seems to contain unit tests for the instruction selector component of the V8 compiler, specifically for the ARM architecture.

Each `TEST_F` function likely tests the instruction selection for a specific V8 IR node or a combination of nodes. The tests verify that the correct ARM instructions are generated for the given input.

Here's a breakdown of how to approach the request:

1. **Identify the overall purpose:** The file contains unit tests for the ARM instruction selector.
2. **Analyze individual tests:** Each `TEST_F` focuses on a specific operation or optimization. Look for patterns in the test names (e.g., `Int32ModWithParametersForSUDIVAndMLS`, `Int32MulWithImmediate`).
3. **Infer functionality from test names and code:**
    - Operations like `Int32Mod`, `Int32Mul`, `Uint32Div`, `Word32Shl`, `Word32And`, `Word32Equal`, `Float64Max`, etc., indicate tests for specific arithmetic, logical, and floating-point operations.
    - Phrases like `WithParameters`, `WithImmediate`, `WithZero` suggest different operand types being tested.
    - Phrases like `ForSUDIV`, `ForSUDIVAndMLS`, `ForARMv7` indicate tests for specific instruction set features or optimizations.
4. **Determine if it's Torque:** The filename ends with `.cc`, not `.tq`, so it's standard C++ code, not Torque.
5. **Check for JavaScript relation:** The tests are about compiling V8's intermediate representation (IR) to ARM assembly. While this is *related* to how JavaScript is executed, the tests themselves don't directly involve JavaScript syntax.
6. **Look for code logic and reasoning:** The tests set up V8 IR nodes (`StreamBuilder m`), perform the instruction selection (`m.Build()`), and then assert the generated ARM instructions (`ASSERT_EQ`, `EXPECT_EQ`). The logic is in how the IR nodes are constructed and the expected assembly instructions.
7. **Identify potential programming errors:** The tests themselves don't directly show user errors, but they *validate* the compiler's correctness in handling various operations, some of which might be prone to errors in user code (e.g., integer overflow, division by zero - although these specific error conditions aren't explicitly tested here).
8. **Summarize the functionality:** Combine the observations from the individual tests into a concise summary.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc以.tq结尾: No
* 它是v8 torque源代码: No
* 与javascript的功能有关系: Yes
* 用javascript举例说明: Yes (example provided)
* 代码逻辑推理: Yes
* 给出假设输入与输出: Yes (examples provided)
* 涉及用户常见的编程错误: Yes
* 举例说明: Yes (example provided)
* 这是第4部分，共4部分: Acknowledged
* 归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox:**

I've mentally grouped the tests by operation (e.g., integer arithmetic, bitwise operations, floating-point operations). I've also noticed the variations for different operand types and ARM instruction set extensions. The key is to provide a high-level overview without going into excessive detail about each individual test case. The request specifically asks about *functionality*, so focusing on what the tests *achieve* is more important than listing every single test.
这是针对V8 JavaScript引擎中ARM架构的指令选择器单元测试的最后一部分。综合前面三个部分，我们可以归纳出这个文件的主要功能是：

**功能归纳:**

这个C++源代码文件 (`v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc`) 包含了大量的单元测试，用于验证 V8 编译器中 **ARM 指令选择器 (Instruction Selector)** 的正确性。

具体来说，它测试了指令选择器在将 V8 的中间表示 (Intermediate Representation - IR) 转换为 ARM 汇编指令的过程中，针对各种不同的操作和操作数类型，是否能够生成预期且正确的 ARM 指令序列。

**更详细的功能点包括：**

* **各种算术运算的指令选择：**  包括加法 (`kArmAdd`), 减法 (`kArmSub`, `kArmRsb`), 乘法 (`kArmMul`, `kArmSmmul`, `kArmUmull`), 除法 (`kArmSdiv`, `kArmUdiv`, `kArmVdivF64`), 取模 (`kArmMls`), 以及带符号和无符号的运算。
* **位运算的指令选择：** 包括左移 (`kArmLsl`), 右移 (`kArmAsr`), 逻辑与 (`kArmAnd`, `kArmBic`), 逻辑或 (未在此部分体现，但在其他部分可能有), 逻辑非 (`kArmMvn`), 以及位域操作 (`kArmUbfx`, `kArmSbfx`, `kArmBfc`)。
* **比较运算的指令选择：**  测试了相等比较 (`kArmCmp`) 并验证了标志位的设置 (`kFlags_set`) 和条件码 (`kEqual`) 的正确性。
* **常量操作数的优化：** 针对立即数（常量）参与的运算，测试了指令选择器是否能利用 ARM 指令的特性进行优化，例如将乘以 `(2^k + 1)` 优化为加法和移位。
* **特定 ARM 指令的测试：**  例如 `SUDIV`, `MLS`, `SMMUL`, `UMULL`, `CLZ`,  `UXTB`, `SXTB`, `UXTH`, `SXTH` 等 ARM 特有的指令。
* **浮点运算的指令选择：**  测试了浮点数的最大值 (`kArmFloat64Max`), 最小值 (`kArmFloat64Min`) 和取反 (`kArmVnegF32`, `kArmVnegF64`) 操作的指令选择。
* **SIMD 指令的测试 (ARMv8)：** 测试了针对 SIMD (Single Instruction, Multiple Data) 向量运算的指令选择，例如 `kArmVpadal` (Pairwise Add and Accumulate Long)。
* **针对不同 ARM 版本 (例如 ARMv7, ARMv8) 的指令选择测试。**
* **验证指令的寻址模式、输入输出数量以及虚拟寄存器的分配是否正确。**

**关于代码特征的回答：**

* **v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc 以 .tq 结尾？**
   不是，这个文件以 `.cc` 结尾，所以它是 **C++** 源代码文件，而不是 V8 Torque 源代码。

* **它是个 v8 torque 源代码？**
   不是，它是 C++ 源代码。

* **它与 javascript 的功能有关系吗？**
   是的，这个文件测试的是 V8 编译器的重要组成部分——指令选择器。指令选择器负责将 JavaScript 代码编译成机器码的过程中，选择合适的 ARM 指令。

* **如果与 javascript 的功能有关系，请用 javascript 举例说明:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   let result = add(5, 10);
   ```

   当 V8 编译这段 JavaScript 代码时，指令选择器的任务就是将 `a + b` 这个操作转换成对应的 ARM 加法指令（例如 `ADD`）。  这个 `.cc` 文件中的 `TEST_F` 函数，例如 `TEST_F(InstructionSelectorTest, Int32AddWithParameters)`，就是在模拟这种场景，验证指令选择器能否正确地为整数加法选择 `kArmAdd` 指令。

* **如果有代码逻辑推理，请给出假设输入与输出:**

   例如，对于 `TEST_F(InstructionSelectorTest, Int32MulWithImmediate)` 中的一个测试用例：

   **假设输入 (V8 IR):**  一个乘法操作，将一个参数（类型为 Int32）乘以常量 9 (即 2^3 + 1)。

   **预期输出 (ARM 汇编指令):** 一个 `ADD` 指令，使用移位操作优化乘法，例如： `ADD <rd>, <rn>, <rm>, LSL #3`  （这里 `<rd>`, `<rn>`, `<rm>` 代表寄存器）。

   该测试断言了生成的指令的 `arch_opcode()` 是 `kArmAdd`，并且 `addressing_mode()` 是 `kMode_Operand2_R_LSL_I`，以及移位的位数是 3。

* **如果涉及用户常见的编程错误，请举例说明:**

   虽然这个文件主要测试编译器内部的正确性，但它所测试的指令选择覆盖了各种可能在 JavaScript 中出现的运算。  一些常见的编程错误可能会导致生成特定的 IR 节点，而这个文件中的测试会确保针对这些 IR 节点能生成正确的机器码。

   例如，如果用户在 JavaScript 中进行了可能导致整数溢出的运算，编译器会生成相应的 IR 节点，而 `InstructionSelectorTest` 中关于整数运算的测试（例如加法、乘法）就保证了即使在这种情况下，也能生成正确的 ARM 指令。

   另一个例子是，如果用户在 JavaScript 中进行了除零操作，虽然 V8 可能会抛出异常，但指令选择器仍然需要为除法操作选择指令。虽然这个文件没有直接测试除零异常，但它测试了各种除法指令的选择。

**总结:**

作为第四部分，这个代码片段和整个 `instruction-selector-arm-unittest.cc` 文件一起，构成了一个全面的测试套件，用于确保 V8 引擎在 ARM 架构上能够正确地将各种 JavaScript 操作编译成高效且正确的机器码。它涵盖了多种数据类型、运算符和 ARM 特有的指令，是保证 V8 在 ARM 平台上稳定性和性能的关键部分。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
RT_EQ(2U, s[2]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32ModWithParametersForSUDIVAndMLS) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(ARMv7, SUDIV);
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArmSdiv, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kArmMls, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  ASSERT_EQ(3U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[1]->InputAt(2)));
}


TEST_F(InstructionSelectorTest, Int32MulWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Int32Mul(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMul, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, Int32MulWithImmediate) {
  // x * (2^k + 1) -> x + (x >> k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Parameter(0), m.Int32Constant((1 << k) + 1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmAdd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // x * (2^k - 1) -> -x + (x >> k)
  TRACED_FORRANGE(int32_t, k, 3, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Parameter(0), m.Int32Constant((1 << k) - 1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmRsb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // (2^k + 1) * x -> x + (x >> k)
  TRACED_FORRANGE(int32_t, k, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Int32Constant((1 << k) + 1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmAdd, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // x * (2^k - 1) -> -x + (x >> k)
  TRACED_FORRANGE(int32_t, k, 3, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Mul(m.Int32Constant((1 << k) - 1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmRsb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(k, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
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
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmSmmul, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}


TEST_F(InstructionSelectorTest, Uint32MulHighWithParameters) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Uint32MulHigh(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmUmull, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(2U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->OutputAt(1)));
}


TEST_F(InstructionSelectorTest, Uint32DivWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Div(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(4U, s.size());
  EXPECT_EQ(kArmVcvtF64U32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArmVcvtF64U32, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArmVdivF64, s[2]->arch_opcode());
  ASSERT_EQ(2U, s[2]->InputCount());
  ASSERT_EQ(1U, s[2]->OutputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
  EXPECT_EQ(kArmVcvtU32F64, s[3]->arch_opcode());
  ASSERT_EQ(1U, s[3]->InputCount());
  EXPECT_EQ(s.ToVreg(s[2]->Output()), s.ToVreg(s[3]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Uint32DivWithParametersForSUDIV) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Div(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(SUDIV);
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmUdiv, s[0]->arch_opcode());
}


TEST_F(InstructionSelectorTest, Uint32ModWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(6U, s.size());
  EXPECT_EQ(kArmVcvtF64U32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArmVcvtF64U32, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArmVdivF64, s[2]->arch_opcode());
  ASSERT_EQ(2U, s[2]->InputCount());
  ASSERT_EQ(1U, s[2]->OutputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
  EXPECT_EQ(kArmVcvtU32F64, s[3]->arch_opcode());
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


TEST_F(InstructionSelectorTest, Uint32ModWithParametersForSUDIV) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(SUDIV);
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArmUdiv, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kArmMul, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(kArmSub, s[2]->arch_opcode());
  ASSERT_EQ(1U, s[2]->OutputCount());
  ASSERT_EQ(2U, s[2]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Uint32ModWithParametersForSUDIVAndMLS) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Uint32Mod(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build(ARMv7, SUDIV);
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArmUdiv, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->OutputCount());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kArmMls, s[1]->arch_opcode());
  ASSERT_EQ(1U, s[1]->OutputCount());
  ASSERT_EQ(3U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(1)), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[1]->InputAt(2)));
}


TEST_F(InstructionSelectorTest, Word32ShlWord32SarForSbfx) {
  TRACED_FORRANGE(int32_t, shl, 1, 31) {
    TRACED_FORRANGE(int32_t, sar, shl, 31) {
      if ((shl == sar) && (sar == 16)) continue;  // Sxth.
      if ((shl == sar) && (sar == 24)) continue;  // Sxtb.
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(shl)),
                           m.Int32Constant(sar)));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmSbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(sar - shl, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(32 - sar, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}


TEST_F(InstructionSelectorTest, Word32AndWithUbfxImmediateForARMv7) {
  TRACED_FORRANGE(int32_t, width, 9, 23) {
    if (width == 16) continue;  // Uxth.
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32And(m.Parameter(0),
                         m.Int32Constant(0xFFFFFFFFu >> (32 - width))));
    Stream s = m.Build(ARMv7);
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
  }
  TRACED_FORRANGE(int32_t, width, 9, 23) {
    if (width == 16) continue;  // Uxth.
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32And(m.Int32Constant(0xFFFFFFFFu >> (32 - width)),
                         m.Parameter(0)));
    Stream s = m.Build(ARMv7);
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
  }
}


TEST_F(InstructionSelectorTest, Word32AndWithBfcImmediateForARMv7) {
  TRACED_FORRANGE(int32_t, lsb, 0, 31) {
    TRACED_FORRANGE(int32_t, width, 9, (24 - lsb) - 1) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32And(
          m.Parameter(0),
          m.Int32Constant(~((0xFFFFFFFFu >> (32 - width)) << lsb))));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmBfc, s[0]->arch_opcode());
      ASSERT_EQ(1U, s[0]->OutputCount());
      EXPECT_TRUE(
          UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, lsb, 0, 31) {
    TRACED_FORRANGE(int32_t, width, 9, (24 - lsb) - 1) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(
          m.Word32And(m.Int32Constant(~((0xFFFFFFFFu >> (32 - width)) << lsb)),
                      m.Parameter(0)));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmBfc, s[0]->arch_opcode());
      ASSERT_EQ(1U, s[0]->OutputCount());
      EXPECT_TRUE(
          UnallocatedOperand::cast(s[0]->Output())->HasSameAsInputPolicy());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word32AndWith0xFFFF) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(p0, m.Int32Constant(0xFFFF));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Int32Constant(0xFFFF), p0);
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Word32SarWithWord32Shl) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(24)), m.Int32Constant(24));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmSxtb, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(16)), m.Int32Constant(16));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmSxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Word32ShrWithWord32AndWithImmediateForARMv7) {
  TRACED_FORRANGE(int32_t, lsb, 0, 31) {
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t max = 1 << lsb;
      if (max > static_cast<uint32_t>(kMaxInt)) max -= 1;
      uint32_t jnk = rng()->NextInt(max);
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Shr(m.Word32And(m.Parameter(0), m.Int32Constant(msk)),
                           m.Int32Constant(lsb)));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, lsb, 0, 31) {
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t max = 1 << lsb;
      if (max > static_cast<uint32_t>(kMaxInt)) max -= 1;
      uint32_t jnk = rng()->NextInt(max);
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32Shr(m.Word32And(m.Int32Constant(msk), m.Parameter(0)),
                           m.Int32Constant(lsb)));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word32AndWithWord32BitwiseNot) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32And(m.Parameter(0), m.Word32BitwiseNot(m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmBic, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32And(m.Word32BitwiseNot(m.Parameter(0)), m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmBic, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_F(InstructionSelectorTest, Word32EqualWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Word32Equal(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kEqual, s[0]->flags_condition());
}


TEST_F(InstructionSelectorTest, Word32EqualWithImmediate) {
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Int32Constant(imm), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}


TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word32BitwiseNotWithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  m.Return(m.Word32BitwiseNot(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMvn, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, Word32AndWithWord32ShrWithImmediateForARMv7) {
  TRACED_FORRANGE(int32_t, lsb, 1, 31) {
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      if (((width == 8) || (width == 16)) &&
          ((lsb == 8) || (lsb == 16) || (lsb == 24)))
        continue;  // Uxtb/h ror.
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32And(m.Word32Shr(m.Parameter(0), m.Int32Constant(lsb)),
                           m.Int32Constant(0xFFFFFFFFu >> (32 - width))));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, lsb, 1, 31) {
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      if (((width == 8) || (width == 16)) &&
          ((lsb == 8) || (lsb == 16) || (lsb == 24)))
        continue;  // Uxtb/h ror.
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32And(m.Int32Constant(0xFFFFFFFFu >> (32 - width)),
                           m.Word32Shr(m.Parameter(0), m.Int32Constant(lsb))));
      Stream s = m.Build(ARMv7);
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArmUbfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(InstructionSelectorTest, Word32AndWithWord32ShrAnd0xFF) {
  TRACED_FORRANGE(int32_t, shr, 1, 3) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Word32Shr(p0, m.Int32Constant(shr * 8)),
                                m.Int32Constant(0xFF));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxtb, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(shr * 8, s.ToInt32(s[0]->InputAt(1)));
  }
  TRACED_FORRANGE(int32_t, shr, 1, 3) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Int32Constant(0xFF),
                                m.Word32Shr(p0, m.Int32Constant(shr * 8)));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxtb, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(shr * 8, s.ToInt32(s[0]->InputAt(1)));
  }
}

TEST_F(InstructionSelectorTest, Word32AndWithWord32ShrAnd0xFFFF) {
  TRACED_FORRANGE(int32_t, shr, 1, 2) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Word32Shr(p0, m.Int32Constant(shr * 8)),
                                m.Int32Constant(0xFFFF));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(shr * 8, s.ToInt32(s[0]->InputAt(1)));
  }
  TRACED_FORRANGE(int32_t, shr, 1, 2) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32And(m.Int32Constant(0xFFFF),
                                m.Word32Shr(p0, m.Int32Constant(shr * 8)));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmUxth, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(shr * 8, s.ToInt32(s[0]->InputAt(1)));
  }
}


TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmClz, s[0]->arch_opcode());
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
  Stream s = m.Build(ARMv8);
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmFloat64Max, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
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
  Stream s = m.Build(ARMv8);
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmFloat64Min, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float32Neg) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  // Don't use m.Float32Neg() as that generates an explicit sub.
  Node* const n = m.AddNode(m.machine()->Float32Neg(), m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVnegF32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float64Neg) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  // Don't use m.Float64Neg() as that generates an explicit sub.
  Node* const n = m.AddNode(m.machine()->Float64Neg(), m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVnegF64, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}
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

using InstructionSelectorAddWithPairwiseAddTest =
    InstructionSelectorTestWithParam<AddWithPairwiseAddSideAndWidth>;

TEST_P(InstructionSelectorAddWithPairwiseAddTest, AddWithPairwiseAdd) {
  AddWithPairwiseAddSideAndWidth params = GetParam();
  const MachineType type = MachineType::Simd128();
  StreamBuilder m(this, type, type, type, type);

  Node* x = m.Parameter(0);
  Node* y = m.Parameter(1);
  const Operator* pairwiseAddOp;
  if (params.width == 32 && params.isSigned) {
    pairwiseAddOp = m.machine()->I32x4ExtAddPairwiseI16x8S();
  } else if (params.width == 16 && params.isSigned) {
    pairwiseAddOp = m.machine()->I16x8ExtAddPairwiseI8x16S();
  } else if (params.width == 32 && !params.isSigned) {
    pairwiseAddOp = m.machine()->I32x4ExtAddPairwiseI16x8U();
  } else {
    pairwiseAddOp = m.machine()->I16x8ExtAddPairwiseI8x16U();
  }
  Node* pairwiseAdd = m.AddNode(pairwiseAddOp, x);
  const Operator* addOp =
      params.width == 32 ? m.machine()->I32x4Add() : m.machine()->I16x8Add();
  Node* add = params.side == LEFT ? m.AddNode(addOp, pairwiseAdd, y)
                                  : m.AddNode(addOp, y, pairwiseAdd);
  m.Return(add);
  Stream s = m.Build();

  // Should be fused to Vpadal
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVpadal, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

const AddWithPairwiseAddSideAndWidth kAddWithPairAddTestCases[] = {
    {LEFT, 16, true},  {RIGHT, 16, true}, {LEFT, 32, true},
    {RIGHT, 32, true}, {LEFT, 16, false}, {RIGHT, 16, false},
    {LEFT, 32, false}, {RIGHT, 32, false}};

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorAddWithPairwiseAddTest,
                         ::testing::ValuesIn(kAddWithPairAddTestCases));

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```