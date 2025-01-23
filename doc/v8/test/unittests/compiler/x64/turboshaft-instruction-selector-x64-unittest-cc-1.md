Response:
The user wants to understand the functionality of a C++ unit test file for V8's Turboshaft instruction selector on the x64 architecture. They provided a snippet of the code and asked for:

1. **Functionality Listing:**  What does this test file do?
2. **Torque Source Check:** Does the file extension indicate a Torque file?
3. **JavaScript Relationship:** If related to JavaScript, provide examples.
4. **Code Logic Inference:** Provide example inputs and outputs.
5. **Common Programming Errors:**  Illustrate relevant errors.
6. **Overall Functionality Summary:**  A concise summary of the provided code snippet.

Let's break down the provided C++ code:

* **`TEST_F(TurboshaftInstructionSelectorTest, ...)`:** This indicates the use of Google Test framework for unit testing. Each `TEST_F` defines an individual test case.
* **`StreamBuilder m(...)`:** This seems to be a helper class for constructing a sequence of operations or instructions. The arguments likely define the input and output types of the operations.
* **`m.Parameter(0)`, `m.Parameter(1)`:** These retrieve input parameters to the test case.
* **`m.Word32ShiftLeft(...)`, `m.Word32Add(...)`, `m.Int32Constant(...)`, `m.Word32Sub(...)`, `m.Word32Mul(...)`, `m.Load(...)`:** These are calls to methods of the `StreamBuilder` which seem to represent specific intermediate representation (IR) operations or instructions, like bitwise shift, addition, subtraction, multiplication, and loading from memory.
* **`m.Return(...)`:**  Indicates the return value of the sequence of operations being built.
* **`Stream s = m.Build();`:**  Finalizes the sequence of operations and gets a `Stream` object, presumably containing the generated instructions.
* **`ASSERT_EQ(...)`, `EXPECT_EQ(...)`, `EXPECT_TRUE(...)`:** These are Google Test assertions to check the properties of the generated instruction stream. They are checking things like the number of instructions, the specific opcode of an instruction (`kX64Lea32`, `kX64Imul32`, etc.), the addressing mode (`kMode_MR2I`, `kMode_MRI`, etc.), and the inputs and outputs of the instructions.
* **`s.ToVreg(...)`:** This likely converts an `OpIndex` (representing an intermediate value) to a virtual register representation.
* **The tests focus on specific sequences of operations and check if the instruction selector correctly translates them into the desired x64 assembly instructions.**  Many tests seem to be checking how different combinations of arithmetic operations (add, sub, mul) and bitwise shifts are optimized, often using the `lea` instruction for efficiency. There are also tests related to memory loads.

**Plan for Response:**

1. **Functionality:** Describe the core purpose of the file as testing the Turboshaft instruction selector for x64, focusing on verifying correct instruction generation for various IR patterns.
2. **Torque:** Clearly state that the `.cc` extension indicates a C++ source file, not Torque.
3. **JavaScript:** Since the tests are about how IR is translated to machine code, illustrate the *kind* of JavaScript operations that *might* lead to these IR patterns (e.g., addition, multiplication, bit shifts).
4. **Logic Inference:** Pick a few representative test cases (e.g., `Int32AddScaled2MulWithConstant`) and provide a simple example of the input parameters and the expected output instruction and its properties.
5. **Common Errors:** Explain that these tests help prevent errors in the *compiler* itself, but for users, related errors could be performance issues if these optimizations weren't in place. Give a simple JavaScript example where understanding how these operations are compiled might be relevant for performance (though usually not a direct user concern).
6. **Summary:** Concisely summarize the functionality of the provided snippet, emphasizing the testing of instruction selection for arithmetic and logical operations, including optimizations like using `lea`.
这是对 v8 源代码文件 `v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc` 的功能进行分析的第二部分。

**功能归纳（基于提供的代码片段）**

这部分代码主要测试了 Turboshaft 编译器在 x64 架构上，对于 **32 位整数运算** 的指令选择逻辑，特别是针对以下几种情况：

1. **使用 `lea` 指令进行优化的加法运算：**  测试了多种使用 `lea` (Load Effective Address) 指令来优化加法运算的场景，包括：
    *  将一个寄存器与另一个寄存器左移 1、2 或 3 位（相当于乘以 2、4 或 8）的结果相加，并加上一个常数。这些测试验证了 `lea` 指令的不同寻址模式 (`kMode_MR2I`, `kMode_MR4I`, `kMode_MR8I`) 的正确选择。
    *  将一个寄存器与另一个寄存器乘以 2 或 3 的结果相加 (`kMode_MR1`, `kMode_MR2`)。
    *  更复杂的加法组合，例如 `Word32Add(Word32Add(s0, p2), p0)`，其中 `s0` 是一个左移操作的结果。
2. **常量减法的指令选择：** 测试了当减去一个常量时，编译器会选择 `subl` 指令（如果该非常量输入只被使用一次）或 `leal` 指令（如果该非常量输入被多次使用）。这展示了编译器根据使用情况选择更优指令的能力。
3. **整数乘法的指令选择和优化：**
    *  测试了两个寄存器相乘的基本 `imul32` 指令。
    *  测试了获取乘法溢出位的 `Int32MulOverflownBits` 和 `Uint32MulOverflownBits` 操作，预期会生成 `kX64ImulHigh32` 和 `kX64UmulHigh32` 指令，并检查了对 `rax` 和 `rdx` 寄存器的使用。
    *  测试了当乘以小的常数（2, 3, 4, 5, 8, 9）时，编译器会使用 `lea` 指令进行优化 (`kMode_MR1`, `kMode_MR2`, `kMode_M4`, `kMode_MR4`, `kMode_M8`, `kMode_MR8`)。
4. **左移操作的指令选择和优化：** 测试了当左移小的常数（1, 2, 3）时，编译器会使用 `lea` 指令进行优化 (`kMode_MR1`, `kMode_M4`, `kMode_M8`)。
5. **涉及内存操作数的二元运算：** 测试了将内存加载操作的结果与寄存器中的值进行比较 (`kX64Cmp8`, `kX64Cmp16`, `kX64Cmp32`)、按位与 (`kX64And32`)、按位或 (`kX64Or32`)、按位异或 (`kX64Xor32`)、加法 (`kX64Lea32`) 和减法 (`kX64Sub32`) 的指令选择。这些测试验证了编译器能够将内存加载操作集成到这些二元运算中。
6. **64 位整数运算的指令选择：**  测试了 64 位整数的按位与 (`kX64And`)、按位或 (`kX64Or`)、按位异或 (`kX64Xor`)、加法 (`kX64Lea`) 和减法 (`kX64Sub`) 等操作，特别是当其中一个操作数是从内存加载时。
7. **浮点运算的指令选择：**
    *  测试了 `Float32Abs` 和 `Float64Abs` 操作，验证了 `kX64Float32Abs` 和 `kX64Float64Abs` 指令的生成。
    *  测试了浮点数的加 (`kAVXFloat64Add`, `kSSEFloat64Add`)、乘 (`kAVXFloat64Mul`, `kSSEFloat64Mul`)、减 (`kAVXFloat64Sub`, `kSSEFloat64Sub`)、除 (`kAVXFloat64Div`, `kSSEFloat64Div`) 等基本算术运算的指令选择，包括 AVX 和 SSE 指令集的测试。
    *  测试了将内存加载操作的结果与浮点寄存器进行运算的情况。

**总结来说，这部分测试用例集中验证了 Turboshaft 编译器在 x64 架构上，对于各种常见的 32 位和 64 位整数运算以及浮点运算的指令选择是否正确和高效，特别关注了使用 `lea` 指令进行优化的场景以及涉及内存操作数的二元运算。**

由于您提供了部分代码，以上分析是基于这些片段的。完整的文件可能包含更多类型的测试用例。

### 提示词
```
这是目录为v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
rameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, m.Int32Constant(1));
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled4MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 2);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled4ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, m.Int32Constant(2));
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled8MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 3);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled8ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 3);
  OpIndex const c0 = m.Int32Constant(15);
  m.Return(m.Word32Add(m.Word32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32SubConstantAsSub) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c0 = m.Int32Constant(-1);
  // If there is only a single use of on of the sub's non-constant input, use a
  // "subl" instruction.
  m.Return(m.Word32Sub(p0, c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32SubConstantAsLea) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c0 = m.Int32Constant(-1);
  // If there are multiple uses of on of the sub's non-constant input, use a
  // "leal" instruction.
  OpIndex const v0 = m.Word32Sub(p0, c0);
  m.Return(m.Int32Div(p0, v0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddScaled2Other) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32(), MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const p2 = m.Parameter(2);
  OpIndex const s0 = m.Word32ShiftLeft(p1, 1);
  OpIndex const a0 = m.Word32Add(s0, p2);
  OpIndex const a1 = m.Word32Add(p0, a0);
  m.Return(a1);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[0]->OutputAt(0)));
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(kX64Lea32, s[1]->arch_opcode());
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a1), s.ToVreg(s[1]->OutputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32AddMinNegativeDisplacement) {
  // This test case is simplified from a Wasm fuzz test in
  // https://crbug.com/1091892. The key here is that we match on a
  // sequence like: Word32Add(Word32Sub(-524288, -2147483648), -26048), which
  // matches on an EmitLea, with -2147483648 as the displacement. Since we
  // have an Int32Sub node, it sets kNegativeDisplacement, and later we try to
  // negate -2147483648, which overflows.
  StreamBuilder m(this, MachineType::Int32());
  OpIndex const c0 = m.Int32Constant(-524288);
  OpIndex const c1 = m.Int32Constant(std::numeric_limits<int32_t>::min());
  OpIndex const c2 = m.Int32Constant(-26048);
  OpIndex const a0 = m.Word32Sub(c0, c1);
  OpIndex const a1 = m.Word32Add(a0, c2);
  m.Return(a1);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());

  EXPECT_EQ(kX64Sub32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kMode_None, s[0]->addressing_mode());
  EXPECT_EQ(s.ToVreg(c0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(c1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[0]->OutputAt(0)));

  EXPECT_EQ(kX64Lea32, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_TRUE(s[1]->InputAt(1)->IsImmediate());
  EXPECT_EQ(s.ToVreg(a1), s.ToVreg(s[1]->OutputAt(0)));
}

// -----------------------------------------------------------------------------
// Multiplication.

TEST_F(TurboshaftInstructionSelectorTest, Int32MulWithInt32MulWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const m0 = m.Word32Mul(p0, p1);
  m.Return(m.Word32Mul(m0, p0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Imul32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(m0), s.ToVreg(s[0]->OutputAt(0)));
  EXPECT_EQ(kX64Imul32, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(m0), s.ToVreg(s[1]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32MulOverflownBits) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Int32MulOverflownBits(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64ImulHigh32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s.IsFixed(s[0]->InputAt(0), rax));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(!s.IsUsedAtStart(s[0]->InputAt(1)));
  ASSERT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_TRUE(s.IsFixed(s[0]->OutputAt(0), rdx));
}

TEST_F(TurboshaftInstructionSelectorTest, Uint32MulOverflownBits) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Uint32MulOverflownBits(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64UmulHigh32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s.IsFixed(s[0]->InputAt(0), rax));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(!s.IsUsedAtStart(s[0]->InputAt(1)));
  ASSERT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  EXPECT_TRUE(s.IsFixed(s[0]->OutputAt(0), rdx));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul2BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(2);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul3BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(3);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul4BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(4);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M4, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul5BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(5);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul8BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(8);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M8, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Mul9BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(9);
  OpIndex const n = m.Word32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

// -----------------------------------------------------------------------------
// Word32ShiftLeft.

TEST_F(TurboshaftInstructionSelectorTest, Int32Shl1BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(1);
  OpIndex const n = m.Word32ShiftLeft(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Shl2BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(2);
  OpIndex const n = m.Word32ShiftLeft(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M4, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}

TEST_F(TurboshaftInstructionSelectorTest, Int32Shl4BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const c1 = m.Int32Constant(3);
  OpIndex const n = m.Word32ShiftLeft(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M8, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}

// -----------------------------------------------------------------------------
// Binops with a memory operand.

TEST_F(TurboshaftInstructionSelectorTest, LoadCmp32) {
  {
    // Word32Equal(Load[Int8](p0, p1), Int32Constant(0)) -> cmpb [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(
        m.Word32Equal(m.Load(MachineType::Int8(), p0, p1), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp8, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(LoadImmutable[Int8](p0, p1), Int32Constant(0)) ->
    //  cmpb [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.LoadImmutable(MachineType::Int8(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp8, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Uint8](p0, p1), Int32Constant(0)) -> cmpb [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Uint8(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp8, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Int16](p0, p1), Int32Constant(0)) -> cmpw [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Int16(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp16, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Uint16](p0, p1), Int32Constant(0)) -> cmpw [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Uint16(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp16, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Int32](p0, p1), Int32Constant(0)) -> cmpl [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Int32(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
  {
    // Word32Equal(Load[Uint32](p0, p1), Int32Constant(0)) -> cmpl [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Load(MachineType::Uint32(), p0, p1),
                           m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAnd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word32BitwiseAnd(
      p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64And32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadOr32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word32BitwiseOr(
      p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Or32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadXor32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word32BitwiseXor(
      p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Xor32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAdd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(
      m.Word32Add(p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  // Use lea instead of add, so memory operand is invalid.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
  EXPECT_EQ(kX64Lea32, s[1]->arch_opcode());
}

TEST_F(TurboshaftInstructionSelectorTest, LoadSub32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(
      m.Word32Sub(p0, m.Load(MachineType::Int32(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Sub32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAnd64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word64BitwiseAnd(
      p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64And, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadOr64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word64BitwiseOr(
      p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Or, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadXor64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(m.Word64BitwiseXor(
      p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Xor, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAdd64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(
      m.Word64Add(p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  // Use lea instead of add, so memory operand is invalid.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Movq, s[0]->arch_opcode());
  EXPECT_EQ(kX64Lea, s[1]->arch_opcode());
}

TEST_F(TurboshaftInstructionSelectorTest, LoadSub64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  m.Return(
      m.Word64Sub(p0, m.Load(MachineType::Int64(), p1, m.Int64Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Sub, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

// -----------------------------------------------------------------------------
// Floating point operations.

TEST_F(TurboshaftInstructionSelectorTest, Float32Abs) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Float32Abs(p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Float32Abs, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(s.IsSameAsFirst(s[0]->Output()));
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Float32Abs(p0);
    m.Return(n);
    Stream s = m.Build(AVX);
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Float32Abs, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Abs) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Float64Abs(p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Float64Abs, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(s.IsSameAsFirst(s[0]->Output()));
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Float64Abs(p0);
    m.Return(n);
    Stream s = m.Build(AVX);
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Float64Abs, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Float64BinopArithmetic) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Float64());
    OpIndex add = m.Float64Add(m.Parameter(0), m.Parameter(1));
    OpIndex mul = m.Float64Mul(add, m.Parameter(1));
    OpIndex sub = m.Float64Sub(mul, add);
    OpIndex ret = m.Float64Div(mul, sub);
    m.Return(ret);
    Stream s = m.Build(AVX);
    ASSERT_EQ(4U, s.size());
    EXPECT_EQ(kAVXFloat64Add, s[0]->arch_opcode());
    EXPECT_EQ(kAVXFloat64Mul, s[1]->arch_opcode());
    EXPECT_EQ(kAVXFloat64Sub, s[2]->arch_opcode());
    EXPECT_EQ(kAVXFloat64Div, s[3]->arch_opcode());
  }
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Float64());
    OpIndex add = m.Float64Add(m.Parameter(0), m.Parameter(1));
    OpIndex mul = m.Float64Mul(add, m.Parameter(1));
    OpIndex sub = m.Float64Sub(mul, add);
    OpIndex ret = m.Float64Div(mul, sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(4U, s.size());
    EXPECT_EQ(kSSEFloat64Add, s[0]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Mul, s[1]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Sub, s[2]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Div, s[3]->arch_opcode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Float32BinopArithmeticWithLoad) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const p2 = m.Parameter(2);
    OpIndex add = m.Float32Add(
        p0, m.Load(MachineType::Float32(), p1, m.Int64Constant(127)));
    OpIndex sub = m.Float32Sub(
        add, m.Load(MachineType::Float32(), p1, m.Int64Constant(127)));
    OpIndex ret = m.Float32Mul(
        m.Load(MachineType::Float32(), p2, m.Int64Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build(AVX);
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kAVXFloat32Add, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kAVXFloat32Sub, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[1]->InputCount());
    EXPECT_EQ(kAVXFloat32Mul, s[2]->arch_opcode());
    ASSERT_EQ(3U, s[2]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[2]->InputAt(1)));
  }
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const p2 = m.Parameter(2);
    OpIndex add = m.Float32Add(
        p0, m.Load(MachineType::Float32(), p1, m.Int64Constant(127)));
    OpIndex sub = m.Float32Sub(
        add, m.Load(MachineType::Float32(), p1, m.Int64Constant(127)));
    OpIndex ret = m.Float32Mul(
        m.Load(MachineType::Float32(), p2, m.Int64Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kSSEFloat32Add, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kSSEFloat32Sub, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[1]->InputCount());
    EXPECT_EQ(kSSEFloat32Mul, s[2]->arch_opcode());
    ASSERT_EQ(3U, s[2]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[2]->InputAt(1)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Float64BinopArithmeticWithLoad) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const p2 = m.Parameter(2);
    OpIndex add = m.Float64Add(
        p0, m.Load
```