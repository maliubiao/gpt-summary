Response:
The user wants me to analyze a C++ source code snippet from V8's unit tests.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The code consists of several `TEST_F` blocks within a `InstructionSelectorTest` class. This strongly suggests that the code tests the instruction selection phase of the V8 compiler for the x64 architecture.

2. **Analyze individual tests:**  Each `TEST_F` appears to set up a small computation graph using `StreamBuilder`, representing operations like addition, multiplication, shifts, and memory loads. The `m.Return()` statement signifies the final result of this computation.

3. **Examine the assertions:**  Following `m.Build()`, each test has a series of `ASSERT_EQ` and `EXPECT_EQ` calls. These are crucial for understanding the expected outcome of the instruction selection process. They check:
    * The number of generated instructions (`s.size()`).
    * The opcode of the first (and sometimes subsequent) instruction (`s[0]->arch_opcode()`).
    * The addressing mode used (`s[0]->addressing_mode()`).
    * The number of inputs to the instruction (`s[0]->InputCount()`).
    * The virtual registers assigned to the inputs and outputs of the instruction (`s.ToVreg(...)`).
    * Whether an input is an immediate value (`s[0]->InputAt(2)->IsImmediate()`).

4. **Connect the computation to the assertions:** The key is to understand how the initial computation graph is translated into the expected x64 instructions. For instance:
    * `Int32Add(constant, parameter + scaled_parameter)` often gets optimized into a single `lea` (load effective address) instruction.
    * `Int32Mul` with small constants (2, 3, 4, 5, 8, 9) and shifts by 1, 2, 3 also frequently result in `lea` instructions, leveraging the addressing modes of x64.
    * `Int32Sub` with a constant can be implemented using `sub` or `lea` depending on the usage of the result.
    * Operations involving memory loads often lead to a single instruction combining the load and the operation (e.g., `cmp`, `and`, `or`, `xor`, `sub`). However, `add` with a memory operand seems to require a separate `mov` instruction first.
    * Integer multiplication that can't be expressed with `lea` uses `imul`.
    * Integer high multiplication (`Int32MulHigh`, `Uint32MulHigh`) uses dedicated `imulh` and `umulh` instructions and interacts with the `rax` and `rdx` registers.
    * Floating-point operations use dedicated SSE or AVX instructions.

5. **Infer the functionality:** Based on the observed patterns, the code tests the instruction selector's ability to:
    * Optimize arithmetic operations (especially additions and multiplications with constants) into efficient `lea` instructions.
    * Handle different addressing modes of the x64 architecture.
    * Select appropriate instructions for various integer and floating-point operations.
    * Deal with memory operands in arithmetic and comparison operations.
    * Handle special cases like high multiplication.

6. **Address specific requests:**
    * **Functionality:** List the identified functionalities.
    * **Torque:** Check the file extension. It's `.cc`, not `.tq`.
    * **JavaScript relation:**  Instruction selection directly impacts the performance of JavaScript code compiled by V8. Provide illustrative examples of how the tested optimizations benefit JavaScript.
    * **Logic inference:** For a few key tests, provide the input (the computation graph) and the expected output (the generated assembly instruction).
    * **Common programming errors:** Relate the optimizations to potential programmer mistakes that the compiler helps mitigate.
    * **Overall functionality (for part 2):** Summarize the functionalities covered in this specific snippet.

7. **Structure the response:** Organize the information logically, starting with the overall function, then delving into specifics, and finally addressing the individual constraints. Use clear headings and examples.

Self-correction/Refinement during the thought process:

* Initially, I might focus too much on the individual tests without seeing the bigger picture. Recognizing the pattern of testing instruction selection for specific operations is crucial.
*  It's important to distinguish between what the C++ code *does* (set up tests and assert outcomes) and what the *underlying system* (the instruction selector) does.
* When providing JavaScript examples, ensure they are simple and directly relate to the tested optimizations.
* For logic inference, selecting representative examples that showcase the key optimizations (like `lea` generation) is better than trying to explain every test.
这是第2部分，让我们归纳一下它的功能。

总的来说，这部分代码的功能是**测试V8 JavaScript引擎中x64架构的指令选择器在处理各种整数和浮点数运算时的正确性和优化能力。**  它具体涵盖了以下几个方面的测试：

**1. Int32 加法与乘法的优化 (Lea 指令的运用):**

*   测试了多种形式的 `Int32Add` 和 `Int32Mul` 运算，特别是当其中一个操作数是常量，或者涉及乘以 2、4、8 等 2 的幂次方时，指令选择器是否能正确地生成 `lea` (Load Effective Address) 指令来进行优化。
*   测试了常量的位置变化以及加法结合律对 `lea` 指令生成的影响。

**2. Int32 减法的优化:**

*   测试了当减去一个常量时，指令选择器根据结果的使用情况选择 `subl` 指令（单次使用）或 `leal` 指令（多次使用）。

**3. Int32 高位乘法:**

*   测试了 `Int32MulHigh` 和 `Uint32MulHigh` 操作，验证指令选择器是否生成了正确的 `kX64ImulHigh32` 和 `kX64UmulHigh32` 指令，并正确处理了 `rax` 和 `rdx` 寄存器的分配。

**4. Word32 左移的优化 (Lea 指令的运用):**

*   类似于乘法，测试了当左移的位数为 1、2、3 时，指令选择器是否能生成 `lea` 指令进行优化。

**5. 带有内存操作数的二元运算:**

*   测试了当二元运算（如 `Word32Equal`, `Word32And`, `Word32Or`, `Word32Xor`, `Int32Sub`, `Word64And`, `Word64Or`, `Word64Xor`, `Int64Sub`）的一个操作数是从内存加载时，指令选择器是否生成了正确的指令，例如 `cmp`, `and`, `or`, `xor`, `sub` 等，直接在内存操作数上进行操作。
*   特别地，测试了 `Int32Add` 和 `Int64Add` 与内存操作数结合时，由于 x64 架构的限制，可能需要先将内存中的值加载到寄存器再进行加法运算。

**6. 浮点数运算:**

*   测试了 `Float32Abs` 和 `Float64Abs` 的指令选择。
*   测试了基本的浮点数二元运算（`Float64Add`, `Float64Mul`, `Float64Sub`, `Float64Div`），并验证了在开启 AVX 指令集支持和不开启 AVX 指令集支持时，指令选择器会选择不同的指令 (`kAVXFloat64Add` vs. `kSSEFloat64Add` 等)。
*   测试了带有内存操作数的浮点数二元运算，验证了指令选择器能够正确处理这种情况。

**总结来说，这部分测试旨在覆盖 x64 架构下常见的整数和浮点数运算场景，验证指令选择器能够选择正确的指令，并利用架构特性进行优化，例如使用 `lea` 指令来代替某些加法、乘法和移位操作，以及直接在内存操作数上进行某些运算。** 这对于生成高效的机器码至关重要，直接影响 JavaScript 代码的执行性能。

### 提示词
```
这是目录为v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(m.Int32Add(c0, p0), s0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2MulWithConstantShuffle5) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(m.Int32Add(p0, s0), c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(1));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled4MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(4));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled4ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(2));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled8MulWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(8));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled8ShlWithConstant) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const s0 = m.Word32Shl(p1, m.Int32Constant(3));
  Node* const c0 = m.Int32Constant(15);
  m.Return(m.Int32Add(c0, m.Int32Add(p0, s0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR8I, s[0]->addressing_mode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_TRUE(s[0]->InputAt(2)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32SubConstantAsSub) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(-1);
  // If there is only a single use of on of the sub's non-constant input, use a
  // "subl" instruction.
  m.Return(m.Int32Sub(p0, c0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32SubConstantAsLea) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const c0 = m.Int32Constant(-1);
  // If there are multiple uses of on of the sub's non-constant input, use a
  // "leal" instruction.
  Node* const v0 = m.Int32Sub(p0, c0);
  m.Return(m.Int32Div(p0, v0));
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
}


TEST_F(InstructionSelectorTest, Int32AddScaled2Other) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32(), MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const p2 = m.Parameter(2);
  Node* const s0 = m.Int32Mul(p1, m.Int32Constant(2));
  Node* const a0 = m.Int32Add(s0, p2);
  Node* const a1 = m.Int32Add(p0, a0);
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
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a1), s.ToVreg(s[1]->OutputAt(0)));
}

TEST_F(InstructionSelectorTest, Int32AddMinNegativeDisplacement) {
  // This test case is simplified from a Wasm fuzz test in
  // https://crbug.com/1091892. The key here is that we match on a
  // sequence like: Int32Add(Int32Sub(-524288, -2147483648), -26048), which
  // matches on an EmitLea, with -2147483648 as the displacement. Since we
  // have an Int32Sub node, it sets kNegativeDisplacement, and later we try to
  // negate -2147483648, which overflows.
  StreamBuilder m(this, MachineType::Int32());
  Node* const c0 = m.Int32Constant(-524288);
  Node* const c1 = m.Int32Constant(std::numeric_limits<int32_t>::min());
  Node* const c2 = m.Int32Constant(-26048);
  Node* const a0 = m.Int32Sub(c0, c1);
  Node* const a1 = m.Int32Add(a0, c2);
  m.Return(a1);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());

  EXPECT_EQ(kX64Sub32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(kMode_None, s[0]->addressing_mode());
  EXPECT_EQ(s.ToVreg(c0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(c1), s.ToVreg(s[0]->InputAt(1)));
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[0]->OutputAt(0)));

  EXPECT_EQ(kX64Add32, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(kMode_None, s[1]->addressing_mode());
  EXPECT_EQ(s.ToVreg(a0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_TRUE(s[1]->InputAt(1)->IsImmediate());
  EXPECT_EQ(s.ToVreg(a1), s.ToVreg(s[1]->OutputAt(0)));
}

// -----------------------------------------------------------------------------
// Multiplication.


TEST_F(InstructionSelectorTest, Int32MulWithInt32MulWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const m0 = m.Int32Mul(p0, p1);
  m.Return(m.Int32Mul(m0, p0));
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


TEST_F(InstructionSelectorTest, Int32MulHigh) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Int32MulHigh(p0, p1);
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


TEST_F(InstructionSelectorTest, Uint32MulHigh) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Uint32MulHigh(p0, p1);
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


TEST_F(InstructionSelectorTest, Int32Mul2BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(2);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32Mul3BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(3);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR2, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32Mul4BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(4);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M4, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Int32Mul5BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(5);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR4, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32Mul8BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(8);
  Node* const n = m.Int32Mul(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M8, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Int32Mul9BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(9);
  Node* const n = m.Int32Mul(p0, c1);
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
// Word32Shl.


TEST_F(InstructionSelectorTest, Int32Shl1BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(1);
  Node* const n = m.Word32Shl(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MR1, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
}


TEST_F(InstructionSelectorTest, Int32Shl2BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(2);
  Node* const n = m.Word32Shl(p0, c1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lea32, s[0]->arch_opcode());
  EXPECT_EQ(kMode_M4, s[0]->addressing_mode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
}


TEST_F(InstructionSelectorTest, Int32Shl4BecomesLea) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32(),
                  MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const c1 = m.Int32Constant(3);
  Node* const n = m.Word32Shl(p0, c1);
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

TEST_F(InstructionSelectorTest, LoadCmp32) {
  {
    // Word32Equal(Load[Int8](p0, p1), Int32Constant(0)) -> cmpb [p0,p1], 0
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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

TEST_F(InstructionSelectorTest, LoadAnd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word32And(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64And32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadOr32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word32Or(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Or32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadXor32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word32Xor(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Xor32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadAdd32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Int32Add(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  // Use lea instead of add, so memory operand is invalid.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
  EXPECT_EQ(kX64Lea32, s[1]->arch_opcode());
}

TEST_F(InstructionSelectorTest, LoadSub32) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Int32Sub(p0, m.Load(MachineType::Int32(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Sub32, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadAnd64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word64And(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64And, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadOr64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word64Or(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Or, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadXor64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Word64Xor(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Xor, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

TEST_F(InstructionSelectorTest, LoadAdd64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Int64Add(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  // Use lea instead of add, so memory operand is invalid.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kX64Movq, s[0]->arch_opcode());
  EXPECT_EQ(kX64Lea, s[1]->arch_opcode());
}

TEST_F(InstructionSelectorTest, LoadSub64) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                  MachineType::Int64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  m.Return(
      m.Int64Sub(p0, m.Load(MachineType::Int64(), p1, m.Int32Constant(127))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Sub, s[0]->arch_opcode());
  ASSERT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
}

// -----------------------------------------------------------------------------
// Floating point operations.

TEST_F(InstructionSelectorTest, Float32Abs) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Float32Abs(p0);
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
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Float32Abs(p0);
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


TEST_F(InstructionSelectorTest, Float64Abs) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Float64Abs(p0);
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
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Float64Abs(p0);
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


TEST_F(InstructionSelectorTest, Float64BinopArithmetic) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Float64());
    Node* add = m.Float64Add(m.Parameter(0), m.Parameter(1));
    Node* mul = m.Float64Mul(add, m.Parameter(1));
    Node* sub = m.Float64Sub(mul, add);
    Node* ret = m.Float64Div(mul, sub);
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
    Node* add = m.Float64Add(m.Parameter(0), m.Parameter(1));
    Node* mul = m.Float64Mul(add, m.Parameter(1));
    Node* sub = m.Float64Sub(mul, add);
    Node* ret = m.Float64Div(mul, sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(4U, s.size());
    EXPECT_EQ(kSSEFloat64Add, s[0]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Mul, s[1]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Sub, s[2]->arch_opcode());
    EXPECT_EQ(kSSEFloat64Div, s[3]->arch_opcode());
  }
}

TEST_F(InstructionSelectorTest, Float32BinopArithmeticWithLoad) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                    MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* add = m.Float32Add(
        p0, m.Load(MachineType::Float32(), p1, m.Int32Constant(127)));
    Node* sub = m.Float32Sub(
        add, m.Load(MachineType::Float32(), p1, m.Int32Constant(127)));
    Node* ret = m.Float32Mul(
        m.Load(MachineType::Float32(), p2, m.Int32Constant(127)), sub);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* add = m.Float32Add(
        p0, m.Load(MachineType::Float32(), p1, m.Int32Constant(127)));
    Node* sub = m.Float32Sub(
        add, m.Load(MachineType::Float32(), p1, m.Int32Constant(127)));
    Node* ret = m.Float32Mul(
        m.Load(MachineType::Float32(), p2, m.Int32Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kSSEFloat32Add, s[0]->arch_opc
```