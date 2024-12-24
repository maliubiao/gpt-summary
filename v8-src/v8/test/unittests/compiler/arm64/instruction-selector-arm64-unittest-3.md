Response: The user wants a summary of the functionality of the provided C++ code, which is part 4 of a larger file. The file seems to contain unit tests for the ARM64 instruction selector in the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name "instruction-selector-arm64-unittest.cc" clearly indicates that it's a unit test file specifically for the ARM64 instruction selector.

2. **Analyze the Test Structure:** The code is structured as a series of `TEST_F` macros. Each `TEST_F` represents an individual test case. The `InstructionSelectorTest` part of the macro name suggests this is a test fixture. Each test typically involves:
    * Creating a `StreamBuilder` to construct a sequence of intermediate representation (IR) nodes.
    * Defining input parameters using `m.Parameter()`.
    * Performing operations on these parameters using methods like `m.Word32Shr()`, `m.Float64Abs()`, etc. These map to specific IR node types.
    * Returning a result using `m.Return()`.
    * Building the instruction stream using `m.Build()`.
    * Asserting properties of the generated instruction stream (`s`). This includes checking the number of instructions (`s.size()`), the opcode of the instruction (`s[0]->arch_opcode()`), the number of inputs (`s[0]->InputCount()`), and the mapping of IR nodes to virtual registers (`s.ToVreg()`).

3. **Infer Functionality from Test Names and Operations:**  The names of the tests (e.g., `Word32ShrWithWord32Shl`, `Float64Abs`, `CompareAgainstZero32`) directly reveal the specific IR node patterns or operations being tested. The operations themselves (shift, absolute value, comparison) are common low-level operations.

4. **Recognize the Connection to JavaScript:** The V8 engine compiles JavaScript code. The instruction selector's job is to translate the high-level IR into machine code for a specific architecture (ARM64 in this case). Therefore, these tests are indirectly related to how JavaScript operations are translated into ARM64 instructions.

5. **Formulate a General Summary:** Based on the above, the primary function is to test the instruction selector's ability to correctly translate various IR node patterns into corresponding ARM64 instructions.

6. **Identify Specific Categories of Tests:**  Scanning the test names reveals groupings of tests:
    * Bitwise operations (shifts, AND, CLZ)
    * Floating-point operations (ABS, ABD, MAX, MIN, NEG, FNMUL)
    * Comparisons (against zero, float comparisons)
    * Memory access (load with shift)
    * Function calls and argument passing (PokePair)
    * (In the latter part) SIMD/vector operations (related to WebAssembly).

7. **Illustrate with JavaScript Examples (If Applicable):** For tests involving standard arithmetic and logical operations, it's straightforward to provide corresponding JavaScript examples. For instance, `Word32Shr` and `Word32Shl` directly map to JavaScript's `>>>` and `<<` operators. Floating-point operations like `Math.abs()` are also direct equivalents. Comparisons using `<`, `>`, `===`, etc., also have clear JavaScript counterparts.

8. **Address the "Part 4" Information:**  The fact that this is part 4 of 4 suggests that the entire file is likely structured into logical sections. Part 4 would likely continue testing different aspects of the instruction selector.

9. **Review and Refine:** Read through the generated summary to ensure clarity, accuracy, and completeness. Make sure the JavaScript examples are correct and relevant. Ensure the summary reflects the key aspects of the code.
这个C++源代码文件是V8 JavaScript引擎针对ARM64架构的指令选择器单元测试的第4部分。它延续了前几部分的功能，主要目的是**测试指令选择器在将中间表示（IR）节点转换为ARM64机器码指令时的正确性**。

具体来说，这部分代码包含了一系列独立的测试用例（以 `TEST_F` 宏定义），每个测试用例都针对特定的IR节点组合或操作，验证指令选择器是否能生成预期的ARM64指令。

以下是这部分代码中测试的一些主要功能点：

* **位运算优化:**
    * 测试 `Word32Shr` (无符号右移) 与 `Word32Shl` (左移) 组合是否能被优化为 `ubfx` 指令 (位域提取)。
    * 测试 `Word32Shl` 与 `Word32And` (按位与) 组合是否能被优化为 `ubfiz` 指令 (位域插入)。
* **其他整数运算:**
    * 测试 `Word32Clz` (计算前导零个数) 是否能正确转换为 `clz` 指令。
* **浮点运算:**
    * 测试 `Float32Abs` 和 `Float64Abs` (绝对值) 是否能正确转换为 `fabs` 指令。
    * 测试 `Float32Abd` 和 `Float64Abd` (绝对差) 是否能正确转换为 `fabd` 指令。
    * 测试 `Float64Max` 和 `Float64Min` (最大值和最小值) 是否能正确转换为 `fmax` 和 `fmin` 指令。
    * 测试通过 `Float32Neg` 和 `Float64Neg` (取负) 以及与乘法 (`Float32Mul`, `Float64Mul`) 组合，能否正确转换为 `fneg` 和 `fnmul` 指令 (融合乘法取负)。
* **内存加载优化:**
    * 测试加载指令 (`Load`) 后跟右移指令 (`Word64Sar`) 是否能被识别并生成优化的 `ldrsw` 指令 (带符号扩展加载字)。
* **比较运算优化:**
    * 测试与零比较的各种条件分支 (`Int32LessThan`, `Int32GreaterThanOrEqual` 等) 是否能被优化为 `cbz` 或 `cbnz` 指令 (比较并跳转)。
    * 特别测试了 `Float64ExtractHighWord32` 配合小于零和大于等于零的比较，验证是否能正确生成 `tbnz` 指令 (测试位并跳转)。
* **外部引用加载:**
    * 测试加载外部引用 (`ExternalConstant`) 能否根据偏移量选择合适的寻址模式，例如使用 `kMode_Root`。
* **函数调用参数准备 (PokePair):**
    * 测试在函数调用前准备参数时，能否正确使用 `kArm64PokePair` 和 `kArm64Poke` 指令来高效地将参数压入栈中，特别是针对不同类型的参数 (Int32, Int64, Float32, Float64) 以及混合类型的情况。
* **WebAssembly SIMD 支持 (如果启用 `V8_ENABLE_WEBASSEMBLY`):**
    * 测试 SIMD (单指令多数据流) 操作，例如：
        * SIMD 常量与零的比较 (`I8x16Eq`, `F64x2Ne` 等)，验证能否优化为单条比较指令。
        * SIMD 按位与 (`S128And`) 和按位与非 (`S128AndNot`) 与常量的组合，验证能否优化为 `and` 或 `bic` 指令。

**与 JavaScript 的关系及举例说明:**

这个文件直接关系到 V8 如何高效地执行 JavaScript 代码。指令选择器的任务是将 JavaScript 代码编译成的抽象语法树 (AST) 转化为更底层的、接近机器码的中间表示，然后再进一步转化为目标架构的机器码。

例如，以下 JavaScript 代码：

```javascript
function foo(a) {
  return a >>> 5; // 无符号右移 5 位
}
```

在 V8 的编译过程中，`>>>` 运算符可能会被表示为一个 `Word32Shr` 的 IR 节点。这个测试文件中的 `TEST_F(InstructionSelectorTest, Word32Shr)` 这样的测试用例就是为了确保当指令选择器遇到 `Word32Shr` 节点时，能够正确地生成 ARM64 的右移指令 (例如 `lsr` 或更复杂的指令，取决于具体情况)。

再例如，JavaScript 的绝对值函数 `Math.abs()`：

```javascript
function bar(x) {
  return Math.abs(x);
}
```

如果 `x` 是一个浮点数，那么 `Math.abs(x)` 在 IR 中可能会被表示为 `Float64Abs` 或 `Float32Abs` 节点。 `TEST_F(InstructionSelectorTest, Float64Abs)`  这样的测试用例就确保了 `Float64Abs` 节点会被正确地转换为 ARM64 的 `fabsd` 指令。

对于函数调用参数准备，例如以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(10, 20);
```

在调用 `add` 函数之前，需要将参数 `10` 和 `20` 传递给函数。指令选择器会生成相应的指令来准备这些参数。 `TEST_F(InstructionSelectorTest, PokePairPrepareArgumentsInt32)` 等测试用例就是为了确保在参数传递过程中，指令选择器能够利用 `kArm64PokePair` 等指令来高效地完成参数传递。

总而言之，这个文件是 V8 引擎为了保证其在 ARM64 架构上高效且正确地执行 JavaScript 代码而进行的大量底层测试的一部分。它专注于指令选择器这个关键组件，确保它能够将高层次的抽象操作转化为最优的 ARM64 指令序列。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word32ShrWithWord32Shl) {
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32Shr(m.Word32Shl(p0, m.Int32Constant(shift)),
                                m.Int32Constant(shift));
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
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32Shr(m.Word32Shl(p0, m.Int32Constant(shift + 32)),
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

TEST_F(InstructionSelectorTest, Word32ShlWithWord32And) {
  TRACED_FORRANGE(int32_t, shift, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Shl(m.Word32And(p0, m.Int32Constant((1 << (31 - shift)) - 1)),
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
    Node* const p0 = m.Parameter(0);
    Node* const r =
        m.Word32Shl(m.Word32And(p0, m.Int32Constant((1u << (31 - shift)) - 1)),
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

TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Clz32, s[0]->arch_opcode());
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
  EXPECT_EQ(kArm64Float32Abs, s[0]->arch_opcode());
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
  EXPECT_EQ(kArm64Float64Abs, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float32Abd) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const fsub = m.Float32Sub(p0, p1);
  Node* const fabs = m.Float32Abs(fsub);
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

TEST_F(InstructionSelectorTest, Float64Abd) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const fsub = m.Float64Sub(p0, p1);
  Node* const fabs = m.Float64Abs(fsub);
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

TEST_F(InstructionSelectorTest, Float64Max) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Float64Max(p0, p1);
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

TEST_F(InstructionSelectorTest, Float64Min) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n = m.Float64Min(p0, p1);
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

TEST_F(InstructionSelectorTest, Float32Neg) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  // Don't use m.Float32Neg() as that generates an explicit sub.
  Node* const n = m.AddNode(m.machine()->Float32Neg(), m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float32Neg, s[0]->arch_opcode());
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
  EXPECT_EQ(kArm64Float64Neg, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Float32NegWithMul) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n1 = m.AddNode(m.machine()->Float32Mul(), p0, p1);
  Node* const n2 = m.AddNode(m.machine()->Float32Neg(), n1);
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

TEST_F(InstructionSelectorTest, Float64NegWithMul) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n1 = m.AddNode(m.machine()->Float64Mul(), p0, p1);
  Node* const n2 = m.AddNode(m.machine()->Float64Neg(), n1);
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

TEST_F(InstructionSelectorTest, Float32MulWithNeg) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n1 = m.AddNode(m.machine()->Float32Neg(), p0);
  Node* const n2 = m.AddNode(m.machine()->Float32Mul(), n1, p1);
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

TEST_F(InstructionSelectorTest, Float64MulWithNeg) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const n1 = m.AddNode(m.machine()->Float64Neg(), p0);
  Node* const n2 = m.AddNode(m.machine()->Float64Mul(), n1, p1);
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

TEST_F(InstructionSelectorTest, LoadAndShiftRight) {
  {
    int32_t immediates[] = {-256, -255, -3,   -2,   -1,    0,    1,
                            2,    3,    255,  256,  260,   4096, 4100,
                            8192, 8196, 3276, 3280, 16376, 16380};
    TRACED_FOREACH(int32_t, index, immediates) {
      StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer());
      Node* const load = m.Load(MachineType::Uint64(), m.Parameter(0),
                                m.Int32Constant(index - 4));
      Node* const sar = m.Word64Sar(load, m.Int32Constant(32));
      // Make sure we don't fold the shift into the following add:
      m.Return(m.Int64Add(sar, m.Parameter(0)));
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

TEST_F(InstructionSelectorTest, CompareAgainstZero32) {
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const param = m.Parameter(0);
    RawMachineLabel a, b;
    m.Branch((m.*cmp.mi.constructor)(param, m.Int32Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, CompareAgainstZero64) {
  TRACED_FOREACH(IntegerCmp, cmp, kBinop64CmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const param = m.Parameter(0);
    RawMachineLabel a, b;
    m.Branch((m.*cmp.mi.constructor)(param, m.Int64Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, CompareFloat64HighLessThanZero64) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  Node* const param = m.Parameter(0);
  Node* const high = m.Float64ExtractHighWord32(param);
  RawMachineLabel a, b;
  m.Branch(m.Int32LessThan(high, m.Int32Constant(0)), &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(1));
  m.Bind(&b);
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

TEST_F(InstructionSelectorTest, CompareFloat64HighGreaterThanOrEqualZero64) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  Node* const param = m.Parameter(0);
  Node* const high = m.Float64ExtractHighWord32(param);
  RawMachineLabel a, b;
  m.Branch(m.Int32GreaterThanOrEqual(high, m.Int32Constant(0)), &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(1));
  m.Bind(&b);
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

TEST_F(InstructionSelectorTest, ExternalReferenceLoad1) {
  // Test offsets we can use kMode_Root for.
  const int64_t kOffsets[] = {0, 1, 4, INT32_MIN, INT32_MAX};
  TRACED_FOREACH(int64_t, offset, kOffsets) {
    StreamBuilder m(this, MachineType::Int64());
    ExternalReference reference =
        base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
    Node* const value =
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

TEST_F(InstructionSelectorTest, ExternalReferenceLoad2) {
  // Offset too large, we cannot use kMode_Root.
  StreamBuilder m(this, MachineType::Int64());
  int64_t offset = 0x100000000;
  ExternalReference reference =
      base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
  Node* const value =
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
void TestPokePair(InstructionSelectorTest::StreamBuilder* m, Zone* zone,
                  MachineSignature::Builder* builder, Node* nodes[],
                  int num_nodes, int expected_poke_pair, int expected_poke) {
  auto call_descriptor =
      InstructionSelectorTest::StreamBuilder::MakeSimpleCallDescriptor(
          zone, builder->Get());

  m->CallN(call_descriptor, num_nodes, nodes);
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

TEST_F(InstructionSelectorTest, PokePairPrepareArgumentsInt32) {
  {
    MachineSignature::Builder builder(zone(), 0, 3);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());

    StreamBuilder m(this, MachineType::AnyTagged());
    Node* nodes[] = {
        m.UndefinedConstant(),
        m.Int32Constant(0),
        m.Int32Constant(0),
        m.Int32Constant(0),
    };

    const int expected_poke_pair = 1;
    // Note: The `+ 1` here comes from the padding Poke in
    // EmitPrepareArguments.
    const int expected_poke = 1 + 1;

    TestPokePair(&m, zone(), &builder, nodes, arraysize(nodes),
                 expected_poke_pair, expected_poke);
  }

  {
    MachineSignature::Builder builder(zone(), 0, 4);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());

    StreamBuilder m(this, MachineType::AnyTagged());
    Node* nodes[] = {
        m.UndefinedConstant(), m.Int32Constant(0), m.Int32Constant(0),
        m.Int32Constant(0),    m.Int32Constant(0),
    };

    const int expected_poke_pair = 2;
    const int expected_poke = 0;

    TestPokePair(&m, zone(), &builder, nodes, arraysize(nodes),
                 expected_poke_pair, expected_poke);
  }
}

TEST_F(InstructionSelectorTest, PokePairPrepareArgumentsInt64) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());

  StreamBuilder m(this, MachineType::AnyTagged());
  Node* nodes[] = {
      m.UndefinedConstant(), m.Int64Constant(0), m.Int64Constant(0),
      m.Int64Constant(0),    m.Int64Constant(0),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, nodes, arraysize(nodes),
               expected_poke_pair, expected_poke);
}

TEST_F(InstructionSelectorTest, PokePairPrepareArgumentsFloat32) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());

  StreamBuilder m(this, MachineType::AnyTagged());
  Node* nodes[] = {
      m.UndefinedConstant(),   m.Float32Constant(0.0f), m.Float32Constant(0.0f),
      m.Float32Constant(0.0f), m.Float32Constant(0.0f),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, nodes, arraysize(nodes),
               expected_poke_pair, expected_poke);
}

TEST_F(InstructionSelectorTest, PokePairPrepareArgumentsFloat64) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());

  StreamBuilder m(this, MachineType::AnyTagged());
  Node* nodes[] = {
      m.UndefinedConstant(),   m.Float64Constant(0.0f), m.Float64Constant(0.0f),
      m.Float64Constant(0.0f), m.Float64Constant(0.0f),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, nodes, arraysize(nodes),
               expected_poke_pair, expected_poke);
}

TEST_F(InstructionSelectorTest, PokePairPrepareArgumentsIntFloatMixed) {
  {
    MachineSignature::Builder builder(zone(), 0, 4);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Float32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Float32());

    StreamBuilder m(this, MachineType::AnyTagged());
    Node* nodes[] = {
        m.UndefinedConstant(), m.Int32Constant(0),      m.Float32Constant(0.0f),
        m.Int32Constant(0),    m.Float32Constant(0.0f),
    };

    const int expected_poke_pair = 0;
    const int expected_poke = 4;

    TestPokePair(&m, zone(), &builder, nodes, arraysize(nodes),
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
    Node* nodes[] = {m.UndefinedConstant(),   m.Float32Constant(0.0f),
                     m.Int32Constant(0),      m.Int32Constant(0),
                     m.Float64Constant(0.0f), m.Int64Constant(0),
                     m.Float64Constant(0.0f), m.Float64Constant(0.0f)};

    const int expected_poke_pair = 2;

    // Note: The `+ 1` here comes from the padding Poke in
    // EmitPrepareArguments.
    const int expected_poke = 3 + 1;

    TestPokePair(&m, zone(), &builder, nodes, arraysize(nodes),
                 expected_poke_pair, expected_poke);
  }
}

#if V8_ENABLE_WEBASSEMBLY
TEST_F(InstructionSelectorTest, PokePairPrepareArgumentsSimd128) {
  MachineSignature::Builder builder(zone(), 0, 2);
  builder.AddParam(MachineType::Simd128());
  builder.AddParam(MachineType::Simd128());

  StreamBuilder m(this, MachineType::AnyTagged());
  Node* nodes[] = {m.UndefinedConstant(),
                   m.AddNode(m.machine()->I32x4Splat(), m.Int32Constant(0)),
                   m.AddNode(m.machine()->I32x4Splat(), m.Int32Constant(0))};

  const int expected_poke_pair = 0;
  const int expected_poke = 2;

  // Using kArm64PokePair is not currently supported for Simd128.
  TestPokePair(&m, zone(), &builder, nodes, arraysize(nodes),
               expected_poke_pair, expected_poke);
}

struct SIMDConstZeroCmTest {
  const bool is_zero;
  const uint8_t lane_size;
  const Operator* (MachineOperatorBuilder::*cm_operator)();
  const ArchOpcode expected_op_left;
  const ArchOpcode expected_op_right;
  const size_t size;
};

static const SIMDConstZeroCmTest SIMDConstZeroCmTests[] = {
    {true, 8, &MachineOperatorBuilder::I8x16Eq, kArm64IEq, kArm64IEq, 1},
    {true, 8, &MachineOperatorBuilder::I8x16Ne, kArm64INe, kArm64INe, 1},
    {true, 8, &MachineOperatorBuilder::I8x16GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 8, &MachineOperatorBuilder::I8x16GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 8, &MachineOperatorBuilder::I8x16Eq, kArm64IEq, kArm64IEq, 2},
    {false, 8, &MachineOperatorBuilder::I8x16Ne, kArm64INe, kArm64INe, 2},
    {false, 8, &MachineOperatorBuilder::I8x16GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 8, &MachineOperatorBuilder::I8x16GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 16, &MachineOperatorBuilder::I16x8Eq, kArm64IEq, kArm64IEq, 1},
    {true, 16, &MachineOperatorBuilder::I16x8Ne, kArm64INe, kArm64INe, 1},
    {true, 16, &MachineOperatorBuilder::I16x8GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 16, &MachineOperatorBuilder::I16x8GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 16, &MachineOperatorBuilder::I16x8Eq, kArm64IEq, kArm64IEq, 2},
    {false, 16, &MachineOperatorBuilder::I16x8Ne, kArm64INe, kArm64INe, 2},
    {false, 16, &MachineOperatorBuilder::I16x8GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 16, &MachineOperatorBuilder::I16x8GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 32, &MachineOperatorBuilder::I32x4Eq, kArm64IEq, kArm64IEq, 1},
    {true, 32, &MachineOperatorBuilder::I32x4Ne, kArm64INe, kArm64INe, 1},
    {true, 32, &MachineOperatorBuilder::I32x4GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 32, &MachineOperatorBuilder::I32x4GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 32, &MachineOperatorBuilder::I32x4Eq, kArm64IEq, kArm64IEq, 2},
    {false, 32, &MachineOperatorBuilder::I32x4Ne, kArm64INe, kArm64INe, 2},
    {false, 32, &MachineOperatorBuilder::I32x4GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 32, &MachineOperatorBuilder::I32x4GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 64, &MachineOperatorBuilder::I64x2Eq, kArm64IEq, kArm64IEq, 1},
    {true, 64, &MachineOperatorBuilder::I64x2Ne, kArm64INe, kArm64INe, 1},
    {true, 64, &MachineOperatorBuilder::I64x2GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 64, &MachineOperatorBuilder::I64x2GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 64, &MachineOperatorBuilder::I64x2Eq, kArm64IEq, kArm64IEq, 2},
    {false, 64, &MachineOperatorBuilder::I64x2Ne, kArm64INe, kArm64INe, 2},
    {false, 64, &MachineOperatorBuilder::I64x2GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 64, &MachineOperatorBuilder::I64x2GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 64, &MachineOperatorBuilder::F64x2Eq, kArm64FEq, kArm64FEq, 1},
    {true, 64, &MachineOperatorBuilder::F64x2Ne, kArm64FNe, kArm64FNe, 1},
    {true, 64, &MachineOperatorBuilder::F64x2Lt, kArm64FGt, kArm64FLt, 1},
    {true, 64, &MachineOperatorBuilder::F64x2Le, kArm64FGe, kArm64FLe, 1},
    {false, 64, &MachineOperatorBuilder::F64x2Eq, kArm64FEq, kArm64FEq, 2},
    {false, 64, &MachineOperatorBuilder::F64x2Ne, kArm64FNe, kArm64FNe, 2},
    {false, 64, &MachineOperatorBuilder::F64x2Lt, kArm64FLt, kArm64FLt, 2},
    {false, 64, &MachineOperatorBuilder::F64x2Le, kArm64FLe, kArm64FLe, 2},
    {true, 32, &MachineOperatorBuilder::F32x4Eq, kArm64FEq, kArm64FEq, 1},
    {true, 32, &MachineOperatorBuilder::F32x4Ne, kArm64FNe, kArm64FNe, 1},
    {true, 32, &MachineOperatorBuilder::F32x4Lt, kArm64FGt, kArm64FLt, 1},
    {true, 32, &MachineOperatorBuilder::F32x4Le, kArm64FGe, kArm64FLe, 1},
    {false, 32, &MachineOperatorBuilder::F32x4Eq, kArm64FEq, kArm64FEq, 2},
    {false, 32, &MachineOperatorBuilder::F32x4Ne, kArm64FNe, kArm64FNe, 2},
    {false, 32, &MachineOperatorBuilder::F32x4Lt, kArm64FLt, kArm64FLt, 2},
    {false, 32, &MachineOperatorBuilder::F32x4Le, kArm64FLe, kArm64FLe, 2},
};

using InstructionSelectorSIMDConstZeroCmTest =
    InstructionSelectorTestWithParam<SIMDConstZeroCmTest>;

TEST_P(InstructionSelectorSIMDConstZeroCmTest, ConstZero) {
  const SIMDConstZeroCmTest param = GetParam();
  uint8_t data[16] = {};
  if (!param.is_zero) data[0] = 0xff;
  // Const node on the left
  {
    StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
    Node* cnst = m.S128Const(data);
    Node* fcm =
        m.AddNode((m.machine()->*param.cm_operator)(), cnst, m.Parameter(0));
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
    Node* cnst = m.S128Const(data);
    Node* fcm =
        m.AddNode((m.machine()->*param.cm_operator)(), m.Parameter(0), cnst);
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDConstZeroCmTest,
                         ::testing::ValuesIn(SIMDConstZeroCmTests));

struct SIMDConstAndTest {
  const uint8_t data[16];
  const Operator* (MachineOperatorBuilder::*simd_op)();
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
     &MachineOperatorBuilder::S128And,
     kArm64S128AndNot,
     true,
     16,
     8,
     0x01,
     1},
    {{0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF,
      0xFE, 0xFF, 0xFE, 0xFF},
     &MachineOperatorBuilder::S128And,
     kArm64S128AndNot,
     true,
     16,
     0,
     0x01,
     1},

    {{0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE,
      0xFF, 0xFF, 0xFF, 0xFE},
     &MachineOperatorBuilder::S128And,
     kArm64S128AndNot,
     true,
     32,
     24,
     0x01,
     1},
    {{0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF,
      0xFF, 0xFF, 0xFE, 0xFF},
     &MachineOperatorBuilder::S128And,
     kArm64S128AndNot,
     true,
     32,
     16,
     0x01,
     1},
    {{0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
      0xFF, 0xFE, 0xFF, 0xFF},
     &MachineOperatorBuilder::S128And,
     kArm64S128AndNot,
     true,
     32,
     8,
     0x01,
     1},
    {{0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
      0xFE, 0xFF, 0xFF, 0xFF},
     &MachineOperatorBuilder::S128And,
     kArm64S128AndNot,
     true,
     32,
     0,
     0x01,
     1},

    {{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
      0xEE, 0xEE, 0xEE, 0xEE},
     &MachineOperatorBuilder::S128And,
     kArm64S128And,
     true,
     0,
     0,
     0x00,
     2},

    {{0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x01, 0x00, 0x01},
     &MachineOperatorBuilder::S128AndNot,
     kArm64S128AndNot,
     false,
     16,
     8,
     0x01,
     1},
    {{0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x01, 0x00},
     &MachineOperatorBuilder::S128AndNot,
     kArm64S128AndNot,
     false,
     16,
     0,
     0x01,
     1},

    {{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01},
     &MachineOperatorBuilder::S128AndNot,
     kArm64S128AndNot,
     false,
     32,
     24,
     0x01,
     1},
    {{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x01, 0x00},
     &MachineOperatorBuilder::S128AndNot,
     kArm64S128AndNot,
     false,
     32,
     16,
     0x01,
     1},
    {{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x00},
     &MachineOperatorBuilder::S128AndNot,
     kArm64S128AndNot,
     false,
     32,
     8,
     0x01,
     1},
    {{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00},
     &MachineOperatorBuilder::S128AndNot,
     kArm64S128AndNot,
     false,
     32,
     0,
     0x01,
     1},

    {{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
      0xEE, 0xEE, 0xEE, 0xEE},
     &MachineOperatorBuilder::S128AndNot,
     kArm64S128AndNot,
     false,
     0,
     0,
     0x00,
     2},
};

using InstructionSelectorSIMDConstAndTest =
    InstructionSelectorTestWithParam<SIMDConstAndTest>;

TEST_P(InstructionSelectorSIMDConstAndTest, ConstAnd) {
  const SIMDConstAndTest param = GetParam();
  // Const node on the left
  {
    StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
    Node* cnst = m.S128Const(param.data);
    Node* op = m.AddNode((m.machine()->*param.simd_op)(), cnst, m.Parameter(0));
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
    Node* cnst = m.S128Const(param.data);
    Node* op = m.AddNode((m.machine()->*param.simd_op)(), m.Parameter(0), cnst);
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDConstAndTest,
                         ::testing::ValuesIn(SIMDConstAndTests));
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace v8::internal::compiler

"""


```