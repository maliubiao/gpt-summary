Response:
The user wants to understand the functionality of the provided C++ code snippet. This code is a unit test file for the instruction selector on the ARM64 architecture in the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The filename `instruction-selector-arm64-unittest.cc` immediately suggests that this file contains unit tests for the ARM64 instruction selector. Instruction selectors are responsible for translating intermediate representation (IR) of code into machine instructions.

2. **Analyze the Code Structure:** The code uses the Google Test framework (`TEST_F`). Each `TEST_F` block represents a single unit test. Inside each test, there's a common pattern:
    * **`StreamBuilder m(...)`:**  This creates a builder object to construct a sequence of IR nodes.
    * **Node Creation (`m.Parameter(...)`, `m.Word32Shr(...)`, etc.):** These lines build the IR graph that will be tested. The node names (e.g., `Word32Shr`, `Float64Abs`) indicate the operations being tested.
    * **`m.Return(...)`:**  Specifies the final result of the operation.
    * **`Stream s = m.Build()`:** This triggers the instruction selection process on the built IR graph.
    * **Assertions (`ASSERT_EQ`, `EXPECT_EQ`):** These lines verify that the generated machine code (represented by the `Stream s`) matches the expected instructions and operands. The `arch_opcode()` checks the instruction type, `InputCount()` and `OutputCount()` check the number of operands, and `ToVreg()` compares the virtual registers used.

3. **Infer Test Goals:** By looking at the names of the test cases (e.g., `Word32ShrWithWord32Shl`, `Float32Abs`, `CompareAgainstZero32`), it's clear that the tests are designed to verify that specific combinations of IR nodes are correctly translated into the corresponding ARM64 instructions. The tests often check for specific instruction opcodes (like `kArm64Ubfx32`, `kArm64Float32Abs`).

4. **Address Specific Instructions:**
    * **`.tq` Check:**  The file ends in `.cc`, not `.tq`, so it's C++, not Torque.
    * **JavaScript Relation:**  The instruction selector directly impacts how JavaScript code is compiled to machine code. It optimizes the generated instructions for the target architecture. An example would be a JavaScript bitwise operation (`>>`, `<<`) being translated into ARM64 shift instructions.
    * **Code Logic Reasoning:** The tests themselves demonstrate code logic reasoning. For instance, `Word32ShrWithWord32Shl` tests if a right shift after a left shift with the same amount can be optimized (often into a bitfield extraction). To provide a concrete example, consider the input `x << 5 >> 5`. The test verifies this is turned into a `Ubfx` instruction, extracting bits. Input: `x = 0b10101010`, `shift = 5`. Output should isolate the lower bits.
    * **Common Programming Errors:**  While this file doesn't directly demonstrate *user* programming errors, it tests the *compiler's* ability to handle various IR patterns, some of which might arise from user code. A related user error might be misunderstanding the behavior of bitwise shifts, leading to unexpected results that the compiler needs to handle correctly. For example, shifting by an amount greater than or equal to the bit width.
    * **Part Number:** Acknowledge that this is part 7/8 and try to summarize the broader purpose.

5. **Synthesize the Summary:** Combine the above observations into a concise summary of the file's functionality. Emphasize that it tests the correctness of the ARM64 instruction selector.

6. **Structure the Output:**  Organize the findings into the requested sections: functionality, Torque check, JavaScript relation, logic reasoning, common errors, and overall summary. Use clear and concise language.

7. **Refine and Review:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check if all parts of the prompt have been addressed. For example, initially, I might focus heavily on individual test cases. During review, I'd realize the need to generalize and explain the overall purpose of the file within the V8 compilation pipeline. I would also ensure the provided JavaScript example is relevant and easy to understand.
好的，我们来分析一下 `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 这个文件的功能。

**文件功能归纳**

`v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 是 V8 JavaScript 引擎中针对 ARM64 架构的**指令选择器**的单元测试文件。

**具体功能分解**

这个文件的主要目的是测试指令选择器在将中间表示 (IR) 代码转换为 ARM64 机器码的过程中是否正确工作。它通过一系列的单元测试用例来验证：

1. **各种 IR 节点的正确指令选择:**  测试针对不同的 IR 操作节点（例如：算术运算、逻辑运算、位运算、浮点运算、加载存储等）是否选择了正确的 ARM64 指令。
2. **指令操作数的正确生成:** 验证生成的 ARM64 指令的操作数（包括寄存器、立即数、内存地址等）是否正确。
3. **特定 IR 模式的优化:**  测试指令选择器是否能够识别某些特定的 IR 模式并进行优化，例如将多个 IR 节点组合成一个更高效的 ARM64 指令。
4. **对特殊情况的处理:**  测试指令选择器对于边界情况或特殊值的处理，例如对零的比较、特定的立即数值等。
5. **与外部引用和常量的交互:**  测试加载外部引用和常量时指令选择器的行为。
6. **函数调用参数准备:**  测试在准备函数调用参数时，如何使用 `kArm64Poke` 和 `kArm64PokePair` 指令来传递参数。
7. **SIMD 指令的生成:**  测试针对 SIMD (Single Instruction, Multiple Data) 操作的指令选择，特别是对常量零的比较和特定的位运算模式。

**关于文件后缀和 Torque**

该文件的后缀是 `.cc`，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。如果文件以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 的功能关系 (举例)**

指令选择器是 JavaScript 代码编译过程中的一个关键环节。它将高级的 JavaScript 代码经过解析和优化的中间表示，最终转化为可以在 ARM64 处理器上执行的机器指令。

例如，以下 JavaScript 代码中的位移操作：

```javascript
function shiftRight(x) {
  return x >> 5;
}
```

在 V8 的编译过程中，`x >> 5` 这个操作会被表示为一个右移的 IR 节点。 `instruction-selector-arm64-unittest.cc` 中的某些测试用例会验证这个 IR 节点是否被正确地转换为 ARM64 的右移指令，例如 `ASR` (Arithmetic Shift Right)。

**代码逻辑推理 (假设输入与输出)**

以 `TEST_F(InstructionSelectorTest, Word32ShrWithWord32Shl)` 中的一个用例为例：

```c++
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const r = m.Word32Shr(m.Word32Shl(p0, m.Int32Constant(shift)),
                                m.Int32Constant(shift));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
```

* **假设输入 (IR 节点):**
    * 一个参数节点 `p0`，类型为 `Int32`。
    * 一个左移节点，将 `p0` 左移 `shift` 位。
    * 一个右移节点，将左移的结果右移 `shift` 位。
* **预期输出 (ARM64 指令):**
    * 一个 `kArm64Ubfx32` 指令 (Unsigned Bitfield Extract)，用于提取位域。

**推理:**  当一个 32 位的值先左移 `shift` 位，然后再右移相同的 `shift` 位时，相当于提取了原始值的一个位域。指令选择器应该能够识别这种模式，并将其优化为一个 `Ubfx` 指令，而不是生成单独的移位指令。

**用户常见的编程错误 (举例)**

虽然这个测试文件主要关注编译器行为，但它测试的场景可能与用户常见的编程错误有关。例如，位移操作的误用：

```javascript
function wrongShift(x) {
  // 假设用户期望保留低 5 位，但错误地使用了左移再右移
  return (x << 5) >> 3;
}
```

虽然这个测试文件不会直接测试这种用户错误，但它会测试编译器在遇到类似的 IR 模式时是否能够生成正确的代码。 确保编译器能够正确处理各种移位操作的组合对于保证程序的正确性至关重要。

**作为第 7 部分的功能归纳**

考虑到这是 8 个部分中的第 7 部分，可以推断出这个系列的文件共同覆盖了 ARM64 架构指令选择器的各种功能和测试场景。 这部分（第 7 部分）可能专注于以下几个方面：

* **更复杂的算术和逻辑运算组合的指令选择。**
* **浮点运算指令的选择，包括绝对值、最大值、最小值和否定等操作。**
* **涉及内存访问和移位操作的组合，例如加载并进行移位。**
* **条件分支指令的选择，特别是与零比较的情况。**
* **函数调用参数准备的详细测试。**
* **对 SIMD 指令的更深入测试，包括比较和位运算。**

总而言之，`v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 是一个关键的测试文件，用于确保 V8 的 ARM64 指令选择器能够正确且高效地将 JavaScript 代码编译成机器码，从而保证在 ARM64 架构上的性能和正确性。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能

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
      0x00, 0x00, 
"""


```