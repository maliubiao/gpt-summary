Response:
The user wants to understand the functionality of the provided C++ code snippet. This code is part of the V8 JavaScript engine and specifically focuses on unit tests for the instruction selector on the x64 architecture.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `instruction-selector-x64-unittest.cc` clearly indicates that this code tests the instruction selection process for the x64 architecture in V8's compiler.

2. **Analyze the structure:** The code uses the `TEST_F` macro, which is characteristic of Google Test. Each `TEST_F` block represents a specific test case. These test cases are grouped by functionality (e.g., `Float32BinopArithmetic`, `Word64Shl`, `SIMDSplatZero`).

3. **Understand the test logic:** Each test case constructs a sequence of intermediate representation (IR) nodes using `StreamBuilder`. These nodes represent operations like addition, subtraction, loading, shifting, etc. Then, `m.Build()` triggers the instruction selection process, and the resulting instruction stream `s` is analyzed using `ASSERT_EQ` and `EXPECT_EQ` to verify that the correct x64 instructions were selected.

4. **Relate to JavaScript:** Instruction selection is a crucial step in compiling JavaScript code. The IR nodes represent JavaScript operations, and the tests ensure that these operations are translated into efficient x64 machine code.

5. **Consider specific test examples:** Pick a few test cases and trace the logic. For example, `Float32BinopArithmetic` tests how floating-point arithmetic operations are translated to SSE or AVX instructions. `Word64Shl` tests the selection of shift instructions.

6. **Address specific instructions:**
    - Check if the file ends with `.tq`. It does not.
    - Determine if it relates to JavaScript. Yes, it's part of V8's compiler.
    - Provide JavaScript examples for related functionalities.
    - Give examples of code logic inference with input and output.
    - Identify common programming errors that might lead to these tested scenarios.

7. **Summarize the overall functionality.**

**Mental Sandbox:**

- Imagine a simple JavaScript addition `a + b`. The compiler creates IR nodes for this. The instruction selector's job is to pick the right x64 instruction (like `add`) for this operation.
- Think about potential optimizations. For instance, if you're shifting by a constant amount, the instruction selector might use an immediate value in the instruction instead of loading the constant from memory.
- Consider different data types. The tests cover integers (32-bit, 64-bit), floating-point numbers (single and double precision), and SIMD vectors.

By following these steps and iteratively analyzing the code, I can construct a comprehensive summary of its functionality.
这是 `v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc` 源代码的第三部分，与前两部分一起，它主要用于**测试 V8 JavaScript 引擎在 x64 架构上的指令选择器 (`InstructionSelector`) 的功能**。

**具体功能归纳:**

这部分代码延续了前两部分的主题，通过编写各种单元测试来验证 `InstructionSelector` 是否能为不同的中间代码 (IR - Intermediate Representation) 节点选择正确的 x64 机器指令。它覆盖了以下几种操作和场景：

1. **浮点数二元运算与加载 (Float64BinopArithmeticWithLoad):**
   - 测试当浮点数加法、减法、乘法等运算的操作数涉及到从内存加载时，指令选择器是否能正确生成指令。
   - 它分别测试了在启用 AVX 和不启用 AVX 的情况下，是否选择了对应的 AVX 或 SSE 指令。

2. **杂项操作 (Miscellaneous):**
   - **Word64ShlWithChangeInt32ToInt64/Word64ShlWithChangeUint32ToUint64:** 测试 64 位左移操作，其中被移位的值是通过将 32 位整数转换为 64 位整数得到的。验证了移位指令 (`kX64Shl`) 的正确选择以及对移位常数的处理。
   - **Word32AndWith0xFF/Word64AndWith0xFFFFFFFF/Word64AndWith0xFFFF/Word64AndWith0xFF/Word64AndWithInt64FitsUint32/Word64AndWithInt64DontFitsUint32/Word32AndWith0xFFFF:** 测试 32 位和 64 位按位与操作，特别是当与操作的其中一个操作数是特定的常数时，指令选择器是否能进行优化，例如使用 `movzx` 系列指令 (用于零扩展加载) 或直接使用 32 位与指令 (`kX64And32`)。
   - **Word32Clz:** 测试计算 32 位无符号整数前导零个数的操作，验证了 `lzcnt` 指令 (`kX64Lzcnt32`) 的选择。
   - **LoadAndWord64ShiftRight32:** 测试先从内存加载 64 位值，然后进行右移 32 位的操作。验证了 `movl` (移动低 32 位) 和 `movsxlq` (符号扩展移动) 指令的选择，以及对移位常数 32 的处理 (通常会优化为字节偏移量 4)。

3. **WebAssembly SIMD 指令测试 (如果 `V8_ENABLE_WEBASSEMBLY` 宏被定义):**
   - **SIMDSplatZero:** 测试 SIMD 向量的 splat 操作，当 splat 的值是 0 时，指令选择器是否能优化为使用 `v128.zero()` 对应的 `kX64SZero` 指令。
   - **SIMDArchShuffle:** 通过一系列预定义的 `kArchShuffles` 结构体，测试各种 SIMD shuffle (重排向量元素) 操作的指令选择。每个结构体包含一个 shuffle 掩码、期望的 x64 指令 (`arch_opcode`) 和输入数量。这部分测试了 V8 特定的架构 shuffle 优化，例如 `UnpackLow/High`，`UnzipLow/High`，`TransposeLow/High`，以及通过匹配 `Concat` 和 `Rotate`/`Alignr` 等操作来实现的 shuffle。
   - **SIMDArchShuffle256:** 类似于 `SIMDArchShuffle`，但针对 256 位的 SIMD 操作 (如果支持)。
   - **SIMDShuffleWithZeroInputTest:** 测试当 SIMD shuffle 操作的其中一个输入是零向量时，指令选择器是否能进行优化，例如使用 `kX64I32X4ShiftZeroExtendI8x16` 指令。
   - **SIMDSwizzleConstant:** 测试当 SIMD swizzle (基于索引重排元素) 操作的索引是常量时，指令选择器是否能进行优化。
   - **F64x2PromoteLowF32x4WithS128Load64Zero:** 测试将 32 位浮点向量的低 64 位提升为 64 位浮点向量，并且源数据是通过 `S128Load64Zero` 加载的场景。
   - **SIMDF32x4SConvert:** 测试将无符号 32 位整数向量转换为浮点向量的操作，特别是当输入是通过零扩展 16 位整数得到时，是否能使用更高效的有符号转换指令 `kX64F32x4SConvertI32x4`。

**是否为 Torque 代码:**

`v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc` 以 `.cc` 结尾，表明它是一个 **C++ 源代码文件**，而不是 Torque (`.tq`) 文件。Torque 是 V8 用于定义内置函数和运行时函数的领域特定语言。

**与 JavaScript 的关系和示例:**

这些测试直接关系到 V8 如何将 JavaScript 代码编译成高效的 x64 机器码。例如：

```javascript
// 浮点数运算
let a = 1.5;
let b = 2.5;
let c = a + b;
let d = c - a;
let e = c * d;

// 整数位运算
let x = 0b10101010;
let y = 0xFF;
let z = x & y; // 对应 Word32AndWith0xFF

// SIMD (需要启用 WebAssembly)
const arr = new Float32Array([1, 2, 3, 4]);
const simdVec = SIMD.float32x4(arr[0], arr[1], arr[2], arr[3]);
const splattedZero = SIMD.float32x4.splat(0); // 对应 SIMDSplatZero
```

当 V8 编译这些 JavaScript 代码时，会生成对应的 IR 节点，而 `InstructionSelector` 的任务就是将这些 IR 节点转换为合适的 x64 指令，例如浮点数加法会映射到 `addsd` 或 `addps` 等 SSE/AVX 指令，位运算会映射到 `and` 指令，SIMD 操作会映射到各种 SSE/AVX SIMD 指令。

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(InstructionSelectorTest, Word32AndWith0xFF)` 中的一个 case 为例：

**假设输入 (IR 节点):**

- 一个代表参数的节点 `p0`，类型为 `MachineType::Int32()`。
- 一个代表常量 `0xFF` 的节点。
- 一个 `Word32And` 节点，其输入为 `p0` 和常量 `0xFF`。

**预期输出 (选定的机器指令):**

- 一条 `kX64Movzxbl` 指令 (move with zero-extend byte to long)。
- 该指令的输入是 `p0` 对应的寄存器。
- 该指令的输出是一个新的寄存器，存储按位与的结果。

**涉及用户常见的编程错误:**

虽然这个测试文件本身不直接演示用户编程错误，但它测试的编译器功能是为了确保即使在某些情况下，生成的代码也是正确的和高效的。一些可能与这些测试相关的用户编程错误或场景包括：

- **类型不匹配的运算:** 例如，尝试直接将一个未转换为 64 位的 32 位整数与一个 64 位整数进行位运算，编译器需要处理这种类型转换。
- **未考虑符号扩展:** 在位运算中，如果用户期望进行符号扩展，但代码中没有明确进行类型转换，编译器可能需要选择合适的带符号扩展的加载指令。
- **对齐问题:** 虽然这里没有直接测试，但内存加载操作的效率可能受到数据对齐的影响。
- **过度使用或不当使用 SIMD:**  用户可能尝试使用 SIMD 指令，但由于数据布局或操作不当，导致性能下降，编译器需要尽可能优化这些 SIMD 操作。

**总结它的功能 (作为第三部分):**

作为 `v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc` 的第三部分，这段代码继续专注于**验证 V8 在 x64 架构上的指令选择器的正确性和效率**。它通过构造特定的 IR 节点序列，模拟不同的计算场景（包括浮点数运算、整数位运算和 SIMD 操作），并断言指令选择器为这些 IR 节点选择了预期的、优化的 x64 机器指令。这部分特别关注了包含内存加载的浮点数运算、涉及类型转换的位移操作，以及各种 SIMD 指令的优化选择，包括针对常量输入和特定 shuffle 模式的优化。与前两部分共同确保了 V8 能够为 x64 架构生成高质量的机器码。

### 提示词
```
这是目录为v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
ode());
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

TEST_F(InstructionSelectorTest, Float64BinopArithmeticWithLoad) {
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* add = m.Float64Add(
        p0, m.Load(MachineType::Float64(), p1, m.Int32Constant(127)));
    Node* sub = m.Float64Sub(
        add, m.Load(MachineType::Float64(), p1, m.Int32Constant(127)));
    Node* ret = m.Float64Mul(
        m.Load(MachineType::Float64(), p2, m.Int32Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build(AVX);
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kAVXFloat64Add, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kAVXFloat64Sub, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[1]->InputCount());
    EXPECT_EQ(kAVXFloat64Mul, s[2]->arch_opcode());
    ASSERT_EQ(3U, s[2]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[2]->InputAt(1)));
  }
  {
    StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                    MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const p2 = m.Parameter(2);
    Node* add = m.Float64Add(
        p0, m.Load(MachineType::Float64(), p1, m.Int32Constant(127)));
    Node* sub = m.Float64Sub(
        add, m.Load(MachineType::Float64(), p1, m.Int32Constant(127)));
    Node* ret = m.Float64Mul(
        m.Load(MachineType::Float64(), p2, m.Int32Constant(127)), sub);
    m.Return(ret);
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kSSEFloat64Add, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(kSSEFloat64Sub, s[1]->arch_opcode());
    ASSERT_EQ(3U, s[1]->InputCount());
    EXPECT_EQ(kSSEFloat64Mul, s[2]->arch_opcode());
    ASSERT_EQ(3U, s[2]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(s.ToVreg(p2), s.ToVreg(s[2]->InputAt(1)));
  }
}

// -----------------------------------------------------------------------------
// Miscellaneous.


TEST_F(InstructionSelectorTest, Word64ShlWithChangeInt32ToInt64) {
  TRACED_FORRANGE(int64_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64Shl(m.ChangeInt32ToInt64(p0), m.Int64Constant(x));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Shl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(x, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(s.IsSameAsFirst(s[0]->Output()));
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Word64ShlWithChangeUint32ToUint64) {
  TRACED_FORRANGE(int64_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Uint32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64Shl(m.ChangeUint32ToUint64(p0), m.Int64Constant(x));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Shl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(x, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE(s.IsSameAsFirst(s[0]->Output()));
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word32AndWith0xFF) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word32And(p0, m.Int32Constant(0xFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxbl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word32And(m.Int32Constant(0xFF), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxbl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word64AndWith0xFFFFFFFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(p0, m.Int32Constant(0xFFFFFFFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(m.Int32Constant(0xFFFFFFFF), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word64AndWith0xFFFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(p0, m.Int32Constant(0xFFFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxwq, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(m.Int32Constant(0xFFFF), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxwq, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word64AndWith0xFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(p0, m.Int32Constant(0xFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxbq, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(m.Int32Constant(0xFF), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxbq, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word64AndWithInt64FitsUint32) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(p0, m.Int64Constant(15));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64And32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(m.Int64Constant(15), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64And32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word64AndWithInt64DontFitsUint32) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(p0, m.Int64Constant(0x100000000));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64And, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word64And(m.Int64Constant(0x100000000), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64And, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(InstructionSelectorTest, Word32AndWith0xFFFF) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word32And(p0, m.Int32Constant(0xFFFF));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxwl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const n = m.Word32And(m.Int32Constant(0xFFFF), p0);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movzxwl, s[0]->arch_opcode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
  }
}


TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lzcnt32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, LoadAndWord64ShiftRight32) {
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint32());
    Node* const p0 = m.Parameter(0);
    Node* const load = m.Load(MachineType::Uint64(), p0);
    Node* const shift = m.Word64Shr(load, m.Int32Constant(32));
    m.Return(shift);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(4, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(shift), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const load = m.Load(MachineType::Int64(), p0);
    Node* const shift = m.Word64Sar(load, m.Int32Constant(32));
    m.Return(shift);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movsxlq, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(4, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(shift), s.ToVreg(s[0]->Output()));
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const load = m.Load(MachineType::Int64(), p0);
    Node* const shift = m.Word64Sar(load, m.Int32Constant(32));
    Node* const truncate = m.TruncateInt64ToInt32(shift);
    m.Return(truncate);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64Movl, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(4, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(shift), s.ToVreg(s[0]->Output()));
  }
}

#if V8_ENABLE_WEBASSEMBLY
// -----------------------------------------------------------------------------
// SIMD.

TEST_F(InstructionSelectorTest, SIMDSplatZero) {
  // Test optimization for splat of contant 0.
  // {i8x16,i16x8,i32x4,i64x2}.splat(const(0)) -> v128.zero().
  // Optimizations for f32x4.splat and f64x2.splat not implemented since it
  // doesn't improve the codegen as much (same number of instructions).
  {
    StreamBuilder m(this, MachineType::Simd128());
    Node* const splat = m.I64x2Splat(m.Int64Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    Node* const splat = m.I32x4Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    Node* const splat = m.I16x8Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    Node* const splat = m.I8x16Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

struct ArchShuffle {
  uint8_t shuffle[kSimd128Size];
  ArchOpcode arch_opcode;
  size_t input_count;
};

static constexpr ArchShuffle kArchShuffles[] = {
    // These are architecture specific shuffles defined in
    // instruction-selecor-x64.cc arch_shuffles.
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23},
        kX64S64x2UnpackLow,
        2,
    },
    {
        {8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31},
        kX64S64x2UnpackHigh,
        2,
    },
    {
        {0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23},
        kX64S32x4UnpackLow,
        2,
    },
    {
        {8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31},
        kX64S32x4UnpackHigh,
        2,
    },
    {
        {0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23},
        kX64S16x8UnpackLow,
        2,
    },
    {
        {8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31},
        kX64S16x8UnpackHigh,
        2,
    },
    {
        {0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23},
        kX64S8x16UnpackLow,
        2,
    },
    {
        {8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31},
        kX64S8x16UnpackHigh,
        2,
    },
    {
        {0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29},
        kX64S16x8UnzipLow,
        2,
    },
    {
        {2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31},
        kX64S16x8UnzipHigh,
        2,
    },
    {
        {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
        kX64S8x16UnzipLow,
        2,
    },
    {
        {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31},
        kX64S8x16UnzipHigh,
        2,
    },
    {
        {0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30},
        kX64S8x16TransposeLow,
        2,
    },
    {
        {1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31},
        kX64S8x16TransposeHigh,
        2,
    },
    {
        {7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8},
        kX64S8x8Reverse,
        1,
    },
    {
        {3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
        kX64S8x4Reverse,
        1,
    },
    {
        {1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14},
        kX64S8x2Reverse,
        1,
    },
    // These are matched by TryMatchConcat && TryMatch32x4Rotate.
    {
        {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3},
        kX64S32x4Rotate,
        2,
    },
    {
        {8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7},
        kX64S32x4Rotate,
        2,
    },
    {
        {12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
        kX64S32x4Rotate,
        2,
    },
    // These are matched by TryMatchConcat && !TryMatch32x4Rotate.
    {
        {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2},
        kX64S8x16Alignr,
        3,
    },
    {
        {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1},
        kX64S8x16Alignr,
        3,
    },
    {
        {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
        kX64S8x16Alignr,
        3,
    },
    // These are matched by TryMatch32x4Shuffle && is_swizzle.
    {
        {0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15},
        kX64S32x4Swizzle,
        2,
    },
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 8, 9, 10, 11},
        kX64S32x4Swizzle,
        2,
    },
    // These are matched by TryMatch32x4Shuffle && !is_swizzle && TryMatchBlend.
    {
        {0, 1, 2, 3, 20, 21, 22, 23, 8, 9, 10, 11, 28, 29, 30, 31},
        kX64S16x8Blend,
        3,
    },
    {
        {16, 17, 18, 19, 4, 5, 6, 7, 24, 25, 26, 27, 12, 13, 14, 15},
        kX64S16x8Blend,
        3,
    },
    // These are matched by TryMatch32x4Shuffle && !is_swizzle &&
    // TryMatchShufps.
    {
        {0, 1, 2, 3, 8, 9, 10, 11, 28, 29, 30, 31, 28, 29, 30, 31},
        kX64Shufps,
        3,
    },
    {
        {8, 9, 10, 11, 0, 1, 2, 3, 28, 29, 30, 31, 28, 29, 30, 31},
        kX64Shufps,
        3,
    },
    // These are matched by TryMatch32x4Shuffle && !is_swizzle.
    {
        {28, 29, 30, 31, 0, 1, 2, 3, 28, 29, 30, 31, 28, 29, 30, 31},
        kX64S32x4Shuffle,
        4,
    },
    // These are matched by TryMatch16x8Shuffle && TryMatchBlend.
    {
        {16, 17, 2, 3, 4, 5, 6, 7, 24, 25, 26, 27, 12, 13, 14, 15},
        kX64S16x8Blend,
        3,
    },
    // These are matched by TryMatch16x8Shuffle && TryMatchSplat<8>.
    {
        {2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3},
        kX64S16x8Dup,
        2,
    },
    // These are matched by TryMatch16x8Shuffle && TryMatch16x8HalfShuffle.
    {
        {6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9},
        kX64S16x8HalfShuffle1,
        3,
    },
    {
        {6, 7, 4, 5, 2, 3, 0, 1, 30, 31, 28, 29, 26, 27, 24, 25},
        kX64S16x8HalfShuffle2,
        5,
    },
    // These are matched by TryMatchSplat<16>.
    {
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
        kX64S8x16Dup,
        2,
    },
    // Generic shuffle that only uses 1 input.
    {
        {1, 15, 2, 14, 3, 13, 4, 12, 5, 11, 6, 10, 7, 9, 8},
        kX64I8x16Shuffle,
        5,
    },
    // Generic shuffle that uses both input.
    {
        {1, 31, 2, 14, 3, 13, 4, 12, 5, 11, 6, 10, 7, 9, 8},
        kX64I8x16Shuffle,
        6,
    },
};

using InstructionSelectorSIMDArchShuffleTest =
    InstructionSelectorTestWithParam<ArchShuffle>;

TEST_P(InstructionSelectorSIMDArchShuffleTest, SIMDArchShuffle) {
  MachineType type = MachineType::Simd128();
  {
    // Tests various shuffle optimizations
    StreamBuilder m(this, type, type, type);
    auto param = GetParam();
    auto shuffle = param.shuffle;
    const Operator* op = m.machine()->I8x16Shuffle(shuffle);
    Node* n = m.AddNode(op, m.Parameter(0), m.Parameter(1));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDArchShuffleTest,
                         ::testing::ValuesIn(kArchShuffles));

struct ArchShuffle256 {
  uint8_t shuffle[kSimd256Size];
  ArchOpcode arch_opcode;
  size_t input_count;
};

static constexpr ArchShuffle256 kArchShuffles256[] = {
    {{4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 0,  1,  2,  3,
      20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19},
     kX64Vpshufd,
     2}};

using InstructionSelectorSIMDArchShuffle256Test =
    InstructionSelectorTestWithParam<ArchShuffle256>;

TEST_P(InstructionSelectorSIMDArchShuffle256Test, SIMDArchShuffle256) {
  MachineType type = MachineType::Simd128();
  {
    // Tests various shuffle optimizations
    StreamBuilder m(this, type, type, type);
    auto param = GetParam();
    auto shuffle = param.shuffle;
    const Operator* op = m.machine()->I8x32Shuffle(shuffle);
    Node* n = m.AddNode(op, m.Parameter(0), m.Parameter(1));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDArchShuffle256Test,
                         ::testing::ValuesIn(kArchShuffles256));

struct ShuffleWithZeroInput {
  uint8_t shuffle_mask[kSimd128Size];
  ArchOpcode arch_opcode;
  size_t input_count;
};

static constexpr ShuffleWithZeroInput kShuffleWithZeroInput[] = {
    // These are matched by TryMatchByteToDwordZeroExtend.
    {
        {16, 1, 2, 3, 17, 4, 5, 6, 18, 7, 8, 9, 19, 10, 11, 12},
        kX64I32X4ShiftZeroExtendI8x16,
        2,
    },
    // Generic shuffle that uses one zero input.
    {
        {16, 1, 2, 3, 17, 4, 5, 6, 18, 7, 8, 9, 19, 20, 21, 22},
        kX64I8x16Shuffle,
        5,
    },
};

using InstructionSelectorSIMDShuffleWithZeroInputTest =
    InstructionSelectorTestWithParam<ShuffleWithZeroInput>;

TEST_P(InstructionSelectorSIMDShuffleWithZeroInputTest,
       SIMDShuffleWithZeroInputTest) {
  MachineType type = MachineType::Simd128();
  {
    // Tests shuffle to packed zero extend optimization
    uint8_t zeros[kSimd128Size] = {0};
    StreamBuilder m(this, type, type);
    auto param = GetParam();
    const Operator* op = m.machine()->I8x16Shuffle(param.shuffle_mask);
    Node* const c = m.S128Const(zeros);
    Node* n = m.AddNode(op, c, m.Parameter(0));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDShuffleWithZeroInputTest,
                         ::testing::ValuesIn(kShuffleWithZeroInput));

struct SwizzleConstants {
  uint8_t shuffle[kSimd128Size];
  bool omit_add;
};

static constexpr SwizzleConstants kSwizzleConstants[] = {
    {
        // all lanes < kSimd128Size
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
        true,
    },
    {
        // lanes that are >= kSimd128Size have top bit set
        {12, 13, 14, 15, 0x90, 0x91, 0x92, 0x93, 0xA0, 0xA1, 0xA2, 0xA3, 0xFC,
         0xFD, 0xFE, 0xFF},
        true,
    },
    {
        {12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27},
        false,
    },
};

using InstructionSelectorSIMDSwizzleConstantTest =
    InstructionSelectorTestWithParam<SwizzleConstants>;

TEST_P(InstructionSelectorSIMDSwizzleConstantTest, SimdSwizzleConstant) {
  // Test optimization of swizzle with constant indices.
  auto param = GetParam();
  StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
  Node* const c = m.S128Const(param.shuffle);
  Node* swizzle = m.AddNode(m.machine()->I8x16Swizzle(), m.Parameter(0), c);
  m.Return(swizzle);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  ASSERT_EQ(kX64I8x16Swizzle, s[1]->arch_opcode());
  ASSERT_EQ(param.omit_add, s[1]->misc());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorSIMDSwizzleConstantTest,
                         ::testing::ValuesIn(kSwizzleConstants));

TEST_F(InstructionSelectorTest, F64x2PromoteLowF32x4WithS128Load64Zero) {
  StreamBuilder m(this, MachineType::Simd128(), MachineType::Int32());
  Node* const load = m.AddNode(
      m.machine()->LoadTransform(MemoryAccessKind::kProtectedByTrapHandler,
                                 LoadTransformation::kS128Load64Zero),
      m.Int32Constant(2), m.Parameter(0));
  Node* const promote = m.AddNode(m.machine()->F64x2PromoteLowF32x4(), load);
  m.Return(promote);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  ASSERT_EQ(kX64F64x2PromoteLowF32x4, s[0]->arch_opcode());
  ASSERT_EQ(kMode_MRI, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(InstructionSelectorTest, SIMDF32x4SConvert) {
  // Test optimization for F32x4UConvertI32x4.
  // If the input of F32x4UConvertI32x4 is zero-extend from I16x8,
  // F32x4SConvertI32x4 can be used, it's more efficient.
  StreamBuilder m(this, MachineType::Simd128());
  Node* const splat = m.I16x8Splat(m.Int32Constant(0xFFFF));
  Node* const extend = m.AddNode(m.machine()->I32x4UConvertI16x8Low(), splat);
  Node* const convert = m.AddNode(m.machine()->F32x4UConvertI32x4(), extend);
  m.Return(convert);
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kX64F32x4SConvertI32x4, s[2]->arch_opcode());
  ASSERT_EQ(1U, s[2]->InputCount());
  EXPECT_EQ(1U, s[2]->OutputCount());
}

#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```