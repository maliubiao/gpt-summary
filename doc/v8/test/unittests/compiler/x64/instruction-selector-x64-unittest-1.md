Response: The user wants a summary of the provided C++ code file. This is the second part of a two-part file. The file seems to be a unit test for the instruction selector in the V8 JavaScript engine, specifically for the x64 architecture.

Therefore, the main function of this file is to test the correct selection of x64 instructions for different intermediate representation (IR) operations. It uses the `InstructionSelectorTest` framework to define various test cases.

The tests cover a range of operations, including:
- Floating-point arithmetic (addition, subtraction, multiplication) with and without memory loads.
- Bitwise shift operations (`Word64Shl`).
- Bitwise AND operations with different constant values.
- Bitwise count leading zeros (`Word32Clz`).
- Loading and bitwise shifting operations.
- SIMD (Single Instruction Multiple Data) operations (if `V8_ENABLE_WEBASSEMBLY` is defined).

For each test case, the code constructs an IR graph using `StreamBuilder`, performs instruction selection using `m.Build()`, and then asserts the correctness of the selected instructions (opcode, input/output counts, and input/output registers).

If `V8_ENABLE_WEBASSEMBLY` is defined, the file also tests various SIMD operations like:
- Splatting a constant zero value.
- Different SIMD shuffle operations with specific opcodes and input counts.
- Shuffling with zero input.
- Swizzling with constant indices.
- Promoting a low F32x4 to F64x2 with a specific load operation.
- Converting integer SIMD vectors to floating-point SIMD vectors.

To illustrate the connection with JavaScript, I need to find a simple JavaScript example that would result in one of the tested instructions. A basic arithmetic operation would be a good starting point.
这个C++源代码文件是V8 JavaScript引擎中用于x64架构的指令选择器的单元测试的第二部分。

它的主要功能是**测试指令选择器是否为特定的中间代码（IR）操作选择了正确的x64机器指令**。 这部分测试覆盖了各种算术、逻辑、位操作以及SIMD（如果启用了WebAssembly）相关的IR操作，并验证了生成的机器指令的类型、输入输出参数的数量以及寄存器的分配是否符合预期。

更具体地说，这部分测试包括以下功能点的指令选择：

- **浮点运算：** 测试了单精度和双精度浮点数的加法、减法和乘法操作，包括直接运算以及与内存加载操作结合的情况。
- **位移操作：** 测试了64位整数的左移操作 (`Word64Shl`)，包括在进行类型转换后的左移。
- **位与操作：**  测试了32位和64位整数的位与操作 (`Word32And`, `Word64And`)，特别是与不同大小的常量进行位与操作，并验证了是否选择了最优的指令（例如，使用 `movzx` 指令进行零扩展）。
- **前导零计数：** 测试了计算32位整数前导零的指令选择 (`Word32Clz`)。
- **加载和位移的组合：** 测试了先从内存加载64位数据，然后进行右移操作的情况，并验证了是否选择了能高效完成操作的指令。
- **SIMD操作（当 `V8_ENABLE_WEBASSEMBLY` 宏被定义时）：**
    - 测试了将常量零值填充到SIMD寄存器的优化 (`SIMDSplatZero`)。
    - 测试了各种SIMD shuffle操作 (`SIMDArchShuffle`, `SIMDArchShuffle256`)，用于重新排列SIMD向量中的元素，并验证了是否选择了特定的架构优化指令。
    - 测试了使用零输入进行SIMD shuffle操作的场景 (`SIMDShuffleWithZeroInputTest`)。
    - 测试了使用常量索引进行SIMD swizzle操作的优化 (`SimdSwizzleConstant`)。
    - 测试了从内存加载数据并进行F32x4到F64x2的类型提升操作 (`F64x2PromoteLowF32x4WithS128Load64Zero`)。
    - 测试了单精度浮点SIMD向量转换指令的选择，特别是当输入来自零扩展操作时 (`SIMDF32x4SConvert`)。

**与 JavaScript 的关系及举例：**

指令选择器是 V8 编译器的一部分，负责将高级的、平台无关的中间代码转换为特定硬件架构（如 x64）的机器指令。 许多 JavaScript 代码最终会通过 V8 编译成机器码，而这些单元测试确保了在 x64 架构上，对于特定的 JavaScript 操作，V8 选择了最高效的机器指令。

例如，考虑以下 JavaScript 代码：

```javascript
function multiplyAndAdd(a, b, c) {
  return a * b + c;
}
```

当 V8 编译这个函数并在 x64 架构上执行时，中间代码中会包含浮点乘法和加法操作。  `InstructionSelectorTest` 中的 `Float32BinopArithmetic` 测试（在第一部分中可能存在类似的测试，或者本部分中的 `Float32BinopArithmeticWithParameter` 和 `Float32BinopArithmeticWithLoad` 测试了类似场景）就是为了验证 V8 在这种情况下是否会选择正确的 x64 浮点乘法 (`kSSEFloat32Mul` 或 `kAVXFloat32Mul`) 和加法 (`kSSEFloat32Add` 或 `kAVXFloat32Add`) 指令。

再例如，考虑一个使用了位与操作的 JavaScript 代码：

```javascript
function maskValue(value) {
  return value & 0xFF;
}
```

`InstructionSelectorTest` 中的 `Word32AndWith0xFF` 测试就是为了验证 V8 是否会选择像 `kX64Movzxbl` 这样的指令，它可以高效地完成位与操作并将结果零扩展到 32 位寄存器中。

对于 SIMD 操作，如果 JavaScript 代码使用了 WebAssembly 的 SIMD 功能（或者未来 JavaScript 本身支持 SIMD），例如：

```javascript
// 需要在 WebAssembly 环境中
const a = i8x16(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
const b = i8x16(16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1);
const shuffled = a.shuffle([1, 15, 2, 14, 3, 13, 4, 12, 5, 11, 6, 10, 7, 9, 8, 0], b);
```

`InstructionSelectorTest` 中的 `InstructionSelectorSIMDArchShuffleTest` 测试就是为了确保对于这样的 shuffle 操作，V8 可以选择像 `kX64I8x16Shuffle` 这样的指令来高效地完成。

总而言之，这个单元测试文件通过模拟各种代码模式，确保 V8 的指令选择器能够为 x64 架构生成正确且高效的机器代码，从而提升 JavaScript 代码在该架构上的执行性能。

Prompt: 
```
这是目录为v8/test/unittests/compiler/x64/instruction-selector-x64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
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

"""


```