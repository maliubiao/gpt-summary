Response: The user wants a summary of the functionality of the provided C++ code snippet. This is part 2 of 2 of a file named `turboshaft-instruction-selector-x64-unittest.cc`.

The file seems to be testing the instruction selection phase of the Turboshaft compiler for the x64 architecture in V8. It defines various test cases that check if specific combinations of intermediate representation (IR) operations are correctly translated into corresponding x64 assembly instructions.

Each test case sets up a small computation using the `StreamBuilder`, which allows building a sequence of IR operations. Then, it calls `m.Build()` to trigger instruction selection and asserts the generated assembly instruction sequence (the `Stream`).

The tests cover a range of operations, including:

- **Floating-point arithmetic:** Addition, subtraction, multiplication with AVX and SSE instructions.
- **Bitwise operations:** Shift left, bitwise AND with different constant values, count leading zeros.
- **Loads:** Loading values from memory and combining with shift operations.
- **SIMD (Single Instruction, Multiple Data) operations:** Splatting constants, shuffling, unpacking, zero extension, swizzling, converting between SIMD types, and performing optimized loads.

If there is a relation to JavaScript, it's through the compilation process. JavaScript code gets compiled into machine code, and this unit test verifies a part of that compilation process for specific JavaScript constructs that might involve the tested operations.

Let's create a JavaScript example that would involve some of the tested operations.
这是 `v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc` 文件的第二部分，延续了第一部分的功能，主要目的是**测试 Turboshaft 编译器在 x64 架构下的指令选择器 (instruction selector) 的正确性**。

具体来说，这部分代码包含了更多的单元测试，用于验证当 Turboshaft 编译器遇到特定的中间代码 (IR) 节点组合时，是否能够正确地选择出最优的 x64 汇编指令。

以下是这部分代码中涵盖的一些功能点：

* **更复杂的浮点运算：** 测试了在 AVX 和 SSE 指令集下，浮点数加法、减法和乘法的指令选择情况，并验证了生成的指令数量和操作码是否符合预期。
* **位运算和类型转换的组合优化：**  测试了左移操作与 `ChangeInt32ToInt64` 和 `ChangeUint32ToUint64` 操作结合时的指令选择，例如 `Word64ShiftLeftWithChangeInt32ToInt64` 和 `Word64ShiftLeftWithChangeUint32ToUint64`。
* **特定常量的位与运算优化：**  测试了与特定常量（如 `0xFF`, `0xFFFF`, `0xFFFFFFFF`）进行位与运算时的指令选择优化，例如使用了 `movzxbl`, `movl`, `movzxwq`, `movzxbq` 等指令。
* **位字段提取优化：**  测试了与可以放入 32 位无符号整数的常量进行 64 位位与运算时的优化，使用了 `and32` 指令。
* **前导零计数指令：** 测试了 `Word32CountLeadingZeros` 操作是否能正确选择 `lzcnt32` 指令。
* **加载和右移的组合优化：** 测试了先加载 64 位数据，然后进行逻辑右移或算术右移 32 位的操作，并验证了是否能优化为 `movl` 或 `movsxlq` 指令。
* **SIMD (Single Instruction, Multiple Data) 指令的选择：**
    * **零值填充优化：** 测试了 `I64x2Splat(0)` 等操作是否能优化为 `v128.zero()` 指令。
    * **特定 SIMD Shuffle 指令的匹配：**  定义了一系列预期的 SIMD shuffle 模式和对应的 x64 指令 (例如 `unpcklqdq`, `unpckhpd` 等)，并编写测试用例来验证是否能正确匹配。
    * **SIMD Shuffle 的多种实现方式：** 测试了通过不同的 IR 节点组合（例如 `Simd128Shuffle` 与 `Simd128Constant` 结合）来触发特定的 SIMD shuffle 指令。
    * **SIMD 零扩展和转换优化：** 测试了 SIMD 数据类型的零扩展和类型转换操作的指令选择优化，例如 `I32X4ShiftZeroExtendI8x16` 和 `F32x4SConvertI32x4`。
    * **SIMD Swizzle 操作的常量优化：** 测试了当 Swizzle 操作的索引是常量时，是否可以进行优化。
    * **SIMD LoadTransform 优化：** 测试了 `Simd128LoadTransform` 操作与 `k64Zero` 转换结合时的指令选择，例如 `F64x2PromoteLowF32x4WithS128Load64Zero`。

**与 JavaScript 的关系：**

虽然这是一个 C++ 的单元测试文件，但它直接关系到 V8 引擎执行 JavaScript 代码的效率。Turboshaft 是 V8 的一个优化编译器，它会将 JavaScript 代码编译成高效的机器码。指令选择器是编译过程中的关键一步，它负责将高级的中间代码转换为底层的机器指令。

这些测试用例模拟了 JavaScript 中可能出现的各种操作，例如：

* **浮点数运算：**  JavaScript 中的 `+`, `-`, `*` 等运算符会涉及到浮点数运算。
* **位运算：** JavaScript 中的 `&`, `|`, `^`, `<<`, `>>`, `>>>` 等位运算符。
* **类型转换：**  JavaScript 中 Number 类型的内部表示以及不同数值类型之间的转换。
* **SIMD 操作：**  WebAssembly 的 SIMD 指令集在 JavaScript 中也有相应的 API (`SIMD.js`, 虽然已被废弃，但其概念仍然影响着后续的 SIMD 实现）。例如，操作 SIMD 数组可以对应到这些测试中的 SIMD 指令。

**JavaScript 示例：**

以下是一些与测试用例中涉及的操作相关的 JavaScript 示例：

```javascript
// 对应浮点数运算的测试用例
function floatOperation(a, b, c) {
  return (a + b) - b * c;
}

// 对应位运算和类型转换的测试用例
function bitShift(x) {
  return (x | 0) << 32; // 将 x 转换为 32 位整数后再左移
}

// 对应位与运算的测试用例
function bitmask(value) {
  return value & 0xFF; // 提取 value 的低 8 位
}

// 对应 SIMD 操作的测试用例 (假设有 SIMD API)
// 注意：以下是概念性示例，实际的 SIMD API 可能略有不同
// function simdOperation(a, b) {
//   const vecA = SIMD.float32x4(a[0], a[1], a[2], a[3]);
//   const vecB = SIMD.float32x4(b[0], b[1], b[2], b[3]);
//   const sum = SIMD.float32x4.add(vecA, vecB);
//   return SIMD.float32x4.extractLane(sum, 0);
// }
```

**总结来说，这个 C++ 单元测试文件通过模拟各种代码模式，验证了 Turboshaft 编译器在将中间代码转换为 x64 汇编指令时，能够正确地选择出高效的指令，从而提升 JavaScript 代码的执行效率。** 它是 V8 引擎质量保证的重要组成部分。

Prompt: 
```
这是目录为v8/test/unittests/compiler/x64/turboshaft-instruction-selector-x64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
(MachineType::Float64(), p1, m.Int64Constant(127)));
    OpIndex sub = m.Float64Sub(
        add, m.Load(MachineType::Float64(), p1, m.Int64Constant(127)));
    OpIndex ret = m.Float64Mul(
        m.Load(MachineType::Float64(), p2, m.Int64Constant(127)), sub);
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
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const p2 = m.Parameter(2);
    OpIndex add = m.Float64Add(
        p0, m.Load(MachineType::Float64(), p1, m.Int64Constant(127)));
    OpIndex sub = m.Float64Sub(
        add, m.Load(MachineType::Float64(), p1, m.Int64Constant(127)));
    OpIndex ret = m.Float64Mul(
        m.Load(MachineType::Float64(), p2, m.Int64Constant(127)), sub);
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

TEST_F(TurboshaftInstructionSelectorTest,
       Word64ShiftLeftWithChangeInt32ToInt64) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n =
        m.Word64ShiftLeft(m.ChangeInt32ToInt64(p0), m.Int32Constant(x));
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

TEST_F(TurboshaftInstructionSelectorTest,
       Word64ShiftLeftWithChangeUint32ToUint64) {
  TRACED_FORRANGE(int32_t, x, 32, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Uint32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n =
        m.Word64ShiftLeft(m.ChangeUint32ToUint64(p0), m.Int32Constant(x));
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

TEST_F(TurboshaftInstructionSelectorTest, Word32BitwiseAndWith0xFF) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word32BitwiseAnd(p0, m.Int32Constant(0xFF));
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

TEST_F(TurboshaftInstructionSelectorTest, Word64BitwiseAndWith0xFFFFFFFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(0xFFFFFFFF));
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

TEST_F(TurboshaftInstructionSelectorTest, Word64BitwiseAndWith0xFFFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(0xFFFF));
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

TEST_F(TurboshaftInstructionSelectorTest, Word64BitwiseAndWith0xFF) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(0xFF));
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

TEST_F(TurboshaftInstructionSelectorTest, Word64BitwiseAndWithInt64FitsUint32) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(15));
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

TEST_F(TurboshaftInstructionSelectorTest,
       Word64BitwiseAndWithInt64DontFitsUint32) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word64BitwiseAnd(p0, m.Int64Constant(0x100000000));
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

TEST_F(TurboshaftInstructionSelectorTest, Word32BitwiseAndWith0xFFFF) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const n = m.Word32BitwiseAnd(p0, m.Int32Constant(0xFFFF));
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

TEST_F(TurboshaftInstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Word32CountLeadingZeros(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kX64Lzcnt32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, LoadAndWord64ShiftRight32) {
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const load = m.Load(MachineType::Uint64(), p0);
    OpIndex const shift = m.Word64ShiftRightLogical(load, m.Int32Constant(32));
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
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const load = m.Load(MachineType::Int64(), p0);
    OpIndex const shift =
        m.Word64ShiftRightArithmetic(load, m.Int32Constant(32));
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
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const load = m.Load(MachineType::Int64(), p0);
    OpIndex const shift =
        m.Word64ShiftRightArithmetic(load, m.Int32Constant(32));
    OpIndex const truncate = m.TruncateWord64ToWord32(shift);
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

TEST_F(TurboshaftInstructionSelectorTest, SIMDSplatZero) {
  // Test optimization for splat of contant 0.
  // {i8x16,i16x8,i32x4,i64x2}.splat(const(0)) -> v128.zero().
  // Optimizations for f32x4.splat and f64x2.splat not implemented since it
  // doesn't improve the codegen as much (same number of instructions).
  {
    StreamBuilder m(this, MachineType::Simd128());
    OpIndex const splat = m.I64x2Splat(m.Int64Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    OpIndex const splat = m.I32x4Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    OpIndex const splat = m.I16x8Splat(m.Int32Constant(0));
    m.Return(splat);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kX64SZero, s[0]->arch_opcode());
    ASSERT_EQ(0U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Simd128());
    OpIndex const splat = m.I8x16Splat(m.Int32Constant(0));
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

using TurboshaftInstructionSelectorSIMDArchShuffleTest =
    TurboshaftInstructionSelectorTestWithParam<ArchShuffle>;

TEST_P(TurboshaftInstructionSelectorSIMDArchShuffleTest, SIMDArchShuffle) {
  MachineType type = MachineType::Simd128();
  {
    // Tests various shuffle optimizations
    StreamBuilder m(this, type, type, type);
    auto param = GetParam();
    OpIndex n = m.Simd128Shuffle(m.Parameter(0), m.Parameter(1), param.shuffle);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDArchShuffleTest,
                         ::testing::ValuesIn(kArchShuffles));

// TODO(dmercadier): port to Turboshaft once Turboshaft supports Simd256
// shuffles.
#if 0

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

using TurboshaftInstructionSelectorSIMDArchShuffle256Test =
    TurboshaftInstructionSelectorTestWithParam<ArchShuffle256>;

TEST_P(TurboshaftInstructionSelectorSIMDArchShuffle256Test,
       SIMDArchShuffle256) {
  MachineType type = MachineType::Simd128();
  {
    // Tests various shuffle optimizations
    StreamBuilder m(this, type, type, type);
    auto param = GetParam();
    auto shuffle = param.shuffle;
    const Operator* op = m.machine()->I8x32Shuffle(shuffle);
    OpIndex n = m.AddNode(op, m.Parameter(0), m.Parameter(1));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDArchShuffle256Test,
                         ::testing::ValuesIn(kArchShuffles256));

#endif

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

using TurboshaftInstructionSelectorSIMDShuffleWithZeroInputTest =
    TurboshaftInstructionSelectorTestWithParam<ShuffleWithZeroInput>;

TEST_P(TurboshaftInstructionSelectorSIMDShuffleWithZeroInputTest,
       SIMDShuffleWithZeroInputTest) {
  MachineType type = MachineType::Simd128();
  {
    // Tests shuffle to packed zero extend optimization
    uint8_t zeros[kSimd128Size] = {0};
    StreamBuilder m(this, type, type);
    auto param = GetParam();
    OpIndex const c = m.Simd128Constant(zeros);
    OpIndex n = m.Simd128Shuffle(c, m.Parameter(0), param.shuffle_mask);
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(param.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(param.input_count, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorSIMDShuffleWithZeroInputTest,
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

using TurboshaftInstructionSelectorSIMDSwizzleConstantTest =
    TurboshaftInstructionSelectorTestWithParam<SwizzleConstants>;

TEST_P(TurboshaftInstructionSelectorSIMDSwizzleConstantTest,
       SimdSwizzleConstant) {
  // Test optimization of swizzle with constant indices.
  auto param = GetParam();
  StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
  OpIndex const c = m.Simd128Constant(param.shuffle);
  OpIndex swizzle = m.I8x16Swizzle(m.Parameter(0), c);
  m.Return(swizzle);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  ASSERT_EQ(kX64I8x16Swizzle, s[1]->arch_opcode());
  ASSERT_EQ(param.omit_add, s[1]->misc());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDSwizzleConstantTest,
                         ::testing::ValuesIn(kSwizzleConstants));

TEST_F(TurboshaftInstructionSelectorTest,
       F64x2PromoteLowF32x4WithS128Load64Zero) {
  StreamBuilder m(this, MachineType::Simd128(), MachineType::Int64());
  V<Simd128> const load = m.Simd128LoadTransform(
      m.Parameter(0), m.Int64Constant(2),
      Simd128LoadTransformOp::LoadKind::RawAligned().Protected(),
      Simd128LoadTransformOp::TransformKind::k64Zero, 0);
  V<Simd128> const promote = m.F64x2PromoteLowF32x4(load);
  m.Return(promote);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  ASSERT_EQ(kX64F64x2PromoteLowF32x4, s[0]->arch_opcode());
  ASSERT_EQ(kMode_MRI, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(TurboshaftInstructionSelectorTest, SIMDF32x4SConvert) {
  // Test optimization for F32x4UConvertI32x4.
  // If the input of F32x4UConvertI32x4 is zero-extend from I16x8,
  // F32x4SConvertI32x4 can be used, it's more efficient.
  StreamBuilder m(this, MachineType::Simd128());
  V<Simd128> const splat = m.I16x8Splat(m.Int32Constant(0xFFFF));
  V<Simd128> const extend = m.I32x4UConvertI16x8Low(splat);
  V<Simd128> const convert = m.F32x4UConvertI32x4(extend);
  m.Return(convert);
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kX64F32x4SConvertI32x4, s[2]->arch_opcode());
  ASSERT_EQ(1U, s[2]->InputCount());
  EXPECT_EQ(1U, s[2]->OutputCount());
}

#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace v8::internal::compiler::turboshaft

"""


```