Response: The user wants a summary of the functionality of the provided C++ code file. This is the fourth part of a series of four files. The file appears to be a unit test suite for the Turboshaft instruction selector on the ARM64 architecture within the V8 JavaScript engine.

Therefore, the main function of this file is to test the correct instruction selection for various operations on the ARM64 architecture. It achieves this by constructing small code snippets (using `StreamBuilder`) representing different operations and then verifying that the instruction selector produces the expected ARM64 assembly instructions (`kArm64...` opcodes).

Since this is part 4, it's likely that this file continues testing different kinds of operations compared to the previous parts.

Regarding the relationship with JavaScript, the instruction selector is a crucial component in the JavaScript compilation pipeline. It translates high-level intermediate representations of JavaScript code into low-level machine instructions.

To illustrate with JavaScript, let's consider a simple JavaScript addition operation that might be tested in this file.
这是 `v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc` 文件的第 4 部分，它继续测试 Turboshaft 编译器在 ARM64 架构上的指令选择功能。

该文件通过一系列的单元测试，针对不同的操作和场景，验证 Turboshaft 编译器是否能正确地将中间表示 (IR) 的操作符转换为相应的 ARM64 汇编指令。

具体而言，这部分测试涵盖了以下功能：

* **位域提取 (Bitfield Extract):**  测试 `Word64ShiftRightLogical` 与 `Word64BitwiseAnd` 的组合是否能正确地转换为 `kArm64Ubfx` 指令，用于提取 64 位值中的位域。
* **高位乘法 (Multiply High):** 测试 `Int32MulOverflownBits` 和 `Uint32MulOverflownBits` 操作，以及它们与移位 (`Word32ShiftRightArithmetic`, `Word32ShiftRightLogical`) 和加法 (`Word32Add`) 操作的组合，是否能正确地转换为 `kArm64Smull` 或 `kArm64Umull` 指令，并处理结果的高位。
* **移位操作的优化:** 测试特定模式的移位操作，例如 `Word32ShiftRightArithmetic` 紧跟 `Word32ShiftLeft`，以及 `Word32ShiftLeft` 紧跟 `Word32BitwiseAnd`，是否能被优化为更高效的位域操作指令，如 `kArm64Sbfx32` 和 `kArm64Ubfx32` 或 `kArm64Ubfiz32`。
* **前导零计数 (Count Leading Zeros):** 测试 `Word32CountLeadingZeros` 操作是否能正确转换为 `kArm64Clz32` 指令。
* **浮点运算:** 测试各种单精度 (`Float32`) 和双精度 (`Float64`) 浮点运算，包括绝对值 (`Abs`), 绝对差 (`Abd`), 最大值 (`Max`), 最小值 (`Min`), 取反 (`Negate`) 以及与乘法结合的取反乘 (`Fnmul`) 操作，是否能正确转换为对应的 ARM64 浮点指令，例如 `kArm64Float32Abs`, `kArm64Float64Abd`, `kArm64Float64Max` 等。
* **加载和移位组合:** 测试加载操作 (`Load`) 后紧跟算术右移 (`Word64ShiftRightArithmetic`) 是否能正确处理，特别是在与符号扩展加载指令 `kArm64Ldrsw` 的配合使用上。
* **与零比较和分支:** 测试各种与零比较的操作 (`Int32LessThan`, `Int32GreaterThanOrEqual` 等) 是否能转换为 `kArm64CompareAndBranch32` 或 `kArm64TestAndBranch32` 等条件分支指令。
* **浮点数高位比较:** 测试提取双精度浮点数高 32 位 (`Float64ExtractHighWord32`) 后与零比较的操作，是否能正确转换为 `kArm64U64MoveFloat64` 和 `kArm64TestAndBranch` 的组合。
* **外部引用加载:** 测试加载外部引用的操作 (`Load` with `ExternalConstant`) 是否能正确利用 ARM64 的寻址模式，包括 `kMode_Root` 模式。
* **函数调用参数准备 (Poke Pair):** 测试在函数调用前准备参数时，是否能有效地使用 `kArm64PokePair` 和 `kArm64Poke` 指令，尤其是针对不同类型的参数 (整数、浮点数)。
* **WebAssembly SIMD 指令 (如果启用):** 这部分测试针对 WebAssembly 的 SIMD (Single Instruction, Multiple Data) 指令，包括与零比较 (`kI8x16Eq`, `kF64x2Ne` 等) 和按位与/与非 (`kS128And`, `kS128AndNot`) 操作，验证是否能正确转换为相应的 ARM64 SIMD 指令，例如 `kArm64IEq`, `kArm64FNe`, `kArm64S128AndNot` 等。

**与 JavaScript 的关系及示例:**

Turboshaft 是 V8 JavaScript 引擎中的一个编译器。该文件测试的指令选择器负责将 JavaScript 代码编译成机器码的过程中，将中间表示形式的操作转换为具体的 ARM64 指令。

例如，以下 JavaScript 代码中的加法操作：

```javascript
function add(a, b) {
  return a + b;
}
```

在 Turboshaft 编译器的处理过程中，`a + b` 这个操作可能会被表示为一个中间表示的加法节点。 指令选择器会根据操作数的类型 (例如，如果 `a` 和 `b` 都是 32 位整数)，将其转换为 ARM64 的 `ADD` 指令。

再例如，以下 JavaScript 代码中的位运算：

```javascript
function bitwiseAnd(x) {
  return x & 0xFF;
}
```

中间表示中，`x & 0xFF` 可能会被转换为一个按位与操作节点。 指令选择器可能会将其转换为 ARM64 的 `AND` 指令。

对于该文件中测试的位域提取，可以考虑以下 JavaScript 场景：

```javascript
function extractBits(value, start, length) {
  return (value >>> start) & ((1 << length) - 1);
}

console.log(extractBits(0xFF00FF00, 8, 8)); // 输出 0xFF
```

在这个例子中， `value >>> start` 对应逻辑右移，`& ((1 << length) - 1)` 对应按位与操作，用于提取特定长度的位。  该文件中的测试就验证了 Turboshaft 能否将这类模式识别出来，并生成高效的 `kArm64Ubfx` 指令。

总之，这个测试文件确保了 Turboshaft 编译器能够针对 ARM64 架构生成正确且优化的机器码，从而提升 JavaScript 代码在该架构上的执行效率。 由于这是第 4 部分，它延续了之前部分的测试，覆盖了更多更复杂的指令选择场景。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
htLogical) {
  // The available shift operand range is `0 <= imm < 64`, but we also test
  // that immediates outside this range are handled properly (modulo-64).
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int64_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int64_t, width, 1, 63) {
      uint64_t msk = (uint64_t{1} << width) - 1;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64BitwiseAnd(
          m.Word64ShiftRightLogical(m.Parameter(0), m.Int32Constant(shift)),
          m.Int64Constant(msk)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      int64_t actual_width = (lsb + width > 64) ? (64 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int64_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int64_t, width, 1, 63) {
      uint64_t msk = (uint64_t{1} << width) - 1;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64BitwiseAnd(
          m.Int64Constant(msk),
          m.Word64ShiftRightLogical(m.Parameter(0), m.Int32Constant(shift))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      int64_t actual_width = (lsb + width > 64) ? (64 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32MulHighWithParameters) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Int32MulOverflownBits(p0, p1);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArm64Smull, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArm64Asr, s[1]->arch_opcode());
  ASSERT_EQ(2U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(32, s.ToInt64(s[1]->InputAt(1)));
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[1]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Word32MulHighWithSar) {
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const n = m.Word32ShiftRightArithmetic(
        m.Int32MulOverflownBits(p0, p1), m.Int32Constant(shift));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Smull, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kArm64Asr, s[1]->arch_opcode());
    ASSERT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
    EXPECT_EQ((shift & 0x1F) + 32, s.ToInt64(s[1]->InputAt(1)));
    ASSERT_EQ(1U, s[1]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[1]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32MulHighWithAdd) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const a = m.Word32Add(m.Int32MulOverflownBits(p0, p1), p0);
  // Test only one shift constant here, as we're only interested in it being a
  // 32-bit operation; the shift amount is irrelevant.
  OpIndex const n = m.Word32ShiftRightArithmetic(a, m.Int32Constant(1));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(3U, s.size());
  EXPECT_EQ(kArm64Smull, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kArm64Add, s[1]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_ASR_I, s[1]->addressing_mode());
  ASSERT_EQ(3U, s[1]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[1]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(1)));
  EXPECT_EQ(32, s.ToInt64(s[1]->InputAt(2)));
  ASSERT_EQ(1U, s[1]->OutputCount());
  EXPECT_EQ(kArm64Asr32, s[2]->arch_opcode());
  ASSERT_EQ(2U, s[2]->InputCount());
  EXPECT_EQ(s.ToVreg(s[1]->Output()), s.ToVreg(s[2]->InputAt(0)));
  EXPECT_EQ(1, s.ToInt64(s[2]->InputAt(1)));
  ASSERT_EQ(1U, s[2]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[2]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Uint32MulHighWithShr) {
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex const n = m.Word32ShiftRightLogical(
        m.Uint32MulOverflownBits(p0, p1), m.Int32Constant(shift));
    m.Return(n);
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArm64Umull, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kArm64Lsr, s[1]->arch_opcode());
    ASSERT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->Output()), s.ToVreg(s[1]->InputAt(0)));
    EXPECT_EQ((shift & 0x1F) + 32, s.ToInt64(s[1]->InputAt(1)));
    ASSERT_EQ(1U, s[1]->OutputCount());
    EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[1]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32SarWithWord32Shl) {
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(p0, m.Int32Constant(shift)), m.Int32Constant(shift));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sbfx32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(p0, m.Int32Constant(shift + 32)),
        m.Int32Constant(shift + 64));
    m.Return(r);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sbfx32, s[0]->arch_opcode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word32ShiftRightLogicalWithWord32Shl) {
  TRACED_FORRANGE(int32_t, shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftRightLogical(
        m.Word32ShiftLeft(p0, m.Int32Constant(shift)), m.Int32Constant(shift));
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
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftRightLogical(
        m.Word32ShiftLeft(p0, m.Int32Constant(shift + 32)),
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

TEST_F(TurboshaftInstructionSelectorTest, Word32ShlWithWord32And) {
  TRACED_FORRANGE(int32_t, shift, 1, 30) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftLeft(
        m.Word32BitwiseAnd(p0, m.Int32Constant((1 << (31 - shift)) - 1)),
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
    OpIndex const p0 = m.Parameter(0);
    OpIndex const r = m.Word32ShiftLeft(
        m.Word32BitwiseAnd(p0, m.Int32Constant((1u << (31 - shift)) - 1)),
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

TEST_F(TurboshaftInstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Word32CountLeadingZeros(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Clz32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float32Abs) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Float32Abs(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float32Abs, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Abs) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Float64Abs(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Abs, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float32Abd) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const fsub = m.Float32Sub(p0, p1);
  OpIndex const fabs = m.Float32Abs(fsub);
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

TEST_F(TurboshaftInstructionSelectorTest, Float64Abd) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const fsub = m.Float64Sub(p0, p1);
  OpIndex const fabs = m.Float64Abs(fsub);
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

TEST_F(TurboshaftInstructionSelectorTest, Float64Max) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Float64Max(p0, p1);
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

TEST_F(TurboshaftInstructionSelectorTest, Float64Min) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n = m.Float64Min(p0, p1);
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

TEST_F(TurboshaftInstructionSelectorTest, Float32Neg) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Float32Negate(m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float32Neg, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float64Neg) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const n = m.Float64Negate(m.Parameter(0));
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Float64Neg, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(TurboshaftInstructionSelectorTest, Float32NegWithMul) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n1 = m.Float32Mul(p0, p1);
  OpIndex const n2 = m.Float32Negate(n1);
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

TEST_F(TurboshaftInstructionSelectorTest, Float64NegWithMul) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n1 = m.Float64Mul(p0, p1);
  OpIndex const n2 = m.Float64Negate(n1);
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

TEST_F(TurboshaftInstructionSelectorTest, Float32MulWithNeg) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float32(),
                  MachineType::Float32());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n1 = m.Float32Negate(p0);
  OpIndex const n2 = m.Float32Mul(n1, p1);
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

TEST_F(TurboshaftInstructionSelectorTest, Float64MulWithNeg) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
                  MachineType::Float64());
  OpIndex const p0 = m.Parameter(0);
  OpIndex const p1 = m.Parameter(1);
  OpIndex const n1 = m.Float64Negate(p0);
  OpIndex const n2 = m.Float64Mul(n1, p1);
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

TEST_F(TurboshaftInstructionSelectorTest, LoadAndShiftRight) {
  {
    int32_t immediates[] = {-256, -255, -3,   -2,   -1,    0,    1,
                            2,    3,    255,  256,  260,   4096, 4100,
                            8192, 8196, 3276, 3280, 16376, 16380};
    TRACED_FOREACH(int32_t, index, immediates) {
      StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer());
      OpIndex const load = m.Load(MachineType::Uint64(), m.Parameter(0),
                                  m.Int64Constant(index - 4));
      OpIndex const sar =
          m.Word64ShiftRightArithmetic(load, m.Int32Constant(32));
      // Make sure we don't fold the shift into the following add:
      m.Return(m.Word64Add(sar, m.Parameter(0)));
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

TEST_F(TurboshaftInstructionSelectorTest, CompareAgainstZero32) {
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    OpIndex const param = m.Parameter(0);
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Emit<Word32>(cmp.mi.op, param, m.Int32Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, CompareAgainstZero64) {
  TRACED_FOREACH(IntegerCmp, cmp, kBinop64CmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    OpIndex const param = m.Parameter(0);
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Emit<Word32>(cmp.mi.op, param, m.Int64Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, CompareFloat64HighLessThanZero64) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  OpIndex const param = m.Parameter(0);
  OpIndex const high = m.Float64ExtractHighWord32(param);
  Block *a = m.NewBlock(), *b = m.NewBlock();
  m.Branch(m.Int32LessThan(high, m.Int32Constant(0)), a, b);
  m.Bind(a);
  m.Return(m.Int32Constant(1));
  m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest,
       CompareFloat64HighGreaterThanOrEqualZero64) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  OpIndex const param = m.Parameter(0);
  OpIndex const high = m.Float64ExtractHighWord32(param);
  Block *a = m.NewBlock(), *b = m.NewBlock();
  m.Branch(m.Int32GreaterThanOrEqual(high, m.Int32Constant(0)), a, b);
  m.Bind(a);
  m.Return(m.Int32Constant(1));
  m.Bind(b);
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

TEST_F(TurboshaftInstructionSelectorTest, ExternalReferenceLoad1) {
  // Test offsets we can use kMode_Root for.
  const int64_t kOffsets[] = {0, 1, 4, INT32_MIN, INT32_MAX};
  TRACED_FOREACH(int64_t, offset, kOffsets) {
    StreamBuilder m(this, MachineType::Int64());
    ExternalReference reference =
        base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
    OpIndex const value =
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

TEST_F(TurboshaftInstructionSelectorTest, ExternalReferenceLoad2) {
  // Offset too large, we cannot use kMode_Root.
  StreamBuilder m(this, MachineType::Int64());
  int64_t offset = 0x100000000;
  ExternalReference reference =
      base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
  OpIndex const value =
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
void TestPokePair(TurboshaftInstructionSelectorTest::StreamBuilder* m,
                  Zone* zone, MachineSignature::Builder* builder,
                  base::Vector<const OpIndex> args, int expected_poke_pair,
                  int expected_poke) {
  auto call_descriptor = TurboshaftInstructionSelectorTest::StreamBuilder::
      MakeSimpleTSCallDescriptor(zone, builder->Get());

  OpIndex callee = m->Int64Constant(0);
  m->Call(callee, OpIndex::Invalid(), args, call_descriptor);
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

TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsInt32) {
  {
    MachineSignature::Builder builder(zone(), 0, 3);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());

    StreamBuilder m(this, MachineType::AnyTagged());
    OpIndex nodes[] = {
        m.Int32Constant(0),
        m.Int32Constant(0),
        m.Int32Constant(0),
    };

    const int expected_poke_pair = 1;
    // Note: The `+ 1` here comes from the padding Poke in
    // EmitPrepareArguments.
    const int expected_poke = 1 + 1;

    TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
                 expected_poke_pair, expected_poke);
  }

  {
    MachineSignature::Builder builder(zone(), 0, 4);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Int32());

    StreamBuilder m(this, MachineType::AnyTagged());
    OpIndex nodes[] = {
        m.Int32Constant(0),
        m.Int32Constant(0),
        m.Int32Constant(0),
        m.Int32Constant(0),
    };

    const int expected_poke_pair = 2;
    const int expected_poke = 0;

    TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
                 expected_poke_pair, expected_poke);
  }
}

TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsInt64) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());
  builder.AddParam(MachineType::Int64());

  StreamBuilder m(this, MachineType::AnyTagged());
  OpIndex nodes[] = {
      m.Int64Constant(0),
      m.Int64Constant(0),
      m.Int64Constant(0),
      m.Int64Constant(0),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
               expected_poke_pair, expected_poke);
}

TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsFloat32) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());
  builder.AddParam(MachineType::Float32());

  StreamBuilder m(this, MachineType::AnyTagged());
  OpIndex nodes[] = {
      m.Float32Constant(0.0f),
      m.Float32Constant(0.0f),
      m.Float32Constant(0.0f),
      m.Float32Constant(0.0f),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
               expected_poke_pair, expected_poke);
}

TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsFloat64) {
  MachineSignature::Builder builder(zone(), 0, 4);
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());
  builder.AddParam(MachineType::Float64());

  StreamBuilder m(this, MachineType::AnyTagged());
  OpIndex nodes[] = {
      m.Float64Constant(0.0f),
      m.Float64Constant(0.0f),
      m.Float64Constant(0.0f),
      m.Float64Constant(0.0f),
  };

  const int expected_poke_pair = 2;
  const int expected_poke = 0;

  TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
               expected_poke_pair, expected_poke);
}

TEST_F(TurboshaftInstructionSelectorTest,
       PokePairPrepareArgumentsIntFloatMixed) {
  {
    MachineSignature::Builder builder(zone(), 0, 4);
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Float32());
    builder.AddParam(MachineType::Int32());
    builder.AddParam(MachineType::Float32());

    StreamBuilder m(this, MachineType::AnyTagged());
    OpIndex nodes[] = {
        m.Int32Constant(0),
        m.Float32Constant(0.0f),
        m.Int32Constant(0),
        m.Float32Constant(0.0f),
    };

    const int expected_poke_pair = 0;
    const int expected_poke = 4;

    TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
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
    OpIndex nodes[] = {m.Float32Constant(0.0f), m.Int32Constant(0),
                       m.Int32Constant(0),      m.Float64Constant(0.0f),
                       m.Int64Constant(0),      m.Float64Constant(0.0f),
                       m.Float64Constant(0.0f)};

    const int expected_poke_pair = 2;

    // Note: The `+ 1` here comes from the padding Poke in
    // EmitPrepareArguments.
    const int expected_poke = 3 + 1;

    TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
                 expected_poke_pair, expected_poke);
  }
}

#if V8_ENABLE_WEBASSEMBLY
TEST_F(TurboshaftInstructionSelectorTest, PokePairPrepareArgumentsSimd128) {
  MachineSignature::Builder builder(zone(), 0, 2);
  builder.AddParam(MachineType::Simd128());
  builder.AddParam(MachineType::Simd128());

  StreamBuilder m(this, MachineType::AnyTagged());
  OpIndex nodes[] = {
      m.Simd128Splat(m.Int32Constant(0), Simd128SplatOp::Kind::kI32x4),
      m.Simd128Splat(m.Int32Constant(0), Simd128SplatOp::Kind::kI32x4)};

  const int expected_poke_pair = 0;
  const int expected_poke = 2;

  // Using kArm64PokePair is not currently supported for Simd128.
  TestPokePair(&m, zone(), &builder, base::VectorOf(nodes, arraysize(nodes)),
               expected_poke_pair, expected_poke);
}

struct SIMDConstZeroCmTest {
  const bool is_zero;
  const uint8_t lane_size;
  TSBinop cm_operator;
  const ArchOpcode expected_op_left;
  const ArchOpcode expected_op_right;
  const size_t size;
};

static const SIMDConstZeroCmTest SIMDConstZeroCmTests[] = {
    {true, 8, TSBinop::kI8x16Eq, kArm64IEq, kArm64IEq, 1},
    {true, 8, TSBinop::kI8x16Ne, kArm64INe, kArm64INe, 1},
    {true, 8, TSBinop::kI8x16GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 8, TSBinop::kI8x16GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 8, TSBinop::kI8x16Eq, kArm64IEq, kArm64IEq, 2},
    {false, 8, TSBinop::kI8x16Ne, kArm64INe, kArm64INe, 2},
    {false, 8, TSBinop::kI8x16GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 8, TSBinop::kI8x16GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 16, TSBinop::kI16x8Eq, kArm64IEq, kArm64IEq, 1},
    {true, 16, TSBinop::kI16x8Ne, kArm64INe, kArm64INe, 1},
    {true, 16, TSBinop::kI16x8GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 16, TSBinop::kI16x8GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 16, TSBinop::kI16x8Eq, kArm64IEq, kArm64IEq, 2},
    {false, 16, TSBinop::kI16x8Ne, kArm64INe, kArm64INe, 2},
    {false, 16, TSBinop::kI16x8GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 16, TSBinop::kI16x8GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 32, TSBinop::kI32x4Eq, kArm64IEq, kArm64IEq, 1},
    {true, 32, TSBinop::kI32x4Ne, kArm64INe, kArm64INe, 1},
    {true, 32, TSBinop::kI32x4GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 32, TSBinop::kI32x4GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 32, TSBinop::kI32x4Eq, kArm64IEq, kArm64IEq, 2},
    {false, 32, TSBinop::kI32x4Ne, kArm64INe, kArm64INe, 2},
    {false, 32, TSBinop::kI32x4GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 32, TSBinop::kI32x4GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 64, TSBinop::kI64x2Eq, kArm64IEq, kArm64IEq, 1},
    {true, 64, TSBinop::kI64x2Ne, kArm64INe, kArm64INe, 1},
    {true, 64, TSBinop::kI64x2GeS, kArm64ILeS, kArm64IGeS, 1},
    {true, 64, TSBinop::kI64x2GtS, kArm64ILtS, kArm64IGtS, 1},
    {false, 64, TSBinop::kI64x2Eq, kArm64IEq, kArm64IEq, 2},
    {false, 64, TSBinop::kI64x2Ne, kArm64INe, kArm64INe, 2},
    {false, 64, TSBinop::kI64x2GeS, kArm64IGeS, kArm64IGeS, 2},
    {false, 64, TSBinop::kI64x2GtS, kArm64IGtS, kArm64IGtS, 2},
    {true, 64, TSBinop::kF64x2Eq, kArm64FEq, kArm64FEq, 1},
    {true, 64, TSBinop::kF64x2Ne, kArm64FNe, kArm64FNe, 1},
    {true, 64, TSBinop::kF64x2Lt, kArm64FGt, kArm64FLt, 1},
    {true, 64, TSBinop::kF64x2Le, kArm64FGe, kArm64FLe, 1},
    {false, 64, TSBinop::kF64x2Eq, kArm64FEq, kArm64FEq, 2},
    {false, 64, TSBinop::kF64x2Ne, kArm64FNe, kArm64FNe, 2},
    {false, 64, TSBinop::kF64x2Lt, kArm64FLt, kArm64FLt, 2},
    {false, 64, TSBinop::kF64x2Le, kArm64FLe, kArm64FLe, 2},
    {true, 32, TSBinop::kF32x4Eq, kArm64FEq, kArm64FEq, 1},
    {true, 32, TSBinop::kF32x4Ne, kArm64FNe, kArm64FNe, 1},
    {true, 32, TSBinop::kF32x4Lt, kArm64FGt, kArm64FLt, 1},
    {true, 32, TSBinop::kF32x4Le, kArm64FGe, kArm64FLe, 1},
    {false, 32, TSBinop::kF32x4Eq, kArm64FEq, kArm64FEq, 2},
    {false, 32, TSBinop::kF32x4Ne, kArm64FNe, kArm64FNe, 2},
    {false, 32, TSBinop::kF32x4Lt, kArm64FLt, kArm64FLt, 2},
    {false, 32, TSBinop::kF32x4Le, kArm64FLe, kArm64FLe, 2},
};

using TurboshaftInstructionSelectorSIMDConstZeroCmTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDConstZeroCmTest>;

TEST_P(TurboshaftInstructionSelectorSIMDConstZeroCmTest, ConstZero) {
  const SIMDConstZeroCmTest param = GetParam();
  uint8_t data[16] = {};
  if (!param.is_zero) data[0] = 0xff;
  // Const node on the left
  {
    StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
    OpIndex cnst = m.Simd128Constant(data);
    OpIndex fcm = m.Emit(param.cm_operator, cnst, m.Parameter(0));
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
    OpIndex cnst = m.Simd128Constant(data);
    OpIndex fcm = m.Emit(param.cm_operator, m.Parameter(0), cnst);
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDConstZeroCmTest,
                         ::testing::ValuesIn(SIMDConstZeroCmTests));

struct SIMDConstAndTest {
  const uint8_t data[16];
  TSBinop simd_op;
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
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     16,
     8,
     0x01,
     1},
    {{0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF,
      0xFE, 0xFF, 0xFE, 0xFF},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     16,
     0,
     0x01,
     1},

    {{0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE,
      0xFF, 0xFF, 0xFF, 0xFE},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     32,
     24,
     0x01,
     1},
    {{0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF,
      0xFF, 0xFF, 0xFE, 0xFF},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     32,
     16,
     0x01,
     1},
    {{0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
      0xFF, 0xFE, 0xFF, 0xFF},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     32,
     8,
     0x01,
     1},
    {{0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
      0xFE, 0xFF, 0xFF, 0xFF},
     TSBinop::kS128And,
     kArm64S128AndNot,
     true,
     32,
     0,
     0x01,
     1},

    {{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
      0xEE, 0xEE, 0xEE, 0xEE},
     TSBinop::kS128And,
     kArm64S128And,
     true,
     0,
     0,
     0x00,
     2},

    {{0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x01, 0x00, 0x01},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     16,
     8,
     0x01,
     1},
    {{0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x01, 0x00},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     16,
     0,
     0x01,
     1},

    {{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     32,
     24,
     0x01,
     1},
    {{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x01, 0x00},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     32,
     16,
     0x01,
     1},
    {{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x00},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     32,
     8,
     0x01,
     1},
    {{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     32,
     0,
     0x01,
     1},

    {{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
      0xEE, 0xEE, 0xEE, 0xEE},
     TSBinop::kS128AndNot,
     kArm64S128AndNot,
     false,
     0,
     0,
     0x00,
     2},
};

using TurboshaftInstructionSelectorSIMDConstAndTest =
    TurboshaftInstructionSelectorTestWithParam<SIMDConstAndTest>;

TEST_P(TurboshaftInstructionSelectorSIMDConstAndTest, ConstAnd) {
  const SIMDConstAndTest param = GetParam();
  // Const node on the left
  {
    StreamBuilder m(this, MachineType::Simd128(), MachineType::Simd128());
    OpIndex cnst = m.Simd128Constant(param.data);
    OpIndex op = m.Emit(param.simd_op, cnst, m.Parameter(0));
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
    OpIndex cnst = m.Simd128Constant(param.data);
    OpIndex op = m.Emit(param.simd_op, m.Parameter(0), cnst);
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorSIMDConstAndTest,
                         ::testing::ValuesIn(SIMDConstAndTests));
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace v8::internal::compiler::turboshaft

"""


```