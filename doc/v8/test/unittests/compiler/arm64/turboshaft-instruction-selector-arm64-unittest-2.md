Response: The user wants me to summarize the functionality of the provided C++ code snippet. This is the third part of a four-part file. The file seems to be a unit test for the Turboshaft instruction selector on the ARM64 architecture within the V8 JavaScript engine.

I need to identify the main purpose of the tests in this section and whether they relate to specific JavaScript features.

Based on the code, this section focuses on testing the instruction selection for:
- Converting 32-bit integers to 64-bit integers (`ChangeInt32ToInt64`).
- Memory access instructions (loads and stores) with various addressing modes (register-register, register-immediate, register-shifted register).
- Integer comparison instructions (`Word32Equal`, `Word64Equal`, `Int32LessThan`, etc.) with different operand types (registers, immediates, shifted registers, extended registers).
- Optimization of flag-setting instructions (like `Add` and `And`) when followed by a comparison with zero.
- Miscellaneous logical operations and bitfield manipulation instructions.
这个C++源代码文件是V8 JavaScript引擎中Turboshaft编译器的ARM64架构指令选择器的单元测试的第三部分。

该部分主要测试了以下功能：

1. **类型转换指令的选择：**
   - 测试了将32位整数转换为64位整数(`ChangeInt32ToInt64`)的不同场景，特别是与加载指令结合使用时，是否正确选择了相应的带符号扩展或零扩展的加载指令（如 `Ldrsb`, `Ldrb`, `Ldrh`, `Ldrsh`, `Ldrsw`）。
   - 测试了 `ChangeInt32ToInt64` 与算术右移指令 (`Word64Sar`) 结合使用时的指令选择，并验证了针对特定立即数范围的优化。

2. **内存访问指令的选择：**
   - 针对不同数据类型（`Int8`, `Uint8`, `Int16`, `Uint16`, `Int32`, `Uint32`, `Int64`, `Uint64`, `Float32`, `Float64`）的加载(`Load`)和存储(`Store`)指令，测试了以下情况：
     - 使用寄存器作为索引地址。
     - 使用立即数作为偏移量。
     - 使用左移后的寄存器作为偏移量，并验证了当偏移量与数据类型大小的对数一致时，是否选择了带有移位寻址模式的指令。
   - 测试了带有写屏障的存储指令 (`Store` with write barriers)。

3. **比较指令的选择：**
   - 测试了各种整数比较指令 (`Word32Equal`, `Word64Equal`) 与不同类型操作数（寄存器，立即数）的组合，验证是否生成了正确的比较指令 (`Cmp`, `Tst`)。
   - 测试了比较指令与移位操作、位掩码操作结合时的指令选择，例如：
     - 与移位指令 (`Word32ShiftLeft`, `Word32ShiftRightArithmetic`) 结合，验证是否使用了带有移位操作数的比较指令。
     - 与零进行比较，验证是否使用了 `Tst` 指令。
     - 与按位与操作 (`Word32BitwiseAnd`) 结合，模拟了按位提取并比较的场景。
   - 测试了比较指令的优化，例如 `Word32Equal` 结果与零比较时，会反转比较条件。
   - 测试了比较指令与带符号扩展的操作数结合时的指令选择。

4. **标志位设置指令的优化：**
   - 测试了当算术或逻辑运算指令（如 `Word32Add`, `Word32BitwiseAnd`）的结果仅被后续的与零比较指令使用时，是否会将这两个操作合并为一个不产生结果但设置标志位的指令（如 `Cmn`, `Tst`）。
   - 验证了这种优化只发生在同一基本块内，且没有其他使用者的情况下。

5. **其他逻辑指令的优化：**
   - 测试了当按位与 (`Word32BitwiseAnd`, `Word64BitwiseAnd`)、按位或 (`Word32BitwiseOr`, `Word64BitwiseOr`)、按位异或 (`Word32BitwiseXor`, `Word64BitwiseXor`) 指令的右操作数是按位非的结果时，是否选择了具有“非”操作的指令（如 `Bic`, `Orn`, `Eon`）。
   - 测试了按位非指令 (`Word32BitwiseNot`, `Word64BitwiseNot`) 的指令选择。
   - 测试了按位异或指令与 `-1` 常量结合时的优化，会被转换为按位非指令。

6. **位域提取指令的优化：**
   - 测试了逻辑右移 (`Word32ShiftRightLogical`, `Word64ShiftRightLogical`) 与按位与 (`Word32BitwiseAnd`, `Word64BitwiseAnd`) 操作结合，且按位与使用特定掩码时，是否会生成位域提取指令 (`Ubfx`)。

**与 JavaScript 的关系：**

这些测试直接关系到 V8 JavaScript 引擎在 ARM64 架构上的性能。JavaScript 引擎需要将 JavaScript 代码转换为机器码执行，而指令选择器是这个过程中的关键组件。正确的指令选择能够利用目标架构的特性，生成更高效的机器码。

例如，以下 JavaScript 代码中的整数运算和比较操作，就可能涉及到这里测试的指令选择逻辑：

```javascript
function test(a, b) {
  let x = a + b; // 可能涉及 Word32Add 或 Word64Add 指令的选择
  if (x > 0) { // 可能涉及 Int32GreaterThan 或 Int64GreaterThan 指令的选择
    return x & 0xFF; // 可能涉及 Word32BitwiseAnd 指令的选择
  } else {
    return ~x; // 可能涉及 Word32BitwiseNot 或 Word64BitwiseNot 指令的选择
  }
}

function loadAndConvert(buffer, offset) {
  const value = buffer.getInt8(offset); // 需要加载 8 位有符号整数
  return value; // 在后续使用中可能需要转换为更大的整数类型，涉及 ChangeInt32ToInt64 类似的转换
}

function compare(a, b) {
  return a === b; // 可能涉及 Word32Equal 或 Word64Equal 指令的选择
}
```

再例如，访问数组元素时会涉及到内存加载和存储操作：

```javascript
function accessArray(arr, index) {
  return arr[index]; //  可能涉及 Load 指令的选择，索引可能需要进行移位计算
}

function setArray(arr, index, value) {
  arr[index] = value; // 可能涉及 Store 指令的选择
}
```

这些测试确保了当 Turboshaft 编译器遇到这些 JavaScript 结构时，能够正确地选择最高效的 ARM64 指令，从而提升 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
;
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int8) -> Ldrsb
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrsb, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint16) -> Ldrh
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrh, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int16) -> Ldrsh
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrsh, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint32) -> Ldrsw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrsw, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int32) -> Ldrsw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Pointer());
    m.Return(m.ChangeInt32ToInt64(
        m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Ldrsw, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, ChangeInt32ToInt64WithWord32Sar) {
  // Test the mod 32 behaviour of Word32ShiftRightArithmetic by iterating up
  // to 33.
  TRACED_FORRANGE(int32_t, imm, 0, 33) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    m.Return(m.ChangeInt32ToInt64(
        m.Word32ShiftRightArithmetic(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sbfx, s[0]->arch_opcode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(imm & 0x1f, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(32 - (imm & 0x1f), s.ToInt32(s[0]->InputAt(2)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64SarWithChangeInt32ToInt64) {
  TRACED_FORRANGE(int32_t, imm, -31, 63) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    m.Return(m.Word64ShiftRightArithmetic(m.ChangeInt32ToInt64(m.Parameter(0)),
                                          m.Int32Constant(imm)));
    Stream s = m.Build();
    // Optimization should only be applied when 0 <= imm < 32
    if (0 <= imm && imm < 32) {
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Sbfx, s[0]->arch_opcode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(32 - imm, s.ToInt64(s[0]->InputAt(2)));
    } else {
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kArm64Sxtw, s[0]->arch_opcode());
      EXPECT_EQ(1U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(kArm64Asr, s[1]->arch_opcode());
      EXPECT_EQ(2U, s[1]->InputCount());
      EXPECT_EQ(1U, s[1]->OutputCount());
      EXPECT_EQ(imm, s.ToInt64(s[1]->InputAt(1)));
    }
  }
}

// -----------------------------------------------------------------------------
// Memory access instructions.

namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode ldr_opcode;
  ArchOpcode str_opcode;
  const int32_t immediates[20];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccess& memacc) {
  return os << memacc.type;
}

}  // namespace

static const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(),
     kArm64LdrsbW,
     kArm64Strb,
     {-256, -255, -3,  -2,   -1,   0,    1,    2,    3,    255,
      256,  257,  258, 1000, 1001, 2121, 2442, 4093, 4094, 4095}},
    {MachineType::Uint8(),
     kArm64Ldrb,
     kArm64Strb,
     {-256, -255, -3,  -2,   -1,   0,    1,    2,    3,    255,
      256,  257,  258, 1000, 1001, 2121, 2442, 4093, 4094, 4095}},
    {MachineType::Int16(),
     kArm64LdrshW,
     kArm64Strh,
     {-256, -255, -3,  -2,   -1,   0,    1,    2,    3,    255,
      256,  258,  260, 4096, 4098, 4100, 4242, 6786, 8188, 8190}},
    {MachineType::Uint16(),
     kArm64Ldrh,
     kArm64Strh,
     {-256, -255, -3,  -2,   -1,   0,    1,    2,    3,    255,
      256,  258,  260, 4096, 4098, 4100, 4242, 6786, 8188, 8190}},
    {MachineType::Int32(),
     kArm64LdrW,
     kArm64StrW,
     {-256, -255, -3,   -2,   -1,   0,    1,    2,    3,     255,
      256,  260,  4096, 4100, 8192, 8196, 3276, 3280, 16376, 16380}},
    {MachineType::Uint32(),
     kArm64LdrW,
     kArm64StrW,
     {-256, -255, -3,   -2,   -1,   0,    1,    2,    3,     255,
      256,  260,  4096, 4100, 8192, 8196, 3276, 3280, 16376, 16380}},
    {MachineType::Int64(),
     kArm64Ldr,
     kArm64Str,
     {-256, -255, -3,   -2,   -1,   0,    1,     2,     3,     255,
      256,  264,  4096, 4104, 8192, 8200, 16384, 16392, 32752, 32760}},
    {MachineType::Uint64(),
     kArm64Ldr,
     kArm64Str,
     {-256, -255, -3,   -2,   -1,   0,    1,     2,     3,     255,
      256,  264,  4096, 4104, 8192, 8200, 16384, 16392, 32752, 32760}},
    {MachineType::Float32(),
     kArm64LdrS,
     kArm64StrS,
     {-256, -255, -3,   -2,   -1,   0,    1,    2,    3,     255,
      256,  260,  4096, 4100, 8192, 8196, 3276, 3280, 16376, 16380}},
    {MachineType::Float64(),
     kArm64LdrD,
     kArm64StrD,
     {-256, -255, -3,   -2,   -1,   0,    1,     2,     3,     255,
      256,  264,  4096, 4104, 8192, 8200, 16384, 16392, 32752, 32760}}};

using TurboshaftInstructionSelectorMemoryAccessTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int64());
  m.Return(m.Load(memacc.type, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, LoadWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int64Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                  MachineType::Int64(), memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Parameter(1),
          m.Parameter(2), kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
  EXPECT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(0U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, StoreWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int64Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, StoreZero) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    MachineRepresentation rep = memacc.type.representation();
    OpIndex zero;
    switch (rep) {
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord32:
        zero = m.Word32Constant(0);
        break;
      case MachineRepresentation::kWord64:
        zero = m.Int64Constant(0);
        break;
      case MachineRepresentation::kFloat32:
        zero = m.Float32Constant(0);
        break;
      case MachineRepresentation::kFloat64:
        zero = m.Float64Constant(0);
        break;
      default:
        UNREACHABLE();
    }
    m.Store(rep, m.Parameter(0), m.Int64Constant(index), zero, kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(0)->kind());
    switch (rep) {
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord32:
      case MachineRepresentation::kWord64:
        EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(0)));
        break;
      case MachineRepresentation::kFloat32:
        EXPECT_EQ(0, s.ToFloat32(s[0]->InputAt(0)));
        break;
      case MachineRepresentation::kFloat64:
        EXPECT_EQ(0, s.ToFloat64(s[0]->InputAt(0)));
        break;
      default:
        UNREACHABLE();
    }
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, LoadWithShiftedIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FORRANGE(int, immediate_shift, 0, 4) {
    // 32 bit shift
    {
      StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                      MachineType::Int32());
      OpIndex const index =
          m.Word32ShiftLeft(m.Parameter(1), m.Int32Constant(immediate_shift));
      m.Return(
          m.Load(memacc.type, m.Parameter(0), m.ChangeUint32ToUint64(index)));
      Stream s = m.Build();
      if (immediate_shift == ElementSizeLog2Of(memacc.type.representation())) {
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
        EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
        EXPECT_EQ(3U, s[0]->InputCount());
        EXPECT_EQ(1U, s[0]->OutputCount());
      } else {
        // Make sure we haven't merged the shift into the load instruction.
        ASSERT_NE(1U, s.size());
        EXPECT_NE(memacc.ldr_opcode, s[0]->arch_opcode());
        EXPECT_NE(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
      }
    }
    // 64 bit shift
    {
      StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                      MachineType::Int64());
      OpIndex const index =
          m.Word64ShiftLeft(m.Parameter(1), m.Int32Constant(immediate_shift));
      m.Return(m.Load(memacc.type, m.Parameter(0), index));
      Stream s = m.Build();
      if (immediate_shift == ElementSizeLog2Of(memacc.type.representation())) {
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
        EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
        EXPECT_EQ(3U, s[0]->InputCount());
        EXPECT_EQ(1U, s[0]->OutputCount());
      } else {
        // Make sure we haven't merged the shift into the load instruction.
        ASSERT_NE(1U, s.size());
        EXPECT_NE(memacc.ldr_opcode, s[0]->arch_opcode());
        EXPECT_NE(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
      }
    }
  }
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, StoreWithShiftedIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FORRANGE(int, immediate_shift, 0, 4) {
    // 32 bit shift
    {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                      MachineType::Int32(), memacc.type);
      OpIndex const index =
          m.Word32ShiftLeft(m.Parameter(1), m.Int32Constant(immediate_shift));
      m.Store(memacc.type.representation(), m.Parameter(0),
              m.ChangeUint32ToUint64(index), m.Parameter(2), kNoWriteBarrier);
      m.Return(m.Int32Constant(0));
      Stream s = m.Build();
      if (immediate_shift == ElementSizeLog2Of(memacc.type.representation())) {
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
        EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
        EXPECT_EQ(4U, s[0]->InputCount());
        EXPECT_EQ(0U, s[0]->OutputCount());
      } else {
        // Make sure we haven't merged the shift into the store instruction.
        ASSERT_NE(1U, s.size());
        EXPECT_NE(memacc.str_opcode, s[0]->arch_opcode());
        EXPECT_NE(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
      }
    }
    // 64 bit shift
    {
      StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                      MachineType::Int64(), memacc.type);
      OpIndex const index =
          m.Word64ShiftLeft(m.Parameter(1), m.Int32Constant(immediate_shift));
      m.Store(memacc.type.representation(), m.Parameter(0), index,
              m.Parameter(2), kNoWriteBarrier);
      m.Return(m.Int64Constant(0));
      Stream s = m.Build();
      if (immediate_shift == ElementSizeLog2Of(memacc.type.representation())) {
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
        EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
        EXPECT_EQ(4U, s[0]->InputCount());
        EXPECT_EQ(0U, s[0]->OutputCount());
      } else {
        // Make sure we haven't merged the shift into the store instruction.
        ASSERT_NE(1U, s.size());
        EXPECT_NE(memacc.str_opcode, s[0]->arch_opcode());
        EXPECT_NE(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
      }
    }
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// This list doesn't contain kIndirectPointerWriteBarrier because only indirect
// pointer fields can be stored to with that barrier kind.
static const WriteBarrierKind kWriteBarrierKinds[] = {
    kMapWriteBarrier, kPointerWriteBarrier, kEphemeronKeyWriteBarrier,
    kFullWriteBarrier};

const int32_t kStoreWithBarrierImmediates[] = {
    -256, -255, -3,   -2,   -1,   0,    1,     2,     3,     255,
    256,  264,  4096, 4104, 8192, 8200, 16384, 16392, 32752, 32760};

using TurboshaftInstructionSelectorStoreWithBarrierTest =
    TurboshaftInstructionSelectorTestWithParam<WriteBarrierKind>;

TEST_P(TurboshaftInstructionSelectorStoreWithBarrierTest,
       StoreWithWriteBarrierParameters) {
  const WriteBarrierKind barrier_kind = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                  MachineType::Int64(), MachineType::AnyTagged());
  m.Store(MachineRepresentation::kTagged, m.Parameter(0), m.Parameter(1),
          m.Parameter(2), barrier_kind);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build(kAllExceptNopInstructions);
  // We have two instructions that are not nops: Store and Return.
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(kArchStoreWithWriteBarrier, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
  EXPECT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(0U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorStoreWithBarrierTest,
       StoreWithWriteBarrierImmediate) {
  const WriteBarrierKind barrier_kind = GetParam();
  TRACED_FOREACH(int32_t, index, kStoreWithBarrierImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::AnyTagged());
    m.Store(MachineRepresentation::kTagged, m.Parameter(0),
            m.Int64Constant(index), m.Parameter(1), barrier_kind);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build(kAllExceptNopInstructions);
    // We have two instructions that are not nops: Store and Return.
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kArchStoreWithWriteBarrier, s[0]->arch_opcode());
    // With compressed pointers, a store with barrier is a 32-bit str which has
    // a smaller immediate range.
    if (COMPRESS_POINTERS_BOOL && (index > 16380)) {
      EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
    } else {
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    }
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorStoreWithBarrierTest,
                         ::testing::ValuesIn(kWriteBarrierKinds));

// -----------------------------------------------------------------------------
// Comparison instructions.

static const MachInst2 kComparisonInstructions[] = {
    {TSBinop::kWord32Equal, "Word32Equal", kArm64Cmp32, MachineType::Int32()},
    {TSBinop::kWord64Equal, "Word64Equal", kArm64Cmp, MachineType::Int64()},
};

using TurboshaftInstructionSelectorComparisonTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorComparisonTest, WithParameters) {
  const MachInst2 cmp = GetParam();
  const MachineType type = cmp.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(cmp.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(cmp.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kEqual, s[0]->flags_condition());
}

TEST_P(TurboshaftInstructionSelectorComparisonTest, WithImmediate) {
  const MachInst2 cmp = GetParam();
  const MachineType type = cmp.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    // Compare with 0 are turned into tst instruction.
    if (imm == 0) continue;
    StreamBuilder m(this, type, type);
    m.Return(m.Emit(cmp.op, m.Parameter(0), BuildConstant(&m, type, imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(cmp.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    // Compare with 0 are turned into tst instruction.
    if (imm == 0) continue;
    StreamBuilder m(this, type, type);
    m.Return(m.Emit(cmp.op, BuildConstant(&m, type, imm), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(cmp.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorComparisonTest,
                         ::testing::ValuesIn(kComparisonInstructions));

TEST_F(TurboshaftInstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Equal(m.Parameter(0), m.Int64Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Equal(m.Int64Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(s[0]->InputAt(0)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32EqualWithWord32Shift) {
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    // Skip non 32-bit shifts or ror operations.
    if (shift.mi.machine_type != MachineType::Int32() ||
        shift.mi.arch_opcode == kArm64Ror32) {
      continue;
    }

    TRACED_FORRANGE(int32_t, imm, -32, 63) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      OpIndex const p0 = m.Parameter(0);
      OpIndex const p1 = m.Parameter(1);
      OpIndex r = m.Emit(shift.mi.op, p1, m.Int32Constant(imm));
      m.Return(m.Word32Equal(p0, r));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
      EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
      EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt32(s[0]->InputAt(2)));
      ASSERT_EQ(1U, s[0]->OutputCount());
    }
    TRACED_FORRANGE(int32_t, imm, -32, 63) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      OpIndex const p0 = m.Parameter(0);
      OpIndex const p1 = m.Parameter(1);
      OpIndex r = m.Emit(shift.mi.op, p1, m.Int32Constant(imm));
      m.Return(m.Word32Equal(r, p0));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
      EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
      EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt32(s[0]->InputAt(2)));
      ASSERT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32EqualWithUnsignedExtendByte) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Word32BitwiseAnd(p1, m.Int32Constant(0xFF));
    m.Return(m.Word32Equal(p0, r));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Word32BitwiseAnd(p1, m.Int32Constant(0xFF));
    m.Return(m.Word32Equal(r, p0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word32EqualWithUnsignedExtendHalfword) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Word32BitwiseAnd(p1, m.Int32Constant(0xFFFF));
    m.Return(m.Word32Equal(p0, r));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Word32BitwiseAnd(p1, m.Int32Constant(0xFFFF));
    m.Return(m.Word32Equal(r, p0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32EqualWithSignedExtendByte) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(p1, m.Int32Constant(24)), m.Int32Constant(24));
    m.Return(m.Word32Equal(p0, r));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(p1, m.Int32Constant(24)), m.Int32Constant(24));
    m.Return(m.Word32Equal(r, p0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32EqualWithSignedExtendHalfword) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(p1, m.Int32Constant(16)), m.Int32Constant(16));
    m.Return(m.Word32Equal(p0, r));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    OpIndex r = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(p1, m.Int32Constant(16)), m.Int32Constant(16));
    m.Return(m.Word32Equal(r, p0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32EqualZeroWithWord32Equal) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Word32Equal(p0, p1), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex const p0 = m.Parameter(0);
    OpIndex const p1 = m.Parameter(1);
    m.Return(m.Word32Equal(m.Int32Constant(0), m.Word32Equal(p0, p1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

namespace {

struct IntegerCmp {
  MachInst2 mi;
  FlagsCondition cond;
  FlagsCondition commuted_cond;
};

std::ostream& operator<<(std::ostream& os, const IntegerCmp& cmp) {
  return os << cmp.mi;
}

// ARM64 32-bit integer comparison instructions.
const IntegerCmp kIntegerCmpInstructions[] = {
    {{TSBinop::kWord32Equal, "Word32Equal", kArm64Cmp32, MachineType::Int32()},
     kEqual,
     kEqual},
    {{TSBinop::kInt32LessThan, "Int32LessThan", kArm64Cmp32,
      MachineType::Int32()},
     kSignedLessThan,
     kSignedGreaterThan},
    {{TSBinop::kInt32LessThanOrEqual, "Int32LessThanOrEqual", kArm64Cmp32,
      MachineType::Int32()},
     kSignedLessThanOrEqual,
     kSignedGreaterThanOrEqual},
    {{TSBinop::kUint32LessThan, "Uint32LessThan", kArm64Cmp32,
      MachineType::Uint32()},
     kUnsignedLessThan,
     kUnsignedGreaterThan},
    {{TSBinop::kUint32LessThanOrEqual, "Uint32LessThanOrEqual", kArm64Cmp32,
      MachineType::Uint32()},
     kUnsignedLessThanOrEqual,
     kUnsignedGreaterThanOrEqual}};

const IntegerCmp kIntegerCmpEqualityInstructions[] = {
    {{TSBinop::kWord32Equal, "Word32Equal", kArm64Cmp32, MachineType::Int32()},
     kEqual,
     kEqual},
    {{TSBinop::kWord32NotEqual, "Word32NotEqual", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual}};
}  // namespace

TEST_F(TurboshaftInstructionSelectorTest, Word32CompareNegateWithWord32Shift) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpEqualityInstructions) {
    TRACED_FOREACH(Shift, shift, kShiftInstructions) {
      // Test 32-bit operations. Ignore ROR shifts, as compare-negate does not
      // support them.
      if (shift.mi.machine_type != MachineType::Int32() ||
          shift.mi.arch_opcode == kArm64Ror32) {
        continue;
      }

      TRACED_FORRANGE(int32_t, imm, -32, 63) {
        StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                        MachineType::Int32());
        OpIndex const p0 = m.Parameter(0);
        OpIndex const p1 = m.Parameter(1);
        OpIndex r = m.Emit(shift.mi.op, p1, m.Int32Constant(imm));
        m.Return(m.Emit(cmp.mi.op, p0, m.Word32Sub(m.Int32Constant(0), r)));
        Stream s = m.Build();
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
        EXPECT_EQ(3U, s[0]->InputCount());
        EXPECT_EQ(shift.mode, s[0]->addressing_mode());
        EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt32(s[0]->InputAt(2)));
        EXPECT_EQ(1U, s[0]->OutputCount());
        EXPECT_EQ(kFlags_set, s[0]->flags_mode());
        EXPECT_EQ(cmp.cond, s[0]->flags_condition());
      }
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CmpWithImmediateOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpInstructions) {
    TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
      // kEqual and kNotEqual trigger the cbz/cbnz optimization, which
      // is tested elsewhere.
      if (cmp.cond == kEqual || cmp.cond == kNotEqual) continue;
      // For signed less than or equal to zero, we generate TBNZ.
      if (cmp.cond == kSignedLessThanOrEqual && imm == 0) continue;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      OpIndex const p0 = m.Parameter(0);
      m.Return(m.Emit(cmp.mi.op, m.Int32Constant(imm), p0));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
      ASSERT_LE(2U, s[0]->InputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(cmp.commuted_cond, s[0]->flags_condition());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CmnWithImmediateOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpEqualityInstructions) {
    TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
      // kEqual and kNotEqual trigger the cbz/cbnz optimization, which
      // is tested elsewhere.
      if (cmp.cond == kEqual || cmp.cond == kNotEqual) continue;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      OpIndex sub = m.Word32Sub(m.Int32Constant(0), m.Parameter(0));
      m.Return(m.Emit(cmp.mi.op, m.Int32Constant(imm), sub));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
      ASSERT_LE(2U, s[0]->InputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(cmp.cond, s[0]->flags_condition());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CmpSignedExtendByteOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex extend = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(24)),
        m.Int32Constant(24));
    m.Return(m.Emit(cmp.mi.op, extend, m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.commuted_cond, s[0]->flags_condition());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CmnSignedExtendByteOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpEqualityInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex sub = m.Word32Sub(m.Int32Constant(0), m.Parameter(0));
    OpIndex extend = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(24)),
        m.Int32Constant(24));
    m.Return(m.Emit(cmp.mi.op, extend, sub));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CmpShiftByImmediateOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpInstructions) {
    TRACED_FOREACH(Shift, shift, kShiftInstructions) {
      // Only test relevant shifted operands.
      if (shift.mi.machine_type != MachineType::Int32()) continue;

      // The available shift operand range is `0 <= imm < 32`, but we also test
      // that immediates outside this range are handled properly (modulo-32).
      TRACED_FORRANGE(int, imm, -32, 63) {
        StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                        MachineType::Int32());
        m.Return(
            m.Emit(cmp.mi.op,
                   m.Emit(shift.mi.op, m.Parameter(1), m.Int32Constant(imm)),
                   m.Parameter(0)));
        Stream s = m.Build();
        // Cmp does not support ROR shifts.
        if (shift.mi.arch_opcode == kArm64Ror32) {
          ASSERT_EQ(2U, s.size());
          continue;
        }
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
        EXPECT_EQ(shift.mode, s[0]->addressing_mode());
        EXPECT_EQ(3U, s[0]->InputCount());
        EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
        EXPECT_EQ(1U, s[0]->OutputCount());
        EXPECT_EQ(kFlags_set, s[0]->flags_mode());
        EXPECT_EQ(cmp.commuted_cond, s[0]->flags_condition());
      }
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CmnShiftByImmediateOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpEqualityInstructions) {
    TRACED_FOREACH(Shift, shift, kShiftInstructions) {
      // Only test relevant shifted operands.
      if (shift.mi.machine_type != MachineType::Int32()) continue;

      // The available shift operand range is `0 <= imm < 32`, but we also test
      // that immediates outside this range are handled properly (modulo-32).
      TRACED_FORRANGE(int, imm, -32, 63) {
        StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                        MachineType::Int32());
        OpIndex sub = m.Word32Sub(m.Int32Constant(0), m.Parameter(0));
        m.Return(m.Emit(
            cmp.mi.op,
            m.Emit(shift.mi.op, m.Parameter(1), m.Int32Constant(imm)), sub));
        Stream s = m.Build();
        // Cmn does not support ROR shifts.
        if (shift.mi.arch_opcode == kArm64Ror32) {
          ASSERT_EQ(2U, s.size());
          continue;
        }
        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
        EXPECT_EQ(shift.mode, s[0]->addressing_mode());
        EXPECT_EQ(3U, s[0]->InputCount());
        EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
        EXPECT_EQ(1U, s[0]->OutputCount());
        EXPECT_EQ(kFlags_set, s[0]->flags_mode());
        EXPECT_EQ(cmp.cond, s[0]->flags_condition());
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Flag-setting add and and instructions.

const IntegerCmp kBinopCmpZeroRightInstructions[] = {
    {{TSBinop::kWord32Equal, "Word32Equal", kArm64Cmp32, MachineType::Int32()},
     kEqual,
     kEqual},
    {{TSBinop::kWord32NotEqual, "Word32NotEqual", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual},
    {{TSBinop::kInt32LessThan, "Int32LessThan", kArm64Cmp32,
      MachineType::Int32()},
     kNegative,
     kNegative},
    {{TSBinop::kInt32GreaterThanOrEqual, "Int32GreaterThanOrEqual", kArm64Cmp32,
      MachineType::Int32()},
     kPositiveOrZero,
     kPositiveOrZero},
    {{TSBinop::kUint32LessThanOrEqual, "Uint32LessThanOrEqual", kArm64Cmp32,
      MachineType::Int32()},
     kEqual,
     kEqual},
    {{TSBinop::kUint32GreaterThan, "Uint32GreaterThan", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual}};

const IntegerCmp kBinop64CmpZeroRightInstructions[] = {
    {{TSBinop::kWord64Equal, "Word64Equal", kArm64Cmp, MachineType::Int64()},
     kEqual,
     kEqual},
    {{TSBinop::kWord64NotEqual, "Word64NotEqual", kArm64Cmp,
      MachineType::Int64()},
     kNotEqual,
     kNotEqual},
    {{TSBinop::kInt64LessThan, "Int64LessThan", kArm64Cmp,
      MachineType::Int64()},
     kNegative,
     kNegative},
    {{TSBinop::kInt64GreaterThanOrEqual, "Int64GreaterThanOrEqual", kArm64Cmp,
      MachineType::Int64()},
     kPositiveOrZero,
     kPositiveOrZero},
    {{TSBinop::kUint64LessThanOrEqual, "Uint64LessThanOrEqual", kArm64Cmp,
      MachineType::Int64()},
     kEqual,
     kEqual},
    {{TSBinop::kUint64GreaterThan, "Uint64GreaterThan", kArm64Cmp,
      MachineType::Int64()},
     kNotEqual,
     kNotEqual},
};

const IntegerCmp kBinopCmpZeroLeftInstructions[] = {
    {{TSBinop::kWord32Equal, "Word32Equal", kArm64Cmp32, MachineType::Int32()},
     kEqual,
     kEqual},
    {{TSBinop::kWord32NotEqual, "Word32NotEqual", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual},
    {{TSBinop::kInt32GreaterThan, "Int32GreaterThan", kArm64Cmp32,
      MachineType::Int32()},
     kNegative,
     kNegative},
    {{TSBinop::kInt32LessThanOrEqual, "Int32LessThanOrEqual", kArm64Cmp32,
      MachineType::Int32()},
     kPositiveOrZero,
     kPositiveOrZero},
    {{TSBinop::kUint32GreaterThanOrEqual, "Uint32GreaterThanOrEqual",
      kArm64Cmp32, MachineType::Int32()},
     kEqual,
     kEqual},
    {{TSBinop::kUint32LessThan, "Uint32LessThan", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual}};

struct FlagSettingInst {
  MachInst2 mi;
  ArchOpcode no_output_opcode;
};

std::ostream& operator<<(std::ostream& os, const FlagSettingInst& inst) {
  return os << inst.mi.constructor_name;
}

const FlagSettingInst kFlagSettingInstructions[] = {
    {{TSBinop::kWord32Add, "Int32Add", kArm64Add32, MachineType::Int32()},
     kArm64Cmn32},
    {{TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd", kArm64And32,
      MachineType::Int32()},
     kArm64Tst32}};

using TurboshaftInstructionSelectorFlagSettingTest =
    TurboshaftInstructionSelectorTestWithParam<FlagSettingInst>;

TEST_P(TurboshaftInstructionSelectorFlagSettingTest, CmpZeroRight) {
  const FlagSettingInst inst = GetParam();
  // Add with single user : a cmp instruction.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex binop = m.Emit(inst.mi.op, m.Parameter(0), m.Parameter(1));
    m.Return(m.Emit(cmp.mi.op, binop, m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(TurboshaftInstructionSelectorFlagSettingTest, CmpZeroLeft) {
  const FlagSettingInst inst = GetParam();
  // Test a cmp with zero on the left-hand side.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroLeftInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex binop = m.Emit(inst.mi.op, m.Parameter(0), m.Parameter(1));
    m.Return(m.Emit(cmp.mi.op, m.Int32Constant(0), binop));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(TurboshaftInstructionSelectorFlagSettingTest,
       CmpZeroOnlyUserInBasicBlock) {
  const FlagSettingInst inst = GetParam();
  // Binop with additional users, but in a different basic block.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex binop = m.Emit(inst.mi.op, m.Parameter(0), m.Parameter(1));
    OpIndex comp = m.Emit(cmp.mi.op, binop, m.Int32Constant(0));
    m.Branch(m.Parameter<Word32>(0), a, b);
    m.Bind(a);
    m.Return(binop);
    m.Bind(b);
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());  // Flag-setting instruction and branch.
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(TurboshaftInstructionSelectorFlagSettingTest, ShiftedOperand) {
  const FlagSettingInst inst = GetParam();
  // Like the test above, but with a shifted input to the binary operator.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex imm = m.Int32Constant(5);
    OpIndex shift = m.Word32ShiftLeft(m.Parameter(1), imm);
    OpIndex binop = m.Emit(inst.mi.op, m.Parameter(0), shift);
    OpIndex comp = m.Emit(cmp.mi.op, binop, m.Int32Constant(0));
    m.Branch(m.Parameter<Word32>(0), a, b);
    m.Bind(a);
    m.Return(binop);
    m.Bind(b);
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());  // Flag-setting instruction and branch.
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(m.Parameter(1)), s.ToVreg(s[0]->InputAt(1)));
    EXPECT_EQ(5, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(TurboshaftInstructionSelectorFlagSettingTest, UsersInSameBasicBlock) {
  const FlagSettingInst inst = GetParam();
  // Binop with additional users, in the same basic block. We need to make sure
  // we don't try to optimise this case.
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex binop = m.Emit(inst.mi.op, m.Parameter(0), m.Parameter(1));
    OpIndex mul = m.Word32Mul(m.Parameter(0), binop);
    OpIndex comp = m.Emit(cmp.mi.op, binop, m.Int32Constant(0));
    m.Branch(m.Parameter<Word32>(0), a, b);
    m.Bind(a);
    m.Return(mul);
    m.Bind(b);
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(4U, s.size());  // Includes the compare and branch instruction.
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
    EXPECT_EQ(kArm64Mul32, s[1]->arch_opcode());
    EXPECT_EQ(kArm64Cmp32, s[2]->arch_opcode());
    EXPECT_EQ(kFlags_set, s[2]->flags_mode());
    EXPECT_EQ(cmp.cond, s[2]->flags_condition());
  }
}

TEST_P(TurboshaftInstructionSelectorFlagSettingTest, CommuteImmediate) {
  const FlagSettingInst inst = GetParam();
  // Immediate on left hand side of the binary operator.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    // 3 can be an immediate on both arithmetic and logical instructions.
    OpIndex imm = m.Int32Constant(3);
    OpIndex binop = m.Emit(inst.mi.op, imm, m.Parameter(0));
    OpIndex comp = m.Emit(cmp.mi.op, binop, m.Int32Constant(0));
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
    EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(3, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_P(TurboshaftInstructionSelectorFlagSettingTest, CommuteShift) {
  const FlagSettingInst inst = GetParam();
  // Left-hand side operand shifted by immediate.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    TRACED_FOREACH(Shift, shift, kShiftInstructions) {
      // Only test relevant shifted operands.
      if (shift.mi.machine_type != MachineType::Int32()) continue;

      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      OpIndex imm = m.Int32Constant(5);
      OpIndex shifted_operand = m.Emit(shift.mi.op, m.Parameter(0), imm);
      OpIndex binop = m.Emit(inst.mi.op, shifted_operand, m.Parameter(1));
      OpIndex comp = m.Emit(cmp.mi.op, binop, m.Int32Constant(0));
      m.Return(comp);
      Stream s = m.Build();
      // Cmn does not support ROR shifts.
      if (inst.no_output_opcode == kArm64Cmn32 &&
          shift.mi.arch_opcode == kArm64Ror32) {
        ASSERT_EQ(2U, s.size());
        continue;
      }
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(inst.no_output_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(5, s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(cmp.cond, s[0]->flags_condition());
    }
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorFlagSettingTest,
                         ::testing::ValuesIn(kFlagSettingInstructions));

TEST_F(TurboshaftInstructionSelectorTest, TstInvalidImmediate) {
  // Make sure we do not generate an invalid immediate for TST.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    // 5 is not a valid constant for TST.
    OpIndex imm = m.Int32Constant(5);
    OpIndex binop = m.Word32BitwiseAnd(imm, m.Parameter(0));
    OpIndex comp = m.Emit(cmp.mi.op, binop, m.Int32Constant(0));
    m.Return(comp);
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
    EXPECT_NE(InstructionOperand::IMMEDIATE, s[0]->InputAt(0)->kind());
    EXPECT_NE(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CommuteAddsExtend) {
  // Extended left-hand side operand.
  TRACED_FOREACH(IntegerCmp, cmp, kBinopCmpZeroRightInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    OpIndex extend = m.Word32ShiftRightArithmetic(
        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(24)),
        m.Int32Constant(24));
    OpIndex binop = m.Word32Add(extend, m.Parameter(1));
    m.Return(m.Emit(cmp.mi.op, binop, m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
  }
}

// -----------------------------------------------------------------------------
// Miscellaneous

static const MachInst2 kLogicalWithNotRHSs[] = {
    {TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd", kArm64Bic32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseAnd, "Word64BitwiseAnd", kArm64Bic,
     MachineType::Int64()},
    {TSBinop::kWord32BitwiseOr, "Word32BitwiseOr", kArm64Orn32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseOr, "Word64BitwiseOr", kArm64Orn,
     MachineType::Int64()},
    {TSBinop::kWord32BitwiseXor, "Word32BitwiseXor", kArm64Eon32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseXor, "Word64BitwiseXor", kArm64Eon,
     MachineType::Int64()}};

using TurboshaftInstructionSelectorLogicalWithNotRHSTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorLogicalWithNotRHSTest, Parameter) {
  const MachInst2 inst = GetParam();
  const MachineType type = inst.machine_type;
  // Test cases where RHS is Xor(x, -1).
  {
    StreamBuilder m(this, type, type, type);
    if (type == MachineType::Int32()) {
      m.Return(m.Emit(inst.op, m.Parameter(0),
                      m.Word32BitwiseXor(m.Parameter(1), m.Int32Constant(-1))));
    } else {
      ASSERT_EQ(MachineType::Int64(), type);
      m.Return(m.Emit(inst.op, m.Parameter(0),
                      m.Word64BitwiseXor(m.Parameter(1), m.Int64Constant(-1))));
    }
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    if (type == MachineType::Int32()) {
      m.Return(m.Emit(inst.op,
                      m.Word32BitwiseXor(m.Parameter(0), m.Int32Constant(-1)),
                      m.Parameter(1)));
    } else {
      ASSERT_EQ(MachineType::Int64(), type);
      m.Return(m.Emit(inst.op,
                      m.Word64BitwiseXor(m.Parameter(0), m.Int64Constant(-1)),
                      m.Parameter(1)));
    }
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  // Test cases where RHS is Not(x).
  {
    StreamBuilder m(this, type, type, type);
    if (type == MachineType::Int32()) {
      m.Return(
          m.Emit(inst.op, m.Parameter(0), m.Word32BitwiseNot(m.Parameter(1))));
    } else {
      ASSERT_EQ(MachineType::Int64(), type);
      m.Return(
          m.Emit(inst.op, m.Parameter(0), m.Word64BitwiseNot(m.Parameter(1))));
    }
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, type, type, type);
    if (type == MachineType::Int32()) {
      m.Return(
          m.Emit(inst.op, m.Word32BitwiseNot(m.Parameter(0)), m.Parameter(1)));
    } else {
      ASSERT_EQ(MachineType::Int64(), type);
      m.Return(
          m.Emit(inst.op, m.Word64BitwiseNot(m.Parameter(0)), m.Parameter(1)));
    }
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorLogicalWithNotRHSTest,
                         ::testing::ValuesIn(kLogicalWithNotRHSs));

TEST_F(TurboshaftInstructionSelectorTest, Word32BitwiseNotWithParameter) {
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  m.Return(m.Word32BitwiseNot(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Not32, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(TurboshaftInstructionSelectorTest, Word64NotWithParameter) {
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
  m.Return(m.Word64BitwiseNot(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArm64Not, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word32BitwiseXorMinusOneWithParameter) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32BitwiseXor(m.Parameter(0), m.Int32Constant(-1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Not32, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32BitwiseXor(m.Int32Constant(-1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Not32, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64XorMinusOneWithParameter) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64BitwiseXor(m.Parameter(0), m.Int64Constant(-1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Not, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64BitwiseXor(m.Int64Constant(-1), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Not, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word32ShiftRightLogicalWithWord32AndWithImmediate) {
  // The available shift operand range is `0 <= imm < 32`, but we also test
  // that immediates outside this range are handled properly (modulo-32).
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t jnk = rng()->NextInt();
      jnk = (lsb > 0) ? (jnk >> (32 - lsb)) : 0;
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32ShiftRightLogical(
          m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(msk)),
          m.Int32Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 32 - lsb) {
      uint32_t jnk = rng()->NextInt();
      jnk = (lsb > 0) ? (jnk >> (32 - lsb)) : 0;
      uint32_t msk = ((0xFFFFFFFFu >> (32 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32ShiftRightLogical(
          m.Word32BitwiseAnd(m.Int32Constant(msk), m.Parameter(0)),
          m.Int32Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word64ShiftRightLogicalWithWord64AndWithImmediate) {
  // The available shift operand range is `0 <= imm < 64`, but we also test
  // that immediates outside this range are handled properly (modulo-64).
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int32_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int32_t, width, 1, 64 - lsb) {
      uint64_t jnk = rng()->NextInt64();
      jnk = (lsb > 0) ? (jnk >> (64 - lsb)) : 0;
      uint64_t msk =
          ((uint64_t{0xFFFFFFFFFFFFFFFF} >> (64 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64ShiftRightLogical(
          m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(msk)),
          m.Int32Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -64, 127) {
    int32_t lsb = shift & 0x3F;
    TRACED_FORRANGE(int32_t, width, 1, 64 - lsb) {
      uint64_t jnk = rng()->NextInt64();
      jnk = (lsb > 0) ? (jnk >> (64 - lsb)) : 0;
      uint64_t msk =
          ((uint64_t{0xFFFFFFFFFFFFFFFF} >> (64 - width)) << lsb) | jnk;
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
      m.Return(m.Word64ShiftRightLogical(
          m.Word64BitwiseAnd(m.Int64Constant(msk), m.Parameter(0)),
          m.Int32Constant(shift)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(width, s.ToInt64(s[0]->InputAt(2)));
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word32AndWithImmediateWithWord32ShiftRightLogical) {
  // The available shift operand range is `0 <= imm < 32`, but we also test
  // that immediates outside this range are handled properly (modulo-32).
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 31) {
      uint32_t msk = (1u << width) - 1;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32BitwiseAnd(
          m.Word32ShiftRightLogical(m.Parameter(0), m.Int32Constant(shift)),
          m.Int32Constant(msk)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      int32_t actual_width = (lsb + width > 32) ? (32 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
  TRACED_FORRANGE(int32_t, shift, -32, 63) {
    int32_t lsb = shift & 0x1F;
    TRACED_FORRANGE(int32_t, width, 1, 31) {
      uint32_t msk = (1u << width) - 1;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      m.Return(m.Word32BitwiseAnd(
          m.Int32Constant(msk),
          m.Word32ShiftRightLogical(m.Parameter(0), m.Int32Constant(shift))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Ubfx32, s[0]->arch_opcode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(lsb, s.ToInt32(s[0]->InputAt(1)));
      int32_t actual_width = (lsb + width > 32) ? (32 - lsb) : width;
      EXPECT_EQ(actual_width, s.ToInt32(s[0]->InputAt(2)));
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word64AndWithImmediateWithWord64ShiftRig
```