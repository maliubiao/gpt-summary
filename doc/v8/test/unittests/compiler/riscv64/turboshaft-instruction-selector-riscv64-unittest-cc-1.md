Response:
The user wants to understand the functionality of the provided C++ code snippet. This code is a unit test file for the Turboshaft instruction selector in V8's compiler for the RISC-V 64-bit architecture.

Here's a breakdown of how to analyze the code and fulfill the user's request:

1. **Identify the core purpose:** The file name `turboshaft-instruction-selector-riscv64-unittest.cc` clearly indicates that this is a unit test for the instruction selector component of the Turboshaft compiler for RISC-V 64-bit. Instruction selectors are responsible for mapping high-level intermediate representation (IR) operations to specific machine instructions.

2. **Analyze the test structure:** The code uses the Google Test framework (`TEST_F`, `TEST_P`, `EXPECT_EQ`, `ASSERT_EQ`). Each test case focuses on verifying the instruction selection for a particular IR operation or a combination of operations. The `StreamBuilder` and `Stream` classes are likely internal V8 classes used for building and inspecting the generated instruction streams.

3. **Examine individual test cases:**  Go through each `TEST_F` and `TEST_P` function.
    - **`TurboshaftInstructionSelectorElidedChangeInt32ToInt64Test` and `ChangeInt32ToInt64AfterLoad`:** These tests verify how `ChangeInt32ToInt64` operations are handled. Some cases might be elided (optimized away) while others result in specific RISC-V instructions like `Lw` (load word).
    - **`TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test` and `ChangeUint32ToUint64AfterLoad`:** Similar to the previous set, but for `ChangeUint32ToUint64`. Pay attention to how loads of smaller unsigned integers are handled (e.g., `Lbu`, `Lhu`, `Lwu`) and whether zero-extension instructions are generated.
    - **`TurboshaftInstructionSelectorMemoryAccessTest`:** This test uses parameterized testing (`TEST_P`) with `kMemoryAccesses` to check the selection of load and store instructions (`Lb`, `Lbu`, `Lh`, `Lhu`, `Lw`, `Sw`, `Ld`, `Sd`, `LoadFloat`, `StoreFloat`, `LoadDouble`, `StoreDouble`) for different data types.
    - **`TurboshaftInstructionSelectorMemoryAccessImmTest` and `TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest`:** These tests focus on load and store operations with immediate offsets. They verify that the correct addressing modes (`kMode_MRI`) and immediate values are used. The "MoreThan16bit" tests likely handle cases where the immediate offset is too large for a single instruction and might require additional instructions to load the offset.
    - **`TurboshaftInstructionSelectorMemoryAccessUnalignedImmTest`:** This test checks unaligned memory access (if supported by the target architecture).
    - **`Word32EqualWithZero` and `Word64EqualWithZero`:** These tests ensure that comparisons with zero are optimized using specialized instructions like `kRiscvCmpZero32` and `kRiscvCmpZero`.
    - **Other commented-out tests:**  Note the presence of commented-out tests for operations like `Clz` (count leading zeros), `Abs` (absolute value), `Max`, `Min`, `ReverseBytes`. These might be tests for instructions that were planned or are under development.
    - **`LoadAndShiftRight`:** This test looks at how a load followed by a shift-right operation is translated. It specifically checks that the shift isn't incorrectly combined with a subsequent addition.
    - **`ExternalReferenceLoad1` and `ExternalReferenceLoad2`:** These tests verify how loads from external references (like global variables) are handled, particularly whether the `kMode_Root` addressing mode (using the isolate root as a base) can be used for small offsets.

4. **Consider the user's specific requests:**
    - **Functionality Listing:** Summarize the functionality of each test case.
    - **Torque Source:** Check the file extension. If it's not `.tq`, then it's not a Torque file.
    - **JavaScript Relation:** Identify tests that involve operations commonly used in JavaScript (e.g., type conversions, arithmetic, memory access). Provide simple JavaScript examples that might lead to these operations.
    - **Code Logic Reasoning:**  For tests involving specific transformations or optimizations (like eliding `Change` operations), provide hypothetical inputs and the expected output instruction sequence.
    - **Common Programming Errors:** Think about common errors that might manifest as incorrect instruction selection for the tested operations (e.g., incorrect type handling, out-of-bounds memory access).
    - **Summary:**  Provide a concise overview of the file's purpose.

5. **Structure the output:** Organize the information clearly, addressing each of the user's points. Use code blocks for the C++ snippets and JavaScript examples.

By following these steps, we can effectively analyze the C++ code and provide a comprehensive response to the user's request.
```cpp
EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint32) -> Lw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int32) -> Lw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

using TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test, Parameter) {
  const MachInst2 binop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), binop.machine_type,
                  binop.machine_type);
  m.Return(m.Emit(TSUnop::kChangeUint32ToUint64,
                  (m.Emit(binop.op, m.Parameter(0), m.Parameter(1)))));
  Stream s = m.Build();
  // Make sure the `ChangeUint32ToUint64` node turned into two op(sli 32 and sri
  // 32).
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test,
    ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

TEST_F(TurboshaftInstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // Lbu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLbu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // Lhu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLhu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // Lwu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLwu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(kRiscvZeroExtendWord, s[2]->arch_opcode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

// ----------------------------------------------------------------------------
// Loads and stores.
// ----------------------------------------------------------------------------

namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
};

static const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(), kRiscvLb, kRiscvSb},
    {MachineType::Uint8(), kRiscvLbu, kRiscvSb},
    {MachineType::Int16(), kRiscvLh, kRiscvSh},
    {MachineType::Uint16(), kRiscvLhu, kRiscvSh},
    {MachineType::Int32(), kRiscvLw, kRiscvSw},
    {MachineType::Float32(), kRiscvLoadFloat, kRiscvStoreFloat},
    {MachineType::Float64(), kRiscvLoadDouble, kRiscvStoreDouble},
    {MachineType::Int64(), kRiscvLd, kRiscvSd}};

struct MemoryAccessImm {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm& acc) {
  return os << acc.type;
}

struct MemoryAccessImm1 {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[5];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm1& acc) {
  return os << acc.type;
}

// ----------------------------------------------------------------------------
// Loads and stores immediate values
// ----------------------------------------------------------------------------

const MemoryAccessImm kMemoryAccessesImm[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}}};

#ifdef RISCV_HAS_NO_UNALIGNED
struct MemoryAccessImm2 {
  MachineType type;
  ArchOpcode store_opcode;
  ArchOpcode store_opcode_unaligned;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm2& acc) {
  return os << acc.type;
}

const MemoryAccessImm2 kMemoryAccessesImmUnaligned[] = {
    {MachineType::Int16(),
     kRiscvUsh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvUsw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvUsd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvUStoreFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvUStoreDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};
#endif
}  // namespace

using TurboshaftInstructionSelectorMemoryAccessTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                  memacc.type, memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Int32Constant(0),
          m.Parameter(1), kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// ----------------------------------------------------------------------------
// Load immediate.
// ----------------------------------------------------------------------------

using TurboshaftInstructionSelectorMemoryAccessImmTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccessImm>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmTest,
       LoadWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int64Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
  }
}

// ----------------------------------------------------------------------------
// Store immediate.
// ----------------------------------------------------------------------------

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmTest,
       StoreWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int64Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_
### 提示词
```
这是目录为v8/test/unittests/compiler/riscv64/turboshaft-instruction-selector-riscv64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/riscv64/turboshaft-instruction-selector-riscv64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Uint32) -> Lw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int32) -> Lw
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Int32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLw, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

using TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test, Parameter) {
  const MachInst2 binop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), binop.machine_type,
                  binop.machine_type);
  m.Return(m.Emit(TSUnop::kChangeUint32ToUint64,
                  (m.Emit(binop.op, m.Parameter(0), m.Parameter(1)))));
  Stream s = m.Build();
  // Make sure the `ChangeUint32ToUint64` node turned into two op(sli 32 and sri
  // 32).
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorElidedChangeUint32ToUint64Test,
    ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

TEST_F(TurboshaftInstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // Lbu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLbu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // Lhu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLhu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // Lwu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint32(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kRiscvAdd64, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kRiscvLwu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(kRiscvZeroExtendWord, s[2]->arch_opcode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

// ----------------------------------------------------------------------------
// Loads and stores.
// ----------------------------------------------------------------------------

namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
};

static const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(), kRiscvLb, kRiscvSb},
    {MachineType::Uint8(), kRiscvLbu, kRiscvSb},
    {MachineType::Int16(), kRiscvLh, kRiscvSh},
    {MachineType::Uint16(), kRiscvLhu, kRiscvSh},
    {MachineType::Int32(), kRiscvLw, kRiscvSw},
    {MachineType::Float32(), kRiscvLoadFloat, kRiscvStoreFloat},
    {MachineType::Float64(), kRiscvLoadDouble, kRiscvStoreDouble},
    {MachineType::Int64(), kRiscvLd, kRiscvSd}};

struct MemoryAccessImm {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm& acc) {
  return os << acc.type;
}

struct MemoryAccessImm1 {
  MachineType type;
  ArchOpcode load_opcode;
  ArchOpcode store_opcode;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[5];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm1& acc) {
  return os << acc.type;
}

// ----------------------------------------------------------------------------
// Loads and stores immediate values
// ----------------------------------------------------------------------------

const MemoryAccessImm kMemoryAccessesImm[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}}};

#ifdef RISCV_HAS_NO_UNALIGNED
struct MemoryAccessImm2 {
  MachineType type;
  ArchOpcode store_opcode;
  ArchOpcode store_opcode_unaligned;
  bool (TurboshaftInstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};

std::ostream& operator<<(std::ostream& os, const MemoryAccessImm2& acc) {
  return os << acc.type;
}

const MemoryAccessImm2 kMemoryAccessesImmUnaligned[] = {
    {MachineType::Int16(),
     kRiscvUsh,
     kRiscvSh,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvUsw,
     kRiscvSw,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvUsd,
     kRiscvSd,
     &TurboshaftInstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvUStoreFloat,
     kRiscvStoreFloat,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvUStoreDouble,
     kRiscvStoreDouble,
     &TurboshaftInstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};
#endif
}  // namespace

using TurboshaftInstructionSelectorMemoryAccessTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                  memacc.type, memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Int32Constant(0),
          m.Parameter(1), kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// ----------------------------------------------------------------------------
// Load immediate.
// ----------------------------------------------------------------------------

using TurboshaftInstructionSelectorMemoryAccessImmTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccessImm>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmTest,
       LoadWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int64Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
  }
}

// ----------------------------------------------------------------------------
// Store immediate.
// ----------------------------------------------------------------------------

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmTest,
       StoreWithImmediateIndex) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int64Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmTest, StoreZero) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    OpIndex zero;
    if (memacc.type.representation() >= MachineRepresentation::kWord8 &&
        memacc.type.representation() <= MachineRepresentation::kWord64) {
      zero = m.WordConstant(
          0, memacc.type.representation() <= MachineRepresentation::kWord32
                 ? WordRepresentation::Word32()
                 : WordRepresentation::Word64());
    } else {
      zero = m.FloatConstant(
          0, memacc.type.representation() == MachineRepresentation::kFloat32
                 ? FloatRepresentation::Float32()
                 : FloatRepresentation::Float64());
    }
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int64Constant(index), zero, kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(0)->kind());
    EXPECT_EQ(0,
              memacc.type.representation() < MachineRepresentation::kFloat32
                  ? s.ToInt64(s[0]->InputAt(0))
              : memacc.type.representation() == MachineRepresentation::kFloat32
                  ? s.ToFloat32(s[0]->InputAt(0))
                  : s.ToFloat64(s[0]->InputAt(0)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMemoryAccessImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImm));

#ifdef RISCV_HAS_NO_UNALIGNED
using TurboshaftInstructionSelectorMemoryAccessUnalignedImmTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccessImm2>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessUnalignedImmTest, StoreZero) {
  const MemoryAccessImm2 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    bool unaligned_store_supported =
        m.machine()->UnalignedStoreSupported(memacc.type.representation());
    m.UnalignedStore(memacc.type.representation(), m.Parameter(0),
                     m.Int32Constant(index), m.Int32Constant(0));
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    uint32_t i = is_int12(index) ? 0 : 1;
    ASSERT_EQ(i + 1, s.size());
    EXPECT_EQ(unaligned_store_supported ? memacc.store_opcode_unaligned
                                        : memacc.store_opcode,
              s[i]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[i]->addressing_mode());
    ASSERT_EQ(3U, s[i]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[i]->InputAt(1)->kind());
    EXPECT_EQ(i == 0 ? index : 0, s.ToInt32(s[i]->InputAt(1)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[i]->InputAt(2)->kind());
    EXPECT_EQ(0, s.ToInt64(s[i]->InputAt(2)));
    EXPECT_EQ(0U, s[i]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorMemoryAccessUnalignedImmTest,
    ::testing::ValuesIn(kMemoryAccessesImmUnaligned));
#endif
// ----------------------------------------------------------------------------
// Load/store offsets more than 16 bits.
// ----------------------------------------------------------------------------

using TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest =
    TurboshaftInstructionSelectorTestWithParam<MemoryAccessImm1>;

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest,
       LoadWithImmediateIndex) {
  const MemoryAccessImm1 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int64Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest,
       StoreWithImmediateIndex) {
  const MemoryAccessImm1 memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int64Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(
    TurboshaftInstructionSelectorTest,
    TurboshaftInstructionSelectorMemoryAccessImmMoreThan16bitTest,
    ::testing::ValuesIn(kMemoryAccessImmMoreThan16bit));

// ----------------------------------------------------------------------------
// kRiscvCmp with zero testing.
// ----------------------------------------------------------------------------

TEST_F(TurboshaftInstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Emit(TSBinop::kWord32Equal, m.Parameter(0), m.Int32Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCmpZero32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Emit(TSBinop::kWord32Equal, m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCmpZero32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Emit(TSBinop::kWord64Equal, m.Parameter(0), m.Int64Constant(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCmpZero, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Emit(TSBinop::kWord64Equal, m.Int64Constant(0), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCmpZero, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

// TEST_F(TurboshaftInstructionSelectorTest, Word32Clz) {
//   StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
//   auto p0 = m.Parameter(0);
//   auto n = m.Word32Clz(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvClz32, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word64Clz) {
//   StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint64());
//   auto p0 = m.Parameter(0);
//   auto n = m.Word64Clz(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvClz64, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float32Abs) {
//   StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
//   auto p0 = m.Parameter(0);
//   auto n = m.Float32Abs(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvAbsS, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float64Abs) {
//   StreamBuilder m(this, MachineType::Float64(), MachineType::Float64());
//   auto p0 = m.Parameter(0);
//   auto n = m.Float64Abs(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvAbsD, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float64Max) {
//   StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
//                   MachineType::Float64());
//   auto p0 = m.Parameter(0);
//   auto p1 = m.Parameter(1);
//   auto n = m.Float64Max(p0, p1);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvFloat64Max, s[0]->arch_opcode());
//   ASSERT_EQ(2U, s[0]->InputCount());
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float64Min) {
//   StreamBuilder m(this, MachineType::Float64(), MachineType::Float64(),
//                   MachineType::Float64());
//   auto p0 = m.Parameter(0);
//   auto p1 = m.Parameter(1);
//   auto n = m.Float64Min(p0, p1);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvFloat64Min, s[0]->arch_opcode());
//   ASSERT_EQ(2U, s[0]->InputCount());
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

TEST_F(TurboshaftInstructionSelectorTest, LoadAndShiftRight) {
  {
    int32_t immediates[] = {-256, -255, -3,   -2,   -1,    0,    1,
                            2,    3,    255,  256,  260,   4096, 4100,
                            8192, 8196, 3276, 3280, 16376, 16380};
    TRACED_FOREACH(int32_t, index, immediates) {
      StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer());
      auto load =
          m.Load(MachineType::Uint64(), m.Parameter(0), m.Int64Constant(index));
      auto sar = m.Emit(TSBinop::kWord64ShiftRightArithmetic, load,
                        m.Int32Constant(32));
      // Make sure we don't fold the shift into the following add:
      m.Return(m.Emit(TSBinop::kWord64Add, sar, m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kRiscvLw, s[0]->arch_opcode());
      EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
      EXPECT_EQ(2U, s[0]->InputCount());
      EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
      ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
#if defined(V8_TARGET_LITTLE_ENDIAN)
      EXPECT_EQ(index + 4, s.ToInt32(s[0]->InputAt(1)));
#elif defined(V8_TARGET_BIG_ENDIAN)
      EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
#endif

      ASSERT_EQ(1U, s[0]->OutputCount());
    }
  }
}

// TEST_F(TurboshaftInstructionSelectorTest, Word32ReverseBytes) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Word32ReverseBytes(m.Parameter(0)));
//     Stream s = m.Build();
//     if (CpuFeatures::IsSupported(ZBB)) {
//       ASSERT_EQ(2U, s.size());
//       EXPECT_EQ(kRiscvRev8, s[0]->arch_opcode());
//       EXPECT_EQ(kRiscvShr64, s[1]->arch_opcode());
//       EXPECT_EQ(1U, s[0]->InputCount());
//       EXPECT_EQ(1U, s[0]->OutputCount());
//     } else {
//       ASSERT_EQ(1U, s.size());
//       EXPECT_EQ(kRiscvByteSwap32, s[0]->arch_opcode());
//       EXPECT_EQ(1U, s[0]->InputCount());
//       EXPECT_EQ(1U, s[0]->OutputCount());
//     }
//   }
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word64ReverseBytes) {
//   {
//     StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
//     m.Return(m.Word64ReverseBytes(m.Parameter(0)));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     if (CpuFeatures::IsSupported(ZBB)) {
//       EXPECT_EQ(kRiscvRev8, s[0]->arch_opcode());
//     } else {
//       EXPECT_EQ(kRiscvByteSwap64, s[0]->arch_opcode());
//     }
//     EXPECT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

TEST_F(TurboshaftInstructionSelectorTest, ExternalReferenceLoad1) {
  // Test offsets we can use kMode_Root for.
  const int64_t kOffsets[] = {0, 1, 4, INT32_MIN, INT32_MAX};
  TRACED_FOREACH(int64_t, offset, kOffsets) {
    StreamBuilder m(this, MachineType::Int64());
    ExternalReference reference =
        base::bit_cast<ExternalReference>(isolate()->isolate_root() + offset);
    auto value = m.Load(MachineType::Int64(), m.ExternalConstant(reference));
    m.Return(value);

    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvLd, s[0]->arch_opcode());
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
  auto value = m.Load(MachineType::Int64(), m.ExternalConstant(reference));
  m.Return(value);

  Stream s = m.Build();

  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kRiscvLd, s[0]->arch_opcode());
  EXPECT_NE(kMode_Root, s[0]->addressing_mode());
}

}  // namespace turboshaft
}  // namespace compiler
}  // namespace internal
}  // namespace v8
```