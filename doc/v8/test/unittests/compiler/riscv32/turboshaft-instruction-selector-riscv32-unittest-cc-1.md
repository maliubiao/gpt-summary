Response:
The user wants a summary of the functionality of the provided C++ code snippet. The snippet is part of the V8 JavaScript engine's Turboshaft compiler for the RISC-V 32-bit architecture. It's a unit test file.

Here's a plan to address the user's request:

1. **Identify the purpose of the file:** The file `turboshaft-instruction-selector-riscv32-unittest.cc` contains unit tests for the instruction selector in the Turboshaft compiler for RISC-V 32-bit. Instruction selectors are responsible for translating high-level intermediate representations (IR) of code into machine-specific instructions.

2. **Analyze the test structure:** The code defines several test fixtures (`TurboshaftInstructionSelectorTest`, `TurboshaftInstructionSelectorTestWithParam`) and uses Google Test's `TEST_P` macro for parameterized tests. This indicates that the tests cover various scenarios by iterating through different input values or configurations.

3. **Categorize the tests:** Observe the different test names and the operations they perform:
    - `LoadWithParameters`, `StoreWithParameters`: Tests for basic load and store instructions with register operands.
    - `LoadWithImmediateIndex`, `StoreWithImmediateIndex`: Tests for load and store instructions with immediate offsets.
    - `StoreZero`: Tests specifically for storing zero values.
    - Tests related to unaligned memory access (if the architecture supports it).
    - Tests for comparisons with zero.
    - Tests for specific instructions like byte swapping.
    - Tests for loading from external references.

4. **Relate to JavaScript functionality:** Memory access (loads and stores) is fundamental to how JavaScript interacts with data. While the tests are low-level, they ensure the compiler correctly translates JavaScript operations involving variable access, object property access, and array access into RISC-V instructions.

5. **Provide examples and explanations:**
    - For memory access, illustrate how JavaScript code translates to load and store operations.
    - For comparisons with zero, show how JavaScript's equality checks (`==`, `===`) might utilize such instructions.

6. **Address potential programming errors:**  Highlight how incorrect memory access (e.g., accessing out-of-bounds memory) can lead to crashes or unexpected behavior.

7. **Summarize the overall functionality.**

**Self-Correction during thought process:**

- Initially, I focused too much on individual test cases. It's more beneficial to group them by functionality (load/store, immediate offsets, etc.) for the summary.
- The user asked if the file were a `.tq` file. I need to explicitly state that it's a `.cc` file (C++) and explain what `.tq` files are in V8 (Torque).
-  I should provide a clear separation between the low-level C++ testing and the higher-level JavaScript concepts.
这是一个针对V8 JavaScript引擎中，针对RISC-V 32位架构的Turboshaft编译器指令选择器的单元测试代码的第二部分。

**归纳一下它的功能:**

这部分代码主要集中在测试Turboshaft编译器在将中间表示（IR）转换为RISC-V 32位汇编指令时，对于**内存访问**指令的选择是否正确。它测试了以下几种不同的内存访问场景：

1. **基本的加载和存储指令:**
   - 测试了使用寄存器作为地址的加载和存储操作，包括不同数据类型（例如，整数、浮点数）的加载和存储。

2. **使用立即数偏移的加载和存储指令:**
   - 测试了在加载和存储指令中使用立即数作为偏移量的情况，验证了编译器能否正确生成带有立即数偏移的指令。
   - 针对不同的立即数值进行了测试，包括正数和负数。

3. **存储零值:**
   - 特别测试了存储零值到内存中的情况，验证了编译器能否正确处理这类操作。

4. **非对齐内存访问 (仅在RISC-V支持非对齐访问时):**
   - 如果RISC-V架构支持非对齐内存访问，则会测试非对齐的存储操作，包括使用立即数偏移的情况。
   - 区分了架构支持非对齐访问和不支持的情况，并验证了在不支持的情况下是否会生成正确的替代指令序列。

5. **超过16位偏移的加载和存储指令:**
   - 测试了当立即数偏移量超过16位时，指令选择器是否能正确生成指令来处理这些较大的偏移。

6. **与零比较的指令选择 (`kRiscvCmpZero`):**
   - 测试了将一个32位整数与零进行比较的情况，验证了编译器是否选择了专门的 `kRiscvCmpZero` 指令。

7. **其他指令的测试 (注释掉的代码):**
   -  代码中注释掉了一些其他指令的测试，例如 `Word32Clz` (计算前导零个数), `Float32Abs`, `Float64Abs` (绝对值), `Float64Max`, `Float64Min` (最大值和最小值), `Word32ReverseBytes` (字节反转)。这些可能是在其他地方测试，或者暂时被注释掉了。

8. **加载外部引用:**
   - 测试了从外部引用加载数据的情况，验证了编译器能否正确生成访问全局或静态变量的指令。

**关于 `v8/test/unittests/compiler/riscv32/turboshaft-instruction-selector-riscv32-unittest.cc` 是否以 `.tq` 结尾:**

该文件以 `.cc` 结尾，因此它是 **C++ 源代码**。以 `.tq` 结尾的文件是 **V8 Torque 源代码**。Torque 是一种用于编写 V8 内部实现的领域特定语言。

**与 JavaScript 功能的关系 (内存访问部分):**

JavaScript 中对变量、对象属性、数组元素的访问都需要通过内存加载和存储操作来实现。 例如：

```javascript
let x = 10; // 存储 10 到变量 x 对应的内存地址
let y = x;  // 从变量 x 对应的内存地址加载值，并存储到变量 y 对应的内存地址
let obj = { a: 20 }; // 存储对象 obj 及其属性 a 的值到内存
let z = obj.a; // 从对象 obj 的属性 a 对应的内存地址加载值
let arr = [1, 2, 3]; // 存储数组 arr 的元素到内存
let w = arr[1]; // 从数组 arr 的索引 1 对应的内存地址加载值
```

Turboshaft 编译器的指令选择器需要将这些 JavaScript 操作转换为 RISC-V 32 位的加载和存储指令 (如 `lw`, `sw`, `flw`, `fsw`, `ld`, `sd`, `fld`, `fsd` 等)。  这个单元测试确保了这些转换的正确性。

**代码逻辑推理 (假设输入与输出):**

以 `TEST_P(TurboshaftInstructionSelectorMemoryAccessTest, LoadWithParameters)` 为例：

**假设输入:**

- `memacc.type`: `MachineType::Int32()` (表示要加载一个 32 位整数)
- `memacc.load_opcode`: `kRiscvLw` (RISC-V 的加载字指令)

**代码逻辑:**

1. 创建一个 Turboshaft 流构建器 `m`，它接受一个指向内存地址的指针作为参数。
2. 使用 `m.Load()` 生成一个加载操作，从参数 `m.Parameter(0)` (即指针) 指向的内存地址加载 `memacc.type` 指定类型的数据。
3. 使用 `m.Return()` 返回加载的值。
4. 构建指令流 `s`。

**预期输出:**

- `s` 的大小为 1，因为它只生成了一个加载指令。
- 第一个指令 `s[0]` 的架构操作码 `arch_opcode()` 应该是 `memacc.load_opcode`，即 `kRiscvLw`。
- 第一个指令的寻址模式 `addressing_mode()` 应该是 `kMode_MRI` (寄存器 + 寄存器间接寻址，这里由于偏移为0，可以简化理解为寄存器间接寻址)。

**涉及用户常见的编程错误 (与内存访问相关):**

1. **空指针解引用:**
   ```javascript
   let obj = null;
   console.log(obj.a); // 运行时错误: Cannot read property 'a' of null
   ```
   在底层，这会导致尝试从地址 `0x0` 加载数据，这是一个无效的内存地址，会导致程序崩溃。

2. **数组越界访问:**
   ```javascript
   let arr = [1, 2, 3];
   console.log(arr[5]); // 返回 undefined，但在某些情况下可能导致越界访问，尤其是在底层操作中
   ```
   编译器需要确保生成的加载指令不会访问超出数组边界的内存。

3. **类型不匹配的内存访问:**
   ```c++ // 假设底层操作，JavaScript 通常会进行类型转换
   int x = 10;
   float* p = (float*)&x;
   float f = *p; // 可能会导致未定义的行为，因为以 float 的方式读取 int 的内存
   ```
   虽然 JavaScript 会进行类型转换，但在 V8 的底层实现中，需要确保内存访问的类型与数据的类型一致。

4. **使用未初始化的变量:**
   ```javascript
   let x;
   console.log(x); // 返回 undefined
   ```
   在底层，这可能意味着尝试加载一个未被赋值的内存地址的值，其结果是不可预测的。

这个单元测试的目的是验证 Turboshaft 编译器在生成内存访问指令时是否能够正确处理各种情况，从而避免这些常见的编程错误在 JavaScript 引擎的底层发生。

### 提示词
```
这是目录为v8/test/unittests/compiler/riscv32/turboshaft-instruction-selector-riscv32-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/riscv32/turboshaft-instruction-selector-riscv32-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
1569,  2587,  3067,  3096,  3462, 3510, 4095}},
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
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
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
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
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
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
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
            m.Int32Constant(index), zero, kNoWriteBarrier);
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
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
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
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
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
    EXPECT_EQ(kRiscvCmpZero, s[0]->arch_opcode());
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
//   Node* const p0 = m.Parameter(0);
//   Node* const n = m.Word32Clz(p0);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvClz32, s[0]->arch_opcode());
//   ASSERT_EQ(1U, s[0]->InputCount());
//   EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

// TEST_F(TurboshaftInstructionSelectorTest, Float32Abs) {
//   StreamBuilder m(this, MachineType::Float32(), MachineType::Float32());
//   Node* const p0 = m.Parameter(0);
//   Node* const n = m.Float32Abs(p0);
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
//   Node* const p0 = m.Parameter(0);
//   Node* const n = m.Float64Abs(p0);
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
//   Node* const p0 = m.Parameter(0);
//   Node* const p1 = m.Parameter(1);
//   Node* const n = m.Float64Max(p0, p1);
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
//   Node* const p0 = m.Parameter(0);
//   Node* const p1 = m.Parameter(1);
//   Node* const n = m.Float64Min(p0, p1);
//   m.Return(n);
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(kRiscvFloat64Min, s[0]->arch_opcode());
//   ASSERT_EQ(2U, s[0]->InputCount());
//   ASSERT_EQ(1U, s[0]->OutputCount());
//   EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
// }

TEST_F(TurboshaftInstructionSelectorTest, Word32ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    // EXPECT_EQ(kRiscvByteSwap32, s[0]->arch_opcode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, ExternalReferenceLoad1) {
  // Test offsets we can use kMode_Root for.
  const int32_t kOffsets[] = {0, 1, 4, INT32_MIN, INT32_MAX};
  TRACED_FOREACH(int64_t, offset, kOffsets) {
    StreamBuilder m(this, MachineType::Int32());
    ExternalReference reference = base::bit_cast<ExternalReference>(
        (int32_t)(isolate()->isolate_root() + offset));
    auto value = m.Load(MachineType::Int32(), m.ExternalConstant(reference));
    m.Return(value);

    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvLw, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Root, s[0]->addressing_mode());
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(s.ToInt64(s[0]->InputAt(0)), offset);
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

}  // namespace turboshaft
}  // namespace compiler
}  // namespace internal
}  // namespace v8
```