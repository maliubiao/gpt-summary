Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Goal:**

The initial request asks for a breakdown of the functionality of a specific V8 unit test file (`instruction-selector-arm64-unittest.cc`). It also includes several constraints and questions about the code's nature (Torque, JavaScript relation), logic, common errors, and a final summary.

**2. Initial Assessment of the File Name and Path:**

The path `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` immediately suggests several things:

* **`v8`:**  This confirms we're dealing with the V8 JavaScript engine.
* **`test/unittests`:**  This clearly indicates it's a unit test file. Unit tests focus on testing small, isolated units of code.
* **`compiler`:** This tells us the code under test is related to the compilation process within V8.
* **`arm64`:** This specifies the target architecture is ARM64.
* **`instruction-selector`:** This is a key component of a compiler. The instruction selector's job is to translate intermediate representations of code into actual machine instructions for the target architecture.
* **`.cc`:** This is a standard C++ file extension.

**3. Checking for Torque:**

The prompt specifically asks if the file ends in `.tq`. Since it ends in `.cc`, it's C++ and *not* a Torque file. This is an important early conclusion.

**4. Analyzing the Code Structure (Top-Down):**

* **Includes:** While not shown in the provided snippet,  a full `.cc` file would start with `#include` directives. These would give clues about the dependencies and specific parts of V8 being tested (likely related to the ARM64 backend and the instruction selector). *While we don't have these, we can infer based on the content.*
* **Namespaces:**  The code uses V8 namespaces (e.g., `v8::internal`). This is typical for V8 code.
* **Test Fixtures and Test Cases:** The code uses Google Test (`TEST_P`, `TEST_F`, `INSTANTIATE_TEST_SUITE_P`). This is a standard way of writing unit tests in C++. We see structures like `InstructionSelectorTest`, `InstructionSelectorMemoryAccessTest`, and individual `TEST_P` and `TEST_F` macros, indicating various test groups and individual test cases.
* **Data Structures for Test Cases:**  The code defines structures like `MemoryAccess`, `MachInst2`, and `IntegerCmp` to hold test data. These structures contain information about machine types, opcodes, and test values. This suggests the tests are parameterized and aim to cover various scenarios.
* **`StreamBuilder` and `Stream`:**  These likely represent a way to build and inspect sequences of machine instructions within the tests. The `m.Load()`, `m.Store()`, `m.Word32Equal()`, etc., methods are clearly constructing these instruction streams.
* **Assertions and Expectations:** The code uses `ASSERT_EQ`, `EXPECT_EQ`, `ASSERT_NE`, etc., to verify the generated instruction sequences match the expected output. This is how the tests assert correctness.
* **Iterators and Loops:**  The code utilizes `TRACED_FOREACH` and `TRACED_FORRANGE` to iterate through test data. This is a common technique for writing comprehensive, data-driven tests.

**5. Inferring Functionality from Test Names and Code:**

* **`InstructionSelectorMemoryAccessTest`:**  The tests within this fixture (`LoadWithParameters`, `LoadWithImmediateIndex`, `StoreWithParameters`, etc.) clearly focus on testing the instruction selector's behavior when handling memory access operations (loads and stores) with different addressing modes (register-register, register-immediate). The parameters passed to the tests (`MemoryAccess`) confirm this.
* **`InstructionSelectorStoreWithBarrierTest`:** This fixture focuses on testing store operations that require write barriers (mechanisms to maintain the integrity of the V8 heap). The `WriteBarrierKind` parameter indicates the different types of write barriers being tested.
* **`InstructionSelectorComparisonTest`:** These tests examine how the instruction selector handles comparison operations (`Word32Equal`, `Word64Equal`) and generates the corresponding ARM64 instructions (like `kArm64Cmp32`, `kArm64Cmp`). The `MachInst2` structure provides the necessary information.
* **Individual Tests (e.g., `Word32EqualWithZero`, `Word32EqualWithWord32Shift`):** These tests explore specific scenarios and optimizations, like handling comparisons with zero or comparisons involving shifted operands.

**6. Connecting to JavaScript Functionality (If Applicable):**

The core function of the instruction selector is to translate *higher-level code* (in V8's case, often generated from JavaScript) into machine code. Therefore, even though the test code is C++, it's directly related to how JavaScript features are implemented at the machine code level.

* **Memory Access:** JavaScript involves reading and writing to memory when accessing variables, object properties, and array elements. The tests for `Load` and `Store` directly relate to how these JavaScript operations are translated to ARM64 instructions.
* **Write Barriers:**  V8's garbage collector requires write barriers when updating object pointers to ensure memory safety. The tests for `StoreWithWriteBarrier` are essential for verifying this mechanism.
* **Comparisons:**  JavaScript uses comparison operators (`==`, `!=`, `<`, `>`, etc.). The tests for `Word32Equal`, `Int32LessThan`, etc., verify that these operators are correctly translated into ARM64 comparison instructions.

**7. Considering Common Programming Errors:**

By understanding what the tests are verifying, we can infer potential programming errors. For example, incorrect handling of immediate values in memory access or failing to generate write barriers when necessary would be bugs in the instruction selector.

**8. Formulating Assumptions for Logic Reasoning:**

To provide input/output examples, we need to make assumptions about the input IR (Intermediate Representation) that the instruction selector receives. The `StreamBuilder` is simulating this input.

**9. Synthesizing the Summary:**

The final step is to consolidate all the observations into a concise summary, highlighting the key functionality of the unit test file.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this testing *all* instruction selection for ARM64?"  *Correction:*  No, it's a unit test file, so it likely focuses on specific aspects or groups of instructions. The directory structure confirms it's within the `arm64` subdirectory, so it's specific to that architecture.
* **Realization:**  The test names and the code itself provide strong clues about the *intent* and *scope* of the tests, even without seeing the include directives.
* **Focus Shift:**  Instead of trying to understand every single line of generated assembly (which isn't fully provided), focus on the *patterns* and the *types of operations* being tested.

By following this systematic approach, we can effectively analyze the provided code snippet and address all aspects of the initial request.
这是对位于 `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 的 V8 源代码的分析，该文件主要用于测试 ARM64 架构的指令选择器。以下是根据您提供的代码片段进行的归纳：

**功能归纳 (基于提供的代码片段 - 第 5 部分)：**

这个代码片段主要关注 **ARM64 指令选择器中内存访问指令的正确生成** 以及 **带有写屏障的存储指令的正确生成** 和 **比较指令的正确生成**。它通过一系列的单元测试用例来验证指令选择器在不同场景下的行为。

**具体功能点：**

1. **内存访问指令测试 (Load/Store):**
   - **测试不同数据类型的加载和存储指令：** 涵盖了 `int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float32`, `float64` 等多种数据类型。
   - **测试不同的寻址模式：**
     - **寄存器-寄存器模式 (MRR):** 使用两个寄存器作为地址。
     - **寄存器-立即数模式 (MRI):** 使用寄存器和一个立即数偏移量作为地址。
     - **带移位的寄存器模式 (Operand2_R_LSL_I):**  使用寄存器和一个移位操作作为地址偏移。
   - **测试不同的立即数偏移量：** 覆盖正数、负数以及边界值，以确保指令选择器能正确处理各种偏移量。

2. **带有写屏障的存储指令测试 (Store with Write Barrier):**
   - **测试不同的写屏障类型：** 涵盖了 `kMapWriteBarrier`, `kPointerWriteBarrier`, `kEphemeronKeyWriteBarrier`, `kFullWriteBarrier` 等不同的写屏障类型。
   - **测试寄存器-寄存器和寄存器-立即数寻址模式下的写屏障存储指令。**

3. **比较指令测试 (Comparison Instructions):**
   - **测试基本的相等比较指令：**  `Word32Equal`, `Word64Equal`。
   - **测试与立即数的比较。**
   - **测试与零的比较 (优化为 `tst` 指令)。**
   - **测试与移位操作结果的比较。**
   - **测试与扩展操作结果的比较：**  包括无符号扩展字节 (`UXTB`)、无符号扩展半字 (`UXTH`)、有符号扩展字节 (`SXTB`)、有符号扩展半字 (`SXTH`)。
   - **测试比较结果与其他值的比较。**
   - **测试不等比较指令：** `Int32LessThan`, `Int32LessThanOrEqual`, `Uint32LessThan`, `Uint32LessThanOrEqual`, `Word32NotEqual`。
   - **测试比较指令中操作数顺序的影响。**
   - **测试比较指令与取反操作 (`Int32Sub(0, ...)`) 的组合 (优化为 `cmn` 指令)。**

**关于其他问题的解答：**

* **`.tq` 后缀：**  `v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。

* **与 JavaScript 的功能关系：** 指令选择器是编译器的一部分，其核心职责是将高级中间表示 (IR) 转换为特定架构的机器指令。当 V8 执行 JavaScript 代码时，它会将 JavaScript 编译成机器码。指令选择器在编译过程中扮演着至关重要的角色。

   **JavaScript 示例：**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   let x = 10;
   let y = 20;
   let sum = add(x, y); // 这里会触发加法运算
   console.log(sum);

   let obj = { value: 5 };
   let z = obj.value; // 这里会触发内存读取
   obj.value = 15;     // 这里会触发内存写入

   if (x == y) { // 这里会触发比较运算
     console.log("x 等于 y");
   }
   ```

   在 V8 编译上述 JavaScript 代码时，指令选择器会根据不同的操作 (加法、内存访问、比较) 选择相应的 ARM64 指令，例如：

   - 加法：可能会选择 `ADD` 指令。
   - 内存读取：可能会选择 `LDR` (Load Register) 指令。
   - 内存写入：可能会选择 `STR` (Store Register) 指令。
   - 相等比较：可能会选择 `CMP` (Compare) 指令。
   - 写屏障：当修改堆上对象指针时，会生成带有写屏障的 `STR` 指令。

* **代码逻辑推理 (假设输入与输出):**

   **假设输入 (基于 `TEST_P(InstructionSelectorMemoryAccessTest, LoadWithImmediateIndex)`)：**

   - `memacc.type`: `MachineType::Int32()` (假设测试的是 32 位整数加载)
   - `memacc.ldr_opcode`: `kArm64LdrW` (对应的 ARM64 加载指令)
   - `index`:  例如 `100`

   **预期输出的 ARM64 指令 (简化表示):**

   ```assembly
   LDR Wd, [Xn, #100]
   ```

   - `LDR Wd`:  32 位加载指令。
   - `Xn`:  表示基址寄存器 (对应 `m.Parameter(0)`)。
   - `#100`: 表示立即数偏移量。

   **假设输入 (基于 `TEST_P(InstructionSelectorComparisonTest, WithImmediate)`)：**

   - `cmp.constructor`: `&RawMachineAssembler::Word32Equal` (32 位相等比较)
   - `cmp.arch_opcode`: `kArm64Cmp32`
   - `imm`: 例如 `50`

   **预期输出的 ARM64 指令 (简化表示):**

   ```assembly
   CMP Wn, #50
   ```

   - `CMP Wn`: 32 位比较指令。
   - `Wn`:  表示寄存器 (对应 `m.Parameter(0)`)。
   - `#50`: 表示立即数。

* **涉及用户常见的编程错误：** 虽然这个测试文件是针对编译器内部的，但它测试的场景与用户代码息息相关。编译器中的错误可能会导致用户代码在运行时出现意想不到的行为或性能问题。

   **示例：**

   - **错误的内存访问：** 如果指令选择器生成的加载或存储指令使用了错误的偏移量或寻址模式，可能导致程序读取或写入错误的内存地址，引发崩溃或数据损坏。 例如，用户可能在 JavaScript 中访问数组越界，如果编译器没有正确处理，就可能导致错误的机器码生成。
   - **比较错误：** 如果指令选择器生成的比较指令使用了错误的条件码或操作数，可能导致 `if` 语句或循环的执行逻辑错误。例如，用户在 JavaScript 中使用了错误的比较运算符，编译器如果不能正确翻译，会导致程序行为不符合预期。
   - **缺少写屏障：**  如果指令选择器在需要写屏障的场景下没有生成相应的指令，可能会导致垃圾回收器错误地回收正在使用的对象，引发程序崩溃。 这通常发生在操作对象之间的引用关系时。

**总结：**

这部分代码是 V8 编译器中 ARM64 指令选择器单元测试套件的一部分，专注于验证指令选择器在处理各种内存访问、带有写屏障的存储以及比较操作时，能够生成正确的 ARM64 机器指令。 这些测试覆盖了不同的数据类型、寻址模式、立即数偏移和操作数组合，旨在确保编译器后端在目标架构上的正确性和可靠性。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能

"""
4094, 4095}},
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

using InstructionSelectorMemoryAccessTest =
    InstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRR, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
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

TEST_P(InstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                  MachineType::Int32(), memacc.type);
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

TEST_P(InstructionSelectorMemoryAccessTest, StoreWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
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

TEST_P(InstructionSelectorMemoryAccessTest, StoreZero) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Int32Constant(0), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(0)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(0)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithShiftedIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FORRANGE(int, immediate_shift, 0, 4) {
    // 32 bit shift
    {
      StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                      MachineType::Int32());
      Node* const index =
          m.Word32Shl(m.Parameter(1), m.Int32Constant(immediate_shift));
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
    // 64 bit shift
    {
      StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                      MachineType::Int64());
      Node* const index =
          m.Word64Shl(m.Parameter(1), m.Int64Constant(immediate_shift));
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

TEST_P(InstructionSelectorMemoryAccessTest, StoreWithShiftedIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FORRANGE(int, immediate_shift, 0, 4) {
    // 32 bit shift
    {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                      MachineType::Int32(), memacc.type);
      Node* const index =
          m.Word32Shl(m.Parameter(1), m.Int32Constant(immediate_shift));
      m.Store(memacc.type.representation(), m.Parameter(0), index,
              m.Parameter(2), kNoWriteBarrier);
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
      Node* const index =
          m.Word64Shl(m.Parameter(1), m.Int64Constant(immediate_shift));
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// This list doesn't contain kIndirectPointerWriteBarrier because only indirect
// pointer fields can be stored to with that barrier kind.
static const WriteBarrierKind kWriteBarrierKinds[] = {
    kMapWriteBarrier, kPointerWriteBarrier, kEphemeronKeyWriteBarrier,
    kFullWriteBarrier};

const int32_t kStoreWithBarrierImmediates[] = {
    -256, -255, -3,   -2,   -1,   0,    1,     2,     3,     255,
    256,  264,  4096, 4104, 8192, 8200, 16384, 16392, 32752, 32760};

using InstructionSelectorStoreWithBarrierTest =
    InstructionSelectorTestWithParam<WriteBarrierKind>;

TEST_P(InstructionSelectorStoreWithBarrierTest,
       StoreWithWriteBarrierParameters) {
  const WriteBarrierKind barrier_kind = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::TaggedPointer(),
                  MachineType::Int32(), MachineType::AnyTagged());
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

TEST_P(InstructionSelectorStoreWithBarrierTest,
       StoreWithWriteBarrierImmediate) {
  const WriteBarrierKind barrier_kind = GetParam();
  TRACED_FOREACH(int32_t, index, kStoreWithBarrierImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::TaggedPointer(),
                    MachineType::AnyTagged());
    m.Store(MachineRepresentation::kTagged, m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), barrier_kind);
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorStoreWithBarrierTest,
                         ::testing::ValuesIn(kWriteBarrierKinds));

// -----------------------------------------------------------------------------
// Comparison instructions.

static const MachInst2 kComparisonInstructions[] = {
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kArm64Cmp32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Equal, "Word64Equal", kArm64Cmp,
     MachineType::Int64()},
};

using InstructionSelectorComparisonTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorComparisonTest, WithParameters) {
  const MachInst2 cmp = GetParam();
  const MachineType type = cmp.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(cmp.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kEqual, s[0]->flags_condition());
}

TEST_P(InstructionSelectorComparisonTest, WithImmediate) {
  const MachInst2 cmp = GetParam();
  const MachineType type = cmp.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    // Compare with 0 are turned into tst instruction.
    if (imm == 0) continue;
    StreamBuilder m(this, type, type);
    m.Return(
        (m.*cmp.constructor)(m.Parameter(0), BuildConstant(&m, type, imm)));
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
    m.Return(
        (m.*cmp.constructor)(BuildConstant(&m, type, imm), m.Parameter(0)));
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorComparisonTest,
                         ::testing::ValuesIn(kComparisonInstructions));

TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
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

TEST_F(InstructionSelectorTest, Word64EqualWithZero) {
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

TEST_F(InstructionSelectorTest, Word32EqualWithWord32Shift) {
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    // Skip non 32-bit shifts or ror operations.
    if (shift.mi.machine_type != MachineType::Int32() ||
        shift.mi.arch_opcode == kArm64Ror32) {
      continue;
    }

    TRACED_FORRANGE(int32_t, imm, -32, 63) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      Node* const p0 = m.Parameter(0);
      Node* const p1 = m.Parameter(1);
      Node* r = (m.*shift.mi.constructor)(p1, m.Int32Constant(imm));
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
      Node* const p0 = m.Parameter(0);
      Node* const p1 = m.Parameter(1);
      Node* r = (m.*shift.mi.constructor)(p1, m.Int32Constant(imm));
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

TEST_F(InstructionSelectorTest, Word32EqualWithUnsignedExtendByte) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r = m.Word32And(p1, m.Int32Constant(0xFF));
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r = m.Word32And(p1, m.Int32Constant(0xFF));
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

TEST_F(InstructionSelectorTest, Word32EqualWithUnsignedExtendHalfword) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r = m.Word32And(p1, m.Int32Constant(0xFFFF));
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r = m.Word32And(p1, m.Int32Constant(0xFFFF));
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

TEST_F(InstructionSelectorTest, Word32EqualWithSignedExtendByte) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r =
        m.Word32Sar(m.Word32Shl(p1, m.Int32Constant(24)), m.Int32Constant(24));
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r =
        m.Word32Sar(m.Word32Shl(p1, m.Int32Constant(24)), m.Int32Constant(24));
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

TEST_F(InstructionSelectorTest, Word32EqualWithSignedExtendHalfword) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r =
        m.Word32Sar(m.Word32Shl(p1, m.Int32Constant(16)), m.Int32Constant(16));
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* r =
        m.Word32Sar(m.Word32Shl(p1, m.Int32Constant(16)), m.Int32Constant(16));
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

TEST_F(InstructionSelectorTest, Word32EqualZeroWithWord32Equal) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
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
    {{&RawMachineAssembler::Word32Equal, "Word32Equal", kArm64Cmp32,
      MachineType::Int32()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Int32LessThan, "Int32LessThan", kArm64Cmp32,
      MachineType::Int32()},
     kSignedLessThan,
     kSignedGreaterThan},
    {{&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
      kArm64Cmp32, MachineType::Int32()},
     kSignedLessThanOrEqual,
     kSignedGreaterThanOrEqual},
    {{&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kArm64Cmp32,
      MachineType::Uint32()},
     kUnsignedLessThan,
     kUnsignedGreaterThan},
    {{&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
      kArm64Cmp32, MachineType::Uint32()},
     kUnsignedLessThanOrEqual,
     kUnsignedGreaterThanOrEqual}};

const IntegerCmp kIntegerCmpEqualityInstructions[] = {
    {{&RawMachineAssembler::Word32Equal, "Word32Equal", kArm64Cmp32,
      MachineType::Int32()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Word32NotEqual, "Word32NotEqual", kArm64Cmp32,
      MachineType::Int32()},
     kNotEqual,
     kNotEqual}};
}  // namespace

TEST_F(InstructionSelectorTest, Word32CompareNegateWithWord32Shift) {
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
        Node* const p0 = m.Parameter(0);
        Node* const p1 = m.Parameter(1);
        Node* r = (m.*shift.mi.constructor)(p1, m.Int32Constant(imm));
        m.Return(
            (m.*cmp.mi.constructor)(p0, m.Int32Sub(m.Int32Constant(0), r)));
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

TEST_F(InstructionSelectorTest, CmpWithImmediateOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpInstructions) {
    TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
      // kEqual and kNotEqual trigger the cbz/cbnz optimization, which
      // is tested elsewhere.
      if (cmp.cond == kEqual || cmp.cond == kNotEqual) continue;
      // For signed less than or equal to zero, we generate TBNZ.
      if (cmp.cond == kSignedLessThanOrEqual && imm == 0) continue;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      Node* const p0 = m.Parameter(0);
      m.Return((m.*cmp.mi.constructor)(m.Int32Constant(imm), p0));
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

TEST_F(InstructionSelectorTest, CmnWithImmediateOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpEqualityInstructions) {
    TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
      // kEqual and kNotEqual trigger the cbz/cbnz optimization, which
      // is tested elsewhere.
      if (cmp.cond == kEqual || cmp.cond == kNotEqual) continue;
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
      Node* sub = m.Int32Sub(m.Int32Constant(0), m.Parameter(0));
      m.Return((m.*cmp.mi.constructor)(m.Int32Constant(imm), sub));
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

TEST_F(InstructionSelectorTest, CmpSignedExtendByteOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* extend = m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(24)),
                               m.Int32Constant(24));
    m.Return((m.*cmp.mi.constructor)(extend, m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.commuted_cond, s[0]->flags_condition());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
  }
}

TEST_F(InstructionSelectorTest, CmnSignedExtendByteOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpEqualityInstructions) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* sub = m.Int32Sub(m.Int32Constant(0), m.Parameter(0));
    Node* extend = m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(24)),
                               m.Int32Constant(24));
    m.Return((m.*cmp.mi.constructor)(extend, sub));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.cond, s[0]->flags_condition());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
  }
}

TEST_F(InstructionSelectorTest, CmpShiftByImmediateOnLeft) {
  TRACED_FOREACH(IntegerCmp, cmp, kIntegerCmpInstructions) {
    TRACED_FOREACH(Shift, shift, kShiftInstructions) {
      // Only test relevant shifted operands.
      if (shift.mi.machine_type != MachineType::Int32()) continue;

      // The available shift operand range is `0 <= imm < 32`, but we also test
      // that immediates outside this range are handled properly (modulo-32).
      TRACED_FORRANGE(int, imm, -32, 63) {
        StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                        MachineType::Int32());
        m.Return((m.*cmp.mi.constructor)(
            (m.*shift.mi.constructor)(m.Parameter(1), m.Int32Constant(imm)),
            m.P
"""


```