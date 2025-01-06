Response:
Let's break down the thought process for analyzing this V8 Turboshaft unit test file.

1. **Understanding the Goal:** The first step is to recognize that this is a unit test file for the instruction selector in V8's Turboshaft compiler, specifically targeting the ARM64 architecture. Unit tests verify the correct behavior of individual components. In this case, it's verifying that the instruction selector chooses the correct ARM64 instructions for certain operations.

2. **File Naming Convention:** The filename `turboshaft-instruction-selector-arm64-unittest.cc` gives crucial information:
    * `turboshaft`:  Indicates the compiler pipeline being tested.
    * `instruction-selector`: Points to the specific component under test.
    * `arm64`: Specifies the target architecture.
    * `unittest`: Clearly labels it as a unit test file.
    * `.cc`:  Indicates a C++ source file. The prompt explicitly checks for `.tq`, which would signify a Torque file. Since it's `.cc`, we know it's C++.

3. **High-Level Structure:**  Unit test files typically follow a pattern:
    * **Includes:** Necessary header files to access testing frameworks and the code being tested. (Though not shown in the provided snippet, we'd expect includes).
    * **Test Fixtures:**  Classes that set up the environment for the tests (like `TurboshaftInstructionSelectorTest`). They often inherit from a base testing class.
    * **Individual Test Cases:** Functions (using macros like `TEST_F` or `TEST_P`) that exercise specific functionalities. Each test aims to verify one particular aspect of the instruction selector.

4. **Analyzing Individual Test Cases:** The core of the analysis involves examining the code within each `TEST_F`. The general structure of a test case here is:
    * **Setup (`StreamBuilder m(...)`)**:  Creates a `StreamBuilder` object. This likely represents a sequence of intermediate representation (IR) instructions that the instruction selector will process. The parameters to `StreamBuilder` hint at the input and output types of the operation being tested.
    * **Operation Under Test (`m.Return(m.ChangeInt32ToInt64(m.Load(...)))`)**: This part constructs the IR representing the computation. It's crucial to understand the V8 IR node names (e.g., `ChangeInt32ToInt64`, `Load`, `Word32ShiftRightArithmetic`).
    * **Building the Stream (`Stream s = m.Build();`)**: This triggers the instruction selection process. The `Stream` object likely holds the resulting sequence of selected ARM64 instructions.
    * **Assertions (`ASSERT_EQ(...)`, `EXPECT_EQ(...)`)**: These are the core of the verification. They check that the generated ARM64 instructions match the expectations. We look for checks on:
        * `s.size()`: The number of instructions generated.
        * `s[0]->arch_opcode()`: The specific ARM64 instruction opcode (e.g., `kArm64Ldrb`, `kArm64Sbfx`).
        * `s[0]->addressing_mode()`: The addressing mode used for memory access.
        * `s[0]->InputCount()`, `s[0]->OutputCount()`: The number of input and output operands.
        * `s.ToInt32(s[0]->InputAt(1))`, etc.: The values of immediate operands.

5. **Identifying Functionality by Grouping Tests:**  Notice how the tests are named and grouped (e.g., tests for `ChangeInt32ToInt64` with different input types, tests for memory access, tests for comparisons). This grouping helps understand the file's overall scope.

6. **Relating to JavaScript (if applicable):** The prompt asks if the code relates to JavaScript. Instruction selection is a crucial part of compiling JavaScript to machine code. We can think of how JavaScript operations might be lowered to the IR nodes being tested. For example, a JavaScript `+` operation on integers might involve an `Add` IR node.

7. **Code Logic Reasoning (with assumptions):** When there's more complex logic (like the `Word64SarWithChangeInt32ToInt64` test with the `if` condition), we need to deduce the expected behavior based on the code. We can make assumptions about compiler optimizations. In that case, the optimization of combining `ChangeInt32ToInt64` and `Word64ShiftRightArithmetic` only happens for a specific range of immediate values.

8. **Common Programming Errors:** The tests involving type conversions (like `ChangeInt32ToInt64`) hint at potential JavaScript errors where type mismatches might occur. Memory access tests highlight risks of accessing memory at incorrect offsets or with incorrect data types.

9. **Synthesizing the Summary:**  Finally, we synthesize the observations into a concise summary, covering the key functionalities, the testing approach, and any connections to JavaScript or common errors. The fact that the prompt says "This is part 5 of 8" suggests we should also consider what broader context this piece fits into within the overall instruction selection testing. It's focusing on specific instruction patterns and optimizations.

**Self-Correction/Refinement During Analysis:**

* **Initial Guess about `.tq`:**  The prompt intentionally includes a distractor about `.tq` files. We need to correctly identify that this is a `.cc` file and therefore C++.
* **Understanding IR Node Names:**  If unfamiliar with V8's IR, some research or looking at related V8 code might be needed to understand what operations like `ChangeInt32ToInt64` or `Word32ShiftRightArithmetic` actually do.
* **Interpreting Assembly Opcodes:** Knowing the ARM64 assembly instructions (`kArm64Ldrb`, `kArm64Sbfx`, etc.) is important for understanding what the tests are verifying. If these are unfamiliar, looking up ARM64 instruction set documentation would be helpful.
* **Connecting IR to Assembly:** The core task is to understand how the instruction selector translates the high-level IR operations into specific machine instructions. This requires some understanding of compiler principles.

By following this structured analysis, we can effectively understand the purpose and functionality of this V8 unit test file.
好的，这是对提供的V8源代码片段的功能进行分析：

**文件功能概述:**

这个C++源代码文件 `v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc` 是 V8 JavaScript 引擎中 Turboshaft 编译器框架下，针对 ARM64 架构的指令选择器（instruction selector）的单元测试。

**具体功能拆解:**

该文件中的测试用例主要验证了指令选择器在处理特定中间表示（IR）操作时，能否正确地选择出期望的 ARM64 汇编指令。涵盖了以下几个方面的功能：

1. **类型转换指令 (`ChangeInt32ToInt64`):**
   - 验证将 32 位整数转换为 64 位整数的不同场景，特别是与加载指令（`Load`）结合时，指令选择器是否选择了正确的带符号或无符号扩展的加载指令 (`Ldrb`, `Ldrsb`, `Ldrh`, `Ldrsh`, `Ldrsw`)。
   - 验证了将 32 位整数转换为 64 位整数后再进行算术右移（`Word32ShiftRightArithmetic`）时，指令选择器选择了 `Sbfx` 指令。
   - 验证了对已转换为 64 位整数的值进行 64 位算术右移 (`Word64ShiftRightArithmetic`)，并在特定立即数范围内的优化，使用了 `Sbfx` 指令，否则使用了 `Sxtw` 和 `Asr` 指令。

2. **内存访问指令 (`Load`, `Store`):**
   - 针对不同大小和类型的内存访问（`Int8`, `Uint8`, `Int16`, `Uint16`, `Int32`, `Uint32`, `Int64`, `Uint64`, `Float32`, `Float64`），测试了 `Load` 和 `Store` 操作在以下情况下的指令选择：
     - 使用寄存器作为偏移量 (`kMode_MRR`)。
     - 使用立即数作为偏移量 (`kMode_MRI`)，并验证了立即数的正确传递。
     - 存储零值时，直接将零值作为立即数编码到指令中。
     - 使用左移后的寄存器作为偏移量 (`kMode_Operand2_R_LSL_I`)，并验证了只有当左移量等于元素大小的对数时才会进行优化合并。
   - 测试了带有写屏障（Write Barrier）的存储操作 (`kArchStoreWithWriteBarrier`)，用于保证垃圾回收的正确性。

3. **比较指令 (`Word32Equal`, `Word64Equal`):**
   - 验证了基本的 32 位和 64 位相等比较操作 (`Cmp32`, `Cmp`)，包括使用寄存器和立即数进行比较。
   - 验证了与零比较的优化，使用了 `Tst32` 和 `Tst` 指令。
   - 验证了与移位操作结果比较的场景，指令选择器能否正确选择带有移位操作数的比较指令。
   - 验证了与零扩展和符号扩展操作结果比较的场景，指令选择器能否正确选择带有扩展操作数的比较指令。
   - 验证了比较结果与零比较的场景，指令选择器能否正确设置条件码。

**关于文件类型和 JavaScript 关系:**

- 该文件以 `.cc` 结尾，因此是 **C++ 源代码**，而不是 Torque 源代码。
- 该文件与 JavaScript 的功能有密切关系。指令选择器是编译器的一部分，负责将 JavaScript 代码编译成机器码。这些单元测试确保了当 JavaScript 代码执行各种操作时，Turboshaft 编译器能够为 ARM64 架构生成正确的、高效的机器指令。

**JavaScript 举例 (与部分功能相关):**

```javascript
function test(arr, index) {
  // 类型转换和加载
  const val8 = arr[index]; // 可能会对应 Load_Uint8 或 Load_Int8
  const val64 = val8;      // 可能会对应 ChangeInt32ToInt64 (如果 val8 被视为 32 位)

  // 内存存储
  arr[index + 1] = 10;   // 可能会对应 Store 操作

  // 比较
  if (arr[index] === 5) { // 可能会对应 Word32Equal 或 Word64Equal
    return true;
  }
  return false;
}
```

**代码逻辑推理 (假设输入与输出):**

**示例 1: `ChangeInt32ToInt64(Load_Uint8)` 测试**

* **假设输入:**  一个指向包含无符号 8 位整数的内存地址的指针，偏移量为 0。
* **IR 操作:**  先执行 `Load(Uint8, pointer, 0)` 加载无符号 8 位整数，然后执行 `ChangeInt32ToInt64` 将加载的结果转换为 64 位整数。
* **预期输出 (ARM64 指令):**  `ldrb  <destination_register>, [<base_register>]`  (假设偏移量为 0 可以简化为这种形式)

**示例 2: `Word32EqualWithWord32Shift` 测试**

* **假设输入:** 两个 32 位整数 `a` 和 `b`，移位量为 2。
* **IR 操作:**  先执行 `Word32ShiftLeft(b, 2)`，然后执行 `Word32Equal(a, shift_result)`。
* **预期输出 (ARM64 指令):** `cmp  <register_a>, <register_b>, lsl #2`

**用户常见的编程错误 (涉及的功能):**

1. **类型不匹配:** 在 JavaScript 中，如果对不同类型的变量进行操作，可能会触发类似的类型转换。例如，将一个小的整数赋值给一个需要 64 位整数的上下文，编译器就需要生成类型转换指令。用户可能无意中导致了大量的类型转换，影响性能。

   ```javascript
   let smallInt = 10;
   let bigIntArray = new BigInt64Array(1);
   bigIntArray[0] = smallInt; // 隐式将 smallInt 转换为 BigInt
   ```

2. **错误的内存访问:**  在 C/C++ 中，或者在理解 JavaScript 底层原理时，错误的指针运算或索引可能导致访问到错误的内存位置。指令选择器为 `Load` 和 `Store` 生成指令，但如果上层的逻辑有误，仍然会导致运行时错误。

   ```javascript
   function accessArray(arr, index) {
     return arr[index + 1000]; // 如果 index 过大，可能超出数组边界
   }
   ```

3. **比较时的类型混淆:**  在 JavaScript 中，`==` 和 `===` 的行为有所不同。使用 `==` 可能导致隐式类型转换，而 `===` 不会。理解比较操作的底层指令，可以帮助开发者避免因类型混淆导致的逻辑错误。

   ```javascript
   if (5 == "5") { // true，因为会进行类型转换
     // ...
   }

   if (5 === "5") { // false
     // ...
   }
   ```

**归纳总结 (第 5 部分功能):**

这部分单元测试主要关注指令选择器在处理 **类型转换 (特别是 32 位到 64 位整数的转换)、基本的内存访问 (加载和存储不同类型的数据) 以及简单的整数比较操作** 时的行为。它验证了指令选择器能够针对这些常见的操作生成正确的、可能经过优化的 ARM64 指令，包括利用立即数寻址、寄存器移位寻址以及带有符号/无符号扩展的加载指令。这些测试是确保 Turboshaft 编译器在 ARM64 架构上生成正确高效代码的关键组成部分。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能

"""
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
  FlagsCondition co
"""


```