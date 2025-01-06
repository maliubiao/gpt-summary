Response:
The user wants to understand the functionality of the provided C++ code snippet. This code is a part of the V8 JavaScript engine, specifically focusing on unit tests for the instruction selector on the RISC-V 64-bit architecture.

Here's a breakdown of the thought process to analyze the code and fulfill the request:

1. **Identify the core purpose:** The filename and the `TEST_F` and `TEST_P` macros immediately suggest that this is a unit test file. The path `v8/test/unittests/compiler/riscv64/` confirms it's testing the compiler for the RISC-V 64-bit architecture. The name `instruction-selector-riscv64-unittest.cc` pinpoints the component being tested: the instruction selector.

2. **Understand the testing methodology:** The code uses Google Test (`EXPECT_EQ`, `ASSERT_EQ`). The `StreamBuilder` and `Stream` classes are V8-specific utilities for generating and inspecting instruction sequences. The tests appear to simulate various operations (loads, stores, arithmetic, etc.) and then verify that the instruction selector generates the expected RISC-V instructions.

3. **Analyze individual test cases:**  Go through each `TEST_F` and `TEST_P` block and understand what it's testing.

    * **`InstructionSelectorElidedChangeUint32ToUint64Test`:** This suite seems to be checking if the instruction selector can optimize away unnecessary `ChangeUint32ToUint64` operations. The first test checks the case where the input is a parameter. The second test checks the case where the result of a binary operation is converted. The use of `kCanElideChangeUint32ToUint64` indicates a set of binary operations that are expected to allow this optimization.

    * **`ChangeUint32ToUint64AfterLoad`:** This test checks if the `ChangeUint32ToUint64` operation is correctly handled when it follows a load instruction (Lbu, Lhu, Lwu). It appears that in some cases, the load instruction itself can perform the zero-extension, making the explicit conversion unnecessary.

    * **Memory Access Tests (`InstructionSelectorMemoryAccessTest`, `InstructionSelectorMemoryAccessImmTest`, etc.):** These tests focus on verifying the correct generation of load and store instructions for different data types and addressing modes (with and without immediate offsets). The `kMemoryAccesses` array defines the data types and their corresponding load/store opcodes. The `kMemoryAccessesImm` arrays test loads and stores with various immediate offsets, checking if they fall within the allowed range for direct addressing. The `kMemoryAccessImmMoreThan16bit` tests scenarios where the immediate offset is larger, potentially requiring additional instructions to load the address. The `#ifdef RISCV_HAS_NO_UNALIGNED` blocks deal with testing unaligned memory access if the target architecture doesn't support it natively.

    * **`Word32EqualWithZero`, `Word64EqualWithZero`:** These tests verify that comparisons with zero are translated into the specific `kRiscvCmpZero32` and `kRiscvCmpZero` instructions, which are more efficient.

    * **`Word32Clz`, `Word64Clz`:** These check the generation of the "count leading zeros" instructions.

    * **`Float32Abs`, `Float64Abs`, `Float64Max`, `Float64Min`:** These test the generation of floating-point absolute value, maximum, and minimum instructions.

    * **`LoadAndShiftRight`:** This test checks that a load followed by a shift-right operation isn't incorrectly optimized into a single instruction, particularly focusing on the immediate offset in the load.

    * **`Word32ReverseBytes`, `Word64ReverseBytes`:** These tests verify the generation of byte-swapping instructions. The conditional logic based on `CpuFeatures::IsSupported(ZBB)` suggests that different instructions might be used depending on the availability of the Zbb extension.

    * **`ExternalReferenceLoad1`, `ExternalReferenceLoad2`:** These tests check how the instruction selector handles loading from external references. The `kMode_Root` addressing mode is specific to accessing data relative to the isolate root. The tests check the cases where the offset is within the allowed range for `kMode_Root` and where it's too large.

4. **Relate to JavaScript (if applicable):** Consider how the tested operations relate to JavaScript. For instance:

    * `ChangeUint32ToUint64`:  JavaScript numbers can be represented as 64-bit floats or sometimes as 32-bit integers. When a 32-bit unsigned integer needs to be used in a context requiring a 64-bit value, this conversion occurs.
    * Loads and Stores:  Accessing object properties, array elements, and variables all involve memory loads and stores.
    * Arithmetic operations: Basic JavaScript operators like `+`, `-`, `*`, `/`, `&`, `|`, `^`, `<<`, `>>`, `>>>` will map to corresponding machine instructions.
    * Comparisons:  `==`, `!=`, `<`, `>`, `<=`, `>=` translate into comparison instructions.
    * Bitwise operations: `~`, `&`, `|`, `^`, `<<`, `>>`, `>>>` have direct counterparts in machine code.
    * Floating-point operations: Operations on JavaScript `Number` values use floating-point instructions.

5. **Illustrate with JavaScript examples:** Create simple JavaScript snippets that would likely trigger the tested code paths.

6. **Infer code logic and provide input/output examples:**  For tests with clear logic (like the zero-comparison tests), provide hypothetical inputs and the expected flags or output.

7. **Identify potential programming errors:** Think about common mistakes developers make that could lead to the scenarios being tested. For example, incorrect type conversions, assuming a variable's size, or issues with endianness.

8. **Synthesize the functionality summary:** Combine the understanding gained from the individual tests into a concise description of the file's purpose. Emphasize that it's testing the correctness of the instruction selection process for various operations on the RISC-V 64-bit architecture.

By following these steps, one can effectively analyze the C++ code snippet and address all parts of the user's request.
This C++ code snippet is a unit test file for the instruction selector component of the V8 JavaScript engine, specifically targeting the RISC-V 64-bit architecture. Here's a breakdown of its functionality based on the provided code:

**Core Functionality:**

This test file aims to verify that the V8 compiler's instruction selector correctly translates high-level intermediate representations (IR) of operations into the appropriate RISC-V 64-bit machine instructions. It does this by:

1. **Building IR:**  Using the `StreamBuilder` class, the tests construct small sequences of IR nodes representing various operations (e.g., addition, loading, storing, bitwise operations, comparisons).
2. **Running Instruction Selection:** The `Build()` method on the `StreamBuilder` implicitly triggers the instruction selection process for the generated IR.
3. **Verifying Output:** The tests then use assertions (`ASSERT_EQ`, `EXPECT_EQ`) to examine the resulting sequence of machine instructions (`Stream s`). They check:
    * **Opcode:** The specific RISC-V instruction selected (e.g., `kRiscvAdd64`, `kRiscvLd`, `kRiscvSw`).
    * **Addressing Mode:** The addressing mode used by the instruction (e.g., `kMode_MRI` for memory access with register and immediate offset, `kMode_None` for register-to-register operations).
    * **Input and Output Counts:** The number of input and output operands for the instruction.
    * **Operand Types and Values:** The types of the operands (register, immediate) and, in some cases, their specific values.
    * **Flags:**  For comparison instructions, it checks the flags set and the condition code.

**Specific Functionalities Demonstrated in the Snippet:**

* **Eliding `ChangeUint32ToUint64`:**  It tests scenarios where an explicit conversion from a 32-bit unsigned integer to a 64-bit unsigned integer can be optimized away by the instruction selector. This often happens when the subsequent operation naturally handles 32-bit values correctly within a 64-bit context.
* **Handling `ChangeUint32ToUint64` after Loads:** It checks that when a 32-bit value is loaded from memory and then converted to 64-bit, the correct load instruction (e.g., `kRiscvLbu`, `kRiscvLhu`, `kRiscvLwu`) is used, potentially followed by a zero-extension instruction (`kRiscvZeroExtendWord`) if the load doesn't implicitly perform the extension.
* **Loads and Stores:**  It comprehensively tests the generation of load and store instructions (`kRiscvLb`, `kRiscvLbu`, `kRiscvLh`, `kRiscvLhu`, `kRiscvLw`, `kRiscvSw`, `kRiscvLd`, `kRiscvSd`, `kRiscvLoadFloat`, `kRiscvStoreFloat`, `kRiscvLoadDouble`, `kRiscvStoreDouble`) for various data types (`MachineType`).
* **Loads and Stores with Immediate Offsets:** It tests loads and stores with different immediate offsets, verifying that the instruction selector correctly handles offsets within the immediate range of the instructions. It also tests cases where the immediate offset is larger than the direct range, which might require additional instructions.
* **Unaligned Memory Access (Conditional):** If the RISC-V architecture doesn't support unaligned access (`RISCV_HAS_NO_UNALIGNED`), it tests the generation of alternative instruction sequences for unaligned stores.
* **Comparisons with Zero:** It verifies that comparisons of integer values with zero are translated into specific optimized instructions (`kRiscvCmpZero32`, `kRiscvCmpZero`).
* **Bit Manipulation Operations:** It tests the selection of instructions for counting leading zeros (`kRiscvClz32`, `kRiscvClz64`) and reversing byte order (`kRiscvByteSwap32`, `kRiscvByteSwap64`, potentially using `kRiscvRev8` with the Zbb extension).
* **Floating-Point Operations:** It checks the generation of instructions for floating-point absolute value (`kRiscvAbsS`, `kRiscvAbsD`), maximum (`kRiscvFloat64Max`), and minimum (`kRiscvFloat64Min`).
* **Load followed by Shift Right:** It ensures that a load operation followed by a shift-right operation is not incorrectly folded into a single instruction when it shouldn't be.
* **Loading from External References:** It tests loading values from external references, verifying the use of the `kMode_Root` addressing mode when the offset is within a certain range and a different mode when it's not.

**Relationship to JavaScript and Examples:**

Yes, this code directly relates to the performance and correctness of JavaScript execution on RISC-V 64-bit. The instruction selector is a crucial part of the compilation pipeline that translates JavaScript code into efficient machine instructions. Here are some JavaScript examples that could trigger the tested scenarios:

* **Eliding `ChangeUint32ToUint64`:**
   ```javascript
   function addUnsigned32(a, b) {
     return (a >>> 0) + (b >>> 0); // Unsigned right shift ensures 32-bit unsigned
   }
   ```
   The internal representation of `a` and `b` might be 32-bit unsigned, and the addition result might be directly usable in a 64-bit context without an explicit conversion instruction.

* **`ChangeUint32ToUint64` after Loads:**
   ```javascript
   const buffer = new Uint8Array([10, 20, 30, 40]);
   const value = buffer[2]; // value will be a 32-bit unsigned integer
   const bigValue = value; // Implicit conversion to potentially a 64-bit representation
   ```
   Loading from a `Uint8Array` results in a 32-bit unsigned value, which might need to be extended to 64-bit in certain operations.

* **Loads and Stores:**
   ```javascript
   const obj = { x: 10 };
   const y = obj.x; // Load
   obj.x = 20;     // Store

   const arr = [1, 2, 3];
   const val = arr[1]; // Load
   arr[1] = 4;        // Store
   ```
   Accessing object properties and array elements involves memory loads and stores.

* **Loads and Stores with Immediate Offsets:**
   ```javascript
   function accessArray(arr, index) {
     return arr[index + 5]; // Immediate offset of 5
   }
   ```
   Accessing array elements with a constant offset translates to memory access with an immediate offset.

* **Comparisons with Zero:**
   ```javascript
   function isZero(x) {
     return x == 0;
   }
   ```
   Comparing a value with zero can be optimized at the instruction level.

* **Bit Manipulation Operations:**
   ```javascript
   function countLeadingZeros(x) {
     return Math.clz32(x);
   }

   function reverseBytes(x) {
     return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >>> 8) | ((x >>> 24) & 0xFF);
   }
   ```
   JavaScript's bitwise operators and `Math.clz32` map to corresponding machine instructions.

* **Floating-Point Operations:**
   ```javascript
   const absValue = Math.abs(-3.14);
   const maxValue = Math.max(1.5, 2.7);
   ```
   Mathematical operations on floating-point numbers utilize floating-point instructions.

**Code Logic Inference with Hypothetical Input and Output:**

Let's take the `Word32EqualWithZero` test as an example:

**Hypothetical Input (IR):**
An IR node representing a 32-bit equality comparison between a parameter and the constant 0.

**Assumptions:**
* The parameter is a 32-bit integer value.

**Expected Output (RISC-V Instructions):**
One instruction: `kRiscvCmpZero32`

**Instruction Details:**
* `arch_opcode()`: `kRiscvCmpZero32`
* `addressing_mode()`: `kMode_None`
* `InputCount()`: 1 (the parameter being compared)
* `OutputCount()`: 1 (implicitly sets flags)
* `flags_mode()`: `kFlags_set`
* `flags_condition()`: `kEqual`

**User-Common Programming Errors:**

* **Incorrect Type Assumptions:**  Assuming a variable is always a 32-bit integer when it might be a 64-bit float internally, leading to unexpected behavior if optimizations rely on the 32-bit assumption.
* **Manual Type Conversions:**  Performing unnecessary manual type conversions (e.g., using bitwise operations to force a 32-bit view) when the underlying system could handle it more efficiently. The instruction selector aims to optimize these situations.
* **Endianness Issues:** While the tests cover byte swapping, developers might make errors when dealing with binary data and not correctly accounting for the endianness of the target architecture.
* **Off-by-One Errors in Array Access:** Incorrectly calculating array indices, even with simple immediate offsets, can lead to memory access errors. The tests with immediate offsets help ensure that the compiler correctly handles these cases.

**Summary of Functionality (Part 2):**

This second part of the unit test file for the RISC-V 64-bit instruction selector focuses on verifying the correct generation of machine instructions for:

* **Optimizations related to `ChangeUint32ToUint64` operations.**
* **Loading and storing various data types from memory, including handling of immediate offsets (within and beyond the direct range).**
* **Optimized comparison instructions with zero.**
* **Bit manipulation operations (counting leading zeros, byte swapping).**
* **Floating-point arithmetic operations.**
* **Scenarios involving a load operation followed by a shift-right operation.**
* **Loading data from external references with appropriate addressing modes.**

Essentially, it tests a wide range of common operations and memory access patterns to ensure that the V8 compiler generates correct and efficient RISC-V 64-bit assembly code for these scenarios.

Prompt: 
```
这是目录为v8/test/unittests/compiler/riscv64/instruction-selector-riscv64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/riscv64/instruction-selector-riscv64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
);
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
}

using InstructionSelectorElidedChangeUint32ToUint64Test =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorElidedChangeUint32ToUint64Test, Parameter) {
  const MachInst2 binop = GetParam();
  StreamBuilder m(this, MachineType::Uint64(), binop.machine_type,
                  binop.machine_type);
  m.Return(m.ChangeUint32ToUint64(
      (m.*binop.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  // Make sure the `ChangeUint32ToUint64` node turned into two op(sli 32 and sri
  // 32).
  ASSERT_EQ(2U, s.size());
  EXPECT_EQ(binop.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorElidedChangeUint32ToUint64Test,
                         ::testing::ValuesIn(kCanElideChangeUint32ToUint64));

TEST_F(InstructionSelectorTest, ChangeUint32ToUint64AfterLoad) {
  // For each case, make sure the `ChangeUint32ToUint64` node turned into a
  // no-op.

  // Lbu
  {
    StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer(),
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
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
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
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
                    MachineType::Int32());
    m.Return(m.ChangeUint32ToUint64(
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
  bool (InstructionSelectorTest::Stream::*val_predicate)(
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
  bool (InstructionSelectorTest::Stream::*val_predicate)(
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
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};

const MemoryAccessImm1 kMemoryAccessImmMoreThan16bit[] = {
    {MachineType::Int8(),
     kRiscvLb,
     kRiscvSb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint8(),
     kRiscvLbu,
     kRiscvSb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int16(),
     kRiscvLh,
     kRiscvSh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Uint16(),
     kRiscvLhu,
     kRiscvSh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int32(),
     kRiscvLw,
     kRiscvSw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float32(),
     kRiscvLoadFloat,
     kRiscvStoreFloat,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Float64(),
     kRiscvLoadDouble,
     kRiscvStoreDouble,
     &InstructionSelectorTest::Stream::IsDouble,
     {-65000, -55000, 32777, 55000, 65000}},
    {MachineType::Int64(),
     kRiscvLd,
     kRiscvSd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-65000, -55000, 32777, 55000, 65000}}};

#ifdef RISCV_HAS_NO_UNALIGNED
struct MemoryAccessImm2 {
  MachineType type;
  ArchOpcode store_opcode;
  ArchOpcode store_opcode_unaligned;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
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
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int32(),
     kRiscvUsw,
     kRiscvSw,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Int64(),
     kRiscvUsd,
     kRiscvSd,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float32(),
     kRiscvUStoreFloat,
     kRiscvStoreFloat,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}},
    {MachineType::Float64(),
     kRiscvUStoreDouble,
     kRiscvStoreDouble,
     &InstructionSelectorTest::Stream::IsDouble,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91,
      -89,   -87,   -86,   -82,   -44,   -23,   -3,    0,    7,    10,
      39,    52,    69,    71,    91,    92,    107,   109,  115,  124,
      286,   655,   1362,  1569,  2587,  3067,  3096,  3462, 3510, 4095}}};
#endif
}  // namespace

using InstructionSelectorMemoryAccessTest =
    InstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.load_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

TEST_P(InstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                  MachineType::Int32(), memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Parameter(1),
          kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

// ----------------------------------------------------------------------------
// Load immediate.
// ----------------------------------------------------------------------------

using InstructionSelectorMemoryAccessImmTest =
    InstructionSelectorTestWithParam<MemoryAccessImm>;

TEST_P(InstructionSelectorMemoryAccessImmTest, LoadWithImmediateIndex) {
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

TEST_P(InstructionSelectorMemoryAccessImmTest, StoreWithImmediateIndex) {
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

TEST_P(InstructionSelectorMemoryAccessImmTest, StoreZero) {
  const MemoryAccessImm memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer());
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Int32Constant(0), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.store_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(0)->kind());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(0)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImm));

#ifdef RISCV_HAS_NO_UNALIGNED
using InstructionSelectorMemoryAccessUnalignedImmTest =
    InstructionSelectorTestWithParam<MemoryAccessImm2>;

TEST_P(InstructionSelectorMemoryAccessUnalignedImmTest, StoreZero) {
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessUnalignedImmTest,
                         ::testing::ValuesIn(kMemoryAccessesImmUnaligned));
#endif
// ----------------------------------------------------------------------------
// Load/store offsets more than 16 bits.
// ----------------------------------------------------------------------------

using InstructionSelectorMemoryAccessImmMoreThan16bitTest =
    InstructionSelectorTestWithParam<MemoryAccessImm1>;

TEST_P(InstructionSelectorMemoryAccessImmMoreThan16bitTest,
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

TEST_P(InstructionSelectorMemoryAccessImmMoreThan16bitTest,
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessImmMoreThan16bitTest,
                         ::testing::ValuesIn(kMemoryAccessImmMoreThan16bit));

// ----------------------------------------------------------------------------
// kRiscvCmp with zero testing.
// ----------------------------------------------------------------------------

TEST_F(InstructionSelectorTest, Word32EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Equal(m.Parameter(0), m.Int32Constant(0)));
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
    m.Return(m.Word32Equal(m.Int32Constant(0), m.Parameter(0)));
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

TEST_F(InstructionSelectorTest, Word64EqualWithZero) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Equal(m.Parameter(0), m.Int64Constant(0)));
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
    m.Return(m.Word64Equal(m.Int64Constant(0), m.Parameter(0)));
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

TEST_F(InstructionSelectorTest, Word32Clz) {
  StreamBuilder m(this, MachineType::Uint32(), MachineType::Uint32());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word32Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kRiscvClz32, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, Word64Clz) {
  StreamBuilder m(this, MachineType::Uint64(), MachineType::Uint64());
  Node* const p0 = m.Parameter(0);
  Node* const n = m.Word64Clz(p0);
  m.Return(n);
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kRiscvClz64, s[0]->arch_opcode());
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
  EXPECT_EQ(kRiscvAbsS, s[0]->arch_opcode());
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
  EXPECT_EQ(kRiscvAbsD, s[0]->arch_opcode());
  ASSERT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
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
  EXPECT_EQ(kRiscvFloat64Max, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
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
  EXPECT_EQ(kRiscvFloat64Min, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(n), s.ToVreg(s[0]->Output()));
}

TEST_F(InstructionSelectorTest, LoadAndShiftRight) {
  {
    int32_t immediates[] = {-256, -255, -3,   -2,   -1,    0,    1,
                            2,    3,    255,  256,  260,   4096, 4100,
                            8192, 8196, 3276, 3280, 16376, 16380};
    TRACED_FOREACH(int32_t, index, immediates) {
      StreamBuilder m(this, MachineType::Uint64(), MachineType::Pointer());
      Node* const load =
          m.Load(MachineType::Uint64(), m.Parameter(0), m.Int32Constant(index));
      Node* const sar = m.Word64Sar(load, m.Int32Constant(32));
      // Make sure we don't fold the shift into the following add:
      m.Return(m.Int64Add(sar, m.Parameter(0)));
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

TEST_F(InstructionSelectorTest, Word32ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    if (CpuFeatures::IsSupported(ZBB)) {
      ASSERT_EQ(2U, s.size());
      EXPECT_EQ(kRiscvRev8, s[0]->arch_opcode());
      EXPECT_EQ(kRiscvShr64, s[1]->arch_opcode());
      EXPECT_EQ(1U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
    } else {
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kRiscvByteSwap32, s[0]->arch_opcode());
      EXPECT_EQ(1U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(InstructionSelectorTest, Word64ReverseBytes) {
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64ReverseBytes(m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    if (CpuFeatures::IsSupported(ZBB)) {
      EXPECT_EQ(kRiscvRev8, s[0]->arch_opcode());
    } else {
      EXPECT_EQ(kRiscvByteSwap64, s[0]->arch_opcode());
    }
    EXPECT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
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
    EXPECT_EQ(kRiscvLd, s[0]->arch_opcode());
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
  EXPECT_EQ(kRiscvLd, s[0]->arch_opcode());
  EXPECT_NE(kMode_Root, s[0]->addressing_mode());
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```