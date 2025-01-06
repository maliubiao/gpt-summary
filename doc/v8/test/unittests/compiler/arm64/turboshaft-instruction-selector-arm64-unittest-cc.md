Response:
The user wants a summary of the functionality of the provided C++ code. The code is a unit test file for the Turboshaft instruction selector on the ARM64 architecture within the V8 JavaScript engine.

Here's a breakdown of the code's structure and purpose:

1. **Includes and Namespace:** The code includes necessary V8 headers and declares itself within the `v8::internal::compiler::turboshaft` namespace.

2. **Helper Structs and Operators:**
   - `MachInst`: Represents a machine instruction with its operation, constructor name, architecture opcode, and machine type.
   - Overloaded `operator<<` for `MachInst` and `Shift`: Makes printing these structs easier for debugging.
   - `Shift`:  Combines a `MachInst2` (binary operation instruction) with an `AddressingMode`.

3. **`BuildConstant` Helper Function:** Creates either an `Int32Constant` or `Int64Constant` operation based on the provided `MachineType`.

4. **Constant Arrays for Instructions:** The code defines several constant arrays of `MachInst` or related structs, representing various ARM64 instructions:
   - `kLogicalInstructions`: Logical bitwise operations (AND, OR, XOR).
   - `kLogical32Immediates`, `kLogical64Immediates`:  Sets of valid immediate values for logical instructions.
   - `kAddSubInstructions`: Addition and subtraction.
   - `kAddSubImmediates`: Valid immediate values for addition and subtraction.
   - `kDPFlagSetInstructions`: Data processing instructions that set flags (like comparisons).
   - `kOvfAddSubInstructions`: Addition and subtraction with overflow checks.
   - `kShiftInstructions`: Shift and rotate operations.
   - `kMulDivInstructions`: Multiplication and division.
   - `kFPArithInstructions`: Floating-point arithmetic.
   - `kFPCmpInstructions`: Floating-point comparison.
   - `kConversionInstructions`: Type conversion instructions.
   - `kCanElideChangeUint32ToUint64`, `kCanElideChangeUint32ToUint64MultiOutput`: Instructions where a `ChangeUint32ToUint64` operation can be optimized away.

5. **Test Fixtures and Test Cases:**
   - The code uses Google Test framework (`TEST_P`, `TEST_F`, `INSTANTIATE_TEST_SUITE_P`).
   - It defines test fixtures (classes inheriting from `TurboshaftInstructionSelectorTestWithParam` or `TurboshaftInstructionSelectorTest`) to group related tests.
   - Each `TEST_P` or `TEST_F` represents a specific test case. These tests generally:
     - Create a `StreamBuilder` to construct a sequence of Turboshaft operations.
     - Emit a specific operation (e.g., `Word32BitwiseAnd`, `Word64Add`).
     - Build the stream of operations.
     - Assertions (`ASSERT_EQ`, `EXPECT_EQ`, `EXPECT_TRUE`) are used to verify the generated machine code (e.g., the correct opcode, number of inputs/outputs, immediate values).

6. **`SignExtendAndEmit` Helper Function:**  Used to handle potential sign extension when emitting binary operations.

**Overall Functionality:**

The primary function of this code is to **test the correct selection of ARM64 machine instructions by the Turboshaft instruction selector** for various Turboshaft intermediate representation (IR) operations. It verifies that for a given Turboshaft operation, the instruction selector produces the expected ARM64 machine instruction with the correct operands and addressing modes.

**Relation to Javascript:**

While this C++ code directly tests the compiler internals, it is indirectly related to JavaScript. The Turboshaft compiler is responsible for taking JavaScript code and translating it into efficient machine code that can be executed by the processor. This unit test ensures that the ARM64 backend of the Turboshaft compiler is functioning correctly. For example, when the JavaScript code performs a bitwise AND operation, this test verifies that the compiler selects the correct ARM64 AND instruction.

**Hypothetical Input and Output (Code Logic Inference):**

Consider the `TurboshaftInstructionSelectorLogicalTest` with the `Word32BitwiseAnd` instruction:

**Hypothetical Input (Turboshaft IR):**
```
%param0 = Parameter [Type: Int32]
%param1 = Parameter [Type: Int32]
%and_result = Word32BitwiseAnd %param0, %param1
Return %and_result
```

**Expected Output (ARM64 Machine Instruction):**
```assembly
and w0, w0, w1  // Assuming parameters are in registers w0 and w1
```
The test verifies that the `arch_opcode` of the selected instruction is `kArm64And32`.

**Common Programming Errors (Indirectly Related):**

While this test code doesn't directly catch user programming errors, it ensures that the *compiler* correctly handles bitwise operations. A common user error related to bitwise operations might be misunderstanding the behavior of AND, OR, and XOR, leading to incorrect results in their JavaScript code. This unit test helps ensure that if a user *correctly* uses bitwise operators in JavaScript, the compiler will generate the intended machine code.

**Summary of Functionality (for Part 1):**

This C++ code defines structures and data to facilitate unit testing of the Turboshaft instruction selector for ARM64. It focuses on verifying the correct selection of basic arithmetic, logical, and shift instructions, including handling of immediate values and different operand types. The tests are parameterized to cover various combinations of operations and operand types.

这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc 的一个 V8 源代码，它是一个 C++ 文件，用于 **单元测试 Turboshaft 编译器在 ARM64 架构上的指令选择器**。

具体来说，它做了以下几件事：

1. **定义了用于表示 ARM64 指令的数据结构 (`MachInst`, `Shift`, `AddSub`, `FPCmp`, `Conversion`)：**  这些结构体包含了 Turboshaft 中间表示的操作类型、指令名称、对应的 ARM64 机器码以及机器类型等信息。

2. **定义了包含各种 ARM64 指令信息的常量数组：** 例如 `kLogicalInstructions` 包含了逻辑运算指令的信息，`kAddSubInstructions` 包含了加减运算指令的信息，等等。这些数组用于测试指令选择器是否能正确地将 Turboshaft 的操作映射到对应的 ARM64 指令。

3. **定义了用于测试的辅助函数 (`BuildConstant`, `SignExtendAndEmit`)：**  `BuildConstant` 用于根据机器类型创建常量操作，`SignExtendAndEmit` 用于处理带符号扩展的指令生成。

4. **使用了 Google Test 框架 (`TEST_P`, `TEST_F`, `INSTANTIATE_TEST_SUITE_P`) 来编写测试用例：**
   - `TEST_P` 表示参数化测试，可以针对不同的指令组合运行相同的测试逻辑。例如，`TurboshaftInstructionSelectorLogicalTest` 使用 `kLogicalInstructions` 中的每条指令进行测试。
   - `TEST_F` 表示非参数化测试，用于测试特定的场景。例如，`TEST_F(TurboshaftInstructionSelectorTest, AddImmediateOnLeft)` 测试了加法指令左操作数为立即数的情况。

5. **测试了各种 ARM64 指令的指令选择：**
   - **逻辑运算指令 (Logical Instructions):**  测试了 `AND`, `OR`, `XOR` 等逻辑运算指令，包括操作数为寄存器、立即数以及移位寄存器的情况。
   - **加减运算指令 (Add and Sub instructions):** 测试了 `ADD`, `SUB` 指令，包括操作数为寄存器、立即数、负立即数以及移位寄存器的情况，还测试了带符号/无符号扩展的情况。
   - **其他指令：** 代码中还定义了用于测试其他类型指令的常量数组，尽管在提供的部分代码中没有看到针对这些数组的完整测试用例，但可以推断后续部分会测试例如乘除法、浮点运算、类型转换等指令的选择。

**如果 v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc 以 .tq 结尾**，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种 V8 使用的领域特定语言，用于定义运行时内置函数和类型系统。 然而，根据文件名，它是一个 `.cc` 文件，因此是 C++ 源代码。

**它与 JavaScript 的功能有关系：**  Turboshaft 是 V8 JavaScript 引擎中的一个编译器。这个单元测试的目标是验证 Turboshaft 编译器在将 JavaScript 代码编译成 ARM64 机器码时，能否正确地选择合适的 ARM64 指令。

**用 JavaScript 举例说明：**

假设有以下 JavaScript 代码：

```javascript
function bitwiseAnd(a, b) {
  return a & b;
}
```

当 V8 的 Turboshaft 编译器编译这个函数时，对于 `a & b` 这个操作，`TurboshaftInstructionSelectorLogicalTest` 中的相关测试用例会验证编译器是否选择了正确的 ARM64 `AND` 指令。

**代码逻辑推理 (假设输入与输出):**

假设 `TurboshaftInstructionSelectorLogicalTest` 中测试 `Word32BitwiseAnd` 指令，并且输入的 Turboshaft 中间表示如下：

**假设输入 (Turboshaft IR):**

```
%param0: Int32 = Parameter(0)
%param1: Int32 = Parameter(1)
%and_result: Int32 = Word32BitwiseAnd(%param0, %param1)
Return(%and_result)
```

**预期输出 (简化的 ARM64 指令):**

```assembly
and w0, w0, w1  // 假设 %param0 和 %param1 分别分配到了 w0 和 w1 寄存器
```

测试代码会断言生成的机器码的 `arch_opcode` 为 `kArm64And32`。

**涉及用户常见的编程错误 (间接相关):**

这个测试文件主要关注编译器本身的正确性，而不是直接检测用户的编程错误。然而，编译器正确地选择指令是程序正确执行的基础。例如，如果指令选择器在处理加法运算时选择了错误的指令，那么即使 JavaScript 代码逻辑正确，也可能得到错误的结果。

**归纳一下它的功能 (第 1 部分):**

总而言之，这个 C++ 源代码文件是 V8 JavaScript 引擎中 Turboshaft 编译器的 ARM64 指令选择器的单元测试。它通过定义数据结构和测试用例，验证了指令选择器能够为 Turboshaft 的基本算术和逻辑运算操作选择正确的 ARM64 机器指令，包括处理寄存器操作数和立即数操作数的情况。这对于确保 V8 在 ARM64 架构上的代码生成质量和程序执行的正确性至关重要。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/machine-type.h"
#include "src/common/globals.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h"

namespace v8::internal::compiler::turboshaft {

template <typename Op>
struct MachInst {
  Op op;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  MachineType machine_type;
};

using MachInst1 = MachInst<TSUnop>;
using MachInst2 = MachInst<TSBinop>;

template <typename T>
std::ostream& operator<<(std::ostream& os, const MachInst<T>& mi) {
  return os << mi.constructor_name;
}

struct Shift {
  MachInst2 mi;
  AddressingMode mode;
};

std::ostream& operator<<(std::ostream& os, const Shift& shift) {
  return os << shift.mi;
}

// Helper to build Int32Constant or Int64Constant depending on the given
// machine type.
OpIndex BuildConstant(TurboshaftInstructionSelectorTest::StreamBuilder* m,
                      MachineType type, int64_t value) {
  switch (type.representation()) {
    case MachineRepresentation::kWord32:
      return m->Int32Constant(static_cast<int32_t>(value));

    case MachineRepresentation::kWord64:
      return m->Int64Constant(value);

    default:
      UNIMPLEMENTED();
  }
}

// ARM64 logical instructions.
const MachInst2 kLogicalInstructions[] = {
    {TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd", kArm64And32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseAnd, "Word64BitwiseAnd", kArm64And,
     MachineType::Int64()},
    {TSBinop::kWord32BitwiseOr, "Word32BitwiseOr", kArm64Or32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseOr, "Word64BitwiseOr", kArm64Or,
     MachineType::Int64()},
    {TSBinop::kWord32BitwiseXor, "Word32BitwiseXor", kArm64Eor32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseXor, "Word64BitwiseXor", kArm64Eor,
     MachineType::Int64()}};

// ARM64 logical immediates: contiguous set bits, rotated about a power of two
// sized block. The block is then duplicated across the word. Below is a random
// subset of the 32-bit immediates.
const uint32_t kLogical32Immediates[] = {
    0x00000002, 0x00000003, 0x00000070, 0x00000080, 0x00000100, 0x000001C0,
    0x00000300, 0x000007E0, 0x00003FFC, 0x00007FC0, 0x0003C000, 0x0003F000,
    0x0003FFC0, 0x0003FFF8, 0x0007FF00, 0x0007FFE0, 0x000E0000, 0x001E0000,
    0x001FFFFC, 0x003F0000, 0x003F8000, 0x00780000, 0x007FC000, 0x00FF0000,
    0x01800000, 0x01800180, 0x01F801F8, 0x03FE0000, 0x03FFFFC0, 0x03FFFFFC,
    0x06000000, 0x07FC0000, 0x07FFC000, 0x07FFFFC0, 0x07FFFFE0, 0x0FFE0FFE,
    0x0FFFF800, 0x0FFFFFF0, 0x0FFFFFFF, 0x18001800, 0x1F001F00, 0x1F801F80,
    0x30303030, 0x3FF03FF0, 0x3FF83FF8, 0x3FFF0000, 0x3FFF8000, 0x3FFFFFC0,
    0x70007000, 0x7F7F7F7F, 0x7FC00000, 0x7FFFFFC0, 0x8000001F, 0x800001FF,
    0x81818181, 0x9FFF9FFF, 0xC00007FF, 0xC0FFFFFF, 0xDDDDDDDD, 0xE00001FF,
    0xE00003FF, 0xE007FFFF, 0xEFFFEFFF, 0xF000003F, 0xF001F001, 0xF3FFF3FF,
    0xF800001F, 0xF80FFFFF, 0xF87FF87F, 0xFBFBFBFB, 0xFC00001F, 0xFC0000FF,
    0xFC0001FF, 0xFC03FC03, 0xFE0001FF, 0xFF000001, 0xFF03FF03, 0xFF800000,
    0xFF800FFF, 0xFF801FFF, 0xFF87FFFF, 0xFFC0003F, 0xFFC007FF, 0xFFCFFFCF,
    0xFFE00003, 0xFFE1FFFF, 0xFFF0001F, 0xFFF07FFF, 0xFFF80007, 0xFFF87FFF,
    0xFFFC00FF, 0xFFFE07FF, 0xFFFF00FF, 0xFFFFC001, 0xFFFFF007, 0xFFFFF3FF,
    0xFFFFF807, 0xFFFFF9FF, 0xFFFFFC0F, 0xFFFFFEFF};

// Random subset of 64-bit logical immediates.
const uint64_t kLogical64Immediates[] = {
    0x0000000000000001, 0x0000000000000002, 0x0000000000000003,
    0x0000000000000070, 0x0000000000000080, 0x0000000000000100,
    0x00000000000001C0, 0x0000000000000300, 0x0000000000000600,
    0x00000000000007E0, 0x0000000000003FFC, 0x0000000000007FC0,
    0x0000000600000000, 0x0000003FFFFFFFFC, 0x000000F000000000,
    0x000001F800000000, 0x0003FC0000000000, 0x0003FC000003FC00,
    0x0003FFFFFFC00000, 0x0003FFFFFFFFFFC0, 0x0006000000060000,
    0x003FFFFFFFFC0000, 0x0180018001800180, 0x01F801F801F801F8,
    0x0600000000000000, 0x1000000010000000, 0x1000100010001000,
    0x1010101010101010, 0x1111111111111111, 0x1F001F001F001F00,
    0x1F1F1F1F1F1F1F1F, 0x1FFFFFFFFFFFFFFE, 0x3FFC3FFC3FFC3FFC,
    0x5555555555555555, 0x7F7F7F7F7F7F7F7F, 0x8000000000000000,
    0x8000001F8000001F, 0x8181818181818181, 0x9999999999999999,
    0x9FFF9FFF9FFF9FFF, 0xAAAAAAAAAAAAAAAA, 0xDDDDDDDDDDDDDDDD,
    0xE0000000000001FF, 0xF800000000000000, 0xF8000000000001FF,
    0xF807F807F807F807, 0xFEFEFEFEFEFEFEFE, 0xFFFEFFFEFFFEFFFE,
    0xFFFFF807FFFFF807, 0xFFFFF9FFFFFFF9FF, 0xFFFFFC0FFFFFFC0F,
    0xFFFFFC0FFFFFFFFF, 0xFFFFFEFFFFFFFEFF, 0xFFFFFEFFFFFFFFFF,
    0xFFFFFF8000000000, 0xFFFFFFFEFFFFFFFE, 0xFFFFFFFFEFFFFFFF,
    0xFFFFFFFFF9FFFFFF, 0xFFFFFFFFFF800000, 0xFFFFFFFFFFFFC0FF,
    0xFFFFFFFFFFFFFFFE};

// ARM64 arithmetic instructions.
struct AddSub {
  MachInst2 mi;
  ArchOpcode negate_arch_opcode;
};

std::ostream& operator<<(std::ostream& os, const AddSub& op) {
  return os << op.mi;
}

const AddSub kAddSubInstructions[] = {
    {{TSBinop::kWord32Add, "Word32Add", kArm64Add32, MachineType::Int32()},
     kArm64Sub32},
    {{TSBinop::kWord64Add, "Word64Add", kArm64Add, MachineType::Int64()},
     kArm64Sub},
    {{TSBinop::kWord32Sub, "Int32Sub", kArm64Sub32, MachineType::Int32()},
     kArm64Add32},
    {{TSBinop::kWord64Sub, "Word64Sub", kArm64Sub, MachineType::Int64()},
     kArm64Add}};

// ARM64 Add/Sub immediates: 12-bit immediate optionally shifted by 12.
// Below is a combination of a random subset and some edge values.
const int32_t kAddSubImmediates[] = {
    0,        1,        69,       493,      599,      701,      719,
    768,      818,      842,      945,      1246,     1286,     1429,
    1669,     2171,     2179,     2182,     2254,     2334,     2338,
    2343,     2396,     2449,     2610,     2732,     2855,     2876,
    2944,     3377,     3458,     3475,     3476,     3540,     3574,
    3601,     3813,     3871,     3917,     4095,     4096,     16384,
    364544,   462848,   970752,   1523712,  1863680,  2363392,  3219456,
    3280896,  4247552,  4526080,  4575232,  4960256,  5505024,  5894144,
    6004736,  6193152,  6385664,  6795264,  7114752,  7233536,  7348224,
    7499776,  7573504,  7729152,  8634368,  8937472,  9465856,  10354688,
    10682368, 11059200, 11460608, 13168640, 13176832, 14336000, 15028224,
    15597568, 15892480, 16773120};

// ARM64 flag setting data processing instructions.
const MachInst2 kDPFlagSetInstructions[] = {
    {TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd", kArm64Tst32,
     MachineType::Int32()},
    {TSBinop::kWord32Add, "Word32Add", kArm64Cmn32, MachineType::Int32()},
    {TSBinop::kWord32Sub, "Int32Sub", kArm64Cmp32, MachineType::Int32()},
    {TSBinop::kWord64BitwiseAnd, "Word64BitwiseAnd", kArm64Tst,
     MachineType::Int64()}};

// ARM64 arithmetic with overflow instructions.
const MachInst2 kOvfAddSubInstructions[] = {
    {TSBinop::kInt32AddCheckOverflow, "Int32AddWithOverflow", kArm64Add32,
     MachineType::Int32()},
    {TSBinop::kInt32SubCheckOverflow, "Int32SubWithOverflow", kArm64Sub32,
     MachineType::Int32()},
    {TSBinop::kInt64AddCheckOverflow, "Int64AddWithOverflow", kArm64Add,
     MachineType::Int64()},
    {TSBinop::kInt64SubCheckOverflow, "Int64SubWithOverflow", kArm64Sub,
     MachineType::Int64()}};

// ARM64 shift instructions.
const Shift kShiftInstructions[] = {
    {{TSBinop::kWord32ShiftLeft, "Word32ShiftLeft", kArm64Lsl32,
      MachineType::Int32()},
     kMode_Operand2_R_LSL_I},
    {{TSBinop::kWord64ShiftLeft, "Word64ShiftLeft", kArm64Lsl,
      MachineType::Int64()},
     kMode_Operand2_R_LSL_I},
    {{TSBinop::kWord32ShiftRightLogical, "Word32ShiftRightLogical", kArm64Lsr32,
      MachineType::Int32()},
     kMode_Operand2_R_LSR_I},
    {{TSBinop::kWord64ShiftRightLogical, "Word64ShiftRightLogical", kArm64Lsr,
      MachineType::Int64()},
     kMode_Operand2_R_LSR_I},
    {{TSBinop::kWord32ShiftRightArithmetic, "Word32ShiftRightArithmetic",
      kArm64Asr32, MachineType::Int32()},
     kMode_Operand2_R_ASR_I},
    {{TSBinop::kWord64ShiftRightArithmetic, "Word64ShiftRightArithmetic",
      kArm64Asr, MachineType::Int64()},
     kMode_Operand2_R_ASR_I},
    {{TSBinop::kWord32RotateRight, "Word32Ror", kArm64Ror32,
      MachineType::Int32()},
     kMode_Operand2_R_ROR_I},
    {{TSBinop::kWord64RotateRight, "Word64Ror", kArm64Ror,
      MachineType::Int64()},
     kMode_Operand2_R_ROR_I}};

// ARM64 Mul/Div instructions.
const MachInst2 kMulDivInstructions[] = {
    {TSBinop::kWord32Mul, "Word32Mul", kArm64Mul32, MachineType::Int32()},
    {TSBinop::kWord64Mul, "Word64Mul", kArm64Mul, MachineType::Int64()},
    {TSBinop::kInt32Div, "Int32Div", kArm64Idiv32, MachineType::Int32()},
    {TSBinop::kInt64Div, "Int64Div", kArm64Idiv, MachineType::Int64()},
    {TSBinop::kUint32Div, "Uint32Div", kArm64Udiv32, MachineType::Int32()},
    {TSBinop::kUint64Div, "Uint64Div", kArm64Udiv, MachineType::Int64()}};

// ARM64 FP arithmetic instructions.
const MachInst2 kFPArithInstructions[] = {
    {TSBinop::kFloat64Add, "Float64Add", kArm64Float64Add,
     MachineType::Float64()},
    {TSBinop::kFloat64Sub, "Float64Sub", kArm64Float64Sub,
     MachineType::Float64()},
    {TSBinop::kFloat64Mul, "Float64Mul", kArm64Float64Mul,
     MachineType::Float64()},
    {TSBinop::kFloat64Div, "Float64Div", kArm64Float64Div,
     MachineType::Float64()}};

struct FPCmp {
  MachInst2 mi;
  FlagsCondition cond;
  FlagsCondition commuted_cond;
};

std::ostream& operator<<(std::ostream& os, const FPCmp& cmp) {
  return os << cmp.mi;
}

// ARM64 FP comparison instructions.
const FPCmp kFPCmpInstructions[] = {
    {{TSBinop::kFloat64Equal, "Float64Equal", kArm64Float64Cmp,
      MachineType::Float64()},
     kEqual,
     kEqual},
    {{TSBinop::kFloat64LessThan, "Float64LessThan", kArm64Float64Cmp,
      MachineType::Float64()},
     kFloatLessThan,
     kFloatGreaterThan},
    {{TSBinop::kFloat64LessThanOrEqual, "Float64LessThanOrEqual",
      kArm64Float64Cmp, MachineType::Float64()},
     kFloatLessThanOrEqual,
     kFloatGreaterThanOrEqual},
    {{TSBinop::kFloat32Equal, "Float32Equal", kArm64Float32Cmp,
      MachineType::Float32()},
     kEqual,
     kEqual},
    {{TSBinop::kFloat32LessThan, "Float32LessThan", kArm64Float32Cmp,
      MachineType::Float32()},
     kFloatLessThan,
     kFloatGreaterThan},
    {{TSBinop::kFloat32LessThanOrEqual, "Float32LessThanOrEqual",
      kArm64Float32Cmp, MachineType::Float32()},
     kFloatLessThanOrEqual,
     kFloatGreaterThanOrEqual}};

struct Conversion {
  // The machine_type field in MachInst1 represents the destination type.
  MachInst1 mi;
  MachineType src_machine_type;
};

std::ostream& operator<<(std::ostream& os, const Conversion& conv) {
  return os << conv.mi;
}

// ARM64 type conversion instructions.
const Conversion kConversionInstructions[] = {
    {{TSUnop::kChangeFloat32ToFloat64, "ChangeFloat32ToFloat64",
      kArm64Float32ToFloat64, MachineType::Float64()},
     MachineType::Float32()},
    {{TSUnop::kTruncateFloat64ToFloat32, "TruncateFloat64ToFloat32",
      kArm64Float64ToFloat32, MachineType::Float32()},
     MachineType::Float64()},
    {{TSUnop::kChangeInt32ToInt64, "ChangeInt32ToInt64", kArm64Sxtw,
      MachineType::Int64()},
     MachineType::Int32()},
    {{TSUnop::kChangeUint32ToUint64, "ChangeUint32ToUint64", kArm64Mov32,
      MachineType::Uint64()},
     MachineType::Uint32()},
    {{TSUnop::kTruncateWord64ToWord32, "TruncateWord64ToWord32", kArchNop,
      MachineType::Int32()},
     MachineType::Int64()},
    {{TSUnop::kChangeInt32ToFloat64, "ChangeInt32ToFloat64",
      kArm64Int32ToFloat64, MachineType::Float64()},
     MachineType::Int32()},
    {{TSUnop::kChangeUint32ToFloat64, "ChangeUint32ToFloat64",
      kArm64Uint32ToFloat64, MachineType::Float64()},
     MachineType::Uint32()},
    {{TSUnop::kReversibleFloat64ToInt32, "ReversibleFloat64ToInt32",
      kArm64Float64ToInt32, MachineType::Int32()},
     MachineType::Float64()},
    {{TSUnop::kReversibleFloat64ToUint32, "ReversibleFloat64ToUint32",
      kArm64Float64ToUint32, MachineType::Uint32()},
     MachineType::Float64()}};

// ARM64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {TSBinop::kWord32BitwiseAnd, "Word32BitwisAnd", kArm64And32,
     MachineType::Uint32()},
    {TSBinop::kWord32BitwiseOr, "Word32BitwisOr", kArm64Or32,
     MachineType::Uint32()},
    {TSBinop::kWord32BitwiseXor, "Word32BitwisXor", kArm64Eor32,
     MachineType::Uint32()},
    {TSBinop::kWord32ShiftLeft, "Word32ShiftLeft", kArm64Lsl32,
     MachineType::Uint32()},
    {TSBinop::kWord32ShiftRightLogical, "Word32ShiftRightLogical", kArm64Lsr32,
     MachineType::Uint32()},
    {TSBinop::kWord32ShiftRightArithmetic, "Word32ShiftRightArithmetic",
     kArm64Asr32, MachineType::Uint32()},
    {TSBinop::kWord32RotateRight, "Word32RotateRight", kArm64Ror32,
     MachineType::Uint32()},
    {TSBinop::kWord32Equal, "Word32Equal", kArm64Cmp32, MachineType::Uint32()},
    {TSBinop::kWord32Add, "Word32Add", kArm64Add32, MachineType::Int32()},
    {TSBinop::kWord32Sub, "Word32Sub", kArm64Sub32, MachineType::Int32()},
    {TSBinop::kWord32Mul, "Word32Mul", kArm64Mul32, MachineType::Int32()},
    {TSBinop::kInt32Div, "Int32Div", kArm64Idiv32, MachineType::Int32()},
    {TSBinop::kInt32Mod, "Int32Mod", kArm64Imod32, MachineType::Int32()},
    {TSBinop::kInt32LessThan, "Int32LessThan", kArm64Cmp32,
     MachineType::Int32()},
    {TSBinop::kInt32LessThanOrEqual, "Int32LessThanOrEqual", kArm64Cmp32,
     MachineType::Int32()},
    {TSBinop::kUint32Div, "Uint32Div", kArm64Udiv32, MachineType::Uint32()},
    {TSBinop::kUint32LessThan, "Uint32LessThan", kArm64Cmp32,
     MachineType::Uint32()},
    {TSBinop::kUint32LessThanOrEqual, "Uint32LessThanOrEqual", kArm64Cmp32,
     MachineType::Uint32()},
    {TSBinop::kUint32Mod, "Uint32Mod", kArm64Umod32, MachineType::Uint32()},
};
const MachInst2 kCanElideChangeUint32ToUint64MultiOutput[] = {
    {TSBinop::kInt32AddCheckOverflow, "Int32AddCheckOverflow", kArm64Add32,
     MachineType::Int32()},
    {TSBinop::kInt32SubCheckOverflow, "Int32SubCheckOverflow", kArm64Sub32,
     MachineType::Int32()},
};

// -----------------------------------------------------------------------------
// Logical instructions.

using TurboshaftInstructionSelectorLogicalTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorLogicalTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorLogicalTest, Immediate) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  if (type == MachineType::Int32()) {
    // Immediate on the right.
    TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
      StreamBuilder m(this, type, type);
      m.Return(m.Emit(dpi.op, m.Parameter(0), m.Int32Constant(imm)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
      ASSERT_EQ(2U, s[0]->InputCount());
      EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }

    // Immediate on the left; all logical ops should commute.
    TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
      StreamBuilder m(this, type, type);
      m.Return(m.Emit(dpi.op, m.Int32Constant(imm), m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
      ASSERT_EQ(2U, s[0]->InputCount());
      EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  } else if (type == MachineType::Int64()) {
    // Immediate on the right.
    TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
      StreamBuilder m(this, type, type);
      m.Return(m.Emit(dpi.op, m.Parameter(0), m.Int64Constant(imm)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
      ASSERT_EQ(2U, s[0]->InputCount());
      EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
      EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }

    // Immediate on the left; all logical ops should commute.
    TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
      StreamBuilder m(this, type, type);
      m.Return(m.Emit(dpi.op, m.Int64Constant(imm), m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
      ASSERT_EQ(2U, s[0]->InputCount());
      EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
      EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_P(TurboshaftInstructionSelectorLogicalTest, ShiftByImmediate) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    // Only test 64-bit shifted operands with 64-bit instructions.
    if (shift.mi.machine_type != type) continue;

    TRACED_FORRANGE(int, imm, 0, ((type == MachineType::Int32()) ? 31 : 63)) {
      StreamBuilder m(this, type, type, type);
      m.Return(
          m.Emit(dpi.op, m.Parameter(0),
                 m.Emit(shift.mi.op, m.Parameter(1), m.Int32Constant(imm))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }

    TRACED_FORRANGE(int, imm, 0, ((type == MachineType::Int32()) ? 31 : 63)) {
      StreamBuilder m(this, type, type, type);
      m.Return(m.Emit(dpi.op,
                      m.Emit(shift.mi.op, m.Parameter(1), m.Int32Constant(imm)),
                      m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorLogicalTest,
                         ::testing::ValuesIn(kLogicalInstructions));

// -----------------------------------------------------------------------------
// Add and Sub instructions.

using TurboshaftInstructionSelectorAddSubTest =
    TurboshaftInstructionSelectorTestWithParam<AddSub>;

TEST_P(TurboshaftInstructionSelectorAddSubTest, Parameter) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(dpi.mi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorAddSubTest, ImmediateOnRight) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    m.Return(m.Emit(dpi.mi.op, m.Parameter(0), BuildConstant(&m, type, imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorAddSubTest, NegImmediateOnRight) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, type, type);
    m.Return(m.Emit(dpi.mi.op, m.Parameter(0), BuildConstant(&m, type, -imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.negate_arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(TurboshaftInstructionSelectorAddSubTest, ShiftByImmediateOnRight) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    // Only test 64-bit shifted operands with 64-bit instructions.
    if (shift.mi.machine_type != type) continue;

    if ((shift.mi.arch_opcode == kArm64Ror32) ||
        (shift.mi.arch_opcode == kArm64Ror)) {
      // Not supported by add/sub instructions.
      continue;
    }

    TRACED_FORRANGE(int, imm, 0, ((type == MachineType::Int32()) ? 31 : 63)) {
      StreamBuilder m(this, type, type, type);
      m.Return(
          m.Emit(dpi.mi.op, m.Parameter(0),
                 m.Emit(shift.mi.op, m.Parameter(1), m.Word32Constant(imm))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

OpIndex SignExtendAndEmit(TurboshaftInstructionSelectorTest::StreamBuilder& m,
                          MachineType type, TSBinop op, OpIndex left,
                          OpIndex right) {
  RegisterRepresentation rep = RegisterRepresentation::FromMachineType(type);
  if (rep == RegisterRepresentation::Word32()) {
    return m.Emit(op, left, right);
  }
  auto left_rep = m.output_graph().Get(left).outputs_rep();
  auto right_rep = m.output_graph().Get(right).outputs_rep();
  DCHECK_EQ(1U, left_rep.size());
  DCHECK_EQ(1U, right_rep.size());
  if (left_rep[0] == RegisterRepresentation::Word32()) {
    left = m.ChangeInt32ToInt64(left);
  }
  if (right_rep[0] == RegisterRepresentation::Word32()) {
    right = m.ChangeInt32ToInt64(right);
  }
  return m.Emit(op, left, right);
}

TEST_P(TurboshaftInstructionSelectorAddSubTest, UnsignedExtendByte) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(SignExtendAndEmit(
      m, type, dpi.mi.op, m.Parameter(0),
      m.Word32BitwiseAnd(m.Parameter(1, RegisterRepresentation::Word32()),
                         m.Int32Constant(0xFF))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorAddSubTest, UnsignedExtendHalfword) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(SignExtendAndEmit(
      m, type, dpi.mi.op, m.Parameter(0),
      m.Word32BitwiseAnd(m.Parameter(1, RegisterRepresentation::Word32()),
                         m.Int32Constant(0xFFFF))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorAddSubTest, SignedExtendByte) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(SignExtendAndEmit(
      m, type, dpi.mi.op, m.Parameter(0),
      m.Word32ShiftRightArithmetic(
          m.Word32ShiftLeft(m.Parameter(1, RegisterRepresentation::Word32()),
                            m.Int32Constant(24)),
          m.Int32Constant(24))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorAddSubTest, SignedExtendHalfword) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(SignExtendAndEmit(
      m, type, dpi.mi.op, m.Parameter(0),
      m.Word32ShiftRightArithmetic(
          m.Word32ShiftLeft(m.Parameter(1, RegisterRepresentation::Word32()),
                            m.Int32Constant(16)),
          m.Int32Constant(16))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_SXTH, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_P(TurboshaftInstructionSelectorAddSubTest, SignedExtendWord) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  if (type != MachineType::Int64()) return;
  StreamBuilder m(this, type, type, MachineType::Int32());
  m.Return(
      m.Emit(dpi.mi.op, m.Parameter(0), m.ChangeInt32ToInt64(m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_SXTW, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorAddSubTest,
                         ::testing::ValuesIn(kAddSubInstructions));

TEST_F(TurboshaftInstructionSelectorTest, AddImmediateOnLeft) {
  // 32-bit add.
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Add(m.Int32Constant(imm), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }

  // 64-bit add.
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Add(m.Int64Constant(imm), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, SubZeroOnLeft) {
  {
    // 32-bit subtract.
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32Sub(m.Int32Constant(0), m.Parameter(0)));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sub32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(0)->IsImmediate());
    EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    // 64-bit subtract.
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                    MachineType::Int64());
    m.Return(m.Word64Sub(m.Int64Constant(0), m.Parameter(0)));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sub, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(0)->IsImmediate());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, SubZeroOnLeftWithShift) {
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    {
      // Test 32-bit operations. Ignore ROR shifts, as subtract does not
      // support them.
      if ((shift.mi.machine_type != MachineType::Int32()) ||
          (shift.mi.arch_opcode == kArm64Ror32) ||
          (shift.mi.arch_opcode == kArm64Ror))
        continue;

      TRACED_FORRANGE(int, imm, -32, 63) {
        StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                        MachineType::Int32());
        m.Return(m.Word32Sub(
            m.Int32Constant(0),
            m.Emit(shift.mi.op, m.Parameter(1), m.Int32Constant(imm))));
        Stream s = m.Build();

        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(kArm64Sub32, s[0]->arch_opcode());
        ASSERT_EQ(3U, s[0]->InputCount());
        EXPECT_TRUE(s[0]->InputAt(0)->IsImmediate());
        EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(0)));
        EXPECT_EQ(shift.mode, s[0]->addressing_mode());
        EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt32(s[0]->InputAt(2)));
        EXPECT_EQ(1U, s[0]->OutputCount());
      }
    }
    {
      // Test 64-bit operations. Ignore ROR shifts, as subtract does not
      // support them.
      if ((shift.mi.machine_type != MachineType::Int64()) ||
          (shift.mi.arch_opcode == kArm64Ror32) ||
          (shift.mi.arch_opcode == kArm64Ror))
        continue;

      TRACED_FORRANGE(int, imm, -32, 127) {
        StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                        MachineType::Int64());
        m.Return(m.Word64Sub(
            m.Int64Constant(0),
            m.Emit(shift.mi.op, m.Parameter(1), m.Int64Constant(imm))));
        Stream s = m.Build();

        ASSERT_EQ(1U, s.size());
        EXPECT_EQ(kArm64Sub, s[0]->arch_opcode());
        ASSERT_EQ(3U, s[0]->InputCount());
        EXPECT_TRUE(s[0]->InputAt(0)->IsImmediate());
        EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(0)));
        EXPECT_EQ(shift.mode, s[0]->addressing_mode());
        EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt32(s[0]->InputAt(2)));
        EXPECT_EQ(1U, s[0]->OutputCount());
      }
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddNegImmediateOnLeft) {
  // 32-bit add.
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32Add(m.Int32Constant(-imm), m.Parameter(0)));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sub32, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }

  // 64-bit add.
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    m.Return(m.Word64Add(m.Int64Constant(-imm), m.Parameter(0)));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sub, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddShiftByImmediateOnLeft) {
  // 32-bit add.
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    // Only test relevant shifted operands.
    if (shift.mi.machine_type != MachineType::Int32()) continue;
    if (shift.mi.arch_opcode == kArm64Ror32) continue;

    // The available shift operand range is `0 <= imm < 32`, but we also test
    // that immediates outside this range are handled properly (modulo-32).
    TRACED_FORRANGE(int, imm, -32, 63) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      m.Return(
          m.Word32Add(m.Emit(shift.mi.op, m.Parameter(1), m.Int32Constant(imm)),
                      m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_E
"""


```