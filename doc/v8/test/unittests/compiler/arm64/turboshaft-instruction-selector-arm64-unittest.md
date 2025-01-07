Response: The user wants to understand the functionality of the provided C++ code snippet. This file seems to be a unit test for the instruction selector in the Turboshaft compiler backend for the ARM64 architecture in V8 (the JavaScript engine).

Here's a breakdown of the thought process to summarize the code:

1. **Identify the core purpose:** The filename `turboshaft-instruction-selector-arm64-unittest.cc` immediately suggests this is a unit test file specifically for the ARM64 instruction selector within the Turboshaft compiler.

2. **Examine includes:** The included headers confirm the context:
    - `src/codegen/machine-type.h`: Deals with machine-specific data types.
    - `src/common/globals.h`:  Likely contains global definitions and settings for V8.
    - `src/compiler/turboshaft/assembler.h`:  Provides tools for generating machine code in Turboshaft.
    - `src/compiler/turboshaft/operations.h`: Defines the operations used in the Turboshaft intermediate representation.
    - `src/compiler/turboshaft/representations.h`:  Deals with how data is represented in the compiler.
    - `src/objects/objects-inl.h`:  Part of V8's object system.
    - `test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h`:  The base class for these specific unit tests.

3. **Look for key data structures:** The code defines several structs and arrays that represent mappings between Turboshaft operations and ARM64 instructions:
    - `MachInst`:  Maps a Turboshaft unary or binary operation to its ARM64 opcode and machine type.
    - `Shift`: Extends `MachInst` for shift operations, adding addressing mode information.
    - Arrays like `kLogicalInstructions`, `kAddSubInstructions`, `kShiftInstructions`, etc.: These arrays contain instances of the above structs, essentially defining test cases for various ARM64 instructions.
    - `AddSub`, `FPCmp`, `Conversion`, `TestAndBranch`:  Similar structs for specific instruction categories with potentially additional related information (like negated opcodes or flags conditions).

4. **Analyze helper functions:**  Functions like `BuildConstant` provide utility for creating constant values in the tests, making the test setup cleaner.

5. **Identify the testing framework:** The use of `TEST_P` and `INSTANTIATE_TEST_SUITE_P` points to Google Test (gtest), a common C++ testing framework. This means the core logic involves defining parameterized tests that iterate through the data structures (like `kLogicalInstructions`).

6. **Understand the test structure:**  The tests generally follow a pattern:
    - Create a `StreamBuilder` to construct a sequence of Turboshaft operations.
    - Emit a specific operation under test, often with parameters or constants.
    - Build the instruction stream.
    - Assertions (`ASSERT_EQ`, `EXPECT_EQ`) are used to verify that the generated machine code has the expected ARM64 opcode, addressing mode, and input/output counts.

7. **Relate to JavaScript (if applicable):**  The code manipulates low-level integer and floating-point operations. These operations are fundamental to how JavaScript code (especially number manipulation and bitwise operations) is eventually executed. For example:
    - Bitwise AND, OR, XOR in JavaScript directly translate to the logical instructions being tested.
    - Addition, subtraction, multiplication, division are tested for both integer and floating-point numbers.
    - Shift operations in JavaScript have corresponding ARM64 instructions.
    - Type conversions (e.g., converting a 32-bit integer to a 64-bit integer) are also tested.

8. **Consider the "part 1 of 4" aspect:** This suggests the full file will likely cover a broader range of ARM64 instructions. This first part seems to focus on basic arithmetic, logical, and bitwise operations.

By following these steps, it's possible to infer the functionality of the code snippet and connect it to the execution of JavaScript. The result is the summarized description provided in the initial prompt's answer.
这个C++源代码文件是V8 JavaScript引擎中Turboshaft编译器的一个单元测试，专门针对ARM64架构的指令选择器。**它的主要功能是测试Turboshaft编译器能否正确地将高级的中间表示（Turboshaft operations）转换为底层的ARM64机器指令。**

具体来说，这个文件：

* **定义了一系列数据结构**（如 `MachInst`, `Shift`, `AddSub`, `FPCmp`, `Conversion`, `TestAndBranch`）用于描述Turboshaft的操作、期望的ARM64指令、寻址模式以及其他相关信息。
* **定义了多个常量数组**（如 `kLogicalInstructions`, `kAddSubInstructions`, `kShiftInstructions`, `kLogical32Immediates`, `kLogical64Immediates` 等）包含了各种Turboshaft操作及其对应的ARM64指令信息，以及一些测试用的立即数。
* **使用 Google Test 框架** 来组织和执行测试用例。
* **每个测试用例** 通常会构造一个简单的Turboshaft操作序列（使用 `StreamBuilder`），然后断言（使用 `ASSERT_EQ`, `EXPECT_EQ`）指令选择器生成的ARM64指令是否与预期一致，包括指令的类型、操作码、寻址模式、输入输出数量等。
* **测试涵盖了多种ARM64指令**，包括：
    * **逻辑运算指令** (AND, OR, XOR)
    * **算术运算指令** (ADD, SUB)
    * **移位指令** (LSL, LSR, ASR, ROR)
    * **乘除法指令** (MUL, DIV)
    * **浮点运算指令** (ADD, SUB, MUL, DIV, CMP)
    * **类型转换指令**
    * **条件分支指令** (通过比较和标志位设置指令)
    * **位测试和分支指令** (TBZ, TBNZ 的模拟)

**与 JavaScript 的关系：**

Turboshaft是V8引擎的一个编译阶段，它负责将JavaScript代码转换为高效的机器码。这个文件测试的指令选择器是Turboshaft的一个重要组成部分。当V8执行JavaScript代码时，Turboshaft会将JavaScript中的各种操作（例如算术运算、位运算、类型转换等）翻译成底层的机器指令。这个单元测试确保了对于ARM64架构，这些JavaScript操作能够正确地映射到相应的ARM64指令上，从而保证JavaScript代码在ARM64架构上的正确执行和性能。

**JavaScript 例子：**

```javascript
function test(a, b) {
  // 位运算，对应测试文件中的逻辑运算指令
  const andResult = a & b;
  const orResult = a | b;
  const xorResult = a ^ b;

  // 算术运算，对应测试文件中的算术运算指令
  const sum = a + b;
  const difference = a - b;

  // 移位运算，对应测试文件中的移位指令
  const leftShift = a << 2;
  const rightShift = a >> 2;
  const unsignedRightShift = a >>> 2;

  // 类型转换 (在 JavaScript 中是隐式的，但在底层编译时需要显式转换)
  const numToString = String(a);

  // 条件判断，对应测试文件中的条件分支指令
  if (a > b) {
    return 1;
  } else {
    return 0;
  }
}

console.log(test(5, 3));
```

在这个JavaScript例子中，`&`, `|`, `^`, `+`, `-`, `<<`, `>>`, `>>>`, `String()` 和 `>` 这些操作，在Turboshaft编译到ARM64架构时，就会涉及到这个单元测试文件中测试的各种ARM64指令的生成和选择。 例如：

* `a & b` 会被翻译成 ARM64 的 `AND` 指令。
* `a + b` 会被翻译成 ARM64 的 `ADD` 指令。
* `a << 2` 会被翻译成 ARM64 的 `LSL` 指令。
* `a > b` 的比较结果会影响后续的条件分支指令的选择。

总而言之，这个单元测试文件是确保V8引擎在ARM64架构上正确执行JavaScript代码的关键组成部分，它验证了编译器能否将JavaScript的高级概念正确地翻译成底层的机器指令。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/turboshaft-instruction-selector-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
      EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }

  // 64-bit add.
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    // Only test relevant shifted operands.
    if (shift.mi.machine_type != MachineType::Int64()) continue;
    if (shift.mi.arch_opcode == kArm64Ror) continue;

    // The available shift operand range is `0 <= imm < 64`, but we also test
    // that immediates outside this range are handled properly (modulo-64).
    TRACED_FORRANGE(int, imm, -64, 127) {
      StreamBuilder m(this, MachineType::Int64(), MachineType::Int64(),
                      MachineType::Int64());
      m.Return(
          m.Word64Add(m.Emit(shift.mi.op, m.Parameter(1), m.Int32Constant(imm)),
                      m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddUnsignedExtendByteOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Word32Add(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(0xFF)),
                    m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int64());
    m.Return(m.Word64Add(m.ChangeInt32ToInt64(m.Word32BitwiseAnd(
                             m.Parameter(0), m.Int32Constant(0xFF))),
                         m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddUnsignedExtendHalfwordOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Word32Add(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(0xFFFF)),
                    m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int64());
    m.Return(m.Word64Add(m.ChangeInt32ToInt64(m.Word32BitwiseAnd(
                             m.Parameter(0), m.Int32Constant(0xFFFF))),
                         m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddSignedExtendByteOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Word32Add(m.Word32ShiftRightArithmetic(
                        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(24)),
                        m.Int32Constant(24)),
                    m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int64());
    m.Return(
        m.Word64Add(m.ChangeInt32ToInt64(m.Word32ShiftRightArithmetic(
                        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(24)),
                        m.Int32Constant(24))),
                    m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddSignedExtendHalfwordOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Word32Add(m.Word32ShiftRightArithmetic(
                        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(16)),
                        m.Int32Constant(16)),
                    m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add32, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32(),
                    MachineType::Int64());
    m.Return(
        m.Word64Add(m.ChangeInt32ToInt64(m.Word32ShiftRightArithmetic(
                        m.Word32ShiftLeft(m.Parameter(0), m.Int32Constant(16)),
                        m.Int32Constant(16))),
                    m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

#if V8_ENABLE_WEBASSEMBLY
enum PairwiseAddSide { LEFT, RIGHT };

std::ostream& operator<<(std::ostream& os, const PairwiseAddSide& side) {
  switch (side) {
    case LEFT:
      return os << "LEFT";
    case RIGHT:
      return os << "RIGHT";
  }
}

struct AddWithPairwiseAddSideAndWidth {
  PairwiseAddSide side;
  int32_t width;
  bool isSigned;
};

std::ostream& operator<<(std::ostream& os,
                         const AddWithPairwiseAddSideAndWidth& sw) {
  return os << "{ side: " << sw.side << ", width: " << sw.width
            << ", isSigned: " << sw.isSigned << " }";
}

using TurboshaftInstructionSelectorAddWithPairwiseAddTest =
    TurboshaftInstructionSelectorTestWithParam<AddWithPairwiseAddSideAndWidth>;

TEST_P(TurboshaftInstructionSelectorAddWithPairwiseAddTest,
       AddWithPairwiseAdd) {
  AddWithPairwiseAddSideAndWidth params = GetParam();
  const MachineType type = MachineType::Simd128();
  StreamBuilder m(this, type, type, type, type);

  OpIndex x = m.Parameter(0);
  OpIndex y = m.Parameter(1);
  OpIndex pairwiseAdd;
  if (params.width == 32 && params.isSigned) {
    pairwiseAdd = m.I32x4ExtAddPairwiseI16x8S(x);
  } else if (params.width == 16 && params.isSigned) {
    pairwiseAdd = m.I16x8ExtAddPairwiseI8x16S(x);
  } else if (params.width == 32 && !params.isSigned) {
    pairwiseAdd = m.I32x4ExtAddPairwiseI16x8U(x);
  } else {
    pairwiseAdd = m.I16x8ExtAddPairwiseI8x16U(x);
  }

  OpIndex add;
  if (params.width == 32) {
    add = params.side == LEFT ? m.I32x4Add(pairwiseAdd, y)
                              : m.I32x4Add(y, pairwiseAdd);
  } else {
    add = params.side == LEFT ? m.I16x8Add(pairwiseAdd, y)
                              : m.I16x8Add(y, pairwiseAdd);
  }

  m.Return(add);
  Stream s = m.Build();

  // Should be fused to Sadalp/Uadalp
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(params.isSigned ? kArm64Sadalp : kArm64Uadalp, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

const AddWithPairwiseAddSideAndWidth kAddWithPairAddTestCases[] = {
    {LEFT, 16, true},  {RIGHT, 16, true}, {LEFT, 32, true},
    {RIGHT, 32, true}, {LEFT, 16, false}, {RIGHT, 16, false},
    {LEFT, 32, false}, {RIGHT, 32, false}};

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorAddWithPairwiseAddTest,
                         ::testing::ValuesIn(kAddWithPairAddTestCases));
#endif  // V8_ENABLE_WEBASSEMBLY

// -----------------------------------------------------------------------------
// Data processing controlled branches.

using TurboshaftInstructionSelectorDPFlagSetTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorDPFlagSetTest, BranchWithParameters) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  Block *a = m.NewBlock(), *b = m.NewBlock();
  OpIndex cond = m.Emit(dpi.op, m.Parameter(0), m.Parameter(1));
  if (type == MachineType::Int64()) cond = m.TruncateWord64ToWord32(cond);
  m.Branch(V<Word32>::Cast(cond), a, b);
  m.Bind(a);
  m.Return(m.Int32Constant(1));
  m.Bind(b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorDPFlagSetTest,
                         ::testing::ValuesIn(kDPFlagSetInstructions));

TEST_F(TurboshaftInstructionSelectorTest, Word32AndBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint32_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(imm)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64AndBranchWithImmediateOnRight) {
  TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint64_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.TruncateWord64ToWord32(
                 m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(imm))),
             a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst, s[0]->arch_opcode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32Add(m.Parameter(0), m.Int32Constant(imm)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, SubBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32Sub(m.Parameter(0), m.Int32Constant(imm)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ((imm == 0) ? kArm64CompareAndBranch32 : kArm64Cmp32,
              s[0]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word32AndBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint32_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32BitwiseAnd(m.Int32Constant(imm), m.Parameter(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst32, s[0]->arch_opcode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    ASSERT_LE(1U, s[0]->InputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, Word64AndBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint64_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.TruncateWord64ToWord32(
                 m.Word64BitwiseAnd(m.Int64Constant(imm), m.Parameter(0))),
             a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Tst, s[0]->arch_opcode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    ASSERT_LE(1U, s[0]->InputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, AddBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32Add(m.Int32Constant(imm), m.Parameter(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    ASSERT_LE(1U, s[0]->InputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

struct TestAndBranch {
  MachInst<
      std::function<V<Word32>(TurboshaftInstructionSelectorTest::StreamBuilder&,
                              OpIndex, uint64_t mask)>>
      mi;
  FlagsCondition cond;
};

std::ostream& operator<<(std::ostream& os, const TestAndBranch& tb) {
  return os << tb.mi;
}

const TestAndBranch kTestAndBranchMatchers32[] = {
    // Branch on the result of Word32BitwiseAnd directly.
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32BitwiseAnd(x, m.Int32Constant(mask));
      },
      "if (x and mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32BinaryNot(m.Word32BitwiseAnd(x, m.Int32Constant(mask)));
      },
      "if not (x and mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    // Branch on the result of '(x and mask) == mask'. This tests that a bit is
    // set rather than cleared which is why conditions are inverted.
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32Equal(m.Word32BitwiseAnd(x, m.Int32Constant(mask)),
                             m.Int32Constant(mask));
      },
      "if ((x and mask) == mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32BinaryNot(
            m.Word32Equal(m.Word32BitwiseAnd(x, m.Int32Constant(mask)),
                          m.Int32Constant(mask)));
      },
      "if ((x and mask) != mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32Equal(m.Int32Constant(mask),
                             m.Word32BitwiseAnd(x, m.Int32Constant(mask)));
      },
      "if (mask == (x and mask))", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint32_t mask) -> V<Word32> {
        return m.Word32BinaryNot(
            m.Word32Equal(m.Int32Constant(mask),
                          m.Word32BitwiseAnd(x, m.Int32Constant(mask))));
      },
      "if (mask != (x and mask))", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual}};

using TurboshaftInstructionSelectorTestAndBranchTest =
    TurboshaftInstructionSelectorTestWithParam<TestAndBranch>;

TEST_P(TurboshaftInstructionSelectorTestAndBranchTest, TestAndBranch32) {
  const TestAndBranch inst = GetParam();
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(inst.mi.op(m, m.Parameter(0), mask), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(inst.cond, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt32(s[0]->InputAt(1)));
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorTestAndBranchTest,
                         ::testing::ValuesIn(kTestAndBranchMatchers32));

// TODO(arm64): Add the missing Word32BinaryNot test cases from the 32-bit
// version.
const TestAndBranch kTestAndBranchMatchers64[] = {
    // Branch on the result of Word64BitwiseAnd directly.
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint64_t mask) -> V<Word32> {
        return m.TruncateWord64ToWord32(
            m.Word64BitwiseAnd(x, m.Int64Constant(mask)));
      },
      "if (x and mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint64_t mask) -> V<Word32> {
        return m.Word64Equal(m.Word64BitwiseAnd(x, m.Int64Constant(mask)),
                             m.Int64Constant(0));
      },
      "if not (x and mask)", kArm64TestAndBranch, MachineType::Int64()},
     kEqual},
    // Branch on the result of '(x and mask) == mask'. This tests that a bit is
    // set rather than cleared which is why conditions are inverted.
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint64_t mask) -> V<Word32> {
        return m.Word64Equal(m.Word64BitwiseAnd(x, m.Int64Constant(mask)),
                             m.Int64Constant(mask));
      },
      "if ((x and mask) == mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](TurboshaftInstructionSelectorTest::StreamBuilder& m, OpIndex x,
         uint64_t mask) -> V<Word32> {
        return m.Word64Equal(m.Int64Constant(mask),
                             m.Word64BitwiseAnd(x, m.Int64Constant(mask)));
      },
      "if (mask == (x and mask))", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual}};

using TurboshaftInstructionSelectorTestAndBranchTest64 =
    TurboshaftInstructionSelectorTestWithParam<TestAndBranch>;

TEST_P(TurboshaftInstructionSelectorTestAndBranchTest64, TestAndBranch64) {
  const TestAndBranch inst = GetParam();
  // TRACED_FORRANGE(int, bit, 0, 63) {
  int bit = 0;
  uint64_t mask = uint64_t{1} << bit;
  StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
  Block *a = m.NewBlock(), *b = m.NewBlock();
  m.Branch(inst.mi.op(m, m.Parameter(0), mask), a, b);
  m.Bind(a);
  m.Return(m.Int64Constant(1));
  m.Bind(b);
  m.Return(m.Int64Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(inst.cond, s[0]->flags_condition());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
  EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  // }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorTestAndBranchTest64,
                         ::testing::ValuesIn(kTestAndBranchMatchers64));

TEST_F(TurboshaftInstructionSelectorTest,
       Word64AndBranchWithOneBitMaskOnRight) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.TruncateWord64ToWord32(
                 m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask))),
             a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       TestAndBranch64EqualWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock(), *c = m.NewBlock();
    OpIndex n = m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask));
    m.Branch(m.Word64Equal(n, m.Int64Constant(0)), a, b);
    m.Bind(a);
    m.Branch(m.Word64Equal(n, m.Int64Constant(3)), b, c);
    m.Bind(c);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(3U, s.size());
    EXPECT_EQ(kArm64And, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(kArm64TestAndBranch, s[1]->arch_opcode());
    EXPECT_EQ(kEqual, s[1]->flags_condition());
    EXPECT_EQ(kArm64Cmp, s[2]->arch_opcode());
    EXPECT_EQ(kEqual, s[2]->flags_condition());
    EXPECT_EQ(2U, s[0]->InputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, TestAndBranch64AndWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.TruncateWord64ToWord32(
                 m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask))),
             a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(4U, s[0]->InputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest, TestAndBranch32AndWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = uint32_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(mask)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(4U, s[0]->InputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word32EqualZeroAndBranchWithOneBitMask) {
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(
        m.Word32Equal(m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(mask)),
                      m.Int32Constant(0)),
        a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt32(s[0]->InputAt(1)));
  }

  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word32NotEqual(
                 m.Word32BitwiseAnd(m.Parameter(0), m.Int32Constant(mask)),
                 m.Int32Constant(0)),
             a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt32(s[0]->InputAt(1)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       Word64EqualZeroAndBranchWithOneBitMask) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(
        m.Word64Equal(m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask)),
                      m.Int64Constant(0)),
        a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }

  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    m.Branch(m.Word64NotEqual(
                 m.Word64BitwiseAnd(m.Parameter(0), m.Int64Constant(mask)),
                 m.Int64Constant(0)),
             a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, CompareAgainstZeroAndBranch) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    V<Word32> p0 = m.Parameter(0);
    m.Branch(p0, a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }

  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word32BinaryNot(p0), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, EqualZeroAndBranch) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word32Equal(p0, m.Int32Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }

  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word32NotEqual(p0, m.Int32Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int32Constant(1));
    m.Bind(b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }

  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word64Equal(p0, m.Int64Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }

  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    Block *a = m.NewBlock(), *b = m.NewBlock();
    OpIndex p0 = m.Parameter(0);
    m.Branch(m.Word64NotEqual(p0, m.Int64Constant(0)), a, b);
    m.Bind(a);
    m.Return(m.Int64Constant(1));
    m.Bind(b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }
}

TEST_F(TurboshaftInstructionSelectorTest, ConditionalCompares) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    OpIndex a = m.Int32LessThan(m.Parameter(0), m.Parameter(1));
    OpIndex b = m.Int32LessThan(m.Parameter(0), m.Parameter(2));
    m.Return(m.Word32BitwiseAnd(a, b));
    Stream s = m.Build();
    EXPECT_EQ(kArm64Cmp32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_conditional_set, s[0]->flags_mode());
    EXPECT_EQ(9U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int64(),
                    MachineType::Int64(), MachineType::Int64());
    OpIndex a = m.Word64Equal(m.Parameter(0), m.Parameter(1));
    OpIndex b = m
"""


```