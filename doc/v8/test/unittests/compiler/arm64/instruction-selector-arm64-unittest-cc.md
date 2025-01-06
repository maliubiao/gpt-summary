Response:
Let's break down the thought process for analyzing this V8 C++ code snippet.

**1. Initial Understanding - What is the Goal?**

The filename `instruction-selector-arm64-unittest.cc` immediately suggests this code is for testing the *instruction selector* component of the V8 compiler, specifically for the ARM64 architecture. "Unit test" further reinforces this. The instruction selector is responsible for translating high-level, machine-independent intermediate representation (IR) of code into low-level, architecture-specific machine instructions.

**2. Identifying Key Data Structures and Helpers:**

* **`MachInst` structs:** These clearly represent machine instructions. The template structure allows defining instructions with varying numbers of operands (using `MachInst1` and `MachInst2`). The members like `constructor`, `constructor_name`, `arch_opcode`, and `machine_type` are fundamental for describing an instruction. The overloaded `operator<<` is for easy printing, helpful for debugging and test output.
* **`Shift` struct:**  This looks like a specialization for instructions involving shifts, combining a `MachInst2` with an `AddressingMode`.
* **`BuildConstant` function:**  A utility function to create constant nodes in the IR, handling both 32-bit and 64-bit integers based on the `MachineType`.
* **Arrays of instructions (e.g., `kLogicalInstructions`, `kAddSubInstructions`):** These are central. They define the sets of instructions the unit tests will exercise. The naming conventions (e.g., "Logical", "AddSub") are very informative.
* **`InstructionSelectorTestWithParam`:** This indicates the use of Google Test's parameterized tests, where the tests run multiple times with different input parameters (the instruction data structures).
* **`StreamBuilder` and `Stream`:** These are likely part of V8's internal testing framework for building and inspecting the generated instruction streams.

**3. Deconstructing the Test Structure:**

The code uses the Google Test framework (evident from `TEST_P`, `TEST_F`, `ASSERT_EQ`, `EXPECT_EQ`, `INSTANTIATE_TEST_SUITE_P`). The tests are organized around different categories of instructions (Logical, Add/Sub, etc.).

* **Parameterized Tests (`TEST_P`):** These take a parameter (from the instruction arrays) and test the behavior of the instruction selector for that specific instruction. Common patterns emerge:
    * **`Parameter` test:**  Tests the basic case where both operands are registers (represented by `m.Parameter(0)` and `m.Parameter(1)`). It verifies the correct opcode and number of inputs/outputs.
    * **`Immediate` test:** Checks if the instruction selector correctly handles immediate values as operands. It tests both immediate-on-the-right and immediate-on-the-left scenarios (and notes commutativity for logical ops).
    * **`ShiftByImmediate` test:** Verifies the generation of instructions with immediate shift amounts.
* **Fixture Tests (`TEST_F`):** These tests are more specific and don't rely on parameterization in the same way. They often test specific combinations or edge cases:
    * Tests for immediate values on the left operand.
    * Tests for specific cases like subtracting from zero.
    * Tests for how the instruction selector handles combined operations like shifts and extends.

**4. Inferring Functionality from the Tests:**

By examining the tests, we can deduce the functionality being verified:

* **Correct Instruction Selection:** The primary goal is to ensure the instruction selector picks the *right* ARM64 instruction (`arch_opcode`) for a given IR operation.
* **Operand Handling:**  The tests confirm that the selector can handle different operand types:
    * Registers (`m.Parameter`)
    * Immediate values (`m.Int32Constant`, `m.Int64Constant`)
    * Shifted registers (using the `Shift` struct and the `BuildConstant` helper).
    * Extended registers (using operations like `m.Word32And`, `m.Word32Sar`, `m.Word32Shl`, `m.ChangeInt32ToInt64`).
* **Addressing Modes:**  The tests explicitly check the `addressing_mode()` of the generated instructions, which is crucial for how operands are accessed.
* **Commutativity:** The tests for logical operations explicitly verify that the order of operands doesn't matter when an immediate is involved.
* **Specific Instruction Properties:**  Tests like `NegImmediateOnRight` and `SubZeroOnLeft` target specific properties and optimizations related to certain instructions.

**5. Considering Potential .tq and JavaScript Relevance:**

The prompt asks about `.tq` files (Torque) and JavaScript relevance. Based on the content, this particular file doesn't *seem* to be Torque (it's C++). However, the *purpose* of the instruction selector is directly related to compiling JavaScript. The code being tested here is the lower-level machinery that makes JavaScript execution on ARM64 possible.

**6. Hypothesizing Inputs and Outputs:**

For individual tests, we can hypothesize:

* **Input:**  A specific IR graph representing an operation (e.g., a binary AND with two parameters, or an addition of a parameter and an immediate). The `StreamBuilder` helps create these mock IR graphs.
* **Output:** The expected sequence of ARM64 instructions (`Stream`) that the instruction selector *should* produce. The tests use `ASSERT_EQ` and `EXPECT_EQ` to compare the actual output with the expected output (implicitly defined by the test's assertions).

**7. Identifying Potential Programming Errors:**

While the code itself is test code, it reveals potential errors the *instruction selector* could make:

* **Incorrect opcode selection:** Choosing the wrong ARM64 instruction for a given operation.
* **Incorrect operand encoding:** Not properly encoding registers, immediates, or shift amounts in the machine instruction.
* **Incorrect addressing mode:** Selecting the wrong addressing mode, leading to incorrect memory access or operand interpretation.
* **Forgetting to handle commutativity:** Not generating the optimal instruction sequence when operand order can be changed (especially with immediates).
* **Missing optimizations:**  Not recognizing opportunities to use more efficient instructions (e.g., using a subtract with a negated immediate instead of a direct add).

**8. Summarizing the Functionality (as requested):**

Finally, we synthesize a summary based on the above observations, focusing on the core purpose and the details revealed by the code structure and tests. This leads to the kind of summary provided in the initial good answer.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/common/globals.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/backend/instruction-selector-unittest.h"

namespace v8::internal::compiler {

template <typename T>
struct MachInst {
  T constructor;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  MachineType machine_type;
};

using MachInst1 = MachInst<Node* (RawMachineAssembler::*)(Node*)>;
using MachInst2 = MachInst<Node* (RawMachineAssembler::*)(Node*, Node*)>;

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
Node* BuildConstant(InstructionSelectorTest::StreamBuilder* m, MachineType type,
                    int64_t value) {
  switch (type.representation()) {
    case MachineRepresentation::kWord32:
      return m->Int32Constant(static_cast<int32_t>(value));

    case MachineRepresentation::kWord64:
      return m->Int64Constant(value);

    default:
      UNIMPLEMENTED();
  }
  return NULL;
}

// ARM64 logical instructions.
const MachInst2 kLogicalInstructions[] = {
    {&RawMachineAssembler::Word32And, "Word32And", kArm64And32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64And, "Word64And", kArm64And,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kArm64Or32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Or, "Word64Or", kArm64Or,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kArm64Eor32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Xor, "Word64Xor", kArm64Eor,
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
    {{&RawMachineAssembler::Int32Add, "Int32Add", kArm64Add32,
      MachineType::Int32()},
     kArm64Sub32},
    {{&RawMachineAssembler::Int64Add, "Int64Add", kArm64Add,
      MachineType::Int64()},
     kArm64Sub},
    {{&RawMachineAssembler::Int32Sub, "Int32Sub", kArm64Sub32,
      MachineType::Int32()},
     kArm64Add32},
    {{&RawMachineAssembler::Int64Sub, "Int64Sub", kArm64Sub,
      MachineType::Int64()},
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
    {&RawMachineAssembler::Word32And, "Word32And", kArm64Tst32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Add, "Int32Add", kArm64Cmn32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kArm64Cmp32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64And, "Word64And", kArm64Tst,
     MachineType::Int64()}};

// ARM64 arithmetic with overflow instructions.
const MachInst2 kOvfAddSubInstructions[] = {
    {&RawMachineAssembler::Int32AddWithOverflow, "Int32AddWithOverflow",
     kArm64Add32, MachineType::Int32()},
    {&RawMachineAssembler::Int32SubWithOverflow, "Int32SubWithOverflow",
     kArm64Sub32, MachineType::Int32()},
    {&RawMachineAssembler::Int64AddWithOverflow, "Int64AddWithOverflow",
     kArm64Add, MachineType::Int64()},
    {&RawMachineAssembler::Int64SubWithOverflow, "Int64SubWithOverflow",
     kArm64Sub, MachineType::Int64()}};

// ARM64 shift instructions.
const Shift kShiftInstructions[] = {
    {{&RawMachineAssembler::Word32Shl, "Word32Shl", kArm64Lsl32,
      MachineType::Int32()},
     kMode_Operand2_R_LSL_I},
    {{&RawMachineAssembler::Word64Shl, "Word64Shl", kArm64Lsl,
      MachineType::Int64()},
     kMode_Operand2_R_LSL_I},
    {{&RawMachineAssembler::Word32Shr, "Word32Shr", kArm64Lsr32,
      MachineType::Int32()},
     kMode_Operand2_R_LSR_I},
    {{&RawMachineAssembler::Word64Shr, "Word64Shr", kArm64Lsr,
      MachineType::Int64()},
     kMode_Operand2_R_LSR_I},
    {{&RawMachineAssembler::Word32Sar, "Word32Sar", kArm64Asr32,
      MachineType::Int32()},
     kMode_Operand2_R_ASR_I},
    {{&RawMachineAssembler::Word64Sar, "Word64Sar", kArm64Asr,
      MachineType::Int64()},
     kMode_Operand2_R_ASR_I},
    {{&RawMachineAssembler::Word32Ror, "Word32Ror", kArm64Ror32,
      MachineType::Int32()},
     kMode_Operand2_R_ROR_I},
    {{&RawMachineAssembler::Word64Ror, "Word64Ror", kArm64Ror,
      MachineType::Int64()},
     kMode_Operand2_R_ROR_I}};

// ARM64 Mul/Div instructions.
const MachInst2 kMulDivInstructions[] = {
    {&RawMachineAssembler::Int32Mul, "Int32Mul", kArm64Mul32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Mul, "Int64Mul", kArm64Mul,
     MachineType::Int64()},
    {&RawMachineAssembler::Int32Div, "Int32Div", kArm64Idiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Div, "Int64Div", kArm64Idiv,
     MachineType::Int64()},
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kArm64Udiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint64Div, "Uint64Div", kArm64Udiv,
     MachineType::Int64()}};

// ARM64 FP arithmetic instructions.
const MachInst2 kFPArithInstructions[] = {
    {&RawMachineAssembler::Float64Add, "Float64Add", kArm64Float64Add,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Sub, "Float64Sub", kArm64Float64Sub,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Mul, "Float64Mul", kArm64Float64Mul,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Div, "Float64Div", kArm64Float64Div,
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
    {{&RawMachineAssembler::Float64Equal, "Float64Equal", kArm64Float64Cmp,
      MachineType::Float64()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Float64LessThan, "Float64LessThan",
      kArm64Float64Cmp, MachineType::Float64()},
     kFloatLessThan,
     kFloatGreaterThan},
    {{&RawMachineAssembler::Float64LessThanOrEqual, "Float64LessThanOrEqual",
      kArm64Float64Cmp, MachineType::Float64()},
     kFloatLessThanOrEqual,
     kFloatGreaterThanOrEqual},
    {{&RawMachineAssembler::Float32Equal, "Float32Equal", kArm64Float32Cmp,
      MachineType::Float32()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Float32LessThan, "Float32LessThan",
      kArm64Float32Cmp, MachineType::Float32()},
     kFloatLessThan,
     kFloatGreaterThan},
    {{&RawMachineAssembler::Float32LessThanOrEqual, "Float32LessThanOrEqual",
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
    {{&RawMachineAssembler::ChangeFloat32ToFloat64, "ChangeFloat32ToFloat64",
      kArm64Float32ToFloat64, MachineType::Float64()},
     MachineType::Float32()},
    {{&RawMachineAssembler::TruncateFloat64ToFloat32,
      "TruncateFloat64ToFloat32", kArm64Float64ToFloat32,
      MachineType::Float32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::ChangeInt32ToInt64, "ChangeInt32ToInt64",
      kArm64Sxtw, MachineType::Int64()},
     MachineType::Int32()},
    {{&RawMachineAssembler::ChangeUint32ToUint64, "ChangeUint32ToUint64",
      kArm64Mov32, MachineType::Uint64()},
     MachineType::Uint32()},
    {{&RawMachineAssembler::TruncateInt64ToInt32, "TruncateInt64ToInt32",
      kArchNop, MachineType::Int32()},
     MachineType::Int64()},
    {{&RawMachineAssembler::ChangeInt32ToFloat64, "ChangeInt32ToFloat64",
      kArm64Int32ToFloat64, MachineType::Float64()},
     MachineType::Int32()},
    {{&RawMachineAssembler::ChangeUint32ToFloat64, "ChangeUint32ToFloat64",
      kArm64Uint32ToFloat64, MachineType::Float64()},
     MachineType::Uint32()},
    {{&RawMachineAssembler::ChangeFloat64ToInt32, "ChangeFloat64ToInt32",
      kArm64Float64ToInt32, MachineType::Int32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::ChangeFloat64ToUint32, "ChangeFloat64ToUint32",
      kArm64Float64ToUint32, MachineType::Uint32()},
     MachineType::Float64()}};

// ARM64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {&RawMachineAssembler::Word32And, "Word32And", kArm64And32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kArm64Or32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kArm64Eor32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Shl, "Word32Shl", kArm64Lsl32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Shr, "Word32Shr", kArm64Lsr32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Sar, "Word32Sar", kArm64Asr32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Ror, "Word32Ror", kArm64Ror32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kArm64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int32Add, "Int32Add", kArm64Add32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32AddWithOverflow, "Int32AddWithOverflow",
     kArm64Add32, MachineType::Int32()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kArm64Sub32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32SubWithOverflow, "Int32SubWithOverflow",
     kArm64Sub32, MachineType::Int32()},
    {&RawMachineAssembler::Int32Mul, "Int32Mul", kArm64Mul32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Div, "Int32Div", kArm64Idiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Mod, "Int32Mod", kArm64Imod32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan", kArm64Cmp32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
     kArm64Cmp32, MachineType::Int32()},
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kArm64Udiv32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kArm64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
     kArm64Cmp32, MachineType::Uint32()},
    {&RawMachineAssembler::Uint32Mod, "Uint32Mod", kArm64Umod32,
     MachineType::Uint32()},
};

// -----------------------------------------------------------------------------
// Logical instructions.

using InstructionSelectorLogicalTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorLogicalTest, Parameter) {
  const MachInst2
Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/common/globals.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/compiler/backend/instruction-selector-unittest.h"

namespace v8::internal::compiler {

template <typename T>
struct MachInst {
  T constructor;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  MachineType machine_type;
};

using MachInst1 = MachInst<Node* (RawMachineAssembler::*)(Node*)>;
using MachInst2 = MachInst<Node* (RawMachineAssembler::*)(Node*, Node*)>;

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
Node* BuildConstant(InstructionSelectorTest::StreamBuilder* m, MachineType type,
                    int64_t value) {
  switch (type.representation()) {
    case MachineRepresentation::kWord32:
      return m->Int32Constant(static_cast<int32_t>(value));

    case MachineRepresentation::kWord64:
      return m->Int64Constant(value);

    default:
      UNIMPLEMENTED();
  }
  return NULL;
}

// ARM64 logical instructions.
const MachInst2 kLogicalInstructions[] = {
    {&RawMachineAssembler::Word32And, "Word32And", kArm64And32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64And, "Word64And", kArm64And,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kArm64Or32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Or, "Word64Or", kArm64Or,
     MachineType::Int64()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kArm64Eor32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64Xor, "Word64Xor", kArm64Eor,
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
    {{&RawMachineAssembler::Int32Add, "Int32Add", kArm64Add32,
      MachineType::Int32()},
     kArm64Sub32},
    {{&RawMachineAssembler::Int64Add, "Int64Add", kArm64Add,
      MachineType::Int64()},
     kArm64Sub},
    {{&RawMachineAssembler::Int32Sub, "Int32Sub", kArm64Sub32,
      MachineType::Int32()},
     kArm64Add32},
    {{&RawMachineAssembler::Int64Sub, "Int64Sub", kArm64Sub,
      MachineType::Int64()},
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
    {&RawMachineAssembler::Word32And, "Word32And", kArm64Tst32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Add, "Int32Add", kArm64Cmn32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kArm64Cmp32,
     MachineType::Int32()},
    {&RawMachineAssembler::Word64And, "Word64And", kArm64Tst,
     MachineType::Int64()}};

// ARM64 arithmetic with overflow instructions.
const MachInst2 kOvfAddSubInstructions[] = {
    {&RawMachineAssembler::Int32AddWithOverflow, "Int32AddWithOverflow",
     kArm64Add32, MachineType::Int32()},
    {&RawMachineAssembler::Int32SubWithOverflow, "Int32SubWithOverflow",
     kArm64Sub32, MachineType::Int32()},
    {&RawMachineAssembler::Int64AddWithOverflow, "Int64AddWithOverflow",
     kArm64Add, MachineType::Int64()},
    {&RawMachineAssembler::Int64SubWithOverflow, "Int64SubWithOverflow",
     kArm64Sub, MachineType::Int64()}};

// ARM64 shift instructions.
const Shift kShiftInstructions[] = {
    {{&RawMachineAssembler::Word32Shl, "Word32Shl", kArm64Lsl32,
      MachineType::Int32()},
     kMode_Operand2_R_LSL_I},
    {{&RawMachineAssembler::Word64Shl, "Word64Shl", kArm64Lsl,
      MachineType::Int64()},
     kMode_Operand2_R_LSL_I},
    {{&RawMachineAssembler::Word32Shr, "Word32Shr", kArm64Lsr32,
      MachineType::Int32()},
     kMode_Operand2_R_LSR_I},
    {{&RawMachineAssembler::Word64Shr, "Word64Shr", kArm64Lsr,
      MachineType::Int64()},
     kMode_Operand2_R_LSR_I},
    {{&RawMachineAssembler::Word32Sar, "Word32Sar", kArm64Asr32,
      MachineType::Int32()},
     kMode_Operand2_R_ASR_I},
    {{&RawMachineAssembler::Word64Sar, "Word64Sar", kArm64Asr,
      MachineType::Int64()},
     kMode_Operand2_R_ASR_I},
    {{&RawMachineAssembler::Word32Ror, "Word32Ror", kArm64Ror32,
      MachineType::Int32()},
     kMode_Operand2_R_ROR_I},
    {{&RawMachineAssembler::Word64Ror, "Word64Ror", kArm64Ror,
      MachineType::Int64()},
     kMode_Operand2_R_ROR_I}};

// ARM64 Mul/Div instructions.
const MachInst2 kMulDivInstructions[] = {
    {&RawMachineAssembler::Int32Mul, "Int32Mul", kArm64Mul32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Mul, "Int64Mul", kArm64Mul,
     MachineType::Int64()},
    {&RawMachineAssembler::Int32Div, "Int32Div", kArm64Idiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int64Div, "Int64Div", kArm64Idiv,
     MachineType::Int64()},
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kArm64Udiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Uint64Div, "Uint64Div", kArm64Udiv,
     MachineType::Int64()}};

// ARM64 FP arithmetic instructions.
const MachInst2 kFPArithInstructions[] = {
    {&RawMachineAssembler::Float64Add, "Float64Add", kArm64Float64Add,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Sub, "Float64Sub", kArm64Float64Sub,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Mul, "Float64Mul", kArm64Float64Mul,
     MachineType::Float64()},
    {&RawMachineAssembler::Float64Div, "Float64Div", kArm64Float64Div,
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
    {{&RawMachineAssembler::Float64Equal, "Float64Equal", kArm64Float64Cmp,
      MachineType::Float64()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Float64LessThan, "Float64LessThan",
      kArm64Float64Cmp, MachineType::Float64()},
     kFloatLessThan,
     kFloatGreaterThan},
    {{&RawMachineAssembler::Float64LessThanOrEqual, "Float64LessThanOrEqual",
      kArm64Float64Cmp, MachineType::Float64()},
     kFloatLessThanOrEqual,
     kFloatGreaterThanOrEqual},
    {{&RawMachineAssembler::Float32Equal, "Float32Equal", kArm64Float32Cmp,
      MachineType::Float32()},
     kEqual,
     kEqual},
    {{&RawMachineAssembler::Float32LessThan, "Float32LessThan",
      kArm64Float32Cmp, MachineType::Float32()},
     kFloatLessThan,
     kFloatGreaterThan},
    {{&RawMachineAssembler::Float32LessThanOrEqual, "Float32LessThanOrEqual",
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
    {{&RawMachineAssembler::ChangeFloat32ToFloat64, "ChangeFloat32ToFloat64",
      kArm64Float32ToFloat64, MachineType::Float64()},
     MachineType::Float32()},
    {{&RawMachineAssembler::TruncateFloat64ToFloat32,
      "TruncateFloat64ToFloat32", kArm64Float64ToFloat32,
      MachineType::Float32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::ChangeInt32ToInt64, "ChangeInt32ToInt64",
      kArm64Sxtw, MachineType::Int64()},
     MachineType::Int32()},
    {{&RawMachineAssembler::ChangeUint32ToUint64, "ChangeUint32ToUint64",
      kArm64Mov32, MachineType::Uint64()},
     MachineType::Uint32()},
    {{&RawMachineAssembler::TruncateInt64ToInt32, "TruncateInt64ToInt32",
      kArchNop, MachineType::Int32()},
     MachineType::Int64()},
    {{&RawMachineAssembler::ChangeInt32ToFloat64, "ChangeInt32ToFloat64",
      kArm64Int32ToFloat64, MachineType::Float64()},
     MachineType::Int32()},
    {{&RawMachineAssembler::ChangeUint32ToFloat64, "ChangeUint32ToFloat64",
      kArm64Uint32ToFloat64, MachineType::Float64()},
     MachineType::Uint32()},
    {{&RawMachineAssembler::ChangeFloat64ToInt32, "ChangeFloat64ToInt32",
      kArm64Float64ToInt32, MachineType::Int32()},
     MachineType::Float64()},
    {{&RawMachineAssembler::ChangeFloat64ToUint32, "ChangeFloat64ToUint32",
      kArm64Float64ToUint32, MachineType::Uint32()},
     MachineType::Float64()}};

// ARM64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {&RawMachineAssembler::Word32And, "Word32And", kArm64And32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Or, "Word32Or", kArm64Or32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kArm64Eor32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Shl, "Word32Shl", kArm64Lsl32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Shr, "Word32Shr", kArm64Lsr32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Sar, "Word32Sar", kArm64Asr32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Ror, "Word32Ror", kArm64Ror32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kArm64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Int32Add, "Int32Add", kArm64Add32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32AddWithOverflow, "Int32AddWithOverflow",
     kArm64Add32, MachineType::Int32()},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kArm64Sub32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32SubWithOverflow, "Int32SubWithOverflow",
     kArm64Sub32, MachineType::Int32()},
    {&RawMachineAssembler::Int32Mul, "Int32Mul", kArm64Mul32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Div, "Int32Div", kArm64Idiv32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32Mod, "Int32Mod", kArm64Imod32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan", kArm64Cmp32,
     MachineType::Int32()},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
     kArm64Cmp32, MachineType::Int32()},
    {&RawMachineAssembler::Uint32Div, "Uint32Div", kArm64Udiv32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kArm64Cmp32,
     MachineType::Uint32()},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
     kArm64Cmp32, MachineType::Uint32()},
    {&RawMachineAssembler::Uint32Mod, "Uint32Mod", kArm64Umod32,
     MachineType::Uint32()},
};

// -----------------------------------------------------------------------------
// Logical instructions.

using InstructionSelectorLogicalTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorLogicalTest, Parameter) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorLogicalTest, Immediate) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  if (type == MachineType::Int32()) {
    // Immediate on the right.
    TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
      StreamBuilder m(this, type, type);
      m.Return((m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm)));
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
      m.Return((m.*dpi.constructor)(m.Int32Constant(imm), m.Parameter(0)));
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
      m.Return((m.*dpi.constructor)(m.Parameter(0), m.Int64Constant(imm)));
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
      m.Return((m.*dpi.constructor)(m.Int64Constant(imm), m.Parameter(0)));
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

TEST_P(InstructionSelectorLogicalTest, ShiftByImmediate) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FOREACH(Shift, shift, kShiftInstructions) {
    // Only test 64-bit shifted operands with 64-bit instructions.
    if (shift.mi.machine_type != type) continue;

    TRACED_FORRANGE(int, imm, 0, ((type == MachineType::Int32()) ? 31 : 63)) {
      StreamBuilder m(this, type, type, type);
      m.Return((m.*dpi.constructor)(
          m.Parameter(0), (m.*shift.mi.constructor)(
                              m.Parameter(1), BuildConstant(&m, type, imm))));
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
      m.Return((m.*dpi.constructor)(
          (m.*shift.mi.constructor)(m.Parameter(1),
                                    BuildConstant(&m, type, imm)),
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorLogicalTest,
                         ::testing::ValuesIn(kLogicalInstructions));

// -----------------------------------------------------------------------------
// Add and Sub instructions.

using InstructionSelectorAddSubTest = InstructionSelectorTestWithParam<AddSub>;

TEST_P(InstructionSelectorAddSubTest, Parameter) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.mi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorAddSubTest, ImmediateOnRight) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, type, type);
    m.Return(
        (m.*dpi.mi.constructor)(m.Parameter(0), BuildConstant(&m, type, imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorAddSubTest, NegImmediateOnRight) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, type, type);
    m.Return(
        (m.*dpi.mi.constructor)(m.Parameter(0), BuildConstant(&m, type, -imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.negate_arch_opcode, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorAddSubTest, ShiftByImmediateOnRight) {
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
      m.Return((m.*dpi.mi.constructor)(
          m.Parameter(0), (m.*shift.mi.constructor)(
                              m.Parameter(1), BuildConstant(&m, type, imm))));
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

TEST_P(InstructionSelectorAddSubTest, UnsignedExtendByte) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.mi.constructor)(
      m.Parameter(0), m.Word32And(m.Parameter(1), m.Int32Constant(0xFF))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorAddSubTest, UnsignedExtendHalfword) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.mi.constructor)(
      m.Parameter(0), m.Word32And(m.Parameter(1), m.Int32Constant(0xFFFF))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorAddSubTest, SignedExtendByte) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.mi.constructor)(
      m.Parameter(0),
      m.Word32Sar(m.Word32Shl(m.Parameter(1), m.Int32Constant(24)),
                  m.Int32Constant(24))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorAddSubTest, SignedExtendHalfword) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.mi.constructor)(
      m.Parameter(0),
      m.Word32Sar(m.Word32Shl(m.Parameter(1), m.Int32Constant(16)),
                  m.Int32Constant(16))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_SXTH, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorAddSubTest, SignedExtendWord) {
  const AddSub dpi = GetParam();
  const MachineType type = dpi.mi.machine_type;
  if (type != MachineType::Int64()) return;
  StreamBuilder m(this, type, type, type);
  m.Return((m.*dpi.mi.constructor)(m.Parameter(0),
                                   m.ChangeInt32ToInt64(m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R_SXTW, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorAddSubTest,
                         ::testing::ValuesIn(kAddSubInstructions));

TEST_F(InstructionSelectorTest, AddImmediateOnLeft) {
  // 32-bit add.
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Int32Constant(imm), m.Parameter(0)));
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
    m.Return(m.Int64Add(m.Int64Constant(imm), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, SubZeroOnLeft) {
  {
    // 32-bit subtract.
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Int32Sub(m.Int32Constant(0), m.Parameter(0)));
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
    m.Return(m.Int64Sub(m.Int64Constant(0), m.Parameter(0)));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sub, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(0)->IsImmediate());
    EXPECT_EQ(0, s.ToInt64(s[0]->InputAt(0)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, SubZeroOnLeftWithShift) {
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
        m.Return(m.Int32Sub(
            m.Int32Constant(0),
            (m.*shift.mi.constructor)(m.Parameter(1), m.Int32Constant(imm))));
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
        m.Return(m.Int64Sub(
            m.Int64Constant(0),
            (m.*shift.mi.constructor)(m.Parameter(1), m.Int64Constant(imm))));
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

TEST_F(InstructionSelectorTest, AddNegImmediateOnLeft) {
  // 32-bit add.
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    if (imm == 0) continue;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Int32Add(m.Int32Constant(-imm), m.Parameter(0)));
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
    m.Return(m.Int64Add(m.Int64Constant(-imm), m.Parameter(0)));
    Stream s = m.Build();

    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Sub, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt64(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, AddShiftByImmediateOnLeft) {
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
      m.Return((m.Int32Add)(
          (m.*shift.mi.constructor)(m.Parameter(1), m.Int32Constant(imm)),
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
      m.Return((m.Int64Add)(
          (m.*shift.mi.constructor)(m.Parameter(1), m.Int64Constant(imm)),
          m.Parameter(0)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
      EXPECT_EQ(shift.mode, s[0]->address
"""


```