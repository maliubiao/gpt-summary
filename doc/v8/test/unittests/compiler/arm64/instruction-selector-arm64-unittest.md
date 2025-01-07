Response: The user wants a summary of the provided C++ code file and an explanation of its functionality, including its relationship to JavaScript if any.

**Plan:**

1. **Identify the core purpose of the file:** Look for keywords like "unittest", "instruction-selector", and the architecture "arm64".
2. **Analyze the data structures and functions:**  Pay attention to `struct` definitions like `MachInst`, `Shift`, `AddSub`, `FPCmp`, and `Conversion`, as well as the usage of `RawMachineAssembler` and `InstructionSelectorTest`.
3. **Determine the testing methodology:** Observe how the tests are structured using `TEST_P` and `TEST_F`, and how they build and verify instruction streams.
4. **Establish the connection to JavaScript:**  Consider how instruction selection relates to the V8 JavaScript engine.
5. **Provide a concise summary:**  Synthesize the findings into a clear explanation of the file's function.
6. **Illustrate with a JavaScript example:** If a connection exists, create a simple JavaScript code snippet and explain how the tested instructions might be involved in its compilation.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于测试在ARM64架构上的指令选择器（Instruction Selector）组件的功能。

**功能归纳:**

这个文件的主要功能是为ARM64架构上的指令选择器编写单元测试。指令选择器是编译器后端的一个重要阶段，它负责将中间表示（IR）的指令转换为目标机器的实际机器指令。

具体来说，这个文件做了以下事情：

1. **定义了用于描述机器指令的数据结构:**  例如 `MachInst`, `Shift`, `AddSub`, `FPCmp`, `Conversion` 等结构体，用于方便地表示不同的ARM64指令及其属性（如构造函数、助记符、操作码、机器类型等）。
2. **定义了各种ARM64指令的常量数组:**  例如 `kLogicalInstructions`, `kAddSubInstructions`, `kShiftInstructions` 等，包含了不同类型和操作的ARM64指令信息。这些数组涵盖了逻辑运算、算术运算、移位操作、浮点运算、类型转换等多种指令。
3. **编写了针对不同指令模式的单元测试:**  使用了 Google Test 框架 (`TEST_P`, `TEST_F`) 来组织和执行测试用例。这些测试用例会构造特定的中间表示代码片段（使用 `RawMachineAssembler`），然后通过指令选择器进行转换，并验证生成的机器指令序列是否符合预期。
4. **测试了指令选择器在不同操作数情况下的行为:** 包括了使用寄存器、立即数、以及移位操作等不同类型的操作数。
5. **特别关注了指令融合和优化的测试:** 例如测试了 `Add` 操作是否能够与移位操作或扩展操作进行融合，生成更高效的指令。
6. **测试了控制流指令的选择:** 例如 `Branch` 指令在与逻辑运算、比较运算结合时，指令选择器是否能正确选择合适的条件分支指令。

**与 JavaScript 的关系和 JavaScript 示例:**

指令选择器是 JavaScript 代码编译过程中的一个关键环节。当 V8 引擎需要执行 JavaScript 代码时，它会将 JavaScript 代码解析成抽象语法树（AST），然后将 AST 转换为更底层的中间表示（IR）。指令选择器的作用就是将这些与平台无关的 IR 指令翻译成特定架构（例如 ARM64）的机器指令，以便 CPU 可以直接执行。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

let x = 10;
let y = 5;
let sum = add(x, y);
console.log(sum);
```

当 V8 编译执行这段 JavaScript 代码时，`add(a, b)` 中的 `a + b` 操作会被转换成中间表示的加法指令。对于 ARM64 架构，`instruction-selector-arm64-unittest.cc` 中测试的 `Int32Add` 或 `Int64Add` 指令（取决于变量的类型）就可能被指令选择器选中，最终生成 ARM64 的 `ADD` 指令。

例如，如果 `a` 和 `b` 在编译时被推断为 32 位整数，那么可能会生成类似以下的 ARM64 汇编指令：

```assembly
ADD w0, w1, w2  // 将寄存器 w1 和 w2 的值相加，结果存储到 w0
```

这里的 `ADD` 指令就对应了 `kArm64Add32` 操作码，而在 `instruction-selector-arm64-unittest.cc` 中就有很多测试用例来验证指令选择器在各种情况下是否能够正确地选择和生成这样的 `ADD` 指令。

总而言之，`instruction-selector-arm64-unittest.cc` 这个文件是确保 V8 引擎在 ARM64 架构上能够正确高效地编译和执行 JavaScript 代码的关键组成部分。它通过大量的单元测试来验证指令选择器组件的正确性，从而保证生成的机器码的性能和可靠性。

Prompt: 
```
这是目录为v8/test/unittests/compiler/arm64/instruction-selector-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
      EXPECT_EQ(shift.mode, s[0]->addressing_mode());
      EXPECT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(0x3F & imm, 0x3F & s.ToInt64(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}

TEST_F(InstructionSelectorTest, AddUnsignedExtendByteOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Int32Add(m.Word32And(m.Parameter(0), m.Int32Constant(0xFF)),
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
    m.Return(m.Int64Add(m.Word32And(m.Parameter(0), m.Int32Constant(0xFF)),
                        m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, AddUnsignedExtendHalfwordOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Int32Add(m.Word32And(m.Parameter(0), m.Int32Constant(0xFFFF)),
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
    m.Return(m.Int64Add(m.Word32And(m.Parameter(0), m.Int32Constant(0xFFFF)),
                        m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_UXTH, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, AddSignedExtendByteOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Add(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(24)),
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
        m.Int64Add(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(24)),
                               m.Int32Constant(24)),
                   m.Parameter(1)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Add, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_SXTB, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorTest, AddSignedExtendHalfwordOnLeft) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(
        m.Int32Add(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(16)),
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
        m.Int64Add(m.Word32Sar(m.Word32Shl(m.Parameter(0), m.Int32Constant(16)),
                               m.Int32Constant(16)),
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

using InstructionSelectorAddWithPairwiseAddTest =
    InstructionSelectorTestWithParam<AddWithPairwiseAddSideAndWidth>;

TEST_P(InstructionSelectorAddWithPairwiseAddTest, AddWithPairwiseAdd) {
  AddWithPairwiseAddSideAndWidth params = GetParam();
  const MachineType type = MachineType::Simd128();
  StreamBuilder m(this, type, type, type, type);

  Node* x = m.Parameter(0);
  Node* y = m.Parameter(1);
  const Operator* pairwiseAddOp;
  if (params.width == 32 && params.isSigned) {
    pairwiseAddOp = m.machine()->I32x4ExtAddPairwiseI16x8S();
  } else if (params.width == 16 && params.isSigned) {
    pairwiseAddOp = m.machine()->I16x8ExtAddPairwiseI8x16S();
  } else if (params.width == 32 && !params.isSigned) {
    pairwiseAddOp = m.machine()->I32x4ExtAddPairwiseI16x8U();
  } else {
    pairwiseAddOp = m.machine()->I16x8ExtAddPairwiseI8x16U();
  }
  Node* pairwiseAdd = m.AddNode(pairwiseAddOp, x);
  const Operator* addOp =
      params.width == 32 ? m.machine()->I32x4Add() : m.machine()->I16x8Add();
  Node* add = params.side == LEFT ? m.AddNode(addOp, pairwiseAdd, y)
                                  : m.AddNode(addOp, y, pairwiseAdd);
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorAddWithPairwiseAddTest,
                         ::testing::ValuesIn(kAddWithPairAddTestCases));
#endif  // V8_ENABLE_WEBASSEMBLY

// -----------------------------------------------------------------------------
// Data processing controlled branches.

using InstructionSelectorDPFlagSetTest =
    InstructionSelectorTestWithParam<MachInst2>;

TEST_P(InstructionSelectorDPFlagSetTest, BranchWithParameters) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  StreamBuilder m(this, type, type, type);
  RawMachineLabel a, b;
  m.Branch((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)), &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(1));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorDPFlagSetTest,
                         ::testing::ValuesIn(kDPFlagSetInstructions));

TEST_F(InstructionSelectorTest, Word32AndBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint32_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32And(m.Parameter(0), m.Int32Constant(imm)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, Word64AndBranchWithImmediateOnRight) {
  TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint64_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64And(m.Parameter(0), m.Int64Constant(imm)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, AddBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Int32Add(m.Parameter(0), m.Int32Constant(imm)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64Cmn32, s[0]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, SubBranchWithImmediateOnRight) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Int32Sub(m.Parameter(0), m.Int32Constant(imm)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ((imm == 0) ? kArm64CompareAndBranch32 : kArm64Cmp32,
              s[0]->arch_opcode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

TEST_F(InstructionSelectorTest, Word32AndBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kLogical32Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint32_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32And(m.Int32Constant(imm), m.Parameter(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, Word64AndBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int64_t, imm, kLogical64Immediates) {
    // Skip the cases where the instruction selector would use tbz/tbnz.
    if (base::bits::CountPopulation(static_cast<uint64_t>(imm)) == 1) continue;

    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64And(m.Int64Constant(imm), m.Parameter(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, AddBranchWithImmediateOnLeft) {
  TRACED_FOREACH(int32_t, imm, kAddSubImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Int32Add(m.Int32Constant(imm), m.Parameter(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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
  MachInst<std::function<Node*(InstructionSelectorTest::StreamBuilder&, Node*,
                               uint64_t mask)>>
      mi;
  FlagsCondition cond;
};

std::ostream& operator<<(std::ostream& os, const TestAndBranch& tb) {
  return os << tb.mi;
}

const TestAndBranch kTestAndBranchMatchers32[] = {
    // Branch on the result of Word32And directly.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x, uint32_t mask)
          -> Node* { return m.Word32And(x, m.Int32Constant(mask)); },
      "if (x and mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32And(x, m.Int32Constant(mask)));
      },
      "if not (x and mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x, uint32_t mask)
          -> Node* { return m.Word32And(m.Int32Constant(mask), x); },
      "if (mask and x)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32And(m.Int32Constant(mask), x));
      },
      "if not (mask and x)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    // Branch on the result of '(x and mask) == mask'. This tests that a bit is
    // set rather than cleared which is why conditions are inverted.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32Equal(m.Word32And(x, m.Int32Constant(mask)),
                             m.Int32Constant(mask));
      },
      "if ((x and mask) == mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32Equal(
            m.Word32And(x, m.Int32Constant(mask)), m.Int32Constant(mask)));
      },
      "if ((x and mask) != mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32Equal(m.Int32Constant(mask),
                             m.Word32And(x, m.Int32Constant(mask)));
      },
      "if (mask == (x and mask))", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32Equal(
            m.Int32Constant(mask), m.Word32And(x, m.Int32Constant(mask))));
      },
      "if (mask != (x and mask))", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    // Same as above but swap 'mask' and 'x'.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32Equal(m.Word32And(m.Int32Constant(mask), x),
                             m.Int32Constant(mask));
      },
      "if ((mask and x) == mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32Equal(
            m.Word32And(m.Int32Constant(mask), x), m.Int32Constant(mask)));
      },
      "if ((mask and x) != mask)", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32Equal(m.Int32Constant(mask),
                             m.Word32And(m.Int32Constant(mask), x));
      },
      "if (mask == (mask and x))", kArm64TestAndBranch32, MachineType::Int32()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint32_t mask) -> Node* {
        return m.Word32BinaryNot(m.Word32Equal(
            m.Int32Constant(mask), m.Word32And(m.Int32Constant(mask), x)));
      },
      "if (mask != (mask and x))", kArm64TestAndBranch32, MachineType::Int32()},
     kEqual}};

using InstructionSelectorTestAndBranchTest =
    InstructionSelectorTestWithParam<TestAndBranch>;

TEST_P(InstructionSelectorTestAndBranchTest, TestAndBranch32) {
  const TestAndBranch inst = GetParam();
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(inst.mi.constructor(m, m.Parameter(0), mask), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorTestAndBranchTest,
                         ::testing::ValuesIn(kTestAndBranchMatchers32));

// TODO(arm64): Add the missing Word32BinaryNot test cases from the 32-bit
// version.
const TestAndBranch kTestAndBranchMatchers64[] = {
    // Branch on the result of Word64And directly.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x, uint64_t mask)
          -> Node* { return m.Word64And(x, m.Int64Constant(mask)); },
      "if (x and mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Word64And(x, m.Int64Constant(mask)),
                             m.Int64Constant(0));
      },
      "if not (x and mask)", kArm64TestAndBranch, MachineType::Int64()},
     kEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x, uint64_t mask)
          -> Node* { return m.Word64And(m.Int64Constant(mask), x); },
      "if (mask and x)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Word64And(m.Int64Constant(mask), x),
                             m.Int64Constant(0));
      },
      "if not (mask and x)", kArm64TestAndBranch, MachineType::Int64()},
     kEqual},
    // Branch on the result of '(x and mask) == mask'. This tests that a bit is
    // set rather than cleared which is why conditions are inverted.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Word64And(x, m.Int64Constant(mask)),
                             m.Int64Constant(mask));
      },
      "if ((x and mask) == mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Int64Constant(mask),
                             m.Word64And(x, m.Int64Constant(mask)));
      },
      "if (mask == (x and mask))", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    // Same as above but swap 'mask' and 'x'.
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Word64And(m.Int64Constant(mask), x),
                             m.Int64Constant(mask));
      },
      "if ((mask and x) == mask)", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual},
    {{[](InstructionSelectorTest::StreamBuilder& m, Node* x,
         uint64_t mask) -> Node* {
        return m.Word64Equal(m.Int64Constant(mask),
                             m.Word64And(m.Int64Constant(mask), x));
      },
      "if (mask == (mask and x))", kArm64TestAndBranch, MachineType::Int64()},
     kNotEqual}};

using InstructionSelectorTestAndBranchTest64 =
    InstructionSelectorTestWithParam<TestAndBranch>;

TEST_P(InstructionSelectorTestAndBranchTest64, TestAndBranch64) {
  const TestAndBranch inst = GetParam();
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(inst.mi.constructor(m, m.Parameter(0), mask), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(inst.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(inst.cond, s[0]->flags_condition());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(bit, s.ToInt64(s[0]->InputAt(1)));
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorTestAndBranchTest64,
                         ::testing::ValuesIn(kTestAndBranchMatchers64));

TEST_F(InstructionSelectorTest, Word64AndBranchWithOneBitMaskOnRight) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64And(m.Parameter(0), m.Int64Constant(mask)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, Word64AndBranchWithOneBitMaskOnLeft) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64And(m.Int64Constant(mask), m.Parameter(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, TestAndBranch64EqualWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b, c;
    Node* n = m.Word64And(m.Parameter(0), m.Int64Constant(mask));
    m.Branch(m.Word64Equal(n, m.Int64Constant(0)), &a, &b);
    m.Bind(&a);
    m.Branch(m.Word64Equal(n, m.Int64Constant(3)), &b, &c);
    m.Bind(&c);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, TestAndBranch64AndWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b, c;
    m.Branch(m.Word64And(m.Parameter(0), m.Int64Constant(mask)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(4U, s[0]->InputCount());
  }
}

TEST_F(InstructionSelectorTest, TestAndBranch32AndWhenCanCoverFalse) {
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = uint32_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b, c;
    m.Branch(m.Word32And(m.Parameter(0), m.Int32Constant(mask)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));

    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64TestAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(4U, s[0]->InputCount());
  }
}

TEST_F(InstructionSelectorTest, Word32EqualZeroAndBranchWithOneBitMask) {
  TRACED_FORRANGE(int, bit, 0, 31) {
    uint32_t mask = 1 << bit;
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32Equal(m.Word32And(m.Int32Constant(mask), m.Parameter(0)),
                           m.Int32Constant(0)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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
    RawMachineLabel a, b;
    m.Branch(
        m.Word32NotEqual(m.Word32And(m.Int32Constant(mask), m.Parameter(0)),
                         m.Int32Constant(0)),
        &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, Word64EqualZeroAndBranchWithOneBitMask) {
  TRACED_FORRANGE(int, bit, 0, 63) {
    uint64_t mask = uint64_t{1} << bit;
    StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
    RawMachineLabel a, b;
    m.Branch(m.Word64Equal(m.Word64And(m.Int64Constant(mask), m.Parameter(0)),
                           m.Int64Constant(0)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
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
    RawMachineLabel a, b;
    m.Branch(
        m.Word64NotEqual(m.Word64And(m.Int64Constant(mask), m.Parameter(0)),
                         m.Int64Constant(0)),
        &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
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

TEST_F(InstructionSelectorTest, CompareAgainstZeroAndBranch) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(p0, &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word32BinaryNot(p0), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch32, s[0]->arch_opcode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  }
}

TEST_F(InstructionSelectorTest, EqualZeroAndBranch) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word32Equal(p0, m.Int32Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word32NotEqual(p0, m.Int32Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
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
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word64Equal(p0, m.Int64Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
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
    RawMachineLabel a, b;
    Node* p0 = m.Parameter(0);
    m.Branch(m.Word64NotEqual(p0, m.Int64Constant(0)), &a, &b);
    m.Bind(&a);
    m.Return(m.Int64Constant(1));
    m.Bind(&b);
    m.Return(m.Int64Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArm64CompareAndBranch, s[0]->arch_opcode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    EXPEC
"""


```