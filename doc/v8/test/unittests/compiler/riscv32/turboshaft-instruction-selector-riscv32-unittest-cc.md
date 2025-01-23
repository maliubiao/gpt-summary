Response:
Let's break down the thought process for analyzing the given C++ code snippet and fulfilling the request.

**1. Understanding the Core Request:**

The primary goal is to understand the *functionality* of the provided C++ code. The prompt gives context: it's a unit test file for the RISC-V 32-bit instruction selector within the V8 JavaScript engine's Turboshaft compiler.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for recognizable patterns and keywords. Key observations include:

* `#include`: Indicates dependencies on other V8 components.
* `namespace v8::internal::compiler::turboshaft`:  Confirms the location within the V8 codebase.
* `template <typename Op> struct MachInst`: Suggests a data structure for representing machine instructions.
* `using MachInst1 = ...; using MachInst2 = ...;`: Creates aliases, likely for unary and binary operations.
* `struct IntCmp`, `struct FPCmp`, `struct Conversion`: More data structures, hinting at different categories of instructions.
* `const ... k...Instructions[]`:  Arrays of these structures, implying a collection of test cases.
* `using TurboshaftInstructionSelector...Test = ...`: Defines test fixture types using Google Test (`TEST_P`, `INSTANTIATE_TEST_SUITE_P`).
* `TEST_P(...)`, `INSTANTIATE_TEST_SUITE_P(...)`:  Google Test macros for parameterized tests.
* `StreamBuilder`, `m.Emit(...)`, `m.Return(...)`:  Suggests a mechanism for building sequences of instructions within the tests.
* `ASSERT_EQ(...)`, `EXPECT_EQ(...)`, `ASSERT_TRUE(...)`: Google Test assertion macros.
* `kRiscv...`:  Prefix for RISC-V specific opcodes (e.g., `kRiscvAdd32`, `kRiscvCmpD`).
* `MachineType::...`:  Represents data types (e.g., `Int32`, `Float64`).
* Comments like "// Logical instructions.", "// Shift instructions." which provide high-level organization.

**3. Deconstructing `MachInst` and Related Structures:**

The `MachInst` template is central. It appears to represent a mapping between a high-level Turboshaft operation (`Op`) and its corresponding RISC-V instruction (`arch_opcode`). The other structures (`IntCmp`, `FPCmp`, `Conversion`) seem to augment `MachInst` with additional information relevant to specific instruction types (e.g., expected size for comparisons, flags conditions for floating-point comparisons, source machine type for conversions).

**4. Identifying Test Patterns:**

The `TEST_P` macros indicate parameterized tests. The `INSTANTIATE_TEST_SUITE_P` macros then populate these tests with values from the `k...Instructions` arrays. The structure of the tests generally follows this pattern:

1. **Get Parameters:** `const ... cmp = GetParam();`
2. **Build Instruction Stream:** Use `StreamBuilder` to create a sequence of instructions based on the test parameters.
3. **Emit Operation:** `m.Emit(cmp.mi.op, ...)` generates the instruction under test.
4. **Return Result:** `m.Return(...)` signifies the end of the instruction sequence.
5. **Build Stream:** `Stream s = m.Build();` finalizes the instruction sequence.
6. **Assertions:** Use `ASSERT_EQ` and `EXPECT_EQ` to verify the properties of the generated instructions (opcode, input/output counts, flags, etc.).

**5. Inferring Functionality:**

Based on the observed patterns, the primary functionality of this file is to **test the instruction selection logic for the RISC-V 32-bit architecture within the Turboshaft compiler**. It verifies that:

* Given a specific high-level Turboshaft operation (e.g., `TSBinop::kWord32Add`), the instruction selector correctly chooses the corresponding RISC-V opcode (e.g., `kRiscvAdd32`).
* The generated RISC-V instruction has the correct number of inputs and outputs.
* For comparison instructions, the correct flags are set.
* For immediate operands, the immediate value is correctly encoded.

**6. Addressing Specific Parts of the Request:**

* **Listing Functionality:** The inferred functionality directly answers this.
* **.tq Extension:** The code uses `.cc`, not `.tq`, so it's C++, not Torque.
* **Relationship to JavaScript:** This code directly contributes to the compilation of JavaScript code. When V8 executes JavaScript, Turboshaft compiles parts of it into machine code. This file tests a specific part of that compilation process for RISC-V. A JavaScript example would be any code that uses the operations being tested (e.g., addition, subtraction, comparisons).
* **Code Logic Inference (Input/Output):**  The input is the high-level Turboshaft operation and its operands (parameters or constants). The output is the selected RISC-V instruction with its operands. For example, input could be "Word32Add" with two parameters of type `Int32`. The expected output would be a `kRiscvAdd32` instruction taking those two parameters as input.
* **Common Programming Errors:**  While this specific *test* code doesn't directly *demonstrate* common programming errors in general JavaScript development, it implicitly helps *prevent* errors in the *compiler*. If the instruction selector were implemented incorrectly, this test code would catch those errors. A general example in C++ related to instruction selection might be incorrectly mapping a high-level operation to the wrong low-level instruction, leading to incorrect behavior.
* **Summarizing Functionality for Part 1:** The summary would reiterate that this file tests the RISC-V 32-bit instruction selector within Turboshaft.

**7. Iteration and Refinement:**

During the process, there might be some back-and-forth. For instance, noticing the `//TODO(riscv):` comments indicates areas where the test coverage is incomplete. This information is also valuable to include in the analysis. Similarly, understanding the role of `StreamBuilder` and the assertion macros is crucial for a complete picture.

By following these steps, a comprehensive understanding of the C++ code's functionality can be achieved, allowing for accurate answers to the prompt's questions.这是v8/test/unittests/compiler/riscv32/turboshaft-instruction-selector-riscv32-unittest.cc的第1部分，其主要功能是**测试 Turboshaft 编译器在 RISC-V 32 位架构下的指令选择器 (Instruction Selector) 的正确性**。

更具体地说，它通过一系列单元测试来验证：

1. **不同的 Turboshaft 中间表示 (Operations) 是否能正确地映射到相应的 RISC-V 汇编指令 (ArchOpcode)。**  例如，它测试 `TSBinop::kWord32Add` 是否被正确地选择为 `kRiscvAdd32` 指令。
2. **生成的 RISC-V 指令是否具有正确的输入和输出数量。**
3. **对于某些指令（例如比较指令），是否设置了正确的标志条件 (FlagsCondition)。**
4. **对于需要立即数 (immediate) 的指令，立即数是否被正确地处理。**

**关于代码的细节：**

* **头文件包含:** 包含了 Turboshaft 编译器、代码生成和通用全局设置相关的头文件。
* **`MachInst` 结构体:**  定义了一个模板结构体 `MachInst`，用于表示一个机器指令，包含 Turboshaft 操作类型 (`Op`)，构造函数名称 (`constructor_name`)，RISC-V 汇编指令码 (`arch_opcode`) 和机器类型 (`machine_type`)。
* **别名 `MachInst1` 和 `MachInst2`:**  为一元和二元操作定义了别名，方便使用。
* **`IntCmp` 和 `FPCmp` 结构体:**  用于表示整数和浮点比较指令，除了包含 `MachInst2` 的信息外，还包含了期望的指令大小 (`expected_size`) 和标志条件 (`cond`)。
* **`Conversion` 结构体:**  用于表示类型转换指令，包含 `MachInst1` 和源机器类型 (`src_machine_type`)。
* **`kFPCmpInstructions`, `kLogicalInstructions`, `kShiftInstructions`, `kMulDivInstructions`, `kModInstructions`, `kFPArithInstructions`, `kAddSubInstructions`, `kAddSubOneInstructions`, `kCmpInstructions`, `kConversionInstructions`, `kFloat32RoundInstructions` 等常量数组:**  这些数组包含了各种 Turboshaft 操作与其期望的 RISC-V 指令码的映射关系，以及其他相关信息，构成了测试用例的数据。
* **`TurboshaftInstructionSelectorFPCmpTest`, `TurboshaftInstructionSelectorCmpTest`, ... 等测试类:** 使用 Google Test 框架定义的参数化测试类，用于针对不同的指令类型进行测试。
* **`TEST_P` 宏:**  定义了具体的测试用例，例如 `TEST_P(TurboshaftInstructionSelectorFPCmpTest, Parameter)` 用于测试浮点比较指令的参数选择。
* **`INSTANTIATE_TEST_SUITE_P` 宏:**  使用 `k...Instructions` 数组中的数据实例化测试套件，为每个数组元素生成一个测试用例。
* **`StreamBuilder` 类:**  用于构建 Turboshaft 指令流，方便在测试中生成中间表示。
* **`m.Emit()`:**  用于在指令流中发射一个 Turboshaft 操作。
* **`m.Return()`:**  表示指令流的返回。
* **`Stream s = m.Build();`:**  构建最终的指令流。
* **`ASSERT_EQ()`, `EXPECT_EQ()`, `ASSERT_TRUE()`:**  Google Test 提供的断言宏，用于验证生成的指令是否符合预期。

**它不是 Torque 源代码:** 文件名以 `.cc` 结尾，表明它是 C++ 源代码，而不是 Torque 源代码（Torque 源代码以 `.tq` 结尾）。

**与 Javascript 的功能关系:**

这个文件中的代码直接关系到 V8 JavaScript 引擎的性能。Turboshaft 是 V8 的一个优化编译器，它将 JavaScript 代码转换为高效的机器代码。指令选择器是编译器后端的一个关键组件，负责将中间表示转换为目标架构（这里是 RISC-V 32 位）的机器指令。如果指令选择器工作不正确，生成的机器代码可能效率低下，甚至会导致程序崩溃或产生错误的结果。

**Javascript 举例说明:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 编译 `add` 函数时，Turboshaft 会生成中间表示，其中 `a + b` 可能会被表示为 `TSBinop::kWord32Add` 操作（如果 `a` 和 `b` 被推断为 32 位整数）。  `turboshaft-instruction-selector-riscv32-unittest.cc` 中的测试就确保了这个 `TSBinop::kWord32Add` 操作会被正确地转换为 RISC-V 的 `kRiscvAdd32` 指令。

**代码逻辑推理 (假设输入与输出):**

假设 `kAddSubInstructions` 数组包含以下元素:

```c++
const MachInst2 kAddSubInstructions[] = {
    {TSBinop::kWord32Add, "Int32Add", kRiscvAdd32, MachineType::Int32()},
    {TSBinop::kWord32Sub, "Int32Sub", kRiscvSub32, MachineType::Int32()}
};
```

并且有一个测试用例使用了 `TurboshaftInstructionSelectorIntArithTwoTest` 和 `kAddSubInstructions` 中的 `TSBinop::kWord32Add`：

**假设输入:**

* Turboshaft 操作: `TSBinop::kWord32Add`
* 输入操作数的机器类型: `MachineType::Int32()`

**预期输出:**

* 生成的 RISC-V 指令码: `kRiscvAdd32`
* 指令的输入数量: 2
* 指令的输出数量: 1

测试代码会构建一个指令流，包含一个 `TSBinop::kWord32Add` 操作，并断言生成的指令的 `arch_opcode()` 是 `kRiscvAdd32`，`InputCount()` 是 2，`OutputCount()` 是 1。

**涉及用户常见的编程错误 (编译器测试主要防止编译器自身的错误，但可以间接避免用户程序的一些问题):**

虽然这个单元测试主要关注编译器内部的正确性，但如果指令选择器存在错误，可能会导致一些看似合理的 JavaScript 代码在 RISC-V 平台上运行出错。例如：

* **类型不匹配:** 如果指令选择器错误地处理了不同类型的操作数，可能会导致类型不匹配的 RISC-V 指令被生成，从而导致运行时错误。
* **溢出或精度问题:**  对于数值计算，如果指令选择器选择了错误的指令，可能会导致计算结果溢出或精度丢失。

**举例说明一个潜在的编译器错误，如果测试没有覆盖到可能导致的问题:**

假设指令选择器在处理 `TSBinop::kWord32ShiftLeft` 时，对于移位量大于等于 32 的情况没有正确处理，错误地生成了与预期不同的 RISC-V 指令。

**用户代码:**

```javascript
let x = 5;
let y = x << 32; // 在 JavaScript 中，移位量会取模 32，结果为 5 << 0 = 5
console.log(y);
```

**潜在的错误编译器行为 (如果测试不完善):**

指令选择器可能错误地生成了实际执行移位 32 位的 RISC-V 指令，而不是应该生成的移位 0 位的指令，导致 `y` 的值不是预期的 5。  这个单元测试通过测试各种移位量的场景，可以防止这种错误的发生。

**功能归纳 (第1部分):**

这个 C++ 源代码文件是 V8 JavaScript 引擎中 Turboshaft 编译器针对 RISC-V 32 位架构的指令选择器单元测试的**第一部分**。它的主要功能是**验证 Turboshaft 编译器能否正确地将各种中间表示的操作映射到对应的 RISC-V 汇编指令**，并确保生成的指令具有正确的属性（如输入输出数量、标志位等）。 通过参数化测试和预定义的指令映射关系，它系统地测试了算术、逻辑、比较、移位、乘除法、取模以及类型转换等多种操作的指令选择逻辑的正确性。 它是确保 V8 在 RISC-V 平台上生成正确且高效机器代码的关键组成部分。

### 提示词
```
这是目录为v8/test/unittests/compiler/riscv32/turboshaft-instruction-selector-riscv32-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/riscv32/turboshaft-instruction-selector-riscv32-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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

namespace v8 {
namespace internal {
namespace compiler {
namespace turboshaft {
namespace {
template <typename Op>
struct MachInst {
  Op op;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  MachineType machine_type;
};

template <typename T>
std::ostream& operator<<(std::ostream& os, const MachInst<T>& mi) {
  return os << mi.constructor_name;
}

using MachInst1 = MachInst<TSUnop>;
using MachInst2 = MachInst<TSBinop>;

// To avoid duplicated code IntCmp helper structure
// is created. It contains MachInst2 with two nodes and expected_size
// because different cmp instructions have different size.
struct IntCmp {
  MachInst2 mi;
  uint32_t expected_size;
};

struct FPCmp {
  MachInst2 mi;
  FlagsCondition cond;
};

const FPCmp kFPCmpInstructions[] = {
    {{TSBinop::kFloat64Equal, "Float64Equal", kRiscvCmpD,
      MachineType::Float64()},
     kEqual},
    {{TSBinop::kFloat64LessThan, "Float64LessThan", kRiscvCmpD,
      MachineType::Float64()},
     kUnsignedLessThan},
    {{TSBinop::kFloat64LessThanOrEqual, "Float64LessThanOrEqual", kRiscvCmpD,
      MachineType::Float64()},
     kUnsignedLessThanOrEqual},
    //TODO(riscv): ADD kFloat64GreaterThan/kFloat64GreaterThanOrEqual
    // in turboshaft-unittestes.
    // {{TSBinop::kFloat64GreaterThan, "Float64GreaterThan",
    //   kRiscvCmpD, MachineType::Float64()},
    //  kUnsignedLessThan},
    // {{TSBinop::kFloat64GreaterThanOrEqual,
    //   "Float64GreaterThanOrEqual", kRiscvCmpD, MachineType::Float64()},
    //  kUnsignedLessThanOrEqual}
};

struct Conversion {
  // The machine_type field in MachInst1 represents the destination type.
  MachInst1 mi;
  MachineType src_machine_type;
};

// ----------------------------------------------------------------------------
// Logical instructions.
// ----------------------------------------------------------------------------

const MachInst2 kLogicalInstructions[] = {
    {TSBinop::kWord32BitwiseAnd, "Word32And", kRiscvAnd, MachineType::Int32()},
    {TSBinop::kWord32BitwiseOr, "Word32Or", kRiscvOr, MachineType::Int32()},
    {TSBinop::kWord32BitwiseXor, "Word32Xor", kRiscvXor, MachineType::Int32()}};

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------
const MachInst2 kShiftInstructions[] = {
    {TSBinop::kWord32ShiftLeft, "Word32Shl", kRiscvShl32, MachineType::Int32()},
    {TSBinop::kWord32ShiftRightLogical, "Word32Shr", kRiscvShr32,
     MachineType::Int32()},
    {TSBinop::kWord32ShiftRightArithmetic, "Word32Sar", kRiscvSar32,
     MachineType::Int32()},
    {TSBinop::kWord32RotateRight, "Word32Ror", kRiscvRor32,
     MachineType::Int32()}};

// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------

const MachInst2 kMulDivInstructions[] = {
    {TSBinop::kWord32Mul, "Int32Mul", kRiscvMul32, MachineType::Int32()},
    {TSBinop::kInt32Div, "Int32Div", kRiscvDiv32, MachineType::Int32()},
    {TSBinop::kUint32Div, "Uint32Div", kRiscvDivU32, MachineType::Uint32()},
    {TSBinop::kFloat64Mul, "Float64Mul", kRiscvMulD, MachineType::Float64()},
    {TSBinop::kFloat64Div, "Float64Div", kRiscvDivD, MachineType::Float64()}};

// ----------------------------------------------------------------------------
// MOD instructions.
// ----------------------------------------------------------------------------

const MachInst2 kModInstructions[] = {
    {TSBinop::kInt32Mod, "Int32Mod", kRiscvMod32, MachineType::Int32()},
    {TSBinop::kUint32Mod, "Uint32Mod", kRiscvModU32, MachineType::Int32()},
    // {TSBinop::kFloat64Mod, "Float64Mod", kRiscvModD,
    //  MachineType::Float64()}
};

// ----------------------------------------------------------------------------
// Arithmetic FPU instructions.
// ----------------------------------------------------------------------------

const MachInst2 kFPArithInstructions[] = {
    {TSBinop::kFloat64Add, "Float64Add", kRiscvAddD, MachineType::Float64()},
    {TSBinop::kFloat64Sub, "Float64Sub", kRiscvSubD, MachineType::Float64()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, two nodes.
// ----------------------------------------------------------------------------

const MachInst2 kAddSubInstructions[] = {
    {TSBinop::kWord32Add, "Int32Add", kRiscvAdd32, MachineType::Int32()},
    {TSBinop::kWord32Sub, "Int32Sub", kRiscvSub32, MachineType::Int32()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, one node.
// ----------------------------------------------------------------------------

const MachInst1 kAddSubOneInstructions[] = {
    // {TSBinop::kInt32Neg, "Int32Neg", kRiscvSub32,
    //  MachineType::Int32()},
};

// ----------------------------------------------------------------------------
// Arithmetic compare instructions.
// ----------------------------------------------------------------------------

const IntCmp kCmpInstructions[] = {
    // {{TSBinop::kWordEqual, "WordEqual", kRiscvCmp,
    //   MachineType::Int64()},
    //  1U},
    // {{TSBinop::kWordNotEqual, "WordNotEqual", kRiscvCmp,
    //   MachineType::Int64()},
    //  1U},
    // {{TSBinop::kWord32Equal, "Word32Equal", kRiscvCmp,
    //   MachineType::Int32()},
    //  1U},
    // {{TSBinop::kWord32NotEqual, "Word32NotEqual", kRiscvCmp,
    //   MachineType::Int32()},
    //  1U},
    {{TSBinop::kInt32LessThan, "Int32LessThan", kRiscvCmp,
      MachineType::Int32()},
     1U},
    {{TSBinop::kInt32LessThanOrEqual, "Int32LessThanOrEqual", kRiscvCmp,
      MachineType::Int32()},
     1U},
    {{TSBinop::kInt32GreaterThan, "Int32GreaterThan", kRiscvCmp,
      MachineType::Int32()},
     1U},
    {{TSBinop::kInt32GreaterThanOrEqual, "Int32GreaterThanOrEqual", kRiscvCmp,
      MachineType::Int32()},
     1U},
    {{TSBinop::kUint32LessThan, "Uint32LessThan", kRiscvCmp,
      MachineType::Uint32()},
     1U},
    {{TSBinop::kUint32LessThanOrEqual, "Uint32LessThanOrEqual", kRiscvCmp,
      MachineType::Uint32()},
     1U}};

// ----------------------------------------------------------------------------
// Conversion instructions.
// ----------------------------------------------------------------------------

const Conversion kConversionInstructions[] = {
    // Conversion instructions are related to machine_operator.h:
    // FPU conversions:
    // Convert representation of integers between float64 and int32/uint32.
    // The precise rounding mode and handling of out of range inputs are *not*
    // defined for these operators, since they are intended only for use with
    // integers.
    {{TSUnop::kChangeInt32ToFloat64, "ChangeInt32ToFloat64", kRiscvCvtDW,
      MachineType::Float64()},
     MachineType::Int32()},
    {{TSUnop::kChangeUint32ToFloat64, "ChangeUint32ToFloat64", kRiscvCvtDUw,
      MachineType::Float64()},
     MachineType::Int32()},

    // {{TSUnop::kChangeFloat64ToInt32, "ChangeFloat64ToInt32",
    //   kRiscvTruncWD, MachineType::Float64()},
    //  MachineType::Int32()},

    // {{TSUnop::kChangeFloat64ToUint32, "ChangeFloat64ToUint32",
    //   kRiscvTruncUwD, MachineType::Float64()},
    //  MachineType::Int32()}
};

const Conversion kFloat32RoundInstructions[] = {
    // {{TSUnop::kFloat32RoundUp, "Float32RoundUp",
    //   kRiscvFloat32RoundUp, MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSUnop::kFloat32RoundDown, "Float32RoundDown",
    //   kRiscvFloat32RoundDown, MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSUnop::Float32RoundTiesEven, "Float32RoundTiesEven",
    //   kRiscvFloat32RoundTiesEven, MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSUnop::Float32RoundTruncate, "Float32RoundTruncate",
    //   kRiscvFloat32RoundTruncate, MachineType::Int32()},
    //  MachineType::Float32()}
};

}  // namespace

using TurboshaftInstructionSelectorFPCmpTest =
    TurboshaftInstructionSelectorTestWithParam<FPCmp>;

TEST_P(TurboshaftInstructionSelectorFPCmpTest, Parameter) {
  const FPCmp cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), cmp.mi.machine_type,
                  cmp.mi.machine_type);
  m.Return(m.Emit(cmp.mi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.cond, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorFPCmpTest,
                         ::testing::ValuesIn(kFPCmpInstructions));

// ----------------------------------------------------------------------------
// Arithmetic compare instructions integers
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorCmpTest =
    TurboshaftInstructionSelectorTestWithParam<IntCmp>;

TEST_P(TurboshaftInstructionSelectorCmpTest, Parameter) {
  const IntCmp cmp = GetParam();
  const MachineType type = cmp.mi.machine_type;
  StreamBuilder m(this, type, type, type);
  m.Return(m.Emit(cmp.mi.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();

  if (v8_flags.debug_code &&
      type.representation() == MachineRepresentation::kWord32) {
    ASSERT_EQ(1U, s.size());

    EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  } else {
    ASSERT_EQ(cmp.expected_size, s.size());
    EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorCmpTest,
                         ::testing::ValuesIn(kCmpInstructions));

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorShiftTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorShiftTest, Immediate) {
  const MachInst2 dpi = GetParam();
  const MachineType type = dpi.machine_type;
  TRACED_FORRANGE(int32_t, imm, 0,
                  ((1 << ElementSizeLog2Of(type.representation())) * 8) - 1) {
    StreamBuilder m(this, type, type);
    m.Return(m.Emit(dpi.op, m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorShiftTest,
                         ::testing::ValuesIn(kShiftInstructions));

// ----------------------------------------------------------------------------
// Logical instructions.
// ----------------------------------------------------------------------------
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorLogicalTest,
                         ::testing::ValuesIn(kLogicalInstructions));

// TEST_F(TurboshaftInstructionSelectorTest, Word32XorMinusOneWithParameter) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Word32Xor(m.Parameter(0), m.Int32Constant(-1)));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvNor, s[0]->arch_opcode());
//     EXPECT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Word32Xor(m.Int32Constant(-1), m.Parameter(0)));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvNor, s[0]->arch_opcode());
//     EXPECT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word32XorMinusOneWithWord32Or) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Word32Xor(m.Word32Or(m.Parameter(0), m.Parameter(0)),
//                          m.Int32Constant(-1)));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvNor, s[0]->arch_opcode());
//     EXPECT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Word32Xor(m.Int32Constant(-1),
//                          m.Word32Or(m.Parameter(0), m.Parameter(0))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvNor, s[0]->arch_opcode());
//     EXPECT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word32ShlWithWord32And) {
//   TRACED_FORRANGE(int32_t, shift, 0, 30) {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     Node* const p0 = m.Parameter(0);
//     Node* const r =
//         m.Word32Shl(m.Word32And(p0, m.Int32Constant((1 << (31 - shift)) -
//         1)),
//                     m.Int32Constant(shift + 1));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvShl32, s[0]->arch_opcode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
// }

// // TEST_F(TurboshaftInstructionSelectorTest, Word64ShlWithWord64And) {
// //   TRACED_FORRANGE(int32_t, shift, 0, 62) {
// //     StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
// //     Node* const p0 = m.Parameter(0);
// //     Node* const r =
// //         m.Word64Shl(m.Word64And(p0, m.Int64Constant((1L << (63 - shift)) -
// //         1)),
// //                     m.Int64Constant(shift + 1));
// //     m.Return(r);
// //     Stream s = m.Build();
// //     ASSERT_EQ(1U, s.size());
// //     EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
// //     ASSERT_EQ(2U, s[0]->InputCount());
// //     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
// //     ASSERT_EQ(1U, s[0]->OutputCount());
// //     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
// //   }
// // }

// TEST_F(TurboshaftInstructionSelectorTest, Word32SarWithWord32Shl) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     Node* const p0 = m.Parameter(0);
//     Node* const r =
//         m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(24)),
//         m.Int32Constant(24));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvSignExtendByte, s[0]->arch_opcode());
//     ASSERT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     Node* const p0 = m.Parameter(0);
//     Node* const r =
//         m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(16)),
//         m.Int32Constant(16));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvSignExtendShort, s[0]->arch_opcode());
//     ASSERT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     Node* const p0 = m.Parameter(0);
//     Node* const r =
//         m.Word32Sar(m.Word32Shl(p0, m.Int32Constant(32)),
//         m.Int32Constant(32));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvShl32, s[0]->arch_opcode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     EXPECT_EQ(0, s.ToInt32(s[0]->InputAt(1)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
// }

// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorMulDivTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorMulDivTest, Parameter) {
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorMulDivTest,
                         ::testing::ValuesIn(kMulDivInstructions));

// ----------------------------------------------------------------------------
// MOD instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorModTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorModTest, Parameter) {
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

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorModTest,
                         ::testing::ValuesIn(kModInstructions));

// ----------------------------------------------------------------------------
// Floating point instructions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorFPArithTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorFPArithTest, Parameter) {
  const MachInst2 fpa = GetParam();
  StreamBuilder m(this, fpa.machine_type, fpa.machine_type, fpa.machine_type);
  m.Return(m.Emit(fpa.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(fpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorFPArithTest,
                         ::testing::ValuesIn(kFPArithInstructions));
// ----------------------------------------------------------------------------
// Integer arithmetic
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorIntArithTwoTest =
    TurboshaftInstructionSelectorTestWithParam<MachInst2>;

TEST_P(TurboshaftInstructionSelectorIntArithTwoTest, Parameter) {
  const MachInst2 intpa = GetParam();
  StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
                  intpa.machine_type);
  m.Return(m.Emit(intpa.op, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorIntArithTwoTest,
                         ::testing::ValuesIn(kAddSubInstructions));

// ----------------------------------------------------------------------------
// One node.
// ----------------------------------------------------------------------------

// using InstructionSelectorIntArithOneTest =
//     InstructionSelectorTestWithParam<MachInst1>;

// TEST_P(TurboshaftInstructionSelectorIntArithOneTest, Parameter) {
//   const MachInst1 intpa = GetParam();
//   StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
//                   intpa.machine_type);
//   m.Return((m.*intpa.constructor)(m.Parameter(0)));
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
//   EXPECT_EQ(2U, s[0]->InputCount());
//   EXPECT_EQ(1U, s[0]->OutputCount());
// }

// INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
//                          InstructionSelectorIntArithOneTest,
//                          ::testing::ValuesIn(kAddSubOneInstructions));
// ----------------------------------------------------------------------------
// Conversions.
// ----------------------------------------------------------------------------
using TurboshaftInstructionSelectorConversionTest =
    TurboshaftInstructionSelectorTestWithParam<Conversion>;

TEST_P(TurboshaftInstructionSelectorConversionTest, Parameter) {
  const Conversion conv = GetParam();
  StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
  m.Return(m.Emit(conv.mi.op, (m.Parameter(0))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
                         TurboshaftInstructionSelectorConversionTest,
                         ::testing::ValuesIn(kConversionInstructions));

using TurboshaftCombineChangeFloat32ToInt32WithRoundFloat32 =
    TurboshaftInstructionSelectorTestWithParam<Conversion>;

// TEST_P(TurboshaftCombineChangeFloat32ToInt32WithRoundFloat32, Parameter) {
//   {
//     const Conversion conv = GetParam();
//     StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
//     m.Return(m.ChangeFloat64ToInt32(
//         m.ChangeFloat32ToFloat64((m.*conv.mi.constructor)(m.Parameter(0)))));
//     Stream s = m.Build();
//     ASSERT_EQ(2U, s.size());
//     EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
//     EXPECT_EQ(kRiscvTruncWS, s[1]->arch_opcode());
//     EXPECT_EQ(kMode_None, s[0]->addressing_mode());
//     ASSERT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

// INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
//                          CombineChangeFloat32ToInt32WithRoundFloat32,
//                          ::testing::ValuesIn(kFloat32RoundInstructions));

TEST_F(TurboshaftInstructionSelectorTest,
       ChangeFloat64ToInt32OfChangeFloat32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
    m.Return(m.Emit(TSUnop::kReversibleFloat64ToInt32,
                    m.Emit(TSUnop::kChangeFloat32ToFloat64, m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvTruncWS, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(TurboshaftInstructionSelectorTest,
       TruncateFloat64ToFloat32OfChangeInt32ToFloat64) {
  {
    StreamBuilder m(this, MachineType::Float32(), MachineType::Int32());
    m.Return(m.Emit(TSUnop::kTruncateFloat64ToFloat32,
                    m.Emit(TSUnop::kChangeInt32ToFloat64, m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvCvtSW, s[0]->arch_opcode());
    EXPECT_EQ(kMode_None, s[0]->addressing_mode());
    ASSERT_EQ(1U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
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
    {MachineType::Float64(), kRiscvLoadDouble, kRiscvStoreDouble}};

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
      286,   655,   1362,
```