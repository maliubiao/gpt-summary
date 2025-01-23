Response:
The user wants to understand the functionality of the given C++ code snippet. This code is a unit test file for the Turboshaft instruction selector in the V8 JavaScript engine, specifically targeting the RISC-V 64-bit architecture.

Here's a breakdown of the thought process to analyze the code and generate the response:

1. **Identify the Core Purpose:** The file name `turboshaft-instruction-selector-riscv64-unittest.cc` clearly indicates that this is a unit test file for the instruction selector component of the Turboshaft compiler on RISC-V 64-bit. Instruction selectors are responsible for translating high-level intermediate representation (IR) operations into machine-specific instructions.

2. **Analyze Includes:** The included headers provide valuable context.
    - `src/codegen/machine-type.h`: Deals with machine-specific data types.
    - `src/common/globals.h`:  Contains global definitions and flags.
    - `src/compiler/turboshaft/assembler.h`: Likely provides tools for building assembly code.
    - `src/compiler/turboshaft/operations.h`: Defines the IR operations being tested.
    - `src/compiler/turboshaft/representations.h`:  Deals with data representation in the compiler.
    - `src/objects/objects-inl.h`:  Relates to V8's object model.
    - `test/unittests/compiler/backend/turboshaft-instruction-selector-unittest.h`: The base class for these tests.

3. **Examine the Namespaces:** The code resides within nested namespaces: `v8::internal::compiler::turboshaft`. This confirms the location and purpose within the V8 project.

4. **Understand the `MachInst` Structures:**  The `MachInst` templates are crucial. They represent a mapping between a Turboshaft operation (`TSUnop` or `TSBinop`), a descriptive name, the corresponding RISC-V opcode (`ArchOpcode`), and the machine type. This is the core of the testing framework – verifying that specific IR operations are correctly translated to specific machine instructions.

5. **Categorize Test Data:** The code defines several arrays of `MachInst` structures, grouped logically (Logical, Shift, MUL/DIV, MOD, FPArith, etc.). This suggests that the tests cover different categories of instructions.

6. **Analyze the Test Structure:**  The code uses Google Test (`TEST_P`, `INSTANTIATE_TEST_SUITE_P`).
    - `TEST_P`: Indicates a parameterized test. The tests are designed to run with different inputs provided by the parameters.
    - `INSTANTIATE_TEST_SUITE_P`: Sets up the parameters for the tests, using the predefined arrays of `MachInst` structures.
    - The core of each test typically involves:
        - Creating a `StreamBuilder` to construct a sequence of IR operations.
        - Emitting a specific IR operation (e.g., `m.Emit(cmp.mi.op, ...)`).
        - Building the stream (`m.Build()`).
        - Assertions (`ASSERT_EQ`, `EXPECT_EQ`) to verify the generated machine instructions (opcode, input/output counts, flags, etc.).

7. **Identify Specific Test Cases:**  Within the parameterized tests, look for the core logic. For example, in `TurboshaftInstructionSelectorFPCmpTest`, it checks if a floating-point comparison operation (`TSBinop::kFloat64Equal`, etc.) generates the correct RISC-V comparison instruction (`kRiscvCmpD`) and sets the appropriate flags (`kFlags_set`, `cmp.cond`).

8. **Look for Non-Parameterized Tests (Using `TEST_F`):** These tests often focus on more specific scenarios or combinations of operations, like the tests for `Word32ShlWithWord32And` or `Word32SarWithWord32Shl`, which check for instruction fusion or optimization patterns.

9. **Consider Edge Cases and Specific Behaviors:** The comments and specific test cases (like the ones involving `COMPRESS_POINTERS_BOOL`) hint at platform-specific behaviors or optimizations being tested.

10. **Relate to JavaScript (If Applicable):**  Think about how the tested operations map to JavaScript code. For instance, bitwise operations (`&`, `|`, `^`), arithmetic operations (`+`, `-`, `*`, `/`, `%`), and comparisons are directly translatable.

11. **Code Logic Reasoning (Hypothetical Inputs and Outputs):** For a test like `TurboshaftInstructionSelectorShiftTest`, if the input is a `Word32ShiftLeft` operation with a value `x` and a shift amount `5`, the expected output is a RISC-V `shl32` instruction with `x` as the source register and `5` as an immediate value.

12. **Common Programming Errors:**  Relate the tested operations to common mistakes. For example, incorrect understanding of signed vs. unsigned right shifts can lead to bugs, and these tests might implicitly cover the correct handling of such operations. Integer overflow or underflow during arithmetic operations could also be relevant, although the immediate focus here is instruction selection.

13. **Address the `.tq` Question:**  Explicitly check the file extension. In this case, it's `.cc`, so it's C++, not Torque.

14. **Structure the Response:** Organize the findings into clear sections: overall functionality, relation to JavaScript, code logic reasoning, common programming errors, and a summary for part 1.

By following these steps, we can systematically analyze the code snippet and provide a comprehensive and accurate explanation of its purpose and functionality.
这是v8/test/unittests/compiler/riscv64/turboshaft-instruction-selector-riscv64-unittest.cc的V8源代码，它是一个**单元测试文件**，专门用于测试 **Turboshaft 编译器**中 **RISC-V 64位架构**的 **指令选择器 (Instruction Selector)** 的功能。

**具体功能归纳如下：**

1. **测试指令选择器对各种 Turboshaft IR 操作的正确指令选择:**
   - 该文件包含了针对 RISC-V64 架构的各种算术运算、逻辑运算、位移运算、比较运算、类型转换等操作的测试用例。
   - 每个测试用例都模拟了一个 Turboshaft IR 操作，并断言指令选择器是否正确地将其转换为预期的 RISC-V64 汇编指令。

2. **测试特定指令的参数和属性:**
   - 测试用例会检查生成的 RISC-V64 指令的操作码 (`arch_opcode()`)、输入操作数的数量 (`InputCount()`)、输出操作数的数量 (`OutputCount()`)、标志位设置 (`flags_mode()`) 和标志位条件 (`flags_condition()`) 等属性是否正确。
   - 对于立即数操作，还会检查立即数的值是否正确。

3. **涵盖不同数据类型:**
   - 测试用例覆盖了 `int32_t`、`uint32_t`、`int64_t`、`uint64_t`、`float32` 和 `float64` 等多种数据类型的操作，确保指令选择器对不同类型的数据都能正确处理。

4. **测试指令融合和优化:**
   - 一些测试用例（例如 `Word32ShlWithWord32And` 和 `Word64SarWithWord32Shl`）旨在测试指令选择器是否能够将多个 Turboshaft IR 操作融合为更高效的单个 RISC-V64 指令。

5. **使用参数化测试提高测试覆盖率:**
   -  使用了 Google Test 框架的参数化测试 (`TEST_P`, `INSTANTIATE_TEST_SUITE_P`)，通过不同的参数组合来测试同一类操作的不同变体，有效地提高了测试覆盖率。例如，对于二元运算，会遍历 `kLogicalInstructions`、`kShiftInstructions` 等数组中定义的不同操作码进行测试。

**关于 .tq 结尾：**

文件 `v8/test/unittests/compiler/riscv64/turboshaft-instruction-selector-riscv64-unittest.cc` 的结尾是 `.cc`，这表示它是一个 **C++ 源代码文件**。如果文件以 `.tq` 结尾，则表示它是一个 **V8 Torque 源代码文件**。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 JavaScript 功能的关系：**

该测试文件直接关系到 JavaScript 代码的编译和执行效率。Turboshaft 是 V8 的新一代编译器，指令选择器作为其关键组成部分，负责将高级的 JavaScript 操作转换为底层的机器指令。如果指令选择器工作不正确，会导致生成的机器码效率低下甚至出现错误，从而影响 JavaScript 代码的性能和正确性。

**JavaScript 示例：**

以下 JavaScript 代码的执行会涉及到该测试文件中测试的某些操作：

```javascript
function test(a, b) {
  let sum = a + b;          // 测试 kAddSubInstructions 中的加法操作
  let andResult = a & b;     // 测试 kLogicalInstructions 中的按位与操作
  let shifted = a << 2;      // 测试 kShiftInstructions 中的左移操作
  let greaterThan = a > b;  // 测试 kCmpInstructions 中的大于比较操作
  let floatSum = 1.5 + 2.5;  // 测试 kFPArithInstructions 中的浮点数加法操作
  return sum + andResult + shifted + (greaterThan ? 1 : 0) + floatSum;
}

console.log(test(5, 3));
```

当 V8 执行这段 JavaScript 代码时，Turboshaft 编译器会将这些 JavaScript 操作转换为中间表示，然后指令选择器会根据目标架构（RISC-V64）选择相应的机器指令。该测试文件就是用来确保这个指令选择过程的正确性。

**代码逻辑推理 (假设输入与输出):**

假设 `TurboshaftInstructionSelectorLogicalTest` 中的一个测试用例，其参数 `dpi` 为 `{TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd", kRiscvAnd32, MachineType::Int32()}`。

**假设输入：**

- `m.Parameter(0)` 代表一个 `int32_t` 类型的输入值，假设其虚拟寄存器 ID 为 `V0`。
- `m.Parameter(1)` 代表另一个 `int32_t` 类型的输入值，假设其虚拟寄存器 ID 为 `V1`。

**代码逻辑：**

`m.Return(m.Emit(dpi.op, m.Parameter(0), m.Parameter(1)));` 会生成一个表示按位与操作的 Turboshaft IR 节点。

**预期输出：**

`Stream s = m.Build();` 构建指令流后，`s[0]` 应该是表示 RISC-V64 按位与操作的指令。

- `s[0]->arch_opcode()` 应该等于 `kRiscvAnd32`。
- `s[0]->InputCount()` 应该等于 `2`。
- `s[0]->OutputCount()` 应该等于 `1`。
- `s[0]->InputAt(0)` 应该引用虚拟寄存器 `V0`。
- `s[0]->InputAt(1)` 应该引用虚拟寄存器 `V1`。
- `s[0]->Output()` 应该引用一个新的虚拟寄存器，用于存储按位与的结果。

**涉及用户常见的编程错误：**

虽然这个测试文件主要关注编译器内部的正确性，但它所测试的操作与用户常见的编程错误密切相关，例如：

1. **位运算错误：** 用户可能不理解位运算的原理，导致位与、位或、位异或等操作的结果与预期不符。例如，错误地使用 `&` 代替 `&&` 进行逻辑判断。

   ```javascript
   let a = 5; // 0101
   let b = 3; // 0011
   let result = a & b; // 0001 (十进制 1) - 用户可能误以为是逻辑与的结果 true

   if (a & b) { // 这种情况会进入 if 块，因为 1 是 truthy 值
       console.log("This will be printed, which might be unexpected.");
   }

   if (a > 0 && b > 0) { // 正确的逻辑与判断
       console.log("This is the correct way to check if both are positive.");
   }
   ```

2. **移位运算错误：** 用户可能不清楚有符号右移和无符号右移的区别，或者对移位溢出没有正确的认识。

   ```javascript
   let num = -8; // 二进制补码表示 ...11111000
   let signedShift = num >> 2;   // 有符号右移，结果可能是 ...11111110 (-2)
   let unsignedShift = num >>> 2; // 无符号右移，结果会变成一个很大的正数

   console.log(signedShift);
   console.log(unsignedShift);
   ```

3. **类型转换错误：**  用户可能没有意识到 JavaScript 中的隐式类型转换，或者在进行数值计算时没有显式地进行类型转换，导致精度丢失或计算错误。虽然这里的测试用例关注的是编译器对类型转换操作的处理，但如果编译器处理错误，就会放大用户代码中的类型转换问题。

   ```javascript
   let numStr = "10";
   let num = 5;
   let result = numStr + num; // "105" (字符串拼接，可能不是用户期望的加法)
   let correctResult = parseInt(numStr) + num; // 15 (正确的加法)
   ```

**总结 - 第 1 部分的功能:**

该 C++ 源代码文件是 V8 引擎中 Turboshaft 编译器针对 RISC-V64 架构的指令选择器单元测试。它通过定义一系列测试用例，验证指令选择器能否将各种 Turboshaft IR 操作正确地转换为对应的 RISC-V64 汇编指令，并检查生成指令的属性是否符合预期。这有助于确保 V8 在 RISC-V64 平台上编译和执行 JavaScript 代码的正确性和效率。

### 提示词
```
这是目录为v8/test/unittests/compiler/riscv64/turboshaft-instruction-selector-riscv64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/riscv64/turboshaft-instruction-selector-riscv64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
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
    {TSBinop::kWord32BitwiseAnd, "Word32BitwiseAnd", kRiscvAnd32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseAnd, "Word64BitwiseAnd", kRiscvAnd,
     MachineType::Int64()},
    {TSBinop::kWord32BitwiseOr, "Word32BitwiseOr", kRiscvOr32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseOr, "Word64BitwiseOr", kRiscvOr,
     MachineType::Int64()},
    {TSBinop::kWord32BitwiseXor, "Word32BitwiseXor", kRiscvXor32,
     MachineType::Int32()},
    {TSBinop::kWord64BitwiseXor, "Word64BitwiseXor", kRiscvXor,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// Shift instructions.
// ----------------------------------------------------------------------------

const MachInst2 kShiftInstructions[] = {
    {TSBinop::kWord32ShiftLeft, "Word32ShiftLeft", kRiscvShl32,
     MachineType::Int32()},
    {TSBinop::kWord64ShiftLeft, "Word64ShiftLeft", kRiscvShl64,
     MachineType::Int64()},
    // {TSBinop::kWord32BitwiseShr, "Word32Shr", kRiscvShr32,
    //  MachineType::Int32()},
    // {TSBinop::kWord64BitwiseShr, "Word64Shr", kRiscvShr64,
    //  MachineType::Int64()},
    {TSBinop::kWord32ShiftRightLogical, "Word32ShiftRightLogical", kRiscvShr32,
     MachineType::Int32()},
    {TSBinop::kWord64ShiftRightLogical, "Word64ShiftRightLogical", kRiscvShr64,
     MachineType::Int64()},
    {TSBinop::kWord32ShiftRightArithmetic, "Word32ShiftRightArithmetic",
     kRiscvSar32, MachineType::Int32()},
    {TSBinop::kWord64ShiftRightArithmetic, "Word64ShiftRightArithmetic",
     kRiscvSar64, MachineType::Int64()},
    {TSBinop::kWord32RotateRight, "Word32Ror", kRiscvRor32,
     MachineType::Int32()},
    {TSBinop::kWord64RotateRight, "Word64Ror", kRiscvRor64,
     MachineType::Int64()}};

// ----------------------------------------------------------------------------
// MUL/DIV instructions.
// ----------------------------------------------------------------------------

const MachInst2 kMulDivInstructions[] = {
    {TSBinop::kWord32Mul, "Word32Mul", kRiscvMul32, MachineType::Int32()},
    {TSBinop::kInt32Div, "Int32Div", kRiscvDiv32, MachineType::Int32()},
    {TSBinop::kUint32Div, "Uint32Div", kRiscvDivU32, MachineType::Uint32()},
    {TSBinop::kWord64Mul, "Word64Mul", kRiscvMul64, MachineType::Int64()},
    {TSBinop::kInt64Div, "Int64Div", kRiscvDiv64, MachineType::Int64()},
    {TSBinop::kUint64Div, "Uint64Div", kRiscvDivU64, MachineType::Uint64()},
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
    {TSBinop::kWord32Add, "Word32Add", kRiscvAdd32, MachineType::Int32()},
    {TSBinop::kWord64Add, "Word64Add", kRiscvAdd64, MachineType::Int64()},
    {TSBinop::kWord32Sub, "Int32Sub", kRiscvSub32, MachineType::Int32()},
    {TSBinop::kWord64Sub, "Word64Sub", kRiscvSub64, MachineType::Int64()}};

// ----------------------------------------------------------------------------
// IntArithTest instructions, one node.
// ----------------------------------------------------------------------------

const MachInst1 kAddSubOneInstructions[] = {
    // {TSBinop::kInt32Neg, "Int32Neg", kRiscvSub32,
    //  MachineType::Int32()},
    // {TSBinop::kInt64Neg, "Int64Neg", kRiscvSub64,
    //  MachineType::Int64()}
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
    // {{TSBinop::kWord32BitwiseEqual, "Word32Equal", kRiscvCmp,
    //   MachineType::Int32()},
    //  COMPRESS_POINTERS_BOOL ? 3U : 1U},
    // {{TSBinop::kWord32BitwiseNotEqual, "Word32NotEqual", kRiscvCmp,
    //   MachineType::Int32()},
    //  COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kInt32LessThan, "Int32LessThan", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kInt32LessThanOrEqual, "Int32LessThanOrEqual", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kInt32GreaterThan, "Int32GreaterThan", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kInt32GreaterThanOrEqual, "Int32GreaterThanOrEqual", kRiscvCmp,
      MachineType::Int32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kUint32LessThan, "Uint32LessThan", kRiscvCmp,
      MachineType::Uint32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U},
    {{TSBinop::kUint32LessThanOrEqual, "Uint32LessThanOrEqual", kRiscvCmp,
      MachineType::Uint32()},
     COMPRESS_POINTERS_BOOL ? 3U : 1U}};

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

const Conversion kFloat64RoundInstructions[] = {
    // {{TSBinop::kFloat64RoundUp, "Float64RoundUp", kRiscvCeilWD,
    //   MachineType::Int32()},
    //  MachineType::Float64()},
    // {{TSBinop::kFloat64RoundDown, "Float64RoundDown", kRiscvFloorWD,
    //   MachineType::Int32()},
    //  MachineType::Float64()},
    // {{TSBinop::kFloat64RoundTiesEven, "Float64RoundTiesEven",
    //   kRiscvRoundWD, MachineType::Int32()},
    //  MachineType::Float64()},
    // {{TSBinop::kFloat64RoundTruncate, "Float64RoundTruncate",
    //   kRiscvTruncWD, MachineType::Int32()},
    //  MachineType::Float64()}
};

const Conversion kFloat32RoundInstructions[] = {
    // {{TSBinop::kFloat32RoundUp, "Float32RoundUp", kRiscvCeilWS,
    //   MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSBinop::kFloat32RoundDown, "Float32RoundDown", kRiscvFloorWS,
    //   MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSBinop::kFloat32RoundTiesEven, "Float32RoundTiesEven",
    //   kRiscvRoundWS, MachineType::Int32()},
    //  MachineType::Float32()},
    // {{TSBinop::kFloat32RoundTruncate, "Float32RoundTruncate",
    //   kRiscvTruncWS, MachineType::Int32()},
    //  MachineType::Float32()}
};

// RISCV64 instructions that clear the top 32 bits of the destination.
const MachInst2 kCanElideChangeUint32ToUint64[] = {
    {TSBinop::kUint32Div, "Uint32Div", kRiscvDivU32, MachineType::Uint32()},
    {TSBinop::kUint32Mod, "Uint32Mod", kRiscvModU32, MachineType::Uint32()},
    // {TSBinop::kUint32MulHigh, "Uint32MulHigh", kRiscvMulHighU32,
    //  MachineType::Uint32()}
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
      type.representation() == MachineRepresentation::kWord32 &&
      cmp.expected_size == 1) {
    ASSERT_EQ(6U, s.size());

    EXPECT_EQ(cmp.mi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());

    EXPECT_EQ(kRiscvShl64, s[1]->arch_opcode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());

    EXPECT_EQ(kRiscvShl64, s[2]->arch_opcode());
    EXPECT_EQ(2U, s[2]->InputCount());
    EXPECT_EQ(1U, s[2]->OutputCount());

    EXPECT_EQ(cmp.mi.arch_opcode, s[3]->arch_opcode());
    EXPECT_EQ(2U, s[3]->InputCount());
    EXPECT_EQ(1U, s[3]->OutputCount());

    EXPECT_EQ(kRiscvAssertEqual, s[4]->arch_opcode());

    EXPECT_EQ(cmp.mi.arch_opcode, s[5]->arch_opcode());
    EXPECT_EQ(2U, s[5]->InputCount());
    EXPECT_EQ(1U, s[5]->OutputCount());
  } else {
    ASSERT_EQ(cmp.expected_size, s.size());
    if (cmp.expected_size == 3) {
      EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
      EXPECT_EQ(2U, s[0]->InputCount());
      EXPECT_EQ(1U, s[0]->OutputCount());

      EXPECT_EQ(kRiscvShl64, s[1]->arch_opcode());
      EXPECT_EQ(2U, s[1]->InputCount());
      EXPECT_EQ(1U, s[1]->OutputCount());
    }
    EXPECT_EQ(cmp.mi.arch_opcode, s[cmp.expected_size - 1]->arch_opcode());
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

// TEST_F(TurboshaftInstructionSelectorTest, Word32ShlWithWord32And) {
//   TRACED_FORRANGE(int32_t, shift, 0, 30) {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     auto r =
//         m.Emit(TSBinop::kWord32ShiftLeft,
//               m.Emit(TSBinop::kWord32BitwiseAnd,  m.Parameter(0),
//               m.Int32Constant((1 << (31 - shift)) - 1)),
//               m.Int32Constant(shift + 1));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvShl32, s[0]->arch_opcode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(m.Parameter(0)), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word64ShlWithWord64And) {
//   TRACED_FORRANGE(int32_t, shift, 0, 62) {
//     StreamBuilder m(this, MachineType::Int64(), MachineType::Int64());
//     auto p0 = m.Parameter(0);
//     auto r = m.Emit(TSBinop::kWord64ShiftLeft,
//                            m.Emit(TSBinop::kWord64BitwiseAnd, p0,
//                                   m.Int64Constant((1L << (63 - shift)) - 1)),
//                            m.Int64Constant(shift + 1));
//     m.Return(r);
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
//     ASSERT_EQ(1U, s[0]->OutputCount());
//     EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->Output()));
//   }
// }

// TEST_F(TurboshaftInstructionSelectorTest, Word32SarWithWord32Shl) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     auto p0 = m.Parameter(0);
//     auto r =
//         m.Emit(TSBinop::kWord32ShiftRightLogical,
//           m.Emit(TSBinop::kWord32ShiftLeft, p0, m.Int32Constant(24)),
//           m.Int32Constant(24));
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
//     auto p0 = m.Parameter(0);
//     auto r =
//         m.Emit(TSBinop::kWord32ShiftRightLogical,
//           m.Emit(TSBinop::kWord32ShiftLeft, p0, m.Int32Constant(16)),
//           m.Int32Constant(16));
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
//     auto p0 = m.Parameter(0);
//     auto r =
//         m.Emit(TSBinop::kWord32ShiftRightLogical,
//           m.Emit(TSBinop::kWord32ShiftLeft, p0, m.Int32Constant(32)),
//           m.Int32Constant(32));
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

// using TurboshaftInstructionSelectorIntArithOneTest =
//     TurboshaftInstructionSelectorTestWithParam<MachInst1>;

// TEST_P(TurboshaftInstructionSelectorIntArithOneTest, Parameter) {
//   const MachInst1 intpa = GetParam();
//   StreamBuilder m(this, intpa.machine_type, intpa.machine_type,
//                   intpa.machine_type);
//   m.Return(m.Emit(intpa.op, m.Parameter(0)));
//   Stream s = m.Build();
//   ASSERT_EQ(1U, s.size());
//   EXPECT_EQ(intpa.arch_opcode, s[0]->arch_opcode());
//   EXPECT_EQ(2U, s[0]->InputCount());
//   EXPECT_EQ(1U, s[0]->OutputCount());
// }

// INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
//                          TurboshaftInstructionSelectorIntArithOneTest,
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

TEST_F(TurboshaftInstructionSelectorTest, ChangesFromToSmi) {
  // {
  //   StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
  //   m.Return(m.Emit(TSUnop::kTruncateInt64ToInt32,
  //       m.Emit(TSBinop::kWord64ShiftRightArithmetic, m.Parameter(0),
  //       m.Int32Constant(32))));
  //   Stream s = m.Build();
  //   ASSERT_EQ(1U, s.size());
  //   EXPECT_EQ(kRiscvSar64, s[0]->arch_opcode());
  //   EXPECT_EQ(kMode_None, s[0]->addressing_mode());
  //   ASSERT_EQ(2U, s[0]->InputCount());
  //   EXPECT_EQ(1U, s[0]->OutputCount());
  // }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Emit(TSBinop::kWord64ShiftLeft,
                    m.Emit(TSUnop::kChangeInt32ToInt64, m.Parameter(0)),
                    m.Int32Constant(32)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kRiscvShl64, s[0]->arch_opcode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

using CombineChangeFloat64ToInt32WithRoundFloat64 =
    TurboshaftInstructionSelectorTestWithParam<Conversion>;

// TEST_P(CombineChangeFloat64ToInt32WithRoundFloat64, Parameter) {
//   {
//     const Conversion conv = GetParam();
//     StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
//     m.Return(m.Emit(TSUnop::kReversibleFloat64ToInt32,
//                     (m.Emit(conv.mi.op, m.Parameter(0)))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
//     EXPECT_EQ(kMode_None, s[0]->addressing_mode());
//     ASSERT_EQ(1U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

// INSTANTIATE_TEST_SUITE_P(TurboshaftInstructionSelectorTest,
//                          CombineChangeFloat64ToInt32WithRoundFloat64,
//                          ::testing::ValuesIn(kFloat64RoundInstructions));

using CombineChangeFloat32ToInt32WithRoundFloat32 =
    TurboshaftInstructionSelectorTestWithParam<Conversion>;

// TEST_P(CombineChangeFloat32ToInt32WithRoundFloat32, Parameter) {
//   {
//     const Conversion conv = GetParam();
//     StreamBuilder m(this, conv.mi.machine_type, conv.src_machine_type);
//     m.Return(m.Emit(TSUnop::kReversibleFloat64ToInt32,
//                     m.Emit(TSUnop::kChangeFloat32ToFloat64,
//                            (m.Emit(conv.mi.op, m.Parameter(0))))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(conv.mi.arch_opcode, s[0]->arch_opcode());
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

// TEST_F(TurboshaftInstructionSelectorTest, CombineShiftsWithDivMod) {
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Emit(TSBinop::kInt32Div,
//       m.Emit(TSBinop::kWord64ShiftRightLogical, m.Parameter(0),
//       m.Int32Constant(32)), m.Emit(TSBinop::kWord64ShiftRightLogical,
//       m.Parameter(0), m.Int32Constant(32))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvDiv64, s[0]->arch_opcode());
//     EXPECT_EQ(kMode_None, s[0]->addressing_mode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
//   {
//     StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
//     m.Return(m.Emit(TSBinop::kInt32Mod,
//       m.Emit(TSBinop::kWord64ShiftRightLogical, m.Parameter(0),
//       m.Int32Constant(32)), m.Emit(TSBinop::kWord64ShiftRightLogical,
//       m.Parameter(0), m.Int32Constant(32))));
//     Stream s = m.Build();
//     ASSERT_EQ(1U, s.size());
//     EXPECT_EQ(kRiscvMod64, s[0]->arch_opcode());
//     EXPECT_EQ(kMode_None, s[0]->addressing_mode());
//     ASSERT_EQ(2U, s[0]->InputCount());
//     EXPECT_EQ(1U, s[0]->OutputCount());
//   }
// }

TEST_F(TurboshaftInstructionSelectorTest, ChangeWord32ToWord64AfterLoad) {
  // For each case, test that the conversion is merged into the load
  // operation.
  // ChangeUint32ToUint64(Load_Uint8) -> Lbu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLbu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int8) -> Lb
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Int8(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLb, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeUint32ToUint64(Load_Uint16) -> Lhu
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeUint32ToUint64,
               m.Load(MachineType::Uint16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLhu, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_EQ(2U, s[1]->InputCount());
    EXPECT_EQ(1U, s[1]->OutputCount());
  }
  // ChangeInt32ToInt64(Load_Int16) -> Lh
  {
    StreamBuilder m(this, MachineType::Int64(), MachineType::Pointer(),
                    MachineType::Int64());
    m.Return(
        m.Emit(TSUnop::kChangeInt32ToInt64,
               m.Load(MachineType::Int16(), m.Parameter(0), m.Parameter(1))));
    Stream s = m.Build();
    ASSERT_EQ(2U, s.size());
    EXPECT_EQ(kRiscvLh, s[1]->arch_opcode());
    EXPECT_EQ(kMode_MRI, s[1]->addressing_mode());
    EXPECT_
```