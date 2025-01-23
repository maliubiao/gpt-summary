Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a part of the V8 JavaScript engine, specifically the instruction selector for the RISC-V 32-bit architecture.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file `instruction-selector-riscv32.cc` suggests it's responsible for selecting RISC-V instructions to implement higher-level operations.

2. **Scan for key classes/templates:** The code uses templates like `RiscvOperandGeneratorT` and `InstructionSelectorT`. These likely handle operand generation and instruction emission.

3. **Look for `Visit` methods:** The presence of numerous `Visit` methods (e.g., `VisitLoad`, `VisitStore`, `VisitInt32Add`) strongly indicates that this code handles the translation of different intermediate representation (IR) nodes into RISC-V instructions. The naming convention of these methods (e.g., `VisitWord32And`) directly maps to specific operations.

4. **Examine helper functions:** Functions like `EmitLoad` and `CanBeImmediate` suggest the presence of logic for handling specific instruction patterns and optimizations (e.g., immediate operands, root register addressing).

5. **Check for architecture-specific details:** The code uses RISC-V specific instruction mnemonics (e.g., `kRiscvAdd32`, `kRiscvLw`) and addressing modes.

6. **Consider different "Adapters":** The use of templates with an `Adapter` parameter hints that this code might be used in different contexts or with different IRs (like Turbofan and Turboshaft).

7. **Address the `.tq` question:**  The prompt asks about the `.tq` extension. Based on the provided code, it's a `.cc` file, so it's C++, not Torque.

8. **Consider JavaScript relevance:**  Since this is part of V8, the generated instructions ultimately execute JavaScript code. Look for examples of how the implemented operations map to JavaScript features.

9. **Think about code logic and examples:**  For operations like addition, loading, and storing, it's possible to create simple input/output scenarios.

10. **Consider common programming errors:**  Relate the code's functionality to potential errors, such as incorrect memory access or type mismatches.

11. **Synthesize the information:** Combine the observations into a concise summary of the file's purpose and key functionalities.

**Self-Correction/Refinement:**

* Initial thought: Focus solely on instruction selection. Refinement: Recognize the role of operand generation and the distinction between Turbofan and Turboshaft.
* Initial thought:  Only mention the direct translation of IR nodes. Refinement: Include the handling of optimizations like immediate operands and root register addressing.
* Initial thought:  Only provide technical descriptions. Refinement:  Add JavaScript examples to connect the code to its higher-level purpose.
这是 V8 JavaScript 引擎中用于 RISC-V 32 位架构的指令选择器（Instruction Selector）的 C++ 源代码文件。指令选择器的主要功能是将高级的、平台无关的中间表示（IR，Intermediate Representation）操作转换为底层的、特定于 RISC-V 32 位架构的机器指令。

以下是根据代码片段归纳的功能点：

1. **指令生成核心:**  `InstructionSelectorT<Adapter>` 类及其模板特化是指令选择的核心。它负责遍历 IR 图（可能是来自 Turbofan 或 Turboshaft 编译器的输出），并为每个 IR 节点选择合适的 RISC-V 指令。

2. **操作数生成:** `RiscvOperandGeneratorT<Adapter>` 类负责生成 RISC-V 指令的操作数，包括寄存器、立即数和内存地址。它提供了一些辅助方法，如 `GetIntegerConstantValue` 用于获取整数常量的值，以及 `CanBeImmediate` 用于判断一个值是否可以作为立即数使用。

3. **支持不同的 IR 适配器:** 代码使用了模板 `Adapter`，这表明它可以与不同的 V8 编译器后端集成，例如 Turbofan（通过 `TurbofanAdapter`）和 Turboshaft（通过 `TurboshaftAdapter`）。针对不同的编译器后端，指令选择的实现可能略有不同。

4. **Load 指令选择 (`VisitLoad`)**:
   - 负责将 IR 中的 Load 操作转换为 RISC-V 的加载指令 (如 `kRiscvLb`, `kRiscvLh`, `kRiscvLw`, `kRiscvLoadFloat`, `kRiscvLoadDouble`, `kRiscvRvvLd`)。
   - 实现了基于基址寄存器和偏移量的寻址模式。
   - 针对全局变量（ExternalReference）和 root 寄存器进行了优化，可以直接使用 root 寄存器加上偏移量进行加载。
   - 考虑了立即数偏移的情况，如果偏移量可以作为立即数，则直接使用立即数寻址模式。

5. **Store 指令选择 (`VisitStore`)**:
   - 负责将 IR 中的 Store 操作转换为 RISC-V 的存储指令 (如 `kRiscvSb`, `kRiscvSh`, `kRiscvSw`, `kRiscvStoreFloat`, `kRiscvStoreDouble`, `kRiscvRvvSt`)。
   - 同样支持基于基址寄存器和偏移量的寻址模式。
   - 实现了写屏障（Write Barrier）的生成逻辑，用于垃圾回收器的内存管理。
   - 针对存储到全局变量和 root 寄存器的情况进行了处理。

6. **SIMD 指令选择 (`VisitStoreLane`, `VisitLoadLane`)**:
   - 针对 SIMD (Single Instruction, Multiple Data)  128 位向量操作，提供了 `VisitStoreLane` 和 `VisitLoadLane` 方法，用于选择 RISC-V 的向量存储 (`kRiscvS128StoreLane`) 和加载指令 (`kRiscvS128LoadLane`)。

7. **算术和逻辑运算指令选择 (`VisitWord32And`, `VisitWord32Or`, `VisitWord32Xor`, `VisitInt32Add`, `VisitInt32Sub`, `VisitInt32Mul`, etc.)**:
   - 为各种 32 位整数的算术和逻辑运算 (AND, OR, XOR, 加法, 减法, 乘法, 除法, 取模) 选择对应的 RISC-V 指令 (如 `kRiscvAnd`, `kRiscvOr`, `kRiscvAdd32`, `kRiscvSub32`, `kRiscvMul32`, `kRiscvDiv32`, `kRiscvMod32`)。
   - 一些指令选择考虑了优化的场景，例如 `VisitInt32Mul` 中针对乘以 2 的幂的情况使用了移位指令。

8. **类型转换指令选择 (`VisitChangeFloat32ToFloat64`, `VisitTruncateFloat32ToInt32`, etc.)**:
   - 负责选择浮点数和整数之间的类型转换指令 (如 `kRiscvCvtDS`, `kRiscvTruncWS`, `kRiscvCvtDW`)。

9. **浮点运算指令选择 (`VisitFloat32Neg`, `VisitFloat64Neg`)**:
   - 为浮点数的运算 (例如取反) 选择对应的 RISC-V 指令 (`kRiscvNegS`, `kRiscvNegD`)。

10. **位操作指令选择 (`VisitWord32Rol`, `VisitWord32Ror`, `VisitWord32ReverseBytes`, `VisitWord32Popcnt`)**:
    - 为位操作 (例如循环左移、循环右移、字节反转、人口计数) 选择相应的 RISC-V 指令 (`kRiscvRor32`, `kRiscvRev8`, `kRiscvByteSwap32`, `kRiscvPopcnt32`)。

**关于 `.tq` 结尾:**

如果 `v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc` 文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 内部使用的领域特定语言，用于定义运行时函数的实现和类型系统。然而，根据您提供的代码内容和文件名，它是一个 `.cc` 文件，因此是 **C++ 源代码文件**。

**与 JavaScript 的功能关系 (示例):**

指令选择器生成的目标代码最终会执行 JavaScript 代码。以下是一些 JavaScript 操作与 `instruction-selector-riscv32.cc` 中功能的对应关系：

```javascript
// 加载一个变量
let x = globalVar; // 可能对应 VisitLoad，生成 kRiscvLw 等加载指令

// 存储一个值到变量
globalVar = 10;  // 可能对应 VisitStore，生成 kRiscvSw 等存储指令

// 32 位整数加法
let a = 5;
let b = 3;
let sum = a + b; // 可能对应 VisitInt32Add，生成 kRiscvAdd32 指令

// 浮点数转换
let floatNum = 3.14;
let intNum = parseInt(floatNum); // 可能对应 VisitTruncateFloat64ToInt32，生成 kRiscvTruncWD 指令

// SIMD 操作
const arr1 = new Uint32Array([1, 2, 3, 4]);
const arr2 = new Uint32Array([5, 6, 7, 8]);
// 假设有某种 SIMD 加法操作
// 可能对应 VisitLoadLane, VisitStoreLane 以及其他 SIMD 指令的选择

// 位运算
let num1 = 0b1010;
let num2 = 0b1100;
let andResult = num1 & num2; // 可能对应 VisitWord32And，生成 kRiscvAnd 指令
```

**代码逻辑推理 (假设输入与输出):**

假设 `VisitInt32Add` 处理一个加法操作，输入是代表两个 32 位整数的 IR 节点 `node`:

**假设输入:**
- `node` 代表一个 Int32Add 操作。
- `node->InputAt(0)` 代表一个持有值 5 的寄存器（例如，`r3`）。
- `node->InputAt(1)` 代表一个持有值 10 的立即数。

**预期输出:**
- `Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_MRI), g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)), g.UseImmediate(10));`
  - 这会生成一个 RISC-V 的 `addiw` 指令 (add immediate word)，将寄存器 `r3` 的值加上立即数 10，并将结果存储到分配给 `node` 的寄存器中。

**用户常见的编程错误 (与指令选择相关):**

虽然指令选择器本身不直接处理用户的源代码错误，但它生成的指令会暴露一些常见的底层错误：

1. **内存访问错误:**
   - 访问了未分配或越界的内存。例如，如果 JavaScript 代码尝试访问数组的负索引或超出数组长度的索引，指令选择器会生成加载/存储指令，但执行时会导致段错误或其他内存访问异常。
   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[10]); // 越界访问
   ```
   指令选择器会为 `arr[10]` 生成加载指令，但在 RISC-V 上执行时会因为地址无效而失败。

2. **类型不匹配:**
   - 虽然 JavaScript 是动态类型语言，但在底层，V8 仍然需要处理不同类型的数据。如果 JavaScript 代码中操作的类型与预期的机器表示不符，可能会导致意外的结果或错误。例如，尝试将一个未初始化的变量作为数字进行运算。
   ```javascript
   let y;
   let z = y + 5; // y 是 undefined，转换为 NaN
   ```
   指令选择器会生成相应的加法指令，但由于 `y` 是 `undefined`，在底层可能会被转换为 `NaN` (Not a Number)，导致运算结果也是 `NaN`。

3. **未定义的行为:**
   - 某些 JavaScript 操作在特定情况下可能会导致未定义的行为，例如对 `NaN` 进行位运算。
   ```javascript
   let nanValue = NaN;
   let result = nanValue | 0; // 位运算应用于 NaN
   ```
   指令选择器会生成位或指令，但 `NaN` 的位表示是特殊的，结果可能不符合预期。

**功能归纳:**

`v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc` 文件的主要功能是作为 V8 JavaScript 引擎中 RISC-V 32 位架构的指令翻译器。它接收来自编译器后端的中间表示，并根据不同的操作类型和操作数，选择并生成最合适的 RISC-V 汇编指令。这个过程涵盖了内存访问 (加载和存储)、算术运算、逻辑运算、类型转换、位操作以及 SIMD 指令的选择，旨在高效地将高级的 JavaScript 代码转化为可以在 RISC-V 32 位处理器上执行的机器码。

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/bits.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/riscv/instruction-selector-riscv.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(...) PrintF(__VA_ARGS__)

template <typename Adapter>
int64_t RiscvOperandGeneratorT<Adapter>::GetIntegerConstantValue(Node* node) {
  DCHECK_EQ(IrOpcode::kInt32Constant, node->opcode());
  return OpParameter<int32_t>(node->op());
}

template <typename Adapter>
bool RiscvOperandGeneratorT<Adapter>::CanBeImmediate(int64_t value,
                                                     InstructionCode opcode) {
  switch (ArchOpcodeField::decode(opcode)) {
    case kRiscvShl32:
    case kRiscvSar32:
    case kRiscvShr32:
      return is_uint5(value);
    case kRiscvAdd32:
    case kRiscvAnd32:
    case kRiscvAnd:
    case kRiscvOr32:
    case kRiscvOr:
    case kRiscvTst32:
    case kRiscvXor:
      return is_int12(value);
    case kRiscvLb:
    case kRiscvLbu:
    case kRiscvSb:
    case kRiscvLh:
    case kRiscvLhu:
    case kRiscvSh:
    case kRiscvLw:
    case kRiscvSw:
    case kRiscvLoadFloat:
    case kRiscvStoreFloat:
    case kRiscvLoadDouble:
    case kRiscvStoreDouble:
      return is_int32(value);
    default:
      return is_int12(value);
  }
}

template <typename Adapter>
void EmitLoad(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode,
              typename Adapter::node_t output = typename Adapter::node_t{}) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);

  ExternalReferenceMatcher m(base);
  if (m.HasResolvedValue() && g.IsIntegerConstant(index) &&
      selector->CanAddressRelativeToRootsRegister(m.ResolvedValue())) {
    ptrdiff_t const delta =
        g.GetIntegerConstantValue(index) +
        MacroAssemblerBase::RootRegisterOffsetForExternalReference(
            selector->isolate(), m.ResolvedValue());
    // Check that the delta is a 32-bit integer due to the limitations of
    // immediate operands.
    if (is_int32(delta)) {
      opcode |= AddressingModeField::encode(kMode_Root);
      selector->Emit(opcode,
                     g.DefineAsRegister(output == nullptr ? node : output),
                     g.UseImmediate(static_cast<int32_t>(delta)));
      return;
    }
  }

  if (base != nullptr && base->opcode() == IrOpcode::kLoadRootRegister) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_Root),
                   g.DefineAsRegister(output == nullptr ? node : output),
                   g.UseImmediate(index));
    return;
  }

  if (g.CanBeImmediate(index, opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output == nullptr ? node : output),
                   g.UseRegister(base), g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output == nullptr ? node : output),
                   addr_reg, g.TempImmediate(0));
  }
}

template <>
void EmitLoad(InstructionSelectorT<TurboshaftAdapter>* selector,
              typename TurboshaftAdapter::node_t node, InstructionCode opcode,
              typename TurboshaftAdapter::node_t output) {
  RiscvOperandGeneratorT<TurboshaftAdapter> g(selector);
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& op = selector->Get(node);
  const LoadOp& load = op.Cast<LoadOp>();
  // The LoadStoreSimplificationReducer transforms all loads into
  // *(base + index).
  OpIndex base = load.base();
  OptionalOpIndex index = load.index();
  DCHECK_EQ(load.offset, 0);
  DCHECK_EQ(load.element_size_log2, 0);

  InstructionOperand inputs[3];
  size_t input_count = 0;
  InstructionOperand output_op;

  // If output is valid, use that as the output register. This is used when we
  // merge a conversion into the load.
  output_op = g.DefineAsRegister(output.valid() ? output : node);

  const Operation& base_op = selector->Get(base);
  if (base_op.Is<Opmask::kExternalConstant>() && index.has_value() &&
      selector->is_integer_constant(selector->value(index))) {
    const ConstantOp& constant_base = base_op.Cast<ConstantOp>();
    if (selector->CanAddressRelativeToRootsRegister(
            constant_base.external_reference())) {
      ptrdiff_t const delta =
          selector->integer_constant(selector->value(index)) +
          MacroAssemblerBase::RootRegisterOffsetForExternalReference(
              selector->isolate(), constant_base.external_reference());
      input_count = 1;
      // Check that the delta is a 32-bit integer due to the limitations of
      // immediate operands.
      if (is_int32(delta)) {
        inputs[0] = g.UseImmediate(static_cast<int32_t>(delta));
        opcode |= AddressingModeField::encode(kMode_Root);
        selector->Emit(opcode, 1, &output_op, input_count, inputs);
        return;
      }
    }
  }

  if (base_op.Is<LoadRootRegisterOp>()) {
    DCHECK(selector->is_integer_constant(selector->value(index)));
    input_count = 1;
    inputs[0] =
        g.UseImmediate64(selector->integer_constant(selector->value(index)));
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, 1, &output_op, input_count, inputs);
    return;
  }

  if (index.has_value() && g.CanBeImmediate(selector->value(index), opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output.valid() ? output : node),
                   g.UseRegister(base),
                   index.has_value() ? g.UseImmediate(selector->value(index))
                                     : g.UseImmediate(0));
  } else {
    if (index.has_value()) {
      InstructionOperand addr_reg = g.TempRegister();
      selector->Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None),
                     addr_reg, g.UseRegister(selector->value(index)),
                     g.UseRegister(base));
      // Emit desired load opcode, using temp addr_reg.
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                     g.DefineAsRegister(output.valid() ? output : node),
                     addr_reg, g.TempImmediate(0));
    } else {
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                     g.DefineAsRegister(output.valid() ? output : node),
                     g.UseRegister(base), g.TempImmediate(0));
    }
  }
}

template <typename Adapter>
void EmitS128Load(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, InstructionCode opcode,
                  VSew sew, Vlmul lmul) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t base = selector->input_at(node, 0);
  typename Adapter::node_t index = selector->input_at(node, 1);

  if (g.CanBeImmediate(index, opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(index), g.UseImmediate(sew),
                   g.UseImmediate(lmul));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(node), addr_reg, g.TempImmediate(0),
                   g.UseImmediate(sew), g.UseImmediate(lmul));
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& store = Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kRiscvS128StoreLane;
  opcode |= LaneSizeField::encode(store.lane_size() * kBitsPerByte);
  if (store.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd32, addr_reg, g.UseRegister(base), g.UseRegister(index));
  InstructionOperand inputs[4] = {
      g.UseRegister(input_at(node, 2)),
      g.UseImmediate(store.lane),
      addr_reg,
      g.TempImmediate(0),
  };
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  StoreLaneParameters params = StoreLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep, params.laneidx);
  InstructionCode opcode = kRiscvS128StoreLane;
  opcode |= MiscField::encode(f.sz);

  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd32, addr_reg, g.UseRegister(base), g.UseRegister(index));
  InstructionOperand inputs[4] = {
      g.UseRegister(node->InputAt(2)),
      g.UseImmediate(f.laneidx),
      addr_reg,
      g.TempImmediate(0),
  };
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& load = this->Get(node).Cast<Simd128LaneMemoryOp>();
  InstructionCode opcode = kRiscvS128LoadLane;
  opcode |= LaneSizeField::encode(load.lane_size() * kBitsPerByte);
  if (load.kind.with_trap_handler) {
    opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd32, addr_reg, g.UseRegister(base), g.UseRegister(index));
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, g.DefineSameAsFirst(node),
       g.UseRegister(this->input_at(node, 2)), g.UseImmediate(load.lane),
       addr_reg, g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep.representation(), params.laneidx);
  InstructionCode opcode = kRiscvS128LoadLane;
  opcode |= MiscField::encode(f.sz);

  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  InstructionOperand addr_reg = g.TempRegister();
  Emit(kRiscvAdd32, addr_reg, g.UseRegister(base), g.UseRegister(index));
  opcode |= AddressingModeField::encode(kMode_MRI);
  Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(2)),
       g.UseImmediate(params.laneidx), addr_reg, g.TempImmediate(0));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  auto load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();
  InstructionCode opcode = kArchNop;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kRiscvLoadFloat;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kRiscvLoadDouble;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsUnsigned() ? kRiscvLbu : kRiscvLb;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsUnsigned() ? kRiscvLhu : kRiscvLh;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      opcode = kRiscvLw;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kRiscvRvvLd;
      break;
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
    case MachineRepresentation::kSandboxedPointer:
    case MachineRepresentation::kMapWord:  // Fall through.
    case MachineRepresentation::kWord64:
    case MachineRepresentation::kNone:
    case MachineRepresentation::kSimd256:  // Fall through.
    case MachineRepresentation::kProtectedPointer:  // Fall through.
    case MachineRepresentation::kIndirectPointer:
    case MachineRepresentation::kFloat16:
      UNREACHABLE();
    }

    EmitLoad(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStore(node_t node) {
  RiscvOperandGeneratorT<TurboshaftAdapter> g(this);
  typename TurboshaftAdapter::StoreView store_view = this->store_view(node);
  node_t base = store_view.base();
  optional_node_t index = store_view.index();
  node_t value = store_view.value();

  WriteBarrierKind write_barrier_kind =
      store_view.stored_rep().write_barrier_kind();
  MachineRepresentation rep = store_view.stored_rep().representation();

  // TODO(riscv): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier && index.has_value() &&
      V8_LIKELY(!v8_flags.disable_write_barriers)) {
    DCHECK(CanBeTaggedPointer(rep));
    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    inputs[input_count++] = g.UseUniqueRegister(this->value(index));
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code;
    if (rep == MachineRepresentation::kIndirectPointer) {
      DCHECK_EQ(write_barrier_kind, kIndirectPointerWriteBarrier);
      // In this case we need to add the IndirectPointerTag as additional input.
      code = kArchStoreIndirectWithWriteBarrier;
      IndirectPointerTag tag = store_view.indirect_pointer_tag();
      inputs[input_count++] = g.UseImmediate64(static_cast<int64_t>(tag));
    } else {
      code = kArchStoreWithWriteBarrier;
    }
    code |= RecordWriteModeField::encode(record_write_mode);
    if (store_view.is_store_trap_on_null()) {
      code |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
    }
    Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    InstructionCode code;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        code = kRiscvStoreFloat;
        break;
      case MachineRepresentation::kFloat64:
        code = kRiscvStoreDouble;
        break;
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        code = kRiscvSb;
        break;
      case MachineRepresentation::kWord16:
        code = kRiscvSh;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kWord32:
        code = kRiscvSw;
        break;
      case MachineRepresentation::kSimd128:
        code = kRiscvRvvSt;
        break;
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
      case MachineRepresentation::kSandboxedPointer:
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kNone:
      case MachineRepresentation::kWord64:
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kIndirectPointer:
      case MachineRepresentation::kFloat16:
        UNREACHABLE();
    }

    if (this->is_load_root_register(base)) {
      Emit(code | AddressingModeField::encode(kMode_Root), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value),
           index.has_value() ? g.UseImmediate(this->value(index))
                             : g.UseImmediate(0));
      return;
    }

    if (index.has_value() && g.CanBeImmediate(this->value(index), code)) {
      Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value), g.UseRegister(base),
           index.has_value() ? g.UseImmediate(this->value(index))
                             : g.UseImmediate(0));
    } else {
      if (index.has_value()) {
        InstructionOperand addr_reg = g.TempRegister();
        Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None), addr_reg,
             g.UseRegister(this->value(index)), g.UseRegister(base));
        // Emit desired store opcode, using temp addr_reg.
        Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
             g.UseRegisterOrImmediateZero(value), addr_reg, g.TempImmediate(0));
      } else {
        Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
             g.UseRegisterOrImmediateZero(value), g.UseRegister(base),
             g.UseImmediate(0));
      }
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStore(Node* node) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  Node* value = node->InputAt(2);

  StoreRepresentation store_rep = StoreRepresentationOf(node->op());
  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  MachineRepresentation rep = store_rep.representation();

  // TODO(riscv): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier &&
      V8_LIKELY(!v8_flags.disable_write_barriers)) {
    DCHECK(CanBeTaggedPointer(rep));
    InstructionOperand inputs[3];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    inputs[input_count++] = g.UseUniqueRegister(index);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code = kArchStoreWithWriteBarrier;
    code |= RecordWriteModeField::encode(record_write_mode);
    Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        opcode = kRiscvStoreFloat;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kRiscvStoreDouble;
        break;
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        opcode = kRiscvSb;
        break;
      case MachineRepresentation::kWord16:
        opcode = kRiscvSh;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kWord32:
        opcode = kRiscvSw;
        break;
      case MachineRepresentation::kSimd128:
        opcode = kRiscvRvvSt;
        break;
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
        UNREACHABLE();
      case MachineRepresentation::kSandboxedPointer:
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kNone:
      case MachineRepresentation::kWord64:
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kIndirectPointer:
      case MachineRepresentation::kFloat16:
        UNREACHABLE();
    }

    if (base != nullptr && base->opcode() == IrOpcode::kLoadRootRegister) {
      Emit(opcode | AddressingModeField::encode(kMode_Root), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value), g.UseImmediate(index));
      return;
    }

    if (g.CanBeImmediate(index, opcode)) {
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value), g.UseRegister(base),
           g.UseImmediate(index));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      Emit(kRiscvAdd32 | AddressingModeField::encode(kMode_None), addr_reg,
           g.UseRegister(index), g.UseRegister(base));
      // Emit desired store opcode, using temp addr_reg.
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegisterOrImmediateZero(value), addr_reg, g.TempImmediate(0));
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
  VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAnd, true,
                                         kRiscvAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvOr, true,
                                           kRiscvOr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvXor, true,
                                           kRiscvXor);
  } else {
    VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvXor, true,
                                           kRiscvXor);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    UNREACHABLE();
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
    VisitRRO(this, kRiscvRor32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    if (CpuFeatures::IsSupported(ZBB)) {
      Emit(kRiscvRev8, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    } else {
      Emit(kRiscvByteSwap32, g.DefineAsRegister(node),
           g.UseRegister(this->input_at(node, 0)));
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kRiscvPopcnt32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Add(node_t node) {
  VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvAdd32, true,
                                         kRiscvAdd32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  VisitBinop<Adapter, Int32BinopMatcher>(this, node, kRiscvSub32);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Mul(node_t node) {
  VisitRRR(this, kRiscvMul32, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Mul(Node* node) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint32_t value = static_cast<uint32_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kRiscvShl32 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kRiscvShl32 | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kRiscvSub32 | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }

  VisitRRR(this, kRiscvMul32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32MulHigh(node_t node) {
  VisitRRR(this, kRiscvMulHigh32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32MulHigh(node_t node) {
  VisitRRR(this, kRiscvMulHighU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Div(node_t node) {
  VisitRRR(this, kRiscvDiv32, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Div(node_t node) {
  VisitRRR(this, kRiscvDivU32, node,
           OperandGenerator::RegisterUseKind::kUseUniqueRegister);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Mod(node_t node) {
  VisitRRR(this, kRiscvMod32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUint32Mod(node_t node) {
  VisitRRR(this, kRiscvModU32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat32ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundInt32ToFloat32(node_t node) {
    VisitRR(this, kRiscvCvtSW, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitRoundUint32ToFloat32(node_t node) {
    VisitRR(this, kRiscvCvtSUw, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeInt32ToFloat64(node_t node) {
  VisitRR(this, kRiscvCvtDW, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeUint32ToFloat64(node_t node) {
    VisitRR(this, kRiscvCvtDUw, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToInt32(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kRiscvTruncWS;
    if (op.Is<Opmask::kTruncateFloat32ToInt32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  } else {
    InstructionCode opcode = kRiscvTruncWS;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat32ToUint32(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = this->Get(node);
    InstructionCode opcode = kRiscvTruncUwS;
    if (op.Is<Opmask::kTruncateFloat32ToUint32OverflowToMin>()) {
      opcode |= MiscField::encode(true);
    }

    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)));
  } else {
    InstructionCode opcode = kRiscvTruncUwS;
    TruncateKind kind = OpParameter<TruncateKind>(node->op());
    if (kind == TruncateKind::kSetOverflowToMin) {
      opcode |= MiscField::encode(true);
    }
    Emit(opcode, g.DefineAsRegister(node), g.UseRegister(node->InputAt(0)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToInt32(node_t node) {
  RiscvOperandGeneratorT<Adapter> g(this);
  node_t value = this->input_at(node, 0);
  if constexpr (Adapter::IsTurboshaft) {
    using Rep = turboshaft::RegisterRepresentation;
    if (CanCover(node, value)) {
      const turboshaft::Operation& op = this->Get(value);
      if (op.Is<turboshaft::ChangeOp>()) {
        const turboshaft::ChangeOp& change = op.Cast<turboshaft::ChangeOp>();
        if (change.kind == turboshaft::ChangeOp::Kind::kFloatConversion) {
          if (change.from == Rep::Float32() && change.to == Rep::Float64()) {
            Emit(kRiscvTruncWS, g.DefineAsRegister(node),
                 g.UseRegister(this->input_at(value, 0)));
            return;
          }
        }
      }
    }
  } else {
    if (CanCover(node, value)) {
      if (value->opcode() == IrOpcode::kChangeFloat32ToFloat64) {
        // Match float32 -> float64 -> int32 representation change path.
        Emit(kRiscvTruncWS, g.DefineAsRegister(node),
             g.UseRegister(value->InputAt(0)));
        return;
      }
    }
  }
  VisitRR(this, kRiscvTruncWD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitChangeFloat64ToUint32(node_t node) {
    VisitRR(this, kRiscvTruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitTruncateFloat64ToUint32(node_t node) {
  VisitRR(this, kRiscvTruncUwD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastFloat32ToInt32(node_t node) {
    VisitRR(this, kRiscvBitcastFloat32ToInt32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitBitcastInt32ToFloat32(node_t node) {
    VisitRR(this, kRiscvBitcastInt32ToFloat32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundDown(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundUp(node_t node) {
  VisitRR(this, kRiscvFloat32RoundUp, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundUp(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTruncate(node_t node) {
  VisitRR(this, kRiscvFloat32RoundTruncate, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTruncate(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesAway(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32RoundTiesEven(node_t node) {
  VisitRR(this, kRiscvFloat32RoundTiesEven, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64RoundTiesEven(node_t node) {
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat32Neg(node_t node) {
  VisitRR(this, kRiscvNegS, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Neg(node_t node) {
  VisitRR(this, kRiscvNegD, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Binop(
    node_t node, InstructionCode opcode) {
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(opcode, g.DefineAsFixed(node, fa0),
         g.UseFixed(this->input_at(node, 0), fa0),
         g.UseFixed(this->input_at(node, 1), fa1))
        ->MarkAsCall();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitFloat64Ieee754Unop(
    node_t n
```