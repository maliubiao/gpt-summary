Response:
My thinking process to summarize the provided C++ code for V8's ARM instruction selector goes like this:

1. **Understand the Goal:** The core purpose of this code is to translate high-level intermediate representation (IR) nodes from V8's compiler into low-level ARM machine instructions. This translation needs to be efficient and correct.

2. **Identify Key Components:** I scan the code for structural elements and recurring patterns. I notice:
    * **Includes:**  These tell me about dependencies on other V8 components (like `codegen`, `compiler`, `base`) and standard library features.
    * **Namespaces:**  `v8::internal::compiler` clearly indicates the code's location within V8.
    * **Templates:**  The use of `template <typename Adapter>` is a strong signal that this code is designed to work with different compiler phases or potentially different IR representations (Turbofan and Turboshaft are hinted at).
    * **Class `ArmOperandGeneratorT`:** This seems responsible for generating the operands (registers, immediates) needed by the ARM instructions. It has methods like `CanBeImmediate`.
    * **`Visit...` functions:** These are the core of the instruction selection process. Each `Visit` function seems to handle a specific IR node type (`VisitRR`, `VisitRRR`, `VisitBinop`, `VisitLoad`, `VisitStore`, etc.). The naming suggests the number of register operands.
    * **`TryMatch...` functions:**  These seem like helper functions to identify specific patterns in the IR and potentially optimize instruction selection (e.g., `TryMatchShift` for combining shifts into operands).
    * **`Emit` function:** This is how the selected ARM instructions are actually generated and added to the instruction stream.
    * **Conditional compilation (`#if V8_ENABLE_WEBASSEMBLY`):**  Indicates special handling for WebAssembly-related operations.
    * **Specific ARM instruction mnemonics (like `kArmAdd`, `kArmMov`, `kArmLdr`, `kArmStr`, `kArmVld1S128`):**  This confirms the target architecture is ARM.
    * **Handling of immediates and shifts:**  A significant portion of the code deals with how constant values (immediates) and shift operations are encoded into ARM instructions.
    * **Handling of memory access (loads and stores):**  Functions like `EmitLoad` and `EmitStore` are crucial for translating memory operations.
    * **Atomic operations:** The presence of `VisitPairAtomicBinOp` indicates support for atomic operations on pairs of values.

3. **Infer Functionality from Components:** Based on the identified components, I start to infer the main functions of the code:
    * **Operand Generation:**  Creating the correct operands for ARM instructions (registers, immediates, shifts).
    * **Instruction Selection:**  Choosing the appropriate ARM instruction for a given IR node. This involves pattern matching and optimization.
    * **Handling Different Operand Types:**  Differentiating between register operands, immediate operands, and shifted register operands.
    * **Memory Access:** Generating ARM load and store instructions, considering different addressing modes.
    * **Binary Operations:** Translating arithmetic and logical operations.
    * **WebAssembly Support:**  Handling SIMD operations and lane access specific to WebAssembly.
    * **Stack Slot Allocation:**  Managing stack frame layout.

4. **Consider Specific Code Sections:** I look at particular code snippets to understand their purpose:
    * The `CanBeImmediate` functions are clearly for checking if a value can be encoded as an immediate operand for a given ARM instruction.
    * The `VisitRR`, `VisitRRR` templates handle simple instructions with one or two register operands.
    * The `TryMatchShift` and related functions show how shift operations can be folded into the operand of other instructions.
    * The `VisitBinop` function demonstrates how to handle binary operations, considering immediates and shifts for optimization.
    * The `EmitLoad` and `EmitStore` functions show the complexity of handling memory addressing, including relative addressing for root registers and handling of SIMD loads/stores.

5. **Address Specific Questions from the Prompt:**
    * **Listing Functionality:** I explicitly list the functions I've inferred.
    * **`.tq` Extension:** I note that the code is `.cc`, so it's not Torque.
    * **JavaScript Relationship:**  I know instruction selection is a crucial step in compiling JavaScript code in V8. I can provide a simple JavaScript example that would trigger some of the operations handled in this code (e.g., `a + b`, `array[i]`).
    * **Code Logic Inference:** I can create a simple example with an addition operation and show how the `VisitBinop` function might select an `ADD` instruction.
    * **Common Programming Errors:** I think about errors that might lead to incorrect code generation or performance issues, such as using non-optimized operations or incorrect memory access patterns.

6. **Synthesize the Summary:** Finally, I combine my observations and inferences into a concise summary, focusing on the core responsibilities of the code and mentioning the key techniques used. I also address the specific points raised in the initial prompt. I organize the summary logically, starting with the overall purpose and then detailing specific aspects.

By following this process, I can systematically analyze the provided C++ code and generate a comprehensive and accurate summary of its functionality. The key is to break down the code into smaller, understandable parts and then piece together the overall picture.
这是对 V8 引擎中 `v8/src/compiler/backend/arm/instruction-selector-arm.cc` 文件的代码片段的分析和功能归纳。

**功能归纳:**

总的来说，这个代码片段是 V8 编译器后端的一部分，负责将 **平台无关的中间表示 (IR)** 转换成 **特定于 ARM 架构的机器指令**。  更具体地说，它是 `InstructionSelector` 的 ARM 平台实现。

**详细功能分解:**

1. **指令选择核心逻辑:**
   -  这个文件定义了 `InstructionSelectorT` 模板类的 ARM 特定实现。`InstructionSelector` 的主要职责是遍历编译器的中间表示 (IR) 图，并为每个 IR 节点选择合适的 ARM 机器指令。
   - 它使用了一系列 `Visit...` 函数 (例如 `VisitRR`, `VisitRRR`, `VisitBinop`, `VisitLoad`, `VisitStore` 等) 来处理不同类型的 IR 节点。每个 `Visit` 函数负责针对特定的 IR 操作生成相应的 ARM 指令序列。

2. **操作数生成 (`ArmOperandGeneratorT`):**
   -  定义了一个名为 `ArmOperandGeneratorT` 的模板类，它继承自通用的 `OperandGeneratorT`。
   -  `ArmOperandGeneratorT` 提供了 ARM 平台特定的方法来创建指令的操作数，例如寄存器、立即数和内存地址。
   -  它包含了 `CanBeImmediate` 函数，用于判断一个值是否可以作为 ARM 指令的立即数，并针对不同的 ARM 指令有不同的判断逻辑。

3. **指令模式匹配和优化:**
   -  代码中存在 `TryMatchShift` 和 `TryMatchImmediateOrShift` 等模板函数，用于尝试匹配特定的 IR 模式，并根据 ARM 架构的特性进行优化。例如，它可以识别移位操作是否可以直接作为某些指令的操作数，从而减少指令的数量。

4. **二元操作处理 (`VisitBinop`):**
   -  `VisitBinop` 函数用于处理各种二元运算 (例如加法、减法、按位与、按位或等)。
   -  它会尝试将操作数优化为立即数或移位操作，以生成更高效的 ARM 指令。
   -  它还处理了操作数相同的特殊情况，以避免生成不必要的指令。

5. **除法和取模运算处理 (`VisitDiv`, `VisitMod`):**
   -  `VisitDiv` 和 `VisitMod` 函数处理除法和取模运算。
   -  针对 ARM 架构是否支持硬件除法指令 (SUDIV)，会采取不同的策略。如果不支持，则会使用浮点运算来模拟。

6. **加载和存储操作处理 (`EmitLoad`, `EmitStore`):**
   -  `EmitLoad` 和 `EmitStore` 函数负责生成 ARM 的加载和存储指令。
   -  它们会根据基址寄存器和偏移量的类型（立即数或寄存器）选择合适的寻址模式。
   -  对于某些 SIMD 指令 (`kArmVld1S128`, `kArmVst1S128`)，会预先计算基址加偏移量。
   -  还处理了从根寄存器加载的情况。

7. **原子操作处理 (`VisitPairAtomicBinOp`):**
   -  `VisitPairAtomicBinOp` 函数处理原子二元操作，例如原子加、原子减等。
   -  它使用了特定的 ARM 原子指令序列，并分配了固定的寄存器。

8. **WebAssembly 支持 (`#if V8_ENABLE_WEBASSEMBLY`):**
   -  代码片段中包含 `#if V8_ENABLE_WEBASSEMBLY` 的条件编译块，表明该文件也负责处理 WebAssembly 相关的指令选择。
   -  `VisitStoreLane` 函数用于处理 SIMD 向量中特定元素的存储操作。

9. **栈槽操作 (`VisitStackSlot`):**
   -  `VisitStackSlot` 函数用于处理访问栈上分配的变量的操作。

10. **调试辅助 (`VisitAbortCSADcheck`):**
    - `VisitAbortCSADcheck` 函数似乎是为了在调试过程中插入检查点。

**关于 .tq 结尾：**

代码注释中提到： "如果 v8/src/compiler/backend/arm/instruction-selector-arm.cc 以 .tq 结尾，那它是个 v8 torque 源代码"。  **当前的这个文件 `instruction-selector-arm.cc` 以 `.cc` 结尾，所以它不是 Torque 源代码，而是标准的 C++ 源代码。** Torque 是 V8 用于定义运行时内置函数的 DSL (Domain Specific Language)，它会生成 C++ 代码。

**与 JavaScript 的关系和示例：**

这个文件直接参与了将 JavaScript 代码编译成机器码的过程。当 V8 编译 JavaScript 代码时，它会经历多个阶段，其中一个重要的阶段就是将平台无关的 IR 转换为特定平台的机器码。 `instruction-selector-arm.cc` 就是在这个阶段发挥作用的。

**JavaScript 例子:**

```javascript
function add(a, b) {
  return a + b;
}

let x = 5;
let y = 10;
let sum = add(x, y);

let arr = [1, 2, 3];
let firstElement = arr[0];
```

当 V8 编译这段 JavaScript 代码时，对于 `a + b` 这个加法操作，`VisitBinop` 函数可能会被调用，并根据 `a` 和 `b` 的类型和值，选择合适的 ARM 加法指令，例如 `ADD` 指令。

对于 `arr[0]` 这个数组访问，`EmitLoad` 函数会被调用，生成相应的 ARM 加载指令，将数组中第一个元素的值加载到寄存器中。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (TurbofanAdapter):**  一个代表 `a + b` 的 IR 节点，其中 `a` 和 `b` 是 32 位整数，并且已经分配了寄存器 (例如 `r1` 和 `r2`)。

**输出:**  调用 `selector->Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_R), output_register, input_register_a, input_register_b);`  其中 `output_register` 是用于存储结果的寄存器，`input_register_a` 对应 `r1`，`input_register_b` 对应 `r2`。 这会生成一个 ARM 的 `ADD` 指令，将 `r1` 和 `r2` 的值相加，并将结果存储到 `output_register` 中。

**用户常见的编程错误 (与该代码相关):**

虽然用户不会直接编写 C++ 代码来调用这些函数，但 JavaScript 代码中的某些模式可能会导致编译器生成效率较低的机器码。例如：

1. **过度依赖动态类型:**  如果 JavaScript 代码中变量的类型经常变化，编译器可能无法进行充分的优化，导致生成的 ARM 指令效率不高。例如，频繁地将数字和字符串进行加法操作。

   ```javascript
   let result = 0;
   for (let i = 0; i < 10; i++) {
     result += i; // 编译器可以优化为整数加法
   }

   let flexibleResult = 0;
   for (let i = 0; i < 10; i++) {
     if (i % 2 === 0) {
       flexibleResult += i;
     } else {
       flexibleResult += "str" + i; // 类型变化，编译器难以优化
     }
   }
   ```

2. **非连续的数组访问:**  虽然 `EmitLoad` 可以处理数组访问，但如果 JavaScript 代码中对数组的访问模式非常随机，可能会导致缓存失效，从而影响性能。

   ```javascript
   let arr = new Array(1000);
   // ... 初始化数组 ...

   // 连续访问，编译器和硬件更容易优化
   for (let i = 0; i < arr.length; i++) {
     console.log(arr[i]);
   }

   // 随机访问，可能导致性能下降
   for (let i = 0; i < 1000; i++) {
     let randomIndex = Math.floor(Math.random() * arr.length);
     console.log(arr[randomIndex]);
   }
   ```

**总结 (针对第 1 部分):**

`v8/src/compiler/backend/arm/instruction-selector-arm.cc` 的这部分代码定义了 V8 编译器后端中针对 ARM 架构的指令选择逻辑。它负责将中间表示的运算和操作转换为具体的 ARM 机器指令，并进行了一些针对 ARM 架构的优化，例如利用立即数和移位操作。它包含了处理各种操作的 `Visit...` 函数，以及用于生成 ARM 操作数的辅助类 `ArmOperandGeneratorT`。这部分代码是 V8 将 JavaScript 代码高效地编译为 ARM 机器码的关键组成部分。

### 提示词
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/instruction-selector-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/bits.h"
#include "src/base/enum-set.h"
#include "src/base/iterator.h"
#include "src/base/logging.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/backend/instruction-selector-adapter.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"

namespace v8 {
namespace internal {
namespace compiler {

// Adds Arm-specific methods for generating InstructionOperands.
template <typename Adapter>
class ArmOperandGeneratorT : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit ArmOperandGeneratorT(InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  bool CanBeImmediate(int32_t value) const {
    return Assembler::ImmediateFitsAddrMode1Instruction(value);
  }

  bool CanBeImmediate(uint32_t value) const {
    return CanBeImmediate(base::bit_cast<int32_t>(value));
  }

  bool CanBeImmediate(node_t node, InstructionCode opcode) {
    if (!selector()->is_integer_constant(node)) return false;
    int64_t value64 = selector()->integer_constant(node);
    DCHECK(base::IsInRange(value64, std::numeric_limits<int32_t>::min(),
                           std::numeric_limits<int32_t>::max()));
    int32_t value = static_cast<int32_t>(value64);
    switch (ArchOpcodeField::decode(opcode)) {
      case kArmAnd:
      case kArmMov:
      case kArmMvn:
      case kArmBic:
        return CanBeImmediate(value) || CanBeImmediate(~value);

      case kArmAdd:
      case kArmSub:
      case kArmCmp:
      case kArmCmn:
        return CanBeImmediate(value) || CanBeImmediate(-value);

      case kArmTst:
      case kArmTeq:
      case kArmOrr:
      case kArmEor:
      case kArmRsb:
        return CanBeImmediate(value);

      case kArmVldrF32:
      case kArmVstrF32:
      case kArmVldrF64:
      case kArmVstrF64:
        return value >= -1020 && value <= 1020 && (value % 4) == 0;

      case kArmLdrb:
      case kArmLdrsb:
      case kArmStrb:
      case kArmLdr:
      case kArmStr:
        return value >= -4095 && value <= 4095;

      case kArmLdrh:
      case kArmLdrsh:
      case kArmStrh:
        return value >= -255 && value <= 255;

      default:
        break;
    }
    return false;
  }
};

namespace {

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
             typename Adapter::node_t node) {
  ArmOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node) {
  ArmOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
}

#if V8_ENABLE_WEBASSEMBLY
void VisitSimdShiftRRR(InstructionSelectorT<TurboshaftAdapter>* selector,
                       ArchOpcode opcode, turboshaft::OpIndex node, int width) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArmOperandGeneratorT<TurboshaftAdapter> g(selector);
  const Simd128ShiftOp& op = selector->Get(node).Cast<Simd128ShiftOp>();
  int32_t shift_by;
  if (selector->MatchIntegralWord32Constant(op.shift(), &shift_by)) {
    if (shift_by % width == 0) {
      selector->EmitIdentity(node);
    } else {
      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(op.input()), g.UseImmediate(op.shift()));
    }
  } else {
    VisitRRR(selector, opcode, node);
  }
}

void VisitSimdShiftRRR(InstructionSelectorT<TurbofanAdapter>* selector,
                       ArchOpcode opcode, Node* node, int width) {
  ArmOperandGeneratorT<TurbofanAdapter> g(selector);
  Int32Matcher m(node->InputAt(1));
  if (m.HasResolvedValue()) {
    if (m.IsMultipleOf(width)) {
      selector->EmitIdentity(node);
    } else {
      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(node->InputAt(0)),
                     g.UseImmediate(node->InputAt(1)));
    }
  } else {
    VisitRRR(selector, opcode, node);
  }
}

template <typename Adapter>
void VisitRRRShuffle(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node,
                     typename Adapter::node_t input0,
                     typename Adapter::node_t input1) {
  ArmOperandGeneratorT<Adapter> g(selector);
  // Swap inputs to save an instruction in the CodeGenerator for High ops.
  if (opcode == kArmS32x4ZipRight || opcode == kArmS32x4UnzipRight ||
      opcode == kArmS32x4TransposeRight || opcode == kArmS16x8ZipRight ||
      opcode == kArmS16x8UnzipRight || opcode == kArmS16x8TransposeRight ||
      opcode == kArmS8x16ZipRight || opcode == kArmS8x16UnzipRight ||
      opcode == kArmS8x16TransposeRight) {
    std::swap(input0, input1);
  }
  // Use DefineSameAsFirst for binary ops that clobber their inputs, e.g. the
  // NEON vzip, vuzp, and vtrn instructions.
  selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(input0),
                 g.UseRegister(input1));
}

template <typename Adapter>
void VisitRRI(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
              typename Adapter::node_t node) {
  ArmOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(node);
    int imm = op.template Cast<Simd128ExtractLaneOp>().lane;
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)),
                   g.UseImmediate(imm));
  } else {
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm));
  }
}

template <typename Adapter>
void VisitRRIR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
               typename Adapter::node_t node) {
  ArmOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const turboshaft::Simd128ReplaceLaneOp& op =
        selector->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.into()),
                   g.UseImmediate(op.lane), g.UseUniqueRegister(op.new_lane()));
  } else {
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm),
                   g.UseUniqueRegister(node->InputAt(1)));
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <IrOpcode::Value kOpcode, int kImmMin, int kImmMax,
          AddressingMode kImmMode, AddressingMode kRegMode>
bool TryMatchShift(InstructionSelectorT<TurbofanAdapter>* selector,
                   InstructionCode* opcode_return, Node* node,
                   InstructionOperand* value_return,
                   InstructionOperand* shift_return) {
  ArmOperandGeneratorT<TurbofanAdapter> g(selector);
  if (node->opcode() == kOpcode) {
    Int32BinopMatcher m(node);
    *value_return = g.UseRegister(m.left().node());
    if (m.right().IsInRange(kImmMin, kImmMax)) {
      *opcode_return |= AddressingModeField::encode(kImmMode);
      *shift_return = g.UseImmediate(m.right().node());
    } else {
      *opcode_return |= AddressingModeField::encode(kRegMode);
      *shift_return = g.UseRegister(m.right().node());
    }
    return true;
  }
  return false;
}

template <typename OpmaskT, int kImmMin, int kImmMax, AddressingMode kImmMode,
          AddressingMode kRegMode>
bool TryMatchShift(InstructionSelectorT<TurboshaftAdapter>* selector,
                   InstructionCode* opcode_return, turboshaft::OpIndex node,
                   InstructionOperand* value_return,
                   InstructionOperand* shift_return) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArmOperandGeneratorT<TurboshaftAdapter> g(selector);
  const Operation& op = selector->Get(node);
  if (op.Is<OpmaskT>()) {
    const ShiftOp& shift = op.Cast<ShiftOp>();
    *value_return = g.UseRegister(shift.left());
    int32_t shift_by;
    if (selector->MatchIntegralWord32Constant(shift.right(), &shift_by) &&
        base::IsInRange(shift_by, kImmMin, kImmMax)) {
      *opcode_return |= AddressingModeField::encode(kImmMode);
      *shift_return = g.UseImmediate(shift.right());
    } else {
      *opcode_return |= AddressingModeField::encode(kRegMode);
      *shift_return = g.UseRegister(shift.right());
    }
    return true;
  }
  return false;
}

template <IrOpcode::Value kOpcode, int kImmMin, int kImmMax,
          AddressingMode kImmMode>
bool TryMatchShiftImmediate(InstructionSelectorT<TurbofanAdapter>* selector,
                            InstructionCode* opcode_return, Node* node,
                            InstructionOperand* value_return,
                            InstructionOperand* shift_return) {
  ArmOperandGeneratorT<TurbofanAdapter> g(selector);
  if (node->opcode() == kOpcode) {
    Int32BinopMatcher m(node);
    if (m.right().IsInRange(kImmMin, kImmMax)) {
      *opcode_return |= AddressingModeField::encode(kImmMode);
      *value_return = g.UseRegister(m.left().node());
      *shift_return = g.UseImmediate(m.right().node());
      return true;
    }
  }
  return false;
}

template <typename OpmaskT, int kImmMin, int kImmMax, AddressingMode kImmMode>
bool TryMatchShiftImmediate(InstructionSelectorT<TurboshaftAdapter>* selector,
                            InstructionCode* opcode_return,
                            turboshaft::OpIndex node,
                            InstructionOperand* value_return,
                            InstructionOperand* shift_return) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArmOperandGeneratorT<TurboshaftAdapter> g(selector);
  const Operation& op = selector->Get(node);
  if (op.Is<OpmaskT>()) {
    const ShiftOp& shift = op.Cast<ShiftOp>();
    int32_t shift_by;
    if (selector->MatchIntegralWord32Constant(shift.right(), &shift_by) &&
        base::IsInRange(shift_by, kImmMin, kImmMax)) {
      *opcode_return |= AddressingModeField::encode(kImmMode);
      *value_return = g.UseRegister(shift.left());
      *shift_return = g.UseImmediate(shift.right());
      return true;
    }
  }
  return false;
}

template <typename Adapter>
bool TryMatchROR(InstructionSelectorT<Adapter>* selector,
                 InstructionCode* opcode_return, typename Adapter::node_t node,
                 InstructionOperand* value_return,
                 InstructionOperand* shift_return) {
  return TryMatchShift<IrOpcode::kWord32Ror, 1, 31, kMode_Operand2_R_ROR_I,
                       kMode_Operand2_R_ROR_R>(selector, opcode_return, node,
                                               value_return, shift_return);
}

template <>
bool TryMatchROR(InstructionSelectorT<TurboshaftAdapter>* selector,
                 InstructionCode* opcode_return, turboshaft::OpIndex node,
                 InstructionOperand* value_return,
                 InstructionOperand* shift_return) {
  return TryMatchShift<turboshaft::Opmask::kWord32RotateRight, 1, 31,
                       kMode_Operand2_R_ROR_I, kMode_Operand2_R_ROR_R>(
      selector, opcode_return, node, value_return, shift_return);
}

template <typename Adapter>
bool TryMatchASR(InstructionSelectorT<Adapter>* selector,
                 InstructionCode* opcode_return, typename Adapter::node_t node,
                 InstructionOperand* value_return,
                 InstructionOperand* shift_return) {
  return TryMatchShift<IrOpcode::kWord32Sar, 1, 32, kMode_Operand2_R_ASR_I,
                       kMode_Operand2_R_ASR_R>(selector, opcode_return, node,
                                               value_return, shift_return);
}

template <>
bool TryMatchASR(InstructionSelectorT<TurboshaftAdapter>* selector,
                 InstructionCode* opcode_return, turboshaft::OpIndex node,
                 InstructionOperand* value_return,
                 InstructionOperand* shift_return) {
  return TryMatchShift<turboshaft::Opmask::kWord32ShiftRightArithmetic, 1, 32,
                       kMode_Operand2_R_ASR_I, kMode_Operand2_R_ASR_R>(
             selector, opcode_return, node, value_return, shift_return) ||
         TryMatchShift<
             turboshaft::Opmask::kWord32ShiftRightArithmeticShiftOutZeros, 1,
             32, kMode_Operand2_R_ASR_I, kMode_Operand2_R_ASR_R>(
             selector, opcode_return, node, value_return, shift_return);
}

template <typename Adapter>
bool TryMatchLSL(InstructionSelectorT<Adapter>* selector,
                 InstructionCode* opcode_return, typename Adapter::node_t node,
                 InstructionOperand* value_return,
                 InstructionOperand* shift_return) {
  return TryMatchShift<IrOpcode::kWord32Shl, 0, 31, kMode_Operand2_R_LSL_I,
                       kMode_Operand2_R_LSL_R>(selector, opcode_return, node,
                                               value_return, shift_return);
}

template <>
bool TryMatchLSL(InstructionSelectorT<TurboshaftAdapter>* selector,
                 InstructionCode* opcode_return, turboshaft::OpIndex node,
                 InstructionOperand* value_return,
                 InstructionOperand* shift_return) {
  return TryMatchShift<turboshaft::Opmask::kWord32ShiftLeft, 0, 31,
                       kMode_Operand2_R_LSL_I, kMode_Operand2_R_LSL_R>(
      selector, opcode_return, node, value_return, shift_return);
}

template <typename Adapter>
bool TryMatchLSLImmediate(InstructionSelectorT<Adapter>* selector,
                          InstructionCode* opcode_return,
                          typename Adapter::node_t node,
                          InstructionOperand* value_return,
                          InstructionOperand* shift_return) {
  return TryMatchShiftImmediate<IrOpcode::kWord32Shl, 0, 31,
                                kMode_Operand2_R_LSL_I>(
      selector, opcode_return, node, value_return, shift_return);
}

template <>
bool TryMatchLSLImmediate(InstructionSelectorT<TurboshaftAdapter>* selector,
                          InstructionCode* opcode_return,
                          turboshaft::OpIndex node,
                          InstructionOperand* value_return,
                          InstructionOperand* shift_return) {
  return TryMatchShiftImmediate<turboshaft::Opmask::kWord32ShiftLeft, 0, 31,
                                kMode_Operand2_R_LSL_I>(
      selector, opcode_return, node, value_return, shift_return);
}

template <typename Adapter>
bool TryMatchLSR(InstructionSelectorT<Adapter>* selector,
                 InstructionCode* opcode_return, typename Adapter::node_t node,
                 InstructionOperand* value_return,
                 InstructionOperand* shift_return) {
  return TryMatchShift<IrOpcode::kWord32Shr, 1, 32, kMode_Operand2_R_LSR_I,
                       kMode_Operand2_R_LSR_R>(selector, opcode_return, node,
                                               value_return, shift_return);
}

template <>
bool TryMatchLSR(InstructionSelectorT<TurboshaftAdapter>* selector,
                 InstructionCode* opcode_return, turboshaft::OpIndex node,
                 InstructionOperand* value_return,
                 InstructionOperand* shift_return) {
  return TryMatchShift<turboshaft::Opmask::kWord32ShiftRightLogical, 1, 32,
                       kMode_Operand2_R_LSR_I, kMode_Operand2_R_LSR_R>(
      selector, opcode_return, node, value_return, shift_return);
}

template <typename Adapter>
bool TryMatchShift(InstructionSelectorT<Adapter>* selector,
                   InstructionCode* opcode_return,
                   typename Adapter::node_t node,
                   InstructionOperand* value_return,
                   InstructionOperand* shift_return) {
  return (
      TryMatchASR(selector, opcode_return, node, value_return, shift_return) ||
      TryMatchLSL(selector, opcode_return, node, value_return, shift_return) ||
      TryMatchLSR(selector, opcode_return, node, value_return, shift_return) ||
      TryMatchROR(selector, opcode_return, node, value_return, shift_return));
}

template <typename Adapter>
bool TryMatchImmediateOrShift(InstructionSelectorT<Adapter>* selector,
                              InstructionCode* opcode_return,
                              typename Adapter::node_t node,
                              size_t* input_count_return,
                              InstructionOperand* inputs) {
  ArmOperandGeneratorT<Adapter> g(selector);
  if (g.CanBeImmediate(node, *opcode_return)) {
    *opcode_return |= AddressingModeField::encode(kMode_Operand2_I);
    inputs[0] = g.UseImmediate(node);
    *input_count_return = 1;
    return true;
  }
  if (TryMatchShift(selector, opcode_return, node, &inputs[0], &inputs[1])) {
    *input_count_return = 2;
    return true;
  }
  return false;
}

template <typename Adapter>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                InstructionCode reverse_opcode,
                FlagsContinuationT<Adapter>* cont) {
  using node_t = typename Adapter::node_t;
  ArmOperandGeneratorT<Adapter> g(selector);
  node_t lhs = selector->input_at(node, 0);
  node_t rhs = selector->input_at(node, 1);
  InstructionOperand inputs[3];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  if (lhs == rhs) {
    // If both inputs refer to the same operand, enforce allocating a register
    // for both of them to ensure that we don't end up generating code like
    // this:
    //
    //   mov r0, r1, asr #16
    //   adds r0, r0, r1, asr #16
    //   bvs label
    InstructionOperand const input = g.UseRegister(lhs);
    opcode |= AddressingModeField::encode(kMode_Operand2_R);
    inputs[input_count++] = input;
    inputs[input_count++] = input;
  } else if (TryMatchImmediateOrShift(selector, &opcode, rhs, &input_count,
                                      &inputs[1])) {
    inputs[0] = g.UseRegister(lhs);
    input_count++;
  } else if (TryMatchImmediateOrShift(selector, &reverse_opcode, lhs,
                                      &input_count, &inputs[1])) {
    inputs[0] = g.UseRegister(rhs);
    opcode = reverse_opcode;
    input_count++;
  } else {
    opcode |= AddressingModeField::encode(kMode_Operand2_R);
    inputs[input_count++] = g.UseRegister(lhs);
    inputs[input_count++] = g.UseRegister(rhs);
  }

  outputs[output_count++] = g.DefineAsRegister(node);

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);
  DCHECK_NE(kMode_None, AddressingModeField::decode(opcode));

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                InstructionCode reverse_opcode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop(selector, node, opcode, reverse_opcode, &cont);
}

template <typename Adapter>
void EmitDiv(InstructionSelectorT<Adapter>* selector, ArchOpcode div_opcode,
             ArchOpcode f64i32_opcode, ArchOpcode i32f64_opcode,
             InstructionOperand result_operand, InstructionOperand left_operand,
             InstructionOperand right_operand) {
  ArmOperandGeneratorT<Adapter> g(selector);
  if (selector->IsSupported(SUDIV)) {
    selector->Emit(div_opcode, result_operand, left_operand, right_operand);
    return;
  }
  InstructionOperand left_double_operand = g.TempDoubleRegister();
  InstructionOperand right_double_operand = g.TempDoubleRegister();
  InstructionOperand result_double_operand = g.TempDoubleRegister();
  selector->Emit(f64i32_opcode, left_double_operand, left_operand);
  selector->Emit(f64i32_opcode, right_double_operand, right_operand);
  selector->Emit(kArmVdivF64, result_double_operand, left_double_operand,
                 right_double_operand);
  selector->Emit(i32f64_opcode, result_operand, result_double_operand);
}

template <typename Adapter>
void VisitDiv(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode div_opcode,
              ArchOpcode f64i32_opcode, ArchOpcode i32f64_opcode) {
    ArmOperandGeneratorT<Adapter> g(selector);
    EmitDiv(selector, div_opcode, f64i32_opcode, i32f64_opcode,
            g.DefineAsRegister(node),
            g.UseRegister(selector->input_at(node, 0)),
            g.UseRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
void VisitMod(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode div_opcode,
              ArchOpcode f64i32_opcode, ArchOpcode i32f64_opcode) {
  ArmOperandGeneratorT<Adapter> g(selector);
  InstructionOperand div_operand = g.TempRegister();
  InstructionOperand result_operand = g.DefineAsRegister(node);
  InstructionOperand left_operand = g.UseRegister(selector->input_at(node, 0));
  InstructionOperand right_operand = g.UseRegister(selector->input_at(node, 1));
  EmitDiv(selector, div_opcode, f64i32_opcode, i32f64_opcode, div_operand,
          left_operand, right_operand);
  if (selector->IsSupported(ARMv7)) {
    selector->Emit(kArmMls, result_operand, div_operand, right_operand,
                   left_operand);
  } else {
    InstructionOperand mul_operand = g.TempRegister();
    selector->Emit(kArmMul, mul_operand, div_operand, right_operand);
    selector->Emit(kArmSub | AddressingModeField::encode(kMode_Operand2_R),
                   result_operand, left_operand, mul_operand);
  }
}

// Adds the base and offset into a register, then change the addressing
// mode of opcode_return to use this register. Certain instructions, e.g.
// vld1 and vst1, when given two registers, will post-increment the offset, i.e.
// perform the operation at base, then add offset to base. What we intend is to
// access at (base+offset).
template <typename Adapter>
void EmitAddBeforeS128LoadStore(InstructionSelectorT<Adapter>* selector,
                                InstructionCode* opcode_return,
                                size_t* input_count_return,
                                InstructionOperand* inputs) {
  ArmOperandGeneratorT<Adapter> g(selector);
  InstructionOperand addr = g.TempRegister();
  InstructionCode op = kArmAdd;
  op |= AddressingModeField::encode(kMode_Operand2_R);
  selector->Emit(op, 1, &addr, 2, inputs);
  *opcode_return |= AddressingModeField::encode(kMode_Operand2_R);
  *input_count_return -= 1;
  inputs[0] = addr;
}

void EmitLoad(InstructionSelectorT<TurboshaftAdapter>* selector,
              InstructionCode opcode, InstructionOperand* output,
              turboshaft::OpIndex base, turboshaft::OpIndex index) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArmOperandGeneratorT<TurboshaftAdapter> g(selector);
  InstructionOperand inputs[3];
  size_t input_count = 2;

  const Operation& base_op = selector->Get(base);
  if (base_op.Is<Opmask::kExternalConstant>() &&
      selector->is_integer_constant(index)) {
    const ConstantOp& constant_base = base_op.Cast<ConstantOp>();
    if (selector->CanAddressRelativeToRootsRegister(
            constant_base.external_reference())) {
      ptrdiff_t const delta =
          selector->integer_constant(index) +
          MacroAssemblerBase::RootRegisterOffsetForExternalReference(
              selector->isolate(), constant_base.external_reference());
      input_count = 1;
      inputs[0] = g.UseImmediate(static_cast<int32_t>(delta));
      opcode |= AddressingModeField::encode(kMode_Root);
      selector->Emit(opcode, 1, output, input_count, inputs);
      return;
    }
  }

  if (base_op.Is<LoadRootRegisterOp>()) {
    input_count = 1;
    // This will only work if {index} is a constant.
    inputs[0] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, 1, output, input_count, inputs);
    return;
  }

  inputs[0] = g.UseRegister(base);
  if (g.CanBeImmediate(index, opcode)) {
    inputs[1] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_Offset_RI);
  } else if ((opcode == kArmLdr) &&
             TryMatchLSLImmediate(selector, &opcode, index, &inputs[1],
                                  &inputs[2])) {
    input_count = 3;
  } else {
    inputs[1] = g.UseRegister(index);
    if (opcode == kArmVld1S128) {
      EmitAddBeforeS128LoadStore(selector, &opcode, &input_count, &inputs[0]);
    } else {
      opcode |= AddressingModeField::encode(kMode_Offset_RR);
    }
  }
  selector->Emit(opcode, 1, output, input_count, inputs);
}

void EmitLoad(InstructionSelectorT<TurbofanAdapter>* selector,
              InstructionCode opcode, InstructionOperand* output, Node* base,
              Node* index) {
  ArmOperandGeneratorT<TurbofanAdapter> g(selector);
  InstructionOperand inputs[3];
  size_t input_count = 2;

  ExternalReferenceMatcher m(base);
  if (m.HasResolvedValue() &&
      selector->CanAddressRelativeToRootsRegister(m.ResolvedValue())) {
    Int32Matcher int_matcher(index);
    if (int_matcher.HasResolvedValue()) {
      ptrdiff_t const delta =
          int_matcher.ResolvedValue() +
          MacroAssemblerBase::RootRegisterOffsetForExternalReference(
              selector->isolate(), m.ResolvedValue());
      input_count = 1;
      inputs[0] = g.UseImmediate(static_cast<int32_t>(delta));
      opcode |= AddressingModeField::encode(kMode_Root);
      selector->Emit(opcode, 1, output, input_count, inputs);
      return;
    }
  }

  if (base->opcode() == IrOpcode::kLoadRootRegister) {
    input_count = 1;
    // This will only work if {index} is a constant.
    inputs[0] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, 1, output, input_count, inputs);
    return;
  }

  inputs[0] = g.UseRegister(base);
  if (g.CanBeImmediate(index, opcode)) {
    inputs[1] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_Offset_RI);
  } else if ((opcode == kArmLdr) &&
             TryMatchLSLImmediate(selector, &opcode, index, &inputs[1],
                                  &inputs[2])) {
    input_count = 3;
  } else {
    inputs[1] = g.UseRegister(index);
    if (opcode == kArmVld1S128) {
      EmitAddBeforeS128LoadStore(selector, &opcode, &input_count, &inputs[0]);
    } else {
      opcode |= AddressingModeField::encode(kMode_Offset_RR);
    }
  }
  selector->Emit(opcode, 1, output, input_count, inputs);
}

template <typename Adapter>
void EmitStore(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
               size_t input_count, InstructionOperand* inputs,
               typename Adapter::node_t index) {
  ArmOperandGeneratorT<Adapter> g(selector);
  ArchOpcode arch_opcode = ArchOpcodeField::decode(opcode);

  if (g.CanBeImmediate(index, opcode)) {
    inputs[input_count++] = g.UseImmediate(index);
    opcode |= AddressingModeField::encode(kMode_Offset_RI);
  } else if ((arch_opcode == kArmStr || arch_opcode == kAtomicStoreWord32) &&
             TryMatchLSLImmediate(selector, &opcode, index, &inputs[2],
                                  &inputs[3])) {
    input_count = 4;
  } else {
    inputs[input_count++] = g.UseRegister(index);
    if (arch_opcode == kArmVst1S128) {
      // Inputs are value, base, index, only care about base and index.
      EmitAddBeforeS128LoadStore(selector, &opcode, &input_count, &inputs[1]);
    } else {
      opcode |= AddressingModeField::encode(kMode_Offset_RR);
    }
  }
  selector->Emit(opcode, 0, nullptr, input_count, inputs);
}

template <typename Adapter>
void VisitPairAtomicBinOp(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node, ArchOpcode opcode) {
  ArmOperandGeneratorT<Adapter> g(selector);
  using node_t = typename Adapter::node_t;
  node_t base = selector->input_at(node, 0);
  node_t index = selector->input_at(node, 1);
  node_t value = selector->input_at(node, 2);
  node_t value_high = selector->input_at(node, 3);
  AddressingMode addressing_mode = kMode_Offset_RR;
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  InstructionOperand inputs[] = {
      g.UseUniqueRegister(value), g.UseUniqueRegister(value_high),
      g.UseUniqueRegister(base), g.UseUniqueRegister(index)};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  InstructionOperand temps[6];
  size_t temp_count = 0;
  temps[temp_count++] = g.TempRegister();
  temps[temp_count++] = g.TempRegister(r6);
  temps[temp_count++] = g.TempRegister(r7);
  temps[temp_count++] = g.TempRegister();
  node_t projection0 = selector->FindProjection(node, 0);
  node_t projection1 = selector->FindProjection(node, 1);
  if (selector->valid(projection0)) {
    outputs[output_count++] = g.DefineAsFixed(projection0, r2);
  } else {
    temps[temp_count++] = g.TempRegister(r2);
  }
  if (selector->valid(projection1)) {
    outputs[output_count++] = g.DefineAsFixed(projection1, r3);
  } else {
    temps[temp_count++] = g.TempRegister(r3);
  }
  selector->Emit(code, output_count, outputs, arraysize(inputs), inputs,
                 temp_count, temps);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackSlot(node_t node) {
  StackSlotRepresentation rep = this->stack_slot_representation_of(node);
  int slot =
      frame_->AllocateSpillSlot(rep.size(), rep.alignment(), rep.is_tagged());
  OperandGenerator g(this);

  Emit(kArchStackSlot, g.DefineAsRegister(node),
       sequence()->AddImmediate(Constant(slot)), 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitAbortCSADcheck(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), r1));
}

#if V8_ENABLE_WEBASSEMBLY
namespace {
MachineRepresentation MachineRepresentationOf(
    turboshaft::Simd128LaneMemoryOp::LaneKind lane_kind) {
  using turboshaft::Simd128LaneMemoryOp;
  switch (lane_kind) {
    case Simd128LaneMemoryOp::LaneKind::k8:
      return MachineRepresentation::kWord8;
    case Simd128LaneMemoryOp::LaneKind::k16:
      return MachineRepresentation::kWord16;
    case Simd128LaneMemoryOp::LaneKind::k32:
      return MachineRepresentation::kWord32;
    case Simd128LaneMemoryOp::LaneKind::k64:
      return MachineRepresentation::kWord64;
  }
}
}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& store = Get(node).Cast<Simd128LaneMemoryOp>();

  LoadStoreLaneParams f(MachineRepresentationOf(store.lane_kind), store.lane);
  InstructionCode opcode =
      f.low_op ? kArmS128StoreLaneLow : kArmS128StoreLaneHigh;
  opcode |= MiscField::encode(f.sz);

  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand inputs[4];
  size_t input_count = 4;
  inputs[0] = g.UseRegister(store.value());
  inputs[1] = g.UseImmediate(f.laneidx);
  inputs[2] = g.UseRegister(store.base());
  inputs[3] = g.UseRegister(store.index());
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[2]);
  Emit(opcode, 0, nullptr, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  StoreLaneParameters params = StoreLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep, params.laneidx);
  InstructionCode opcode =
      f.low_op ? kArmS128StoreLaneLow : kArmS128StoreLaneHigh;
  opcode |= MiscField::encode(f.sz);

  ArmOperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand inputs[4];
  size_t input_count = 4;
  inputs[0] = g.UseRegister(node->InputAt(2));
  inputs[1] = g.UseImmediate(f.laneidx);
  inputs[2] = g.UseRegister(node->InputAt(0));
  inputs[3] = g.UseRegister(node->InputAt(1));
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &
```