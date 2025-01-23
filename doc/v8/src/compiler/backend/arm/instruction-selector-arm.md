Response: The user wants me to summarize the functionality of the provided C++ code. This is the first part of a larger file. The code seems to be related to instruction selection for the ARM architecture within the V8 JavaScript engine.

Here's a breakdown of the code:

1. **Includes:** Standard C++ headers and V8-specific headers related to compiler infrastructure.
2. **Namespaces:**  Code resides within `v8::internal::compiler`.
3. **`ArmOperandGeneratorT`:** A template class that extends `OperandGeneratorT`. It provides ARM-specific methods for generating instruction operands, specifically focusing on whether certain values can be used as immediate operands for various ARM instructions.
4. **Helper Functions:** Several template helper functions (`VisitRR`, `VisitRRR`, `VisitSimdShiftRRR`, `VisitRRRShuffle`, `VisitRRI`, `VisitRRIR`) are defined for emitting different types of ARM instructions. These functions handle the details of extracting operands from the compiler's intermediate representation and formatting them for the assembler. There's also a conditional compilation block for WebAssembly (`#if V8_ENABLE_WEBASSEMBLY`).
5. **`TryMatchShift` Family:** A set of template functions (`TryMatchShift`, `TryMatchShiftImmediate`) that attempt to recognize shift operations in the intermediate representation and encode them directly into the instruction operand, potentially avoiding explicit shift instructions.
6. **`TryMatchImmediateOrShift`:** A template function that tries to match either an immediate operand or a shift operation.
7. **`VisitBinop`:** Template functions for handling binary operations. These functions determine the appropriate ARM instruction based on the operands and addressing modes, potentially using immediate values or shift operations when possible.
8. **`EmitDiv` and `VisitDiv`:** Functions for emitting division instructions, handling the case where integer division instructions might not be directly supported by the target architecture.
9. **`VisitMod`:** A function for emitting modulo operations.
10. **`EmitAddBeforeS128LoadStore`:** A function to pre-calculate the address for certain SIMD load/store instructions.
11. **`EmitLoad`:** Functions for emitting load instructions, handling different addressing modes, including those relative to the root register.
12. **`EmitStore`:** A function for emitting store instructions.
13. **`VisitPairAtomicBinOp`:** A function to handle atomic binary operations on pairs of values.
14. **`VisitStackSlot`:**  Handles the allocation of stack slots.
15. **`VisitAbortCSADcheck`:**  Seems to be a specific check related to code generation.
16. **WebAssembly Specific Code:**  Sections for handling WebAssembly SIMD instructions (`VisitStoreLane`, `VisitLoadLane`, `VisitLoadTransform`).
17. **`VisitLoad`:** Handles general load operations, mapping the compiler's representation to specific ARM load instructions.
18. **`VisitProtectedLoad`:** Marked as unimplemented.
19. **`GetStoreOpcode` and `GetAtomicStoreOpcode`:** Helper functions to determine the correct store opcode based on the data type and atomicity requirements.
20. **`VisitStoreCommon`:** A common function used by `VisitStore` and potentially other store-related visitors to handle write barriers and generate the appropriate store instruction.
21. **`VisitStorePair`:** Marked as unreachable.
22. **`VisitStore`:** Handles general store operations.
23. **`VisitProtectedStore`:** Marked as unimplemented.
24. **`VisitUnalignedLoad` and `VisitUnalignedStore`:** Handle load and store operations for unaligned memory access, potentially requiring special handling for floating-point values.
25. **`EmitBic` and `EmitUbfx`:** Helper functions for emitting specific bit manipulation instructions.
26. **`VisitWord32And`:** Handles 32-bit AND operations, with optimizations for specific constant operands and the possibility of merging shift operations.
27. **`VisitWord32Or`:** Handles 32-bit OR operations.
28. **`VisitWord32Xor`:** Handles 32-bit XOR operations, including an optimization for XORing with -1 (NOT operation).

**Overall Functionality:**

This code defines the ARM-specific logic for the instruction selection phase of the V8 compiler. It takes the architecture-independent intermediate representation of the code and translates it into sequences of ARM instructions. It includes optimizations for common patterns, such as using immediate values and combining shift operations with arithmetic/logical operations. The code also handles memory access (loads and stores), including specific logic for unaligned access and write barriers for garbage collection. There's also dedicated code for supporting WebAssembly SIMD instructions.

**Relationship to JavaScript:**

This code is a crucial part of the V8 engine, which executes JavaScript code. The instruction selection process directly impacts the performance of the generated machine code for JavaScript programs. The optimizations implemented here can lead to more efficient execution of JavaScript.

**JavaScript Examples (Illustrative):**

While this C++ code doesn't directly *execute* JavaScript, its behavior is determined by the need to efficiently implement JavaScript semantics. Here are some JavaScript examples and how this code *might* be involved in their compilation:

1. **Bitwise Operations:**

    ```javascript
    let a = 10;
    let b = 5;
    let c = a & b; // Bitwise AND
    let d = a | b; // Bitwise OR
    let e = a ^ b; // Bitwise XOR
    let f = ~a;   // Bitwise NOT
    ```

    The `VisitWord32And`, `VisitWord32Or`, and `VisitWord32Xor` functions (and the associated optimizations like handling `~value` in `VisitWord32And` and `-1` in `VisitWord32Xor`) would be directly involved in selecting the optimal ARM instructions to perform these bitwise operations.

2. **Arithmetic Operations:**

    ```javascript
    let x = 10;
    let y = 3;
    let sum = x + y;
    let diff = x - y;
    let prod = x * y;
    let quot = Math.floor(x / y);
    let rem = x % y;
    ```

    The `VisitBinop` function would be used for addition and subtraction. `VisitDiv` and `VisitMod` would be responsible for generating the division and modulo operations, potentially using floating-point emulation if integer division isn't directly supported.

3. **Memory Access:**

    ```javascript
    let arr = [1, 2, 3];
    let first = arr[0];
    arr[1] = 4;
    ```

    The `VisitLoad` function would be used to generate instructions for reading `arr[0]`, and `VisitStore` would be used for writing to `arr[1]`. The logic within these functions would handle the address calculation and potentially the write barrier if the array contains objects.

4. **Shift Operations:**

    ```javascript
    let num = 8;
    let shiftedLeft = num << 2;
    let shiftedRight = num >> 1;
    let unsignedShift = num >>> 1;
    ```

    The `TryMatchShift` family of functions would attempt to integrate these shift operations directly into the operands of other instructions, or generate explicit shift instructions if necessary.

5. **WebAssembly (if enabled):**

    ```javascript
    const wasmInstance = new WebAssembly.Instance(wasmModule);
    const simdResult = wasmInstance.exports.simdFunction();
    ```

    The WebAssembly-specific `VisitStoreLane`, `VisitLoadLane`, and `VisitLoadTransform` functions would be used to generate the appropriate ARM NEON instructions for WebAssembly's SIMD operations.

In essence, this C++ code acts as a translator, converting the abstract operations defined in the intermediate representation of a JavaScript program into the concrete instructions that the ARM processor can understand and execute. Its efficiency and correctness are vital for the overall performance of JavaScript execution in V8 on ARM-based devices.

这是 `v8/src/compiler/backend/arm/instruction-selector-arm.cc` 文件的第一部分，主要负责 **ARM 架构下的指令选择**。指令选择是编译器后端的一个关键阶段，它将中间表示 (IR) 的操作转换成目标架构 (这里是 ARM) 的具体机器指令。

以下是这个部分的主要功能归纳：

1. **定义了 `ArmOperandGeneratorT` 模板类:**  这个类继承自 `OperandGeneratorT`，专门为 ARM 架构生成指令操作数。它包含了一些辅助方法，用于判断一个值是否可以作为 ARM 指令的立即数，针对不同的 ARM 指令有不同的判断规则。

2. **提供了一系列模板化的访问函数 (`VisitRR`, `VisitRRR` 等):** 这些函数用于处理不同类型的操作节点，并生成相应的 ARM 指令。例如，`VisitRR` 处理两个寄存器操作数的指令，`VisitRRR` 处理三个寄存器操作数的指令。

3. **实现了 SIMD 指令的支持 (如果启用了 WebAssembly):**  `VisitSimdShiftRRR`, `VisitRRRShuffle`, `VisitRRI`, `VisitRRIR` 等函数用于处理 SIMD (单指令多数据流) 指令，这在 WebAssembly 中被广泛使用以提高性能。

4. **提供了匹配移位操作的机制 (`TryMatchShift` 系列函数):** 这些函数尝试识别 IR 中的移位操作，并将其直接编码到指令的操作数中，而不是生成单独的移位指令，从而优化代码。

5. **实现了匹配立即数或移位操作的机制 (`TryMatchImmediateOrShift`):** 这个函数尝试判断一个操作数是否可以是立即数或一个移位操作的结果，并相应地设置指令的寻址模式。

6. **定义了处理二元运算的函数 (`VisitBinop`):**  这个函数根据操作符和操作数的类型，选择合适的 ARM 二元运算指令，并处理立即数和移位操作数的优化。

7. **实现了除法和取模运算的处理 (`EmitDiv`, `VisitDiv`, `VisitMod`):**  这些函数处理整数的除法和取模运算，考虑到 ARM 架构可能不支持直接的整数除法指令，会采用浮点数运算进行模拟。

8. **提供了处理 S128 (128 位 SIMD) 加载和存储前的地址计算 (`EmitAddBeforeS128LoadStore`):**  这个函数用于在执行某些 SIMD 加载和存储指令之前，计算出正确的内存地址。

9. **实现了加载指令的处理 (`EmitLoad`, `VisitLoad`):**  这些函数负责将 IR 中的加载操作转换成 ARM 的加载指令 (`LDR`, `LDRB`, `LDRH`, `VLDR` 等)，并处理不同的数据类型和寻址模式，包括基于 Root Register 的寻址。

10. **实现了存储指令的处理 (`EmitStore`, `VisitStoreCommon`, `VisitStore`):** 这些函数负责将 IR 中的存储操作转换成 ARM 的存储指令 (`STR`, `STRB`, `STRH`, `VSTR` 等)，并处理不同的数据类型、寻址模式以及写屏障 (Write Barrier) 的插入，用于垃圾回收。

11. **实现了未对齐的加载和存储指令的处理 (`VisitUnalignedLoad`, `VisitUnalignedStore`):**  这些函数处理内存未对齐的情况，特别是对于浮点数的加载和存储，可能需要使用额外的指令来保证正确性。

12. **实现了位运算的处理 (`EmitBic`, `EmitUbfx`, `VisitWord32And`, `VisitWord32Or`, `VisitWord32Xor`):**  这些函数负责将 IR 中的位运算操作 (AND, OR, XOR) 转换成相应的 ARM 指令，并进行了一些特定的优化，例如使用 `BIC` 指令来实现某些 `AND` 操作，使用 `UBFX` 指令来实现位域提取等。

**与 JavaScript 功能的关系:**

这段代码是 V8 JavaScript 引擎的一部分，负责将 JavaScript 代码编译成高效的 ARM 机器码。它直接影响 JavaScript 代码的执行效率。

**JavaScript 例子:**

```javascript
let a = 10;
let b = 5;
let c = a + b; // 加法
let d = a & b; // 位与
let arr = [1, 2, 3];
let first = arr[0]; // 读取数组元素
arr[1] = 4;       // 修改数组元素

// 如果启用了 WebAssembly
const wasmBuffer = new Uint8Array([...]); // WebAssembly 字节码
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const result = wasmInstance.exports.add(a, b);
```

*   **`let c = a + b;`**:  `VisitBinop` 函数会被调用，选择 ARM 的加法指令 (`ADD`)。`ArmOperandGeneratorT` 会判断 `a` 和 `b` 是否可以直接作为立即数，或者需要加载到寄存器中。
*   **`let d = a & b;`**: `VisitWord32And` 函数会被调用，选择 ARM 的位与指令 (`AND`)。代码中会尝试优化，例如，如果 `b` 是一个特定的常数，可能会使用 `BIC` 指令。
*   **`let first = arr[0];`**: `VisitLoad` 函数会被调用，生成 ARM 的加载指令 (`LDR`) 从数组的内存地址中读取数据。
*   **`arr[1] = 4;`**: `VisitStore` 函数会被调用，生成 ARM 的存储指令 (`STR`) 将值 `4` 写入数组的内存地址。如果数组存储的是对象，还会涉及到写屏障的处理。
*   **WebAssembly**:  如果 JavaScript 代码调用了 WebAssembly 模块，并且 WebAssembly 代码中使用了 SIMD 指令，那么 `VisitSimdShiftRRR` 等函数会被用来生成相应的 ARM NEON 指令。

总而言之，这个 C++ 文件是 V8 引擎中将 JavaScript 代码转换为高效 ARM 机器码的关键部分，它通过精细的指令选择和优化，提升 JavaScript 的执行性能。

### 提示词
```
这是目录为v8/src/compiler/backend/arm/instruction-selector-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[2]);
  Emit(opcode, 0, nullptr, input_count, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LaneMemoryOp& load = this->Get(node).Cast<Simd128LaneMemoryOp>();
  LoadStoreLaneParams f(MachineRepresentationOf(load.lane_kind), load.lane);
  InstructionCode opcode =
      f.low_op ? kArmS128LoadLaneLow : kArmS128LoadLaneHigh;
  opcode |= MiscField::encode(f.sz);

  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand output = g.DefineSameAsFirst(node);
  InstructionOperand inputs[4];
  size_t input_count = 4;
  inputs[0] = g.UseRegister(load.value());
  inputs[1] = g.UseImmediate(f.laneidx);
  inputs[2] = g.UseRegister(load.base());
  inputs[3] = g.UseRegister(load.index());
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[2]);
  Emit(opcode, 1, &output, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep.representation(), params.laneidx);
  InstructionCode opcode =
      f.low_op ? kArmS128LoadLaneLow : kArmS128LoadLaneHigh;
  opcode |= MiscField::encode(f.sz);

  ArmOperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand output = g.DefineSameAsFirst(node);
  InstructionOperand inputs[4];
  size_t input_count = 4;
  inputs[0] = g.UseRegister(node->InputAt(2));
  inputs[1] = g.UseImmediate(f.laneidx);
  inputs[2] = g.UseRegister(node->InputAt(0));
  inputs[3] = g.UseRegister(node->InputAt(1));
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[2]);
  Emit(opcode, 1, &output, input_count, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LoadTransformOp& op =
      this->Get(node).Cast<Simd128LoadTransformOp>();
  InstructionCode opcode = kArchNop;
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kArmS128Load8Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kArmS128Load16Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kArmS128Load32Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kArmS128Load64Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8S:
      opcode = kArmS128Load8x8S;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kArmS128Load8x8U;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kArmS128Load16x4S;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kArmS128Load16x4U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kArmS128Load32x2S;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kArmS128Load32x2U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kArmS128Load32Zero;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Zero:
      opcode = kArmS128Load64Zero;
      break;
    default:
      UNIMPLEMENTED();
  }

  ArmOperandGeneratorT<TurboshaftAdapter> g(this);
  InstructionOperand output = g.DefineAsRegister(node);
  InstructionOperand inputs[2];
  size_t input_count = 2;
  inputs[0] = g.UseRegister(op.base());
  inputs[1] = g.UseRegister(op.index());
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[0]);
  Emit(opcode, 1, &output, input_count, inputs);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());
  InstructionCode opcode = kArchNop;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kArmS128Load8Splat;
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kArmS128Load16Splat;
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kArmS128Load32Splat;
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kArmS128Load64Splat;
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kArmS128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kArmS128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kArmS128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kArmS128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kArmS128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kArmS128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kArmS128Load32Zero;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kArmS128Load64Zero;
      break;
    default:
      UNIMPLEMENTED();
  }

  ArmOperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand output = g.DefineAsRegister(node);
  InstructionOperand inputs[2];
  size_t input_count = 2;
  inputs[0] = g.UseRegister(node->InputAt(0));
  inputs[1] = g.UseRegister(node->InputAt(1));
  EmitAddBeforeS128LoadStore(this, &opcode, &input_count, &inputs[0]);
  Emit(opcode, 1, &output, input_count, inputs);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  typename Adapter::LoadView load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();
  ArmOperandGeneratorT<Adapter> g(this);
  node_t base = load.base();
  node_t index = load.index();

  InstructionCode opcode = kArchNop;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kArmVldrF32;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kArmVldrF64;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsUnsigned() ? kArmLdrb : kArmLdrsb;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsUnsigned() ? kArmLdrh : kArmLdrsh;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      opcode = kArmLdr;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kArmVld1S128;
      break;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kSimd256:            // Fall through.
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:         // Fall through.
    case MachineRepresentation::kProtectedPointer:   // Fall through.
    case MachineRepresentation::kIndirectPointer:    // Fall through.
    case MachineRepresentation::kSandboxedPointer:   // Fall through.
    case MachineRepresentation::kWord64:             // Fall through.
    case MachineRepresentation::kMapWord:            // Fall through.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }

  InstructionOperand output = g.DefineAsRegister(node);
  EmitLoad(this, opcode, &output, base, index);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

namespace {

ArchOpcode GetStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kFloat32:
      return kArmVstrF32;
    case MachineRepresentation::kFloat64:
      return kArmVstrF64;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return kArmStrb;
    case MachineRepresentation::kWord16:
      return kArmStrh;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      return kArmStr;
    case MachineRepresentation::kSimd128:
      return kArmVst1S128;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kSimd256:            // Fall through.
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:         // Fall through.
    case MachineRepresentation::kProtectedPointer:   // Fall through.
    case MachineRepresentation::kIndirectPointer:    // Fall through.
    case MachineRepresentation::kSandboxedPointer:   // Fall through.
    case MachineRepresentation::kWord64:             // Fall through.
    case MachineRepresentation::kMapWord:            // Fall through.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }
}

ArchOpcode GetAtomicStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kWord8:
      return kAtomicStoreWord8;
    case MachineRepresentation::kWord16:
      return kAtomicStoreWord16;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      return kAtomicStoreWord32;
    default:
      UNREACHABLE();
  }
}

template <typename Adapter>
void VisitStoreCommon(InstructionSelectorT<Adapter>* selector,
                      typename Adapter::node_t node,
                      StoreRepresentation store_rep,
                      std::optional<AtomicMemoryOrder> atomic_order) {
  using node_t = typename Adapter::node_t;
  ArmOperandGeneratorT<Adapter> g(selector);
  auto store_view = selector->store_view(node);
  node_t base = store_view.base();
  node_t index = selector->value(store_view.index());
  node_t value = store_view.value();

  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  MachineRepresentation rep = store_rep.representation();

  if (v8_flags.enable_unconditional_write_barriers && CanBeTaggedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[3];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    // OutOfLineRecordWrite uses the index in an 'add' instruction as well as
    // for the store itself, so we must check compatibility with both.
    if (g.CanBeImmediate(index, kArmAdd) && g.CanBeImmediate(index, kArmStr)) {
      inputs[input_count++] = g.UseImmediate(index);
      addressing_mode = kMode_Offset_RI;
    } else {
      inputs[input_count++] = g.UseUniqueRegister(index);
      addressing_mode = kMode_Offset_RR;
    }
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionCode code;
    if (!atomic_order) {
      code = kArchStoreWithWriteBarrier;
      code |= RecordWriteModeField::encode(record_write_mode);
    } else {
      code = kArchAtomicStoreWithWriteBarrier;
      code |= AtomicMemoryOrderField::encode(*atomic_order);
      code |= AtomicStoreRecordWriteModeField::encode(record_write_mode);
    }
    code |= AddressingModeField::encode(addressing_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs);
  } else {
    InstructionCode opcode = kArchNop;
    if (!atomic_order) {
      opcode = GetStoreOpcode(rep);
    } else {
      // Release stores emit DMB ISH; STR while sequentially consistent stores
      // emit DMB ISH; STR; DMB ISH.
      // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
      opcode = GetAtomicStoreOpcode(rep);
      opcode |= AtomicMemoryOrderField::encode(*atomic_order);
    }

    std::optional<ExternalReference> external_base;
    if constexpr (Adapter::IsTurboshaft) {
      ExternalReference value;
      if (selector->MatchExternalConstant(store_view.base(), &value)) {
        external_base = value;
      }
    } else {
      ExternalReferenceMatcher m(store_view.base());
      if (m.HasResolvedValue()) {
        external_base = m.ResolvedValue();
      }
    }

    if (external_base &&
        selector->CanAddressRelativeToRootsRegister(*external_base)) {
      if (selector->is_integer_constant(index)) {
        ptrdiff_t const delta =
            selector->integer_constant(index) +
            MacroAssemblerBase::RootRegisterOffsetForExternalReference(
                selector->isolate(), *external_base);
        int input_count = 2;
        InstructionOperand inputs[2];
        inputs[0] = g.UseRegister(value);
        inputs[1] = g.UseImmediate(static_cast<int32_t>(delta));
        opcode |= AddressingModeField::encode(kMode_Root);
        selector->Emit(opcode, 0, nullptr, input_count, inputs);
        return;
      }
    }

    if (selector->is_load_root_register(base)) {
      int input_count = 2;
      InstructionOperand inputs[2];
      inputs[0] = g.UseRegister(value);
      inputs[1] = g.UseImmediate(index);
      opcode |= AddressingModeField::encode(kMode_Root);
      selector->Emit(opcode, 0, nullptr, input_count, inputs);
      return;
    }

    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseRegister(value);
    inputs[input_count++] = g.UseRegister(base);
    EmitStore(selector, opcode, input_count, inputs, index);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(node_t node) {
  VisitStoreCommon(this, node, this->store_view(node).stored_rep(),
                   std::nullopt);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  auto load = this->load_view(node);
  MachineRepresentation load_rep = load.loaded_rep().representation();
  ArmOperandGeneratorT<Adapter> g(this);
  node_t base = this->input_at(node, 0);
  node_t index = this->input_at(node, 1);

  InstructionCode opcode = kArmLdr;
  // Only floating point loads need to be specially handled; integer loads
  // support unaligned access. We support unaligned FP loads by loading to
  // integer registers first, then moving to the destination FP register. If
  // NEON is supported, we use the vld1.8 instruction.
  switch (load_rep) {
    case MachineRepresentation::kFloat32: {
      InstructionOperand temp = g.TempRegister();
      EmitLoad(this, opcode, &temp, base, index);
      Emit(kArmVmovF32U32, g.DefineAsRegister(node), temp);
      return;
    }
    case MachineRepresentation::kFloat64: {
      // Compute the address of the least-significant byte of the FP value.
      // We assume that the base node is unlikely to be an encodable immediate
      // or the result of a shift operation, so only consider the addressing
      // mode that should be used for the index node.
      InstructionCode add_opcode = kArmAdd;
      InstructionOperand inputs[3];
      inputs[0] = g.UseRegister(base);

      size_t input_count;
      if (TryMatchImmediateOrShift(this, &add_opcode, index, &input_count,
                                   &inputs[1])) {
        // input_count has been set by TryMatchImmediateOrShift(), so
        // increment it to account for the base register in inputs[0].
        input_count++;
      } else {
        add_opcode |= AddressingModeField::encode(kMode_Operand2_R);
        inputs[1] = g.UseRegister(index);
        input_count = 2;  // Base register and index.
      }

      InstructionOperand addr = g.TempRegister();
      Emit(add_opcode, 1, &addr, input_count, inputs);

      if (CpuFeatures::IsSupported(NEON)) {
        // With NEON we can load directly from the calculated address.
        InstructionCode op = kArmVld1F64;
        op |= AddressingModeField::encode(kMode_Operand2_R);
        Emit(op, g.DefineAsRegister(node), addr);
      } else {
        // Load both halves and move to an FP register.
        InstructionOperand fp_lo = g.TempRegister();
        InstructionOperand fp_hi = g.TempRegister();
        opcode |= AddressingModeField::encode(kMode_Offset_RI);
        Emit(opcode, fp_lo, addr, g.TempImmediate(0));
        Emit(opcode, fp_hi, addr, g.TempImmediate(4));
        Emit(kArmVmovF64U32U32, g.DefineAsRegister(node), fp_lo, fp_hi);
      }
      return;
    }
    default:
      // All other cases should support unaligned accesses.
      UNREACHABLE();
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  auto store_view = this->store_view(node);
  node_t base = store_view.base();
  node_t index = this->value(store_view.index());
  node_t value = store_view.value();

  InstructionOperand inputs[4];
  size_t input_count = 0;

  UnalignedStoreRepresentation store_rep =
      store_view.stored_rep().representation();

  // Only floating point stores need to be specially handled; integer stores
  // support unaligned access. We support unaligned FP stores by moving the
  // value to integer registers first, then storing to the destination address.
  // If NEON is supported, we use the vst1.8 instruction.
  switch (store_rep) {
    case MachineRepresentation::kFloat32: {
      inputs[input_count++] = g.TempRegister();
      Emit(kArmVmovU32F32, inputs[0], g.UseRegister(value));
      inputs[input_count++] = g.UseRegister(base);
      EmitStore(this, kArmStr, input_count, inputs, index);
      return;
    }
    case MachineRepresentation::kFloat64: {
      if (CpuFeatures::IsSupported(NEON)) {
        InstructionOperand address = g.TempRegister();
        {
          // First we have to calculate the actual address.
          InstructionCode add_opcode = kArmAdd;
          InstructionOperand inputs[3];
          inputs[0] = g.UseRegister(base);

          size_t input_count;
          if (TryMatchImmediateOrShift(this, &add_opcode, index, &input_count,
                                       &inputs[1])) {
            // input_count has been set by TryMatchImmediateOrShift(), so
            // increment it to account for the base register in inputs[0].
            input_count++;
          } else {
            add_opcode |= AddressingModeField::encode(kMode_Operand2_R);
            inputs[1] = g.UseRegister(index);
            input_count = 2;  // Base register and index.
          }

          Emit(add_opcode, 1, &address, input_count, inputs);
        }

        inputs[input_count++] = g.UseRegister(value);
        inputs[input_count++] = address;
        InstructionCode op = kArmVst1F64;
        op |= AddressingModeField::encode(kMode_Operand2_R);
        Emit(op, 0, nullptr, input_count, inputs);
      } else {
        // Store a 64-bit floating point value using two 32-bit integer stores.
        // Computing the store address here would require three live temporary
        // registers (fp<63:32>, fp<31:0>, address), so compute base + 4 after
        // storing the least-significant half of the value.

        // First, move the 64-bit FP value into two temporary integer registers.
        InstructionOperand fp[] = {g.TempRegister(), g.TempRegister()};
        inputs[input_count++] = g.UseRegister(value);
        Emit(kArmVmovU32U32F64, arraysize(fp), fp, input_count, inputs);

        // Store the least-significant half.
        inputs[0] = fp[0];  // Low 32-bits of FP value.
        inputs[input_count++] =
            g.UseRegister(base);  // First store base address.
        EmitStore(this, kArmStr, input_count, inputs, index);

        // Store the most-significant half.
        InstructionOperand base4 = g.TempRegister();
        Emit(kArmAdd | AddressingModeField::encode(kMode_Operand2_I), base4,
             g.UseRegister(base), g.TempImmediate(4));  // Compute base + 4.
        inputs[0] = fp[1];  // High 32-bits of FP value.
        inputs[1] = base4;  // Second store base + 4 address.
        EmitStore(this, kArmStr, input_count, inputs, index);
      }
      return;
    }
    default:
      // All other cases should support unaligned accesses.
      UNREACHABLE();
  }
}

namespace {

template <typename Adapter>
void EmitBic(InstructionSelectorT<Adapter>* selector,
             typename Adapter::node_t node, typename Adapter::node_t left,
             typename Adapter::node_t right) {
  ArmOperandGeneratorT<Adapter> g(selector);
  InstructionCode opcode = kArmBic;
  InstructionOperand value_operand;
  InstructionOperand shift_operand;
  if (TryMatchShift(selector, &opcode, right, &value_operand, &shift_operand)) {
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
                   value_operand, shift_operand);
    return;
  }
  selector->Emit(opcode | AddressingModeField::encode(kMode_Operand2_R),
                 g.DefineAsRegister(node), g.UseRegister(left),
                 g.UseRegister(right));
}

template <typename Adapter>
void EmitUbfx(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, typename Adapter::node_t left,
              uint32_t lsb, uint32_t width) {
  DCHECK_LE(lsb, 31u);
  DCHECK_LE(1u, width);
  DCHECK_LE(width, 32u - lsb);
  ArmOperandGeneratorT<Adapter> g(selector);
  selector->Emit(kArmUbfx, g.DefineAsRegister(node), g.UseRegister(left),
                 g.TempImmediate(lsb), g.TempImmediate(width));
}

}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  ArmOperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<WordBinopOp>();
  const Operation& lhs = Get(bitwise_and.left());

  if (lhs.Is<Opmask::kWord32BitwiseXor>() &&
      CanCover(node, bitwise_and.left())) {
    const WordBinopOp& bitwise_xor = lhs.Cast<WordBinopOp>();
    int32_t bitmask;
    if (MatchIntegralWord32Constant(bitwise_xor.right(), &bitmask) &&
        bitmask == -1) {
      EmitBic(this, node, bitwise_and.right(), bitwise_xor.left());
      return;
    }
  }

  const Operation& rhs = Get(bitwise_and.right());
  if (rhs.Is<Opmask::kWord32BitwiseXor>() &&
      CanCover(node, bitwise_and.right())) {
    const WordBinopOp& bitwise_xor = rhs.Cast<WordBinopOp>();
    int32_t bitmask;
    if (MatchIntegralWord32Constant(bitwise_xor.right(), &bitmask) &&
        bitmask == -1) {
      EmitBic(this, node, bitwise_and.left(), bitwise_xor.left());
      return;
    }
  }

  if (is_integer_constant(bitwise_and.right())) {
    uint32_t const value = integer_constant(bitwise_and.right());
    uint32_t width = base::bits::CountPopulation(value);
    uint32_t leading_zeros = base::bits::CountLeadingZeros32(value);

    // Try to merge SHR operations on the left hand input into this AND.
    if (lhs.Is<Opmask::kWord32ShiftRightLogical>()) {
      const ShiftOp& shr = lhs.Cast<ShiftOp>();
      if (is_integer_constant(shr.right())) {
        uint32_t const shift = integer_constant(shr.right());

        if (((shift == 8) || (shift == 16) || (shift == 24)) &&
            (value == 0xFF)) {
          // Merge SHR into AND by emitting a UXTB instruction with a
          // bytewise rotation.
          Emit(kArmUxtb, g.DefineAsRegister(node), g.UseRegister(shr.left()),
               g.TempImmediate(shift));
          return;
        } else if (((shift == 8) || (shift == 16)) && (value == 0xFFFF)) {
          // Merge SHR into AND by emitting a UXTH instruction with a
          // bytewise rotation.
          Emit(kArmUxth, g.DefineAsRegister(node), g.UseRegister(shr.left()),
               g.TempImmediate(shift));
          return;
        } else if (IsSupported(ARMv7) && (width != 0) &&
                   ((leading_zeros + width) == 32)) {
          // Merge Shr into And by emitting a UBFX instruction.
          DCHECK_EQ(0u, base::bits::CountTrailingZeros32(value));
          if ((1 <= shift) && (shift <= 31)) {
            // UBFX cannot extract bits past the register size, however since
            // shifting the original value would have introduced some zeros we
            // can still use UBFX with a smaller mask and the remaining bits
            // will be zeros.
            EmitUbfx(this, node, shr.left(), shift,
                     std::min(width, 32 - shift));
            return;
          }
        }
      }
    } else if (value == 0xFFFF) {
      // Emit UXTH for this AND. We don't bother testing for UXTB, as it's no
      // better than AND 0xFF for this operation.
      Emit(kArmUxth, g.DefineAsRegister(node),
           g.UseRegister(bitwise_and.left()), g.TempImmediate(0));
      return;
    }
    if (g.CanBeImmediate(~value)) {
      // Emit BIC for this AND by inverting the immediate value first.
      Emit(kArmBic | AddressingModeField::encode(kMode_Operand2_I),
           g.DefineAsRegister(node), g.UseRegister(bitwise_and.left()),
           g.TempImmediate(~value));
      return;
    }
    if (!g.CanBeImmediate(value) && IsSupported(ARMv7)) {
      // If value has 9 to 23 contiguous set bits, and has the lsb set, we can
      // replace this AND with UBFX. Other contiguous bit patterns have
      // already been handled by BIC or will be handled by AND.
      if ((width != 0) && ((leading_zeros + width) == 32) &&
          (9 <= leading_zeros) && (leading_zeros <= 23)) {
        DCHECK_EQ(0u, base::bits::CountTrailingZeros32(value));
        EmitUbfx(this, node, bitwise_and.left(), 0, width);
        return;
      }

      width = 32 - width;
      leading_zeros = base::bits::CountLeadingZeros32(~value);
      uint32_t lsb = base::bits::CountTrailingZeros32(~value);
      if ((leading_zeros + width + lsb) == 32) {
        // This AND can be replaced with BFC.
        Emit(kArmBfc, g.DefineSameAsFirst(node),
             g.UseRegister(bitwise_and.left()), g.TempImmediate(lsb),
             g.TempImmediate(width));
        return;
      }
    }
  }
  VisitBinop(this, node, kArmAnd, kArmAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
    ArmOperandGeneratorT<Adapter> g(this);
    Int32BinopMatcher m(node);
    if (m.left().IsWord32Xor() && CanCover(node, m.left().node())) {
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().Is(-1)) {
        EmitBic(this, node, m.right().node(), mleft.left().node());
        return;
      }
    }
    if (m.right().IsWord32Xor() && CanCover(node, m.right().node())) {
      Int32BinopMatcher mright(m.right().node());
      if (mright.right().Is(-1)) {
        EmitBic(this, node, m.left().node(), mright.left().node());
        return;
      }
    }
    if (m.right().HasResolvedValue()) {
      uint32_t const value = m.right().ResolvedValue();
      uint32_t width = base::bits::CountPopulation(value);
      uint32_t leading_zeros = base::bits::CountLeadingZeros32(value);

      // Try to merge SHR operations on the left hand input into this AND.
      if (m.left().IsWord32Shr()) {
        Int32BinopMatcher mshr(m.left().node());
        if (mshr.right().HasResolvedValue()) {
          uint32_t const shift = mshr.right().ResolvedValue();

          if (((shift == 8) || (shift == 16) || (shift == 24)) &&
              (value == 0xFF)) {
            // Merge SHR into AND by emitting a UXTB instruction with a
            // bytewise rotation.
            Emit(kArmUxtb, g.DefineAsRegister(m.node()),
                 g.UseRegister(mshr.left().node()),
                 g.TempImmediate(mshr.right().ResolvedValue()));
            return;
          } else if (((shift == 8) || (shift == 16)) && (value == 0xFFFF)) {
            // Merge SHR into AND by emitting a UXTH instruction with a
            // bytewise rotation.
            Emit(kArmUxth, g.DefineAsRegister(m.node()),
                 g.UseRegister(mshr.left().node()),
                 g.TempImmediate(mshr.right().ResolvedValue()));
            return;
          } else if (IsSupported(ARMv7) && (width != 0) &&
                     ((leading_zeros + width) == 32)) {
            // Merge Shr into And by emitting a UBFX instruction.
            DCHECK_EQ(0u, base::bits::CountTrailingZeros32(value));
            if ((1 <= shift) && (shift <= 31)) {
              // UBFX cannot extract bits past the register size, however since
              // shifting the original value would have introduced some zeros we
              // can still use UBFX with a smaller mask and the remaining bits
              // will be zeros.
              EmitUbfx(this, node, mshr.left().node(), shift,
                       std::min(width, 32 - shift));
              return;
            }
          }
        }
      } else if (value == 0xFFFF) {
        // Emit UXTH for this AND. We don't bother testing for UXTB, as it's no
        // better than AND 0xFF for this operation.
        Emit(kArmUxth, g.DefineAsRegister(m.node()),
             g.UseRegister(m.left().node()), g.TempImmediate(0));
        return;
      }
      if (g.CanBeImmediate(~value)) {
        // Emit BIC for this AND by inverting the immediate value first.
        Emit(kArmBic | AddressingModeField::encode(kMode_Operand2_I),
             g.DefineAsRegister(node), g.UseRegister(m.left().node()),
             g.TempImmediate(~value));
        return;
      }
      if (!g.CanBeImmediate(value) && IsSupported(ARMv7)) {
        // If value has 9 to 23 contiguous set bits, and has the lsb set, we can
        // replace this AND with UBFX. Other contiguous bit patterns have
        // already been handled by BIC or will be handled by AND.
        if ((width != 0) && ((leading_zeros + width) == 32) &&
            (9 <= leading_zeros) && (leading_zeros <= 23)) {
          DCHECK_EQ(0u, base::bits::CountTrailingZeros32(value));
          EmitUbfx(this, node, m.left().node(), 0, width);
          return;
        }

        width = 32 - width;
        leading_zeros = base::bits::CountLeadingZeros32(~value);
        uint32_t lsb = base::bits::CountTrailingZeros32(~value);
        if ((leading_zeros + width + lsb) == 32) {
          // This AND can be replaced with BFC.
          Emit(kArmBfc, g.DefineSameAsFirst(node),
               g.UseRegister(m.left().node()), g.TempImmediate(lsb),
               g.TempImmediate(width));
          return;
        }
      }
    }
    VisitBinop(this, node, kArmAnd, kArmAnd);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  VisitBinop(this, node, kArmOrr, kArmOrr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  ArmOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& bitwise_xor =
        this->Get(node).template Cast<WordBinopOp>();
    int32_t mask;
    if (this->MatchIntegralWord32Constant(bitwise_xor.right(), &mask) &&
        mask == -1) {
      InstructionCode opcode = kArmMvn;
      InstructionOperand value_operand;
      InstructionOperand shift_operand;
      if (TryMatchShift(this, &opcode, bitwise_xor.left(), &value_operand,
                        &shift_operand)) {
        Emit(opcode, g.DefineAsRegister(node), value_operand, shift_operand);
        return;
      }
      Emit(opcode | AddressingModeField::encode(kMode_Operand2_R),
           g.DefineAsRegister(node), g.UseRegister(bitwise_xor.left()));
      return;
    }
    VisitBinop(this, node, kArmEor, kArmEor);
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(-1)) {
      InstructionCode opcode = kArmMvn;
      InstructionOperand value_operand;
      InstructionOperand shift_operand;
      if (TryMatchShift(this, &opcode, m.left().node(), &value_operand,
                        &shift_operand)) {
        Emit(opcode, g.DefineAsRegister(node), value_operand, shift_operand);
        return;
      }
      Emit(opcode | AddressingModeField::encode(kMode_Operand2_R),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()));
      return;
    }
    VisitBinop(this, node, kArmEor, kArmEor);
  }
}

template <typename Adapter>
void Instructi
```