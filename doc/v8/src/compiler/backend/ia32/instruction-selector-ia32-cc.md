Response:
My thought process for analyzing the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The file name `instruction-selector-ia32.cc` immediately suggests its primary function: selecting machine instructions for the IA32 architecture within the V8 compiler. The "instruction selector" part is key.

2. **Scan for Key V8 Concepts:**  I look for familiar V8 terms and namespaces: `v8`, `internal`, `compiler`, `turboshaft`, `turbofan`, `Node`, `Operator`, `MachineRepresentation`, `LoadRepresentation`, `InstructionCode`, `AddressingMode`, etc. These indicate the code is deeply embedded within the V8 compilation pipeline.

3. **Analyze Includes:**  The included headers provide clues about dependencies and functionalities:
    * Standard C++ headers (`<stddef.h>`, `<stdint.h>`, `<limits>`, etc.): Basic utilities.
    * V8 base libraries (`src/base/...`):  Low-level utilities, flags, logging.
    * Code generation (`src/codegen/...`): Assembler, registers, machine types.
    * Compiler infrastructure (`src/compiler/...`):  Core compiler components, including instruction selection itself.
    * WebAssembly (`src/wasm/...`):  Indicates support for WebAssembly compilation.

4. **Examine Namespaces:** The code resides in `v8::internal::compiler`, reinforcing its role within the compiler. The anonymous namespace `namespace { ... }` suggests helper functions and structs that are internal to this compilation unit.

5. **Deconstruct Key Structures and Functions:** I focus on the major structures and functions defined:
    * `LoadStoreView`: A simple struct to extract common information from load and store operations.
    * `ScaledIndexMatch`, `BaseWithScaledIndexAndDisplacementMatch`: These structs are crucial for recognizing addressing modes involving scaled indices and displacements, which are fundamental to IA32 architecture. The comments "Copied from x64" are significant, indicating code reuse and potential similarities in addressing mode handling across architectures.
    * `MatchScaledIndex`, `TryMatchScaledIndex`, `TryMatchBaseWithScaledIndexAndDisplacementForWordBinop`, `TryMatchBaseWithScaledIndexAndDisplacement`:  These functions are the heart of addressing mode analysis. They attempt to match patterns in the intermediate representation (IR) to IA32 addressing modes. The "TryMatch" prefix suggests they might return optional values, indicating success or failure of the match.
    * `IA32OperandGeneratorT`: This template class is responsible for generating machine operands (registers, immediates, memory addresses) based on the IR nodes. The `Use...` and `Define...` methods are typical for operand generation.
    * Helper functions like `GetLoadOpcode`, `VisitRO`, `VisitRR`, `VisitRROFloat`, `VisitRRSimd`, etc.: These functions emit specific IA32 instructions based on the opcode and operands. The naming convention (`Visit` followed by operand types) is common in instruction selectors.

6. **Identify Key Tasks:** Based on the structure and function names, I can infer the main tasks:
    * **Pattern Matching:** Recognizing addressing mode patterns in the IR.
    * **Operand Generation:** Creating machine operands for instructions.
    * **Instruction Emission:** Generating the actual IA32 instructions.
    * **Handling Different Data Types:**  The code handles various `MachineRepresentation` types (integers, floats, SIMD).
    * **Supporting CPU Features:** The code checks for CPU features like AVX to use optimized instructions.
    * **WebAssembly Support:**  Specific handling for WebAssembly SIMD operations.

7. **Look for Architecture-Specific Details:** IA32-specific registers (e.g., `eax`, `edx`), addressing modes (e.g., `kMode_MRI`, `kMode_MRn`), and instruction mnemonics (e.g., `kIA32Movl`, `kIA32Add`) confirm the target architecture.

8. **Infer Relationships to JavaScript (if applicable):**  Since this is part of the V8 compiler, which compiles JavaScript, the generated machine code will ultimately execute JavaScript code. The connection isn't direct in this specific file, which focuses on a low-level compilation stage. However, operations like loading and storing values, arithmetic operations, and function calls are all related to how JavaScript code is executed.

9. **Consider Potential Programming Errors:** The complexity of addressing mode matching and operand generation suggests potential errors related to incorrect operand selection, missing addressing mode cases, or incorrect instruction emission.

10. **Synthesize a Summary:** Based on the above analysis, I formulate a concise summary of the file's purpose and key functionalities.

By following these steps, I can dissect the C++ code snippet and understand its role within the larger V8 project, even without having deep expertise in IA32 assembly or the intricacies of the V8 compiler. The key is to leverage the available information (file names, includes, function names, V8-specific terminology) to build a mental model of the code's functionality.
这是对 V8 引擎中 `v8/src/compiler/backend/ia32/instruction-selector-ia32.cc` 文件内容的第一部分分析。根据提供的信息，我们可以归纳出以下功能：

**核心功能： IA32 架构的指令选择**

这个 C++ 文件是 V8 编译器后端的一部分，专门负责为 IA32 (x86) 架构选择合适的机器指令。它将 V8 编译器生成的中间表示 (IR, 例如 Turboshaft 或 TurboFan 的图) 转换为可以在 IA32 处理器上执行的实际机器指令。

**详细功能点：**

1. **头文件引入:**  引入了大量的头文件，涵盖了：
    * **标准库:**  `stddef.h`, `stdint.h`, `<limits>`, `<optional>`, 等，提供了基本的数据类型和工具。
    * **V8 基础库:** `src/base/...`，提供了 V8 基础的工具函数、宏、标志位等。
    * **IA32 特定:** `src/codegen/ia32/...`，包含了 IA32 汇编器、寄存器定义等。
    * **编译器核心:** `src/compiler/...`，包含了编译器后端、指令、操作符、节点等核心组件的定义。
    * **WebAssembly (可选):** `src/wasm/...`，如果启用了 WebAssembly，则包含相关的支持。

2. **命名空间:** 代码位于 `v8::internal::compiler` 命名空间下，表明它是 V8 编译器内部实现的一部分。

3. **`LoadStoreView` 结构体:**  用于方便地访问 Load 和 Store 操作中的基址、索引和偏移量信息。

4. **`ScaledIndexMatch` 和 `BaseWithScaledIndexAndDisplacementMatch` 结构体:**  用于匹配带有缩放索引和位移的寻址模式。这在 IA32 架构中非常常见，例如访问数组元素 `array[i * scale + offset]`。

5. **`MatchScaledIndex` 和相关函数:**  实现对带有缩放的索引进行匹配的功能。它尝试识别形如 `index * scale` 或 `index << scale` 的模式。注释提到这段代码是从 x64 架构复制而来，并移除了 64 位常量支持，暗示了跨架构的相似性和针对 IA32 的调整。

6. **`IA32OperandGeneratorT` 模板类:**  这是一个重要的类，负责生成 IA32 指令的操作数。它继承自 `OperandGeneratorT`，并添加了 IA32 特定的功能：
    * **`UseByteRegister`:**  用于获取字节寄存器操作数。
    * **`CanBeMemoryOperand`:**  判断某个节点是否可以作为内存操作数。它会检查操作码、输入节点的类型和效果级别。
    * **`CanBeImmediate`:**  判断某个节点是否可以作为立即数。它会检查常量类型和值范围。
    * **`GetImmediateIntegerValue`:**  获取立即数的整数值。
    * **`ValueFitsIntoImmediate`:**  判断一个 64 位的值是否能放入 32 位立即数中。
    * **`GenerateMemoryOperandInputs`:**  根据基址、索引、缩放和位移生成内存操作数的输入。它处理了不同的寻址模式和常量基址的情况。
    * **`GetEffectiveAddressMemoryOperand`:**  获取有效地址的内存操作数。它尝试匹配不同的寻址模式，包括基于 RootRegister 的寻址。注释中提到了一些代码是从 x64 复制而来。
    * **`GetEffectiveIndexOperand`:**  获取有效索引操作数。
    * **`CanBeBetterLeftOperand`:**  判断一个节点是否可以作为指令的左操作数，通常是为了优化寄存器分配。

7. **`GetLoadOpcode` 函数:**  根据加载操作的表示类型 (`LoadRepresentation`) 返回对应的 IA32 加载指令操作码。

8. **`VisitRO`，`VisitRR` 等模板函数:**  这些函数是用于生成特定指令模式的辅助函数，其中 `R` 代表寄存器，`O` 代表操作数。例如 `VisitRO` 生成一个寄存器到操作数的指令。它们简化了指令发射的过程。

9. **WebAssembly 支持 (`#if V8_ENABLE_WEBASSEMBLY`):**  代码中包含针对 WebAssembly SIMD 指令的支持，例如 `VisitRRSimd`, `VisitRROSimd`, `VisitRRISimd` 等函数，以及 `GetSimdLaneConstant` 函数用于获取 SIMD 通道的常量。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含直接的 JavaScript 代码，但它是 V8 引擎编译 JavaScript 代码的关键部分。

当 V8 执行 JavaScript 代码时，会经历以下编译过程（简化）：

1. **解析 (Parsing):** 将 JavaScript 代码转换为抽象语法树 (AST)。
2. **字节码生成 (Bytecode Generation):** 将 AST 转换为 V8 的字节码。
3. **优化编译 (Optimizing Compilation):**  对于热点代码，V8 会使用 TurboFan 或 Turboshaft 等优化编译器将其编译为更高效的机器码。
4. **指令选择 (Instruction Selection):**  `instruction-selector-ia32.cc` 就属于这个阶段，它将优化编译器生成的中间表示转换为 IA32 的机器指令。

因此，`instruction-selector-ia32.cc` 的工作直接影响着 JavaScript 代码在 IA32 架构上的执行效率。它负责选择最合适的 IA32 指令来实现 JavaScript 的各种操作。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的 JavaScript 加法操作：

```javascript
function add(a, b) {
  return a + b;
}
```

在优化编译过程中，`a + b` 可能会被表示为一个加法操作的 IR 节点。`instruction-selector-ia32.cc` 的相关逻辑可能会进行如下处理：

* **假设输入:** 一个表示加法操作的 IR 节点，输入是代表变量 `a` 和 `b` 的寄存器或内存位置。
* **逻辑推理:**  指令选择器会判断操作数的类型和位置，然后选择合适的 IA32 加法指令，例如 `ADD` 指令。
* **假设输出:**  一个 `Instruction` 对象，其中包含了 `kIA32Add` 操作码，以及代表 `a` 和 `b` 的源操作数和目标操作数（通常是一个寄存器）。

**用户常见的编程错误 (间接相关):**

虽然这个文件不直接处理用户编写的 JavaScript 代码错误，但它与性能优化密切相关。用户编写的某些模式的 JavaScript 代码可能会导致编译器生成低效的 IR，进而导致指令选择器选择效率较低的 IA32 指令。

例如，频繁访问未优化的对象属性可能会导致生成大量的内存加载和存储指令，而指令选择器需要有效地处理这些操作。

**总结：**

`v8/src/compiler/backend/ia32/instruction-selector-ia32.cc` 的第一部分代码定义了针对 IA32 架构进行指令选择的基础结构和工具。它包含了用于匹配寻址模式、生成操作数以及选择和发射机器指令的关键类和函数。这部分代码是 V8 编译器将高级语言 (如 JavaScript) 转换为可在 IA32 处理器上执行的低级机器指令的核心组件。它也初步展现了对 WebAssembly SIMD 指令的支持。

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/instruction-selector-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/instruction-selector-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <optional>
#include <type_traits>
#include <vector>

#include "src/base/bits.h"
#include "src/base/flags.h"
#include "src/base/iterator.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/codegen/cpu-features.h"
#include "src/codegen/ia32/assembler-ia32.h"
#include "src/codegen/ia32/register-ia32.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/macro-assembler-base.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/backend/instruction-selector-adapter.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/backend/instruction.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/frame.h"
#include "src/compiler/globals.h"
#include "src/compiler/linkage.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/flags/flags.h"
#include "src/utils/utils.h"
#include "src/zone/zone-containers.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/simd-shuffle.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

namespace {

struct LoadStoreView {
  explicit LoadStoreView(const turboshaft::Operation& op) {
    DCHECK(op.Is<turboshaft::LoadOp>() || op.Is<turboshaft::StoreOp>());
    if (const turboshaft::LoadOp* load = op.TryCast<turboshaft::LoadOp>()) {
      base = load->base();
      index = load->index();
      offset = load->offset;
    } else {
      DCHECK(op.Is<turboshaft::StoreOp>());
      const turboshaft::StoreOp& store = op.Cast<turboshaft::StoreOp>();
      base = store.base();
      index = store.index();
      offset = store.offset;
    }
  }
  turboshaft::OpIndex base;
  turboshaft::OptionalOpIndex index;
  int32_t offset;
};

template <typename Adapter>
struct ScaledIndexMatch {
  using node_t = typename Adapter::node_t;

  node_t base;
  node_t index;
  int scale;
};

template <typename Adapter>
struct BaseWithScaledIndexAndDisplacementMatch {
  using node_t = typename Adapter::node_t;

  node_t base = {};
  node_t index = {};
  int scale = 0;
  int32_t displacement = 0;
  DisplacementMode displacement_mode = kPositiveDisplacement;
};

// Copied from x64, dropped kWord64 constant support.
bool MatchScaledIndex(InstructionSelectorT<TurboshaftAdapter>* selector,
                      turboshaft::OpIndex node, turboshaft::OpIndex* index,
                      int* scale, bool* power_of_two_plus_one) {
  DCHECK_NOT_NULL(index);
  DCHECK_NOT_NULL(scale);
  using namespace turboshaft;  // NOLINT(build/namespaces)

  auto MatchScaleConstant = [](const Operation& op, int& scale,
                               bool* plus_one) {
    const ConstantOp* constant = op.TryCast<ConstantOp>();
    if (constant == nullptr) return false;
    if (constant->kind != ConstantOp::Kind::kWord32) return false;

    uint64_t value = constant->integral();
    if (plus_one) *plus_one = false;
    if (value == 1) return (scale = 0), true;
    if (value == 2) return (scale = 1), true;
    if (value == 4) return (scale = 2), true;
    if (value == 8) return (scale = 3), true;
    if (plus_one == nullptr) return false;
    *plus_one = true;
    if (value == 3) return (scale = 1), true;
    if (value == 5) return (scale = 2), true;
    if (value == 9) return (scale = 3), true;
    return false;
  };

  const Operation& op = selector->Get(node);
  if (const WordBinopOp* binop = op.TryCast<WordBinopOp>()) {
    if (binop->kind != WordBinopOp::Kind::kMul) return false;
    if (MatchScaleConstant(selector->Get(binop->right()), *scale,
                           power_of_two_plus_one)) {
      *index = binop->left();
      return true;
    }
    if (MatchScaleConstant(selector->Get(binop->left()), *scale,
                           power_of_two_plus_one)) {
      *index = binop->right();
      return true;
    }
    return false;
  } else if (const ShiftOp* shift = op.TryCast<ShiftOp>()) {
    if (shift->kind != ShiftOp::Kind::kShiftLeft) return false;
    int32_t scale_value;
    if (selector->MatchIntegralWord32Constant(shift->right(), &scale_value)) {
      if (scale_value < 0 || scale_value > 3) return false;
      *index = shift->left();
      *scale = static_cast<int>(scale_value);
      if (power_of_two_plus_one) *power_of_two_plus_one = false;
      return true;
    }
  }
  return false;
}

std::optional<ScaledIndexMatch<TurboshaftAdapter>> TryMatchScaledIndex(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex node,
    bool allow_power_of_two_plus_one) {
  ScaledIndexMatch<TurboshaftAdapter> match;
  bool plus_one = false;
  if (MatchScaledIndex(selector, node, &match.index, &match.scale,
                       allow_power_of_two_plus_one ? &plus_one : nullptr)) {
    match.base = plus_one ? match.index : turboshaft::OpIndex{};
    return match;
  }
  return std::nullopt;
}

// Copied verbatim from x64 (just renamed).
std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>>
TryMatchBaseWithScaledIndexAndDisplacementForWordBinop(
    InstructionSelectorT<TurboshaftAdapter>* selector, turboshaft::OpIndex left,
    turboshaft::OpIndex right) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
  result.displacement_mode = kPositiveDisplacement;

  auto OwnedByAddressingOperand = [](OpIndex) {
    // TODO(nicohartmann@): Consider providing this. For now we just allow
    // everything to be covered regardless of other uses.
    return true;
  };

  // Check (S + ...)
  if (MatchScaledIndex(selector, left, &result.index, &result.scale, nullptr) &&
      OwnedByAddressingOperand(left)) {
    result.displacement_mode = kPositiveDisplacement;

    // Check (S + (... binop ...))
    if (const WordBinopOp* right_binop =
            selector->Get(right).TryCast<WordBinopOp>()) {
      // Check (S + (B - D))
      if (right_binop->kind == WordBinopOp::Kind::kSub &&
          OwnedByAddressingOperand(right)) {
        if (!selector->MatchIntegralWord32Constant(right_binop->right(),
                                                   &result.displacement)) {
          return std::nullopt;
        }
        result.base = right_binop->left();
        result.displacement_mode = kNegativeDisplacement;
        return result;
      }
      // Check (S + (... + ...))
      if (right_binop->kind == WordBinopOp::Kind::kAdd &&
          OwnedByAddressingOperand(right)) {
        if (selector->MatchIntegralWord32Constant(right_binop->right(),
                                                  &result.displacement)) {
          // (S + (B + D))
          result.base = right_binop->left();
        } else if (selector->MatchIntegralWord32Constant(
                       right_binop->left(), &result.displacement)) {
          // (S + (D + B))
          result.base = right_binop->right();
        } else {
          // Treat it as (S + B)
          result.base = right;
          result.displacement = 0;
        }
        return result;
      }
    }

    // Check (S + D)
    if (selector->MatchIntegralWord32Constant(right, &result.displacement)) {
      result.base = OpIndex{};
      return result;
    }

    // Treat it as (S + B)
    result.base = right;
    result.displacement = 0;
    return result;
  }

  // Check ((... + ...) + ...)
  if (const WordBinopOp* left_add = selector->Get(left).TryCast<WordBinopOp>();
      left_add && left_add->kind == WordBinopOp::Kind::kAdd &&
      OwnedByAddressingOperand(left)) {
    // Check ((S + ...) + ...)
    if (MatchScaledIndex(selector, left_add->left(), &result.index,
                         &result.scale, nullptr)) {
      result.displacement_mode = kPositiveDisplacement;
      // Check ((S + D) + B)
      if (selector->MatchIntegralWord32Constant(left_add->right(),
                                                &result.displacement)) {
        result.base = right;
        return result;
      }
      // Check ((S + B) + D)
      if (selector->MatchIntegralWord32Constant(right, &result.displacement)) {
        result.base = left_add->right();
        return result;
      }
      // Treat it as (B + B) and use index as right B.
      result.base = left;
      result.index = right;
      result.scale = 0;
      DCHECK_EQ(result.displacement, 0);
      return result;
    }
  }

  DCHECK_EQ(result.index, OpIndex{});
  DCHECK_EQ(result.scale, 0);
  result.displacement_mode = kPositiveDisplacement;

  // Check (B + D)
  if (selector->MatchIntegralWord32Constant(right, &result.displacement)) {
    result.base = left;
    return result;
  }

  // Treat as (B + B) and use index as left B.
  result.index = left;
  result.base = right;
  return result;
}

// Copied verbatim from x64 (just renamed).
std::optional<BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter>>
TryMatchBaseWithScaledIndexAndDisplacement(
    InstructionSelectorT<TurboshaftAdapter>* selector,
    turboshaft::OpIndex node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)

  // The BaseWithIndexAndDisplacementMatcher canonicalizes the order of
  // displacements and scale factors that are used as inputs, so instead of
  // enumerating all possible patterns by brute force, checking for node
  // clusters using the following templates in the following order suffices
  // to find all of the interesting cases (S = index * scale, B = base
  // input, D = displacement input):
  //
  // (S + (B + D))
  // (S + (B + B))
  // (S + D)
  // (S + B)
  // ((S + D) + B)
  // ((S + B) + D)
  // ((B + D) + B)
  // ((B + B) + D)
  // (B + D)
  // (B + B)
  BaseWithScaledIndexAndDisplacementMatch<TurboshaftAdapter> result;
  result.displacement_mode = kPositiveDisplacement;

  const Operation& op = selector->Get(node);
  if (const LoadOp* load = op.TryCast<LoadOp>()) {
    result.base = load->base();
    result.index = load->index().value_or_invalid();
    result.scale = load->element_size_log2;
    result.displacement = load->offset;
    if (load->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (const StoreOp* store = op.TryCast<StoreOp>()) {
    result.base = store->base();
    result.index = store->index().value_or_invalid();
    result.scale = store->element_size_log2;
    result.displacement = store->offset;
    if (store->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (op.Is<WordBinopOp>()) {
    // Nothing to do here, fall into the case below.
#ifdef V8_ENABLE_WEBASSEMBLY
  } else if (const Simd128LaneMemoryOp* lane_op =
                 op.TryCast<Simd128LaneMemoryOp>()) {
    result.base = lane_op->base();
    result.index = lane_op->index();
    result.scale = 0;
    result.displacement = 0;
    if (lane_op->kind.tagged_base) result.displacement -= kHeapObjectTag;
    return result;
  } else if (const Simd128LoadTransformOp* load_transform =
                 op.TryCast<Simd128LoadTransformOp>()) {
    result.base = load_transform->base();
    result.index = load_transform->index();
    DCHECK_EQ(load_transform->offset, 0);
    result.scale = 0;
    result.displacement = 0;
    DCHECK(!load_transform->load_kind.tagged_base);
    return result;
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    return std::nullopt;
  }

  const WordBinopOp& binop = op.Cast<WordBinopOp>();
  OpIndex left = binop.left();
  OpIndex right = binop.right();
  return TryMatchBaseWithScaledIndexAndDisplacementForWordBinop(selector, left,
                                                                right);
}

}  // namespace

// Adds IA32-specific methods for generating operands.
template <typename Adapter>
class IA32OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit IA32OperandGeneratorT(InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  InstructionOperand UseByteRegister(node_t node) {
    // TODO(titzer): encode byte register use constraints.
    return UseFixed(node, edx);
  }

  bool CanBeMemoryOperand(InstructionCode opcode, node_t node, node_t input,
                          int effect_level) {
    if (!this->IsLoadOrLoadImmutable(input)) return false;
    if (!selector()->CanCover(node, input)) return false;
    if (effect_level != selector()->GetEffectLevel(input)) {
      return false;
    }
    MachineRepresentation rep =
        this->load_view(input).loaded_rep().representation();
    switch (opcode) {
      case kIA32And:
      case kIA32Or:
      case kIA32Xor:
      case kIA32Add:
      case kIA32Sub:
      case kIA32Cmp:
      case kIA32Test:
        return rep == MachineRepresentation::kWord32 || IsAnyTagged(rep);
      case kIA32Cmp16:
      case kIA32Test16:
        return rep == MachineRepresentation::kWord16;
      case kIA32Cmp8:
      case kIA32Test8:
        return rep == MachineRepresentation::kWord8;
      default:
        break;
    }
    return false;
  }

  bool CanBeImmediate(node_t node) {
    if (this->IsExternalConstant(node)) return true;
    if (!this->is_constant(node)) return false;
    auto constant = this->constant_view(node);
    if (constant.is_int32() || constant.is_relocatable_int32() ||
        constant.is_relocatable_int64()) {
      return true;
    }
    if (constant.is_number_zero()) {
      return true;
    }
    // If we want to support HeapConstant nodes here, we must find a way
    // to check that they're not in new-space without dereferencing the
    // handle (which isn't safe to do concurrently).
    return false;
  }

  int32_t GetImmediateIntegerValue(node_t node) {
    DCHECK(CanBeImmediate(node));
    auto constant = this->constant_view(node);
    if (constant.is_int32()) return constant.int32_value();
    DCHECK(constant.is_number_zero());
    return 0;
  }

  bool ValueFitsIntoImmediate(int64_t value) const {
    // int32_t min will overflow if displacement mode is kNegativeDisplacement.
    return std::numeric_limits<int32_t>::min() < value &&
           value <= std::numeric_limits<int32_t>::max();
  }

  AddressingMode GenerateMemoryOperandInputs(
      optional_node_t index, int scale, node_t base, int32_t displacement,
      DisplacementMode displacement_mode, InstructionOperand inputs[],
      size_t* input_count,
      RegisterMode register_mode = RegisterMode::kRegister) {
    AddressingMode mode = kMode_MRI;
    if (displacement_mode == kNegativeDisplacement) {
      displacement = base::bits::WraparoundNeg32(displacement);
    }
    if (this->valid(base) && this->is_constant(base)) {
      auto constant_base = this->constant_view(base);
      if (constant_base.is_int32()) {
        displacement = base::bits::WraparoundAdd32(displacement,
                                                   constant_base.int32_value());
        base = node_t{};
      }
    }
    if (this->valid(base)) {
      inputs[(*input_count)++] = UseRegisterWithMode(base, register_mode);
      if (this->valid(index)) {
        DCHECK(scale >= 0 && scale <= 3);
        inputs[(*input_count)++] =
            UseRegisterWithMode(this->value(index), register_mode);
        if (displacement != 0) {
          inputs[(*input_count)++] = TempImmediate(displacement);
          static const AddressingMode kMRnI_modes[] = {kMode_MR1I, kMode_MR2I,
                                                       kMode_MR4I, kMode_MR8I};
          mode = kMRnI_modes[scale];
        } else {
          static const AddressingMode kMRn_modes[] = {kMode_MR1, kMode_MR2,
                                                      kMode_MR4, kMode_MR8};
          mode = kMRn_modes[scale];
        }
      } else {
        if (displacement == 0) {
          mode = kMode_MR;
        } else {
          inputs[(*input_count)++] = TempImmediate(displacement);
          mode = kMode_MRI;
        }
      }
    } else {
      DCHECK(scale >= 0 && scale <= 3);
      if (this->valid(index)) {
        inputs[(*input_count)++] =
            UseRegisterWithMode(this->value(index), register_mode);
        if (displacement != 0) {
          inputs[(*input_count)++] = TempImmediate(displacement);
          static const AddressingMode kMnI_modes[] = {kMode_MRI, kMode_M2I,
                                                      kMode_M4I, kMode_M8I};
          mode = kMnI_modes[scale];
        } else {
          static const AddressingMode kMn_modes[] = {kMode_MR, kMode_M2,
                                                     kMode_M4, kMode_M8};
          mode = kMn_modes[scale];
        }
      } else {
        inputs[(*input_count)++] = TempImmediate(displacement);
        return kMode_MI;
      }
    }
    return mode;
  }

  AddressingMode GenerateMemoryOperandInputs(
      Node* index, int scale, Node* base, Node* displacement_node,
      DisplacementMode displacement_mode, InstructionOperand inputs[],
      size_t* input_count,
      RegisterMode register_mode = RegisterMode::kRegister) {
    int32_t displacement = (displacement_node == nullptr)
                               ? 0
                               : OpParameter<int32_t>(displacement_node->op());
    return GenerateMemoryOperandInputs(index, scale, base, displacement,
                                       displacement_mode, inputs, input_count,
                                       register_mode);
  }

  AddressingMode GetEffectiveAddressMemoryOperand(
      node_t node, InstructionOperand inputs[], size_t* input_count,
      RegisterMode register_mode = RegisterMode::kRegister) {
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const Operation& op = this->Get(node);
      if (op.Is<LoadOp>() || op.Is<StoreOp>()) {
        LoadStoreView load_or_store(op);
        if (ExternalReference reference;
            this->MatchExternalConstant(load_or_store.base, &reference) &&
            !load_or_store.index.valid()) {
          if (selector()->CanAddressRelativeToRootsRegister(reference)) {
            const ptrdiff_t delta =
                load_or_store.offset +
                MacroAssemblerBase::RootRegisterOffsetForExternalReference(
                    selector()->isolate(), reference);
            if (is_int32(delta)) {
              inputs[(*input_count)++] =
                  TempImmediate(static_cast<int32_t>(delta));
              return kMode_Root;
            }
          }
        }
      }

      auto m = TryMatchBaseWithScaledIndexAndDisplacement(selector(), node);
      DCHECK(m.has_value());
      if (TurboshaftAdapter::valid(m->base) &&
          this->Get(m->base).template Is<LoadRootRegisterOp>()) {
        DCHECK(!this->valid(m->index));
        DCHECK_EQ(m->scale, 0);
        DCHECK(ValueFitsIntoImmediate(m->displacement));
        inputs[(*input_count)++] =
            UseImmediate(static_cast<int>(m->displacement));
        return kMode_Root;
      } else if (ValueFitsIntoImmediate(m->displacement)) {
        return GenerateMemoryOperandInputs(
            m->index, m->scale, m->base, m->displacement, m->displacement_mode,
            inputs, input_count, register_mode);
      } else if (!TurboshaftAdapter::valid(m->base) &&
                 m->displacement_mode == kPositiveDisplacement) {
        // The displacement cannot be an immediate, but we can use the
        // displacement as base instead and still benefit from addressing
        // modes for the scale.
        UNIMPLEMENTED();
      } else {
        // TODO(nicohartmann@): Turn this into a `DCHECK` once we have some
        // coverage.
        CHECK_EQ(m->displacement, 0);
        inputs[(*input_count)++] = UseRegisterWithMode(m->base, register_mode);
        inputs[(*input_count)++] = UseRegisterWithMode(m->index, register_mode);
        return kMode_MR1;
      }
    } else {
      {
        LoadMatcher<ExternalReferenceMatcher> m(node);
        if (m.index().HasResolvedValue() && m.object().HasResolvedValue() &&
            selector()->CanAddressRelativeToRootsRegister(
                m.object().ResolvedValue())) {
          ptrdiff_t const delta =
              m.index().ResolvedValue() +
              MacroAssemblerBase::RootRegisterOffsetForExternalReference(
                  selector()->isolate(), m.object().ResolvedValue());
          if (is_int32(delta)) {
            inputs[(*input_count)++] =
                TempImmediate(static_cast<int32_t>(delta));
            return kMode_Root;
          }
        }
      }

      BaseWithIndexAndDisplacement32Matcher m(node, AddressOption::kAllowAll);
      DCHECK(m.matches());
      if (m.base() != nullptr &&
          m.base()->opcode() == IrOpcode::kLoadRootRegister) {
        DCHECK_EQ(m.index(), nullptr);
        DCHECK_EQ(m.scale(), 0);
        inputs[(*input_count)++] = UseImmediate(m.displacement());
        return kMode_Root;
      } else if ((m.displacement() == nullptr ||
                  CanBeImmediate(m.displacement()))) {
        return GenerateMemoryOperandInputs(
            m.index(), m.scale(), m.base(), m.displacement(),
            m.displacement_mode(), inputs, input_count, register_mode);
      } else {
        inputs[(*input_count)++] =
            UseRegisterWithMode(node->InputAt(0), register_mode);
        inputs[(*input_count)++] =
            UseRegisterWithMode(node->InputAt(1), register_mode);
        return kMode_MR1;
      }
    }
  }

  InstructionOperand GetEffectiveIndexOperand(node_t index,
                                              AddressingMode* mode) {
    if (CanBeImmediate(index)) {
      *mode = kMode_MRI;
      return UseImmediate(index);
    } else {
      *mode = kMode_MR1;
      return UseUniqueRegister(index);
    }
  }

  bool CanBeBetterLeftOperand(node_t node) const {
    return !selector()->IsLive(node);
  }
};

namespace {

ArchOpcode GetLoadOpcode(LoadRepresentation load_rep) {
  ArchOpcode opcode;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kIA32Movss;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kIA32Movsd;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsSigned() ? kIA32Movsxbl : kIA32Movzxbl;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsSigned() ? kIA32Movsxwl : kIA32Movzxwl;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      opcode = kIA32Movl;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kIA32Movdqu;
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
  return opcode;
}

template <typename Adapter>
void VisitRO(InstructionSelectorT<Adapter>* selector,
             typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  typename Adapter::node_t input = selector->input_at(node, 0);
  // We have to use a byte register as input to movsxb.
  InstructionOperand input_op =
      opcode == kIA32Movsxbl ? g.UseFixed(input, eax) : g.Use(input);
  selector->Emit(opcode, g.DefineAsRegister(node), input_op);
}

template <typename Adapter>
void VisitROWithTemp(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempRegister()};
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.Use(selector->input_at(node, 0)), arraysize(temps), temps);
}

template <typename Adapter>
void VisitROWithTempSimd(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempSimd128Register()};
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseUniqueRegister(selector->input_at(node, 0)),
                 arraysize(temps), temps);
}

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector,
             typename Adapter::node_t node, InstructionCode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRROFloat(InstructionSelectorT<Adapter>* selector,
                   typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand operand0 = g.UseRegister(selector->input_at(node, 0));
  InstructionOperand operand1 = g.Use(selector->input_at(node, 1));
  if (selector->IsSupported(AVX)) {
    selector->Emit(opcode, g.DefineAsRegister(node), operand0, operand1);
  } else {
    selector->Emit(opcode, g.DefineSameAsFirst(node), operand0, operand1);
  }
}

// For float unary operations. Also allocates a temporary general register for
// used in external operands. If a temp is not required, use VisitRRSimd (since
// float and SIMD registers are the same on IA32).
template <typename Adapter>
void VisitFloatUnop(InstructionSelectorT<Adapter>* selector,
                    typename Adapter::node_t node,
                    typename Adapter::node_t input, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempRegister()};
  // No need for unique because inputs are float but temp is general.
  if (selector->IsSupported(AVX)) {
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(input),
                   arraysize(temps), temps);
  } else {
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(input),
                   arraysize(temps), temps);
  }
}

#if V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void VisitRRSimd(InstructionSelectorT<Adapter>* selector,
                 typename Adapter::node_t node, ArchOpcode avx_opcode,
                 ArchOpcode sse_opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand operand0 = g.UseRegister(selector->input_at(node, 0));
  if (selector->IsSupported(AVX)) {
    selector->Emit(avx_opcode, g.DefineAsRegister(node), operand0);
  } else {
    selector->Emit(sse_opcode, g.DefineSameAsFirst(node), operand0);
  }
}

template <typename Adapter>
void VisitRRSimd(InstructionSelectorT<Adapter>* selector,
                 typename Adapter::node_t node, ArchOpcode opcode) {
  VisitRRSimd(selector, node, opcode, opcode);
}

// TODO(v8:9198): Like VisitRROFloat, but for SIMD. SSE requires operand1 to be
// a register as we don't have memory alignment yet. For AVX, memory operands
// are fine, but can have performance issues if not aligned to 16/32 bytes
// (based on load size), see SDM Vol 1, chapter 14.9
template <typename Adapter>
void VisitRROSimd(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, ArchOpcode avx_opcode,
                  ArchOpcode sse_opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand operand0 = g.UseRegister(selector->input_at(node, 0));
  if (selector->IsSupported(AVX)) {
    selector->Emit(avx_opcode, g.DefineAsRegister(node), operand0,
                   g.UseRegister(selector->input_at(node, 1)));
  } else {
    selector->Emit(sse_opcode, g.DefineSameAsFirst(node), operand0,
                   g.UseRegister(selector->input_at(node, 1)));
  }
}

template <typename Adapter>
void VisitRRRSimd(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand dst = selector->IsSupported(AVX)
                               ? g.DefineAsRegister(node)
                               : g.DefineSameAsFirst(node);
  InstructionOperand operand0 = g.UseRegister(selector->input_at(node, 0));
  InstructionOperand operand1 = g.UseRegister(selector->input_at(node, 1));
  selector->Emit(opcode, dst, operand0, operand1);
}

int32_t GetSimdLaneConstant(InstructionSelectorT<TurboshaftAdapter>* selector,
                            turboshaft::OpIndex node) {
  const turboshaft::Simd128ExtractLaneOp& op =
      selector->Get(node).template Cast<turboshaft::Simd128ExtractLaneOp>();
  return op.lane;
}

int32_t GetSimdLaneConstant(InstructionSelectorT<TurbofanAdapter>* selector,
                            Node* node) {
  return OpParameter<int32_t>(node->op());
}

template <typename Adapter>
void VisitRRISimd(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand operand0 = g.UseRegister(selector->input_at(node, 0));
  InstructionOperand operand1 =
      g.UseImmediate(GetSimdLaneConstant(selector, node));
  // 8x16 uses movsx_b on dest to extract a byte, which only works
  // if dest is a byte register.
  InstructionOperand dest = opcode == kIA32I8x16ExtractLaneS
                                ? g.DefineAsFixed(node, eax)
                                : g.DefineAsRegister(node);
  selector->Emit(opcode, dest, operand0, operand1);
}

template <typename Adapter>
void VisitRRISimd(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, ArchOpcode avx_opcode,
                  ArchOpcode sse_opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand operand0 = g.UseRegister(selector->input_at(node, 0));
  InstructionOperand operand1 =
      g.UseImmediate(GetSimdLaneConstant(selector, node));
  if (selector->IsSupported(AVX)) {
    selector->Emit(avx_opcode, g.DefineAsRegister(node), operand0, operand1);
  } else {
    selector->Emit(sse_opcode, g.DefineSameAsFirst(node), operand0, operand1);
  }
}

template <typename Adapter>
void VisitRROSimdShift(InstructionSelectorT<Adapter>* selector,
                       typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  if (g.CanBeImmediate(selector->input_at(node, 1))) {
    selector->Emit(opcode, g.DefineSameAsFirst(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseImmediate(selector->input_at(node, 1)));
  } else {
    InstructionOperand operand0 =
        g.UseUniqueRegister(selector->input_at(node, 0));
    InstructionOperand operand1 =
        g.UseUniqueRegister(selector->input_at(node, 1));
    InstructionOperand temps[] = {g.TempSimd128Register(), g.TempRegister()};
    selector->Emit(opcode, g.DefineSameAsFirst(node), operand0, operand1,
                   arraysize(temps), temps);
  }
}

template <typename Adapter>
void VisitRRRR(InstructionSelectorT<Adapter>* selector,
               typename Adapter::node_t node, InstructionCode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)),
                 g.UseRegister(selector->input_at(node, 2)));
}

template <typename Adapter>
void VisitI8x16Shift(InstructionSelectorT<Adapter>* selector,
                     typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand output = CpuFeatures::IsSupported(AVX)
                                  ? g.UseRegister(node)
                                  : g.DefineSameAsFirst(node);

  if (g.CanBeImmediate(selector->inpu
"""


```