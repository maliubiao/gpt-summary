Response: My thinking process to summarize the C++ code goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided C++ code and its relation to JavaScript. It also mentions this is part 1 of 3, implying there will be more related code to consider.

2. **Identify Key Information:**  I first scan the code for obvious markers and structural elements. This includes:
    * **Copyright and License:** Standard boilerplate, indicating the code's origin and usage terms.
    * **Include Headers:**  A long list of `#include` directives. These are crucial for understanding what functionalities this file relies on. I'll pay attention to those with "ia32", "compiler", and potentially "javascript" or "v8" in their names.
    * **Namespaces:**  The code is within `v8::internal::compiler`. This immediately tells me it's part of the V8 JavaScript engine's compilation pipeline.
    * **Helper Structures/Templates:**  Structures like `LoadStoreView`, `ScaledIndexMatch`, and `BaseWithScaledIndexAndDisplacementMatch`, along with the template function `MatchScaledIndex`, suggest the code is dealing with memory access patterns and address calculations specific to the IA-32 architecture.
    * **`IA32OperandGeneratorT` Class:** This class, inheriting from `OperandGeneratorT`, is a strong indicator that this file is responsible for generating machine code operands for IA-32 instructions. The methods like `UseByteRegister`, `CanBeMemoryOperand`, `GenerateMemoryOperandInputs`, and `GetEffectiveAddressMemoryOperand` are key functions in this process.
    * **`InstructionSelectorT` Class and `Visit...` Methods:**  The template class `InstructionSelectorT` and its many `Visit...` methods (e.g., `VisitStackSlot`, `VisitLoad`, `VisitStore`, `VisitWord32And`, etc.) are the heart of the instruction selection process. Each `Visit` method likely corresponds to a specific high-level operation and handles how it should be translated into IA-32 instructions.
    * **`GetLoadOpcode`, `GetStoreOpcode`:** Functions to determine the appropriate IA-32 opcode based on the data type (MachineRepresentation).
    * **WebAssembly (`V8_ENABLE_WEBASSEMBLY`):**  The presence of `#if V8_ENABLE_WEBASSEMBLY` and related code (e.g., `VisitLoadLane`, `VisitLoadTransform`, `VisitStoreLane`) indicates this file also handles instruction selection for WebAssembly code on the IA-32 architecture.

3. **Infer Functionality:** Based on the identified elements, I start to deduce the file's purpose:
    * **Instruction Selection for IA-32:** The file takes higher-level operations (likely from an intermediate representation of the JavaScript or WebAssembly code) and selects the corresponding IA-32 machine instructions to perform those operations.
    * **Operand Generation:** It handles the creation of operands for these instructions, including registers, immediate values, and memory addresses, considering the specific addressing modes available on IA-32.
    * **Memory Access Handling:**  The helper structures and functions for matching scaled indices and base-index-displacement patterns show a focus on efficiently representing and generating memory access instructions.
    * **Data Type Awareness:**  The `MachineRepresentation` enum and the `GetLoadOpcode`/`GetStoreOpcode` functions highlight that the instruction selection process is aware of the data types being manipulated.
    * **Integration with V8 Compiler:** The namespace and class names clearly indicate its role within the V8 compiler's backend.
    * **WebAssembly Support:**  The conditional compilation for WebAssembly indicates it also plays a role in compiling WebAssembly code to IA-32.

4. **Relate to JavaScript (Conceptual):**  While the code itself is C++, I need to explain its connection to JavaScript. This involves understanding the compilation pipeline:
    * **JavaScript to Intermediate Representation:**  The V8 engine first parses JavaScript code and converts it into an intermediate representation (IR), which is more abstract and machine-independent.
    * **Instruction Selection:** This C++ file is part of the backend that takes this IR and translates it into actual machine code for a specific architecture (IA-32 in this case).
    * **Example (Conceptual):**  I need a simple JavaScript example and how it *might* be translated. Something like `a + b` would involve loading the values of `a` and `b` from memory (or registers), performing an addition, and storing the result. This file would be responsible for selecting the `ADD` instruction and determining the operands.

5. **Structure the Summary:** I organize my findings into a clear and concise summary, addressing the key aspects:
    * **Overall Function:** Start with a high-level description of the file's purpose.
    * **Key Responsibilities:** Break down the main tasks performed by the code.
    * **Relation to JavaScript:** Explain the role of this file in the JavaScript compilation process and provide a conceptual example.
    * **WebAssembly:** Briefly mention its support for WebAssembly.
    * **Part 1 of 3:** Acknowledge this information.

6. **Refine and Review:** I reread my summary to ensure accuracy, clarity, and completeness, checking that it addresses all parts of the request. I also make sure the JavaScript example is simple and illustrative.

This systematic approach allows me to dissect the C++ code, even without understanding every single line, and extract the essential information needed to generate a meaningful summary and connect it to the broader context of JavaScript execution.这个C++源代码文件 `instruction-selector-ia32.cc` 是 **V8 JavaScript 引擎** 中 **Turbofan 编译器** 的一部分，负责 **将中间表示（IR）指令选择和翻译成 IA-32 (x86) 架构的机器指令**。

更具体地说，它的主要功能可以归纳为：

1. **指令选择 (Instruction Selection):**
   - 它遍历 Turbofan 编译器生成的中间表示（IR）图，该图表示了 JavaScript 代码的计算逻辑。
   - 针对每个 IR 操作（例如，加载、存储、算术运算等），它选择最合适的 IA-32 机器指令序列来实现该操作。
   - 这个过程需要考虑 IA-32 架构的特性、指令集、寻址模式以及性能优化。

2. **操作数生成 (Operand Generation):**
   - 它负责生成机器指令所需的操作数。这些操作数可以是寄存器、立即数（常量）、内存地址等。
   - 它需要管理寄存器的分配和使用，以提高代码效率。
   - 它会根据 IR 指令的操作数类型和 IA-32 的寻址模式，生成合适的内存访问表达式。

3. **寻址模式匹配 (Addressing Mode Matching):**
   -  代码中包含一些复杂的模式匹配逻辑（例如 `MatchScaledIndex`，`TryMatchBaseWithScaledIndexAndDisplacement`），用于识别常见的内存访问模式，例如基于基址寄存器、索引寄存器和偏移量的寻址。
   -  这有助于生成更紧凑和高效的机器代码。

4. **特定于 IA-32 的处理:**
   -  该文件包含了许多特定于 IA-32 架构的代码，例如：
      - 使用 IA-32 特有的寄存器（如 `eax`, `ecx`, `edx`）。
      - 生成 IA-32 指令（如 `movl`, `add`, `sub`, `imul` 等）。
      - 处理 IA-32 的寻址模式（如 `kMode_MRI`, `kMode_MRnI` 等）。
      - 考虑 IA-32 的 CPU 特性（例如 AVX，SSE）。

5. **与 WebAssembly 的集成 (如果启用):**
   - 文件中包含了 `#if V8_ENABLE_WEBASSEMBLY` 相关的代码，表明它也负责处理 WebAssembly 的指令选择，将 WebAssembly 的操作映射到 IA-32 的 SIMD 指令等。

**与 JavaScript 的关系 (使用 JavaScript 举例说明):**

这个 C++ 文件直接参与了将 JavaScript 代码转化为机器代码的过程。当 V8 引擎执行 JavaScript 代码时，Turbofan 编译器会将热点代码编译成本地机器码以提高执行速度。 `instruction-selector-ia32.cc` 就是这个编译过程中的关键一环。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

let x = 10;
let y = 20;
let sum = add(x, y);
console.log(sum);
```

**编译过程中的大致映射 (简化):**

1. **JavaScript 解析和生成 AST:**  V8 首先解析 JavaScript 代码，生成抽象语法树 (AST)。
2. **生成中间表示 (IR):**  Turbofan 编译器将 AST 转换为中间表示 (IR)，例如：
   - `Load x` (从内存中加载变量 `x` 的值)
   - `Load y` (从内存中加载变量 `y` 的值)
   - `Add <value of x>, <value of y>` (执行加法操作)
   - `Store <result of addition>, sum` (将结果存储到变量 `sum`)
   - `Call console.log, <value of sum>` (调用 `console.log` 函数)
3. **指令选择 (由 `instruction-selector-ia32.cc` 完成):**
   - 对于 `Load x`，`instruction-selector-ia32.cc` 可能会选择 IA-32 的 `movl` 指令，将内存地址 `x` 的内容加载到寄存器中。
   - 对于 `Load y`，也会选择 `movl` 指令加载 `y` 的值到另一个寄存器。
   - 对于 `Add <value of x>, <value of y>`，会选择 IA-32 的 `add` 指令，将两个寄存器中的值相加。
   - 对于 `Store <result of addition>, sum`，会选择 `movl` 指令将寄存器中的结果存储到内存地址 `sum`。
   - 对于 `Call console.log, <value of sum>`，会生成一系列指令来设置函数调用的参数，并将控制权转移到 `console.log` 函数的代码。

**C++ 代码中的体现:**

- `VisitLoad()` 函数会处理 IR 中的加载操作，并根据加载的数据类型选择合适的 IA-32 `mov` 指令（例如 `kIA32Movl` for 32-bit values）。
- `VisitBinop()` 函数会处理二元运算（如加法），并选择相应的 IA-32 算术指令（例如 `kIA32Add`）。
- `IA32OperandGeneratorT` 类中的方法（如 `UseRegister()`, `UseImmediate()`, `GetEffectiveAddressMemoryOperand()`）会生成 `movl` 和 `add` 指令所需的操作数。

**总结:**

`instruction-selector-ia32.cc` 是 V8 引擎中将高级的 JavaScript 代码转化为可以在 IA-32 架构上执行的低级机器代码的关键组件。它负责选择正确的 IA-32 指令并生成相应的操作数，是连接 JavaScript 逻辑和底层硬件的桥梁。它是编译器后端架构中非常重要的一部分。

由于这是第 1 部分，后续的部分可能会涉及更具体的指令选择规则、优化策略以及与其他编译阶段的交互。

Prompt: 
```
这是目录为v8/src/compiler/backend/ia32/instruction-selector-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

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

  if (g.CanBeImmediate(selector->input_at(node, 1))) {
    if (opcode == kIA32I8x16ShrS) {
      selector->Emit(opcode, output, g.UseRegister(selector->input_at(node, 0)),
                     g.UseImmediate(selector->input_at(node, 1)));
    } else {
      InstructionOperand temps[] = {g.TempRegister()};
      selector->Emit(opcode, output, g.UseRegister(selector->input_at(node, 0)),
                     g.UseImmediate(selector->input_at(node, 1)),
                     arraysize(temps), temps);
    }
  } else {
    InstructionOperand operand0 =
        g.UseUniqueRegister(selector->input_at(node, 0));
    InstructionOperand operand1 =
        g.UseUniqueRegister(selector->input_at(node, 1));
    InstructionOperand temps[] = {g.TempRegister(), g.TempSimd128Register()};
    selector->Emit(opcode, output, operand0, operand1, arraysize(temps), temps);
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

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
  IA32OperandGeneratorT<Adapter> g(this);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), edx));
}

#if V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoadLane(node_t node) {
  InstructionCode opcode;
  int lane;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& load =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    lane = load.lane;
    switch (load.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kIA32Pinsrb;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kIA32Pinsrw;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kIA32Pinsrd;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        // pinsrq not available on IA32.
        if (lane == 0) {
          opcode = kIA32Movlps;
        } else {
          DCHECK_EQ(1, lane);
          opcode = kIA32Movhps;
        }
        break;
    }
    // IA32 supports unaligned loads.
    DCHECK(!load.kind.maybe_unaligned);
    // Trap handler is not supported on IA32.
    DCHECK(!load.kind.with_trap_handler);
  } else {
    // Turbofan.
    LoadLaneParameters params = LoadLaneParametersOf(node->op());
    lane = params.laneidx;
    if (params.rep == MachineType::Int8()) {
      opcode = kIA32Pinsrb;
    } else if (params.rep == MachineType::Int16()) {
      opcode = kIA32Pinsrw;
    } else if (params.rep == MachineType::Int32()) {
      opcode = kIA32Pinsrd;
    } else if (params.rep == MachineType::Int64()) {
      // pinsrq not available on IA32.
      if (params.laneidx == 0) {
        opcode = kIA32Movlps;
      } else {
        DCHECK_EQ(1, params.laneidx);
        opcode = kIA32Movhps;
      }
    } else {
      UNREACHABLE();
    }
    // IA32 supports unaligned loads.
    DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);
    // Trap handler is not supported on IA32.
    DCHECK_NE(params.kind, MemoryAccessKind::kProtectedByTrapHandler);
  }

  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand outputs[] = {IsSupported(AVX) ? g.DefineAsRegister(node)
                                                   : g.DefineSameAsFirst(node)};
  // Input 0 is value node, 1 is lane idx, and GetEffectiveAddressMemoryOperand
  // uses up to 3 inputs. This ordering is consistent with other operations that
  // use the same opcode.
  InstructionOperand inputs[5];
  size_t input_count = 0;

  inputs[input_count++] = g.UseRegister(this->input_at(node, 2));
  inputs[input_count++] = g.UseImmediate(lane);

  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(mode);

  DCHECK_GE(5, input_count);

  Emit(opcode, 1, outputs, input_count, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LoadTransformOp& op =
      this->Get(node).Cast<Simd128LoadTransformOp>();
  ArchOpcode opcode;
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8x8S:
      opcode = kIA32S128Load8x8S;
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kIA32S128Load8x8U;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kIA32S128Load16x4S;
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kIA32S128Load16x4U;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kIA32S128Load32x2S;
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kIA32S128Load32x2U;
      break;
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kIA32S128Load8Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kIA32S128Load16Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kIA32S128Load32Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kIA32S128Load64Splat;
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kIA32Movss;
      break;
    case Simd128LoadTransformOp::TransformKind::k64Zero:
      opcode = kIA32Movsd;
      break;
  }

  // IA32 supports unaligned loads
  DCHECK(!op.load_kind.maybe_unaligned);
  // Trap handler is not supported on IA32.
  DCHECK(!op.load_kind.with_trap_handler);

  VisitLoad(node, node, opcode);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());
  InstructionCode opcode;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kIA32S128Load8Splat;
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kIA32S128Load16Splat;
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kIA32S128Load32Splat;
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kIA32S128Load64Splat;
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kIA32S128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kIA32S128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kIA32S128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kIA32S128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kIA32S128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kIA32S128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kIA32Movss;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kIA32Movsd;
      break;
    default:
      UNREACHABLE();
  }

  // IA32 supports unaligned loads.
  DCHECK_NE(params.kind, MemoryAccessKind::kUnaligned);
  // Trap handler is not supported on IA32.
  DCHECK_NE(params.kind, MemoryAccessKind::kProtectedByTrapHandler);

  VisitLoad(node, node, opcode);
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node, node_t value,
                                              InstructionCode opcode) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(node);
  InstructionOperand inputs[3];
  size_t input_count = 0;
  AddressingMode mode =
      g.GetEffectiveAddressMemoryOperand(value, inputs, &input_count);
  InstructionCode code = opcode | AddressingModeField::encode(mode);
  Emit(code, 1, outputs, input_count, inputs);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  LoadRepresentation load_rep = this->load_view(node).loaded_rep();
  DCHECK(!load_rep.IsMapWord());
  VisitLoad(node, node, GetLoadOpcode(load_rep));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // Trap handler is not supported on IA32.
  UNREACHABLE();
}

namespace {

ArchOpcode GetStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kFloat32:
      return kIA32Movss;
    case MachineRepresentation::kFloat64:
      return kIA32Movsd;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return kIA32Movb;
    case MachineRepresentation::kWord16:
      return kIA32Movw;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      return kIA32Movl;
    case MachineRepresentation::kSimd128:
      return kIA32Movdqu;
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

ArchOpcode GetSeqCstStoreOpcode(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kWord8:
      return kAtomicExchangeInt8;
    case MachineRepresentation::kWord16:
      return kAtomicExchangeInt16;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord32:
      return kAtomicExchangeWord32;
    default:
      UNREACHABLE();
  }
}

template <typename Adapter>
void VisitAtomicExchange(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node, ArchOpcode opcode,
                         MachineRepresentation rep) {
  using node_t = typename Adapter::node_t;
  IA32OperandGeneratorT<Adapter> g(selector);
  node_t base = selector->input_at(node, 0);
  node_t index = selector->input_at(node, 1);
  node_t value = selector->input_at(node, 2);

  AddressingMode addressing_mode;
  InstructionOperand value_operand = (rep == MachineRepresentation::kWord8)
                                         ? g.UseFixed(value, edx)
                                         : g.UseUniqueRegister(value);
  InstructionOperand inputs[] = {
      value_operand, g.UseUniqueRegister(base),
      g.GetEffectiveIndexOperand(index, &addressing_mode)};
  InstructionOperand outputs[] = {
      (rep == MachineRepresentation::kWord8)
          // Using DefineSameAsFirst requires the register to be unallocated.
          ? g.DefineAsFixed(node, edx)
          : g.DefineSameAsFirst(node)};
  InstructionCode code = opcode | AddressingModeField::encode(addressing_mode);
  selector->Emit(code, 1, outputs, arraysize(inputs), inputs);
}

template <typename Adapter>
void VisitStoreCommon(InstructionSelectorT<Adapter>* selector,
                      const typename Adapter::StoreView& store) {
  using node_t = typename Adapter::node_t;
  using optional_node_t = typename Adapter::optional_node_t;
  IA32OperandGeneratorT<Adapter> g(selector);

  node_t base = store.base();
  optional_node_t index = store.index();
  node_t value = store.value();
  int32_t displacement = store.displacement();
  uint8_t element_size_log2 = store.element_size_log2();
  std::optional<AtomicMemoryOrder> atomic_order = store.memory_order();
  StoreRepresentation store_rep = store.stored_rep();

  WriteBarrierKind write_barrier_kind = store_rep.write_barrier_kind();
  MachineRepresentation rep = store_rep.representation();
  const bool is_seqcst =
      atomic_order && *atomic_order == AtomicMemoryOrder::kSeqCst;

  if (v8_flags.enable_unconditional_write_barriers && CanBeTaggedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    addressing_mode = g.GenerateMemoryOperandInputs(
        index, element_size_log2, base, displacement,
        DisplacementMode::kPositiveDisplacement, inputs, &input_count,
        IA32OperandGeneratorT<Adapter>::RegisterMode::kUniqueRegister);
    DCHECK_LT(input_count, 4);
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code = is_seqcst ? kArchAtomicStoreWithWriteBarrier
                                     : kArchStoreWithWriteBarrier;
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    InstructionOperand inputs[4];
    size_t input_count = 0;
    // To inform the register allocator that xchg clobbered its input.
    InstructionOperand outputs[1];
    size_t output_count = 0;
    ArchOpcode opcode;
    AddressingMode addressing_mode;

    if (is_seqcst) {
      // SeqCst stores emit XCHG instead of MOV, so encode the inputs as we
      // would for XCHG. XCHG can't encode the value as an immediate and has
      // fewer addressing modes available.
      if (rep == MachineRepresentation::kWord8 ||
          rep == MachineRepresentation::kBit) {
        inputs[input_count++] = g.UseFixed(value, edx);
        outputs[output_count++] = g.DefineAsFixed(store, edx);
      } else {
        inputs[input_count++] = g.UseUniqueRegister(value);
        outputs[output_count++] = g.DefineSameAsFirst(store);
      }
      addressing_mode = g.GetEffectiveAddressMemoryOperand(
          store, inputs, &input_count,
          IA32OperandGeneratorT<Adapter>::RegisterMode::kUniqueRegister);
      opcode = GetSeqCstStoreOpcode(rep);
    } else {
      // Release and non-atomic stores emit MOV.
      // https://www.cl.cam.ac.uk/~pes20/cpp/cpp0xmappings.html
      InstructionOperand val;
      if (g.CanBeImmediate(value)) {
        val = g.UseImmediate(value);
      } else if (!atomic_order && (rep == MachineRepresentation::kWord8 ||
                                   rep == MachineRepresentation::kBit)) {
        val = g.UseByteRegister(value);
      } else {
        val = g.UseUniqueRegister(value);
      }
      addressing_mode = g.GetEffectiveAddressMemoryOperand(
          store, inputs, &input_count,
          IA32OperandGeneratorT<Adapter>::RegisterMode::kUniqueRegister);
      inputs[input_count++] = val;
      opcode = GetStoreOpcode(rep);
    }
    InstructionCode code =
        opcode | AddressingModeField::encode(addressing_mode);
    selector->Emit(code, output_count, outputs, input_count, inputs);
  }
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(node_t node) {
  VisitStoreCommon(this, this->store_view(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // Trap handler is not supported on IA32.
  UNREACHABLE();
}

#if V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStoreLane(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  InstructionCode opcode = kArchNop;
  int lane;
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Simd128LaneMemoryOp& store =
        this->Get(node).template Cast<Simd128LaneMemoryOp>();
    lane = store.lane;
    switch (store.lane_kind) {
      case Simd128LaneMemoryOp::LaneKind::k8:
        opcode = kIA32Pextrb;
        break;
      case Simd128LaneMemoryOp::LaneKind::k16:
        opcode = kIA32Pextrw;
        break;
      case Simd128LaneMemoryOp::LaneKind::k32:
        opcode = kIA32S128Store32Lane;
        break;
      case Simd128LaneMemoryOp::LaneKind::k64:
        if (lane == 0) {
          opcode = kIA32Movlps;
        } else {
          DCHECK_EQ(1, lane);
          opcode = kIA32Movhps;
        }
        break;
    }
  } else {
    StoreLaneParameters params = StoreLaneParametersOf(node->op());
    lane = params.laneidx;
    if (params.rep == MachineRepresentation::kWord8) {
      opcode = kIA32Pextrb;
    } else if (params.rep == MachineRepresentation::kWord16) {
      opcode = kIA32Pextrw;
    } else if (params.rep == MachineRepresentation::kWord32) {
      opcode = kIA32S128Store32Lane;
    } else if (params.rep == MachineRepresentation::kWord64) {
      if (params.laneidx == 0) {
        opcode = kIA32Movlps;
      } else {
        DCHECK_EQ(1, params.laneidx);
        opcode = kIA32Movhps;
      }
    } else {
      UNREACHABLE();
    }
  }

  InstructionOperand inputs[4];
  size_t input_count = 0;
  AddressingMode addressing_mode =
      g.GetEffectiveAddressMemoryOperand(node, inputs, &input_count);
  opcode |= AddressingModeField::encode(addressing_mode);

  InstructionOperand value_operand = g.UseRegister(this->input_at(node, 2));
  inputs[input_count++] = value_operand;
  inputs[input_count++] = g.UseImmediate(lane);
  DCHECK_GE(4, input_count);
  Emit(opcode, 0, nullptr, input_count, inputs);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Architecture supports unaligned access, therefore VisitLoad is used instead
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  UNREACHABLE();
}

// Architecture supports unaligned access, therefore VisitStore is used instead
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  UNREACHABLE();
}

namespace {

// Shared routine for multiple binary operations.
template <typename Adapter>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                FlagsContinuationT<Adapter>* cont) {
  IA32OperandGeneratorT<Adapter> g(selector);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  InstructionOperand inputs[6];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  // TODO(turbofan): match complex addressing modes.
  if (left == right) {
    // If both inputs refer to the same operand, enforce allocating a register
    // for both of them to ensure that we don't end up generating code like
    // this:
    //
    //   mov eax, [ebp-0x10]
    //   add eax, [ebp-0x10]
    //   jo label
    InstructionOperand const input = g.UseRegister(left);
    inputs[input_count++] = input;
    inputs[input_count++] = input;
  } else if (g.CanBeImmediate(right)) {
    inputs[input_count++] = g.UseRegister(left);
    inputs[input_count++] = g.UseImmediate(right);
  } else {
    int effect_level = selector->GetEffectLevel(node, cont);
    if (selector->IsCommutative(node) && g.CanBeBetterLeftOperand(right) &&
        (!g.CanBeBetterLeftOperand(left) ||
         !g.CanBeMemoryOperand(opcode, node, right, effect_level))) {
      std::swap(left, right);
    }
    if (g.CanBeMemoryOperand(opcode, node, right, effect_level)) {
      inputs[input_count++] = g.UseRegister(left);
      AddressingMode addressing_mode =
          g.GetEffectiveAddressMemoryOperand(right, inputs, &input_count);
      opcode |= AddressingModeField::encode(addressing_mode);
    } else {
      inputs[input_count++] = g.UseRegister(left);
      inputs[input_count++] = g.Use(right);
    }
  }

  outputs[output_count++] = g.DefineSameAsFirst(node);

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop(selector, node, opcode, &cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
  VisitBinop(this, node, kIA32And);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  VisitBinop(this, node, kIA32Or);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::WordBinopOp& binop =
        this->Get(node).template Cast<turboshaft::WordBinopOp>();
    int32_t constant;
    if (this->MatchIntegralWord32Constant(binop.right(), &constant) &&
        constant == -1) {
      Emit(kIA32Not, g.DefineSameAsFirst(node), g.UseRegister(binop.left()));
      return;
    }
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(-1)) {
      Emit(kIA32Not, g.DefineSameAsFirst(node), g.UseRegister(m.left().node()));
      return;
    }
  }
  VisitBinop(this, node, kIA32Xor);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuation* cont) {
  StackCheckKind kind;
  if constexpr (Adapter::IsTurboshaft) {
    kind = this->Get(node)
               .template Cast<turboshaft::StackPointerGreaterThanOp>()
               .kind;
  } else {
    kind = StackCheckKindOf(node->op());
  }
  {  // Temporary scope to minimize indentation change churn below.
    InstructionCode opcode = kArchStackPointerGreaterThan |
                             MiscField::encode(static_cast<int>(kind));

    int effect_level = GetEffectLevel(node, cont);

    IA32OperandGeneratorT<Adapter> g(this);

    // No outputs.
    InstructionOperand* const outputs = nullptr;
    const int output_count = 0;

    // Applying an offset to this stack check requires a temp register. Offsets
    // are only applied to the first stack check. If applying an offset, we must
    // ensure the input and temp registers do not alias, thus kUniqueRegister.
    InstructionOperand temps[] = {g.TempRegister()};
    const int temp_count = (kind == StackCheckKind::kJSFunctionEntry) ? 1 : 0;
    const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                   ? OperandGenerator::kUniqueRegister
                                   : OperandGenerator::kRegister;

    node_t value = this->input_at(node, 0);
    if (g.CanBeMemoryOperand(kIA32Cmp, node, value, effect_level)) {
      DCHECK(this->IsLoadOrLoadImmutable(value));

      // GetEffectiveAddressMemoryOperand can create at most 3 inputs.
      static constexpr int kMaxInputCount = 3;

      size_t input_count = 0;
      InstructionOperand inputs[kMaxInputCount];
      AddressingMode addressing_mode = g.GetEffectiveAddressMemoryOperand(
          value, inputs, &input_count, register_mode);
      opcode |= AddressingModeField::encode(addressing_mode);
      DCHECK_LE(input_count, kMaxInputCount);

      EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                           temp_count, temps, cont);
    } else {
      InstructionOperand inputs[] = {
          g.UseRegisterWithMode(value, register_mode)};
      static constexpr int input_count = arraysize(inputs);
      EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                           temp_count, temps, cont);
    }
  }
}

// Shared routine for multiple shift operations.
template <typename Adapter>
static inline void VisitShift(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);

  if (g.CanBeImmediate(right)) {
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.UseImmediate(right));
  } else {
    selector->Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(left),
                   g.UseFixed(right, ecx));
  }
}

namespace {

template <typename Adapter>
void VisitMulHigh(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempRegister(eax)};
  selector->Emit(opcode, g.DefineAsFixed(node, edx),
                 g.UseFixed(selector->input_at(node, 0), eax),
                 g.UseUniqueRegister(selector->input_at(node, 1)),
                 arraysize(temps), temps);
}

template <typename Adapter>
void VisitDiv(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempRegister(edx)};
  selector->Emit(opcode, g.DefineAsFixed(node, eax),
                 g.UseFixed(selector->input_at(node, 0), eax),
                 g.UseUnique(selector->input_at(node, 1)), arraysize(temps),
                 temps);
}

template <typename Adapter>
void VisitMod(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, ArchOpcode opcode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand temps[] = {g.TempRegister(eax)};
  selector->Emit(opcode, g.DefineAsFixed(node, edx),
                 g.UseFixed(selector->input_at(node, 0), eax),
                 g.UseUnique(selector->input_at(node, 1)), arraysize(temps),
                 temps);
}

// {Displacement} is either Adapter::node_t or int32_t.
template <typename Adapter, typename Displacement>
void EmitLea(InstructionSelectorT<Adapter>* selector,
             typename Adapter::node_t result, typename Adapter::node_t index,
             int scale, typename Adapter::node_t base,
             Displacement displacement, DisplacementMode displacement_mode) {
  IA32OperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[4];
  size_t input_count = 0;
  AddressingMode mode =
      g.GenerateMemoryOperandInputs(index, scale, base, displacement,
                                    displacement_mode, inputs, &input_count);

  DCHECK_NE(0u, input_count);
  DCHECK_GE(arraysize(inputs), input_count);

  InstructionOperand outputs[1];
  outputs[0] = g.DefineAsRegister(result);

  InstructionCode opcode = AddressingModeField::encode(mode) | kIA32Lea;

  selector->Emit(opcode, 1, outputs, input_count, inputs);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shl(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    if (auto m = TryMatchScaledIndex(this, node, true)) {
      EmitLea(this, node, m->index, m->scale, m->base, 0,
              kPositiveDisplacement);
      return;
    }
  } else {
    Int32ScaleMatcher m(node, true);
    if (m.matches()) {
      Node* index = node->InputAt(0);
      Node* base = m.power_of_two_plus_one() ? index : nullptr;
      EmitLea(this, node, index, m.scale(), base, nullptr,
              kPositiveDisplacement);
      return;
    }
  }
  VisitShift(this, node, kIA32Shl);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shr(node_t node) {
  VisitShift(this, node, kIA32Shr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Sar(node_t node) {
  VisitShift(this, node, kIA32Sar);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairAdd(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);

  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection1)) {
    // We use UseUniqueRegister here to avoid register sharing with the temp
    // register.
    InstructionOperand inputs[] = {
        g.UseRegister(this->input_at(node, 0)),
        g.UseUniqueRegisterOrSlotOrConstant(this->input_at(node, 1)),
        g.UseRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineSameAsFirst(node),
                                    g.DefineAsRegister(projection1)};

    InstructionOperand temps[] = {g.TempRegister()};

    Emit(kIA32AddPair, 2, outputs, 4, inputs, 1, temps);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kIA32Add, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)),
         g.Use(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairSub(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);

  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection1)) {
    // We use UseUniqueRegister here to avoid register sharing with the temp
    // register.
    InstructionOperand inputs[] = {
        g.UseRegister(this->input_at(node, 0)),
        g.UseUniqueRegisterOrSlotOrConstant(this->input_at(node, 1)),
        g.UseRegister(this->input_at(node, 2)),
        g.UseUniqueRegister(this->input_at(node, 3))};

    InstructionOperand outputs[] = {g.DefineSameAsFirst(node),
                                    g.DefineAsRegister(projection1)};

    InstructionOperand temps[] = {g.TempRegister()};

    Emit(kIA32SubPair, 2, outputs, 4, inputs, 1, temps);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kIA32Sub, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)),
         g.Use(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32PairMul(node_t node) {
  IA32OperandGeneratorT<Adapter> g(this);

  node_t projection1 = FindProjection(node, 1);
  if (this->valid(projection1)) {
    // InputAt(3) explicitly shares ecx with OutputRegister(1) to save one
    // register and one mov instruction.
    InstructionOperand inputs[] = {
        g.UseUnique(this->input_at(node, 0)),
        g.UseUniqueRegisterOrSlotOrConstant(this->input_at(node, 1)),
        g.UseUniqueRegister(this->input_at(node, 2)),
        g.UseFixed(this->input_at(node, 3), ecx)};

    InstructionOperand outputs[] = {g.DefineAsFixed(node, eax),
                                    g.DefineAsFixed(projection1, ecx)};

    InstructionOperand temps[] = {g.TempRegister(edx)};

    Emit(kIA32MulPair, 2, outputs, 4, inputs, 1, temps);
  } else {
    // The high word of the result is not used, so we emit the standard 32 bit
    // instruction.
    Emit(kIA32Imul, g.DefineSameAsFirst(node),
         g.UseRegister(this->input_at(node, 0)),
         g.Use(this->input_at(node, 2)));
  }
}

template <typename Adapter>
void VisitWord32PairShift(InstructionSelectorT<Adapter>* selector,
                          InstructionCode opcode,
                          typename Adapter::node_t node) {
  using node_t = typename Adapter::node_t;
  IA32OperandGeneratorT<Adapter> g(selector);

  node_t shift = selector->input_at(node, 2);
  InstructionOperand shift_operand;
  if (g.CanBeImmediate(shift)) {
    shift_operand = g.UseImmediate(shift);
  } else {
    shift_operand = g.UseFixed(shift, ecx);
  }
  InstructionOperand inputs[] = {g.UseFixed(selector->input_at(node, 0), eax),
                                 g.UseFixed(selector->input_at(node, 1), edx),
                                 shift_operand};

  InstructionOperand outputs[2];
  InstructionOperand temps[1];
  int32_t output_count = 0;
  int32_t temp_count = 0;
  outputs[output_count++] = g.DefineAs
"""


```