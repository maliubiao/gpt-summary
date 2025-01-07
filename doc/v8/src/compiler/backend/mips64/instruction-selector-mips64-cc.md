Response:
Let's break down the thought process for analyzing this V8 source code snippet.

1. **Identify the Core Purpose:** The file name `instruction-selector-mips64.cc` immediately signals its role: selecting machine instructions for the MIPS64 architecture within the V8 compiler's backend. The `instruction-selector` part is key – it's about translating higher-level operations into concrete assembly instructions.

2. **Recognize the Architectural Focus:** The `mips64` directory confirms this is specific to the MIPS64 architecture. This means the code will contain MIPS64-specific instructions and addressing modes.

3. **Understand the Context:** The file resides within `v8/src/compiler/backend`. This places it firmly within the code generation pipeline. The preceding phases would have performed optimizations and intermediate representation building. This phase is the bridge to actual machine code.

4. **Scan for Key Components:**  Look for prominent language features and patterns:
    * **Includes:**  These reveal dependencies on other V8 components like `codegen`, `compiler`, and `turboshaft`. The presence of `turboshaft` hints at newer compiler infrastructure.
    * **Namespaces:** `v8::internal::compiler` establishes the organizational context.
    * **Templates:** The `template <typename Adapter>` pattern is pervasive. This suggests the code is designed to be flexible and work with different compiler "adapters" (likely for Turbofan and Turboshaft). This is a crucial observation.
    * **Macros/Boilerplate:** `OPERAND_GENERATOR_T_BOILERPLATE` hints at a structured way to generate instruction operands.
    * **Class Definition:** The `Mips64OperandGeneratorT` class is central. Its purpose is to create `InstructionOperand` objects, handling immediates, registers, and constants.
    * **`Visit...` Functions:** The numerous `VisitRR`, `VisitRRI`, `VisitLoad`, `VisitStore`, etc., functions are the core of the instruction selection logic. Each handles a specific type of intermediate representation node.
    * **`Emit` Function Calls:**  These are the points where actual machine instructions are emitted into the instruction stream.
    * **Addressing Modes:**  The use of `AddressingModeField::encode` and constants like `kMode_MRI` indicates handling of different ways to access memory.
    * **Load/Store Logic:**  The `VisitLoad` and `VisitStore` functions, along with the `ExtendingLoadMatcher`, are clearly about memory access.
    * **Write Barriers:**  The handling of `write_barrier_kind` in `VisitStore` points to garbage collection integration.
    * **Conditional Compilation:**  `if constexpr (Adapter::IsTurboshaft)` shows code that differs based on the active compiler.

5. **Analyze `Mips64OperandGeneratorT`:** This class is fundamental. Its methods like `UseOperand`, `UseRegister`, `UseImmediate`, and `CanBeImmediate` are used extensively in the `Visit` functions. Understanding how it generates operands is key to understanding instruction selection.

6. **Examine `Visit...` Function Patterns:** Notice the common structure:
    * Take a node from the intermediate representation.
    * Use `Mips64OperandGeneratorT` to create operands.
    * Call `selector->Emit` to generate the machine instruction.
    * Often involve matching input node types (e.g., `Int32BinopMatcher`).

7. **Focus on Specific Examples:** Dive into some of the more complex `Visit` functions like `VisitLoad` and `VisitStore`. Pay attention to how they handle different data types, addressing modes, and potential optimizations (like the extending load).

8. **Connect to Concepts:** Relate the code to compiler concepts:
    * **Instruction Selection:**  The core function of the file.
    * **Register Allocation:**  The `UseRegister` and `DefineAsRegister` methods implicitly interact with register allocation.
    * **Addressing Modes:** The `kMode_MRI`, `kMode_Root` constants are examples.
    * **Intermediate Representation (IR):** The `node_t` and the structure of `Visit` functions handling different IR node types.
    * **Code Generation:**  The overall goal.
    * **Garbage Collection:** The write barrier logic.

9. **Address Specific Questions:** Now, tackle the prompt's questions:
    * **Functionality:** Summarize the identified components and their roles.
    * **Torque:** Check for `.tq` extension. It's `.cc`, so it's C++.
    * **JavaScript Relationship:**  Think about what these instructions *do* in the context of JavaScript execution. Examples like arithmetic, memory access for object properties, and function calls are relevant.
    * **Code Logic Inference:** Choose a simple `Visit` function (like `VisitRR`) and trace the flow with hypothetical inputs.
    * **Common Programming Errors:** Think about what could go wrong at this stage of compilation – incorrect instruction selection, wrong operand types, etc.
    * **Summary (Part 1):**  Synthesize the key findings into a concise summary.

10. **Review and Refine:**  Read through the analysis, ensuring clarity, accuracy, and completeness. Correct any misinterpretations or omissions. For instance, initially, one might just see "operand generation," but recognizing the *different kinds* of operands (immediate, register, constant) and the logic within `CanBeImmediate` adds more depth. Similarly, just saying "handles loads and stores" isn't as informative as explaining how it deals with different data types and addressing modes.
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(...) PrintF(__VA_ARGS__)

// Adds Mips-specific methods for generating InstructionOperands.
template <typename Adapter>
class Mips64OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit Mips64OperandGeneratorT<Adapter>(
      InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  // ... (rest of Mips64OperandGeneratorT implementation)
};

template <typename Adapter>
static void VisitRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                    typename Adapter::node_t node) {
  // ... (implementation for RR instruction)
}

// ... (implementations for other Visit functions like VisitRRI, VisitSimdShift, etc.)

template <typename Adapter>
struct ExtendingLoadMatcher {
  // ... (implementation for ExtendingLoadMatcher)
};

template <typename Adapter>
bool TryEmitExtendingLoad(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node,
                          typename Adapter::node_t output_node) {
  // ... (implementation for TryEmitExtendingLoad)
}

template <typename Adapter>
bool TryMatchImmediate(InstructionSelectorT<Adapter>* selector,
                       InstructionCode* opcode_return,
                       typename Adapter::node_t node,
                       size_t* input_count_return, InstructionOperand* inputs) {
  // ... (implementation for TryMatchImmediate)
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode,
                       FlagsContinuationT<TurboshaftAdapter>* cont) {
  // ... (implementation for VisitBinop for Turboshaft)
}

// ... (other VisitBinop overloads)

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackSlot(node_t node) {
  // ... (implementation for VisitStackSlot)
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitAbortCSADcheck(node_t node) {
  // ... (implementation for VisitAbortCSADcheck)
}

template <typename Adapter>
void EmitLoad(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode,
              typename Adapter::node_t output = typename Adapter::node_t{}) {
  // ... (implementation for EmitLoad)
}

template <>
void EmitLoad(InstructionSelectorT<TurboshaftAdapter>* selector,
              typename TurboshaftAdapter::node_t node, InstructionCode opcode,
              typename TurboshaftAdapter::node_t output) {
  // ... (implementation for EmitLoad specialization for Turboshaft)
}

namespace {
template <typename Adapter>
InstructionOperand EmitAddBeforeS128LoadStore(
    InstructionSelectorT<Adapter>* selector, Node* node,
    InstructionCode* opcode) {
  // ... (implementation for EmitAddBeforeS128LoadStore)
}

}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  // ... (implementation for VisitStoreLane for Turbofan)
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  // ... (implementation for VisitLoadLane for Turbofan)
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  // ... (implementation for VisitLoadTransform for Turbofan)
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  // ... (implementation for VisitLoad)
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // ... (implementation for VisitProtectedLoad)
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(typename Adapter::node_t node) {
  // ... (implementation for VisitStore)
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // ... (implementation for VisitProtectedStore)
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(
    turboshaft::OpIndex node) {
  // ... (implementation for VisitWord32And for Turboshaft)
}
```

## 功能归纳 (Part 1)

`v8/src/compiler/backend/mips64/instruction-selector-mips64.cc` 的主要功能是 **为 MIPS64 架构选择合适的机器指令**。这是 V8 编译器后端代码生成过程中的一个关键步骤。

更具体地说，这个文件定义了以下关键组成部分和功能：

1. **`Mips64OperandGeneratorT` 模板类:**
   - 这是一个辅助类，专门用于为 MIPS64 指令生成操作数 (operands)。
   - 它提供了便捷的方法来判断一个节点是否可以作为立即数使用，以及如何获取立即数的值。
   - 它区分了寄存器操作数和立即数操作数，并能生成特定类型的操作数，例如用于表示零的立即数。

2. **`Visit...` 函数模板:**
   - 这些函数负责处理编译器中间表示 (IR) 中的不同类型的节点 (例如，表示加法、减法、加载、存储等操作的节点)。
   - 针对每种节点类型，`Visit...` 函数会决定使用哪条 MIPS64 指令来实现该操作。
   - 它们使用 `Mips64OperandGeneratorT` 来创建指令所需的源操作数和目标操作数。
   - 例如，`VisitRR` 处理两个寄存器作为操作数的指令，`VisitRRI` 处理两个寄存器和一个立即数作为操作数的指令。

3. **`ExtendingLoadMatcher` 结构体和 `TryEmitExtendingLoad` 函数模板:**
   - 这部分代码专门处理一种优化场景：当加载一个 64 位值并右移 32 位时，可以直接加载并符号扩展低 32 位，这在处理 SMI (Small Integer) 时很常见。
   - `ExtendingLoadMatcher` 用于识别这种模式，而 `TryEmitExtendingLoad` 则负责生成相应的优化指令。

4. **`TryMatchImmediate` 函数模板:**
   - 这是一个辅助函数，用于尝试将一个节点匹配为立即数操作数。

5. **`VisitBinop` 函数模板:**
   -  用于处理二元操作符（例如加法、减法、与、或等）。
   -  它会尝试将其中一个操作数作为立即数处理，并选择合适的指令（可能有反向操作数的指令）。

6. **`VisitStackSlot` 函数:**
   -  处理栈槽的分配和访问。

7. **`VisitAbortCSADcheck` 函数:**
   -  可能与安全检查或调试相关。

8. **`EmitLoad` 函数模板:**
   -  负责生成加载指令，可以处理不同的内存寻址模式（例如基于寄存器加偏移量，基于根寄存器）。

9. **`VisitLoad` 和 `VisitStore` 函数模板:**
   -  `VisitLoad` 处理从内存中加载数据的操作，根据加载的数据类型选择不同的 MIPS64 加载指令（例如 `lwc1` for float32, `ld` for 64-bit integers）。
   -  `VisitStore` 处理将数据存储到内存的操作，类似地根据存储的数据类型选择不同的 MIPS64 存储指令。它还包含了写屏障 (Write Barrier) 的处理逻辑，用于垃圾回收。

10. **针对 Turbofan 和 Turboshaft 编译器的适配:**
    - 代码中使用了模板和条件编译 (`if constexpr (Adapter::IsTurboshaft)`)，表明该文件需要支持 V8 的两个编译器后端：Turbofan 和 Turboshaft。
    - 有些 `Visit...` 函数有针对特定编译器的特殊实现。

**关于问题中的其他点:**

* **`.tq` 结尾:**  该文件以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。
* **与 Javascript 的功能关系:**  这个文件直接参与了将 JavaScript 代码编译成机器码的过程。例如：
    - 当执行 JavaScript 中的 `a + b` 时，编译器会生成一个表示加法操作的 IR 节点，`VisitBinop` 函数会选择合适的 MIPS64 加法指令（例如 `dadd`）。
    - 当访问 JavaScript 对象的属性时（例如 `obj.prop`），编译器会生成加载或存储操作的 IR 节点，`VisitLoad` 或 `VisitStore` 函数会生成相应的 MIPS64 加载或存储指令。

**JavaScript 举例说明:**

```javascript
function add(a, b) {
  return a + b;
}

let obj = { x: 10 };
let y = obj.x;
```

在编译上述 JavaScript 代码时，`instruction-selector-mips64.cc` 会参与以下操作：

- 对于 `a + b`，`VisitBinop` 可能会生成 `dadd` (Doubleword Add) 指令。
- 对于 `obj.x` 的加载操作，`VisitLoad` 可能会生成 `ld` 指令来从 `obj` 对象在内存中的位置加载 `x` 的值。

**代码逻辑推理 (假设输入与输出):**

假设输入一个表示 32 位整数加法的 IR 节点，其中两个输入节点都对应于已经分配了寄存器的值：

**假设输入:**

- IR 节点类型: `kInt32Add`
- 输入节点 0:  表示变量 `a`，已分配寄存器 `r1`
- 输入节点 1:  表示变量 `b`，已分配寄存器 `r2`

**预期输出:**

- 生成 MIPS64 指令: `addw rd, r1, r2`  (rd 是新分配的用于存储结果的寄存器)
- 调用 `selector->Emit(kMips64Add, g.DefineAsRegister(node), g.UseRegister(input0_node), g.UseRegister(input1_node))`

**用户常见的编程错误 (在这个编译阶段不太容易直接体现，但相关的错误可能在之前的编译阶段导致)：**

- **类型不匹配:** 如果之前的编译阶段未能正确推断类型，可能导致指令选择器选择了错误的指令，例如尝试用浮点数加法指令处理整数。
- **内存访问错误:** 如果指针计算错误，可能导致 `VisitLoad` 或 `VisitStore` 生成错误的内存访问指令，导致程序崩溃或读取/写入错误的数据。

总而言之，`v8/src/compiler/backend/mips64/instruction-selector-mips64.cc` 是 V8 编译器中至关重要的一个组成部分，它将平台无关的中间表示转换为特定的 MIPS64 机器指令，使得 JavaScript 代码能够在 MIPS64 架构的处理器上高效执行。

Prompt: 
```
这是目录为v8/src/compiler/backend/mips64/instruction-selector-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/mips64/instruction-selector-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/codegen/machine-type.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(...) PrintF(__VA_ARGS__)

// Adds Mips-specific methods for generating InstructionOperands.
template <typename Adapter>
class Mips64OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit Mips64OperandGeneratorT<Adapter>(
      InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  InstructionOperand UseOperand(typename Adapter::node_t node,
                                InstructionCode opcode) {
    if (CanBeImmediate(node, opcode)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  // Use the zero register if the node has the immediate value zero, otherwise
  // assign a register.
  InstructionOperand UseRegisterOrImmediateZero(typename Adapter::node_t node) {
    if (this->is_constant(node)) {
      auto constant = selector()->constant_view(node);
      if ((IsIntegerConstant(constant) &&
           GetIntegerConstantValue(constant) == 0) ||
          constant.is_float_zero()) {
        return UseImmediate(node);
      }
    }
    return UseRegister(node);
  }

  bool IsIntegerConstant(node_t node) {
    return selector()->is_integer_constant(node);
  }

  int64_t GetIntegerConstantValue(Node* node) {
    if (node->opcode() == IrOpcode::kInt32Constant) {
      return OpParameter<int32_t>(node->op());
    }
    DCHECK_EQ(IrOpcode::kInt64Constant, node->opcode());
    return OpParameter<int64_t>(node->op());
  }

  int64_t GetIntegerConstantValue(typename Adapter::ConstantView constant) {
    if (constant.is_int32()) {
      return constant.int32_value();
    }
    DCHECK(constant.is_int64());
    return constant.int64_value();
  }

  std::optional<int64_t> GetOptionalIntegerConstant(node_t operation) {
    if (!this->IsIntegerConstant(operation)) return {};
    return this->GetIntegerConstantValue(selector()->constant_view(operation));
  }

  bool IsFloatConstant(Node* node) {
    return (node->opcode() == IrOpcode::kFloat32Constant) ||
           (node->opcode() == IrOpcode::kFloat64Constant);
  }

  double GetFloatConstantValue(Node* node) {
    if (node->opcode() == IrOpcode::kFloat32Constant) {
      return OpParameter<float>(node->op());
    }
    DCHECK_EQ(IrOpcode::kFloat64Constant, node->opcode());
    return OpParameter<double>(node->op());
  }

  bool CanBeImmediate(node_t node, InstructionCode mode) {
    if (!this->is_constant(node)) return false;
    auto constant = this->constant_view(node);
    return IsIntegerConstant(constant) &&
           CanBeImmediate(GetIntegerConstantValue(constant), mode);
  }

  bool CanBeImmediate(int64_t value, InstructionCode opcode) {
    switch (ArchOpcodeField::decode(opcode)) {
      case kMips64Shl:
      case kMips64Sar:
      case kMips64Shr:
        return is_uint5(value);
      case kMips64Dshl:
      case kMips64Dsar:
      case kMips64Dshr:
        return is_uint6(value);
      case kMips64Add:
      case kMips64And32:
      case kMips64And:
      case kMips64Dadd:
      case kMips64Or32:
      case kMips64Or:
      case kMips64Tst:
      case kMips64Xor:
        return is_uint16(value);
      case kMips64Lb:
      case kMips64Lbu:
      case kMips64Sb:
      case kMips64Lh:
      case kMips64Lhu:
      case kMips64Sh:
      case kMips64Lw:
      case kMips64Sw:
      case kMips64Ld:
      case kMips64Sd:
      case kMips64Lwc1:
      case kMips64Swc1:
      case kMips64Ldc1:
      case kMips64Sdc1:
        return is_int32(value);
      default:
        return is_int16(value);
    }
  }

 private:
  bool ImmediateFitsAddrMode1Instruction(int32_t imm) const {
    TRACE("UNIMPLEMENTED instr_sel: %s at line %d\n", __FUNCTION__, __LINE__);
    return false;
  }
};

template <typename Adapter>
static void VisitRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                    typename Adapter::node_t node) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
static void VisitRRI(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(selector);
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm));
  }
}

template <typename Adapter>
static void VisitSimdShift(InstructionSelectorT<Adapter>* selector,
                           ArchOpcode opcode, typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(selector);
    if (g.IsIntegerConstant(node->InputAt(1))) {
      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(node->InputAt(0)),
                     g.UseImmediate(node->InputAt(1)));
    } else {
      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(node->InputAt(0)),
                     g.UseRegister(node->InputAt(1)));
    }
  }
}

template <typename Adapter>
static void VisitRRIR(InstructionSelectorT<Adapter>* selector,
                      ArchOpcode opcode, typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(selector);
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm),
                   g.UseRegister(node->InputAt(1)));
  }
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
              typename Adapter::node_t node) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
static void VisitUniqueRRR(InstructionSelectorT<Adapter>* selector,
                           ArchOpcode opcode, typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(selector);
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseUniqueRegister(node->InputAt(0)),
                   g.UseUniqueRegister(node->InputAt(1)));
  }
}

template <typename Adapter>
void VisitRRRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
               typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    UNIMPLEMENTED();
  } else {
    Mips64OperandGeneratorT<Adapter> g(selector);
    selector->Emit(
        opcode, g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(0)),
        g.UseRegister(node->InputAt(1)), g.UseRegister(node->InputAt(2)));
  }
}

template <typename Adapter>
static void VisitRRO(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseOperand(selector->input_at(node, 1), opcode));
}

template <typename Adapter>
struct ExtendingLoadMatcher {
  ExtendingLoadMatcher(typename Adapter::node_t node,
                       InstructionSelectorT<Adapter>* selector)
      : matches_(false), selector_(selector), immediate_(0) {
    Initialize(node);
  }

  bool Matches() const { return matches_; }

  typename Adapter::node_t base() const {
    DCHECK(Matches());
    return base_;
  }
  int64_t immediate() const {
    DCHECK(Matches());
    return immediate_;
  }
  ArchOpcode opcode() const {
    DCHECK(Matches());
    return opcode_;
  }

 private:
  bool matches_;
  InstructionSelectorT<Adapter>* selector_;
  typename Adapter::node_t base_{};
  int64_t immediate_;
  ArchOpcode opcode_;

  void Initialize(Node* node) {
    Int64BinopMatcher m(node);
    // When loading a 64-bit value and shifting by 32, we should
    // just load and sign-extend the interesting 4 bytes instead.
    // This happens, for example, when we're loading and untagging SMIs.
    DCHECK(m.IsWord64Sar());
    if (m.left().IsLoad() && m.right().Is(32) &&
        selector_->CanCover(m.node(), m.left().node())) {
      DCHECK_EQ(selector_->GetEffectLevel(node),
                selector_->GetEffectLevel(m.left().node()));
      MachineRepresentation rep =
          LoadRepresentationOf(m.left().node()->op()).representation();
      DCHECK_EQ(3, ElementSizeLog2Of(rep));
      if (rep != MachineRepresentation::kTaggedSigned &&
          rep != MachineRepresentation::kTaggedPointer &&
          rep != MachineRepresentation::kTagged &&
          rep != MachineRepresentation::kWord64) {
        return;
      }

      Mips64OperandGeneratorT<Adapter> g(selector_);
      Node* load = m.left().node();
      Node* offset = load->InputAt(1);
      base_ = load->InputAt(0);
      opcode_ = kMips64Lw;
      if (g.CanBeImmediate(offset, opcode_)) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
        immediate_ = g.GetIntegerConstantValue(offset) + 4;
#elif defined(V8_TARGET_BIG_ENDIAN)
        immediate_ = g.GetIntegerConstantValue(offset);
#endif
        matches_ = g.CanBeImmediate(immediate_, kMips64Lw);
      }
    }
  }

  void Initialize(turboshaft::OpIndex node) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shift = selector_->Get(node).template Cast<ShiftOp>();
    DCHECK(shift.kind == ShiftOp::Kind::kShiftRightArithmetic ||
           shift.kind == ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros);
    // When loading a 64-bit value and shifting by 32, we should
    // just load and sign-extend the interesting 4 bytes instead.
    // This happens, for example, when we're loading and untagging SMIs.
    const Operation& lhs = selector_->Get(shift.left());
    int64_t constant_rhs;

    if (lhs.Is<LoadOp>() &&
        selector_->MatchIntegralWord64Constant(shift.right(), &constant_rhs) &&
        constant_rhs == 32 && selector_->CanCover(node, shift.left())) {
      Mips64OperandGeneratorT<Adapter> g(selector_);

      const LoadOp& load = lhs.Cast<LoadOp>();
      base_ = load.base();
      opcode_ = kMips64Lw;
      if (load.index().has_value()) {
        int64_t index_constant;
        if (selector_->MatchIntegralWord64Constant(load.index().value(),
                                                   &index_constant)) {
          DCHECK_EQ(load.element_size_log2, 0);
          immediate_ = index_constant + 4;
          matches_ = g.CanBeImmediate(immediate_, kMips64Lw);
        }
      } else {
        immediate_ = load.offset + 4;
        matches_ = g.CanBeImmediate(immediate_, kMips64Lw);
      }
    }
  }
};

template <typename Adapter>
bool TryEmitExtendingLoad(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node,
                          typename Adapter::node_t output_node) {
  ExtendingLoadMatcher<Adapter> m(node, selector);
  Mips64OperandGeneratorT<Adapter> g(selector);
  if (m.Matches()) {
    InstructionOperand inputs[2];
    inputs[0] = g.UseRegister(m.base());
    InstructionCode opcode =
        m.opcode() | AddressingModeField::encode(kMode_MRI);
    DCHECK(is_int32(m.immediate()));
    inputs[1] = g.TempImmediate(static_cast<int32_t>(m.immediate()));
    InstructionOperand outputs[] = {g.DefineAsRegister(output_node)};
    selector->Emit(opcode, arraysize(outputs), outputs, arraysize(inputs),
                   inputs);
    return true;
  }
  return false;
}

template <typename Adapter>
bool TryMatchImmediate(InstructionSelectorT<Adapter>* selector,
                       InstructionCode* opcode_return,
                       typename Adapter::node_t node,
                       size_t* input_count_return, InstructionOperand* inputs) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  if (g.CanBeImmediate(node, *opcode_return)) {
    *opcode_return |= AddressingModeField::encode(kMode_MRI);
    inputs[0] = g.UseImmediate(node);
    *input_count_return = 1;
    return true;
  }
  return false;
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode,
                       FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Mips64OperandGeneratorT<TurboshaftAdapter> g(selector);
  InstructionOperand inputs[2];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  const Operation& binop = selector->Get(node);
  OpIndex left_node = binop.input(0);
  OpIndex right_node = binop.input(1);

  if (TryMatchImmediate(selector, &opcode, right_node, &input_count,
                        &inputs[1])) {
    inputs[0] = g.UseRegister(left_node);
    input_count++;
  } else if (has_reverse_opcode &&
             TryMatchImmediate(selector, &reverse_opcode, left_node,
                               &input_count, &inputs[1])) {
    inputs[0] = g.UseRegister(right_node);
    opcode = reverse_opcode;
    input_count++;
  } else {
    inputs[input_count++] = g.UseRegister(left_node);
    inputs[input_count++] = g.UseOperand(right_node, opcode);
  }

  outputs[output_count++] = g.DefineAsRegister(node);

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode) {
  FlagsContinuationT<TurboshaftAdapter> cont;
  VisitBinop(selector, node, opcode, has_reverse_opcode, reverse_opcode, &cont);
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode,
                       FlagsContinuationT<TurboshaftAdapter>* cont) {
  VisitBinop(selector, node, opcode, false, kArchNop, cont);
}

static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode) {
  VisitBinop(selector, node, opcode, false, kArchNop);
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode,
                       FlagsContinuationT<Adapter>* cont) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  Int32BinopMatcher m(node);
  InstructionOperand inputs[2];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  if (TryMatchImmediate(selector, &opcode, m.right().node(), &input_count,
                        &inputs[1])) {
    inputs[0] = g.UseRegister(m.left().node());
    input_count++;
  } else if (has_reverse_opcode &&
             TryMatchImmediate(selector, &reverse_opcode, m.left().node(),
                               &input_count, &inputs[1])) {
    inputs[0] = g.UseRegister(m.right().node());
    opcode = reverse_opcode;
    input_count++;
  } else {
    inputs[input_count++] = g.UseRegister(m.left().node());
    inputs[input_count++] = g.UseOperand(m.right().node(), opcode);
  }

  outputs[output_count++] = g.DefineAsRegister(node);

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop(selector, node, opcode, has_reverse_opcode, reverse_opcode, &cont);
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode,
                       FlagsContinuationT<Adapter>* cont) {
  VisitBinop(selector, node, opcode, false, kArchNop, cont);
}

template <typename Adapter>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode) {
  VisitBinop(selector, node, opcode, false, kArchNop);
}

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
  Mips64OperandGeneratorT<Adapter> g(this);
  Emit(kArchAbortCSADcheck, g.NoOutput(),
       g.UseFixed(this->input_at(node, 0), a0));
}

template <typename Adapter>
void EmitLoad(InstructionSelectorT<Adapter>* selector,
              typename Adapter::node_t node, InstructionCode opcode,
              typename Adapter::node_t output = typename Adapter::node_t{}) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);

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
    selector->Emit(kMips64Dadd | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(base), g.UseRegister(index));
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
  Mips64OperandGeneratorT<TurboshaftAdapter> g(selector);
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Operation& op = selector->Get(node);
  const LoadOp& load = op.Cast<LoadOp>();

  // The LoadStoreSimplificationReducer transforms all loads into
  // *(base + index).
  OpIndex base = load.base();
  OpIndex index = load.index().value();
  CHECK_EQ(load.offset, 0);
  DCHECK_EQ(load.element_size_log2, 0);

  InstructionOperand inputs[3];
  size_t input_count = 0;
  InstructionOperand output_op;

  // If output is valid, use that as the output register. This is used when we
  // merge a conversion into the load.
  output_op = g.DefineAsRegister(output.valid() ? output : node);

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
    DCHECK(selector->is_integer_constant(index));
    input_count = 1;
    inputs[0] = g.UseImmediate64(selector->integer_constant(index));
    opcode |= AddressingModeField::encode(kMode_Root);
    selector->Emit(opcode, 1, &output_op, input_count, inputs);
    return;
  }

  if (g.CanBeImmediate(index, opcode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output.valid() ? output : node),
                   g.UseRegister(base), g.UseImmediate(index));
  } else {
    InstructionOperand addr_reg = g.TempRegister();
    selector->Emit(kMips64Dadd | AddressingModeField::encode(kMode_None),
                   addr_reg, g.UseRegister(index), g.UseRegister(base));
    // Emit desired load opcode, using temp addr_reg.
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(output.valid() ? output : node), addr_reg,
                   g.TempImmediate(0));
  }
}

namespace {
template <typename Adapter>
InstructionOperand EmitAddBeforeS128LoadStore(
    InstructionSelectorT<Adapter>* selector, Node* node,
    InstructionCode* opcode) {
  Mips64OperandGeneratorT<Adapter> g(selector);
  Node* base = node->InputAt(0);
  Node* index = node->InputAt(1);
  InstructionOperand addr_reg = g.TempRegister();
  selector->Emit(kMips64Dadd | AddressingModeField::encode(kMode_None),
                 addr_reg, g.UseRegister(base), g.UseRegister(index));
  *opcode |= AddressingModeField::encode(kMode_MRI);
  return addr_reg;
}

}  // namespace

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitStoreLane(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitStoreLane(Node* node) {
  StoreLaneParameters params = StoreLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep, params.laneidx);
  InstructionCode opcode = kMips64S128StoreLane;
  opcode |= MiscField::encode(f.sz);

  Mips64OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeS128LoadStore(this, node, &opcode);
  InstructionOperand inputs[4] = {
      g.UseRegister(node->InputAt(2)),
      g.UseImmediate(f.laneidx),
      addr,
      g.TempImmediate(0),
  };
  Emit(opcode, 0, nullptr, 4, inputs);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadLane(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadLane(Node* node) {
  LoadLaneParameters params = LoadLaneParametersOf(node->op());
  LoadStoreLaneParams f(params.rep.representation(), params.laneidx);
  InstructionCode opcode = kMips64S128LoadLane;
  opcode |= MiscField::encode(f.sz);

  Mips64OperandGeneratorT<TurbofanAdapter> g(this);
  InstructionOperand addr = EmitAddBeforeS128LoadStore(this, node, &opcode);
  Emit(opcode, g.DefineSameAsFirst(node), g.UseRegister(node->InputAt(2)),
       g.UseImmediate(f.laneidx), addr, g.TempImmediate(0));
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());

  InstructionCode opcode = kArchNop;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kMips64S128LoadSplat;
      opcode |= MiscField::encode(MSASize::MSA_B);
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kMips64S128LoadSplat;
      opcode |= MiscField::encode(MSASize::MSA_H);
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kMips64S128LoadSplat;
      opcode |= MiscField::encode(MSASize::MSA_W);
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kMips64S128LoadSplat;
      opcode |= MiscField::encode(MSASize::MSA_D);
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kMips64S128Load8x8S;
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kMips64S128Load8x8U;
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kMips64S128Load16x4S;
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kMips64S128Load16x4U;
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kMips64S128Load32x2S;
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kMips64S128Load32x2U;
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kMips64S128Load32Zero;
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kMips64S128Load64Zero;
      break;
    default:
      UNIMPLEMENTED();
  }

  EmitLoad(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  auto load = this->load_view(node);
  LoadRepresentation load_rep = load.loaded_rep();

  InstructionCode opcode = kArchNop;
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      opcode = kMips64Lwc1;
      break;
    case MachineRepresentation::kFloat64:
      opcode = kMips64Ldc1;
      break;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      opcode = load_rep.IsUnsigned() ? kMips64Lbu : kMips64Lb;
      break;
    case MachineRepresentation::kWord16:
      opcode = load_rep.IsUnsigned() ? kMips64Lhu : kMips64Lh;
      break;
    case MachineRepresentation::kWord32:
      opcode = kMips64Lw;
      break;
    case MachineRepresentation::kTaggedSigned:   // Fall through.
    case MachineRepresentation::kTaggedPointer:  // Fall through.
    case MachineRepresentation::kTagged:         // Fall through.
    case MachineRepresentation::kWord64:
      opcode = kMips64Ld;
      break;
    case MachineRepresentation::kSimd128:
      opcode = kMips64MsaLd;
      break;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kSimd256:            // Fall through.
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kProtectedPointer:   // Fall through.
    case MachineRepresentation::kSandboxedPointer:   // Fall through.
    case MachineRepresentation::kCompressed:         // Fall through.
    case MachineRepresentation::kMapWord:            // Fall through.
    case MachineRepresentation::kIndirectPointer:    // Fall through.
    case MachineRepresentation::kNone:
      UNREACHABLE();
  }

  EmitLoad(this, node, opcode);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(typename Adapter::node_t node) {
  Mips64OperandGeneratorT<Adapter> g(this);
  typename Adapter::StoreView store_view = this->store_view(node);
  DCHECK_EQ(store_view.displacement(), 0);
  node_t base = store_view.base();
  node_t index = this->value(store_view.index());
  node_t value = store_view.value();

  WriteBarrierKind write_barrier_kind =
      store_view.stored_rep().write_barrier_kind();
  MachineRepresentation rep = store_view.stored_rep().representation();

  if (v8_flags.enable_unconditional_write_barriers && CanBeTaggedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  // TODO(mips): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
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
    code |= MiscField::encode(static_cast<int>(record_write_mode));
    Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;
    switch (rep) {
      case MachineRepresentation::kFloat32:
        opcode = kMips64Swc1;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kMips64Sdc1;
        break;
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        opcode = kMips64Sb;
        break;
      case MachineRepresentation::kWord16:
        opcode = kMips64Sh;
        break;
      case MachineRepresentation::kWord32:
        opcode = kMips64Sw;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:         // Fall through.
      case MachineRepresentation::kWord64:
        opcode = kMips64Sd;
        break;
      case MachineRepresentation::kSimd128:
        opcode = kMips64MsaSt;
        break;
      case MachineRepresentation::kFloat16:
        UNIMPLEMENTED();
      case MachineRepresentation::kSimd256:            // Fall through.
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:         // Fall through.
      case MachineRepresentation::kProtectedPointer:   // Fall through.
      case MachineRepresentation::kSandboxedPointer:   // Fall through.
      case MachineRepresentation::kMapWord:            // Fall through.
      case MachineRepresentation::kIndirectPointer:    // Fall through.
      case MachineRepresentation::kNone:
        UNREACHABLE();
    }

    if (this->is_load_root_register(base)) {
      // This will only work if {index} is a constant.
      Emit(opcode | AddressingModeField::encode(kMode_Root), g.NoOutput(),
           g.UseImmediate(index), g.UseRegisterOrImmediateZero(value));
      return;
    }

    if (g.CanBeImmediate(index, opcode)) {
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           g.UseRegister(base), g.UseImmediate(index),
           g.UseRegisterOrImmediateZero(value));
    } else {
      InstructionOperand addr_reg = g.TempRegister();
      Emit(kMips64Dadd | AddressingModeField::encode(kMode_None), addr_reg,
           g.UseRegister(index), g.UseRegister(base));
      // Emit desired store opcode, using temp addr_reg.
      Emit(opcode | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
           addr_reg, g.TempImmediate(0), g.UseRegisterOrImmediateZero(value));
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(
    turboshaft::OpIndex node) {
  // TODO(MIPS_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kMips64And32, true, kMips64And32)
"""


```