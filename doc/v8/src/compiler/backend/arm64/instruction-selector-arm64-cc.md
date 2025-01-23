Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

**1. Initial Understanding of the Request:**

The request asks for a functional overview of the provided C++ code snippet. Key constraints include identifying if it's Torque, its relationship to JavaScript, providing examples, handling code logic/reasoning, mentioning common programming errors, and summarizing its function within a larger context (part 1 of 11).

**2. High-Level Code Scan and Keyword Identification:**

The first step is to quickly scan the code for familiar keywords and patterns. This helps establish the general domain. I noticed:

* `#include`: Indicates C++ code. The included headers (`assembler-inl.h`, `instruction-selector-impl.h`, `node-matchers.h`, `turboshaft/*`) strongly suggest this is related to code generation or compilation within V8.
* `namespace v8`, `namespace internal`, `namespace compiler`:  Confirms it's part of the V8 compiler infrastructure.
* `class Arm64OperandGeneratorT`:  Indicates code specific to the ARM64 architecture.
* `InstructionSelectorT`: A common pattern in compiler backends, responsible for selecting machine instructions.
* `Emit`:  Suggests the process of generating machine instructions.
* `VisitRR`, `VisitRRR`, `VisitBinop`: Functions that seem to handle different instruction formats.
* `ImmediateMode`, `CanBeImmediate`:  Relates to handling immediate values in instructions.
* `TryMatch...`: Functions that attempt to recognize specific code patterns.
* `kArm64Ldrsw`, `kArm64Add32`, etc.:  Mnemonics for ARM64 instructions.
* `turboshaft`:  Indicates the presence of V8's newer compilation pipeline.
* `// Copyright 2014 the V8 project authors`: Basic information about the code.

**3. Deeper Dive into Core Components:**

After the initial scan, I focused on the main classes and functions to understand their roles:

* **`Arm64OperandGeneratorT`:**  This class is responsible for generating operands (registers, immediates) for ARM64 instructions. The various `CanBeImmediate` methods are crucial for determining if a value can be directly encoded within an instruction. The `UseOperand`, `UseRegister`, `UseImmediate` methods are used to create the actual operand objects.

* **`InstructionSelectorT`:** This template class (with the `Adapter`) is the central orchestrator. It takes an intermediate representation of the code and selects the appropriate ARM64 instructions. The `Emit` methods are the core of this process, generating the instructions.

* **`VisitRR`, `VisitRRR`, `VisitRRO`, `VisitBinop`:** These functions seem to handle different instruction patterns:
    * `RR`: Register-Register operations (one input register).
    * `RRR`: Register-Register-Register operations (two input registers).
    * `RRO`: Register-Register-Operand operations (one input register, one immediate or register).
    * `VisitBinop`: Handles binary operations, including immediate optimizations, commutativity, and handling of flags.

* **`TryMatch...` functions:** These functions are pattern matchers. They look for specific sequences of operations (like shifts, extends, loads with shifts) and try to generate more efficient ARM64 instructions. This is a key optimization technique in code generation.

**4. Identifying Key Functionalities:**

Based on the deeper dive, I started to list the core functionalities:

* **Instruction Selection:** The primary goal.
* **Operand Generation:** Creating register and immediate operands.
* **Immediate Value Handling:** Determining when values can be encoded as immediates.
* **Instruction Emission:** Generating the actual machine instructions.
* **Pattern Matching and Optimization:** Identifying common code patterns for optimization.
* **Binary Operation Handling:** Specific logic for arithmetic and logical operations, including commutativity and flags.
* **Load/Store Handling:**  Specific support for load and store instructions, including indexed addressing.
* **Shift and Extend Operations:** Optimizations related to shift and extend operations.
* **Turboshaft Support:**  Evidence of supporting V8's newer compiler.

**5. Addressing Specific Request Points:**

* **Torque:**  The code uses `.cc` extension, so it's not Torque.
* **JavaScript Relationship:**  This code is *part* of the process that makes JavaScript execution possible. It translates the internal representation of JavaScript code into machine code. The example provided demonstrates a simple JavaScript addition that would eventually be handled (in a much more complex form) by this type of code.
* **Code Logic Reasoning (Hypothetical Input/Output):**  I chose a simple binary addition as an example. The "input" is a representation of the `+` operation with two operands. The "output" is the ARM64 `ADD` instruction.
* **Common Programming Errors:**  I considered errors related to immediate values (out of range) and register allocation (clobbering), as these are relevant to instruction selection.
* **Summary (Part 1 of 11):** I emphasized the foundational role of this file in the instruction selection process for ARM64.

**6. Structuring the Response:**

Finally, I organized the information into a clear and structured format using headings and bullet points to address each part of the request. I aimed for a balance of technical detail and understandable explanations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps the `Visit` functions directly correspond to specific IR nodes.
* **Correction:** Realized they handle instruction *patterns*, potentially encompassing multiple IR nodes (e.g., a load followed by a shift).
* **Initial thought:** Focused too much on individual instructions.
* **Correction:** Stepped back to understand the overall workflow of instruction selection and how this file fits in.
* **Ensuring Clarity:**  Used clear language, avoided overly technical jargon where possible, and provided concrete examples.

By following these steps, combining code analysis with an understanding of compiler principles, and systematically addressing each part of the request, I arrived at the comprehensive response provided earlier.
好的，让我们来分析一下 `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 这个文件的功能。

**文件功能归纳:**

`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc` 文件是 V8 JavaScript 引擎中，负责将**平台无关的中间表示 (Intermediate Representation, IR)** 的代码，转换成 **ARM64 架构特定的机器指令**的关键组件。它属于编译器后端的一部分，专注于为 ARM64 架构生成高效的目标代码。

更具体地说，这个文件的主要功能可以概括为：

1. **指令选择 (Instruction Selection):**  根据输入的 IR 节点（代表操作），选择最合适的 ARM64 汇编指令来实现该操作。 这包括考虑操作的类型、操作数以及目标机器的特性。

2. **操作数生成 (Operand Generation):** 为选择的 ARM64 指令生成所需的操作数。这包括确定操作数是寄存器、立即数还是内存地址，并生成相应的表示。 `Arm64OperandGeneratorT` 类就负责这项任务。

3. **立即数处理 (Immediate Handling):**  高效地处理可以编码为指令一部分的立即数。文件中定义了 `ImmediateMode` 枚举，用于区分不同类型的立即数，并提供 `CanBeImmediate` 函数来判断一个值是否可以作为立即数使用。

4. **指令发射 (Instruction Emission):**  将选择的指令及其操作数传递给指令流，最终生成可执行的机器代码。 `selector->Emit()` 函数负责此过程。

5. **模式匹配和优化 (Pattern Matching and Optimization):**  识别特定的 IR 节点模式，并用更高效的 ARM64 指令序列来替换它们。 例如，`TryMatchExtendingLoad`、`TryMatchAnyShift` 和 `TryMatchAnyExtend` 等函数就用于进行这种模式匹配和优化。

6. **支持不同的操作类型:**  文件中包含了处理各种操作类型的代码，例如算术运算、逻辑运算、位运算、加载/存储操作、比较操作等。  `VisitRR`, `VisitRRR`, `VisitBinop` 等函数针对不同的操作数结构和指令格式进行处理。

7. **处理 Turboshaft 编译管道 (Turboshaft Support):** 文件中包含针对 V8 新的 Turboshaft 编译管道的支持 (`Adapter::IsTurboshaft`)，这意味着它可以处理 Turboshaft 生成的 IR。

**关于文件扩展名 `.tq`:**

你提到如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。  `v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`  以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 文件。 Torque 是一种 V8 使用的领域特定语言，用于生成一些底层的代码，例如内置函数的桩代码。

**与 JavaScript 的功能关系:**

`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`  直接参与了 JavaScript 代码的执行过程。 当 V8 引擎执行 JavaScript 代码时，它会经历以下关键阶段：

1. **解析 (Parsing):** 将 JavaScript 源代码转换为抽象语法树 (AST)。
2. **编译 (Compilation):** 将 AST 转换为中间表示 (IR)。 V8 有多个编译器，例如 Crankshaft 和 Turbofan，以及最新的 Turboshaft。
3. **代码生成 (Code Generation):** 将 IR 转换为特定架构的机器代码。 `instruction-selector-arm64.cc`  就负责 ARM64 架构的代码生成。
4. **执行 (Execution):** 执行生成的机器代码。

因此，`instruction-selector-arm64.cc`  是将高级的 JavaScript 代码转化为能在 ARM64 处理器上运行的低级指令的关键环节。

**JavaScript 示例:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 执行这段代码时，`instruction-selector-arm64.cc`  会参与将 `a + b` 这个操作转换为 ARM64 的加法指令，例如 `ADD`。  它会确定变量 `a` 和 `b` 的值存储在哪里（例如寄存器或内存），并生成相应的 `ADD` 指令，将这两个值相加，并将结果存储到另一个寄存器或内存位置。

**代码逻辑推理（假设输入与输出）:**

假设一个 IR 节点表示一个 32 位整数的加法操作，操作数为两个寄存器：

**假设输入 (IR 节点):**

```
Operation: kInt32Add
Input 0: Register(R1)  // 代表变量 a
Input 1: Register(R2)  // 代表变量 b
Output:  Register(R0)  // 代表结果
```

`instruction-selector-arm64.cc` 中的相关逻辑可能会选择 ARM64 的 `ADD Wd, Wn, Wm` 指令，其中 `Wd` 是目标寄存器，`Wn` 和 `Wm` 是源寄存器。

**可能的输出 (ARM64 指令):**

```assembly
ADD W0, W1, W2
```

这里，`W0` 对应输出寄存器 `R0`，`W1` 对应输入寄存器 `R1`，`W2` 对应输入寄存器 `R2`。  `instruction-selector-arm64.cc`  负责确定这些寄存器的分配并生成正确的指令。

**涉及用户常见的编程错误（示例）:**

虽然 `instruction-selector-arm64.cc`  本身不直接处理用户编写的 JavaScript 代码错误，但它在代码生成过程中需要处理一些与数值范围、类型转换等相关的问题，这些问题可能源自用户的编程错误。

例如，如果 JavaScript 代码中存在可能导致整数溢出的加法运算，指令选择器需要生成正确的指令来处理溢出（或者假设没有溢出，这取决于编译器的优化策略）。

一个更直接相关的例子是处理立即数。  如果 JavaScript 代码中使用了超出 ARM64 指令立即数编码范围的常量，指令选择器需要采取措施，例如将常量加载到寄存器中，然后再进行操作。 用户可能不会直接意识到这种底层的处理，但如果生成的代码效率不高，可能是因为编译器需要处理这些超出范围的常量。

**归纳其功能 (第 1 部分，共 11 部分):**

作为 11 个部分中的第一部分，`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`  奠定了将高级语言操作转换为具体 ARM64 机器指令的基础。 它的主要职责是 **指令选择和操作数生成**，为后续的机器码生成和优化阶段提供核心的转换逻辑。  这个文件定义了如何将抽象的计算步骤映射到 ARM64 处理器的硬件能力上。 后续的部分可能会涉及更高级的优化、寄存器分配、代码布局等。

总而言之，`v8/src/compiler/backend/arm64/instruction-selector-arm64.cc`  是 V8 引擎将 JavaScript 代码编译成高效 ARM64 机器码的关键组成部分，它连接了平台无关的中间表示和特定硬件架构的指令集。

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/instruction-selector-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/instruction-selector-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/bits.h"
#include "src/base/logging.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/machine-type.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operation-matcher.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/flags/flags.h"

namespace v8 {
namespace internal {
namespace compiler {

enum ImmediateMode {
  kArithmeticImm,  // 12 bit unsigned immediate shifted left 0 or 12 bits
  kShift32Imm,     // 0 - 31
  kShift64Imm,     // 0 - 63
  kLogical32Imm,
  kLogical64Imm,
  kLoadStoreImm8,  // signed 8 bit or 12 bit unsigned scaled by access size
  kLoadStoreImm16,
  kLoadStoreImm32,
  kLoadStoreImm64,
  kConditionalCompareImm,
  kNoImmediate
};

// Adds Arm64-specific methods for generating operands.
template <typename Adapter>
class Arm64OperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit Arm64OperandGeneratorT(InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  InstructionOperand UseOperand(node_t node, ImmediateMode mode) {
    if (CanBeImmediate(node, mode)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  bool IsImmediateZero(typename Adapter::node_t node) {
    if (this->is_constant(node)) {
      auto constant = selector()->constant_view(node);
      if ((IsIntegerConstant(constant) &&
           GetIntegerConstantValue(constant) == 0) ||
          constant.is_float_zero()) {
        return true;
      }
    }
    return false;
  }

  // Use the zero register if the node has the immediate value zero, otherwise
  // assign a register.
  InstructionOperand UseRegisterOrImmediateZero(typename Adapter::node_t node) {
    if (IsImmediateZero(node)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  // Use the zero register if the node has the immediate value zero, otherwise
  // assign a register, keeping it alive for the whole sequence of continuation
  // instructions.
  InstructionOperand UseRegisterAtEndOrImmediateZero(
      typename Adapter::node_t node) {
    if (IsImmediateZero(node)) {
      return UseImmediate(node);
    }
    return this->UseRegisterAtEnd(node);
  }

  // Use the provided node if it has the required value, or create a
  // TempImmediate otherwise.
  InstructionOperand UseImmediateOrTemp(node_t node, int32_t value) {
    if (selector()->integer_constant(node) == value) {
      return UseImmediate(node);
    }
    return TempImmediate(value);
  }

  int64_t GetIntegerConstantValue(Node* node) {
    if (node->opcode() == IrOpcode::kInt32Constant) {
      return OpParameter<int32_t>(node->op());
    }
    DCHECK_EQ(IrOpcode::kInt64Constant, node->opcode());
    return OpParameter<int64_t>(node->op());
  }

  bool IsIntegerConstant(node_t node) const {
    return selector()->is_integer_constant(node);
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

  bool CanBeImmediate(node_t node, ImmediateMode mode) {
    if (!this->is_constant(node)) return false;
    auto constant = this->constant_view(node);
    if (constant.is_compressed_heap_object()) {
      if (!COMPRESS_POINTERS_BOOL) return false;
      // For builtin code we need static roots
      if (selector()->isolate()->bootstrapper() && !V8_STATIC_ROOTS_BOOL) {
        return false;
      }
      const RootsTable& roots_table = selector()->isolate()->roots_table();
      RootIndex root_index;
      Handle<HeapObject> value = constant.heap_object_value();
      if (roots_table.IsRootHandle(value, &root_index)) {
        if (!RootsTable::IsReadOnly(root_index)) return false;
        return CanBeImmediate(MacroAssemblerBase::ReadOnlyRootPtr(
                                  root_index, selector()->isolate()),
                              mode);
      }
      return false;
    }

    return IsIntegerConstant(constant) &&
           CanBeImmediate(GetIntegerConstantValue(constant), mode);
  }

  bool CanBeImmediate(int64_t value, ImmediateMode mode) {
    unsigned ignored;
    switch (mode) {
      case kLogical32Imm:
        // TODO(dcarney): some unencodable values can be handled by
        // switching instructions.
        return Assembler::IsImmLogical(static_cast<uint32_t>(value), 32,
                                       &ignored, &ignored, &ignored);
      case kLogical64Imm:
        return Assembler::IsImmLogical(static_cast<uint64_t>(value), 64,
                                       &ignored, &ignored, &ignored);
      case kArithmeticImm:
        return Assembler::IsImmAddSub(value);
      case kLoadStoreImm8:
        return IsLoadStoreImmediate(value, 0);
      case kLoadStoreImm16:
        return IsLoadStoreImmediate(value, 1);
      case kLoadStoreImm32:
        return IsLoadStoreImmediate(value, 2);
      case kLoadStoreImm64:
        return IsLoadStoreImmediate(value, 3);
      case kNoImmediate:
        return false;
      case kConditionalCompareImm:
        return Assembler::IsImmConditionalCompare(value);
      case kShift32Imm:  // Fall through.
      case kShift64Imm:
        // Shift operations only observe the bottom 5 or 6 bits of the value.
        // All possible shifts can be encoded by discarding bits which have no
        // effect.
        return true;
    }
    return false;
  }

  bool CanBeLoadStoreShiftImmediate(node_t node, MachineRepresentation rep) {
    // TODO(arm64): Load and Store on 128 bit Q registers is not supported yet.
    DCHECK_GT(MachineRepresentation::kSimd128, rep);
    if (!selector()->is_constant(node)) return false;
    auto constant = selector()->constant_view(node);
    return IsIntegerConstant(constant) &&
           (GetIntegerConstantValue(constant) == ElementSizeLog2Of(rep));
  }

 private:
  bool IsLoadStoreImmediate(int64_t value, unsigned size) {
    return Assembler::IsImmLSScaled(value, size) ||
           Assembler::IsImmLSUnscaled(value);
  }
};

namespace {

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
             typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
             typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
              Node* node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(node->InputAt(0)),
                 g.UseRegister(node->InputAt(1)));
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
}

#if V8_ENABLE_WEBASSEMBLY
template <typename Adapter>
void VisitSimdShiftRRR(InstructionSelectorT<Adapter>* selector,
                       ArchOpcode opcode, typename Adapter::node_t node,
                       int width) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  if (selector->is_integer_constant(selector->input_at(node, 1))) {
    if (selector->integer_constant(selector->input_at(node, 1)) % width == 0) {
      selector->EmitIdentity(node);
    } else {
      selector->Emit(opcode, g.DefineAsRegister(node),
                     g.UseRegister(selector->input_at(node, 0)),
                     g.UseImmediate(selector->input_at(node, 1)));
    }
  } else {
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
  }
}

template <typename Adapter>
void VisitRRI(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(node);
    int imm = op.template Cast<Simd128ExtractLaneOp>().lane;
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)),
                   g.UseImmediate(imm));
  } else {
    Arm64OperandGeneratorT<Adapter> g(selector);
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm));
  }
}

template <typename Adapter>
void VisitRRIR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
               typename Adapter::node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ReplaceLaneOp& op =
        selector->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    Arm64OperandGeneratorT<Adapter> g(selector);
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)),
                   g.UseImmediate(op.lane), g.UseUniqueRegister(op.input(1)));
  } else {
    Arm64OperandGeneratorT<Adapter> g(selector);
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(node->InputAt(0)), g.UseImmediate(imm),
                   g.UseUniqueRegister(node->InputAt(1)));
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

template <typename Adapter>
void VisitRRO(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
              typename Adapter::node_t node, ImmediateMode operand_mode) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseOperand(selector->input_at(node, 1), operand_mode));
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
      Arm64OperandGeneratorT<Adapter> g(selector_);
      Node* load = m.left().node();
      Node* offset = load->InputAt(1);
      base_ = load->InputAt(0);
      opcode_ = kArm64Ldrsw;
      if (g.IsIntegerConstant(offset)) {
        immediate_ = g.GetIntegerConstantValue(offset) + 4;
        matches_ = g.CanBeImmediate(immediate_, kLoadStoreImm32);
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
      Arm64OperandGeneratorT<Adapter> g(selector_);
      const LoadOp& load = lhs.Cast<LoadOp>();
      base_ = load.base();
      opcode_ = kArm64Ldrsw;
      if (load.index().has_value()) {
        int64_t index_constant;
        if (selector_->MatchIntegralWord64Constant(load.index().value(),
                                                   &index_constant)) {
          DCHECK_EQ(load.element_size_log2, 0);
          immediate_ = index_constant + 4;
          matches_ = g.CanBeImmediate(immediate_, kLoadStoreImm32);
        }
      } else {
        immediate_ = load.offset + 4;
        matches_ = g.CanBeImmediate(immediate_, kLoadStoreImm32);
      }
    }
  }
};

template <typename Adapter>
bool TryMatchExtendingLoad(InstructionSelectorT<Adapter>* selector,
                           typename Adapter::node_t node) {
  ExtendingLoadMatcher<Adapter> m(node, selector);
  return m.Matches();
}

template <typename Adapter>
bool TryEmitExtendingLoad(InstructionSelectorT<Adapter>* selector,
                          typename Adapter::node_t node) {
  ExtendingLoadMatcher<Adapter> m(node, selector);
  Arm64OperandGeneratorT<Adapter> g(selector);
  if (m.Matches()) {
    InstructionOperand inputs[2];
    inputs[0] = g.UseRegister(m.base());
    InstructionCode opcode =
        m.opcode() | AddressingModeField::encode(kMode_MRI);
    DCHECK(is_int32(m.immediate()));
    inputs[1] = g.TempImmediate(static_cast<int32_t>(m.immediate()));
    InstructionOperand outputs[] = {g.DefineAsRegister(node)};
    selector->Emit(opcode, arraysize(outputs), outputs, arraysize(inputs),
                   inputs);
    return true;
  }
  return false;
}

template <typename Adapter>
bool TryMatchAnyShift(InstructionSelectorT<Adapter>* selector, Node* node,
                      Node* input_node, InstructionCode* opcode, bool try_ror,
                      MachineRepresentation rep) {
  Arm64OperandGeneratorT<Adapter> g(selector);

  if (!selector->CanCover(node, input_node)) return false;
  if (input_node->InputCount() != 2) return false;
  if (!g.IsIntegerConstant(input_node->InputAt(1))) return false;

  switch (input_node->opcode()) {
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord32Shr:
    case IrOpcode::kWord32Sar:
    case IrOpcode::kWord32Ror:
      if (rep != MachineRepresentation::kWord32) return false;
      break;
    case IrOpcode::kWord64Shl:
    case IrOpcode::kWord64Shr:
    case IrOpcode::kWord64Sar:
    case IrOpcode::kWord64Ror:
      if (rep != MachineRepresentation::kWord64) return false;
      break;
    default:
      return false;
  }

  switch (input_node->opcode()) {
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord64Shl:
      *opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
      return true;
    case IrOpcode::kWord32Shr:
    case IrOpcode::kWord64Shr:
      *opcode |= AddressingModeField::encode(kMode_Operand2_R_LSR_I);
      return true;
    case IrOpcode::kWord32Sar:
      *opcode |= AddressingModeField::encode(kMode_Operand2_R_ASR_I);
      return true;
    case IrOpcode::kWord64Sar:
      if (TryMatchExtendingLoad(selector, input_node)) return false;
      *opcode |= AddressingModeField::encode(kMode_Operand2_R_ASR_I);
      return true;
    case IrOpcode::kWord32Ror:
    case IrOpcode::kWord64Ror:
      if (try_ror) {
        *opcode |= AddressingModeField::encode(kMode_Operand2_R_ROR_I);
        return true;
      }
      return false;
    default:
      UNREACHABLE();
  }
}

bool TryMatchAnyShift(InstructionSelectorT<TurboshaftAdapter>* selector,
                      turboshaft::OpIndex node, turboshaft::OpIndex input_node,
                      InstructionCode* opcode, bool try_ror,
                      turboshaft::RegisterRepresentation rep) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  Arm64OperandGeneratorT<TurboshaftAdapter> g(selector);

  if (!selector->CanCover(node, input_node)) return false;
  if (const ShiftOp* shift = selector->Get(input_node).TryCast<ShiftOp>()) {
    // Differently to Turbofan, the representation should always match.
    DCHECK_EQ(shift->rep, rep);
    if (shift->rep != rep) return false;
    if (!g.IsIntegerConstant(shift->right())) return false;

    switch (shift->kind) {
      case ShiftOp::Kind::kShiftLeft:
        *opcode |= AddressingModeField::encode(kMode_Operand2_R_LSL_I);
        return true;
      case ShiftOp::Kind::kShiftRightLogical:
        *opcode |= AddressingModeField::encode(kMode_Operand2_R_LSR_I);
        return true;
      case ShiftOp::Kind::kShiftRightArithmetic:
      case ShiftOp::Kind::kShiftRightArithmeticShiftOutZeros:
        if (rep == WordRepresentation::Word64() &&
            TryMatchExtendingLoad(selector, input_node)) {
          return false;
        }
        *opcode |= AddressingModeField::encode(kMode_Operand2_R_ASR_I);
        return true;
      case ShiftOp::Kind::kRotateRight:
        if (try_ror) {
          *opcode |= AddressingModeField::encode(kMode_Operand2_R_ROR_I);
          return true;
        }
        return false;
      case ShiftOp::Kind::kRotateLeft:
        return false;
    }
  }
  return false;
}

bool TryMatchAnyExtend(Arm64OperandGeneratorT<TurbofanAdapter>* g,
                       InstructionSelectorT<TurbofanAdapter>* selector,
                       Node* node, Node* left_node, Node* right_node,
                       InstructionOperand* left_op,
                       InstructionOperand* right_op, InstructionCode* opcode) {
  if (!selector->CanCover(node, right_node)) return false;

  NodeMatcher nm(right_node);

  if (nm.IsWord32And()) {
    Int32BinopMatcher mright(right_node);
    if (mright.right().Is(0xFF) || mright.right().Is(0xFFFF)) {
      int32_t mask = mright.right().ResolvedValue();
      *left_op = g->UseRegister(left_node);
      *right_op = g->UseRegister(mright.left().node());
      *opcode |= AddressingModeField::encode(
          (mask == 0xFF) ? kMode_Operand2_R_UXTB : kMode_Operand2_R_UXTH);
      return true;
    }
  } else if (nm.IsWord32Sar()) {
    Int32BinopMatcher mright(right_node);
    if (selector->CanCover(mright.node(), mright.left().node()) &&
        mright.left().IsWord32Shl()) {
      Int32BinopMatcher mleft_of_right(mright.left().node());
      if ((mright.right().Is(16) && mleft_of_right.right().Is(16)) ||
          (mright.right().Is(24) && mleft_of_right.right().Is(24))) {
        int32_t shift = mright.right().ResolvedValue();
        *left_op = g->UseRegister(left_node);
        *right_op = g->UseRegister(mleft_of_right.left().node());
        *opcode |= AddressingModeField::encode(
            (shift == 24) ? kMode_Operand2_R_SXTB : kMode_Operand2_R_SXTH);
        return true;
      }
    }
  } else if (nm.IsChangeInt32ToInt64()) {
    // Use extended register form.
    *opcode |= AddressingModeField::encode(kMode_Operand2_R_SXTW);
    *left_op = g->UseRegister(left_node);
    *right_op = g->UseRegister(right_node->InputAt(0));
    return true;
  }
  return false;
}

bool TryMatchBitwiseAndSmallMask(turboshaft::OperationMatcher& matcher,
                                 turboshaft::OpIndex op,
                                 turboshaft::OpIndex* left, int32_t* mask) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (const ChangeOp* change_op =
          matcher.TryCast<Opmask::kChangeInt32ToInt64>(op)) {
    return TryMatchBitwiseAndSmallMask(matcher, change_op->input(), left, mask);
  }
  if (const WordBinopOp* bitwise_and =
          matcher.TryCast<Opmask::kWord32BitwiseAnd>(op)) {
    if (matcher.MatchIntegralWord32Constant(bitwise_and->right(), mask) &&
        (*mask == 0xFF || *mask == 0xFFFF)) {
      *left = bitwise_and->left();
      return true;
    }
    if (matcher.MatchIntegralWord32Constant(bitwise_and->left(), mask) &&
        (*mask == 0xFF || *mask == 0xFFFF)) {
      *left = bitwise_and->right();
      return true;
    }
  }
  return false;
}

bool TryMatchSignExtendShift(InstructionSelectorT<TurboshaftAdapter>* selector,
                             turboshaft::OpIndex op, turboshaft::OpIndex* left,
                             int32_t* shift_by) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (const ChangeOp* change_op =
          selector->TryCast<Opmask::kChangeInt32ToInt64>(op)) {
    return TryMatchSignExtendShift(selector, change_op->input(), left,
                                   shift_by);
  }

  if (const ShiftOp* sar =
          selector->TryCast<Opmask::kWord32ShiftRightArithmetic>(op)) {
    const Operation& sar_lhs = selector->Get(sar->left());
    if (sar_lhs.Is<Opmask::kWord32ShiftLeft>() &&
        selector->CanCover(op, sar->left())) {
      const ShiftOp& shl = sar_lhs.Cast<ShiftOp>();
      int32_t sar_by, shl_by;
      if (selector->MatchIntegralWord32Constant(sar->right(), &sar_by) &&
          selector->MatchIntegralWord32Constant(shl.right(), &shl_by) &&
          sar_by == shl_by && (sar_by == 16 || sar_by == 24)) {
        *left = shl.left();
        *shift_by = sar_by;
        return true;
      }
    }
  }
  return false;
}

bool TryMatchAnyExtend(Arm64OperandGeneratorT<TurboshaftAdapter>* g,
                       InstructionSelectorT<TurboshaftAdapter>* selector,
                       turboshaft::OpIndex node, turboshaft::OpIndex left_node,
                       turboshaft::OpIndex right_node,
                       InstructionOperand* left_op,
                       InstructionOperand* right_op, InstructionCode* opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (!selector->CanCover(node, right_node)) return false;

  const Operation& right = selector->Get(right_node);
  OpIndex bitwise_and_left;
  int32_t mask;
  if (TryMatchBitwiseAndSmallMask(*selector, right_node, &bitwise_and_left,
                                  &mask)) {
    *left_op = g->UseRegister(left_node);
    *right_op = g->UseRegister(bitwise_and_left);
    *opcode |= AddressingModeField::encode(
        (mask == 0xFF) ? kMode_Operand2_R_UXTB : kMode_Operand2_R_UXTH);
    return true;
  }

  OpIndex shift_input_left;
  int32_t shift_by;
  if (TryMatchSignExtendShift(selector, right_node, &shift_input_left,
                              &shift_by)) {
    *left_op = g->UseRegister(left_node);
    *right_op = g->UseRegister(shift_input_left);
    *opcode |= AddressingModeField::encode(
        (shift_by == 24) ? kMode_Operand2_R_SXTB : kMode_Operand2_R_SXTH);
    return true;
  }

  if (const ChangeOp* change_op =
          right.TryCast<Opmask::kChangeInt32ToInt64>()) {
    // Use extended register form.
    *opcode |= AddressingModeField::encode(kMode_Operand2_R_SXTW);
    *left_op = g->UseRegister(left_node);
    *right_op = g->UseRegister(change_op->input());
    return true;
  }
  return false;
}

template <typename Adapter>
bool TryMatchLoadStoreShift(Arm64OperandGeneratorT<Adapter>* g,
                            InstructionSelectorT<Adapter>* selector,
                            MachineRepresentation rep,
                            typename Adapter::node_t node,
                            typename Adapter::node_t index,
                            InstructionOperand* index_op,
                            InstructionOperand* shift_immediate_op) {
  if (!selector->CanCover(node, index)) return false;
  if (index->InputCount() != 2) return false;
  switch (index->opcode()) {
    case IrOpcode::kWord32Shl:
    case IrOpcode::kWord64Shl: {
      Node* left = index->InputAt(0);
      Node* right = index->InputAt(1);
      if (!g->CanBeLoadStoreShiftImmediate(right, rep)) {
        return false;
      }
      *index_op = g->UseRegister(left);
      *shift_immediate_op = g->UseImmediate(right);
      return true;
    }
    default:
      return false;
  }
}

template <>
bool TryMatchLoadStoreShift(Arm64OperandGeneratorT<TurboshaftAdapter>* g,
                            InstructionSelectorT<TurboshaftAdapter>* selector,
                            MachineRepresentation rep, turboshaft::OpIndex node,
                            turboshaft::OpIndex index,
                            InstructionOperand* index_op,
                            InstructionOperand* shift_immediate_op) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (!selector->CanCover(node, index)) return false;
  if (const ChangeOp* change =
          selector->Get(index).TryCast<Opmask::kChangeUint32ToUint64>();
      change && selector->CanCover(index, change->input())) {
    index = change->input();
  }
  const ShiftOp* shift = selector->Get(index).TryCast<Opmask::kShiftLeft>();
  if (shift == nullptr) return false;
  if (!g->CanBeLoadStoreShiftImmediate(shift->right(), rep)) return false;
  *index_op = g->UseRegister(shift->left());
  *shift_immediate_op = g->UseImmediate(shift->right());
  return true;
}

// Bitfields describing binary operator properties:
// CanCommuteField is true if we can switch the two operands, potentially
// requiring commuting the flags continuation condition.
using CanCommuteField = base::BitField8<bool, 1, 1>;
// MustCommuteCondField is true when we need to commute the flags continuation
// condition in order to switch the operands.
using MustCommuteCondField = base::BitField8<bool, 2, 1>;
// IsComparisonField is true when the operation is a comparison and has no other
// result other than the condition.
using IsComparisonField = base::BitField8<bool, 3, 1>;
// IsAddSubField is true when an instruction is encoded as ADD or SUB.
using IsAddSubField = base::BitField8<bool, 4, 1>;

// Get properties of a binary operator.
uint8_t GetBinopProperties(InstructionCode opcode) {
  uint8_t result = 0;
  switch (opcode) {
    case kArm64Cmp32:
    case kArm64Cmp:
      // We can commute CMP by switching the inputs and commuting
      // the flags continuation.
      result = CanCommuteField::update(result, true);
      result = MustCommuteCondField::update(result, true);
      result = IsComparisonField::update(result, true);
      // The CMP and CMN instructions are encoded as SUB or ADD
      // with zero output register, and therefore support the same
      // operand modes.
      result = IsAddSubField::update(result, true);
      break;
    case kArm64Cmn32:
    case kArm64Cmn:
      result = CanCommuteField::update(result, true);
      result = IsComparisonField::update(result, true);
      result = IsAddSubField::update(result, true);
      break;
    case kArm64Add32:
    case kArm64Add:
      result = CanCommuteField::update(result, true);
      result = IsAddSubField::update(result, true);
      break;
    case kArm64Sub32:
    case kArm64Sub:
      result = IsAddSubField::update(result, true);
      break;
    case kArm64Tst32:
    case kArm64Tst:
      result = CanCommuteField::update(result, true);
      result = IsComparisonField::update(result, true);
      break;
    case kArm64And32:
    case kArm64And:
    case kArm64Or32:
    case kArm64Or:
    case kArm64Eor32:
    case kArm64Eor:
      result = CanCommuteField::update(result, true);
      break;
    default:
      UNREACHABLE();
  }
  DCHECK_IMPLIES(MustCommuteCondField::decode(result),
                 CanCommuteField::decode(result));
  return result;
}

// Shared routine for multiple binary operations.
template <typename Adapter, typename Matcher>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                ImmediateMode operand_mode, FlagsContinuationT<Adapter>* cont) {
  Arm64OperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[5];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  Node* left_node = node->InputAt(0);
  Node* right_node = node->InputAt(1);

  uint8_t properties = GetBinopProperties(opcode);
  bool can_commute = CanCommuteField::decode(properties);
  bool must_commute_cond = MustCommuteCondField::decode(properties);
  bool is_add_sub = IsAddSubField::decode(properties);

  if (g.CanBeImmediate(right_node, operand_mode)) {
    inputs[input_count++] = g.UseRegister(left_node);
    inputs[input_count++] = g.UseImmediate(right_node);
  } else if (can_commute && g.CanBeImmediate(left_node, operand_mode)) {
    if (must_commute_cond) cont->Commute();
    inputs[input_count++] = g.UseRegister(right_node);
    inputs[input_count++] = g.UseImmediate(left_node);
  } else if (is_add_sub &&
             TryMatchAnyExtend(&g, selector, node, left_node, right_node,
                               &inputs[0], &inputs[1], &opcode)) {
    input_count += 2;
  } else if (is_add_sub && can_commute &&
             TryMatchAnyExtend(&g, selector, node, right_node, left_node,
                               &inputs[0], &inputs[1], &opcode)) {
    if (must_commute_cond) cont->Commute();
    input_count += 2;
  } else if (TryMatchAnyShift(selector, node, right_node, &opcode, !is_add_sub,
                              Matcher::representation)) {
    Matcher m_shift(right_node);
    inputs[input_count++] = g.UseRegisterOrImmediateZero(left_node);
    inputs[input_count++] = g.UseRegister(m_shift.left().node());
    // We only need at most the last 6 bits of the shift.
    inputs[input_count++] = g.UseImmediate(static_cast<int>(
        g.GetIntegerConstantValue(m_shift.right().node()) & 0x3F));
  } else if (can_commute &&
             TryMatchAnyShift(selector, node, left_node, &opcode, !is_add_sub,
                              Matcher::representation)) {
    if (must_commute_cond) cont->Commute();
    Matcher m_shift(left_node);
    inputs[input_count++] = g.UseRegisterOrImmediateZero(right_node);
    inputs[input_count++] = g.UseRegister(m_shift.left().node());
    // We only need at most the last 6 bits of the shift.
    inputs[input_count++] = g.UseImmediate(static_cast<int>(
        g.GetIntegerConstantValue(m_shift.right().node()) & 0x3F));
  } else {
    inputs[input_count++] = g.UseRegisterOrImmediateZero(left_node);
    inputs[input_count++] = g.UseRegister(right_node);
  }

  if (!IsComparisonField::decode(properties)) {
    outputs[output_count++] = g.DefineAsRegister(node);
  }

  if (cont->IsSelect()) {
    // Keep the values live until the end so that we can use operations that
    // write registers to generate the condition, without accidently
    // overwriting the inputs.
    inputs[input_count++] =
        g.UseRegisterAtEndOrImmediateZero(cont->true_value());
    inputs[input_count++] =
        g.UseRegisterAtEndOrImmediateZero(cont->false_value());
  }

  DCHECK_NE(0u, input_count);
  DCHECK((output_count != 0) || IsComparisonField::decode(properties));
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

// Shared routine for multiple binary operations.
template <typename Adapter, typ
```