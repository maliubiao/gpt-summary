Response:
The user wants a summary of the provided C++ header file for the RISC-V instruction selector in V8.

Here's a breakdown of the request and how to approach it:

1. **Identify the core purpose:** The filename `instruction-selector-riscv.h` strongly suggests this file defines the logic for selecting RISC-V instructions based on the intermediate representation (IR) of the V8 JavaScript engine.

2. **Examine key components:**  Look for important classes, methods, and data structures within the code. The `RiscvOperandGeneratorT` template is immediately noticeable, hinting at operand handling. The numerous `Visit...` functions suggest patterns for processing different IR nodes.

3. **Analyze functionality by section:**
    * **Operand Generation:** The `RiscvOperandGeneratorT` class is central to creating instruction operands (registers, immediates, memory addresses) specifically for RISC-V.
    * **Instruction Emission:** The `Emit` functions (e.g., `selector->Emit(...)`) are used to generate the actual RISC-V instructions.
    * **IR Node Visiting:** The `Visit...` functions handle different types of IR nodes (e.g., binary operations, comparisons, loads, stores) and translate them into corresponding RISC-V instructions. The templates parameterized by `Adapter` suggest support for different IR representations (like Turbofan and Turboshaft).
    * **Immediate Handling:**  The code explicitly checks if operands can be represented as immediate values.
    * **Comparison Logic:** Dedicated `VisitCompare` and related functions handle comparison operations and conditional branching.
    * **Switch Statements:**  The `VisitSwitch` function deals with compiling JavaScript `switch` statements into efficient RISC-V code (potentially using jump tables or binary search).
    * **SIMD Support:**  The presence of `VisitSimd...` and `EmitS128Load` indicates support for Single Instruction, Multiple Data (SIMD) operations.

4. **Address specific requests:**
    * **.tq extension:** The prompt asks about `.tq` files (Torque). The provided file is a `.h` (header) file, not a `.tq` file.
    * **Relationship to JavaScript:** The instruction selector's role is to translate V8's internal representation of JavaScript code into machine code. The operations it performs (arithmetic, comparisons, memory access) directly correspond to JavaScript language features.
    * **Code Logic Reasoning:**  Focus on simple examples like binary operations and comparisons to illustrate input/output.
    * **Common Programming Errors:** Think about typical errors that might occur during instruction selection or that the generated code might expose (e.g., type mismatches leading to incorrect instruction choices).

5. **Structure the summary:** Organize the findings into logical categories (Operand Generation, Instruction Selection for Different Operations, etc.) to create a clear and understandable overview.

6. **Refine and clarify:** Ensure the language is precise and avoids overly technical jargon where possible. Provide brief explanations of key concepts.
好的，让我们来分析一下 `v8/src/compiler/backend/riscv/instruction-selector-riscv.h` 文件的功能。

**功能归纳:**

`v8/src/compiler/backend/riscv/instruction-selector-riscv.h` 文件是 V8 JavaScript 引擎中针对 RISC-V 架构的**指令选择器 (Instruction Selector)** 的头文件。  它的主要功能是定义了将 V8 的中间表示 (IR - Intermediate Representation) 节点转换为具体的 RISC-V 机器指令的过程和相关工具。

更具体地说，它包含了以下方面的定义和声明：

1. **`RiscvOperandGeneratorT` 模板类:**  这是一个用于生成 RISC-V 指令操作数的辅助类。它可以根据 IR 节点的类型和值，生成相应的寄存器操作数、立即数操作数或内存操作数。它还包含了一些判断操作数是否可以作为立即数的逻辑。

2. **`Visit...` 函数模板:**  定义了一系列用于处理不同类型 IR 节点的函数模板。例如：
   - `VisitRR`: 处理两个寄存器操作数的指令。
   - `VisitRRI`: 处理两个寄存器和一个立即数操作数的指令。
   - `VisitRRR`: 处理三个寄存器操作数的指令。
   - `VisitBinop`:  处理二元运算操作。
   - `VisitCompare`: 处理比较操作。
   - `VisitLoadTransform`: 处理特殊的加载转换操作，尤其针对 SIMD 指令。
   - `VisitStackSlot`: 处理栈槽分配。
   - `VisitSwitch`: 处理 `switch` 语句。

   这些函数负责根据 IR 节点的语义选择合适的 RISC-V 指令，并使用 `RiscvOperandGeneratorT` 生成正确的操作数。

3. **辅助函数:**  提供了一些辅助函数，例如 `TryMatchImmediate` 用于尝试将操作数匹配为立即数，以及针对不同数据类型和操作的比较函数 (`VisitFloat32Compare`, `VisitFloat64Compare`, `VisitWordCompare`, `VisitWordCompareZero`)。

4. **与架构相关的定义:** 包含了一些 RISC-V 特定的定义，例如判断立即数是否适合特定指令模式的函数 (`ImmediateFitsAddrMode1Instruction`)。

5. **模板化设计:** 使用 C++ 模板 (`template <typename Adapter>`)  使得指令选择器可以与不同的 V8 编译器后端适配器 (`Adapter`) 一起工作，例如 Turbofan 和 Turboshaft。

**关于 .tq 扩展名:**

正如文件中所见，`v8/src/compiler/backend/riscv/instruction-selector-riscv.h` 以 `.h` 结尾，这是一个标准的 C++ 头文件。 **如果一个文件以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。** Torque 是一种 V8 自定义的语言，用于生成高效的运行时代码。

**与 JavaScript 功能的关系及示例:**

指令选择器在 V8 编译 JavaScript 代码的过程中扮演着至关重要的角色。它负责将高级的、平台无关的中间表示转换为底层的、特定于 RISC-V 架构的机器指令。

以下是一些 JavaScript 功能以及指令选择器如何处理它们的示例：

* **算术运算 (+, -, *, /):**
  当 JavaScript 代码执行加法运算 `a + b` 时，编译器会生成一个表示加法操作的 IR 节点。指令选择器中的 `VisitBinop` 函数（或其他相应的 `Visit...` 函数）会被调用，并根据 `a` 和 `b` 的类型（整数、浮点数等）选择合适的 RISC-V 加法指令，例如 `add`, `fadd.s`, `fadd.d` 等。

  ```javascript
  // JavaScript 代码
  function add(a, b) {
    return a + b;
  }
  ```

  **假设输入 (IR Node):**  一个表示加法操作的 IR 节点，输入分别是代表变量 `a` 和 `b` 的 IR 节点。

  **可能的输出 (RISC-V 指令):** 如果 `a` 和 `b` 都是整数，指令选择器可能会生成 `add rd, rs1, rs2` 这样的指令，其中 `rd`, `rs1`, `rs2` 是寄存器。如果其中一个是立即数，则可能是 `addi rd, rs1, imm`。

* **比较运算 (>, <, ==, !=):**
  当执行比较操作 `a > b` 时，指令选择器中的 `VisitCompare` 或 `VisitWordCompare` 等函数会被调用。它会生成相应的 RISC-V 比较指令，例如 `slt`, `sgt`, `beq`, `bne` 等，并配合条件分支指令来控制程序的流程。

  ```javascript
  // JavaScript 代码
  function compare(a, b) {
    if (a > b) {
      return true;
    } else {
      return false;
    }
  }
  ```

  **假设输入 (IR Node):** 一个表示大于比较的 IR 节点，输入分别是代表变量 `a` 和 `b` 的 IR 节点。

  **可能的输出 (RISC-V 指令):**  可能生成 `slt rd, rs1, rs2` (如果需要保存比较结果) 或直接生成条件分支指令 `bgt rs1, rs2, label`。

* **访问对象属性:**
  当访问对象的属性 `object.property` 时，指令选择器需要生成加载指令来获取属性的值。

  ```javascript
  // JavaScript 代码
  const obj = { x: 10 };
  const value = obj.x;
  ```

  **假设输入 (IR Node):**  一个表示加载对象属性的 IR 节点，包括对象和属性的信息。

  **可能的输出 (RISC-V 指令):**  可能生成类似 `lw rd, offset(rs1)` 的指令，其中 `rs1` 指向对象，`offset` 是属性的偏移量。

* **函数调用:**
  当调用一个 JavaScript 函数时，指令选择器需要生成函数调用相关的指令，包括参数传递、跳转到函数地址、保存和恢复寄存器等。

**代码逻辑推理示例:**

假设有以下 C++ 代码片段（简化自头文件）：

```c++
template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
}
```

**假设输入:**
- `selector`: 一个指向 `InstructionSelectorT` 实例的指针。
- `opcode`:  `kRiscvAdd` (RISC-V 加法指令的指令码)。
- `node`:  一个表示二元加法运算的 IR 节点，其输入分别是两个变量 `a` 和 `b` 的 IR 节点。

**输出:**
该函数会调用 `selector->Emit` 生成一个 RISC-V 加法指令，其目标寄存器是 `node` 对应的寄存器，源操作数分别是 `a` 和 `b` 对应的寄存器。生成的指令可能类似于： `add rd_node, rs_a, rs_b`。

**用户常见的编程错误示例 (与生成的代码相关):**

虽然这个头文件本身是 V8 内部代码，用户不会直接编写或修改它，但指令选择器的逻辑正确性至关重要，因为它直接影响最终生成的机器码的正确性和效率。

与指令选择器相关的潜在问题，最终可能体现为 JavaScript 程序的运行时错误：

* **类型错误导致指令选择错误:**  例如，如果 JavaScript 代码中对不同类型的值进行了不恰当的运算，指令选择器可能选择了错误的指令（例如，将浮点数加法指令用于整数运算），导致结果不正确或程序崩溃。

  ```javascript
  // 潜在的类型错误
  let x = 5;
  let y = "10";
  let sum = x + y; // JavaScript 会将 "10" 转换为字符串，结果是 "510"
  ```
  如果指令选择器错误地将其视为数字加法，生成的机器码将无法得到预期的字符串拼接结果。

* **内存访问错误:**  如果指令选择器在处理对象属性访问或数组访问时，计算了错误的内存地址，可能导致程序尝试访问无效的内存区域，从而引发崩溃。

* **精度问题:**  在处理浮点数运算时，指令选择器的实现细节可能会影响计算精度。选择不合适的指令或处理舍入的方式不当，可能导致浮点数计算结果与预期略有偏差。

**这是第1部分，共3部分，请归纳一下它的功能:**

总而言之，`v8/src/compiler/backend/riscv/instruction-selector-riscv.h` 文件的核心功能是**定义了将 V8 的中间表示 (IR) 转换为 RISC-V 架构机器指令的规则和机制**。它通过提供操作数生成工具和针对不同 IR 节点类型的处理函数，实现了从高级语义到低级指令的映射，是 V8 编译器后端针对 RISC-V 架构的关键组成部分。

Prompt: 
```
这是目录为v8/src/compiler/backend/riscv/instruction-selector-riscv.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/instruction-selector-riscv.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef V8_COMPILER_BACKEND_RISCV_INSTRUCTION_SELECTOR_RISCV_H_
#define V8_COMPILER_BACKEND_RISCV_INSTRUCTION_SELECTOR_RISCV_H_

#include <optional>

#include "src/base/bits.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/operations.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(...) PrintF(__VA_ARGS__)

// Adds RISC-V-specific methods for generating InstructionOperands.
template <typename Adapter>
class RiscvOperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit RiscvOperandGeneratorT<Adapter>(
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

  bool IsIntegerConstant(typename Adapter::node_t node) const {
    return selector()->is_integer_constant(node);
  }

  int64_t GetIntegerConstantValue(Node* node);

  bool IsIntegerConstant(typename Adapter::ConstantView constant) {
    return constant.is_int32() || constant.is_int64();
  }

  int64_t GetIntegerConstantValue(typename Adapter::ConstantView constant) {
    if (constant.is_int32()) {
      return constant.int32_value();
    }
    DCHECK(constant.is_int64());
    return constant.int64_value();
  }

  std::optional<int64_t> GetOptionalIntegerConstant(
      InstructionSelectorT<TurboshaftAdapter>* selector,
      turboshaft::OpIndex operation) {
    if (!this->is_constant(operation)) return {};
    auto constant = selector->constant_view(operation);
    if (!this->IsIntegerConstant(constant)) return {};
    return this->GetIntegerConstantValue(constant);
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
  bool CanBeZero(typename Adapter::node_t node) {
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

  bool CanBeImmediate(node_t node, InstructionCode mode) {
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

  bool CanBeImmediate(int64_t value, InstructionCode opcode);

 private:
  bool ImmediateFitsAddrMode1Instruction(int32_t imm) const {
    TRACE("UNIMPLEMENTED instr_sel: %s at line %d\n", __FUNCTION__, __LINE__);
    return false;
  }
};

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
             typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
             typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
static void VisitRRI(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& op = selector->Get(node);
    int imm = op.template Cast<Simd128ExtractLaneOp>().lane;
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)),
                   g.UseImmediate(imm));
  } else {
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseImmediate(imm));
  }
}

template <typename Adapter>
static void VisitSimdShift(InstructionSelectorT<Adapter>* selector,
                           ArchOpcode opcode, typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  if (g.IsIntegerConstant(selector->input_at(node, 1))) {
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseImmediate(selector->input_at(node, 1)));
  } else {
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseRegister(selector->input_at(node, 1)));
  }
}

template <typename Adapter>
static void VisitRRIR(InstructionSelectorT<Adapter>* selector,
                      ArchOpcode opcode, typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Simd128ReplaceLaneOp& op =
        selector->Get(node).template Cast<turboshaft::Simd128ReplaceLaneOp>();
    selector->Emit(opcode, g.DefineAsRegister(node), g.UseRegister(op.input(0)),
                   g.UseImmediate(op.lane), g.UseUniqueRegister(op.input(1)));
  } else {
    int32_t imm = OpParameter<int32_t>(node->op());
    selector->Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(selector->input_at(node, 0)),
                   g.UseImmediate(imm),
                   g.UseRegister(selector->input_at(node, 1)));
  }
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node,
              typename OperandGeneratorT<Adapter>::RegisterUseKind kind =
                  OperandGeneratorT<Adapter>::RegisterUseKind::kUseRegister) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1), kind));
}

void VisitRRR(InstructionSelectorT<TurbofanAdapter>* selector,
              InstructionCode opcode, Node* node) {
  RiscvOperandGeneratorT<TurbofanAdapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
static void VisitUniqueRRR(InstructionSelectorT<Adapter>* selector,
                           ArchOpcode opcode, typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseUniqueRegister(selector->input_at(node, 0)),
                 g.UseUniqueRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
void VisitRRRR(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
               typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineSameAsFirst(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)),
                 g.UseRegister(selector->input_at(node, 2)));
}

template <typename Adapter>
static void VisitRRO(InstructionSelectorT<Adapter>* selector, ArchOpcode opcode,
                     typename Adapter::node_t node) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseOperand(selector->input_at(node, 1), opcode));
}

template <typename Adapter>
bool TryMatchImmediate(InstructionSelectorT<Adapter>* selector,
                       InstructionCode* opcode_return,
                       typename Adapter::node_t node,
                       size_t* input_count_return, InstructionOperand* inputs) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  if (g.CanBeImmediate(node, *opcode_return)) {
    *opcode_return |= AddressingModeField::encode(kMode_MRI);
    inputs[0] = g.UseImmediate(node);
    *input_count_return = 1;
    return true;
  }
  return false;
}

// Shared routine for multiple binary operations.
template <typename Adapter, typename Matcher>
static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       typename TurboshaftAdapter::node_t node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode,
                       FlagsContinuationT<TurboshaftAdapter>* cont) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  RiscvOperandGeneratorT<TurboshaftAdapter> g(selector);
  InstructionOperand inputs[2];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  const Operation& binop = selector->Get(node);
  OpIndex left_node = binop.input(0);
  OpIndex right_node = binop.input(1);

  if (TryMatchImmediate(selector, &opcode, right_node, &input_count,
                        &inputs[1])) {
    inputs[0] = g.UseRegisterOrImmediateZero(left_node);
    input_count++;
  } else if (has_reverse_opcode &&
             TryMatchImmediate(selector, &reverse_opcode, left_node,
                               &input_count, &inputs[1])) {
    inputs[0] = g.UseRegisterOrImmediateZero(right_node);
    opcode = reverse_opcode;
    input_count++;
  } else {
    inputs[input_count++] = g.UseRegister(left_node);
    inputs[input_count++] = g.UseOperand(right_node, opcode);
  }

  if (cont->IsDeoptimize()) {
    // If we can deoptimize as a result of the binop, we need to make sure that
    // the deopt inputs are not overwritten by the binop result. One way
    // to achieve that is to declare the output register as same-as-first.
    outputs[output_count++] = g.DefineSameAsFirst(node);
  } else {
    outputs[output_count++] = g.DefineAsRegister(node);
  }

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter, typename Matcher>
static void VisitBinop(InstructionSelectorT<TurboshaftAdapter>* selector,
                       TurboshaftAdapter::node_t node, InstructionCode opcode,
                       bool has_reverse_opcode,
                       InstructionCode reverse_opcode) {
  FlagsContinuationT<TurboshaftAdapter> cont;
  VisitBinop<Adapter, Matcher>(selector, node, opcode, has_reverse_opcode,
                               reverse_opcode, &cont);
}

template <typename Adapter, typename Matcher>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode,
                       FlagsContinuationT<Adapter>* cont) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  Int32BinopMatcher m(node);
  InstructionOperand inputs[2];
  size_t input_count = 0;
  InstructionOperand outputs[1];
  size_t output_count = 0;

  if (TryMatchImmediate(selector, &opcode, m.right().node(), &input_count,
                        &inputs[1])) {
    inputs[0] = g.UseRegisterOrImmediateZero(m.left().node());
    input_count++;
  } else if (has_reverse_opcode &&
             TryMatchImmediate(selector, &reverse_opcode, m.left().node(),
                               &input_count, &inputs[1])) {
    inputs[0] = g.UseRegisterOrImmediateZero(m.right().node());
    opcode = reverse_opcode;
    input_count++;
  } else {
    inputs[input_count++] = g.UseRegister(m.left().node());
    inputs[input_count++] = g.UseOperand(m.right().node(), opcode);
  }

  if (cont->IsDeoptimize()) {
    // If we can deoptimize as a result of the binop, we need to make sure that
    // the deopt inputs are not overwritten by the binop result. One way
    // to achieve that is to declare the output register as same-as-first.
    outputs[output_count++] = g.DefineSameAsFirst(node);
  } else {
    outputs[output_count++] = g.DefineAsRegister(node);
  }

  DCHECK_NE(0u, input_count);
  DCHECK_EQ(1u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

template <typename Adapter, typename Matcher>
static void VisitBinop(InstructionSelectorT<Adapter>* selector, Node* node,
                       InstructionCode opcode, bool has_reverse_opcode,
                       InstructionCode reverse_opcode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop<Adapter, Matcher>(selector, node, opcode, has_reverse_opcode,
                               reverse_opcode, &cont);
}

template <typename Adapter, typename Matcher>
static void VisitBinop(InstructionSelectorT<Adapter>* selector,
                       typename Adapter::node_t node, InstructionCode opcode,
                       FlagsContinuationT<Adapter>* cont) {
  VisitBinop<Adapter, Matcher>(selector, node, opcode, false, kArchNop, cont);
}

template <typename Adapter, typename Matcher>
static void VisitBinop(InstructionSelectorT<Adapter>* selector,
                       typename Adapter::node_t node, InstructionCode opcode) {
  VisitBinop<Adapter, Matcher>(selector, node, opcode, false, kArchNop);
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
    RiscvOperandGeneratorT<Adapter> g(this);
    Emit(kArchAbortCSADcheck, g.NoOutput(),
         g.UseFixed(this->input_at(node, 0), a0));
}

template <typename Adapter>
void EmitS128Load(InstructionSelectorT<Adapter>* selector,
                  typename Adapter::node_t node, InstructionCode opcode,
                  VSew sew, Vlmul lmul);

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitLoadTransform(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const Simd128LoadTransformOp& op =
      this->Get(node).Cast<Simd128LoadTransformOp>();
  bool is_protected = (op.load_kind.with_trap_handler);
  InstructionCode opcode = kArchNop;
  switch (op.transform_kind) {
    case Simd128LoadTransformOp::TransformKind::k8Splat:
      opcode = kRiscvS128LoadSplat;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E8, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k16Splat:
      opcode = kRiscvS128LoadSplat;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E16, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k32Splat:
      opcode = kRiscvS128LoadSplat;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E32, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k64Splat:
      opcode = kRiscvS128LoadSplat;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E64, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8S:
      opcode = kRiscvS128Load64ExtendS;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E16, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k8x8U:
      opcode = kRiscvS128Load64ExtendU;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E16, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4S:
      opcode = kRiscvS128Load64ExtendS;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E32, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k16x4U:
      opcode = kRiscvS128Load64ExtendU;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E32, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2S:
      opcode = kRiscvS128Load64ExtendS;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E64, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k32x2U:
      opcode = kRiscvS128Load64ExtendU;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E64, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k32Zero:
      opcode = kRiscvS128Load32Zero;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E32, m1);
      break;
    case Simd128LoadTransformOp::TransformKind::k64Zero:
      opcode = kRiscvS128Load64Zero;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E64, m1);
      break;
    default:
      UNIMPLEMENTED();
  }
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitLoadTransform(Node* node) {
  LoadTransformParameters params = LoadTransformParametersOf(node->op());
  bool is_protected =
      (params.kind == MemoryAccessKind::kProtectedByTrapHandler);
  InstructionCode opcode = kArchNop;
  switch (params.transformation) {
    case LoadTransformation::kS128Load8Splat:
      opcode = kRiscvS128LoadSplat;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E8, m1);
      break;
    case LoadTransformation::kS128Load16Splat:
      opcode = kRiscvS128LoadSplat;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E16, m1);
      break;
    case LoadTransformation::kS128Load32Splat:
      opcode = kRiscvS128LoadSplat;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E32, m1);
      break;
    case LoadTransformation::kS128Load64Splat:
      opcode = kRiscvS128LoadSplat;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E64, m1);
      break;
    case LoadTransformation::kS128Load8x8S:
      opcode = kRiscvS128Load64ExtendS;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E16, m1);
      break;
    case LoadTransformation::kS128Load8x8U:
      opcode = kRiscvS128Load64ExtendU;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E16, m1);
      break;
    case LoadTransformation::kS128Load16x4S:
      opcode = kRiscvS128Load64ExtendS;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E32, m1);
      break;
    case LoadTransformation::kS128Load16x4U:
      opcode = kRiscvS128Load64ExtendU;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E32, m1);
      break;
    case LoadTransformation::kS128Load32x2S:
      opcode = kRiscvS128Load64ExtendS;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E64, m1);
      break;
    case LoadTransformation::kS128Load32x2U:
      opcode = kRiscvS128Load64ExtendU;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E64, m1);
      break;
    case LoadTransformation::kS128Load32Zero:
      opcode = kRiscvS128Load32Zero;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E32, m1);
      break;
    case LoadTransformation::kS128Load64Zero:
      opcode = kRiscvS128Load64Zero;
      if (is_protected) {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
      EmitS128Load(this, node, opcode, E64, m1);
      break;
    default:
      UNIMPLEMENTED();
  }
}

// Shared routine for multiple compare operations.
template <typename Adapter>
static Instruction* VisitCompare(InstructionSelectorT<Adapter>* selector,
                                 InstructionCode opcode,
                                 InstructionOperand left,
                                 InstructionOperand right,
                                 FlagsContinuationT<Adapter>* cont) {
#ifdef V8_COMPRESS_POINTERS
  if (opcode == kRiscvCmp32) {
    RiscvOperandGeneratorT<Adapter> g(selector);
    InstructionOperand inputs[] = {left, right};
    if (right.IsImmediate()) {
      InstructionOperand temps[1] = {g.TempRegister()};
      return selector->EmitWithContinuation(opcode, 0, nullptr,
                                            arraysize(inputs), inputs,
                                            arraysize(temps), temps, cont);
    } else {
      InstructionOperand temps[2] = {g.TempRegister(), g.TempRegister()};
      return selector->EmitWithContinuation(opcode, 0, nullptr,
                                            arraysize(inputs), inputs,
                                            arraysize(temps), temps, cont);
    }
  }
#endif
  return selector->EmitWithContinuation(opcode, left, right, cont);
}

// Shared routine for multiple compare operations.
template <typename Adapter>
static Instruction* VisitWordCompareZero(
    InstructionSelectorT<Adapter>* selector, InstructionOperand value,
    FlagsContinuationT<Adapter>* cont) {
  return selector->EmitWithContinuation(kRiscvCmpZero, value, cont);
}

// Shared routine for multiple float32 compare operations.
template <typename Adapter>
void VisitFloat32Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ComparisonOp& op = selector->Get(node).template Cast<ComparisonOp>();
    OpIndex left = op.left();
    OpIndex right = op.right();
    if (selector->MatchZero(right)) {
      VisitCompare(selector, kRiscvCmpS, g.UseRegister(left),
                   g.UseImmediate(right), cont);
    } else if (selector->MatchZero(left)) {
      cont->Commute();
      VisitCompare(selector, kRiscvCmpS, g.UseRegister(right),
                   g.UseImmediate(left), cont);
    } else {
      VisitCompare(selector, kRiscvCmpS, g.UseRegister(left),
                   g.UseRegister(right), cont);
    }
  } else {
    Float32BinopMatcher m(node);
    InstructionOperand lhs, rhs;

    lhs = m.left().IsZero() ? g.UseImmediate(m.left().node())
                            : g.UseRegister(m.left().node());
    rhs = m.right().IsZero() ? g.UseImmediate(m.right().node())
                             : g.UseRegister(m.right().node());
    VisitCompare(selector, kRiscvCmpS, lhs, rhs, cont);
  }
}

// Shared routine for multiple float64 compare operations.
template <typename Adapter>
void VisitFloat64Compare(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t node,
                         FlagsContinuationT<Adapter>* cont) {
  if constexpr (Adapter::IsTurboshaft) {
    RiscvOperandGeneratorT<Adapter> g(selector);
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const Operation& compare = selector->Get(node);
    DCHECK(compare.Is<ComparisonOp>());
    OpIndex lhs = compare.input(0);
    OpIndex rhs = compare.input(1);
    if (selector->MatchZero(rhs)) {
      VisitCompare(selector, kRiscvCmpD, g.UseRegister(lhs),
                   g.UseImmediate(rhs), cont);
    } else if (selector->MatchZero(lhs)) {
      VisitCompare(selector, kRiscvCmpD, g.UseImmediate(lhs),
                   g.UseRegister(rhs), cont);
    } else {
      VisitCompare(selector, kRiscvCmpD, g.UseRegister(lhs), g.UseRegister(rhs),
                   cont);
    }
  } else {
    RiscvOperandGeneratorT<Adapter> g(selector);
    Float64BinopMatcher m(node);
    InstructionOperand lhs, rhs;

    lhs = m.left().IsZero() ? g.UseImmediate(m.left().node())
                            : g.UseRegister(m.left().node());
    rhs = m.right().IsZero() ? g.UseImmediate(m.right().node())
                             : g.UseRegister(m.right().node());
    VisitCompare(selector, kRiscvCmpD, lhs, rhs, cont);
  }
}

// Shared routine for multiple word compare operations.
template <typename Adapter>
Instruction* VisitWordCompare(InstructionSelectorT<Adapter>* selector,
                              typename Adapter::node_t node,
                              InstructionCode opcode,
                              FlagsContinuationT<Adapter>* cont,
                              bool commutative) {
  RiscvOperandGeneratorT<Adapter> g(selector);
  DCHECK_EQ(selector->value_input_count(node), 2);
  auto left = selector->input_at(node, 0);
  auto right = selector->input_at(node, 1);
  // If one of the two inputs is an immediate, make sure it's on the right.
  if (!g.CanBeImmediate(right, opcode) && g.CanBeImmediate(left, opcode)) {
    cont->Commute();
    std::swap(left, right);
  }
  // Match immediates on right side of comparison.
  if (g.CanBeImmediate(right, opcode)) {
#if V8_TARGET_ARCH_RISCV64
    if (opcode == kRiscvTst64 || opcode == kRiscvTst32) {
#elif V8_TARGET_ARCH_RISCV32
    if (opcode == kRiscvTst32) {
#endif
      if constexpr (Adapter::IsTurbofan) {
        if (selector->opcode(left) ==
            Adapter::opcode_t::kTruncateInt64ToInt32) {
          return VisitCompare(selector, opcode,
                              g.UseRegister(selector->input_at(left, 0)),
                              g.UseImmediate(right), cont);
        } else {
          return VisitCompare(selector, opcode, g.UseRegister(left),
                              g.UseImmediate(right), cont);
        }
      } else {
        return VisitCompare(selector, opcode, g.UseRegister(left),
                            g.UseImmediate(right), cont);
      }
    } else {
      switch (cont->condition()) {
        case kEqual:
        case kNotEqual:
          if (cont->IsSet()) {
            return VisitCompare(selector, opcode, g.UseRegister(left),
                                g.UseImmediate(right), cont);
          } else {
            if (g.CanBeZero(right)) {
              return VisitWordCompareZero(
                  selector, g.UseRegisterOrImmediateZero(left), cont);
            } else {
              return VisitCompare(selector, opcode, g.UseRegister(left),
                                  g.UseRegister(right), cont);
            }
          }
          break;
        case kSignedLessThan:
        case kSignedGreaterThanOrEqual:
        case kUnsignedLessThan:
        case kUnsignedGreaterThanOrEqual: {
          if (g.CanBeZero(right)) {
            return VisitWordCompareZero(
                selector, g.UseRegisterOrImmediateZero(left), cont);
          } else {
            return VisitCompare(selector, opcode, g.UseRegister(left),
                                g.UseImmediate(right), cont);
          }
        } break;
        default:
          if (g.CanBeZero(right)) {
            return VisitWordCompareZero(
                selector, g.UseRegisterOrImmediateZero(left), cont);
          } else {
            return VisitCompare(selector, opcode, g.UseRegister(left),
                                g.UseRegister(right), cont);
          }
      }
    }
  } else {
    return VisitCompare(selector, opcode, g.UseRegister(left),
                        g.UseRegister(right), cont);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSwitch(node_t node,
                                                const SwitchInfo& sw) {
    RiscvOperandGeneratorT<Adapter> g(this);
    InstructionOperand value_operand = g.UseRegister(this->input_at(node, 0));

    // Emit either ArchTableSwitch or ArchBinarySearchSwitch.
    if (enable_switch_jump_table_ ==
        InstructionSelector::kEnableSwitchJumpTable) {
      static const size_t kMaxTableSwitchValueRange = 2 << 16;
      size_t table_space_cost = 10 + 2 * sw.value_range();
      size_t table_time_cost = 3;
      size_t lookup_space_cost = 2 + 2 * sw.case_count();
      size_t lookup_time_cost = sw.case_count();
      if (sw.case_count() > 0 &&
          table_space_cost + 3 * table_time_cost <=
              lookup_space_cost + 3 * lookup_time_cost &&
          sw.min_value() > std::numeric_limits<int32_t>::min() &&
          sw.value_range() <= kMaxTableSwitchValueRange) {
        InstructionOperand index_operand = value_operand;
        if (sw.min_value()) {
          index_operand = g.TempRegister();
          Emit(kRiscvSub32, index_operand, value_operand,
               g.TempImmediate(sw.min_value()));
        }
        // Generate a table lookup.
        return EmitTableSwitch(sw, index_operand);
      }
    }

    // Generate a tree of conditional jumps.
    return EmitBinarySearchSwitch(sw, value_operand);
}

template <typename Adapter>
void EmitWordCompareZero(InstructionSelectorT<Adapter>* selector,
                         typename Adapter::node_t value,
               
"""


```