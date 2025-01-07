Response: Let's break down the thought process for analyzing this C++ file and generating the summary and JavaScript examples.

1. **Understanding the Goal:** The request asks for a summary of the `instruction.cc` file's functionality within the V8 compiler and how it relates to JavaScript. The key is to identify the core concepts and data structures this file defines and their role in the compilation process.

2. **Initial Skim for Keywords and Structure:**  The first step is a quick scan of the code for recurring keywords, class names, and general structure. I see things like `Instruction`, `InstructionOperand`, `InstructionBlock`, `ParallelMove`, `Constant`, `PhiInstruction`, `FrameStateDescriptor`. The `#include` directives also give hints (e.g., `compiler/backend`, `codegen`, `objects`).

3. **Identifying Core Data Structures:**  The repeated class names suggest these are the fundamental building blocks. I'll focus on understanding what each of these represents:

    * **`Instruction`:**  This seems like the most central element. It probably represents a single operation or step in the compiled code. The presence of `input`, `output`, and `temp` operands confirms this. The `opcode_` member reinforces the idea of an operation code.

    * **`InstructionOperand`:**  Instructions need data to operate on. These operands likely represent registers, memory locations (stack slots), or constant values. The various subclasses like `UnallocatedOperand`, `ConstantOperand`, `ImmediateOperand`, and `LocationOperand` suggest different types of operands with varying allocation states.

    * **`InstructionBlock`:**  Code isn't just a flat sequence of instructions. It's organized into blocks. This class likely represents a basic block in the control flow graph. The members like `successors_`, `predecessors_`, and `phis_` strongly point to this.

    * **`ParallelMove`:**  Optimization often involves moving data between locations. This class likely deals with sequences of moves that can be performed simultaneously.

    * **`Constant`:**  Literal values used in the code.

    * **`PhiInstruction`:**  Used in static single assignment (SSA) form, these instructions merge values from different control flow paths at a join point.

    * **`FrameStateDescriptor`:**  This seems related to the runtime state of the program, particularly when entering or leaving functions or when deoptimization occurs. The members like `parameters_count`, `locals_count`, and the connection to `BytecodeOffset` suggest its role in describing the stack frame.

4. **Inferring Relationships and Functionality:**  Now I'll think about how these structures interact and what their purpose is within the compiler:

    * Instructions operate on operands.
    * Instructions are grouped into blocks.
    * `ParallelMove` likely optimizes data movements between instructions or blocks.
    * `PhiInstruction` helps manage data flow in control flow merges.
    * `FrameStateDescriptor` is crucial for handling function calls, returns, and deoptimization.

5. **Connecting to the Compilation Process:**  Based on the `#include` directives and the class names, I can infer where this file fits within the V8 compilation pipeline:

    * It's in `src/compiler/backend`, suggesting it's part of the later stages, dealing with instruction generation and optimization for a specific architecture.
    * It interacts with `codegen`, which handles the final machine code generation.
    * It's related to `deoptimizer`, indicating involvement in the process of reverting from optimized code back to the interpreter.

6. **Identifying JavaScript Relevance:**  The core function of a JavaScript engine's compiler is to translate JavaScript code into efficient machine code. Therefore, everything in this file, even low-level details, ultimately contributes to how JavaScript code is executed.

    * **Instructions:** Directly correspond to the operations performed when executing JavaScript code.
    * **Operands:** Represent the values (variables, constants) manipulated in JavaScript.
    * **Control Flow:**  `InstructionBlock` reflects the branching and looping structures in JavaScript code.
    * **Function Calls and Deoptimization:** `FrameStateDescriptor` is essential for correctly handling JavaScript function calls and the process of deoptimizing code when assumptions become invalid.

7. **Generating JavaScript Examples:**  To illustrate the connection to JavaScript, I need to come up with simple JavaScript code snippets that would result in the concepts defined in the C++ file being used during compilation.

    * **Variables and Operations:**  Simple arithmetic or variable assignments demonstrate the need for instructions and operands.
    * **Control Flow:** `if/else` statements and loops show how `InstructionBlock` and branching are relevant.
    * **Function Calls:**  Calling a function illustrates the use of `FrameStateDescriptor`.
    * **Deoptimization:**  Examples of type changes or operations that can lead to deoptimization demonstrate the purpose of `FrameStateDescriptor` in that context.

8. **Structuring the Output:**  Finally, I organize the information into a clear and structured format:

    * A concise summary of the file's overall purpose.
    * Explanations of the key classes and their roles.
    * Direct connections to JavaScript functionality.
    * Concrete JavaScript examples for each key concept.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual methods within the classes. The request asks for the *functionality*, so I need to abstract and describe the high-level purpose of the classes.
*  I might have initially missed the significance of `FrameStateDescriptor`. Recognizing its connection to function calls and deoptimization is crucial for understanding its JavaScript relevance.
*  For the JavaScript examples, I need to ensure they are simple and directly illustrate the concept without introducing unnecessary complexity.

By following this thought process, which involves understanding the code structure, inferring relationships, connecting to the larger context of the V8 compiler, and then grounding it with concrete JavaScript examples, I can arrive at a comprehensive and accurate answer to the request.
这个C++源代码文件 `v8/src/compiler/backend/instruction.cc` 定义了在 V8 的 **TurboFan 编译器后端** 中用于表示和操作 **指令 (Instruction)** 的各种类和数据结构。 它的主要功能是：

**1. 定义指令和操作数的抽象表示:**

* **`Instruction` 类:**  代表一个单个的机器指令。它包含：
    * `opcode_`: 指令的操作码 (InstructionCode)。
    * 输入、输出和临时操作数 (`operands_`)：指向 `InstructionOperand` 对象的指针数组。
    * 并行移动 (`parallel_moves_`):  表示在指令执行前后需要进行的寄存器或栈槽之间的并行数据移动。这对于优化（例如寄存器分配）至关重要。
    * 引用映射 (`reference_map_`):  记录指令中哪些操作数是指向堆对象的指针，用于垃圾回收。
    * 所属基本块 (`block_`): 指向该指令所属的 `InstructionBlock`。

* **`InstructionOperand` 类:**  表示指令的操作数。这是一个抽象基类，有多个派生类，代表不同类型的操作数：
    * **`UnallocatedOperand`:** 表示尚未分配具体位置（寄存器或栈槽）的虚拟寄存器。
    * **`ConstantOperand`:** 表示常量值。
    * **`ImmediateOperand`:** 表示立即数（编译时已知的值）。
    * **`LocationOperand`:** 表示已分配的具体位置，可以是寄存器 (`RegisterOperand`, `DoubleRegisterOperand`, `FloatRegisterOperand`, `Simd128RegisterOperand`) 或栈槽 (`StackSlotOperand`, `FPStackSlotOperand`).
    * **`PendingOperand`:** 用于表示需要稍后处理的操作数。

* **`MoveOperands` 类:** 表示一个单独的数据移动操作，包含源操作数和目标操作数。

* **`ParallelMove` 类:**  表示一组需要同时执行的数据移动操作。

**2. 定义基本块 (Basic Block) 的表示:**

* **`InstructionBlock` 类:** 代表控制流图中的一个基本块。它包含：
    * RPO 编号 (`rpo_number_`): 逆后序遍历编号，用于排序。
    * 循环信息 (`loop_header_`, `loop_end_`): 指示该块是否属于循环。
    * 前驱和后继块 (`predecessors_`, `successors_`): 控制流关系。
    * Phi 指令列表 (`phis_`):  用于 SSA (Static Single Assignment) 形式的合并点。
    * 指令范围 (`code_start_`, `code_end_`):  该块包含的指令在 `InstructionSequence` 中的索引范围。

* **`PhiInstruction` 类:**  表示 SSA 形式的 Phi 指令，用于在控制流汇合点合并来自不同路径的值。

**3. 定义指令序列 (Instruction Sequence) 的表示和管理:**

* **`InstructionSequence` 类:**  代表一个函数或一段代码的指令序列。它包含：
    * 指令块列表 (`instruction_blocks_`):  所有基本块的集合。
    * 指令列表 (`instructions_`):  所有指令的有序列表。
    * 常量池 (`constants_`):  存储代码中使用的常量。
    * 立即数池 (`immediates_`): 存储代码中使用的立即数。
    * 虚拟寄存器计数器 (`next_virtual_register_`): 用于分配新的虚拟寄存器。
    * 引用映射列表 (`reference_maps_`):  存储所有指令的引用映射。
    * 类型信息 (`representations_`):  存储虚拟寄存器的类型信息。
    * 反优化入口点 (`deoptimization_entries_`):  用于处理反优化。

**4. 提供操作指令和操作数的工具函数:**

*  例如，`CommuteFlagsCondition` 用于交换比较标志的条件。
*  `InterferesWith` 用于判断两个操作数是否会相互干扰（例如，共享同一个寄存器）。
*  `IsCompatible` 用于判断两个操作数是否可以互相赋值。
*  `Print` 函数用于打印指令和相关信息，方便调试。

**5. 定义帧状态描述符 (Frame State Descriptor):**

* **`FrameStateDescriptor` 类:** 用于描述函数调用时的帧状态，包含参数、局部变量、栈大小等信息。这对于反优化和调试非常重要。

**它与 JavaScript 的功能有关系，因为它直接参与了 JavaScript 代码的编译和执行过程。** TurboFan 编译器将 JavaScript 代码转换为这种中间表示（指令序列和基本块），然后进行各种优化，最终生成机器码。

**JavaScript 举例说明:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  if (a > 10) {
    return a + b;
  } else {
    return a * b;
  }
}

let result = add(5, 7);
```

当 V8 的 TurboFan 编译器编译 `add` 函数时，`instruction.cc` 中定义的类和数据结构将会被使用，例如：

* **`InstructionBlock`:**  会创建多个 `InstructionBlock` 对象来表示 `if` 语句的不同分支（`a > 10` 为真和为假的情况）。
* **`Instruction`:**  会创建 `Instruction` 对象来表示加法 (`a + b`) 和乘法 (`a * b`) 操作，以及比较操作 (`a > 10`)。
* **`InstructionOperand`:**
    * `a` 和 `b` 会被表示为 `UnallocatedOperand`，在后续的寄存器分配阶段会被分配到具体的寄存器或栈槽。
    * `10` 会被表示为 `ImmediateOperand` 或 `ConstantOperand`。
* **`ParallelMove`:**  在函数调用 `add(5, 7)` 前后，可能需要使用 `ParallelMove` 来将参数传递到函数所需的寄存器中，并将返回值从函数返回的寄存器移动到变量 `result` 所在的内存位置。
* **`FrameStateDescriptor`:**  在调用 `add` 函数时，会创建一个 `FrameStateDescriptor` 对象来记录当前的函数调用栈状态，包括 `a` 和 `b` 的值，以及返回地址等信息。如果后续执行过程中需要进行反优化，这个信息会被用来恢复到解释器状态。

**更具体的指令示例 (伪代码，与实际生成的汇编代码略有不同):**

对于 `a + b`，可能会生成类似以下的指令：

```
// 假设 a 在寄存器 R1， b 在寄存器 R2
MOV R1, v1  // 将虚拟寄存器 v1 (代表 a) 的值移动到物理寄存器 R1
MOV R2, v2  // 将虚拟寄存器 v2 (代表 b) 的值移动到物理寄存器 R2
ADD R0, R1, R2 // 将 R1 和 R2 的值相加，结果存入 R0
MOV v3, R0  // 将 R0 的值移动到虚拟寄存器 v3 (代表 a + b 的结果)
```

对于 `if (a > 10)`，可能会生成类似以下的指令：

```
// 假设 a 在寄存器 R1
CMP R1, #10  // 将 R1 的值与立即数 10 进行比较
BLE label_else // 如果小于等于，则跳转到 label_else 分支
// ... then 分支的代码 ...
JMP label_end  // 跳转到结束标签
label_else:
// ... else 分支的代码 ...
label_end:
```

**总结:**

`v8/src/compiler/backend/instruction.cc` 文件是 V8 编译器后端的关键组成部分，它定义了表示和操作底层指令的核心数据结构。这些数据结构直接参与了将 JavaScript 代码转换为高效机器码的过程，并且与 JavaScript 的控制流、数据操作、函数调用和反优化等功能密切相关。理解这个文件的内容有助于深入了解 V8 编译器的内部工作原理。

Prompt: 
```
这是目录为v8/src/compiler/backend/instruction.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/backend/instruction.h"

#include <cstddef>
#include <iomanip>

#include "src/base/iterator.h"
#include "src/codegen/aligned-slot-allocator.h"
#include "src/codegen/interface-descriptors.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/register-configuration.h"
#include "src/codegen/source-position.h"
#include "src/compiler/backend/instruction-codes.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/frame-states.h"
#include "src/compiler/node.h"
#include "src/compiler/schedule.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/loop-finder.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/utils/ostreams.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/value-type.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

const RegisterConfiguration* (*GetRegConfig)() = RegisterConfiguration::Default;

FlagsCondition CommuteFlagsCondition(FlagsCondition condition) {
  switch (condition) {
    case kSignedLessThan:
      return kSignedGreaterThan;
    case kSignedGreaterThanOrEqual:
      return kSignedLessThanOrEqual;
    case kSignedLessThanOrEqual:
      return kSignedGreaterThanOrEqual;
    case kSignedGreaterThan:
      return kSignedLessThan;
    case kUnsignedLessThan:
      return kUnsignedGreaterThan;
    case kUnsignedGreaterThanOrEqual:
      return kUnsignedLessThanOrEqual;
    case kUnsignedLessThanOrEqual:
      return kUnsignedGreaterThanOrEqual;
    case kUnsignedGreaterThan:
      return kUnsignedLessThan;
    case kFloatLessThanOrUnordered:
      return kFloatGreaterThanOrUnordered;
    case kFloatGreaterThanOrEqual:
      return kFloatLessThanOrEqual;
    case kFloatLessThanOrEqual:
      return kFloatGreaterThanOrEqual;
    case kFloatGreaterThanOrUnordered:
      return kFloatLessThanOrUnordered;
    case kFloatLessThan:
      return kFloatGreaterThan;
    case kFloatGreaterThanOrEqualOrUnordered:
      return kFloatLessThanOrEqualOrUnordered;
    case kFloatLessThanOrEqualOrUnordered:
      return kFloatGreaterThanOrEqualOrUnordered;
    case kFloatGreaterThan:
      return kFloatLessThan;
    case kPositiveOrZero:
    case kNegative:
      UNREACHABLE();
    case kEqual:
    case kNotEqual:
    case kOverflow:
    case kNotOverflow:
    case kUnorderedEqual:
    case kUnorderedNotEqual:
    case kIsNaN:
    case kIsNotNaN:
      return condition;
  }
  UNREACHABLE();
}

bool InstructionOperand::InterferesWith(const InstructionOperand& other) const {
  const bool combine_fp_aliasing = kFPAliasing == AliasingKind::kCombine &&
                                   this->IsFPLocationOperand() &&
                                   other.IsFPLocationOperand();
  const bool stack_slots = this->IsAnyStackSlot() && other.IsAnyStackSlot();
  if (!combine_fp_aliasing && !stack_slots) {
    return EqualsCanonicalized(other);
  }
  const LocationOperand& loc = *LocationOperand::cast(this);
  const LocationOperand& other_loc = LocationOperand::cast(other);
  MachineRepresentation rep = loc.representation();
  MachineRepresentation other_rep = other_loc.representation();
  LocationOperand::LocationKind kind = loc.location_kind();
  LocationOperand::LocationKind other_kind = other_loc.location_kind();
  if (kind != other_kind) return false;

  if (combine_fp_aliasing && !stack_slots) {
    if (rep == other_rep) return EqualsCanonicalized(other);
    DCHECK_EQ(kind, LocationOperand::REGISTER);
    // FP register-register interference.
    return GetRegConfig()->AreAliases(rep, loc.register_code(), other_rep,
                                      other_loc.register_code());
  }

  DCHECK(stack_slots);
  int num_slots =
      AlignedSlotAllocator::NumSlotsForWidth(ElementSizeInBytes(rep));
  int num_slots_other =
      AlignedSlotAllocator::NumSlotsForWidth(ElementSizeInBytes(other_rep));
  const bool complex_stack_slot_interference =
      (num_slots > 1 || num_slots_other > 1);
  if (!complex_stack_slot_interference) {
    return EqualsCanonicalized(other);
  }

  // Complex multi-slot operand interference:
  // - slots of different FP reps can alias because the gap resolver may break a
  // move into 2 or 4 equivalent smaller moves,
  // - stack layout can be rearranged for tail calls
  DCHECK_EQ(LocationOperand::STACK_SLOT, kind);
  int index_hi = loc.index();
  int index_lo =
      index_hi -
      AlignedSlotAllocator::NumSlotsForWidth(ElementSizeInBytes(rep)) + 1;
  int other_index_hi = other_loc.index();
  int other_index_lo =
      other_index_hi -
      AlignedSlotAllocator::NumSlotsForWidth(ElementSizeInBytes(other_rep)) + 1;
  return other_index_hi >= index_lo && index_hi >= other_index_lo;
}

bool LocationOperand::IsCompatible(LocationOperand* op) {
  if (IsRegister() || IsStackSlot()) {
    return op->IsRegister() || op->IsStackSlot();
  } else if (kFPAliasing != AliasingKind::kCombine) {
    // A backend may choose to generate the same instruction sequence regardless
    // of the FP representation. As a result, we can relax the compatibility and
    // allow a Double to be moved in a Float for example. However, this is only
    // allowed if registers do not overlap.
    return (IsFPRegister() || IsFPStackSlot()) &&
           (op->IsFPRegister() || op->IsFPStackSlot());
  } else if (IsFloatRegister() || IsFloatStackSlot()) {
    return op->IsFloatRegister() || op->IsFloatStackSlot();
  } else if (IsDoubleRegister() || IsDoubleStackSlot()) {
    return op->IsDoubleRegister() || op->IsDoubleStackSlot();
  } else {
    return (IsSimd128Register() || IsSimd128StackSlot()) &&
           (op->IsSimd128Register() || op->IsSimd128StackSlot());
  }
}

void InstructionOperand::Print() const { StdoutStream{} << *this << std::endl; }

std::ostream& operator<<(std::ostream& os, const InstructionOperand& op) {
  switch (op.kind()) {
    case InstructionOperand::UNALLOCATED: {
      const UnallocatedOperand* unalloc = UnallocatedOperand::cast(&op);
      os << "v" << unalloc->virtual_register();
      if (unalloc->basic_policy() == UnallocatedOperand::FIXED_SLOT) {
        return os << "(=" << unalloc->fixed_slot_index() << "S)";
      }
      switch (unalloc->extended_policy()) {
        case UnallocatedOperand::NONE:
          return os;
        case UnallocatedOperand::FIXED_REGISTER:
          return os << "(="
                    << Register::from_code(unalloc->fixed_register_index())
                    << ")";
        case UnallocatedOperand::FIXED_FP_REGISTER:
          return os << "(="
                    << (unalloc->IsSimd128Register()
                            ? i::RegisterName((Simd128Register::from_code(
                                  unalloc->fixed_register_index())))
                            : i::RegisterName(DoubleRegister::from_code(
                                  unalloc->fixed_register_index())))
                    << ")";
        case UnallocatedOperand::MUST_HAVE_REGISTER:
          return os << "(R)";
        case UnallocatedOperand::MUST_HAVE_SLOT:
          return os << "(S)";
        case UnallocatedOperand::SAME_AS_INPUT:
          return os << "(" << unalloc->input_index() << ")";
        case UnallocatedOperand::REGISTER_OR_SLOT:
          return os << "(-)";
        case UnallocatedOperand::REGISTER_OR_SLOT_OR_CONSTANT:
          return os << "(*)";
      }
    }
    case InstructionOperand::CONSTANT:
      return os << "[constant:v" << ConstantOperand::cast(op).virtual_register()
                << "]";
    case InstructionOperand::IMMEDIATE: {
      ImmediateOperand imm = ImmediateOperand::cast(op);
      switch (imm.type()) {
        case ImmediateOperand::INLINE_INT32:
          return os << "#" << imm.inline_int32_value();
        case ImmediateOperand::INLINE_INT64:
          return os << "#" << imm.inline_int64_value();
        case ImmediateOperand::INDEXED_RPO:
          return os << "[rpo_immediate:" << imm.indexed_value() << "]";
        case ImmediateOperand::INDEXED_IMM:
          return os << "[immediate:" << imm.indexed_value() << "]";
      }
    }
    case InstructionOperand::PENDING:
      return os << "[pending: " << PendingOperand::cast(op).next() << "]";
    case InstructionOperand::ALLOCATED: {
      LocationOperand allocated = LocationOperand::cast(op);
      if (op.IsStackSlot()) {
        os << "[stack:" << allocated.index();
      } else if (op.IsFPStackSlot()) {
        os << "[fp_stack:" << allocated.index();
      } else if (op.IsRegister()) {
        const char* name =
            allocated.register_code() < Register::kNumRegisters
                ? RegisterName(Register::from_code(allocated.register_code()))
                : Register::GetSpecialRegisterName(allocated.register_code());
        os << "[" << name << "|R";
      } else if (op.IsDoubleRegister()) {
        os << "[" << DoubleRegister::from_code(allocated.register_code())
           << "|R";
      } else if (op.IsFloatRegister()) {
        os << "[" << FloatRegister::from_code(allocated.register_code())
           << "|R";
#if V8_TARGET_ARCH_X64
      } else if (op.IsSimd256Register()) {
        os << "[" << Simd256Register::from_code(allocated.register_code())
           << "|R";
#endif  // V8_TARGET_ARCH_X64
      } else {
        DCHECK(op.IsSimd128Register());
        os << "[" << Simd128Register::from_code(allocated.register_code())
           << "|R";
      }
      switch (allocated.representation()) {
        case MachineRepresentation::kNone:
          os << "|-";
          break;
        case MachineRepresentation::kBit:
          os << "|b";
          break;
        case MachineRepresentation::kWord8:
          os << "|w8";
          break;
        case MachineRepresentation::kWord16:
          os << "|w16";
          break;
        case MachineRepresentation::kWord32:
          os << "|w32";
          break;
        case MachineRepresentation::kWord64:
          os << "|w64";
          break;
        case MachineRepresentation::kFloat16:
          os << "|f16";
          break;
        case MachineRepresentation::kFloat32:
          os << "|f32";
          break;
        case MachineRepresentation::kFloat64:
          os << "|f64";
          break;
        case MachineRepresentation::kSimd128:
          os << "|s128";
          break;
        case MachineRepresentation::kSimd256:
          os << "|s256";
          break;
        case MachineRepresentation::kTaggedSigned:
          os << "|ts";
          break;
        case MachineRepresentation::kTaggedPointer:
          os << "|tp";
          break;
        case MachineRepresentation::kTagged:
          os << "|t";
          break;
        case MachineRepresentation::kCompressedPointer:
          os << "|cp";
          break;
        case MachineRepresentation::kCompressed:
          os << "|c";
          break;
        case MachineRepresentation::kProtectedPointer:
          os << "|pp";
          break;
        case MachineRepresentation::kIndirectPointer:
          os << "|ip";
          break;
        case MachineRepresentation::kSandboxedPointer:
          os << "|sb";
          break;
        case MachineRepresentation::kMapWord:
          UNREACHABLE();
      }
      return os << "]";
    }
    case InstructionOperand::INVALID:
      return os << "(x)";
  }
  UNREACHABLE();
}

void MoveOperands::Print() const {
  StdoutStream{} << destination() << " = " << source() << std::endl;
}

std::ostream& operator<<(std::ostream& os, const MoveOperands& mo) {
  os << mo.destination();
  if (!mo.source().Equals(mo.destination())) {
    os << " = " << mo.source();
  }
  return os;
}

bool ParallelMove::IsRedundant() const {
  for (MoveOperands* move : *this) {
    if (!move->IsRedundant()) return false;
  }
  return true;
}

void ParallelMove::PrepareInsertAfter(
    MoveOperands* move, ZoneVector<MoveOperands*>* to_eliminate) const {
  bool no_aliasing = kFPAliasing != AliasingKind::kCombine ||
                     !move->destination().IsFPLocationOperand();
  MoveOperands* replacement = nullptr;
  MoveOperands* eliminated = nullptr;
  for (MoveOperands* curr : *this) {
    if (curr->IsEliminated()) continue;
    if (curr->destination().EqualsCanonicalized(move->source())) {
      // We must replace move's source with curr's destination in order to
      // insert it into this ParallelMove.
      DCHECK(!replacement);
      replacement = curr;
      if (no_aliasing && eliminated != nullptr) break;
    } else if (curr->destination().InterferesWith(move->destination())) {
      // We can eliminate curr, since move overwrites at least a part of its
      // destination, implying its value is no longer live.
      eliminated = curr;
      to_eliminate->push_back(curr);
      if (no_aliasing && replacement != nullptr) break;
    }
  }
  if (replacement != nullptr) move->set_source(replacement->source());
}

bool ParallelMove::Equals(const ParallelMove& that) const {
  if (this->size() != that.size()) return false;
  for (size_t i = 0; i < this->size(); ++i) {
    if (!(*this)[i]->Equals(*that[i])) return false;
  }
  return true;
}

void ParallelMove::Eliminate() {
  for (MoveOperands* move : *this) {
    move->Eliminate();
  }
}

Instruction::Instruction(InstructionCode opcode)
    : opcode_(opcode),
      bit_field_(OutputCountField::encode(0) | InputCountField::encode(0) |
                 TempCountField::encode(0) | IsCallField::encode(false)),
      reference_map_(nullptr),
      block_(nullptr) {
  parallel_moves_[0] = nullptr;
  parallel_moves_[1] = nullptr;

  // PendingOperands are required to be 8 byte aligned.
  static_assert(offsetof(Instruction, operands_) % 8 == 0);
}

Instruction::Instruction(InstructionCode opcode, size_t output_count,
                         InstructionOperand* outputs, size_t input_count,
                         InstructionOperand* inputs, size_t temp_count,
                         InstructionOperand* temps)
    : opcode_(opcode),
      bit_field_(OutputCountField::encode(output_count) |
                 InputCountField::encode(input_count) |
                 TempCountField::encode(temp_count) |
                 IsCallField::encode(false)),
      reference_map_(nullptr),
      block_(nullptr) {
  parallel_moves_[0] = nullptr;
  parallel_moves_[1] = nullptr;
  size_t offset = 0;
  for (size_t i = 0; i < output_count; ++i) {
    DCHECK(!outputs[i].IsInvalid());
    operands_[offset++] = outputs[i];
  }
  for (size_t i = 0; i < input_count; ++i) {
    DCHECK(!inputs[i].IsInvalid());
    operands_[offset++] = inputs[i];
  }
  for (size_t i = 0; i < temp_count; ++i) {
    DCHECK(!temps[i].IsInvalid());
    operands_[offset++] = temps[i];
  }
}

bool Instruction::AreMovesRedundant() const {
  for (int i = Instruction::FIRST_GAP_POSITION;
       i <= Instruction::LAST_GAP_POSITION; i++) {
    if (parallel_moves_[i] != nullptr && !parallel_moves_[i]->IsRedundant()) {
      return false;
    }
  }
  return true;
}

void Instruction::Print() const { StdoutStream{} << *this << std::endl; }

std::ostream& operator<<(std::ostream& os, const ParallelMove& pm) {
  const char* delimiter = "";
  for (MoveOperands* move : pm) {
    if (move->IsEliminated()) continue;
    os << delimiter << *move;
    delimiter = "; ";
  }
  return os;
}

void ReferenceMap::RecordReference(const AllocatedOperand& op) {
  // Do not record arguments as pointers.
  if (op.IsStackSlot() && LocationOperand::cast(op).index() < 0) return;
  DCHECK(!op.IsFPRegister() && !op.IsFPStackSlot());
  reference_operands_.push_back(op);
}

std::ostream& operator<<(std::ostream& os, const ReferenceMap& pm) {
  os << "{";
  const char* separator = "";
  for (const InstructionOperand& op : pm.reference_operands_) {
    os << separator << op;
    separator = ";";
  }
  return os << "}";
}

std::ostream& operator<<(std::ostream& os, const ArchOpcode& ao) {
  switch (ao) {
#define CASE(Name) \
  case k##Name:    \
    return os << #Name;
    ARCH_OPCODE_LIST(CASE)
#undef CASE
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, const AddressingMode& am) {
  switch (am) {
    case kMode_None:
      return os;
#define CASE(Name)   \
  case kMode_##Name: \
    return os << #Name;
      TARGET_ADDRESSING_MODE_LIST(CASE)
#undef CASE
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, const FlagsMode& fm) {
  switch (fm) {
    case kFlags_none:
      return os;
    case kFlags_branch:
      return os << "branch";
    case kFlags_deoptimize:
      return os << "deoptimize";
    case kFlags_set:
      return os << "set";
    case kFlags_trap:
      return os << "trap";
    case kFlags_select:
      return os << "select";
    case kFlags_conditional_set:
      return os << "conditional set";
    case kFlags_conditional_branch:
      return os << "conditional branch";
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, const FlagsCondition& fc) {
  switch (fc) {
    case kEqual:
      return os << "equal";
    case kNotEqual:
      return os << "not equal";
    case kSignedLessThan:
      return os << "signed less than";
    case kSignedGreaterThanOrEqual:
      return os << "signed greater than or equal";
    case kSignedLessThanOrEqual:
      return os << "signed less than or equal";
    case kSignedGreaterThan:
      return os << "signed greater than";
    case kUnsignedLessThan:
      return os << "unsigned less than";
    case kUnsignedGreaterThanOrEqual:
      return os << "unsigned greater than or equal";
    case kUnsignedLessThanOrEqual:
      return os << "unsigned less than or equal";
    case kUnsignedGreaterThan:
      return os << "unsigned greater than";
    case kFloatLessThanOrUnordered:
      return os << "less than or unordered (FP)";
    case kFloatGreaterThanOrEqual:
      return os << "greater than or equal (FP)";
    case kFloatLessThanOrEqual:
      return os << "less than or equal (FP)";
    case kFloatGreaterThanOrUnordered:
      return os << "greater than or unordered (FP)";
    case kFloatLessThan:
      return os << "less than (FP)";
    case kFloatGreaterThanOrEqualOrUnordered:
      return os << "greater than, equal or unordered (FP)";
    case kFloatLessThanOrEqualOrUnordered:
      return os << "less than, equal or unordered (FP)";
    case kFloatGreaterThan:
      return os << "greater than (FP)";
    case kUnorderedEqual:
      return os << "unordered equal";
    case kUnorderedNotEqual:
      return os << "unordered not equal";
    case kOverflow:
      return os << "overflow";
    case kNotOverflow:
      return os << "not overflow";
    case kPositiveOrZero:
      return os << "positive or zero";
    case kNegative:
      return os << "negative";
    case kIsNaN:
      return os << "is nan";
    case kIsNotNaN:
      return os << "is not nan";
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, const Instruction& instr) {
  os << "gap ";
  for (int i = Instruction::FIRST_GAP_POSITION;
       i <= Instruction::LAST_GAP_POSITION; i++) {
    os << "(";
    if (instr.parallel_moves()[i] != nullptr) {
      os << *instr.parallel_moves()[i];
    }
    os << ") ";
  }
  os << "\n          ";

  if (instr.OutputCount() == 1) {
    os << *instr.OutputAt(0) << " = ";
  } else if (instr.OutputCount() > 1) {
    os << "(" << *instr.OutputAt(0);
    for (size_t i = 1; i < instr.OutputCount(); i++) {
      os << ", " << *instr.OutputAt(i);
    }
    os << ") = ";
  }

  os << ArchOpcodeField::decode(instr.opcode());
  AddressingMode am = AddressingModeField::decode(instr.opcode());
  if (am != kMode_None) {
    os << " : " << AddressingModeField::decode(instr.opcode());
  }
  FlagsMode fm = FlagsModeField::decode(instr.opcode());
  if (fm != kFlags_none) {
    os << " && " << fm << " if " << FlagsConditionField::decode(instr.opcode());
  }
  for (size_t i = 0; i < instr.InputCount(); i++) {
    os << " " << *instr.InputAt(i);
  }
  return os;
}

Constant::Constant(int32_t v) : type_(kInt32), value_(v) {}

Constant::Constant(RelocatablePtrConstantInfo info) {
  if (info.type() == RelocatablePtrConstantInfo::kInt32) {
    type_ = kInt32;
  } else if (info.type() == RelocatablePtrConstantInfo::kInt64) {
    type_ = kInt64;
  } else {
    UNREACHABLE();
  }
  value_ = info.value();
  rmode_ = info.rmode();
}

IndirectHandle<HeapObject> Constant::ToHeapObject() const {
  DCHECK(kHeapObject == type() || kCompressedHeapObject == type());
  IndirectHandle<HeapObject> value(
      reinterpret_cast<Address*>(static_cast<intptr_t>(value_)));
  return value;
}

IndirectHandle<Code> Constant::ToCode() const {
  DCHECK_EQ(kHeapObject, type());
  IndirectHandle<Code> value(
      reinterpret_cast<Address*>(static_cast<intptr_t>(value_)));
  DCHECK(IsCode(*value));
  return value;
}

std::ostream& operator<<(std::ostream& os, const Constant& constant) {
  switch (constant.type()) {
    case Constant::kInt32:
      return os << constant.ToInt32();
    case Constant::kInt64:
      return os << constant.ToInt64() << "l";
    case Constant::kFloat32:
      return os << constant.ToFloat32() << "f";
    case Constant::kFloat64:
      return os << constant.ToFloat64().value();
    case Constant::kExternalReference:
      return os << constant.ToExternalReference();
    case Constant::kHeapObject:  // Fall through.
    case Constant::kCompressedHeapObject:
      return os << Brief(*constant.ToHeapObject());
    case Constant::kRpoNumber:
      return os << "RPO" << constant.ToRpoNumber().ToInt();
  }
  UNREACHABLE();
}

PhiInstruction::PhiInstruction(Zone* zone, int virtual_register,
                               size_t input_count)
    : virtual_register_(virtual_register),
      output_(UnallocatedOperand(UnallocatedOperand::NONE, virtual_register)),
      operands_(input_count, InstructionOperand::kInvalidVirtualRegister,
                zone) {}

void PhiInstruction::SetInput(size_t offset, int virtual_register) {
  DCHECK_EQ(InstructionOperand::kInvalidVirtualRegister, operands_[offset]);
  operands_[offset] = virtual_register;
}

void PhiInstruction::RenameInput(size_t offset, int virtual_register) {
  DCHECK_NE(InstructionOperand::kInvalidVirtualRegister, operands_[offset]);
  operands_[offset] = virtual_register;
}

InstructionBlock::InstructionBlock(Zone* zone, RpoNumber rpo_number,
                                   RpoNumber loop_header, RpoNumber loop_end,
                                   RpoNumber dominator, bool deferred,
                                   bool handler)
    : successors_(zone),
      predecessors_(zone),
      phis_(zone),
      ao_number_(RpoNumber::Invalid()),
      rpo_number_(rpo_number),
      loop_header_(loop_header),
      loop_end_(loop_end),
      dominator_(dominator),
      deferred_(deferred),
      handler_(handler),
      switch_target_(false),
      code_target_alignment_(false),
      loop_header_alignment_(false),
      needs_frame_(false),
      must_construct_frame_(false),
      must_deconstruct_frame_(false),
      omitted_by_jump_threading_(false) {}

size_t InstructionBlock::PredecessorIndexOf(RpoNumber rpo_number) const {
  size_t j = 0;
  for (InstructionBlock::Predecessors::const_iterator i = predecessors_.begin();
       i != predecessors_.end(); ++i, ++j) {
    if (*i == rpo_number) break;
  }
  return j;
}

static RpoNumber GetRpo(const BasicBlock* block) {
  if (block == nullptr) return RpoNumber::Invalid();
  return RpoNumber::FromInt(block->rpo_number());
}

static RpoNumber GetRpo(const turboshaft::Block* block) {
  if (block == nullptr) return RpoNumber::Invalid();
  return RpoNumber::FromInt(block->index().id());
}

static RpoNumber GetLoopEndRpo(const BasicBlock* block) {
  if (!block->IsLoopHeader()) return RpoNumber::Invalid();
  return RpoNumber::FromInt(block->loop_end()->rpo_number());
}

static RpoNumber GetLoopEndRpo(const turboshaft::Block* block) {
  if (!block->IsLoop()) return RpoNumber::Invalid();
  // In Turbofan, the `block->loop_end()` refers to the first after (outside)
  // the loop. In the relevant use cases, we retrieve the backedge block by
  // subtracting one from the rpo_number, so for Turboshaft we "fake" this by
  // adding 1 to the backedge block's rpo_number.
  return RpoNumber::FromInt(GetRpo(block->LastPredecessor()).ToInt() + 1);
}

static InstructionBlock* InstructionBlockFor(Zone* zone,
                                             const BasicBlock* block) {
  bool is_handler =
      !block->empty() && block->front()->opcode() == IrOpcode::kIfException;
  InstructionBlock* instr_block = zone->New<InstructionBlock>(
      zone, GetRpo(block), GetRpo(block->loop_header()), GetLoopEndRpo(block),
      GetRpo(block->dominator()), block->deferred(), is_handler);
  // Map successors and precessors
  instr_block->successors().reserve(block->SuccessorCount());
  for (BasicBlock* successor : block->successors()) {
    instr_block->successors().push_back(GetRpo(successor));
  }
  instr_block->predecessors().reserve(block->PredecessorCount());
  for (BasicBlock* predecessor : block->predecessors()) {
    instr_block->predecessors().push_back(GetRpo(predecessor));
  }
  if (block->PredecessorCount() == 1 &&
      block->predecessors()[0]->control() == BasicBlock::Control::kSwitch) {
    instr_block->set_switch_target(true);
  }
  return instr_block;
}

static InstructionBlock* InstructionBlockFor(
    Zone* zone, const turboshaft::Graph& graph, const turboshaft::Block* block,
    const turboshaft::Block* loop_header) {
  bool is_handler =
      block->FirstOperation(graph).Is<turboshaft::CatchBlockBeginOp>();
  bool deferred = block->get_custom_data(
      turboshaft::Block::CustomDataKind::kDeferredInSchedule);
  InstructionBlock* instr_block = zone->New<InstructionBlock>(
      zone, GetRpo(block), GetRpo(loop_header), GetLoopEndRpo(block),
      GetRpo(block->GetDominator()), deferred, is_handler);
  if (block->PredecessorCount() == 1) {
    const turboshaft::Block* predecessor = block->LastPredecessor();
    if (V8_UNLIKELY(
            predecessor->LastOperation(graph).Is<turboshaft::SwitchOp>())) {
      instr_block->set_switch_target(true);
    }
  }
  // Map successors and predecessors.
  base::SmallVector<turboshaft::Block*, 4> succs =
      turboshaft::SuccessorBlocks(block->LastOperation(graph));
  instr_block->successors().reserve(succs.size());
  for (const turboshaft::Block* successor : succs) {
    instr_block->successors().push_back(GetRpo(successor));
  }
  instr_block->predecessors().reserve(block->PredecessorCount());
  for (const turboshaft::Block* predecessor = block->LastPredecessor();
       predecessor; predecessor = predecessor->NeighboringPredecessor()) {
    instr_block->predecessors().push_back(GetRpo(predecessor));
  }
  std::reverse(instr_block->predecessors().begin(),
               instr_block->predecessors().end());
  return instr_block;
}

std::ostream& operator<<(std::ostream& os,
                         const PrintableInstructionBlock& printable_block) {
  const InstructionBlock* block = printable_block.block_;
  const InstructionSequence* code = printable_block.code_;

  os << "B" << block->rpo_number();
  if (block->ao_number().IsValid()) {
    os << ": AO#" << block->ao_number();
  } else {
    os << ": AO#?";
  }
  if (block->IsDeferred()) os << " (deferred)";
  if (!block->needs_frame()) os << " (no frame)";
  if (block->must_construct_frame()) os << " (construct frame)";
  if (block->must_deconstruct_frame()) os << " (deconstruct frame)";
  if (block->IsLoopHeader()) {
    os << " loop blocks: [" << block->rpo_number() << ", " << block->loop_end()
       << ")";
  }
  os << "  instructions: [" << block->code_start() << ", " << block->code_end()
     << ")" << std::endl
     << " predecessors:";

  for (RpoNumber pred : block->predecessors()) {
    os << " B" << pred.ToInt();
  }
  os << std::endl;

  for (const PhiInstruction* phi : block->phis()) {
    os << "     phi: " << phi->output() << " =";
    for (int input : phi->operands()) {
      os << " v" << input;
    }
    os << std::endl;
  }

  for (int j = block->first_instruction_index();
       j <= block->last_instruction_index(); j++) {
    os << "   " << std::setw(5) << j << ": " << *code->InstructionAt(j)
       << std::endl;
  }

  os << " successors:";
  for (RpoNumber succ : block->successors()) {
    os << " B" << succ.ToInt();
  }
  os << std::endl;
  return os;
}

InstructionBlocks* InstructionSequence::InstructionBlocksFor(
    Zone* zone, const Schedule* schedule) {
  InstructionBlocks* blocks = zone->AllocateArray<InstructionBlocks>(1);
  new (blocks) InstructionBlocks(
      static_cast<int>(schedule->rpo_order()->size()), nullptr, zone);
  size_t rpo_number = 0;
  for (BasicBlockVector::const_iterator it = schedule->rpo_order()->begin();
       it != schedule->rpo_order()->end(); ++it, ++rpo_number) {
    DCHECK(!(*blocks)[rpo_number]);
    DCHECK_EQ(GetRpo(*it).ToSize(), rpo_number);
    (*blocks)[rpo_number] = InstructionBlockFor(zone, *it);
  }
  return blocks;
}

InstructionBlocks* InstructionSequence::InstructionBlocksFor(
    Zone* zone, const turboshaft::Graph& graph) {
  InstructionBlocks* blocks = zone->AllocateArray<InstructionBlocks>(1);
  new (blocks)
      InstructionBlocks(static_cast<int>(graph.block_count()), nullptr, zone);
  size_t rpo_number = 0;
  // TODO(dmercadier): currently, the LoopFinder is just used to compute loop
  // headers. Since it's somewhat expensive to compute this, we should also use
  // the LoopFinder to compute the special RPO (we would only need to run the
  // LoopFinder once to compute both the special RPO and the loop headers).
  turboshaft::LoopFinder loop_finder(zone, &graph);
  for (const turboshaft::Block& block : graph.blocks()) {
    DCHECK(!(*blocks)[rpo_number]);
    DCHECK_EQ(RpoNumber::FromInt(block.index().id()).ToSize(), rpo_number);
    (*blocks)[rpo_number] = InstructionBlockFor(
        zone, graph, &block, loop_finder.GetLoopHeader(&block));
    ++rpo_number;
  }
  return blocks;
}

void InstructionSequence::ValidateEdgeSplitForm() const {
  // Validate blocks are in edge-split form: no block with multiple successors
  // has an edge to a block (== a successor) with more than one predecessors.
  for (const InstructionBlock* block : instruction_blocks()) {
    if (block->SuccessorCount() > 1) {
      for (const RpoNumber& successor_id : block->successors()) {
        const InstructionBlock* successor = InstructionBlockAt(successor_id);
        // Expect precisely one predecessor: "block".
        CHECK(successor->PredecessorCount() == 1 &&
              successor->predecessors()[0] == block->rpo_number());
      }
    }
  }
}

void InstructionSequence::ValidateDeferredBlockExitPaths() const {
  // A deferred block with more than one successor must have all its successors
  // deferred.
  for (const InstructionBlock* block : instruction_blocks()) {
    if (!block->IsDeferred() || block->SuccessorCount() <= 1) continue;
    for (RpoNumber successor_id : block->successors()) {
      CHECK(InstructionBlockAt(successor_id)->IsDeferred());
    }
  }
}

void InstructionSequence::ValidateDeferredBlockEntryPaths() const {
  // If a deferred block has multiple predecessors, they have to
  // all be deferred. Otherwise, we can run into a situation where a range
  // that spills only in deferred blocks inserts its spill in the block, but
  // other ranges need moves inserted by ResolveControlFlow in the predecessors,
  // which may clobber the register of this range.
  for (const InstructionBlock* block : instruction_blocks()) {
    if (!block->IsDeferred() || block->PredecessorCount() <= 1) continue;
    for (RpoNumber predecessor_id : block->predecessors()) {
      CHECK(InstructionBlockAt(predecessor_id)->IsDeferred());
    }
  }
}

void InstructionSequence::ValidateSSA() const {
  // TODO(mtrofin): We could use a local zone here instead.
  BitVector definitions(VirtualRegisterCount(), zone());
  for (const Instruction* instruction : *this) {
    for (size_t i = 0; i < instruction->OutputCount(); ++i) {
      const InstructionOperand* output = instruction->OutputAt(i);
      int vreg = (output->IsConstant())
                     ? ConstantOperand::cast(output)->virtual_register()
                     : UnallocatedOperand::cast(output)->virtual_register();
      CHECK(!definitions.Contains(vreg));
      definitions.Add(vreg);
    }
  }
}

void InstructionSequence::ComputeAssemblyOrder() {
  int ao = 0;
  RpoNumber invalid = RpoNumber::Invalid();

  ao_blocks_ = zone()->AllocateArray<InstructionBlocks>(1);
  new (ao_blocks_) InstructionBlocks(zone());
  ao_blocks_->reserve(instruction_blocks_->size());

  // Place non-deferred blocks.
  for (InstructionBlock* const block : *instruction_blocks_) {
    DCHECK_NOT_NULL(block);
    if (block->IsDeferred()) continue;            // skip deferred blocks.
    if (block->ao_number() != invalid) continue;  // loop rotated.
    if (block->IsLoopHeader()) {
      bool header_align = true;
      if (v8_flags.turbo_loop_rotation) {
        // Perform loop rotation for non-deferred loops.
        InstructionBlock* loop_end =
            instruction_blocks_->at(block->loop_end().ToSize() - 1);
        if (loop_end->SuccessorCount() == 1 && /* ends with goto */
            loop_end != block /* not a degenerate infinite loop */) {
          // If the last block has an unconditional jump back to the header,
          // then move it to be in front of the header in the assembly order.
          DCHECK_EQ(block->rpo_number(), loop_end->successors()[0]);
          loop_end->set_ao_number(RpoNumber::FromInt(ao++));
          ao_blocks_->push_back(loop_end);
          // This block will be the new machine-level loop header, so align
          // this block instead of the loop header block.
          loop_end->set_loop_header_alignment(true);
          header_align = false;
        }
      }
      block->set_loop_header_alignment(header_align);
    }
    if (block->loop_header().IsValid() && block->IsSwitchTarget()) {
      block->set_code_target_alignment(true);
    }
    block->set_ao_number(RpoNumber::FromInt(ao++));
    ao_blocks_->push_back(block);
  }
  // Add all leftover (deferred) blocks.
  for (InstructionBlock* const block : *instruction_blocks_) {
    if (block->ao_number() == invalid) {
      block->set_ao_number(RpoNumber::FromInt(ao++));
      ao_blocks_->push_back(block);
    }
  }
  DCHECK_EQ(instruction_blocks_->size(), ao);
}

void InstructionSequence::RecomputeAssemblyOrderForTesting() {
  RpoNumber invalid = RpoNumber::Invalid();
  for (InstructionBlock* block : *instruction_blocks_) {
    block->set_ao_number(invalid);
  }
  ComputeAssemblyOrder();
}

InstructionSequence::InstructionSequence(Isolate* isolate,
                                         Zone* instruction_zone,
                                         InstructionBlocks* instruction_blocks)
    : isolate_(isolate),
      zone_(instruction_zone),
      instruction_blocks_(instruction_blocks),
      ao_blocks_(nullptr),
      // Pre-allocate the hash map of source positions based on the block count.
      // (The actual number of instructions is only known after instruction
      // selection, but should at least correlate with the block count.)
      source_positions_(zone(), instruction_blocks->size() * 2),
      // Avoid collisions for functions with 256 or less constant vregs.
      constants_(zone(), 256),
      immediates_(zone()),
      rpo_immediates_(instruction_blocks->size(), zone()),
      instructions_(zone()),
      next_virtual_register_(0),
      reference_maps_(zone()),
      representations_(zone()),
      representation_mask_(0),
      deoptimization_entries_(zone()),
      current_block_(nullptr) {
  ComputeAssemblyOrder();
}

int InstructionSequence::NextVirtualRegister() {
  int virtual_register = next_virtual_register_++;
  CHECK_NE(virtual_register, InstructionOperand::kInvalidVirtualRegister);
  return virtual_register;
}

Instruction* InstructionSequence::GetBlockStart(RpoNumber rpo) const {
  const InstructionBlock* block = InstructionBlockAt(rpo);
  return InstructionAt(block->code_start());
}

void InstructionSequence::StartBlock(RpoNumber rpo) {
  DCHECK_NULL(current_block_);
  current_block_ = InstructionBlockAt(rpo);
  int code_start = static_cast<int>(instructions_.size());
  current_block_->set_code_start(code_start);
}

void InstructionSequence::EndBlock(RpoNumber rpo) {
  int end = static_cast<int>(instructions_.size());
  DCHECK_EQ(current_block_->rpo_number(), rpo);
  CHECK(current_block_->code_start() >= 0 &&
        current_block_->code_start() < end);
  current_block_->set_code_end(end);
  current_block_ = nullptr;
}

int InstructionSequence::AddInstruction(Instruction* instr) {
  DCHECK_NOT_NULL(current_block_);
  int index = static_cast<int>(instructions_.size());
  instr->set_block(current_block_);
  instructions_.push_back(instr);
  if (instr->NeedsReferenceMap()) {
    DCHECK_NULL(instr->reference_map());
    ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
    reference_map->set_instruction_position(index);
    instr->set_reference_map(reference_map);
    reference_maps_.push_back(reference_map);
  }
  return index;
}

static MachineRepresentation FilterRepresentation(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kBit:
    case MachineRepresentation::kWord8:
    case MachineRepresentation::kWord16:
      return InstructionSequence::DefaultRepresentation();
    case MachineRepresentation::kFloat16:
      return MachineRepresentation::kFloat32;
    case MachineRepresentation::kWord32:
    case MachineRepresentation::kWord64:
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
    case MachineRepresentation::kFloat32:
    case MachineRepresentation::kFloat64:
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256:
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kSandboxedPointer:
      return rep;
    case MachineRepresentation::kNone:
    case MachineRepresentation::kMapWord:
    case MachineRepresentation::kIndirectPointer:
      UNREACHABLE();
  }
}

MachineRepresentation InstructionSequence::GetRepresentation(
    int virtual_register) const {
  DCHECK_LE(0, virtual_register);
  DCHECK_LT(virtual_register, VirtualRegisterCount());
  if (virtual_register >= static_cast<int>(representations_.size())) {
    return DefaultRepresentation();
  }
  return representations_[virtual_register];
}

void InstructionSequence::MarkAsRepresentation(MachineRepresentation rep,
                                               int virtual_register) {
  DCHECK_LE(0, virtual_register);
  DCHECK_LT(virtual_register, VirtualRegisterCount());
  if (virtual_register >= static_cast<int>(representations_.size())) {
    representations_.resize(VirtualRegisterCount(), DefaultRepresentation());
  }
  rep = FilterRepresentation(rep);
  DCHECK_IMPLIES(representations_[virtual_register] != rep,
                 representations_[virtual_register] == DefaultRepresentation());
  representations_[virtual_register] = rep;
  representation_mask_ |= RepresentationBit(rep);
}

int InstructionSequence::AddDeoptimizationEntry(
    FrameStateDescriptor* descriptor, DeoptimizeKind kind,
    DeoptimizeReason reason, NodeId node_id, FeedbackSource const& feedback) {
  int deoptimization_id = static_cast<int>(deoptimization_entries_.size());
  deoptimization_entries_.push_back(
      DeoptimizationEntry(descriptor, kind, reason, node_id, feedback));
  return deoptimization_id;
}

DeoptimizationEntry const& InstructionSequence::GetDeoptimizationEntry(
    int state_id) {
  return deoptimization_entries_[state_id];
}

RpoNumber InstructionSequence::InputRpo(Instruction* instr, size_t index) {
  InstructionOperand* operand = instr->InputAt(index);
  Constant constant =
      operand->IsImmediate()
          ? GetImmediate(ImmediateOperand::cast(operand))
          : GetConstant(ConstantOperand::cast(operand)->virtual_register());
  return constant.ToRpoNumber();
}

bool InstructionSequence::GetSourcePosition(const Instruction* instr,
                                            SourcePosition* result) const {
  auto it = source_positions_.find(instr);
  if (it == source_positions_.end()) return false;
  *result = it->second;
  return true;
}

void InstructionSequence::SetSourcePosition(const Instruction* instr,
                                            SourcePosition value) {
  source_positions_.insert(std::make_pair(instr, value));
}

void InstructionSequence::Print() const {
  StdoutStream{} << *this << std::endl;
}

void InstructionSequence::PrintBlock(int block_id) const {
  RpoNumber rpo = RpoNumber::FromInt(block_id);
  const InstructionBlock* block = InstructionBlockAt(rpo);
  CHECK(block->rpo_number() == rpo);
  StdoutStream{} << PrintableInstructionBlock{block, this} << std::endl;
}

const RegisterConfiguration*
    InstructionSequence::registerConfigurationForTesting_ = nullptr;

const RegisterConfiguration*
InstructionSequence::RegisterConfigurationForTesting() {
  DCHECK_NOT_NULL(registerConfigurationForTesting_);
  return registerConfigurationForTesting_;
}

void InstructionSequence::SetRegisterConfigurationForTesting(
    const RegisterConfiguration* regConfig) {
  registerConfigurationForTesting_ = regConfig;
  GetRegConfig = InstructionSequence::RegisterConfigurationForTesting;
}

namespace {

size_t GetConservativeFrameSizeInBytes(FrameStateType type,
                                       size_t parameters_count,
                                       size_t locals_count,
                                       BytecodeOffset bailout_id,
                                       uint32_t wasm_liftoff_frame_size) {
  switch (type) {
    case FrameStateType::kUnoptimizedFunction: {
      auto info = UnoptimizedFrameInfo::Conservative(
          static_cast<int>(parameters_count), static_cast<int>(locals_count));
      return info.frame_size_in_bytes();
    }
    case FrameStateType::kInlinedExtraArguments:
      // The inlined extra arguments frame state is only used in the deoptimizer
      // and does not occupy any extra space in the stack.
      // Check out the design doc:
      // https://docs.google.com/document/d/150wGaUREaZI6YWqOQFD5l2mWQXaPbbZjcAIJLOFrzMs/edit
      // We just need to account for the additional parameters we might push
      // here.
      return UnoptimizedFrameInfo::GetStackSizeForAdditionalArguments(
          static_cast<int>(parameters_count));
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kWasmInlinedIntoJS:
#endif
    case FrameStateType::kConstructCreateStub: {
      auto info = ConstructStubFrameInfo::Conservative(
          static_cast<int>(parameters_count));
      return info.frame_size_in_bytes();
    }
    case FrameStateType::kConstructInvokeStub:
      return FastConstructStubFrameInfo::Conservative().frame_size_in_bytes();
    case FrameStateType::kBuiltinContinuation:
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kJSToWasmBuiltinContinuation:
#endif  // V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kJavaScriptBuiltinContinuation:
    case FrameStateType::kJavaScriptBuiltinContinuationWithCatch: {
      const RegisterConfiguration* config = RegisterConfiguration::Default();
      auto info = BuiltinContinuationFrameInfo::Conservative(
          static_cast<int>(parameters_count),
          Builtins::CallInterfaceDescriptorFor(
              Builtins::GetBuiltinFromBytecodeOffset(bailout_id)),
          config);
      return info.frame_size_in_bytes();
    }
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kLiftoffFunction:
      return wasm_liftoff_frame_size;
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  UNREACHABLE();
}

size_t GetTotalConservativeFrameSizeInBytes(FrameStateType type,
                                            size_t parameters_count,
                                            size_t locals_count,
                                            BytecodeOffset bailout_id,
                                            uint32_t wasm_liftoff_frame_size,
                                            FrameStateDescriptor* outer_state) {
  size_t outer_total_conservative_frame_size_in_bytes =
      (outer_state == nullptr)
          ? 0
          : outer_state->total_conservative_frame_size_in_bytes();
  return GetConservativeFrameSizeInBytes(type, parameters_count, locals_count,
                                         bailout_id, wasm_liftoff_frame_size) +
         outer_total_conservative_frame_size_in_bytes;
}

}  // namespace

FrameStateDescriptor::FrameStateDescriptor(
    Zone* zone, FrameStateType type, BytecodeOffset bailout_id,
    OutputFrameStateCombine state_combine, uint16_t parameters_count,
    uint16_t max_arguments, size_t locals_count, size_t stack_count,
    MaybeIndirectHandle<SharedFunctionInfo> shared_info,
    MaybeIndirectHandle<BytecodeArray> bytecode_aray,
    FrameStateDescriptor* outer_state, uint32_t wasm_liftoff_frame_size,
    uint32_t wasm_function_index)
    : type_(type),
      bailout_id_(bailout_id),
      frame_state_combine_(state_combine),
      parameters_count_(parameters_count),
      max_arguments_(max_arguments),
      locals_count_(locals_count),
      stack_count_(stack_count),
      total_conservative_frame_size_in_bytes_(
          GetTotalConservativeFrameSizeInBytes(
              type, parameters_count, locals_count, bailout_id,
              wasm_liftoff_frame_size, outer_state)),
      values_(zone),
      shared_info_(shared_info),
      bytecode_array_(bytecode_aray),
      outer_state_(outer_state),
      wasm_function_index_(wasm_function_index) {}

size_t FrameStateDescriptor::GetHeight() const {
  switch (type()) {
    case FrameStateType::kUnoptimizedFunction:
      return locals_count();  // The accumulator is *not* included.
    case FrameStateType::kBuiltinContinuation:
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kJSToWasmBuiltinContinuation:
    case FrameStateType::kWasmInlinedIntoJS:
#endif
      // Custom, non-JS calling convention (that does not have a notion of
      // a receiver or context).
      return parameters_count();
    case FrameStateType::kInlinedExtraArguments:
    case FrameStateType::kConstructCreateStub:
    case FrameStateType::kConstructInvokeStub:
    case FrameStateType::kJavaScriptBuiltinContinuation:
    case FrameStateType::kJavaScriptBuiltinContinuationWithCatch:
      // JS linkage. The parameters count
      // - includes the receiver (input 1 in CreateArtificialFrameState, and
      //   passed as part of stack parameters to
      //   CreateJavaScriptBuiltinContinuationFrameState), and
      // - does *not* include the context.
      return parameters_count();
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kLiftoffFunction:
      return locals_count() + parameters_count();
#endif
  }
  UNREACHABLE();
}

size_t FrameStateDescriptor::GetSize() const {
  return (HasClosure() ? 1 : 0) + parameters_count() + locals_count() +
         stack_count() + (HasContext() ? 1 : 0);
}

size_t FrameStateDescriptor::GetTotalSize() const {
  size_t total_size = 0;
  for (const FrameStateDescriptor* iter = this; iter != nullptr;
       iter = iter->outer_state_) {
    total_size += iter->GetSize();
  }
  return total_size;
}

size_t FrameStateDescriptor::GetFrameCount() const {
  size_t count = 0;
  for (const FrameStateDescriptor* iter = this; iter != nullptr;
       iter = iter->outer_state_) {
    ++count;
  }
  return count;
}

size_t FrameStateDescriptor::GetJSFrameCount() const {
  size_t count = 0;
  for (const FrameStateDescriptor* iter = this; iter != nullptr;
       iter = iter->outer_state_) {
    if (FrameStateFunctionInfo::IsJSFunctionType(iter->type_)) {
      ++count;
    }
  }
  return count;
}

#if V8_ENABLE_WEBASSEMBLY
JSToWasmFrameStateDescriptor::JSToWasmFrameStateDescriptor(
    Zone* zone, FrameStateType type, BytecodeOffset bailout_id,
    OutputFrameStateCombine state_combine, uint16_t parameters_count,
    size_t locals_count, size_t stack_count,
    MaybeIndirectHandle<SharedFunctionInfo> shared_info,
    FrameStateDescriptor* outer_state, const wasm::CanonicalSig* wasm_signature)
    : FrameStateDescriptor(zone, type, bailout_id, state_combine,
                           parameters_count, 0, locals_count, stack_count,
                           shared_info, {}, outer_state),
      return_kind_(wasm::WasmReturnTypeFromSignature(wasm_signature)) {}
#endif  // V8_ENABLE_WEBASSEMBLY

std::ostream& operator<<(std::ostream& os, const RpoNumber& rpo) {
  return os << rpo.ToSize();
}

std::ostream& operator<<(std::ostream& os, const InstructionSequence& code) {
  for (size_t i = 0; i < code.immediates_.size(); ++i) {
    Constant constant = code.immediates_[i];
    os << "IMM#" << i << ": " << constant << "\n";
  }
  int n = 0;
  for (ConstantMap::const_iterator it = code.constants_.begin();
       it != code.constants_.end(); ++n, ++it) {
    os << "CST#" << n << ": v" << it->first << " = " << it->second << "\n";
  }
  for (int i = 0; i < code.InstructionBlockCount(); i++) {
    auto* block = code.InstructionBlockAt(RpoNumber::FromInt(i));
    os << PrintableInstructionBlock{block, &code};
  }
  return os;
}

std::ostream& operator<<(std::ostream& os, StateValueKind kind) {
  switch (kind) {
    case StateValueKind::kArgumentsElements:
      return os << "ArgumentsElements";
    case StateValueKind::kArgumentsLength:
      return os << "ArgumentsLength";
    case StateValueKind::kRestLength:
      return os << "RestLength";
    case StateValueKind::kPlain:
      return os << "Plain";
    case StateValueKind::kOptimizedOut:
      return os << "OptimizedOut";
    case StateValueKind::kNestedObject:
      return os << "NestedObject";
    case StateValueKind::kDuplicate:
      return os << "Duplicate";
    case StateValueKind::kStringConcat:
      return os << "StringConcat";
  }
}

void StateValueDescriptor::Print(std::ostream& os) const {
  os << "kind=" << kind_ << ", type=" << type_;
  if (kind_ == StateValueKind::kDuplicate ||
      kind_ == StateValueKind::kNestedObject) {
    os << ", id=" << id_;
  } else if (kind_ == StateValueKind::kArgumentsElements) {
    os << ", args_type=" << args_type_;
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```