Response:
My thinking process to summarize the provided C++ code snippet goes like this:

1. **Identify the Core Subject:** The code is located in `v8/src/maglev/maglev-code-generator.cc`. The filename itself strongly suggests its primary function: generating machine code for the Maglev compiler in V8.

2. **Scan for Key Data Structures and Classes:**  I look for prominent classes and structs. The most obvious are:
    * `ParallelMoveResolver`: This immediately jumps out as a complex piece of logic dealing with moving data between registers and memory efficiently. The comments explain its purpose – handling parallel moves and resolving potential conflicts.
    * `ExceptionHandlerTrampolineBuilder`:  This class clearly deals with generating code for handling exceptions in Maglev-compiled code. The term "trampoline" hints at a small piece of code that redirects execution.
    * `MaglevCodeGeneratingNodeProcessor`: This looks like the main driver for the code generation process, iterating through nodes in a graph.

3. **Analyze `ParallelMoveResolver`:**  I focus on understanding *what* this class does, not necessarily *how* it does it in detail at this stage. The core idea is resolving simultaneous moves to avoid clobbering data. The example provided in the comments helps solidify this understanding. Keywords like "move graph," "clobbering order," and "cycles" are important.

4. **Analyze `ExceptionHandlerTrampolineBuilder`:**  The name and the comments provide clear clues. It sets up code that runs when an exception occurs. It needs to move data (phi values) to the correct locations for the catch block to function. The mention of "materialisation" suggests dealing with values that need to be computed or created on the fly.

5. **Analyze `MaglevCodeGeneratingNodeProcessor`:**  This class seems responsible for the overall flow of code generation. The methods `PreProcessGraph`, `PostProcessGraph`, `PreProcessBasicBlock`, and `Process` strongly indicate a graph-based processing approach, where the compiler iterates through the nodes of an intermediate representation (the Maglev graph). The code within `PreProcessGraph` regarding deferred blocks and reordering is important to note.

6. **Connect to Broader Concepts:** I relate these classes to general compiler concepts. `ParallelMoveResolver` is an optimization technique in register allocation and code generation. `ExceptionHandlerTrampolineBuilder` is essential for robust exception handling. `MaglevCodeGeneratingNodeProcessor` embodies the core logic of traversing the IR and emitting corresponding machine code.

7. **Address the Specific Questions:** Now, I go through the questions in the prompt:
    * **Functionality:**  Based on the class analysis, the main function is generating machine code for the Maglev compiler, with specific focus on handling parallel moves and exceptions.
    * **.tq extension:** The code is `.cc`, so it's C++, not Torque.
    * **Relationship to JavaScript:**  Since Maglev is a V8 component, it compiles JavaScript. The generated code will directly execute JavaScript functionality. However, providing a specific JavaScript example that *directly* maps to this *internal* code is difficult and not the focus of this summary. It's more about the *process* of compilation.
    * **Code logic inference:** The `ParallelMoveResolver` provides a good example of logic. I can describe the input (a set of moves) and the output (a reordered sequence of moves that avoids conflicts). The cycle detection and temporary variable usage are key aspects.
    * **Common programming errors:**  The `ParallelMoveResolver` helps *avoid* errors in the *generated* code related to register clobbering. I can explain the problem of simultaneous moves overwriting each other and how this resolver prevents it.
    * **Summary of Functionality:**  Finally, I synthesize the information into a concise summary, highlighting the key responsibilities of the `maglev-code-generator.cc` file.

8. **Refine and Organize:** I review my notes and structure the summary logically, starting with the main purpose and then delving into the key components and their functions. I ensure the language is clear and avoids overly technical jargon where possible, while still being accurate.
好的，根据你提供的代码片段，以下是对 `v8/src/maglev/maglev-code-generator.cc` 功能的归纳：

**主要功能:**

`v8/src/maglev/maglev-code-generator.cc` 文件的主要功能是 **将 Maglev 中间表示（IR）转换为目标机器码**。它是 V8 引擎中 Maglev 编译器的核心组成部分，负责实际的代码生成过程。

**具体功能点:**

1. **代码生成框架:**  它定义了代码生成的整体流程和结构，例如 `MaglevCodeGeneratingNodeProcessor` 类，负责遍历 Maglev 图并为每个节点生成相应的机器码。

2. **寄存器分配和管理:**  虽然代码片段中没有直接展示复杂的寄存器分配算法，但可以看到它使用了 `MaglevAssembler` 来操作寄存器，并且定义了可分配的寄存器列表 (`kAllocatableRegisters`, `kAllocatableDoubleRegisters`)，这表明它参与了寄存器的管理。

3. **并行移动解析 (ParallelMoveResolver):**  这是一个关键的优化组件，用于安全有效地执行多个寄存器和栈槽之间的并行数据移动。它可以检测并解决移动操作之间的冲突（例如，一个寄存器的值被另一个移动覆盖）。

4. **异常处理跳转表构建 (ExceptionHandlerTrampolineBuilder):**  负责生成在发生异常时跳转到的代码片段。这个跳转表需要将异常发生时的程序状态正确地传递给异常处理代码。

5. **图的预处理和后处理:**  `PreProcessGraph` 函数执行一些图的优化和准备工作，例如计算延迟块、重新排序块、处理 OSR (On-Stack Replacement) 等。`PostProcessGraph` 函数则执行一些清理或最终化操作。

6. **基本块处理:** `PreProcessBasicBlock` 函数处理代码块级别的操作，例如绑定块标签、添加代码注释等。

7. **节点处理:** `Process` 函数是核心的代码生成逻辑，它针对 Maglev 图中的每个节点类型，调用相应的代码生成函数来生成机器码。

8. **栈帧管理:** 代码中涉及到栈槽的分配和访问，例如 `masm()->GetFramePointerOffsetForStackSlot()`，这表明它负责管理 Maglev 函数的栈帧布局。

9. **调试支持:** 代码中包含一些调试相关的代码，例如 `v8_flags.maglev_break_on_entry` 和 `v8_flags.code_comments`，可以在开发和调试阶段提供帮助。

**关于 .tq 扩展名:**

你提供的代码片段以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 Torque 源代码文件。如果文件以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。 Torque 是一种 V8 内部使用的领域特定语言，用于生成一些底层的 C++ 代码，通常用于实现内置函数或运行时功能。

**与 JavaScript 功能的关系:**

`v8/src/maglev/maglev-code-generator.cc` 直接负责将 JavaScript 代码（经过 Maglev 编译器的处理）转换为可执行的机器码。  它生成的代码直接实现了 JavaScript 的各种功能，例如：

* **变量访问和赋值:**  生成的机器码会负责将 JavaScript 变量的值加载到寄存器或从寄存器存储到内存。
* **函数调用:**  生成的机器码会设置调用栈，传递参数，并跳转到被调用函数的入口点。
* **算术和逻辑运算:**  生成的机器码会执行 JavaScript 中的加减乘除、比较、逻辑与或非等操作。
* **对象和属性操作:**  生成的机器码会负责访问和修改 JavaScript 对象的属性。
* **控制流 (if/else, loops):** 生成的机器码会实现 JavaScript 中的条件分支和循环结构。
* **异常处理 (try/catch):**  `ExceptionHandlerTrampolineBuilder` 生成的代码就是为了处理 JavaScript 中的 `try...catch` 语句。

**JavaScript 示例 (概念性):**

虽然无法直接用一个简单的 JavaScript 例子精确对应到 `maglev-code-generator.cc` 的内部实现，但可以理解为，当你执行以下 JavaScript 代码时：

```javascript
function add(a, b) {
  return a + b;
}

let x = 5;
let y = 10;
let sum = add(x, y);
console.log(sum);
```

Maglev 编译器，包括 `maglev-code-generator.cc`，会生成类似于以下的机器码 (概念性且高度简化)：

```assembly
// 函数 add
add_entry:
  // 将参数 a 加载到寄存器 R1
  load R1, [栈地址_a]
  // 将参数 b 加载到寄存器 R2
  load R2, [栈地址_b]
  // 执行加法 R1 = R1 + R2
  add R1, R2
  // 将结果存储到返回值寄存器
  mov 返回值寄存器, R1
  // 返回
  ret

// 主程序
main:
  // 将常量 5 赋值给变量 x
  mov [栈地址_x], 5
  // 将常量 10 赋值给变量 y
  mov [栈地址_y], 10
  // 调用函数 add，传递参数 x 和 y
  push [栈地址_x] // 推入参数
  push [栈地址_y]
  call add_entry
  // 将返回值存储到变量 sum
  mov [栈地址_sum], 返回值寄存器
  // 调用 console.log，传递参数 sum
  push [栈地址_sum]
  call console_log_entry
  // ...
```

**代码逻辑推理 (假设输入与输出):**

考虑 `ParallelMoveResolver`，假设我们有以下需要并行执行的移动操作（用伪代码表示）：

**假设输入:**

```
move r1 -> r2
move r2 -> r3
move r3 -> r1
```

**代码逻辑推理:**

`ParallelMoveResolver` 会检测到这是一个循环依赖，直接按照顺序执行会导致数据丢失。它会引入一个临时寄存器来打破循环。

**可能的输出 (机器码):**

```assembly
  // 使用临时寄存器 tmp
  mov tmp, r1   // r1 -> tmp
  mov r3, r2   // r2 -> r3
  mov r1, r3   // r3 -> r1
  mov r2, tmp   // tmp -> r2
```

**用户常见的编程错误:**

虽然 `maglev-code-generator.cc` 是编译器内部代码，但它生成的代码的质量和正确性直接影响到用户编写的 JavaScript 代码的执行。  用户常见的编程错误，例如：

* **类型错误:**  例如，尝试将一个字符串当作数字进行算术运算。Maglev 生成的代码可能需要进行类型检查，并在类型不匹配时抛出错误或进行类型转换。
* **未定义变量:**  访问未声明或未初始化的变量会导致运行时错误。Maglev 生成的代码需要能够检测到这种情况。
* **逻辑错误:**  例如，无限循环或错误的条件判断。Maglev 生成的代码会忠实地执行这些逻辑，导致程序行为不符合预期。
* **性能问题:**  虽然不是错误，但编写低效的 JavaScript 代码会导致 Maglev 生成效率较低的机器码。

**总结:**

`v8/src/maglev/maglev-code-generator.cc` 是 Maglev 编译器的核心，负责将高级的中间表示转换为底层的机器码，从而驱动 JavaScript 代码的执行。它包含了复杂的逻辑来处理寄存器分配、并行移动优化、异常处理等关键任务。虽然用户不会直接与此文件交互，但它的功能对于 V8 引擎的性能和正确性至关重要。

### 提示词
```
这是目录为v8/src/maglev/maglev-code-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-code-generator.cc以.tq结尾，那它是个v8 torque源代码，
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

#include "src/maglev/maglev-code-generator.h"

#include <algorithm>

#include "src/base/hashmap.h"
#include "src/base/logging.h"
#include "src/codegen/code-desc.h"
#include "src/codegen/compiler.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/interface-descriptors.h"
#include "src/codegen/register.h"
#include "src/codegen/reglist.h"
#include "src/codegen/safepoint-table.h"
#include "src/codegen/source-position.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/deoptimizer/frame-translation-builder.h"
#include "src/execution/frame-constants.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles-inl.h"
#include "src/interpreter/bytecode-register.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-code-gen-state.h"
#include "src/maglev/maglev-compilation-unit.h"
#include "src/maglev/maglev-graph-labeller.h"
#include "src/maglev/maglev-graph-printer.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-regalloc-data.h"
#include "src/objects/code-inl.h"
#include "src/objects/deoptimization-data.h"
#include "src/utils/identity-map.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm()->

namespace {

template <typename RegisterT>
struct RegisterTHelper;
template <>
struct RegisterTHelper<Register> {
  static constexpr RegList kAllocatableRegisters =
      MaglevAssembler::GetAllocatableRegisters();
};
template <>
struct RegisterTHelper<DoubleRegister> {
  static constexpr DoubleRegList kAllocatableRegisters =
      MaglevAssembler::GetAllocatableDoubleRegisters();
};

enum NeedsDecompression { kDoesNotNeedDecompression, kNeedsDecompression };

// The ParallelMoveResolver is used to resolve multiple moves between registers
// and stack slots that are intended to happen, semantically, in parallel. It
// finds chains of moves that would clobber each other, and emits them in a non
// clobbering order; it also detects cycles of moves and breaks them by moving
// to a temporary.
//
// For example, given the moves:
//
//     r1 -> r2
//     r2 -> r3
//     r3 -> r4
//     r4 -> r1
//     r4 -> r5
//
// These can be represented as a move graph
//
//     r2 → r3
//     ↑     ↓
//     r1 ← r4 → r5
//
// and safely emitted (breaking the cycle with a temporary) as
//
//     r1 -> tmp
//     r4 -> r1
//     r4 -> r5
//     r3 -> r4
//     r2 -> r3
//    tmp -> r2
//
// It additionally keeps track of materialising moves, which don't have a stack
// slot but rather materialise a value from, e.g., a constant. These can safely
// be emitted at the end, once all the parallel moves are done.
template <typename RegisterT, bool DecompressIfNeeded>
class ParallelMoveResolver {
  static constexpr auto kAllocatableRegistersT =
      RegisterTHelper<RegisterT>::kAllocatableRegisters;
  static_assert(!DecompressIfNeeded || std::is_same_v<Register, RegisterT>);
  static_assert(!DecompressIfNeeded || COMPRESS_POINTERS_BOOL);

 public:
  explicit ParallelMoveResolver(MaglevAssembler* masm)
      : masm_(masm), scratch_(RegisterT::no_reg()) {}

  void RecordMove(ValueNode* source_node, compiler::InstructionOperand source,
                  compiler::AllocatedOperand target,
                  bool target_needs_to_be_decompressed) {
    if (target.IsAnyRegister()) {
      RecordMoveToRegister(source_node, source, ToRegisterT<RegisterT>(target),
                           target_needs_to_be_decompressed);
    } else {
      RecordMoveToStackSlot(source_node, source,
                            masm_->GetFramePointerOffsetForStackSlot(target),
                            target_needs_to_be_decompressed);
    }
  }

  void RecordMove(ValueNode* source_node, compiler::InstructionOperand source,
                  RegisterT target_reg,
                  NeedsDecompression target_needs_to_be_decompressed) {
    RecordMoveToRegister(source_node, source, target_reg,
                         target_needs_to_be_decompressed);
  }

  void EmitMoves(RegisterT scratch) {
    DCHECK(!scratch_.is_valid());
    scratch_ = scratch;
    for (RegisterT reg : kAllocatableRegistersT) {
      StartEmitMoveChain(reg);
      ValueNode* materializing_register_move =
          materializing_register_moves_[reg.code()];
      if (materializing_register_move) {
        materializing_register_move->LoadToRegister(masm_, reg);
      }
    }
    // Emit stack moves until the move set is empty -- each EmitMoveChain will
    // pop entries off the moves_from_stack_slot map so we can't use a simple
    // iteration here.
    while (!moves_from_stack_slot_.empty()) {
      StartEmitMoveChain(moves_from_stack_slot_.begin()->first);
    }
    for (auto [stack_slot, node] : materializing_stack_slot_moves_) {
      node->LoadToRegister(masm_, scratch_);
      __ Move(StackSlot{stack_slot}, scratch_);
    }
  }

  ParallelMoveResolver(ParallelMoveResolver&&) = delete;
  ParallelMoveResolver operator=(ParallelMoveResolver&&) = delete;
  ParallelMoveResolver(const ParallelMoveResolver&) = delete;
  ParallelMoveResolver operator=(const ParallelMoveResolver&) = delete;

 private:
  // For the GapMoveTargets::needs_decompression member when DecompressIfNeeded
  // is false.
  struct DummyNeedsDecompression {
    // NOLINTNEXTLINE
    DummyNeedsDecompression(NeedsDecompression) {}
  };

  // The targets of moves from a source, i.e. the set of outgoing edges for
  // a node in the move graph.
  struct GapMoveTargets {
    base::SmallVector<int32_t, 1> stack_slots = base::SmallVector<int32_t, 1>{};
    RegListBase<RegisterT> registers;

    // We only need this field for DecompressIfNeeded, otherwise use an empty
    // dummy value.
    V8_NO_UNIQUE_ADDRESS
    std::conditional_t<DecompressIfNeeded, NeedsDecompression,
                       DummyNeedsDecompression>
        needs_decompression = kDoesNotNeedDecompression;

    GapMoveTargets() = default;
    GapMoveTargets(GapMoveTargets&&) V8_NOEXCEPT = default;
    GapMoveTargets& operator=(GapMoveTargets&&) V8_NOEXCEPT = default;
    GapMoveTargets(const GapMoveTargets&) = delete;
    GapMoveTargets& operator=(const GapMoveTargets&) = delete;

    bool is_empty() const {
      return registers.is_empty() && stack_slots.empty();
    }
  };

#ifdef DEBUG
  void CheckNoExistingMoveToRegister(RegisterT target_reg) {
    for (RegisterT reg : kAllocatableRegistersT) {
      if (moves_from_register_[reg.code()].registers.has(target_reg)) {
        FATAL("Existing move from %s to %s", RegisterName(reg),
              RegisterName(target_reg));
      }
    }
    for (auto& [stack_slot, targets] : moves_from_stack_slot_) {
      if (targets.registers.has(target_reg)) {
        FATAL("Existing move from stack slot %d to %s", stack_slot,
              RegisterName(target_reg));
      }
    }
    if (materializing_register_moves_[target_reg.code()] != nullptr) {
      FATAL("Existing materialization of %p to %s",
            materializing_register_moves_[target_reg.code()],
            RegisterName(target_reg));
    }
  }

  void CheckNoExistingMoveToStackSlot(int32_t target_slot) {
    for (RegisterT reg : kAllocatableRegistersT) {
      auto& stack_slots = moves_from_register_[reg.code()].stack_slots;
      if (std::any_of(stack_slots.begin(), stack_slots.end(),
                      [&](int32_t slot) { return slot == target_slot; })) {
        FATAL("Existing move from %s to stack slot %d", RegisterName(reg),
              target_slot);
      }
    }
    for (auto& [stack_slot, targets] : moves_from_stack_slot_) {
      auto& stack_slots = targets.stack_slots;
      if (std::any_of(stack_slots.begin(), stack_slots.end(),
                      [&](int32_t slot) { return slot == target_slot; })) {
        FATAL("Existing move from stack slot %d to stack slot %d", stack_slot,
              target_slot);
      }
    }
    for (auto& [stack_slot, node] : materializing_stack_slot_moves_) {
      if (stack_slot == target_slot) {
        FATAL("Existing materialization of %p to stack slot %d", node,
              stack_slot);
      }
    }
  }
#else
  void CheckNoExistingMoveToRegister(RegisterT target_reg) {}
  void CheckNoExistingMoveToStackSlot(int32_t target_slot) {}
#endif

  void RecordMoveToRegister(ValueNode* node,
                            compiler::InstructionOperand source,
                            RegisterT target_reg,
                            bool target_needs_to_be_decompressed) {
    // There shouldn't have been another move to this register already.
    CheckNoExistingMoveToRegister(target_reg);

    NeedsDecompression needs_decompression = kDoesNotNeedDecompression;
    if constexpr (DecompressIfNeeded) {
      if (target_needs_to_be_decompressed &&
          !node->decompresses_tagged_result()) {
        needs_decompression = kNeedsDecompression;
      }
    } else {
      DCHECK_IMPLIES(target_needs_to_be_decompressed,
                     node->decompresses_tagged_result());
    }

    GapMoveTargets* targets;
    if (source.IsAnyRegister()) {
      RegisterT source_reg = ToRegisterT<RegisterT>(source);
      if (target_reg == source_reg) {
        // We should never have a register aliasing case that needs
        // decompression, since this path is only used by exception phis and
        // they have no reg->reg moves.
        DCHECK_EQ(needs_decompression, kDoesNotNeedDecompression);
        return;
      }
      targets = &moves_from_register_[source_reg.code()];
    } else if (source.IsAnyStackSlot()) {
      int32_t source_slot = masm_->GetFramePointerOffsetForStackSlot(
          compiler::AllocatedOperand::cast(source));
      targets = &moves_from_stack_slot_[source_slot];
    } else {
      DCHECK(source.IsConstant());
      DCHECK(IsConstantNode(node->opcode()));
      materializing_register_moves_[target_reg.code()] = node;
      // No need to update `targets.needs_decompression`, materialization is
      // always decompressed.
      return;
    }

    targets->registers.set(target_reg);
    if (needs_decompression == kNeedsDecompression) {
      targets->needs_decompression = kNeedsDecompression;
    }
  }

  void RecordMoveToStackSlot(ValueNode* node,
                             compiler::InstructionOperand source,
                             int32_t target_slot,
                             bool target_needs_to_be_decompressed) {
    // There shouldn't have been another move to this stack slot already.
    CheckNoExistingMoveToStackSlot(target_slot);

    NeedsDecompression needs_decompression = kDoesNotNeedDecompression;
    if constexpr (DecompressIfNeeded) {
      if (target_needs_to_be_decompressed &&
          !node->decompresses_tagged_result()) {
        needs_decompression = kNeedsDecompression;
      }
    } else {
      DCHECK_IMPLIES(target_needs_to_be_decompressed,
                     node->decompresses_tagged_result());
    }

    GapMoveTargets* targets;
    if (source.IsAnyRegister()) {
      RegisterT source_reg = ToRegisterT<RegisterT>(source);
      targets = &moves_from_register_[source_reg.code()];
    } else if (source.IsAnyStackSlot()) {
      int32_t source_slot = masm_->GetFramePointerOffsetForStackSlot(
          compiler::AllocatedOperand::cast(source));
      if (source_slot == target_slot &&
          needs_decompression == kDoesNotNeedDecompression) {
        return;
      }
      targets = &moves_from_stack_slot_[source_slot];
    } else {
      DCHECK(source.IsConstant());
      DCHECK(IsConstantNode(node->opcode()));
      materializing_stack_slot_moves_.emplace_back(target_slot, node);
      // No need to update `targets.needs_decompression`, materialization is
      // always decompressed.
      return;
    }

    targets->stack_slots.push_back(target_slot);
    if (needs_decompression == kNeedsDecompression) {
      targets->needs_decompression = kNeedsDecompression;
    }
  }

  // Finds and clears the targets for a given source. In terms of move graph,
  // this returns and removes all outgoing edges from the source.
  GapMoveTargets PopTargets(RegisterT source_reg) {
    return std::exchange(moves_from_register_[source_reg.code()],
                         GapMoveTargets{});
  }
  GapMoveTargets PopTargets(int32_t source_slot) {
    auto handle = moves_from_stack_slot_.extract(source_slot);
    if (handle.empty()) return {};
    DCHECK(!handle.mapped().is_empty());
    return std::move(handle.mapped());
  }

  // Emit a single move chain starting at the given source (either a register or
  // a stack slot). This is a destructive operation on the move graph, and
  // removes the emitted edges from the graph. Subsequent calls with the same
  // source should emit no code.
  template <typename SourceT>
  void StartEmitMoveChain(SourceT source) {
    DCHECK(!scratch_has_cycle_start_);
    GapMoveTargets targets = PopTargets(source);
    if (targets.is_empty()) return;

    // Start recursively emitting the move chain, with this source as the start
    // of the chain.
    bool has_cycle = RecursivelyEmitMoveChainTargets(source, targets);

    // Each connected component in the move graph can only have one cycle
    // (proof: each target can only have one incoming edge, so cycles in the
    // graph can only have outgoing edges, so there's no way to connect two
    // cycles). This means that if there's a cycle, the saved value must be the
    // chain start.
    if (has_cycle) {
      if (!scratch_has_cycle_start_) {
        Pop(scratch_);
        scratch_has_cycle_start_ = true;
      }
      EmitMovesFromSource(scratch_, std::move(targets));
      scratch_has_cycle_start_ = false;
      __ RecordComment("--   * End of cycle");
    } else {
      EmitMovesFromSource(source, std::move(targets));
      __ RecordComment("--   * Chain emitted with no cycles");
    }
  }

  template <typename ChainStartT, typename SourceT>
  bool ContinueEmitMoveChain(ChainStartT chain_start, SourceT source) {
    if constexpr (std::is_same_v<ChainStartT, SourceT>) {
      // If the recursion has returned to the start of the chain, then this must
      // be a cycle.
      if (chain_start == source) {
        __ RecordComment("--   * Cycle");
        DCHECK(!scratch_has_cycle_start_);
        if constexpr (std::is_same_v<ChainStartT, int32_t>) {
          __ Move(scratch_, StackSlot{chain_start});
        } else {
          __ Move(scratch_, chain_start);
        }
        scratch_has_cycle_start_ = true;
        return true;
      }
    }

    GapMoveTargets targets = PopTargets(source);
    if (targets.is_empty()) {
      __ RecordComment("--   * End of chain");
      return false;
    }

    bool has_cycle = RecursivelyEmitMoveChainTargets(chain_start, targets);

    EmitMovesFromSource(source, std::move(targets));
    return has_cycle;
  }

  // Calls RecursivelyEmitMoveChain for each target of a source. This is used to
  // share target visiting code between StartEmitMoveChain and
  // ContinueEmitMoveChain.
  template <typename ChainStartT>
  bool RecursivelyEmitMoveChainTargets(ChainStartT chain_start,
                                       GapMoveTargets& targets) {
    bool has_cycle = false;
    for (auto target : targets.registers) {
      has_cycle |= ContinueEmitMoveChain(chain_start, target);
    }
    for (int32_t target_slot : targets.stack_slots) {
      has_cycle |= ContinueEmitMoveChain(chain_start, target_slot);
    }
    return has_cycle;
  }

  void EmitMovesFromSource(RegisterT source_reg, GapMoveTargets&& targets) {
    DCHECK(moves_from_register_[source_reg.code()].is_empty());
    if constexpr (DecompressIfNeeded) {
      // The DecompressIfNeeded clause is redundant with the if-constexpr above,
      // but otherwise this code cannot be compiled by compilers not yet
      // implementing CWG2518.
      static_assert(DecompressIfNeeded && COMPRESS_POINTERS_BOOL);

      if (targets.needs_decompression == kNeedsDecompression) {
        __ DecompressTagged(source_reg, source_reg);
      }
    }
    for (RegisterT target_reg : targets.registers) {
      DCHECK(moves_from_register_[target_reg.code()].is_empty());
      __ Move(target_reg, source_reg);
    }
    for (int32_t target_slot : targets.stack_slots) {
      DCHECK_EQ(moves_from_stack_slot_.find(target_slot),
                moves_from_stack_slot_.end());
      __ Move(StackSlot{target_slot}, source_reg);
    }
  }

  void EmitMovesFromSource(int32_t source_slot, GapMoveTargets&& targets) {
    DCHECK_EQ(moves_from_stack_slot_.find(source_slot),
              moves_from_stack_slot_.end());

    // Cache the slot value on a register.
    RegisterT register_with_slot_value = RegisterT::no_reg();
    if (!targets.registers.is_empty()) {
      // If one of the targets is a register, we can move our value into it and
      // optimize the moves from this stack slot to always be via that register.
      register_with_slot_value = targets.registers.PopFirst();
    } else {
      DCHECK(!targets.stack_slots.empty());
      // Otherwise, cache the slot value on the scratch register, clobbering it
      // if necessary.
      if (scratch_has_cycle_start_) {
        Push(scratch_);
        scratch_has_cycle_start_ = false;
      }
      register_with_slot_value = scratch_;
    }
    // Now emit moves from that cached register instead of from the stack slot.
    DCHECK(register_with_slot_value.is_valid());
    DCHECK(moves_from_register_[register_with_slot_value.code()].is_empty());
    __ Move(register_with_slot_value, StackSlot{source_slot});
    // Decompress after the first move, subsequent moves reuse this register so
    // they're guaranteed to be decompressed.
    if constexpr (DecompressIfNeeded) {
      // The DecompressIfNeeded clause is redundant with the if-constexpr above,
      // but otherwise this code cannot be compiled by compilers not yet
      // implementing CWG2518.
      static_assert(DecompressIfNeeded && COMPRESS_POINTERS_BOOL);

      if (targets.needs_decompression == kNeedsDecompression) {
        __ DecompressTagged(register_with_slot_value, register_with_slot_value);
        targets.needs_decompression = kDoesNotNeedDecompression;
      }
    }
    EmitMovesFromSource(register_with_slot_value, std::move(targets));
  }

  void Push(Register reg) { __ Push(reg); }
  void Push(DoubleRegister reg) { __ PushAll({reg}); }
  void Pop(Register reg) { __ Pop(reg); }
  void Pop(DoubleRegister reg) { __ PopAll({reg}); }

  MaglevAssembler* masm() const { return masm_; }

  MaglevAssembler* const masm_;
  RegisterT scratch_;

  // Keep moves to/from registers and stack slots separate -- there are a fixed
  // number of registers but an infinite number of stack slots, so the register
  // moves can be kept in a fixed size array while the stack slot moves need a
  // map.

  // moves_from_register_[source] = target.
  std::array<GapMoveTargets, RegisterT::kNumRegisters> moves_from_register_ =
      {};

  // TODO(victorgomes): Use MaglevAssembler::StackSlot instead of int32_t.
  // moves_from_stack_slot_[source] = target.
  std::unordered_map<int32_t, GapMoveTargets> moves_from_stack_slot_;

  // materializing_register_moves[target] = node.
  std::array<ValueNode*, RegisterT::kNumRegisters>
      materializing_register_moves_ = {};

  // materializing_stack_slot_moves = {(node,target), ... }.
  std::vector<std::pair<int32_t, ValueNode*>> materializing_stack_slot_moves_;

  bool scratch_has_cycle_start_ = false;
};

class ExceptionHandlerTrampolineBuilder {
 public:
  static void Build(MaglevAssembler* masm, NodeBase* node) {
    ExceptionHandlerTrampolineBuilder builder(masm);
    builder.EmitTrampolineFor(node);
  }

 private:
  explicit ExceptionHandlerTrampolineBuilder(MaglevAssembler* masm)
      : masm_(masm) {}

  struct Move {
    explicit Move(const ValueLocation& target, ValueNode* source)
        : target(target), source(source) {}
    const ValueLocation& target;
    ValueNode* const source;
  };
  using MoveVector = base::SmallVector<Move, 16>;

  void EmitTrampolineFor(NodeBase* node) {
    DCHECK(node->properties().can_throw());

    ExceptionHandlerInfo* const handler_info = node->exception_handler_info();
    if (handler_info->ShouldLazyDeopt()) return;
    DCHECK(handler_info->HasExceptionHandler());
    BasicBlock* const catch_block = handler_info->catch_block.block_ptr();
    LazyDeoptInfo* const deopt_info = node->lazy_deopt_info();

    // The exception handler trampoline resolves moves for exception phis and
    // then jumps to the actual catch block. There are a few points worth
    // noting:
    //
    // - All source locations are assumed to be stack slots, except the
    // accumulator which is stored in kReturnRegister0. We don't emit an
    // explicit move for it, instead it is pushed and popped at the boundaries
    // of the entire move sequence (necessary due to materialisation).
    //
    // - Some values may require materialisation, i.e. heap number construction
    // through calls to the NewHeapNumber builtin. To avoid potential conflicts
    // with other moves (which may happen due to stack slot reuse, i.e. a
    // target location of move A may equal source location of move B), we
    // materialise and push results to new temporary stack slots before the
    // main move sequence, and then pop results into their final target
    // locations afterwards. Note this is only safe because a) materialised
    // values are tagged and b) the stack walk treats unknown stack slots as
    // tagged.

    const InterpretedDeoptFrame& lazy_frame =
        deopt_info->GetFrameForExceptionHandler(handler_info);

    // TODO(v8:7700): Handle inlining.
    ParallelMoveResolver<Register, COMPRESS_POINTERS_BOOL> direct_moves(masm_);
    MoveVector materialising_moves;
    bool save_accumulator = false;
    RecordMoves(lazy_frame.unit(), catch_block, lazy_frame.frame_state(),
                &direct_moves, &materialising_moves, &save_accumulator);
    __ BindJumpTarget(&handler_info->trampoline_entry);
    __ RecordComment("-- Exception handler trampoline START");
    EmitMaterialisationsAndPushResults(materialising_moves, save_accumulator);

    __ RecordComment("EmitMoves");
    MaglevAssembler::TemporaryRegisterScope temps(masm_);
    Register scratch = temps.AcquireScratch();
    direct_moves.EmitMoves(scratch);
    EmitPopMaterialisedResults(materialising_moves, save_accumulator, scratch);
    __ Jump(catch_block->label());
    __ RecordComment("-- Exception handler trampoline END");
  }

  MaglevAssembler* masm() const { return masm_; }

  void RecordMoves(
      const MaglevCompilationUnit& unit, BasicBlock* catch_block,
      const CompactInterpreterFrameState* register_frame,
      ParallelMoveResolver<Register, COMPRESS_POINTERS_BOOL>* direct_moves,
      MoveVector* materialising_moves, bool* save_accumulator) {
    if (!catch_block->has_phi()) return;
    for (Phi* phi : *catch_block->phis()) {
      DCHECK(phi->is_exception_phi());
      if (!phi->has_valid_live_range()) continue;

      const ValueLocation& target = phi->result();
      if (phi->owner() == interpreter::Register::virtual_accumulator()) {
        // If the accumulator is live, then it is the exception object located
        // at kReturnRegister0.  We don't emit a move for it since the value is
        // already in the right spot, but we do have to ensure it isn't
        // clobbered by calls to the NewHeapNumber builtin during
        // materialisation.
        DCHECK_EQ(target.AssignedGeneralRegister(), kReturnRegister0);
        *save_accumulator = true;
        continue;
      }

      ValueNode* source = register_frame->GetValueOf(phi->owner(), unit);
      DCHECK_NOT_NULL(source);
      if (VirtualObject* vobj = source->TryCast<VirtualObject>()) {
        DCHECK(vobj->allocation()->HasEscaped());
        source = vobj->allocation();
      }
      // All registers must have been spilled due to the call.
      // TODO(jgruber): Which call? Because any throw requires at least a call
      // to Runtime::kThrowFoo?
      DCHECK(!source->allocation().IsRegister());

      switch (source->properties().value_representation()) {
        case ValueRepresentation::kIntPtr:
          UNREACHABLE();
        case ValueRepresentation::kTagged:
          direct_moves->RecordMove(
              source, source->allocation(),
              compiler::AllocatedOperand::cast(target.operand()),
              phi->decompresses_tagged_result() ? kNeedsDecompression
                                                : kDoesNotNeedDecompression);
          break;
        case ValueRepresentation::kInt32:
        case ValueRepresentation::kUint32:
          materialising_moves->emplace_back(target, source);
          break;
        case ValueRepresentation::kFloat64:
        case ValueRepresentation::kHoleyFloat64:
          materialising_moves->emplace_back(target, source);
          break;
          UNREACHABLE();
      }
    }
  }

  void EmitMaterialisationsAndPushResults(const MoveVector& moves,
                                          bool save_accumulator) const {
    if (moves.empty()) return;

    // It's possible to optimize this further, at the cost of additional
    // complexity:
    //
    // - If the target location is a register, we could theoretically move the
    // materialised result there immediately, with the additional complication
    // that following calls to NewHeapNumber may clobber the register.
    //
    // - If the target location is a stack slot which is neither a source nor
    // target slot for any other moves (direct or materialising), we could move
    // the result there directly instead of pushing and later popping it. This
    // doesn't seem worth the extra code complexity though, given we are
    // talking about a presumably infrequent case for exception handlers.

    __ RecordComment("EmitMaterialisationsAndPushResults");

    if (save_accumulator) __ Push(kReturnRegister0);

#ifdef DEBUG
    // Allow calls in these materialisations.
    __ set_allow_call(true);
#endif
    for (const Move& move : moves) {
      // We consider constants after all other operations, since constants
      // don't need to call NewHeapNumber.
      if (IsConstantNode(move.source->opcode())) continue;
      __ MaterialiseValueNode(kReturnRegister0, move.source);
      __ Push(kReturnRegister0);
    }
#ifdef DEBUG
    __ set_allow_call(false);
#endif
  }

  void EmitPopMaterialisedResults(const MoveVector& moves,
                                  bool save_accumulator,
                                  Register scratch) const {
    if (moves.empty()) return;
    __ RecordComment("EmitPopMaterialisedResults");
    for (const Move& move : base::Reversed(moves)) {
      const ValueLocation& target = move.target;
      Register target_reg = target.operand().IsAnyRegister()
                                ? target.AssignedGeneralRegister()
                                : scratch;
      if (IsConstantNode(move.source->opcode())) {
        __ MaterialiseValueNode(target_reg, move.source);
      } else {
        __ Pop(target_reg);
      }
      if (target_reg == scratch) {
        __ Move(masm_->ToMemOperand(target.operand()), scratch);
      }
    }
    if (save_accumulator) __ Pop(kReturnRegister0);
  }

  MaglevAssembler* const masm_;
};

class MaglevCodeGeneratingNodeProcessor {
 public:
  MaglevCodeGeneratingNodeProcessor(MaglevAssembler* masm, Zone* zone)
      : masm_(masm), zone_(zone) {}

  void PreProcessGraph(Graph* graph) {
    // TODO(victorgomes): I wonder if we want to create a struct that shares
    // these fields between graph and code_gen_state.
    code_gen_state()->set_untagged_slots(graph->untagged_stack_slots());
    code_gen_state()->set_tagged_slots(graph->tagged_stack_slots());
    code_gen_state()->set_max_deopted_stack_size(
        graph->max_deopted_stack_size());
    code_gen_state()->set_max_call_stack_args_(graph->max_call_stack_args());

    if (v8_flags.maglev_break_on_entry) {
      __ DebugBreak();
    }

    if (graph->is_osr()) {
      __ OSRPrologue(graph);
    } else {
      __ Prologue(graph);
    }

    // "Deferred" computation has to be done before block removal, because
    // block removal doesn't propagate deferredness of removed blocks.
    int deferred_count = ComputeDeferred(graph);

    // If we deferred the first block, un-defer it. This can happen because we
    // defer a block if all its successors are deferred (i.e., lead to an
    // unconditional deopt). E.g., if we only executed exception throwing code
    // paths, the non-exception code paths might be untaken, and thus contain
    // unconditional deopts, so we end up deferring all non-exception code
    // paths, including the first block.
    if (graph->blocks()[0]->is_deferred()) {
      graph->blocks()[0]->set_deferred(false);
      --deferred_count;
    }

    // Reorder the blocks so that dererred blocks are at the end.
    int non_deferred_count = graph->num_blocks() - deferred_count;

    ZoneVector<BasicBlock*> new_blocks(graph->num_blocks(), zone_);

    size_t ix_non_deferred = 0;
    size_t ix_deferred = non_deferred_count;
    for (auto block_it = graph->begin(); block_it != graph->end(); ++block_it) {
      BasicBlock* block = *block_it;
      if (block->is_deferred()) {
        new_blocks[ix_deferred++] = block;
      } else {
        new_blocks[ix_non_deferred++] = block;
      }
    }
    CHECK_EQ(ix_deferred, graph->num_blocks());
    CHECK_EQ(ix_non_deferred, non_deferred_count);
    graph->set_blocks(new_blocks);

    // Remove empty blocks.
    ZoneVector<BasicBlock*>& blocks = graph->blocks();
    size_t current_ix = 0;
    for (size_t i = 0; i < blocks.size(); ++i) {
      BasicBlock* block = blocks[i];
      if (block->RealJumpTarget() == block) {
        // This block cannot be replaced.
        blocks[current_ix++] = block;
      }
    }
    blocks.resize(current_ix);
  }

  void PostProcessGraph(Graph* graph) {}
  void PostPhiProcessing() {}

  BlockProcessResult PreProcessBasicBlock(BasicBlock* block) {
    if (block->is_loop()) {
      __ LoopHeaderAlign();
    }
    if (v8_flags.code_comments) {
      std::stringstream ss;
      ss << "-- Block b" << graph_labeller()->BlockId(block);
      __ RecordComment(ss.str());
    }
    __ BindBlock(block);
    return BlockProcessResult::kContinue;
  }

  template <typename NodeT>
  ProcessResult Process(NodeT* node, const ProcessingState& state) {
    if (v8_flags.code_comments) {
      std::stringstream ss;
      ss << "--   " << graph_labeller()->NodeId(node) << ": "
         << PrintNode(graph_labeller(), node);
      __ RecordComment(ss.str());
    }

    if (v8_flags.maglev_assert_stack_size) {
      __ AssertStackSizeCorrect();
    }

    PatchJumps(node);

    // Emit Phi moves before visiting the control node.
    if (std::is_base_of<UnconditionalControlNode, NodeT>::value) {
      EmitBlockEndGapMoves(node->template Cast<UnconditionalControlNode>(),
                           state);
    }

    if (v8_flags.debug_code && !std::is_same_v<NodeT, Phi>) {
      // Check that all int32/uint32 inputs are zero extended.
      // Note that we don't do this for Phis, since they are virtual operations
      // whose inputs aren't actual inputs but are injected on incoming
      // branches. There's thus nothing to verify for the inputs we see for the
      // phi.
      for (Input& input : *node) {
        ValueRepresentation rep =
            input.node()->properties().value_representation();
        if (IsZeroExtendedRepresentation(rep)) {
          // TODO(leszeks): Ideally we'd check non-register inputs too, but
          // AssertZeroExtended needs the scratch register, so we'd have to do
          // some manual push/pop here to free up another register.
          if (input.IsGeneralRegister()) {
            __ AssertZeroExtended(ToRegister(input));
          }
        }
      }
    }

    MaglevAssembler::TemporaryRegisterScope scratch_scope(masm());
    scratch_scope.Include(node->general_temporaries());
    scratch_scope.IncludeDouble(node->double_temporaries());

#ifdef DEBUG
    masm()->set_allow_allocate(node->properties().can_allocate());
    masm()->set_allow_call(node->properties().is_call());
    masm()->set_allow_deferred_call(node->properties().is_deferred_call());
#endif

    node->GenerateCode(masm(), state);

#ifdef DEBUG
    masm()->set_allow_allocate(fals
```