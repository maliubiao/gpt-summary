Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The request asks for the functionality of `raw-machine-assembler.cc` and its relation to JavaScript, illustrated with JavaScript examples.

2. **Initial Skim and Keyword Recognition:** Quickly scan the code for recognizable terms. Keywords like "assembler," "machine," "graph," "node," "schedule," "compiler," "JavaScript," and functions like `Goto`, `Branch`, `Return`, `CallN` stand out. These suggest the file is about generating low-level machine code representations.

3. **Identify Core Functionality (High-Level):**  The name "RawMachineAssembler" strongly suggests it's a tool for building machine code instructions. The presence of `Graph` and `Schedule` implies this construction is happening within a compiler's intermediate representation.

4. **Analyze Key Methods (Mid-Level):**  Examine the purpose of important methods:
    * **Constructor:** Initializes the assembler with core components like `Isolate`, `Graph`, `CallDescriptor`, etc. This hints at its integration within the V8 engine.
    * **`AddNode` and `MakeNode`:** These are likely responsible for creating nodes in the internal graph representation, which represent machine operations.
    * **`Goto`, `Branch`, `Return`, `Switch`:** These methods correspond to fundamental control flow instructions in assembly language.
    * **`CallN`, `TailCallN`, `CallCFunction`:** These deal with function calls, including calling native C++ functions.
    * **`Phi`:** This is a compiler concept for merging values from different control flow paths.
    * **`Bind`:**  Associates a label with a basic block, crucial for control flow.
    * **`ExportForTest` and `ExportForOptimization`:** These suggest the assembler produces output that can be used for testing or further optimization.
    * **Methods related to source positions (`SetCurrentExternalSourcePosition`, etc.):** Indicate support for debugging and linking back to the original source code.
    * **Methods related to constants (`NullConstant`, `UndefinedConstant`, etc.):**  Provide ways to represent common values in the generated code.
    * **`OptimizeControlFlow` and `MakeReschedulable`:** These suggest the assembler performs some level of optimization and transformation on the generated code.

5. **Connect to JavaScript (Crucial Step):**  Think about *where* and *how* this low-level code generation fits into the V8 JavaScript execution pipeline. The most direct connection is the **Turbofan compiler**. Turbofan takes JavaScript code and transforms it into efficient machine code. `RawMachineAssembler` is a tool *used by* Turbofan.

6. **Illustrate with JavaScript Examples:**  Now, map common JavaScript constructs to the low-level operations handled by `RawMachineAssembler`:
    * **`if/else`:** Directly corresponds to `Branch` instructions.
    * **`return`:**  Maps to the `Return` instruction.
    * **Function calls:** Correlate to `CallN`. Differentiate between JavaScript function calls and calls to C++ functions (`CallCFunction`).
    * **Loops (`for`, `while`):**  Connect to the concept of loop headers and back edges, which `RawMachineAssembler` helps construct using `Loop` nodes.
    * **`switch` statements:**  Clearly map to the `Switch` method.

7. **Refine and Organize:** Structure the findings into a clear summary of functionality and then provide the JavaScript examples with explanations. Emphasize the key takeaway: `RawMachineAssembler` is an *internal tool* of the V8 compiler, not something directly exposed to JavaScript developers.

8. **Address Nuances:** Consider edge cases or less obvious features, like the handling of source positions and the different export methods.

9. **Review and Verify:** Double-check the accuracy of the summary and the relevance of the JavaScript examples. Ensure the explanation clearly articulates the relationship between the C++ code and JavaScript execution. For example, it's important to stress that developers don't *directly* use `RawMachineAssembler` in their JavaScript code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe this is about the V8 bytecode interpreter?"  **Correction:** While the interpreter exists, the filename and the presence of "machine assembler" strongly point to the *compiler* (Turbofan).
* **Initial thought on examples:** "Just show simple `if` and `return`." **Refinement:**  Include examples of function calls (both JS and C++), loops, and `switch` statements to provide broader coverage.
* **Wording:** Ensure the language is clear and avoids overly technical jargon where possible while still being accurate. For example, explaining "intermediate representation" helps contextualize the role of `RawMachineAssembler`.

By following these steps, the analysis can move from a basic understanding of the code to a comprehensive explanation of its function and its connection to JavaScript.
这个C++源代码文件 `raw-machine-assembler.cc` 定义了一个名为 `RawMachineAssembler` 的类，它是 **V8 JavaScript 引擎中用于生成底层机器码指令的工具**。

**主要功能归纳:**

1. **构建机器码图 (Graph Construction):** `RawMachineAssembler` 提供了创建和连接代表机器指令的节点 (`Node`) 的方法，从而构建一个表示程序执行流程的图 (`Graph`). 这些节点可以代表算术运算、内存访问、控制流操作等。

2. **控制流管理 (Control Flow Management):** 它提供了管理代码执行顺序的方法，例如：
   - `Goto`:  跳转到指定的标签。
   - `Branch`:  根据条件跳转到不同的标签。
   - `Switch`:  根据不同的值跳转到不同的标签。
   - `Return`:  从函数返回。
   - `Continuations`: 处理函数调用成功和异常的情况。
   - `Bind`:  将标签与代码块关联。

3. **操作码抽象 (Opcode Abstraction):** 它封装了底层的机器指令，允许开发者使用更高级的抽象概念（如 `common()->Return()`, `simplified()->AllocateRaw()`）来创建指令，而无需直接操作机器码。

4. **函数调用 (Function Calls):**  支持调用 JavaScript 函数 (`CallN`, `TailCallN`) 和 C++ 函数 (`CallCFunction`).

5. **常量表示 (Constant Representation):**  提供了创建各种常量（如 `NullConstant`, `UndefinedConstant`, 数字常量等）的方法。

6. **中间表示优化 (Intermediate Representation Optimization):**  包含一些用于优化控制流的初步方法 (`OptimizeControlFlow`) 和将调度图转换为可调度的图表示的方法 (`MakeReschedulable`).

7. **调试支持 (Debugging Support):**  允许插入调试断点 (`DebugBreak`) 和添加注释 (`Comment`)。

8. **与调度器交互 (Interaction with Scheduler):**  它与 V8 的调度器 (`Scheduler`) 紧密合作，管理代码块的执行顺序。

9. **源代码位置跟踪 (Source Position Tracking):**  记录生成的机器码与原始 JavaScript 源代码的对应关系，用于调试和性能分析。

**与 JavaScript 的关系 (以及 JavaScript 举例):**

`RawMachineAssembler` 是 **V8 引擎内部的工具，开发者通常不会直接在 JavaScript 代码中使用它。** 它的主要作用是 **将 JavaScript 代码编译成高效的机器码**。

当 V8 的 Turbofan 编译器优化 JavaScript 代码时，它会使用 `RawMachineAssembler` (或其他类似的汇编器) 来生成底层的机器指令。

**JavaScript 代码示例 (说明 `RawMachineAssembler` 背后的工作原理):**

假设有以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  if (a > 10) {
    return a + b;
  } else {
    return a - b;
  }
}
```

当 V8 编译这个函数时，`RawMachineAssembler` 可能会生成类似于以下逻辑的机器码表示（这只是一个简化的概念性示例，实际生成的机器码会更复杂且特定于架构）：

```c++
// 假设 RawMachineAssembler 实例为 rma

// 获取参数 a 和 b
Node* param_a = rma->Parameter(0);
Node* param_b = rma->Parameter(1);

// 创建标签
RawMachineLabel if_true_label, if_false_label, end_label;

// 比较 a 是否大于 10
Node* ten_constant = rma->Int32Constant(10);
Node* compare_result = rma->GreaterThan(param_a, ten_constant);

// 根据比较结果跳转
rma->Branch(compare_result, &if_true_label, &if_false_label);

// 如果 a > 10
rma->Bind(&if_true_label);
Node* add_result = rma->Int32Add(param_a, param_b);
rma->Return(add_result);
rma->Goto(&end_label);

// 否则 (a <= 10)
rma->Bind(&if_false_label);
Node* subtract_result = rma->Int32Sub(param_a, param_b);
rma->Return(subtract_result);

// 结束
rma->Bind(&end_label);
```

**解释:**

- JavaScript 的 `if (a > 10)` 语句会被翻译成 `RawMachineAssembler` 中的比较操作 (`GreaterThan`) 和条件分支 (`Branch`).
- JavaScript 的 `return a + b;` 和 `return a - b;` 会被翻译成相应的算术运算 (`Int32Add`, `Int32Sub`) 和 `Return` 指令。
- `RawMachineLabel` 用于标记代码块，`Goto` 和 `Branch` 用于控制代码的执行流程。

**总结:**

`RawMachineAssembler` 是 V8 引擎中一个非常核心的组件，它负责将高级的中间表示（例如由 Turbofan 生成的）转换为可以直接在机器上执行的底层指令。虽然 JavaScript 开发者不会直接使用它，但它的存在和高效运作对于 JavaScript 代码的性能至关重要。它充当了高级语言和机器硬件之间的桥梁。

Prompt: 
```
这是目录为v8/src/compiler/raw-machine-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/raw-machine-assembler.h"

#include <optional>

#include "src/base/small-vector.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/scheduler.h"
#include "src/heap/factory-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

RawMachineAssembler::RawMachineAssembler(
    Isolate* isolate, Graph* graph, CallDescriptor* call_descriptor,
    MachineRepresentation word, MachineOperatorBuilder::Flags flags,
    MachineOperatorBuilder::AlignmentRequirements alignment_requirements)
    : isolate_(isolate),
      graph_(graph),
      schedule_(zone()->New<Schedule>(zone())),
      source_positions_(zone()->New<SourcePositionTable>(graph)),
      machine_(zone(), word, flags, alignment_requirements),
      common_(zone()),
      simplified_(zone()),
      call_descriptor_(call_descriptor),
      dynamic_js_parameter_count_(nullptr),
      target_parameter_(nullptr),
      parameters_(parameter_count(), zone()),
      current_block_(schedule()->start()) {
  int param_count = static_cast<int>(parameter_count());
  // Add an extra input for the JSFunction parameter to the start node.
  graph->SetStart(graph->NewNode(common_.Start(param_count + 1)));
  if (call_descriptor->IsJSFunctionCall()) {
    target_parameter_ = AddNode(
        common()->Parameter(Linkage::kJSCallClosureParamIndex), graph->start());
  }
  for (size_t i = 0; i < parameter_count(); ++i) {
    parameters_[i] =
        AddNode(common()->Parameter(static_cast<int>(i)), graph->start());
  }
  graph->SetEnd(graph->NewNode(common_.End(0)));
  source_positions_->AddDecorator();
}

void RawMachineAssembler::SetCurrentExternalSourcePosition(
    FileAndLine file_and_line) {
  int file_id =
      isolate()->LookupOrAddExternallyCompiledFilename(file_and_line.first);
  SourcePosition p = SourcePosition::External(file_and_line.second, file_id);
  DCHECK_EQ(p.ExternalLine(), file_and_line.second);
  source_positions()->SetCurrentPosition(p);
}

FileAndLine RawMachineAssembler::GetCurrentExternalSourcePosition() const {
  SourcePosition p = source_positions_->GetCurrentPosition();
  if (!p.IsKnown()) return {nullptr, -1};
  int file_id = p.ExternalFileId();
  const char* file_name = isolate()->GetExternallyCompiledFilename(file_id);
  int line = p.ExternalLine();
  return {file_name, line};
}

Node* RawMachineAssembler::NullConstant() {
  return HeapConstant(isolate()->factory()->null_value());
}

Node* RawMachineAssembler::UndefinedConstant() {
  return HeapConstant(isolate()->factory()->undefined_value());
}

Node* RawMachineAssembler::RelocatableIntPtrConstant(intptr_t value,
                                                     RelocInfo::Mode rmode) {
  return kSystemPointerSize == 8
             ? RelocatableInt64Constant(value, rmode)
             : RelocatableInt32Constant(static_cast<int>(value), rmode);
}

Node* RawMachineAssembler::OptimizedAllocate(Node* size,
                                             AllocationType allocation) {
  return AddNode(simplified()->AllocateRaw(Type::Any(), allocation), size);
}

Schedule* RawMachineAssembler::ExportForTest() {
  // Compute the correct codegen order.
  DCHECK(schedule_->rpo_order()->empty());
  if (v8_flags.trace_turbo_scheduler) {
    PrintF("--- RAW SCHEDULE -------------------------------------------\n");
    StdoutStream{} << *schedule_;
  }
  schedule_->EnsureCFGWellFormedness();
  Scheduler::ComputeSpecialRPO(zone(), schedule_);
  Scheduler::GenerateDominatorTree(schedule_);
  schedule_->PropagateDeferredMark();
  if (v8_flags.trace_turbo_scheduler) {
    PrintF("--- EDGE SPLIT AND PROPAGATED DEFERRED SCHEDULE ------------\n");
    StdoutStream{} << *schedule_;
  }
  // Invalidate RawMachineAssembler.
  source_positions_->RemoveDecorator();
  Schedule* schedule = schedule_;
  schedule_ = nullptr;
  return schedule;
}

Graph* RawMachineAssembler::ExportForOptimization() {
  // Compute the correct codegen order.
  DCHECK(schedule_->rpo_order()->empty());
  if (v8_flags.trace_turbo_scheduler) {
    PrintF("--- RAW SCHEDULE -------------------------------------------\n");
    StdoutStream{} << *schedule_;
  }
  schedule_->EnsureCFGWellFormedness();
  OptimizeControlFlow(schedule_, graph(), common());
  Scheduler::ComputeSpecialRPO(zone(), schedule_);
  if (v8_flags.trace_turbo_scheduler) {
    PrintF("--- SCHEDULE BEFORE GRAPH CREATION -------------------------\n");
    StdoutStream{} << *schedule_;
  }
  MakeReschedulable();
  // Invalidate RawMachineAssembler.
  schedule_ = nullptr;
  return graph();
}

void RawMachineAssembler::OptimizeControlFlow(Schedule* schedule, Graph* graph,
                                              CommonOperatorBuilder* common) {
  for (bool changed = true; changed;) {
    changed = false;
    for (size_t i = 0; i < schedule->all_blocks()->size(); ++i) {
      BasicBlock* block = (*schedule->all_blocks())[i];
      if (block == nullptr) continue;

      // Short-circuit a goto if the succeeding block is not a control-flow
      // merge. This is not really useful on it's own since graph construction
      // has the same effect, but combining blocks improves the pattern-match on
      // their structure below.
      if (block->control() == BasicBlock::kGoto) {
        DCHECK_EQ(block->SuccessorCount(), 1);
        BasicBlock* successor = block->SuccessorAt(0);
        if (successor->PredecessorCount() == 1) {
          DCHECK_EQ(successor->PredecessorAt(0), block);
          for (Node* node : *successor) {
            schedule->SetBlockForNode(nullptr, node);
            schedule->AddNode(block, node);
          }
          block->set_control(successor->control());
          Node* control_input = successor->control_input();
          block->set_control_input(control_input);
          if (control_input) {
            schedule->SetBlockForNode(block, control_input);
          }
          if (successor->deferred()) block->set_deferred(true);
          block->ClearSuccessors();
          schedule->MoveSuccessors(successor, block);
          schedule->ClearBlockById(successor->id());
          changed = true;
          --i;
          continue;
        }
      }
      // Block-cloning in the simple case where a block consists only of a phi
      // node and a branch on that phi. This just duplicates the branch block
      // for each predecessor, replacing the phi node with the corresponding phi
      // input.
      if (block->control() == BasicBlock::kBranch && block->NodeCount() == 1) {
        Node* phi = block->NodeAt(0);
        if (phi->opcode() != IrOpcode::kPhi) continue;
        Node* branch = block->control_input();
        DCHECK_EQ(branch->opcode(), IrOpcode::kBranch);
        if (NodeProperties::GetValueInput(branch, 0) != phi) continue;
        if (phi->UseCount() != 1) continue;
        DCHECK_EQ(phi->op()->ValueInputCount(), block->PredecessorCount());

        // Turn projection blocks into normal blocks.
        DCHECK_EQ(block->SuccessorCount(), 2);
        BasicBlock* true_block = block->SuccessorAt(0);
        BasicBlock* false_block = block->SuccessorAt(1);
        DCHECK_EQ(true_block->NodeAt(0)->opcode(), IrOpcode::kIfTrue);
        DCHECK_EQ(false_block->NodeAt(0)->opcode(), IrOpcode::kIfFalse);
        (*true_block->begin())->Kill();
        true_block->RemoveNode(true_block->begin());
        (*false_block->begin())->Kill();
        false_block->RemoveNode(false_block->begin());
        true_block->ClearPredecessors();
        false_block->ClearPredecessors();

        size_t arity = block->PredecessorCount();
        for (size_t j = 0; j < arity; ++j) {
          BasicBlock* predecessor = block->PredecessorAt(j);
          predecessor->ClearSuccessors();
          if (block->deferred()) predecessor->set_deferred(true);
          Node* branch_clone = graph->CloneNode(branch);
          int phi_input = static_cast<int>(j);
          NodeProperties::ReplaceValueInput(
              branch_clone, NodeProperties::GetValueInput(phi, phi_input), 0);
          BasicBlock* new_true_block = schedule->NewBasicBlock();
          BasicBlock* new_false_block = schedule->NewBasicBlock();
          new_true_block->AddNode(
              graph->NewNode(common->IfTrue(), branch_clone));
          new_false_block->AddNode(
              graph->NewNode(common->IfFalse(), branch_clone));
          schedule->AddGoto(new_true_block, true_block);
          schedule->AddGoto(new_false_block, false_block);
          DCHECK_EQ(predecessor->control(), BasicBlock::kGoto);
          predecessor->set_control(BasicBlock::kNone);
          schedule->AddBranch(predecessor, branch_clone, new_true_block,
                              new_false_block);
        }
        branch->Kill();
        schedule->ClearBlockById(block->id());
        changed = true;
        continue;
      }
    }
  }
}

void RawMachineAssembler::MakeReschedulable() {
  std::vector<Node*> block_final_control(schedule_->all_blocks_.size());
  std::vector<Node*> block_final_effect(schedule_->all_blocks_.size());

  struct LoopHeader {
    BasicBlock* block;
    Node* loop_node;
    Node* effect_phi;
  };
  std::vector<LoopHeader> loop_headers;

  // These are hoisted outside of the loop to avoid re-allocation.
  std::vector<Node*> merge_inputs;
  std::vector<Node*> effect_phi_inputs;

  for (BasicBlock* block : *schedule_->rpo_order()) {
    Node* current_control;
    Node* current_effect;
    if (block == schedule_->start()) {
      current_control = current_effect = graph()->start();
    } else if (block == schedule_->end()) {
      for (size_t i = 0; i < block->PredecessorCount(); ++i) {
        NodeProperties::MergeControlToEnd(
            graph(), common(), block->PredecessorAt(i)->control_input());
      }
    } else if (block->IsLoopHeader()) {
      // The graph()->start() inputs are just placeholders until we computed the
      // real back-edges and re-structure the control flow so the loop has
      // exactly two predecessors.
      current_control = graph()->NewNode(common()->Loop(2), graph()->start(),
                                         graph()->start());
      current_effect =
          graph()->NewNode(common()->EffectPhi(2), graph()->start(),
                           graph()->start(), current_control);

      Node* terminate = graph()->NewNode(common()->Terminate(), current_effect,
                                         current_control);
      NodeProperties::MergeControlToEnd(graph(), common(), terminate);
      loop_headers.push_back(
          LoopHeader{block, current_control, current_effect});
    } else if (block->PredecessorCount() == 1) {
      BasicBlock* predecessor = block->PredecessorAt(0);
      DCHECK_LT(predecessor->rpo_number(), block->rpo_number());
      current_effect = block_final_effect[predecessor->id().ToSize()];
      current_control = block_final_control[predecessor->id().ToSize()];
    } else {
      // Create control merge nodes and effect phis for all predecessor blocks.
      merge_inputs.clear();
      effect_phi_inputs.clear();
      int predecessor_count = static_cast<int>(block->PredecessorCount());
      for (int i = 0; i < predecessor_count; ++i) {
        BasicBlock* predecessor = block->PredecessorAt(i);
        DCHECK_LT(predecessor->rpo_number(), block->rpo_number());
        merge_inputs.push_back(block_final_control[predecessor->id().ToSize()]);
        effect_phi_inputs.push_back(
            block_final_effect[predecessor->id().ToSize()]);
      }
      current_control = graph()->NewNode(common()->Merge(predecessor_count),
                                         static_cast<int>(merge_inputs.size()),
                                         merge_inputs.data());
      effect_phi_inputs.push_back(current_control);
      current_effect = graph()->NewNode(
          common()->EffectPhi(predecessor_count),
          static_cast<int>(effect_phi_inputs.size()), effect_phi_inputs.data());
    }

    auto update_current_control_and_effect = [&](Node* node) {
      bool existing_effect_and_control =
          IrOpcode::IsIfProjectionOpcode(node->opcode()) ||
          IrOpcode::IsPhiOpcode(node->opcode());
      if (node->op()->EffectInputCount() > 0) {
        DCHECK_EQ(1, node->op()->EffectInputCount());
        if (existing_effect_and_control) {
          NodeProperties::ReplaceEffectInput(node, current_effect);
        } else {
          node->AppendInput(graph()->zone(), current_effect);
        }
      }
      if (node->op()->ControlInputCount() > 0) {
        DCHECK_EQ(1, node->op()->ControlInputCount());
        if (existing_effect_and_control) {
          NodeProperties::ReplaceControlInput(node, current_control);
        } else {
          node->AppendInput(graph()->zone(), current_control);
        }
      }
      if (node->op()->EffectOutputCount() > 0) {
        DCHECK_EQ(1, node->op()->EffectOutputCount());
        current_effect = node;
      }
      if (node->op()->ControlOutputCount() > 0) {
        current_control = node;
      }
    };

    for (Node* node : *block) {
      update_current_control_and_effect(node);
    }
    if (block->deferred()) MarkControlDeferred(current_control);

    if (Node* block_terminator = block->control_input()) {
      update_current_control_and_effect(block_terminator);
    }

    block_final_effect[block->id().ToSize()] = current_effect;
    block_final_control[block->id().ToSize()] = current_control;
  }

  // Fix-up loop backedges and re-structure control flow so that loop nodes have
  // exactly two control predecessors.
  for (const LoopHeader& loop_header : loop_headers) {
    BasicBlock* block = loop_header.block;
    std::vector<BasicBlock*> loop_entries;
    std::vector<BasicBlock*> loop_backedges;
    for (size_t i = 0; i < block->PredecessorCount(); ++i) {
      BasicBlock* predecessor = block->PredecessorAt(i);
      if (block->LoopContains(predecessor)) {
        loop_backedges.push_back(predecessor);
      } else {
        DCHECK(loop_backedges.empty());
        loop_entries.push_back(predecessor);
      }
    }
    DCHECK(!loop_entries.empty());
    DCHECK(!loop_backedges.empty());

    int entrance_count = static_cast<int>(loop_entries.size());
    int backedge_count = static_cast<int>(loop_backedges.size());
    Node* control_loop_entry = CreateNodeFromPredecessors(
        loop_entries, block_final_control, common()->Merge(entrance_count), {});
    Node* control_backedge =
        CreateNodeFromPredecessors(loop_backedges, block_final_control,
                                   common()->Merge(backedge_count), {});
    Node* effect_loop_entry = CreateNodeFromPredecessors(
        loop_entries, block_final_effect, common()->EffectPhi(entrance_count),
        {control_loop_entry});
    Node* effect_backedge = CreateNodeFromPredecessors(
        loop_backedges, block_final_effect, common()->EffectPhi(backedge_count),
        {control_backedge});

    loop_header.loop_node->ReplaceInput(0, control_loop_entry);
    loop_header.loop_node->ReplaceInput(1, control_backedge);
    loop_header.effect_phi->ReplaceInput(0, effect_loop_entry);
    loop_header.effect_phi->ReplaceInput(1, effect_backedge);

    for (Node* node : *block) {
      if (node->opcode() == IrOpcode::kPhi) {
        MakePhiBinary(node, static_cast<int>(loop_entries.size()),
                      control_loop_entry, control_backedge);
      }
    }
  }
}

Node* RawMachineAssembler::CreateNodeFromPredecessors(
    const std::vector<BasicBlock*>& predecessors,
    const std::vector<Node*>& sidetable, const Operator* op,
    const std::vector<Node*>& additional_inputs) {
  if (predecessors.size() == 1) {
    return sidetable[predecessors.front()->id().ToSize()];
  }
  std::vector<Node*> inputs;
  inputs.reserve(predecessors.size());
  for (BasicBlock* predecessor : predecessors) {
    inputs.push_back(sidetable[predecessor->id().ToSize()]);
  }
  for (Node* additional_input : additional_inputs) {
    inputs.push_back(additional_input);
  }
  return graph()->NewNode(op, static_cast<int>(inputs.size()), inputs.data());
}

void RawMachineAssembler::MakePhiBinary(Node* phi, int split_point,
                                        Node* left_control,
                                        Node* right_control) {
  int value_count = phi->op()->ValueInputCount();
  if (value_count == 2) return;
  DCHECK_LT(split_point, value_count);
  DCHECK_GT(split_point, 0);

  MachineRepresentation rep = PhiRepresentationOf(phi->op());
  int left_input_count = split_point;
  int right_input_count = value_count - split_point;

  Node* left_input;
  if (left_input_count == 1) {
    left_input = NodeProperties::GetValueInput(phi, 0);
  } else {
    std::vector<Node*> inputs;
    inputs.reserve(left_input_count);
    for (int i = 0; i < left_input_count; ++i) {
      inputs.push_back(NodeProperties::GetValueInput(phi, i));
    }
    inputs.push_back(left_control);
    left_input =
        graph()->NewNode(common()->Phi(rep, static_cast<int>(left_input_count)),
                         static_cast<int>(inputs.size()), inputs.data());
  }

  Node* right_input;
  if (right_input_count == 1) {
    right_input = NodeProperties::GetValueInput(phi, split_point);
  } else {
    std::vector<Node*> inputs;
    for (int i = split_point; i < value_count; ++i) {
      inputs.push_back(NodeProperties::GetValueInput(phi, i));
    }
    inputs.push_back(right_control);
    right_input = graph()->NewNode(
        common()->Phi(rep, static_cast<int>(right_input_count)),
        static_cast<int>(inputs.size()), inputs.data());
  }

  Node* control = NodeProperties::GetControlInput(phi);
  phi->TrimInputCount(3);
  phi->ReplaceInput(0, left_input);
  phi->ReplaceInput(1, right_input);
  phi->ReplaceInput(2, control);
  NodeProperties::ChangeOp(phi, common()->Phi(rep, 2));
}

void RawMachineAssembler::MarkControlDeferred(Node* control_node) {
  BranchHint new_branch_hint;
  Node* responsible_branch = nullptr;
  while (responsible_branch == nullptr) {
    switch (control_node->opcode()) {
      case IrOpcode::kIfException:
        // IfException projections are deferred by default.
        return;
      case IrOpcode::kIfSuccess:
        control_node = NodeProperties::GetControlInput(control_node);
        continue;
      case IrOpcode::kIfValue: {
        IfValueParameters parameters = IfValueParametersOf(control_node->op());
        if (parameters.hint() != BranchHint::kFalse) {
          NodeProperties::ChangeOp(
              control_node, common()->IfValue(parameters.value(),
                                              parameters.comparison_order(),
                                              BranchHint::kFalse));
        }
        return;
      }
      case IrOpcode::kIfDefault:
        if (BranchHintOf(control_node->op()) != BranchHint::kFalse) {
          NodeProperties::ChangeOp(control_node,
                                   common()->IfDefault(BranchHint::kFalse));
        }
        return;
      case IrOpcode::kIfTrue: {
        Node* branch = NodeProperties::GetControlInput(control_node);
        BranchHint hint = BranchHintOf(branch->op());
        if (hint == BranchHint::kTrue) {
          // The other possibility is also deferred, so the responsible branch
          // has to be before.
          control_node = NodeProperties::GetControlInput(branch);
          continue;
        }
        new_branch_hint = BranchHint::kFalse;
        responsible_branch = branch;
        break;
      }
      case IrOpcode::kIfFalse: {
        Node* branch = NodeProperties::GetControlInput(control_node);
        BranchHint hint = BranchHintOf(branch->op());
        if (hint == BranchHint::kFalse) {
          // The other possibility is also deferred, so the responsible branch
          // has to be before.
          control_node = NodeProperties::GetControlInput(branch);
          continue;
        }
        new_branch_hint = BranchHint::kTrue;
        responsible_branch = branch;
        break;
      }
      case IrOpcode::kMerge:
        for (int i = 0; i < control_node->op()->ControlInputCount(); ++i) {
          MarkControlDeferred(NodeProperties::GetControlInput(control_node, i));
        }
        return;
      case IrOpcode::kLoop:
        control_node = NodeProperties::GetControlInput(control_node, 0);
        continue;
      case IrOpcode::kBranch:
      case IrOpcode::kSwitch:
        UNREACHABLE();
      case IrOpcode::kStart:
        return;
      default:
        DCHECK_EQ(1, control_node->op()->ControlInputCount());
        control_node = NodeProperties::GetControlInput(control_node);
        continue;
    }
  }

  BranchHint hint = BranchHintOf(responsible_branch->op());
  if (hint == new_branch_hint) return;
  NodeProperties::ChangeOp(responsible_branch,
                           common()->Branch(new_branch_hint));
}

Node* RawMachineAssembler::TargetParameter() {
  DCHECK_NOT_NULL(target_parameter_);
  return target_parameter_;
}

Node* RawMachineAssembler::Parameter(size_t index) {
  DCHECK_LT(index, parameter_count());
  return parameters_[index];
}


void RawMachineAssembler::Goto(RawMachineLabel* label) {
  DCHECK(current_block_ != schedule()->end());
  schedule()->AddGoto(CurrentBlock(), Use(label));
  current_block_ = nullptr;
}


void RawMachineAssembler::Branch(Node* condition, RawMachineLabel* true_val,
                                 RawMachineLabel* false_val) {
  DCHECK(current_block_ != schedule()->end());
  Node* branch = MakeNode(common()->Branch(BranchHint::kNone), 1, &condition);
  BasicBlock* true_block = schedule()->NewBasicBlock();
  BasicBlock* false_block = schedule()->NewBasicBlock();
  schedule()->AddBranch(CurrentBlock(), branch, true_block, false_block);

  true_block->AddNode(MakeNode(common()->IfTrue(), 1, &branch));
  schedule()->AddGoto(true_block, Use(true_val));

  false_block->AddNode(MakeNode(common()->IfFalse(), 1, &branch));
  schedule()->AddGoto(false_block, Use(false_val));

  current_block_ = nullptr;
}

void RawMachineAssembler::Continuations(Node* call, RawMachineLabel* if_success,
                                        RawMachineLabel* if_exception) {
  DCHECK_NOT_NULL(schedule_);
  DCHECK_NOT_NULL(current_block_);
  schedule()->AddCall(CurrentBlock(), call, Use(if_success), Use(if_exception));
  current_block_ = nullptr;
}

void RawMachineAssembler::Switch(Node* index, RawMachineLabel* default_label,
                                 const int32_t* case_values,
                                 RawMachineLabel** case_labels,
                                 size_t case_count) {
  DCHECK_NE(schedule()->end(), current_block_);
  size_t succ_count = case_count + 1;
  Node* switch_node = MakeNode(common()->Switch(succ_count), 1, &index);
  BasicBlock** succ_blocks = zone()->AllocateArray<BasicBlock*>(succ_count);
  for (size_t i = 0; i < case_count; ++i) {
    int32_t case_value = case_values[i];
    BasicBlock* case_block = schedule()->NewBasicBlock();
    Node* case_node =
        graph()->NewNode(common()->IfValue(case_value), switch_node);
    schedule()->AddNode(case_block, case_node);
    schedule()->AddGoto(case_block, Use(case_labels[i]));
    succ_blocks[i] = case_block;
  }
  BasicBlock* default_block = schedule()->NewBasicBlock();
  Node* default_node = graph()->NewNode(common()->IfDefault(), switch_node);
  schedule()->AddNode(default_block, default_node);
  schedule()->AddGoto(default_block, Use(default_label));
  succ_blocks[case_count] = default_block;
  schedule()->AddSwitch(CurrentBlock(), switch_node, succ_blocks, succ_count);
  current_block_ = nullptr;
}

void RawMachineAssembler::Return(Node* value) {
  Node* values[] = {Int32Constant(0), value};
  Node* ret = MakeNode(common()->Return(1), 2, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::Return(Node* v1, Node* v2) {
  Node* values[] = {Int32Constant(0), v1, v2};
  Node* ret = MakeNode(common()->Return(2), 3, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::Return(Node* v1, Node* v2, Node* v3) {
  Node* values[] = {Int32Constant(0), v1, v2, v3};
  Node* ret = MakeNode(common()->Return(3), 4, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::Return(Node* v1, Node* v2, Node* v3, Node* v4) {
  Node* values[] = {Int32Constant(0), v1, v2, v3, v4};
  Node* ret = MakeNode(common()->Return(4), 5, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::Return(int count, Node* vs[]) {
  using Node_ptr = Node*;
  Node** values = new Node_ptr[count + 1];
  values[0] = Int32Constant(0);
  for (int i = 0; i < count; ++i) values[i + 1] = vs[i];
  Node* ret = MakeNode(common()->Return(count), count + 1, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
  delete[] values;
}

void RawMachineAssembler::PopAndReturn(Node* pop, Node* value) {
  // PopAndReturn is supposed to be used ONLY in CSA/Torque builtins for
  // dropping ALL JS arguments that are currently located on the stack.
  // The check below ensures that there are no directly accessible stack
  // parameters from current builtin, which implies that the builtin with
  // JS calling convention (TFJ) was created with kDontAdaptArgumentsSentinel.
  // This simplifies semantics of this instruction because in case of presence
  // of directly accessible stack parameters it's impossible to distinguish
  // the following cases:
  // 1) stack parameter is included in JS arguments (and therefore it will be
  //    dropped as a part of 'pop' number of arguments),
  // 2) stack parameter is NOT included in JS arguments (and therefore it should
  //    be dropped in ADDITION to the 'pop' number of arguments).
  // Additionally, in order to simplify assembly code, PopAndReturn is also
  // not allowed in builtins with stub linkage and parameters on stack.
  CHECK_EQ(call_descriptor()->ParameterSlotCount(), 0);
  Node* values[] = {pop, value};
  Node* ret = MakeNode(common()->Return(1), 2, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::PopAndReturn(Node* pop, Node* v1, Node* v2) {
  Node* values[] = {pop, v1, v2};
  Node* ret = MakeNode(common()->Return(2), 3, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::PopAndReturn(Node* pop, Node* v1, Node* v2,
                                       Node* v3) {
  Node* values[] = {pop, v1, v2, v3};
  Node* ret = MakeNode(common()->Return(3), 4, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::PopAndReturn(Node* pop, Node* v1, Node* v2, Node* v3,
                                       Node* v4) {
  Node* values[] = {pop, v1, v2, v3, v4};
  Node* ret = MakeNode(common()->Return(4), 5, values);
  schedule()->AddReturn(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::AbortCSADcheck(Node* message) {
  AddNode(machine()->AbortCSADcheck(), message);
}

void RawMachineAssembler::DebugBreak() { AddNode(machine()->DebugBreak()); }

void RawMachineAssembler::Unreachable() {
  Node* ret = MakeNode(common()->Throw(), 0, nullptr);
  schedule()->AddThrow(CurrentBlock(), ret);
  current_block_ = nullptr;
}

void RawMachineAssembler::Comment(const std::string& msg) {
  size_t length = msg.length() + 1;
  char* zone_buffer = zone()->AllocateArray<char>(length);
  MemCopy(zone_buffer, msg.c_str(), length);
  AddNode(machine()->Comment(zone_buffer));
}

void RawMachineAssembler::StaticAssert(Node* value, const char* source) {
  AddNode(common()->StaticAssert(source), value);
}

Node* RawMachineAssembler::CallN(CallDescriptor* call_descriptor,
                                 int input_count, Node* const* inputs) {
  DCHECK(!call_descriptor->NeedsFrameState());
  // +1 is for target.
  DCHECK_EQ(input_count, call_descriptor->ParameterCount() + 1);
  return AddNode(common()->Call(call_descriptor), input_count, inputs);
}

Node* RawMachineAssembler::CallNWithFrameState(CallDescriptor* call_descriptor,
                                               int input_count,
                                               Node* const* inputs) {
  DCHECK(call_descriptor->NeedsFrameState());
  // +2 is for target and frame state.
  DCHECK_EQ(input_count, call_descriptor->ParameterCount() + 2);
  return AddNode(common()->Call(call_descriptor), input_count, inputs);
}

void RawMachineAssembler::TailCallN(CallDescriptor* call_descriptor,
                                    int input_count, Node* const* inputs) {
  // +1 is for target.
  DCHECK_EQ(input_count, call_descriptor->ParameterCount() + 1);
  Node* tail_call =
      MakeNode(common()->TailCall(call_descriptor), input_count, inputs);
  schedule()->AddTailCall(CurrentBlock(), tail_call);
  current_block_ = nullptr;
}

namespace {

enum FunctionDescriptorMode { kHasFunctionDescriptor, kNoFunctionDescriptor };

Node* CallCFunctionImpl(
    RawMachineAssembler* rasm, Node* function,
    std::optional<MachineType> return_type,
    std::initializer_list<RawMachineAssembler::CFunctionArg> args,
    bool caller_saved_regs, SaveFPRegsMode mode,
    FunctionDescriptorMode no_function_descriptor) {
  static constexpr std::size_t kNumCArgs = 10;

  MachineSignature::Builder builder(rasm->zone(), return_type ? 1 : 0,
                                    args.size());
  if (return_type) {
    builder.AddReturn(*return_type);
  }
  for (const auto& arg : args) builder.AddParam(arg.first);

  bool caller_saved_fp_regs =
      caller_saved_regs && (mode == SaveFPRegsMode::kSave);
  CallDescriptor::Flags flags = CallDescriptor::kNoFlags;
  if (caller_saved_regs) flags |= CallDescriptor::kCallerSavedRegisters;
  if (caller_saved_fp_regs) flags |= CallDescriptor::kCallerSavedFPRegisters;
  if (no_function_descriptor) flags |= CallDescriptor::kNoFunctionDescriptor;
  auto call_descriptor =
      Linkage::GetSimplifiedCDescriptor(rasm->zone(), builder.Get(), flags);

  base::SmallVector<Node*, kNumCArgs> nodes(args.size() + 1);
  nodes[0] = function;
  std::transform(
      args.begin(), args.end(), std::next(nodes.begin()),
      [](const RawMachineAssembler::CFunctionArg& arg) { return arg.second; });

  auto common = rasm->common();
  return rasm->AddNode(common->Call(call_descriptor),
                       static_cast<int>(nodes.size()), nodes.begin());
}

}  // namespace

Node* RawMachineAssembler::CallCFunction(
    Node* function, std::optional<MachineType> return_type,
    std::initializer_list<RawMachineAssembler::CFunctionArg> args) {
  return CallCFunctionImpl(this, function, return_type, args, false,
                           SaveFPRegsMode::kIgnore, kHasFunctionDescriptor);
}

Node* RawMachineAssembler::CallCFunctionWithoutFunctionDescriptor(
    Node* function, MachineType return_type,
    std::initializer_list<RawMachineAssembler::CFunctionArg> args) {
  return CallCFunctionImpl(this, function, return_type, args, false,
                           SaveFPRegsMode::kIgnore, kNoFunctionDescriptor);
}

Node* RawMachineAssembler::CallCFunctionWithCallerSavedRegisters(
    Node* function, MachineType return_type, SaveFPRegsMode mode,
    std::initializer_list<RawMachineAssembler::CFunctionArg> args) {
  return CallCFunctionImpl(this, function, return_type, args, true, mode,
                           kHasFunctionDescriptor);
}

BasicBlock* RawMachineAssembler::Use(RawMachineLabel* label) {
  label->used_ = true;
  return EnsureBlock(label);
}

BasicBlock* RawMachineAssembler::EnsureBlock(RawMachineLabel* label) {
  if (label->block_ == nullptr) {
    label->block_ = schedule()->NewBasicBlock();
  }
  return label->block_;
}

void RawMachineAssembler::Bind(RawMachineLabel* label) {
  DCHECK_NULL(current_block_);
  DCHECK(!label->bound_);
  label->bound_ = true;
  current_block_ = EnsureBlock(label);
  current_block_->set_deferred(label->deferred_);
}

#if DEBUG
void RawMachineAssembler::Bind(RawMachineLabel* label,
                               AssemblerDebugInfo info) {
  if (current_block_ != nullptr) {
    std::stringstream str;
    str << "Binding label without closing previous block:"
        << "\n#    label:          " << info
        << "\n#    previous block: " << *current_block_;
    FATAL("%s", str.str().c_str());
  }
  Bind(label);
  current_block_->set_debug_info(info);
}

void RawMachineAssembler::PrintCurrentBlock(std::ostream& os) {
  os << CurrentBlock();
}

void RawMachineAssembler::SetInitialDebugInformation(
    AssemblerDebugInfo debug_info) {
  CurrentBlock()->set_debug_info(debug_info);
}
#endif  // DEBUG

bool RawMachineAssembler::InsideBlock() { return current_block_ != nullptr; }

BasicBlock* RawMachineAssembler::CurrentBlock() {
  DCHECK(current_block_);
  return current_block_;
}

Node* RawMachineAssembler::Phi(MachineRepresentation rep, int input_count,
                               Node* const* inputs) {
  Node** buffer = zone()->AllocateArray<Node*>(input_count + 1);
  std::copy(inputs, inputs + input_count, buffer);
  buffer[input_count] = graph()->start();
  return AddNode(common()->Phi(rep, input_count), input_count + 1, buffer);
}

void RawMachineAssembler::AppendPhiInput(Node* phi, Node* new_input) {
  const Operator* op = phi->op();
  const Operator* new_op = common()->ResizeMergeOrPhi(op, phi->InputCount());
  phi->InsertInput(zone(), phi->InputCount() - 1, new_input);
  NodeProperties::ChangeOp(phi, new_op);
}

Node* RawMachineAssembler::AddNode(const Operator* op, int input_count,
                                   Node* const* inputs) {
  DCHECK_NOT_NULL(schedule_);
  DCHECK_NOT_NULL(current_block_);
  Node* node = MakeNode(op, input_count, inputs);
  schedule()->AddNode(CurrentBlock(), node);
  return node;
}

Node* RawMachineAssembler::MakeNode(const Operator* op, int input_count,
                                    Node* const* inputs) {
  // The raw machine assembler nodes do not have effect and control inputs,
  // so we disable checking input counts here.
  return graph()->NewNodeUnchecked(op, input_count, inputs);
}

RawMachineLabel::~RawMachineLabel() {
#if DEBUG
  if (bound_ == used_) return;
  std::stringstream str;
  if (bound_) {
    str << "A label has been bound but it's not used."
        << "\n#    label: " << *block_;
  } else {
    str << "A label has been used but it's not bound.";
  }
  FATAL("%s", str.str().c_str());
#endif  // DEBUG
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```