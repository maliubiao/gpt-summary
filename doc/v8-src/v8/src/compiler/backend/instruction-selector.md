Response: The user wants a summary of the C++ code in `v8/src/compiler/backend/instruction-selector.cc`. This is the first part of a larger file.

My plan is to:
1. **Identify the core responsibility of this code.**  Based on the file name, it's likely responsible for selecting machine instructions from a higher-level representation.
2. **Examine key classes and functions.** Look for constructors, core methods like `Visit...`, and any obvious data structures.
3. **Focus on the functionality within this specific section.**  Since this is part 1, I shouldn't try to summarize the entire file's functionality.
4. **Look for connections to JavaScript.**  This will likely involve mentions of concepts like `Smi`, `HeapObject`, or interactions with the V8 runtime.
5. **Provide a concise summary and a JavaScript example if applicable.** The example should illustrate how the concepts in the C++ code relate to JavaScript behavior.
This C++ code file, `instruction-selector.cc`, is the core of the instruction selection phase in the V8 compiler's backend. Its primary function is to translate a platform-independent intermediate representation (likely from Turbofan or Turboshaft, the optimization pipelines) of the JavaScript code into platform-specific machine instructions.

Here's a breakdown of its functionality in this first part:

* **Core Task: Instruction Selection:** The code defines the `InstructionSelectorT` template class (instantiated with `TurbofanAdapter` and `TurboshaftAdapter`), which is responsible for traversing the intermediate representation of the code and emitting corresponding machine instructions.
* **Visiting Operations:** It provides a `Visit##op` macro and default implementations for handling different operations (`op`). The `UNIMPLEMENTED()` indicates that specific instruction selection logic for each operation will likely be in the architecture-specific implementations or in later parts of this file.
* **Managing Instructions:** It maintains a list of `Instruction` objects (`instructions_`) that represent the selected machine instructions.
* **Handling Basic Blocks:** It processes the code basic block by basic block, respecting the control flow graph (`schedule_`).
* **Register Allocation Hints:**  It starts managing virtual registers (`virtual_registers_`) which are later mapped to physical registers during register allocation. It also handles renaming of virtual registers (`virtual_register_rename_`).
* **Tracking Definitions and Uses:** It keeps track of which nodes in the intermediate representation have been processed and defined as instructions (`defined_`) and which have their results used (`used_`).
* **Effect Levels:** It tracks the "effect level" of nodes, likely related to side effects and dependencies during instruction selection.
* **Source Position Tracking:** It interacts with a `source_position_table_t` to associate generated instructions with their original source code locations.
* **Deoptimization Support:**  It includes mechanisms for handling deoptimization, a process where optimized code needs to fall back to a less optimized version. This involves functions like `OperandForDeopt` and structures for managing frame state information.
* **Call Handling:** It introduces `CallBufferT` and `InitializeCallBuffer` for preparing arguments and outputs for function calls.
* **Flags Continuations:** It uses `FlagsContinuation` to represent control flow changes (like branches) and other effects that influence instruction selection.

**Relationship to JavaScript and Example:**

While this code doesn't directly *execute* JavaScript, it's crucial for how JavaScript code is ultimately run efficiently. The instruction selection process bridges the gap between the abstract representation of JavaScript logic and the concrete steps a processor needs to take.

A simple JavaScript example can illustrate the kind of operation this code deals with:

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

When the V8 compiler optimizes the `add` function, it might create an intermediate representation of the addition operation. The `InstructionSelector` (specifically the architecture-specific parts) would then be responsible for selecting the appropriate machine instruction(s) to perform the addition. For instance, on an x64 architecture, it might select an `ADD` instruction.

The `instruction-selector.cc` also deals with more complex JavaScript concepts:

* **`Smi`:** The `NumberConstantToSmi` function suggests it handles small integers, which are often represented as `Smi` (Small Integer) in V8 for efficiency. In the JavaScript example, the constants `5` and `10` might initially be represented as Smis.
* **Heap Objects:** The code interacts with `JSHeapBroker` and has logic for handling `HeapObject` constants during deoptimization. In JavaScript, objects, strings, and functions are heap objects.
* **Function Calls:** The `CallBufferT` and related logic handle the intricacies of calling JavaScript functions, including setting up arguments and managing the call stack.

**In essence, this part of `instruction-selector.cc` sets up the foundational framework for translating JavaScript's operations into the low-level instructions that the CPU can understand and execute. It manages the core data structures, the overall selection process, and handles fundamental aspects like deoptimization and function calls.**

Prompt: 
```
这是目录为v8/src/compiler/backend/instruction-selector.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/backend/instruction-selector.h"

#include <limits>
#include <optional>

#include "include/v8-internal.h"
#include "src/base/iterator.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/tick-counter.h"
#include "src/common/globals.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/backend/instruction.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/globals.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/schedule.h"
#include "src/compiler/state-values-utils.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/numbers/conversions-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/simd-shuffle.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {
namespace compiler {

#define VISIT_UNSUPPORTED_OP(op)                          \
  template <typename Adapter>                             \
  void InstructionSelectorT<Adapter>::Visit##op(node_t) { \
    UNIMPLEMENTED();                                      \
  }

namespace {
// Here we really want the raw Bits of the mask, but the `.bits()` method is
// not constexpr, and so users of this constant need to call it.
// TODO(turboshaft): EffectDimensions could probably be defined via
// base::Flags<> instead, which should solve this.
constexpr turboshaft::EffectDimensions kTurboshaftEffectLevelMask =
    turboshaft::OpEffects().CanReadMemory().produces;
}

Tagged<Smi> NumberConstantToSmi(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kNumberConstant);
  const double d = OpParameter<double>(node->op());
  Tagged<Smi> smi = Smi::FromInt(static_cast<int32_t>(d));
  CHECK_EQ(smi.value(), d);
  return smi;
}

template <typename Adapter>
InstructionSelectorT<Adapter>::InstructionSelectorT(
    Zone* zone, size_t node_count, Linkage* linkage,
    InstructionSequence* sequence, schedule_t schedule,
    source_position_table_t* source_positions, Frame* frame,
    InstructionSelector::EnableSwitchJumpTable enable_switch_jump_table,
    TickCounter* tick_counter, JSHeapBroker* broker,
    size_t* max_unoptimized_frame_height, size_t* max_pushed_argument_count,
    InstructionSelector::SourcePositionMode source_position_mode,
    Features features, InstructionSelector::EnableScheduling enable_scheduling,
    InstructionSelector::EnableRootsRelativeAddressing
        enable_roots_relative_addressing,
    InstructionSelector::EnableTraceTurboJson trace_turbo)
    : Adapter(schedule),
      zone_(zone),
      linkage_(linkage),
      sequence_(sequence),
      source_positions_(source_positions),
      source_position_mode_(source_position_mode),
      features_(features),
      schedule_(schedule),
      current_block_(nullptr),
      instructions_(zone),
      continuation_inputs_(sequence->zone()),
      continuation_outputs_(sequence->zone()),
      continuation_temps_(sequence->zone()),
      defined_(static_cast<int>(node_count), zone),
      used_(static_cast<int>(node_count), zone),
      effect_level_(node_count, 0, zone),
      virtual_registers_(node_count,
                         InstructionOperand::kInvalidVirtualRegister, zone),
      virtual_register_rename_(zone),
      scheduler_(nullptr),
      enable_scheduling_(enable_scheduling),
      enable_roots_relative_addressing_(enable_roots_relative_addressing),
      enable_switch_jump_table_(enable_switch_jump_table),
      state_values_cache_(zone),
      frame_(frame),
      instruction_selection_failed_(false),
      instr_origins_(sequence->zone()),
      trace_turbo_(trace_turbo),
      tick_counter_(tick_counter),
      broker_(broker),
      max_unoptimized_frame_height_(max_unoptimized_frame_height),
      max_pushed_argument_count_(max_pushed_argument_count)
#if V8_TARGET_ARCH_64_BIT
      ,
      node_count_(node_count),
      phi_states_(zone)
#endif
{
  if constexpr (Adapter::IsTurboshaft) {
    turboshaft_use_map_.emplace(*schedule_, zone);
    protected_loads_to_remove_.emplace(static_cast<int>(node_count), zone);
    additional_protected_instructions_.emplace(static_cast<int>(node_count),
                                               zone);
  }

  DCHECK_EQ(*max_unoptimized_frame_height, 0);  // Caller-initialized.

  instructions_.reserve(node_count);
  continuation_inputs_.reserve(5);
  continuation_outputs_.reserve(2);

  if (trace_turbo_ == InstructionSelector::kEnableTraceTurboJson) {
    instr_origins_.assign(node_count, {-1, 0});
  }
}

template <typename Adapter>
std::optional<BailoutReason>
InstructionSelectorT<Adapter>::SelectInstructions() {
  // Mark the inputs of all phis in loop headers as used.
  block_range_t blocks = this->rpo_order(schedule());
  for (const block_t block : blocks) {
    if (!this->IsLoopHeader(block)) continue;
    DCHECK_LE(2u, this->PredecessorCount(block));
    for (node_t node : this->nodes(block)) {
      if (!this->IsPhi(node)) continue;

      // Mark all inputs as used.
      for (node_t input : this->inputs(node)) {
        MarkAsUsed(input);
      }
    }
  }

  // Visit each basic block in post order.
  for (auto i = blocks.rbegin(); i != blocks.rend(); ++i) {
    VisitBlock(*i);
    if (instruction_selection_failed())
      return BailoutReason::kCodeGenerationFailed;
  }

  // Schedule the selected instructions.
  if (UseInstructionScheduling()) {
    scheduler_ = zone()->template New<InstructionScheduler>(zone(), sequence());
  }

  for (const block_t block : blocks) {
    InstructionBlock* instruction_block =
        sequence()->InstructionBlockAt(this->rpo_number(block));
    for (size_t i = 0; i < instruction_block->phis().size(); i++) {
      UpdateRenamesInPhi(instruction_block->PhiAt(i));
    }
    size_t end = instruction_block->code_end();
    size_t start = instruction_block->code_start();
    DCHECK_LE(end, start);
    StartBlock(this->rpo_number(block));
    if (end != start) {
      while (start-- > end + 1) {
        UpdateRenames(instructions_[start]);
        AddInstruction(instructions_[start]);
      }
      UpdateRenames(instructions_[end]);
      AddTerminator(instructions_[end]);
    }
    EndBlock(this->rpo_number(block));
  }
#if DEBUG
  sequence()->ValidateSSA();
#endif
  return std::nullopt;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::StartBlock(RpoNumber rpo) {
  if (UseInstructionScheduling()) {
    DCHECK_NOT_NULL(scheduler_);
    scheduler_->StartBlock(rpo);
  } else {
    sequence()->StartBlock(rpo);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::EndBlock(RpoNumber rpo) {
  if (UseInstructionScheduling()) {
    DCHECK_NOT_NULL(scheduler_);
    scheduler_->EndBlock(rpo);
  } else {
    sequence()->EndBlock(rpo);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddTerminator(Instruction* instr) {
  if (UseInstructionScheduling()) {
    DCHECK_NOT_NULL(scheduler_);
    scheduler_->AddTerminator(instr);
  } else {
    sequence()->AddInstruction(instr);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::AddInstruction(Instruction* instr) {
  if (UseInstructionScheduling()) {
    DCHECK_NOT_NULL(scheduler_);
    scheduler_->AddInstruction(instr);
  } else {
    sequence()->AddInstruction(instr);
  }
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(InstructionCode opcode,
                                                 InstructionOperand output,
                                                 size_t temp_count,
                                                 InstructionOperand* temps) {
  size_t output_count = output.IsInvalid() ? 0 : 1;
  return Emit(opcode, output_count, &output, 0, nullptr, temp_count, temps);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(InstructionCode opcode,
                                                 InstructionOperand output,
                                                 InstructionOperand a,
                                                 size_t temp_count,
                                                 InstructionOperand* temps) {
  size_t output_count = output.IsInvalid() ? 0 : 1;
  return Emit(opcode, output_count, &output, 1, &a, temp_count, temps);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(
    InstructionCode opcode, InstructionOperand output, InstructionOperand a,
    InstructionOperand b, size_t temp_count, InstructionOperand* temps) {
  size_t output_count = output.IsInvalid() ? 0 : 1;
  InstructionOperand inputs[] = {a, b};
  size_t input_count = arraysize(inputs);
  return Emit(opcode, output_count, &output, input_count, inputs, temp_count,
              temps);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(
    InstructionCode opcode, InstructionOperand output, InstructionOperand a,
    InstructionOperand b, InstructionOperand c, size_t temp_count,
    InstructionOperand* temps) {
  size_t output_count = output.IsInvalid() ? 0 : 1;
  InstructionOperand inputs[] = {a, b, c};
  size_t input_count = arraysize(inputs);
  return Emit(opcode, output_count, &output, input_count, inputs, temp_count,
              temps);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(
    InstructionCode opcode, InstructionOperand output, InstructionOperand a,
    InstructionOperand b, InstructionOperand c, InstructionOperand d,
    size_t temp_count, InstructionOperand* temps) {
  size_t output_count = output.IsInvalid() ? 0 : 1;
  InstructionOperand inputs[] = {a, b, c, d};
  size_t input_count = arraysize(inputs);
  return Emit(opcode, output_count, &output, input_count, inputs, temp_count,
              temps);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(
    InstructionCode opcode, InstructionOperand output, InstructionOperand a,
    InstructionOperand b, InstructionOperand c, InstructionOperand d,
    InstructionOperand e, size_t temp_count, InstructionOperand* temps) {
  size_t output_count = output.IsInvalid() ? 0 : 1;
  InstructionOperand inputs[] = {a, b, c, d, e};
  size_t input_count = arraysize(inputs);
  return Emit(opcode, output_count, &output, input_count, inputs, temp_count,
              temps);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(
    InstructionCode opcode, InstructionOperand output, InstructionOperand a,
    InstructionOperand b, InstructionOperand c, InstructionOperand d,
    InstructionOperand e, InstructionOperand f, size_t temp_count,
    InstructionOperand* temps) {
  size_t output_count = output.IsInvalid() ? 0 : 1;
  InstructionOperand inputs[] = {a, b, c, d, e, f};
  size_t input_count = arraysize(inputs);
  return Emit(opcode, output_count, &output, input_count, inputs, temp_count,
              temps);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(
    InstructionCode opcode, InstructionOperand output, InstructionOperand a,
    InstructionOperand b, InstructionOperand c, InstructionOperand d,
    InstructionOperand e, InstructionOperand f, InstructionOperand g,
    InstructionOperand h, size_t temp_count, InstructionOperand* temps) {
  size_t output_count = output.IsInvalid() ? 0 : 1;
  InstructionOperand inputs[] = {a, b, c, d, e, f, g, h};
  size_t input_count = arraysize(inputs);
  return Emit(opcode, output_count, &output, input_count, inputs, temp_count,
              temps);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(
    InstructionCode opcode, size_t output_count, InstructionOperand* outputs,
    size_t input_count, InstructionOperand* inputs, size_t temp_count,
    InstructionOperand* temps) {
  if (output_count >= Instruction::kMaxOutputCount ||
      input_count >= Instruction::kMaxInputCount ||
      temp_count >= Instruction::kMaxTempCount) {
    set_instruction_selection_failed();
    return nullptr;
  }

  Instruction* instr =
      Instruction::New(instruction_zone(), opcode, output_count, outputs,
                       input_count, inputs, temp_count, temps);
  return Emit(instr);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::Emit(Instruction* instr) {
  instructions_.push_back(instr);
  return instr;
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::CanCover(node_t user, node_t node) const {
  // 1. Both {user} and {node} must be in the same basic block.
  if (this->block(schedule(), node) != current_block_) {
    return false;
  }

  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Operation& op = this->Get(node);
    // 2. If node does not produce anything, it can be covered.
    if (op.Effects().produces.bits() == 0) {
      return this->is_exclusive_user_of(user, node);
    }
  } else {
    // 2. Pure {node}s must be owned by the {user}.
    if (node->op()->HasProperty(Operator::kPure)) {
      return node->OwnedBy(user);
    }
  }

  // 3. Otherwise, the {node}'s effect level must match the {user}'s.
  if (GetEffectLevel(node) != current_effect_level_) {
    return false;
  }

  // 4. Only {node} must have value edges pointing to {user}.
  return this->is_exclusive_user_of(user, node);
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::CanCoverProtectedLoad(node_t user,
                                                          node_t node) const {
  if constexpr (Adapter::IsTurboshaft) {
    DCHECK(CanCover(user, node));
    const turboshaft::Graph* graph = this->turboshaft_graph();
    for (turboshaft::OpIndex next = graph->NextIndex(node); next.valid();
         next = graph->NextIndex(next)) {
      if (next == user) break;
      const turboshaft::Operation& op = graph->Get(next);
      turboshaft::OpEffects effects = op.Effects();
      if (effects.produces.control_flow || effects.required_when_unused) {
        return false;
      }
    }
    return true;
  } else {
    UNREACHABLE();
  }
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsOnlyUserOfNodeInSameBlock(
    node_t user, node_t node) const {
  block_t bb_user = this->block(schedule(), user);
  block_t bb_node = this->block(schedule(), node);
  if (bb_user != bb_node) return false;

  if constexpr (Adapter::IsTurboshaft) {
    const turboshaft::Operation& node_op = this->turboshaft_graph()->Get(node);
    if (node_op.saturated_use_count.Get() == 1) return true;
    for (turboshaft::OpIndex use : turboshaft_uses(node)) {
      if (use == user) continue;
      if (this->block(schedule(), use) == bb_user) return false;
    }
    return true;
  } else {
    for (Edge const edge : node->use_edges()) {
      Node* from = edge.from();
      if ((from != user) && (this->block(schedule(), from) == bb_user)) {
        return false;
      }
    }
  }
  return true;
}

template <>
Node* InstructionSelectorT<TurbofanAdapter>::FindProjection(
    Node* node, size_t projection_index) {
  return NodeProperties::FindProjection(node, projection_index);
}

template <>
turboshaft::OpIndex InstructionSelectorT<TurboshaftAdapter>::FindProjection(
    turboshaft::OpIndex node, size_t projection_index) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  const turboshaft::Graph* graph = this->turboshaft_graph();
  // Projections are always emitted right after the operation.
  for (OpIndex next = graph->NextIndex(node); next.valid();
       next = graph->NextIndex(next)) {
    const ProjectionOp* projection = graph->Get(next).TryCast<ProjectionOp>();
    if (projection == nullptr) break;
    DCHECK(!projection->saturated_use_count.IsZero());
    if (projection->saturated_use_count.IsOne()) {
      // If the projection has a single use, it is the following tuple, so we
      // don't return it, since there is no point in emitting it.
      DCHECK(turboshaft_uses(next).size() == 1 &&
             graph->Get(turboshaft_uses(next)[0]).Is<TupleOp>());
      continue;
    }
    if (projection->index == projection_index) return next;
  }

  // If there is no Projection with index {projection_index} following the
  // operation, then there shouldn't be any such Projection in the graph. We
  // verify this in Debug mode.
#ifdef DEBUG
  for (OpIndex use : turboshaft_uses(node)) {
    if (const ProjectionOp* projection =
            this->Get(use).TryCast<ProjectionOp>()) {
      DCHECK_EQ(projection->input(), node);
      if (projection->index == projection_index) {
        // If we found the projection, it should have a single use: a Tuple
        // (which doesn't count as a regular use since it is just an artifact of
        // the Turboshaft graph).
        DCHECK(turboshaft_uses(use).size() == 1 &&
               graph->Get(turboshaft_uses(use)[0]).Is<TupleOp>());
      }
    }
  }
#endif  // DEBUG
  return OpIndex::Invalid();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::UpdateRenames(Instruction* instruction) {
  for (size_t i = 0; i < instruction->InputCount(); i++) {
    TryRename(instruction->InputAt(i));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::UpdateRenamesInPhi(PhiInstruction* phi) {
  for (size_t i = 0; i < phi->operands().size(); i++) {
    int vreg = phi->operands()[i];
    int renamed = GetRename(vreg);
    if (vreg != renamed) {
      phi->RenameInput(i, renamed);
    }
  }
}

template <typename Adapter>
int InstructionSelectorT<Adapter>::GetRename(int virtual_register) {
  int rename = virtual_register;
  while (true) {
    if (static_cast<size_t>(rename) >= virtual_register_rename_.size()) break;
    int next = virtual_register_rename_[rename];
    if (next == InstructionOperand::kInvalidVirtualRegister) {
      break;
    }
    rename = next;
  }
  return rename;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::TryRename(InstructionOperand* op) {
  if (!op->IsUnallocated()) return;
  UnallocatedOperand* unalloc = UnallocatedOperand::cast(op);
  int vreg = unalloc->virtual_register();
  int rename = GetRename(vreg);
  if (rename != vreg) {
    *unalloc = UnallocatedOperand(*unalloc, rename);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::SetRename(node_t node, node_t rename) {
  int vreg = GetVirtualRegister(node);
  if (static_cast<size_t>(vreg) >= virtual_register_rename_.size()) {
    int invalid = InstructionOperand::kInvalidVirtualRegister;
    virtual_register_rename_.resize(vreg + 1, invalid);
  }
  virtual_register_rename_[vreg] = GetVirtualRegister(rename);
}

template <typename Adapter>
int InstructionSelectorT<Adapter>::GetVirtualRegister(node_t node) {
  DCHECK(this->valid(node));
  size_t const id = this->id(node);
  DCHECK_LT(id, virtual_registers_.size());
  int virtual_register = virtual_registers_[id];
  if (virtual_register == InstructionOperand::kInvalidVirtualRegister) {
    virtual_register = sequence()->NextVirtualRegister();
    virtual_registers_[id] = virtual_register;
  }
  return virtual_register;
}

template <typename Adapter>
const std::map<typename Adapter::id_t, int>
InstructionSelectorT<Adapter>::GetVirtualRegistersForTesting() const {
  std::map<typename Adapter::id_t, int> virtual_registers;
  for (size_t n = 0; n < virtual_registers_.size(); ++n) {
    if (virtual_registers_[n] != InstructionOperand::kInvalidVirtualRegister) {
      typename Adapter::id_t const id = static_cast<typename Adapter::id_t>(n);
      virtual_registers.insert(std::make_pair(id, virtual_registers_[n]));
    }
  }
  return virtual_registers;
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsDefined(node_t node) const {
  DCHECK(this->valid(node));
  return defined_.Contains(this->id(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::MarkAsDefined(node_t node) {
  DCHECK(this->valid(node));
  defined_.Add(this->id(node));
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsUsed(node_t node) const {
  DCHECK(this->valid(node));
  if constexpr (Adapter::IsTurbofan) {
    // TODO(bmeurer): This is a terrible monster hack, but we have to make sure
    // that the Retain is actually emitted, otherwise the GC will mess up.
    if (this->IsRetain(node)) return true;
  } else {
    static_assert(Adapter::IsTurboshaft);
    if (!turboshaft::ShouldSkipOptimizationStep() &&
        turboshaft::ShouldSkipOperation(this->Get(node))) {
      return false;
    }
  }
  if (this->IsRequiredWhenUnused(node)) return true;
  return used_.Contains(this->id(node));
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::IsReallyUsed(node_t node) const {
  DCHECK(this->valid(node));
  if constexpr (Adapter::IsTurbofan) {
    // TODO(bmeurer): This is a terrible monster hack, but we have to make sure
    // that the Retain is actually emitted, otherwise the GC will mess up.
    if (this->IsRetain(node)) return true;
  } else {
    static_assert(Adapter::IsTurboshaft);
    if (!turboshaft::ShouldSkipOptimizationStep() &&
        turboshaft::ShouldSkipOperation(this->Get(node))) {
      return false;
    }
  }
  return used_.Contains(this->id(node));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::MarkAsUsed(node_t node) {
  DCHECK(this->valid(node));
  used_.Add(this->id(node));
}

template <typename Adapter>
int InstructionSelectorT<Adapter>::GetEffectLevel(node_t node) const {
  DCHECK(this->valid(node));
  size_t const id = this->id(node);
  DCHECK_LT(id, effect_level_.size());
  return effect_level_[id];
}

template <typename Adapter>
int InstructionSelectorT<Adapter>::GetEffectLevel(
    node_t node, FlagsContinuation* cont) const {
  return cont->IsBranch() ? GetEffectLevel(this->block_terminator(
                                this->PredecessorAt(cont->true_block(), 0)))
                          : GetEffectLevel(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::SetEffectLevel(node_t node,
                                                   int effect_level) {
  DCHECK(this->valid(node));
  size_t const id = this->id(node);
  DCHECK_LT(id, effect_level_.size());
  effect_level_[id] = effect_level;
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::CanAddressRelativeToRootsRegister(
    const ExternalReference& reference) const {
  // There are three things to consider here:
  // 1. CanUseRootsRegister: Is kRootRegister initialized?
  const bool root_register_is_available_and_initialized = CanUseRootsRegister();
  if (!root_register_is_available_and_initialized) return false;

  // 2. enable_roots_relative_addressing_: Can we address everything on the heap
  //    through the root register, i.e. are root-relative addresses to arbitrary
  //    addresses guaranteed not to change between code generation and
  //    execution?
  const bool all_root_relative_offsets_are_constant =
      (enable_roots_relative_addressing_ ==
       InstructionSelector::kEnableRootsRelativeAddressing);
  if (all_root_relative_offsets_are_constant) return true;

  // 3. IsAddressableThroughRootRegister: Is the target address guaranteed to
  //    have a fixed root-relative offset? If so, we can ignore 2.
  const bool this_root_relative_offset_is_constant =
      MacroAssemblerBase::IsAddressableThroughRootRegister(isolate(),
                                                           reference);
  return this_root_relative_offset_is_constant;
}

template <typename Adapter>
bool InstructionSelectorT<Adapter>::CanUseRootsRegister() const {
  return linkage()->GetIncomingDescriptor()->flags() &
         CallDescriptor::kCanUseRoots;
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::MarkAsRepresentation(
    MachineRepresentation rep, const InstructionOperand& op) {
  UnallocatedOperand unalloc = UnallocatedOperand::cast(op);
  sequence()->MarkAsRepresentation(rep, unalloc.virtual_register());
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::MarkAsRepresentation(
    MachineRepresentation rep, node_t node) {
  sequence()->MarkAsRepresentation(rep, GetVirtualRegister(node));
}

namespace {

InstructionOperand OperandForDeopt(Isolate* isolate,
                                   OperandGeneratorT<TurboshaftAdapter>* g,
                                   turboshaft::OpIndex input,
                                   FrameStateInputKind kind,
                                   MachineRepresentation rep) {
  if (rep == MachineRepresentation::kNone) {
    return g->TempImmediate(FrameStateDescriptor::kImpossibleValue);
  }

  const turboshaft::Operation& op = g->turboshaft_graph()->Get(input);
  if (const turboshaft::ConstantOp* constant =
          op.TryCast<turboshaft::ConstantOp>()) {
    using Kind = turboshaft::ConstantOp::Kind;
    switch (constant->kind) {
      case Kind::kWord32:
      case Kind::kWord64:
      case Kind::kSmi:
      case Kind::kFloat32:
      case Kind::kFloat64:
        return g->UseImmediate(input);
      case Kind::kNumber:
        if (rep == MachineRepresentation::kWord32) {
          const double d = constant->number().get_scalar();
          Tagged<Smi> smi = Smi::FromInt(static_cast<int32_t>(d));
          CHECK_EQ(smi.value(), d);
          return g->UseImmediate(static_cast<int32_t>(smi.ptr()));
        }
        return g->UseImmediate(input);
      case turboshaft::ConstantOp::Kind::kHeapObject:
      case turboshaft::ConstantOp::Kind::kCompressedHeapObject:
      case turboshaft::ConstantOp::Kind::kTrustedHeapObject: {
        if (!CanBeTaggedOrCompressedPointer(rep)) {
          // If we have inconsistent static and dynamic types, e.g. if we
          // smi-check a string, we can get here with a heap object that
          // says it is a smi. In that case, we return an invalid instruction
          // operand, which will be interpreted as an optimized-out value.

          // TODO(jarin) Ideally, we should turn the current instruction
          // into an abort (we should never execute it).
          return InstructionOperand();
        }

        Handle<HeapObject> object = constant->handle();
        RootIndex root_index;
        if (isolate->roots_table().IsRootHandle(object, &root_index) &&
            root_index == RootIndex::kOptimizedOut) {
          // For an optimized-out object we return an invalid instruction
          // operand, so that we take the fast path for optimized-out values.
          return InstructionOperand();
        }

        return g->UseImmediate(input);
      }
      default:
        UNIMPLEMENTED();
    }
  } else if (const turboshaft::TaggedBitcastOp* bitcast =
                 op.TryCast<turboshaft::Opmask::kTaggedBitcastSmi>()) {
    const turboshaft::Operation& input = g->Get(bitcast->input());
    if (const turboshaft::ConstantOp* cst =
            input.TryCast<turboshaft::Opmask::kWord32Constant>()) {
      if constexpr (Is64()) {
        return g->UseImmediate64(cst->word32());
      } else {
        return g->UseImmediate(cst->word32());
      }
    } else if (Is64() && input.Is<turboshaft::Opmask::kWord64Constant>()) {
      if (rep == MachineRepresentation::kWord32) {
        return g->UseImmediate(input.Cast<turboshaft::ConstantOp>().word32());
      } else {
        return g->UseImmediate64(input.Cast<turboshaft::ConstantOp>().word64());
      }
    }
  }

  switch (kind) {
    case FrameStateInputKind::kStackSlot:
      return g->UseUniqueSlot(input);
    case FrameStateInputKind::kAny:
      // Currently deopts "wrap" other operations, so the deopt's inputs
      // are potentially needed until the end of the deoptimising code.
      return g->UseAnyAtEnd(input);
  }
}

InstructionOperand OperandForDeopt(Isolate* isolate,
                                   OperandGeneratorT<TurbofanAdapter>* g,
                                   Node* input, FrameStateInputKind kind,
                                   MachineRepresentation rep) {
  if (rep == MachineRepresentation::kNone) {
    return g->TempImmediate(FrameStateDescriptor::kImpossibleValue);
  }

  switch (input->opcode()) {
    case IrOpcode::kInt32Constant:
    case IrOpcode::kInt64Constant:
    case IrOpcode::kFloat32Constant:
    case IrOpcode::kFloat64Constant:
      return g->UseImmediate(input);
    case IrOpcode::kNumberConstant:
      if (rep == MachineRepresentation::kWord32) {
        Tagged<Smi> smi = NumberConstantToSmi(input);
        return g->UseImmediate(static_cast<int32_t>(smi.ptr()));
      } else {
        return g->UseImmediate(input);
      }
    case IrOpcode::kHeapConstant:
    case IrOpcode::kCompressedHeapConstant:
    case IrOpcode::kTrustedHeapConstant: {
      if (!CanBeTaggedOrCompressedPointer(rep)) {
        // If we have inconsistent static and dynamic types, e.g. if we
        // smi-check a string, we can get here with a heap object that
        // says it is a smi. In that case, we return an invalid instruction
        // operand, which will be interpreted as an optimized-out value.

        // TODO(jarin) Ideally, we should turn the current instruction
        // into an abort (we should never execute it).
        return InstructionOperand();
      }

      Handle<HeapObject> constant = HeapConstantOf(input->op());
      RootIndex root_index;
      if (isolate->roots_table().IsRootHandle(constant, &root_index) &&
          root_index == RootIndex::kOptimizedOut) {
        // For an optimized-out object we return an invalid instruction
        // operand, so that we take the fast path for optimized-out values.
        return InstructionOperand();
      }

      return g->UseImmediate(input);
    }
    case IrOpcode::kArgumentsElementsState:
    case IrOpcode::kArgumentsLengthState:
    case IrOpcode::kObjectState:
    case IrOpcode::kTypedObjectState:
      UNREACHABLE();
    case IrOpcode::kBitcastWordToTaggedSigned: {
      if (input->InputAt(0)->opcode() == IrOpcode::kInt32Constant) {
        int32_t value = OpParameter<int32_t>(input->InputAt(0)->op());
        if constexpr (Is64()) {
          return g->UseImmediate64(value);
        } else {
          return g->UseImmediate(value);
        }
      } else if (Is64() &&
                 input->InputAt(0)->opcode() == IrOpcode::kInt64Constant) {
        int64_t value = OpParameter<int64_t>(input->InputAt(0)->op());
        if (rep == MachineRepresentation::kWord32) {
          return g->UseImmediate(static_cast<int>(value));
        } else {
          return g->UseImmediate64(value);
        }
      }
    }
      [[fallthrough]];
    default:
      switch (kind) {
        case FrameStateInputKind::kStackSlot:
          return g->UseUniqueSlot(input);
        case FrameStateInputKind::kAny:
          // Currently deopts "wrap" other operations, so the deopt's inputs
          // are potentially needed until the end of the deoptimising code.
          return g->UseAnyAtEnd(input);
      }
  }
  UNREACHABLE();
}

}  // namespace

class TurbofanStateObjectDeduplicator {
 public:
  explicit TurbofanStateObjectDeduplicator(Zone* zone) : objects_(zone) {}
  static const size_t kNotDuplicated = SIZE_MAX;

  size_t GetObjectId(Node* node) {
    DCHECK(node->opcode() == IrOpcode::kTypedObjectState ||
           node->opcode() == IrOpcode::kObjectId ||
           node->opcode() == IrOpcode::kArgumentsElementsState);
    for (size_t i = 0; i < objects_.size(); ++i) {
      if (objects_[i] == node) return i;
      // ObjectId nodes are the Turbofan way to express objects with the same
      // identity in the deopt info. So they should always be mapped to
      // previously appearing TypedObjectState nodes.
      if (HasObjectId(objects_[i]) && HasObjectId(node) &&
          ObjectIdOf(objects_[i]->op()) == ObjectIdOf(node->op())) {
        return i;
      }
    }
    DCHECK(node->opcode() == IrOpcode::kTypedObjectState ||
           node->opcode() == IrOpcode::kArgumentsElementsState);
    return kNotDuplicated;
  }

  size_t InsertObject(Node* node) {
    DCHECK(node->opcode() == IrOpcode::kTypedObjectState ||
           node->opcode() == IrOpcode::kObjectId ||
           node->opcode() == IrOpcode::kArgumentsElementsState);
    size_t id = objects_.size();
    objects_.push_back(node);
    return id;
  }

  size_t size() const { return objects_.size(); }

 private:
  static bool HasObjectId(Node* node) {
    return node->opcode() == IrOpcode::kTypedObjectState ||
           node->opcode() == IrOpcode::kObjectId;
  }

  ZoneVector<Node*> objects_;
};

class TurboshaftStateObjectDeduplicator {
 public:
  explicit TurboshaftStateObjectDeduplicator(Zone* zone) : object_ids_(zone) {}
  static constexpr uint32_t kArgumentsElementsDummy =
      std::numeric_limits<uint32_t>::max();
  static constexpr size_t kNotDuplicated = std::numeric_limits<size_t>::max();

  size_t GetObjectId(uint32_t object) {
    for (size_t i = 0; i < object_ids_.size(); ++i) {
      if (object_ids_[i] == object) return i;
    }
    return kNotDuplicated;
  }

  size_t InsertObject(uint32_t object) {
    object_ids_.push_back(object);
    return object_ids_.size() - 1;
  }

  void InsertDummyForArgumentsElements() {
    object_ids_.push_back(kArgumentsElementsDummy);
  }

  size_t size() const { return object_ids_.size(); }

 private:
  ZoneVector<uint32_t> object_ids_;
};

// Returns the number of instruction operands added to inputs.
template <>
size_t InstructionSelectorT<TurbofanAdapter>::AddOperandToStateValueDescriptor(
    StateValueList* values, InstructionOperandVector* inputs,
    OperandGeneratorT<TurbofanAdapter>* g,
    StateObjectDeduplicator* deduplicator, Node* input, MachineType type,
    FrameStateInputKind kind, Zone* zone) {
  DCHECK_NOT_NULL(input);
  switch (input->opcode()) {
    case IrOpcode::kArgumentsElementsState: {
      values->PushArgumentsElements(ArgumentsStateTypeOf(input->op()));
      // The elements backing store of an arguments object participates in the
      // duplicate object counting, but can itself never appear duplicated.
      DCHECK_EQ(StateObjectDeduplicator::kNotDuplicated,
                deduplicator->GetObjectId(input));
      deduplicator->InsertObject(input);
      return 0;
    }
    case IrOpcode::kArgumentsLengthState: {
      values->PushArgumentsLength();
      return 0;
    }
    case IrOpcode::kObjectState:
      UNREACHABLE();
    case IrOpcode::kTypedObjectState:
    case IrOpcode::kObjectId: {
      size_t id = deduplicator->GetObjectId(input);
      if (id == StateObjectDeduplicator::kNotDuplicated) {
        DCHECK_EQ(IrOpcode::kTypedObjectState, input->opcode());
        size_t entries = 0;
        id = deduplicator->InsertObject(input);
        StateValueList* nested = values->PushRecursiveField(zone, id);
        int const input_count = input->op()->ValueInputCount();
        ZoneVector<MachineType> const* types = MachineTypesOf(input->op());
        for (int i = 0; i < input_count; ++i) {
          entries += AddOperandToStateValueDescriptor(
              nested, inputs, g, deduplicator, input->InputAt(i), types->at(i),
              kind, zone);
        }
        return entries;
      } else {
        // Deoptimizer counts duplicate objects for the running id, so we have
        // to push the input again.
        deduplicator->InsertObject(input);
        values->PushDuplicate(id);
        return 0;
      }
    }
    default: {
      InstructionOperand op =
          OperandForDeopt(isolate(), g, input, kind, type.representation());
      if (op.kind() == InstructionOperand::INVALID) {
        // Invalid operand means the value is impossible or optimized-out.
        values->PushOptimizedOut();
        return 0;
      } else {
        inputs->push_back(op);
        values->PushPlain(type);
        return 1;
      }
    }
  }
}

template <typename Adapter>
struct InstructionSelectorT<Adapter>::CachedStateValues : public ZoneObject {
 public:
  CachedStateValues(Zone* zone, StateValueList* values, size_t values_start,
                    InstructionOperandVector* inputs, size_t inputs_start)
      : inputs_(inputs->begin() + inputs_start, inputs->end(), zone),
        values_(values->MakeSlice(values_start)) {}

  size_t Emit(InstructionOperandVector* inputs, StateValueList* values) {
    inputs->insert(inputs->end(), inputs_.begin(), inputs_.end());
    values->PushCachedSlice(values_);
    return inputs_.size();
  }

 private:
  InstructionOperandVector inputs_;
  StateValueList::Slice values_;
};

template <typename Adapter>
class InstructionSelectorT<Adapter>::CachedStateValuesBuilder {
 public:
  explicit CachedStateValuesBuilder(StateValueList* values,
                                    InstructionOperandVector* inputs,
                                    StateObjectDeduplicator* deduplicator)
      : values_(values),
        inputs_(inputs),
        deduplicator_(deduplicator),
        values_start_(values->size()),
        nested_start_(values->nested_count()),
        inputs_start_(inputs->size()),
        deduplicator_start_(deduplicator->size()) {}

  // We can only build a CachedStateValues for a StateValue if it didn't update
  // any of the ids in the deduplicator.
  bool CanCache() const { return deduplicator_->size() == deduplicator_start_; }

  InstructionSelectorT<Adapter>::CachedStateValues* Build(Zone* zone) {
    DCHECK(CanCache());
    DCHECK(values_->nested_count() == nested_start_);
    return zone->New<InstructionSelectorT<Adapter>::CachedStateValues>(
        zone, values_, values_start_, inputs_, inputs_start_);
  }

 private:
  StateValueList* values_;
  InstructionOperandVector* inputs_;
  StateObjectDeduplicator* deduplicator_;
  size_t values_start_;
  size_t nested_start_;
  size_t inputs_start_;
  size_t deduplicator_start_;
};

template <>
size_t InstructionSelectorT<TurbofanAdapter>::AddInputsToFrameStateDescriptor(
    StateValueList* values, InstructionOperandVector* inputs,
    OperandGeneratorT<TurbofanAdapter>* g,
    StateObjectDeduplicator* deduplicator, node_t node,
    FrameStateInputKind kind, Zone* zone) {
  // StateValues are often shared across different nodes, and processing them
  // is expensive, so cache the result of processing a StateValue so that we
  // can quickly copy the result if we see it again.
  FrameStateInput key(node, kind);
  auto cache_entry = state_values_cache_.find(key);
  if (cache_entry != state_values_cache_.end()) {
    // Entry found in cache, emit cached version.
    return cache_entry->second->Emit(inputs, values);
  } else {
    // Not found in cache, generate and then store in cache if possible.
    size_t entries = 0;
    CachedStateValuesBuilder cache_builder(values, inputs, deduplicator);
    StateValuesAccess::iterator it = StateValuesAccess(node).begin();
    // Take advantage of sparse nature of StateValuesAccess to skip over
    // multiple empty nodes at once pushing repeated OptimizedOuts all in one
    // go.
    while (!it.done()) {
      values->PushOptimizedOut(it.AdvanceTillNotEmpty());
      if (it.done()) break;
      StateValuesAccess::TypedNode input_node = *it;
      entries += AddOperandToStateValueDescriptor(values, inputs, g,
                                                  deduplicator, input_node.node,
                                                  input_node.type, kind, zone);
      ++it;
    }
    if (cache_builder.CanCache()) {
      // Use this->zone() to build the cache entry in the instruction
      // selector's zone rather than the more long-lived instruction zone.
      state_values_cache_.emplace(key, cache_builder.Build(this->zone()));
    }
    return entries;
  }
}

size_t AddOperandToStateValueDescriptor(
    InstructionSelectorT<TurboshaftAdapter>* selector, StateValueList* values,
    InstructionOperandVector* inputs, OperandGeneratorT<TurboshaftAdapter>* g,
    TurboshaftStateObjectDeduplicator* deduplicator,
    turboshaft::FrameStateData::Iterator* it, FrameStateInputKind kind,
    Zone* zone) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (it->current_instr()) {
    case FrameStateData::Instr::kUnusedRegister:
      it->ConsumeUnusedRegister();
      values->PushOptimizedOut();
      return 0;
    case FrameStateData::Instr::kInput: {
      MachineType type;
      OpIndex input;
      it->ConsumeInput(&type, &input);
      const Operation& op = selector->Get(input);
      if (op.outputs_rep()[0] == RegisterRepresentation::Word64() &&
          type.representation() == MachineRepresentation::kWord32) {
        // 64 to 32-bit conversion is implicit in turboshaft.
        // TODO(nicohartmann@): Fix this once we have explicit truncations.
        UNIMPLEMENTED();
      }
      InstructionOperand instr_op = OperandForDeopt(
          selector->isolate(), g, input, kind, type.representation());
      if (instr_op.kind() == InstructionOperand::INVALID) {
        // Invalid operand means the value is impossible or optimized-out.
        values->PushOptimizedOut();
        return 0;
      } else {
        inputs->push_back(instr_op);
        values->PushPlain(type);
        return 1;
      }
    }
    case FrameStateData::Instr::kDematerializedObject: {
      uint32_t obj_id;
      uint32_t field_count;
      it->ConsumeDematerializedObject(&obj_id, &field_count);
      size_t id = deduplicator->GetObjectId(obj_id);
      if (id == TurboshaftStateObjectDeduplicator::kNotDuplicated) {
        id = deduplicator->InsertObject(obj_id);
        size_t entries = 0;
        StateValueList* nested = values->PushRecursiveField(zone, id);
        for (uint32_t i = 0; i < field_count; ++i) {
          entries += AddOperandToStateValueDescriptor(
              selector, nested, inputs, g, deduplicator, it, kind, zone);
        }
        return entries;
      } else {
        // Deoptimizer counts duplicate objects for the running id, so we have
        // to push the input again.
        deduplicator->InsertObject(obj_id);
        values->PushDuplicate(id);
        return 0;
      }
    }
    case FrameStateData::Instr::kDematerializedObjectReference: {
      uint32_t obj_id;
      it->ConsumeDematerializedObjectReference(&obj_id);
      size_t id = deduplicator->GetObjectId(obj_id);
      DCHECK_NE(id, TurboshaftStateObjectDeduplicator::kNotDuplicated);
      // Deoptimizer counts duplicate objects for the running id, so we have
      // to push the input again.
      deduplicator->InsertObject(obj_id);
      values->PushDuplicate(id);
      return 0;
    }
    case FrameStateData::Instr::kDematerializedStringConcat: {
      DCHECK(v8_flags.turboshaft_string_concat_escape_analysis);
      it->ConsumeDematerializedStringConcat();
      StateValueList* nested = values->PushStringConcat(zone);
      static constexpr int kLeft = 1, kRight = 1;
      static constexpr int kInputCount = kLeft + kRight;
      size_t entries = 0;
      for (uint32_t i = 0; i < kInputCount; i++) {
        entries += AddOperandToStateValueDescriptor(
            selector, nested, inputs, g, deduplicator, it, kind, zone);
      }
      return entries;
    }
    case FrameStateData::Instr::kArgumentsElements: {
      CreateArgumentsType type;
      it->ConsumeArgumentsElements(&type);
      values->PushArgumentsElements(type);
      // The elements backing store of an arguments object participates in the
      // duplicate object counting, but can itself never appear duplicated.
      deduplicator->InsertDummyForArgumentsElements();
      return 0;
    }
    case FrameStateData::Instr::kArgumentsLength:
      it->ConsumeArgumentsLength();
      values->PushArgumentsLength();
      return 0;
    case FrameStateData::Instr::kRestLength:
      it->ConsumeRestLength();
      values->PushRestLength();
      return 0;
  }
  UNREACHABLE();
}

// Returns the number of instruction operands added to inputs.
template <>
size_t InstructionSelectorT<TurboshaftAdapter>::AddInputsToFrameStateDescriptor(
    FrameStateDescriptor* descriptor, node_t state_node, OperandGenerator* g,
    TurboshaftStateObjectDeduplicator* deduplicator,
    InstructionOperandVector* inputs, FrameStateInputKind kind, Zone* zone) {
  turboshaft::FrameStateOp& state =
      schedule()->Get(state_node).template Cast<turboshaft::FrameStateOp>();
  const FrameStateInfo& info = state.data->frame_state_info;
  USE(info);
  turboshaft::FrameStateData::Iterator it =
      state.data->iterator(state.state_values());

  size_t entries = 0;
  size_t initial_size = inputs->size();
  USE(initial_size);  // initial_size is only used for debug.
  if (descriptor->outer_state()) {
    entries += AddInputsToFrameStateDescriptor(
        descriptor->outer_state(), state.parent_frame_state(), g, deduplicator,
        inputs, kind, zone);
  }

  DCHECK_EQ(descriptor->parameters_count(), info.parameter_count());
  DCHECK_EQ(descriptor->locals_count(), info.local_count());
  DCHECK_EQ(descriptor->stack_count(), info.stack_count());

  StateValueList* values_descriptor = descriptor->GetStateValueDescriptors();

  DCHECK_EQ(values_descriptor->size(), 0u);
  values_descriptor->ReserveSize(descriptor->GetSize());

  // Function
  if (descriptor->HasClosure()) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it,
        FrameStateInputKind::kStackSlot, zone);
  } else {
    // Advance the iterator either way.
    MachineType unused_type;
    turboshaft::OpIndex unused_input;
    it.ConsumeInput(&unused_type, &unused_input);
  }

  // Parameters
  for (size_t i = 0; i < descriptor->parameters_count(); ++i) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it, kind, zone);
  }

  // Context
  if (descriptor->HasContext()) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it,
        FrameStateInputKind::kStackSlot, zone);
  } else {
    // Advance the iterator either way.
    MachineType unused_type;
    turboshaft::OpIndex unused_input;
    it.ConsumeInput(&unused_type, &unused_input);
  }

  // Locals
  for (size_t i = 0; i < descriptor->locals_count(); ++i) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it, kind, zone);
  }

  // Stack
  for (size_t i = 0; i < descriptor->stack_count(); ++i) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it, kind, zone);
  }

  DCHECK_EQ(initial_size + entries, inputs->size());
  return entries;
}

template <>
size_t InstructionSelectorT<TurbofanAdapter>::AddInputsToFrameStateDescriptor(
    FrameStateDescriptor* descriptor, node_t state_node, OperandGenerator* g,
    StateObjectDeduplicator* deduplicator, InstructionOperandVector* inputs,
    FrameStateInputKind kind, Zone* zone) {
  FrameState state{state_node};
  size_t entries = 0;
  size_t initial_size = inputs->size();
  USE(initial_size);  // initial_size is only used for debug.

  if (descriptor->outer_state()) {
    entries += AddInputsToFrameStateDescriptor(
        descriptor->outer_state(), FrameState{state.outer_frame_state()}, g,
        deduplicator, inputs, kind, zone);
  }

  Node* parameters = state.parameters();
  Node* locals = state.locals();
  Node* stack = state.stack();
  Node* context = state.context();
  Node* function = state.function();

  DCHECK_EQ(descriptor->parameters_count(),
            StateValuesAccess(parameters).size());
  DCHECK_EQ(descriptor->locals_count(), StateValuesAccess(locals).size());
  DCHECK_EQ(descriptor->stack_count(), StateValuesAccess(stack).size());

  StateValueList* values_descriptor = descriptor->GetStateValueDescriptors();

  DCHECK_EQ(values_descriptor->size(), 0u);
  values_descriptor->ReserveSize(descriptor->GetSize());

  if (descriptor->HasClosure()) {
    DCHECK_NOT_NULL(function);
    entries += AddOperandToStateValueDescriptor(
        values_descriptor, inputs, g, deduplicator, function,
        MachineType::AnyTagged(), FrameStateInputKind::kStackSlot, zone);
  }

  entries += AddInputsToFrameStateDescriptor(
      values_descriptor, inputs, g, deduplicator, parameters, kind, zone);

  if (descriptor->HasContext()) {
    DCHECK_NOT_NULL(context);
    entries += AddOperandToStateValueDescriptor(
        values_descriptor, inputs, g, deduplicator, context,
        MachineType::AnyTagged(), FrameStateInputKind::kStackSlot, zone);
  }

  entries += AddInputsToFrameStateDescriptor(values_descriptor, inputs, g,
                                             deduplicator, locals, kind, zone);

  entries += AddInputsToFrameStateDescriptor(values_descriptor, inputs, g,
                                             deduplicator, stack, kind, zone);
  DCHECK_EQ(initial_size + entries, inputs->size());
  return entries;
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, InstructionOperand a, FlagsContinuation* cont) {
  return EmitWithContinuation(opcode, 0, nullptr, 1, &a, cont);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, InstructionOperand a, InstructionOperand b,
    FlagsContinuation* cont) {
  InstructionOperand inputs[] = {a, b};
  return EmitWithContinuation(opcode, 0, nullptr, arraysize(inputs), inputs,
                              cont);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, InstructionOperand a, InstructionOperand b,
    InstructionOperand c, FlagsContinuation* cont) {
  InstructionOperand inputs[] = {a, b, c};
  return EmitWithContinuation(opcode, 0, nullptr, arraysize(inputs), inputs,
                              cont);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, size_t output_count, InstructionOperand* outputs,
    size_t input_count, InstructionOperand* inputs, FlagsContinuation* cont) {
  return EmitWithContinuation(opcode, output_count, outputs, input_count,
                              inputs, 0, nullptr, cont);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, size_t output_count, InstructionOperand* outputs,
    size_t input_count, InstructionOperand* inputs, size_t temp_count,
    InstructionOperand* temps, FlagsContinuation* cont) {
  OperandGenerator g(this);

  opcode = cont->Encode(opcode);

  continuation_inputs_.resize(0);
  for (size_t i = 0; i < input_count; i++) {
    continuation_inputs_.push_back(inputs[i]);
  }

  continuation_outputs_.resize(0);
  for (size_t i = 0; i < output_count; i++) {
    continuation_outputs_.push_back(outputs[i]);
  }

  continuation_temps_.resize(0);
  for (size_t i = 0; i < temp_count; i++) {
    continuation_temps_.push_back(temps[i]);
  }

  if (cont->IsBranch() || cont->IsConditionalBranch()) {
    continuation_inputs_.push_back(g.Label(cont->true_block()));
    continuation_inputs_.push_back(g.Label(cont->false_block()));
  } else if (cont->IsDeoptimize()) {
    int immediate_args_count = 0;
    opcode |= DeoptImmedArgsCountField::encode(immediate_args_count) |
              DeoptFrameStateOffsetField::encode(static_cast<int>(input_count));
    AppendDeoptimizeArguments(&continuation_inputs_, cont->reason(),
                              cont->node_id(), cont->feedback(),
                              cont->frame_state());
  } else if (cont->IsSet() || cont->IsConditionalSet()) {
    continuation_outputs_.push_back(g.DefineAsRegister(cont->result()));
  } else if (cont->IsSelect()) {
    // The {Select} should put one of two values into the output register,
    // depending on the result of the condition. The two result values are in
    // the last two input slots, the {false_value} in {input_count - 2}, and the
    // true_value in {input_count - 1}. The other inputs are used for the
    // condition.
    AddOutputToSelectContinuation(&g, static_cast<int>(input_count) - 2,
                                  cont->result());
  } else if (cont->IsTrap()) {
    int trap_id = static_cast<int>(cont->trap_id());
    continuation_inputs_.push_back(g.UseImmediate(trap_id));
  } else {
    DCHECK(cont->IsNone());
  }

  size_t const emit_inputs_size = continuation_inputs_.size();
  auto* emit_inputs =
      emit_inputs_size ? &continuation_inputs_.front() : nullptr;
  size_t const emit_outputs_size = continuation_outputs_.size();
  auto* emit_outputs =
      emit_outputs_size ? &continuation_outputs_.front() : nullptr;
  size_t const emit_temps_size = continuation_temps_.size();
  auto* emit_temps = emit_temps_size ? &continuation_temps_.front() : nullptr;
  return Emit(opcode, emit_outputs_size, emit_outputs, emit_inputs_size,
              emit_inputs, emit_temps_size, emit_temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::AppendDeoptimizeArguments(
    InstructionOperandVector* args, DeoptimizeReason reason, id_t node_id,
    FeedbackSource const& feedback, node_t frame_state, DeoptimizeKind kind) {
  OperandGenerator g(this);
  FrameStateDescriptor* const descriptor = GetFrameStateDescriptor(frame_state);
  int const state_id = sequence()->AddDeoptimizationEntry(
      descriptor, kind, reason, node_id, feedback);
  args->push_back(g.TempImmediate(state_id));
  StateObjectDeduplicator deduplicator(instruction_zone());
  AddInputsToFrameStateDescriptor(descriptor, frame_state, &g, &deduplicator,
                                  args, FrameStateInputKind::kAny,
                                  instruction_zone());
}

// An internal helper class for generating the operands to calls.
// TODO(bmeurer): Get rid of the CallBuffer business and make
// InstructionSelector::VisitCall platform independent instead.
template <typename Adapter>
struct CallBufferT {
  using PushParameter = PushParameterT<Adapter>;
  CallBufferT(Zone* zone, const CallDescriptor* call_descriptor,
              FrameStateDescriptor* frame_state)
      : descriptor(call_descriptor),
        frame_state_descriptor(frame_state),
        output_nodes(zone),
        outputs(zone),
        instruction_args(zone),
        pushed_nodes(zone) {
    output_nodes.reserve(call_descriptor->ReturnCount());
    outputs.reserve(call_descriptor->ReturnCount());
    pushed_nodes.reserve(input_count());
    instruction_args.reserve(input_count() + frame_state_value_count());
  }

  const CallDescriptor* descriptor;
  FrameStateDescriptor* frame_state_descriptor;
  ZoneVector<PushParameter> output_nodes;
  InstructionOperandVector outputs;
  InstructionOperandVector instruction_args;
  ZoneVector<PushParameter> pushed_nodes;

  size_t input_count() const { return descriptor->InputCount(); }

  size_t frame_state_count() const { return descriptor->FrameStateCount(); }

  size_t frame_state_value_count() const {
    return (frame_state_descriptor == nullptr)
               ? 0
               : (frame_state_descriptor->GetTotalSize() +
                  1);  // Include deopt id.
  }
};

// TODO(bmeurer): Get rid of the CallBuffer business and make
// InstructionSelector::VisitCall platform independent instead.
template <typename Adapter>
void InstructionSelectorT<Adapter>::InitializeCallBuffer(
    node_t node, CallBuffer* buffer, CallBufferFlags flags,
    int stack_param_delta) {
  OperandGenerator g(this);
  size_t ret_count = buffer->descriptor->ReturnCount();
  bool is_tail_call = (flags & kCallTail) != 0;
  auto call = this->call_view(node);
  DCHECK_LE(call.return_count(), ret_count);

  if (ret_count > 0) {
    // Collect the projections that represent multiple outputs from this call.
    if (ret_count == 1) {
      PushParameter result = {call, buffer->descriptor->GetReturnLocation(0)};
      buffer->output_nodes.push_back(result);
    } else {
      buffer->output_nodes.resize(ret_count);
      for (size_t i = 0; i < ret_count; ++i) {
        LinkageLocation location = buffer->descriptor->GetReturnLocation(i);
        buffer->output_nodes[i] = PushParameter({}, location);
      }
      if constexpr (Adapter::IsTurboshaft) {
        for (turboshaft::OpIndex call_use : turboshaft_uses(call)) {
          const turboshaft::Operation& use_op = this->Get(call_use);
          if (use_op.Is<turboshaft::DidntThrowOp>()) {
            for (turboshaft::OpIndex use : turboshaft_uses(call_use)) {
              DCHECK(this->is_projection(use));
              size_t index = this->projection_index_of(use);
              DCHECK_LT(index, buffer->output_nodes.size());
              DCHECK(!Adapter::valid(buffer->output_nodes[index].node));
              buffer->output_nodes[index].node = use;
            }
          } else {
            DCHECK(use_op.Is<turboshaft::CheckExceptionOp>());
          }
        }
      } else {
        for (Edge const edge : ((node_t)call)->use_edges()) {
          if (!NodeProperties::IsValueEdge(edge)) continue;
          Node* node = edge.from();
          DCHECK_EQ(IrOpcode::kProjection, node->opcode());
          size_t const index = ProjectionIndexOf(node->op());

          DCHECK_LT(index, buffer->output_nodes.size());
          DCHECK(!buffer->output_nodes[index].node);
          buffer->output_nodes[index].node = node;
        }
      }
      frame_->EnsureReturnSlots(
          static_cast<int>(buffer->descriptor->ReturnSlotCount()));
    }

    // Filter out the outputs that aren't live because no projection uses them.
    size_t outputs_needed_by_framestate =
        buffer->frame_state_descriptor == nullptr
            ? 0
            : buffer->frame_state_descriptor->state_combine()
                  .ConsumedOutputCount();
    for (size_t i = 0; i < buffer->output_nodes.size(); i++) {
      bool output_is_live = this->valid(buffer->output_nodes[i].node) ||
                            i < outputs_needed_by_framestate;
      if (output_is_live) {
        LinkageLocation location = buffer->output_nodes[i].location;
        MachineRepresentation rep = location.GetType().representation();

        node_t output = buffer->output_nodes[i].node;
        InstructionOperand op = !this->valid(output)
                                    ? g.TempLocation(location)
                                    : g.DefineAsLocation(output, location);
        MarkAsRepresentation(rep, op);

        if (!UnallocatedOperand::cast(op).HasFixedSlotPolicy()) {
          buffer->outputs.push_back(op);
          buffer->output_nodes[i].node = {};
        }
      }
    }
  }

  // The first argument is always the callee code.
  node_t callee = call.callee();
  bool call_code_immediate = (flags & kCallCodeImmediate) != 0;
  bool call_address_immediate = (flags & kCallAddressImmediate) != 0;
  bool call_use_fixed_target_reg = (flags & kCallFixedTargetRegister) != 0;
  switch (buffer->descriptor->kind()) {
    case CallDescriptor::kCallCodeObject:
      buffer->instruction_args.push_back(
          (call_code_immediate && this->IsHeapConstant(callee))
              ? g.UseImmediate(callee)
          : call_use_fixed_target_reg
              ? g.UseFixed(callee, kJavaScriptCallCodeStartRegister)
              : g.UseRegister(callee));
      break;
    case CallDescriptor::kCallAddress:
      buffer->instruction_args.push_back(
          (call_address_immediate && this->IsExternalConstant(callee))
              ? g.UseImmediate(callee)
          : call_use_fixed_target_reg
              ? g.UseFixed(callee, kJavaScriptCallCodeStartRegister)
              : g.UseRegister(callee));
      break;
#if V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallWasmCapiFunction:
    case CallDescriptor::kCallWasmFunction:
    case CallDescriptor::kCallWasmImportWrapper:
      buffer->instruction_args.push_back(
          (call_address_immediate && this->IsRelocatableWasmConstant(callee))
              ? g.UseImmediate(callee)
          : call_use_fixed_target_reg
              ? g.UseFixed(callee, kJavaScriptCallCodeStartRegister)
              : g.UseRegister(callee));
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallBuiltinPointer: {
      // The common case for builtin pointers is to have the target in a
      // register. If we have a constant, we use a register anyway to simplify
      // related code.
      LinkageLocation location = buffer->descriptor->GetInputLocation(0);
      bool location_is_fixed_register =
          location.IsRegister() && !location.IsAnyRegister();
      InstructionOperand op;
      // If earlier phases specified a particular register, don't override
      // their choice.
      if (location_is_fixed_register) {
        op = g.UseLocation(callee, location);
      } else if (call_use_fixed_target_reg) {
        op = g.UseFixed(callee, kJavaScriptCallCodeStartRegister);
      } else {
        op = g.UseRegister(callee);
      }
      buffer->instruction_args.push_back(op);
      break;
    }
    case CallDescriptor::kCallJSFunction:
      buffer->instruction_args.push_back(
          g.UseLocation(callee, buffer->descriptor->GetInputLocation(0)));
      break;
  }
  DCHECK_EQ(1u, buffer->instruction_args.size());

  // If the call needs a frame state, we insert the state information as
  // follows (n is the number of value inputs to the frame state):
  // arg 1               : deoptimization id.
  // arg 2 - arg (n + 2) : value inputs to the frame state.
  size_t frame_state_entries = 0;
  USE(frame_state_entries);  // frame_state_entries is only used for debug.
  if (buffer->frame_state_descriptor != nullptr) {
    node_t frame_state = call.frame_state();

    // If it was a syntactic tail call we need to drop the current frame and
    // all the frames on top of it that are either inlined extra arguments
    // or a tail caller frame.
    if (is_tail_call) {
      frame_state = this->parent_frame_state(frame_state);
      buffer->frame_state_descriptor =
          buffer->frame_state_descriptor->outer_state();
      while (buffer->frame_state_descriptor != nullptr &&
             buffer->frame_state_descriptor->type() ==
                 FrameStateType::kInlinedExtraArguments) {
        frame_state = this->parent_frame_state(frame_state);
        buffer->frame_state_descriptor =
            buffer->frame_state_descriptor->outer_state();
      }
    }

    int const state_id = sequence()->AddDeoptimizationEntry(
        buffer->frame_state_descriptor, DeoptimizeKind::kLazy,
        DeoptimizeReason::kUnknown, this->id(call), FeedbackSource());
    buffer->instruction_args.push_back(g.TempImmediate(state_id));

    StateObjectDeduplicator deduplicator(instruction_zone());

    frame_state_entries =
        1 + AddInputsToFrameStateDescriptor(
                buffer->frame_state_descriptor, frame_state, &g, &deduplicator,
                &buffer->instruction_args, FrameStateInputKind::kStackSlot,
                instruction_zone());

    DCHECK_EQ(1 + frame_state_entries, buffer->instruction_args.size());
  }

  size_t input_count = buffer->input_count();

  // Split the arguments into pushed_nodes and instruction_args. Pushed
  // arguments require an explicit push instruction before the call and do
  // not appear as arguments to the call. Everything else ends up
  // as an InstructionOperand argument to the call.
  auto arguments = call.arguments();
  auto iter(arguments.begin());
  size_t pushed_count = 0;
  for (size_t index = 1; index < input_count; ++iter, ++index) {
    DCHECK_NE(iter, arguments.end());

    LinkageLocation location = buffer->descriptor->GetInputLocation(index);
    if (is_tail_call) {
      location = LinkageLocation::ConvertToTailCallerLocation(
          location, stack_param_delta);
    }
    InstructionOperand op = g.UseLocation(*iter, location);
    UnallocatedOperand unallocated = UnallocatedOperand::cast(op);
    if (unallocated.HasFixedSlotPolicy() && !is_tail_call) {
      int stack_index = buffer->descriptor->GetStackIndexFromSlot(
          unallocated.fixed_slot_index());
      // This can insert empty slots before stack_index and will insert enough
      // slots after stack_index to store the parameter.
      if (static_cast<size_t>(stack_index) >= buffer->pushed_nodes.size()) {
        int num_slots = location.GetSizeInPointers();
        buffer->pushed_nodes.resize(stack_index + num_slots);
      }
      PushParameter param = {*iter, location};
      buffer->pushed_nodes[stack_index] = param;
      pushed_count++;
    } else {
      if (location.IsNullRegister()) {
        EmitMoveFPRToParam(&op, location);
      }
      buffer->instruction_args.push_back(op);
    }
  }
  DCHECK_EQ(input_count, buffer->instruction_args.size() + pushed_count -
                             frame_state_entries);
  USE(pushed_count);
  if (V8_TARGET_ARCH_STORES_RETURN_ADDRESS_ON_STACK && is_tail_call &&
      stack_param_delta != 0) {
    // For tail calls that change the size of their parameter list and keep
    // their return address on the stack, move the return address to just above
    // the parameters.
    LinkageLocation saved_return_location =
        LinkageLocat
"""


```