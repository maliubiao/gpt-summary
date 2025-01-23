Response: The user wants a summary of the functionality of the C++ source code file `v8/src/compiler/backend/register-allocator.cc`.

This file seems to be part of the register allocation process in the V8 JavaScript engine's optimizing compiler (TurboFan). Register allocation is the process of assigning physical registers to virtual registers used in the intermediate representation of the code.

Based on the included headers and the code snippets, the file likely handles:

1. **Data structures for representing live ranges:**  `LiveRange`, `TopLevelLiveRange`, `UsePosition`, `UseInterval`. These structures track when and where virtual registers are "live" (their values are needed).
2. **Management of spill slots:**  When there aren't enough physical registers, values are "spilled" to memory (stack slots). The `SpillRange` class likely helps manage these.
3. **Handling of fixed registers:** Some values might need to be in specific physical registers due to calling conventions or other constraints.
4. **Constraint building:** The `ConstraintBuilder` class appears to analyze the instructions and set up constraints for the register allocator, ensuring that register assignments are valid.
5. **Phi functions:** The `RegisterAllocationData::PhiMapValue` structure handles the merging of values at control flow join points (phi functions).
6. **Debugging and tracing:** The `TRACE` macro and `Print` methods suggest debugging capabilities.

The relationship with JavaScript is that this code is a crucial part of the compilation process that turns JavaScript code into efficient machine code. Register allocation directly impacts the performance of the generated code.

To illustrate with JavaScript, consider a simple function:

```javascript
function add(a, b) {
  let sum = a + b;
  return sum;
}
```

During compilation, the variables `a`, `b`, and `sum` might be represented as virtual registers. The `register-allocator.cc` code would be responsible for deciding which physical CPU registers (like `rax`, `rbx`, etc. on x64) should hold the values of `a`, `b`, and `sum` at different points in the execution of the compiled code. If there are not enough registers, the value of `sum` might be temporarily stored in a stack slot. The constraints would ensure, for example, that if `a` needs to be in a specific register for the addition operation, the allocator respects that.

This C++ source code file is a core component of the register allocation process within the V8 JavaScript engine's optimizing compiler (TurboFan). Its primary function is to manage the assignment of physical machine registers (or stack slots) to virtual registers used in the intermediate representation of the code being compiled. Here's a breakdown of its key responsibilities as evidenced in this first part:

1. **Data Structures for Representing Live Ranges:** It defines classes like `LiveRange`, `TopLevelLiveRange`, `UsePosition`, and `UseInterval`. These structures are fundamental for tracking the "liveness" of virtual registers –  the periods during which their values might be needed.
    *   `LiveRange`: Represents the lifetime of a value held in a virtual register. It can be split into smaller ranges.
    *   `TopLevelLiveRange`: Represents the complete lifetime of a virtual register, potentially spanning multiple `LiveRange` instances after splits.
    *   `UsePosition`:  Marks a specific point in the code where a virtual register is used. It can contain hints about desired register assignments.
    *   `UseInterval`:  Defines a continuous interval within the lifetime of a virtual register where its value might be used.

2. **Management of Spill Slots:** When the number of live virtual registers exceeds the available physical registers, some values need to be "spilled" to memory (stack slots). The code includes structures and logic related to managing these spill slots (`SpillRange`).

3. **Handling of Fixed Registers:** Certain values might need to reside in specific physical registers due to calling conventions, instruction requirements, or other constraints. The code includes mechanisms to handle these fixed register assignments.

4. **Constraint Building:** The `ConstraintBuilder` class (partially shown) is responsible for analyzing the instructions and setting up constraints for the register allocator. These constraints ensure that the register assignments are valid and satisfy the requirements of the operations being performed.

5. **Phi Functions:**  The `RegisterAllocationData::PhiMapValue` structure is used to handle phi functions, which occur at control flow merge points in the code. Phi functions conceptually merge the values of a virtual register coming from different control flow paths.

6. **Debugging and Tracing:** The code includes a `TRACE` macro that allows for conditional printing of debugging information during the register allocation process, helpful for understanding and verifying its behavior.

**Relationship to JavaScript with a JavaScript Example:**

The register allocator directly impacts the performance of compiled JavaScript code. Consider this simple JavaScript function:

```javascript
function add(x, y) {
  let sum = x + y;
  return sum;
}
```

During the compilation of this function by TurboFan, the variables `x`, `y`, and `sum` will be represented as virtual registers. The `register-allocator.cc` code is responsible for deciding which physical CPU registers (like `rax`, `rbx`, `rcx` on x64 architectures) will hold the values of `x`, `y`, and `sum` during the execution of the compiled machine code.

*   The `LiveRange` for `x`, `y`, and `sum` will be determined based on when these variables are first used and last used.
*   The allocator might try to assign `x` and `y` to different registers for the addition operation.
*   If there are not enough available registers, the value of `sum` might be temporarily stored in a stack slot (spilled). The `SpillRange` would manage this.
*   The `ConstraintBuilder` would ensure that if the addition instruction requires its operands to be in registers, the allocator respects this constraint.

In essence, this C++ code is a crucial part of the machinery that transforms the high-level concept of JavaScript variables into the concrete reality of machine registers, directly influencing the efficiency of the executed JavaScript code.

### 提示词
```
这是目录为v8/src/compiler/backend/register-allocator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/backend/register-allocator.h"

#include <iomanip>
#include <optional>

#include "src/base/iterator.h"
#include "src/base/small-vector.h"
#include "src/base/vector.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/tick-counter.h"
#include "src/compiler/backend/spill-placer.h"
#include "src/compiler/linkage.h"
#include "src/strings/string-stream.h"

namespace v8 {
namespace internal {
namespace compiler {

#define TRACE(...)                                       \
  do {                                                   \
    if (v8_flags.trace_turbo_alloc) PrintF(__VA_ARGS__); \
  } while (false)

namespace {

static constexpr int kFloat32Bit =
    RepresentationBit(MachineRepresentation::kFloat32);
static constexpr int kSimd128Bit =
    RepresentationBit(MachineRepresentation::kSimd128);

const InstructionBlock* GetContainingLoop(const InstructionSequence* sequence,
                                          const InstructionBlock* block) {
  RpoNumber index = block->loop_header();
  if (!index.IsValid()) return nullptr;
  return sequence->InstructionBlockAt(index);
}

const InstructionBlock* GetInstructionBlock(const InstructionSequence* code,
                                            LifetimePosition pos) {
  return code->GetInstructionBlock(pos.ToInstructionIndex());
}

Instruction* GetLastInstruction(InstructionSequence* code,
                                const InstructionBlock* block) {
  return code->InstructionAt(block->last_instruction_index());
}

}  // namespace

using DelayedInsertionMapKey = std::pair<ParallelMove*, InstructionOperand>;

struct DelayedInsertionMapCompare {
  bool operator()(const DelayedInsertionMapKey& a,
                  const DelayedInsertionMapKey& b) const {
    if (a.first == b.first) {
      return a.second.Compare(b.second);
    }
    return a.first < b.first;
  }
};

using DelayedInsertionMap = ZoneMap<DelayedInsertionMapKey, InstructionOperand,
                                    DelayedInsertionMapCompare>;

UsePosition::UsePosition(LifetimePosition pos, InstructionOperand* operand,
                         void* hint, UsePositionHintType hint_type)
    : operand_(operand), hint_(hint), pos_(pos), flags_(0) {
  DCHECK_IMPLIES(hint == nullptr, hint_type == UsePositionHintType::kNone);
  bool register_beneficial = true;
  UsePositionType type = UsePositionType::kRegisterOrSlot;
  if (operand_ != nullptr && operand_->IsUnallocated()) {
    const UnallocatedOperand* unalloc = UnallocatedOperand::cast(operand_);
    if (unalloc->HasRegisterPolicy()) {
      type = UsePositionType::kRequiresRegister;
    } else if (unalloc->HasSlotPolicy()) {
      type = UsePositionType::kRequiresSlot;
      register_beneficial = false;
    } else if (unalloc->HasRegisterOrSlotOrConstantPolicy()) {
      type = UsePositionType::kRegisterOrSlotOrConstant;
      register_beneficial = false;
    } else {
      register_beneficial = !unalloc->HasRegisterOrSlotPolicy();
    }
  }
  flags_ = TypeField::encode(type) | HintTypeField::encode(hint_type) |
           RegisterBeneficialField::encode(register_beneficial) |
           AssignedRegisterField::encode(kUnassignedRegister);
  DCHECK(pos_.IsValid());
}

bool UsePosition::HasHint() const {
  int hint_register;
  return HintRegister(&hint_register);
}

bool UsePosition::HintRegister(int* register_code) const {
  if (hint_ == nullptr) return false;
  switch (HintTypeField::decode(flags_)) {
    case UsePositionHintType::kNone:
    case UsePositionHintType::kUnresolved:
      return false;
    case UsePositionHintType::kUsePos: {
      UsePosition* use_pos = reinterpret_cast<UsePosition*>(hint_);
      int assigned_register = AssignedRegisterField::decode(use_pos->flags_);
      if (assigned_register == kUnassignedRegister) return false;
      *register_code = assigned_register;
      return true;
    }
    case UsePositionHintType::kOperand: {
      InstructionOperand* operand =
          reinterpret_cast<InstructionOperand*>(hint_);
      *register_code = LocationOperand::cast(operand)->register_code();
      return true;
    }
    case UsePositionHintType::kPhi: {
      RegisterAllocationData::PhiMapValue* phi =
          reinterpret_cast<RegisterAllocationData::PhiMapValue*>(hint_);
      int assigned_register = phi->assigned_register();
      if (assigned_register == kUnassignedRegister) return false;
      *register_code = assigned_register;
      return true;
    }
  }
  UNREACHABLE();
}

UsePositionHintType UsePosition::HintTypeForOperand(
    const InstructionOperand& op) {
  switch (op.kind()) {
    case InstructionOperand::CONSTANT:
    case InstructionOperand::IMMEDIATE:
      return UsePositionHintType::kNone;
    case InstructionOperand::UNALLOCATED:
      return UsePositionHintType::kUnresolved;
    case InstructionOperand::ALLOCATED:
      if (op.IsRegister() || op.IsFPRegister()) {
        return UsePositionHintType::kOperand;
      } else {
        DCHECK(op.IsStackSlot() || op.IsFPStackSlot());
        return UsePositionHintType::kNone;
      }
    case InstructionOperand::PENDING:
    case InstructionOperand::INVALID:
      break;
  }
  UNREACHABLE();
}

void UsePosition::SetHint(UsePosition* use_pos) {
  DCHECK_NOT_NULL(use_pos);
  hint_ = use_pos;
  flags_ = HintTypeField::update(flags_, UsePositionHintType::kUsePos);
}

void UsePosition::ResolveHint(UsePosition* use_pos) {
  DCHECK_NOT_NULL(use_pos);
  if (HintTypeField::decode(flags_) != UsePositionHintType::kUnresolved) return;
  hint_ = use_pos;
  flags_ = HintTypeField::update(flags_, UsePositionHintType::kUsePos);
}

void UsePosition::set_type(UsePositionType type, bool register_beneficial) {
  DCHECK_IMPLIES(type == UsePositionType::kRequiresSlot, !register_beneficial);
  DCHECK_EQ(kUnassignedRegister, AssignedRegisterField::decode(flags_));
  flags_ = TypeField::encode(type) |
           RegisterBeneficialField::encode(register_beneficial) |
           HintTypeField::encode(HintTypeField::decode(flags_)) |
           AssignedRegisterField::encode(kUnassignedRegister);
}

void LifetimePosition::Print() const { StdoutStream{} << *this << std::endl; }

LiveRange::LiveRange(int relative_id, MachineRepresentation rep,
                     TopLevelLiveRange* top_level)
    : relative_id_(relative_id),
      bits_(0),
      intervals_(),
      positions_span_(),
      top_level_(top_level),
      next_(nullptr),
      current_interval_(intervals_.begin()) {
  DCHECK(AllocatedOperand::IsSupportedRepresentation(rep));
  bits_ = AssignedRegisterField::encode(kUnassignedRegister) |
          RepresentationField::encode(rep) |
          ControlFlowRegisterHint::encode(kUnassignedRegister);
}

#ifdef DEBUG
void LiveRange::VerifyPositions() const {
  SLOW_DCHECK(std::is_sorted(positions().begin(), positions().end(),
                             UsePosition::Ordering()));

  // Verify that each `UsePosition` is covered by a `UseInterval`.
  UseIntervalVector::const_iterator interval = intervals().begin();
  for (UsePosition* pos : positions()) {
    DCHECK_LE(Start(), pos->pos());
    DCHECK_LE(pos->pos(), End());
    DCHECK_NE(interval, intervals().end());
    // NOTE: Even though `UseInterval`s are conceptually half-open (e.g., when
    // splitting), we still regard the `UsePosition` that coincides with
    // the end of an interval as covered by that interval.
    while (!interval->Contains(pos->pos()) && interval->end() != pos->pos()) {
      ++interval;
      DCHECK_NE(interval, intervals().end());
    }
  }
}

void LiveRange::VerifyIntervals() const {
  DCHECK(!intervals().empty());
  DCHECK_EQ(intervals().front().start(), Start());
  // The `UseInterval`s must be sorted and disjoint.
  LifetimePosition last_end = intervals().front().end();
  for (UseIntervalVector::const_iterator interval = intervals().begin() + 1;
       interval != intervals().end(); ++interval) {
    DCHECK_LE(last_end, interval->start());
    last_end = interval->end();
  }
  DCHECK_EQ(last_end, End());
}
#endif

void LiveRange::set_assigned_register(int reg) {
  DCHECK(!HasRegisterAssigned() && !spilled());
  bits_ = AssignedRegisterField::update(bits_, reg);
}

void LiveRange::UnsetAssignedRegister() {
  DCHECK(HasRegisterAssigned() && !spilled());
  bits_ = AssignedRegisterField::update(bits_, kUnassignedRegister);
}

void LiveRange::AttachToNext(Zone* zone) {
  DCHECK_NOT_NULL(next_);

  // Update cache for `TopLevelLiveRange::GetChildCovers()`.
  auto& children = TopLevel()->children_;
  children.erase(std::lower_bound(children.begin(), children.end(), next_,
                                  LiveRangeOrdering()));

  // Merge use intervals.
  intervals_.Append(zone, next_->intervals_);
  // `start_` doesn't change.
  end_ = next_->end_;

  // Merge use positions.
  CHECK_EQ(positions_span_.end(), next_->positions_span_.begin());
  positions_span_ =
      base::VectorOf(positions_span_.begin(),
                     positions_span_.size() + next_->positions_span_.size());

  // Join linked lists of live ranges.
  LiveRange* old_next = next_;
  next_ = next_->next_;
  old_next->next_ = nullptr;
}

void LiveRange::Unspill() {
  DCHECK(spilled());
  set_spilled(false);
  bits_ = AssignedRegisterField::update(bits_, kUnassignedRegister);
}

void LiveRange::Spill() {
  DCHECK(!spilled());
  DCHECK(!TopLevel()->HasNoSpillType());
  set_spilled(true);
  bits_ = AssignedRegisterField::update(bits_, kUnassignedRegister);
}

RegisterKind LiveRange::kind() const {
  if (kFPAliasing == AliasingKind::kIndependent &&
      IsSimd128(representation())) {
    return RegisterKind::kSimd128;
  } else {
    return IsFloatingPoint(representation()) ? RegisterKind::kDouble
                                             : RegisterKind::kGeneral;
  }
}

bool LiveRange::RegisterFromFirstHint(int* register_index) {
  DCHECK_LE(current_hint_position_index_, positions_span_.size());
  if (current_hint_position_index_ == positions_span_.size()) {
    return false;
  }
  DCHECK_GE(positions_span_[current_hint_position_index_]->pos(),
            positions_span_.first()->pos());
  DCHECK_LE(positions_span_[current_hint_position_index_]->pos(), End());

  bool needs_revisit = false;
  UsePosition** pos_it = positions_span_.begin() + current_hint_position_index_;
  for (; pos_it != positions_span_.end(); ++pos_it) {
    if ((*pos_it)->HintRegister(register_index)) {
      break;
    }
    // Phi and use position hints can be assigned during allocation which
    // would invalidate the cached hint position. Make sure we revisit them.
    needs_revisit = needs_revisit ||
                    (*pos_it)->hint_type() == UsePositionHintType::kPhi ||
                    (*pos_it)->hint_type() == UsePositionHintType::kUsePos;
  }
  if (!needs_revisit) {
    current_hint_position_index_ =
        std::distance(positions_span_.begin(), pos_it);
  }
#ifdef DEBUG
  UsePosition** pos_check_it =
      std::find_if(positions_span_.begin(), positions_span_.end(),
                   [](UsePosition* pos) { return pos->HasHint(); });
  CHECK_EQ(pos_it, pos_check_it);
#endif
  return pos_it != positions_span_.end();
}

UsePosition* const* LiveRange::NextUsePosition(LifetimePosition start) const {
  return std::lower_bound(positions_span_.cbegin(), positions_span_.cend(),
                          start, [](UsePosition* use, LifetimePosition start) {
                            return use->pos() < start;
                          });
}

UsePosition* LiveRange::NextUsePositionRegisterIsBeneficial(
    LifetimePosition start) const {
  UsePosition* const* use_pos_it = std::find_if(
      NextUsePosition(start), positions_span_.cend(),
      [](const UsePosition* pos) { return pos->RegisterIsBeneficial(); });
  return use_pos_it == positions_span_.cend() ? nullptr : *use_pos_it;
}

LifetimePosition LiveRange::NextLifetimePositionRegisterIsBeneficial(
    const LifetimePosition& start) const {
  UsePosition* next_use = NextUsePositionRegisterIsBeneficial(start);
  if (next_use == nullptr) return End();
  return next_use->pos();
}

UsePosition* LiveRange::NextUsePositionSpillDetrimental(
    LifetimePosition start) const {
  UsePosition* const* use_pos_it =
      std::find_if(NextUsePosition(start), positions_span_.cend(),
                   [](const UsePosition* pos) {
                     return pos->type() == UsePositionType::kRequiresRegister ||
                            pos->SpillDetrimental();
                   });
  return use_pos_it == positions_span_.cend() ? nullptr : *use_pos_it;
}

UsePosition* LiveRange::NextRegisterPosition(LifetimePosition start) const {
  UsePosition* const* use_pos_it =
      std::find_if(NextUsePosition(start), positions_span_.cend(),
                   [](const UsePosition* pos) {
                     return pos->type() == UsePositionType::kRequiresRegister;
                   });
  return use_pos_it == positions_span_.cend() ? nullptr : *use_pos_it;
}

bool LiveRange::CanBeSpilled(LifetimePosition pos) const {
  // We cannot spill a live range that has a use requiring a register
  // at the current or the immediate next position.
  UsePosition* use_pos = NextRegisterPosition(pos);
  if (use_pos == nullptr) return true;
  return use_pos->pos() > pos.NextStart().End();
}

bool LiveRange::IsTopLevel() const { return top_level_ == this; }

InstructionOperand LiveRange::GetAssignedOperand() const {
  DCHECK(!IsEmpty());
  if (HasRegisterAssigned()) {
    DCHECK(!spilled());
    return AllocatedOperand(LocationOperand::REGISTER, representation(),
                            assigned_register());
  }
  DCHECK(spilled());
  DCHECK(!HasRegisterAssigned());
  if (TopLevel()->HasSpillOperand()) {
    InstructionOperand* op = TopLevel()->GetSpillOperand();
    DCHECK(!op->IsUnallocated());
    return *op;
  }
  return TopLevel()->GetSpillRangeOperand();
}

UseIntervalVector::iterator LiveRange::FirstSearchIntervalForPosition(
    LifetimePosition position) {
  DCHECK_NE(current_interval_, intervals_.end());
  if (current_interval_->start() > position) {
    current_interval_ = std::lower_bound(
        intervals_.begin(), intervals_.end(), position,
        [](const UseInterval& interval, LifetimePosition position) {
          return interval.end() < position;
        });
  }
  return current_interval_;
}

void LiveRange::AdvanceLastProcessedMarker(
    UseIntervalVector::iterator to_start_of, LifetimePosition but_not_past) {
  DCHECK_LE(intervals_.begin(), to_start_of);
  DCHECK_LT(to_start_of, intervals_.end());
  DCHECK_NE(current_interval_, intervals_.end());
  if (to_start_of->start() > but_not_past) return;
  if (to_start_of->start() > current_interval_->start()) {
    current_interval_ = to_start_of;
  }
}

LiveRange* LiveRange::SplitAt(LifetimePosition position, Zone* zone) {
  DCHECK(Start() < position);
  DCHECK(End() > position);

  int new_id = TopLevel()->GetNextChildId();
  LiveRange* result =
      zone->New<LiveRange>(new_id, representation(), TopLevel());

  // Partition original use intervals to the two live ranges.

  // Find the first interval that ends after the position. (This either needs
  // to be split or completely belongs to the split-off LiveRange.)
  UseIntervalVector::iterator split_interval = std::upper_bound(
      intervals_.begin(), intervals_.end(), position,
      [](LifetimePosition position, const UseInterval& interval) {
        return position < interval.end();
      });
  DCHECK_NE(split_interval, intervals_.end());

  bool split_at_start = false;
  if (split_interval->start() == position) {
    split_at_start = true;
  } else if (split_interval->Contains(position)) {
    UseInterval new_interval = split_interval->SplitAt(position);
    split_interval = intervals_.insert(zone, split_interval + 1, new_interval);
  }
  result->intervals_ = intervals_.SplitAt(split_interval);
  DCHECK(!intervals_.empty());
  DCHECK(!result->intervals_.empty());

  result->start_ = result->intervals_.front().start();
  result->end_ = end_;
  end_ = intervals_.back().end();

  // Partition use positions.
  UsePosition** split_position_it;
  if (split_at_start) {
    // The split position coincides with the beginning of a use interval
    // (the end of a lifetime hole). Use at this position should be attributed
    // to the split child because split child owns use interval covering it.
    split_position_it = std::lower_bound(
        positions_span_.begin(), positions_span_.end(), position,
        [](const UsePosition* use_pos, LifetimePosition pos) {
          return use_pos->pos() < pos;
        });
  } else {
    split_position_it = std::lower_bound(
        positions_span_.begin(), positions_span_.end(), position,
        [](const UsePosition* use_pos, LifetimePosition pos) {
          return use_pos->pos() <= pos;
        });
  }

  size_t result_size = std::distance(split_position_it, positions_span_.end());
  result->positions_span_ = base::VectorOf(split_position_it, result_size);
  positions_span_.Truncate(positions_span_.size() - result_size);

  // Update or discard cached iteration state to make sure it does not point
  // to use positions and intervals that no longer belong to this live range.
  if (current_hint_position_index_ >= positions_span_.size()) {
    result->current_hint_position_index_ =
        current_hint_position_index_ - positions_span_.size();
    current_hint_position_index_ = 0;
  }

  current_interval_ = intervals_.begin();
  result->current_interval_ = result->intervals_.begin();

#ifdef DEBUG
  VerifyChildStructure();
  result->VerifyChildStructure();
#endif

  result->top_level_ = TopLevel();
  result->next_ = next_;
  next_ = result;

  // Update cache for `TopLevelLiveRange::GetChildCovers()`.
  auto& children = TopLevel()->children_;
  children.insert(std::upper_bound(children.begin(), children.end(), result,
                                   LiveRangeOrdering()),
                  1, result);
  return result;
}

void LiveRange::ConvertUsesToOperand(const InstructionOperand& op,
                                     const InstructionOperand& spill_op) {
  for (UsePosition* pos : positions_span_) {
    DCHECK(Start() <= pos->pos() && pos->pos() <= End());
    if (!pos->HasOperand()) continue;
    switch (pos->type()) {
      case UsePositionType::kRequiresSlot:
        DCHECK(spill_op.IsStackSlot() || spill_op.IsFPStackSlot());
        InstructionOperand::ReplaceWith(pos->operand(), &spill_op);
        break;
      case UsePositionType::kRequiresRegister:
        DCHECK(op.IsRegister() || op.IsFPRegister());
        [[fallthrough]];
      case UsePositionType::kRegisterOrSlot:
      case UsePositionType::kRegisterOrSlotOrConstant:
        InstructionOperand::ReplaceWith(pos->operand(), &op);
        break;
    }
  }
}

// This implements an ordering on live ranges so that they are ordered by their
// start positions.  This is needed for the correctness of the register
// allocation algorithm.  If two live ranges start at the same offset then there
// is a tie breaker based on where the value is first used.  This part of the
// ordering is merely a heuristic.
bool LiveRange::ShouldBeAllocatedBefore(const LiveRange* other) const {
  LifetimePosition start = Start();
  LifetimePosition other_start = other->Start();
  if (start == other_start) {
    // Prefer register that has a controlflow hint to make sure it gets
    // allocated first. This allows the control flow aware alloction to
    // just put ranges back into the queue without other ranges interfering.
    if (controlflow_hint() < other->controlflow_hint()) {
      return true;
    }
    // The other has a smaller hint.
    if (controlflow_hint() > other->controlflow_hint()) {
      return false;
    }
    // Both have the same hint or no hint at all. Use first use position.
    // To make the order total, handle the case where both positions are null.
    if (positions_span_.empty() && other->positions_span_.empty()) {
      return TopLevel()->vreg() < other->TopLevel()->vreg();
    }
    if (positions_span_.empty()) return false;
    if (other->positions_span_.empty()) return true;
    UsePosition* pos = positions_span_.first();
    UsePosition* other_pos = other->positions_span_.first();
    // To make the order total, handle the case where both positions are equal.
    if (pos->pos() == other_pos->pos())
      return TopLevel()->vreg() < other->TopLevel()->vreg();
    return pos->pos() < other_pos->pos();
  }
  return start < other_start;
}

void LiveRange::SetUseHints(int register_index) {
  for (UsePosition* pos : positions_span_) {
    if (!pos->HasOperand()) continue;
    switch (pos->type()) {
      case UsePositionType::kRequiresSlot:
        break;
      case UsePositionType::kRequiresRegister:
      case UsePositionType::kRegisterOrSlot:
      case UsePositionType::kRegisterOrSlotOrConstant:
        pos->set_assigned_register(register_index);
        break;
    }
  }
}

bool LiveRange::CanCover(LifetimePosition position) const {
  if (IsEmpty()) return false;
  return Start() <= position && position < End();
}

bool LiveRange::Covers(LifetimePosition position) {
  if (!CanCover(position)) return false;
  bool covers = false;
  UseIntervalVector::iterator interval =
      FirstSearchIntervalForPosition(position);
  while (interval != intervals().end() && interval->start() <= position) {
    // The list of `UseInterval`s shall be sorted.
    DCHECK(interval + 1 == intervals().end() ||
           interval[1].start() >= interval->start());
    if (interval->Contains(position)) {
      covers = true;
      break;
    }
    ++interval;
  }
  if (!covers && interval > intervals_.begin()) {
    // To ensure that we advance {current_interval_} below, move back to the
    // last interval starting before position.
    interval--;
    DCHECK_LE(interval->start(), position);
  }
  AdvanceLastProcessedMarker(interval, position);
  return covers;
}

LifetimePosition LiveRange::NextEndAfter(LifetimePosition position) {
  // NOTE: A binary search was measured to be slower, e.g., on the binary from
  // https://crbug.com/v8/9529.
  UseIntervalVector::iterator interval = std::find_if(
      FirstSearchIntervalForPosition(position), intervals_.end(),
      [=](const UseInterval& interval) { return interval.end() >= position; });
  DCHECK_NE(interval, intervals().end());
  return interval->end();
}

LifetimePosition LiveRange::NextStartAfter(LifetimePosition position) {
  // NOTE: A binary search was measured to be slower, e.g., on the binary from
  // https://crbug.com/v8/9529.
  UseIntervalVector::iterator interval =
      std::find_if(FirstSearchIntervalForPosition(position), intervals_.end(),
                   [=](const UseInterval& interval) {
                     return interval.start() >= position;
                   });
  DCHECK_NE(interval, intervals().end());
  next_start_ = interval->start();
  return next_start_;
}

LifetimePosition LiveRange::FirstIntersection(LiveRange* other) {
  if (IsEmpty() || other->IsEmpty() || other->Start() > End() ||
      Start() > other->End())
    return LifetimePosition::Invalid();

  LifetimePosition min_end = std::min(End(), other->End());
  UseIntervalVector::iterator b = other->intervals_.begin();
  LifetimePosition advance_last_processed_up_to = b->start();
  UseIntervalVector::iterator a = FirstSearchIntervalForPosition(b->start());
  while (a != intervals().end() && b != other->intervals().end()) {
    if (a->start() > min_end || b->start() > min_end) break;
    LifetimePosition cur_intersection = a->Intersect(*b);
    if (cur_intersection.IsValid()) {
      return cur_intersection;
    }
    if (a->start() < b->start()) {
      ++a;
      if (a == intervals().end() || a->start() > other->End()) break;
      AdvanceLastProcessedMarker(a, advance_last_processed_up_to);
    } else {
      ++b;
    }
  }
  return LifetimePosition::Invalid();
}

void LiveRange::Print(const RegisterConfiguration* config,
                      bool with_children) const {
  StdoutStream os;
  PrintableLiveRange wrapper;
  wrapper.register_configuration_ = config;
  for (const LiveRange* i = this; i != nullptr; i = i->next()) {
    wrapper.range_ = i;
    os << wrapper << std::endl;
    if (!with_children) break;
  }
}

void LiveRange::Print(bool with_children) const {
  Print(RegisterConfiguration::Default(), with_children);
}

bool LiveRange::RegisterFromBundle(int* hint) const {
  LiveRangeBundle* bundle = TopLevel()->get_bundle();
  if (bundle == nullptr || bundle->reg() == kUnassignedRegister) return false;
  *hint = bundle->reg();
  return true;
}

void LiveRange::UpdateBundleRegister(int reg) const {
  LiveRangeBundle* bundle = TopLevel()->get_bundle();
  if (bundle == nullptr || bundle->reg() != kUnassignedRegister) return;
  bundle->set_reg(reg);
}

struct TopLevelLiveRange::SpillMoveInsertionList : ZoneObject {
  SpillMoveInsertionList(int gap_index, InstructionOperand* operand,
                         SpillMoveInsertionList* next)
      : gap_index(gap_index), operand(operand), next(next) {}
  const int gap_index;
  InstructionOperand* const operand;
  SpillMoveInsertionList* next;
};

TopLevelLiveRange::TopLevelLiveRange(int vreg, MachineRepresentation rep,
                                     Zone* zone)
    : LiveRange(0, rep, this),
      vreg_(vreg),
      last_child_id_(0),
      spill_operand_(nullptr),
      spill_move_insertion_locations_(nullptr),
      children_({this}, zone),
      spilled_in_deferred_blocks_(false),
      has_preassigned_slot_(false),
      spill_start_index_(kMaxInt) {
  bits_ |= SpillTypeField::encode(SpillType::kNoSpillType);
}

void TopLevelLiveRange::RecordSpillLocation(Zone* zone, int gap_index,
                                            InstructionOperand* operand) {
  DCHECK(HasNoSpillType());
  spill_move_insertion_locations_ = zone->New<SpillMoveInsertionList>(
      gap_index, operand, spill_move_insertion_locations_);
}

void TopLevelLiveRange::CommitSpillMoves(RegisterAllocationData* data,
                                         const InstructionOperand& op) {
  DCHECK_IMPLIES(op.IsConstant(),
                 GetSpillMoveInsertionLocations(data) == nullptr);

  if (HasGeneralSpillRange()) {
    SetLateSpillingSelected(false);
  }

  InstructionSequence* sequence = data->code();
  Zone* zone = sequence->zone();

  for (SpillMoveInsertionList* to_spill = GetSpillMoveInsertionLocations(data);
       to_spill != nullptr; to_spill = to_spill->next) {
    Instruction* instr = sequence->InstructionAt(to_spill->gap_index);
    ParallelMove* move =
        instr->GetOrCreateParallelMove(Instruction::START, zone);
    move->AddMove(*to_spill->operand, op);
    instr->block()->mark_needs_frame();
  }
}

void TopLevelLiveRange::FilterSpillMoves(RegisterAllocationData* data,
                                         const InstructionOperand& op) {
  DCHECK_IMPLIES(op.IsConstant(),
                 GetSpillMoveInsertionLocations(data) == nullptr);
  bool might_be_duplicated = has_slot_use() || spilled();
  InstructionSequence* sequence = data->code();

  SpillMoveInsertionList* previous = nullptr;
  for (SpillMoveInsertionList* to_spill = GetSpillMoveInsertionLocations(data);
       to_spill != nullptr; previous = to_spill, to_spill = to_spill->next) {
    Instruction* instr = sequence->InstructionAt(to_spill->gap_index);
    ParallelMove* move = instr->GetParallelMove(Instruction::START);
    // Skip insertion if it's possible that the move exists already as a
    // constraint move from a fixed output register to a slot.
    bool found = false;
    if (move != nullptr && (might_be_duplicated || has_preassigned_slot())) {
      for (MoveOperands* move_op : *move) {
        if (move_op->IsEliminated()) continue;
        if (move_op->source().Equals(*to_spill->operand) &&
            move_op->destination().Equals(op)) {
          found = true;
          if (has_preassigned_slot()) move_op->Eliminate();
          break;
        }
      }
    }
    if (found || has_preassigned_slot()) {
      // Remove the item from the list.
      if (previous == nullptr) {
        spill_move_insertion_locations_ = to_spill->next;
      } else {
        previous->next = to_spill->next;
      }
      // Even though this location doesn't need a spill instruction, the
      // block does require a frame.
      instr->block()->mark_needs_frame();
    }
  }
}

void TopLevelLiveRange::SetSpillOperand(InstructionOperand* operand) {
  DCHECK(HasNoSpillType());
  DCHECK(!operand->IsUnallocated() && !operand->IsImmediate());
  set_spill_type(SpillType::kSpillOperand);
  spill_operand_ = operand;
}

void TopLevelLiveRange::SetSpillRange(SpillRange* spill_range) {
  DCHECK(!HasSpillOperand());
  DCHECK(spill_range);
  spill_range_ = spill_range;
}

AllocatedOperand TopLevelLiveRange::GetSpillRangeOperand() const {
  SpillRange* spill_range = GetSpillRange();
  int index = spill_range->assigned_slot();
  return AllocatedOperand(LocationOperand::STACK_SLOT, representation(), index);
}

LiveRange* TopLevelLiveRange::GetChildCovers(LifetimePosition pos) {
#ifdef DEBUG
  // Make sure the cache contains the correct, actual children.
  LiveRange* child = this;
  for (LiveRange* cached_child : children_) {
    DCHECK_EQ(cached_child, child);
    child = child->next();
  }
  DCHECK_NULL(child);
#endif

  auto child_it =
      std::lower_bound(children_.begin(), children_.end(), pos,
                       [](const LiveRange* range, LifetimePosition pos) {
                         return range->End() <= pos;
                       });
  return child_it == children_.end() || !(*child_it)->Covers(pos) ? nullptr
                                                                  : *child_it;
}

#ifdef DEBUG
void TopLevelLiveRange::Verify() const {
  VerifyChildrenInOrder();
  for (const LiveRange* child = this; child != nullptr; child = child->next()) {
    VerifyChildStructure();
  }
}

void TopLevelLiveRange::VerifyChildrenInOrder() const {
  LifetimePosition last_end = End();
  for (const LiveRange* child = this->next(); child != nullptr;
       child = child->next()) {
    DCHECK(last_end <= child->Start());
    last_end = child->End();
  }
}
#endif

void TopLevelLiveRange::ShortenTo(LifetimePosition start) {
  TRACE("Shorten live range %d to [%d\n", vreg(), start.value());
  DCHECK(!IsEmpty());
  DCHECK_LE(intervals_.front().start(), start);
  intervals_.front().set_start(start);
  start_ = start;
}

void TopLevelLiveRange::EnsureInterval(LifetimePosition start,
                                       LifetimePosition end, Zone* zone) {
  TRACE("Ensure live range %d in interval [%d %d[\n", vreg(), start.value(),
        end.value());
  DCHECK(!IsEmpty());

  // Drop front intervals until intervals_.front().start() > end.
  LifetimePosition new_end = end;
  while (!intervals_.empty() && intervals_.front().start() <= end) {
    if (intervals_.front().end() > end) {
      new_end = intervals_.front().end();
    }
    intervals_.pop_front();
  }
  intervals_.push_front(zone, UseInterval(start, new_end));
  current_interval_ = intervals_.begin();
  if (end_ < new_end) {
    end_ = new_end;
  }
  if (start_ > start) {
    start_ = start;
  }
}

void TopLevelLiveRange::AddUseInterval(LifetimePosition start,
                                       LifetimePosition end, Zone* zone) {
  TRACE("Add to live range %d interval [%d %d[\n", vreg(), start.value(),
        end.value());
  if (intervals_.empty()) {
    intervals_.push_front(zone, UseInterval(start, end));
    start_ = start;
    end_ = end;
  } else {
    UseInterval& first_interval = intervals_.front();
    if (end == first_interval.start()) {
      // Coalesce directly adjacent intervals.
      first_interval.set_start(start);
      start_ = start;
    } else if (end < first_interval.start()) {
      intervals_.push_front(zone, UseInterval(start, end));
      start_ = start;
    } else {
      // Order of instruction's processing (see ProcessInstructions) guarantees
      // that each new use interval either precedes, intersects with or touches
      // the last added interval.
      DCHECK(intervals_.size() == 1 || end <= intervals_.begin()[1].start());
      first_interval.set_start(std::min(start, first_interval.start()));
      first_interval.set_end(std::max(end, first_interval.end()));
      if (start_ > start) {
        start_ = start;
      }
      if (end_ < end) {
        end_ = end;
      }
    }
  }
  current_interval_ = intervals_.begin();
}

void TopLevelLiveRange::AddUsePosition(UsePosition* use_pos, Zone* zone) {
  TRACE("Add to live range %d use position %d\n", vreg(),
        use_pos->pos().value());
  // Since we `ProcessInstructions` in reverse, the `use_pos` is almost always
  // inserted at the front of `positions_`, hence (i) use linear instead of
  // binary search and (ii) grow towards the `kFront` exclusively on `insert`.
  UsePositionVector::iterator insert_it = std::find_if(
      positions_.begin(), positions_.end(), [=](const UsePosition* pos) {
        return UsePosition::Ordering()(use_pos, pos);
      });
  positions_.insert<kFront>(zone, insert_it, use_pos);

  positions_span_ = base::VectorOf(positions_);
  // We must not have child `LiveRange`s yet (e.g. from splitting), otherwise we
  // would have to adjust their `positions_span_` as well.
  DCHECK_NULL(next_);
}

std::ostream& operator<<(std::ostream& os,
                         const PrintableLiveRange& printable_range) {
  const LiveRange* range = printable_range.range_;
  os << "Range: " << range->TopLevel()->vreg() << ":" << range->relative_id()
     << " ";
  if (range->TopLevel()->is_phi()) os << "phi ";
  if (range->TopLevel()->is_non_loop_phi()) os << "nlphi ";

  os << "{" << std::endl;
  for (UsePosition* use_pos : range->positions()) {
    if (use_pos->HasOperand()) {
      os << *use_pos->operand() << use_pos->pos() << " ";
    }
  }
  os << std::endl;

  for (const UseInterval& interval : range->intervals()) {
    interval.PrettyPrint(os);
    os << std::endl;
  }
  os << "}";
  return os;
}

namespace {
void PrintBlockRow(std::ostream& os, const InstructionBlocks& blocks) {
  os << "     ";
  for (auto block : blocks) {
    LifetimePosition start_pos = LifetimePosition::GapFromInstructionIndex(
        block->first_instruction_index());
    LifetimePosition end_pos = LifetimePosition::GapFromInstructionIndex(
                                   block->last_instruction_index())
                                   .NextFullStart();
    int length = end_pos.value() - start_pos.value();
    constexpr int kMaxPrefixLength = 32;
    char buffer[kMaxPrefixLength];
    int rpo_number = block->rpo_number().ToInt();
    const char* deferred_marker = block->IsDeferred() ? "(deferred)" : "";
    int max_prefix_length = std::min(length, kMaxPrefixLength);
    int prefix = snprintf(buffer, max_prefix_length, "[-B%d-%s", rpo_number,
                          deferred_marker);
    os << buffer;
    int remaining = length - std::min(prefix, max_prefix_length) - 1;
    for (int i = 0; i < remaining; ++i) os << '-';
    os << ']';
  }
  os << '\n';
}
}  // namespace

void LinearScanAllocator::PrintRangeRow(std::ostream& os,
                                        const TopLevelLiveRange* toplevel) {
  int position = 0;
  os << std::setw(3) << toplevel->vreg() << ": ";

  const char* kind_string;
  switch (toplevel->spill_type()) {
    case TopLevelLiveRange::SpillType::kSpillRange:
      kind_string = "ss";
      break;
    case TopLevelLiveRange::SpillType::kDeferredSpillRange:
      kind_string = "sd";
      break;
    case TopLevelLiveRange::SpillType::kSpillOperand:
      kind_string = "so";
      break;
    default:
      kind_string = "s?";
  }

  for (const LiveRange* range = toplevel; range != nullptr;
       range = range->next()) {
    for (const UseInterval& interval : range->intervals()) {
      LifetimePosition start = interval.start();
      LifetimePosition end = interval.end();
      CHECK_GE(start.value(), position);
      for (; start.value() > position; position++) {
        os << ' ';
      }
      int length = end.value() - start.value();
      constexpr int kMaxPrefixLength = 32;
      char buffer[kMaxPrefixLength];
      int max_prefix_length = std::min(length + 1, kMaxPrefixLength);
      int prefix;
      if (range->spilled()) {
        prefix = snprintf(buffer, max_prefix_length, "|%s", kind_string);
      } else {
        prefix = snprintf(buffer, max_prefix_length, "|%s",
                          RegisterName(range->assigned_register()));
      }
      os << buffer;
      position += std::min(prefix, max_prefix_length - 1);
      CHECK_GE(end.value(), position);
      const char line_style = range->spilled() ? '-' : '=';
      for (; end.value() > position; position++) {
        os << line_style;
      }
    }
  }
  os << '\n';
}

void LinearScanAllocator::PrintRangeOverview() {
  std::ostringstream os;
  PrintBlockRow(os, code()->instruction_blocks());
  for (auto const toplevel : data()->fixed_live_ranges()) {
    if (toplevel == nullptr) continue;
    PrintRangeRow(os, toplevel);
  }
  int rowcount = 0;
  for (auto toplevel : data()->live_ranges()) {
    if (!CanProcessRange(toplevel)) continue;
    if (rowcount++ % 10 == 0) PrintBlockRow(os, code()->instruction_blocks());
    PrintRangeRow(os, toplevel);
  }
  PrintF("%s\n", os.str().c_str());
}

SpillRange::SpillRange(TopLevelLiveRange* parent, Zone* zone)
    : ranges_(zone),
      intervals_(zone),
      assigned_slot_(kUnassignedSlot),
      byte_width_(ByteWidthForStackSlot(parent->representation())) {
  DCHECK(!parent->IsEmpty());

  // Spill ranges are created for top level. This is so that, when merging
  // decisions are made, we consider the full extent of the virtual register,
  // and avoid clobbering it.
  LifetimePosition last_end = LifetimePosition::MaxPosition();
  for (const LiveRange* range = parent; range != nullptr;
       range = range->next()) {
    // Deep copy the `UseInterval`s, since the `LiveRange`s are subsequently
    // modified, so just storing those has correctness issues.
    for (UseInterval interval : range->intervals()) {
      DCHECK_NE(LifetimePosition::MaxPosition(), interval.start());
      bool can_coalesce = last_end == interval.start();
      if (can_coalesce) {
        intervals_.back().set_end(interval.end());
      } else {
        intervals_.push_back(interval);
      }
      last_end = interval.end();
    }
  }
  ranges_.push_back(parent);
  parent->SetSpillRange(this);
}

// Checks if the `UseInterval`s in `a` intersect with those in `b`.
// Returns the two intervals that intersected, or `std::nullopt` if none did.
static std::optional<std::pair<UseInterval, UseInterval>>
AreUseIntervalsIntersectingVector(base::Vector<const UseInterval> a,
                                  base::Vector<const UseInterval> b) {
  SLOW_DCHECK(std::is_sorted(a.begin(), a.end()) &&
              std::is_sorted(b.begin(), b.end()));
  if (a.empty() || b.empty() || a.last().end() <= b.first().start() ||
      b.last().end() <= a.first().start()) {
    return {};
  }

  // `a` shall have less intervals then `b`.
  if (a.size() > b.size()) {
    std::swap(a, b);
  }

  auto a_it = a.begin();
  // Advance `b` already to the interval that ends at or after `a_start`.
  LifetimePosition a_start = a.first().start();
  auto b_it = std::lower_bound(
      b.begin(), b.end(), a_start,
      [](const UseInterval& interval, LifetimePosition position) {
        return interval.end() < position;
      });
  while (a_it != a.end() && b_it != b.end()) {
    if (a_it->end() <= b_it->start()) {
      ++a_it;
    } else if (b_it->end() <= a_it->start()) {
      ++b_it;
    } else {
      return std::make_pair(*a_it, *b_it);
    }
  }
  return {};
}

// Used by `LiveRangeBundle`s and `SpillRange`s, hence allow passing different
// containers of `UseInterval`s, as long as they can be converted to a
// `base::Vector` (which is essentially just a memory span).
template <typename ContainerA, typename ContainerB>
std::optional<std::pair<UseInterval, UseInterval>> AreUseIntervalsIntersecting(
    const ContainerA& a, const ContainerB& b) {
  return AreUseIntervalsIntersectingVector(base::VectorOf(a),
                                           base::VectorOf(b));
}

bool SpillRange::TryMerge(SpillRange* other) {
  if (HasSlot() || other->HasSlot()) return false;
  if (byte_width() != other->byte_width()) return false;
  if (AreUseIntervalsIntersecting(intervals_, other->intervals_)) return false;

  // Merge vectors of `UseInterval`s.
  intervals_.reserve(intervals_.size() + other->intervals_.size());
  for (UseInterval interval : other->intervals_) {
    UseInterval* insert_it =
        std::lower_bound(intervals_.begin(), intervals_.end(), interval);
    // Since the intervals didn't intersect, they should also be unique.
    DCHECK_IMPLIES(insert_it != intervals_.end(), *insert_it != interval);
    intervals_.insert(insert_it, 1, interval);
  }
  other->intervals_.clear();

  // Merge vectors of `TopLevelLiveRange`s.
  for (TopLevelLiveRange* range : other->ranges_) {
    DCHECK(range->GetSpillRange() == other);
    range->SetSpillRange(this);
  }
  ranges_.insert(ranges_.end(), other->ranges_.begin(), other->ranges_.end());
  other->ranges_.clear();

  return true;
}

void SpillRange::Print() const {
  StdoutStream os;
  os << "{" << std::endl;
  for (const TopLevelLiveRange* range : ranges_) {
    os << range->vreg() << " ";
  }
  os << std::endl;

  for (const UseInterval& interval : intervals_) {
    interval.PrettyPrint(os);
    os << std::endl;
  }
  os << "}" << std::endl;
}

RegisterAllocationData::PhiMapValue::PhiMapValue(PhiInstruction* phi,
                                                 const InstructionBlock* block,
                                                 Zone* zone)
    : phi_(phi),
      block_(block),
      incoming_operands_(zone),
      assigned_register_(kUnassignedRegister) {
  incoming_operands_.reserve(phi->operands().size());
}

void RegisterAllocationData::PhiMapValue::AddOperand(
    InstructionOperand* operand) {
  incoming_operands_.push_back(operand);
}

void RegisterAllocationData::PhiMapValue::CommitAssignment(
    const InstructionOperand& assigned) {
  for (InstructionOperand* operand : incoming_operands_) {
    InstructionOperand::ReplaceWith(operand, &assigned);
  }
}

RegisterAllocationData::RegisterAllocationData(
    const RegisterConfiguration* config, Zone* zone, Frame* frame,
    InstructionSequence* code, TickCounter* tick_counter,
    const char* debug_name)
    : allocation_zone_(zone),
      frame_(frame),
      code_(code),
      debug_name_(debug_name),
      config_(config),
      phi_map_(allocation_zone()),
      live_in_sets_(code->InstructionBlockCount(), nullptr, allocation_zone()),
      live_out_sets_(code->InstructionBlockCount(), nullptr, allocation_zone()),
      live_ranges_(code->VirtualRegisterCount(), nullptr, allocation_zone()),
      fixed_live_ranges_(kNumberOfFixedRangesPerRegister *
                             this->config()->num_general_registers(),
                         nullptr, allocation_zone()),
      fixed_float_live_ranges_(allocation_zone()),
      fixed_double_live_ranges_(kNumberOfFixedRangesPerRegister *
                                    this->config()->num_double_registers(),
                                nullptr, allocation_zone()),
      fixed_simd128_live_ranges_(allocation_zone()),
      delayed_references_(allocation_zone()),
      assigned_registers_(nullptr),
      assigned_double_registers_(nullptr),
      virtual_register_count_(code->VirtualRegisterCount()),
      preassigned_slot_ranges_(zone),
      spill_state_(code->InstructionBlockCount(), ZoneVector<LiveRange*>(zone),
                   zone),
      tick_counter_(tick_counter),
      slot_for_const_range_(zone) {
  if (kFPAliasing == AliasingKind::kCombine) {
    fixed_float_live_ranges_.resize(
        kNumberOfFixedRangesPerRegister * this->config()->num_float_registers(),
        nullptr);
    fixed_simd128_live_ranges_.resize(
        kNumberOfFixedRangesPerRegister *
            this->config()->num_simd128_registers(),
        nullptr);
  } else if (kFPAliasing == AliasingKind::kIndependent) {
    fixed_simd128_live_ranges_.resize(
        kNumberOfFixedRangesPerRegister *
            this->config()->num_simd128_registers(),
        nullptr);
  }

  // Eagerly initialize live ranges to avoid repeated null checks.
  DCHECK_EQ(code->VirtualRegisterCount(), live_ranges_.size());
  for (int i = 0; i < code->VirtualRegisterCount(); ++i) {
    live_ranges_[i] = NewLiveRange(i, RepresentationFor(i));
  }

  assigned_registers_ = code_zone()->New<BitVector>(
      this->config()->num_general_registers(), code_zone());
  assigned_double_registers_ = code_zone()->New<BitVector>(
      this->config()->num_double_registers(), code_zone());
  fixed_register_use_ = code_zone()->New<BitVector>(
      this->config()->num_general_registers(), code_zone());
  fixed_fp_register_use_ = code_zone()->New<BitVector>(
      this->config()->num_double_registers(), code_zone());
  if (kFPAliasing == AliasingKind::kIndependent) {
    assigned_simd128_registers_ = code_zone()->New<BitVector>(
        this->config()->num_simd128_registers(), code_zone());
    fixed_simd128_register_use_ = code_zone()->New<BitVector>(
        this->config()->num_simd128_registers(), code_zone());
  }

  this->frame()->SetAllocatedRegisters(assigned_registers_);
  this->frame()->SetAllocatedDoubleRegisters(assigned_double_registers_);
}

MoveOperands* RegisterAllocationData::AddGapMove(
    int index, Instruction::GapPosition position,
    const InstructionOperand& from, const InstructionOperand& to) {
  Instruction* instr = code()->InstructionAt(index);
  ParallelMove* moves = instr->GetOrCreateParallelMove(position, code_zone());
  return moves->AddMove(from, to);
}

MachineRepresentation RegisterAllocationData::RepresentationFor(
    int virtual_register) {
  DCHECK_LT(virtual_register, code()->VirtualRegisterCount());
  return code()->GetRepresentation(virtual_register);
}

TopLevelLiveRange* RegisterAllocationData::GetLiveRangeFor(int index) {
  TopLevelLiveRange* result = live_ranges()[index];
  DCHECK_NOT_NULL(result);
  DCHECK_EQ(live_ranges()[index]->vreg(), index);
  return result;
}

TopLevelLiveRange* RegisterAllocationData::NewLiveRange(
    int index, MachineRepresentation rep) {
  return allocation_zone()->New<TopLevelLiveRange>(index, rep,
                                                   allocation_zone());
}

RegisterAllocationData::PhiMapValue* RegisterAllocationData::InitializePhiMap(
    const InstructionBlock* block, PhiInstruction* phi) {
  RegisterAllocationData::PhiMapValue* map_value =
      allocation_zone()->New<RegisterAllocationData::PhiMapValue>(
          phi, block, allocation_zone());
  auto res =
      phi_map_.insert(std::make_pair(phi->virtual_register(), map_value));
  DCHECK(res.second);
  USE(res);
  return map_value;
}

RegisterAllocationData::PhiMapValue* RegisterAllocationData::GetPhiMapValueFor(
    int virtual_register) {
  auto it = phi_map_.find(virtual_register);
  DCHECK(it != phi_map_.end());
  return it->second;
}

RegisterAllocationData::PhiMapValue* RegisterAllocationData::GetPhiMapValueFor(
    TopLevelLiveRange* top_range) {
  return GetPhiMapValueFor(top_range->vreg());
}

bool RegisterAllocationData::ExistsUseWithoutDefinition() {
  bool found = false;
  for (int operand_index : *live_in_sets()[0]) {
    found = true;
    PrintF("Register allocator error: live v%d reached first block.\n",
           operand_index);
    LiveRange* range = GetLiveRangeFor(operand_index);
    PrintF("  (first use is at position %d in instruction %d)\n",
           range->positions().first()->pos().value(),
           range->positions().first()->pos().ToInstructionIndex());
    if (debug_name() == nullptr) {
      PrintF("\n");
    } else {
      PrintF("  (function: %s)\n", debug_name());
    }
  }
  return found;
}

// If a range is defined in a deferred block, we can expect all the range
// to only cover positions in deferred blocks. Otherwise, a block on the
// hot path would be dominated by a deferred block, meaning it is unreachable
// without passing through the deferred block, which is contradictory.
// In particular, when such a range contributes a result back on the hot
// path, it will be as one of the inputs of a phi. In that case, the value
// will be transferred via a move in the Gap::END's of the last instruction
// of a deferred block.
bool RegisterAllocationData::RangesDefinedInDeferredStayInDeferred() {
  const size_t live_ranges_size = live_ranges().size();
  for (const TopLevelLiveRange* range : live_ranges()) {
    CHECK_EQ(live_ranges_size,
             live_ranges().size());  // TODO(neis): crbug.com/831822
    DCHECK_NOT_NULL(range);
    if (range->IsEmpty() ||
        !code()
             ->GetInstructionBlock(range->Start().ToInstructionIndex())
             ->IsDeferred()) {
      continue;
    }
    for (const UseInterval& interval : range->intervals()) {
      int first = interval.FirstGapIndex();
      int last = interval.LastGapIndex();
      for (int instr = first; instr <= last;) {
        const InstructionBlock* block = code()->GetInstructionBlock(instr);
        if (!block->IsDeferred()) return false;
        instr = block->last_instruction_index() + 1;
      }
    }
  }
  return true;
}

SpillRange* RegisterAllocationData::AssignSpillRangeToLiveRange(
    TopLevelLiveRange* range, SpillMode spill_mode) {
  using SpillType = TopLevelLiveRange::SpillType;
  DCHECK(!range->HasSpillOperand());

  SpillRange* spill_range = range->GetAllocatedSpillRange();
  if (spill_range == nullptr) {
    spill_range = allocation_zone()->New<SpillRange>(range, allocation_zone());
  }
  if (spill_mode == SpillMode::kSpillDeferred &&
      (range->spill_type() != SpillType::kSpillRange)) {
    range->set_spill_type(SpillType::kDeferredSpillRange);
  } else {
    range->set_spill_type(SpillType::kSpillRange);
  }

  return spill_range;
}

void RegisterAllocationData::MarkFixedUse(MachineRepresentation rep,
                                          int index) {
  switch (rep) {
    case MachineRepresentation::kFloat16:
    case MachineRepresentation::kFloat32:
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256:
      if (kFPAliasing == AliasingKind::kOverlap) {
        fixed_fp_register_use_->Add(index);
      } else if (kFPAliasing == AliasingKind::kIndependent) {
        if (rep == MachineRepresentation::kFloat16 ||
            rep == MachineRepresentation::kFloat32) {
          fixed_fp_register_use_->Add(index);
        } else {
          fixed_simd128_register_use_->Add(index);
        }
      } else {
        int alias_base_index = -1;
        int aliases = config()->GetAliases(
            rep, index, MachineRepresentation::kFloat64, &alias_base_index);
        DCHECK(aliases > 0 || (aliases == 0 && alias_base_index == -1));
        while (aliases--) {
          int aliased_reg = alias_base_index + aliases;
          fixed_fp_register_use_->Add(aliased_reg);
        }
      }
      break;
    case MachineRepresentation::kFloat64:
      fixed_fp_register_use_->Add(index);
      break;
    default:
      DCHECK(!IsFloatingPoint(rep));
      fixed_register_use_->Add(index);
      break;
  }
}

bool RegisterAllocationData::HasFixedUse(MachineRepresentation rep, int index) {
  switch (rep) {
    case MachineRepresentation::kFloat16:
    case MachineRepresentation::kFloat32:
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256: {
      if (kFPAliasing == AliasingKind::kOverlap) {
        return fixed_fp_register_use_->Contains(index);
      } else if (kFPAliasing == AliasingKind::kIndependent) {
        if (rep == MachineRepresentation::kFloat16 ||
            rep == MachineRepresentation::kFloat32) {
          return fixed_fp_register_use_->Contains(index);
        } else {
          return fixed_simd128_register_use_->Contains(index);
        }
      } else {
        int alias_base_index = -1;
        int aliases = config()->GetAliases(
            rep, index, MachineRepresentation::kFloat64, &alias_base_index);
        DCHECK(aliases > 0 || (aliases == 0 && alias_base_index == -1));
        bool result = false;
        while (aliases-- && !result) {
          int aliased_reg = alias_base_index + aliases;
          result |= fixed_fp_register_use_->Contains(aliased_reg);
        }
        return result;
      }
    }
    case MachineRepresentation::kFloat64:
      return fixed_fp_register_use_->Contains(index);
    default:
      DCHECK(!IsFloatingPoint(rep));
      return fixed_register_use_->Contains(index);
  }
}

void RegisterAllocationData::MarkAllocated(MachineRepresentation rep,
                                           int index) {
  switch (rep) {
    case MachineRepresentation::kFloat16:
    case MachineRepresentation::kFloat32:
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256:
      if (kFPAliasing == AliasingKind::kOverlap) {
        assigned_double_registers_->Add(index);
      } else if (kFPAliasing == AliasingKind::kIndependent) {
        if (rep == MachineRepresentation::kFloat16 ||
            rep == MachineRepresentation::kFloat32) {
          assigned_double_registers_->Add(index);
        } else {
          assigned_simd128_registers_->Add(index);
        }
      } else {
        int alias_base_index = -1;
        int aliases = config()->GetAliases(
            rep, index, MachineRepresentation::kFloat64, &alias_base_index);
        DCHECK(aliases > 0 || (aliases == 0 && alias_base_index == -1));
        while (aliases--) {
          int aliased_reg = alias_base_index + aliases;
          assigned_double_registers_->Add(aliased_reg);
        }
      }
      break;
    case MachineRepresentation::kFloat64:
      assigned_double_registers_->Add(index);
      break;
    default:
      DCHECK(!IsFloatingPoint(rep));
      assigned_registers_->Add(index);
      break;
  }
}

bool RegisterAllocationData::IsBlockBoundary(LifetimePosition pos) const {
  return pos.IsFullStart() &&
         (static_cast<size_t>(pos.ToInstructionIndex()) ==
              code()->instructions().size() ||
          code()->GetInstructionBlock(pos.ToInstructionIndex())->code_start() ==
              pos.ToInstructionIndex());
}

ConstraintBuilder::ConstraintBuilder(RegisterAllocationData* data)
    : data_(data) {}

InstructionOperand* ConstraintBuilder::AllocateFixed(
    UnallocatedOperand* operand, int pos, bool is_tagged, bool is_input) {
  TRACE("Allocating fixed reg for op %d\n", operand->virtual_register());
  DCHECK(operand->HasFixedPolicy());
  InstructionOperand allocated;
  MachineRepresentation rep = InstructionSequence::DefaultRepresentation();
  int virtual_register = operand->virtual_register();
  if (virtual_register != InstructionOperand::kInvalidVirtualRegister) {
    rep = data()->RepresentationFor(virtual_register);
  }
  if (operand->HasFixedSlotPolicy()) {
    allocated = AllocatedOperand(AllocatedOperand::STACK_SLOT, rep,
                                 operand->fixed_slot_index());
  } else if (operand->HasFixedRegisterPolicy()) {
    DCHECK(!IsFloatingPoint(rep));
    DCHECK(data()->config()->IsAllocatableGeneralCode(
        operand->fixed_register_index()));
    allocated = AllocatedOperand(AllocatedOperand::REGISTER, rep,
                                 operand->fixed_register_index());
  } else if (operand->HasFixedFPRegisterPolicy()) {
    DCHECK(IsFloatingPoint(rep));
    DCHECK_NE(InstructionOperand::kInvalidVirtualRegister, virtual_register);
    allocated = AllocatedOperand(AllocatedOperand::REGISTER, rep,
                                 operand->fixed_register_index());
  } else {
    UNREACHABLE();
  }
  if (is_input && allocated.IsAnyRegister()) {
    data()->MarkFixedUse(rep, operand->fixed_register_index());
  }
  InstructionOperand::ReplaceWith(operand, &allocated);
  if (is_tagged) {
    TRACE("Fixed reg is tagged at %d\n", pos);
    Instruction* instr = code()->InstructionAt(pos);
    if (instr->HasReferenceMap()) {
      instr->reference_map()->RecordReference(*AllocatedOperand::cast(operand));
    }
  }
  return operand;
}

void ConstraintBuilder::MeetRegisterConstraints() {
  for (InstructionBlock* block : code()->instruction_blocks()) {
    data_->tick_counter()->TickAndMaybeEnterSafepoint();
    MeetRegisterConstraints(block);
  }
}

void ConstraintBuilder::MeetRegisterConstraints(const InstructionBlock* block) {
  int start = block->first_instruction_index();
  int end = block->last_instruction_index();
  DCHECK_NE(-1, start);
  for (int i = start; i <= end; ++i) {
    MeetConstraintsBefore(i);
    if (i != end) MeetConstraintsAfter(i);
  }
  // Meet register constraints for the instruction in the end.
  MeetRegisterConstraintsForLastInstructionInBlock(block);
}

void ConstraintBuilder::MeetRegisterConstraintsForLastInstructionInBlock(
    const InstructionBlock* block) {
  int end = block->last_instruction_index();
  Instruction* last_instruction = code()->InstructionAt(end);
  for (size_t i = 0; i < last_instruction->OutputCount(); i++) {
    InstructionOperand* output_operand = last_instruction->OutputAt(i);
    DCHECK(!output_operand->IsConstant());
    UnallocatedOperand* output = UnallocatedOperand::cast(output_operand);
    int output_vreg = output->virtual_register();
    TopLevelLiveRange* range = data()->GetLiveRangeFor(output_vreg);
    bool assigned = false;
    if (output->HasFixedPolicy()) {
      AllocateFixed(output, -1, false, false);
      // This value is produced on the stack, we never need to spill it.
      if (output->IsStackSlot()) {
        DCHECK(LocationOperand::cast(output)->index() <
               data()->frame()->GetSpillSlotCount());
        range->SetSpillOperand(LocationOperand::cast(output));
        range->SetSpillStartIndex(end);
        assigned = true;
      }

      for (const RpoNumber& succ : block->successors()) {
        const InstructionBlock* successor = code()->InstructionBlockAt(succ);
        DCHECK_EQ(1, successor->PredecessorCount());
        int gap_index = successor->first_instruction_index();
        // Create an unconstrained operand for the same virtual register
        // and insert a gap move from the fixed output to the operand.
        UnallocatedOperand output_copy(UnallocatedOperand::REGISTER_OR_SLOT,
                                       output_vreg);
        data()->AddGapMove(gap_index, Instruction::START, *output, output_copy);
      }
    }

    if (!assigned) {
      for (const RpoNumber& succ : block->successors()) {
        const InstructionBlock* successor = code()->InstructionBlockAt(succ);
        DCHECK_EQ(1, successor->PredecessorCount());
        int gap_index = successor->first_instruction_index();
        range->RecordSpillLocation(allocation_zone(), gap_index, output);
        range->SetSpillStartIndex(gap_index);
      }
    }
  }
}

void ConstraintBuilder::MeetConstraintsAfter(int instr_index) {
  Instruction* first = code()->InstructionAt(instr_index);
  // Handle fixed temporaries.
  for (size_t i = 0; i < first->TempCount(); i++) {
    UnallocatedOperand* temp = UnallocatedOperand::cast(first->TempAt(i));
    if (temp->HasFixedPolicy()) AllocateFixed(temp, instr_index, false, false);
  }
  // Handle constant/fixed output operands.
  for (size_t i = 0; i < first->OutputCount(); i++) {
    InstructionOperand* output = first->OutputAt(i);
    if (output->IsConstant()) {
      int output_vreg = ConstantOperand::cast(output)->virtual_register();
      TopLevelLiveRange* range = data()->GetLiveRangeFor(output_vreg);
      range->SetSpillStartIndex(instr_index + 1);
      range->SetSpillOperand(output);
      continue;
    }
    UnallocatedOperand* first_output = UnallocatedOperand::cast(output);
    TopLevelLiveRange* range =
        data()->GetLiveRangeFor(first_output->virtual_register());
    bool assigned = false;
    if (first_output->HasFixedPolicy()) {
      int output_vreg = first_output->virtual_register();
      UnallocatedOperand output_copy(UnallocatedOperand::REGISTER_OR_SLOT,
                                     output_vreg);
      bool is_tagged = code()->IsReference(output_vreg);
      if (first_output->HasSecondaryStorage()) {
        range->MarkHasPreassignedSlot();
        data()->preassigned_slot_ranges().push_back(
            std::make_pair(range, first_output->GetSecondaryStorage()));
      }
      AllocateFixed(first_output, instr_index, is_tagged, false);

      // This value is produced on the stack, we never need to spill it.
      if (first_output->IsStackSlot()) {
        DCHECK(LocationOperand::cast(first_output)->index() <
               data()->frame()->GetTotalFrameSlotCount());
        range->SetSpillOperand(LocationOperand::cast(first_output));
        range->SetSpillStartIndex(instr_index + 1);
        assigned = true;
      }
      data()->AddGapMove(instr_index + 1, Instruction::START, *first_output,
                         output_copy);
    }
    // Make sure we add a gap move for spilling (if we have not done
    // so already).
    if (!assigned) {
      range->RecordSpillLocation(allocation_zone(), instr_index + 1,
                                 first_output);
      range->SetSpillStartIndex(instr_index + 1);
    }
  }
}

void ConstraintBuilder::MeetConstraintsBefore(int instr_index) {
  Instruction* second = code()->InstructionAt(instr_index);
  // Handle fixed input operands of second instruction.
  ZoneVector<TopLevelLiveRange*>* spilled_consts = nullptr;
  for (size_t i = 0; i < second->InputCount(); i++) {
    InstructionOperand* input = second->InputAt(i);
    if (input->IsImmediate()) {
      continue;  // Ignore immediates.
    }
    UnallocatedOperand* cur_input = UnallocatedOperand::cast(input);
    if (cur_input->HasSlotPolicy()) {
      TopLevelLiveRange* range =
          data()->GetLiveRangeFor(cur_input->virtual_register());
      if (range->HasSpillOperand() && range->GetSpillOperand()->IsConstant()) {
        bool already_spilled = false;
        if (spilled_consts == nullptr) {
          spilled_consts =
              allocation_zone()->New<ZoneVector<TopLevelLiveRange*>>(
                  allocation_zone());
        } else {
          auto it =
              std::find(spilled_consts->begin(), spilled_consts->end(), range);
          already_spilled = it != spilled_consts->end();
        }
        auto it = data()->slot_for_const_range().find(range);
        if (it == data()->slot_for_const_range().end()) {
          DCHECK(!already_spilled);
          int width = ByteWidthForStackSlot(range->representation());
          int index = data()->frame()->AllocateSpillSlot(width);
          auto* slot = AllocatedOperand::New(allocation_zone(),
                                             LocationOperand::STACK_SLOT,
                                             range->representation(), index);
          it = data()->slot_for_const_range().emplace(range, slot).first;
        }
        if (!already_spilled) {
          auto* slot = it->second;
          int input_vreg = cur_input->virtual_register();
          UnallocatedOperand input_copy(UnallocatedOperand::REGISTER_OR_SLOT,
                                        input_vreg);
          // Spill at every use position for simplicity, this case is very rare.
          data()->AddGapMove(instr_index, Instruction::END, input_copy, *slot);
          spilled_consts->push_back(range);
        }
      }
    }
    if (cur_input->HasFixedPolicy()) {
      int input_vreg = cur_input->virtual_register();
      UnallocatedOperand input_copy(UnallocatedOperand::REGISTER_OR_SLOT,
                                    input_vreg);
      bool is_tagged = code()->IsReference(input_vreg);
      AllocateFixed(cur_input, instr_index, is_tagged, true);
      data()->AddGapMove(instr_index, Instruction::END, input_copy, *cur_input);
    }
  }
  // Handle "output same as input" for second instruction.
  for (size_t i = 0; i < second->OutputCount(); i++) {
    InstructionOperand* output = second->OutputAt(i);
    if (!output->IsUnallocated()) continue;
    UnallocatedOperand* second_output = UnallocatedOperand::cast(output);
    if (!second_output->HasSameAsInputPolicy()) continue;
    DCHECK_EQ(0, i);  // Only valid for first output.
    UnallocatedOperand* cur_input =
        UnallocatedOperand::cast(second->InputAt(second_output->input_index()));
    int output_vreg = second_output->virtual_register();
    int input_vreg = cur_input->virtual_register();
    UnallocatedOperand input_copy(UnallocatedOperand::REGISTER_OR_SLOT,
                                  input_vreg);
    *cur_input =
        UnallocatedOperand(*cur_input, second_output->virtual_register());
    MoveOperands* gap_move = data()->AddGapMove(instr_index, Instruction::END,
                                                input_copy, *cur_input);
    DCHECK_NOT_NULL(gap_move);
    if (code()->IsReference(input_vreg) && !code()->IsReference(output_vreg)) {
      if (second->HasReferenceMap()) {
        RegisterAllocationData::DelayedReference delayed_reference = {
            second->reference_map()
```