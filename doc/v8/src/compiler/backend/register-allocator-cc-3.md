Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/backend/register-allocator.cc`.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Task:** The filename `register-allocator.cc` strongly suggests that this code is responsible for managing the assignment of registers to variables or intermediate values during compilation. This is a crucial step in optimizing code execution.

2. **Analyze Class Structure:**  The code defines several classes: `LiveRangeBuilder`, `BundleBuilder`, `LiveRangeBundle`, `RegisterAllocator`, and `LinearScanAllocator`. This suggests a modular design with different components handling specific aspects of register allocation.

3. **Examine Key Methods within Each Class:**
    * **`LiveRangeBuilder`:**  Methods like `IntervalStartsAtBlockBoundary`, `IntervalPredecessorsCoveredByRange`, and `NextIntervalStartsInDifferentBlocks` point to analyzing the lifetime of variables across different code blocks. This class seems to be involved in determining when a variable is "live" and needs a register.
    * **`BundleBuilder`:** The `BuildBundles` method suggests grouping live ranges together. The logic inside the loop, especially the handling of `phi` instructions and merging bundles, indicates an attempt to optimize register usage for values flowing through control flow merges (like at the beginning of loops).
    * **`LiveRangeBundle`:**  Methods like `TryAddRange`, `AddRange`, `TryMerge`, and `MergeSpillRangesAndClear` are clearly about managing groups of live ranges (bundles). The naming suggests efforts to avoid conflicts and efficiently handle spilling (moving data to memory).
    * **`RegisterAllocator`:** This appears to be the base class providing core register allocation functionality. Methods like `GetSplitPositionForInstruction`, `SplitAndSpillRangesDefinedByMemoryOperand`, `SplitRangeAt`, `SplitBetween`, `FindOptimalSplitPos`, `FindOptimalSpillingPos`, and `Spill` clearly indicate actions related to dividing the lifetime of variables and deciding when to move them to memory. The constructor also shows it's aware of different register kinds.
    * **`LinearScanAllocator`:**  The presence of `unhandled_live_ranges_`, `active_live_ranges_`, and `inactive_live_ranges_` suggests a linear scan algorithm approach. Methods like `MaybeSpillPreviousRanges`, `MaybeUndoPreviousSplit`, `SpillNotLiveRanges`, `AssignRegisterOnReload`, `ReloadLiveRanges`, and `ComputeStateFromManyPredecessors` detail the steps involved in iterating through live ranges and assigning registers based on their lifetimes and potential conflicts.

4. **Infer High-Level Functionality:** Based on the class structure and methods, the overall functionality appears to be:
    * **Live Range Analysis:** Determining the start and end points of a variable's usage.
    * **Live Range Bundling:** Grouping compatible live ranges to potentially share the same register.
    * **Register Assignment:**  Assigning physical registers to live ranges, potentially using a linear scan approach.
    * **Spilling:** Deciding when to move a variable's value from a register to memory (the "stack") when there aren't enough registers available.
    * **Splitting:** Dividing a live range into smaller pieces, potentially to assign different registers or spill parts of it.
    * **Handling Control Flow:**  Special consideration for `phi` instructions at merge points in the control flow graph.

5. **Address Specific Prompts:**
    * **`.tq` extension:** The code snippet is C++, so it's not a Torque file.
    * **JavaScript Relation:** Register allocation directly impacts how efficiently JavaScript code runs. When V8 compiles JavaScript, it needs to manage the storage of values. Register allocation tries to keep frequently used values in fast registers.
    * **Code Logic Reasoning:** Focus on the `BundleBuilder::BuildBundles` method as it has identifiable input and output. The input is a `phi` instruction and its operands (which represent incoming values). The output is the merging of live range bundles.
    * **Common Programming Errors:** Spilling is often related to performance. If register allocation is poor, excessive spilling can lead to slow execution.
    * **Part of a Larger Process:** Acknowledge that this is part of a multi-step process.

6. **Structure the Summary:** Organize the findings into a clear and concise summary addressing each point raised in the prompt. Use bullet points for readability.

7. **Refine and Review:** Ensure the summary accurately reflects the code's functionality and addresses all aspects of the user's request. For instance, emphasize the optimization aspect of register allocation.
```cpp
rval));
        }
      }
    }
  }
}

bool LiveRangeBuilder::IntervalStartsAtBlockBoundary(
    UseInterval interval) const {
  LifetimePosition start = interval.start();
  if (!start.IsFullStart()) return false;
  int instruction_index = start.ToInstructionIndex();
  const InstructionBlock* block =
      data()->code()->GetInstructionBlock(instruction_index);
  return block->first_instruction_index() == instruction_index;
}

bool LiveRangeBuilder::IntervalPredecessorsCoveredByRange(
    UseInterval interval, TopLevelLiveRange* range) const {
  LifetimePosition start = interval.start();
  int instruction_index = start.ToInstructionIndex();
  const InstructionBlock* block =
      data()->code()->GetInstructionBlock(instruction_index);
  for (RpoNumber pred_index : block->predecessors()) {
    const InstructionBlock* predecessor =
        data()->code()->InstructionBlockAt(pred_index);
    LifetimePosition last_pos = LifetimePosition::GapFromInstructionIndex(
        predecessor->last_instruction_index());
    last_pos = last_pos.NextStart().End();
    if (!range->Covers(last_pos)) return false;
  }
  return true;
}

bool LiveRangeBuilder::NextIntervalStartsInDifferentBlocks(
    UseInterval interval, UseInterval next) const {
  LifetimePosition end = interval.end();
  LifetimePosition next_start = next.start();
  // Since end is not covered, but the previous position is, move back a
  // position
  end = end.IsStart() ? end.PrevStart().End() : end.Start();
  int last_covered_index = end.ToInstructionIndex();
  const InstructionBlock* block =
      data()->code()->GetInstructionBlock(last_covered_index);
  const InstructionBlock* next_block =
      data()->code()->GetInstructionBlock(next_start.ToInstructionIndex());
  return block->rpo_number() < next_block->rpo_number();
}
#endif

void BundleBuilder::BuildBundles() {
  TRACE("Build bundles\n");
  // Process the blocks in reverse order.
  for (int block_id = code()->InstructionBlockCount() - 1; block_id >= 0;
       --block_id) {
    InstructionBlock* block =
        code()->InstructionBlockAt(RpoNumber::FromInt(block_id));
    TRACE("Block B%d\n", block_id);
    for (auto phi : block->phis()) {
      TopLevelLiveRange* out_range =
          data()->GetLiveRangeFor(phi->virtual_register());
      LiveRangeBundle* out = out_range->get_bundle();
      if (out == nullptr) {
        out = data()->allocation_zone()->New<LiveRangeBundle>(
            data()->allocation_zone(), next_bundle_id_++);
        out->TryAddRange(out_range);
      }
      TRACE("Processing phi for v%d with %d:%d\n", phi->virtual_register(),
            out_range->TopLevel()->vreg(), out_range->relative_id());
      bool phi_interferes_with_backedge_input = false;
      for (auto input : phi->operands()) {
        TopLevelLiveRange* input_range = data()->GetLiveRangeFor(input);
        TRACE("Input value v%d with range %d:%d\n", input,
              input_range->TopLevel()->vreg(), input_range->relative_id());
        LiveRangeBundle* input_bundle = input_range->get_bundle();
        if (input_bundle != nullptr) {
          TRACE("Merge\n");
          LiveRangeBundle* merged =
              LiveRangeBundle::TryMerge(out, input_bundle);
          if (merged != nullptr) {
            DCHECK_EQ(out_range->get_bundle(), merged);
            DCHECK_EQ(input_range->get_bundle(), merged);
            out = merged;
            TRACE("Merged %d and %d to %d\n", phi->virtual_register(), input,
                  out->id());
          } else if (input_range->Start() > out_range->Start()) {
            // We are only interested in values defined after the phi, because
            // those are values that will go over a back-edge.
            phi_interferes_with_backedge_input = true;
          }
        } else {
          TRACE("Add\n");
          if (out->TryAddRange(input_range)) {
            TRACE("Added %d and %d to %d\n", phi->virtual_register(), input,
                  out->id());
          } else if (input_range->Start() > out_range->Start()) {
            // We are only interested in values defined after the phi, because
            // those are values that will go over a back-edge.
            phi_interferes_with_backedge_input = true;
          }
        }
      }
      // Spilling the phi at the loop header is not beneficial if there is
      // a back-edge with an input for the phi that interferes with the phi's
      // value, because in case that input gets spilled it might introduce
      // a stack-to-stack move at the back-edge.
      if (phi_interferes_with_backedge_input)
        out_range->TopLevel()->set_spilling_at_loop_header_not_beneficial();
    }
    TRACE("Done block B%d\n", block_id);
  }
}

bool LiveRangeBundle::TryAddRange(TopLevelLiveRange* range) {
  DCHECK_NULL(range->get_bundle());
  // We may only add a new live range if its use intervals do not
  // overlap with existing intervals in the bundle.
  if (AreUseIntervalsIntersecting(this->intervals_, range->intervals()))
    return false;
  AddRange(range);
  return true;
}

void LiveRangeBundle::AddRange(TopLevelLiveRange* range) {
  TopLevelLiveRange** insert_it = std::lower_bound(
      ranges_.begin(), ranges_.end(), range, LiveRangeOrdering());
  DCHECK_IMPLIES(insert_it != ranges_.end(), *insert_it != range);
  // TODO(dlehmann): We might save some memory by using
  // `DoubleEndedSplitVector::insert<kFront>()` here: Since we add ranges
  // mostly backwards, ranges with an earlier `Start()` are inserted mostly
  // at the front.
  ranges_.insert(insert_it, 1, range);
  range->set_bundle(this);

  // We also tried `std::merge`ing the sorted vectors of `intervals_` directly,
  // but it turns out the (always happening) copies are more expensive
  // than the (apparently seldom) copies due to insertion in the middle.
  for (UseInterval interval : range->intervals()) {
    UseInterval* insert_it =
        std::lower_bound(intervals_.begin(), intervals_.end(), interval);
    DCHECK_IMPLIES(insert_it != intervals_.end(), *insert_it != interval);
    intervals_.insert(insert_it, 1, interval);
  }
}

LiveRangeBundle* LiveRangeBundle::TryMerge(LiveRangeBundle* lhs,
                                           LiveRangeBundle* rhs) {
  if (rhs == lhs) return lhs;

  if (auto found =
          AreUseIntervalsIntersecting(lhs->intervals_, rhs->intervals_)) {
    auto [interval1, interval2] = *found;
    TRACE("No merge %d:%d %d:%d\n", interval1.start().value(),
          interval1.end().value(), interval2.start().value(),
          interval2.end().value());
    return nullptr;
  }
  // Uses are disjoint, merging is possible.

  // Merge the smaller bundle into the bigger.
  if (lhs->intervals_.size() < rhs->intervals_.size()) {
    std::swap(lhs, rhs);
  }
  for (TopLevelLiveRange* range : rhs->ranges_) {
    lhs->AddRange(range);
  }

  rhs->ranges_.clear();
  rhs->intervals_.clear();

  return lhs;
}

void LiveRangeBundle::MergeSpillRangesAndClear() {
  DCHECK_IMPLIES(ranges_.empty(), intervals_.empty());
  SpillRange* target = nullptr;
  for (auto range : ranges_) {
    if (range->TopLevel()->HasSpillRange()) {
      SpillRange* current = range->TopLevel()->GetSpillRange();
      if (target == nullptr) {
        target = current;
      } else if (target != current) {
        target->TryMerge(current);
      }
    }
  }
  // Clear the fields so that we don't try to merge the spill ranges again when
  // we hit the same bundle from a different LiveRange in AssignSpillSlots.
  // LiveRangeBundles are not used after this.
  ranges_.clear();
  intervals_.clear();
}

RegisterAllocator::RegisterAllocator(RegisterAllocationData* data,
                                     RegisterKind kind)
    : data_(data),
      mode_(kind),
      num_registers_(GetRegisterCount(data->config(), kind)),
      num_allocatable_registers_(
          GetAllocatableRegisterCount(data->config(), kind)),
      allocatable_register_codes_(
          GetAllocatableRegisterCodes(data->config(), kind)),
      check_fp_aliasing_(false) {
  if (kFPAliasing == AliasingKind::kCombine && kind == RegisterKind::kDouble) {
    check_fp_aliasing_ = (data->code()->representation_mask() &
                          (kFloat32Bit | kSimd128Bit)) != 0;
  }
}

LifetimePosition RegisterAllocator::GetSplitPositionForInstruction(
    const LiveRange* range, int instruction_index) {
  LifetimePosition ret = LifetimePosition::Invalid();

  ret = LifetimePosition::GapFromInstructionIndex(instruction_index);
  if (range->Start() >= ret || ret >= range->End()) {
    return LifetimePosition::Invalid();
  }
  return ret;
}

void RegisterAllocator::SplitAndSpillRangesDefinedByMemoryOperand() {
  size_t initial_range_count = data()->live_ranges().size();
  for (size_t i = 0; i < initial_range_count; ++i) {
    CHECK_EQ(initial_range_count,
             data()->live_ranges().size());  // TODO(neis): crbug.com/831822
    TopLevelLiveRange* range = data()->live_ranges()[i];
    if (!CanProcessRange(range)) continue;
    // Only assume defined by memory operand if we are guaranteed to spill it or
    // it has a spill operand.
    if (range->HasNoSpillType() ||
        (range->HasSpillRange() && !range->has_non_deferred_slot_use())) {
      continue;
    }
    LifetimePosition start = range->Start();
    TRACE("Live range %d:%d is defined by a spill operand.\n",
          range->TopLevel()->vreg(), range->relative_id());
    LifetimePosition next_pos = start;
    if (next_pos.IsGapPosition()) {
      next_pos = next_pos.NextStart();
    }

    UsePosition* pos = range->NextUsePositionRegisterIsBeneficial(next_pos);
    // If the range already has a spill operand and it doesn't need a
    // register immediately, split it and spill the first part of the range.
    if (pos == nullptr) {
      Spill(range, SpillMode::kSpillAtDefinition);
    } else if (pos->pos() > range->Start().NextStart()) {
      // Do not spill live range eagerly if use position that can benefit from
      // the register is too close to the start of live range.
      LifetimePosition split_pos = GetSplitPositionForInstruction(
          range, pos->pos().ToInstructionIndex());
      // There is no place to split, so we can't split and spill.
      if (!split_pos.IsValid()) continue;

      split_pos =
          FindOptimalSplitPos(range->Start().NextFullStart(), split_pos);

      SplitRangeAt(range, split_pos);
      Spill(range, SpillMode::kSpillAtDefinition);
    }
  }
}

LiveRange* RegisterAllocator::SplitRangeAt(LiveRange* range,
                                           LifetimePosition pos) {
  DCHECK(!range->TopLevel()->IsFixed());
  TRACE("Splitting live range %d:%d at %d\n", range->TopLevel()->vreg(),
        range->relative_id(), pos.value());

  if (pos <= range->Start()) return range;

  // We can't properly connect liveranges if splitting occurred at the end
  // a block.
  DCHECK(pos.IsStart() || pos.IsGapPosition() ||
         (GetInstructionBlock(code(), pos)->last_instruction_index() !=
          pos.ToInstructionIndex()));

  LiveRange* result = range->SplitAt(pos, allocation_zone());
  return result;
}

LiveRange* RegisterAllocator::SplitBetween(LiveRange* range,
                                           LifetimePosition start,
                                           LifetimePosition end) {
  DCHECK(!range->TopLevel()->IsFixed());
  TRACE("Splitting live range %d:%d in position between [%d, %d]\n",
        range->TopLevel()->vreg(), range->relative_id(), start.value(),
        end.value());

  LifetimePosition split_pos = FindOptimalSplitPos(start, end);
  DCHECK(split_pos >= start);
  return SplitRangeAt(range, split_pos);
}

LifetimePosition RegisterAllocator::FindOptimalSplitPos(LifetimePosition start,
                                                        LifetimePosition end) {
  int start_instr = start.ToInstructionIndex();
  int end_instr = end.ToInstructionIndex();
  DCHECK_LE(start_instr, end_instr);

  // We have no choice
  if (start_instr == end_instr) return end;

  const InstructionBlock* start_block = GetInstructionBlock(code(), start);
  const InstructionBlock* end_block = GetInstructionBlock(code(), end);

  if (end_block == start_block) {
    // The interval is split in the same basic block. Split at the latest
    // possible position.
    return end;
  }

  const InstructionBlock* block = end_block;
  // Find header of outermost loop.
  do {
    const InstructionBlock* loop = GetContainingLoop(code(), block);
    if (loop == nullptr ||
        loop->rpo_number().ToInt() <= start_block->rpo_number().ToInt()) {
      // No more loops or loop starts before the lifetime start.
      break;
    }
    block = loop;
  } while (true);

  // We did not find any suitable outer loop. Split at the latest possible
  // position unless end_block is a loop header itself.
  if (block == end_block && !end_block->IsLoopHeader()) return end;

  return LifetimePosition::GapFromInstructionIndex(
      block->first_instruction_index());
}

LifetimePosition RegisterAllocator::FindOptimalSpillingPos(
    LiveRange* range, LifetimePosition pos, SpillMode spill_mode,
    LiveRange** begin_spill_out) {
  *begin_spill_out = range;
  // TODO(herhut): Be more clever here as long as we do not move pos out of
  // deferred code.
  if (spill_mode == SpillMode::kSpillDeferred) return pos;
  const InstructionBlock* block = GetInstructionBlock(code(), pos.Start());
  const InstructionBlock* loop_header =
      block->IsLoopHeader() ? block : GetContainingLoop(code(), block);
  if (loop_header == nullptr) return pos;

  while (loop_header != nullptr) {
    // We are going to spill live range inside the loop.
    // If possible try to move spilling position backwards to loop header.
    // This will reduce number of memory moves on the back edge.
    LifetimePosition loop_start = LifetimePosition::GapFromInstructionIndex(
        loop_header->first_instruction_index());
    // Stop if we moved to a loop header before the value is defined or
    // at the define position that is not beneficial to spill.
    if (range->TopLevel()->Start() > loop_start ||
        (range->TopLevel()->Start() == loop_start &&
         range->TopLevel()->SpillAtLoopHeaderNotBeneficial()))
      return pos;

    LiveRange* live_at_header = range->TopLevel()->GetChildCovers(loop_start);

    if (live_at_header != nullptr && !live_at_header->spilled()) {
      for (const LiveRange* check_use = live_at_header;
           check_use != nullptr && check_use->Start() < pos;
           check_use = check_use->next()) {
        // If we find a use for which spilling is detrimental, don't spill
        // at the loop header
        UsePosition* next_use =
            check_use->NextUsePositionSpillDetrimental(loop_start);
        // UsePosition at the end of a UseInterval may
        // have the same value as the start of next range.
        if (next_use != nullptr && next_use->pos() <= pos) {
          return pos;
        }
      }
      // No register beneficial use inside the loop before the pos.
      *begin_spill_out = live_at_header;
      pos = loop_start;
    }

    // Try hoisting out to an outer loop.
    loop_header = GetContainingLoop(code(), loop_header);
  }
  return pos;
}

void RegisterAllocator::Spill(LiveRange* range, SpillMode spill_mode) {
  DCHECK(!range->spilled());
  DCHECK(spill_mode == SpillMode::kSpillAtDefinition ||
         GetInstructionBlock(code(), range->Start())->IsDeferred());
  TopLevelLiveRange* first = range->TopLevel();
  TRACE("Spilling live range %d:%d mode %d\n", first->vreg(),
        range->relative_id(), spill_mode);

  TRACE("Starting spill type is %d\n", static_cast<int>(first->spill_type()));
  if (first->HasNoSpillType()) {
    TRACE("New spill range needed\n");
    data()->AssignSpillRangeToLiveRange(first, spill_mode);
  }
  // Upgrade the spillmode, in case this was only spilled in deferred code so
  // far.
  if ((spill_mode == SpillMode::kSpillAtDefinition) &&
      (first->spill_type() ==
       TopLevelLiveRange::SpillType::kDeferredSpillRange)) {
    TRACE("Upgrading\n");
    first->set_spill_type(TopLevelLiveRange::SpillType::kSpillRange);
  }
  TRACE("Final spill type is %d\n", static_cast<int>(first->spill_type()));
  range->Spill();
}

const char* RegisterAllocator::RegisterName(int register_code) const {
  if (register_code == kUnassignedRegister) return "unassigned";
  switch (mode()) {
    case RegisterKind::kGeneral:
      return i::RegisterName(Register::from_code(register_code));
    case RegisterKind::kDouble:
      return i::RegisterName(DoubleRegister::from_code(register_code));
    case RegisterKind::kSimd128:
      return i::RegisterName(Simd128Register::from_code(register_code));
  }
}

LinearScanAllocator::LinearScanAllocator(RegisterAllocationData* data,
                                         RegisterKind kind, Zone* local_zone)
    : RegisterAllocator(data, kind),
      unhandled_live_ranges_(local_zone),
      active_live_ranges_(local_zone),
      inactive_live_ranges_(num_registers(), InactiveLiveRangeQueue(local_zone),
                            local_zone),
      next_active_ranges_change_(LifetimePosition::Invalid()),
      next_inactive_ranges_change_(LifetimePosition::Invalid()) {
  active_live_ranges().reserve(8);
}

void LinearScanAllocator::MaybeSpillPreviousRanges(LiveRange* begin_range,
                                                   LifetimePosition begin_pos,
                                                   LiveRange* end_range) {
  // Spill begin_range after begin_pos, then spill every live range of this
  // virtual register until but excluding end_range.
  DCHECK(begin_range->Covers(begin_pos));
  DCHECK_EQ(begin_range->TopLevel(), end_range->TopLevel());

  if (begin_range != end_range) {
    DCHECK_LE(begin_range->End(), end_range->Start());
    if (!begin_range->spilled()) {
      SpillAfter(begin_range, begin_pos, SpillMode::kSpillAtDefinition);
    }
    for (LiveRange* range = begin_range->next(); range != end_range;
         range = range->next()) {
      if (!range->spilled()) {
        range->Spill();
      }
    }
  }
}

void LinearScanAllocator::MaybeUndoPreviousSplit(LiveRange* range, Zone* zone) {
  if (range->next() != nullptr && range->next()->ShouldRecombine()) {
    LiveRange* to_remove = range->next();
    TRACE("Recombining %d:%d with %d\n", range->TopLevel()->vreg(),
          range->relative_id(), to_remove->relative_id());

    // Remove the range from unhandled, as attaching it will change its
    // state and hence ordering in the unhandled set.
    auto removed_cnt = unhandled_live_ranges().erase(to_remove);
    DCHECK_EQ(removed_cnt, 1);
    USE(removed_cnt);

    range->AttachToNext(zone);
  } else if (range->next() != nullptr) {
    TRACE("No recombine for %d:%d to %d\n", range->TopLevel()->vreg(),
          range->relative_id(), range->next()->relative_id());
  }
}

void LinearScanAllocator::SpillNotLiveRanges(RangeRegisterSmallMap& to_be_live,
                                             LifetimePosition position,
                                             SpillMode spill_mode) {
  for (auto it = active_live_ranges().begin();
       it != active_live_ranges().end();) {
    LiveRange* active_range = *it;
    TopLevelLiveRange* toplevel = (*it)->TopLevel();
    auto found = to_be_live.find(toplevel);
    if (found == to_be_live.end()) {
      // Is not contained in {to_be_live}, spill it.
      // Fixed registers are exempt from this. They might have been
      // added from inactive at the block boundary but we know that
      // they cannot conflict as they are built before register
      // allocation starts. It would be algorithmically fine to split
      // them and reschedule but the code does not allow to do this.
      if (toplevel->IsFixed()) {
        TRACE("Keeping reactivated fixed range for %s\n",
              RegisterName(toplevel->assigned_register()));
        ++it;
      } else {
        // When spilling a previously spilled/reloaded range, we add back the
        // tail that we might have split off when we reloaded/spilled it
        // previously. Otherwise we might keep generating small split-offs.
        MaybeUndoPreviousSplit(active_range, allocation_zone());
        TRACE("Putting back %d:%d\n", toplevel->vreg(),
              active_range->relative_id());
        LiveRange* split = SplitRangeAt(active_range, position);
        DCHECK_NE(split, active_range);

        // Make sure we revisit this range once it has a use that requires
        // a register.
        UsePosition* next_use = split->NextRegisterPosition(position);
        if (next_use != nullptr) {
          // Move to the start of the gap before use so that we have a space
          // to perform the potential reload. Otherwise, do not spill but add
          // to unhandled for reallocation.
          LifetimePosition revisit_at = next_use->pos().FullStart();
          TRACE("Next use at %d\n", revisit_at.value());
          if (!data()->IsBlockBoundary(revisit_at)) {
            // Leave some space so we have enough gap room.
            revisit_at = revisit_at.PrevStart().FullStart();
          }
          // If this range became life right at the block boundary that we are
          // currently processing, we do not need to split it. Instead move it
          // to unhandled right away.
          if (position < revisit_at) {
            LiveRange* third_part = SplitRangeAt(split, revisit_at);
            DCHECK_NE(split, third_part);
            Spill(split, spill_mode);
            TRACE("Marking %d:%d to recombine\n", toplevel->vreg(),
                  third_part->relative_id());
            third_part->SetRecombine();
            AddToUnhandled(third_part);
          } else {
            AddToUnhandled(split);
          }
        } else {
          Spill(split, spill_mode);
        }
        it = ActiveToHandled(it);
      }
    } else {
      // This range is contained in {to_be_live}, so we can keep it.
      int expected_register = found->second;
      to_be_live.erase(found);
      if (expected_register == active_range->assigned_register()) {
        // Was life and in correct register, simply pass through.
        TRACE("Keeping %d:%d in %s\n", toplevel->vreg(),
              active_range->relative_id(),
              RegisterName(active_range->assigned_register()));
        ++it;
      } else {
        // Was life but wrong register. Split and schedule for
        // allocation.
        TRACE("Scheduling %d:%d\n", toplevel->vreg(),
              active_range->relative_id());
        LiveRange* split = SplitRangeAt(active_range, position);
        split->set_controlflow_hint(expected_register);
        AddToUnhandled(split);
        it = ActiveToHandled(it);
      }
    }
  }
}

LiveRange* LinearScanAllocator::AssignRegisterOnReload(LiveRange* range,
                                                       int reg) {
  // We know the register is currently free but it might be in
  // use by a currently inactive range. So we might not be able
  // to reload for the full distance. In such case, split here.
  // TODO(herhut):
  // It might be better if we could use the normal unhandled queue and
  // give reloading registers pecedence. That way we would compute the
  // intersection for the entire future.
  LifetimePosition new_end = range->End();
  for (int cur_reg = 0; cur_reg < num_registers(); ++cur_reg) {
    if ((kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) &&
        cur_reg != reg) {
      continue;
    }
    SlowDCheckInactiveLiveRangesIsSorted(cur_reg);
    for (LiveRange* cur_inactive : inactive_live_ranges(cur_reg)) {
      if (kFPAliasing == AliasingKind::kCombine && check_fp_aliasing() &&
          !data()->config()->AreAliases(cur_inactive->representation(), cur_reg,
                                        range->representation(), reg)) {
        continue;
      }
      if (new_end <= cur_inactive->NextStart()) {
        // Inactive ranges are sorted by their next start, so the remaining
        // ranges cannot contribute to new_end.
        break;
      }
      auto next_intersection = cur_inactive->FirstIntersection(range);
      if (!next_intersection.IsValid()) continue;
      new_end = std::min(new_end, next_intersection);
    }
  }
  if (new_end != range->End()) {
    TRACE("Found new end for %d:%d at %d\n", range->TopLevel()->vreg(),
          range->relative_id(), new_end.value());
    LiveRange* tail = SplitRangeAt(range, new_end);
    AddToUnhandled(tail);
  }
  SetLiveRangeAssignedRegister(range, reg);
  return range;
}

void LinearScanAllocator::ReloadLiveRanges(
    RangeRegisterSmallMap const& to_be_live, LifetimePosition position) {
  // Assumption: All ranges in {to_be_live} are currently spilled and there are
  // no conflicting registers in the active ranges.
  // The former is ensured by SpillNotLiveRanges, the latter is by construction
  // of the to_be_live set.
  for (auto [range, reg] : to_be_live) {
    LiveRange* to_resurrect = range->GetChildCovers(position);
    if (to_resurrect == nullptr) {
      // While the range was life until the end of the predecessor block, it is
      // not live in this block. Either there is a lifetime gap or the range
      // died.
      TRACE("No candidate for %d at %d\n", range->vreg(), position.value());
    } else {
      // We might be resurrecting a range that we spilled until its next use
      // before. In such cases, we have to unsplit it before processing as
      // otherwise we might get register changes from one range to the other
      // in the middle of blocks.
      // If there is a gap between this range and the next, we can just keep
      // it as a register change won't hurt.
      MaybeUndoPreviousSplit(to_resurrect, allocation_zone());
      if (to_resurrect->Start() == position) {
        // This range already starts at this block. It might have been spilled,
        // so we have to unspill it. Otherwise, it is already in the unhandled
        // queue waiting for processing.
        D
### 提示词
```
这是目录为v8/src/compiler/backend/register-allocator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/register-allocator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
rval));
        }
      }
    }
  }
}

bool LiveRangeBuilder::IntervalStartsAtBlockBoundary(
    UseInterval interval) const {
  LifetimePosition start = interval.start();
  if (!start.IsFullStart()) return false;
  int instruction_index = start.ToInstructionIndex();
  const InstructionBlock* block =
      data()->code()->GetInstructionBlock(instruction_index);
  return block->first_instruction_index() == instruction_index;
}

bool LiveRangeBuilder::IntervalPredecessorsCoveredByRange(
    UseInterval interval, TopLevelLiveRange* range) const {
  LifetimePosition start = interval.start();
  int instruction_index = start.ToInstructionIndex();
  const InstructionBlock* block =
      data()->code()->GetInstructionBlock(instruction_index);
  for (RpoNumber pred_index : block->predecessors()) {
    const InstructionBlock* predecessor =
        data()->code()->InstructionBlockAt(pred_index);
    LifetimePosition last_pos = LifetimePosition::GapFromInstructionIndex(
        predecessor->last_instruction_index());
    last_pos = last_pos.NextStart().End();
    if (!range->Covers(last_pos)) return false;
  }
  return true;
}

bool LiveRangeBuilder::NextIntervalStartsInDifferentBlocks(
    UseInterval interval, UseInterval next) const {
  LifetimePosition end = interval.end();
  LifetimePosition next_start = next.start();
  // Since end is not covered, but the previous position is, move back a
  // position
  end = end.IsStart() ? end.PrevStart().End() : end.Start();
  int last_covered_index = end.ToInstructionIndex();
  const InstructionBlock* block =
      data()->code()->GetInstructionBlock(last_covered_index);
  const InstructionBlock* next_block =
      data()->code()->GetInstructionBlock(next_start.ToInstructionIndex());
  return block->rpo_number() < next_block->rpo_number();
}
#endif

void BundleBuilder::BuildBundles() {
  TRACE("Build bundles\n");
  // Process the blocks in reverse order.
  for (int block_id = code()->InstructionBlockCount() - 1; block_id >= 0;
       --block_id) {
    InstructionBlock* block =
        code()->InstructionBlockAt(RpoNumber::FromInt(block_id));
    TRACE("Block B%d\n", block_id);
    for (auto phi : block->phis()) {
      TopLevelLiveRange* out_range =
          data()->GetLiveRangeFor(phi->virtual_register());
      LiveRangeBundle* out = out_range->get_bundle();
      if (out == nullptr) {
        out = data()->allocation_zone()->New<LiveRangeBundle>(
            data()->allocation_zone(), next_bundle_id_++);
        out->TryAddRange(out_range);
      }
      TRACE("Processing phi for v%d with %d:%d\n", phi->virtual_register(),
            out_range->TopLevel()->vreg(), out_range->relative_id());
      bool phi_interferes_with_backedge_input = false;
      for (auto input : phi->operands()) {
        TopLevelLiveRange* input_range = data()->GetLiveRangeFor(input);
        TRACE("Input value v%d with range %d:%d\n", input,
              input_range->TopLevel()->vreg(), input_range->relative_id());
        LiveRangeBundle* input_bundle = input_range->get_bundle();
        if (input_bundle != nullptr) {
          TRACE("Merge\n");
          LiveRangeBundle* merged =
              LiveRangeBundle::TryMerge(out, input_bundle);
          if (merged != nullptr) {
            DCHECK_EQ(out_range->get_bundle(), merged);
            DCHECK_EQ(input_range->get_bundle(), merged);
            out = merged;
            TRACE("Merged %d and %d to %d\n", phi->virtual_register(), input,
                  out->id());
          } else if (input_range->Start() > out_range->Start()) {
            // We are only interested in values defined after the phi, because
            // those are values that will go over a back-edge.
            phi_interferes_with_backedge_input = true;
          }
        } else {
          TRACE("Add\n");
          if (out->TryAddRange(input_range)) {
            TRACE("Added %d and %d to %d\n", phi->virtual_register(), input,
                  out->id());
          } else if (input_range->Start() > out_range->Start()) {
            // We are only interested in values defined after the phi, because
            // those are values that will go over a back-edge.
            phi_interferes_with_backedge_input = true;
          }
        }
      }
      // Spilling the phi at the loop header is not beneficial if there is
      // a back-edge with an input for the phi that interferes with the phi's
      // value, because in case that input gets spilled it might introduce
      // a stack-to-stack move at the back-edge.
      if (phi_interferes_with_backedge_input)
        out_range->TopLevel()->set_spilling_at_loop_header_not_beneficial();
    }
    TRACE("Done block B%d\n", block_id);
  }
}

bool LiveRangeBundle::TryAddRange(TopLevelLiveRange* range) {
  DCHECK_NULL(range->get_bundle());
  // We may only add a new live range if its use intervals do not
  // overlap with existing intervals in the bundle.
  if (AreUseIntervalsIntersecting(this->intervals_, range->intervals()))
    return false;
  AddRange(range);
  return true;
}

void LiveRangeBundle::AddRange(TopLevelLiveRange* range) {
  TopLevelLiveRange** insert_it = std::lower_bound(
      ranges_.begin(), ranges_.end(), range, LiveRangeOrdering());
  DCHECK_IMPLIES(insert_it != ranges_.end(), *insert_it != range);
  // TODO(dlehmann): We might save some memory by using
  // `DoubleEndedSplitVector::insert<kFront>()` here: Since we add ranges
  // mostly backwards, ranges with an earlier `Start()` are inserted mostly
  // at the front.
  ranges_.insert(insert_it, 1, range);
  range->set_bundle(this);

  // We also tried `std::merge`ing the sorted vectors of `intervals_` directly,
  // but it turns out the (always happening) copies are more expensive
  // than the (apparently seldom) copies due to insertion in the middle.
  for (UseInterval interval : range->intervals()) {
    UseInterval* insert_it =
        std::lower_bound(intervals_.begin(), intervals_.end(), interval);
    DCHECK_IMPLIES(insert_it != intervals_.end(), *insert_it != interval);
    intervals_.insert(insert_it, 1, interval);
  }
}

LiveRangeBundle* LiveRangeBundle::TryMerge(LiveRangeBundle* lhs,
                                           LiveRangeBundle* rhs) {
  if (rhs == lhs) return lhs;

  if (auto found =
          AreUseIntervalsIntersecting(lhs->intervals_, rhs->intervals_)) {
    auto [interval1, interval2] = *found;
    TRACE("No merge %d:%d %d:%d\n", interval1.start().value(),
          interval1.end().value(), interval2.start().value(),
          interval2.end().value());
    return nullptr;
  }
  // Uses are disjoint, merging is possible.

  // Merge the smaller bundle into the bigger.
  if (lhs->intervals_.size() < rhs->intervals_.size()) {
    std::swap(lhs, rhs);
  }
  for (TopLevelLiveRange* range : rhs->ranges_) {
    lhs->AddRange(range);
  }

  rhs->ranges_.clear();
  rhs->intervals_.clear();

  return lhs;
}

void LiveRangeBundle::MergeSpillRangesAndClear() {
  DCHECK_IMPLIES(ranges_.empty(), intervals_.empty());
  SpillRange* target = nullptr;
  for (auto range : ranges_) {
    if (range->TopLevel()->HasSpillRange()) {
      SpillRange* current = range->TopLevel()->GetSpillRange();
      if (target == nullptr) {
        target = current;
      } else if (target != current) {
        target->TryMerge(current);
      }
    }
  }
  // Clear the fields so that we don't try to merge the spill ranges again when
  // we hit the same bundle from a different LiveRange in AssignSpillSlots.
  // LiveRangeBundles are not used after this.
  ranges_.clear();
  intervals_.clear();
}

RegisterAllocator::RegisterAllocator(RegisterAllocationData* data,
                                     RegisterKind kind)
    : data_(data),
      mode_(kind),
      num_registers_(GetRegisterCount(data->config(), kind)),
      num_allocatable_registers_(
          GetAllocatableRegisterCount(data->config(), kind)),
      allocatable_register_codes_(
          GetAllocatableRegisterCodes(data->config(), kind)),
      check_fp_aliasing_(false) {
  if (kFPAliasing == AliasingKind::kCombine && kind == RegisterKind::kDouble) {
    check_fp_aliasing_ = (data->code()->representation_mask() &
                          (kFloat32Bit | kSimd128Bit)) != 0;
  }
}

LifetimePosition RegisterAllocator::GetSplitPositionForInstruction(
    const LiveRange* range, int instruction_index) {
  LifetimePosition ret = LifetimePosition::Invalid();

  ret = LifetimePosition::GapFromInstructionIndex(instruction_index);
  if (range->Start() >= ret || ret >= range->End()) {
    return LifetimePosition::Invalid();
  }
  return ret;
}

void RegisterAllocator::SplitAndSpillRangesDefinedByMemoryOperand() {
  size_t initial_range_count = data()->live_ranges().size();
  for (size_t i = 0; i < initial_range_count; ++i) {
    CHECK_EQ(initial_range_count,
             data()->live_ranges().size());  // TODO(neis): crbug.com/831822
    TopLevelLiveRange* range = data()->live_ranges()[i];
    if (!CanProcessRange(range)) continue;
    // Only assume defined by memory operand if we are guaranteed to spill it or
    // it has a spill operand.
    if (range->HasNoSpillType() ||
        (range->HasSpillRange() && !range->has_non_deferred_slot_use())) {
      continue;
    }
    LifetimePosition start = range->Start();
    TRACE("Live range %d:%d is defined by a spill operand.\n",
          range->TopLevel()->vreg(), range->relative_id());
    LifetimePosition next_pos = start;
    if (next_pos.IsGapPosition()) {
      next_pos = next_pos.NextStart();
    }

    UsePosition* pos = range->NextUsePositionRegisterIsBeneficial(next_pos);
    // If the range already has a spill operand and it doesn't need a
    // register immediately, split it and spill the first part of the range.
    if (pos == nullptr) {
      Spill(range, SpillMode::kSpillAtDefinition);
    } else if (pos->pos() > range->Start().NextStart()) {
      // Do not spill live range eagerly if use position that can benefit from
      // the register is too close to the start of live range.
      LifetimePosition split_pos = GetSplitPositionForInstruction(
          range, pos->pos().ToInstructionIndex());
      // There is no place to split, so we can't split and spill.
      if (!split_pos.IsValid()) continue;

      split_pos =
          FindOptimalSplitPos(range->Start().NextFullStart(), split_pos);

      SplitRangeAt(range, split_pos);
      Spill(range, SpillMode::kSpillAtDefinition);
    }
  }
}

LiveRange* RegisterAllocator::SplitRangeAt(LiveRange* range,
                                           LifetimePosition pos) {
  DCHECK(!range->TopLevel()->IsFixed());
  TRACE("Splitting live range %d:%d at %d\n", range->TopLevel()->vreg(),
        range->relative_id(), pos.value());

  if (pos <= range->Start()) return range;

  // We can't properly connect liveranges if splitting occurred at the end
  // a block.
  DCHECK(pos.IsStart() || pos.IsGapPosition() ||
         (GetInstructionBlock(code(), pos)->last_instruction_index() !=
          pos.ToInstructionIndex()));

  LiveRange* result = range->SplitAt(pos, allocation_zone());
  return result;
}

LiveRange* RegisterAllocator::SplitBetween(LiveRange* range,
                                           LifetimePosition start,
                                           LifetimePosition end) {
  DCHECK(!range->TopLevel()->IsFixed());
  TRACE("Splitting live range %d:%d in position between [%d, %d]\n",
        range->TopLevel()->vreg(), range->relative_id(), start.value(),
        end.value());

  LifetimePosition split_pos = FindOptimalSplitPos(start, end);
  DCHECK(split_pos >= start);
  return SplitRangeAt(range, split_pos);
}

LifetimePosition RegisterAllocator::FindOptimalSplitPos(LifetimePosition start,
                                                        LifetimePosition end) {
  int start_instr = start.ToInstructionIndex();
  int end_instr = end.ToInstructionIndex();
  DCHECK_LE(start_instr, end_instr);

  // We have no choice
  if (start_instr == end_instr) return end;

  const InstructionBlock* start_block = GetInstructionBlock(code(), start);
  const InstructionBlock* end_block = GetInstructionBlock(code(), end);

  if (end_block == start_block) {
    // The interval is split in the same basic block. Split at the latest
    // possible position.
    return end;
  }

  const InstructionBlock* block = end_block;
  // Find header of outermost loop.
  do {
    const InstructionBlock* loop = GetContainingLoop(code(), block);
    if (loop == nullptr ||
        loop->rpo_number().ToInt() <= start_block->rpo_number().ToInt()) {
      // No more loops or loop starts before the lifetime start.
      break;
    }
    block = loop;
  } while (true);

  // We did not find any suitable outer loop. Split at the latest possible
  // position unless end_block is a loop header itself.
  if (block == end_block && !end_block->IsLoopHeader()) return end;

  return LifetimePosition::GapFromInstructionIndex(
      block->first_instruction_index());
}

LifetimePosition RegisterAllocator::FindOptimalSpillingPos(
    LiveRange* range, LifetimePosition pos, SpillMode spill_mode,
    LiveRange** begin_spill_out) {
  *begin_spill_out = range;
  // TODO(herhut): Be more clever here as long as we do not move pos out of
  // deferred code.
  if (spill_mode == SpillMode::kSpillDeferred) return pos;
  const InstructionBlock* block = GetInstructionBlock(code(), pos.Start());
  const InstructionBlock* loop_header =
      block->IsLoopHeader() ? block : GetContainingLoop(code(), block);
  if (loop_header == nullptr) return pos;

  while (loop_header != nullptr) {
    // We are going to spill live range inside the loop.
    // If possible try to move spilling position backwards to loop header.
    // This will reduce number of memory moves on the back edge.
    LifetimePosition loop_start = LifetimePosition::GapFromInstructionIndex(
        loop_header->first_instruction_index());
    // Stop if we moved to a loop header before the value is defined or
    // at the define position that is not beneficial to spill.
    if (range->TopLevel()->Start() > loop_start ||
        (range->TopLevel()->Start() == loop_start &&
         range->TopLevel()->SpillAtLoopHeaderNotBeneficial()))
      return pos;

    LiveRange* live_at_header = range->TopLevel()->GetChildCovers(loop_start);

    if (live_at_header != nullptr && !live_at_header->spilled()) {
      for (const LiveRange* check_use = live_at_header;
           check_use != nullptr && check_use->Start() < pos;
           check_use = check_use->next()) {
        // If we find a use for which spilling is detrimental, don't spill
        // at the loop header
        UsePosition* next_use =
            check_use->NextUsePositionSpillDetrimental(loop_start);
        // UsePosition at the end of a UseInterval may
        // have the same value as the start of next range.
        if (next_use != nullptr && next_use->pos() <= pos) {
          return pos;
        }
      }
      // No register beneficial use inside the loop before the pos.
      *begin_spill_out = live_at_header;
      pos = loop_start;
    }

    // Try hoisting out to an outer loop.
    loop_header = GetContainingLoop(code(), loop_header);
  }
  return pos;
}

void RegisterAllocator::Spill(LiveRange* range, SpillMode spill_mode) {
  DCHECK(!range->spilled());
  DCHECK(spill_mode == SpillMode::kSpillAtDefinition ||
         GetInstructionBlock(code(), range->Start())->IsDeferred());
  TopLevelLiveRange* first = range->TopLevel();
  TRACE("Spilling live range %d:%d mode %d\n", first->vreg(),
        range->relative_id(), spill_mode);

  TRACE("Starting spill type is %d\n", static_cast<int>(first->spill_type()));
  if (first->HasNoSpillType()) {
    TRACE("New spill range needed\n");
    data()->AssignSpillRangeToLiveRange(first, spill_mode);
  }
  // Upgrade the spillmode, in case this was only spilled in deferred code so
  // far.
  if ((spill_mode == SpillMode::kSpillAtDefinition) &&
      (first->spill_type() ==
       TopLevelLiveRange::SpillType::kDeferredSpillRange)) {
    TRACE("Upgrading\n");
    first->set_spill_type(TopLevelLiveRange::SpillType::kSpillRange);
  }
  TRACE("Final spill type is %d\n", static_cast<int>(first->spill_type()));
  range->Spill();
}

const char* RegisterAllocator::RegisterName(int register_code) const {
  if (register_code == kUnassignedRegister) return "unassigned";
  switch (mode()) {
    case RegisterKind::kGeneral:
      return i::RegisterName(Register::from_code(register_code));
    case RegisterKind::kDouble:
      return i::RegisterName(DoubleRegister::from_code(register_code));
    case RegisterKind::kSimd128:
      return i::RegisterName(Simd128Register::from_code(register_code));
  }
}

LinearScanAllocator::LinearScanAllocator(RegisterAllocationData* data,
                                         RegisterKind kind, Zone* local_zone)
    : RegisterAllocator(data, kind),
      unhandled_live_ranges_(local_zone),
      active_live_ranges_(local_zone),
      inactive_live_ranges_(num_registers(), InactiveLiveRangeQueue(local_zone),
                            local_zone),
      next_active_ranges_change_(LifetimePosition::Invalid()),
      next_inactive_ranges_change_(LifetimePosition::Invalid()) {
  active_live_ranges().reserve(8);
}

void LinearScanAllocator::MaybeSpillPreviousRanges(LiveRange* begin_range,
                                                   LifetimePosition begin_pos,
                                                   LiveRange* end_range) {
  // Spill begin_range after begin_pos, then spill every live range of this
  // virtual register until but excluding end_range.
  DCHECK(begin_range->Covers(begin_pos));
  DCHECK_EQ(begin_range->TopLevel(), end_range->TopLevel());

  if (begin_range != end_range) {
    DCHECK_LE(begin_range->End(), end_range->Start());
    if (!begin_range->spilled()) {
      SpillAfter(begin_range, begin_pos, SpillMode::kSpillAtDefinition);
    }
    for (LiveRange* range = begin_range->next(); range != end_range;
         range = range->next()) {
      if (!range->spilled()) {
        range->Spill();
      }
    }
  }
}

void LinearScanAllocator::MaybeUndoPreviousSplit(LiveRange* range, Zone* zone) {
  if (range->next() != nullptr && range->next()->ShouldRecombine()) {
    LiveRange* to_remove = range->next();
    TRACE("Recombining %d:%d with %d\n", range->TopLevel()->vreg(),
          range->relative_id(), to_remove->relative_id());

    // Remove the range from unhandled, as attaching it will change its
    // state and hence ordering in the unhandled set.
    auto removed_cnt = unhandled_live_ranges().erase(to_remove);
    DCHECK_EQ(removed_cnt, 1);
    USE(removed_cnt);

    range->AttachToNext(zone);
  } else if (range->next() != nullptr) {
    TRACE("No recombine for %d:%d to %d\n", range->TopLevel()->vreg(),
          range->relative_id(), range->next()->relative_id());
  }
}

void LinearScanAllocator::SpillNotLiveRanges(RangeRegisterSmallMap& to_be_live,
                                             LifetimePosition position,
                                             SpillMode spill_mode) {
  for (auto it = active_live_ranges().begin();
       it != active_live_ranges().end();) {
    LiveRange* active_range = *it;
    TopLevelLiveRange* toplevel = (*it)->TopLevel();
    auto found = to_be_live.find(toplevel);
    if (found == to_be_live.end()) {
      // Is not contained in {to_be_live}, spill it.
      // Fixed registers are exempt from this. They might have been
      // added from inactive at the block boundary but we know that
      // they cannot conflict as they are built before register
      // allocation starts. It would be algorithmically fine to split
      // them and reschedule but the code does not allow to do this.
      if (toplevel->IsFixed()) {
        TRACE("Keeping reactivated fixed range for %s\n",
              RegisterName(toplevel->assigned_register()));
        ++it;
      } else {
        // When spilling a previously spilled/reloaded range, we add back the
        // tail that we might have split off when we reloaded/spilled it
        // previously. Otherwise we might keep generating small split-offs.
        MaybeUndoPreviousSplit(active_range, allocation_zone());
        TRACE("Putting back %d:%d\n", toplevel->vreg(),
              active_range->relative_id());
        LiveRange* split = SplitRangeAt(active_range, position);
        DCHECK_NE(split, active_range);

        // Make sure we revisit this range once it has a use that requires
        // a register.
        UsePosition* next_use = split->NextRegisterPosition(position);
        if (next_use != nullptr) {
          // Move to the start of the gap before use so that we have a space
          // to perform the potential reload. Otherwise, do not spill but add
          // to unhandled for reallocation.
          LifetimePosition revisit_at = next_use->pos().FullStart();
          TRACE("Next use at %d\n", revisit_at.value());
          if (!data()->IsBlockBoundary(revisit_at)) {
            // Leave some space so we have enough gap room.
            revisit_at = revisit_at.PrevStart().FullStart();
          }
          // If this range became life right at the block boundary that we are
          // currently processing, we do not need to split it. Instead move it
          // to unhandled right away.
          if (position < revisit_at) {
            LiveRange* third_part = SplitRangeAt(split, revisit_at);
            DCHECK_NE(split, third_part);
            Spill(split, spill_mode);
            TRACE("Marking %d:%d to recombine\n", toplevel->vreg(),
                  third_part->relative_id());
            third_part->SetRecombine();
            AddToUnhandled(third_part);
          } else {
            AddToUnhandled(split);
          }
        } else {
          Spill(split, spill_mode);
        }
        it = ActiveToHandled(it);
      }
    } else {
      // This range is contained in {to_be_live}, so we can keep it.
      int expected_register = found->second;
      to_be_live.erase(found);
      if (expected_register == active_range->assigned_register()) {
        // Was life and in correct register, simply pass through.
        TRACE("Keeping %d:%d in %s\n", toplevel->vreg(),
              active_range->relative_id(),
              RegisterName(active_range->assigned_register()));
        ++it;
      } else {
        // Was life but wrong register. Split and schedule for
        // allocation.
        TRACE("Scheduling %d:%d\n", toplevel->vreg(),
              active_range->relative_id());
        LiveRange* split = SplitRangeAt(active_range, position);
        split->set_controlflow_hint(expected_register);
        AddToUnhandled(split);
        it = ActiveToHandled(it);
      }
    }
  }
}

LiveRange* LinearScanAllocator::AssignRegisterOnReload(LiveRange* range,
                                                       int reg) {
  // We know the register is currently free but it might be in
  // use by a currently inactive range. So we might not be able
  // to reload for the full distance. In such case, split here.
  // TODO(herhut):
  // It might be better if we could use the normal unhandled queue and
  // give reloading registers pecedence. That way we would compute the
  // intersection for the entire future.
  LifetimePosition new_end = range->End();
  for (int cur_reg = 0; cur_reg < num_registers(); ++cur_reg) {
    if ((kFPAliasing != AliasingKind::kCombine || !check_fp_aliasing()) &&
        cur_reg != reg) {
      continue;
    }
    SlowDCheckInactiveLiveRangesIsSorted(cur_reg);
    for (LiveRange* cur_inactive : inactive_live_ranges(cur_reg)) {
      if (kFPAliasing == AliasingKind::kCombine && check_fp_aliasing() &&
          !data()->config()->AreAliases(cur_inactive->representation(), cur_reg,
                                        range->representation(), reg)) {
        continue;
      }
      if (new_end <= cur_inactive->NextStart()) {
        // Inactive ranges are sorted by their next start, so the remaining
        // ranges cannot contribute to new_end.
        break;
      }
      auto next_intersection = cur_inactive->FirstIntersection(range);
      if (!next_intersection.IsValid()) continue;
      new_end = std::min(new_end, next_intersection);
    }
  }
  if (new_end != range->End()) {
    TRACE("Found new end for %d:%d at %d\n", range->TopLevel()->vreg(),
          range->relative_id(), new_end.value());
    LiveRange* tail = SplitRangeAt(range, new_end);
    AddToUnhandled(tail);
  }
  SetLiveRangeAssignedRegister(range, reg);
  return range;
}

void LinearScanAllocator::ReloadLiveRanges(
    RangeRegisterSmallMap const& to_be_live, LifetimePosition position) {
  // Assumption: All ranges in {to_be_live} are currently spilled and there are
  // no conflicting registers in the active ranges.
  // The former is ensured by SpillNotLiveRanges, the latter is by construction
  // of the to_be_live set.
  for (auto [range, reg] : to_be_live) {
    LiveRange* to_resurrect = range->GetChildCovers(position);
    if (to_resurrect == nullptr) {
      // While the range was life until the end of the predecessor block, it is
      // not live in this block. Either there is a lifetime gap or the range
      // died.
      TRACE("No candidate for %d at %d\n", range->vreg(), position.value());
    } else {
      // We might be resurrecting a range that we spilled until its next use
      // before. In such cases, we have to unsplit it before processing as
      // otherwise we might get register changes from one range to the other
      // in the middle of blocks.
      // If there is a gap between this range and the next, we can just keep
      // it as a register change won't hurt.
      MaybeUndoPreviousSplit(to_resurrect, allocation_zone());
      if (to_resurrect->Start() == position) {
        // This range already starts at this block. It might have been spilled,
        // so we have to unspill it. Otherwise, it is already in the unhandled
        // queue waiting for processing.
        DCHECK(!to_resurrect->HasRegisterAssigned());
        TRACE("Reload %d:%d starting at %d itself\n", range->vreg(),
              to_resurrect->relative_id(), position.value());
        if (to_resurrect->spilled()) {
          to_resurrect->Unspill();
          to_resurrect->set_controlflow_hint(reg);
          AddToUnhandled(to_resurrect);
        } else {
          // Assign the preassigned register if we know. Otherwise, nothing to
          // do as already in unhandeled.
          if (reg != kUnassignedRegister) {
            auto erased_cnt = unhandled_live_ranges().erase(to_resurrect);
            DCHECK_EQ(erased_cnt, 1);
            USE(erased_cnt);
            // We know that there is no conflict with active ranges, so just
            // assign the register to the range.
            to_resurrect = AssignRegisterOnReload(to_resurrect, reg);
            AddToActive(to_resurrect);
          }
        }
      } else {
        // This range was spilled before. We have to split it and schedule the
        // second part for allocation (or assign the register if we know).
        DCHECK(to_resurrect->spilled());
        LiveRange* split = SplitRangeAt(to_resurrect, position);
        TRACE("Reload %d:%d starting at %d as %d\n", range->vreg(),
              to_resurrect->relative_id(), split->Start().value(),
              split->relative_id());
        DCHECK_NE(split, to_resurrect);
        if (reg != kUnassignedRegister) {
          // We know that there is no conflict with active ranges, so just
          // assign the register to the range.
          split = AssignRegisterOnReload(split, reg);
          AddToActive(split);
        } else {
          // Let normal register assignment find a suitable register.
          split->set_controlflow_hint(reg);
          AddToUnhandled(split);
        }
      }
    }
  }
}

RpoNumber LinearScanAllocator::ChooseOneOfTwoPredecessorStates(
    InstructionBlock* current_block, LifetimePosition boundary) {
  // Pick the state that would generate the least spill/reloads.
  // Compute vectors of ranges with use counts for both sides.
  // We count uses only for live ranges that are unique to either the left or
  // the right predecessor since many live ranges are shared between both.
  // Shared ranges don't influence the decision anyway and this is faster.
  auto& left = data()->GetSpillState(current_block->predecessors()[0]);
  auto& right = data()->GetSpillState(current_block->predecessors()[1]);

  // Build a set of the `TopLevelLiveRange`s in the left predecessor.
  // Usually this set is very small, e.g., for JetStream2 at most 3 ranges in
  // ~72% of the cases and at most 8 ranges in ~93% of the cases. In those cases
  // `SmallMap` is backed by inline storage and uses fast linear search.
  // In some pathological cases the set grows large (e.g. the Wasm binary of
  // v8:9529) and then `SmallMap` gives us O(log n) worst case lookup when
  // intersecting with the right predecessor below. The set is encoded as a
  // `SmallMap` to `Dummy` values, since we don't have an equivalent `SmallSet`.
  struct Dummy {};
  SmallZoneMap<TopLevelLiveRange*, Dummy, 16> left_set(allocation_zone());
  for (LiveRange* range : left) {
    TopLevelLiveRange* parent = range->TopLevel();
    auto [_, inserted] = left_set.emplace(parent, Dummy{});
    // The `LiveRange`s in `left` come from the spill state, which is just the
    // list of active `LiveRange`s at the end of the block (see
    // `RememberSpillState`). Since at most one `LiveRange` out of a
    // `TopLevelLiveRange` can be active at the same time, there should never be
    // the same `TopLevelLiveRange` twice in `left_set`, hence this check.
    DCHECK(inserted);
    USE(inserted);
  }

  // Now build a list of ranges unique to either the left or right predecessor.
  struct RangeUseCount {
    // The set above contains `TopLevelLiveRange`s, but ultimately we want to
    // count uses of the child `LiveRange` covering `boundary`.
    // The lookup in `GetChildCovers` is O(log n), so do it only once when
    // inserting into this list.
    LiveRange* range;
    // +1 if used in the left predecessor, -1 if used in the right predecessor.
    int use_count_delta;
  };
  SmallZoneVector<RangeUseCount, 16> unique_range_use_counts(allocation_zone());
  for (LiveRange* range : right) {
    TopLevelLiveRange* parent = range->TopLevel();
    auto left_it = left_set.find(parent);
    bool range_is_shared_left_and_right = left_it != left_set.end();
    if (range_is_shared_left_and_right) {
      left_set.erase(left_it);
    } else {
      // This range is unique to the right predecessor, so insert into the list.
      LiveRange* child = parent->GetChildCovers(boundary);
      if (child != nullptr) {
        unique_range_use_counts.push_back({child, -1});
      }
    }
  }
  // So far `unique_range_use_counts` contains only the ranges unique in the
  // right predecessor. Now also add the ranges from the left predecessor.
  for (auto [parent, _] : left_set) {
    LiveRange* child = parent->GetChildCovers(boundary);
    if (child != nullptr) {
      unique_range_use_counts.push_back({child, +1});
    }
  }

  // Finally, count the uses for each range.
  int use_count_difference = 0;
  for (auto [range, use_count] : unique_range_use_counts) {
    if (range->NextUsePositionRegisterIsBeneficial(boundary) != nullptr) {
      use_count_difference += use_count;
    }
  }
  if (use_count_difference == 0) {
    // There is a tie in beneficial register uses. Now, look at any use at all.
    // We do not account for all uses, like flowing into a phi.
    // So we just look at ranges still being live.
    TRACE("Looking at only uses\n");
    for (auto [range, use_count] : unique_range_use_counts) {
      if (range->NextUsePosition(boundary) != range->positions().end()) {
        use_count_difference += use_count;
      }
    }
  }
  TRACE("Left predecessor has %d more uses than right\n", use_count_difference);
  return use_count_difference > 0 ? current_block->predecessors()[0]
                                  : current_block->predecessors()[1];
}

bool LinearScanAllocator::CheckConflict(
    MachineRepresentation rep, int reg,
    const RangeRegisterSmallMap& to_be_live) {
  for (auto [range, expected_reg] : to_be_live) {
    if (data()->config()->AreAliases(range->representation(), expected_reg, rep,
                                     reg)) {
      return true;
    }
  }
  return false;
}

void LinearScanAllocator::ComputeStateFromManyPredecessors(
    InstructionBlock* current_block, RangeRegisterSmallMap& to_be_live) {
  struct Vote {
    size_t count;
    int used_register
```