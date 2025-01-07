Response: The user wants me to summarize the functionality of the provided C++ code snippet. This is the second part of a larger file. I need to focus on the logic within this specific chunk. The code appears to be related to register allocation in a compiler, specifically focusing on building live ranges and handling phi nodes. I also need to provide a JavaScript example if any connection exists between this C++ code and JavaScript functionality.

Looking at the code, I see functions like `ResolvePhis`, `LiveRangeBuilder`, and `ProcessInstructions`. These strongly suggest that this part of the code is responsible for determining when and where variables are "live" (in use) within the compiled code. This information is crucial for allocating registers efficiently. Phi nodes are special instructions used in static single assignment (SSA) form to merge values from different control flow paths, and their handling is a key aspect of register allocation.

Regarding the JavaScript connection, while this specific C++ code doesn't directly interact with JavaScript syntax, the *purpose* of this code – efficient register allocation – is crucial for the performance of JavaScript engines like V8. V8 compiles JavaScript into machine code, and register allocation is a vital step in that process.

Let's break down the functionality of the methods in this part:

*   **`ConstraintBuilder::ResolvePhis`**: This method seems to be responsible for inserting "gap moves" around phi instructions. Gap moves are likely used to move data between registers at control flow merge points.
*   **`LiveRangeBuilder`**: This class is central to the process. It computes live ranges for variables.
    *   **`ComputeLiveOut`**:  Determines which variables are live *after* a block of code has executed.
    *   **`AddInitialIntervals`**: Adds initial time intervals during which variables are considered live.
    *   **`FixedLiveRangeFor` and `FixedFPLiveRangeFor`**:  Handles the allocation of fixed registers (registers that have a predetermined purpose).
    *   **`LiveRangeFor`**:  Retrieves the live range information for a given operand.
    *   **`Define` and `Use`**:  Record when and where variables are defined and used, respectively.
    *   **`ProcessInstructions`**:  Iterates through the instructions in a block and updates the live range information based on the operands.
    *   **`ProcessPhis`**: Specifically handles phi instructions, potentially adding hints for register allocation.
    *   **`ProcessLoopHeader`**:  Handles the special case of loop headers, extending live ranges across the loop.
    *   **`BuildLiveRanges`**:  The main method to build live ranges for the entire function.
*   Helper functions like `NewUsePosition` are used to create data structures for tracking variable usage.
This part of the `register-allocator.cc` file in V8 focuses on the **construction of live ranges** for variables and the **handling of phi nodes** within the intermediate representation of the code being compiled.

Here's a breakdown of its functionality:

1. **Constraint Building (Specifically for Phi Nodes):**
    *   The `ConstraintBuilder::ResolvePhis` and `ConstraintBuilder::ResolvePhis(const InstructionBlock* block)` methods are responsible for setting up constraints related to phi nodes.
    *   Phi nodes represent the merging of values from different control flow paths. These methods insert "gap moves" before the phi node in each predecessor block. These moves ensure that the correct value is available when the phi node executes.
    *   They also associate spill locations with phi node outputs, indicating where the value might reside in memory if not in a register.

2. **Live Range Building:**
    *   The `LiveRangeBuilder` class is the core component for determining the "lifespan" of each variable (represented by a virtual register). A live range defines the intervals during which a variable's value might be needed.
    *   **`ComputeLiveOut`**: This method calculates the set of variables that are "live out" of a given instruction block. This means their value might be needed in a successor block. It considers both regular control flow and the inputs to phi nodes in successor blocks.
    *   **`AddInitialIntervals`**:  It initializes the live ranges by assuming variables live-out of a block are live throughout the entire block. These intervals will be refined later.
    *   **`FixedLiveRangeFor` and `FixedFPLiveRangeFor`**: These methods create or retrieve live ranges for fixed registers (registers with a predefined purpose, like function arguments or return values). They handle different register types (general-purpose, floating-point, SIMD).
    *   **`LiveRangeFor`**: This method retrieves the `TopLevelLiveRange` associated with a given `InstructionOperand`.
    *   **`Define` and `Use`**: These are crucial methods. `Define` marks the point where a variable gets its value, while `Use` marks where a variable's value is needed. They add corresponding intervals and use positions to the variable's live range.
    *   **`ProcessInstructions`**: This method iterates through the instructions in a block in reverse order. For each instruction, it analyzes the inputs, outputs, and temporary values, updating the live ranges by calling `Define` and `Use`. It also handles register clobbering (where an instruction modifies a register's value). It specifically manages the moves within instruction gaps (points between instructions where parallel moves can occur), making sure the sources of these moves are considered live.
    *   **`ProcessPhis`**: This method specifically handles phi instructions. It determines a "hint" operand for each phi output, preferably from a predecessor block that is earlier in the reverse post-order (RPO) traversal. This hinting helps the register allocator make better decisions.
    *   **`ProcessLoopHeader`**: For loop headers, it extends the live ranges of variables live on entry to the loop to cover the entire loop.
    *   **`BuildLiveRanges`**: This is the main driver for live range construction. It iterates through the instruction blocks in reverse RPO, calling the other `LiveRangeBuilder` methods to compute and refine the live ranges. It also handles the assignment of spill slots to live ranges that require them.

**Relationship to JavaScript (and an Example):**

While this C++ code doesn't directly contain JavaScript syntax, its function is essential for the performance of JavaScript engines like V8. When V8 compiles JavaScript code, it goes through several stages, including generating an intermediate representation and then allocating registers for variables to optimize execution speed.

The live ranges built by this code directly inform the subsequent **register allocation** phase. By knowing when each variable is live, the register allocator can assign physical registers to variables in a way that minimizes conflicts and the need to spill (store variables in memory).

**JavaScript Example (Illustrating the *concept* of live ranges):**

```javascript
function example(a, b) {
  let x = a + 1; // 'x' is defined here
  let y = b * 2; // 'y' is defined here

  if (x > 10) {
    console.log(x + y); // 'x' and 'y' are used here
    return x + y;
  } else {
    console.log(y - x); // 'y' and 'x' are used here
    return y - x;
  }
}
```

In the compiled code for this JavaScript function:

*   The live range of `x` would start at the assignment `let x = a + 1;` and extend to the points where `x` is used in `console.log(x + y)` and `console.log(y - x)`.
*   Similarly, the live range of `y` would start at `let y = b * 2;` and extend to its uses.

The `register-allocator.cc` code is responsible for automatically determining these live ranges within the compiled representation of the JavaScript code. The efficient calculation of these ranges allows the register allocator to assign registers so that `x` and `y` (or their underlying virtual registers) can reside in registers for as much of their lifespan as possible, avoiding slower memory accesses.

In essence, this C++ code is a crucial part of the machinery that makes JavaScript execution fast by optimizing how variables are handled at the machine code level.

Prompt: 
```
这是目录为v8/src/compiler/backend/register-allocator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
, &gap_move->source()};
        data()->delayed_references().push_back(delayed_reference);
      }
    }
  }
}

void ConstraintBuilder::ResolvePhis() {
  // Process the blocks in reverse order.
  for (InstructionBlock* block : base::Reversed(code()->instruction_blocks())) {
    data_->tick_counter()->TickAndMaybeEnterSafepoint();
    ResolvePhis(block);
  }
}

void ConstraintBuilder::ResolvePhis(const InstructionBlock* block) {
  for (PhiInstruction* phi : block->phis()) {
    int phi_vreg = phi->virtual_register();
    RegisterAllocationData::PhiMapValue* map_value =
        data()->InitializePhiMap(block, phi);
    InstructionOperand& output = phi->output();
    // Map the destination operands, so the commitment phase can find them.
    for (size_t i = 0; i < phi->operands().size(); ++i) {
      InstructionBlock* cur_block =
          code()->InstructionBlockAt(block->predecessors()[i]);
      UnallocatedOperand input(UnallocatedOperand::REGISTER_OR_SLOT,
                               phi->operands()[i]);
      MoveOperands* move = data()->AddGapMove(
          cur_block->last_instruction_index(), Instruction::END, input, output);
      map_value->AddOperand(&move->destination());
      DCHECK(!code()
                  ->InstructionAt(cur_block->last_instruction_index())
                  ->HasReferenceMap());
    }
    TopLevelLiveRange* live_range = data()->GetLiveRangeFor(phi_vreg);
    int gap_index = block->first_instruction_index();
    live_range->RecordSpillLocation(allocation_zone(), gap_index, &output);
    live_range->SetSpillStartIndex(gap_index);
    // We use the phi-ness of some nodes in some later heuristics.
    live_range->set_is_phi(true);
    live_range->set_is_non_loop_phi(!block->IsLoopHeader());
  }
}

LiveRangeBuilder::LiveRangeBuilder(RegisterAllocationData* data,
                                   Zone* local_zone)
    : data_(data), phi_hints_(local_zone) {}

SparseBitVector* LiveRangeBuilder::ComputeLiveOut(
    const InstructionBlock* block, RegisterAllocationData* data) {
  size_t block_index = block->rpo_number().ToSize();
  SparseBitVector* live_out = data->live_out_sets()[block_index];
  if (live_out == nullptr) {
    // Compute live out for the given block, except not including backward
    // successor edges.
    Zone* zone = data->allocation_zone();
    const InstructionSequence* code = data->code();

    live_out = zone->New<SparseBitVector>(zone);

    // Process all successor blocks.
    for (const RpoNumber& succ : block->successors()) {
      // Add values live on entry to the successor.
      if (succ <= block->rpo_number()) continue;
      SparseBitVector* live_in = data->live_in_sets()[succ.ToSize()];
      if (live_in != nullptr) live_out->Union(*live_in);

      // All phi input operands corresponding to this successor edge are live
      // out from this block.
      const InstructionBlock* successor = code->InstructionBlockAt(succ);
      size_t index = successor->PredecessorIndexOf(block->rpo_number());
      DCHECK(index < successor->PredecessorCount());
      for (PhiInstruction* phi : successor->phis()) {
        live_out->Add(phi->operands()[index]);
      }
    }
    data->live_out_sets()[block_index] = live_out;
  }
  return live_out;
}

void LiveRangeBuilder::AddInitialIntervals(const InstructionBlock* block,
                                           SparseBitVector* live_out) {
  // Add an interval that includes the entire block to the live range for
  // each live_out value.
  LifetimePosition start = LifetimePosition::GapFromInstructionIndex(
      block->first_instruction_index());
  LifetimePosition end = LifetimePosition::InstructionFromInstructionIndex(
                             block->last_instruction_index())
                             .NextStart();
  for (int operand_index : *live_out) {
    TopLevelLiveRange* range = data()->GetLiveRangeFor(operand_index);
    range->AddUseInterval(start, end, allocation_zone());
  }
}

int LiveRangeBuilder::FixedFPLiveRangeID(int index, MachineRepresentation rep) {
  int result = -index - 1;
  switch (rep) {
    case MachineRepresentation::kSimd256:
      result -=
          kNumberOfFixedRangesPerRegister * config()->num_simd128_registers();
      [[fallthrough]];
    case MachineRepresentation::kSimd128:
      result -=
          kNumberOfFixedRangesPerRegister * config()->num_float_registers();
      [[fallthrough]];
    case MachineRepresentation::kFloat32:
      result -=
          kNumberOfFixedRangesPerRegister * config()->num_double_registers();
      [[fallthrough]];
    case MachineRepresentation::kFloat64:
      result -=
          kNumberOfFixedRangesPerRegister * config()->num_general_registers();
      break;
    default:
      UNREACHABLE();
  }
  return result;
}

TopLevelLiveRange* LiveRangeBuilder::FixedLiveRangeFor(int index,
                                                       SpillMode spill_mode) {
  int offset = spill_mode == SpillMode::kSpillAtDefinition
                   ? 0
                   : config()->num_general_registers();
  DCHECK(index < config()->num_general_registers());
  TopLevelLiveRange* result = data()->fixed_live_ranges()[offset + index];
  if (result == nullptr) {
    MachineRepresentation rep = InstructionSequence::DefaultRepresentation();
    result = data()->NewLiveRange(FixedLiveRangeID(offset + index), rep);
    DCHECK(result->IsFixed());
    result->set_assigned_register(index);
    data()->MarkAllocated(rep, index);
    if (spill_mode == SpillMode::kSpillDeferred) {
      result->set_deferred_fixed();
    }
    data()->fixed_live_ranges()[offset + index] = result;
  }
  return result;
}

TopLevelLiveRange* LiveRangeBuilder::FixedFPLiveRangeFor(
    int index, MachineRepresentation rep, SpillMode spill_mode) {
  int num_regs = config()->num_double_registers();
  ZoneVector<TopLevelLiveRange*>* live_ranges =
      &data()->fixed_double_live_ranges();
  if (kFPAliasing == AliasingKind::kCombine) {
    switch (rep) {
      case MachineRepresentation::kFloat16:
      case MachineRepresentation::kFloat32:
        num_regs = config()->num_float_registers();
        live_ranges = &data()->fixed_float_live_ranges();
        break;
      case MachineRepresentation::kSimd128:
        num_regs = config()->num_simd128_registers();
        live_ranges = &data()->fixed_simd128_live_ranges();
        break;
      default:
        break;
    }
  }

  int offset = spill_mode == SpillMode::kSpillAtDefinition ? 0 : num_regs;

  DCHECK(index < num_regs);
  USE(num_regs);
  TopLevelLiveRange* result = (*live_ranges)[offset + index];
  if (result == nullptr) {
    result = data()->NewLiveRange(FixedFPLiveRangeID(offset + index, rep), rep);
    DCHECK(result->IsFixed());
    result->set_assigned_register(index);
    data()->MarkAllocated(rep, index);
    if (spill_mode == SpillMode::kSpillDeferred) {
      result->set_deferred_fixed();
    }
    (*live_ranges)[offset + index] = result;
  }
  return result;
}

TopLevelLiveRange* LiveRangeBuilder::FixedSIMD128LiveRangeFor(
    int index, SpillMode spill_mode) {
  DCHECK_EQ(kFPAliasing, AliasingKind::kIndependent);
  int num_regs = config()->num_simd128_registers();
  ZoneVector<TopLevelLiveRange*>* live_ranges =
      &data()->fixed_simd128_live_ranges();
  int offset = spill_mode == SpillMode::kSpillAtDefinition ? 0 : num_regs;

  DCHECK(index < num_regs);
  USE(num_regs);
  TopLevelLiveRange* result = (*live_ranges)[offset + index];
  if (result == nullptr) {
    result = data()->NewLiveRange(
        FixedFPLiveRangeID(offset + index, MachineRepresentation::kSimd128),
        MachineRepresentation::kSimd128);
    DCHECK(result->IsFixed());
    result->set_assigned_register(index);
    data()->MarkAllocated(MachineRepresentation::kSimd128, index);
    if (spill_mode == SpillMode::kSpillDeferred) {
      result->set_deferred_fixed();
    }
    (*live_ranges)[offset + index] = result;
  }
  return result;
}

TopLevelLiveRange* LiveRangeBuilder::LiveRangeFor(InstructionOperand* operand,
                                                  SpillMode spill_mode) {
  if (operand->IsUnallocated()) {
    return data()->GetLiveRangeFor(
        UnallocatedOperand::cast(operand)->virtual_register());
  } else if (operand->IsConstant()) {
    return data()->GetLiveRangeFor(
        ConstantOperand::cast(operand)->virtual_register());
  } else if (operand->IsRegister()) {
    return FixedLiveRangeFor(
        LocationOperand::cast(operand)->GetRegister().code(), spill_mode);
  } else if (operand->IsFPRegister()) {
    LocationOperand* op = LocationOperand::cast(operand);
    if (kFPAliasing == AliasingKind::kIndependent &&
        op->representation() == MachineRepresentation::kSimd128) {
      return FixedSIMD128LiveRangeFor(op->register_code(), spill_mode);
    }
    return FixedFPLiveRangeFor(op->register_code(), op->representation(),
                               spill_mode);
  } else {
    return nullptr;
  }
}

UsePosition* LiveRangeBuilder::NewUsePosition(LifetimePosition pos,
                                              InstructionOperand* operand,
                                              void* hint,
                                              UsePositionHintType hint_type) {
  return allocation_zone()->New<UsePosition>(pos, operand, hint, hint_type);
}

UsePosition* LiveRangeBuilder::Define(LifetimePosition position,
                                      InstructionOperand* operand, void* hint,
                                      UsePositionHintType hint_type,
                                      SpillMode spill_mode) {
  TopLevelLiveRange* range = LiveRangeFor(operand, spill_mode);
  if (range == nullptr) return nullptr;

  if (range->IsEmpty() || range->Start() > position) {
    // Can happen if there is a definition without use.
    range->AddUseInterval(position, position.NextStart(), allocation_zone());
    range->AddUsePosition(NewUsePosition(position.NextStart()),
                          allocation_zone());
  } else {
    range->ShortenTo(position);
  }
  if (!operand->IsUnallocated()) return nullptr;
  UnallocatedOperand* unalloc_operand = UnallocatedOperand::cast(operand);
  UsePosition* use_pos =
      NewUsePosition(position, unalloc_operand, hint, hint_type);
  range->AddUsePosition(use_pos, allocation_zone());
  return use_pos;
}

UsePosition* LiveRangeBuilder::Use(LifetimePosition block_start,
                                   LifetimePosition position,
                                   InstructionOperand* operand, void* hint,
                                   UsePositionHintType hint_type,
                                   SpillMode spill_mode) {
  TopLevelLiveRange* range = LiveRangeFor(operand, spill_mode);
  if (range == nullptr) return nullptr;
  UsePosition* use_pos = nullptr;
  if (operand->IsUnallocated()) {
    UnallocatedOperand* unalloc_operand = UnallocatedOperand::cast(operand);
    use_pos = NewUsePosition(position, unalloc_operand, hint, hint_type);
    range->AddUsePosition(use_pos, allocation_zone());
  }
  range->AddUseInterval(block_start, position, allocation_zone());
  return use_pos;
}

void LiveRangeBuilder::ProcessInstructions(const InstructionBlock* block,
                                           SparseBitVector* live) {
  int block_start = block->first_instruction_index();
  LifetimePosition block_start_position =
      LifetimePosition::GapFromInstructionIndex(block_start);
  bool fixed_float_live_ranges = false;
  bool fixed_simd128_live_ranges = false;
  if (kFPAliasing == AliasingKind::kCombine) {
    int mask = data()->code()->representation_mask();
    fixed_float_live_ranges = (mask & kFloat32Bit) != 0;
    fixed_simd128_live_ranges = (mask & kSimd128Bit) != 0;
  } else if (kFPAliasing == AliasingKind::kIndependent) {
    int mask = data()->code()->representation_mask();
    fixed_simd128_live_ranges = (mask & kSimd128Bit) != 0;
  }
  SpillMode spill_mode = SpillModeForBlock(block);

  for (int index = block->last_instruction_index(); index >= block_start;
       index--) {
    LifetimePosition curr_position =
        LifetimePosition::InstructionFromInstructionIndex(index);
    Instruction* instr = code()->InstructionAt(index);
    DCHECK_NOT_NULL(instr);
    DCHECK(curr_position.IsInstructionPosition());
    // Process output, inputs, and temps of this instruction.
    for (size_t i = 0; i < instr->OutputCount(); i++) {
      InstructionOperand* output = instr->OutputAt(i);
      if (output->IsUnallocated()) {
        // Unsupported.
        DCHECK(!UnallocatedOperand::cast(output)->HasSlotPolicy());
        int out_vreg = UnallocatedOperand::cast(output)->virtual_register();
        live->Remove(out_vreg);
      } else if (output->IsConstant()) {
        int out_vreg = ConstantOperand::cast(output)->virtual_register();
        live->Remove(out_vreg);
      }
      if (block->IsHandler() && index == block_start && output->IsAllocated() &&
          output->IsRegister() &&
          AllocatedOperand::cast(output)->GetRegister() ==
              v8::internal::kReturnRegister0) {
        // The register defined here is blocked from gap start - it is the
        // exception value.
        // TODO(mtrofin): should we explore an explicit opcode for
        // the first instruction in the handler?
        Define(LifetimePosition::GapFromInstructionIndex(index), output,
               spill_mode);
      } else {
        Define(curr_position, output, spill_mode);
      }
    }

    if (instr->ClobbersRegisters()) {
      for (int i = 0; i < config()->num_allocatable_general_registers(); ++i) {
        // Create a UseInterval at this instruction for all fixed registers,
        // (including the instruction outputs). Adding another UseInterval here
        // is OK because AddUseInterval will just merge it with the existing
        // one at the end of the range.
        int code = config()->GetAllocatableGeneralCode(i);
        TopLevelLiveRange* range = FixedLiveRangeFor(code, spill_mode);
        range->AddUseInterval(curr_position, curr_position.End(),
                              allocation_zone());
      }
    }

    if (instr->ClobbersDoubleRegisters()) {
      for (int i = 0; i < config()->num_allocatable_double_registers(); ++i) {
        // Add a UseInterval for all DoubleRegisters. See comment above for
        // general registers.
        int code = config()->GetAllocatableDoubleCode(i);
        TopLevelLiveRange* range = FixedFPLiveRangeFor(
            code, MachineRepresentation::kFloat64, spill_mode);
        range->AddUseInterval(curr_position, curr_position.End(),
                              allocation_zone());
      }
      // Clobber fixed float registers on archs with non-simple aliasing.
      if (kFPAliasing == AliasingKind::kCombine) {
        if (fixed_float_live_ranges) {
          for (int i = 0; i < config()->num_allocatable_float_registers();
               ++i) {
            // Add a UseInterval for all FloatRegisters. See comment above for
            // general registers.
            int code = config()->GetAllocatableFloatCode(i);
            TopLevelLiveRange* range = FixedFPLiveRangeFor(
                code, MachineRepresentation::kFloat32, spill_mode);
            range->AddUseInterval(curr_position, curr_position.End(),
                                  allocation_zone());
          }
        }
        if (fixed_simd128_live_ranges) {
          for (int i = 0; i < config()->num_allocatable_simd128_registers();
               ++i) {
            int code = config()->GetAllocatableSimd128Code(i);
            TopLevelLiveRange* range = FixedFPLiveRangeFor(
                code, MachineRepresentation::kSimd128, spill_mode);
            range->AddUseInterval(curr_position, curr_position.End(),
                                  allocation_zone());
          }
        }
      } else if (kFPAliasing == AliasingKind::kIndependent) {
        if (fixed_simd128_live_ranges) {
          for (int i = 0; i < config()->num_allocatable_simd128_registers();
               ++i) {
            int code = config()->GetAllocatableSimd128Code(i);
            TopLevelLiveRange* range =
                FixedSIMD128LiveRangeFor(code, spill_mode);
            range->AddUseInterval(curr_position, curr_position.End(),
                                  allocation_zone());
          }
        }
      }
    }

    for (size_t i = 0; i < instr->InputCount(); i++) {
      InstructionOperand* input = instr->InputAt(i);
      if (input->IsImmediate()) {
        continue;  // Ignore immediates.
      }
      LifetimePosition use_pos;
      if (input->IsUnallocated() &&
          UnallocatedOperand::cast(input)->IsUsedAtStart()) {
        use_pos = curr_position;
      } else {
        use_pos = curr_position.End();
      }

      if (input->IsUnallocated()) {
        UnallocatedOperand* unalloc = UnallocatedOperand::cast(input);
        int vreg = unalloc->virtual_register();
        live->Add(vreg);
        if (unalloc->HasSlotPolicy()) {
          data()->GetLiveRangeFor(vreg)->register_slot_use(
              block->IsDeferred()
                  ? TopLevelLiveRange::SlotUseKind::kDeferredSlotUse
                  : TopLevelLiveRange::SlotUseKind::kGeneralSlotUse);
        }
      }
      Use(block_start_position, use_pos, input, spill_mode);
    }

    for (size_t i = 0; i < instr->TempCount(); i++) {
      InstructionOperand* temp = instr->TempAt(i);
      // Unsupported.
      DCHECK_IMPLIES(temp->IsUnallocated(),
                     !UnallocatedOperand::cast(temp)->HasSlotPolicy());
      if (instr->ClobbersTemps()) {
        if (temp->IsRegister()) continue;
        if (temp->IsUnallocated()) {
          UnallocatedOperand* temp_unalloc = UnallocatedOperand::cast(temp);
          if (temp_unalloc->HasFixedPolicy()) {
            continue;
          }
        }
      }
      Use(block_start_position, curr_position.End(), temp, spill_mode);
      Define(curr_position, temp, spill_mode);
    }

    // Process the moves of the instruction's gaps, making their sources live.
    const Instruction::GapPosition kPositions[] = {Instruction::END,
                                                   Instruction::START};
    curr_position = curr_position.PrevStart();
    DCHECK(curr_position.IsGapPosition());
    for (const Instruction::GapPosition& position : kPositions) {
      ParallelMove* move = instr->GetParallelMove(position);
      if (move == nullptr) continue;
      if (position == Instruction::END) {
        curr_position = curr_position.End();
      } else {
        curr_position = curr_position.Start();
      }
      for (MoveOperands* cur : *move) {
        InstructionOperand& from = cur->source();
        InstructionOperand& to = cur->destination();
        void* hint = &to;
        UsePositionHintType hint_type = UsePosition::HintTypeForOperand(to);
        UsePosition* to_use = nullptr;
        int phi_vreg = -1;
        if (to.IsUnallocated()) {
          int to_vreg = UnallocatedOperand::cast(to).virtual_register();
          TopLevelLiveRange* to_range = data()->GetLiveRangeFor(to_vreg);
          if (to_range->is_phi()) {
            phi_vreg = to_vreg;
            if (to_range->is_non_loop_phi()) {
              hint = to_range->current_hint_position();
              hint_type = hint == nullptr ? UsePositionHintType::kNone
                                          : UsePositionHintType::kUsePos;
            } else {
              hint_type = UsePositionHintType::kPhi;
              hint = data()->GetPhiMapValueFor(to_vreg);
            }
          } else {
            if (live->Contains(to_vreg)) {
              to_use =
                  Define(curr_position, &to, &from,
                         UsePosition::HintTypeForOperand(from), spill_mode);
              live->Remove(to_vreg);
            } else {
              cur->Eliminate();
              continue;
            }
          }
        } else {
          Define(curr_position, &to, spill_mode);
        }
        UsePosition* from_use = Use(block_start_position, curr_position, &from,
                                    hint, hint_type, spill_mode);
        // Mark range live.
        if (from.IsUnallocated()) {
          live->Add(UnallocatedOperand::cast(from).virtual_register());
        }
        // When the value is moved to a register to meet input constraints,
        // we should consider this value use similar as a register use in the
        // backward spilling heuristics, even though this value use is not
        // register benefical at the AllocateBlockedReg stage.
        if (to.IsAnyRegister() ||
            (to.IsUnallocated() &&
             UnallocatedOperand::cast(&to)->HasRegisterPolicy())) {
          from_use->set_spill_detrimental();
        }
        // Resolve use position hints just created.
        if (to_use != nullptr && from_use != nullptr) {
          to_use->ResolveHint(from_use);
          from_use->ResolveHint(to_use);
        }
        DCHECK_IMPLIES(to_use != nullptr, to_use->IsResolved());
        DCHECK_IMPLIES(from_use != nullptr, from_use->IsResolved());
        // Potentially resolve phi hint.
        if (phi_vreg != -1) ResolvePhiHint(&from, from_use);
      }
    }
  }
}

void LiveRangeBuilder::ProcessPhis(const InstructionBlock* block,
                                   SparseBitVector* live) {
  for (PhiInstruction* phi : block->phis()) {
    // The live range interval already ends at the first instruction of the
    // block.
    int phi_vreg = phi->virtual_register();
    live->Remove(phi_vreg);
    // Select a hint from a predecessor block that precedes this block in the
    // rpo order. In order of priority:
    // - Avoid hints from deferred blocks.
    // - Prefer hints from allocated (or explicit) operands.
    // - Prefer hints from empty blocks (containing just parallel moves and a
    //   jump). In these cases, if we can elide the moves, the jump threader
    //   is likely to be able to elide the jump.
    // The enforcement of hinting in rpo order is required because hint
    // resolution that happens later in the compiler pipeline visits
    // instructions in reverse rpo order, relying on the fact that phis are
    // encountered before their hints.
    InstructionOperand* hint = nullptr;
    int hint_preference = 0;

    // The cost of hinting increases with the number of predecessors. At the
    // same time, the typical benefit decreases, since this hinting only
    // optimises the execution path through one predecessor. A limit of 2 is
    // sufficient to hit the common if/else pattern.
    int predecessor_limit = 2;

    for (RpoNumber predecessor : block->predecessors()) {
      const InstructionBlock* predecessor_block =
          code()->InstructionBlockAt(predecessor);
      DCHECK_EQ(predecessor_block->rpo_number(), predecessor);

      // Only take hints from earlier rpo numbers.
      if (predecessor >= block->rpo_number()) continue;

      // Look up the predecessor instruction.
      const Instruction* predecessor_instr =
          GetLastInstruction(code(), predecessor_block);
      InstructionOperand* predecessor_hint = nullptr;
      // Phis are assigned in the END position of the last instruction in each
      // predecessor block.
      for (MoveOperands* move :
           *predecessor_instr->GetParallelMove(Instruction::END)) {
        InstructionOperand& to = move->destination();
        if (to.IsUnallocated() &&
            UnallocatedOperand::cast(to).virtual_register() == phi_vreg) {
          predecessor_hint = &move->source();
          break;
        }
      }
      DCHECK_NOT_NULL(predecessor_hint);

      // For each predecessor, generate a score according to the priorities
      // described above, and pick the best one. Flags in higher-order bits have
      // a higher priority than those in lower-order bits.
      int predecessor_hint_preference = 0;
      const int kNotDeferredBlockPreference = (1 << 2);
      const int kMoveIsAllocatedPreference = (1 << 1);
      const int kBlockIsEmptyPreference = (1 << 0);

      // - Avoid hints from deferred blocks.
      if (!predecessor_block->IsDeferred()) {
        predecessor_hint_preference |= kNotDeferredBlockPreference;
      }

      // - Prefer hints from allocated operands.
      //
      // Already-allocated operands are typically assigned using the parallel
      // moves on the last instruction. For example:
      //
      //      gap (v101 = [x0|R|w32]) (v100 = v101)
      //      ArchJmp
      //    ...
      //    phi: v100 = v101 v102
      //
      // We have already found the END move, so look for a matching START move
      // from an allocated operand.
      //
      // Note that we cannot simply look up data()->live_ranges()[vreg] here
      // because the live ranges are still being built when this function is
      // called.
      // TODO(v8): Find a way to separate hinting from live range analysis in
      // BuildLiveRanges so that we can use the O(1) live-range look-up.
      auto moves = predecessor_instr->GetParallelMove(Instruction::START);
      if (moves != nullptr) {
        for (MoveOperands* move : *moves) {
          InstructionOperand& to = move->destination();
          if (predecessor_hint->Equals(to)) {
            if (move->source().IsAllocated()) {
              predecessor_hint_preference |= kMoveIsAllocatedPreference;
            }
            break;
          }
        }
      }

      // - Prefer hints from empty blocks.
      if (predecessor_block->last_instruction_index() ==
          predecessor_block->first_instruction_index()) {
        predecessor_hint_preference |= kBlockIsEmptyPreference;
      }

      if ((hint == nullptr) ||
          (predecessor_hint_preference > hint_preference)) {
        // Take the hint from this predecessor.
        hint = predecessor_hint;
        hint_preference = predecessor_hint_preference;
      }

      if (--predecessor_limit <= 0) break;
    }
    DCHECK_NOT_NULL(hint);

    LifetimePosition block_start = LifetimePosition::GapFromInstructionIndex(
        block->first_instruction_index());
    UsePosition* use_pos = Define(block_start, &phi->output(), hint,
                                  UsePosition::HintTypeForOperand(*hint),
                                  SpillModeForBlock(block));
    MapPhiHint(hint, use_pos);
  }
}

void LiveRangeBuilder::ProcessLoopHeader(const InstructionBlock* block,
                                         SparseBitVector* live) {
  DCHECK(block->IsLoopHeader());
  // Add a live range stretching from the first loop instruction to the last
  // for each value live on entry to the header.
  LifetimePosition start = LifetimePosition::GapFromInstructionIndex(
      block->first_instruction_index());
  LifetimePosition end = LifetimePosition::GapFromInstructionIndex(
                             code()->LastLoopInstructionIndex(block))
                             .NextFullStart();
  for (int operand_index : *live) {
    TopLevelLiveRange* range = data()->GetLiveRangeFor(operand_index);
    range->EnsureInterval(start, end, allocation_zone());
  }
  // Insert all values into the live in sets of all blocks in the loop.
  for (int i = block->rpo_number().ToInt() + 1; i < block->loop_end().ToInt();
       ++i) {
    live_in_sets()[i]->Union(*live);
  }
}

void LiveRangeBuilder::BuildLiveRanges() {
  // Process the blocks in reverse order.
  for (int block_id = code()->InstructionBlockCount() - 1; block_id >= 0;
       --block_id) {
    data_->tick_counter()->TickAndMaybeEnterSafepoint();
    InstructionBlock* block =
        code()->InstructionBlockAt(RpoNumber::FromInt(block_id));
    SparseBitVector* live = ComputeLiveOut(block, data());
    // Initially consider all live_out values live for the entire block. We
    // will shorten these intervals if necessary.
    AddInitialIntervals(block, live);
    // Process the instructions in reverse order, generating and killing
    // live values.
    ProcessInstructions(block, live);
    // All phi output operands are killed by this block.
    ProcessPhis(block, live);
    // Now live is live_in for this block except not including values live
    // out on backward successor edges.
    if (block->IsLoopHeader()) ProcessLoopHeader(block, live);
    live_in_sets()[block_id] = live;
  }
  // Postprocess the ranges.
  const size_t live_ranges_size = data()->live_ranges().size();
  for (TopLevelLiveRange* range : data()->live_ranges()) {
    data_->tick_counter()->TickAndMaybeEnterSafepoint();
    CHECK_EQ(live_ranges_size,
             data()->live_ranges().size());  // TODO(neis): crbug.com/831822
    DCHECK_NOT_NULL(range);
    // Give slots to all ranges with a non fixed slot use.
    if (range->has_slot_use() && range->HasNoSpillType()) {
      SpillMode spill_mode =
          range->slot_use_kind() ==
                  TopLevelLiveRange::SlotUseKind::kDeferredSlotUse
              ? SpillMode::kSpillDeferred
              : SpillMode::kSpillAtDefinition;
      data()->AssignSpillRangeToLiveRange(range, spill_mode);
    }
    // TODO(bmeurer): This is a horrible hack to make sure that for constant
    // live ranges, every use requires the constant to be in a register.
    // Without this hack, all uses with "any" policy would get the constant
    // operand assigned.
    if (range->HasSpillOperand() && range->GetSpillOperand()->IsConstant()) {
      for (UsePosition* pos : range->positions()) {
        if (pos->type() == UsePositionType::kRequiresSlot ||
            pos->type() == UsePositionType::kRegisterOrSlotOrConstant) {
          continue;
        }
        UsePositionType new_type = UsePositionType::kRegisterOrSlot;
        // Can't mark phis as needing a register.
        if (!pos->pos().IsGapPosition()) {
          new_type = UsePositionType::kRequiresRegister;
        }
        pos->set_type(new_type, true);
      }
    }
    range->ResetCurrentHintPosition();
  }
  for (auto preassigned : data()->preassigned_slot_ranges()) {
    TopLevelLiveRange* range = preassigned.first;
    int slot_id = preassigned.second;
    SpillRange* spill = range->HasSpillRange()
                            ? range->GetSpillRange()
                            : data()->AssignSpillRangeToLiveRange(
                                  range, SpillMode::kSpillAtDefinition);
    spill->set_assigned_slot(slot_id);
  }
#ifdef DEBUG
  Verify();
#endif
}

void LiveRangeBuilder::MapPhiHint(InstructionOperand* operand,
                                  UsePosition* use_pos) {
  DCHECK(!use_pos->IsResolved());
  auto res = phi_hints_.insert(std::make_pair(operand, use_pos));
  DCHECK(res.second);
  USE(res);
}

void LiveRangeBuilder::ResolvePhiHint(InstructionOperand* operand,
                                      UsePosition* use_pos) {
  auto it = phi_hints_.find(operand);
  if (it == phi_hints_.end()) return;
  DCHECK(!it->second->IsResolved());
  it->second->ResolveHint(use_pos);
}

#ifdef DEBUG
void LiveRangeBuilder::Verify() const {
  for (auto& hint : phi_hints_) {
    DCHECK(hint.second->IsResolved());
  }
  for (TopLevelLiveRange* current : data()->live_ranges()) {
    DCHECK_NOT_NULL(current);
    if (!current->IsEmpty()) {
      // New LiveRanges should not be split.
      DCHECK_NULL(current->next());
      // General integrity check.
      current->Verify();
      if (current->intervals().size() < 2) continue;

      // Consecutive intervals should not end and start in the same block,
      // otherwise the intervals should have been joined, because the
      // variable is live throughout that block.
      UseIntervalVector::const_iterator interval = current->intervals().begin();
      UseIntervalVector::const_iterator next_interval = interval + 1;
      DCHECK(NextIntervalStartsInDifferentBlocks(*interval, *next_interval));

      for (++interval; interval != current->intervals().end(); ++interval) {
        // Except for the first interval, the other intevals must start at
        // a block boundary, otherwise data wouldn't flow to them.
        // You might trigger this CHECK if your SSA is not valid. For instance,
        // if the inputs of a Phi node are in the wrong order.
        DCHECK(IntervalStartsAtBlockBoundary(*interval));
        // The last instruction of the predecessors of the block the interval
        // starts must be covered by the range.
        DCHECK(IntervalPredecessorsCoveredByRange(*interval, current));
        next_interval = interval + 1;
        if (next_interval != current->intervals().end()) {
          // Check the consecutive intervals property, except for the last
          // interval, where it doesn't apply.
          DCHECK(
              NextIntervalStartsInDifferentBlocks(*interval, *next_interval));
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
"""


```