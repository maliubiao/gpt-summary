Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's WebAssembly interpreter.

Here's a breakdown of how to arrive at the answer:

1. **Identify the Core Functionality:** The code is part of a `WasmBytecodeGenerator` class. The methods within it deal with managing a stack, slots (memory locations), and processing WebAssembly instructions. Keywords like `LocalGet`, `CopyToSlot`, `PreserveArgsAndLocals`, `ReserveBlockSlots`, `StoreBlockParamsIntoSlots`, `EndBlock`, `Return`, and `DecodeInstruction` are strong indicators.

2. **Group Related Methods:**  Notice patterns in the methods. Some handle local variables (`LocalGet`, `CopyToSlot`), others manage the structure of blocks (`PreserveArgsAndLocals`, `ReserveBlockSlots`, `StoreBlockParamsIntoSlots`, `EndBlock`), and yet others deal with instruction decoding (`DecodeInstruction`).

3. **Infer Purpose from Method Names and Code:**
    * `CopyToSlot`:  Copies data to a memory slot.
    * `PopSlot`: Removes a slot from the stack.
    * `PreserveArgsAndLocals`: Ensures local variables have their own dedicated memory when entering blocks, preventing unexpected modifications.
    * `ReserveBlockSlots`: Allocates memory slots for block parameters and return values.
    * `StoreBlockParamsIntoSlots`:  Moves parameters into the allocated slots for a block.
    * `StoreBlockParamsAndResultsIntoSlots`: Handles both parameters and results when entering or exiting a block.
    * `RestoreIfElseParams`: Restores parameters when entering the `else` branch of an `if` statement.
    * `ScanConstInstructions`:  Looks for constant instructions to determine memory needs.
    * `EndBlock`:  Finalizes the processing for the end of a block.
    * `Return`: Handles the return from a function.
    * `DecodeInstruction`: Parses the raw WebAssembly bytecode to understand the instruction.

4. **Address Specific Instructions:** The user asked about `.tq` files (Torque). The provided code is `.cc`, so it's standard C++, not Torque.

5. **JavaScript Relevance:**  Since this is part of the V8 engine, the operations directly support the execution of WebAssembly, which is often compiled from languages like C/C++ but interacts with JavaScript environments. The connection is the execution of WebAssembly within a JavaScript engine.

6. **Code Logic Inference (with Assumptions):** The `CopyToSlot` and `LocalGet` logic hints at a "copy-on-write" strategy. If a local variable is accessed multiple times, they might initially share the same memory location. Modification triggers a copy.

7. **Common Programming Errors:** The `PreserveArgsAndLocals` function addresses a potential issue where changes in one part of the code (within a block) could unexpectedly affect values in another part due to shared memory.

8. **Part of a Larger System:**  The "Part 10 of 15" indicates this code is a module within a larger compilation or explanation.

9. **Synthesize the Summary:** Combine the individual functionalities into a coherent overview.

**Self-Correction/Refinement during Thought Process:**

* Initially, I might focus too much on the low-level stack and slot manipulation. It's important to step back and see the higher-level purpose: managing the execution context of WebAssembly code.
* I need to be careful not to overstate the JavaScript connection. It's about *executing* WebAssembly *within* a JavaScript environment, not direct interaction of these specific C++ functions with JavaScript code.
* The explanation of "copy-on-write" for `LocalGet` needs to be clear and concise.
* The example of a common programming error should be relatable to a general programming concept (like unexpected side effects).

By following these steps, I can arrive at a comprehensive and accurate summary of the code's functionality.
```cpp
bool WasmBytecodeGenerator::CopyToSlot(ValueType value_type,
                                         uint32_t from_stack_index,
                                         uint32_t to_stack_index,
                                         bool copy_from_reg) {
  DCHECK(!stack_.empty());
  DCHECK_LT(to_stack_index, stack_.size() - (copy_from_reg ? 0 : 1));

  // LocalGet uses a "copy-on-write" mechanism: the arg/local value is not
  // copied and instead the stack entry references the same slot. When the
  // arg/local value is modified, we need to preserve the old value of the stack
  // entry in a new slot.
  CopyToSlot(value_type, stack_.back(), to_stack_index, copy_from_reg);

  if (!is_tee && !copy_from_reg) {
    PopSlot();

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_execution) {
      EMIT_INSTR_HANDLER(trace_PopSlot);
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  }
}

// This function is called when we enter a new 'block', 'loop' or 'if' block
// statement. Checks whether any of the 'non-locals' stack entries share a slot
// with an arg/local stack entry. In that case stop make sure the local stack
// entry will get its own slot. This is necessary because at runtime we could
// jump at the block after having modified the local value in some other code
// path.
// TODO(paolosev@microsoft.com) - Understand why this is not required only for
// 'loop' blocks.
void WasmBytecodeGenerator::PreserveArgsAndLocals() {
  uint32_t num_args_and_locals = args_count_ + locals_count_;

  // If there are only args/locals entries in the stack, nothing to do.
  if (num_args_and_locals >= stack_size()) return;

  for (uint32_t local_index = 0; local_index < num_args_and_locals;
       ++local_index) {
    uint32_t new_slot_index;
    if (FindSharedSlot(local_index, &new_slot_index)) {
      ValueType value_type = slots_[stack_[local_index]].value_type;
      EmitCopySlot(value_type, stack_[local_index], new_slot_index);
    }
  }
}

uint32_t WasmBytecodeGenerator::ReserveBlockSlots(
    uint8_t opcode, const WasmInstruction::Optional::Block& block_data,
    size_t* rets_slots_count, size_t* params_slots_count) {
  uint32_t first_slot_index = 0;
  *rets_slots_count = 0;
  *params_slots_count = 0;
  bool first_slot_found = false;
  const ValueType value_type = block_data.value_type();
  if (value_type == kWasmBottom) {
    const FunctionSig* sig = module_->signature(block_data.sig_index);
    *rets_slots_count = sig->return_count();
    for (uint32_t i = 0; i < *rets_slots_count; i++) {
      uint32_t slot_index = CreateSlot(sig->GetReturn(i));
      if (!first_slot_found) {
        first_slot_index = slot_index;
        first_slot_found = true;
      }
    }
    *params_slots_count = sig->parameter_count();
    for (uint32_t i = 0; i < *params_slots_count; i++) {
      uint32_t slot_index = CreateSlot(sig->GetParam(i));
      if (!first_slot_found) {
        first_slot_index = slot_index;
        first_slot_found = true;
      }
    }
  } else if (value_type != kWasmVoid) {
    *rets_slots_count = 1;
    first_slot_index = CreateSlot(value_type);
  }
  return first_slot_index;
}

void WasmBytecodeGenerator::StoreBlockParamsIntoSlots(
    uint32_t target_block_index, bool update_stack) {
  const WasmBytecodeGenerator::BlockData& target_block_data =
      blocks_[target_block_index];
  DCHECK_EQ(target_block_data.opcode_, kExprLoop);

  uint32_t params_count = ParamsCount(target_block_data);
  uint32_t rets_count = ReturnsCount(target_block_data);
  uint32_t first_param_slot_index =
      target_block_data.first_block_index_ + rets_count;
  for (uint32_t i = 0; i < params_count; i++) {
    uint32_t from_slot_index =
        stack_[stack_top_index() - (params_count - 1) + i];
    uint32_t to_slot_index = first_param_slot_index + i;
    if (from_slot_index != to_slot_index) {
      EmitCopySlot(GetParamType(target_block_data, i), from_slot_index,
                   to_slot_index);
      if (update_stack) {
        DCHECK_EQ(GetParamType(target_block_data, i),
                  slots_[first_param_slot_index + i].value_type);
        UpdateStack(stack_top_index() - (params_count - 1) + i,
                    first_param_slot_index + i);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
        if (v8_flags.trace_drumbrake_execution) {
          EMIT_INSTR_HANDLER(trace_UpdateStack);
          EmitI32Const(stack_top_index() - (params_count - 1) + i);
          EmitI32Const(slots_[first_param_slot_index + i].slot_offset *
                       kSlotSize);
        }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
      }
    }
  }
}

void WasmBytecodeGenerator::StoreBlockParamsAndResultsIntoSlots(
    uint32_t target_block_index, WasmOpcode opcode) {
  bool is_branch = kExprBr == opcode || kExprBrIf == opcode ||
                   kExprBrTable == opcode || kExprBrOnNull == opcode ||
                   kExprBrOnNonNull == opcode || kExprBrOnCast == opcode;
  const WasmBytecodeGenerator::BlockData& target_block_data =
      blocks_[target_block_index];
  bool is_target_loop_block = target_block_data.opcode_ == kExprLoop;
  if (is_target_loop_block && is_branch) {
    StoreBlockParamsIntoSlots(target_block_index, false);
  }

  // Ignore params if this is the function main block.
  uint32_t params_count =
      target_block_index == 0 ? 0 : ParamsCount(target_block_data);
  uint32_t rets_count = ReturnsCount(target_block_data);

  // There could be valid code where there are not enough elements in the
  // stack if some code in unreachable (for example if a 'i32.const 0' is
  // followed by a 'br_if' the if branch is never reachable).
  uint32_t count = std::min(static_cast<uint32_t>(stack_.size()), rets_count);
  for (uint32_t i = 0; i < count; i++) {
    uint32_t from_slot_index = stack_[stack_top_index() - (count - 1) + i];
    uint32_t to_slot_index = target_block_data.first_block_index_ + i;
    if (from_slot_index != to_slot_index) {
      EmitCopySlot(GetReturnType(target_block_data, i), from_slot_index,
                   to_slot_index);
    }
  }

  bool is_else = (kExprElse == opcode);
  bool is_return = (kExprReturn == opcode);
  bool is_catch = (kExprCatch == opcode || kExprCatchAll == opcode);
  if (!is_branch && !is_return && !is_else && !is_catch) {
    uint32_t new_stack_height =
        target_block_data.stack_size_ - params_count + rets_count;
    DCHECK(new_stack_height <= stack_.size() ||
           !was_current_instruction_reachable_);
    stack_.resize(new_stack_height);

    for (uint32_t i = 0; i < rets_count; i++) {
      DCHECK_EQ(GetReturnType(target_block_data, i),
                slots_[target_block_data.first_block_index_ + i].value_type);
      UpdateStack(target_block_data.stack_size_ - params_count + i,
                  target_block_data.first_block_index_ + i);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EMIT_INSTR_HANDLER(trace_UpdateStack);
        EmitI32Const(target_block_data.stack_size_ - params_count + i);
        EmitI32Const(
            slots_[target_block_data.first_block_index_ + i].slot_offset *
            kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
    }
  }
}

void WasmBytecodeGenerator::RestoreIfElseParams(uint32_t if_block_index) {
  const WasmBytecodeGenerator::BlockData& if_block_data =
      blocks_[if_block_index];
  DCHECK_EQ(if_block_data.opcode_, kExprIf);

  stack_.resize(blocks_[if_block_index].stack_size_);
  uint32_t params_count = if_block_index == 0 ? 0 : ParamsCount(if_block_data);
  for (uint32_t i = 0; i < params_count; i++) {
    UpdateStack(if_block_data.stack_size_ - params_count + i,
                if_block_data.GetParam(i), GetParamType(if_block_data, i));
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_execution) {
      EMIT_INSTR_HANDLER(trace_UpdateStack);
      EmitI32Const(if_block_data.stack_size_ - params_count + i);
      EmitI32Const(slots_[if_block_data.GetParam(i)].slot_offset * kSlotSize);
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  }
}

uint32_t WasmBytecodeGenerator::ScanConstInstructions() const {
  Decoder decoder(wasm_code_->start, wasm_code_->end);
  uint32_t const_slots_size = 0;
  pc_t pc = wasm_code_->locals.encoded_size;
  pc_t limit = wasm_code_->end - wasm_code_->start;
  while (pc < limit) {
    uint32_t opcode = wasm_code_->start[pc];
    if (opcode == kExprI32Const || opcode == kExprF32Const) {
      const_slots_size += sizeof(uint32_t) / kSlotSize;
    } else if (opcode == kExprI64Const || opcode == kExprF64Const) {
      const_slots_size += sizeof(uint64_t) / kSlotSize;
    } else if (opcode == kSimdPrefix) {
      auto [opcode_index, opcode_len] =
          decoder.read_u32v<Decoder::FullValidationTag>(
              wasm_code_->start + pc + 1, "prefixed opcode index");
      opcode = (kSimdPrefix << 8) | opcode_index;
      if (opcode == kExprS128Const || opcode == kExprI8x16Shuffle) {
        const_slots_size += sizeof(Simd128) / kSlotSize;
      }
    }
    pc++;
  }
  return const_slots_size;
}

int32_t WasmBytecodeGenerator::EndBlock(WasmOpcode opcode) {
  WasmBytecodeGenerator::BlockData& block_data = blocks_[current_block_index_];
  bool is_try_catch =
      block_data.IsTry() || block_data.IsCatch() || block_data.IsCatchAll();

  StoreBlockParamsAndResultsIntoSlots(current_block_index_, opcode);

  if (block_data.IsLoop()) {
    loop_end_code_offsets_.push_back(static_cast<uint32_t>(code_.size()));
    EMIT_INSTR_HANDLER(s2s_OnLoopBackwardJump);
  }

  block_data.end_code_offset_ = CurrentCodePos();
  if (opcode == kExprEnd && block_data.IsElse()) {
    DCHECK_GT(block_data.if_else_block_index_, 0);
    blocks_[block_data.if_else_block_index_].end_code_offset_ =
        CurrentCodePos();
  }

  if (!is_try_catch) {
    current_block_index_ = blocks_[current_block_index_].parent_block_index_;
  }

  if (is_try_catch && (opcode == kExprEnd || opcode == kExprDelegate)) {
    int32_t try_block_index =
        eh_data_.EndTryCatchBlocks(current_block_index_, CurrentCodePos());
    DCHECK_GE(try_block_index, 0);
    current_block_index_ = blocks_[try_block_index].parent_block_index_;
  }

  last_instr_offset_ = kInvalidCodeOffset;

  return current_block_index_;
}

void WasmBytecodeGenerator::Return() {
  if (current_block_index_ >= 0) {
    StoreBlockParamsAndResultsIntoSlots(0, kExprReturn);
  }

  EMIT_INSTR_HANDLER(s2s_Return);

  const WasmBytecodeGenerator::BlockData& target_block_data = blocks_[0];
  uint32_t final_stack_size =
      target_block_data.stack_size_ + ReturnsCount(target_block_data);
  EmitI32Const(final_stack_size);
}

WasmInstruction WasmBytecodeGenerator::DecodeInstruction(pc_t pc,
                                                         Decoder& decoder) {
  pc_t limit = wasm_code_->end - wasm_code_->start;
  if (pc >= limit) return WasmInstruction();

  int len = 1;
  uint8_t orig = wasm_code_->start[pc];
  WasmOpcode opcode = static_cast<WasmOpcode>(orig);
  if (WasmOpcodes::IsPrefixOpcode(opcode)) {
    uint32_t prefixed_opcode_length;
    std::tie(opcode, prefixed_opcode_length) =
        decoder.read_prefixed_opcode<Decoder::NoValidationTag>(
            wasm_code_->at(pc));
    // skip breakpoint by switching on original code.
    len = prefixed_opcode_length;
  }

  WasmInstruction::Optional optional;
  switch (orig) {
    case kExprUnreachable:
      break;
    case kExprNop:
      break;
    case kExprBlock:
    case kExprLoop:
    case kExprIf:
    case kExprTry: {
      BlockTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
                             wasm_code_->at(pc + 1), Decoder::kNoValidation);
      if (imm.sig_index.valid()) {
        // The block has at least one argument or at least two results, its
        // signature is identified by sig_index.
        optional.block.sig_index = imm.sig_index;
        optional.block.value_type_bitfield = kWasmBottom.raw_bit_field();
      } else if (imm.sig.return_count() + imm.sig.parameter_count() == 0) {
        // Void signature: no arguments and no results.
        optional.block.sig_index = ModuleTypeIndex::Invalid();
        optional.block.value_type_bitfield = kWasmVoid.raw_bit_field();
      } else {
        // No arguments and one result.
        optional.block.sig_index = ModuleTypeIndex::Invalid();
        std::optional<wasm::ValueType> wasm_return_type =
            GetWasmReturnTypeFromSignature(&imm.sig);
        DCHECK(wasm_return_type.has_value());
        optional.block.value_type_bitfield =
            wasm_return_type.value().raw_bit_field();
      }
      len = 1 + imm.length;
      break;
    }
    case kExprElse:
      break;
    case kExprCatch: {
      TagIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                            Decoder::kNoValidation);
      optional.index = imm.index;
      len = 1 + imm.length;
      break;
    }
    case kExprCatchAll:
      break;
    case kExprEnd:
      break;
    case kExprThrow: {
      TagIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                            Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprRethrow:
    case kExprBr:
    case kExprBrIf:
    case kExprBrOnNull:
    case kExprBrOnNonNull:
    case kExprDelegate: {
      BranchDepthImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.depth = imm.depth;
      break;
    }
    case kExprBrTable: {
      BranchTableImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      BranchTableIterator<Decoder::NoValidationTag> iterator(&decoder, imm);
      optional.br_table.table_count = imm.table_count;
      optional.br_table.labels_index =
          static_cast<uint32_t>(br_table_labels_.size());
      for (uint32_t i = 0; i <= imm.table_count; i++) {
        DCHECK(iterator.has_next());
        br_table_labels_.emplace_back(iterator.next());
      }
      len = static_cast<int>(1 + iterator.pc() - imm.start);
      break;
    }
    case kExprReturn:
      break;
    case kExprCallFunction:
    case kExprReturnCall: {
      CallFunctionImmediate imm(&decoder, wasm_code_->at(pc + 1),
                                Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprCallIndirect:
    case kExprReturnCallIndirect: {
      CallIndirectImmediate imm(&decoder, wasm_code_->at(pc + 1),
                                Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.indirect_call.table_index = imm.table_imm.index;
      optional.indirect_call.sig_index = imm.sig_imm.index;
      break;
    }
    case kExprDrop:
      break;
    case kExprSelect:
      break;
    case kExprSelectWithType: {
      SelectTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
                              wasm_code_->at(pc + 1), Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprLocalGet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprLocalSet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprLocalTee: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprGlobalGet: {
      GlobalIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprGlobalSet: {
      GlobalIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprTableGet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "table index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprTableSet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "table index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }

#define LOAD_CASE(name, ctype, mtype, rep, type)                        \
  case kExpr##name: {                                                   \
    MemoryAccessImmediate imm(                                          \
        &decoder, wasm_code_->at(pc + 1), sizeof(ctype),                \
        !module_->memories.empty() && module_->memories[0].is_memory64, \
        Decoder::kNoValidation);                                        \
    len = 1 + imm.length;                                               \
    optional.offset = imm.offset;                                       \
    break;                                                              \
  }
      LOAD_CASE(I32LoadMem8S, int32_t, int8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem8U, int32_t, uint8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem16S, int32_t, int16_t, kWord16, I32);
      LOAD_CASE(I32LoadMem16U, int32_t, uint16_t, kWord16, I32);
      LOAD_CASE(I64LoadMem8S, int64_t, int8_t, kWord8, I64);
      LOAD_CASE(I64LoadMem8U, int64_t, uint8_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16S, int64_t, int16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16U, int64_t, uint16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem32S, int64_t, int32_t, kWord32, I64);
      LOAD_CASE(I64LoadMem32U, int64_t, uint32_t, kWord32, I64);
      LOAD_CASE(I32LoadMem, int32_t, int32_t, kWord32, I32);
      LOAD_CASE(I64LoadMem, int64_t, int64_t, kWord64, I64);
      LOAD_CASE(F32LoadMem, Float32, uint32_t, kFloat32, F32);
      LOAD_CASE(F64LoadMem, Float64, uint64_t, kFloat64, F64);
#undef LOAD_CASE

#define STORE_CASE(name, ctype, mtype, rep, type)                       \
  case kExpr##name: {                                                   \
    MemoryAccessImmediate imm(                                          \
        &decoder, wasm_code_->at(pc + 1), sizeof(ctype),                \
        !module_->memories.empty() && module_->memories[0].is_memory64, \
        Decoder::kNoValidation);                                        \
    len = 1 + imm.length;                                               \
    optional.offset = imm.offset;                                       \
    break;                                                              \
  }
      STORE_CASE(I32StoreMem8, int32_t, int8_t, kWord8, I32);
      STORE_CASE(I32StoreMem16, int32_t, int16_t, kWord16, I32);
      STORE_CASE(I64StoreMem8, int64_t, int8_t, kWord8, I64);
      STORE_CASE(I64StoreMem16, int64_t, int16_t, kWord16, I64);
      STORE_CASE(I64StoreMem32, int64_t, int32_t, kWord32, I64);
      STORE_CASE(I32StoreMem, int32_t, int32_t, kWord32, I32);
      STORE_CASE(I64StoreMem, int64_t, int64_t, kWord64, I64);
      STORE_CASE(F32StoreMem, Float32, uint32_t, kFloat32, F32);
      STORE_CASE(F64StoreMem, Float64, uint64_t, kFloat64, F64);
#undef STORE_CASE

    case kExprMemorySize: {
      MemoryIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprMemoryGrow: {
      MemoryIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprI32Const: {
      ImmI32Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.i32 = imm.value;
      break;
    }
    case kExprI64Const: {
      ImmI64Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.i64 = imm.value;
      break;
    }
    case kExprF32Const: {
      ImmF32Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.f32 = imm.value;
      break;
    }
    case kExprF64Const: {
      ImmF64Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.f64 = imm.value;
      break;
    }

#define EXECUTE_BINOP(name, ctype, reg, op, type) \
  case kExpr##name:                               \
    break;

      FOREACH_COMPARISON_BINOP(EXECUTE_BINOP)
      FOREACH_ARITHMETIC_BINOP(EXECUTE_BINOP)
      FOREACH_TRAPPING_BINOP(EXECUTE_BINOP)
      FOREACH_MORE_BINOP(EXECUTE_BINOP)
#undef EXECUTE_BINOP

#define EXECUTE_UNOP(name, ctype, reg, op, type) \
  case kExpr##name:                              \
    break;

      FOREACH_SIMPLE_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                     to_reg)                                                   \
  case kExpr##name:                                                            \
    break;

      FOREACH_ADDITIONAL_CONVERT_UNOP(EXECUTE_UNOP)
      FOREACH_CONVERT_UNOP(EXECUTE_UNOP)
      FOREACH_REINTERPRET_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, to_ctype, to_type, op) \
  case kExpr##name:                                                      \
    break;

      FOREACH_BITS_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, to_ctype, to_type) \
  case kExpr##name:                                                  \
    break;

      FOREACH_EXTENSION_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

    case kExprRefNull: {
      HeapTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
bool is_tee, bool copy_from_reg) {
  DCHECK(!stack_.empty());
  DCHECK_LT(to_stack_index, stack_.size() - (copy_from_reg ? 0 : 1));

  // LocalGet uses a "copy-on-write" mechanism: the arg/local value is not
  // copied and instead the stack entry references the same slot. When the
  // arg/local value is modified, we need to preserve the old value of the stack
  // entry in a new slot.
  CopyToSlot(value_type, stack_.back(), to_stack_index, copy_from_reg);

  if (!is_tee && !copy_from_reg) {
    PopSlot();

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_execution) {
      EMIT_INSTR_HANDLER(trace_PopSlot);
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  }
}

// This function is called when we enter a new 'block', 'loop' or 'if' block
// statement. Checks whether any of the 'non-locals' stack entries share a slot
// with an arg/local stack entry. In that case stop make sure the local stack
// entry will get its own slot. This is necessary because at runtime we could
// jump at the block after having modified the local value in some other code
// path.
// TODO(paolosev@microsoft.com) - Understand why this is not required only for
// 'loop' blocks.
void WasmBytecodeGenerator::PreserveArgsAndLocals() {
  uint32_t num_args_and_locals = args_count_ + locals_count_;

  // If there are only args/locals entries in the stack, nothing to do.
  if (num_args_and_locals >= stack_size()) return;

  for (uint32_t local_index = 0; local_index < num_args_and_locals;
       ++local_index) {
    uint32_t new_slot_index;
    if (FindSharedSlot(local_index, &new_slot_index)) {
      ValueType value_type = slots_[stack_[local_index]].value_type;
      EmitCopySlot(value_type, stack_[local_index], new_slot_index);
    }
  }
}

uint32_t WasmBytecodeGenerator::ReserveBlockSlots(
    uint8_t opcode, const WasmInstruction::Optional::Block& block_data,
    size_t* rets_slots_count, size_t* params_slots_count) {
  uint32_t first_slot_index = 0;
  *rets_slots_count = 0;
  *params_slots_count = 0;
  bool first_slot_found = false;
  const ValueType value_type = block_data.value_type();
  if (value_type == kWasmBottom) {
    const FunctionSig* sig = module_->signature(block_data.sig_index);
    *rets_slots_count = sig->return_count();
    for (uint32_t i = 0; i < *rets_slots_count; i++) {
      uint32_t slot_index = CreateSlot(sig->GetReturn(i));
      if (!first_slot_found) {
        first_slot_index = slot_index;
        first_slot_found = true;
      }
    }
    *params_slots_count = sig->parameter_count();
    for (uint32_t i = 0; i < *params_slots_count; i++) {
      uint32_t slot_index = CreateSlot(sig->GetParam(i));
      if (!first_slot_found) {
        first_slot_index = slot_index;
        first_slot_found = true;
      }
    }
  } else if (value_type != kWasmVoid) {
    *rets_slots_count = 1;
    first_slot_index = CreateSlot(value_type);
  }
  return first_slot_index;
}

void WasmBytecodeGenerator::StoreBlockParamsIntoSlots(
    uint32_t target_block_index, bool update_stack) {
  const WasmBytecodeGenerator::BlockData& target_block_data =
      blocks_[target_block_index];
  DCHECK_EQ(target_block_data.opcode_, kExprLoop);

  uint32_t params_count = ParamsCount(target_block_data);
  uint32_t rets_count = ReturnsCount(target_block_data);
  uint32_t first_param_slot_index =
      target_block_data.first_block_index_ + rets_count;
  for (uint32_t i = 0; i < params_count; i++) {
    uint32_t from_slot_index =
        stack_[stack_top_index() - (params_count - 1) + i];
    uint32_t to_slot_index = first_param_slot_index + i;
    if (from_slot_index != to_slot_index) {
      EmitCopySlot(GetParamType(target_block_data, i), from_slot_index,
                   to_slot_index);
      if (update_stack) {
        DCHECK_EQ(GetParamType(target_block_data, i),
                  slots_[first_param_slot_index + i].value_type);
        UpdateStack(stack_top_index() - (params_count - 1) + i,
                    first_param_slot_index + i);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
        if (v8_flags.trace_drumbrake_execution) {
          EMIT_INSTR_HANDLER(trace_UpdateStack);
          EmitI32Const(stack_top_index() - (params_count - 1) + i);
          EmitI32Const(slots_[first_param_slot_index + i].slot_offset *
                       kSlotSize);
        }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
      }
    }
  }
}

void WasmBytecodeGenerator::StoreBlockParamsAndResultsIntoSlots(
    uint32_t target_block_index, WasmOpcode opcode) {
  bool is_branch = kExprBr == opcode || kExprBrIf == opcode ||
                   kExprBrTable == opcode || kExprBrOnNull == opcode ||
                   kExprBrOnNonNull == opcode || kExprBrOnCast == opcode;
  const WasmBytecodeGenerator::BlockData& target_block_data =
      blocks_[target_block_index];
  bool is_target_loop_block = target_block_data.opcode_ == kExprLoop;
  if (is_target_loop_block && is_branch) {
    StoreBlockParamsIntoSlots(target_block_index, false);
  }

  // Ignore params if this is the function main block.
  uint32_t params_count =
      target_block_index == 0 ? 0 : ParamsCount(target_block_data);
  uint32_t rets_count = ReturnsCount(target_block_data);

  // There could be valid code where there are not enough elements in the
  // stack if some code in unreachable (for example if a 'i32.const 0' is
  // followed by a 'br_if' the if branch is never reachable).
  uint32_t count = std::min(static_cast<uint32_t>(stack_.size()), rets_count);
  for (uint32_t i = 0; i < count; i++) {
    uint32_t from_slot_index = stack_[stack_top_index() - (count - 1) + i];
    uint32_t to_slot_index = target_block_data.first_block_index_ + i;
    if (from_slot_index != to_slot_index) {
      EmitCopySlot(GetReturnType(target_block_data, i), from_slot_index,
                   to_slot_index);
    }
  }

  bool is_else = (kExprElse == opcode);
  bool is_return = (kExprReturn == opcode);
  bool is_catch = (kExprCatch == opcode || kExprCatchAll == opcode);
  if (!is_branch && !is_return && !is_else && !is_catch) {
    uint32_t new_stack_height =
        target_block_data.stack_size_ - params_count + rets_count;
    DCHECK(new_stack_height <= stack_.size() ||
           !was_current_instruction_reachable_);
    stack_.resize(new_stack_height);

    for (uint32_t i = 0; i < rets_count; i++) {
      DCHECK_EQ(GetReturnType(target_block_data, i),
                slots_[target_block_data.first_block_index_ + i].value_type);
      UpdateStack(target_block_data.stack_size_ - params_count + i,
                  target_block_data.first_block_index_ + i);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution) {
        EMIT_INSTR_HANDLER(trace_UpdateStack);
        EmitI32Const(target_block_data.stack_size_ - params_count + i);
        EmitI32Const(
            slots_[target_block_data.first_block_index_ + i].slot_offset *
            kSlotSize);
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
    }
  }
}

void WasmBytecodeGenerator::RestoreIfElseParams(uint32_t if_block_index) {
  const WasmBytecodeGenerator::BlockData& if_block_data =
      blocks_[if_block_index];
  DCHECK_EQ(if_block_data.opcode_, kExprIf);

  stack_.resize(blocks_[if_block_index].stack_size_);
  uint32_t params_count = if_block_index == 0 ? 0 : ParamsCount(if_block_data);
  for (uint32_t i = 0; i < params_count; i++) {
    UpdateStack(if_block_data.stack_size_ - params_count + i,
                if_block_data.GetParam(i), GetParamType(if_block_data, i));
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_execution) {
      EMIT_INSTR_HANDLER(trace_UpdateStack);
      EmitI32Const(if_block_data.stack_size_ - params_count + i);
      EmitI32Const(slots_[if_block_data.GetParam(i)].slot_offset * kSlotSize);
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  }
}

uint32_t WasmBytecodeGenerator::ScanConstInstructions() const {
  Decoder decoder(wasm_code_->start, wasm_code_->end);
  uint32_t const_slots_size = 0;
  pc_t pc = wasm_code_->locals.encoded_size;
  pc_t limit = wasm_code_->end - wasm_code_->start;
  while (pc < limit) {
    uint32_t opcode = wasm_code_->start[pc];
    if (opcode == kExprI32Const || opcode == kExprF32Const) {
      const_slots_size += sizeof(uint32_t) / kSlotSize;
    } else if (opcode == kExprI64Const || opcode == kExprF64Const) {
      const_slots_size += sizeof(uint64_t) / kSlotSize;
    } else if (opcode == kSimdPrefix) {
      auto [opcode_index, opcode_len] =
          decoder.read_u32v<Decoder::FullValidationTag>(
              wasm_code_->start + pc + 1, "prefixed opcode index");
      opcode = (kSimdPrefix << 8) | opcode_index;
      if (opcode == kExprS128Const || opcode == kExprI8x16Shuffle) {
        const_slots_size += sizeof(Simd128) / kSlotSize;
      }
    }
    pc++;
  }
  return const_slots_size;
}

int32_t WasmBytecodeGenerator::EndBlock(WasmOpcode opcode) {
  WasmBytecodeGenerator::BlockData& block_data = blocks_[current_block_index_];
  bool is_try_catch =
      block_data.IsTry() || block_data.IsCatch() || block_data.IsCatchAll();

  StoreBlockParamsAndResultsIntoSlots(current_block_index_, opcode);

  if (block_data.IsLoop()) {
    loop_end_code_offsets_.push_back(static_cast<uint32_t>(code_.size()));
    EMIT_INSTR_HANDLER(s2s_OnLoopBackwardJump);
  }

  block_data.end_code_offset_ = CurrentCodePos();
  if (opcode == kExprEnd && block_data.IsElse()) {
    DCHECK_GT(block_data.if_else_block_index_, 0);
    blocks_[block_data.if_else_block_index_].end_code_offset_ =
        CurrentCodePos();
  }

  if (!is_try_catch) {
    current_block_index_ = blocks_[current_block_index_].parent_block_index_;
  }

  if (is_try_catch && (opcode == kExprEnd || opcode == kExprDelegate)) {
    int32_t try_block_index =
        eh_data_.EndTryCatchBlocks(current_block_index_, CurrentCodePos());
    DCHECK_GE(try_block_index, 0);
    current_block_index_ = blocks_[try_block_index].parent_block_index_;
  }

  last_instr_offset_ = kInvalidCodeOffset;

  return current_block_index_;
}

void WasmBytecodeGenerator::Return() {
  if (current_block_index_ >= 0) {
    StoreBlockParamsAndResultsIntoSlots(0, kExprReturn);
  }

  EMIT_INSTR_HANDLER(s2s_Return);

  const WasmBytecodeGenerator::BlockData& target_block_data = blocks_[0];
  uint32_t final_stack_size =
      target_block_data.stack_size_ + ReturnsCount(target_block_data);
  EmitI32Const(final_stack_size);
}

WasmInstruction WasmBytecodeGenerator::DecodeInstruction(pc_t pc,
                                                         Decoder& decoder) {
  pc_t limit = wasm_code_->end - wasm_code_->start;
  if (pc >= limit) return WasmInstruction();

  int len = 1;
  uint8_t orig = wasm_code_->start[pc];
  WasmOpcode opcode = static_cast<WasmOpcode>(orig);
  if (WasmOpcodes::IsPrefixOpcode(opcode)) {
    uint32_t prefixed_opcode_length;
    std::tie(opcode, prefixed_opcode_length) =
        decoder.read_prefixed_opcode<Decoder::NoValidationTag>(
            wasm_code_->at(pc));
    // skip breakpoint by switching on original code.
    len = prefixed_opcode_length;
  }

  WasmInstruction::Optional optional;
  switch (orig) {
    case kExprUnreachable:
      break;
    case kExprNop:
      break;
    case kExprBlock:
    case kExprLoop:
    case kExprIf:
    case kExprTry: {
      BlockTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
                             wasm_code_->at(pc + 1), Decoder::kNoValidation);
      if (imm.sig_index.valid()) {
        // The block has at least one argument or at least two results, its
        // signature is identified by sig_index.
        optional.block.sig_index = imm.sig_index;
        optional.block.value_type_bitfield = kWasmBottom.raw_bit_field();
      } else if (imm.sig.return_count() + imm.sig.parameter_count() == 0) {
        // Void signature: no arguments and no results.
        optional.block.sig_index = ModuleTypeIndex::Invalid();
        optional.block.value_type_bitfield = kWasmVoid.raw_bit_field();
      } else {
        // No arguments and one result.
        optional.block.sig_index = ModuleTypeIndex::Invalid();
        std::optional<wasm::ValueType> wasm_return_type =
            GetWasmReturnTypeFromSignature(&imm.sig);
        DCHECK(wasm_return_type.has_value());
        optional.block.value_type_bitfield =
            wasm_return_type.value().raw_bit_field();
      }
      len = 1 + imm.length;
      break;
    }
    case kExprElse:
      break;
    case kExprCatch: {
      TagIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                            Decoder::kNoValidation);
      optional.index = imm.index;
      len = 1 + imm.length;
      break;
    }
    case kExprCatchAll:
      break;
    case kExprEnd:
      break;
    case kExprThrow: {
      TagIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                            Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprRethrow:
    case kExprBr:
    case kExprBrIf:
    case kExprBrOnNull:
    case kExprBrOnNonNull:
    case kExprDelegate: {
      BranchDepthImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.depth = imm.depth;
      break;
    }
    case kExprBrTable: {
      BranchTableImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      BranchTableIterator<Decoder::NoValidationTag> iterator(&decoder, imm);
      optional.br_table.table_count = imm.table_count;
      optional.br_table.labels_index =
          static_cast<uint32_t>(br_table_labels_.size());
      for (uint32_t i = 0; i <= imm.table_count; i++) {
        DCHECK(iterator.has_next());
        br_table_labels_.emplace_back(iterator.next());
      }
      len = static_cast<int>(1 + iterator.pc() - imm.start);
      break;
    }
    case kExprReturn:
      break;
    case kExprCallFunction:
    case kExprReturnCall: {
      CallFunctionImmediate imm(&decoder, wasm_code_->at(pc + 1),
                                Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprCallIndirect:
    case kExprReturnCallIndirect: {
      CallIndirectImmediate imm(&decoder, wasm_code_->at(pc + 1),
                                Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.indirect_call.table_index = imm.table_imm.index;
      optional.indirect_call.sig_index = imm.sig_imm.index;
      break;
    }
    case kExprDrop:
      break;
    case kExprSelect:
      break;
    case kExprSelectWithType: {
      SelectTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
                              wasm_code_->at(pc + 1), Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprLocalGet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprLocalSet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprLocalTee: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "local index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprGlobalGet: {
      GlobalIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprGlobalSet: {
      GlobalIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprTableGet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "table index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }
    case kExprTableSet: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "table index",
                         Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.index = imm.index;
      break;
    }

#define LOAD_CASE(name, ctype, mtype, rep, type)                        \
  case kExpr##name: {                                                   \
    MemoryAccessImmediate imm(                                          \
        &decoder, wasm_code_->at(pc + 1), sizeof(ctype),                \
        !module_->memories.empty() && module_->memories[0].is_memory64, \
        Decoder::kNoValidation);                                        \
    len = 1 + imm.length;                                               \
    optional.offset = imm.offset;                                       \
    break;                                                              \
  }
      LOAD_CASE(I32LoadMem8S, int32_t, int8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem8U, int32_t, uint8_t, kWord8, I32);
      LOAD_CASE(I32LoadMem16S, int32_t, int16_t, kWord16, I32);
      LOAD_CASE(I32LoadMem16U, int32_t, uint16_t, kWord16, I32);
      LOAD_CASE(I64LoadMem8S, int64_t, int8_t, kWord8, I64);
      LOAD_CASE(I64LoadMem8U, int64_t, uint8_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16S, int64_t, int16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem16U, int64_t, uint16_t, kWord16, I64);
      LOAD_CASE(I64LoadMem32S, int64_t, int32_t, kWord32, I64);
      LOAD_CASE(I64LoadMem32U, int64_t, uint32_t, kWord32, I64);
      LOAD_CASE(I32LoadMem, int32_t, int32_t, kWord32, I32);
      LOAD_CASE(I64LoadMem, int64_t, int64_t, kWord64, I64);
      LOAD_CASE(F32LoadMem, Float32, uint32_t, kFloat32, F32);
      LOAD_CASE(F64LoadMem, Float64, uint64_t, kFloat64, F64);
#undef LOAD_CASE

#define STORE_CASE(name, ctype, mtype, rep, type)                       \
  case kExpr##name: {                                                   \
    MemoryAccessImmediate imm(                                          \
        &decoder, wasm_code_->at(pc + 1), sizeof(ctype),                \
        !module_->memories.empty() && module_->memories[0].is_memory64, \
        Decoder::kNoValidation);                                        \
    len = 1 + imm.length;                                               \
    optional.offset = imm.offset;                                       \
    break;                                                              \
  }
      STORE_CASE(I32StoreMem8, int32_t, int8_t, kWord8, I32);
      STORE_CASE(I32StoreMem16, int32_t, int16_t, kWord16, I32);
      STORE_CASE(I64StoreMem8, int64_t, int8_t, kWord8, I64);
      STORE_CASE(I64StoreMem16, int64_t, int16_t, kWord16, I64);
      STORE_CASE(I64StoreMem32, int64_t, int32_t, kWord32, I64);
      STORE_CASE(I32StoreMem, int32_t, int32_t, kWord32, I32);
      STORE_CASE(I64StoreMem, int64_t, int64_t, kWord64, I64);
      STORE_CASE(F32StoreMem, Float32, uint32_t, kFloat32, F32);
      STORE_CASE(F64StoreMem, Float64, uint64_t, kFloat64, F64);
#undef STORE_CASE

    case kExprMemorySize: {
      MemoryIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprMemoryGrow: {
      MemoryIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                               Decoder::kNoValidation);
      len = 1 + imm.length;
      break;
    }
    case kExprI32Const: {
      ImmI32Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.i32 = imm.value;
      break;
    }
    case kExprI64Const: {
      ImmI64Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.i64 = imm.value;
      break;
    }
    case kExprF32Const: {
      ImmF32Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.f32 = imm.value;
      break;
    }
    case kExprF64Const: {
      ImmF64Immediate imm(&decoder, wasm_code_->at(pc + 1),
                          Decoder::kNoValidation);
      len = 1 + imm.length;
      optional.f64 = imm.value;
      break;
    }

#define EXECUTE_BINOP(name, ctype, reg, op, type) \
  case kExpr##name:                               \
    break;

      FOREACH_COMPARISON_BINOP(EXECUTE_BINOP)
      FOREACH_ARITHMETIC_BINOP(EXECUTE_BINOP)
      FOREACH_TRAPPING_BINOP(EXECUTE_BINOP)
      FOREACH_MORE_BINOP(EXECUTE_BINOP)
#undef EXECUTE_BINOP

#define EXECUTE_UNOP(name, ctype, reg, op, type) \
  case kExpr##name:                              \
    break;

      FOREACH_SIMPLE_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                     to_reg)                                                   \
  case kExpr##name:                                                            \
    break;

      FOREACH_ADDITIONAL_CONVERT_UNOP(EXECUTE_UNOP)
      FOREACH_CONVERT_UNOP(EXECUTE_UNOP)
      FOREACH_REINTERPRET_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, to_ctype, to_type, op) \
  case kExpr##name:                                                      \
    break;

      FOREACH_BITS_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, to_ctype, to_type) \
  case kExpr##name:                                                  \
    break;

      FOREACH_EXTENSION_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

    case kExprRefNull: {
      HeapTypeImmediate imm(WasmEnabledFeatures::All(), &decoder,
                            wasm_code_->at(pc + 1), Decoder::kNoValidation);
      optional.ref_type = imm.type.representation();
      len = 1 + imm.length;
      break;
    }
    case kExprRefIsNull:
    case kExprRefEq:
    case kExprRefAsNonNull: {
      len = 1;
      break;
    }
    case kExprRefFunc: {
      IndexImmediate imm(&decoder, wasm_code_->at(pc + 1), "function index",
                         Decoder::kNoValidation);
      optional.index = imm.index;
      len = 1 + imm.length;
      break;
    }

    case kGCPrefix:
      DecodeGCOp(opcode, &optional, &decoder, wasm_code_, pc, &len);
      break;

    case kNumericPrefix:
      DecodeNumericOp(opcode, &optional, &decoder, wasm_code_, pc, &len);
      break;

    case kAtomicPrefix:
      DecodeAtomicOp(opcode, &optional, &decoder, wasm_code_, pc, &len);
      break;

    case kSimdPrefix: {
      bool is_valid_simd_op =
          DecodeSimdOp(opcode, &optional, &decoder, wasm_code_, pc, &len);
      if (V8_UNLIKELY(!is_valid_simd_op)) {
        UNREACHABLE();
      }
      break;
    }

    case kExprCallRef:
    case kExprReturnCallRef: {
      SigIndexImmediate imm(&decoder, wasm_code_->at(pc + 1),
                            Decoder::kNoValidation);
      optional.index = imm.index;
      len = 1 + imm.length;
      break;
    }

    default:
      // Not implemented yet
      UNREACHABLE();
  }

  return WasmInstruction{orig, opcode, len, static_cast<uint32_t>(pc),
                         optional};
}

void WasmBytecodeGenerator::DecodeGCOp(WasmOpcode opcode,
                                       WasmInstruction::Optional* optional,
                                       Decoder* decoder, InterpreterCode* code,
                                       pc_t pc, int* const len) {
  switch (opcode) {
    case kExprStructNew:
    case kExprStructNewDefault: {
      StructIndexImmediate imm(decoder, code->at(pc + *len),
                               Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprStructGet:
    case kExprStructGetS:
    case kExprStructGetU:
    case kExprStructSet: {
      FieldImmediate imm(decoder, code->at(pc + *len), Decoder::kNoValidation);
      optional->gc_field_immediate = {imm.struct_imm.index,
                                      imm.field_imm.index};
      *len += imm.length;
      break;
    }
    case kExprArrayNew:
    case kExprArrayNewDefault:
    case kExprArrayGet:
    case kExprArrayGetS:
    case kExprArrayGetU:
    case kExprArraySet:
    case kExprArrayFill: {
      ArrayIndexImmediate imm(decoder, code->at(pc + *len),
                              Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }

    case kExprArrayNewFixed: {
      ArrayIndexImmediate array_imm(decoder, code->at(pc + *len),
                                    Decoder::kNoValidation);
      optional->gc_array_new_fixed.array_index = array_imm.index;
      *len += array_imm.length;
      IndexImmediate data_imm(decoder, code->at(pc + *len), "array length",
                              Decoder::kNoValidation);
      optional->gc_array_new_fixed.length = data_imm.index;
      *len += data_imm.length;
      break;
    }

    case kExprArrayNewData:
    case kExprArrayNewElem:
    case kExprArrayInitData:
    case kExprArrayInitElem: {
      ArrayIndexImmediate array_imm(decoder, code->at(pc + *len),
                                    Decoder::kNoValidation);
      optional->gc_array_new_or_init_data.array_index = array_imm.index;
      *len += array_imm.length;
      IndexImmediate data_imm(decoder, code->at(pc + *len), "segment index",
                              Decoder::kNoValidation);
      optional->gc_array_new_or_init_data.data_index = data_imm.index;
      *len += data_imm.length;
      break;
    }

    case kExprArrayCopy: {
      ArrayIndexImmediate dest_array_imm(decoder, code->at(pc + *len),
                                         Decoder::kNoValidation);
      optional->gc_array_copy.dest_array_index = dest_array_imm.index;
      *len += dest_array_imm.length;
      ArrayIndexImmediate src_array_imm(decoder, code->at(pc + *len),
                                        Decoder::kNoValidation);
      optional->gc_array_copy.src_array_index = src_array_imm.index;
      *len += src_array_imm.length;
      break;
    }

    case kExprRefI31:
    case kExprI31GetS:
    case kExprI31GetU:
    case kExprAnyConvertExtern:
    case kExprExternConvertAny:
    case kExprArrayLen:
      break;

    case kExprRefCast:
    case kExprRefCastNull:
    case kExprRefTest:
    case kExprRefTestNull: {
      HeapTypeImmediate imm(WasmEnabledFeatures::All(), decoder,
                            code->at(pc + *len), Decoder::kNoValidation);
      optional->gc_heap_type_immediate.length = imm.length;
      optional->gc_heap_type_immediate.type_representation =
          imm.type.representation();
      *len += imm.length;
      break;
    }

    case kExprBrOnCast:
    case kExprBrOnCastFail: {
      BrOnCastImmediate flags_imm(decoder, code->at(pc + *len),
                                  Decoder::kNoValidation);
      *len += flags_imm.length;
      BranchDepthImmediate branch(decoder, code->at(pc + *len),
                                  Decoder::kNoValidation);
      *len += branch.length;
      HeapTypeImmediate source_imm(WasmEnabledFeatures::All(), decoder,
                                   code->at(pc + *len), Decoder::kNoValidation);
      *len += source_imm.length;
      HeapTypeImmediate target_imm(WasmEnabledFeatures::All(), decoder,
                                   code->at(pc + *len), Decoder::kNoValidation);
      *len += target_imm.length;
      optional->br_on_cast_data = BranchOnCastData{
          branch.depth, flags_imm.flags.src_is_null,
          flags_imm.flags.res_is_null, target_imm.type.representation()};
      break;
    }

    default:
      FATAL("Unknown or unimplemented opcode #%d:%s", code->start[pc],
            WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(code->start[pc])));
      UNREACHABLE();
  }
}

void WasmBytecodeGenerator::DecodeNumericOp(WasmOpcode opcode,
                                            WasmInstruction::Optional* optional,
                                            Decoder* decoder,
                                            InterpreterCode* code, pc_t pc,
                                            int* const len) {
  switch (opcode) {
#define DECODE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                    to_reg)                                                   \
  case kExpr##name:                                                           \
    break;

    FOREACH_TRUNCSAT_UNOP(DECODE_UNOP)
#undef DECODE_UNOP

    case kExprMemoryInit: {
      MemoryInitImmediate imm(decoder, code->at(pc + *len),
                              Decoder::kNoValidation);
      DCHECK_LT(imm.data_segment.index, module_->num_declared_data_segments);
      optional->index = imm.data_segment.index;
      *len += imm.length;
      break;
    }
    case kExprDataDrop: {
      IndexImmediate imm(decoder, code->at(pc + *len), "data segment index",
                         Decoder::kNoValidation);
      DCHECK_LT(imm.index, module_->num_declared_data_segments);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprMemoryCopy: {
      MemoryCopyImmediate imm(decoder, code->at(pc + *len),
                              Decoder::kNoValidation);
      *len += imm.length;
      break;
    }
    case kExprMemoryFill: {
      MemoryIndexImmediate imm(decoder, code->at(pc + *len),
                               Decoder::kNoValidation);
      *len += imm.length;
      break;
    }
    case kExprTableInit: {
      TableInitImmediate imm(decoder, code->at(pc + *len),
                             Decoder::kNoValidation);
      optional->table_init.table_index = imm.table.index;
      optional->table_init.element_segment_index = imm.element_segment.index;
      *len += imm.length;
      break;
    }
    case kExprElemDrop: {
      IndexImmediate imm(decoder, code->at(pc + *len), "element segment index",
                         Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprTableCopy: {
      TableCopyImmediate imm(decoder, code->at(pc + *len),
                             Decoder::kNoValidation);
      optional->table_copy.dst_table_index = imm.table_dst.index;
      optional->table_copy.src_table_index = imm.table_src.index;
      *len += imm.length;
      break;
    }
    case kExprTableGrow: {
      IndexImmediate imm(decoder, code->at(pc + *len), "table index",
                         Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprTableSize: {
      IndexImmediate imm(decoder, code->at(pc + *len), "table index",
                         Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    case kExprTableFill: {
      IndexImmediate imm(decoder, code->at(pc + *len), "table index",
                         Decoder::kNoValidation);
      optional->index = imm.index;
      *len += imm.length;
      break;
    }
    default:
      FATAL("Unknown or unimplemented opcode #%d:%s", code->start[pc],
            WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(code->start[pc])));
      UNREACHABLE();
  }
}

void WasmBytecodeGenerator::DecodeAtomicOp(WasmOpcode opcode,
                                           WasmInstruction::Optional* optional,
                                           Decoder* decoder,
                                           InterpreterCode* code, pc_t pc,
                                           int* const len) {
  switch (opcode) {
    case kExprAtomicNotify:
    case kExprI32AtomicWait: {
      MachineType memtype = MachineType::Uint32();
      MemoryAccessImmediate imm(decoder, code->at(pc + *len),
                                ElementSizeLog2Of(memtype.representation()),
                                IsMemory64(), Decoder::kNoValidation);
      optional->offset = imm.offset;
      *len += imm.length;
      break;
    }
    case kExprI64AtomicWait: {
      MachineType memtype = MachineType::Uint64();
      MemoryAccessImmediate imm(decoder, code->at(pc + *len),
                                ElementSizeLog2Of(memtype.representation()),
                                IsMemory64(), Decoder::kNoValidation);
      optional->offset = imm.offset;
      *len += imm.length;
      break;
    }
    case kExprAtomicFence:
      *len += 1;
      break;

#define ATOMIC_BINOP(name, Type,
```