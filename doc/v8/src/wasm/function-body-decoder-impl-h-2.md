Response:
My goal is to analyze the provided C++ code snippet and describe its functionality according to the user's instructions. Here's a breakdown of my thought process:

1. **Identify the Core Functionality:** The code contains several `Validate` methods and a `OpcodeLength` method. The `Validate` methods take a program counter (`pc`) and some immediate value (like index, type, etc.) as input. They seem to be checking if these immediate values are valid within the context of a WebAssembly module. The `OpcodeLength` method calculates the length of a WebAssembly opcode and its associated immediates. The first function, which takes `kExprLoop` as a condition, seems to analyze the structure of a loop and identify assigned local variables.

2. **Relate to WebAssembly Decoding:** The file path `v8/src/wasm/function-body-decoder-impl.h` strongly suggests this code is part of the WebAssembly decoding process in V8. The presence of `WasmOpcode` and various immediate types (like `IndexImmediate`, `MemoryAccessImmediate`) confirms this.

3. **Analyze Individual Functions:**

   * **`ComputeAssignedLocalsInLoop`:** This function iterates through the bytecode within a `loop` block, keeping track of nested block depths. It identifies `local.set` and `local.tee` instructions and records the indices of the modified locals in a `BitVector`. It also includes logic for handling calls, suggesting it's aware of potential instance cache usage.

   * **`Validate` methods:** Each `Validate` method checks the validity of a specific type of immediate value. For example, `Validate(pc, TagIndexImmediate& imm)` checks if the tag index is within the bounds of the module's tags. These methods often involve checking bounds, types, and potentially shared/non-shared access restrictions. They use the `DecodeError` function to report invalid immediates.

   * **`CanReturnCall`:** This checks if the return types of the current function signature are subtypes of the target function's return types.

   * **`OpcodeLength`:** This function uses a `switch` statement based on the `WasmOpcode` to determine the total length of the instruction, including the opcode itself and the lengths of its immediate operands. It handles prefixed opcodes (numeric, SIMD, atomic, GC) recursively. It also incorporates "observers" which can be used to extract information about the immediates.

4. **Infer Overall Purpose:** The primary function of this code is to perform *validation* of the WebAssembly bytecode during decoding. It ensures that indices, types, and other immediate values are consistent with the module's definition and the WebAssembly specification. The `OpcodeLength` function is essential for advancing the decoder's program counter.

5. **Address Specific User Queries:**

   * **Functionality List:** I will list the key functions and describe their individual purposes.

   * **`.tq` Check:** The file extension is `.h`, not `.tq`. Therefore, it's standard C++ header code, not Torque.

   * **JavaScript Relationship:**  This code is part of the *implementation* of WebAssembly in V8, which directly enables JavaScript to *run* WebAssembly code. I can provide a JavaScript example of loading and executing WebAssembly to illustrate the connection.

   * **Code Logic Reasoning (Loop Analysis):** I'll create a simple example of a WebAssembly loop with `local.set` instructions and trace the `ComputeAssignedLocalsInLoop` function's behavior.

   * **Common Programming Errors:** The validation checks directly relate to common errors in writing or generating WebAssembly, such as using out-of-bounds indices, incorrect types, or accessing shared resources improperly. I can provide examples of these errors in WebAssembly text format.

   * **Summary:** I'll summarize the overarching purpose of the code as part of the WebAssembly decoding and validation process.

6. **Structure the Output:** I'll organize the information into clear sections addressing each of the user's requests, providing code examples and explanations where needed. I will explicitly state that this is part 3 of 9, as requested.

7. **Refine and Review:**  I'll review my response to ensure accuracy, clarity, and completeness, making sure all aspects of the user's prompt are addressed. I'll double-check the generated JavaScript and WebAssembly examples for correctness. I will also ensure the tone is informative and helpful.

By following this thought process, I can systematically analyze the code and generate a comprehensive and accurate response that satisfies the user's requirements.
```cpp
 pc,
                                          uint32_t locals_count, Zone* zone,
                                          bool* loop_is_innermost = nullptr) {
    if (pc >= decoder->end()) return nullptr;
    if (*pc != kExprLoop) return nullptr;
    // The number of locals_count is augmented by 1 so that the 'locals_count'
    // index can be used to track the instance cache.
    BitVector* assigned = zone->New<BitVector>(locals_count + 1, zone);
    int depth = -1;  // We will increment the depth to 0 when we decode the
                     // starting 'loop' opcode.
    if (loop_is_innermost) *loop_is_innermost = true;
    // Iteratively process all AST nodes nested inside the loop.
    while (pc < decoder->end() && VALIDATE(decoder->ok())) {
      WasmOpcode opcode = static_cast<WasmOpcode>(*pc);
      switch (opcode) {
        case kExprLoop:
          if (loop_is_innermost && depth >= 0) *loop_is_innermost = false;
          [[fallthrough]];
        case kExprIf:
        case kExprBlock:
        case kExprTry:
        case kExprTryTable:
          depth++;
          break;
        case kExprLocalSet:
        case kExprLocalTee: {
          IndexImmediate imm(decoder, pc + 1, "local index", validate);
          // Unverified code might have an out-of-bounds index.
          if (imm.index < locals_count) assigned->Add(imm.index);
          break;
        }
        case kExprMemoryGrow:
        case kExprCallFunction:
        case kExprCallIndirect:
        case kExprCallRef:
          // Add instance cache to the assigned set.
          assigned->Add(locals_count);
          break;
        case kExprEnd:
          depth--;
          break;
        default:
          break;
      }
      if (depth < 0) break;
      pc += OpcodeLength(decoder, pc);
    }
    return VALIDATE(decoder->ok()) ? assigned : nullptr;
  }

  bool Validate(const uint8_t* pc, TagIndexImmediate& imm) {
    size_t num_tags = module_->tags.size();
    if (!VALIDATE(imm.index < num_tags)) {
      DecodeError(pc, "Invalid tag index: %u", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_tags);
    imm.tag = &module_->tags[imm.index];
    return true;
  }

  bool Validate(const uint8_t* pc, GlobalIndexImmediate& imm) {
    // We compare with the current size of the globals vector. This is important
    // if we are decoding a constant expression in the global section.
    size_t num_globals = module_->globals.size();
    if (!VALIDATE(imm.index < num_globals)) {
      DecodeError(pc, "Invalid global index: %u", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_globals);
    imm.global = &module_->globals[imm.index];
    if (!VALIDATE(!is_shared_ || imm.global->shared)) {
      DecodeError(pc, "Cannot access non-shared global %d in a shared %s",
                  imm.index,
                  decoding_mode == kConstantExpression ? "constant expression"
                                                       : "function");
      return false;
    }

    if constexpr (decoding_mode == kConstantExpression) {
      if (!VALIDATE(!imm.global->mutability)) {
        this->DecodeError(pc,
                          "mutable globals cannot be used in constant "
                          "expressions");
        return false;
      }
    }

    return true;
  }

  bool Validate(const uint8_t* pc, SigIndexImmediate& imm) {
    if (!VALIDATE(module_->has_signature(imm.index))) {
      DecodeError(pc, "invalid signature index: %u", imm.index.index);
      return false;
    }
    imm.sig = module_->signature(imm.index);
    return true;
  }

  bool Validate(const uint8_t* pc, StructIndexImmediate& imm) {
    if (!VALIDATE(module_->has_struct(imm.index))) {
      DecodeError(pc, "invalid struct index: %u", imm.index.index);
      return false;
    }
    imm.struct_type = module_->struct_type(imm.index);
    return true;
  }

  bool Validate(const uint8_t* pc, FieldImmediate& imm) {
    if (!Validate(pc, imm.struct_imm)) return false;
    if (!VALIDATE(imm.field_imm.index <
                  imm.struct_imm.struct_type->field_count())) {
      DecodeError(pc + imm.struct_imm.length, "invalid field index: %u",
                  imm.field_imm.index);
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, ArrayIndexImmediate& imm) {
    if (!VALIDATE(module_->has_array(imm.index))) {
      DecodeError(pc, "invalid array index: %u", imm.index.index);
      return false;
    }
    imm.array_type = module_->array_type(imm.index);
    return true;
  }

  bool CanReturnCall(const FunctionSig* target_sig) {
    if (sig_->return_count() != target_sig->return_count()) return false;
    auto target_sig_it = target_sig->returns().begin();
    for (ValueType ret_type : sig_->returns()) {
      if (!IsSubtypeOf(*target_sig_it++, ret_type, this->module_)) return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, CallFunctionImmediate& imm) {
    size_t num_functions = module_->functions.size();
    if (!VALIDATE(imm.index < num_functions)) {
      DecodeError(pc, "function index #%u is out of bounds", imm.index);
      return false;
    }
    if (is_shared_ && !module_->function_is_shared(imm.index)) {
      DecodeError(pc, "cannot call non-shared function %u", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_functions);
    imm.sig = module_->functions[imm.index].sig;
    return true;
  }

  bool Validate(const uint8_t* pc, CallIndirectImmediate& imm) {
    if (!Validate(pc, imm.sig_imm)) return false;
    if (!Validate(pc + imm.sig_imm.length, imm.table_imm)) return false;
    ValueType table_type = imm.table_imm.table->type;
    if (!VALIDATE(IsSubtypeOf(table_type, kWasmFuncRef, module_) ||
                  IsSubtypeOf(table_type,
                              ValueType::RefNull(HeapType::kFuncShared),
                              module_))) {
      DecodeError(
          pc, "call_indirect: immediate table #%u is not of a function type",
          imm.table_imm.index);
      return false;
    }
    // The type specified by the immediate does not need to have any static
    // relation (neither sub nor super) to the type of the table. The type
    // of the function will be checked at runtime.

    imm.sig = module_->signature(imm.sig_imm.index);
    return true;
  }

  bool Validate(const uint8_t* pc, BranchDepthImmediate& imm,
                size_t control_depth) {
    if (!VALIDATE(imm.depth < control_depth)) {
      DecodeError(pc, "invalid branch depth: %u", imm.depth);
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, BranchTableImmediate& imm) {
    if (!VALIDATE(imm.table_count <= kV8MaxWasmFunctionBrTableSize)) {
      DecodeError(pc, "invalid table count (> max br_table size): %u",
                  imm.table_count);
      return false;
    }
    return checkAvailable(imm.table_count);
  }

  bool Validate(const uint8_t* pc, WasmOpcode opcode, SimdLaneImmediate& imm) {
    uint8_t num_lanes = 0;
    switch (opcode) {
      case kExprF64x2ExtractLane:
      case kExprF64x2ReplaceLane:
      case kExprI64x2ExtractLane:
      case kExprI64x2ReplaceLane:
      case kExprS128Load64Lane:
      case kExprS128Store64Lane:
        num_lanes = 2;
        break;
      case kExprF32x4ExtractLane:
      case kExprF32x4ReplaceLane:
      case kExprI32x4ExtractLane:
      case kExprI32x4ReplaceLane:
      case kExprS128Load32Lane:
      case kExprS128Store32Lane:
        num_lanes = 4;
        break;
      case kExprF16x8ExtractLane:
      case kExprF16x8ReplaceLane:
      case kExprI16x8ExtractLaneS:
      case kExprI16x8ExtractLaneU:
      case kExprI16x8ReplaceLane:
      case kExprS128Load16Lane:
      case kExprS128Store16Lane:
        num_lanes = 8;
        break;
      case kExprI8x16ExtractLaneS:
      case kExprI8x16ExtractLaneU:
      case kExprI8x16ReplaceLane:
      case kExprS128Load8Lane:
      case kExprS128Store8Lane:
        num_lanes = 16;
        break;
      default:
        UNREACHABLE();
        break;
    }
    if (!VALIDATE(imm.lane >= 0 && imm.lane < num_lanes)) {
      DecodeError(pc, "invalid lane index");
      return false;
    } else {
      return true;
    }
  }

  bool Validate(const uint8_t* pc, Simd128Immediate& imm) {
    uint8_t max_lane = 0;
    for (uint32_t i = 0; i < kSimd128Size; ++i) {
      max_lane = std::max(max_lane, imm.value[i]);
    }
    // Shuffle indices must be in [0..31] for a 16 lane shuffle.
    if (!VALIDATE(max_lane < 2 * kSimd128Size)) {
      DecodeError(pc, "invalid shuffle mask");
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, BlockTypeImmediate& imm) {
    if (imm.sig.all().begin() == nullptr) {
      // Then use {sig_index} to initialize the signature.
      if (!VALIDATE(module_->has_signature(imm.sig_index))) {
        DecodeError(pc, "block type index %u is not a signature definition",
                    imm.sig_index);
        return false;
      }
      imm.sig = *module_->signature(imm.sig_index);
    } else {
      // Then it's an MVP immediate with 0 parameters and 0-1 returns.
      DCHECK_EQ(0, imm.sig.parameter_count());
      DCHECK_GE(1, imm.sig.return_count());
      if (imm.sig.return_count()) {
        if (!ValidateValueType(pc, imm.sig.GetReturn(0))) return false;
      }
    }
    return true;
  }

  bool Validate(const uint8_t* pc, MemoryIndexImmediate& imm) {
    size_t num_memories = module_->memories.size();
    if (imm.index > 0 || imm.length > 1) {
      this->detected_->add_multi_memory();
    }

    if (!VALIDATE(imm.index < num_memories)) {
      DecodeError(pc,
                  "memory index %u exceeds number of declared memories (%zu)",
                  imm.index, num_memories);
      return false;
    }

    V8_ASSUME(imm.index < num_memories);
    imm.memory = this->module_->memories.data() + imm.index;

    return true;
  }

  bool Validate(const uint8_t* pc, MemoryAccessImmediate& imm) {
    size_t num_memories = module_->memories.size();
    if (!VALIDATE(imm.mem_index < num_memories)) {
      DecodeError(pc,
                  "memory index %u exceeds number of declared memories (%zu)",
                  imm.mem_index, num_memories);
      return false;
    }
    if (!VALIDATE(this->module_->memories[imm.mem_index].is_memory64() ||
                  imm.offset <= kMaxUInt32)) {
      this->DecodeError(pc, "memory offset outside 32-bit range: %" PRIu64,
                        imm.offset);
      return false;
    }

    V8_ASSUME(imm.mem_index < num_memories);
    imm.memory = this->module_->memories.data() + imm.mem_index;

    return true;
  }

  bool Validate(const uint8_t* pc, MemoryInitImmediate& imm) {
    return ValidateDataSegment(pc, imm.data_segment) &&
           Validate(pc + imm.data_segment.length, imm.memory);
  }

  bool Validate(const uint8_t* pc, MemoryCopyImmediate& imm) {
    return Validate(pc, imm.memory_src) &&
           Validate(pc + imm.memory_src.length, imm.memory_dst);
  }

  bool Validate(const uint8_t* pc, TableInitImmediate& imm) {
    if (!ValidateElementSegment(pc, imm.element_segment)) return false;
    if (!Validate(pc + imm.element_segment.length, imm.table)) {
      return false;
    }
    ValueType elem_type =
        module_->elem_segments[imm.element_segment.index].type;
    if (!VALIDATE(IsSubtypeOf(elem_type, imm.table.table->type, module_))) {
      DecodeError(pc, "table %u is not a super-type of %s", imm.table.index,
                  elem_type.name().c_str());
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, TableCopyImmediate& imm) {
    if (!Validate(pc, imm.table_src)) return false;
    if (!Validate(pc + imm.table_src.length, imm.table_dst)) return false;
    ValueType src_type = imm.table_src.table->type;
    if (!VALIDATE(IsSubtypeOf(src_type, imm.table_dst.table->type, module_))) {
      DecodeError(pc, "table %u is not a super-type of %s", imm.table_dst.index,
                  src_type.name().c_str());
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, StringConstImmediate& imm) {
    if (!VALIDATE(imm.index < module_->stringref_literals.size())) {
      DecodeError(pc, "Invalid string literal index: %u", imm.index);
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, TableIndexImmediate& imm) {
    if (imm.index > 0 || imm.length > 1) {
      this->detected_->add_reftypes();
    }
    size_t num_tables = module_->tables.size();
    if (!VALIDATE(imm.index < num_tables)) {
      DecodeError(pc, "table index %u exceeds number of tables (%zu)",
                  imm.index, num_tables);
      return false;
    }
    imm.table = this->module_->tables.data() + imm.index;

    if (!VALIDATE(!is_shared_ || imm.table->shared)) {
      DecodeError(pc,
                  "cannot reference non-shared table %u from shared function",
                  imm.index);
      return false;
    }

    return true;
  }

  // The following Validate* functions all validate an `IndexImmediate`, albeit
  // differently according to context.
  bool ValidateElementSegment(const uint8_t* pc, IndexImmediate& imm) {
    size_t num_elem_segments = module_->elem_segments.size();
    if (!VALIDATE(imm.index < num_elem_segments)) {
      DecodeError(pc, "invalid element segment index: %u", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_elem_segments);
    if (!VALIDATE(!is_shared_ || module_->elem_segments[imm.index].shared)) {
      DecodeError(
          pc,
          "cannot reference non-shared element segment %u from shared function",
          imm.index);
      return false;
    }
    return true;
  }

  bool ValidateLocal(const uint8_t* pc, IndexImmediate& imm) {
    if (!VALIDATE(imm.index < num_locals())) {
      DecodeError(pc, "invalid local index: %u", imm.index);
      return false;
    }
    return true;
  }

  bool ValidateFunction(const uint8_t* pc, IndexImmediate& imm) {
    size_t num_functions = module_->functions.size();
    if (!VALIDATE(imm.index < num_functions)) {
      DecodeError(pc, "function index #%u is out of bounds", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_functions);
    if (decoding_mode == kFunctionBody &&
        !VALIDATE(module_->functions[imm.index].declared)) {
      DecodeError(pc, "undeclared reference to function #%u", imm.index);
      return false;
    }
    return true;
  }

  bool ValidateDataSegment(const uint8_t* pc, IndexImmediate& imm) {
    if (!VALIDATE(imm.index < module_->num_declared_data_segments)) {
      DecodeError(pc, "invalid data segment index: %u", imm.index);
      return false;
    }
    // TODO(14616): Data segments aren't available during eager validation.
    // Discussion: github.com/WebAssembly/shared-everything-threads/issues/83
    if (!VALIDATE(!is_shared_ || module_->data_segments[imm.index].shared)) {
      DecodeError(
          pc, "cannot refer to non-shared segment %u from a shared function",
          imm.index);
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, SelectTypeImmediate& imm) {
    return ValidateValueType(pc, imm.type);
  }

  bool Validate(const uint8_t* pc, HeapTypeImmediate& imm) {
    return ValidateHeapType(pc, imm.type);
  }

  bool ValidateValueType(const uint8_t* pc, ValueType type) {
    return value_type_reader::ValidateValueType<ValidationTag>(this, pc,
                                                               module_, type);
  }

  bool ValidateHeapType(const uint8_t* pc, HeapType type) {
    return value_type_reader::ValidateHeapType<ValidationTag>(this, pc, module_,
                                                              type);
  }

  // Returns the length of the opcode under {pc}.
  template <typename... ImmediateObservers>
  static uint32_t OpcodeLength(WasmDecoder* decoder, const uint8_t* pc,
                               ImmediateObservers&... ios) {
    WasmOpcode opcode = static_cast<WasmOpcode>(*pc);
    // We don't have information about the module here, so we just assume that
    // memory64 and multi-memory are enabled when parsing memory access
    // immediates. This is backwards-compatible; decode errors will be detected
    // at another time when actually decoding that opcode.
    constexpr bool kConservativelyAssumeMemory64 = true;
    switch (opcode) {
      /********** Control opcodes **********/
      case kExprUnreachable:
      case kExprNop:
      case kExprNopForTestingUnsupportedInLiftoff:
      case kExprElse:
      case kExprEnd:
      case kExprReturn:
        return 1;
      case kExprTry:
      case kExprIf:
      case kExprLoop:
      case kExprBlock: {
        BlockTypeImmediate imm(WasmEnabledFeatures::All(), decoder, pc + 1,
                               validate);
        (ios.BlockType(imm), ...);
        return 1 + imm.length;
      }
      case kExprRethrow:
      case kExprBr:
      case kExprBrIf:
      case kExprBrOnNull:
      case kExprBrOnNonNull:
      case kExprDelegate: {
        BranchDepthImmediate imm(decoder, pc + 1, validate);
        (ios.BranchDepth(imm), ...);
        return 1 + imm.length;
      }
      case kExprBrTable: {
        BranchTableImmediate imm(decoder, pc + 1, validate);
        (ios.BranchTable(imm), ...);
        BranchTableIterator<ValidationTag> iterator(decoder, imm);
        return 1 + iterator.length();
      }
      case kExprTryTable: {
        BlockTypeImmediate block_type_imm(WasmEnabledFeatures::All(), decoder,
                                          pc + 1, validate);
        (ios.BlockType(block_type_imm), ...);
        TryTableImmediate try_table_imm(decoder, pc + 1 + block_type_imm.length,
                                        validate);
        (ios.TryTable(try_table_imm), ...);
        TryTableIterator<ValidationTag> iterator(decoder, try_table_imm);
        return 1 + block_type_imm.length + iterator.length();
      }
      case kExprThrow:
      case kExprCatch: {
        TagIndexImmediate imm(decoder, pc + 1, validate);
        (ios.TagIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprThrowRef:
        return 1;

      /********** Misc opcodes **********/
      case kExprCallFunction:
      case kExprReturnCall: {
        CallFunctionImmediate imm(decoder, pc + 1, validate);
        (ios.FunctionIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprCallIndirect:
      case kExprReturnCallIndirect: {
        CallIndirectImmediate imm(decoder, pc + 1, validate);
        (ios.CallIndirect(imm), ...);
        return 1 + imm.length;
      }
      case kExprCallRef:
      case kExprReturnCallRef: {
        SigIndexImmediate imm(decoder, pc + 1, validate);
        (ios.TypeIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprDrop:
      case kExprSelect:
      case kExprCatchAll:
      case kExprRefEq:
        return 1;
      case kExprSelectWithType: {
        SelectTypeImmediate imm(WasmEnabledFeatures::All(), decoder, pc + 1,
                                validate);
        (ios.SelectType(imm), ...);
        return 1 + imm.length;
      }

      case kExprLocalGet:
      case kExprLocalSet:
      case kExprLocalTee: {
        IndexImmediate imm(decoder, pc + 1, "local index", validate);
        (ios.LocalIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprGlobalGet:
      case kExprGlobalSet: {
        GlobalIndexImmediate imm(decoder, pc + 1, validate);
        (ios.GlobalIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprTableGet:
      case kExprTableSet: {
        TableIndexImmediate imm(decoder, pc + 1, validate);
        (ios.TableIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprI32Const: {
        ImmI32Immediate imm(decoder, pc + 1, validate);
        (ios.I32Const(imm), ...);
        return 1 + imm.length;
      }
      case kExprI64Const: {
        ImmI64Immediate imm(decoder, pc + 1, validate);
        (ios.I64Const(imm), ...);
        return 1 + imm.length;
      }
      case kExprF32Const:
        if (sizeof...(ios) > 0) {
          ImmF32Immediate imm(decoder, pc + 1, validate);
          (ios.F32Const(imm), ...);
        }
        return 5;
      case kExprF64Const:
        if (sizeof...(ios) > 0) {
          ImmF64Immediate imm(decoder, pc + 1, validate);
          (ios.F64Const(imm), ...);
        }
        return 9;
      case kExprRefNull: {
        HeapTypeImmediate imm(WasmEnabledFeatures::All(), decoder, pc + 1,
                              validate);
        (ios.HeapType(imm), ...);
        return 1 + imm.length;
      }
      case kExprRefIsNull:
      case kExprRefAsNonNull:
        return 1;
      case kExprRefFunc: {
        IndexImmediate imm(decoder, pc + 1, "function index", validate);
        (ios.FunctionIndex(imm), ...);
        return 1 + imm.length;
      }

#define DECLARE_OPCODE_CASE(name, ...) case kExpr##name:
        // clang-format off
      /********** Simple and memory opcodes **********/
      FOREACH_SIMPLE_OPCODE(DECLARE_OPCODE_CASE)
      FOREACH_SIMPLE_PROTOTYPE_OPCODE(DECLARE_OPCODE_CASE)
        return 1;
      FOREACH_LOAD_MEM_OPCODE(DECLARE_OPCODE_CASE)
      FOREACH_STORE_MEM_OPCODE(DECLARE_OPCODE_CASE) {
        MemoryAccessImmediate imm(decoder, pc + 1, UINT32_MAX,
                                  kConservativelyAssumeMemory64,
                                  validate);
        (ios.MemoryAccess(imm), ...);
        return 1 + imm.length;
      }
      // clang-format on
      case kExprMemoryGrow:
      case kExprMemorySize: {
        MemoryIndexImmediate imm(decoder, pc + 1, validate);
        (ios.MemoryIndex(imm), ...);
        return 1 + imm.length;
      }

      /********** Prefixed opcodes **********/
      case kNumericPrefix: {
        uint32_t length;
        std::tie(opcode, length) =
            decoder->read_prefixed_opcode<ValidationTag>(pc);
        switch (opcode) {
          case kExprI32SConvertSatF32:
          case kExprI32UConvertSatF32:
          case kExprI32SConvertSatF64:
          case kExprI32UConvertSatF64:
          case kExprI64SConvertSatF32:
          case kExprI64UConvertSatF32:
          case kExprI64SConvertSatF64:
          case kExprI64UConvertSatF64:
            return length;
          case kExprMemoryInit: {
            MemoryInitImmediate imm(decoder, pc + length, validate);
            (ios.MemoryInit(imm), ...);
            return length + imm.length;
          }
          case kExprDataDrop: {
            IndexImmediate imm(decoder, pc + length, "data segment index",
                               validate);
            (ios.DataSegmentIndex(imm), ...);
            return length + imm.length;
          }
          case kExprMemoryCopy: {
            MemoryCopyImmediate imm(decoder, pc + length, validate);
            (ios.MemoryCopy(imm), ...);
            return length + imm.length;
          }
          case kExprMemoryFill: {
            MemoryIndexImmediate imm(decoder, pc + length, validate);
            (ios.MemoryIndex(imm), ...);
            return length + imm.length;
          }
          case kExprTableInit: {
            TableInitImmediate imm(decoder, pc + length, validate);
            (ios.TableInit(imm), ...);
            return length + imm.length;
          }
          case kExprElemDrop: {
            IndexImmediate imm(decoder, pc + length, "element segment index",
                               validate);
            (ios.ElemSegmentIndex(imm), ...);
            return length + imm.length;
          }
          case kExprTableCopy: {
            TableCopyImmediate imm(decoder, pc + length, validate);
            (ios.TableCopy(imm), ...);
            return length + imm.length;
          }
          case kExprTableGrow:
          case kExprTableSize:
          case kExprTableFill: {
            TableIndexImmediate imm(decoder, pc + length, validate);

### 提示词
```
这是目录为v8/src/wasm/function-body-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-body-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能
```

### 源代码
```c
pc,
                                          uint32_t locals_count, Zone* zone,
                                          bool* loop_is_innermost = nullptr) {
    if (pc >= decoder->end()) return nullptr;
    if (*pc != kExprLoop) return nullptr;
    // The number of locals_count is augmented by 1 so that the 'locals_count'
    // index can be used to track the instance cache.
    BitVector* assigned = zone->New<BitVector>(locals_count + 1, zone);
    int depth = -1;  // We will increment the depth to 0 when we decode the
                     // starting 'loop' opcode.
    if (loop_is_innermost) *loop_is_innermost = true;
    // Iteratively process all AST nodes nested inside the loop.
    while (pc < decoder->end() && VALIDATE(decoder->ok())) {
      WasmOpcode opcode = static_cast<WasmOpcode>(*pc);
      switch (opcode) {
        case kExprLoop:
          if (loop_is_innermost && depth >= 0) *loop_is_innermost = false;
          [[fallthrough]];
        case kExprIf:
        case kExprBlock:
        case kExprTry:
        case kExprTryTable:
          depth++;
          break;
        case kExprLocalSet:
        case kExprLocalTee: {
          IndexImmediate imm(decoder, pc + 1, "local index", validate);
          // Unverified code might have an out-of-bounds index.
          if (imm.index < locals_count) assigned->Add(imm.index);
          break;
        }
        case kExprMemoryGrow:
        case kExprCallFunction:
        case kExprCallIndirect:
        case kExprCallRef:
          // Add instance cache to the assigned set.
          assigned->Add(locals_count);
          break;
        case kExprEnd:
          depth--;
          break;
        default:
          break;
      }
      if (depth < 0) break;
      pc += OpcodeLength(decoder, pc);
    }
    return VALIDATE(decoder->ok()) ? assigned : nullptr;
  }

  bool Validate(const uint8_t* pc, TagIndexImmediate& imm) {
    size_t num_tags = module_->tags.size();
    if (!VALIDATE(imm.index < num_tags)) {
      DecodeError(pc, "Invalid tag index: %u", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_tags);
    imm.tag = &module_->tags[imm.index];
    return true;
  }

  bool Validate(const uint8_t* pc, GlobalIndexImmediate& imm) {
    // We compare with the current size of the globals vector. This is important
    // if we are decoding a constant expression in the global section.
    size_t num_globals = module_->globals.size();
    if (!VALIDATE(imm.index < num_globals)) {
      DecodeError(pc, "Invalid global index: %u", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_globals);
    imm.global = &module_->globals[imm.index];
    if (!VALIDATE(!is_shared_ || imm.global->shared)) {
      DecodeError(pc, "Cannot access non-shared global %d in a shared %s",
                  imm.index,
                  decoding_mode == kConstantExpression ? "constant expression"
                                                       : "function");
      return false;
    }

    if constexpr (decoding_mode == kConstantExpression) {
      if (!VALIDATE(!imm.global->mutability)) {
        this->DecodeError(pc,
                          "mutable globals cannot be used in constant "
                          "expressions");
        return false;
      }
    }

    return true;
  }

  bool Validate(const uint8_t* pc, SigIndexImmediate& imm) {
    if (!VALIDATE(module_->has_signature(imm.index))) {
      DecodeError(pc, "invalid signature index: %u", imm.index.index);
      return false;
    }
    imm.sig = module_->signature(imm.index);
    return true;
  }

  bool Validate(const uint8_t* pc, StructIndexImmediate& imm) {
    if (!VALIDATE(module_->has_struct(imm.index))) {
      DecodeError(pc, "invalid struct index: %u", imm.index.index);
      return false;
    }
    imm.struct_type = module_->struct_type(imm.index);
    return true;
  }

  bool Validate(const uint8_t* pc, FieldImmediate& imm) {
    if (!Validate(pc, imm.struct_imm)) return false;
    if (!VALIDATE(imm.field_imm.index <
                  imm.struct_imm.struct_type->field_count())) {
      DecodeError(pc + imm.struct_imm.length, "invalid field index: %u",
                  imm.field_imm.index);
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, ArrayIndexImmediate& imm) {
    if (!VALIDATE(module_->has_array(imm.index))) {
      DecodeError(pc, "invalid array index: %u", imm.index.index);
      return false;
    }
    imm.array_type = module_->array_type(imm.index);
    return true;
  }

  bool CanReturnCall(const FunctionSig* target_sig) {
    if (sig_->return_count() != target_sig->return_count()) return false;
    auto target_sig_it = target_sig->returns().begin();
    for (ValueType ret_type : sig_->returns()) {
      if (!IsSubtypeOf(*target_sig_it++, ret_type, this->module_)) return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, CallFunctionImmediate& imm) {
    size_t num_functions = module_->functions.size();
    if (!VALIDATE(imm.index < num_functions)) {
      DecodeError(pc, "function index #%u is out of bounds", imm.index);
      return false;
    }
    if (is_shared_ && !module_->function_is_shared(imm.index)) {
      DecodeError(pc, "cannot call non-shared function %u", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_functions);
    imm.sig = module_->functions[imm.index].sig;
    return true;
  }

  bool Validate(const uint8_t* pc, CallIndirectImmediate& imm) {
    if (!Validate(pc, imm.sig_imm)) return false;
    if (!Validate(pc + imm.sig_imm.length, imm.table_imm)) return false;
    ValueType table_type = imm.table_imm.table->type;
    if (!VALIDATE(IsSubtypeOf(table_type, kWasmFuncRef, module_) ||
                  IsSubtypeOf(table_type,
                              ValueType::RefNull(HeapType::kFuncShared),
                              module_))) {
      DecodeError(
          pc, "call_indirect: immediate table #%u is not of a function type",
          imm.table_imm.index);
      return false;
    }
    // The type specified by the immediate does not need to have any static
    // relation (neither sub nor super) to the type of the table. The type
    // of the function will be checked at runtime.

    imm.sig = module_->signature(imm.sig_imm.index);
    return true;
  }

  bool Validate(const uint8_t* pc, BranchDepthImmediate& imm,
                size_t control_depth) {
    if (!VALIDATE(imm.depth < control_depth)) {
      DecodeError(pc, "invalid branch depth: %u", imm.depth);
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, BranchTableImmediate& imm) {
    if (!VALIDATE(imm.table_count <= kV8MaxWasmFunctionBrTableSize)) {
      DecodeError(pc, "invalid table count (> max br_table size): %u",
                  imm.table_count);
      return false;
    }
    return checkAvailable(imm.table_count);
  }

  bool Validate(const uint8_t* pc, WasmOpcode opcode, SimdLaneImmediate& imm) {
    uint8_t num_lanes = 0;
    switch (opcode) {
      case kExprF64x2ExtractLane:
      case kExprF64x2ReplaceLane:
      case kExprI64x2ExtractLane:
      case kExprI64x2ReplaceLane:
      case kExprS128Load64Lane:
      case kExprS128Store64Lane:
        num_lanes = 2;
        break;
      case kExprF32x4ExtractLane:
      case kExprF32x4ReplaceLane:
      case kExprI32x4ExtractLane:
      case kExprI32x4ReplaceLane:
      case kExprS128Load32Lane:
      case kExprS128Store32Lane:
        num_lanes = 4;
        break;
      case kExprF16x8ExtractLane:
      case kExprF16x8ReplaceLane:
      case kExprI16x8ExtractLaneS:
      case kExprI16x8ExtractLaneU:
      case kExprI16x8ReplaceLane:
      case kExprS128Load16Lane:
      case kExprS128Store16Lane:
        num_lanes = 8;
        break;
      case kExprI8x16ExtractLaneS:
      case kExprI8x16ExtractLaneU:
      case kExprI8x16ReplaceLane:
      case kExprS128Load8Lane:
      case kExprS128Store8Lane:
        num_lanes = 16;
        break;
      default:
        UNREACHABLE();
        break;
    }
    if (!VALIDATE(imm.lane >= 0 && imm.lane < num_lanes)) {
      DecodeError(pc, "invalid lane index");
      return false;
    } else {
      return true;
    }
  }

  bool Validate(const uint8_t* pc, Simd128Immediate& imm) {
    uint8_t max_lane = 0;
    for (uint32_t i = 0; i < kSimd128Size; ++i) {
      max_lane = std::max(max_lane, imm.value[i]);
    }
    // Shuffle indices must be in [0..31] for a 16 lane shuffle.
    if (!VALIDATE(max_lane < 2 * kSimd128Size)) {
      DecodeError(pc, "invalid shuffle mask");
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, BlockTypeImmediate& imm) {
    if (imm.sig.all().begin() == nullptr) {
      // Then use {sig_index} to initialize the signature.
      if (!VALIDATE(module_->has_signature(imm.sig_index))) {
        DecodeError(pc, "block type index %u is not a signature definition",
                    imm.sig_index);
        return false;
      }
      imm.sig = *module_->signature(imm.sig_index);
    } else {
      // Then it's an MVP immediate with 0 parameters and 0-1 returns.
      DCHECK_EQ(0, imm.sig.parameter_count());
      DCHECK_GE(1, imm.sig.return_count());
      if (imm.sig.return_count()) {
        if (!ValidateValueType(pc, imm.sig.GetReturn(0))) return false;
      }
    }
    return true;
  }

  bool Validate(const uint8_t* pc, MemoryIndexImmediate& imm) {
    size_t num_memories = module_->memories.size();
    if (imm.index > 0 || imm.length > 1) {
      this->detected_->add_multi_memory();
    }

    if (!VALIDATE(imm.index < num_memories)) {
      DecodeError(pc,
                  "memory index %u exceeds number of declared memories (%zu)",
                  imm.index, num_memories);
      return false;
    }

    V8_ASSUME(imm.index < num_memories);
    imm.memory = this->module_->memories.data() + imm.index;

    return true;
  }

  bool Validate(const uint8_t* pc, MemoryAccessImmediate& imm) {
    size_t num_memories = module_->memories.size();
    if (!VALIDATE(imm.mem_index < num_memories)) {
      DecodeError(pc,
                  "memory index %u exceeds number of declared memories (%zu)",
                  imm.mem_index, num_memories);
      return false;
    }
    if (!VALIDATE(this->module_->memories[imm.mem_index].is_memory64() ||
                  imm.offset <= kMaxUInt32)) {
      this->DecodeError(pc, "memory offset outside 32-bit range: %" PRIu64,
                        imm.offset);
      return false;
    }

    V8_ASSUME(imm.mem_index < num_memories);
    imm.memory = this->module_->memories.data() + imm.mem_index;

    return true;
  }

  bool Validate(const uint8_t* pc, MemoryInitImmediate& imm) {
    return ValidateDataSegment(pc, imm.data_segment) &&
           Validate(pc + imm.data_segment.length, imm.memory);
  }

  bool Validate(const uint8_t* pc, MemoryCopyImmediate& imm) {
    return Validate(pc, imm.memory_src) &&
           Validate(pc + imm.memory_src.length, imm.memory_dst);
  }

  bool Validate(const uint8_t* pc, TableInitImmediate& imm) {
    if (!ValidateElementSegment(pc, imm.element_segment)) return false;
    if (!Validate(pc + imm.element_segment.length, imm.table)) {
      return false;
    }
    ValueType elem_type =
        module_->elem_segments[imm.element_segment.index].type;
    if (!VALIDATE(IsSubtypeOf(elem_type, imm.table.table->type, module_))) {
      DecodeError(pc, "table %u is not a super-type of %s", imm.table.index,
                  elem_type.name().c_str());
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, TableCopyImmediate& imm) {
    if (!Validate(pc, imm.table_src)) return false;
    if (!Validate(pc + imm.table_src.length, imm.table_dst)) return false;
    ValueType src_type = imm.table_src.table->type;
    if (!VALIDATE(IsSubtypeOf(src_type, imm.table_dst.table->type, module_))) {
      DecodeError(pc, "table %u is not a super-type of %s", imm.table_dst.index,
                  src_type.name().c_str());
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, StringConstImmediate& imm) {
    if (!VALIDATE(imm.index < module_->stringref_literals.size())) {
      DecodeError(pc, "Invalid string literal index: %u", imm.index);
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, TableIndexImmediate& imm) {
    if (imm.index > 0 || imm.length > 1) {
      this->detected_->add_reftypes();
    }
    size_t num_tables = module_->tables.size();
    if (!VALIDATE(imm.index < num_tables)) {
      DecodeError(pc, "table index %u exceeds number of tables (%zu)",
                  imm.index, num_tables);
      return false;
    }
    imm.table = this->module_->tables.data() + imm.index;

    if (!VALIDATE(!is_shared_ || imm.table->shared)) {
      DecodeError(pc,
                  "cannot reference non-shared table %u from shared function",
                  imm.index);
      return false;
    }

    return true;
  }

  // The following Validate* functions all validate an `IndexImmediate`, albeit
  // differently according to context.
  bool ValidateElementSegment(const uint8_t* pc, IndexImmediate& imm) {
    size_t num_elem_segments = module_->elem_segments.size();
    if (!VALIDATE(imm.index < num_elem_segments)) {
      DecodeError(pc, "invalid element segment index: %u", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_elem_segments);
    if (!VALIDATE(!is_shared_ || module_->elem_segments[imm.index].shared)) {
      DecodeError(
          pc,
          "cannot reference non-shared element segment %u from shared function",
          imm.index);
      return false;
    }
    return true;
  }

  bool ValidateLocal(const uint8_t* pc, IndexImmediate& imm) {
    if (!VALIDATE(imm.index < num_locals())) {
      DecodeError(pc, "invalid local index: %u", imm.index);
      return false;
    }
    return true;
  }

  bool ValidateFunction(const uint8_t* pc, IndexImmediate& imm) {
    size_t num_functions = module_->functions.size();
    if (!VALIDATE(imm.index < num_functions)) {
      DecodeError(pc, "function index #%u is out of bounds", imm.index);
      return false;
    }
    V8_ASSUME(imm.index < num_functions);
    if (decoding_mode == kFunctionBody &&
        !VALIDATE(module_->functions[imm.index].declared)) {
      DecodeError(pc, "undeclared reference to function #%u", imm.index);
      return false;
    }
    return true;
  }

  bool ValidateDataSegment(const uint8_t* pc, IndexImmediate& imm) {
    if (!VALIDATE(imm.index < module_->num_declared_data_segments)) {
      DecodeError(pc, "invalid data segment index: %u", imm.index);
      return false;
    }
    // TODO(14616): Data segments aren't available during eager validation.
    // Discussion: github.com/WebAssembly/shared-everything-threads/issues/83
    if (!VALIDATE(!is_shared_ || module_->data_segments[imm.index].shared)) {
      DecodeError(
          pc, "cannot refer to non-shared segment %u from a shared function",
          imm.index);
      return false;
    }
    return true;
  }

  bool Validate(const uint8_t* pc, SelectTypeImmediate& imm) {
    return ValidateValueType(pc, imm.type);
  }

  bool Validate(const uint8_t* pc, HeapTypeImmediate& imm) {
    return ValidateHeapType(pc, imm.type);
  }

  bool ValidateValueType(const uint8_t* pc, ValueType type) {
    return value_type_reader::ValidateValueType<ValidationTag>(this, pc,
                                                               module_, type);
  }

  bool ValidateHeapType(const uint8_t* pc, HeapType type) {
    return value_type_reader::ValidateHeapType<ValidationTag>(this, pc, module_,
                                                              type);
  }

  // Returns the length of the opcode under {pc}.
  template <typename... ImmediateObservers>
  static uint32_t OpcodeLength(WasmDecoder* decoder, const uint8_t* pc,
                               ImmediateObservers&... ios) {
    WasmOpcode opcode = static_cast<WasmOpcode>(*pc);
    // We don't have information about the module here, so we just assume that
    // memory64 and multi-memory are enabled when parsing memory access
    // immediates. This is backwards-compatible; decode errors will be detected
    // at another time when actually decoding that opcode.
    constexpr bool kConservativelyAssumeMemory64 = true;
    switch (opcode) {
      /********** Control opcodes **********/
      case kExprUnreachable:
      case kExprNop:
      case kExprNopForTestingUnsupportedInLiftoff:
      case kExprElse:
      case kExprEnd:
      case kExprReturn:
        return 1;
      case kExprTry:
      case kExprIf:
      case kExprLoop:
      case kExprBlock: {
        BlockTypeImmediate imm(WasmEnabledFeatures::All(), decoder, pc + 1,
                               validate);
        (ios.BlockType(imm), ...);
        return 1 + imm.length;
      }
      case kExprRethrow:
      case kExprBr:
      case kExprBrIf:
      case kExprBrOnNull:
      case kExprBrOnNonNull:
      case kExprDelegate: {
        BranchDepthImmediate imm(decoder, pc + 1, validate);
        (ios.BranchDepth(imm), ...);
        return 1 + imm.length;
      }
      case kExprBrTable: {
        BranchTableImmediate imm(decoder, pc + 1, validate);
        (ios.BranchTable(imm), ...);
        BranchTableIterator<ValidationTag> iterator(decoder, imm);
        return 1 + iterator.length();
      }
      case kExprTryTable: {
        BlockTypeImmediate block_type_imm(WasmEnabledFeatures::All(), decoder,
                                          pc + 1, validate);
        (ios.BlockType(block_type_imm), ...);
        TryTableImmediate try_table_imm(decoder, pc + 1 + block_type_imm.length,
                                        validate);
        (ios.TryTable(try_table_imm), ...);
        TryTableIterator<ValidationTag> iterator(decoder, try_table_imm);
        return 1 + block_type_imm.length + iterator.length();
      }
      case kExprThrow:
      case kExprCatch: {
        TagIndexImmediate imm(decoder, pc + 1, validate);
        (ios.TagIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprThrowRef:
        return 1;

      /********** Misc opcodes **********/
      case kExprCallFunction:
      case kExprReturnCall: {
        CallFunctionImmediate imm(decoder, pc + 1, validate);
        (ios.FunctionIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprCallIndirect:
      case kExprReturnCallIndirect: {
        CallIndirectImmediate imm(decoder, pc + 1, validate);
        (ios.CallIndirect(imm), ...);
        return 1 + imm.length;
      }
      case kExprCallRef:
      case kExprReturnCallRef: {
        SigIndexImmediate imm(decoder, pc + 1, validate);
        (ios.TypeIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprDrop:
      case kExprSelect:
      case kExprCatchAll:
      case kExprRefEq:
        return 1;
      case kExprSelectWithType: {
        SelectTypeImmediate imm(WasmEnabledFeatures::All(), decoder, pc + 1,
                                validate);
        (ios.SelectType(imm), ...);
        return 1 + imm.length;
      }

      case kExprLocalGet:
      case kExprLocalSet:
      case kExprLocalTee: {
        IndexImmediate imm(decoder, pc + 1, "local index", validate);
        (ios.LocalIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprGlobalGet:
      case kExprGlobalSet: {
        GlobalIndexImmediate imm(decoder, pc + 1, validate);
        (ios.GlobalIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprTableGet:
      case kExprTableSet: {
        TableIndexImmediate imm(decoder, pc + 1, validate);
        (ios.TableIndex(imm), ...);
        return 1 + imm.length;
      }
      case kExprI32Const: {
        ImmI32Immediate imm(decoder, pc + 1, validate);
        (ios.I32Const(imm), ...);
        return 1 + imm.length;
      }
      case kExprI64Const: {
        ImmI64Immediate imm(decoder, pc + 1, validate);
        (ios.I64Const(imm), ...);
        return 1 + imm.length;
      }
      case kExprF32Const:
        if (sizeof...(ios) > 0) {
          ImmF32Immediate imm(decoder, pc + 1, validate);
          (ios.F32Const(imm), ...);
        }
        return 5;
      case kExprF64Const:
        if (sizeof...(ios) > 0) {
          ImmF64Immediate imm(decoder, pc + 1, validate);
          (ios.F64Const(imm), ...);
        }
        return 9;
      case kExprRefNull: {
        HeapTypeImmediate imm(WasmEnabledFeatures::All(), decoder, pc + 1,
                              validate);
        (ios.HeapType(imm), ...);
        return 1 + imm.length;
      }
      case kExprRefIsNull:
      case kExprRefAsNonNull:
        return 1;
      case kExprRefFunc: {
        IndexImmediate imm(decoder, pc + 1, "function index", validate);
        (ios.FunctionIndex(imm), ...);
        return 1 + imm.length;
      }

#define DECLARE_OPCODE_CASE(name, ...) case kExpr##name:
        // clang-format off
      /********** Simple and memory opcodes **********/
      FOREACH_SIMPLE_OPCODE(DECLARE_OPCODE_CASE)
      FOREACH_SIMPLE_PROTOTYPE_OPCODE(DECLARE_OPCODE_CASE)
        return 1;
      FOREACH_LOAD_MEM_OPCODE(DECLARE_OPCODE_CASE)
      FOREACH_STORE_MEM_OPCODE(DECLARE_OPCODE_CASE) {
        MemoryAccessImmediate imm(decoder, pc + 1, UINT32_MAX,
                                  kConservativelyAssumeMemory64,
                                  validate);
        (ios.MemoryAccess(imm), ...);
        return 1 + imm.length;
      }
      // clang-format on
      case kExprMemoryGrow:
      case kExprMemorySize: {
        MemoryIndexImmediate imm(decoder, pc + 1, validate);
        (ios.MemoryIndex(imm), ...);
        return 1 + imm.length;
      }

      /********** Prefixed opcodes **********/
      case kNumericPrefix: {
        uint32_t length;
        std::tie(opcode, length) =
            decoder->read_prefixed_opcode<ValidationTag>(pc);
        switch (opcode) {
          case kExprI32SConvertSatF32:
          case kExprI32UConvertSatF32:
          case kExprI32SConvertSatF64:
          case kExprI32UConvertSatF64:
          case kExprI64SConvertSatF32:
          case kExprI64UConvertSatF32:
          case kExprI64SConvertSatF64:
          case kExprI64UConvertSatF64:
            return length;
          case kExprMemoryInit: {
            MemoryInitImmediate imm(decoder, pc + length, validate);
            (ios.MemoryInit(imm), ...);
            return length + imm.length;
          }
          case kExprDataDrop: {
            IndexImmediate imm(decoder, pc + length, "data segment index",
                               validate);
            (ios.DataSegmentIndex(imm), ...);
            return length + imm.length;
          }
          case kExprMemoryCopy: {
            MemoryCopyImmediate imm(decoder, pc + length, validate);
            (ios.MemoryCopy(imm), ...);
            return length + imm.length;
          }
          case kExprMemoryFill: {
            MemoryIndexImmediate imm(decoder, pc + length, validate);
            (ios.MemoryIndex(imm), ...);
            return length + imm.length;
          }
          case kExprTableInit: {
            TableInitImmediate imm(decoder, pc + length, validate);
            (ios.TableInit(imm), ...);
            return length + imm.length;
          }
          case kExprElemDrop: {
            IndexImmediate imm(decoder, pc + length, "element segment index",
                               validate);
            (ios.ElemSegmentIndex(imm), ...);
            return length + imm.length;
          }
          case kExprTableCopy: {
            TableCopyImmediate imm(decoder, pc + length, validate);
            (ios.TableCopy(imm), ...);
            return length + imm.length;
          }
          case kExprTableGrow:
          case kExprTableSize:
          case kExprTableFill: {
            TableIndexImmediate imm(decoder, pc + length, validate);
            (ios.TableIndex(imm), ...);
            return length + imm.length;
          }
          case kExprF32LoadMemF16:
          case kExprF32StoreMemF16: {
            MemoryAccessImmediate imm(decoder, pc + length, UINT32_MAX,
                                      kConservativelyAssumeMemory64, validate);
            (ios.MemoryAccess(imm), ...);
            return length + imm.length;
          }
          default:
            // This path is only possible if we are validating.
            V8_ASSUME(ValidationTag::validate);
            decoder->DecodeError(pc, "invalid numeric opcode");
            return length;
        }
      }
      case kSimdPrefix: {
        uint32_t length;
        std::tie(opcode, length) =
            decoder->read_prefixed_opcode<ValidationTag>(pc);
        switch (opcode) {
          // clang-format off
          FOREACH_SIMD_0_OPERAND_OPCODE(DECLARE_OPCODE_CASE)
            return length;
          FOREACH_SIMD_1_OPERAND_OPCODE(DECLARE_OPCODE_CASE)
        if (sizeof...(ios) > 0) {
              SimdLaneImmediate lane_imm(decoder, pc + length, validate);
             (ios.SimdLane(lane_imm), ...);
            }
            return length + 1;
          FOREACH_SIMD_MEM_OPCODE(DECLARE_OPCODE_CASE) {
            MemoryAccessImmediate imm(decoder, pc + length, UINT32_MAX,
                                      kConservativelyAssumeMemory64,
                                      validate);
            (ios.MemoryAccess(imm), ...);
            return length + imm.length;
          }
          FOREACH_SIMD_MEM_1_OPERAND_OPCODE(DECLARE_OPCODE_CASE) {
            MemoryAccessImmediate imm(
                decoder, pc + length, UINT32_MAX,
                kConservativelyAssumeMemory64,
                validate);
        if (sizeof...(ios) > 0) {
              SimdLaneImmediate lane_imm(decoder,
                                         pc + length + imm.length, validate);
             (ios.MemoryAccess(imm), ...);
             (ios.SimdLane(lane_imm), ...);
            }
            // 1 more byte for lane index immediate.
            return length + imm.length + 1;
          }
          // clang-format on
          // Shuffles require a byte per lane, or 16 immediate bytes.
          case kExprS128Const:
          case kExprI8x16Shuffle:
            if (sizeof...(ios) > 0) {
              Simd128Immediate imm(decoder, pc + length, validate);
              (ios.S128Const(imm), ...);
            }
            return length + kSimd128Size;
          default:
            // This path is only possible if we are validating.
            V8_ASSUME(ValidationTag::validate);
            decoder->DecodeError(pc, "invalid SIMD opcode");
            return length;
        }
      }
      case kAtomicPrefix: {
        uint32_t length;
        std::tie(opcode, length) =
            decoder->read_prefixed_opcode<ValidationTag>(pc, "atomic_index");
        switch (opcode) {
          FOREACH_ATOMIC_OPCODE(DECLARE_OPCODE_CASE) {
            MemoryAccessImmediate imm(decoder, pc + length, UINT32_MAX,
                                      kConservativelyAssumeMemory64, validate);
            (ios.MemoryAccess(imm), ...);
            return length + imm.length;
          }
          FOREACH_ATOMIC_0_OPERAND_OPCODE(DECLARE_OPCODE_CASE) {
            // One unused zero-byte.
            return length + 1;
          }
          default:
            // This path is only possible if we are validating.
            V8_ASSUME(ValidationTag::validate);
            decoder->DecodeError(pc, "invalid Atomics opcode");
            return length;
        }
      }
      case kGCPrefix: {
        uint32_t length;
        std::tie(opcode, length) =
            decoder->read_prefixed_opcode<ValidationTag>(pc, "gc_index");
        switch (opcode) {
          case kExprStructNew:
          case kExprStructNewDefault: {
            StructIndexImmediate imm(decoder, pc + length, validate);
            (ios.TypeIndex(imm), ...);
            return length + imm.length;
          }
          case kExprStructGet:
          case kExprStructGetS:
          case kExprStructGetU:
          case kExprStructSet: {
            FieldImmediate imm(decoder, pc + length, validate);
            (ios.Field(imm), ...);
            return length + imm.length;
          }
          case kExprArrayNew:
          case kExprArrayNewDefault:
          case kExprArrayGet:
          case kExprArrayGetS:
          case kExprArrayGetU:
          case kExprArraySet: {
            ArrayIndexImmediate imm(decoder, pc + length, validate);
            (ios.TypeIndex(imm), ...);
            return length + imm.length;
          }
          case kExprArrayNewFixed: {
            ArrayIndexImmediate array_imm(decoder, pc + length, validate);
            IndexImmediate length_imm(decoder, pc + length + array_imm.length,
                                      "array length", validate);
            (ios.TypeIndex(array_imm), ...);
            (ios.Length(length_imm), ...);
            return length + array_imm.length + length_imm.length;
          }
          case kExprArrayCopy: {
            ArrayIndexImmediate dst_imm(decoder, pc + length, validate);
            ArrayIndexImmediate src_imm(decoder, pc + length + dst_imm.length,
                                        validate);
            (ios.ArrayCopy(dst_imm, src_imm), ...);
            return length + dst_imm.length + src_imm.length;
          }
          case kExprArrayFill: {
            ArrayIndexImmediate imm(decoder, pc + length, validate);
            (ios.TypeIndex(imm), ...);
            return length + imm.length;
          }
          case kExprArrayNewData:
          case kExprArrayNewElem:
          case kExprArrayInitData:
          case kExprArrayInitElem: {
            ArrayIndexImmediate array_imm(decoder, pc + length, validate);
            IndexImmediate data_imm(decoder, pc + length + array_imm.length,
                                    "segment index", validate);
            (ios.TypeIndex(array_imm), ...);
            (ios.DataSegmentIndex(data_imm), ...);
            return length + array_imm.length + data_imm.length;
          }
          case kExprRefCast:
          case kExprRefCastNull:
          case kExprRefCastNop:
          case kExprRefTest:
          case kExprRefTestNull: {
            HeapTypeImmediate imm(WasmEnabledFeatures::All(), decoder,
                                  pc + length, validate);
            (ios.HeapType(imm), ...);
            return length + imm.length;
          }
          case kExprBrOnCast:
          case kExprBrOnCastFail: {
            BrOnCastImmediate flags_imm(decoder, pc + length, validate);
            BranchDepthImmediate branch(decoder, pc + length + flags_imm.length,
                                        validate);
            HeapTypeImmediate source_imm(
                WasmEnabledFeatures::All(), decoder,
                pc + length + flags_imm.length + branch.length, validate);
            HeapTypeImmediate target_imm(WasmEnabledFeatures::All(), decoder,
                                         pc + length + flags_imm.length +
                                             branch.length + source_imm.length,
                                         validate);
            (ios.BrOnCastFlags(flags_imm), ...);
            (ios.BranchDepth(branch), ...);
            // This code has grown historically (while the GC proposal's design
            // evolved), but it's convenient: for the text format, we want to
            // pretend that we have two ValueTypes; whereas the mjsunit
            // module builder format cares only about the encapsulated
            // HeapTypes (and the raw flags value, see callback above).
            (ios.ValueType(source_imm, flags_imm.flags.src_is_null), ...);
            (ios.ValueType(target_imm, flags_imm.flags.res_is_null), ...);
            return length + flags_imm.length + branch.length +
                   source_imm.length + target_imm.length;
          }
          case kExprRefI31:
          case kExprI31GetS:
          case kExprI31GetU:
          case kExprAnyConvertExtern:
          case kExprExternConvertAny:
          case kExprArrayLen:
            return length;
          case kExprStringNewUtf8:
          case kExprStringNewUtf8Try:
          case kExprStringNewLossyUtf8:
          case kExprStringNewWtf8:
          case kExprStringEncodeUtf8:
          case kExprStringEncodeLossyUtf8:
          case kExprStringEncodeWtf8:
          case kExprStringViewWtf8EncodeUtf8:
          case kExprStringViewWtf8EncodeLossyUtf8:
          case kExprStringViewWtf8EncodeWtf8:
          case kExprStringNewWtf16:
          case kExprStringEncodeWtf16:
          case kExprStringViewWtf16Encode: {
            MemoryI
```