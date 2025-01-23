Response:
The user wants a summary of the functionality of the provided C++ code snippet. I need to analyze the code and identify its key responsibilities within the V8 WebAssembly Turboshaft compiler.

Here's a breakdown of the thought process:

1. **Identify the Core Function:** The code is within `v8/src/wasm/turboshaft-graph-interface.cc`, indicating it's part of the Turboshaft compiler for WebAssembly. The name "graph-interface" suggests it deals with the interface between the compiler and the graph representation of the code.

2. **Analyze Key Functions and Methods:** I'll scan the code for prominent functions and their actions. This includes:
    * `BuildAsmjsI32Op`: Handles specific integer operations with Asm.js semantics. This likely involves translating Asm.js integer operations into lower-level Turboshaft graph operations, including handling edge cases like division by zero and modulo with negative numbers.
    * `BoundsCheckMem`: Deals with memory access bounds checking. It seems to determine the necessary checks based on memory type, configuration, and whether trap handlers are used.
    * `MemStart`, `MemBuffer`, `MemSize`: These seem to be utilities for calculating memory addresses and sizes within the WebAssembly instance. They handle different memory indexing scenarios.
    * `GetMemoryAccessKind`: Determines the appropriate type of memory access operation based on bounds checking and memory representation.
    * `TraceMemoryOperation`:  Likely for debugging and profiling, tracing memory accesses during execution.
    * `StackCheck`: Implements stack overflow checks.
    * `BuildImportedFunctionTargetAndImplicitArg`, `BuildIndirectCallTargetAndImplicitArg`, `BuildFunctionReferenceTargetAndImplicitArg`: These functions handle the resolution of function call targets for different call types (imported, indirect, and through function references), including signature verification.
    * `BuildWasmCall`, `BuildWasmMaybeReturnCall`: Generate the necessary graph nodes for WebAssembly function calls, handling both regular calls and tail calls.
    * `CallBuiltinThroughJumptable`:  Handles calls to built-in functions via a jump table.
    * `CallAndMaybeCatchException`:  Wraps call operations and handles potential exceptions, especially important for WebAssembly's structured exception handling.
    * `CallCStackSlotToInt32`, `CallCStackSlotToStackSlot`: Methods for calling C functions, likely for interacting with the V8 runtime or external libraries. They manage stack allocation for arguments.
    * `MemOrTableAddressToUintPtrOrOOBTrap`: Converts memory or table addresses to usable pointers while ensuring they are within bounds, triggering traps if necessary.

3. **Identify Patterns and Themes:** Several recurring themes emerge:
    * **Memory Management and Safety:**  A significant portion of the code is dedicated to memory access, bounds checking, and alignment.
    * **Function Calls:** Handling different types of function calls (direct, indirect, imported) is a core function.
    * **Asm.js Support:**  Specific handling for Asm.js integer operations is present.
    * **Error Handling:** The code deals with potential runtime errors like out-of-bounds access, signature mismatches, and null dereferences, often using traps.
    * **Integration with V8 Runtime:**  Calls to runtime functions and access to internal V8 data structures are evident.

4. **Consider Specific Instructions:**  The `switch` statement in `BuildAsmjsI32Op` handles individual Asm.js integer operations. Understanding the semantics of operations like `kExprI32AsmjsDivS` and `kExprI32AsmjsRemU` provides insight into the function's purpose.

5. **Relate to JavaScript (if applicable):**  While this code is primarily about WebAssembly compilation, there's a connection to JavaScript through the Asm.js subset. Asm.js code has a defined relationship with corresponding JavaScript.

6. **Address Potential Programming Errors:**  The bounds checking and trap mechanisms directly address common programming errors in languages like C/C++ that involve manual memory management. Integer overflow and division by zero are also explicitly handled in the Asm.js section.

7. **Consider the ".tq" Extension:** The prompt mentions a `.tq` extension, indicating Torque. Since this file is `.cc`, the prompt is probing understanding of V8's build system and different source file types. This file is *not* a Torque file.

8. **Synthesize a Summary:**  Combine the observations into a concise summary of the file's purpose.

9. **Structure the Response:** Organize the information according to the user's request, covering functionality, JavaScript relation, code logic, common errors, and a final summary.
```cpp
2Div(lhs, rhs));
          }
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsDivU: {
        // asmjs semantics return 0 when dividing by 0.
        if (SupportedOperations::uint32_div_is_safe()) {
          return __ Uint32Div(lhs, rhs);
        }
        Label<Word32> done(&asm_);
        IF (UNLIKELY(__ Word32Equal(rhs, 0))) {
          GOTO(done, __ Word32Constant(0));
        } ELSE {
          GOTO(done, __ Uint32Div(lhs, rhs));
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsRemS: {
        // General case for signed integer modulus, with optimization for
        // (unknown) power of 2 right hand side.
        //
        //   if 0 < rhs then
        //     mask = rhs - 1
        //     if rhs & mask != 0 then
        //       lhs % rhs
        //     else
        //       if lhs < 0 then
        //         -(-lhs & mask)
        //       else
        //         lhs & mask
        //   else
        //     if rhs < -1 then
        //       lhs % rhs
        //     else
        //       zero
        Label<Word32> done(&asm_);
        IF (__ Int32LessThan(0, rhs)) {
          V<Word32> mask = __ Word32Sub(rhs, 1);
          IF (__ Word32Equal(__ Word32BitwiseAnd(rhs, mask), 0)) {
            IF (UNLIKELY(__ Int32LessThan(lhs, 0))) {
              V<Word32> neg_lhs = __ Word32Sub(0, lhs);
              V<Word32> combined = __ Word32BitwiseAnd(neg_lhs, mask);
              GOTO(done, __ Word32Sub(0, combined));
            } ELSE {
              GOTO(done, __ Word32BitwiseAnd(lhs, mask));
            }
          } ELSE {
            GOTO(done, __ Int32Mod(lhs, rhs));
          }
        } ELSE {
          IF (__ Int32LessThan(rhs, -1)) {
            GOTO(done, __ Int32Mod(lhs, rhs));
          } ELSE {
            GOTO(done, __ Word32Constant(0));
          }
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsRemU: {
        // asmjs semantics return 0 for mod with 0.
        Label<Word32> done(&asm_);
        IF (UNLIKELY(__ Word32Equal(rhs, 0))) {
          GOTO(done, __ Word32Constant(0));
        } ELSE {
          GOTO(done, __ Uint32Mod(lhs, rhs));
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsStoreMem8:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int8());
        return rhs;
      case kExprI32AsmjsStoreMem16:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int16());
        return rhs;
      case kExprI32AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int32());
        return rhs;
      case kExprF32AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Float32());
        return rhs;
      case kExprF64AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Float64());
        return rhs;
      default:
        UNREACHABLE();
    }
  }

  std::pair<V<WordPtr>, compiler::BoundsCheckResult> BoundsCheckMem(
      const wasm::WasmMemory* memory, MemoryRepresentation repr, OpIndex index,
      uintptr_t offset, compiler::EnforceBoundsCheck enforce_bounds_check,
      compiler::AlignmentCheck alignment_check) {
    // The function body decoder already validated that the access is not
    // statically OOB.
    DCHECK(base::IsInBounds(offset, static_cast<uintptr_t>(repr.SizeInBytes()),
                            memory->max_memory_size));

    wasm::BoundsCheckStrategy bounds_checks = memory->bounds_checks;
    // Convert the index to uintptr.
    // TODO(jkummerow): This should reuse MemoryAddressToUintPtrOrOOBTrap.
    V<WordPtr> converted_index = index;
    if (!memory->is_memory64()) {
      // Note: this doesn't just satisfy the compiler's internal consistency
      // checks, it's also load-bearing to prevent escaping from a compromised
      // sandbox (where in-sandbox corruption can cause the high word of
      // what's supposed to be an i32 to be non-zero).
      converted_index = __ ChangeUint32ToUintPtr(index);
    } else if (kSystemPointerSize == kInt32Size) {
      // Truncate index to 32-bit.
      converted_index = V<WordPtr>::Cast(__ TruncateWord64ToWord32(index));
    }

    const uintptr_t align_mask = repr.SizeInBytes() - 1;
    // Do alignment checks only for > 1 byte accesses (otherwise they trivially
    // pass).
    if (static_cast<bool>(alignment_check) && align_mask != 0) {
      // TODO(14108): Optimize constant index as per wasm-compiler.cc.

      // Unlike regular memory accesses, atomic memory accesses should trap if
      // the effective offset is misaligned.
      // TODO(wasm): this addition is redundant with one inserted by
      // {MemBuffer}.
      OpIndex effective_offset =
          __ WordPtrAdd(MemBuffer(memory->index, offset), converted_index);

      V<Word32> cond = __ TruncateWordPtrToWord32(__ WordPtrBitwiseAnd(
          effective_offset, __ IntPtrConstant(align_mask)));
      __ TrapIfNot(__ Word32Equal(cond, __ Word32Constant(0)),
                   TrapId::kTrapUnalignedAccess);
    }

    // If no bounds checks should be performed (for testing), just return the
    // converted index and assume it to be in-bounds.
    if (bounds_checks == wasm::kNoBoundsChecks) {
      return {converted_index, compiler::BoundsCheckResult::kInBounds};
    }

    if (memory->is_memory64() && kSystemPointerSize == kInt32Size) {
      // In memory64 mode on 32-bit systems, the upper 32 bits need to be zero
      // to succeed the bounds check.
      DCHECK_EQ(kExplicitBoundsChecks, bounds_checks);
      V<Word32> high_word =
          __ TruncateWord64ToWord32(__ Word64ShiftRightLogical(index, 32));
      __ TrapIf(high_word, TrapId::kTrapMemOutOfBounds);
    }

    uintptr_t end_offset = offset + repr.SizeInBytes() - 1u;
    DCHECK_LT(end_offset, memory->max_memory_size);

    // The index can be invalid if we are generating unreachable operations.
    if (end_offset <= memory->min_memory_size && index.valid() &&
        __ output_graph().Get(index).Is<ConstantOp>()) {
      ConstantOp& constant_index_op =
          __ output_graph().Get(index).Cast<ConstantOp>();
      uintptr_t constant_index = memory->is_memory64()
                                     ? constant_index_op.word64()
                                     : constant_index_op.word32();
      if (constant_index < memory->min_memory_size - end_offset) {
        return {converted_index, compiler::BoundsCheckResult::kInBounds};
      }
    }

#if V8_TRAP_HANDLER_SUPPORTED
    if (bounds_checks == kTrapHandler &&
        enforce_bounds_check ==
            compiler::EnforceBoundsCheck::kCanOmitBoundsCheck) {
      if (memory->is_memory64()) {
        // Bounds check `index` against `max_mem_size - end_offset`, such that
        // at runtime `index + end_offset` will be within `max_mem_size`, where
        // the trap handler can handle out-of-bound accesses.
        V<Word32> cond = __ Uint64LessThan(
            V<Word64>::Cast(converted_index),
            __ Word64Constant(uint64_t{memory->max_memory_size - end_offset}));
        __ TrapIfNot(cond, TrapId::kTrapMemOutOfBounds);
      }
      return {converted_index, compiler::BoundsCheckResult::kTrapHandler};
    }
#else
    CHECK_NE(bounds_checks, kTrapHandler);
#endif  // V8_TRAP_HANDLER_SUPPORTED

    V<WordPtr> memory_size = MemSize(memory->index);
    if (end_offset > memory->min_memory_size) {
      // The end offset is larger than the smallest memory.
      // Dynamically check the end offset against the dynamic memory size.
      __ TrapIfNot(
          __ UintPtrLessThan(__ UintPtrConstant(end_offset), memory_size),
          TrapId::kTrapMemOutOfBounds);
    }

    // This produces a positive number since {end_offset <= min_size <=
    // mem_size}.
    V<WordPtr> effective_size = __ WordPtrSub(memory_size, end_offset);
    __ TrapIfNot(__ UintPtrLessThan(converted_index, effective_size),
                 TrapId::kTrapMemOutOfBounds);
    return {converted_index, compiler::BoundsCheckResult::kDynamicallyChecked};
  }

  V<WordPtr> MemStart(uint32_t index) {
    if (index == 0) {
      // TODO(14108): Port TF's dynamic "cached_memory_index" infrastructure.
      return instance_cache_.memory0_start();
    } else {
      // TODO(14616): Fix sharedness.
      V<TrustedFixedAddressArray> instance_memories =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(trusted_instance_data(false),
                                                  MemoryBasesAndSizes,
                                                  TrustedFixedAddressArray);
      return __ Load(instance_memories, LoadOp::Kind::TaggedBase(),
                     MemoryRepresentation::UintPtr(),
                     TrustedFixedAddressArray::OffsetOfElementAt(2 * index));
    }
  }

  V<WordPtr> MemBuffer(uint32_t mem_index, uintptr_t offset) {
    V<WordPtr> mem_start = MemStart(mem_index);
    if (offset == 0) return mem_start;
    return __ WordPtrAdd(mem_start, offset);
  }

  V<WordPtr> MemSize(uint32_t index) {
    if (index == 0) {
      // TODO(14108): Port TF's dynamic "cached_memory_index" infrastructure.
      return instance_cache_.memory0_size();
    } else {
      // TODO(14616): Fix sharedness.
      V<TrustedByteArray> instance_memories =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(trusted_instance_data(false),
                                                  MemoryBasesAndSizes,
                                                  TrustedByteArray);
      return __ Load(
          instance_memories, LoadOp::Kind::TaggedBase().NotLoadEliminable(),
          MemoryRepresentation::UintPtr(),
          TrustedFixedAddressArray::OffsetOfElementAt(2 * index + 1));
    }
  }

  LoadOp::Kind GetMemoryAccessKind(
      MemoryRepresentation repr,
      compiler::BoundsCheckResult bounds_check_result) {
    LoadOp::Kind result;
    if (bounds_check_result == compiler::BoundsCheckResult::kTrapHandler) {
      DCHECK(repr == MemoryRepresentation::Int8() ||
             repr == MemoryRepresentation::Uint8() ||
             SupportedOperations::IsUnalignedLoadSupported(repr));
      result = LoadOp::Kind::Protected();
    } else if (repr != MemoryRepresentation::Int8() &&
               repr != MemoryRepresentation::Uint8() &&
               !SupportedOperations::IsUnalignedLoadSupported(repr)) {
      result = LoadOp::Kind::RawUnaligned();
    } else {
      result = LoadOp::Kind::RawAligned();
    }
    return result.NotLoadEliminable();
  }

  void TraceMemoryOperation(FullDecoder* decoder, bool is_store,
                            MemoryRepresentation repr, V<WordPtr> index,
                            uintptr_t offset) {
    int kAlign = 4;  // Ensure that the LSB is 0, like a Smi.
    V<WordPtr> info = __ StackSlot(sizeof(MemoryTracingInfo), kAlign);
    V<WordPtr> effective_offset = __ WordPtrAdd(index, offset);
    __ Store(info, effective_offset, StoreOp::Kind::RawAligned(),
             MemoryRepresentation::UintPtr(), compiler::kNoWriteBarrier,
             offsetof(MemoryTracingInfo, offset));
    __ Store(info, __ Word32Constant(is_store ? 1 : 0),
             StoreOp::Kind::RawAligned(), MemoryRepresentation::Uint8(),
             compiler::kNoWriteBarrier, offsetof(MemoryTracingInfo, is_store));
    V<Word32> rep_as_int = __ Word32Constant(
        static_cast<int>(repr.ToMachineType().representation()));
    __ Store(info, rep_as_int, StoreOp::Kind::RawAligned(),
             MemoryRepresentation::Uint8(), compiler::kNoWriteBarrier,
             offsetof(MemoryTracingInfo, mem_rep));
    CallRuntime(decoder->zone(), Runtime::kWasmTraceMemory, {info},
                __ NoContextConstant());
  }

  void StackCheck(WasmStackCheckOp::Kind kind, FullDecoder* decoder) {
    if (V8_UNLIKELY(!v8_flags.wasm_stack_checks)) return;
    __ WasmStackCheck(kind);
  }

 private:
  std::pair<V<WasmCodePtr>, V<HeapObject>>
  BuildImportedFunctionTargetAndImplicitArg(FullDecoder* decoder,
                                            uint32_t function_index) {
    ModuleTypeIndex sig_index =
        decoder->module_->functions[function_index].sig_index;
    bool shared = decoder->module_->type(sig_index).is_shared;
    return WasmGraphBuilderBase::BuildImportedFunctionTargetAndImplicitArg(
        function_index, trusted_instance_data(shared));
  }

  // Returns the call target and the implicit argument (WasmTrustedInstanceData
  // or WasmImportData) for an indirect call.
  std::pair<V<WasmCodePtr>, V<ExposedTrustedObject>>
  BuildIndirectCallTargetAndImplicitArg(FullDecoder* decoder,
                                        V<WordPtr> index_wordptr,
                                        CallIndirectImmediate imm,
                                        bool needs_type_or_null_check = true) {
    static_assert(kV8MaxWasmTableSize < size_t{kMaxInt});
    const WasmTable* table = imm.table_imm.table;

    /* Step 1: Load the indirect function tables for this table. */
    V<WasmDispatchTable> dispatch_table;
    if (imm.table_imm.index == 0) {
      dispatch_table =
          LOAD_PROTECTED_INSTANCE_FIELD(trusted_instance_data(table->shared),
                                        DispatchTable0, WasmDispatchTable);
    } else {
      V<ProtectedFixedArray> dispatch_tables =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(
              trusted_instance_data(table->shared), DispatchTables,
              ProtectedFixedArray);
      dispatch_table =
          V<WasmDispatchTable>::Cast(__ LoadProtectedFixedArrayElement(
              dispatch_tables, imm.table_imm.index));
    }

    /* Step 2: Bounds check against the table size. */
    V<Word32> table_length;
    bool needs_dynamic_size =
        !table->has_maximum_size || table->maximum_size != table->initial_size;
    if (needs_dynamic_size) {
      table_length = __ LoadField<Word32>(
          dispatch_table, AccessBuilder::ForWasmDispatchTableLength());
    } else {
      table_length = __ Word32Constant(table->initial_size);
    }
    V<Word32> in_bounds = __ UintPtrLessThan(
        index_wordptr, __ ChangeUint32ToUintPtr(table_length));
    __ TrapIfNot(in_bounds, TrapId::kTrapTableOutOfBounds);

    /* Step 3: Check the canonical real signature against the canonical declared
     * signature. */
    ModuleTypeIndex sig_index = imm.sig_imm.index;
    bool needs_type_check =
        needs_type_or_null_check &&
        !EquivalentTypes(table->type.AsNonNull(), ValueType::Ref(sig_index),
                         decoder->module_, decoder->module_);
    bool needs_null_check =
        needs_type_or_null_check && table->type.is_nullable();

    V<WordPtr> dispatch_table_entry_offset = __ WordPtrAdd(
        __ WordPtrMul(index_wordptr, WasmDispatchTable::kEntrySize),
        WasmDispatchTable::kEntriesOffset);

    if (needs_type_check) {
      CanonicalTypeIndex sig_id = env_->module->canonical_sig_id(sig_index);
      V<Word32> expected_canonical_sig =
          __ RelocatableWasmCanonicalSignatureId(sig_id.index);

      V<Word32> loaded_sig =
          __ Load(dispatch_table, dispatch_table_entry_offset,
                  LoadOp::Kind::TaggedBase(), MemoryRepresentation::Uint32(),
                  WasmDispatchTable::kSigBias);
      V<Word32> sigs_match = __ Word32Equal(expected_canonical_sig, loaded_sig);
      if (!decoder->module_->type(sig_index).is_final) {
        // In this case, a full type check is needed.
        Label<> end(&asm_);

        // First, check if signatures happen to match exactly.
        GOTO_IF(sigs_match, end);

        if (needs_null_check) {
          // Trap on null element.
          __ TrapIf(__ Word32Equal(loaded_sig, -1),
                    TrapId::kTrapFuncSigMismatch);
        }
        bool shared = decoder->module_->type(sig_index).is_shared;
        V<Map> formal_rtt = __ RttCanon(managed_object_maps(shared), sig_index);
        int rtt_depth = GetSubtypingDepth(decoder->module_, sig_index);
        DCHECK_GE(rtt_depth, 0);

        // Since we have the canonical index of the real rtt, we have to load it
        // from the isolate rtt-array (which is canonically indexed). Since this
        // reference is weak, we have to promote it to a strong reference.
        // Note: The reference cannot have been cleared: Since the loaded_sig
        // corresponds to a function of the same canonical type, that function
        // will have kept the type alive.
        V<WeakFixedArray> rtts = LOAD_ROOT(WasmCanonicalRtts);
        V<Object> weak_rtt = __ Load(
            rtts, __ ChangeInt32ToIntPtr(loaded_sig),
            LoadOp::Kind::TaggedBase(), MemoryRepresentation::TaggedPointer(),
            OFFSET_OF_DATA_START(WeakFixedArray), kTaggedSizeLog2);
        V<Map> real_rtt =
            V<Map>::Cast(__ BitcastWordPtrToTagged(__ WordPtrBitwiseAnd(
                __ BitcastHeapObjectToWordPtr(V<HeapObject>::Cast(weak_rtt)),
                ~kWeakHeapObjectMask)));
        V<WasmTypeInfo> type_info =
            __ Load(real_rtt, LoadOp::Kind::TaggedBase(),
                    MemoryRepresentation::TaggedPointer(),
                    Map::kConstructorOrBackPointerOrNativeContextOffset);
        // If the depth of the rtt is known to be less than the minimum
        // supertype array length, we can access the supertype without
        // bounds-checking the supertype array.
        if (static_cast<uint32_t>(rtt_depth) >=
            wasm::kMinimumSupertypeArraySize) {
          V<Word32> supertypes_length =
              __ UntagSmi(__ Load(type_info, LoadOp::Kind::TaggedBase(),
                                  MemoryRepresentation::TaggedSigned(),
                                  WasmTypeInfo::kSupertypesLengthOffset));
          __ TrapIfNot(__ Uint32LessThan(rtt_depth, supertypes_length),
                       OpIndex::Invalid(), TrapId::kTrapFuncSigMismatch);
        }
        V<Map> maybe_match =
            __ Load(type_info, LoadOp::Kind::TaggedBase(),
                    MemoryRepresentation::TaggedPointer(),
                    WasmTypeInfo::kSupertypesOffset + kTaggedSize * rtt_depth);
        __ TrapIfNot(__ TaggedEqual(maybe_match, formal_rtt),
                     OpIndex::Invalid(), TrapId::kTrapFuncSigMismatch);
        GOTO(end);
        BIND(end);
      } else {
        // In this case, signatures must match exactly.
        __ TrapIfNot(sigs_match, TrapId::kTrapFuncSigMismatch);
      }
    } else if (needs_null_check) {
      V<Word32> loaded_sig =
          __ Load(dispatch_table, dispatch_table_entry_offset,
                  LoadOp::Kind::TaggedBase(), MemoryRepresentation::Uint32(),
                  WasmDispatchTable::kSigBias);
      __ TrapIf(__ Word32Equal(-1, loaded_sig), TrapId::kTrapFuncSigMismatch);
    }

    /* Step 4: Extract ref and target. */
    V<WasmCodePtr> target = __ Load(dispatch_table, dispatch_table_entry_offset,
                                    LoadOp::Kind::TaggedBase(),
                                    MemoryRepresentation::WasmCodePointer(),
                                    WasmDispatchTable::kTargetBias);
    V<ExposedTrustedObject> implicit_arg =
        V<ExposedTrustedObject>::Cast(__ LoadProtectedPointerField(
            dispatch_table, dispatch_table_entry_offset,
            LoadOp::Kind::TaggedBase(), WasmDispatchTable::kImplicitArgBias,
            0));

    return {target, implicit_arg};
  }

  // Load the call target and implicit arg (WasmTrustedInstanceData or
  // WasmImportData) from a function reference.
  std::pair<V<WasmCodePtr>, V<ExposedTrustedObject>>
  BuildFunctionReferenceTargetAndImplicitArg(V<WasmFuncRef> func_ref,
                                             ValueType type,
                                             uint64_t expected_sig_hash) {
    if (type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      func_ref = V<WasmFuncRef>::Cast(
          __ AssertNotNull(func_ref, type, TrapId::kTrapNullDereference));
    }

    LoadOp::Kind load_kind =
        type.is_nullable() && null_check_strategy_ ==
                                  compiler::NullCheckStrategy::kTrapHandler
            ? LoadOp::Kind::TrapOnNull().Immutable()
            : LoadOp::Kind::TaggedBase().Immutable();

    V<WasmInternalFunction> internal_function =
        V<WasmInternalFunction>::Cast(__ LoadTrustedPointerField(
            func_ref, load_kind, kWasmInternalFunctionIndirectPointerTag,
            WasmFuncRef::kTrustedInternalOffset));

    return BuildFunctionTargetAndImplicitArg(internal_function,
                                             expected_sig_hash);
  }

  OpIndex AnnotateResultIfReference(OpIndex result, wasm::ValueType type) {
    return type.is_object_reference()
               ? __ AnnotateWasmType(V<Object>::Cast(result), type)
               : result;
  }

  void BuildWasmCall(FullDecoder* decoder, const FunctionSig* sig,
                     V<CallTarget> callee, V<HeapObject> ref,
                     const Value args[], Value returns[],
                     CheckForException check_for_exception =
                         CheckForException::kCatchInThisFrame) {
    const TSCallDescriptor* descriptor = TSCallDescriptor::Create(
        compiler::GetWasmCallDescriptor(__ graph_zone(), sig),
        compiler::CanThrow::kYes, compiler::LazyDeoptOnThrow::kNo,
        __ graph_zone());

    SmallZoneVector<OpIndex, 16> arg_indices(sig->parameter_count() + 1,
                                             decoder->zone());
    arg_indices[0] = ref;
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      arg_indices[i + 1] = args[i].op;
    }

    OpIndex call = CallAndMaybeCatchException(
        decoder, callee, base::VectorOf(arg_indices), descriptor,
        check_for_exception, OpEffects().CanCallAnything());

    if (sig->return_count() == 1) {
      returns[0].op = AnnotateResultIfReference(call, sig->GetReturn(0));
    } else if (sig->return_count() > 1) {
      for (uint32_t i = 0; i < sig->return_count(); i++) {
        wasm::ValueType type = sig->GetReturn(i);
        returns[i].op = AnnotateResultIfReference(
            __ Projection(call, i, RepresentationFor(type)), type);
      }
    }
    // Calls might mutate cached instance fields.
    instance_cache_.ReloadCachedMemory();
  }

 private:
  void BuildWasmMaybeReturnCall(FullDecoder* decoder, const FunctionSig* sig,
                                V<CallTarget> callee, V<HeapObject> ref,
                                const Value args[]) {
    if (mode_ == kRegular || mode_ == kInlinedTailCall) {
      const TSCallDescriptor* descriptor = TSCallDescriptor::Create(
          compiler::GetWasmCallDescriptor(__ graph_zone(), sig),
          compiler::CanThrow::kYes, compiler::LazyDeoptOnThrow::kNo,
          __ graph_zone());

      SmallZoneVector<OpIndex, 16> arg_indices(sig->parameter_count() + 1,
                                               decoder->zone_);
      arg_indices[0] = ref;
      for (uint32_t i = 0; i < sig->parameter_count(); i++) {
        arg_indices[i + 1] = args[i].op;
      }
      __ TailCall(callee, base::VectorOf(arg_indices), descriptor);
    } else {
      if (__ generating_unreachable_operations()) return;
      // This is a tail call in the inlinee, which in turn was a regular call.
      // Transform the tail call into a regular call, and return the return
      // values to the caller.
      size_t return_count = sig->return_count();
      SmallZoneVector<Value, 16> returns(return_count, decoder->zone_);
      // Since an exception in a tail call cannot be caught in this frame, we
      // should only catch exceptions in the generated call if this is a
      // recursively inlined function, and the parent frame provides a handler.
      BuildWasmCall(decoder, sig, callee, ref, args, returns.data(),
                    CheckForException::kCatchInParentFrame);
      for (size_t i = 0; i < return_count; i++) {
        return_phis_->AddInputForPhi(i, returns[i].op);
      }
      __ Goto(return_block_);
    }
  }

  template <typename Descriptor>
  std::enable_if_t<!Descriptor::kNeedsContext,
                   compiler::turboshaft::detail::index_type_for_t<
                       typename Descriptor::results_t>>
  CallBuiltinThroughJumptable(
      FullDecoder* decoder, const typename Descriptor::arguments_t& args,
      CheckForException check_for_exception = CheckForException::kNo) {
    DCHECK_NE(check_for_exception, CheckForException::kCatchInParentFrame);

    V<WordPtr> callee =
        __ RelocatableWasmBuiltinCallTarget(Descriptor::kFunction);
    auto arguments = std::apply(
        [](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t> + 1>{
              std::forward<decltype(as)>(as)...};
        },
        args);

    return CallAndMaybeCatchException(
        decoder, callee, base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallWasmRuntimeStub,
                           __ output_graph().graph_zone()),
        check_for_exception, Descriptor::kEffects);
  }

  template <typename Descriptor>
  std::enable_if_t<Descriptor::kNeedsContext,
                   compiler::turboshaft::detail::index_type_for_t<
                       typename Descriptor::results_t>>
  CallBuiltinThroughJumptable(
      FullDecoder* decoder, V<Context> context,
      const typename Descriptor::arguments_t& args,
      CheckForException check_for_exception = CheckForException::kNo) {
    DCHECK_NE(check_for_exception, CheckForException::kCatchInParentFrame);

    V<WordPtr
### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
2Div(lhs, rhs));
          }
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsDivU: {
        // asmjs semantics return 0 when dividing by 0.
        if (SupportedOperations::uint32_div_is_safe()) {
          return __ Uint32Div(lhs, rhs);
        }
        Label<Word32> done(&asm_);
        IF (UNLIKELY(__ Word32Equal(rhs, 0))) {
          GOTO(done, __ Word32Constant(0));
        } ELSE {
          GOTO(done, __ Uint32Div(lhs, rhs));
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsRemS: {
        // General case for signed integer modulus, with optimization for
        // (unknown) power of 2 right hand side.
        //
        //   if 0 < rhs then
        //     mask = rhs - 1
        //     if rhs & mask != 0 then
        //       lhs % rhs
        //     else
        //       if lhs < 0 then
        //         -(-lhs & mask)
        //       else
        //         lhs & mask
        //   else
        //     if rhs < -1 then
        //       lhs % rhs
        //     else
        //       zero
        Label<Word32> done(&asm_);
        IF (__ Int32LessThan(0, rhs)) {
          V<Word32> mask = __ Word32Sub(rhs, 1);
          IF (__ Word32Equal(__ Word32BitwiseAnd(rhs, mask), 0)) {
            IF (UNLIKELY(__ Int32LessThan(lhs, 0))) {
              V<Word32> neg_lhs = __ Word32Sub(0, lhs);
              V<Word32> combined = __ Word32BitwiseAnd(neg_lhs, mask);
              GOTO(done, __ Word32Sub(0, combined));
            } ELSE {
              GOTO(done, __ Word32BitwiseAnd(lhs, mask));
            }
          } ELSE {
            GOTO(done, __ Int32Mod(lhs, rhs));
          }
        } ELSE {
          IF (__ Int32LessThan(rhs, -1)) {
            GOTO(done, __ Int32Mod(lhs, rhs));
          } ELSE {
            GOTO(done, __ Word32Constant(0));
          }
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsRemU: {
        // asmjs semantics return 0 for mod with 0.
        Label<Word32> done(&asm_);
        IF (UNLIKELY(__ Word32Equal(rhs, 0))) {
          GOTO(done, __ Word32Constant(0));
        } ELSE {
          GOTO(done, __ Uint32Mod(lhs, rhs));
        }
        BIND(done, result);
        return result;
      }
      case kExprI32AsmjsStoreMem8:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int8());
        return rhs;
      case kExprI32AsmjsStoreMem16:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int16());
        return rhs;
      case kExprI32AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Int32());
        return rhs;
      case kExprF32AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Float32());
        return rhs;
      case kExprF64AsmjsStoreMem:
        AsmjsStoreMem(lhs, rhs, MemoryRepresentation::Float64());
        return rhs;
      default:
        UNREACHABLE();
    }
  }

  std::pair<V<WordPtr>, compiler::BoundsCheckResult> BoundsCheckMem(
      const wasm::WasmMemory* memory, MemoryRepresentation repr, OpIndex index,
      uintptr_t offset, compiler::EnforceBoundsCheck enforce_bounds_check,
      compiler::AlignmentCheck alignment_check) {
    // The function body decoder already validated that the access is not
    // statically OOB.
    DCHECK(base::IsInBounds(offset, static_cast<uintptr_t>(repr.SizeInBytes()),
                            memory->max_memory_size));

    wasm::BoundsCheckStrategy bounds_checks = memory->bounds_checks;
    // Convert the index to uintptr.
    // TODO(jkummerow): This should reuse MemoryAddressToUintPtrOrOOBTrap.
    V<WordPtr> converted_index = index;
    if (!memory->is_memory64()) {
      // Note: this doesn't just satisfy the compiler's internal consistency
      // checks, it's also load-bearing to prevent escaping from a compromised
      // sandbox (where in-sandbox corruption can cause the high word of
      // what's supposed to be an i32 to be non-zero).
      converted_index = __ ChangeUint32ToUintPtr(index);
    } else if (kSystemPointerSize == kInt32Size) {
      // Truncate index to 32-bit.
      converted_index = V<WordPtr>::Cast(__ TruncateWord64ToWord32(index));
    }

    const uintptr_t align_mask = repr.SizeInBytes() - 1;
    // Do alignment checks only for > 1 byte accesses (otherwise they trivially
    // pass).
    if (static_cast<bool>(alignment_check) && align_mask != 0) {
      // TODO(14108): Optimize constant index as per wasm-compiler.cc.

      // Unlike regular memory accesses, atomic memory accesses should trap if
      // the effective offset is misaligned.
      // TODO(wasm): this addition is redundant with one inserted by
      // {MemBuffer}.
      OpIndex effective_offset =
          __ WordPtrAdd(MemBuffer(memory->index, offset), converted_index);

      V<Word32> cond = __ TruncateWordPtrToWord32(__ WordPtrBitwiseAnd(
          effective_offset, __ IntPtrConstant(align_mask)));
      __ TrapIfNot(__ Word32Equal(cond, __ Word32Constant(0)),
                   TrapId::kTrapUnalignedAccess);
    }

    // If no bounds checks should be performed (for testing), just return the
    // converted index and assume it to be in-bounds.
    if (bounds_checks == wasm::kNoBoundsChecks) {
      return {converted_index, compiler::BoundsCheckResult::kInBounds};
    }

    if (memory->is_memory64() && kSystemPointerSize == kInt32Size) {
      // In memory64 mode on 32-bit systems, the upper 32 bits need to be zero
      // to succeed the bounds check.
      DCHECK_EQ(kExplicitBoundsChecks, bounds_checks);
      V<Word32> high_word =
          __ TruncateWord64ToWord32(__ Word64ShiftRightLogical(index, 32));
      __ TrapIf(high_word, TrapId::kTrapMemOutOfBounds);
    }

    uintptr_t end_offset = offset + repr.SizeInBytes() - 1u;
    DCHECK_LT(end_offset, memory->max_memory_size);

    // The index can be invalid if we are generating unreachable operations.
    if (end_offset <= memory->min_memory_size && index.valid() &&
        __ output_graph().Get(index).Is<ConstantOp>()) {
      ConstantOp& constant_index_op =
          __ output_graph().Get(index).Cast<ConstantOp>();
      uintptr_t constant_index = memory->is_memory64()
                                     ? constant_index_op.word64()
                                     : constant_index_op.word32();
      if (constant_index < memory->min_memory_size - end_offset) {
        return {converted_index, compiler::BoundsCheckResult::kInBounds};
      }
    }

#if V8_TRAP_HANDLER_SUPPORTED
    if (bounds_checks == kTrapHandler &&
        enforce_bounds_check ==
            compiler::EnforceBoundsCheck::kCanOmitBoundsCheck) {
      if (memory->is_memory64()) {
        // Bounds check `index` against `max_mem_size - end_offset`, such that
        // at runtime `index + end_offset` will be within `max_mem_size`, where
        // the trap handler can handle out-of-bound accesses.
        V<Word32> cond = __ Uint64LessThan(
            V<Word64>::Cast(converted_index),
            __ Word64Constant(uint64_t{memory->max_memory_size - end_offset}));
        __ TrapIfNot(cond, TrapId::kTrapMemOutOfBounds);
      }
      return {converted_index, compiler::BoundsCheckResult::kTrapHandler};
    }
#else
    CHECK_NE(bounds_checks, kTrapHandler);
#endif  // V8_TRAP_HANDLER_SUPPORTED

    V<WordPtr> memory_size = MemSize(memory->index);
    if (end_offset > memory->min_memory_size) {
      // The end offset is larger than the smallest memory.
      // Dynamically check the end offset against the dynamic memory size.
      __ TrapIfNot(
          __ UintPtrLessThan(__ UintPtrConstant(end_offset), memory_size),
          TrapId::kTrapMemOutOfBounds);
    }

    // This produces a positive number since {end_offset <= min_size <=
    // mem_size}.
    V<WordPtr> effective_size = __ WordPtrSub(memory_size, end_offset);
    __ TrapIfNot(__ UintPtrLessThan(converted_index, effective_size),
                 TrapId::kTrapMemOutOfBounds);
    return {converted_index, compiler::BoundsCheckResult::kDynamicallyChecked};
  }

  V<WordPtr> MemStart(uint32_t index) {
    if (index == 0) {
      // TODO(14108): Port TF's dynamic "cached_memory_index" infrastructure.
      return instance_cache_.memory0_start();
    } else {
      // TODO(14616): Fix sharedness.
      V<TrustedFixedAddressArray> instance_memories =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(trusted_instance_data(false),
                                                  MemoryBasesAndSizes,
                                                  TrustedFixedAddressArray);
      return __ Load(instance_memories, LoadOp::Kind::TaggedBase(),
                     MemoryRepresentation::UintPtr(),
                     TrustedFixedAddressArray::OffsetOfElementAt(2 * index));
    }
  }

  V<WordPtr> MemBuffer(uint32_t mem_index, uintptr_t offset) {
    V<WordPtr> mem_start = MemStart(mem_index);
    if (offset == 0) return mem_start;
    return __ WordPtrAdd(mem_start, offset);
  }

  V<WordPtr> MemSize(uint32_t index) {
    if (index == 0) {
      // TODO(14108): Port TF's dynamic "cached_memory_index" infrastructure.
      return instance_cache_.memory0_size();
    } else {
      // TODO(14616): Fix sharedness.
      V<TrustedByteArray> instance_memories =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(trusted_instance_data(false),
                                                  MemoryBasesAndSizes,
                                                  TrustedByteArray);
      return __ Load(
          instance_memories, LoadOp::Kind::TaggedBase().NotLoadEliminable(),
          MemoryRepresentation::UintPtr(),
          TrustedFixedAddressArray::OffsetOfElementAt(2 * index + 1));
    }
  }

  LoadOp::Kind GetMemoryAccessKind(
      MemoryRepresentation repr,
      compiler::BoundsCheckResult bounds_check_result) {
    LoadOp::Kind result;
    if (bounds_check_result == compiler::BoundsCheckResult::kTrapHandler) {
      DCHECK(repr == MemoryRepresentation::Int8() ||
             repr == MemoryRepresentation::Uint8() ||
             SupportedOperations::IsUnalignedLoadSupported(repr));
      result = LoadOp::Kind::Protected();
    } else if (repr != MemoryRepresentation::Int8() &&
               repr != MemoryRepresentation::Uint8() &&
               !SupportedOperations::IsUnalignedLoadSupported(repr)) {
      result = LoadOp::Kind::RawUnaligned();
    } else {
      result = LoadOp::Kind::RawAligned();
    }
    return result.NotLoadEliminable();
  }

  void TraceMemoryOperation(FullDecoder* decoder, bool is_store,
                            MemoryRepresentation repr, V<WordPtr> index,
                            uintptr_t offset) {
    int kAlign = 4;  // Ensure that the LSB is 0, like a Smi.
    V<WordPtr> info = __ StackSlot(sizeof(MemoryTracingInfo), kAlign);
    V<WordPtr> effective_offset = __ WordPtrAdd(index, offset);
    __ Store(info, effective_offset, StoreOp::Kind::RawAligned(),
             MemoryRepresentation::UintPtr(), compiler::kNoWriteBarrier,
             offsetof(MemoryTracingInfo, offset));
    __ Store(info, __ Word32Constant(is_store ? 1 : 0),
             StoreOp::Kind::RawAligned(), MemoryRepresentation::Uint8(),
             compiler::kNoWriteBarrier, offsetof(MemoryTracingInfo, is_store));
    V<Word32> rep_as_int = __ Word32Constant(
        static_cast<int>(repr.ToMachineType().representation()));
    __ Store(info, rep_as_int, StoreOp::Kind::RawAligned(),
             MemoryRepresentation::Uint8(), compiler::kNoWriteBarrier,
             offsetof(MemoryTracingInfo, mem_rep));
    CallRuntime(decoder->zone(), Runtime::kWasmTraceMemory, {info},
                __ NoContextConstant());
  }

  void StackCheck(WasmStackCheckOp::Kind kind, FullDecoder* decoder) {
    if (V8_UNLIKELY(!v8_flags.wasm_stack_checks)) return;
    __ WasmStackCheck(kind);
  }

 private:
  std::pair<V<WasmCodePtr>, V<HeapObject>>
  BuildImportedFunctionTargetAndImplicitArg(FullDecoder* decoder,
                                            uint32_t function_index) {
    ModuleTypeIndex sig_index =
        decoder->module_->functions[function_index].sig_index;
    bool shared = decoder->module_->type(sig_index).is_shared;
    return WasmGraphBuilderBase::BuildImportedFunctionTargetAndImplicitArg(
        function_index, trusted_instance_data(shared));
  }

  // Returns the call target and the implicit argument (WasmTrustedInstanceData
  // or WasmImportData) for an indirect call.
  std::pair<V<WasmCodePtr>, V<ExposedTrustedObject>>
  BuildIndirectCallTargetAndImplicitArg(FullDecoder* decoder,
                                        V<WordPtr> index_wordptr,
                                        CallIndirectImmediate imm,
                                        bool needs_type_or_null_check = true) {
    static_assert(kV8MaxWasmTableSize < size_t{kMaxInt});
    const WasmTable* table = imm.table_imm.table;

    /* Step 1: Load the indirect function tables for this table. */
    V<WasmDispatchTable> dispatch_table;
    if (imm.table_imm.index == 0) {
      dispatch_table =
          LOAD_PROTECTED_INSTANCE_FIELD(trusted_instance_data(table->shared),
                                        DispatchTable0, WasmDispatchTable);
    } else {
      V<ProtectedFixedArray> dispatch_tables =
          LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(
              trusted_instance_data(table->shared), DispatchTables,
              ProtectedFixedArray);
      dispatch_table =
          V<WasmDispatchTable>::Cast(__ LoadProtectedFixedArrayElement(
              dispatch_tables, imm.table_imm.index));
    }

    /* Step 2: Bounds check against the table size. */
    V<Word32> table_length;
    bool needs_dynamic_size =
        !table->has_maximum_size || table->maximum_size != table->initial_size;
    if (needs_dynamic_size) {
      table_length = __ LoadField<Word32>(
          dispatch_table, AccessBuilder::ForWasmDispatchTableLength());
    } else {
      table_length = __ Word32Constant(table->initial_size);
    }
    V<Word32> in_bounds = __ UintPtrLessThan(
        index_wordptr, __ ChangeUint32ToUintPtr(table_length));
    __ TrapIfNot(in_bounds, TrapId::kTrapTableOutOfBounds);

    /* Step 3: Check the canonical real signature against the canonical declared
     * signature. */
    ModuleTypeIndex sig_index = imm.sig_imm.index;
    bool needs_type_check =
        needs_type_or_null_check &&
        !EquivalentTypes(table->type.AsNonNull(), ValueType::Ref(sig_index),
                         decoder->module_, decoder->module_);
    bool needs_null_check =
        needs_type_or_null_check && table->type.is_nullable();

    V<WordPtr> dispatch_table_entry_offset = __ WordPtrAdd(
        __ WordPtrMul(index_wordptr, WasmDispatchTable::kEntrySize),
        WasmDispatchTable::kEntriesOffset);

    if (needs_type_check) {
      CanonicalTypeIndex sig_id = env_->module->canonical_sig_id(sig_index);
      V<Word32> expected_canonical_sig =
          __ RelocatableWasmCanonicalSignatureId(sig_id.index);

      V<Word32> loaded_sig =
          __ Load(dispatch_table, dispatch_table_entry_offset,
                  LoadOp::Kind::TaggedBase(), MemoryRepresentation::Uint32(),
                  WasmDispatchTable::kSigBias);
      V<Word32> sigs_match = __ Word32Equal(expected_canonical_sig, loaded_sig);
      if (!decoder->module_->type(sig_index).is_final) {
        // In this case, a full type check is needed.
        Label<> end(&asm_);

        // First, check if signatures happen to match exactly.
        GOTO_IF(sigs_match, end);

        if (needs_null_check) {
          // Trap on null element.
          __ TrapIf(__ Word32Equal(loaded_sig, -1),
                    TrapId::kTrapFuncSigMismatch);
        }
        bool shared = decoder->module_->type(sig_index).is_shared;
        V<Map> formal_rtt = __ RttCanon(managed_object_maps(shared), sig_index);
        int rtt_depth = GetSubtypingDepth(decoder->module_, sig_index);
        DCHECK_GE(rtt_depth, 0);

        // Since we have the canonical index of the real rtt, we have to load it
        // from the isolate rtt-array (which is canonically indexed). Since this
        // reference is weak, we have to promote it to a strong reference.
        // Note: The reference cannot have been cleared: Since the loaded_sig
        // corresponds to a function of the same canonical type, that function
        // will have kept the type alive.
        V<WeakFixedArray> rtts = LOAD_ROOT(WasmCanonicalRtts);
        V<Object> weak_rtt = __ Load(
            rtts, __ ChangeInt32ToIntPtr(loaded_sig),
            LoadOp::Kind::TaggedBase(), MemoryRepresentation::TaggedPointer(),
            OFFSET_OF_DATA_START(WeakFixedArray), kTaggedSizeLog2);
        V<Map> real_rtt =
            V<Map>::Cast(__ BitcastWordPtrToTagged(__ WordPtrBitwiseAnd(
                __ BitcastHeapObjectToWordPtr(V<HeapObject>::Cast(weak_rtt)),
                ~kWeakHeapObjectMask)));
        V<WasmTypeInfo> type_info =
            __ Load(real_rtt, LoadOp::Kind::TaggedBase(),
                    MemoryRepresentation::TaggedPointer(),
                    Map::kConstructorOrBackPointerOrNativeContextOffset);
        // If the depth of the rtt is known to be less than the minimum
        // supertype array length, we can access the supertype without
        // bounds-checking the supertype array.
        if (static_cast<uint32_t>(rtt_depth) >=
            wasm::kMinimumSupertypeArraySize) {
          V<Word32> supertypes_length =
              __ UntagSmi(__ Load(type_info, LoadOp::Kind::TaggedBase(),
                                  MemoryRepresentation::TaggedSigned(),
                                  WasmTypeInfo::kSupertypesLengthOffset));
          __ TrapIfNot(__ Uint32LessThan(rtt_depth, supertypes_length),
                       OpIndex::Invalid(), TrapId::kTrapFuncSigMismatch);
        }
        V<Map> maybe_match =
            __ Load(type_info, LoadOp::Kind::TaggedBase(),
                    MemoryRepresentation::TaggedPointer(),
                    WasmTypeInfo::kSupertypesOffset + kTaggedSize * rtt_depth);
        __ TrapIfNot(__ TaggedEqual(maybe_match, formal_rtt),
                     OpIndex::Invalid(), TrapId::kTrapFuncSigMismatch);
        GOTO(end);
        BIND(end);
      } else {
        // In this case, signatures must match exactly.
        __ TrapIfNot(sigs_match, TrapId::kTrapFuncSigMismatch);
      }
    } else if (needs_null_check) {
      V<Word32> loaded_sig =
          __ Load(dispatch_table, dispatch_table_entry_offset,
                  LoadOp::Kind::TaggedBase(), MemoryRepresentation::Uint32(),
                  WasmDispatchTable::kSigBias);
      __ TrapIf(__ Word32Equal(-1, loaded_sig), TrapId::kTrapFuncSigMismatch);
    }

    /* Step 4: Extract ref and target. */
    V<WasmCodePtr> target = __ Load(dispatch_table, dispatch_table_entry_offset,
                                    LoadOp::Kind::TaggedBase(),
                                    MemoryRepresentation::WasmCodePointer(),
                                    WasmDispatchTable::kTargetBias);
    V<ExposedTrustedObject> implicit_arg =
        V<ExposedTrustedObject>::Cast(__ LoadProtectedPointerField(
            dispatch_table, dispatch_table_entry_offset,
            LoadOp::Kind::TaggedBase(), WasmDispatchTable::kImplicitArgBias,
            0));

    return {target, implicit_arg};
  }

  // Load the call target and implicit arg (WasmTrustedInstanceData or
  // WasmImportData) from a function reference.
  std::pair<V<WasmCodePtr>, V<ExposedTrustedObject>>
  BuildFunctionReferenceTargetAndImplicitArg(V<WasmFuncRef> func_ref,
                                             ValueType type,
                                             uint64_t expected_sig_hash) {
    if (type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      func_ref = V<WasmFuncRef>::Cast(
          __ AssertNotNull(func_ref, type, TrapId::kTrapNullDereference));
    }

    LoadOp::Kind load_kind =
        type.is_nullable() && null_check_strategy_ ==
                                  compiler::NullCheckStrategy::kTrapHandler
            ? LoadOp::Kind::TrapOnNull().Immutable()
            : LoadOp::Kind::TaggedBase().Immutable();

    V<WasmInternalFunction> internal_function =
        V<WasmInternalFunction>::Cast(__ LoadTrustedPointerField(
            func_ref, load_kind, kWasmInternalFunctionIndirectPointerTag,
            WasmFuncRef::kTrustedInternalOffset));

    return BuildFunctionTargetAndImplicitArg(internal_function,
                                             expected_sig_hash);
  }

  OpIndex AnnotateResultIfReference(OpIndex result, wasm::ValueType type) {
    return type.is_object_reference()
               ? __ AnnotateWasmType(V<Object>::Cast(result), type)
               : result;
  }

  void BuildWasmCall(FullDecoder* decoder, const FunctionSig* sig,
                     V<CallTarget> callee, V<HeapObject> ref,
                     const Value args[], Value returns[],
                     CheckForException check_for_exception =
                         CheckForException::kCatchInThisFrame) {
    const TSCallDescriptor* descriptor = TSCallDescriptor::Create(
        compiler::GetWasmCallDescriptor(__ graph_zone(), sig),
        compiler::CanThrow::kYes, compiler::LazyDeoptOnThrow::kNo,
        __ graph_zone());

    SmallZoneVector<OpIndex, 16> arg_indices(sig->parameter_count() + 1,
                                             decoder->zone());
    arg_indices[0] = ref;
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      arg_indices[i + 1] = args[i].op;
    }

    OpIndex call = CallAndMaybeCatchException(
        decoder, callee, base::VectorOf(arg_indices), descriptor,
        check_for_exception, OpEffects().CanCallAnything());

    if (sig->return_count() == 1) {
      returns[0].op = AnnotateResultIfReference(call, sig->GetReturn(0));
    } else if (sig->return_count() > 1) {
      for (uint32_t i = 0; i < sig->return_count(); i++) {
        wasm::ValueType type = sig->GetReturn(i);
        returns[i].op = AnnotateResultIfReference(
            __ Projection(call, i, RepresentationFor(type)), type);
      }
    }
    // Calls might mutate cached instance fields.
    instance_cache_.ReloadCachedMemory();
  }

 private:
  void BuildWasmMaybeReturnCall(FullDecoder* decoder, const FunctionSig* sig,
                                V<CallTarget> callee, V<HeapObject> ref,
                                const Value args[]) {
    if (mode_ == kRegular || mode_ == kInlinedTailCall) {
      const TSCallDescriptor* descriptor = TSCallDescriptor::Create(
          compiler::GetWasmCallDescriptor(__ graph_zone(), sig),
          compiler::CanThrow::kYes, compiler::LazyDeoptOnThrow::kNo,
          __ graph_zone());

      SmallZoneVector<OpIndex, 16> arg_indices(sig->parameter_count() + 1,
                                               decoder->zone_);
      arg_indices[0] = ref;
      for (uint32_t i = 0; i < sig->parameter_count(); i++) {
        arg_indices[i + 1] = args[i].op;
      }
      __ TailCall(callee, base::VectorOf(arg_indices), descriptor);
    } else {
      if (__ generating_unreachable_operations()) return;
      // This is a tail call in the inlinee, which in turn was a regular call.
      // Transform the tail call into a regular call, and return the return
      // values to the caller.
      size_t return_count = sig->return_count();
      SmallZoneVector<Value, 16> returns(return_count, decoder->zone_);
      // Since an exception in a tail call cannot be caught in this frame, we
      // should only catch exceptions in the generated call if this is a
      // recursively inlined function, and the parent frame provides a handler.
      BuildWasmCall(decoder, sig, callee, ref, args, returns.data(),
                    CheckForException::kCatchInParentFrame);
      for (size_t i = 0; i < return_count; i++) {
        return_phis_->AddInputForPhi(i, returns[i].op);
      }
      __ Goto(return_block_);
    }
  }

  template <typename Descriptor>
  std::enable_if_t<!Descriptor::kNeedsContext,
                   compiler::turboshaft::detail::index_type_for_t<
                       typename Descriptor::results_t>>
  CallBuiltinThroughJumptable(
      FullDecoder* decoder, const typename Descriptor::arguments_t& args,
      CheckForException check_for_exception = CheckForException::kNo) {
    DCHECK_NE(check_for_exception, CheckForException::kCatchInParentFrame);

    V<WordPtr> callee =
        __ RelocatableWasmBuiltinCallTarget(Descriptor::kFunction);
    auto arguments = std::apply(
        [](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t> + 1>{
              std::forward<decltype(as)>(as)...};
        },
        args);

    return CallAndMaybeCatchException(
        decoder, callee, base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallWasmRuntimeStub,
                           __ output_graph().graph_zone()),
        check_for_exception, Descriptor::kEffects);
  }

  template <typename Descriptor>
  std::enable_if_t<Descriptor::kNeedsContext,
                   compiler::turboshaft::detail::index_type_for_t<
                       typename Descriptor::results_t>>
  CallBuiltinThroughJumptable(
      FullDecoder* decoder, V<Context> context,
      const typename Descriptor::arguments_t& args,
      CheckForException check_for_exception = CheckForException::kNo) {
    DCHECK_NE(check_for_exception, CheckForException::kCatchInParentFrame);

    V<WordPtr> callee =
        __ RelocatableWasmBuiltinCallTarget(Descriptor::kFunction);
    auto arguments = std::apply(
        [context](auto&&... as) {
          return base::SmallVector<
              OpIndex, std::tuple_size_v<typename Descriptor::arguments_t> + 1>{
              std::forward<decltype(as)>(as)..., context};
        },
        args);

    return CallAndMaybeCatchException(
        decoder, callee, base::VectorOf(arguments),
        Descriptor::Create(StubCallMode::kCallWasmRuntimeStub,
                           __ output_graph().graph_zone()),
        check_for_exception, Descriptor::kEffects);
  }

 private:
  void MaybeSetPositionToParent(OpIndex call,
                                CheckForException check_for_exception) {
    // For tail calls that we transform to regular calls, we need to set the
    // call's position to that of the inlined call node to get correct stack
    // traces.
    if (check_for_exception == CheckForException::kCatchInParentFrame) {
      __ output_graph().operation_origins()[call] = WasmPositionToOpIndex(
          parent_position_.ScriptOffset(), parent_position_.InliningId() == -1
                                               ? kNoInliningId
                                               : parent_position_.InliningId());
    }
  }

  OpIndex CallAndMaybeCatchException(FullDecoder* decoder, V<CallTarget> callee,
                                     base::Vector<const OpIndex> args,
                                     const TSCallDescriptor* descriptor,
                                     CheckForException check_for_exception,
                                     OpEffects effects) {
    if (check_for_exception == CheckForException::kNo) {
      return __ Call(callee, OpIndex::Invalid(), args, descriptor, effects);
    }
    bool handled_in_this_frame =
        decoder && decoder->current_catch() != -1 &&
        check_for_exception == CheckForException::kCatchInThisFrame;
    if (!handled_in_this_frame && mode_ != kInlinedWithCatch) {
      OpIndex call =
          __ Call(callee, OpIndex::Invalid(), args, descriptor, effects);
      MaybeSetPositionToParent(call, check_for_exception);
      return call;
    }

    TSBlock* catch_block;
    if (handled_in_this_frame) {
      Control* current_catch =
          decoder->control_at(decoder->control_depth_of_current_catch());
      catch_block = current_catch->false_or_loop_or_catch_block;
    } else {
      DCHECK_EQ(mode_, kInlinedWithCatch);
      catch_block = return_catch_block_;
    }
    TSBlock* success_block = __ NewBlock();
    TSBlock* exception_block = __ NewBlock();
    OpIndex call;
    {
      Assembler::CatchScope scope(asm_, exception_block);

      call = __ Call(callee, OpIndex::Invalid(), args, descriptor, effects);
      __ Goto(success_block);
    }

    __ Bind(exception_block);
    OpIndex exception = __ CatchBlockBegin();
    if (handled_in_this_frame) {
      // The exceptional operation could have modified memory size; we need
      // to reload the memory context into the exceptional control path.
      instance_cache_.ReloadCachedMemory();
      SetupControlFlowEdge(decoder, catch_block, 0, exception);
    } else {
      DCHECK_EQ(mode_, kInlinedWithCatch);
      if (exception.valid()) return_phis_->AddIncomingException(exception);
      // Reloading the InstanceCache will happen when {return_exception_phis_}
      // are retrieved.
    }
    __ Goto(catch_block);

    __ Bind(success_block);

    MaybeSetPositionToParent(call, check_for_exception);

    return call;
  }

  OpIndex CallCStackSlotToInt32(OpIndex arg, ExternalReference ref,
                                MemoryRepresentation arg_type) {
    OpIndex stack_slot_param =
        __ StackSlot(arg_type.SizeInBytes(), arg_type.SizeInBytes());
    __ Store(stack_slot_param, arg, StoreOp::Kind::RawAligned(), arg_type,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    MachineType reps[]{MachineType::Int32(), MachineType::Pointer()};
    MachineSignature sig(1, 1, reps);
    return CallC(&sig, ref, stack_slot_param);
  }

  V<Word32> CallCStackSlotToInt32(
      ExternalReference ref,
      std::initializer_list<std::pair<OpIndex, MemoryRepresentation>> args) {
    int slot_size = 0;
    for (auto arg : args) slot_size += arg.second.SizeInBytes();
    // Since we are storing the arguments unaligned anyway, we do not need
    // alignment > 0.
    V<WordPtr> stack_slot_param = __ StackSlot(slot_size, 0);
    int offset = 0;
    for (auto arg : args) {
      __ Store(stack_slot_param, arg.first,
               StoreOp::Kind::MaybeUnaligned(arg.second), arg.second,
               compiler::WriteBarrierKind::kNoWriteBarrier, offset);
      offset += arg.second.SizeInBytes();
    }
    MachineType reps[]{MachineType::Int32(), MachineType::Pointer()};
    MachineSignature sig(1, 1, reps);
    return CallC(&sig, ref, stack_slot_param);
  }

  OpIndex CallCStackSlotToStackSlot(
      ExternalReference ref, MemoryRepresentation res_type,
      std::initializer_list<std::pair<OpIndex, MemoryRepresentation>> args) {
    int slot_size = 0;
    for (auto arg : args) slot_size += arg.second.SizeInBytes();
    // Since we are storing the arguments unaligned anyway, we do not need
    // alignment > 0.
    slot_size = std::max<int>(slot_size, res_type.SizeInBytes());
    V<WordPtr> stack_slot_param = __ StackSlot(slot_size, 0);
    int offset = 0;
    for (auto arg : args) {
      __ Store(stack_slot_param, arg.first,
               StoreOp::Kind::MaybeUnaligned(arg.second), arg.second,
               compiler::WriteBarrierKind::kNoWriteBarrier, offset);
      offset += arg.second.SizeInBytes();
    }
    MachineType reps[]{MachineType::Pointer()};
    MachineSignature sig(0, 1, reps);
    CallC(&sig, ref, stack_slot_param);
    return __ Load(stack_slot_param, LoadOp::Kind::RawAligned(), res_type);
  }

  OpIndex CallCStackSlotToStackSlot(OpIndex arg, ExternalReference ref,
                                    MemoryRepresentation arg_type) {
    return CallCStackSlotToStackSlot(arg, ref, arg_type, arg_type);
  }

  OpIndex CallCStackSlotToStackSlot(OpIndex arg, ExternalReference ref,
                                    MemoryRepresentation arg_type,
                                    MemoryRepresentation res_type) {
    return CallCStackSlotToStackSlot(ref, res_type, {{arg, arg_type}});
  }

  OpIndex CallCStackSlotToStackSlot(OpIndex arg0, OpIndex arg1,
                                    ExternalReference ref,
                                    MemoryRepresentation arg_type) {
    return CallCStackSlotToStackSlot(ref, arg_type,
                                     {{arg0, arg_type}, {arg1, arg_type}});
  }

  V<WordPtr> MemOrTableAddressToUintPtrOrOOBTrap(AddressType address_type,
                                                 V<Word> index,
                                                 TrapId trap_reason) {
    // Note: this {ChangeUint32ToUintPtr} doesn't just satisfy the compiler's
    // consistency checks, it's also load-bearing to prevent escaping from a
    // compromised sandbox (where in-sandbox corruption
```