Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/function-body-decoder-impl.h`.

The code seems to be part of a WebAssembly function body decoder. It handles various aspects of decoding and validating WebAssembly instructions, particularly those related to memory access, control flow, and GC operations.

Here's a breakdown of the code's functionality:

1. **Stack Manipulation:** The code interacts heavily with a `stack_` to manage operands during decoding. Functions like `EnsureStackArguments`, `Drop`, `Pop`, and `Push` are used for this.
2. **Control Flow:** It manages a `control_` stack to track control flow structures like blocks, loops, and if-else statements. Functions like `PushControl` and `PopControl` manage this stack.
3. **Memory Access:** It decodes and handles memory access instructions like `load` and `store`, including bounds checking and handling different data types and sizes.
4. **SIMD Operations:** It decodes and handles SIMD (Single Instruction, Multiple Data) instructions, including lane manipulation, shuffling, and loading/storing SIMD values from/to memory.
5. **Garbage Collection (GC) Operations:** It decodes and handles GC-related instructions for working with structs and arrays, like creating new instances, accessing and modifying fields, and initializing arrays from data or element segments.
6. **Type Validation:** It performs type validation to ensure operands and results of instructions are of the expected types. Functions like `ValidateParameters`, `ValidateStackValue`, `IsSubtypeOf`, `TypeCheckAlwaysFails`, and `TypeCheckAlwaysSucceeds` are used for this.
7. **Error Handling:** The code uses `VALIDATE` and `DecodeError` to handle decoding errors and invalid WebAssembly code. It also handles unreachable code.
8. **Immediate Decoding:** It decodes immediate values associated with instructions using classes like `MemoryAccessImmediate`, `SimdLaneImmediate`, `Simd128Immediate`, `StructIndexImmediate`, `FieldIndexImmediate`, and `ArrayIndexImmediate`.
9. **Interface Calls:** It uses `CALL_INTERFACE_IF_OK_AND_REACHABLE` to invoke abstract methods (likely implemented in a base class or interface) for the actual execution or processing of the decoded instructions.

The user also asked to consider if the header file were a `.tq` file (Torque source), its relationship to JavaScript, provide examples, discuss potential programming errors, and synthesize the functionality.

Based on the code's content, it doesn't seem like a Torque file. Torque files are typically involved in generating code for built-in functions and runtime components, often directly manipulating JavaScript objects and the V8 heap. This file focuses on decoding the binary format of WebAssembly.

The code interacts with JavaScript indirectly by being a core component of the WebAssembly engine in V8. When JavaScript code calls a WebAssembly function, this decoder is responsible for processing the WebAssembly bytecode.

Let's prepare the response by addressing each of the user's points.
```cpp
 control_.back().stack_depth;
    if (!VALIDATE(control_.back().unreachable())) {
      NotEnoughArgumentsError(count, stack_.size() - limit);
    }
    // Silently create unreachable values out of thin air underneath the
    // existing stack values. To do so, we have to move existing stack values
    // upwards in the stack, then instantiate the new Values as
    // {UnreachableValue}.
    int current_values = stack_.size() - limit;
    int additional_values = count - current_values;
    DCHECK_GT(additional_values, 0);
    // Ensure that after this operation there is still room for one more value.
    // Callers might not expect this operation to push values on the stack
    // (because it only does so in exceptional cases).
    stack_.EnsureMoreCapacity(additional_values + 1, this->zone_);
    Value unreachable_value = UnreachableValue(this->pc_);
    for (int i = 0; i < additional_values; ++i) stack_.push(unreachable_value);
    if (current_values > 0) {
      // Move the current values up to the end of the stack, and create
      // unreachable values below.
      Value* stack_base = stack_value(current_values + additional_values);
      for (int i = current_values - 1; i >= 0; i--) {
        stack_base[additional_values + i] = stack_base[i];
      }
      for (int i = 0; i < additional_values; i++) {
        stack_base[i] = UnreachableValue(this->pc_);
      }
    }
    return additional_values;
  }

  V8_INLINE void ValidateParameters(const FunctionSig* sig) {
    int num_params = static_cast<int>(sig->parameter_count());
    EnsureStackArguments(num_params);
    Value* param_base = stack_.end() - num_params;
    for (int i = 0; i < num_params; i++) {
      ValidateStackValue(i, param_base[i], sig->GetParam(i));
    }
  }

  // Drops a number of stack elements equal to the {sig}'s parameter count (0 if
  // {sig} is null), or all of them if less are present.
  V8_INLINE void DropArgs(const FunctionSig* sig) {
    int count = static_cast<int>(sig->parameter_count());
    Drop(count);
  }

  V8_INLINE PoppedArgVector PopArgs(const StructType* type) {
    int count = static_cast<int>(type->field_count());
    EnsureStackArguments(count);
    DCHECK_LE(control_.back().stack_depth, stack_size());
    DCHECK_GE(stack_size() - control_.back().stack_depth, count);
    Value* args_base = stack_.end() - count;
    for (int i = 0; i < count; i++) {
      ValidateStackValue(i, args_base[i], type->field(i).Unpacked());
    }
    // Note: Popping from the {FastZoneVector} does not invalidate the old (now
    // out-of-range) elements.
    stack_.pop(count);
    return PoppedArgVector{base::VectorOf(args_base, count)};
  }
  // Drops a number of stack elements equal to the struct's field count, or all
  // of them if less are present.
  V8_INLINE void DropArgs(const StructType* type) {
    Drop(static_cast<int>(type->field_count()));
  }

  // Pops arguments as required by signature, returning them by copy as a
  // vector.
  V8_INLINE PoppedArgVector PopArgs(const FunctionSig* sig) {
    int count = static_cast<int>(sig->parameter_count());
    EnsureStackArguments(count);
    DCHECK_LE(control_.back().stack_depth, stack_size());
    DCHECK_GE(stack_size() - control_.back().stack_depth, count);
    Value* args_base = stack_.end() - count;
    for (int i = 0; i < count; ++i) {
      ValidateStackValue(i, args_base[i], sig->GetParam(i));
    }
    // Note: Popping from the {FastZoneVector} does not invalidate the old (now
    // out-of-range) elements.
    stack_.pop(count);
    return PoppedArgVector{base::VectorOf(args_base, count)};
  }

  Control* PushControl(ControlKind kind, const BlockTypeImmediate& imm) {
    DCHECK(!control_.empty());
    ValidateParameters(&imm.sig);
    uint32_t consumed_values = static_cast<uint32_t>(imm.sig.parameter_count());
    uint32_t stack_depth = stack_.size();
    DCHECK_LE(consumed_values, stack_depth);
    uint32_t inner_stack_depth = stack_depth - consumed_values;
    DCHECK_LE(control_.back().stack_depth, inner_stack_depth);

    uint32_t init_stack_depth = this->locals_initialization_stack_depth();
    Reachability reachability = control_.back().innerReachability();
    control_.EnsureMoreCapacity(1, this->zone_);
    control_.emplace_back(this->zone_, kind, inner_stack_depth,
                          init_stack_depth, this->pc_, reachability);
    Control* new_block = &control_.back();

    Value* arg_base = stack_.end() - consumed_values;
    // Update the type of input nodes to the more general types expected by the
    // block. In particular, in unreachable code, the input would have bottom
    // type otherwise.
    for (uint32_t i = 0; i < consumed_values; ++i) {
      DCHECK_IMPLIES(this->ok(), IsSubtypeOf(arg_base[i].type, imm.in_type(i),
                                             this->module_) ||
                                     arg_base[i].type == kWasmBottom);
      arg_base[i].type = imm.in_type(i);
    }

    // Initialize start- and end-merges of {c} with values according to the
    // in- and out-types of {c} respectively.
    const uint8_t* pc = this->pc_;
    InitMerge(&new_block->end_merge, imm.out_arity(), [pc, &imm](uint32_t i) {
      return Value{pc, imm.out_type(i)};
    });
    InitMerge(&new_block->start_merge, imm.in_arity(),
              [arg_base](uint32_t i) { return arg_base[i]; });
    return new_block;
  }

  void PopControl() {
    // This cannot be the outermost control block.
    DCHECK_LT(1, control_.size());
    Control* c = &control_.back();
    DCHECK_LE(c->stack_depth, stack_.size());

    CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(PopControl, c);

    // - In non-unreachable code, a loop just leaves the values on the stack.
    // - In unreachable code, it is not guaranteed that we have Values of the
    //   correct types on the stack, so we have to make sure we do. Their values
    //   do not matter, so we might as well push the (uninitialized) values of the
    //   loop's end merge.
    if (!c->is_loop() || c->unreachable()) {
      PushMergeValues(c, &c->end_merge);
    }
    RollbackLocalsInitialization(c);

    bool parent_reached =
        c->reachable() || c->end_merge.reached || c->is_onearmed_if();
    control_.pop();
    // If the parent block was reachable before, but the popped control does not
    // return to here, this block becomes "spec only reachable".
    if (!parent_reached) SetSucceedingCodeDynamicallyUnreachable();
    current_code_reachable_and_ok_ =
        VALIDATE(this->ok()) && control_.back().reachable();
  }

  int DecodeLoadMem(LoadType type, int prefix_len = 1) {
    MemoryAccessImmediate imm =
        MakeMemoryAccessImmediate(prefix_len, type.size_log_2());
    if (!this->Validate(this->pc_ + prefix_len, imm)) return 0;
    ValueType address_type = MemoryAddressType(imm.memory);
    Value index = Pop(address_type);
    Value* result = Push(type.value_type());
    if (V8_LIKELY(
            !CheckStaticallyOutOfBounds(imm.memory, type.size(), imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(LoadMem, type, imm, index, result);
    }
    return prefix_len + imm.length;
  }

  int DecodeLoadTransformMem(LoadType type, LoadTransformationKind transform,
                             uint32_t opcode_length) {
    // Load extends always load 64-bits.
    uint32_t max_alignment =
        transform == LoadTransformationKind::kExtend ? 3 : type.size_log_2();
    MemoryAccessImmediate imm =
        MakeMemoryAccessImmediate(opcode_length, max_alignment);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
    ValueType address_type = MemoryAddressType(imm.memory);
    Value index = Pop(address_type);
    Value* result = Push(kWasmS128);
    uintptr_t op_size =
        transform == LoadTransformationKind::kExtend ? 8 : type.size();
    if (V8_LIKELY(
            !CheckStaticallyOutOfBounds(imm.memory, op_size, imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(LoadTransform, type, transform, imm,
                                         index, result);
    }
    return opcode_length + imm.length;
  }

  int DecodeLoadLane(WasmOpcode opcode, LoadType type, uint32_t opcode_length) {
    MemoryAccessImmediate mem_imm =
        MakeMemoryAccessImmediate(opcode_length, type.size_log_2());
    if (!this->Validate(this->pc_ + opcode_length, mem_imm)) return 0;
    SimdLaneImmediate lane_imm(this, this->pc_ + opcode_length + mem_imm.length,
                               validate);
    if (!this->Validate(this->pc_ + opcode_length, opcode, lane_imm)) return 0;
    ValueType address_type = MemoryAddressType(mem_imm.memory);
    auto [index, v128] = Pop(address_type, kWasmS128);

    Value* result = Push(kWasmS128);
    if (V8_LIKELY(!CheckStaticallyOutOfBounds(mem_imm.memory, type.size(),
                                              mem_imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(LoadLane, type, v128, index, mem_imm,
                                         lane_imm.lane, result);
    }
    return opcode_length + mem_imm.length + lane_imm.length;
  }

  int DecodeStoreLane(WasmOpcode opcode, StoreType type,
                      uint32_t opcode_length) {
    MemoryAccessImmediate mem_imm =
        MakeMemoryAccessImmediate(opcode_length, type.size_log_2());
    if (!this->Validate(this->pc_ + opcode_length, mem_imm)) return 0;
    SimdLaneImmediate lane_imm(this, this->pc_ + opcode_length + mem_imm.length,
                               validate);
    if (!this->Validate(this->pc_ + opcode_length, opcode, lane_imm)) return 0;
    ValueType address_type = MemoryAddressType(mem_imm.memory);
    auto [index, v128] = Pop(address_type, kWasmS128);

    if (V8_LIKELY(!CheckStaticallyOutOfBounds(mem_imm.memory, type.size(),
                                              mem_imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(StoreLane, type, mem_imm, index, v128,
                                         lane_imm.lane);
    }
    return opcode_length + mem_imm.length + lane_imm.length;
  }

  bool CheckStaticallyOutOfBounds(const WasmMemory* memory, uint64_t size,
                                  uint64_t offset) {
    const bool statically_oob =
        !base::IsInBounds<uint64_t>(offset, size, memory->max_memory_size);
    if (V8_UNLIKELY(statically_oob)) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(Trap, TrapReason::kTrapMemOutOfBounds);
      SetSucceedingCodeDynamicallyUnreachable();
    }
    return statically_oob;
  }

  int DecodeStoreMem(StoreType store, int prefix_len = 1) {
    MemoryAccessImmediate imm =
        MakeMemoryAccessImmediate(prefix_len, store.size_log_2());
    if (!this->Validate(this->pc_ + prefix_len, imm)) return 0;
    ValueType address_type = MemoryAddressType(imm.memory);
    auto [index, value] = Pop(address_type, store.value_type());
    if (V8_LIKELY(!CheckStaticallyOutOfBounds(imm.memory, store.size(),
                                              imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(StoreMem, store, imm, index, value);
    }
    return prefix_len + imm.length;
  }

  uint32_t SimdConstOp(uint32_t opcode_length) {
    Simd128Immediate imm(this, this->pc_ + opcode_length, validate);
    Value* result = Push(kWasmS128);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(S128Const, imm, result);
    return opcode_length + kSimd128Size;
  }

  uint32_t SimdExtractLane(WasmOpcode opcode, ValueType type,
                           uint32_t opcode_length) {
    SimdLaneImmediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, opcode, imm)) return 0;
    Value input = Pop(kWasmS128);
    Value* result = Push(type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(SimdLaneOp, opcode, imm,
                                       base::VectorOf({input}), result);
    return opcode_length + imm.length;
  }

  uint32_t SimdReplaceLane(WasmOpcode opcode, ValueType type,
                           uint32_t opcode_length) {
    SimdLaneImmediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, opcode, imm)) return 0;
    auto [v128, lane_val] = Pop(kWasmS128, type);
    Value* result = Push(kWasmS128);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(
        SimdLaneOp, opcode, imm, base::VectorOf({v128, lane_val}), result);
    return opcode_length + imm.length;
  }

  uint32_t Simd8x16ShuffleOp(uint32_t opcode_length) {
    Simd128Immediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
    auto [input0, input1] = Pop(kWasmS128, kWasmS128);
    Value* result = Push(kWasmS128);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Simd8x16ShuffleOp, imm, input0, input1,
                                       result);
    return opcode_length + 16;
  }

  uint32_t DecodeSimdOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    if constexpr (decoding_mode == kConstantExpression) {
      // Currently, only s128.const is allowed in constant expressions.
      if (opcode != kExprS128Const) {
        this->DecodeError("opcode %s is not allowed in constant expressions",
                          this->SafeOpcodeNameAt(this->pc()));
        return 0;
      }
      return SimdConstOp(opcode_length);
    }
    // opcode_length is the number of bytes that this SIMD-specific opcode takes
    // up in the LEB128 encoded form.
    switch (opcode) {
      case kExprF64x2ExtractLane:
        return SimdExtractLane(opcode, kWasmF64, opcode_length);
      case kExprF16x8ExtractLane: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid simd opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        [[fallthrough]];
      }
      case kExprF32x4ExtractLane:
        return SimdExtractLane(opcode, kWasmF32, opcode_length);
      case kExprI64x2ExtractLane:
        return SimdExtractLane(opcode, kWasmI64, opcode_length);
      case kExprI32x4ExtractLane:
      case kExprI16x8ExtractLaneS:
      case kExprI16x8ExtractLaneU:
      case kExprI8x16ExtractLaneS:
      case kExprI8x16ExtractLaneU:
        return SimdExtractLane(opcode, kWasmI32, opcode_length);
      case kExprF64x2ReplaceLane:
        return SimdReplaceLane(opcode, kWasmF64, opcode_length);
      case kExprF16x8ReplaceLane: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid simd opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        [[fallthrough]];
      }
      case kExprF32x4ReplaceLane:
        return SimdReplaceLane(opcode, kWasmF32, opcode_length);
      case kExprI64x2ReplaceLane:
        return SimdReplaceLane(opcode, kWasmI64, opcode_length);
      case kExprI32x4ReplaceLane:
      case kExprI16x8ReplaceLane:
      case kExprI8x16ReplaceLane:
        return SimdReplaceLane(opcode, kWasmI32, opcode_length);
      case kExprI8x16Shuffle:
        return Simd8x16ShuffleOp(opcode_length);
      case kExprS128LoadMem:
        return DecodeLoadMem(LoadType::kS128Load, opcode_length);
      case kExprS128StoreMem:
        return DecodeStoreMem(StoreType::kS128Store, opcode_length);
      case kExprS128Load32Zero:
        return DecodeLoadTransformMem(LoadType::kI32Load,
                                      LoadTransformationKind::kZeroExtend,
                                      opcode_length);
      case kExprS128Load64Zero:
        return DecodeLoadTransformMem(LoadType::kI64Load,
                                      LoadTransformationKind::kZeroExtend,
                                      opcode_length);
      case kExprS128Load8Splat:
        return DecodeLoadTransformMem(LoadType::kI32Load8S,
                                      LoadTransformationKind::kSplat,
                                      opcode_length);
      case kExprS128Load16Splat:
        return DecodeLoadTransformMem(LoadType::kI32Load16S,
                                      LoadTransformationKind::kSplat,
                                      opcode_length);
      case kExprS128Load32Splat:
        return DecodeLoadTransformMem(
            LoadType::kI32Load, LoadTransformationKind::kSplat, opcode_length);
      case kExprS128Load64Splat:
        return DecodeLoadTransformMem(
            LoadType::kI64Load, LoadTransformationKind::kSplat, opcode_length);
      case kExprS128Load8x8S:
        return DecodeLoadTransformMem(LoadType::kI32Load8S,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load8x8U:
        return DecodeLoadTransformMem(LoadType::kI32Load8U,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load16x4S:
        return DecodeLoadTransformMem(LoadType::kI32Load16S,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load16x4U:
        return DecodeLoadTransformMem(LoadType::kI32Load16U,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load32x2S:
        return DecodeLoadTransformMem(LoadType::kI64Load32S,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load32x2U:
        return DecodeLoadTransformMem(LoadType::kI64Load32U,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load8Lane: {
        return DecodeLoadLane(opcode, LoadType::kI32Load8S, opcode_length);
      }
      case kExprS128Load16Lane: {
        return DecodeLoadLane(opcode, LoadType::kI32Load16S, opcode_length);
      }
      case kExprS128Load32Lane: {
        return DecodeLoadLane(opcode, LoadType::kI32Load, opcode_length);
      }
      case kExprS128Load64Lane: {
        return DecodeLoadLane(opcode, LoadType::kI64Load, opcode_length);
      }
      case kExprS128Store8Lane: {
        return DecodeStoreLane(opcode, StoreType::kI32Store8, opcode_length);
      }
      case kExprS128Store16Lane: {
        return DecodeStoreLane(opcode, StoreType::kI32Store16, opcode_length);
      }
      case kExprS128Store32Lane: {
        return DecodeStoreLane(opcode, StoreType::kI32Store, opcode_length);
      }
      case kExprS128Store64Lane: {
        return DecodeStoreLane(opcode, StoreType::kI64Store, opcode_length);
      }
      case kExprS128Const:
        return SimdConstOp(opcode_length);
      case kExprF16x8Splat:
      case kExprF16x8Abs:
      case kExprF16x8Neg:
      case kExprF16x8Sqrt:
      case kExprF16x8Ceil:
      case kExprF16x8Floor:
      case kExprF16x8Trunc:
      case kExprF16x8NearestInt:
      case kExprF16x8Eq:
      case kExprF16x8Ne:
      case kExprF16x8Lt:
      case kExprF16x8Gt:
      case kExprF16x8Le:
      case kExprF16x8Ge:
      case kExprF16x8Add:
      case kExprF16x8Sub:
      case kExprF16x8Mul:
      case kExprF16x8Div:
      case kExprF16x8Min:
      case kExprF16x8Max:
      case kExprF16x8Pmin:
      case kExprF16x8Pmax:
      case kExprI16x8SConvertF16x8:
      case kExprI16x8UConvertF16x8:
      case kExprF16x8SConvertI16x8:
      case kExprF16x8UConvertI16x8:
      case kExprF16x8DemoteF32x4Zero:
      case kExprF16x8DemoteF64x2Zero:
      case kExprF32x4PromoteLowF16x8:
      case kExprF16x8Qfma:
      case kExprF16x8Qfms: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid simd opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        [[fallthrough]];
      }
      default: {
        const FunctionSig* sig = WasmOpcodes::Signature(opcode);
        if (!VALIDATE(sig != nullptr)) {
          this->DecodeError("invalid simd opcode");
          return 0;
        }
        PoppedArgVector args = PopArgs(sig);
        Value* results = sig->return_count() == 0 ? nullptr : PushReturns(sig);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(SimdOp, opcode, args.data(),
                                           results);
        return opcode_length;
      }
    }
  }

  // Returns true if type checking will always fail, either because the types
  // are unrelated or because the target_type is one of the null sentinels and
  // conversion to null does not succeed.
  bool TypeCheckAlwaysFails(Value obj, HeapType expected_type,
                            bool null_succeeds) {
    bool types_unrelated =
        !IsSubtypeOf(ValueType::Ref(expected_type), obj.type, this->module_) &&
        !IsSubtypeOf(obj.type, ValueType::RefNull(expected_type),
                     this->module_);
    // For "unrelated" types the check can still succeed for the null value on
    // instructions treating null as a successful check.
    // TODO(12868): For string views, this implementation anticipates that
    // https://github.com/WebAssembly/stringref/issues/40 will be resolved
    // by making the views standalone types.
    return (types_unrelated &&
            (!null_succeeds || !obj.type.is_nullable() ||
             obj.type.is_string_view() || expected_type.is_string_view())) ||
           ((!null_succeeds || !obj.type.is_nullable()) &&
            (expected_type.representation() == HeapType::kNone ||
             expected_type.representation() == HeapType::kNoFunc ||
             expected_type.representation() == HeapType::kNoExtern ||
             expected_type.representation() == HeapType::kNoExn));
  }

  // Checks if {obj} is a subtype of type, thus checking will always
  // succeed.
  bool TypeCheckAlwaysSucceeds(Value obj, HeapType type) {
    return IsSubtypeOf(obj.type, ValueType::RefNull(type), this->module_);
  }

#define NON_CONST_ONLY                                                    \
  if constexpr (decoding_mode == kConstantExpression) {                   \
    this->DecodeError("opcode %s is not allowed in constant expressions", \
                      this->SafeOpcodeNameAt(this->pc()));                \
    return 0;                                                             \
  }

  int DecodeGCOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    // Bigger GC opcodes are handled via {DecodeStringRefOpcode}, so we can
    // assume here that opcodes are within [0xfb00, 0xfbff].
    // This assumption might help the big switch below.
    V8_ASSUME(opcode >> 8 == kGCPrefix);
    switch (opcode) {
      case kExprStructNew: {
        StructIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        PoppedArgVector args = PopArgs(imm.struct_type);
        Value* value = Push(ValueType::Ref(imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StructNew, imm, args.data(), value);
        return opcode_length + imm.length;
      }
      case kExprStructNewDefault: {
        StructIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        if (ValidationTag::validate) {
          for (uint32_t i = 0; i < imm.struct_type->field_count(); i++) {
            ValueType ftype = imm.struct_type->field(i);
            if (!VALIDATE(ftype.is_defaultable())) {
              this->DecodeError(
                  "%s: struct type %d has field %d of non-defaultable type %s",
                  WasmOpcodes::OpcodeName(opcode), imm.index, i,
                  ftype.name().c_str());
              return 0;
            }
          }
        }
        Value* value = Push(ValueType::Ref(imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StructNewDefault, imm, value);
        return opcode_length + imm.length;
      }
      case kExprStructGet: {
        NON_CONST_ONLY
        FieldImmediate field(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, field)) return 0;
        ValueType field_type =
            field.struct_imm.struct_type->field(field.field_imm.index);
        if (!VALIDATE(!field_type.is_packed())) {
          this->DecodeError(
              "struct.get: Immediate field %d of type %d has packed type %s. "
              "Use struct.get_s or struct.get_u instead.",
              field.field_imm.index, field.struct_imm.index,
              field_type.name().c_str());
          return 0;
        }
        Value struct_obj = Pop(ValueType::RefNull(field.struct_imm.index));
        Value*
Prompt: 
```
这是目录为v8/src/wasm/function-body-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-body-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共9部分，请归纳一下它的功能

"""
 control_.back().stack_depth;
    if (!VALIDATE(control_.back().unreachable())) {
      NotEnoughArgumentsError(count, stack_.size() - limit);
    }
    // Silently create unreachable values out of thin air underneath the
    // existing stack values. To do so, we have to move existing stack values
    // upwards in the stack, then instantiate the new Values as
    // {UnreachableValue}.
    int current_values = stack_.size() - limit;
    int additional_values = count - current_values;
    DCHECK_GT(additional_values, 0);
    // Ensure that after this operation there is still room for one more value.
    // Callers might not expect this operation to push values on the stack
    // (because it only does so in exceptional cases).
    stack_.EnsureMoreCapacity(additional_values + 1, this->zone_);
    Value unreachable_value = UnreachableValue(this->pc_);
    for (int i = 0; i < additional_values; ++i) stack_.push(unreachable_value);
    if (current_values > 0) {
      // Move the current values up to the end of the stack, and create
      // unreachable values below.
      Value* stack_base = stack_value(current_values + additional_values);
      for (int i = current_values - 1; i >= 0; i--) {
        stack_base[additional_values + i] = stack_base[i];
      }
      for (int i = 0; i < additional_values; i++) {
        stack_base[i] = UnreachableValue(this->pc_);
      }
    }
    return additional_values;
  }

  V8_INLINE void ValidateParameters(const FunctionSig* sig) {
    int num_params = static_cast<int>(sig->parameter_count());
    EnsureStackArguments(num_params);
    Value* param_base = stack_.end() - num_params;
    for (int i = 0; i < num_params; i++) {
      ValidateStackValue(i, param_base[i], sig->GetParam(i));
    }
  }

  // Drops a number of stack elements equal to the {sig}'s parameter count (0 if
  // {sig} is null), or all of them if less are present.
  V8_INLINE void DropArgs(const FunctionSig* sig) {
    int count = static_cast<int>(sig->parameter_count());
    Drop(count);
  }

  V8_INLINE PoppedArgVector PopArgs(const StructType* type) {
    int count = static_cast<int>(type->field_count());
    EnsureStackArguments(count);
    DCHECK_LE(control_.back().stack_depth, stack_size());
    DCHECK_GE(stack_size() - control_.back().stack_depth, count);
    Value* args_base = stack_.end() - count;
    for (int i = 0; i < count; i++) {
      ValidateStackValue(i, args_base[i], type->field(i).Unpacked());
    }
    // Note: Popping from the {FastZoneVector} does not invalidate the old (now
    // out-of-range) elements.
    stack_.pop(count);
    return PoppedArgVector{base::VectorOf(args_base, count)};
  }
  // Drops a number of stack elements equal to the struct's field count, or all
  // of them if less are present.
  V8_INLINE void DropArgs(const StructType* type) {
    Drop(static_cast<int>(type->field_count()));
  }

  // Pops arguments as required by signature, returning them by copy as a
  // vector.
  V8_INLINE PoppedArgVector PopArgs(const FunctionSig* sig) {
    int count = static_cast<int>(sig->parameter_count());
    EnsureStackArguments(count);
    DCHECK_LE(control_.back().stack_depth, stack_size());
    DCHECK_GE(stack_size() - control_.back().stack_depth, count);
    Value* args_base = stack_.end() - count;
    for (int i = 0; i < count; ++i) {
      ValidateStackValue(i, args_base[i], sig->GetParam(i));
    }
    // Note: Popping from the {FastZoneVector} does not invalidate the old (now
    // out-of-range) elements.
    stack_.pop(count);
    return PoppedArgVector{base::VectorOf(args_base, count)};
  }

  Control* PushControl(ControlKind kind, const BlockTypeImmediate& imm) {
    DCHECK(!control_.empty());
    ValidateParameters(&imm.sig);
    uint32_t consumed_values = static_cast<uint32_t>(imm.sig.parameter_count());
    uint32_t stack_depth = stack_.size();
    DCHECK_LE(consumed_values, stack_depth);
    uint32_t inner_stack_depth = stack_depth - consumed_values;
    DCHECK_LE(control_.back().stack_depth, inner_stack_depth);

    uint32_t init_stack_depth = this->locals_initialization_stack_depth();
    Reachability reachability = control_.back().innerReachability();
    control_.EnsureMoreCapacity(1, this->zone_);
    control_.emplace_back(this->zone_, kind, inner_stack_depth,
                          init_stack_depth, this->pc_, reachability);
    Control* new_block = &control_.back();

    Value* arg_base = stack_.end() - consumed_values;
    // Update the type of input nodes to the more general types expected by the
    // block. In particular, in unreachable code, the input would have bottom
    // type otherwise.
    for (uint32_t i = 0; i < consumed_values; ++i) {
      DCHECK_IMPLIES(this->ok(), IsSubtypeOf(arg_base[i].type, imm.in_type(i),
                                             this->module_) ||
                                     arg_base[i].type == kWasmBottom);
      arg_base[i].type = imm.in_type(i);
    }

    // Initialize start- and end-merges of {c} with values according to the
    // in- and out-types of {c} respectively.
    const uint8_t* pc = this->pc_;
    InitMerge(&new_block->end_merge, imm.out_arity(), [pc, &imm](uint32_t i) {
      return Value{pc, imm.out_type(i)};
    });
    InitMerge(&new_block->start_merge, imm.in_arity(),
              [arg_base](uint32_t i) { return arg_base[i]; });
    return new_block;
  }

  void PopControl() {
    // This cannot be the outermost control block.
    DCHECK_LT(1, control_.size());
    Control* c = &control_.back();
    DCHECK_LE(c->stack_depth, stack_.size());

    CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(PopControl, c);

    // - In non-unreachable code, a loop just leaves the values on the stack.
    // - In unreachable code, it is not guaranteed that we have Values of the
    //   correct types on the stack, so we have to make sure we do. Their values
    //   do not matter, so we might as well push the (uninitialized) values of
    //   the loop's end merge.
    if (!c->is_loop() || c->unreachable()) {
      PushMergeValues(c, &c->end_merge);
    }
    RollbackLocalsInitialization(c);

    bool parent_reached =
        c->reachable() || c->end_merge.reached || c->is_onearmed_if();
    control_.pop();
    // If the parent block was reachable before, but the popped control does not
    // return to here, this block becomes "spec only reachable".
    if (!parent_reached) SetSucceedingCodeDynamicallyUnreachable();
    current_code_reachable_and_ok_ =
        VALIDATE(this->ok()) && control_.back().reachable();
  }

  int DecodeLoadMem(LoadType type, int prefix_len = 1) {
    MemoryAccessImmediate imm =
        MakeMemoryAccessImmediate(prefix_len, type.size_log_2());
    if (!this->Validate(this->pc_ + prefix_len, imm)) return 0;
    ValueType address_type = MemoryAddressType(imm.memory);
    Value index = Pop(address_type);
    Value* result = Push(type.value_type());
    if (V8_LIKELY(
            !CheckStaticallyOutOfBounds(imm.memory, type.size(), imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(LoadMem, type, imm, index, result);
    }
    return prefix_len + imm.length;
  }

  int DecodeLoadTransformMem(LoadType type, LoadTransformationKind transform,
                             uint32_t opcode_length) {
    // Load extends always load 64-bits.
    uint32_t max_alignment =
        transform == LoadTransformationKind::kExtend ? 3 : type.size_log_2();
    MemoryAccessImmediate imm =
        MakeMemoryAccessImmediate(opcode_length, max_alignment);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
    ValueType address_type = MemoryAddressType(imm.memory);
    Value index = Pop(address_type);
    Value* result = Push(kWasmS128);
    uintptr_t op_size =
        transform == LoadTransformationKind::kExtend ? 8 : type.size();
    if (V8_LIKELY(
            !CheckStaticallyOutOfBounds(imm.memory, op_size, imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(LoadTransform, type, transform, imm,
                                         index, result);
    }
    return opcode_length + imm.length;
  }

  int DecodeLoadLane(WasmOpcode opcode, LoadType type, uint32_t opcode_length) {
    MemoryAccessImmediate mem_imm =
        MakeMemoryAccessImmediate(opcode_length, type.size_log_2());
    if (!this->Validate(this->pc_ + opcode_length, mem_imm)) return 0;
    SimdLaneImmediate lane_imm(this, this->pc_ + opcode_length + mem_imm.length,
                               validate);
    if (!this->Validate(this->pc_ + opcode_length, opcode, lane_imm)) return 0;
    ValueType address_type = MemoryAddressType(mem_imm.memory);
    auto [index, v128] = Pop(address_type, kWasmS128);

    Value* result = Push(kWasmS128);
    if (V8_LIKELY(!CheckStaticallyOutOfBounds(mem_imm.memory, type.size(),
                                              mem_imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(LoadLane, type, v128, index, mem_imm,
                                         lane_imm.lane, result);
    }
    return opcode_length + mem_imm.length + lane_imm.length;
  }

  int DecodeStoreLane(WasmOpcode opcode, StoreType type,
                      uint32_t opcode_length) {
    MemoryAccessImmediate mem_imm =
        MakeMemoryAccessImmediate(opcode_length, type.size_log_2());
    if (!this->Validate(this->pc_ + opcode_length, mem_imm)) return 0;
    SimdLaneImmediate lane_imm(this, this->pc_ + opcode_length + mem_imm.length,
                               validate);
    if (!this->Validate(this->pc_ + opcode_length, opcode, lane_imm)) return 0;
    ValueType address_type = MemoryAddressType(mem_imm.memory);
    auto [index, v128] = Pop(address_type, kWasmS128);

    if (V8_LIKELY(!CheckStaticallyOutOfBounds(mem_imm.memory, type.size(),
                                              mem_imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(StoreLane, type, mem_imm, index, v128,
                                         lane_imm.lane);
    }
    return opcode_length + mem_imm.length + lane_imm.length;
  }

  bool CheckStaticallyOutOfBounds(const WasmMemory* memory, uint64_t size,
                                  uint64_t offset) {
    const bool statically_oob =
        !base::IsInBounds<uint64_t>(offset, size, memory->max_memory_size);
    if (V8_UNLIKELY(statically_oob)) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(Trap, TrapReason::kTrapMemOutOfBounds);
      SetSucceedingCodeDynamicallyUnreachable();
    }
    return statically_oob;
  }

  int DecodeStoreMem(StoreType store, int prefix_len = 1) {
    MemoryAccessImmediate imm =
        MakeMemoryAccessImmediate(prefix_len, store.size_log_2());
    if (!this->Validate(this->pc_ + prefix_len, imm)) return 0;
    ValueType address_type = MemoryAddressType(imm.memory);
    auto [index, value] = Pop(address_type, store.value_type());
    if (V8_LIKELY(!CheckStaticallyOutOfBounds(imm.memory, store.size(),
                                              imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(StoreMem, store, imm, index, value);
    }
    return prefix_len + imm.length;
  }

  uint32_t SimdConstOp(uint32_t opcode_length) {
    Simd128Immediate imm(this, this->pc_ + opcode_length, validate);
    Value* result = Push(kWasmS128);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(S128Const, imm, result);
    return opcode_length + kSimd128Size;
  }

  uint32_t SimdExtractLane(WasmOpcode opcode, ValueType type,
                           uint32_t opcode_length) {
    SimdLaneImmediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, opcode, imm)) return 0;
    Value input = Pop(kWasmS128);
    Value* result = Push(type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(SimdLaneOp, opcode, imm,
                                       base::VectorOf({input}), result);
    return opcode_length + imm.length;
  }

  uint32_t SimdReplaceLane(WasmOpcode opcode, ValueType type,
                           uint32_t opcode_length) {
    SimdLaneImmediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, opcode, imm)) return 0;
    auto [v128, lane_val] = Pop(kWasmS128, type);
    Value* result = Push(kWasmS128);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(
        SimdLaneOp, opcode, imm, base::VectorOf({v128, lane_val}), result);
    return opcode_length + imm.length;
  }

  uint32_t Simd8x16ShuffleOp(uint32_t opcode_length) {
    Simd128Immediate imm(this, this->pc_ + opcode_length, validate);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
    auto [input0, input1] = Pop(kWasmS128, kWasmS128);
    Value* result = Push(kWasmS128);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Simd8x16ShuffleOp, imm, input0, input1,
                                       result);
    return opcode_length + 16;
  }

  uint32_t DecodeSimdOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    if constexpr (decoding_mode == kConstantExpression) {
      // Currently, only s128.const is allowed in constant expressions.
      if (opcode != kExprS128Const) {
        this->DecodeError("opcode %s is not allowed in constant expressions",
                          this->SafeOpcodeNameAt(this->pc()));
        return 0;
      }
      return SimdConstOp(opcode_length);
    }
    // opcode_length is the number of bytes that this SIMD-specific opcode takes
    // up in the LEB128 encoded form.
    switch (opcode) {
      case kExprF64x2ExtractLane:
        return SimdExtractLane(opcode, kWasmF64, opcode_length);
      case kExprF16x8ExtractLane: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid simd opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        [[fallthrough]];
      }
      case kExprF32x4ExtractLane:
        return SimdExtractLane(opcode, kWasmF32, opcode_length);
      case kExprI64x2ExtractLane:
        return SimdExtractLane(opcode, kWasmI64, opcode_length);
      case kExprI32x4ExtractLane:
      case kExprI16x8ExtractLaneS:
      case kExprI16x8ExtractLaneU:
      case kExprI8x16ExtractLaneS:
      case kExprI8x16ExtractLaneU:
        return SimdExtractLane(opcode, kWasmI32, opcode_length);
      case kExprF64x2ReplaceLane:
        return SimdReplaceLane(opcode, kWasmF64, opcode_length);
      case kExprF16x8ReplaceLane: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid simd opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        [[fallthrough]];
      }
      case kExprF32x4ReplaceLane:
        return SimdReplaceLane(opcode, kWasmF32, opcode_length);
      case kExprI64x2ReplaceLane:
        return SimdReplaceLane(opcode, kWasmI64, opcode_length);
      case kExprI32x4ReplaceLane:
      case kExprI16x8ReplaceLane:
      case kExprI8x16ReplaceLane:
        return SimdReplaceLane(opcode, kWasmI32, opcode_length);
      case kExprI8x16Shuffle:
        return Simd8x16ShuffleOp(opcode_length);
      case kExprS128LoadMem:
        return DecodeLoadMem(LoadType::kS128Load, opcode_length);
      case kExprS128StoreMem:
        return DecodeStoreMem(StoreType::kS128Store, opcode_length);
      case kExprS128Load32Zero:
        return DecodeLoadTransformMem(LoadType::kI32Load,
                                      LoadTransformationKind::kZeroExtend,
                                      opcode_length);
      case kExprS128Load64Zero:
        return DecodeLoadTransformMem(LoadType::kI64Load,
                                      LoadTransformationKind::kZeroExtend,
                                      opcode_length);
      case kExprS128Load8Splat:
        return DecodeLoadTransformMem(LoadType::kI32Load8S,
                                      LoadTransformationKind::kSplat,
                                      opcode_length);
      case kExprS128Load16Splat:
        return DecodeLoadTransformMem(LoadType::kI32Load16S,
                                      LoadTransformationKind::kSplat,
                                      opcode_length);
      case kExprS128Load32Splat:
        return DecodeLoadTransformMem(
            LoadType::kI32Load, LoadTransformationKind::kSplat, opcode_length);
      case kExprS128Load64Splat:
        return DecodeLoadTransformMem(
            LoadType::kI64Load, LoadTransformationKind::kSplat, opcode_length);
      case kExprS128Load8x8S:
        return DecodeLoadTransformMem(LoadType::kI32Load8S,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load8x8U:
        return DecodeLoadTransformMem(LoadType::kI32Load8U,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load16x4S:
        return DecodeLoadTransformMem(LoadType::kI32Load16S,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load16x4U:
        return DecodeLoadTransformMem(LoadType::kI32Load16U,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load32x2S:
        return DecodeLoadTransformMem(LoadType::kI64Load32S,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load32x2U:
        return DecodeLoadTransformMem(LoadType::kI64Load32U,
                                      LoadTransformationKind::kExtend,
                                      opcode_length);
      case kExprS128Load8Lane: {
        return DecodeLoadLane(opcode, LoadType::kI32Load8S, opcode_length);
      }
      case kExprS128Load16Lane: {
        return DecodeLoadLane(opcode, LoadType::kI32Load16S, opcode_length);
      }
      case kExprS128Load32Lane: {
        return DecodeLoadLane(opcode, LoadType::kI32Load, opcode_length);
      }
      case kExprS128Load64Lane: {
        return DecodeLoadLane(opcode, LoadType::kI64Load, opcode_length);
      }
      case kExprS128Store8Lane: {
        return DecodeStoreLane(opcode, StoreType::kI32Store8, opcode_length);
      }
      case kExprS128Store16Lane: {
        return DecodeStoreLane(opcode, StoreType::kI32Store16, opcode_length);
      }
      case kExprS128Store32Lane: {
        return DecodeStoreLane(opcode, StoreType::kI32Store, opcode_length);
      }
      case kExprS128Store64Lane: {
        return DecodeStoreLane(opcode, StoreType::kI64Store, opcode_length);
      }
      case kExprS128Const:
        return SimdConstOp(opcode_length);
      case kExprF16x8Splat:
      case kExprF16x8Abs:
      case kExprF16x8Neg:
      case kExprF16x8Sqrt:
      case kExprF16x8Ceil:
      case kExprF16x8Floor:
      case kExprF16x8Trunc:
      case kExprF16x8NearestInt:
      case kExprF16x8Eq:
      case kExprF16x8Ne:
      case kExprF16x8Lt:
      case kExprF16x8Gt:
      case kExprF16x8Le:
      case kExprF16x8Ge:
      case kExprF16x8Add:
      case kExprF16x8Sub:
      case kExprF16x8Mul:
      case kExprF16x8Div:
      case kExprF16x8Min:
      case kExprF16x8Max:
      case kExprF16x8Pmin:
      case kExprF16x8Pmax:
      case kExprI16x8SConvertF16x8:
      case kExprI16x8UConvertF16x8:
      case kExprF16x8SConvertI16x8:
      case kExprF16x8UConvertI16x8:
      case kExprF16x8DemoteF32x4Zero:
      case kExprF16x8DemoteF64x2Zero:
      case kExprF32x4PromoteLowF16x8:
      case kExprF16x8Qfma:
      case kExprF16x8Qfms: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid simd opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        [[fallthrough]];
      }
      default: {
        const FunctionSig* sig = WasmOpcodes::Signature(opcode);
        if (!VALIDATE(sig != nullptr)) {
          this->DecodeError("invalid simd opcode");
          return 0;
        }
        PoppedArgVector args = PopArgs(sig);
        Value* results = sig->return_count() == 0 ? nullptr : PushReturns(sig);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(SimdOp, opcode, args.data(),
                                           results);
        return opcode_length;
      }
    }
  }

  // Returns true if type checking will always fail, either because the types
  // are unrelated or because the target_type is one of the null sentinels and
  // conversion to null does not succeed.
  bool TypeCheckAlwaysFails(Value obj, HeapType expected_type,
                            bool null_succeeds) {
    bool types_unrelated =
        !IsSubtypeOf(ValueType::Ref(expected_type), obj.type, this->module_) &&
        !IsSubtypeOf(obj.type, ValueType::RefNull(expected_type),
                     this->module_);
    // For "unrelated" types the check can still succeed for the null value on
    // instructions treating null as a successful check.
    // TODO(12868): For string views, this implementation anticipates that
    // https://github.com/WebAssembly/stringref/issues/40 will be resolved
    // by making the views standalone types.
    return (types_unrelated &&
            (!null_succeeds || !obj.type.is_nullable() ||
             obj.type.is_string_view() || expected_type.is_string_view())) ||
           ((!null_succeeds || !obj.type.is_nullable()) &&
            (expected_type.representation() == HeapType::kNone ||
             expected_type.representation() == HeapType::kNoFunc ||
             expected_type.representation() == HeapType::kNoExtern ||
             expected_type.representation() == HeapType::kNoExn));
  }

  // Checks if {obj} is a subtype of type, thus checking will always
  // succeed.
  bool TypeCheckAlwaysSucceeds(Value obj, HeapType type) {
    return IsSubtypeOf(obj.type, ValueType::RefNull(type), this->module_);
  }

#define NON_CONST_ONLY                                                    \
  if constexpr (decoding_mode == kConstantExpression) {                   \
    this->DecodeError("opcode %s is not allowed in constant expressions", \
                      this->SafeOpcodeNameAt(this->pc()));                \
    return 0;                                                             \
  }

  int DecodeGCOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    // Bigger GC opcodes are handled via {DecodeStringRefOpcode}, so we can
    // assume here that opcodes are within [0xfb00, 0xfbff].
    // This assumption might help the big switch below.
    V8_ASSUME(opcode >> 8 == kGCPrefix);
    switch (opcode) {
      case kExprStructNew: {
        StructIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        PoppedArgVector args = PopArgs(imm.struct_type);
        Value* value = Push(ValueType::Ref(imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StructNew, imm, args.data(), value);
        return opcode_length + imm.length;
      }
      case kExprStructNewDefault: {
        StructIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        if (ValidationTag::validate) {
          for (uint32_t i = 0; i < imm.struct_type->field_count(); i++) {
            ValueType ftype = imm.struct_type->field(i);
            if (!VALIDATE(ftype.is_defaultable())) {
              this->DecodeError(
                  "%s: struct type %d has field %d of non-defaultable type %s",
                  WasmOpcodes::OpcodeName(opcode), imm.index, i,
                  ftype.name().c_str());
              return 0;
            }
          }
        }
        Value* value = Push(ValueType::Ref(imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StructNewDefault, imm, value);
        return opcode_length + imm.length;
      }
      case kExprStructGet: {
        NON_CONST_ONLY
        FieldImmediate field(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, field)) return 0;
        ValueType field_type =
            field.struct_imm.struct_type->field(field.field_imm.index);
        if (!VALIDATE(!field_type.is_packed())) {
          this->DecodeError(
              "struct.get: Immediate field %d of type %d has packed type %s. "
              "Use struct.get_s or struct.get_u instead.",
              field.field_imm.index, field.struct_imm.index,
              field_type.name().c_str());
          return 0;
        }
        Value struct_obj = Pop(ValueType::RefNull(field.struct_imm.index));
        Value* value = Push(field_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StructGet, struct_obj, field, true,
                                           value);
        return opcode_length + field.length;
      }
      case kExprStructGetU:
      case kExprStructGetS: {
        NON_CONST_ONLY
        FieldImmediate field(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, field)) return 0;
        ValueType field_type =
            field.struct_imm.struct_type->field(field.field_imm.index);
        if (!VALIDATE(field_type.is_packed())) {
          this->DecodeError(
              "%s: Immediate field %d of type %d has non-packed type %s. Use "
              "struct.get instead.",
              WasmOpcodes::OpcodeName(opcode), field.field_imm.index,
              field.struct_imm.index, field_type.name().c_str());
          return 0;
        }
        Value struct_obj = Pop(ValueType::RefNull(field.struct_imm.index));
        Value* value = Push(field_type.Unpacked());
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StructGet, struct_obj, field,
                                           opcode == kExprStructGetS, value);
        return opcode_length + field.length;
      }
      case kExprStructSet: {
        NON_CONST_ONLY
        FieldImmediate field(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, field)) return 0;
        const StructType* struct_type = field.struct_imm.struct_type;
        if (!VALIDATE(struct_type->mutability(field.field_imm.index))) {
          this->DecodeError("struct.set: Field %d of type %d is immutable.",
                            field.field_imm.index, field.struct_imm.index);
          return 0;
        }
        auto [struct_obj, field_value] =
            Pop(ValueType::RefNull(field.struct_imm.index),
                struct_type->field(field.field_imm.index).Unpacked());
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StructSet, struct_obj, field,
                                           field_value);
        return opcode_length + field.length;
      }
      case kExprArrayNew: {
        ArrayIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        auto [initial_value, length] =
            Pop(imm.array_type->element_type().Unpacked(), kWasmI32);
        Value* value = Push(ValueType::Ref(imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayNew, imm, length, initial_value,
                                           value);
        return opcode_length + imm.length;
      }
      case kExprArrayNewDefault: {
        ArrayIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        if (!VALIDATE(imm.array_type->element_type().is_defaultable())) {
          this->DecodeError(
              "%s: array type %d has non-defaultable element type %s",
              WasmOpcodes::OpcodeName(opcode), imm.index,
              imm.array_type->element_type().name().c_str());
          return 0;
        }
        Value length = Pop(kWasmI32);
        Value* value = Push(ValueType::Ref(imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayNewDefault, imm, length, value);
        return opcode_length + imm.length;
      }
      case kExprArrayNewData: {
        // TODO(14616): Add check that array sharedness == segment sharedness?
        NON_CONST_ONLY
        ArrayIndexImmediate array_imm(this, this->pc_ + opcode_length,
                                      validate);
        if (!this->Validate(this->pc_ + opcode_length, array_imm)) return 0;
        ValueType element_type = array_imm.array_type->element_type();
        if (element_type.is_reference()) {
          this->DecodeError(
              "array.new_data can only be used with numeric-type arrays, found "
              "array type #%d instead",
              array_imm.index);
          return 0;
        }
        const uint8_t* data_index_pc =
            this->pc_ + opcode_length + array_imm.length;
        IndexImmediate data_segment(this, data_index_pc, "data segment",
                                    validate);
        if (!this->ValidateDataSegment(data_index_pc, data_segment)) return 0;

        auto [offset, length] = Pop(kWasmI32, kWasmI32);

        Value* array = Push(ValueType::Ref(array_imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayNewSegment, array_imm,
                                           data_segment, offset, length, array);
        return opcode_length + array_imm.length + data_segment.length;
      }
      case kExprArrayNewElem: {
        // TODO(14616): Add check that array sharedness == segment sharedness?
        NON_CONST_ONLY
        ArrayIndexImmediate array_imm(this, this->pc_ + opcode_length,
                                      validate);
        if (!this->Validate(this->pc_ + opcode_length, array_imm)) return 0;
        ValueType element_type = array_imm.array_type->element_type();
        if (element_type.is_numeric()) {
          this->DecodeError(
              "array.new_elem can only be used with reference-type arrays, "
              "found array type #%d instead",
              array_imm.index);
          return 0;
        }
        const uint8_t* elem_index_pc =
            this->pc_ + opcode_length + array_imm.length;
        IndexImmediate elem_segment(this, elem_index_pc, "element segment",
                                    validate);
        if (!this->ValidateElementSegment(elem_index_pc, elem_segment)) {
          return 0;
        }

        ValueType elem_segment_type =
            this->module_->elem_segments[elem_segment.index].type;
        if (V8_UNLIKELY(
                !IsSubtypeOf(elem_segment_type, element_type, this->module_))) {
          this->DecodeError(
              "array.new_elem: segment type %s is not a subtype of array "
              "element type %s",
              elem_segment_type.name().c_str(), element_type.name().c_str());
          return 0;
        }

        auto [offset, length] = Pop(kWasmI32, kWasmI32);
        Value* array = Push(ValueType::Ref(array_imm.index));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayNewSegment, array_imm,
                                           elem_segment, offset, length, array);
        return opcode_length + array_imm.length + elem_segment.length;
      }
      case kExprArrayInitData: {
        NON_CONST_ONLY
        // TODO(14616): Add check that array sharedness == segment sharedness?
        ArrayIndexImmediate array_imm(this, this->pc_ + opcode_length,
                                      validate);
        if (!this->Validate(this->pc_ + opcode_length, array_imm)) return 0;
        if (!array_imm.array_type->mutability()) {
          this->DecodeError(
              "array.init_data can only be used with mutable arrays, found "
              "array type #%d instead",
              array_imm.index);
          return 0;
        }
        ValueType element_type = array_imm.array_type->element_type();
        if (element_type.is_reference()) {
          this->DecodeError(
              "array.init_data can only be used with numeric-type arrays, "
              "found array type #%d instead",
              array_imm.index);
          return 0;
        }
        const uint8_t* data_index_pc =
            this->pc_ + opcode_length + array_imm.length;
        IndexImmediate data_segment(this, data_index_pc, "data segment",
                                    validate);
        if (!this->ValidateDataSegment(data_index_pc, data_segment)) return 0;

        auto [array, array_index, data_offset, length] = Pop(
            ValueType::RefNull(array_imm.index), kWasmI32, kWasmI32, kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ArrayInitSegment, array_imm,
                                           data_segment, array, array_index,
                                           data_offset, length);
        retur
"""


```