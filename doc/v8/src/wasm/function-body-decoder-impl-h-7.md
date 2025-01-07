Response:
My thinking process for answering the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ header file, specifically focusing on its role in decoding WebAssembly function bodies within the V8 JavaScript engine. It also emphasizes identifying connections to JavaScript, potential programming errors, and its position within a larger series.

2. **Initial Analysis of the Code Snippet:**  I quickly scan the code and notice a few key patterns:
    * **`case kExpr...` blocks:**  This strongly suggests a switch statement handling different WebAssembly opcodes.
    * **`Pop(...)` and `Push(...)`:** These function calls likely manipulate a stack, which is a common pattern in virtual machines and compilers. The `kWasm...` prefixes indicate WebAssembly-specific types.
    * **`CALL_INTERFACE_IF_OK_AND_REACHABLE(...)`:**  This macro suggests calling out to other parts of the V8 engine to handle the actual execution or interpretation of the opcodes.
    * **String-related opcodes:** A significant portion of the code deals with `kExprString...` operations, indicating support for WebAssembly's stringref proposal.
    * **Atomic opcodes:** The `kAtomicPrefix` and related cases suggest support for multithreading primitives.
    * **Numeric opcodes:**  `kNumericPrefix` and related cases handle standard WebAssembly numerical operations and memory manipulation.

3. **Identify Core Functionality:** Based on the patterns, I deduce that the primary function of this code is to *decode* WebAssembly bytecode. It takes an opcode and, based on that opcode, performs actions such as:
    * Popping values from a stack.
    * Performing operations on those values.
    * Pushing results back onto the stack.
    * Potentially calling out to other V8 components.
    * Handling different data types (integers, floats, references, strings, etc.).

4. **Connect to JavaScript:** I know that WebAssembly is designed to be integrated with JavaScript. The string-related opcodes provide a clear link. JavaScript has native string manipulation capabilities. I hypothesize that these WebAssembly string operations are designed to be interoperable with JavaScript strings. This leads to the idea of providing JavaScript examples that demonstrate similar string operations.

5. **Consider Potential Programming Errors:** When dealing with stacks and specific data types, common errors arise from:
    * **Type mismatches:**  Trying to use a value of the wrong type for an operation.
    * **Stack underflow/overflow:**  Trying to pop from an empty stack or pushing too much onto a limited stack.
    * **Incorrect memory access:** Trying to read or write to invalid memory locations. The atomic operations also bring in the possibility of race conditions in concurrent programming.

6. **Address the `.tq` Extension:** The request explicitly asks about the `.tq` extension. I know that Torque is V8's internal language for implementing built-in functions. If this file had that extension, it would mean the decoding logic itself was implemented in Torque. Since it doesn't, I note that it's standard C++.

7. **Handle Code Logic and Examples:** For the string operations, I choose a few representative examples (`StringEncodeWtf16`, `StringConcat`, `StringViewWtf16GetCodeunit`). For each, I create a simplified hypothetical scenario with input and output to illustrate the function's behavior.

8. **Address the "Part 8 of 9" Aspect:** This indicates the code snippet is part of a larger decoding process. I infer that earlier parts likely handle initial parsing and control flow, while the final part might deal with completing the decoding process or connecting the decoded representation to the execution engine.

9. **Structure the Answer:** I organize my findings into clear sections based on the request's prompts:
    * Functionality summary.
    * Explanation of the `.tq` extension.
    * JavaScript relationship with examples.
    * Code logic examples with input/output.
    * Common programming errors.
    * Summary of the part's role within the larger process.

10. **Refine and Review:**  I review my answer to ensure clarity, accuracy, and completeness. I double-check that I've addressed all aspects of the request. I make sure the JavaScript examples are relevant and easy to understand. I also ensure the error examples are plausible.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive and informative response that addresses all the requirements of the request. The key is to break down the code into its constituent parts, understand the underlying principles of WebAssembly and virtual machines, and connect the specific details to the broader context of the V8 engine and JavaScript.
```cpp
pe addr_type = MemoryAddressType(imm.memory);
        auto [str, addr] = Pop(kWasmStringRef, addr_type);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringEncodeWtf16, imm, str, addr,
                                           result);
        return opcode_length + imm.length;
      }
      case kExprStringConcat: {
        NON_CONST_ONLY
        auto [head, tail] = Pop(kWasmStringRef, kWasmStringRef);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringConcat, head, tail, result);
        return opcode_length;
      }
      case kExprStringEq: {
        NON_CONST_ONLY
        auto [a, b] = Pop(kWasmStringRef, kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringEq, a, b, result);
        return opcode_length;
      }
      case kExprStringIsUSVSequence: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringIsUSVSequence, str, result);
        return opcode_length;
      }
      case kExprStringAsWtf8: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(ValueType::Ref(HeapType::kStringViewWtf8));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringAsWtf8, str, result);
        return opcode_length;
      }
      case kExprStringViewWtf8Advance: {
        NON_CONST_ONLY
        auto [view, pos, bytes] = Pop(kWasmStringViewWtf8, kWasmI32, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf8Advance, view, pos,
                                           bytes, result);
        return opcode_length;
      }
      case kExprStringViewWtf8EncodeUtf8:
        return DecodeStringViewWtf8Encode(unibrow::Utf8Variant::kUtf8,
                                          opcode_length);
      case kExprStringViewWtf8EncodeLossyUtf8:
        return DecodeStringViewWtf8Encode(unibrow::Utf8Variant::kLossyUtf8,
                                          opcode_length);
      case kExprStringViewWtf8EncodeWtf8:
        return DecodeStringViewWtf8Encode(unibrow::Utf8Variant::kWtf8,
                                          opcode_length);
      case kExprStringViewWtf8Slice: {
        NON_CONST_ONLY
        auto [view, start, end] = Pop(kWasmStringViewWtf8, kWasmI32, kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf8Slice, view, start,
                                           end, result);
        return opcode_length;
      }
      case kExprStringAsWtf16: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(ValueType::Ref(HeapType::kStringViewWtf16));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringAsWtf16, str, result);
        return opcode_length;
      }
      case kExprStringViewWtf16Length: {
        NON_CONST_ONLY
        Value view = Pop(kWasmStringViewWtf16);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringMeasureWtf16, view, result);
        return opcode_length;
      }
      case kExprStringViewWtf16GetCodeunit: {
        NON_CONST_ONLY
        auto [view, pos] = Pop(kWasmStringViewWtf16, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf16GetCodeUnit, view,
                                           pos, result);
        return opcode_length;
      }
      case kExprStringViewWtf16Encode: {
        NON_CONST_ONLY
        MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType addr_type = MemoryAddressType(imm.memory);
        auto [view, addr, pos, codeunits] =
            Pop(kWasmStringViewWtf16, addr_type, kWasmI32, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf16Encode, imm, view,
                                           addr, pos, codeunits, result);
        return opcode_length + imm.length;
      }
      case kExprStringViewWtf16Slice: {
        NON_CONST_ONLY
        auto [view, start, end] = Pop(kWasmStringViewWtf16, kWasmI32, kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf16Slice, view, start,
                                           end, result);
        return opcode_length;
      }
      case kExprStringAsIter: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(ValueType::Ref(HeapType::kStringViewIter));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringAsIter, str, result);
        return opcode_length;
      }
      case kExprStringViewIterNext: {
        NON_CONST_ONLY
        Value view = Pop(kWasmStringViewIter);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewIterNext, view, result);
        return opcode_length;
      }
      case kExprStringViewIterAdvance: {
        NON_CONST_ONLY
        auto [view, codepoints] = Pop(kWasmStringViewIter, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewIterAdvance, view,
                                           codepoints, result);
        return opcode_length;
      }
      case kExprStringViewIterRewind: {
        NON_CONST_ONLY
        auto [view, codepoints] = Pop(kWasmStringViewIter, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewIterRewind, view,
                                           codepoints, result);
        return opcode_length;
      }
      case kExprStringViewIterSlice: {
        NON_CONST_ONLY
        auto [view, codepoints] = Pop(kWasmStringViewIter, kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewIterSlice, view,
                                           codepoints, result);
        return opcode_length;
      }
      case kExprStringNewUtf8Array:
        return DecodeStringNewWtf8Array(unibrow::Utf8Variant::kUtf8,
                                        opcode_length);
      case kExprStringNewUtf8ArrayTry:
        return DecodeStringNewWtf8Array(unibrow::Utf8Variant::kUtf8NoTrap,
                                        opcode_length);
      case kExprStringNewLossyUtf8Array:
        return DecodeStringNewWtf8Array(unibrow::Utf8Variant::kLossyUtf8,
                                        opcode_length);
      case kExprStringNewWtf8Array:
        return DecodeStringNewWtf8Array(unibrow::Utf8Variant::kWtf8,
                                        opcode_length);
      case kExprStringNewWtf16Array: {
        NON_CONST_ONLY
        Value end = Pop(2, kWasmI32);
        Value start = Pop(1, kWasmI32);
        Value array = PopPackedArray(0, kWasmI16, WasmArrayAccess::kRead);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringNewWtf16Array, array, start,
                                           end, result);
        return opcode_length;
      }
      case kExprStringEncodeUtf8Array:
        return DecodeStringEncodeWtf8Array(unibrow::Utf8Variant::kUtf8,
                                           opcode_length);
      case kExprStringEncodeLossyUtf8Array:
        return DecodeStringEncodeWtf8Array(unibrow::Utf8Variant::kLossyUtf8,
                                           opcode_length);
      case kExprStringEncodeWtf8Array:
        return DecodeStringEncodeWtf8Array(unibrow::Utf8Variant::kWtf8,
                                           opcode_length);
      case kExprStringEncodeWtf16Array: {
        NON_CONST_ONLY
        Value start = Pop(2, kWasmI32);
        Value array = PopPackedArray(1, kWasmI16, WasmArrayAccess::kWrite);
        Value str = Pop(0, kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringEncodeWtf16Array, str, array,
                                           start, result);
        return opcode_length;
      }
      case kExprStringCompare: {
        NON_CONST_ONLY
        auto [lhs, rhs] = Pop(kWasmStringRef, kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringCompare, lhs, rhs, result);
        return opcode_length;
      }
      case kExprStringFromCodePoint: {
        NON_CONST_ONLY
        Value code_point = Pop(kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringFromCodePoint, code_point,
                                           result);
        return opcode_length;
      }
      case kExprStringHash: {
        NON_CONST_ONLY
        Value string = Pop(kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringHash, string, result);
        return opcode_length;
      }
      default:
        this->DecodeError("invalid stringref opcode: %x", opcode);
        return 0;
    }
  }
#undef NON_CONST_ONLY

  uint32_t DecodeAtomicOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    // Fast check for out-of-range opcodes (only allow 0xfeXX).
    if (!VALIDATE((opcode >> 8) == kAtomicPrefix)) {
      this->DecodeError("invalid atomic opcode: 0x%x", opcode);
      return 0;
    }

    MachineType memtype;
    switch (opcode) {
#define CASE_ATOMIC_STORE_OP(Name, Type)          \
  case kExpr##Name: {                             \
    memtype = MachineType::Type();                \
    break; /* to generic mem access code below */ \
  }
      ATOMIC_STORE_OP_LIST(CASE_ATOMIC_STORE_OP)
#undef CASE_ATOMIC_STORE_OP
#define CASE_ATOMIC_OP(Name, Type)                \
  case kExpr##Name: {                             \
    memtype = MachineType::Type();                \
    break; /* to generic mem access code below */ \
  }
      ATOMIC_OP_LIST(CASE_ATOMIC_OP)
#undef CASE_ATOMIC_OP
      case kExprAtomicFence: {
        uint8_t zero = this->template read_u8<ValidationTag>(
            this->pc_ + opcode_length, "zero");
        if (!VALIDATE(zero == 0)) {
          this->DecodeError(this->pc_ + opcode_length,
                            "invalid atomic operand");
          return 0;
        }
        CALL_INTERFACE_IF_OK_AND_REACHABLE(AtomicFence);
        return 1 + opcode_length;
      }
      default:
        // This path is only possible if we are validating.
        V8_ASSUME(ValidationTag::validate);
        this->DecodeError("invalid atomic opcode: 0x%x", opcode);
        return 0;
    }

    const uint32_t element_size_log2 =
        ElementSizeLog2Of(memtype.representation());
    MemoryAccessImmediate imm =
        MakeMemoryAccessImmediate(opcode_length, element_size_log2);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return false;
    if (!VALIDATE(imm.alignment == element_size_log2)) {
      this->DecodeError(this->pc_,
                        "invalid alignment for atomic operation; expected "
                        "alignment is %u, actual alignment is %u",
                        element_size_log2, imm.alignment);
    }

    const FunctionSig* sig =
        WasmOpcodes::SignatureForAtomicOp(opcode, imm.memory->is_memory64());
    V8_ASSUME(sig != nullptr);
    PoppedArgVector args = PopArgs(sig);
    Value* result = sig->return_count() ? Push(sig->GetReturn()) : nullptr;
    if (V8_LIKELY(!CheckStaticallyOutOfBounds(imm.memory, memtype.MemSize(),
                                              imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(AtomicOp, opcode, args.data(),
                                         sig->parameter_count(), imm, result);
    }

    return opcode_length + imm.length;
  }

  unsigned DecodeNumericOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    // Fast check for out-of-range opcodes (only allow 0xfcXX).
    // This avoids a dynamic check in signature lookup, and might also help the
    // big switch below.
    if (!VALIDATE((opcode >> 8) == kNumericPrefix)) {
      this->DecodeError("invalid numeric opcode: 0x%x", opcode);
      return 0;
    }

    const FunctionSig* sig = WasmOpcodes::Signature(opcode);
    switch (opcode) {
      case kExprI32SConvertSatF32:
      case kExprI32UConvertSatF32:
      case kExprI32SConvertSatF64:
      case kExprI32UConvertSatF64:
      case kExprI64SConvertSatF32:
      case kExprI64UConvertSatF32:
      case kExprI64SConvertSatF64:
      case kExprI64UConvertSatF64: {
        BuildSimpleOperator(opcode, sig);
        return opcode_length;
      }
      case kExprMemoryInit: {
        MemoryInitImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType mem_type = MemoryAddressType(imm.memory.memory);
        auto [dst, offset, size] = Pop(mem_type, kWasmI32, kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(MemoryInit, imm, dst, offset, size);
        return opcode_length + imm.length;
      }
      case kExprDataDrop: {
        IndexImmediate imm(this, this->pc_ + opcode_length,
                           "data segment index", validate);
        if (!this->ValidateDataSegment(this->pc_ + opcode_length, imm)) {
          return 0;
        }
        CALL_INTERFACE_IF_OK_AND_REACHABLE(DataDrop, imm);
        return opcode_length + imm.length;
      }
      case kExprMemoryCopy: {
        MemoryCopyImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType dst_type = MemoryAddressType(imm.memory_dst.memory);
        ValueType src_type = MemoryAddressType(imm.memory_src.memory);
        // size_type = min(dst_type, src_type), where kI32 < kI64.
        ValueType size_type = dst_type == kWasmI32 ? kWasmI32 : src_type;

        auto [dst, src, size] = Pop(dst_type, src_type, size_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(MemoryCopy, imm, dst, src, size);
        return opcode_length + imm.length;
      }
      case kExprMemoryFill: {
        MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType mem_type = MemoryAddressType(imm.memory);
        auto [dst, value, size] = Pop(mem_type, kWasmI32, mem_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(MemoryFill, imm, dst, value, size);
        return opcode_length + imm.length;
      }
      case kExprTableInit: {
        TableInitImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType table_address_type = TableAddressType(imm.table.table);
        auto [dst, src, size] = Pop(table_address_type, kWasmI32, kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableInit, imm, dst, src, size);
        return opcode_length + imm.length;
      }
      case kExprElemDrop: {
        IndexImmediate imm(this, this->pc_ + opcode_length,
                           "element segment index", validate);
        if (!this->ValidateElementSegment(this->pc_ + opcode_length, imm)) {
          return 0;
        }
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ElemDrop, imm);
        return opcode_length + imm.length;
      }
      case kExprTableCopy: {
        TableCopyImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType dst_type = TableAddressType(imm.table_dst.table);
        ValueType src_type = TableAddressType(imm.table_src.table);
        // size_type = min(dst_type, src_type), where kI32 < kI64.
        ValueType size_type = dst_type == kWasmI32 ? kWasmI32 : src_type;

        auto [dst, src, size] = Pop(dst_type, src_type, size_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableCopy, imm, dst, src, size);
        return opcode_length + imm.length;
      }
      case kExprTableGrow: {
        TableIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType table_address_type = TableAddressType(imm.table);
        auto [value, delta] = Pop(imm.table->type, table_address_type);
        Value* result = Push(table_address_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableGrow, imm, value, delta,
                                           result);
        return opcode_length + imm.length;
      }
      case kExprTableSize: {
        TableIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        Value* result = Push(TableAddressType(imm.table));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableSize, imm, result);
        return opcode_length + imm.length;
      }
      case kExprTableFill: {
        TableIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType table_address_type = TableAddressType(imm.table);
        auto [start, value, count] =
            Pop(table_address_type, imm.table->type, table_address_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableFill, imm, start, value, count);
        return opcode_length + imm.length;
      }
      case kExprF32LoadMemF16: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid numeric opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        return DecodeLoadMem(LoadType::kF32LoadF16, 2);
      }
      case kExprF32StoreMemF16: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid numeric opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        return DecodeStoreMem(StoreType::kF32StoreF16, 2);
      }
      default:
        this->DecodeError("invalid numeric opcode: 0x%x", opcode);
        return 0;
    }
  }

  V8_INLINE Value CreateValue(ValueType type) { return Value{this->pc_, type}; }

  V8_INLINE Value* Push(Value value) {
    DCHECK_IMPLIES(this->ok(), value.type != kWasmVoid);
    if (!VALIDATE(!this->is_shared_ || IsShared(value.type, this->module_))) {
      this->DecodeError(value.pc(), "%s does not have a shared type",
                        SafeOpcodeNameAt(value.pc()));
      return nullptr;
    }
    // {stack_.EnsureMoreCapacity} should have been called before, either in the
    // central decoding loop, or individually if more than one element is
    // pushed.
    stack_.push(value);
    return &stack_.back();
  }

  V8_INLINE Value* Push(ValueType type) { return Push(CreateValue(type)); }

  void PushMergeValues(Control* c, Merge<Value>* merge) {
    if constexpr (decoding_mode == kConstantExpression) return;
    DCHECK_EQ(c, &control_.back());
    DCHECK(merge == &c->start_merge || merge == &c->end_merge);
    stack_.shrink_to(c->stack_depth);
    if (merge->arity == 1) {
      // {stack_.EnsureMoreCapacity} should have been called before in the
      // central decoding loop.
      Push(merge->vals.first);
    } else {
      stack_.EnsureMoreCapacity(merge->arity, this->zone_);
      for (uint32_t i = 0; i < merge->arity; i++) {
        Push(merge->vals.array[i]);
      }
    }
    DCHECK_EQ(c->stack_depth + merge->arity, stack_.size());
  }

  V8_INLINE void PushReturns(ReturnVector values) {
    stack_.EnsureMoreCapacity(static_cast<int>(values.size()), this->zone_);
    for (Value& value : values) Push(value);
  }

  Value* PushReturns(const FunctionSig* sig) {
    size_t return_count = sig->return_count();
    stack_.EnsureMoreCapacity(static_cast<int>(return_count), this->zone_);
    for (size_t i = 0; i < return_count; ++i) {
      Push(sig->GetReturn(i));
    }
    return stack_.end() - return_count;
  }

  // We do not inline these functions because doing so causes a large binary
  // size increase. Not inlining them should not create a performance
  // degradation, because their invocations are guarded by V8_LIKELY.
  V8_NOINLINE V8_PRESERVE_MOST void PopTypeError(int index, Value val,
                                                 const char* expected) {
    this->DecodeError(val.pc(), "%s[%d] expected %s, found %s of type %s",
                      SafeOpcodeNameAt(this->pc_), index, expected,
                      SafeOpcodeNameAt(val.pc()), val.type.name().c_str());
  }

  V8_NOINLINE V8_PRESERVE_MOST void PopTypeError(int index, Value val,
                                                 std::string expected) {
    PopTypeError(index, val, expected.c_str());
  }

  V8_NOINLINE V8_PRESERVE_MOST void PopTypeError(int index, Value val,
                                                 ValueType expected) {
    PopTypeError(index, val, ("type " + expected.name()).c_str());
  }

  V8_NOINLINE V8_PRESERVE_MOST void NotEnoughArgumentsError(int needed,
                                                            int actual) {
    DCHECK_LT(0, needed);
    DCHECK_LE(0, actual);
    DCHECK_LT(actual, needed);
    this->DecodeError(
        "not enough arguments on the stack for %s (need %d, got %d)",
        SafeOpcodeNameAt(this->pc_), needed, actual);
  }

  V8_INLINE Value Pop(int index, ValueType expected) {
    Value value = Pop();
    ValidateStackValue(index, value, expected);
    return value;
  }

  V8_INLINE void ValidateStackValue(int index, Value value,
                                    ValueType expected) {
    if (!VALIDATE(IsSubtypeOf(value.type, expected, this->module_) ||
                  value.type == kWasmBottom || expected == kWasmBottom)) {
      PopTypeError(index, value, expected);
    }
  }

  V8_INLINE Value Pop() {
    DCHECK(!control_.empty());
    uint32_t limit = control_.back().stack_depth;
    if (V8_UNLIKELY(stack_size() <= limit)) {
      // Popping past the current control start in reachable code.
      if (!VALIDATE(control_.back().unreachable())) {
        NotEnoughArgumentsError(1, 0);
      }
      return UnreachableValue(this->pc_);
    }
    Value top_of_stack = stack_.back();
    stack_.pop();
    return top_of_stack;
  }

  V8_INLINE Value Peek(int depth, int index, ValueType expected) {
    Value value = Peek(depth);
    ValidateStackValue(index, value, expected);
    return value;
  }

  V8_INLINE Value Peek(int depth = 0) {
    DCHECK(!control_.empty());
    uint32_t limit = control_.back().stack_depth;
    if (V8_UNLIKELY(stack_.size() <= limit + depth)) {
      // Peeking past the current control start in reachable code.
      if (!VALIDATE(decoding_mode == kFunctionBody &&
                    control_.back().unreachable())) {
        NotEnoughArgumentsError(depth + 1, stack_.size() - limit);
      }
      return UnreachableValue(this->pc_);
    }
    DCHECK_LT(depth, stack_.size());
    return *(stack_.end() - depth - 1);
  }

  V8_INLINE Value Peek(ValueType expected) { return Peek(0, 0, expected); }

  // Pop multiple values at once; faster than multiple individual {Pop}s.
  // Returns an array of the popped values if there are multiple, or the popped
  // value itself if a single type is passed.
  template <typename... ValueTypes,
            typename = std::enable_if_t<
                // Pop is only allowed to be called with ValueType parameters.
                std::conjunction_v<std::is_same<ValueType, ValueTypes>...>>>
  V8_INLINE std::conditional_t<sizeof...(ValueTypes) == 1, Value,
                               std::array<Value, sizeof...(ValueTypes)>>
  Pop(ValueTypes... expected_types) {
    constexpr int kCount = sizeof...(ValueTypes);
    EnsureStackArguments(kCount);
    DCHECK_LE(control_.back().stack_depth, stack_size());
    DCHECK_GE(stack_size() - control_.back().stack_depth, kCount);
    // Note: Popping from the {
Prompt: 
```
这是目录为v8/src/wasm/function-body-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-body-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共9部分，请归纳一下它的功能

"""
pe addr_type = MemoryAddressType(imm.memory);
        auto [str, addr] = Pop(kWasmStringRef, addr_type);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringEncodeWtf16, imm, str, addr,
                                           result);
        return opcode_length + imm.length;
      }
      case kExprStringConcat: {
        NON_CONST_ONLY
        auto [head, tail] = Pop(kWasmStringRef, kWasmStringRef);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringConcat, head, tail, result);
        return opcode_length;
      }
      case kExprStringEq: {
        NON_CONST_ONLY
        auto [a, b] = Pop(kWasmStringRef, kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringEq, a, b, result);
        return opcode_length;
      }
      case kExprStringIsUSVSequence: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringIsUSVSequence, str, result);
        return opcode_length;
      }
      case kExprStringAsWtf8: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(ValueType::Ref(HeapType::kStringViewWtf8));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringAsWtf8, str, result);
        return opcode_length;
      }
      case kExprStringViewWtf8Advance: {
        NON_CONST_ONLY
        auto [view, pos, bytes] = Pop(kWasmStringViewWtf8, kWasmI32, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf8Advance, view, pos,
                                           bytes, result);
        return opcode_length;
      }
      case kExprStringViewWtf8EncodeUtf8:
        return DecodeStringViewWtf8Encode(unibrow::Utf8Variant::kUtf8,
                                          opcode_length);
      case kExprStringViewWtf8EncodeLossyUtf8:
        return DecodeStringViewWtf8Encode(unibrow::Utf8Variant::kLossyUtf8,
                                          opcode_length);
      case kExprStringViewWtf8EncodeWtf8:
        return DecodeStringViewWtf8Encode(unibrow::Utf8Variant::kWtf8,
                                          opcode_length);
      case kExprStringViewWtf8Slice: {
        NON_CONST_ONLY
        auto [view, start, end] = Pop(kWasmStringViewWtf8, kWasmI32, kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf8Slice, view, start,
                                           end, result);
        return opcode_length;
      }
      case kExprStringAsWtf16: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(ValueType::Ref(HeapType::kStringViewWtf16));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringAsWtf16, str, result);
        return opcode_length;
      }
      case kExprStringViewWtf16Length: {
        NON_CONST_ONLY
        Value view = Pop(kWasmStringViewWtf16);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringMeasureWtf16, view, result);
        return opcode_length;
      }
      case kExprStringViewWtf16GetCodeunit: {
        NON_CONST_ONLY
        auto [view, pos] = Pop(kWasmStringViewWtf16, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf16GetCodeUnit, view,
                                           pos, result);
        return opcode_length;
      }
      case kExprStringViewWtf16Encode: {
        NON_CONST_ONLY
        MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType addr_type = MemoryAddressType(imm.memory);
        auto [view, addr, pos, codeunits] =
            Pop(kWasmStringViewWtf16, addr_type, kWasmI32, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf16Encode, imm, view,
                                           addr, pos, codeunits, result);
        return opcode_length + imm.length;
      }
      case kExprStringViewWtf16Slice: {
        NON_CONST_ONLY
        auto [view, start, end] = Pop(kWasmStringViewWtf16, kWasmI32, kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewWtf16Slice, view, start,
                                           end, result);
        return opcode_length;
      }
      case kExprStringAsIter: {
        NON_CONST_ONLY
        Value str = Pop(kWasmStringRef);
        Value* result = Push(ValueType::Ref(HeapType::kStringViewIter));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringAsIter, str, result);
        return opcode_length;
      }
      case kExprStringViewIterNext: {
        NON_CONST_ONLY
        Value view = Pop(kWasmStringViewIter);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewIterNext, view, result);
        return opcode_length;
      }
      case kExprStringViewIterAdvance: {
        NON_CONST_ONLY
        auto [view, codepoints] = Pop(kWasmStringViewIter, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewIterAdvance, view,
                                           codepoints, result);
        return opcode_length;
      }
      case kExprStringViewIterRewind: {
        NON_CONST_ONLY
        auto [view, codepoints] = Pop(kWasmStringViewIter, kWasmI32);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewIterRewind, view,
                                           codepoints, result);
        return opcode_length;
      }
      case kExprStringViewIterSlice: {
        NON_CONST_ONLY
        auto [view, codepoints] = Pop(kWasmStringViewIter, kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringViewIterSlice, view,
                                           codepoints, result);
        return opcode_length;
      }
      case kExprStringNewUtf8Array:
        return DecodeStringNewWtf8Array(unibrow::Utf8Variant::kUtf8,
                                        opcode_length);
      case kExprStringNewUtf8ArrayTry:
        return DecodeStringNewWtf8Array(unibrow::Utf8Variant::kUtf8NoTrap,
                                        opcode_length);
      case kExprStringNewLossyUtf8Array:
        return DecodeStringNewWtf8Array(unibrow::Utf8Variant::kLossyUtf8,
                                        opcode_length);
      case kExprStringNewWtf8Array:
        return DecodeStringNewWtf8Array(unibrow::Utf8Variant::kWtf8,
                                        opcode_length);
      case kExprStringNewWtf16Array: {
        NON_CONST_ONLY
        Value end = Pop(2, kWasmI32);
        Value start = Pop(1, kWasmI32);
        Value array = PopPackedArray(0, kWasmI16, WasmArrayAccess::kRead);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringNewWtf16Array, array, start,
                                           end, result);
        return opcode_length;
      }
      case kExprStringEncodeUtf8Array:
        return DecodeStringEncodeWtf8Array(unibrow::Utf8Variant::kUtf8,
                                           opcode_length);
      case kExprStringEncodeLossyUtf8Array:
        return DecodeStringEncodeWtf8Array(unibrow::Utf8Variant::kLossyUtf8,
                                           opcode_length);
      case kExprStringEncodeWtf8Array:
        return DecodeStringEncodeWtf8Array(unibrow::Utf8Variant::kWtf8,
                                           opcode_length);
      case kExprStringEncodeWtf16Array: {
        NON_CONST_ONLY
        Value start = Pop(2, kWasmI32);
        Value array = PopPackedArray(1, kWasmI16, WasmArrayAccess::kWrite);
        Value str = Pop(0, kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringEncodeWtf16Array, str, array,
                                           start, result);
        return opcode_length;
      }
      case kExprStringCompare: {
        NON_CONST_ONLY
        auto [lhs, rhs] = Pop(kWasmStringRef, kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringCompare, lhs, rhs, result);
        return opcode_length;
      }
      case kExprStringFromCodePoint: {
        NON_CONST_ONLY
        Value code_point = Pop(kWasmI32);
        Value* result = Push(kWasmRefString);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringFromCodePoint, code_point,
                                           result);
        return opcode_length;
      }
      case kExprStringHash: {
        NON_CONST_ONLY
        Value string = Pop(kWasmStringRef);
        Value* result = Push(kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(StringHash, string, result);
        return opcode_length;
      }
      default:
        this->DecodeError("invalid stringref opcode: %x", opcode);
        return 0;
    }
  }
#undef NON_CONST_ONLY

  uint32_t DecodeAtomicOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    // Fast check for out-of-range opcodes (only allow 0xfeXX).
    if (!VALIDATE((opcode >> 8) == kAtomicPrefix)) {
      this->DecodeError("invalid atomic opcode: 0x%x", opcode);
      return 0;
    }

    MachineType memtype;
    switch (opcode) {
#define CASE_ATOMIC_STORE_OP(Name, Type)          \
  case kExpr##Name: {                             \
    memtype = MachineType::Type();                \
    break; /* to generic mem access code below */ \
  }
      ATOMIC_STORE_OP_LIST(CASE_ATOMIC_STORE_OP)
#undef CASE_ATOMIC_STORE_OP
#define CASE_ATOMIC_OP(Name, Type)                \
  case kExpr##Name: {                             \
    memtype = MachineType::Type();                \
    break; /* to generic mem access code below */ \
  }
      ATOMIC_OP_LIST(CASE_ATOMIC_OP)
#undef CASE_ATOMIC_OP
      case kExprAtomicFence: {
        uint8_t zero = this->template read_u8<ValidationTag>(
            this->pc_ + opcode_length, "zero");
        if (!VALIDATE(zero == 0)) {
          this->DecodeError(this->pc_ + opcode_length,
                            "invalid atomic operand");
          return 0;
        }
        CALL_INTERFACE_IF_OK_AND_REACHABLE(AtomicFence);
        return 1 + opcode_length;
      }
      default:
        // This path is only possible if we are validating.
        V8_ASSUME(ValidationTag::validate);
        this->DecodeError("invalid atomic opcode: 0x%x", opcode);
        return 0;
    }

    const uint32_t element_size_log2 =
        ElementSizeLog2Of(memtype.representation());
    MemoryAccessImmediate imm =
        MakeMemoryAccessImmediate(opcode_length, element_size_log2);
    if (!this->Validate(this->pc_ + opcode_length, imm)) return false;
    if (!VALIDATE(imm.alignment == element_size_log2)) {
      this->DecodeError(this->pc_,
                        "invalid alignment for atomic operation; expected "
                        "alignment is %u, actual alignment is %u",
                        element_size_log2, imm.alignment);
    }

    const FunctionSig* sig =
        WasmOpcodes::SignatureForAtomicOp(opcode, imm.memory->is_memory64());
    V8_ASSUME(sig != nullptr);
    PoppedArgVector args = PopArgs(sig);
    Value* result = sig->return_count() ? Push(sig->GetReturn()) : nullptr;
    if (V8_LIKELY(!CheckStaticallyOutOfBounds(imm.memory, memtype.MemSize(),
                                              imm.offset))) {
      CALL_INTERFACE_IF_OK_AND_REACHABLE(AtomicOp, opcode, args.data(),
                                         sig->parameter_count(), imm, result);
    }

    return opcode_length + imm.length;
  }

  unsigned DecodeNumericOpcode(WasmOpcode opcode, uint32_t opcode_length) {
    // Fast check for out-of-range opcodes (only allow 0xfcXX).
    // This avoids a dynamic check in signature lookup, and might also help the
    // big switch below.
    if (!VALIDATE((opcode >> 8) == kNumericPrefix)) {
      this->DecodeError("invalid numeric opcode: 0x%x", opcode);
      return 0;
    }

    const FunctionSig* sig = WasmOpcodes::Signature(opcode);
    switch (opcode) {
      case kExprI32SConvertSatF32:
      case kExprI32UConvertSatF32:
      case kExprI32SConvertSatF64:
      case kExprI32UConvertSatF64:
      case kExprI64SConvertSatF32:
      case kExprI64UConvertSatF32:
      case kExprI64SConvertSatF64:
      case kExprI64UConvertSatF64: {
        BuildSimpleOperator(opcode, sig);
        return opcode_length;
      }
      case kExprMemoryInit: {
        MemoryInitImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType mem_type = MemoryAddressType(imm.memory.memory);
        auto [dst, offset, size] = Pop(mem_type, kWasmI32, kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(MemoryInit, imm, dst, offset, size);
        return opcode_length + imm.length;
      }
      case kExprDataDrop: {
        IndexImmediate imm(this, this->pc_ + opcode_length,
                           "data segment index", validate);
        if (!this->ValidateDataSegment(this->pc_ + opcode_length, imm)) {
          return 0;
        }
        CALL_INTERFACE_IF_OK_AND_REACHABLE(DataDrop, imm);
        return opcode_length + imm.length;
      }
      case kExprMemoryCopy: {
        MemoryCopyImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType dst_type = MemoryAddressType(imm.memory_dst.memory);
        ValueType src_type = MemoryAddressType(imm.memory_src.memory);
        // size_type = min(dst_type, src_type), where kI32 < kI64.
        ValueType size_type = dst_type == kWasmI32 ? kWasmI32 : src_type;

        auto [dst, src, size] = Pop(dst_type, src_type, size_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(MemoryCopy, imm, dst, src, size);
        return opcode_length + imm.length;
      }
      case kExprMemoryFill: {
        MemoryIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType mem_type = MemoryAddressType(imm.memory);
        auto [dst, value, size] = Pop(mem_type, kWasmI32, mem_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(MemoryFill, imm, dst, value, size);
        return opcode_length + imm.length;
      }
      case kExprTableInit: {
        TableInitImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType table_address_type = TableAddressType(imm.table.table);
        auto [dst, src, size] = Pop(table_address_type, kWasmI32, kWasmI32);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableInit, imm, dst, src, size);
        return opcode_length + imm.length;
      }
      case kExprElemDrop: {
        IndexImmediate imm(this, this->pc_ + opcode_length,
                           "element segment index", validate);
        if (!this->ValidateElementSegment(this->pc_ + opcode_length, imm)) {
          return 0;
        }
        CALL_INTERFACE_IF_OK_AND_REACHABLE(ElemDrop, imm);
        return opcode_length + imm.length;
      }
      case kExprTableCopy: {
        TableCopyImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType dst_type = TableAddressType(imm.table_dst.table);
        ValueType src_type = TableAddressType(imm.table_src.table);
        // size_type = min(dst_type, src_type), where kI32 < kI64.
        ValueType size_type = dst_type == kWasmI32 ? kWasmI32 : src_type;

        auto [dst, src, size] = Pop(dst_type, src_type, size_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableCopy, imm, dst, src, size);
        return opcode_length + imm.length;
      }
      case kExprTableGrow: {
        TableIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType table_address_type = TableAddressType(imm.table);
        auto [value, delta] = Pop(imm.table->type, table_address_type);
        Value* result = Push(table_address_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableGrow, imm, value, delta,
                                           result);
        return opcode_length + imm.length;
      }
      case kExprTableSize: {
        TableIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        Value* result = Push(TableAddressType(imm.table));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableSize, imm, result);
        return opcode_length + imm.length;
      }
      case kExprTableFill: {
        TableIndexImmediate imm(this, this->pc_ + opcode_length, validate);
        if (!this->Validate(this->pc_ + opcode_length, imm)) return 0;
        ValueType table_address_type = TableAddressType(imm.table);
        auto [start, value, count] =
            Pop(table_address_type, imm.table->type, table_address_type);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(TableFill, imm, start, value, count);
        return opcode_length + imm.length;
      }
      case kExprF32LoadMemF16: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid numeric opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        return DecodeLoadMem(LoadType::kF32LoadF16, 2);
      }
      case kExprF32StoreMemF16: {
        if (!v8_flags.experimental_wasm_fp16) {
          this->DecodeError(
              "invalid numeric opcode: 0x%x, "
              "enable with --experimental-wasm-fp16",
              opcode);
          return 0;
        }
        return DecodeStoreMem(StoreType::kF32StoreF16, 2);
      }
      default:
        this->DecodeError("invalid numeric opcode: 0x%x", opcode);
        return 0;
    }
  }

  V8_INLINE Value CreateValue(ValueType type) { return Value{this->pc_, type}; }

  V8_INLINE Value* Push(Value value) {
    DCHECK_IMPLIES(this->ok(), value.type != kWasmVoid);
    if (!VALIDATE(!this->is_shared_ || IsShared(value.type, this->module_))) {
      this->DecodeError(value.pc(), "%s does not have a shared type",
                        SafeOpcodeNameAt(value.pc()));
      return nullptr;
    }
    // {stack_.EnsureMoreCapacity} should have been called before, either in the
    // central decoding loop, or individually if more than one element is
    // pushed.
    stack_.push(value);
    return &stack_.back();
  }

  V8_INLINE Value* Push(ValueType type) { return Push(CreateValue(type)); }

  void PushMergeValues(Control* c, Merge<Value>* merge) {
    if constexpr (decoding_mode == kConstantExpression) return;
    DCHECK_EQ(c, &control_.back());
    DCHECK(merge == &c->start_merge || merge == &c->end_merge);
    stack_.shrink_to(c->stack_depth);
    if (merge->arity == 1) {
      // {stack_.EnsureMoreCapacity} should have been called before in the
      // central decoding loop.
      Push(merge->vals.first);
    } else {
      stack_.EnsureMoreCapacity(merge->arity, this->zone_);
      for (uint32_t i = 0; i < merge->arity; i++) {
        Push(merge->vals.array[i]);
      }
    }
    DCHECK_EQ(c->stack_depth + merge->arity, stack_.size());
  }

  V8_INLINE void PushReturns(ReturnVector values) {
    stack_.EnsureMoreCapacity(static_cast<int>(values.size()), this->zone_);
    for (Value& value : values) Push(value);
  }

  Value* PushReturns(const FunctionSig* sig) {
    size_t return_count = sig->return_count();
    stack_.EnsureMoreCapacity(static_cast<int>(return_count), this->zone_);
    for (size_t i = 0; i < return_count; ++i) {
      Push(sig->GetReturn(i));
    }
    return stack_.end() - return_count;
  }

  // We do not inline these functions because doing so causes a large binary
  // size increase. Not inlining them should not create a performance
  // degradation, because their invocations are guarded by V8_LIKELY.
  V8_NOINLINE V8_PRESERVE_MOST void PopTypeError(int index, Value val,
                                                 const char* expected) {
    this->DecodeError(val.pc(), "%s[%d] expected %s, found %s of type %s",
                      SafeOpcodeNameAt(this->pc_), index, expected,
                      SafeOpcodeNameAt(val.pc()), val.type.name().c_str());
  }

  V8_NOINLINE V8_PRESERVE_MOST void PopTypeError(int index, Value val,
                                                 std::string expected) {
    PopTypeError(index, val, expected.c_str());
  }

  V8_NOINLINE V8_PRESERVE_MOST void PopTypeError(int index, Value val,
                                                 ValueType expected) {
    PopTypeError(index, val, ("type " + expected.name()).c_str());
  }

  V8_NOINLINE V8_PRESERVE_MOST void NotEnoughArgumentsError(int needed,
                                                            int actual) {
    DCHECK_LT(0, needed);
    DCHECK_LE(0, actual);
    DCHECK_LT(actual, needed);
    this->DecodeError(
        "not enough arguments on the stack for %s (need %d, got %d)",
        SafeOpcodeNameAt(this->pc_), needed, actual);
  }

  V8_INLINE Value Pop(int index, ValueType expected) {
    Value value = Pop();
    ValidateStackValue(index, value, expected);
    return value;
  }

  V8_INLINE void ValidateStackValue(int index, Value value,
                                    ValueType expected) {
    if (!VALIDATE(IsSubtypeOf(value.type, expected, this->module_) ||
                  value.type == kWasmBottom || expected == kWasmBottom)) {
      PopTypeError(index, value, expected);
    }
  }

  V8_INLINE Value Pop() {
    DCHECK(!control_.empty());
    uint32_t limit = control_.back().stack_depth;
    if (V8_UNLIKELY(stack_size() <= limit)) {
      // Popping past the current control start in reachable code.
      if (!VALIDATE(control_.back().unreachable())) {
        NotEnoughArgumentsError(1, 0);
      }
      return UnreachableValue(this->pc_);
    }
    Value top_of_stack = stack_.back();
    stack_.pop();
    return top_of_stack;
  }

  V8_INLINE Value Peek(int depth, int index, ValueType expected) {
    Value value = Peek(depth);
    ValidateStackValue(index, value, expected);
    return value;
  }

  V8_INLINE Value Peek(int depth = 0) {
    DCHECK(!control_.empty());
    uint32_t limit = control_.back().stack_depth;
    if (V8_UNLIKELY(stack_.size() <= limit + depth)) {
      // Peeking past the current control start in reachable code.
      if (!VALIDATE(decoding_mode == kFunctionBody &&
                    control_.back().unreachable())) {
        NotEnoughArgumentsError(depth + 1, stack_.size() - limit);
      }
      return UnreachableValue(this->pc_);
    }
    DCHECK_LT(depth, stack_.size());
    return *(stack_.end() - depth - 1);
  }

  V8_INLINE Value Peek(ValueType expected) { return Peek(0, 0, expected); }

  // Pop multiple values at once; faster than multiple individual {Pop}s.
  // Returns an array of the popped values if there are multiple, or the popped
  // value itself if a single type is passed.
  template <typename... ValueTypes,
            typename = std::enable_if_t<
                // Pop is only allowed to be called with ValueType parameters.
                std::conjunction_v<std::is_same<ValueType, ValueTypes>...>>>
  V8_INLINE std::conditional_t<sizeof...(ValueTypes) == 1, Value,
                               std::array<Value, sizeof...(ValueTypes)>>
  Pop(ValueTypes... expected_types) {
    constexpr int kCount = sizeof...(ValueTypes);
    EnsureStackArguments(kCount);
    DCHECK_LE(control_.back().stack_depth, stack_size());
    DCHECK_GE(stack_size() - control_.back().stack_depth, kCount);
    // Note: Popping from the {FastZoneVector} does not invalidate the old (now
    // out-of-range) elements.
    stack_.pop(kCount);
    auto ValidateAndGetNextArg = [this, i = 0](ValueType type) mutable {
      ValidateStackValue(i, stack_.end()[i], type);
      return stack_.end()[i++];
    };
    return {ValidateAndGetNextArg(expected_types)...};
  }

  Value PopPackedArray(uint32_t operand_index, ValueType expected_element_type,
                       WasmArrayAccess access) {
    Value array = Pop();
    if (array.type.is_bottom()) {
      // We are in a polymorphic stack. Leave the stack as it is.
      DCHECK(!current_code_reachable_and_ok_);
      return array;
    }
    // Inputs of type "none" are okay due to implicit upcasting. The stringref
    // spec doesn't say this explicitly yet, but it's consistent with the rest
    // of Wasm. (Of course such inputs will trap at runtime.) See:
    // https://github.com/WebAssembly/stringref/issues/66
    if (array.type.is_reference_to(HeapType::kNone)) return array;
    if (VALIDATE(array.type.is_object_reference() && array.type.has_index())) {
      ModuleTypeIndex ref_index = array.type.ref_index();
      if (VALIDATE(this->module_->has_array(ref_index))) {
        const ArrayType* array_type = this->module_->array_type(ref_index);
        if (VALIDATE(array_type->element_type() == expected_element_type &&
                     (access == WasmArrayAccess::kRead ||
                      array_type->mutability()))) {
          return array;
        }
      }
    }
    PopTypeError(operand_index, array,
                 (std::string("array of ") +
                  (access == WasmArrayAccess::kWrite ? "mutable " : "") +
                  expected_element_type.name())
                     .c_str());
    return array;
  }

  // Drop the top {count} stack elements, or all of them if less than {count}
  // are present.
  V8_INLINE void Drop(int count = 1) {
    DCHECK(!control_.empty());
    uint32_t limit = control_.back().stack_depth;
    if (V8_UNLIKELY(stack_.size() < limit + count)) {
      // Pop what we can.
      count = std::min(count, static_cast<int>(stack_.size() - limit));
    }
    stack_.pop(count);
  }
  // Drop the top stack element if present. Takes a Value input for more
  // descriptive call sites.
  V8_INLINE void Drop(const Value& /* unused */) { Drop(1); }

  enum StackElementsCountMode : bool {
    kNonStrictCounting = false,
    kStrictCounting = true
  };

  enum MergeType {
    kBranchMerge,
    kReturnMerge,
    kFallthroughMerge,
    kInitExprMerge
  };

  enum class PushBranchValues : bool {
    kNo = false,
    kYes = true,
  };
  enum class RewriteStackTypes : bool {
    kNo = false,
    kYes = true,
  };

  // - If the current code is reachable, check if the current stack values are
  //   compatible with {merge} based on their number and types. If
  //   {strict_count}, check that #(stack elements) == {merge->arity}, otherwise
  //   #(stack elements) >= {merge->arity}.
  // - If the current code is unreachable, check if any values that may exist on
  //   top of the stack are compatible with {merge}. If {push_branch_values},
  //   push back to the stack values based on the type of {merge} (this is
  //   needed for conditional branches due to their typing rules, and
  //   fallthroughs so that the outer control finds the expected values on the
  //   stack). TODO(manoskouk): We expect the unreachable-code behavior to
  //   change, either due to relaxation of dead code verification, or the
  //   introduction of subtyping.
  template <StackElementsCountMode strict_count,
            PushBranchValues push_branch_values, MergeType merge_type,
            RewriteStackTypes rewrite_types>
  V8_INLINE bool TypeCheckStackAgainstMerge(Merge<Value>* merge) {
    uint32_t arity = merge->arity;
    uint32_t actual = stack_.size() - control_.back().stack_depth;
    // Handle trivial cases first. Arity 0 is the most common case.
    if (arity == 0 && (!strict_count || actual == 0)) return true;
    // Arity 1 is still common enough that we handle it separately (only doing
    // the most basic subtype check).
    if (arity == 1 && (strict_count ? actual == arity : actual >= arity)) {
      if (stack_.back().type == merge->vals.first.type) return true;
    }
    return TypeCheckStackAgainstMerge_Slow<strict_count, push_branch_values,
                                           merge_type, rewrite_types>(merge);
  }

  // Slow path for {TypeCheckStackAgainstMerge}.
  template <StackElementsCountMode strict_count,
            PushBranchValues push_branch_values, MergeType merge_type,
            RewriteStackTypes rewrite_types>
  V8_PRESERVE_MOST V8_NOINLINE bool TypeCheckStackAgainstMerge_Slow(
      Merge<Value>* merge) {
    constexpr const char* merge_description =
        merge_type == kBranchMerge     ? "branch"
        : merge_type == kReturnMerge   ? "return"
        : merge_type == kInitExprMerge ? "constant expression"
                                       : "fallthru";
    uint32_t arity = merge->arity;
    uint32_t actual = stack_.size() - control_.back().stack_depth;
    // Here we have to check for !unreachable(), because we need to typecheck as
    // if the current code is reachable even if it is spec-only reachable.
    if (V8_LIKELY(decoding_mode == kConstantExpression ||
                  !control_.back().unreachable())) {
      if (V8_UNLIKELY(strict_count ? actual != arity : actual < arity)) {
        this->DecodeError("expected %u elements on the stack for %s, found %u",
                          arity, merge_description, actual);
        return false;
      }
      // Typecheck the topmost {merge->arity} values on the stack.
      Value* stack_values = stack_.end() - arity;
      for (uint32_t i = 0; i < arity; ++i) {
        Value& val = stack_values[i];
        Value& old = (*merge)[i];
        if (!IsSubtypeOf(val.type, old.type, this->module_)) {
          this->DecodeError("type error in %s[%u] (expected %s, got %s)",
                            merge_description, i, old.type.name().c_str(),
                            val.type.name().c_str());
          return false;
        }
        if constexpr (static_cast<bool>(rewrite_types)) {
          // Upcast type on the stack to the target type of the label.
          val.type = old.type;
        }
      }
      return true;
    }
    // Unreachable code validation starts here.
    if (V8_UNLIKELY(strict_count && actual > arity)) {
      this->DecodeError("expected %u elements on the stack for %s, found %u",
                        arity, merge_description, actual);
      return false;
    }
    // TODO(manoskouk): Use similar code as above if we keep unreachable checks.
    for (int i = arity - 1, depth = 0; i >= 0; --i, ++depth) {
      Peek(depth, i, (*merge)[i].type);
    }
    if constexpr (static_cast<bool>(push_branch_values)) {
      uint32_t inserted_value_count =
          static_cast<uint32_t>(EnsureStackArguments(arity));
      if (inserted_value_count > 0) {
        // stack_.EnsureMoreCapacity() may have inserted unreachable values into
        // the bottom of the stack. If so, mark them with the correct type. If
        // drop values were also inserted, disregard them, as they will be
        // dropped anyway.
        Value* stack_base = stack_value(arity);
        for (uint32_t i = 0; i < std::min(arity, inserted_value_count); i++) {
          if (stack_base[i].type == kWasmBottom) {
            stack_base[i].type = (*merge)[i].type;
          }
        }
      }
    }
    return VALIDATE(this->ok());
  }

  template <StackElementsCountMode strict_count, MergeType merge_type>
  bool DoReturn() {
    if (!VALIDATE(
            (TypeCheckStackAgainstMerge<strict_count, PushBranchValues::kNo,
                                        merge_type, RewriteStackTypes::kNo>(
                &control_.front().end_merge)))) {
      return false;
    }
    DCHECK_IMPLIES(current_code_reachable_and_ok_,
                   stack_.size() >= this->sig_->return_count());
    CALL_INTERFACE_IF_OK_AND_REACHABLE(DoReturn, 0);
    EndControl();
    return true;
  }

  int startrel(const uint8_t* ptr) {
    return static_cast<int>(ptr - this->start_);
  }

  void FallThrough() {
    Control* c = &control_.back();
    DCHECK_NE(c->kind, kControlLoop);
    if (!VALIDATE(TypeCheckFallThru())) return;
    CALL_INTERFACE_IF_OK_AND_REACHABLE(FallThruTo, c);
    if (c->reachable()) c->end_merge.reached = true;
  }

  bool TypeCheckOneArmedIf(Control* c) {
    DCHECK(c->is_onearmed_if());
    if (c->end_merge.arity != c->start_merge.arity) {
      this->DecodeError(c->pc(),
                        "start-arity and end-arity of one-armed if must match");
      return false;
    }
    for (uint32_t i = 0; i < c->star
"""


```