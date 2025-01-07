Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/wasm/fuzzing/random-module-generation.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The file name `random-module-generation.cc` strongly suggests that the code is involved in generating random WebAssembly modules. The functions within the snippet seem to correspond to different WASM instructions or operations.

2. **Analyze the Structure:** The code defines a class (implicitly, as it's a part of a larger file) with template methods and regular member functions. The template parameters often involve `WasmOpcode` and `ValueKind`, indicating that the code manipulates WASM instructions and data types. The presence of a `builder_` member suggests interaction with a WASM module building interface.

3. **Examine Key Functions:**  Go through each function and try to infer its purpose based on its name and the WASM opcodes it emits.
    * `atomic_size`, `max_alignment`: These likely deal with the properties of atomic operations in WASM, particularly their size and alignment requirements.
    * `memop`: This function seems to handle memory operations (loads, stores, atomics). It generates an address, potentially with large offsets, and emits the appropriate WASM memory instruction with alignment and memory index.
    * `op_with_prefix`: This appears to handle WASM instructions that require a prefix opcode (like SIMD instructions).
    * `simd_const`, `simd_lane_op`, `simd_lane_memop`, `simd_shuffle`: These functions clearly deal with generating different kinds of SIMD instructions.
    * `drop`:  This function generates a value and then drops it from the stack.
    * `call`: Handles different types of function calls (direct, indirect, reference). It generates arguments based on the function signature and emits the appropriate call instruction. It also manages return values.
    * `Convert`:  Deals with explicit type conversions between numeric WASM types.
    * `local_op`, `get_local`, `set_local`, `tee_local`: These manage local variables (getting, setting, and teeing their values).
    * `i32_const`, `i64_const`: Generate constant integer values.
    * `global_op`, `get_global`, `set_global`: Manage global variables.
    * `select_with_type`: Implements the `select` instruction with a specific type.
    * `throw_or_rethrow`: Generates `throw` and `rethrow` instructions for exception handling.
    * `sequence`: Generates a sequence of values.
    * `memory_size`, `grow_memory`:  Generate instructions to query and grow the linear memory.
    * `ref_null`: Generates a null reference.
    * `get_local_ref`, `new_object`: Handle the creation and retrieval of reference types (structs, arrays, functions).
    * `table_op`, `select_random_table`, `table_get`, `table_set`, `table_size`, `table_grow`, `table_fill`, `table_copy`: Manage table-related operations (getting, setting, growing, copying table entries).
    * `array_get_helper`, `array_get`, `array_get_ref`, `array_len`, `array_copy`, `array_fill`, `array_init_data`, `array_init_elem`, `array_set`: Generate various array manipulation instructions.
    * `i31_get`: Generates instructions to extract values from `i31ref`.
    * `struct_get_helper`, `struct_get`: Generate instructions to access struct fields.

4. **Identify Relationships to JavaScript:**  WASM is the compilation target for JavaScript. The generated WASM modules are executed within a JavaScript environment. This connection should be highlighted. Examples of JavaScript code that might result in the generation of these WASM instructions should be provided. Focus on scenarios where JavaScript features have a direct WASM counterpart (e.g., array manipulation, function calls, memory access).

5. **Consider Potential Errors:**  Think about common programming mistakes related to the WASM instructions being generated. For example, incorrect memory access, type mismatches, or issues with table and array bounds are common sources of errors. Provide illustrative examples.

6. **Address Specific Instructions:**
    * **`.tq` extension:**  Explain that `.tq` signifies Torque code, a language used within V8 for implementing built-in functions. Confirm that this file *does not* have that extension.
    * **Code Logic Inference:**  For functions like `memop`, demonstrate how inputs (e.g., `memory_op`, alignment, offset) lead to the emission of specific WASM bytecode. Provide a concrete example.

7. **Summarize Functionality (Part 2):**  Focus on the operations covered in the provided snippet, which largely involve memory access, SIMD, local and global variables, function calls, type conversions, exception handling, and basic memory management.

8. **Structure the Output:** Organize the information logically with clear headings and bullet points. Start with a general description and then delve into specifics. Address each part of the user's request.

9. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have missed the nuances of the different `call` variants or the specific details of array initialization. Reviewing would help catch these omissions.
```cpp
tomicXor8U:
      case kExprI64AtomicExchange8U:
      case kExprI64AtomicCompareExchange8U:
      case kExprS128Load8Splat:
        return 0;
      default:
        return 0;
    }
  }

  template <WasmOpcode memory_op, ValueKind... arg_kinds>
  void memop(DataRange* data) {
    // Atomic operations need to be aligned exactly to their max alignment.
    const bool is_atomic = memory_op >> 8 == kAtomicPrefix;
    const uint8_t align = is_atomic ? max_alignment(memory_op)
                                    : data->getPseudoRandom<uint8_t>() %
                                          (max_alignment(memory_op) + 1);

    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    uint64_t offset = data->get<uint16_t>();
    // With a 1/256 chance generate potentially very large offsets.
    if ((offset & 0xff) == 0xff) {
      offset = builder_->builder()->IsMemory64(memory_index)
                   ? data->getPseudoRandom<uint64_t>() & 0x1ffffffff
                   : data->getPseudoRandom<uint32_t>();
    }

    // Generate the index and the arguments, if any.
    builder_->builder()->IsMemory64(memory_index)
        ? Generate<kI64, arg_kinds...>(data)
        : Generate<kI32, arg_kinds...>(data);

    // Format of the instruction (supports multi-memory):
    // memory_op (align | 0x40) memory_index offset
    if (WasmOpcodes::IsPrefixOpcode(static_cast<WasmOpcode>(memory_op >> 8))) {
      DCHECK(memory_op >> 8 == kAtomicPrefix || memory_op >> 8 == kSimdPrefix);
      builder_->EmitWithPrefix(memory_op);
    } else {
      builder_->Emit(memory_op);
    }
    builder_->EmitU32V(align | 0x40);
    builder_->EmitU32V(memory_index);
    builder_->EmitU64V(offset);
  }

  template <WasmOpcode Op, ValueKind... Args>
  void op_with_prefix(DataRange* data) {
    Generate<Args...>(data);
    builder_->EmitWithPrefix(Op);
  }

  void simd_const(DataRange* data) {
    builder_->EmitWithPrefix(kExprS128Const);
    for (int i = 0; i < kSimd128Size; i++) {
      builder_->EmitByte(data->getPseudoRandom<uint8_t>());
    }
  }

  template <WasmOpcode Op, int lanes, ValueKind... Args>
  void simd_lane_op(DataRange* data) {
    Generate<Args...>(data);
    builder_->EmitWithPrefix(Op);
    builder_->EmitByte(data->get<uint8_t>() % lanes);
  }

  template <WasmOpcode Op, int lanes, ValueKind... Args>
  void simd_lane_memop(DataRange* data) {
    // Simd load/store instructions that have a lane immediate.
    memop<Op, Args...>(data);
    builder_->EmitByte(data->get<uint8_t>() % lanes);
  }

  void simd_shuffle(DataRange* data) {
    Generate<kS128, kS128>(data);
    builder_->EmitWithPrefix(kExprI8x16Shuffle);
    for (int i = 0; i < kSimd128Size; i++) {
      builder_->EmitByte(static_cast<uint8_t>(data->get<uint8_t>() % 32));
    }
  }

  void drop(DataRange* data) {
    Generate(GetValueType<options>(
                 data, static_cast<uint32_t>(functions_.size() +
                                             structs_.size() + arrays_.size())),
             data);
    builder_->Emit(kExprDrop);
  }

  enum CallKind { kCallDirect, kCallIndirect, kCallRef };

  template <ValueKind wanted_kind>
  void call(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallDirect);
  }

  template <ValueKind wanted_kind>
  void call_indirect(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallIndirect);
  }

  template <ValueKind wanted_kind>
  void call_ref(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallRef);
  }

  void Convert(ValueType src, ValueType dst) {
    auto idx = [](ValueType t) -> int {
      switch (t.kind()) {
        case kI32:
          return 0;
        case kI64:
          return 1;
        case kF32:
          return 2;
        case kF64:
          return 3;
        default:
          UNREACHABLE();
      }
    };
    static constexpr WasmOpcode kConvertOpcodes[] = {
        // {i32, i64, f32, f64} -> i32
        kExprNop, kExprI32ConvertI64, kExprI32SConvertF32, kExprI32SConvertF64,
        // {i32, i64, f32, f64} -> i64
        kExprI64SConvertI32, kExprNop, kExprI64SConvertF32, kExprI64SConvertF64,
        // {i32, i64, f32, f64} -> f32
        kExprF32SConvertI32, kExprF32SConvertI64, kExprNop, kExprF32ConvertF64,
        // {i32, i64, f32, f64} -> f64
        kExprF64SConvertI32, kExprF64SConvertI64, kExprF64ConvertF32, kExprNop};
    int arr_idx = idx(dst) << 2 | idx(src);
    builder_->Emit(kConvertOpcodes[arr_idx]);
  }

  int choose_function_table_index(DataRange* data) {
    int table_count = builder_->builder()->NumTables();
    int start = data->get<uint8_t>() % table_count;
    for (int i = 0; i < table_count; ++i) {
      int index = (start + i) % table_count;
      if (builder_->builder()->GetTableType(index).is_reference_to(
              HeapType::kFunc)) {
        return index;
      }
    }
    FATAL("No funcref table found; table index 0 is expected to be funcref");
  }

  void call(DataRange* data, ValueType wanted_kind, CallKind call_kind) {
    uint8_t random_byte = data->get<uint8_t>();
    int func_index = random_byte % functions_.size();
    ModuleTypeIndex sig_index = functions_[func_index];
    const FunctionSig* sig = builder_->builder()->GetSignature(sig_index);
    // Generate arguments.
    for (size_t i = 0; i < sig->parameter_count(); ++i) {
      Generate(sig->GetParam(i), data);
    }
    // Emit call.
    // If the return types of the callee happen to match the return types of the
    // caller, generate a tail call.
    bool use_return_call = random_byte > 127;
    if (use_return_call &&
        std::equal(sig->returns().begin(), sig->returns().end(),
                   builder_->signature()->returns().begin(),
                   builder_->signature()->returns().end())) {
      if (call_kind == kCallDirect) {
        builder_->EmitWithU32V(kExprReturnCall,
                               NumImportedFunctions() + func_index);
      } else if (call_kind == kCallIndirect) {
        // This will not trap because table[func_index] always contains function
        // func_index.
        uint32_t table_index = choose_function_table_index(data);
        builder_->builder()->IsTable64(table_index)
            ? builder_->EmitI64Const(func_index)
            : builder_->EmitI32Const(func_index);
        builder_->EmitWithU32V(kExprReturnCallIndirect, sig_index);
        builder_->EmitByte(table_index);
      } else {
        GenerateRef(HeapType(sig_index), data);
        builder_->EmitWithU32V(kExprReturnCallRef, sig_index);
      }
      return;
    } else {
      if (call_kind == kCallDirect) {
        builder_->EmitWithU32V(kExprCallFunction,
                               NumImportedFunctions() + func_index);
      } else if (call_kind == kCallIndirect) {
        // This will not trap because table[func_index] always contains function
        // func_index.
        uint32_t table_index = choose_function_table_index(data);
        builder_->builder()->IsTable64(table_index)
            ? builder_->EmitI64Const(func_index)
            : builder_->EmitI32Const(func_index);
        builder_->EmitWithU32V(kExprCallIndirect, sig_index);
        builder_->EmitByte(table_index);
      } else {
        GenerateRef(HeapType(sig_index), data);
        builder_->EmitWithU32V(kExprCallRef, sig_index);
      }
    }
    if (sig->return_count() == 0 && wanted_kind != kWasmVoid) {
      // The call did not generate a value. Thus just generate it here.
      Generate(wanted_kind, data);
      return;
    }
    if (wanted_kind == kWasmVoid) {
      // The call did generate values, but we did not want one.
      for (size_t i = 0; i < sig->return_count(); ++i) {
        builder_->Emit(kExprDrop);
      }
      return;
    }
    auto wanted_types =
        base::VectorOf(&wanted_kind, wanted_kind == kWasmVoid ? 0 : 1);
    ConsumeAndGenerate(sig->returns(), wanted_types, data);
  }

  struct Var {
    uint32_t index;
    ValueType type = kWasmVoid;
    Var() = default;
    Var(uint32_t index, ValueType type) : index(index), type(type) {}
    bool is_valid() const { return type != kWasmVoid; }
  };

  Var GetRandomLocal(DataRange* data) {
    uint32_t num_params =
        static_cast<uint32_t>(builder_->signature()->parameter_count());
    uint32_t num_locals = static_cast<uint32_t>(locals_.size());
    if (num_params + num_locals == 0) return {};
    uint32_t index = data->get<uint8_t>() % (num_params + num_locals);
    ValueType type = index < num_params ? builder_->signature()->GetParam(index)
                                        : locals_[index - num_params];
    return {index, type};
  }

  constexpr static bool is_convertible_kind(ValueKind kind) {
    return kind == kI32 || kind == kI64 || kind == kF32 || kind == kF64;
  }

  template <ValueKind wanted_kind>
  void local_op(DataRange* data, WasmOpcode opcode) {
    static_assert(wanted_kind == kVoid || is_convertible_kind(wanted_kind));
    Var local = GetRandomLocal(data);
    // If there are no locals and no parameters, just generate any value (if a
    // value is needed), or do nothing.
    if (!local.is_valid() || !is_convertible_kind(local.type.kind())) {
      if (wanted_kind == kVoid) return;
      return Generate<wanted_kind>(data);
    }

    if (opcode != kExprLocalGet) Generate(local.type, data);
    builder_->EmitWithU32V(opcode, local.index);
    if (wanted_kind != kVoid && local.type.kind() != wanted_kind) {
      Convert(local.type, ValueType::Primitive(wanted_kind));
    }
  }

  template <ValueKind wanted_kind>
  void get_local(DataRange* data) {
    static_assert(wanted_kind != kVoid, "illegal type");
    local_op<wanted_kind>(data, kExprLocalGet);
  }

  void set_local(DataRange* data) { local_op<kVoid>(data, kExprLocalSet); }

  template <ValueKind wanted_kind>
  void tee_local(DataRange* data) {
    local_op<wanted_kind>(data, kExprLocalTee);
  }

  template <size_t num_bytes>
  void i32_const(DataRange* data) {
    builder_->EmitI32Const(data->getPseudoRandom<int32_t, num_bytes>());
  }

  template <size_t num_bytes>
  void i64_const(DataRange* data) {
    builder_->EmitI64Const(data->getPseudoRandom<int64_t, num_bytes>());
  }

  Var GetRandomGlobal(DataRange* data, bool ensure_mutable) {
    uint32_t index;
    if (ensure_mutable) {
      if (mutable_globals_.empty()) return {};
      index = mutable_globals_[data->get<uint8_t>() % mutable_globals_.size()];
    } else {
      if (globals_.empty()) return {};
      index = data->get<uint8_t>() % globals_.size();
    }
    ValueType type = globals_[index];
    return {index, type};
  }

  template <ValueKind wanted_kind>
  void global_op(DataRange* data) {
    static_assert(wanted_kind == kVoid || is_convertible_kind(wanted_kind));
    constexpr bool is_set = wanted_kind == kVoid;
    Var global = GetRandomGlobal(data, is_set);
    // If there are no globals, just generate any value (if a value is needed),
    // or do nothing.
    if (!global.is_valid() || !is_convertible_kind(global.type.kind())) {
      if (wanted_kind == kVoid) return;
      return Generate<wanted_kind>(data);
    }

    if (is_set) Generate(global.type, data);
    builder_->EmitWithU32V(is_set ? kExprGlobalSet : kExprGlobalGet,
                           global.index);
    if (!is_set && global.type.kind() != wanted_kind) {
      Convert(global.type, ValueType::Primitive(wanted_kind));
    }
  }

  template <ValueKind wanted_kind>
  void get_global(DataRange* data) {
    static_assert(wanted_kind != kVoid, "illegal type");
    global_op<wanted_kind>(data);
  }

  template <ValueKind select_kind>
  void select_with_type(DataRange* data) {
    static_assert(select_kind != kVoid, "illegal kind for select");
    Generate<select_kind, select_kind, kI32>(data);
    // num_types is always 1.
    uint8_t num_types = 1;
    builder_->EmitWithU8U8(kExprSelectWithType, num_types,
                           ValueType::Primitive(select_kind).value_type_code());
  }

  void set_global(DataRange* data) { global_op<kVoid>(data); }

  void throw_or_rethrow(DataRange* data) {
    bool rethrow = data->get<bool>();
    if (rethrow && !catch_blocks_.empty()) {
      int control_depth = static_cast<int>(blocks_.size() - 1);
      int catch_index =
          data->get<uint8_t>() % static_cast<int>(catch_blocks_.size());
      builder_->EmitWithU32V(kExprRethrow,
                             control_depth - catch_blocks_[catch_index]);
    } else {
      int tag = data->get<uint8_t>() % builder_->builder()->NumTags();
      const FunctionSig* exception_sig = builder_->builder()->GetTagType(tag);
      Generate(exception_sig->parameters(), data);
      builder_->EmitWithU32V(kExprThrow, tag);
    }
  }

  template <ValueKind... Types>
  void sequence(DataRange* data) {
    Generate<Types...>(data);
  }

  void memory_size(DataRange* data) {
    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    builder_->EmitWithU8(kExprMemorySize, memory_index);
    // The `memory_size` returns an I32. However, `kExprMemorySize` for memory64
    // returns an I64, so we should convert it.
    if (builder_->builder()->IsMemory64(memory_index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  void grow_memory(DataRange* data) {
    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    // Generate the index and the arguments, if any.
    builder_->builder()->IsMemory64(memory_index) ? Generate<kI64>(data)
                                                  : Generate<kI32>(data);
    builder_->EmitWithU8(kExprMemoryGrow, memory_index);
    // The `grow_memory` returns an I32. However, `kExprMemoryGrow` for memory64
    // returns an I64, so we should convert it.
    if (builder_->builder()->IsMemory64(memory_index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  void ref_null(HeapType type, DataRange* data) {
    builder_->EmitWithI32V(kExprRefNull, type.code());
  }

  bool get_local_ref(HeapType type, DataRange* data, Nullability nullable) {
    Var local = GetRandomLocal(data);
    // TODO(14034): Ideally we would check for subtyping here over type
    // equality, but we don't have a module.
    if (local.is_valid() && local.type.is_object_reference() &&
        local.type.heap_type() == type &&
        (local.type.is_nullable()
             ? nullable == kNullable  // We check for nullability-subtyping
             : locals_initialized_    // If the local is not nullable, we cannot
                                      // use it during locals initialization
         )) {
      builder_->EmitWithU32V(kExprLocalGet, local.index);
      return true;
    }

    return false;
  }

  bool new_object(HeapType type, DataRange* data, Nullability nullable) {
    DCHECK(type.is_index());

    ModuleTypeIndex index = type.ref_index();
    bool new_default = data->get<bool>();

    if (builder_->builder()->IsStructType(index)) {
      const StructType* struct_gen = builder_->builder()->GetStructType(index);
      int field_count = struct_gen->field_count();
      bool can_be_defaultable = std::all_of(
          struct_gen->fields().begin(), struct_gen->fields().end(),
          [](ValueType type) -> bool { return type.is_defaultable(); });

      if (new_default && can_be_defaultable) {
        builder_->EmitWithPrefix(kExprStructNewDefault);
        builder_->EmitU32V(index);
      } else {
        for (int i = 0; i < field_count; i++) {
          Generate(struct_gen->field(i).Unpacked(), data);
        }
        builder_->EmitWithPrefix(kExprStructNew);
        builder_->EmitU32V(index);
      }
    } else if (builder_->builder()->IsArrayType(index)) {
      ValueType element_type =
          builder_->builder()->GetArrayType(index)->element_type();
      bool can_be_defaultable = element_type.is_defaultable();
      WasmOpcode array_new_op[] = {
          kExprArrayNew,        kExprArrayNewFixed,
          kExprArrayNewData,    kExprArrayNewElem,
          kExprArrayNewDefault,  // default op has to be at the end of the list.
      };
      size_t op_size = arraysize(array_new_op);
      if (!can_be_defaultable) --op_size;
      switch (array_new_op[data->get<uint8_t>() % op_size]) {
        case kExprArrayNewElem:
        case kExprArrayNewData: {
          // This is more restrictive than it has to be.
          // TODO(14034): Also support nonnullable and non-index reference
          // types.
          if (element_type.is_reference() && element_type.is_nullable() &&
              element_type.has_index()) {
            // Add a new element segment with the corresponding type.
            uint32_t element_segment = GenerateRefTypeElementSegment(
                data, builder_->builder(), element_type);
            // Generate offset, length.
            // TODO(14034): Change the distribution here to make it more likely
            // that the numbers are in range.
            Generate(base::VectorOf({kWasmI32, kWasmI32}), data);
            // Generate array.new_elem instruction.
            builder_->EmitWithPrefix(kExprArrayNewElem);
            builder_->EmitU32V(index);
            builder_->EmitU32V(element_segment);
            break;
          } else if (!element_type.is_reference()) {
            // Lazily create a data segment if the module doesn't have one yet.
            if (builder_->builder()->NumDataSegments() == 0) {
              GeneratePassiveDataSegment(data, builder_->builder());
            }
            int data_index =
                data->get<uint8_t>() % builder_->builder()->NumDataSegments();
            // Generate offset, length.
            Generate(base::VectorOf({kWasmI32, kWasmI32}), data);
            builder_->EmitWithPrefix(kExprArrayNewData);
            builder_->EmitU32V(index);
            builder_->EmitU32V(data_index);
            break;
          }
          [[fallthrough]];  // To array.new.
        }
        case kExprArrayNew:
          Generate(element_type.Unpacked(), data);
          Generate(kWasmI32, data);
          builder_->EmitI32Const(kMaxArraySize);
          builder_->Emit(kExprI32RemS);
          builder_->EmitWithPrefix(kExprArrayNew);
          builder_->EmitU32V(index);
          break;
        case kExprArrayNewFixed: {
          size_t element_count =
              std::min(static_cast<size_t>(data->get<uint8_t>()), data->size());
          for (size_t i = 0; i < element_count; ++i) {
            Generate(element_type.Unpacked(), data);
          }
          builder_->EmitWithPrefix(kExprArrayNewFixed);
          builder_->EmitU32V(index);
          builder_->EmitU32V(static_cast<uint32_t>(element_count));
          break;
        }
        case kExprArrayNewDefault:
          Generate(kWasmI32, data);
          builder_->EmitI32Const(kMaxArraySize);
          builder_->Emit(kExprI32RemS);
          builder_->EmitWithPrefix(kExprArrayNewDefault);
          builder_->EmitU32V(index);
          break;
        default:
          FATAL("Unimplemented opcode");
      }
    } else {
      CHECK(builder_->builder()->IsSignature(index));
      // Map the type index to a function index.
      // TODO(11954. 7748): Once we have type canonicalization, choose a random
      // function from among those matching the signature (consider function
      // subtyping?).
      uint32_t declared_func_index =
          index.index - static_cast<uint32_t>(arrays_.size() + structs_.size());
      size_t num_functions = builder_->builder()->NumDeclaredFunctions();
      const FunctionSig* sig = builder_->builder()->GetSignature(index);
      for (size_t i = 0; i < num_functions; ++i) {
        if (sig == builder_->builder()
                       ->GetFunction(declared_func_index)
                       ->signature()) {
          uint32_t absolute_func_index =
              NumImportedFunctions() + declared_func_index;
          builder_->EmitWithU32V(kExprRefFunc, absolute_func_index);
          return true;
        }
        declared_func_index = (declared_func_index + 1) % num_functions;
      }
      // We did not find a function matching the requested signature.
      builder_->EmitWithI32V(kExprRefNull, index.index);
      if (!nullable) {
        builder_->Emit(kExprRefAsNonNull);
      }
    }

    return true;
  }

  void table_op(uint32_t index, std::vector<ValueType> types, DataRange* data,
                WasmOpcode opcode) {
    DCHECK(opcode == kExprTableSet || opcode == kExprTableSize ||
           opcode == kExprTableGrow || opcode == kExprTableFill);
    for (size_t i = 0; i < types.size(); i++) {
      // When passing the reftype by default kWasmFuncRef is used.
      // Then the type is changed according to its table type.
      if (types[i] == kWasmFuncRef) {
        types[i] = builder_->builder()->GetTableType(index);
      }
    }
    Generate(base::VectorOf(types), data);
    if (opcode == kExprTableSet) {
      builder_->Emit(opcode);
    } else {
      builder_->EmitWithPrefix(opcode);
    }
    builder_->EmitU32V(index);

    // The `table_size` and `table_grow` should return an I32. However, the Wasm
    // instruction for table64 returns an I64, so it should be converted.
    if ((opcode == kExprTableSize || opcode == kExprTableGrow) &&
        builder_->builder()->IsTable64(index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  ValueType table_address_type(int table_index) {
    return builder_->builder()->IsTable64(table_index) ? kWasmI64 : kWasmI32;
  }

  std::pair<int, ValueType> select_random_table(DataRange* data) {
    int num_tables = builder_->builder()->NumTables();
    DCHECK_GT(num_tables, 0);
    int index = data->get<uint8_t>() % num_tables;
    ValueType address_type = table_address_type(index);

    return {index, address_type};
  }

  bool table_get(HeapType type, DataRange* data, Nullability nullable) {
    ValueType needed_type = ValueType::RefMaybeNull(type, nullable);
    int table_count = builder_->builder()->NumTables();
    DCHECK_GT(table_count, 0);
    ZoneVector<uint32_t> table(builder_->builder()->zone());
    for (int i = 0; i < table_count; i++) {
      if (builder_->builder()->GetTableType(i) == needed_type) {
        table.push_back(i);
      
Prompt: 
```
这是目录为v8/src/wasm/fuzzing/random-module-generation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/fuzzing/random-module-generation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能

"""
tomicXor8U:
      case kExprI64AtomicExchange8U:
      case kExprI64AtomicCompareExchange8U:
      case kExprS128Load8Splat:
        return 0;
      default:
        return 0;
    }
  }

  template <WasmOpcode memory_op, ValueKind... arg_kinds>
  void memop(DataRange* data) {
    // Atomic operations need to be aligned exactly to their max alignment.
    const bool is_atomic = memory_op >> 8 == kAtomicPrefix;
    const uint8_t align = is_atomic ? max_alignment(memory_op)
                                    : data->getPseudoRandom<uint8_t>() %
                                          (max_alignment(memory_op) + 1);

    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    uint64_t offset = data->get<uint16_t>();
    // With a 1/256 chance generate potentially very large offsets.
    if ((offset & 0xff) == 0xff) {
      offset = builder_->builder()->IsMemory64(memory_index)
                   ? data->getPseudoRandom<uint64_t>() & 0x1ffffffff
                   : data->getPseudoRandom<uint32_t>();
    }

    // Generate the index and the arguments, if any.
    builder_->builder()->IsMemory64(memory_index)
        ? Generate<kI64, arg_kinds...>(data)
        : Generate<kI32, arg_kinds...>(data);

    // Format of the instruction (supports multi-memory):
    // memory_op (align | 0x40) memory_index offset
    if (WasmOpcodes::IsPrefixOpcode(static_cast<WasmOpcode>(memory_op >> 8))) {
      DCHECK(memory_op >> 8 == kAtomicPrefix || memory_op >> 8 == kSimdPrefix);
      builder_->EmitWithPrefix(memory_op);
    } else {
      builder_->Emit(memory_op);
    }
    builder_->EmitU32V(align | 0x40);
    builder_->EmitU32V(memory_index);
    builder_->EmitU64V(offset);
  }

  template <WasmOpcode Op, ValueKind... Args>
  void op_with_prefix(DataRange* data) {
    Generate<Args...>(data);
    builder_->EmitWithPrefix(Op);
  }

  void simd_const(DataRange* data) {
    builder_->EmitWithPrefix(kExprS128Const);
    for (int i = 0; i < kSimd128Size; i++) {
      builder_->EmitByte(data->getPseudoRandom<uint8_t>());
    }
  }

  template <WasmOpcode Op, int lanes, ValueKind... Args>
  void simd_lane_op(DataRange* data) {
    Generate<Args...>(data);
    builder_->EmitWithPrefix(Op);
    builder_->EmitByte(data->get<uint8_t>() % lanes);
  }

  template <WasmOpcode Op, int lanes, ValueKind... Args>
  void simd_lane_memop(DataRange* data) {
    // Simd load/store instructions that have a lane immediate.
    memop<Op, Args...>(data);
    builder_->EmitByte(data->get<uint8_t>() % lanes);
  }

  void simd_shuffle(DataRange* data) {
    Generate<kS128, kS128>(data);
    builder_->EmitWithPrefix(kExprI8x16Shuffle);
    for (int i = 0; i < kSimd128Size; i++) {
      builder_->EmitByte(static_cast<uint8_t>(data->get<uint8_t>() % 32));
    }
  }

  void drop(DataRange* data) {
    Generate(GetValueType<options>(
                 data, static_cast<uint32_t>(functions_.size() +
                                             structs_.size() + arrays_.size())),
             data);
    builder_->Emit(kExprDrop);
  }

  enum CallKind { kCallDirect, kCallIndirect, kCallRef };

  template <ValueKind wanted_kind>
  void call(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallDirect);
  }

  template <ValueKind wanted_kind>
  void call_indirect(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallIndirect);
  }

  template <ValueKind wanted_kind>
  void call_ref(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallRef);
  }

  void Convert(ValueType src, ValueType dst) {
    auto idx = [](ValueType t) -> int {
      switch (t.kind()) {
        case kI32:
          return 0;
        case kI64:
          return 1;
        case kF32:
          return 2;
        case kF64:
          return 3;
        default:
          UNREACHABLE();
      }
    };
    static constexpr WasmOpcode kConvertOpcodes[] = {
        // {i32, i64, f32, f64} -> i32
        kExprNop, kExprI32ConvertI64, kExprI32SConvertF32, kExprI32SConvertF64,
        // {i32, i64, f32, f64} -> i64
        kExprI64SConvertI32, kExprNop, kExprI64SConvertF32, kExprI64SConvertF64,
        // {i32, i64, f32, f64} -> f32
        kExprF32SConvertI32, kExprF32SConvertI64, kExprNop, kExprF32ConvertF64,
        // {i32, i64, f32, f64} -> f64
        kExprF64SConvertI32, kExprF64SConvertI64, kExprF64ConvertF32, kExprNop};
    int arr_idx = idx(dst) << 2 | idx(src);
    builder_->Emit(kConvertOpcodes[arr_idx]);
  }

  int choose_function_table_index(DataRange* data) {
    int table_count = builder_->builder()->NumTables();
    int start = data->get<uint8_t>() % table_count;
    for (int i = 0; i < table_count; ++i) {
      int index = (start + i) % table_count;
      if (builder_->builder()->GetTableType(index).is_reference_to(
              HeapType::kFunc)) {
        return index;
      }
    }
    FATAL("No funcref table found; table index 0 is expected to be funcref");
  }

  void call(DataRange* data, ValueType wanted_kind, CallKind call_kind) {
    uint8_t random_byte = data->get<uint8_t>();
    int func_index = random_byte % functions_.size();
    ModuleTypeIndex sig_index = functions_[func_index];
    const FunctionSig* sig = builder_->builder()->GetSignature(sig_index);
    // Generate arguments.
    for (size_t i = 0; i < sig->parameter_count(); ++i) {
      Generate(sig->GetParam(i), data);
    }
    // Emit call.
    // If the return types of the callee happen to match the return types of the
    // caller, generate a tail call.
    bool use_return_call = random_byte > 127;
    if (use_return_call &&
        std::equal(sig->returns().begin(), sig->returns().end(),
                   builder_->signature()->returns().begin(),
                   builder_->signature()->returns().end())) {
      if (call_kind == kCallDirect) {
        builder_->EmitWithU32V(kExprReturnCall,
                               NumImportedFunctions() + func_index);
      } else if (call_kind == kCallIndirect) {
        // This will not trap because table[func_index] always contains function
        // func_index.
        uint32_t table_index = choose_function_table_index(data);
        builder_->builder()->IsTable64(table_index)
            ? builder_->EmitI64Const(func_index)
            : builder_->EmitI32Const(func_index);
        builder_->EmitWithU32V(kExprReturnCallIndirect, sig_index);
        builder_->EmitByte(table_index);
      } else {
        GenerateRef(HeapType(sig_index), data);
        builder_->EmitWithU32V(kExprReturnCallRef, sig_index);
      }
      return;
    } else {
      if (call_kind == kCallDirect) {
        builder_->EmitWithU32V(kExprCallFunction,
                               NumImportedFunctions() + func_index);
      } else if (call_kind == kCallIndirect) {
        // This will not trap because table[func_index] always contains function
        // func_index.
        uint32_t table_index = choose_function_table_index(data);
        builder_->builder()->IsTable64(table_index)
            ? builder_->EmitI64Const(func_index)
            : builder_->EmitI32Const(func_index);
        builder_->EmitWithU32V(kExprCallIndirect, sig_index);
        builder_->EmitByte(table_index);
      } else {
        GenerateRef(HeapType(sig_index), data);
        builder_->EmitWithU32V(kExprCallRef, sig_index);
      }
    }
    if (sig->return_count() == 0 && wanted_kind != kWasmVoid) {
      // The call did not generate a value. Thus just generate it here.
      Generate(wanted_kind, data);
      return;
    }
    if (wanted_kind == kWasmVoid) {
      // The call did generate values, but we did not want one.
      for (size_t i = 0; i < sig->return_count(); ++i) {
        builder_->Emit(kExprDrop);
      }
      return;
    }
    auto wanted_types =
        base::VectorOf(&wanted_kind, wanted_kind == kWasmVoid ? 0 : 1);
    ConsumeAndGenerate(sig->returns(), wanted_types, data);
  }

  struct Var {
    uint32_t index;
    ValueType type = kWasmVoid;
    Var() = default;
    Var(uint32_t index, ValueType type) : index(index), type(type) {}
    bool is_valid() const { return type != kWasmVoid; }
  };

  Var GetRandomLocal(DataRange* data) {
    uint32_t num_params =
        static_cast<uint32_t>(builder_->signature()->parameter_count());
    uint32_t num_locals = static_cast<uint32_t>(locals_.size());
    if (num_params + num_locals == 0) return {};
    uint32_t index = data->get<uint8_t>() % (num_params + num_locals);
    ValueType type = index < num_params ? builder_->signature()->GetParam(index)
                                        : locals_[index - num_params];
    return {index, type};
  }

  constexpr static bool is_convertible_kind(ValueKind kind) {
    return kind == kI32 || kind == kI64 || kind == kF32 || kind == kF64;
  }

  template <ValueKind wanted_kind>
  void local_op(DataRange* data, WasmOpcode opcode) {
    static_assert(wanted_kind == kVoid || is_convertible_kind(wanted_kind));
    Var local = GetRandomLocal(data);
    // If there are no locals and no parameters, just generate any value (if a
    // value is needed), or do nothing.
    if (!local.is_valid() || !is_convertible_kind(local.type.kind())) {
      if (wanted_kind == kVoid) return;
      return Generate<wanted_kind>(data);
    }

    if (opcode != kExprLocalGet) Generate(local.type, data);
    builder_->EmitWithU32V(opcode, local.index);
    if (wanted_kind != kVoid && local.type.kind() != wanted_kind) {
      Convert(local.type, ValueType::Primitive(wanted_kind));
    }
  }

  template <ValueKind wanted_kind>
  void get_local(DataRange* data) {
    static_assert(wanted_kind != kVoid, "illegal type");
    local_op<wanted_kind>(data, kExprLocalGet);
  }

  void set_local(DataRange* data) { local_op<kVoid>(data, kExprLocalSet); }

  template <ValueKind wanted_kind>
  void tee_local(DataRange* data) {
    local_op<wanted_kind>(data, kExprLocalTee);
  }

  template <size_t num_bytes>
  void i32_const(DataRange* data) {
    builder_->EmitI32Const(data->getPseudoRandom<int32_t, num_bytes>());
  }

  template <size_t num_bytes>
  void i64_const(DataRange* data) {
    builder_->EmitI64Const(data->getPseudoRandom<int64_t, num_bytes>());
  }

  Var GetRandomGlobal(DataRange* data, bool ensure_mutable) {
    uint32_t index;
    if (ensure_mutable) {
      if (mutable_globals_.empty()) return {};
      index = mutable_globals_[data->get<uint8_t>() % mutable_globals_.size()];
    } else {
      if (globals_.empty()) return {};
      index = data->get<uint8_t>() % globals_.size();
    }
    ValueType type = globals_[index];
    return {index, type};
  }

  template <ValueKind wanted_kind>
  void global_op(DataRange* data) {
    static_assert(wanted_kind == kVoid || is_convertible_kind(wanted_kind));
    constexpr bool is_set = wanted_kind == kVoid;
    Var global = GetRandomGlobal(data, is_set);
    // If there are no globals, just generate any value (if a value is needed),
    // or do nothing.
    if (!global.is_valid() || !is_convertible_kind(global.type.kind())) {
      if (wanted_kind == kVoid) return;
      return Generate<wanted_kind>(data);
    }

    if (is_set) Generate(global.type, data);
    builder_->EmitWithU32V(is_set ? kExprGlobalSet : kExprGlobalGet,
                           global.index);
    if (!is_set && global.type.kind() != wanted_kind) {
      Convert(global.type, ValueType::Primitive(wanted_kind));
    }
  }

  template <ValueKind wanted_kind>
  void get_global(DataRange* data) {
    static_assert(wanted_kind != kVoid, "illegal type");
    global_op<wanted_kind>(data);
  }

  template <ValueKind select_kind>
  void select_with_type(DataRange* data) {
    static_assert(select_kind != kVoid, "illegal kind for select");
    Generate<select_kind, select_kind, kI32>(data);
    // num_types is always 1.
    uint8_t num_types = 1;
    builder_->EmitWithU8U8(kExprSelectWithType, num_types,
                           ValueType::Primitive(select_kind).value_type_code());
  }

  void set_global(DataRange* data) { global_op<kVoid>(data); }

  void throw_or_rethrow(DataRange* data) {
    bool rethrow = data->get<bool>();
    if (rethrow && !catch_blocks_.empty()) {
      int control_depth = static_cast<int>(blocks_.size() - 1);
      int catch_index =
          data->get<uint8_t>() % static_cast<int>(catch_blocks_.size());
      builder_->EmitWithU32V(kExprRethrow,
                             control_depth - catch_blocks_[catch_index]);
    } else {
      int tag = data->get<uint8_t>() % builder_->builder()->NumTags();
      const FunctionSig* exception_sig = builder_->builder()->GetTagType(tag);
      Generate(exception_sig->parameters(), data);
      builder_->EmitWithU32V(kExprThrow, tag);
    }
  }

  template <ValueKind... Types>
  void sequence(DataRange* data) {
    Generate<Types...>(data);
  }

  void memory_size(DataRange* data) {
    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    builder_->EmitWithU8(kExprMemorySize, memory_index);
    // The `memory_size` returns an I32. However, `kExprMemorySize` for memory64
    // returns an I64, so we should convert it.
    if (builder_->builder()->IsMemory64(memory_index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  void grow_memory(DataRange* data) {
    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    // Generate the index and the arguments, if any.
    builder_->builder()->IsMemory64(memory_index) ? Generate<kI64>(data)
                                                  : Generate<kI32>(data);
    builder_->EmitWithU8(kExprMemoryGrow, memory_index);
    // The `grow_memory` returns an I32. However, `kExprMemoryGrow` for memory64
    // returns an I64, so we should convert it.
    if (builder_->builder()->IsMemory64(memory_index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  void ref_null(HeapType type, DataRange* data) {
    builder_->EmitWithI32V(kExprRefNull, type.code());
  }

  bool get_local_ref(HeapType type, DataRange* data, Nullability nullable) {
    Var local = GetRandomLocal(data);
    // TODO(14034): Ideally we would check for subtyping here over type
    // equality, but we don't have a module.
    if (local.is_valid() && local.type.is_object_reference() &&
        local.type.heap_type() == type &&
        (local.type.is_nullable()
             ? nullable == kNullable  // We check for nullability-subtyping
             : locals_initialized_    // If the local is not nullable, we cannot
                                      // use it during locals initialization
         )) {
      builder_->EmitWithU32V(kExprLocalGet, local.index);
      return true;
    }

    return false;
  }

  bool new_object(HeapType type, DataRange* data, Nullability nullable) {
    DCHECK(type.is_index());

    ModuleTypeIndex index = type.ref_index();
    bool new_default = data->get<bool>();

    if (builder_->builder()->IsStructType(index)) {
      const StructType* struct_gen = builder_->builder()->GetStructType(index);
      int field_count = struct_gen->field_count();
      bool can_be_defaultable = std::all_of(
          struct_gen->fields().begin(), struct_gen->fields().end(),
          [](ValueType type) -> bool { return type.is_defaultable(); });

      if (new_default && can_be_defaultable) {
        builder_->EmitWithPrefix(kExprStructNewDefault);
        builder_->EmitU32V(index);
      } else {
        for (int i = 0; i < field_count; i++) {
          Generate(struct_gen->field(i).Unpacked(), data);
        }
        builder_->EmitWithPrefix(kExprStructNew);
        builder_->EmitU32V(index);
      }
    } else if (builder_->builder()->IsArrayType(index)) {
      ValueType element_type =
          builder_->builder()->GetArrayType(index)->element_type();
      bool can_be_defaultable = element_type.is_defaultable();
      WasmOpcode array_new_op[] = {
          kExprArrayNew,        kExprArrayNewFixed,
          kExprArrayNewData,    kExprArrayNewElem,
          kExprArrayNewDefault,  // default op has to be at the end of the list.
      };
      size_t op_size = arraysize(array_new_op);
      if (!can_be_defaultable) --op_size;
      switch (array_new_op[data->get<uint8_t>() % op_size]) {
        case kExprArrayNewElem:
        case kExprArrayNewData: {
          // This is more restrictive than it has to be.
          // TODO(14034): Also support nonnullable and non-index reference
          // types.
          if (element_type.is_reference() && element_type.is_nullable() &&
              element_type.has_index()) {
            // Add a new element segment with the corresponding type.
            uint32_t element_segment = GenerateRefTypeElementSegment(
                data, builder_->builder(), element_type);
            // Generate offset, length.
            // TODO(14034): Change the distribution here to make it more likely
            // that the numbers are in range.
            Generate(base::VectorOf({kWasmI32, kWasmI32}), data);
            // Generate array.new_elem instruction.
            builder_->EmitWithPrefix(kExprArrayNewElem);
            builder_->EmitU32V(index);
            builder_->EmitU32V(element_segment);
            break;
          } else if (!element_type.is_reference()) {
            // Lazily create a data segment if the module doesn't have one yet.
            if (builder_->builder()->NumDataSegments() == 0) {
              GeneratePassiveDataSegment(data, builder_->builder());
            }
            int data_index =
                data->get<uint8_t>() % builder_->builder()->NumDataSegments();
            // Generate offset, length.
            Generate(base::VectorOf({kWasmI32, kWasmI32}), data);
            builder_->EmitWithPrefix(kExprArrayNewData);
            builder_->EmitU32V(index);
            builder_->EmitU32V(data_index);
            break;
          }
          [[fallthrough]];  // To array.new.
        }
        case kExprArrayNew:
          Generate(element_type.Unpacked(), data);
          Generate(kWasmI32, data);
          builder_->EmitI32Const(kMaxArraySize);
          builder_->Emit(kExprI32RemS);
          builder_->EmitWithPrefix(kExprArrayNew);
          builder_->EmitU32V(index);
          break;
        case kExprArrayNewFixed: {
          size_t element_count =
              std::min(static_cast<size_t>(data->get<uint8_t>()), data->size());
          for (size_t i = 0; i < element_count; ++i) {
            Generate(element_type.Unpacked(), data);
          }
          builder_->EmitWithPrefix(kExprArrayNewFixed);
          builder_->EmitU32V(index);
          builder_->EmitU32V(static_cast<uint32_t>(element_count));
          break;
        }
        case kExprArrayNewDefault:
          Generate(kWasmI32, data);
          builder_->EmitI32Const(kMaxArraySize);
          builder_->Emit(kExprI32RemS);
          builder_->EmitWithPrefix(kExprArrayNewDefault);
          builder_->EmitU32V(index);
          break;
        default:
          FATAL("Unimplemented opcode");
      }
    } else {
      CHECK(builder_->builder()->IsSignature(index));
      // Map the type index to a function index.
      // TODO(11954. 7748): Once we have type canonicalization, choose a random
      // function from among those matching the signature (consider function
      // subtyping?).
      uint32_t declared_func_index =
          index.index - static_cast<uint32_t>(arrays_.size() + structs_.size());
      size_t num_functions = builder_->builder()->NumDeclaredFunctions();
      const FunctionSig* sig = builder_->builder()->GetSignature(index);
      for (size_t i = 0; i < num_functions; ++i) {
        if (sig == builder_->builder()
                       ->GetFunction(declared_func_index)
                       ->signature()) {
          uint32_t absolute_func_index =
              NumImportedFunctions() + declared_func_index;
          builder_->EmitWithU32V(kExprRefFunc, absolute_func_index);
          return true;
        }
        declared_func_index = (declared_func_index + 1) % num_functions;
      }
      // We did not find a function matching the requested signature.
      builder_->EmitWithI32V(kExprRefNull, index.index);
      if (!nullable) {
        builder_->Emit(kExprRefAsNonNull);
      }
    }

    return true;
  }

  void table_op(uint32_t index, std::vector<ValueType> types, DataRange* data,
                WasmOpcode opcode) {
    DCHECK(opcode == kExprTableSet || opcode == kExprTableSize ||
           opcode == kExprTableGrow || opcode == kExprTableFill);
    for (size_t i = 0; i < types.size(); i++) {
      // When passing the reftype by default kWasmFuncRef is used.
      // Then the type is changed according to its table type.
      if (types[i] == kWasmFuncRef) {
        types[i] = builder_->builder()->GetTableType(index);
      }
    }
    Generate(base::VectorOf(types), data);
    if (opcode == kExprTableSet) {
      builder_->Emit(opcode);
    } else {
      builder_->EmitWithPrefix(opcode);
    }
    builder_->EmitU32V(index);

    // The `table_size` and `table_grow` should return an I32. However, the Wasm
    // instruction for table64 returns an I64, so it should be converted.
    if ((opcode == kExprTableSize || opcode == kExprTableGrow) &&
        builder_->builder()->IsTable64(index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  ValueType table_address_type(int table_index) {
    return builder_->builder()->IsTable64(table_index) ? kWasmI64 : kWasmI32;
  }

  std::pair<int, ValueType> select_random_table(DataRange* data) {
    int num_tables = builder_->builder()->NumTables();
    DCHECK_GT(num_tables, 0);
    int index = data->get<uint8_t>() % num_tables;
    ValueType address_type = table_address_type(index);

    return {index, address_type};
  }

  bool table_get(HeapType type, DataRange* data, Nullability nullable) {
    ValueType needed_type = ValueType::RefMaybeNull(type, nullable);
    int table_count = builder_->builder()->NumTables();
    DCHECK_GT(table_count, 0);
    ZoneVector<uint32_t> table(builder_->builder()->zone());
    for (int i = 0; i < table_count; i++) {
      if (builder_->builder()->GetTableType(i) == needed_type) {
        table.push_back(i);
      }
    }
    if (table.empty()) {
      return false;
    }
    int table_index =
        table[data->get<uint8_t>() % static_cast<int>(table.size())];
    ValueType address_type = table_address_type(table_index);
    Generate(address_type, data);
    builder_->Emit(kExprTableGet);
    builder_->EmitU32V(table_index);
    return true;
  }

  void table_set(DataRange* data) {
    auto [table_index, address_type] = select_random_table(data);
    table_op(table_index, {address_type, kWasmFuncRef}, data, kExprTableSet);
  }

  void table_size(DataRange* data) {
    auto [table_index, _] = select_random_table(data);
    table_op(table_index, {}, data, kExprTableSize);
  }

  void table_grow(DataRange* data) {
    auto [table_index, address_type] = select_random_table(data);
    table_op(table_index, {kWasmFuncRef, address_type}, data, kExprTableGrow);
  }

  void table_fill(DataRange* data) {
    auto [table_index, address_type] = select_random_table(data);
    table_op(table_index, {address_type, kWasmFuncRef, address_type}, data,
             kExprTableFill);
  }

  void table_copy(DataRange* data) {
    ValueType needed_type = data->get<bool>() ? kWasmFuncRef : kWasmExternRef;
    int table_count = builder_->builder()->NumTables();
    ZoneVector<uint32_t> table(builder_->builder()->zone());
    for (int i = 0; i < table_count; i++) {
      if (builder_->builder()->GetTableType(i) == needed_type) {
        table.push_back(i);
      }
    }
    if (table.empty()) {
      return;
    }
    int first_index = data->get<uint8_t>() % static_cast<int>(table.size());
    int second_index = data->get<uint8_t>() % static_cast<int>(table.size());
    ValueType first_addrtype = table_address_type(table[first_index]);
    ValueType second_addrtype = table_address_type(table[second_index]);
    ValueType result_addrtype =
        first_addrtype == kWasmI32 ? kWasmI32 : second_addrtype;
    Generate(first_addrtype, data);
    Generate(second_addrtype, data);
    Generate(result_addrtype, data);
    builder_->EmitWithPrefix(kExprTableCopy);
    builder_->EmitU32V(table[first_index]);
    builder_->EmitU32V(table[second_index]);
  }

  bool array_get_helper(ValueType value_type, DataRange* data) {
    WasmModuleBuilder* builder = builder_->builder();
    ZoneVector<ModuleTypeIndex> array_indices(builder->zone());

    for (ModuleTypeIndex i : arrays_) {
      DCHECK(builder->IsArrayType(i));
      if (builder->GetArrayType(i)->element_type().Unpacked() == value_type) {
        array_indices.push_back(i);
      }
    }

    if (!array_indices.empty()) {
      int index = data->get<uint8_t>() % static_cast<int>(array_indices.size());
      GenerateRef(HeapType(array_indices[index]), data, kNullable);
      Generate(kWasmI32, data);
      if (builder->GetArrayType(array_indices[index])
              ->element_type()
              .is_packed()) {
        builder_->EmitWithPrefix(data->get<bool>() ? kExprArrayGetS
                                                   : kExprArrayGetU);

      } else {
        builder_->EmitWithPrefix(kExprArrayGet);
      }
      builder_->EmitU32V(array_indices[index]);
      return true;
    }

    return false;
  }

  template <ValueKind wanted_kind>
  void array_get(DataRange* data) {
    bool got_array_value =
        array_get_helper(ValueType::Primitive(wanted_kind), data);
    if (!got_array_value) {
      Generate<wanted_kind>(data);
    }
  }
  bool array_get_ref(HeapType type, DataRange* data, Nullability nullable) {
    ValueType needed_type = ValueType::RefMaybeNull(type, nullable);
    return array_get_helper(needed_type, data);
  }

  void i31_get(DataRange* data) {
    GenerateRef(HeapType(HeapType::kI31), data);
    if (data->get<bool>()) {
      builder_->EmitWithPrefix(kExprI31GetS);
    } else {
      builder_->EmitWithPrefix(kExprI31GetU);
    }
  }

  void array_len(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    GenerateRef(HeapType(HeapType::kArray), data);
    builder_->EmitWithPrefix(kExprArrayLen);
  }

  void array_copy(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    // TODO(14034): The source element type only has to be a subtype of the
    // destination element type. Currently this only generates copy from same
    // typed arrays.
    ModuleTypeIndex array_index =
        arrays_[data->get<uint8_t>() % arrays_.size()];
    DCHECK(builder_->builder()->IsArrayType(array_index));
    GenerateRef(HeapType(array_index), data);  // destination
    Generate(kWasmI32, data);                  // destination index
    GenerateRef(HeapType(array_index), data);  // source
    Generate(kWasmI32, data);                  // source index
    Generate(kWasmI32, data);                  // length
    builder_->EmitWithPrefix(kExprArrayCopy);
    builder_->EmitU32V(array_index);  // destination array type index
    builder_->EmitU32V(array_index);  // source array type index
  }

  void array_fill(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    ModuleTypeIndex array_index =
        arrays_[data->get<uint8_t>() % arrays_.size()];
    DCHECK(builder_->builder()->IsArrayType(array_index));
    ValueType element_type = builder_->builder()
                                 ->GetArrayType(array_index)
                                 ->element_type()
                                 .Unpacked();
    GenerateRef(HeapType(array_index), data);  // array
    Generate(kWasmI32, data);                  // offset
    Generate(element_type, data);              // value
    Generate(kWasmI32, data);                  // length
    builder_->EmitWithPrefix(kExprArrayFill);
    builder_->EmitU32V(array_index);
  }

  void array_init_data(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    ModuleTypeIndex array_index =
        arrays_[data->get<uint8_t>() % arrays_.size()];
    DCHECK(builder_->builder()->IsArrayType(array_index));
    const ArrayType* array_type =
        builder_->builder()->GetArrayType(array_index);
    DCHECK(array_type->mutability());
    ValueType element_type = array_type->element_type().Unpacked();
    if (element_type.is_reference()) {
      return;
    }
    if (builder_->builder()->NumDataSegments() == 0) {
      GeneratePassiveDataSegment(data, builder_->builder());
    }

    int data_index =
        data->get<uint8_t>() % builder_->builder()->NumDataSegments();
    // Generate array, index, data_offset, length.
    Generate(base::VectorOf({ValueType::RefNull(array_index), kWasmI32,
                             kWasmI32, kWasmI32}),
             data);
    builder_->EmitWithPrefix(kExprArrayInitData);
    builder_->EmitU32V(array_index);
    builder_->EmitU32V(data_index);
  }

  void array_init_elem(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    ModuleTypeIndex array_index =
        arrays_[data->get<uint8_t>() % arrays_.size()];
    DCHECK(builder_->builder()->IsArrayType(array_index));
    const ArrayType* array_type =
        builder_->builder()->GetArrayType(array_index);
    DCHECK(array_type->mutability());
    ValueType element_type = array_type->element_type().Unpacked();
    // This is more restrictive than it has to be.
    // TODO(14034): Also support nonnullable and non-index reference
    // types.
    if (!element_type.is_reference() || element_type.is_non_nullable() ||
        !element_type.has_index()) {
      return;
    }
    // Add a new element segment with the corresponding type.
    uint32_t element_segment =
        GenerateRefTypeElementSegment(data, builder_->builder(), element_type);
    // Generate array, index, elem_offset, length.
    // TODO(14034): Change the distribution here to make it more likely
    // that the numbers are in range.
    Generate(base::VectorOf({ValueType::RefNull(array_index), kWasmI32,
                             kWasmI32, kWasmI32}),
             data);
    // Generate array.new_elem instruction.
    builder_->EmitWithPrefix(kExprArrayInitElem);
    builder_->EmitU32V(array_index);
    builder_->EmitU32V(element_segment);
  }

  void array_set(DataRange* data) {
    WasmModuleBuilder* builder = builder_->builder();
    ZoneVector<ModuleTypeIndex> array_indices(builder->zone());
    for (ModuleTypeIndex i : arrays_) {
      DCHECK(builder->IsArrayType(i));
      if (builder->GetArrayType(i)->mutability()) {
        array_indices.push_back(i);
      }
    }

    if (array_indices.empty()) {
      return;
    }

    int index = data->get<uint8_t>() % static_cast<int>(array_indices.size());
    GenerateRef(HeapType(array_indices[index]), data);
    Generate(kWasmI32, data);
    Generate(
        builder->GetArrayType(array_indices[index])->element_type().Unpacked(),
        data);
    builder_->EmitWithPrefix(kExprArraySet);
    builder_->EmitU32V(array_indices[index]);
  }

  bool struct_get_helper(ValueType value_type, DataRange* data) {
    WasmModuleBuilder* builder = builder_->builder();
    ZoneVector<uint32_t> field_index(builder->zone());
    ZoneVector<ModuleTypeIndex> struct_index(builder->zone());
    for (ModuleTypeIndex i : structs_) {
      DCHECK(builder->IsStructType(i));
      int field_count = builder->GetStructType(i)->field_count();
      for (int index = 0; index < field_count; index++) {
        // TODO(14034): This should be a subtype check!
        if (builder->GetStructType(i)->field(index) == value_type) {
          field_index.push_back(index);
          struct_index.push_back(i);
        }
      }
    }
    if (!field_index.empty()) {
      int index = data->get<uint8_t>() % static_cast<int>(field_index.size());
      GenerateRef(HeapType(struct_index[index]), data, kNullable);
      if (builder->GetStructType(struct_index[index])
              ->field(field_index[index])
              .is_packed()) {
        builder_->EmitWithPrefix(data->get<bool>() ? kExprStructGetS
                                                   : kExprStructGetU);
      } else {
        builder_->EmitWithPrefix(kExprStructGet);
      }
      builder_->EmitU32V(struct_index[index]);
      builder_->EmitU32V(field_index[index]);
      return true;
    }
    return false;
  }

  template <ValueKind wanted_kind>
  void struct_get(DataRange* data) {
    bool got_struct_value =
        struct_get_helper(ValueType::Primitive(wanted_kind), data);
    if (!got_struct_value) {
      Gene
"""


```