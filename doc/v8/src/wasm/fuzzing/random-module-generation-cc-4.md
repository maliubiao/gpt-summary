Response:
The user wants me to analyze a C++ source code file for WebAssembly module generation within the V8 JavaScript engine. I need to identify its functionalities, relate it to JavaScript if applicable, provide code logic examples with input/output, point out common programming errors it might help avoid, and summarize its purpose. Since this is part 5 of 7, I should focus on the features and logic present in this specific snippet.

Here's a breakdown of the tasks:

1. **Functionality Listing:**  I'll go through the code and identify the key functions and classes, focusing on their purpose in generating WebAssembly modules. This will involve recognizing patterns related to generating different WASM constructs (types, functions, globals, tables, etc.).

2. **Torque Check:**  The prompt mentions checking for `.tq` extension. This file is `.cc`, so it's C++ and not Torque.

3. **JavaScript Relation:** I need to determine if this C++ code directly relates to any JavaScript functionalities. Since this code is about *generating* WASM, the connection is likely when JavaScript *uses* WASM modules. I'll focus on how JavaScript loads and interacts with WASM modules.

4. **Code Logic with Input/Output:**  I'll choose a specific function or code block and illustrate its behavior with hypothetical input and the expected output based on the logic.

5. **Common Programming Errors:**  I'll consider the kind of errors that can occur when writing WASM manually or through code generation, and how this code might help prevent them (e.g., type mismatches, invalid memory access).

6. **Part 5 Summary:**  Given that this is part 5, I'll look for themes or specific areas of WASM generation that are prominent in this section. The heading `GenerateInitExpr` and the frequent calls to `GenerateRef` and `Generate` suggest a focus on generating initializers and references.

**Mental Sandbox:**

* **`GenerateRef` function:**  Seems to be central to generating references of various types (functions, externals, user-defined types). It uses a `DataRange` for randomness.
* **`Generate` function:** Handles generating values of different types, potentially involving multi-value blocks.
* **`Consume` and `ConsumeAndGenerate`:**  Deal with managing values on the stack, similar to how a WASM virtual machine would operate.
* **`ModuleGen` class:**  Appears to be the main class for generating the overall WASM module structure (memories, types, globals, tables, etc.).
* **`GenerateInitExpr` functions:**  Specifically for generating the initial values of globals and table elements. This looks like the main focus of this snippet.

**Key Observation:**  This section seems heavily focused on the *initialization* of WASM module components, especially using random data to create diverse scenarios for fuzzing.

Strategizing complete. I will now generate the response based on these observations and the code provided.
```cpp
 + emit_i31ref + fallback_to_eqref);
        // Try generating one of the alternatives
        // and continue to the rest of the methods in case it fails.
        if (random >= num_types + emit_i31ref) {
          if (GenerateOneOf(alternatives_other, type, data, nullability)) {
            return;
          }
          random = data->get<uint8_t>() % (num_types + emit_i31ref);
        }
        if (random < num_types) {
          // Using `HeapType(random)` here relies on the assumption that struct
          // and array types come before signatures.
          DCHECK(builder_->builder()->IsArrayType(random) ||
                 builder_->builder()->IsStructType(random));
          GenerateRef(HeapType(ModuleTypeIndex{random}), data, nullability);
        } else {
          GenerateRef(HeapType(HeapType::kI31), data, nullability);
        }
        return;
      }
      case HeapType::kFunc: {
        uint32_t random = data->get<uint8_t>() % (functions_.size() + 1);
        /// Try generating one of the alternatives
        // and continue to the rest of the methods in case it fails.
        if (random >= functions_.size()) {
          if (GenerateOneOf(alternatives_func_any, type, data, nullability)) {
            return;
          }
          random = data->get<uint8_t>() % functions_.size();
        }
        ModuleTypeIndex signature_index = functions_[random];
        DCHECK(builder_->builder()->IsSignature(signature_index));
        GenerateRef(HeapType(signature_index), data, nullability);
        return;
      }
      case HeapType::kI31: {
        // Try generating one of the alternatives
        // and continue to the rest of the methods in case it fails.
        if (data->get<bool>() &&
            GenerateOneOf(alternatives_other, type, data, nullability)) {
          return;
        }
        Generate(kWasmI32, data);
        builder_->EmitWithPrefix(kExprRefI31);
        return;
      }
      case HeapType::kExn: {
        // TODO(manoskouk): Can we somehow come up with a nontrivial exnref?
        ref_null(type, data);
        if (nullability == kNonNullable) {
          builder_->Emit(kExprRefAsNonNull);
        }
        return;
      }
      case HeapType::kExtern: {
        uint8_t choice = data->get<uint8_t>();
        if (choice < 25) {
          // ~10% chance of extern.convert_any.
          GenerateRef(HeapType(HeapType::kAny), data);
          builder_->EmitWithPrefix(kExprExternConvertAny);
          if (nullability == kNonNullable) {
            builder_->Emit(kExprRefAsNonNull);
          }
          return;
        }
        // ~80% chance of string.
        if (choice < 230 && ShouldGenerateWasmGC(options)) {
          uint8_t subchoice = choice % 7;
          switch (subchoice) {
            case 0:
              return string_cast(data);
            case 1:
              return string_fromcharcode(data);
            case 2:
              return string_fromcodepoint(data);
            case 3:
              return string_concat(data);
            case 4:
              return string_substring(data);
            case 5:
              return string_fromcharcodearray(data);
            case 6:
              return string_fromutf8array(data);
          }
        }
        // ~10% chance of fallthrough.
        [[fallthrough]];
      }
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
      case HeapType::kNone:
      case HeapType::kNoExn:
        ref_null(type, data);
        if (nullability == kNonNullable) {
          builder_->Emit(kExprRefAsNonNull);
        }
        return;
      default:
        // Indexed type (i.e. user-defined type).
        DCHECK(type.is_index());
        if (ShouldGenerateWasmGC(options) &&
            type.ref_index() == string_imports_.array_i8 &&
            data->get<uint8_t>() < 32) {
          // 1/8th chance, fits the number of remaining alternatives (7) well.
          return string_toutf8array(data);
        }
        GenerateOneOf(alternatives_indexed_type, type, data, nullability);
        return;
    }
    UNREACHABLE();
  }

  void GenerateRef(DataRange* data) {
    constexpr HeapType::Representation top_types[] = {
        HeapType::kAny,
        HeapType::kFunc,
        HeapType::kExtern,
    };
    HeapType::Representation type =
        top_types[data->get<uint8_t>() % arraysize(top_types)];
    GenerateRef(HeapType(type), data);
  }

  std::vector<ValueType> GenerateTypes(DataRange* data) {
    return fuzzing::GenerateTypes<options>(
        data, static_cast<uint32_t>(functions_.size() + structs_.size() +
                                    arrays_.size()));
  }

  void Generate(base::Vector<const ValueType> types, DataRange* data) {
    // Maybe emit a multi-value block with the expected return type. Use a
    // non-default value to indicate block generation to avoid recursion when we
    // reach the end of the data.
    bool generate_block = data->get<uint8_t>() % 32 == 1;
    if (generate_block) {
      GeneratorRecursionScope rec_scope(this);
      if (!recursion_limit_reached()) {
        const auto param_types = GenerateTypes(data);
        Generate(base::VectorOf(param_types), data);
        any_block(base::VectorOf(param_types), types, data);
        return;
      }
    }

    if (types.size() == 0) {
      Generate(kWasmVoid, data);
      return;
    }
    if (types.size() == 1) {
      Generate(types[0], data);
      return;
    }

    // Split the types in two halves and recursively generate each half.
    // Each half is non empty to ensure termination.
    size_t split_index = data->get<uint8_t>() % (types.size() - 1) + 1;
    base::Vector<const ValueType> lower_half = types.SubVector(0, split_index);
    base::Vector<const ValueType> upper_half =
        types.SubVector(split_index, types.size());
    DataRange first_range = data->split();
    Generate(lower_half, &first_range);
    Generate(upper_half, data);
  }

  void Consume(ValueType type) {
    // Try to store the value in a local if there is a local with the same
    // type. TODO(14034): For reference types a local with a super type
    // would also be fine.
    size_t num_params = builder_->signature()->parameter_count();
    for (uint32_t local_offset = 0; local_offset < locals_.size();
         ++local_offset) {
      if (locals_[local_offset] == type) {
        uint32_t local_index = static_cast<uint32_t>(local_offset + num_params);
        builder_->EmitWithU32V(kExprLocalSet, local_index);
        return;
      }
    }
    for (uint32_t param_index = 0; param_index < num_params; ++param_index) {
      if (builder_->signature()->GetParam(param_index) == type) {
        builder_->EmitWithU32V(kExprLocalSet, param_index);
        return;
      }
    }
    // No opportunity found to use the value, so just drop it.
    builder_->Emit(kExprDrop);
  }

  // Emit code to match an arbitrary signature.
  // TODO(11954): Add the missing reference type conversion/upcasting.
  void ConsumeAndGenerate(base::Vector<const ValueType> param_types,
                          base::Vector<const ValueType> return_types,
                          DataRange* data) {
    // This numeric conversion logic consists of picking exactly one
    // index in the return values and dropping all the values that come
    // before that index. Then we convert the value from that index to the
    // wanted type. If we don't find any value we generate it.
    auto primitive = [](ValueType t) -> bool {
      switch (t.kind()) {
        case kI32:
        case kI64:
        case kF32:
        case kF64:
          return true;
        default:
          return false;
      }
    };

    if (return_types.size() == 0 || param_types.size() == 0 ||
        !primitive(return_types[0])) {
      for (auto iter = param_types.rbegin(); iter != param_types.rend();
           ++iter) {
        Consume(*iter);
      }
      Generate(return_types, data);
      return;
    }

    int bottom_primitives = 0;

    while (static_cast<int>(param_types.size()) > bottom_primitives &&
           primitive(param_types[bottom_primitives])) {
      bottom_primitives++;
    }
    int return_index =
        bottom_primitives > 0 ? (data->get<uint8_t>() % bottom_primitives) : -1;
    for (int i = static_cast<int>(param_types.size() - 1); i > return_index;
         --i) {
      Consume(param_types[i]);
    }
    for (int i = return_index; i > 0; --i) {
      Convert(param_types[i], param_types[i - 1]);
      builder_->EmitI32Const(0);
      builder_->Emit(kExprSelect);
    }
    DCHECK(!return_types.empty());
    if (return_index >= 0) {
      Convert(param_types[0], return_types[0]);
      Generate(return_types + 1, data);
    } else {
      Generate(return_types, data);
    }
  }

  bool HasSimd() { return has_simd_; }

  void InitializeNonDefaultableLocals(DataRange* data) {
    for (uint32_t i = 0; i < locals_.size(); i++) {
      if (!locals_[i].is_defaultable()) {
        GenerateRef(locals_[i].heap_type(), data, kNonNullable);
        builder_->EmitWithU32V(
            kExprLocalSet, i + static_cast<uint32_t>(
                                   builder_->signature()->parameter_count()));
      }
    }
    locals_initialized_ = true;
  }

 private:
  WasmFunctionBuilder* builder_;
  std::vector<std::vector<ValueType>> blocks_;
  const std::vector<ModuleTypeIndex>& functions_;
  std::vector<ValueType> locals_;
  std::vector<ValueType> globals_;
  std::vector<uint8_t> mutable_globals_;  // indexes into {globals_}.
  uint32_t recursion_depth = 0;
  std::vector<int> catch_blocks_;
  bool has_simd_ = false;
  const std::vector<ModuleTypeIndex>& structs_;
  const std::vector<ModuleTypeIndex>& arrays_;
  const StringImports& string_imports_;
  bool locals_initialized_ = false;

  bool recursion_limit_reached() {
    return recursion_depth >= kMaxRecursionDepth;
  }
};

WasmInitExpr GenerateInitExpr(Zone* zone, DataRange& range,
                              WasmModuleBuilder* builder, ValueType type,
                              const std::vector<ModuleTypeIndex>& structs,
                              const std::vector<ModuleTypeIndex>& arrays,
                              uint32_t recursion_depth);

template <WasmModuleGenerationOptions options>
class ModuleGen {
 public:
  explicit ModuleGen(Zone* zone, WasmModuleBuilder* fn, DataRange* module_range,
                     uint8_t num_functions, uint8_t num_structs,
                     uint8_t num_arrays, uint8_t num_signatures)
      : zone_(zone),
        builder_(fn),
        module_range_(module_range),
        num_functions_(num_functions),
        num_structs_(num_structs),
        num_arrays_(num_arrays),
        num_signatures_(num_signatures),
        num_types_(num_signatures + num_structs + num_arrays) {}

  // Generates and adds random number of memories.
  void GenerateRandomMemories() {
    int num_memories = 1 + (module_range_->get<uint8_t>() % kMaxMemories);
    for (int i = 0; i < num_memories; i++) {
      uint8_t random_byte = module_range_->get<uint8_t>();
      bool mem64 = random_byte & 1;
      bool has_maximum = random_byte & 2;
      static_assert(kV8MaxWasmMemory64Pages <= kMaxUInt32);
      uint32_t max_supported_pages =
          mem64 ? kV8MaxWasmMemory64Pages : kV8MaxWasmMemory32Pages;
      uint32_t min_pages =
          module_range_->get<uint32_t>() % (max_supported_pages + 1);
      if (has_maximum) {
        uint32_t max_pages =
            std::max(min_pages, module_range_->get<uint32_t>() %
                                    (max_supported_pages + 1));
        if (mem64) {
          builder_->AddMemory64(min_pages, max_pages);
        } else {
          builder_->AddMemory(min_pages, max_pages);
        }
      } else {
        if (mem64) {
          builder_->AddMemory64(min_pages);
        } else {
          builder_->AddMemory(min_pages);
        }
      }
    }
  }

  // Puts the types into random recursive groups.
  std::map<uint8_t, uint8_t> GenerateRandomRecursiveGroups(
      uint8_t kNumDefaultArrayTypes) {
    // (Type_index -> end of explicit rec group).
    std::map<uint8_t, uint8_t> explicit_rec_groups;
    uint8_t current_type_index = 0;

    // The default array types are each in their own recgroup.
    for (uint8_t i = 0; i < kNumDefaultArrayTypes; i++) {
      explicit_rec_groups.emplace(current_type_index, current_type_index);
      builder_->AddRecursiveTypeGroup(current_type_index++, 1);
    }

    while (current_type_index < num_types_) {
      // First, pick a random start for the next group. We allow it to be
      // beyond the end of types (i.e., we add no further recursive groups).
      uint8_t group_start = module_range_->get<uint8_t>() %
                                (num_types_ - current_type_index + 1) +
                            current_type_index;
      DCHECK_GE(group_start, current_type_index);
      current_type_index = group_start;
      if (group_start < num_types_) {
        // If we did not reach the end of the types, pick a random group size.
        uint8_t group_size =
            module_range_->get<uint8_t>() % (num_types_ - group_start) + 1;
        DCHECK_LE(group_start + group_size, num_types_);
        for (uint8_t i = group_start; i < group_start + group_size; i++) {
          explicit_rec_groups.emplace(i, group_start + group_size - 1);
        }
        builder_->AddRecursiveTypeGroup(group_start, group_size);
        current_type_index += group_size;
      }
    }
    return explicit_rec_groups;
  }

  // Generates and adds random struct types.
  void GenerateRandomStructs(
      const std::map<uint8_t, uint8_t>& explicit_rec_groups,
      std::vector<ModuleTypeIndex>& struct_types, uint8_t& current_type_index,
      uint8_t kNumDefaultArrayTypes) {
    uint8_t last_struct_type_index = current_type_index + num_structs_;
    for (; current_type_index < last_struct_type_index; current_type_index++) {
      auto rec_group = explicit_rec_groups.find(current_type_index);
      uint8_t current_rec_group_end = rec_group != explicit_rec_groups.end()
                                          ? rec_group->second
                                          : current_type_index;

      ModuleTypeIndex supertype = kNoSuperType;
      uint8_t num_fields =
          module_range_->get<uint8_t>() % (kMaxStructFields + 1);

      uint32_t existing_struct_types =
          current_type_index - kNumDefaultArrayTypes;
      if (existing_struct_types > 0 && module_range_->get<bool>()) {
        supertype = ModuleTypeIndex{module_range_->get<uint8_t>() %
                                        existing_struct_types +
                                    kNumDefaultArrayTypes};
        num_fields += builder_->GetStructType(supertype)->field_count();
      }
      StructType::Builder struct_builder(zone_, num_fields);

      // Add all fields from super type.
      uint32_t field_index = 0;
      if (supertype != kNoSuperType) {
        const StructType* parent = builder_->GetStructType(supertype);
        for (; field_index < parent->field_count(); ++field_index) {
          // TODO(14034): This could also be any sub type of the supertype's
          // element type.
          struct_builder.AddField(parent->field(field_index),
                                  parent->mutability(field_index));
        }
      }
      for (; field_index < num_fields; field_index++) {
        // Notes:
        // - We allow a type to only have non-nullable fields of types that
        //   are defined earlier. This way we avoid infinite non-nullable
        //   constructions. Also relevant for arrays and functions.
        // - On the other hand, nullable fields can be picked up to the end of
        //   the current recursive group.
        // - We exclude the non-nullable generic types arrayref, anyref,
        //   structref, eqref and externref from the fields of structs and
        //   arrays. This is so that GenerateInitExpr has a way to break a
        //   recursion between a struct/array field and those types
        //   ((ref extern) gets materialized through (ref any)).
        ValueType type = GetValueTypeHelper<options>(
            module_range_, current_rec_group_end + 1, current_type_index,
            kIncludeNumericTypes, kIncludePackedTypes, kExcludeSomeGenerics);

        bool mutability = module_range_->get<bool>();
        struct_builder.AddField(type, mutability);
      }
      StructType* struct_fuz = struct_builder.Build();
      // TODO(14034): Generate some final types too.
      ModuleTypeIndex index =
          builder_->AddStructType(struct_fuz, false, supertype);
      struct_types.push_back(index);
    }
  }

  // Creates and adds random array types.
  void GenerateRandomArrays(
      const std::map<uint8_t, uint8_t>& explicit_rec_groups,
      std::vector<ModuleTypeIndex>& array_types, uint8_t& current_type_index) {
    uint32_t last_struct_type_index = current_type_index + num_structs_;
    for (; current_type_index < num_structs_ + num_arrays_;
         current_type_index++) {
      auto rec_group = explicit_rec_groups.find(current_type_index);
      uint8_t current_rec_group_end = rec_group != explicit_rec_groups.end()
                                          ? rec_group->second
                                          : current_type_index;
      ValueType type = GetValueTypeHelper<options>(
          module_range_, current_rec_group_end + 1, current_type_index,
          kIncludeNumericTypes, kIncludePackedTypes, kExcludeSomeGenerics);
      ModuleTypeIndex supertype = kNoSuperType;
      if (current_type_index > last_struct_type_index &&
          module_range_->get<bool>()) {
        // Do not include the default array types, because they are final.
        uint8_t existing_array_types =
            current_type_index - last_struct_type_index;
        supertype = ModuleTypeIndex{
            last_struct_type_index +
            (module_range_->get<uint8_t>() % existing_array_types)};
        // TODO(14034): This could also be any sub type of the supertype's
        // element type.
        type = builder_->GetArrayType(supertype)->element_type();
      }
      ArrayType* array_fuz = zone_->New<ArrayType>(type, true);
      // TODO(14034): Generate some final types too.
      ModuleTypeIndex index =
          builder_->AddArrayType(array_fuz, false, supertype);
      array_types.push_back(index);
    }
  }

  enum SigKind { kFunctionSig, kExceptionSig };

  FunctionSig* GenerateSig(SigKind sig_kind, int num_types) {
    // Generate enough parameters to spill some to the stack.
    int num_params = int{module_range_->get<uint8_t>()} % (kMaxParameters + 1);
    int num_returns =
        sig_kind == kFunctionSig
            ? int{module_range_->get<uint8_t>()} % (kMaxReturns + 1)
            : 0;

    FunctionSig::Builder builder(zone_, num_returns, num_params);
    for (int i = 0; i < num_returns; ++i) {
      builder.AddReturn(GetValueType<options>(module_range_, num_types));
    }
    for (int i = 0; i < num_params; ++i) {
      builder.AddParam(GetValueType<options>(module_range_, num_types));
    }
    return builder.Get();
  }

  // Creates and adds random function signatures.
  void GenerateRandomFunctionSigs(
      const std::map<uint8_t, uint8_t>& explicit_rec_groups,
      std::vector<ModuleTypeIndex>& function_signatures,
      uint8_t& current_type_index, bool kIsFinal) {
    // Recursive groups consist of recursive types that came with the WasmGC
    // proposal.
    DCHECK_IMPLIES(!ShouldGenerateWasmGC(options), explicit_rec_groups.empty());

    for (; current_type_index < num_types_; current_type_index++) {
      auto rec_group = explicit_rec_groups.find(current_type_index);
      uint8_t current_rec_group_end = rec_group != explicit_rec_groups.end()
                                          ? rec_group->second
                                          : current_type_index;
      FunctionSig* sig = GenerateSig(kFunctionSig, current_rec_group_end + 1);
      ModuleTypeIndex signature_index =
          builder_->ForceAddSignature(sig, kIsFinal);
      function_signatures.push_back(signature_index);
    }
  }

  void GenerateRandomExceptions(uint8_t num_exceptions) {
    for (int i = 0; i < num_exceptions; ++i) {
      FunctionSig* sig = GenerateSig(kExceptionSig, num_types_);
      builder_->AddTag(sig);
    }
  }

  // Adds the "wasm:js-string" imports to the module.
  StringImports AddImportedStringImports() {
    static constexpr ModuleTypeIndex kArrayI8{0};
    static constexpr ModuleTypeIndex kArrayI16{1};
    StringImports strings;
    strings.array_i8 = kArrayI8;
    strings.array_i16 = kArrayI16;
    static constexpr ValueType kRefExtern = ValueType::Ref(HeapType::kExtern);
    static constexpr ValueType kExternRef = kWasmExternRef;
    static constexpr ValueType kI32 = kWasmI32;
    static constexpr ValueType kRefA8 = ValueType::Ref(kArrayI8);
    static constexpr ValueType kRefNullA8 = ValueType::RefNull(kArrayI8);
    static constexpr ValueType kRefNullA16 = ValueType::RefNull(kArrayI16);

    // Shorthands: "r" = nullable "externref",
    // "e" = non-nullable "ref extern".
    static constexpr ValueType kReps_e_i[] = {kRefExtern, kI32};
    static constexpr ValueType kReps_e_rr[] = {kRefExtern, kExternRef,
                                               kExternRef};
    static constexpr ValueType kReps_e_rii[] = {kRefExtern, kExternRef, kI32,
                                                kI32};
    static constexpr ValueType kReps_i_ri[] = {kI32, kExternRef, kI32};
    static constexpr ValueType kReps_i_rr[] = {kI32, kExternRef, kExternRef};
    static constexpr ValueType kReps_from_a16[] = {kRefExtern, kRefNullA16,
                                                   kI32, kI32};
    static constexpr ValueType kReps_from_a8[] = {kRefExtern, kRefNullA8, kI32,
                                                  kI32};
    static constexpr ValueType kReps_into_a16[] = {kI32, kExternRef,
                                                   kRefNullA16, kI32};
    static constexpr ValueType kReps_into_a8[] = {kI32, kExternRef, kRefNullA8,
                                                  kI32};
    static constexpr ValueType kReps_to_a8[] = {kRefA8, kExternRef};

    static constexpr FunctionSig kSig_e_i(1, 1, kReps_e_i);
    static constexpr FunctionSig kSig_e_r(1, 1, kReps_e_rr);
    static constexpr FunctionSig kSig_e_rr(1, 2, kReps_e_rr);
    static constexpr FunctionSig kSig_e_rii(1, 3, kReps_e_rii);

    static constexpr FunctionSig kSig_i_r(1, 1, kReps_i_ri);
    static constexpr FunctionSig kSig_i_ri(1, 2, kReps_i_ri);
    static constexpr FunctionSig kSig_i_rr(1, 2, kReps_i_rr);
    static constexpr FunctionSig kSig_from_a16(1, 3, kReps_from_a16);
    static constexpr FunctionSig kSig_from_a8(1, 3, kReps_from_a8);
    static constexpr FunctionSig kSig_into_a16(1, 3, kReps_into_a16);
    static constexpr FunctionSig kSig_into_a8(1, 3, kReps_into_a8);
    static constexpr FunctionSig kSig_to_a8(1, 1, kReps_to_a8);

    static constexpr base::Vector<const char> kJsString =
        base::StaticCharVector("wasm:js-string");
    static constexpr base::Vector<const char> kTextDecoder =
        base::StaticCharVector("wasm:text-decoder");
    static constexpr base::Vector<const char> kTextEncoder =
        base::StaticCharVector("wasm:text-encoder");

#define STRINGFUNC(name, sig, group) \
  strings.name = builder_->AddImport(base::CStrVector(#name), &sig, group)

    STRINGFUNC(cast, kSig_e_r, kJsString);
    STRINGFUNC(test, kSig_i_r, kJsString);
    STRINGFUNC(fromCharCode, kSig_e_i, kJsString);
    STRINGFUNC(fromCodePoint, kSig_e_i, kJsString);
    STRINGFUNC(charCodeAt, kSig_i_ri, kJsString);
    STRINGFUNC(codePointAt, kSig_i_ri, kJsString);
    STRINGFUNC(length, kSig_i_r, kJsString);
    STRINGFUNC(concat, kSig_e_rr, kJsString);
    STRINGFUNC(substring, kSig_e_rii, kJsString);
    STRINGFUNC(equals, kSig_i_rr, kJsString);
    STRINGFUNC(compare, kSig_i_rr, kJsString);
    STRINGFUNC(fromCharCodeArray, kSig_from_a16, kJsString);
    STRINGFUNC(intoCharCodeArray, kSig_into_a16, kJsString);
    STRINGFUNC(measureStringAsUTF8, kSig_i_r, kTextEncoder);
    STRINGFUNC(encodeStringIntoUTF8Array, kSig_into_a8, kTextEncoder);
    STRINGFUNC(encodeStringToUTF8Array, kSig_to_a8, kTextEncoder);
    STRINGFUNC(decodeStringFromUTF8Array, kSig_from_a8, kTextDecoder);

#undef STRINGFUNC

    return strings;
  }

  // Creates and adds random tables.
  void GenerateRandomTables(const std::vector<ModuleTypeIndex>& array_types,
                            const std::vector<ModuleTypeIndex>& struct_types) {
    int num_tables = module_range_->get<uint8_t>() % kMaxTables + 1;
    int are_table64 = module_range_->get<uint8_t>();
    static_assert(
        kMaxTables <= 8,
        "Too many tables. Use more random bits to choose their address type.");
    for (int i = 0; i < num_tables; i++) {
      uint32_t min_size = i == 0
                              ? num_functions_
                              : module_range_->get<uint8_t>() % kMaxTableSize;
      uint32_t max_size =
          module_range_->get<uint8_t>() % (kMaxTableSize - min_size
Prompt: 
```
这是目录为v8/src/wasm/fuzzing/random-module-generation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/fuzzing/random-module-generation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能

"""
 + emit_i31ref + fallback_to_eqref);
        // Try generating one of the alternatives
        // and continue to the rest of the methods in case it fails.
        if (random >= num_types + emit_i31ref) {
          if (GenerateOneOf(alternatives_other, type, data, nullability)) {
            return;
          }
          random = data->get<uint8_t>() % (num_types + emit_i31ref);
        }
        if (random < num_types) {
          // Using `HeapType(random)` here relies on the assumption that struct
          // and array types come before signatures.
          DCHECK(builder_->builder()->IsArrayType(random) ||
                 builder_->builder()->IsStructType(random));
          GenerateRef(HeapType(ModuleTypeIndex{random}), data, nullability);
        } else {
          GenerateRef(HeapType(HeapType::kI31), data, nullability);
        }
        return;
      }
      case HeapType::kFunc: {
        uint32_t random = data->get<uint8_t>() % (functions_.size() + 1);
        /// Try generating one of the alternatives
        // and continue to the rest of the methods in case it fails.
        if (random >= functions_.size()) {
          if (GenerateOneOf(alternatives_func_any, type, data, nullability)) {
            return;
          }
          random = data->get<uint8_t>() % functions_.size();
        }
        ModuleTypeIndex signature_index = functions_[random];
        DCHECK(builder_->builder()->IsSignature(signature_index));
        GenerateRef(HeapType(signature_index), data, nullability);
        return;
      }
      case HeapType::kI31: {
        // Try generating one of the alternatives
        // and continue to the rest of the methods in case it fails.
        if (data->get<bool>() &&
            GenerateOneOf(alternatives_other, type, data, nullability)) {
          return;
        }
        Generate(kWasmI32, data);
        builder_->EmitWithPrefix(kExprRefI31);
        return;
      }
      case HeapType::kExn: {
        // TODO(manoskouk): Can we somehow come up with a nontrivial exnref?
        ref_null(type, data);
        if (nullability == kNonNullable) {
          builder_->Emit(kExprRefAsNonNull);
        }
        return;
      }
      case HeapType::kExtern: {
        uint8_t choice = data->get<uint8_t>();
        if (choice < 25) {
          // ~10% chance of extern.convert_any.
          GenerateRef(HeapType(HeapType::kAny), data);
          builder_->EmitWithPrefix(kExprExternConvertAny);
          if (nullability == kNonNullable) {
            builder_->Emit(kExprRefAsNonNull);
          }
          return;
        }
        // ~80% chance of string.
        if (choice < 230 && ShouldGenerateWasmGC(options)) {
          uint8_t subchoice = choice % 7;
          switch (subchoice) {
            case 0:
              return string_cast(data);
            case 1:
              return string_fromcharcode(data);
            case 2:
              return string_fromcodepoint(data);
            case 3:
              return string_concat(data);
            case 4:
              return string_substring(data);
            case 5:
              return string_fromcharcodearray(data);
            case 6:
              return string_fromutf8array(data);
          }
        }
        // ~10% chance of fallthrough.
        [[fallthrough]];
      }
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
      case HeapType::kNone:
      case HeapType::kNoExn:
        ref_null(type, data);
        if (nullability == kNonNullable) {
          builder_->Emit(kExprRefAsNonNull);
        }
        return;
      default:
        // Indexed type (i.e. user-defined type).
        DCHECK(type.is_index());
        if (ShouldGenerateWasmGC(options) &&
            type.ref_index() == string_imports_.array_i8 &&
            data->get<uint8_t>() < 32) {
          // 1/8th chance, fits the number of remaining alternatives (7) well.
          return string_toutf8array(data);
        }
        GenerateOneOf(alternatives_indexed_type, type, data, nullability);
        return;
    }
    UNREACHABLE();
  }

  void GenerateRef(DataRange* data) {
    constexpr HeapType::Representation top_types[] = {
        HeapType::kAny,
        HeapType::kFunc,
        HeapType::kExtern,
    };
    HeapType::Representation type =
        top_types[data->get<uint8_t>() % arraysize(top_types)];
    GenerateRef(HeapType(type), data);
  }

  std::vector<ValueType> GenerateTypes(DataRange* data) {
    return fuzzing::GenerateTypes<options>(
        data, static_cast<uint32_t>(functions_.size() + structs_.size() +
                                    arrays_.size()));
  }

  void Generate(base::Vector<const ValueType> types, DataRange* data) {
    // Maybe emit a multi-value block with the expected return type. Use a
    // non-default value to indicate block generation to avoid recursion when we
    // reach the end of the data.
    bool generate_block = data->get<uint8_t>() % 32 == 1;
    if (generate_block) {
      GeneratorRecursionScope rec_scope(this);
      if (!recursion_limit_reached()) {
        const auto param_types = GenerateTypes(data);
        Generate(base::VectorOf(param_types), data);
        any_block(base::VectorOf(param_types), types, data);
        return;
      }
    }

    if (types.size() == 0) {
      Generate(kWasmVoid, data);
      return;
    }
    if (types.size() == 1) {
      Generate(types[0], data);
      return;
    }

    // Split the types in two halves and recursively generate each half.
    // Each half is non empty to ensure termination.
    size_t split_index = data->get<uint8_t>() % (types.size() - 1) + 1;
    base::Vector<const ValueType> lower_half = types.SubVector(0, split_index);
    base::Vector<const ValueType> upper_half =
        types.SubVector(split_index, types.size());
    DataRange first_range = data->split();
    Generate(lower_half, &first_range);
    Generate(upper_half, data);
  }

  void Consume(ValueType type) {
    // Try to store the value in a local if there is a local with the same
    // type. TODO(14034): For reference types a local with a super type
    // would also be fine.
    size_t num_params = builder_->signature()->parameter_count();
    for (uint32_t local_offset = 0; local_offset < locals_.size();
         ++local_offset) {
      if (locals_[local_offset] == type) {
        uint32_t local_index = static_cast<uint32_t>(local_offset + num_params);
        builder_->EmitWithU32V(kExprLocalSet, local_index);
        return;
      }
    }
    for (uint32_t param_index = 0; param_index < num_params; ++param_index) {
      if (builder_->signature()->GetParam(param_index) == type) {
        builder_->EmitWithU32V(kExprLocalSet, param_index);
        return;
      }
    }
    // No opportunity found to use the value, so just drop it.
    builder_->Emit(kExprDrop);
  }

  // Emit code to match an arbitrary signature.
  // TODO(11954): Add the missing reference type conversion/upcasting.
  void ConsumeAndGenerate(base::Vector<const ValueType> param_types,
                          base::Vector<const ValueType> return_types,
                          DataRange* data) {
    // This numeric conversion logic consists of picking exactly one
    // index in the return values and dropping all the values that come
    // before that index. Then we convert the value from that index to the
    // wanted type. If we don't find any value we generate it.
    auto primitive = [](ValueType t) -> bool {
      switch (t.kind()) {
        case kI32:
        case kI64:
        case kF32:
        case kF64:
          return true;
        default:
          return false;
      }
    };

    if (return_types.size() == 0 || param_types.size() == 0 ||
        !primitive(return_types[0])) {
      for (auto iter = param_types.rbegin(); iter != param_types.rend();
           ++iter) {
        Consume(*iter);
      }
      Generate(return_types, data);
      return;
    }

    int bottom_primitives = 0;

    while (static_cast<int>(param_types.size()) > bottom_primitives &&
           primitive(param_types[bottom_primitives])) {
      bottom_primitives++;
    }
    int return_index =
        bottom_primitives > 0 ? (data->get<uint8_t>() % bottom_primitives) : -1;
    for (int i = static_cast<int>(param_types.size() - 1); i > return_index;
         --i) {
      Consume(param_types[i]);
    }
    for (int i = return_index; i > 0; --i) {
      Convert(param_types[i], param_types[i - 1]);
      builder_->EmitI32Const(0);
      builder_->Emit(kExprSelect);
    }
    DCHECK(!return_types.empty());
    if (return_index >= 0) {
      Convert(param_types[0], return_types[0]);
      Generate(return_types + 1, data);
    } else {
      Generate(return_types, data);
    }
  }

  bool HasSimd() { return has_simd_; }

  void InitializeNonDefaultableLocals(DataRange* data) {
    for (uint32_t i = 0; i < locals_.size(); i++) {
      if (!locals_[i].is_defaultable()) {
        GenerateRef(locals_[i].heap_type(), data, kNonNullable);
        builder_->EmitWithU32V(
            kExprLocalSet, i + static_cast<uint32_t>(
                                   builder_->signature()->parameter_count()));
      }
    }
    locals_initialized_ = true;
  }

 private:
  WasmFunctionBuilder* builder_;
  std::vector<std::vector<ValueType>> blocks_;
  const std::vector<ModuleTypeIndex>& functions_;
  std::vector<ValueType> locals_;
  std::vector<ValueType> globals_;
  std::vector<uint8_t> mutable_globals_;  // indexes into {globals_}.
  uint32_t recursion_depth = 0;
  std::vector<int> catch_blocks_;
  bool has_simd_ = false;
  const std::vector<ModuleTypeIndex>& structs_;
  const std::vector<ModuleTypeIndex>& arrays_;
  const StringImports& string_imports_;
  bool locals_initialized_ = false;

  bool recursion_limit_reached() {
    return recursion_depth >= kMaxRecursionDepth;
  }
};

WasmInitExpr GenerateInitExpr(Zone* zone, DataRange& range,
                              WasmModuleBuilder* builder, ValueType type,
                              const std::vector<ModuleTypeIndex>& structs,
                              const std::vector<ModuleTypeIndex>& arrays,
                              uint32_t recursion_depth);

template <WasmModuleGenerationOptions options>
class ModuleGen {
 public:
  explicit ModuleGen(Zone* zone, WasmModuleBuilder* fn, DataRange* module_range,
                     uint8_t num_functions, uint8_t num_structs,
                     uint8_t num_arrays, uint8_t num_signatures)
      : zone_(zone),
        builder_(fn),
        module_range_(module_range),
        num_functions_(num_functions),
        num_structs_(num_structs),
        num_arrays_(num_arrays),
        num_signatures_(num_signatures),
        num_types_(num_signatures + num_structs + num_arrays) {}

  // Generates and adds random number of memories.
  void GenerateRandomMemories() {
    int num_memories = 1 + (module_range_->get<uint8_t>() % kMaxMemories);
    for (int i = 0; i < num_memories; i++) {
      uint8_t random_byte = module_range_->get<uint8_t>();
      bool mem64 = random_byte & 1;
      bool has_maximum = random_byte & 2;
      static_assert(kV8MaxWasmMemory64Pages <= kMaxUInt32);
      uint32_t max_supported_pages =
          mem64 ? kV8MaxWasmMemory64Pages : kV8MaxWasmMemory32Pages;
      uint32_t min_pages =
          module_range_->get<uint32_t>() % (max_supported_pages + 1);
      if (has_maximum) {
        uint32_t max_pages =
            std::max(min_pages, module_range_->get<uint32_t>() %
                                    (max_supported_pages + 1));
        if (mem64) {
          builder_->AddMemory64(min_pages, max_pages);
        } else {
          builder_->AddMemory(min_pages, max_pages);
        }
      } else {
        if (mem64) {
          builder_->AddMemory64(min_pages);
        } else {
          builder_->AddMemory(min_pages);
        }
      }
    }
  }

  // Puts the types into random recursive groups.
  std::map<uint8_t, uint8_t> GenerateRandomRecursiveGroups(
      uint8_t kNumDefaultArrayTypes) {
    // (Type_index -> end of explicit rec group).
    std::map<uint8_t, uint8_t> explicit_rec_groups;
    uint8_t current_type_index = 0;

    // The default array types are each in their own recgroup.
    for (uint8_t i = 0; i < kNumDefaultArrayTypes; i++) {
      explicit_rec_groups.emplace(current_type_index, current_type_index);
      builder_->AddRecursiveTypeGroup(current_type_index++, 1);
    }

    while (current_type_index < num_types_) {
      // First, pick a random start for the next group. We allow it to be
      // beyond the end of types (i.e., we add no further recursive groups).
      uint8_t group_start = module_range_->get<uint8_t>() %
                                (num_types_ - current_type_index + 1) +
                            current_type_index;
      DCHECK_GE(group_start, current_type_index);
      current_type_index = group_start;
      if (group_start < num_types_) {
        // If we did not reach the end of the types, pick a random group size.
        uint8_t group_size =
            module_range_->get<uint8_t>() % (num_types_ - group_start) + 1;
        DCHECK_LE(group_start + group_size, num_types_);
        for (uint8_t i = group_start; i < group_start + group_size; i++) {
          explicit_rec_groups.emplace(i, group_start + group_size - 1);
        }
        builder_->AddRecursiveTypeGroup(group_start, group_size);
        current_type_index += group_size;
      }
    }
    return explicit_rec_groups;
  }

  // Generates and adds random struct types.
  void GenerateRandomStructs(
      const std::map<uint8_t, uint8_t>& explicit_rec_groups,
      std::vector<ModuleTypeIndex>& struct_types, uint8_t& current_type_index,
      uint8_t kNumDefaultArrayTypes) {
    uint8_t last_struct_type_index = current_type_index + num_structs_;
    for (; current_type_index < last_struct_type_index; current_type_index++) {
      auto rec_group = explicit_rec_groups.find(current_type_index);
      uint8_t current_rec_group_end = rec_group != explicit_rec_groups.end()
                                          ? rec_group->second
                                          : current_type_index;

      ModuleTypeIndex supertype = kNoSuperType;
      uint8_t num_fields =
          module_range_->get<uint8_t>() % (kMaxStructFields + 1);

      uint32_t existing_struct_types =
          current_type_index - kNumDefaultArrayTypes;
      if (existing_struct_types > 0 && module_range_->get<bool>()) {
        supertype = ModuleTypeIndex{module_range_->get<uint8_t>() %
                                        existing_struct_types +
                                    kNumDefaultArrayTypes};
        num_fields += builder_->GetStructType(supertype)->field_count();
      }
      StructType::Builder struct_builder(zone_, num_fields);

      // Add all fields from super type.
      uint32_t field_index = 0;
      if (supertype != kNoSuperType) {
        const StructType* parent = builder_->GetStructType(supertype);
        for (; field_index < parent->field_count(); ++field_index) {
          // TODO(14034): This could also be any sub type of the supertype's
          // element type.
          struct_builder.AddField(parent->field(field_index),
                                  parent->mutability(field_index));
        }
      }
      for (; field_index < num_fields; field_index++) {
        // Notes:
        // - We allow a type to only have non-nullable fields of types that
        //   are defined earlier. This way we avoid infinite non-nullable
        //   constructions. Also relevant for arrays and functions.
        // - On the other hand, nullable fields can be picked up to the end of
        //   the current recursive group.
        // - We exclude the non-nullable generic types arrayref, anyref,
        //   structref, eqref and externref from the fields of structs and
        //   arrays. This is so that GenerateInitExpr has a way to break a
        //   recursion between a struct/array field and those types
        //   ((ref extern) gets materialized through (ref any)).
        ValueType type = GetValueTypeHelper<options>(
            module_range_, current_rec_group_end + 1, current_type_index,
            kIncludeNumericTypes, kIncludePackedTypes, kExcludeSomeGenerics);

        bool mutability = module_range_->get<bool>();
        struct_builder.AddField(type, mutability);
      }
      StructType* struct_fuz = struct_builder.Build();
      // TODO(14034): Generate some final types too.
      ModuleTypeIndex index =
          builder_->AddStructType(struct_fuz, false, supertype);
      struct_types.push_back(index);
    }
  }

  // Creates and adds random array types.
  void GenerateRandomArrays(
      const std::map<uint8_t, uint8_t>& explicit_rec_groups,
      std::vector<ModuleTypeIndex>& array_types, uint8_t& current_type_index) {
    uint32_t last_struct_type_index = current_type_index + num_structs_;
    for (; current_type_index < num_structs_ + num_arrays_;
         current_type_index++) {
      auto rec_group = explicit_rec_groups.find(current_type_index);
      uint8_t current_rec_group_end = rec_group != explicit_rec_groups.end()
                                          ? rec_group->second
                                          : current_type_index;
      ValueType type = GetValueTypeHelper<options>(
          module_range_, current_rec_group_end + 1, current_type_index,
          kIncludeNumericTypes, kIncludePackedTypes, kExcludeSomeGenerics);
      ModuleTypeIndex supertype = kNoSuperType;
      if (current_type_index > last_struct_type_index &&
          module_range_->get<bool>()) {
        // Do not include the default array types, because they are final.
        uint8_t existing_array_types =
            current_type_index - last_struct_type_index;
        supertype = ModuleTypeIndex{
            last_struct_type_index +
            (module_range_->get<uint8_t>() % existing_array_types)};
        // TODO(14034): This could also be any sub type of the supertype's
        // element type.
        type = builder_->GetArrayType(supertype)->element_type();
      }
      ArrayType* array_fuz = zone_->New<ArrayType>(type, true);
      // TODO(14034): Generate some final types too.
      ModuleTypeIndex index =
          builder_->AddArrayType(array_fuz, false, supertype);
      array_types.push_back(index);
    }
  }

  enum SigKind { kFunctionSig, kExceptionSig };

  FunctionSig* GenerateSig(SigKind sig_kind, int num_types) {
    // Generate enough parameters to spill some to the stack.
    int num_params = int{module_range_->get<uint8_t>()} % (kMaxParameters + 1);
    int num_returns =
        sig_kind == kFunctionSig
            ? int{module_range_->get<uint8_t>()} % (kMaxReturns + 1)
            : 0;

    FunctionSig::Builder builder(zone_, num_returns, num_params);
    for (int i = 0; i < num_returns; ++i) {
      builder.AddReturn(GetValueType<options>(module_range_, num_types));
    }
    for (int i = 0; i < num_params; ++i) {
      builder.AddParam(GetValueType<options>(module_range_, num_types));
    }
    return builder.Get();
  }

  // Creates and adds random function signatures.
  void GenerateRandomFunctionSigs(
      const std::map<uint8_t, uint8_t>& explicit_rec_groups,
      std::vector<ModuleTypeIndex>& function_signatures,
      uint8_t& current_type_index, bool kIsFinal) {
    // Recursive groups consist of recursive types that came with the WasmGC
    // proposal.
    DCHECK_IMPLIES(!ShouldGenerateWasmGC(options), explicit_rec_groups.empty());

    for (; current_type_index < num_types_; current_type_index++) {
      auto rec_group = explicit_rec_groups.find(current_type_index);
      uint8_t current_rec_group_end = rec_group != explicit_rec_groups.end()
                                          ? rec_group->second
                                          : current_type_index;
      FunctionSig* sig = GenerateSig(kFunctionSig, current_rec_group_end + 1);
      ModuleTypeIndex signature_index =
          builder_->ForceAddSignature(sig, kIsFinal);
      function_signatures.push_back(signature_index);
    }
  }

  void GenerateRandomExceptions(uint8_t num_exceptions) {
    for (int i = 0; i < num_exceptions; ++i) {
      FunctionSig* sig = GenerateSig(kExceptionSig, num_types_);
      builder_->AddTag(sig);
    }
  }

  // Adds the "wasm:js-string" imports to the module.
  StringImports AddImportedStringImports() {
    static constexpr ModuleTypeIndex kArrayI8{0};
    static constexpr ModuleTypeIndex kArrayI16{1};
    StringImports strings;
    strings.array_i8 = kArrayI8;
    strings.array_i16 = kArrayI16;
    static constexpr ValueType kRefExtern = ValueType::Ref(HeapType::kExtern);
    static constexpr ValueType kExternRef = kWasmExternRef;
    static constexpr ValueType kI32 = kWasmI32;
    static constexpr ValueType kRefA8 = ValueType::Ref(kArrayI8);
    static constexpr ValueType kRefNullA8 = ValueType::RefNull(kArrayI8);
    static constexpr ValueType kRefNullA16 = ValueType::RefNull(kArrayI16);

    // Shorthands: "r" = nullable "externref",
    // "e" = non-nullable "ref extern".
    static constexpr ValueType kReps_e_i[] = {kRefExtern, kI32};
    static constexpr ValueType kReps_e_rr[] = {kRefExtern, kExternRef,
                                               kExternRef};
    static constexpr ValueType kReps_e_rii[] = {kRefExtern, kExternRef, kI32,
                                                kI32};
    static constexpr ValueType kReps_i_ri[] = {kI32, kExternRef, kI32};
    static constexpr ValueType kReps_i_rr[] = {kI32, kExternRef, kExternRef};
    static constexpr ValueType kReps_from_a16[] = {kRefExtern, kRefNullA16,
                                                   kI32, kI32};
    static constexpr ValueType kReps_from_a8[] = {kRefExtern, kRefNullA8, kI32,
                                                  kI32};
    static constexpr ValueType kReps_into_a16[] = {kI32, kExternRef,
                                                   kRefNullA16, kI32};
    static constexpr ValueType kReps_into_a8[] = {kI32, kExternRef, kRefNullA8,
                                                  kI32};
    static constexpr ValueType kReps_to_a8[] = {kRefA8, kExternRef};

    static constexpr FunctionSig kSig_e_i(1, 1, kReps_e_i);
    static constexpr FunctionSig kSig_e_r(1, 1, kReps_e_rr);
    static constexpr FunctionSig kSig_e_rr(1, 2, kReps_e_rr);
    static constexpr FunctionSig kSig_e_rii(1, 3, kReps_e_rii);

    static constexpr FunctionSig kSig_i_r(1, 1, kReps_i_ri);
    static constexpr FunctionSig kSig_i_ri(1, 2, kReps_i_ri);
    static constexpr FunctionSig kSig_i_rr(1, 2, kReps_i_rr);
    static constexpr FunctionSig kSig_from_a16(1, 3, kReps_from_a16);
    static constexpr FunctionSig kSig_from_a8(1, 3, kReps_from_a8);
    static constexpr FunctionSig kSig_into_a16(1, 3, kReps_into_a16);
    static constexpr FunctionSig kSig_into_a8(1, 3, kReps_into_a8);
    static constexpr FunctionSig kSig_to_a8(1, 1, kReps_to_a8);

    static constexpr base::Vector<const char> kJsString =
        base::StaticCharVector("wasm:js-string");
    static constexpr base::Vector<const char> kTextDecoder =
        base::StaticCharVector("wasm:text-decoder");
    static constexpr base::Vector<const char> kTextEncoder =
        base::StaticCharVector("wasm:text-encoder");

#define STRINGFUNC(name, sig, group) \
  strings.name = builder_->AddImport(base::CStrVector(#name), &sig, group)

    STRINGFUNC(cast, kSig_e_r, kJsString);
    STRINGFUNC(test, kSig_i_r, kJsString);
    STRINGFUNC(fromCharCode, kSig_e_i, kJsString);
    STRINGFUNC(fromCodePoint, kSig_e_i, kJsString);
    STRINGFUNC(charCodeAt, kSig_i_ri, kJsString);
    STRINGFUNC(codePointAt, kSig_i_ri, kJsString);
    STRINGFUNC(length, kSig_i_r, kJsString);
    STRINGFUNC(concat, kSig_e_rr, kJsString);
    STRINGFUNC(substring, kSig_e_rii, kJsString);
    STRINGFUNC(equals, kSig_i_rr, kJsString);
    STRINGFUNC(compare, kSig_i_rr, kJsString);
    STRINGFUNC(fromCharCodeArray, kSig_from_a16, kJsString);
    STRINGFUNC(intoCharCodeArray, kSig_into_a16, kJsString);
    STRINGFUNC(measureStringAsUTF8, kSig_i_r, kTextEncoder);
    STRINGFUNC(encodeStringIntoUTF8Array, kSig_into_a8, kTextEncoder);
    STRINGFUNC(encodeStringToUTF8Array, kSig_to_a8, kTextEncoder);
    STRINGFUNC(decodeStringFromUTF8Array, kSig_from_a8, kTextDecoder);

#undef STRINGFUNC

    return strings;
  }

  // Creates and adds random tables.
  void GenerateRandomTables(const std::vector<ModuleTypeIndex>& array_types,
                            const std::vector<ModuleTypeIndex>& struct_types) {
    int num_tables = module_range_->get<uint8_t>() % kMaxTables + 1;
    int are_table64 = module_range_->get<uint8_t>();
    static_assert(
        kMaxTables <= 8,
        "Too many tables. Use more random bits to choose their address type.");
    for (int i = 0; i < num_tables; i++) {
      uint32_t min_size = i == 0
                              ? num_functions_
                              : module_range_->get<uint8_t>() % kMaxTableSize;
      uint32_t max_size =
          module_range_->get<uint8_t>() % (kMaxTableSize - min_size) + min_size;
      // Table 0 is always funcref. This guarantees that
      // - call_indirect has at least one funcref table to work with,
      // - we have a place to reference all functions in the program, so they
      //   count as "declared" for ref.func.
      bool force_funcref = i == 0;
      ValueType type =
          force_funcref
              ? kWasmFuncRef
              : GetValueTypeHelper<options>(
                    module_range_, num_types_, num_types_, kExcludeNumericTypes,
                    kExcludePackedTypes, kIncludeAllGenerics);
      bool use_initializer =
          !type.is_defaultable() || module_range_->get<bool>();
      AddressType address_type =
          (are_table64 & 1) ? AddressType::kI32 : AddressType::kI64;
      are_table64 >>= 1;
      uint32_t table_index =
          use_initializer
              ? builder_->AddTable(
                    type, min_size, max_size,
                    GenerateInitExpr(zone_, *module_range_, builder_, type,
                                     struct_types, array_types, 0),
                    address_type)
              : builder_->AddTable(type, min_size, max_size, address_type);
      if (type.is_reference_to(HeapType::kFunc)) {
        // For function tables, initialize them with functions from the program.
        // Currently, the fuzzer assumes that every funcref/(ref func) table
        // contains the functions in the program in the order they are defined.
        // TODO(11954): Consider generalizing this.
        WasmInitExpr init_expr = builder_->IsTable64(table_index)
                                     ? WasmInitExpr(static_cast<int64_t>(0))
                                     : WasmInitExpr(static_cast<int32_t>(0));
        WasmModuleBuilder::WasmElemSegment segment(zone_, type, table_index,
                                                   init_expr);
        for (int entry_index = 0; entry_index < static_cast<int>(min_size);
             entry_index++) {
          segment.entries.emplace_back(
              WasmModuleBuilder::WasmElemSegment::Entry::kRefFuncEntry,
              builder_->NumImportedFunctions() +
                  (entry_index % num_functions_));
        }
        builder_->AddElementSegment(std::move(segment));
      }
    }
  }

  // Creates and adds random globals.
  std::tuple<std::vector<ValueType>, std::vector<uint8_t>>
  GenerateRandomGlobals(const std::vector<ModuleTypeIndex>& array_types,
                        const std::vector<ModuleTypeIndex>& struct_types) {
    int num_globals = module_range_->get<uint8_t>() % (kMaxGlobals + 1);
    std::vector<ValueType> globals;
    std::vector<uint8_t> mutable_globals;
    globals.reserve(num_globals);
    mutable_globals.reserve(num_globals);

    for (int i = 0; i < num_globals; ++i) {
      ValueType type = GetValueType<options>(module_range_, num_types_);
      // 1/8 of globals are immutable.
      const bool mutability = (module_range_->get<uint8_t>() % 8) != 0;
      builder_->AddGlobal(type, mutability,
                          GenerateInitExpr(zone_, *module_range_, builder_,
                                           type, struct_types, array_types, 0));
      globals.push_back(type);
      if (mutability) mutable_globals.push_back(static_cast<uint8_t>(i));
    }

    return {globals, mutable_globals};
  }

 private:
  Zone* zone_;
  WasmModuleBuilder* builder_;
  DataRange* module_range_;
  const uint8_t num_functions_;
  const uint8_t num_structs_;
  const uint8_t num_arrays_;
  const uint8_t num_signatures_;
  const uint16_t num_types_;
};

WasmInitExpr GenerateStructNewInitExpr(
    Zone* zone, DataRange& range, WasmModuleBuilder* builder,
    ModuleTypeIndex index, const std::vector<ModuleTypeIndex>& structs,
    const std::vector<ModuleTypeIndex>& arrays, uint32_t recursion_depth) {
  const StructType* struct_type = builder->GetStructType(index);
  bool use_new_default =
      std::all_of(struct_type->fields().begin(), struct_type->fields().end(),
                  [](ValueType type) { return type.is_defaultable(); }) &&
      range.get<bool>();

  if (use_new_default) {
    return WasmInitExpr::StructNewDefault(index);
  } else {
    ZoneVector<WasmInitExpr>* elements =
        zone->New<ZoneVector<WasmInitExpr>>(zone);
    int field_count = struct_type->field_count();
    for (int field_index = 0; field_index < field_count; field_index++) {
      elements->push_back(GenerateInitExpr(
          zone, range, builder, struct_type->field(field_index), structs,
          arrays, recursion_depth + 1));
    }
    return WasmInitExpr::StructNew(index, elements);
  }
}

WasmInitExpr GenerateArrayInitExpr(Zone* zone, DataRange& range,
                                   WasmModuleBuilder* builder,
                                   ModuleTypeIndex index,
                                   const std::vector<ModuleTypeIndex>& structs,
                                   const std::vector<ModuleTypeIndex>& arrays,
                                   uint32_t recursion_depth) {
  constexpr int kMaxArrayLength = 20;
  uint8_t choice = range.get<uint8_t>() % 3;
  ValueType element_type = builder->GetArrayType(index)->element_type();
  if (choice == 0) {
    size_t element_count = range.get<uint8_t>() % kMaxArrayLength;
    if (!element_type.is_defaultable()) {
      // If the element type is not defaultable, limit the size to 0 or 1
      // to prevent having to create too many such elements on the value
      // stack. (With multiple non-nullable references, this can explode
      // in size very quickly.)
      element_count %= 2;
    }
    ZoneVector<WasmInitExpr>* elements =
        zone->New<ZoneVector<WasmInitExpr>>(zone);
    for (size_t i = 0; i < element_count; i++) {
      elements->push_back(GenerateInitExpr(zone, range, builder, element_type,
                                           structs, arrays,
                                           recursion_depth + 1));
    }
    return WasmInitExpr::ArrayNewFixed(index, elements);
  } else if (choice == 1 || !element_type.is_defaultable()) {
    // TODO(14034): Add other int expressions to length (same below).
    WasmInitExpr length = WasmInitExpr(range.get<uint8_t>() % kMaxArrayLength);
    WasmInitExpr init = GenerateInitExpr(zone, range, builder, element_type,
                                         structs, arrays, recursion_depth + 1);
    return WasmInitExpr::ArrayNew(zone, index, init, length);
  } else {
    WasmInitExpr length = WasmInitExpr(range.get<uint8_t>() % kMaxArrayLength);
    return WasmInitExpr::ArrayNewDefault(zone, index, length);
  }
}

WasmInitExpr GenerateInitExpr(Zone* zone, DataRange& range,
                              WasmModuleBuilder* builder, ValueType type,
                              const std::vector<ModuleTypeIndex>& structs,
                              const std::vector<ModuleTypeIndex>& arrays,
                              uint32_t recursion_depth) {
  switch (type.kind()) {
    case kI8:
    case kI16:
    case kI32: {
      if (range.size() == 0 || recursion_depth >= kMaxRecursionDepth) {
        return WasmInitExpr(int32_t{0});
      }
      // 50% to generate a constant, 50% to generate a binary operator.
      uint8_t choice = range.get<uint8_t>() % 6;
      switch (choice) {
        case 0:
        case 1:
        case 2:
          if (choice % 2 == 0 && builder->NumGlobals()) {
            // Search for a matching global to emit a global.get.
            int num_globals = builder->NumGlobals();
            int start_index = range.get<uint8_t>() % num_globals;
            for (int
"""


```