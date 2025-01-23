Response: The user wants a summary of the C++ code in `v8/src/codegen/code-stub-assembler.cc`, specifically part 11 out of 12. They also want to know how it relates to JavaScript and see a JavaScript example if applicable.

My plan is to:
1. **Scan the code:** Quickly read through the provided C++ code to get a high-level understanding of the functions and their purposes.
2. **Identify key functionalities:** Group related functions and determine the main features implemented in this code snippet.
3. **Summarize the functionalities:**  Describe the identified features in concise terms.
4. **Analyze the relation to JavaScript:** Think about how these C++ functionalities could be used in the V8 engine to execute JavaScript code.
5. **Provide a JavaScript example:** If a clear connection to a JavaScript feature exists, create a simple JavaScript code snippet that demonstrates it.
Based on the provided C++ code snippet from `v8/src/codegen/code-stub-assembler.cc`, this part of the file focuses on providing **helper functions and utilities for generating machine code within the CodeStubAssembler framework**. It offers abstractions and operations related to various aspects of the V8 engine's internals.

Here's a breakdown of the functionalities:

* **Elements Kind Operations:**  Functions like `IsHoleyElementsKind`, `IsElementsKindGreaterThan`, etc., are used to check and compare the *kind* of elements stored in JavaScript arrays. This is crucial for optimizing array operations based on the element types (e.g., packed integers, doubles, or potentially "holey" arrays with missing elements).

* **Debugging and Asynchronous Operations:** Functions like `IsDebugActive` and `HasAsyncEventDelegate` provide information about the current state of the V8 engine, specifically whether the debugger is active or if there's an asynchronous event delegate registered. These are important for features like debugging JavaScript code and handling asynchronous operations (like Promises).

* **Promise Hook Management:**  Functions such as `PromiseHookFlags`, `IsAnyPromiseHookEnabled`, etc., deal with enabling and checking the status of Promise hooks. These hooks allow external code to intercept and monitor Promise lifecycle events, which is useful for debugging and performance analysis.

* **Builtin Code Loading:** The `LoadBuiltin` function retrieves the machine code associated with a specific built-in JavaScript function (like `Array.prototype.push` or `Math.sin`). This is fundamental for executing JavaScript code efficiently, as many core functionalities are implemented as optimized built-ins.

* **SharedFunctionInfo Code Retrieval:** The `GetSharedFunctionInfoCode` function is responsible for determining the actual executable code associated with a `SharedFunctionInfo` object. A `SharedFunctionInfo` stores metadata about a JavaScript function. This function handles various scenarios, including compiled bytecode, baseline code, interpreter data, and uncompiled functions (which need lazy compilation).

* **Code Object Information:**  Functions like `LoadCodeInstructionStart` and `IsMarkedForDeoptimization` provide access to information about `Code` objects, which represent compiled machine code. This includes the starting address of the code and whether it's marked for deoptimization (a process where optimized code is discarded in favor of slower, more generic code when assumptions are violated).

* **Root Function Allocation:**  `AllocateRootFunctionWithContext` is used to create instances of built-in JavaScript functions. It sets up the necessary internal fields like the map, properties, elements, and the associated code.

* **Prototype Chain and Enum Cache Checks:**  `CheckPrototypeEnumCache` and `CheckEnumCache` are related to optimizing property access in JavaScript. They check if the prototype chain and enumeration caches are in a consistent and expected state, allowing for faster property lookups.

* **Argument Handling:** `GetArgumentValue` and `SetArgumentValue` are utilities for accessing and modifying arguments passed to functions within the code stubs.

* **Printing and Debugging:** The `Print` and `PrintErr` functions provide ways to output debugging information during code stub execution.

* **Stack Checking:** `PerformStackCheck` ensures that the current stack usage is within limits to prevent stack overflow errors.

* **Array Creation:** `CallRuntimeNewArray`, `TailCallRuntimeNewArray`, and `ArrayCreate` provide different ways to create JavaScript arrays, potentially using runtime calls for more complex scenarios or directly allocating memory for simpler cases.

* **Property Length Manipulation:** `SetPropertyLength` is used to set the `length` property of JavaScript array-like objects.

* **Math Random Refill:** `RefillMathRandom` is specific to the `Math.random()` function and handles replenishing the internal random number cache.

* **String Conversion:** `TaggedToDirectString` helps in efficiently converting tagged JavaScript string objects to their underlying raw string representation.

* **Finalization Registry Management:** `RemoveFinalizationRegistryCellFromUnregisterTokenMap` is involved in managing finalization registries, which allow running cleanup code when objects are garbage collected.

* **Prototype Checking with Identity and Constness:** The `PrototypeCheckAssembler` class provides more sophisticated checks for the integrity of prototype objects, including verifying property values and constness.

* **Swiss Name Dictionary Operations:** A significant portion of this part deals with the implementation and manipulation of `SwissNameDictionary`, a high-performance hash table used for storing object properties. This includes functions for allocation, copying, loading/storing elements, and searching within the dictionary.

* **Shared Value Barrier:** `SharedValueBarrier` ensures that certain JavaScript values can be safely shared across different isolates (independent instances of the V8 engine).

* **ArrayList Allocation:** `AllocateArrayList` provides a mechanism for allocating dynamic arrays.

**Relationship to JavaScript and Example:**

Many of these functions directly support the execution of JavaScript code. For example, consider the `GetSharedFunctionInfoCode` function. When JavaScript code calls a function, V8 needs to find the executable code for that function. This function is a key part of that process.

Here's a simplified JavaScript example that demonstrates the relevance of `GetSharedFunctionInfoCode`:

```javascript
function myFunction() {
  console.log("Hello from myFunction!");
}

myFunction(); // When this line executes, V8 uses GetSharedFunctionInfoCode (among other things)
              // to determine how to execute the code inside myFunction.
```

In this example, when `myFunction()` is called, V8 will:

1. Look up the `SharedFunctionInfo` associated with `myFunction`.
2. Call `GetSharedFunctionInfoCode` on that `SharedFunctionInfo`.
3. Based on whether the function has been compiled, is running in the interpreter, etc., `GetSharedFunctionInfoCode` will return the appropriate code entry point (e.g., the interpreter entry trampoline, the compiled code address, or a trigger for lazy compilation).

Similarly, the `SwissNameDictionary` functions are used internally when you create JavaScript objects and add properties to them. V8 might use a `SwissNameDictionary` to store the properties of your object efficiently.

```javascript
const myObject = {
  name: "Alice",
  age: 30
};
```

When these properties are added to `myObject`, V8 might internally use the `SwissNameDictionaryAdd` function (or similar dictionary operations) to store the "name" and "age" properties and their corresponding values.

In summary, this part of `code-stub-assembler.cc` provides low-level building blocks and utilities that the V8 engine uses to implement core JavaScript functionalities, optimize performance, and manage internal state. It bridges the gap between high-level JavaScript code and the underlying machine instructions that the processor executes.

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第11部分，共12部分，请归纳一下它的功能
```

### 源代码
```
(PACKED_NONEXTENSIBLE_ELEMENTS | 1));
  static_assert(HOLEY_SEALED_ELEMENTS == (PACKED_SEALED_ELEMENTS | 1));
  static_assert(HOLEY_FROZEN_ELEMENTS == (PACKED_FROZEN_ELEMENTS | 1));
  return IsSetWord32(elements_kind, 1);
}

TNode<BoolT> CodeStubAssembler::IsElementsKindGreaterThan(
    TNode<Int32T> target_kind, ElementsKind reference_kind) {
  return Int32GreaterThan(target_kind, Int32Constant(reference_kind));
}

TNode<BoolT> CodeStubAssembler::IsElementsKindGreaterThanOrEqual(
    TNode<Int32T> target_kind, ElementsKind reference_kind) {
  return Int32GreaterThanOrEqual(target_kind, Int32Constant(reference_kind));
}

TNode<BoolT> CodeStubAssembler::IsElementsKindLessThanOrEqual(
    TNode<Int32T> target_kind, ElementsKind reference_kind) {
  return Int32LessThanOrEqual(target_kind, Int32Constant(reference_kind));
}

TNode<Int32T> CodeStubAssembler::GetNonRabGsabElementsKind(
    TNode<Int32T> elements_kind) {
  Label is_rab_gsab(this), end(this);
  TVARIABLE(Int32T, result);
  result = elements_kind;
  Branch(Int32GreaterThanOrEqual(elements_kind,
                                 Int32Constant(RAB_GSAB_UINT8_ELEMENTS)),
         &is_rab_gsab, &end);
  BIND(&is_rab_gsab);
  result = Int32Sub(elements_kind,
                    Int32Constant(RAB_GSAB_UINT8_ELEMENTS - UINT8_ELEMENTS));
  Goto(&end);
  BIND(&end);
  return result.value();
}

TNode<BoolT> CodeStubAssembler::IsDebugActive() {
  TNode<Uint8T> is_debug_active = Load<Uint8T>(
      ExternalConstant(ExternalReference::debug_is_active_address(isolate())));
  return Word32NotEqual(is_debug_active, Int32Constant(0));
}

TNode<BoolT> CodeStubAssembler::HasAsyncEventDelegate() {
  const TNode<RawPtrT> async_event_delegate = Load<RawPtrT>(ExternalConstant(
      ExternalReference::async_event_delegate_address(isolate())));
  return WordNotEqual(async_event_delegate, IntPtrConstant(0));
}

TNode<Uint32T> CodeStubAssembler::PromiseHookFlags() {
  return Load<Uint32T>(ExternalConstant(
    ExternalReference::promise_hook_flags_address(isolate())));
}

TNode<BoolT> CodeStubAssembler::IsAnyPromiseHookEnabled(TNode<Uint32T> flags) {
  uint32_t mask = Isolate::PromiseHookFields::HasContextPromiseHook::kMask |
                  Isolate::PromiseHookFields::HasIsolatePromiseHook::kMask;
  return IsSetWord32(flags, mask);
}

TNode<BoolT> CodeStubAssembler::IsIsolatePromiseHookEnabled(
    TNode<Uint32T> flags) {
  return IsSetWord32<Isolate::PromiseHookFields::HasIsolatePromiseHook>(flags);
}

#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
TNode<BoolT> CodeStubAssembler::IsContextPromiseHookEnabled(
    TNode<Uint32T> flags) {
  return IsSetWord32<Isolate::PromiseHookFields::HasContextPromiseHook>(flags);
}
#endif

TNode<BoolT>
CodeStubAssembler::IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate(
    TNode<Uint32T> flags) {
  uint32_t mask = Isolate::PromiseHookFields::HasIsolatePromiseHook::kMask |
                  Isolate::PromiseHookFields::HasAsyncEventDelegate::kMask;
  return IsSetWord32(flags, mask);
}

TNode<BoolT> CodeStubAssembler::
    IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(
        TNode<Uint32T> flags) {
  uint32_t mask = Isolate::PromiseHookFields::HasIsolatePromiseHook::kMask |
                  Isolate::PromiseHookFields::HasAsyncEventDelegate::kMask |
                  Isolate::PromiseHookFields::IsDebugActive::kMask;
  return IsSetWord32(flags, mask);
}

TNode<BoolT> CodeStubAssembler::NeedsAnyPromiseHooks(TNode<Uint32T> flags) {
  return Word32NotEqual(flags, Int32Constant(0));
}

TNode<Code> CodeStubAssembler::LoadBuiltin(TNode<Smi> builtin_id) {
  CSA_DCHECK(this, SmiBelow(builtin_id, SmiConstant(Builtins::kBuiltinCount)));

  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(SmiToBInt(builtin_id), SYSTEM_POINTER_ELEMENTS);

  TNode<ExternalReference> table = IsolateField(IsolateFieldId::kBuiltinTable);

  return CAST(BitcastWordToTagged(Load<RawPtrT>(table, offset)));
}

#ifdef V8_ENABLE_LEAPTIERING
TNode<JSDispatchHandleT> CodeStubAssembler::LoadBuiltinDispatchHandle(
    JSBuiltinDispatchHandleRoot::Idx dispatch_root_idx) {
  static_assert(Isolate::kBuiltinDispatchHandlesAreStatic);
  DCHECK_LT(dispatch_root_idx, JSBuiltinDispatchHandleRoot::Idx::kCount);
  return ReinterpretCast<JSDispatchHandleT>(
      Uint32Constant(isolate()->builtin_dispatch_handle(dispatch_root_idx)));
}
#endif  // V8_ENABLE_LEAPTIERING

TNode<Code> CodeStubAssembler::GetSharedFunctionInfoCode(
    TNode<SharedFunctionInfo> shared_info, TVariable<Uint16T>* data_type_out,
    Label* if_compile_lazy) {

  Label done(this);
  Label use_untrusted_data(this);
  Label unknown_data(this);
  TVARIABLE(Code, sfi_code);

  TNode<Object> sfi_data = LoadSharedFunctionInfoTrustedData(shared_info);
  GotoIf(TaggedEqual(sfi_data, SmiConstant(0)), &use_untrusted_data);
  {
    TNode<Uint16T> data_type = LoadInstanceType(CAST(sfi_data));
    if (data_type_out) {
      *data_type_out = data_type;
    }

    int32_t case_values[] = {
        BYTECODE_ARRAY_TYPE,
        CODE_TYPE,
        INTERPRETER_DATA_TYPE,
        UNCOMPILED_DATA_WITHOUT_PREPARSE_DATA_TYPE,
        UNCOMPILED_DATA_WITH_PREPARSE_DATA_TYPE,
        UNCOMPILED_DATA_WITHOUT_PREPARSE_DATA_WITH_JOB_TYPE,
        UNCOMPILED_DATA_WITH_PREPARSE_DATA_AND_JOB_TYPE,
#if V8_ENABLE_WEBASSEMBLY
        WASM_CAPI_FUNCTION_DATA_TYPE,
        WASM_EXPORTED_FUNCTION_DATA_TYPE,
        WASM_JS_FUNCTION_DATA_TYPE,
#endif  // V8_ENABLE_WEBASSEMBLY
    };
    Label check_is_bytecode_array(this);
    Label check_is_baseline_data(this);
    Label check_is_interpreter_data(this);
    Label check_is_uncompiled_data(this);
    Label check_is_wasm_function_data(this);
    Label* case_labels[] = {
        &check_is_bytecode_array,     &check_is_baseline_data,
        &check_is_interpreter_data,   &check_is_uncompiled_data,
        &check_is_uncompiled_data,    &check_is_uncompiled_data,
        &check_is_uncompiled_data,
#if V8_ENABLE_WEBASSEMBLY
        &check_is_wasm_function_data, &check_is_wasm_function_data,
        &check_is_wasm_function_data,
#endif  // V8_ENABLE_WEBASSEMBLY
    };
    static_assert(arraysize(case_values) == arraysize(case_labels));
    Switch(data_type, &unknown_data, case_values, case_labels,
           arraysize(case_labels));

    // IsBytecodeArray: Interpret bytecode
    BIND(&check_is_bytecode_array);
    sfi_code =
        HeapConstantNoHole(BUILTIN_CODE(isolate(), InterpreterEntryTrampoline));
    Goto(&done);

    // IsBaselineData: Execute baseline code
    BIND(&check_is_baseline_data);
    {
      TNode<Code> baseline_code = CAST(sfi_data);
      sfi_code = baseline_code;
      Goto(&done);
    }

    // IsInterpreterData: Interpret bytecode
    BIND(&check_is_interpreter_data);
    {
      TNode<Code> trampoline = CAST(LoadProtectedPointerField(
          CAST(sfi_data), InterpreterData::kInterpreterTrampolineOffset));
      sfi_code = trampoline;
    }
    Goto(&done);

    // IsUncompiledDataWithPreparseData | IsUncompiledDataWithoutPreparseData:
    // Compile lazy
    BIND(&check_is_uncompiled_data);
    sfi_code = HeapConstantNoHole(BUILTIN_CODE(isolate(), CompileLazy));
    Goto(if_compile_lazy ? if_compile_lazy : &done);

#if V8_ENABLE_WEBASSEMBLY
    // IsWasmFunctionData: Use the wrapper code
    BIND(&check_is_wasm_function_data);
    sfi_code = CAST(LoadObjectField(
        CAST(sfi_data), WasmExportedFunctionData::kWrapperCodeOffset));
    Goto(&done);
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  BIND(&use_untrusted_data);
  {
    sfi_data = LoadSharedFunctionInfoUntrustedData(shared_info);
    Label check_instance_type(this);

    // IsSmi: Is builtin
    GotoIf(TaggedIsNotSmi(sfi_data), &check_instance_type);
    if (data_type_out) {
      *data_type_out = Uint16Constant(0);
    }
    if (if_compile_lazy) {
      GotoIf(SmiEqual(CAST(sfi_data), SmiConstant(Builtin::kCompileLazy)),
             if_compile_lazy);
    }
    sfi_code = LoadBuiltin(CAST(sfi_data));
    Goto(&done);

    // Switch on data's instance type.
    BIND(&check_instance_type);
    TNode<Uint16T> data_type = LoadInstanceType(CAST(sfi_data));
    if (data_type_out) {
      *data_type_out = data_type;
    }

    int32_t case_values[] = {
        FUNCTION_TEMPLATE_INFO_TYPE,
#if V8_ENABLE_WEBASSEMBLY
        ASM_WASM_DATA_TYPE,
        WASM_RESUME_DATA_TYPE,
#endif  // V8_ENABLE_WEBASSEMBLY
    };
    Label check_is_function_template_info(this);
    Label check_is_asm_wasm_data(this);
    Label check_is_wasm_resume(this);
    Label* case_labels[] = {
        &check_is_function_template_info,
#if V8_ENABLE_WEBASSEMBLY
        &check_is_asm_wasm_data,
        &check_is_wasm_resume,
#endif  // V8_ENABLE_WEBASSEMBLY
    };
    static_assert(arraysize(case_values) == arraysize(case_labels));
    Switch(data_type, &unknown_data, case_values, case_labels,
           arraysize(case_labels));

    // IsFunctionTemplateInfo: API call
    BIND(&check_is_function_template_info);
    sfi_code =
        HeapConstantNoHole(BUILTIN_CODE(isolate(), HandleApiCallOrConstruct));
    Goto(&done);

#if V8_ENABLE_WEBASSEMBLY
    // IsAsmWasmData: Instantiate using AsmWasmData
    BIND(&check_is_asm_wasm_data);
    sfi_code = HeapConstantNoHole(BUILTIN_CODE(isolate(), InstantiateAsmJs));
    Goto(&done);

    // IsWasmResumeData: Resume the suspended wasm continuation.
    BIND(&check_is_wasm_resume);
    sfi_code = HeapConstantNoHole(BUILTIN_CODE(isolate(), WasmResume));
    Goto(&done);
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  BIND(&unknown_data);
  Unreachable();

  BIND(&done);
  return sfi_code.value();
}

TNode<RawPtrT> CodeStubAssembler::LoadCodeInstructionStart(
    TNode<Code> code, CodeEntrypointTag tag) {
#ifdef V8_ENABLE_SANDBOX
  // In this case, the entrypoint is stored in the code pointer table entry
  // referenced via the Code object's 'self' indirect pointer.
  return LoadCodeEntrypointViaCodePointerField(
      code, Code::kSelfIndirectPointerOffset, tag);
#else
  return LoadObjectField<RawPtrT>(code, Code::kInstructionStartOffset);
#endif
}

TNode<BoolT> CodeStubAssembler::IsMarkedForDeoptimization(TNode<Code> code) {
  static_assert(FIELD_SIZE(Code::kFlagsOffset) * kBitsPerByte == 32);
  return IsSetWord32<Code::MarkedForDeoptimizationField>(
      LoadObjectField<Int32T>(code, Code::kFlagsOffset));
}

TNode<JSFunction> CodeStubAssembler::AllocateRootFunctionWithContext(
    RootIndex function, TNode<Context> context,
    std::optional<TNode<NativeContext>> maybe_native_context) {
  DCHECK_GE(function, RootIndex::kFirstBuiltinWithSfiRoot);
  DCHECK_LE(function, RootIndex::kLastBuiltinWithSfiRoot);
  DCHECK(v8::internal::IsSharedFunctionInfo(
      isolate()->root(function).GetHeapObject()));
  Tagged<SharedFunctionInfo> sfi = v8::internal::Cast<SharedFunctionInfo>(
      isolate()->root(function).GetHeapObject());
  const TNode<SharedFunctionInfo> sfi_obj =
      UncheckedCast<SharedFunctionInfo>(LoadRoot(function));
  const TNode<NativeContext> native_context =
      maybe_native_context ? *maybe_native_context : LoadNativeContext(context);
  const TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX));
  const TNode<HeapObject> fun = Allocate(JSFunction::kSizeWithoutPrototype);
  static_assert(JSFunction::kSizeWithoutPrototype == 7 * kTaggedSize);
  StoreMapNoWriteBarrier(fun, map);
  StoreObjectFieldRoot(fun, JSObject::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(fun, JSObject::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(fun, JSFunction::kFeedbackCellOffset,
                       RootIndex::kManyClosuresCell);
  StoreObjectFieldNoWriteBarrier(fun, JSFunction::kSharedFunctionInfoOffset,
                                 sfi_obj);
  StoreObjectFieldNoWriteBarrier(fun, JSFunction::kContextOffset, context);
  // For the native closures that are initialized here we statically know their
  // builtin id, so there's no need to use
  // CodeStubAssembler::GetSharedFunctionInfoCode().
  DCHECK(sfi->HasBuiltinId());
#ifdef V8_ENABLE_LEAPTIERING
  const TNode<JSDispatchHandleT> dispatch_handle =
      LoadBuiltinDispatchHandle(function);
  CSA_DCHECK(this,
             TaggedEqual(LoadBuiltin(SmiConstant(sfi->builtin_id())),
                         LoadCodeObjectFromJSDispatchTable(dispatch_handle)));
  StoreObjectFieldNoWriteBarrier(fun, JSFunction::kDispatchHandleOffset,
                                 dispatch_handle);
  USE(sfi);
#else
  const TNode<Code> code = LoadBuiltin(SmiConstant(sfi->builtin_id()));
  StoreCodePointerFieldNoWriteBarrier(fun, JSFunction::kCodeOffset, code);
#endif  // V8_ENABLE_LEAPTIERING

  return CAST(fun);
}

void CodeStubAssembler::CheckPrototypeEnumCache(TNode<JSReceiver> receiver,
                                                TNode<Map> receiver_map,
                                                Label* if_fast,
                                                Label* if_slow) {
  TVARIABLE(JSReceiver, var_object, receiver);
  TVARIABLE(Map, object_map, receiver_map);

  Label loop(this, {&var_object, &object_map}), done_loop(this);
  Goto(&loop);
  BIND(&loop);
  {
    // Check that there are no elements on the current {var_object}.
    Label if_no_elements(this);

    // The following relies on the elements only aliasing with JSProxy::target,
    // which is a JavaScript value and hence cannot be confused with an elements
    // backing store.
    static_assert(static_cast<int>(JSObject::kElementsOffset) ==
                  static_cast<int>(JSProxy::kTargetOffset));
    TNode<Object> object_elements =
        LoadObjectField(var_object.value(), JSObject::kElementsOffset);
    GotoIf(IsEmptyFixedArray(object_elements), &if_no_elements);
    GotoIf(IsEmptySlowElementDictionary(object_elements), &if_no_elements);

    // It might still be an empty JSArray.
    GotoIfNot(IsJSArrayMap(object_map.value()), if_slow);
    TNode<Number> object_length = LoadJSArrayLength(CAST(var_object.value()));
    Branch(TaggedEqual(object_length, SmiConstant(0)), &if_no_elements,
           if_slow);

    // Continue with {var_object}'s prototype.
    BIND(&if_no_elements);
    TNode<HeapObject> object = LoadMapPrototype(object_map.value());
    GotoIf(IsNull(object), if_fast);

    // For all {object}s but the {receiver}, check that the cache is empty.
    var_object = CAST(object);
    object_map = LoadMap(object);
    TNode<Uint32T> object_enum_length = LoadMapEnumLength(object_map.value());
    Branch(Word32Equal(object_enum_length, Uint32Constant(0)), &loop, if_slow);
  }
}

TNode<Map> CodeStubAssembler::CheckEnumCache(TNode<JSReceiver> receiver,
                                             Label* if_empty,
                                             Label* if_runtime) {
  Label if_fast(this), if_cache(this), if_no_cache(this, Label::kDeferred);
  TNode<Map> receiver_map = LoadMap(receiver);

  // Check if the enum length field of the {receiver} is properly initialized,
  // indicating that there is an enum cache.
  TNode<Uint32T> receiver_enum_length = LoadMapEnumLength(receiver_map);
  Branch(Word32Equal(receiver_enum_length,
                     Uint32Constant(kInvalidEnumCacheSentinel)),
         &if_no_cache, &if_cache);

  BIND(&if_no_cache);
  {
    // Avoid runtime-call for empty dictionary receivers.
    GotoIfNot(IsDictionaryMap(receiver_map), if_runtime);
    TNode<Smi> length;
    TNode<HeapObject> properties = LoadSlowProperties(receiver);

    // g++ version 8 has a bug when using `if constexpr(false)` with a lambda:
    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=85149
    // TODO(miladfarca): Use `if constexpr` once all compilers handle this
    // properly.
    CSA_DCHECK(this, Word32Or(IsPropertyDictionary(properties),
                              IsGlobalDictionary(properties)));
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      length = Select<Smi>(
          IsPropertyDictionary(properties),
          [=, this] {
            return GetNumberOfElements(
                UncheckedCast<PropertyDictionary>(properties));
          },
          [=, this] {
            return GetNumberOfElements(
                UncheckedCast<GlobalDictionary>(properties));
          });

    } else {
      static_assert(static_cast<int>(NameDictionary::kNumberOfElementsIndex) ==
                    static_cast<int>(GlobalDictionary::kNumberOfElementsIndex));
      length = GetNumberOfElements(UncheckedCast<HashTableBase>(properties));
    }

    GotoIfNot(TaggedEqual(length, SmiConstant(0)), if_runtime);
    // Check that there are no elements on the {receiver} and its prototype
    // chain. Given that we do not create an EnumCache for dict-mode objects,
    // directly jump to {if_empty} if there are no elements and no properties
    // on the {receiver}.
    CheckPrototypeEnumCache(receiver, receiver_map, if_empty, if_runtime);
  }

  // Check that there are no elements on the fast {receiver} and its
  // prototype chain.
  BIND(&if_cache);
  CheckPrototypeEnumCache(receiver, receiver_map, &if_fast, if_runtime);

  BIND(&if_fast);
  return receiver_map;
}

TNode<Object> CodeStubAssembler::GetArgumentValue(TorqueStructArguments args,
                                                  TNode<IntPtrT> index) {
  return CodeStubArguments(this, args).GetOptionalArgumentValue(index);
}

void CodeStubAssembler::SetArgumentValue(TorqueStructArguments args,
                                         TNode<IntPtrT> index,
                                         TNode<Object> value) {
  CodeStubArguments(this, args).SetArgumentValue(index, value);
}

TorqueStructArguments CodeStubAssembler::GetFrameArguments(
    TNode<RawPtrT> frame, TNode<IntPtrT> argc,
    FrameArgumentsArgcType argc_type) {
  if (argc_type == FrameArgumentsArgcType::kCountExcludesReceiver) {
    argc = IntPtrAdd(argc, IntPtrConstant(kJSArgcReceiverSlots));
  }
  return CodeStubArguments(this, argc, frame).GetTorqueArguments();
}

void CodeStubAssembler::Print(const char* s) {
  PrintToStream(s, fileno(stdout));
}

void CodeStubAssembler::PrintErr(const char* s) {
  PrintToStream(s, fileno(stderr));
}

void CodeStubAssembler::PrintToStream(const char* s, int stream) {
  std::string formatted(s);
  formatted += "\n";
  CallRuntime(Runtime::kGlobalPrint, NoContextConstant(),
              StringConstant(formatted.c_str()), SmiConstant(stream));
}

void CodeStubAssembler::Print(const char* prefix,
                              TNode<MaybeObject> tagged_value) {
  PrintToStream(prefix, tagged_value, fileno(stdout));
}

void CodeStubAssembler::Print(const char* prefix, TNode<UintPtrT> value) {
  PrintToStream(prefix, value, fileno(stdout));
}

void CodeStubAssembler::Print(const char* prefix, TNode<Float64T> value) {
  PrintToStream(prefix, value, fileno(stdout));
}

void CodeStubAssembler::PrintErr(const char* prefix,
                                 TNode<MaybeObject> tagged_value) {
  PrintToStream(prefix, tagged_value, fileno(stderr));
}

void CodeStubAssembler::PrintToStream(const char* prefix,
                                      TNode<MaybeObject> tagged_value,
                                      int stream) {
  if (prefix != nullptr) {
    std::string formatted(prefix);
    formatted += ": ";
    Handle<String> string =
        isolate()->factory()->InternalizeString(formatted.c_str());
    CallRuntime(Runtime::kGlobalPrint, NoContextConstant(),
                HeapConstantNoHole(string), SmiConstant(stream));
  }
  // CallRuntime only accepts Objects, so do an UncheckedCast to object.
  // DebugPrint explicitly checks whether the tagged value is a
  // Tagged<MaybeObject>.
  TNode<Object> arg = UncheckedCast<Object>(tagged_value);
  CallRuntime(Runtime::kDebugPrint, NoContextConstant(), arg,
              SmiConstant(stream));
}

void CodeStubAssembler::PrintToStream(const char* prefix, TNode<UintPtrT> value,
                                      int stream) {
  if (prefix != nullptr) {
    std::string formatted(prefix);
    formatted += ": ";
    Handle<String> string =
        isolate()->factory()->InternalizeString(formatted.c_str());
    CallRuntime(Runtime::kGlobalPrint, NoContextConstant(),
                HeapConstantNoHole(string), SmiConstant(stream));
  }

  // We use 16 bit per chunk.
  TNode<Smi> chunks[4];
  for (int i = 0; i < 4; ++i) {
    chunks[i] = SmiFromUint32(ReinterpretCast<Uint32T>(Word32And(
        TruncateIntPtrToInt32(ReinterpretCast<IntPtrT>(value)), 0xFFFF)));
    value = WordShr(value, IntPtrConstant(16));
  }

  // Args are: <bits 63-48>, <bits 47-32>, <bits 31-16>, <bits 15-0>, stream.
  CallRuntime(Runtime::kDebugPrintWord, NoContextConstant(), chunks[3],
              chunks[2], chunks[1], chunks[0], SmiConstant(stream));
}

void CodeStubAssembler::PrintToStream(const char* prefix, TNode<Float64T> value,
                                      int stream) {
  if (prefix != nullptr) {
    std::string formatted(prefix);
    formatted += ": ";
    Handle<String> string =
        isolate()->factory()->InternalizeString(formatted.c_str());
    CallRuntime(Runtime::kGlobalPrint, NoContextConstant(),
                HeapConstantNoHole(string), SmiConstant(stream));
  }

  // We use word32 extraction instead of `BitcastFloat64ToInt64` to support 32
  // bit architectures, too.
  TNode<Uint32T> high = Float64ExtractHighWord32(value);
  TNode<Uint32T> low = Float64ExtractLowWord32(value);

  // We use 16 bit per chunk.
  TNode<Smi> chunks[4];
  chunks[0] = SmiFromUint32(ReinterpretCast<Uint32T>(Word32And(low, 0xFFFF)));
  chunks[1] = SmiFromUint32(ReinterpretCast<Uint32T>(
      Word32And(Word32Shr(low, Int32Constant(16)), 0xFFFF)));
  chunks[2] = SmiFromUint32(ReinterpretCast<Uint32T>(Word32And(high, 0xFFFF)));
  chunks[3] = SmiFromUint32(ReinterpretCast<Uint32T>(
      Word32And(Word32Shr(high, Int32Constant(16)), 0xFFFF)));

  // Args are: <bits 63-48>, <bits 47-32>, <bits 31-16>, <bits 15-0>, stream.
  CallRuntime(Runtime::kDebugPrintFloat, NoContextConstant(), chunks[3],
              chunks[2], chunks[1], chunks[0], SmiConstant(stream));
}

IntegerLiteral CodeStubAssembler::ConstexprIntegerLiteralAdd(
    const IntegerLiteral& lhs, const IntegerLiteral& rhs) {
  return lhs + rhs;
}
IntegerLiteral CodeStubAssembler::ConstexprIntegerLiteralLeftShift(
    const IntegerLiteral& lhs, const IntegerLiteral& rhs) {
  return lhs << rhs;
}
IntegerLiteral CodeStubAssembler::ConstexprIntegerLiteralBitwiseOr(
    const IntegerLiteral& lhs, const IntegerLiteral& rhs) {
  return lhs | rhs;
}

void CodeStubAssembler::PerformStackCheck(TNode<Context> context) {
  Label ok(this), stack_check_interrupt(this, Label::kDeferred);

  TNode<UintPtrT> stack_limit = UncheckedCast<UintPtrT>(
      Load(MachineType::Pointer(),
           ExternalConstant(ExternalReference::address_of_jslimit(isolate()))));
  TNode<BoolT> sp_within_limit = StackPointerGreaterThan(stack_limit);

  Branch(sp_within_limit, &ok, &stack_check_interrupt);

  BIND(&stack_check_interrupt);
  CallRuntime(Runtime::kStackGuard, context);
  Goto(&ok);

  BIND(&ok);
}

TNode<Object> CodeStubAssembler::CallRuntimeNewArray(
    TNode<Context> context, TNode<Object> receiver, TNode<Object> length,
    TNode<Object> new_target, TNode<Object> allocation_site) {
  // Runtime_NewArray receives arguments in the JS order (to avoid unnecessary
  // copy). Except the last two (new_target and allocation_site) which are add
  // on top of the stack later.
  return CallRuntime(Runtime::kNewArray, context, length, receiver, new_target,
                     allocation_site);
}

void CodeStubAssembler::TailCallRuntimeNewArray(TNode<Context> context,
                                                TNode<Object> receiver,
                                                TNode<Object> length,
                                                TNode<Object> new_target,
                                                TNode<Object> allocation_site) {
  // Runtime_NewArray receives arguments in the JS order (to avoid unnecessary
  // copy). Except the last two (new_target and allocation_site) which are add
  // on top of the stack later.
  return TailCallRuntime(Runtime::kNewArray, context, length, receiver,
                         new_target, allocation_site);
}

TNode<JSArray> CodeStubAssembler::ArrayCreate(TNode<Context> context,
                                              TNode<Number> length) {
  TVARIABLE(JSArray, array);
  Label allocate_js_array(this);

  Label done(this), next(this), runtime(this, Label::kDeferred);
  TNode<Smi> limit = SmiConstant(JSArray::kInitialMaxFastElementArray);
  CSA_DCHECK_BRANCH(this, ([=, this](Label* ok, Label* not_ok) {
                      BranchIfNumberRelationalComparison(
                          Operation::kGreaterThanOrEqual, length,
                          SmiConstant(0), ok, not_ok);
                    }));
  // This check also transitively covers the case where length is too big
  // to be representable by a SMI and so is not usable with
  // AllocateJSArray.
  BranchIfNumberRelationalComparison(Operation::kGreaterThanOrEqual, length,
                                     limit, &runtime, &next);

  BIND(&runtime);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<JSFunction> array_function =
        CAST(LoadContextElement(native_context, Context::ARRAY_FUNCTION_INDEX));
    array = CAST(CallRuntimeNewArray(context, array_function, length,
                                     array_function, UndefinedConstant()));
    Goto(&done);
  }

  BIND(&next);
  TNode<Smi> length_smi = CAST(length);

  TNode<Map> array_map = CAST(LoadContextElement(
      context, Context::JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX));

  // TODO(delphick): Consider using
  // AllocateUninitializedJSArrayWithElements to avoid initializing an
  // array and then writing over it.
  array = AllocateJSArray(PACKED_SMI_ELEMENTS, array_map, length_smi,
                          SmiConstant(0));
  Goto(&done);

  BIND(&done);
  return array.value();
}

void CodeStubAssembler::SetPropertyLength(TNode<Context> context,
                                          TNode<Object> array,
                                          TNode<Number> length) {
  SetPropertyStrict(context, array, CodeStubAssembler::LengthStringConstant(),
                    length);
}

TNode<Smi> CodeStubAssembler::RefillMathRandom(
    TNode<NativeContext> native_context) {
  // Cache exhausted, populate the cache. Return value is the new index.
  const TNode<ExternalReference> refill_math_random =
      ExternalConstant(ExternalReference::refill_math_random());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  MachineType type_tagged = MachineType::AnyTagged();
  MachineType type_ptr = MachineType::Pointer();

  return CAST(CallCFunction(refill_math_random, type_tagged,
                            std::make_pair(type_ptr, isolate_ptr),
                            std::make_pair(type_tagged, native_context)));
}

TNode<String> CodeStubAssembler::TaggedToDirectString(TNode<Object> value,
                                                      Label* fail) {
  ToDirectStringAssembler to_direct(state(), CAST(value));
  to_direct.TryToDirect(fail);
  to_direct.PointerToData(fail);
  return CAST(value);
}

void CodeStubAssembler::RemoveFinalizationRegistryCellFromUnregisterTokenMap(
    TNode<JSFinalizationRegistry> finalization_registry,
    TNode<WeakCell> weak_cell) {
  const TNode<ExternalReference> remove_cell = ExternalConstant(
      ExternalReference::
          js_finalization_registry_remove_cell_from_unregister_token_map());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());

  CallCFunction(remove_cell, MachineType::Pointer(),
                std::make_pair(MachineType::Pointer(), isolate_ptr),
                std::make_pair(MachineType::AnyTagged(), finalization_registry),
                std::make_pair(MachineType::AnyTagged(), weak_cell));
}

PrototypeCheckAssembler::PrototypeCheckAssembler(
    compiler::CodeAssemblerState* state, Flags flags,
    TNode<NativeContext> native_context, TNode<Map> initial_prototype_map,
    base::Vector<DescriptorIndexNameValue> properties)
    : CodeStubAssembler(state),
      flags_(flags),
      native_context_(native_context),
      initial_prototype_map_(initial_prototype_map),
      properties_(properties) {}

void PrototypeCheckAssembler::CheckAndBranch(TNode<HeapObject> prototype,
                                             Label* if_unmodified,
                                             Label* if_modified) {
  TNode<Map> prototype_map = LoadMap(prototype);
  TNode<DescriptorArray> descriptors = LoadMapDescriptors(prototype_map);

  // The continuation of a failed fast check: if property identity checks are
  // enabled, we continue there (since they may still classify the prototype as
  // fast), otherwise we bail out.
  Label property_identity_check(this, Label::kDeferred);
  Label* if_fast_check_failed =
      ((flags_ & kCheckPrototypePropertyIdentity) == 0)
          ? if_modified
          : &property_identity_check;

  if ((flags_ & kCheckPrototypePropertyConstness) != 0) {
    // A simple prototype map identity check. Note that map identity does not
    // guarantee unmodified properties. It does guarantee that no new properties
    // have been added, or old properties deleted.

    GotoIfNot(TaggedEqual(prototype_map, initial_prototype_map_),
              if_fast_check_failed);

    // We need to make sure that relevant properties in the prototype have
    // not been tampered with. We do this by checking that their slots
    // in the prototype's descriptor array are still marked as const.

    TNode<Uint32T> combined_details;
    for (int i = 0; i < properties_.length(); i++) {
      // Assert the descriptor index is in-bounds.
      int descriptor = properties_[i].descriptor_index;
      CSA_DCHECK(this, Int32LessThan(Int32Constant(descriptor),
                                     LoadNumberOfDescriptors(descriptors)));

      // Assert that the name is correct. This essentially checks that
      // the descriptor index corresponds to the insertion order in
      // the bootstrapper.
      CSA_DCHECK(
          this,
          TaggedEqual(LoadKeyByDescriptorEntry(descriptors, descriptor),
                      CodeAssembler::LoadRoot(properties_[i].name_root_index)));

      TNode<Uint32T> details =
          DescriptorArrayGetDetails(descriptors, Uint32Constant(descriptor));

      if (i == 0) {
        combined_details = details;
      } else {
        combined_details = Word32And(combined_details, details);
      }
    }

    TNode<Uint32T> constness =
        DecodeWord32<PropertyDetails::ConstnessField>(combined_details);

    Branch(
        Word32Equal(constness,
                    Int32Constant(static_cast<int>(PropertyConstness::kConst))),
        if_unmodified, if_fast_check_failed);
  }

  if ((flags_ & kCheckPrototypePropertyIdentity) != 0) {
    // The above checks have failed, for whatever reason (maybe the prototype
    // map has changed, or a property is no longer const). This block implements
    // a more thorough check that can also accept maps which 1. do not have the
    // initial map, 2. have mutable relevant properties, but 3. still match the
    // expected value for all relevant properties.

    BIND(&property_identity_check);

    int max_descriptor_index = -1;
    for (int i = 0; i < properties_.length(); i++) {
      max_descriptor_index =
          std::max(max_descriptor_index, properties_[i].descriptor_index);
    }

    // If the greatest descriptor index is out of bounds, the map cannot be
    // fast.
    GotoIfNot(Int32LessThan(Int32Constant(max_descriptor_index),
                            LoadNumberOfDescriptors(descriptors)),
              if_modified);

    // Logic below only handles maps with fast properties.
    GotoIfMapHasSlowProperties(prototype_map, if_modified);

    for (int i = 0; i < properties_.length(); i++) {
      const DescriptorIndexNameValue& p = properties_[i];
      const int descriptor = p.descriptor_index;

      // Check if the name is correct. This essentially checks that
      // the descriptor index corresponds to the insertion order in
      // the bootstrapper.
      GotoIfNot(TaggedEqual(LoadKeyByDescriptorEntry(descriptors, descriptor),
                            CodeAssembler::LoadRoot(p.name_root_index)),
                if_modified);

      // Finally, check whether the actual value equals the expected value.
      TNode<Uint32T> details =
          DescriptorArrayGetDetails(descriptors, Uint32Constant(descriptor));
      TVARIABLE(Uint32T, var_details, details);
      TVARIABLE(Object, var_value);

      const int key_index = DescriptorArray::ToKeyIndex(descriptor);
      LoadPropertyFromFastObject(prototype, prototype_map, descriptors,
                                 IntPtrConstant(key_index), &var_details,
                                 &var_value);

      TNode<Object> actual_value = var_value.value();
      TNode<Object> expected_value =
          LoadContextElement(native_context_, p.expected_value_context_index);
      GotoIfNot(TaggedEqual(actual_value, expected_value), if_modified);
    }

    Goto(if_unmodified);
  }
}

//
// Begin of SwissNameDictionary macros
//

namespace {

// Provides load and store functions that abstract over the details of accessing
// the meta table in memory. Instead they allow using logical indices that are
// independent from the underlying entry size in the meta table of a
// SwissNameDictionary.
class MetaTableAccessor {
 public:
  MetaTableAccessor(CodeStubAssembler& csa, MachineType mt)
      : csa{csa}, mt{mt} {}

  TNode<Uint32T> Load(TNode<ByteArray> meta_table, TNode<IntPtrT> index) {
    TNode<IntPtrT> offset = OverallOffset(meta_table, index);

    return csa.UncheckedCast<Uint32T>(
        csa.LoadFromObject(mt, meta_table, offset));
  }

  TNode<Uint32T> Load(TNode<ByteArray> meta_table, int index) {
    return Load(meta_table, csa.IntPtrConstant(index));
  }

  void Store(TNode<ByteArray> meta_table, TNode<IntPtrT> index,
             TNode<Uint32T> data) {
    TNode<IntPtrT> offset = OverallOffset(meta_table, index);

#ifdef DEBUG
    int bits = mt.MemSize() * 8;
    TNode<UintPtrT> max_value = csa.UintPtrConstant((1ULL << bits) - 1);

    CSA_DCHECK(&csa, csa.UintPtrLessThanOrEqual(csa.ChangeUint32ToWord(data),
                                                max_value));
#endif

    csa.StoreToObject(mt.representation(), meta_table, offset, data,
                      StoreToObjectWriteBarrier::kNone);
  }

  void Store(TNode<ByteArray> meta_table, int index, TNode<Uint32T> data) {
    Store(meta_table, csa.IntPtrConstant(index), data);
  }

 private:
  TNode<IntPtrT> OverallOffset(TNode<ByteArray> meta_table,
                               TNode<IntPtrT> index) {
    // TODO(v8:11330): consider using ElementOffsetFromIndex().

    int offset_to_data_minus_tag =
        OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag;

    TNode<IntPtrT> overall_offset;
    int size = mt.MemSize();
    intptr_t constant;
    if (csa.TryToIntPtrConstant(index, &constant)) {
      intptr_t index_offset = constant * size;
      overall_offset =
          csa.IntPtrConstant(offset_to_data_minus_tag + index_offset);
    } else {
      TNode<IntPtrT> index_offset =
          csa.IntPtrMul(index, csa.IntPtrConstant(size));
      overall_offset = csa.IntPtrAdd(
          csa.IntPtrConstant(offset_to_data_minus_tag), index_offset);
    }

#ifdef DEBUG
    TNode<IntPtrT> byte_array_data_bytes =
        csa.SmiToIntPtr(csa.LoadFixedArrayBaseLength(meta_table));
    TNode<IntPtrT> max_allowed_offset = csa.IntPtrAdd(
        byte_array_data_bytes, csa.IntPtrConstant(offset_to_data_minus_tag));
    CSA_DCHECK(&csa, csa.UintPtrLessThan(overall_offset, max_allowed_offset));
#endif

    return overall_offset;
  }

  CodeStubAssembler& csa;
  MachineType mt;
};

// Type of functions that given a MetaTableAccessor, use its load and store
// functions to generate code for operating on the meta table.
using MetaTableAccessFunction = std::function<void(MetaTableAccessor&)>;

// Helper function for macros operating on the meta table of a
// SwissNameDictionary. Given a MetaTableAccessFunction, generates branching
// code and uses the builder to generate code for each of the three possible
// sizes per entry a meta table can have.
void GenerateMetaTableAccess(CodeStubAssembler* csa, TNode<IntPtrT> capacity,
                             MetaTableAccessFunction builder) {
  MetaTableAccessor mta8 = MetaTableAccessor(*csa, MachineType::Uint8());
  MetaTableAccessor mta16 = MetaTableAccessor(*csa, MachineType::Uint16());
  MetaTableAccessor mta32 = MetaTableAccessor(*csa, MachineType::Uint32());

  using Label = compiler::CodeAssemblerLabel;
  Label small(csa), medium(csa), done(csa);

  csa->GotoIf(
      csa->IntPtrLessThanOrEqual(
          capacity,
          csa->IntPtrConstant(SwissNameDictionary::kMax1ByteMetaTableCapacity)),
      &small);
  csa->GotoIf(
      csa->IntPtrLessThanOrEqual(
          capacity,
          csa->IntPtrConstant(SwissNameDictionary::kMax2ByteMetaTableCapacity)),
      &medium);

  builder(mta32);
  csa->Goto(&done);

  csa->Bind(&medium);
  builder(mta16);
  csa->Goto(&done);

  csa->Bind(&small);
  builder(mta8);
  csa->Goto(&done);
  csa->Bind(&done);
}

}  // namespace

TNode<IntPtrT> CodeStubAssembler::LoadSwissNameDictionaryNumberOfElements(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity) {
  TNode<ByteArray> meta_table = LoadSwissNameDictionaryMetaTable(table);

  TVARIABLE(Uint32T, nof, Uint32Constant(0));
  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    nof = mta.Load(meta_table,
                   SwissNameDictionary::kMetaTableElementCountFieldIndex);
  };

  GenerateMetaTableAccess(this, capacity, builder);
  return ChangeInt32ToIntPtr(nof.value());
}

TNode<IntPtrT>
CodeStubAssembler::LoadSwissNameDictionaryNumberOfDeletedElements(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity) {
  TNode<ByteArray> meta_table = LoadSwissNameDictionaryMetaTable(table);

  TVARIABLE(Uint32T, nod, Uint32Constant(0));
  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    nod =
        mta.Load(meta_table,
                 SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex);
  };

  GenerateMetaTableAccess(this, capacity, builder);
  return ChangeInt32ToIntPtr(nod.value());
}

void CodeStubAssembler::StoreSwissNameDictionaryEnumToEntryMapping(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
    TNode<IntPtrT> enum_index, TNode<Int32T> entry) {
  TNode<ByteArray> meta_table = LoadSwissNameDictionaryMetaTable(table);
  TNode<IntPtrT> meta_table_index = IntPtrAdd(
      IntPtrConstant(SwissNameDictionary::kMetaTableEnumerationDataStartIndex),
      enum_index);

  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    mta.Store(meta_table, meta_table_index, Unsigned(entry));
  };

  GenerateMetaTableAccess(this, capacity, builder);
}

TNode<Uint32T>
CodeStubAssembler::SwissNameDictionaryIncreaseElementCountOrBailout(
    TNode<ByteArray> meta_table, TNode<IntPtrT> capacity,
    TNode<Uint32T> max_usable_capacity, Label* bailout) {
  TVARIABLE(Uint32T, used_var, Uint32Constant(0));

  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    TNode<Uint32T> nof = mta.Load(
        meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex);
    TNode<Uint32T> nod =
        mta.Load(meta_table,
                 SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex);
    TNode<Uint32T> used = Uint32Add(nof, nod);
    GotoIf(Uint32GreaterThanOrEqual(used, max_usable_capacity), bailout);
    TNode<Uint32T> inc_nof = Uint32Add(nof, Uint32Constant(1));
    mta.Store(meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex,
              inc_nof);
    used_var = used;
  };

  GenerateMetaTableAccess(this, capacity, builder);
  return used_var.value();
}

TNode<Uint32T> CodeStubAssembler::SwissNameDictionaryUpdateCountsForDeletion(
    TNode<ByteArray> meta_table, TNode<IntPtrT> capacity) {
  TVARIABLE(Uint32T, new_nof_var, Uint32Constant(0));

  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    TNode<Uint32T> nof = mta.Load(
        meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex);
    TNode<Uint32T> nod =
        mta.Load(meta_table,
                 SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex);

    TNode<Uint32T> new_nof = Uint32Sub(nof, Uint32Constant(1));
    TNode<Uint32T> new_nod = Uint32Add(nod, Uint32Constant(1));

    mta.Store(meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex,
              new_nof);
    mta.Store(meta_table,
              SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex,
              new_nod);

    new_nof_var = new_nof;
  };

  GenerateMetaTableAccess(this, capacity, builder);
  return new_nof_var.value();
}

TNode<SwissNameDictionary> CodeStubAssembler::AllocateSwissNameDictionary(
    TNode<IntPtrT> at_least_space_for) {
  // Note that as AllocateNameDictionary, we return a table with initial
  // (non-zero) capacity even if |at_least_space_for| is 0.

  TNode<IntPtrT> capacity =
      IntPtrMax(IntPtrConstant(SwissNameDictionary::kInitialCapacity),
                SwissNameDictionaryCapacityFor(at_least_space_for));

  return AllocateSwissNameDictionaryWithCapacity(capacity);
}

TNode<SwissNameDictionary> CodeStubAssembler::AllocateSwissNameDictionary(
    int at_least_space_for) {
  return AllocateSwissNameDictionary(IntPtrConstant(at_least_space_for));
}

TNode<SwissNameDictionary>
CodeStubAssembler::AllocateSwissNameDictionaryWithCapacity(
    TNode<IntPtrT> capacity) {
  Comment("[ AllocateSwissNameDictionaryWithCapacity");
  CSA_DCHECK(this, WordIsPowerOfTwo(capacity));
  CSA_DCHECK(this, UintPtrGreaterThanOrEqual(
                       capacity,
                       IntPtrConstant(SwissNameDictionary::kInitialCapacity)));
  CSA_DCHECK(this,
             UintPtrLessThanOrEqual(
                 capacity, IntPtrConstant(SwissNameDictionary::MaxCapacity())));

  Comment("Size check.");
  intptr_t capacity_constant;
  if (ToParameterConstant(capacity, &capacity_constant)) {
    CHECK_LE(capacity_constant, SwissNameDictionary::MaxCapacity());
  } else {
    Label if_out_of_memory(this, Label::kDeferred), next(this);
    Branch(UintPtrGreaterThan(
               capacity, IntPtrConstant(SwissNameDictionary::MaxCapacity())),
           &if_out_of_memory, &next);

    BIND(&if_out_of_memory);
    CallRuntime(Runtime::kFatalProcessOutOfMemoryInAllocateRaw,
                NoContextConstant());
    Unreachable();

    BIND(&next);
  }

  // TODO(v8:11330) Consider adding dedicated handling for constant capacties,
  // similar to AllocateOrderedHashTableWithCapacity.

  // We must allocate the ByteArray first. Otherwise, allocating the ByteArray
  // may trigger GC, which may try to verify the un-initialized
  // SwissNameDictionary.
  Comment("Meta table allocation.");
  TNode<IntPtrT> meta_table_payload_size =
      SwissNameDictionaryMetaTableSizeFor(capacity);

  TNode<ByteArray> meta_table =
      AllocateNonEmptyByteArray(Unsigned(meta_table_payload_size));

  Comment("SwissNameDictionary allocation.");
  TNode<IntPtrT> total_size = SwissNameDictionarySizeFor(capacity);

  TNode<SwissNameDictionary> table =
      UncheckedCast<SwissNameDictionary>(Allocate(total_size));

  StoreMapNoWriteBarrier(table, RootIndex::kSwissNameDictionaryMap);

  Comment(
      "Initialize the hash, capacity, meta table pointer, and number of "
      "(deleted) elements.");

  StoreSwissNameDictionaryHash(table,
                               Uint32Constant(PropertyArray::kNoHashSentinel));
  StoreSwissNameDictionaryCapacity(table, TruncateIntPtrToInt32(capacity));
  StoreSwissNameDictionaryMetaTable(table, meta_table);

  // Set present and deleted element count without doing branching needed for
  // meta table access twice.
  MetaTableAccessFunction builder = [&](MetaTableAccessor& mta) {
    mta.Store(meta_table, SwissNameDictionary::kMetaTableElementCountFieldIndex,
              Uint32Constant(0));
    mta.Store(meta_table,
              SwissNameDictionary::kMetaTableDeletedElementCountFieldIndex,
              Uint32Constant(0));
  };
  GenerateMetaTableAccess(this, capacity, builder);

  Comment("Initialize the ctrl table.");

  TNode<IntPtrT> ctrl_table_start_offset_minus_tag =
      SwissNameDictionaryCtrlTableStartOffsetMT(capacity);

  TNode<IntPtrT> table_address_with_tag = BitcastTaggedToWord(table);
  TNode<IntPtrT> ctrl_table_size_bytes =
      IntPtrAdd(capacity, IntPtrConstant(SwissNameDictionary::kGroupWidth));
  TNode<IntPtrT> ctrl_table_start_ptr =
      IntPtrAdd(table_address_with_tag, ctrl_table_start_offset_minus_tag);
  TNode<IntPtrT> ctrl_table_end_ptr =
      IntPtrAdd(ctrl_table_start_ptr, ctrl_table_size_bytes);

  // |ctrl_table_size_bytes| (= capacity + kGroupWidth) is divisble by four:
  static_assert(SwissNameDictionary::kGroupWidth % 4 == 0);
  static_assert(SwissNameDictionary::kInitialCapacity % 4 == 0);

  // TODO(v8:11330) For all capacities except 4, we know that
  // |ctrl_table_size_bytes| is divisible by 8. Consider initializing the ctrl
  // table with WordTs in those cases. Alternatively, always initialize as many
  // bytes as possbible with WordT and then, if necessary, the remaining 4 bytes
  // with Word32T.

  constexpr uint8_t kEmpty = swiss_table::Ctrl::kEmpty;
  constexpr uint32_t kEmpty32 =
      (kEmpty << 24) | (kEmpty << 16) | (kEmpty << 8) | kEmpty;
  TNode<Int32T> empty32 = Int32Constant(kEmpty32);
  BuildFastLoop<IntPtrT>(
      ctrl_table_start_ptr, ctrl_table_end_ptr,
      [=, this](TNode<IntPtrT> current) {
        UnsafeStoreNoWriteBarrier(MachineRepresentation::kWord32, current,
                                  empty32);
      },
      sizeof(uint32_t), LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);

  Comment("Initialize the data table.");

  TNode<IntPtrT> data_table_start_offset_minus_tag =
      SwissNameDictionaryDataTableStartOffsetMT();
  TNode<IntPtrT> data_table_ptr =
      IntPtrAdd(table_address_with_tag, data_table_start_offset_minus_tag);
  TNode<IntPtrT> data_table_size = IntPtrMul(
      IntPtrConstant(SwissNameDictionary::kDataTableEntryCount * kTaggedSize),
      capacity);

  StoreFieldsNoWriteBarrier(data_table_ptr,
                            IntPtrAdd(data_table_ptr, data_table_size),
                            TheHoleConstant());

  Comment("AllocateSwissNameDictionaryWithCapacity ]");

  return table;
}

TNode<SwissNameDictionary> CodeStubAssembler::CopySwissNameDictionary(
    TNode<SwissNameDictionary> original) {
  Comment("[ CopySwissNameDictionary");

  TNode<IntPtrT> capacity =
      Signed(ChangeUint32ToWord(LoadSwissNameDictionaryCapacity(original)));

  // We must allocate the ByteArray first. Otherwise, allocating the ByteArray
  // may trigger GC, which may try to verify the un-initialized
  // SwissNameDictionary.
  Comment("Meta table allocation.");
  TNode<IntPtrT> meta_table_payload_size =
      SwissNameDictionaryMetaTableSizeFor(capacity);

  TNode<ByteArray> meta_table =
      AllocateNonEmptyByteArray(Unsigned(meta_table_payload_size));

  Comment("SwissNameDictionary allocation.");
  TNode<IntPtrT> total_size = SwissNameDictionarySizeFor(capacity);

  TNode<SwissNameDictionary> table =
      UncheckedCast<SwissNameDictionary>(Allocate(total_size));

  StoreMapNoWriteBarrier(table, RootIndex::kSwissNameDictionaryMap);

  Comment("Copy the hash and capacity.");

  StoreSwissNameDictionaryHash(table, LoadSwissNameDictionaryHash(original));
  StoreSwissNameDictionaryCapacity(table, TruncateIntPtrToInt32(capacity));
  StoreSwissNameDictionaryMetaTable(table, meta_table);
  // Not setting up number of (deleted elements), copying whole meta table
  // instead.

  TNode<ExternalReference> memcpy =
      ExternalConstant(ExternalReference::libc_memcpy_function());

  TNode<IntPtrT> old_table_address_with_tag = BitcastTaggedToWord(original);
  TNode<IntPtrT> new_table_address_with_tag = BitcastTaggedToWord(table);

  TNode<IntPtrT> ctrl_table_start_offset_minus_tag =
      SwissNameDictionaryCtrlTableStartOffsetMT(capacity);

  TNode<IntPtrT> ctrl_table_size_bytes =
      IntPtrAdd(capacity, IntPtrConstant(SwissNameDictionary::kGroupWidth));

  Comment("Copy the ctrl table.");
  {
    TNode<IntPtrT> old_ctrl_table_start_ptr = IntPtrAdd(
        old_table_address_with_tag, ctrl_table_start_offset_minus_tag);
    TNode<IntPtrT> new_ctrl_table_start_ptr = IntPtrAdd(
        new_table_address_with_tag, ctrl_table_start_offset_minus_tag);

    CallCFunction(
        memcpy, MachineType::Pointer(),
        std::make_pair(MachineType::Pointer(), new_ctrl_table_start_ptr),
        std::make_pair(MachineType::Pointer(), old_ctrl_table_start_ptr),
        std::make_pair(MachineType::UintPtr(), ctrl_table_size_bytes));
  }

  Comment("Copy the data table.");
  {
    TNode<IntPtrT> start_offset =
        IntPtrConstant(SwissNameDictionary::DataTableStartOffset());
    TNode<IntPtrT> data_table_size = IntPtrMul(
        IntPtrConstant(SwissNameDictionary::kDataTableEntryCount * kTaggedSize),
        capacity);

    BuildFastLoop<IntPtrT>(
        start_offset, IntPtrAdd(start_offset, data_table_size),
        [=, this](TNode<IntPtrT> offset) {
          TNode<Object> table_field = LoadObjectField(original, offset);
          StoreObjectField(table, offset, table_field);
        },
        kTaggedSize, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
  }

  Comment("Copy the meta table");
  {
    TNode<IntPtrT> old_meta_table_address_with_tag =
        BitcastTaggedToWord(LoadSwissNameDictionaryMetaTable(original));
    TNode<IntPtrT> new_meta_table_address_with_tag =
        BitcastTaggedToWord(meta_table);

    TNode<IntPtrT> meta_table_size =
        SwissNameDictionaryMetaTableSizeFor(capacity);

    TNode<IntPtrT> old_data_start = IntPtrAdd(
        old_meta_table_address_with_tag,
        IntPtrConstant(OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag));
    TNode<IntPtrT> new_data_start = IntPtrAdd(
        new_meta_table_address_with_tag,
        IntPtrConstant(OFFSET_OF_DATA_START(ByteArray) - kHeapObjectTag));

    CallCFunction(memcpy, MachineType::Pointer(),
                  std::make_pair(MachineType::Pointer(), new_data_start),
                  std::make_pair(MachineType::Pointer(), old_data_start),
                  std::make_pair(MachineType::UintPtr(), meta_table_size));
  }

  Comment("Copy the PropertyDetails table");
  {
    TNode<IntPtrT> property_details_start_offset_minus_tag =
        SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(table, capacity,
                                                            IntPtrConstant(0));

    // Offset to property details entry
    TVARIABLE(IntPtrT, details_table_offset_minus_tag,
              property_details_start_offset_minus_tag);

    TNode<IntPtrT> start = ctrl_table_start_offset_minus_tag;

    VariableList in_loop_variables({&details_table_offset_minus_tag}, zone());
    BuildFastLoop<IntPtrT>(
        in_loop_variables, start, IntPtrAdd(start, ctrl_table_size_bytes),
        [&](TNode<IntPtrT> ctrl_table_offset) {
          TNode<Uint8T> ctrl = Load<Uint8T>(original, ctrl_table_offset);

          // TODO(v8:11330) Entries in the PropertyDetails table may be
          // uninitialized if the corresponding buckets in the data/ctrl table
          // are empty. Therefore, to avoid accessing un-initialized memory
          // here, we need to check the ctrl table to determine whether we
          // should copy a certain PropertyDetails entry or not.
          // TODO(v8:11330) If this function becomes performance-critical, we
          // may consider always initializing the PropertyDetails table entirely
          // during allocation, to avoid the branching during copying.
          Label done(this);
          // |kNotFullMask| catches kEmpty and kDeleted, both of which indicate
          // entries that we don't want to copy the PropertyDetails for.
          GotoIf(IsSetWord32(ctrl, swiss_table::kNotFullMask), &done);

          TNode<Uint8T> details =
              Load<Uint8T>(original, details_table_offset_minus_tag.value());

          StoreToObject(MachineRepresentation::kWord8, table,
                        details_table_offset_minus_tag.value(), details,
                        StoreToObjectWriteBarrier::kNone);
          Goto(&done);
          BIND(&done);

          details_table_offset_minus_tag =
              IntPtrAdd(details_table_offset_minus_tag.value(),
                        IntPtrConstant(kOneByteSize));
        },
        kOneByteSize, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);
  }

  Comment("CopySwissNameDictionary ]");

  return table;
}

TNode<IntPtrT> CodeStubAssembler::SwissNameDictionaryOffsetIntoDataTableMT(
    TNode<SwissNameDictionary> dict, TNode<IntPtrT> index, int field_index) {
  TNode<IntPtrT> data_table_start = SwissNameDictionaryDataTableStartOffsetMT();

  TNode<IntPtrT> offset_within_data_table = IntPtrMul(
      index,
      IntPtrConstant(SwissNameDictionary::kDataTableEntryCount * kTaggedSize));

  if (field_index != 0) {
    offset_within_data_table = IntPtrAdd(
        offset_within_data_table, IntPtrConstant(field_index * kTaggedSize));
  }

  return IntPtrAdd(data_table_start, offset_within_data_table);
}

TNode<IntPtrT>
CodeStubAssembler::SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(
    TNode<SwissNameDictionary> dict, TNode<IntPtrT> capacity,
    TNode<IntPtrT> index) {
  CSA_DCHECK(this,
             WordEqual(capacity, ChangeUint32ToWord(
                                     LoadSwissNameDictionaryCapacity(dict))));

  TNode<IntPtrT> data_table_start = SwissNameDictionaryDataTableStartOffsetMT();

  TNode<IntPtrT> gw = IntPtrConstant(SwissNameDictionary::kGroupWidth);
  TNode<IntPtrT> data_and_ctrl_table_size = IntPtrAdd(
      IntPtrMul(capacity,
                IntPtrConstant(kOneByteSize +
                               SwissNameDictionary::kDataTableEntryCount *
                                   kTaggedSize)),
      gw);

  TNode<IntPtrT> property_details_table_start =
      IntPtrAdd(data_table_start, data_and_ctrl_table_size);

  CSA_DCHECK(
      this,
      WordEqual(FieldSliceSwissNameDictionaryPropertyDetailsTable(dict).offset,
                // Our calculation subtracted the tag, Torque's offset didn't.
                IntPtrAdd(property_details_table_start,
                          IntPtrConstant(kHeapObjectTag))));

  TNode<IntPtrT> offset_within_details_table = index;
  return IntPtrAdd(property_details_table_start, offset_within_details_table);
}

void CodeStubAssembler::StoreSwissNameDictionaryCapacity(
    TNode<SwissNameDictionary> table, TNode<Int32T> capacity) {
  StoreObjectFieldNoWriteBarrier<Word32T>(
      table, SwissNameDictionary::CapacityOffset(), capacity);
}

TNode<Name> CodeStubAssembler::LoadSwissNameDictionaryKey(
    TNode<SwissNameDictionary> dict, TNode<IntPtrT> entry) {
  TNode<IntPtrT> offset_minus_tag = SwissNameDictionaryOffsetIntoDataTableMT(
      dict, entry, SwissNameDictionary::kDataTableKeyEntryIndex);

  // TODO(v8:11330) Consider using LoadObjectField here.
  return CAST(Load<Object>(dict, offset_minus_tag));
}

TNode<Uint8T> CodeStubAssembler::LoadSwissNameDictionaryPropertyDetails(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
    TNode<IntPtrT> entry) {
  TNode<IntPtrT> offset_minus_tag =
      SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(table, capacity,
                                                          entry);
  // TODO(v8:11330) Consider using LoadObjectField here.
  return Load<Uint8T>(table, offset_minus_tag);
}

void CodeStubAssembler::StoreSwissNameDictionaryPropertyDetails(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
    TNode<IntPtrT> entry, TNode<Uint8T> details) {
  TNode<IntPtrT> offset_minus_tag =
      SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(table, capacity,
                                                          entry);

  // TODO(v8:11330) Consider using StoreObjectField here.
  StoreToObject(MachineRepresentation::kWord8, table, offset_minus_tag, details,
                StoreToObjectWriteBarrier::kNone);
}

void CodeStubAssembler::StoreSwissNameDictionaryKeyAndValue(
    TNode<SwissNameDictionary> dict, TNode<IntPtrT> entry, TNode<Object> key,
    TNode<Object> value) {
  static_assert(SwissNameDictionary::kDataTableKeyEntryIndex == 0);
  static_assert(SwissNameDictionary::kDataTableValueEntryIndex == 1);

  // TODO(v8:11330) Consider using StoreObjectField here.
  TNode<IntPtrT> key_offset_minus_tag =
      SwissNameDictionaryOffsetIntoDataTableMT(
          dict, entry, SwissNameDictionary::kDataTableKeyEntryIndex);
  StoreToObject(MachineRepresentation::kTagged, dict, key_offset_minus_tag, key,
                StoreToObjectWriteBarrier::kFull);

  TNode<IntPtrT> value_offset_minus_tag =
      IntPtrAdd(key_offset_minus_tag, IntPtrConstant(kTaggedSize));
  StoreToObject(MachineRepresentation::kTagged, dict, value_offset_minus_tag,
                value, StoreToObjectWriteBarrier::kFull);
}

TNode<Uint64T> CodeStubAssembler::LoadSwissNameDictionaryCtrlTableGroup(
    TNode<IntPtrT> address) {
  TNode<RawPtrT> ptr = ReinterpretCast<RawPtrT>(address);
  TNode<Uint64T> data = UnalignedLoad<Uint64T>(ptr, IntPtrConstant(0));

#ifdef V8_TARGET_LITTLE_ENDIAN
  return data;
#else
  // Reverse byte order.
  // TODO(v8:11330) Doing this without using dedicated instructions (which we
  // don't have access to here) will destroy any performance benefit Swiss
  // Tables have. So we just support this so that we don't have to disable the
  // test suite for SwissNameDictionary on big endian platforms.

  TNode<Uint64T> result = Uint64Constant(0);
  constexpr int count = sizeof(uint64_t);
  for (int i = 0; i < count; ++i) {
    int src_offset = i * 8;
    int dest_offset = (count - i - 1) * 8;

    TNode<Uint64T> mask = Uint64Constant(0xffULL << src_offset);
    TNode<Uint64T> src_data = Word64And(data, mask);

    TNode<Uint64T> shifted =
        src_offset < dest_offset
            ? Word64Shl(src_data, Uint64Constant(dest_offset - src_offset))
            : Word64Shr(src_data, Uint64Constant(src_offset - dest_offset));
    result = Unsigned(Word64Or(result, shifted));
  }
  return result;
#endif
}

void CodeStubAssembler::SwissNameDictionarySetCtrl(
    TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
    TNode<IntPtrT> entry, TNode<Uint8T> ctrl) {
  CSA_DCHECK(this,
             WordEqual(capacity, ChangeUint32ToWord(
                                     LoadSwissNameDictionaryCapacity(table))));
  CSA_DCHECK(this, UintPtrLessThan(entry, capacity));

  TNode<IntPtrT> one = IntPtrConstant(1);
  TNode<IntPtrT> offset = SwissNameDictionaryCtrlTableStartOffsetMT(capacity);

  CSA_DCHECK(this,
             WordEqual(FieldSliceSwissNameDictionaryCtrlTable(table).offset,
                       IntPtrAdd(offset, one)));

  TNode<IntPtrT> offset_entry = IntPtrAdd(offset, entry);
  StoreToObject(MachineRepresentation::kWord8, table, offset_entry, ctrl,
                StoreToObjectWriteBarrier::kNone);

  TNode<IntPtrT> mask = IntPtrSub(capacity, one);
  TNode<IntPtrT> group_width = IntPtrConstant(SwissNameDictionary::kGroupWidth);

  // See SwissNameDictionary::SetCtrl for description of what's going on here.

  // ((entry - Group::kWidth) & mask) + 1
  TNode<IntPtrT> copy_entry_lhs =
      IntPtrAdd(WordAnd(IntPtrSub(entry, group_width), mask), one);
  // ((Group::kWidth - 1) & mask)
  TNode<IntPtrT> copy_entry_rhs = WordAnd(IntPtrSub(group_width, one), mask);
  TNode<IntPtrT> copy_entry = IntPtrAdd(copy_entry_lhs, copy_entry_rhs);
  TNode<IntPtrT> offset_copy_entry = IntPtrAdd(offset, copy_entry);

  // |entry| < |kGroupWidth| implies |copy_entry| == |capacity| + |entry|
  CSA_DCHECK(this, Word32Or(UintPtrGreaterThanOrEqual(entry, group_width),
                            WordEqual(copy_entry, IntPtrAdd(capacity, entry))));

  // |entry| >= |kGroupWidth| implies |copy_entry| == |entry|
  CSA_DCHECK(this, Word32Or(UintPtrLessThan(entry, group_width),
                            WordEqual(copy_entry, entry)));

  // TODO(v8:11330): consider using StoreObjectFieldNoWriteBarrier here.
  StoreToObject(MachineRepresentation::kWord8, table, offset_copy_entry, ctrl,
                StoreToObjectWriteBarrier::kNone);
}

void CodeStubAssembler::SwissNameDictionaryFindEntry(
    TNode<SwissNameDictionary> table, TNode<Name> key, Label* found,
    TVariable<IntPtrT>* var_found_entry, Label* not_found) {
  if (SwissNameDictionary::kUseSIMD) {
    SwissNameDictionaryFindEntrySIMD(table, key, found, var_found_entry,
                                     not_found);
  } else {
    SwissNameDictionaryFindEntryPortable(table, key, found, var_found_entry,
                                         not_found);
  }
}

void CodeStubAssembler::SwissNameDictionaryAdd(TNode<SwissNameDictionary> table,
                                               TNode<Name> key,
                                               TNode<Object> value,
                                               TNode<Uint8T> property_details,
                                               Label* needs_resize) {
  if (SwissNameDictionary::kUseSIMD) {
    SwissNameDictionaryAddSIMD(table, key, value, property_details,
                               needs_resize);
  } else {
    SwissNameDictionaryAddPortable(table, key, value, property_details,
                                   needs_resize);
  }
}

void CodeStubAssembler::SharedValueBarrier(
    TNode<Context> context, TVariable<Object>* var_shared_value) {
  // The barrier ensures that the value can be shared across Isolates.
  // The fast paths should be kept in sync with Object::Share.

  TNode<Object> value = var_shared_value->value();
  Label check_in_shared_heap(this), slow(this), skip_barrier(this), done(this);

  // Fast path: Smis are trivially shared.
  GotoIf(TaggedIsSmi(value), &done);
  // Fast path: Shared memory features imply shared RO space, so RO objects are
  // trivially shared.
  CSA_DCHECK(this, BoolConstant(ReadOnlyHeap::IsReadOnlySpaceShared()));
  TNode<IntPtrT> page_flags = LoadMemoryChunkFlags(CAST(value));
  GotoIf(WordNotEqual(
             WordAnd(page_flags, IntPtrConstant(MemoryChunk::READ_ONLY_HEAP)),
             IntPtrConstant(0)),
         &skip_barrier);

  // Fast path: Check if the HeapObject is already shared.
  TNode<Uint16T> value_instance_type =
      LoadMapInstanceType(LoadMap(CAST(value)));
  GotoIf(IsSharedStringInstanceType(value_instance_type), &skip_barrier);
  GotoIf(IsAlwaysSharedSpaceJSObjectInstanceType(value_instance_type),
         &skip_barrier);
  GotoIf(IsHeapNumberInstanceType(value_instance_type), &check_in_shared_heap);
  Goto(&slow);

  BIND(&check_in_shared_heap);
  {
    Branch(WordNotEqual(
               WordAnd(page_flags,
                       IntPtrConstant(MemoryChunk::IN_WRITABLE_SHARED_SPACE)),
               IntPtrConstant(0)),
           &skip_barrier, &slow);
  }

  // Slow path: Call out to runtime to share primitives and to throw on
  // non-shared JS objects.
  BIND(&slow);
  {
    *var_shared_value =
        CallRuntime(Runtime::kSharedValueBarrierSlow, context, value);
    Goto(&skip_barrier);
  }

  BIND(&skip_barrier);
  {
    CSA_DCHECK(
        this,
        WordNotEqual(
            WordAnd(LoadMemoryChunkFlags(CAST(var_shared_value->value())),
                    IntPtrConstant(MemoryChunk::READ_ONLY_HEAP |
                                   MemoryChunk::IN_WRITABLE_SHARED_SPACE)),
            IntPtrConstant(0)));
    Goto(&done);
  }

  BIND(&done);
}

TNode<ArrayList> CodeStubAssembler::AllocateArrayList(TNode<Smi> capacity) {
  TVARIABLE(ArrayList, result);
  Label empty(this), nonempty(this), done(this);

  Branch(SmiEqual(capacity, SmiConstant(0)), &empty, &nonempty);

  BIND(&nonempty);
  {
    CSA_DCHECK(this, SmiGreaterThan(capacity, SmiConstant(0)));

    intptr_t capacity_constant;
    if (ToParameterConstant(capacity, &capacity_constant)) {
      CHECK_LE(capacity_constant, ArrayList::kMaxCapacity);
    } else {
      Label if_out_of_memory(this, Label::kDeferred), next(this);
      Branch(SmiGreaterThan(capacity, SmiConstant(ArrayList::kMaxCapacity)),
             &if_out_of_memory, &next);

      BIND(&if_out_of_memory);
      CallRuntime(Runtime::kFatalProcessOutOfMemoryInvalidArrayLength,
                  NoContextConstant());
      Unreachable();

      BIND(&next);
    }

    TNode<IntPtrT> total_size = GetArrayAllocationSize(
        capacity, PACKED_ELEMENTS, OFFSET_OF_DATA_START(ArrayList));
    TNode<HeapObject> array = Allocate(total_size);
    RootIndex map_index = RootIndex::kArrayListMap;
    DCHECK(RootsTable::IsImmortalImmovable(map_index));
    StoreMapNoWriteBarrier(array, map_index);
    StoreObjectFieldNoWriteBarrier(array, offsetof(ArrayList, capacity_),
                                   capacity);
    StoreObjectFieldNoWriteBarrier(array, offsetof(
```