Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/wasm/wasm-objects.cc`. I need to analyze the code and identify its key features. The decomposed instructions ask for specific things:

1. **List the functionalities:** I need to extract the main purposes of this code. It seems to be defining and manipulating various WebAssembly related objects within V8.
2. **Check for Torque source:** The user asks if the file ends in `.tq`. This snippet is C++, so the answer is no.
3. **Relationship with JavaScript:** I need to find parts of the code that interact with or relate to JavaScript and provide JavaScript examples. The code mentions `JSFunction`, `JSObject`, and interactions with JavaScript values.
4. **Code logic inference:**  Look for functions with clear input-output relationships and provide examples. The encoding and decoding functions for exception values seem like good candidates.
5. **Common programming errors:** Identify potential pitfalls or errors related to this code. Type mismatches during conversions or when handling exceptions might be relevant.
6. **Summarize the functionality:** Provide a concise overview of the code's purpose.
7. **Part number:** Acknowledge that this is part 4 of 4.

**Functionality Breakdown (Initial thoughts):**

* **Exception Handling:** The code defines `WasmExceptionPackage` and related functions for creating, getting, and encoding/decoding exception values.
* **Continuations:** The `WasmContinuationObject` suggests support for continuations in WebAssembly.
* **Function Wrappers:**  There are mentions of `WasmExportedFunction`, `WasmCapiFunction`, and `WasmJSFunction`, indicating how different types of functions are represented and wrapped.
* **Type Conversions:** The `JSToWasmObject` and `WasmToJSObject` functions highlight the conversion between JavaScript and WebAssembly values.
* **Canonical Signatures:** The code deals with `CanonicalSig` and how function signatures are handled.
* **Function References:**  `WasmFuncRef` appears, likely representing references to WebAssembly functions.
* **Asm.js Support:** `AsmWasmData` indicates some level of support for asm.js.

**JavaScript Relationship (Potential examples):**

* Creating and throwing WebAssembly exceptions from JavaScript.
* Calling exported WebAssembly functions from JavaScript.
* Passing JavaScript functions as imports to WebAssembly.
* Handling values returned from WebAssembly functions in JavaScript.

**Code Logic Inference (Example):**

* `EncodeI32ExceptionValue`: Input: `FixedArray`, `index`, `uint32_t value`. Output: Modifies `FixedArray` at `index` and `index + 1`.
* `DecodeI32ExceptionValue`: Input: `FixedArray`, `index`, `uint32_t* value`. Output: Populates `*value` from `FixedArray` at `index` and `index + 1`.

**Common Errors (Examples):**

* Passing a JavaScript value of the wrong type to a WebAssembly function.
* Attempting to access exception values in JavaScript before they are thrown by WebAssembly.
* Incorrectly creating or handling `WasmExceptionPackage` objects.

**Overall Plan:**

1. Go through the code and annotate each significant class and function, summarizing its purpose.
2. Identify sections directly related to JavaScript interaction.
3. Select functions suitable for demonstrating code logic.
4. Pinpoint potential error scenarios based on the code's functionality, especially around type conversions and object handling.
5. Synthesize a concise summary of the code's role.
```cpp
anonical_sig_index) const {
#if DEBUG
  // TODO(14034): Change this if indexed types are allowed.
  for (wasm::CanonicalValueType type : this->sig()->all()) {
    CHECK(!type.has_index());
  }
#endif
  // TODO(14034): Check for subtyping instead if C API functions can define
  // signature supertype.
  return shared()->wasm_capi_function_data()->sig_index() ==
         other_canonical_sig_index;
}

// static
Handle<WasmExceptionPackage> WasmExceptionPackage::New(
    Isolate* isolate, DirectHandle<WasmExceptionTag> exception_tag, int size) {
  DirectHandle<FixedArray> values = isolate->factory()->NewFixedArray(size);
  return New(isolate, exception_tag, values);
}

Handle<WasmExceptionPackage> WasmExceptionPackage::New(
    Isolate* isolate, DirectHandle<WasmExceptionTag> exception_tag,
    DirectHandle<FixedArray> values) {
  Handle<JSFunction> exception_cons(
      isolate->native_context()->wasm_exception_constructor(), isolate);
  Handle<JSObject> exception = isolate->factory()->NewJSObject(exception_cons);
  exception->InObjectPropertyAtPut(kTagIndex, *exception_tag);
  exception->InObjectPropertyAtPut(kValuesIndex, *values);
  return Cast<WasmExceptionPackage>(exception);
}

// static
Handle<Object> WasmExceptionPackage::GetExceptionTag(
    Isolate* isolate, Handle<WasmExceptionPackage> exception_package) {
  Handle<Object> tag;
  if (JSReceiver::GetProperty(isolate, exception_package,
                              isolate->factory()->wasm_exception_tag_symbol())
          .ToHandle(&tag)) {
    return tag;
  }
  return ReadOnlyRoots(isolate).undefined_value_handle();
}

// static
Handle<Object> WasmExceptionPackage::GetExceptionValues(
    Isolate* isolate, Handle<WasmExceptionPackage> exception_package) {
  Handle<Object> values;
  if (JSReceiver::GetProperty(
          isolate, exception_package,
          isolate->factory()->wasm_exception_values_symbol())
          .ToHandle(&values)) {
    DCHECK_IMPLIES(!IsUndefined(*values), IsFixedArray(*values));
    return values;
  }
  return ReadOnlyRoots(isolate).undefined_value_handle();
}

void EncodeI32ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint32_t value) {
  encoded_values->set((*encoded_index)++, Smi::FromInt(value >> 16));
  encoded_values->set((*encoded_index)++, Smi::FromInt(value & 0xffff));
}

void EncodeI64ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint64_t value) {
  EncodeI32ExceptionValue(encoded_values, encoded_index,
                          static_cast<uint32_t>(value >> 32));
  EncodeI32ExceptionValue(encoded_values, encoded_index,
                          static_cast<uint32_t>(value));
}

void DecodeI32ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint32_t* value) {
  uint32_t msb = Cast<Smi>(encoded_values->get((*encoded_index)++)).value();
  uint32_t lsb = Cast<Smi>(encoded_values->get((*encoded_index)++)).value();
  *value = (msb << 16) | (lsb & 0xffff);
}

void DecodeI64ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint64_t* value) {
  uint32_t lsb = 0, msb = 0;
  DecodeI32ExceptionValue(encoded_values, encoded_index, &msb);
  DecodeI32ExceptionValue(encoded_values, encoded_index, &lsb);
  *value = (static_cast<uint64_t>(msb) << 32) | static_cast<uint64_t>(lsb);
}

// static
Handle<WasmContinuationObject> WasmContinuationObject::New(
    Isolate* isolate, wasm::StackMemory* stack,
    wasm::JumpBuffer::StackState state, DirectHandle<HeapObject> parent,
    AllocationType allocation_type) {
  stack->jmpbuf()->stack_limit = stack->jslimit();
  stack->jmpbuf()->sp = stack->base();
  stack->jmpbuf()->fp = kNullAddress;
  stack->jmpbuf()->state = state;
  wasm::JumpBuffer* jmpbuf = stack->jmpbuf();
  Handle<WasmContinuationObject> result =
      isolate->factory()->NewWasmContinuationObject(
          reinterpret_cast<Address>(jmpbuf), stack, parent, allocation_type);
  return result;
}

bool UseGenericWasmToJSWrapper(wasm::ImportCallKind kind,
                               const wasm::CanonicalSig* sig,
                               wasm::Suspend suspend) {
  if (kind != wasm::ImportCallKind::kJSFunctionArityMatch &&
      kind != wasm::ImportCallKind::kJSFunctionArityMismatch) {
    return false;
  }
  DCHECK(wasm::IsJSCompatibleSignature(sig));
#if !V8_TARGET_ARCH_X64 && !V8_TARGET_ARCH_ARM64 && !V8_TARGET_ARCH_ARM && \
    !V8_TARGET_ARCH_IA32 && !V8_TARGET_ARCH_RISCV64 &&                     \
    !V8_TARGET_ARCH_RISCV32 && !V8_TARGET_ARCH_PPC64 &&                    \
    !V8_TARGET_ARCH_S390X && !V8_TARGET_ARCH_LOONG64 && !V8_TARGET_ARCH_MIPS64
  return false;
#else
  if (suspend != wasm::Suspend::kNoSuspend) return false;

  return v8_flags.wasm_generic_wrapper;
#endif
}

// static
Handle<WasmContinuationObject> WasmContinuationObject::New(
    Isolate* isolate, wasm::StackMemory* stack,
    wasm::JumpBuffer::StackState state, AllocationType allocation_type) {
  auto parent = ReadOnlyRoots(isolate).undefined_value();
  return New(isolate, stack, state, handle(parent, isolate), allocation_type);
}
#ifdef DEBUG

namespace {

constexpr uint32_t kBytesPerExceptionValuesArrayElement = 2;

size_t ComputeEncodedElementSize(wasm::ValueType type) {
  size_t byte_size = type.value_kind_size();
  DCHECK_EQ(byte_size % kBytesPerExceptionValuesArrayElement, 0);
  DCHECK_LE(1, byte_size / kBytesPerExceptionValuesArrayElement);
  return byte_size / kBytesPerExceptionValuesArrayElement;
}

}  // namespace

#endif  // DEBUG

// static
uint32_t WasmExceptionPackage::GetEncodedSize(const wasm::WasmTag* tag) {
  return GetEncodedSize(tag->sig);
}

// static
uint32_t WasmExceptionPackage::GetEncodedSize(const wasm::WasmTagSig* sig) {
  uint32_t encoded_size = 0;
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
    switch (sig->GetParam(i).kind()) {
      case wasm::kI32:
      case wasm::kF32:
        DCHECK_EQ(2, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 2;
        break;
      case wasm::kI64:
      case wasm::kF64:
        DCHECK_EQ(4, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 4;
        break;
      case wasm::kS128:
        DCHECK_EQ(8, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 8;
        break;
      case wasm::kRef:
      case wasm::kRefNull:
        encoded_size += 1;
        break;
      case wasm::kRtt:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
        UNREACHABLE();
    }
  }
  return encoded_size;
}

bool WasmExportedFunction::IsWasmExportedFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  Tagged<Code> code = js_function->code(GetIsolateForSandbox(js_function));
  if (CodeKind::JS_TO_WASM_FUNCTION != code->kind() &&
#if V8_ENABLE_DRUMBRAKE
      code->builtin_id() != Builtin::kGenericJSToWasmInterpreterWrapper &&
#endif  // V8_ENABLE_DRUMBRAKE
      code->builtin_id() != Builtin::kJSToWasmWrapper &&
      code->builtin_id() != Builtin::kWasmPromising &&
      code->builtin_id() != Builtin::kWasmStressSwitch) {
    return false;
  }
  DCHECK(js_function->shared()->HasWasmExportedFunctionData());
  return true;
}

bool WasmCapiFunction::IsWasmCapiFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  // TODO(jkummerow): Enable this when there is a JavaScript wrapper
  // able to call this function.
  // if (js_function->code()->kind() != CodeKind::WASM_TO_CAPI_FUNCTION) {
  //   return false;
  // }
  // DCHECK(js_function->shared()->HasWasmCapiFunctionData());
  // return true;
  return js_function->shared()->HasWasmCapiFunctionData();
}

Handle<WasmCapiFunction> WasmCapiFunction::New(
    Isolate* isolate, Address call_target, DirectHandle<Foreign> embedder_data,
    wasm::CanonicalTypeIndex sig_index, const wasm::CanonicalSig* sig,
    uintptr_t signature_hash) {
  // TODO(jkummerow): Install a JavaScript wrapper. For now, calling
  // these functions directly is unsupported; they can only be called
  // from Wasm code.

  // To support simulator builds, we potentially have to redirect the
  // call target (which is an address pointing into the C++ binary).
  call_target = ExternalReference::Create(call_target).address();

  DirectHandle<Map> rtt = isolate->factory()->wasm_func_ref_map();
  DirectHandle<WasmCapiFunctionData> fun_data =
      isolate->factory()->NewWasmCapiFunctionData(
          call_target, embedder_data, BUILTIN_CODE(isolate, Illegal), rtt,
          sig_index, sig, signature_hash);
  Handle<SharedFunctionInfo> shared =
      isolate->factory()->NewSharedFunctionInfoForWasmCapiFunction(fun_data);
  Handle<JSFunction> result =
      Factory::JSFunctionBuilder{isolate, shared, isolate->native_context()}
          .Build();
  fun_data->internal()->set_external(*result);
  return Cast<WasmCapiFunction>(result);
}

Handle<WasmExportedFunction> WasmExportedFunction::New(
    Isolate* isolate, DirectHandle<WasmTrustedInstanceData> instance_data,
    DirectHandle<WasmFuncRef> func_ref,
    DirectHandle<WasmInternalFunction> internal_function, int arity,
    DirectHandle<Code> export_wrapper) {
  DCHECK(CodeKind::JS_TO_WASM_FUNCTION == export_wrapper->kind() ||
         (export_wrapper->is_builtin() &&
          (export_wrapper->builtin_id() == Builtin::kJSToWasmWrapper ||
#if V8_ENABLE_DRUMBRAKE
           export_wrapper->builtin_id() ==
               Builtin::kGenericJSToWasmInterpreterWrapper ||
#endif  // V8_ENABLE_DRUMBRAKE
           export_wrapper->builtin_id() == Builtin::kWasmPromising ||
           export_wrapper->builtin_id() == Builtin::kWasmStressSwitch)));
  int func_index = internal_function->function_index();
  Factory* factory = isolate->factory();
  DirectHandle<Map> rtt;
  wasm::Promise promise =
      export_wrapper->builtin_id() == Builtin::kWasmPromising
          ? wasm::kPromise
          : wasm::kNoPromise;
  const wasm::WasmModule* module = instance_data->module();
  wasm::CanonicalTypeIndex sig_id =
      module->canonical_sig_id(module->functions[func_index].sig_index);
  const wasm::CanonicalSig* sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);
  DirectHandle<WasmExportedFunctionData> function_data =
      factory->NewWasmExportedFunctionData(
          export_wrapper, instance_data, func_ref, internal_function, sig,
          sig_id, v8_flags.wasm_wrapper_tiering_budget, promise);

#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    uint32_t aligned_size =
        wasm::WasmBytecode::JSToWasmWrapperPackedArraySize(sig);
    bool hasRefArgs = wasm::WasmBytecode::RefArgsCount(sig) > 0;
    bool hasRefRets = wasm::WasmBytecode::RefRetsCount(sig) > 0;
    function_data->set_packed_args_size(
        wasm::WasmInterpreterRuntime::PackedArgsSizeField::encode(
            aligned_size) |
        wasm::WasmInterpreterRuntime::HasRefArgsField::encode(hasRefArgs) |
        wasm::WasmInterpreterRuntime::HasRefRetsField::encode(hasRefRets));
  }
#endif  // V8_ENABLE_DRUMBRAKE

  MaybeHandle<String> maybe_name;
  bool is_asm_js_module = is_asmjs_module(module);
  if (is_asm_js_module) {
    // We can use the function name only for asm.js. For WebAssembly, the
    // function name is specified as the function_index.toString().
    maybe_name = WasmModuleObject::GetFunctionNameOrNull(
        isolate, handle(instance_data->module_object(), isolate), func_index);
  }
  Handle<String> name;
  if (!maybe_name.ToHandle(&name)) {
    base::EmbeddedVector<char, 16> buffer;
    int length = SNPrintF(buffer, "%d", func_index);
    name = factory
               ->NewStringFromOneByte(
                   base::Vector<uint8_t>::cast(buffer.SubVector(0, length)))
               .ToHandleChecked();
  }
  Handle<Map> function_map;
  switch (module->origin) {
    case wasm::kWasmOrigin:
      function_map = isolate->wasm_exported_function_map();
      break;
    case wasm::kAsmJsSloppyOrigin:
      function_map = isolate->sloppy_function_map();
      break;
    case wasm::kAsmJsStrictOrigin:
      function_map = isolate->strict_function_map();
      break;
  }

  Handle<NativeContext> context(isolate->native_context());
  Handle<SharedFunctionInfo> shared =
      factory->NewSharedFunctionInfoForWasmExportedFunction(name, function_data,
                                                            arity, kAdapt);

  Handle<JSFunction> js_function =
      Factory::JSFunctionBuilder{isolate, shared, context}
          .set_map(function_map)
          .Build();

  // According to the spec, exported functions should not have a [[Construct]]
  // method. This does not apply to functions exported from asm.js however.
  DCHECK_EQ(is_asm_js_module, IsConstructor(*js_function));
  if (instance_data->has_instance_object()) {
    shared->set_script(instance_data->module_object()->script(), kReleaseStore);
  } else {
    shared->set_script(*isolate->factory()->undefined_value(), kReleaseStore);
  }
  function_data->internal()->set_external(*js_function);
  return Cast<WasmExportedFunction>(js_function);
}

bool WasmExportedFunctionData::MatchesSignature(
    wasm::CanonicalTypeIndex other_canonical_type_index) {
  return wasm::GetTypeCanonicalizer()->IsCanonicalSubtype(
      sig_index(), other_canonical_type_index);
}

// static
std::unique_ptr<char[]> WasmExportedFunction::GetDebugName(
    const wasm::CanonicalSig* sig) {
  constexpr const char kPrefix[] = "js-to-wasm:";
  // prefix + parameters + delimiter + returns + zero byte
  size_t len = strlen(kPrefix) + sig->all().size() + 2;
  auto buffer = base::OwnedVector<char>::New(len);
  memcpy(buffer.begin(), kPrefix, strlen(kPrefix));
  PrintSignature(buffer.as_vector() + strlen(kPrefix), sig);
  return buffer.ReleaseData();
}

// static
bool WasmJSFunction::IsWasmJSFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  return js_function->shared()->HasWasmJSFunctionData();
}

Handle<Map> CreateFuncRefMap(Isolate* isolate, Handle<Map> opt_rtt_parent) {
  const int inobject_properties = 0;
  const InstanceType instance_type = WASM_FUNC_REF_TYPE;
  const ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
  DirectHandle<WasmTypeInfo> type_info = isolate->factory()->NewWasmTypeInfo(
      kNullAddress, opt_rtt_parent, Handle<WasmTrustedInstanceData>(),
      wasm::ModuleTypeIndex::Invalid());
  constexpr int kInstanceSize = WasmFuncRef::kSize;
  DCHECK_EQ(
      kInstanceSize,
      Cast<Map>(isolate->root(RootIndex::kWasmFuncRefMap))->instance_size());
  Handle<Map> map = isolate->factory()->NewContextlessMap(
      instance_type, kInstanceSize, elements_kind, inobject_properties);
  map->set_wasm_type_info(*type_info);
  return map;
}

Handle<WasmJSFunction> WasmJSFunction::New(Isolate* isolate,
                                           const wasm::FunctionSig* sig,
                                           Handle<JSReceiver> callable,
                                           wasm::Suspend suspend) {
  DCHECK_LE(sig->all().size(), kMaxInt);
  int parameter_count = static_cast<int>(sig->parameter_count());
  Factory* factory = isolate->factory();

  DirectHandle<Map> rtt;
  Handle<NativeContext> context(isolate->native_context());

  static_assert(wasm::kMaxCanonicalTypes <= kMaxInt);
  // TODO(clemensb): Merge the next two lines into a single call.
  wasm::CanonicalTypeIndex sig_id =
      wasm::GetTypeCanonicalizer()->AddRecursiveGroup(sig);
  const wasm::CanonicalSig* canonical_sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);

  wasm::TypeCanonicalizer::PrepareForCanonicalTypeId(isolate, sig_id);

  DirectHandle<WeakFixedArray> canonical_rtts(
      isolate->heap()->wasm_canonical_rtts(), isolate);

  Tagged<MaybeObject> maybe_canonical_map = canonical_rtts->get(sig_id.index);

  if (!maybe_canonical_map.IsCleared()) {
    rtt = direct_handle(
        Cast<Map>(maybe_canonical_map.GetHeapObjectAssumeWeak()), isolate);
  } else {
    rtt = CreateFuncRefMap(isolate, Handle<Map>());
    canonical_rtts->set(sig_id.index, MakeWeak(*rtt));
  }

  DirectHandle<Code> js_to_js_wrapper_code =
      wasm::IsJSCompatibleSignature(canonical_sig)
          ? isolate->builtins()->code_handle(Builtin::kJSToJSWrapper)
          : isolate->builtins()->code_handle(Builtin::kJSToJSWrapperInvalidSig);

#if V8_ENABLE_SANDBOX
  uint64_t signature_hash = wasm::SignatureHasher::Hash(sig);
#else
  uintptr_t signature_hash = 0;
#endif

  DirectHandle<WasmJSFunctionData> function_data =
      factory->NewWasmJSFunctionData(sig_id, callable, js_to_js_wrapper_code,
                                     rtt, suspend, wasm::kNoPromise,
                                     signature_hash);
  DirectHandle<WasmInternalFunction> internal_function{
      function_data->internal(), isolate};

  if (!wasm::IsJSCompatibleSignature(canonical_sig)) {
    internal_function->set_call_target(
        wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperInvalidSig>(
            isolate));
#if V8_ENABLE_DRUMBRAKE
  } else if (v8_flags.wasm_jitless) {
    function_data->func_ref()->internal(isolate)->set_call_target(
        wasm::GetBuiltinCodePointer<
            Builtin::kGenericWasmToJSInterpreterWrapper>(isolate));
#endif  // V8_ENABLE_DRUMBRAKE
  } else {
    int expected_arity = parameter_count;
    wasm::ImportCallKind kind;
    if (IsJSFunction(*callable)) {
      Tagged<SharedFunctionInfo> shared = Cast<JSFunction>(callable)->shared();
      expected_arity =
          shared->internal_formal_parameter_count_without_receiver();
      if (expected_arity == parameter_count) {
        kind = wasm::ImportCallKind::kJSFunctionArityMatch;
      } else {
        kind = wasm::ImportCallKind::kJSFunctionArityMismatch;
      }
    } else {
      kind = wasm::ImportCallKind::kUseCallBuiltin;
    }
    wasm::WasmCodeRefScope code_ref_scope;
    wasm::WasmImportWrapperCache* cache = wasm::GetWasmImportWrapperCache();
    wasm::WasmCode* wrapper =
        cache->MaybeGet(kind, sig_id, expected_arity, suspend);
    if (wrapper) {
      internal_function->set_call_target(wrapper->code_pointer());
      function_data->offheap_data()->set_wrapper(wrapper);
    } else if (UseGenericWasmToJSWrapper(kind, canonical_sig, suspend)) {
      internal_function->set_call_target(
          wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperAsm>(isolate));
    } else {
      // Initialize the import wrapper cache if that hasn't happened yet.
      cache->LazyInitialize(isolate);
      constexpr bool kNoSourcePositions = false;
      wrapper = cache->CompileWasmImportCallWrapper(
          isolate, kind, canonical_sig, sig_id, kNoSourcePositions,
          expected_arity, suspend);
      internal_function->set_call_target(wrapper->code_pointer());
      function_data->offheap_data()->set_wrapper(wrapper);
    }
  }

  Handle<String> name = factory->Function_string();
  if (IsJSFunction(*callable)) {
    name = JSFunction::GetDebugName(Cast<JSFunction>(callable));
    name = String::Flatten(isolate, name);
  }
  Handle<SharedFunctionInfo> shared =
      factory->NewSharedFunctionInfoForWasmJSFunction(name, function_data);
  shared->set_internal_formal_parameter_count(
      JSParameterCount(parameter_count));
  Handle<JSFunction> js_function =
      Factory::JSFunctionBuilder{isolate, shared, context}
          .set_map(isolate->wasm_exported_function_map())
          .Build();
  internal_function->set_external(*js_function);
  return Cast<WasmJSFunction>(js_function);
}

void WasmJSFunctionData::OffheapData::set_wrapper(wasm::WasmCode* wrapper) {
  DCHECK_NULL(wrapper_);  // We shouldn't overwrite existing wrappers.
  wrapper_ = wrapper;
  wrapper->IncRef();
}

WasmJSFunctionData::OffheapData::~OffheapData() {
  if (wrapper_) {
    wasm::WasmCode::DecrementRefCount({&wrapper_, 1});
  }
}

Tagged<JSReceiver> WasmJSFunctionData::GetCallable() const {
  return Cast<JSReceiver>(
      Cast<WasmImportData>(internal()->implicit_arg())->callable());
}

wasm::Suspend WasmJSFunctionData::GetSuspend() const {
  return static_cast<wasm::Suspend>(
      Cast<WasmImportData>(internal()->implicit_arg())->suspend());
}

const wasm::CanonicalSig* WasmJSFunctionData::GetSignature() const {
  return wasm::GetWasmEngine()->type_canonicalizer()->LookupFunctionSignature(
      sig_index());
}

bool WasmJSFunctionData::MatchesSignature(
    wasm::CanonicalTypeIndex other_canonical_sig_index) const {
#if DEBUG
  // TODO(14034): Change this if indexed types are allowed.
  const wasm::CanonicalSig* sig = GetSignature();
  for (wasm::CanonicalValueType type : sig->all()) CHECK(!type.has_index());
#endif
  // TODO(14034): Check for subtyping instead if WebAssembly.Function can define
  // signature supertype.
  return sig_index() == other_canonical_sig_index;
}

bool WasmExternalFunction::IsWasmExternalFunction(Tagged<Object> object) {
  return WasmExportedFunction::IsWasmExportedFunction(object) ||
         WasmJSFunction::IsWasmJSFunction(object) ||
         WasmCapiFunction::IsWasmCapiFunction(object);
}

Handle<WasmExceptionTag> WasmExceptionTag::New(Isolate* isolate, int index) {
  auto result = Cast<WasmExceptionTag>(isolate->factory()->NewStruct(
      WASM_EXCEPTION_TAG_TYPE, AllocationType::kOld));
  result->set_index(index);
  return result;
}

Handle<AsmWasmData> AsmWasmData::New(
    Isolate* isolate, std::shared_ptr<wasm::NativeModule> native_module,
    DirectHandle<HeapNumber> uses_bitset) {
  const WasmModule* module = native_module->module();
  const bool kUsesLiftoff = false;
  size_t memory_estimate =
      wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
          module, kUsesLiftoff, wasm::kNoDynamicTiering) +
      wasm::WasmCodeManager::EstimateNativeModuleMetaDataSize(module);
  DirectHandle<Managed<wasm::NativeModule>> managed_native_module =
      Managed<wasm::NativeModule>::From(isolate, memory_estimate,
                                        std::move(native_module));
  auto result = Cast<AsmWasmData>(
      isolate->factory()->NewStruct(ASM_WASM_DATA_TYPE, AllocationType::kOld));
  result->set_managed_native_module(*managed_native_module);
  result->set_uses_bitset(*uses_bitset);
  return result;
}

namespace {
constexpr int32_t kInt31MaxValue = 0x3fffffff;
constexpr int32_t kInt31MinValue = -kInt31MaxValue - 1;

// Tries to canonicalize a HeapNumber to an i31ref Smi. Returns the original
// HeapNumber if it fails.
Handle<Object> CanonicalizeHeapNumber(Handle<Object> number, Isolate* isolate) {
  double double_value = Cast<HeapNumber>(number)->value();
  if (double_value >= kInt31MinValue && double_value <= kInt31MaxValue &&
      !IsMinusZero(double_value) &&
      double_value == FastI2D(FastD2I(double_value))) {
    return handle(Smi::FromInt(FastD2I(double_value)), isolate);
  }
  return number;
}

// Tries to canonicalize a Smi into an i31 Smi. Returns a HeapNumber if it
// fails.
Handle<Object> CanonicalizeSmi(Handle<Object> smi, Isolate* isolate) {
  if constexpr (SmiValuesAre31Bits()) return smi;

  int32_t value = Cast<Smi>(*smi).value();

  if (value <= kInt31MaxValue && value >= kInt31MinValue) {
    return smi;
  } else {
    return isolate->factory()->NewHeapNumber(value);
  }
}
}  // namespace

namespace wasm {
MaybeHandle<Object> JSToWasmObject(Isolate* isolate, Handle<Object> value,
                                   CanonicalValueType expected,
                                   const char** error_message) {
  DCHECK(expected.is_object_reference());
  if (expected.kind() == kRefNull && IsNull(*value, isolate)) {
    switch (expected.heap_representation()) {
      case HeapType::kStringViewWtf8:
        *error_message = "stringview_wtf8 has no JS representation";
        return {};
      case HeapType::kStringViewWtf16:
        *error_message = "stringview_wtf16 has no JS representation";
        return {};
      case HeapType::kStringViewIter:
        *error_message = "stringview_iter has no JS representation";
        return {};
      case HeapType::kExn:
        *error_message = "invalid type (ref null exn)";
        return {};
      case HeapType::kNoExn:
        *error_message = "invalid type (ref null noexn)";
        return {};
      default:
        return expected.use
Prompt: 
```
这是目录为v8/src/wasm/wasm-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
anonical_sig_index) const {
#if DEBUG
  // TODO(14034): Change this if indexed types are allowed.
  for (wasm::CanonicalValueType type : this->sig()->all()) {
    CHECK(!type.has_index());
  }
#endif
  // TODO(14034): Check for subtyping instead if C API functions can define
  // signature supertype.
  return shared()->wasm_capi_function_data()->sig_index() ==
         other_canonical_sig_index;
}

// static
Handle<WasmExceptionPackage> WasmExceptionPackage::New(
    Isolate* isolate, DirectHandle<WasmExceptionTag> exception_tag, int size) {
  DirectHandle<FixedArray> values = isolate->factory()->NewFixedArray(size);
  return New(isolate, exception_tag, values);
}

Handle<WasmExceptionPackage> WasmExceptionPackage::New(
    Isolate* isolate, DirectHandle<WasmExceptionTag> exception_tag,
    DirectHandle<FixedArray> values) {
  Handle<JSFunction> exception_cons(
      isolate->native_context()->wasm_exception_constructor(), isolate);
  Handle<JSObject> exception = isolate->factory()->NewJSObject(exception_cons);
  exception->InObjectPropertyAtPut(kTagIndex, *exception_tag);
  exception->InObjectPropertyAtPut(kValuesIndex, *values);
  return Cast<WasmExceptionPackage>(exception);
}

// static
Handle<Object> WasmExceptionPackage::GetExceptionTag(
    Isolate* isolate, Handle<WasmExceptionPackage> exception_package) {
  Handle<Object> tag;
  if (JSReceiver::GetProperty(isolate, exception_package,
                              isolate->factory()->wasm_exception_tag_symbol())
          .ToHandle(&tag)) {
    return tag;
  }
  return ReadOnlyRoots(isolate).undefined_value_handle();
}

// static
Handle<Object> WasmExceptionPackage::GetExceptionValues(
    Isolate* isolate, Handle<WasmExceptionPackage> exception_package) {
  Handle<Object> values;
  if (JSReceiver::GetProperty(
          isolate, exception_package,
          isolate->factory()->wasm_exception_values_symbol())
          .ToHandle(&values)) {
    DCHECK_IMPLIES(!IsUndefined(*values), IsFixedArray(*values));
    return values;
  }
  return ReadOnlyRoots(isolate).undefined_value_handle();
}

void EncodeI32ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint32_t value) {
  encoded_values->set((*encoded_index)++, Smi::FromInt(value >> 16));
  encoded_values->set((*encoded_index)++, Smi::FromInt(value & 0xffff));
}

void EncodeI64ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint64_t value) {
  EncodeI32ExceptionValue(encoded_values, encoded_index,
                          static_cast<uint32_t>(value >> 32));
  EncodeI32ExceptionValue(encoded_values, encoded_index,
                          static_cast<uint32_t>(value));
}

void DecodeI32ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint32_t* value) {
  uint32_t msb = Cast<Smi>(encoded_values->get((*encoded_index)++)).value();
  uint32_t lsb = Cast<Smi>(encoded_values->get((*encoded_index)++)).value();
  *value = (msb << 16) | (lsb & 0xffff);
}

void DecodeI64ExceptionValue(DirectHandle<FixedArray> encoded_values,
                             uint32_t* encoded_index, uint64_t* value) {
  uint32_t lsb = 0, msb = 0;
  DecodeI32ExceptionValue(encoded_values, encoded_index, &msb);
  DecodeI32ExceptionValue(encoded_values, encoded_index, &lsb);
  *value = (static_cast<uint64_t>(msb) << 32) | static_cast<uint64_t>(lsb);
}

// static
Handle<WasmContinuationObject> WasmContinuationObject::New(
    Isolate* isolate, wasm::StackMemory* stack,
    wasm::JumpBuffer::StackState state, DirectHandle<HeapObject> parent,
    AllocationType allocation_type) {
  stack->jmpbuf()->stack_limit = stack->jslimit();
  stack->jmpbuf()->sp = stack->base();
  stack->jmpbuf()->fp = kNullAddress;
  stack->jmpbuf()->state = state;
  wasm::JumpBuffer* jmpbuf = stack->jmpbuf();
  Handle<WasmContinuationObject> result =
      isolate->factory()->NewWasmContinuationObject(
          reinterpret_cast<Address>(jmpbuf), stack, parent, allocation_type);
  return result;
}

bool UseGenericWasmToJSWrapper(wasm::ImportCallKind kind,
                               const wasm::CanonicalSig* sig,
                               wasm::Suspend suspend) {
  if (kind != wasm::ImportCallKind::kJSFunctionArityMatch &&
      kind != wasm::ImportCallKind::kJSFunctionArityMismatch) {
    return false;
  }
  DCHECK(wasm::IsJSCompatibleSignature(sig));
#if !V8_TARGET_ARCH_X64 && !V8_TARGET_ARCH_ARM64 && !V8_TARGET_ARCH_ARM && \
    !V8_TARGET_ARCH_IA32 && !V8_TARGET_ARCH_RISCV64 &&                     \
    !V8_TARGET_ARCH_RISCV32 && !V8_TARGET_ARCH_PPC64 &&                    \
    !V8_TARGET_ARCH_S390X && !V8_TARGET_ARCH_LOONG64 && !V8_TARGET_ARCH_MIPS64
  return false;
#else
  if (suspend != wasm::Suspend::kNoSuspend) return false;

  return v8_flags.wasm_generic_wrapper;
#endif
}

// static
Handle<WasmContinuationObject> WasmContinuationObject::New(
    Isolate* isolate, wasm::StackMemory* stack,
    wasm::JumpBuffer::StackState state, AllocationType allocation_type) {
  auto parent = ReadOnlyRoots(isolate).undefined_value();
  return New(isolate, stack, state, handle(parent, isolate), allocation_type);
}
#ifdef DEBUG

namespace {

constexpr uint32_t kBytesPerExceptionValuesArrayElement = 2;

size_t ComputeEncodedElementSize(wasm::ValueType type) {
  size_t byte_size = type.value_kind_size();
  DCHECK_EQ(byte_size % kBytesPerExceptionValuesArrayElement, 0);
  DCHECK_LE(1, byte_size / kBytesPerExceptionValuesArrayElement);
  return byte_size / kBytesPerExceptionValuesArrayElement;
}

}  // namespace

#endif  // DEBUG

// static
uint32_t WasmExceptionPackage::GetEncodedSize(const wasm::WasmTag* tag) {
  return GetEncodedSize(tag->sig);
}

// static
uint32_t WasmExceptionPackage::GetEncodedSize(const wasm::WasmTagSig* sig) {
  uint32_t encoded_size = 0;
  for (size_t i = 0; i < sig->parameter_count(); ++i) {
    switch (sig->GetParam(i).kind()) {
      case wasm::kI32:
      case wasm::kF32:
        DCHECK_EQ(2, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 2;
        break;
      case wasm::kI64:
      case wasm::kF64:
        DCHECK_EQ(4, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 4;
        break;
      case wasm::kS128:
        DCHECK_EQ(8, ComputeEncodedElementSize(sig->GetParam(i)));
        encoded_size += 8;
        break;
      case wasm::kRef:
      case wasm::kRefNull:
        encoded_size += 1;
        break;
      case wasm::kRtt:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
        UNREACHABLE();
    }
  }
  return encoded_size;
}

bool WasmExportedFunction::IsWasmExportedFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  Tagged<Code> code = js_function->code(GetIsolateForSandbox(js_function));
  if (CodeKind::JS_TO_WASM_FUNCTION != code->kind() &&
#if V8_ENABLE_DRUMBRAKE
      code->builtin_id() != Builtin::kGenericJSToWasmInterpreterWrapper &&
#endif  // V8_ENABLE_DRUMBRAKE
      code->builtin_id() != Builtin::kJSToWasmWrapper &&
      code->builtin_id() != Builtin::kWasmPromising &&
      code->builtin_id() != Builtin::kWasmStressSwitch) {
    return false;
  }
  DCHECK(js_function->shared()->HasWasmExportedFunctionData());
  return true;
}

bool WasmCapiFunction::IsWasmCapiFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  // TODO(jkummerow): Enable this when there is a JavaScript wrapper
  // able to call this function.
  // if (js_function->code()->kind() != CodeKind::WASM_TO_CAPI_FUNCTION) {
  //   return false;
  // }
  // DCHECK(js_function->shared()->HasWasmCapiFunctionData());
  // return true;
  return js_function->shared()->HasWasmCapiFunctionData();
}

Handle<WasmCapiFunction> WasmCapiFunction::New(
    Isolate* isolate, Address call_target, DirectHandle<Foreign> embedder_data,
    wasm::CanonicalTypeIndex sig_index, const wasm::CanonicalSig* sig,
    uintptr_t signature_hash) {
  // TODO(jkummerow): Install a JavaScript wrapper. For now, calling
  // these functions directly is unsupported; they can only be called
  // from Wasm code.

  // To support simulator builds, we potentially have to redirect the
  // call target (which is an address pointing into the C++ binary).
  call_target = ExternalReference::Create(call_target).address();

  DirectHandle<Map> rtt = isolate->factory()->wasm_func_ref_map();
  DirectHandle<WasmCapiFunctionData> fun_data =
      isolate->factory()->NewWasmCapiFunctionData(
          call_target, embedder_data, BUILTIN_CODE(isolate, Illegal), rtt,
          sig_index, sig, signature_hash);
  Handle<SharedFunctionInfo> shared =
      isolate->factory()->NewSharedFunctionInfoForWasmCapiFunction(fun_data);
  Handle<JSFunction> result =
      Factory::JSFunctionBuilder{isolate, shared, isolate->native_context()}
          .Build();
  fun_data->internal()->set_external(*result);
  return Cast<WasmCapiFunction>(result);
}

Handle<WasmExportedFunction> WasmExportedFunction::New(
    Isolate* isolate, DirectHandle<WasmTrustedInstanceData> instance_data,
    DirectHandle<WasmFuncRef> func_ref,
    DirectHandle<WasmInternalFunction> internal_function, int arity,
    DirectHandle<Code> export_wrapper) {
  DCHECK(CodeKind::JS_TO_WASM_FUNCTION == export_wrapper->kind() ||
         (export_wrapper->is_builtin() &&
          (export_wrapper->builtin_id() == Builtin::kJSToWasmWrapper ||
#if V8_ENABLE_DRUMBRAKE
           export_wrapper->builtin_id() ==
               Builtin::kGenericJSToWasmInterpreterWrapper ||
#endif  // V8_ENABLE_DRUMBRAKE
           export_wrapper->builtin_id() == Builtin::kWasmPromising ||
           export_wrapper->builtin_id() == Builtin::kWasmStressSwitch)));
  int func_index = internal_function->function_index();
  Factory* factory = isolate->factory();
  DirectHandle<Map> rtt;
  wasm::Promise promise =
      export_wrapper->builtin_id() == Builtin::kWasmPromising
          ? wasm::kPromise
          : wasm::kNoPromise;
  const wasm::WasmModule* module = instance_data->module();
  wasm::CanonicalTypeIndex sig_id =
      module->canonical_sig_id(module->functions[func_index].sig_index);
  const wasm::CanonicalSig* sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);
  DirectHandle<WasmExportedFunctionData> function_data =
      factory->NewWasmExportedFunctionData(
          export_wrapper, instance_data, func_ref, internal_function, sig,
          sig_id, v8_flags.wasm_wrapper_tiering_budget, promise);

#if V8_ENABLE_DRUMBRAKE
  if (v8_flags.wasm_jitless) {
    uint32_t aligned_size =
        wasm::WasmBytecode::JSToWasmWrapperPackedArraySize(sig);
    bool hasRefArgs = wasm::WasmBytecode::RefArgsCount(sig) > 0;
    bool hasRefRets = wasm::WasmBytecode::RefRetsCount(sig) > 0;
    function_data->set_packed_args_size(
        wasm::WasmInterpreterRuntime::PackedArgsSizeField::encode(
            aligned_size) |
        wasm::WasmInterpreterRuntime::HasRefArgsField::encode(hasRefArgs) |
        wasm::WasmInterpreterRuntime::HasRefRetsField::encode(hasRefRets));
  }
#endif  // V8_ENABLE_DRUMBRAKE

  MaybeHandle<String> maybe_name;
  bool is_asm_js_module = is_asmjs_module(module);
  if (is_asm_js_module) {
    // We can use the function name only for asm.js. For WebAssembly, the
    // function name is specified as the function_index.toString().
    maybe_name = WasmModuleObject::GetFunctionNameOrNull(
        isolate, handle(instance_data->module_object(), isolate), func_index);
  }
  Handle<String> name;
  if (!maybe_name.ToHandle(&name)) {
    base::EmbeddedVector<char, 16> buffer;
    int length = SNPrintF(buffer, "%d", func_index);
    name = factory
               ->NewStringFromOneByte(
                   base::Vector<uint8_t>::cast(buffer.SubVector(0, length)))
               .ToHandleChecked();
  }
  Handle<Map> function_map;
  switch (module->origin) {
    case wasm::kWasmOrigin:
      function_map = isolate->wasm_exported_function_map();
      break;
    case wasm::kAsmJsSloppyOrigin:
      function_map = isolate->sloppy_function_map();
      break;
    case wasm::kAsmJsStrictOrigin:
      function_map = isolate->strict_function_map();
      break;
  }

  Handle<NativeContext> context(isolate->native_context());
  Handle<SharedFunctionInfo> shared =
      factory->NewSharedFunctionInfoForWasmExportedFunction(name, function_data,
                                                            arity, kAdapt);

  Handle<JSFunction> js_function =
      Factory::JSFunctionBuilder{isolate, shared, context}
          .set_map(function_map)
          .Build();

  // According to the spec, exported functions should not have a [[Construct]]
  // method. This does not apply to functions exported from asm.js however.
  DCHECK_EQ(is_asm_js_module, IsConstructor(*js_function));
  if (instance_data->has_instance_object()) {
    shared->set_script(instance_data->module_object()->script(), kReleaseStore);
  } else {
    shared->set_script(*isolate->factory()->undefined_value(), kReleaseStore);
  }
  function_data->internal()->set_external(*js_function);
  return Cast<WasmExportedFunction>(js_function);
}

bool WasmExportedFunctionData::MatchesSignature(
    wasm::CanonicalTypeIndex other_canonical_type_index) {
  return wasm::GetTypeCanonicalizer()->IsCanonicalSubtype(
      sig_index(), other_canonical_type_index);
}

// static
std::unique_ptr<char[]> WasmExportedFunction::GetDebugName(
    const wasm::CanonicalSig* sig) {
  constexpr const char kPrefix[] = "js-to-wasm:";
  // prefix + parameters + delimiter + returns + zero byte
  size_t len = strlen(kPrefix) + sig->all().size() + 2;
  auto buffer = base::OwnedVector<char>::New(len);
  memcpy(buffer.begin(), kPrefix, strlen(kPrefix));
  PrintSignature(buffer.as_vector() + strlen(kPrefix), sig);
  return buffer.ReleaseData();
}

// static
bool WasmJSFunction::IsWasmJSFunction(Tagged<Object> object) {
  if (!IsJSFunction(object)) return false;
  Tagged<JSFunction> js_function = Cast<JSFunction>(object);
  return js_function->shared()->HasWasmJSFunctionData();
}

Handle<Map> CreateFuncRefMap(Isolate* isolate, Handle<Map> opt_rtt_parent) {
  const int inobject_properties = 0;
  const InstanceType instance_type = WASM_FUNC_REF_TYPE;
  const ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
  DirectHandle<WasmTypeInfo> type_info = isolate->factory()->NewWasmTypeInfo(
      kNullAddress, opt_rtt_parent, Handle<WasmTrustedInstanceData>(),
      wasm::ModuleTypeIndex::Invalid());
  constexpr int kInstanceSize = WasmFuncRef::kSize;
  DCHECK_EQ(
      kInstanceSize,
      Cast<Map>(isolate->root(RootIndex::kWasmFuncRefMap))->instance_size());
  Handle<Map> map = isolate->factory()->NewContextlessMap(
      instance_type, kInstanceSize, elements_kind, inobject_properties);
  map->set_wasm_type_info(*type_info);
  return map;
}

Handle<WasmJSFunction> WasmJSFunction::New(Isolate* isolate,
                                           const wasm::FunctionSig* sig,
                                           Handle<JSReceiver> callable,
                                           wasm::Suspend suspend) {
  DCHECK_LE(sig->all().size(), kMaxInt);
  int parameter_count = static_cast<int>(sig->parameter_count());
  Factory* factory = isolate->factory();

  DirectHandle<Map> rtt;
  Handle<NativeContext> context(isolate->native_context());

  static_assert(wasm::kMaxCanonicalTypes <= kMaxInt);
  // TODO(clemensb): Merge the next two lines into a single call.
  wasm::CanonicalTypeIndex sig_id =
      wasm::GetTypeCanonicalizer()->AddRecursiveGroup(sig);
  const wasm::CanonicalSig* canonical_sig =
      wasm::GetTypeCanonicalizer()->LookupFunctionSignature(sig_id);

  wasm::TypeCanonicalizer::PrepareForCanonicalTypeId(isolate, sig_id);

  DirectHandle<WeakFixedArray> canonical_rtts(
      isolate->heap()->wasm_canonical_rtts(), isolate);

  Tagged<MaybeObject> maybe_canonical_map = canonical_rtts->get(sig_id.index);

  if (!maybe_canonical_map.IsCleared()) {
    rtt = direct_handle(
        Cast<Map>(maybe_canonical_map.GetHeapObjectAssumeWeak()), isolate);
  } else {
    rtt = CreateFuncRefMap(isolate, Handle<Map>());
    canonical_rtts->set(sig_id.index, MakeWeak(*rtt));
  }

  DirectHandle<Code> js_to_js_wrapper_code =
      wasm::IsJSCompatibleSignature(canonical_sig)
          ? isolate->builtins()->code_handle(Builtin::kJSToJSWrapper)
          : isolate->builtins()->code_handle(Builtin::kJSToJSWrapperInvalidSig);

#if V8_ENABLE_SANDBOX
  uint64_t signature_hash = wasm::SignatureHasher::Hash(sig);
#else
  uintptr_t signature_hash = 0;
#endif

  DirectHandle<WasmJSFunctionData> function_data =
      factory->NewWasmJSFunctionData(sig_id, callable, js_to_js_wrapper_code,
                                     rtt, suspend, wasm::kNoPromise,
                                     signature_hash);
  DirectHandle<WasmInternalFunction> internal_function{
      function_data->internal(), isolate};

  if (!wasm::IsJSCompatibleSignature(canonical_sig)) {
    internal_function->set_call_target(
        wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperInvalidSig>(
            isolate));
#if V8_ENABLE_DRUMBRAKE
  } else if (v8_flags.wasm_jitless) {
    function_data->func_ref()->internal(isolate)->set_call_target(
        wasm::GetBuiltinCodePointer<
            Builtin::kGenericWasmToJSInterpreterWrapper>(isolate));
#endif  // V8_ENABLE_DRUMBRAKE
  } else {
    int expected_arity = parameter_count;
    wasm::ImportCallKind kind;
    if (IsJSFunction(*callable)) {
      Tagged<SharedFunctionInfo> shared = Cast<JSFunction>(callable)->shared();
      expected_arity =
          shared->internal_formal_parameter_count_without_receiver();
      if (expected_arity == parameter_count) {
        kind = wasm::ImportCallKind::kJSFunctionArityMatch;
      } else {
        kind = wasm::ImportCallKind::kJSFunctionArityMismatch;
      }
    } else {
      kind = wasm::ImportCallKind::kUseCallBuiltin;
    }
    wasm::WasmCodeRefScope code_ref_scope;
    wasm::WasmImportWrapperCache* cache = wasm::GetWasmImportWrapperCache();
    wasm::WasmCode* wrapper =
        cache->MaybeGet(kind, sig_id, expected_arity, suspend);
    if (wrapper) {
      internal_function->set_call_target(wrapper->code_pointer());
      function_data->offheap_data()->set_wrapper(wrapper);
    } else if (UseGenericWasmToJSWrapper(kind, canonical_sig, suspend)) {
      internal_function->set_call_target(
          wasm::GetBuiltinCodePointer<Builtin::kWasmToJsWrapperAsm>(isolate));
    } else {
      // Initialize the import wrapper cache if that hasn't happened yet.
      cache->LazyInitialize(isolate);
      constexpr bool kNoSourcePositions = false;
      wrapper = cache->CompileWasmImportCallWrapper(
          isolate, kind, canonical_sig, sig_id, kNoSourcePositions,
          expected_arity, suspend);
      internal_function->set_call_target(wrapper->code_pointer());
      function_data->offheap_data()->set_wrapper(wrapper);
    }
  }

  Handle<String> name = factory->Function_string();
  if (IsJSFunction(*callable)) {
    name = JSFunction::GetDebugName(Cast<JSFunction>(callable));
    name = String::Flatten(isolate, name);
  }
  Handle<SharedFunctionInfo> shared =
      factory->NewSharedFunctionInfoForWasmJSFunction(name, function_data);
  shared->set_internal_formal_parameter_count(
      JSParameterCount(parameter_count));
  Handle<JSFunction> js_function =
      Factory::JSFunctionBuilder{isolate, shared, context}
          .set_map(isolate->wasm_exported_function_map())
          .Build();
  internal_function->set_external(*js_function);
  return Cast<WasmJSFunction>(js_function);
}

void WasmJSFunctionData::OffheapData::set_wrapper(wasm::WasmCode* wrapper) {
  DCHECK_NULL(wrapper_);  // We shouldn't overwrite existing wrappers.
  wrapper_ = wrapper;
  wrapper->IncRef();
}

WasmJSFunctionData::OffheapData::~OffheapData() {
  if (wrapper_) {
    wasm::WasmCode::DecrementRefCount({&wrapper_, 1});
  }
}

Tagged<JSReceiver> WasmJSFunctionData::GetCallable() const {
  return Cast<JSReceiver>(
      Cast<WasmImportData>(internal()->implicit_arg())->callable());
}

wasm::Suspend WasmJSFunctionData::GetSuspend() const {
  return static_cast<wasm::Suspend>(
      Cast<WasmImportData>(internal()->implicit_arg())->suspend());
}

const wasm::CanonicalSig* WasmJSFunctionData::GetSignature() const {
  return wasm::GetWasmEngine()->type_canonicalizer()->LookupFunctionSignature(
      sig_index());
}

bool WasmJSFunctionData::MatchesSignature(
    wasm::CanonicalTypeIndex other_canonical_sig_index) const {
#if DEBUG
  // TODO(14034): Change this if indexed types are allowed.
  const wasm::CanonicalSig* sig = GetSignature();
  for (wasm::CanonicalValueType type : sig->all()) CHECK(!type.has_index());
#endif
  // TODO(14034): Check for subtyping instead if WebAssembly.Function can define
  // signature supertype.
  return sig_index() == other_canonical_sig_index;
}

bool WasmExternalFunction::IsWasmExternalFunction(Tagged<Object> object) {
  return WasmExportedFunction::IsWasmExportedFunction(object) ||
         WasmJSFunction::IsWasmJSFunction(object) ||
         WasmCapiFunction::IsWasmCapiFunction(object);
}

Handle<WasmExceptionTag> WasmExceptionTag::New(Isolate* isolate, int index) {
  auto result = Cast<WasmExceptionTag>(isolate->factory()->NewStruct(
      WASM_EXCEPTION_TAG_TYPE, AllocationType::kOld));
  result->set_index(index);
  return result;
}

Handle<AsmWasmData> AsmWasmData::New(
    Isolate* isolate, std::shared_ptr<wasm::NativeModule> native_module,
    DirectHandle<HeapNumber> uses_bitset) {
  const WasmModule* module = native_module->module();
  const bool kUsesLiftoff = false;
  size_t memory_estimate =
      wasm::WasmCodeManager::EstimateNativeModuleCodeSize(
          module, kUsesLiftoff, wasm::kNoDynamicTiering) +
      wasm::WasmCodeManager::EstimateNativeModuleMetaDataSize(module);
  DirectHandle<Managed<wasm::NativeModule>> managed_native_module =
      Managed<wasm::NativeModule>::From(isolate, memory_estimate,
                                        std::move(native_module));
  auto result = Cast<AsmWasmData>(
      isolate->factory()->NewStruct(ASM_WASM_DATA_TYPE, AllocationType::kOld));
  result->set_managed_native_module(*managed_native_module);
  result->set_uses_bitset(*uses_bitset);
  return result;
}

namespace {
constexpr int32_t kInt31MaxValue = 0x3fffffff;
constexpr int32_t kInt31MinValue = -kInt31MaxValue - 1;

// Tries to canonicalize a HeapNumber to an i31ref Smi. Returns the original
// HeapNumber if it fails.
Handle<Object> CanonicalizeHeapNumber(Handle<Object> number, Isolate* isolate) {
  double double_value = Cast<HeapNumber>(number)->value();
  if (double_value >= kInt31MinValue && double_value <= kInt31MaxValue &&
      !IsMinusZero(double_value) &&
      double_value == FastI2D(FastD2I(double_value))) {
    return handle(Smi::FromInt(FastD2I(double_value)), isolate);
  }
  return number;
}

// Tries to canonicalize a Smi into an i31 Smi. Returns a HeapNumber if it
// fails.
Handle<Object> CanonicalizeSmi(Handle<Object> smi, Isolate* isolate) {
  if constexpr (SmiValuesAre31Bits()) return smi;

  int32_t value = Cast<Smi>(*smi).value();

  if (value <= kInt31MaxValue && value >= kInt31MinValue) {
    return smi;
  } else {
    return isolate->factory()->NewHeapNumber(value);
  }
}
}  // namespace

namespace wasm {
MaybeHandle<Object> JSToWasmObject(Isolate* isolate, Handle<Object> value,
                                   CanonicalValueType expected,
                                   const char** error_message) {
  DCHECK(expected.is_object_reference());
  if (expected.kind() == kRefNull && IsNull(*value, isolate)) {
    switch (expected.heap_representation()) {
      case HeapType::kStringViewWtf8:
        *error_message = "stringview_wtf8 has no JS representation";
        return {};
      case HeapType::kStringViewWtf16:
        *error_message = "stringview_wtf16 has no JS representation";
        return {};
      case HeapType::kStringViewIter:
        *error_message = "stringview_iter has no JS representation";
        return {};
      case HeapType::kExn:
        *error_message = "invalid type (ref null exn)";
        return {};
      case HeapType::kNoExn:
        *error_message = "invalid type (ref null noexn)";
        return {};
      default:
        return expected.use_wasm_null() ? isolate->factory()->wasm_null()
                                        : value;
    }
  }

  switch (expected.heap_representation_non_shared()) {
    case HeapType::kFunc: {
      if (!(WasmExternalFunction::IsWasmExternalFunction(*value) ||
            WasmCapiFunction::IsWasmCapiFunction(*value))) {
        *error_message =
            "function-typed object must be null (if nullable) or a Wasm "
            "function object";
        return {};
      }
      return handle(
          Cast<JSFunction>(*value)->shared()->wasm_function_data()->func_ref(),
          isolate);
    }
    case HeapType::kExtern: {
      if (!IsNull(*value, isolate)) return value;
      *error_message = "null is not allowed for (ref extern)";
      return {};
    }
    case HeapType::kAny: {
      if (IsSmi(*value)) return CanonicalizeSmi(value, isolate);
      if (IsHeapNumber(*value)) {
        return CanonicalizeHeapNumber(value, isolate);
      }
      if (!IsNull(*value, isolate)) return value;
      *error_message = "null is not allowed for (ref any)";
      return {};
    }
    case HeapType::kExn:
      *error_message = "invalid type (ref exn)";
      return {};
    case HeapType::kStruct: {
      if (IsWasmStruct(*value)) {
        return value;
      }
      *error_message =
          "structref object must be null (if nullable) or a wasm struct";
      return {};
    }
    case HeapType::kArray: {
      if (IsWasmArray(*value)) {
        return value;
      }
      *error_message =
          "arrayref object must be null (if nullable) or a wasm array";
      return {};
    }
    case HeapType::kEq: {
      if (IsSmi(*value)) {
        Handle<Object> truncated = CanonicalizeSmi(value, isolate);
        if (IsSmi(*truncated)) return truncated;
      } else if (IsHeapNumber(*value)) {
        Handle<Object> truncated = CanonicalizeHeapNumber(value, isolate);
        if (IsSmi(*truncated)) return truncated;
      } else if (IsWasmStruct(*value) || IsWasmArray(*value)) {
        return value;
      }
      *error_message =
          "eqref object must be null (if nullable), or a wasm "
          "struct/array, or a Number that fits in i31ref range";
      return {};
    }
    case HeapType::kI31: {
      if (IsSmi(*value)) {
        Handle<Object> truncated = CanonicalizeSmi(value, isolate);
        if (IsSmi(*truncated)) return truncated;
      } else if (IsHeapNumber(*value)) {
        Handle<Object> truncated = CanonicalizeHeapNumber(value, isolate);
        if (IsSmi(*truncated)) return truncated;
      }
      *error_message =
          "i31ref object must be null (if nullable) or a Number that fits "
          "in i31ref range";
      return {};
    }
    case HeapType::kString:
      if (IsString(*value)) return value;
      *error_message = "wrong type (expected a string)";
      return {};
    case HeapType::kStringViewWtf8:
      *error_message = "stringview_wtf8 has no JS representation";
      return {};
    case HeapType::kStringViewWtf16:
      *error_message = "stringview_wtf16 has no JS representation";
      return {};
    case HeapType::kStringViewIter:
      *error_message = "stringview_iter has no JS representation";
      return {};
    case HeapType::kNoFunc:
    case HeapType::kNoExtern:
    case HeapType::kNoExn:
    case HeapType::kNone: {
      *error_message = "only null allowed for null types";
      return {};
    }
    default: {
      DCHECK(expected.has_index());
      CanonicalTypeIndex canonical_index = expected.ref_index();
      auto type_canonicalizer = GetWasmEngine()->type_canonicalizer();

      if (WasmExportedFunction::IsWasmExportedFunction(*value)) {
        Tagged<WasmExportedFunction> function =
            Cast<WasmExportedFunction>(*value);
        CanonicalTypeIndex real_type_index =
            function->shared()->wasm_exported_function_data()->sig_index();
        if (!type_canonicalizer->IsCanonicalSubtype(real_type_index,
                                                    canonical_index)) {
          *error_message =
              "assigned exported function has to be a subtype of the "
              "expected type";
          return {};
        }
        return handle(Cast<WasmExternalFunction>(*value)->func_ref(), isolate);
      } else if (WasmJSFunction::IsWasmJSFunction(*value)) {
        if (!Cast<WasmJSFunction>(*value)
                 ->shared()
                 ->wasm_js_function_data()
                 ->MatchesSignature(canonical_index)) {
          *error_message =
              "assigned WebAssembly.Function has to be a subtype of the "
              "expected type";
          return {};
        }
        return handle(Cast<WasmExternalFunction>(*value)->func_ref(), isolate);
      } else if (WasmCapiFunction::IsWasmCapiFunction(*value)) {
        if (!Cast<WasmCapiFunction>(*value)->MatchesSignature(
                canonical_index)) {
          *error_message =
              "assigned C API function has to be a subtype of the expected "
              "type";
          return {};
        }
        return handle(Cast<WasmExternalFunction>(*value)->func_ref(), isolate);
      } else if (IsWasmStruct(*value) || IsWasmArray(*value)) {
        auto wasm_obj = Cast<WasmObject>(value);
        Tagged<WasmTypeInfo> type_info = wasm_obj->map()->wasm_type_info();
        ModuleTypeIndex real_idx = type_info->type_index();
        const WasmModule* real_module =
            type_info->trusted_data(isolate)->module();
        CanonicalTypeIndex real_canonical_index =
            real_module->canonical_type_id(real_idx);
        if (!type_canonicalizer->IsCanonicalSubtype(real_canonical_index,
                                                    canonical_index)) {
          *error_message = "object is not a subtype of expected type";
          return {};
        }
        return value;
      } else {
        *error_message = "JS object does not match expected wasm type";
        return {};
      }
    }
  }
}

// Utility which canonicalizes {expected} in addition.
MaybeHandle<Object> JSToWasmObject(Isolate* isolate, const WasmModule* module,
                                   Handle<Object> value, ValueType expected,
                                   const char** error_message) {
  CanonicalValueType canonical;
  if (expected.has_index()) {
    CanonicalTypeIndex index = module->canonical_type_id(expected.ref_index());
    canonical = CanonicalValueType::FromIndex(expected.kind(), index);
  } else {
    canonical = CanonicalValueType{expected};
  }
  return JSToWasmObject(isolate, value, canonical, error_message);
}

Handle<Object> WasmToJSObject(Isolate* isolate, Handle<Object> value) {
  if (IsWasmNull(*value)) {
    return isolate->factory()->null_value();
  } else if (IsWasmFuncRef(*value)) {
    return i::WasmInternalFunction::GetOrCreateExternal(
        i::handle(i::Cast<i::WasmFuncRef>(*value)->internal(isolate), isolate));
  } else {
    return value;
  }
}

}  // namespace wasm

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"
#undef TRACE_IFT

"""


```