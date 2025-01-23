Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/api/api.cc`. I need to analyze the code and address the following:

1. **List the functionalities:** Describe what the code does.
2. **Torque source:** Check if the filename ends with `.tq`.
3. **JavaScript relation:** If the code interacts with JavaScript features, provide JavaScript examples.
4. **Code logic reasoning:** Identify any logical flow and provide example inputs and outputs.
5. **Common programming errors:** Point out potential mistakes developers might make when using these APIs.
6. **Summarize functionality:** Give a concise overview of the code's purpose.

**Analysis of the code:**

- The code primarily deals with the `v8::V8` and `v8::Context` classes, which are fundamental to embedding V8.
- It includes functions for initializing V8, handling WebAssembly traps, managing memory error callbacks, setting entropy sources, and disposing of V8.
- It defines structures for collecting heap and shared memory statistics.
- It provides functions for initializing ICU for internationalization support.
- There's code related to sandboxing, if enabled.
- The core of the snippet focuses on creating and managing `v8::Context` objects, including:
    - `NewContext`: Creating a new context.
    - `FromSnapshot`: Creating a context from a snapshot.
    - `NewRemoteContext`: Creating a context with access checks.
    - Security token management (`SetSecurityToken`, `UseDefaultSecurityToken`, `GetSecurityToken`).
    - Deep freezing of contexts (`DeepFreeze`).
    - Getting the associated `v8::Isolate` and `v8::MicrotaskQueue`.
    - Setting the microtask queue.
    - Accessing the global object (`Global`).
    - Detaching the global object (`DetachGlobal`).
    - Getting the extras binding object (`GetExtrasBindingObject`).
    - Controlling code generation from strings (`AllowCodeGenerationFromStrings`, `IsCodeGenerationFromStringsAllowed`, `SetErrorMessageForCodeGenerationFromStrings`).
    - Setting an error message for WebAssembly code generation (`SetErrorMessageForWasmCodeGeneration`).
    - Setting a callback to abort script execution (`SetAbortScriptExecution`).
    - Setting promise hooks (`SetPromiseHooks`).

**Plan:**

1. State the primary focus of the code: initialization and context management.
2. Confirm that the file is not a Torque file.
3. Provide JavaScript examples for context creation, global object access, and security token manipulation.
4. Explain the logic behind context creation and deep freezing with hypothetical scenarios.
5. Highlight common errors like using a detached context or setting microtask queues incorrectly.
6. Summarize the code's role in the V8 embedding API.
```cpp
cks = true;
#else
  const bool kV8EnableChecks = false;
#endif
  if (kEmbedderEnableChecks != kV8EnableChecks) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "V8_ENABLE_CHECKS is %s while on V8 side it's %s.",
        kEmbedderEnableChecks ? "ENABLED" : "DISABLED",
        kV8EnableChecks ? "ENABLED" : "DISABLED");
  }

  i::V8::Initialize();
  return true;
}

#if V8_OS_LINUX || V8_OS_DARWIN
bool TryHandleWebAssemblyTrapPosix(int sig_code, siginfo_t* info,
                                   void* context) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  return i::trap_handler::TryHandleSignal(sig_code, info, context);
#else
  return false;
#endif
}
#endif

#if V8_OS_WIN
bool TryHandleWebAssemblyTrapWindows(EXCEPTION_POINTERS* exception) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  return i::trap_handler::TryHandleWasmTrap(exception);
#else
  return false;
#endif
}
#endif

bool V8::EnableWebAssemblyTrapHandler(bool use_v8_signal_handler) {
#if V8_ENABLE_WEBASSEMBLY
  return v8::internal::trap_handler::EnableTrapHandler(use_v8_signal_handler);
#else
  return false;
#endif
}

#if defined(V8_OS_WIN)
void V8::SetUnhandledExceptionCallback(
    UnhandledExceptionCallback unhandled_exception_callback) {
#if defined(V8_OS_WIN64)
  v8::internal::win64_unwindinfo::SetUnhandledExceptionCallback(
      unhandled_exception_callback);
#else
  // Not implemented, port needed.
#endif  // V8_OS_WIN64
}
#endif  // V8_OS_WIN

void v8::V8::SetFatalMemoryErrorCallback(
    v8::OOMErrorCallback oom_error_callback) {
  g_oom_error_callback = oom_error_callback;
}

void v8::V8::SetEntropySource(EntropySource entropy_source) {
  base::RandomNumberGenerator::SetEntropySource(entropy_source);
}

void v8::V8::SetReturnAddressLocationResolver(
    ReturnAddressLocationResolver return_address_resolver) {
  i::StackFrame::SetReturnAddressLocationResolver(return_address_resolver);
}

bool v8::V8::Dispose() {
  i::V8::Dispose();
  return true;
}

SharedMemoryStatistics::SharedMemoryStatistics()
    : read_only_space_size_(0),
      read_only_space_used_size_(0),
      read_only_space_physical_size_(0) {}

HeapStatistics::HeapStatistics()
    : total_heap_size_(0),
      total_heap_size_executable_(0),
      total_physical_size_(0),
      total_available_size_(0),
      used_heap_size_(0),
      heap_size_limit_(0),
      malloced_memory_(0),
      external_memory_(0),
      peak_malloced_memory_(0),
      does_zap_garbage_(false),
      number_of_native_contexts_(0),
      number_of_detached_contexts_(0) {}

HeapSpaceStatistics::HeapSpaceStatistics()
    : space_name_(nullptr),
      space_size_(0),
      space_used_size_(0),
      space_available_size_(0),
      physical_space_size_(0) {}

HeapObjectStatistics::HeapObjectStatistics()
    : object_type_(nullptr),
      object_sub_type_(nullptr),
      object_count_(0),
      object_size_(0) {}

HeapCodeStatistics::HeapCodeStatistics()
    : code_and_metadata_size_(0),
      bytecode_and_metadata_size_(0),
      external_script_source_size_(0),
      cpu_profiler_metadata_size_(0) {}

bool v8::V8::InitializeICU(const char* icu_data_file) {
  return i::InitializeICU(icu_data_file);
}

bool v8::V8::InitializeICUDefaultLocation(const char* exec_path,
                                          const char* icu_data_file) {
  return i::InitializeICUDefaultLocation(exec_path, icu_data_file);
}

void v8::V8::InitializeExternalStartupData(const char* directory_path) {
  i::InitializeExternalStartupData(directory_path);
}

// static
void v8::V8::InitializeExternalStartupDataFromFile(const char* snapshot_blob) {
  i::InitializeExternalStartupDataFromFile(snapshot_blob);
}

const char* v8::V8::GetVersion() { return i::Version::GetVersion(); }

#ifdef V8_ENABLE_SANDBOX
VirtualAddressSpace* v8::V8::GetSandboxAddressSpace() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxAddressSpace",
                  "The sandbox must be initialized first");
  return i::GetProcessWideSandbox()->address_space();
}

size_t v8::V8::GetSandboxSizeInBytes() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxSizeInBytes",
                  "The sandbox must be initialized first.");
  return i::GetProcessWideSandbox()->size();
}

size_t v8::V8::GetSandboxReservationSizeInBytes() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxReservationSizeInBytes",
                  "The sandbox must be initialized first");
  return i::GetProcessWideSandbox()->reservation_size();
}

bool v8::V8::IsSandboxConfiguredSecurely() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::IsSandoxConfiguredSecurely",
                  "The sandbox must be initialized first");
  // The sandbox is configured insecurely if either
  // * It is only partially reserved since in that case unrelated memory
  //   mappings may end up inside the sandbox address space where they could be
  //   corrupted by an attacker, or
  // * The first four GB of the address space were not reserved since in that
  //   case, Smi<->HeapObject confusions (treating a 32-bit Smi as a pointer)
  //   can also cause memory accesses to unrelated mappings.
  auto sandbox = i::GetProcessWideSandbox();
  return !sandbox->is_partially_reserved() &&
         sandbox->smi_address_range_is_inaccessible();
}
#endif  // V8_ENABLE_SANDBOX

void V8::GetSharedMemoryStatistics(SharedMemoryStatistics* statistics) {
  i::ReadOnlyHeap::PopulateReadOnlySpaceStatistics(statistics);
}

template <typename ObjectType>
struct InvokeBootstrapper;

template <>
struct InvokeBootstrapper<i::NativeContext> {
  i::DirectHandle<i::NativeContext> Invoke(
      i::Isolate* i_isolate,
      i::MaybeHandle<i::JSGlobalProxy> maybe_global_proxy,
      v8::Local<v8::ObjectTemplate> global_proxy_template,
      v8::ExtensionConfiguration* extensions, size_t context_snapshot_index,
      i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
      v8::MicrotaskQueue* microtask_queue) {
    return i_isolate->bootstrapper()->CreateEnvironment(
        maybe_global_proxy, global_proxy_template, extensions,
        context_snapshot_index, embedder_fields_deserializer, microtask_queue);
  }
};

template <>
struct InvokeBootstrapper<i::JSGlobalProxy> {
  i::DirectHandle<i::JSGlobalProxy> Invoke(
      i::Isolate* i_isolate,
      i::MaybeHandle<i::JSGlobalProxy> maybe_global_proxy,
      v8::Local<v8::ObjectTemplate> global_proxy_template,
      v8::ExtensionConfiguration* extensions, size_t context_snapshot_index,
      i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
      v8::MicrotaskQueue* microtask_queue) {
    USE(extensions);
    USE(context_snapshot_index);
    return i_isolate->bootstrapper()->NewRemoteContext(maybe_global_proxy,
                                                       global_proxy_template);
  }
};

template <typename ObjectType>
static i::DirectHandle<ObjectType> CreateEnvironment(
    i::Isolate* i_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> maybe_global_template,
    v8::MaybeLocal<Value> maybe_global_proxy, size_t context_snapshot_index,
    i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue) {
  i::DirectHandle<ObjectType> result;

  {
    ENTER_V8_FOR_NEW_CONTEXT(i_isolate);
    v8::Local<ObjectTemplate> proxy_template;
    i::Handle<i::FunctionTemplateInfo> proxy_constructor;
    i::Handle<i::FunctionTemplateInfo> global_constructor;
    i::DirectHandle<i::UnionOf<i::Undefined, i::InterceptorInfo>>
        named_interceptor(i_isolate->factory()->undefined_value());
    i::DirectHandle<i::UnionOf<i::Undefined, i::InterceptorInfo>>
        indexed_interceptor(i_isolate->factory()->undefined_value());

    if (!maybe_global_template.IsEmpty()) {
      v8::Local<v8::ObjectTemplate> global_template =
          maybe_global_template.ToLocalChecked();
      // Make sure that the global_template has a constructor.
      global_constructor = EnsureConstructor(i_isolate, *global_template);

      // Create a fresh template for the global proxy object.
      proxy_template =
          ObjectTemplate::New(reinterpret_cast<v8::Isolate*>(i_isolate));
      proxy_constructor = EnsureConstructor(i_isolate, *proxy_template);

      // Set the global template to be the prototype template of
      // global proxy template.
      i::FunctionTemplateInfo::SetPrototypeTemplate(
          i_isolate, proxy_constructor, Utils::OpenHandle(*global_template));

      proxy_template->SetInternalFieldCount(
          global_template->InternalFieldCount());

      // Migrate security handlers from global_template to
      // proxy_template. Temporarily removing access check
      // information from the global template.
      if (!IsUndefined(global_constructor->GetAccessCheckInfo(), i_isolate)) {
        i::FunctionTemplateInfo::SetAccessCheckInfo(
            i_isolate, proxy_constructor,
            i::handle(global_constructor->GetAccessCheckInfo(), i_isolate));
        proxy_constructor->set_needs_access_check(
            global_constructor->needs_access_check());
        global_constructor->set_needs_access_check(false);
        i::FunctionTemplateInfo::SetAccessCheckInfo(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).undefined_value_handle());
      }

      // Same for other interceptors. If the global constructor has
      // interceptors, we need to replace them temporarily with noop
      // interceptors, so the map is correctly marked as having interceptors,
      // but we don't invoke any.
      if (!IsUndefined(global_constructor->GetNamedPropertyHandler(),
                       i_isolate)) {
        named_interceptor =
            handle(global_constructor->GetNamedPropertyHandler(), i_isolate);
        i::FunctionTemplateInfo::SetNamedPropertyHandler(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).noop_interceptor_info_handle());
      }
      if (!IsUndefined(global_constructor->GetIndexedPropertyHandler(),
                       i_isolate)) {
        indexed_interceptor =
            handle(global_constructor->GetIndexedPropertyHandler(), i_isolate);
        i::FunctionTemplateInfo::SetIndexedPropertyHandler(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).noop_interceptor_info_handle());
      }
    }

    i::MaybeHandle<i::JSGlobalProxy> maybe_proxy;
    if (!maybe_global_proxy.IsEmpty()) {
      maybe_proxy = i::Cast<i::JSGlobalProxy>(
          Utils::OpenHandle(*maybe_global_proxy.ToLocalChecked()));
    }
    // Create the environment.
    InvokeBootstrapper<ObjectType> invoke;
    result = invoke.Invoke(i_isolate, maybe_proxy, proxy_template, extensions,
                           context_snapshot_index, embedder_fields_deserializer,
                           microtask_queue);

    // Restore the access check info and interceptors on the global template.
    if (!maybe_global_template.IsEmpty()) {
      DCHECK(!global_constructor.is_null());
      DCHECK(!proxy_constructor.is_null());
      i::FunctionTemplateInfo::SetAccessCheckInfo(
          i_isolate, global_constructor,
          i::handle(proxy_constructor->GetAccessCheckInfo(), i_isolate));
      global_constructor->set_needs_access_check(
          proxy_constructor->needs_access_check());
      i::FunctionTemplateInfo::SetNamedPropertyHandler(
          i_isolate, global_constructor, named_interceptor);
      i::FunctionTemplateInfo::SetIndexedPropertyHandler(
          i_isolate, global_constructor, indexed_interceptor);
    }
  }
  // Leave V8.

  return result;
}

Local<Context> NewContext(
    v8::Isolate* external_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> global_template,
    v8::MaybeLocal<Value> global_object, size_t context_snapshot_index,
    i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  // TODO(jkummerow): This is for crbug.com/713699. Remove it if it doesn't
  // fail.
  // Sanity-check that the isolate is initialized and usable.
  CHECK(IsCode(i_isolate->builtins()->code(i::Builtin::kIllegal)));

  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.NewContext");
  API_RCS_SCOPE(i_isolate, Context, New);
  i::HandleScope scope(i_isolate);
  ExtensionConfiguration no_extensions;
  if (extensions == nullptr) extensions = &no_extensions;
  i::DirectHandle<i::NativeContext> env = CreateEnvironment<i::NativeContext>(
      i_isolate, extensions, global_template, global_object,
      context_snapshot_index, embedder_fields_deserializer, microtask_queue);
  if (env.is_null()) return Local<Context>();
  return Utils::ToLocal(scope.CloseAndEscape(env));
}

Local<Context> v8::Context::New(
    v8::Isolate* external_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> global_template,
    v8::MaybeLocal<Value> global_object,
    v8::DeserializeInternalFieldsCallback internal_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue,
    v8::DeserializeContextDataCallback context_callback_deserializer,
    v8::DeserializeAPIWrapperCallback api_wrapper_deserializer) {
  return NewContext(
      external_isolate, extensions, global_template, global_object, 0,
      i::DeserializeEmbedderFieldsCallback(internal_fields_deserializer,
                                           context_callback_deserializer,
                                           api_wrapper_deserializer),
      microtask_queue);
}

MaybeLocal<Context> v8::Context::FromSnapshot(
    v8::Isolate* external_isolate, size_t context_snapshot_index,
    v8::DeserializeInternalFieldsCallback internal_fields_deserializer,
    v8::ExtensionConfiguration* extensions, MaybeLocal<Value> global_object,
    v8::MicrotaskQueue* microtask_queue,
    v8::DeserializeContextDataCallback context_callback_deserializer,
    v8::DeserializeAPIWrapperCallback api_wrapper_deserializer) {
  size_t index_including_default_context = context_snapshot_index + 1;
  if (!i::Snapshot::HasContextSnapshot(
          reinterpret_cast<i::Isolate*>(external_isolate),
          index_including_default_context)) {
    return MaybeLocal<Context>();
  }
  return NewContext(
      external_isolate, extensions, MaybeLocal<ObjectTemplate>(), global_object,
      index_including_default_context,
      i::DeserializeEmbedderFieldsCallback(internal_fields_deserializer,
                                           context_callback_deserializer,
                                           api_wrapper_deserializer),
      microtask_queue);
}

MaybeLocal<Object> v8::Context::NewRemoteContext(
    v8::Isolate* external_isolate, v8::Local<ObjectTemplate> global_template,
    v8::MaybeLocal<v8::Value> global_object) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  API_RCS_SCOPE(i_isolate, Context, NewRemoteContext);
  i::HandleScope scope(i_isolate);
  i::DirectHandle<i::FunctionTemplateInfo> global_constructor =
      EnsureConstructor(i_isolate, *global_template);
  Utils::ApiCheck(global_constructor->needs_access_check(),
                  "v8::Context::NewRemoteContext",
                  "Global template needs to have access checks enabled");
  i::DirectHandle<i::AccessCheckInfo> access_check_info(
      i::Cast<i::AccessCheckInfo>(global_constructor->GetAccessCheckInfo()),
      i_isolate);
  Utils::ApiCheck(
      access_check_info->named_interceptor() != i::Tagged<i::Object>(),
      "v8::Context::NewRemoteContext",
      "Global template needs to have access check handlers");
  i::DirectHandle<i::JSObject> global_proxy =
      CreateEnvironment<i::JSGlobalProxy>(
          i_isolate, nullptr, global_template, global_object, 0,
          i::DeserializeEmbedderFieldsCallback(), nullptr);
  if (global_proxy.is_null()) {
    if (i_isolate->has_exception()) i_isolate->clear_exception();
    return MaybeLocal<Object>();
  }
  return Utils::ToLocal(scope.CloseAndEscape(global_proxy));
}

void v8::Context::SetSecurityToken(Local<Value> token) {
  auto env = Utils::OpenDirectHandle(this);
  auto token_handle = Utils::OpenDirectHandle(*token);
  env->set_security_token(*token_handle);
}

void v8::Context::UseDefaultSecurityToken() {
  auto env = Utils::OpenDirectHandle(this);
  env->set_security_token(env->global_object());
}

Local<Value> v8::Context::GetSecurityToken() {
  auto env = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();
  i::Tagged<i::Object> security_token = env->security_token();
  return Utils::ToLocal(i::direct_handle(security_token, i_isolate));
}

namespace {

bool MayContainObjectsToFreeze(i::InstanceType obj_type) {
  if (i::InstanceTypeChecker::IsString(obj_type)) return false;
  // SharedFunctionInfo is cross-context so it shouldn't be frozen.
  if (i::InstanceTypeChecker::IsSharedFunctionInfo(obj_type)) return false;
  return true;
}

bool RequiresEmbedderSupportToFreeze(i::InstanceType obj_type) {
  DCHECK(i::InstanceTypeChecker::IsJSReceiver(obj_type));

  return (i::InstanceTypeChecker::IsJSApiObject(obj_type) ||
          i::InstanceTypeChecker::IsJSExternalObject(obj_type) ||
          i::InstanceTypeChecker::IsJSAPIObjectWithEmbedderSlots(obj_type));
}

bool IsJSReceiverSafeToFreeze(i::InstanceType obj_type) {
  DCHECK(i::InstanceTypeChecker::IsJSReceiver(obj_type));

  switch (obj_type) {
    case i::JS_OBJECT_TYPE:
    case i::JS_GLOBAL_OBJECT_TYPE:
    case i::JS_GLOBAL_PROXY_TYPE:
    case i::JS_PRIMITIVE_WRAPPER_TYPE:
    case i::JS_FUNCTION_TYPE:
    /* Function types */
    case i::BIGINT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::BIGUINT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT8_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT8_CLAMPED_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT8_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::JS_ARRAY_CONSTRUCTOR_TYPE:
    case i::JS_PROMISE_CONSTRUCTOR_TYPE:
    case i::JS_REG_EXP_CONSTRUCTOR_TYPE:
    case i::JS_CLASS_CONSTRUCTOR_TYPE:
    /* Prototype Types */
    case i::JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_OBJECT_PROTOTYPE_TYPE:
    case i::JS_PROMISE_PROTOTYPE_TYPE:
    case i::JS_REG_EXP_PROTOTYPE_TYPE:
    case i::JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_SET_PROTOTYPE_TYPE:
    case i::JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_TYPED_ARRAY_PROTOTYPE_TYPE:
    /* */
    case i::JS_ARRAY_TYPE:
      return true;
#if V8_ENABLE_WEBASSEMBLY
    case i::WASM_ARRAY_TYPE:
    case i::WASM_STRUCT_TYPE:
    case i::WASM_TAG_OBJECT_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
    case i::JS_PROXY_TYPE:
      return true;
    // These types are known not to freeze.
    case i::JS_MAP_KEY_ITERATOR_TYPE:
    case i::JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case i::JS_MAP_VALUE_ITERATOR_TYPE:
    case i::JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case i::JS_SET_VALUE_ITERATOR_TYPE:
    case i::JS_GENERATOR_OBJECT_TYPE:
    case i::JS_ASYNC_FUNCTION_OBJECT_TYPE:
    case i::JS_ASYNC_GENERATOR_OBJECT_TYPE:
    case i::JS_ARRAY_ITERATOR_TYPE: {
      return false;
    }
    default:
      // TODO(behamilton): Handle any types that fall through here.
      return false;
  }
}

class ObjectVisitorDeepFreezer : i::ObjectVisitor {
 public:
  explicit ObjectVisitorDeepFreezer(i::Isolate* isolate,
                                    Context::DeepFreezeDelegate* delegate)
      : isolate_(isolate), delegate_(delegate) {}

  bool DeepFreeze(i::DirectHandle<i::Context> context) {
    bool success = VisitObject(i::Cast<i::HeapObject>(*context));
    if (success) {
      success = InstantiateAndVisitLazyAccessorPairs();
    }
    DCHECK_EQ(success, !error_.has_value());
    if (!success) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate_, NewTypeError(error_->msg_id, error_->name), false);
    }
    for (const auto& obj : objects_to_freeze_) {
      MAYBE_RETURN_ON_EXCEPTION_VALUE(
          isolate_,
          i::JSReceiver::SetIntegrityLevel(isolate_, obj, i::FROZEN,
                                           i::kThrowOnError),
          false);
    }
    return true;
  }

  void VisitPointers(i::Tagged<i::HeapObject> host, i::ObjectSlot start,
                     i::ObjectSlot end) final {
    VisitPointersImpl(start, end);
  }
  void VisitPointers(i::Tagged<i::HeapObject> host, i::MaybeObjectSlot start,
                     i::MaybeObjectSlot end) final {
    VisitPointersImpl(start, end);
  }
  void VisitMapPointer(i::Tagged<i::HeapObject> host) final {
    VisitPointer(host, host->map_slot());
  }
  void VisitInstructionStreamPointer(i::Tagged<i::Code> host,
                                     i::InstructionStreamSlot slot) final {}
  void VisitCustomWeakPointers(i::Tagged<i::HeapObject> host,
                               i::ObjectSlot start, i::ObjectSlot end) final {}

 private:
  struct ErrorInfo {
    i::MessageTemplate msg_id;
    i::Handle<i::String> name;
  };

  template <typename TSlot>
  void VisitPointersImpl(TSlot start, TSlot end) {
    for (TSlot current = start; current < end; ++current) {
      typename TSlot::TObject object = current.load(isolate_);
      i::Tagged<i::HeapObject> heap_object;
      if (object.GetHeapObjectIfStrong(&heap_object)) {
        if (!VisitObject(heap_object)) {
          return;
        }
      }
    }
  }

  bool FreezeEmbedderObjectAndVisitChildren(i::Handle<i::JSObject> obj) {
    DCHECK(delegate_);
    LocalVector<Object> children(reinterpret_cast<Isolate*>(isolate_));
    if (!delegate_->FreezeEmbedderObjectAndGetChildren(Utils::ToLocal(obj),
                                                       children)) {
      return false;
    }
    for (auto child : children) {
      if (!VisitObject(
              *Utils::OpenDirectHandle<Object, i::JSReceiver>(child))) {
        return false;
      }
    }
    return true;
  }

  bool VisitObject(i::Tagged<i::HeapObject> obj) {
    DCHECK(!obj.is_null());
    if (error_.has_value()) {
      return false;
    }

    i::DisallowGarbageCollection no_gc;
    i::InstanceType obj_type = obj->map()->instance_type();

    // Skip common types that can't contain items to freeze.
    if (!MayContainObjectsToFreeze(obj_type)) {
      return true;
    }

    if (!done_list_.insert(obj).second) {
      // If we couldn't insert (because it is already in the set) then we're
      // done.
      return true;
    }

    if (i::InstanceTypeChecker::IsAccessorPair(obj_type)) {
      // For AccessorPairs we need to ensure that the functions they point to
      // have been instantiated into actual JavaScript objects that can be
      // frozen. If they haven't then we need to save them to instantiate
      // (and recurse) before freezing.
      i::Tagged<i::AccessorPair> accessor_pair = i::Cast<i::AccessorPair>(obj);
      if (i::IsFunctionTemplateInfo(accessor_pair->getter()) ||
          IsFunctionTemplateInfo(accessor_pair->setter())) {
        i::Handle<i::AccessorPair> lazy_accessor_pair(accessor_pair, isolate_);
        lazy_accessor_pairs_to_freeze_.push_back(lazy_accessor_pair);
      }
    } else if (i::InstanceTypeChecker::IsContext(obj_type)) {
      // For contexts we need to ensure that all accessible locals are const.
      // If not they could be replaced to bypass freezing.
      i::Tagged<i::ScopeInfo> scope_info =
          i::Cast<i::Context>(obj)->scope_info();
      for (auto it : i::ScopeInfo::IterateLocalNames(scope_info, no_gc)) {
        if (!IsImmutableLexicalVariableMode(
                scope_info->ContextLocalMode(it->index()))) {
          DCHECK(!error_.has_value());
          error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeValue,
                             i::handle(it->name(), isolate_)};
          return false;
        }
      }
    } else if (i::InstanceTypeChecker::IsJSReceiver(obj_type)) {
      i::Handle<i::JSReceiver> receiver(i::Cast<i::JSReceiver>(obj), isolate_);
      if (RequiresEmbedderSupportToFreeze(obj_type)) {
        auto js_obj = i::Cast<i::JSObject>(receiver);

        // External objects don't have slots but still need to be processed by
        // the embedder.
        if (i::InstanceTypeChecker::IsJSExternalObject(obj_type) ||
            js_obj->GetEmbedderFieldCount() > 0) {
          if (!delegate_) {
            DCHECK(!error_.has_value());
            error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeObject,
                               i::handle(receiver->class_name(), isolate_)};
            return false;
          }

          // Handle embedder specific types and any v8 children it wants to
          // freeze.
          if (!FreezeEmbedderObjectAndVisitChildren(js_obj)) {
            return false;
          }
        } else {
          DCHECK_EQ(js_obj->GetEmbedderFieldCount(), 0);
        }
      } else {
        DCHECK_IMPLIES(
            i::InstanceTypeChecker::IsJSObject(obj_type),
            i::Cast<i::JSObject>(*receiver)->GetEmbedderFieldCount() == 0);
        if (!IsJSReceiverSafeToFreeze(obj_type)) {
          DCHECK(!error_.has_value());
          error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeObject,
                             i::handle(receiver->class_name(), isolate_)};
          return false;
        }
      }

      // Save this to freeze after we are done. Freezing triggers garbage
      // collection which doesn't work well with this visitor pattern, so we
      // delay it until after.
      objects_to_freeze_.push_back(receiver);

    } else {
### 提示词
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
cks = true;
#else
  const bool kV8EnableChecks = false;
#endif
  if (kEmbedderEnableChecks != kV8EnableChecks) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "V8_ENABLE_CHECKS is %s while on V8 side it's %s.",
        kEmbedderEnableChecks ? "ENABLED" : "DISABLED",
        kV8EnableChecks ? "ENABLED" : "DISABLED");
  }

  i::V8::Initialize();
  return true;
}

#if V8_OS_LINUX || V8_OS_DARWIN
bool TryHandleWebAssemblyTrapPosix(int sig_code, siginfo_t* info,
                                   void* context) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  return i::trap_handler::TryHandleSignal(sig_code, info, context);
#else
  return false;
#endif
}
#endif

#if V8_OS_WIN
bool TryHandleWebAssemblyTrapWindows(EXCEPTION_POINTERS* exception) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  return i::trap_handler::TryHandleWasmTrap(exception);
#else
  return false;
#endif
}
#endif

bool V8::EnableWebAssemblyTrapHandler(bool use_v8_signal_handler) {
#if V8_ENABLE_WEBASSEMBLY
  return v8::internal::trap_handler::EnableTrapHandler(use_v8_signal_handler);
#else
  return false;
#endif
}

#if defined(V8_OS_WIN)
void V8::SetUnhandledExceptionCallback(
    UnhandledExceptionCallback unhandled_exception_callback) {
#if defined(V8_OS_WIN64)
  v8::internal::win64_unwindinfo::SetUnhandledExceptionCallback(
      unhandled_exception_callback);
#else
  // Not implemented, port needed.
#endif  // V8_OS_WIN64
}
#endif  // V8_OS_WIN

void v8::V8::SetFatalMemoryErrorCallback(
    v8::OOMErrorCallback oom_error_callback) {
  g_oom_error_callback = oom_error_callback;
}

void v8::V8::SetEntropySource(EntropySource entropy_source) {
  base::RandomNumberGenerator::SetEntropySource(entropy_source);
}

void v8::V8::SetReturnAddressLocationResolver(
    ReturnAddressLocationResolver return_address_resolver) {
  i::StackFrame::SetReturnAddressLocationResolver(return_address_resolver);
}

bool v8::V8::Dispose() {
  i::V8::Dispose();
  return true;
}

SharedMemoryStatistics::SharedMemoryStatistics()
    : read_only_space_size_(0),
      read_only_space_used_size_(0),
      read_only_space_physical_size_(0) {}

HeapStatistics::HeapStatistics()
    : total_heap_size_(0),
      total_heap_size_executable_(0),
      total_physical_size_(0),
      total_available_size_(0),
      used_heap_size_(0),
      heap_size_limit_(0),
      malloced_memory_(0),
      external_memory_(0),
      peak_malloced_memory_(0),
      does_zap_garbage_(false),
      number_of_native_contexts_(0),
      number_of_detached_contexts_(0) {}

HeapSpaceStatistics::HeapSpaceStatistics()
    : space_name_(nullptr),
      space_size_(0),
      space_used_size_(0),
      space_available_size_(0),
      physical_space_size_(0) {}

HeapObjectStatistics::HeapObjectStatistics()
    : object_type_(nullptr),
      object_sub_type_(nullptr),
      object_count_(0),
      object_size_(0) {}

HeapCodeStatistics::HeapCodeStatistics()
    : code_and_metadata_size_(0),
      bytecode_and_metadata_size_(0),
      external_script_source_size_(0),
      cpu_profiler_metadata_size_(0) {}

bool v8::V8::InitializeICU(const char* icu_data_file) {
  return i::InitializeICU(icu_data_file);
}

bool v8::V8::InitializeICUDefaultLocation(const char* exec_path,
                                          const char* icu_data_file) {
  return i::InitializeICUDefaultLocation(exec_path, icu_data_file);
}

void v8::V8::InitializeExternalStartupData(const char* directory_path) {
  i::InitializeExternalStartupData(directory_path);
}

// static
void v8::V8::InitializeExternalStartupDataFromFile(const char* snapshot_blob) {
  i::InitializeExternalStartupDataFromFile(snapshot_blob);
}

const char* v8::V8::GetVersion() { return i::Version::GetVersion(); }

#ifdef V8_ENABLE_SANDBOX
VirtualAddressSpace* v8::V8::GetSandboxAddressSpace() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxAddressSpace",
                  "The sandbox must be initialized first");
  return i::GetProcessWideSandbox()->address_space();
}

size_t v8::V8::GetSandboxSizeInBytes() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxSizeInBytes",
                  "The sandbox must be initialized first.");
  return i::GetProcessWideSandbox()->size();
}

size_t v8::V8::GetSandboxReservationSizeInBytes() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxReservationSizeInBytes",
                  "The sandbox must be initialized first");
  return i::GetProcessWideSandbox()->reservation_size();
}

bool v8::V8::IsSandboxConfiguredSecurely() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::IsSandoxConfiguredSecurely",
                  "The sandbox must be initialized first");
  // The sandbox is configured insecurely if either
  // * It is only partially reserved since in that case unrelated memory
  //   mappings may end up inside the sandbox address space where they could be
  //   corrupted by an attacker, or
  // * The first four GB of the address space were not reserved since in that
  //   case, Smi<->HeapObject confusions (treating a 32-bit Smi as a pointer)
  //   can also cause memory accesses to unrelated mappings.
  auto sandbox = i::GetProcessWideSandbox();
  return !sandbox->is_partially_reserved() &&
         sandbox->smi_address_range_is_inaccessible();
}
#endif  // V8_ENABLE_SANDBOX

void V8::GetSharedMemoryStatistics(SharedMemoryStatistics* statistics) {
  i::ReadOnlyHeap::PopulateReadOnlySpaceStatistics(statistics);
}

template <typename ObjectType>
struct InvokeBootstrapper;

template <>
struct InvokeBootstrapper<i::NativeContext> {
  i::DirectHandle<i::NativeContext> Invoke(
      i::Isolate* i_isolate,
      i::MaybeHandle<i::JSGlobalProxy> maybe_global_proxy,
      v8::Local<v8::ObjectTemplate> global_proxy_template,
      v8::ExtensionConfiguration* extensions, size_t context_snapshot_index,
      i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
      v8::MicrotaskQueue* microtask_queue) {
    return i_isolate->bootstrapper()->CreateEnvironment(
        maybe_global_proxy, global_proxy_template, extensions,
        context_snapshot_index, embedder_fields_deserializer, microtask_queue);
  }
};

template <>
struct InvokeBootstrapper<i::JSGlobalProxy> {
  i::DirectHandle<i::JSGlobalProxy> Invoke(
      i::Isolate* i_isolate,
      i::MaybeHandle<i::JSGlobalProxy> maybe_global_proxy,
      v8::Local<v8::ObjectTemplate> global_proxy_template,
      v8::ExtensionConfiguration* extensions, size_t context_snapshot_index,
      i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
      v8::MicrotaskQueue* microtask_queue) {
    USE(extensions);
    USE(context_snapshot_index);
    return i_isolate->bootstrapper()->NewRemoteContext(maybe_global_proxy,
                                                       global_proxy_template);
  }
};

template <typename ObjectType>
static i::DirectHandle<ObjectType> CreateEnvironment(
    i::Isolate* i_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> maybe_global_template,
    v8::MaybeLocal<Value> maybe_global_proxy, size_t context_snapshot_index,
    i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue) {
  i::DirectHandle<ObjectType> result;

  {
    ENTER_V8_FOR_NEW_CONTEXT(i_isolate);
    v8::Local<ObjectTemplate> proxy_template;
    i::Handle<i::FunctionTemplateInfo> proxy_constructor;
    i::Handle<i::FunctionTemplateInfo> global_constructor;
    i::DirectHandle<i::UnionOf<i::Undefined, i::InterceptorInfo>>
        named_interceptor(i_isolate->factory()->undefined_value());
    i::DirectHandle<i::UnionOf<i::Undefined, i::InterceptorInfo>>
        indexed_interceptor(i_isolate->factory()->undefined_value());

    if (!maybe_global_template.IsEmpty()) {
      v8::Local<v8::ObjectTemplate> global_template =
          maybe_global_template.ToLocalChecked();
      // Make sure that the global_template has a constructor.
      global_constructor = EnsureConstructor(i_isolate, *global_template);

      // Create a fresh template for the global proxy object.
      proxy_template =
          ObjectTemplate::New(reinterpret_cast<v8::Isolate*>(i_isolate));
      proxy_constructor = EnsureConstructor(i_isolate, *proxy_template);

      // Set the global template to be the prototype template of
      // global proxy template.
      i::FunctionTemplateInfo::SetPrototypeTemplate(
          i_isolate, proxy_constructor, Utils::OpenHandle(*global_template));

      proxy_template->SetInternalFieldCount(
          global_template->InternalFieldCount());

      // Migrate security handlers from global_template to
      // proxy_template.  Temporarily removing access check
      // information from the global template.
      if (!IsUndefined(global_constructor->GetAccessCheckInfo(), i_isolate)) {
        i::FunctionTemplateInfo::SetAccessCheckInfo(
            i_isolate, proxy_constructor,
            i::handle(global_constructor->GetAccessCheckInfo(), i_isolate));
        proxy_constructor->set_needs_access_check(
            global_constructor->needs_access_check());
        global_constructor->set_needs_access_check(false);
        i::FunctionTemplateInfo::SetAccessCheckInfo(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).undefined_value_handle());
      }

      // Same for other interceptors. If the global constructor has
      // interceptors, we need to replace them temporarily with noop
      // interceptors, so the map is correctly marked as having interceptors,
      // but we don't invoke any.
      if (!IsUndefined(global_constructor->GetNamedPropertyHandler(),
                       i_isolate)) {
        named_interceptor =
            handle(global_constructor->GetNamedPropertyHandler(), i_isolate);
        i::FunctionTemplateInfo::SetNamedPropertyHandler(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).noop_interceptor_info_handle());
      }
      if (!IsUndefined(global_constructor->GetIndexedPropertyHandler(),
                       i_isolate)) {
        indexed_interceptor =
            handle(global_constructor->GetIndexedPropertyHandler(), i_isolate);
        i::FunctionTemplateInfo::SetIndexedPropertyHandler(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).noop_interceptor_info_handle());
      }
    }

    i::MaybeHandle<i::JSGlobalProxy> maybe_proxy;
    if (!maybe_global_proxy.IsEmpty()) {
      maybe_proxy = i::Cast<i::JSGlobalProxy>(
          Utils::OpenHandle(*maybe_global_proxy.ToLocalChecked()));
    }
    // Create the environment.
    InvokeBootstrapper<ObjectType> invoke;
    result = invoke.Invoke(i_isolate, maybe_proxy, proxy_template, extensions,
                           context_snapshot_index, embedder_fields_deserializer,
                           microtask_queue);

    // Restore the access check info and interceptors on the global template.
    if (!maybe_global_template.IsEmpty()) {
      DCHECK(!global_constructor.is_null());
      DCHECK(!proxy_constructor.is_null());
      i::FunctionTemplateInfo::SetAccessCheckInfo(
          i_isolate, global_constructor,
          i::handle(proxy_constructor->GetAccessCheckInfo(), i_isolate));
      global_constructor->set_needs_access_check(
          proxy_constructor->needs_access_check());
      i::FunctionTemplateInfo::SetNamedPropertyHandler(
          i_isolate, global_constructor, named_interceptor);
      i::FunctionTemplateInfo::SetIndexedPropertyHandler(
          i_isolate, global_constructor, indexed_interceptor);
    }
  }
  // Leave V8.

  return result;
}

Local<Context> NewContext(
    v8::Isolate* external_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> global_template,
    v8::MaybeLocal<Value> global_object, size_t context_snapshot_index,
    i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  // TODO(jkummerow): This is for crbug.com/713699. Remove it if it doesn't
  // fail.
  // Sanity-check that the isolate is initialized and usable.
  CHECK(IsCode(i_isolate->builtins()->code(i::Builtin::kIllegal)));

  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.NewContext");
  API_RCS_SCOPE(i_isolate, Context, New);
  i::HandleScope scope(i_isolate);
  ExtensionConfiguration no_extensions;
  if (extensions == nullptr) extensions = &no_extensions;
  i::DirectHandle<i::NativeContext> env = CreateEnvironment<i::NativeContext>(
      i_isolate, extensions, global_template, global_object,
      context_snapshot_index, embedder_fields_deserializer, microtask_queue);
  if (env.is_null()) return Local<Context>();
  return Utils::ToLocal(scope.CloseAndEscape(env));
}

Local<Context> v8::Context::New(
    v8::Isolate* external_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> global_template,
    v8::MaybeLocal<Value> global_object,
    v8::DeserializeInternalFieldsCallback internal_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue,
    v8::DeserializeContextDataCallback context_callback_deserializer,
    v8::DeserializeAPIWrapperCallback api_wrapper_deserializer) {
  return NewContext(
      external_isolate, extensions, global_template, global_object, 0,
      i::DeserializeEmbedderFieldsCallback(internal_fields_deserializer,
                                           context_callback_deserializer,
                                           api_wrapper_deserializer),
      microtask_queue);
}

MaybeLocal<Context> v8::Context::FromSnapshot(
    v8::Isolate* external_isolate, size_t context_snapshot_index,
    v8::DeserializeInternalFieldsCallback internal_fields_deserializer,
    v8::ExtensionConfiguration* extensions, MaybeLocal<Value> global_object,
    v8::MicrotaskQueue* microtask_queue,
    v8::DeserializeContextDataCallback context_callback_deserializer,
    v8::DeserializeAPIWrapperCallback api_wrapper_deserializer) {
  size_t index_including_default_context = context_snapshot_index + 1;
  if (!i::Snapshot::HasContextSnapshot(
          reinterpret_cast<i::Isolate*>(external_isolate),
          index_including_default_context)) {
    return MaybeLocal<Context>();
  }
  return NewContext(
      external_isolate, extensions, MaybeLocal<ObjectTemplate>(), global_object,
      index_including_default_context,
      i::DeserializeEmbedderFieldsCallback(internal_fields_deserializer,
                                           context_callback_deserializer,
                                           api_wrapper_deserializer),
      microtask_queue);
}

MaybeLocal<Object> v8::Context::NewRemoteContext(
    v8::Isolate* external_isolate, v8::Local<ObjectTemplate> global_template,
    v8::MaybeLocal<v8::Value> global_object) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  API_RCS_SCOPE(i_isolate, Context, NewRemoteContext);
  i::HandleScope scope(i_isolate);
  i::DirectHandle<i::FunctionTemplateInfo> global_constructor =
      EnsureConstructor(i_isolate, *global_template);
  Utils::ApiCheck(global_constructor->needs_access_check(),
                  "v8::Context::NewRemoteContext",
                  "Global template needs to have access checks enabled");
  i::DirectHandle<i::AccessCheckInfo> access_check_info(
      i::Cast<i::AccessCheckInfo>(global_constructor->GetAccessCheckInfo()),
      i_isolate);
  Utils::ApiCheck(
      access_check_info->named_interceptor() != i::Tagged<i::Object>(),
      "v8::Context::NewRemoteContext",
      "Global template needs to have access check handlers");
  i::DirectHandle<i::JSObject> global_proxy =
      CreateEnvironment<i::JSGlobalProxy>(
          i_isolate, nullptr, global_template, global_object, 0,
          i::DeserializeEmbedderFieldsCallback(), nullptr);
  if (global_proxy.is_null()) {
    if (i_isolate->has_exception()) i_isolate->clear_exception();
    return MaybeLocal<Object>();
  }
  return Utils::ToLocal(scope.CloseAndEscape(global_proxy));
}

void v8::Context::SetSecurityToken(Local<Value> token) {
  auto env = Utils::OpenDirectHandle(this);
  auto token_handle = Utils::OpenDirectHandle(*token);
  env->set_security_token(*token_handle);
}

void v8::Context::UseDefaultSecurityToken() {
  auto env = Utils::OpenDirectHandle(this);
  env->set_security_token(env->global_object());
}

Local<Value> v8::Context::GetSecurityToken() {
  auto env = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();
  i::Tagged<i::Object> security_token = env->security_token();
  return Utils::ToLocal(i::direct_handle(security_token, i_isolate));
}

namespace {

bool MayContainObjectsToFreeze(i::InstanceType obj_type) {
  if (i::InstanceTypeChecker::IsString(obj_type)) return false;
  // SharedFunctionInfo is cross-context so it shouldn't be frozen.
  if (i::InstanceTypeChecker::IsSharedFunctionInfo(obj_type)) return false;
  return true;
}

bool RequiresEmbedderSupportToFreeze(i::InstanceType obj_type) {
  DCHECK(i::InstanceTypeChecker::IsJSReceiver(obj_type));

  return (i::InstanceTypeChecker::IsJSApiObject(obj_type) ||
          i::InstanceTypeChecker::IsJSExternalObject(obj_type) ||
          i::InstanceTypeChecker::IsJSAPIObjectWithEmbedderSlots(obj_type));
}

bool IsJSReceiverSafeToFreeze(i::InstanceType obj_type) {
  DCHECK(i::InstanceTypeChecker::IsJSReceiver(obj_type));

  switch (obj_type) {
    case i::JS_OBJECT_TYPE:
    case i::JS_GLOBAL_OBJECT_TYPE:
    case i::JS_GLOBAL_PROXY_TYPE:
    case i::JS_PRIMITIVE_WRAPPER_TYPE:
    case i::JS_FUNCTION_TYPE:
    /* Function types */
    case i::BIGINT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::BIGUINT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT8_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT8_CLAMPED_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT8_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::JS_ARRAY_CONSTRUCTOR_TYPE:
    case i::JS_PROMISE_CONSTRUCTOR_TYPE:
    case i::JS_REG_EXP_CONSTRUCTOR_TYPE:
    case i::JS_CLASS_CONSTRUCTOR_TYPE:
    /* Prototype Types */
    case i::JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_OBJECT_PROTOTYPE_TYPE:
    case i::JS_PROMISE_PROTOTYPE_TYPE:
    case i::JS_REG_EXP_PROTOTYPE_TYPE:
    case i::JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_SET_PROTOTYPE_TYPE:
    case i::JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_TYPED_ARRAY_PROTOTYPE_TYPE:
    /* */
    case i::JS_ARRAY_TYPE:
      return true;
#if V8_ENABLE_WEBASSEMBLY
    case i::WASM_ARRAY_TYPE:
    case i::WASM_STRUCT_TYPE:
    case i::WASM_TAG_OBJECT_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
    case i::JS_PROXY_TYPE:
      return true;
    // These types are known not to freeze.
    case i::JS_MAP_KEY_ITERATOR_TYPE:
    case i::JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case i::JS_MAP_VALUE_ITERATOR_TYPE:
    case i::JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case i::JS_SET_VALUE_ITERATOR_TYPE:
    case i::JS_GENERATOR_OBJECT_TYPE:
    case i::JS_ASYNC_FUNCTION_OBJECT_TYPE:
    case i::JS_ASYNC_GENERATOR_OBJECT_TYPE:
    case i::JS_ARRAY_ITERATOR_TYPE: {
      return false;
    }
    default:
      // TODO(behamilton): Handle any types that fall through here.
      return false;
  }
}

class ObjectVisitorDeepFreezer : i::ObjectVisitor {
 public:
  explicit ObjectVisitorDeepFreezer(i::Isolate* isolate,
                                    Context::DeepFreezeDelegate* delegate)
      : isolate_(isolate), delegate_(delegate) {}

  bool DeepFreeze(i::DirectHandle<i::Context> context) {
    bool success = VisitObject(i::Cast<i::HeapObject>(*context));
    if (success) {
      success = InstantiateAndVisitLazyAccessorPairs();
    }
    DCHECK_EQ(success, !error_.has_value());
    if (!success) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate_, NewTypeError(error_->msg_id, error_->name), false);
    }
    for (const auto& obj : objects_to_freeze_) {
      MAYBE_RETURN_ON_EXCEPTION_VALUE(
          isolate_,
          i::JSReceiver::SetIntegrityLevel(isolate_, obj, i::FROZEN,
                                           i::kThrowOnError),
          false);
    }
    return true;
  }

  void VisitPointers(i::Tagged<i::HeapObject> host, i::ObjectSlot start,
                     i::ObjectSlot end) final {
    VisitPointersImpl(start, end);
  }
  void VisitPointers(i::Tagged<i::HeapObject> host, i::MaybeObjectSlot start,
                     i::MaybeObjectSlot end) final {
    VisitPointersImpl(start, end);
  }
  void VisitMapPointer(i::Tagged<i::HeapObject> host) final {
    VisitPointer(host, host->map_slot());
  }
  void VisitInstructionStreamPointer(i::Tagged<i::Code> host,
                                     i::InstructionStreamSlot slot) final {}
  void VisitCustomWeakPointers(i::Tagged<i::HeapObject> host,
                               i::ObjectSlot start, i::ObjectSlot end) final {}

 private:
  struct ErrorInfo {
    i::MessageTemplate msg_id;
    i::Handle<i::String> name;
  };

  template <typename TSlot>
  void VisitPointersImpl(TSlot start, TSlot end) {
    for (TSlot current = start; current < end; ++current) {
      typename TSlot::TObject object = current.load(isolate_);
      i::Tagged<i::HeapObject> heap_object;
      if (object.GetHeapObjectIfStrong(&heap_object)) {
        if (!VisitObject(heap_object)) {
          return;
        }
      }
    }
  }

  bool FreezeEmbedderObjectAndVisitChildren(i::Handle<i::JSObject> obj) {
    DCHECK(delegate_);
    LocalVector<Object> children(reinterpret_cast<Isolate*>(isolate_));
    if (!delegate_->FreezeEmbedderObjectAndGetChildren(Utils::ToLocal(obj),
                                                       children)) {
      return false;
    }
    for (auto child : children) {
      if (!VisitObject(
              *Utils::OpenDirectHandle<Object, i::JSReceiver>(child))) {
        return false;
      }
    }
    return true;
  }

  bool VisitObject(i::Tagged<i::HeapObject> obj) {
    DCHECK(!obj.is_null());
    if (error_.has_value()) {
      return false;
    }

    i::DisallowGarbageCollection no_gc;
    i::InstanceType obj_type = obj->map()->instance_type();

    // Skip common types that can't contain items to freeze.
    if (!MayContainObjectsToFreeze(obj_type)) {
      return true;
    }

    if (!done_list_.insert(obj).second) {
      // If we couldn't insert (because it is already in the set) then we're
      // done.
      return true;
    }

    if (i::InstanceTypeChecker::IsAccessorPair(obj_type)) {
      // For AccessorPairs we need to ensure that the functions they point to
      // have been instantiated into actual JavaScript objects that can be
      // frozen. If they haven't then we need to save them to instantiate
      // (and recurse) before freezing.
      i::Tagged<i::AccessorPair> accessor_pair = i::Cast<i::AccessorPair>(obj);
      if (i::IsFunctionTemplateInfo(accessor_pair->getter()) ||
          IsFunctionTemplateInfo(accessor_pair->setter())) {
        i::Handle<i::AccessorPair> lazy_accessor_pair(accessor_pair, isolate_);
        lazy_accessor_pairs_to_freeze_.push_back(lazy_accessor_pair);
      }
    } else if (i::InstanceTypeChecker::IsContext(obj_type)) {
      // For contexts we need to ensure that all accessible locals are const.
      // If not they could be replaced to bypass freezing.
      i::Tagged<i::ScopeInfo> scope_info =
          i::Cast<i::Context>(obj)->scope_info();
      for (auto it : i::ScopeInfo::IterateLocalNames(scope_info, no_gc)) {
        if (!IsImmutableLexicalVariableMode(
                scope_info->ContextLocalMode(it->index()))) {
          DCHECK(!error_.has_value());
          error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeValue,
                             i::handle(it->name(), isolate_)};
          return false;
        }
      }
    } else if (i::InstanceTypeChecker::IsJSReceiver(obj_type)) {
      i::Handle<i::JSReceiver> receiver(i::Cast<i::JSReceiver>(obj), isolate_);
      if (RequiresEmbedderSupportToFreeze(obj_type)) {
        auto js_obj = i::Cast<i::JSObject>(receiver);

        // External objects don't have slots but still need to be processed by
        // the embedder.
        if (i::InstanceTypeChecker::IsJSExternalObject(obj_type) ||
            js_obj->GetEmbedderFieldCount() > 0) {
          if (!delegate_) {
            DCHECK(!error_.has_value());
            error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeObject,
                               i::handle(receiver->class_name(), isolate_)};
            return false;
          }

          // Handle embedder specific types and any v8 children it wants to
          // freeze.
          if (!FreezeEmbedderObjectAndVisitChildren(js_obj)) {
            return false;
          }
        } else {
          DCHECK_EQ(js_obj->GetEmbedderFieldCount(), 0);
        }
      } else {
        DCHECK_IMPLIES(
            i::InstanceTypeChecker::IsJSObject(obj_type),
            i::Cast<i::JSObject>(*receiver)->GetEmbedderFieldCount() == 0);
        if (!IsJSReceiverSafeToFreeze(obj_type)) {
          DCHECK(!error_.has_value());
          error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeObject,
                             i::handle(receiver->class_name(), isolate_)};
          return false;
        }
      }

      // Save this to freeze after we are done. Freezing triggers garbage
      // collection which doesn't work well with this visitor pattern, so we
      // delay it until after.
      objects_to_freeze_.push_back(receiver);

    } else {
      DCHECK(!i::InstanceTypeChecker::IsAccessorPair(obj_type));
      DCHECK(!i::InstanceTypeChecker::IsContext(obj_type));
      DCHECK(!i::InstanceTypeChecker::IsJSReceiver(obj_type));
    }

    DCHECK(!error_.has_value());
    i::VisitObject(isolate_, obj, this);
    // Iterate sets error_ on failure. We should propagate errors.
    return !error_.has_value();
  }

  bool InstantiateAndVisitLazyAccessorPairs() {
    i::Handle<i::NativeContext> native_context = isolate_->native_context();

    std::vector<i::Handle<i::AccessorPair>> lazy_accessor_pairs_to_freeze;
    std::swap(lazy_accessor_pairs_to_freeze, lazy_accessor_pairs_to_freeze_);

    for (const auto& accessor_pair : lazy_accessor_pairs_to_freeze) {
      i::AccessorPair::GetComponent(isolate_, native_context, accessor_pair,
                                    i::ACCESSOR_GETTER);
      i::AccessorPair::GetComponent(isolate_, native_context, accessor_pair,
                                    i::ACCESSOR_SETTER);
      VisitObject(*accessor_pair);
    }
    // Ensure no new lazy accessor pairs were discovered.
    CHECK_EQ(lazy_accessor_pairs_to_freeze_.size(), 0);
    return true;
  }

  i::Isolate* isolate_;
  Context::DeepFreezeDelegate* delegate_;
  std::unordered_set<i::Tagged<i::Object>, i::Object::Hasher> done_list_;
  std::vector<i::Handle<i::JSReceiver>> objects_to_freeze_;
  std::vector<i::Handle<i::AccessorPair>> lazy_accessor_pairs_to_freeze_;
  std::optional<ErrorInfo> error_;
};

}  // namespace

Maybe<void> Context::DeepFreeze(DeepFreezeDelegate* delegate) {
  auto env = Utils::OpenHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();

  // TODO(behamilton): Incorporate compatibility improvements similar to NodeJS:
  // https://github.com/nodejs/node/blob/main/lib/internal/freeze_intrinsics.js
  // These need to be done before freezing.

  Local<Context> context = Utils::ToLocal(env);
  ENTER_V8_NO_SCRIPT(i_isolate, context, Context, DeepFreeze, i::HandleScope);
  ObjectVisitorDeepFreezer vfreezer(i_isolate, delegate);
  has_exception = !vfreezer.DeepFreeze(env);

  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(void);
  return JustVoid();
}

v8::Isolate* Context::GetIsolate() {
  return reinterpret_cast<Isolate*>(
      Utils::OpenDirectHandle(this)->GetIsolate());
}

v8::MicrotaskQueue* Context::GetMicrotaskQueue() {
  auto env = Utils::OpenDirectHandle(this);
  Utils::ApiCheck(i::IsNativeContext(*env), "v8::Context::GetMicrotaskQueue",
                  "Must be called on a native context");
  return env->microtask_queue();
}

void Context::SetMicrotaskQueue(v8::MicrotaskQueue* queue) {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  Utils::ApiCheck(i::IsNativeContext(*context),
                  "v8::Context::SetMicrotaskQueue",
                  "Must be called on a native context");
  i::HandleScopeImplementer* impl = i_isolate->handle_scope_implementer();
  Utils::ApiCheck(!context->microtask_queue()->IsRunningMicrotasks(),
                  "v8::Context::SetMicrotaskQueue",
                  "Must not be running microtasks");
  Utils::ApiCheck(context->microtask_queue()->GetMicrotasksScopeDepth() == 0,
                  "v8::Context::SetMicrotaskQueue",
                  "Must not have microtask scope pushed");
  Utils::ApiCheck(impl->EnteredContextCount() == 0,
                  "v8::Context::SetMicrotaskQueue()",
                  "Cannot set Microtask Queue with an entered context");
  context->set_microtask_queue(i_isolate,
                               static_cast<const i::MicrotaskQueue*>(queue));
}

v8::Local<v8::Object> Context::Global() {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  i::DirectHandle<i::JSGlobalProxy> global(context->global_proxy(), i_isolate);
  // TODO(chromium:324812): This should always return the global proxy
  // but can't presently as calls to GetPrototype will return the wrong result.
  if (global->IsDetachedFrom(context->global_object())) {
    i::DirectHandle<i::JSObject> result(context->global_object(), i_isolate);
    return Utils::ToLocal(result);
  }
  return Utils::ToLocal(i::Cast<i::JSObject>(global));
}

void Context::DetachGlobal() {
  auto context = Utils::OpenHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i_isolate->DetachGlobal(context);
}

Local<v8::Object> Context::GetExtrasBindingObject() {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  return Utils::ToLocal(
      i::direct_handle(context->extras_binding_object(), i_isolate));
}

void Context::AllowCodeGenerationFromStrings(bool allow) {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  context->set_allow_code_gen_from_strings(
      i::ReadOnlyRoots(i_isolate).boolean_value(allow));
}

bool Context::IsCodeGenerationFromStringsAllowed() const {
  auto context = Utils::OpenDirectHandle(this);
  return !IsFalse(context->allow_code_gen_from_strings(),
                  context->GetIsolate());
}

void Context::SetErrorMessageForCodeGenerationFromStrings(Local<String> error) {
  auto context = Utils::OpenDirectHandle(this);
  auto error_handle = Utils::OpenDirectHandle(*error);
  context->set_error_message_for_code_gen_from_strings(*error_handle);
}

void Context::SetErrorMessageForWasmCodeGeneration(Local<String> error) {
  auto context = Utils::OpenDirectHandle(this);
  auto error_handle = Utils::OpenDirectHandle(*error);
  context->set_error_message_for_wasm_code_gen(*error_handle);
}

void Context::SetAbortScriptExecution(
    Context::AbortScriptExecutionCallback callback) {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  if (callback == nullptr) {
    context->set_script_execution_callback(
        i::ReadOnlyRoots(i_isolate).undefined_value());
  } else {
    SET_FIELD_WRAPPED(i_isolate, context, set_script_execution_callback,
                      callback, internal::kApiAbortScriptExecutionCallbackTag);
  }
}

void v8::Context::SetPromiseHooks(Local<Function> init_hook,
                                  Local<Function> before_hook,
                                  Local<Function> after_hook,
                                  Local<Function> resolve_hook) {
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();

  auto undefined = i_isolate->f
```