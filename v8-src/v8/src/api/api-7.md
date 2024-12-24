Response: The user wants a summary of the C++ source code file `v8/src/api/api.cc`. I need to identify the main functionalities implemented in this file. The prompt also asks to illustrate the connection to JavaScript with examples if applicable. Since this is part 8 of 8, it likely contains miscellaneous API functionalities not covered in the previous parts.

Looking at the code, the main features seem to be:

1. **Code Event Handling:**  The `CodeEvent` and `CodeEventHandler` classes suggest functionality for tracking and handling events related to code execution within V8.
2. **Heap Snapshotting and Profiling:**  The `HeapGraphEdge`, `HeapGraphNode`, `HeapSnapshot`, and `HeapProfiler` classes indicate features for taking snapshots of the JavaScript heap and analyzing its structure.
3. **Embedder Graph:** The `EmbedderGraph` class and related methods in `HeapProfiler` suggest functionality for integrating V8's heap profiling with the embedder's (the application using V8) own object graph.
4. **C++ Function Interoperability:** The `CFunction` and `CFunctionInfo` classes likely deal with the mechanism for calling C++ functions from JavaScript.
5. **Handle Scopes:** The `HandleScopeImplementer` class is core to V8's memory management, controlling the lifetime of `Local` handles.
6. **Callback Invocation:** Functions like `InvokeAccessorGetterCallback`, `InvokeFunctionCallbackGeneric`, and `InvokeFunctionCallbackOptimized` are responsible for dispatching calls from JavaScript to C++ callbacks.
7. **Finalization Registry:**  The function `InvokeFinalizationRegistryCleanupFromTask` suggests support for JavaScript's FinalizationRegistry API.
8. **Type Conversion:**  Template functions like `ConvertDouble` handle the conversion of JavaScript numbers to C++ types.
9. **Callback Info Validation:** Template functions like `ValidateFunctionCallbackInfo` and `ValidatePropertyCallbackInfo` perform checks on the arguments passed to C++ callbacks.
10. **External Memory Accounting:** The `ExternalMemoryAccounterBase` class manages the accounting of memory allocated by the embedder that is reachable from V8.
11. **Array to C++ Buffer Copying:** Template functions like `TryToCopyAndConvertArrayToCppBuffer` provide utilities for efficiently transferring data from JavaScript arrays to C++ buffers.
12. **Wasm Streaming (Conditional):** The presence of the `WasmStreaming` class (although its implementation is empty when WebAssembly is disabled) indicates support for streaming compilation of WebAssembly modules.

Now, let's try to create JavaScript examples for some of these.
This C++ source code file, `api.cc`, which is the 8th and final part, primarily focuses on providing **advanced and less frequently used features of the V8 JavaScript engine's API**. It deals with functionalities that allow for deeper introspection, interaction with the engine's internals, and integration with external C++ code.

Here's a breakdown of its main functional areas:

**1. Code Event Handling:**

*   Provides mechanisms to track and categorize different types of code execution events within V8.
*   Allows embedders (applications using V8) to register listeners to be notified of these events.
*   This is useful for debugging, profiling, and understanding the runtime behavior of JavaScript code.

```javascript
// Example of how code events might be conceptually used (not a direct V8 API):
// Imagine an external profiler using these events
function someFunction() {
  console.log("Inside someFunction");
}

// The profiler could hook into "CodeEventType.kJavaScriptCallType"
// when someFunction is called.
someFunction();
```

**2. Heap Snapshot and Profiling:**

*   Offers detailed access to the V8 heap, allowing the creation and inspection of heap snapshots.
*   Provides ways to traverse the object graph within the heap, examining nodes (objects) and edges (references between objects).
*   This is crucial for memory leak detection, performance analysis, and understanding object relationships in JavaScript applications.

```javascript
// Example of taking a heap snapshot (using the 'v8-profiler' npm package, which uses V8's API):
const v8Profiler = require('v8-profiler-next');
const fs = require('fs');

function allocateMemory() {
  global.myArray = Array(1000000).fill({});
}

allocateMemory();

const snapshot1 = v8Profiler.takeSnapshot();

// ... some more code execution ...

const snapshot2 = v8Profiler.takeSnapshot();

snapshot2.compare(snapshot1).then(changes => {
  fs.writeFileSync('heapdiff.json', JSON.stringify(changes, null, 2));
});
```

**3. Interaction with C++ Functions:**

*   Includes structures (`CFunction`, `CFunctionInfo`) that define how C++ functions can be exposed and called from JavaScript.
*   Handles the marshaling of arguments and return values between JavaScript and C++.
*   This is the foundation for creating native extensions and binding C++ libraries to JavaScript.

```javascript
// Hypothetical example (simplified, actual API is more involved):
// Assume a C++ function 'add(int a, int b)' is exposed to JavaScript.

// Call the C++ function from JavaScript
const result = add(5, 3);
console.log(result); // Output: 8
```

**4. Handle Scopes and Memory Management:**

*   Deals with the internal mechanisms (`HandleScopeImplementer`) for managing the lifetime of `Local` handles, which are used to represent JavaScript objects in C++.
*   While not directly exposed to JavaScript developers, it's fundamental to V8's memory management and how C++ code interacts with JavaScript objects safely.

**5. Callback Invocation:**

*   Contains functions (`InvokeAccessorGetterCallback`, `InvokeFunctionCallbackGeneric`, etc.) that are responsible for calling JavaScript functions from C++ (callbacks).
*   Handles the setup of the execution environment and error handling when invoking JavaScript code from native code.

```javascript
// Example where C++ might invoke a JavaScript callback:
// Imagine a C++ API that takes a JavaScript function as an argument
function myCallback(data) {
  console.log("Callback received data:", data);
}

// The C++ code would internally use functions from api.cc to invoke myCallback.
// (This is not a directly callable V8 API from JS)
```

**6. Finalization Registry Support:**

*   Includes functions related to the implementation of JavaScript's `FinalizationRegistry` API.
*   This API allows you to register callbacks that are executed when an object is garbage collected.

```javascript
let registry = new FinalizationRegistry(heldValue => {
  console.log("Object was garbage collected, held value:", heldValue);
});

let obj = {};
registry.register(obj, "some information");

// When 'obj' is no longer reachable and garbage collected, the callback will be invoked.
```

**7. Type Conversion and Validation:**

*   Provides utility functions for converting between JavaScript data types and C++ data types.
*   Includes validation routines to ensure the integrity of data passed between JavaScript and C++.

```javascript
// Example of implicit type conversion when calling a C++ function:
// If a C++ function expects an integer and you pass a floating-point number,
// V8's conversion mechanisms (potentially involving code in api.cc) will handle it.
// (This is generally handled implicitly, not a direct API call)
```

**8. External Memory Accounting:**

*   Allows embedders to inform V8 about memory allocated outside of V8's heap that is being used by JavaScript objects (e.g., buffers).
*   This helps V8's garbage collector make more informed decisions about memory pressure.

```javascript
// Example of using ArrayBuffer (backed by external memory):
let buffer = new ArrayBuffer(1024);
let uint8Array = new Uint8Array(buffer);

// V8's external memory accounting (handled in C++) keeps track of the memory used by 'buffer'.
```

**In summary, `v8/src/api/api.cc` (part 8) contains the plumbing and infrastructure for some of the more advanced and specialized interactions between JavaScript and the underlying V8 engine, particularly focusing on heap inspection, native code integration, and memory management.** It enables powerful features for profiling, debugging, and extending the capabilities of JavaScript environments.

Prompt: 
```
这是目录为v8/src/api/api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第8部分，共8部分，请归纳一下它的功能

"""
reinterpret_cast<i::CodeEvent*>(this)->previous_code_start_address;
}

const char* CodeEvent::GetCodeEventTypeName(CodeEventType code_event_type) {
  switch (code_event_type) {
    case kUnknownType:
      return "Unknown";
#define V(Name)       \
  case k##Name##Type: \
    return #Name;
      CODE_EVENTS_LIST(V)
#undef V
  }
  // The execution should never pass here
  UNREACHABLE();
}

CodeEventHandler::CodeEventHandler(Isolate* v8_isolate) {
  internal_listener_ = new i::ExternalLogEventListener(
      reinterpret_cast<i::Isolate*>(v8_isolate));
}

CodeEventHandler::~CodeEventHandler() {
  delete reinterpret_cast<i::ExternalLogEventListener*>(internal_listener_);
}

void CodeEventHandler::Enable() {
  reinterpret_cast<i::ExternalLogEventListener*>(internal_listener_)
      ->StartListening(this);
}

void CodeEventHandler::Disable() {
  reinterpret_cast<i::ExternalLogEventListener*>(internal_listener_)
      ->StopListening();
}

static i::HeapGraphEdge* ToInternal(const HeapGraphEdge* edge) {
  return const_cast<i::HeapGraphEdge*>(
      reinterpret_cast<const i::HeapGraphEdge*>(edge));
}

HeapGraphEdge::Type HeapGraphEdge::GetType() const {
  return static_cast<HeapGraphEdge::Type>(ToInternal(this)->type());
}

Local<Value> HeapGraphEdge::GetName() const {
  i::HeapGraphEdge* edge = ToInternal(this);
  i::Isolate* i_isolate = edge->isolate();
  switch (edge->type()) {
    case i::HeapGraphEdge::kContextVariable:
    case i::HeapGraphEdge::kInternal:
    case i::HeapGraphEdge::kProperty:
    case i::HeapGraphEdge::kShortcut:
    case i::HeapGraphEdge::kWeak:
      return ToApiHandle<String>(
          i_isolate->factory()->InternalizeUtf8String(edge->name()));
    case i::HeapGraphEdge::kElement:
    case i::HeapGraphEdge::kHidden:
      return ToApiHandle<Number>(
          i_isolate->factory()->NewNumberFromInt(edge->index()));
    default:
      UNREACHABLE();
  }
}

const HeapGraphNode* HeapGraphEdge::GetFromNode() const {
  const i::HeapEntry* from = ToInternal(this)->from();
  return reinterpret_cast<const HeapGraphNode*>(from);
}

const HeapGraphNode* HeapGraphEdge::GetToNode() const {
  const i::HeapEntry* to = ToInternal(this)->to();
  return reinterpret_cast<const HeapGraphNode*>(to);
}

static i::HeapEntry* ToInternal(const HeapGraphNode* entry) {
  return const_cast<i::HeapEntry*>(
      reinterpret_cast<const i::HeapEntry*>(entry));
}

HeapGraphNode::Type HeapGraphNode::GetType() const {
  return static_cast<HeapGraphNode::Type>(ToInternal(this)->type());
}

Local<String> HeapGraphNode::GetName() const {
  i::Isolate* i_isolate = ToInternal(this)->isolate();
  return ToApiHandle<String>(
      i_isolate->factory()->InternalizeUtf8String(ToInternal(this)->name()));
}

SnapshotObjectId HeapGraphNode::GetId() const { return ToInternal(this)->id(); }

size_t HeapGraphNode::GetShallowSize() const {
  return ToInternal(this)->self_size();
}

int HeapGraphNode::GetChildrenCount() const {
  return ToInternal(this)->children_count();
}

const HeapGraphEdge* HeapGraphNode::GetChild(int index) const {
  return reinterpret_cast<const HeapGraphEdge*>(ToInternal(this)->child(index));
}

static i::HeapSnapshot* ToInternal(const HeapSnapshot* snapshot) {
  return const_cast<i::HeapSnapshot*>(
      reinterpret_cast<const i::HeapSnapshot*>(snapshot));
}

void HeapSnapshot::Delete() {
  i::Isolate* i_isolate = ToInternal(this)->profiler()->isolate();
  if (i_isolate->heap_profiler()->GetSnapshotsCount() > 1 ||
      i_isolate->heap_profiler()->IsTakingSnapshot()) {
    ToInternal(this)->Delete();
  } else {
    // If this is the last snapshot, clean up all accessory data as well.
    i_isolate->heap_profiler()->DeleteAllSnapshots();
  }
}

const HeapGraphNode* HeapSnapshot::GetRoot() const {
  return reinterpret_cast<const HeapGraphNode*>(ToInternal(this)->root());
}

const HeapGraphNode* HeapSnapshot::GetNodeById(SnapshotObjectId id) const {
  return reinterpret_cast<const HeapGraphNode*>(
      ToInternal(this)->GetEntryById(id));
}

int HeapSnapshot::GetNodesCount() const {
  return static_cast<int>(ToInternal(this)->entries().size());
}

const HeapGraphNode* HeapSnapshot::GetNode(int index) const {
  return reinterpret_cast<const HeapGraphNode*>(
      &ToInternal(this)->entries().at(index));
}

SnapshotObjectId HeapSnapshot::GetMaxSnapshotJSObjectId() const {
  return ToInternal(this)->max_snapshot_js_object_id();
}

void HeapSnapshot::Serialize(OutputStream* stream,
                             HeapSnapshot::SerializationFormat format) const {
  Utils::ApiCheck(format == kJSON, "v8::HeapSnapshot::Serialize",
                  "Unknown serialization format");
  Utils::ApiCheck(stream->GetChunkSize() > 0, "v8::HeapSnapshot::Serialize",
                  "Invalid stream chunk size");
  i::HeapSnapshotJSONSerializer serializer(ToInternal(this));
  serializer.Serialize(stream);
}

// static
STATIC_CONST_MEMBER_DEFINITION const SnapshotObjectId
    HeapProfiler::kUnknownObjectId;

int HeapProfiler::GetSnapshotCount() {
  return reinterpret_cast<i::HeapProfiler*>(this)->GetSnapshotsCount();
}

void HeapProfiler::QueryObjects(Local<Context> v8_context,
                                QueryObjectPredicate* predicate,
                                std::vector<Global<Object>>* objects) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_context->GetIsolate());
  i::HeapProfiler* profiler = reinterpret_cast<i::HeapProfiler*>(this);
  DCHECK_EQ(isolate, profiler->isolate());
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(isolate);
  profiler->QueryObjects(Utils::OpenHandle(*v8_context), predicate, objects);
}

const HeapSnapshot* HeapProfiler::GetHeapSnapshot(int index) {
  return reinterpret_cast<const HeapSnapshot*>(
      reinterpret_cast<i::HeapProfiler*>(this)->GetSnapshot(index));
}

SnapshotObjectId HeapProfiler::GetObjectId(Local<Value> value) {
  auto obj = Utils::OpenHandle(*value);
  return reinterpret_cast<i::HeapProfiler*>(this)->GetSnapshotObjectId(obj);
}

SnapshotObjectId HeapProfiler::GetObjectId(NativeObject value) {
  return reinterpret_cast<i::HeapProfiler*>(this)->GetSnapshotObjectId(value);
}

Local<Value> HeapProfiler::FindObjectById(SnapshotObjectId id) {
  i::Handle<i::Object> obj =
      reinterpret_cast<i::HeapProfiler*>(this)->FindHeapObjectById(id);
  if (obj.is_null()) return Local<Value>();
  return Utils::ToLocal(obj);
}

void HeapProfiler::ClearObjectIds() {
  reinterpret_cast<i::HeapProfiler*>(this)->ClearHeapObjectMap();
}

const HeapSnapshot* HeapProfiler::TakeHeapSnapshot(
    const HeapSnapshotOptions& options) {
  return reinterpret_cast<const HeapSnapshot*>(
      reinterpret_cast<i::HeapProfiler*>(this)->TakeSnapshot(options));
}

const HeapSnapshot* HeapProfiler::TakeHeapSnapshot(ActivityControl* control,
                                                   ObjectNameResolver* resolver,
                                                   bool hide_internals,
                                                   bool capture_numeric_value) {
  HeapSnapshotOptions options;
  options.control = control;
  options.global_object_name_resolver = resolver;
  options.snapshot_mode = hide_internals ? HeapSnapshotMode::kRegular
                                         : HeapSnapshotMode::kExposeInternals;
  options.numerics_mode = capture_numeric_value
                              ? NumericsMode::kExposeNumericValues
                              : NumericsMode::kHideNumericValues;
  return TakeHeapSnapshot(options);
}

std::vector<v8::Local<v8::Value>> HeapProfiler::GetDetachedJSWrapperObjects() {
  return reinterpret_cast<i::HeapProfiler*>(this)
      ->GetDetachedJSWrapperObjects();
}

void HeapProfiler::StartTrackingHeapObjects(bool track_allocations) {
  reinterpret_cast<i::HeapProfiler*>(this)->StartHeapObjectsTracking(
      track_allocations);
}

void HeapProfiler::StopTrackingHeapObjects() {
  reinterpret_cast<i::HeapProfiler*>(this)->StopHeapObjectsTracking();
}

SnapshotObjectId HeapProfiler::GetHeapStats(OutputStream* stream,
                                            int64_t* timestamp_us) {
  i::HeapProfiler* heap_profiler = reinterpret_cast<i::HeapProfiler*>(this);
  return heap_profiler->PushHeapObjectsStats(stream, timestamp_us);
}

bool HeapProfiler::StartSamplingHeapProfiler(uint64_t sample_interval,
                                             int stack_depth,
                                             SamplingFlags flags) {
  return reinterpret_cast<i::HeapProfiler*>(this)->StartSamplingHeapProfiler(
      sample_interval, stack_depth, flags);
}

void HeapProfiler::StopSamplingHeapProfiler() {
  reinterpret_cast<i::HeapProfiler*>(this)->StopSamplingHeapProfiler();
}

AllocationProfile* HeapProfiler::GetAllocationProfile() {
  return reinterpret_cast<i::HeapProfiler*>(this)->GetAllocationProfile();
}

void HeapProfiler::DeleteAllHeapSnapshots() {
  reinterpret_cast<i::HeapProfiler*>(this)->DeleteAllSnapshots();
}

v8::EmbedderGraph::Node* v8::EmbedderGraph::V8Node(
    const v8::Local<v8::Data>& data) {
  CHECK(data->IsValue());
  return V8Node(data.As<v8::Value>());
}

void HeapProfiler::AddBuildEmbedderGraphCallback(
    BuildEmbedderGraphCallback callback, void* data) {
  reinterpret_cast<i::HeapProfiler*>(this)->AddBuildEmbedderGraphCallback(
      callback, data);
}

void HeapProfiler::RemoveBuildEmbedderGraphCallback(
    BuildEmbedderGraphCallback callback, void* data) {
  reinterpret_cast<i::HeapProfiler*>(this)->RemoveBuildEmbedderGraphCallback(
      callback, data);
}

void HeapProfiler::SetGetDetachednessCallback(GetDetachednessCallback callback,
                                              void* data) {
  reinterpret_cast<i::HeapProfiler*>(this)->SetGetDetachednessCallback(callback,
                                                                       data);
}

bool HeapProfiler::IsTakingSnapshot() {
  return reinterpret_cast<i::HeapProfiler*>(this)->IsTakingSnapshot();
}

const char* HeapProfiler::CopyNameForHeapSnapshot(const char* name) {
  return reinterpret_cast<i::HeapProfiler*>(this)->CopyNameForHeapSnapshot(
      name);
}

EmbedderStateScope::EmbedderStateScope(Isolate* v8_isolate,
                                       Local<v8::Context> context,
                                       EmbedderStateTag tag)
    : embedder_state_(new internal::EmbedderState(v8_isolate, context, tag)) {}

// std::unique_ptr's destructor is not compatible with Forward declared
// EmbedderState class.
// Default destructor must be defined in implementation file.
EmbedderStateScope::~EmbedderStateScope() = default;

void TracedReferenceBase::CheckValue() const {
#ifdef V8_HOST_ARCH_64_BIT
  if (IsEmpty()) return;

  CHECK_NE(internal::kGlobalHandleZapValue,
           *reinterpret_cast<uint64_t*>(slot()));
#endif  // V8_HOST_ARCH_64_BIT
}

CFunction::CFunction(const void* address, const CFunctionInfo* type_info)
    : address_(address), type_info_(type_info) {
  CHECK_NOT_NULL(address_);
  CHECK_NOT_NULL(type_info_);
}

CFunctionInfo::CFunctionInfo(const CTypeInfo& return_info,
                             unsigned int arg_count, const CTypeInfo* arg_info,
                             Int64Representation repr)
    : return_info_(return_info),
      repr_(repr),
      arg_count_(arg_count),
      arg_info_(arg_info) {
  DCHECK(repr == Int64Representation::kNumber ||
         repr == Int64Representation::kBigInt);
  if (arg_count_ > 0) {
    for (unsigned int i = 0; i < arg_count_ - 1; ++i) {
      DCHECK(arg_info_[i].GetType() != CTypeInfo::kCallbackOptionsType);
    }
  }
}

const CTypeInfo& CFunctionInfo::ArgumentInfo(unsigned int index) const {
  DCHECK_LT(index, ArgumentCount());
  return arg_info_[index];
}

namespace api_internal {
V8_EXPORT v8::Local<v8::Value> GetFunctionTemplateData(
    v8::Isolate* isolate, v8::Local<v8::Data> raw_target) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::DirectHandle<i::Object> target = Utils::OpenDirectHandle(*raw_target);
  if (i::IsFunctionTemplateInfo(*target)) {
    i::Handle<i::Object> data(
        i::Cast<i::FunctionTemplateInfo>(*target)->callback_data(kAcquireLoad),
        i_isolate);
    return Utils::ToLocal(data);

  } else if (i::IsJSFunction(*target)) {
    i::DirectHandle<i::JSFunction> target_func = i::Cast<i::JSFunction>(target);
    if (target_func->shared()->IsApiFunction()) {
      i::Handle<i::Object> data(
          target_func->shared()->api_func_data()->callback_data(kAcquireLoad),
          i_isolate);
      return Utils::ToLocal(data);
    }
  }
  Utils::ApiCheck(false, "api_internal::GetFunctionTemplateData",
                  "Target function is not an Api function");
  UNREACHABLE();
}
}  // namespace api_internal

void FastApiTypedArrayBase::ValidateIndex(size_t index) const {
  DCHECK_LT(index, length_);
}

RegisterState::RegisterState()
    : pc(nullptr), sp(nullptr), fp(nullptr), lr(nullptr) {}
RegisterState::~RegisterState() = default;

RegisterState::RegisterState(const RegisterState& other) { *this = other; }

RegisterState& RegisterState::operator=(const RegisterState& other) {
  if (&other != this) {
    pc = other.pc;
    sp = other.sp;
    fp = other.fp;
    lr = other.lr;
    if (other.callee_saved) {
      // Make a deep copy if {other.callee_saved} is non-null.
      callee_saved =
          std::make_unique<CalleeSavedRegisters>(*(other.callee_saved));
    } else {
      // Otherwise, set {callee_saved} to null to match {other}.
      callee_saved.reset();
    }
  }
  return *this;
}

#if !V8_ENABLE_WEBASSEMBLY
// If WebAssembly is disabled, we still need to provide an implementation of the
// WasmStreaming API. Since {WasmStreaming::Unpack} will always fail, all
// methods are unreachable.

class WasmStreaming::WasmStreamingImpl {};

WasmStreaming::WasmStreaming(std::unique_ptr<WasmStreamingImpl>) {
  UNREACHABLE();
}

WasmStreaming::~WasmStreaming() = default;

void WasmStreaming::OnBytesReceived(const uint8_t* bytes, size_t size) {
  UNREACHABLE();
}

void WasmStreaming::Finish(bool can_use_compiled_module) { UNREACHABLE(); }

void WasmStreaming::Abort(MaybeLocal<Value> exception) { UNREACHABLE(); }

bool WasmStreaming::SetCompiledModuleBytes(const uint8_t* bytes, size_t size) {
  UNREACHABLE();
}

void WasmStreaming::SetMoreFunctionsCanBeSerializedCallback(
    std::function<void(CompiledWasmModule)>) {
  UNREACHABLE();
}

void WasmStreaming::SetUrl(const char* url, size_t length) { UNREACHABLE(); }

// static
std::shared_ptr<WasmStreaming> WasmStreaming::Unpack(Isolate* v8_isolate,
                                                     Local<Value> value) {
  FATAL("WebAssembly is disabled");
}
#endif  // !V8_ENABLE_WEBASSEMBLY

namespace internal {

const size_t HandleScopeImplementer::kEnteredContextsOffset =
    offsetof(HandleScopeImplementer, entered_contexts_);

void HandleScopeImplementer::FreeThreadResources() { Free(); }

char* HandleScopeImplementer::ArchiveThread(char* storage) {
  HandleScopeData* current = isolate_->handle_scope_data();
  handle_scope_data_ = *current;
  MemCopy(storage, this, sizeof(*this));

  ResetAfterArchive();
  current->Initialize();

  return storage + ArchiveSpacePerThread();
}

int HandleScopeImplementer::ArchiveSpacePerThread() {
  return sizeof(HandleScopeImplementer);
}

char* HandleScopeImplementer::RestoreThread(char* storage) {
  MemCopy(this, storage, sizeof(*this));
  *isolate_->handle_scope_data() = handle_scope_data_;
  return storage + ArchiveSpacePerThread();
}

void HandleScopeImplementer::IterateThis(RootVisitor* v) {
#ifdef DEBUG
  bool found_block_before_persistent = false;
#endif
  // Iterate over all handles in the blocks except for the last.
  for (int i = static_cast<int>(blocks()->size()) - 2; i >= 0; --i) {
    Address* block = blocks()->at(i);
    // Cast possibly-unrelated pointers to plain Address before comparing them
    // to avoid undefined behavior.
    if (HasPersistentScope() &&
        (reinterpret_cast<Address>(
             last_handle_before_persistent_block_.value()) <=
         reinterpret_cast<Address>(&block[kHandleBlockSize])) &&
        (reinterpret_cast<Address>(
             last_handle_before_persistent_block_.value()) >=
         reinterpret_cast<Address>(block))) {
      v->VisitRootPointers(
          Root::kHandleScope, nullptr, FullObjectSlot(block),
          FullObjectSlot(last_handle_before_persistent_block_.value()));
      DCHECK(!found_block_before_persistent);
#ifdef DEBUG
      found_block_before_persistent = true;
#endif
    } else {
      v->VisitRootPointers(Root::kHandleScope, nullptr, FullObjectSlot(block),
                           FullObjectSlot(&block[kHandleBlockSize]));
    }
  }

  DCHECK_EQ(HasPersistentScope() &&
                last_handle_before_persistent_block_.value() != nullptr,
            found_block_before_persistent);

  // Iterate over live handles in the last block (if any).
  if (!blocks()->empty()) {
    v->VisitRootPointers(Root::kHandleScope, nullptr,
                         FullObjectSlot(blocks()->back()),
                         FullObjectSlot(handle_scope_data_.next));
  }

  saved_contexts_.shrink_to_fit();
  if (!saved_contexts_.empty()) {
    FullObjectSlot start(&saved_contexts_.front());
    v->VisitRootPointers(Root::kHandleScope, nullptr, start,
                         start + static_cast<int>(saved_contexts_.size()));
  }
  entered_contexts_.shrink_to_fit();
  if (!entered_contexts_.empty()) {
    FullObjectSlot start(&entered_contexts_.front());
    v->VisitRootPointers(Root::kHandleScope, nullptr, start,
                         start + static_cast<int>(entered_contexts_.size()));
  }
}

void HandleScopeImplementer::Iterate(RootVisitor* v) {
  HandleScopeData* current = isolate_->handle_scope_data();
  handle_scope_data_ = *current;
  IterateThis(v);
}

char* HandleScopeImplementer::Iterate(RootVisitor* v, char* storage) {
  HandleScopeImplementer* scope_implementer =
      reinterpret_cast<HandleScopeImplementer*>(storage);
  scope_implementer->IterateThis(v);
  return storage + ArchiveSpacePerThread();
}

std::unique_ptr<PersistentHandles> HandleScopeImplementer::DetachPersistent(
    Address* first_block) {
  std::unique_ptr<PersistentHandles> ph(new PersistentHandles(isolate()));
  DCHECK(HasPersistentScope());
  DCHECK_NOT_NULL(first_block);

  Address* block_start;
  do {
    block_start = blocks_.back();
    ph->blocks_.push_back(blocks_.back());
#if DEBUG
    ph->ordered_blocks_.insert(blocks_.back());
#endif
    blocks_.pop_back();
  } while (block_start != first_block);

  // ph->blocks_ now contains the blocks installed on the HandleScope stack
  // since BeginPersistentScope was called, but in reverse order.

  // Switch first and last blocks, such that the last block is the one
  // that is potentially half full.
  DCHECK(!ph->blocks_.empty());
  std::swap(ph->blocks_.front(), ph->blocks_.back());

  ph->block_next_ = isolate()->handle_scope_data()->next;
  block_start = ph->blocks_.back();
  ph->block_limit_ = block_start + kHandleBlockSize;

  DCHECK_EQ(blocks_.empty(),
            last_handle_before_persistent_block_.value() == nullptr);
  last_handle_before_persistent_block_.reset();
  return ph;
}

void InvokeAccessorGetterCallback(
    v8::Local<v8::Name> property,
    const v8::PropertyCallbackInfo<v8::Value>& info) {
  // Leaving JavaScript.
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(i_isolate, RuntimeCallCounterId::kAccessorGetterCallback);

  v8::AccessorNameGetterCallback getter;
  {
    Address arg = i_isolate->isolate_data()->api_callback_thunk_argument();
    // Currently we don't call InterceptorInfo callbacks via CallApiGetter.
    DCHECK(IsAccessorInfo(Tagged<Object>(arg)));
    Tagged<AccessorInfo> accessor_info =
        Cast<AccessorInfo>(Tagged<Object>(arg));
    getter = reinterpret_cast<v8::AccessorNameGetterCallback>(
        accessor_info->getter(i_isolate));

    if (V8_UNLIKELY(i_isolate->should_check_side_effects())) {
      i::Handle<Object> receiver_check_unsupported;

      if (!i_isolate->debug()->PerformSideEffectCheckForAccessor(
              handle(accessor_info, i_isolate), receiver_check_unsupported,
              ACCESSOR_GETTER)) {
        return;
      }
    }
  }
  ExternalCallbackScope call_scope(i_isolate, FUNCTION_ADDR(getter),
                                   v8::ExceptionContext::kAttributeGet, &info);
  getter(property, info);
}

namespace {

inline Tagged<FunctionTemplateInfo> GetTargetFunctionTemplateInfo(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  Tagged<Object> target = FunctionCallbackArguments::GetTarget(info);
  CHECK(IsFunctionTemplateInfo(target));
  return Cast<FunctionTemplateInfo>(target);
}

inline void InvokeFunctionCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info, CallApiCallbackMode mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(i_isolate, RuntimeCallCounterId::kFunctionCallback);

  Tagged<FunctionTemplateInfo> fti = GetTargetFunctionTemplateInfo(info);
  v8::FunctionCallback callback =
      reinterpret_cast<v8::FunctionCallback>(fti->callback(i_isolate));
  switch (mode) {
    case CallApiCallbackMode::kGeneric: {
      if (V8_UNLIKELY(i_isolate->should_check_side_effects())) {
        if (!i_isolate->debug()->PerformSideEffectCheckForCallback(
                handle(fti, i_isolate))) {
          // Failed side effect check.
          return;
        }
        if (DEBUG_BOOL) {
          // Clear raw pointer to ensure it's not accidentally used after
          // potential GC in PerformSideEffectCheckForCallback.
          fti = {};
        }
      }
      break;
    }
    case CallApiCallbackMode::kOptimized:
      // CallFunction builtin should deoptimize an optimized function when
      // side effects checking is enabled, so we don't have to handle side
      // effects checking in the optimized version of the builtin.
      DCHECK(!i_isolate->should_check_side_effects());
      break;
    case CallApiCallbackMode::kOptimizedNoProfiling:
      // This mode doesn't call InvokeFunctionCallback.
      UNREACHABLE();
  }

  ExternalCallbackScope call_scope(i_isolate, FUNCTION_ADDR(callback),
                                   info.IsConstructCall()
                                       ? v8::ExceptionContext::kConstructor
                                       : v8::ExceptionContext::kOperation,
                                   &info);
  callback(info);
}
}  // namespace

void InvokeFunctionCallbackGeneric(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  InvokeFunctionCallback(info, CallApiCallbackMode::kGeneric);
}

void InvokeFunctionCallbackOptimized(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  InvokeFunctionCallback(info, CallApiCallbackMode::kOptimized);
}

void InvokeFinalizationRegistryCleanupFromTask(
    Handle<NativeContext> native_context,
    Handle<JSFinalizationRegistry> finalization_registry,
    Handle<Object> callback) {
  i::Isolate* i_isolate = finalization_registry->native_context()->GetIsolate();
  RCS_SCOPE(i_isolate,
            RuntimeCallCounterId::kFinalizationRegistryCleanupFromTask);
  // Do not use ENTER_V8 because this is always called from a running
  // FinalizationRegistryCleanupTask within V8 and we should not log it as an
  // API call. This method is implemented here to avoid duplication of the
  // exception handling and microtask running logic in CallDepthScope.
  if (i_isolate->is_execution_terminating()) return;
  Local<v8::Context> api_context = Utils::ToLocal(native_context);
  CallDepthScope<true> call_depth_scope(i_isolate, api_context);
  VMState<OTHER> state(i_isolate);
  Handle<Object> argv[] = {callback};
  USE(Execution::CallBuiltin(i_isolate,
                             i_isolate->finalization_registry_cleanup_some(),
                             finalization_registry, arraysize(argv), argv));
}

template <>
EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
int32_t ConvertDouble(double d) {
  return internal::DoubleToInt32(d);
}

template <>
EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
uint32_t ConvertDouble(double d) {
  return internal::DoubleToUint32(d);
}

template <>
EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
float ConvertDouble(double d) {
  return internal::DoubleToFloat32(d);
}

template <>
EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
double ConvertDouble(double d) {
  return d;
}

template <>
EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
int64_t ConvertDouble(double d) {
  return internal::DoubleToWebIDLInt64(d);
}

template <>
EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
uint64_t ConvertDouble(double d) {
  return internal::DoubleToWebIDLUint64(d);
}

template <>
EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
bool ConvertDouble(double d) {
  // Implements https://tc39.es/ecma262/#sec-toboolean.
  return !std::isnan(d) && d != 0;
}

// Undefine macros for jumbo build.
#undef SET_FIELD_WRAPPED
#undef NEW_STRING
#undef CALLBACK_SETTER

template <typename T>
bool ValidateFunctionCallbackInfo(const FunctionCallbackInfo<T>& info) {
  CHECK_GE(info.Length(), 0);
  // Theortically args-length is unlimited, practically we run out of stack
  // space. This should guard against accidentally used raw pointers.
  CHECK_LE(info.Length(), 0xFFFFF);
  if (info.Length() > 0) {
    CHECK(info[0]->IsValue());
    CHECK(info[info.Length() - 1]->IsValue());
  }
  auto* i_isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  CHECK_EQ(i_isolate, Isolate::Current());
  CHECK(!i_isolate->GetIncumbentContext().is_null());
  CHECK(info.This()->IsValue());
  CHECK(info.HolderSoonToBeDeprecated()->IsObject());
  CHECK(!info.Data().IsEmpty());
  CHECK(info.GetReturnValue().Get()->IsValue());
  return true;
}

template <typename T>
bool ValidatePropertyCallbackInfo(const PropertyCallbackInfo<T>& info) {
  auto* i_isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  CHECK_EQ(i_isolate, Isolate::Current());
  CHECK(info.This()->IsValue());
  CHECK(info.HolderV2()->IsObject());
  CHECK(!i::IsJSGlobalObject(*Utils::OpenDirectHandle(*info.HolderV2())));
  // Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
  // TODO(https://crbug.com/333672197): remove.
  START_ALLOW_USE_DEPRECATED()
  CHECK(info.Holder()->IsObject());
  CHECK_IMPLIES(info.Holder() != info.HolderV2(),
                i::IsJSGlobalObject(*Utils::OpenDirectHandle(*info.Holder())));
  END_ALLOW_USE_DEPRECATED()
  i::Tagged<i::Object> key = i::PropertyCallbackArguments::GetPropertyKey(info);
  CHECK(i::IsSmi(key) || i::IsName(key));
  CHECK(info.Data()->IsValue());
  USE(info.ShouldThrowOnError());
  if (!std::is_same<T, void>::value) {
    CHECK(info.GetReturnValue().Get()->IsValue());
  }
  return true;
}

template <>
bool V8_EXPORT ValidateCallbackInfo(const FunctionCallbackInfo<void>& info) {
  return ValidateFunctionCallbackInfo(info);
}

template <>
bool V8_EXPORT
ValidateCallbackInfo(const FunctionCallbackInfo<v8::Value>& info) {
  return ValidateFunctionCallbackInfo(info);
}

template <>
bool V8_EXPORT
ValidateCallbackInfo(const PropertyCallbackInfo<v8::Value>& info) {
  return ValidatePropertyCallbackInfo(info);
}

template <>
bool V8_EXPORT
ValidateCallbackInfo(const PropertyCallbackInfo<v8::Array>& info) {
  return ValidatePropertyCallbackInfo(info);
}

template <>
bool V8_EXPORT
ValidateCallbackInfo(const PropertyCallbackInfo<v8::Boolean>& info) {
  return ValidatePropertyCallbackInfo(info);
}

template <>
bool V8_EXPORT
ValidateCallbackInfo(const PropertyCallbackInfo<v8::Integer>& info) {
  return ValidatePropertyCallbackInfo(info);
}

template <>
bool V8_EXPORT ValidateCallbackInfo(const PropertyCallbackInfo<void>& info) {
  return ValidatePropertyCallbackInfo(info);
}

ExternalMemoryAccounterBase::~ExternalMemoryAccounterBase() {
#ifdef DEBUG
  DCHECK_EQ(amount_of_external_memory_, 0U);
#endif
}

ExternalMemoryAccounterBase::ExternalMemoryAccounterBase(
    ExternalMemoryAccounterBase&& other) V8_NOEXCEPT {
#if DEBUG
  amount_of_external_memory_ =
      std::exchange(other.amount_of_external_memory_, 0U);
  isolate_ = std::exchange(other.isolate_, nullptr);
#endif
}

ExternalMemoryAccounterBase& ExternalMemoryAccounterBase::operator=(
    ExternalMemoryAccounterBase&& other) V8_NOEXCEPT {
#if DEBUG
  if (this == &other) {
    return *this;
  }
  DCHECK_EQ(amount_of_external_memory_, 0U);
  amount_of_external_memory_ =
      std::exchange(other.amount_of_external_memory_, 0U);
  isolate_ = std::exchange(other.isolate_, nullptr);
#endif
  return *this;
}

void ExternalMemoryAccounterBase::Increase(Isolate* isolate, size_t size) {
#ifdef DEBUG
  DCHECK(isolate == isolate_ || isolate_ == nullptr);
  isolate_ = isolate;
  amount_of_external_memory_ += size;
#endif
  reinterpret_cast<v8::Isolate*>(isolate)
      ->AdjustAmountOfExternalAllocatedMemory(static_cast<int64_t>(size));
}

void ExternalMemoryAccounterBase::Update(Isolate* isolate, int64_t delta) {
#ifdef DEBUG
  DCHECK(isolate == isolate_ || isolate_ == nullptr);
  DCHECK_GE(static_cast<int64_t>(amount_of_external_memory_), -delta);
  isolate_ = isolate;
  amount_of_external_memory_ += delta;
#endif
  reinterpret_cast<v8::Isolate*>(isolate)
      ->AdjustAmountOfExternalAllocatedMemory(delta);
}

void ExternalMemoryAccounterBase::Decrease(Isolate* isolate, size_t size) {
  DisallowGarbageCollection no_gc;
  if (size == 0) {
    return;
  }
#ifdef DEBUG
  DCHECK_EQ(isolate, isolate_);
  DCHECK_GE(amount_of_external_memory_, size);
  amount_of_external_memory_ -= size;
#endif
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->heap()->UpdateExternalMemory(-static_cast<int64_t>(size));
}

}  // namespace internal

template <>
bool V8_EXPORT V8_WARN_UNUSED_RESULT
TryToCopyAndConvertArrayToCppBuffer<CTypeInfoBuilder<int32_t>::Build().GetId(),
                                    int32_t>(Local<Array> src, int32_t* dst,
                                             uint32_t max_length) {
  return CopyAndConvertArrayToCppBuffer<
      CTypeInfo(CTypeInfo::Type::kInt32, CTypeInfo::SequenceType::kIsSequence)
          .GetId(),
      int32_t>(src, dst, max_length);
}

template <>
bool V8_EXPORT V8_WARN_UNUSED_RESULT
TryToCopyAndConvertArrayToCppBuffer<CTypeInfoBuilder<uint32_t>::Build().GetId(),
                                    uint32_t>(Local<Array> src, uint32_t* dst,
                                              uint32_t max_length) {
  return CopyAndConvertArrayToCppBuffer<
      CTypeInfo(CTypeInfo::Type::kUint32, CTypeInfo::SequenceType::kIsSequence)
          .GetId(),
      uint32_t>(src, dst, max_length);
}

template <>
bool V8_EXPORT V8_WARN_UNUSED_RESULT
TryToCopyAndConvertArrayToCppBuffer<CTypeInfoBuilder<float>::Build().GetId(),
                                    float>(Local<Array> src, float* dst,
                                           uint32_t max_length) {
  return CopyAndConvertArrayToCppBuffer<
      CTypeInfo(CTypeInfo::Type::kFloat32, CTypeInfo::SequenceType::kIsSequence)
          .GetId(),
      float>(src, dst, max_length);
}

template <>
bool V8_EXPORT V8_WARN_UNUSED_RESULT
TryToCopyAndConvertArrayToCppBuffer<CTypeInfoBuilder<double>::Build().GetId(),
                                    double>(Local<Array> src, double* dst,
                                            uint32_t max_length) {
  return CopyAndConvertArrayToCppBuffer<
      CTypeInfo(CTypeInfo::Type::kFloat64, CTypeInfo::SequenceType::kIsSequence)
          .GetId(),
      double>(src, dst, max_length);
}

}  // namespace v8

EXPORT_CONTEXTUAL_VARIABLE(v8::internal::StackAllocatedCheck)

#include "src/api/api-macros-undef.h"

"""


```