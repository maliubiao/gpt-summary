Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/api/api.cc`. The summary should cover:

1. **General Functionality**: What does this code do?
2. **Torque Source**:  Is it a Torque file?
3. **JavaScript Relationship**: Does it interact with JavaScript, and how? Provide JavaScript examples.
4. **Code Logic Inference**:  Any clear logical flow with inputs and outputs?
5. **Common Programming Errors**:  Does it relate to typical user mistakes?
6. **Overall Summary**: A concise conclusion of its purpose.

Let's break down the code section by section and identify the key functionalities.

*   **`CodeEvent` and `CodeEventHandler`**: These seem related to tracking and logging code execution events within V8.
*   **`HeapGraphEdge` and `HeapGraphNode`**: These structures are clearly part of V8's heap snapshotting and analysis capabilities, representing the connections and objects in the heap.
*   **`HeapSnapshot`**: This class manages a snapshot of the V8 heap, providing methods to access and serialize its contents.
*   **`HeapProfiler`**: This is a central class for initiating and managing heap profiling activities like taking snapshots, querying objects, and tracking allocations.
*   **`EmbedderGraph`**:  Seems related to integrating embedder-specific objects into heap snapshots.
*   **`EmbedderStateScope`**: Likely manages the state of the embedding application within the V8 context.
*   **`TracedReferenceBase`**:  Possibly a base class for handling references that need to be tracked by the garbage collector.
*   **`CFunction` and `CFunctionInfo`**:  These appear to describe C++ functions that can be called from JavaScript.
*   **`api_internal::GetFunctionTemplateData`**:  A utility function to retrieve data associated with function templates.
*   **`FastApiTypedArrayBase`**:  A base class for optimized TypedArray implementations.
*   **`RegisterState`**:  Represents the state of CPU registers, potentially used for debugging or profiling.
*   **`WasmStreaming`**: Deals with the streaming compilation of WebAssembly modules.
*   **`HandleScopeImplementer`**: Manages the scope of V8 handles, crucial for memory management.
*   **`InvokeAccessorGetterCallback` and `InvokeFunctionCallback`**: These functions handle the invocation of JavaScript callbacks from C++.
*   **`InvokeFinalizationRegistryCleanupFromTask`**:  Specifically handles the cleanup of finalization registries.
*   **`ConvertDouble` template specializations**:  Defines how to convert doubles to other C++ types, likely used when passing data between JavaScript and C++.
*   **`ValidateFunctionCallbackInfo` and `ValidatePropertyCallbackInfo`**:  Debugging checks for API callback parameters.
*   **`ExternalMemoryAccounterBase`**: Helps track memory allocated outside the V8 heap.
*   **`TryToCopyAndConvertArrayToCppBuffer`**:  Utilities for efficiently copying data from JavaScript arrays to C++ buffers.

Now, let's address the specific questions:

*   **.tq extension**: The file ends in `.cc`, not `.tq`. So it's a standard C++ source file.
*   **JavaScript relationship**:  Many parts relate to how V8 interacts with JavaScript: calling C++ functions, handling callbacks, memory management of JavaScript objects, and profiling the heap.

Plan:

1. State the main purpose of the file: V8 API implementation.
2. Confirm it's not a Torque file.
3. Illustrate the JavaScript relationship with examples for callbacks and heap profiling.
4. Provide hypothetical input/output for a simple function like `GetNodeById`.
5. Give an example of a common user error related to handle scopes.
6. Summarize the overall functionality.
这是一个V8源代码文件 `v8/src/api/api.cc`，它主要负责实现 **V8 JavaScript 引擎的 C++ API**。这个 API 允许嵌入 V8 的应用程序（例如 Chrome 浏览器或 Node.js）与 V8 引擎进行交互，执行 JavaScript 代码，管理对象，并进行性能分析等操作。

**功能列举:**

1. **代码事件跟踪 (`CodeEvent`, `CodeEventHandler`):** 提供了跟踪 V8 引擎内部代码执行事件的机制，例如记录哪些函数被执行，执行的起始地址等。这对于性能分析和调试非常有用。
2. **堆快照 (`HeapGraphEdge`, `HeapGraphNode`, `HeapSnapshot`, `HeapProfiler`):**  包含了创建、管理和分析 V8 堆快照的功能。
    *   `HeapGraphEdge` 和 `HeapGraphNode` 表示堆图中的边和节点，描述了对象之间的引用关系。
    *   `HeapSnapshot` 代表一个完整的堆内存快照，可以用于离线分析内存泄漏和对象生命周期。
    *   `HeapProfiler` 提供了控制和获取堆快照的方法，例如 `TakeHeapSnapshot`。
3. **嵌入器集成 (`EmbedderGraph`, `EmbedderStateScope`):**  允许嵌入 V8 的应用程序将自身的数据和状态集成到 V8 的堆快照和生命周期管理中。
4. **追踪引用 (`TracedReferenceBase`):**  可能是一个基类，用于管理需要在垃圾回收期间特别处理的引用。
5. **C++ 函数绑定 (`CFunction`, `CFunctionInfo`):**  定义了如何在 JavaScript 中调用 C++ 函数，包括函数地址、参数和返回值类型等信息。
6. **函数模板数据访问 (`api_internal::GetFunctionTemplateData`):**  提供了一种方法来获取与函数模板关联的自定义数据。
7. **快速 API 类型化数组 (`FastApiTypedArrayBase`):**  可能是为了优化类型化数组在 API 边界上的处理。
8. **寄存器状态 (`RegisterState`):**  用于存储和管理 CPU 寄存器的状态，可能用于调试或性能分析。
9. **WebAssembly 流式编译 (`WasmStreaming`):**  处理 WebAssembly 模块的流式编译过程。
10. **句柄作用域管理 (`HandleScopeImplementer`):**  `HandleScope` 是 V8 API 中用于管理 JavaScript 对象句柄的关键机制，防止内存泄漏。`HandleScopeImplementer` 提供了其内部实现。
11. **回调函数调用 (`InvokeAccessorGetterCallback`, `InvokeFunctionCallback`):**  负责从 V8 引擎内部调用由用户提供的 JavaScript 回调函数。
12. **FinalizationRegistry 清理 (`InvokeFinalizationRegistryCleanupFromTask`):**  处理 `FinalizationRegistry` 对象的清理回调。
13. **类型转换 (`ConvertDouble` 模板):**  提供了一组模板函数，用于在 C++ 和 JavaScript 之间进行数据类型转换，特别是 `double` 类型到其他类型的转换。
14. **回调信息验证 (`ValidateFunctionCallbackInfo`, `ValidatePropertyCallbackInfo`):**  在调试模式下验证传递给 API 回调函数的参数是否有效。
15. **外部内存记账 (`ExternalMemoryAccounterBase`):**  用于跟踪 V8 引擎之外分配的内存，这部分内存也需要纳入 V8 的内存管理考虑。
16. **数组数据复制 (`TryToCopyAndConvertArrayToCppBuffer`):**  提供了高效地将 JavaScript 数组复制到 C++ 缓冲区的工具函数。

**关于 .tq 结尾:**

`v8/src/api/api.cc` 以 `.cc` 结尾，所以它是一个 **V8 C++ 源代码文件**，而不是 Torque 源代码文件。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的功能关系及 JavaScript 示例:**

该文件中的许多功能都直接与 JavaScript 的行为和 V8 的 API 使用相关。以下是一些示例：

1. **堆快照:**  JavaScript 代码可以通过 V8 提供的开发者工具（例如 Chrome DevTools）或 Node.js 的 `heapdump` 模块来触发堆快照的创建。`HeapProfiler` 中的方法如 `TakeHeapSnapshot` 就在幕后执行。

    ```javascript
    // Node.js 示例 (需要引入 heapdump 模块)
    const heapdump = require('heapdump');

    heapdump.writeSnapshot('snapshot.heapsnapshot');
    console.log('Heap snapshot written to snapshot.heapsnapshot');
    ```

2. **C++ 函数绑定:**  Node.js 的原生模块 (Native Addons) 允许开发者编写 C++ 代码，并通过 V8 的 API 将 C++ 函数暴露给 JavaScript 调用。 `CFunction` 和 `CFunctionInfo` 就描述了这种绑定关系。

    ```cpp
    // C++ 代码 (example_addon.cc)
    #include <v8.h>

    void MyFunction(const v8::FunctionCallbackInfo<v8::Value>& args) {
      v8::Isolate* isolate = args.GetIsolate();
      v8::Local<v8::String> result = v8::String::NewFromUtf8(isolate, "Hello from C++").ToLocalChecked();
      args.GetReturnValue().
Prompt: 
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第15部分，共15部分，请归纳一下它的功能

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