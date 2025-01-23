Response: The user wants me to summarize the functionality of the C++ source code file `v8/src/execution/isolate.cc`. This is the fourth part of a five-part summary, which implies that the previous parts have already covered some aspects of the file's functionality. I should focus on the functionalities present in this specific code snippet.

The code snippet primarily deals with:
- Initialization and teardown of embedded built-in code.
- Initialization of the Isolate, including with snapshots.
- Adding crash keys for debugging.
- Managing code ranges.
- Setting up internal data structures and services like compilation cache, global handles, bootstrapper, etc.
- Handling shared heaps.
- Deserialization from snapshots.
- Entering and exiting the Isolate.
- Dumping and resetting statistics.
- Managing concurrent optimization.
- Handling regular expression code generation.
- Logging code creation.
- Managing source positions.
- Handling feedback vectors for profiling.
- Managing symbol tables.
- Implementing before and after call callbacks.
- Handling dynamic imports.
- Managing import meta objects.
- Handling shadow realms.
- Managing stack trace preparation.
- Managing externally compiled filenames.
- Setting and running atomics wait callbacks.
- Setting and running promise hooks.
- Handling asynchronous functions and promises.

If the code relates to JavaScript functionality, I need to provide a JavaScript example. Many of the features listed above directly relate to JavaScript features, such as dynamic imports, promises, and function calls.

Here's a breakdown of the code and potential JavaScript connections:
- `RemapEmbeddedBuiltins`, `TearDownEmbeddedBlob`:  Relate to the internal implementation of built-in JavaScript functions. No direct JS example.
- `InitWithoutSnapshot`, `InitWithSnapshot`:  Related to the startup process of the V8 engine, indirectly connected to the execution of any JS code. No direct JS example.
- `AddCrashKeysForIsolateAndHeapPointers`: Debugging related, no direct JS example.
- `InitializeCodeRanges`: Internal memory management, no direct JS example.
- The section with `stack_access_count_map`:  Relates to performance analysis of optimized JavaScript functions. No direct JS example.
- `VerifyStaticRoots`: Internal consistency checks, no direct JS example.
- The extensive `Init` function: Covers a broad range of internal initializations required to run JavaScript. Many parts are indirectly related to JavaScript features.
- `Enter`, `Exit`:  Related to the execution context of JavaScript code. No direct JS example.
- `DumpAndResetStats`: Performance analysis, no direct JS example.
- `IncreaseConcurrentOptimizationPriority`, `AbortConcurrentOptimization`: Related to optimizing JavaScript code execution. No direct JS example.
- `IncreaseTotalRegexpCodeGenerated`:  Related to the execution of regular expressions in JavaScript. Example: `const regex = /abc/; regex.test('abcdef');`
- `IsLoggingCodeCreation`: Debugging/profiling, no direct JS example.
- `NeedsSourcePositions`: Debugging/profiling, no direct JS example.
- `SetFeedbackVectorsForProfilingTools`, `MaybeInitializeVectorListFromHeap`: Profiling related, no direct JS example.
- `SymbolFor`: Relates to the internal representation of JavaScript symbols. Example: `const mySymbol = Symbol('mySymbol');`
- `AddBeforeCallEnteredCallback`, `AddCallCompletedCallback`, `FireCallCompletedCallbackInternal`:  Relates to function call hooks, used for debugging or instrumentation. No direct JS example without using V8's embedding API.
- `RunHostImportModuleDynamicallyCallback`, `GetImportAttributesFromArgument`:  Directly related to JavaScript dynamic imports. Example: `import('./my-module.js');`
- `RunHostInitializeImportMetaObjectCallback`: Related to the `import.meta` object in JavaScript modules. Example: `// in my-module.js: console.log(import.meta.url);`
- `RunHostCreateShadowRealmContextCallback`: Related to the ShadowRealm API in JavaScript. Example: `const realm = new ShadowRealm();`
- `RunPrepareStackTraceCallback`: Related to customizing stack traces in JavaScript. Example:  Overriding `Error.prepareStackTrace`.
- `SetAddCrashKeyCallback`: Debugging, no direct JS example.
- `RunAtomicsWaitCallback`: Related to the `Atomics.wait` functionality in JavaScript. Example: `const sab = new SharedArrayBuffer(4); const int32Array = new Int32Array(sab); Atomics.wait(int32Array, 0, 0);`
- `SetPromiseHook`, `RunAllPromiseHooks`, `OnAsyncFunctionSuspended`, `OnPromiseThen`, `OnPromiseBefore`, `OnPromiseAfter`: Directly related to JavaScript Promises and asynchronous functions. Example: `const promise = new Promise((resolve) => setTimeout(resolve, 100)); promise.then(() => console.log('resolved')); async function myFunction() { await promise; }`
这个C++源代码文件 `v8/src/execution/isolate.cc` 的主要功能是**管理 V8 JavaScript 引擎中的 Isolate 对象**。 Isolate 可以被理解为一个独立的 JavaScript 虚拟机实例，拥有自己的堆、执行上下文和内置对象。

具体来说，这部分代码负责以下方面：

1. **嵌入式 Built-ins 的管理:**
   - `RemapEmbeddedBuiltins`:  将嵌入式 built-in 代码重新映射到代码段。这通常在启动时发生，确保内置函数可以被有效执行。
   - `TearDownEmbeddedBlob`: 释放嵌入式 built-in 代码占用的内存。

2. **Isolate 的初始化和销毁:**
   - `InitWithoutSnapshot`:  不使用快照数据初始化 Isolate。这意味着 V8 需要从头开始创建所有内置对象和环境。
   - `InitWithSnapshot`: 使用快照数据初始化 Isolate。快照是引擎状态的序列化表示，可以加速启动过程。
   - `Init`:  底层的 Isolate 初始化函数，处理堆的创建、内置对象的加载以及各种子系统的初始化。

3. **崩溃报告支持:**
   - `AddCrashKeysForIsolateAndHeapPointers`: 在发生崩溃时添加有用的调试信息，例如 Isolate 和堆的地址。

4. **代码段管理:**
   - `InitializeCodeRanges`:  初始化代码页的范围信息，用于内存管理和安全性。

5. **内部数据结构的初始化:**
   - 代码中初始化了许多关键的 V8 内部数据结构，例如 `CompilationCache` (编译缓存), `GlobalHandles` (全局句柄), `Bootstrapper` (启动器), `StubCache` (桩缓存) 等。这些结构是 V8 引擎运行的基础。

6. **共享堆的管理:**
   - 代码中处理了共享堆的初始化和连接逻辑，允许多个 Isolate 共享某些数据，减少内存占用。

7. **反序列化:**
   - 代码处理了从快照数据反序列化 Isolate 状态的过程。

8. **Isolate 的进入和退出:**
   - `Enter`: 使当前线程进入此 Isolate，使其成为当前执行上下文。
   - `Exit`: 使当前线程退出此 Isolate。

9. **性能统计:**
   - `DumpAndResetStats`:  输出并重置各种性能统计信息，用于分析 V8 的运行状况。

10. **并发优化控制:**
    - `IncreaseConcurrentOptimizationPriority`: 提高并发优化的优先级。
    - `AbortConcurrentOptimization`: 中止正在进行的并发优化。

11. **正则表达式代码生成统计:**
    - `IncreaseTotalRegexpCodeGenerated`: 记录生成的正则表达式代码大小。

12. **代码创建日志:**
    - 提供了判断是否记录代码创建事件的接口。

13. **源码位置信息:**
    - 提供了判断是否需要详细源码位置信息的接口，用于调试和性能分析。

14. **Profiling 支持:**
    - 提供了设置用于 profiling 工具的反馈向量的接口。
    - `MaybeInitializeVectorListFromHeap`: 从堆中初始化反馈向量列表。

15. **符号表管理:**
    - `SymbolFor`:  获取或创建全局符号。

16. **函数调用回调:**
    - `AddBeforeCallEnteredCallback`, `RemoveBeforeCallEnteredCallback`, `AddCallCompletedCallback`, `RemoveCallCompletedCallback`, `FireCallCompletedCallbackInternal`:  允许注册在函数调用前后执行的回调函数，常用于调试和性能分析。

17. **动态模块导入:**
    - `RunHostImportModuleDynamicallyCallback`:  执行宿主环境提供的动态模块导入回调。
    - `GetImportAttributesFromArgument`: 从参数中获取导入属性。

18. **Import Meta 对象:**
    - `RunHostInitializeImportMetaObjectCallback`: 执行宿主环境提供的初始化 `import.meta` 对象的回调。

19. **ShadowRealm 支持:**
    - `RunHostCreateShadowRealmContextCallback`:  执行宿主环境提供的创建 ShadowRealm 上下文的回调。

20. **堆栈追踪定制:**
    - `RunPrepareStackTraceCallback`: 执行宿主环境提供的定制堆栈追踪信息的回调。
    - `SetPrepareStackTraceCallback`, `HasPrepareStackTraceCallback`: 设置和检查是否设置了自定义堆栈追踪回调。

21. **外部编译文件名管理:**
    - `LookupOrAddExternallyCompiledFilename`, `GetExternallyCompiledFilename`, `GetExternallyCompiledFilenameCount`, `PrepareBuiltinSourcePositionMap`:  用于管理外部编译文件的文件名，可能用于 source map 或调试信息。

22. **崩溃键设置:**
    - `SetAddCrashKeyCallback`: 设置添加崩溃键的回调函数。

23. **Atomics.wait 回调:**
    - `SetAtomicsWaitCallback`, `RunAtomicsWaitCallback`:  设置和执行 `Atomics.wait` 的回调函数，用于处理原子操作的等待事件。

24. **Promise Hook:**
    - `SetPromiseHook`, `RunAllPromiseHooks`, `RunPromiseHook`, `OnAsyncFunctionSuspended`, `OnPromiseThen`, `OnPromiseBefore`, `OnPromiseAfter`:  用于注册和触发 Promise 的生命周期钩子，可以用于调试、监控和集成。

**与 JavaScript 的关系及示例:**

这个文件中的许多功能都直接或间接地支持 JavaScript 的执行。以下是一些例子：

**1. 动态模块导入 (`import()`):**

```javascript
// my-module.js
export function hello() {
  console.log('Hello from my-module!');
}

// main.js
async function loadModule() {
  const module = await import('./my-module.js');
  module.hello();
}

loadModule();
```

`RunHostImportModuleDynamicallyCallback` 和相关函数在 V8 内部负责处理 `import()` 语句，调用宿主环境提供的回调来加载和执行模块。

**2. `import.meta`:**

```javascript
// my-module.js
console.log(import.meta.url);
```

`RunHostInitializeImportMetaObjectCallback` 允许宿主环境自定义 `import.meta` 对象的内容。

**3. ShadowRealm:**

```javascript
const realm = new ShadowRealm();
const globalEval = realm.evaluate('globalThis.eval');
globalEval('console.log("Hello from ShadowRealm!")');
```

`RunHostCreateShadowRealmContextCallback`  负责创建 ShadowRealm 实例所需的新的 JavaScript 上下文。

**4. 自定义堆栈追踪:**

```javascript
Error.prepareStackTrace = function(error, structuredStackTrace) {
  return structuredStackTrace.map(function(frame) {
    return `  at ${frame.getFunctionName()} (${frame.getFileName()}:${frame.getLineNumber()}:${frame.getColumnNumber()})`;
  }).join('\n');
};

try {
  throw new Error('Something went wrong');
} catch (e) {
  console.log(e.stack);
}
```

`RunPrepareStackTraceCallback`  在生成错误堆栈时会被调用，允许宿主环境自定义堆栈信息的格式。

**5. `Atomics.wait`:**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
const int32Array = new Int32Array(sab);
let result = Atomics.wait(int32Array, 0, 0, 1000); // 等待 1000 毫秒
console.log(result);
```

`RunAtomicsWaitCallback`  在 JavaScript 调用 `Atomics.wait` 时，通知宿主环境有线程正在等待共享内存上的某个值发生变化。

**6. Promise Hook:**

虽然 JavaScript 代码本身不能直接注册 Promise Hooks，但 V8 的嵌入 API 允许宿主环境注册这些钩子来监控 Promise 的生命周期。这对于调试和分析异步操作非常有用。例如，你可以监控 Promise 何时被创建、解决或拒绝。

总而言之， `v8/src/execution/isolate.cc` 的这部分代码是 V8 引擎的核心组成部分，负责创建、初始化和管理 JavaScript 执行所需的隔离环境，并提供了许多与 JavaScript 语言特性紧密集成的功能接口。

### 提示词
```
这是目录为v8/src/execution/isolate.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
heap_.code_range_->RemapEmbeddedBuiltins(
      this, embedded_blob_code_, embedded_blob_code_size_);
  CHECK_NOT_NULL(embedded_blob_code_);
  // The un-embedded code blob is already a part of the registered code range
  // so it's not necessary to register it again.
}

void Isolate::TearDownEmbeddedBlob() {
  // Nothing to do in case the blob is embedded into the binary or unset.
  if (StickyEmbeddedBlobCode() == nullptr) return;

  if (!is_short_builtin_calls_enabled()) {
    CHECK_EQ(embedded_blob_code(), StickyEmbeddedBlobCode());
    CHECK_EQ(embedded_blob_data(), StickyEmbeddedBlobData());
  }
  CHECK_EQ(CurrentEmbeddedBlobCode(), StickyEmbeddedBlobCode());
  CHECK_EQ(CurrentEmbeddedBlobData(), StickyEmbeddedBlobData());

  base::MutexGuard guard(current_embedded_blob_refcount_mutex_.Pointer());
  current_embedded_blob_refs_--;
  if (current_embedded_blob_refs_ == 0 && enable_embedded_blob_refcounting_) {
    // We own the embedded blob and are the last holder. Free it.
    OffHeapInstructionStream::FreeOffHeapOffHeapInstructionStream(
        const_cast<uint8_t*>(CurrentEmbeddedBlobCode()),
        embedded_blob_code_size(),
        const_cast<uint8_t*>(CurrentEmbeddedBlobData()),
        embedded_blob_data_size());
    ClearEmbeddedBlob();
  }
}

bool Isolate::InitWithoutSnapshot() {
  return Init(nullptr, nullptr, nullptr, false);
}

bool Isolate::InitWithSnapshot(SnapshotData* startup_snapshot_data,
                               SnapshotData* read_only_snapshot_data,
                               SnapshotData* shared_heap_snapshot_data,
                               bool can_rehash) {
  DCHECK_NOT_NULL(startup_snapshot_data);
  DCHECK_NOT_NULL(read_only_snapshot_data);
  DCHECK_NOT_NULL(shared_heap_snapshot_data);
  return Init(startup_snapshot_data, read_only_snapshot_data,
              shared_heap_snapshot_data, can_rehash);
}

namespace {
static std::string ToHexString(uintptr_t address) {
  std::stringstream stream_address;
  stream_address << "0x" << std::hex << address;
  return stream_address.str();
}
}  // namespace

void Isolate::AddCrashKeysForIsolateAndHeapPointers() {
  DCHECK_NOT_NULL(add_crash_key_callback_);

  const uintptr_t isolate_address = reinterpret_cast<uintptr_t>(this);
  add_crash_key_callback_(v8::CrashKeyId::kIsolateAddress,
                          ToHexString(isolate_address));

  const uintptr_t ro_space_firstpage_address =
      heap()->read_only_space()->FirstPageAddress();
  add_crash_key_callback_(v8::CrashKeyId::kReadonlySpaceFirstPageAddress,
                          ToHexString(ro_space_firstpage_address));

  const uintptr_t old_space_firstpage_address =
      heap()->old_space()->FirstPageAddress();
  add_crash_key_callback_(v8::CrashKeyId::kOldSpaceFirstPageAddress,
                          ToHexString(old_space_firstpage_address));

  if (heap()->code_range_base()) {
    const uintptr_t code_range_base_address = heap()->code_range_base();
    add_crash_key_callback_(v8::CrashKeyId::kCodeRangeBaseAddress,
                            ToHexString(code_range_base_address));
  }

  if (heap()->code_space()->first_page()) {
    const uintptr_t code_space_firstpage_address =
        heap()->code_space()->FirstPageAddress();
    add_crash_key_callback_(v8::CrashKeyId::kCodeSpaceFirstPageAddress,
                            ToHexString(code_space_firstpage_address));
  }
  const v8::StartupData* data = Snapshot::DefaultSnapshotBlob();
  // TODO(cbruni): Implement strategy to infrequently collect this.
  const uint32_t v8_snapshot_checksum_calculated = 0;
  add_crash_key_callback_(v8::CrashKeyId::kSnapshotChecksumCalculated,
                          ToHexString(v8_snapshot_checksum_calculated));
  const uint32_t v8_snapshot_checksum_expected =
      Snapshot::GetExpectedChecksum(data);
  add_crash_key_callback_(v8::CrashKeyId::kSnapshotChecksumExpected,
                          ToHexString(v8_snapshot_checksum_expected));
}

void Isolate::InitializeCodeRanges() {
  DCHECK_NULL(GetCodePages());
  MemoryRange embedded_range{
      reinterpret_cast<const void*>(embedded_blob_code()),
      embedded_blob_code_size()};
  code_pages_buffer1_.push_back(embedded_range);
  SetCodePages(&code_pages_buffer1_);
}

namespace {

// This global counter contains number of stack loads/stores per optimized/wasm
// function.
using MapOfLoadsAndStoresPerFunction =
    std::map<std::string /* function_name */,
             std::pair<uint64_t /* loads */, uint64_t /* stores */>>;
MapOfLoadsAndStoresPerFunction* stack_access_count_map = nullptr;

class BigIntPlatform : public bigint::Platform {
 public:
  explicit BigIntPlatform(Isolate* isolate) : isolate_(isolate) {}
  ~BigIntPlatform() override = default;

  bool InterruptRequested() override {
    StackLimitCheck interrupt_check(isolate_);
    return (interrupt_check.InterruptRequested() &&
            isolate_->stack_guard()->HasTerminationRequest());
  }

 private:
  Isolate* isolate_;
};
}  // namespace

#ifdef V8_COMPRESS_POINTERS
VirtualMemoryCage* Isolate::GetPtrComprCodeCageForTesting() {
  return V8_EXTERNAL_CODE_SPACE_BOOL ? heap_.code_range()
                                     : isolate_group_->GetPtrComprCage();
}
#endif  // V8_COMPRESS_POINTERS

void Isolate::VerifyStaticRoots() {
#if V8_STATIC_ROOTS_BOOL
  static_assert(ReadOnlyHeap::IsReadOnlySpaceShared(),
                "Static read only roots are only supported when there is one "
                "shared read only space per cage");
#define STATIC_ROOTS_FAILED_MSG                                            \
  "Read-only heap layout changed. Run `tools/dev/gen-static-roots.py` to " \
  "update static-roots.h."
  static_assert(static_cast<int>(RootIndex::kReadOnlyRootsCount) ==
                    StaticReadOnlyRootsPointerTable.size(),
                STATIC_ROOTS_FAILED_MSG);
  auto& roots = roots_table();
  RootIndex idx = RootIndex::kFirstReadOnlyRoot;
  for (Tagged_t cmp_ptr : StaticReadOnlyRootsPointerTable) {
    Address the_root = roots[idx];
    Address ptr =
        V8HeapCompressionScheme::DecompressTagged(cage_base(), cmp_ptr);
    CHECK_WITH_MSG(the_root == ptr, STATIC_ROOTS_FAILED_MSG);
    ++idx;
  }

  idx = RootIndex::kFirstReadOnlyRoot;
#define CHECK_NAME(_1, _2, CamelName)                                     \
  CHECK_WITH_MSG(StaticReadOnlyRoot::k##CamelName ==                      \
                     V8HeapCompressionScheme::CompressObject(roots[idx]), \
                 STATIC_ROOTS_FAILED_MSG);                                \
  ++idx;
  STRONG_READ_ONLY_ROOT_LIST(CHECK_NAME)
#undef CHECK_NAME

  // Check if instance types to map range mappings are still valid.
  //
  // Is##type(map) may be computed by checking if the map pointer lies in a
  // statically known range of addresses, whereas Is##type(instance_type) is the
  // definitive source of truth. If they disagree it means that a particular
  // entry in InstanceTypeChecker::kUniqueMapRangeOfInstanceTypeRangeList is out
  // of date. This can also happen if an instance type is starting to be used by
  // more maps.
  //
  // If this check fails either re-arrange allocations in the read-only heap
  // such that the static map range is restored (consult static-roots.h for a
  // sorted list of addresses) or remove the offending entry from the list.
  for (auto idx = RootIndex::kFirstRoot; idx <= RootIndex::kLastRoot; ++idx) {
    Tagged<Object> obj = roots_table().slot(idx).load(this);
    if (obj.ptr() == kNullAddress || !IsMap(obj)) continue;
    Tagged<Map> map = Cast<Map>(obj);

#define INSTANCE_TYPE_CHECKER_SINGLE(type, _)  \
  CHECK_EQ(InstanceTypeChecker::Is##type(map), \
           InstanceTypeChecker::Is##type(map->instance_type()));
    INSTANCE_TYPE_CHECKERS_SINGLE(INSTANCE_TYPE_CHECKER_SINGLE)
#undef INSTANCE_TYPE_CHECKER_SINGLE

#define INSTANCE_TYPE_CHECKER_RANGE(type, _1, _2) \
  CHECK_EQ(InstanceTypeChecker::Is##type(map),    \
           InstanceTypeChecker::Is##type(map->instance_type()));
    INSTANCE_TYPE_CHECKERS_RANGE(INSTANCE_TYPE_CHECKER_RANGE)
#undef INSTANCE_TYPE_CHECKER_RANGE

    // This limit is used in various places as a fast IsJSReceiver check.
    CHECK_IMPLIES(
        InstanceTypeChecker::IsPrimitiveHeapObject(map->instance_type()),
        V8HeapCompressionScheme::CompressObject(map.ptr()) <
            InstanceTypeChecker::kNonJsReceiverMapLimit);
    CHECK_IMPLIES(InstanceTypeChecker::IsJSReceiver(map->instance_type()),
                  V8HeapCompressionScheme::CompressObject(map.ptr()) >=
                      InstanceTypeChecker::kNonJsReceiverMapLimit);
    CHECK(InstanceTypeChecker::kNonJsReceiverMapLimit <
          read_only_heap()->read_only_space()->Size());

    if (InstanceTypeChecker::IsString(map->instance_type())) {
      CHECK_EQ(InstanceTypeChecker::IsString(map),
               InstanceTypeChecker::IsString(map->instance_type()));
      CHECK_EQ(InstanceTypeChecker::IsSeqString(map),
               InstanceTypeChecker::IsSeqString(map->instance_type()));
      CHECK_EQ(InstanceTypeChecker::IsExternalString(map),
               InstanceTypeChecker::IsExternalString(map->instance_type()));
      CHECK_EQ(
          InstanceTypeChecker::IsUncachedExternalString(map),
          InstanceTypeChecker::IsUncachedExternalString(map->instance_type()));
      CHECK_EQ(InstanceTypeChecker::IsInternalizedString(map),
               InstanceTypeChecker::IsInternalizedString(map->instance_type()));
      CHECK_EQ(InstanceTypeChecker::IsConsString(map),
               InstanceTypeChecker::IsConsString(map->instance_type()));
      CHECK_EQ(InstanceTypeChecker::IsSlicedString(map),
               InstanceTypeChecker::IsSlicedString(map->instance_type()));
      CHECK_EQ(InstanceTypeChecker::IsThinString(map),
               InstanceTypeChecker::IsThinString(map->instance_type()));
      CHECK_EQ(InstanceTypeChecker::IsOneByteString(map),
               InstanceTypeChecker::IsOneByteString(map->instance_type()));
      CHECK_EQ(InstanceTypeChecker::IsTwoByteString(map),
               InstanceTypeChecker::IsTwoByteString(map->instance_type()));
    }
  }

  // Sanity check the API
  CHECK_EQ(
      v8::internal::Internals::GetRoot(reinterpret_cast<v8::Isolate*>(this),
                                       static_cast<int>(RootIndex::kNullValue)),
      ReadOnlyRoots(this).null_value().ptr());
#undef STATIC_ROOTS_FAILED_MSG
#endif  // V8_STATIC_ROOTS_BOOL
}

bool Isolate::Init(SnapshotData* startup_snapshot_data,
                   SnapshotData* read_only_snapshot_data,
                   SnapshotData* shared_heap_snapshot_data, bool can_rehash) {
  TRACE_ISOLATE(init);

#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE
  CHECK_EQ(V8HeapCompressionScheme::base(), cage_base());
#endif  // V8_COMPRESS_POINTERS_IN_SHARED_CAGE

  const bool create_heap_objects = (shared_heap_snapshot_data == nullptr);
  // We either have both or none.
  DCHECK_EQ(create_heap_objects, startup_snapshot_data == nullptr);
  DCHECK_EQ(create_heap_objects, read_only_snapshot_data == nullptr);

  EnableRoAllocationForSnapshotScope enable_ro_allocation(this);

  base::ElapsedTimer timer;
  if (create_heap_objects && v8_flags.profile_deserialization) timer.Start();

  time_millis_at_init_ = heap_.MonotonicallyIncreasingTimeInMs();

  Isolate* use_shared_space_isolate = nullptr;

  if (v8_flags.shared_heap) {
    if (isolate_group_->has_shared_space_isolate()) {
      owns_shareable_data_ = false;
      use_shared_space_isolate = isolate_group_->shared_space_isolate();
    } else {
      isolate_group_->init_shared_space_isolate(this);
      use_shared_space_isolate = isolate_group_->shared_space_isolate();
      is_shared_space_isolate_ = true;
      DCHECK(owns_shareable_data_);
    }
  }

  CHECK_IMPLIES(is_shared_space_isolate_, V8_CAN_CREATE_SHARED_HEAP_BOOL);

  stress_deopt_count_ = v8_flags.deopt_every_n_times;
  force_slow_path_ = v8_flags.force_slow_path;

  has_fatal_error_ = false;

  // The initialization process does not handle memory exhaustion.
  AlwaysAllocateScope always_allocate(heap());

#define ASSIGN_ELEMENT(CamelName, hacker_name)                  \
  isolate_addresses_[IsolateAddressId::k##CamelName##Address] = \
      reinterpret_cast<Address>(hacker_name##_address());
  FOR_EACH_ISOLATE_ADDRESS_NAME(ASSIGN_ELEMENT)
#undef ASSIGN_ELEMENT

  // We need to initialize code_pages_ before any on-heap code is allocated to
  // make sure we record all code allocations.
  InitializeCodeRanges();

  compilation_cache_ = new CompilationCache(this);
  descriptor_lookup_cache_ = new DescriptorLookupCache();
  global_handles_ = new GlobalHandles(this);
  eternal_handles_ = new EternalHandles();
  bootstrapper_ = new Bootstrapper(this);
  handle_scope_implementer_ = new HandleScopeImplementer(this);
  load_stub_cache_ = new StubCache(this);
  store_stub_cache_ = new StubCache(this);
  define_own_stub_cache_ = new StubCache(this);
  materialized_object_store_ = new MaterializedObjectStore(this);
  regexp_stack_ = new RegExpStack();
  isolate_data()->set_regexp_static_result_offsets_vector(
      jsregexp_static_offsets_vector());
  date_cache_ = new DateCache();
  heap_profiler_ = new HeapProfiler(heap());
  interpreter_ = new interpreter::Interpreter(this);
  bigint_processor_ = bigint::Processor::New(new BigIntPlatform(this));

  if (is_shared_space_isolate_) {
    global_safepoint_ = std::make_unique<GlobalSafepoint>(this);
  }

  if (v8_flags.lazy_compile_dispatcher) {
    lazy_compile_dispatcher_ = std::make_unique<LazyCompileDispatcher>(
        this, V8::GetCurrentPlatform(), v8_flags.stack_size);
  }
#ifdef V8_ENABLE_SPARKPLUG
  baseline_batch_compiler_ = new baseline::BaselineBatchCompiler(this);
#endif  // V8_ENABLE_SPARKPLUG
#ifdef V8_ENABLE_MAGLEV
  maglev_concurrent_dispatcher_ = new maglev::MaglevConcurrentDispatcher(this);
#endif  // V8_ENABLE_MAGLEV

#if USE_SIMULATOR
  simulator_data_ = new SimulatorData;
#endif

  // Enable logging before setting up the heap
  v8_file_logger_->SetUp(this);

  metrics_recorder_ = std::make_shared<metrics::Recorder>();

  {
    // Ensure that the thread has a valid stack guard.  The v8::Locker object
    // will ensure this too, but we don't have to use lockers if we are only
    // using one thread.
    ExecutionAccess lock(this);
    stack_guard()->InitThread(lock);
  }

  // Create LocalIsolate/LocalHeap for the main thread and set state to Running.
  main_thread_local_isolate_.reset(new LocalIsolate(this, ThreadKind::kMain));

  {
    IgnoreLocalGCRequests ignore_gc_requests(heap());
    main_thread_local_heap()->Unpark();
  }

  // Requires a LocalHeap to be set up to register a GC epilogue callback.
  inner_pointer_to_code_cache_ = new InnerPointerToCodeCache(this);

#if V8_ENABLE_WEBASSEMBLY
  wasm_code_look_up_cache_ = new wasm::WasmCodeLookupCache;
#endif  // V8_ENABLE_WEBASSEMBLY

  // Lock clients_mutex_ in order to prevent shared GCs from other clients
  // during deserialization.
  std::optional<base::RecursiveMutexGuard> clients_guard;

  if (use_shared_space_isolate && !is_shared_space_isolate()) {
    clients_guard.emplace(
        &use_shared_space_isolate->global_safepoint()->clients_mutex_);
    use_shared_space_isolate->global_safepoint()->AppendClient(this);
  }

  shared_space_isolate_ = use_shared_space_isolate;

  isolate_data_.is_shared_space_isolate_flag_ = is_shared_space_isolate();
  isolate_data_.uses_shared_heap_flag_ = has_shared_space();

  if (use_shared_space_isolate && !is_shared_space_isolate() &&
      use_shared_space_isolate->heap()
          ->incremental_marking()
          ->IsMajorMarking()) {
    heap_.SetIsMarkingFlag(true);
  }

  // Set up the object heap.
  DCHECK(!heap_.HasBeenSetUp());
  heap_.SetUp(main_thread_local_heap());
  InitializeIsShortBuiltinCallsEnabled();
  if (!create_heap_objects) {
    // Must be done before deserializing RO space, since RO space may contain
    // builtin Code objects which point into the (potentially remapped)
    // embedded blob.
    MaybeRemapEmbeddedBuiltinsIntoCodeRange();
  }
  {
    // Must be done before deserializing RO space since the deserialization
    // process refers to these data structures.
    isolate_data_.external_reference_table()->InitIsolateIndependent(
        isolate_group()->external_ref_table());
#ifdef V8_COMPRESS_POINTERS
    external_pointer_table().Initialize();
    external_pointer_table().InitializeSpace(
        heap()->read_only_external_pointer_space());
    external_pointer_table().AttachSpaceToReadOnlySegment(
        heap()->read_only_external_pointer_space());
    external_pointer_table().InitializeSpace(
        heap()->young_external_pointer_space());
    external_pointer_table().InitializeSpace(
        heap()->old_external_pointer_space());
    cpp_heap_pointer_table().Initialize();
    cpp_heap_pointer_table().InitializeSpace(heap()->cpp_heap_pointer_space());
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
    trusted_pointer_table().Initialize();
    trusted_pointer_table().InitializeSpace(heap()->trusted_pointer_space());
#endif  // V8_ENABLE_SANDBOX
  }
  ReadOnlyHeap::SetUp(this, read_only_snapshot_data, can_rehash);
  heap_.SetUpSpaces(isolate_data_.new_allocation_info_,
                    isolate_data_.old_allocation_info_);

  DCHECK_EQ(this, Isolate::Current());
  PerIsolateThreadData* const current_data = CurrentPerIsolateThreadData();
  DCHECK_EQ(current_data->isolate(), this);
  SetIsolateThreadLocals(this, current_data);

  if (OwnsStringTables()) {
    string_table_ = std::make_unique<StringTable>(this);
    string_forwarding_table_ = std::make_unique<StringForwardingTable>(this);
  } else {
    // Only refer to shared string table after attaching to the shared isolate.
    DCHECK(has_shared_space());
    DCHECK(!is_shared_space_isolate());
    DCHECK_NOT_NULL(string_table());
    DCHECK_NOT_NULL(string_forwarding_table());
  }

#ifdef V8_EXTERNAL_CODE_SPACE
  {
    VirtualMemoryCage* code_cage;
    if (heap_.code_range()) {
      code_cage = heap_.code_range();
    } else {
      CHECK(jitless_);
      // In jitless mode the code space pages will be allocated in the main
      // pointer compression cage.
      code_cage = isolate_group_->GetPtrComprCage();
    }
    code_cage_base_ = ExternalCodeCompressionScheme::PrepareCageBaseAddress(
        code_cage->base());
    if (COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL) {
      // .. now that it's available, initialize the thread-local base.
      ExternalCodeCompressionScheme::InitBase(code_cage_base_);
    }
    CHECK_EQ(ExternalCodeCompressionScheme::base(), code_cage_base_);

    // Ensure that ExternalCodeCompressionScheme is applicable to all objects
    // stored in the code cage.
    using ComprScheme = ExternalCodeCompressionScheme;
    Address base = code_cage->base();
    Address last = base + code_cage->size() - 1;
    PtrComprCageBase code_cage_base{code_cage_base_};
    CHECK_EQ(base, ComprScheme::DecompressTagged(
                       code_cage_base, ComprScheme::CompressObject(base)));
    CHECK_EQ(last, ComprScheme::DecompressTagged(
                       code_cage_base, ComprScheme::CompressObject(last)));
  }
#endif  // V8_EXTERNAL_CODE_SPACE

  isolate_data_.external_reference_table()->Init(this);

#ifdef V8_COMPRESS_POINTERS
  if (owns_shareable_data()) {
    isolate_data_.shared_external_pointer_table_ = new ExternalPointerTable();
    shared_external_pointer_space_ = new ExternalPointerTable::Space();
    shared_external_pointer_table().Initialize();
    shared_external_pointer_table().InitializeSpace(
        shared_external_pointer_space());
  } else {
    DCHECK(has_shared_space());
    isolate_data_.shared_external_pointer_table_ =
        shared_space_isolate()->isolate_data_.shared_external_pointer_table_;
    shared_external_pointer_space_ =
        shared_space_isolate()->shared_external_pointer_space_;
  }
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  IsolateGroup::current()->code_pointer_table()->InitializeSpace(
      heap()->code_pointer_space());
  if (owns_shareable_data()) {
    isolate_data_.shared_trusted_pointer_table_ = new TrustedPointerTable();
    shared_trusted_pointer_space_ = new TrustedPointerTable::Space();
    shared_trusted_pointer_table().Initialize();
    shared_trusted_pointer_table().InitializeSpace(
        shared_trusted_pointer_space());
  } else {
    DCHECK(has_shared_space());
    isolate_data_.shared_trusted_pointer_table_ =
        shared_space_isolate()->isolate_data_.shared_trusted_pointer_table_;
    shared_trusted_pointer_space_ =
        shared_space_isolate()->shared_trusted_pointer_space_;
  }

#endif  // V8_ENABLE_SANDBOX
#ifdef V8_ENABLE_LEAPTIERING
  GetProcessWideJSDispatchTable()->InitializeSpace(
      heap()->js_dispatch_table_space());
#endif  // V8_ENABLE_LEAPTIERING

#if V8_ENABLE_WEBASSEMBLY
  wasm::GetWasmEngine()->AddIsolate(this);
#endif  // V8_ENABLE_WEBASSEMBLY

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
  if (v8_flags.enable_etw_stack_walking) {
    ETWJITInterface::AddIsolate(this);
  }
#endif  // defined(V8_OS_WIN)

  if (setup_delegate_ == nullptr) {
    setup_delegate_ = new SetupIsolateDelegate;
  }

  if (!v8_flags.inline_new) heap_.DisableInlineAllocation();

  if (!setup_delegate_->SetupHeap(this, create_heap_objects)) {
    V8::FatalProcessOutOfMemory(this, "heap object creation");
  }

  if (create_heap_objects) {
    // Terminate the startup and shared heap object caches so we can iterate.
    startup_object_cache_.push_back(ReadOnlyRoots(this).undefined_value());
    shared_heap_object_cache_.push_back(ReadOnlyRoots(this).undefined_value());
  }

  InitializeThreadLocal();

  // Profiler has to be created after ThreadLocal is initialized
  // because it makes use of interrupts.
  tracing_cpu_profiler_.reset(new TracingCpuProfilerImpl(this));

  bootstrapper_->Initialize(create_heap_objects);

  if (create_heap_objects) {
    builtins_constants_table_builder_ = new BuiltinsConstantsTableBuilder(this);

    setup_delegate_->SetupBuiltins(this, true);

    builtins_constants_table_builder_->Finalize();
    delete builtins_constants_table_builder_;
    builtins_constants_table_builder_ = nullptr;

    CreateAndSetEmbeddedBlob();
  } else {
    setup_delegate_->SetupBuiltins(this, false);
  }

  // Initialize custom memcopy and memmove functions (must happen after
  // embedded blob setup).
  init_memcopy_functions();

  if (v8_flags.trace_turbo || v8_flags.trace_turbo_graph ||
      v8_flags.turbo_profiling) {
    PrintF("Concurrent recompilation has been disabled for tracing.\n");
  } else if (OptimizingCompileDispatcher::Enabled()) {
    optimizing_compile_dispatcher_ = new OptimizingCompileDispatcher(this);
  }

  // Initialize before deserialization since collections may occur,
  // clearing/updating ICs (and thus affecting tiering decisions).
  tiering_manager_ = new TieringManager(this);

  if (!create_heap_objects) {
    // If we are deserializing, read the state into the now-empty heap.
    SharedHeapDeserializer shared_heap_deserializer(
        this, shared_heap_snapshot_data, can_rehash);
    shared_heap_deserializer.DeserializeIntoIsolate();

    StartupDeserializer startup_deserializer(this, startup_snapshot_data,
                                             can_rehash);
    startup_deserializer.DeserializeIntoIsolate();
  }
  InitializeBuiltinJSDispatchTable();
  if (DEBUG_BOOL) VerifyStaticRoots();
  load_stub_cache_->Initialize();
  store_stub_cache_->Initialize();
  define_own_stub_cache_->Initialize();
  interpreter_->Initialize();
  heap_.NotifyDeserializationComplete();

  delete setup_delegate_;
  setup_delegate_ = nullptr;

  Builtins::InitializeIsolateDataTables(this);

  // Extra steps in the logger after the heap has been set up.
  v8_file_logger_->LateSetup(this);

#ifdef DEBUG
  // Verify that the current heap state (usually deserialized from the snapshot)
  // is compatible with the embedded blob. If this DCHECK fails, we've likely
  // loaded a snapshot generated by a different V8 version or build-time
  // configuration.
  if (!IsolateIsCompatibleWithEmbeddedBlob(this)) {
    FATAL(
        "The Isolate is incompatible with the embedded blob. This is usually "
        "caused by incorrect usage of mksnapshot. When generating custom "
        "snapshots, embedders must ensure they pass the same flags as during "
        "the V8 build process (e.g.: --turbo-instruction-scheduling).");
  }
#endif  // DEBUG

  if (v8_flags.print_builtin_code) builtins()->PrintBuiltinCode();
  if (v8_flags.print_builtin_size) builtins()->PrintBuiltinSize();

  // Finish initialization of ThreadLocal after deserialization is done.
  clear_exception();
  clear_pending_message();

  // Quiet the heap NaN if needed on target platform.
  if (!create_heap_objects)
    Assembler::QuietNaN(ReadOnlyRoots(this).nan_value());

  if (v8_flags.trace_turbo) {
    // Create an empty file.
    std::ofstream(GetTurboCfgFileName(this).c_str(), std::ios_base::trunc);
  }

  isolate_data_.continuation_preserved_embedder_data_ =
      *factory()->undefined_value();

  {
    HandleScope scope(this);
    ast_string_constants_ = new AstStringConstants(this, HashSeed(this));
  }

  initialized_from_snapshot_ = !create_heap_objects;

  if (v8_flags.stress_sampling_allocation_profiler > 0) {
    uint64_t sample_interval = v8_flags.stress_sampling_allocation_profiler;
    int stack_depth = 128;
    v8::HeapProfiler::SamplingFlags sampling_flags =
        v8::HeapProfiler::SamplingFlags::kSamplingForceGC;
    heap_profiler()->StartSamplingHeapProfiler(sample_interval, stack_depth,
                                               sampling_flags);
  }

  if (create_heap_objects && v8_flags.profile_deserialization) {
    double ms = timer.Elapsed().InMillisecondsF();
    PrintF("[Initializing isolate from scratch took %0.3f ms]\n", ms);
  }

  if (initialized_from_snapshot_) {
    SLOW_DCHECK(SharedFunctionInfo::UniqueIdsAreUnique(this));
  }

  if (v8_flags.harmony_struct) {
    // Initialize or get the struct type registry shared by all isolates.
    if (is_shared_space_isolate()) {
      shared_struct_type_registry_ =
          std::make_unique<SharedStructTypeRegistry>();
    } else {
      DCHECK_NOT_NULL(shared_struct_type_registry());
    }
  }

#ifdef V8_ENABLE_WEBASSEMBLY
#if V8_STATIC_ROOTS_BOOL
  // Protect the payload of wasm null.
  if (!page_allocator()->DecommitPages(
          reinterpret_cast<void*>(factory()->wasm_null()->payload()),
          WasmNull::kSize - kTaggedSize)) {
    V8::FatalProcessOutOfMemory(this, "decommitting WasmNull payload");
  }
#endif  // V8_STATIC_ROOTS_BOOL

  wasm::WasmCodePointerTable* wasm_code_pointer_table =
      wasm::GetProcessWideWasmCodePointerTable();
  for (size_t i = 0; i < Builtins::kNumWasmIndirectlyCallableBuiltins; i++) {
    // TODO(sroettger): investigate if we can use a global set of handles for
    // these builtins.
    wasm_builtin_code_handles_[i] =
        wasm_code_pointer_table->AllocateAndInitializeEntry(Builtins::EntryOf(
            Builtins::kWasmIndirectlyCallableBuiltins[i], this));
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Isolate initialization allocates long living objects that should be
  // pretenured to old space.
  DCHECK_IMPLIES(heap()->new_space(), heap()->new_space()->Size() == 0);
  DCHECK_IMPLIES(heap()->new_lo_space(), heap()->new_lo_space()->Size() == 0);
  DCHECK_EQ(heap()->gc_count(), 0);

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
  if (v8_flags.enable_etw_stack_walking) {
    ETWJITInterface::MaybeSetHandlerNow(this);
  }
#endif  // defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)

#if defined(V8_USE_PERFETTO)
  PerfettoLogger::RegisterIsolate(this);
#endif  // defined(V8_USE_PERFETTO)

  initialized_ = true;

  return true;
}

void Isolate::Enter() {
  Isolate* current_isolate = nullptr;
  PerIsolateThreadData* current_data = CurrentPerIsolateThreadData();

#ifdef V8_ENABLE_CHECKS
  // No different thread must have entered the isolate. Allow re-entering.
  ThreadId thread_id = ThreadId::Current();
  if (current_thread_id_.IsValid()) {
    CHECK_EQ(current_thread_id_, thread_id);
  } else {
    CHECK_EQ(0, current_thread_counter_);
    current_thread_id_ = thread_id;
  }
  current_thread_counter_++;
#endif

  // Set the stack start for the main thread that enters the isolate.
  heap()->SetStackStart();

  if (current_data != nullptr) {
    current_isolate = current_data->isolate_;
    DCHECK_NOT_NULL(current_isolate);
    if (current_isolate == this) {
      DCHECK(Current() == this);
      auto entry_stack = entry_stack_.load();
      DCHECK_NOT_NULL(entry_stack);
      DCHECK(entry_stack->previous_thread_data == nullptr ||
             entry_stack->previous_thread_data->thread_id() ==
                 ThreadId::Current());
      // Same thread re-enters the isolate, no need to re-init anything.
      entry_stack->entry_count++;
      return;
    }
  }

  PerIsolateThreadData* data = FindOrAllocatePerThreadDataForThisThread();
  DCHECK_NOT_NULL(data);
  DCHECK(data->isolate_ == this);

  EntryStackItem* item =
      new EntryStackItem(current_data, current_isolate, entry_stack_);
  entry_stack_ = item;

  SetIsolateThreadLocals(this, data);

  // In case it's the first time some thread enters the isolate.
  set_thread_id(data->thread_id());
}

void Isolate::Exit() {
  auto current_entry_stack = entry_stack_.load();
  DCHECK_NOT_NULL(current_entry_stack);
  DCHECK(current_entry_stack->previous_thread_data == nullptr ||
         current_entry_stack->previous_thread_data->thread_id() ==
             ThreadId::Current());

#ifdef V8_ENABLE_CHECKS
  // The current thread must have entered the isolate.
  CHECK_EQ(current_thread_id_, ThreadId::Current());
  if (--current_thread_counter_ == 0) current_thread_id_ = ThreadId::Invalid();
#endif

  if (--current_entry_stack->entry_count > 0) return;

  DCHECK_NOT_NULL(CurrentPerIsolateThreadData());
  DCHECK(CurrentPerIsolateThreadData()->isolate_ == this);

  // Pop the stack.
  entry_stack_ = current_entry_stack->previous_item;

  PerIsolateThreadData* previous_thread_data =
      current_entry_stack->previous_thread_data;
  Isolate* previous_isolate = current_entry_stack->previous_isolate;

  delete current_entry_stack;

  // Reinit the current thread for the isolate it was running before this one.
  SetIsolateThreadLocals(previous_isolate, previous_thread_data);
}

std::unique_ptr<PersistentHandles> Isolate::NewPersistentHandles() {
  return std::make_unique<PersistentHandles>(this);
}

void Isolate::DumpAndResetStats() {
  if (v8_flags.trace_turbo_stack_accesses) {
    StdoutStream os;
    uint64_t total_loads = 0;
    uint64_t total_stores = 0;
    os << "=== Stack access counters === " << std::endl;
    if (!stack_access_count_map) {
      os << "No stack accesses in optimized/wasm functions found.";
    } else {
      DCHECK_NOT_NULL(stack_access_count_map);
      os << "Number of optimized/wasm stack-access functions: "
         << stack_access_count_map->size() << std::endl;
      for (auto it = stack_access_count_map->cbegin();
           it != stack_access_count_map->cend(); it++) {
        std::string function_name((*it).first);
        std::pair<uint64_t, uint64_t> per_func_count = (*it).second;
        os << "Name: " << function_name << ", Loads: " << per_func_count.first
           << ", Stores: " << per_func_count.second << std::endl;
        total_loads += per_func_count.first;
        total_stores += per_func_count.second;
      }
      os << "Total Loads: " << total_loads << ", Total Stores: " << total_stores
         << std::endl;
      stack_access_count_map = nullptr;
    }
  }
  if (turbo_statistics_ != nullptr) {
    DCHECK(v8_flags.turbo_stats || v8_flags.turbo_stats_nvp);
    StdoutStream os;
    if (v8_flags.turbo_stats) {
      AsPrintableStatistics ps = {"Turbofan", *turbo_statistics_, false};
      os << ps << std::endl;
    }
    if (v8_flags.turbo_stats_nvp) {
      AsPrintableStatistics ps = {"Turbofan", *turbo_statistics_, true};
      os << ps << std::endl;
    }
    turbo_statistics_.reset();
  }

#ifdef V8_ENABLE_MAGLEV
  if (maglev_statistics_ != nullptr) {
    DCHECK(v8_flags.maglev_stats || v8_flags.maglev_stats_nvp);
    StdoutStream os;
    if (v8_flags.maglev_stats) {
      AsPrintableStatistics ps = {"Maglev", *maglev_statistics_, false};
      os << ps << std::endl;
    }
    if (v8_flags.maglev_stats_nvp) {
      AsPrintableStatistics ps = {"Maglev", *maglev_statistics_, true};
      os << ps << std::endl;
    }
    maglev_statistics_.reset();
  }
#endif  // V8_ENABLE_MAGLEV

#if V8_ENABLE_WEBASSEMBLY
  // TODO(7424): There is no public API for the {WasmEngine} yet. So for now we
  // just dump and reset the engines statistics together with the Isolate.
  if (v8_flags.turbo_stats_wasm) {
    wasm::GetWasmEngine()->DumpAndResetTurboStatistics();
  }
#endif  // V8_ENABLE_WEBASSEMBLY
#if V8_RUNTIME_CALL_STATS
  if (V8_UNLIKELY(TracingFlags::runtime_stats.load(std::memory_order_relaxed) ==
                  v8::tracing::TracingCategoryObserver::ENABLED_BY_NATIVE)) {
    counters()->worker_thread_runtime_call_stats()->AddToMainTable(
        counters()->runtime_call_stats());
    counters()->runtime_call_stats()->Print();
    counters()->runtime_call_stats()->Reset();
  }
#endif  // V8_RUNTIME_CALL_STATS
}

void Isolate::DumpAndResetBuiltinsProfileData() {
  if (BasicBlockProfiler::Get()->HasData(this)) {
    if (v8_flags.turbo_profiling_output) {
      FILE* f = std::fopen(v8_flags.turbo_profiling_output, "w");
      if (f == nullptr) {
        FATAL("Unable to open file \"%s\" for writing.\n",
              v8_flags.turbo_profiling_output.value());
      }
      OFStream pgo_stream(f);
      BasicBlockProfiler::Get()->Log(this, pgo_stream);
    } else {
      StdoutStream out;
      BasicBlockProfiler::Get()->Print(this, out);
    }
    BasicBlockProfiler::Get()->ResetCounts(this);
  } else {
    // Only log builtins PGO data if v8 was built with
    // v8_enable_builtins_profiling=true
    CHECK_NULL(v8_flags.turbo_profiling_output);
  }
}

void Isolate::IncreaseConcurrentOptimizationPriority(
    CodeKind kind, Tagged<SharedFunctionInfo> function) {
  DCHECK_EQ(kind, CodeKind::TURBOFAN_JS);
  optimizing_compile_dispatcher()->Prioritize(function);
}

void Isolate::AbortConcurrentOptimization(BlockingBehavior behavior) {
  if (concurrent_recompilation_enabled()) {
    DisallowGarbageCollection no_recursive_gc;
    optimizing_compile_dispatcher()->Flush(behavior);
  }
#ifdef V8_ENABLE_MAGLEV
  if (maglev_concurrent_dispatcher()->is_enabled()) {
    DisallowGarbageCollection no_recursive_gc;
    maglev_concurrent_dispatcher()->Flush(behavior);
  }
#endif
}

std::shared_ptr<CompilationStatistics> Isolate::GetTurboStatistics() {
  if (turbo_statistics_ == nullptr) {
    turbo_statistics_.reset(new CompilationStatistics());
  }
  return turbo_statistics_;
}

#ifdef V8_ENABLE_MAGLEV

std::shared_ptr<CompilationStatistics> Isolate::GetMaglevStatistics() {
  if (maglev_statistics_ == nullptr) {
    maglev_statistics_.reset(new CompilationStatistics());
  }
  return maglev_statistics_;
}

#endif  // V8_ENABLE_MAGLEV

CodeTracer* Isolate::GetCodeTracer() {
  if (code_tracer() == nullptr) set_code_tracer(new CodeTracer(id()));
  return code_tracer();
}

bool Isolate::use_optimizer() {
  // TODO(v8:7700): Update this predicate for a world with multiple tiers.
  return (v8_flags.turbofan || v8_flags.maglev) && !serializer_enabled_ &&
         CpuFeatures::SupportsOptimizer() && !is_precise_count_code_coverage();
}

void Isolate::IncreaseTotalRegexpCodeGenerated(DirectHandle<HeapObject> code) {
  PtrComprCageBase cage_base(this);
  DCHECK(IsCode(*code, cage_base) || IsTrustedByteArray(*code, cage_base));
  total_regexp_code_generated_ += code->Size(cage_base);
}

bool Isolate::NeedsDetailedOptimizedCodeLineInfo() const {
  return NeedsSourcePositions() || detailed_source_positions_for_profiling();
}

bool Isolate::IsLoggingCodeCreation() const {
  return v8_file_logger()->is_listening_to_code_events() || is_profiling() ||
         v8_flags.log_function_events ||
         logger()->is_listening_to_code_events();
}

bool Isolate::AllowsCodeCompaction() const {
  return v8_flags.compact_code_space && logger()->allows_code_compaction();
}

bool Isolate::NeedsSourcePositions() const {
  return
      // Static conditions.
      v8_flags.trace_deopt || v8_flags.trace_turbo ||
      v8_flags.trace_turbo_graph || v8_flags.turbo_profiling ||
      v8_flags.print_maglev_code || v8_flags.perf_prof || v8_flags.log_maps ||
      v8_flags.log_ic || v8_flags.log_function_events ||
      v8_flags.heap_snapshot_on_oom ||
      // Dynamic conditions; changing any of these conditions triggers source
      // position collection for the entire heap
      // (CollectSourcePositionsForAllBytecodeArrays).
      is_profiling() || debug_->is_active() || v8_file_logger_->is_logging();
}

void Isolate::SetFeedbackVectorsForProfilingTools(Tagged<Object> value) {
  DCHECK(IsUndefined(value, this) || IsArrayList(value));
  heap()->set_feedback_vectors_for_profiling_tools(value);
}

void Isolate::MaybeInitializeVectorListFromHeap() {
  if (!IsUndefined(heap()->feedback_vectors_for_profiling_tools(), this)) {
    // Already initialized, return early.
    DCHECK(IsArrayList(heap()->feedback_vectors_for_profiling_tools()));
    return;
  }

  // Collect existing feedback vectors.
  DirectHandleVector<FeedbackVector> vectors(this);

  {
    HeapObjectIterator heap_iterator(heap());
    for (Tagged<HeapObject> current_obj = heap_iterator.Next();
         !current_obj.is_null(); current_obj = heap_iterator.Next()) {
      if (!IsFeedbackVector(current_obj)) continue;

      Tagged<FeedbackVector> vector = Cast<FeedbackVector>(current_obj);
      Tagged<SharedFunctionInfo> shared = vector->shared_function_info();

      // No need to preserve the feedback vector for non-user-visible functions.
      if (!shared->IsSubjectToDebugging()) continue;

      vectors.emplace_back(vector, this);
    }
  }

  // Add collected feedback vectors to the root list lest we lose them to GC.
  Handle<ArrayList> list =
      ArrayList::New(this, static_cast<int>(vectors.size()));
  for (const auto& vector : vectors) list = ArrayList::Add(this, list, vector);
  SetFeedbackVectorsForProfilingTools(*list);
}

void Isolate::set_date_cache(DateCache* date_cache) {
  if (date_cache != date_cache_) {
    delete date_cache_;
  }
  date_cache_ = date_cache;
}

Isolate::KnownPrototype Isolate::IsArrayOrObjectOrStringPrototype(
    Tagged<JSObject> object) {
  Tagged<Map> metamap = object->map(this)->map(this);
  Tagged<NativeContext> native_context = metamap->native_context();
  if (native_context->initial_object_prototype() == object) {
    return KnownPrototype::kObject;
  } else if (native_context->initial_array_prototype() == object) {
    return KnownPrototype::kArray;
  } else if (native_context->initial_string_prototype() == object) {
    return KnownPrototype::kString;
  }
  return KnownPrototype::kNone;
}

bool Isolate::IsInCreationContext(Tagged<JSObject> object, uint32_t index) {
  DisallowGarbageCollection no_gc;
  Tagged<Map> metamap = object->map(this)->map(this);
  // Filter out native-context independent objects.
  if (metamap == ReadOnlyRoots(this).meta_map()) return false;
  Tagged<NativeContext> native_context = metamap->native_context();
  return native_context->get(index) == object;
}

void Isolate::UpdateNoElementsProtectorOnSetElement(
    DirectHandle<JSObject> object) {
  DisallowGarbageCollection no_gc;
  if (!object->map()->is_prototype_map()) return;
  if (!Protectors::IsNoElementsIntact(this)) return;
  KnownPrototype obj_type = IsArrayOrObjectOrStringPrototype(*object);
  if (obj_type == KnownPrototype::kNone) return;
  if (obj_type == KnownPrototype::kObject) {
    this->CountUsage(v8::Isolate::kObjectPrototypeHasElements);
  } else if (obj_type == KnownPrototype::kArray) {
    this->CountUsage(v8::Isolate::kArrayPrototypeHasElements);
  }
  Protectors::InvalidateNoElements(this);
}

void Isolate::UpdateProtectorsOnSetPrototype(
    DirectHandle<JSObject> object, DirectHandle<Object> new_prototype) {
  UpdateNoElementsProtectorOnSetPrototype(object);
  UpdateTypedArraySpeciesLookupChainProtectorOnSetPrototype(object);
  UpdateNumberStringNotRegexpLikeProtectorOnSetPrototype(object);
  UpdateStringWrapperToPrimitiveProtectorOnSetPrototype(object, new_prototype);
}

void Isolate::UpdateTypedArraySpeciesLookupChainProtectorOnSetPrototype(
    DirectHandle<JSObject> object) {
  // Setting the __proto__ of TypedArray constructor could change TypedArray's
  // @@species. So we need to invalidate the @@species protector.
  if (IsTypedArrayConstructor(*object) &&
      Protectors::IsTypedArraySpeciesLookupChainIntact(this)) {
    Protectors::InvalidateTypedArraySpeciesLookupChain(this);
  }
}

void Isolate::UpdateNumberStringNotRegexpLikeProtectorOnSetPrototype(
    DirectHandle<JSObject> object) {
  if (!Protectors::IsNumberStringNotRegexpLikeIntact(this)) {
    return;
  }
  // We need to protect the prototype chain of `Number.prototype` and
  // `String.prototype`.
  // Since `Object.prototype.__proto__` is not writable, we can assume it
  // doesn't occur here. We detect `Number.prototype` and `String.prototype` by
  // checking for a prototype that is a JSPrimitiveWrapper. This is a safe
  // approximation. Using JSPrimitiveWrapper as prototype should be
  // sufficiently rare.
  DCHECK(!IsJSObjectPrototype(*object));
  if (object->map()->is_prototype_map() && (IsJSPrimitiveWrapper(*object))) {
    Protectors::InvalidateNumberStringNotRegexpLike(this);
  }
}

void Isolate::UpdateStringWrapperToPrimitiveProtectorOnSetPrototype(
    DirectHandle<JSObject> object, DirectHandle<Object> new_prototype) {
  if (!Protectors::IsStringWrapperToPrimitiveIntact(this)) {
    return;
  }

  // We can have a custom @@toPrimitive on a string wrapper also if we subclass
  // String and the subclass (or one of its subclasses) defines its own
  // @@toPrimive. Thus we invalidate the protector whenever we detect
  // subclassing String - it should be reasonably rare.
  if (IsStringWrapper(*object) || IsStringWrapper(*new_prototype)) {
    Protectors::InvalidateStringWrapperToPrimitive(this);
  }
}

static base::RandomNumberGenerator* ensure_rng_exists(
    base::RandomNumberGenerator** rng, int seed) {
  if (*rng == nullptr) {
    if (seed != 0) {
      *rng = new base::RandomNumberGenerator(seed);
    } else {
      *rng = new base::RandomNumberGenerator();
    }
  }
  return *rng;
}

base::RandomNumberGenerator* Isolate::random_number_generator() {
  // TODO(bmeurer) Initialized lazily because it depends on flags; can
  // be fixed once the default isolate cleanup is done.
  return ensure_rng_exists(&random_number_generator_, v8_flags.random_seed);
}

base::RandomNumberGenerator* Isolate::fuzzer_rng() {
  if (fuzzer_rng_ == nullptr) {
    int64_t seed = v8_flags.fuzzer_random_seed;
    if (seed == 0) {
      seed = random_number_generator()->initial_seed();
    }

    fuzzer_rng_ = new base::RandomNumberGenerator(seed);
  }

  return fuzzer_rng_;
}

int Isolate::GenerateIdentityHash(uint32_t mask) {
  int hash;
  int attempts = 0;
  do {
    hash = random_number_generator()->NextInt() & mask;
  } while (hash == 0 && attempts++ < 30);
  return hash != 0 ? hash : 1;
}

#ifdef DEBUG
#define ISOLATE_FIELD_OFFSET(type, name, ignored) \
  const intptr_t Isolate::name##_debug_offset_ = OFFSET_OF(Isolate, name##_);
ISOLATE_INIT_LIST(ISOLATE_FIELD_OFFSET)
ISOLATE_INIT_ARRAY_LIST(ISOLATE_FIELD_OFFSET)
#undef ISOLATE_FIELD_OFFSET
#endif

Handle<Symbol> Isolate::SymbolFor(RootIndex dictionary_index,
                                  Handle<String> name, bool private_symbol) {
  Handle<String> key = factory()->InternalizeString(name);
  Handle<RegisteredSymbolTable> dictionary =
      Cast<RegisteredSymbolTable>(root_handle(dictionary_index));
  InternalIndex entry = dictionary->FindEntry(this, key);
  Handle<Symbol> symbol;
  if (entry.is_not_found()) {
    symbol =
        private_symbol ? factory()->NewPrivateSymbol() : factory()->NewSymbol();
    symbol->set_description(*key);
    dictionary = RegisteredSymbolTable::Add(this, dictionary, key, symbol);

    switch (dictionary_index) {
      case RootIndex::kPublicSymbolTable:
        symbol->set_is_in_public_symbol_table(true);
        heap()->set_public_symbol_table(*dictionary);
        break;
      case RootIndex::kApiSymbolTable:
        heap()->set_api_symbol_table(*dictionary);
        break;
      case RootIndex::kApiPrivateSymbolTable:
        heap()->set_api_private_symbol_table(*dictionary);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    symbol = Handle<Symbol>(Cast<Symbol>(dictionary->ValueAt(entry)), this);
  }
  return symbol;
}

void Isolate::AddBeforeCallEnteredCallback(BeforeCallEnteredCallback callback) {
  auto pos = std::find(before_call_entered_callbacks_.begin(),
                       before_call_entered_callbacks_.end(), callback);
  if (pos != before_call_entered_callbacks_.end()) return;
  before_call_entered_callbacks_.push_back(callback);
}

void Isolate::RemoveBeforeCallEnteredCallback(
    BeforeCallEnteredCallback callback) {
  auto pos = std::find(before_call_entered_callbacks_.begin(),
                       before_call_entered_callbacks_.end(), callback);
  if (pos == before_call_entered_callbacks_.end()) return;
  before_call_entered_callbacks_.erase(pos);
}

void Isolate::AddCallCompletedCallback(CallCompletedCallback callback) {
  auto pos = std::find(call_completed_callbacks_.begin(),
                       call_completed_callbacks_.end(), callback);
  if (pos != call_completed_callbacks_.end()) return;
  call_completed_callbacks_.push_back(callback);
}

void Isolate::RemoveCallCompletedCallback(CallCompletedCallback callback) {
  auto pos = std::find(call_completed_callbacks_.begin(),
                       call_completed_callbacks_.end(), callback);
  if (pos == call_completed_callbacks_.end()) return;
  call_completed_callbacks_.erase(pos);
}

void Isolate::FireCallCompletedCallbackInternal(
    MicrotaskQueue* microtask_queue) {
  DCHECK(thread_local_top()->CallDepthIsZero());

  bool perform_checkpoint =
      microtask_queue &&
      microtask_queue->microtasks_policy() == v8::MicrotasksPolicy::kAuto &&
      !is_execution_terminating();

  v8::Isolate* isolate = reinterpret_cast<v8::Isolate*>(this);
  if (perform_checkpoint) microtask_queue->PerformCheckpoint(isolate);

  if (call_completed_callbacks_.empty()) return;
  // Fire callbacks.  Increase call depth to prevent recursive callbacks.
  v8::Isolate::SuppressMicrotaskExecutionScope suppress(isolate);
  std::vector<CallCompletedCallback> callbacks(call_completed_callbacks_);
  for (auto& callback : callbacks) {
    callback(reinterpret_cast<v8::Isolate*>(this));
  }
}

#ifdef V8_ENABLE_WEBASSEMBLY
void Isolate::WasmInitJSPIFeature() {
  if (IsUndefined(root(RootIndex::kActiveContinuation))) {
    wasm::StackMemory* stack(wasm::StackMemory::GetCentralStackView(this));
    this->wasm_stacks().emplace_back(stack);
    stack->set_index(0);
    if (v8_flags.trace_wasm_stack_switching) {
      PrintF("Set up native stack object (limit: %p, base: %p)\n",
             stack->jslimit(), reinterpret_cast<void*>(stack->base()));
    }
    HandleScope scope(this);
    DirectHandle<WasmContinuationObject> continuation =
        WasmContinuationObject::New(this, stack, wasm::JumpBuffer::Active,
                                    AllocationType::kOld);
    heap()
        ->roots_table()
        .slot(RootIndex::kActiveContinuation)
        .store(*continuation);
  }
}
#endif

void Isolate::UpdatePromiseHookProtector() {
  if (Protectors::IsPromiseHookIntact(this)) {
    HandleScope scope(this);
    Protectors::InvalidatePromiseHook(this);
  }
}

void Isolate::PromiseHookStateUpdated() {
  promise_hook_flags_ =
      (promise_hook_flags_ & PromiseHookFields::HasContextPromiseHook::kMask) |
      PromiseHookFields::HasIsolatePromiseHook::encode(promise_hook_) |
      PromiseHookFields::HasAsyncEventDelegate::encode(async_event_delegate_) |
      PromiseHookFields::IsDebugActive::encode(debug()->is_active());

  if (promise_hook_flags_ != 0) {
    UpdatePromiseHookProtector();
  }
}

namespace {

MaybeHandle<JSPromise> NewRejectedPromise(Isolate* isolate,
                                          v8::Local<v8::Context> api_context,
                                          Handle<Object> exception) {
  v8::Local<v8::Promise::Resolver> resolver;
  API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, resolver,
                                       v8::Promise::Resolver::New(api_context),
                                       MaybeHandle<JSPromise>());

  MAYBE_RETURN_ON_EXCEPTION_VALUE(
      isolate, resolver->Reject(api_context, v8::Utils::ToLocal(exception)),
      MaybeHandle<JSPromise>());

  v8::Local<v8::Promise> promise = resolver->GetPromise();
  return v8::Utils::OpenHandle(*promise);
}

}  // namespace

MaybeHandle<JSPromise> Isolate::RunHostImportModuleDynamicallyCallback(
    MaybeHandle<Script> maybe_referrer, Handle<Object> specifier,
    ModuleImportPhase phase,
    MaybeHandle<Object> maybe_import_options_argument) {
  DCHECK(!is_execution_terminating());
  v8::Local<v8::Context> api_context = v8::Utils::ToLocal(native_context());
  if (host_import_module_dynamically_callback_ == nullptr) {
    Handle<Object> exception =
        factory()->NewError(error_function(), MessageTemplate::kUnsupported);
    return NewRejectedPromise(this, api_context, exception);
  }

  Handle<String> specifier_str;
  MaybeHandle<String> maybe_specifier = Object::ToString(this, specifier);
  if (!maybe_specifier.ToHandle(&specifier_str)) {
    if (is_execution_terminating()) {
      return MaybeHandle<JSPromise>();
    }
    Handle<Object> exception(this->exception(), this);
    clear_exception();
    return NewRejectedPromise(this, api_context, exception);
  }
  DCHECK(!has_exception());

  v8::Local<v8::Promise> promise;
  Handle<FixedArray> import_attributes_array;
  if (!GetImportAttributesFromArgument(maybe_import_options_argument)
           .ToHandle(&import_attributes_array)) {
    if (is_execution_terminating()) {
      return MaybeHandle<JSPromise>();
    }
    Handle<Object> exception(this->exception(), this);
    clear_exception();
    return NewRejectedPromise(this, api_context, exception);
  }
  Handle<FixedArray> host_defined_options;
  Handle<Object> resource_name;
  if (maybe_referrer.is_null()) {
    host_defined_options = factory()->empty_fixed_array();
    resource_name = factory()->null_value();
  } else {
    DirectHandle<Script> referrer = maybe_referrer.ToHandleChecked();
    host_defined_options = handle(referrer->host_defined_options(), this);
    resource_name = handle(referrer->name(), this);
  }

  switch (phase) {
    case ModuleImportPhase::kEvaluation:
      // TODO(42204365): Deprecate HostImportModuleDynamicallyCallback once
      // HostImportModuleWithPhaseDynamicallyCallback is stable.
      API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          this, promise,
          host_import_module_dynamically_callback_(
              api_context, v8::Utils::ToLocal(host_defined_options),
              v8::Utils::ToLocal(resource_name),
              v8::Utils::ToLocal(specifier_str),
              ToApiHandle<v8::FixedArray>(import_attributes_array)),
          MaybeHandle<JSPromise>());
      break;
    case ModuleImportPhase::kSource:
      CHECK(v8_flags.js_source_phase_imports);
      CHECK_NOT_NULL(host_import_module_with_phase_dynamically_callback_);
      API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          this, promise,
          host_import_module_with_phase_dynamically_callback_(
              api_context, v8::Utils::ToLocal(host_defined_options),
              v8::Utils::ToLocal(resource_name),
              v8::Utils::ToLocal(specifier_str), phase,
              ToApiHandle<v8::FixedArray>(import_attributes_array)),
          MaybeHandle<JSPromise>());
      break;
    default:
      UNREACHABLE();
  }

  return v8::Utils::OpenHandle(*promise);
}

MaybeHandle<FixedArray> Isolate::GetImportAttributesFromArgument(
    MaybeHandle<Object> maybe_import_options_argument) {
  Handle<FixedArray> import_attributes_array = factory()->empty_fixed_array();
  Handle<Object> import_options_argument;
  if (!maybe_import_options_argument.ToHandle(&import_options_argument) ||
      IsUndefined(*import_options_argument)) {
    return import_attributes_array;
  }

  // The parser shouldn't have allowed the second argument to import() if
  // the flag wasn't enabled.
  DCHECK(v8_flags.harmony_import_attributes);

  if (!IsJSReceiver(*import_options_argument)) {
    this->Throw(
        *factory()->NewTypeError(MessageTemplate::kNonObjectImportArgument));
    return MaybeHandle<FixedArray>();
  }

  Handle<JSReceiver> import_options_argument_receiver =
      Cast<JSReceiver>(import_options_argument);

  Handle<Object> import_attributes_object;

  if (v8_flags.harmony_import_attributes) {
    Handle<Name> with_key = factory()->with_string();
    if (!JSReceiver::GetProperty(this, import_options_argument_receiver,
                                 with_key)
             .ToHandle(&import_attributes_object)) {
      // This can happen if the property has a getter function that throws
      // an error.
      return MaybeHandle<FixedArray>();
    }
  }

  // If there is no 'with' option in the options bag, it's not an error. Just do
  // the import() as if no attributes were provided.
  if (IsUndefined(*import_attributes_object)) return import_attributes_array;

  if (!IsJSReceiver(*import_attributes_object)) {
    this->Throw(
        *factory()->NewTypeError(MessageTemplate::kNonObjectAttributesOption));
    return MaybeHandle<FixedArray>();
  }

  Handle<JSReceiver> import_attributes_object_receiver =
      Cast<JSReceiver>(import_attributes_object);

  Handle<FixedArray> attribute_keys;
  if (!KeyAccumulator::GetKeys(this, import_attributes_object_receiver,
                               KeyCollectionMode::kOwnOnly, ENUMERABLE_STRINGS,
                               GetKeysConversion::kConvertToString)
           .ToHandle(&attribute_keys)) {
    // This happens if the attributes object is a Proxy whose ownKeys() or
    // getOwnPropertyDescriptor() trap throws.
    return MaybeHandle<FixedArray>();
  }

  bool has_non_string_attribute = false;

  // The attributes will be passed to the host in the form: [key1,
  // value1, key2, value2, ...].
  constexpr size_t kAttributeEntrySizeForDynamicImport = 2;
  import_attributes_array = factory()->NewFixedArray(static_cast<int>(
      attribute_keys->length() * kAttributeEntrySizeForDynamicImport));
  for (int i = 0; i < attribute_keys->length(); i++) {
    Handle<String> attribute_key(Cast<String>(attribute_keys->get(i)), this);
    Handle<Object> attribute_value;
    if (!Object::GetPropertyOrElement(this, import_attributes_object_receiver,
                                      attribute_key)
             .ToHandle(&attribute_value)) {
      // This can happen if the property has a getter function that throws
      // an error.
      return MaybeHandle<FixedArray>();
    }

    if (!IsString(*attribute_value)) {
      has_non_string_attribute = true;
    }

    import_attributes_array->set((i * kAttributeEntrySizeForDynamicImport),
                                 *attribute_key);
    import_attributes_array->set((i * kAttributeEntrySizeForDynamicImport) + 1,
                                 *attribute_value);
  }

  if (has_non_string_attribute) {
    this->Throw(*factory()->NewTypeError(
        MessageTemplate::kNonStringImportAttributeValue));
    return MaybeHandle<FixedArray>();
  }

  return import_attributes_array;
}

void Isolate::ClearKeptObjects() { heap()->ClearKeptObjects(); }

void Isolate::SetHostImportModuleDynamicallyCallback(
    HostImportModuleDynamicallyCallback callback) {
  host_import_module_dynamically_callback_ = callback;
}

void Isolate::SetHostImportModuleWithPhaseDynamicallyCallback(
    HostImportModuleWithPhaseDynamicallyCallback callback) {
  host_import_module_with_phase_dynamically_callback_ = callback;
}

MaybeHandle<JSObject> Isolate::RunHostInitializeImportMetaObjectCallback(
    Handle<SourceTextModule> module) {
  CHECK(IsTheHole(module->import_meta(kAcquireLoad), this));
  Handle<JSObject> import_meta = factory()->NewJSObjectWithNullProto();
  if (host_initialize_import_meta_object_callback_ != nullptr) {
    v8::Local<v8::Context> api_context = v8::Utils::ToLocal(native_context());
    host_initialize_import_meta_object_callback_(
        api_context, Utils::ToLocal(Cast<Module>(module)),
        v8::Local<v8::Object>::Cast(v8::Utils::ToLocal(import_meta)));
    if (has_exception()) return {};
  }
  return import_meta;
}

void Isolate::SetHostInitializeImportMetaObjectCallback(
    HostInitializeImportMetaObjectCallback callback) {
  host_initialize_import_meta_object_callback_ = callback;
}

void Isolate::SetHostCreateShadowRealmContextCallback(
    HostCreateShadowRealmContextCallback callback) {
  host_create_shadow_realm_context_callback_ = callback;
}

MaybeHandle<NativeContext> Isolate::RunHostCreateShadowRealmContextCallback() {
  if (host_create_shadow_realm_context_callback_ == nullptr) {
    DirectHandle<Object> exception =
        factory()->NewError(error_function(), MessageTemplate::kUnsupported);
    Throw(*exception);
    return kNullMaybeHandle;
  }

  v8::Local<v8::Context> api_context = v8::Utils::ToLocal(native_context());
  v8::Local<v8::Context> shadow_realm_context;
  API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      this, shadow_realm_context,
      host_create_shadow_realm_context_callback_(api_context),
      MaybeHandle<NativeContext>());
  Handle<Context> shadow_realm_context_handle =
      v8::Utils::OpenHandle(*shadow_realm_context);
  DCHECK(IsNativeContext(*shadow_realm_context_handle));
  shadow_realm_context_handle->set_scope_info(
      ReadOnlyRoots(this).shadow_realm_scope_info());
  return Cast<NativeContext>(shadow_realm_context_handle);
}

MaybeHandle<Object> Isolate::RunPrepareStackTraceCallback(
    Handle<NativeContext> context, Handle<JSObject> error,
    Handle<JSArray> sites) {
  v8::Local<v8::Context> api_context = Utils::ToLocal(context);

  v8::Local<v8::Value> stack;
  API_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      this, stack,
      prepare_stack_trace_callback_(api_context, Utils::ToLocal(error),
                                    Utils::ToLocal(sites)),
      MaybeHandle<Object>());
  return Utils::OpenHandle(*stack);
}

int Isolate::LookupOrAddExternallyCompiledFilename(const char* filename) {
  if (embedded_file_writer_ != nullptr) {
    return embedded_file_writer_->LookupOrAddExternallyCompiledFilename(
        filename);
  }
  return 0;
}

const char* Isolate::GetExternallyCompiledFilename(int index) const {
  if (embedded_file_writer_ != nullptr) {
    return embedded_file_writer_->GetExternallyCompiledFilename(index);
  }
  return "";
}

int Isolate::GetExternallyCompiledFilenameCount() const {
  if (embedded_file_writer_ != nullptr) {
    return embedded_file_writer_->GetExternallyCompiledFilenameCount();
  }
  return 0;
}

void Isolate::PrepareBuiltinSourcePositionMap() {
  if (embedded_file_writer_ != nullptr) {
    return embedded_file_writer_->PrepareBuiltinSourcePositionMap(
        this->builtins());
  }
}

#if defined(V8_OS_WIN64)
void Isolate::SetBuiltinUnwindData(
    Builtin builtin,
    const win64_unwindinfo::BuiltinUnwindInfo& unwinding_info) {
  if (embedded_file_writer_ != nullptr) {
    embedded_file_writer_->SetBuiltinUnwindData(builtin, unwinding_info);
  }
}
#endif  // V8_OS_WIN64

void Isolate::SetPrepareStackTraceCallback(PrepareStackTraceCallback callback) {
  prepare_stack_trace_callback_ = callback;
}

bool Isolate::HasPrepareStackTraceCallback() const {
  return prepare_stack_trace_callback_ != nullptr;
}

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
void Isolate::SetFilterETWSessionByURLCallback(
    FilterETWSessionByURLCallback callback) {
  filter_etw_session_by_url_callback_ = callback;
}

bool Isolate::RunFilterETWSessionByURLCallback(
    const std::string& etw_filter_payload) {
  if (!filter_etw_session_by_url_callback_) return true;
  v8::Local<v8::Context> context = Utils::ToLocal(native_context());
  return filter_etw_session_by_url_callback_(context, etw_filter_payload);
}
#endif  // V8_OS_WIN && V8_ENABLE_ETW_STACK_WALKING

void Isolate::SetAddCrashKeyCallback(AddCrashKeyCallback callback) {
  add_crash_key_callback_ = callback;

  // Log the initial set of data.
  AddCrashKeysForIsolateAndHeapPointers();
}

void Isolate::SetAtomicsWaitCallback(v8::Isolate::AtomicsWaitCallback callback,
                                     void* data) {
  atomics_wait_callback_ = callback;
  atomics_wait_callback_data_ = data;
}

void Isolate::RunAtomicsWaitCallback(v8::Isolate::AtomicsWaitEvent event,
                                     Handle<JSArrayBuffer> array_buffer,
                                     size_t offset_in_bytes, int64_t value,
                                     double timeout_in_ms,
                                     AtomicsWaitWakeHandle* stop_handle) {
  DCHECK(array_buffer->is_shared());
  if (atomics_wait_callback_ == nullptr) return;
  HandleScope handle_scope(this);
  atomics_wait_callback_(
      event, v8::Utils::ToLocalShared(array_buffer), offset_in_bytes, value,
      timeout_in_ms,
      reinterpret_cast<v8::Isolate::AtomicsWaitWakeHandle*>(stop_handle),
      atomics_wait_callback_data_);
}

void Isolate::SetPromiseHook(PromiseHook hook) {
  promise_hook_ = hook;
  PromiseHookStateUpdated();
}

void Isolate::RunAllPromiseHooks(PromiseHookType type,
                                 Handle<JSPromise> promise,
                                 Handle<Object> parent) {
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  if (HasContextPromiseHooks()) {
    native_context()->RunPromiseHook(type, promise, parent);
  }
#endif
  if (HasIsolatePromiseHooks() || HasAsyncEventDelegate()) {
    RunPromiseHook(type, promise, parent);
  }
}

void Isolate::RunPromiseHook(PromiseHookType type, Handle<JSPromise> promise,
                             Handle<Object> parent) {
  if (!HasIsolatePromiseHooks()) return;
  DCHECK(promise_hook_ != nullptr);
  promise_hook_(type, v8::Utils::PromiseToLocal(promise),
                v8::Utils::ToLocal(parent));
}

void Isolate::OnAsyncFunctionSuspended(Handle<JSPromise> promise,
                                       Handle<JSPromise> parent) {
  DCHECK(!promise->has_async_task_id());
  RunAllPromiseHooks(PromiseHookType::kInit, promise, parent);
  if (HasAsyncEventDelegate()) {
    DCHECK_NE(nullptr, async_event_delegate_);
    current_async_task_id_ =
        JSPromise::GetNextAsyncTaskId(current_async_task_id_);
    promise->set_async_task_id(current_async_task_id_);
    async_event_delegate_->AsyncEventOccurred(debug::kDebugAwait,
                                              promise->async_task_id(), false);
  }
}

void Isolate::OnPromiseThen(DirectHandle<JSPromise> promise) {
  if (!HasAsyncEventDelegate()) return;
  Maybe<debug::DebugAsyncActionType> action_type =
      Nothing<debug::DebugAsyncActionType>();
  for (JavaScriptStackFrameIterator it(this); !it.done(); it.Advance()) {
    std::vector<Handle<SharedFunctionInfo>> infos;
    it.frame()->GetFunctions(&infos);
    for (auto it = infos.rbegin(); it != infos.rend(); ++it) {
      DirectHandle<SharedFunctionInfo> info = *it;
      if (info->HasBuiltinId()) {
        // We should not report PromiseThen and PromiseCatch which is called
        // indirectly, e.g. Promise.all calls Promise.then internally.
        switch (info->builtin_id()) {
          case Builtin::kPromisePrototypeCatch:
            action_type = Just(debug::kDebugPromiseCatch);
            continue;
          case Builtin::kPromisePrototypeFinally:
            action_type = Just(debug::kDebugPromiseFinally);
            continue;
          case Builtin::kPromisePrototypeThen:
            action_type = Just(debug::kDebugPromiseThen);
            continue;
          default:
            return;
        }
      }
      if (info->IsUserJavaScript() && action_type.IsJust()) {
        DCHECK(!promise->has_async_task_id());
        current_async_task_id_ =
            JSPromise::GetNextAsyncTaskId(current_async_task_id_);
        promise->set_async_task_id(current_async_task_id_);
        async_event_delegate_->AsyncEventOccurred(action_type.FromJust(),
                                                  promise->async_task_id(),
                                                  debug()->IsBlackboxed(info));
      }
      return;
    }
  }
}

void Isolate::OnPromiseBefore(Handle<JSPromise> promise) {
  RunPromiseHook(PromiseHookType::kBefore, promise,
                 factory()->undefined_value());
  if (HasAsyncEventDelegate()) {
    if (promise->has_async_task_id()) {
      async_event_delegate_->AsyncEventOccurred(
          debug::kDebugWillHandle, promise->async_task_id(), false);
    }
  }
}

void Isolate::OnPromiseAfter(Handle<JSPromise> promise) {
  RunPromiseHook(PromiseHookType::kAfter, promise,
                 factory()->undefined_
```