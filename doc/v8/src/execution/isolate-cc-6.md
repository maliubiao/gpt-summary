Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `v8/src/execution/isolate.cc`. The request includes several constraints: identify if it's Torque code, relate it to JavaScript, provide examples, demonstrate code logic with inputs/outputs, mention common programming errors, and summarize the overall function as part 7 of 9.

**Plan:**

1. **High-level understanding:** Read through the code to grasp the main actions performed. The code appears to deal with initialization, teardown, and management of the `Isolate` object in V8. Key areas seem to be related to embedded blobs, snapshots, crash reporting, code ranges, and general isolate setup.
2. **Torque check:** Look for the `.tq` file extension. The provided snippet is `.cc`, so it's not Torque.
3. **JavaScript relationship:** Identify parts of the code that relate to JavaScript execution. Concepts like snapshots, builtins, and heap management directly influence how JavaScript runs.
4. **JavaScript examples:**  For relevant functionalities, provide simple JavaScript code that would trigger these actions or be affected by them.
5. **Code logic reasoning:** Select a specific function or block and create a hypothetical scenario with input and expected output.
6. **Common programming errors:**  Think about how incorrect V8 configuration or usage might lead to errors based on the code.
7. **Overall function summary:**  Condense the observed functionalities into a concise summary.
8. **Part number:** Acknowledge that this is part 7 of 9.

**Detailed Steps & Reasoning:**

* **Embedded Blob Handling (`RemapEmbeddedBuiltins`, `TearDownEmbeddedBlob`):** This relates to pre-compiled code. JavaScript benefits from faster startup due to these builtins.
* **Snapshot Initialization (`InitWithoutSnapshot`, `InitWithSnapshot`):**  Crucial for fast V8 startup. JavaScript execution heavily relies on the initial state loaded from snapshots.
* **Crash Reporting (`AddCrashKeysForIsolateAndHeapPointers`):**  Helps in debugging. While not directly related to JavaScript *execution*, it's vital for V8's stability when JavaScript crashes occur.
* **Code Range Management (`InitializeCodeRanges`):**  Related to how V8 manages memory for compiled JavaScript code.
* **Static Roots Verification (`VerifyStaticRoots`):** This is an internal consistency check. It ensures V8's read-only data structures are as expected, which is fundamental for correct JavaScript execution.
* **Isolate Initialization (`Init`):** The core function for setting up a V8 isolate. This encompasses many aspects that directly affect how JavaScript can be run.
* **Isolate Entry/Exit (`Enter`, `Exit`):** Manages the context of execution, important for multi-threading scenarios where JavaScript from different isolates might be running.
* **Statistics (`DumpAndResetStats`):** Used for internal V8 monitoring and performance analysis, less directly related to basic JavaScript functionality but important for V8 development.

**Pre-computation/Pre-analysis:**

* **Torque:**  Knowing that `.tq` files are for Torque is essential.
* **V8 Architecture:** Basic understanding of Isolates, Heaps, and Builtins is needed to make meaningful connections to JavaScript.
* **Snapshots:** Understanding how snapshots speed up V8 startup is key.

**Self-Correction/Refinement:**

* Initially, I might focus too much on low-level details. The request asks for connections to JavaScript, so I need to frame the functionalities in terms of their impact on or relation to JavaScript execution.
* The "code logic推理" part requires a specific example. I'll choose a simpler function like `TearDownEmbeddedBlob` to illustrate.
* For common programming errors, I should focus on mistakes users might make when embedding or configuring V8, rather than internal V8 errors.

By following these steps, I can generate a comprehensive and accurate answer that addresses all the user's requirements and constraints.
好的，让我们来分析一下 `v8/src/execution/isolate.cc` 代码片段的功能。

**功能列举：**

1. **重新映射内嵌 Builtins 代码 (`RemapEmbeddedBuiltins`)：**
   - 当 V8 的堆的 code range（用于存放编译后的代码）可用时，此函数会将内嵌的 Builtins 代码（例如，用于实现 `Array.prototype.map` 等原生 JavaScript 功能的代码）重新映射到该 code range 中。这有助于代码的管理和执行。
   - 它假设内嵌的 blob 代码已经加载。

2. **清理内嵌 Blob (`TearDownEmbeddedBlob`)：**
   - 此函数负责清理内嵌的 blob（Binary Large Object），其中包含 Builtins 代码和数据。
   - 它会检查内嵌 blob 的引用计数。如果引用计数降为 0 并且启用了引用计数，则会释放内嵌 blob 占用的内存。
   - 如果 blob 被嵌入到二进制文件中或未设置，则不执行任何操作。

3. **初始化 Isolate (不带快照) (`InitWithoutSnapshot`)：**
   - 提供一种初始化 V8 Isolate 的方式，而不使用预先存在的快照数据。这意味着 Isolate 将从头开始构建其堆和执行环境。

4. **初始化 Isolate (带快照) (`InitWithSnapshot`)：**
   - 提供一种使用快照数据来初始化 V8 Isolate 的方式。快照包含了堆的预先构建状态，可以显著加快 Isolate 的启动速度。
   - 需要提供启动快照、只读快照和共享堆快照数据。`can_rehash` 参数可能与哈希表的重建有关。

5. **添加 Isolate 和堆指针的崩溃键 (`AddCrashKeysForIsolateAndHeapPointers`)：**
   - 此函数用于在发生崩溃时提供调试信息。它会添加一些关键的内存地址作为崩溃报告的一部分，例如 Isolate 对象的地址、只读空间的首地址、老生代空间的首地址以及代码区域的地址。这些信息有助于开发者分析崩溃原因。

6. **初始化代码区域 (`InitializeCodeRanges`)：**
   - 初始化用于存储编译后的代码的内存区域。它将内嵌 blob 的代码区域添加到代码页的列表中。

**关于是否为 Torque 源代码：**

代码片段以 `.cc` 结尾，这意味着它是 C++ 源代码，而不是 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及 JavaScript 举例：**

`v8/src/execution/isolate.cc` 中的代码与 JavaScript 功能有着非常密切的关系，因为它直接管理着 V8 引擎的核心组件 `Isolate`。`Isolate` 是 V8 引擎中隔离的执行上下文，可以理解为一个独立的 JavaScript 虚拟机实例。

* **内嵌 Builtins 代码 (`RemapEmbeddedBuiltins`)：**  这直接关系到 JavaScript 内置对象和函数的实现。例如，`Array.prototype.map`、`String.prototype.toUpperCase` 等方法的实现就可能存在于这些内嵌的 Builtins 代码中。

   ```javascript
   // 当你调用 Array.prototype.map 时，V8 引擎会执行内嵌的 Builtins 代码。
   const numbers = [1, 2, 3];
   const doubled = numbers.map(x => x * 2);
   console.log(doubled); // 输出: [2, 4, 6]
   ```

* **快照初始化 (`InitWithSnapshot`)：**  快照使得 V8 能够快速启动，因为许多 JavaScript 的内置对象和函数都已经预先创建并存储在快照中。这避免了每次启动时都重新创建它们的开销。

   ```javascript
   // V8 启动时会加载快照，其中包含了 String、Array 等内置对象的原型和构造函数。
   const str = "hello"; // String 对象可能在快照中就已经部分初始化。
   const arr = [];     // Array 对象也类似。
   ```

* **崩溃键 (`AddCrashKeysForIsolateAndHeapPointers`)：** 虽然不直接影响 JavaScript 的执行逻辑，但在 JavaScript 代码导致 V8 崩溃时，这些信息对于诊断错误至关重要。例如，一个无限循环或内存泄漏可能导致崩溃，而崩溃键可以帮助 V8 开发者定位问题发生时的内存状态。

**代码逻辑推理（假设输入与输出）：**

**函数:** `TearDownEmbeddedBlob`

**假设输入：**
- `enable_embedded_blob_refcounting_` 为 `true`
- `current_embedded_blob_refs_` 的初始值为 `1`
- 内嵌 blob 代码和数据已分配 (`CurrentEmbeddedBlobCode()` 和 `CurrentEmbeddedBlobData()` 返回非空指针)

**执行过程：**
1. `current_embedded_blob_refs_` 减 1，变为 `0`。
2. 因为 `current_embedded_blob_refs_` 等于 `0` 并且 `enable_embedded_blob_refcounting_` 为 `true`，所以条件成立。
3. 调用 `OffHeapInstructionStream::FreeOffHeapOffHeapInstructionStream` 来释放内嵌 blob 代码和数据占用的内存。
4. 调用 `ClearEmbeddedBlob()` 清空内嵌 blob 的相关指针。

**预期输出：**
- 内嵌 blob 占用的内存被释放。
- `CurrentEmbeddedBlobCode()` 和 `CurrentEmbeddedBlobData()` 将返回空指针。

**涉及用户常见的编程错误：**

这个代码片段本身更多的是 V8 引擎的内部实现，直接与用户编写的 JavaScript 交互较少。然而，理解其背后的概念可以帮助避免一些与性能相关的错误：

* **过度依赖全局状态或意外修改内置对象原型：** 虽然 V8 提供了隔离的 `Isolate`，但在某些嵌入场景下，如果错误地跨 Isolate 共享状态或修改内置对象的原型（例如 `Array.prototype`），可能会导致不可预测的行为，甚至崩溃。虽然 `Isolate` 提供了隔离，但在使用 V8 API 时，仍然需要小心管理对象和状态的生命周期。

   ```javascript
   // 这是一个不推荐的做法，可能会影响其他使用 Array 的代码。
   Array.prototype.myCustomMethod = function() {
       return 'custom';
   };

   const arr = [1, 2];
   console.log(arr.myCustomMethod());
   ```

* **内存泄漏：**  虽然 V8 有垃圾回收机制，但在某些情况下（例如，在 native 代码中持有 JavaScript 对象的引用但没有正确释放），仍然可能发生内存泄漏。理解 V8 的堆管理和快照机制有助于识别潜在的内存问题。

**第 7 部分功能归纳：**

这段代码主要负责 V8 `Isolate` 对象生命周期中的关键阶段，包括：

- **优化代码执行:** 通过重新映射内嵌 Builtins 代码到 code range，提高代码执行效率。
- **资源管理:**  清理内嵌 blob 占用的资源，避免内存泄漏。
- **快速启动:** 提供使用快照数据初始化 Isolate 的机制，加速 V8 引擎的启动过程。
- **崩溃诊断:**  在发生崩溃时收集关键的内存地址信息，方便开发者进行调试和问题定位。
- **内存布局管理:** 初始化代码区域，管理编译后的 JavaScript 代码的存储。

总而言之，这部分代码是 `v8/src/execution/isolate.cc` 中关于 `Isolate` 对象初始化、资源管理和错误处理的重要组成部分，直接影响着 V8 引擎的性能、稳定性和可调试性。

### 提示词
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  // TODO(7424): There is no publi
```