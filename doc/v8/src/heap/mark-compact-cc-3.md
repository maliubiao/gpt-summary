Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/heap/mark-compact.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename "mark-compact.cc" strongly suggests this code is part of the mark-compact garbage collection algorithm in V8.

2. **Analyze the Top-Level Function:** The snippet starts within a function, likely a method of the `MarkCompactCollector` class. The context suggests this is happening *after* the marking phase, as it checks `was_marked_incrementally`.

3. **Examine Key Operations:** Look for the actions being performed. Keywords like "Clear," "Transition," "Process," "Mark," "Sweep," and "Filter" are important. Also note the use of job queues (`ParallelClearingJob`).

4. **Identify Data Structures and Components:**  Pay attention to the data structures being manipulated (e.g., string tables, weak reference lists, map transitions, code objects) and V8 components involved (e.g., `Isolate`, `Heap`, `GCTracer`).

5. **Group Related Operations:** Cluster the identified actions into logical phases or stages. For example, clearing string tables seems to be a distinct phase.

6. **Consider Parallelism:** The use of `ParallelClearingJob` indicates that some operations are performed concurrently to improve performance.

7. **Connect to GC Concepts:** Relate the observed operations to the standard phases of a mark-compact GC algorithm (marking, sweeping, compaction - although compaction isn't explicitly in this snippet). This snippet focuses heavily on the "clear" phase after marking.

8. **Address Specific Instructions:**
    * **`.tq` extension:** State that this is not a Torque file.
    * **JavaScript relation:** Find aspects that directly impact JavaScript execution (e.g., clearing weak references to JavaScript objects, flushing bytecode).
    * **Code logic/inference:** Look for conditional logic and its implications.
    * **Common programming errors:**  Think about potential issues related to memory management and weak references.
    * **Part of a larger process:** Acknowledge that this is a stage within a broader GC cycle.

9. **Synthesize a Summary:**  Combine the findings into a concise description of the code's role.

**Pre-computation and Pre-analysis (Internal Thought Process):**

* **Incrementality:** The check for `was_marked_incrementally` indicates this part of the code handles the completion of both full and incremental marking.
* **Clearing:** The presence of multiple "Clear" operations suggests the primary focus is on removing dead objects and associated metadata.
* **Weak References:**  The emphasis on clearing weak references is a key aspect of garbage collection, ensuring that objects only held weakly are collected.
* **String Interning:** The manipulation of string tables is related to how V8 optimizes string storage.
* **Code Flushing:** The actions involving bytecode and code objects relate to reclaiming memory used by compiled JavaScript code that is no longer needed.
* **Parallelism:** The job-based approach suggests an attempt to optimize GC performance by utilizing multiple threads.

By following these steps and considering the underlying principles of garbage collection, I can generate a comprehensive summary that addresses all aspects of the user's request.
这是 v8 源代码文件 `v8/src/heap/mark-compact.cc` 的一部分，主要负责 **标记-压缩垃圾回收算法中的清除（Clearing）阶段**。  这是在标记阶段之后执行的，目的是回收未被标记的、不再使用的内存。

根据您提供的代码片段，以下是其主要功能点的归纳：

**核心功能：清除（Clearing）非活动对象和关联数据结构**

1. **完成标记阶段的收尾工作:**
   - 如果是增量标记，则禁用标记屏障 (`MarkingBarrier::DeactivateAll`)。
   - 设置 `TracedHandles` 状态为非标记 (`SetIsMarking(false)`)。
   - 递增垃圾回收的 epoch 计数器。

2. **并行清除任务调度 (`ParallelClearingJob`):**
   - 使用 `v8::JobTask` 创建并管理并行执行的清除任务，提高清除阶段的效率。
   - 实现了 `GetMaxConcurrency` 来控制并行任务的最大并发数。
   - 提供了 `Add` 方法来添加需要并行执行的清除项。

3. **清除字符串表 (`ClearStringTableJobItem`):**
   - 针对字符串表进行清理，移除只被字符串表引用的字符串。
   - 使用 `InternalizedStringTableCleaner` 遍历并删除不再需要的字符串。
   - 可以并行执行。

4. **清除字符串转发表 (`FullStringForwardingTableCleaner`):**
   - 将转发表中的字符串转换为 `ThinString` 或 `ExternalString`，并在之后清空转发表。
   - 在执行带有栈的垃圾回收时，会采取更保守的策略，标记转发对象以保持其存活，并在之后更新已迁移对象的条目。

5. **清除共享结构体类型注册表 (`ClearSharedStructTypeRegistryJobItem`):**
   - 清理共享空间中存储的 `SharedStructTypeRegistry`，移除未被标记的 `Map` 对象。
   - 可以并行执行。

6. **清除简单弱引用 (`MarkCompactCollector::ClearTrivialWeakRefJobItem`):**
   - 并行地清除那些目标对象明显已经死亡的简单弱引用。

7. **过滤非简单弱引用 (`MarkCompactCollector::FilterNonTrivialWeakRefJobItem`):**
   - 并行地过滤那些需要更复杂处理的非简单弱引用。

8. **清除非活动引用 (`ClearNonLiveReferences`):**
   - 这是清除阶段的核心函数，它协调执行各种清除操作。
   - 清除字符串转发表。
   - 清除 `Isolate::topmost_script_having_context` 中不再活动的脚本上下文引用。
   - 启动并行任务来清除字符串表和共享结构体类型注册表。
   - 清除外部字符串表。
   - 清除弱全局句柄和跟踪句柄中不再引用的对象。
   - 处理被刷新的字节码（`ProcessFlushedBaselineCandidates`，`ClearFlushedJsFunctions`）。
   - 处理弱列表中的弱引用 (`heap_->ProcessAllWeakReferences`)。
   - 清除 Maps 的全映射转换 (`ClearFullMapTransitions`)。
   - 弱化记录的强 `DescriptorArray` 对象 (`WeakenStrongDescriptorArrays`)。
   - 启动并行任务来清除简单弱引用和过滤非简单弱引用。
   - 清理外部指针表、可信指针表和代码指针表 (在开启相应编译选项时)。
   - 等待过滤非简单弱引用的并行任务完成。
   - 处理非简单弱引用 (`ClearNonTrivialWeakReferences`)、弱集合 (`ClearWeakCollections`) 和 JS 弱引用 (`ClearJSWeakRefs`)。
   - 标记依赖代码进行反优化 (`MarkDependentCodeForDeoptimization`)。
   - 等待所有并行清除任务完成。
   - 在启用了 `sticky_mark_bits` 特性时，取消激活主要的垃圾回收正在进行标志。
   - 断言各种弱对象列表为空，表示清除工作已完成。

9. **标记依赖代码进行反优化 (`MarkDependentCodeForDeoptimization`):**
   - 检查是否有被弱引用的代码对象，如果其引用的对象未被标记，则标记该代码对象进行反优化。

10. **清除潜在的简单 Map 转换 (`ClearPotentialSimpleMapTransition`):**
    - 当一个 Map 对象不再存活时，会检查是否存在指向它的简单 Map 转换，并清理这些转换。

11. **特殊清除 Map 插槽 (`SpecialClearMapSlot`):**
    - 针对特定类型的 Map 插槽（例如字段类型）进行特殊处理，以避免错误地重新学习字段类型。

12. **从 SFI 中刷新字节码 (`FlushBytecodeFromSFI`):**
    - 当 `SharedFunctionInfo` 中的字节码需要被刷新时，将其替换为 `UncompiledData` 对象，并清理相关的内存和引用。

**关于您的问题中的其他点：**

* **`.tq` 结尾：**  `v8/src/heap/mark-compact.cc` 以 `.cc` 结尾，这是一个标准的 C++ 源文件。因此，它不是一个 V8 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

* **与 Javascript 的功能关系：**  这段代码直接关系到 Javascript 的内存管理。垃圾回收是 Javascript 引擎的核心组成部分，用于自动回收不再使用的对象，防止内存泄漏。清除阶段负责识别和回收这些不再需要的对象，包括：
    * **Javascript 对象：** 清除不再被强引用的 Javascript 对象。
    * **字符串：** 清理不再使用的字符串，包括内部化字符串和外部字符串。
    * **函数和代码：** 刷新不再使用的编译后的 Javascript 代码和字节码，减少内存占用。
    * **弱引用：** 处理 Javascript 中的弱引用机制，确保当对象只被弱引用时可以被回收。

   **Javascript 示例：**

   ```javascript
   let obj1 = { data: "some data" };
   let weakRef = new WeakRef(obj1); // 创建一个指向 obj1 的弱引用

   obj1 = null; // 移除对 obj1 的强引用

   // 在垃圾回收之后，如果 obj1 没有其他强引用，
   // weakRef.deref() 将返回 undefined。
   setTimeout(() => {
     console.log(weakRef.deref()); // 可能输出 undefined
   }, 1000);
   ```

   在这个例子中，`MarkCompactCollector` 的清除阶段会负责识别 `obj1` 是否可以被回收，并且会更新 `weakRef` 的状态。

* **代码逻辑推理（假设输入与输出）：**

   **假设输入：**
   - 堆中有一些未被标记的字符串对象。
   - 存在一些指向已死亡 Javascript 对象的弱引用。
   - 一些 `SharedFunctionInfo` 对象关联的字节码不再需要。

   **预期输出：**
   - 清除阶段完成后，未被标记的字符串对象占用的内存被回收。
   - 指向已死亡对象的弱引用被清理，其 `deref()` 方法将返回 `undefined` 或 `null`。
   - 不再需要的字节码被刷新，相关的 `SharedFunctionInfo` 对象更新为 `UncompiledData`。

* **涉及用户常见的编程错误：**

   1. **内存泄漏：** 如果垃圾回收器没有正确工作，或者代码中存在无法触及的循环引用，会导致内存泄漏。这段代码的目标就是避免这种情况。
   2. **意外的对象被回收：**  如果错误地使用了弱引用，或者对对象的生命周期理解不透彻，可能会导致本应存活的对象被提前回收。例如：

      ```javascript
      let observer = new FinalizationRegistry(heldValue => {
        console.log("对象被回收了：", heldValue);
      });

      let obj = { name: "my object" };
      observer.register(obj, "obj的信息");
      obj = null; // 错误地移除了强引用，可能导致对象过早被回收
      ```
      `MarkCompactCollector` 的弱引用处理逻辑会影响 `FinalizationRegistry` 的行为。

**总结 `v8/src/heap/mark-compact.cc` (第 4 部分):**

这段代码是 `MarkCompactCollector` 中负责 **清除（Clearing）阶段** 的关键部分。它在标记阶段之后执行，通过并行处理各种清理任务，回收未使用的内存，清理与已死亡对象相关的元数据和引用，包括字符串、弱引用、编译后的代码等，从而保证 V8 引擎的内存健康和性能。它涉及到许多与 Javascript 运行时息息相关的功能，例如弱引用的处理和代码的刷新。

### 提示词
```
这是目录为v8/src/heap/mark-compact.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/mark-compact.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
cal_marking_worklists_.get()));
    VerifyEphemeronMarking();
  }

  if (was_marked_incrementally) {
    // Disable the marking barrier after concurrent/parallel marking has
    // finished as it will reset page flags that share the same bitmap as
    // the evacuation candidate bit.
    MarkingBarrier::DeactivateAll(heap_);
    heap_->isolate()->traced_handles()->SetIsMarking(false);
  }

  epoch_++;
}

namespace {

class ParallelClearingJob final : public v8::JobTask {
 public:
  class ClearingItem {
   public:
    virtual ~ClearingItem() = default;
    virtual void Run(JobDelegate* delegate) = 0;
  };

  explicit ParallelClearingJob(MarkCompactCollector* collector)
      : collector_(collector) {}
  ~ParallelClearingJob() override = default;
  ParallelClearingJob(const ParallelClearingJob&) = delete;
  ParallelClearingJob& operator=(const ParallelClearingJob&) = delete;

  // v8::JobTask overrides.
  void Run(JobDelegate* delegate) override {
    std::unique_ptr<ClearingItem> item;
    {
      base::MutexGuard guard(&items_mutex_);
      item = std::move(items_.back());
      items_.pop_back();
    }
    item->Run(delegate);
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    base::MutexGuard guard(&items_mutex_);
    if (!v8_flags.parallel_weak_ref_clearing ||
        !collector_->UseBackgroundThreadsInCycle()) {
      return std::min<size_t>(items_.size(), 1);
    }
    return items_.size();
  }

  void Add(std::unique_ptr<ClearingItem> item) {
    items_.push_back(std::move(item));
  }

 private:
  MarkCompactCollector* collector_;
  mutable base::Mutex items_mutex_;
  std::vector<std::unique_ptr<ClearingItem>> items_;
};

class ClearStringTableJobItem final : public ParallelClearingJob::ClearingItem {
 public:
  explicit ClearStringTableJobItem(Isolate* isolate)
      : isolate_(isolate),
        trace_id_(reinterpret_cast<uint64_t>(this) ^
                  isolate->heap()->tracer()->CurrentEpoch(
                      GCTracer::Scope::MC_CLEAR_STRING_TABLE)) {}

  void Run(JobDelegate* delegate) final {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate_);

    if (isolate_->OwnsStringTables()) {
      TRACE_GC1_WITH_FLOW(isolate_->heap()->tracer(),
                          GCTracer::Scope::MC_CLEAR_STRING_TABLE,
                          delegate->IsJoiningThread() ? ThreadKind::kMain
                                                      : ThreadKind::kBackground,
                          trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
      // Prune the string table removing all strings only pointed to by the
      // string table.  Cannot use string_table() here because the string
      // table is marked.
      StringTable* string_table = isolate_->string_table();
      InternalizedStringTableCleaner internalized_visitor(isolate_->heap());
      string_table->DropOldData();
      string_table->IterateElements(&internalized_visitor);
      string_table->NotifyElementsRemoved(
          internalized_visitor.PointersRemoved());
    }
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  Isolate* const isolate_;
  const uint64_t trace_id_;
};

}  // namespace

class FullStringForwardingTableCleaner final
    : public StringForwardingTableCleanerBase {
 public:
  explicit FullStringForwardingTableCleaner(Heap* heap)
      : StringForwardingTableCleanerBase(heap), heap_(heap) {
    USE(heap_);
  }

  // Transition all strings in the forwarding table to
  // ThinStrings/ExternalStrings and clear the table afterwards.
  void TransitionStrings() {
    DCHECK(!heap_->IsGCWithStack() ||
           v8_flags.transition_strings_during_gc_with_stack);
    StringForwardingTable* forwarding_table =
        isolate_->string_forwarding_table();
    forwarding_table->IterateElements(
        [&](StringForwardingTable::Record* record) {
          TransitionStrings(record);
        });
    forwarding_table->Reset();
  }

  // When performing GC with a stack, we conservatively assume that
  // the GC could have been triggered by optimized code. Optimized code
  // assumes that flat strings don't transition during GCs, so we are not
  // allowed to transition strings to ThinString/ExternalString in that
  // case.
  // Instead we mark forward objects to keep them alive and update entries
  // of evacuated objects later.
  void ProcessFullWithStack() {
    DCHECK(heap_->IsGCWithStack() &&
           !v8_flags.transition_strings_during_gc_with_stack);
    StringForwardingTable* forwarding_table =
        isolate_->string_forwarding_table();
    forwarding_table->IterateElements(
        [&](StringForwardingTable::Record* record) {
          MarkForwardObject(record);
        });
  }

 private:
  void MarkForwardObject(StringForwardingTable::Record* record) {
    Tagged<Object> original = record->OriginalStringObject(isolate_);
    if (!IsHeapObject(original)) {
      DCHECK_EQ(original, StringForwardingTable::deleted_element());
      return;
    }
    Tagged<String> original_string = Cast<String>(original);
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_,
                                            original_string)) {
      Tagged<Object> forward = record->ForwardStringObjectOrHash(isolate_);
      if (!IsHeapObject(forward) ||
          (MarkingHelper::GetLivenessMode(heap_, Cast<HeapObject>(forward)) ==
           MarkingHelper::LivenessMode::kAlwaysLive)) {
        return;
      }
      marking_state_->TryMarkAndAccountLiveBytes(Cast<HeapObject>(forward));
    } else {
      DisposeExternalResource(record);
      record->set_original_string(StringForwardingTable::deleted_element());
    }
  }

  void TransitionStrings(StringForwardingTable::Record* record) {
    Tagged<Object> original = record->OriginalStringObject(isolate_);
    if (!IsHeapObject(original)) {
      DCHECK_EQ(original, StringForwardingTable::deleted_element());
      return;
    }
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_,
                                            Cast<HeapObject>(original))) {
      Tagged<String> original_string = Cast<String>(original);
      if (IsThinString(original_string)) {
        original_string = Cast<ThinString>(original_string)->actual();
      }
      TryExternalize(original_string, record);
      TryInternalize(original_string, record);
      original_string->set_raw_hash_field(record->raw_hash(isolate_));
    } else {
      DisposeExternalResource(record);
    }
  }

  void TryExternalize(Tagged<String> original_string,
                      StringForwardingTable::Record* record) {
    // If the string is already external, dispose the resource.
    if (IsExternalString(original_string)) {
      record->DisposeUnusedExternalResource(isolate_, original_string);
      return;
    }

    bool is_one_byte;
    v8::String::ExternalStringResourceBase* external_resource =
        record->external_resource(&is_one_byte);
    if (external_resource == nullptr) return;

    if (is_one_byte) {
      original_string->MakeExternalDuringGC(
          isolate_,
          reinterpret_cast<v8::String::ExternalOneByteStringResource*>(
              external_resource));
    } else {
      original_string->MakeExternalDuringGC(
          isolate_, reinterpret_cast<v8::String::ExternalStringResource*>(
                        external_resource));
    }
  }

  void TryInternalize(Tagged<String> original_string,
                      StringForwardingTable::Record* record) {
    if (IsInternalizedString(original_string)) return;
    Tagged<Object> forward = record->ForwardStringObjectOrHash(isolate_);
    if (!IsHeapObject(forward)) {
      return;
    }
    Tagged<String> forward_string = Cast<String>(forward);

    // Mark the forwarded string to keep it alive.
    if (MarkingHelper::GetLivenessMode(heap_, forward_string) !=
        MarkingHelper::LivenessMode::kAlwaysLive) {
      marking_state_->TryMarkAndAccountLiveBytes(forward_string);
    }
    // Transition the original string to a ThinString and override the
    // forwarding index with the correct hash.
    original_string->MakeThin(isolate_, forward_string);
    // Record the slot in the old-to-old remembered set. This is
    // required as the internalized string could be relocated during
    // compaction.
    ObjectSlot slot(&Cast<ThinString>(original_string)->actual_);
    MarkCompactCollector::RecordSlot(original_string, slot, forward_string);
  }

  Heap* const heap_;
};

namespace {

class SharedStructTypeRegistryCleaner final : public RootVisitor {
 public:
  explicit SharedStructTypeRegistryCleaner(Heap* heap) : heap_(heap) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    UNREACHABLE();
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK_EQ(root, Root::kSharedStructTypeRegistry);
    // The SharedStructTypeRegistry holds the canonical SharedStructType
    // instance maps weakly. Visit all Map pointers in [start, end), deleting
    // it if unmarked.
    auto* marking_state = heap_->marking_state();
    Isolate* const isolate = heap_->isolate();
    for (OffHeapObjectSlot p = start; p < end; p++) {
      Tagged<Object> o = p.load(isolate);
      DCHECK(!IsString(o));
      if (IsMap(o)) {
        Tagged<HeapObject> map = Cast<Map>(o);
        DCHECK(HeapLayout::InAnySharedSpace(map));
        if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state, map))
          continue;
        elements_removed_++;
        p.store(SharedStructTypeRegistry::deleted_element());
      }
    }
  }

  int ElementsRemoved() const { return elements_removed_; }

 private:
  Heap* heap_;
  int elements_removed_ = 0;
};

class ClearSharedStructTypeRegistryJobItem final
    : public ParallelClearingJob::ClearingItem {
 public:
  explicit ClearSharedStructTypeRegistryJobItem(Isolate* isolate)
      : isolate_(isolate) {
    DCHECK(isolate->is_shared_space_isolate());
    DCHECK_NOT_NULL(isolate->shared_struct_type_registry());
  }

  void Run(JobDelegate* delegate) final {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate_);

    auto* registry = isolate_->shared_struct_type_registry();
    SharedStructTypeRegistryCleaner cleaner(isolate_->heap());
    registry->IterateElements(isolate_, &cleaner);
    registry->NotifyElementsRemoved(cleaner.ElementsRemoved());
  }

 private:
  Isolate* const isolate_;
};

}  // namespace

class MarkCompactCollector::ClearTrivialWeakRefJobItem final
    : public ParallelClearingJob::ClearingItem {
 public:
  explicit ClearTrivialWeakRefJobItem(MarkCompactCollector* collector)
      : collector_(collector),
        trace_id_(reinterpret_cast<uint64_t>(this) ^
                  collector->heap()->tracer()->CurrentEpoch(
                      GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_TRIVIAL)) {}

  void Run(JobDelegate* delegate) final {
    Heap* heap = collector_->heap();

    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(heap->isolate());

    TRACE_GC1_WITH_FLOW(heap->tracer(),
                        GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_TRIVIAL,
                        delegate->IsJoiningThread() ? ThreadKind::kMain
                                                    : ThreadKind::kBackground,
                        trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    collector_->ClearTrivialWeakReferences();
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  MarkCompactCollector* collector_;
  const uint64_t trace_id_;
};

class MarkCompactCollector::FilterNonTrivialWeakRefJobItem final
    : public ParallelClearingJob::ClearingItem {
 public:
  explicit FilterNonTrivialWeakRefJobItem(MarkCompactCollector* collector)
      : collector_(collector),
        trace_id_(
            reinterpret_cast<uint64_t>(this) ^
            collector->heap()->tracer()->CurrentEpoch(
                GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_FILTER_NON_TRIVIAL)) {
  }

  void Run(JobDelegate* delegate) final {
    Heap* heap = collector_->heap();

    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(heap->isolate());

    TRACE_GC1_WITH_FLOW(
        heap->tracer(),
        GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_FILTER_NON_TRIVIAL,
        delegate->IsJoiningThread() ? ThreadKind::kMain
                                    : ThreadKind::kBackground,
        trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    collector_->FilterNonTrivialWeakReferences();
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  MarkCompactCollector* collector_;
  const uint64_t trace_id_;
};

void MarkCompactCollector::ClearNonLiveReferences() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR);

  Isolate* const isolate = heap_->isolate();
  if (isolate->OwnsStringTables()) {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_CLEAR_STRING_FORWARDING_TABLE);
    // Clear string forwarding table. Live strings are transitioned to
    // ThinStrings/ExternalStrings in the cleanup process, if this is a GC
    // without stack.
    // Clearing the string forwarding table must happen before clearing the
    // string table, as entries in the forwarding table can keep internalized
    // strings alive.
    FullStringForwardingTableCleaner forwarding_table_cleaner(heap_);
    if (!heap_->IsGCWithStack() ||
        v8_flags.transition_strings_during_gc_with_stack) {
      forwarding_table_cleaner.TransitionStrings();
    } else {
      forwarding_table_cleaner.ProcessFullWithStack();
    }
  }

  {
    // Clear Isolate::topmost_script_having_context slot if it's not alive.
    Tagged<Object> maybe_caller_context =
        isolate->topmost_script_having_context();
    if (maybe_caller_context.IsHeapObject() &&
        MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, marking_state_, Cast<HeapObject>(maybe_caller_context))) {
      isolate->clear_topmost_script_having_context();
    }
  }

  std::unique_ptr<JobHandle> clear_string_table_job_handle;
  {
    auto job = std::make_unique<ParallelClearingJob>(this);
    auto job_item = std::make_unique<ClearStringTableJobItem>(isolate);
    const uint64_t trace_id = job_item->trace_id();
    job->Add(std::move(job_item));
    TRACE_GC_NOTE_WITH_FLOW("ClearStringTableJob started", trace_id,
                            TRACE_EVENT_FLAG_FLOW_OUT);
    if (isolate->is_shared_space_isolate() &&
        isolate->shared_struct_type_registry()) {
      auto registry_job_item =
          std::make_unique<ClearSharedStructTypeRegistryJobItem>(isolate);
      job->Add(std::move(registry_job_item));
    }
    clear_string_table_job_handle = V8::GetCurrentPlatform()->CreateJob(
        TaskPriority::kUserBlocking, std::move(job));
  }
  if (v8_flags.parallel_weak_ref_clearing && UseBackgroundThreadsInCycle()) {
    clear_string_table_job_handle->NotifyConcurrencyIncrease();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_EXTERNAL_STRING_TABLE);
    ExternalStringTableCleanerVisitor<ExternalStringTableCleaningMode::kAll>
        external_visitor(heap_);
    heap_->external_string_table_.IterateAll(&external_visitor);
    heap_->external_string_table_.CleanUpAll();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_WEAK_GLOBAL_HANDLES);
    // We depend on `IterateWeakRootsForPhantomHandles()` being called before
    // `ProcessOldCodeCandidates()` in order to identify flushed bytecode in the
    // CPU profiler.
    isolate->global_handles()->IterateWeakRootsForPhantomHandles(
        &IsUnmarkedHeapObject);
    isolate->traced_handles()->ResetDeadNodes(&IsUnmarkedHeapObject);

    if (isolate->is_shared_space_isolate()) {
      isolate->global_safepoint()->IterateClientIsolates([](Isolate* client) {
        client->global_handles()->IterateWeakRootsForPhantomHandles(
            &IsUnmarkedSharedHeapObject);
        // No need to reset traced handles since they are always strong.
      });
    }
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_FLUSHABLE_BYTECODE);
    // `ProcessFlushedBaselineCandidates()` must be called after
    // `ProcessOldCodeCandidates()` so that we correctly set the code object on
    // the JSFunction after flushing.
    ProcessOldCodeCandidates();
#ifndef V8_ENABLE_LEAPTIERING
    // With leaptiering this is done during sweeping.
    ProcessFlushedBaselineCandidates();
#endif  // !V8_ENABLE_LEAPTIERING
  }

#ifdef V8_ENABLE_LEAPTIERING
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_JS_DISPATCH_TABLE);
    JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
    Tagged<Code> compile_lazy = *BUILTIN_CODE(heap_->isolate(), CompileLazy);
    jdt->Sweep(heap_->js_dispatch_table_space(), isolate->counters(),
               [&](JSDispatchEntry& entry) {
                 Tagged<Code> code = entry.GetCode();
                 if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
                         heap_, marking_state_, code)) {
                   // Baseline flushing: if the Code object is no longer alive,
                   // it must have been flushed and so we replace it with the
                   // CompileLazy builtin. Once we use leaptiering on all
                   // platforms, we can probably simplify the other code related
                   // to baseline flushing.

                   // Currently, we can also see optimized code here. This
                   // happens when a FeedbackCell for which no JSFunctions
                   // remain references optimized code. However, in that case we
                   // probably do want to delete the optimized code, so that is
                   // working as intended. It does mean, however, that we cannot
                   // DCHECK here that we only see baseline code.
                   DCHECK(code->kind() == CodeKind::FOR_TESTING ||
                          code->kind() == CodeKind::BASELINE ||
                          code->kind() == CodeKind::MAGLEV ||
                          code->kind() == CodeKind::TURBOFAN_JS);
                   entry.SetCodeAndEntrypointPointer(
                       compile_lazy.ptr(), compile_lazy->instruction_start());
                 }
               });
  }
#endif  // V8_ENABLE_LEAPTIERING

  // TODO(olivf, 42204201): If we make the bytecode accessible from the dispatch
  // table this could also be implemented during JSDispatchTable::Sweep.
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_FLUSHED_JS_FUNCTIONS);
    ClearFlushedJsFunctions();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_WEAK_LISTS);
    // Process the weak references.
    MarkCompactWeakObjectRetainer mark_compact_object_retainer(heap_,
                                                               marking_state_);
    heap_->ProcessAllWeakReferences(&mark_compact_object_retainer);
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_MAPS);
    // ClearFullMapTransitions must be called before weak references are
    // cleared.
    ClearFullMapTransitions();
    // Weaken recorded strong DescriptorArray objects. This phase can
    // potentially move everywhere after `ClearFullMapTransitions()`.
    WeakenStrongDescriptorArrays();
  }

  // Start two parallel jobs: one for clearing trivial weak references and one
  // for filtering out non-trivial weak references that will not be cleared.
  // Both jobs read the values of weak references and the corresponding
  // mark bits. They cannot start before the following methods have finished,
  // because these may change the values of weak references and/or mark more
  // objects, thus creating data races:
  //   - ProcessOldCodeCandidates
  //   - ProcessAllWeakReferences
  //   - ClearFullMapTransitions
  //   - WeakenStrongDescriptorArrays
  // The two jobs could be merged but it's convenient to keep them separate,
  // as they are joined at different times. The filtering job must be joined
  // before proceeding to the actual clearing of non-trivial weak references,
  // whereas the job for clearing trivial weak references can be joined at the
  // end of this method.
  std::unique_ptr<JobHandle> clear_trivial_weakrefs_job_handle;
  {
    auto job = std::make_unique<ParallelClearingJob>(this);
    auto job_item = std::make_unique<ClearTrivialWeakRefJobItem>(this);
    const uint64_t trace_id = job_item->trace_id();
    job->Add(std::move(job_item));
    TRACE_GC_NOTE_WITH_FLOW("ClearTrivialWeakRefJob started", trace_id,
                            TRACE_EVENT_FLAG_FLOW_OUT);
    clear_trivial_weakrefs_job_handle = V8::GetCurrentPlatform()->CreateJob(
        TaskPriority::kUserBlocking, std::move(job));
  }
  std::unique_ptr<JobHandle> filter_non_trivial_weakrefs_job_handle;
  {
    auto job = std::make_unique<ParallelClearingJob>(this);
    auto job_item = std::make_unique<FilterNonTrivialWeakRefJobItem>(this);
    const uint64_t trace_id = job_item->trace_id();
    job->Add(std::move(job_item));
    TRACE_GC_NOTE_WITH_FLOW("FilterNonTrivialWeakRefJob started", trace_id,
                            TRACE_EVENT_FLAG_FLOW_OUT);
    filter_non_trivial_weakrefs_job_handle =
        V8::GetCurrentPlatform()->CreateJob(TaskPriority::kUserBlocking,
                                            std::move(job));
  }
  if (v8_flags.parallel_weak_ref_clearing && UseBackgroundThreadsInCycle()) {
    clear_trivial_weakrefs_job_handle->NotifyConcurrencyIncrease();
    filter_non_trivial_weakrefs_job_handle->NotifyConcurrencyIncrease();
  }

#ifdef V8_COMPRESS_POINTERS
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_EXTERNAL_POINTER_TABLE);
    // External pointer table sweeping needs to happen before evacuating live
    // objects as it may perform table compaction, which requires objects to
    // still be at the same location as during marking.
    //
    // Note we explicitly do NOT run SweepAndCompact on
    // read_only_external_pointer_space since these entries are all immortal by
    // definition.
    isolate->external_pointer_table().EvacuateAndSweepAndCompact(
        isolate->heap()->old_external_pointer_space(),
        isolate->heap()->young_external_pointer_space(), isolate->counters());
    isolate->heap()->young_external_pointer_space()->AssertEmpty();
    if (isolate->owns_shareable_data()) {
      isolate->shared_external_pointer_table().SweepAndCompact(
          isolate->shared_external_pointer_space(), isolate->counters());
    }
    isolate->cpp_heap_pointer_table().SweepAndCompact(
        isolate->heap()->cpp_heap_pointer_space(), isolate->counters());
  }
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_TRUSTED_POINTER_TABLE);
    isolate->trusted_pointer_table().Sweep(heap_->trusted_pointer_space(),
                                           isolate->counters());
    if (isolate->owns_shareable_data()) {
      isolate->shared_trusted_pointer_table().Sweep(
          isolate->shared_trusted_pointer_space(), isolate->counters());
    }
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_CODE_POINTER_TABLE);
    IsolateGroup::current()->code_pointer_table()->Sweep(
        heap_->code_pointer_space(), isolate->counters());
  }
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_WEBASSEMBLY
  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_SWEEP_WASM_CODE_POINTER_TABLE);
    wasm::GetProcessWideWasmCodePointerTable()->SweepSegments();
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_JOIN_FILTER_JOB);
    filter_non_trivial_weakrefs_job_handle->Join();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_WEAKNESS_HANDLING);
    ClearNonTrivialWeakReferences();
    ClearWeakCollections();
    ClearJSWeakRefs();
  }

  PROFILE(heap_->isolate(), WeakCodeClearEvent());

  {
    // This method may be called from within a DisallowDeoptimizations scope.
    // Temporarily allow deopts for marking code for deopt. This is not doing
    // the deopt yet and the actual deopts will be bailed out on later if the
    // current safepoint is not safe for deopts.
    // TODO(357636610): Reconsider whether the DisallowDeoptimization scopes are
    // truly needed.
    AllowDeoptimization allow_deoptimization(heap_->isolate());
    MarkDependentCodeForDeoptimization();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_JOIN_JOB);
    clear_string_table_job_handle->Join();
    clear_trivial_weakrefs_job_handle->Join();
  }

  if (v8_flags.sticky_mark_bits) {
    // TODO(333906585): Consider adjusting the dchecks that happen on clearing
    // and move this phase into MarkingBarrier::DeactivateAll.
    heap()->DeactivateMajorGCInProgressFlag();
  }

  DCHECK(weak_objects_.transition_arrays.IsEmpty());
  DCHECK(weak_objects_.weak_references_trivial.IsEmpty());
  DCHECK(weak_objects_.weak_references_non_trivial.IsEmpty());
  DCHECK(weak_objects_.weak_references_non_trivial_unmarked.IsEmpty());
  DCHECK(weak_objects_.weak_objects_in_code.IsEmpty());
  DCHECK(weak_objects_.js_weak_refs.IsEmpty());
  DCHECK(weak_objects_.weak_cells.IsEmpty());
  DCHECK(weak_objects_.code_flushing_candidates.IsEmpty());
  DCHECK(weak_objects_.flushed_js_functions.IsEmpty());
#ifndef V8_ENABLE_LEAPTIERING
  DCHECK(weak_objects_.baseline_flushing_candidates.IsEmpty());
#endif  // !V8_ENABLE_LEAPTIERING
}

void MarkCompactCollector::MarkDependentCodeForDeoptimization() {
  HeapObjectAndCode weak_object_in_code;
  while (local_weak_objects()->weak_objects_in_code_local.Pop(
      &weak_object_in_code)) {
    Tagged<HeapObject> object = weak_object_in_code.heap_object;
    Tagged<Code> code = weak_object_in_code.code;
    if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, non_atomic_marking_state_, object) &&
        !code->embedded_objects_cleared()) {
      if (!code->marked_for_deoptimization()) {
        code->SetMarkedForDeoptimization(heap_->isolate(), "weak objects");
        have_code_to_deoptimize_ = true;
      }
      code->ClearEmbeddedObjects(heap_);
      DCHECK(code->embedded_objects_cleared());
    }
  }
}

void MarkCompactCollector::ClearPotentialSimpleMapTransition(
    Tagged<Map> dead_target) {
  DCHECK(non_atomic_marking_state_->IsUnmarked(dead_target));
  Tagged<Object> potential_parent = dead_target->constructor_or_back_pointer();
  if (IsMap(potential_parent)) {
    Tagged<Map> parent = Cast<Map>(potential_parent);
    DisallowGarbageCollection no_gc_obviously;
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, non_atomic_marking_state_,
                                            parent) &&
        TransitionsAccessor(heap_->isolate(), parent)
            .HasSimpleTransitionTo(dead_target)) {
      ClearPotentialSimpleMapTransition(parent, dead_target);
    }
  }
}

void MarkCompactCollector::ClearPotentialSimpleMapTransition(
    Tagged<Map> map, Tagged<Map> dead_target) {
  DCHECK(!map->is_prototype_map());
  DCHECK(!dead_target->is_prototype_map());
  DCHECK_EQ(map->raw_transitions(), MakeWeak(dead_target));
  // Take ownership of the descriptor array.
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  Tagged<DescriptorArray> descriptors =
      map->instance_descriptors(heap_->isolate());
  if (descriptors == dead_target->instance_descriptors(heap_->isolate()) &&
      number_of_own_descriptors > 0) {
    TrimDescriptorArray(map, descriptors);
    DCHECK(descriptors->number_of_descriptors() == number_of_own_descriptors);
  }
}

bool MarkCompactCollector::SpecialClearMapSlot(Tagged<HeapObject> host,
                                               Tagged<Map> map,
                                               HeapObjectSlot slot) {
  ClearPotentialSimpleMapTransition(map);

  // Special handling for clearing field type entries, identified by their host
  // being a descriptor array.
  // TODO(olivf): This whole special handling of field-type clearing
  // could be replaced by eagerly triggering field type dependencies and
  // generalizing field types, as soon as a field-type map becomes
  // unstable.
  if (IsDescriptorArray(host)) {
    // We want to distinguish two cases:
    // 1. There are no instances of the descriptor owner's map left.
    // 2. The field type is not up to date because the stored object
    //    migrated away to a different map.
    // In case (1) it makes sense to clear the field type such that we
    // can learn a new one should we ever start creating instances
    // again.
    // In case (2) we must not re-learn a new field type. Doing so could
    // lead us to learning a field type that is not consistent with
    // still existing object's contents. To conservatively identify case
    // (1) we check the stability of the dead map.
    MaybeObjectSlot location(slot);
    if (map->is_stable() && FieldType::kFieldTypesCanBeClearedOnGC) {
      location.store(FieldType::None());
    } else {
      location.store(FieldType::Any());
    }
    return true;
  }
  return false;
}

void MarkCompactCollector::FlushBytecodeFromSFI(
    Tagged<SharedFunctionInfo> shared_info) {
  DCHECK(shared_info->HasBytecodeArray());

  // Retain objects required for uncompiled data.
  Tagged<String> inferred_name = shared_info->inferred_name();
  int start_position = shared_info->StartPosition();
  int end_position = shared_info->EndPosition();

  shared_info->DiscardCompiledMetadata(
      heap_->isolate(),
      [](Tagged<HeapObject> object, ObjectSlot slot,
         Tagged<HeapObject> target) { RecordSlot(object, slot, target); });

  // The size of the bytecode array should always be larger than an
  // UncompiledData object.
  static_assert(BytecodeArray::SizeFor(0) >=
                UncompiledDataWithoutPreparseData::kSize);

  // Replace the bytecode with an uncompiled data object.
  Tagged<BytecodeArray> bytecode_array =
      shared_info->GetBytecodeArray(heap_->isolate());

#ifdef V8_ENABLE_SANDBOX
  DCHECK(!HeapLayout::InWritableSharedSpace(shared_info));
  // Zap the old entry in the trusted pointer table.
  TrustedPointerTable& table = heap_->isolate()->trusted_pointer_table();
  IndirectPointerSlot self_indirect_pointer_slot =
      bytecode_array->RawIndirectPointerField(
          BytecodeArray::kSelfIndirectPointerOffset,
          kBytecodeArrayIndirectPointerTag);
  table.Zap(self_indirect_pointer_slot.Relaxed_LoadHandle());
#endif

  Tagged<HeapObject> compiled_data = bytecode_array;
  Address compiled_data_start = compiled_data.address();
  int compiled_data_size = ALIGN_TO_ALLOCATION_ALIGNMENT(compiled_data->Size());
  MutablePageMetadata* chunk =
      MutablePageMetadata::FromAddress(compiled_data_start);

  // Clear any recorded slots for the compiled data as being invalid.
  RememberedSet<OLD_TO_NEW>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_SHARED>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_OLD>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<TRUSTED_TO_TRUSTED>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);

  // Swap the map, using set_map_after_allocation to avoid verify heap checks
  // which are not necessary since we are doing this during the GC atomic pause.
  compiled_data->set_map_after_allocation(
      heap_->isolate(),
      ReadOnlyRoots(heap_).uncompiled_data_without_preparse_data_map(),
      SKIP_WRITE_BARRIER);

  // Create a filler object for any left over space in the bytecode array.
  if (!heap_->IsLargeObject(compiled_data)) {
    const int aligned_filler_offset =
        ALIGN_TO_ALLOCATION_ALIGNMENT(UncompiledDataWith
```