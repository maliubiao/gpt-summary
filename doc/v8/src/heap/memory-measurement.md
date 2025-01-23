Response: Let's break down the thought process for analyzing this C++ code.

1. **Identify the Core Purpose:**  The filename `memory-measurement.cc` and the class name `MemoryMeasurement` strongly suggest this code is about tracking and reporting memory usage within the V8 engine.

2. **Look for Key Data Structures and Classes:**  Scanning the code reveals several important classes:
    * `MemoryMeasurementResultBuilder`:  Clearly responsible for constructing the output of a memory measurement operation.
    * `MeasureMemoryDelegate`:  An interface for handling the completion of a measurement.
    * `MemoryMeasurement`: The main class managing the overall process.
    * `NativeContextStats`:  Used to aggregate memory statistics per context.

3. **Analyze `MemoryMeasurementResultBuilder`:** This class has methods like `AddTotal`, `AddCurrent`, `AddOther`, `AddWasm`, and `Build`. These methods correspond to different categories of memory being tracked (total, current context, other contexts, WebAssembly). The `Build` method suggests it compiles these individual pieces into a final result. The use of `factory_->NewJSObject()` and `AddProperty` points to the creation of JavaScript objects as the output format.

4. **Analyze `MeasureMemoryDelegate`:** This looks like a callback mechanism. The `ShouldMeasure` method likely determines if a particular context should be included in the measurement. `MeasurementComplete` is where the aggregated results are processed and likely passed back to the JavaScript side. The constructor takes an `Isolate`, `Context`, and `Promise::Resolver`, hinting at an asynchronous operation triggered from JavaScript.

5. **Analyze `MemoryMeasurement`:** This is the central orchestrator. Key methods include:
    * `EnqueueRequest`:  This is likely the entry point from JavaScript to initiate a memory measurement. It takes a `delegate`, an `execution` mode, and the relevant `contexts`.
    * `StartProcessing`:  Prepares for the measurement by gathering the contexts to be examined.
    * `FinishProcessing`:  Receives the memory statistics after garbage collection and associates them with the requests.
    * `ScheduleGCTask`:  Initiates garbage collection, which is crucial for accurate memory measurement.
    * `ReportResults`:  Formats and delivers the results back using the `MeasureMemoryDelegate`.

6. **Look for Connections to JavaScript:** The usage of `v8::Isolate`, `v8::Context`, `v8::Local`, `v8::Promise::Resolver`, and the creation of JavaScript objects within `MemoryMeasurementResultBuilder` are strong indicators of interaction with JavaScript. The `DefaultDelegate` function returns a `MeasureMemoryDelegate`, suggesting a default implementation used when JavaScript requests a measurement.

7. **Infer the Workflow:** Based on the above observations, a likely workflow emerges:
    1. JavaScript calls a V8 API function to request memory measurement, providing context and execution mode.
    2. This call goes through to `MemoryMeasurement::EnqueueRequest`.
    3. `EnqueueRequest` creates a `MeasureMemoryDelegate` and stores the request.
    4. A garbage collection task (`ScheduleGCTask`) is triggered to ensure accurate measurement.
    5. V8 performs garbage collection.
    6. `MemoryMeasurement::StartProcessing` is called, identifying the contexts to measure.
    7. Memory is measured during or after GC.
    8. `MemoryMeasurement::FinishProcessing` receives the `NativeContextStats` and associates the memory usage with the original requests.
    9. `MemoryMeasurement::ReportResults` uses the `MeasureMemoryDelegate` to deliver the formatted results (as JavaScript objects) back to the waiting JavaScript promise.

8. **Consider the `MeasureMemoryMode`:**  The code handles `kDetailed` mode differently, including more granular information (like the size of individual contexts). This suggests different levels of memory reporting detail are possible.

9. **Address the JavaScript Example Request:** Now that the function is understood, it's possible to construct a JavaScript example. The example needs to show how to trigger this measurement and how to interpret the returned results. The key is understanding that it likely involves a V8 API function (potentially experimental or internal). The returned data structure is clearly based on the structure created by `MemoryMeasurementResultBuilder`.

10. **Review and Refine:** Read through the analysis, ensuring the explanation is clear and accurate. Check for any missed details or inconsistencies. For example, notice the use of `WeakFixedArray` to hold context references, which is common in V8 for managing object lifecycles. Also, note the handling of WebAssembly memory.

By following these steps, we can systematically dissect the C++ code and arrive at a comprehensive understanding of its function and its relationship to JavaScript. The focus is on understanding the data flow, the key classes involved, and how the C++ code interacts with the V8 JavaScript engine.
这个C++源代码文件 `memory-measurement.cc` 的主要功能是**实现 V8 引擎的内存测量机制，允许开发者获取 JavaScript 堆的内存使用情况，并提供不同粒度的报告**。

更具体地说，它的功能包括：

1. **发起内存测量请求 (EnqueueRequest):**  接收来自 JavaScript (或其他 V8 API 调用者) 的内存测量请求。请求中会包含要测量的上下文 (Context)，以及期望的测量粒度 (例如，是否需要详细信息)。

2. **触发垃圾回收 (ScheduleGCTask):** 为了获得准确的内存使用情况，通常需要在测量前进行垃圾回收。该文件负责根据请求的执行模式 (例如，立即执行、延迟执行) 安排垃圾回收任务。

3. **处理测量过程 (StartProcessing, FinishProcessing):**  在垃圾回收完成后，开始实际的内存测量过程。
    * `StartProcessing` 会收集需要测量的所有上下文。
    * `FinishProcessing` 会接收每个上下文的内存使用统计信息，并将其与原始的测量请求关联起来。

4. **构建内存测量结果 (MemoryMeasurementResultBuilder):**  将收集到的内存使用信息组织成结构化的数据。这个数据结构包含了总内存、当前上下文内存、其他上下文内存，以及 WebAssembly 相关的内存使用情况 (如果启用了 WebAssembly)。结果以 JavaScript 对象的形式构建。

5. **报告内存测量结果 (ReportResults):**  将构建好的内存测量结果通过一个回调接口 (`MeasureMemoryDelegate`) 传递回 JavaScript。

6. **提供默认的测量代理 (DefaultDelegate):**  提供一个默认的 `MeasureMemoryDelegate` 实现，用于处理测量完成后的结果。这个代理会将结果通过 Promise 返回给 JavaScript。

**与 JavaScript 的关系以及 JavaScript 示例：**

这个 C++ 文件直接支持了 V8 提供给 JavaScript 的内存测量 API。虽然具体的 JavaScript API 可能不是直接暴露出 `MemoryMeasurement` 类，但它会使用到这里实现的功能。

**可能的 JavaScript API (取决于 V8 的具体版本和暴露方式，以下是概念性示例):**

```javascript
async function measureMemory() {
  try {
    const measurement = await performance.measureMemory({ detailed: true });
    console.log("Total Memory:", measurement.total.estimate);
    console.log("Current Context Memory:", measurement.current.estimate);
    console.log("Other Contexts Memory:", measurement.other);
    if (measurement.WebAssembly) {
      console.log("WebAssembly Code:", measurement.WebAssembly.code);
      console.log("WebAssembly Metadata:", measurement.WebAssembly.metadata);
    }
  } catch (error) {
    console.error("Failed to measure memory:", error);
  }
}

measureMemory();
```

**解释：**

* **`performance.measureMemory()`:**  这是一个假设的 API，用于触发 V8 的内存测量功能。实际上，具体的 API 可能会有所不同，可能需要使用到特定的 V8 扩展或内部 API (在 Node.js 环境下或使用 V8 的嵌入式环境中)。
* **`{ detailed: true }`:**  这个选项可能对应于 C++ 代码中的 `v8::MeasureMemoryMode::kDetailed`，指示 V8 返回更详细的内存使用信息，包括各个上下文的内存占用。
* **`measurement.total.estimate`:**  对应于 C++ 代码中 `MemoryMeasurementResultBuilder::AddTotal` 添加的信息，表示总的 JavaScript 堆内存估计值。
* **`measurement.current.estimate`:**  对应于 `MemoryMeasurementResultBuilder::AddCurrent`，表示当前 JavaScript 上下文的内存估计值。
* **`measurement.other`:**  对应于 `MemoryMeasurementResultBuilder::AddOther`，是一个数组，包含了其他 JavaScript 上下文的内存估计值。
* **`measurement.WebAssembly`:** 对应于 `MemoryMeasurementResultBuilder::AddWasm`，包含了 WebAssembly 代码和元数据的内存使用情况。

**C++ 代码和 JavaScript 的关联：**

1. 当 JavaScript 调用 `performance.measureMemory()` (或类似的 API) 时，V8 引擎会接收到这个请求。

2. V8 内部会创建一个 `MeasureMemoryDelegate` 的实例，并将其传递给 `MemoryMeasurement::EnqueueRequest`。

3. `MemoryMeasurement` 对象会根据 `detailed` 选项的值，决定是否需要进行更精细的测量。

4. `MemoryMeasurement` 会调度垃圾回收任务，以确保内存测量的准确性。

5. 在垃圾回收完成后，`MemoryMeasurement` 会遍历相关的 JavaScript 上下文，收集内存使用统计信息。

6. `MemoryMeasurementResultBuilder` 会将这些信息格式化成一个 JavaScript 对象。

7. `MeasureMemoryDelegate::MeasurementComplete` 方法会将构建好的 JavaScript 对象通过 Promise 的 `resolve` 方法返回给 JavaScript。

**总结：**

`v8/src/heap/memory-measurement.cc` 是 V8 引擎中负责实现内存测量功能的核心 C++ 代码。它响应来自 JavaScript 的内存测量请求，协调垃圾回收，收集内存使用数据，并最终将结果以结构化的 JavaScript 对象的形式返回给 JavaScript 环境，使得开发者能够了解其 JavaScript 代码的内存消耗情况。

### 提示词
```
这是目录为v8/src/heap/memory-measurement.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/memory-measurement.h"

#include "include/v8-local-handle.h"
#include "src/api/api-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/factory-inl.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/marking-worklist.h"
#include "src/logging/counters.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-promise-inl.h"
#include "src/tasks/task-utils.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#endif

namespace v8::internal {
namespace {
// Must only be used from stack.
//
// TODO(374253377): This should be implemented purely on the public API and move
// to d8. There's no reason V8 would need to provide a default delegate on its
// API.
class MemoryMeasurementResultBuilder final {
 public:
  explicit MemoryMeasurementResultBuilder(v8::Isolate* isolate)
      : isolate_(reinterpret_cast<Isolate*>(isolate)),
        factory_(isolate_->factory()) {
    result_ = NewJSObject();
  }
  void AddTotal(size_t estimate, size_t lower_bound, size_t upper_bound) {
    AddProperty(result_, factory_->total_string(),
                NewResult(estimate, lower_bound, upper_bound));
  }
  void AddCurrent(size_t estimate, size_t lower_bound, size_t upper_bound) {
    detailed_ = true;
    AddProperty(result_, factory_->current_string(),
                NewResult(estimate, lower_bound, upper_bound));
  }
  void AddOther(size_t estimate, size_t lower_bound, size_t upper_bound) {
    detailed_ = true;
    other_.push_back(NewResult(estimate, lower_bound, upper_bound));
  }
  void AddWasm(size_t code, size_t metadata) {
    Handle<JSObject> wasm = NewJSObject();
    AddProperty(wasm, factory_->NewStringFromAsciiChecked("code"),
                NewNumber(code));
    AddProperty(wasm, factory_->NewStringFromAsciiChecked("metadata"),
                NewNumber(metadata));
    AddProperty(result_, factory_->NewStringFromAsciiChecked("WebAssembly"),
                wasm);
  }
  Handle<JSObject> Build() {
    if (detailed_) {
      int length = static_cast<int>(other_.size());
      DirectHandle<FixedArray> other = factory_->NewFixedArray(length);
      for (int i = 0; i < length; i++) {
        other->set(i, *other_[i]);
      }
      AddProperty(result_, factory_->other_string(),
                  factory_->NewJSArrayWithElements(other));
    }
    return result_;
  }

 private:
  Handle<JSObject> NewResult(size_t estimate, size_t lower_bound,
                             size_t upper_bound) {
    Handle<JSObject> result = NewJSObject();
    DirectHandle<Object> estimate_obj = NewNumber(estimate);
    AddProperty(result, factory_->jsMemoryEstimate_string(), estimate_obj);
    DirectHandle<Object> range = NewRange(lower_bound, upper_bound);
    AddProperty(result, factory_->jsMemoryRange_string(), range);
    return result;
  }
  Handle<Object> NewNumber(size_t value) {
    return factory_->NewNumberFromSize(value);
  }
  Handle<JSObject> NewJSObject() {
    return factory_->NewJSObject(isolate_->object_function());
  }
  Handle<JSArray> NewRange(size_t lower_bound, size_t upper_bound) {
    DirectHandle<Object> lower = NewNumber(lower_bound);
    DirectHandle<Object> upper = NewNumber(upper_bound);
    DirectHandle<FixedArray> elements = factory_->NewFixedArray(2);
    elements->set(0, *lower);
    elements->set(1, *upper);
    return factory_->NewJSArrayWithElements(elements);
  }
  void AddProperty(Handle<JSObject> object, Handle<String> name,
                   DirectHandle<Object> value) {
    JSObject::AddProperty(isolate_, object, name, value, NONE);
  }
  Isolate* isolate_;
  Factory* factory_;
  Handle<JSObject> result_;
  std::vector<Handle<JSObject>> other_;
  bool detailed_ = false;
};
}  // anonymous namespace

class V8_EXPORT_PRIVATE MeasureMemoryDelegate
    : public v8::MeasureMemoryDelegate {
 public:
  MeasureMemoryDelegate(v8::Isolate* isolate, v8::Local<v8::Context> context,
                        v8::Local<v8::Promise::Resolver> promise,
                        v8::MeasureMemoryMode mode);
  ~MeasureMemoryDelegate() override = default;

  // v8::MeasureMemoryDelegate overrides:
  bool ShouldMeasure(v8::Local<v8::Context> context) override;
  void MeasurementComplete(Result result) override;

 private:
  v8::Isolate* isolate_;
  const v8::Global<v8::Context> context_;
  const v8::Global<v8::Promise::Resolver> promise_;
  const v8::MeasureMemoryMode mode_;
};

MeasureMemoryDelegate::MeasureMemoryDelegate(
    v8::Isolate* isolate, v8::Local<v8::Context> context,
    v8::Local<v8::Promise::Resolver> promise, v8::MeasureMemoryMode mode)
    : isolate_(isolate),
      context_(isolate_, context),
      promise_(isolate_, promise),
      mode_(mode) {}

bool MeasureMemoryDelegate::ShouldMeasure(
    v8::Local<v8::Context> other_context) {
  return context_.Get(isolate_)->GetSecurityToken() ==
         other_context->GetSecurityToken();
}

void MeasureMemoryDelegate::MeasurementComplete(Result result) {
  size_t shared_size = result.unattributed_size_in_bytes;
  size_t wasm_code = result.wasm_code_size_in_bytes;
  size_t wasm_metadata = result.wasm_metadata_size_in_bytes;
  v8::Local<v8::Context> v8_context = context_.Get(isolate_);
  v8::Context::Scope scope(v8_context);
  size_t total_size = 0;
  size_t current_size = 0;
  DCHECK_EQ(result.contexts.size(), result.sizes_in_bytes.size());
  for (size_t i = 0; i < result.contexts.size(); ++i) {
    total_size += result.sizes_in_bytes[i];
    if (context_ == result.contexts[i]) {
      current_size = result.sizes_in_bytes[i];
    }
  }
  MemoryMeasurementResultBuilder result_builder(isolate_);
  result_builder.AddTotal(total_size, total_size, total_size + shared_size);
  if (wasm_code > 0 || wasm_metadata > 0) {
    result_builder.AddWasm(wasm_code, wasm_metadata);
  }

  if (mode_ == v8::MeasureMemoryMode::kDetailed) {
    result_builder.AddCurrent(current_size, current_size,
                              current_size + shared_size);
    for (size_t i = 0; i < result.contexts.size(); ++i) {
      if (context_ != result.contexts[i]) {
        size_t other_size = result.sizes_in_bytes[i];
        result_builder.AddOther(other_size, other_size,
                                other_size + shared_size);
      }
    }
  }

  auto v8_result = ToApiHandle<v8::Object>(result_builder.Build());
  auto v8_promise = promise_.Get(isolate_);
  if (v8_promise->Resolve(v8_context, v8_result).IsNothing()) {
    CHECK(reinterpret_cast<Isolate*>(isolate_)->is_execution_terminating());
  }
}

MemoryMeasurement::MemoryMeasurement(Isolate* isolate)
    : isolate_(isolate),
      task_runner_(isolate->heap()->GetForegroundTaskRunner()),
      random_number_generator_() {
  if (v8_flags.random_seed) {
    random_number_generator_.SetSeed(v8_flags.random_seed);
  }
}

bool MemoryMeasurement::EnqueueRequest(
    std::unique_ptr<v8::MeasureMemoryDelegate> delegate,
    v8::MeasureMemoryExecution execution,
    const std::vector<Handle<NativeContext>> contexts) {
  int length = static_cast<int>(contexts.size());
  DirectHandle<WeakFixedArray> weak_contexts =
      isolate_->factory()->NewWeakFixedArray(length);
  for (int i = 0; i < length; ++i) {
    weak_contexts->set(i, MakeWeak(*contexts[i]));
  }
  Handle<WeakFixedArray> global_weak_contexts =
      isolate_->global_handles()->Create(*weak_contexts);
  Request request = {std::move(delegate),          // delegate
                     global_weak_contexts,         // contexts
                     std::vector<size_t>(length),  // sizes
                     0u,                           // shared
                     0u,                           // wasm_code
                     0u,                           // wasm_metadata
                     {}};                          // timer
  request.timer.Start();
  received_.push_back(std::move(request));
  ScheduleGCTask(execution);
  return true;
}

std::vector<Address> MemoryMeasurement::StartProcessing() {
  if (received_.empty()) return {};
  std::unordered_set<Address> unique_contexts;
  DCHECK(processing_.empty());
  processing_ = std::move(received_);
  for (const auto& request : processing_) {
    DirectHandle<WeakFixedArray> contexts = request.contexts;
    for (int i = 0; i < contexts->length(); i++) {
      Tagged<HeapObject> context;
      if (contexts->get(i).GetHeapObject(&context)) {
        unique_contexts.insert(context.ptr());
      }
    }
  }
  return std::vector<Address>(unique_contexts.begin(), unique_contexts.end());
}

void MemoryMeasurement::FinishProcessing(const NativeContextStats& stats) {
  if (processing_.empty()) return;

  size_t shared = stats.Get(MarkingWorklists::kSharedContext);
#if V8_ENABLE_WEBASSEMBLY
  size_t wasm_code = wasm::GetWasmCodeManager()->committed_code_space();
  size_t wasm_metadata =
      wasm::GetWasmEngine()->EstimateCurrentMemoryConsumption() +
      wasm::GetWasmImportWrapperCache()->EstimateCurrentMemoryConsumption();
#endif

  while (!processing_.empty()) {
    Request request = std::move(processing_.front());
    processing_.pop_front();
    for (int i = 0; i < static_cast<int>(request.sizes.size()); i++) {
      Tagged<HeapObject> context;
      if (!request.contexts->get(i).GetHeapObject(&context)) {
        continue;
      }
      request.sizes[i] = stats.Get(context.ptr());
    }
    request.shared = shared;
#if V8_ENABLE_WEBASSEMBLY
    request.wasm_code = wasm_code;
    request.wasm_metadata = wasm_metadata;
#endif
    done_.push_back(std::move(request));
  }
  ScheduleReportingTask();
}

void MemoryMeasurement::ScheduleReportingTask() {
  if (reporting_task_pending_) return;
  reporting_task_pending_ = true;
  task_runner_->PostTask(MakeCancelableTask(isolate_, [this] {
    reporting_task_pending_ = false;
    ReportResults();
  }));
}

bool MemoryMeasurement::IsGCTaskPending(v8::MeasureMemoryExecution execution) {
  DCHECK(execution == v8::MeasureMemoryExecution::kEager ||
         execution == v8::MeasureMemoryExecution::kDefault);
  return execution == v8::MeasureMemoryExecution::kEager
             ? eager_gc_task_pending_
             : delayed_gc_task_pending_;
}

void MemoryMeasurement::SetGCTaskPending(v8::MeasureMemoryExecution execution) {
  DCHECK(execution == v8::MeasureMemoryExecution::kEager ||
         execution == v8::MeasureMemoryExecution::kDefault);
  if (execution == v8::MeasureMemoryExecution::kEager) {
    eager_gc_task_pending_ = true;
  } else {
    delayed_gc_task_pending_ = true;
  }
}

void MemoryMeasurement::SetGCTaskDone(v8::MeasureMemoryExecution execution) {
  DCHECK(execution == v8::MeasureMemoryExecution::kEager ||
         execution == v8::MeasureMemoryExecution::kDefault);
  if (execution == v8::MeasureMemoryExecution::kEager) {
    eager_gc_task_pending_ = false;
  } else {
    delayed_gc_task_pending_ = false;
  }
}

void MemoryMeasurement::ScheduleGCTask(v8::MeasureMemoryExecution execution) {
  if (execution == v8::MeasureMemoryExecution::kLazy) return;
  if (IsGCTaskPending(execution)) return;
  SetGCTaskPending(execution);
  auto task = MakeCancelableTask(isolate_, [this, execution] {
    SetGCTaskDone(execution);
    if (received_.empty()) return;
    Heap* heap = isolate_->heap();
    if (v8_flags.incremental_marking) {
      if (heap->incremental_marking()->IsStopped()) {
        heap->StartIncrementalMarking(GCFlag::kNoFlags,
                                      GarbageCollectionReason::kMeasureMemory);
      } else {
        if (execution == v8::MeasureMemoryExecution::kEager) {
          heap->FinalizeIncrementalMarkingAtomically(
              GarbageCollectionReason::kMeasureMemory);
        }
        ScheduleGCTask(execution);
      }
    } else {
      heap->CollectGarbage(OLD_SPACE, GarbageCollectionReason::kMeasureMemory);
    }
  });
  if (execution == v8::MeasureMemoryExecution::kEager) {
    task_runner_->PostTask(std::move(task));
  } else {
    task_runner_->PostDelayedTask(std::move(task), NextGCTaskDelayInSeconds());
  }
}

int MemoryMeasurement::NextGCTaskDelayInSeconds() {
  return kGCTaskDelayInSeconds +
         random_number_generator_.NextInt(kGCTaskDelayInSeconds);
}

void MemoryMeasurement::ReportResults() {
  while (!done_.empty() && !isolate_->is_execution_terminating()) {
    Request request = std::move(done_.front());
    done_.pop_front();
    HandleScope handle_scope(isolate_);
    v8::LocalVector<v8::Context> contexts(
        reinterpret_cast<v8::Isolate*>(isolate_));
    std::vector<size_t> size_in_bytes;
    DCHECK_EQ(request.sizes.size(),
              static_cast<size_t>(request.contexts->length()));
    for (int i = 0; i < request.contexts->length(); i++) {
      Tagged<HeapObject> raw_context;
      if (!request.contexts->get(i).GetHeapObject(&raw_context)) {
        continue;
      }
      Local<v8::Context> context = Utils::Convert<HeapObject, v8::Context>(
          direct_handle(raw_context, isolate_));
      contexts.push_back(context);
      size_in_bytes.push_back(request.sizes[i]);
    }
    request.delegate->MeasurementComplete(
        {{contexts.begin(), contexts.end()},
         {size_in_bytes.begin(), size_in_bytes.end()},
         request.shared,
         request.wasm_code,
         request.wasm_metadata});
    isolate_->counters()->measure_memory_delay_ms()->AddSample(
        static_cast<int>(request.timer.Elapsed().InMilliseconds()));
  }
}

std::unique_ptr<v8::MeasureMemoryDelegate> MemoryMeasurement::DefaultDelegate(
    v8::Isolate* isolate, v8::Local<v8::Context> context,
    v8::Local<v8::Promise::Resolver> promise, v8::MeasureMemoryMode mode) {
  return std::make_unique<MeasureMemoryDelegate>(isolate, context, promise,
                                                 mode);
}

void NativeContextStats::Clear() { size_by_context_.clear(); }

void NativeContextStats::Merge(const NativeContextStats& other) {
  for (const auto& it : other.size_by_context_) {
    size_by_context_[it.first] += it.second;
  }
}

void NativeContextStats::IncrementExternalSize(Address context, Tagged<Map> map,
                                               Tagged<HeapObject> object) {
  InstanceType instance_type = map->instance_type();
  size_t external_size = 0;
  if (instance_type == JS_ARRAY_BUFFER_TYPE) {
    external_size = Cast<JSArrayBuffer>(object)->GetByteLength();
  } else {
    DCHECK(InstanceTypeChecker::IsExternalString(instance_type));
    external_size = Cast<ExternalString>(object)->ExternalPayloadSize();
  }
  size_by_context_[context] += external_size;
}

}  // namespace v8::internal
```