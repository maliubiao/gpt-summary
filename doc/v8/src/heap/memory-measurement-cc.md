Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of `memory-measurement.cc`, connections to JavaScript, potential programming errors, and considerations for Torque (`.tq`).

2. **Initial Code Scan - High-Level Overview:**
   - The file includes several V8 headers (`v8-local-handle.h`, `api-inl.h`, etc.), indicating it's part of V8's internal implementation.
   - The namespace `v8::internal` confirms this.
   - The presence of `MeasureMemoryDelegate` and `MemoryMeasurement` classes suggests this code is about measuring memory usage within V8.
   - `#if V8_ENABLE_WEBASSEMBLY` blocks point to specific handling for WebAssembly memory.

3. **Focus on Key Classes:** The two main classes are `MemoryMeasurementResultBuilder` and `MemoryMeasurement`. Let's examine them in detail.

4. **`MemoryMeasurementResultBuilder`:**
   - **Purpose:** The name strongly suggests building a result object for memory measurements.
   - **Constructor:** Takes a `v8::Isolate*`, indicating it's tied to a specific V8 instance. It creates a JavaScript object (`result_`).
   - **`AddTotal`, `AddCurrent`, `AddOther`, `AddWasm`:** These methods add properties to the `result_` object. The names clearly indicate what kind of memory they represent (total, current, other contexts, WebAssembly). They take size estimates and bounds, suggesting a level of approximation in the measurements.
   - **`Build`:** This method finalizes the result object, potentially adding an "other" array if `detailed_` is true.
   - **Helper Methods (`NewResult`, `NewNumber`, `NewJSObject`, `NewRange`, `AddProperty`):** These encapsulate the creation of JavaScript values and the structure of the result object. Notice how it creates nested objects with "estimate" and "range" properties.
   - **Private Members:** `isolate_`, `factory_`, `result_`, `other_`, `detailed_`. These store the context, the object factory, the constructed result, and temporary data.

5. **`MeasureMemoryDelegate`:**
   - **Purpose:** The name hints at a delegate pattern for handling memory measurement events. It inherits from `v8::MeasureMemoryDelegate`.
   - **Constructor:** Takes `v8::Isolate*`, `v8::Local<v8::Context>`, `v8::Local<v8::Promise::Resolver>`, and `v8::MeasureMemoryMode`. This indicates it's associated with a specific context and uses a Promise to return the result.
   - **`ShouldMeasure`:** Determines if measurement should occur for a given context, likely based on security tokens. This is crucial for multi-context scenarios.
   - **`MeasurementComplete`:** The core of the delegate. It receives the measurement results (`Result`), processes them, uses `MemoryMeasurementResultBuilder` to create a JavaScript object, and resolves the associated Promise. Pay attention to how it handles "shared" memory and the conditional logic for detailed mode.

6. **`MemoryMeasurement`:**
   - **Purpose:** The central class for managing memory measurement requests.
   - **Constructor:** Takes an `Isolate*` and initializes a task runner and a random number generator (for delaying GC).
   - **`EnqueueRequest`:** Adds a new measurement request, associating it with a delegate, execution mode, and relevant contexts. It also schedules a garbage collection task.
   - **`StartProcessing`:**  Initiates the measurement process, collecting unique contexts to measure.
   - **`FinishProcessing`:** Receives the memory statistics (`NativeContextStats`), distributes the sizes to the requests, and schedules the reporting task. WebAssembly memory is handled here.
   - **`ScheduleReportingTask`, `ReportResults`:** Manages the asynchronous reporting of results back to JavaScript through the Promises.
   - **GC-Related Methods (`IsGCTaskPending`, `SetGCTaskPending`, `SetGCTaskDone`, `ScheduleGCTask`, `NextGCTaskDelayInSeconds`):** These methods are responsible for triggering and managing garbage collection cycles to get accurate memory measurements. The random delay is interesting.
   - **`DefaultDelegate`:** A static method to create a default `MeasureMemoryDelegate`.

7. **`NativeContextStats`:**
   - **Purpose:** A simple class to store memory usage per native context.
   - **Methods:** `Clear`, `Merge`, `IncrementExternalSize`. The latter handles special cases for `JSArrayBuffer` and `ExternalString`.

8. **Connecting to JavaScript:**
   - The `MeasureMemoryDelegate` receives a `v8::Local<v8::Promise::Resolver>`. This is the key connection. When `MeasurementComplete` is called, it resolves this Promise with the JavaScript object built by `MemoryMeasurementResultBuilder`.
   -  The structure of the JavaScript object being built (with "total", "current", "other", "WebAssembly", "estimate", "range") provides the data that JavaScript will receive.

9. **Torque Consideration:** The code is C++, not Torque. The request provides a hint about `.tq` files, which isn't applicable here. Acknowledge this and move on.

10. **Code Logic and Assumptions:**
    - **Input (JavaScript side):**  The user would call a V8 API function (not shown in this snippet) to trigger memory measurement, likely providing a context and an execution mode. This would create a `MeasureMemoryDelegate` and enqueue it.
    - **Internal Processing:**  `MemoryMeasurement` manages the lifecycle, triggering GC and collecting statistics.
    - **Output (JavaScript side):** A Promise that resolves to a JavaScript object with memory usage details. Structure of the object is determined by `MemoryMeasurementResultBuilder`.

11. **Common Programming Errors:**  Think about how a *user* might misuse this API (even though the C++ is internal, the API it exposes to JS is relevant).
    - Calling the API without a valid context.
    - Misinterpreting the "estimate" and "range" values.
    - Not understanding the implications of different `MeasureMemoryMode` values.
    - Assuming instantaneous results (since it's asynchronous).

12. **Refine and Organize:**  Structure the answer logically with clear headings, examples (JavaScript), and explanations. Ensure all aspects of the request are addressed. Use clear and concise language. For the JavaScript example, provide a plausible (though simplified) scenario, focusing on the asynchronous nature and the structure of the returned object.

By following these steps, we can systematically analyze the C++ code and address all the points raised in the request. The key is to break down the code into smaller, manageable parts and understand the purpose and interactions of each component.
这段C++源代码文件 `v8/src/heap/memory-measurement.cc` 的主要功能是**提供一种机制来测量V8堆内存的使用情况，并将结果报告给JavaScript环境。** 它允许开发者获取关于 V8 引擎在不同上下文中的内存消耗的详细信息。

让我们分解一下它的主要组成部分和功能：

**1. `MemoryMeasurementResultBuilder` 类:**

* **功能:**  这个类负责构建最终要返回给 JavaScript 的内存测量结果对象。它是一个辅助类，用于组织和格式化测量数据。
* **工作原理:**
    * 它在构造函数中创建一个空的 JavaScript 对象。
    * 提供 `AddTotal`, `AddCurrent`, `AddOther`, `AddWasm` 等方法来添加不同类型的内存测量数据（总内存、当前上下文内存、其他上下文内存、WebAssembly 相关内存）。
    * 这些 `Add` 方法内部会创建包含 `estimate`（估计值）和 `range`（范围，包含下限和上限）的 JavaScript 对象。
    * `Build` 方法最终将所有收集到的数据整理成一个 JavaScript 对象并返回。
* **与 JavaScript 的关系:**  这个类直接创建可以被 JavaScript 代码访问的 JavaScript 对象。例如，`AddTotal` 方法会将一个名为 "total" 的属性添加到结果对象中，该属性的值也是一个包含 "jsMemoryEstimate" 和 "jsMemoryRange" 属性的 JavaScript 对象。

**JavaScript 示例:**

假设 `v8/src/heap/memory-measurement.cc` 的功能被暴露给 JavaScript，开发者可能会使用类似这样的 API：

```javascript
// 假设存在一个全局函数或对象可以触发内存测量
v8.measureMemory().then(memoryInfo => {
  console.log("总内存:", memoryInfo.total.jsMemoryEstimate);
  console.log("当前上下文内存:", memoryInfo.current.jsMemoryEstimate);
  if (memoryInfo.other) {
    console.log("其他上下文内存:", memoryInfo.other.map(o => o.jsMemoryEstimate));
  }
  if (memoryInfo.WebAssembly) {
    console.log("WebAssembly 代码内存:", memoryInfo.WebAssembly.code);
    console.log("WebAssembly 元数据内存:", memoryInfo.WebAssembly.metadata);
  }
});
```

**2. `MeasureMemoryDelegate` 类:**

* **功能:**  这是一个实现了 `v8::MeasureMemoryDelegate` 接口的类，用于处理内存测量的完成事件。它充当了 V8 内部测量机制和 JavaScript 回调之间的桥梁。
* **工作原理:**
    * 构造函数接收 `v8::Isolate`、`v8::Context` 和 `v8::Promise::Resolver`。`Promise::Resolver` 用于在测量完成后将结果返回给 JavaScript。
    * `ShouldMeasure` 方法决定是否应该测量给定的上下文。通常基于安全令牌进行判断，确保只测量相关的上下文。
    * `MeasurementComplete` 方法在内存测量完成后被调用。它接收包含各个上下文内存大小的 `Result` 对象。
    * 在 `MeasurementComplete` 中，它会使用 `MemoryMeasurementResultBuilder` 来构建结果对象，并将结果通过 `Promise::Resolver` 返回给 JavaScript。

**3. `MemoryMeasurement` 类:**

* **功能:**  这个类是内存测量功能的核心管理器。它负责调度垃圾回收、收集内存统计信息，并管理测量请求。
* **工作原理:**
    * 维护一个请求队列 `received_` 和一个正在处理的请求队列 `processing_`。
    * `EnqueueRequest` 方法接收来自 JavaScript 的测量请求，创建一个 `MeasureMemoryDelegate`，并将其添加到 `received_` 队列。
    * `StartProcessing` 方法开始处理请求，通常会在垃圾回收之前调用，以获取需要测量的上下文列表。
    * `FinishProcessing` 方法在垃圾回收完成后被调用，接收包含每个上下文内存大小的 `NativeContextStats`。它将这些信息与请求关联起来。
    * `ScheduleGCTask` 方法负责调度垃圾回收。它可以选择立即执行（`kEager`）或延迟执行（`kDefault`）。进行垃圾回收是为了获取准确的内存使用情况。
    * `ReportResults` 方法在所有测量完成后被调用，它会遍历 `done_` 队列，调用每个请求的 `MeasureMemoryDelegate` 的 `MeasurementComplete` 方法，将结果返回给 JavaScript。

**4. `NativeContextStats` 类:**

* **功能:**  用于存储每个 NativeContext 的内存使用统计信息。
* **工作原理:**
    * 使用 `std::unordered_map` `size_by_context_` 来存储上下文地址和对应的内存大小。
    * 提供 `Clear`, `Merge`, `IncrementExternalSize` 等方法来管理统计数据。`IncrementExternalSize` 用于记录外部资源（如 ArrayBuffer 和外部字符串）的大小。

**与 JavaScript 的关系:**

虽然 `memory-measurement.cc` 本身是 C++ 代码，但它的最终目标是为 JavaScript 提供内存使用情况的洞察。V8 引擎会暴露一些 JavaScript API（具体 API 可能不在这个文件中定义，而是在其他地方，例如 `v8/src/api/api.cc`），允许 JavaScript 代码请求内存测量。

**代码逻辑推理:**

**假设输入:**

1. JavaScript 代码调用 V8 提供的内存测量 API，并指定要测量的上下文（或默认测量所有上下文）。
2. V8 内部创建了一个 `MeasureMemoryDelegate` 实例和一个 `Promise` 对象。

**输出:**

1. 在一段时间后（可能涉及垃圾回收），JavaScript 的 Promise 会被 resolve，并返回一个 JavaScript 对象，该对象包含以下信息（取决于 `MeasureMemoryMode`）：
   * `total`:  包含整个 V8 堆的总估计内存大小和范围。
   * `current`:  包含指定上下文的估计内存大小和范围（如果 `MeasureMemoryMode` 是 `kDetailed`）。
   * `other`:  一个数组，包含其他上下文的估计内存大小和范围（如果 `MeasureMemoryMode` 是 `kDetailed`）。
   * `WebAssembly`:  包含 WebAssembly 代码和元数据的内存大小（如果存在）。

**用户常见的编程错误:**

由于 `memory-measurement.cc` 是 V8 内部代码，用户不会直接编写或修改它。然而，用户在使用 V8 提供的内存测量 API 时可能会遇到以下编程错误或误解：

1. **误解估计值和范围:** 用户可能会认为返回的 `estimate` 是一个精确的值，而忽略了 `range` 提供的误差范围。实际的内存使用可能在这个范围内波动。
2. **过度依赖单一测量结果:**  内存使用是一个动态变化的值。用户可能会基于一次测量结果做出错误的性能判断。应该进行多次测量并取平均值或观察趋势。
3. **不理解垃圾回收的影响:** 内存测量通常会触发垃圾回收以获取更准确的结果。用户可能会不理解为什么调用内存测量 API 后，程序的性能会暂时受到影响。
4. **错误地比较不同类型的内存大小:**  用户可能会混淆 JavaScript 堆内存、WebAssembly 内存、代码缓存等不同类型的内存消耗。返回的结果会尝试区分这些类型，但用户需要理解这些概念。
5. **在性能关键代码中频繁调用:**  内存测量操作本身会有一定的开销，尤其是在触发垃圾回收的情况下。在性能关键的代码路径中频繁调用可能会导致性能下降。

**关于 `.tq` 结尾:**

如果 `v8/src/heap/memory-measurement.cc` 以 `.tq` 结尾，那么它确实是 V8 Torque 源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。然而，根据您提供的文件名，它以 `.cc` 结尾，这意味着它是 C++ 源代码。

**总结:**

`v8/src/heap/memory-measurement.cc` 是 V8 引擎中一个关键的组件，它提供了测量和报告 JavaScript 堆内存使用情况的功能。它通过 `MeasureMemoryDelegate` 和 `MemoryMeasurementResultBuilder` 等类来管理测量过程和格式化结果，并将最终的测量数据通过 Promise 返回给 JavaScript 环境。理解这个文件的功能有助于理解 V8 如何进行内存管理和为开发者提供内存使用情况的洞察。

Prompt: 
```
这是目录为v8/src/heap/memory-measurement.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/memory-measurement.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```