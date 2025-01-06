Response:
Let's break down the thought process for analyzing the `v8-metrics.h` file and answering the prompt's questions.

**1. Initial Scan and Understanding the Purpose:**

* **Keywords:** The filename itself, "metrics," immediately suggests the file is about collecting and reporting performance data. The copyright notice confirms it's a V8 project file.
* **Headers:** The included headers (`stddef.h`, `stdint.h`, `<optional>`, `<vector>`, `v8-internal.h`, `v8-isolate.h`, `v8-local-handle.h`, `v8config.h`) provide clues. They indicate the file deals with basic types, optional values, dynamic arrays, and V8-specific concepts like isolates, contexts, and internal structures.
* **Namespace:** The code is within the `v8::metrics` namespace, clearly delineating its role within the broader V8 project.
* **Key Structures:**  Quickly identifying the major `struct` definitions like `GarbageCollectionPhases`, `GarbageCollectionSizes`, `GarbageCollectionFullCycle`, `WasmModuleDecoded`, `WasmModuleCompiled`, etc., is crucial. These structs represent different types of metrics being tracked.

**2. Deconstructing the Structures:**

* **Garbage Collection Metrics:** The abundance of `GarbageCollection...` structs signals a strong focus on tracking garbage collection performance. Looking at the members within these structs (`total_wall_clock_duration_in_us`, `bytes_before`, `bytes_after`, `reason`, `priority`, etc.) provides insight into the specific aspects being measured (timing, memory usage, reasons for GC, etc.). The different phases (mark, sweep, compact) are clearly broken down.
* **Wasm Metrics:** The `WasmModuleDecoded`, `WasmModuleCompiled`, and `WasmModuleInstantiated` structs clearly relate to WebAssembly execution. The members (e.g., `async`, `streamed`, `success`, `module_size_in_bytes`, `code_size_in_bytes`, `wall_clock_duration_in_us`) indicate metrics related to different stages of the Wasm lifecycle.
* **`Recorder` Class:** This class is central. The comments explicitly state its role as a base class for recording events. The virtual `AddMainThreadEvent` and `AddThreadSafeEvent` methods with different struct types as arguments demonstrate how different types of metrics are reported. The `ContextId` nested class and the `GetContext`/`GetContextId` static methods suggest a mechanism for associating metrics with specific JavaScript contexts.
* **`LongTaskStats` Struct:** The comments clearly mark this as an experimental API for tracking long-running tasks and attribute work within those tasks.

**3. Inferring Functionality from Structures and Methods:**

* **Performance Monitoring:** The primary function is clearly performance monitoring and tracking of various V8 subsystems, particularly garbage collection and WebAssembly.
* **Event-Based Metrics:** The `Recorder` class and the "Add...Event" methods indicate an event-driven approach to metrics collection. When certain events happen (e.g., a GC cycle completes, a Wasm module is compiled), a corresponding metric is recorded.
* **Thread Safety:** The distinction between `AddMainThreadEvent` and `AddThreadSafeEvent` is important. It highlights that some metrics can be collected from any thread, while others are specific to the main V8 thread. This likely relates to access to V8's internal state.
* **Context Association:** The `ContextId` and related methods suggest the ability to associate metrics with specific JavaScript execution contexts, allowing for fine-grained analysis.

**4. Addressing the Specific Questions in the Prompt:**

* **Functionality Listing:**  Based on the identified structures and methods, listing the core functionalities becomes straightforward (tracking GC, Wasm compilation, providing a base class for custom metrics, experimental long task tracking).
* **Torque Source:** The prompt explicitly states the `.tq` condition. Since the filename is `.h`, this part is a quick check.
* **JavaScript Relationship and Example:**  Connecting GC and Wasm to JavaScript is crucial. GC is fundamental to JavaScript's memory management. Wasm is often used within JavaScript environments. The example focuses on triggering GC through object creation and Wasm usage via the `WebAssembly` API.
* **Code Logic and Assumptions:**  The GC structs offer opportunities for logical reasoning. The example demonstrates calculating `bytes_freed` and efficiency, highlighting basic metric calculations. The assumptions are simply that the before/after values are correctly recorded.
* **Common Programming Errors:**  Thinking about how users might interact with a metrics system leads to potential errors. Forgetting to set the recorder, assuming immediate availability of context data, and misinterpreting time units are all plausible mistakes.

**5. Refining and Organizing the Answer:**

* **Clear Headings:**  Using headings for each part of the prompt makes the answer easy to read and understand.
* **Concise Explanations:**  Avoid overly technical jargon where possible. Explain concepts clearly and simply.
* **Code Examples:**  Provide concrete JavaScript examples to illustrate the connection to user-level code.
* **Structured Output:**  Format the information logically, addressing each part of the prompt systematically.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the file also handles CPU profiling?  **Correction:**  A closer look at the structs reveals a primary focus on memory (GC) and Wasm compilation stages. CPU profiling might be handled elsewhere in V8.
* **Initial thought:**  How are these metrics *used*? **Correction:** The file defines the *structure* of the metrics and the *interface* for recording them. The actual consumption and reporting of these metrics likely happen in other parts of V8 or by the embedder (e.g., Chrome). The prompt is focused on *what* is being measured, not *how* it's used.
* **Ensuring JavaScript Examples are Relevant:**  Double-checking that the JavaScript examples genuinely demonstrate the concepts being discussed (GC and Wasm).

By following this structured approach, combining code analysis with domain knowledge about V8, and addressing each part of the prompt systematically, it's possible to generate a comprehensive and accurate answer.
The `v8/include/v8-metrics.h` file in the V8 source code defines data structures and an interface for recording various performance metrics within the V8 JavaScript engine. Let's break down its functionalities based on the provided code.

**Core Functionalities:**

1. **Garbage Collection Metrics:** This is a major focus. The file defines structs to capture detailed information about both full and young generation garbage collection cycles:
   - **`GarbageCollectionPhases`:**  Tracks the duration of different GC phases (compact, mark, sweep, weak processing).
   - **`GarbageCollectionSizes`:** Records memory usage before and after GC, and the amount of memory freed.
   - **`GarbageCollectionFullCycle`:**  Aggregates information about a full GC cycle, including the reason for the GC, isolate priority, detailed phase timings (on the main thread and potentially other threads), object and memory size changes, collection rates, and efficiency metrics.
   - **`GarbageCollectionYoungCycle`:**  Similar to `GarbageCollectionFullCycle` but for young generation GCs, which are typically faster and more frequent.
   - **Batched Incremental Marking/Sweeping Metrics:**  Structures to record durations of individual incremental marking and sweeping steps within a full GC.

2. **WebAssembly (Wasm) Metrics:**  The file includes structs to track the different stages of Wasm module processing:
   - **`WasmModuleDecoded`:**  Records information about Wasm module decoding, including whether it was asynchronous, streamed, successful, the module size, function count, and decoding duration.
   - **`WasmModuleCompiled`:** Captures details about Wasm compilation, including whether it was async, streamed, cached, deserialized, lazy, successful, the code size, the number of "liftoff" bailout events (an optimization technique), and compilation time.
   - **`WasmModuleInstantiated`:**  Tracks Wasm instantiation, including asynchronicity, success, the number of imported functions, and instantiation duration.
   - **`WasmModulesPerIsolate`:** A simple counter for the number of Wasm modules in an isolate.

3. **`Recorder` Class:** This is the core interface for reporting metrics. Embedders (like Chrome) implementing V8 will provide a concrete implementation of this class.
   - **Event-Based:** The `Recorder` uses an event-based approach. When specific events occur in V8 (like a GC cycle finishing or a Wasm module being compiled), the corresponding `Add...Event` method on the registered `Recorder` is called.
   - **Main Thread vs. Thread-Safe Events:**  The `Recorder` distinguishes between events that happen on the main V8 thread (which can access the current context) and thread-safe events (which cannot). This is crucial for concurrency safety.
   - **Context Association:** The `ContextId` nested class and the `GetContext`/`GetContextId` static methods allow associating metrics with specific JavaScript contexts.

4. **`LongTaskStats` (Experimental):** This struct and its associated methods are for tracking the duration of long-running tasks and attributing V8's work within those tasks (GC time, execution time). This is designed for integration with systems like UKM (User Keyed Metrics) in Chromium to identify performance bottlenecks.

**If `v8/include/v8-metrics.h` ended with `.tq`, it would be a V8 Torque source file.**

Torque is V8's domain-specific language for writing compiler intrinsics and runtime functions. It generates C++ code that is highly optimized and tightly integrated with V8's internal workings. If `v8-metrics.h` were a `.tq` file, it would likely contain Torque code to efficiently record and potentially process these metrics directly within V8's internal runtime.

**Relationship with JavaScript and Examples:**

Many of the metrics in `v8-metrics.h` directly relate to the performance of JavaScript execution.

**Garbage Collection:**  JavaScript relies on garbage collection for automatic memory management. The GC metrics directly reflect how efficiently V8 is reclaiming memory. Frequent or long GC pauses can impact JavaScript application responsiveness.

```javascript
// JavaScript example to trigger garbage collection (indirectly)

let myObject = {};
let largeArray = [];
for (let i = 0; i < 1000000; i++) {
  largeArray.push(i);
}
myObject.data = largeArray;

// ... later, if myObject is no longer reachable, it becomes eligible for GC.
myObject = null;

// You cannot directly trigger GC in standard JavaScript, but you can
// often observe its effects through performance monitoring.
```

When the JavaScript engine runs the garbage collector, the `GarbageCollectionFullCycle` or `GarbageCollectionYoungCycle` events would be triggered, and the `Recorder` would capture the details defined in the corresponding structs. The metrics would show how long the GC took, how much memory was freed, etc.

**WebAssembly:**  Wasm allows running code written in languages like C++ at near-native speed within the browser. The Wasm metrics track the performance of loading and compiling Wasm modules, which directly impacts the startup time and performance of web applications using Wasm.

```javascript
// JavaScript example using WebAssembly

async function loadAndRunWasm() {
  try {
    const response = await fetch('my_module.wasm');
    const buffer = await response.arrayBuffer();
    const module = await WebAssembly.compile(buffer); // Triggers WasmModuleCompiled metrics
    const instance = await WebAssembly.instantiate(module); // Triggers WasmModuleInstantiated metrics
    const result = instance.exports.add(5, 10);
    console.log("Wasm result:", result);
  } catch (e) {
    console.error("Error loading or running Wasm:", e);
  }
}

loadAndRunWasm(); // Triggers WasmModuleDecoded when fetching starts
```

When the `WebAssembly.compile()` and `WebAssembly.instantiate()` functions are called, the corresponding `WasmModuleCompiled` and `WasmModuleInstantiated` events would be triggered, and the `Recorder` would capture the associated metrics (compilation time, success/failure, etc.).

**Code Logic Inference with Assumptions:**

Let's take the `GarbageCollectionFullCycle` struct as an example.

**Hypothetical Input:**

Assume a full garbage collection cycle just completed with the following:

- **`reason`:**  `kAllocationPressure` (the GC was triggered due to memory pressure)
- **`priority`:** `v8::Isolate::Priority::kForeground`
- **`total.total_wall_clock_duration_in_us`:** 150000 (microseconds)
- **`objects.bytes_before`:** 10000000 (bytes)
- **`objects.bytes_after`:** 5000000 (bytes)

**Code Logic (within the `Recorder` implementation, not explicitly in this header):**

The `Recorder` implementation would likely have logic to calculate metrics based on these raw values. For example:

- **`objects.bytes_freed`:** `objects.bytes_before - objects.bytes_after` = 10000000 - 5000000 = 5000000 bytes.
- **`efficiency_in_bytes_per_us`:** `objects.bytes_freed / total.total_wall_clock_duration_in_us` = 5000000 / 150000 = 33.33 bytes/us.

**Hypothetical Output (recorded by the `Recorder`):**

The `GarbageCollectionFullCycle` event recorded would contain these calculated values, along with the input values.

**User-Common Programming Errors Related to Metrics:**

1. **Not Setting a Metrics Recorder:**  If the embedder forgets to call `v8::Isolate::SetMetricsRecorder()`, no metrics will be collected, even though V8 is generating the events. This is a configuration error.

   ```cpp
   // Example of missing the metrics recorder setup
   v8::Isolate::CreateParams create_params;
   create_params.array_buffer_allocator =
       v8::ArrayBuffer::Allocator::NewDefaultAllocator();
   v8::Isolate* isolate = v8::Isolate::New(create_params);

   // Missing: isolate->SetMetricsRecorder(my_recorder_implementation);

   {
     v8::Isolate::Scope isolate_scope(isolate);
     v8::HandleScope handle_scope(isolate);
     v8::Local<v8::Context> context = v8::Context::New(isolate);
     v8::Context::Scope context_scope(context);
     // ... run JavaScript that generates metrics ...
   }

   isolate->Dispose();
   delete create_params.array_buffer_allocator;
   ```

2. **Misinterpreting Metric Units:**  Forgetting that durations are often in microseconds (`_in_us`) or that sizes are in bytes can lead to incorrect analysis. A developer might assume milliseconds and draw wrong conclusions about performance.

3. **Assuming Immediate Availability of Context Information in Thread-Safe Events:** Thread-safe events in the `Recorder` do not carry the context directly. While they have a `ContextId`, the actual `Context` object might have been garbage collected by the time the event is processed. Trying to dereference an invalid context handle based on a thread-safe event's `ContextId` would be an error.

4. **Focusing on Raw Timings Without Considering Context:** A high GC duration might be acceptable if it happens infrequently and reclaims a large amount of memory. Just looking at the raw duration without considering the `bytes_freed` or the reason for the GC can lead to misleading conclusions.

5. **Not Understanding the Asynchronous Nature of Some Operations:** For Wasm, the `async` flags in the metrics structs are crucial. If a developer only looks at synchronous compilation times, they might miss the performance benefits of asynchronous compilation.

In summary, `v8/include/v8-metrics.h` is a critical header file in V8 that defines the structure for collecting and reporting various performance metrics related to garbage collection and WebAssembly. It provides the foundation for understanding and optimizing the performance of the V8 JavaScript engine and applications running on it.

Prompt: 
```
这是目录为v8/include/v8-metrics.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-metrics.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_METRICS_H_
#define V8_METRICS_H_

#include <stddef.h>
#include <stdint.h>

#include <optional>
#include <vector>

#include "v8-internal.h"      // NOLINT(build/include_directory)
#include "v8-isolate.h"       // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

class Context;
class Isolate;

namespace metrics {

struct GarbageCollectionPhases {
  int64_t total_wall_clock_duration_in_us = -1;
  int64_t compact_wall_clock_duration_in_us = -1;
  int64_t mark_wall_clock_duration_in_us = -1;
  int64_t sweep_wall_clock_duration_in_us = -1;
  int64_t weak_wall_clock_duration_in_us = -1;
};

struct GarbageCollectionSizes {
  int64_t bytes_before = -1;
  int64_t bytes_after = -1;
  int64_t bytes_freed = -1;
};

struct GarbageCollectionFullCycle {
  int reason = -1;
  // The priority of the isolate during the GC cycle. A nullopt value denotes a
  // mixed priority cycle, meaning the Isolate's priority was changed while the
  // cycle was in progress.
  std::optional<v8::Isolate::Priority> priority = std::nullopt;
  GarbageCollectionPhases total;
  GarbageCollectionPhases total_cpp;
  GarbageCollectionPhases main_thread;
  GarbageCollectionPhases main_thread_cpp;
  GarbageCollectionPhases main_thread_atomic;
  GarbageCollectionPhases main_thread_atomic_cpp;
  GarbageCollectionPhases main_thread_incremental;
  GarbageCollectionPhases main_thread_incremental_cpp;
  GarbageCollectionSizes objects;
  GarbageCollectionSizes objects_cpp;
  GarbageCollectionSizes memory;
  GarbageCollectionSizes memory_cpp;
  double collection_rate_in_percent = -1.0;
  double collection_rate_cpp_in_percent = -1.0;
  double efficiency_in_bytes_per_us = -1.0;
  double efficiency_cpp_in_bytes_per_us = -1.0;
  double main_thread_efficiency_in_bytes_per_us = -1.0;
  double main_thread_efficiency_cpp_in_bytes_per_us = -1.0;
  double collection_weight_in_percent = -1.0;
  double collection_weight_cpp_in_percent = -1.0;
  double main_thread_collection_weight_in_percent = -1.0;
  double main_thread_collection_weight_cpp_in_percent = -1.0;
  int64_t incremental_marking_start_stop_wall_clock_duration_in_us = -1;
};

struct GarbageCollectionFullMainThreadIncrementalMark {
  int64_t wall_clock_duration_in_us = -1;
  int64_t cpp_wall_clock_duration_in_us = -1;
};

struct GarbageCollectionFullMainThreadIncrementalSweep {
  int64_t wall_clock_duration_in_us = -1;
  int64_t cpp_wall_clock_duration_in_us = -1;
};

template <typename EventType>
struct GarbageCollectionBatchedEvents {
  std::vector<EventType> events;
};

using GarbageCollectionFullMainThreadBatchedIncrementalMark =
    GarbageCollectionBatchedEvents<
        GarbageCollectionFullMainThreadIncrementalMark>;
using GarbageCollectionFullMainThreadBatchedIncrementalSweep =
    GarbageCollectionBatchedEvents<
        GarbageCollectionFullMainThreadIncrementalSweep>;

struct GarbageCollectionYoungCycle {
  int reason = -1;
  // The priority of the isolate during the GC cycle. A nullopt value denotes a
  // mixed priority cycle, meaning the Isolate's priority was changed while the
  // cycle was in progress.
  std::optional<v8::Isolate::Priority> priority = std::nullopt;
  int64_t total_wall_clock_duration_in_us = -1;
  int64_t main_thread_wall_clock_duration_in_us = -1;
  double collection_rate_in_percent = -1.0;
  double efficiency_in_bytes_per_us = -1.0;
  double main_thread_efficiency_in_bytes_per_us = -1.0;
#if defined(CPPGC_YOUNG_GENERATION)
  GarbageCollectionPhases total_cpp;
  GarbageCollectionSizes objects_cpp;
  GarbageCollectionSizes memory_cpp;
  double collection_rate_cpp_in_percent = -1.0;
  double efficiency_cpp_in_bytes_per_us = -1.0;
  double main_thread_efficiency_cpp_in_bytes_per_us = -1.0;
#endif  // defined(CPPGC_YOUNG_GENERATION)
};

struct WasmModuleDecoded {
  WasmModuleDecoded() = default;
  WasmModuleDecoded(bool async, bool streamed, bool success,
                    size_t module_size_in_bytes, size_t function_count,
                    int64_t wall_clock_duration_in_us)
      : async(async),
        streamed(streamed),
        success(success),
        module_size_in_bytes(module_size_in_bytes),
        function_count(function_count),
        wall_clock_duration_in_us(wall_clock_duration_in_us) {}

  bool async = false;
  bool streamed = false;
  bool success = false;
  size_t module_size_in_bytes = 0;
  size_t function_count = 0;
  int64_t wall_clock_duration_in_us = -1;
};

struct WasmModuleCompiled {
  WasmModuleCompiled() = default;

  WasmModuleCompiled(bool async, bool streamed, bool cached, bool deserialized,
                     bool lazy, bool success, size_t code_size_in_bytes,
                     size_t liftoff_bailout_count,
                     int64_t wall_clock_duration_in_us)
      : async(async),
        streamed(streamed),
        cached(cached),
        deserialized(deserialized),
        lazy(lazy),
        success(success),
        code_size_in_bytes(code_size_in_bytes),
        liftoff_bailout_count(liftoff_bailout_count),
        wall_clock_duration_in_us(wall_clock_duration_in_us) {}

  bool async = false;
  bool streamed = false;
  bool cached = false;
  bool deserialized = false;
  bool lazy = false;
  bool success = false;
  size_t code_size_in_bytes = 0;
  size_t liftoff_bailout_count = 0;
  int64_t wall_clock_duration_in_us = -1;
};

struct WasmModuleInstantiated {
  bool async = false;
  bool success = false;
  size_t imported_function_count = 0;
  int64_t wall_clock_duration_in_us = -1;
};

struct WasmModulesPerIsolate {
  size_t count = 0;
};

/**
 * This class serves as a base class for recording event-based metrics in V8.
 * There a two kinds of metrics, those which are expected to be thread-safe and
 * whose implementation is required to fulfill this requirement and those whose
 * implementation does not have that requirement and only needs to be
 * executable on the main thread. If such an event is triggered from a
 * background thread, it will be delayed and executed by the foreground task
 * runner.
 *
 * The embedder is expected to call v8::Isolate::SetMetricsRecorder()
 * providing its implementation and have the virtual methods overwritten
 * for the events it cares about.
 */
class V8_EXPORT Recorder {
 public:
  // A unique identifier for a context in this Isolate.
  // It is guaranteed to not be reused throughout the lifetime of the Isolate.
  class ContextId {
   public:
    ContextId() : id_(kEmptyId) {}

    bool IsEmpty() const { return id_ == kEmptyId; }
    static const ContextId Empty() { return ContextId{kEmptyId}; }

    bool operator==(const ContextId& other) const { return id_ == other.id_; }
    bool operator!=(const ContextId& other) const { return id_ != other.id_; }

   private:
    friend class ::v8::Context;
    friend class ::v8::internal::Isolate;

    explicit ContextId(uintptr_t id) : id_(id) {}

    static constexpr uintptr_t kEmptyId = 0;
    uintptr_t id_;
  };

  virtual ~Recorder() = default;

  // Main thread events. Those are only triggered on the main thread, and hence
  // can access the context.
#define ADD_MAIN_THREAD_EVENT(E) \
  virtual void AddMainThreadEvent(const E&, ContextId) {}
  ADD_MAIN_THREAD_EVENT(GarbageCollectionFullCycle)
  ADD_MAIN_THREAD_EVENT(GarbageCollectionFullMainThreadIncrementalMark)
  ADD_MAIN_THREAD_EVENT(GarbageCollectionFullMainThreadBatchedIncrementalMark)
  ADD_MAIN_THREAD_EVENT(GarbageCollectionFullMainThreadIncrementalSweep)
  ADD_MAIN_THREAD_EVENT(GarbageCollectionFullMainThreadBatchedIncrementalSweep)
  ADD_MAIN_THREAD_EVENT(GarbageCollectionYoungCycle)
  ADD_MAIN_THREAD_EVENT(WasmModuleDecoded)
  ADD_MAIN_THREAD_EVENT(WasmModuleCompiled)
  ADD_MAIN_THREAD_EVENT(WasmModuleInstantiated)
#undef ADD_MAIN_THREAD_EVENT

  // Thread-safe events are not allowed to access the context and therefore do
  // not carry a context ID with them. These IDs can be generated using
  // Recorder::GetContextId() and the ID will be valid throughout the lifetime
  // of the isolate. It is not guaranteed that the ID will still resolve to
  // a valid context using Recorder::GetContext() at the time the metric is
  // recorded. In this case, an empty handle will be returned.
#define ADD_THREAD_SAFE_EVENT(E) \
  virtual void AddThreadSafeEvent(const E&) {}
  ADD_THREAD_SAFE_EVENT(WasmModulesPerIsolate)
#undef ADD_THREAD_SAFE_EVENT

  virtual void NotifyIsolateDisposal() {}

  // Return the context with the given id or an empty handle if the context
  // was already garbage collected.
  static MaybeLocal<Context> GetContext(Isolate* isolate, ContextId id);
  // Return the unique id corresponding to the given context.
  static ContextId GetContextId(Local<Context> context);
};

/**
 * Experimental API intended for the LongTasks UKM (crbug.com/1173527).
 * The Reset() method should be called at the start of a potential
 * long task. The Get() method returns durations of V8 work that
 * happened during the task.
 *
 * This API is experimental and may be removed/changed in the future.
 */
struct V8_EXPORT LongTaskStats {
  /**
   * Resets durations of V8 work for the new task.
   */
  V8_INLINE static void Reset(Isolate* isolate) {
    v8::internal::Internals::IncrementLongTasksStatsCounter(isolate);
  }

  /**
   * Returns durations of V8 work that happened since the last Reset().
   */
  static LongTaskStats Get(Isolate* isolate);

  int64_t gc_full_atomic_wall_clock_duration_us = 0;
  int64_t gc_full_incremental_wall_clock_duration_us = 0;
  int64_t gc_young_wall_clock_duration_us = 0;
  // Only collected with --slow-histograms
  int64_t v8_execute_us = 0;
};

}  // namespace metrics
}  // namespace v8

#endif  // V8_METRICS_H_

"""

```