Response:
Let's break down the thought process for analyzing this Chromium source code.

**1. Initial Understanding of the Request:**

The request asks for a functional breakdown of `v8_detailed_memory_reporter_impl.cc`, focusing on its relationship with JavaScript, HTML, and CSS, logical inference, potential errors, and debugging context.

**2. High-Level Overview of the File:**

The `#include` directives and the namespace `blink` immediately suggest this file is part of the Blink rendering engine, specifically dealing with memory reporting related to V8 (the JavaScript engine). The name `V8DetailedMemoryReporterImpl` strongly implies its purpose is to provide detailed information about V8's memory usage. The "Impl" suffix often signifies this is the concrete implementation of an interface.

**3. Deconstructing the Code - Key Components and Their Functions:**

* **`FrameAssociatedMeasurementDelegate`:** This class inherits from `v8::MeasureMemoryDelegate`. This is a crucial hint. V8 has a mechanism to measure memory, and this delegate likely customizes that process for Blink's needs. The constructor takes a callback, indicating asynchronous operation. The `ShouldMeasure` method always returns `true`, meaning it will measure all V8 contexts. `MeasurementComplete` is the core logic – it processes the V8 measurement results. It iterates through contexts, identifying the associated `LocalFrame` (if any). It filters out non-main world contexts (e.g., extension contexts). It collects memory usage per context and accumulates detached context information.

* **`ToV8MeasureMemoryExecution`:** This is a simple helper function mapping Blink's `Mode` enum (DEFAULT, EAGER, LAZY) to V8's `MeasureMemoryExecution` enum. This suggests different levels of aggressiveness in memory measurement.

* **`ToExecutionContextToken`:** This function converts various worker tokens (Dedicated, Shared, Service) to a common `ExecutionContextToken`. This signifies the reporter needs to track memory usage across different JavaScript execution environments.

* **`V8ProcessMemoryReporter`:** This is a key class responsible for orchestrating the entire memory reporting process. It's `RefCounted`, suggesting it needs to stay alive until its asynchronous operations complete. It takes a callback to deliver the final results. `StartMeasurements` initiates the process:
    * It triggers a `v8::Isolate::MeasureMemory` call for the main V8 isolate, using the `FrameAssociatedMeasurementDelegate`.
    * It calls `V8WorkerMemoryReporter::GetMemoryUsage` to get memory information from worker isolates.
    * The `MainV8MeasurementComplete` method is called when the main isolate measurement is done. It then triggers Blink-specific memory collection (nodes and CSS) using `ThreadState::Current()->CollectNodeAndCssStatistics`.
    * `MainBlinkMeasurementComplete` combines the V8 and Blink memory data and then calls `MeasureCanvasMemory`.
    * `MeasureCanvasMemory` collects canvas-related memory usage, associating it with execution contexts.
    * `WorkerMeasurementComplete` processes the results from worker isolates.
    * `MaybeInvokeCallback` ensures the final callback is only invoked after both main and worker measurements are complete.

* **`GetV8DetailedMemoryReporter`:** This uses the "Meyers Singleton" pattern to provide a single instance of the reporter.

* **`Bind`:**  This is a typical Mojo binding function, indicating this reporter exposes its functionality through a Mojo interface (`mojom::blink::V8DetailedMemoryReporter`). The comment indicates it's called once per process.

* **`GetV8MemoryUsage`:** This is the main entry point for requesting memory usage information. It creates a `V8ProcessMemoryReporter` and starts the measurement process.

**4. Identifying Relationships with JavaScript, HTML, and CSS:**

* **JavaScript:**  The entire purpose revolves around V8 memory, the JavaScript engine. The tracking of V8 contexts, worker isolates, and the use of `v8::Isolate` are direct connections.
* **HTML:** The `FrameAssociatedMeasurementDelegate` uses `LocalFrame` and `LocalDOMWindow`, which are core HTML DOM concepts. The canvas memory measurement within `MeasureCanvasMemory` also ties into HTML's `<canvas>` element.
* **CSS:** The call to `ThreadState::Current()->CollectNodeAndCssStatistics` explicitly links the reporter to CSS memory usage.

**5. Logical Inference and Examples:**

The code infers the execution context of V8 contexts through the `LocalFrame`. It assumes a one-to-one relationship between a `LocalFrame` and a main-world V8 context within that frame.

* **Assumption/Input:** A webpage with a main frame and an iframe.
* **Output:** The reporter would output separate `PerContextV8MemoryUsage` entries, one for the main frame's context and one for the iframe's context, each with its respective memory usage.

**6. Identifying User/Programming Errors:**

The `DCHECK` statements are crucial for catching programming errors during development.

* **Error:** Accidentally calling `V8DetailedMemoryReporterImpl::Bind` more than once in a process.
* **Consequence:** The `DCHECK(!GetV8DetailedMemoryReporter().receiver_.is_bound())` would fail, indicating an incorrect initialization.

**7. Tracing User Actions to the Code:**

This requires understanding how memory reporting is triggered. It's likely initiated programmatically, either internally by Chromium components or through developer tools.

* **User Action:** Opening Chrome's Task Manager or using the Performance panel in DevTools.
* **Internal Trigger:**  These tools likely send a request through the Mojo interface (`mojom::blink::V8DetailedMemoryReporter`) to the renderer process.
* **Code Execution Flow:** This would eventually call `V8DetailedMemoryReporterImpl::GetV8MemoryUsage`, starting the measurement process described above.

**8. Iterative Refinement:**

Initially, one might only grasp the high-level purpose. By carefully examining each class and its methods, paying attention to the types and function names, and considering the overall flow, a more detailed understanding emerges. The comments in the code provide valuable clues. Looking for keywords like "MeasureMemory," "Context," "Isolate," and "Worker" helps pinpoint the core functionality.

This structured approach, combining code analysis with an understanding of the surrounding system (Chromium, Blink, V8), allows for a comprehensive explanation of the code's function and its relationships to web technologies.
This file, `v8_detailed_memory_reporter_impl.cc`, within the Chromium Blink rendering engine, is responsible for providing **detailed memory usage information about the V8 JavaScript engine** and related Blink components within a renderer process. It aims to break down memory usage by V8 contexts and associate it with the corresponding browsing context (like frames and workers).

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Detailed V8 Context Memory Measurement:** It uses V8's internal memory measurement APIs (`v8::Isolate::MeasureMemory`) to get memory usage for each V8 context within the main isolate of a renderer process.

2. **Association with Browsing Contexts:**  It maps the measured V8 context memory usage to the corresponding `LocalFrame` (for main frames and iframes) or worker (`DedicatedWorker`, `SharedWorker`, `ServiceWorker`). This allows for understanding which parts of a web page or which workers are consuming the most JavaScript memory.

3. **Handling Detached Contexts:** It tracks memory used by V8 contexts that are no longer associated with a live frame (detached contexts).

4. **Worker Isolate Memory Measurement:** It collaborates with `V8WorkerMemoryReporter` to collect memory usage information from separate V8 isolates running for Web Workers.

5. **Blink Specific Memory Measurement:**  It gathers memory usage related to Blink's internal structures, specifically:
    * **DOM Node and CSS Object Statistics:** It collects the memory footprint of DOM nodes and CSS objects.
    * **Canvas Memory:** It tracks memory used by `<canvas>` elements and their associated rendering contexts.

6. **Combining and Reporting:** It aggregates the V8 context memory, worker memory, and Blink-specific memory usage into a structured report (`mojom::blink::PerProcessV8MemoryUsage`). This report includes breakdowns by isolate and then by individual contexts within each isolate.

7. **Mojo Interface:** It exposes its functionality through a Mojo interface (`mojom::blink::V8DetailedMemoryReporter`), allowing other components within Chromium (like the browser process or DevTools) to request this detailed memory information.

**Relationship with JavaScript, HTML, and CSS:**

This file is **deeply intertwined** with JavaScript, HTML, and CSS:

* **JavaScript:** The primary focus is on V8, the JavaScript engine. It measures the memory used by JavaScript objects, closures, and other V8 internal structures. The association of memory with V8 contexts is directly related to JavaScript execution environments.

    * **Example:** If a JavaScript heavy application creates many objects or closures, this reporter will reflect that increased memory usage in the corresponding V8 context.

* **HTML:** The file uses `LocalFrame` and `LocalDOMWindow` to identify the HTML browsing context associated with a V8 context. This allows linking JavaScript memory usage to specific parts of the HTML document. The canvas memory measurement directly relates to the `<canvas>` HTML element.

    * **Example:**  If an iframe on a page runs a complex JavaScript application, the reporter will attribute the memory usage to the V8 context associated with that iframe's `LocalFrame`. Memory used by drawing operations on a `<canvas>` element will also be captured.

* **CSS:** The file explicitly calls `ThreadState::Current()->CollectNodeAndCssStatistics` to measure the memory used by CSS objects. This connects CSS rendering and styling to memory consumption.

    * **Example:**  A page with a large number of complex CSS selectors and styles will consume more memory for CSS objects, which will be reported by this mechanism.

**Logical Inference (Assumption, Input, Output):**

* **Assumption:** A V8 context is uniquely associated with a `LocalFrame` in the main world or a specific worker.
* **Input:** A renderer process with a main frame, an iframe, and a dedicated worker, each running JavaScript code that allocates memory.
* **Output:** The `V8ProcessMemoryReporter` would produce a `mojom::blink::PerProcessV8MemoryUsage` report containing:
    * One `PerIsolateV8MemoryUsage` entry for the main V8 isolate.
    * Within the main isolate's entry:
        * A `PerContextV8MemoryUsage` entry for the main frame's V8 context, with its `token` and `bytes_used`.
        * A `PerContextV8MemoryUsage` entry for the iframe's V8 context, with its `token` and `bytes_used`.
        * Potentially entries for detached contexts, if any exist.
        * The total `blink_bytes_used` (DOM nodes + CSS objects).
        * `PerContextCanvasMemoryUsage` entries for canvas elements in the main frame and iframe.
    * One `PerIsolateV8MemoryUsage` entry for the dedicated worker's V8 isolate.
    * Within the worker isolate's entry:
        * A `PerContextV8MemoryUsage` entry for the worker's context, with its `token`, `bytes_used`, and potentially the worker's URL.

**User or Programming Common Usage Errors:**

* **Incorrectly assuming the reporter is always accurate at a precise moment:** Memory allocation and garbage collection are asynchronous. The reported values represent a snapshot in time and might not perfectly reflect the exact memory usage at every instant.
* **Misinterpreting "detached contexts":** Developers might not understand that detached contexts can still hold onto memory. A common mistake is to assume that closing a tab or navigating away immediately frees all associated memory.
* **Over-reliance on this single metric:**  While detailed, this reporter doesn't capture all forms of memory usage in a renderer process (e.g., image decoding buffers, GPU memory). Developers should use it in conjunction with other memory profiling tools.
* **Forgetting to handle asynchronous nature:** The `GetV8MemoryUsage` function is asynchronous. Callbacks need to be properly handled to process the results. A common mistake is to try to access the results before the callback is invoked.

**User Operation Steps to Reach Here (Debugging Context):**

1. **User opens a web page in Chrome.** This triggers the creation of a renderer process for that page.
2. **The renderer process initializes the Blink engine, including the V8 JavaScript engine.**
3. **The web page executes JavaScript code.** This code allocates objects and data in the V8 heap.
4. **The user might interact with the page, causing more JavaScript execution and DOM manipulation.** This further affects memory usage.
5. **A developer (or an internal Chromium process) wants to understand the memory breakdown.** This could happen through:
    * **Opening Chrome's Task Manager:** The Task Manager periodically queries renderer processes for memory information. While the Task Manager shows aggregated data, the underlying mechanism likely involves calls to similar reporting functions.
    * **Using Chrome DevTools' Performance panel:**  When recording a performance profile or taking a heap snapshot, DevTools will internally trigger detailed memory measurements, which would involve this reporter.
    * **Internal Chromium memory monitoring:** Chromium has internal systems for tracking memory usage for diagnostic purposes and to trigger actions based on memory pressure. These systems might use this reporter.
6. **The request for detailed V8 memory usage is routed to the renderer process.** This involves inter-process communication (IPC), potentially via Mojo.
7. **The `V8DetailedMemoryReporterImpl::GetV8MemoryUsage` function is called.**
8. **The `V8ProcessMemoryReporter` is created and starts the measurement process.** This involves:
    * Asking the main V8 isolate to measure its memory using `FrameAssociatedMeasurementDelegate`.
    * Asking worker isolates (if any) to report their memory usage via `V8WorkerMemoryReporter`.
    * Collecting Blink-specific memory statistics (DOM nodes, CSS, canvas).
9. **The results are aggregated and returned via the callback.**

By examining the code, developers can understand how Chrome tracks JavaScript and related memory usage, which is crucial for identifying memory leaks, optimizing web page performance, and diagnosing memory-related issues. The file acts as a key component in providing insights into the inner workings of the Blink rendering engine and its resource management.

### 提示词
```
这是目录为blink/renderer/controller/performance_manager/v8_detailed_memory_reporter_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/controller/performance_manager/v8_detailed_memory_reporter_impl.h"

#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/controller/performance_manager/v8_worker_memory_reporter.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context_host.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_resource_tracker.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/ref_counted.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

class FrameAssociatedMeasurementDelegate : public v8::MeasureMemoryDelegate {
 public:
  using ResultCallback =
      base::OnceCallback<void(mojom::blink::PerIsolateV8MemoryUsagePtr)>;

  explicit FrameAssociatedMeasurementDelegate(ResultCallback&& callback)
      : callback_(std::move(callback)) {}

  ~FrameAssociatedMeasurementDelegate() override {
    if (callback_) {
      std::move(callback_).Run(mojom::blink::PerIsolateV8MemoryUsage::New());
    }
  }

 private:
  bool ShouldMeasure(v8::Local<v8::Context> context) override {
    // Measure all contexts.
    return true;
  }

  void MeasurementComplete(v8::MeasureMemoryDelegate::Result result) override {
    DCHECK(IsMainThread());
    mojom::blink::PerIsolateV8MemoryUsagePtr isolate_memory_usage =
        mojom::blink::PerIsolateV8MemoryUsage::New();
    DCHECK_EQ(result.contexts.size(), result.sizes_in_bytes.size());
    for (size_t i = 0; i < result.contexts.size(); ++i) {
      const v8::Local<v8::Context>& context = result.contexts[i];
      const size_t size = result.sizes_in_bytes[i];

      LocalFrame* frame = ToLocalFrameIfNotDetached(context);

      if (!frame) {
        // TODO(crbug.com/1080672): It would be prefereable to count the
        // V8SchemaRegistry context's overhead with unassociated_bytes, but at
        // present there isn't a public API that allows this distinction.
        ++(isolate_memory_usage->num_detached_contexts);
        isolate_memory_usage->detached_bytes_used += size;
        continue;
      }
      v8::Isolate* isolate = context->GetIsolate();
      if (DOMWrapperWorld::World(isolate, context).GetWorldId() !=
          DOMWrapperWorld::kMainWorldId) {
        // TODO(crbug.com/1085129): Handle extension contexts once they get
        // their own V8ContextToken.
        continue;
      }
      auto context_memory_usage = mojom::blink::PerContextV8MemoryUsage::New();
      context_memory_usage->token =
          frame->DomWindow()->GetExecutionContextToken();
      context_memory_usage->bytes_used = size;
#if DCHECK_IS_ON()
      // Check that the token didn't already occur.
      for (const auto& entry : isolate_memory_usage->contexts) {
        DCHECK_NE(entry->token, context_memory_usage->token);
      }
#endif
      isolate_memory_usage->contexts.push_back(std::move(context_memory_usage));
    }
    isolate_memory_usage->shared_bytes_used = result.unattributed_size_in_bytes;
    std::move(callback_).Run(std::move(isolate_memory_usage));
  }

 private:
  ResultCallback callback_;
};

v8::MeasureMemoryExecution ToV8MeasureMemoryExecution(
    V8DetailedMemoryReporterImpl::Mode mode) {
  switch (mode) {
    case V8DetailedMemoryReporterImpl::Mode::DEFAULT:
      return v8::MeasureMemoryExecution::kDefault;
    case V8DetailedMemoryReporterImpl::Mode::EAGER:
      return v8::MeasureMemoryExecution::kEager;
    case V8DetailedMemoryReporterImpl::Mode::LAZY:
      return v8::MeasureMemoryExecution::kLazy;
  }
  NOTREACHED();
}

ExecutionContextToken ToExecutionContextToken(WorkerToken token) {
  if (token.Is<DedicatedWorkerToken>())
    return ExecutionContextToken(token.GetAs<DedicatedWorkerToken>());
  if (token.Is<SharedWorkerToken>())
    return ExecutionContextToken(token.GetAs<SharedWorkerToken>());
  return ExecutionContextToken(token.GetAs<ServiceWorkerToken>());
}

// A helper class that runs two async functions, combines their
// results, and invokes the given callback. The async functions are:
// - v8::Isolate::MeasureMemory - for the main V8 isolate.
// - V8WorkerMemoryReporter::GetMemoryUsage - for all worker isolates.
class V8ProcessMemoryReporter : public RefCounted<V8ProcessMemoryReporter> {
 public:
  using GetV8MemoryUsageCallback =
      mojom::blink::V8DetailedMemoryReporter::GetV8MemoryUsageCallback;

  explicit V8ProcessMemoryReporter(GetV8MemoryUsageCallback&& callback)
      : callback_(std::move(callback)),
        result_(mojom::blink::PerProcessV8MemoryUsage::New()) {}

  void StartMeasurements(V8DetailedMemoryReporterImpl::Mode mode) {
    DCHECK(IsMainThread());
    DCHECK(!isolate_);
    isolate_ = v8::Isolate::GetCurrent();
    // 1. Start measurement of the main V8 isolate.
    if (!isolate_) {
      // This can happen in tests that do not set up the main V8 isolate
      // or during setup/teardown of the process.
      MainMeasurementComplete(mojom::blink::PerIsolateV8MemoryUsage::New());
    } else {
      auto delegate = std::make_unique<FrameAssociatedMeasurementDelegate>(
          WTF::BindOnce(&V8ProcessMemoryReporter::MainV8MeasurementComplete,
                        scoped_refptr<V8ProcessMemoryReporter>(this)));

      isolate_->MeasureMemory(std::move(delegate),
                              ToV8MeasureMemoryExecution(mode));
    }
    // 2. Start measurement of all worker isolates.
    V8WorkerMemoryReporter::GetMemoryUsage(
        WTF::BindOnce(&V8ProcessMemoryReporter::WorkerMeasurementComplete,
                      scoped_refptr<V8ProcessMemoryReporter>(this)),
        ToV8MeasureMemoryExecution(mode));
  }

 private:
  void MainV8MeasurementComplete(
      mojom::blink::PerIsolateV8MemoryUsagePtr isolate_memory_usage) {
    // At this point measurement of the main V8 isolate is done and we
    // can measure the corresponding Blink memory. Note that the order
    // of the measurements is important because the V8 measurement does
    // a GC and we want to get the Blink memory after the GC.
    // This function and V8ProcessMemoryReporter::StartMeasurements both
    // run on the main thread of the renderer. This means that the Blink
    // heap given by ThreadState::Current() is attached to the main V8
    // isolate given by v8::Isolate::GetCurrent().
    ThreadState::Current()->CollectNodeAndCssStatistics(
        WTF::BindOnce(&V8ProcessMemoryReporter::MainBlinkMeasurementComplete,
                      scoped_refptr<V8ProcessMemoryReporter>(this),
                      std::move(isolate_memory_usage)));
  }

  void MainBlinkMeasurementComplete(
      mojom::blink::PerIsolateV8MemoryUsagePtr isolate_memory_usage,
      size_t node_bytes,
      size_t css_bytes) {
    isolate_memory_usage->blink_bytes_used = node_bytes + css_bytes;
    MeasureCanvasMemory(std::move(isolate_memory_usage));
  }

  void MeasureCanvasMemory(
      mojom::blink::PerIsolateV8MemoryUsagePtr isolate_memory_usage) {
    // We do not use HashMap here because there is no designated deleted value
    // of ExecutionContextToken.
    std::unordered_map<ExecutionContextToken, uint64_t,
                       ExecutionContextToken::Hasher>
        per_context_bytes;
    // Group and accumulate canvas bytes by execution context token.
    for (auto entry : CanvasResourceTracker::For(isolate_)->GetResourceMap()) {
      ExecutionContextToken token = entry.value->GetExecutionContextToken();
      uint64_t bytes_used = entry.key->GetMemoryUsage();
      if (!bytes_used) {
        // Ignore canvas elements that do not have buffers.
        continue;
      }
      auto it = per_context_bytes.find(token);
      if (it == per_context_bytes.end()) {
        per_context_bytes[token] = bytes_used;
      } else {
        it->second += bytes_used;
      }
    }
    for (auto entry : per_context_bytes) {
      auto memory_usage = mojom::blink::PerContextCanvasMemoryUsage::New();
      memory_usage->token = entry.first;
      memory_usage->bytes_used = entry.second;
      isolate_memory_usage->canvas_contexts.push_back(std::move(memory_usage));
    }

    MainMeasurementComplete(std::move(isolate_memory_usage));
  }

  void MainMeasurementComplete(
      mojom::blink::PerIsolateV8MemoryUsagePtr isolate_memory_usage) {
    result_->isolates.push_back(std::move(isolate_memory_usage));
    main_measurement_done_ = true;
    MaybeInvokeCallback();
  }

  void WorkerMeasurementComplete(const V8WorkerMemoryReporter::Result& result) {
    for (auto& worker : result.workers) {
      auto worker_memory_usage = mojom::blink::PerIsolateV8MemoryUsage::New();
      auto context_memory_usage = mojom::blink::PerContextV8MemoryUsage::New();
      context_memory_usage->token = ToExecutionContextToken(worker.token);
      context_memory_usage->bytes_used = worker.bytes;
      if (!worker.url.IsNull()) {
        context_memory_usage->url = worker.url.GetString();
      }
      worker_memory_usage->contexts.push_back(std::move(context_memory_usage));
      result_->isolates.push_back(std::move(worker_memory_usage));
    }
    worker_measurement_done_ = true;
    MaybeInvokeCallback();
  }

  void MaybeInvokeCallback() {
    if (!main_measurement_done_ || !worker_measurement_done_)
      return;

    std::move(callback_).Run(std::move(result_));
  }
  raw_ptr<v8::Isolate> isolate_ = nullptr;
  GetV8MemoryUsageCallback callback_;
  mojom::blink::PerProcessV8MemoryUsagePtr result_;
  bool main_measurement_done_ = false;
  bool worker_measurement_done_ = false;
};

V8DetailedMemoryReporterImpl& GetV8DetailedMemoryReporter() {
  DEFINE_STATIC_LOCAL(V8DetailedMemoryReporterImpl, v8_memory_reporter, ());
  return v8_memory_reporter;
}

}  // namespace

// static
void V8DetailedMemoryReporterImpl::Bind(
    mojo::PendingReceiver<mojom::blink::V8DetailedMemoryReporter> receiver) {
  // This should be called only once per process on RenderProcessWillLaunch.
  DCHECK(!GetV8DetailedMemoryReporter().receiver_.is_bound());
  GetV8DetailedMemoryReporter().receiver_.Bind(std::move(receiver));
}

void V8DetailedMemoryReporterImpl::GetV8MemoryUsage(
    V8DetailedMemoryReporterImpl::Mode mode,
    GetV8MemoryUsageCallback callback) {
  auto v8_process_memory_reporter =
      base::MakeRefCounted<V8ProcessMemoryReporter>(std::move(callback));
  // Start async measurements. The lifetime of the reporter is extended
  // using more shared pointers until the measuremnts complete.
  v8_process_memory_reporter->StartMeasurements(mode);
}

}  // namespace blink
```