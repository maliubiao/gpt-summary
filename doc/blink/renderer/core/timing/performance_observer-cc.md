Response:
Let's break down the thought process for analyzing the `performance_observer.cc` file.

**1. Understanding the Goal:**

The core request is to understand the functionality of this C++ file within the Chromium Blink rendering engine. Specifically, how it relates to JavaScript, HTML, CSS, common usage errors, and debugging.

**2. Initial Scan and Keyword Identification:**

First, I'd quickly scan the code looking for keywords and familiar terms. This helps to get a general sense of the file's purpose:

* **`PerformanceObserver`**: This is the central class, so it's clearly about observing performance events.
* **`PerformanceEntry`**:  These are the things being observed (marks, measures, resources, etc.).
* **`callback`**:  Indicates that this code interacts with JavaScript through callbacks.
* **`observe()`**, **`disconnect()`**, **`takeRecords()`**:  These are likely the main methods used from JavaScript.
* **`buffered`**: Suggests the ability to retrieve historical performance data.
* **`entryTypes`**, **`type`**:  Options for filtering which performance entries to observe.
* **`ScriptState`**, **`ExecutionContext`**:  Indicates interaction with the JavaScript environment.
* **`DOMWindowPerformance`**, **`WorkerGlobalScopePerformance`**:  Shows it works in both window and worker contexts.
* **`UseCounter`**:  Implies tracking of feature usage.
* **`ConsoleMessage`**:  Suggests logging or warnings to the developer console.

**3. Deeper Dive into Key Sections:**

Now, I'd go back and examine the code more closely, focusing on the main functions and their logic:

* **`PerformanceObserver::Create()`**:  Determines if the observer is being created in a window or worker context. Crucially, it validates the context. This immediately links it to the JavaScript `PerformanceObserver` constructor.
* **`PerformanceObserver::supportedEntryTypeMask()` and `supportedEntryTypes()`**: These static methods reveal the kinds of performance entries that can be observed. The conditional inclusion based on `RuntimeEnabledFeatures` hints at feature flags and potential variations in supported types. This directly connects to the `supportedEntryTypes` static method in the JavaScript `PerformanceObserver`.
* **`PerformanceObserver::observe()`**: This is the most complex part. I'd break down its logic step-by-step:
    * Checks if `performance_` is valid (related to object destruction).
    * Handles the `entryTypes` vs. `type` options, including error handling for using both. This clarifies how JavaScript developers configure the observer.
    * Shows how the `buffered` option works.
    * Explains the `durationThreshold` for event entries.
    * Uses `UseCounter` for different observation types, indicating feature tracking.
    * Registers the observer with the `Performance` object.
* **`PerformanceObserver::disconnect()`**:  Simple cleanup.
* **`PerformanceObserver::takeRecords()`**: Retrieves buffered entries.
* **`PerformanceObserver::EnqueuePerformanceEntry()`**: Shows how new performance entries are added to the observer's internal queue.
* **`PerformanceObserver::CanObserve()`**:  A filtering mechanism, particularly important for event entries with a duration threshold.
* **`PerformanceObserver::Deliver()`**:  This is where the callback to JavaScript happens. It creates a `PerformanceObserverEntryList` and invokes the registered callback function. The `dropped_entries_count` is also important here.
* **`PerformanceObserver::ContextLifecycleStateChanged()`**: Handles the observer's behavior when the frame's lifecycle changes (running vs. suspended).

**4. Connecting to JavaScript, HTML, and CSS:**

With a good understanding of the C++ code, I can now make the connections to the web technologies:

* **JavaScript:** The `PerformanceObserver` class directly mirrors the JavaScript `PerformanceObserver` API. The methods like `observe`, `disconnect`, and `takeRecords` are directly analogous. The callback mechanism is the primary interaction point. The `supportedEntryTypes` function maps to the static method in JavaScript.
* **HTML:** The performance entries often relate to HTML elements and the page lifecycle. For example, `largest-contentful-paint` refers to a specific element on the page. Navigation timings are triggered by page loads initiated in the HTML.
* **CSS:**  Layout shifts, paint timings, and even resource timings are influenced by CSS. Changes in CSS can directly lead to these performance events.

**5. Inferring Logical Relationships and Examples:**

Based on the code's logic, I can create hypothetical scenarios:

* **Input/Output:**  Demonstrate how calling `observe` with different options affects the entries delivered in the callback.
* **User Errors:** Identify common mistakes developers might make, such as using both `entryTypes` and `type` or not checking supported types.

**6. Tracing User Actions:**

This requires thinking about the typical workflow of a web developer:

1. Open DevTools.
2. Go to the Performance tab.
3. Start recording. *This triggers the browser to start collecting performance data.*
4. Interact with the webpage (load, scroll, click, etc.). *These actions generate performance entries.*
5. Stop recording. *The collected data is processed and displayed.*
6. *Alternatively, a developer might use the `PerformanceObserver` API in their JavaScript code directly.*

By understanding the different paths (DevTools vs. direct API usage), I can explain how a user action leads to the execution of the `PerformanceObserver` code.

**7. Refinement and Organization:**

Finally, I organize the information into the requested categories (functionality, relationships to web technologies, logical reasoning, user errors, debugging) and use clear, concise language with examples. I pay attention to the specific phrasing requested in the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps focus heavily on the individual `PerformanceEntry` types.
* **Correction:** Realized the core functionality is managing the observer and delivering entries. The specific entry types are important, but secondary to the observer's overall role.
* **Initial thought:** Focus only on direct JavaScript API usage.
* **Correction:**  Recognized the importance of the DevTools Performance tab as a common entry point for triggering this functionality.
* **Initial thought:**  Simply list the included headers.
* **Correction:** Understood that the headers provide context about dependencies (V8 bindings, execution context, etc.) and should be explained in relation to the functionality.

By following these steps and iteratively refining my understanding, I can arrive at a comprehensive and accurate explanation of the `performance_observer.cc` file.
好的，让我们来详细分析一下 `blink/renderer/core/timing/performance_observer.cc` 这个 Chromium Blink 引擎源代码文件的功能。

**文件功能概述**

`performance_observer.cc` 文件实现了 Web 性能监控 API 中的 `PerformanceObserver` 接口。这个接口允许 JavaScript 代码注册一个观察者，以便在浏览器记录新的性能条目（PerformanceEntry）时接收通知。这些性能条目涵盖了各种与网页性能相关的事件，例如：

* 页面加载和导航 (Navigation Timing)
* 资源加载 (Resource Timing)
* 用户自定义标记和测量 (Mark and Measure)
* 长任务 (Long Task)
* 渲染相关的事件 (Paint Timing, Layout Shift, Largest Contentful Paint)
* 用户输入延迟 (First Input Delay)
* 元素级别的性能信息 (Element Timing)
* 可见性状态变化 (Visibility State)
* 软导航 (Soft Navigation)
* 往返缓存恢复 (Back/Forward Cache Restoration)
* 长动画帧 (Long Animation Frame)
* 事件 (Event)

**与 JavaScript, HTML, CSS 的关系及举例说明**

`PerformanceObserver` 是一个直接暴露给 JavaScript 的 API，因此它与 JavaScript 有着最直接的关系。它允许 JavaScript 代码主动地监控和分析网页的性能。它间接地与 HTML 和 CSS 相关，因为 HTML 结构、CSS 样式以及 JavaScript 代码的行为会直接影响各种性能指标的生成。

**JavaScript:**

* **注册观察者:** JavaScript 代码可以使用 `new PerformanceObserver(callback)` 创建一个 `PerformanceObserver` 实例，并将一个回调函数 (`callback`) 传递给它。每当有新的符合条件的性能条目生成时，这个回调函数会被调用。

  ```javascript
  const observer = new PerformanceObserver((list, observer) => {
    list.getEntries().forEach(entry => {
      console.log(entry.entryType, entry.name, entry.startTime, entry.duration);
    });
  });
  ```

* **指定观察的条目类型:**  使用 `observer.observe({ entryTypes: ['navigation', 'resource'] })`  或 `observer.observe({ type: 'paint' })` 来指定希望观察的性能条目类型。

  ```javascript
  // 观察 navigation 和 resource 类型的性能条目
  observer.observe({ entryTypes: ['navigation', 'resource'] });

  // 观察 paint 类型的性能条目
  observer.observe({ type: 'paint' });
  ```

* **`buffered` 选项:**  使用 `observer.observe({ type: 'navigation', buffered: true })` 可以获取在观察者注册之前已经发生的，符合条件的性能条目。

  ```javascript
  // 获取之前发生的 navigation 类型的性能条目
  observer.observe({ type: 'navigation', buffered: true });
  ```

* **`durationThreshold` 选项:**  对于 `event` 类型的条目，可以使用 `durationThreshold` 来过滤持续时间超过指定阈值的事件。

  ```javascript
  // 观察持续时间超过 100 毫秒的 'click' 事件
  observer.observe({ type: 'event', durationThreshold: 100 });
  ```

* **断开观察:**  使用 `observer.disconnect()` 停止观察。

  ```javascript
  observer.disconnect();
  ```

* **手动获取记录:**  使用 `observer.takeRecords()` 可以获取当前缓冲区中的所有性能条目，并清空缓冲区。

  ```javascript
  const currentEntries = observer.takeRecords();
  ```

**HTML:**

HTML 结构直接影响性能条目的生成。例如：

* **Navigation Timing:**  HTML 的加载过程（例如 DNS 查询、TCP 连接、请求响应、DOM 解析等）会生成 `navigation` 类型的性能条目。
* **Resource Timing:**  HTML 中引用的外部资源（例如 `<img>`, `<link>`, `<script>`）的加载会生成 `resource` 类型的性能条目。

**CSS:**

CSS 样式也会影响性能条目的生成。例如：

* **Paint Timing:**  首次内容绘制（First Contentful Paint, FCP）和首次有意义绘制（Largest Contentful Paint, LCP）等 `paint` 类型的性能条目会受到 CSS 阻塞渲染的影响。
* **Layout Shift:**  CSS 的改变可能导致页面布局发生意外移动，生成 `layout-shift` 类型的性能条目。

**逻辑推理 (假设输入与输出)**

假设 JavaScript 代码如下：

```javascript
const observer = new PerformanceObserver((list, observer) => {
  list.getEntries().forEach(entry => {
    console.log(entry.entryType, entry.name, entry.startTime.toFixed(2));
  });
});
observer.observe({ entryTypes: ['mark', 'measure'] });

performance.mark('start-process');
// ... 执行一些操作 ...
performance.measure('process-time', 'start-process');
```

**假设输入:**

* 用户访问一个网页，该网页执行上述 JavaScript 代码。
* 在 `performance.mark('start-process')` 和 `performance.measure('process-time', 'start-process')` 之间执行了一些耗时操作。

**预期输出 (在控制台中):**

```
mark start-process 1234.56  // startTime 可能不同
measure process-time 1234.56 // startTime 可能不同，但与 mark 的 startTime 相同
```

**解释:**

1. `PerformanceObserver` 被创建并配置为观察 `mark` 和 `measure` 类型的性能条目。
2. `performance.mark('start-process')` 创建了一个名为 "start-process" 的 `mark` 条目。
3. `performance.measure('process-time', 'start-process')` 创建了一个名为 "process-time" 的 `measure` 条目，其起始时间与 "start-process" 标记的时间相同。
4. 当 `measure` 条目创建时，`PerformanceObserver` 的回调函数被调用，并将这两个条目添加到列表中。
5. 回调函数遍历列表，并打印出条目的 `entryType`、`name` 和 `startTime`。

**用户或编程常见的使用错误及举例说明**

1. **尝试观察不支持的条目类型:**

   ```javascript
   const observer = new PerformanceObserver(() => {});
   observer.observe({ type: 'non-existent-type' }); // 错误：尝试观察不存在的类型
   ```
   **结果:**  在控制台中会输出警告信息，告知该条目类型不存在或不支持。

2. **同时使用 `entryTypes` 和 `type` 选项:**

   ```javascript
   const observer = new PerformanceObserver(() => {});
   observer.observe({ entryTypes: ['mark'], type: 'measure' }); // 错误：不能同时使用
   ```
   **结果:**  会抛出 `TypeError` 异常，提示 `observe()` 调用不能同时包含 `entryTypes` 和 `type` 参数。

3. **在错误的上下文中使用 `PerformanceObserver`:**

   ```javascript
   // 在不支持 Performance API 的环境中
   const observer = new PerformanceObserver(() => {}); // 可能抛出 ReferenceError
   ```
   **结果:**  如果当前环境（例如某些 Web Worker 的特定上下文）不支持 `PerformanceObserver` API，则尝试创建 `PerformanceObserver` 可能会导致 `ReferenceError`。

4. **忘记断开观察:**

   ```javascript
   const observer = new PerformanceObserver(() => { /* 处理性能条目 */ });
   observer.observe({ type: 'navigation' });
   // ... 页面卸载或不再需要观察时忘记调用 observer.disconnect()
   ```
   **结果:**  即使不再需要观察，观察者仍然会监听性能事件，可能造成不必要的资源消耗。

**用户操作是如何一步步的到达这里，作为调试线索**

假设开发者想要调试页面加载缓慢的问题，并使用了 `PerformanceObserver` API 来收集导航相关的性能数据。以下是用户操作如何逐步到达 `performance_observer.cc` 的过程：

1. **开发者编写 JavaScript 代码:** 开发者编写如下 JavaScript 代码嵌入到 HTML 页面中，或者在浏览器的开发者工具控制台中执行：

   ```javascript
   const observer = new PerformanceObserver((list) => {
     list.getEntriesByType('navigation').forEach(entry => {
       console.log('Navigation Timing:', entry.name, entry.startTime, entry.duration);
     });
   });
   observer.observe({ type: 'navigation', buffered: true });
   ```

2. **用户访问网页:** 用户在浏览器中输入网址或点击链接访问包含上述 JavaScript 代码的网页。

3. **Blink 引擎解析和执行 JavaScript:** 当浏览器加载网页时，Blink 引擎的 JavaScript 引擎（V8）会解析并执行这段 JavaScript 代码。

4. **创建 PerformanceObserver 对象:**  执行 `new PerformanceObserver(...)` 时，会调用到 `performance_observer.cc` 中的 `PerformanceObserver::Create` 方法。这个方法会根据当前的执行上下文（Window 或 Worker）创建 `PerformanceObserver` 对象。

5. **调用 `observe` 方法:**  执行 `observer.observe(...)` 时，会调用到 `performance_observer.cc` 中的 `PerformanceObserver::observe` 方法。

   * 这个方法会解析 `observe` 方法的参数（例如 `entryTypes` 或 `type`，以及 `buffered` 等选项）。
   * 它会检查请求的条目类型是否被支持。
   * 它会将这个 `PerformanceObserver` 对象注册到 `Performance` 对象中，以便在有新的性能条目生成时得到通知。

6. **性能条目生成:** 当浏览器执行各种操作（例如发起网络请求、解析 HTML、渲染页面等）时，会生成不同类型的 `PerformanceEntry` 对象（例如 `NavigationTiming` 条目）。

7. **通知 PerformanceObserver:**  当生成新的 `PerformanceEntry` 且其类型与已注册的观察者匹配时，`Performance` 对象会通知相应的 `PerformanceObserver` 对象。这通常会调用到 `PerformanceObserver::EnqueuePerformanceEntry` 方法，将新的条目添加到观察者的内部队列中。

8. **触发回调函数:**  在合适的时机（例如，如果 `buffered: true`，则在注册时立即触发；否则，在新的条目添加到队列后），Blink 引擎会调用 `PerformanceObserver` 的回调函数。这会调用到 `performance_observer.cc` 中的 `PerformanceObserver::Deliver` 方法。

   * `Deliver` 方法会将队列中的 `PerformanceEntry` 对象封装成 `PerformanceObserverEntryList`。
   * 它会通过 V8 的绑定机制，将这个列表传递给 JavaScript 中定义的回调函数。

9. **JavaScript 处理性能条目:**  JavaScript 回调函数接收到性能条目列表，并执行相应的处理逻辑（例如打印到控制台、发送到服务器等）。

**调试线索:**

当开发者遇到性能问题并使用 `PerformanceObserver` 进行调试时，如果发现某些性能条目没有被捕获到，或者回调函数没有按预期执行，可以从以下几个方面进行排查：

* **确认观察的条目类型是否正确:**  检查 `observe` 方法中指定的 `entryTypes` 或 `type` 是否包含了期望的性能条目类型。
* **检查 `buffered` 选项:**  如果需要获取在观察者注册之前发生的条目，确保使用了 `buffered: true`。
* **查看控制台警告信息:**  检查浏览器控制台是否有关于不支持的条目类型的警告信息。
* **断点调试 C++ 代码:**  如果怀疑是 Blink 引擎内部的问题，可以使用调试器（例如 gdb）附加到 Chrome 进程，并在 `performance_observer.cc` 中的关键方法（例如 `Create`, `observe`, `EnqueuePerformanceEntry`, `Deliver`) 设置断点，逐步跟踪代码执行流程，查看性能条目的生成和传递过程。
* **检查浏览器版本和特性支持:**  确保使用的浏览器版本支持 `PerformanceObserver` API 以及所需的性能条目类型。某些较新的性能条目类型可能需要在较新的浏览器版本中才能使用。

总而言之，`performance_observer.cc` 是 Blink 引擎中实现 Web 性能监控 API 核心功能的关键文件，它连接了 JavaScript API 和底层的性能事件收集机制，使得开发者能够以编程方式监控和分析网页的性能表现。

### 提示词
```
这是目录为blink/renderer/core/timing/performance_observer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/performance_observer.h"

#include <algorithm>

#include "third_party/blink/public/mojom/frame/lifecycle.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_performance_observer_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_performance_observer_callback_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_performance_observer_init.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance_entry.h"
#include "third_party/blink/renderer/core/timing/performance_observer_entry_list.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/core/timing/worker_global_scope_performance.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/timer.h"

namespace blink {

PerformanceObserver* PerformanceObserver::Create(
    ScriptState* script_state,
    V8PerformanceObserverCallback* callback) {
  LocalDOMWindow* window = ToLocalDOMWindow(script_state->GetContext());
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (window) {
    UseCounter::Count(context, WebFeature::kPerformanceObserverForWindow);
    return MakeGarbageCollected<PerformanceObserver>(
        context, DOMWindowPerformance::performance(*window), callback);
  }
  if (auto* scope = DynamicTo<WorkerGlobalScope>(context)) {
    UseCounter::Count(context, WebFeature::kPerformanceObserverForWorker);
    return MakeGarbageCollected<PerformanceObserver>(
        context, WorkerGlobalScopePerformance::performance(*scope), callback);
  }
  V8ThrowException::ThrowTypeError(
      script_state->GetIsolate(),
      ExceptionMessages::FailedToConstruct(
          "PerformanceObserver",
          "No 'worker' or 'window' in current context."));
  return nullptr;
}

// static
PerformanceEntryType PerformanceObserver::supportedEntryTypeMask(
    ScriptState* script_state) {
  constexpr PerformanceEntryType types_always_supported =
      PerformanceEntry::kMark | PerformanceEntry::kMeasure |
      PerformanceEntry::kResource;
  constexpr PerformanceEntryType types_supported_on_window =
      types_always_supported | PerformanceEntry::kNavigation |
      PerformanceEntry::kLongTask | PerformanceEntry::kPaint |
      PerformanceEntry::kEvent | PerformanceEntry::kFirstInput |
      PerformanceEntry::kElement | PerformanceEntry::kLayoutShift |
      PerformanceEntry::kLargestContentfulPaint |
      PerformanceEntry::kVisibilityState;

  auto* execution_context = ExecutionContext::From(script_state);

  if (!execution_context->IsWindow()) {
    return types_always_supported;
  }

  PerformanceEntryType mask = types_supported_on_window;
  if (RuntimeEnabledFeatures::NavigationIdEnabled(execution_context)) {
    mask |= PerformanceEntry::kBackForwardCacheRestoration;
  }
  if (RuntimeEnabledFeatures::SoftNavigationHeuristicsEnabled(
          execution_context)) {
    mask |= PerformanceEntry::kSoftNavigation;
  }
  if (RuntimeEnabledFeatures::LongAnimationFrameTimingEnabled(
          execution_context)) {
    mask |= PerformanceEntry::kLongAnimationFrame;
  }
  return mask;
}

// static
Vector<AtomicString> PerformanceObserver::supportedEntryTypes(
    ScriptState* script_state) {
  // Get the list of currently supported types. This may change at runtime due
  // to the dynamic addition of origin trial tokens.
  PerformanceEntryType mask = supportedEntryTypeMask(script_state);

  // The list of supported types to return, in alphabetical order.
  Vector<AtomicString> supportedEntryTypes;

  if (mask & PerformanceEntry::kBackForwardCacheRestoration) {
    supportedEntryTypes.push_back(
        performance_entry_names::kBackForwardCacheRestoration);
  }
  if (mask & PerformanceEntry::kElement) {
    supportedEntryTypes.push_back(performance_entry_names::kElement);
  }
  if (mask & PerformanceEntry::kEvent) {
    supportedEntryTypes.push_back(performance_entry_names::kEvent);
  }
  if (mask & PerformanceEntry::kFirstInput) {
    supportedEntryTypes.push_back(performance_entry_names::kFirstInput);
  }
  if (mask & PerformanceEntry::kLargestContentfulPaint) {
    supportedEntryTypes.push_back(
        performance_entry_names::kLargestContentfulPaint);
  }
  if (mask & PerformanceEntry::kLayoutShift) {
    supportedEntryTypes.push_back(performance_entry_names::kLayoutShift);
  }
  if (mask & PerformanceEntry::kLongAnimationFrame) {
    supportedEntryTypes.push_back(performance_entry_names::kLongAnimationFrame);
  }
  if (mask & PerformanceEntry::kLongTask) {
    supportedEntryTypes.push_back(performance_entry_names::kLongtask);
  }
  if (mask & PerformanceEntry::kMark) {
    supportedEntryTypes.push_back(performance_entry_names::kMark);
  }
  if (mask & PerformanceEntry::kMeasure) {
    supportedEntryTypes.push_back(performance_entry_names::kMeasure);
  }
  if (mask & PerformanceEntry::kNavigation) {
    supportedEntryTypes.push_back(performance_entry_names::kNavigation);
  }
  if (mask & PerformanceEntry::kPaint) {
    supportedEntryTypes.push_back(performance_entry_names::kPaint);
  }
  if (mask & PerformanceEntry::kResource) {
    supportedEntryTypes.push_back(performance_entry_names::kResource);
  }
  if (mask & PerformanceEntry::kSoftNavigation) {
    supportedEntryTypes.push_back(performance_entry_names::kSoftNavigation);
  }
  if (mask & PerformanceEntry::kVisibilityState) {
    supportedEntryTypes.push_back(performance_entry_names::kVisibilityState);
  }
  return supportedEntryTypes;
}

PerformanceObserver::PerformanceObserver(
    ExecutionContext* execution_context,
    Performance* performance,
    V8PerformanceObserverCallback* callback)
    : ActiveScriptWrappable<PerformanceObserver>({}),
      ExecutionContextLifecycleStateObserver(execution_context),
      callback_(callback),
      performance_(performance),
      filter_options_(PerformanceEntry::kInvalid),
      type_(PerformanceObserverType::kUnknown),
      is_registered_(false) {
  DCHECK(performance_);
  UpdateStateIfNeeded();
}

void PerformanceObserver::observe(ScriptState* script_state,
                                  const PerformanceObserverInit* observer_init,
                                  ExceptionState& exception_state) {
  if (!performance_) {
    exception_state.ThrowTypeError(
        "Window/worker may be destroyed? Performance target is invalid.");
    return;
  }

  // Get the list of currently supported types. This may change at runtime due
  // to the dynamic addition of origin trial tokens.
  PerformanceEntryType supported_types = supportedEntryTypeMask(script_state);
  bool is_buffered = false;
  if (observer_init->hasEntryTypes()) {
    if (observer_init->hasType()) {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kPerformanceObserverTypeError);
      exception_state.ThrowTypeError(
          "An observe() call must not include "
          "both entryTypes and type arguments.");
      return;
    }
    if (type_ == PerformanceObserverType::kTypeObserver) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidModificationError,
          "This PerformanceObserver has performed observe({type:...}, "
          "therefore it cannot "
          "perform observe({entryTypes:...})");
      return;
    }
    type_ = PerformanceObserverType::kEntryTypesObserver;
    PerformanceEntryTypeMask entry_types = PerformanceEntry::kInvalid;
    const Vector<String>& sequence = observer_init->entryTypes();
    for (const auto& entry_type_string : sequence) {
      PerformanceEntry::EntryType entry_type =
          PerformanceEntry::ToEntryTypeEnum(AtomicString(entry_type_string));
      if (!(supported_types & entry_type)) {
        String message = "The entry type '" + entry_type_string +
                         "' does not exist or isn't supported.";
        if (GetExecutionContext()) {
          GetExecutionContext()->AddConsoleMessage(
              MakeGarbageCollected<ConsoleMessage>(
                  mojom::ConsoleMessageSource::kJavaScript,
                  mojom::ConsoleMessageLevel::kWarning, message));
        }
      } else {
        entry_types |= entry_type;
      }
    }
    if (entry_types == PerformanceEntry::kInvalid) {
      // No valid entry types were given.
      return;
    }
    if (observer_init->buffered() || observer_init->hasDurationThreshold()) {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kPerformanceObserverEntryTypesAndBuffered);
      String message =
          "The PerformanceObserver does not support buffered flag with "
          "the entryTypes argument.";
      if (GetExecutionContext()) {
        GetExecutionContext()->AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::ConsoleMessageSource::kJavaScript,
                mojom::ConsoleMessageLevel::kWarning, message));
      }
    }
    filter_options_ = entry_types;
  } else {
    if (!observer_init->hasType()) {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kPerformanceObserverTypeError);
      exception_state.ThrowTypeError(
          "An observe() call must include either "
          "entryTypes or type arguments.");
      return;
    }
    if (type_ == PerformanceObserverType::kEntryTypesObserver) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidModificationError,
          "This observer has performed observe({entryTypes:...}, therefore it "
          "cannot perform observe({type:...})");
      return;
    }
    type_ = PerformanceObserverType::kTypeObserver;
    AtomicString entry_type_atomic_string(observer_init->type());
    PerformanceEntryType entry_type =
        PerformanceEntry::ToEntryTypeEnum(entry_type_atomic_string);
    if (!(supported_types & entry_type)) {
      String message = "The entry type '" + observer_init->type() +
                       "' does not exist or isn't supported.";
      if (GetExecutionContext()) {
        GetExecutionContext()->AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::ConsoleMessageSource::kJavaScript,
                mojom::ConsoleMessageLevel::kWarning, message));
      }
      return;
    }
    include_soft_navigation_observations_ =
        observer_init->includeSoftNavigationObservations();
    if (observer_init->buffered()) {
      // Append all entries of this type to the current performance_entries_
      // to be returned on the next callback.
      performance_entries_.AppendVector(performance_->getBufferedEntriesByType(
          AtomicString(observer_init->type()),
          include_soft_navigation_observations_));
      std::sort(performance_entries_.begin(), performance_entries_.end(),
                PerformanceEntry::StartTimeCompareLessThan);
      is_buffered = true;
    }
    if (entry_type == PerformanceEntry::kEvent &&
        observer_init->hasDurationThreshold()) {
      // TODO(npm): should we do basic validation (like negative values etc?).
      duration_threshold_ = std::max(16.0, observer_init->durationThreshold());
    }
    filter_options_ |= entry_type;
  }
  if (filter_options_ & PerformanceEntry::kLayoutShift) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kLayoutShiftExplicitlyRequested);
  }
  if (filter_options_ & PerformanceEntry::kElement) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kElementTimingExplicitlyRequested);
  }
  if (filter_options_ & PerformanceEntry::kLargestContentfulPaint) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kLargestContentfulPaintExplicitlyRequested);
  }
  if (filter_options_ & PerformanceEntry::kResource) {
    UseCounter::Count(GetExecutionContext(), WebFeature::kResourceTiming);
  }
  if (filter_options_ & PerformanceEntry::kLongTask) {
    UseCounter::Count(GetExecutionContext(), WebFeature::kLongTaskObserver);
  }
  if (filter_options_ & PerformanceEntry::kVisibilityState) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kVisibilityStateObserver);
  }
  if (filter_options_ & PerformanceEntry::kLongAnimationFrame) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kLongAnimationFrameObserver);
  }

  requires_dropped_entries_ = true;
  if (is_registered_)
    performance_->UpdatePerformanceObserverFilterOptions();
  else
    performance_->RegisterPerformanceObserver(*this);
  is_registered_ = true;
  if (is_buffered) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kPerformanceObserverBufferedFlag);
    performance_->ActivateObserver(*this);
  }
}

void PerformanceObserver::disconnect() {
  performance_entries_.clear();
  if (performance_)
    performance_->UnregisterPerformanceObserver(*this);
  is_registered_ = false;
  filter_options_ = PerformanceEntry::kInvalid;
}

PerformanceEntryVector PerformanceObserver::takeRecords() {
  PerformanceEntryVector performance_entries;
  performance_entries.swap(performance_entries_);
  return performance_entries;
}

void PerformanceObserver::EnqueuePerformanceEntry(PerformanceEntry& entry) {
  performance_entries_.push_back(&entry);
  if (performance_)
    performance_->ActivateObserver(*this);
}

bool PerformanceObserver::CanObserve(const PerformanceEntry& entry) const {
  if (entry.EntryTypeEnum() != PerformanceEntry::kEvent)
    return true;
  return entry.duration() >= duration_threshold_;
}

bool PerformanceObserver::HasPendingActivity() const {
  return is_registered_;
}

void PerformanceObserver::Deliver(std::optional<int> dropped_entries_count) {
  if (!GetExecutionContext())
    return;
  DCHECK(!GetExecutionContext()->IsContextPaused());

  if (performance_entries_.empty())
    return;

  PerformanceEntryVector performance_entries;
  performance_entries.swap(performance_entries_);
  PerformanceObserverEntryList* entry_list =
      MakeGarbageCollected<PerformanceObserverEntryList>(performance_entries);
  auto* options = PerformanceObserverCallbackOptions::Create();
  if (dropped_entries_count.has_value()) {
    options->setDroppedEntriesCount(dropped_entries_count.value());
  }
  requires_dropped_entries_ = false;
  callback_->InvokeAndReportException(this, entry_list, this, options);
}

void PerformanceObserver::ContextLifecycleStateChanged(
    mojom::FrameLifecycleState state) {
  if (state == mojom::FrameLifecycleState::kRunning)
    performance_->ActivateObserver(*this);
  else
    performance_->SuspendObserver(*this);
}

void PerformanceObserver::Trace(Visitor* visitor) const {
  visitor->Trace(callback_);
  visitor->Trace(performance_);
  visitor->Trace(performance_entries_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleStateObserver::Trace(visitor);
}

}  // namespace blink
```