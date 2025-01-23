Response:
Let's break down the thought process for analyzing the `performance_user_timing.cc` file.

**1. Initial Understanding and Goal:**

The request is to understand the functionality of this specific Chromium Blink engine source code file. The key directives are to list its functions, explain its relationship to web technologies (JavaScript, HTML, CSS), provide examples of logic, identify potential user/programming errors, and describe how user actions lead to this code.

**2. High-Level Skim and Keywords:**

I start by quickly skimming the code, looking for keywords and patterns. Things that jump out:

* `PerformanceUserTiming`: This immediately suggests it's related to the User Timing API.
* `mark`, `measure`:  These are core concepts in User Timing.
* `PerformanceMark`, `PerformanceMeasure`:  These are likely classes representing those concepts.
* `Performance`: This likely refers to the main Performance interface.
* `TRACE_EVENT`: Indicates involvement in performance tracing.
* `ExecutionContext`, `ScriptValue`: Hints at interaction with JavaScript.
* `DOMException`: Signals potential error handling and API usage issues.
* `PerformanceTiming`: Suggests interaction with navigation timing.
* `GetSerializedDetail`: Points to handling of potentially complex data passed to the API.
* `ClearMarks`, `ClearMeasures`, `GetMarks`, `GetMeasures`:  Methods for managing and retrieving user timing data.

**3. Function-by-Function Analysis:**

Next, I go through each method in the class `UserTiming` and try to understand its purpose:

* **`UserTiming::UserTiming(Performance& performance)`:** Constructor, takes a `Performance` object as a dependency. This means `UserTiming` relies on the broader `Performance` API.
* **`UserTiming::GetSerializedDetail(const ScriptValue& detail)`:**  This method serializes a JavaScript value (`ScriptValue`) into a string, likely for storage or tracing. The use of `v8::JSON::Stringify` is a strong indicator of JSON serialization. *Hypothesis:*  User Timing `mark` and `measure` calls can accept a `detail` object. This function prepares that object for internal use.
* **`UserTiming::AddMarkToPerformanceTimeline(...)`:** This is where the creation of a performance mark happens. It inserts the mark into internal data structures (`marks_map_`, `marks_buffer_`) and also triggers a trace event if tracing is enabled. The `mark_options` parameter suggests optional details can be attached to the mark.
* **`UserTiming::ClearMarks(const AtomicString& mark_name)`:**  Removes marks, either all of them or those with a specific name.
* **`UserTiming::FindExistingMark(const AtomicString& mark_name)`:**  Looks up a previously created mark by its name.
* **`UserTiming::FindExistingMarkStartTime(...)`:** Retrieves the start time of a mark. Importantly, it also handles the case where the "mark" name refers to a property on the `PerformanceTiming` interface (like `loadEventEnd`). This shows a connection to navigation timing.
* **`UserTiming::GetTimeOrFindMarkTime(...)`:**  A helper function to get a time, which can either be a raw timestamp or the start time of an existing mark. This adds flexibility to the `measure` API.
* **`UserTiming::GetPerformanceMarkUnsafeTimeForTraces(...)`:** Seems related to getting a consistent timestamp for tracing purposes, potentially adjusting for time origins.
* **`UserTiming::Measure(...)`:** This is the core of creating a performance *measure*. It calculates start and end times based on provided arguments (marks, timestamps, duration), and it also handles tracing. The logic for handling `start`, `end`, and `duration` combinations is important to understand.
* **`UserTiming::ClearMeasures(const AtomicString& measure_name)`:**  Similar to `ClearMarks`, but for measures.
* **`UserTiming::GetMarks()` and `GetMarks(const AtomicString& name)`:**  Methods to retrieve created marks.
* **`UserTiming::GetMeasures()` and `GetMeasures(const AtomicString& name)`:** Methods to retrieve created measures.
* **`UserTiming::InsertPerformanceEntry(...)`:** A private helper function to add a `PerformanceMark` or `PerformanceMeasure` to the internal data structures, maintaining sorted order.
* **`UserTiming::ClearPerformanceEntries(...)`:** A private helper function to clear entries from the internal data structures.
* **`UserTiming::Trace(Visitor* visitor) const`:**  Part of Blink's tracing infrastructure, allowing inspection of the object's state.

**4. Connecting to Web Technologies:**

Now, I explicitly think about how these functions relate to JavaScript, HTML, and CSS:

* **JavaScript:**  The User Timing API is exposed to JavaScript. The `performance.mark()`, `performance.measure()`, `performance.clearMarks()`, and `performance.clearMeasures()` methods directly correspond to the functionality implemented in this file. The `detail` argument for marks and measures allows passing arbitrary JavaScript objects.
* **HTML:**  While not directly involved in rendering, the timing information collected here can be crucial for understanding the performance of loading and interacting with HTML documents. For example, developers might use measures to track the time it takes to render a specific part of the page.
* **CSS:** Similar to HTML, CSS affects rendering performance. Developers could use User Timing to measure the impact of CSS changes on rendering time.

**5. Examples and Scenarios:**

To solidify understanding, I create simple usage examples:

* **`performance.mark('start-fetch')`; `fetch(...) .then(() => performance.mark('end-fetch'));` `performance.measure('fetch-time', 'start-fetch', 'end-fetch');`:**  This demonstrates a common use case for measuring asynchronous operations.
* **`performance.mark('dom-ready');` (triggered by some DOM event):** Shows how marks can be placed at specific points in the page lifecycle.
* **`performance.measure('my-custom-metric', performance.timeOrigin + 100, performance.now());`:**  Illustrates using raw timestamps.

**6. Identifying Potential Errors:**

I consider common mistakes developers might make when using the User Timing API:

* Incorrect mark names in `measure()`.
* Providing negative timestamps.
* Confusing `start`, `end`, and `duration` parameters in `measure()`.
* Trying to measure against `PerformanceTiming` attributes in a Worker context.

**7. Debugging and User Actions:**

I consider how a developer might end up investigating this specific file during debugging:

* Experiencing performance issues and suspecting custom timing measurements are involved.
* Setting breakpoints in the JavaScript User Timing API calls.
* Looking at trace logs generated by the `TRACE_EVENT` calls in this file.

**8. Structuring the Answer:**

Finally, I organize the information into the requested format: functions, relationship to web technologies, examples, errors, and debugging. I use clear and concise language, providing code snippets where appropriate.

This detailed step-by-step process allows for a comprehensive understanding of the code and its role within the larger Blink rendering engine. It combines code analysis with knowledge of web standards and common development practices.
好的，我们来分析一下 `blink/renderer/core/timing/performance_user_timing.cc` 这个文件。

**文件功能概述**

`performance_user_timing.cc` 文件实现了 Chromium Blink 引擎中 User Timing API 的核心逻辑。User Timing API 允许开发者在他们的应用程序中插入自定义的“标记 (marks)”和“度量 (measures)”，以便更精细地测量和分析应用程序的性能。

**主要功能点：**

1. **创建和管理 Performance Marks (性能标记):**
    *   允许开发者通过 `performance.mark()` JavaScript 方法创建命名的时间点。
    *   内部使用 `PerformanceMark` 类来表示这些标记。
    *   将这些标记存储在内部数据结构 (`marks_map_`, `marks_buffer_`) 中。
    *   支持通过名称清除特定的标记或所有标记 (`clearMarks()`)。
    *   在 tracing 系统中记录标记事件。

2. **创建和管理 Performance Measures (性能度量):**
    *   允许开发者通过 `performance.measure()` JavaScript 方法创建两个标记之间或相对于特定时间点的持续时间度量。
    *   内部使用 `PerformanceMeasure` 类来表示这些度量。
    *   将这些度量存储在内部数据结构 (`measures_map_`, `measures_buffer_`) 中。
    *   支持通过名称清除特定的度量或所有度量 (`clearMeasures()`)。
    *   在 tracing 系统中记录度量事件。

3. **获取性能条目 (Performance Entries):**
    *   提供方法 (`GetMarks()`, `GetMeasures()`) 来获取所有已创建的标记和度量。
    *   提供方法 (`GetMarks(name)`, `GetMeasures(name)`) 来获取具有特定名称的标记和度量。

4. **与 Performance Timing API 集成:**
    *   `performance.measure()` 可以使用 `PerformanceTiming` 接口中的属性 (如 `loadEventEnd`) 作为起始或结束时间点。

5. **与 Tracing 系统集成:**
    *   使用 `TRACE_EVENT` 宏将 User Timing 事件记录到 Chromium 的 tracing 系统中，方便开发者进行性能分析。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件直接实现了暴露给 JavaScript 的 User Timing API。以下是具体的联系：

*   **JavaScript:**
    *   **`performance.mark(markName, markOptions)`:**  当 JavaScript 调用此方法时，Blink 引擎会调用 `UserTiming::AddMarkToPerformanceTimeline` 方法，创建一个 `PerformanceMark` 对象，并将其添加到内部存储中。
        *   **例子:** `performance.mark('dataFetched', { detail: { api: 'users' } });`  这里，`'dataFetched'` 是标记的名称，`{ detail: { api: 'users' } }` 是一个可选的附加信息对象。`GetSerializedDetail` 方法会将这个 `detail` 对象序列化成字符串，用于 tracing。
    *   **`performance.measure(measureName, startMarkOrMeasureOrTime, endMarkOrMeasureOrTime)` 或 `performance.measure(measureName, startMarkOrMeasureOrTime, options)`:** 当 JavaScript 调用此方法时，Blink 引擎会调用 `UserTiming::Measure` 方法，创建一个 `PerformanceMeasure` 对象。
        *   **例子 1 (基于标记):** `performance.measure('fetchToRender', 'fetchStart', 'renderEnd');`  这里，度量从名为 `'fetchStart'` 的标记开始，到名为 `'renderEnd'` 的标记结束。`FindExistingMarkStartTime` 方法会被调用来查找这些标记的起始时间。
        *   **例子 2 (基于时间戳):** `performance.measure('customSection', performance.now() - 100, performance.now());` 这里，度量基于 `performance.now()` 返回的时间戳。
        *   **例子 3 (使用 PerformanceTiming):** `performance.measure('domLoadingToLoad', 'domLoading', 'loadEventEnd');`  这里，`'domLoading'` 和 `'loadEventEnd'` 是 `PerformanceTiming` 接口的属性。`FindExistingMarkStartTime` 会识别这些属性并从 `PerformanceTiming` 对象中获取相应的时间。
    *   **`performance.clearMarks(markName)`:** 当 JavaScript 调用此方法时，Blink 引擎会调用 `UserTiming::ClearMarks` 方法来清除指定的标记。
    *   **`performance.clearMeasures(measureName)`:** 当 JavaScript 调用此方法时，Blink 引擎会调用 `UserTiming::ClearMeasures` 方法来清除指定的度量。
    *   **`performance.getEntriesByType('mark')` 或 `performance.getEntriesByName('myMark', 'mark')`:** 这些方法最终会使用 `UserTiming::GetMarks` 来返回存储的 `PerformanceMark` 对象。
    *   **`performance.getEntriesByType('measure')` 或 `performance.getEntriesByName('myMeasure', 'measure')`:** 这些方法最终会使用 `UserTiming::GetMeasures` 来返回存储的 `PerformanceMeasure` 对象。

*   **HTML 和 CSS:**
    虽然 `performance_user_timing.cc` 本身不直接处理 HTML 或 CSS 的解析和渲染，但开发者可以使用 User Timing API 来测量与 HTML 和 CSS 相关的性能指标：
    *   **测量资源加载时间:** 使用标记来标记资源请求的开始和结束，然后使用度量来计算加载时间。例如，在 JavaScript 中监听图像加载事件，并在加载开始和结束时创建标记。
    *   **测量渲染时间:**  在关键的渲染阶段插入标记，例如首次内容绘制 (FCP) 或最大内容绘制 (LCP) 的时间点，然后使用度量来计算这些阶段之间的时间。
    *   **测量 CSS 动画或过渡的性能:** 在动画或过渡开始和结束时添加标记，以分析其性能。

**逻辑推理、假设输入与输出**

**假设输入：** JavaScript 代码调用 `performance.measure('dataProcessing', 'fetchEnd', performance.now())`

**逻辑推理：**

1. `UserTiming::Measure` 方法被调用。
2. `start` 参数是字符串 `'fetchEnd'`，因此 `GetTimeOrFindMarkTime` 方法被调用。
3. 在 `GetTimeOrFindMarkTime` 中，由于 `mark_or_time` 是字符串，`FindExistingMarkStartTime` 被调用。
4. `FindExistingMarkStartTime` 在 `marks_map_` 中查找名为 `'fetchEnd'` 的标记。
    *   **假设 1 (找到标记):** 如果找到了名为 `'fetchEnd'` 的标记，则返回该标记的 `startTime()`。
    *   **假设 2 (未找到标记):** 如果未找到，并且 `'fetchEnd'` 不是 `PerformanceTiming` 的属性，则会抛出一个 `DOMException`，指示标记不存在。
5. `end` 参数是 `performance.now()` 返回的当前时间戳。
6. 如果成功获取了 `start_time` 和 `end_time`，则创建一个 `PerformanceMeasure` 对象，计算持续时间，并将其添加到 `measures_map_` 和 `measures_buffer_` 中。
7. 如果启用了 tracing，则会记录一个 tracing 事件。

**假设输出 (假设 1)：**  在性能时间线上添加一个新的 `PerformanceMeasure` 条目，其名称为 `'dataProcessing'`，起始时间为 `'fetchEnd'` 标记的时间，结束时间为调用 `performance.now()` 时的当前时间。

**用户或编程常见的使用错误**

1. **标记名称拼写错误:**
    *   **错误示例:**  `performance.mark('fetchDataStart');` ... `performance.measure('processData', 'fetDataStart', 'fetchDataEnd');`  (`'fetDataStart'` 拼写错误)
    *   **结果:** 当调用 `performance.measure` 时，`FindExistingMarkStartTime` 将找不到名为 `'fetDataStart'` 的标记，并抛出 `DOMException`。

2. **在 `measure` 中使用不存在的标记名称:**
    *   **错误示例:** `performance.measure('renderTime', 'navigationStart', 'nonExistentMark');`
    *   **结果:**  `FindExistingMarkStartTime` 找不到 `'nonExistentMark'`，并抛出 `DOMException`。

3. **在 `measure` 中混淆 `start` 和 `end` 参数的类型:**
    *   **错误示例:**  `performance.measure('duration', 100, 'myMark');`  (期望 `'myMark'` 的时间戳是 100 毫秒之后，但实际会将 `'myMark'` 当作结束标记)
    *   **结果:**  可能导致不准确的度量结果，或者如果 `'myMark'` 不存在，则抛出异常。

4. **在 Worker 上下文中尝试使用 PerformanceTiming 属性作为标记名称:**
    *   **错误示例 (在 Worker 中):** `performance.measure('loadTime', 'domContentLoadedEventEnd', performance.now());`
    *   **结果:**  `FindExistingMarkStartTime` 会检测到在 Worker 上下文中使用了 `PerformanceTiming` 属性，并抛出 `TypeError`。

5. **提供负的时间戳给 `measure`:**
    *   **错误示例:** `performance.measure('negativeTime', -10, performance.now());`
    *   **结果:** `GetTimeOrFindMarkTime` 会检查时间戳是否为负数，如果为负数则抛出 `TypeError`。

**用户操作是如何一步步的到达这里，作为调试线索**

假设开发者想要调试一个页面加载缓慢的问题，并使用了 User Timing API 来标记关键阶段。

1. **开发者在 JavaScript 代码中插入 `performance.mark()` 和 `performance.measure()` 调用:**
    ```javascript
    console.time('pageLoad'); // 使用 console.time 作为对比
    performance.mark('navigationStart');

    window.addEventListener('DOMContentLoaded', () => {
      performance.mark('domContentLoaded');
      performance.measure('navigationToDomContentLoaded', 'navigationStart', 'domContentLoaded');
    });

    window.addEventListener('load', () => {
      performance.mark('pageLoadEnd');
      performance.measure('domContentLoadedToLoad', 'domContentLoaded', 'pageLoadEnd');
      performance.measure('totalPageLoad', 'navigationStart', 'pageLoadEnd');
      console.timeEnd('pageLoad');
    });
    ```

2. **用户在浏览器中打开或刷新页面:**  这将触发上述 JavaScript 代码的执行。

3. **浏览器执行 JavaScript 代码，并调用 `performance.mark()` 和 `performance.measure()`:**  这些调用会进入 Blink 引擎，最终调用 `performance_user_timing.cc` 中的方法。

4. **如果开发者发现 `totalPageLoad` 度量的时间过长，想要进一步分析:**

5. **开发者可以使用浏览器的开发者工具 (Performance 面板):**  Performance 面板会显示 User Timing 的标记和度量，方便开发者查看。

6. **如果开发者需要更深入的调试，例如想知道某个标记是否被正确创建或测量逻辑是否正确:**

7. **开发者可能会在 JavaScript 代码中设置断点:**  在 `performance.mark()` 或 `performance.measure()` 调用处设置断点，查看参数值。

8. **开发者可能会查看浏览器的 tracing 信息 (chrome://tracing):**  `performance_user_timing.cc` 中的 `TRACE_EVENT` 调用会将相关信息记录到 tracing 系统中。开发者可以加载 tracing 日志，查看 `blink.user_timing` 分类下的事件，了解标记和度量的创建时间、名称等信息。

9. **如果怀疑 Blink 引擎内部的逻辑有问题，或者需要理解 `performance_user_timing.cc` 的具体实现:**

10. **开发者可能会下载 Chromium 源代码，并找到 `performance_user_timing.cc` 文件。**

11. **开发者可以使用调试器 (例如 gdb 或 lldb) attach 到 Chrome 进程，并在 `performance_user_timing.cc` 的关键方法上设置断点，例如 `AddMarkToPerformanceTimeline` 或 `Measure`。**

12. **当用户操作触发相应的 JavaScript 代码时，断点会被命中，开发者可以单步执行代码，查看内部变量的值，例如 `marks_map_` 和 `measures_map_` 的内容，以及时间戳的计算过程。**

总而言之，`performance_user_timing.cc` 是 User Timing API 在 Blink 引擎中的核心实现，它负责接收来自 JavaScript 的请求，创建和管理性能标记和度量，并将这些信息暴露给开发者进行性能分析。调试线索可以从 JavaScript 代码开始，逐步深入到浏览器开发者工具、tracing 系统，最终可能需要查看 Blink 引擎的源代码并进行调试。

### 提示词
```
这是目录为blink/renderer/core/timing/performance_user_timing.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Intel Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/timing/performance_user_timing.h"

#include "base/trace_event/typed_macros.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_performance_mark_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_double_string.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/core/timing/performance_mark.h"
#include "third_party/blink/renderer/core/timing/performance_measure.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"

namespace blink {

namespace {

bool IsTracingEnabled() {
  bool enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("blink.user_timing", &enabled);
  return enabled;
}

}  // namespace

UserTiming::UserTiming(Performance& performance) : performance_(&performance) {}

String UserTiming::GetSerializedDetail(const ScriptValue& detail) {
  String serialized_detail = "";
  if (ExecutionContext* execution_context =
          performance_->GetExecutionContext()) {
    v8::Isolate* isolate = execution_context->GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    if (!(detail.IsEmpty() || detail.V8Value()->IsNullOrUndefined())) {
      v8::Local<v8::String> v8_string;
      if (v8::JSON::Stringify(context, detail.V8Value()).ToLocal(&v8_string)) {
        serialized_detail = ToCoreString(isolate, v8_string);
      }
    }
  }
  return serialized_detail;
}
void UserTiming::AddMarkToPerformanceTimeline(
    PerformanceMark& mark,
    PerformanceMarkOptions* mark_options) {
  InsertPerformanceEntry(marks_map_, marks_buffer_, mark);
  if (!IsTracingEnabled()) {
    return;
  }
  ScriptValue detail = mark_options && mark_options->hasDetail()
                           ? mark_options->detail()
                           : ScriptValue();
  String serialized_detail = GetSerializedDetail(detail);
  auto source_location = CaptureSourceLocation();

  const auto trace_event_details = [&](perfetto::EventContext ctx) {
    ctx.event()->set_name(mark.name().Utf8().c_str());
    ctx.AddDebugAnnotation("data", [&](perfetto::TracedValue trace_context) {
      auto dict = std::move(trace_context).WriteDictionary();
      dict.Add("startTime", mark.startTime());
      dict.Add("stackTrace", source_location);
      // Only set when performance_ is a WindowPerformance.
      // performance_->timing() returns null when performance_ is a
      // WorkerPerformance.
      if (serialized_detail.length()) {
        dict.Add("detail", serialized_detail);
      }
      if (performance_->timing()) {
        performance_->timing()->WriteInto(dict);
      }
    });
  };
  TRACE_EVENT_INSTANT("blink.user_timing", nullptr, mark.UnsafeTimeForTraces(),
                      trace_event_details);
}

void UserTiming::ClearMarks(const AtomicString& mark_name) {
  ClearPerformanceEntries(marks_map_, marks_buffer_, mark_name);
  if (IsTracingEnabled()) {
    TRACE_EVENT_INSTANT("blink.user_timing", "clearMarks", "name",
                        mark_name.Utf8().c_str());
  }
}

const PerformanceMark* UserTiming::FindExistingMark(
    const AtomicString& mark_name) {
  PerformanceEntryMap::const_iterator existing_marks =
      marks_map_.find(mark_name);
  if (existing_marks != marks_map_.end()) {
    PerformanceEntry* entry = existing_marks->value->back().Get();
    DCHECK(entry->entryType() == performance_entry_names::kMark);
    return static_cast<PerformanceMark*>(entry);
  }
  return nullptr;
}

double UserTiming::FindExistingMarkStartTime(const AtomicString& mark_name,
                                             ExceptionState& exception_state) {
  const PerformanceMark* mark = FindExistingMark(mark_name);
  if (mark) {
    return mark->startTime();
  }

  // Although there was no mark with the given name in UserTiming, we need to
  // support measuring with respect to |PerformanceTiming| attributes.
  if (!PerformanceTiming::IsAttributeName(mark_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The mark '" + mark_name + "' does not exist.");
    return 0.0;
  }

  PerformanceTiming* timing = performance_->timing();
  if (!timing) {
    // According to
    // https://w3c.github.io/user-timing/#convert-a-name-to-a-timestamp.
    exception_state.ThrowTypeError(
        "When converting a mark name ('" + mark_name +
        "') to a timestamp given a name that is a read only attribute in the "
        "PerformanceTiming interface, the global object has to be a Window "
        "object.");
    return 0.0;
  }

  // Because we know |PerformanceTiming::IsAttributeName(mark_name)| is true
  // (from above), we know calling |GetNamedAttribute| won't fail.
  double value = static_cast<double>(timing->GetNamedAttribute(mark_name));
  if (!value) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "'" + mark_name +
                                          "' is empty: either the event hasn't "
                                          "happened yet, or it would provide "
                                          "cross-origin timing information.");
    return 0.0;
  }

  // Count the usage of PerformanceTiming attribute names in performance
  // measure. See crbug.com/1318445.
  blink::UseCounter::Count(performance_->GetExecutionContext(),
                           WebFeature::kPerformanceMeasureFindExistingName);

  return value - timing->navigationStart();
}

double UserTiming::GetTimeOrFindMarkTime(
    const AtomicString& measure_name,
    const V8UnionDoubleOrString* mark_or_time,
    ExceptionState& exception_state) {
  DCHECK(mark_or_time);

  switch (mark_or_time->GetContentType()) {
    case V8UnionDoubleOrString::ContentType::kDouble: {
      const double time = mark_or_time->GetAsDouble();
      if (time < 0.0) {
        exception_state.ThrowTypeError("'" + measure_name +
                                       "' cannot have a negative time stamp.");
      }
      return time;
    }
    case V8UnionDoubleOrString::ContentType::kString:
      return FindExistingMarkStartTime(
          AtomicString(mark_or_time->GetAsString()), exception_state);
  }

  NOTREACHED();
}

base::TimeTicks UserTiming::GetPerformanceMarkUnsafeTimeForTraces(
    double start_time,
    const V8UnionDoubleOrString* maybe_mark_name) {
  if (maybe_mark_name && maybe_mark_name->IsString()) {
    const PerformanceMark* mark =
        FindExistingMark(AtomicString(maybe_mark_name->GetAsString()));
    if (mark) {
      return mark->UnsafeTimeForTraces();
    }
  }
  return performance_->GetTimeOriginInternal() + base::Milliseconds(start_time);
}

PerformanceMeasure* UserTiming::Measure(ScriptState* script_state,
                                        const AtomicString& measure_name,
                                        const V8UnionDoubleOrString* start,
                                        const std::optional<double>& duration,
                                        const V8UnionDoubleOrString* end,
                                        const ScriptValue& detail,
                                        ExceptionState& exception_state,
                                        DOMWindow* source) {
  double start_time =
      start ? GetTimeOrFindMarkTime(measure_name, start, exception_state) : 0;
  if (exception_state.HadException())
    return nullptr;

  double end_time =
      end ? GetTimeOrFindMarkTime(measure_name, end, exception_state)
          : performance_->now();
  if (exception_state.HadException())
    return nullptr;

  if (duration.has_value()) {
    // When |duration| is specified, we require that exactly one of |start| and
    // |end| were specified. Then, since |start| + |duration| = |end|, we'll
    // compute the missing boundary.
    if (!start) {
      start_time = end_time - duration.value();
    } else {
      DCHECK(!end) << "When duration is specified, one of 'start' or "
                      "'end' must be unspecified";
      end_time = start_time + duration.value();
    }
  }

  if (IsTracingEnabled()) {
    base::TimeTicks unsafe_start_time =
        GetPerformanceMarkUnsafeTimeForTraces(start_time, start);
    base::TimeTicks unsafe_end_time =
        GetPerformanceMarkUnsafeTimeForTraces(end_time, end);
    unsigned hash = WTF::GetHash(measure_name);
    WTF::AddFloatToHash(hash, start_time);
    WTF::AddFloatToHash(hash, end_time);
    String serialized_detail = GetSerializedDetail(detail);
    auto source_location = CaptureSourceLocation();
    if (serialized_detail.length()) {
      TRACE_EVENT_BEGIN("blink.user_timing", nullptr, perfetto::Track(hash),
                        unsafe_start_time, "startTime", start_time,
                        "stackTrace", source_location, "detail",
                        serialized_detail, [&](perfetto::EventContext ctx) {
                          ctx.event()->set_name(measure_name.Utf8().c_str());
                        });
    } else {
      TRACE_EVENT_BEGIN("blink.user_timing", nullptr, perfetto::Track(hash),
                        unsafe_start_time, "startTime", start_time,
                        "stackTrace", source_location,
                        [&](perfetto::EventContext ctx) {
                          ctx.event()->set_name(measure_name.Utf8().c_str());
                        });
    }
    TRACE_EVENT_END("blink.user_timing", perfetto::Track(hash),
                    unsafe_end_time);
  }

  PerformanceMeasure* measure =
      PerformanceMeasure::Create(script_state, measure_name, start_time,
                                 end_time, detail, exception_state, source);
  if (!measure)
    return nullptr;
  InsertPerformanceEntry(measures_map_, measures_buffer_, *measure);
  return measure;
}

void UserTiming::ClearMeasures(const AtomicString& measure_name) {
  ClearPerformanceEntries(measures_map_, measures_buffer_, measure_name);
  if (IsTracingEnabled()) {
    TRACE_EVENT_INSTANT("blink.user_timing", "clearMeasures", "name",
                        measure_name.Utf8().c_str());
  }
}

PerformanceEntryVector UserTiming::GetMarks() const {
  return marks_buffer_;
}

PerformanceEntryVector UserTiming::GetMarks(const AtomicString& name) const {
  PerformanceEntryMap::const_iterator it = marks_map_.find(name);
  if (it != marks_map_.end()) {
    return *it->value;
  }
  return {};
}

PerformanceEntryVector UserTiming::GetMeasures() const {
  return measures_buffer_;
}

PerformanceEntryVector UserTiming::GetMeasures(const AtomicString& name) const {
  PerformanceEntryMap::const_iterator it = measures_map_.find(name);
  if (it != measures_map_.end()) {
    return *it->value;
  }
  return {};
}

void UserTiming::InsertPerformanceEntry(
    PerformanceEntryMap& performance_entry_map,
    PerformanceEntryVector& performance_entry_buffer,
    PerformanceEntry& entry) {
  performance_->InsertEntryIntoSortedBuffer(performance_entry_buffer, entry,
                                            Performance::kDoNotRecordSwaps);

  auto it = performance_entry_map.find(entry.name());
  if (it == performance_entry_map.end()) {
    PerformanceEntryVector* entries =
        MakeGarbageCollected<PerformanceEntryVector>();
    entries->push_back(&entry);
    performance_entry_map.Set(entry.name(), entries);
    return;
  }

  DCHECK(it->value);
  performance_->InsertEntryIntoSortedBuffer(*it->value.Get(), entry,
                                            Performance::kDoNotRecordSwaps);
}

void UserTiming::ClearPerformanceEntries(
    PerformanceEntryMap& performance_entry_map,
    PerformanceEntryVector& performance_entry_buffer,
    const AtomicString& name) {
  if (name.IsNull()) {
    performance_entry_map.clear();
    performance_entry_buffer.clear();
    return;
  }

  if (performance_entry_map.Contains(name)) {
    UseCounter::Count(performance_->GetExecutionContext(),
                      WebFeature::kClearPerformanceEntries);

    // Remove key/value pair from the map.
    performance_entry_map.erase(name);

    // In favor of quicker getEntries() calls, we tradeoff performance here to
    // linearly 'clear' entries in the vector.
    performance_entry_buffer.erase(
        std::remove_if(performance_entry_buffer.begin(),
                       performance_entry_buffer.end(),
                       [name](auto& entry) { return entry->name() == name; }),
        performance_entry_buffer.end());
  }
}

void UserTiming::Trace(Visitor* visitor) const {
  visitor->Trace(performance_);
  visitor->Trace(marks_map_);
  visitor->Trace(measures_map_);
  visitor->Trace(marks_buffer_);
  visitor->Trace(measures_buffer_);
}

}  // namespace blink
```