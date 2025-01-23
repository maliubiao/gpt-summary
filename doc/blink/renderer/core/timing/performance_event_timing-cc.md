Response:
Let's break down the thought process for analyzing the `performance_event_timing.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific Chromium Blink source code file and its relationship to web technologies (JavaScript, HTML, CSS), identify potential user errors, and trace how user actions lead to its execution.

2. **Initial Reading and Keyword Identification:** Scan the code for important keywords and class names. Immediately, we see:
    * `PerformanceEventTiming`: This is the central class. The file is clearly about tracking the timing of events.
    * `PerformanceEntry`:  `PerformanceEventTiming` inherits from this. This suggests it's part of the broader Performance API.
    * `EventTimingReportingInfo`: This struct likely holds the raw timing data for events.
    * `DOMHighResTimeStamp`:  Indicates high-precision time measurements, essential for performance tracking.
    * `interactionId`, `interactionOffset`: Hints at tracking user interactions.
    * `processingStart`, `processingEnd`:  Points to measuring the time taken to process an event.
    * `cancelable`:  Relates to whether the event can be prevented.
    * `target`: The DOM element the event is associated with.
    * `perfetto`: The presence of `perfetto::protos::pbzero::EventTiming` suggests integration with the Perfetto tracing system.
    * `V8ObjectBuilder`: Indicates interaction with the V8 JavaScript engine.

3. **Deconstructing the Class Structure:** Analyze the `PerformanceEventTiming` class:
    * **Constructors:** Notice the different ways `PerformanceEventTiming` objects are created (`Create`, `CreateFirstInputTiming`). The parameters passed to the constructors give clues about the data being tracked. The `CreateFirstInputTiming` function is significant, highlighting a specific focus on the first user interaction.
    * **Member Variables:**  The member variables (like `reporting_info_`, `processing_start_`, `target_`, `interactionId_`) confirm the data being managed.
    * **Methods:** Examine the methods. What information do they provide or modify?
        * Getter methods (`processingStart`, `processingEnd`, `target`, `interactionId`, `HasKnownEndTime`, `GetEndTime`) expose the timing data.
        * Setter methods (`SetTarget`, `SetInteractionId`, `SetInteractionIdAndOffset`, `SetDuration`) allow modification of the object's state.
        * `BuildJSONValue`: This is crucial. It demonstrates how the performance data is structured for consumption by JavaScript (via the Performance API).
        * `SetPerfettoData`: Shows integration with the Perfetto tracing system for performance analysis.
        * `ToTracedValue`:  Another method for exporting data, likely for DevTools.

4. **Relating to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `BuildJSONValue` method strongly links this code to JavaScript. The data collected here becomes available through the `PerformanceEventTiming` interface in JavaScript's Performance API. The `performance.getEntriesByType("event")` and `performance.getEntriesByType("first-input")` examples directly demonstrate this.
    * **HTML:**  The `target_` member variable, representing a `Node`, connects to HTML elements. Events are dispatched on specific HTML elements. The example of clicking a button illustrates this.
    * **CSS:** While this specific file doesn't directly manipulate CSS, event timing can *indirectly* be affected by CSS. For example, a complex CSS animation might delay the processing of a click event.

5. **Logical Reasoning and Examples:**
    * **First Input Delay (FID):** The `CreateFirstInputTiming` method and the `kFirstInput` entry type directly relate to FID. The logic of copying data from the original event timing entry is evident.
    * **Event Timing Calculation:** The `processingStart` and `processingEnd` methods, along with `creation_time` in the constructor, are clearly used to calculate event processing duration.

6. **Identifying User/Programming Errors:**
    * **Incorrect Event Listeners:**  Attaching event listeners to the wrong element or not preventing default behavior when needed can lead to unexpected timing measurements.
    * **Performance Bottlenecks:** While not strictly an *error* in this file, the data collected here helps identify performance issues in event handlers. Slow JavaScript code can increase `processingEnd - processingStart`.

7. **Tracing User Actions:**  Think about the chain of events that leads to this code being executed:
    * A user interacts with a webpage (clicks, touches, presses a key).
    * The browser detects this interaction.
    * An event object is created.
    * Blink (the rendering engine) begins processing the event. This is where `PerformanceEventTiming` comes into play to record the timing.
    * Event listeners are invoked (JavaScript code runs).
    * The browser renders updates based on the event handling.

8. **Debugging Clues:** Consider how the information in this file helps developers debug performance issues:
    * **Identifying Slow Events:**  Long `processingEnd - processingStart` times pinpoint slow event handlers.
    * **Understanding FID:**  The `first-input` entry helps diagnose responsiveness issues.
    * **Tracing Event Flow:** The `interactionId` can help correlate related events.

9. **Refinement and Organization:** Structure the findings logically with clear headings and examples. Use the provided code snippets to support the explanations. Ensure the language is clear and concise. For example, initially, I might just say "tracks event timing," but then I'd refine it to be more specific like, "measures the various stages of event processing, from creation to completion."

10. **Review and Verify:**  Read through the analysis to ensure accuracy and completeness. Double-check the connections to web technologies and the examples provided. Make sure the explanation of user actions and debugging is clear and helpful.

By following these steps, we can systematically analyze the source code and provide a comprehensive explanation of its functionality and context.
好的，让我们来分析一下 `blink/renderer/core/timing/performance_event_timing.cc` 这个文件。

**文件功能概述:**

`PerformanceEventTiming.cc` 文件的主要功能是**记录和管理与用户交互事件相关的性能指标**。它实现了 `PerformanceEventTiming` 类，该类继承自 `PerformanceEntry`，用于表示在浏览器的性能时间线中发生的特定事件的时序信息。这些信息对于衡量网页的交互性和响应速度至关重要。

**具体功能点:**

1. **创建 `PerformanceEventTiming` 对象:**
   - 提供了 `Create` 静态方法，用于创建表示普通事件的 `PerformanceEventTiming` 对象。它接收事件类型、报告信息、是否可取消、事件目标节点和事件源窗口等参数。
   - 提供了 `CreateFirstInputTiming` 静态方法，用于基于现有的 `PerformanceEventTiming` 对象创建表示首次输入延迟 (First Input Delay - FID) 的 `PerformanceEventTiming` 对象。FID 是一个关键的性能指标，衡量用户首次与页面交互（例如点击、触摸）到浏览器实际响应之间的时间间隔。

2. **存储事件时序信息:**
   - 存储事件的创建时间 (`reporting_info_.creation_time`)。
   - 存储事件处理的开始时间 (`reporting_info_.processing_start_time`)。
   - 存储事件处理的结束时间 (`reporting_info_.processing_end_time`)。
   - 存储事件最终呈现时间或回退时间 (`reporting_info_.presentation_time`, `reporting_info_.fallback_time`)。
   - 存储事件是否可取消 (`cancelable_`)。
   - 存储事件的目标 DOM 节点 (`target_`)。
   - 存储事件的交互 ID 和偏移量 (`interaction_id_`, `interaction_offset_`)，用于关联一系列相关的用户交互事件。

3. **提供访问时序数据的方法:**
   - 提供 `processingStart()` 和 `processingEnd()` 方法，用于获取事件处理的开始和结束时间。这些时间戳被转换为高精度时间 (`DOMHighResTimeStamp`)。
   - 提供 `target()` 方法获取事件的目标节点。出于安全考虑，如果节点不应该暴露，则返回 `nullptr`。
   - 提供 `interactionId()` 和 `interactionOffset()` 方法获取交互 ID 和偏移量。
   - 提供 `HasKnownEndTime()` 和 `GetEndTime()` 方法判断和获取事件的最终结束时间。

4. **支持将数据序列化为 JSON:**
   - `BuildJSONValue` 方法用于将 `PerformanceEventTiming` 对象的数据添加到 JSON 对象中，方便 JavaScript 代码通过 Performance API 获取这些信息。

5. **支持集成到性能追踪系统 (Perfetto):**
   - `SetPerfettoData` 方法将 `PerformanceEventTiming` 对象的数据转换为 Perfetto 的事件格式，用于更底层的性能分析和追踪。

6. **支持生成用于开发者工具的追踪数据:**
   - `ToTracedValue` 方法生成用于 Chrome 开发者工具性能面板的追踪数据。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`PerformanceEventTiming` 类是 Web Performance API 的一部分，直接与 JavaScript 交互，并间接地与 HTML 和 CSS 相关。

**与 JavaScript 的关系:**

- **JavaScript Performance API:**  JavaScript 代码可以使用 `performance.getEntriesByType('event')` 或 `performance.getEntriesByType('first-input')` 方法来获取 `PerformanceEventTiming` 对象数组。
  ```javascript
  performance.getEntriesByType('event').forEach(entry => {
    console.log(entry.name, entry.startTime, entry.duration, entry.processingStart, entry.processingEnd, entry.interactionId);
  });

  performance.getEntriesByType('first-input').forEach(entry => {
    console.log(entry.name, entry.startTime, entry.duration, entry.processingStart, entry.processingEnd);
  });
  ```
- **事件处理函数:** 当用户与页面上的元素交互时，浏览器会触发相应的事件（如 `click`, `keydown` 等）。`PerformanceEventTiming` 会记录这些事件的时序信息，包括执行 JavaScript 事件处理函数的时间。

**与 HTML 的关系:**

- **DOM 元素作为事件目标:**  `PerformanceEventTiming` 对象会记录事件的目标 HTML 元素 (`target_`)。例如，当用户点击一个按钮时，该按钮的 DOM 节点会被记录为事件目标。
  ```html
  <button id="myButton">Click Me</button>
  <script>
    document.getElementById('myButton').addEventListener('click', function() {
      // 一些 JavaScript 代码
    });
  </script>
  ```
  当用户点击 "Click Me" 按钮时，会创建一个 `PerformanceEventTiming` 对象，其 `target()` 方法会返回该按钮的 DOM 元素。

**与 CSS 的关系:**

- **CSS 动画和过渡:** CSS 动画和过渡可能会影响事件的呈现时间。`PerformanceEventTiming` 记录的 `processingEnd` 和可能的呈现时间 (`presentation_time`) 可以反映 CSS 渲染对事件处理的影响。例如，如果一个按钮的点击事件触发了一个复杂的 CSS 动画，那么动画的渲染完成时间可能会体现在 `presentation_time` 中。
- **阻塞渲染:** 某些 CSS 操作（例如同步加载阻塞渲染的 CSS）可能会延迟事件处理的开始时间。

**逻辑推理、假设输入与输出:**

假设用户在页面加载完成后点击了一个按钮：

**假设输入:**

- 用户在 `t0` 时刻点击了 ID 为 `myButton` 的 `<button>` 元素。
- 浏览器在 `t1` 时刻接收到点击事件。
- 浏览器在 `t2` 时刻开始处理该点击事件。
- 与该按钮关联的 JavaScript 事件处理函数执行，并在 `t3` 时刻完成。
- 浏览器在 `t4` 时刻完成与该事件相关的渲染更新。

**`PerformanceEventTiming` 对象的输出:**

- `name()`:  "click"
- `startTime`:  接近 `t1` 转换后的高精度时间戳 (事件创建时间)
- `processingStart()`: 接近 `t2` 转换后的高精度时间戳
- `processingEnd()`: 接近 `t3` 转换后的高精度时间戳
- `duration`:  `processingEnd() - startTime`  (或其他相关时间点的差值，取决于具体计算)
- `interactionId()`: 如果该点击是用户交互的一部分，则会有一个非零的 ID。
- `processingStart - startTime`:  事件从创建到开始处理的延迟。
- `processingEnd - processingStart`:  事件处理的耗时。

**用户或编程常见的使用错误及举例说明:**

1. **误解 `processingStart` 和 `processingEnd` 的含义:** 开发者可能会错误地认为这两个时间点完全涵盖了所有与事件相关的操作，而忽略了事件入队、渲染更新等其他阶段。

2. **过度依赖 `duration` 属性:**  `duration` 属性的计算方式可能因事件类型而异，开发者应该仔细理解其含义，而不是简单地将其作为衡量事件性能的唯一指标。

3. **没有正确处理事件取消:**  如果事件被取消（`cancelable` 为 true 且调用了 `preventDefault()`），其后续处理流程可能会有所不同，性能指标也会受到影响。开发者需要理解事件取消对性能指标的意义。

4. **在性能分析时忽略 `interactionId`:**  对于一系列相关的用户交互，`interactionId` 可以帮助将它们关联起来进行分析。忽略它可能会导致对用户体验的理解不完整。

**用户操作如何一步步到达这里，作为调试线索:**

以下是一个典型的用户操作流程，最终会涉及到 `PerformanceEventTiming.cc` 中的代码执行：

1. **用户在浏览器中加载网页:**  浏览器解析 HTML、CSS 和 JavaScript。
2. **用户与网页上的元素进行交互:** 例如，用户点击了一个按钮、在文本框中输入内容或滚动页面。
3. **浏览器捕获用户交互事件:** 浏览器内核（包括 Blink 引擎）会检测到用户的操作，并创建一个表示该事件的对象 (例如 `MouseEvent`, `KeyboardEvent`)。
4. **事件被分发到目标元素:** 浏览器将事件传递给相应的 DOM 元素。
5. **Blink 引擎创建 `PerformanceEventTiming` 对象:**  在事件分发和处理的关键阶段，`PerformanceEventTiming::Create` 或 `PerformanceEventTiming::CreateFirstInputTiming` 方法会被调用，以记录事件的时序信息。这通常发生在事件开始处理之前或之后。
6. **JavaScript 事件监听器被执行:** 如果有与该事件关联的 JavaScript 事件监听器，它们会被执行。
7. **事件处理完成:**  浏览器完成与该事件相关的处理，包括执行 JavaScript 代码和可能的页面渲染更新。
8. **`PerformanceEventTiming` 对象记录处理时间和呈现时间:**  在事件处理的不同阶段，会更新 `PerformanceEventTiming` 对象中的 `processingStart_`, `processingEnd_`, `reporting_info_.presentation_time` 等成员变量。
9. **开发者可以使用 Performance API 查看事件时序信息:**  开发者可以通过在浏览器的开发者工具中输入 `performance.getEntriesByType('event')` 或 `performance.getEntriesByType('first-input')` 来查看 `PerformanceEventTiming` 对象记录的信息，从而分析页面性能。

**作为调试线索:**

当开发者遇到网页交互响应缓慢的问题时，`PerformanceEventTiming` 提供的数据可以作为重要的调试线索：

- **高 `processingEnd - processingStart` 值:**  表明 JavaScript 事件处理函数执行时间过长，可能是性能瓶颈所在。
- **较大的 `processingStart - startTime` 值:**  可能表示事件在被处理前等待了较长时间，例如主线程被其他任务阻塞。
- **`first-input` 类型的 `PerformanceEventTiming` 对象:** 可以帮助定位导致首次输入延迟的问题，例如页面加载时执行了大量的 JavaScript 代码。
- **`interactionId` 的使用:** 可以帮助追踪一系列相关的用户交互，例如用户点击一个按钮后触发的一系列操作的耗时。

总而言之，`PerformanceEventTiming.cc` 文件是 Chromium Blink 引擎中负责记录和管理用户交互事件性能数据的关键组件，它为 Web Performance API 提供了底层实现，并为开发者进行性能分析和优化提供了重要的数据支持。

### 提示词
```
这是目录为blink/renderer/core/timing/performance_event_timing.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/performance_event_timing.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"

namespace blink {

// static
PerformanceEventTiming* PerformanceEventTiming::Create(
    const AtomicString& event_type,
    EventTimingReportingInfo reporting_info,
    bool cancelable,
    Node* target,
    DOMWindow* source) {
  CHECK(source);
  return MakeGarbageCollected<PerformanceEventTiming>(
      event_type, performance_entry_names::kEvent, std::move(reporting_info),
      cancelable, target, source);
}

// static
PerformanceEventTiming* PerformanceEventTiming::CreateFirstInputTiming(
    PerformanceEventTiming* entry) {
  PerformanceEventTiming* first_input =
      MakeGarbageCollected<PerformanceEventTiming>(
          entry->name(), performance_entry_names::kFirstInput,
          *entry->GetEventTimingReportingInfo(), entry->cancelable(),
          entry->target(), entry->source());
  first_input->SetDuration(entry->duration_);
  if (entry->HasKnownInteractionID()) {
    first_input->SetInteractionIdAndOffset(entry->interactionId(),
                                           entry->interactionOffset());
  }
  return first_input;
}

PerformanceEventTiming::PerformanceEventTiming(
    const AtomicString& event_type,
    const AtomicString& entry_type,
    EventTimingReportingInfo reporting_info,
    bool cancelable,
    Node* target,
    DOMWindow* source)
    : PerformanceEntry(
          event_type,
          DOMWindowPerformance::performance(*source->ToLocalDOMWindow())
              ->MonotonicTimeToDOMHighResTimeStamp(
                  reporting_info.creation_time),
          0.0,
          source),
      entry_type_(entry_type),
      cancelable_(cancelable),
      target_(target),
      reporting_info_(reporting_info) {}

PerformanceEventTiming::~PerformanceEventTiming() = default;

PerformanceEntryType PerformanceEventTiming::EntryTypeEnum() const {
  return entry_type_ == performance_entry_names::kEvent
             ? PerformanceEntry::EntryType::kEvent
             : PerformanceEntry::EntryType::kFirstInput;
}

DOMHighResTimeStamp PerformanceEventTiming::processingStart() const {
  if (!processing_start_) {
    processing_start_ =
        DOMWindowPerformance::performance(*source()->ToLocalDOMWindow())
            ->MonotonicTimeToDOMHighResTimeStamp(
                reporting_info_.processing_start_time);
  }
  return processing_start_;
}

DOMHighResTimeStamp PerformanceEventTiming::processingEnd() const {
  if (!processing_end_) {
    processing_end_ =
        DOMWindowPerformance::performance(*source()->ToLocalDOMWindow())
            ->MonotonicTimeToDOMHighResTimeStamp(
                reporting_info_.processing_end_time);
  }
  return processing_end_;
}

Node* PerformanceEventTiming::target() const {
  return Performance::CanExposeNode(target_) ? target_ : nullptr;
}

void PerformanceEventTiming::SetTarget(Node* target) {
  target_ = target;
}

uint32_t PerformanceEventTiming::interactionId() const {
  if (reporting_info_.prevent_counting_as_interaction) {
    return 0u;
  }
  return interaction_id_.value_or(0);
}

void PerformanceEventTiming::SetInteractionId(uint32_t interaction_id) {
  interaction_id_ = interaction_id;
}

bool PerformanceEventTiming::HasKnownInteractionID() const {
  return interaction_id_.has_value();
}

bool PerformanceEventTiming::HasKnownEndTime() const {
  return reporting_info_.presentation_time.has_value() ||
         reporting_info_.fallback_time.has_value();
}

base::TimeTicks PerformanceEventTiming::GetEndTime() const {
  CHECK(HasKnownEndTime());
  if (reporting_info_.fallback_time.has_value()) {
    return reporting_info_.fallback_time.value();
  }
  return reporting_info_.presentation_time.value();
}

uint32_t PerformanceEventTiming::interactionOffset() const {
  return interaction_offset_;
}

void PerformanceEventTiming::SetInteractionIdAndOffset(
    uint32_t interaction_id,
    uint32_t interaction_offset) {
  interaction_id_ = interaction_id;
  interaction_offset_ = interaction_offset;
}

void PerformanceEventTiming::SetDuration(double duration) {
  // TODO(npm): enable this DCHECK once https://crbug.com/852846 is fixed.
  // DCHECK_LE(0, duration);
  duration_ = duration;
}

void PerformanceEventTiming::BuildJSONValue(V8ObjectBuilder& builder) const {
  PerformanceEntry::BuildJSONValue(builder);
  builder.AddInteger("interactionId", interactionId());
  builder.AddNumber("processingStart", processingStart());
  builder.AddNumber("processingEnd", processingEnd());
  builder.AddBoolean("cancelable", cancelable_);
}

void PerformanceEventTiming::Trace(Visitor* visitor) const {
  PerformanceEntry::Trace(visitor);
  visitor->Trace(target_);
}

namespace {
perfetto::protos::pbzero::EventTiming::EventType GetEventType(
    const AtomicString& name) {
  using ProtoType = perfetto::protos::pbzero::EventTiming::EventType;
  if (name == event_type_names::kAuxclick) {
    return ProtoType::AUX_CLICK_EVENT;
  }
  if (name == event_type_names::kClick) {
    return ProtoType::CLICK_EVENT;
  }
  if (name == event_type_names::kContextmenu) {
    return ProtoType::CONTEXT_MENU_EVENT;
  }
  if (name == event_type_names::kDblclick) {
    return ProtoType::DOUBLE_CLICK_EVENT;
  }
  if (name == event_type_names::kMousedown) {
    return ProtoType::MOUSE_DOWN_EVENT;
  }
  if (name == event_type_names::kMouseenter) {
    return ProtoType::MOUSE_ENTER_EVENT;
  }
  if (name == event_type_names::kMouseleave) {
    return ProtoType::MOUSE_LEAVE_EVENT;
  }
  if (name == event_type_names::kMouseout) {
    return ProtoType::MOUSE_OUT_EVENT;
  }
  if (name == event_type_names::kMouseover) {
    return ProtoType::MOUSE_OVER_EVENT;
  }
  if (name == event_type_names::kMouseup) {
    return ProtoType::MOUSE_UP_EVENT;
  }
  if (name == event_type_names::kPointerover) {
    return ProtoType::POINTER_OVER_EVENT;
  }
  if (name == event_type_names::kPointerenter) {
    return ProtoType::POINTER_ENTER_EVENT;
  }
  if (name == event_type_names::kPointerdown) {
    return ProtoType::POINTER_DOWN_EVENT;
  }
  if (name == event_type_names::kPointerup) {
    return ProtoType::POINTER_UP_EVENT;
  }
  if (name == event_type_names::kPointercancel) {
    return ProtoType::POINTER_CANCEL_EVENT;
  }
  if (name == event_type_names::kPointerout) {
    return ProtoType::POINTER_OUT_EVENT;
  }
  if (name == event_type_names::kPointerleave) {
    return ProtoType::POINTER_LEAVE_EVENT;
  }
  if (name == event_type_names::kGotpointercapture) {
    return ProtoType::GOT_POINTER_CAPTURE_EVENT;
  }
  if (name == event_type_names::kLostpointercapture) {
    return ProtoType::LOST_POINTER_CAPTURE_EVENT;
  }
  if (name == event_type_names::kTouchstart) {
    return ProtoType::TOUCH_START_EVENT;
  }
  if (name == event_type_names::kTouchend) {
    return ProtoType::TOUCH_END_EVENT;
  }
  if (name == event_type_names::kTouchcancel) {
    return ProtoType::TOUCH_CANCEL_EVENT;
  }
  if (name == event_type_names::kKeydown) {
    return ProtoType::KEY_DOWN_EVENT;
  }
  if (name == event_type_names::kKeypress) {
    return ProtoType::KEY_PRESS_EVENT;
  }
  if (name == event_type_names::kKeyup) {
    return ProtoType::KEY_UP_EVENT;
  }
  if (name == event_type_names::kBeforeinput) {
    return ProtoType::BEFORE_INPUT_EVENT;
  }
  if (name == event_type_names::kInput) {
    return ProtoType::INPUT_EVENT;
  }
  if (name == event_type_names::kCompositionstart) {
    return ProtoType::COMPOSITION_START_EVENT;
  }
  if (name == event_type_names::kCompositionupdate) {
    return ProtoType::COMPOSITION_UPDATE_EVENT;
  }
  if (name == event_type_names::kCompositionend) {
    return ProtoType::COMPOSITION_END_EVENT;
  }
  if (name == event_type_names::kDragstart) {
    return ProtoType::DRAG_START_EVENT;
  }
  if (name == event_type_names::kDragend) {
    return ProtoType::DRAG_END_EVENT;
  }
  if (name == event_type_names::kDragenter) {
    return ProtoType::DRAG_ENTER_EVENT;
  }
  if (name == event_type_names::kDragleave) {
    return ProtoType::DRAG_LEAVE_EVENT;
  }
  if (name == event_type_names::kDragover) {
    return ProtoType::DRAG_OVER_EVENT;
  }
  if (name == event_type_names::kDrop) {
    return ProtoType::DROP_EVENT;
  }
  return ProtoType::UNDEFINED;
}
}  // namespace

void PerformanceEventTiming::SetPerfettoData(
    Frame* frame,
    perfetto::protos::pbzero::EventTiming* event_timing,
    base::TimeTicks time_origin) {
  event_timing->set_type(GetEventType(name()));
  event_timing->set_cancelable(cancelable());
  if (HasKnownInteractionID()) {
    event_timing->set_interaction_id(interactionId());
    event_timing->set_interaction_offset(interactionOffset());
  }
  event_timing->set_node_id(target_ ? target_->GetDomNodeId()
                                    : kInvalidDOMNodeId);
  event_timing->set_frame(GetFrameIdForTracing(frame).Ascii());
  if (reporting_info_.fallback_time.has_value()) {
    event_timing->set_fallback_time_us(
        (reporting_info_.fallback_time.value() - time_origin).InMicroseconds());
  }
  if (reporting_info_.key_code.has_value()) {
    event_timing->set_key_code(reporting_info_.key_code.value());
  }
  if (reporting_info_.pointer_id.has_value()) {
    event_timing->set_pointer_id(reporting_info_.pointer_id.value());
  }
}

// TODO(sullivan): Remove this deprecated data when DevTools migrates to the
// perfetto events.
std::unique_ptr<TracedValue> PerformanceEventTiming::ToTracedValue(
    Frame* frame) const {
  auto traced_value = std::make_unique<TracedValue>();
  traced_value->SetString("type", name());
  // Recalculate this as the stored duration value is rounded.
  traced_value->SetDouble(
      "duration",
      (GetEndTime() - reporting_info_.creation_time).InMillisecondsF());
  traced_value->SetBoolean("cancelable", cancelable());
  // If int overflows occurs, the static_cast may not work correctly.
  traced_value->SetInteger("interactionId", static_cast<int>(interactionId()));
  traced_value->SetInteger("interactionOffset",
                           static_cast<int>(interactionOffset()));
  traced_value->SetInteger(
      "nodeId", target_ ? target_->GetDomNodeId() : kInvalidDOMNodeId);
  traced_value->SetString("frame", GetFrameIdForTracing(frame));
  if (!source() || !source()->IsLocalDOMWindow()) {
    // Only report timing data if there is a valid source window to base the
    // origin time on.
    return traced_value;
  }
  base::TimeTicks origin_time =
      WindowPerformance::GetTimeOrigin(To<LocalDOMWindow>(source()));
  traced_value->SetDouble(
      "timeStamp",
      (reporting_info_.creation_time - origin_time).InMillisecondsF());
  traced_value->SetDouble(
      "processingStart",
      (reporting_info_.processing_start_time - origin_time).InMillisecondsF());
  traced_value->SetDouble(
      "processingEnd",
      (reporting_info_.processing_end_time - origin_time).InMillisecondsF());
  traced_value->SetDouble(
      "enqueuedToMainThreadTime",
      (reporting_info_.enqueued_to_main_thread_time - origin_time)
          .InMillisecondsF());

  if (reporting_info_.commit_finish_time.has_value()) {
    traced_value->SetDouble(
        "commitFinishTime",
        (reporting_info_.commit_finish_time.value() - origin_time)
            .InMillisecondsF());
  }
  return traced_value;
}

}  // namespace blink
```