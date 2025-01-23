Response:
Let's break down the thought process for analyzing the `event_dispatcher.cc` file. The goal is to understand its functionality and its relationships to web technologies.

**1. Initial Skim and Keyword Identification:**

The first step is to quickly read through the code, looking for familiar keywords and patterns. This helps establish a basic understanding of the file's purpose. Some key observations from a quick skim include:

* **`EventDispatcher` class:** This is clearly the central element.
* **`DispatchEvent` methods:**  Indicates the core functionality of sending events.
* **Event types (e.g., `kClick`, `kMousedown`, `kKeyup`, `kChange`):**  Relates to standard DOM events.
* **`Node`, `Element`, `Document`, `Window`:** These are fundamental DOM concepts.
* **`JavaScript`, `HTML`, `CSS` (implicitly):**  Since it deals with DOM events, it must interact with how these technologies work.
* **`SimulatedClick`:**  Suggests programmatic event triggering.
* **`Capturing Phase`, `Bubbling Phase`:**  Key concepts in DOM event propagation.
* **`DefaultEventHandler`:** Hints at the browser's default actions for events.
* **`Trusted` events:**  Distinguishes between user-initiated and script-initiated events.
* **`PreventDefault`:**  A standard way to stop default browser actions.
* **Includes (`#include`):**  Provides clues about dependencies and related functionality (e.g., `keyboard_event.h`, `mouse_event.h`, `html_input_element.h`).

**2. Focus on Core Functionality: `DispatchEvent`:**

The `DispatchEvent` methods are the entry points. The main `DispatchEvent(Node& node, Event& event)` is a static method, suggesting a common way to trigger event dispatch. The instance method `Dispatch()` contains the core logic of the event dispatching process.

**3. Analyze the Event Dispatching Process (within `Dispatch()`):**

This is where the bulk of the analysis lies. I'd follow the code flow within the `Dispatch()` method, commenting mentally or physically on each section:

* **Trace Event:**  For performance monitoring.
* **Empty Event Path Check:**  Handles cases where retargeting has removed the event path.
* **Event Timing:**  For performance measurement related to events.
* **Layout Shift Tracker:**  Specific to the `change` event, indicating interaction with layout stability.
* **Event Path Context:** Ensures proper setup for event handling.
* **Soft Navigation Heuristics:**  Related to tracking user navigation patterns.
* **Ad Click Tracking:**  Specific to click events in ad frames.
* **Activation Target:**  Determines the element that "activates" on a click or similar event.
* **Setting Target:**  Ensures the correct target for the event.
* **`DispatchEventPreProcess`:**  Handles actions before the main dispatching (e.g., `PreDispatchEventHandler`).
* **`DispatchEventAtCapturing`:** Implements the capturing phase of event propagation. Note the loop iterating *down* the tree.
* **`DispatchEventAtBubbling`:** Implements the bubbling phase, iterating *up* the tree.
* **`DispatchEventPostProcess`:**  Handles actions after the main dispatching (e.g., resetting flags, invoking default handlers, `PostDispatchEventHandler`).

**4. Identify Relationships with Web Technologies:**

As the analysis of `Dispatch()` progresses, connections to JavaScript, HTML, and CSS become clear:

* **JavaScript:**  The event handlers called during capturing and bubbling are often JavaScript functions attached to DOM elements. The ability to `preventDefault()` directly affects JavaScript's control over the browser's behavior.
* **HTML:** The code interacts with specific HTML elements like `HTMLInputElement` and `HTMLSelectElement`, and the concept of "activation behavior" is tied to interactive HTML elements.
* **CSS:**  While not directly manipulated, the `LayoutShiftTracker` interaction with the `change` event suggests an indirect link. Changes to form elements can trigger layout shifts.

**5. Consider Edge Cases and Potential Errors:**

* **Infinite Recursion in `DispatchSimulatedClick`:** The comment about the `nodes_dispatching_simulated_clicks` set directly addresses a potential programming error.
* **`preventDefault()` and Default Actions:**  Misunderstanding how `preventDefault()` works is a common developer error. The code implicitly handles this.
* **Event Order and Propagation:** Developers sometimes misunderstand the capturing and bubbling phases, leading to unexpected event handling.

**6. Construct Examples and Scenarios:**

To solidify understanding and illustrate the relationships, concrete examples are crucial. This involves creating hypothetical HTML structures and JavaScript code snippets to demonstrate how events are dispatched and handled. Thinking about different user interactions (clicks, keyboard input, etc.) and how they lead to event dispatch helps.

**7. Debugging Perspective:**

The prompt specifically asks about debugging. Thinking about how a developer might trace an event through the system helps. Key points include:

* User action triggers a low-level event.
* This event is translated into a DOM event.
* `EventDispatcher::DispatchEvent` is the entry point.
* Stepping through the `Dispatch()` method reveals the propagation phases and handler execution.

**Self-Correction/Refinement during the process:**

* **Initial Over-Simplification:**  At first glance, it's easy to think "this just sends events."  However, digging into `Dispatch()` reveals the complexity of the capturing/bubbling phases, default handling, and interactions with other browser components.
* **Specificity of Examples:**  Generic examples are less helpful than specific ones that illustrate particular aspects (e.g., the difference between capturing and bubbling).
* **Connecting Code to Concepts:** It's important not just to describe *what* the code does, but *why* it does it in the context of DOM events and web standards.

By following these steps, a comprehensive understanding of the `event_dispatcher.cc` file can be achieved, along with clear explanations and relevant examples.
好的，我们来详细分析 `blink/renderer/core/dom/events/event_dispatcher.cc` 这个文件。

**文件功能概述：**

`event_dispatcher.cc` 文件是 Chromium Blink 渲染引擎中处理 DOM 事件的核心组件。它的主要职责是：

1. **接收和启动事件分发：**  当一个 DOM 事件（例如，鼠标点击、键盘按下等）发生时，这个文件中的 `EventDispatcher` 类负责接收该事件，并启动整个事件分发流程。
2. **管理事件传播的各个阶段：**  DOM 事件传播分为捕获阶段（Capturing Phase）、目标阶段（At Target Phase）和冒泡阶段（Bubbling Phase）。`EventDispatcher` 负责按照规范管理事件在这三个阶段的传播路径和处理顺序。
3. **调用事件监听器：** 在事件传播的各个阶段，`EventDispatcher` 会查找并调用注册在该事件目标或其祖先节点上的相应事件监听器（通常是 JavaScript 代码）。
4. **处理事件的默认行为：**  对于某些事件，浏览器有默认的行为（例如，点击链接会跳转页面，提交表单会发送数据）。`EventDispatcher` 负责在适当的时候触发这些默认行为，除非事件监听器调用了 `preventDefault()` 方法阻止了默认行为。
5. **处理模拟事件：**  该文件还包含了处理模拟事件的逻辑，例如通过无障碍功能触发的点击事件。
6. **管理事件相关的性能指标：**  例如，记录事件发生的时间，用于性能分析和优化。

**与 JavaScript, HTML, CSS 的关系：**

`EventDispatcher` 是 Blink 引擎连接 HTML 结构、CSS 样式和 JavaScript 行为的关键桥梁。

* **HTML:** `EventDispatcher` 处理的事件都发生在 HTML 元素上。它会根据 HTML 元素的层级结构来确定事件传播的路径。例如，点击一个按钮，事件会从 `<body>` 元素开始捕获，到达按钮元素，然后在按钮元素上冒泡回 `<body>`。
* **JavaScript:**  `EventDispatcher` 的主要作用之一就是执行 JavaScript 中注册的事件监听器。开发者通过 JavaScript 的 `addEventListener` 方法将函数注册为特定元素的特定事件的监听器。当事件发生时，`EventDispatcher` 会找到这些监听器并执行它们。
    * **举例 (JavaScript):**
      ```javascript
      const button = document.getElementById('myButton');
      button.addEventListener('click', function(event) {
        console.log('Button clicked!');
        event.preventDefault(); // 阻止按钮的默认行为（通常是提交表单）
      });
      ```
      在这个例子中，当按钮被点击时，`EventDispatcher` 会接收到 `click` 事件，并执行这个 JavaScript 函数。`event.preventDefault()` 的调用会影响 `EventDispatcher` 后续对该事件默认行为的处理。
* **CSS:**  虽然 `EventDispatcher` 不直接处理 CSS，但 CSS 的某些特性会影响事件的行为。例如：
    * **`pointer-events` CSS 属性:**  可以控制元素是否可以成为鼠标事件的目标。`EventDispatcher` 在确定事件目标时会考虑这个属性。
    * **CSS 伪类（例如 `:hover`, `:active`):**  这些伪类的状态变化可能会触发 JavaScript 事件，例如鼠标悬停在一个元素上会触发 `mouseover` 事件，而这些事件会经过 `EventDispatcher` 的处理。

**逻辑推理、假设输入与输出：**

假设用户在浏览器中点击了一个链接 `<a>` 元素。

**假设输入:**

* **事件类型:** `click`
* **事件目标节点:**  该 `<a>` 元素
* **当前 DOM 树结构:**  包含该 `<a>` 元素及其祖先元素
* **注册的事件监听器:** 可能在该 `<a>` 元素及其祖先元素上注册了 `click` 事件的监听器。

**逻辑推理过程:**

1. **事件捕获阶段:** `EventDispatcher` 从文档根节点开始，沿着 DOM 树向下遍历，查找是否有注册了捕获阶段 `click` 事件监听器的元素。如果有，则执行这些监听器。
2. **目标阶段:**  事件到达目标节点（`<a>` 元素）。`EventDispatcher` 执行在该元素上注册的 `click` 事件监听器，无论这些监听器是注册在捕获阶段还是冒泡阶段。
3. **事件冒泡阶段:** `EventDispatcher` 从目标节点开始，沿着 DOM 树向上遍历，查找是否有注册了冒泡阶段 `click` 事件监听器的元素。如果有，则执行这些监听器。
4. **默认行为处理:**  如果没有任何监听器调用 `event.preventDefault()`，`EventDispatcher` 会触发链接的默认行为，即导航到 `<a>` 元素的 `href` 属性指定的 URL。

**假设输出:**

* 如果没有 `preventDefault()` 调用，浏览器会跳转到链接的 URL。
* 如果有监听器调用了 `preventDefault()`，则浏览器不会跳转，链接的默认行为被阻止。
* 控制台中可能会打印出由事件监听器输出的日志信息。

**用户或编程常见的使用错误：**

1. **忘记调用 `preventDefault()` 阻止默认行为:**  开发者可能期望通过 JavaScript 完全控制事件的行为，但忘记调用 `preventDefault()`，导致浏览器的默认行为仍然发生，例如表单被提交，链接被跳转。
    * **举例:**  一个开发者想要在用户点击链接后执行一些 JavaScript 代码，但不希望页面跳转。如果他们只注册了事件监听器，而没有调用 `event.preventDefault()`，页面仍然会跳转。
2. **对事件传播阶段理解不足:**  开发者可能在错误的阶段注册了监听器，导致监听器没有按预期执行。例如，如果开发者希望在目标元素接收到事件之前进行处理，应该在捕获阶段注册监听器。
3. **事件冒泡导致意外行为:**  开发者可能没有意识到事件会冒泡到父元素，导致父元素的事件监听器也被触发，产生意外的结果。
    * **举例:**  一个列表中每个列表项都有一个删除按钮。开发者可能只在按钮上注册了点击事件监听器，但如果父元素（列表本身）也有点击事件监听器，点击按钮时父元素的监听器也会被触发。
4. **在事件监听器中修改 DOM 结构导致问题:**  在事件处理过程中修改 DOM 结构可能会导致事件传播路径的变化，甚至引发错误。

**用户操作如何一步步到达 `event_dispatcher.cc` 作为调试线索：**

假设用户点击了一个网页上的按钮，我们想要追踪这个点击事件是如何被 `event_dispatcher.cc` 处理的：

1. **用户操作 (鼠标点击):**  用户将鼠标指针移动到按钮上，并按下鼠标左键，然后释放。
2. **操作系统捕获事件:**  操作系统 (例如 Windows, macOS) 捕获到鼠标事件。
3. **浏览器进程接收事件:** 浏览器的渲染进程接收到操作系统传递的鼠标事件信息。
4. **浏览器将操作系统事件转换为 Blink 事件:**  浏览器将操作系统级别的鼠标事件转换为 Blink 引擎内部的 `WebMouseEvent` 或类似的事件对象。
5. **事件被路由到正确的 Frame 或 Document:**  根据鼠标点击的位置，事件被路由到相应的渲染帧 (Frame) 或文档 (Document)。
6. **创建 DOM 事件对象:**  Blink 引擎根据 `WebMouseEvent` 创建一个 DOM 级别的 `MouseEvent` 对象。
7. **`EventDispatcher::DispatchEvent` 被调用:**  在确定了事件目标节点后，`EventDispatcher::DispatchEvent` 静态方法会被调用，传入目标节点和创建的 `MouseEvent` 对象。这是进入 `event_dispatcher.cc` 的关键入口点。
8. **`EventDispatcher` 对象创建和初始化:**  在 `DispatchEvent` 内部，会创建一个 `EventDispatcher` 对象，并进行初始化，包括设置事件传播路径等。
9. **事件传播和监听器调用:**  `EventDispatcher::Dispatch()` 方法会被调用，负责执行事件的捕获、目标和冒泡阶段，并调用相应的 JavaScript 事件监听器。
10. **默认行为处理:** 如果没有 `preventDefault()`，`EventDispatcher` 会触发事件的默认行为。

**调试线索:**

* **在 Blink 源码中设置断点:**  在 `event_dispatcher.cc` 的关键函数（例如 `DispatchEvent`, `Dispatch`, 事件传播阶段的处理函数等）设置断点。
* **使用浏览器开发者工具的 "Event Listener Breakpoints":**  Chrome 开发者工具允许你在特定类型的事件发生时暂停 JavaScript 执行，这可以帮助你追踪事件处理的起始点。
* **查看事件的 `target` 和 `currentTarget` 属性:**  在事件监听器中打印 `event.target` 和 `event.currentTarget` 可以帮助你理解事件传播的路径。
* **使用 `console.log` 或调试器在事件监听器中观察变量:**  查看事件对象本身的信息，以及相关 DOM 元素的状态。
* **阅读 Blink 源码:**  深入理解 `event_dispatcher.cc` 以及相关的事件处理代码可以帮助你更准确地定位问题。

希望以上分析能够帮助你理解 `blink/renderer/core/dom/events/event_dispatcher.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/dom/events/event_dispatcher.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/dom/events/event_dispatcher.h"

#include <optional>

#include "base/feature_list.h"
#include "base/memory/scoped_refptr.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_result.h"
#include "third_party/blink/renderer/core/dom/events/event_path.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/events/window_event_context.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/simulated_event_util.h"
#include "third_party/blink/renderer/core/events/text_event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/ad_tracker.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"
#include "third_party/blink/renderer/core/timing/event_timing.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "ui/events/keycodes/dom/keycode_converter.h"
namespace blink {

DispatchEventResult EventDispatcher::DispatchEvent(Node& node, Event& event) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
               "EventDispatcher::dispatchEvent");
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  EventDispatcher dispatcher(node, event);
  return event.DispatchEvent(dispatcher);
}

EventDispatcher::EventDispatcher(Node& node, Event& event)
    : node_(&node), event_(&event) {
  view_ = node.GetDocument().View();
  event_->InitEventPath(*node_);
}

void EventDispatcher::DispatchScopedEvent(Node& node, Event& event) {
  // We need to set the target here because it can go away by the time we
  // actually fire the event.
  event.SetTarget(&EventPath::EventTargetRespectingTargetRules(node));
  ScopedEventQueue::Instance()->EnqueueEvent(event);
}

void EventDispatcher::DispatchSimulatedClick(
    Node& node,
    const Event* underlying_event,
    SimulatedClickCreationScope creation_scope) {
  // This persistent vector doesn't cause leaks, because added Nodes are removed
  // before dispatchSimulatedClick() returns. This vector is here just to
  // prevent the code from running into an infinite recursion of
  // dispatchSimulatedClick().
  DEFINE_STATIC_LOCAL(Persistent<HeapHashSet<Member<Node>>>,
                      nodes_dispatching_simulated_clicks,
                      (MakeGarbageCollected<HeapHashSet<Member<Node>>>()));

  if (IsDisabledFormControl(&node))
    return;

  if (nodes_dispatching_simulated_clicks->Contains(&node))
    return;

  nodes_dispatching_simulated_clicks->insert(&node);

  Element* element = DynamicTo<Element>(node);
  bool prevent_mouse_events = false;

  if (creation_scope == SimulatedClickCreationScope::kFromAccessibility) {
    DispatchEventResult dispatch_result =
        EventDispatcher(node, *SimulatedEventUtil::CreateEvent(
                                  event_type_names::kPointerdown, node,
                                  underlying_event, creation_scope))
            .Dispatch();
    prevent_mouse_events =
        dispatch_result == DispatchEventResult::kCanceledByEventHandler;
    if (!prevent_mouse_events) {
      EventDispatcher(node, *SimulatedEventUtil::CreateEvent(
                                event_type_names::kMousedown, node,
                                underlying_event, creation_scope))
          .Dispatch();
    }
    if (element)
      element->SetActive(true);
    EventDispatcher(node, *SimulatedEventUtil::CreateEvent(
                              event_type_names::kPointerup, node,
                              underlying_event, creation_scope))
        .Dispatch();
    if (!prevent_mouse_events) {
      EventDispatcher(node, *SimulatedEventUtil::CreateEvent(
                                event_type_names::kMouseup, node,
                                underlying_event, creation_scope))
          .Dispatch();
    }
  }
  // Some elements (e.g. the color picker) may set active state to true before
  // calling this method and expect the state to be reset during the call.
  if (element)
    element->SetActive(false);

  // Always send click.
  EventDispatcher(
      node, *SimulatedEventUtil::CreateEvent(event_type_names::kClick, node,
                                             underlying_event, creation_scope))
      .Dispatch();

  nodes_dispatching_simulated_clicks->erase(&node);
}

void EventDispatcher::DispatchSimulatedEnterEvent(
    HTMLInputElement& input_element) {
  LocalDOMWindow* local_dom_window = input_element.GetDocument().domWindow();
  for (auto type : {WebInputEvent::Type::kRawKeyDown,
                    WebInputEvent::Type::kChar, WebInputEvent::Type::kKeyUp}) {
    WebKeyboardEvent enter{type, WebInputEvent::kNoModifiers,
                           base::TimeTicks::Now()};
    enter.dom_key = ui::DomKey::ENTER;
    enter.dom_code = static_cast<int>(ui::DomKey::ENTER);
    enter.native_key_code = blink::VKEY_RETURN;
    enter.windows_key_code = blink::VKEY_RETURN;
    enter.text[0] = blink::VKEY_RETURN;
    enter.unmodified_text[0] = blink::VKEY_RETURN;

    KeyboardEvent* event =
        blink::KeyboardEvent::Create(enter, local_dom_window, true);
    event->SetTrusted(true);
    DispatchScopedEvent(input_element, *event);
  }
}

// https://dom.spec.whatwg.org/#dispatching-events
DispatchEventResult EventDispatcher::Dispatch() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
               "EventDispatcher::dispatch");

#if DCHECK_IS_ON()
  DCHECK(!event_dispatched_);
  event_dispatched_ = true;
#endif
  if (GetEvent().GetEventPath().IsEmpty()) {
    // eventPath() can be empty if relatedTarget retargeting has shrunk the
    // path.
    return DispatchEventResult::kNotCanceled;
  }
  std::optional<EventTiming> eventTiming;
  auto& document = node_->GetDocument();
  LocalFrame* frame = document.GetFrame();
  LocalDOMWindow* window = nullptr;
  if (frame) {
    window = frame->DomWindow();
  }

  if (frame && window) {
    eventTiming = EventTiming::TryCreate(window, *event_, event_->target());
  }

  if (event_->type() == event_type_names::kChange && event_->isTrusted() &&
      view_) {
    view_->GetLayoutShiftTracker().NotifyChangeEvent();
  }
  event_->GetEventPath().EnsureWindowEventContext();

  const bool is_click =
      event_->IsMouseEvent() && event_->type() == event_type_names::kClick;

  std::optional<SoftNavigationHeuristics::EventScope> soft_navigation_scope;
  if (window) {
    if (auto* heuristics = SoftNavigationHeuristics::From(*window)) {
      soft_navigation_scope =
          heuristics->MaybeCreateEventScopeForEvent(*event_);
    }
  }

  if (is_click && event_->isTrusted() && frame) {
    // A genuine mouse click cannot be triggered by script so we don't expect
    // there are any script in the stack.
    DCHECK(!frame->GetAdTracker() || !frame->GetAdTracker()->IsAdScriptInStack(
                                         AdTracker::StackType::kBottomAndTop));
    if (frame->IsAdFrame()) {
      UseCounter::Count(document, WebFeature::kAdClick);
    }
  }

  // 6. Let isActivationEvent be true, if event is a MouseEvent object and
  // event's type attribute is "click", and false otherwise.
  //
  // We need to include non-standard textInput event for HTMLInputElement.
  const bool is_activation_event =
      is_click || event_->type() == event_type_names::kTextInput;

  // 7. Let activationTarget be target, if isActivationEvent is true and target
  // has activation behavior, and null otherwise.
  Node* activation_target =
      is_activation_event && node_->HasActivationBehavior() ? node_ : nullptr;

  // A part of step 9 loop.
  if (is_activation_event && !activation_target && event_->bubbles()) {
    wtf_size_t size = event_->GetEventPath().size();
    for (wtf_size_t i = 1; i < size; ++i) {
      Node& target = event_->GetEventPath()[i].GetNode();
      if (target.HasActivationBehavior()) {
        activation_target = &target;
        break;
      }
    }
  }

  event_->SetTarget(&EventPath::EventTargetRespectingTargetRules(*node_));
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  DCHECK(event_->target());
  DEVTOOLS_TIMELINE_TRACE_EVENT("EventDispatch",
                                inspector_event_dispatch_event::Data, *event_,
                                document.GetAgent().isolate());
  EventDispatchHandlingState* pre_dispatch_event_handler_result = nullptr;
  if (DispatchEventPreProcess(activation_target,
                              pre_dispatch_event_handler_result) ==
      kContinueDispatching) {
    if (DispatchEventAtCapturing() == kContinueDispatching) {
      DispatchEventAtBubbling();
    }
  }
  DispatchEventPostProcess(activation_target,
                           pre_dispatch_event_handler_result);

  auto result = EventTarget::GetDispatchEventResult(*event_);

  return result;
}

inline EventDispatchContinuation EventDispatcher::DispatchEventPreProcess(
    Node* activation_target,
    EventDispatchHandlingState*& pre_dispatch_event_handler_result) {
  // 11. If activationTarget is non-null and activationTarget has
  // legacy-pre-activation behavior, then run activationTarget's
  // legacy-pre-activation behavior.
  if (activation_target) {
    pre_dispatch_event_handler_result =
        activation_target->PreDispatchEventHandler(*event_);
  }

  return (event_->GetEventPath().IsEmpty() || event_->PropagationStopped())
             ? kDoneDispatching
             : kContinueDispatching;
}

inline EventDispatchContinuation EventDispatcher::DispatchEventAtCapturing() {
  // Trigger capturing event handlers, starting at the top and working our way
  // down. When we get to the last one, the target, change the event phase to
  // AT_TARGET and fire only the capture listeners on it.
  event_->SetEventPhase(Event::PhaseType::kCapturingPhase);

  if (event_->GetEventPath().GetWindowEventContext().HandleLocalEvents(
          *event_) &&
      event_->PropagationStopped())
    return kDoneDispatching;

  for (wtf_size_t i = event_->GetEventPath().size(); i > 0; --i) {
    const NodeEventContext& event_context = event_->GetEventPath()[i - 1];
    if (event_context.CurrentTargetSameAsTarget()) {
      event_->SetEventPhase(Event::PhaseType::kAtTarget);
      event_->SetFireOnlyCaptureListenersAtTarget(true);
      event_context.HandleLocalEvents(*event_);
      event_->SetFireOnlyCaptureListenersAtTarget(false);
    } else {
      event_->SetEventPhase(Event::PhaseType::kCapturingPhase);
      event_context.HandleLocalEvents(*event_);
    }
    if (event_->PropagationStopped())
      return kDoneDispatching;
  }

  return kContinueDispatching;
}

inline void EventDispatcher::DispatchEventAtBubbling() {
  // Trigger bubbling event handlers, starting at the bottom and working our way
  // up. On the first one, the target, change the event phase to AT_TARGET and
  // fire only the bubble listeners on it.
  wtf_size_t size = event_->GetEventPath().size();
  for (wtf_size_t i = 0; i < size; ++i) {
    const NodeEventContext& event_context = event_->GetEventPath()[i];
    if (event_context.CurrentTargetSameAsTarget()) {
      // TODO(hayato): Need to check cancelBubble() also here?
      event_->SetEventPhase(Event::PhaseType::kAtTarget);
      event_->SetFireOnlyNonCaptureListenersAtTarget(true);
      event_context.HandleLocalEvents(*event_);
      event_->SetFireOnlyNonCaptureListenersAtTarget(false);
    } else if (event_->bubbles() && !event_->cancelBubble()) {
      event_->SetEventPhase(Event::PhaseType::kBubblingPhase);
      event_context.HandleLocalEvents(*event_);
    } else {
      continue;
    }
    if (event_->PropagationStopped())
      return;
  }
  if (event_->bubbles() && !event_->cancelBubble()) {
    event_->SetEventPhase(Event::PhaseType::kBubblingPhase);
    event_->GetEventPath().GetWindowEventContext().HandleLocalEvents(*event_);
  }
}

inline void EventDispatcher::DispatchEventPostProcess(
    Node* activation_target,
    EventDispatchHandlingState* pre_dispatch_event_handler_result) {
  event_->SetTarget(&EventPath::EventTargetRespectingTargetRules(*node_));
  // https://dom.spec.whatwg.org/#concept-event-dispatch
  // 14. Unset event’s dispatch flag, stop propagation flag, and stop immediate
  // propagation flag.
  event_->SetStopPropagation(false);
  event_->SetStopImmediatePropagation(false);
  // 15. Set event’s eventPhase attribute to NONE.
  event_->SetEventPhase(Event::PhaseType::kNone);
  // TODO(rakina): investigate this and move it to the bottom of step 16
  // 17. Set event’s currentTarget attribute to null.
  event_->SetCurrentTarget(nullptr);

  auto* mouse_event = DynamicTo<MouseEvent>(event_);
  bool is_click =
      mouse_event && mouse_event->type() == event_type_names::kClick;
  if (is_click) {
    // Fire an accessibility event indicating a node was clicked on.  This is
    // safe if event_->target()->ToNode() returns null.
    if (AXObjectCache* cache = node_->GetDocument().ExistingAXObjectCache())
      cache->HandleClicked(event_->target()->ToNode());

    // Pass the data from the PreDispatchEventHandler to the
    // PostDispatchEventHandler.
    // This may dispatch an event, and node_ and event_ might be altered.
    if (activation_target) {
      activation_target->PostDispatchEventHandler(
          *event_, pre_dispatch_event_handler_result);
    }
    // TODO(tkent): Is it safe to kick DefaultEventHandler() with such altered
    // event_?
  }

  // The DOM Events spec says that events dispatched by JS (other than "click")
  // should not have their default handlers invoked.
  bool is_trusted_or_click = event_->isTrusted() || is_click;

  // For Android WebView (distinguished by wideViewportQuirkEnabled)
  // enable untrusted events for mouse down on select elements because
  // fastclick.js seems to generate these. crbug.com/642698
  // TODO(dtapuska): Change this to a target SDK quirk crbug.com/643705
  if (!is_trusted_or_click && event_->IsMouseEvent() &&
      event_->type() == event_type_names::kMousedown &&
      IsA<HTMLSelectElement>(*node_)) {
    if (Settings* settings = node_->GetDocument().GetSettings()) {
      is_trusted_or_click = settings->GetWideViewportQuirkEnabled();
    }
  }

  // Call default event handlers. While the DOM does have a concept of
  // preventing default handling, the detail of which handlers are called is an
  // internal implementation detail and not part of the DOM.
  if (!event_->defaultPrevented() && !event_->DefaultHandled() &&
      is_trusted_or_click) {
    // Non-bubbling events call only one default event handler, the one for the
    // target.
    node_->DefaultEventHandler(*event_);
    // For bubbling events, call default event handlers on the same targets in
    // the same order as the bubbling phase.
    if (!event_->DefaultHandled() && !event_->defaultPrevented() &&
        event_->bubbles()) {
      wtf_size_t size = event_->GetEventPath().size();
      for (wtf_size_t i = 1; i < size; ++i) {
        event_->GetEventPath()[i].GetNode().DefaultEventHandler(*event_);
        if (event_->DefaultHandled() || event_->defaultPrevented()) {
          break;
        }
      }
    }
  } else {
#if BUILDFLAG(IS_MAC)
    // If a keypress event is prevented, the cursor position may be out of
    // sync as RenderWidgetHostViewCocoa::insertText assumes that the text
    // has been accepted. See https://crbug.com/1204523 for details.
    if (event_->type() == event_type_names::kKeypress && view_)
      view_->GetFrame().GetEditor().SyncSelection(SyncCondition::kForced);
#endif  // BUILDFLAG(IS_MAC)
  }

  auto* keyboard_event = DynamicTo<KeyboardEvent>(event_);
  if (Page* page = node_->GetDocument().GetPage()) {
    if (page->GetSettings().GetSpatialNavigationEnabled() &&
        is_trusted_or_click && keyboard_event &&
        keyboard_event->key() == keywords::kCapitalEnter &&
        event_->type() == event_type_names::kKeyup) {
      page->GetSpatialNavigationController().ResetEnterKeyState();
    }
  }

  // Track the usage of sending a mousedown event to a select element to force
  // it to open. This measures a possible breakage of not allowing untrusted
  // events to open select boxes.
  if (!event_->isTrusted() && event_->IsMouseEvent() &&
      event_->type() == event_type_names::kMousedown &&
      IsA<HTMLSelectElement>(*node_)) {
    UseCounter::Count(node_->GetDocument(),
                      WebFeature::kUntrustedMouseDownEventDispatchedToSelect);
  }
  // 16. If target's root is a shadow root, then set event's target attribute
  // and event's relatedTarget to null.
  event_->SetTarget(event_->GetEventPath().GetWindowEventContext().Target());
  if (!event_->target())
    event_->SetRelatedTargetIfExists(nullptr);
}

}  // namespace blink
```