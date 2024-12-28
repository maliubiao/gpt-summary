Response:
Let's break down the thought process for analyzing this code snippet and generating the detailed explanation.

**1. Initial Understanding - Context is Key:**

The prompt clearly states this is part 2 of the `blink/renderer/core/dom/events/event_target.cc` file. Part 1 likely dealt with adding event listeners. Knowing this is about event handling in the Blink rendering engine provides crucial context. This immediately suggests the code will deal with:

* Removing event listeners.
* Dispatching events.
* Managing the list of event listeners.
* Interactions with JavaScript event handling.

**2. Decomposition by Function:**

The most logical approach is to go function by function. For each function, I need to understand:

* **Purpose:** What does this function do? What's its core responsibility?
* **Parameters:** What inputs does it take? What are their types?
* **Return Value:** What does it output?  What does the return type signify?
* **Logic:** What are the key steps involved in the function's execution? Are there any important data structures manipulated?
* **Connections to Other Parts:** How does this function relate to other functions in this snippet or potentially in part 1?

**3. Identifying Key Concepts and Data Structures:**

As I go through the functions, I'll identify recurring concepts and data structures:

* **`EventTarget`:**  The core class responsible for handling events.
* **`EventListener`:** Represents a function (often in JavaScript) that should be called when an event occurs.
* **`RegisteredEventListener`:**  A wrapper around `EventListener` that stores additional information like capture phase and `once` option.
* **`EventListenerVector`:**  A container (likely a `std::vector`) holding `RegisteredEventListener` objects.
* **`EventTargetData`:**  A likely internal data structure within `EventTarget` to store the `event_listener_map`.
* **`event_listener_map`:**  A map (likely `std::map` or `WTF::HashMap`) that associates event types (e.g., "click", "mouseover") with their corresponding `EventListenerVector`.
* **`Event`:**  Represents the event object being dispatched.
* **Capture Phase:** The phase of event propagation where listeners on ancestor elements are triggered first.
* **Bubbling Phase:** The phase of event propagation where listeners on the target element and then its ancestors are triggered.
* **`ExecutionContext`:**  Represents the execution environment (e.g., a document's window).
* **`AtomicString`:**  Blink's efficient string class.
* **`DispatchEventResult`:** An enum indicating the outcome of event dispatch.

**4. Connecting to JavaScript, HTML, and CSS:**

Once I understand the functions, I can start making connections to web technologies:

* **JavaScript:** The `EventListener` often originates from JavaScript using `addEventListener` or setting `on...` attributes. The code handles the invocation of these JavaScript functions.
* **HTML:**  HTML elements are the typical `EventTarget` objects. The `on...` attributes in HTML directly correspond to setting attribute event listeners.
* **CSS:** While CSS itself doesn't directly interact with `EventTarget` at this level, CSS animations and transitions trigger events (`transitionend`, `animationstart`, etc.), which this code handles.

**5. Logical Reasoning and Examples:**

For each function, I try to imagine scenarios and provide examples of how it works. This involves:

* **`removeEventListener`:**  Think about removing a listener added earlier. Consider the `useCapture` parameter.
* **`dispatchEvent`:** Imagine a button click. Trace the flow of the event through the `EventTarget`.
* **Attribute Event Listeners:** How do `onclick="..."` attributes get handled?

**6. Common Usage Errors:**

Based on the function signatures and logic, I can identify common mistakes:

* **Mismatched `addEventListener`/`removeEventListener` parameters:** Incorrect event type, listener function, or `useCapture` value.
* **Removing a listener that wasn't added:** `removeEventListener` will return `false`.
* **Incorrectly assuming the order of listener execution:**  The order is generally the order of addition, but the capture/bubbling phases affect this.

**7. Debugging Clues and User Actions:**

I think about how a developer might end up looking at this code during debugging. What user actions would trigger this code path?

* Clicking a button.
* Hovering over an element.
* JavaScript code explicitly calling `dispatchEvent`.
* JavaScript code calling `removeEventListener`.

**8. Structure and Clarity:**

Finally, I organize the information logically, using clear headings and bullet points. I use code snippets to illustrate examples. I aim for a comprehensive yet understandable explanation.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Simplification:** I might initially think a function is simpler than it is. Deeper inspection of the code and variable names helps to uncover nuances (e.g., the handling of legacy event types).
* **Missed Connections:** I might not immediately see the relationship between `SetAttributeEventListener` and HTML attributes. Thinking about the overall event flow helps to make these connections.
* **Ambiguity:** If a function's purpose isn't immediately clear, I'll re-read the code, look at variable names, and consider how it fits into the larger context of event handling. Looking at the surrounding functions can also provide clues.

By following this systematic approach, I can thoroughly analyze the code snippet and generate a comprehensive and informative explanation. The focus is on understanding the code's functionality, its relationship to web technologies, and its role in the broader event handling mechanism.
好的，让我们继续分析 `blink/renderer/core/dom/events/event_target.cc` 文件的第二部分，并归纳其功能。

**功能归纳：**

这部分代码主要负责 **移除事件监听器**、**触发（分发）事件** 以及 **管理事件监听器** 的核心逻辑。 它补充了第一部分添加事件监听器的功能，构成了一个完整的事件处理机制。

**具体功能点：**

1. **移除事件监听器 (`removeEventListener`)**:
    *   提供了多种重载版本，允许根据不同的参数类型移除事件监听器：
        *   指定事件类型、`V8EventListener`（JavaScript 函数对象）和表示是否捕获的布尔值。
        *   指定事件类型、`V8EventListener` 和一个包含 `capture` 属性的 `EventListenerOptions` 对象。
        *   指定事件类型、`EventListener` 指针和表示是否捕获的布尔值。
        *   指定事件类型、`EventListener` 指针和 `EventListenerOptions` 对象。
    *   内部调用 `RemoveEventListenerInternal` 来执行实际的移除操作。
    *   如果成功移除，会调用 `RemovedEventListener` (目前为空实现，可能用于扩展或调试)。

2. **移除事件监听器内部实现 (`RemoveEventListenerInternal`)**:
    *   检查 `listener` 是否为空。
    *   获取与 `EventTarget` 关联的 `EventTargetData` 对象（存储事件监听器信息）。
    *   调用 `event_listener_map` 的 `Remove` 方法，根据事件类型、监听器和选项来移除对应的 `RegisteredEventListener`。
    *   如果找到并成功移除，则返回 `true`。

3. **获取属性事件监听器 (`GetAttributeRegisteredEventListener`)**:
    *   用于获取通过 HTML 属性（例如 `onclick`）设置的事件监听器。
    *   遍历指定事件类型的监听器列表。
    *   查找 `EventListener` 是否是 `EventHandler` 类型，并且属于当前执行的 JavaScript 上下文。
    *   返回找到的 `RegisteredEventListener` 指针。

4. **设置属性事件监听器 (`SetAttributeEventListener`)**:
    *   用于设置通过 HTML 属性设置的事件监听器。
    *   如果传入的 `listener` 为空，则移除已存在的属性事件监听器。
    *   如果已存在属性事件监听器，则更新其回调函数。
    *   如果不存在，则调用 `addEventListener` 添加新的监听器。

5. **获取属性事件监听器 (`GetAttributeEventListener`)**:
    *   用于获取通过 HTML 属性设置的事件监听器的回调函数。
    *   调用 `GetAttributeRegisteredEventListener` 获取 `RegisteredEventListener`，然后返回其回调函数。

6. **分发事件 (绑定到 JavaScript) (`dispatchEventForBindings`)**:
    *   是 JavaScript 调用 `dispatchEvent` 方法的入口。
    *   检查事件是否已初始化且未被分发。
    *   获取执行上下文。
    *   设置事件为非信任事件（由脚本触发）。
    *   调用内部的 `DispatchEventInternal` 方法来执行实际的分发。
    *   返回事件是否被取消（`CanceledByEventHandler`）。

7. **分发事件 (`DispatchEvent`)**:
    *   用于在 Blink 内部触发事件。
    *   检查执行上下文。
    *   设置事件为信任事件（由浏览器内部触发）。
    *   调用 `DispatchEventInternal`。

8. **分发事件内部实现 (`DispatchEventInternal`)**:
    *   设置事件的目标 (`target`) 和当前目标 (`currentTarget`) 为当前 `EventTarget` 对象。
    *   设置事件的阶段为 `AT_TARGET`（目标阶段）。
    *   调用 `FireEventListeners` 来触发与该事件关联的监听器。
    *   将事件的阶段重置为 `NONE`。
    *   返回 `FireEventListeners` 的结果。

9. **获取/确保事件目标数据 (`GetEventTargetData`, `EnsureEventTargetData`)**:
    *   `GetEventTargetData` 返回存储事件监听器数据的 `EventTargetData` 指针，如果不存在则返回 `nullptr`。
    *   `EnsureEventTargetData` 返回 `EventTargetData` 对象的引用，如果不存在则创建它。

10. **处理旧版本事件类型 (`LegacyType`)**:
    *   将一些新的事件类型映射到旧版本的事件类型名称 (带有 `webkit` 前缀)。 例如，将 `transitionend` 映射到 `webkitTransitionEnd`。

11. **统计旧版本事件的使用 (`CountLegacyEvents`)**:
    *   用于统计页面中使用的旧版本和新版本事件的次数，用于浏览器特性使用情况的统计。

12. **触发事件监听器 (`FireEventListeners`)**:
    *   这是事件分发的关键步骤。
    *   检查事件是否已初始化。
    *   查找与事件类型匹配的监听器列表 (`listeners_vector`)。
    *   如果存在旧版本的事件类型，也会查找旧版本的监听器列表 (`legacy_listeners_vector`)。
    *   如果找到监听器，则调用 `FireEventListeners` 的另一个重载版本来实际执行监听器。
    *   如果事件是信任事件并且存在旧版本的监听器但没有新版本的监听器，则会临时将事件类型设置为旧版本，然后触发旧版本的监听器。
    *   在触发监听器后，会调用 `event.DoneDispatchingEventAtCurrentTarget()`，并统计事件的使用情况。

13. **触发事件监听器 (内部实现) (`FireEventListeners` - 重载版本)**:
    *   遍历指定事件类型的监听器列表的副本 (避免在事件处理过程中修改列表导致问题)。
    *   检查监听器是否已被移除。
    *   如果 `stopImmediatePropagation` 被调用，则停止处理后续监听器。
    *   检查监听器是否应该被触发 (例如，考虑捕获阶段)。
    *   如果监听器是 "once" 类型的，则在触发后移除它。
    *   设置事件的 `handlingPassive` 属性。
    *   执行监听器的回调函数 (`listener->Invoke`)。
    *   如果启用了阻塞事件警告，并且监听器是非被动的，且未发出警告，且事件未被阻止默认行为，则会报告阻塞事件。
    *   重置事件的 `handlingPassive` 属性。

14. **获取事件分发结果 (`GetDispatchEventResult`)**:
    *   根据事件的 `defaultPrevented` 和 `DefaultHandled` 状态返回 `DispatchEventResult` 枚举值，表示事件是否被处理或取消。

15. **获取事件监听器列表 (`GetEventListeners`)**:
    *   返回指定事件类型的监听器列表的指针。

16. **获取事件监听器数量 (`NumberOfEventListeners`)**:
    *   返回指定事件类型的监听器数量。

17. **获取所有事件类型 (`EventTypes`)**:
    *   返回当前 `EventTarget` 上注册的所有事件类型的列表。

18. **移除所有事件监听器 (`RemoveAllEventListeners`)**:
    *   清空 `event_listener_map`，移除所有注册的事件监听器。

19. **将事件加入队列 (`EnqueueEvent`)**:
    *   将事件加入到指定类型的任务队列中，稍后异步执行。

20. **分发队列中的事件 (`DispatchEnqueuedEvent`)**:
    *   从任务队列中取出事件并分发。

21. **追踪 (`Trace`)**:
    *   用于 Chromium 的垃圾回收机制，标记引用的对象。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:**
    *   `addEventListener` 和 `removeEventListener` 在 JavaScript 中被调用，最终会调用到这里的 C++ 代码。
        *   **例子 (JavaScript):**
            ```javascript
            const button = document.getElementById('myButton');
            function handleClick() { console.log('Button clicked!'); }
            button.addEventListener('click', handleClick); // 调用到 C++ 的 addEventListener
            button.removeEventListener('click', handleClick); // 调用到 C++ 的 removeEventListener
            ```
    *   通过 HTML 属性设置的事件处理函数（如 `onclick`）也会映射到这里的逻辑。
        *   **例子 (HTML):**
            ```html
            <button id="myButton" onclick="console.log('Button clicked!')"></button>
            ```
            这段 HTML 会在内部通过 `SetAttributeEventListener` 设置一个事件监听器。
    *   `dispatchEvent` 方法在 JavaScript 中调用，对应于 `dispatchEventForBindings` 函数。
        *   **例子 (JavaScript):**
            ```javascript
            const event = new CustomEvent('my-custom-event', { detail: { key: 'value' } });
            element.dispatchEvent(event); // 调用到 C++ 的 dispatchEventForBindings
            ```

*   **HTML:**
    *   HTML 元素是事件的目标 (`EventTarget`)。
    *   HTML 属性（如 `onclick`, `onload`, `onmouseover` 等）用于设置事件监听器。

*   **CSS:**
    *   CSS 动画和过渡完成后会触发 `transitionend`, `animationstart` 等事件，这些事件的处理流程也会经过 `EventTarget` 的 `FireEventListeners`。
        *   **例子 (CSS 和 JavaScript):**
            ```css
            .box {
                transition: width 1s;
            }
            ```
            ```javascript
            const box = document.querySelector('.box');
            box.addEventListener('transitionend', () => {
                console.log('Transition ended!');
            });
            box.style.width = '200px'; // 触发 transitionend 事件
            ```
            当 CSS 的 `transition` 结束后，`transitionend` 事件会被触发，Blink 会调用相应的事件监听器。

**逻辑推理的例子：**

**假设输入：**

1. 一个 `div` 元素上添加了一个 `click` 事件监听器 `listenerA`。
2. 然后尝试移除该监听器，使用相同的事件类型 (`click`) 和监听器对象 (`listenerA`)。

**输出：**

*   `removeEventListener` 函数会找到匹配的 `RegisteredEventListener` 并将其移除。
*   后续点击该 `div` 元素将不再触发 `listenerA`。
*   `removeEventListener` 函数会返回 `true`（表示成功移除）。

**常见的使用错误：**

1. **移除监听器时参数不匹配：**
    *   **错误例子 (JavaScript):**
        ```javascript
        const button = document.getElementById('myButton');
        function handleClick(event) { console.log('Clicked with capture:', event.eventPhase); }
        button.addEventListener('click', handleClick, true); // 使用捕获
        button.removeEventListener('click', handleClick, false); // 尝试用冒泡方式移除，失败
        ```
        在这个例子中，添加监听器时使用了捕获 (`true`)，但移除时尝试使用冒泡 (`false`)，导致移除失败。

2. **尝试移除未添加的监听器：**
    *   **错误例子 (JavaScript):**
        ```javascript
        const button = document.getElementById('myButton');
        function someOtherHandler() { console.log('This was never added.'); }
        button.removeEventListener('click', someOtherHandler); // 尝试移除一个未添加的监听器
        ```
        `removeEventListener` 会返回 `false`。

3. **在事件处理函数中移除自身，但未考虑执行顺序：**
    *   **错误例子 (JavaScript):**
        ```javascript
        const button = document.getElementById('myButton');
        button.addEventListener('click', function handleClick() {
            console.log('Click handled');
            button.removeEventListener('click', handleClick); // 移除自身
            // 可能会在当前事件处理周期结束后才真正生效，如果还有其他监听器，执行顺序可能不符合预期。
        });
        ```

**用户操作如何到达这里（调试线索）：**

1. **用户点击网页上的一个元素 (例如按钮、链接)。**
    *   浏览器会捕获到点击事件。
    *   事件会从 `Window` 对象开始向下传播（捕获阶段），检查是否有注册在捕获阶段的监听器。
    *   到达目标元素后，会触发目标元素上注册的监听器（目标阶段）。 这会涉及到 `FireEventListeners` 函数。
    *   然后事件会向上冒泡，检查是否有注册在冒泡阶段的监听器。

2. **JavaScript 代码调用 `addEventListener` 或 `removeEventListener`。**
    *   这些 JavaScript 方法最终会调用到 C++ 层的对应函数。

3. **JavaScript 代码调用 `dispatchEvent` 手动触发事件。**
    *   这会调用到 `dispatchEventForBindings` 和 `DispatchEventInternal`。

4. **CSS 动画或过渡完成。**
    *   浏览器会触发 `transitionend` 或 `animationend` 事件，这些事件的处理也会涉及到 `FireEventListeners`。

**总结：**

这部分 `event_target.cc` 代码是 Blink 引擎中事件处理机制的核心组成部分，负责移除事件监听器和触发事件。它与 JavaScript 的事件 API 紧密相连，并处理由 HTML 结构和 CSS 样式变化引发的事件。理解这部分代码有助于深入了解浏览器如何响应用户交互和页面状态变化。

Prompt: 
```
这是目录为blink/renderer/core/dom/events/event_target.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
n removeEventListener(event_type, event_listener, /*use_capture=*/false);
}

bool EventTarget::removeEventListener(
    const AtomicString& event_type,
    V8EventListener* listener,
    const V8UnionBooleanOrEventListenerOptions* bool_or_options) {
  DCHECK(bool_or_options);

  EventListener* event_listener = JSEventListener::CreateOrNull(listener);

  switch (bool_or_options->GetContentType()) {
    case V8UnionBooleanOrEventListenerOptions::ContentType::kBoolean:
      return removeEventListener(event_type, event_listener,
                                 bool_or_options->GetAsBoolean());
    case V8UnionBooleanOrEventListenerOptions::ContentType::
        kEventListenerOptions: {
      EventListenerOptions* options =
          bool_or_options->GetAsEventListenerOptions();
      return removeEventListener(event_type, event_listener, options);
    }
  }

  NOTREACHED();
}

bool EventTarget::removeEventListener(const AtomicString& event_type,
                                      const EventListener* listener,
                                      bool use_capture) {
  EventListenerOptions* options = EventListenerOptions::Create();
  options->setCapture(use_capture);
  return RemoveEventListenerInternal(event_type, listener, options);
}

bool EventTarget::removeEventListener(const AtomicString& event_type,
                                      const EventListener* listener,
                                      EventListenerOptions* options) {
  return RemoveEventListenerInternal(event_type, listener, options);
}

bool EventTarget::RemoveEventListenerInternal(
    const AtomicString& event_type,
    const EventListener* listener,
    const EventListenerOptions* options) {
  if (!listener)
    return false;

  EventTargetData* d = GetEventTargetData();
  if (!d)
    return false;

  RegisteredEventListener* registered_listener;

  if (!d->event_listener_map.Remove(event_type, listener, options,
                                    &registered_listener)) {
    return false;
  }

  CHECK(registered_listener);
  RemovedEventListener(event_type, *registered_listener);
  return true;
}

void EventTarget::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {}

RegisteredEventListener* EventTarget::GetAttributeRegisteredEventListener(
    const AtomicString& event_type) {
  EventListenerVector* listener_vector = GetEventListeners(event_type);
  if (!listener_vector)
    return nullptr;

  for (auto& registered_listener : *listener_vector) {
    EventListener* listener = registered_listener->Callback();
    if (GetExecutionContext() && listener->IsEventHandler() &&
        listener->BelongsToTheCurrentWorld(GetExecutionContext()))
      return registered_listener.Get();
  }
  return nullptr;
}

bool EventTarget::SetAttributeEventListener(const AtomicString& event_type,
                                            EventListener* listener) {
  RegisteredEventListener* registered_listener =
      GetAttributeRegisteredEventListener(event_type);
  if (!listener) {
    if (registered_listener)
      removeEventListener(event_type, registered_listener->Callback(), false);
    return false;
  }
  if (registered_listener) {
    if (IsA<JSBasedEventListener>(listener) &&
        IsInstrumentedForAsyncStack(event_type)) {
      listener->async_task_context()->Schedule(GetExecutionContext(),
                                               event_type);
    }
    registered_listener->SetCallback(listener);
    return true;
  }
  return addEventListener(event_type, listener, false);
}

EventListener* EventTarget::GetAttributeEventListener(
    const AtomicString& event_type) {
  RegisteredEventListener* registered_listener =
      GetAttributeRegisteredEventListener(event_type);
  if (registered_listener)
    return registered_listener->Callback();
  return nullptr;
}

bool EventTarget::dispatchEventForBindings(Event* event,
                                           ExceptionState& exception_state) {
  if (!event->WasInitialized()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The event provided is uninitialized.");
    return false;
  }
  if (event->IsBeingDispatched()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The event is already being dispatched.");
    return false;
  }

  if (!GetExecutionContext())
    return false;

  event->SetTrusted(false);

  // Return whether the event was cancelled or not to JS not that it
  // might have actually been default handled; so check only against
  // CanceledByEventHandler.
  return DispatchEventInternal(*event) !=
         DispatchEventResult::kCanceledByEventHandler;
}

DispatchEventResult EventTarget::DispatchEvent(Event& event) {
  if (!GetExecutionContext())
    return DispatchEventResult::kCanceledBeforeDispatch;
  event.SetTrusted(true);
  return DispatchEventInternal(event);
}

DispatchEventResult EventTarget::DispatchEventInternal(Event& event) {
  event.SetTarget(this);
  event.SetCurrentTarget(this);
  event.SetEventPhase(Event::PhaseType::kAtTarget);
  DispatchEventResult dispatch_result = FireEventListeners(event);
  event.SetEventPhase(Event::PhaseType::kNone);
  return dispatch_result;
}

EventTargetData* EventTarget::GetEventTargetData() {
  return data_.Get();
}

EventTargetData& EventTarget::EnsureEventTargetData() {
  if (!data_) {
    data_ = MakeGarbageCollected<EventTargetData>();
  }
  return *data_;
}

static const AtomicString& LegacyType(const Event& event) {
  if (event.type() == event_type_names::kTransitionend)
    return event_type_names::kWebkitTransitionEnd;

  if (event.type() == event_type_names::kAnimationstart)
    return event_type_names::kWebkitAnimationStart;

  if (event.type() == event_type_names::kAnimationend)
    return event_type_names::kWebkitAnimationEnd;

  if (event.type() == event_type_names::kAnimationiteration)
    return event_type_names::kWebkitAnimationIteration;

  if (event.type() == event_type_names::kWheel)
    return event_type_names::kMousewheel;

  return g_empty_atom;
}

void EventTarget::CountLegacyEvents(
    const AtomicString& legacy_type_name,
    EventListenerVector* listeners_vector,
    EventListenerVector* legacy_listeners_vector) {
  WebFeature unprefixed_feature;
  WebFeature prefixed_feature;
  WebFeature prefixed_and_unprefixed_feature;
  if (legacy_type_name == event_type_names::kWebkitTransitionEnd) {
    prefixed_feature = WebFeature::kPrefixedTransitionEndEvent;
    unprefixed_feature = WebFeature::kUnprefixedTransitionEndEvent;
    prefixed_and_unprefixed_feature =
        WebFeature::kPrefixedAndUnprefixedTransitionEndEvent;
  } else if (legacy_type_name == event_type_names::kWebkitAnimationEnd) {
    prefixed_feature = WebFeature::kPrefixedAnimationEndEvent;
    unprefixed_feature = WebFeature::kUnprefixedAnimationEndEvent;
    prefixed_and_unprefixed_feature =
        WebFeature::kPrefixedAndUnprefixedAnimationEndEvent;
  } else if (legacy_type_name == event_type_names::kWebkitAnimationStart) {
    prefixed_feature = WebFeature::kPrefixedAnimationStartEvent;
    unprefixed_feature = WebFeature::kUnprefixedAnimationStartEvent;
    prefixed_and_unprefixed_feature =
        WebFeature::kPrefixedAndUnprefixedAnimationStartEvent;
  } else if (legacy_type_name == event_type_names::kWebkitAnimationIteration) {
    prefixed_feature = WebFeature::kPrefixedAnimationIterationEvent;
    unprefixed_feature = WebFeature::kUnprefixedAnimationIterationEvent;
    prefixed_and_unprefixed_feature =
        WebFeature::kPrefixedAndUnprefixedAnimationIterationEvent;
  } else if (legacy_type_name == event_type_names::kMousewheel) {
    prefixed_feature = WebFeature::kMouseWheelEvent;
    unprefixed_feature = WebFeature::kWheelEvent;
    prefixed_and_unprefixed_feature = WebFeature::kMouseWheelAndWheelEvent;
  } else {
    return;
  }

  if (const LocalDOMWindow* executing_window = ExecutingWindow()) {
    if (Document* document = executing_window->document()) {
      if (legacy_listeners_vector) {
        if (listeners_vector)
          UseCounter::Count(*document, prefixed_and_unprefixed_feature);
        else
          UseCounter::Count(*document, prefixed_feature);
      } else if (listeners_vector) {
        UseCounter::Count(*document, unprefixed_feature);
      }
    }
  }
}

DispatchEventResult EventTarget::FireEventListeners(Event& event) {
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  DCHECK(event.WasInitialized());

  EventTargetData* d = GetEventTargetData();
  if (!d)
    return DispatchEventResult::kNotCanceled;

  EventListenerVector* legacy_listeners_vector = nullptr;
  AtomicString legacy_type_name = LegacyType(event);
  if (!legacy_type_name.empty())
    legacy_listeners_vector = d->event_listener_map.Find(legacy_type_name);

  EventListenerVector* listeners_vector =
      d->event_listener_map.Find(event.type());

  bool fired_event_listeners = false;
  if (listeners_vector) {
    // Calling `FireEventListener` causes a clone of `listeners_vector`.
    fired_event_listeners = FireEventListeners(event, d, *listeners_vector);
  } else if (event.isTrusted() && legacy_listeners_vector) {
    AtomicString unprefixed_type_name = event.type();
    event.SetType(legacy_type_name);
    // Calling `FireEventListener` causes a clone of `legacy_listeners_vector`.
    fired_event_listeners =
        FireEventListeners(event, d, *legacy_listeners_vector);
    event.SetType(unprefixed_type_name);
  }

  // Only invoke the callback if event listeners were fired for this phase.
  if (fired_event_listeners) {
    event.DoneDispatchingEventAtCurrentTarget();

    // Only count uma metrics if we really fired an event listener.
    Editor::CountEvent(GetExecutionContext(), event);
    CountLegacyEvents(legacy_type_name, listeners_vector,
                      legacy_listeners_vector);
  }
  return GetDispatchEventResult(event);
}

// Fire event listeners, creates a copy of EventListenerVector on being called.
bool EventTarget::FireEventListeners(Event& event,
                                     EventTargetData* d,
                                     EventListenerVector entry) {
  // Fire all listeners registered for this event. Don't fire listeners removed
  // during event dispatch. Also, don't fire event listeners added during event
  // dispatch. Conveniently, all new event listeners will be added after or at
  // index |size|, so iterating up to (but not including) |size| naturally
  // excludes new event listeners.

  ExecutionContext* context = GetExecutionContext();
  if (!context)
    return false;

  CountFiringEventListeners(event, ExecutingWindow());

  base::TimeDelta blocked_event_threshold =
      BlockedEventsWarningThreshold(context, event);
  base::TimeTicks now;
  bool should_report_blocked_event = false;
  if (!blocked_event_threshold.is_zero()) {
    now = base::TimeTicks::Now();
    should_report_blocked_event =
        now - event.PlatformTimeStamp() > blocked_event_threshold;
  }
  bool fired_listener = false;

  for (auto& registered_listener : entry) {
    if (registered_listener->Removed()) [[unlikely]] {
      continue;
    }

    // If stopImmediatePropagation has been called, we just break out
    // immediately, without handling any more events on this target.
    if (event.ImmediatePropagationStopped()) {
      break;
    }

    if (!registered_listener->ShouldFire(event)) {
      continue;
    }

    EventListener* listener = registered_listener->Callback();
    // The listener will be retained by Member<EventListener> in the
    // registeredListener, i and size are updated with the firing event iterator
    // in case the listener is removed from the listener vector below.
    if (registered_listener->Once()) {
      removeEventListener(event.type(), listener,
                          registered_listener->Capture());
    }
    event.SetHandlingPassive(EventPassiveMode(*registered_listener));

    probe::UserCallback probe(context, nullptr, event.type(), false, this);
    probe::AsyncTask async_task(context, listener->async_task_context(),
                                "event",
                                IsInstrumentedForAsyncStack(event.type()));

    // To match Mozilla, the AT_TARGET phase fires both capturing and bubbling
    // event listeners, even though that violates some versions of the DOM spec.
    listener->Invoke(context, &event);
    fired_listener = true;

    // If we're about to report this event listener as blocking, make sure it
    // wasn't removed while handling the event.
    if (should_report_blocked_event && !registered_listener->Removed() &&
        !registered_listener->Passive() &&
        !registered_listener->BlockedEventWarningEmitted() &&
        !event.defaultPrevented()) {
      ReportBlockedEvent(*this, event, registered_listener,
                         now - event.PlatformTimeStamp());
    }

    event.SetHandlingPassive(Event::PassiveMode::kNotPassive);
  }
  return fired_listener;
}

DispatchEventResult EventTarget::GetDispatchEventResult(const Event& event) {
  if (event.defaultPrevented())
    return DispatchEventResult::kCanceledByEventHandler;
  if (event.DefaultHandled())
    return DispatchEventResult::kCanceledByDefaultEventHandler;
  return DispatchEventResult::kNotCanceled;
}

EventListenerVector* EventTarget::GetEventListeners(
    const AtomicString& event_type) {
  EventTargetData* data = GetEventTargetData();
  if (!data)
    return nullptr;
  return data->event_listener_map.Find(event_type);
}

int EventTarget::NumberOfEventListeners(const AtomicString& event_type) const {
  EventListenerVector* listeners =
      const_cast<EventTarget*>(this)->GetEventListeners(event_type);
  return listeners ? listeners->size() : 0;
}

Vector<AtomicString> EventTarget::EventTypes() {
  EventTargetData* d = GetEventTargetData();
  return d ? d->event_listener_map.EventTypes() : Vector<AtomicString>();
}

void EventTarget::RemoveAllEventListeners() {
  if (auto* d = GetEventTargetData()) {
    d->event_listener_map.Clear();
  }
}

void EventTarget::EnqueueEvent(Event& event, TaskType task_type) {
  ExecutionContext* context = GetExecutionContext();
  if (!context)
    return;
  event.async_task_context()->Schedule(context, event.type());
  context->GetTaskRunner(task_type)->PostTask(
      FROM_HERE,
      WTF::BindOnce(&EventTarget::DispatchEnqueuedEvent, WrapPersistent(this),
                    WrapPersistent(&event), WrapPersistent(context)));
}

void EventTarget::DispatchEnqueuedEvent(Event* event,
                                        ExecutionContext* context) {
  if (!GetExecutionContext()) {
    event->async_task_context()->Cancel();
    return;
  }
  this->ResetEventQueueStatus(event->type());
  probe::AsyncTask async_task(context, event->async_task_context());
  DispatchEvent(*event);
}

void EventTarget::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  visitor->Trace(data_);
}

}  // namespace blink

"""


```