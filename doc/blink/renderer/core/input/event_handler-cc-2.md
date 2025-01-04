Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Understanding and Context:**

* **Identify the file:** `blink/renderer/core/input/event_handler.cc`. This tells us it's part of the Blink rendering engine, specifically dealing with input events. The `.cc` extension indicates C++ code.
* **Recognize the class:** The code belongs to the `EventHandler` class. This immediately suggests its core responsibility is managing and processing events.
* **Note the context provided:** The user explicitly states this is *part 3 of 4*. This is crucial for the final summarization. We shouldn't try to understand *everything* about event handling from just this snippet.

**2. Function-by-Function Analysis (The Core Work):**

This is the most detailed and important step. For each function, ask:

* **What does it do?**  Read the function name, the arguments, and the code itself. Look for keywords and patterns.
* **What are the inputs?**  What data does the function receive?  What types are they?
* **What are the outputs?** What does the function return? What side effects does it have (modifying state, calling other functions)?
* **What other components does it interact with?** Are there calls to other classes or managers (like `pointer_event_manager_`, `gesture_manager_`, `mouse_event_manager_`)? This reveals the broader system interaction.
* **Is there any connection to web technologies (JavaScript, HTML, CSS)?**  Look for concepts like "element", "DOM", "context menu", "scrolling", "hover", "active state".

**Example of Function-by-Function Thought Process (for `Capture()`):**

* **Function name:** `Capture()`
* **Code:** `ReleaseMouseCaptureFromLocalRoot();`
* **Interpretation:**  The function releases mouse capture. "LocalRoot" suggests it pertains to the current frame or document.
* **Connection to web technologies:** Mouse capture is a browser feature that can be initiated and controlled via JavaScript.

**Example of Function-by-Function Thought Process (for `DispatchMousePointerEvent()`):**

* **Function name:** `DispatchMousePointerEvent()`
* **Arguments:**  `event_type`, `target_element`, `mouse_event`, `coalesced_events`, `predicted_events`, `skip_click_dispatch`. These clearly relate to mouse events and their handling.
* **Code:**  Calls `pointer_event_manager_->SendMousePointerEvent(...)`.
* **Interpretation:** This function takes a mouse event and delegates its dispatch to the `pointer_event_manager_`.
* **Connection to web technologies:**  This directly relates to how user mouse interactions in the browser (clicks, movements) are processed and trigger JavaScript event handlers.

**3. Identifying Relationships with Web Technologies:**

As you analyze each function, actively look for links to JavaScript, HTML, and CSS.

* **JavaScript:** Event dispatching, handling of user interactions, APIs like `setPointerCapture`, context menu events.
* **HTML:** Elements (targets of events), frame structure, context menu behavior.
* **CSS:** Hover and active states (though the code doesn't directly manipulate CSS, it manages the *logic* that triggers those states).

**4. Looking for Logic and Assumptions:**

* **Conditional statements (`if`, `else`):**  What conditions trigger different behavior?  What are the assumptions behind these conditions? (e.g., checking for `LocalFrame` before accessing its `EventHandler`).
* **Loops (`while`):**  How are iterations controlled? What data is being processed iteratively?
* **Assertions (`DCHECK`):** These are internal checks. While not directly user-facing, they reveal the developer's expectations about the state of the system.

**5. Identifying Potential User/Programming Errors:**

Think about how developers using the browser's APIs or how the browser itself might misuse these functions.

* **Incorrect target elements:** Passing the wrong element as the target of an event.
* **Mismatched event types:**  Trying to handle a mouse event as a touch event, for instance.
* **Unexpected frame structure:** The code relies on a certain frame hierarchy. What happens if that hierarchy is broken or manipulated unexpectedly?

**6. Tracing User Actions (Debugging Clues):**

Imagine a simple user interaction, like a click, and trace its path through the code.

* **Mouse click:** User clicks on an element.
* **Browser receives the event:** The operating system signals the browser.
* **Event is translated:** The raw OS event is converted into a `WebMouseEvent`.
* **`EventHandler` is involved:**  A function like `DispatchMousePointerEvent` or `HandleTargetedMouseEvent` is called.
* **Hit testing:** The browser determines which element was clicked.
* **Event dispatch:** The event is passed to the appropriate JavaScript handler.

**7. Structuring the Answer:**

Organize the findings logically:

* **Overall Functionality:** Start with a high-level summary.
* **Key Functionalities (grouped):** Group related functions together (e.g., pointer capture, gesture handling, context menu).
* **Relationships with Web Technologies:**  Provide concrete examples.
* **Logical Reasoning (with examples):** Explain any inferred logic and provide hypothetical inputs and outputs.
* **Common Errors:**  Illustrate with examples.
* **User Action Trace:** Describe the journey of a user interaction.
* **Summary (for Part 3):**  Focus on the aspects covered in this specific snippet and acknowledge that it's part of a larger system.

**Self-Correction/Refinement during the Process:**

* **If a function is unclear:** Re-read it carefully, look at the names of called functions, and try to infer its purpose from the surrounding code.
* **If a connection to web technologies isn't obvious:** Think about the *user experience* and how the browser reacts to different events. What JavaScript APIs are related?
* **If the logic is complex:**  Break it down into smaller steps. Use comments or mental notes to track the flow of execution.

By following this structured and inquisitive approach, you can effectively analyze complex source code snippets like the one provided and extract meaningful information. The key is to be systematic, pay attention to detail, and connect the code to the broader context of web development.
好的，这是`blink/renderer/core/input/event_handler.cc`文件的第三部分代码的功能归纳：

**整体功能归纳 (基于提供的代码片段)：**

这部分`EventHandler`的代码主要负责处理和分发各种输入事件，特别是鼠标、触摸和手势事件。它致力于精确地确定事件的目标，并根据需要进行调整（例如触摸调整），同时维护和更新跨 frame 的 hover 和 active 状态。此外，它还负责处理上下文菜单的显示。

**具体功能列举和说明:**

1. **释放鼠标捕获:**
   - `Capture()`:  调用 `ReleaseMouseCaptureFromLocalRoot()`，释放当前 frame 的鼠标捕获。
   - **与 JavaScript, HTML, CSS 的关系:** JavaScript 可以使用 `element.setPointerCapture()` 获取鼠标捕获，此函数则用于释放捕获。HTML 元素是捕获的目标。CSS 的 `:active` 伪类可能受到鼠标捕获的影响。
   - **用户操作 -> 这里:**  JavaScript 代码调用了 `releasePointerCapture()` 或者浏览器内部逻辑决定释放捕获时。

2. **检查是否拥有指针捕获:**
   - `HasPointerCapture(PointerId pointer_id, const Element* target) const`: 检查指定的 `pointer_id` 是否被捕获，并且可能检查是否被特定的 `target` 元素捕获。
   - **与 JavaScript, HTML, CSS 的关系:**  与 `Capture()` 相反，用于查询捕获状态。JavaScript 可以使用 `element.hasPointerCapture()` 查询。
   - **用户操作 -> 这里:**  当需要确定某个指针事件是否应该被特定元素处理时。

3. **处理元素移除:**
   - `ElementRemoved(Element* target)`: 当一个元素从 DOM 树中移除时被调用，用于清理与该元素相关的指针事件和鼠标滚轮事件的追踪信息。
   - **与 JavaScript, HTML, CSS 的关系:**  当 JavaScript 操作 DOM 移除元素（例如 `element.remove()`）时会触发此函数。
   - **用户操作 -> 这里:**  JavaScript 代码移除一个 HTML 元素。

4. **重置指针解锁后的鼠标位置:**
   - `ResetMousePositionForPointerUnlock()`:  在指针解锁后移除最后记录的鼠标位置，这可能与指针约束 API 有关。
   - **与 JavaScript, HTML, CSS 的关系:** 与 Pointer Lock API 相关，JavaScript 可以请求和释放鼠标锁定。
   - **用户操作 -> 这里:**  JavaScript 代码释放了鼠标锁定。

5. **判断长按是否应触发上下文菜单:**
   - `LongTapShouldInvokeContextMenu()`:  查询手势管理器，判断当前的长按手势是否应该触发上下文菜单。
   - **与 JavaScript, HTML, CSS 的关系:**  长按操作是用户交互，最终可能触发浏览器的上下文菜单，与 HTML 元素上的右键点击效果类似。
   - **用户操作 -> 这里:** 用户在触摸设备上进行长按操作。

6. **分发鼠标指针事件:**
   - `DispatchMousePointerEvent(const WebInputEvent::Type event_type, Element* target_element, const WebMouseEvent& mouse_event, const Vector<WebMouseEvent>& coalesced_events, const Vector<WebMouseEvent>& predicted_events, bool skip_click_dispatch)`: 将鼠标指针事件（例如 mousemove, mouseup, mousedown）发送到指定的 `target_element`。
   - **与 JavaScript, HTML, CSS 的关系:**  这是处理所有鼠标交互的核心函数之一。鼠标事件最终会触发 HTML 元素上注册的 JavaScript 事件监听器。CSS 的伪类（如 `:hover`, `:active`）也与这些事件相关。
   - **假设输入与输出:**
     - **假设输入:**  `event_type` 为 `WebInputEvent::Type::kMouseUp`，`target_element` 是一个按钮元素，`mouse_event` 包含了鼠标释放的位置和按键信息。
     - **逻辑推理:**  函数会将 `mouseup` 事件发送到该按钮元素，浏览器会检查是否有 JavaScript 事件监听器注册到该按钮的 `mouseup` 事件上，如果有则执行。
     - **假设输出:** 返回一个 `WebInputEventResult`，指示事件是否被处理。
   - **用户操作 -> 这里:**  用户点击或释放鼠标按键，或者移动鼠标。

7. **处理鼠标滚轮事件:**
   - `HandleWheelEvent(const WebMouseWheelEvent& event)`: 将鼠标滚轮事件传递给 `mouse_wheel_event_manager_` 进行处理。
   - **与 JavaScript, HTML, CSS 的关系:**  处理页面滚动。JavaScript 可以监听 `wheel` 事件。CSS 的 `overflow` 属性决定了元素是否可以滚动。
   - **用户操作 -> 这里:**  用户滚动鼠标滚轮。

8. **处理定向的鼠标事件:**
   - `HandleTargetedMouseEvent(Element* target, const WebMouseEvent& event, const AtomicString& mouse_event_type, const Vector<WebMouseEvent>& coalesced_events, const Vector<WebMouseEvent>& predicted_events)`:  直接将鼠标事件分发到指定的 `target` 元素，绕过通常的事件处理路径。
   - **与 JavaScript, HTML, CSS 的关系:**  与 `DispatchMousePointerEvent` 类似，但更加直接。可能用于处理一些特殊情况或优化路径。
   - **用户操作 -> 这里:**  某些特定场景下，浏览器内部逻辑可能会直接触发此类事件。

9. **处理手势事件 (根 Frame):**
   - `HandleGestureEvent(const WebGestureEvent& gesture_event)`: 处理手势事件，例如 tap, scroll, pinch 等。这个版本是针对根 frame 的。
   - **与 JavaScript, HTML, CSS 的关系:**  处理触摸屏上的手势操作。JavaScript 可以监听 `touchstart`, `touchmove`, `touchend`, `gesturestart`, `gesturechange`, `gestureend` 等事件。这些手势可能导致页面滚动、缩放或触发其他交互。
   - **假设输入与输出:**
     - **假设输入:**  `gesture_event` 是一个 `WebInputEvent::Type::kGestureTap` 事件，表示用户进行了一次点击。
     - **逻辑推理:**  函数会进行 hit-test 以确定点击的目标元素，然后将事件分发到该元素。
     - **假设输出:** 返回一个 `WebInputEventResult`，指示事件是否被处理。
   - **用户操作 -> 这里:**  用户在触摸屏上进行各种手势操作。

10. **处理手势事件 (指定 Frame):**
    - `HandleGestureEvent(const GestureEventWithHitTestResults& targeted_event)`: 处理已经包含 hit-test 结果的手势事件。
    - `HandleGestureEventInFrame(const GestureEventWithHitTestResults& targeted_event)`:  在一个特定的 frame 内处理手势事件。
    - **与 JavaScript, HTML, CSS 的关系:**  与上一个函数类似，但处理的是已经确定目标的手势事件，可能发生在 iframe 场景中。
    - **用户操作 -> 这里:** 用户在包含 iframe 的页面上进行手势操作。

11. **设置MouseDown可能开始自动滚动:**
    - `SetMouseDownMayStartAutoscroll()`:  通知鼠标事件管理器，当前的 mousedown 事件可能导致自动滚动。
    - **与 JavaScript, HTML, CSS 的关系:**  浏览器提供的自动滚动功能，通常在用户长按鼠标并拖动时触发。
    - **用户操作 -> 这里:** 用户按下鼠标按键。

12. **判断是否应该应用触摸调整:**
    - `ShouldApplyTouchAdjustment(const WebGestureEvent& event) const`:  判断给定的手势事件是否应该应用触摸调整。触摸调整是为了提高触摸操作的精度，特别是针对较小的触摸目标。
    - **与 JavaScript, HTML, CSS 的关系:**  触摸调整是浏览器为了改善触摸体验而进行的内部优化，对 JavaScript 或 CSS 来说是透明的，但会影响事件的目标和坐标。
    - **用户操作 -> 这里:**  当接收到触摸或手势事件时。

13. **缓存触摸调整结果:**
    - `CacheTouchAdjustmentResult(uint32_t id, gfx::PointF adjusted_point)`:  缓存触摸调整后的事件 ID 和调整后的坐标。
    - **与 JavaScript, HTML, CSS 的关系:**  内部优化，对 web 技术透明。
    - **用户操作 -> 这里:**  在进行触摸调整计算后。

14. **判断手势是否对应于调整后的触摸:**
    - `GestureCorrespondsToAdjustedTouch(const WebGestureEvent& event)`: 判断当前的手势事件是否与之前调整过的触摸事件相关联，以便后续手势事件可以使用相同的调整结果。
    - **与 JavaScript, HTML, CSS 的关系:**  内部优化，对 web 技术透明。
    - **用户操作 -> 这里:**  当接收到新的手势事件时。

15. **确定最佳的 Hit-Test 节点:**
    - `BestNodeForHitTestResult(TouchAdjustmentCandidateType candidate_type, const HitTestLocation& location, const HitTestResult& result, gfx::Point& adjusted_point, Node*& adjusted_node)`:  根据 hit-test 结果，确定最适合作为触摸调整目标的节点。
    - **与 JavaScript, HTML, CSS 的关系:**  影响事件最终传递到的 HTML 元素。
    - **用户操作 -> 这里:**  在进行触摸调整时。

16. **更新跨 Frame 的 Hover 和 Active 状态:**
    - `UpdateCrossFrameHoverActiveState(bool is_active, Element* inner_element)`:  当鼠标悬停或激活状态发生变化时，更新跨 frame 的状态。
    - **与 JavaScript, HTML, CSS 的关系:**  直接影响 CSS 的 `:hover` 和 `:active` 伪类的应用，以及 JavaScript 中与这些状态相关的逻辑。
    - **用户操作 -> 这里:**  鼠标移动到元素上或按下鼠标按键。

17. **更新手势目标节点的鼠标相关事件:**
    - `UpdateGestureTargetNodeForMouseEvent(const GestureEventWithHitTestResults& targeted_event)`: 在手势事件发生时，为了模拟鼠标事件（mouseover/mouseout 等），更新跨 frame 的状态。
    - **与 JavaScript, HTML, CSS 的关系:**  确保在使用触摸手势时，鼠标相关的事件也能正确触发，以保持与现有 web 内容的兼容性。
    - **用户操作 -> 这里:**  用户进行触摸手势操作。

18. **定位手势事件:**
    - `TargetGestureEvent(const WebGestureEvent& gesture_event, bool read_only = false)`:  执行 hit-test 以确定手势事件的目标元素，并更新 hover 和 active 状态。
    - `HitTestResultForGestureEvent(const WebGestureEvent& gesture_event, HitTestRequest::HitTestRequestType hit_type)`:  执行实际的 hit-test 过程。
    - **与 JavaScript, HTML, CSS 的关系:**  决定哪个 HTML 元素接收到手势事件。
    - **用户操作 -> 这里:**  用户进行触摸手势操作。

19. **应用触摸调整:**
    - `ApplyTouchAdjustment(WebGestureEvent* gesture_event, HitTestLocation& location, HitTestResult& hit_test_result)`:  根据 hit-test 结果，对触摸事件的坐标进行调整。
    - **与 JavaScript, HTML, CSS 的关系:**  内部优化，对 web 技术透明，但会影响事件的坐标。
    - **用户操作 -> 这里:**  在处理触摸或手势事件时。

20. **发送上下文菜单事件:**
    - `SendContextMenuEvent(const WebMouseEvent& event, Element* override_target_element)`:  触发上下文菜单事件。
    - **与 JavaScript, HTML, CSS 的关系:**  触发浏览器的上下文菜单，用户可以通过右键点击或长按等方式触发。JavaScript 可以监听 `contextmenu` 事件。
    - **用户操作 -> 这里:**  用户右键点击或长按操作。

21. **显示无位置信息的上下文菜单:**
    - `ShowNonLocatedContextMenu(Element* override_target_element, WebMenuSourceType source_type)`:  显示不依赖于特定鼠标位置的上下文菜单，例如通过键盘快捷键触发。
    - **与 JavaScript, HTML, CSS 的关系:**  与 `SendContextMenuEvent` 类似。
    - **用户操作 -> 这里:**  用户按下上下文菜单键或通过其他非鼠标方式触发。

22. **获取焦点元素用于无位置上下文菜单的矩形:**
    - `GetFocusedElementRectForNonLocatedContextMenu(Element* focused_element)`:  获取焦点元素的可见区域，用于确定无位置上下文菜单的显示位置。
    - **与 JavaScript, HTML, CSS 的关系:**  影响上下文菜单的显示位置。
    - **用户操作 -> 这里:**  在显示无位置上下文菜单时。

23. **调度 Hover 状态更新:**
    - `ScheduleHoverStateUpdate()`:  安排更新 hover 状态，通常使用定时器延迟更新。
    - **与 JavaScript, HTML, CSS 的关系:**  与 CSS 的 `:hover` 伪类相关。
    - **用户操作 -> 这里:**  鼠标移动。

24. **调度光标更新:**
    - `ScheduleCursorUpdate()`:  安排更新鼠标光标，也使用定时器。
    - **与 JavaScript, HTML, CSS 的关系:**  与 CSS 的 `cursor` 属性相关。
    - **用户操作 -> 这里:**  鼠标移动。

25. **检查光标更新是否待处理:**
    - `CursorUpdatePending()`:  检查是否有待处理的光标更新。

26. **判断是否正在处理键盘事件:**
    - `IsHandlingKeyEvent() const`:  查询键盘事件管理器，判断当前是否正在处理键盘事件。
    - **与 JavaScript, HTML, CSS 的关系:**  与 JavaScript 的 `keydown`, `keyup`, `keypress` 事件相关。
    - **用户操作 -> 这里:**  用户按下或释放键盘按键。

27. **设置正在调整大小的 FrameSet:**
    - `SetResizingFrameSet(HTMLFrameSetElement* frame_set)`:  标记一个 `HTMLFrameSetElement` 正在被调整大小，并捕获鼠标事件。
    - **与 JavaScript, HTML, CSS 的关系:**  与 HTML 的 `<frameset>` 元素相关。
    - **用户操作 -> 这里:**  用户拖动 frame 之间的边框来调整大小。

28. **处理可滚动区域销毁:**
    - `ResizeScrollableAreaDestroyed()`:  当一个可滚动区域被销毁时进行清理。
    - **与 JavaScript, HTML, CSS 的关系:**  与 CSS 的 `overflow` 属性以及页面的滚动机制相关。
    - **用户操作 -> 这里:**  当页面结构发生变化导致可滚动区域被移除时。

29. **Hover 定时器触发:**
    - `HoverTimerFired(TimerBase*)`:  当 hover 定时器到期时被调用，执行实际的 hover 状态更新。
    - **与 JavaScript, HTML, CSS 的关系:**  与 CSS 的 `:hover` 伪类相关。
    - **用户操作 -> 这里:**  在鼠标移动一段时间后，如果需要更新 hover 状态。

**用户或编程常见的使用错误举例:**

* **错误地假设事件目标:**  JavaScript 代码可能基于错误的假设来处理事件，例如假设某个事件总是发生在特定的元素上，而忽略了事件冒泡或目标重定向的可能性。
* **preventDefault 的滥用:**  过度使用 `event.preventDefault()` 可能阻止浏览器的默认行为，例如阻止表单提交或链接跳转。
* **事件监听器泄露:**  在 JavaScript 中添加了事件监听器但没有在元素移除时移除，可能导致内存泄漏。
* **在不合适的时机操作 DOM:**  在事件处理函数中进行大量的、同步的 DOM 操作可能会导致页面卡顿。

**用户操作如何一步步到达这里 (调试线索):**

以一个简单的鼠标点击事件为例：

1. **用户操作:** 用户将鼠标移动到屏幕上的某个元素上，然后点击鼠标左键。
2. **操作系统:** 操作系统检测到鼠标事件，并将其传递给浏览器进程。
3. **浏览器进程:** 浏览器进程将操作系统事件转换为 `WebMouseEvent`。
4. **渲染器进程:**  浏览器进程将事件发送到渲染器进程。
5. **事件路由:** 渲染器进程的事件处理机制开始工作，确定事件发生的位置和可能的处理者。
6. **`EventHandler::DispatchMousePointerEvent` (或 `HandleTargetedMouseEvent`):**  根据事件类型和目标元素，最终会调用到 `EventHandler` 的相关方法，例如 `DispatchMousePointerEvent`。
7. **Hit-testing:** 在此过程中，可能需要进行 hit-testing 来精确确定点击的目标元素。
8. **事件分发:** 事件最终会被分发到目标元素的 JavaScript 事件监听器。

对于触摸事件或手势事件，流程类似，只是操作系统传递的是触摸或手势信息，渲染器进程会将其转换为 `WebGestureEvent` 等类型，并调用 `EventHandler` 中相应的 `HandleGestureEvent` 方法。

**总结 (针对第 3 部分):**

这部分 `EventHandler` 的代码专注于处理和分发各种类型的输入事件（鼠标、触摸、手势），并维护相关的状态（例如指针捕获、hover 和 active 状态）。它体现了 Blink 引擎如何将底层的输入事件转化为更高层次的事件，并最终传递给 JavaScript 代码进行处理。 触摸调整、跨 frame 事件处理和上下文菜单管理是这部分代码的关键功能。

Prompt: 
```
这是目录为blink/renderer/core/input/event_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
terCapture() {
  ReleaseMouseCaptureFromLocalRoot();
}

bool EventHandler::HasPointerCapture(PointerId pointer_id,
                                     const Element* target) const {
  if (LocalFrame* tracking_frame =
          DetermineActivePointerTrackerFrame(pointer_id)) {
    return tracking_frame->GetEventHandler()
        .pointer_event_manager_->HasPointerCapture(pointer_id, target);
  }
  return false;
}

void EventHandler::ElementRemoved(Element* target) {
  if (!target->GetDocument().StatePreservingAtomicMoveInProgress()) {
    pointer_event_manager_->ElementRemoved(target);
  }
  if (target)
    mouse_wheel_event_manager_->ElementRemoved(target);
}

void EventHandler::ResetMousePositionForPointerUnlock() {
  pointer_event_manager_->RemoveLastMousePosition();
}

bool EventHandler::LongTapShouldInvokeContextMenu() {
  return gesture_manager_->GestureContextMenuDeferred();
}

WebInputEventResult EventHandler::DispatchMousePointerEvent(
    const WebInputEvent::Type event_type,
    Element* target_element,
    const WebMouseEvent& mouse_event,
    const Vector<WebMouseEvent>& coalesced_events,
    const Vector<WebMouseEvent>& predicted_events,
    bool skip_click_dispatch) {
  const auto& event_result = pointer_event_manager_->SendMousePointerEvent(
      EffectiveMouseEventTargetElement(target_element), event_type, mouse_event,
      coalesced_events, predicted_events, skip_click_dispatch);
  return event_result;
}

WebInputEventResult EventHandler::HandleWheelEvent(
    const WebMouseWheelEvent& event) {
  return mouse_wheel_event_manager_->HandleWheelEvent(event);
}

// TODO(crbug.com/665924): This function bypasses all Handle*Event path.
// It should be using that flow instead of creating/sending events directly.
WebInputEventResult EventHandler::HandleTargetedMouseEvent(
    Element* target,
    const WebMouseEvent& event,
    const AtomicString& mouse_event_type,
    const Vector<WebMouseEvent>& coalesced_events,
    const Vector<WebMouseEvent>& predicted_events) {
  mouse_event_manager_->SetClickCount(event.click_count);
  return pointer_event_manager_->DirectDispatchMousePointerEvent(
      target, event, mouse_event_type, coalesced_events, predicted_events);
}

WebInputEventResult EventHandler::HandleGestureEvent(
    const WebGestureEvent& gesture_event) {
  // Propagation to inner frames is handled below this function.
  DCHECK_EQ(frame_, &frame_->LocalFrameRoot());
  DCHECK_NE(0, gesture_event.FrameScale());

  // Gesture scroll events are handled on the compositor thread.
  DCHECK(!gesture_event.IsScrollEvent());

  // Hit test across all frames and do touch adjustment as necessary for the
  // event type.
  GestureEventWithHitTestResults targeted_event =
      TargetGestureEvent(gesture_event);

  return HandleGestureEvent(targeted_event);
}

WebInputEventResult EventHandler::HandleGestureEvent(
    const GestureEventWithHitTestResults& targeted_event) {
  TRACE_EVENT0("input", "EventHandler::handleGestureEvent");
  if (!frame_->GetPage())
    return WebInputEventResult::kNotHandled;

  // Propagation to inner frames is handled below this function.
  DCHECK_EQ(frame_, &frame_->LocalFrameRoot());

  // Non-scrolling related gesture events do a single cross-frame hit-test and
  // jump directly to the inner most frame. This matches handleMousePressEvent
  // etc.
  DCHECK(!targeted_event.Event().IsScrollEvent());

  if (targeted_event.Event().GetType() ==
      WebInputEvent::Type::kGestureShowPress)
    last_show_press_timestamp_ = base::TimeTicks::Now();

  // Update mouseout/leave/over/enter events before jumping directly to the
  // inner most frame.
  if (targeted_event.Event().GetType() == WebInputEvent::Type::kGestureTap)
    UpdateGestureTargetNodeForMouseEvent(targeted_event);

  // Route to the correct frame.
  if (LocalFrame* inner_frame =
          targeted_event.GetHitTestResult().InnerNodeFrame())
    return inner_frame->GetEventHandler().HandleGestureEventInFrame(
        targeted_event);

  // No hit test result, handle in root instance. Perhaps we should just return
  // false instead?
  return gesture_manager_->HandleGestureEventInFrame(targeted_event);
}

WebInputEventResult EventHandler::HandleGestureEventInFrame(
    const GestureEventWithHitTestResults& targeted_event) {
  bool is_tap =
      targeted_event.Event().GetType() == WebInputEvent::Type::kGestureTap;
  if (is_tap && discarded_events_.tap_target != kInvalidDOMNodeId &&
      discarded_events_.tap_target ==
          targeted_event.InnerNode()->GetDomNodeId() &&
      targeted_event.Event().TimeStamp() - discarded_events_.tap_time <
          event_handling_util::kDiscardedEventMistakeInterval) {
    targeted_event.InnerNode()->GetDocument().CountUse(
        WebFeature::kInputEventToRecentlyMovedIframeMistakenlyDiscarded);
  }
  if (event_handling_util::ShouldDiscardEventTargetingFrame(
          targeted_event.Event(), *frame_)) {
    if (is_tap) {
      discarded_events_.tap_target = targeted_event.InnerNode()->GetDomNodeId();
      discarded_events_.tap_time = targeted_event.Event().TimeStamp();
    }
    return WebInputEventResult::kHandledSuppressed;
  }
  if (is_tap) {
    discarded_events_.tap_target = kInvalidDOMNodeId;
    discarded_events_.tap_time = base::TimeTicks();
  }
  return gesture_manager_->HandleGestureEventInFrame(targeted_event);
}

void EventHandler::SetMouseDownMayStartAutoscroll() {
  mouse_event_manager_->SetMouseDownMayStartAutoscroll();
}

bool EventHandler::ShouldApplyTouchAdjustment(
    const WebGestureEvent& event) const {
  if (event.primary_pointer_type == WebPointerProperties::PointerType::kPen)
    return false;

  return !event.TapAreaInRootFrame().IsEmpty();
}

void EventHandler::CacheTouchAdjustmentResult(uint32_t id,
                                              gfx::PointF adjusted_point) {
  touch_adjustment_result_.unique_event_id = id;
  touch_adjustment_result_.adjusted_point = adjusted_point;
}

bool EventHandler::GestureCorrespondsToAdjustedTouch(
    const WebGestureEvent& event) {
  // Gesture events start with a GestureTapDown. If GestureTapDown's unique id
  // matches stored adjusted touchstart event id, then we can use the stored
  // result for following gesture event.
  if (event.GetType() == WebInputEvent::Type::kGestureTapDown) {
    should_use_touch_event_adjusted_point_ =
        (event.unique_touch_event_id != 0 &&
         event.unique_touch_event_id ==
             touch_adjustment_result_.unique_event_id);
  }

  // Check if the adjusted point is in the gesture event tap rect.
  // If not, should not use this touch point in following events.
  if (should_use_touch_event_adjusted_point_) {
    gfx::SizeF size = event.TapAreaInRootFrame();
    gfx::RectF tap_rect(
        event.PositionInRootFrame() -
            gfx::Vector2dF(size.width() * 0.5, size.height() * 0.5),
        size);
    should_use_touch_event_adjusted_point_ =
        tap_rect.InclusiveContains(touch_adjustment_result_.adjusted_point);
  }

  return should_use_touch_event_adjusted_point_;
}

bool EventHandler::BestNodeForHitTestResult(
    TouchAdjustmentCandidateType candidate_type,
    const HitTestLocation& location,
    const HitTestResult& result,
    gfx::Point& adjusted_point,
    Node*& adjusted_node) {
  TRACE_EVENT0("input", "EventHandler::BestNodeForHitTestResult");
  CHECK(location.IsRectBasedTest());

  // If the touch is over a scrollbar or a resizer, we don't adjust the touch
  // point.  This is because touch adjustment only takes into account DOM nodes
  // so a touch over a scrollbar or a resizer would be adjusted towards a nearby
  // DOM node, making the scrollbar/resizer unusable.
  //
  // Context-menu hittests are excluded from this consideration because a
  // right-click/long-press doesn't drag the scrollbar therefore prefers DOM
  // nodes with relevant contextmenu properties.
  if (candidate_type != TouchAdjustmentCandidateType::kContextMenu &&
      (result.GetScrollbar() || result.IsOverResizer())) {
    return false;
  }

  gfx::Point touch_hotspot =
      frame_->View()->ConvertToRootFrame(location.RoundedPoint());
  gfx::Rect touch_rect =
      frame_->View()->ConvertToRootFrame(location.ToEnclosingRect());

  if (touch_rect.IsEmpty()) {
    return false;
  }

  CHECK(location.BoundingBox().Contains(location.Point()) ||
        (location.BoundingBox().Right() == LayoutUnit::Max() &&
         location.Point().left == LayoutUnit::Max()) ||
        (location.BoundingBox().Bottom() == LayoutUnit::Max() &&
         location.Point().top == LayoutUnit::Max()));

  HeapVector<Member<Node>, 11> nodes(result.ListBasedTestResult());

  return FindBestTouchAdjustmentCandidate(candidate_type, adjusted_node,
                                          adjusted_point, touch_hotspot,
                                          touch_rect, nodes);
}

// Update the hover and active state across all frames.  This logic is
// different than the mouse case because mice send MouseLeave events to frames
// as they're exited.  With gestures or manual applications, a single event
// conceptually both 'leaves' whatever frame currently had hover and enters a
// new frame so we need to update state in the old frame chain as well.
void EventHandler::UpdateCrossFrameHoverActiveState(bool is_active,
                                                    Element* inner_element) {
  DCHECK_EQ(frame_, &frame_->LocalFrameRoot());

  HeapVector<Member<LocalFrame>> new_hover_frame_chain;
  LocalFrame* new_hover_frame_in_document =
      inner_element ? inner_element->GetDocument().GetFrame() : nullptr;
  // Insert the ancestors of the frame having the new hovered element to the
  // frame chain.  The frame chain doesn't include the main frame to avoid the
  // redundant work that cleans the hover state because the hover state for the
  // main frame is updated by calling Document::UpdateHoverActiveState.
  while (new_hover_frame_in_document && new_hover_frame_in_document != frame_) {
    new_hover_frame_chain.push_back(new_hover_frame_in_document);
    Frame* parent_frame = new_hover_frame_in_document->Tree().Parent();
    new_hover_frame_in_document = DynamicTo<LocalFrame>(parent_frame);
  }

  Element* old_hover_element_in_cur_doc = frame_->GetDocument()->HoverElement();
  Element* new_innermost_hover_element = inner_element;

  if (new_innermost_hover_element != old_hover_element_in_cur_doc) {
    wtf_size_t index_frame_chain = new_hover_frame_chain.size();

    // Clear the hover state on any frames which are no longer in the frame
    // chain of the hovered element.
    while (old_hover_element_in_cur_doc &&
           old_hover_element_in_cur_doc->IsFrameOwnerElement()) {
      LocalFrame* new_hover_frame = nullptr;
      // If we can't get the frame from the new hover frame chain,
      // the newHoverFrame will be null and the old hover state will be cleared.
      if (index_frame_chain > 0)
        new_hover_frame = new_hover_frame_chain[--index_frame_chain];

      auto* owner = To<HTMLFrameOwnerElement>(old_hover_element_in_cur_doc);
      LocalFrame* old_hover_frame =
          DynamicTo<LocalFrame>(owner->ContentFrame());
      if (!old_hover_frame)
        break;

      Document* doc = old_hover_frame->GetDocument();
      if (!doc)
        break;

      old_hover_element_in_cur_doc = doc->HoverElement();
      // If the old hovered frame is different from the new hovered frame.
      // we should clear the old hovered element from the old hovered frame.
      if (new_hover_frame != old_hover_frame) {
        doc->UpdateHoverActiveState(is_active,
                                    /*update_active_chain=*/true, nullptr);
      }
    }
  }

  // Recursively set the new active/hover states on every frame in the chain of
  // innerElement.
  frame_->GetDocument()->UpdateHoverActiveState(is_active,
                                                /*update_active_chain=*/true,
                                                inner_element);
}

// Update the mouseover/mouseenter/mouseout/mouseleave events across all frames
// for this gesture, before passing the targeted gesture event directly to a hit
// frame.
void EventHandler::UpdateGestureTargetNodeForMouseEvent(
    const GestureEventWithHitTestResults& targeted_event) {
  DCHECK_EQ(frame_, &frame_->LocalFrameRoot());

  // Behaviour of this function is as follows:
  // - Create the chain of all entered frames.
  // - Compare the last frame chain under the gesture to newly entered frame
  //   chain from the main frame one by one.
  // - If the last frame doesn't match with the entered frame, then create the
  //   chain of exited frames from the last frame chain.
  // - Dispatch mouseout/mouseleave events of the exited frames from the inside
  //   out.
  // - Dispatch mouseover/mouseenter events of the entered frames into the
  //   inside.

  // Insert the ancestors of the frame having the new target node to the entered
  // frame chain.
  HeapVector<Member<LocalFrame>, 2> entered_frame_chain;
  LocalFrame* entered_frame_in_document =
      targeted_event.GetHitTestResult().InnerNodeFrame();
  while (entered_frame_in_document) {
    entered_frame_chain.push_back(entered_frame_in_document);
    Frame* parent_frame = entered_frame_in_document->Tree().Parent();
    entered_frame_in_document = DynamicTo<LocalFrame>(parent_frame);
  }

  wtf_size_t index_entered_frame_chain = entered_frame_chain.size();
  LocalFrame* exited_frame_in_document = frame_;
  HeapVector<Member<LocalFrame>, 2> exited_frame_chain;
  // Insert the frame from the disagreement between last frames and entered
  // frames.
  while (exited_frame_in_document) {
    Node* last_node_under_tap =
        exited_frame_in_document->GetEventHandler()
            .mouse_event_manager_->GetElementUnderMouse();
    if (!last_node_under_tap)
      break;

    LocalFrame* next_exited_frame_in_document = nullptr;
    if (auto* owner = DynamicTo<HTMLFrameOwnerElement>(last_node_under_tap)) {
      next_exited_frame_in_document =
          DynamicTo<LocalFrame>(owner->ContentFrame());
    }

    if (exited_frame_chain.size() > 0) {
      exited_frame_chain.push_back(exited_frame_in_document);
    } else {
      LocalFrame* last_entered_frame_in_document =
          index_entered_frame_chain
              ? entered_frame_chain[index_entered_frame_chain - 1]
              : nullptr;
      if (exited_frame_in_document != last_entered_frame_in_document)
        exited_frame_chain.push_back(exited_frame_in_document);
      else if (next_exited_frame_in_document && index_entered_frame_chain)
        --index_entered_frame_chain;
    }
    exited_frame_in_document = next_exited_frame_in_document;
  }

  const WebGestureEvent& gesture_event = targeted_event.Event();
  unsigned modifiers = gesture_event.GetModifiers();
  WebMouseEvent fake_mouse_move(
      WebInputEvent::Type::kMouseMove, gesture_event,
      WebPointerProperties::Button::kNoButton,
      /* clickCount */ 0,
      modifiers | WebInputEvent::Modifiers::kIsCompatibilityEventForTouch,
      gesture_event.TimeStamp());

  // Update the mouseout/mouseleave event
  wtf_size_t index_exited_frame_chain = exited_frame_chain.size();
  while (index_exited_frame_chain) {
    LocalFrame* leave_frame = exited_frame_chain[--index_exited_frame_chain];
    leave_frame->GetEventHandler().mouse_event_manager_->SetElementUnderMouse(
        EffectiveMouseEventTargetElement(nullptr), fake_mouse_move);
  }

  // update the mouseover/mouseenter event
  while (index_entered_frame_chain) {
    Frame* parent_frame =
        entered_frame_chain[--index_entered_frame_chain]->Tree().Parent();
    if (auto* parent_local_frame = DynamicTo<LocalFrame>(parent_frame)) {
      parent_local_frame->GetEventHandler()
          .mouse_event_manager_->SetElementUnderMouse(
              EffectiveMouseEventTargetElement(To<HTMLFrameOwnerElement>(
                  entered_frame_chain[index_entered_frame_chain]->Owner())),
              fake_mouse_move);
    }
  }
}

GestureEventWithHitTestResults EventHandler::TargetGestureEvent(
    const WebGestureEvent& gesture_event,
    bool read_only) {
  TRACE_EVENT0("input", "EventHandler::targetGestureEvent");

  DCHECK_EQ(frame_, &frame_->LocalFrameRoot());
  // Scrolling events get hit tested per frame (like wheel events do).
  DCHECK(!gesture_event.IsScrollEvent());

  HitTestRequest::HitTestRequestType hit_type =
      gesture_manager_->GetHitTypeForGestureType(gesture_event.GetType());
  base::TimeDelta active_interval;
  bool should_keep_active_for_min_interval = false;
  if (read_only) {
    hit_type |= HitTestRequest::kReadOnly;
  } else if (gesture_event.GetType() == WebInputEvent::Type::kGestureTap &&
             last_show_press_timestamp_) {
    // If the Tap is received very shortly after ShowPress, we want to
    // delay clearing of the active state so that it's visible to the user
    // for at least a couple of frames.
    active_interval =
        base::TimeTicks::Now() - last_show_press_timestamp_.value();
    should_keep_active_for_min_interval =
        active_interval < kMinimumActiveInterval;
    if (should_keep_active_for_min_interval)
      hit_type |= HitTestRequest::kReadOnly;
  }

  GestureEventWithHitTestResults event_with_hit_test_results =
      HitTestResultForGestureEvent(gesture_event, hit_type);
  // Now apply hover/active state to the final target.
  HitTestRequest request(hit_type | HitTestRequest::kAllowChildFrameContent);
  if (!request.ReadOnly()) {
    UpdateCrossFrameHoverActiveState(
        request.Active(),
        event_with_hit_test_results.GetHitTestResult().InnerElement());
  }

  if (should_keep_active_for_min_interval) {
    last_deferred_tap_element_ =
        event_with_hit_test_results.GetHitTestResult().InnerElement();
    // TODO(https://crbug.com/668758): Use a normal BeginFrame update for this.
    active_interval_timer_.StartOneShot(
        kMinimumActiveInterval - active_interval, FROM_HERE);
  }

  return event_with_hit_test_results;
}

GestureEventWithHitTestResults EventHandler::HitTestResultForGestureEvent(
    const WebGestureEvent& gesture_event,
    HitTestRequest::HitTestRequestType hit_type) {
  // Perform the rect-based hit-test (or point-based if adjustment is
  // disabled). Note that we don't yet apply hover/active state here because
  // we need to resolve touch adjustment first so that we apply hover/active
  // it to the final adjusted node.
  hit_type |= HitTestRequest::kReadOnly;
  WebGestureEvent adjusted_event = gesture_event;
  PhysicalSize hit_rect_size;
  if (ShouldApplyTouchAdjustment(gesture_event)) {
    // If gesture_event unique id matches the stored touch event result, do
    // point-base hit test. Otherwise add padding and do rect-based hit test.
    if (GestureCorrespondsToAdjustedTouch(gesture_event)) {
      adjusted_event.ApplyTouchAdjustment(
          touch_adjustment_result_.adjusted_point);
    } else {
      gfx::SizeF tap_area = adjusted_event.TapAreaInRootFrame();
      hit_rect_size = GetHitTestRectForAdjustment(
          *frame_, PhysicalSize(LayoutUnit(tap_area.width()),
                                LayoutUnit(tap_area.height())));
      if (!hit_rect_size.IsEmpty())
        hit_type |= HitTestRequest::kListBased;
    }
  }

  HitTestLocation location;
  LocalFrame& root_frame = frame_->LocalFrameRoot();
  HitTestResult hit_test_result;
  if (hit_rect_size.IsEmpty()) {
    location = HitTestLocation(adjusted_event.PositionInRootFrame());
    hit_test_result = root_frame.GetEventHandler().HitTestResultAtLocation(
        location, hit_type);
  } else {
    PhysicalOffset top_left =
        PhysicalOffset::FromPointFRound(adjusted_event.PositionInRootFrame());
    top_left -= PhysicalOffset(LayoutUnit(hit_rect_size.width * 0.5f),
                               LayoutUnit(hit_rect_size.height * 0.5f));
    location = HitTestLocation(PhysicalRect(top_left, hit_rect_size));
    hit_test_result = root_frame.GetEventHandler().HitTestResultAtLocation(
        location, hit_type);

    // Adjust the location of the gesture to the most likely nearby node, as
    // appropriate for the type of event.
    ApplyTouchAdjustment(&adjusted_event, location, hit_test_result);
    // Do a new hit-test at the (adjusted) gesture coordinates. This is
    // necessary because rect-based hit testing and touch adjustment sometimes
    // return a different node than what a point-based hit test would return for
    // the same point.
    // FIXME: Fix touch adjustment to avoid the need for a redundant hit test.
    // http://crbug.com/398914
    LocalFrame* hit_frame = hit_test_result.InnerNodeFrame();
    if (!hit_frame)
      hit_frame = frame_;
    location = HitTestLocation(adjusted_event.PositionInRootFrame());
    hit_test_result = root_frame.GetEventHandler().HitTestResultAtLocation(
        location,
        (hit_type | HitTestRequest::kReadOnly) & ~HitTestRequest::kListBased);
  }

  // If we did a rect-based hit test it must be resolved to the best single node
  // by now to ensure consumers don't accidentally use one of the other
  // candidates.
  DCHECK(!location.IsRectBasedTest());

  return GestureEventWithHitTestResults(adjusted_event, location,
                                        hit_test_result);
}

void EventHandler::ApplyTouchAdjustment(WebGestureEvent* gesture_event,
                                        HitTestLocation& location,
                                        HitTestResult& hit_test_result) {
  TouchAdjustmentCandidateType touch_adjustment_candiate_type =
      TouchAdjustmentCandidateType::kClickable;
  switch (gesture_event->GetType()) {
    case WebInputEvent::Type::kGestureTap:
    case WebInputEvent::Type::kGestureTapUnconfirmed:
    case WebInputEvent::Type::kGestureTapDown:
    case WebInputEvent::Type::kGestureShowPress:
      break;
    case WebInputEvent::Type::kGestureShortPress:
    case WebInputEvent::Type::kGestureLongPress:
    case WebInputEvent::Type::kGestureLongTap:
    case WebInputEvent::Type::kGestureTwoFingerTap:
      touch_adjustment_candiate_type =
          TouchAdjustmentCandidateType::kContextMenu;
      break;
    default:
      NOTREACHED();
  }

  Node* adjusted_node = nullptr;
  gfx::Point adjusted_point;
  if (BestNodeForHitTestResult(touch_adjustment_candiate_type, location,
                               hit_test_result, adjusted_point,
                               adjusted_node)) {
    // Update the hit-test result to be a point-based result instead of a
    // rect-based result.
    PhysicalOffset point(frame_->View()->ConvertFromRootFrame(adjusted_point));
    DCHECK(location.ContainsPoint(gfx::PointF(point)));
    DCHECK(location.IsRectBasedTest());
    location = hit_test_result.ResolveRectBasedTest(adjusted_node, point);
    gesture_event->ApplyTouchAdjustment(
        gfx::PointF(adjusted_point.x(), adjusted_point.y()));
  }
}

WebInputEventResult EventHandler::SendContextMenuEvent(
    const WebMouseEvent& event,
    Element* override_target_element) {
  LocalFrameView* v = frame_->View();
  if (!v)
    return WebInputEventResult::kNotHandled;

  // Clear mouse press state to avoid initiating a drag while context menu is
  // up.
  mouse_event_manager_->ReleaseMousePress();
  if (last_scrollbar_under_mouse_)
    last_scrollbar_under_mouse_->MouseUp(event);

  PhysicalOffset position_in_contents(v->ConvertFromRootFrame(
      gfx::ToFlooredPoint(event.PositionInRootFrame())));
  HitTestRequest request(HitTestRequest::kActive);
  MouseEventWithHitTestResults mev =
      frame_->GetDocument()->PerformMouseEventHitTest(
          request, position_in_contents, event);
  // Since |Document::performMouseEventHitTest()| modifies layout tree for
  // setting hover element, we need to update layout tree for requirement of
  // |SelectionController::sendContextMenuEvent()|.
  frame_->GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kContextMenu);

  Element* target_element =
      override_target_element ? override_target_element : mev.InnerElement();
  return mouse_event_manager_->DispatchMouseEvent(
      EffectiveMouseEventTargetElement(target_element),
      event_type_names::kContextmenu, event, nullptr, nullptr, false, event.id,
      PointerEventFactory::PointerTypeNameForWebPointPointerType(
          event.pointer_type));
}

static bool ShouldShowContextMenuAtSelection(const FrameSelection& selection) {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  selection.GetDocument().UpdateStyleAndLayout(
      DocumentUpdateReason::kContextMenu);

  const VisibleSelection& visible_selection =
      selection.ComputeVisibleSelectionInDOMTree();
  if (!visible_selection.IsRange() && !visible_selection.RootEditableElement())
    return false;
  return selection.SelectionHasFocus();
}

WebInputEventResult EventHandler::ShowNonLocatedContextMenu(
    Element* override_target_element,
    WebMenuSourceType source_type) {
  LocalFrameView* view = frame_->View();
  if (!view)
    return WebInputEventResult::kNotHandled;

  Document* doc = frame_->GetDocument();
  if (!doc)
    return WebInputEventResult::kNotHandled;

  static const int kContextMenuMargin = 1;

  gfx::Point location_in_root_frame;

  Element* focused_element =
      override_target_element ? override_target_element : doc->FocusedElement();
  FrameSelection& selection = frame_->Selection();
  VisualViewport& visual_viewport = frame_->GetPage()->GetVisualViewport();

  if (!override_target_element && ShouldShowContextMenuAtSelection(selection)) {
    DCHECK(!doc->NeedsLayoutTreeUpdate());

    // Enclose the selection rect fully between the handles. If the handles are
    // on the same line, the selection rect is empty.
    const SelectionInDOMTree& visible_selection =
        selection.ComputeVisibleSelectionInDOMTree().AsSelection();
    const PositionWithAffinity start_position(
        visible_selection.ComputeStartPosition(), visible_selection.Affinity());
    const gfx::Point start_point =
        GetMiddleSelectionCaretOfPosition(start_position);
    const PositionWithAffinity end_position(
        visible_selection.ComputeEndPosition(), visible_selection.Affinity());
    const gfx::Point end_point =
        GetMiddleSelectionCaretOfPosition(end_position);

    int left = std::min(start_point.x(), end_point.x());
    int top = std::min(start_point.y(), end_point.y());
    int right = std::max(start_point.x(), end_point.x());
    int bottom = std::max(start_point.y(), end_point.y());

    // If selection is a caret and is inside an anchor element, then set that
    // as the "focused" element so we can show "open link" option in context
    // menu.
    if (visible_selection.IsCaret()) {
      Element* anchor_element =
          EnclosingAnchorElement(visible_selection.ComputeStartPosition());
      if (anchor_element)
        focused_element = anchor_element;
    }
    // Intersect the selection rect and the visible bounds of focused_element.
    if (focused_element) {
      gfx::Rect clipped_rect = view->ConvertFromRootFrame(
          GetFocusedElementRectForNonLocatedContextMenu(focused_element));
      left = std::max(clipped_rect.x(), left);
      top = std::max(clipped_rect.y(), top);
      right = std::min(clipped_rect.right(), right);
      bottom = std::min(clipped_rect.bottom(), bottom);
    }
    gfx::Rect selection_rect = gfx::Rect(left, top, right - left, bottom - top);

    if (ContainsEvenAtEdge(selection_rect, start_point)) {
      location_in_root_frame = view->ConvertToRootFrame(start_point);
    } else if (ContainsEvenAtEdge(selection_rect, end_point)) {
      location_in_root_frame = view->ConvertToRootFrame(end_point);
    } else {
      location_in_root_frame =
          view->ConvertToRootFrame(selection_rect.CenterPoint());
    }
  } else if (focused_element) {
    gfx::Rect clipped_rect =
        GetFocusedElementRectForNonLocatedContextMenu(focused_element);
    location_in_root_frame = clipped_rect.CenterPoint();
  } else {
    // TODO(crbug.com/1274078): Should this use ScrollPosition()?
    location_in_root_frame =
        gfx::Point(visual_viewport.GetScrollOffset().x() + kContextMenuMargin,
                   visual_viewport.GetScrollOffset().y() + kContextMenuMargin);
  }

  frame_->View()->SetCursor(PointerCursor());
  gfx::Point global_position =
      view->GetChromeClient()
          ->LocalRootToScreenDIPs(
              gfx::Rect(location_in_root_frame, gfx::Size()), frame_->View())
          .origin();

  // Use the focused node as the target for hover and active.
  HitTestRequest request(HitTestRequest::kActive);
  HitTestLocation location(location_in_root_frame);
  HitTestResult result(request, location);
  result.SetInnerNode(focused_element ? static_cast<Node*>(focused_element)
                                      : doc);
  doc->UpdateHoverActiveState(request.Active(), !request.Move(),
                              result.InnerElement());

  // The contextmenu event is a mouse event even when invoked using the
  // keyboard.  This is required for web compatibility.
  WebInputEvent::Type event_type = WebInputEvent::Type::kMouseDown;
  if (frame_->GetSettings() &&
      frame_->GetSettings()->GetShowContextMenuOnMouseUp())
    event_type = WebInputEvent::Type::kMouseUp;

  WebMouseEvent mouse_event(
      event_type,
      gfx::PointF(location_in_root_frame.x(), location_in_root_frame.y()),
      gfx::PointF(global_position.x(), global_position.y()),
      WebPointerProperties::Button::kNoButton, /* clickCount */ 0,
      WebInputEvent::kNoModifiers, base::TimeTicks::Now(), source_type);
  mouse_event.id = PointerEventFactory::kMouseId;

  // TODO(dtapuska): Transition the mouseEvent to be created really in viewport
  // coordinates instead of root frame coordinates.
  mouse_event.SetFrameScale(1);

  return SendContextMenuEvent(mouse_event, focused_element);
}

gfx::Rect EventHandler::GetFocusedElementRectForNonLocatedContextMenu(
    Element* focused_element) {
  gfx::Rect visible_rect = focused_element->VisibleBoundsInLocalRoot();

  VisualViewport& visual_viewport = frame_->GetPage()->GetVisualViewport();

  // TODO(bokan): This method may not work as expected when the local root
  // isn't the main frame since the result won't be transformed and clipped by
  // the visual viewport (which is accessible only from the outermost main
  // frame).
  if (frame_->LocalFrameRoot().IsOutermostMainFrame()) {
    visible_rect = visual_viewport.RootFrameToViewport(visible_rect);
    visible_rect.Intersect(gfx::Rect(visual_viewport.Size()));
  }

  gfx::Rect clipped_rect = visible_rect;
  // The bounding rect of multiline elements may include points that are
  // not within the element. Intersect the clipped rect with the first
  // outline rect to ensure that the selection rect only includes visible
  // points within the focused element.
  Vector<gfx::Rect> outline_rects = focused_element->OutlineRectsInWidget();
  if (outline_rects.size() > 1)
    clipped_rect.Intersect(outline_rects[0]);

  return visual_viewport.ViewportToRootFrame(clipped_rect);
}

void EventHandler::ScheduleHoverStateUpdate() {
  // TODO(https://crbug.com/668758): Use a normal BeginFrame update for this.
  if (!hover_timer_.IsActive() &&
      !mouse_event_manager_->IsMousePositionUnknown())
    hover_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void EventHandler::ScheduleCursorUpdate() {
  // We only want one timer for the page, rather than each frame having it's own
  // timer competing which eachother (since there's only one mouse cursor).
  DCHECK_EQ(frame_, &frame_->LocalFrameRoot());

  // TODO(https://crbug.com/668758): Use a normal BeginFrame update for this.
  if (!cursor_update_timer_.IsActive())
    cursor_update_timer_.StartOneShot(kCursorUpdateInterval, FROM_HERE);
}

bool EventHandler::CursorUpdatePending() {
  return cursor_update_timer_.IsActive();
}

bool EventHandler::IsHandlingKeyEvent() const {
  return keyboard_event_manager_->is_handling_key_event();
}

void EventHandler::SetResizingFrameSet(HTMLFrameSetElement* frame_set) {
  CaptureMouseEventsToWidget(true);
  frame_set_being_resized_ = frame_set;
}

void EventHandler::ResizeScrollableAreaDestroyed() {
  scroll_manager_->ClearResizeScrollableArea(true);
}

void EventHandler::HoverTimerFired(TimerBase*) {
  TRACE_EVENT0("input", "EventHandler::hoverTimerFired");

  DCHECK(frame_);
  DCHECK(frame_->GetDocument());

  if (auto* layout_object = frame_->ContentLayoutObject()) {
    if (LocalFrameView* view = frame_->View()) {
      HitTestRequest request(HitTestRequest::kMove);
      HitTestLocation location(view->ViewportToFrame(
      
"""


```