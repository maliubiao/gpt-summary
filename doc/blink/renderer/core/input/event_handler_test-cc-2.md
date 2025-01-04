Response:
The user wants a summary of the functionalities of the provided C++ code snippet, which is a part of a larger test file for the Chromium Blink engine's `EventHandler`. I need to extract the distinct test cases and describe what aspect of the `EventHandler` they are testing. Specifically, I need to address the relationship to Javascript, HTML, and CSS, provide input/output examples for logical reasoning, discuss common user/programming errors, and describe user interactions leading to these code sections.

Here's a breakdown of the code's functionalities:

1. **Tooltip Handling after Focus Change:** Tests if a tooltip remains visible after programmatically moving focus to a different element.
2. **Unbuffered Input Events:** Checks if the `EventHandler` correctly requests unbuffered input events from the browser when a canvas element indicates it needs them.
3. **Scroll End Event Generation:** Verifies that a `GestureScrollEnd` event is generated when a mouse button is released off a scrollbar after pressing it down on the scrollbar. It also checks that no scroll events are generated for right-clicks on the scrollbar.
4. **Scroll Snapping with Gesture Tap:** Tests that scroll snapping animations are not immediately cancelled after a gesture tap on a scrollbar.
5. **Mouse Leave and Mouse Position Unknown:** Checks if the `EventHandler` correctly marks the mouse position as unknown when the mouse leaves the window or an iframe.
6. **Cursor Style Before Dragging:** Verifies that the cursor style remains unchanged for a draggable element when the mouse is moved slightly after a mouse down, before dragging starts.
7. **Tap and Active State in Iframe:** Tests if a tap gesture within an iframe correctly activates an element within that iframe.
8. **Updating Hover After Compositor Scroll:** Verifies that hover states are updated after a compositor-driven scroll finishes.
9. **Updating Hover After Javascript Scroll:** Checks that hover states are updated after a Javascript-driven smooth scroll completes.
10. **Large Custom Cursor Intersection:** Tests if a large custom cursor is correctly detected as intersecting the viewport.
11. **Small Custom Cursor Intersection:** Verifies that a small custom cursor is also correctly detected as intersecting the viewport.
12. **Suppressing Key Events for Javascript:**  This test case seems incomplete in the provided snippet.

Now, I'll structure the response to cover each of these points, relating them to web technologies, providing examples, and addressing potential errors and user interactions.
这是`blink/renderer/core/input/event_handler_test.cc`文件的第三部分，主要包含以下功能：

**1. 测试焦点改变后 Tooltip 的显示:**

* **功能:**  验证当鼠标悬停在一个元素上显示 tooltip 后，如果通过编程方式将焦点移动到另一个元素，tooltip 是否仍然保持显示。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:** 测试中使用了 HTML 元素 (`<a id='a1' title='tooltip'></a>` 和 `<button id='b2'></button>`) 来创建带有 tooltip 的链接和按钮。
    * **Javascript:**  虽然没有直接的 Javascript 代码，但测试逻辑模拟了 Javascript 中 `element.focus()` 的行为来移动焦点。
    * **CSS:**  tooltip 的显示样式通常由浏览器默认提供或可以通过 CSS 进行自定义。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 用户鼠标悬停在 ID 为 `a1` 的链接上。
        2. 代码通过 `GetDocument().getElementById(AtomicString("b2"))->Focus();` 将焦点移动到 ID 为 `b2` 的按钮上。
    * **预期输出:**
        1. 在鼠标悬停时，`LastToolTipText()` 返回 "tooltip"。
        2. 在焦点移动后，`LastToolTipText()` 仍然返回 "tooltip"。
* **用户或编程常见的使用错误:**
    * 开发者可能错误地认为在焦点改变后 tooltip 会自动消失，从而在 Javascript 中编写额外的隐藏 tooltip 的代码，但这可能导致不一致的行为。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户在浏览器中打开一个包含带有 `title` 属性的链接和另一个可聚焦元素（例如按钮）的网页。
    2. 用户将鼠标指针移动到链接上，触发 tooltip 显示。
    3. 网页上的 Javascript 代码（或者浏览器自身的某些行为）调用了另一个元素的 `focus()` 方法。
    4. 该测试用例模拟了这一系列事件，以确保 `EventHandler` 的行为符合预期。

**2. 测试需要非缓冲输入事件 (Unbuffered Input Events) 的请求:**

* **功能:**  验证当一个 canvas 元素调用 `setNeedsUnbufferedInputEvents(true)` 后，`EventHandler` 是否会请求非缓冲输入事件。这通常用于需要高精度和低延迟输入处理的场景，例如在 canvas 上进行绘制。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:** 使用 `<canvas>` 元素。
    * **Javascript:**  测试中模拟了 Javascript 调用 `canvas.setNeedsUnbufferedInputEvents(true)` 的行为。`onpointermove='return;'`  属性也可能包含 Javascript 代码。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 创建一个带有 `onpointermove` 事件处理的 canvas 元素。
        2. 模拟鼠标按下事件。
        3. 调用 `canvas.setNeedsUnbufferedInputEvents(true)`。
        4. 再次模拟鼠标按下事件。
        5. 调用 `canvas.setNeedsUnbufferedInputEvents(false)`。
        6. 再次模拟鼠标按下事件。
    * **预期输出:**
        1. 首次鼠标按下后，`chrome_client_->ReceivedRequestForUnbufferedInput()` 返回 `false`。
        2. 调用 `setNeedsUnbufferedInputEvents(true)` 后的鼠标按下，`chrome_client_->ReceivedRequestForUnbufferedInput()` 返回 `true`。
        3. 调用 `setNeedsUnbufferedInputEvents(false)` 后的鼠标按下，`chrome_client_->ReceivedRequestForUnbufferedInput()` 返回 `false`。
* **用户或编程常见的使用错误:**
    * 开发者可能在需要高精度输入处理的 canvas 上忘记调用 `setNeedsUnbufferedInputEvents(true)`，导致输入事件被缓冲，产生延迟。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户在浏览器中打开一个包含 canvas 元素的网页。
    2. 网页上的 Javascript 代码根据某些条件（例如，用户开始在 canvas 上进行交互）调用了 canvas 元素的 `setNeedsUnbufferedInputEvents(true)` 方法。
    3. 用户在 canvas 上进行鼠标操作（例如按下鼠标）。
    4. 测试验证 Blink 引擎是否正确处理了对非缓冲输入事件的请求。

**3. 测试鼠标在滚动条外部抬起时生成滚动结束事件:**

* **功能:**  验证当鼠标在滚动条上按下，然后移动到滚动条外部并抬起时，`EventHandler` 是否会生成 `GestureScrollEnd` 事件。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  创建了一个高度超出视口的内容 (`<div style='height:1000px'>`)，从而触发滚动条的显示。
    * **Javascript:**  测试本身不涉及 Javascript 代码的执行，但被测试的行为是浏览器处理用户与滚动条交互的一部分。
    * **CSS:**  CSS 用于设置内容的高度，从而触发滚动条的出现。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 页面内容高度超出视口，显示滚动条。
        2. 鼠标在滚动条轨道上按下 (`kMouseDown`)。
        3. 鼠标移动到页面内容区域 (`kMouseMove`)。
        4. 鼠标在页面内容区域抬起 (`kMouseUp`)。
    * **预期输出:**
        1. 在滚动条上按下鼠标会生成 `GestureScrollBegin` 和 `GestureScrollUpdate` 事件（如果滚动条允许命中测试）。
        2. 鼠标移动不会生成额外的滚动事件。
        3. 鼠标抬起会生成 `GestureScrollEnd` 事件。
* **用户或编程常见的使用错误:**
    * 开发者可能依赖于特定的滚动事件顺序，而没有考虑到用户可能在滚动操作过程中将鼠标移出滚动条的情况。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个内容超出视口的网页，浏览器显示滚动条。
    2. 用户将鼠标指针移动到滚动条的轨道上并按下鼠标左键。
    3. 用户在不松开鼠标左键的情况下，将鼠标指针移动到页面内容区域。
    4. 用户松开鼠标左键。
    5. 测试验证在此场景下是否正确生成了 `GestureScrollEnd` 事件。

**4. 测试只在滚动条上抬起鼠标的情况:**

* **功能:** 验证当鼠标在页面内容区域按下，然后移动到滚动条上并抬起时，`EventHandler` 不会生成 `GestureScrollEnd` 事件，因为没有 `GestureScrollBegin` 事件在滚动条上触发。
* **与 Javascript, HTML, CSS 的关系:**  与上述滚动条测试类似。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 页面内容高度超出视口，显示滚动条。
        2. 鼠标在页面内容区域按下 (`kMouseDown`)。
        3. 鼠标移动到滚动条轨道上 (`kMouseMove`)。
        4. 鼠标在滚动条轨道上抬起 (`kMouseUp`)。
    * **预期输出:**  不会生成任何滚动相关的 `Gesture` 事件。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个内容超出视口的网页。
    2. 用户将鼠标指针移动到页面内容区域并按下鼠标左键。
    3. 用户在不松开鼠标左键的情况下，将鼠标指针移动到滚动条的轨道上。
    4. 用户松开鼠标左键。

**5. 测试右键点击不产生手势事件:**

* **功能:** 验证在滚动条上进行右键点击操作时，`EventHandler` 不会生成任何手势事件。
* **与 Javascript, HTML, CSS 的关系:**  与上述滚动条测试类似。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 页面内容高度超出视口，显示滚动条。
        2. 鼠标在滚动条轨道上按下右键 (`kMouseDown` with right button)。
        3. 鼠标在滚动条轨道上抬起右键 (`kMouseUp` with right button)。
    * **预期输出:**  不会生成任何 `Gesture` 事件。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个内容超出视口的网页。
    2. 用户将鼠标指针移动到滚动条的轨道上。
    3. 用户点击鼠标右键。

**6. 测试带有滚动吸附 (Scroll Snaps) 的手势点击:**

* **功能:**  验证当在一个启用了滚动吸附的滚动容器上通过手势点击滚动条时，`SnapController` 不会立即取消生成的动画。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  创建了一个带有滚动条和启用滚动吸附的容器 (`<div id='container'>`)。
    * **CSS:**  使用了 CSS 属性 `scroll-snap-type: y mandatory;` 和 `scroll-snap-align: start` 来启用和配置滚动吸附。
    * **Javascript:**  虽然没有直接的 Javascript 代码，但测试模拟了手势点击事件，这与用户在触摸设备上的操作类似。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 页面包含一个启用了滚动吸附的滚动容器。
        2. 用户在滚动条上进行手势点击 (`kGestureTapDown` 和 `kGestureTap`)。
    * **预期输出:**
        1. 手势点击会生成 `GestureScrollBegin`、`GestureScrollUpdate` 和 `GestureScrollEnd` 事件。
        2. 在 `GestureScrollEnd` 事件处理后，滚动容器上仍然存在正在运行的动画。
        3. 动画运行一段时间后，滚动停止并吸附到指定的位置。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户在支持触摸的设备上打开一个包含启用滚动吸附的滚动容器的网页。
    2. 用户在滚动条上进行轻触操作。
    3. 测试验证滚动吸附动画是否按预期执行。

**7. 测试离开窗口后鼠标位置变为未知:**

* **功能:** 验证当鼠标离开浏览器窗口时，`EventHandler` 会将鼠标位置标记为未知。
* **与 Javascript, HTML, CSS 的关系:**  主要与浏览器的事件处理机制相关，不直接涉及特定的 HTML 或 CSS 结构。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 鼠标在浏览器窗口内移动并按下。
        2. 鼠标移动到浏览器窗口外。
    * **预期输出:**
        1. 鼠标在窗口内按下后，`IsMousePositionUnknown()` 返回 `false`。
        2. 鼠标离开窗口后，`IsMousePositionUnknown()` 返回 `true`。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个网页。
    2. 用户将鼠标指针移动到网页内容区域并点击。
    3. 用户在不松开鼠标的情况下（或者只是移动鼠标），将鼠标指针移出浏览器窗口的边界。

**8. 测试离开 iframe 后鼠标位置在 iframe 中变为未知:**

* **功能:** 验证当鼠标离开一个 iframe 时，该 iframe 的 `EventHandler` 会将其鼠标位置标记为未知。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  页面包含一个 `<iframe>` 元素。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 鼠标在主文档的 iframe 内部移动。
        2. 鼠标移动到主文档的 iframe 外部。
    * **预期输出:**
        1. 当鼠标在 iframe 内部时，主文档和 iframe 的 `IsMousePositionUnknown()` 都返回 `false`。
        2. 当鼠标移动到 iframe 外部后，iframe 的 `IsMousePositionUnknown()` 返回 `true`，而主文档的仍然为 `false`。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个包含 iframe 的网页。
    2. 用户将鼠标指针移动到 iframe 的内容区域内。
    3. 用户将鼠标指针移动到 iframe 的内容区域外，但仍在主文档的范围内。

**9. 测试拖拽元素开始前光标样式:**

* **功能:** 验证在可拖拽元素上按下鼠标并轻微移动鼠标时，光标样式不会改变，直到实际开始拖拽操作。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  使用了 `draggable='true'` 属性的 `<div>` 元素。
    * **CSS:**  为该 `<div>` 元素设置了 `cursor: help;` 样式。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 用户在一个 `draggable='true'` 的元素上按下鼠标。
        2. 用户轻微移动鼠标，但移动距离不足以触发拖拽开始。
    * **预期输出:**  光标样式仍然是 CSS 中设置的 `help` 样式。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个包含可拖拽元素的网页。
    2. 用户将鼠标指针移动到该元素上并按下鼠标左键。
    3. 用户在不松开鼠标左键的情况下，轻微移动鼠标。

**10. 测试 iframe 中的 Tap 事件应用 Active 状态:**

* **功能:** 验证在 iframe 中的元素上进行 Tap 手势操作时，该元素会被应用 active 状态。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  页面包含一个 `<iframe>` 元素，iframe 内部包含一个 `<div>` 元素。
    * **CSS:**  可能定义了 `:active` 伪类的样式。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 用户在 iframe 内部的 `<div>` 元素上进行 Tap 手势 (`kTapDown` 和 `kTap`)。
    * **预期输出:**
        1. 在 `kTapDown` 和 `kShowPress` 事件后，主文档和 iframe 的 active 元素都被设置为对应的元素。
        2. 在 `kTap` 事件后，active 元素仍然存在。
        3. 经过一段时间后，active 状态被取消。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户在支持触摸的设备上打开一个包含 iframe 的网页。
    2. 用户轻触 iframe 内部的某个元素。

**11. 测试在 Compositor 滚动结束后更新 Hover 状态:**

* **功能:** 验证在 Compositor 驱动的滚动结束后，hover 状态会在下一个 begin frame 时更新。这确保了在滚动过程中 hover 状态不会立即更新，从而避免不必要的重绘。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  包含一些带有 `mouseover` 和 `mouseout` 事件监听器的 `<div>` 元素。
    * **Javascript:**  Javascript 代码用于监听 `mouseover` 和 `mouseout` 事件并修改元素的内容。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 鼠标悬停在第一个 `<div>` 元素上。
        2. 触发 Compositor 滚动。
    * **预期输出:**
        1. 初始状态下，第一个元素显示 "currently hovered"。
        2. 滚动发生后，hover 状态不会立即更新。
        3. 在下一个 begin frame 时，hover 状态更新，第一个元素显示 "was hovered"，而鼠标指针下的新元素显示 "currently hovered"。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个包含可滚动内容的网页，并将鼠标悬停在某个元素上。
    2. 用户通过拖动滚动条或其他方式触发 Compositor 滚动。

**12. 测试在 Javascript 滚动结束后更新 Hover 状态:**

* **功能:** 验证在 Javascript 驱动的平滑滚动结束后，hover 状态会在下一个 begin frame 时更新。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  包含一个可滚动的区域和一个用于 hover 测试的 `<div>` 元素。
    * **Javascript:**  通过 Javascript 代码调用 `scrollable_area->SetScrollOffset` 来触发平滑滚动。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        1. 鼠标悬停在一个 `<div>` 元素上。
        2. 通过 Javascript 代码触发平滑滚动。
    * **预期输出:**
        1. 初始状态下，该元素处于 hover 状态。
        2. 在滚动进行期间，hover 状态不变。
        3. 在滚动结束后，hover 状态在下一个 begin frame 时更新。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个包含可滚动内容的网页，并将鼠标悬停在某个元素上。
    2. 网页上的 Javascript 代码执行滚动操作（例如，响应按钮点击或定时器）。

**13. 测试大型自定义光标是否与视口相交:**

* **功能:** 验证当使用大型自定义光标时，只有当光标的实际绘制区域与视口相交时，才会显示自定义光标，否则会回退到默认光标。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  包含一个覆盖整个视口的 `<div>` 元素。
    * **CSS:**  为该 `<div>` 元素设置了一个大型的自定义光标。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  鼠标指针移动到不同的坐标，有些坐标会导致自定义光标与视口相交，有些则不会。
    * **预期输出:**  当鼠标位置使得自定义光标与视口相交时，光标类型为 `kCustom`，否则为 `kPointer`。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个网页，该网页使用了较大的自定义光标。
    2. 用户移动鼠标指针到页面的不同位置。

**14. 测试小型自定义光标是否与视口相交:**

* **功能:**  与上述大型自定义光标测试类似，但针对小型自定义光标。
* **与 Javascript, HTML, CSS 的关系:**  类似上述测试。
* **逻辑推理 (假设输入与输出):**  类似上述测试。
* **用户操作到达这里的步骤 (调试线索):**  类似上述测试。

**15. 测试永不暴露键盘事件给 Javascript:**

* **功能:** 验证当设置 `DontSendKeyEventsToJavascript` 为 true 时，键盘事件不会被发送到 Javascript。这通常用于某些特殊场景，例如需要浏览器完全控制键盘事件的情况。
* **与 Javascript, HTML, CSS 的关系:**
    * **HTML:**  包含一个输入框和一个用于记录事件的段落。
    * **Javascript:**  Javascript 代码监听 `keydown` 事件并记录事件信息。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  用户在输入框中按下键盘按键。
    * **预期输出:**  由于 `DontSendKeyEventsToJavascript` 被设置为 true，Javascript 的 `keydown` 事件监听器不会被触发，日志区域不会更新。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户打开一个包含输入框的网页。
    2. 网页的设置中启用了 `DontSendKeyEventsToJavascript`。
    3. 用户在输入框中按下键盘按键。

**总结一下这个代码片段的功能:**

这部分 `event_handler_test.cc` 文件主要用于测试 Blink 引擎中 `EventHandler` 组件在处理各种鼠标和触摸输入事件时的行为，包括：

* **鼠标事件处理:**  悬停、点击、移动、离开窗口/iframe，以及与滚动条的交互。
* **焦点管理:**  焦点改变对 tooltip 显示的影响。
* **手势事件处理:**  手势点击与滚动吸附的配合。
* **自定义光标:**  自定义光标是否正确显示，取决于其与视口的相交情况。
* **键盘事件控制:**  控制键盘事件是否发送给 Javascript。
* **非缓冲输入事件:**  按需请求非缓冲输入事件。
* **Hover 状态更新:**  确保 hover 状态在滚动结束后正确更新。
* **Active 状态管理:**  Tap 事件在 iframe 中的 active 状态应用。

这些测试覆盖了用户与网页交互的多个方面，确保了 Blink 引擎能够正确地解释和处理用户的输入，从而提供流畅和一致的用户体验。

Prompt: 
```
这是目录为blink/renderer/core/input/event_handler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
utEvent::kNoModifiers,
      base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  EXPECT_EQ("tooltip", LastToolTipText());

  // Then, programmatically move the focus to another element.
  Element* element = GetDocument().getElementById(AtomicString("b2"));
  element->Focus();

  EXPECT_EQ("tooltip", LastToolTipText());
}

class UnbufferedInputEventsTrackingChromeClient : public EmptyChromeClient {
 public:
  UnbufferedInputEventsTrackingChromeClient() = default;

  void RequestUnbufferedInputEvents(LocalFrame*) override {
    received_unbuffered_request_ = true;
  }

  bool ReceivedRequestForUnbufferedInput() {
    bool value = received_unbuffered_request_;
    received_unbuffered_request_ = false;
    return value;
  }

 private:
  bool received_unbuffered_request_ = false;
};

class EventHandlerLatencyTest : public PageTestBase {
 protected:
  void SetUp() override {
    chrome_client_ =
        MakeGarbageCollected<UnbufferedInputEventsTrackingChromeClient>();
    SetupPageWithClients(chrome_client_);
  }

  void SetHtmlInnerHTML(const char* html_content) {
    GetDocument().documentElement()->setInnerHTML(
        String::FromUTF8(html_content));
    UpdateAllLifecyclePhasesForTest();
  }

  Persistent<UnbufferedInputEventsTrackingChromeClient> chrome_client_;
};

TEST_F(EventHandlerLatencyTest, NeedsUnbufferedInput) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetHtmlInnerHTML(
      "<canvas style='width: 100px; height: 100px' id='first' "
      "onpointermove='return;'>");

  auto& canvas = To<HTMLCanvasElement>(
      *GetDocument().getElementById(AtomicString("first")));

  ASSERT_FALSE(chrome_client_->ReceivedRequestForUnbufferedInput());

  WebMouseEvent mouse_press_event(
      WebInputEvent::Type::kMouseDown, gfx::PointF(51, 50), gfx::PointF(51, 50),
      WebPointerProperties::Button::kLeft, 0, WebInputEvent::kNoModifiers,
      base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_press_event);
  ASSERT_FALSE(chrome_client_->ReceivedRequestForUnbufferedInput());

  canvas.SetNeedsUnbufferedInputEvents(true);

  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_press_event);
  ASSERT_TRUE(chrome_client_->ReceivedRequestForUnbufferedInput());

  canvas.SetNeedsUnbufferedInputEvents(false);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_press_event);
  ASSERT_FALSE(chrome_client_->ReceivedRequestForUnbufferedInput());
}

TEST_F(EventHandlerSimTest, MouseUpOffScrollbarGeneratesScrollEnd) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div style='height:1000px'>
    Tall text to create viewport scrollbar</div>
  )HTML");

  Compositor().BeginFrame();
  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);

  // PageTestBase sizes the page to 800x600. Click on the scrollbar
  // track, move off, then release the mouse and verify that GestureScrollEnd
  // was queued up.

  // If the scrollbar theme does not allow hit testing, we should not get
  // any injected gesture events. Mobile overlay scrollbar theme does not
  // allow hit testing.
  bool scrollbar_theme_allows_hit_test =
      GetDocument().GetPage()->GetScrollbarTheme().AllowsHitTest();

  const gfx::PointF scrollbar_forward_track(795, 560);
  WebMouseEvent mouse_down(WebInputEvent::Type::kMouseDown,
                           scrollbar_forward_track, scrollbar_forward_track,
                           WebPointerProperties::Button::kLeft, 0,
                           WebInputEvent::kNoModifiers, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(mouse_down);

  // Mouse down on the scrollbar track should have generated GSB/GSU.
  if (scrollbar_theme_allows_hit_test) {
    EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 2u);
    EXPECT_EQ(
        GetWebFrameWidget().GetInjectedScrollEvents()[0]->Event().GetType(),
        WebInputEvent::Type::kGestureScrollBegin);
    EXPECT_EQ(
        GetWebFrameWidget().GetInjectedScrollEvents()[1]->Event().GetType(),
        WebInputEvent::Type::kGestureScrollUpdate);
  } else {
    EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);
  }

  const gfx::PointF middle_of_page(100, 100);
  WebMouseEvent mouse_move(WebInputEvent::Type::kMouseMove, middle_of_page,
                           middle_of_page, WebPointerProperties::Button::kLeft,
                           0, WebInputEvent::kNoModifiers,
                           base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  // Mouse move should not have generated any gestures.
  if (scrollbar_theme_allows_hit_test) {
    EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 2u);
  } else {
    EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);
  }

  WebMouseEvent mouse_up(WebInputEvent::Type::kMouseUp, middle_of_page,
                         middle_of_page, WebPointerProperties::Button::kLeft, 0,
                         WebInputEvent::kNoModifiers, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(mouse_up);

  // Mouse up must generate GestureScrollEnd.
  if (scrollbar_theme_allows_hit_test) {
    EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 3u);
    EXPECT_EQ(
        GetWebFrameWidget().GetInjectedScrollEvents()[2]->Event().GetType(),
        WebInputEvent::Type::kGestureScrollEnd);
  } else {
    EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);
  }
}

TEST_F(EventHandlerSimTest, MouseUpOnlyOnScrollbar) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div style='height:1000px'>
    Tall text to create viewport scrollbar</div>
  )HTML");

  Compositor().BeginFrame();

  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);

  // Mouse down on the page, the move the mouse to the scrollbar and release.
  // Validate that we don't inject a ScrollEnd (since no ScrollBegin was
  // injected).

  const gfx::PointF middle_of_page(100, 100);
  WebMouseEvent mouse_down(WebInputEvent::Type::kMouseDown, middle_of_page,
                           middle_of_page, WebPointerProperties::Button::kLeft,
                           0, WebInputEvent::kNoModifiers,
                           base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(mouse_down);

  // Mouse down on the page should not generate scroll gestures.
  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);

  const gfx::PointF scrollbar_forward_track(795, 560);
  WebMouseEvent mouse_move(WebInputEvent::Type::kMouseMove,
                           scrollbar_forward_track, scrollbar_forward_track,
                           WebPointerProperties::Button::kLeft, 0,
                           WebInputEvent::kNoModifiers, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  // Mouse move should not have generated any gestures.
  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);

  WebMouseEvent mouse_up(WebInputEvent::Type::kMouseUp, scrollbar_forward_track,
                         scrollbar_forward_track,
                         WebPointerProperties::Button::kLeft, 0,
                         WebInputEvent::kNoModifiers, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(mouse_up);

  // Mouse up should not have generated any gestures.
  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);
}

TEST_F(EventHandlerSimTest, RightClickNoGestures) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div style='height:1000px'>
    Tall text to create viewport scrollbar</div>
  )HTML");

  Compositor().BeginFrame();

  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);

  // PageTestBase sizes the page to 800x600. Right click on the scrollbar
  // track, and release the mouse and verify that no gesture events are
  // queued up (right click doesn't scroll scrollbars).

  const gfx::PointF scrollbar_forward_track(795, 560);
  WebMouseEvent mouse_down(WebInputEvent::Type::kMouseDown,
                           scrollbar_forward_track, scrollbar_forward_track,
                           WebPointerProperties::Button::kRight, 0,
                           WebInputEvent::kNoModifiers, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(mouse_down);

  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);

  WebMouseEvent mouse_up(WebInputEvent::Type::kMouseUp, scrollbar_forward_track,
                         scrollbar_forward_track,
                         WebPointerProperties::Button::kRight, 0,
                         WebInputEvent::kNoModifiers, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(mouse_up);

  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);
}

// https://crbug.com/976557 tracks the fix for re-enabling this test on Mac.
#if BUILDFLAG(IS_MAC)
#define MAYBE_GestureTapWithScrollSnaps DISABLED_GestureTapWithScrollSnaps
#else
#define MAYBE_GestureTapWithScrollSnaps GestureTapWithScrollSnaps
#endif

TEST_F(EventHandlerSimTest, MAYBE_GestureTapWithScrollSnaps) {
  // Create a page that has scroll snaps enabled for a scroller. Tap on the
  // scrollbar and verify that the SnapController does not immediately cancel
  // the resulting animation during the handling of GestureScrollEnd - this
  // should be deferred until the animation completes or is cancelled.

  // Enable scroll animations - this test relies on animations being
  // queued up in response to GestureScrollUpdate events.
  GetDocument().GetSettings()->SetScrollAnimatorEnabled(true);

  // Enable accelerated compositing in order to ensure the Page's
  // ScrollingCoordinator is initialized.
  GetDocument().GetSettings()->SetAcceleratedCompositingEnabled(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body { margin:0 }
      #container {
        overflow: scroll;
        width:500px;
        height:500px;
        scroll-snap-type: y mandatory;
      }
      div {
        height:400px;
        scroll-snap-align: start
      }
    </style>
    <body>
    <div id='container'>
    <div></div><div></div><div></div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 0u);

  // Only run this test if scrollbars are hit-testable (they are not on
  // Android).
  bool scrollbar_theme_allows_hit_test =
      GetDocument().GetPage()->GetScrollbarTheme().AllowsHitTest();
  if (!scrollbar_theme_allows_hit_test)
    return;

  // kGestureTapDown sets the pressed parts which is a pre-requisite for
  // kGestureTap performing a scroll.
  const gfx::PointF scrollbar_forward_track(495, 450);
  TapDownEventBuilder tap_down(scrollbar_forward_track);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(tap_down);

  TapEventBuilder tap(scrollbar_forward_track, 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(tap);
  EXPECT_EQ(GetWebFrameWidget().GetInjectedScrollEvents().size(), 3u);

  const Vector<std::unique_ptr<blink::WebCoalescedInputEvent>>& data =
      GetWebFrameWidget().GetInjectedScrollEvents();
  EXPECT_EQ(data[0]->Event().GetType(),
            WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(data[1]->Event().GetType(),
            WebInputEvent::Type::kGestureScrollUpdate);
  EXPECT_EQ(data[2]->Event().GetType(), WebInputEvent::Type::kGestureScrollEnd);
  const WebGestureEvent& gsb =
      static_cast<const WebGestureEvent&>(data[0]->Event());
  const WebGestureEvent& gsu =
      static_cast<const WebGestureEvent&>(data[1]->Event());
  const WebGestureEvent& gse =
      static_cast<const WebGestureEvent&>(data[2]->Event());

  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(gsb);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(gsu);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(gse);

  // Ensure that there is an active animation on the scrollable area event
  // though GSE was handled. The actual handling should be deferred.
  Element* scrollable_div =
      GetDocument().getElementById(AtomicString("container"));
  ScrollableArea* scrollable_area =
      scrollable_div->GetLayoutBox()->GetScrollableArea();
  EXPECT_TRUE(scrollable_area->ExistingScrollAnimator());
  EXPECT_TRUE(scrollable_area->ExistingScrollAnimator()->HasRunningAnimation());

  // Run the animation for a few frames to ensure that snapping did not
  // immediately happen.
  // One frame to update run_state_, one to set start_time = now, then advance
  // two frames into the animation.
  const int kFramesToRun = 4;
  for (int i = 0; i < kFramesToRun; i++)
    Compositor().BeginFrame();

  EXPECT_NE(scrollable_area->GetScrollOffset().y(), 0);

  // Finish the animation, verify that we're back at 0 and not animating.
  Compositor().BeginFrame(0.3);

  EXPECT_EQ(scrollable_area->GetScrollOffset().y(), 0);
  EXPECT_FALSE(
      scrollable_area->ExistingScrollAnimator()->HasRunningAnimation());
}

// Test that leaving a window leaves mouse position unknown.
TEST_F(EventHandlerTest, MouseLeaveResetsUnknownState) {
  SetHtmlInnerHTML("<div></div>");
  WebMouseEvent mouse_down_event(WebMouseEvent::Type::kMouseDown,
                                 gfx::PointF(262, 29), gfx::PointF(329, 67),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().IsMousePositionUnknown());

  WebMouseEvent mouse_leave_event(WebMouseEvent::Type::kMouseLeave,
                                  gfx::PointF(262, 29), gfx::PointF(329, 67),
                                  WebPointerProperties::Button::kNoButton, 1,
                                  WebInputEvent::Modifiers::kNoModifiers,
                                  WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseLeaveEvent(
      mouse_leave_event);
  EXPECT_TRUE(
      GetDocument().GetFrame()->GetEventHandler().IsMousePositionUnknown());
}

// Test that leaving an iframe sets the mouse position to unknown on that
// iframe.
TEST_F(EventHandlerSimTest, MouseLeaveIFrameResets) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    div {
      width: 200px;
      height: 200px;
    }
    iframe {
      width: 200px;
      height: 200px;
    }
    </style>
    <div></div>
    <iframe id='frame' src='frame.html'></iframe>
  )HTML");

  frame_resource.Complete("<!DOCTYPE html>");
  Compositor().BeginFrame();
  WebMouseEvent mouse_move_inside_event(
      WebMouseEvent::Type::kMouseMove, gfx::PointF(100, 229),
      gfx::PointF(100, 229), WebPointerProperties::Button::kNoButton, 0,
      WebInputEvent::Modifiers::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_inside_event, Vector<WebMouseEvent>(),
      Vector<WebMouseEvent>());
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().IsMousePositionUnknown());
  auto* child_frame = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("frame")));
  child_frame->contentDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(GetDocument().GetFrame()->Tree().FirstChild());
  EXPECT_FALSE(To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild())
                   ->GetEventHandler()
                   .IsMousePositionUnknown());

  WebMouseEvent mouse_move_outside_event(
      WebMouseEvent::Type::kMouseMove, gfx::PointF(300, 29),
      gfx::PointF(300, 29), WebPointerProperties::Button::kNoButton, 0,
      WebInputEvent::Modifiers::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_outside_event, Vector<WebMouseEvent>(),
      Vector<WebMouseEvent>());
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().IsMousePositionUnknown());
  EXPECT_TRUE(GetDocument().GetFrame()->Tree().FirstChild());
  EXPECT_TRUE(To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild())
                  ->GetEventHandler()
                  .IsMousePositionUnknown());
}

// Test that mouse down and move a small distance on a draggable element will
// not change cursor style.
TEST_F(EventHandlerSimTest, CursorStyleBeforeStartDragging) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    div {
      width: 300px;
      height: 100px;
      cursor: help;
    }
    </style>
    <div draggable='true'>foo</div>
  )HTML");
  Compositor().BeginFrame();

  WebMouseEvent mouse_down_event(WebMouseEvent::Type::kMouseDown,
                                 gfx::PointF(150, 50), gfx::PointF(150, 50),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);

  WebMouseEvent mouse_move_event(WebMouseEvent::Type::kMouseMove,
                                 gfx::PointF(151, 50), gfx::PointF(151, 50),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());
  EXPECT_EQ(ui::mojom::blink::CursorType::kHelp, GetDocument()
                                                     .GetFrame()
                                                     ->GetChromeClient()
                                                     .LastSetCursorForTesting()
                                                     .type());
}

// Ensure that tap on element in iframe should apply active state.
TEST_F(EventHandlerSimTest, TapActiveInFrame) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/iframe.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    iframe {
      width: 200px;
      height: 200px;
    }
    </style>
    <iframe id='iframe' src='iframe.html'>
    </iframe>
  )HTML");

  frame_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    div {
      width: 100px;
      height: 100px;
    }
    </style>
    <div></div>
  )HTML");
  Compositor().BeginFrame();

  auto* iframe_element = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("iframe")));
  Document* iframe_doc = iframe_element->contentDocument();

  TapDownEventBuilder tap_down(gfx::PointF(10, 10));
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(tap_down);

  ShowPressEventBuilder show_press(gfx::PointF(10, 10));
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(show_press);

  // TapDown and ShowPress active the iframe.
  EXPECT_TRUE(GetDocument().GetActiveElement());
  EXPECT_TRUE(iframe_doc->GetActiveElement());

  TapEventBuilder tap(gfx::PointF(10, 10), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(tap);

  // Should still active.
  EXPECT_TRUE(GetDocument().GetActiveElement());
  EXPECT_TRUE(iframe_doc->GetActiveElement());

  // The active will cancel after 15ms.
  test::RunDelayedTasks(base::Seconds(0.2));
  EXPECT_FALSE(GetDocument().GetActiveElement());
  EXPECT_FALSE(iframe_doc->GetActiveElement());
}

// Test that the hover is updated at the next begin frame after the compositor
// scroll ends.
TEST_F(EventHandlerSimTest, TestUpdateHoverAfterCompositorScrollAtBeginFrame) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body, html {
        margin: 0;
      }
      div {
        height: 300px;
        width: 100%;
      }
    </style>
    <body>
    <div class="hoverme" id="line1">hover over me</div>
    <div class="hoverme" id="line2">hover over me</div>
    <div class="hoverme" id="line3">hover over me</div>
    <div class="hoverme" id="line4">hover over me</div>
    <div class="hoverme" id="line5">hover over me</div>
    </body>
    <script>
      let array = document.getElementsByClassName('hoverme');
      for (let element of array) {
        element.addEventListener('mouseover', function (e) {
          this.innerHTML = "currently hovered";
        });
        element.addEventListener('mouseout', function (e) {
          this.innerHTML = "was hovered";
        });
      }
    </script>
  )HTML");
  Compositor().BeginFrame();

  // Set mouse position and active web view.
  InitializeMousePositionAndActivateView(1, 1);

  WebElement element1 = GetDocument().getElementById(AtomicString("line1"));
  WebElement element2 = GetDocument().getElementById(AtomicString("line2"));
  WebElement element3 = GetDocument().getElementById(AtomicString("line3"));
  EXPECT_EQ("currently hovered", element1.InnerHTML().Utf8());
  EXPECT_EQ("hover over me", element2.InnerHTML().Utf8());
  EXPECT_EQ("hover over me", element3.InnerHTML().Utf8());

  // Do a compositor scroll and set |hover_needs_update_at_scroll_end| to be
  // true in WebViewImpl.
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->DidCompositorScroll(gfx::PointF(0, 500));
  WebView().MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false, 0, 0,
       cc::BrowserControlsState::kBoth, true});
  ASSERT_EQ(500, frame_view->LayoutViewport()->GetScrollOffset().y());
  EXPECT_EQ("currently hovered", element1.InnerHTML().Utf8());
  EXPECT_EQ("hover over me", element2.InnerHTML().Utf8());
  EXPECT_EQ("hover over me", element3.InnerHTML().Utf8());

  // The fake mouse move event is dispatched at the begin frame to update hover.
  Compositor().BeginFrame();
  EXPECT_EQ("was hovered", element1.InnerHTML().Utf8());
  EXPECT_EQ("currently hovered", element2.InnerHTML().Utf8());
  EXPECT_EQ("hover over me", element3.InnerHTML().Utf8());
}

// Test that the hover is updated at the next begin frame after the smooth JS
// scroll ends.
TEST_F(EventHandlerSimTest, TestUpdateHoverAfterJSScrollAtBeginFrame) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 500));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body, html {
        margin: 0;
        height: 500vh;
      }
      div {
        height: 500px;
        width: 100%;
      }
    </style>
    <body>
    <div class="hoverme" id="hoverarea">hover over me</div>
    </body>
  )HTML");
  Compositor().BeginFrame();

  // Set mouse position and active web view.
  InitializeMousePositionAndActivateView(100, 100);

  Element* element = GetDocument().getElementById(AtomicString("hoverarea"));
  EXPECT_TRUE(element->IsHovered());

  // Find the scrollable area and set scroll offset.
  ScrollableArea* scrollable_area =
      GetDocument().GetLayoutView()->GetScrollableArea();
  bool finished = false;
  scrollable_area->SetScrollOffset(
      ScrollOffset(0, 1000), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kSmooth,
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](bool* finished, ScrollableArea::ScrollCompletionMode) {
            *finished = true;
          },
          WTF::Unretained(&finished))));
  Compositor().BeginFrame();
  LocalFrameView* frame_view = GetDocument().View();
  ASSERT_EQ(0, frame_view->LayoutViewport()->GetScrollOffset().y());
  ASSERT_FALSE(finished);
  // Scrolling is in progress but the hover is not updated yet.
  Compositor().BeginFrame();
  // Start scroll animation, but it is not finished.
  Compositor().BeginFrame();
  ASSERT_GT(frame_view->LayoutViewport()->GetScrollOffset().y(), 0);
  ASSERT_FALSE(finished);

  // Mark hover state dirty but the hover state does not change after the
  // animation finishes.
  Compositor().BeginFrame(1);
  ASSERT_EQ(1000, frame_view->LayoutViewport()->GetScrollOffset().y());
  ASSERT_TRUE(finished);
  EXPECT_TRUE(element->IsHovered());

  // Hover state is updated after the begin frame.
  Compositor().BeginFrame();
  EXPECT_FALSE(element->IsHovered());
}

TEST_F(EventHandlerSimTest, LargeCustomCursorIntersectsViewport) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest cursor_request("https://example.com/100x100.png",
                                       "image/png");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
        <!DOCTYPE html>
        <style>
        div {
          width: 100vw;
          height: 100vh;
          cursor: url('100x100.png') 50 50, auto;
        }
        </style>
        <div>foo</div>
      )HTML");
  GetDocument().UpdateStyleAndLayoutTree();

  cursor_request.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("notifications/100x100.png")));

  Compositor().BeginFrame();

  EventHandler& event_handler = GetDocument().GetFrame()->GetEventHandler();

  struct TestCase {
    gfx::PointF point;
    bool custom_expected;
    float cursor_accessibility_scale_factor = 1.f;
    float device_scale_factor = 1.f;
    std::string ToString() const {
      return base::StringPrintf(
          "point: (%s), cursor-scale: %g, device-scale: %g, custom?: %d",
          point.ToString().c_str(), cursor_accessibility_scale_factor,
          device_scale_factor, custom_expected);
    }
  } test_cases[] = {
      // Test top left and bottom right, within viewport.
      {gfx::PointF(60, 60), true},
      {gfx::PointF(740, 540), true},
      // Test top left and bottom right, beyond viewport.
      {gfx::PointF(40, 40), false},
      {gfx::PointF(760, 560), false},
      // Test a larger cursor accessibility scale factor. crbug.com/1455005
      {gfx::PointF(110, 110), true, 2.f},
      {gfx::PointF(690, 490), true, 2.f},
      {gfx::PointF(90, 90), false, 2.f},
      {gfx::PointF(710, 510), false, 2.f},
      // Test a larger display device scale factor. crbug.com/1357442
      {gfx::PointF(110, 110), true, 1.f, 2.f},
      {gfx::PointF(690, 490), true, 1.f, 2.f},
      {gfx::PointF(90, 90), false, 1.f, 2.f},
      {gfx::PointF(710, 510), false, 1.f, 2.f},
  };
  for (const TestCase& test_case : test_cases) {
    SCOPED_TRACE(test_case.ToString());
    DeviceEmulationParams params;
    params.device_scale_factor = test_case.device_scale_factor;
    WebView().EnableDeviceEmulation(params);
    event_handler.set_cursor_accessibility_scale_factor(
        test_case.cursor_accessibility_scale_factor);
    WebMouseEvent mouse_move_event(
        WebMouseEvent::Type::kMouseMove, test_case.point, test_case.point,
        WebPointerProperties::Button::kNoButton, 0, 0,
        WebInputEvent::GetStaticTimeStampForTests());
    event_handler.HandleMouseMoveEvent(mouse_move_event, {}, {});
    const ui::Cursor& cursor =
        GetDocument().GetFrame()->GetChromeClient().LastSetCursorForTesting();
    const ui::mojom::blink::CursorType expected_type =
        test_case.custom_expected ? ui::mojom::blink::CursorType::kCustom
                                  : ui::mojom::blink::CursorType::kPointer;
    EXPECT_EQ(expected_type, cursor.type());
  }
}

TEST_F(EventHandlerSimTest, SmallCustomCursorIntersectsViewport) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest cursor_request("https://example.com/48x48.png",
                                       "image/png");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
        <!DOCTYPE html>
        <style>
        div {
          width: 300px;
          height: 100px;
          cursor: -webkit-image-set(url('48x48.png') 2x) 24 24, auto;
        }
        </style>
        <div>foo</div>
      )HTML");

  GetDocument().UpdateStyleAndLayoutTree();

  cursor_request.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("notifications/48x48.png")));

  Compositor().BeginFrame();

  // Move the cursor so no part of it intersects the viewport.
  {
    WebMouseEvent mouse_move_event(
        WebMouseEvent::Type::kMouseMove, gfx::PointF(25, 25),
        gfx::PointF(25, 25), WebPointerProperties::Button::kNoButton, 0, 0,
        WebInputEvent::GetStaticTimeStampForTests());
    GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
        mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

    const ui::Cursor& cursor =
        GetDocument().GetFrame()->GetChromeClient().LastSetCursorForTesting();
    EXPECT_EQ(ui::mojom::blink::CursorType::kCustom, cursor.type());
  }

  // Now, move the cursor so that it intersects the visual viewport. The cursor
  // should not be removed because it is below
  // kMaximumCursorSizeWithoutFallback.
  {
    WebMouseEvent mouse_move_event(
        WebMouseEvent::Type::kMouseMove, gfx::PointF(23, 23),
        gfx::PointF(23, 23), WebPointerProperties::Button::kNoButton, 0, 0,
        WebInputEvent::GetStaticTimeStampForTests());
    GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
        mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

    const ui::Cursor& cursor =
        GetDocument().GetFrame()->GetChromeClient().LastSetCursorForTesting();
    EXPECT_EQ(ui::mojom::blink::CursorType::kCustom, cursor.type());
  }
}

TEST_F(EventHandlerSimTest, NeverExposeKeyboardEvent) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  GetDocument().GetSettings()->SetDontSendKeyEventsToJavascript(true);
  GetDocument().GetSettings()->SetScrollAnimatorEnabled(false);
  GetDocument().GetSettings()->SetWebAppScope(GetDocument().Url());
  WebView().MainFrameImpl()->LocalRootFrameWidget()->SetDisplayMode(
      blink::mojom::DisplayMode::kFullscreen);
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      height: 10000px;
    }
    </style>
    Last event: <br>
    <p id='log'>no event</p>
    <input id="input1" type="text">

    <script>
      document.addEventListener('keydown', (e) => {
        let log = document.getElementById('l
"""


```