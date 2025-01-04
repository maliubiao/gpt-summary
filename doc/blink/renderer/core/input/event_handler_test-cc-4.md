Response:
The user wants to understand the functionality of the `event_handler_test.cc` file in the Chromium Blink engine. Specifically, they are interested in:

1. **Functionality:** A general overview of what the tests in this file do.
2. **Relation to web technologies:** How these tests relate to JavaScript, HTML, and CSS.
3. **Logic and I/O:**  Any logical deductions made by the tests, and examples of input and expected output.
4. **Common errors:** Scenarios where users or programmers might misuse related features.
5. **User interaction flow:** How user actions lead to this code being executed (as a debugging aid).
6. **Summary of functionality:**  A concise recap of the file's purpose.

Since this is part 5 of 5, the user expects a concluding summary of the overall functionality of the file, building on the previous parts.

Let's break down the provided code snippets to address these points:

**Code Snippet Analysis:**

* **Scrollend event tests:** These tests verify that the `scrollend` event is fired correctly under different scrolling conditions (smooth scrolling and instant scrolling) and when interrupted by other events like `keyup`.
* **Discarding events to moved iframes:** This section tests a feature where input events are discarded if an iframe has recently moved, likely to prevent unintended interactions during layout changes. It also tracks if discarded events *shouldn't* have been discarded (mistakenly discarded).
* **`click.pointerId` for gesture taps:** This test checks that the `pointerId` property of a `click` event is correctly populated even when the underlying pointer events are not explicitly handled by the page.
* **Gesture tap hover state:** This test examines how hover styles are applied and maintained after a gesture tap and subsequent scrolling.

**Connecting to Web Technologies:**

* **JavaScript:** The tests heavily rely on JavaScript event listeners (e.g., `scrollend`, `click`) to observe the behavior of the Blink rendering engine. They also manipulate the DOM using JavaScript (e.g., setting `innerHTML`, `textContent`, focusing elements).
* **HTML:** The HTML code sets up the structure for the tests, including elements that can be scrolled, iframes, and elements with specific styles.
* **CSS:** CSS is used to define the visual appearance and behavior of elements, such as the `overflow: scroll` property for scrollable containers and the `:hover` pseudo-class for styling on hover.

**Logical Inferences and I/O:**

The tests follow a pattern of setting up an initial state, performing an action (e.g., simulating a scroll or a key press), and then asserting the expected outcome (e.g., checking the content of the log element).

* **Scrollend test with interrupt:**
    * **Input:** Initiate a smooth scroll, then press and release a key *before* the scroll finishes.
    * **Output:** The `scrollend` event should *not* fire until the scroll animation completes.
* **Scrollend test with instant scroll:**
    * **Input:** Send multiple `keydown` events to trigger instant scrolls, then a `keyup` event.
    * **Output:** The `scrollend` event should fire upon the `keyup` event.
* **Discarding events test:**
    * **Input:** Move an iframe by different amounts and then simulate mouse clicks within the iframe's bounds.
    * **Output:**  Events should be discarded if the iframe has moved beyond a certain threshold within a specific timeframe.
* **`click.pointerId` test:**
    * **Input:** Simulate a tap gesture.
    * **Output:** The `click` event's `pointerId` should be a positive integer, and it should increase with subsequent taps.
* **Gesture tap hover state test:**
    * **Input:** Simulate a tap on an element, then scroll the page.
    * **Output:** The tapped element should remain in its hover state even after scrolling.

**Common Usage Errors:**

* **Misunderstanding `scrollend`:** Developers might expect `scrollend` to fire after every small scroll increment, but it only fires when the scrolling action is complete (either smooth or instant). The tests with `keyup` demonstrate how other events can influence the timing of `scrollend`.
* **Unexpected event discarding:** Developers might be surprised that events are discarded to recently moved iframes. This can lead to situations where clicks seem to be ignored. The test highlights this behavior and the conditions under which it occurs.
* **Incorrectly assuming pointer event handling:** Developers might expect to always handle low-level pointer events for `click` events to have a valid `pointerId`. The test shows that even without explicit pointer event listeners, the `pointerId` is populated for gesture-based clicks.
* **Issues with hover state after touch:**  Historically, hover states could get "stuck" on mobile devices after a touch. The "Gesture tap hover state" test verifies that Blink correctly maintains the hover state after a tap and subsequent scrolling.

**User Interaction and Debugging:**

1. **Scrolling:** A user scrolling with a mouse wheel, scrollbar, or keyboard (Page Up/Down, arrow keys) can trigger the `scrollend` event. The tests simulate these actions using `Compositor().BeginFrame()`. If `scrollend` is not firing as expected, these tests provide a starting point for debugging the scrolling logic.
2. **Clicking/Tapping:** User clicks or taps on the screen trigger mouse or touch events. The tests simulate these events using `HandleMousePressEvent`, `HandleMouseReleaseEvent`, and `HandleGestureEvent`. Issues with click handling, especially on iframes, can be investigated using the "discarding events" tests.
3. **Keyboard Input:** Typing or using keyboard shortcuts generates key events. The `scrollend` tests with `keyup` illustrate how keyboard input can interact with other events.
4. **Moving iframes:**  Website developers might dynamically reposition iframes using JavaScript or CSS. The "discarding events" tests are relevant when debugging issues where clicks on iframes are not being registered after the iframe has been moved.

**Summary of Functionality (Part 5):**

This part of `event_handler_test.cc` focuses on testing specific aspects of event handling in Blink, particularly related to:

* **The `scrollend` event:** Ensuring it fires correctly in various scrolling scenarios, including smooth and instant scrolling, and when interrupted by other events.
* **Optimizations for iframe interactions:** Verifying the mechanism that discards input events to iframes that have recently moved to avoid unintended behavior during layout changes. It also checks for cases where events are mistakenly discarded.
* **Gesture tap event details:** Confirming that `click` events generated from taps have a valid and consistent `pointerId`, even when low-level pointer events aren't explicitly handled.
* **Hover state management after taps:** Making sure that elements maintain their hover state after a user taps on them, even if the page is scrolled afterward.

**Overall Functionality of `event_handler_test.cc`:**

Based on the context of all five parts, the `event_handler_test.cc` file serves as a comprehensive suite of unit tests for the event handling logic within the Blink rendering engine. It covers a wide range of input events (mouse, keyboard, touch/gesture), focusing on:

* **Correctness:** Ensuring events are dispatched and processed according to web standards and Blink's internal logic.
* **Performance:** Testing optimizations like event coalescing and discarding to improve responsiveness.
* **Edge cases:** Handling unusual or less common event sequences and interactions.
* **Integration:** Verifying how different types of events interact with each other and with other parts of the rendering engine (e.g., scrolling, layout).
* **Regression prevention:** Making sure that new code changes do not introduce bugs or break existing event handling behavior.

The tests use a simulation environment (`EventHandlerSimTest`) to create controlled scenarios and assert the expected outcomes. They interact with the DOM, JavaScript, CSS, and the compositor to mimic real-world user interactions and verify the end-to-end behavior of event handling in Blink. This file is crucial for maintaining the stability and reliability of the Blink engine's input handling capabilities.

好的，这是对 `blink/renderer/core/input/event_handler_test.cc` 文件剩余部分的分析和功能归纳：

**功能列举:**

* **测试 `scrollend` 事件在 `KeyUp` 事件后触发 (瞬间滚动):**  验证在禁用平滑滚动的情况下，如果一系列快速的滚动（通过按下方向键实现）之后立即触发 `KeyUp` 事件，`scrollend` 事件是否会被正确触发。这模拟了用户快速按下并释放按键导致内容快速滚动的场景。
* **测试丢弃发送到最近移动的 iframe 的事件:**  测试 Blink 的一项优化功能，即当 iframe 在短时间内发生较大位移后，会丢弃发送给该 iframe 的输入事件。这是为了防止在布局变动时，用户对 iframe 的操作产生意外的效果。测试覆盖了在阈值内和超出阈值移动 iframe 的情况，以及连续点击被丢弃事件的目标时，是否会记录为“错误地丢弃”。
* **测试手势点击的 `click.pointerId` 的有效性:** 验证对于没有低级别指针事件（pointerdown, pointermove, pointerup 等）监听器的手势点击事件，其关联的 `click` 事件的 `pointerId` 属性是否有效。这确保即使在没有显式处理指针事件的情况下，点击事件也能提供有效的指针信息。
* **测试手势点击的悬停状态:**  测试在用户进行手势点击后，元素的悬停状态是否正确设置和保持。即使在点击后页面发生滚动，之前点击的元素应该仍然保持其 `:hover` 样式。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **事件监听:** 测试用 JavaScript 代码添加了 `scrollend` 和 `click` 事件监听器，用于捕获和验证事件是否被触发，以及事件对象的属性值（例如 `e.pointerId`）。
    * **DOM 操作:**  JavaScript 代码通过 `document.getElementById` 获取元素，并修改元素的 `innerHTML` 或 `textContent` 来记录事件发生或显示 `pointerId` 的值。
    * **模拟用户行为:**  虽然测试本身是用 C++ 编写的，但它模拟的用户行为最终会触发 JavaScript 代码的执行。
    * **示例:**  在测试 `scrollend` 事件的例子中，JavaScript 代码 `scroller.addEventListener('scrollend', ...)` 用于监听滚动结束事件，并在事件触发时将 "scrollend" 写入 `<p id='log'>` 元素。

* **HTML:**
    * **页面结构:**  HTML 代码定义了测试页面的基本结构，包括可滚动的 `div` (`#scroller`)，用于记录日志的段落 (`#log`)，以及用于测试 iframe 事件丢弃的 `iframe` 元素。
    * **元素属性:**  使用了 `tabindex=0` 属性使 `#scroller` 元素可以获得焦点，这对于触发某些键盘事件至关重要。
    * **示例:**  `<div id="scroller" tabindex=0>` 定义了一个可滚动的容器，`tabindex=0` 使得该元素可以通过键盘导航获得焦点，从而可以接收键盘事件触发滚动。

* **CSS:**
    * **样式定义:** CSS 代码定义了元素的样式，例如 `#scroller` 的滚动条行为 (`overflow: scroll`) 和高度，以及 `:hover` 伪类来定义鼠标悬停时的背景颜色变化。
    * **布局影响:**  在测试 iframe 事件丢弃的例子中，CSS 的 `margin-left` 和 `margin-top` 属性被用来移动 iframe 的位置，从而触发事件丢弃的逻辑。
    * **示例:**  `p:hover { background: red; }` 定义了当鼠标悬停在 `<p>` 元素上时，其背景颜色变为红色，这在测试手势点击的悬停状态时被用来验证悬停效果。

**逻辑推理及假设输入与输出:**

* **测试 `scrollend` 事件在 `KeyUp` 事件后触发 (瞬间滚动):**
    * **假设输入:** 用户通过按下方向键多次触发快速滚动，然后释放按键。
    * **预期输出:** 在释放按键 (`KeyUp`) 后，`scrollend` 事件被触发，`#log` 元素的 `innerHTML` 变为 "scrollend"。
* **测试丢弃发送到最近移动的 iframe 的事件:**
    * **假设输入 (不丢弃):** 在 iframe 位置稳定后或移动距离在阈值内时，模拟鼠标按下和释放事件。
    * **预期输出:** `HandleMousePressEvent` 和 `HandleMouseReleaseEvent` 的返回值不是 `WebInputEventResult::kHandledSuppressed`，表明事件被正常处理。
    * **假设输入 (丢弃):** 在 iframe 移动距离超出阈值时，模拟鼠标按下和释放事件。
    * **预期输出:** `HandleMousePressEvent` 和 `HandleMouseReleaseEvent` 的返回值是 `WebInputEventResult::kHandledSuppressed`，表明事件被丢弃。
    * **假设输入 (连续点击被丢弃目标):** 在事件被丢弃后的一段时间内，再次点击相同的 iframe 区域。
    * **预期输出:**  `UseCounter` 会记录 `kInputEventToRecentlyMovedIframeMistakenlyDiscarded` 特性，表明系统认为之前的丢弃可能是错误的。
* **测试手势点击的 `click.pointerId` 的有效性:**
    * **假设输入:** 模拟一次手势点击事件。
    * **预期输出:**  `click` 事件的 `pointerId` 属性值大于 1，并且每次新的点击事件 `pointerId` 的值会递增。
* **测试手势点击的悬停状态:**
    * **假设输入:** 模拟一次在元素 `#a` 上的手势点击事件，然后滚动页面。
    * **预期输出:** 在点击后，元素 `#a` 的背景颜色变为红色 (hover 状态)，即使页面滚动后，`#a` 仍然保持红色背景。

**用户或编程常见的使用错误:**

* **对 `scrollend` 事件的理解偏差:** 开发者可能认为 `scrollend` 会在每次滚动像素发生变化时触发，而实际上它只在滚动动画或瞬间滚动完成后触发。快速连续滚动后立即进行其他操作可能导致 `scrollend` 延迟触发，从而产生意外的行为。
* **不了解 iframe 事件丢弃机制:**  开发者在动态移动 iframe 后，可能会疑惑为什么发送给 iframe 的事件没有被处理。这通常是因为触发了 Blink 的事件丢弃优化。需要注意 iframe 移动的速度和距离，以及事件发生的时间。
* **依赖低级别指针事件处理 `click` 事件的 `pointerId`:**  开发者可能认为只有在监听了 `pointerdown` 等低级别指针事件后，`click` 事件的 `pointerId` 才会有效。实际上，对于手势点击，即使没有这些监听器，`pointerId` 也会被赋值。
* **触摸设备上悬停状态的处理不当:**  在移动设备上，触摸操作可能会导致元素的悬停状态“卡住”。开发者需要理解浏览器如何处理触摸和悬停状态的交互，并进行相应的适配。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户滚动页面:** 用户通过鼠标滚轮、拖动滚动条、使用键盘按键（Page Up/Down, 方向键）等方式滚动页面。这可能会触发 `scrollend` 事件相关的代码。
2. **用户点击或触摸屏幕:** 用户点击屏幕上的元素或在触摸屏上进行触摸操作。这会触发鼠标事件（mousedown, mouseup, click）或触摸事件（touchstart, touchmove, touchend），对于没有指针事件监听器的情况，最终可能会转化为 `click` 事件，从而触发关于 `pointerId` 的测试代码。
3. **用户与 iframe 交互:** 用户尝试点击或与页面中的 iframe 元素进行交互。如果 iframe 在短时间内发生了移动，可能会触发事件丢弃的逻辑，相关的测试会模拟这种情况。
4. **用户触发悬停效果:** 用户将鼠标悬停在元素上（桌面端）或在触摸屏上进行短暂触摸（可能触发悬停效果），然后进行点击或滚动操作。这会触发关于悬停状态的测试代码。
5. **开发者调试:** 当开发者遇到与滚动、点击、iframe 交互或悬停状态相关的 Bug 时，可能会通过以下步骤到达这些测试代码：
    * **怀疑是事件处理的问题:**  通过现象（例如点击没有反应，滚动行为异常）判断问题可能出在事件处理流程中。
    * **查找相关代码:**  根据事件类型（如 `scrollend`，`click`）或相关功能（如 iframe 事件处理），在 Blink 源代码中搜索相关的事件处理函数或测试文件。
    * **定位到 `event_handler_test.cc`:**  发现这个测试文件包含了大量关于各种事件处理的测试用例，可能包含与问题相关的测试。
    * **分析具体的测试用例:**  仔细阅读相关的测试用例代码，理解测试的场景、输入和预期输出，从而帮助理解 Blink 内部的事件处理逻辑，并找到潜在的 Bug 根源。

**功能归纳 (作为第 5 部分的总结):**

总而言之，`blink/renderer/core/input/event_handler_test.cc` 文件的这最后一部分，继续深入测试了 Blink 引擎中事件处理器的关键功能，特别关注以下几个方面：

* **完善 `scrollend` 事件的测试:**  补充了在特定用户交互模式下（快速滚动后释放按键）`scrollend` 事件的触发机制测试。
* **验证 iframe 事件处理的优化策略:**  详细测试了 Blink 为了提升性能和避免意外行为而采取的针对最近移动的 iframe 的事件丢弃机制，并考虑了可能误判的情况。
* **确保手势操作的事件信息完整性:**  验证了即使在没有显式处理底层指针事件的情况下，由手势操作触发的 `click` 事件也能提供有效的指针 ID 信息。
* **保障用户交互的视觉反馈一致性:**  测试了手势点击后元素的悬停状态是否能正确保持，即使在页面滚动后也能维持视觉反馈。

结合之前部分的分析，`event_handler_test.cc` 是一个全面的事件处理器测试套件，覆盖了各种输入事件类型和用户交互场景，旨在确保 Blink 引擎能够正确、高效地处理用户输入，并提供一致和可靠的用户体验。它对于维护 Blink 引擎的稳定性和可靠性至关重要，并且是开发者理解 Blink 事件处理机制的重要参考。

Prompt: 
```
这是目录为blink/renderer/core/input/event_handler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
that we have not yet fired scrollend.
  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("log"))->innerHTML().Utf8(),
      "");

  // Fire keyUp, which should not tigger a scrollend event since another scroll
  // is in progress.
  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);

  // Tick second scroll to completion which should fire scrollend.
  Compositor().BeginFrame(0.30);

  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("log"))->innerHTML().Utf8(),
      "scrollend");
}

TEST_F(EventHandlerSimTest, TestScrollendFiresOnKeyUpAfterScrollInstant) {
  GetDocument().GetSettings()->SetScrollAnimatorEnabled(false);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        #scroller {
          overflow: scroll;
          height: 100px;
          height: 100px;
        }
        #spacer {
          height: 400px;
          height: 400px;
        }
      </style>
      <body>
        <p id='log'></p> <br>
        <div id="scroller" tabindex=0>
          <div id="spacer"></div>
        </div>
      </body>
      <script>
        scroller.addEventListener('scrollend', (e) => {
          let log = document.getElementById('log');
          log.innerText += 'scrollend';
        });
      </script>
      )HTML");
  Compositor().BeginFrame();
  WebKeyboardEvent e{WebInputEvent::Type::kRawKeyDown,
                     WebInputEvent::kNoModifiers,
                     WebInputEvent::GetStaticTimeStampForTests()};
  const int num_keydowns = 5;

  GetDocument()
      .getElementById(AtomicString("scroller"))
      ->Focus(FocusOptions::Create());
  // Send first keyDown.
  e.windows_key_code = VKEY_DOWN;
  e.SetType(WebInputEvent::Type::kKeyDown);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  // BeginFrame to trigger first instant scroll.
  Compositor().BeginFrame();

  // Trigger a sequence of instant scrolls.
  for (int i = 0; i < num_keydowns - 1; i++) {
    GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
    Compositor().BeginFrame();
  }

  // Verify that we have not yet fired scrollend.
  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("log"))->innerHTML().Utf8(),
      "");

  // Fire keyUp, which should trigger a scrollend event.
  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);

  Compositor().BeginFrame();
  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("log"))->innerHTML().Utf8(),
      "scrollend");
}

TEST_F(EventHandlerSimTest, DiscardEventsToRecentlyMovedIframe) {
  base::FieldTrialParams field_trial_params;
  field_trial_params["time_ms"] = "500";
  field_trial_params["distance_factor"] = "0.5";
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeatureWithParameters(
      features::kDiscardInputEventsToRecentlyMovedFrames, field_trial_params);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://cross-origin.com/iframe.html",
                            "text/html");
  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <iframe id='iframe' src='https://cross-origin.com/iframe.html'></iframe>
  )HTML");
  frame_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Hello, world!</div>
  )HTML");

  // The first BeginFrame() sets the last known position of the iframe. The
  // second BeginFrame(), after a delay with no layout changes, will mark the
  // iframe as having a stable position, so input events will not be discarded.
  Compositor().BeginFrame();
  GetDocument().GetFrame()->View()->ScheduleAnimation();
  Compositor().BeginFrame(0.5);

  // Iframe position is stable, do not discard events.
  WebInputEventResult event_result =
      GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
          WebMouseEvent(WebInputEvent::Type::kMouseDown, gfx::PointF(100, 50),
                        gfx::PointF(100, 50),
                        WebPointerProperties::Button::kLeft, 1,
                        WebInputEvent::Modifiers::kLeftButtonDown,
                        base::TimeTicks::Now()));
  EXPECT_NE(event_result, WebInputEventResult::kHandledSuppressed);
  event_result =
      GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(
          WebMouseEvent(WebInputEvent::Type::kMouseUp, gfx::PointF(100, 50),
                        gfx::PointF(100, 50),
                        WebPointerProperties::Button::kLeft, 1,
                        WebInputEvent::kNoModifiers, base::TimeTicks::Now()));
  EXPECT_NE(event_result, WebInputEventResult::kHandledSuppressed);

  Element* iframe =
      GetDocument().getElementById(AtomicString::FromUTF8("iframe"));
  ASSERT_TRUE(iframe);

  // Move iframe, but within the threshold for discarding. Events should not be
  // discarded.
  iframe->SetInlineStyleProperty(CSSPropertyID::kMarginLeft, "70px");
  iframe->SetInlineStyleProperty(CSSPropertyID::kMarginTop, "40px");
  Compositor().BeginFrame();
  event_result =
      GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
          WebMouseEvent(WebInputEvent::Type::kMouseDown, gfx::PointF(170, 90),
                        gfx::PointF(170, 90),
                        WebPointerProperties::Button::kLeft, 1,
                        WebInputEvent::Modifiers::kLeftButtonDown,
                        base::TimeTicks::Now()));
  EXPECT_NE(event_result, WebInputEventResult::kHandledSuppressed);
  event_result =
      GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(
          WebMouseEvent(WebInputEvent::Type::kMouseUp, gfx::PointF(170, 90),
                        gfx::PointF(170, 90),
                        WebPointerProperties::Button::kLeft, 1,
                        WebInputEvent::kNoModifiers, base::TimeTicks::Now()));
  EXPECT_NE(event_result, WebInputEventResult::kHandledSuppressed);

  // Move iframe past threshold for discarding; events should be discarded.
  iframe->SetInlineStyleProperty(CSSPropertyID::kMarginLeft, "200px");
  Compositor().BeginFrame();
  base::TimeTicks event_time =
      Compositor().LastFrameTime() + base::Milliseconds(400);

  event_result =
      GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
          WebMouseEvent(WebInputEvent::Type::kMouseDown, gfx::PointF(300, 90),
                        gfx::PointF(300, 90),
                        WebPointerProperties::Button::kLeft, 1,
                        WebInputEvent::Modifiers::kLeftButtonDown, event_time));
  EXPECT_EQ(event_result, WebInputEventResult::kHandledSuppressed);
  event_result =
      GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(
          WebMouseEvent(WebInputEvent::Type::kMouseUp, gfx::PointF(300, 90),
                        gfx::PointF(300, 90),
                        WebPointerProperties::Button::kLeft, 1,
                        WebInputEvent::kNoModifiers, event_time));
  EXPECT_EQ(event_result, WebInputEventResult::kHandledSuppressed);

  // A second click on the same target within 5 seconds of a discarded click
  // should be recorded as "mistakenly discarded".
  EXPECT_FALSE(
      To<HTMLIFrameElement>(iframe)
          ->contentDocument()
          ->Loader()
          ->GetUseCounter()
          .IsCounted(
              WebFeature::kInputEventToRecentlyMovedIframeMistakenlyDiscarded));
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      WebMouseEvent(WebInputEvent::Type::kMouseDown, gfx::PointF(300, 90),
                    gfx::PointF(300, 90), WebPointerProperties::Button::kLeft,
                    1, WebInputEvent::Modifiers::kLeftButtonDown, event_time));
  EXPECT_TRUE(
      To<HTMLIFrameElement>(iframe)
          ->contentDocument()
          ->Loader()
          ->GetUseCounter()
          .IsCounted(
              WebFeature::kInputEventToRecentlyMovedIframeMistakenlyDiscarded));
}

// Tests that click.pointerId is valid for a gesture tap for which no low-level
// pointer events (pointerdown, pointermove, pointerup etc) are sent from the
// browser to the renderer because of absence of relevant event listeners.
TEST_F(EventHandlerSimTest, ValidClickPointerIdForUnseenPointerEvent) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='pointer_id' style='width:100px;height:100px'></div>
    <script>
      document.body.addEventListener('click', e => {
        document.getElementById('pointer_id').textContent = e.pointerId;
      });
    </script>
  )HTML");

  WebElement pointer_id_elem =
      GetDocument().getElementById(AtomicString("pointer_id"));
  EXPECT_EQ("", pointer_id_elem.TextContent().Utf8());

  TapEventBuilder tap_event(gfx::PointF(20, 20), 1);

  // Blink-defined behavior: touch pointer-id starts at 2.
  tap_event.primary_unique_touch_event_id = 321;
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(tap_event);
  auto pointer_id_1 = stoi(pointer_id_elem.TextContent().Utf8());
  EXPECT_GT(pointer_id_1, 1);

  // Blink-defined behavior: pointer-id increases with each new event.
  tap_event.primary_unique_touch_event_id = 123;
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(tap_event);
  auto pointer_id_2 = stoi(pointer_id_elem.TextContent().Utf8());
  EXPECT_GT(pointer_id_2, pointer_id_1);
}

TEST_F(EventHandlerSimTest, GestureTapHoverState) {
  ResizeView(gfx::Size(800, 600));

  // RecomputeMouseHoverState() bails early if we are not focused.
  GetPage().SetFocused(true);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body { height: 1000px; margin: 0; }
        p { height: 100px; margin: 0; background: white; }
        p:hover { background: red; }
      </style>
      <body>
        <p id=a>A</p>
        <p id=b>B</p>
      </body>
      )HTML");

  Compositor().BeginFrame();
  Document& doc = GetDocument();
  LayoutObject* a = doc.getElementById(AtomicString("a"))->GetLayoutObject();
  LayoutObject* b = doc.getElementById(AtomicString("b"))->GetLayoutObject();

  auto ColorOf = [](const LayoutObject* lo) {
    const auto& bg_color_prop = GetCSSPropertyBackgroundColor();
    Color color = lo->Style()->VisitedDependentColor(bg_color_prop);
    return color.SerializeAsCSSColor();
  };
  String rgb_white = "rgb(255, 255, 255)";
  String rgb_red = "rgb(255, 0, 0)";

  EXPECT_EQ(rgb_white, ColorOf(a));
  EXPECT_EQ(rgb_white, ColorOf(b));

  TapEventBuilder tap(gfx::PointF(10, 10), 1);
  doc.GetFrame()->GetEventHandler().HandleGestureEvent(tap);
  Compositor().BeginFrame();

  // #a is hovered after tap.
  EXPECT_EQ(rgb_red, ColorOf(a));
  EXPECT_EQ(rgb_white, ColorOf(b));

  doc.scrollingElement()->scrollBy(0, 100);
  Compositor().BeginFrame();

  // #a is still hovered after scrolling away (crbug.com/366020097).
  EXPECT_EQ(rgb_red, ColorOf(a));
  EXPECT_EQ(rgb_white, ColorOf(b));
}

}  // namespace blink

"""


```