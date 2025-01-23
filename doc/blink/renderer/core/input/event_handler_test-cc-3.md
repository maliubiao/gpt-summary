Response:
The user wants me to analyze a C++ source code file (`event_handler_test.cc`) from the Chromium Blink engine. They're asking for:

1. **Functionality:** What does this code do?
2. **Relation to web technologies:** How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logic and I/O:** If it performs logical reasoning, give examples of assumed inputs and outputs.
4. **Common user/programming errors:**  Illustrate potential mistakes.
5. **User journey:** How does a user action lead to this code being executed?
6. **Summary:** A concise summary of the file's purpose.

This is part 4 of a 5-part analysis, suggesting I've been providing similar information for other parts of the file. The provided code snippet contains various test cases (using the `TEST_F` macro). Each test case simulates user interactions and verifies the behavior of the event handling system in Blink.

**Mental Sandbox:**

* **Core functionality:** The file is clearly about testing the `EventHandler` class in Blink. It simulates different input events (keyboard, mouse, touch, gestures) and checks if the event handling logic works correctly.
* **Web tech connection:** The tests directly interact with the DOM (getting elements, setting focus, triggering events). They also verify how JavaScript event listeners are triggered and how events can be canceled. The HTML and CSS in the test setup are used to create specific scenarios for testing (e.g., scrollable areas, transformed elements).
* **Logic and I/O:** The tests make assertions (`EXPECT_EQ`, `EXPECT_NE`, `ASSERT_TRUE`, `ASSERT_FALSE`, `EXPECT_GT`) based on the state of the DOM or other internal Blink components after simulating events. The "input" is the sequence of simulated events, and the "output" is the state of the DOM or internal variables being checked.
* **User errors:**  Potential errors could involve incorrect event dispatching, issues with focus management, or incorrect handling of event cancellation.
* **User journey:** A user interacting with a webpage (typing, clicking, scrolling) triggers events that are eventually processed by the `EventHandler`. This file tests those processing pathways.
* **Summary:**  This part of the `event_handler_test.cc` focuses on simulating various input events, particularly keyboard, mouse, and gesture events, in different scenarios, including interactions with iframes, transformed elements, and scrollable areas, and verifies the correct behavior of the Blink event handling system.

**Constraint Checklist & Confidence Score:**

* Provide functionality? Yes.
* Relation to JS/HTML/CSS with examples? Yes.
* Logic/I/O examples? Yes.
* User/programming errors? Yes.
* User journey? Yes.
* Summarize functionality? Yes.
* Part 4 of 5? Yes.

Confidence Score: 5/5 - I am confident I can address all the user's requests accurately.

**Strategizing complete.** I will now generate the response based on the above analysis.
```cpp
TEST_F(EventHandlerSimTest, TestScrollendFiresAfterScrollWithEarlyKeyUp) {
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

  GetDocument()
      .getElementById(AtomicString("scroller"))
      ->Focus(FocusOptions::Create());

  // Send first keyDown.
  e.windows_key_code = VKEY_DOWN;
  e.SetType(WebInputEvent::Type::kKeyDown);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  // BeginFrame to create first scroll_animation.
  Compositor().BeginFrame();
  // BeginFrame to tick first scroll_animation to completion.
  Compositor().BeginFrame(0.30);

  // Start a second scroll_animation that should end after the keyup event.
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  Compositor().BeginFrame();

  // Verify
```

### 功能列举

这个代码片段延续了 `blink/renderer/core/input/event_handler_test.cc` 文件的功能，主要用于测试 Blink 渲染引擎中 **事件处理器的行为**。具体来说，这部分代码侧重于以下几点：

* **键盘事件处理:**  测试 `keydown` 和 `keyup` 事件在不同场景下的处理，包括是否会触发 JavaScript 事件监听器，以及事件是否可取消 (cancelable)。
* **事件的阻止和传播:**  通过设置 `DontSendKeyEventsToJavascript` 来模拟阻止键盘事件传递给 JavaScript，并验证其效果。
* **焦点管理:**  测试在有焦点元素的情况下（例如，文本输入框），键盘事件的处理方式。
* **触摸板滚动:** 测试触摸板滚动事件在 `overflow: hidden` 元素上的行为，验证是否会阻止滚动。
* **手势滚动事件:**  测试手势滚动事件的目标定位（viewport 或特定元素），包括在 iframe 中的情况，以及当页面有缩放时的行为。
* **鼠标事件和捕获:** 测试在元素捕获鼠标事件后，鼠标移动和释放事件的处理，特别是涉及到元素有 CSS 变换 (transform) 的情况。
* **鼠标右键事件和 iframe:**  测试鼠标右键按下并在移动到 iframe 上的事件路由。
* **Pen 事件:**  测试笔触在元素上拖动时，元素是否保持激活状态。
* **鼠标滚轮事件:** 测试鼠标滚轮事件的处理，包括 delta 为零的情况，以及不同阶段 (phase) 的滚轮事件是否会触发 JavaScript 的 `wheel` 事件。
* **`scrollend` 事件:**  测试在键盘事件触发滚动动画后，`scrollend` 事件是否会在 `keyup` 事件后正确触发，以及提前释放按键的情况下 `scrollend` 事件的触发时机。

### 与 JavaScript, HTML, CSS 的关系举例说明

这些测试用例直接验证了 Blink 的事件处理器与 JavaScript, HTML, CSS 的交互：

1. **JavaScript 事件监听器:**
   ```html
   <script>
     document.addEventListener('keydown', (e) => {
       let log = document.getElementById('log');
       log.innerText = 'keydown cancelable=' + e.cancelable;
     });
   </script>
   ```
   这段 JavaScript 代码监听了 `keydown` 事件。测试用例会模拟 `keydown` 事件，并断言 `log` 元素的 `innerText` 是否被更新，以此验证 JavaScript 监听器是否被触发。

2. **HTML 结构和元素:**
   ```html
   <div id='log'>no event</div>
   <input id="input1" type="text">
   <div id="scroller" tabindex=0>
     <div id="spacer"></div>
   </div>
   ```
   测试用例会通过 `GetDocument().getElementById()` 获取 HTML 元素，并模拟在这些元素上发生的事件。例如，测试会聚焦到 `input` 元素，模拟在 `scroller` 元素上的滚动操作。HTML 结构定义了事件发生的环境和目标。

3. **CSS 样式:**
   ```css
   #outer {
     width: 100vw;
     height: 100vh;
     overflow-x: hidden;
     overflow-y: scroll;
   }
   #target' style = "width:250px; transform: rotate(180deg)"
   ```
   CSS 样式定义了元素的视觉效果和布局行为，这些行为会影响事件的处理。例如，`overflow: hidden` 会阻止元素的滚动，`transform: rotate(180deg)` 会改变元素的坐标系，影响鼠标事件的定位。测试用例会利用这些 CSS 属性来创建特定的测试场景。

   **例子：CSS 变换与鼠标捕获**
   在 `TEST_F(EventHandlerSimTest, SelecteTransformedTextWhenCapturing)` 中，`#target` 元素被旋转了 180 度。测试用例模拟鼠标按下并移动，验证即使在元素经过变换后，鼠标捕获和文本选择功能依然能够正确工作。这说明 Blink 的事件处理器考虑了 CSS 变换对事件坐标的影响。

### 逻辑推理的假设输入与输出

以下是一些测试用例中的逻辑推理示例：

**示例 1: `NotExposeKeyboardEvent` 测试用例**

* **假设输入:**
    * 设置 `DontSendKeyEventsToJavascript(true)`。
    * 模拟 `VKEY_DOWN` 的 `keydown` 和 `keyup` 事件。
    * 模拟 `dom_key = 0x00400031` 的 `keydown` 和 `keyup` 事件。
    * 设置焦点到 `input` 元素。
    * 再次模拟 `dom_key = 0x00400031` 的 `keydown` 事件（方向键）。
* **逻辑推理:**  如果 `DontSendKeyEventsToJavascript` 为 true，则前两组键盘事件应该不会触发 JavaScript 监听器。但是，特定的按键（如方向键）即使在设置了该标志后，也可能需要在编辑器等场景下被处理。
* **预期输出:**
    * 前两组事件后，`log` 元素的 `innerText` 仍然是 "no event"。
    * `dom_key = 0x00400031` 的事件会触发 JavaScript 监听器，因为即使禁用了全局键盘事件，某些特定按键仍然会传递，且 `cancelable` 属性为 `false`。
    * 当焦点在 `input` 元素上时，相同的按键会触发 JavaScript 监听器，且 `cancelable` 属性为 `true`，因为这些按键可能需要被编辑器处理。
    * 由于最后模拟的是方向键，且焦点在可滚动的区域，页面会发生滚动。

**示例 2: `DoNotScrollWithTouchpadIfOverflowIsHidden` 测试用例**

* **假设输入:**
    * HTML 结构包含一个 `overflow-x: hidden` 的外部 div 和一个内容超出其尺寸的内部 div。
    * 模拟触摸板的 `GestureScrollBegin`, `GestureScrollUpdate`, `GestureScrollEnd` 事件。
* **逻辑推理:** 当外部 div 的 `overflow-x` 设置为 `hidden` 时，水平方向的滚动应该被阻止，即使内容超出了其边界。
* **预期输出:**  在模拟滚动事件后，外部 div 的 `scrollLeft()` 应该保持为 0。

**示例 3: `TestWheelEventsWithDifferentPhases` 测试用例**

* **假设输入:**
    * 模拟不同 `phase` 值的鼠标滚轮事件 (e.g., `kPhaseBegan`, `kPhaseChanged`, `kPhaseStationary`, `kPhaseEnded`).
* **逻辑推理:**  只有特定阶段的滚轮事件才应该触发 JavaScript 的 `wheel` 事件监听器。
* **预期输出:**  `kPhaseBegan`, `kPhaseChanged`, `kPhaseStationary` 阶段的事件会触发 JavaScript 监听器并更新 `log` 元素的内容，而 `kPhaseEnded` 不会。

### 用户或编程常见的使用错误举例说明

1. **未正确处理事件的 `cancelable` 属性:**
   一个常见的错误是在 JavaScript 中监听事件时，没有检查事件的 `cancelable` 属性。例如，如果一个键盘事件是不可取消的，调用 `event.preventDefault()` 将不会有任何效果，开发者可能会因此误解事件处理流程。`NotExposeKeyboardEvent` 测试用例就演示了这种情况。

2. **对事件目标的错误假设:**
   开发者可能会错误地假设事件总是发生在特定的元素上，而忽略了事件冒泡或捕获阶段。例如，一个点击事件可能最终由文档对象处理，而不是直接点击的子元素。`ElementTargetedGestureScroll` 测试用例通过模拟针对不同元素（包括 viewport）的手势滚动事件，验证了事件目标定位的正确性。

3. **忽略 CSS 样式对事件的影响:**
   CSS 样式（如 `overflow`, `transform`, `pointer-events`）会显著影响事件的触发和处理。例如，设置了 `overflow: hidden` 的元素不会产生滚动条，触摸板滚动事件的处理也会有所不同，如 `DoNotScrollWithTouchpadIfOverflowIsHidden` 测试用例所示。

4. **对 `scrollend` 事件触发时机的误解:**
   开发者可能认为 `scrollend` 事件会在滚动立即结束后触发，但实际上，它通常会在滚动动画结束后触发。`TestScrollendFiresOnKeyUpAfterScroll` 和 `TestScrollendFiresAfterScrollWithEarlyKeyUp` 这两个测试用例强调了 `scrollend` 事件与键盘事件和滚动动画的交互。

### 用户操作如何一步步的到达这里 (调试线索)

1. **用户交互:** 用户在浏览器中执行操作，例如：
   * **键盘输入:** 用户按下或释放键盘上的按键。
   * **鼠标操作:** 用户点击、移动鼠标，或者滚动鼠标滚轮。
   * **触摸操作:** 用户在触摸屏上滑动、捏合等。
   * **使用触摸板:** 用户在触摸板上进行滚动或手势操作。

2. **浏览器事件生成:**  用户的物理操作会被操作系统转化为相应的输入事件。浏览器接收到这些操作系统事件。

3. **Blink 事件处理:** 浏览器将这些事件传递给 Blink 渲染引擎进行处理。

4. **`EventHandler` 接收事件:**  Blink 的 `EventHandler` 类是处理这些输入事件的核心组件。根据事件类型（如 `keydown`, `mousedown`, `wheel`, `gestureScrollBegin`），`EventHandler` 会调用相应的处理函数。

5. **事件分发和目标确定:** `EventHandler` 会确定事件的目标元素（例如，用户点击的按钮，键盘焦点所在的输入框）。这可能涉及到事件冒泡或捕获阶段。

6. **JavaScript 事件监听器触发:** 如果目标元素或其父元素注册了相应的 JavaScript 事件监听器，这些监听器会被调用。

7. **默认浏览器行为:**  在 JavaScript 事件处理结束后，或者如果没有监听器阻止默认行为，浏览器会执行默认的操作（例如，滚动页面，输入文本）。

**调试线索:**

当调试与事件处理相关的问题时，可以按照以下步骤：

* **确认事件是否被正确触发:** 使用浏览器的开发者工具的 "Event Listeners" 面板，查看特定元素上注册了哪些事件监听器，以及这些监听器是否被触发。
* **检查事件对象的属性:**  在事件处理函数中打印事件对象的属性（如 `type`, `target`, `currentTarget`, `cancelable`, `deltaX`, `deltaY` 等），以了解事件的详细信息。
* **分析事件传播路径:**  理解事件冒泡和捕获的顺序，确定事件是否按照预期的路径传播。
* **排查 JavaScript 错误:**  检查 JavaScript 代码中是否存在错误，导致事件处理逻辑不正确。
* **考虑 CSS 样式的影响:**  检查相关的 CSS 样式是否会影响事件的触发或处理。
* **使用 Blink 内部日志:**  如果问题涉及到 Blink 内部的事件处理逻辑，可能需要查看 Blink 的内部日志或使用调试工具来跟踪事件的流向。`event_handler_test.cc` 中的测试用例可以作为参考，了解 Blink 内部是如何处理各种事件的。

例如，如果用户反馈一个页面无法通过触摸板水平滚动，可以检查相关元素的 CSS `overflow-x` 属性，并参考 `DoNotScrollWithTouchpadIfOverflowIsHidden` 测试用例，了解 Blink 在 `overflow: hidden` 时的行为。

### 功能归纳

这是 `blink/renderer/core/input/event_handler_test.cc` 文件的第四部分，主要功能是 **全面测试 Blink 渲染引擎中事件处理器的各种场景和功能**。

这部分测试重点覆盖了：

* **键盘事件的精细控制和 JavaScript 交互:**  包括阻止事件传递、焦点状态下的处理、以及特定按键的行为。
* **不同类型的滚动事件处理:**  触摸板滚动、手势滚动（包括目标定位和 iframe 中的情况）。
* **鼠标和 Pen 事件的复杂交互:**  包括鼠标捕获、CSS 变换的影响、以及鼠标右键在 iframe 中的路由。
* **鼠标滚轮事件的不同阶段和 JavaScript 触发。**
* **`scrollend` 事件在键盘滚动场景下的触发时机。**

总而言之，这部分测试用例旨在确保 Blink 的事件处理器能够正确、可靠地处理各种用户输入事件，并与 JavaScript, HTML, CSS 等 Web 技术协同工作，保证网页的交互功能正常运行。

### 提示词
```
这是目录为blink/renderer/core/input/event_handler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
og');
        log.innerText = 'keydown cancelable=' + e.cancelable;
      });
      document.addEventListener('keyup', (e) => {
        let log = document.getElementById('log');
        log.innerText = 'keyup cancelable=' + e.cancelable;
      });
    </script>
  )HTML");
  Compositor().BeginFrame();

  WebElement element = GetDocument().getElementById(AtomicString("log"));
  WebKeyboardEvent e{WebInputEvent::Type::kRawKeyDown,
                     WebInputEvent::kNoModifiers,
                     WebInputEvent::GetStaticTimeStampForTests()};
  e.windows_key_code = VKEY_DOWN;
  // TODO(crbug.com/949766) Should cleanup these magic number.
  e.dom_key = 0x00200309;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyDown);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("no event", element.InnerHTML().Utf8());

  // TODO(crbug.com/949766) Should cleanup these magic number.
  e.dom_key = 0x00200310;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_NE("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_NE("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyDown);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_NE("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_NE("no event", element.InnerHTML().Utf8());
}

TEST_F(EventHandlerSimTest, NotExposeKeyboardEvent) {
  GetDocument().GetSettings()->SetDontSendKeyEventsToJavascript(true);
  GetDocument().GetSettings()->SetScrollAnimatorEnabled(false);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
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
        let log = document.getElementById('log');
        log.innerText = 'keydown cancelable=' + e.cancelable;
      });
      document.addEventListener('keyup', (e) => {
        let log = document.getElementById('log');
        log.innerText = 'keyup cancelable=' + e.cancelable;
      });
    </script>
  )HTML");
  Compositor().BeginFrame();

  WebElement element = GetDocument().getElementById(AtomicString("log"));
  WebKeyboardEvent e{WebInputEvent::Type::kRawKeyDown,
                     WebInputEvent::kNoModifiers,
                     WebInputEvent::GetStaticTimeStampForTests()};
  e.windows_key_code = VKEY_DOWN;
  // TODO(crbug.com/949766) Should cleanup these magic number.
  e.dom_key = 0x00200309;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyDown);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("no event", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("no event", element.InnerHTML().Utf8());

  // Key send to js but not cancellable.
  e.dom_key = 0x00400031;
  e.SetType(WebInputEvent::Type::kRawKeyDown);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("keydown cancelable=false", element.InnerHTML().Utf8());

  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("keyup cancelable=false", element.InnerHTML().Utf8());

  // Key send to js and cancellable in editor.
  WebElement input = GetDocument().getElementById(AtomicString("input1"));
  GetDocument().SetFocusedElement(
      input.Unwrap<Element>(),
      FocusParams(SelectionBehaviorOnFocus::kNone,
                  mojom::blink::FocusType::kNone, nullptr));

  e.SetType(WebInputEvent::Type::kRawKeyDown);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  EXPECT_EQ("keydown cancelable=true", element.InnerHTML().Utf8());

  // Arrow key caused scroll down in post event dispatch process. Ensure page
  // scrolled.
  ScrollableArea* scrollable_area = GetDocument().View()->LayoutViewport();
  EXPECT_GT(scrollable_area->ScrollOffsetInt().y(), 0);
}

TEST_F(EventHandlerSimTest, DoNotScrollWithTouchpadIfOverflowIsHidden) {
  ResizeView(gfx::Size(400, 400));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #outer {
        width: 100vw;
        height: 100vh;
        overflow-x: hidden;
        overflow-y: scroll;
    }
    #inner {
        width: 300vw;
        height: 300vh;
    }
    </style>
    <body>
      <div id='outer'>
        <div id='inner'>
      </div>
    </body>
  )HTML");
  Compositor().BeginFrame();

  WebGestureEvent scroll_begin_event(
      WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      blink::WebGestureDevice::kTouchpad);
  scroll_begin_event.SetPositionInWidget(gfx::PointF(10, 10));
  scroll_begin_event.SetPositionInScreen(gfx::PointF(10, 10));

  WebGestureEvent scroll_update_event(
      WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      blink::WebGestureDevice::kTouchpad);
  scroll_update_event.data.scroll_update.delta_x = -100;
  scroll_update_event.data.scroll_update.delta_y = -100;
  scroll_update_event.SetPositionInWidget(gfx::PointF(10, 10));
  scroll_update_event.SetPositionInScreen(gfx::PointF(10, 10));

  WebGestureEvent scroll_end_event(WebInputEvent::Type::kGestureScrollEnd,
                                   WebInputEvent::kNoModifiers,
                                   WebInputEvent::GetStaticTimeStampForTests(),
                                   blink::WebGestureDevice::kTouchpad);
  scroll_end_event.SetPositionInWidget(gfx::PointF(10, 10));
  scroll_end_event.SetPositionInScreen(gfx::PointF(10, 10));

  GetWebFrameWidget().DispatchThroughCcInputHandler(scroll_begin_event);
  GetWebFrameWidget().DispatchThroughCcInputHandler(scroll_update_event);
  GetWebFrameWidget().DispatchThroughCcInputHandler(scroll_end_event);

  Compositor().BeginFrame();
  EXPECT_EQ(0,
            GetDocument().getElementById(AtomicString("outer"))->scrollLeft());
}

TEST_F(EventHandlerSimTest, ElementTargetedGestureScroll) {
  ResizeView(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #scroller {
        overflow-y:scroll;
        height:200px;
      }
      #talldiv {
        height:1000px;
      }
    </style>
    <div id="talldiv">Tall text to create viewport scrollbar</div>
    <div id="scroller">
      <div style="height:2000px">To create subscroller scrollbar</div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Element* const scroller =
      GetDocument().getElementById(AtomicString("scroller"));
  constexpr float delta_y = 100;
  // Send GSB/GSU at 0,0 to target the viewport first, then verify that
  // the viewport scrolled accordingly.
  WebGestureEvent gesture_scroll_begin{
      WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  gesture_scroll_begin.data.scroll_begin.delta_x_hint = 0;
  gesture_scroll_begin.data.scroll_begin.delta_y_hint = -delta_y;
  DispatchElementTargetedGestureScroll(gesture_scroll_begin);

  WebGestureEvent gesture_scroll_update{
      WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  gesture_scroll_update.data.scroll_update.delta_x = 0;
  gesture_scroll_update.data.scroll_update.delta_y = -delta_y;

  DispatchElementTargetedGestureScroll(gesture_scroll_update);

  WebGestureEvent gesture_scroll_end{
      WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  DispatchElementTargetedGestureScroll(gesture_scroll_end);

  Compositor().BeginFrame();
  LocalFrameView* frame_view = GetDocument().View();
  ASSERT_EQ(frame_view->LayoutViewport()->GetScrollOffset().y(), delta_y);

  // Switch to the element_id-based targeting for GSB, then resend GSU
  // and validate that the subscroller scrolled (and that the viewport
  // did not).
  ScrollableArea* scrollable_area =
      scroller->GetLayoutBox()->GetScrollableArea();
  gesture_scroll_begin.data.scroll_begin.scrollable_area_element_id =
      scrollable_area->GetScrollElementId().GetInternalValue();

  DispatchElementTargetedGestureScroll(gesture_scroll_begin);
  DispatchElementTargetedGestureScroll(gesture_scroll_update);
  DispatchElementTargetedGestureScroll(gesture_scroll_end);

  Compositor().BeginFrame();
  ASSERT_EQ(scrollable_area->ScrollOffsetInt().y(), delta_y);
  ASSERT_EQ(frame_view->LayoutViewport()->GetScrollOffset().y(), delta_y);

  // Remove the scroller, update layout, and ensure the same gestures
  // don't crash or scroll the layout viewport.
  scroller->remove();
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  DispatchElementTargetedGestureScroll(gesture_scroll_begin);
  DispatchElementTargetedGestureScroll(gesture_scroll_update);
  DispatchElementTargetedGestureScroll(gesture_scroll_end);

  Compositor().BeginFrame();
  ASSERT_EQ(frame_view->LayoutViewport()->GetScrollOffset().y(), delta_y);
}

TEST_F(EventHandlerSimTest, ElementTargetedGestureScrollIFrame) {
  ResizeView(gfx::Size(800, 600));
  SimRequest request_outer("https://example.com/test-outer.html", "text/html");
  SimRequest request_inner("https://example.com/test-inner.html", "text/html");
  LoadURL("https://example.com/test-outer.html");
  request_outer.Complete(R"HTML(
    <!DOCTYPE html>
    <iframe id="iframe" src="test-inner.html"></iframe>
    <div style="height:1000px"></div>
    )HTML");

  request_inner.Complete(R"HTML(
    <!DOCTYPE html>
    <div style="height:1000px"></div>
  )HTML");
  Compositor().BeginFrame();

  auto* const iframe = To<HTMLFrameElementBase>(
      GetDocument().getElementById(AtomicString("iframe")));
  FrameView* child_frame_view =
      iframe->GetLayoutEmbeddedContent()->ChildFrameView();
  auto* local_child_frame_view = DynamicTo<LocalFrameView>(child_frame_view);
  ScrollableArea* scrollable_area = local_child_frame_view->GetScrollableArea();

  // Target the iframe scrollable area and make sure it scrolls when targeted
  // with gestures.
  constexpr float delta_y = 100;
  WebGestureEvent gesture_scroll_begin{
      WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  gesture_scroll_begin.data.scroll_begin.delta_x_hint = 0;
  gesture_scroll_begin.data.scroll_begin.delta_y_hint = -delta_y;
  gesture_scroll_begin.data.scroll_begin.scrollable_area_element_id =
      scrollable_area->GetScrollElementId().GetInternalValue();
  DispatchElementTargetedGestureScroll(gesture_scroll_begin);

  WebGestureEvent gesture_scroll_update{
      WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  gesture_scroll_update.data.scroll_update.delta_x = 0;
  gesture_scroll_update.data.scroll_update.delta_y = -delta_y;

  DispatchElementTargetedGestureScroll(gesture_scroll_update);

  WebGestureEvent gesture_scroll_end{
      WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  DispatchElementTargetedGestureScroll(gesture_scroll_end);

  Compositor().BeginFrame();
  LocalFrameView* frame_view = GetDocument().View();
  ASSERT_EQ(frame_view->LayoutViewport()->GetScrollOffset().y(), 0);
  ASSERT_EQ(scrollable_area->ScrollOffsetInt().y(), delta_y);
}

TEST_F(EventHandlerSimTest, ElementTargetedGestureScrollViewport) {
  ResizeView(gfx::Size(800, 600));
  // Set a page scale factor so that the VisualViewport will also scroll.
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div style="height:1000px">Tall text to create viewport scrollbar</div>
  )HTML");
  WebView().SetPageScaleFactor(2);
  Compositor().BeginFrame();

  // Delta in (scaled) physical pixels.
  constexpr float delta_y = 1400;
  const VisualViewport& visual_viewport =
      GetDocument().GetPage()->GetVisualViewport();
  const ScrollableArea& layout_viewport =
      *GetDocument().View()->LayoutViewport();

  WebGestureEvent gesture_scroll_begin{
      WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  gesture_scroll_begin.data.scroll_begin.delta_x_hint = 0;
  gesture_scroll_begin.data.scroll_begin.delta_y_hint = -delta_y;

  // For a viewport-distributed scroll, cc::Viewport::ScrollBy expects the
  // layout viewport to be the "currently scrolling node".  On desktop, viewport
  // scrollbars are owned by the layout viewport, so scrollbar interactions will
  // inject appropriately-targeted GestureScrollBegin.  On Android, scrollbars
  // are owned by the visual viewport, but they don't support interactions, so
  // we never see injected GSB targeting the visual viewport.
  gesture_scroll_begin.data.scroll_begin.scrollable_area_element_id =
      layout_viewport.GetScrollElementId().GetInternalValue();

  GetWebFrameWidget().DispatchThroughCcInputHandler(gesture_scroll_begin);

  WebGestureEvent gesture_scroll_update{
      WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  gesture_scroll_update.data.scroll_update.delta_x = 0;
  gesture_scroll_update.data.scroll_update.delta_y = -delta_y;

  GetWebFrameWidget().DispatchThroughCcInputHandler(gesture_scroll_update);

  WebGestureEvent gesture_scroll_end{
      WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(),
      WebGestureDevice::kTouchscreen};
  GetWebFrameWidget().DispatchThroughCcInputHandler(gesture_scroll_end);

  Compositor().BeginFrame();
  ASSERT_EQ(layout_viewport.GetScrollOffset().y(), 400);
  ASSERT_EQ(visual_viewport.GetScrollOffset().y(), 300);
}

TEST_F(EventHandlerSimTest, SelecteTransformedTextWhenCapturing) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
      <div id='target' style = "width:250px; transform: rotate(180deg)">
      Some text to select
      </div>
  )HTML");
  Compositor().BeginFrame();

  WebMouseEvent mouse_down_event(WebInputEvent::Type::kMouseDown,
                                 gfx::PointF(100, 20), gfx::PointF(0, 0),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);

  ASSERT_TRUE(GetDocument()
                  .GetFrame()
                  ->GetEventHandler()
                  .GetSelectionController()
                  .MouseDownMayStartSelect());

  Element* target = GetDocument().getElementById(AtomicString("target"));
  GetDocument().GetFrame()->GetEventHandler().SetPointerCapture(
      PointerEventFactory::kMouseId, target);

  WebMouseEvent mouse_move_event(WebInputEvent::Type::kMouseMove,
                                 gfx::PointF(258, 20), gfx::PointF(0, 0),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  WebMouseEvent mouse_up_event(
      WebMouseEvent::Type::kMouseUp, gfx::PointF(258, 20), gfx::PointF(0, 0),
      WebPointerProperties::Button::kLeft, 1, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(
      mouse_up_event);

  ASSERT_FALSE(GetDocument()
                   .GetFrame()
                   ->GetEventHandler()
                   .GetSelectionController()
                   .MouseDownMayStartSelect());

  ASSERT_TRUE(GetDocument().GetSelection());
  EXPECT_EQ("Some text to select", GetDocument().GetSelection()->toString());
}

// Test that mouse right button down and move to an iframe will route the events
// to iframe correctly.
TEST_F(EventHandlerSimTest, MouseRightButtonDownMoveToIFrame) {
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
  WebMouseEvent mouse_down_outside_event(
      WebMouseEvent::Type::kMouseDown, gfx::PointF(300, 29),
      gfx::PointF(300, 29), WebPointerProperties::Button::kRight, 0,
      WebInputEvent::Modifiers::kRightButtonDown,
      WebInputEvent::GetStaticTimeStampForTests());
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_down_outside_event, ui::LatencyInfo()));

  WebMouseEvent mouse_move_outside_event(
      WebMouseEvent::Type::kMouseMove, gfx::PointF(300, 29),
      gfx::PointF(300, 29), WebPointerProperties::Button::kRight, 0,
      WebInputEvent::Modifiers::kRightButtonDown,
      WebInputEvent::GetStaticTimeStampForTests());
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_move_outside_event, ui::LatencyInfo()));

  WebMouseEvent mouse_move_inside_event(
      WebMouseEvent::Type::kMouseMove, gfx::PointF(100, 229),
      gfx::PointF(100, 229), WebPointerProperties::Button::kRight, 0,
      WebInputEvent::Modifiers::kRightButtonDown,
      WebInputEvent::GetStaticTimeStampForTests());
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_move_inside_event, ui::LatencyInfo()));
  EXPECT_FALSE(
      GetDocument().GetFrame()->GetEventHandler().IsMousePositionUnknown());
  EXPECT_FALSE(To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild())
                   ->GetEventHandler()
                   .IsMousePositionUnknown());
}

// Tests that pen dragging on an element and moves will keep the element active.
TEST_F(EventHandlerSimTest, PenDraggingOnElementActive) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  SimRequest main_resource("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    div {
      width: 200px;
      height: 200px;
    }
    </style>
    <div id="target"></div>
  )HTML");

  Compositor().BeginFrame();
  WebMouseEvent pen_down(WebMouseEvent::Type::kMouseDown, gfx::PointF(100, 100),
                         gfx::PointF(100, 100),
                         WebPointerProperties::Button::kLeft, 0,
                         WebInputEvent::Modifiers::kLeftButtonDown,
                         WebInputEvent::GetStaticTimeStampForTests());
  pen_down.pointer_type = blink::WebPointerProperties::PointerType::kPen;
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(pen_down, ui::LatencyInfo()));

  WebMouseEvent pen_move(WebMouseEvent::Type::kMouseMove, gfx::PointF(100, 100),
                         gfx::PointF(100, 100),
                         WebPointerProperties::Button::kLeft, 0,
                         WebInputEvent::Modifiers::kLeftButtonDown,
                         WebInputEvent::GetStaticTimeStampForTests());
  pen_move.pointer_type = blink::WebPointerProperties::PointerType::kPen;
  // Send first mouse move to update mouse event sates.
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(pen_move, ui::LatencyInfo()));

  // Send another mouse move again to update active element to verify mouse
  // event states.
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(pen_move, ui::LatencyInfo()));

  EXPECT_EQ(GetDocument().GetActiveElement(),
            GetDocument().getElementById(AtomicString("target")));
}

TEST_F(EventHandlerSimTest, TestNoCrashOnMouseWheelZeroDelta) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body>
      <div id="area" style="width:100px;height:100px">
      </div>
      <p id='log'>no wheel event</p>
    </body>
    <script>
      document.addEventListener('wheel', (e) => {
        let log = document.getElementById('log');
        log.innerText = 'received wheel event, deltaX: ' + e.deltaX + ' deltaY: ' + e.deltaY;
      });
    </script>
  )HTML");
  Compositor().BeginFrame();

  // Set mouse position and active web view.
  InitializeMousePositionAndActivateView(50, 50);
  Compositor().BeginFrame();

  WebElement element = GetDocument().getElementById(AtomicString("log"));
  WebMouseWheelEvent wheel_event(
      blink::WebInputEvent::Type::kMouseWheel,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  wheel_event.SetPositionInScreen(50, 50);
  wheel_event.delta_x = 0;
  wheel_event.delta_y = 0;
  wheel_event.phase = WebMouseWheelEvent::kPhaseBegan;
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("received wheel event, deltaX: 0 deltaY: 0",
            element.InnerHTML().Utf8());
  ASSERT_EQ(0, GetDocument().View()->LayoutViewport()->GetScrollOffset().y());
  ASSERT_EQ(0, GetDocument().View()->LayoutViewport()->GetScrollOffset().x());
}

// The mouse wheel events which have the phases of "MayBegin" or "Cancel"
// should fire wheel events to the DOM.
TEST_F(EventHandlerSimTest, TestNoWheelEventWithPhaseMayBeginAndCancel) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body>
      <div id="area" style="width:100px;height:100px">
      </div>
      <p id='log'>no wheel event</p>
    </body>
    <script>
      document.addEventListener('wheel', (e) => {
        let log = document.getElementById('log');
        log.innerText = 'received wheel event, deltaX: ' + e.deltaX + ' deltaY: ' + e.deltaY;
      });
    </script>
  )HTML");
  Compositor().BeginFrame();

  // Set mouse position and active web view.
  InitializeMousePositionAndActivateView(50, 50);
  Compositor().BeginFrame();

  WebElement element = GetDocument().getElementById(AtomicString("log"));
  WebMouseWheelEvent wheel_event(
      blink::WebInputEvent::Type::kMouseWheel,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  wheel_event.SetPositionInScreen(50, 50);
  wheel_event.delta_x = 0;
  wheel_event.delta_y = 0;
  wheel_event.phase = WebMouseWheelEvent::kPhaseMayBegin;
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("no wheel event", element.InnerHTML().Utf8());

  wheel_event.phase = WebMouseWheelEvent::kPhaseCancelled;
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("no wheel event", element.InnerHTML().Utf8());
}

// The mouse wheel events which have the phases of "End" should fire wheel
// events to the DOM, but for other phases like "Begin", "Change" and
// "Stationary", there should be wheels evnets fired to the DOM.
TEST_F(EventHandlerSimTest, TestWheelEventsWithDifferentPhases) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <body>
      <div id="area" style="width:100px;height:100px">
      </div>
      <p id='log'>no wheel event</p>
    </body>
    <script>
      document.addEventListener('wheel', (e) => {
        let log = document.getElementById('log');
        log.innerText = 'received wheel event, deltaX: ' + e.deltaX + ' deltaY: ' + e.deltaY;
      });
    </script>
  )HTML");
  Compositor().BeginFrame();

  // Set mouse position and active web view.
  InitializeMousePositionAndActivateView(50, 50);
  Compositor().BeginFrame();

  auto* element = GetDocument().getElementById(AtomicString("log"));
  WebMouseWheelEvent wheel_event(
      blink::WebInputEvent::Type::kMouseWheel,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  wheel_event.SetPositionInScreen(50, 50);
  wheel_event.delta_x = 0;
  wheel_event.delta_y = 0;
  wheel_event.phase = WebMouseWheelEvent::kPhaseMayBegin;
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("no wheel event", element->innerHTML().Utf8());

  wheel_event.delta_y = -1;
  wheel_event.phase = WebMouseWheelEvent::kPhaseBegan;
  element->setInnerHTML("no wheel event");
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("received wheel event, deltaX: 0 deltaY: 1",
            element->innerHTML().Utf8());

  wheel_event.delta_y = -2;
  wheel_event.phase = WebMouseWheelEvent::kPhaseChanged;
  element->setInnerHTML("no wheel event");
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("received wheel event, deltaX: 0 deltaY: 2",
            element->innerHTML().Utf8());

  wheel_event.delta_y = -3;
  wheel_event.phase = WebMouseWheelEvent::kPhaseChanged;
  element->setInnerHTML("no wheel event");
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("received wheel event, deltaX: 0 deltaY: 3",
            element->innerHTML().Utf8());

  wheel_event.delta_y = -4;
  wheel_event.phase = WebMouseWheelEvent::kPhaseStationary;
  element->setInnerHTML("no wheel event");
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("received wheel event, deltaX: 0 deltaY: 4",
            element->innerHTML().Utf8());

  wheel_event.delta_y = -5;
  wheel_event.phase = WebMouseWheelEvent::kPhaseChanged;
  element->setInnerHTML("no wheel event");
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("received wheel event, deltaX: 0 deltaY: 5",
            element->innerHTML().Utf8());

  wheel_event.delta_y = 0;
  wheel_event.phase = WebMouseWheelEvent::kPhaseEnded;
  element->setInnerHTML("no wheel event");
  GetDocument().GetFrame()->GetEventHandler().HandleWheelEvent(wheel_event);
  EXPECT_EQ("no wheel event", element->innerHTML().Utf8());
}

TEST_F(EventHandlerSimTest, TestScrollendFiresOnKeyUpAfterScroll) {
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
  // BeginFrame to create scroll_animation.
  Compositor().BeginFrame();
  // BeginFrame to Tick scroll_animation far enough to complete scroll.
  Compositor().BeginFrame(0.30);

  // The first invocation of BeginFrame will create another scroll_animation
  // and subsequent ones will update the animation target.
  for (int i = 0; i < num_keydowns - 1; i++) {
    GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
    Compositor().BeginFrame();
  }
  // BeginFrame to advance to the end of the last scroll animation.
  Compositor().BeginFrame(0.15 * num_keydowns);

  // Verify that we have not yet fired scrollend.
  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("log"))->innerHTML().Utf8(),
      "");

  // Fire keyUp, which should tigger a scrollend event.
  e.SetType(WebInputEvent::Type::kKeyUp);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);

  Compositor().BeginFrame();
  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("log"))->innerHTML().Utf8(),
      "scrollend");
}

TEST_F(EventHandlerSimTest, TestScrollendFiresAfterScrollWithEarlyKeyUp) {
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

  GetDocument()
      .getElementById(AtomicString("scroller"))
      ->Focus(FocusOptions::Create());

  // Send first keyDown.
  e.windows_key_code = VKEY_DOWN;
  e.SetType(WebInputEvent::Type::kKeyDown);
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  // BeginFrame to create first scroll_animation.
  Compositor().BeginFrame();
  // BeginFrame to tick first scroll_animation to completion.
  Compositor().BeginFrame(0.30);

  // Start a second scroll_animation that should end after the keyup event.
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  Compositor().BeginFrame();

  // Verify
```