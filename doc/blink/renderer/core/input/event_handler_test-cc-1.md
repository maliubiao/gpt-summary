Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. The file is `blink/renderer/core/input/event_handler_test.cc`.

I need to:
1. **List the functionalities** demonstrated by the code.
2. **Identify relationships** with JavaScript, HTML, and CSS and provide examples.
3. **Explain logical inferences** with hypothetical inputs and outputs.
4. **Illustrate common user/programming errors** using examples.
5. **Describe user actions** leading to these code executions (debugging perspective).
6. **Summarize the overall functionality** of the provided code block as part 2 of 5.

The code consists of several test cases using the `TEST_F` macro, which indicates that these are unit tests. Each test case focuses on a specific aspect of event handling within the Blink rendering engine.

**Functionalities observed in the code:**

- **Cursor handling:** Testing cursor types based on element properties (resize, writing-mode).
- **Keyboard event handling:** Simulating key presses for spatial navigation and other actions.
- **Context menu event handling:** Verifying that context menu events are dispatched correctly with up-to-date layout.
- **Tap event handling:** Testing behavior for single and double taps on text fields and editable elements, including selection and insertion handle visibility.
- **Long press event handling:**  Testing behavior for long presses on text fields.
- **Mouse event handling:** Testing behavior of mouse clicks (single, double, triple) and drag-and-drop interactions, including the effect of `user-select: none`.
- **Tooltip handling:** Testing how tooltips are displayed and cleared based on mouse events, keyboard focus, and script interactions.
- **Gesture event handling:**  Testing handling of two-finger tap gestures and scenarios with held-back touch pointer events.
- **Drag and drop:** Testing the `dragEndInNewDrag` scenario and ensuring fake mouse moves don't trigger drag.

**Relationships with JavaScript, HTML, and CSS:**

- **HTML:** The tests use `SetHtmlInnerHTML` to create DOM structures for testing. They interact with specific HTML elements like `<button>`, `<p>`, `<div>`, `<textarea>`, `<img>`, and elements with `contenteditable` and `draggable` attributes.
- **CSS:** CSS styles are used within the HTML to influence element behavior, such as `resize`, `writing-mode`, `display`, `user-select`, and `:hover` effects. These styles are directly involved in determining cursor types and event handling outcomes.
- **JavaScript:** Some tests involve setting up event listeners in JavaScript (`document.addEventListener`) to simulate user interactions or prevent default behavior.

**Logical inferences:**

- **Cursor type determination:** If an element has `resize: both` and the mouse is near a corner, the cursor should change to a resize cursor (e.g., `kSouthWestResize`, `kSouthEastResize`). The writing mode (`vertical-lr`) influences which corner triggers which cursor.
    - **Input:** An HTML element with `style='resize:both;writing-mode:vertical-lr;width:30px;height:30px;overflow:hidden;display:inline'` and a mouse coordinate near the origin.
    - **Output:** The cursor type is `ui::mojom::blink::CursorType::kSouthEastResize`.
- **Text selection on double tap:** If a user double-taps within a `contenteditable` element, the nearest word should be selected.
    - **Input:** A double-tap gesture event on the word "selection" within a `contenteditable` `<p>` tag.
    - **Output:** The text "selection" is selected.
- **Tooltip visibility:** If the mouse hovers over an element with a `title` attribute, the tooltip with the title text should be displayed. Moving the mouse away should hide it. Focusing an element with the Tab key should also show its tooltip.

**Common user/programming errors:**

- **Forgetting to prevent default:** In the context menu test, the JavaScript `event.preventDefault()` is crucial to observe the test behavior. Forgetting this would lead to the browser's default context menu appearing.
- **Incorrect event coordinates:** Providing incorrect coordinates for simulated mouse or touch events might lead to the events not hitting the intended elements, causing tests to fail.
- **Misunderstanding event ordering:** The `dragEndInNewDrag` test highlights a potential error in the sequence of drag events, which should be handled gracefully by the engine.

**User operations as debugging clues:**

- **Mouse movements:** Moving the mouse over elements can trigger `mousemove` and `mouseleave` events, relevant for tooltip tests and cursor changes.
- **Mouse clicks:** Clicking on elements triggers `mousedown` and `mouseup` events, crucial for selection, focus, and drag-and-drop.
- **Keyboard input:** Pressing keys triggers `keydown` and `keyup` events, relevant for navigation (Tab key), access keys (Alt + key), and text input.
- **Touch gestures:** Tapping, double-tapping, long-pressing, and two-finger tapping on touch devices trigger various gesture events, important for text editing and other interactive elements.
- **Right-clicking:** Right-clicking triggers `contextmenu` events.

**Summary of functionality (Part 2):**

This section of the `event_handler_test.cc` file primarily focuses on testing the behavior of the Blink rendering engine's event handling logic related to **cursor appearance, keyboard interactions, context menus, and basic touch gestures (taps and long presses) on various HTML elements, especially those involved in text input and editing.** It includes tests for cursor changes based on CSS properties, handling of key events for navigation, preventing default context menu behavior, and managing text selection and insertion handles on touch devices. Furthermore, it begins to explore drag-and-drop scenarios and the display of tooltips based on user interactions.

这是 `blink/renderer/core/input/event_handler_test.cc` 文件的第二部分，主要功能是**测试 Blink 渲染引擎处理各种用户输入事件的行为，特别是与光标显示、键盘事件、上下文菜单事件以及触摸手势相关的逻辑。** 这部分代码着重于验证事件处理器在不同场景下的正确性，包括元素样式（如 `resize` 和 `writing-mode`）对光标的影响，键盘导航，以及触摸操作（如点击和长按）在文本编辑区域的行为。

下面对各个方面进行更详细的解释：

**1. 功能列举:**

* **测试不同 `resize` 属性和书写模式 (`writing-mode`) 下的光标显示:** 验证当鼠标移动到设置了 `resize:both` 且具有不同 `writing-mode` 属性的元素边缘时，光标是否正确显示为相应的缩放光标 (例如 `kSouthWestResize`, `kSouthEastResize`)。
* **测试键盘事件处理:**
    * 模拟按下方向键 (`ARROW_DOWN`) 和特定键码 (`0x00200310`)，用于测试空间导航等功能。
* **测试上下文菜单事件处理 (`contextmenu`):**
    * 验证在元素上触发 `contextmenu` 事件时，是否使用了最新的布局树，特别是在存在 `:hover` 样式的情况下。
    * 测试通过 JavaScript 的 `event.preventDefault()` 阻止默认上下文菜单的行为。
* **测试触摸事件处理 (Tap 和 Long Press):**
    * **Tap (点击):**
        * 验证在空的和非空的 `<textarea>` 元素上点击时，光标的显示和插入光标控制柄的可见性。
        * 验证在包含 `<br/>` 的 `contenteditable` 的 `<div>` 上点击时的行为。
    * **Long Press (长按):**
        * 验证在空的和非空的 `<textarea>` 元素上长按时，光标和插入光标控制柄的显示。
        * 测试在长按后，单击空白编辑字段是否会清除插入光标控制柄。
    * **Double Press (双击):**
        * 验证在 `contenteditable` 元素上双击是否能选中附近的单词。
        * 测试在双击期间，如果 `mousedown` 事件被 `preventDefault()` 阻止，是否会阻止文本选中。
* **测试鼠标事件处理:**
    * 验证在文本区域，通过鼠标事件 (单击、双击、三击) 触发光标移动或选择时，是否不会显示插入光标控制柄 (这通常是触摸设备的特性)。
    * 测试在 `user-select: none` 的父元素下，包含 `user-select: text` 的子元素的情况下，三击鼠标的选中文本行为。
* **测试拼写错误上下文菜单事件:**
    * 验证在包含拼写错误的文本区域，触发上下文菜单时，光标和插入光标控制柄的显示状态。
* **测试触摸调整算法在没有布局对象的 `contenteditable` 元素上的处理:**  确保在 `display: contents` 的可编辑元素上进行触摸操作不会崩溃。
* **测试处理“滞后”的触摸指针事件引起的双指手势:** 模拟一种多点触摸场景，其中第一个触摸点的事件未发送到 Blink，但后续的触摸点事件被发送，验证事件处理器的健壮性。
* **测试 `dragEndInNewDrag` 场景:**  模拟在拖放操作尚未开始时就调用 `DragSourceEndedAt` 的情况，测试事件处理器的容错能力。
* **测试带有修饰符 `kRelativeMotionEvent` 的虚假鼠标移动事件是否会触发拖放:** 验证带有特定修饰符的 `mousemove` 事件不会意外启动拖放操作。
* **测试工具提示 (Tooltip) 的显示和清除:**
    * 验证鼠标移入和移出带有 `title` 属性的元素时，工具提示的显示和清除。
    * 验证通过 Tab 键切换焦点时，带有 `title` 属性的元素是否会更新工具提示。
    * 验证通过快捷键 (`accessKey`) 切换焦点时，工具提示的更新。
    * 验证通过鼠标操作或脚本设置焦点时，是否不会触发键盘触发的工具提示更新。
    * 验证在脚本触发焦点设置时（由按键事件引起），工具提示的更新。
    * 验证通过脚本设置焦点到没有 `title` 属性的元素时，是否会清除之前键盘触发的工具提示。
    * 验证当鼠标触发的工具提示可见时，通过脚本设置焦点是否不会清除该工具提示。

**2. 与 JavaScript, HTML, CSS 的关系:**

* **HTML:** 代码使用 `SetHtmlInnerHTML` 函数来设置测试所需的 HTML 结构。例如，创建带有 `resize` 样式的 `<p>` 标签，包含 `contenteditable` 属性的 `<div>` 或 `<textarea>` 元素，以及带有 `title` 和 `accessKey` 属性的 `<button>` 元素。
    ```c++
    SetHtmlInnerHTML(
        "Test<p style='resize:both;writing-mode:vertical-lr;...'>...</p>Test");
    SetHtmlInnerHTML("<textarea cols=50 rows=50></textarea>");
    SetHtmlInnerHTML(
        R"HTML(
          <button id='b1' title='my tooltip 1'>button 1</button>
        )HTML");
    ```
* **CSS:**  测试依赖于 CSS 样式来触发特定的行为。例如，`resize:both` 用于测试缩放光标，`writing-mode:vertical-lr` 用于测试垂直书写模式下的光标，`user-select: none` 用于测试文本选择行为，`:hover` 用于测试上下文菜单事件。
    ```c++
    SetHtmlInnerHTML(
        "<style>*:hover { color: red; }</style>"
        "<div>foo</div>");
    ```
* **JavaScript:**  部分测试使用 JavaScript 代码来模拟用户行为或设置事件监听器。例如，阻止默认的上下文菜单行为：
    ```c++
    Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
    script->setInnerHTML(
        "document.addEventListener('contextmenu', event => "
        "event.preventDefault());");
    GetDocument().body()->AppendChild(script);
    ```

**3. 逻辑推理 (假设输入与输出):**

* **假设输入:** 一个 HTML 元素 `<div style='resize:both;width:30px;height:30px;'></div>`，鼠标坐标位于该元素的右下角附近。
* **输出:**  `EventHandler::SelectCursor` 函数应该返回一个表示 `kSouthEastResize` 光标类型的枚举值。

* **假设输入:** 用户在 `contenteditable` 的 `<p>` 元素 "Test selection" 中的 "selection" 单词上进行双击操作。
* **输出:** `Selection().SelectedText()` 应该返回字符串 "selection"，表示该单词被选中。

**4. 用户或编程常见的使用错误:**

* **未正确处理事件的 `preventDefault()`:**  例如，在测试上下文菜单时，如果没有在 JavaScript 中调用 `event.preventDefault()`，浏览器可能会显示默认的上下文菜单，导致测试结果与预期不符。
* **事件坐标计算错误:** 在模拟鼠标或触摸事件时，如果提供的坐标不正确，可能导致事件没有命中预期的目标元素，从而使测试失败。
* **对事件顺序的错误假设:** `dragEndInNewDrag` 测试场景模拟了一种不常见的事件顺序，即在拖放操作开始之前就收到了拖放结束的事件。开发者可能会错误地假设拖放结束事件总是发生在拖放开始之后。

**5. 用户操作如何一步步的到达这里 (调试线索):**

* **光标测试:** 用户将鼠标指针移动到可以调整大小的元素的边缘或角落。
* **键盘事件测试:** 用户按下键盘上的特定按键，例如方向键或 Tab 键。
* **上下文菜单测试:** 用户在元素上点击鼠标右键或长按（在触摸设备上）。
* **触摸事件测试:** 用户在屏幕上进行点击、双击或长按操作。
* **鼠标事件测试:** 用户进行鼠标点击、双击或三击操作。
* **工具提示测试:** 用户将鼠标悬停在带有 `title` 属性的元素上，或使用 Tab 键切换焦点。

作为调试线索，这些测试用例模拟了用户的各种输入操作，可以帮助开发者理解当用户执行特定操作时，Blink 引擎是如何响应的，以及事件是如何被处理和传递的。如果出现与用户交互相关的 Bug，可以参考这些测试用例，并尝试重现 Bug 触发的事件序列，来定位问题所在。

**6. 功能归纳 (第2部分):**

总而言之，这部分 `event_handler_test.cc` 代码的主要功能是**验证 Blink 渲染引擎的核心事件处理机制在各种用户交互场景下的正确性，特别是关注光标的显示逻辑、键盘事件处理、上下文菜单事件的派发以及触摸手势在文本编辑区域的行为。** 它通过模拟用户操作和检查预期的状态变化（例如光标类型、文本选择、工具提示显示等）来确保事件处理的稳定性和可靠性。 这一部分深入探讨了用户与网页的交互方式，并针对不同的交互模式进行了细致的测试。

### 提示词
```
这是目录为blink/renderer/core/input/event_handler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
element->GetLayoutObject()->AbsoluteBoundingBoxRect().bottom_left();
  point.Offset(5, -5);
  HitTestLocation location(point);
  HitTestResult result =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_EQ(GetDocument()
                .GetFrame()
                ->GetEventHandler()
                .SelectCursor(location, result)
                .value()
                .type(),
            // An south-west resize signals both horizontal and
            // vertical resizability when direction is RTL.
            ui::mojom::blink::CursorType::kSouthWestResize);
}

TEST_F(EventHandlerTest, CursorForInlineVerticalWritingMode) {
  SetHtmlInnerHTML(
      "Test<p style='resize:both;writing-mode:vertical-lr;"
      "width:30px;height:30px;overflow:hidden;display:inline'>Test "
      "Test</p>Test");
  Node* const element = GetDocument().body()->firstChild()->nextSibling();
  gfx::Point point =
      element->GetLayoutObject()->AbsoluteBoundingBoxRect().origin();
  point.Offset(25, 25);
  HitTestLocation location(point);
  HitTestResult result =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_EQ(GetDocument()
                .GetFrame()
                ->GetEventHandler()
                .SelectCursor(location, result)
                .value()
                .type(),
            ui::mojom::blink::CursorType::kSouthEastResize);
}

TEST_F(EventHandlerTest, CursorForBlockVerticalWritingMode) {
  SetHtmlInnerHTML(
      "Test<p style='resize:both;writing-mode:vertical-lr;"
      "width:30px;height:30px;overflow:hidden;display:block'>Test "
      "Test</p>Test");
  Node* const element = GetDocument().body()->firstChild()->nextSibling();
  gfx::Point point =
      element->GetLayoutObject()->AbsoluteBoundingBoxRect().origin();
  point.Offset(25, 25);
  HitTestLocation location(point);
  HitTestResult result =
      GetDocument().GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location);
  EXPECT_EQ(GetDocument()
                .GetFrame()
                ->GetEventHandler()
                .SelectCursor(location, result)
                .value()
                .type(),
            ui::mojom::blink::CursorType::kSouthEastResize);
}

TEST_F(EventHandlerTest, implicitSend) {
  SetHtmlInnerHTML("<button>abc</button>");
  GetDocument().GetSettings()->SetSpatialNavigationEnabled(true);

  WebKeyboardEvent e{WebInputEvent::Type::kRawKeyDown,
                     WebInputEvent::kNoModifiers,
                     WebInputEvent::GetStaticTimeStampForTests()};
  e.dom_code = static_cast<int>(ui::DomCode::ARROW_DOWN);
  e.dom_key = ui::DomKey::ARROW_DOWN;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);

  // TODO(crbug.com/949766) Should cleanup these magic numbers.
  e.dom_code = 0;
  e.dom_key = 0x00200310;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
}

// Regression test for http://crbug.com/641403 to verify we use up-to-date
// layout tree for dispatching "contextmenu" event.
TEST_F(EventHandlerTest, sendContextMenuEventWithHover) {
  SetHtmlInnerHTML(
      "<style>*:hover { color: red; }</style>"
      "<div>foo</div>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      "document.addEventListener('contextmenu', event => "
      "event.preventDefault());");
  GetDocument().body()->AppendChild(script);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position(GetDocument().body(), 0))
          .Build(),
      SetSelectionOptions());
  WebMouseEvent mouse_down_event(
      WebMouseEvent::Type::kMouseDown, gfx::PointF(0, 0), gfx::PointF(100, 200),
      WebPointerProperties::Button::kRight, 1,
      WebInputEvent::Modifiers::kRightButtonDown, base::TimeTicks::Now());
  EXPECT_EQ(WebInputEventResult::kHandledApplication,
            GetDocument().GetFrame()->GetEventHandler().SendContextMenuEvent(
                mouse_down_event));
}

TEST_F(EventHandlerTest, EmptyTextfieldInsertionOnTap) {
  SetHtmlInnerHTML("<textarea cols=50 rows=50></textarea>");

  TapEventBuilder single_tap_event(gfx::PointF(200, 200), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_FALSE(Selection().IsHandleVisible());
}

TEST_F(EventHandlerTest, NonEmptyTextfieldInsertionOnTap) {
  SetHtmlInnerHTML("<textarea cols=50 rows=50>Enter text</textarea>");

  TapEventBuilder single_tap_event(gfx::PointF(200, 200), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_TRUE(Selection().IsHandleVisible());
}

TEST_F(EventHandlerTest, NewlineDivInsertionOnTap) {
  SetHtmlInnerHTML("<div contenteditable><br/></div>");

  TapEventBuilder single_tap_event(gfx::PointF(10, 10), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_TRUE(Selection().IsHandleVisible());
}

TEST_F(EventHandlerTest, EmptyTextfieldInsertionOnLongPress) {
  SetHtmlInnerHTML("<textarea cols=50 rows=50></textarea>");

  LongPressEventBuilder long_press_event(gfx::PointF(200, 200));
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      long_press_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_TRUE(Selection().IsHandleVisible());

  // Single Tap on an empty edit field should clear insertion handle
  TapEventBuilder single_tap_event(gfx::PointF(200, 200), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_FALSE(Selection().IsHandleVisible());
}

TEST_F(EventHandlerTest, NonEmptyTextfieldInsertionOnLongPress) {
  SetHtmlInnerHTML("<textarea cols=50 rows=50>Enter text</textarea>");

  LongPressEventBuilder long_press_event(gfx::PointF(200, 200));
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      long_press_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_TRUE(Selection().IsHandleVisible());
}

TEST_F(EventHandlerTest, SelectionOnDoublePress) {
  ScopedTouchTextEditingRedesignForTest touch_text_editing_redesign(true);
  SetHtmlInnerHTML(
      R"HTML(
        <div id='targetdiv' style='font-size:500%;width:50px;'>
        <p id='target' contenteditable>Test selection</p>
        </div>
      )HTML");

  Element* element = GetDocument().getElementById(AtomicString("target"));
  gfx::PointF tap_point = gfx::PointF(element->BoundsInWidget().CenterPoint());
  TapDownEventBuilder single_tap_down_event(tap_point);
  single_tap_down_event.data.tap_down.tap_down_count = 1;
  TapEventBuilder single_tap_event(tap_point, 1);
  TapDownEventBuilder double_tap_down_event(tap_point);
  double_tap_down_event.data.tap_down.tap_down_count = 2;
  TapEventBuilder double_tap_event(tap_point, 2);

  // Double press should select nearest word.
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_down_event);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      double_tap_down_event);
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_EQ(Selection().SelectedText(), "selection");

  // Releasing double tap should keep the selection.
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      double_tap_event);
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  EXPECT_EQ(Selection().SelectedText(), "selection");
}

TEST_F(EventHandlerTest, SelectionOnDoublePressPreventDefaultMousePress) {
  ScopedTouchTextEditingRedesignForTest touch_text_editing_redesign(true);
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetHtmlInnerHTML(
      R"HTML(
        <div id='targetdiv' style='font-size:500%;width:50px;'>
        <p id='target' contenteditable>Test selection</p>
        </div>
      )HTML");
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      R"HTML(
        let targetDiv = document.getElementById('targetdiv');
        targetDiv.addEventListener('mousedown', (e) => {
          e.preventDefault();
        });
      )HTML");
  GetDocument().body()->AppendChild(script);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Element* element = GetDocument().getElementById(AtomicString("target"));
  gfx::PointF tap_point = gfx::PointF(element->BoundsInWidget().CenterPoint());
  TapDownEventBuilder single_tap_down_event(tap_point);
  single_tap_down_event.data.tap_down.tap_down_count = 1;
  TapEventBuilder single_tap_event(tap_point, 1);
  TapDownEventBuilder double_tap_down_event(tap_point);
  double_tap_down_event.data.tap_down.tap_down_count = 2;
  TapEventBuilder double_tap_event(tap_point, 2);

  // Double press should not select anything.
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_down_event);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      double_tap_down_event);
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());

  // Releasing double tap also should not select anything.
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      double_tap_event);
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
}

TEST_F(EventHandlerTest, ClearHandleAfterTap) {
  SetHtmlInnerHTML("<textarea cols=50  rows=10>Enter text</textarea>");

  // Show handle
  LongPressEventBuilder long_press_event(gfx::PointF(200, 10));
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      long_press_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_TRUE(Selection().IsHandleVisible());

  // Tap away from text area should clear handle
  TapEventBuilder single_tap_event(gfx::PointF(200, 350), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);

  ASSERT_FALSE(Selection().IsHandleVisible());
}

TEST_F(EventHandlerTest, HandleNotShownOnMouseEvents) {
  SetHtmlInnerHTML("<textarea cols=50 rows=50>Enter text</textarea>");

  MousePressEventBuilder left_mouse_press_event(
      gfx::Point(200, 200), 1, WebPointerProperties::Button::kLeft);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      left_mouse_press_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_FALSE(Selection().IsHandleVisible());

  MousePressEventBuilder right_mouse_press_event(
      gfx::Point(200, 200), 1, WebPointerProperties::Button::kRight);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      right_mouse_press_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_FALSE(Selection().IsHandleVisible());

  MousePressEventBuilder double_click_mouse_press_event(
      gfx::Point(200, 200), 2, WebPointerProperties::Button::kLeft);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      double_click_mouse_press_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  ASSERT_FALSE(Selection().IsHandleVisible());

  MousePressEventBuilder triple_click_mouse_press_event(
      gfx::Point(200, 200), 3, WebPointerProperties::Button::kLeft);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      triple_click_mouse_press_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsRange());
  ASSERT_FALSE(Selection().IsHandleVisible());
}

// https://crbug.com/1410448
TEST_F(EventHandlerTest,
       TripleClickUserSelectNoneParagraphWithSelectableChildren) {
  LoadAhem(*GetDocument().GetFrame());
  InsertStyleElement("body { margin: 0; font: 20px/1 Ahem; }");

  SetBodyInnerHTML(R"HTML(<div style="user-select:none">
        <span style="user-select:text">
          <span style="user-select:text">Hel</span>
          lo
        </span>
        <span style="user-select:text"> lo </span>
        <span style="user-select:text">there</span>
      </div>)HTML");

  MousePressEventBuilder triple_click_mouse_press_event(
      gfx::Point(10, 10), 3, WebPointerProperties::Button::kLeft);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      triple_click_mouse_press_event);

  EXPECT_EQ(R"HTML(<div style="user-select:none">
        <span style="user-select:text">
          <span style="user-select:text">^Hel</span>
          lo
        </span>
        <span style="user-select:text"> lo </span>
        <span style="user-select:text">there|</span>
      </div>)HTML",
            SelectionSample::GetSelectionText(
                *GetDocument().body(), Selection().GetSelectionInDOMTree()));
}

TEST_F(EventHandlerTest, MisspellingContextMenuEvent) {
  if (GetDocument()
          .GetFrame()
          ->GetEditor()
          .Behavior()
          .ShouldSelectOnContextualMenuClick())
    return;

  SetHtmlInnerHTML("<textarea cols=50 rows=50>Mispellinggg</textarea>");

  TapEventBuilder single_tap_event(gfx::PointF(10, 10), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_TRUE(Selection().IsHandleVisible());

  GetDocument().GetFrame()->GetEventHandler().ShowNonLocatedContextMenu(
      nullptr, kMenuSourceTouchHandle);

  ASSERT_TRUE(Selection().GetSelectionInDOMTree().IsCaret());
  ASSERT_TRUE(Selection().IsHandleVisible());
}

// Tests that touch adjustment algorithm can handle editable elements without
// layout objects.
//
// TODO(mustaq): A fix for https://crbug.com/1230045 can make this test
// obsolete.
TEST_F(EventHandlerTest, TouchAdjustmentOnEditableDisplayContents) {
  SetHtmlInnerHTML(
      "<div style='display:contents' contenteditable='true'>TEXT</div>");
  TapEventBuilder single_tap_event(gfx::PointF(1, 1), 1);
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      single_tap_event);

  LongPressEventBuilder long_press_event(gfx::PointF(1, 1));
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      long_press_event);

  // This test passes if it doesn't crash.
}

// Tests that `EventHandler` can gracefully handle a multi-touch gesture event
// for which the first touch pointer event was NOT sent to Blink but a latter
// touch pointer event was sent. https://crbug.com/1409069
TEST_F(EventHandlerTest, GestureHandlingForHeldBackTouchPointer) {
  SetHtmlInnerHTML("<div style='width:50px;height:50px'></div>");

  int32_t pointer_id_1 = 123;
  int32_t pointer_id_2 = 125;  // Must be greater than `pointer_id_1`.

  WebPointerEvent pointer_down_2 = CreateMinimalTouchPointerEvent(
      WebInputEvent::Type::kPointerDown, gfx::PointF(10, 10));
  pointer_down_2.unique_touch_event_id = pointer_id_2;
  GetDocument().GetFrame()->GetEventHandler().HandlePointerEvent(
      pointer_down_2, Vector<WebPointerEvent>(), Vector<WebPointerEvent>());

  WebGestureEvent two_finger_tap = CreateMinimalGestureEvent(
      WebInputEvent::Type::kGestureTwoFingerTap, gfx::PointF(20, 20));
  two_finger_tap.primary_unique_touch_event_id = pointer_id_1;

  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      two_finger_tap);

  // This test passes if it doesn't crash.
}

TEST_F(EventHandlerTest, dragEndInNewDrag) {
  SetHtmlInnerHTML(
      "<style>.box { width: 100px; height: 100px; display: block; }</style>"
      "<a class='box' href=''>Drag me</a>");

  WebMouseEvent mouse_down_event(
      WebInputEvent::Type::kMouseDown, gfx::PointF(50, 50), gfx::PointF(50, 50),
      WebPointerProperties::Button::kLeft, 1,
      WebInputEvent::Modifiers::kLeftButtonDown, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);

  WebMouseEvent mouse_move_event(
      WebInputEvent::Type::kMouseMove, gfx::PointF(51, 50), gfx::PointF(51, 50),
      WebPointerProperties::Button::kLeft, 1,
      WebInputEvent::Modifiers::kLeftButtonDown, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  // This reproduces what might be the conditions of http://crbug.com/677916
  //
  // TODO(crbug.com/682047): The call sequence below should not occur outside
  // this contrived test. Given the current code, it is unclear how the
  // dragSourceEndedAt() call could occur before a drag operation is started.

  WebMouseEvent mouse_up_event(
      WebInputEvent::Type::kMouseUp, gfx::PointF(100, 50),
      gfx::PointF(200, 250), WebPointerProperties::Button::kLeft, 1,
      WebInputEvent::kNoModifiers, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().DragSourceEndedAt(
      mouse_up_event, ui::mojom::blink::DragOperation::kNone);

  // This test passes if it doesn't crash.
}

// This test mouse move with modifier kRelativeMotionEvent
// should not start drag.
TEST_F(EventHandlerTest, FakeMouseMoveNotStartDrag) {
  SetHtmlInnerHTML(
      "<style>"
      "body { margin: 0px; }"
      ".line { font-family: sans-serif; background: blue; width: 300px; "
      "height: 30px; font-size: 40px; margin-left: 250px; }"
      "</style>"
      "<div style='width: 300px; height: 100px;'>"
      "<span class='line' draggable='true'>abcd</span>"
      "</div>");
  WebMouseEvent mouse_down_event(WebMouseEvent::Type::kMouseDown,
                                 gfx::PointF(262, 29), gfx::PointF(329, 67),
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);

  WebMouseEvent fake_mouse_move(
      WebMouseEvent::Type::kMouseMove, gfx::PointF(618, 298),
      gfx::PointF(685, 436), WebPointerProperties::Button::kLeft, 1,
      WebInputEvent::Modifiers::kLeftButtonDown |
          WebInputEvent::Modifiers::kRelativeMotionEvent,
      WebInputEvent::GetStaticTimeStampForTests());
  EXPECT_EQ(
      WebInputEventResult::kHandledSuppressed,
      GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
          fake_mouse_move, Vector<WebMouseEvent>(), Vector<WebMouseEvent>()));

  EXPECT_EQ(gfx::Point(0, 0), GetDocument()
                                  .GetFrame()
                                  ->GetEventHandler()
                                  .DragDataTransferLocationForTesting());
}

class TooltipCapturingChromeClient : public EmptyChromeClient {
 public:
  TooltipCapturingChromeClient() = default;

  void UpdateTooltipUnderCursor(LocalFrame&,
                                const String& str,
                                TextDirection) override {
    last_tooltip_text_ = str;
    // Always reset the bounds to zero as this function doesn't set bounds.
    last_tooltip_bounds_ = gfx::Rect();
    triggered_from_cursor_ = true;
  }

  void UpdateTooltipFromKeyboard(LocalFrame&,
                                 const String& str,
                                 TextDirection,
                                 const gfx::Rect& bounds) override {
    last_tooltip_text_ = str;
    last_tooltip_bounds_ = bounds;
    triggered_from_cursor_ = false;
  }

  void ClearKeyboardTriggeredTooltip(LocalFrame&) override {
    if (triggered_from_cursor_)
      return;

    last_tooltip_text_ = String();
    last_tooltip_bounds_ = gfx::Rect();
  }

  void ResetTooltip() {
    last_tooltip_text_ = "";
    last_tooltip_bounds_ = gfx::Rect();
  }

  const String& LastToolTipText() { return last_tooltip_text_; }
  const gfx::Rect& LastToolTipBounds() { return last_tooltip_bounds_; }

 private:
  String last_tooltip_text_;
  gfx::Rect last_tooltip_bounds_;
  bool triggered_from_cursor_ = false;
};

class EventHandlerTooltipTest : public EventHandlerTest {
 public:
  EventHandlerTooltipTest() = default;

  void SetUp() override {
    chrome_client_ = MakeGarbageCollected<TooltipCapturingChromeClient>();
    SetupPageWithClients(chrome_client_);
  }

  const String& LastToolTipText() { return chrome_client_->LastToolTipText(); }
  const gfx::Rect& LastToolTipBounds() {
    return chrome_client_->LastToolTipBounds();
  }
  void ResetTooltip() { chrome_client_->ResetTooltip(); }

 private:
  Persistent<TooltipCapturingChromeClient> chrome_client_;
};

TEST_F(EventHandlerTooltipTest, mouseLeaveClearsTooltip) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetHtmlInnerHTML(
      "<style>.box { width: 100%; height: 100%; }</style>"
      "<img src='image.png' class='box' title='tooltip'>link</img>");

  EXPECT_EQ(WTF::String(), LastToolTipText());

  WebMouseEvent mouse_move_event(
      WebInputEvent::Type::kMouseMove, gfx::PointF(51, 50), gfx::PointF(51, 50),
      WebPointerProperties::Button::kNoButton, 0, WebInputEvent::kNoModifiers,
      base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  EXPECT_EQ("tooltip", LastToolTipText());

  WebMouseEvent mouse_leave_event(
      WebInputEvent::Type::kMouseLeave, gfx::PointF(0, 0), gfx::PointF(0, 0),
      WebPointerProperties::Button::kNoButton, 0, WebInputEvent::kNoModifiers,
      base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMouseLeaveEvent(
      mouse_leave_event);

  EXPECT_EQ(WTF::String(), LastToolTipText());
}

// macOS doesn't have keyboard-triggered tooltips.
#if BUILDFLAG(IS_MAC)
#define MAYBE_FocusSetFromTabUpdatesTooltip \
  DISABLED_FocusSetFromTabUpdatesTooltip
#else
#define MAYBE_FocusSetFromTabUpdatesTooltip FocusSetFromTabUpdatesTooltip
#endif
// Moving the focus with the tab key should trigger a tooltip update.
TEST_F(EventHandlerTooltipTest, MAYBE_FocusSetFromTabUpdatesTooltip) {
  SetHtmlInnerHTML(
      R"HTML(
        <button id='b1' title='my tooltip 1'>button 1</button>
        <button id='b2'>button 2</button>
      )HTML");

  EXPECT_EQ(WTF::String(), LastToolTipText());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());

  WebKeyboardEvent e{WebInputEvent::Type::kRawKeyDown,
                     WebInputEvent::kNoModifiers,
                     WebInputEvent::GetStaticTimeStampForTests()};
  e.dom_code = static_cast<int>(ui::DomCode::TAB);
  e.dom_key = ui::DomKey::TAB;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);

  Element* element = GetDocument().getElementById(AtomicString("b1"));
  EXPECT_EQ("my tooltip 1", LastToolTipText());
  EXPECT_EQ(element->BoundsInWidget(), LastToolTipBounds());

  // Doing the same but for a button that doesn't have a tooltip text should
  // still trigger a tooltip update. The browser-side TooltipController will
  // handle this case.
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);
  element = GetDocument().getElementById(AtomicString("b2"));
  EXPECT_TRUE(LastToolTipText().IsNull());
  EXPECT_EQ(element->BoundsInWidget(), LastToolTipBounds());
}

// macOS doesn't have keyboard-triggered tooltips.
#if BUILDFLAG(IS_MAC)
#define MAYBE_FocusSetFromAccessKeyUpdatesTooltip \
  DISABLED_FocusSetFromAccessKeyUpdatesTooltip
#else
#define MAYBE_FocusSetFromAccessKeyUpdatesTooltip \
  FocusSetFromAccessKeyUpdatesTooltip
#endif
// Moving the focus by pressing the access key on button should trigger a
// tooltip update.
TEST_F(EventHandlerTooltipTest, MAYBE_FocusSetFromAccessKeyUpdatesTooltip) {
  SetHtmlInnerHTML(
      R"HTML(
        <button id='b' title='my tooltip' accessKey='a'>button</button>
      )HTML");

  EXPECT_EQ(WTF::String(), LastToolTipText());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());

  WebKeyboardEvent e{WebInputEvent::Type::kRawKeyDown, WebInputEvent::kAltKey,
                     WebInputEvent::GetStaticTimeStampForTests()};
  e.unmodified_text[0] = 'a';
  GetDocument().GetFrame()->GetEventHandler().HandleAccessKey(e);

  Element* element = GetDocument().getElementById(AtomicString("b"));
  EXPECT_EQ("my tooltip", LastToolTipText());
  EXPECT_EQ(element->BoundsInWidget(), LastToolTipBounds());
}

// macOS doesn't have keyboard-triggered tooltips.
#if BUILDFLAG(IS_MAC)
#define MAYBE_FocusSetFromMouseDoesntUpdateTooltip \
  DISABLED_FocusSetFromMouseDoesntUpdateTooltip
#else
#define MAYBE_FocusSetFromMouseDoesntUpdateTooltip \
  FocusSetFromMouseDoesntUpdateTooltip
#endif
// Moving the focus to an element with a mouse action shouldn't update the
// tooltip.
TEST_F(EventHandlerTooltipTest, MAYBE_FocusSetFromMouseDoesntUpdateTooltip) {
  SetHtmlInnerHTML(
      R"HTML(
        <button id='b' title='my tooltip'>button</button>
      )HTML");

  EXPECT_EQ(WTF::String(), LastToolTipText());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());

  Element* element = GetDocument().getElementById(AtomicString("b"));
  gfx::PointF mouse_press_point =
      gfx::PointF(element->BoundsInWidget().CenterPoint());
  WebMouseEvent mouse_press_event(
      WebInputEvent::Type::kMouseDown, mouse_press_point, mouse_press_point,
      WebPointerProperties::Button::kLeft, 1,
      WebInputEvent::Modifiers::kLeftButtonDown, base::TimeTicks::Now());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_press_event);

  EXPECT_TRUE(LastToolTipText().IsNull());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());
}

// macOS doesn't have keyboard-triggered tooltips.
#if BUILDFLAG(IS_MAC)
#define MAYBE_FocusSetFromScriptDoesntUpdateTooltip \
  DISABLED_FocusSetFromScriptDoesntUpdateTooltip
#else
#define MAYBE_FocusSetFromScriptDoesntUpdateTooltip \
  FocusSetFromScriptDoesntUpdateTooltip
#endif
// Moving the focus to an element with a script action (FocusType::kNone means
// that the focus was set from a script) shouldn't update the tooltip.
TEST_F(EventHandlerTooltipTest, MAYBE_FocusSetFromScriptDoesntUpdateTooltip) {
  SetHtmlInnerHTML(
      R"HTML(
        <button id='b' title='my tooltip'>button</button>
      )HTML");

  EXPECT_EQ(WTF::String(), LastToolTipText());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());

  Element* element = GetDocument().getElementById(AtomicString("b"));
  element->Focus();

  EXPECT_TRUE(LastToolTipText().IsNull());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());
}

// macOS doesn't have keyboard-triggered tooltips.
#if BUILDFLAG(IS_MAC)
#define MAYBE_FocusSetScriptInitiatedFromKeypressUpdatesTooltip \
  DISABLED_FocusSetScriptInitiatedFromKeypressUpdatesTooltip
#else
#define MAYBE_FocusSetScriptInitiatedFromKeypressUpdatesTooltip \
  FocusSetScriptInitiatedFromKeypressUpdatesTooltip
#endif
// Moving the focus with a keypress that leads to a script being called
// should trigger a tooltip update.
TEST_F(EventHandlerTooltipTest,
       MAYBE_FocusSetScriptInitiatedFromKeypressUpdatesTooltip) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetHtmlInnerHTML(
      R"HTML(
        <button id='b1' title='my tooltip 1'>button 1</button>
        <button id='b2'>button 2</button>
      )HTML");
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(
      R"HTML(
        document.addEventListener('keydown', (e) => {
          if (e.keyCode == 37) {
            document.getElementById('b1').focus();
          } else if (e.keyCode == 39) {
            document.getElementById('b2').focus();
          }
        });
      )HTML");
  GetDocument().body()->AppendChild(script);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_EQ(WTF::String(), LastToolTipText());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());

  WebKeyboardEvent e{WebInputEvent::Type::kRawKeyDown,
                     WebInputEvent::kNoModifiers,
                     WebInputEvent::GetStaticTimeStampForTests()};
  e.dom_code = static_cast<int>(ui::DomCode::ARROW_LEFT);
  e.dom_key = ui::DomKey::ARROW_LEFT;
  e.native_key_code = e.windows_key_code = blink::VKEY_LEFT;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);

  Element* element = GetDocument().getElementById(AtomicString("b1"));
  EXPECT_EQ("my tooltip 1", LastToolTipText());
  EXPECT_EQ(element->BoundsInWidget(), LastToolTipBounds());

  // Doing the same but for a button that doesn't have a tooltip text should
  // still trigger a tooltip update. The browser-side TooltipController will
  // handle this case.
  WebKeyboardEvent e2{WebInputEvent::Type::kRawKeyDown,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests()};
  e2.dom_code = static_cast<int>(ui::DomCode::ARROW_RIGHT);
  e2.dom_key = ui::DomKey::ARROW_RIGHT;
  e2.native_key_code = e2.windows_key_code = blink::VKEY_RIGHT;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e2);

  element = GetDocument().getElementById(AtomicString("b2"));
  EXPECT_TRUE(LastToolTipText().IsNull());

  // But when the Element::Focus() is called outside of a keypress context,
  // no tooltip is shown.
  element = GetDocument().getElementById(AtomicString("b1"));
  element->Focus(FocusOptions::Create());
  EXPECT_TRUE(LastToolTipText().IsNull());
}

// macOS doesn't have keyboard-triggered tooltips.
#if BUILDFLAG(IS_MAC)
#define MAYBE_FocusSetFromScriptClearsKeyboardTriggeredTooltip \
  DISABLED_FocusSetFromScriptClearsKeyboardTriggeredTooltip
#else
#define MAYBE_FocusSetFromScriptClearsKeyboardTriggeredTooltip \
  FocusSetFromScriptClearsKeyboardTriggeredTooltip
#endif
// Moving the focus programmatically to an element that doesn't have a title
// attribute set while the user previously set the focus from keyboard on an
// element with a title text should hide the tooltip.
TEST_F(EventHandlerTooltipTest,
       MAYBE_FocusSetFromScriptClearsKeyboardTriggeredTooltip) {
  SetHtmlInnerHTML(
      R"HTML(
        <button id='b1' title='my tooltip 1'>button 1</button>
        <button id='b2'>button 2</button>
      )HTML");

  // First, show a keyboard-triggered tooltip using the 'tab' key.
  WebKeyboardEvent e{WebInputEvent::Type::kRawKeyDown,
                     WebInputEvent::kNoModifiers,
                     WebInputEvent::GetStaticTimeStampForTests()};
  e.dom_code = static_cast<int>(ui::DomCode::TAB);
  e.dom_key = ui::DomKey::TAB;
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);

  Element* element = GetDocument().getElementById(AtomicString("b1"));
  EXPECT_EQ("my tooltip 1", LastToolTipText());
  EXPECT_EQ(element->BoundsInWidget(), LastToolTipBounds());

  // Validate that blurring an element that is not focused will not just hide
  // the tooltip. It wouldn't make sense.
  element = GetDocument().getElementById(AtomicString("b2"));
  element->blur();

  EXPECT_EQ("my tooltip 1", LastToolTipText());
  EXPECT_EQ(GetDocument().getElementById(AtomicString("b1"))->BoundsInWidget(),
            LastToolTipBounds());

  // Then, programmatically move the focus to another button that has no title
  // text. This should hide the tooltip.
  element->Focus();

  EXPECT_TRUE(LastToolTipText().IsNull());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());

  // Move the focus on the first button again and validate that it trigger a
  // tooltip again.
  GetDocument().GetFrame()->GetEventHandler().KeyEvent(e);

  element = GetDocument().getElementById(AtomicString("b1"));
  EXPECT_EQ("my tooltip 1", LastToolTipText());
  EXPECT_EQ(element->BoundsInWidget(), LastToolTipBounds());

  // Then, programmatically blur the button to validate that the tooltip gets
  // hidden.
  element->blur();

  EXPECT_TRUE(LastToolTipText().IsNull());
  EXPECT_EQ(gfx::Rect(), LastToolTipBounds());
}

// Moving the focus programmatically while a cursor-triggered tooltip is visible
// shouldn't hide the visible tooltip.
TEST_F(EventHandlerTooltipTest,
       FocusSetFromScriptDoesntClearCursorTriggeredTooltip) {
  SetHtmlInnerHTML(
      R"HTML(
        <style>.box { width: 100px; height: 100px; }</style>
        <img src='image.png' class='box' title='tooltip'>link</img>

        <button id='b2'>button 2</button>
      )HTML");
  // First, show a cursor-triggered tooltip.
  WebMouseEvent mouse_move_event(
      WebInputEvent::Type::kMouseMove, gfx::PointF(51, 50), gfx::PointF(51, 50),
      WebPointerProperties::Button::kNoButton, 0, WebInp
```