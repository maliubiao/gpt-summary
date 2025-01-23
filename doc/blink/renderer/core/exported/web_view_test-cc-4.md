Response:
The user wants a summary of the provided C++ code snippet, which is part of a larger test file (`web_view_test.cc`) for the Chromium Blink rendering engine. The focus is on the functionality of the code, its relationship to web technologies (JavaScript, HTML, CSS), and common usage scenarios, including potential errors and debugging.

Here's a breakdown of how to approach this:

1. **Identify the core functionality:**  The code consists of several test functions (`TEST_F`) within a `WebViewTest` fixture. These tests primarily deal with simulating user interactions (long presses, double taps, mouse clicks) on different HTML elements and verifying the resulting behavior of the `WebViewImpl`.

2. **Analyze individual test cases:** Go through each `TEST_F` block and determine what it's testing. Look for:
    * HTML files being loaded (`RegisterMockedHttpURLLoad`).
    * Simulated input events (`WebGestureEvent`, `WebPointerEvent`, `WebMouseEvent`).
    * Assertions (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_NE`) about the state of the `WebViewImpl` (e.g., whether a context menu is shown, selection is made, drag events are triggered).
    * Manipulation of `WebViewImpl` settings.

3. **Relate to web technologies:**  Connect the test scenarios to how users interact with web pages. For example:
    * Long presses are a common touch interaction for triggering context menus.
    * Double taps are used for word selection.
    * Drag and drop is a feature that can be tested.
    * Context menus are a standard UI element in web browsers.

4. **Identify potential JavaScript/HTML/CSS involvement:** Look for tests that might indirectly involve these technologies. For example, testing whether an object can start selection might depend on CSS properties or JavaScript event handlers. Similarly, the behavior of dragging elements is often influenced by JavaScript event listeners.

5. **Infer logical reasoning and assumptions:** For each test, determine the input (the simulated user action and the state of the web page) and the expected output (the asserted state of the `WebViewImpl`).

6. **Consider user/programming errors:** Think about what mistakes a developer or user might make that these tests are designed to catch. For example, a developer might incorrectly implement drag and drop, or a user might expect a context menu to appear in certain situations where it shouldn't.

7. **Trace user actions:** Describe how a user interacting with a web page would end up triggering the code being tested. This involves understanding the sequence of events that lead to the specific Blink functionality being exercised.

8. **Synthesize the information for the summary:**  Group related tests and describe the overall purpose of this section of the test file.

**Self-Correction during the thought process:**

* **Initial thought:** Focus only on the C++ API calls.
* **Correction:** Realize the tests are about web behavior, so need to connect the C++ to the underlying web concepts.
* **Initial thought:** Describe each test case in isolation.
* **Correction:** Group related tests (e.g., all the long press tests) to provide a more coherent summary.
* **Initial thought:** Only mention explicit JavaScript interactions.
* **Correction:**  Understand that even without explicit JavaScript calls in the test, the *behavior* being tested is often influenced by JavaScript or HTML attributes.

By following this process, the aim is to generate a comprehensive and insightful summary that addresses all aspects of the user's request.
This code snippet from `web_view_test.cc` focuses on testing the **long press gesture** and **double tap gesture** behavior within a `WebView`, particularly in relation to:

* **Context Menus:**  Verifying when and how context menus are triggered by long presses on various elements (objects, images, videos, links).
* **Text Selection:** Testing the initiation and behavior of text selection on different types of content (editable areas, non-editable areas, elements with `onselectstart` event handlers) when long pressed or double tapped.
* **Drag and Drop:**  Examining how long presses initiate drag and drop operations and the associated events (like `touchcancel` and the display of context menus at the end of a drag).
* **Input Method (IME) Integration:**  Checking how finishing a composition affects selection handles after a long press.
* **Caret Blinking:** Ensuring the caret blinks correctly after a long press and when closing context menus.
* **Handling of Read-Only Inputs:** Testing selection behavior in read-only input fields.
* **Keyboard Event Handling:**  Verifying how specific key presses (like Page Down, Arrow Down, Ctrl+Home) are handled for scrolling.

Here's a breakdown with examples related to JavaScript, HTML, and CSS:

**Functionality:**

1. **Long Press Context Menu Tests:**
   - **`LongPressObjectNoFallback`:** Tests that a long press on an object (likely an `<object>` tag) does **not** allow selection by default.
     - **HTML Example:** `<object id="obj" data="some-data"></object>`
     - **Logic:** It simulates a long press gesture at a specific point and checks if the element (`obj`) can start selection. The expectation is `false`.
     - **Input:** A long press gesture at coordinates (10, 10).
     - **Output:** `element->CanStartSelection()` returns `false`.
   - **`LongPressObjectFallback`:** Tests that if `AlwaysShowContextMenuOnTouch` is enabled, a long press on an object **does** allow selection. This implies a fallback mechanism where the context menu interaction takes precedence.
     - **HTML Example:** Same as above.
     - **Logic:** Similar to the previous test, but with the setting enabled. The expectation is `true`.
     - **Input:** A long press gesture at coordinates (10, 10).
     - **Output:** `element->CanStartSelection()` returns `true`.
   - **`LongPressImage`:** Tests that a long press on an image triggers the display of a context menu.
     - **HTML Example:** `<img src="image.jpg">`
     - **Logic:** Simulates a long press and checks if a context menu node exists for the main frame.
     - **Input:** A long press gesture at coordinates (10, 10).
     - **Output:** `web_view->GetPage()->GetContextMenuController().ContextMenuNodeForFrame(...)` returns a valid pointer (meaning a context menu is present).
   - **`LongPressVideo` and `LongPressLink`:**  These likely test similar context menu behavior for `<video>` and `<a>` tags, respectively.
     - **HTML Examples:** `<video src="video.mp4"></video>`, `<a href="link.html">Link</a>`
     - **Logic:** Similar to `LongPressImage`, they verify context menu appearance.
     - **Input:** Long press gestures at specific coordinates.
     - **Output:** Context menu logic is triggered (though the exact presence of a context menu node might not be explicitly asserted in the `LongPressVideo` test in this snippet).

2. **Long Press Drag and Drop Tests:**
   - **`TouchCancelOnStartDragging`:** Tests that when a long press initiates a drag operation, a `touchcancel` event is sent to the DOM. This is important for cleaning up any ongoing touch interactions.
     - **HTML Example:**  A draggable `<div>`: `<div id="target" draggable="true">Draggable</div>`
     - **JavaScript Example:**  JavaScript might listen for `dragstart` and `touchcancel` events to track the drag state.
     - **Logic:** It simulates a long press on a draggable element, checks for a `dragstart` event, and then verifies that a `touchcancel` event is also dispatched.
     - **Input:** Pointer down, followed by a long press gesture on the "target" element.
     - **Output:** The document title changes to "dragstart" and then "touchcancel" as these events are fired and handled by JavaScript in the loaded HTML.
   - **`TouchDragContextMenuWithoutDrag`:** Tests that if `TouchDragEndContextMenu` is enabled, a long press followed by a stationary drag (no movement) will show a context menu at the end of the "drag."
     - **HTML Example:** Same as above.
     - **Logic:** Simulates a long press to start a drag, then calls `DragSourceEndedAt` with the same start and end points, verifying the appearance of the context menu.
     - **Input:** Pointer down, long press, and a `DragSourceEndedAt` call with no movement.
     - **Output:** A context menu is present.
   - **`TouchDragContextMenuAtDragEnd`:**  Tests that if `TouchDragEndContextMenu` is enabled, a long press followed by an actual drag (movement) will **not** show a context menu at the end of the drag (likely because the drag action takes precedence).
     - **HTML Example:** Same as above.
     - **Logic:** Similar to the previous test, but `DragSourceEndedAt` is called with different start and end points, indicating a drag.
     - **Input:** Pointer down, long press, and a `DragSourceEndedAt` call with movement.
     - **Output:** A context menu is **not** present.
   - **`ContextMenuOnLinkAndImageLongPress`:** Tests that long pressing on links and images triggers the `contextmenu` event (which can be observed in JavaScript).
     - **HTML Example:** `<a id="anchorTag" href="#">Link</a> <img id="imageTag" src="image.png">`
     - **JavaScript Example:**  The test likely relies on JavaScript in the loaded HTML to set the document title when a `contextmenu` event occurs on the targeted elements.
     - **Logic:** Simulates long presses on the anchor and image tags and checks the document title to confirm the `contextmenu` event was fired for each.
     - **Input:** Long press gestures on the "anchorTag" and "imageTag" elements.
     - **Output:** The document title reflects the sequence of `contextmenu` events: "contextmenu@a," then "contextmenu@a,contextmenu@img,".
   - **`ContextMenuAndDragOnImageLongPress` and `ContextMenuAndDragOnLinkLongPress`:** These tests explore scenarios where a short press might initiate a drag, and a subsequent long press on the same element might trigger a context menu in addition to the ongoing drag. This checks the interplay between different touch gestures.
     - **HTML Example:** Same as above.
     - **Logic:** Simulate a short press (likely triggering `dragstart`) followed by a long press (potentially triggering `contextmenu`).
     - **Input:** Short press then long press on the same element.
     - **Output:** The document title reflects the sequence of events: "dragstart@img,contextmenu@img,".

3. **Long Press and Double Tap Selection Tests:**
   - **`LongPressEmptyEditableSelection`:** Tests that a long press in an empty editable area does something (likely focuses the area or prepares for input). The exact expectation isn't explicitly asserted in this snippet.
     - **HTML Example:** `<div contenteditable="true"></div>`
     - **Logic:** Simulates a long press in an empty editable div.
     - **Input:** A long press gesture at coordinates (10, 10).
     - **Output:**  The test expects the event to be handled by the system (`WebInputEventResult::kHandledSystem`), implying some action is taken.
   - **`LongPressEmptyNonEditableSelection`:** Tests that a long press on an image (a non-editable element) when there is no existing selection does **not** create a selection.
     - **HTML Example:** `<img src="image.jpg">`
     - **Logic:** Simulates a long press on the image and checks if any text is selected.
     - **Input:** A long press gesture at coordinates (300, 300).
     - **Output:** `frame->SelectionAsText().IsEmpty()` returns `true`.
   - **`LongPressSelection`:** Tests that a long press on selectable text selects that text. It also tests that if an element has an `onselectstart="false"` attribute, a long press on it will not result in a selection.
     - **HTML Example:** `<div id="target">testword</div> <div id="onselectstartfalse" onselectstart="false">prevent selection</div>`
     - **Logic:** Simulates long presses on both elements and checks the selected text.
     - **Input:** Long press gestures on "onselectstartfalse" and "target" elements.
     - **Output:** Selection is empty for "onselectstartfalse", and "testword" is selected for "target".
   - **`DoublePressSelection`:** Tests that a double tap on text selects the nearest word.
     - **HTML Example:** `<div id="target">this is a selection</div>`
     - **Logic:** Simulates a sequence of tap down and tap events mimicking a double tap and verifies the selected text.
     - **Input:** A double tap gesture on the "target" element.
     - **Output:** The text "selection" is selected.
   - **`DoublePressSelectionOnSelectStartFalse`:** Tests that a double tap on an element with `onselectstart="false"` does not select any text.
     - **HTML Example:**  `<div id="onselectstartfalse" onselectstart="false">prevent selection</div>`
     - **Logic:** Simulates a double tap and checks for selected text.
     - **Input:** A double tap gesture on the "onselectstartfalse" element.
     - **Output:** No text is selected.
   - **`DoublePressSelectionPreventDefaultMouseDown`:** Tests that if the `mousedown` event is prevented (using `preventDefault()` in JavaScript), a double tap will not result in text selection.
     - **HTML Example:** `<div id="targetdiv">this is a selection</div>`
     - **JavaScript Example:** The test adds an event listener to prevent the default `mousedown` behavior.
     - **Logic:** Simulates a double tap after setting up the event listener and checks for selected text.
     - **Input:** A double tap gesture on the "target" element.
     - **Output:** No text is selected.

4. **IME and Selection Handle Test:**
   - **`FinishComposingTextDoesNotDismissHandles`:** Tests that after a long press selects text, finishing an Input Method Engine (IME) composition (like typing Chinese characters) while keeping the selection does not dismiss the selection handles.
     - **HTML Example:**  A simple text element like `<div id="target">initial text</div>`
     - **Logic:**  It simulates a long press to select text, then simulates IME composition, and finally checks if the selection handles are still visible after finishing the composition.
     - **Input:** Long press on "target", followed by IME composition and finishing.
     - **Output:** Selection handles remain visible.

5. **Textarea Selection Tests (Platform-Specific):**
   - **`TouchDoesntSelectEmptyTextarea` (Not on Mac):**  Tests that long pressing or double tapping within an empty `<textarea>` does not result in any selection. It also tests this behavior after adding text and then interacting near the end of the text.
     - **HTML Example:** `<textarea id="blanklinestextbox"></textarea>`
     - **Logic:** Simulates long presses and double taps at various points in an empty and non-empty textarea.
     - **Input:** Long press and double tap gestures on the textarea.
     - **Output:** No text is selected.

6. **ContentEditable Image Selection Test:**
   - **`LongPressImageTextarea`:** Tests that a long press on an image within a `contenteditable` element selects the image.
     - **HTML Example:** `<div contenteditable="true"><img id="purpleimage" src="purple.png"></div>`
     - **Logic:** Simulates a long press on the image and checks the selection range.
     - **Input:** Long press gesture on the "purpleimage" element.
     - **Output:** A selection range is created, starting at offset 0 with a length of 1 (representing the single image node).

7. **Caret Blinking Tests:**
   - **`BlinkCaretAfterLongPress`:**  Tests that the text input caret resumes blinking after a long press.
     - **HTML Example:**  An editable element like `<div id="target" contenteditable="true"></div>`
     - **Logic:** Simulates a long press in the editable area and checks if caret blinking is no longer suspended.
     - **Input:** Long press gesture on the "target" element.
     - **Output:** Caret blinking is not suspended.
   - **`BlinkCaretOnClosingContextMenu`:** Tests that the caret blinking is suspended when a context menu is shown (e.g., via a right-click) and resumes when the context menu is closed.
     - **HTML Example:** A simple form with focusable elements.
     - **Logic:** Simulates a right-click to show the context menu and then closes it, checking the caret blinking state at each step.
     - **Input:** Mouse right-click to show context menu, then closing the context menu.
     - **Output:** Caret blinking is suspended while the context menu is open and resumes after closing.

8. **Read-Only Input Selection Test:**
   - **`SelectionOnReadOnlyInput`:** Tests that text within a read-only input field can be selected programmatically.
     - **HTML Example:** `<input type="text" readonly value="This text should be selected.">`
     - **Logic:**  The test likely sets the selection programmatically and verifies the selected text.
     - **Input:**  The initial state of the read-only input.
     - **Output:** The text "This text should be selected." is selected.

9. **Keyboard Event Handling Tests:**
   - **`KeyDownScrollsHandled`:**  Tests that certain key presses (like Page Down, Arrow Down) are handled by the WebView for scrolling the page, while others (like Ctrl+Down, Shift, Meta, Alt alone) are not. It also tests platform-specific behavior for Alt+Down on Windows vs. Mac.
     - **HTML Example:** A page with content wider than the viewport to enable scrolling.
     - **Logic:** Simulates various key down and key up events and checks the return value of `HandleInputEvent` to see if the event was handled by the system.
     - **Input:**  Various key press events with different modifiers.
     - **Output:** `WebInputEventResult::kHandledSystem` for keys that should trigger scrolling, and `WebInputEventResult::kNotHandled` for others.

**Relationship to JavaScript, HTML, and CSS:**

* **HTML:** The tests heavily rely on specific HTML structures and attributes (like `id`, `draggable`, `contenteditable`, `onselectstart`, `readonly`) to set up the scenarios being tested. The behavior of long presses and double taps is often dependent on the type of HTML element being interacted with.
* **JavaScript:** While not always explicitly shown in the test code, JavaScript plays a crucial role in the underlying behavior being tested. For example:
    * The `dragstart` and `touchcancel` events tested in `TouchCancelOnStartDragging` are JavaScript events.
    * The `contextmenu` event handling in `ContextMenuOnLinkAndImageLongPress` likely involves JavaScript code in the loaded HTML.
    * The `preventDefault()` call in `DoublePressSelectionPreventDefaultMouseDown` is a JavaScript mechanism.
* **CSS:**  CSS can influence whether an element is selectable or draggable. While not directly tested in this snippet, the tests implicitly rely on the default CSS behaviors of various HTML elements.

**Assumptions, Inputs, and Outputs (Examples):**

* **Assumption:** The testing environment correctly simulates touch gestures like long press and double tap.
* **Input (for `LongPressImage`):**  The HTML file `long_press_image.html` contains an `<img>` tag. A `WebGestureEvent` of type `kGestureLongPress` is dispatched at coordinates (10, 10).
* **Output (for `LongPressImage`):** The `ContextMenuController` for the main frame has a non-null `ContextMenuNodeForFrame`, indicating a context menu is ready to be displayed.

**User and Programming Errors:**

* **User Error:** A user might expect a context menu to appear on a long press for an element where it's not intended (e.g., a plain `<div>`). These tests help ensure consistent and expected behavior.
* **Programming Error:** A developer might incorrectly handle drag and drop events, leading to issues like the `touchcancel` event not being dispatched correctly. They might also incorrectly prevent or allow selection on certain elements. These tests act as regression checks to catch such errors.

**User Operations Leading to These Tests:**

To reach the code being tested, a user would perform the following actions in a browser using the Blink engine:

1. **Load a webpage:** The user navigates to a website containing various HTML elements like images, links, editable areas, etc.
2. **Perform touch gestures:**
   - **Long Press:** The user touches and holds their finger on an element for a short duration. This can trigger context menus, initiate drag and drop, or start text selection.
   - **Double Tap:** The user quickly taps an element twice. This is often used for zooming or selecting words.
3. **Interact with the context menu:** If a context menu appears, the user might tap on different options.
4. **Drag elements:** The user might long press and then drag a draggable element across the screen.

These tests simulate these user actions programmatically to ensure the underlying Blink engine handles them correctly.

**Summary of Functionality (Part 5 of 9):**

This section of `web_view_test.cc` primarily focuses on verifying the correct handling of **long press** and **double tap** gestures within a `WebView`. It thoroughly tests how these gestures interact with different HTML elements, focusing on triggering context menus, initiating drag and drop operations, and controlling text selection. The tests also cover related aspects like IME integration and caret blinking behavior in response to these gestures. The aim is to ensure a consistent and predictable user experience when interacting with web content using touch input.

### 提示词
```
这是目录为blink/renderer/core/exported/web_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
ent>(static_cast<Node*>(
      web_view->MainFrameImpl()->GetDocument().GetElementById("obj")));
  EXPECT_FALSE(element->CanStartSelection());
}

TEST_F(WebViewTest, LongPressObjectFallback) {
  RegisterMockedHttpURLLoad("long_press_object_fallback.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_object_fallback.html");
  web_view->SettingsImpl()->SetAlwaysShowContextMenuOnTouch(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(10, 10));

  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));

  auto* element = To<HTMLElement>(static_cast<Node*>(
      web_view->MainFrameImpl()->GetDocument().GetElementById("obj")));
  EXPECT_TRUE(element->CanStartSelection());
}

TEST_F(WebViewTest, LongPressImage) {
  RegisterMockedHttpURLLoad("long_press_image.html");

  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "long_press_image.html");
  web_view->SettingsImpl()->SetAlwaysShowContextMenuOnTouch(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(10, 10));

  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
  EXPECT_TRUE(
      web_view->GetPage()->GetContextMenuController().ContextMenuNodeForFrame(
          web_view->MainFrameImpl()->GetFrame()));
}

TEST_F(WebViewTest, LongPressVideo) {
  RegisterMockedHttpURLLoad("long_press_video.html");

  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "long_press_video.html");
  web_view->SettingsImpl()->SetAlwaysShowContextMenuOnTouch(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(10, 10));

  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
}

TEST_F(WebViewTest, LongPressLink) {
  RegisterMockedHttpURLLoad("long_press_link.html");

  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "long_press_link.html");
  web_view->SettingsImpl()->SetAlwaysShowContextMenuOnTouch(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(500, 300));

  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
}

// Tests that we send touchcancel when drag start by long press.
TEST_F(WebViewTest, TouchCancelOnStartDragging) {
  RegisterMockedHttpURLLoad("long_press_draggable_div.html");

  url_test_helpers::RegisterMockedURLLoad(
      ToKURL("http://www.test.com/foo.png"),
      test::CoreTestDataPath("white-1x1.png"));
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_draggable_div.html");

  web_view->SettingsImpl()->SetTouchDragDropEnabled(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebPointerEvent pointer_down(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch), 5, 5);
  pointer_down.SetPositionInWidget(250, 8);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(pointer_down, ui::LatencyInfo()));
  web_view->MainFrameWidget()->DispatchBufferedTouchEvents();

  WebString target_id = WebString::FromUTF8("target");

  // Send long press to start dragging
  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, target_id));
  EXPECT_EQ("dragstart", web_view->MainFrameImpl()->GetDocument().Title());

  // Check pointer cancel is sent to dom.
  WebPointerEvent pointer_cancel(
      WebInputEvent::Type::kPointerCancel,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch), 5, 5);
  pointer_cancel.SetPositionInWidget(250, 8);
  EXPECT_NE(WebInputEventResult::kHandledSuppressed,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(pointer_cancel, ui::LatencyInfo())));
  web_view->MainFrameWidget()->DispatchBufferedTouchEvents();
  EXPECT_EQ("touchcancel", web_view->MainFrameImpl()->GetDocument().Title());
}

// Tests that a touch drag context menu is enabled, a dragend shows a context
// menu when there is no drag.
TEST_F(WebViewTest, TouchDragContextMenuWithoutDrag) {
  RegisterMockedHttpURLLoad("long_press_draggable_div.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_draggable_div.html");

  web_view->SettingsImpl()->SetTouchDragDropEnabled(true);
  web_view->SettingsImpl()->SetTouchDragEndContextMenu(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebPointerEvent pointer_down(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch), 5, 5);
  pointer_down.SetPositionInWidget(250, 8);
  pointer_down.SetPositionInScreen(250, 8);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(pointer_down, ui::LatencyInfo()));
  web_view->MainFrameWidget()->DispatchBufferedTouchEvents();

  WebString target_id = WebString::FromUTF8("target");

  // Simulate long press to start dragging.
  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, target_id));
  EXPECT_EQ("dragstart", web_view->MainFrameImpl()->GetDocument().Title());

  // Simulate the end of a non-moving drag.
  const gfx::PointF dragend_point(250, 8);
  web_view->MainFrameViewWidget()->DragSourceEndedAt(
      dragend_point, dragend_point, ui::mojom::blink::DragOperation::kNone,
      base::DoNothing());
  EXPECT_TRUE(
      web_view->GetPage()->GetContextMenuController().ContextMenuNodeForFrame(
          web_view->MainFrameImpl()->GetFrame()));
}

// Tests that a dragend does not show a context menu after a drag when
// touch-drag-context-menu is enabled.
TEST_F(WebViewTest, TouchDragContextMenuAtDragEnd) {
  ScopedTouchDragAndContextMenuForTest touch_drag_and_context_menu(false);
  RegisterMockedHttpURLLoad("long_press_draggable_div.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_draggable_div.html");

  web_view->SettingsImpl()->SetTouchDragDropEnabled(true);
  web_view->SettingsImpl()->SetTouchDragEndContextMenu(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebPointerEvent pointer_down(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch), 5, 5);
  pointer_down.SetPositionInWidget(250, 8);
  pointer_down.SetPositionInScreen(250, 8);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(pointer_down, ui::LatencyInfo()));
  web_view->MainFrameWidget()->DispatchBufferedTouchEvents();

  WebString target_id = WebString::FromUTF8("target");

  // Simulate long press to start dragging.
  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, target_id));
  EXPECT_EQ("dragstart", web_view->MainFrameImpl()->GetDocument().Title());

  // Simulate the end of a drag.
  const gfx::PointF dragend_point(270, 28);
  web_view->MainFrameViewWidget()->DragSourceEndedAt(
      dragend_point, dragend_point, ui::mojom::blink::DragOperation::kNone,
      base::DoNothing());

  // TODO(https://crbug.com/1290905): When TouchDragAndContextMenu is enabled,
  // this becomes true.  This shouldn't be the case.
  EXPECT_FALSE(
      web_view->GetPage()->GetContextMenuController().ContextMenuNodeForFrame(
          web_view->MainFrameImpl()->GetFrame()));
}

TEST_F(WebViewTest, ContextMenuOnLinkAndImageLongPress) {
  ScopedTouchDragAndContextMenuForTest touch_drag_and_context_menu(false);
  RegisterMockedHttpURLLoad("long_press_links_and_images.html");

  url_test_helpers::RegisterMockedURLLoad(
      ToKURL("http://www.test.com/foo.png"),
      test::CoreTestDataPath("white-1x1.png"));
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_links_and_images.html");

  web_view->SettingsImpl()->SetTouchDragDropEnabled(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString anchor_tag_id = WebString::FromUTF8("anchorTag");
  WebString image_tag_id = WebString::FromUTF8("imageTag");

  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, anchor_tag_id));
  EXPECT_EQ("contextmenu@a,", web_view->MainFrameImpl()->GetDocument().Title());

  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, image_tag_id));
  EXPECT_EQ("contextmenu@a,contextmenu@img,",
            web_view->MainFrameImpl()->GetDocument().Title());
}

TEST_F(WebViewTest, ContextMenuAndDragOnImageLongPress) {
  ScopedTouchDragOnShortPressForTest touch_drag_on_short_press(true);
  RegisterMockedHttpURLLoad("long_press_links_and_images.html");

  url_test_helpers::RegisterMockedURLLoad(
      ToKURL("http://www.test.com/foo.png"),
      test::CoreTestDataPath("white-1x1.png"));
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_links_and_images.html");

  web_view->SettingsImpl()->SetTouchDragDropEnabled(true);
  web_view->SettingsImpl()->SetModalContextMenu(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString image_tag_id = WebString::FromUTF8("imageTag");

  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureShortPress, image_tag_id));
  EXPECT_EQ("dragstart@img,",
            web_view->MainFrameImpl()->GetDocument().Title().Ascii());
  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, image_tag_id));
  EXPECT_EQ("dragstart@img,contextmenu@img,",
            web_view->MainFrameImpl()->GetDocument().Title().Ascii());
}

TEST_F(WebViewTest, ContextMenuAndDragOnLinkLongPress) {
  ScopedTouchDragOnShortPressForTest touch_drag_on_short_press(true);

  RegisterMockedHttpURLLoad("long_press_links_and_images.html");

  url_test_helpers::RegisterMockedURLLoad(
      ToKURL("http://www.test.com/foo.png"),
      test::CoreTestDataPath("white-1x1.png"));
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_links_and_images.html");

  web_view->SettingsImpl()->SetTouchDragDropEnabled(true);
  web_view->SettingsImpl()->SetModalContextMenu(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString anchor_tag_id = WebString::FromUTF8("anchorTag");

  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureShortPress, anchor_tag_id));
  EXPECT_EQ("dragstart@a,",
            web_view->MainFrameImpl()->GetDocument().Title().Ascii());
  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, anchor_tag_id));
  EXPECT_EQ("dragstart@a,contextmenu@a,",
            web_view->MainFrameImpl()->GetDocument().Title().Ascii());
}

TEST_F(WebViewTest, LongPressEmptyEditableSelection) {
  RegisterMockedHttpURLLoad("long_press_empty_editable_selection.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_empty_editable_selection.html");
  web_view->SettingsImpl()->SetAlwaysShowContextMenuOnTouch(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(10, 10));

  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
}

TEST_F(WebViewTest, LongPressEmptyNonEditableSelection) {
  RegisterMockedHttpURLLoad("long_press_image.html");

  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "long_press_image.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(300, 300));
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();

  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
  EXPECT_TRUE(frame->SelectionAsText().IsEmpty());
}

TEST_F(WebViewTest, LongPressSelection) {
  RegisterMockedHttpURLLoad("longpress_selection.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "longpress_selection.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString target = WebString::FromUTF8("target");
  WebString onselectstartfalse = WebString::FromUTF8("onselectstartfalse");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();

  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, onselectstartfalse));
  EXPECT_EQ("", frame->SelectionAsText().Utf8());
  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, target));
  EXPECT_EQ("testword", frame->SelectionAsText().Utf8());
}

TEST_F(WebViewTest, DoublePressSelection) {
  ScopedTouchTextEditingRedesignForTest touch_text_editing_redesign(true);
  RegisterMockedHttpURLLoad("double_press_selection.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "double_press_selection.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString target = WebString::FromUTF8("target");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();

  // Double press should select nearest word.
  EXPECT_TRUE(SimulateTapEventAtElementById(
      WebInputEvent::Type::kGestureTapDown, 1, target));
  EXPECT_TRUE(SimulateTapEventAtElementById(WebInputEvent::Type::kGestureTap, 1,
                                            target));
  EXPECT_TRUE(SimulateTapEventAtElementById(
      WebInputEvent::Type::kGestureTapDown, 2, target));
  EXPECT_EQ("selection", frame->SelectionAsText().Utf8());

  // Releasing double tap should keep the selection.
  EXPECT_TRUE(SimulateTapEventAtElementById(WebInputEvent::Type::kGestureTap, 2,
                                            target));
  EXPECT_EQ("selection", frame->SelectionAsText().Utf8());
}

TEST_F(WebViewTest, DoublePressSelectionOnSelectStartFalse) {
  ScopedTouchTextEditingRedesignForTest touch_text_editing_redesign(true);
  RegisterMockedHttpURLLoad("double_press_selection.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "double_press_selection.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString onselectstartfalse = WebString::FromUTF8("onselectstartfalse");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();

  // Should not select anything when onselectstart is false.
  EXPECT_TRUE(SimulateTapEventAtElementById(
      WebInputEvent::Type::kGestureTapDown, 1, onselectstartfalse));
  EXPECT_TRUE(SimulateTapEventAtElementById(WebInputEvent::Type::kGestureTap, 1,
                                            onselectstartfalse));
  EXPECT_TRUE(SimulateTapEventAtElementById(
      WebInputEvent::Type::kGestureTapDown, 2, onselectstartfalse));
  EXPECT_EQ("", frame->SelectionAsText().Utf8());
  EXPECT_TRUE(SimulateTapEventAtElementById(WebInputEvent::Type::kGestureTap, 2,
                                            onselectstartfalse));
  EXPECT_EQ("", frame->SelectionAsText().Utf8());
}

TEST_F(WebViewTest, DoublePressSelectionPreventDefaultMouseDown) {
  ScopedTouchTextEditingRedesignForTest touch_text_editing_redesign(true);
  RegisterMockedHttpURLLoad("double_press_selection.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "double_press_selection.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  web_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("document.getElementById('targetdiv').addEventListener("
                      "'mousedown', function(e) { e.preventDefault();});"));

  WebString target = WebString::FromUTF8("target");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();

  // Double press should not select anything.
  EXPECT_TRUE(SimulateTapEventAtElementById(
      WebInputEvent::Type::kGestureTapDown, 1, target));
  EXPECT_TRUE(SimulateTapEventAtElementById(WebInputEvent::Type::kGestureTap, 1,
                                            target));
  EXPECT_TRUE(SimulateTapEventAtElementById(
      WebInputEvent::Type::kGestureTapDown, 2, target));
  EXPECT_EQ("", frame->SelectionAsText().Utf8());

  // Releasing double tap also should not select anything.
  EXPECT_TRUE(SimulateTapEventAtElementById(WebInputEvent::Type::kGestureTap, 2,
                                            target));
  EXPECT_EQ("", frame->SelectionAsText().Utf8());
}

TEST_F(WebViewTest, FinishComposingTextDoesNotDismissHandles) {
  RegisterMockedHttpURLLoad("longpress_selection.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "longpress_selection.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString target = WebString::FromUTF8("target");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  web_view->SetIsActive(true);
  web_view->SetPageFocus(true);
  WebInputMethodController* active_input_method_controller =
      frame->FrameWidget()->GetActiveWebInputMethodController();
  EXPECT_TRUE(
      SimulateGestureAtElementById(WebInputEvent::Type::kGestureTap, target));
  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  frame->SetEditableSelectionOffsets(8, 8);
  EXPECT_TRUE(active_input_method_controller->SetComposition(
      "12345", empty_ime_text_spans, WebRange(), 8, 13));
  EXPECT_TRUE(frame->GetFrame()->GetInputMethodController().HasComposition());
  EXPECT_EQ("", frame->SelectionAsText().Utf8());
  EXPECT_FALSE(frame->GetFrame()->Selection().IsHandleVisible());
  EXPECT_TRUE(frame->GetFrame()->GetInputMethodController().HasComposition());

  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, target));
  EXPECT_EQ("testword12345", frame->SelectionAsText().Utf8());
  EXPECT_TRUE(frame->GetFrame()->Selection().IsHandleVisible());
  EXPECT_TRUE(frame->GetFrame()->GetInputMethodController().HasComposition());

  // Check that finishComposingText(KeepSelection) does not dismiss handles.
  active_input_method_controller->FinishComposingText(
      WebInputMethodController::kKeepSelection);
  EXPECT_TRUE(frame->GetFrame()->Selection().IsHandleVisible());
}

#if !BUILDFLAG(IS_MAC)
TEST_F(WebViewTest, TouchDoesntSelectEmptyTextarea) {
  RegisterMockedHttpURLLoad("longpress_textarea.html");

  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "longpress_textarea.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString blanklinestextbox = WebString::FromUTF8("blanklinestextbox");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();

  // Long-press on carriage returns.
  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, blanklinestextbox));
  EXPECT_TRUE(frame->SelectionAsText().IsEmpty());

  // Double-tap on carriage returns.
  WebGestureEvent event(WebInputEvent::Type::kGestureTap,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(100, 25));
  event.data.tap.tap_count = 2;

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  EXPECT_TRUE(frame->SelectionAsText().IsEmpty());

  auto* text_area_element = To<HTMLTextAreaElement>(static_cast<Node*>(
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          blanklinestextbox)));
  text_area_element->SetValue("hello");

  // Long-press past last word of textbox.
  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, blanklinestextbox));
  EXPECT_TRUE(frame->SelectionAsText().IsEmpty());

  // Double-tap past last word of textbox.
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  EXPECT_TRUE(frame->SelectionAsText().IsEmpty());
}
#endif

TEST_F(WebViewTest, LongPressImageTextarea) {
  RegisterMockedHttpURLLoad("longpress_image_contenteditable.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "longpress_image_contenteditable.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString image = WebString::FromUTF8("purpleimage");

  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, image));
  WebRange range = web_view->MainFrameImpl()
                       ->GetInputMethodController()
                       ->GetSelectionOffsets();
  EXPECT_FALSE(range.IsNull());
  EXPECT_EQ(0, range.StartOffset());
  EXPECT_EQ(1, range.length());
}

TEST_F(WebViewTest, BlinkCaretAfterLongPress) {
  RegisterMockedHttpURLLoad("blink_caret_on_typing_after_long_press.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "blink_caret_on_typing_after_long_press.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(640, 480));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString target = WebString::FromUTF8("target");
  WebLocalFrameImpl* main_frame = web_view->MainFrameImpl();

  EXPECT_TRUE(SimulateGestureAtElementById(
      WebInputEvent::Type::kGestureLongPress, target));
  EXPECT_FALSE(main_frame->GetFrame()->Selection().IsCaretBlinkingSuspended());
}

TEST_F(WebViewTest, BlinkCaretOnClosingContextMenu) {
  RegisterMockedHttpURLLoad("form.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "form.html");

  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  RunPendingTasks();

  // We suspend caret blinking when pressing with mouse right button.
  // Note that we do not send MouseUp event here since it will be consumed
  // by the context menu once it shows up.
  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetPositionInWidget(1, 1);
  mouse_event.click_count = 1;
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));
  RunPendingTasks();

  WebLocalFrameImpl* main_frame = web_view->MainFrameImpl();
  EXPECT_TRUE(main_frame->GetFrame()->Selection().IsCaretBlinkingSuspended());

  // Caret blinking is still suspended after showing context menu.
  web_view->MainFrameImpl()->LocalRootFrameWidget()->ShowContextMenu(
      ui::mojom::blink::MenuSourceType::kMouse,
      web_view->MainFrameImpl()->GetPositionInViewportForTesting());

  EXPECT_TRUE(main_frame->GetFrame()->Selection().IsCaretBlinkingSuspended());

  // Caret blinking will be resumed only after context menu is closed.
  web_view->DidCloseContextMenu();

  EXPECT_FALSE(main_frame->GetFrame()->Selection().IsCaretBlinkingSuspended());
}

TEST_F(WebViewTest, SelectionOnReadOnlyInput) {
  RegisterMockedHttpURLLoad("selection_readonly.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "selection_readonly.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(640, 480));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  std::string test_word = "This text should be selected.";

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  EXPECT_EQ(test_word, frame->SelectionAsText().Utf8());

  WebRange range = web_view->MainFrameImpl()
                       ->GetInputMethodController()
                       ->GetSelectionOffsets();
  EXPECT_FALSE(range.IsNull());
  EXPECT_EQ(0, range.StartOffset());
  EXPECT_EQ(static_cast<int>(test_word.length()), range.length());
}

TEST_F(WebViewTest, KeyDownScrollsHandled) {
  RegisterMockedHttpURLLoad("content-width-1000.html");

  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "content-width-1000.html");
  web_view->MainFrameViewWidget()->Resize(gfx::Size(100, 100));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebKeyboardEvent key_event(WebInputEvent::Type::kRawKeyDown,
                             WebInputEvent::kNoModifiers,
                             WebInputEvent::GetStaticTimeStampForTests());

  // RawKeyDown pagedown should be handled.
  key_event.windows_key_code = VKEY_NEXT;
  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  // Coalesced KeyDown arrow-down should be handled.
  key_event.windows_key_code = VKEY_DOWN;
  key_event.SetType(WebInputEvent::Type::kKeyDown);
  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  // Ctrl-Home should be handled...
  key_event.windows_key_code = VKEY_HOME;
  key_event.SetModifiers(WebInputEvent::kControlKey);
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  // But Ctrl-Down should not.
  key_event.windows_key_code = VKEY_DOWN;
  key_event.SetModifiers(WebInputEvent::kControlKey);
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  // Shift, meta, and alt should not be handled.
  key_event.windows_key_code = VKEY_NEXT;
  key_event.SetModifiers(WebInputEvent::kShiftKey);
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  key_event.windows_key_code = VKEY_NEXT;
  key_event.SetModifiers(WebInputEvent::kMetaKey);
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  key_event.windows_key_code = VKEY_NEXT;
  key_event.SetModifiers(WebInputEvent::kAltKey);
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  // System-key labeled Alt-Down (as in Windows) should do nothing,
  // but non-system-key labeled Alt-Down (as in Mac) should be handled
  // as a page-down.
  key_event.windows_key_code = VKEY_DOWN;
  key_event.SetModifiers(WebInputEvent::kAltKey);
  key_event.is_system_key = true;
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  key_event.windows_key_code = VKEY_DOWN;
  key_event.SetModifiers(WebInputEvent::kAltKey);
  key_event.is_system_key = false;
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(key_event, ui::LatencyInfo())));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));
}

class MiddleClickAutoscrollWebFrameWidget
    : public frame_test_helpers::TestWebFrameWidget {
 public:
  template <typename... Args>
  explicit MiddleClickAutoscrollWebFrameWidget(Args&&... args)
      : frame_test_helpers::TestWebFrameWidget(std::forward<Args>(args)...) {}

  // FrameWidget overrides:
  void DidChangeCursor(const ui::Cursor& cursor) override {
    last_cursor_type_ = cursor.type();
  }

  ui::mojom::blink::CursorType GetLastCursorType() const {
    return last_cursor_type_;
  }

 private:
  ui::mojom::blink::CursorType last_cursor_type_ =
      ui::mojom::blink::CursorType::kPointer;
};

class MiddleClickWebViewTest : public WebViewTest {
 public:
  MiddleClickWebViewTest()
      : WebViewTest(WTF::BindRepeating(
            &frame_test_helpers::WebViewHelper::CreateTestWebFrameWidget<
                MiddleClickAuto
```