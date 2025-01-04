Response:
The user wants a summary of the functionality of the `web_view_test.cc` file in the Chromium Blink engine. They also want to know about its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning with input/output, common user/programming errors, and how a user might reach this code (debugging). This is part 6 of 9.

My plan is to:

1. **Identify the core purpose:** The file contains unit tests for `WebViewImpl`.
2. **Categorize the tests:** Group the tests based on the functionality they are testing. Look for patterns in the test names and the actions performed.
3. **Relate to web technologies:**  Where applicable, explain how the tested functionality interacts with JavaScript, HTML, and CSS.
4. **Analyze logical reasoning:** For tests involving conditional logic or state changes, describe the setup (assumed input) and the expected outcome (output).
5. **Identify potential errors:**  Based on the tests, infer common mistakes users or developers might make.
6. **Describe user interaction:**  Explain how user actions in a browser can trigger the tested code paths.
7. **Summarize the overall functionality** based on the identified categories.
这是 `blink/renderer/core/exported/web_view_test.cc` 文件的第六部分，主要包含了针对 `WebViewImpl` 类的各种功能进行单元测试的代码。这些测试覆盖了与用户交互、页面生命周期、输入事件处理、焦点管理、表单处理以及显示模式等相关的场景。

以下是根据提供的代码片段归纳出的功能点，并结合你提出的要求进行说明：

**功能归纳 (基于提供的第6部分代码):**

* **中键点击自动滚动 (Middle Click Autoscroll):**  测试了中键点击并拖动时的自动滚动功能，以及光标的显示逻辑。会根据页面内容是否可以水平或垂直滚动来显示不同的光标样式。
* **触摸按下高亮链接 (ShowPressOnTransformedLink):** 测试了当触摸按下发生在一个使用了 CSS `transform` 属性的链接上时，是否能正确处理高亮显示，以避免程序崩溃或其他错误。
* **自动填充 (Autofill) 相关测试:**  包含了多个测试用例，用于验证在不同场景下（例如失去焦点、输入法完成输入、使用现有文本设置输入法组合等），是否会不恰当地触发自动填充的 `TextFieldDidChange` 回调，从而避免不必要的自动填充行为。
* **输入法组合 (Composition) 相关测试:**  测试了在使用输入法进行输入时，例如按下 Backspace 键是否会意外取消输入法组合。
* **窗口焦点管理 (Window Focus Management):**
    * 测试了从本地 Frame 发起导航时，是否会错误地聚焦当前 Frame。
    * 测试了通过链接导航到一个已存在的窗口时，是否能正确聚焦该窗口。
    * 测试了在 `CreateNewWindow` 时重用现有窗口的情况下，导航策略是否正确。
    * 测试了通过 `SetFocus` 方法切换焦点时，是否会触发正确的 `focusout` 和 `focusin` (以及 `DOMFocusOut` 和 `DOMFocusIn`) 事件。
* **日期时间选择器 (Date/Time Chooser):** 测试了与日期和时间相关的 `<input>` 元素（如 `date`, `datetime-local`, `month`, `time`, `week`）弹出选择器并选择值的功能。
* **显示模式 (Display Mode):** 测试了通过 `SetDisplayMode` 方法改变 WebView 的显示模式（例如从 "regular-ui" 到 "minimal-ui"）是否会触发相应的渲染更新和通知监听器。包括主 Frame 和子 Frame 的情况。
* **在 `unload` 事件中添加 Frame:** 测试了在页面的 `unload` 事件处理函数中尝试添加新的 Frame 是否会导致问题。包括普通 `unload` 和通过 `ClosePageForTesting` 触发的 `unload`。
* **触摸事件消费者 (Touch Event Consumers):** 测试了 `FrameWidgetHost::SetHasTouchEventConsumers` 方法是否在不同的事件监听器添加和移除操作时被正确调用。这用于优化触摸事件的处理。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 测试用例中大量使用了 HTML 代码片段来创建不同的页面结构和交互元素，例如链接 (`<a>`)、输入框 (`<input>`)、iframe (`<iframe>`) 以及用于事件监听的元素。 例如，测试中会加载包含特定 HTML 结构的页面，然后模拟用户交互来触发相应的行为。
    ```html
    // 例如，用于测试触摸按下高亮链接的 HTML：
    "<a href='http://www.test.com' style='position: absolute; left: 20px; "
    "top: 20px; width: 200px; transform:translateZ(0);'>A link to "
    "highlight</a>"
    ```
* **CSS:**  部分测试关注 CSS 属性的影响，例如 `transform` 属性影响链接高亮显示的处理。另外，显示模式的改变也会影响页面的渲染，这与 CSS 的应用密切相关。
* **JavaScript:** 虽然测试代码本身是 C++，但它模拟了 JavaScript 事件的处理和行为。例如，测试焦点事件、输入法事件以及显示模式变化时，实际上是在测试 Blink 引擎如何响应和触发 JavaScript 事件。例如，在测试显示模式时，页面上可能存在监听 `displaymodechange` 事件的 JavaScript 代码，测试会验证这些监听器是否被正确触发。

**逻辑推理及假设输入与输出:**

* **中键点击自动滚动光标:**
    * **假设输入 1:** 页面宽度 1000px，高度 2000px，WebView 大小设置为 100x100。
    * **预期输出 1:** 中键按下并拖动时，光标类型应为包含四个方向箭头的自动滚动光标 (`MiddlePanningCursor`)，因为页面在水平和垂直方向都可以滚动。
    * **假设输入 2:** 页面宽度 1000px，高度 2000px，WebView 大小设置为 1010x100。
    * **预期输出 2:** 中键按下并拖动时，光标类型应为只包含垂直方向箭头的自动滚动光标 (`MiddlePanningVerticalCursor`)，因为页面只能在垂直方向滚动。
    * **假设输入 3:** 页面宽度 1000px，高度 2000px，WebView 大小设置为 100x2010。
    * **预期输出 3:** 中键按下并拖动时，光标类型应为只包含水平方向箭头的自动滚动光标 (`MiddlePanningHorizontalCursor`)，因为页面只能在水平方向滚动。

* **自动填充触发时机:**
    * **假设输入:**  一个包含已填充值的 `<input>` 元素的页面被加载，用户在一个输入框中进行输入法组合，然后失去焦点。
    * **预期输出:**  `MockAutofillClient::TextFieldDidChange` 不会被调用，因为失去焦点不应该触发自动填充的文本改变通知。

* **输入法组合与 Backspace:**
    * **假设输入:**  在一个输入框中使用输入法输入 "fghij" 并处于组合状态，然后按下 Backspace 键。
    * **预期输出:** 输入法组合不会被取消，而是会更新为 "fghi"。

**用户或编程常见的使用错误及举例说明:**

* **自动填充误触发:**  开发者可能会错误地认为某些操作（例如失去焦点）应该触发自动填充的更新。这些测试确保了 Blink 引擎在这种情况下不会误触发自动填充，避免了不必要的网络请求和性能损耗。
* **输入法组合意外取消:**  在处理键盘事件时，开发者可能会引入 bug，导致输入法组合在不应该取消的情况下被取消，影响用户输入体验。 相关的测试用例可以帮助发现这类问题。
* **焦点管理错误:**  在多窗口或 iframe 场景下，焦点管理可能变得复杂。开发者可能会错误地假设焦点会自然而然地转移到新窗口或特定的 iframe。相关的测试用例验证了 Blink 引擎在这些场景下的焦点处理逻辑是否符合预期。
* **日期时间选择器处理错误:**  开发者在处理日期时间选择器的返回值时，可能会错误地假设用户总是会选择一个有效值。测试用例模拟了用户取消选择或选择无效值的情况，确保代码能正确处理这些边界情况。
* **在 `unload` 事件中执行不安全的操作:**  在页面的 `unload` 事件中添加新的 Frame 或执行其他可能导致资源竞争或崩溃的操作是一种常见的错误。相关的测试用例验证了 Blink 引擎在这种情况下是否能安全地处理。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户使用鼠标中键点击页面并拖动:**  这个操作会触发中键自动滚动功能的代码，相关的测试用例就在测试这个场景。调试时可以关注鼠标事件的处理流程，以及 `MiddleClickAutoscrollWebFrameWidget` 类的行为。
2. **用户在触摸屏设备上点击一个带有 `transform` 属性的链接:**  这个操作会触发触摸按下高亮链接的代码，相关的测试用例模拟了这个过程。调试时可以关注触摸事件的处理和渲染流程。
3. **用户与表单进行交互:**
    * 在输入框中输入内容，可能会触发自动填充相关的代码。
    * 使用输入法进行输入，会触发输入法组合相关的代码。
    * 切换输入框的焦点，会触发焦点管理相关的代码。
4. **用户点击日期或时间类型的 `<input>` 元素，并与弹出的选择器交互:** 这会触发日期时间选择器的代码。调试时可以关注 `<input>` 元素的事件处理，以及外部日期时间选择器的交互。
5. **网页的显示模式发生改变 (例如，通过 Manifest 或 API 调用):**  这会触发显示模式相关的代码。调试时可以关注 `LocalFrameWidget::SetDisplayMode` 方法的调用以及相关事件的触发。
6. **页面被关闭或导航到新的页面:**  这会触发 `unload` 事件，相关的测试用例检查了在 `unload` 事件处理函数中添加 Frame 的情况。
7. **用户与页面上的可触摸元素进行交互:** 这会触发触摸事件，相关的测试用例验证了触摸事件监听器的添加和移除是否正确地通知了 `FrameWidgetHost`。

**总结 (基于提供的第6部分代码):**

这个代码片段主要负责测试 `blink::WebViewImpl` 类的各种与用户交互、页面生命周期管理、输入事件处理以及渲染相关的核心功能。它通过模拟用户操作和浏览器行为，验证了这些功能在各种场景下的正确性和健壮性，特别是关注了自动填充、输入法、焦点管理、日期时间选择器和显示模式等方面的功能。 这些测试确保了 Blink 引擎能够正确地响应用户输入，管理页面状态，并提供良好的用户体验。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共9部分，请归纳一下它的功能

"""
scrollWebFrameWidget>)) {}
};

TEST_F(MiddleClickWebViewTest, MiddleClickAutoscrollCursor) {
  ScopedMiddleClickAutoscrollForTest middle_click_autoscroll(true);
  RegisterMockedHttpURLLoad("content-width-1000.html");

  // We will be changing the size of the page to test each of the panning
  // cursor variations. For reference, content-width-1000.html is 1000px wide
  // and 2000px tall.
  // 1. 100 x 100 - The page will be scrollable in both x and y directions, so
  //      we expect to see the cursor with arrows in all four directions.
  // 2. 1010 x 100 - The page will be scrollable in the y direction, but not x,
  //      so we expect to see the cursor with only the vertical arrows.
  // 3. 100 x 2010 - The page will be scrollable in the x direction, but not y,
  //      so we expect to see the cursor with only the horizontal arrows.
  struct CursorTests {
    int resize_width;
    int resize_height;
    ui::mojom::blink::CursorType expected_cursor;
  } cursor_tests[] = {{100, 100, MiddlePanningCursor().type()},
                      {1010, 100, MiddlePanningVerticalCursor().type()},
                      {100, 2010, MiddlePanningHorizontalCursor().type()}};

  for (const CursorTests current_test : cursor_tests) {
    WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
        base_url_ + "content-width-1000.html", nullptr, nullptr);
    web_view->MainFrameWidget()->Resize(
        gfx::Size(current_test.resize_width, current_test.resize_height));
    UpdateAllLifecyclePhases();
    RunPendingTasks();

    MiddleClickAutoscrollWebFrameWidget* widget =
        static_cast<MiddleClickAutoscrollWebFrameWidget*>(
            web_view_helper_.GetMainFrameWidget());
    LocalFrame* local_frame =
        To<WebLocalFrameImpl>(web_view->MainFrame())->GetFrame();

    // Setup a mock clipboard.  On linux, middle click can paste from the
    // clipboard, so the input handler below will access the clipboard.
    PageTestBase::MockClipboardHostProvider mock_clip_host_provider(
        local_frame->GetBrowserInterfaceBroker());

    WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                              WebInputEvent::kNoModifiers,
                              WebInputEvent::GetStaticTimeStampForTests());
    mouse_event.button = WebMouseEvent::Button::kMiddle;
    mouse_event.SetPositionInWidget(1, 1);
    mouse_event.click_count = 1;

    // Start middle-click autoscroll.
    web_view->MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));
    mouse_event.SetType(WebInputEvent::Type::kMouseUp);
    web_view->MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));

    EXPECT_EQ(current_test.expected_cursor, widget->GetLastCursorType());

    // Even if a plugin tries to change the cursor type, that should be ignored
    // during middle-click autoscroll.
    web_view->GetChromeClient().SetCursorForPlugin(PointerCursor(),
                                                   local_frame);
    EXPECT_EQ(current_test.expected_cursor, widget->GetLastCursorType());

    // End middle-click autoscroll.
    mouse_event.SetType(WebInputEvent::Type::kMouseDown);
    web_view->MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));
    mouse_event.SetType(WebInputEvent::Type::kMouseUp);
    web_view->MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));

    web_view->GetChromeClient().SetCursorForPlugin(IBeamCursor(), local_frame);
    EXPECT_EQ(IBeamCursor().type(), widget->GetLastCursorType());
  }

  // Explicitly reset to break dependency on locally scoped client.
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, ShowPressOnTransformedLink) {
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.Initialize();
  web_view_impl->GetPage()
      ->GetSettings()
      .SetPreferCompositingToLCDTextForTesting(true);

  int page_width = 640;
  int page_height = 480;
  web_view_impl->MainFrameViewWidget()->Resize(
      gfx::Size(page_width, page_height));

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view_impl->MainFrameImpl(),
      "<a href='http://www.test.com' style='position: absolute; left: 20px; "
      "top: 20px; width: 200px; transform:translateZ(0);'>A link to "
      "highlight</a>",
      base_url);

  WebGestureEvent event(WebInputEvent::Type::kGestureShowPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(20, 20));

  // Just make sure we don't hit any asserts.
  web_view_impl->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
}

class MockAutofillClient : public WebAutofillClient {
 public:
  MockAutofillClient() = default;

  ~MockAutofillClient() override = default;

  void TextFieldDidChange(const WebFormControlElement&) override {
    ++text_changes_;
  }
  void UserGestureObserved() override { ++user_gesture_notifications_count_; }

  bool ShouldSuppressKeyboard(const WebFormControlElement&) override {
    return should_suppress_keyboard_;
  }

  void SetShouldSuppressKeyboard(bool should_suppress_keyboard) {
    should_suppress_keyboard_ = should_suppress_keyboard;
  }

  void ClearChangeCounts() { text_changes_ = 0; }

  int TextChanges() { return text_changes_; }
  int GetUserGestureNotificationsCount() {
    return user_gesture_notifications_count_;
  }

 private:
  int text_changes_ = 0;
  int user_gesture_notifications_count_ = 0;
  bool should_suppress_keyboard_ = false;
};

TEST_F(WebViewTest, LosingFocusDoesNotTriggerAutofillTextChange) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  MockAutofillClient client;
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetAutofillClient(&client);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  // Set up a composition that needs to be committed.
  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  frame->SetEditableSelectionOffsets(4, 10);
  frame->SetCompositionFromExistingText(8, 12, empty_ime_text_spans);
  WebTextInputInfo info = frame->GetInputMethodController()->TextInputInfo();
  EXPECT_EQ(4, info.selection_start);
  EXPECT_EQ(10, info.selection_end);
  EXPECT_EQ(8, info.composition_start);
  EXPECT_EQ(12, info.composition_end);

  // Clear the focus and track that the subsequent composition commit does not
  // trigger a text changed notification for autofill.
  client.ClearChangeCounts();
  web_view->MainFrameWidget()->SetFocus(false);
  EXPECT_EQ(0, client.TextChanges());

  frame->SetAutofillClient(nullptr);
}

static void VerifySelectionAndComposition(WebViewImpl* web_view,
                                          int selection_start,
                                          int selection_end,
                                          int composition_start,
                                          int composition_end,
                                          const char* fail_message) {
  WebTextInputInfo info =
      web_view->MainFrameImpl()->GetInputMethodController()->TextInputInfo();
  EXPECT_EQ(selection_start, info.selection_start) << fail_message;
  EXPECT_EQ(selection_end, info.selection_end) << fail_message;
  EXPECT_EQ(composition_start, info.composition_start) << fail_message;
  EXPECT_EQ(composition_end, info.composition_end) << fail_message;
}

TEST_F(WebViewTest, CompositionNotCancelledByBackspace) {
  RegisterMockedHttpURLLoad("composition_not_cancelled_by_backspace.html");
  MockAutofillClient client;
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "composition_not_cancelled_by_backspace.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetAutofillClient(&client);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  // Test both input elements.
  for (int i = 0; i < 2; ++i) {
    // Select composition and do sanity check.
    WebVector<ui::ImeTextSpan> empty_ime_text_spans;
    frame->SetEditableSelectionOffsets(6, 6);
    WebInputMethodController* active_input_method_controller =
        frame->FrameWidget()->GetActiveWebInputMethodController();
    EXPECT_TRUE(active_input_method_controller->SetComposition(
        "fghij", empty_ime_text_spans, WebRange(), 0, 5));
    frame->SetEditableSelectionOffsets(11, 11);
    VerifySelectionAndComposition(web_view, 11, 11, 6, 11, "initial case");

    // Press Backspace and verify composition didn't get cancelled. This is to
    // verify the fix for crbug.com/429916.
    WebKeyboardEvent key_event(WebInputEvent::Type::kRawKeyDown,
                               WebInputEvent::kNoModifiers,
                               WebInputEvent::GetStaticTimeStampForTests());
    key_event.dom_key = ui::DomKey::BACKSPACE;
    key_event.windows_key_code = VKEY_BACK;
    web_view->MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

    frame->SetEditableSelectionOffsets(6, 6);
    EXPECT_TRUE(active_input_method_controller->SetComposition(
        "fghi", empty_ime_text_spans, WebRange(), 0, 4));
    frame->SetEditableSelectionOffsets(10, 10);
    VerifySelectionAndComposition(web_view, 10, 10, 6, 10,
                                  "after pressing Backspace");

    key_event.SetType(WebInputEvent::Type::kKeyUp);
    web_view->MainFrameWidget()->HandleInputEvent(
        WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

    web_view->AdvanceFocus(false);
  }

  frame->SetAutofillClient(nullptr);
}

TEST_F(WebViewTest, FinishComposingTextDoesntTriggerAutofillTextChange) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  MockAutofillClient client;
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetAutofillClient(&client);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  WebDocument document = web_view->MainFrameImpl()->GetDocument();
  auto* form = To<HTMLFormControlElement>(
      static_cast<Element*>(document.GetElementById("sample")));

  WebInputMethodController* active_input_method_controller =
      frame->FrameWidget()->GetActiveWebInputMethodController();
  // Set up a composition that needs to be committed.
  std::string composition_text("testingtext");

  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      0, static_cast<int>(composition_text.length()));

  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ((int)composition_text.length(), info.selection_end);
  EXPECT_EQ(0, info.composition_start);
  EXPECT_EQ((int)composition_text.length(), info.composition_end);

  form->SetAutofillState(blink::WebAutofillState::kAutofilled);
  client.ClearChangeCounts();

  active_input_method_controller->FinishComposingText(
      WebInputMethodController::kKeepSelection);
  EXPECT_EQ(0, client.TextChanges());

  EXPECT_TRUE(form->IsAutofilled());

  frame->SetAutofillClient(nullptr);
}

TEST_F(WebViewTest,
       SetCompositionFromExistingTextDoesntTriggerAutofillTextChange) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  MockAutofillClient client;
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetAutofillClient(&client);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  WebVector<ui::ImeTextSpan> empty_ime_text_spans;

  client.ClearChangeCounts();
  frame->SetCompositionFromExistingText(8, 12, empty_ime_text_spans);

  WebTextInputInfo info = frame->GetInputMethodController()->TextInputInfo();
  EXPECT_EQ("0123456789abcdefghijklmnopqrstuvwxyz", info.value.Utf8());
  EXPECT_EQ(8, info.composition_start);
  EXPECT_EQ(12, info.composition_end);

  EXPECT_EQ(0, client.TextChanges());

  WebDocument document = web_view->MainFrameImpl()->GetDocument();
  EXPECT_EQ(WebString::FromUTF8("none"),
            document.GetElementById("inputEvent").FirstChild().NodeValue());

  frame->SetAutofillClient(nullptr);
}

class ViewCreatingWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  // WebLocalFrameClient overrides.
  WebView* CreateNewWindow(
      const WebURLRequest&,
      const WebWindowFeatures&,
      const WebString& name,
      WebNavigationPolicy,
      network::mojom::blink::WebSandboxFlags,
      const SessionStorageNamespaceId&,
      bool& consumed_user_gesture,
      const std::optional<Impression>&,
      const std::optional<WebPictureInPictureWindowOptions>&,
      const WebURL&) override {
    return web_view_helper_.InitializeWithOpener(Frame());
  }
  WebView* CreatedWebView() const { return web_view_helper_.GetWebView(); }

 private:
  frame_test_helpers::WebViewHelper web_view_helper_;
};

class ViewCreatingWebViewClient : public WebViewClient {
 public:
  ViewCreatingWebViewClient() = default;

  void DidFocus() override { did_focus_called_ = true; }

  bool DidFocusCalled() const { return did_focus_called_; }

 private:
  bool did_focus_called_ = false;
};

TEST_F(WebViewTest, DoNotFocusCurrentFrameOnNavigateFromLocalFrame) {
  ViewCreatingWebFrameClient frame_client;
  ViewCreatingWebViewClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.Initialize(&frame_client, &client);

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view_impl->MainFrameImpl(),
      "<html><body><iframe src=\"about:blank\"></iframe></body></html>",
      base_url);

  // Make a request from a local frame.
  WebURLRequest web_url_request_with_target_start(KURL("about:blank"));
  LocalFrame* local_frame =
      To<WebLocalFrameImpl>(web_view_impl->MainFrame()->FirstChild())
          ->GetFrame();
  FrameLoadRequest request_with_target_start(
      local_frame->DomWindow(),
      web_url_request_with_target_start.ToResourceRequest());
  local_frame->Tree().FindOrCreateFrameForNavigation(request_with_target_start,
                                                     AtomicString("_top"));
  EXPECT_FALSE(client.DidFocusCalled());

  web_view_helper.Reset();  // Remove dependency on locally scoped client.
}

TEST_F(WebViewTest, FocusExistingFrameOnNavigate) {
  ViewCreatingWebFrameClient frame_client;
  ViewCreatingWebViewClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.Initialize(&frame_client, &client);
  WebLocalFrameImpl* frame = web_view_impl->MainFrameImpl();
  frame->SetName("_start");

  // Make a request that will open a new window
  WebURLRequest web_url_request(KURL("about:blank"));
  FrameLoadRequest request(nullptr, web_url_request.ToResourceRequest());
  To<LocalFrame>(web_view_impl->GetPage()->MainFrame())
      ->Tree()
      .FindOrCreateFrameForNavigation(request, AtomicString("_blank"));
  ASSERT_TRUE(frame_client.CreatedWebView());
  EXPECT_FALSE(client.DidFocusCalled());

  // Make a request from the new window that will navigate the original window.
  // The original window should be focused.
  WebURLRequest web_url_request_with_target_start(KURL("about:blank"));
  FrameLoadRequest request_with_target_start(
      nullptr, web_url_request_with_target_start.ToResourceRequest());
  To<LocalFrame>(static_cast<WebViewImpl*>(frame_client.CreatedWebView())
                     ->GetPage()
                     ->MainFrame())
      ->Tree()
      .FindOrCreateFrameForNavigation(request_with_target_start,
                                      AtomicString("_start"));
  EXPECT_TRUE(client.DidFocusCalled());

  web_view_helper.Reset();  // Remove dependency on locally scoped client.
}

class ViewReusingWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  ViewReusingWebFrameClient() = default;

  // WebLocalFrameClient methods
  WebView* CreateNewWindow(
      const WebURLRequest&,
      const WebWindowFeatures&,
      const WebString& name,
      WebNavigationPolicy,
      network::mojom::blink::WebSandboxFlags,
      const SessionStorageNamespaceId&,
      bool& consumed_user_gesture,
      const std::optional<Impression>&,
      const std::optional<WebPictureInPictureWindowOptions>&,
      const WebURL&) override {
    return web_view_;
  }

  void SetWebView(WebView* view) { web_view_ = view; }

 private:
  WebView* web_view_ = nullptr;
};

TEST_F(WebViewTest,
       ReuseExistingWindowOnCreateViewUsesCorrectNavigationPolicy) {
  ViewReusingWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.Initialize(&frame_client);
  frame_client.SetWebView(web_view_impl);
  LocalFrame* frame = To<LocalFrame>(web_view_impl->GetPage()->MainFrame());

  // Request a new window, but the WebViewClient will decline to and instead
  // return the current window.
  WebURLRequest web_url_request(KURL("about:blank"));
  FrameLoadRequest request(frame->DomWindow(),
                           web_url_request.ToResourceRequest());
  FrameTree::FindResult result = frame->Tree().FindOrCreateFrameForNavigation(
      request, AtomicString("_blank"));
  EXPECT_EQ(frame, result.frame);
  EXPECT_EQ(kNavigationPolicyCurrentTab, request.GetNavigationPolicy());
}

TEST_F(WebViewTest, DispatchesFocusOutFocusInOnViewToggleFocus) {
  RegisterMockedHttpURLLoad("focusout_focusin_events.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "focusout_focusin_events.html");

  web_view->MainFrameWidget()->SetFocus(true);
  web_view->MainFrameWidget()->SetFocus(false);
  web_view->MainFrameWidget()->SetFocus(true);

  WebElement element =
      web_view->MainFrameImpl()->GetDocument().GetElementById("message");
  EXPECT_EQ("focusoutfocusin", element.TextContent());
}

TEST_F(WebViewTest, DispatchesDomFocusOutDomFocusInOnViewToggleFocus) {
  RegisterMockedHttpURLLoad("domfocusout_domfocusin_events.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "domfocusout_domfocusin_events.html");

  web_view->MainFrameWidget()->SetFocus(true);
  web_view->MainFrameWidget()->SetFocus(false);
  web_view->MainFrameWidget()->SetFocus(true);

  WebElement element =
      web_view->MainFrameImpl()->GetDocument().GetElementById("message");
  EXPECT_EQ("DOMFocusOutDOMFocusIn", element.TextContent());
}

static void OpenDateTimeChooser(WebView* web_view,
                                HTMLInputElement* input_element) {
  input_element->Focus();

  WebKeyboardEvent key_event(WebInputEvent::Type::kRawKeyDown,
                             WebInputEvent::kNoModifiers,
                             WebInputEvent::GetStaticTimeStampForTests());
  key_event.dom_key = ui::DomKey::FromCharacter(' ');
  key_event.windows_key_code = VKEY_SPACE;
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  key_event.SetType(WebInputEvent::Type::kKeyUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));
}

TEST_F(WebViewTest, ChooseValueFromDateTimeChooser) {
  ScopedInputMultipleFieldsUIForTest input_multiple_fields_ui(false);
  std::string url = RegisterMockedHttpURLLoad("date_time_chooser.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(url, nullptr, nullptr);

  Document* document =
      web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();

  auto* input_element =
      To<HTMLInputElement>(document->getElementById(AtomicString("date")));
  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)->ResponseHandler(true, 0);
  EXPECT_EQ("1970-01-01", input_element->Value());

  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)
      ->ResponseHandler(true, std::numeric_limits<double>::quiet_NaN());
  EXPECT_EQ("", input_element->Value());

  input_element = To<HTMLInputElement>(
      document->getElementById(AtomicString("datetimelocal")));
  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)->ResponseHandler(true, 0);
  EXPECT_EQ("1970-01-01T00:00", input_element->Value());

  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)
      ->ResponseHandler(true, std::numeric_limits<double>::quiet_NaN());
  EXPECT_EQ("", input_element->Value());

  input_element =
      To<HTMLInputElement>(document->getElementById(AtomicString("month")));
  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)->ResponseHandler(true, 0);
  EXPECT_EQ("1970-01", input_element->Value());

  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)
      ->ResponseHandler(true, std::numeric_limits<double>::quiet_NaN());
  EXPECT_EQ("", input_element->Value());

  input_element =
      To<HTMLInputElement>(document->getElementById(AtomicString("time")));
  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)->ResponseHandler(true, 0);
  EXPECT_EQ("00:00", input_element->Value());

  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)
      ->ResponseHandler(true, std::numeric_limits<double>::quiet_NaN());
  EXPECT_EQ("", input_element->Value());

  input_element =
      To<HTMLInputElement>(document->getElementById(AtomicString("week")));
  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)->ResponseHandler(true, 0);
  EXPECT_EQ("1970-W01", input_element->Value());

  OpenDateTimeChooser(web_view_impl, input_element);
  GetExternalDateTimeChooser(web_view_impl)
      ->ResponseHandler(true, std::numeric_limits<double>::quiet_NaN());
  EXPECT_EQ("", input_element->Value());

  // Clear the WebViewClient from the webViewHelper to avoid use-after-free in
  // the WebViewHelper destructor.
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, DispatchesFocusBlurOnViewToggle) {
  RegisterMockedHttpURLLoad("focus_blur_events.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "focus_blur_events.html");

  web_view->MainFrameWidget()->SetFocus(true);
  web_view->MainFrameWidget()->SetFocus(false);
  web_view->MainFrameWidget()->SetFocus(true);

  WebElement element =
      web_view->MainFrameImpl()->GetDocument().GetElementById("message");
  // Expect not to see duplication of events.
  EXPECT_EQ("blurfocus", element.TextContent());
}

class CreateChildCounterFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  CreateChildCounterFrameClient() : count_(0) {}
  WebLocalFrame* CreateChildFrame(
      mojom::blink::TreeScopeType,
      const WebString& name,
      const WebString& fallback_name,
      const FramePolicy&,
      const WebFrameOwnerProperties&,
      FrameOwnerElementType,
      WebPolicyContainerBindParams policy_container_bind_params,
      ukm::SourceId document_ukm_source_id,
      base::FunctionRef<void(
          WebLocalFrame*,
          const DocumentToken&,
          CrossVariantMojoRemote<mojom::BrowserInterfaceBrokerInterfaceBase>)>
          complete_initialization) override;

  int Count() const { return count_; }

 private:
  int count_;
};

WebLocalFrame* CreateChildCounterFrameClient::CreateChildFrame(
    mojom::blink::TreeScopeType scope,
    const WebString& name,
    const WebString& fallback_name,
    const FramePolicy& frame_policy,
    const WebFrameOwnerProperties& frame_owner_properties,
    FrameOwnerElementType frame_owner_element_type,
    WebPolicyContainerBindParams policy_container_bind_params,
    ukm::SourceId document_ukm_source_id,
    base::FunctionRef<void(
        WebLocalFrame*,
        const DocumentToken&,
        CrossVariantMojoRemote<mojom::BrowserInterfaceBrokerInterfaceBase>)>
        complete_initialization) {
  ++count_;
  return TestWebFrameClient::CreateChildFrame(
      scope, name, fallback_name, frame_policy, frame_owner_properties,
      frame_owner_element_type, std::move(policy_container_bind_params),
      document_ukm_source_id, complete_initialization);
}

TEST_F(WebViewTest, ChangeDisplayMode) {
  RegisterMockedHttpURLLoad("display_mode.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "display_mode.html");

  String content = TestWebFrameContentDumper::DumpWebViewAsText(web_view, 21);
  EXPECT_EQ("regular-ui", content);

  web_view->MainFrameImpl()->LocalRootFrameWidget()->SetDisplayMode(
      mojom::blink::DisplayMode::kMinimalUi);
  content = TestWebFrameContentDumper::DumpWebViewAsText(web_view, 21);
  EXPECT_EQ("minimal-ui", content);
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, ChangeDisplayModeChildFrame) {
  RegisterMockedHttpURLLoad("iframe-display_mode.html");
  RegisterMockedHttpURLLoad("display_mode.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "iframe-display_mode.html");

  String content = TestWebFrameContentDumper::DumpWebViewAsText(web_view, 21);
  // An iframe inserts whitespace into the content.
  EXPECT_EQ("regular-ui", content.StripWhiteSpace());

  web_view->MainFrameImpl()->LocalRootFrameWidget()->SetDisplayMode(
      mojom::blink::DisplayMode::kMinimalUi);
  content = TestWebFrameContentDumper::DumpWebViewAsText(web_view, 21);
  // An iframe inserts whitespace into the content.
  EXPECT_EQ("minimal-ui", content.StripWhiteSpace());
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, ChangeDisplayModeAlertsListener) {
  RegisterMockedHttpURLLoad("display_mode_listener.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "display_mode_listener.html");

  String content = TestWebFrameContentDumper::DumpWebViewAsText(web_view, 21);
  EXPECT_EQ("regular-ui", content);

  web_view->MainFrameImpl()->LocalRootFrameWidget()->SetDisplayMode(
      mojom::blink::DisplayMode::kMinimalUi);
  content = TestWebFrameContentDumper::DumpWebViewAsText(web_view, 21);
  EXPECT_EQ("minimal-ui", content);
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, ChangeDisplayModeChildFrameAlertsListener) {
  RegisterMockedHttpURLLoad("iframe-display_mode_listener.html");
  RegisterMockedHttpURLLoad("display_mode_listener.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "iframe-display_mode_listener.html");

  String content = TestWebFrameContentDumper::DumpWebViewAsText(web_view, 21);
  // An iframe inserts whitespace into the content.
  EXPECT_EQ("regular-ui", content.StripWhiteSpace());

  web_view->MainFrameImpl()->LocalRootFrameWidget()->SetDisplayMode(
      mojom::blink::DisplayMode::kMinimalUi);
  content = TestWebFrameContentDumper::DumpWebViewAsText(web_view, 21);
  // An iframe inserts whitespace into the content.
  EXPECT_EQ("minimal-ui", content.StripWhiteSpace());
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, AddFrameInCloseUnload) {
  CreateChildCounterFrameClient frame_client;
  RegisterMockedHttpURLLoad("add_frame_in_unload.html");
  web_view_helper_.InitializeAndLoad(base_url_ + "add_frame_in_unload.html",
                                     &frame_client);
  web_view_helper_.Reset();
  EXPECT_EQ(0, frame_client.Count());
}

TEST_F(WebViewTest, AddFrameInCloseURLUnload) {
  CreateChildCounterFrameClient frame_client;
  RegisterMockedHttpURLLoad("add_frame_in_unload.html");
  web_view_helper_.InitializeAndLoad(base_url_ + "add_frame_in_unload.html",
                                     &frame_client);
  // Dispatch unload event.
  web_view_helper_.LocalMainFrame()->GetFrame()->ClosePageForTesting();
  EXPECT_EQ(0, frame_client.Count());
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, AddFrameInNavigateUnload) {
  CreateChildCounterFrameClient frame_client;
  RegisterMockedHttpURLLoad("add_frame_in_unload.html");
  web_view_helper_.InitializeAndLoad(base_url_ + "add_frame_in_unload.html",
                                     &frame_client);
  frame_test_helpers::LoadFrame(web_view_helper_.GetWebView()->MainFrameImpl(),
                                "about:blank");
  EXPECT_EQ(0, frame_client.Count());
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, AddFrameInChildInNavigateUnload) {
  CreateChildCounterFrameClient frame_client;
  RegisterMockedHttpURLLoad("add_frame_in_unload_wrapper.html");
  RegisterMockedHttpURLLoad("add_frame_in_unload.html");
  web_view_helper_.InitializeAndLoad(
      base_url_ + "add_frame_in_unload_wrapper.html", &frame_client);
  frame_test_helpers::LoadFrame(web_view_helper_.GetWebView()->MainFrameImpl(),
                                "about:blank");
  EXPECT_EQ(1, frame_client.Count());
  web_view_helper_.Reset();
}

class TouchEventConsumersWebFrameWidgetHost
    : public frame_test_helpers::TestWebFrameWidgetHost {
 public:
  int GetAndResetHasTouchEventHandlerCallCount(bool state) {
    int value = has_touch_event_handler_count_[state];
    has_touch_event_handler_count_[state] = 0;
    return value;
  }

  // mojom::FrameWidgetHost overrides:
  void SetHasTouchEventConsumers(
      mojom::blink::TouchEventConsumersPtr consumers) override {
    // Only count the times the state changes.
    bool state = consumers->has_touch_event_handlers;
    if (state != has_touch_event_handler_)
      has_touch_event_handler_count_[state]++;
    has_touch_event_handler_ = state;
  }

 private:
  int has_touch_event_handler_count_[2]{};
  bool has_touch_event_handler_ = false;
};

class TouchEventConsumersWebFrameWidget
    : public frame_test_helpers::TestWebFrameWidget {
 public:
  template <typename... Args>
  explicit TouchEventConsumersWebFrameWidget(Args&&... args)
      : frame_test_helpers::TestWebFrameWidget(std::forward<Args>(args)...) {}

  // frame_test_helpers::TestWebFrameWidget overrides.
  std::unique_ptr<frame_test_helpers::TestWebFrameWidgetHost> CreateWidgetHost()
      override {
    return std::make_unique<TouchEventConsumersWebFrameWidgetHost>();
  }

  TouchEventConsumersWebFrameWidgetHost& TouchEventWidgetHost() {
    return static_cast<TouchEventConsumersWebFrameWidgetHost&>(WidgetHost());
  }
};

class TouchEventConsumersWebViewTest : public WebViewTest {
 public:
  TouchEventConsumersWebViewTest()
      : WebViewTest(WTF::BindRepeating(
            &frame_test_helpers::WebViewHelper::CreateTestWebFrameWidget<
                TouchEventConsumersWebFrameWidget>)) {}
};

// This test verifies that FrameWidgetHost::SetHasTouchEventConsumers is called
// accordingly for various calls to EventHandlerRegistry::did{Add|Remove|
// RemoveAll}EventHandler(..., TouchEvent). Verifying that those calls are made
// correctly is the job of web_tests/fast/events/event-handler-count.html.
TEST_F(TouchEventConsumersWebViewTest, SetHasTouchEventConsumers) {
  std::string url = RegisterMockedHttpURLLoad("has_touch_event_handlers.html");
  WebViewImpl* web_view_impl = web_view_helper_.InitializeAndLoad(url);

  TouchEventConsumersWebFrameWidget* widget =
      static_cast<TouchEventConsumersWebFrameWidget*>(
          web_view_helper_.GetMainFrameWidget());
  TouchEventConsumersWebFrameWidgetHost& frame_widget_host =
      widget->TouchEventWidgetHost();

  const EventHandlerRegistry::EventHandlerClass kTouchEvent =
      EventHandlerRegistry::kTouchStartOrMoveEventBlocking;

  // The page is initialized with at least one no-handlers call.
  // In practice we get two such calls because WebViewHelper::initializeAndLoad
  // first initializes an empty frame, and then loads a document into it, so
  // there are two FrameLoader::commitProvisionalLoad calls.
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding the first document handler results in a has-handlers call.
  Document* document =
      web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();
  EventHandlerRegistry* registry =
      &document->GetFr
"""


```