Response:
Let's break down the thought process for analyzing the provided code snippet and generating the comprehensive answer.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the given C++ code snippet from `web_view_test.cc`. The request specifically asks about its relation to web technologies (JavaScript, HTML, CSS), logic, potential errors, debugging, and a summary of its function within the larger context (part 7 of 9).

**2. Initial Code Scan and Keyword Recognition:**

The first step is a quick scan of the code, looking for recognizable patterns and keywords:

* **`TEST_F(WebViewTest, ...)`:** This immediately identifies the code as a test case within the `WebViewTest` fixture. This tells us it's focused on verifying the behavior of `WebViewImpl` or related components.
* **`EventHandlerRegistry`:** This is a key data structure related to managing event listeners in the Blink rendering engine.
* **`DidAddEventHandler`, `DidRemoveEventHandler`, `DidRemoveAllEventHandlers`:** These functions clearly manipulate the event handler registry.
* **`kTouchEvent`:**  This constant indicates that the test is specifically concerned with touch events.
* **`frame_widget_host.GetAndResetHasTouchEventHandlerCallCount`:** This suggests an interaction with a `FrameWidgetHost` and its ability to track whether touch event handlers are present. The `GetAndReset` implies the test is verifying state changes over time.
* **`document->getElementById`, `parent_div`, `child_frame`, `child_document`, `child_div`:** These indicate manipulation of the Document Object Model (DOM), specifically targeting elements within the main document and an iframe.
* **`EXPECT_EQ`:** These are assertion statements, used to verify that expected outcomes match actual behavior.
* **`base::RunLoop().RunUntilIdle()`:** This is a common pattern in Chromium tests to ensure asynchronous operations (like event handling) have completed before assertions are checked.

**3. Inferring Functionality based on Keywords:**

Based on the identified keywords, we can start to infer the functionality of this specific test:

* **Focus on Touch Events:** The repetition of `kTouchEvent` and the `GetAndResetHasTouchEventHandlerCallCount` strongly suggest the test verifies how the system tracks the presence of touch event listeners.
* **DOM Manipulation:**  The use of `getElementById` and references to parent divs and child iframes indicates the test explores how event listeners are managed across different parts of the DOM hierarchy.
* **Adding and Removing Handlers:** The `DidAddEventHandler` and `DidRemoveEventHandler` calls clearly demonstrate the test's focus on the mechanics of adding and removing event listeners.
* **Testing Different Scenarios:** The sequence of adding, removing, and adding again, both on the document and individual elements, suggests the test covers various scenarios for managing touch event listeners.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

Now, let's connect these observations to web technologies:

* **JavaScript:** The event handlers being added and removed are fundamentally tied to JavaScript. JavaScript code uses `addEventListener` and `removeEventListener` (or similar mechanisms) to attach functions that respond to events.
* **HTML:** The `document`, `div`, and `iframe` elements are all core HTML elements. The test simulates the kind of DOM structure you'd find in a web page.
* **CSS:** While not directly manipulated in *this specific snippet*, the presence of elements and the triggering of events can be influenced by CSS (e.g., `pointer-events: none` could prevent touch events). It's important to acknowledge this broader context, even if this test is narrowly focused.

**5. Constructing Assumptions, Inputs, and Outputs:**

To illustrate the logic, let's create some hypothetical scenarios:

* **Assumption:**  The `frame_widget_host` tracks whether *any* element within the frame has a touch event listener.
* **Input 1:** Add a touch event listener to the document.
* **Output 1:** `GetAndResetHasTouchEventHandlerCallCount(true)` should return 1 (a handler exists).
* **Input 2:** Remove the listener.
* **Output 2:** `GetAndResetHasTouchEventHandlerCallCount(false)` should return 1 (no handler exists).
* **Input 3:** Add a listener to a `div`.
* **Output 3:** `GetAndResetHasTouchEventHandlerCallCount(true)` should return 1.

**6. Identifying Potential User/Programming Errors:**

Thinking about common mistakes helps demonstrate the value of such tests:

* **Forgetting to remove event listeners:**  If a developer adds listeners but doesn't remove them when they're no longer needed, it can lead to memory leaks or unexpected behavior. This test indirectly verifies that the registry correctly handles removals.
* **Incorrectly targeting event listeners:**  Trying to remove a listener from the wrong element won't work. The test with the `parent_div` highlights this scenario.
* **Over-reliance on document-level listeners:**  While convenient, sometimes it's better to attach listeners to specific elements for performance or clarity. This test shows how the registry handles both scenarios.

**7. Debugging Scenario and User Steps:**

To connect this to a real-world debugging scenario:

* **User Action:** A user interacts with a web page on a touch device.
* **Problem:** A touch event handler is not firing as expected.
* **Debugging Steps:** A developer might inspect the DOM, check for JavaScript errors, and then potentially look at the Blink internals to see if the event listener is even registered correctly. This test provides a lower-level view of that registration process.

**8. Summarizing the Function:**

Finally, the request asks for a summary of the code's function within the larger `web_view_test.cc` file and its position (part 7 of 9). The summary should be concise and capture the main purpose. Given the focus on touch events and the event handler registry, a summary like "This part of the test suite focuses on verifying the correct behavior of the event handler registry, specifically for touch events..." is appropriate.

**9. Iteration and Refinement:**

Throughout this process, there might be some back-and-forth. For example, initially, I might have focused too much on the `FrameWidgetHost`. However, realizing the central role of `EventHandlerRegistry` requires adjusting the emphasis. Similarly, the connection to JavaScript, HTML, and CSS needs to be explicitly drawn. The examples for assumptions, errors, and debugging help solidify the understanding and make it more concrete.
这是 `blink/renderer/core/exported/web_view_test.cc` 文件中的一部分代码，它主要的功能是**测试 `EventHandlerRegistry` 对于 touch 事件的添加和移除的正确性**。

作为第 7 部分，结合上下文（假设之前的章节测试了 `EventHandlerRegistry` 的其他事件类型或基本功能），这一部分深入测试了 `EventHandlerRegistry` 在处理 touch 事件时的行为，包括在 document 和 element 上添加和移除 handler，以及在 iframe 中的处理。

以下是对代码功能的详细解释，并结合 JavaScript, HTML, CSS 进行说明：

**功能列举:**

1. **测试在 Document 上添加和移除 touch 事件 handler:**  验证 `EventHandlerRegistry` 能否正确跟踪 document 上 touch 事件 handler 的添加和移除。
2. **测试在 Element 上添加和移除 touch 事件 handler:** 验证 `EventHandlerRegistry` 能否正确跟踪特定 element (例如 `<div>`) 上 touch 事件 handler 的添加和移除。
3. **测试重复添加和移除 handler 的影响:** 验证重复添加相同的 handler 是否会多次触发，以及重复移除是否会影响剩余的 handler。
4. **测试 `DidRemoveAllEventHandlers` 的功能:** 验证 `DidRemoveAllEventHandlers` 能否正确移除指定元素上的所有事件 handler。
5. **测试在 iframe 中添加和移除 touch 事件 handler:** 验证 `EventHandlerRegistry` 能否正确处理跨 frame 的事件 handler 添加和移除，特别是在父 frame 和子 frame 之间。
6. **验证 `FrameWidgetHost` 的调用计数:** 通过 `frame_widget_host.GetAndResetHasTouchEventHandlerCallCount` 方法来断言在添加和移除 touch 事件 handler 时，`FrameWidgetHost` 是否被正确通知 (has-handlers 或 no-handlers)。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  这段 C++ 代码模拟了 JavaScript 中使用 `addEventListener('touchstart', ...)` 和 `removeEventListener('touchstart', ...)` 添加和移除 touch 事件监听器的行为。`kTouchEvent` 常量对应了 JavaScript 中的 `touchstart`, `touchmove`, `touchend`, `touchcancel` 等 touch 事件。
* **HTML:** 代码中使用了 `document->getElementById(AtomicString("parentdiv"))` 和 `document->getElementById(AtomicString("childframe"))` 来获取 HTML 元素。这模拟了 JavaScript 中通过 ID 获取 DOM 元素的操作，然后在其上添加事件监听器。`simple_div.html` 和包含 iframe 的 HTML 文件是测试用例的 HTML 结构基础。
* **CSS:**  虽然这段代码没有直接操作 CSS，但 CSS 的 `touch-action` 属性会影响 touch 事件的行为。例如，如果一个元素的 `touch-action` 被设置为 `none`，则可能不会触发 touch 事件。这段测试假设 HTML 结构和 CSS 设置允许 touch 事件正常触发和传播。

**逻辑推理 (假设输入与输出):**

假设 HTML 结构包含以下元素：

```html
<body>
  <div id="parentdiv"></div>
  <iframe id="childframe"></iframe>
  <script>
    // 一些 JavaScript 代码可能会在这里添加 touch 事件监听器
  </script>
</body>
```

并且 iframe 的内容包含：

```html
<body>
  <div id="childdiv"></div>
</body>
```

* **假设输入:**  在 document 上添加一个 touch 事件 handler。
* **预期输出:** `frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true)` 返回 1，`frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false)` 返回 0。

* **假设输入:** 移除刚刚添加的 touch 事件 handler。
* **预期输出:** `frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false)` 返回 1，`frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true)` 返回 0。

* **假设输入:** 在 `parentdiv` 上添加一个 touch 事件 handler。
* **预期输出:** `frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true)` 返回 1，`frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false)` 返回 0。

* **假设输入:** 在 `childdiv` (iframe 中) 上添加一个 touch 事件 handler。
* **预期输出:** `frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true)` 返回 1，`frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false)` 返回 0。

**用户或编程常见的使用错误 (举例说明):**

1. **忘记移除事件监听器导致内存泄漏:**  JavaScript 开发者可能会在动态创建的元素上添加事件监听器，但在元素不再使用时忘记移除，导致内存泄漏。这段测试验证了 `EventHandlerRegistry` 的移除机制，确保 Blink 引擎能正确清理不再需要的监听器。
2. **错误地移除事件监听器:**  开发者可能会尝试移除一个不存在的监听器，或者使用错误的元素或事件类型。这段测试验证了即使多次移除或移除不存在的监听器，系统也能保持一致的状态。
3. **在 iframe 环境下管理事件监听器出错:**  在涉及 iframe 的复杂页面中，开发者可能会在错误的 frame 上添加或移除事件监听器。这段测试覆盖了跨 frame 的场景，确保 `EventHandlerRegistry` 能正确处理。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户触摸屏幕:** 用户在支持触摸的设备上与网页进行交互，例如点击、滑动等。
2. **浏览器接收触摸事件:** 操作系统将用户的触摸操作转化为浏览器可以理解的触摸事件。
3. **Blink 渲染引擎处理触摸事件:**  Blink 的事件处理机制接收这些触摸事件。
4. **查找事件目标和监听器:**  Blink 会根据事件发生的位置，查找相应的 DOM 元素，并检查该元素及其父元素是否注册了相应的 touch 事件监听器。
5. **`EventHandlerRegistry` 参与:**  `EventHandlerRegistry` 负责维护已注册的事件监听器信息。当事件发生时，Blink 会查询 `EventHandlerRegistry` 以确定哪些监听器应该被触发。
6. **测试覆盖的场景:** 这段测试代码模拟了在不同元素上添加和移除 touch 事件监听器的过程，覆盖了用户交互可能触发的各种场景。如果用户发现 touch 事件没有按预期工作，开发者可能会怀疑是事件监听器的注册或移除出现了问题，进而查看 `EventHandlerRegistry` 的相关代码和测试用例。

**第 7 部分功能归纳:**

这部分测试主要集中在 **`EventHandlerRegistry` 对于 touch 事件处理的正确性和健壮性**。它验证了在 document 和 element 上添加、移除、重复添加、移除所有 touch 事件 handler 的行为，以及在包含 iframe 的复杂 DOM 结构中，touch 事件 handler 的管理是否正确。通过断言 `FrameWidgetHost` 的调用计数，间接验证了渲染流程中是否正确通知了 touch 事件 handler 的存在与否。这部分是 `web_view_test.cc` 中关于事件处理测试的一个重要组成部分，特别关注移动端和触摸交互场景。

### 提示词
```
这是目录为blink/renderer/core/exported/web_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
ame()->GetEventHandlerRegistry();
  registry->DidAddEventHandler(*document, kTouchEvent);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding another handler has no effect.
  registry->DidAddEventHandler(*document, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Removing the duplicate handler has no effect.
  registry->DidRemoveEventHandler(*document, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Removing the final handler results in a no-handlers call.
  registry->DidRemoveEventHandler(*document, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding a handler on a div results in a has-handlers call.
  Element* parent_div = document->getElementById(AtomicString("parentdiv"));
  DCHECK(parent_div);
  registry->DidAddEventHandler(*parent_div, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding a duplicate handler on the div, clearing all document handlers
  // (of which there are none) and removing the extra handler on the div
  // all have no effect.
  registry->DidAddEventHandler(*parent_div, kTouchEvent);
  registry->DidRemoveAllEventHandlers(*document);
  registry->DidRemoveEventHandler(*parent_div, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Removing the final handler on the div results in a no-handlers call.
  registry->DidRemoveEventHandler(*parent_div, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding two handlers then clearing them in a single call results in a
  // has-handlers then no-handlers call.
  registry->DidAddEventHandler(*parent_div, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));
  registry->DidAddEventHandler(*parent_div, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));
  registry->DidRemoveAllEventHandlers(*parent_div);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding a handler inside of a child iframe results in a has-handlers call.
  Element* child_frame = document->getElementById(AtomicString("childframe"));
  DCHECK(child_frame);
  Document* child_document =
      To<HTMLIFrameElement>(child_frame)->contentDocument();
  Element* child_div = child_document->getElementById(AtomicString("childdiv"));
  DCHECK(child_div);
  registry->DidAddEventHandler(*child_div, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding and clearing handlers in the parent doc or elsewhere in the child
  // doc has no impact.
  registry->DidAddEventHandler(*document, kTouchEvent);
  registry->DidAddEventHandler(*child_frame, kTouchEvent);
  registry->DidAddEventHandler(*child_document, kTouchEvent);
  registry->DidRemoveAllEventHandlers(*document);
  registry->DidRemoveAllEventHandlers(*child_frame);
  registry->DidRemoveAllEventHandlers(*child_document);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Removing the final handler inside the child frame results in a no-handlers
  // call.
  registry->DidRemoveAllEventHandlers(*child_div);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding a handler inside the child frame results in a has-handlers call.
  registry->DidAddEventHandler(*child_document, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Adding a handler in the parent document and removing the one in the frame
  // has no effect.
  registry->DidAddEventHandler(*child_frame, kTouchEvent);
  registry->DidRemoveEventHandler(*child_document, kTouchEvent);
  registry->DidRemoveAllEventHandlers(*child_document);
  registry->DidRemoveAllEventHandlers(*document);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));

  // Now removing the handler in the parent document results in a no-handlers
  // call.
  registry->DidRemoveEventHandler(*child_frame, kTouchEvent);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(false));
  EXPECT_EQ(0,
            frame_widget_host.GetAndResetHasTouchEventHandlerCallCount(true));
}

// This test checks that deleting nodes which have only non-JS-registered touch
// handlers also removes them from the event handler registry. Note that this
// is different from detaching and re-attaching the same node, which is covered
// by web tests under fast/events/.
TEST_F(WebViewTest, DeleteElementWithRegisteredHandler) {
  std::string url = RegisterMockedHttpURLLoad("simple_div.html");
  WebViewImpl* web_view_impl = web_view_helper_.InitializeAndLoad(url);

  Persistent<Document> document =
      web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();
  Element* div = document->getElementById(AtomicString("div"));
  EventHandlerRegistry& registry =
      document->GetFrame()->GetEventHandlerRegistry();

  registry.DidAddEventHandler(*div, EventHandlerRegistry::kScrollEvent);
  EXPECT_TRUE(registry.HasEventHandlers(EventHandlerRegistry::kScrollEvent));

  DummyExceptionStateForTesting exception_state;
  div->remove(exception_state);

  // For oilpan we have to force a GC to ensure the event handlers have been
  // removed when checking below. We do a precise GC (collectAllGarbage does not
  // scan the stack) to ensure the div element dies. This is also why the
  // Document is in a Persistent since we want that to stay around.
  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_FALSE(registry.HasEventHandlers(EventHandlerRegistry::kScrollEvent));
}

// This test verifies the text input flags are correctly exposed to script.
TEST_F(WebViewTest, TextInputFlags) {
  std::string url = RegisterMockedHttpURLLoad("text_input_flags.html");
  WebViewImpl* web_view_impl = web_view_helper_.InitializeAndLoad(url);
  web_view_impl->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  WebLocalFrameImpl* frame = web_view_impl->MainFrameImpl();
  WebInputMethodController* active_input_method_controller =
      frame->GetInputMethodController();
  Document* document = frame->GetFrame()->GetDocument();

  // (A) <input>
  // (A.1) Verifies autocorrect/autocomplete/spellcheck flags are Off and
  // autocapitalize is set to none.
  auto* input_element =
      To<HTMLInputElement>(document->getElementById(AtomicString("input")));
  document->SetFocusedElement(
      input_element, FocusParams(SelectionBehaviorOnFocus::kNone,
                                 mojom::blink::FocusType::kNone, nullptr));
  web_view_impl->MainFrameWidget()->SetFocus(true);
  WebTextInputInfo info1 = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(kWebTextInputFlagAutocompleteOff | kWebTextInputFlagAutocorrectOff |
                kWebTextInputFlagSpellcheckOff |
                kWebTextInputFlagAutocapitalizeNone,
            info1.flags);

  // (A.2) Verifies autocorrect/autocomplete/spellcheck flags are On and
  // autocapitalize is set to sentences.
  input_element =
      To<HTMLInputElement>(document->getElementById(AtomicString("input2")));
  document->SetFocusedElement(
      input_element, FocusParams(SelectionBehaviorOnFocus::kNone,
                                 mojom::blink::FocusType::kNone, nullptr));
  web_view_impl->MainFrameWidget()->SetFocus(true);
  WebTextInputInfo info2 = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(kWebTextInputFlagAutocompleteOn | kWebTextInputFlagAutocorrectOn |
                kWebTextInputFlagSpellcheckOn |
                kWebTextInputFlagAutocapitalizeSentences,
            info2.flags);

  // (B) <textarea> Verifies the default text input flags are
  // WebTextInputFlagAutocapitalizeSentences.
  auto* text_area_element = To<HTMLTextAreaElement>(
      document->getElementById(AtomicString("textarea")));
  document->SetFocusedElement(
      text_area_element, FocusParams(SelectionBehaviorOnFocus::kNone,
                                     mojom::blink::FocusType::kNone, nullptr));
  web_view_impl->MainFrameWidget()->SetFocus(true);
  WebTextInputInfo info3 = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(kWebTextInputFlagAutocapitalizeSentences, info3.flags);

  // (C) Verifies the WebTextInputInfo's don't equal.
  EXPECT_FALSE(info1.Equals(info2));
  EXPECT_FALSE(info2.Equals(info3));

  // Free the webView before freeing the NonUserInputTextUpdateWebViewClient.
  web_view_helper_.Reset();
}

// Check that the WebAutofillClient is correctly notified about first user
// gestures after load, following various input events.
TEST_F(WebViewTest, FirstUserGestureObservedKeyEvent) {
  RegisterMockedHttpURLLoad("form.html");
  MockAutofillClient client;
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "form.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetAutofillClient(&client);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  EXPECT_EQ(0, client.GetUserGestureNotificationsCount());

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

  EXPECT_EQ(1, client.GetUserGestureNotificationsCount());
  frame->SetAutofillClient(nullptr);
}

TEST_F(WebViewTest, FirstUserGestureObservedMouseEvent) {
  RegisterMockedHttpURLLoad("form.html");
  MockAutofillClient client;
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "form.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetAutofillClient(&client);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  EXPECT_EQ(0, client.GetUserGestureNotificationsCount());

  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());
  mouse_event.button = WebMouseEvent::Button::kLeft;
  mouse_event.SetPositionInWidget(1, 1);
  mouse_event.click_count = 1;
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));
  mouse_event.SetType(WebInputEvent::Type::kMouseUp);
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));

  EXPECT_EQ(1, client.GetUserGestureNotificationsCount());
  frame->SetAutofillClient(nullptr);
}

TEST_F(WebViewTest, CompositionIsUserGesture) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  MockAutofillClient client;
  frame->SetAutofillClient(&client);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  EXPECT_EQ(0, client.TextChanges());
  EXPECT_TRUE(
      frame->FrameWidget()->GetActiveWebInputMethodController()->SetComposition(
          WebString::FromUTF8("hello"), WebVector<ui::ImeTextSpan>(),
          WebRange(), 3, 3));
  EXPECT_TRUE(frame->HasTransientUserActivation());
  EXPECT_EQ(1, client.TextChanges());
  EXPECT_TRUE(frame->HasMarkedText());

  frame->SetAutofillClient(nullptr);
}

// Currently, SelectionAsText() is built upon TextIterator, but
// TestWebFrameContentDumper is built upon TextDumperForTests. Their results can
// be different, making the test fail.
// TODO(crbug.com/781434): Build a selection serializer upon TextDumperForTests.
TEST_F(WebViewTest, DISABLED_CompareSelectAllToContentAsText) {
  RegisterMockedHttpURLLoad("longpress_selection.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "longpress_selection.html");

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->ExecuteScript(WebScriptSource(
      WebString::FromUTF8("document.execCommand('SelectAll', false, null)")));
  std::string actual = frame->SelectionAsText().Utf8();

  const int kMaxOutputCharacters = 1024;
  std::string expected = TestWebFrameContentDumper::DumpWebViewAsText(
                             web_view, kMaxOutputCharacters)
                             .Utf8();
  EXPECT_EQ(expected, actual);
}

TEST_F(WebViewTest, AutoResizeSubtreeLayout) {
  std::string url = RegisterMockedHttpURLLoad("subtree-layout.html");
  WebViewImpl* web_view = web_view_helper_.Initialize();

  web_view->EnableAutoResizeMode(gfx::Size(200, 200), gfx::Size(200, 200));
  LoadFrame(web_view->MainFrameImpl(), url);

  LocalFrameView* frame_view =
      web_view_helper_.LocalMainFrame()->GetFrameView();

  // Auto-resizing used to DCHECK(needsLayout()) in LayoutBlockFlow::layout.
  // This EXPECT is merely a dummy. The real test is that we don't trigger
  // asserts in debug builds.
  EXPECT_FALSE(frame_view->NeedsLayout());
}

TEST_F(WebViewTest, PreferredSize) {
  std::string url = base_url_ + "specify_size.html?100px:100px";
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(url), test::CoreTestDataPath("specify_size.html"));
  WebView* web_view = web_view_helper_.InitializeAndLoad(url);

  gfx::Size size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(100, size.width());
  EXPECT_EQ(100, size.height());

  web_view->MainFrameWidget()->SetZoomLevel(ZoomFactorToZoomLevel(2.0));
  UpdateAllLifecyclePhases();
  size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(200, size.width());
  EXPECT_EQ(200, size.height());

  // Verify that both width and height are rounded (in this case up)
  web_view->MainFrameWidget()->SetZoomLevel(ZoomFactorToZoomLevel(0.9995));
  UpdateAllLifecyclePhases();
  size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(100, size.width());
  EXPECT_EQ(100, size.height());

  // Verify that both width and height are rounded (in this case down)
  web_view->MainFrameWidget()->SetZoomLevel(ZoomFactorToZoomLevel(1.0005));
  UpdateAllLifecyclePhases();
  size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(100, size.width());
  EXPECT_EQ(100, size.height());

  url = base_url_ + "specify_size.html?1.5px:1.5px";
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(url), test::CoreTestDataPath("specify_size.html"));
  web_view = web_view_helper_.InitializeAndLoad(url);

  web_view->MainFrameWidget()->SetZoomLevel(ZoomFactorToZoomLevel(1));
  UpdateAllLifecyclePhases();
  size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(2, size.width());
  EXPECT_EQ(2, size.height());
}

TEST_F(WebViewTest, PreferredMinimumSizeQuirksMode) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  frame_test_helpers::LoadHTMLString(
      web_view->MainFrameImpl(),
      R"HTML(<html>
        <body style="margin: 0px;">
          <div style="width: 99px; height: 100px; display: inline-block;"></div>
        </body>
      </html>)HTML",
      url_test_helpers::ToKURL("http://example.com/"));

  gfx::Size size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(99, size.width());
  // When in quirks mode the preferred height stretches to fill the viewport.
  EXPECT_EQ(600, size.height());
}

TEST_F(WebViewTest, PreferredSizeWithGrid) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     R"HTML(<!DOCTYPE html>
    <style>
      html { writing-mode: vertical-rl; }
      body { margin: 0px; }
    </style>
    <div style="width: 100px;">
      <div style="display: grid; width: 100%;">
        <div style="writing-mode: horizontal-tb; height: 100px;"></div>
      </div>
    </div>
                                   )HTML",
                                     base_url);

  gfx::Size size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(0, size.width());
  EXPECT_EQ(100, size.height());
}

TEST_F(WebViewTest, PreferredSizeWithNGGridSkipped) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     R"HTML(<!DOCTYPE html>
    <style>
      body { margin: 0px; }
    </style>
    <div style="display: inline-grid;
                padding: 1%;
                border: 5px solid black;
                grid-template-rows: 1fr 2fr">
      <svg id="target" viewBox="0 0 1 1" style="background: green;
                                                height: 100%;" >
        <circle id="c1" cx="50" cy="50" r="50"/>
      </svg>
    </div>
                                   )HTML",
                                     base_url);

  gfx::Size size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(10, size.width());
  EXPECT_EQ(10, size.height());
}

TEST_F(WebViewTest, PreferredSizeWithGridMinWidth) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     R"HTML(<!DOCTYPE html>
    <body style="margin: 0px;">
      <div style="display: inline-grid; min-width: 200px;">
        <div>item</div>
      </div>
    </body>
                                   )HTML",
                                     base_url);

  gfx::Size size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(200, size.width());
}

TEST_F(WebViewTest, PreferredSizeWithGridMinWidthFlexibleTracks) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     R"HTML(<!DOCTYPE html>
    <body style="margin: 0px;">
      <div style="display: inline-grid; min-width: 200px; grid-template-columns: 1fr;">
        <div>item</div>
      </div>
    </body>
                                   )HTML",
                                     base_url);

  gfx::Size size = web_view->ContentsPreferredMinimumSize();
  EXPECT_EQ(200, size.width());
}

#if BUILDFLAG(ENABLE_UNHANDLED_TAP)

// Helps set up any test that uses a mock Mojo implementation.
class MojoTestHelper {
 public:
  MojoTestHelper(const String& test_file,
                 frame_test_helpers::WebViewHelper& web_view_helper)
      : web_view_helper_(web_view_helper) {
    web_view_ =
        web_view_helper.InitializeAndLoad(test_file.Utf8(), &web_frame_client_);
  }

  ~MojoTestHelper() {
    web_view_helper_.Reset();  // Remove dependency on locally scoped client.
  }

  WebViewImpl* WebView() const { return web_view_; }

 private:
  WebViewImpl* web_view_;
  frame_test_helpers::WebViewHelper& web_view_helper_;
  frame_test_helpers::TestWebFrameClient web_frame_client_;
};

// Mock implementation of the UnhandledTapNotifier Mojo receiver, for testing
// the ShowUnhandledTapUIIfNeeded notification.
class MockUnhandledTapNotifierImpl : public mojom::blink::UnhandledTapNotifier {
 public:
  MockUnhandledTapNotifierImpl() = default;
  ~MockUnhandledTapNotifierImpl() override = default;

  void Bind(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(mojo::PendingReceiver<mojom::blink::UnhandledTapNotifier>(
        std::move(handle)));
  }

  void ShowUnhandledTapUIIfNeeded(
      mojom::blink::UnhandledTapInfoPtr unhandled_tap_info) override {
    was_unhandled_tap_ = true;
    tapped_position_ = unhandled_tap_info->tapped_position_in_viewport;
  }
  bool WasUnhandledTap() const { return was_unhandled_tap_; }
  int GetTappedXPos() const { return tapped_position_.x(); }
  int GetTappedYPos() const { return tapped_position_.y(); }
  void Reset() {
    was_unhandled_tap_ = false;
    tapped_position_ = gfx::Point();
    receiver_.reset();
  }

 private:
  bool was_unhandled_tap_ = false;
  gfx::Point tapped_position_;

  mojo::Receiver<mojom::blink::UnhandledTapNotifier> receiver_{this};
};

// A Test Fixture for testing ShowUnhandledTapUIIfNeeded usages.
class ShowUnhandledTapTest : public WebViewTest {
 public:
  void SetUp() override {
    WebViewTest::SetUp();
    std::string test_file = "show_unhandled_tap.html";
    RegisterMockedHttpURLLoad("Ahem.ttf");
    RegisterMockedHttpURLLoad(test_file);

    mojo_test_helper_ = std::make_unique<MojoTestHelper>(
        WebString::FromUTF8(base_url_ + test_file), web_view_helper_);

    web_view_ = mojo_test_helper_->WebView();
    web_view_->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
    web_view_->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
    RunPendingTasks();

    WebLocalFrameImpl* web_local_frame = web_view_->MainFrameImpl();
    web_local_frame->GetFrame()
        ->GetBrowserInterfaceBroker()
        .SetBinderForTesting(
            mojom::blink::UnhandledTapNotifier::Name_,
            WTF::BindRepeating(&MockUnhandledTapNotifierImpl::Bind,
                               WTF::Unretained(&mock_notifier_)));
  }

  void TearDown() override {
    WebLocalFrameImpl* web_local_frame = web_view_->MainFrameImpl();
    web_local_frame->GetFrame()
        ->GetBrowserInterfaceBroker()
        .SetBinderForTesting(mojom::blink::UnhandledTapNotifier::Name_, {});

    WebViewTest::TearDown();
  }

 protected:
  // Tap on the given element by ID.
  void Tap(const String& element_id) {
    mock_notifier_.Reset();
    EXPECT_TRUE(SimulateGestureAtElementById(WebInputEvent::Type::kGestureTap,
                                             element_id));
  }

  // Set up a test script for the given |operation| with the given |handler|.
  void SetTestScript(const String& operation, const String& handler) {
    String test_key = operation + "-" + handler;
    web_view_->MainFrameImpl()->ExecuteScript(
        WebScriptSource(String("setTest('" + test_key + "');")));
  }

  // Test each mouse event combination with the given |handler|, and verify the
  // |expected| outcome.
  void TestEachMouseEvent(const String& handler, bool expected) {
    SetTestScript("mousedown", handler);
    Tap("target");
    EXPECT_EQ(expected, mock_notifier_.WasUnhandledTap());

    SetTestScript("mouseup", handler);
    Tap("target");
    EXPECT_EQ(expected, mock_notifier_.WasUnhandledTap());

    SetTestScript("click", handler);
    Tap("target");
    EXPECT_EQ(expected, mock_notifier_.WasUnhandledTap());
  }

  WebViewImpl* web_view_;
  MockUnhandledTapNotifierImpl mock_notifier_;

 private:
  std::unique_ptr<MojoTestHelper> mojo_test_helper_;
};

TEST_F(ShowUnhandledTapTest, ShowUnhandledTapUIIfNeeded) {
  // Scroll the bottom into view so we can distinguish window coordinates from
  // document coordinates.
  Tap("bottom");
  EXPECT_TRUE(mock_notifier_.WasUnhandledTap());
  EXPECT_EQ(64, mock_notifier_.GetTappedXPos());
  EXPECT_EQ(278, mock_notifier_.GetTappedYPos());

  // Test basic tap handling and notification.
  Tap("target");
  EXPECT_TRUE(mock_notifier_.WasUnhandledTap());
  EXPECT_EQ(144, mock_notifier_.GetTappedXPos());
  EXPECT_EQ(82, mock_notifier_.GetTappedYPos());

  // Test correct conversion of coordinates to viewport space under pinch-zoom.
  constexpr float scale = 1.5f;
  constexpr float visual_x = 6.f;
  constexpr float visual_y = 10.f;

  web_view_->SetPageScaleFactor(scale);
  web_view_->SetVisualViewportOffset(gfx::PointF(visual_x, visual_y));

  Tap("target");

  // Ensure position didn't change as a result of scroll into view.
  ASSERT_EQ(visual_x, web_view_->VisualViewportOffset().x());
  ASSERT_EQ(visual_y, web_view_->VisualViewportOffset().y());

  EXPECT_TRUE(mock_notifier_.WasUnhandledTap());

  constexpr float expected_x = 144 * scale - (scale * visual_x);
  constexpr float expected_y = 82 * scale - (scale * visual_y);
  EXPECT_EQ(expected_x, mock_notifier_.GetTappedXPos());
  EXPECT_EQ(expected_y, mock_notifier_.GetTappedYPos());
}

TEST_F(ShowUnhandledTapTest, ShowUnhandledTapUIIfNeededWithMutateDom) {
  // Test dom mutation.
  TestEachMouseEvent("mutateDom", false);

  // Test without any DOM mutation.
  TestEachMouseEvent("none", true);
}

TEST_F(ShowUnhandledTapTest, ShowUnhandledTapUIIfNeededWithMutateStyle) {
  // Test style mutation.
  TestEachMouseEvent("mutateStyle", false);

  // Test checkbox:indeterminate style mutation.
  TestEachMouseEvent("mutateIndeterminate", false);

  // Test click div with :active style.
  Tap("style_active");
  EXPECT_FALSE(mock_notifier_.WasUnhandledTap());
}

TEST_F(ShowUnhandledTapTest, ShowUnhandledTapUIIfNeededWithPreventDefault) {
  // Test swallowing.
  TestEachMouseEvent("preventDefault", false);

  // Test without any preventDefault.
  TestEachMouseEvent("none", true);
}

TEST_F(ShowUnhandledTapTest, ShowUnhandledTapUIIfNeededWithNonTriggeringNodes) {
  Tap("image");
  EXPECT_FALSE(mock_notifier_.WasUnhandledTap());

  Tap("editable");
  EXPECT_FALSE(mock_notifier_.WasUnhandledTap());

  Tap("focusable");
  EXPECT_FALSE(mock_notifier_.WasUnhandledTap());
}

#endif  // BUILDFLAG(ENABLE_UNHANDLED_TAP)

TEST_F(WebViewTest, ShouldSuppressKeyboardForPasswordField) {
  RegisterMockedHttpURLLoad("input_field_password.html");
  // Pretend client has fill data for all fields it's queried.
  MockAutofillClient client;
  client.SetShouldSuppressKeyboard(true);
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_password.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetAutofillClient(&client);
  // No field is focused.
  EXPECT_FALSE(frame->ShouldSuppressKeyboardForFocusedElement());

  // Focusing a field should result in treating it autofillable.
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  EXPECT_TRUE(frame->ShouldSuppressKeyboardForFocusedElement());

  // Pretend that |client| no longer has autofill data available.
  client.SetShouldSuppressKeyboard(false);
  EXPECT_FALSE(frame->ShouldSuppressKeyboardForFocusedElement());
  frame->SetAutofillClient(nullptr);
}

TEST_F(WebViewTest, PasswordFieldEditingIsUserGesture) {
  RegisterMockedHttpURLLoad("input_field_password.html");
  MockAutofillClient client;
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_password.html");
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  frame->SetAutofillClient(&client);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  WebVector<ui::ImeTextSpan> empty_ime_text_spans;

  EXPECT_EQ(0, client.TextChanges());
  EXPECT_TRUE(
      frame->FrameWidget()->GetActiveWebInputMethodController()->CommitText(
          WebString::FromUTF8("hello"), empty_ime_text_spans, WebRange(), 0));
  EXPECT_TRUE(frame->HasTransientUserActivation());
  EXPECT_EQ(1, client.TextChanges());
  frame->SetAutofillClient(nullptr);
}

// Verify that a WebView created with a ScopedPagePauser already on the
// stack defers its loads.
TEST_F(WebViewTest, CreatedDuringPagePause) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kPausePagesPerBrowsingContextGroup);

  {
    WebViewImpl* web_view = web_view_helper_.Initialize();
    EXPECT_FALSE(web_view->GetPage()->Paused());
  }

  {
    ScopedPagePauser pauser;
    WebViewImpl* web_view = web_view_helper_.Initialize();
    EXPECT_TRUE(web_view->GetPage()->Paused());
  }
}

// Similar to CreatedDuringPagePause, but pauses only pages that belong to the
// same browsing context group.
TEST_F(WebViewTest, CreatedDuringBrowsingContextGroupPause) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPausePagesPerBrowsingContextGroup);

  WebViewImpl* opener_webview = web_view_helper_.Initialize();
  EXPECT_FALSE(opener_webview->GetPage()->Paused());

  auto pauser = std::make_unique<ScopedBrowsingContextGroupPauser>(
      *opener_webview->GetPage());
  EXPECT_TRUE(opener_webview->GetPage()->Paused());

  frame_test_helpers::WebViewHelper web_view_helper2;
  WebViewImpl* webview2 =
      web_view_helper2.InitializeWithOpener(opener_webview->MainFrame());
  EXPECT_TRUE(webview2->GetPage()->Paused());

  // The following page does not belong to the same browsing context group so
  // it should not be paused.
  frame_test_helpers::WebViewHelper web_view_helper3;
  WebViewImpl* webview3 = web_view_helper3.Initialize();
  EXPECT_FALSE(webview3->GetPage()->Paused());

  // Removing the pauser should unpause pages.
  pauser.reset();
  EXPECT_FALSE(opener_webview->GetPage()->Paused());
  EXPECT_FALSE(webview2->GetPage()->Paused());
}

// Make sure the SubframeBeforeUnloadUseCounter is only incremented on subframe
// unloads. crbug.com/635029.
TEST_F(WebViewTest, SubframeBeforeUnloadUseCounter) {
  RegisterMockedHttpURLLoad("visible_iframe.html");
  RegisterMockedHttpURLLoad("single_iframe.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "single_iframe.html");

  WebLocalFrame* frame = web_view_helper_.LocalMainFrame();
  Document* document =
      To<LocalFrame>(web_view_helper_.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();

  // Add a beforeunload handler in the main frame. Make sure firing
  // beforeunload doesn't increment the subframe use counter.
  {
    frame->ExecuteScript(
        WebScriptSource("addEventListener('beforeunload', function() {});"));
    web_view->MainFrameImpl()->DispatchBeforeUnloadEvent(false);
    EXPECT_FALSE(
        document->IsUseCounted(WebFeature::kSubFrameBeforeUnloadFired));
  }

  // Add a beforeunload handler in the iframe and dispatch. Make sure we do
  // increment the use counter for subframe beforeunloads.
  {
    frame->ExecuteScript(WebScriptSource(
        "document.getElementsByTagName('iframe')[0].contentWindow."
        "addEventListener('beforeunload', function() {});"));
    To<WebLocalFrameImpl>(
        web_view->MainFrame()->FirstChild()->ToWebLocalFrame())
```