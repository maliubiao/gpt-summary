Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_frame_test.cc`. The request also asks for connections to JavaScript, HTML, and CSS, examples of logical reasoning with input/output, common usage errors, and a summarization of the functionality in the context of being part 7 of 19.

Here's a breakdown of the thought process:

1. **Identify the Core Function:** The code snippet primarily contains a series of `TEST_F` macros within the `WebFrameTest` test fixture. This immediately indicates that the primary function of this code is to *test* the behavior of `WebFrame` related functionalities within the Chromium Blink engine.

2. **Analyze Each Test Case:**  Go through each `TEST_F` individually to understand what specific aspect of `WebFrame` is being tested.

    * `ReloadPreservesState`: Tests whether reloading a page preserves its scroll position and zoom level. This is directly related to user experience when interacting with web pages.

    * `ReloadWhileProvisional`: Examines the behavior when a reload is initiated while the initial page load is still in progress. This is a more nuanced scenario concerning the lifecycle of page loading.

    * `ClearFocusedNodeTest`: Checks if explicitly blurring a focused element correctly clears the focused node state. This relates to how user interaction (like clicking away) and JavaScript can affect focus.

    * `TabKeyCursorMoveTriggersOneSelectionChange`:  Verifies that pressing the Tab key to move between focusable elements triggers the expected number of selection change events. This is directly tied to keyboard navigation and accessibility.

    * `ContextNotificationsLoadUnload`:  Focuses on the notifications emitted when JavaScript contexts are created and destroyed during page load and unload (including iframes). This is related to the JavaScript execution environment.

    * `ContextNotificationsReload`:  Similar to the previous test but for page reloads, ensuring proper context creation and destruction during the reload process.

    * `ContextNotificationsIsolatedWorlds`: Tests context creation and destruction for JavaScript running in isolated worlds (used for extensions and content scripts).

    * `FindInPage`:  Covers various scenarios of the "find in page" functionality, including searching in different HTML elements (div, input, textarea, contentEditable) and verifying the selection and focus after finding.

    * `GetContentAsPlainText`: Checks the functionality that extracts the plain text content of a web page, including cases with iframes and length limitations. This is often used for accessibility or data extraction.

    * `GetFullHtmlOfPage`: Tests the ability to get the complete HTML source code of a page and verifies that reloading with this source maintains the same content. It also touches on selection manipulation.

    * `ExecuteScriptDuringDidCreateScriptContext`:  Tests if executing JavaScript within the `DidCreateScriptContext` callback works correctly. This tests specific timing and execution order within the rendering engine.

    * `FindInPageMatchRects` (Android Specific):  Verifies the retrieval and interaction with the bounding boxes of "find in page" matches, specific to Android.

    * `FindInPageActiveIndex`: Checks if the active match index is correctly updated during "find in page."

    * `FindOnDetachedFrame`:  Tests "find in page" when a frame is detached from the document.

    * `FindDetachFrameBeforeScopeStrings`: Tests a specific sequence of events where a frame is detached during the "find in page" process.

3. **Identify Relationships with Web Technologies:**  For each test case, explicitly link it to JavaScript, HTML, or CSS if applicable.

    * **JavaScript:** Context creation/destruction, executing scripts, focus manipulation, selection changes, "find in page" functionality often interacted with via JavaScript APIs.
    * **HTML:**  The structure of the page being tested (iframes, input fields, text areas, divs, etc.), how elements are rendered and their content.
    * **CSS:**  While not explicitly tested for styling in this snippet, the `ReloadPreservesState` test touches on how page scale (influenced by CSS and viewport) is handled. The `FindInPageMatchRects` test indirectly involves layout, which CSS affects.

4. **Construct Hypothetical Input/Output:** For tests involving logical reasoning (like `ReloadPreservesState` or `TabKeyCursorMoveTriggersOneSelectionChange`), create simple input scenarios and their expected output based on the test's purpose.

5. **Identify Potential User/Programming Errors:**  Think about what mistakes a developer or user might make that these tests help to prevent. For example, forgetting to reset scroll state on navigation or assuming state is preserved on reload when it shouldn't be.

6. **Synthesize the Overall Function:** Combine the individual test case analyses into a cohesive summary of the file's purpose.

7. **Contextualize within the Series:**  Acknowledge that this is part 7 of 19, suggesting it covers a specific subset of `WebFrame` functionality and likely builds upon concepts from earlier parts and prepares for later ones. The placement within the series might imply a focus on frame lifecycle, navigation, and basic user interactions.

8. **Refine and Organize:** Structure the answer clearly with headings and bullet points for readability. Ensure the language is precise and avoids jargon where possible while still being technically accurate.

**Self-Correction/Refinement During Thought Process:**

* Initially, I might have just listed the tests. However, the prompt specifically asks for *functionality*. Therefore, I needed to rephrase the test names into descriptions of the features being tested.
* I considered whether to include very low-level implementation details. The prompt seems to target a higher-level understanding, so focusing on the *what* and *why* rather than the *how* seemed more appropriate.
* I made sure to explicitly tie the tests back to the core web technologies (HTML, CSS, JavaScript) as requested.
* I reviewed the prompt carefully to ensure all parts of the request were addressed, including the specific format for input/output examples and common errors.
这个文件 `web_frame_test.cc` 是 Chromium Blink 引擎中用于测试 `WebFrame` 及其相关功能的单元测试文件。作为第 7 部分（共 19 部分），它很可能专注于 `WebFrame` 中与 **页面加载、导航、用户交互、JavaScript 上下文生命周期以及页面查找功能** 相关的特定方面。

以下是该代码片段中涉及的功能的详细列举和说明：

**主要功能归纳：**

* **页面重载行为测试:**  测试页面重载时状态的保持与重置，以及在 provisional 状态下重载的行为。
* **焦点管理测试:** 测试清除焦点节点的功能。
* **用户交互事件测试:** 测试 Tab 键移动光标时是否触发了预期的选择变化事件。
* **JavaScript 上下文生命周期管理测试:** 测试 JavaScript 上下文的创建和销毁通知机制，包括页面加载、卸载、重载以及隔离的 JavaScript 世界。
* **页面查找功能测试:**  测试在不同类型的 HTML 元素（如 `div`, `input`, `textarea`, 可编辑元素）中进行查找的功能，以及查找结果的选取和高亮。
* **获取页面内容测试:** 测试获取页面纯文本内容和完整 HTML 内容的功能。
* **在 JavaScript 上下文创建时执行脚本测试:** 测试在 `DidCreateScriptContext` 回调中执行 JavaScript 代码的能力。
* **页面查找客户端交互测试:** 测试 `FindInPageClient` 接口的交互，例如接收匹配数量和激活匹配的信息。
* **特定平台的页面查找测试 (Android):**  针对 Android 平台测试页面查找匹配区域的功能。
* **在分离的 Frame 上执行查找测试:** 测试当一个 Frame 从文档中分离后，查找功能是否还能正常工作。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **JavaScript 上下文生命周期:**
   * **关系:**  `DidCreateScriptContext` 和 `WillReleaseScriptContext` 这两个回调直接关联到 JavaScript 执行环境的生命周期。
   * **举例:** 当浏览器加载一个包含 `<script>` 标签的 HTML 页面时，会创建对应的 JavaScript 上下文。`DidCreateScriptContext` 会被调用，并提供新创建的 `v8::Context` 对象。当页面卸载或重载时，`WillReleaseScriptContext` 会被调用。

2. **用户交互事件 (Tab 键移动光标):**
   * **关系:**  `TabKeyCursorMoveTriggersOneSelectionChange` 测试模拟了用户按下 Tab 键的操作，这会触发浏览器对焦点和选择的更新。
   * **举例:**  HTML 中有多个 `<input>` 元素，当用户按下 Tab 键时，焦点会从一个输入框移动到下一个，这可能会导致文本选择的变化。测试验证了 `DidChangeSelection` 回调被调用的次数是否符合预期。

3. **页面重载行为:**
   * **关系:** 页面重载是浏览器的一个核心功能，涉及到如何重新请求和渲染 HTML, CSS, 和 JavaScript 资源。
   * **举例:**  `ReloadPreservesState` 测试验证了在重载后，页面的滚动位置和缩放比例是否被正确重置，这关系到用户体验和页面的状态管理。

4. **焦点管理:**
   * **关系:** 焦点是 HTML 文档中当前接收键盘输入的元素。JavaScript 可以通过 `focus()` 和 `blur()` 方法来控制元素的焦点。
   * **举例:** `ClearFocusedNodeTest` 测试通过 JavaScript 代码 `web_view_helper.GetWebView()->FocusedElement()->blur();` 显式地移除焦点，然后验证 `web_view_helper.GetWebView()->FocusedElement()` 是否返回空指针。

5. **页面查找功能:**
   * **关系:**  "查找"功能允许用户在页面中搜索特定的文本。这涉及到对 HTML 内容的解析和匹配，以及对匹配结果的标记和导航。通常，浏览器会高亮匹配的文本，并允许用户跳转到下一个或上一个匹配项。
   * **举例:** `FindInPage` 测试了在不同 HTML 元素（如 `<div>`, `<input>`, `<textarea>`）中查找文本，并验证了查找到的文本是否被正确选中，以及焦点是否移动到了相关的可编辑元素。

6. **获取页面内容:**
   * **关系:**  获取页面的纯文本或 HTML 内容涉及到对 DOM 树的遍历和序列化。这对于辅助功能、爬虫或者开发者工具等场景非常重要。
   * **举例:** `GetContentAsPlainText` 测试了将页面内容提取为纯文本的功能，这可以用于分析页面的文本内容，而忽略 HTML 标签和样式。`GetFullHtmlOfPage` 测试了获取页面完整 HTML 源代码的功能。

**逻辑推理、假设输入与输出：**

* **`ReloadPreservesState` 测试:**
    * **假设输入:** 加载一个 200x300 像素的页面，设置页面缩放比例为 1.1684，滚动偏移为 (30, 25)。执行页面重载。
    * **预期输出:** 重载后的页面滚动偏移为 (0, 0)，页面缩放比例为 1.0。 这是因为 `ClearScrollStateOnCommitWebFrameClient` 明确在提交导航时重置了滚动和缩放状态。

* **`TabKeyCursorMoveTriggersOneSelectionChange` 测试:**
    * **假设输入:** 一个包含多个 `<input type="text">`, `<input type="number">`, `<div contenteditable="true">` 和普通 `<div>` 元素的 HTML 页面。焦点初始在第一个文本输入框。模拟按下 Tab 键。
    * **预期输出:** 每当焦点移动到可编辑元素（文本输入框、数字输入框、可编辑 div）时，`DidChangeSelection` 回调会被调用一次。当焦点移动到不可编辑的 div 时，`DidChangeSelection` 不会被调用。

**用户或编程常见的使用错误举例：**

* **`ReloadPreservesState` 相关:** 开发者可能会错误地认为页面重载会保留所有客户端状态（例如滚动位置），但实际上，默认行为是会重置一些状态。这个测试帮助验证了 Blink 引擎的默认行为是重置滚动和缩放状态的。开发者如果需要保留这些状态，需要采取额外的措施，例如使用 `history.pushState` 或 `sessionStorage`。
* **`ClearFocusedNodeTest` 相关:**  在某些 JavaScript 代码中，可能会错误地假设焦点会因为某些操作自动丢失，但实际上可能需要显式地调用 `blur()` 方法。这个测试验证了显式调用 `blur()` 的效果。
* **`FindInPage` 相关:**  开发者可能会错误地认为在所有类型的 HTML 元素中都能进行查找，或者对查找结果的选取和焦点移动行为有错误的预期。这个测试覆盖了多种 HTML 元素，帮助理解查找功能的限制和行为。

**作为第 7 部分的功能归纳：**

作为 `web_frame_test.cc` 系列的第 7 部分，这个代码片段主要关注 `WebFrame` 在 **导航和页面加载过程中的行为、用户交互的基本响应（如 Tab 键），以及 JavaScript 上下文的管理和页面内容提取能力**。它构建在前面部分可能已经测试过的 `WebFrame` 基础功能之上，并为后续部分可能涉及的更复杂的功能（例如渲染、布局、事件处理等）奠定基础。 这部分测试着重于确保 `WebFrame` 能够正确地管理其生命周期，响应用户的基本操作，并提供必要的信息提取能力。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第7部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
itWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidCommitNavigation(
      WebHistoryCommitType commit_type,
      bool should_reset_browser_interface_broker,
      const ParsedPermissionsPolicy& permissions_policy_header,
      const DocumentPolicyFeatureState& document_policy_header) override {
    Frame()->View()->ResetScrollAndScaleState();
  }
};

TEST_F(WebFrameTest, ReloadPreservesState) {
  const std::string url = "200-by-300.html";
  const float kPageScaleFactor = 1.1684f;
  const int kPageWidth = 120;
  const int kPageHeight = 100;

  RegisterMockedHttpURLLoad(url);

  ClearScrollStateOnCommitWebFrameClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + url, &client);
  web_view_helper.Resize(gfx::Size(kPageWidth, kPageHeight));
  web_view_helper.LocalMainFrame()->SetScrollOffset(
      gfx::PointF(kPageWidth / 4, kPageHeight / 4));
  web_view_helper.GetWebView()->SetPageScaleFactor(kPageScaleFactor);

  // Reload the page and end up at the same url. State should not be propagated.
  web_view_helper.GetWebView()->MainFrameImpl()->StartReload(
      WebFrameLoadType::kReload);
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.LocalMainFrame());
  EXPECT_EQ(gfx::PointF(), web_view_helper.LocalMainFrame()->GetScrollOffset());
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, ReloadWhileProvisional) {
  // Test that reloading while the previous load is still pending does not cause
  // the initial request to get lost.
  RegisterMockedHttpURLLoad("fixed_layout.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  FrameLoadRequest frame_load_request(
      nullptr, ResourceRequest(ToKURL(base_url_ + "fixed_layout.html")));
  main_frame->GetFrame()->Loader().StartNavigation(frame_load_request);
  // start reload before first request is delivered.
  frame_test_helpers::ReloadFrameBypassingCache(
      web_view_helper.GetWebView()->MainFrameImpl());

  WebDocumentLoader* document_loader =
      web_view_helper.LocalMainFrame()->GetDocumentLoader();
  ASSERT_TRUE(document_loader);
  EXPECT_EQ(ToKURL(base_url_ + "fixed_layout.html"),
            KURL(document_loader->GetUrl()));
}

TEST_F(WebFrameTest, ClearFocusedNodeTest) {
  RegisterMockedHttpURLLoad("iframe_clear_focused_node_test.html");
  RegisterMockedHttpURLLoad("autofocus_input_field_iframe.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ +
                                    "iframe_clear_focused_node_test.html");

  // Clear the focused node.
  web_view_helper.GetWebView()->FocusedElement()->blur();

  // Now retrieve the FocusedNode and test it should be null.
  EXPECT_EQ(nullptr, web_view_helper.GetWebView()->FocusedElement());
}

class ChangedSelectionCounter : public frame_test_helpers::TestWebFrameClient {
 public:
  ChangedSelectionCounter() : call_count_(0) {}
  void DidChangeSelection(bool isSelectionEmpty,
                          blink::SyncCondition force_sync) override {
    ++call_count_;
  }
  int Count() const { return call_count_; }
  void Reset() { call_count_ = 0; }

 private:
  int call_count_;
};

TEST_F(WebFrameTest, TabKeyCursorMoveTriggersOneSelectionChange) {
  ChangedSelectionCounter counter;
  frame_test_helpers::WebViewHelper web_view_helper;
  RegisterMockedHttpURLLoad("editable_elements.html");
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "editable_elements.html", &counter);

  WebKeyboardEvent tab_down(WebInputEvent::Type::kKeyDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());
  WebKeyboardEvent tab_up(WebInputEvent::Type::kKeyUp,
                          WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests());
  tab_down.dom_key = ui::DomKey::TAB;
  tab_up.dom_key = ui::DomKey::TAB;
  tab_down.windows_key_code = VKEY_TAB;
  tab_up.windows_key_code = VKEY_TAB;

  // Move to the next text-field: 1 cursor change.
  counter.Reset();
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_down, ui::LatencyInfo()));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_up, ui::LatencyInfo()));
  EXPECT_EQ(1, counter.Count());

  // Move to another text-field: 1 cursor change.
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_down, ui::LatencyInfo()));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_up, ui::LatencyInfo()));
  EXPECT_EQ(2, counter.Count());

  // Move to a number-field: 1 cursor change.
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_down, ui::LatencyInfo()));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_up, ui::LatencyInfo()));
  EXPECT_EQ(3, counter.Count());

  // Move to an editable element: 1 cursor change.
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_down, ui::LatencyInfo()));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_up, ui::LatencyInfo()));
  EXPECT_EQ(4, counter.Count());

  // Move to a non-editable element: 0 cursor changes.
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_down, ui::LatencyInfo()));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(tab_up, ui::LatencyInfo()));
  EXPECT_EQ(4, counter.Count());
}

// Implementation of WebLocalFrameClient that tracks the v8 contexts that are
// created and destroyed for verification.
class ContextLifetimeTestWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  struct Notification {
   public:
    Notification(WebLocalFrame* frame,
                 v8::Local<v8::Context> context,
                 int32_t world_id)
        : frame(frame),
          context(context->GetIsolate(), context),
          world_id(world_id) {}

    ~Notification() { context.Reset(); }

    bool Equals(Notification* other) {
      return other && frame == other->frame && context == other->context &&
             world_id == other->world_id;
    }

    WebLocalFrame* frame;
    v8::Persistent<v8::Context> context;
    int32_t world_id;
  };

  ContextLifetimeTestWebFrameClient(
      Vector<std::unique_ptr<Notification>>& create_notifications,
      Vector<std::unique_ptr<Notification>>& release_notifications)
      : create_notifications_(create_notifications),
        release_notifications_(release_notifications) {}
  ~ContextLifetimeTestWebFrameClient() override = default;

  void Reset() {
    create_notifications_.clear();
    release_notifications_.clear();
  }

  // WebLocalFrameClient:
  WebLocalFrame* CreateChildFrame(
      mojom::blink::TreeScopeType scope,
      const WebString& name,
      const WebString& fallback_name,
      const FramePolicy&,
      const WebFrameOwnerProperties&,
      FrameOwnerElementType,
      WebPolicyContainerBindParams policy_container_bind_params,
      ukm::SourceId document_ukm_source_id,
      FinishChildFrameCreationFn finish_creation) override {
    return CreateLocalChild(*Frame(), scope,
                            std::make_unique<ContextLifetimeTestWebFrameClient>(
                                create_notifications_, release_notifications_),
                            std::move(policy_container_bind_params),
                            finish_creation);
  }

  void DidCreateScriptContext(v8::Local<v8::Context> context,
                              int32_t world_id) override {
    create_notifications_.push_back(
        std::make_unique<Notification>(Frame(), context, world_id));
  }

  void WillReleaseScriptContext(v8::Local<v8::Context> context,
                                int32_t world_id) override {
    release_notifications_.push_back(
        std::make_unique<Notification>(Frame(), context, world_id));
  }

 private:
  Vector<std::unique_ptr<Notification>>& create_notifications_;
  Vector<std::unique_ptr<Notification>>& release_notifications_;
};

TEST_F(WebFrameTest, ContextNotificationsLoadUnload) {
  RegisterMockedHttpURLLoad("context_notifications_test.html");
  RegisterMockedHttpURLLoad("context_notifications_test_frame.html");

  // Load a frame with an iframe, make sure we get the right create
  // notifications.
  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      create_notifications;
  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      release_notifications;
  ContextLifetimeTestWebFrameClient web_frame_client(create_notifications,
                                                     release_notifications);
  frame_test_helpers::WebViewHelper web_view_helper;
  v8::HandleScope handle_scope(
      web_view_helper.GetAgentGroupScheduler().Isolate());
  web_view_helper.InitializeAndLoad(
      base_url_ + "context_notifications_test.html", &web_frame_client);

  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  WebFrame* child_frame = main_frame->FirstChild();

  ASSERT_EQ(2u, create_notifications.size());
  EXPECT_EQ(0u, release_notifications.size());

  auto& first_create_notification = create_notifications[0];
  auto& second_create_notification = create_notifications[1];

  EXPECT_EQ(main_frame, first_create_notification->frame);
  EXPECT_EQ(main_frame->MainWorldScriptContext(),
            first_create_notification->context);
  EXPECT_EQ(0, first_create_notification->world_id);

  EXPECT_EQ(child_frame, second_create_notification->frame);
  EXPECT_EQ(child_frame->ToWebLocalFrame()->MainWorldScriptContext(),
            second_create_notification->context);
  EXPECT_EQ(0, second_create_notification->world_id);

  // Close the view. We should get two release notifications that are exactly
  // the same as the create ones, in reverse order.
  web_view_helper.Reset();

  ASSERT_EQ(2u, release_notifications.size());
  auto& first_release_notification = release_notifications[0];
  auto& second_release_notification = release_notifications[1];

  ASSERT_TRUE(
      first_create_notification->Equals(second_release_notification.get()));
  ASSERT_TRUE(
      second_create_notification->Equals(first_release_notification.get()));
}

TEST_F(WebFrameTest, ContextNotificationsReload) {
  RegisterMockedHttpURLLoad("context_notifications_test.html");
  RegisterMockedHttpURLLoad("context_notifications_test_frame.html");

  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      create_notifications;
  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      release_notifications;
  ContextLifetimeTestWebFrameClient web_frame_client(create_notifications,
                                                     release_notifications);
  frame_test_helpers::WebViewHelper web_view_helper;
  v8::HandleScope handle_scope(
      web_view_helper.GetAgentGroupScheduler().Isolate());
  web_view_helper.InitializeAndLoad(
      base_url_ + "context_notifications_test.html", &web_frame_client);

  // Refresh, we should get two release notifications and two more create
  // notifications.
  frame_test_helpers::ReloadFrame(
      web_view_helper.GetWebView()->MainFrameImpl());
  ASSERT_EQ(4u, create_notifications.size());
  ASSERT_EQ(2u, release_notifications.size());

  // The two release notifications we got should be exactly the same as the
  // first two create notifications.
  for (wtf_size_t i = 0; i < release_notifications.size(); ++i) {
    EXPECT_TRUE(release_notifications[i]->Equals(
        create_notifications[create_notifications.size() - 3 - i].get()));
  }

  // The last two create notifications should be for the current frames and
  // context.
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  WebFrame* child_frame = main_frame->FirstChild();
  auto& first_refresh_notification = create_notifications[2];
  auto& second_refresh_notification = create_notifications[3];

  EXPECT_EQ(main_frame, first_refresh_notification->frame);
  EXPECT_EQ(main_frame->MainWorldScriptContext(),
            first_refresh_notification->context);
  EXPECT_EQ(0, first_refresh_notification->world_id);

  EXPECT_EQ(child_frame, second_refresh_notification->frame);
  EXPECT_EQ(child_frame->ToWebLocalFrame()->MainWorldScriptContext(),
            second_refresh_notification->context);
  EXPECT_EQ(0, second_refresh_notification->world_id);
}

TEST_F(WebFrameTest, ContextNotificationsIsolatedWorlds) {
  RegisterMockedHttpURLLoad("context_notifications_test.html");
  RegisterMockedHttpURLLoad("context_notifications_test_frame.html");

  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      create_notifications;
  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      release_notifications;
  ContextLifetimeTestWebFrameClient web_frame_client(create_notifications,
                                                     release_notifications);
  frame_test_helpers::WebViewHelper web_view_helper;
  v8::Isolate* isolate = web_view_helper.GetAgentGroupScheduler().Isolate();
  v8::HandleScope handle_scope(isolate);
  web_view_helper.InitializeAndLoad(
      base_url_ + "context_notifications_test.html", &web_frame_client);

  // Add an isolated world.
  web_frame_client.Reset();

  int32_t isolated_world_id = 42;
  WebScriptSource script_source("hi!");
  web_view_helper.LocalMainFrame()->ExecuteScriptInIsolatedWorld(
      isolated_world_id, script_source, BackForwardCacheAware::kAllow);

  // We should now have a new create notification.
  ASSERT_EQ(1u, create_notifications.size());
  auto& notification = create_notifications[0];
  ASSERT_EQ(isolated_world_id, notification->world_id);
  ASSERT_EQ(web_view_helper.GetWebView()->MainFrame(), notification->frame);

  // We don't have an API to enumarate isolated worlds for a frame, but we can
  // at least assert that the context we got is *not* the main world's context.
  ASSERT_NE(web_view_helper.LocalMainFrame()->MainWorldScriptContext(),
            v8::Local<v8::Context>::New(isolate, notification->context));

  // Check that the context we got has the right isolated world id.
  ASSERT_EQ(isolated_world_id,
            web_view_helper.LocalMainFrame()->GetScriptContextWorldId(
                v8::Local<v8::Context>::New(isolate, notification->context)));

  web_view_helper.Reset();

  // We should have gotten three release notifications (one for each of the
  // frames, plus one for the isolated context).
  ASSERT_EQ(3u, release_notifications.size());

  // And one of them should be exactly the same as the create notification for
  // the isolated context.
  int match_count = 0;
  for (wtf_size_t i = 0; i < release_notifications.size(); ++i) {
    if (release_notifications[i]->Equals(create_notifications[0].get()))
      ++match_count;
  }
  EXPECT_EQ(1, match_count);
}

TEST_F(WebFrameTest, FindInPage) {
  RegisterMockedHttpURLLoad("find.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find.html");
  ASSERT_TRUE(web_view_helper.LocalMainFrame());
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  const int kFindIdentifier = 12345;
  auto options = mojom::blink::FindOptions::New();

  // Find in a <div> element.
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, WebString::FromUTF8("bar1"), *options, false));
  frame->GetFindInPage()->StopFinding(
      blink::mojom::StopFindAction::kStopFindActionKeepSelection);
  WebRange range = frame->SelectionRange();
  EXPECT_EQ(5, range.StartOffset());
  EXPECT_EQ(9, range.EndOffset());
  EXPECT_TRUE(frame->GetDocument().FocusedElement().IsNull());

  // Find in an <input> value.
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, WebString::FromUTF8("bar2"), *options, false));
  // Confirm stopFinding(WebLocalFrame::StopFindActionKeepSelection) sets the
  // selection on the found text.
  frame->GetFindInPage()->StopFinding(
      blink::mojom::StopFindAction::kStopFindActionKeepSelection);
  range = frame->SelectionRange();
  ASSERT_FALSE(range.IsNull());
  EXPECT_EQ(5, range.StartOffset());
  EXPECT_EQ(9, range.EndOffset());
  EXPECT_TRUE(frame->GetDocument().FocusedElement().HasHTMLTagName("input"));

  // Find in a <textarea> content.
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, WebString::FromUTF8("bar3"), *options, false));
  // Confirm stopFinding(WebLocalFrame::StopFindActionKeepSelection) sets the
  // selection on the found text.
  frame->GetFindInPage()->StopFinding(
      blink::mojom::StopFindAction::kStopFindActionKeepSelection);
  range = frame->SelectionRange();
  ASSERT_FALSE(range.IsNull());
  EXPECT_EQ(5, range.StartOffset());
  EXPECT_EQ(9, range.EndOffset());
  EXPECT_TRUE(frame->GetDocument().FocusedElement().HasHTMLTagName("textarea"));

  // Find in a contentEditable element.
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, WebString::FromUTF8("bar4"), *options, false));
  // Confirm stopFinding(WebLocalFrame::StopFindActionKeepSelection) sets the
  // selection on the found text.
  frame->GetFindInPage()->StopFinding(
      blink::mojom::StopFindAction::kStopFindActionKeepSelection);
  range = frame->SelectionRange();
  ASSERT_FALSE(range.IsNull());
  EXPECT_EQ(0, range.StartOffset());
  EXPECT_EQ(4, range.EndOffset());
  // "bar4" is surrounded by <span>, but the focusable node should be the parent
  // <div>.
  EXPECT_TRUE(frame->GetDocument().FocusedElement().HasHTMLTagName("div"));

  // Find in <select> content.
  EXPECT_FALSE(frame->GetFindInPage()->FindInternal(
      kFindIdentifier, WebString::FromUTF8("bar5"), *options, false));
  // If there are any matches, stopFinding will set the selection on the found
  // text.  However, we do not expect any matches, so check that the selection
  // is null.
  frame->GetFindInPage()->StopFinding(
      blink::mojom::StopFindAction::kStopFindActionKeepSelection);
  range = frame->SelectionRange();
  ASSERT_TRUE(range.IsNull());
}

TEST_F(WebFrameTest, GetContentAsPlainText) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  // We set the size because it impacts line wrapping, which changes the
  // resulting text value.
  web_view_helper.Resize(gfx::Size(640, 480));
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // Generate a simple test case.
  const char kSimpleSource[] = "<div>Foo bar</div><div></div>baz";
  KURL test_url = ToKURL("about:blank");
  frame_test_helpers::LoadHTMLString(frame, kSimpleSource, test_url);

  // Make sure it comes out OK.
  const std::string expected("Foo bar\nbaz");
  WebString text = TestWebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ(expected, text.Utf8());

  // Try reading the same one with clipping of the text.
  const int kLength = 5;
  text = TestWebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), kLength);
  EXPECT_EQ(expected.substr(0, kLength), text.Utf8());

  // Now do a new test with a subframe.
  const char kOuterFrameSource[] = "Hello<iframe></iframe> world";
  frame_test_helpers::LoadHTMLString(frame, kOuterFrameSource, test_url);

  // Load something into the subframe.
  WebLocalFrame* subframe = frame->FirstChild()->ToWebLocalFrame();
  ASSERT_TRUE(subframe);
  frame_test_helpers::LoadHTMLString(subframe, "sub<p>text", test_url);

  text = TestWebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ("Hello world\n\nsub\n\ntext", text.Utf8());

  // Get the frame text where the subframe separator falls on the boundary of
  // what we'll take. There used to be a crash in this case.
  text = TestWebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), 12);
  EXPECT_EQ("Hello world", text.Utf8());
}

TEST_F(WebFrameTest, GetFullHtmlOfPage) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // Generate a simple test case.
  const char kSimpleSource[] = "<p>Hello</p><p>World</p>";
  KURL test_url = ToKURL("about:blank");
  frame_test_helpers::LoadHTMLString(frame, kSimpleSource, test_url);

  WebString text = TestWebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ("Hello\n\nWorld", text.Utf8());

  const std::string html =
      TestWebFrameContentDumper::DumpAsMarkup(frame).Utf8();

  // Load again with the output html.
  frame_test_helpers::LoadHTMLString(frame, html, test_url);

  EXPECT_EQ(html, TestWebFrameContentDumper::DumpAsMarkup(frame).Utf8());

  text = TestWebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ("Hello\n\nWorld", text.Utf8());

  // Test selection check
  EXPECT_FALSE(frame->HasSelection());
  frame->ExecuteCommand(WebString::FromUTF8("SelectAll"));
  EXPECT_TRUE(frame->HasSelection());
  frame->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_FALSE(frame->HasSelection());
  WebString selection_html = frame->SelectionAsMarkup();
  EXPECT_TRUE(selection_html.IsEmpty());
}

class TestExecuteScriptDuringDidCreateScriptContext
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestExecuteScriptDuringDidCreateScriptContext() = default;
  ~TestExecuteScriptDuringDidCreateScriptContext() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidCreateScriptContext(v8::Local<v8::Context> context,
                              int32_t world_id) override {
    Frame()->ExecuteScript(WebScriptSource("window.history = 'replaced';"));
  }
};

TEST_F(WebFrameTest, ExecuteScriptDuringDidCreateScriptContext) {
  RegisterMockedHttpURLLoad("hello_world.html");

  TestExecuteScriptDuringDidCreateScriptContext web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "hello_world.html",
                                    &web_frame_client);

  frame_test_helpers::ReloadFrame(
      web_view_helper.GetWebView()->MainFrameImpl());
}

class TestFindInPageClient : public mojom::blink::FindInPageClient {
 public:
  TestFindInPageClient()
      : find_results_are_ready_(false), count_(-1), active_index_(-1) {}

  ~TestFindInPageClient() override = default;

  void SetFrame(WebLocalFrameImpl* frame) {
    frame->GetFindInPage()->SetClient(receiver_.BindNewPipeAndPassRemote());
  }

  void SetNumberOfMatches(
      int request_id,
      unsigned int current_number_of_matches,
      mojom::blink::FindMatchUpdateType final_update) final {
    count_ = current_number_of_matches;
    find_results_are_ready_ =
        (final_update == mojom::blink::FindMatchUpdateType::kFinalUpdate);
  }

  void SetActiveMatch(int request_id,
                      const gfx::Rect& active_match_rect,
                      int active_match_ordinal,
                      mojom::blink::FindMatchUpdateType final_update) final {
    active_index_ = active_match_ordinal;
    find_results_are_ready_ =
        (final_update == mojom::blink::FindMatchUpdateType::kFinalUpdate);
  }

  bool FindResultsAreReady() const { return find_results_are_ready_; }
  int Count() const { return count_; }
  int ActiveIndex() const { return active_index_; }

 private:
  bool find_results_are_ready_;
  int count_;
  int active_index_;
  mojo::Receiver<mojom::blink::FindInPageClient> receiver_{this};
};

#if BUILDFLAG(IS_ANDROID)
TEST_F(WebFrameTest, FindInPageMatchRects) {
  RegisterMockedHttpURLLoad("find_in_page_frame.html");

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_page_frame.html",
                                    &frame_client);
  web_view_helper.Resize(gfx::Size(640, 480));
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  RunPendingTasks();

  // Note that the 'result 19' in the <select> element is not expected to
  // produce a match. Also, results 00 and 01 are in a different frame that is
  // not included in this test.
  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;
  const int kNumResults = 17;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(main_frame);
  EXPECT_TRUE(main_frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false));

  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, *options);
  }
  RunPendingTasks();
  EXPECT_TRUE(find_in_page_client.FindResultsAreReady());

  WebVector<gfx::RectF> web_match_rects =
      main_frame->EnsureTextFinder().FindMatchRects();
  ASSERT_EQ(static_cast<size_t>(kNumResults), web_match_rects.size());
  int rects_version = main_frame->GetFindInPage()->FindMatchMarkersVersion();

  for (int result_index = 0; result_index < kNumResults; ++result_index) {
    const gfx::RectF& result_rect = web_match_rects[result_index];

    // Select the match by the center of its rect.
    EXPECT_EQ(main_frame->EnsureTextFinder().SelectNearestFindMatch(
                  result_rect.CenterPoint(), nullptr),
              result_index + 1);

    // Check that the find result ordering matches with our expectations.
    Range* result = main_frame->GetTextFinder()->ActiveMatch();
    ASSERT_TRUE(result);
    result->setEnd(result->endContainer(), result->endOffset() + 3);
    EXPECT_EQ(result->GetText(),
              String::Format("%s %02d", kFindString, result_index + 2));

    // Verify that the expected match rect also matches the currently active
    // match.  Compare the enclosing rects to prevent precision issues caused by
    // CSS transforms.
    gfx::RectF active_match =
        main_frame->GetFindInPage()->ActiveFindMatchRect();
    EXPECT_EQ(gfx::ToEnclosingRect(active_match),
              gfx::ToEnclosingRect(result_rect));

    // The rects version should not have changed.
    EXPECT_EQ(main_frame->GetFindInPage()->FindMatchMarkersVersion(),
              rects_version);
  }

  // Resizing should update the rects version.
  web_view_helper.Resize(gfx::Size(800, 600));
  RunPendingTasks();
  EXPECT_TRUE(main_frame->GetFindInPage()->FindMatchMarkersVersion() !=
              rects_version);
}
#endif  // BUILDFLAG(IS_ANDROID)

TEST_F(WebFrameTest, FindInPageActiveIndex) {
  RegisterMockedHttpURLLoad("find_match_count.html");

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_match_count.html",
                                    &frame_client);
  web_view_helper.GetWebView()->MainFrameViewWidget()->Resize(
      gfx::Size(640, 480));
  RunPendingTasks();

  const char* kFindString = "a";
  const int kFindIdentifier = 7777;
  const int kActiveIndex = 1;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(main_frame);

  EXPECT_TRUE(main_frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false));
  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, *options);
  }
  RunPendingTasks();

  EXPECT_TRUE(main_frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false));
  main_frame->GetFindInPage()->StopFinding(
      mojom::StopFindAction::kStopFindActionClearSelection);

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, *options);
  }

  RunPendingTasks();
  EXPECT_TRUE(find_in_page_client.FindResultsAreReady());
  EXPECT_EQ(kActiveIndex, find_in_page_client.ActiveIndex());

  const char* kFindStringNew = "e";
  WebString search_text_new = WebString::FromUTF8(kFindStringNew);

  EXPECT_TRUE(main_frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text_new, *options, false));
  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(
        kFindIdentifier, search_text_new, *options);
  }

  RunPendingTasks();
  EXPECT_TRUE(find_in_page_client.FindResultsAreReady());
  EXPECT_EQ(kActiveIndex, find_in_page_client.ActiveIndex());
}

TEST_F(WebFrameTest, FindOnDetachedFrame) {
  RegisterMockedHttpURLLoad("find_in_page.html");
  RegisterMockedHttpURLLoad("find_in_page_frame.html");

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_page.html",
                                    &frame_client);
  web_view_helper.Resize(gfx::Size(640, 480));
  RunPendingTasks();

  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  TestFindInPageClient main_find_in_page_client;
  main_find_in_page_client.SetFrame(main_frame);

  auto* second_frame = To<WebLocalFrameImpl>(main_frame->TraverseNext());

  // Detach the frame before finding.
  RemoveElementById(main_frame, AtomicString("frame"));

  EXPECT_TRUE(main_frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false));
  EXPECT_FALSE(second_frame->GetFindInPage()->FindInternal(
      kFindIdentifier, search_text, *options, false));

  RunPendingTasks();
  EXPECT_FALSE(main_find_in_page_client.FindResultsAreReady());

  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, *options);
  }

  RunPendingTasks();
  EXPECT_TRUE(main_find_in_page_client.FindResultsAreReady());
}

TEST_F(WebFrameTest, FindDetachFrameBeforeScopeStrings) {
  RegisterMockedHttpURLLoad("find_in_page.html");
  RegisterMockedHttpURLLoad("find_in_page_frame.html");

  frame_test_helpers::TestWebFrameClient frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_page.html",
                                    &frame_client);
  web_view_helper.Resize(gfx::Size(640, 480));
  RunPendingTasks();

  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;

  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  TestFindInPageClient find_in_page_client;
  find_in_page_client.SetFrame(main_frame);

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = To<WebLocalFrameImpl>(frame->TraverseNext())) {
    EXPECT_TRUE(frame->GetFindInPage()-
```