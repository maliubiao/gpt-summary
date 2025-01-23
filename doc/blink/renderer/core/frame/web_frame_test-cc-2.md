Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_frame_test.cc`. This involves identifying the main features being tested and how they relate to web technologies like JavaScript, HTML, and CSS. I need to look for `TEST_F` blocks and analyze what each test is verifying. Specifically, I should pay attention to actions performed within the tests (like loading HTML, executing JavaScript, manipulating CSS) and the assertions made afterwards.

Here's a breakdown of the identified test cases and their functionalities:

1. **`WebFrameCSSCallbackTest, DisplayContents`**: Tests how the `WatchCSSSelectors` API interacts with elements having `display: contents`. It checks if the callback is triggered correctly when elements match the selector, even within `display: contents` trees, and when the `display` property changes.

2. **`WebFrameCSSCallbackTest, Reparenting`**: Verifies that moving a DOM element that matches a watched CSS selector doesn't trigger unnecessary callbacks if the element still matches after the move.

3. **`WebFrameCSSCallbackTest, MultiSelector`**: Checks that `WatchCSSSelectors` treats a comma-separated list of selectors as a single entity, reporting the entire matching selector string.

4. **`WebFrameCSSCallbackTest, InvalidSelector`**: Ensures that an invalid CSS selector in the watched list doesn't prevent valid selectors from being matched and reported.

5. **`WebFrameTest, PostMessageEvent`**: Tests the functionality of `PostMessageEvent`. It verifies that messages sent with the correct origin are received, while those with incorrect origins are ignored. This directly relates to JavaScript's `postMessage` API for cross-origin communication.

6. **`WebFrameTest, PostMessageThenDetach`**: Checks that posting a message to a frame and then detaching the frame doesn't cause a crash. This is a stability test related to the `postMessage` API.

7. **`WebFrameTest, PostMessageEvent_CannotDeserialize`**: Tests the scenario where a posted message cannot be deserialized. It verifies that a `messageerror` event is dispatched in this case, which is part of the JavaScript `postMessage` error handling mechanism.

8. **`WebFrameTest, ChangeInFixedLayoutResetsTextAutosizingMultipliers`**:  Focuses on the interaction between fixed layout viewports and text autosizing. It verifies that changing the fixed layout width resets the text autosizing multipliers to their default value (1). This relates to how the browser optimizes text rendering in fixed-width layouts.

9. **`WebFrameTest, WorkingTextAutosizingMultipliers_VirtualViewport`**: Checks if text autosizing multipliers are calculated correctly in a virtual viewport scenario, which is common on mobile devices.

10. **`WebFrameTest, VisualViewportSetSizeInvalidatesTextAutosizingMultipliers`**: Tests that changing the size of the visual viewport invalidates the layout, requiring recalculation of text autosizing multipliers.

11. **`WebFrameTest, ZeroHeightPositiveWidthNotIgnored`**: Ensures that setting the viewport height to zero while having a positive width is handled correctly and not ignored by the layout engine.

12. **`WebFrameTest, DeviceScaleFactorUsesDefaultWithoutViewportTag`**: Verifies that if a page doesn't have a viewport meta tag, the device scale factor is used as the default. This relates to how the browser scales content based on screen density.

13. **`WebFrameTest, FixedLayoutInitializeAtMinimumScale`**: Checks that when a page with a fixed layout loads, it initializes at the minimum allowed page scale, even if the window size is determined after the initial load.

14. **`WebFrameTest, WideDocumentInitializeAtMinimumScale`**: Similar to the previous test, but for documents wider than the viewport. It ensures the page initializes at the minimum scale to fit the content.

15. **`WebFrameTest, DelayedViewportInitialScale`**: Tests the scenario where the viewport's `initial-scale` is set after the initial page load. It verifies that the page scale factor is updated accordingly.

16. **`WebFrameTest, setLoadWithOverviewModeToFalse`**: Checks that setting `load-with-overview-mode` to `false` forces the page to load at 100% zoom. This relates to a browser setting that can affect initial zoom level.

17. **`WebFrameTest, SetLoadWithOverviewModeToFalseAndNoWideViewport`**: Verifies that even for pages with wide content, setting `load-with-overview-mode` to `false` and disabling the wide viewport quirk results in a 100% initial zoom.

18. **`WebFrameTest, NoWideViewportIgnoresPageViewportWidth`**: Ensures that when the wide viewport quirk is disabled, the `width` property in the viewport meta tag is ignored.

19. **`WebFrameTest, NoWideViewportIgnoresPageViewportWidthButAccountsScale`**:  Similar to the previous test, but confirms that while the viewport `width` is ignored, the `initial-scale` value is still respected when the wide viewport quirk is disabled.

20. **`WebFrameTest, WideViewportSetsTo980WithoutViewportTag`**: Checks that if a page lacks a viewport meta tag but the wide viewport quirk is enabled, the viewport width defaults to 980 pixels.

21. **`WebFrameTest, WideViewportSetsTo980WithXhtmlMp`**:  Verifies that the wide viewport quirk applies to XHTML Mobile Profile (xhtmlmp) documents as well.

22. **`WebFrameTest, NoWideViewportAndHeightInMeta`**:  Ensures that when the wide viewport quirk is disabled, a `height` property in the viewport meta tag is still respected.

23. **`WebFrameTest, WideViewportSetsTo980WithAutoWidth`**: Confirms that the wide viewport quirk sets the viewport width to 980 even when the viewport meta tag specifies `width=device-width` or `width=auto`.

24. **`WebFrameTest, PageViewportInitialScaleOverridesLoadWithOverviewMode`**: Tests that the `initial-scale` in the viewport meta tag takes precedence over the `load-with-overview-mode` setting.

25. **`WebFrameTest, setInitialPageScaleFactorPermanently`**:  Checks the functionality of setting a permanent initial page scale factor, which overrides other scaling mechanisms.

26. **`WebFrameTest, PermanentInitialPageScaleFactorOverridesLoadWithOverviewMode`**: Verifies that a permanently set initial page scale factor overrides the `load-with-overview-mode` setting.

27. **`WebFrameTest, PermanentInitialPageScaleFactorOverridesPageViewportInitialScale`**:  Ensures that a permanently set initial page scale factor overrides the `initial-scale` specified in the viewport meta tag.

28. **`WebFrameTest, SmallPermanentInitialPageScaleFactorIsClobbered`**: Tests a specific quirk where a small permanent initial page scale factor might be overridden under certain conditions, especially on pages with specific viewport configurations.
这是 `blink/renderer/core/frame/web_frame_test.cc` 文件的第 3 部分，共 19 部分。 从这部分的代码来看，主要关注以下功能：

**主要功能归纳:**

这部分代码主要测试了 `WebFrame` 的 CSS 选择器监听回调 (`WatchCSSSelectors`) 以及 `postMessage` 事件处理的相关功能，并深入测试了与页面缩放 (page scale) 和视口 (viewport) 配置相关的各种场景，特别是在 Android 环境下。

**具体功能及与 JavaScript, HTML, CSS 的关系:**

1. **CSS 选择器监听回调 (`WebFrameCSSCallbackTest`)**:
    *   **功能:**  测试 `Doc().WatchCSSSelectors()` 方法，该方法允许监听特定 CSS 选择器在页面上的匹配情况，并在匹配元素发生变化时触发回调。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **CSS:**  直接测试了 CSS 选择器的匹配机制，例如 `display: contents` 属性的影响。
        *   **JavaScript:**  通过 `ExecuteScript()` 执行 JavaScript 代码来动态修改 DOM 结构和 CSS 样式，从而触发或取消 CSS 选择器的匹配，并验证回调是否按预期执行。
        *   **HTML:**  通过 `LoadHTML()` 加载不同的 HTML 结构来测试不同场景下的选择器匹配。
    *   **假设输入与输出:**
        *   **假设输入:** 加载包含 `<span>` 元素的 HTML，并使用 `WatchCSSSelectors` 监听 `"span"` 选择器。
        *   **预期输出:** 初始化时回调会被触发一次，`UpdateCount()` 为 1，`MatchedSelectors()` 包含 `"span"`。
        *   **假设输入:**  执行 JavaScript 代码将 `<span>` 元素的父元素的 `display` 属性设置为 `none`。
        *   **预期输出:** 回调再次被触发，`UpdateCount()` 增加，`MatchedSelectors()` 为空。
    *   **用户或编程常见错误:**
        *   **错误:** 误以为 `WatchCSSSelectors` 会对每个单独的选择器独立触发回调，而实际上对于逗号分隔的选择器列表，会作为一个整体匹配。
        *   **示例:**  监听了 `"span"` 和 `"span, p"` 两个选择器，期望 `span` 元素的出现会触发两次回调，但实际只会触发一次，且 `MatchedSelectors()` 会同时包含这两个选择器字符串。
        *   **错误:**  在监听选择器时包含无效的 CSS 选择器，期望这会阻止其他有效选择器的匹配。
        *   **示例:** 监听了 `"span"` 和 `"["` (无效选择器)，期望由于无效选择器导致没有回调，但实际上 `"span"` 仍然会正常匹配并触发回调。

2. **`postMessage` 事件处理 (`WebFrameTest, PostMessageEvent`, `WebFrameTest, PostMessageThenDetach`, `WebFrameTest, PostMessageEvent_CannotDeserialize`)**:
    *   **功能:** 测试 `PostMessageEvent` 方法，该方法用于模拟跨文档消息传递。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **JavaScript:**  模拟了 JavaScript 的 `window.postMessage()` API 的行为。测试发送和接收跨域消息的能力，以及处理消息反序列化失败的情况。
        *   **HTML:**  加载 HTML 页面用于测试 `postMessage` 的接收方。
    *   **假设输入与输出:**
        *   **假设输入:**  发送一个源地址正确的 `postMessage`。
        *   **预期输出:** 接收页面的 JavaScript 代码能够处理该消息。
        *   **假设输入:**  发送一个源地址错误的 `postMessage`。
        *   **预期输出:** 接收页面的 JavaScript 代码不会处理该消息。
        *   **假设输入:**  尝试发送一个无法反序列化的消息。
        *   **预期输出:**  接收方会触发 `messageerror` 事件。
    *   **用户或编程常见错误:**
        *   **错误:**  不理解 `postMessage` 的源地址验证机制，导致跨域消息无法正常传递。
        *   **示例:**  从 `https://origin.com` 发送消息到目标页面，但目标页面只监听来自 `https://another-origin.com` 的消息，导致消息被忽略。

3. **文本自动缩放 (Text Autosizing) 相关测试 (`WebFrameTest, ChangeInFixedLayoutResetsTextAutosizingMultipliers`, `WebFrameTest, WorkingTextAutosizingMultipliers_VirtualViewport`, `WebFrameTest, VisualViewportSetSizeInvalidatesTextAutosizingMultipliers`)**:
    *   **功能:** 测试在不同视口配置下，文本自动缩放功能的行为，包括固定布局、虚拟视口以及视觉视口大小变化时的影响。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **CSS:**  涉及到 CSS 布局模型 (例如固定布局) 以及浏览器对文本大小的自动调整。
        *   **HTML:**  加载包含文本内容的 HTML 页面进行测试。
    *   **假设输入与输出:**
        *   **假设输入:**  加载一个固定宽度的页面，并设置一个非 1 的文本自动缩放倍数。然后修改固定宽度。
        *   **预期输出:** 文本自动缩放倍数会被重置为 1。

4. **视口 (Viewport) 和页面缩放 (Page Scale) 相关测试 (`WebFrameTest, ZeroHeightPositiveWidthNotIgnored` 到 `WebFrameTest, SmallPermanentInitialPageScaleFactorIsClobbered`)**:
    *   **功能:**  大量测试了在不同配置下，浏览器的视口行为和页面初始缩放的计算方式，尤其是在 Android 环境下。涵盖了以下方面：
        *   零高度视口的正确处理。
        *   设备像素比 (device scale factor) 的应用。
        *   固定布局和宽文档的初始缩放行为。
        *   延迟设置视口 `initial-scale` 的影响。
        *   `load-with-overview-mode` 设置的效果。
        *   `use-wide-viewport` 设置的影响。
        *   缺少 `viewport` meta 标签时的默认行为。
        *   `viewport` meta 标签中各种属性 (如 `width`, `initial-scale`) 的解析和应用。
        *   永久设置初始页面缩放因子的影响，以及它与其他视口设置的优先级关系。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **HTML:**  加载包含不同 `viewport` meta 标签的 HTML 页面，测试各种视口配置。
        *   **CSS:**  视口的配置直接影响页面的布局和渲染。
    *   **假设输入与输出:**  （这类测试有大量的排列组合，此处只举例说明）
        *   **假设输入:** 加载一个没有 `viewport` meta 标签的页面，并设置了设备像素比为 2。
        *   **预期输出:**  页面的设备像素比为 2。
        *   **假设输入:** 加载一个设置了 `initial-scale=2` 的页面，并且 `load-with-overview-mode` 设置为 `false`。
        *   **预期输出:** 页面初始缩放为 2 (`initial-scale` 优先级更高)。
        *   **假设输入:**  设置一个永久的初始页面缩放因子为 0.5，并加载一个 `initial-scale=1` 的页面。
        *   **预期输出:** 页面初始缩放为 0.5 (永久设置优先级更高)。
    *   **用户或编程常见错误:**
        *   **错误:**  不理解各种视口 meta 标签属性的含义和优先级，导致页面在不同设备上的显示效果不一致。
        *   **示例:**  错误地认为设置了 `width=device-width` 就一定能让页面以 100% 宽度显示在所有设备上，而忽略了 `initial-scale` 等其他属性的影响。
        *   **错误:**  在 Android WebView 中不理解 `load-with-overview-mode` 和 `use-wide-viewport` 等设置的作用，导致页面缩放行为不符合预期。

总而言之，这部分 `web_frame_test.cc` 代码专注于测试 `WebFrame` 中与 CSS 选择器监听、跨文档消息传递以及页面视口和缩放控制相关的核心功能，并特别关注了 Android 平台上的特定行为和配置。 这些测试确保了 Blink 引擎能够正确地解析和应用相关的 Web 标准，并处理各种复杂的视口配置场景。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
ntents) {
  LoadHTML("<div style='display:contents'><span></span></div>");

  Vector<WebString> selectors(1u, WebString::FromUTF8("span"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();

  EXPECT_EQ(1, UpdateCount()) << "Match elements in display:contents trees.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "s = document.querySelector('span');"
      "s.style.display = 'contents';");
  EXPECT_EQ(1, UpdateCount()) << "Match elements which are display:contents.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'block';");
  EXPECT_EQ(1, UpdateCount())
      << "Still match display:contents after parent becomes display:block.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'none';");
  EXPECT_EQ(2, UpdateCount())
      << "No longer matched when parent becomes display:none.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre());
}

TEST_F(WebFrameCSSCallbackTest, Reparenting) {
  LoadHTML(
      "<div id='d1'><span></span></div>"
      "<div id='d2'></div>");

  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();

  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "s = document.querySelector('span');"
      "d2 = document.getElementById('d2');"
      "d2.appendChild(s);");
  EXPECT_EQ(1, UpdateCount()) << "Just moving an element that continues to "
                                 "match shouldn't send a spurious callback.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));
}

TEST_F(WebFrameCSSCallbackTest, MultiSelector) {
  LoadHTML("<span></span>");

  // Check that selector lists match as the whole list, not as each element
  // independently.
  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  selectors.push_back(WebString::FromUTF8("span,p"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();

  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), UnorderedElementsAre("span", "span, p"));
}

TEST_F(WebFrameCSSCallbackTest, InvalidSelector) {
  LoadHTML("<p><span></span></p>");

  // Build a list with one valid selector and one invalid.
  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  selectors.push_back(WebString::FromUTF8("["));       // Invalid.
  selectors.push_back(WebString::FromUTF8("p span"));  // Not compound.
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();

  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"))
      << "An invalid selector shouldn't prevent other selectors from matching.";
}

TEST_F(WebFrameTest, PostMessageEvent) {
  RegisterMockedHttpURLLoad("postmessage_test.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "postmessage_test.html");

  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());

  auto make_message = []() {
    BlinkTransferableMessage message;
    message.message = SerializedScriptValue::NullValue();
    message.sender_origin =
        SecurityOrigin::CreateFromString("https://origin.com");
    message.sender_agent_cluster_id = base::UnguessableToken::Create();
    return message;
  };

  // Send a message with the correct origin.
  scoped_refptr<SecurityOrigin> correct_origin =
      SecurityOrigin::Create(ToKURL(base_url_));
  frame->PostMessageEvent(std::nullopt, g_empty_string,
                          correct_origin->ToString(), make_message());

  // Send another message with incorrect origin.
  scoped_refptr<SecurityOrigin> incorrect_origin =
      SecurityOrigin::Create(ToKURL(chrome_url_));
  frame->PostMessageEvent(std::nullopt, g_empty_string,
                          incorrect_origin->ToString(), make_message());

  // Verify that only the first addition is in the body of the page.
  std::string content = TestWebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_NE(std::string::npos, content.find("Message 1."));
  EXPECT_EQ(std::string::npos, content.find("Message 2."));
}

namespace {

scoped_refptr<SerializedScriptValue> SerializeString(
    const StringView& message,
    ScriptState* script_state) {
  // This is inefficient, but avoids duplicating serialization logic for the
  // sake of this test.
  NonThrowableExceptionState exception_state;
  ScriptState::Scope scope(script_state);
  V8ScriptValueSerializer serializer(script_state);
  return serializer.Serialize(V8String(script_state->GetIsolate(), message),
                              exception_state);
}

}  // namespace

TEST_F(WebFrameTest, PostMessageThenDetach) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");

  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  NonThrowableExceptionState exception_state;
  scoped_refptr<SerializedScriptValue> message =
      SerializeString("message", ToScriptStateForMainWorld(frame));
  MessagePortArray message_ports;
  frame->DomWindow()->PostMessageForTesting(
      message, message_ports, "*", frame->DomWindow(), exception_state);
  web_view_helper.Reset();
  EXPECT_FALSE(exception_state.HadException());

  // Success is not crashing.
  RunPendingTasks();
}

TEST_F(WebFrameTest, PostMessageEvent_CannotDeserialize) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");

  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  LocalDOMWindow* window = frame->DomWindow();

  base::RunLoop run_loop;
  auto* wait = MakeGarbageCollected<WaitForEvent>();
  wait->AddEventListener(window, event_type_names::kMessage);
  wait->AddEventListener(window, event_type_names::kMessageerror);
  wait->AddCompletionClosure(run_loop.QuitClosure());

  scoped_refptr<SerializedScriptValue> message =
      SerializeString("message", ToScriptStateForMainWorld(frame));
  SerializedScriptValue::ScopedOverrideCanDeserializeInForTesting
      override_can_deserialize_in(base::BindLambdaForTesting(
          [&](const SerializedScriptValue& value,
              ExecutionContext* execution_context, bool can_deserialize) {
            EXPECT_EQ(&value, message.get());
            EXPECT_EQ(execution_context, window);
            EXPECT_TRUE(can_deserialize);
            return false;
          }));

  NonThrowableExceptionState exception_state;
  frame->DomWindow()->PostMessageForTesting(message, MessagePortArray(), "*",
                                            window, exception_state);
  EXPECT_FALSE(exception_state.HadException());

  run_loop.Run();
  EXPECT_EQ(wait->GetLastEvent()->type(), event_type_names::kMessageerror);
}

namespace {

// Helper function to set autosizing multipliers on a document.
bool SetTextAutosizingMultiplier(Document* document, float multiplier) {
  bool multiplier_set = false;
  for (LayoutObject* layout_object = document->GetLayoutView(); layout_object;
       layout_object = layout_object->NextInPreOrder()) {
    if (layout_object->Style()) {
      ComputedStyleBuilder builder(layout_object->StyleRef());
      builder.SetTextAutosizingMultiplier(multiplier);
      layout_object->SetStyle(builder.TakeStyle(),
                              LayoutObject::ApplyStyleChanges::kNo);
      multiplier_set = true;
    }
  }
  return multiplier_set;
}

// Helper function to check autosizing multipliers on a document.
bool CheckTextAutosizingMultiplier(Document* document, float multiplier) {
  bool multiplier_checked = false;
  for (LayoutObject* layout_object = document->GetLayoutView(); layout_object;
       layout_object = layout_object->NextInPreOrder()) {
    if (layout_object->Style() && layout_object->IsText()) {
      EXPECT_EQ(multiplier, layout_object->Style()->TextAutosizingMultiplier());
      multiplier_checked = true;
    }
  }
  return multiplier_checked;
}

void UpdateScreenInfoAndResizeView(
    frame_test_helpers::WebViewHelper* web_view_helper,
    const display::ScreenInfo& screen_info) {
  display::ScreenInfos screen_infos(screen_info);
  web_view_helper->GetWebView()->MainFrameViewWidget()->UpdateScreenInfo(
      screen_infos);
  web_view_helper->Resize(screen_info.rect.size());
}

void UpdateScreenInfoAndResizeView(
    frame_test_helpers::WebViewHelper* web_view_helper,
    int viewport_width,
    int viewport_height) {
  display::ScreenInfo screen_info =
      web_view_helper->GetMainFrameWidget()->GetOriginalScreenInfo();
  screen_info.rect = gfx::Rect(viewport_width, viewport_height);
  UpdateScreenInfoAndResizeView(web_view_helper, screen_info);
}

}  // namespace

TEST_F(WebFrameTest, ChangeInFixedLayoutResetsTextAutosizingMultipliers) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    nullptr, ConfigureAndroid);

  Document* document =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  document->GetSettings()->SetTextAutosizingEnabled(true);
  EXPECT_TRUE(document->GetSettings()->GetTextAutosizingEnabled());
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_TRUE(SetTextAutosizingMultiplier(document, 2));

  ViewportDescription description =
      document->GetViewportData().GetViewportDescription();
  // Choose a width that's not going match the viewport width of the loaded
  // document.
  description.min_width = Length::Fixed(100);
  description.max_width = Length::Fixed(100);
  web_view_helper.GetWebView()->UpdatePageDefinedViewportConstraints(
      description);

  EXPECT_TRUE(CheckTextAutosizingMultiplier(document, 1));
}

TEST_F(WebFrameTest, WorkingTextAutosizingMultipliers_VirtualViewport) {
  const std::string html_file = "fixed_layout.html";
  RegisterMockedHttpURLLoad(html_file);

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + html_file, nullptr, nullptr,
                                    ConfigureAndroid);

  Document* document =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  document->GetSettings()->SetTextAutosizingEnabled(true);
  EXPECT_TRUE(document->GetSettings()->GetTextAutosizingEnabled());

  web_view_helper.Resize(gfx::Size(490, 800));

  // Multiplier: 980 / 490 = 2.0
  EXPECT_TRUE(CheckTextAutosizingMultiplier(document, 2.0));
}

TEST_F(WebFrameTest,
       VisualViewportSetSizeInvalidatesTextAutosizingMultipliers) {
  RegisterMockedHttpURLLoad("iframe_reload.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframe_reload.html", nullptr,
                                    nullptr, ConfigureAndroid);

  auto* main_frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  Document* document = main_frame->GetDocument();
  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  document->GetSettings()->SetTextAutosizingEnabled(true);
  EXPECT_TRUE(document->GetSettings()->GetTextAutosizingEnabled());
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  for (Frame* frame = main_frame; frame; frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame)
      continue;
    EXPECT_TRUE(SetTextAutosizingMultiplier(local_frame->GetDocument(), 2));
    for (LayoutObject* layout_object =
             local_frame->GetDocument()->GetLayoutView();
         layout_object; layout_object = layout_object->NextInPreOrder()) {
      if (layout_object->IsText())
        EXPECT_FALSE(layout_object->NeedsLayout());
    }
  }

  frame_view->GetPage()->GetVisualViewport().SetSize(gfx::Size(200, 200));

  for (Frame* frame = main_frame; frame; frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame)
      continue;
    for (LayoutObject* layout_object =
             local_frame->GetDocument()->GetLayoutView();
         !layout_object; layout_object = layout_object->NextInPreOrder()) {
      if (layout_object->IsText())
        EXPECT_TRUE(layout_object->NeedsLayout());
    }
  }
}

TEST_F(WebFrameTest, ZeroHeightPositiveWidthNotIgnored) {
  int viewport_width = 1280;
  int viewport_height = 0;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->GetLayoutSize()
                                .width());
  EXPECT_EQ(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->GetLayoutSize()
                                 .height());
}

TEST_F(WebFrameTest, DeviceScaleFactorUsesDefaultWithoutViewportTag) {
  RegisterMockedHttpURLLoad("no_viewport_tag.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "no_viewport_tag.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->SetDeviceScaleFactorForTesting(2.f);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  DCHECK(frame);
  EXPECT_EQ(2, frame->DevicePixelRatio());

  // Device scale factor should be independent of page scale.
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(1, 2);
  web_view_helper.GetWebView()->SetPageScaleFactor(0.5);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(1, web_view_helper.GetWebView()->PageScaleFactor());

  // Force the layout to happen before leaving the test.
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
}

TEST_F(WebFrameTest, FixedLayoutInitializeAtMinimumScale) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  int viewport_width = 640;
  int viewport_height = 480;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "fixed_layout.html");
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  int default_fixed_layout_width = 980;
  float minimum_page_scale_factor =
      viewport_width / (float)default_fixed_layout_width;
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->MinimumPageScaleFactor());

  // Assume the user has pinch zoomed to page scale factor 2.
  float user_pinch_page_scale_factor = 2;
  web_view_helper.GetWebView()->SetPageScaleFactor(
      user_pinch_page_scale_factor);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  // Make sure we don't reset to initial scale if the page continues to load.
  web_view_helper.GetWebView()->DidCommitLoad(false, false);
  web_view_helper.GetWebView()->DidChangeContentsSize();
  EXPECT_EQ(user_pinch_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  // Make sure we don't reset to initial scale if the viewport size changes.
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height + 100));
  EXPECT_EQ(user_pinch_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, WideDocumentInitializeAtMinimumScale) {
  RegisterMockedHttpURLLoad("wide_document.html");

  int viewport_width = 640;
  int viewport_height = 480;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "wide_document.html");
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  int wide_document_width = 1500;
  float minimum_page_scale_factor = viewport_width / (float)wide_document_width;
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->MinimumPageScaleFactor());

  // Assume the user has pinch zoomed to page scale factor 2.
  float user_pinch_page_scale_factor = 2;
  web_view_helper.GetWebView()->SetPageScaleFactor(
      user_pinch_page_scale_factor);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  // Make sure we don't reset to initial scale if the page continues to load.
  web_view_helper.GetWebView()->DidCommitLoad(false, false);
  web_view_helper.GetWebView()->DidChangeContentsSize();
  EXPECT_EQ(user_pinch_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  // Make sure we don't reset to initial scale if the viewport size changes.
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height + 100));
  EXPECT_EQ(user_pinch_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, DelayedViewportInitialScale) {
  RegisterMockedHttpURLLoad("viewport-auto-initial-scale.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-auto-initial-scale.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(0.25f, web_view_helper.GetWebView()->PageScaleFactor());

  ViewportData& viewport =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument()
          ->GetViewportData();
  ViewportDescription description = viewport.GetViewportDescription();
  description.zoom = 2;
  viewport.SetViewportDescription(description);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(2, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, setLoadWithOverviewModeToFalse) {
  RegisterMockedHttpURLLoad("viewport-auto-initial-scale.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-auto-initial-scale.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  // The page must be displayed at 100% zoom.
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, SetLoadWithOverviewModeToFalseAndNoWideViewport) {
  RegisterMockedHttpURLLoad("large-div.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "large-div.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  // The page must be displayed at 100% zoom, despite that it hosts a wide div
  // element.
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, NoWideViewportIgnoresPageViewportWidth) {
  RegisterMockedHttpURLLoad("viewport-auto-initial-scale.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-auto-initial-scale.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  // The page sets viewport width to 3000, but with UseWideViewport == false is
  // must be ignored.
  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->Size()
                                .width());
  EXPECT_EQ(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->Size()
                                 .height());
}

TEST_F(WebFrameTest, NoWideViewportIgnoresPageViewportWidthButAccountsScale) {
  RegisterMockedHttpURLLoad("viewport-wide-2x-initial-scale.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-wide-2x-initial-scale.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  // The page sets viewport width to 3000, but with UseWideViewport == false it
  // must be ignored while the initial scale specified by the page must be
  // accounted.
  EXPECT_EQ(viewport_width / 2, web_view_helper.GetWebView()
                                    ->MainFrameImpl()
                                    ->GetFrameView()
                                    ->Size()
                                    .width());
  EXPECT_EQ(viewport_height / 2, web_view_helper.GetWebView()
                                     ->MainFrameImpl()
                                     ->GetFrameView()
                                     ->Size()
                                     .height());
}

TEST_F(WebFrameTest, WideViewportSetsTo980WithoutViewportTag) {
  RegisterMockedHttpURLLoad("no_viewport_tag.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "no_viewport_tag.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(980, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->LayoutViewport()
                     ->ContentsSize()
                     .width());
  EXPECT_EQ(980.0 / viewport_width * viewport_height,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->LayoutViewport()
                ->ContentsSize()
                .height());
}

TEST_F(WebFrameTest, WideViewportSetsTo980WithXhtmlMp) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-xhtmlmp.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  frame_test_helpers::LoadFrame(
      web_view_helper.GetWebView()->MainFrameImpl(),
      base_url_ + "viewport/viewport-legacy-xhtmlmp.html");

  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->Size()
                                .width());
  EXPECT_EQ(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->Size()
                                 .height());
}

TEST_F(WebFrameTest, NoWideViewportAndHeightInMeta) {
  RegisterMockedHttpURLLoad("viewport-height-1000.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport-height-1000.html",
                                    nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->Size()
                                .width());
}

TEST_F(WebFrameTest, WideViewportSetsTo980WithAutoWidth) {
  RegisterMockedHttpURLLoad("viewport-2x-initial-scale.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-2x-initial-scale.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(980, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->Size()
                     .width());
  EXPECT_EQ(980.0 / viewport_width * viewport_height,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->Size()
                .height());
}

TEST_F(WebFrameTest, PageViewportInitialScaleOverridesLoadWithOverviewMode) {
  RegisterMockedHttpURLLoad("viewport-wide-2x-initial-scale.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-wide-2x-initial-scale.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  // The page must be displayed at 200% zoom, as specified in its viewport meta
  // tag.
  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, setInitialPageScaleFactorPermanently) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  float enforced_page_scale_factor = 2.0f;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  int viewport_width = 640;
  int viewport_height = 480;
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  web_view_helper.GetWebView()->SetInitialPageScaleOverride(-1);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(1.0, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest,
       PermanentInitialPageScaleFactorOverridesLoadWithOverviewMode) {
  RegisterMockedHttpURLLoad("viewport-auto-initial-scale.html");

  int viewport_width = 640;
  int viewport_height = 480;
  float enforced_page_scale_factor = 0.5f;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-auto-initial-scale.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest,
       PermanentInitialPageScaleFactorOverridesPageViewportInitialScale) {
  RegisterMockedHttpURLLoad("viewport-wide-2x-initial-scale.html");

  int viewport_width = 640;
  int viewport_height = 480;
  float enforced_page_scale_factor = 0.5f;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-wide-2x-initial-scale.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, SmallPermanentInitialPageScaleFactorIsClobbered) {
  const auto pages = std::to_array<const char*>(
      {// These pages trigger the clobbering condition. There must be a matching
       // item in "pageScaleFactors" array.
       "viewport-device-0.5x-initial-scale.html",
       "viewport-initial-scale-1.html",
       // These ones do not.
       "viewport-auto-initial-scale.html",
       "viewport-target-densitydpi-device-and-fixed-width.html"});
  const std::array<float, 2> page_scale_factors = {0.5f, 1.0f};
  for (size_t i = 0; i < std::size(pages); ++i)
    RegisterMockedHttpURLLoad(pages[i]);

  int viewport_width = 400;
  int viewport_height = 300;
  float enforced_page_scale_factor = 0.75f;

  for (size_t i = 0; i < std::size(pages); ++i) {
    for (int quirk_enabled = 0; quirk_enabled <= 1; ++quirk_enabled) {
      frame_test_helpers::WebViewHelper web_view_helper;
      web_view_helper.InitializeAndLoad(base_url_ + pages[i], nullptr, nullptr,
                                        ConfigureAndroid);
      web_view_helper.GetWebView()
          ->GetSettings()
          ->SetClobberUserAgentInitialScaleQuirk(quirk_enabled);
      web_view_helper.GetWebV
```