Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_frame_test.cc`. I need to analyze the code, identify the key features being tested, and explain their relationship to web technologies like JavaScript, HTML, and CSS. I also need to look for examples of logic, potential user errors, and consider the context of this being part 10 of 19.

Here's a breakdown of the code's functionality:

1. **Spellchecking:** Several tests (`ReplaceMisspelledRange`, `RemoveSpellingMarkers`, `RemoveSpellingMarkersUnderWords`, `SlowSpellcheckMarkerPosition`, `SpellcheckResultErasesMarkers`, `SpellcheckResultsSavedInDocument`) focus on spellchecking functionality. They test inserting text, triggering the spellchecker, selecting misspelled words, replacing them, and removing markers.
2. **Accessing Initial Document:**  Tests (`DidAccessInitialMainDocumentBody`, `DidAccessInitialMainDocumentOpen`, `DidAccessInitialMainDocumentNavigator`, `DidAccessInitialMainDocumentViaJavascriptUrl`, `DidAccessInitialMainDocumentBodyBeforeModalDialog`, `DidWriteToInitialMainDocumentBeforeModalDialog`) investigate when and how the browser detects access to the initial (empty) document of a new window from another window, especially via JavaScript.
3. **Scrolling:** The `CompositorScrollIsUserScrollLongPage` test examines how compositor-initiated scrolling is treated (as a user scroll) and how programmatic scrolling behaves.
4. **Cookies and Redirects:** The `SiteForCookiesForRedirect` test verifies how the site for cookies is determined during a redirect.
5. **New Windows and Navigation:** The `ModifiedClickNewWindow` test checks the behavior of opening new windows with modified clicks (like Ctrl+Click) and ensures the navigation policy is correctly determined.
6. **Navigation Cache and Reload:** Tests (`BackToReload`, `ReloadPost`) explore the interaction between back/forward navigation, reloads, and caching, particularly with POST requests.

Considering this is part 10 of 19, it likely focuses on a specific set of related functionalities within the broader `WebFrame` component.

**Plan:**
- Summarize the core functionality of each test case.
- Highlight the relationship to JavaScript, HTML, or CSS where applicable.
- Provide examples of input and expected output for logical tests.
- Identify potential user/programming errors.
- Synthesize a concise summary for part 10.
这个代码片段主要集中在 **测试 Blink 渲染引擎中 WebFrame 的以下功能**：

**1. 拼写检查 (Spellchecking):**

   - **功能:** 测试在 WebFrame 中进行拼写检查和更正的功能。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **HTML:**  测试用例会操作 HTML 文档中的元素（例如，通过 `getElementById` 获取 `<div id="data">` 元素）。
     - **JavaScript:**  测试用例会使用 `document.execCommand("InsertText", ...)`  来插入文本，模拟用户输入。也会通过 JavaScript API (`frame->SelectRange`) 来模拟文本选择。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** HTML 中存在一个可编辑的元素，其中包含拼写错误的单词 "wellcome"。
     - **预期输出 (`ReplaceMisspelledRange`):** 调用 `ReplaceMisspelledRange("welcome")` 后，"wellcome" 会被替换为 "welcome"。
     - **预期输出 (`RemoveSpellingMarkers`):** 调用 `RemoveSpellingMarkers()` 后，拼写错误的标记将被移除。
     - **预期输出 (`RemoveSpellingMarkersUnderWords`):** 调用 `RemoveSpellingMarkersUnderWords(["wellcome"])` 后，单词 "wellcome" 下的拼写错误标记将被移除。
   - **用户或编程常见的使用错误:**
     - **错误示例:**  开发者可能错误地假设在 `document.execCommand("InsertText", ...)` 之后拼写检查会立即发生并标记错误。实际上，拼写检查通常是异步的，可能需要手动触发 (`ForceInvocationForTesting`) 或等待一段时间。

**2. 访问初始文档 (Accessing Initial Document):**

   - **功能:** 测试当一个新窗口被打开时，另一个窗口尝试访问这个新窗口的初始（空白）文档时的行为。这部分主要关注 `DidAccessInitialMainDocument()` 方法的调用时机。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **JavaScript:**  测试用例主要通过 JavaScript 代码 (`window.opener.document...`) 从一个窗口访问另一个窗口的文档。测试不同的访问方式，例如修改 `body.innerHTML`，调用 `document.open()`，访问 `navigator` 对象等。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**  一个网页打开了一个新的空白窗口。
     - **预期输出:** 如果另一个窗口通过 JavaScript 访问了该空白窗口的 `document` 对象（例如，读取或修改其属性），`DidAccessInitialMainDocument()` 方法应该被调用。
   - **用户或编程常见的使用错误:**
     - **错误示例:** 开发者可能在新的空白窗口完全加载内容之前，就尝试从 opener 窗口访问其 `document` 对象，导致不可预测的行为或错误。浏览器需要跟踪这种访问，以确保安全性和正确的行为。

**3. 滚动 (Scrolling):**

   - **功能:** 测试 WebFrame 中的滚动行为，特别是区分用户发起的滚动（通过合成器）和程序化滚动。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **JavaScript:** 测试用例使用 `window.scrollTo()` 来模拟程序化滚动。
     - **HTML:**  `long_scroll.html` 预计是一个内容较长的 HTML 页面，以便测试滚动行为。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个内容超出视口的长页面。用户通过拖动滚动条或使用鼠标滚轮进行滚动。
     - **预期输出:**  `DidChangeScrollOffset()` 应该被调用，并且 `initial_scroll_state.was_scrolled_by_user` 应该为 true。
     - **假设输入:** 使用 JavaScript `window.scrollTo()` 进行滚动。
     - **预期输出:** `DidChangeScrollOffset()` 应该被调用，但 `initial_scroll_state.was_scrolled_by_user` 应该为 false。
   - **用户或编程常见的使用错误:**
     - **错误示例:** 开发者可能依赖于 `DidChangeScrollOffset()` 来判断所有类型的滚动，而没有区分用户发起的和程序化的滚动，这可能导致逻辑错误。

**4. Cookie 和重定向 (Cookies and Redirects):**

   - **功能:** 测试在发生 HTTP 重定向时，如何确定用于 Cookie 的站点 (Site for Cookies)。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **HTTP:** 这部分直接关系到 HTTP 协议中的重定向机制。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**  用户访问 `first_party_redirect.html`，该页面会重定向到 `first_party.html`。
     - **预期输出:**  最终加载的 `first_party.html` 的 `SiteForCookies()` 应该与重定向目标的 URL 一致。

**5. 新窗口和导航 (New Windows and Navigation):**

   - **功能:** 测试通过修改过的点击事件 (例如 Ctrl+Click) 打开新窗口时的导航行为。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **HTML:** 测试用例操作包含链接的 HTML 页面。
     - **JavaScript:** 测试用例模拟鼠标点击事件。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 用户在链接上按下 Ctrl 键并点击。
     - **预期输出:**  `BeginNavigation()` 方法应该被调用，以便客户端决定导航策略，而不是浏览器直接打开一个新窗口。

**6. 导航缓存和重新加载 (Navigation Cache and Reload):**

   - **功能:** 测试在进行后退操作和重新加载操作时，浏览器的缓存策略。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **HTML:** 测试用例加载包含链接和表单的 HTML 页面。
     - **JavaScript:** 测试用例使用 JavaScript 提交表单。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 用户访问一个页面，然后导航到另一个页面，然后点击后退按钮。
     - **预期输出:**  在后退导航时，缓存模式应该是默认的 (`kDefault`)。
     - **假设输入:** 用户重新加载一个包含 POST 表单的页面。
     - **预期输出:**  重新加载时，缓存模式应该是验证缓存 (`kValidateCache`)，并且导航类型是表单重新提交 (`kWebNavigationTypeFormResubmittedReload`)。

**总结 (针对第 10 部分):**

这部分 `web_frame_test.cc` 主要测试了 **WebFrame 的拼写检查功能**以及与 **新窗口打开和初始文档访问相关的行为**。此外，还涵盖了 **滚动事件的处理，重定向时的 Cookie 策略，以及后退和重新加载操作的缓存机制**。这些测试确保了 WebFrame 在处理文本编辑、窗口交互、页面导航和资源加载等方面的正确性和可靠性。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第10部分，共19部分，请归纳一下它的功能

"""
GetDocument();
  Element* element = document->getElementById(AtomicString("data"));

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      mojom::EditingBehavior::kEditingWindowsBehavior);

  element->Focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "_wellcome_.", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckController()
      .ForceInvocationForTesting();

  const int kAllTextBeginOffset = 0;
  const int kAllTextLength = 11;
  frame->SelectRange(WebRange(kAllTextBeginOffset, kAllTextLength),
                     WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);
  EphemeralRange selection_range = frame->GetFrame()
                                       ->Selection()
                                       .ComputeVisibleSelectionInDOMTree()
                                       .ToNormalizedEphemeralRange();

  EXPECT_EQ(1, textcheck.NumberOfTimesChecked());
  EXPECT_EQ(1, NumMarkersInRange(document, selection_range,
                                 DocumentMarker::MarkerTypes::Spelling()));

  frame->ReplaceMisspelledRange("welcome");
  EXPECT_EQ("_welcome_.", TestWebFrameContentDumper::DumpWebViewAsText(
                              web_view_helper.GetWebView(),
                              std::numeric_limits<size_t>::max())
                              .Utf8());
}

TEST_F(WebFrameTest, RemoveSpellingMarkers) {
  RegisterMockedHttpURLLoad("spell.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  TextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById(AtomicString("data"));

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      mojom::EditingBehavior::kEditingWindowsBehavior);

  element->Focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "_wellcome_.", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckController()
      .ForceInvocationForTesting();

  frame->RemoveSpellingMarkers();

  const int kAllTextBeginOffset = 0;
  const int kAllTextLength = 11;
  frame->SelectRange(WebRange(kAllTextBeginOffset, kAllTextLength),
                     WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide,
                     WebLocalFrame::kSelectionSetFocus);
  EphemeralRange selection_range = frame->GetFrame()
                                       ->Selection()
                                       .ComputeVisibleSelectionInDOMTree()
                                       .ToNormalizedEphemeralRange();

  EXPECT_EQ(0, NumMarkersInRange(document, selection_range,
                                 DocumentMarker::MarkerTypes::Spelling()));
}

static void GetSpellingMarkerOffsets(WebVector<unsigned>* offsets,
                                     const Document& document) {
  Vector<unsigned> result;
  const DocumentMarkerVector& document_markers = document.Markers().Markers();
  for (wtf_size_t i = 0; i < document_markers.size(); ++i)
    result.push_back(document_markers[i]->StartOffset());
  offsets->Assign(result);
}

TEST_F(WebFrameTest, RemoveSpellingMarkersUnderWords) {
  RegisterMockedHttpURLLoad("spell.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* web_frame = web_view_helper.LocalMainFrame();
  TextCheckClient textcheck;
  web_frame->SetTextCheckClient(&textcheck);

  LocalFrame* frame = web_frame->GetFrame();
  Document* document = frame->GetDocument();
  Element* element = document->getElementById(AtomicString("data"));

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      mojom::EditingBehavior::kEditingWindowsBehavior);

  element->Focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, " wellcome ", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  frame->GetSpellChecker()
      .GetIdleSpellCheckController()
      .ForceInvocationForTesting();

  WebVector<unsigned> offsets1;
  GetSpellingMarkerOffsets(&offsets1, *frame->GetDocument());
  EXPECT_EQ(1U, offsets1.size());

  Vector<String> words;
  words.push_back("wellcome");
  frame->RemoveSpellingMarkersUnderWords(words);

  WebVector<unsigned> offsets2;
  GetSpellingMarkerOffsets(&offsets2, *frame->GetDocument());
  EXPECT_EQ(0U, offsets2.size());
}

class StubbornTextCheckClient : public WebTextCheckClient {
 public:
  StubbornTextCheckClient() : completion_(nullptr) {}
  ~StubbornTextCheckClient() override = default;

  // WebTextCheckClient:
  bool IsSpellCheckingEnabled() const override { return true; }
  void RequestCheckingOfText(
      const WebString&,
      std::unique_ptr<WebTextCheckingCompletion> completion) override {
    completion_ = std::move(completion);
  }

  void KickNoResults() { Kick(-1, -1, kWebTextDecorationTypeSpelling); }

  void Kick() { Kick(1, 8, kWebTextDecorationTypeSpelling); }

  void KickGrammar() { Kick(1, 8, kWebTextDecorationTypeGrammar); }

 private:
  void Kick(int misspelling_start_offset,
            int misspelling_length,
            WebTextDecorationType type) {
    if (!completion_)
      return;
    Vector<WebTextCheckingResult> results;
    if (misspelling_start_offset >= 0 && misspelling_length > 0) {
      results.push_back(WebTextCheckingResult(type, misspelling_start_offset,
                                              misspelling_length));
    }
    completion_->DidFinishCheckingText(results);
    completion_.reset();
  }

  std::unique_ptr<WebTextCheckingCompletion> completion_;
};

TEST_F(WebFrameTest, SlowSpellcheckMarkerPosition) {
  RegisterMockedHttpURLLoad("spell.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  StubbornTextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById(AtomicString("data"));

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      mojom::EditingBehavior::kEditingWindowsBehavior);

  element->Focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "wellcome ", exception_state);
  EXPECT_FALSE(exception_state.HadException());
  document->execCommand("InsertText", false, "he", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckController()
      .ForceInvocationForTesting();

  textcheck.Kick();

  WebVector<unsigned> offsets;
  GetSpellingMarkerOffsets(&offsets, *frame->GetFrame()->GetDocument());
  EXPECT_EQ(0U, offsets.size());
}

TEST_F(WebFrameTest, SpellcheckResultErasesMarkers) {
  RegisterMockedHttpURLLoad("spell.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  StubbornTextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById(AtomicString("data"));

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      mojom::EditingBehavior::kEditingWindowsBehavior);

  element->Focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "welcome ", exception_state);

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckController()
      .ForceInvocationForTesting();

  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_FALSE(exception_state.HadException());
  auto range = EphemeralRange::RangeOfContents(*element);
  document->Markers().AddSpellingMarker(range);
  document->Markers().AddGrammarMarker(range);
  EXPECT_EQ(2U, document->Markers().Markers().size());

  textcheck.KickNoResults();
  EXPECT_EQ(0U, document->Markers().Markers().size());
}

TEST_F(WebFrameTest, SpellcheckResultsSavedInDocument) {
  RegisterMockedHttpURLLoad("spell.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  StubbornTextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById(AtomicString("data"));

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      mojom::EditingBehavior::kEditingWindowsBehavior);

  element->Focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "wellcome ", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckController()
      .ForceInvocationForTesting();

  textcheck.Kick();
  ASSERT_EQ(1U, document->Markers().Markers().size());
  ASSERT_NE(static_cast<DocumentMarker*>(nullptr),
            document->Markers().Markers()[0]);
  EXPECT_EQ(DocumentMarker::kSpelling,
            document->Markers().Markers()[0]->GetType());

  document->execCommand("InsertText", false, "wellcome ", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckController()
      .ForceInvocationForTesting();

  textcheck.KickGrammar();
  ASSERT_EQ(1U, document->Markers().Markers().size());
  ASSERT_NE(static_cast<DocumentMarker*>(nullptr),
            document->Markers().Markers()[0]);
  EXPECT_EQ(DocumentMarker::kGrammar,
            document->Markers().Markers()[0]->GetType());
}

class TestAccessInitialDocumentLocalFrameHost
    : public mojom::blink::LocalMainFrameHost {
 public:
  TestAccessInitialDocumentLocalFrameHost() = default;
  ~TestAccessInitialDocumentLocalFrameHost() override = default;

  void Init(blink::AssociatedInterfaceProvider* provider) {
    provider->OverrideBinderForTesting(
        mojom::blink::LocalMainFrameHost::Name_,
        WTF::BindRepeating(
            &TestAccessInitialDocumentLocalFrameHost::BindFrameHostReceiver,
            WTF::Unretained(this)));
  }

  // LocalMainFrameHost:
  void ScaleFactorChanged(float scale) override {}
  void ContentsPreferredSizeChanged(const ::gfx::Size& pref_size) override {}
  void TextAutosizerPageInfoChanged(
      ::blink::mojom::blink::TextAutosizerPageInfoPtr page_info) override {}
  void FocusPage() override {}
  void TakeFocus(bool reverse) override {}
  void UpdateTargetURL(const ::blink::KURL& url,
                       UpdateTargetURLCallback callback) override {
    std::move(callback).Run();
  }
  void RequestClose() override {}
  void ShowCreatedWindow(const ::blink::LocalFrameToken& opener_frame_token,
                         ::ui::mojom::blink::WindowOpenDisposition disposition,
                         const mojom::blink::WindowFeaturesPtr window_features,
                         bool opened_by_user_gesture,
                         ShowCreatedWindowCallback callback) override {
    std::move(callback).Run();
  }
  void SetWindowRect(const ::gfx::Rect& bounds,
                     SetWindowRectCallback callback) override {
    std::move(callback).Run();
  }
  void Minimize() override {}
  void Maximize() override {}
  void Restore() override {}
  void SetResizable(bool resizable) override {}
  void DidFirstVisuallyNonEmptyPaint() override {}
  void DidAccessInitialMainDocument() override {
    ++did_access_initial_main_document_;
  }
  void DraggableRegionsChanged(
      Vector<mojom::blink::DraggableRegionPtr> regions) override {}
  void OnFirstContentfulPaint() override {}

  // !!!!!!!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!!!!!!
  // If the actual counts in the tests below increase, this could be an
  // indicator of a bug that causes DidAccessInitialMainDocument() to always be
  // invoked, regardless of whether or not the initial document is accessed.
  // Please do not simply increment the expected counts in the below tests
  // without understanding what's causing the increased count.
  int did_access_initial_main_document_ = 0;

 private:
  void BindFrameHostReceiver(mojo::ScopedInterfaceEndpointHandle handle) {
    receiver_.Bind(
        mojo::PendingAssociatedReceiver<mojom::blink::LocalMainFrameHost>(
            std::move(handle)));
  }
  mojo::AssociatedReceiver<mojom::blink::LocalMainFrameHost> receiver_{this};
};

TEST_F(WebFrameTest, DidAccessInitialMainDocumentBody) {
  TestAccessInitialDocumentLocalFrameHost frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Create another window that will try to access it.
  frame_test_helpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Access the initial document by modifying the body.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.document.body.innerHTML += 'Modified';"));
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  web_view_helper.Reset();
}

TEST_F(WebFrameTest, DidAccessInitialMainDocumentOpen) {
  TestAccessInitialDocumentLocalFrameHost frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Create another window that will try to access it.
  frame_test_helpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Access the initial document by calling document.open(), which allows
  // arbitrary modification of the initial document.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.document.open();"));
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  web_view_helper.Reset();
}

TEST_F(WebFrameTest, DidAccessInitialMainDocumentNavigator) {
  TestAccessInitialDocumentLocalFrameHost frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Create another window that will try to access it.
  frame_test_helpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Access the initial document to get to the navigator object.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("console.log(window.opener.navigator);"));
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  web_view_helper.Reset();
}

TEST_F(WebFrameTest, DidAccessInitialMainDocumentViaJavascriptUrl) {
  TestAccessInitialDocumentLocalFrameHost frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Access the initial document from a javascript: URL.
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                "javascript:document.body.appendChild(document."
                                "createTextNode('Modified'))");
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  web_view_helper.Reset();
}

TEST_F(WebFrameTest, DidAccessInitialMainDocumentBodyBeforeModalDialog) {
  TestAccessInitialDocumentLocalFrameHost frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Create another window that will try to access it.
  frame_test_helpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Access the initial document by modifying the body.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.document.body.innerHTML += 'Modified';"));
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  // Run a modal dialog, which used to run a nested run loop and require
  // a special case for notifying about the access.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.confirm('Modal');"));
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  // Ensure that we don't notify again later.
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  web_view_helper.Reset();
}

TEST_F(WebFrameTest, DidWriteToInitialMainDocumentBeforeModalDialog) {
  TestAccessInitialDocumentLocalFrameHost frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Create another window that will try to access it.
  frame_test_helpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, frame_host.did_access_initial_main_document_);

  // Access the initial document with document.write, which moves us past the
  // initial empty document state of the state machine.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.document.write('Modified'); "
                      "window.opener.document.close();"));
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  // Run a modal dialog, which used to run a nested run loop and require
  // a special case for notifying about the access.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.confirm('Modal');"));
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  // Ensure that we don't notify again later.
  RunPendingTasks();
  EXPECT_EQ(1, frame_host.did_access_initial_main_document_);

  web_view_helper.Reset();
}

class TestScrolledFrameClient : public frame_test_helpers::TestWebFrameClient {
 public:
  TestScrolledFrameClient() { Reset(); }
  ~TestScrolledFrameClient() override = default;

  void Reset() { did_scroll_frame_ = false; }
  bool WasFrameScrolled() const { return did_scroll_frame_; }

  // WebLocalFrameClient:
  void DidChangeScrollOffset() override {
    if (Frame()->Parent())
      return;
    EXPECT_FALSE(did_scroll_frame_);
    LocalFrameView* view = To<WebLocalFrameImpl>(Frame())->GetFrameView();
    // LocalFrameView can be scrolled in
    // LocalFrameView::SetFixedVisibleContentRect which is called from
    // LocalFrame::CreateView (before the frame is associated with the the
    // view).
    if (view)
      did_scroll_frame_ = true;
  }

 private:
  bool did_scroll_frame_;
};

TEST_F(WebFrameTest, CompositorScrollIsUserScrollLongPage) {
  RegisterMockedHttpURLLoad("long_scroll.html");
  TestScrolledFrameClient client;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "long_scroll.html", &client);
  web_view_helper.Resize(gfx::Size(1000, 1000));

  WebLocalFrameImpl* frame_impl = web_view_helper.LocalMainFrame();
  DocumentLoader::InitialScrollState& initial_scroll_state =
      frame_impl->GetFrame()
          ->Loader()
          .GetDocumentLoader()
          ->GetInitialScrollState();

  EXPECT_FALSE(client.WasFrameScrolled());
  EXPECT_FALSE(initial_scroll_state.was_scrolled_by_user);

  auto* scrollable_area = frame_impl->GetFrameView()->LayoutViewport();

  // Do a compositor scroll, verify that this is counted as a user scroll.
  scrollable_area->DidCompositorScroll(gfx::PointF(0, 1));
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.7f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  EXPECT_TRUE(client.WasFrameScrolled());
  EXPECT_TRUE(initial_scroll_state.was_scrolled_by_user);

  client.Reset();
  initial_scroll_state.was_scrolled_by_user = false;

  // The page scale 1.0f and scroll.
  scrollable_area->DidCompositorScroll(gfx::PointF(0, 2));
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.0f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  EXPECT_TRUE(client.WasFrameScrolled());
  EXPECT_TRUE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();
  initial_scroll_state.was_scrolled_by_user = false;

  // No scroll event if there is no scroll delta.
  scrollable_area->DidCompositorScroll(gfx::PointF(0, 2));
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.0f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  EXPECT_FALSE(client.WasFrameScrolled());
  EXPECT_FALSE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();

  // Non zero page scale and scroll.
  scrollable_area->DidCompositorScroll(gfx::PointF(9, 15));
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        0.6f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  EXPECT_TRUE(client.WasFrameScrolled());
  EXPECT_TRUE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();
  initial_scroll_state.was_scrolled_by_user = false;

  // Programmatic scroll.
  frame_impl->ExecuteScript(WebScriptSource("window.scrollTo(0, 20);"));
  EXPECT_TRUE(client.WasFrameScrolled());
  EXPECT_FALSE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();

  // Programmatic scroll to same offset. No scroll event should be generated.
  frame_impl->ExecuteScript(WebScriptSource("window.scrollTo(0, 20);"));
  EXPECT_FALSE(client.WasFrameScrolled());
  EXPECT_FALSE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();
}

TEST_F(WebFrameTest, SiteForCookiesForRedirect) {
  String file_path = test::CoreTestDataPath("first_party.html");

  WebURL test_url(ToKURL("http://internal.test/first_party_redirect.html"));
  char redirect[] = "http://internal.test/first_party.html";
  WebURL redirect_url(ToKURL(redirect));
  WebURLResponse redirect_response;
  redirect_response.SetMimeType("text/html");
  redirect_response.SetHttpStatusCode(302);
  redirect_response.SetHttpHeaderField("Location", redirect);
  RegisterMockedURLLoadWithCustomResponse(test_url, file_path,
                                          redirect_response);

  WebURLResponse final_response;
  final_response.SetMimeType("text/html");
  RegisterMockedURLLoadWithCustomResponse(redirect_url, file_path,
                                          final_response);

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "first_party_redirect.html");
  EXPECT_TRUE(web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetDocument()
                  .SiteForCookies()
                  .IsEquivalent(net::SiteForCookies::FromUrl(GURL(redirect))));
}

class TestNewWindowWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestNewWindowWebFrameClient() : begin_navigation_call_count_(0) {}
  ~TestNewWindowWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void BeginNavigation(std::unique_ptr<WebNavigationInfo> info) override {
    if (ignore_navigations_) {
      begin_navigation_call_count_++;
      return;
    }
    TestWebFrameClient::BeginNavigation(std::move(info));
  }

  WebView* CreateNewWindow(
      const WebURLRequest&,
      const WebWindowFeatures&,
      const WebString&,
      WebNavigationPolicy,
      network::mojom::blink::WebSandboxFlags,
      const SessionStorageNamespaceId&,
      bool& consumed_user_gesture,
      const std::optional<Impression>&,
      const std::optional<WebPictureInPictureWindowOptions>&,
      const WebURL&) override {
    EXPECT_TRUE(false);
    return nullptr;
  }

  int BeginNavigationCallCount() const { return begin_navigation_call_count_; }
  void IgnoreNavigations() { ignore_navigations_ = true; }

 private:
  bool ignore_navigations_ = false;
  int begin_navigation_call_count_;
};

TEST_F(WebFrameTest, ModifiedClickNewWindow) {
  // This test checks that ctrl+click does not just open a new window,
  // but instead goes to client to decide the navigation policy.
  RegisterMockedHttpURLLoad("ctrl_click.html");
  RegisterMockedHttpURLLoad("hello_world.html");
  TestNewWindowWebFrameClient web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "ctrl_click.html",
                                    &web_frame_client);

  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  LocalDOMWindow* window = frame->DomWindow();
  KURL destination = ToKURL(base_url_ + "hello_world.html");

  // ctrl+click event
  MouseEventInit* mouse_initializer = MouseEventInit::Create();
  mouse_initializer->setView(window);
  mouse_initializer->setButton(1);
  mouse_initializer->setCtrlKey(true);

  Event* event =
      MouseEvent::Create(nullptr, event_type_names::kClick, mouse_initializer);
  FrameLoadRequest frame_request(window, ResourceRequest(destination));
  frame_request.SetNavigationPolicy(NavigationPolicyFromEvent(event));
  frame_request.SetTriggeringEventInfo(
      mojom::blink::TriggeringEventInfo::kFromTrustedEvent);
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  web_frame_client.IgnoreNavigations();
  frame->Loader().StartNavigation(frame_request, WebFrameLoadType::kStandard);
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.LocalMainFrame());

  // BeginNavigation should be called for the ctrl+click.
  EXPECT_EQ(1, web_frame_client.BeginNavigationCallCount());
}

class TestBeginNavigationCacheModeClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestBeginNavigationCacheModeClient()
      : cache_mode_(mojom::FetchCacheMode::kDefault) {}
  ~TestBeginNavigationCacheModeClient() override = default;

  mojom::FetchCacheMode GetCacheMode() const { return cache_mode_; }

  void BeginNavigation(std::unique_ptr<WebNavigationInfo> info) override {
    cache_mode_ = info->url_request.GetCacheMode();
    TestWebFrameClient::BeginNavigation(std::move(info));
  }

 private:
  mojom::FetchCacheMode cache_mode_;
};

TEST_F(WebFrameTest, BackToReload) {
  RegisterMockedHttpURLLoad("fragment_middle_click.html");
  TestBeginNavigationCacheModeClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fragment_middle_click.html",
                                    &client);
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  const FrameLoader& main_frame_loader =
      web_view_helper.LocalMainFrame()->GetFrame()->Loader();
  Persistent<HistoryItem> first_item =
      main_frame_loader.GetDocumentLoader()->GetHistoryItem();
  EXPECT_TRUE(first_item);

  RegisterMockedHttpURLLoad("white-1x1.png");
  frame_test_helpers::LoadFrame(frame, base_url_ + "white-1x1.png");
  EXPECT_NE(first_item.Get(),
            main_frame_loader.GetDocumentLoader()->GetHistoryItem());

  frame_test_helpers::LoadHistoryItem(frame, WebHistoryItem(first_item.Get()),
                                      mojom::FetchCacheMode::kDefault);
  EXPECT_EQ(first_item.Get(),
            main_frame_loader.GetDocumentLoader()->GetHistoryItem());

  frame_test_helpers::ReloadFrame(frame);
  EXPECT_EQ(mojom::FetchCacheMode::kValidateCache, client.GetCacheMode());
}

TEST_F(WebFrameTest, ReloadPost) {
  RegisterMockedHttpURLLoad("reload_post.html");
  TestBeginNavigationCacheModeClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "reload_post.html", &client);
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  auto* main_frame = web_view_helper.GetWebView()->MainFrameImpl();

  frame_test_helpers::LoadFrame(main_frame,
                                "javascript:document.forms[0].submit()");
  // Pump requests one more time after the javascript URL has executed to
  // trigger the actual POST load request.
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.LocalMainFrame());
  EXPECT_EQ(WebString::FromUTF8("POST"),
            frame->GetDocumentLoader()->HttpMethod());

  frame_test_helpers::ReloadFrame(frame);
  EXPECT_EQ(mojom::FetchCacheMode::kValidateCache, client.GetCacheMode());
  EXPECT_EQ(kWebNavigationTypeFormResubmittedReload,
            frame->GetDocumentLoader()->GetNavigationType());
}

class TestCachePolicyWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestCachePolicyWebFrameClient()
      : cache_mode_(mojom::FetchCacheMode::kDefault),
        begin_navigation_call_count_(0) {}
  ~TestCachePolicyWebFrameClient() override = default;

  mojom::FetchCacheMode GetCacheMode() const { return cache_mode_; }
  int BeginNavigationCallCount() const { return begin_navigation_call_count_; }
  TestCachePolicyWebFrameClient& ChildClient(wtf_size_t i) {
    return *child_clients_[i].get();
  }
  wtf_size_t ChildFrameCreationCount() const { return child_clients_.size(); }

  // frame_test_helpers::TestWebFrameClient:
  WebLocalFrame* CreateChildFrame(
      mojom::blink::TreeScopeType scope,
      const WebString&,
      const WebString&,
      const FramePolicy&,
      const WebFrameOwnerProperties& frame_owner_properties,
      FrameOwnerElementType,
      WebPolicyContainerBindParams policy_container_bind_params,
      ukm::SourceId document_ukm_source_id,
      FinishChildFrameCreationFn finish_creation) override {
    auto child = std::make_unique<TestCachePolicyWebFrameClient>();
    auto* child_ptr = child.get();
    child_clients_.push_back(std::move(child));
    return CreateLocalChild(*Frame(), scope, child_ptr,
                            std::move(policy_container_bind_params),
    
"""


```