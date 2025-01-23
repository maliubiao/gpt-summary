Response:
The user wants a summary of the functionality of the `web_frame_test.cc` file in the Chromium Blink engine. They are particularly interested in:

1. **General Functions:** What does the file do overall?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?  Provide examples.
3. **Logic and Assumptions:**  Are there any logical deductions or assumptions made? If so, give examples with input and output.
4. **Common Errors:** Does the code highlight potential user or programming mistakes? Give examples.
5. **Overall Summary:** A concise summary of the file's purpose, considering this is part 13 of 19.

**Mental Model:**

This file appears to be a unit test suite for the `WebFrame` and related components within the Blink rendering engine. It focuses heavily on testing frame swapping, a mechanism for transitioning between different types of frames (local and remote) and ensuring consistency and correct behavior during these transitions.

**Plan:**

1. **Identify Core Functionality:** Focus on the `TEST_F` macros, which define individual test cases. Look for patterns and common themes among the tests. Frame swapping seems central.
2. **Analyze Test Case Relationships to Web Technologies:** Examine how the tests interact with web content (loading HTML, executing JavaScript). Look for tests that manipulate DOM elements or interact with browser features like page scale.
3. **Infer Logic and Assumptions:**  Consider the setup and assertions within each test. What assumptions are being made about the state of the frames and the expected outcome of actions like swapping? Provide hypothetical scenarios.
4. **Spot Potential Errors:** Identify test cases that seem designed to catch specific error conditions or edge cases, especially those related to incorrect frame state or resource handling.
5. **Synthesize a Summary:** Combine the above points to create a concise description of the file's role within the larger Blink project, keeping in mind its position in the sequence of files.

**Detailed Breakdown of the Provided Code Snippet:**

*   **`WebFrameSwapTest` Class:**  A fixture for tests related to frame swapping.
*   **`SwapMainFrameLocalToRemote`:** Tests swapping a local main frame to a remote one. It loads a simple HTML file and checks the content.
*   **`SwapMainFrameLocalToLocal`:** Tests swapping a local main frame with another local frame, focusing on `DidClearWindowObject` and V8 context handling. This relates to the JavaScript environment.
*   **`DetachProvisionalLocalFrameAndPlaceholderRemoteFrame`:** Tests detaching a provisional frame and verifies it doesn't affect other frames. This highlights a potential error: not handling detached frames correctly.
*   **`SwapMainFrameWithPageScaleReset`:** Checks if page scale is reset after a main frame swap. This relates to CSS layout and rendering.
*   **`ValidateSizeOnRemoteToLocalMainFrameSwap`:**  Ensures viewport size is preserved after swapping. Related to CSS layout and browser viewport.
*   **`ValidateBrowserControlsSizeOnRemoteToLocalMainFrameSwap`:** Verifies browser control size is maintained. Related to browser UI integration.
*   **`SwapMainFrameWhileLoading`:** Tests swapping during page load. Related to the page lifecycle.
*   **`SwapChildAddFrameInUnload`:** Tests adding a frame during the unload event of another frame. This is a complex scenario that can lead to errors if not handled properly.
*   **`SwapAndVerifyFirstChildConsistency`, `SwapAndVerifyMiddleChildConsistency`, `SwapAndVerifyLastChildConsistency`:** Helper functions and tests for swapping child frames at different positions in the frame tree, ensuring the tree structure remains consistent.
*   **`AdHighlightEarlyApply`:** Tests that ad highlighting settings are applied correctly even for provisional frames. Relates to browser features and potentially CSS styling.
*   **`DISABLED_DoNotPropagateDisplayNonePropertyOnSwap`:** Tests that `display: none` is not incorrectly propagated during a swap. Related to CSS rendering.
*   **`SwapAndVerifySubframeConsistency`:** Helper function for swapping subframes.
*   **`EventsOnDisconnectedSubDocumentSkipped`, `EventsOnDisconnectedElementSkipped`:** Tests that events are not incorrectly dispatched to disconnected frames/elements. Related to JavaScript event handling.
*   **`SwapParentShouldDetachChildren`:** Checks that child frames are detached when their parent is swapped. This is crucial for resource management.
*   **`SwapPreservesGlobalContext`:** Tests that JavaScript global objects (like `window`) are correctly preserved during swaps. Crucial for JavaScript functionality.
*   **`SetTimeoutAfterSwap`:** Tests that `setTimeout` behaves correctly after a swap, especially regarding security restrictions on cross-origin frames. Related to JavaScript APIs and security.
*   **`SwapInitializesGlobal`:**  Verifies that global JavaScript objects are initialized correctly after a swap.
*   **`RemoteFramesAreIndexable`, `RemoteFrameLengthAccess`, `RemoteWindowNamedAccess`, `RemoteWindowToString`, `FramesOfRemoteParentAreIndexable`:** Tests how JavaScript interacts with remote frames, focusing on properties and indexing.
这个Blink引擎源代码文件 `web_frame_test.cc` 的主要功能是**测试 `WebFrame` 及其相关的 frame 切换（swapping）机制的正确性**。由于这是第 13 部分，我们可以推断前面和后面的部分可能涵盖了 `WebFrame` 的其他方面的测试。

下面列举一下这个文件的具体功能，并结合 JavaScript, HTML, CSS 进行说明：

**主要功能:**

1. **测试不同类型的 Frame 之间的切换 (Swapping):**  这是该文件最核心的功能。它测试了本地 (local) frame 和远程 (remote) frame 之间各种组合的切换场景，包括主 frame 和子 frame。

    *   **本地到远程 (Local to Remote):**  将一个在当前渲染进程中的 frame 替换为一个在不同进程中的 frame。
    *   **远程到本地 (Remote to Local):** 将一个在不同进程中的 frame 替换为一个在当前渲染进程中的 frame。
    *   **本地到本地 (Local to Local):** 在相同渲染进程内切换 frame (尽管这里更多的是测试跨 Page 的 local swap)。

2. **验证 Frame 切换后的状态和属性:**  测试切换后 Frame 的各种属性是否正确，例如：

    *   **Frame 树的结构 (Parent-Child relationships):**  确保切换后 parent frame 和 child frame 的关系正确。
    *   **Frame 的 detached 状态:**  验证旧的 frame 是否被正确地 detached。
    *   **JavaScript 全局对象 (Window object):** 确保切换后 JavaScript 的全局对象能够正确访问和使用，包括 `window` 对象的属性和方法。
    *   **页面缩放 (Page Scale Factor):** 验证切换是否会影响页面的缩放比例。
    *   **视口大小 (Viewport Size):**  确保切换后视口的大小保持一致。
    *   **浏览器控件大小 (Browser Controls Size):** 验证浏览器控件的大小在切换后是否正确。

3. **测试 Frame 切换过程中或前后的事件和生命周期:**  测试在 frame 切换的不同阶段（例如，加载过程中，卸载过程中）进行切换是否会引发问题。

4. **测试 Frame 切换对 JavaScript API 的影响:**  例如，测试 `setTimeout` 在跨域 frame 切换后的行为，以及如何访问 remote frame 的 `window` 对象。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **JavaScript:**

    *   **全局对象访问:**  `TEST_F(WebFrameSwapTest, SwapPreservesGlobalContext)` 测试了在 frame 切换后，JavaScript 代码是否还能正确访问到另一个 frame 的 `contentWindow` 属性，以及 `top` 属性是否指向正确的顶层 window。
        *   **假设输入:** 页面包含两个 iframe，#frame1 和 #frame2。
        *   **操作:** 将 #frame2 从 local 切换到 remote。
        *   **预期输出:**  `document.querySelector('#frame2').contentWindow` 返回的 window 对象在切换前后是同一个（尽管是 proxy）。`document.querySelector('#frame2').contentWindow.top` 始终指向顶层 window。
    *   **`setTimeout` 的行为:** `TEST_F(WebFrameSwapTest, SetTimeoutAfterSwap)` 测试了在 frame 切换到 remote 后，尝试在该 remote frame 中调用 `setTimeout` 是否会抛出安全错误（如果跨域）。
        *   **假设输入:**  一个 local frame 被切换成一个 cross-origin 的 remote frame。
        *   **操作:**  尝试在切换前的 local frame 的 `window` 对象上调用 `setTimeout`（通过保存的引用）。
        *   **预期输出:** 抛出一个 `SecurityError`。
    *   **访问 Remote Frame 的属性:** `TEST_F(WebFrameSwapTest, RemoteWindowNamedAccess)` 测试了尝试访问 remote frame 的 window 对象的属性，即使该属性不存在，也不会导致崩溃。
    *   **Frame 的索引访问:** `TEST_F(WebFrameSwapTest, RemoteFramesAreIndexable)` 测试了可以通过 `window[index]` 的方式访问 remote frame 的 window 对象。
    *   **事件处理:** `TEST_F(WebFrameSwapTest, EventsOnDisconnectedSubDocumentSkipped)` 和 `TEST_F(WebFrameSwapTest, EventsOnDisconnectedElementSkipped)` 测试了当 frame 或其内部元素断开连接后，事件不会被错误地触发或处理。

*   **HTML:**

    *   **加载 HTML 内容:**  `TEST_F(WebFrameSwapTest, SwapMainFrameLocalToRemote)` 中使用了 `frame_test_helpers::LoadFrame` 来加载 HTML 文件到 frame 中，验证切换后的内容是否正确。
    *   **iframe 元素的添加和移除:**  `TEST_F(WebFrameTest, SwapChildAddFrameInUnload)` 测试了在 iframe 的 `unload` 事件处理函数中动态添加新的 iframe，并进行 frame 切换，验证是否会导致问题。

*   **CSS:**

    *   **页面缩放:** `TEST_F(WebFrameSwapTest, SwapMainFrameWithPageScaleReset)` 测试了 main frame 切换后，页面的缩放比例是否会重置为默认值。
    *   **元素的 `display` 属性:** `TEST_F(WebFrameSwapTest, DISABLED_DoNotPropagateDisplayNonePropertyOnSwap)` (已禁用) 测试了 frame 切换时不应该错误地传递 `display: none` 属性。
    *   **广告高亮:** `TEST_F(WebFrameSwapTest, AdHighlightEarlyApply)` 测试了即使在 frame 还是 provisional 状态时设置了广告高亮，切换后也能正确应用到 frame 上。

**逻辑推理和假设输入/输出:**

*   **假设输入:** 一个包含父 frame 和子 frame 的页面。
*   **操作:** 将子 frame 从 local 切换到 remote。
*   **预期输出:**
    *   `parentFrame.firstChild` 指向的 frame 变成 remote frame。
    *   remote frame 的 `parent` 属性指向父 frame。
    *   在父 frame 的 JavaScript 上下文中访问 `window[子 frame的索引]` 可以获取到 remote frame 的 window proxy 对象。
*   **假设输入:**  正在加载一个 HTML 页面的 local frame。
*   **操作:**  在该 frame 加载完成前，将其切换为一个 remote frame。
*   **预期输出:**  之前的加载操作会被取消，新的 remote frame 开始其加载过程。

**用户或编程常见的使用错误:**

*   **在 Frame 切换后仍然持有旧 Frame 的引用:** 这可能导致访问到已经被 detached 的 frame，引发错误。例如，在 `TEST_F(WebFrameSwapTest, SwapPreservesGlobalContext)` 中，虽然 window 对象是同一个（proxy），但直接操作旧的 frame 对象可能会有问题。
*   **没有正确处理跨域 Frame 的安全限制:**  例如，在 remote frame 加载完成后，尝试直接访问其 `contentDocument` 或执行 JavaScript 可能因为跨域策略而被阻止。`TEST_F(WebFrameSwapTest, SetTimeoutAfterSwap)` 就体现了这一点。
*   **在 Frame 卸载过程中进行不安全的操作:**  例如，在 `unload` 事件处理函数中进行复杂的 DOM 操作或网络请求，可能导致竞态条件或崩溃。`TEST_F(WebFrameTest, SwapChildAddFrameInUnload)` 旨在测试这类场景。
*   **错误地假设 Frame 切换后 JavaScript 全局对象保持不变:**  虽然 Blink 试图保持 window 对象的连续性，但在某些情况下，例如 cross-origin 的切换，旧的 window 对象实际上会被替换为 proxy 对象。

**功能归纳 (作为第 13 部分):**

作为系列测试的第 13 部分，这个 `web_frame_test.cc` 文件专注于 **`WebFrame` 组件中至关重要的 frame 切换机制的测试**。它深入验证了在各种场景下，local frame 和 remote frame 之间进行切换时的正确性，包括 frame 树的结构、JavaScript 上下文的维护、页面状态的保持以及对 web 标准 (HTML, CSS, JavaScript) 的符合性。  考虑到这是一个较大的测试套件的一部分，可以推断之前的部分可能涉及了 `WebFrame` 的创建、加载、渲染等基础功能测试，而后续部分可能会覆盖更高级的功能或特定的 edge cases。  这个文件特别强调了 frame 切换对 JavaScript 环境和安全性的影响。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第13部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
te_frame);

  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);

  // Committing a navigation in `local_frame` should swap it back in.
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");

  std::string content =
      TestWebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("hello", content);
}

class DidClearWindowObjectCounter
    : public frame_test_helpers::TestWebFrameClient {
 public:
  void DidClearWindowObject() override { ++count_; }

  int Count() const { return count_; }

 private:
  int count_ = 0;
};

TEST_F(WebFrameSwapTest, SwapMainFrameLocalToLocal) {
  // Start with a WebView with a local main frame.
  Frame* original_page_main_frame = WebFrame::ToCoreFrame(*MainFrame());
  EXPECT_EQ(original_page_main_frame,
            web_view_helper_.GetWebView()->GetPage()->MainFrame());

  // Set up a new WebView with a placeholder remote frame and a provisional
  // local frame, to do a local swap with the previous WebView.
  frame_test_helpers::WebViewHelper new_view_helper;
  new_view_helper.InitializePlaceholderRemote();
  DidClearWindowObjectCounter counter_client;
  WebLocalFrameImpl* provisional_frame = new_view_helper.CreateProvisional(
      *new_view_helper.RemoteMainFrame(), &counter_client);
  new_view_helper.GetWebView()->GetPage()->SetPreviousMainFrameForLocalSwap(
      DynamicTo<LocalFrame>(original_page_main_frame));
  EXPECT_NE(web_view_helper_.GetWebView(), new_view_helper.GetWebView());
  EXPECT_EQ(WebFrame::ToCoreFrame(*new_view_helper.RemoteMainFrame()),
            new_view_helper.GetWebView()->GetPage()->MainFrame());

  // Perform a cross-Page main frame swap. This should unload the previous
  // Page's main LocalFrame, replacing it with a placeholder RemoteFrame. After
  // that, the placeholder RemoteFrame in the new Page will be swapped out, and
  // the new main LocalFrame will be swapped in.
  auto params = std::make_unique<WebNavigationParams>();
  params->url = url_test_helpers::ToKURL("about:blank");
  // `CommitNavigation` will swap in the local frame to replace the remote
  // frame.
  provisional_frame->CommitNavigation(std::move(params), nullptr);

  // Android WebView's Java Object bridge is sensitive to exactly when and how
  // often `DidClearWindowObject()` is called. Though this is a fairly indirect
  // signal, it's still better than no signal at all.
  EXPECT_EQ(1, counter_client.Count());

  // Make sure the WindowProxy itself is not initialized, since the original
  // frame never ran script and was never scripted.
  LocalFrame* const frame = new_view_helper.LocalMainFrame()->GetFrame();
  v8::Isolate* const isolate = ToIsolate(frame);
  // Technically not needed for this test, but if something is broken, it fails
  // more gracefully with a HandleScope.
  v8::HandleScope scope(ToIsolate(frame));
  v8::Local<v8::Context> context =
      ToV8ContextMaybeEmpty(frame, DOMWrapperWorld::MainWorld(isolate));
  EXPECT_TRUE(context.IsEmpty());

  // The new WebView's main frame is now set to a new main LocalFrame.
  EXPECT_EQ(WebFrame::ToCoreFrame(*provisional_frame),
            new_view_helper.GetWebView()->GetPage()->MainFrame());

  // The old WebView's main frame is now a placeholder RemoteFrame that is not
  // detached.
  EXPECT_NE(original_page_main_frame,
            web_view_helper_.GetWebView()->GetPage()->MainFrame());
  EXPECT_TRUE(original_page_main_frame->IsDetached());
  EXPECT_TRUE(
      web_view_helper_.GetWebView()->GetPage()->MainFrame()->IsRemoteFrame());

  new_view_helper.Reset();
}

TEST_F(WebFrameSwapTest, DetachProvisionalLocalFrameAndPlaceholderRemoteFrame) {
  // Start with a WebView with a local main frame.
  Frame* original_page_main_frame = WebFrame::ToCoreFrame(*MainFrame());
  EXPECT_EQ(original_page_main_frame,
            web_view_helper_.GetWebView()->GetPage()->MainFrame());

  // Set up a new WebView with a placeholder remote frame and a provisional
  // local frame, that is set to do local swap with the previous WebView.
  frame_test_helpers::WebViewHelper new_view_helper;
  new_view_helper.InitializePlaceholderRemote();
  WebRemoteFrameImpl* remote_frame = new_view_helper.RemoteMainFrame();
  WebLocalFrameImpl* provisional_local_frame =
      new_view_helper.CreateProvisional(*remote_frame);
  new_view_helper.GetWebView()->GetPage()->SetPreviousMainFrameForLocalSwap(
      DynamicTo<LocalFrame>(original_page_main_frame));
  EXPECT_NE(web_view_helper_.GetWebView(), new_view_helper.GetWebView());
  EXPECT_EQ(WebFrame::ToCoreFrame(*remote_frame),
            new_view_helper.GetWebView()->GetPage()->MainFrame());

  // Detach the new WebView's provisional local main frame before any swapping
  // happens.
  provisional_local_frame->Detach();
  // The detachment should not affect the placeholder RemoteFrame, nor the
  // previous page.
  EXPECT_FALSE(
      WebFrame::ToCoreFrame(*new_view_helper.RemoteMainFrame())->IsDetached());
  EXPECT_FALSE(
      WebFrame::ToCoreFrame(*web_view_helper_.LocalMainFrame())->IsDetached());

  // Make sure that shutting down the new WebView does not affect the previous
  // WebView.
  new_view_helper.Reset();
  // The detachment should not affect the previous page too.
  EXPECT_FALSE(
      WebFrame::ToCoreFrame(*web_view_helper_.LocalMainFrame())->IsDetached());
}

TEST_F(WebFrameSwapTest, SwapMainFrameWithPageScaleReset) {
  WebView()->SetDefaultPageScaleLimits(1, 2);
  WebView()->SetPageScaleFactor(1.25);
  EXPECT_EQ(1.25, WebView()->PageScaleFactor());

  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame(), remote_frame);

  mojo::AssociatedRemote<mojom::blink::RemoteMainFrameHost> main_frame_host;
  std::ignore = main_frame_host.BindNewEndpointAndPassDedicatedReceiver();
  WebView()->DidAttachRemoteMainFrame(
      main_frame_host.Unbind(),
      mojo::AssociatedRemote<mojom::blink::RemoteMainFrame>()
          .BindNewEndpointAndPassDedicatedReceiver());

  EXPECT_EQ(1.0, WebView()->PageScaleFactor());
}

TEST_F(WebFrameSwapTest, ValidateSizeOnRemoteToLocalMainFrameSwap) {
  gfx::Size size(111, 222);

  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame(), remote_frame);

  To<WebViewImpl>(remote_frame->View())->Resize(size);

  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);

  // Verify that the size that was set with a remote main frame is correct
  // after swapping to a local frame.
  Page* page =
      To<WebViewImpl>(local_frame->View())->GetPage()->MainFrame()->GetPage();
  EXPECT_EQ(size.width(), page->GetVisualViewport().Size().width());
  EXPECT_EQ(size.height(), page->GetVisualViewport().Size().height());
}

// Verify that size changes to browser controls while the main frame is remote
// are preserved when the main frame swaps to a local frame.  See
// https://crbug.com/769321.
TEST_F(WebFrameSwapTest,
       ValidateBrowserControlsSizeOnRemoteToLocalMainFrameSwap) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame(), remote_frame);

  // Create a provisional main frame frame but don't swap it in yet.
  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);

  WebViewImpl* web_view = To<WebViewImpl>(local_frame->View());
  EXPECT_TRUE(web_view->MainFrame() &&
              web_view->MainFrame()->IsWebRemoteFrame());

  // Resize the browser controls.
  float top_browser_controls_height = 40;
  float bottom_browser_controls_height = 60;
  web_view->ResizeWithBrowserControls(gfx::Size(100, 100),
                                      top_browser_controls_height,
                                      bottom_browser_controls_height, false);

  // Swap the provisional frame in and verify that the browser controls size is
  // correct.
  remote_frame->Swap(local_frame);
  Page* page =
      To<WebViewImpl>(local_frame->View())->GetPage()->MainFrame()->GetPage();
  EXPECT_EQ(top_browser_controls_height,
            page->GetBrowserControls().TopHeight());
  EXPECT_EQ(bottom_browser_controls_height,
            page->GetBrowserControls().BottomHeight());
}

namespace {

class SwapMainFrameWhenTitleChangesWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  SwapMainFrameWhenTitleChangesWebFrameClient() = default;
  ~SwapMainFrameWhenTitleChangesWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidReceiveTitle(const WebString& title) override {
    if (title.IsEmpty())
      return;

    if (!Frame()->Parent()) {
      frame_test_helpers::SwapRemoteFrame(Frame(),
                                          frame_test_helpers::CreateRemote());
    }
  }
};

}  // namespace

TEST_F(WebFrameTest, SwapMainFrameWhileLoading) {
  SwapMainFrameWhenTitleChangesWebFrameClient frame_client;

  frame_test_helpers::WebViewHelper web_view_helper;
  RegisterMockedHttpURLLoad("frame-a-b-c.html");
  RegisterMockedHttpURLLoad("subframe-a.html");
  RegisterMockedHttpURLLoad("subframe-b.html");
  RegisterMockedHttpURLLoad("subframe-c.html");
  RegisterMockedHttpURLLoad("subframe-hello.html");

  web_view_helper.InitializeAndLoad(base_url_ + "frame-a-b-c.html",
                                    &frame_client);
}

TEST_F(WebFrameTest, SwapChildAddFrameInUnload) {
  frame_test_helpers::WebViewHelper web_view_helper;

  // This sets up a main frame with one child frame. When the document in the
  // child frame is unloaded (e.g. due to the `Frame::Swap()` call below), the
  // unload handler will insert a new <iframe> into the main frame's document.
  RegisterMockedHttpURLLoad("add-frame-in-unload-main.html");
  RegisterMockedHttpURLLoad("add-frame-in-unload-subframe.html");
  web_view_helper.InitializeAndLoad(base_url_ +
                                    "add-frame-in-unload-main.html");

  WebLocalFrame* new_frame = web_view_helper.CreateProvisional(
      *web_view_helper.LocalMainFrame()->FirstChild());

  // This triggers the unload handler in the child frame's Document, mutating
  // the frame tree during the `Frame::Swap()` call.
  web_view_helper.LocalMainFrame()->FirstChild()->Swap(new_frame);

  // TODO(dcheng): This is currently required to trigger a crash when the bug is
  // not fixed. Removing a frame from the frame tree will fail one of the
  // consistency checks in `Frame::RemoveChild()` if the frame tree is
  // corrupted.  This should be replaced with a test helper that comprehensively
  // validates that a frame tree is not corrupted: this helper could also be
  // used to simplify the various SwapAndVerify* helpers below.
  web_view_helper.LocalMainFrame()->ExecuteScript(
      WebScriptSource("document.querySelector('iframe').remove()"));
}

void WebFrameTest::SwapAndVerifyFirstChildConsistency(const char* const message,
                                                      WebFrame* parent,
                                                      WebFrame* new_child) {
  SCOPED_TRACE(message);
  if (new_child->IsWebLocalFrame()) {
    parent->FirstChild()->Swap(new_child->ToWebLocalFrame());
  } else {
    frame_test_helpers::SwapRemoteFrame(parent->FirstChild(),
                                        new_child->ToWebRemoteFrame());
  }

  EXPECT_EQ(new_child, parent->FirstChild());
  EXPECT_EQ(new_child->Parent(), parent);
  EXPECT_EQ(new_child,
            parent->LastChild()->PreviousSibling()->PreviousSibling());
  EXPECT_EQ(new_child->NextSibling(), parent->LastChild()->PreviousSibling());
}

TEST_F(WebFrameSwapTest, SwapFirstChild) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  SwapAndVerifyFirstChildConsistency("local->remote", MainFrame(),
                                     remote_frame);

  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  SwapAndVerifyFirstChildConsistency("remote->local", MainFrame(), local_frame);

  // FIXME: This almost certainly fires more load events on the iframe element
  // than it should.
  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  std::string content =
      TestWebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("  \n\nhello\n\nb \n\na\n\nc", content);
}

// Asserts that the `Settings::SetHighlightAds` is properly applied to a
// `LocalFrame` even if `Settings::SetHighlightAds` is fired when the
// `LocalFrame` is still provisional. See crbug/1312107. While the bug is first
// observed on fenced frames, the underlying issue lies in the timing of the
// `Settings::SetHighlightAds` call with respect to the navigation progress of
// the frame.
TEST_F(WebFrameSwapTest, AdHighlightEarlyApply) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  SwapAndVerifyFirstChildConsistency("local->remote", MainFrame(),
                                     remote_frame);

  // Create the provisional frame and set its ad evidence.
  WebLocalFrameImpl* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  // Value of `parent_is_ad` does not matter.
  blink::FrameAdEvidence ad_evidence(/*parent_is_ad=*/false);
  ad_evidence.set_created_by_ad_script(
      mojom::FrameCreationStackEvidence::kCreatedByAdScript);
  ad_evidence.set_is_complete();
  local_frame->SetAdEvidence(ad_evidence);

  // Toggle the settings for provisional local frame.
  local_frame->View()->GetSettings()->SetHighlightAds(true);

  // Assert that the local frame does not have any overlay color since it is not
  // in the frame tree yet.
  ASSERT_EQ(local_frame->GetFrame()->GetFrameOverlayColorForTesting(),
            std::nullopt);

  WebDocument doc_before_navigation = local_frame->GetDocument();

  auto params = std::make_unique<WebNavigationParams>();
  params->url = url_test_helpers::ToKURL("about:blank");
  // `CommitNavigation` will swap in the local frame to replace the remote
  // frame.
  local_frame->CommitNavigation(std::move(params), nullptr);

  ASSERT_FALSE(local_frame->IsProvisional());
  ASSERT_NE(doc_before_navigation, local_frame->GetDocument());
  ASSERT_EQ(local_frame->GetFrame()->GetFrameOverlayColorForTesting(),
            SkColorSetARGB(128, 255, 0, 0));
}

// TODO(crbug.com/1314493): This test is flaky with the TimedHTMLParserBudget
// feature enabled.
TEST_F(WebFrameSwapTest, DISABLED_DoNotPropagateDisplayNonePropertyOnSwap) {
  WebFrameSwapTestClient* main_frame_client =
      static_cast<WebFrameSwapTestClient*>(MainFrame()->Client());
  EXPECT_FALSE(main_frame_client->DidPropagateDisplayNoneProperty());

  WebLocalFrame* child_frame = MainFrame()->FirstChild()->ToWebLocalFrame();
  frame_test_helpers::LoadFrame(child_frame, "subframe-hello.html");
  EXPECT_FALSE(main_frame_client->DidPropagateDisplayNoneProperty());

  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(child_frame, remote_frame);
  EXPECT_FALSE(main_frame_client->DidPropagateDisplayNoneProperty());

  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);
  EXPECT_FALSE(main_frame_client->DidPropagateDisplayNoneProperty());
  Reset();
}

void WebFrameTest::SwapAndVerifyMiddleChildConsistency(
    const char* const message,
    WebFrame* parent,
    WebFrame* new_child) {
  SCOPED_TRACE(message);

  if (new_child->IsWebLocalFrame()) {
    parent->FirstChild()->NextSibling()->Swap(new_child->ToWebLocalFrame());
  } else {
    frame_test_helpers::SwapRemoteFrame(parent->FirstChild()->NextSibling(),
                                        new_child->ToWebRemoteFrame());
  }

  Frame* parent_frame = WebFrame::ToCoreFrame(*parent);
  Frame* new_child_frame = WebFrame::ToCoreFrame(*new_child);

  EXPECT_EQ(new_child_frame, parent_frame->FirstChild()->NextSibling());
  EXPECT_EQ(new_child_frame, parent_frame->LastChild()->PreviousSibling());
  EXPECT_EQ(new_child_frame->Parent(), parent_frame);
  EXPECT_EQ(new_child_frame, parent_frame->FirstChild()->NextSibling());
  EXPECT_EQ(new_child_frame->PreviousSibling(), parent_frame->FirstChild());
  EXPECT_EQ(new_child_frame, parent_frame->LastChild()->PreviousSibling());
  EXPECT_EQ(new_child_frame->NextSibling(), parent_frame->LastChild());
}

TEST_F(WebFrameSwapTest, SwapMiddleChild) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  SwapAndVerifyMiddleChildConsistency("local->remote", MainFrame(),
                                      remote_frame);

  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  SwapAndVerifyMiddleChildConsistency("remote->local", MainFrame(),
                                      local_frame);

  // FIXME: This almost certainly fires more load events on the iframe element
  // than it should.
  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  std::string content =
      TestWebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("  \n\na\n\nhello\n\nc", content);
}

void WebFrameTest::SwapAndVerifyLastChildConsistency(const char* const message,
                                                     WebFrame* parent,
                                                     WebFrame* new_child) {
  SCOPED_TRACE(message);
  if (new_child->IsWebLocalFrame()) {
    parent->LastChild()->Swap(new_child->ToWebLocalFrame());
  } else {
    frame_test_helpers::SwapRemoteFrame(parent->LastChild(),
                                        new_child->ToWebRemoteFrame());
  }

  EXPECT_EQ(new_child, parent->LastChild());
  EXPECT_EQ(new_child->Parent(), parent);
  EXPECT_EQ(new_child, parent->LastChild()->PreviousSibling()->NextSibling());
  EXPECT_EQ(new_child, parent->FirstChild()->NextSibling()->NextSibling());
  EXPECT_EQ(new_child->PreviousSibling(), parent->FirstChild()->NextSibling());
}

TEST_F(WebFrameSwapTest, SwapLastChild) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  SwapAndVerifyLastChildConsistency("local->remote", MainFrame(), remote_frame);

  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  SwapAndVerifyLastChildConsistency("remote->local", MainFrame(), local_frame);

  // FIXME: This almost certainly fires more load events on the iframe element
  // than it should.
  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  std::string content =
      TestWebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("  \n\na\n\nb \n\na\n\nhello", content);
}

TEST_F(WebFrameSwapTest, DetachProvisionalFrame) {
  WebRemoteFrameImpl* remote_frame = frame_test_helpers::CreateRemote();
  SwapAndVerifyMiddleChildConsistency("local->remote", MainFrame(),
                                      remote_frame);

  WebLocalFrameImpl* provisional_frame =
      web_view_helper_.CreateProvisional(*remote_frame);

  // The provisional frame should have a local frame owner.
  FrameOwner* owner = provisional_frame->GetFrame()->Owner();
  ASSERT_TRUE(owner->IsLocal());

  // But the owner should point to |remoteFrame|, since the new frame is still
  // provisional.
  EXPECT_EQ(remote_frame->GetFrame(), owner->ContentFrame());

  // After detaching the provisional frame, the frame owner should still point
  // at |remoteFrame|.
  provisional_frame->Detach();

  // The owner should not be affected by detaching the provisional frame, so it
  // should still point to |remoteFrame|.
  EXPECT_EQ(remote_frame->GetFrame(), owner->ContentFrame());
}

void WebFrameTest::SwapAndVerifySubframeConsistency(const char* const message,
                                                    WebFrame* old_frame,
                                                    WebFrame* new_frame) {
  SCOPED_TRACE(message);

  EXPECT_TRUE(old_frame->FirstChild());

  if (new_frame->IsWebLocalFrame()) {
    old_frame->Swap(new_frame->ToWebLocalFrame());
  } else {
    frame_test_helpers::SwapRemoteFrame(old_frame,
                                        new_frame->ToWebRemoteFrame());
  }

  EXPECT_FALSE(new_frame->FirstChild());
  EXPECT_FALSE(new_frame->LastChild());
}

TEST_F(WebFrameSwapTest, EventsOnDisconnectedSubDocumentSkipped) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild()->NextSibling();
  EXPECT_TRUE(target_frame);
  SwapAndVerifySubframeConsistency("local->remote", target_frame, remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  WebLocalFrameImpl* local_child =
      web_view_helper_.CreateLocalChild(*remote_frame, "local-inside-remote");

  LocalFrame* main_frame = WebView()->MainFrameImpl()->GetFrame();
  Document* child_document = local_child->GetFrame()->GetDocument();
  EventHandlerRegistry& event_registry =
      local_child->GetFrame()->GetEventHandlerRegistry();

  // Add the non-connected, but local, child document as having an event.
  event_registry.DidAddEventHandler(
      *child_document, EventHandlerRegistry::kTouchStartOrMoveEventBlocking);
  // Passes if this does not crash or DCHECK.
  main_frame->View()->UpdateAllLifecyclePhasesForTest();
}

TEST_F(WebFrameSwapTest, EventsOnDisconnectedElementSkipped) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild()->NextSibling();
  EXPECT_TRUE(target_frame);
  SwapAndVerifySubframeConsistency("local->remote", target_frame, remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  WebLocalFrameImpl* local_child =
      web_view_helper_.CreateLocalChild(*remote_frame, "local-inside-remote");

  LocalFrame* main_frame = WebView()->MainFrameImpl()->GetFrame();

  // Layout ensures that elements in the local_child frame get LayoutObjects
  // attached, but doesn't paint, because the child frame needs to not have
  // been composited for the purpose of this test.
  local_child->GetFrameView()->UpdateStyleAndLayout();
  Document* child_document = local_child->GetFrame()->GetDocument();
  EventHandlerRegistry& event_registry =
      local_child->GetFrame()->GetEventHandlerRegistry();

  // Add the non-connected body element as having an event.
  event_registry.DidAddEventHandler(
      *child_document->body(),
      EventHandlerRegistry::kTouchStartOrMoveEventBlocking);
  // Passes if this does not crash or DCHECK.
  main_frame->View()->UpdateAllLifecyclePhasesForTest();
}

TEST_F(WebFrameSwapTest, SwapParentShouldDetachChildren) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild()->NextSibling();
  EXPECT_TRUE(target_frame);
  SwapAndVerifySubframeConsistency("local->remote", target_frame, remote_frame);

  target_frame = MainFrame()->FirstChild()->NextSibling();
  EXPECT_TRUE(target_frame);

  // Create child frames in the target frame before testing the swap.
  frame_test_helpers::CreateRemoteChild(*remote_frame);

  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  SwapAndVerifySubframeConsistency("remote->local", target_frame, local_frame);

  // FIXME: This almost certainly fires more load events on the iframe element
  // than it should.
  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  std::string content =
      TestWebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("  \n\na\n\nhello\n\nc", content);
}

TEST_F(WebFrameSwapTest, SwapPreservesGlobalContext) {
  v8::HandleScope scope(web_view_helper_.GetAgentGroupScheduler().Isolate());
  v8::Local<v8::Value> window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("window"));
  ASSERT_TRUE(window_top->IsObject());
  v8::Local<v8::Value> original_window =
      MainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("document.querySelector('#frame2').contentWindow;"));
  ASSERT_TRUE(original_window->IsObject());

  // Make sure window reference stays the same when swapping to a remote frame.
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild()->NextSibling();
  frame_test_helpers::SwapRemoteFrame(target_frame, remote_frame);
  v8::Local<v8::Value> remote_window = MainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("document.querySelector('#frame2').contentWindow;"));
  EXPECT_TRUE(original_window->StrictEquals(remote_window));
  // Check that its view is consistent with the world.
  v8::Local<v8::Value> remote_window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource(
          "document.querySelector('#frame2').contentWindow.top;"));
  EXPECT_TRUE(window_top->StrictEquals(remote_window_top));

  // Now check that remote -> local works too, since it goes through a different
  // code path.
  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);
  v8::Local<v8::Value> local_window = MainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("document.querySelector('#frame2').contentWindow;"));
  EXPECT_TRUE(original_window->StrictEquals(local_window));
  v8::Local<v8::Value> local_window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource(
          "document.querySelector('#frame2').contentWindow.top;"));
  EXPECT_TRUE(window_top->StrictEquals(local_window_top));
}

TEST_F(WebFrameSwapTest, SetTimeoutAfterSwap) {
  v8::Isolate* isolate = web_view_helper_.GetAgentGroupScheduler().Isolate();
  v8::HandleScope scope(isolate);
  MainFrame()->ExecuteScript(
      WebScriptSource("savedSetTimeout = window[0].setTimeout"));

  // Swap the frame to a remote frame.
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild();
  frame_test_helpers::SwapRemoteFrame(target_frame, remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  // Invoking setTimeout should throw a security error.
  {
    v8::Local<v8::Value> exception = MainFrame()->ExecuteScriptAndReturnValue(
        WebScriptSource("try {\n"
                        "  savedSetTimeout.call(window[0], () => {}, 0);\n"
                        "} catch (e) { e; }"));
    ASSERT_TRUE(!exception.IsEmpty());
    EXPECT_EQ(
        "SecurityError: Blocked a frame with origin \"http://internal.test\" "
        "from accessing a cross-origin frame.",
        ToCoreString(isolate,
                     exception
                         ->ToString(ToScriptStateForMainWorld(
                                        WebView()->MainFrameImpl()->GetFrame())
                                        ->GetContext())
                         .ToLocalChecked()));
  }
}

TEST_F(WebFrameSwapTest, SwapInitializesGlobal) {
  v8::HandleScope scope(web_view_helper_.GetAgentGroupScheduler().Isolate());

  v8::Local<v8::Value> window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("window"));
  ASSERT_TRUE(window_top->IsObject());

  v8::Local<v8::Value> last_child = MainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("saved = window[2]"));
  ASSERT_TRUE(last_child->IsObject());

  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame()->LastChild(), remote_frame);
  v8::Local<v8::Value> remote_window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("saved.top"));
  EXPECT_TRUE(remote_window_top->IsObject());
  EXPECT_TRUE(window_top->StrictEquals(remote_window_top));

  WebLocalFrame* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame);
  // Committing a navigation in a provisional frame will swap it in.
  frame_test_helpers::LoadFrame(local_frame, "data:text/html,");
  v8::Local<v8::Value> local_window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("saved.top"));
  EXPECT_TRUE(local_window_top->IsObject());
  EXPECT_TRUE(window_top->StrictEquals(local_window_top));
  local_frame->ExecuteScriptAndReturnValue(WebScriptSource("42"));
}

TEST_F(WebFrameSwapTest, RemoteFramesAreIndexable) {
  v8::HandleScope scope(web_view_helper_.GetAgentGroupScheduler().Isolate());

  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame()->LastChild(), remote_frame);
  v8::Local<v8::Value> remote_window =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("window[2]"));
  EXPECT_TRUE(remote_window->IsObject());
  v8::Local<v8::Value> window_length = MainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("window.length"));
  ASSERT_TRUE(window_length->IsInt32());
  EXPECT_EQ(3, window_length.As<v8::Int32>()->Value());
}

TEST_F(WebFrameSwapTest, RemoteFrameLengthAccess) {
  v8::HandleScope scope(web_view_helper_.GetAgentGroupScheduler().Isolate());

  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame()->LastChild(), remote_frame);
  v8::Local<v8::Value> remote_window_length =
      MainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("window[2].length"));
  ASSERT_TRUE(remote_window_length->IsInt32());
  EXPECT_EQ(0, remote_window_length.As<v8::Int32>()->Value());
}

TEST_F(WebFrameSwapTest, RemoteWindowNamedAccess) {
  v8::HandleScope scope(web_view_helper_.GetAgentGroupScheduler().Isolate());

  // TODO(dcheng): Once OOPIF unit test infrastructure is in place, test that
  // named window access on a remote window works. For now, just test that
  // accessing a named property doesn't crash.
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame()->LastChild(), remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);
  v8::Local<v8::Value> remote_window_property =
      MainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("window[2].foo"));
  EXPECT_TRUE(remote_window_property.IsEmpty());
}

TEST_F(WebFrameSwapTest, RemoteWindowToString) {
  v8::Isolate* isolate = web_view_helper_.GetAgentGroupScheduler().Isolate();
  v8::HandleScope scope(isolate);

  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame()->LastChild(), remote_frame);
  v8::Local<v8::Value> to_string_result =
      MainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("Object.prototype.toString.call(window[2])"));
  ASSERT_FALSE(to_string_result.IsEmpty());
  EXPECT_STREQ("[object Object]",
               *v8::String::Utf8Value(isolate, to_string_result));
}

// TODO(alexmos, dcheng): This test and some other OOPIF tests use
// very little of the test fixture support in WebFrameSwapTest.  We should
// clean these tests up.
TEST_F(WebFrameSwapTest, FramesOfRemoteParentAreIndexable) {
  v8::HandleScope scope(web_view_helper_.GetAgentGroupScheduler().Isolate());

  WebRemoteFrame* remote_parent_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame(), remote_parent_frame);
  remote_parent_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  WebLocalFrame* child_frame =
      web_view_helper_.CreateLocalChild(*remote_parent_frame);
  frame_test_helpers::LoadFrame(child_frame, base_url_ + "subframe-hello.html");

  v8::Local<v8::Value> window =
      child_frame->ExecuteScriptAndReturnValue(WebScriptSource("window"));
  v8::Local<v8::Value> child_of_remote_parent =
      child_frame->ExecuteScriptAndReturnValue(
          WebScriptSource("parent.frames[0]"));
  EXPECT_TRUE(child_of_remote_parent->IsObject());
  EXPECT_TRUE(window->StrictEquals(child_of_remote_parent));

  v8::Local<v8::Value> window_length = child_frame->ExecuteScriptAndReturnValue(
      WebScriptSource("parent.frames.length"));
  ASSERT_TRUE(window_length->IsInt32());
  EXPECT_EQ(1, window_length.As<v8::Int32>()->Value());
}

// Check t
```