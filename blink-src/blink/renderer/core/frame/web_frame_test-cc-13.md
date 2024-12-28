Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_frame_test.cc`. I need to analyze each test case and describe what it's testing. If a test relates to JavaScript, HTML, or CSS, I need to provide a concrete example. For tests involving logical reasoning, I should create a hypothetical input and output. If a test addresses common user or programming errors, I need to illustrate those with examples. Finally, I need to provide a concise overall summary of the file's purpose, keeping in mind this is part 14 of 19.

Here's a breakdown of the test cases:

1. **FrameElementInFramesWithRemoteParent**: Checks if accessing `window.frameElement` in a child frame with a remote parent frame doesn't crash and that it returns `null` due to cross-origin restrictions.
2. **HistoryCommitTypeAfterExistingRemoteToLocalSwap**: Verifies that the history commit type is `Standard` when swapping a remote frame to a local frame after commits have occurred.
3. **NavigateRemoteFrameViaLocation**: Tests navigating a remote frame using `location.href` and that the navigation is intercepted.
4. **WindowOpenOnRemoteFrame**: Checks the behavior of `window.open()` on a remote frame, including opening a new URL and targeting an existing named frame.
5. **WindowOpenRemoteClose**: Tests closing a remote window using `window.close()`, verifying that it requires the window to be opened by a script.
6. **WindowCloseOnDetach**: Ensures that calling `window.close()` during WebView detachment (e.g., closing the browser) doesn't crash.
7. **NavigateRemoteToLocalWithOpener**: Checks the security origin of a newly swapped-in local frame when it has an opener on a different origin.
8. **SwapWithOpenerCycle**: Verifies that swapping a remote frame with an opener cycle to a local frame doesn't crash and preserves the opener cycle.
9. **DetachRemoteFrame**: Tests detaching a remote child frame.
10. **CrossDomainAccessErrorsUseCallingWindow**: Checks that console errors related to cross-origin access (like navigation and setting iframe `src`) are reported in the calling window's console.
11. **ResizeInvalidatesDeviceMediaQueries**: Tests that resizing the browser window triggers re-evaluation of device-specific media queries.
12. **DeviceEmulationTest.DeviceSizeInvalidatedOnResize**: Verifies that device size emulation settings are applied and updated correctly on resize.
13. **DeviceEmulationTest.PointerAndHoverTypes**: Checks the values of pointer and hover media features when touch event emulation is enabled.
14. **CreateLocalChildWithPreviousSibling**: Tests creating local child frames with specified previous siblings, ensuring the correct frame tree structure.
15. **SendBeaconFromChildWithRemoteMainFrame**: Checks if `navigator.sendBeacon()` works correctly in a local child frame when the main frame is remote.
16. **SiteForCookiesFromChildWithRemoteMainFrame**: Verifies that the `siteForCookies` property of a document in a local child frame with a remote main frame is correctly determined.
17. **RemoteToLocalSwapOnMainFrameInitializesCoreFrame**: Ensures that performing a remote-to-local swap on the main frame properly initializes the core frame.
18. **PausedPageLoadWithRemoteMainFrame**: Tests that the `ScopedPagePauser` correctly pauses and resumes page loads, including in child frames.
19. **WebFrameOverscrollTest**:  A series of tests related to overscroll behavior, checking accumulated overscroll and unused delta values on root and non-root frames.
这是 `blink/renderer/core/frame/web_frame_test.cc` 文件的第 14 部分，主要包含关于 `WebFrame` 及其相关操作的测试，特别是涉及到 **跨域 (cross-origin)**、**远程 Frame (RemoteFrame)** 和 **本地 Frame (LocalFrame)** 之间的交互和转换。

以下是代码段中各个测试用例的功能及其与 JavaScript, HTML, CSS 的关系，逻辑推理，以及可能的用户或编程错误：

**功能归纳:**

这一部分主要测试了以下 `WebFrame` 的功能：

* **跨域 Frame 的 `frameElement` 访问:** 验证了当子 Frame 的父 Frame 是远程的且跨域时，访问 `window.frameElement` 不会崩溃，并会返回 `null`。
* **远程 Frame 切换为本地 Frame 后的历史记录提交类型:**  测试了在已经提交过导航的远程 Frame 切换为本地 Frame 后，历史记录的提交类型应为 `Standard`。
* **通过 `location` 导航远程 Frame:** 验证了可以通过 JavaScript 的 `location.href` 来导航远程 Frame，并且导航请求会被拦截。
* **在远程 Frame 上使用 `window.open()`:** 测试了在远程 Frame 上调用 `window.open()` 的行为，包括打开新的 URL 和指向已命名的 Frame。
* **关闭远程窗口:**  测试了如何通过 JavaScript 关闭远程窗口，并验证了只有当窗口是被脚本打开时才能成功关闭。
* **在 Detach 时关闭窗口:**  测试了在 `WebView` 被关闭导致文档 Detach 时调用 `window.close()` 不会发生崩溃。
* **带有 Opener 的远程 Frame 切换为本地 Frame:** 验证了当一个带有 opener 的远程 Frame 切换为本地 Frame 后，其安全来源的正确性。
* **Opener 循环时的 Frame 切换:**  测试了当存在 opener 循环时，将远程 Frame 切换为本地 Frame 不会崩溃，并且 opener 关系会被保留。
* **Detaching 远程 Frame:**  测试了分离远程子 Frame 的功能。
* **跨域访问错误使用调用窗口的控制台:**  验证了跨域访问子 Frame 资源（如导航、设置 `src`）时产生的错误信息会显示在调用窗口的控制台中。
* **调整大小使设备媒体查询失效:** 测试了调整浏览器窗口大小会触发重新评估设备相关的媒体查询。
* **设备仿真下的尺寸变化:** 验证了在设备仿真模式下，调整窗口大小会影响页面中获取到的设备尺寸信息。
* **获取 Pointer 和 Hover 类型:** 测试了在设备仿真模式下，是否能正确获取 pointer 和 hover 类型的媒体特性。
* **创建带有前一个兄弟元素的本地子 Frame:**  测试了创建本地子 Frame 时指定前一个兄弟元素的功能，以控制子 Frame 的插入顺序。
* **从带有远程主 Frame 的子 Frame 发送 Beacon:**  验证了在主 Frame 是远程的情况下，子 Frame 可以正常使用 `navigator.sendBeacon()` 发送数据。
* **带有远程主 Frame 的子 Frame 的 Cookie Site:** 测试了在主 Frame 是远程的情况下，子 Frame 的 `document.siteForCookies` 属性是否正确。
* **在主 Frame 上进行远程到本地切换时初始化 CoreFrame:** 确保在主 Frame 上执行远程到本地的切换操作后，CoreFrame 能够正确初始化。
* **带有远程主 Frame 的暂停页面加载:** 测试了 `ScopedPagePauser` 能否正确暂停和恢复包含远程主 Frame 的页面的加载，以及其子 Frame 的加载。
* **WebFrame 的 Overscroll 测试:** 测试了 Overscroll 的行为，包括累积 Overscroll 量和未使用的 Delta 值。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **`window.frameElement` (JavaScript):**
    * **功能:**  允许 JavaScript 访问当前 Frame 的父 HTML 元素 (`<iframe>` 或 `<frame>`)。
    * **示例:**  在 `FrameElementInFramesWithRemoteParent` 测试中，使用了 `child_frame->ExecuteScriptAndReturnValue(WebScriptSource("window.frameElement"))` 来执行 JavaScript 代码并获取 `window.frameElement` 的值。由于跨域，预期返回 `null`。
* **`location.href` (JavaScript):**
    * **功能:** 用于获取或设置当前窗口或 Frame 的 URL，可以用来进行页面导航。
    * **示例:** 在 `NavigateRemoteFrameViaLocation` 测试中，使用了 `MainFrame()->ExecuteScript(WebScriptSource("document.getElementsByTagName('iframe')[0].contentWindow.location = 'data:text/html,hi'"))` 来尝试通过 JavaScript 修改 iframe 的 `location.href` 进行导航。
* **`window.open()` (JavaScript):**
    * **功能:** 用于打开一个新的浏览器窗口或查找已命名的窗口。
    * **示例:** 在 `WindowOpenOnRemoteFrame` 测试中，使用了 `main_window->open(script_state->GetIsolate(), destination, AtomicString("frame1"), "", exception_state)` 来模拟通过 JavaScript 打开新窗口或定位已命名的 Frame。
* **`window.close()` (JavaScript):**
    * **功能:** 用于关闭当前窗口。
    * **示例:** 在 `RemoteWindowCloseTest` 和 `WebFrameTest` 中，使用了 `remote_frame->DomWindow()->close(local_script_state->GetIsolate())` 和 `local_frame->DomWindow()->close()` 来测试关闭窗口的行为。
* **`navigator.sendBeacon()` (JavaScript):**
    * **功能:**  允许异步地向服务器发送少量数据，而不会延迟页面的卸载或导航。
    * **示例:** 在 `SendBeaconFromChildWithRemoteMainFrame` 测试中，加载了一个包含 `navigator.sendBeacon()` 调用的 HTML 文件来验证其功能。
* **`document.siteForCookies` (JavaScript):**
    * **功能:**  返回用于 Cookie 策略的站点。
    * **示例:** 在 `SiteForCookiesFromChildWithRemoteMainFrame` 测试中，检查了 `local_frame->GetDocument().SiteForCookies()` 的值。
* **`<iframe>` (HTML):**
    * **功能:**  用于在当前 HTML 页面中嵌入另一个 HTML 页面。
    * **示例:**  在多个测试中，例如 `NavigateRemoteFrameViaLocation` 和 `CrossDomainAccessErrorsUseCallingWindow`，都涉及到操作 `<iframe>` 元素，例如获取其 `contentWindow` 或设置其 `src` 属性。
* **媒体查询 (CSS):**
    * **功能:**  允许根据不同的设备或环境特性应用不同的 CSS 样式。
    * **示例:** 在 `ResizeInvalidatesDeviceMediaQueries` 和 `DeviceEmulationTest` 中，测试了调整窗口大小是否会触发媒体查询的重新评估，影响元素的样式和尺寸。HTML 文件 (`device_media_queries.html` 和 `device_emulation.html`) 中会包含基于不同屏幕尺寸设置样式的 CSS 规则。

**逻辑推理及假设输入与输出:**

* **`FrameElementInFramesWithRemoteParent`:**
    * **假设输入:** 一个 HTML 页面包含一个 `<iframe>`，该 iframe 的父 Frame 是一个来自不同域的远程 Frame。
    * **预期输出:**  在子 Frame 的 JavaScript 中执行 `window.frameElement` 应该返回 `null`。
* **`HistoryCommitTypeAfterExistingRemoteToLocalSwap`:**
    * **假设输入:** 一个页面包含一个远程 Frame，该 Frame 已经进行了一些导航。然后，该远程 Frame 被切换为一个本地 Frame。
    * **预期输出:**  在本地 Frame 提交导航时，其历史记录提交类型应为 `Standard`。
* **`NavigateRemoteFrameViaLocation`:**
    * **假设输入:** 一个包含远程 iframe 的页面，尝试通过 JavaScript 设置该 iframe 的 `contentWindow.location` 为一个 `data:` URL。
    * **预期输出:**  远程 Frame 的 `OpenURL` 方法会被调用，并且拦截到的 URL 参数应该与设置的 `data:` URL 一致。

**用户或编程常见的使用错误及举例说明:**

* **尝试跨域访问 `frameElement`:**  开发者可能会尝试在子 Frame 中访问 `window.frameElement` 并期望获取到父 Frame 的 DOM 元素，但如果父 Frame 是跨域的，这种访问会被浏览器阻止，返回 `null`。开发者需要理解浏览器的同源策略。
* **在未被脚本打开的窗口上调用 `window.close()`:** 用户可能会尝试通过控制台或其他方式获取到一个并非由脚本打开的窗口的引用，并调用 `close()` 方法，但这通常不会生效。例如，直接打开的浏览器窗口不能通过脚本轻易关闭。
* **错误地认为远程 Frame 和本地 Frame 的行为完全一致:**  开发者可能会假设对本地 Frame 的操作可以直接应用于远程 Frame，而忽略了跨进程通信和隔离带来的差异。例如，直接操作远程 Frame 的 DOM 可能会导致错误或不可预测的行为。
* **没有考虑设备仿真对媒体查询的影响:**  开发者在进行前端开发时，如果没有启用或正确配置设备仿真，可能会在桌面浏览器上看到与目标设备不同的样式效果，导致调试困难。

**总结:**

作为第 14 部分，这段代码继续深入测试了 `WebFrame` 在复杂场景下的行为，特别是聚焦于远程 Frame 和本地 Frame 之间的交互，以及与浏览器安全策略（如同源策略）相关的特性。它涵盖了 Frame 的生命周期管理、导航、窗口操作、安全限制以及与渲染相关的特性（如媒体查询和 Overscroll）。这部分测试确保了 Blink 引擎在处理 Frame 切换、跨域访问和设备仿真等功能时的稳定性和正确性，并帮助开发者避免常见的编程错误。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第14部分，共19部分，请归纳一下它的功能

"""
hat frames with a remote parent don't crash while accessing
// window.frameElement.
TEST_F(WebFrameSwapTest, FrameElementInFramesWithRemoteParent) {
  v8::HandleScope scope(web_view_helper_.GetAgentGroupScheduler().Isolate());

  WebRemoteFrame* remote_parent_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame(), remote_parent_frame);
  remote_parent_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  WebLocalFrame* child_frame =
      web_view_helper_.CreateLocalChild(*remote_parent_frame);
  frame_test_helpers::LoadFrame(child_frame, base_url_ + "subframe-hello.html");

  v8::Local<v8::Value> frame_element = child_frame->ExecuteScriptAndReturnValue(
      WebScriptSource("window.frameElement"));
  // frameElement should be null if cross-origin.
  ASSERT_FALSE(frame_element.IsEmpty());
  EXPECT_TRUE(frame_element->IsNull());
}

class RemoteToLocalSwapWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  ~RemoteToLocalSwapWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidCommitNavigation(
      WebHistoryCommitType history_commit_type,
      bool should_reset_browser_interface_broker,
      const ParsedPermissionsPolicy& permissions_policy_header,
      const DocumentPolicyFeatureState& document_policy_header) override {
    history_commit_type_ = history_commit_type;
  }

  WebHistoryCommitType HistoryCommitType() const {
    return *history_commit_type_;
  }

  std::optional<WebHistoryCommitType> history_commit_type_;
};

// The commit type should be Standard if we are swapping a RemoteFrame to a
// LocalFrame after commits have already happened in the frame.  The browser
// process will inform us via setCommittedFirstRealLoad.
TEST_F(WebFrameSwapTest, HistoryCommitTypeAfterExistingRemoteToLocalSwap) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild();
  ASSERT_TRUE(target_frame);
  frame_test_helpers::SwapRemoteFrame(target_frame, remote_frame);
  ASSERT_TRUE(MainFrame()->FirstChild());
  ASSERT_EQ(MainFrame()->FirstChild(), remote_frame);

  RemoteToLocalSwapWebFrameClient client;
  WebLocalFrameImpl* local_frame =
      web_view_helper_.CreateProvisional(*remote_frame, &client);
  local_frame->SetIsNotOnInitialEmptyDocument();
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  EXPECT_EQ(kWebStandardCommit, client.HistoryCommitType());

  // Manually reset to break WebViewHelper's dependency on the stack allocated
  // TestWebFrameClient.
  Reset();
}

class RemoteFrameHostInterceptor : public FakeRemoteFrameHost {
 public:
  RemoteFrameHostInterceptor() = default;
  ~RemoteFrameHostInterceptor() override = default;

  // FakeRemoteFrameHost:
  void OpenURL(mojom::blink::OpenURLParamsPtr params) override {
    intercepted_params_ = std::move(params);
  }

  const mojom::blink::OpenURLParamsPtr& GetInterceptedParams() {
    return intercepted_params_;
  }

 private:
  mojom::blink::OpenURLParamsPtr intercepted_params_;
};

TEST_F(WebFrameSwapTest, NavigateRemoteFrameViaLocation) {
  RemoteFrameHostInterceptor interceptor;
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild();
  ASSERT_TRUE(target_frame);
  frame_test_helpers::SwapRemoteFrame(target_frame, remote_frame,
                                      interceptor.BindNewAssociatedRemote());
  ASSERT_TRUE(MainFrame()->FirstChild());
  ASSERT_EQ(MainFrame()->FirstChild(), remote_frame);

  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin::CreateFromString("http://127.0.0.1"), false);
  MainFrame()->ExecuteScript(
      WebScriptSource("document.getElementsByTagName('iframe')[0]."
                      "contentWindow.location = 'data:text/html,hi'"));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(interceptor.GetInterceptedParams());
  EXPECT_EQ(ToKURL("data:text/html,hi"),
            KURL(interceptor.GetInterceptedParams()->url));

  // Manually reset to break WebViewHelper's dependency on the stack allocated
  // TestWebFrameClient.
  Reset();
}

TEST_F(WebFrameSwapTest, WindowOpenOnRemoteFrame) {
  // This test needs explicitly named iframes due to the open() call below.
  frame_test_helpers::LoadFrame(MainFrame(),
                                base_url_ + "named-frame-a-b-c.html");

  RemoteFrameHostInterceptor interceptor;
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame()->FirstChild(), remote_frame,
                                      interceptor.BindNewAssociatedRemote());
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  ASSERT_TRUE(MainFrame()->FirstChild()->IsWebRemoteFrame());
  LocalDOMWindow* main_window =
      To<WebLocalFrameImpl>(MainFrame())->GetFrame()->DomWindow();

  String destination = "data:text/html:destination";
  NonThrowableExceptionState exception_state;
  ScriptState* script_state =
      ToScriptStateForMainWorld(main_window->GetFrame());
  ScriptState::Scope entered_context_scope(script_state);
  v8::Context::BackupIncumbentScope incumbent_context_scope(
      script_state->GetContext());
  main_window->open(script_state->GetIsolate(), destination,
                    AtomicString("frame1"), "", exception_state);
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(interceptor.GetInterceptedParams());
  EXPECT_EQ(KURL(interceptor.GetInterceptedParams()->url), KURL(destination));

  // Pointing a named frame to an empty URL should just return a reference to
  // the frame's window without navigating it.
  DOMWindow* result =
      main_window->open(script_state->GetIsolate(), "", AtomicString("frame1"),
                        "", exception_state);
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(interceptor.GetInterceptedParams());
  EXPECT_EQ(KURL(interceptor.GetInterceptedParams()->url), KURL(destination));
  EXPECT_EQ(result, WebFrame::ToCoreFrame(*remote_frame)->DomWindow());

  Reset();
}

// blink::mojom::RemoteMainFrameHost instance that intecepts CloseWindowSoon()
// mojo calls and provides a getter to know if it was ever called.
class TestRemoteMainFrameHostForWindowClose : public FakeRemoteMainFrameHost {
 public:
  TestRemoteMainFrameHostForWindowClose() = default;
  ~TestRemoteMainFrameHostForWindowClose() override = default;

  // FakeRemoteMainFrameHost:
  void RouteCloseEvent() override { remote_window_closed_ = true; }

  bool remote_window_closed() const { return remote_window_closed_; }

 private:
  bool remote_window_closed_ = false;
};

class RemoteWindowCloseTest : public WebFrameTest {
 public:
  RemoteWindowCloseTest() = default;
  ~RemoteWindowCloseTest() override = default;

  bool Closed() const { return remote_main_frame_host_.remote_window_closed(); }

  TestRemoteMainFrameHostForWindowClose* remote_main_frame_host() {
    return &remote_main_frame_host_;
  }

 private:
  TestRemoteMainFrameHostForWindowClose remote_main_frame_host_;
};

TEST_F(RemoteWindowCloseTest, WindowOpenRemoteClose) {
  frame_test_helpers::WebViewHelper main_web_view;
  main_web_view.Initialize();

  // Create a remote window that will be closed later in the test.
  frame_test_helpers::WebViewHelper popup;
  popup.InitializeRemote(nullptr, nullptr);
  popup.GetWebView()->DidAttachRemoteMainFrame(
      remote_main_frame_host()->BindNewAssociatedRemote(),
      mojo::AssociatedRemote<mojom::blink::RemoteMainFrame>()
          .BindNewEndpointAndPassDedicatedReceiver());

  LocalFrame* local_frame = main_web_view.LocalMainFrame()->GetFrame();
  RemoteFrame* remote_frame = popup.RemoteMainFrame()->GetFrame();

  remote_frame->SetOpenerDoNotNotify(local_frame);

  // Attempt to close the window, which should fail as it isn't opened
  // by a script.
  ScriptState* local_script_state = ToScriptStateForMainWorld(local_frame);
  ScriptState::Scope entered_context_scope(local_script_state);
  v8::Context::BackupIncumbentScope incumbent_context_scope(
      local_script_state->GetContext());
  remote_frame->DomWindow()->close(local_script_state->GetIsolate());
  EXPECT_FALSE(Closed());

  // Marking it as opened by a script should now allow it to be closed.
  remote_frame->GetPage()->SetOpenedByDOM();
  remote_frame->DomWindow()->close(local_script_state->GetIsolate());

  // The request to close the remote window is not immediately sent to make sure
  // that the JS finishes executing, so we need to wait for pending tasks first.
  RunPendingTasks();
  EXPECT_TRUE(Closed());
}

// Tests that calling window.close() when detaching document as a result of
// closing the WebView shouldn't crash. This is a regression test for
// https://crbug.com/5058796.
TEST_F(WebFrameTest, WindowCloseOnDetach) {
  // Open a page that calls window.close() from its pagehide handler.
  RegisterMockedHttpURLLoad("close-on-pagehide.html");
  frame_test_helpers::WebViewHelper main_web_view;
  main_web_view.InitializeAndLoad(base_url_ + "close-on-pagehide.html");

  // Mark the Page as opened by DOM so that window.close() will work.
  LocalFrame* local_frame = main_web_view.LocalMainFrame()->GetFrame();
  local_frame->GetPage()->SetOpenedByDOM();

  // Reset the WebView, which will detach the document, triggering the pagehide
  // handler, eventually calling window.close().
  main_web_view.Reset();

  // window.close() should synchronously mark the page as closed.
  EXPECT_TRUE(local_frame->DomWindow()->closed());

  // We used to still post a task to close the WebView even after the WebView is
  // reset, causing a crash when the task runs. Now we won't post the task, and
  // the crash should not happen. Verify that we won't crash if we run pending
  // tasks.
  RunPendingTasks();
}

TEST_F(WebFrameTest, NavigateRemoteToLocalWithOpener) {
  frame_test_helpers::WebViewHelper main_web_view;
  main_web_view.Initialize();
  WebLocalFrame* main_frame = main_web_view.LocalMainFrame();

  // Create a popup with a remote frame and set its opener to the main frame.
  frame_test_helpers::WebViewHelper popup_helper;
  popup_helper.InitializeRemoteWithOpener(
      main_frame, SecurityOrigin::CreateFromString("http://foo.com"));
  WebRemoteFrame* popup_remote_frame = popup_helper.RemoteMainFrame();
  EXPECT_FALSE(main_frame->GetSecurityOrigin().CanAccess(
      popup_remote_frame->GetSecurityOrigin()));

  // Do a remote-to-local swap in the popup.
  WebLocalFrame* popup_local_frame =
      popup_helper.CreateProvisional(*popup_remote_frame);
  popup_remote_frame->Swap(popup_local_frame);

  // The initial document created in a provisional frame should not be
  // scriptable by any other frame.
  EXPECT_FALSE(main_frame->GetSecurityOrigin().CanAccess(
      popup_helper.LocalMainFrame()->GetSecurityOrigin()));
  EXPECT_TRUE(popup_helper.LocalMainFrame()->GetSecurityOrigin().IsOpaque());
}

TEST_F(WebFrameTest, SwapWithOpenerCycle) {
  // First, create a remote main frame with itself as the opener.
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebRemoteFrame* remote_frame = helper.RemoteMainFrame();
  WebFrame::ToCoreFrame(*helper.RemoteMainFrame())
      ->SetOpenerDoNotNotify(WebFrame::ToCoreFrame(*remote_frame));

  // Now swap in a local frame. It shouldn't crash.
  WebLocalFrame* local_frame = helper.CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);

  // And the opener cycle should still be preserved.
  EXPECT_EQ(local_frame, local_frame->Opener());
}

class CommitTypeWebFrameClient final
    : public frame_test_helpers::TestWebFrameClient {
 public:
  CommitTypeWebFrameClient() = default;
  ~CommitTypeWebFrameClient() override = default;

  WebHistoryCommitType HistoryCommitType() const {
    return history_commit_type_;
  }

  // frame_test_helpers::TestWebFrameClient:
  void DidCommitNavigation(
      WebHistoryCommitType history_commit_type,
      bool should_reset_browser_interface_broker,
      const ParsedPermissionsPolicy& permissions_policy_header,
      const DocumentPolicyFeatureState& document_policy_header) final {
    history_commit_type_ = history_commit_type;
  }

 private:
  WebHistoryCommitType history_commit_type_ = kWebHistoryInertCommit;
};

TEST_F(WebFrameTest, DetachRemoteFrame) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebRemoteFrame* child_frame =
      frame_test_helpers::CreateRemoteChild(*helper.RemoteMainFrame());
  child_frame->Detach();
}

class TestConsoleMessageWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestConsoleMessageWebFrameClient() = default;
  ~TestConsoleMessageWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidAddMessageToConsole(const WebConsoleMessage& message,
                              const WebString& source_name,
                              unsigned source_line,
                              const WebString& stack_trace) override {
    messages.push_back(message);
  }

  Vector<WebConsoleMessage> messages;
};

TEST_F(WebFrameTest, CrossDomainAccessErrorsUseCallingWindow) {
  RegisterMockedHttpURLLoad("hidden_frames.html");
  RegisterMockedChromeURLLoad("hello_world.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  TestConsoleMessageWebFrameClient web_frame_client;
  web_view_helper.InitializeAndLoad(base_url_ + "hidden_frames.html",
                                    &web_frame_client);

  // Create another window with a cross-origin page, and point its opener to
  // first window.
  frame_test_helpers::WebViewHelper popup_web_view_helper;
  TestConsoleMessageWebFrameClient popup_web_frame_client;
  WebViewImpl* popup_view = popup_web_view_helper.InitializeAndLoad(
      chrome_url_ + "hello_world.html", &popup_web_frame_client);
  WebFrame::ToCoreFrame(*popup_view->MainFrame())
      ->SetOpenerDoNotNotify(
          WebFrame::ToCoreFrame(*web_view_helper.GetWebView()->MainFrame()));

  // Attempt a blocked navigation of an opener's subframe, and ensure that
  // the error shows up on the popup (calling) window's console, rather than
  // the target window.
  popup_view->MainFrameImpl()->ExecuteScript(WebScriptSource(
      "try { opener.frames[1].location.href='data:text/html,foo'; } catch (e) "
      "{}"));
  EXPECT_TRUE(web_frame_client.messages.empty());
  ASSERT_EQ(1u, popup_web_frame_client.messages.size());
  EXPECT_TRUE(std::string::npos !=
              popup_web_frame_client.messages[0].text.Utf8().find(
                  "Unsafe attempt to initiate navigation"));

  // Try setting a cross-origin iframe element's source to a javascript: URL,
  // and check that this error is also printed on the calling window.
  popup_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("opener.document.querySelectorAll('iframe')[1].src='"
                      "javascript:alert()'"));
  EXPECT_TRUE(web_frame_client.messages.empty());
  ASSERT_EQ(2u, popup_web_frame_client.messages.size());
  EXPECT_TRUE(
      std::string::npos !=
      popup_web_frame_client.messages[1].text.Utf8().find("Blocked a frame"));

  // Manually reset to break WebViewHelpers' dependencies on the stack
  // allocated WebLocalFrameClients.
  web_view_helper.Reset();
  popup_web_view_helper.Reset();
}

TEST_F(WebFrameTest, ResizeInvalidatesDeviceMediaQueries) {
  RegisterMockedHttpURLLoad("device_media_queries.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "device_media_queries.html",
                                    nullptr, nullptr, ConfigureAndroid);
  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  Element* element = frame->GetDocument()->getElementById(AtomicString("test"));
  ASSERT_TRUE(element);

  display::ScreenInfo screen_info =
      web_view_helper.GetMainFrameWidget()->GetOriginalScreenInfo();
  screen_info.rect = screen_info.available_rect = gfx::Rect(700, 500);
  UpdateScreenInfoAndResizeView(&web_view_helper, screen_info);
  EXPECT_EQ(300, element->OffsetWidth());
  EXPECT_EQ(300, element->OffsetHeight());

  screen_info.rect = screen_info.available_rect = gfx::Rect(710, 500);
  UpdateScreenInfoAndResizeView(&web_view_helper, screen_info);
  EXPECT_EQ(400, element->OffsetWidth());
  EXPECT_EQ(300, element->OffsetHeight());

  screen_info.rect = screen_info.available_rect = gfx::Rect(690, 500);
  UpdateScreenInfoAndResizeView(&web_view_helper, screen_info);
  EXPECT_EQ(200, element->OffsetWidth());
  EXPECT_EQ(300, element->OffsetHeight());

  screen_info.rect = screen_info.available_rect = gfx::Rect(700, 510);
  UpdateScreenInfoAndResizeView(&web_view_helper, screen_info);
  EXPECT_EQ(300, element->OffsetWidth());
  EXPECT_EQ(400, element->OffsetHeight());

  screen_info.rect = screen_info.available_rect = gfx::Rect(700, 490);
  UpdateScreenInfoAndResizeView(&web_view_helper, screen_info);
  EXPECT_EQ(300, element->OffsetWidth());
  EXPECT_EQ(200, element->OffsetHeight());

  screen_info.rect = screen_info.available_rect = gfx::Rect(690, 510);
  UpdateScreenInfoAndResizeView(&web_view_helper, screen_info);
  EXPECT_EQ(200, element->OffsetWidth());
  EXPECT_EQ(400, element->OffsetHeight());
}

class DeviceEmulationTest : public WebFrameTest {
 protected:
  DeviceEmulationTest() {
    RegisterMockedHttpURLLoad("device_emulation.html");
    web_view_helper_.InitializeAndLoad(base_url_ + "device_emulation.html",
                                       nullptr, nullptr);
  }

  void TestResize(const gfx::Size& size, const String& expected_size) {
    display::ScreenInfo screen_info =
        web_view_helper_.GetMainFrameWidget()->GetOriginalScreenInfo();
    screen_info.rect = screen_info.available_rect = gfx::Rect(size);
    UpdateScreenInfoAndResizeView(&web_view_helper_, screen_info);
    EXPECT_EQ(expected_size, DumpSize("test"));
  }

  String DumpSize(const String& id) {
    String code = "dumpSize('" + id + "')";
    v8::HandleScope scope(web_view_helper_.GetAgentGroupScheduler().Isolate());
    ScriptExecutionCallbackHelper callback_helper;
    ExecuteScriptInMainWorld(web_view_helper_.GetWebView()->MainFrameImpl(),
                             code, callback_helper.Callback());
    RunPendingTasks();
    EXPECT_TRUE(callback_helper.DidComplete());
    return callback_helper.SingleStringValue();
  }

  frame_test_helpers::WebViewHelper web_view_helper_;
};

TEST_F(DeviceEmulationTest, DeviceSizeInvalidatedOnResize) {
  DeviceEmulationParams params;
  params.screen_type = mojom::EmulatedScreenType::kMobile;
  web_view_helper_.GetWebView()->EnableDeviceEmulation(params);

  TestResize(gfx::Size(700, 500), "300x300");
  TestResize(gfx::Size(710, 500), "400x300");
  TestResize(gfx::Size(690, 500), "200x300");
  TestResize(gfx::Size(700, 510), "300x400");
  TestResize(gfx::Size(700, 490), "300x200");
  TestResize(gfx::Size(710, 510), "400x400");
  TestResize(gfx::Size(690, 490), "200x200");
  TestResize(gfx::Size(800, 600), "400x400");

  web_view_helper_.GetWebView()->DisableDeviceEmulation();
}

TEST_F(DeviceEmulationTest, PointerAndHoverTypes) {
  web_view_helper_.GetWebView()
      ->GetDevToolsEmulator()
      ->SetTouchEventEmulationEnabled(true, 1);
  EXPECT_EQ("20x20", DumpSize("pointer"));
  web_view_helper_.GetWebView()
      ->GetDevToolsEmulator()
      ->SetTouchEventEmulationEnabled(false, 1);
}

TEST_F(WebFrameTest, CreateLocalChildWithPreviousSibling) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebRemoteFrame* parent = helper.RemoteMainFrame();

  WebLocalFrame* second_frame(helper.CreateLocalChild(*parent, "name2"));
  WebLocalFrame* fourth_frame(helper.CreateLocalChild(
      *parent, "name4", WebFrameOwnerProperties(), second_frame));
  WebLocalFrame* third_frame(helper.CreateLocalChild(
      *parent, "name3", WebFrameOwnerProperties(), second_frame));
  WebLocalFrame* first_frame(helper.CreateLocalChild(*parent, "name1"));

  EXPECT_EQ(first_frame, parent->FirstChild());
  EXPECT_EQ(nullptr, first_frame->PreviousSibling());
  EXPECT_EQ(second_frame, first_frame->NextSibling());

  EXPECT_EQ(first_frame, second_frame->PreviousSibling());
  EXPECT_EQ(third_frame, second_frame->NextSibling());

  EXPECT_EQ(second_frame, third_frame->PreviousSibling());
  EXPECT_EQ(fourth_frame, third_frame->NextSibling());

  EXPECT_EQ(third_frame, fourth_frame->PreviousSibling());
  EXPECT_EQ(nullptr, fourth_frame->NextSibling());
  EXPECT_EQ(fourth_frame, parent->LastChild());

  EXPECT_EQ(parent, first_frame->Parent());
  EXPECT_EQ(parent, second_frame->Parent());
  EXPECT_EQ(parent, third_frame->Parent());
  EXPECT_EQ(parent, fourth_frame->Parent());
}

TEST_F(WebFrameTest, SendBeaconFromChildWithRemoteMainFrame) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebLocalFrame* local_frame =
      helper.CreateLocalChild(*helper.RemoteMainFrame());

  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  RegisterMockedHttpURLLoad("send_beacon.html");
  RegisterMockedHttpURLLoad("reload_post.html");  // url param to sendBeacon()
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "send_beacon.html");
  // Wait for the post.
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(local_frame);
}

TEST_F(WebFrameTest, SiteForCookiesFromChildWithRemoteMainFrame) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote(SecurityOrigin::Create(ToKURL(not_base_url_)));

  WebLocalFrame* local_frame =
      helper.CreateLocalChild(*helper.RemoteMainFrame());

  RegisterMockedHttpURLLoad("foo.html");
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "foo.html");
  EXPECT_TRUE(local_frame->GetDocument().SiteForCookies().IsNull());

#if DCHECK_IS_ON()
  // TODO(crbug.com/1329535): Remove if threaded preload scanner doesn't launch.
  // This is needed because the preload scanner creates a thread when loading a
  // page.
  WTF::SetIsBeforeThreadCreatedForTest();
#endif
  SchemeRegistry::RegisterURLSchemeAsFirstPartyWhenTopLevel("http");
  EXPECT_TRUE(net::SiteForCookies::FromUrl(GURL(not_base_url_))
                  .IsEquivalent(local_frame->GetDocument().SiteForCookies()));
  SchemeRegistry::RemoveURLSchemeAsFirstPartyWhenTopLevel("http");
}

// See https://crbug.com/525285.
TEST_F(WebFrameTest, RemoteToLocalSwapOnMainFrameInitializesCoreFrame) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();

  helper.CreateLocalChild(*helper.RemoteMainFrame());

  // Do a remote-to-local swap of the top frame.
  WebLocalFrame* local_root =
      helper.CreateProvisional(*helper.RemoteMainFrame());
  helper.RemoteMainFrame()->Swap(local_root);

  // Load a page with a child frame in the new root to make sure this doesn't
  // crash when the child frame invokes setCoreFrame.
  RegisterMockedHttpURLLoad("single_iframe.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");
  frame_test_helpers::LoadFrame(local_root, base_url_ + "single_iframe.html");
}

// See https://crbug.com/628942.
TEST_F(WebFrameTest, PausedPageLoadWithRemoteMainFrame) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebRemoteFrameImpl* remote_root = helper.RemoteMainFrame();

  // Check that ScopedPagePauser properly triggers deferred loading for
  // the current Page.
  Page* page = remote_root->GetFrame()->GetPage();
  EXPECT_FALSE(page->Paused());
  {
    ScopedPagePauser pauser;
    EXPECT_TRUE(page->Paused());
  }
  EXPECT_FALSE(page->Paused());

  // Repeat this for a page with a local child frame, and ensure that the
  // child frame's loads are also suspended.
  WebLocalFrameImpl* web_local_child = helper.CreateLocalChild(*remote_root);
  RegisterMockedHttpURLLoad("foo.html");
  frame_test_helpers::LoadFrame(web_local_child, base_url_ + "foo.html");
  LocalFrame* local_child = web_local_child->GetFrame();
  EXPECT_FALSE(page->Paused());
  EXPECT_FALSE(
      local_child->GetDocument()->Fetcher()->GetProperties().IsPaused());
  {
    ScopedPagePauser pauser;
    EXPECT_TRUE(page->Paused());
    EXPECT_TRUE(
        local_child->GetDocument()->Fetcher()->GetProperties().IsPaused());
  }
  EXPECT_FALSE(page->Paused());
  EXPECT_FALSE(
      local_child->GetDocument()->Fetcher()->GetProperties().IsPaused());
}

class WebFrameOverscrollTest
    : public WebFrameTest,
      public testing::WithParamInterface<WebGestureDevice> {
 public:
  WebFrameOverscrollTest() {}

 protected:
  WebGestureEvent GenerateEvent(WebInputEvent::Type type,
                                float delta_x = 0.0,
                                float delta_y = 0.0) {
    WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests(),
                          GetParam());
    // TODO(wjmaclean): Make sure that touchpad device is only ever used for
    // gesture scrolling event types.
    event.SetPositionInWidget(gfx::PointF(100, 100));
    if (type == WebInputEvent::Type::kGestureScrollUpdate) {
      event.data.scroll_update.delta_x = delta_x;
      event.data.scroll_update.delta_y = delta_y;
    } else if (type == WebInputEvent::Type::kGestureScrollBegin) {
      event.data.scroll_begin.delta_x_hint = delta_x;
      event.data.scroll_begin.delta_y_hint = delta_y;
    }
    return event;
  }

  void ScrollBegin(frame_test_helpers::WebViewHelper* web_view_helper,
                   float delta_x_hint,
                   float delta_y_hint) {
    web_view_helper->GetMainFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, delta_x_hint,
                      delta_y_hint));
  }

  void ScrollUpdate(frame_test_helpers::WebViewHelper* web_view_helper,
                    float delta_x,
                    float delta_y) {
    web_view_helper->GetMainFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, delta_x,
                      delta_y));
  }

  void ScrollEnd(frame_test_helpers::WebViewHelper* web_view_helper) {
    web_view_helper->GetMainFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  }

  void ExpectOverscrollParams(
      const mojom::blink::DidOverscrollParamsPtr& params,
      gfx::Vector2dF expected_accumulated_overscroll,
      gfx::Vector2dF expected_latest_overscroll_delta,
      gfx::Vector2dF expected_current_fling_velocity,
      gfx::PointF expected_causal_event_viewport_point,
      cc::OverscrollBehavior expected_overscroll_behavior) {
    // Rounding errors are sometimes too big for DidOverscrollParams::Equals.
    const float kAbsError = 0.001;

    EXPECT_VECTOR2DF_NEAR(expected_accumulated_overscroll,
                          params->accumulated_overscroll, kAbsError);
    EXPECT_VECTOR2DF_NEAR(expected_latest_overscroll_delta,
                          params->latest_overscroll_delta, kAbsError);
    EXPECT_VECTOR2DF_NEAR(expected_current_fling_velocity,
                          params->current_fling_velocity, kAbsError);
    EXPECT_POINTF_NEAR(expected_causal_event_viewport_point,
                       params->causal_event_viewport_point, kAbsError);
    EXPECT_EQ(expected_overscroll_behavior, params->overscroll_behavior);
  }
};

INSTANTIATE_TEST_SUITE_P(All,
                         WebFrameOverscrollTest,
                         testing::Values(WebGestureDevice::kTouchpad,
                                         WebGestureDevice::kTouchscreen));

TEST_P(WebFrameOverscrollTest,
       AccumulatedRootOverscrollAndUnsedDeltaValuesOnOverscroll) {
  RegisterMockedHttpURLLoad("overscroll/overscroll.html");
  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "overscroll/overscroll.html",
                                    nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(200, 200));

  auto* widget = web_view_helper.GetMainFrameWidget();
  auto* layer_tree_host = web_view_helper.GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  // Calculation of accumulatedRootOverscroll and unusedDelta on multiple
  // scrollUpdate.
  ScrollBegin(&web_view_helper, -300, -316);
  ScrollUpdate(&web_view_helper, -308, -316);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(8, 16),
                         gfx::Vector2dF(8, 16), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  ScrollUpdate(&web_view_helper, 0, -13);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(8, 29),
                         gfx::Vector2dF(0, 13), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  ScrollUpdate(&web_view_helper, -20, -13);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(28, 42),
                         gfx::Vector2dF(20, 13), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  // Overscroll is not reported.
  ScrollUpdate(&web_view_helper, 0, 1);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollUpdate(&web_view_helper, 1, 0);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  // Overscroll is reported.
  ScrollUpdate(&web_view_helper, 0, 1000);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(0, -701),
                         gfx::Vector2dF(0, -701), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  // Overscroll is not reported.
  ScrollEnd(&web_view_helper);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());
}

TEST_P(WebFrameOverscrollTest,
       AccumulatedOverscrollAndUnusedDeltaValuesOnDifferentAxesOverscroll) {
  RegisterMockedHttpURLLoad("overscroll/div-overscroll.html");
  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/div-overscroll.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(200, 200));

  auto* widget = web_view_helper.GetMainFrameWidget();
  auto* layer_tree_host = web_view_helper.GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 0, -316);

  // Scroll the Div to the end.
  ScrollUpdate(&web_view_helper, 0, -316);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollEnd(&web_view_helper);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 0, -100);

  // Now On Scrolling DIV, scroll is bubbled and root layer is over-scrolled.
  ScrollUpdate(&web_view_helper, 0, -100);
  ScrollUpdate(&web_view_helper, 0, -100);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(0, 100),
                         gfx::Vector2dF(0, 100), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  // TODO(bokan): This has never worked but by the accident that this test was
  // being run in a WebView without a size. This test should be fixed along with
  // the bug, crbug.com/589320.
  // Page scrolls vertically, but over-scrolls horizontally.
  // EXPECT_CALL(client, didOverscroll(gfx::Vector2dF(-100, 0),
  // gfx::Vector2dF(-
"""


```