Response:
Let's break down the thought process for analyzing this `frame_loader_test.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning with examples, common user/programming errors, and how a user might reach the tested code.

2. **Identify the Core Subject:** The file name `frame_loader_test.cc` immediately tells us this is a test file for the `FrameLoader` component in the Blink rendering engine. This is the central point around which all other observations will revolve.

3. **Scan for Key Classes and Functions:** Looking through the `#include` directives and the test definitions (`TEST_F`), we can identify the primary classes being tested and the nature of the tests.
    * `#include "third_party/blink/renderer/core/frame/frame_loader.h"` (implicitly, even though not explicitly included, the test targets it)
    * `FrameLoaderSimTest`, `FrameLoaderJavaScriptUrlWebFrameClient`, `FrameLoaderJavaScriptUrlTest`, `FrameLoaderTest`: These are the test fixture classes, indicating different testing scenarios.
    * `LoadEventProgressBeforeUnloadCanceled`, `Click`, `JavaScriptUrlTargetBlank`, `CtrlClickJavaScriptUrlTargetBlank`, `PolicyContainerIsStoredOnCommitNavigation`: These are the individual test cases, revealing specific aspects of `FrameLoader`'s behavior being verified.

4. **Infer Functionality from Test Names and Code:**  The test names are very descriptive and provide immediate clues about what's being tested:
    * `LoadEventProgressBeforeUnloadCanceled`: Focuses on how the load event progresses when `beforeunload` is involved, specifically when it's canceled. This hints at testing the navigation lifecycle.
    * `Click`, `JavaScriptUrlTargetBlank`, `CtrlClickJavaScriptUrlTargetBlank`:  Clearly test how the `FrameLoader` handles clicks on links with `javascript:` URLs, with different target attributes and modifiers (Ctrl key).
    * `PolicyContainerIsStoredOnCommitNavigation`: Checks if the `PolicyContainer` (related to security policies) is correctly stored when a navigation is committed.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `javascript:` URL tests directly involve JavaScript execution. The `beforeunload` event is also a JavaScript event.
    * **HTML:** The test cases use HTML structures (iframes, links with `href` and `target` attributes) to set up the scenarios. The parsing and interpretation of these HTML elements by the `FrameLoader` is being indirectly tested.
    * **CSS:** While not explicitly tested in *these specific tests*, the `FrameLoader` is responsible for loading and applying CSS. It's important to note that this file's tests *don't* directly cover CSS, but the `FrameLoader`'s broader responsibility includes it.

6. **Reason about Logic and Provide Examples:** For each test case, try to understand the underlying logic being tested and create illustrative examples:
    * **`beforeunload` cancellation:** The test shows the scenario where a user attempts to navigate away, but a JavaScript `beforeunload` handler prevents it. The examples should clearly demonstrate the input (navigation attempt) and the expected output (navigation blocked or allowed).
    * **`javascript:` URLs:** The tests explore different scenarios of clicking links with `javascript:` URLs. The examples should illustrate when the JavaScript is executed and when it's not, based on the `target` attribute and modifier keys.
    * **`PolicyContainer`:**  This test focuses on internal state management during navigation, so the example involves creating a navigation with specific policy settings and verifying that those settings are correctly stored.

7. **Consider User/Programming Errors:** Think about common mistakes related to the tested functionalities:
    * **`beforeunload`:**  Users might be annoyed if a website excessively or incorrectly uses `beforeunload`. Developers might not handle the event properly, leading to unexpected behavior.
    * **`javascript:` URLs:**  While sometimes used legitimately, they can also be a security risk if not handled carefully. Developers might misuse them, and users might encounter unexpected JavaScript execution.
    * **`PolicyContainer`:** While less directly user-facing, incorrect policy handling can lead to security vulnerabilities, which is a major programming error.

8. **Trace User Operations (Debugging Clues):** Think about how a user's actions could lead to the code being executed:
    * **Navigation:** Typing a URL, clicking a link, using the back/forward buttons are all core navigation actions that involve the `FrameLoader`.
    * **`beforeunload`:**  Closing a tab or window, navigating to a different page, or clicking a link that triggers navigation can all invoke the `beforeunload` event.
    * **`javascript:` URLs:**  Clicking on links with this type of URL is the primary way to trigger this functionality.
    * **`target="_blank"`:** Clicking links with this attribute leads to new tabs or windows, influencing how navigations are handled.
    * **Ctrl+Click:**  A common user action for opening links in new tabs.

9. **Structure the Answer:** Organize the findings into logical sections as requested: Functionality, relationship to web technologies (with examples), logical reasoning (with input/output), user/programming errors, and debugging clues.

10. **Refine and Elaborate:**  Review the generated answer and add more details or clarify any ambiguous points. For example, explaining *why* JavaScript URLs with `target="_blank"` are often ignored enhances the explanation. Ensuring the examples are clear and concise is also important.
这个文件 `blink/renderer/core/loader/frame_loader_test.cc` 是 Chromium Blink 引擎中用于测试 `FrameLoader` 组件功能的单元测试文件。`FrameLoader` 负责处理 frame (iframe 或主 frame) 的加载、导航和卸载等核心操作。

以下是该文件的详细功能列表，以及与 JavaScript, HTML, CSS 的关系和示例：

**主要功能:**

1. **测试 Frame 的加载流程:** 验证 `FrameLoader` 在各种场景下正确地加载 HTML 文档。这包括主 frame 和 iframe 的加载，以及各种加载选项和状态。

2. **测试导航行为:**  测试各种导航场景，例如用户点击链接、通过 JavaScript 修改 `window.location`、服务器重定向等。

3. **测试 `beforeunload` 事件:**  重点测试了 `beforeunload` 事件的处理流程，包括用户取消导航和允许导航的情况。这涉及到用户可能丢失未保存数据的场景。

4. **测试 JavaScript URL 的处理:**  专门测试了点击 `href` 为 `javascript:` 的链接时的行为，包括在相同 frame 和新窗口打开的情况。

5. **测试 PolicyContainer 的存储:** 验证在提交导航时，与安全策略相关的 `PolicyContainer` 对象是否被正确存储。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML:** 该文件中的测试用例大量使用了 HTML 字符串来模拟网页内容和结构。这些 HTML 包含 `<iframe>` 标签（用于测试 frame 加载），`<a>` 标签（用于测试链接导航），以及 `<script>` 标签（用于添加 JavaScript 代码）。
    * **例子 (HTML):**
        ```html
        <!DOCTYPE html>
        <html><body>
        <iframe src="subframe-a.html"></iframe>
        <a id="link" href="next-page.html">Next Page</a>
        <a href="javascript:'moo'"></a>
        </body></html>
        ```
        这些 HTML 片段被用来创建测试场景，例如加载包含 iframe 的页面，或包含 JavaScript URL 链接的页面。

* **JavaScript:**  测试用例涉及到 JavaScript 代码的执行和交互。
    * **例子 (JavaScript `beforeunload`):**
        ```javascript
        window.onbeforeunload = (e) => {
          e.returnValue = '';
          e.preventDefault();
        };
        ```
        这个 JavaScript 代码片段被注入到 iframe 中，用于模拟用户尝试离开页面时弹出确认对话框的场景。测试验证了当用户取消对话框时，导航是否被阻止。
    * **例子 (JavaScript URL):** 测试了点击 `href="javascript:'moo'"` 的链接后，JavaScript 代码 `'moo'` 是否被执行，以及在不同 `target` 属性下的行为。
    * **例子 (模拟用户操作):** 测试代码使用 Blink 提供的 API 模拟用户点击事件，例如 `anchor->DispatchSimulatedClick(event);`，这会触发链接的默认行为，可能涉及到 JavaScript 的执行或页面导航。

* **CSS:**  虽然这个特定的测试文件没有直接涉及到 CSS 的测试，但 `FrameLoader` 的职责之一是加载和解析 CSS。在更广泛的 Blink 测试框架中，会有其他专门测试 CSS 加载和应用的测试文件。`FrameLoader` 确保在加载 HTML 后，相关的 CSS 资源能够被正确获取和应用，从而影响页面的渲染。

**逻辑推理 (假设输入与输出):**

* **测试用例: `LoadEventProgressBeforeUnloadCanceled`**
    * **假设输入:** 用户点击一个链接，导致页面尝试导航到新的 URL。当前页面（或其子 frame）注册了 `beforeunload` 事件监听器。
    * **子场景 1 (用户取消 `beforeunload`):**
        * **假设输入:**  `beforeunload` 事件被触发，浏览器弹出确认对话框，用户点击了“取消”按钮。
        * **预期输出:**  导航被取消，当前页面保持不变，`BeforeUnloadStarted()` 状态保持为 `false`。
    * **子场景 2 (用户允许 `beforeunload`):**
        * **假设输入:** `beforeunload` 事件被触发，浏览器弹出确认对话框，用户点击了“确定”按钮（或类似允许导航的按钮）。
        * **预期输出:** 导航继续进行，相关的 frame 的 `BeforeUnloadStarted()` 状态变为 `true`。

* **测试用例: `Click` (JavaScript URL)**
    * **假设输入:** 页面包含一个 `<a href="javascript:'moo'"></a>` 链接。用户点击了这个链接。
    * **预期输出:**  JavaScript 代码 `'moo'` 被执行。在这个测试中，`'moo'` 会被当作文本设置到 `document.documentElement()->innerText()`，因此页面内容会变为 "moo"。

* **测试用例: `JavaScriptUrlTargetBlank`**
    * **假设输入:** 页面包含一个 `<a href="javascript:'moo'" target="_blank"></a>` 链接。用户点击了这个链接。
    * **预期输出:**  由于 `target="_blank"`，新的浏览上下文会被创建，但 `javascript:` URL 不会在新的上下文中执行。测试验证了没有待处理的 JavaScript URL 任务。

**用户或编程常见的使用错误:**

* **过度使用或不当使用 `beforeunload`:**  开发者可能会在不必要的情况下使用 `beforeunload`，或者在处理用户取消导航时出现逻辑错误，导致用户体验下降或数据丢失的风险。例如，忘记正确处理用户取消的情况，导致页面状态不一致。
* **滥用 `javascript:` URLs:** 虽然 `javascript:` URLs 有其用途，但过度或不当使用可能导致安全问题或代码可读性降低。例如，在大型应用中使用复杂的 `javascript:` URLs 进行导航可能会难以维护和调试。
* **对 `target="_blank"` 和 JavaScript URL 的行为理解不足:**  开发者可能没有意识到点击 `target="_blank"` 的 `javascript:` URL 链接通常不会执行 JavaScript 代码，这可能导致意外的行为。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个包含链接的网页。**
2. **该网页可能包含带有 `beforeunload` 事件监听器的脚本。**
3. **用户尝试离开该页面，例如：**
    * 关闭标签页或窗口。
    * 在地址栏输入新的 URL 并回车。
    * 点击页面上的链接导航到其他页面。
    * 点击浏览器的后退或前进按钮。
4. **如果存在 `beforeunload` 监听器，浏览器会触发该事件，并可能显示一个确认对话框。**
5. **用户可以选择 "取消" (阻止导航) 或 "确定" (允许导航)。**  `FrameLoader` 的代码会根据用户的选择进行不同的处理，这正是 `LoadEventProgressBeforeUnloadCanceled` 测试用例所覆盖的场景。

或者：

1. **用户在浏览器中访问一个包含 `href="javascript:..."` 链接的网页。**
2. **用户点击了这个链接。**
3. **`FrameLoader` 会拦截这次点击事件，并根据链接的 `target` 属性和用户的操作（例如是否按下了 Ctrl 键）来决定如何处理 `javascript:` URL。**  相关的测试用例是 `Click`, `JavaScriptUrlTargetBlank`, 和 `CtrlClickJavaScriptUrlTargetBlank`。

或者：

1. **程序或用户发起一次导航到一个新的页面。** 这可能是通过用户在地址栏输入 URL，点击链接，或者通过 JavaScript 代码实现。
2. **在导航过程中，Blink 引擎会创建并管理 `PolicyContainer` 对象，其中包含了与安全策略相关的信息。**
3. **`FrameLoader` 负责提交这次导航，并将 `PolicyContainer` 与新的 frame 关联起来。** `PolicyContainerIsStoredOnCommitNavigation` 测试用例验证了这个过程。

总而言之，`frame_loader_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎的页面加载和导航功能能够正确、安全地运行，并且能够按照 Web 标准处理各种用户交互和 JavaScript 代码。它通过模拟各种场景来验证 `FrameLoader` 的行为，为 Chromium 浏览器的稳定性和安全性提供了保障。

### 提示词
```
这是目录为blink/renderer/core/loader/frame_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/user_agent/user_agent_metadata.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mouse_event_init.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/policy_container.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/page/chrome_client_impl.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

class FrameLoaderSimTest : public SimTest {
 public:
  FrameLoaderSimTest() = default;

  void SetUp() override {
    SimTest::SetUp();
    WebView().MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }
};

// Ensure that the load event progress is progressed through BeforeUnload only
// if the event is uncanceled.
TEST_F(FrameLoaderSimTest, LoadEventProgressBeforeUnloadCanceled) {
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest request_a("https://example.com/subframe-a.html", "text/html");
  SimRequest request_b("https://example.com/subframe-b.html", "text/html");
  SimRequest request_c("https://example.com/subframe-c.html", "text/html");
  SimRequest request_unload("https://example.com/next-page.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe src="subframe-a.html"></iframe>
  )HTML");

  request_a.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe src="subframe-b.html"></iframe>
      <a id="link" href="next-page.html">Next Page</a>
  )HTML");
  request_b.Complete(R"HTML(
      <!DOCTYPE html>
      <script>
        window.onbeforeunload = (e) => {
          e.returnValue = '';
          e.preventDefault();
        };
      </script>
      <iframe src="subframe-c.html"></iframe>
  )HTML");
  request_c.Complete(R"HTML(
      <!DOCTYPE html>
  )HTML");
  Compositor().BeginFrame();

  auto* main_frame = To<LocalFrame>(GetDocument().GetPage()->MainFrame());
  auto* frame_a = To<LocalFrame>(main_frame->Tree().FirstChild());
  auto* frame_b = To<LocalFrame>(frame_a->Tree().FirstChild());
  auto* frame_c = To<LocalFrame>(frame_b->Tree().FirstChild());

  ASSERT_FALSE(main_frame->GetDocument()->BeforeUnloadStarted());
  ASSERT_FALSE(frame_a->GetDocument()->BeforeUnloadStarted());
  ASSERT_FALSE(frame_b->GetDocument()->BeforeUnloadStarted());
  ASSERT_FALSE(frame_c->GetDocument()->BeforeUnloadStarted());

  // We'll only allow canceling a beforeunload if there's a sticky user
  // activation present so simulate a user gesture.
  LocalFrame::NotifyUserActivation(
      frame_b, mojom::UserActivationNotificationType::kTest);

  auto& chrome_client =
      To<ChromeClientImpl>(WebView().GetPage()->GetChromeClient());

  // Simulate the user canceling the navigation away. Since the navigation was
  // "canceled", we expect that each of the frames should remain in their state
  // before the beforeunload was dispatched.
  {
    chrome_client.SetBeforeUnloadConfirmPanelResultForTesting(false);

    // Note: We can't perform a navigation to check this because the
    // beforeunload event is dispatched from content's RenderFrameImpl, Blink
    // tests mock this out using a WebFrameTestProxy which doesn't check
    // beforeunload before navigating.
    ASSERT_FALSE(frame_a->Loader().ShouldClose());

    EXPECT_FALSE(main_frame->GetDocument()->BeforeUnloadStarted());
    EXPECT_FALSE(frame_a->GetDocument()->BeforeUnloadStarted());
    EXPECT_FALSE(frame_b->GetDocument()->BeforeUnloadStarted());
    EXPECT_FALSE(frame_c->GetDocument()->BeforeUnloadStarted());
  }

  // Now test the opposite, the user allowing the navigation away.
  {
    chrome_client.SetBeforeUnloadConfirmPanelResultForTesting(true);
    ASSERT_TRUE(frame_a->Loader().ShouldClose());

    // The navigation was in frame a so it shouldn't affect the parent.
    EXPECT_FALSE(main_frame->GetDocument()->BeforeUnloadStarted());
    EXPECT_TRUE(frame_a->GetDocument()->BeforeUnloadStarted());
    EXPECT_TRUE(frame_b->GetDocument()->BeforeUnloadStarted());
    EXPECT_TRUE(frame_c->GetDocument()->BeforeUnloadStarted());
  }
}

class FrameLoaderJavaScriptUrlWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  void BeginNavigation(std::unique_ptr<WebNavigationInfo> info) override {
    // The initial page is not loaded via a call to `BeginNavigation()`, and
    // javascript: URLs should always be handled internally in Blink, so this
    // should never be reached in tests.
    ASSERT_TRUE(false);
  }
};

class FrameLoaderJavaScriptUrlTest : public SimTest {
  std::unique_ptr<frame_test_helpers::TestWebFrameClient>
  CreateWebFrameClientForMainFrame() override {
    return std::make_unique<FrameLoaderJavaScriptUrlWebFrameClient>();
  }
};

// This is mostly a differential test, to verify that JavaScriptUrlTargetBlank
// and CtrlClickJavaScriptUrlTargetBlank don't unexpectedly pass. That is, if
// this test starts failing, any pass results for the aforementioned tests
// should be considered highly suspicious.
TEST_F(FrameLoaderJavaScriptUrlTest, Click) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <html><body>
      <a href="javascript:'moo'"></a>
      </body></html>
  )HTML");

  // Generate and dispatch a click event.
  MouseEventInit* mouse_initializer = MouseEventInit::Create();
  mouse_initializer->setView(&Window());
  mouse_initializer->setButton(1);

  Event* event =
      MouseEvent::Create(nullptr, event_type_names::kClick, mouse_initializer);
  Element* anchor = GetDocument().QuerySelector(AtomicString("a"));
  anchor->DispatchSimulatedClick(event);

  // Navigations to JavaScript URLs should queue a task:
  // https://whatwg.org/c/browsing-the-web.html#beginning-navigation:navigate-to-a-javascript:-url
  EXPECT_TRUE(GetDocument().HasPendingJavaScriptUrlsForTest());

  base::RunLoop run_loop;
  GetDocument()
      .GetFrame()
      ->GetTaskRunner(TaskType::kNetworking)
      ->PostTask(FROM_HERE, run_loop.QuitClosure());
  run_loop.Run();

  EXPECT_EQ("moo", GetDocument().documentElement()->innerText());
}

// Clicking an anchor with href="javascript:..." and target="_blank" should not
// run the JavaScript URL.
TEST_F(FrameLoaderJavaScriptUrlTest, JavaScriptUrlTargetBlank) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <html><body>
      <a href="javascript:'moo'" target="_blank"></a>
      </body></html>
  )HTML");

  // Generate and dispatch a click event.
  MouseEventInit* mouse_initializer = MouseEventInit::Create();
  mouse_initializer->setView(&Window());
  mouse_initializer->setButton(1);

  Event* event =
      MouseEvent::Create(nullptr, event_type_names::kClick, mouse_initializer);
  Element* anchor = GetDocument().QuerySelector(AtomicString("a"));
  anchor->DispatchSimulatedClick(event);

  // No task should be queued, since this navigation attempt should be ignored.
  EXPECT_FALSE(GetDocument().HasPendingJavaScriptUrlsForTest());
}

// Ctrl+clicking an anchor with href="javascript:..." and target="_blank" should
// not run the JavaScript URL. Regression test for crbug.com/41490237.
TEST_F(FrameLoaderJavaScriptUrlTest, CtrlClickJavaScriptUrlTargetBlank) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <html><body>
      <a href="javascript:'moo'" target="_blank"></a>
      </body></html>
  )HTML");

  // Generate and dispatch a ctrl+click event.
  MouseEventInit* mouse_initializer = MouseEventInit::Create();
  mouse_initializer->setView(&Window());
  mouse_initializer->setButton(1);
  mouse_initializer->setCtrlKey(true);

  Event* event =
      MouseEvent::Create(nullptr, event_type_names::kClick, mouse_initializer);
  Element* anchor = GetDocument().QuerySelector(AtomicString("a"));
  anchor->DispatchSimulatedClick(event);

  // No task should be queued, since this navigation attempt should be ignored.
  EXPECT_FALSE(GetDocument().HasPendingJavaScriptUrlsForTest());
}

class FrameLoaderTest : public testing::Test {
 protected:
  void SetUp() override {
    web_view_helper_.Initialize();
    url_test_helpers::RegisterMockedURLLoad(
        url_test_helpers::ToKURL("https://example.com/foo.html"),
        test::CoreTestDataPath("foo.html"));
  }

  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper web_view_helper_;
};

TEST_F(FrameLoaderTest, PolicyContainerIsStoredOnCommitNavigation) {
  WebViewImpl* web_view_impl = web_view_helper_.Initialize();

  const KURL& url = KURL(NullURL(), "https://www.example.com/bar.html");
  std::unique_ptr<WebNavigationParams> params =
      WebNavigationParams::CreateWithEmptyHTMLForTesting(url);
  MockPolicyContainerHost mock_policy_container_host;
  params->policy_container = std::make_unique<WebPolicyContainer>(
      WebPolicyContainerPolicies{
          network::mojom::CrossOriginEmbedderPolicyValue::kNone,
          network::mojom::ReferrerPolicy::kAlways,
          WebVector<WebContentSecurityPolicy>(),
      },
      mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
  LocalFrame* local_frame =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame());
  local_frame->Loader().CommitNavigation(std::move(params), nullptr);

  EXPECT_EQ(*mojom::blink::PolicyContainerPolicies::New(
                network::CrossOriginEmbedderPolicy(
                    network::mojom::CrossOriginEmbedderPolicyValue::kNone),
                network::mojom::ReferrerPolicy::kAlways,
                Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
                /*anonymous=*/false, network::mojom::WebSandboxFlags::kNone,
                network::mojom::blink::IPAddressSpace::kUnknown,
                /*can_navigate_top_without_user_gesture=*/true,
                /*allow_cross_origin_isolation_under_initial_empty_document=*/
                false),
            local_frame->DomWindow()->GetPolicyContainer()->GetPolicies());
}

}  // namespace blink
```