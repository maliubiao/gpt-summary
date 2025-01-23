Response:
My thought process for analyzing the provided C++ code snippet and generating the summary involves the following steps:

1. **Identify the Core Purpose:** The filename `web_frame_test.cc` immediately suggests that this code contains unit tests for the `WebFrame` class (or related classes) within the Blink rendering engine. The inclusion of `frame_test_helpers.h` reinforces this.

2. **Break Down by Test Case:**  The code is organized into distinct `TEST_F` blocks. Each `TEST_F` represents a specific test scenario for different aspects of `WebFrame` functionality. I would iterate through each `TEST_F` and try to understand its goal.

3. **Analyze Individual Test Cases (and Group Where Applicable):**

   * **Referrer Policy Tests:** The first block of tests focuses on how referrer policies are set and handled. I recognize the patterns of creating `MockPolicyContainerHost`, setting up policy containers, loading HTML strings with different referrer-related attributes (`meta name='referrer'`, `referrerpolicy`), and then asserting the expected `referrer_` and `referrer_policy_` on the `frame_host`. I'd group these together as testing different ways to specify referrer policy.

   * **Remote Frame Compositing Scale Factor Tests:**  Several tests (`RemoteFrameCompositingScaleFactor`, `RotatedRemoteFrameCompositingScaleFactor`, `ZeroScaleRemoteFrameCompositingScaleFactor`, `LargeScaleRemoteFrameCompositingScaleFactor`) are clearly related. They involve setting up an iframe with different CSS `transform` properties (scaling and rotation) and then checking the `GetCompositingScaleFactor` on the remote frame. I would identify the common theme of testing how parent frame transformations affect the compositing behavior of child remote frames.

   * **Vertical Right-to-Left Scrolling:** The `VerticalRLScrollOffset` test stands out as focusing on scrolling behavior in a specific writing mode (`vertical-rl`). It sets the writing mode, scrolls, and verifies the scroll offsets.

   * **Frame Owner Color Scheme:**  The `FrameOwnerColorScheme` test explores how the `color-scheme` CSS property on a frame owner (like `<frame>`) is inherited by the content of the iframe.

   * **Render Blocking Resource Promotion:** The `RenderBlockingPromotesResource` test uses `SimRequest` and `SimSubresourceRequest` to simulate network requests and check how the `blocking="render"` attribute on a `<script>` tag can dynamically promote the priority of a resource.

   * **Runtime Feature Overrides:** The `SetModifiedFeaturesInOverrideContext` test examines how runtime feature flags are passed and stored during navigations, particularly using `modified_runtime_features` in `WebNavigationParams`.

   * **Iframe Move and Subframe Counts:** The `IframeMoveBeforeConnectedSubframeCount` test focuses on how moving an iframe within the DOM affects the count of connected subframes on different parent elements.

4. **Identify Connections to Web Technologies (HTML, CSS, JavaScript):**  As I analyze each test case, I explicitly look for interactions with HTML elements (`<meta>`, `<iframe>`, `<script>`, `<div>`), CSS properties (`transform`, `writing-mode`, `color-scheme`), and implied interactions with JavaScript (e.g., DOM manipulation in `IframeMoveBeforeConnectedSubframeCount`).

5. **Infer Assumptions and Logic:** For tests involving assertions, I consider the underlying logic. For example, in the referrer policy tests, I infer the browser's default behavior when no policy is specified. In the compositing scale factor tests, I understand the optimization goal of rendering scaled-down iframes at a lower resolution.

6. **Consider Potential User/Programming Errors:** Based on the test scenarios, I think about common mistakes developers might make. For instance, misunderstanding how referrer policies are inherited or how CSS transforms affect iframe rendering could lead to unexpected behavior.

7. **Synthesize and Group:** Finally, I group the related test cases and synthesize a concise summary of the file's functionality, highlighting the areas it covers and providing concrete examples. The fact that it's part 19 of 19 signals that this is likely the last set of tests for this particular file, so a concluding remark about covering various aspects of frame behavior is appropriate.

8. **Structure the Output:** I organize the information into clear sections (Functionality, Relationship to Web Technologies, Logical Inference, User/Programming Errors, Summary) as requested in the prompt, making it easier to understand the purpose and implications of the code.

By following these steps, I can effectively dissect the C++ test code and generate a comprehensive and informative summary that addresses all the points raised in the prompt.
这个文件 `web_frame_test.cc` 是 Chromium Blink 引擎中关于 `WebFrame` 类的单元测试文件。它的主要功能是**测试 `WebFrame` 类的各种行为和功能**，确保其按照预期工作。由于这是第 19 部分，也是最后一部分，这意味着这个文件涵盖了 `WebFrame` 类各种功能的最后一部分测试。

以下是这个文件中代码片段的具体功能分解和与 Web 技术的关系：

**功能列举：**

1. **测试 Referrer Policy 的设置和生效:**
   - 验证通过 `<meta name='referrer' content='...'>` 标签设置 Referrer Policy。
   - 验证通过 `referrerpolicy='...'` 属性设置 Referrer Policy。
   - 验证在没有声明 Referrer Policy 时，默认策略的生效。
   - 验证不同 Referrer Policy 取值 (`origin`, `same-origin`, `no-referrer`) 对请求头中 Referrer 的影响。

2. **测试 Remote Frame 的 Compositing Scale Factor (合成缩放因子):**
   - 验证当父窗口通过 CSS `transform: scale()` 缩放包含 iframe 的元素时，远程 iframe 的合成缩放因子是否正确计算。
   - 验证旋转的 iframe 的合成缩放因子计算是否正确。
   - 验证当 iframe 的 `transform: scale(0)` 时，合成缩放因子是否会设置为一个合理的最小值。
   - 验证当 iframe 的 `transform: scale()` 非常大时，合成缩放因子是否会限制在一个最大值。

3. **测试垂直右到左 (vertical-rl) 书写模式下的滚动偏移:**
   - 验证在设置了 `writing-mode: vertical-rl` 的文档中，设置和获取滚动偏移是否正确。

4. **测试 Frame Owner 的 `color-scheme` 属性:**
   - 验证 frame 标签的 `color-scheme` CSS 属性如何影响 iframe 内容文档的颜色方案。

5. **测试 Render-Blocking 资源的优先级提升:**
   - 验证带有 `blocking="render"` 属性的 `<script>` 标签如何提升资源的加载优先级，即使该脚本还带有 `fetchpriority="low"` 属性。

6. **测试导航提交时 Runtime Feature 的修改:**
   - 验证在导航发生时，通过 `WebNavigationParams` 传递的 `modified_runtime_features` 是否正确地设置到了新文档的 `RuntimeFeatureStateOverrideContext` 中。

7. **测试在 iframe 移动到新的父节点之前和之后的连接子帧计数:**
   - 验证通过 JavaScript 将 iframe 从一个父节点移动到另一个父节点时，父节点的连接子帧计数是否正确更新。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**
    - `<meta name='referrer' content='...'>`:  用于在 HTML 文档中声明文档的 Referrer Policy。 例如：`<meta name='referrer' content='origin'>`。
    - `<iframe></iframe>`:  用于嵌入其他 HTML 页面。本测试中用于模拟远程 frame 的场景。
    - `<script blocking="render" src="script.js"></script>`:  `<script>` 标签的 `blocking="render"` 属性指示该脚本是渲染阻塞的。
    - `<div id=oldParent><iframe></iframe></div>`:  HTML 结构用于测试 DOM 操作和子帧计数。
    - `referrerpolicy='...'`: HTML 元素（如 `<a>`, `<link>`, `<iframe>`) 的属性，用于指定该元素发起的请求的 Referrer Policy。例如：`<iframe referrerpolicy='origin'></iframe>`。
    - `<frameset><frame id=frame></frame></frameset>`: 用于创建 frame 结构以测试 `color-scheme` 的继承。

* **CSS:**
    - `transform: scale(0.5)`: CSS `transform` 属性用于缩放元素，这里用于测试远程 frame 的合成缩放因子。
    - `writing-mode: vertical-rl`: CSS 属性，用于设置文本的排列方向为垂直方向，从右到左。
    - `color-scheme: dark`: CSS 属性，用于指定元素使用的颜色方案。

* **JavaScript:**
    - `new_parent->moveBefore(iframe, nullptr, ASSERT_NO_EXCEPTION);`:  模拟 JavaScript 的 DOM 操作，将 iframe 移动到新的父节点。

**逻辑推理 (假设输入与输出):**

1. **Referrer Policy 测试 (以第 4 个测试用例为例):**
   - **假设输入:** 一个包含 `<iframe>` 标签的 HTML 字符串，该标签带有 `referrerpolicy='origin'` 属性。加载到 `WebFrame` 中。
   - **预期输出:** `frame_host.referrer_` 将会是加载页面的源 (`http://www.test.com/`)，`frame_host.referrer_policy_` 将会是 `network::mojom::ReferrerPolicy::kOrigin`。

2. **Remote Frame Compositing Scale Factor 测试 (以缩放为例):**
   - **假设输入:** 父窗口大小为 800x800，其中包含一个 `<iframe>`，CSS 设置 `transform: scale(0.5)`。
   - **预期输出:** 远程 iframe 的 `GetCompositingScaleFactor()` 将会返回 `0.5f`。

3. **Vertical Right-to-Left 滚动偏移测试:**
   - **假设输入:** 文档的根元素设置了 `writing-mode: vertical-rl`，文档内容超出可视区域。调用 `web_main_frame->SetScrollOffset(gfx::PointF(-100, 100))`。
   - **预期输出:** `web_main_frame->GetScrollOffset()` 将返回 `gfx::PointF(0, 100)`。因为在 `vertical-rl` 模式下，水平滚动会影响 X 坐标，负值会被限制为 0。

**用户或编程常见的使用错误举例:**

1. **Referrer Policy 设置冲突:** 用户可能在 HTML 中同时使用了 `<meta name='referrer'>` 标签和元素的 `referrerpolicy` 属性，可能不清楚哪个会生效（通常元素属性优先级更高）。测试覆盖了这些情况，确保 Blink 按照规范处理。

2. **误解 CSS `transform` 对 iframe 合成的影响:** 开发者可能没有意识到父窗口的 CSS `transform` 会影响子 iframe 的渲染方式。测试验证了 Blink 是否正确地将这些变换信息传递给渲染流程。

3. **不理解 `blocking="render"` 的作用:** 开发者可能不清楚 `blocking="render"` 会提升资源的加载优先级，或者将其与 `async` 或 `defer` 混淆。测试明确了其行为。

4. **在垂直书写模式下错误的滚动偏移计算:** 开发者可能在 `vertical-rl` 模式下仍然按照水平书写模式的习惯来设置滚动偏移，导致意料之外的结果。测试验证了 Blink 在这种模式下的滚动行为。

**归纳其功能 (作为第 19 部分):**

作为 `web_frame_test.cc` 的最后一部分，这段代码继续覆盖了 `WebFrame` 类的一些关键但可能较为细节的功能，包括：

* **细致的 Referrer Policy 处理逻辑:** 涵盖了多种设置方式和取值，确保 Referrer Policy 的正确传递和生效。
* **远程 Frame 合成优化的细节:**  特别是父窗口变换对子窗口渲染的影响，这对于性能优化至关重要。
* **特定书写模式下的行为:** 确保对非标准书写模式的支持正确。
* **资源加载优先级控制的细微之处:**  例如 `blocking="render"` 的行为。
* **导航过程中状态传递的正确性:** 例如 Runtime Feature 的传递。
* **DOM 操作对 Frame 结构的影响:**  例如 iframe 移动后的子帧计数。

总而言之，这个文件通过一系列细致的单元测试，确保 `WebFrame` 类在各种场景下都能正确、稳定地工作，涵盖了与网页加载、渲染、安全和 DOM 操作相关的多个重要方面。由于是最后一部分，可以推断之前的部分已经覆盖了 `WebFrame` 更基础和核心的功能。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第19部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
_host.referrer_policy_,
              network::mojom::ReferrerPolicy::kNever);
    policy_container_host.FlushForTesting();
  }

  {
    // 2.<meta name='referrer' content='origin'>
    MockPolicyContainerHost policy_container_host;
    frame->GetFrame()->DomWindow()->SetPolicyContainer(
        std::make_unique<PolicyContainer>(
            policy_container_host.BindNewEndpointAndPassDedicatedRemote(),
            mojom::blink::PolicyContainerPolicies::New()));
    EXPECT_CALL(policy_container_host,
                SetReferrerPolicy(network::mojom::ReferrerPolicy::kOrigin));
    frame_test_helpers::LoadHTMLString(
        frame, GetHTMLStringForReferrerPolicy("origin", std::string()),
        test_url);
    EXPECT_EQ(frame_host.referrer_, ToKURL("http://www.test.com/"));
    EXPECT_EQ(frame_host.referrer_policy_,
              network::mojom::ReferrerPolicy::kOrigin);
    policy_container_host.FlushForTesting();
  }

  {
    // 3.Without any declared referrer-policy attribute
    MockPolicyContainerHost policy_container_host;
    frame->GetFrame()->DomWindow()->SetPolicyContainer(
        std::make_unique<PolicyContainer>(
            policy_container_host.BindNewEndpointAndPassDedicatedRemote(),
            mojom::blink::PolicyContainerPolicies::New()));
    EXPECT_CALL(policy_container_host, SetReferrerPolicy(_)).Times(0);
    frame_test_helpers::LoadHTMLString(
        frame, GetHTMLStringForReferrerPolicy(std::string(), std::string()),
        test_url);
    EXPECT_EQ(frame_host.referrer_, test_url);
    EXPECT_EQ(frame_host.referrer_policy_,
              ReferrerUtils::MojoReferrerPolicyResolveDefault(
                  network::mojom::ReferrerPolicy::kDefault));
    policy_container_host.FlushForTesting();
  }

  {
    // 4.referrerpolicy='origin'
    MockPolicyContainerHost policy_container_host;
    frame->GetFrame()->DomWindow()->SetPolicyContainer(
        std::make_unique<PolicyContainer>(
            policy_container_host.BindNewEndpointAndPassDedicatedRemote(),
            mojom::blink::PolicyContainerPolicies::New()));
    EXPECT_CALL(policy_container_host, SetReferrerPolicy(_)).Times(0);
    frame_test_helpers::LoadHTMLString(
        frame, GetHTMLStringForReferrerPolicy(std::string(), "origin"),
        test_url);
    EXPECT_EQ(frame_host.referrer_, ToKURL("http://www.test.com/"));
    EXPECT_EQ(frame_host.referrer_policy_,
              network::mojom::ReferrerPolicy::kOrigin);
    policy_container_host.FlushForTesting();
  }

  {
    // 5.referrerpolicy='same-origin'
    MockPolicyContainerHost policy_container_host;
    frame->GetFrame()->DomWindow()->SetPolicyContainer(
        std::make_unique<PolicyContainer>(
            policy_container_host.BindNewEndpointAndPassDedicatedRemote(),
            mojom::blink::PolicyContainerPolicies::New()));
    EXPECT_CALL(policy_container_host, SetReferrerPolicy(_)).Times(0);
    frame_test_helpers::LoadHTMLString(
        frame, GetHTMLStringForReferrerPolicy(std::string(), "same-origin"),
        test_url);
    EXPECT_EQ(frame_host.referrer_, test_url);
    EXPECT_EQ(frame_host.referrer_policy_,
              network::mojom::ReferrerPolicy::kSameOrigin);
    policy_container_host.FlushForTesting();
  }

  {
    // 6.referrerpolicy='no-referrer'
    MockPolicyContainerHost policy_container_host;
    frame->GetFrame()->DomWindow()->SetPolicyContainer(
        std::make_unique<PolicyContainer>(
            policy_container_host.BindNewEndpointAndPassDedicatedRemote(),
            mojom::blink::PolicyContainerPolicies::New()));
    EXPECT_CALL(policy_container_host, SetReferrerPolicy(_)).Times(0);
    frame_test_helpers::LoadHTMLString(
        frame, GetHTMLStringForReferrerPolicy(std::string(), "no-referrer"),
        test_url);
    EXPECT_TRUE(frame_host.referrer_.IsEmpty());
    EXPECT_EQ(frame_host.referrer_policy_,
              network::mojom::ReferrerPolicy::kNever);
    policy_container_host.FlushForTesting();
  }

  web_view_helper.Reset();
}

TEST_F(WebFrameTest, RemoteFrameCompositingScaleFactor) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->Resize(gfx::Size(800, 800));
  InitializeWithHTML(*web_view->MainFrameImpl()->GetFrame(), R"HTML(
      <!DOCTYPE html>
      <style>
        iframe {
          width: 1600px;
          height: 1200px;
          transform-origin: top left;
          transform: scale(0.5);
          border: none;
        }
      </style>
      <iframe></iframe>
  )HTML");

  WebRemoteFrameImpl* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(
      web_view_helper.LocalMainFrame()->FirstChild(), remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  // Call directly into frame view since we need to RunPostLifecycleSteps() too.
  web_view->MainFrameImpl()
      ->GetFrame()
      ->View()
      ->UpdateAllLifecyclePhasesForTest();
  RunPendingTasks();

  // The compositing scale factor tells the OOPIF compositor to raster at a
  // lower scale since the frame is scaled down in the parent webview.
  EXPECT_EQ(remote_frame->GetCompositingRect(), gfx::Rect(0, 0, 1600, 1200));
  EXPECT_EQ(remote_frame->GetFrame()->View()->GetCompositingScaleFactor(),
            0.5f);
}

TEST_F(WebFrameTest, RotatedRemoteFrameCompositingScaleFactor) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->Resize(gfx::Size(800, 800));
  InitializeWithHTML(*web_view->MainFrameImpl()->GetFrame(), R"HTML(
      <!DOCTYPE html>
      <style>
        iframe {
          width: 1600px;
          height: 1200px;
          transform-origin: top left;
          transform: scale(0.5) rotate(45deg);
          border: none;
        }
      </style>
      <iframe></iframe>
  )HTML");

  WebRemoteFrameImpl* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(
      web_view_helper.LocalMainFrame()->FirstChild(), remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  // Call directly into frame view since we need to RunPostLifecycleSteps() too.
  web_view->MainFrameImpl()
      ->GetFrame()
      ->View()
      ->UpdateAllLifecyclePhasesForTest();
  RunPendingTasks();

  // The compositing scale factor tells the OOPIF compositor to raster at a
  // lower scale since the frame is scaled down in the parent webview.
  EXPECT_EQ(remote_frame->GetCompositingRect(), gfx::Rect(0, 0, 1600, 1200));
  EXPECT_EQ(remote_frame->GetFrame()->View()->GetCompositingScaleFactor(),
            0.5f);
}

TEST_F(WebFrameTest, ZeroScaleRemoteFrameCompositingScaleFactor) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->Resize(gfx::Size(800, 800));
  InitializeWithHTML(*web_view->MainFrameImpl()->GetFrame(), R"HTML(
      <!DOCTYPE html>
      <style>
        iframe {
          width: 1600px;
          height: 1200px;
          transform-origin: top left;
          transform: scale(0);
          border: none;
        }
      </style>
      <iframe></iframe>
  )HTML");

  WebRemoteFrameImpl* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(
      web_view_helper.LocalMainFrame()->FirstChild(), remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  // Call directly into frame view since we need to RunPostLifecycleSteps() too.
  web_view->MainFrameImpl()
      ->GetFrame()
      ->View()
      ->UpdateAllLifecyclePhasesForTest();
  RunPendingTasks();

  // The compositing scale factor tells the OOPIF compositor to raster at a
  // reasonable minimum scale even though the iframe's transform scale is zero.
  EXPECT_EQ(remote_frame->GetFrame()->View()->GetCompositingScaleFactor(),
            0.25f);
}

TEST_F(WebFrameTest, LargeScaleRemoteFrameCompositingScaleFactor) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->Resize(gfx::Size(800, 800));
  InitializeWithHTML(*web_view->MainFrameImpl()->GetFrame(), R"HTML(
      <!DOCTYPE html>
      <style>
        iframe {
          width: 1600px;
          height: 1200px;
          transform-origin: top left;
          transform: scale(10.0);
          border: none;
        }
      </style>
      <iframe></iframe>
  )HTML");

  WebRemoteFrameImpl* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(
      web_view_helper.LocalMainFrame()->FirstChild(), remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUniqueOpaque()), false);

  // Call directly into frame view since we need to RunPostLifecycleSteps() too.
  web_view->MainFrameImpl()
      ->GetFrame()
      ->View()
      ->UpdateAllLifecyclePhasesForTest();
  RunPendingTasks();

  // The compositing scale factor is at most 5.0 irrespective of iframe scale.
  EXPECT_EQ(remote_frame->GetFrame()->View()->GetCompositingScaleFactor(),
            5.0f);
}

TEST_F(WebFrameTest, VerticalRLScrollOffset) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->Resize(gfx::Size(800, 800));
  auto* frame = web_view->MainFrameImpl()->GetFrame();
  InitializeWithHTML(*frame, R"HTML(
    <!DOCTYPE html>
    <style>body { margin: 0; }</style>
    <div style="width: 2000px; height: 2000px"></div>
  )HTML");

  frame->GetDocument()->documentElement()->setAttribute(
      html_names::kStyleAttr, AtomicString("writing-mode: vertical-rl"));
  frame->View()->UpdateAllLifecyclePhasesForTest();

  auto* web_main_frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ(gfx::PointF(1200, 0), web_main_frame->GetScrollOffset());
  web_main_frame->SetScrollOffset(gfx::PointF(-100, 100));
  EXPECT_EQ(gfx::PointF(0, 100), web_main_frame->GetScrollOffset());
}

TEST_F(WebFrameTest, FrameOwnerColorScheme) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      "data:text/html,<frameset><frame id=frame></frame></frameset>");

  WebViewImpl* web_view = web_view_helper.GetWebView();

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  HTMLFrameOwnerElement* frame = To<HTMLFrameOwnerElement>(
      document->getElementById(AtomicString("frame")));
  EXPECT_EQ(frame->GetColorScheme(), mojom::blink::ColorScheme::kLight);
  EXPECT_EQ(frame->contentDocument()->GetStyleEngine().GetOwnerColorScheme(),
            mojom::blink::ColorScheme::kLight);

  frame->SetInlineStyleProperty(CSSPropertyID::kColorScheme, "dark");
  EXPECT_EQ(frame->GetColorScheme(), mojom::blink::ColorScheme::kLight);

  UpdateAllLifecyclePhases(web_view);
  EXPECT_EQ(frame->GetColorScheme(), mojom::blink::ColorScheme::kDark);
  EXPECT_EQ(frame->contentDocument()->GetStyleEngine().GetOwnerColorScheme(),
            mojom::blink::ColorScheme::kDark);
}

TEST_F(WebFrameSimTest, RenderBlockingPromotesResource) {
  SimRequest main_request("https://example.com/", "text/html");
  SimSubresourceRequest script_request("https://example.com/script.js",
                                       "text/javascript");

  LoadURL("https://example.com/");
  main_request.Write(R"HTML(
    <!doctype html>
    <script defer fetchpriority="low" src="script.js"></script>
  )HTML");

  Resource* script = GetDocument().Fetcher()->AllResources().at(
      ToKURL("https://example.com/script.js"));

  // Script is fetched at the low priority due to `fetchpriority="low"`.
  ASSERT_TRUE(script);
  EXPECT_EQ(ResourceLoadPriority::kLow,
            script->GetResourceRequest().Priority());

  main_request.Complete(R"HTML(
    <script defer fetchpriority="low" blocking="render" src="script.js"></script>
  )HTML");

  // `blocking=render` promotes the priority to high.
  EXPECT_EQ(ResourceLoadPriority::kHigh,
            script->GetResourceRequest().Priority());

  script_request.Complete();
}

// Verify that modified_runtime_features is correctly set in the
// RuntimeFeatureStateOverrideContext when a navigation is committed.
TEST_F(WebFrameSimTest, SetModifiedFeaturesInOverrideContext) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();

  auto params = std::make_unique<WebNavigationParams>();
  // The url isn't important, just pick something.
  params->url = url_test_helpers::ToKURL("http://www.example.com");

  // Create a modified features value map and give it a value that we can check.
  auto modified_features =
      base::flat_map<::blink::mojom::RuntimeFeature, bool>();
  modified_features[blink::mojom::RuntimeFeature::kTestFeature] = true;
  params->modified_runtime_features = modified_features;

  // Commit the navigation
  frame->CommitNavigation(std::move(params), nullptr);

  // Get the override context and compare the override values map with the
  // modified features map.
  RuntimeFeatureStateOverrideContext* override_context =
      frame->GetFrame()->DomWindow()->GetRuntimeFeatureStateOverrideContext();
  EXPECT_EQ(override_context->GetOverrideValuesForTesting(), modified_features);

  // Do the same thing for a value of "false"
  params = std::make_unique<WebNavigationParams>();
  params->url = url_test_helpers::ToKURL("http://www.example2.com");
  modified_features = base::flat_map<::blink::mojom::RuntimeFeature, bool>();
  modified_features[blink::mojom::RuntimeFeature::kTestFeature] = false;
  params->modified_runtime_features = modified_features;
  frame->CommitNavigation(std::move(params), nullptr);
  override_context =
      frame->GetFrame()->DomWindow()->GetRuntimeFeatureStateOverrideContext();
  EXPECT_EQ(override_context->GetOverrideValuesForTesting(), modified_features);
}

TEST_F(WebFrameTest, IframeMoveBeforeConnectedSubframeCount) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->Resize(gfx::Size(800, 800));
  auto* frame = web_view->MainFrameImpl()->GetFrame();
  InitializeWithHTML(*frame, R"HTML(
    <!DOCTYPE html>
    <body>
      <div id=oldParent><iframe></iframe></div>
      <div id=newParent></div>
    </body>
  )HTML");

  frame->View()->UpdateAllLifecyclePhasesForTest();

  Element* body = frame->GetDocument()->body();
  Element* iframe = frame->GetDocument()->QuerySelector(AtomicString("iframe"));
  Element* old_parent =
      frame->GetDocument()->getElementById(AtomicString("oldParent"));
  Element* new_parent =
      frame->GetDocument()->getElementById(AtomicString("newParent"));

  EXPECT_EQ(body->ConnectedSubframeCount(), 1u);
  EXPECT_EQ(old_parent->ConnectedSubframeCount(), 1u);
  EXPECT_EQ(new_parent->ConnectedSubframeCount(), 0u);

  new_parent->moveBefore(iframe, nullptr, ASSERT_NO_EXCEPTION);
  EXPECT_EQ(body->ConnectedSubframeCount(), 1u);
  EXPECT_EQ(old_parent->ConnectedSubframeCount(), 0u);
  EXPECT_EQ(new_parent->ConnectedSubframeCount(), 1u);
}

}  // namespace blink
```