Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/exported/web_view_test.cc`. This is part 8 of a 9-part file, suggesting a larger test suite. I need to:

1. **Identify the primary purpose of the code:**  It seems to be testing various functionalities of the `WebViewImpl` class in the Blink rendering engine.
2. **Categorize the tests:** Look for patterns or related groups of tests.
3. **Explain the connection to web technologies:** Point out how these tests relate to JavaScript, HTML, and CSS features.
4. **Illustrate with examples:**  Provide specific scenarios or code snippets demonstrating the functionality being tested.
5. **Infer assumptions and outputs:** For logical tests, deduce the expected behavior.
6. **Highlight potential user/developer errors:** Identify common mistakes that these tests might be preventing.
7. **Describe the user path to these tests:** Explain how a user's interaction with a web page might lead to the execution of the tested code.
8. **Summarize the overall function of this part of the test file.**

Based on the code, here's a breakdown of the test categories I see:

* **BeforeUnload Event Handling:** Testing the `beforeunload` event in subframes.
* **Page Pausing:** Tests related to pausing and resuming page loads using `ScopedPagePauser` and `ScopedBrowsingContextGroupPauser`.
* **Closing Pages:**  Testing the paused state when a page is being closed via JavaScript.
* **Viewport Manipulation:** Tests for programmatically controlling the viewport using DevTools emulation features. This includes forcing and resetting the viewport, and how it interacts with device metrics.
* **Printing and Viewport Units:** Tests specifically for how viewport units (vw, vh) are handled during printing, including interactions with page zoom.
* **Resizing with Fixed Position Elements:** Testing for crashes when resizing during printing with fixed position elements.
* **Device Emulation and Scrollbars:**  Verifying that enabling and disabling device emulation correctly manages scrollbar visibility.
* **Zooming with Focused Plugins:** Testing that zooming works even when a plugin has focus.
* **Plugin Detachment during Layout:** Ensuring that detaching a plugin during layout doesn't cause crashes, even if the plugin tries to execute script during destruction.
* **First Input Delay Measurement:** Tests related to accurately measuring and reporting the First Input Delay (FID) metric, including scenarios with keyboard and pointer events. This includes excluding processing time in the FID calculation.
* **Root Layer Attachment:** Testing when the root compositing layer is attached.
* **Force Dark Mode:** Ensuring that enabling forced dark mode triggers a full paint invalidation.
* **Context Menu and Gestures:** Testing interactions between long press and long tap gestures, especially on images.
* **Target URL Updates:** Testing how the target URL is updated, even with invalid URLs.
* **Context Menu in Iframes:** Testing that a context menu can be triggered in an iframe.

Now, I'll synthesize these observations into a structured answer.
这是 `blink/renderer/core/exported/web_view_test.cc` 文件的第 8 部分，主要包含了一系列针对 `WebViewImpl` 类的功能测试。这些测试涵盖了页面生命周期、渲染、用户交互以及与 DevTools 的集成等多个方面。

以下是这一部分测试的功能的详细列举和说明：

**功能列表:**

1. **验证子框架的 `beforeunload` 事件触发:**  测试当主框架卸载时，子框架是否能正确触发 `beforeunload` 事件。
2. **测试嵌套的页面暂停机制:**  使用 `ScopedPagePauser` 和 `ScopedBrowsingContextGroupPauser` 来验证页面加载可以被暂停，并且嵌套的暂停器都能正确工作。
3. **测试关闭页面时的暂停状态:** 验证当使用 JavaScript 关闭窗口时，页面会被标记为正在关闭，并进入暂停状态。
4. **测试强制和重置视口功能:**  验证通过 DevTools 模拟器可以强制设置视口，并且可以正确地重置回原始状态。
5. **测试视口覆盖与设备指标的集成:**  验证 DevTools 的视口覆盖功能如何与设备像素比和缩放等设备指标协同工作。
6. **测试视口覆盖如何适应缩放和滚动:**  验证视口覆盖在页面缩放和滚动发生变化时是否能动态调整。
7. **测试打印时视口单位的调整:** 验证在打印过程中，视口单位（如 `vw` 和 `vh`）能否根据打印页面大小正确计算。
8. **测试打印后页面缩放对 `width` 媒体查询的影响:** 验证在打印操作后，页面缩放比例是否会影响 CSS 媒体查询的结果。
9. **测试页面缩放下的视口单位打印:** 验证在页面缩放的情况下，打印时视口单位的计算是否正确。
10. **测试包含固定定位元素的页面在打印时的缩放操作:**  确保在包含 `position: fixed` 元素的页面进行打印和缩放操作时不会崩溃。
11. **测试设备模拟重置滚动条:**  验证启用和禁用设备模拟后，滚动条的提供者（是视口还是视图）是否会正确切换。
12. **测试插件获得焦点时设置缩放级别:**  验证即使当插件获得焦点时，WebView 的缩放级别也能正常设置。
13. **测试在布局更新中分离插件:** 验证在布局更新过程中分离插件，即使插件在销毁时尝试执行脚本，也不会导致崩溃。
14. **测试首次输入延迟的报告:**  验证首次用户交互（键盘事件）的延迟时间是否能正确报告给文档。
15. **测试输入延迟的报告:** 验证多次用户交互的延迟时间是否能正确记录到直方图中。
16. **测试指针按下和抬起事件的首次输入延迟:** 验证首次输入是 `pointerdown` 事件，直到 `pointerup` 事件发生时，延迟才能正确报告。
17. **测试首次输入延迟排除处理时间:**  验证首次输入延迟的计算是否排除了事件处理的时间。
18. **测试根图层的附加:** 验证根合成图层在合适的生命周期阶段被附加。
19. **测试强制暗黑模式触发重绘:** 验证启用强制暗黑模式后，是否会触发完整的重绘。
20. **回归测试：长按图片后长按图片:**  防止在长按图片后立即长按同一图片时出现问题。
21. **回归测试：更新目标 URL 时使用无效的 URL:** 验证即使目标 URL 无效，也能正确处理。
22. **回归测试：在 iframe 中长按然后长按链接会启动上下文菜单:** 确保在 iframe 中进行特定手势操作能正确触发上下文菜单。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **`beforeunload` 事件:** 测试代码中模拟了页面卸载，这会触发 JavaScript 的 `beforeunload` 事件。开发者可以使用这个事件来提示用户保存未保存的数据。
    ```javascript
    window.addEventListener('beforeunload', function (e) {
      e.preventDefault();
      e.returnValue = ''; // Standard for most browsers
      return ''; // For some older browsers
    });
    ```
    * **关闭窗口 (`window.close()`):** 测试中使用了 JavaScript 的 `window.close()` 方法来模拟关闭窗口的操作，并验证了页面此时的暂停状态。
    * **事件监听 (`addEventListener`)**: 在测试首次输入延迟时，会通过 JavaScript 添加事件监听器，确保事件不会被优化掉。

* **HTML:**
    * **`<iframe>` 标签:**  回归测试涉及到在 `<iframe>` 元素中的链接上进行手势操作。
    * **`<object>` 标签:** 测试插件相关的功能时使用了 `<object>` 标签来嵌入插件。
    * **`<meta name='viewport'>`:** 测试设备模拟和滚动条时使用了 viewport meta 标签来控制视口行为。

* **CSS:**
    * **视口单位 (`vw`, `vh`):** 测试了打印时视口单位的计算，例如在 CSS 中使用 `width: 100vw`。
    * **媒体查询 (`@media`):**  测试了打印后页面缩放对基于 `width` 的媒体查询的影响。
    * **固定定位 (`position: fixed`):**  测试了包含固定定位元素的页面在打印时的行为。
    * **`display: none`:** 在测试插件分离时，使用 CSS 样式 `display: none` 来触发插件的分离。

**逻辑推理、假设输入与输出:**

* **测试嵌套的页面暂停机制:**
    * **假设输入:** 创建 `WebViewImpl` 实例后，依次创建两个嵌套的 `ScopedPagePauser` 对象。
    * **预期输出:** 在任何一个 `ScopedPagePauser` 对象存在期间，`web_view->GetPage()->Paused()` 应该返回 `true`。只有当所有暂停器都被销毁后，该方法才会返回 `false`。

* **测试强制视口功能:**
    * **假设输入:**  加载一个 200x300 的 HTML 页面，然后使用 `ForceViewportForTesting` 方法设置一个偏移量和缩放比例。
    * **预期输出:** `GetDeviceEmulationTransform()` 返回的变换矩阵应该反映设置的偏移量和缩放比例。

**用户或编程常见的使用错误及举例说明:**

* **忘记释放 `ScopedPagePauser`:** 如果开发者创建了 `ScopedPagePauser` 但忘记让其超出作用域或显式销毁，页面可能会一直处于暂停状态，导致加载停滞。
* **在插件销毁时执行脚本:**  如测试 `DetachPluginInLayout` 所示，如果在插件的 `Destroy()` 方法中尝试执行 JavaScript，可能会导致崩溃，因为插件相关的资源可能已经被释放。
* **错误理解视口单位在打印时的行为:**  开发者可能错误地认为打印时的视口单位与屏幕上的视口单位相同，而没有考虑到打印页面大小的影响。测试 `ResizeForPrintingViewportUnits` 就是为了验证这种场景。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个包含子框架的网页。**
2. **用户尝试关闭包含这个子框架的标签页或窗口。** 这会触发主框架的卸载，进而触发子框架的 `beforeunload` 事件（测试 1）。
3. **网站使用了某种机制来暂停页面加载，例如在执行耗时操作前阻止页面渲染。** 这就可能涉及到 `ScopedPagePauser` 或类似的机制（测试 2）。
4. **用户通过 JavaScript 代码尝试关闭当前窗口。** 这会触发页面关闭流程，可能涉及到页面暂停（测试 3）。
5. **开发者使用 Chrome DevTools 的设备模拟功能来调试网站在不同设备上的显示效果。**  这会触发视口的强制设置和重置（测试 4, 5, 6）。
6. **用户尝试打印网页。** 浏览器会根据打印设置调整页面布局，这涉及到视口单位的计算（测试 7, 8, 9, 10）。
7. **用户在启用了设备模拟的情况下浏览网页，可能会注意到滚动条的行为变化。** 这与设备模拟如何影响滚动条的提供者有关（测试 11）。
8. **用户与网页上的插件（例如 Flash）进行交互，并且同时可能触发了浏览器的缩放操作。**  这会触发插件焦点和缩放相关的逻辑（测试 12, 13）。
9. **用户与网页进行交互，例如点击或按下键盘。** 浏览器会记录首次响应用户操作的延迟时间，即首次输入延迟（测试 14, 16, 17）。
10. **网页的渲染过程涉及到图层的创建和管理。** 根图层的附加是渲染过程中的关键步骤（测试 18）。
11. **用户启用了浏览器的强制暗黑模式功能。** 这会导致网页的颜色被调整，需要触发重绘（测试 19）。
12. **用户在触摸屏设备上长按网页上的图片或链接。** 这会触发上下文菜单相关的逻辑（测试 20, 22）。
13. **网页上的链接可能包含一些格式不正确的 URL。** 浏览器需要能够处理这些无效的 URL（测试 21）。

**功能归纳:**

这部分 `web_view_test.cc` 主要集中测试了 `WebViewImpl` 在处理页面生命周期事件（如加载、卸载、关闭）、视口管理（包括 DevTools 模拟）、打印、插件交互、用户输入延迟测量以及一些特定的回归场景下的行为。它确保了 `WebViewImpl` 的核心功能在各种情况下都能正确运行，并且对常见的开发者错误和用户操作有良好的处理机制。

### 提示词
```
这是目录为blink/renderer/core/exported/web_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
->DispatchBeforeUnloadEvent(false);

    Document* child_document = To<LocalFrame>(web_view_helper_.GetWebView()
                                                  ->GetPage()
                                                  ->MainFrame()
                                                  ->Tree()
                                                  .FirstChild())
                                   ->GetDocument();
    EXPECT_TRUE(
        child_document->IsUseCounted(WebFeature::kSubFrameBeforeUnloadFired));
  }
}

// Verify that page loads are deferred until all ScopedPagePausers are
// destroyed.
TEST_F(WebViewTest, NestedPagePauses) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kPausePagesPerBrowsingContextGroup);

  WebViewImpl* web_view = web_view_helper_.Initialize();
  EXPECT_FALSE(web_view->GetPage()->Paused());

  {
    ScopedPagePauser pauser;
    EXPECT_TRUE(web_view->GetPage()->Paused());

    {
      ScopedPagePauser pauser2;
      EXPECT_TRUE(web_view->GetPage()->Paused());
    }

    EXPECT_TRUE(web_view->GetPage()->Paused());
  }

  EXPECT_FALSE(web_view->GetPage()->Paused());
}

// Similar to NestedPagePauses but uses ScopedBrowsingContextGroupPauser
// instead.
TEST_F(WebViewTest, NestedPagePausesPerBrowsingContextGroup) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPausePagesPerBrowsingContextGroup);

  WebViewImpl* web_view = web_view_helper_.Initialize();
  EXPECT_FALSE(web_view->GetPage()->Paused());

  {
    ScopedBrowsingContextGroupPauser pauser(*web_view->GetPage());
    EXPECT_TRUE(web_view->GetPage()->Paused());

    {
      ScopedBrowsingContextGroupPauser pauser2(*web_view->GetPage());
      EXPECT_TRUE(web_view->GetPage()->Paused());
    }

    EXPECT_TRUE(web_view->GetPage()->Paused());
  }

  EXPECT_FALSE(web_view->GetPage()->Paused());
}

TEST_F(WebViewTest, ClosingPageIsPaused) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  Page* page = web_view_helper_.GetWebView()->GetPage();
  EXPECT_FALSE(page->Paused());

  web_view->SetOpenedByDOM();

  auto* main_frame = To<LocalFrame>(page->MainFrame());
  EXPECT_FALSE(main_frame->DomWindow()->closed());

  ScriptState* script_state = ToScriptStateForMainWorld(main_frame);
  ScriptState::Scope entered_context_scope(script_state);
  v8::Context::BackupIncumbentScope incumbent_context_scope(
      script_state->GetContext());

  main_frame->DomWindow()->close(script_state->GetIsolate());
  // The window should be marked closed...
  EXPECT_TRUE(main_frame->DomWindow()->closed());
  // EXPECT_TRUE(page->isClosing());
  // ...but not yet detached.
  EXPECT_TRUE(main_frame->GetPage());

  {
    ScopedPagePauser pauser;
    EXPECT_TRUE(page->Paused());
  }
}

TEST_F(WebViewTest, ForceAndResetViewport) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "200-by-300.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(100, 150));
  SetViewportSize(gfx::Size(100, 150));
  DevToolsEmulator* dev_tools_emulator = web_view_impl->GetDevToolsEmulator();

  gfx::Transform expected_matrix;
  expected_matrix.MakeIdentity();
  EXPECT_EQ(expected_matrix, web_view_impl->GetDeviceEmulationTransform());

  // Override applies transform, sets visible rect, and disables
  // visual viewport clipping.
  gfx::Transform matrix =
      dev_tools_emulator->ForceViewportForTesting(gfx::PointF(50, 55), 2.f);
  expected_matrix = gfx::Transform::MakeScale(2.f);
  expected_matrix.Translate(-50, -55);
  EXPECT_EQ(expected_matrix, matrix);

  // Setting new override discards previous one.
  matrix = dev_tools_emulator->ForceViewportForTesting(gfx::PointF(5.4f, 10.5f),
                                                       1.5f);
  expected_matrix = gfx::Transform::MakeScale(1.5f);
  expected_matrix.Translate(-5.4f, -10.5f);
  EXPECT_EQ(expected_matrix, matrix);

  // Clearing override restores original transform, visible rect and
  // visual viewport clipping.
  matrix = dev_tools_emulator->ResetViewportForTesting();
  expected_matrix.MakeIdentity();
  EXPECT_EQ(expected_matrix, matrix);
}

TEST_F(WebViewTest, ViewportOverrideIntegratesDeviceMetricsOffsetAndScale) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "200-by-300.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(100, 150));

  gfx::Transform expected_matrix;
  expected_matrix.MakeIdentity();
  EXPECT_EQ(expected_matrix, web_view_impl->GetDeviceEmulationTransform());

  DeviceEmulationParams emulation_params;
  emulation_params.scale = 2.f;
  web_view_impl->EnableDeviceEmulation(emulation_params);
  expected_matrix = gfx::Transform::MakeScale(2.f);
  EXPECT_EQ(expected_matrix, web_view_impl->GetDeviceEmulationTransform());

  // Device metrics offset and scale are applied before viewport override.
  emulation_params.viewport_offset = gfx::PointF(5, 10);
  emulation_params.viewport_scale = 1.5f;
  web_view_impl->EnableDeviceEmulation(emulation_params);
  expected_matrix = gfx::Transform::MakeScale(1.5f);
  expected_matrix.Translate(-5, -10);
  expected_matrix.Scale(2.f);
  EXPECT_EQ(expected_matrix, web_view_impl->GetDeviceEmulationTransform());
}

TEST_F(WebViewTest, ViewportOverrideAdaptsToScaleAndScroll) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "200-by-300.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(100, 150));
  SetViewportSize(gfx::Size(100, 150));
  LocalFrameView* frame_view =
      web_view_impl->MainFrameImpl()->GetFrame()->View();

  gfx::Transform expected_matrix;
  expected_matrix.MakeIdentity();
  EXPECT_EQ(expected_matrix, web_view_impl->GetDeviceEmulationTransform());

  // Initial transform takes current page scale and scroll position into
  // account.
  web_view_impl->SetPageScaleFactor(1.5f);
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(100, 150), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant);

  DeviceEmulationParams emulation_params;
  emulation_params.viewport_offset = gfx::PointF(50, 55);
  emulation_params.viewport_scale = 2.f;
  web_view_impl->EnableDeviceEmulation(emulation_params);
  expected_matrix = gfx::Transform::MakeScale(2.f);
  expected_matrix.Translate(-50, -55);
  expected_matrix.Translate(100, 150);
  expected_matrix.Scale(1. / 1.5f);
  EXPECT_EQ(expected_matrix, web_view_impl->GetDeviceEmulationTransform());

  // Transform adapts to scroll changes.
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(50, 55), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant);
  expected_matrix = gfx::Transform::MakeScale(2.f);
  expected_matrix.Translate(-50, -55);
  expected_matrix.Translate(50, 55);
  expected_matrix.Scale(1. / 1.5f);
  EXPECT_EQ(expected_matrix, web_view_impl->GetDeviceEmulationTransform());

  // Transform adapts to page scale changes.
  web_view_impl->SetPageScaleFactor(2.f);
  expected_matrix = gfx::Transform::MakeScale(2.f);
  expected_matrix.Translate(-50, -55);
  expected_matrix.Translate(50, 55);
  expected_matrix.Scale(1. / 2.f);
  EXPECT_EQ(expected_matrix, web_view_impl->GetDeviceEmulationTransform());
}

TEST_F(WebViewTest, ResizeForPrintingViewportUnits) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<style>"
                                     "  body { margin: 0px; }"
                                     "  #vw { width: 100vw; height: 100vh; }"
                                     "</style>"
                                     "<div id=vw></div>",
                                     base_url);

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  Document* document = frame->GetFrame()->GetDocument();
  Element* vw_element = document->getElementById(AtomicString("vw"));

  EXPECT_EQ(800, vw_element->OffsetWidth());

  gfx::Size page_size(300, 360);

  WebPrintParams print_params((gfx::SizeF(page_size)));

  gfx::Size expected_size = page_size;

  frame->PrintBegin(print_params, WebNode());

  EXPECT_EQ(expected_size.width(), vw_element->OffsetWidth());
  EXPECT_EQ(expected_size.height(), vw_element->OffsetHeight());

  web_view->MainFrameWidget()->Resize(page_size);

  EXPECT_EQ(expected_size.width(), vw_element->OffsetWidth());
  EXPECT_EQ(expected_size.height(), vw_element->OffsetHeight());

  web_view->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  frame->PrintEnd();

  EXPECT_EQ(800, vw_element->OffsetWidth());
}

TEST_F(WebViewTest, WidthMediaQueryWithPageZoomAfterPrinting) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  web_view->MainFrameWidget()->SetZoomLevel(ZoomFactorToZoomLevel(2.0));

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<style>"
                                     "  @media (max-width: 600px) {"
                                     "    div { color: green }"
                                     "  }"
                                     "</style>"
                                     "<div id=d></div>",
                                     base_url);

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  Document* document = frame->GetFrame()->GetDocument();
  Element* div = document->getElementById(AtomicString("d"));

  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      div->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  gfx::SizeF page_size(300, 360);

  WebPrintParams print_params(page_size);

  frame->PrintBegin(print_params, WebNode());
  frame->PrintEnd();

  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      div->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(WebViewTest, ViewportUnitsPrintingWithPageZoom) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  web_view->MainFrameWidget()->SetZoomLevel(ZoomFactorToZoomLevel(2.0));

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<style>"
                                     "  body { margin: 0 }"
                                     "  #t1 { width: 100% }"
                                     "  #t2 { width: 100vw }"
                                     "</style>"
                                     "<div id=t1></div>"
                                     "<div id=t2></div>",
                                     base_url);

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  Document* document = frame->GetFrame()->GetDocument();
  Element* t1 = document->getElementById(AtomicString("t1"));
  Element* t2 = document->getElementById(AtomicString("t2"));

  EXPECT_EQ(400, t1->OffsetWidth());
  EXPECT_EQ(400, t2->OffsetWidth());

  gfx::Size page_size(600, 720);
  int expected_width = page_size.width();

  WebPrintParams print_params((gfx::SizeF(page_size)));

  frame->PrintBegin(print_params, WebNode());

  EXPECT_EQ(expected_width, t1->OffsetWidth());
  EXPECT_EQ(expected_width, t2->OffsetWidth());

  frame->PrintEnd();
}

TEST_F(WebViewTest, ResizeWithFixedPosCrash) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<div style='position:fixed;'></div>",
                                     base_url);
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  gfx::Size page_size(300, 360);
  WebPrintParams print_params((gfx::SizeF(page_size)));
  frame->PrintBegin(print_params, WebNode());
  web_view->MainFrameWidget()->Resize(page_size);
  frame->PrintEnd();
}

TEST_F(WebViewTest, DeviceEmulationResetScrollbars) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<!doctype html>"
                                     "<meta name='viewport'"
                                     "    content='width=device-width'>"
                                     "<style>"
                                     "  body {margin: 0px; height:3000px;}"
                                     "</style>",
                                     base_url);
  UpdateAllLifecyclePhases();

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  auto* frame_view = frame->GetFrameView();
  EXPECT_FALSE(frame_view->VisualViewportSuppliesScrollbars());
  EXPECT_NE(nullptr, frame_view->LayoutViewport()->VerticalScrollbar());

  DeviceEmulationParams params;
  params.screen_type = mojom::EmulatedScreenType::kMobile;
  params.device_scale_factor = 0;
  params.scale = 1;

  web_view->EnableDeviceEmulation(params);

  // The visual viewport should now proivde the scrollbars instead of the view.
  EXPECT_TRUE(frame_view->VisualViewportSuppliesScrollbars());
  EXPECT_EQ(nullptr, frame_view->LayoutViewport()->VerticalScrollbar());

  web_view->DisableDeviceEmulation();

  // The view should once again provide the scrollbars.
  EXPECT_FALSE(frame_view->VisualViewportSuppliesScrollbars());
  EXPECT_NE(nullptr, frame_view->LayoutViewport()->VerticalScrollbar());
}

TEST_F(WebViewTest, SetZoomLevelWhilePluginFocused) {
  class PluginCreatingWebFrameClient
      : public frame_test_helpers::TestWebFrameClient {
   public:
    // WebLocalFrameClient overrides:
    WebPlugin* CreatePlugin(const WebPluginParams& params) override {
      return new FakeWebPlugin(params);
    }
  };
  PluginCreatingWebFrameClient frame_client;
  WebViewImpl* web_view = web_view_helper_.Initialize(&frame_client);
  WebURL base_url = url_test_helpers::ToKURL("https://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view->MainFrameImpl(),
      "<!DOCTYPE html><html><body>"
      "<object type='application/x-webkit-test-plugin'></object>"
      "</body></html>",
      base_url);
  // Verify the plugin is loaded.
  LocalFrame* main_frame = web_view->MainFrameImpl()->GetFrame();
  auto* plugin_element =
      To<HTMLObjectElement>(main_frame->GetDocument()->body()->firstChild());
  EXPECT_TRUE(plugin_element->OwnedPlugin());
  // Focus the plugin element, and then change the zoom level on the WebView.
  plugin_element->Focus();
  EXPECT_FLOAT_EQ(1.0f, main_frame->LayoutZoomFactor());
  web_view->MainFrameWidget()->SetZoomLevel(-1.0);
  // Even though the plugin is focused, the entire frame's zoom factor should
  // still be updated.
  EXPECT_FLOAT_EQ(5.0f / 6.0f, main_frame->LayoutZoomFactor());
  web_view_helper_.Reset();  // Remove dependency on locally scoped client.
}

// Tests that a layout update that detaches a plugin doesn't crash if the
// plugin tries to execute script while being destroyed.
TEST_F(WebViewTest, DetachPluginInLayout) {
  class ScriptInDestroyPlugin : public FakeWebPlugin {
   public:
    ScriptInDestroyPlugin(WebLocalFrame* frame, const WebPluginParams& params)
        : FakeWebPlugin(params), frame_(frame) {}

    // WebPlugin overrides:
    void Destroy() override {
      frame_->ExecuteScript(WebScriptSource("console.log('done')"));
      // Deletes this.
      FakeWebPlugin::Destroy();
    }

   private:
    WebLocalFrame* frame_;  // Unowned
  };

  class PluginCreatingWebFrameClient
      : public frame_test_helpers::TestWebFrameClient {
   public:
    // WebLocalFrameClient overrides:
    WebPlugin* CreatePlugin(const WebPluginParams& params) override {
      return new ScriptInDestroyPlugin(Frame(), params);
    }

    void DidAddMessageToConsole(const WebConsoleMessage& message,
                                const WebString& source_name,
                                unsigned source_line,
                                const WebString& stack_trace) override {
      message_ = message.text;
    }

    const String& Message() const { return message_; }

   private:
    String message_;
  };

  PluginCreatingWebFrameClient frame_client;
  WebViewImpl* web_view = web_view_helper_.Initialize(&frame_client);
  WebURL base_url = url_test_helpers::ToKURL("https://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view->MainFrameImpl(),
      "<!DOCTYPE html><html><body>"
      "<object type='application/x-webkit-test-plugin'></object>"
      "</body></html>",
      base_url);
  // Verify the plugin is loaded.
  LocalFrame* main_frame = web_view->MainFrameImpl()->GetFrame();
  auto* plugin_element =
      To<HTMLObjectElement>(main_frame->GetDocument()->body()->firstChild());
  EXPECT_TRUE(plugin_element->OwnedPlugin());

  plugin_element->style()->setCSSText(main_frame->DomWindow(), "display: none",
                                      ASSERT_NO_EXCEPTION);
  EXPECT_TRUE(plugin_element->OwnedPlugin());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(plugin_element->OwnedPlugin());
  EXPECT_EQ("done", frame_client.Message());
  web_view_helper_.Reset();  // Remove dependency on locally scoped client.
}

// Check that first input delay is correctly reported to the document.
TEST_F(WebViewTest, FirstInputDelayReported) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<html><body></body></html>", base_url);

  LocalFrame* main_frame = web_view->MainFrameImpl()->GetFrame();
  ASSERT_NE(nullptr, main_frame);

  Document* document = main_frame->GetDocument();
  ASSERT_NE(nullptr, document);

  base::TimeTicks start_time = test_task_runner_->NowTicks();
  test_task_runner_->FastForwardBy(base::Milliseconds(70));

  InteractiveDetector* interactive_detector =
      GetTestInteractiveDetector(*document);

  EXPECT_FALSE(interactive_detector->GetFirstInputDelay().has_value());

  WebKeyboardEvent key_event1(WebInputEvent::Type::kRawKeyDown,
                              WebInputEvent::kNoModifiers,
                              WebInputEvent::GetStaticTimeStampForTests());
  key_event1.dom_key = ui::DomKey::FromCharacter(' ');
  key_event1.windows_key_code = VKEY_SPACE;
  key_event1.SetTimeStamp(test_task_runner_->NowTicks());
  test_task_runner_->FastForwardBy(base::Milliseconds(50));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event1, ui::LatencyInfo()));

  EXPECT_TRUE(interactive_detector->GetFirstInputDelay().has_value());
  EXPECT_NEAR(50,
              (*interactive_detector->GetFirstInputDelay()).InMillisecondsF(),
              0.01);
  EXPECT_EQ(70, (*interactive_detector->GetFirstInputTimestamp() - start_time)
                    .InMillisecondsF());

  // Sending a second event won't change the FirstInputDelay.
  WebKeyboardEvent key_event2(WebInputEvent::Type::kRawKeyDown,
                              WebInputEvent::kNoModifiers,
                              WebInputEvent::GetStaticTimeStampForTests());
  key_event2.dom_key = ui::DomKey::FromCharacter(' ');
  key_event2.windows_key_code = VKEY_SPACE;
  test_task_runner_->FastForwardBy(base::Milliseconds(60));
  key_event2.SetTimeStamp(test_task_runner_->NowTicks());
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event2, ui::LatencyInfo()));

  EXPECT_NEAR(50,
              (*interactive_detector->GetFirstInputDelay()).InMillisecondsF(),
              0.01);
  EXPECT_EQ(70, (*interactive_detector->GetFirstInputTimestamp() - start_time)
                    .InMillisecondsF());
}

TEST_F(WebViewTest, InputDelayReported) {
  test_task_runner_->FastForwardBy(base::Milliseconds(50));

  WebViewImpl* web_view = web_view_helper_.Initialize();

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<html><body></body></html>", base_url,
                                     test_task_runner_->GetMockTickClock());

  LocalFrame* main_frame = web_view->MainFrameImpl()->GetFrame();
  ASSERT_NE(nullptr, main_frame);
  Document* document = main_frame->GetDocument();
  ASSERT_NE(nullptr, document);
  GetTestInteractiveDetector(*document);

  test_task_runner_->FastForwardBy(base::Milliseconds(70));

  base::HistogramTester histogram_tester;
  WebKeyboardEvent key_event1(WebInputEvent::Type::kRawKeyDown,
                              WebInputEvent::kNoModifiers,
                              WebInputEvent::GetStaticTimeStampForTests());
  key_event1.dom_key = ui::DomKey::FromCharacter(' ');
  key_event1.windows_key_code = VKEY_SPACE;
  key_event1.SetTimeStamp(test_task_runner_->NowTicks());
  test_task_runner_->FastForwardBy(base::Milliseconds(50));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event1, ui::LatencyInfo()));

  WebKeyboardEvent key_event2(WebInputEvent::Type::kRawKeyDown,
                              WebInputEvent::kNoModifiers,
                              WebInputEvent::GetStaticTimeStampForTests());
  key_event2.dom_key = ui::DomKey::FromCharacter(' ');
  key_event2.windows_key_code = VKEY_SPACE;
  key_event2.SetTimeStamp(test_task_runner_->NowTicks());
  test_task_runner_->FastForwardBy(base::Milliseconds(50));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event2, ui::LatencyInfo()));

  WebKeyboardEvent key_event3(WebInputEvent::Type::kRawKeyDown,
                              WebInputEvent::kNoModifiers,
                              WebInputEvent::GetStaticTimeStampForTests());
  key_event3.dom_key = ui::DomKey::FromCharacter(' ');
  key_event3.windows_key_code = VKEY_SPACE;
  key_event3.SetTimeStamp(test_task_runner_->NowTicks());
  test_task_runner_->FastForwardBy(base::Milliseconds(70));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event3, ui::LatencyInfo()));

  histogram_tester.ExpectTotalCount("PageLoad.InteractiveTiming.InputDelay3",
                                    3);
  histogram_tester.ExpectBucketCount("PageLoad.InteractiveTiming.InputDelay3",
                                     50, 2);
  histogram_tester.ExpectBucketCount("PageLoad.InteractiveTiming.InputDelay3",
                                     70, 1);

  histogram_tester.ExpectTotalCount(
      "PageLoad.InteractiveTiming.InputTimestamp3", 3);
  histogram_tester.ExpectBucketCount(
      "PageLoad.InteractiveTiming.InputTimestamp3", 70, 1);
  histogram_tester.ExpectBucketCount(
      "PageLoad.InteractiveTiming.InputTimestamp3", 120, 1);
  histogram_tester.ExpectBucketCount(
      "PageLoad.InteractiveTiming.InputTimestamp3", 170, 1);
}

// TODO(npm): Improve this test to receive real input sequences and avoid hacks.
// Check that first input delay is correctly reported to the document when the
// first input is a pointer down event, and we receive a pointer up event.
TEST_F(WebViewTest, PointerDownUpFirstInputDelay) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<html><body></body></html>", base_url);
  // Add an event listener for pointerdown to ensure it is not optimized out
  // before reaching the EventDispatcher.
  WebLocalFrame* frame = web_view_helper_.LocalMainFrame();
  frame->ExecuteScript(
      WebScriptSource("addEventListener('pointerdown', function() {});"));

  LocalFrame* main_frame = web_view->MainFrameImpl()->GetFrame();
  ASSERT_NE(nullptr, main_frame);

  Document* document = main_frame->GetDocument();
  ASSERT_NE(nullptr, document);

  base::TimeTicks start_time = test_task_runner_->NowTicks();
  test_task_runner_->FastForwardBy(base::Milliseconds(70));

  InteractiveDetector* interactive_detector =
      GetTestInteractiveDetector(*document);

  WebPointerEvent pointer_down(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch), 5, 5);
  pointer_down.SetTimeStamp(test_task_runner_->NowTicks());
  // Set this to the left button, needed for testing to behave properly.
  pointer_down.SetModifiers(WebInputEvent::kLeftButtonDown);
  pointer_down.button = WebPointerProperties::Button::kLeft;
  test_task_runner_->FastForwardBy(base::Milliseconds(50));
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(pointer_down, ui::LatencyInfo()));

  // We don't know if this pointer event will result in a scroll or not, so we
  // can't report its delay. We don't consider a scroll to be meaningful input.
  EXPECT_FALSE(interactive_detector->GetFirstInputDelay().has_value());

  // When we receive a pointer up, we report the delay of the pointer down.
  WebPointerEvent pointer_up(
      WebInputEvent::Type::kPointerUp,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch), 5, 5);
  test_task_runner_->FastForwardBy(base::Milliseconds(60));
  pointer_up.SetTimeStamp(test_task_runner_->NowTicks());
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(pointer_up, ui::LatencyInfo()));

  EXPECT_NEAR(50,
              (*interactive_detector->GetFirstInputDelay()).InMillisecondsF(),
              0.01);
  EXPECT_EQ(70, (*interactive_detector->GetFirstInputTimestamp() - start_time)
                    .InMillisecondsF());
}

// We need a way for JS to advance the mock clock. Hook into console.log, so
// that logging advances the clock by |event_handling_delay| seconds.
class MockClockAdvancingWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  MockClockAdvancingWebFrameClient(
      scoped_refptr<base::TestMockTimeTaskRunner> task_runner,
      base::TimeDelta event_handling_delay)
      : task_runner_(std::move(task_runner)),
        event_handling_delay_(event_handling_delay) {}
  // WebLocalFrameClient overrides:
  void DidAddMessageToConsole(const WebConsoleMessage& message,
                              const WebString& source_name,
                              unsigned source_line,
                              const WebString& stack_trace) override {
    task_runner_->FastForwardBy(event_handling_delay_);
  }

 private:
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner_;
  base::TimeDelta event_handling_delay_;
};

// Check that the input delay is correctly reported to the document.
TEST_F(WebViewTest, FirstInputDelayExcludesProcessingTime) {
  // Page load timing logic depends on the time not being zero.
  test_task_runner_->FastForwardBy(base::Milliseconds(1));
  MockClockAdvancingWebFrameClient frame_client(test_task_runner_,
                                                base::Milliseconds(6000));
  WebViewImpl* web_view = web_view_helper_.Initialize(&frame_client);
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(),
                                     "<html><body></body></html>", base_url,
                                     test_task_runner_->GetMockTickClock());

  LocalFrame* main_frame = web_view->MainFrameImpl()->GetFrame();
  ASSERT_NE(nullptr, main_frame);

  Document* document = main_frame->GetDocument();
  ASSERT_NE(nullptr, document);

  WebLocalFrame* frame = web_view_helper_.LocalMainFrame();
  // console.log will advance the mock clock.
  frame->ExecuteScript(
      WebScriptSource("document.addEventListener('keydown', "
                      "() => {console.log('advancing timer');})"));

  InteractiveDetector* interactive_detector =
      GetTestInteractiveDetector(*document);

  WebKeyboardEvent key_event(WebInputEvent::Type::kRawKeyDown,
                             WebInputEvent::kNoModifiers,
                             WebInputEvent::GetStaticTimeStampForTests());
  key_event.dom_key = ui::DomKey::FromCharacter(' ');
  key_event.windows_key_code = VKEY_SPACE;
  key_event.SetTimeStamp(test_task_runner_->NowTicks());

  test_task_runner_->FastForwardBy(base::Milliseconds(5000));

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  EXPECT_TRUE(interactive_detector->GetFirstInputDelay().has_value());
  base::TimeDelta first_input_delay =
      *interactive_detector->GetFirstInputDelay();
  EXPECT_EQ(5000, first_input_delay.InMillisecondsF());

  web_view_helper_.Reset();  // Remove dependency on locally scoped client.
}

TEST_F(WebViewTest, RootLayerAttachment) {
  WebView* web_view = web_view_helper_.InitializeAndLoad("about:blank");

  // Do a lifecycle update that includes compositing but not paint. Hit test
  // events are an example of a real case where this occurs
  // (see: WebViewTest::ClientTapHandling).
  web_view->MainFrameWidget()->UpdateLifecycle(WebLifecycleUpdate::kPrePaint,
                                               DocumentUpdateReason::kTest);

  // Layers (including the root layer) should not be attached until the paint
  // lifecycle phase.
  cc::LayerTreeHost* layer_tree_host = web_view_helper_.GetLayerTreeHost();
  EXPECT_FALSE(layer_tree_host->root_layer());

  // Do a full lifecycle update and ensure that the root layer has been added.
  web_view->MainFrameWidget()->UpdateLifecycle(WebLifecycleUpdate::kAll,
                                               DocumentUpdateReason::kTest);
  EXPECT_TRUE(layer_tree_host->root_layer());
}

TEST_F(WebViewTest, ForceDarkModeInvalidatesPaint) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  UpdateAllLifecyclePhases();

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  ASSERT_TRUE(document);
  web_view->GetSettings()->SetForceDarkModeEnabled(true);
  EXPECT_TRUE(document->GetLayoutView()->ShouldDoFullPaintInvalidation());
}

// Regression test for https://crbug.com/1012068
TEST_F(WebViewTest, LongPressImageAndThenLongTapImage) {
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

  WebGestureEvent tap_event(WebInputEvent::Type::kGestureLongTap,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests(),
                            WebGestureDevice::kTouchscreen);
  tap_event.SetPositionInWidget(gfx::PointF(10, 10));

  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(tap_event, ui::LatencyInfo())));
  EXPECT_TRUE(
      web_view->GetPage()->GetContextMenuController().ContextMenuNodeForFrame(
          web_view->MainFrameImpl()->GetFrame()));
}

// Regression test for http://crbug.com/41562
TEST_F(WebViewTest, UpdateTargetURLWithInvalidURL) {
  WebViewImpl* web_view = web_view_helper_.Initialize();
  const KURL invalid_kurl("http://");
  web_view->UpdateTargetURL(blink::WebURL(invalid_kurl),
                            /* fallback_url=*/blink::WebURL());
  EXPECT_EQ(invalid_kurl, web_view->target_url_);
}

// Regression test for https://crbug.com/1112987
TEST_F(WebViewTest, LongPressThenLongTapLinkInIframeStartsContextMenu) {
  Regist
```