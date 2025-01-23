Response:
The user wants a summary of the functionalities of the C++ source code file `visual_viewport_test.cc` in the Chromium Blink engine.
This is part 3 of a 4-part request, implying previous parts already covered some aspects.

I need to:
1. **List the functionalities** demonstrated in the provided code snippet.
2. **Explain the relation to Javascript, HTML, and CSS** with examples if applicable.
3. **Provide examples of logical reasoning** with hypothetical inputs and outputs.
4. **Illustrate common user or programming errors** related to the covered functionality.
5. **Summarize the functionalities** based on the code provided in this part.

Based on the code snippet, the functionalities revolve around testing the behavior of the `VisualViewport` class in various scenarios, particularly related to:

- **Browser controls interaction**: How the visual viewport adapts to the appearance and disappearance of browser controls (e.g., address bar).
- **Resizing behavior**: How the visual viewport behaves when the window or its own size changes.
- **Scrollbar visibility**: Testing the attachment of scrollbar layers based on settings.
- **Content size changes**: How the visual viewport responds to changes in the content size.
- **Coordinate transformations**: Testing the conversion between viewport and root frame coordinates.
- **Viewport properties**: Verifying that certain properties (like `window.innerWidth`, `window.innerHeight`) are not affected by the visual viewport.
- **Initial frame sizing**: How new frames are sized.
- **Fractional scroll offsets**: Handling of non-integer scroll positions.
- **Accessibility hit testing**: Ensuring correct hit testing within the visual viewport when zoomed.
- **Scroll anchoring**:  Maintaining the user's scroll position during resizes.
- **`background-attachment: fixed`**: Testing how fixed background images are handled during resizes and browser control changes.
- **Raster invalidation**: Checking when repainting is necessary.
- **Overscroll elasticity**: Ensuring the correct creation of transform nodes for overscroll effects.
- **Scrollbar theming**:  Verifying the creation of effect nodes for scrollbars.
这是对 `blink/renderer/core/frame/visual_viewport_test.cc` 文件功能的总结，基于你提供的第三部分代码片段。

**功能归纳：**

这部分代码主要集中测试 `VisualViewport` 类在以下场景中的行为和属性：

1. **浏览器控件交互与大小调整：**
   - 测试当浏览器控件（例如地址栏）出现或隐藏时，`VisualViewport` 的大小和位置如何变化。
   - 验证在浏览器控件调整大小时，内容滚动偏移是否正确保持，避免不必要的偏移重置。
   - 涉及到 `WebView()->GetBrowserControls().SetShownRatio()` 和 `WebView()->ResizeWithBrowserControls()` 等方法。

   **与 Javascript, HTML, CSS 的关系举例：**
   - **Javascript:**  `window.scrollTo()` 可以触发页面滚动，从而可能触发浏览器控件的显示或隐藏，进而影响 `VisualViewport` 的行为。例如，一个网站可以使用 Javascript 在用户向下滚动到一定程度时隐藏地址栏。
   - **HTML:**  页面的内容高度会影响滚动条的出现和滚动范围，进而影响 `VisualViewport` 的滚动行为。
   - **CSS:**  某些 CSS 属性，如 `position: fixed;`，其元素的布局可能受到 `VisualViewport` 的影响。

   **假设输入与输出:**
   - **假设输入:**  浏览器窗口大小为 500x800，页面内容高度为 1200，浏览器控件高度为 100。用户通过 Javascript 调用 `window.scrollTo(0, 1000)` 将页面滚动到接近底部，导致浏览器控件自动隐藏。
   - **预期输出:** `VisualViewport` 的可见区域高度会增加（因为浏览器控件隐藏），内容偏移也会相应调整，以保持用户看到的页面内容一致。

2. **滚动条显示与隐藏设置：**
   - 测试当 WebSettings 中的 `hideScrollbars` 设置为 true 或 false 时，滚动条相关的 Layer 是否正确地附加到 `VisualViewport` 的容器层。

   **与 Javascript, HTML, CSS 的关系举例：**
   - **HTML:**  如果页面内容超出视口，通常会出现滚动条，但 `hideScrollbars` 设置可以改变这种默认行为。
   - **CSS:**  开发者可以使用 CSS 来自定义滚动条的样式，但 `hideScrollbars` 设置会影响这些样式是否生效。

   **假设输入与输出:**
   - **假设输入:** 初始化 WebView 时，WebSettings 设置 `hideScrollbars` 为 true。加载一个内容超出视口的 HTML 页面。
   - **预期输出:**  `visual_viewport.LayerForHorizontalScrollbar()` 和 `visual_viewport.LayerForVerticalScrollbar()` 将返回 false 或空指针，表示滚动条的 Layer 没有被创建或附加。

3. **内容大小变化对滚动边界的影响：**
   - 测试通过 Javascript 动态修改页面内容的大小（例如修改元素的 `width` 和 `height` 样式），`VisualViewport` 的滚动边界是否会相应更新。

   **与 Javascript, HTML, CSS 的关系举例：**
   - **Javascript:**  Javascript 可以直接操作 DOM 元素的样式，改变其尺寸。
   - **HTML:**  `<div>` 等元素的尺寸会直接影响页面的内容大小。
   - **CSS:**  CSS 的 `width` 和 `height` 属性定义了元素的尺寸。

   **假设输入与输出:**
   - **假设输入:**  加载一个初始宽度为 100px 的 `<div>` 元素的页面。然后通过 Javascript 将该元素的宽度修改为 1500px。
   - **预期输出:** `VisualViewport` 的滚动范围会相应增加，允许用户滚动查看新增的内容。`scroll_node->ContentsRect()` 的宽度会更新为 1500。

4. **`VisualViewport` 大小调整的限制：**
   - 测试调整 `VisualViewport` 的大小时，其边界是否会保持在外部视口（Outer Viewport）的范围内。

   **假设输入与输出:**
   - **假设输入:** 初始窗口大小为 100x200。将 `VisualViewport` 的大小调整为 100x100，然后将其位置向下移动 100px。之后尝试将 `VisualViewport` 的大小调整回 100x200。
   - **预期输出:**  `VisualViewport` 的位置会被调整，使其仍然完全包含在 100x200 的窗口内，例如，其垂直偏移会被重置为 0。

5. **元素在 Widget 空间中的边界计算：**
   - 测试在进行缩放和偏移后，如何计算元素在 Widget 坐标空间中的边界，确保计算考虑了 `VisualViewport` 的变换。

   **与 Javascript, HTML, CSS 的关系举例：**
   - **Javascript:**  可以使用 `element.getBoundingClientRect()` 获取元素相对于视口的坐标，而 `BoundsInWidget()` 方法则计算了相对于整个 Widget 的坐标，这之间的差异就与 `VisualViewport` 的变换有关。
   - **HTML:** 元素的布局和位置会影响其边界。
   - **CSS:**  缩放 (e.g., `transform: scale(2);`) 和偏移 (e.g., `transform: translate(10px, 20px);`) 可以改变元素的视觉位置，`VisualViewport` 的缩放和偏移也会产生类似的效果。

   **假设输入与输出:**
   - **假设输入:**  一个位于页面左上角的输入框。`VisualViewport` 的缩放设置为 2，并偏移 (250, 400)。
   - **预期输出:**  `input_element->BoundsInWidget()` 返回的坐标是考虑了 2 倍缩放和 (250, 400) 偏移后的结果。

**总结来说，这部分测试代码主要关注 `VisualViewport` 如何响应浏览器控件的变化、不同的设置以及内容的变化，并验证其在各种情况下是否能正确地管理和报告视口的大小、位置和滚动状态。** 这对于确保网页在移动设备上正确渲染和交互至关重要，因为移动设备上的视口管理比桌面浏览器更复杂。

### 提示词
```
这是目录为blink/renderer/core/frame/visual_viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
500, visual_viewport_height), visual_viewport.Size());

  // Scroll all the way to the bottom, showing the the browser controls in the
  // process. (This could happen via window.scrollTo during a scroll, for
  // example).
  WebView()->GetBrowserControls().SetShownRatio(1, 0);
  visual_viewport.Move(ScrollOffset(10000, 10000));
  frame_view.LayoutViewport()->ScrollBy(ScrollOffset(10000, 10000),
                                        mojom::blink::ScrollType::kUser);

  EXPECT_EQ(gfx::SizeF(250, (visual_viewport_height - browser_controls_height) /
                                page_scale),
            visual_viewport.VisibleRect().size());

  ScrollOffset frame_view_expected(
      0, content_height - (layout_viewport_height -
                           browser_controls_height / min_page_scale));
  ScrollOffset visual_viewport_expected = ScrollOffset(
      750, (layout_viewport_height - browser_controls_height / min_page_scale -
            visual_viewport.VisibleRect().height()));

  EXPECT_EQ(visual_viewport_expected, visual_viewport.GetScrollOffset());
  EXPECT_EQ(frame_view_expected,
            frame_view.LayoutViewport()->GetScrollOffset());

  ScrollOffset total_expected = visual_viewport_expected + frame_view_expected;

  // Resize the widget to match the browser controls adjustment. Ensure that the
  // total offset (i.e. what the user sees) doesn't change because of clamping
  // the offsets to valid values.
  WebView()->ResizeWithBrowserControls(
      gfx::Size(500, visual_viewport_height - browser_controls_height), 20, 0,
      true);
  UpdateAllLifecyclePhases();

  EXPECT_EQ(gfx::Size(500, visual_viewport_height - browser_controls_height),
            visual_viewport.Size());
  EXPECT_EQ(gfx::SizeF(250, (visual_viewport_height - browser_controls_height) /
                                page_scale),
            visual_viewport.VisibleRect().size());
  EXPECT_EQ(gfx::Size(1000, layout_viewport_height -
                                browser_controls_height / min_page_scale),
            frame_view.FrameRect().size());
  EXPECT_EQ(total_expected, visual_viewport.GetScrollOffset() +
                                frame_view.LayoutViewport()->GetScrollOffset());
}

// Tests that a resize due to browser controls hiding doesn't incorrectly clamp
// the main frame's scroll offset. crbug.com/428193.
TEST_P(VisualViewportTest, TestTopControlHidingResizeDoesntClampMainFrame) {
  InitializeWithAndroidSettings();
  WebView()->ResizeWithBrowserControls(
      gfx::Size(WebView()->MainFrameViewWidget()->Size()), 500, 0, false);
  UpdateAllLifecyclePhases();
  WebView()->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1, false, 1, 0,
       cc::BrowserControlsState::kBoth});
  WebView()->ResizeWithBrowserControls(gfx::Size(1000, 1000), 500, 0, true);
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");
  UpdateAllLifecyclePhases();

  // Scroll the LocalFrameView to the bottom of the page but "hide" the browser
  // controls on the compositor side so the max scroll position should account
  // for the full viewport height.
  WebView()->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1, false, -1, 0,
       cc::BrowserControlsState::kBoth});
  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();
  frame_view.LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 10000), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_EQ(500, frame_view.LayoutViewport()->GetScrollOffset().y());

  // Now send the resize, make sure the scroll offset doesn't change.
  WebView()->ResizeWithBrowserControls(gfx::Size(1000, 1500), 500, 0, false);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(500, frame_view.LayoutViewport()->GetScrollOffset().y());
}

static void ConfigureHiddenScrollbarsSettings(WebSettings* settings) {
  VisualViewportTest::ConfigureAndroidSettings(settings);
  settings->SetHideScrollbars(true);
}

// Tests that scrollbar layers are not attached to the inner viewport container
// layer when hideScrollbars WebSetting is true.
TEST_P(VisualViewportTest,
       TestScrollbarsNotAttachedWhenHideScrollbarsSettingIsTrue) {
  InitializeWithAndroidSettings(ConfigureHiddenScrollbarsSettings);
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 150));
  NavigateTo("about:blank");

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_FALSE(visual_viewport.LayerForHorizontalScrollbar());
  EXPECT_FALSE(visual_viewport.LayerForVerticalScrollbar());
}

// Tests that scrollbar layers are attached to the inner viewport container
// layer when hideScrollbars WebSetting is false.
TEST_P(VisualViewportTest,
       TestScrollbarsAttachedWhenHideScrollbarsSettingIsFalse) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 150));
  UpdateAllLifecyclePhases();
  NavigateTo("about:blank");

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_TRUE(visual_viewport.LayerForHorizontalScrollbar());
  EXPECT_TRUE(visual_viewport.LayerForVerticalScrollbar());
}

// Tests that the layout viewport's scroll node bounds are updated.
// crbug.com/423188.
TEST_P(VisualViewportTest, TestChangingContentSizeAffectsScrollBounds) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 150));

  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");

  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();

  WebView()->MainFrameImpl()->ExecuteScript(
      WebScriptSource("var content = document.getElementById(\"content\");"
                      "content.style.width = \"1500px\";"
                      "content.style.height = \"2400px\";"));
  UpdateAllLifecyclePhases();

  const auto* scroll_node =
      frame_view.GetLayoutView()->FirstFragment().PaintProperties()->Scroll();
  float scale = GetFrame()->GetPage()->GetVisualViewport().Scale();
  EXPECT_EQ(gfx::Size(100 / scale, 150 / scale),
            scroll_node->ContainerRect().size());
  EXPECT_EQ(gfx::Rect(0, 0, 1500, 2400), scroll_node->ContentsRect());
}

// Tests that resizing the visual viepwort keeps its bounds within the outer
// viewport.
TEST_P(VisualViewportTest, ResizeVisualViewportStaysWithinOuterViewport) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 200));

  NavigateTo("about:blank");
  UpdateAllLifecyclePhases();

  WebView()->ResizeVisualViewport(gfx::Size(100, 100));

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.Move(ScrollOffset(0, 100));

  EXPECT_EQ(100, visual_viewport.GetScrollOffset().y());

  WebView()->ResizeVisualViewport(gfx::Size(100, 200));

  EXPECT_EQ(0, visual_viewport.GetScrollOffset().y());
}

TEST_P(VisualViewportTest, ElementBoundsInWidgetSpaceAccountsForViewport) {
  InitializeWithAndroidSettings();

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(500, 800));

  RegisterMockedHttpURLLoad("pinch-viewport-input-field.html");
  NavigateTo(base_url_ + "pinch-viewport-input-field.html");

  To<LocalFrame>(WebView()->GetPage()->MainFrame())->SetInitialFocus(false);
  Element* input_element = WebView()->FocusedElement();

  gfx::Rect bounds =
      input_element->GetLayoutObject()->AbsoluteBoundingBoxRect();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  gfx::Vector2dF scroll_delta(250, 400);
  visual_viewport.SetScale(2);
  visual_viewport.SetLocation(gfx::PointAtOffsetFromOrigin(scroll_delta));

  const gfx::Rect bounds_in_viewport = input_element->BoundsInWidget();
  gfx::Rect expected_bounds = gfx::ScaleToRoundedRect(bounds, 2.f);
  gfx::Vector2dF expected_scroll_delta = scroll_delta;
  expected_scroll_delta.Scale(2.f, 2.f);

  EXPECT_EQ(gfx::ToRoundedPoint(gfx::PointF(expected_bounds.origin()) -
                                expected_scroll_delta),
            bounds_in_viewport.origin());
  EXPECT_EQ(expected_bounds.size(), bounds_in_viewport.size());
}

// Test that the various window.scroll and document.body.scroll properties and
// methods don't change with the visual viewport.
TEST_P(VisualViewportTest, visualViewportIsInert) {
  WebViewImpl* web_view_impl = helper_.InitializeWithAndroidSettings();

  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(200, 300));

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(
      web_view_impl->MainFrameImpl(),
      "<!DOCTYPE html>"
      "<meta name='viewport' content='width=200,minimum-scale=1'>"
      "<style>"
      "  body {"
      "    width: 800px;"
      "    height: 800px;"
      "    margin: 0;"
      "  }"
      "</style>",
      base_url);
  UpdateAllLifecyclePhases();
  LocalDOMWindow* window =
      web_view_impl->MainFrameImpl()->GetFrame()->DomWindow();
  auto* html = To<HTMLHtmlElement>(window->document()->documentElement());

  ASSERT_EQ(200, window->innerWidth());
  ASSERT_EQ(300, window->innerHeight());
  ASSERT_EQ(200, html->clientWidth());
  ASSERT_EQ(300, html->clientHeight());

  VisualViewport& visual_viewport = web_view_impl->MainFrameImpl()
                                        ->GetFrame()
                                        ->GetPage()
                                        ->GetVisualViewport();
  visual_viewport.SetScale(2);

  ASSERT_EQ(100, visual_viewport.VisibleRect().width());
  ASSERT_EQ(150, visual_viewport.VisibleRect().height());

  EXPECT_EQ(200, window->innerWidth());
  EXPECT_EQ(300, window->innerHeight());
  EXPECT_EQ(200, html->clientWidth());
  EXPECT_EQ(300, html->clientHeight());

  visual_viewport.SetScrollOffset(
      ScrollOffset(10, 15), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());

  ASSERT_EQ(10, visual_viewport.GetScrollOffset().x());
  ASSERT_EQ(15, visual_viewport.GetScrollOffset().y());
  EXPECT_EQ(0, window->scrollX());
  EXPECT_EQ(0, window->scrollY());

  html->setScrollLeft(5);
  html->setScrollTop(30);
  EXPECT_EQ(5, html->scrollLeft());
  EXPECT_EQ(30, html->scrollTop());
  EXPECT_EQ(10, visual_viewport.GetScrollOffset().x());
  EXPECT_EQ(15, visual_viewport.GetScrollOffset().y());

  html->setScrollLeft(5000);
  html->setScrollTop(5000);
  EXPECT_EQ(600, html->scrollLeft());
  EXPECT_EQ(500, html->scrollTop());
  EXPECT_EQ(10, visual_viewport.GetScrollOffset().x());
  EXPECT_EQ(15, visual_viewport.GetScrollOffset().y());

  html->setScrollLeft(0);
  html->setScrollTop(0);
  EXPECT_EQ(0, html->scrollLeft());
  EXPECT_EQ(0, html->scrollTop());
  EXPECT_EQ(10, visual_viewport.GetScrollOffset().x());
  EXPECT_EQ(15, visual_viewport.GetScrollOffset().y());

  window->scrollTo(5000, 5000);
  EXPECT_EQ(600, html->scrollLeft());
  EXPECT_EQ(500, html->scrollTop());
  EXPECT_EQ(10, visual_viewport.GetScrollOffset().x());
  EXPECT_EQ(15, visual_viewport.GetScrollOffset().y());
}

// Tests that when a new frame is created, it is created with the intended size
// (i.e. viewport at minimum scale, 100x200 / 0.5).
TEST_P(VisualViewportTest, TestMainFrameInitializationSizing) {
  InitializeWithAndroidSettings();

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 200));

  RegisterMockedHttpURLLoad("content-width-1000-min-scale.html");
  NavigateTo(base_url_ + "content-width-1000-min-scale.html");

  WebLocalFrameImpl* local_frame = WebView()->MainFrameImpl();
  // The shutdown() calls are a hack to prevent this test from violating
  // invariants about frame state during navigation/detach.
  local_frame->GetFrame()->GetDocument()->Shutdown();
  local_frame->CreateFrameView();

  LocalFrameView& frame_view = *local_frame->GetFrameView();
  EXPECT_EQ(gfx::Size(200, 400), frame_view.FrameRect().size());
  frame_view.Dispose();
}

// Tests that the maximum scroll offset of the viewport can be fractional.
TEST_P(VisualViewportTest, FractionalMaxScrollOffset) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(101, 201));
  NavigateTo("about:blank");

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  ScrollableArea* scrollable_area = &visual_viewport;

  WebView()->SetPageScaleFactor(1.0);
  EXPECT_EQ(ScrollOffset(), scrollable_area->MaximumScrollOffset());

  WebView()->SetPageScaleFactor(2);
  EXPECT_EQ(ScrollOffset(101. / 2., 201. / 2.),
            scrollable_area->MaximumScrollOffset());
}

// Tests that the scroll offset is consistent when scale specified.
TEST_P(VisualViewportTest, MaxScrollOffsetAtScale) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(101, 201));
  NavigateTo("about:blank");

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();

  WebView()->SetPageScaleFactor(0.1);
  EXPECT_EQ(ScrollOffset(), visual_viewport.MaximumScrollOffsetAtScale(1.0));

  WebView()->SetPageScaleFactor(2);
  EXPECT_EQ(ScrollOffset(), visual_viewport.MaximumScrollOffsetAtScale(1.0));

  WebView()->SetPageScaleFactor(5);
  EXPECT_EQ(ScrollOffset(), visual_viewport.MaximumScrollOffsetAtScale(1.0));

  WebView()->SetPageScaleFactor(10);
  EXPECT_EQ(ScrollOffset(101. / 2., 201. / 2.),
            visual_viewport.MaximumScrollOffsetAtScale(2.0));
}

TEST_P(VisualViewportTest, AccessibilityHitTestWhileZoomedIn) {
  InitializeWithDesktopSettings();

  RegisterMockedHttpURLLoad("hit-test.html");
  NavigateTo(base_url_ + "hit-test.html");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  UpdateAllLifecyclePhases();

  WebDocument web_doc = WebView()->MainFrameImpl()->GetDocument();
  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();

  WebAXContext ax_context(web_doc, ui::kAXModeComplete);

  WebView()->SetPageScaleFactor(2);
  WebView()->SetVisualViewportOffset(gfx::PointF(200, 230));
  frame_view.LayoutViewport()->SetScrollOffset(
      ScrollOffset(400, 1100), mojom::blink::ScrollType::kProgrammatic);

  // FIXME(504057): PaintLayerScrollableArea dirties the compositing state.
  ForceFullCompositingUpdate();

  // Because of where the visual viewport is located, this should hit the bottom
  // right target (target 4).
  WebAXObject hitNode =
      WebAXObject::FromWebDocument(web_doc).HitTest(gfx::Point(154, 165));
  ax::mojom::NameFrom name_from;
  WebVector<WebAXObject> name_objects;
  EXPECT_EQ(std::string("Target4"),
            hitNode.GetName(name_from, name_objects).Utf8());
}

// Tests that the maximum scroll offset of the viewport can be fractional.
TEST_P(VisualViewportTest, TestCoordinateTransforms) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");

  VisualViewport& visual_viewport = WebView()->GetPage()->GetVisualViewport();
  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();

  // At scale = 1 the transform should be a no-op.
  visual_viewport.SetScale(1);
  EXPECT_POINTF_EQ(gfx::PointF(314, 273),
                   visual_viewport.ViewportToRootFrame(gfx::PointF(314, 273)));
  EXPECT_POINTF_EQ(gfx::PointF(314, 273),
                   visual_viewport.RootFrameToViewport(gfx::PointF(314, 273)));

  // At scale = 2.
  visual_viewport.SetScale(2);
  EXPECT_POINTF_EQ(gfx::PointF(55, 75),
                   visual_viewport.ViewportToRootFrame(gfx::PointF(110, 150)));
  EXPECT_POINTF_EQ(gfx::PointF(110, 150),
                   visual_viewport.RootFrameToViewport(gfx::PointF(55, 75)));

  // At scale = 2 and with the visual viewport offset.
  visual_viewport.SetLocation(gfx::PointF(10, 12));
  EXPECT_POINTF_EQ(gfx::PointF(50, 62),
                   visual_viewport.ViewportToRootFrame(gfx::PointF(80, 100)));
  EXPECT_POINTF_EQ(gfx::PointF(80, 100),
                   visual_viewport.RootFrameToViewport(gfx::PointF(50, 62)));

  // Test points that will cause non-integer values.
  EXPECT_POINTF_EQ(gfx::PointF(50.5, 62.4),
                   visual_viewport.ViewportToRootFrame(gfx::PointF(81, 100.8)));
  EXPECT_POINTF_EQ(gfx::PointF(81, 100.8), visual_viewport.RootFrameToViewport(
                                               gfx::PointF(50.5, 62.4)));

  // Scrolling the main frame should have no effect.
  frame_view.LayoutViewport()->SetScrollOffset(
      ScrollOffset(100, 120), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_POINTF_EQ(gfx::PointF(50, 62),
                   visual_viewport.ViewportToRootFrame(gfx::PointF(80, 100)));
  EXPECT_POINTF_EQ(gfx::PointF(80, 100),
                   visual_viewport.RootFrameToViewport(gfx::PointF(50, 62)));
}

// Tests that the window dimensions are available before a full layout occurs.
// More specifically, it checks that the innerWidth and innerHeight window
// properties will trigger a layout which will cause an update to viewport
// constraints and a refreshed initial scale. crbug.com/466718
TEST_P(VisualViewportTest, WindowDimensionsOnLoad) {
  InitializeWithAndroidSettings();
  RegisterMockedHttpURLLoad("window_dimensions.html");
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  NavigateTo(base_url_ + "window_dimensions.html");

  Element* output =
      GetFrame()->GetDocument()->getElementById(AtomicString("output"));
  DCHECK(output);
  EXPECT_EQ("1600x1200", output->innerHTML());
}

// Similar to above but make sure the initial scale is updated with the content
// width for a very wide page. That is, make that innerWidth/Height actually
// trigger a layout of the content, and not just an update of the viepwort.
// crbug.com/466718
TEST_P(VisualViewportTest, WindowDimensionsOnLoadWideContent) {
  InitializeWithAndroidSettings();
  RegisterMockedHttpURLLoad("window_dimensions_wide_div.html");
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  NavigateTo(base_url_ + "window_dimensions_wide_div.html");

  Element* output =
      GetFrame()->GetDocument()->getElementById(AtomicString("output"));
  DCHECK(output);
  EXPECT_EQ("2000x1500", output->innerHTML());
}

TEST_P(VisualViewportTest, ResizeWithScrollAnchoring) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  RegisterMockedHttpURLLoad("icb-relative-content.html");
  NavigateTo(base_url_ + "icb-relative-content.html");

  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();
  frame_view.LayoutViewport()->SetScrollOffset(
      ScrollOffset(700, 500), mojom::blink::ScrollType::kProgrammatic);

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(800, 300));
  UpdateAllLifecyclePhases();
  EXPECT_EQ(ScrollOffset(700, 200),
            frame_view.LayoutViewport()->GetScrollOffset());
}

// Make sure a composited background-attachment:fixed background gets resized
// by browser controls.
TEST_P(VisualViewportTest, ResizeCompositedAndFixedBackground) {
  WebViewImpl* web_view_impl = helper_.InitializeWithAndroidSettings();

  int page_width = 640;
  int page_height = 480;
  float browser_controls_height = 50.0f;
  int smallest_height = page_height - browser_controls_height;

  web_view_impl->ResizeWithBrowserControls(gfx::Size(page_width, page_height),
                                           browser_controls_height, 0, false);
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("http://example.com/foo.png", "white-1x1.png");
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view_impl->MainFrameImpl(),
                                     "<!DOCTYPE html>"
                                     "<style>"
                                     "  body {"
                                     "    background: url('foo.png');"
                                     "    background-attachment: fixed;"
                                     "    background-size: cover;"
                                     "    background-repeat: no-repeat;"
                                     "  }"
                                     "  div { height:1000px; width: 200px; }"
                                     "</style>"
                                     "<div></div>",
                                     base_url);

  UpdateAllLifecyclePhases();
  Document* document =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame())->GetDocument();
  VisualViewport& visual_viewport =
      web_view_impl->GetPage()->GetVisualViewport();
  auto* background_layer = visual_viewport.LayerForScrolling();
  ASSERT_TRUE(background_layer);

  ASSERT_EQ(page_width, background_layer->bounds().width());
  ASSERT_EQ(page_height, background_layer->bounds().height());
  ASSERT_EQ(page_width, document->View()->GetLayoutSize().width());
  ASSERT_EQ(smallest_height, document->View()->GetLayoutSize().height());

  web_view_impl->ResizeWithBrowserControls(
      gfx::Size(page_width, smallest_height), browser_controls_height, 0, true);
  UpdateAllLifecyclePhases();

  // The layout size should not have changed.
  ASSERT_EQ(page_width, document->View()->GetLayoutSize().width());
  ASSERT_EQ(smallest_height, document->View()->GetLayoutSize().height());

  // The background layer's size should have changed though.
  EXPECT_EQ(page_width, background_layer->bounds().width());
  EXPECT_EQ(smallest_height, background_layer->bounds().height());

  web_view_impl->ResizeWithBrowserControls(gfx::Size(page_width, page_height),
                                           browser_controls_height, 0, true);
  UpdateAllLifecyclePhases();

  // The background layer's size should change again.
  EXPECT_EQ(page_width, background_layer->bounds().width());
  EXPECT_EQ(page_height, background_layer->bounds().height());
}

static void ConfigureViewportNonCompositing(WebSettings* settings) {
  frame_test_helpers::WebViewHelper::UpdateAndroidCompositingSettings(settings);
  settings->SetLCDTextPreference(LCDTextPreference::kStronglyPreferred);
}

// Make sure a non-composited background-attachment:fixed background gets
// resized by browser controls.
TEST_P(VisualViewportTest, ResizeNonCompositedAndFixedBackground) {
  WebViewImpl* web_view_impl =
      helper_.InitializeWithSettings(&ConfigureViewportNonCompositing);

  int page_width = 640;
  int page_height = 480;
  float browser_controls_height = 50.0f;
  int smallest_height = page_height - browser_controls_height;

  web_view_impl->ResizeWithBrowserControls(gfx::Size(page_width, page_height),
                                           browser_controls_height, 0, false);
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("http://example.com/foo.png", "white-1x1.png");
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view_impl->MainFrameImpl(),
                                     "<!DOCTYPE html>"
                                     "<style>"
                                     "  body {"
                                     "    margin: 0px;"
                                     "    background: url('foo.png');"
                                     "    background-attachment: fixed;"
                                     "    background-size: cover;"
                                     "    background-repeat: no-repeat;"
                                     "  }"
                                     "  div { height:1000px; width: 200px; }"
                                     "</style>"
                                     "<div></div>",
                                     base_url);
  UpdateAllLifecyclePhases();
  Document* document =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame())->GetDocument();
  document->View()->SetTracksRasterInvalidations(true);
  web_view_impl->ResizeWithBrowserControls(
      gfx::Size(page_width, smallest_height), browser_controls_height, 0, true);
  UpdateAllLifecyclePhases();

  // The layout size should not have changed.
  ASSERT_EQ(page_width, document->View()->GetLayoutSize().width());
  ASSERT_EQ(smallest_height, document->View()->GetLayoutSize().height());

  // Fixed-attachment background is affected by viewport size.
  {
    const auto& raster_invalidations =
        GetRasterInvalidationTracking(*GetFrame()->View())->Invalidations();
    EXPECT_THAT(
        raster_invalidations,
        UnorderedElementsAre(RasterInvalidationInfo{
            ScrollingBackgroundClient(document).Id(),
            ScrollingBackgroundClient(document).DebugName(),
            gfx::Rect(0, 0, 640, 1000), PaintInvalidationReason::kBackground}));
  }

  document->View()->SetTracksRasterInvalidations(false);

  document->View()->SetTracksRasterInvalidations(true);
  web_view_impl->ResizeWithBrowserControls(gfx::Size(page_width, page_height),
                                           browser_controls_height, 0, true);
  UpdateAllLifecyclePhases();

  // Fixed-attachment background is affected by viewport size.
  {
    const auto& raster_invalidations =
        GetRasterInvalidationTracking(*GetFrame()->View())->Invalidations();
    EXPECT_THAT(
        raster_invalidations,
        UnorderedElementsAre(RasterInvalidationInfo{
            ScrollingBackgroundClient(document).Id(),
            ScrollingBackgroundClient(document).DebugName(),
            gfx::Rect(0, 0, 640, 1000), PaintInvalidationReason::kBackground}));
  }

  document->View()->SetTracksRasterInvalidations(false);
}

// Make sure a browser control resize with background-attachment:not-fixed
// background doesn't cause invalidation or layout.
TEST_P(VisualViewportTest, ResizeNonFixedBackgroundNoLayoutOrInvalidation) {
  WebViewImpl* web_view_impl = helper_.InitializeWithAndroidSettings();

  int page_width = 640;
  int page_height = 480;
  float browser_controls_height = 50.0f;
  int smallest_height = page_height - browser_controls_height;

  web_view_impl->ResizeWithBrowserControls(gfx::Size(page_width, page_height),
                                           browser_controls_height, 0, false);
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("http://example.com/foo.png", "white-1x1.png");
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  // This time the background is the default attachment.
  frame_test_helpers::LoadHTMLString(web_view_impl->MainFrameImpl(),
                                     "<!DOCTYPE html>"
                                     "<style>"
                                     "  body {"
                                     "    margin: 0px;"
                                     "    background: url('foo.png');"
                                     "    background-size: cover;"
                                     "    background-repeat: no-repeat;"
                                     "  }"
                                     "  div { height:1000px; width: 200px; }"
                                     "</style>"
                                     "<div></div>",
                                     base_url);
  UpdateAllLifecyclePhases();
  Document* document =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame())->GetDocument();

  // A resize will do a layout synchronously so manually check that we don't
  // setNeedsLayout from viewportSizeChanged.
  document->View()->ViewportSizeChanged();
  unsigned needs_layout_objects = 0;
  unsigned total_objects = 0;
  bool is_subtree = false;
  EXPECT_FALSE(document->View()->NeedsLayout());
  document->View()->CountObjectsNeedingLayout(needs_layout_objects,
                                              total_objects, is_subtree);
  EXPECT_EQ(0u, needs_layout_objects);

  UpdateAllLifecyclePhases();
  // Do a real resize to check for invalidations.
  document->View()->SetTracksRasterInvalidations(true);
  web_view_impl->ResizeWithBrowserControls(
      gfx::Size(page_width, smallest_height), browser_controls_height, 0, true);
  UpdateAllLifecyclePhases();

  // The layout size should not have changed.
  ASSERT_EQ(page_width, document->View()->GetLayoutSize().width());
  ASSERT_EQ(smallest_height, document->View()->GetLayoutSize().height());

  EXPECT_FALSE(
      GetRasterInvalidationTracking(*GetFrame()->View())->HasInvalidations());

  document->View()->SetTracksRasterInvalidations(false);
}

TEST_P(VisualViewportTest, InvalidateLayoutViewWhenDocumentSmallerThanView) {
  WebViewImpl* web_view_impl = helper_.InitializeWithAndroidSettings();

  int page_width = 320;
  int page_height = 590;
  float browser_controls_height = 50.0f;
  int largest_height = page_height + browser_controls_height;

  web_view_impl->ResizeWithBrowserControls(gfx::Size(page_width, page_height),
                                           browser_controls_height, 0, true);
  UpdateAllLifecyclePhases();

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(web_view_impl->MainFrameImpl(),
                                     "<div style='height: 20px'>Text</div>",
                                     base_url);
  UpdateAllLifecyclePhases();
  Document* document =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame())->GetDocument();

  // Do a resize to check for invalidations.
  document->View()->SetTracksRasterInvalidations(true);
  web_view_impl->ResizeWithBrowserControls(
      gfx::Size(page_width, largest_height), browser_controls_height, 0, false);
  UpdateAllLifecyclePhases();

  // The layout size should not have changed.
  ASSERT_EQ(page_width, document->View()->GetLayoutSize().width());
  ASSERT_EQ(page_height, document->View()->GetLayoutSize().height());

  // Incremental raster invalidation is needed because the resize exposes
  // unpainted area of background.
  {
    const auto& raster_invalidations =
        GetRasterInvalidationTracking(*GetFrame()->View())->Invalidations();
    EXPECT_THAT(raster_invalidations,
                UnorderedElementsAre(RasterInvalidationInfo{
                    ScrollingBackgroundClient(document).Id(),
                    ScrollingBackgroundClient(document).DebugName(),
                    gfx::Rect(0, 590, 320, 50),
                    PaintInvalidationReason::kIncremental}));
  }

  document->View()->SetTracksRasterInvalidations(false);

  // Resize back to the original size.
  document->View()->SetTracksRasterInvalidations(true);
  web_view_impl->ResizeWithBrowserControls(gfx::Size(page_width, page_height),
                                           browser_controls_height, 0, false);
  UpdateAllLifecyclePhases();

  // No raster invalidation is needed because of no change within the root
  // scrolling layer.
  EXPECT_FALSE(
      GetRasterInvalidationTracking(*GetFrame()->View())->HasInvalidations());

  document->View()->SetTracksRasterInvalidations(false);
}

// Ensure we create transform node for overscroll elasticity properly.
TEST_P(VisualViewportTest, EnsureOverscrollElasticityTransformNode) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  NavigateTo("about:blank");
  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_EQ(visual_viewport.GetOverscrollType() == OverscrollType::kTransform,
            !!visual_viewport.GetOverscrollElasticityTransformNode());

  visual_viewport.SetOverscrollTypeForTesting(OverscrollType::kNone);
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(visual_viewport.GetOverscrollElasticityTransformNode());

  visual_viewport.SetOverscrollTypeForTesting(OverscrollType::kTransform);
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(visual_viewport.GetOverscrollElasticityTransformNode());
}

// Ensure we create effect node for scrollbar properly.
TEST_P(VisualViewportTest, EnsureEffectNodeForScrollbars) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  NavigateTo("about:blank");
  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  auto* vertical_scrollbar = visual_viewport.LayerForVerticalScrollbar();
  auto* horizontal_scrollbar = visual_viewport.LayerForHorizontalScrollbar();
  ASSERT_TRUE(vertical_scrollbar);
  ASSERT_TRUE(horizontal_scrollbar);

  auto& theme = ScrollbarThemeOverlayMobile::GetInstance();
  int scrollbar_thickness = theme.ScrollbarThickness(
      visual_viewport.ScaleFromDIP(), EScrollbarWidth::kAuto);

  EXPECT_EQ(vertical_scrollbar->effect_tree_index(),
            vertical_scrollbar->layer_tree_host()
                ->property_trees()
```