Response:
The user wants me to summarize the functionality of the provided C++ code snippet from a Chromium test file. I need to identify what aspects of the Blink rendering engine are being tested. Specifically, I should look for interactions with JavaScript, HTML, and CSS, and provide examples if they exist. I also need to look for logical reasoning within the tests and provide hypothetical inputs and outputs. Finally, I should identify common user or programming errors that the tests might be preventing.

The code snippet consists of several test cases within a larger test suite. These test cases focus on the `VisualViewport` class in Blink.

Here's a breakdown of the individual tests:

- **TestViewportSizeResetOnNavigation:** Tests that the visual viewport's size, scale, and offset are reset when navigating to a new page.
- **TestFrameViewSizedToViewportMetaMinimumScale:** Tests that the main frame's view is correctly sized based on the `minimum-scale` property in the viewport meta tag.
- **TestVisualViewportGetsSizeInAutoSizeMode:** Tests that the visual viewport gets sized correctly when the browser is in auto-resize mode.
- **TestTextSelectionHandles:** Tests that the position of text selection handles accounts for the visual viewport's position and scale.
- **TestSavedToHistoryItem:** Tests that the visual viewport's offset and scale are saved when a page's history item is created.
- **TestRestoredFromHistoryItem:** Tests that the visual viewport's state is correctly restored from a history item.
- **TestRestoredFromLegacyHistoryItem:** Tests how visual viewport state is restored from older history items that don't explicitly store the visual viewport offset.
- **TestNavigateToSmallerFrameViewHistoryItemClobberBug:** Tests that navigating to a page with a smaller frame view doesn't overwrite the scroll offset in the previous page's history item.
- **TestWebFrameRangeAccountsForVisualViewportScroll:** Tests that the coordinates used for moving a text selection range are correctly offset by the visual viewport's scroll position. (DISABLED)
- **TestWebViewResizeCausesViewportConstrainedLayout:** Tests that resizing the WebView triggers a relayout for elements constrained by the viewport (e.g., fixed position elements).
- **TestContextMenuShownInCorrectLocation:** Tests that the context menu appears at the correct location, even with visual viewport transformations applied.
- **TestClientNotifiedOfScrollEvents:** Tests that the client is notified when the visual viewport scrolls.
- **ScrollIntoViewFractionalOffset:** Tests that calling `scrollIntoView` on a visible element doesn't cause unnecessary scrolling due to fractional offsets.
- **TestBrowserControlsAdjustment:** Tests how the visual viewport and layout viewport are adjusted when browser controls (like the address bar) are shown or hidden.
- **TestBrowserControlsAdjustmentWithScale:** Extends the previous test to include the effects of page scale on browser control adjustments.
- **TestBrowserControlsAdjustmentAndResize:** Tests the interaction between browser control adjustments and window resizing, ensuring correct scroll behavior.
- **TestBrowserControlsShrinkAdjustmentAndResize:** Similar to the previous test, but focuses on scenarios where browser controls shrink the content area.
这段代码是 `blink/renderer/core/frame/visual_viewport_test.cc` 文件的第二部分，主要功能是 **测试 `VisualViewport` 类的各种行为和功能**。`VisualViewport` 代表了用户在网页上实际可见的区域，可以进行缩放和平移。

**主要功能归纳:**

1. **测试导航时的状态重置:**  验证在页面导航时，VisualViewport 的大小、缩放比例和滚动偏移是否会被正确重置。
2. **测试基于 viewport meta 标签的 FrameView 大小:** 验证当页面包含带有 `minimum-scale` 属性的 viewport meta 标签时，主 FrameView 的大小是否能正确根据最小缩放比例进行设置。
3. **测试自动调整大小时的 VisualViewport 大小:**  验证在浏览器启用自动调整大小模式时，VisualViewport 是否能正确获取大小。
4. **测试文本选择句柄的位置:** 验证文本选择句柄的位置是否正确地考虑了 VisualViewport 的偏移和缩放。
5. **测试 VisualViewport 状态的保存和恢复:**  验证 VisualViewport 的滚动偏移和缩放比例是否能正确地保存到浏览历史记录项中，并在页面回退或前进时正确恢复。
6. **测试旧版本历史记录的恢复:**  验证如何从不包含 VisualViewport 滚动偏移信息的旧版本历史记录项中恢复 VisualViewport 的状态。
7. **测试导航到更小 FrameView 时的历史记录问题:**  验证导航到 FrameView 较小的页面时，不会错误地覆盖前一个页面的历史记录项中的滚动偏移。
8. **测试 WebFrame 范围是否考虑 VisualViewport 滚动 (DISABLED):**  验证在移动文本选择范围时，坐标是否会正确地考虑 VisualViewport 的滚动位置。（这个测试被禁用了，可能存在问题或尚未完成）。
9. **测试 WebView 调整大小是否触发 Viewport 约束对象的布局:** 验证当 WebView 的大小改变时，依赖于视口的元素（例如，`position: fixed` 的元素）是否会触发重新布局。
10. **测试上下文菜单的显示位置:** 验证在存在 VisualViewport 偏移的情况下，上下文菜单是否会在正确的位置显示。
11. **测试客户端是否收到滚动事件通知:** 验证当 VisualViewport 发生滚动时，客户端是否会收到相应的通知。
12. **测试 `scrollIntoView` 的小数偏移:** 验证对可见元素调用 `scrollIntoView` 时，是否会因为小数偏移而导致不必要的滚动。
13. **测试浏览器控件调整:** 验证当浏览器控件（例如地址栏）显示或隐藏时，VisualViewport 和 LayoutViewport 如何进行调整。
14. **测试带缩放的浏览器控件调整:**  与上一个测试类似，但增加了缩放比例对浏览器控件调整的影响。
15. **测试浏览器控件调整和窗口大小调整:**  测试浏览器控件调整和窗口大小调整同时发生时的行为，确保滚动位置不会因为取整而产生意外变化。
16. **测试浏览器控件收缩调整和窗口大小调整:**  类似于上一个测试，但关注浏览器控件收缩内容区域的情况。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **viewport meta 标签:**  测试用例 `TestFrameViewSizedToViewportMetaMinimumScale` 涉及到解析 HTML 中的 `<meta name="viewport" content="minimum-scale=2.0">` 这样的标签，并根据其 `minimum-scale` 属性来调整 FrameView 的大小。
    * **页面内容大小:** 多个测试用例，例如 `TestViewportSizeResetOnNavigation` 和 `TestBrowserControlsAdjustment`，会加载具有不同内容宽度的 HTML 页面（例如 "content-width-1000.html"），以测试 VisualViewport 在不同页面布局下的行为。
    * **可滚动元素:**  测试用例 `ScrollIntoViewFractionalOffset` 中，通过 JavaScript 获取 HTML 中的一个 `input` 元素 (`<input id="box">`)，并调用其 `scrollIntoViewIfNeeded` 方法，来测试滚动行为。

* **CSS:**
    * **固定定位 (position: fixed):**  测试用例 `TestWebViewResizeCausesViewportConstrainedLayout` 加载包含固定定位元素的 HTML 页面 ("pinch-viewport-fixed-pos.html")，验证 WebView 调整大小时，这些元素是否会触发重新布局。
    * **内容尺寸和布局:**  VisualViewport 的行为直接受到页面 CSS 布局的影响，例如内容超出视口时的滚动，以及不同元素的尺寸和位置。

* **JavaScript:**
    * **设置/获取缩放和偏移:**  在测试用例中，会使用类似 `visual_viewport.SetScale(2)` 和 `visual_viewport.Move(ScrollOffset(50, 60))` 这样的 C++ 代码来模拟 JavaScript 中对 VisualViewport 的操作。虽然不是直接的 JavaScript 代码，但测试的是 Blink 引擎响应 JavaScript 操作的行为。
    * **执行脚本 (WebScriptSource):**  测试用例 `TestWebFrameRangeAccountsForVisualViewportScroll` 中使用了 `main_frame->ExecuteScript(WebScriptSource("selectRange();"))` 来模拟 JavaScript 代码选择文本的行为，并测试选择范围的计算。
    * **滚动到元素 (scrollIntoViewIfNeeded):**  测试用例 `ScrollIntoViewFractionalOffset` 中，虽然是用 C++ 代码调用，但测试的是与 JavaScript 中 `element.scrollIntoViewIfNeeded()` 方法相同的逻辑。

**逻辑推理与假设输入输出:**

**示例 1: `TestViewportSizeResetOnNavigation`**

* **假设输入:**
    1. 加载一个宽度为 1000px 的页面 ("content-width-1000.html")。
    2. 设置 VisualViewport 的缩放比例为 2，偏移为 (50, 60)。
    3. 导航到另一个页面 ("viewport-device-width.html")，该页面的视口被设置为 `width=device-width`，在当前设备上解析为 320px 宽。

* **预期输出:**
    1. 导航后，VisualViewport 的滚动内容大小应与新的 FrameView 大小 (320x240) 匹配。
    2. VisualViewport 的滚动偏移应重置为 (0, 0)。
    3. VisualViewport 的缩放比例应重置为 1。

**示例 2: `TestTextSelectionHandles`**

* **假设输入:**
    1. 加载包含输入框的页面 ("pinch-viewport-input-field.html")。
    2. 在输入框中选择一些文本。
    3. 获取选择锚点和焦点的原始屏幕坐标。
    4. 设置页面缩放比例为 2。
    5. 移动 VisualViewport 的位置到 (100, 400)。

* **预期输出:**
    1. 重新计算的选择锚点和焦点的屏幕坐标，应该考虑到 VisualViewport 的缩放和偏移。预期新的坐标是将原始坐标减去 VisualViewport 可见区域的偏移，然后再乘以缩放比例。

**用户或编程常见的使用错误及举例说明:**

1. **错误地假设导航后 VisualViewport 的状态保持不变:** 用户或开发者可能错误地认为在页面导航后，之前的缩放或滚动位置仍然有效。`TestViewportSizeResetOnNavigation` 测试防止了这种假设带来的问题。例如，一个 Web 应用可能在导航后尝试使用之前的 VisualViewport 偏移量来定位元素，如果状态没有重置，则可能导致定位错误。

2. **未考虑 `minimum-scale` 导致布局问题:**  开发者可能没有考虑到 viewport meta 标签中的 `minimum-scale` 属性会对页面的初始布局产生影响。`TestFrameViewSizedToViewportMetaMinimumScale` 确保 Blink 引擎正确处理这种情况，防止页面在最小缩放级别下显示不正确。

3. **在自动调整大小模式下错误地设置 VisualViewport 大小:**  在自动调整大小模式下，页面的大小由浏览器决定。开发者不应该手动设置 VisualViewport 的大小。`TestVisualViewportGetsSizeInAutoSizeMode` 验证了在这种模式下 VisualViewport 能正确获取大小，避免开发者进行不必要或错误的设置。

4. **未考虑 VisualViewport 影响坐标计算:**  在处理用户交互（例如点击、触摸）时，开发者可能没有考虑到 VisualViewport 的缩放和偏移，导致坐标计算错误。`TestTextSelectionHandles` 和 `TestContextMenuShownInCorrectLocation` 测试了 Blink 引擎在这方面的正确性，防止开发者因为坐标转换错误而导致交互问题。

5. **历史记录状态管理错误:**  在实现前进/后退功能时，开发者可能会错误地处理 VisualViewport 的状态，导致页面回退后显示位置或缩放比例不正确。 `TestSavedToHistoryItem`, `TestRestoredFromHistoryItem`, 和 `TestRestoredFromLegacyHistoryItem` 等测试确保了 Blink 引擎正确地保存和恢复这些状态。

总而言之，这段代码通过一系列细致的测试用例，验证了 `VisualViewport` 类在各种场景下的行为是否符合预期，从而确保了 Blink 引擎能够正确地处理页面缩放、滚动以及与浏览器控件的交互，为用户提供一致且可靠的浏览体验。这些测试覆盖了与 HTML 结构、CSS 布局以及 JavaScript 交互相关的多个方面，并有助于避免开发者常犯的一些错误。

### 提示词
```
这是目录为blink/renderer/core/frame/visual_viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));

  // Load a wider page first, the navigation should resize the scroll layer to
  // the smaller size on the second navigation.
  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");
  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.SetScale(2);
  visual_viewport.Move(ScrollOffset(50, 60));

  // Move and scale the viewport to make sure it gets reset in the navigation.
  EXPECT_EQ(ScrollOffset(50, 60), visual_viewport.GetScrollOffset());
  EXPECT_EQ(2, visual_viewport.Scale());

  // Navigate again, this time the LocalFrameView should be smaller.
  RegisterMockedHttpURLLoad("viewport-device-width.html");
  NavigateTo(base_url_ + "viewport-device-width.html");
  UpdateAllLifecyclePhases();

  // Ensure the scroll contents size matches the frame view's size.
  EXPECT_EQ(gfx::Size(320, 240), visual_viewport.LayerForScrolling()->bounds());
  EXPECT_EQ(gfx::Rect(0, 0, 320, 240),
            visual_viewport.GetScrollNode()->ContentsRect());

  // Ensure the location and scale were reset.
  EXPECT_EQ(ScrollOffset(), visual_viewport.GetScrollOffset());
  EXPECT_EQ(1, visual_viewport.Scale());
}

// The main LocalFrameView's size should be set such that its the size of the
// visual viewport at minimum scale. Test that the LocalFrameView is
// appropriately sized in the presence of a viewport <meta> tag.
TEST_P(VisualViewportTest, TestFrameViewSizedToViewportMetaMinimumScale) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(320, 240));

  RegisterMockedHttpURLLoad("200-by-300-min-scale-2.html");
  NavigateTo(base_url_ + "200-by-300-min-scale-2.html");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 160));
  UpdateAllLifecyclePhases();

  EXPECT_EQ(gfx::Size(50, 80),
            WebView()->MainFrameImpl()->GetFrameView()->FrameRect().size());
}

// Test that the visual viewport still gets sized in AutoSize/AutoResize mode.
TEST_P(VisualViewportTest, TestVisualViewportGetsSizeInAutoSizeMode) {
  InitializeWithDesktopSettings();

  EXPECT_EQ(gfx::Size(0, 0), WebView()->MainFrameViewWidget()->Size());
  EXPECT_EQ(gfx::Size(0, 0), GetFrame()->GetPage()->GetVisualViewport().Size());

  WebView()->EnableAutoResizeMode(gfx::Size(10, 10), gfx::Size(1000, 1000));

  RegisterMockedHttpURLLoad("200-by-300.html");
  NavigateTo(base_url_ + "200-by-300.html");

  EXPECT_EQ(gfx::Size(200, 300),
            GetFrame()->GetPage()->GetVisualViewport().Size());
}

// Test that the text selection handle's position accounts for the visual
// viewport.
TEST_P(VisualViewportTest, TestTextSelectionHandles) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(500, 800));

  RegisterMockedHttpURLLoad("pinch-viewport-input-field.html");
  NavigateTo(base_url_ + "pinch-viewport-input-field.html");

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  To<LocalFrame>(WebView()->GetPage()->MainFrame())->SetInitialFocus(false);

  gfx::Rect original_anchor;
  gfx::Rect original_focus;
  WebView()->MainFrameViewWidget()->CalculateSelectionBounds(original_anchor,
                                                             original_focus);

  WebView()->SetPageScaleFactor(2);
  visual_viewport.SetLocation(gfx::PointF(100, 400));

  gfx::Rect anchor;
  gfx::Rect focus;
  WebView()->MainFrameViewWidget()->CalculateSelectionBounds(anchor, focus);

  gfx::Point expected = original_anchor.origin();
  expected -=
      gfx::ToFlooredVector2d(visual_viewport.VisibleRect().OffsetFromOrigin());
  expected = gfx::ScaleToRoundedPoint(expected, visual_viewport.Scale());

  EXPECT_EQ(expected, anchor.origin());
  EXPECT_EQ(expected, focus.origin());

  // FIXME(bokan) - http://crbug.com/364154 - Figure out how to test text
  // selection as well rather than just carret.
}

// Test that the HistoryItem for the page stores the visual viewport's offset
// and scale.
TEST_P(VisualViewportTest, TestSavedToHistoryItem) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(200, 300));
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("200-by-300.html");
  NavigateTo(base_url_ + "200-by-300.html");

  EXPECT_FALSE(To<LocalFrame>(WebView()->GetPage()->MainFrame())
                   ->Loader()
                   .GetDocumentLoader()
                   ->GetHistoryItem()
                   ->GetViewState()
                   .has_value());

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.SetScale(2);

  EXPECT_EQ(2, To<LocalFrame>(WebView()->GetPage()->MainFrame())
                   ->Loader()
                   .GetDocumentLoader()
                   ->GetHistoryItem()
                   ->GetViewState()
                   ->page_scale_factor_);

  visual_viewport.SetLocation(gfx::PointF(10, 20));

  EXPECT_EQ(ScrollOffset(10, 20),
            To<LocalFrame>(WebView()->GetPage()->MainFrame())
                ->Loader()
                .GetDocumentLoader()
                ->GetHistoryItem()
                ->GetViewState()
                ->visual_viewport_scroll_offset_);
}

// Test restoring a HistoryItem properly restores the visual viewport's state.
TEST_P(VisualViewportTest, TestRestoredFromHistoryItem) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(200, 300));

  RegisterMockedHttpURLLoad("200-by-300.html");

  HistoryItem* item = MakeGarbageCollected<HistoryItem>();
  item->SetURL(url_test_helpers::ToKURL(base_url_ + "200-by-300.html"));
  item->SetVisualViewportScrollOffset(ScrollOffset(100, 120));
  item->SetPageScaleFactor(2);

  frame_test_helpers::LoadHistoryItem(WebView()->MainFrameImpl(), item,
                                      mojom::FetchCacheMode::kDefault);
  UpdateAllLifecyclePhases();
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_EQ(2, visual_viewport.Scale());

  EXPECT_POINTF_EQ(gfx::PointF(100, 120),
                   visual_viewport.VisibleRect().origin());
}

// Test restoring a HistoryItem without the visual viewport offset falls back to
// distributing the scroll offset between the main frame and the visual
// viewport.
TEST_P(VisualViewportTest, TestRestoredFromLegacyHistoryItem) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 150));

  RegisterMockedHttpURLLoad("200-by-300-viewport.html");

  HistoryItem* item = MakeGarbageCollected<HistoryItem>();
  item->SetURL(
      url_test_helpers::ToKURL(base_url_ + "200-by-300-viewport.html"));
  // (-1, -1) will be used if the HistoryItem is an older version prior to
  // having visual viewport scroll offset.
  item->SetVisualViewportScrollOffset(ScrollOffset(-1, -1));
  item->SetScrollOffset(ScrollOffset(120, 180));
  item->SetPageScaleFactor(2);

  frame_test_helpers::LoadHistoryItem(WebView()->MainFrameImpl(), item,
                                      mojom::FetchCacheMode::kDefault);
  UpdateAllLifecyclePhases();
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_EQ(2, visual_viewport.Scale());
  EXPECT_EQ(ScrollOffset(100, 150),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
  EXPECT_POINTF_EQ(gfx::PointF(20, 30), visual_viewport.VisibleRect().origin());
}

// Test that navigation to a new page with a different sized main frame doesn't
// clobber the history item's main frame scroll offset. crbug.com/371867
TEST_P(VisualViewportTest,
       TestNavigateToSmallerFrameViewHistoryItemClobberBug) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");

  LocalFrameView* frame_view = WebView()->MainFrameImpl()->GetFrameView();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 1000), mojom::blink::ScrollType::kProgrammatic);

  EXPECT_EQ(gfx::Size(1000, 1000), frame_view->FrameRect().size());

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.SetScale(2);
  visual_viewport.SetLocation(gfx::PointF(350, 350));

  Persistent<HistoryItem> firstItem = WebView()
                                          ->MainFrameImpl()
                                          ->GetFrame()
                                          ->Loader()
                                          .GetDocumentLoader()
                                          ->GetHistoryItem();
  EXPECT_EQ(ScrollOffset(0, 1000), firstItem->GetViewState()->scroll_offset_);

  // Now navigate to a page which causes a smaller frame_view. Make sure that
  // navigating doesn't cause the history item to set a new scroll offset
  // before the item was replaced.
  NavigateTo("about:blank");
  frame_view = WebView()->MainFrameImpl()->GetFrameView();

  EXPECT_NE(firstItem, WebView()
                           ->MainFrameImpl()
                           ->GetFrame()
                           ->Loader()
                           .GetDocumentLoader()
                           ->GetHistoryItem());
  EXPECT_LT(frame_view->FrameRect().size().width(), 1000);
  EXPECT_EQ(ScrollOffset(0, 1000), firstItem->GetViewState()->scroll_offset_);
}

// Test that the coordinates sent into moveRangeSelection are offset by the
// visual viewport's location.
TEST_P(VisualViewportTest,
       DISABLED_TestWebFrameRangeAccountsForVisualViewportScroll) {
  InitializeWithDesktopSettings();
  WebView()->GetSettings()->SetDefaultFontSize(12);
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(640, 480));
  RegisterMockedHttpURLLoad("move_range.html");
  NavigateTo(base_url_ + "move_range.html");

  gfx::Rect base_rect;
  gfx::Rect extent_rect;

  WebView()->SetPageScaleFactor(2);
  WebLocalFrame* main_frame = WebView()->MainFrameImpl();

  // Select some text and get the base and extent rects (that's the start of
  // the range and its end). Do a sanity check that the expected text is
  // selected
  main_frame->ExecuteScript(WebScriptSource("selectRange();"));
  EXPECT_EQ("ir", main_frame->SelectionAsText().Utf8());

  WebView()->MainFrameViewWidget()->CalculateSelectionBounds(base_rect,
                                                             extent_rect);
  gfx::Point initial_point = base_rect.origin();
  gfx::Point end_point = extent_rect.origin();

  // Move the visual viewport over and make the selection in the same
  // screen-space location. The selection should change to two characters to the
  // right and down one line.
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.Move(ScrollOffset(60, 25));
  main_frame->MoveRangeSelection(initial_point, end_point);
  EXPECT_EQ("t ", main_frame->SelectionAsText().Utf8());
}

// Test that resizing the WebView causes ViewportConstrained objects to
// relayout.
TEST_P(VisualViewportTest, TestWebViewResizeCausesViewportConstrainedLayout) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(500, 300));

  RegisterMockedHttpURLLoad("pinch-viewport-fixed-pos.html");
  NavigateTo(base_url_ + "pinch-viewport-fixed-pos.html");

  LayoutObject* layout_view = GetFrame()->GetDocument()->GetLayoutView();
  EXPECT_FALSE(layout_view->NeedsLayout());

  GetFrame()->View()->Resize(gfx::Size(500, 200));
  EXPECT_TRUE(layout_view->NeedsLayout());
}

class VisualViewportMockWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  MOCK_METHOD2(UpdateContextMenuDataForTesting,
               void(const ContextMenuData&, const std::optional<gfx::Point>&));
  MOCK_METHOD0(DidChangeScrollOffset, void());
};

MATCHER_P2(ContextMenuAtLocation,
           x,
           y,
           std::string(negation ? "is" : "isn't") + " at expected location [" +
               PrintToString(x) + ", " + PrintToString(y) + "]") {
  return arg.mouse_position.x() == x && arg.mouse_position.y() == y;
}

// Test that the context menu's location is correct in the presence of visual
// viewport offset.
TEST_P(VisualViewportTest, TestContextMenuShownInCorrectLocation) {
  InitializeWithDesktopSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(200, 300));

  RegisterMockedHttpURLLoad("200-by-300.html");
  NavigateTo(base_url_ + "200-by-300.html");

  WebMouseEvent mouse_down_event(WebInputEvent::Type::kMouseDown,
                                 WebInputEvent::kNoModifiers,
                                 WebInputEvent::GetStaticTimeStampForTests());
  mouse_down_event.SetPositionInWidget(10, 10);
  mouse_down_event.SetPositionInScreen(110, 210);
  mouse_down_event.click_count = 1;
  mouse_down_event.button = WebMouseEvent::Button::kRight;

  // Corresponding release event (Windows shows context menu on release).
  WebMouseEvent mouse_up_event(mouse_down_event);
  mouse_up_event.SetType(WebInputEvent::Type::kMouseUp);

  WebLocalFrameClient* old_client = WebView()->MainFrameImpl()->Client();
  VisualViewportMockWebFrameClient mock_web_frame_client;
  EXPECT_CALL(
      mock_web_frame_client,
      UpdateContextMenuDataForTesting(
          ContextMenuAtLocation(mouse_down_event.PositionInWidget().x(),
                                mouse_down_event.PositionInWidget().y()),
          _));

  // Do a sanity check with no scale applied.
  WebView()->MainFrameImpl()->SetClient(&mock_web_frame_client);
  WebView()->MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_down_event, ui::LatencyInfo()));
  WebView()->MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_up_event, ui::LatencyInfo()));

  Mock::VerifyAndClearExpectations(&mock_web_frame_client);
  mouse_down_event.button = WebMouseEvent::Button::kLeft;
  WebView()->MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_down_event, ui::LatencyInfo()));

  // Now pinch zoom into the page and move the visual viewport. The context menu
  // should still appear at the location of the event, relative to the WebView.
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  WebView()->SetPageScaleFactor(2);
  EXPECT_CALL(mock_web_frame_client, DidChangeScrollOffset());
  visual_viewport.SetLocation(gfx::PointF(60, 80));
  EXPECT_CALL(
      mock_web_frame_client,
      UpdateContextMenuDataForTesting(
          ContextMenuAtLocation(mouse_down_event.PositionInWidget().x(),
                                mouse_down_event.PositionInWidget().y()),
          _));

  mouse_down_event.button = WebMouseEvent::Button::kRight;
  WebView()->MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_down_event, ui::LatencyInfo()));
  WebView()->MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_up_event, ui::LatencyInfo()));

  // Reset the old client so destruction can occur naturally.
  WebView()->MainFrameImpl()->SetClient(old_client);
}

// Test that the client is notified if page scroll events.
TEST_P(VisualViewportTest, TestClientNotifiedOfScrollEvents) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(200, 300));

  RegisterMockedHttpURLLoad("200-by-300.html");
  NavigateTo(base_url_ + "200-by-300.html");

  WebLocalFrameClient* old_client = WebView()->MainFrameImpl()->Client();
  VisualViewportMockWebFrameClient mock_web_frame_client;
  WebView()->MainFrameImpl()->SetClient(&mock_web_frame_client);

  WebView()->SetPageScaleFactor(2);
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();

  EXPECT_CALL(mock_web_frame_client, DidChangeScrollOffset());
  visual_viewport.SetLocation(gfx::PointF(60, 80));
  Mock::VerifyAndClearExpectations(&mock_web_frame_client);

  // Scroll vertically.
  EXPECT_CALL(mock_web_frame_client, DidChangeScrollOffset());
  visual_viewport.SetLocation(gfx::PointF(60, 90));
  Mock::VerifyAndClearExpectations(&mock_web_frame_client);

  // Scroll horizontally.
  EXPECT_CALL(mock_web_frame_client, DidChangeScrollOffset());
  visual_viewport.SetLocation(gfx::PointF(70, 90));

  // Reset the old client so destruction can occur naturally.
  WebView()->MainFrameImpl()->SetClient(old_client);
}

// Tests that calling scroll into view on a visible element doesn't cause
// a scroll due to a fractional offset. Bug crbug.com/463356.
TEST_P(VisualViewportTest, ScrollIntoViewFractionalOffset) {
  InitializeWithAndroidSettings();

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(1000, 1000));

  RegisterMockedHttpURLLoad("scroll-into-view.html");
  NavigateTo(base_url_ + "scroll-into-view.html");

  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();
  ScrollableArea* layout_viewport_scrollable_area = frame_view.LayoutViewport();
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  Element* inputBox =
      GetFrame()->GetDocument()->getElementById(AtomicString("box"));

  WebView()->SetPageScaleFactor(2);

  // The element is already in the view so the scrollIntoView shouldn't move
  // the viewport at all.
  WebView()->SetVisualViewportOffset(gfx::PointF(250.25f, 100.25f));
  layout_viewport_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 900.75), mojom::blink::ScrollType::kProgrammatic);
  inputBox->scrollIntoViewIfNeeded(false);

  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled()) {
    EXPECT_EQ(ScrollOffset(0, 900.75),
              layout_viewport_scrollable_area->GetScrollOffset());
  } else {
    EXPECT_EQ(ScrollOffset(0, 900),
              layout_viewport_scrollable_area->GetScrollOffset());
  }
  EXPECT_EQ(ScrollOffset(250.25f, 100.25f), visual_viewport.GetScrollOffset());

  // Change the fractional part of the frameview to one that would round down.
  layout_viewport_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 900.125), mojom::blink::ScrollType::kProgrammatic);
  inputBox->scrollIntoViewIfNeeded(false);

  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled()) {
    EXPECT_EQ(ScrollOffset(0, 900.125),
              layout_viewport_scrollable_area->GetScrollOffset());
  } else {
    EXPECT_EQ(ScrollOffset(0, 900),
              layout_viewport_scrollable_area->GetScrollOffset());
  }
  EXPECT_EQ(ScrollOffset(250.25f, 100.25f), visual_viewport.GetScrollOffset());

  // Repeat both tests above with the visual viewport at a high fractional.
  WebView()->SetVisualViewportOffset(gfx::PointF(250.875f, 100.875f));
  layout_viewport_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 900.75), mojom::blink::ScrollType::kProgrammatic);
  inputBox->scrollIntoViewIfNeeded(false);

  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled()) {
    EXPECT_EQ(ScrollOffset(0, 900.75),
              layout_viewport_scrollable_area->GetScrollOffset());
  } else {
    EXPECT_EQ(ScrollOffset(0, 900),
              layout_viewport_scrollable_area->GetScrollOffset());
  }
  EXPECT_EQ(ScrollOffset(250.875f, 100.875f),
            visual_viewport.GetScrollOffset());

  // Change the fractional part of the frameview to one that would round down.
  layout_viewport_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 900.125), mojom::blink::ScrollType::kProgrammatic);
  inputBox->scrollIntoViewIfNeeded(false);

  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled()) {
    EXPECT_EQ(ScrollOffset(0, 900.125),
              layout_viewport_scrollable_area->GetScrollOffset());
  } else {
    EXPECT_EQ(ScrollOffset(0, 900),
              layout_viewport_scrollable_area->GetScrollOffset());
  }
  EXPECT_EQ(ScrollOffset(250.875f, 100.875f),
            visual_viewport.GetScrollOffset());

  // Both viewports with a 0.5 fraction.
  WebView()->SetVisualViewportOffset(gfx::PointF(250.5f, 100.5f));
  layout_viewport_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 900.5), mojom::blink::ScrollType::kProgrammatic);
  inputBox->scrollIntoViewIfNeeded(false);

  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled()) {
    EXPECT_EQ(ScrollOffset(0, 900.5),
              layout_viewport_scrollable_area->GetScrollOffset());
  } else {
    EXPECT_EQ(ScrollOffset(0, 900),
              layout_viewport_scrollable_area->GetScrollOffset());
  }
  EXPECT_EQ(ScrollOffset(250.5f, 100.5f), visual_viewport.GetScrollOffset());
}

static ScrollOffset expectedMaxLayoutViewportScrollOffset(
    VisualViewport& visual_viewport,
    LocalFrameView& frame_view) {
  float aspect_ratio = visual_viewport.VisibleRect().width() /
                       visual_viewport.VisibleRect().height();
  float new_height = frame_view.FrameRect().width() / aspect_ratio;
  gfx::Size contents_size = frame_view.LayoutViewport()->ContentsSize();
  return ScrollOffset(contents_size.width() - frame_view.FrameRect().width(),
                      contents_size.height() - new_height);
}

TEST_P(VisualViewportTest, TestBrowserControlsAdjustment) {
  InitializeWithAndroidSettings();
  WebView()->ResizeWithBrowserControls(gfx::Size(500, 450), 20, 0, false);
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");
  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();

  visual_viewport.SetScale(1);
  EXPECT_EQ(gfx::SizeF(500, 450), visual_viewport.VisibleRect().size());
  EXPECT_EQ(gfx::Size(1000, 900), frame_view.FrameRect().size());

  // Simulate bringing down the browser controls by 20px.
  WebView()->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1, false, 1, 0,
       cc::BrowserControlsState::kBoth});
  EXPECT_EQ(gfx::SizeF(500, 430), visual_viewport.VisibleRect().size());

  // Test that the scroll bounds are adjusted appropriately: the visual viewport
  // should be shrunk by 20px to 430px. The outer viewport was shrunk to
  // maintain the
  // aspect ratio so it's height is 860px.
  visual_viewport.Move(ScrollOffset(10000, 10000));
  EXPECT_EQ(ScrollOffset(500, 860 - 430), visual_viewport.GetScrollOffset());

  // The outer viewport (LocalFrameView) should be affected as well.
  frame_view.LayoutViewport()->ScrollBy(ScrollOffset(10000, 10000),
                                        mojom::blink::ScrollType::kUser);
  EXPECT_EQ(expectedMaxLayoutViewportScrollOffset(visual_viewport, frame_view),
            frame_view.LayoutViewport()->GetScrollOffset());

  // Simulate bringing up the browser controls by 10.5px.
  WebView()->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1, false, -10.5f / 20, 0,
       cc::BrowserControlsState::kBoth});
  EXPECT_SIZEF_EQ(gfx::SizeF(500, 440.5f),
                  visual_viewport.VisibleRect().size());

  // maximumScrollPosition |ceil|s the browser controls adjustment.
  visual_viewport.Move(ScrollOffset(10000, 10000));
  EXPECT_VECTOR2DF_EQ(ScrollOffset(500, 881 - 441),
                      visual_viewport.GetScrollOffset());

  // The outer viewport (LocalFrameView) should be affected as well.
  frame_view.LayoutViewport()->ScrollBy(ScrollOffset(10000, 10000),
                                        mojom::blink::ScrollType::kUser);
  EXPECT_EQ(expectedMaxLayoutViewportScrollOffset(visual_viewport, frame_view),
            frame_view.LayoutViewport()->GetScrollOffset());
}

TEST_P(VisualViewportTest, TestBrowserControlsAdjustmentWithScale) {
  InitializeWithAndroidSettings();
  WebView()->ResizeWithBrowserControls(gfx::Size(500, 450), 20, 0, false);
  UpdateAllLifecyclePhases();

  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");
  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();

  visual_viewport.SetScale(2);
  EXPECT_EQ(gfx::SizeF(250, 225), visual_viewport.VisibleRect().size());
  EXPECT_EQ(gfx::Size(1000, 900), frame_view.FrameRect().size());

  // Simulate bringing down the browser controls by 20px. Since we're zoomed in,
  // the browser controls take up half as much space (in document-space) than
  // they do at an unzoomed level.
  WebView()->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1, false, 1, 0,
       cc::BrowserControlsState::kBoth});
  EXPECT_EQ(gfx::SizeF(250, 215), visual_viewport.VisibleRect().size());

  // Test that the scroll bounds are adjusted appropriately.
  visual_viewport.Move(ScrollOffset(10000, 10000));
  EXPECT_EQ(ScrollOffset(750, 860 - 215), visual_viewport.GetScrollOffset());

  // The outer viewport (LocalFrameView) should be affected as well.
  frame_view.LayoutViewport()->ScrollBy(ScrollOffset(10000, 10000),
                                        mojom::blink::ScrollType::kUser);
  ScrollOffset expected =
      expectedMaxLayoutViewportScrollOffset(visual_viewport, frame_view);
  EXPECT_EQ(expected, frame_view.LayoutViewport()->GetScrollOffset());

  // Scale back out, LocalFrameView max scroll shouldn't have changed. Visual
  // viewport should be moved up to accommodate larger view.
  WebView()->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 0.5f, false, 0, 0,
       cc::BrowserControlsState::kBoth});
  EXPECT_EQ(1, visual_viewport.Scale());
  EXPECT_EQ(expected, frame_view.LayoutViewport()->GetScrollOffset());
  frame_view.LayoutViewport()->ScrollBy(ScrollOffset(10000, 10000),
                                        mojom::blink::ScrollType::kUser);
  EXPECT_EQ(expected, frame_view.LayoutViewport()->GetScrollOffset());

  EXPECT_EQ(ScrollOffset(500, 860 - 430), visual_viewport.GetScrollOffset());
  visual_viewport.Move(ScrollOffset(10000, 10000));
  EXPECT_EQ(ScrollOffset(500, 860 - 430), visual_viewport.GetScrollOffset());

  // Scale out, use a scale that causes fractional rects.
  WebView()->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 0.8f, false, -1, 0,
       cc::BrowserControlsState::kBoth});
  EXPECT_EQ(gfx::SizeF(625, 562.5), visual_viewport.VisibleRect().size());

  // Bring out the browser controls by 11
  WebView()->MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1, false, 11 / 20.f, 0,
       cc::BrowserControlsState::kBoth});
  EXPECT_EQ(gfx::SizeF(625, 548.75), visual_viewport.VisibleRect().size());

  // Ensure max scroll offsets are updated properly.
  visual_viewport.Move(ScrollOffset(10000, 10000));
  EXPECT_VECTOR2DF_EQ(ScrollOffset(375, 877.5 - 548.75),
                      visual_viewport.GetScrollOffset());

  frame_view.LayoutViewport()->ScrollBy(ScrollOffset(10000, 10000),
                                        mojom::blink::ScrollType::kUser);
  EXPECT_EQ(expectedMaxLayoutViewportScrollOffset(visual_viewport, frame_view),
            frame_view.LayoutViewport()->GetScrollOffset());
}

// Tests that a scroll all the way to the bottom of the page, while hiding the
// browser controls doesn't cause a clamp in the viewport scroll offset when the
// top controls initiated resize occurs.
TEST_P(VisualViewportTest, TestBrowserControlsAdjustmentAndResize) {
  int browser_controls_height = 20;
  int visual_viewport_height = 450;
  int layout_viewport_height = 900;
  float page_scale = 2;
  float min_page_scale = 0.5;

  InitializeWithAndroidSettings();

  // Initialize with browser controls showing and shrinking the Blink size.
  cc::BrowserControlsParams controls;
  controls.top_controls_height = browser_controls_height;
  controls.browser_controls_shrink_blink_size = true;
  // TODO(danakj): The browser (RenderWidgetHostImpl) doesn't shrink the widget
  // size by the browser controls, only the visible_viewport_size, but this test
  // shrinks and grows both.
  WebView()->ResizeWithBrowserControls(
      gfx::Size(500, visual_viewport_height - browser_controls_height),
      gfx::Size(500, visual_viewport_height - browser_controls_height),
      controls);
  UpdateAllLifecyclePhases();
  WebView()->GetBrowserControls().SetShownRatio(1, 0);

  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");
  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();

  visual_viewport.SetScale(page_scale);
  EXPECT_EQ(gfx::SizeF(250, (visual_viewport_height - browser_controls_height) /
                                page_scale),
            visual_viewport.VisibleRect().size());
  EXPECT_EQ(gfx::Size(1000, layout_viewport_height -
                                browser_controls_height / min_page_scale),
            frame_view.FrameRect().size());
  EXPECT_EQ(gfx::Size(500, visual_viewport_height - browser_controls_height),
            visual_viewport.Size());

  // Scroll all the way to the bottom, hiding the browser controls in the
  // process.
  visual_viewport.Move(ScrollOffset(10000, 10000));
  frame_view.LayoutViewport()->ScrollBy(ScrollOffset(10000, 10000),
                                        mojom::blink::ScrollType::kUser);
  WebView()->GetBrowserControls().SetShownRatio(0, 0);

  EXPECT_EQ(gfx::SizeF(250, visual_viewport_height / page_scale),
            visual_viewport.VisibleRect().size());

  ScrollOffset frame_view_expected =
      expectedMaxLayoutViewportScrollOffset(visual_viewport, frame_view);
  ScrollOffset visual_viewport_expected = ScrollOffset(
      750, layout_viewport_height - visual_viewport_height / page_scale);

  EXPECT_EQ(visual_viewport_expected, visual_viewport.GetScrollOffset());
  EXPECT_EQ(frame_view_expected,
            frame_view.LayoutViewport()->GetScrollOffset());

  ScrollOffset total_expected = visual_viewport_expected + frame_view_expected;

  // Resize the widget and visible viewport to match the browser controls
  // adjustment. Ensure that the total offset (i.e. what the user sees) doesn't
  // change because of clamping the offsets to valid values.
  controls.browser_controls_shrink_blink_size = false;
  WebView()->ResizeWithBrowserControls(gfx::Size(500, visual_viewport_height),
                                       gfx::Size(500, visual_viewport_height),
                                       controls);
  UpdateAllLifecyclePhases();

  EXPECT_EQ(gfx::Size(500, visual_viewport_height), visual_viewport.Size());
  EXPECT_EQ(gfx::SizeF(250, visual_viewport_height / page_scale),
            visual_viewport.VisibleRect().size());
  EXPECT_EQ(gfx::Size(1000, layout_viewport_height),
            frame_view.FrameRect().size());

  EXPECT_EQ(total_expected, visual_viewport.GetScrollOffset() +
                                frame_view.LayoutViewport()->GetScrollOffset());

  EXPECT_EQ(visual_viewport_expected, visual_viewport.GetScrollOffset());
  EXPECT_EQ(frame_view_expected,
            frame_view.LayoutViewport()->GetScrollOffset());
}

// Tests that a scroll all the way to the bottom while showing the browser
// controls doesn't cause a clamp to the viewport scroll offset when the browser
// controls initiated resize occurs.
TEST_P(VisualViewportTest, TestBrowserControlsShrinkAdjustmentAndResize) {
  int browser_controls_height = 20;
  int visual_viewport_height = 500;
  int layout_viewport_height = 1000;
  int content_height = 2000;
  float page_scale = 2;
  float min_page_scale = 0.5;

  InitializeWithAndroidSettings();

  // Initialize with browser controls hidden and not shrinking the Blink size.
  WebView()->ResizeWithBrowserControls(gfx::Size(500, visual_viewport_height),
                                       20, 0, false);
  UpdateAllLifecyclePhases();
  WebView()->GetBrowserControls().SetShownRatio(0, 0);

  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");
  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  LocalFrameView& frame_view = *WebView()->MainFrameImpl()->GetFrameView();

  visual_viewport.SetScale(page_scale);
  EXPECT_EQ(gfx::SizeF(250, visual_viewport_height / page_scale),
            visual_viewport.VisibleRect().size());
  EXPECT_EQ(gfx::Size(1000, layout_viewport_height),
            frame_view.FrameRect().size());
  EXPECT_EQ(gfx::Size(
```