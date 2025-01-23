Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is a test file for the Blink rendering engine, specifically focusing on the `PaintLayerScrollableArea` class.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core component:** The filename `paint_layer_scrollable_area_test.cc` clearly indicates that the tests are for the `PaintLayerScrollableArea` class.

2. **Recognize the testing framework:** The presence of `TEST_P` and `EXPECT_EQ`/`EXPECT_TRUE`/`EXPECT_FALSE` strongly suggests this is using a testing framework (likely Google Test). The `SetBodyInnerHTML` function is a hint that these tests involve rendering HTML.

3. **Analyze the individual test cases:** Go through each `TEST_P` block and try to understand what it's testing:
    * **`ViewScrollWithFixedAttachmentBackground`:** Checks how scrolling the main view affects elements with `background-attachment: fixed`. It examines invalidation flags and paint properties.
    * **`ViewScrollWithSolidColorFixedAttachmentBackground`:** Similar to the previous test, but with a solid color background. This likely tests optimizations or different behavior for solid colors.
    * **`ViewScrollWithFixedAttachmentBackgroundPreferCompositingToLCDText`:** This test seems to investigate how the `prefer-compositing-to-lcd-text` setting influences the invalidation behavior of fixed backgrounds during scrolling.
    * **`ViewScrollWithScrollAttachmentBackground`:**  Tests scrolling with `background-attachment: scroll` on the root element.
    * **`ViewScrollWithLocalAttachmentBackground`:** Tests scrolling with `background-attachment: local` on the root element.
    * **`HitTestOverlayScrollbars`:**  Checks if hit-testing correctly identifies overlay scrollbars.
    * **`ShowNonCompositedScrollbarOnCompositorScroll`:** Examines the behavior of non-composited scrollbars when scrolling is initiated by the compositor.
    * **`CompositedStickyDescendant`:** Tests how sticky positioned elements are handled during scrolling, specifically checking their transform properties.
    * **`StickyPositionUseCounter`:** Verifies if the `position: sticky` CSS property is correctly tracked for usage statistics.
    * **`IgnoreDelayedScrollOnDestroyedLayer`:** This looks like a crash prevention test, ensuring that attempting to apply a delayed scroll offset on a destroyed layer doesn't cause a crash.
    * **`ScrollbarMaximum`:**  Tests that the scrollbar correctly reports its maximum scroll position.
    * **`ScrollingBackgroundVisualRect`:** Checks the calculation of the visual rectangle for the scrolling background.
    * **`RtlScrollOriginSnapping`:** Focuses on right-to-left (RTL) layouts and how the scroll origin is adjusted.
    * **`ShowCustomResizerInTextarea`:** Checks if a custom resizer is displayed for textareas.
    * **`ApplyPendingHistoryRestoreScrollOffsetTwice`:**  Tests the logic of restoring scroll positions from history and ensures it doesn't have unintended side effects when called multiple times.
    * **`CompositeWithTrivial3D`:**  Verifies if applying a trivial 3D transform forces composited scrolling.
    * **`LowEndCompositeWithTrivial3D`:** Similar to the previous test but specifically for low-end devices.
    * **`RootScrollbarShouldUseParentOfOverscrollNodeAsTransformNode`:** Checks the transform node hierarchy for root and non-root scrollbars.
    * **`ResizeSmallerToBeScrollableWithResizerAndStackedChild`:** Tests the interaction between resizable elements, scrolling, and stacking contexts.
    * **`RemoveAddResizerWithoutScrollbars`:** Examines adding and removing the resizer on an element that doesn't initially have scrollbars.
    * **Several `UsedColorSchemeRootScrollbars...` tests:** These tests focus on how the `color-scheme` CSS property and user preferences affect the appearance of scrollbars, particularly the root scrollbars. They check invalidation behavior when the color scheme changes.

4. **Identify relationships to web technologies:** Note the connections to HTML (structure), CSS (styling, properties like `background-attachment`, `overflow`, `position: sticky`, `resize`, `color-scheme`), and JavaScript (programmatic scrolling via `SetScrollOffset`).

5. **Infer assumptions and inputs/outputs:**  For tests involving scrolling, the assumption is there's an element with `overflow: scroll` and content that exceeds its boundaries. Input would be triggering a scroll (programmatic or potentially user interaction), and output would be the state of invalidation flags, paint properties, and scroll positions.

6. **Consider common errors:**  Think about what developers might do wrong when dealing with scrolling, fixed backgrounds, sticky positioning, or custom scrollbars. Examples include incorrect assumptions about repaint behavior, issues with z-index and overlapping content, or unexpected behavior on different devices.

7. **Relate to debugging:**  The tests provide insights into how to debug paint and scrolling issues. Understanding when and why repaints are triggered, how fixed backgrounds are handled, and how compositing is involved are all crucial for debugging.

8. **Synthesize the summary:** Combine the observations from the individual tests and the broader context into a concise description of the file's purpose. Emphasize the core functionality being tested (scrollable areas, painting), the CSS properties involved, and the kinds of scenarios covered.

9. **Focus on the "归纳一下它的功能" (summarize its functionality) request for part 2:** Since this is part 2 of a 3-part request, focus on summarizing the overall functionality of the *provided code snippet* rather than trying to encompass the entire file.

This systematic approach allows for a comprehensive understanding of the test file and its role in verifying the behavior of the Blink rendering engine's scrollable areas.
好的，这是对提供的代码片段的功能归纳：

**功能归纳：**

这段代码主要测试了 `PaintLayerScrollableArea` 类在处理不同类型的滚动场景，特别是与背景绘制和 CSS `background-attachment` 属性相关的行为。它涵盖了以下几个方面的功能测试：

1. **固定背景 (fixed attachment background) 的滚动影响：**
   - 测试了当视口（viewport）滚动时，带有 `background-attachment: fixed` 属性的元素是否需要进行全量重绘 (full paint invalidation)。
   - 测试了当自身可滚动区域滚动时，带有 `background-attachment: fixed` 属性的元素是否需要进行全量重绘。
   - 区分了线性渐变背景和纯色背景在 `background-attachment: fixed` 时的处理差异。
   - 考虑了 `prefer-compositing-to-lcd-text` 设置对固定背景滚动重绘的影响。

2. **其他背景附件属性的滚动影响：**
   - 测试了 `background-attachment: scroll` 和 `background-attachment: local` 在视口滚动时的行为，以及是否需要属性更新 (NeedsPaintPropertyUpdate)。

3. **覆盖滚动条 (overlay scrollbars) 的命中测试 (hit testing)：**
   - 测试了当覆盖滚动条显示或隐藏时，命中测试是否能正确识别滚动条区域。

4. **合成器滚动 (compositor scroll) 时非合成滚动条的显示：**
   - 测试了当使用合成器滚动时，即使滚动条通常是覆盖的，也会显示出来的情况。

5. **合成的粘性定位 (composited sticky descendant)：**
   - 测试了带有 `position: sticky` 属性的元素在滚动时的变换 (transform) 属性是否正确更新，以实现粘性效果。

6. **粘性定位的使用计数器 (sticky position use counter)：**
   - 测试了是否正确记录了 `position: sticky` 属性的使用情况。

7. **延迟滚动偏移量钳制 (delayed scroll offset clamping)：**
   - 测试了在图层被销毁后，忽略延迟的滚动偏移量钳制操作，防止崩溃。

8. **滚动条最大值 (scrollbar maximum)：**
   - 测试了滚动条是否能正确报告其最大滚动位置。

9. **滚动背景的可视矩形 (scrolling background visual rect)：**
   - 测试了滚动背景的可视矩形的计算是否正确。

10. **RTL 滚动原点捕捉 (RTL scroll origin snapping)：**
    - 测试了在 RTL (Right-to-Left) 布局下，滚动原点是否被正确捕捉，以保证最大滚动偏移量为零。

11. **在文本域 (textarea) 中显示自定义调整大小控件 (custom resizer)：**
    - 测试了在 `textarea` 元素上是否能正确显示自定义的调整大小控件。

12. **多次应用待处理的历史恢复滚动偏移量 (apply pending history restore scroll offset twice)：**
    - 测试了多次调用 `ApplyPendingHistoryRestoreScrollOffset` 方法是否会产生预期外的副作用。

13. **通过简单的 3D 变换进行合成 (composite with trivial 3D)：**
    - 测试了即使应用了简单的 3D 变换 (如 `translateZ(0)`），是否会触发合成滚动。

14. **低端设备上的简单 3D 合成：**
    - 针对低端设备，测试了简单的 3D 变换是否仍然能触发合成滚动。

15. **根滚动条应使用溢出滚动节点 (overscroll node) 的父节点作为变换节点：**
    - 测试了根滚动条和非根滚动条在渲染时使用的变换节点的层级关系。

16. **缩小可滚动区域并带有调整大小控件和堆叠子元素 (ResizeSmallerToBeScrollableWithResizerAndStackedChild)：**
    - 测试了当一个可调整大小的元素被缩小到可以滚动时，其滚动条和调整大小控件的渲染行为，特别是与堆叠上下文的子元素的关系。

17. **移除和添加没有滚动条的调整大小控件 (RemoveAddResizerWithoutScrollbars)：**
    - 测试了在一个没有滚动条的元素上添加和移除调整大小控件时的行为。

18. **使用的颜色方案 (used color scheme) 对根滚动条的影响：**
    - 测试了 `color-scheme` CSS 属性以及用户偏好设置如何影响根滚动条的样式，并检查了在颜色方案改变时是否触发了必要的重绘。

**总结来说，这段代码主要集中在测试 `PaintLayerScrollableArea` 类在各种滚动和背景渲染场景下的正确性和性能，特别是涉及到 CSS 的 `background-attachment`、`overflow`、`position: sticky`、`resize` 和 `color-scheme` 属性时的行为。**

### 提示词
```
这是目录为blink/renderer/core/paint/paint_layer_scrollable_area_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ML(
    <style>
      html, #fixed-background {
        background: linear-gradient(black, white) fixed;
      }
      #fixed-background {
        width: 200px;
        height: 200px;
        overflow: scroll;
      }
    </style>
    <div id="fixed-background">
      <div style="height: 3000px"></div>
    </div>
    <div style="height: 3000px"></div>
  )HTML");

  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            GetLayoutView().GetBackgroundPaintLocation());
  auto* fixed_background_div = GetLayoutBoxByElementId("fixed-background");
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            fixed_background_div->GetBackgroundPaintLocation());
  auto* div_scrollable_area = fixed_background_div->GetScrollableArea();
  auto* view_scrollable_area = GetLayoutView().GetScrollableArea();

  // Programmatically changing the view's scroll offset. Should invalidate all
  // objects with fixed attachment background.
  view_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 1), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(fixed_background_div->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(fixed_background_div->BackgroundNeedsFullPaintInvalidation());
  EXPECT_FALSE(fixed_background_div->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(GetLayoutView().ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(GetLayoutView().BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(GetLayoutView().NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Programmatically changing the div's scroll offset. Should invalidate the
  // scrolled div with fixed attachment background.
  div_scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                       mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(fixed_background_div->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(fixed_background_div->BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(fixed_background_div->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(GetLayoutView().ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().BackgroundNeedsFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().NeedsPaintPropertyUpdate());
}

TEST_P(PaintLayerScrollableAreaTest,
       ViewScrollWithSolidColorFixedAttachmentBackground) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html, #fixed-background {
        background: green fixed;
      }
      #fixed-background {
        width: 200px;
        height: 200px;
        overflow: scroll;
      }
    </style>
    <div id="fixed-background">
      <div style="height: 3000px"></div>
    </div>
    <div style="height: 3000px"></div>
  )HTML");

  // Fixed-attachment solid-color background should be treated as default
  // attachment.
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            GetLayoutView().GetBackgroundPaintLocation());
  auto* fixed_background_div = GetLayoutBoxByElementId("fixed-background");
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            fixed_background_div->GetBackgroundPaintLocation());
  auto* div_scrollable_area = fixed_background_div->GetScrollableArea();
  auto* view_scrollable_area = GetLayoutView().GetScrollableArea();

  // Programmatically changing the view's scroll offset. Should invalidate all
  // objects with fixed attachment background.
  view_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 1), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_FALSE(fixed_background_div->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(fixed_background_div->BackgroundNeedsFullPaintInvalidation());
  EXPECT_FALSE(fixed_background_div->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(GetLayoutView().ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(GetLayoutView().NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Programmatically changing the div's scroll offset. Should invalidate the
  // scrolled div with fixed attachment background.
  div_scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                       mojom::blink::ScrollType::kProgrammatic);
  EXPECT_FALSE(fixed_background_div->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(fixed_background_div->BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(fixed_background_div->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(GetLayoutView().ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().BackgroundNeedsFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().NeedsPaintPropertyUpdate());
}

TEST_P(PaintLayerScrollableAreaTest,
       ViewScrollWithFixedAttachmentBackgroundPreferCompositingToLCDText) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>
      html {
        background: linear-gradient(black, white) fixed;
      }
      #fixed-background {
        background: linear-gradient(black, white) fixed,
                    linear-gradient(blue, yellow) local;
        width: 200px;
        height: 200px;
        overflow: scroll;
      }
    </style>
    <div id="fixed-background">
      <div style="height: 3000px"></div>
    </div>
    <div style="height: 3000px"></div>
  )HTML");

  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            GetLayoutView().GetBackgroundPaintLocation());
  auto* fixed_background_div = GetLayoutBoxByElementId("fixed-background");
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            fixed_background_div->GetBackgroundPaintLocation());
  auto* div_scrollable_area = fixed_background_div->GetScrollableArea();
  auto* view_scrollable_area = GetLayoutView().GetScrollableArea();

  // Programmatically changing the view's scroll offset. Should invalidate all
  // objects with fixed attachment background except the layout view.
  view_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 1), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(fixed_background_div->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(fixed_background_div->BackgroundNeedsFullPaintInvalidation());
  EXPECT_FALSE(fixed_background_div->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(GetLayoutView().ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(GetLayoutView().NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Programmatically changing the div's scroll offset. Should invalidate the
  // scrolled div with fixed attachment background.
  div_scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                       mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(fixed_background_div->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(fixed_background_div->BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(fixed_background_div->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(GetLayoutView().ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().BackgroundNeedsFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().NeedsPaintPropertyUpdate());
}

TEST_P(PaintLayerScrollableAreaTest, ViewScrollWithScrollAttachmentBackground) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>html { background: linear-gradient(black, white) scroll; }</style>
    <div style="height: 3000px"></div>
  )HTML");

  // background-attachment: scroll on the view is equivalent to local.
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            GetLayoutView().GetBackgroundPaintLocation());
  auto* view_scrollable_area = GetLayoutView().GetScrollableArea();
  EXPECT_FALSE(view_scrollable_area->BackgroundNeedsRepaintOnScroll());
  view_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 1), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_FALSE(GetLayoutView().ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(GetLayoutView().NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintLayerScrollableAreaTest, ViewScrollWithLocalAttachmentBackground) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>html { background: linear-gradient(black, white) local; }</style>
    <div style="height: 3000px"></div>
  )HTML");

  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            GetLayoutView().GetBackgroundPaintLocation());
  auto* view_scrollable_area = GetLayoutView().GetScrollableArea();
  EXPECT_FALSE(view_scrollable_area->BackgroundNeedsRepaintOnScroll());
  view_scrollable_area->SetScrollOffset(
      ScrollOffset(0, 1), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_FALSE(GetLayoutView().ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(GetLayoutView().BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(GetLayoutView().NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintLayerScrollableAreaTest, HitTestOverlayScrollbars) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
    }
    #scroller {
      overflow: scroll;
      height: 100px;
      width: 100px;
    }
    #scrolled {
      width: 1000px;
      height: 1000px;
    }
    </style>
    <div id='scroller'><div id='scrolled'></div></div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();

  scrollable_area->SetScrollbarsHiddenIfOverlay(true);

  HitTestRequest hit_request(HitTestRequest::kMove | HitTestRequest::kReadOnly);
  HitTestLocation location(PhysicalOffset(95, 5));
  HitTestResult hit_result(hit_request, location);
  GetDocument().GetLayoutView()->HitTest(location, hit_result);
  EXPECT_EQ(hit_result.GetScrollbar(), nullptr);
  location = HitTestLocation(PhysicalOffset(5, 95));
  hit_result = HitTestResult(hit_request, location);
  GetDocument().GetLayoutView()->HitTest(location, hit_result);
  EXPECT_EQ(hit_result.GetScrollbar(), nullptr);

  scrollable_area->SetScrollbarsHiddenIfOverlay(false);

  location = HitTestLocation(PhysicalOffset(95, 5));
  hit_result = HitTestResult(hit_request, location);
  GetDocument().GetLayoutView()->HitTest(location, hit_result);
  EXPECT_EQ(hit_result.GetScrollbar(), scrollable_area->VerticalScrollbar());
  location = HitTestLocation(PhysicalOffset(5, 95));
  hit_result = HitTestResult(hit_request, location);
  GetDocument().GetLayoutView()->HitTest(location, hit_result);
  EXPECT_EQ(hit_result.GetScrollbar(), scrollable_area->HorizontalScrollbar());
}

TEST_P(PaintLayerScrollableAreaTest,
       ShowNonCompositedScrollbarOnCompositorScroll) {
  // Scrollbars are always composited in RasterInducingScroll.
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    return;
  }

  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
    }
    #scroller {
      overflow: scroll;
      height: 100px;
      width: 100px;
    }
    #scrolled {
      width: 1000px;
      height: 1000px;
    }
    </style>
    <div id='scroller'><div id='scrolled'></div></div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();

  scrollable_area->SetScrollbarsHiddenIfOverlay(true);

  EXPECT_TRUE(scrollable_area->ScrollbarsHiddenIfOverlay());

  // This is false because we prefer LCD-text by default and the scroller
  // doesn't have an opaque background to preserve LCD-text if composited.
  EXPECT_FALSE(scrollable_area->UsesCompositedScrolling());

  scrollable_area->SetScrollOffset(ScrollOffset(0, 20),
                                   mojom::blink::ScrollType::kCompositor);

  EXPECT_FALSE(scrollable_area->ScrollbarsHiddenIfOverlay());
}

TEST_P(PaintLayerScrollableAreaTest, CompositedStickyDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id=scroller style="overflow: scroll; width: 500px; height: 300px;
        will-change: transform">
      <div id=sticky style="top: 0px; position: sticky; background: green">
      </div>
      <div style="width: 10px; height: 700px; background: lightblue"></div>
    </div>
  )HTML");
  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();
  auto* sticky = GetLayoutBoxByElementId("sticky");

  EXPECT_EQ(&sticky->FirstFragment().LocalBorderBoxProperties().Transform(),
            sticky->FirstFragment().PaintProperties()->StickyTranslation());
  EXPECT_TRUE(sticky->FirstFragment()
                  .PaintProperties()
                  ->StickyTranslation()
                  ->IsIdentity());

  scrollable_area->SetScrollOffset(ScrollOffset(0, 50),
                                   mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(gfx::Vector2dF(0, 50), sticky->FirstFragment()
                                       .PaintProperties()
                                       ->StickyTranslation()
                                       ->Get2dTranslation());
}

TEST_P(PaintLayerScrollableAreaTest, StickyPositionUseCounter) {
  SetBodyInnerHTML(R"HTML(
    <div style="overflow: scroll; width: 500px; height: 300px;">
      <div id=test></div>
      <div id=forcescroll style="width: 10px; height: 700px;"></div>
    </div>
  )HTML");
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kPositionSticky));

  auto* test = GetElementById("test");
  test->setAttribute(html_names::kStyleAttr, AtomicString("position: sticky;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kPositionSticky));

  test->setAttribute(html_names::kStyleAttr,
                     AtomicString("top: 0; position: sticky;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kPositionSticky));
}

// Delayed scroll offset clamping should not crash. https://crbug.com/842495
TEST_P(PaintLayerScrollableAreaTest, IgnoreDelayedScrollOnDestroyedLayer) {
  SetBodyInnerHTML(R"HTML(
    <div id=scroller style="overflow: scroll; width: 200px; height: 200px;">
      <div style="height: 1000px;"></div>
    </div>
  )HTML");
  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  {
    PaintLayerScrollableArea::DelayScrollOffsetClampScope scope;
    PaintLayerScrollableArea::DelayScrollOffsetClampScope::SetNeedsClamp(
        scroller->GetLayoutBox()->GetScrollableArea());
    scroller->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                     CSSValueID::kNone);
    UpdateAllLifecyclePhasesForTest();
  }
}

TEST_P(PaintLayerScrollableAreaTest, ScrollbarMaximum) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #spacer {
      height: 17.984375px;
    }
    #scroller {
      border-top: 0.328125px solid gray;
      border-bottom: 0.328125px solid gray;
      height:149.34375px;
      width: 100px;
      overflow-y:auto;
    }
    #content {
      height: 156.578125px;
    }
    </style>
    <div id='spacer'></div>
    <div id='scroller'>
      <div id='content'></div>
    </div>
  )HTML");

  LayoutBox* scroller = GetLayoutBoxByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();

  scrollable_area->ScrollBy(ScrollOffset(0, 1000),
                            mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(scrollbar->CurrentPos(), scrollbar->Maximum());
}

TEST_P(PaintLayerScrollableAreaTest, ScrollingBackgroundVisualRect) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      #scroller {
        width: 100.7px;
        height: 100.4px;
        overflow: scroll;
        border-top: 2.6px solid blue;
        border-left: 2.4px solid blue;
        will-change: transform;
      }
      #content {
        width: 50.7px;
        height: 200.4px;
      }
    </style>
    <div id="scroller">
      <div id="content"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(2, 2, 101, 200),
            GetLayoutBoxByElementId("scroller")
                ->GetScrollableArea()
                ->ScrollingBackgroundVisualRect(PhysicalOffset()));
}

TEST_P(PaintLayerScrollableAreaTest, RtlScrollOriginSnapping) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #container {
        direction: rtl;
        display: flex;
      }
      #scroller {
        width: 100%;
        height: 100px;
        overflow: hidden;
      }
      #scroller-content {
        width: 200%;
        height: 200px;
      }
    </style>
    <div id="container">
      <div id="first-child" style="flex:1; display:none"></div>
      <div style="flex:2.2">
        <div id="scroller">
          <div id ="scroller-content"></div>
        </div>
      </div>
    </div>
  )HTML");

  // Test that scroll origin is snapped such that maximum scroll offset is
  // always zero for an rtl block.

  GetFrame().View()->Resize(795, 600);
  UpdateAllLifecyclePhasesForTest();
  LayoutBox* scroller = GetLayoutBoxByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  EXPECT_EQ(scrollable_area->MaximumScrollOffsetInt(), gfx::Vector2d(0, 100));

  Element* first_child = GetElementById("first-child");
  first_child->RemoveInlineStyleProperty(CSSPropertyID::kDisplay);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(scrollable_area->MaximumScrollOffsetInt(), gfx::Vector2d(0, 100));
}

TEST_P(PaintLayerScrollableAreaTest, ShowCustomResizerInTextarea) {
  GetPage().GetSettings().SetTextAreasAreResizable(true);
  SetBodyInnerHTML(R"HTML(
    <!doctype HTML>
    <style>
      textarea {
        width: 200px;
        height: 100px;
      }
      ::-webkit-resizer {
        background-color: red;
      }
    </style>
    <textarea id="target"></textarea>
  )HTML");

  const auto* paint_layer = GetPaintLayerByElementId("target");
  ASSERT_TRUE(paint_layer);

  EXPECT_NE(paint_layer->GetScrollableArea()->Resizer(), nullptr);
}

TEST_P(PaintLayerScrollableAreaTest,
       ApplyPendingHistoryRestoreScrollOffsetTwice) {
  GetPage().GetSettings().SetTextAreasAreResizable(true);
  SetBodyInnerHTML(R"HTML(
    <!doctype HTML>
    <div id="target" style="overflow: scroll; width: 50px; height: 50px">
      <div style="width: 50px; height: 500px">
      </div>
    </div>
  )HTML");

  const auto* paint_layer = GetPaintLayerByElementId("target");
  auto* scrollable_area = paint_layer->GetScrollableArea();

  HistoryItem::ViewState view_state;
  view_state.scroll_offset_ = ScrollOffset(0, 100);
  scrollable_area->SetPendingHistoryRestoreScrollOffset(
      view_state, true, mojom::blink::ScrollBehavior::kAuto);
  scrollable_area->ApplyPendingHistoryRestoreScrollOffset();
  EXPECT_EQ(ScrollOffset(0, 100), scrollable_area->GetScrollOffset());

  scrollable_area->SetScrollOffset(ScrollOffset(0, 50),
                                   mojom::blink::ScrollType::kUser);

  // The second call to ApplyPendingHistoryRestoreScrollOffset should
  // do nothing, since the history was already restored.
  scrollable_area->ApplyPendingHistoryRestoreScrollOffset();
  EXPECT_EQ(ScrollOffset(0, 50), scrollable_area->GetScrollOffset());
}

// Test that a trivial 3D transform results in composited scrolling.
TEST_P(PaintLayerScrollableAreaTest, CompositeWithTrivial3D) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        width: 100px;
        height: 100px;
        overflow: scroll;
        transform: translateZ(0);
      }
      #scrolled {
        width: 200px;
        height: 200px;
      }
    </style>
    <div id="scroller">
      <div id="scrolled"></div>
    </div>
  )HTML");

  EXPECT_TRUE(UsesCompositedScrolling(GetLayoutBoxByElementId("scroller")));
}

class PaintLayerScrollableAreaTestLowEndPlatform
    : public TestingPlatformSupport {
 public:
  bool IsLowEndDevice() override { return true; }
};

// Test that a trivial 3D transform results in composited scrolling even on
// low-end devices that may not composite trivial 3D transforms.
TEST_P(PaintLayerScrollableAreaTest, LowEndCompositeWithTrivial3D) {
  ScopedTestingPlatformSupport<PaintLayerScrollableAreaTestLowEndPlatform>
      platform;
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        width: 100px;
        height: 100px;
        overflow: scroll;
        transform: translateZ(0);
      }
      #scrolled {
        width: 200px;
        height: 200px;
      }
    </style>
    <div id="scroller">
      <div id="scrolled"></div>
    </div>
  )HTML");

  EXPECT_TRUE(UsesCompositedScrolling(GetLayoutBoxByElementId("scroller")));
}

TEST_P(PaintLayerScrollableAreaTest,
       RootScrollbarShouldUseParentOfOverscrollNodeAsTransformNode) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>
    ::-webkit-scrollbar {
      width: 12px;
      background: darkblue;
    }
    ::-webkit-scrollbar-thumb {
      background: white;
    }
    #scroller {
      height: 100px;
      overflow-y: scroll;
    }
    .big {
      height: 1000px;
    }
    </style>

    <div class='big'></div>
    <div id='scroller'>
      <div class='big'></div>
    </div>
  )HTML");

  {
    const auto* root_scrollable = GetDocument().View()->LayoutViewport();
    const auto& visual_viewport = GetPage().GetVisualViewport();

    const auto& paint_chunks = ContentPaintChunks();
    bool found_root_scrollbar = false;
    const auto* parent_transform =
        visual_viewport.GetOverscrollElasticityTransformNode()
            ? visual_viewport.GetOverscrollElasticityTransformNode()->Parent()
            : visual_viewport.GetPageScaleNode()->Parent();
    for (const auto& chunk : paint_chunks) {
      if (chunk.id == PaintChunk::Id(root_scrollable->VerticalScrollbar()->Id(),
                                     DisplayItem::kScrollbarHitTest)) {
        EXPECT_EQ(parent_transform, &chunk.properties.Transform());
        found_root_scrollbar = true;
      }
    }
    EXPECT_TRUE(found_root_scrollbar);
  }

  // Non root scrollbar should use scroller's transform node.
  {
    PaintLayer* scroller_layer = GetPaintLayerByElementId("scroller");
    PaintLayerScrollableArea* scrollable_area =
        scroller_layer->GetScrollableArea();
    ASSERT_TRUE(scrollable_area);

    auto paint_properties = scroller_layer->GetLayoutObject()
                                .FirstFragment()
                                .LocalBorderBoxProperties();

    const auto& paint_chunks = ContentPaintChunks();
    bool found_subscroller_scrollbar = false;
    for (const auto& chunk : paint_chunks) {
      if (chunk.id == PaintChunk::Id(scrollable_area->VerticalScrollbar()->Id(),
                                     DisplayItem::kScrollbarHitTest)) {
        EXPECT_EQ(&chunk.properties.Transform(), &paint_properties.Transform());

        found_subscroller_scrollbar = true;
      }
    }
    EXPECT_TRUE(found_subscroller_scrollbar);
  }
}

TEST_P(PaintLayerScrollableAreaTest,
       ResizeSmallerToBeScrollableWithResizerAndStackedChild) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <div id="scroller"
         style="overflow: auto; width: 150px; height: 100px; resize: both">
      <div style="width: 149px; height: 98px; position: relative"></div>
    </div>
  )HTML");

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  auto* scrollable_area = scroller->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_FALSE(scrollable_area->HasScrollbar());
  // The resizer needs to be painted above the stacked child.
  EXPECT_TRUE(scrollable_area->HasOverlayOverflowControls());
  EXPECT_TRUE(
      scroller->GetLayoutBox()->Layer()->NeedsReorderOverlayOverflowControls());

  // Shrink the scroller, and it becomes scrollable.
  scroller->SetInlineStyleProperty(CSSPropertyID::kWidth, "140px");
  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(scrollable_area->HasScrollbar());
  ASSERT_FALSE(scrollable_area->HorizontalScrollbar()->IsOverlayScrollbar());
  // Because there is non-overlay scrollbar, the resizer on longer overlaps
  // with the contents, so no need to overlay.
  EXPECT_FALSE(scrollable_area->HasOverlayOverflowControls());
  EXPECT_FALSE(
      scroller->GetLayoutBox()->Layer()->NeedsReorderOverlayOverflowControls());
}

TEST_P(PaintLayerScrollableAreaTest, RemoveAddResizerWithoutScrollbars) {
  SetBodyInnerHTML(R"HTML(
    <div id="target"
         style="width: 100px; height: 100px; resize: both; overflow: hidden">
      <div style="position: relative; height: 50px"></div>
    </div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* scrollable_area = target->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_FALSE(scrollable_area->HasScrollbar());
  EXPECT_TRUE(scrollable_area->HasOverlayOverflowControls());
  EXPECT_TRUE(scrollable_area->Layer()->NeedsReorderOverlayOverflowControls());

  target->RemoveInlineStyleProperty(CSSPropertyID::kResize);
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(scrollable_area, target->GetLayoutBox()->GetScrollableArea());
  ASSERT_FALSE(scrollable_area->HasScrollbar());
  EXPECT_FALSE(scrollable_area->HasOverlayOverflowControls());
  EXPECT_FALSE(scrollable_area->Layer()->NeedsReorderOverlayOverflowControls());

  target->SetInlineStyleProperty(CSSPropertyID::kResize, "both");
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(scrollable_area, target->GetLayoutBox()->GetScrollableArea());
  ASSERT_FALSE(scrollable_area->HasScrollbar());
  EXPECT_TRUE(scrollable_area->HasOverlayOverflowControls());
  EXPECT_TRUE(scrollable_area->Layer()->NeedsReorderOverlayOverflowControls());
}

TEST_P(PaintLayerScrollableAreaTest, UsedColorSchemeRootScrollbarsDark) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetHtmlInnerHTML(R"HTML(
    <style>
      body { height: 1000px; }
      .container { overflow-y: scroll; width: 100px; height: 100px; }
      .scrollable { height: 400px; }
      #dark { color-scheme: light dark; }
    </style>

    <div id="dark" class="container">
      <div class="scrollable"></div>
    </div>
    <div id="normal" class="container">
      <div class="scrollable"></div>
    </div>
  )HTML");

  AssertDefaultPreferredColorSchemes();

  const auto* root_scrollable_area = GetLayoutView().GetScrollableArea();
  ASSERT_TRUE(root_scrollable_area);
  const auto* non_root_scrollable_area_dark =
      GetPaintLayerByElementId("dark")->GetScrollableArea();
  ASSERT_TRUE(non_root_scrollable_area_dark);
  const auto* non_root_scrollable_area_normal =
      GetPaintLayerByElementId("normal")->GetScrollableArea();
  ASSERT_TRUE(non_root_scrollable_area_normal);

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);
  EXPECT_EQ(non_root_scrollable_area_dark->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);
  EXPECT_EQ(non_root_scrollable_area_normal->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);

  // Change color scheme to dark.
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  UpdateAllLifecyclePhasesForTest();

  // Root scrollable area hasn't changed its value because the browser color
  // scheme is light.
  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);
  EXPECT_EQ(non_root_scrollable_area_dark->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kDark);
  EXPECT_EQ(non_root_scrollable_area_normal->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);

  // Change browser preferred color scheme to dark.
  color_scheme_helper.SetPreferredRootScrollbarColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kDark);
  EXPECT_EQ(non_root_scrollable_area_dark->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kDark);
  EXPECT_EQ(non_root_scrollable_area_normal->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);
}

TEST_P(PaintLayerScrollableAreaTest,
       UsedColorSchemeRootScrollbarsMetaLightDark) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetHtmlInnerHTML(R"HTML(
    <meta name="color-scheme" content="light dark">
    <style>
      html { height: 1000px; }
    </style>
  )HTML");

  AssertDefaultPreferredColorSchemes();

  const auto* root_scrollable_area = GetLayoutView().GetScrollableArea();
  ASSERT_TRUE(root_scrollable_area);

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);

  ColorSchemeHelper color_scheme_helper(GetDocument());
  SetPreferredColorSchemesToDark(color_scheme_helper);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kDark);
}

TEST_P(PaintLayerScrollableAreaTest, UsedColorSchemeRootScrollbarsHtmlLight) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetHtmlInnerHTML(R"HTML(
    <meta name="color-scheme" content="dark">
    <style>
      html { height: 1000px; color-scheme: light; }
    </style>
  )HTML");

  AssertDefaultPreferredColorSchemes();

  const auto* root_scrollable_area = GetLayoutView().GetScrollableArea();
  ASSERT_TRUE(root_scrollable_area);

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);

  ColorSchemeHelper color_scheme_helper(GetDocument());
  SetPreferredColorSchemesToDark(color_scheme_helper);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kLight);
}

TEST_P(PaintLayerScrollableAreaTest, UsedColorSchemeRootScrollbarsBodyLight) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetHtmlInnerHTML(R"HTML(
    <meta name="color-scheme" content="dark">
    <style>
      body { height: 1000px; color-scheme: light; }
    </style>
  )HTML");

  AssertDefaultPreferredColorSchemes();

  const auto* root_scrollable_area = GetLayoutView().GetScrollableArea();
  ASSERT_TRUE(root_scrollable_area);

  EXPECT_EQ(root_scrollable_area->UsedColorSchemeScrollbars(),
            mojom::blink::ColorScheme::kDark);
}

TEST_P(PaintLayerScrollableAreaTest,
       UsedColorSchemeRootScrollbarsInvalidateOnPreferredColorSchemeChange) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetHtmlInnerHTML(R"HTML(
    <style>
      html { height: 1000px; width: 1000px; }
      .container { overflow: scroll; width: 100px; height: 100px; }
      .scrollable { height: 400px; width: 400px; }
    </style>
    <div id="normal" class="container">
      <div class="scrollable"></div>
    </div>
  )HTML");

  AssertDefaultPreferredColorSchemes();

  const auto* non_root_scroller = GetLayoutBoxByElementId("normal");
  ASSERT_TRUE(non_root_scroller);

  // Change preferred color scheme to dark.
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);

  // Root scrollbars should be set for invalidation after the preferred color
  // scheme change.
  EXPECT_TRUE(GetLayoutView().ShouldDoFullPaintInvalidation());

  // Non root scrollbars should not change.
  EXPECT_FALSE(non_root_scroller->ShouldDoFullPaintInvalidation());
}

TEST_P(PaintLayerScrollableAreaTest,
       UsedColorSchemeRootScrollbarsInvalidateOnNormalToLightChange) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetHtmlInnerHTML(R"HTML(
    <style>
      html { height: 1000px; width: 1000px; }
      .container { overflow: scroll; width: 100px; height: 100px; }
      .scrollable { height: 400px; width: 400px; }
    </style>
    <div id="normal" class="container">
      <div class="scrollable"></div>
    </div>
  )HTML");

  AssertDefaultPreferredColorSchemes();

  const auto* root_scrollable_area = GetLayoutView().GetScrollableArea();
  ASSERT_TRUE(root_scrollable_area);
  const auto* non_root_scrollable_area =
      GetPaintLayerByElementId("normal")->GetScrollableArea();
  ASSERT_TRUE(non_root_scrollable_area);

  ColorSchemeHelper color_scheme_helper(GetDocument());
  SetPreferredColorSchemesToDark(color_scheme_helper);
  UpdateAllLifecyclePhasesForTest();

  // Set root element's color scheme to light.
  GetDocument().documentElement()->SetInlineStyleProperty(
      CSSPropertyID::kColorScheme, AtomicString("light"));

  // Update lifecycle up until the pre-paint before the scrollbars paint is
  // invalidated.
  GetDocument().View()->UpdateLifecycleToCompositingInputsClean(
      DocumentUpdateReason::kTest);

  // Root scrollbars should be set for invalidation after the color scheme
  // change.
  ExpectEqAllScrollContr
```