Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. The code is part of a test file (`scrolling_test.cc`) and focuses on testing scrolling-related features.

Here's a breakdown of the code's functionality:

1. **Hit Testing for Non-Composited Scrollers:** Tests how hit-test regions are generated for non-composited scrollable areas.
2. **Hit Testing for Resizers:** Examines the hit-test regions for resizable elements, considering compositing status.
3. **Touch Action Regions:** Verifies how `touch-action` CSS property updates the touch action region on a composited layer.
4. **Main Thread Scroll Updates:** Checks how scroll updates initiated from the main thread and the compositor thread are handled and reflected in the scroll position.
5. **Scrollbar Invalidation:** Tests if changes to the scrollbar thumb part correctly trigger layer invalidation (for non-solid color scrollbars).
6. **Scroll Node Creation and Management:**  Uses `UnifiedScrollingSimTest` to test the creation, update, and reasons for compositor scroll nodes in various scenarios:
    - Non-composited scrollers (due to properties like `box-shadow: inset`).
    - Transitioning between composited and non-composited states.
    - Scrollers within iframes (both direct and nested).
    - Invisible non-composited scrollers (opacity 0).
    - Non-composited scrollable input boxes.
7. **Basic Scrolling Simulation:** Uses `ScrollingSimTest` to simulate user-initiated scrolling and verifies the resulting scroll offsets.
8. **Immediate Composited Scrolling:** Tests that scrolls on composited layers are applied immediately on the compositor thread.
9. **Deferred Composited Scrolling with Scroll-Linked Animations:** Checks that scrolls are deferred when linked to animations via `animation-timeline: scroll()`.
10. **Composited Sticky Element Scrolling:** Verifies that the position of sticky elements is correctly updated during scrolling, even when main thread repaints are involved.
11. **Scroll Timeline Activation:** Tests the activation of scroll timelines at the boundaries of the scrollable area.
这是 `blink/renderer/core/page/scrolling/scrolling_test.cc` 文件的第 4 部分，主要功能是测试 Blink 引擎中与页面滚动相关的特性，特别是与 **Compositor（合成器）** 相关的滚动行为。

以下是对其功能的详细归纳和解释：

**核心功能： Compositor 相关的滚动测试**

这一部分的代码主要集中在测试当页面元素进行硬件加速合成（Compositing）时，滚动行为的正确性。它验证了 Compositor 如何处理滚动事件，以及如何与主线程同步滚动状态。

**具体功能点：**

1. **非合成滚动器的命中测试区域 (NonComposited Scroll Hit Test Region):**
   - **功能:** 测试对于没有被合成的滚动容器，其命中测试区域是如何生成的。命中测试区域决定了哪些触摸或鼠标事件应该被视为针对该滚动器的操作。
   - **与 JavaScript/HTML/CSS 的关系:**
     - **HTML:** 通过 HTML 结构创建非合成的滚动容器 (`<div id="container">`, `<div id="non_scroller">`)。
     - **CSS:** 通过 CSS 属性（例如没有 `will-change: transform`）来使元素不被合成。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个包含非合成滚动容器的 HTML 结构，该容器内部有内容可以滚动。
     - **预期输出:**  Compositor 中的 `cc_layer` (对应于非滚动容器的合成层) 会包含一个 `MainThreadScrollHitTestRegion` (如果 `FastNonCompositedScrollHitTestEnabled` 未启用) 或 `NonCompositedScrollHitTestRect` 列表 (如果启用)，定义了该非合成滚动器的可交互区域。
   - **用户/编程常见错误:**  开发者可能错误地认为所有设置了 `overflow: scroll` 的元素都会被合成，而忽略了某些 CSS 属性可能会阻止合成，导致滚动行为不在 Compositor 中处理，影响性能。
   - **用户操作调试线索:** 用户滚动一个没有被合成的区域，开发者在调试时可能会检查 Compositor 的层树结构，查看是否生成了预期的 `MainThreadScrollHitTestRegion` 或 `NonCompositedScrollHitTestRect`。

2. **非合成和合成 Resizer 的命中测试区域 (NonCompositedResizerMainThreadScrollHitTestRegion, CompositedResizerMainThreadScrollHitTestRegion):**
   - **功能:** 测试对于可以调整大小 (`resize: both`) 的元素，其命中测试区域是如何生成的，并区分了元素是否被合成的情况。Resizer 通常在元素的边缘，允许用户拖拽改变元素大小。
   - **与 JavaScript/HTML/CSS 的关系:**
     - **HTML:** 使用带有 `resize` 属性的元素 (`<div id="scroller">`)。
     - **CSS:**  通过 `resize: both` 启用调整大小，通过 `will-change: transform` 控制是否合成。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**  包含可调整大小元素的 HTML 结构，分别测试合成和非合成的情况。
     - **预期输出:** Compositor 中的对应层会包含一个 `MainThreadScrollHitTestRegion`，其位置和大小与 Resizer 的位置和大小相符。对于非合成的 Resizer，命中测试区域可能位于其父容器的层上。
   - **用户/编程常见错误:** 开发者可能没有考虑到 Resizer 的命中测试区域，导致在某些情况下用户无法正确地拖拽调整大小。
   - **用户操作调试线索:** 用户尝试拖拽 Resizer 但没有反应，开发者可以检查 Compositor 的命中测试区域是否覆盖了 Resizer 的实际位置。

3. **TouchAction 在 Interest Rect 之外的更新 (TouchActionUpdatesOutsideInterestRect):**
   - **功能:** 测试当通过 JavaScript 动态更新元素的 `touch-action` CSS 属性时，Compositor 中对应的触摸操作区域是否能正确更新，即使该区域可能在“兴趣矩形”之外（通常指视口或附近区域）。
   - **与 JavaScript/HTML/CSS 的关系:**
     - **HTML:**  包含可以滚动的元素和用于测试 `touch-action` 的元素 (`<div id="touchaction">`)。
     - **CSS:**  设置滚动和 `touch-action` 属性。
     - **JavaScript:**  使用 JavaScript 动态修改 `touch-action` 属性 (`touch_action->setAttribute(...)`).
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个包含可滚动区域和设置了 `touch-action: none` 的元素的 HTML 结构，通过 JavaScript 动态设置 `touch-action`。
     - **预期输出:** Compositor 中对应层的 `touch_action_region` 会根据 `touch-action` 的值进行更新，阻止或允许特定的触摸操作。
   - **用户/编程常见错误:** 开发者可能在 JavaScript 中动态修改了 `touch-action`，但 Compositor 没有及时更新，导致触摸行为与预期不符。
   - **用户操作调试线索:** 用户在应该禁止滚动的区域仍然可以滚动，开发者可以检查 Compositor 中对应元素的 `touch_action_region` 是否已正确更新。

4. **主线程滚动和来自 Impl 侧的 Delta (MainThreadScrollAndDeltaFromImplSide):**
   - **功能:** 测试滚动偏移的同步，包括主线程直接设置的滚动偏移和来自 Compositor 线程（Impl 侧）的滚动增量 (delta)。
   - **与 JavaScript/HTML/CSS 的关系:**
     - **HTML:**  包含可滚动的元素 (`<div id='scroller'>`)。
     - **JavaScript:** 使用 JavaScript 的 `scrollTo` 方法触发主线程滚动。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个包含可滚动元素的 HTML 结构，先通过 JavaScript `scrollTo` 滚动，然后模拟来自 Compositor 的滚动增量。
     - **预期输出:**  `scrollable_area->ScrollPosition()` (Blink 主线程的滚动位置) 和 `CurrentScrollOffset(element_id)` (Compositor 线程的滚动位置) 都会正确地反映主线程的滚动和 Compositor 提供的增量。
   - **用户/编程常见错误:** 滚动同步逻辑错误可能导致主线程和 Compositor 线程的滚动位置不一致，造成视觉上的跳跃或抖动。
   - **用户操作调试线索:** 用户滚动页面时出现不连贯的滚动效果，开发者可以检查主线程和 Compositor 线程的滚动偏移是否同步。

5. **Thumb 使 Layer 失效 (ThumbInvalidatesLayer):**
   - **功能:** 测试当滚动条的 Thumb 部分需要重绘时，是否会正确地使对应的 Layer 失效，触发重绘。这对于非纯色滚动条尤其重要。
   - **与 JavaScript/HTML/CSS 的关系:**
     - **HTML:** 包含可滚动的元素 (`<div id='scroller'>`)。
     - **CSS:** 影响滚动条样式的 CSS 可能会影响此测试的结果 (例如，纯色滚动条不会触发重绘)。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个包含可滚动元素的 HTML 结构。
     - **预期输出:** 当调用 `VerticalScrollbar()->SetNeedsPaintInvalidation(kThumbPart)` 时，如果滚动条不是纯色的，则对应的 Layer 的 `update_rect()` 不为空，表示需要重绘。
   - **用户/编程常见错误:**  滚动条的重绘逻辑可能存在问题，导致滚动条的 Thumb 部分在应该更新时没有更新。
   - **用户操作调试线索:** 用户拖动滚动条的 Thumb 时，Thumb 的视觉效果没有及时更新。

6. **UnifiedScrollingSimTest：Compositor 滚动节点测试:**
   - **功能:**  这是一组更高级的测试，使用 `UnifiedScrollingSimTest` 框架，专注于测试 Compositor 中 **滚动节点 (Scroll Node)** 的创建和管理。滚动节点是 Compositor 中用于管理滚动行为的关键数据结构。
   - **具体测试点包括：**
     - 对于由于某些 CSS 属性（例如 `box-shadow: inset`）而无法合成的滚动器，是否生成了带有正确非合成原因的滚动节点。
     - 当一个原本合成的滚动器变为非合成时，Compositor 是否保留了滚动节点并更新了其状态。
     - 嵌套在 iframe 中的滚动器是否能正确生成滚动节点。
     - 对于 `opacity: 0` 的非合成滚动器是否生成了滚动节点，而对于 `display: none` 的滚动器则不生成。
     - 对于非合成的 `<input type="text">` 元素是否生成了滚动节点。
   - **与 JavaScript/HTML/CSS 的关系:**  这些测试大量使用了 HTML 和 CSS 来创建各种不同的滚动场景，并验证 Compositor 的行为。
   - **逻辑推理 (假设输入与输出):**  每个测试都有特定的 HTML 和 CSS 输入，以及对 Compositor 中滚动节点属性（如 `is_composited`, `main_thread_repaint_reasons`, `element_id`) 的预期输出。
   - **用户/编程常见错误:**  Compositor 没有为某些应该有滚动节点的元素创建节点，或者滚动节点的状态不正确，会导致滚动行为异常。
   - **用户操作调试线索:**  在包含复杂滚动结构的页面中，滚动行为不符合预期，开发者可以使用 Compositor 的调试工具来检查滚动节点的创建和状态。

7. **ScrollingSimTest：基本滚动模拟和高级滚动场景测试:**
   - **功能:** 使用 `ScrollingSimTest` 框架模拟用户的滚动操作，并验证滚动行为。
   - **具体测试点包括：**
     - 基本的触摸滚动操作。
     - Compositor 线程的立即滚动 (Immediate Composited Scroll)。
     - 当滚动与 CSS 动画关联时，Compositor 线程的滚动延迟 (Composited Scroll Deferred With Linked Animation)。
     - 包含 `position: sticky` 元素的滚动行为，并检查 Compositor 如何跟踪主线程的重绘滚动 (Composited Sticky Tracks Main Repaint Scroll)。
     - 测试滚动时间轴在边界处的激活状态 (ScrollTimelineActiveAtBoundary)。
   - **与 JavaScript/HTML/CSS 的关系:**  通过构建包含各种滚动场景的 HTML 和 CSS，并模拟用户的触摸事件来触发滚动。
   - **逻辑推理 (假设输入与输出):**  每个测试都模拟了特定的滚动操作，并验证了滚动偏移、动画状态等预期结果。
   - **用户/编程常见错误:**  滚动行为在特定情况下不正确，例如，与动画关联的滚动没有正确延迟，或者 sticky 元素在滚动时没有正确固定。
   - **用户操作调试线索:**  用户在页面上执行特定的滚动操作时，出现非预期的行为，例如滚动不流畅，sticky 元素位置错误，或者动画没有与滚动同步。

**总结这一部分的功能：**

这部分 `scrolling_test.cc` 的主要功能是 **全面测试 Blink 引擎中与硬件加速合成（Compositing）相关的滚动机制。** 它覆盖了 Compositor 如何处理不同类型的滚动场景，包括非合成和合成的滚动器，Resizer，以及与 `touch-action` 和 CSS 动画相关的滚动。 通过这些测试，可以确保 Blink 引擎在进行硬件加速渲染时，滚动行为的正确性和性能。

作为调试线索，当用户遇到与滚动相关的 bug 时，例如滚动不流畅、滚动位置错误、触摸操作失效等，开发者可以参考这些测试用例，理解 Compositor 的工作原理，并利用浏览器的开发者工具来检查 Compositor 的层树结构、滚动节点状态、以及事件处理流程，从而定位问题。

### 提示词
```
这是目录为blink/renderer/core/page/scrolling/scrolling_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
OMElementId("composited_container");
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    // The non-scrolling layer should have a NonCompositedScrollHitTestRect
    // for the non-composited scroller.
    EXPECT_TRUE(cc_layer->main_thread_scroll_hit_test_region().IsEmpty());
    EXPECT_EQ(
        gfx::Rect(20, 20, 200, 200),
        cc_layer->non_composited_scroll_hit_test_rects()->at(0).hit_test_rect);
  } else {
    // The non-scrolling layer should have a MainThreadScrollHitTestRegion for
    // the non-composited scroller.
    EXPECT_EQ(cc::Region(gfx::Rect(20, 20, 200, 200)),
              cc_layer->main_thread_scroll_hit_test_region());
    EXPECT_TRUE(cc_layer->non_composited_scroll_hit_test_rects()->empty());
  }
}

TEST_P(ScrollingTest, NonCompositedResizerMainThreadScrollHitTestRegion) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <style>
      #container {
        will-change: transform;
        border: 20px solid blue;
      }
      #scroller {
        width: 80px;
        height: 80px;
        resize: both;
        overflow-y: scroll;
      }
    </style>
    <div id="container">
      <div id="offset" style="height: 35px;"></div>
      <div id="scroller"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  auto* container_cc_layer = LayerByDOMElementId("container");
  // The non-fast scrollable region should be on the container's layer and not
  // one of the viewport scroll layers because the region should move when the
  // container moves and not when the viewport scrolls.
  auto region = container_cc_layer->main_thread_scroll_hit_test_region();
  EXPECT_EQ(cc::Region(gfx::Rect(86, 121, 14, 14)), region);
}

TEST_P(ScrollingTest, CompositedResizerMainThreadScrollHitTestRegion) {
  LoadHTML(R"HTML(
    <style>
      #container { will-change: transform; }
      #scroller {
        will-change: transform;
        width: 80px;
        height: 80px;
        resize: both;
        overflow-y: scroll;
      }
    </style>
    <div id="container">
      <div id="offset" style="height: 35px;"></div>
      <div id="scroller"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  auto region =
      LayerByDOMElementId("scroller")->main_thread_scroll_hit_test_region();
  EXPECT_EQ(cc::Region(gfx::Rect(66, 66, 14, 14)), region);
}

TEST_P(ScrollingTest, TouchActionUpdatesOutsideInterestRect) {
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #scroller {
        will-change: transform;
        width: 200px;
        height: 200px;
        background: blue;
        overflow-y: scroll;
      }
      .spacer {
        height: 1000px;
      }
      #touchaction {
        height: 100px;
        background: yellow;
      }
    </style>
    <div id="scroller">
      <div class="spacer"></div>
      <div class="spacer"></div>
      <div class="spacer"></div>
      <div class="spacer"></div>
      <div class="spacer"></div>
      <div id="touchaction">This should not scroll via touch.</div>
    </div>
  )HTML");

  ForceFullCompositingUpdate();

  auto* touch_action =
      GetFrame()->GetDocument()->getElementById(AtomicString("touchaction"));
  touch_action->setAttribute(html_names::kStyleAttr,
                             AtomicString("touch-action: none;"));

  ForceFullCompositingUpdate();

  ScrollableAreaByDOMElementId("scroller")
      ->SetScrollOffset(ScrollOffset(0, 5100),
                        mojom::blink::ScrollType::kProgrammatic);

  ForceFullCompositingUpdate();

  auto* cc_layer = ScrollingContentsLayerByDOMElementId("scroller");
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 5000, 200, 100)), region);
}

TEST_P(ScrollingTest, MainThreadScrollAndDeltaFromImplSide) {
  LoadHTML(R"HTML(
    <div id='scroller' style='overflow: scroll; width: 100px; height: 100px'>
      <div style='height: 1000px'></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  auto* scroller =
      GetFrame()->GetDocument()->getElementById(AtomicString("scroller"));
  auto* scrollable_area = scroller->GetLayoutBox()->GetScrollableArea();
  auto element_id = scrollable_area->GetScrollElementId();

  EXPECT_EQ(gfx::PointF(), CurrentScrollOffset(element_id));

  // Simulate a direct scroll update out of document lifecycle update.
  scroller->scrollTo(0, 200);
  EXPECT_EQ(gfx::PointF(0, 200), scrollable_area->ScrollPosition());
  EXPECT_EQ(gfx::PointF(0, 200), CurrentScrollOffset(element_id));

  // Simulate the scroll update with scroll delta from impl-side at the
  // beginning of BeginMainFrame.
  cc::CompositorCommitData commit_data;
  commit_data.scrolls.push_back(cc::CompositorCommitData::ScrollUpdateInfo(
      element_id, gfx::Vector2dF(0, 10), std::nullopt));
  RootCcLayer()->layer_tree_host()->ApplyCompositorChanges(&commit_data);
  EXPECT_EQ(gfx::PointF(0, 210), scrollable_area->ScrollPosition());
  EXPECT_EQ(gfx::PointF(0, 210), CurrentScrollOffset(element_id));
}

TEST_P(ScrollingTest, ThumbInvalidatesLayer) {
  ScopedMockOverlayScrollbars mock_overlay_scrollbar(false);
  LoadHTML(R"HTML(
    <div id='scroller' style='overflow-y: scroll; width: 100px; height: 100px'>
      <div style='height: 1000px'></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  auto* scroll_node = ScrollNodeByDOMElementId("scroller");
  auto* layer = ScrollbarLayerForScrollNode(
      scroll_node, cc::ScrollbarOrientation::kVertical);
  // Solid color scrollbars do not repaint (see:
  // |SolidColorScrollbarLayer::SetNeedsDisplayRect|).
  if (layer->GetScrollbarLayerType() != cc::ScrollbarLayerBase::kSolidColor) {
    layer->ResetUpdateRectForTesting();
    ASSERT_TRUE(layer->update_rect().IsEmpty());

    auto* scrollable_area = ScrollableAreaByDOMElementId("scroller");
    scrollable_area->VerticalScrollbar()->SetNeedsPaintInvalidation(kThumbPart);
    EXPECT_FALSE(layer->update_rect().IsEmpty());
  }
}

class UnifiedScrollingSimTest : public SimTest, public PaintTestConfigurations {
 public:
  UnifiedScrollingSimTest() = default;

  void SetUp() override {
    SimTest::SetUp();
    SetPreferCompositingToLCDText(false);
    WebView().MainFrameViewWidget()->Resize(gfx::Size(1000, 1000));
    WebView().MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  void RunIdleTasks() {
    ThreadScheduler::Current()
        ->ToMainThreadScheduler()
        ->StartIdlePeriodForTesting();
    test::RunPendingTasks();
  }

  const cc::Layer* RootCcLayer() { return GetDocument().View()->RootCcLayer(); }

  const cc::ScrollNode* ScrollNodeForScrollableArea(
      const ScrollableArea* scrollable_area) {
    if (!scrollable_area)
      return nullptr;
    const auto* property_trees =
        RootCcLayer()->layer_tree_host()->property_trees();
    return property_trees->scroll_tree().FindNodeFromElementId(
        scrollable_area->GetScrollElementId());
  }

  PaintLayerScrollableArea* ScrollableAreaByDOMElementId(const char* id_value) {
    auto* box = MainFrame()
                    .GetFrame()
                    ->GetDocument()
                    ->getElementById(AtomicString(id_value))
                    ->GetLayoutBoxForScrolling();
    return box ? box->GetScrollableArea() : nullptr;
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(UnifiedScrollingSimTest);

// Tests that the compositor gets a scroll node for noncomposited scrollers by
// loading a page with a scroller that has an inset box-shadow, and ensuring
// that scroller generates a compositor scroll node with the proper
// noncomposited reasons set. It then removes the box-shadow property and
// ensures the compositor node updates accordingly.
TEST_P(UnifiedScrollingSimTest, ScrollNodeForNonCompositedScroller) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #noncomposited {
      width: 200px;
      height: 200px;
      overflow: auto;
      position: absolute;
      top: 300px;
      background: white;
      box-shadow: 10px 10px black inset;
    }
    #spacer {
      width: 100%;
      height: 10000px;
    }
    </style>
    <div id="noncomposited">
      <div id="spacer"></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Element* noncomposited_element =
      MainFrame().GetFrame()->GetDocument()->getElementById(
          AtomicString("noncomposited"));
  auto* scrollable_area =
      noncomposited_element->GetLayoutBoxForScrolling()->GetScrollableArea();
  const auto* scroll_node = ScrollNodeForScrollableArea(scrollable_area);
  ASSERT_NOT_COMPOSITED(
      scroll_node,
      RuntimeEnabledFeatures::RasterInducingScrollEnabled()
          ? cc::MainThreadScrollingReason::kNotScrollingOnMain
          : cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  EXPECT_EQ(scroll_node->element_id, scrollable_area->GetScrollElementId());

  // Now remove the box-shadow property and ensure the compositor scroll node
  // changes.
  noncomposited_element->setAttribute(html_names::kStyleAttr,
                                      AtomicString("box-shadow: none"));
  Compositor().BeginFrame();

  ASSERT_COMPOSITED(scroll_node);
  EXPECT_EQ(scroll_node->element_id, scrollable_area->GetScrollElementId());
}

// Tests that the compositor retains the scroll node for a composited scroller
// when it becomes noncomposited, and ensures the scroll node has its
// IsComposited state updated accordingly.
TEST_P(UnifiedScrollingSimTest,
       ScrollNodeForCompositedToNonCompositedScroller) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #composited {
      width: 200px;
      height: 200px;
      overflow: auto;
      position: absolute;
      top: 300px;
      background: white;
    }
    #spacer {
      width: 100%;
      height: 10000px;
    }
    </style>
    <div id="composited">
      <div id="spacer"></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Element* composited_element =
      MainFrame().GetFrame()->GetDocument()->getElementById(
          AtomicString("composited"));
  auto* scrollable_area =
      composited_element->GetLayoutBoxForScrolling()->GetScrollableArea();
  const auto* scroll_node = ScrollNodeForScrollableArea(scrollable_area);
  ASSERT_COMPOSITED(scroll_node);
  EXPECT_EQ(scroll_node->element_id, scrollable_area->GetScrollElementId());

  // Now add an inset box-shadow property to make the node noncomposited and
  // ensure the compositor scroll node updates accordingly.
  composited_element->setAttribute(
      html_names::kStyleAttr,
      AtomicString("box-shadow: 10px 10px black inset"));
  Compositor().BeginFrame();

  ASSERT_NOT_COMPOSITED(
      scroll_node,
      RuntimeEnabledFeatures::RasterInducingScrollEnabled()
          ? cc::MainThreadScrollingReason::kNotScrollingOnMain
          : cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  EXPECT_EQ(scroll_node->element_id, scrollable_area->GetScrollElementId());
}

// Tests that the compositor gets a scroll node for noncomposited scrollers
// embedded in an iframe, by loading a document with an iframe that has a
// scroller with an inset box shadow, and ensuring that scroller generates a
// compositor scroll node with the proper noncomposited reasons set.
TEST_P(UnifiedScrollingSimTest, ScrollNodeForEmbeddedScrollers) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #iframe {
      width: 300px;
      height: 300px;
      overflow: auto;
    }
    </style>
    <iframe id="iframe" srcdoc="
        <!DOCTYPE html>
        <style>
          body {
            background: white;
          }
          #scroller {
            width: 200px;
            height: 200px;
            overflow: auto;
            position: absolute;
            top: 50px;
            background: white;
            box-shadow: 10px 10px black inset;
          }
          #spacer {
            width: 100%;
            height: 10000px;
          }
        </style>
        <div id='scroller'>
          <div id='spacer'></div>
        </div>
        <div id='spacer'></div>">
    </iframe>
  )HTML");

  // RunIdleTasks to load the srcdoc iframe.
  RunIdleTasks();
  Compositor().BeginFrame();

  HTMLFrameOwnerElement* iframe = To<HTMLFrameOwnerElement>(
      GetDocument().getElementById(AtomicString("iframe")));
  auto* iframe_scrollable_area =
      iframe->contentDocument()->View()->LayoutViewport();
  const auto* iframe_scroll_node =
      ScrollNodeForScrollableArea(iframe_scrollable_area);

  // The iframe itself is a composited scroller.
  ASSERT_COMPOSITED(iframe_scroll_node);
  EXPECT_EQ(iframe_scroll_node->element_id,
            iframe_scrollable_area->GetScrollElementId());

  // Ensure we have a compositor scroll node for the noncomposited subscroller.
  auto* child_scrollable_area = iframe->contentDocument()
                                    ->getElementById(AtomicString("scroller"))
                                    ->GetLayoutBoxForScrolling()
                                    ->GetScrollableArea();
  const auto* child_scroll_node =
      ScrollNodeForScrollableArea(child_scrollable_area);
  ASSERT_NOT_COMPOSITED(
      child_scroll_node,
      RuntimeEnabledFeatures::RasterInducingScrollEnabled()
          ? cc::MainThreadScrollingReason::kNotScrollingOnMain
          : cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  EXPECT_EQ(child_scroll_node->element_id,
            child_scrollable_area->GetScrollElementId());
}

// Similar to the above test, but for deeper nesting iframes to ensure we
// generate scroll nodes that are deeper than the main frame's children.
TEST_P(UnifiedScrollingSimTest, ScrollNodeForNestedEmbeddedScrollers) {
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest child_request_1("https://example.com/child1.html", "text/html");
  SimRequest child_request_2("https://example.com/child2.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    iframe {
      width: 300px;
      height: 300px;
      overflow: auto;
    }
    </style>
    <iframe id="child1" src="child1.html">
  )HTML");

  child_request_1.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    iframe {
      width: 300px;
      height: 300px;
      overflow: auto;
    }
    </style>
    <iframe id="child2" src="child2.html">
  )HTML");

  child_request_2.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #scroller {
        width: 200px;
        height: 200px;
        overflow: auto;
        position: absolute;
        top: 50px;
        background: white;
        box-shadow: 10px 10px black inset;
      }
      #spacer {
        width: 100%;
        height: 10000px;
      }
    </style>
    <div id='scroller'>
      <div id='spacer'></div>
    </div>
    <div id='spacer'></div>
  )HTML");

  RunIdleTasks();
  Compositor().BeginFrame();

  HTMLFrameOwnerElement* child_iframe_1 = To<HTMLFrameOwnerElement>(
      GetDocument().getElementById(AtomicString("child1")));

  HTMLFrameOwnerElement* child_iframe_2 = To<HTMLFrameOwnerElement>(
      child_iframe_1->contentDocument()->getElementById(
          AtomicString("child2")));

  // Ensure we have a compositor scroll node for the noncomposited subscroller
  // nested in the second iframe.
  auto* child_scrollable_area = child_iframe_2->contentDocument()
                                    ->getElementById(AtomicString("scroller"))
                                    ->GetLayoutBoxForScrolling()
                                    ->GetScrollableArea();
  const auto* child_scroll_node =
      ScrollNodeForScrollableArea(child_scrollable_area);
  ASSERT_NOT_COMPOSITED(
      child_scroll_node,
      RuntimeEnabledFeatures::RasterInducingScrollEnabled()
          ? cc::MainThreadScrollingReason::kNotScrollingOnMain
          : cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  EXPECT_EQ(child_scroll_node->element_id,
            child_scrollable_area->GetScrollElementId());
}

// Tests that the compositor gets a scroll node for opacity 0 noncomposited
// scrollers by loading a page with an opacity 0 scroller that has an inset
// box-shadow, and ensuring that scroller generates a compositor scroll node
// with the proper noncomposited reasons set. The test also ensures that there
// is no scroll node for a display:none scroller, as there is no scrollable
// area.
TEST_P(UnifiedScrollingSimTest, ScrollNodeForInvisibleNonCompositedScroller) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    .noncomposited {
      width: 200px;
      height: 200px;
      overflow: auto;
      position: absolute;
      top: 300px;
      background: white;
      box-shadow: 10px 10px black inset;
    }
    #invisible {
      opacity: 0;
    }
    #displaynone {
      display: none;
    }
    #spacer {
      width: 100%;
      height: 10000px;
    }
    </style>
    <div id="invisible" class="noncomposited">
      <div id="spacer"></div>
    </div>
    <div id="displaynone" class="noncomposited">
      <div id="spacer"></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  // Ensure the opacity 0 noncomposited scrollable area generates a scroll node
  auto* invisible_scrollable_area = ScrollableAreaByDOMElementId("invisible");
  const auto* invisible_scroll_node =
      ScrollNodeForScrollableArea(invisible_scrollable_area);
  ASSERT_NOT_COMPOSITED(
      invisible_scroll_node,
      RuntimeEnabledFeatures::RasterInducingScrollEnabled()
          ? cc::MainThreadScrollingReason::kNotScrollingOnMain
          : cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  EXPECT_EQ(invisible_scroll_node->element_id,
            invisible_scrollable_area->GetScrollElementId());

  // Ensure there's no scrollable area (and therefore no scroll node) for a
  // display none scroller.
  EXPECT_EQ(nullptr, ScrollableAreaByDOMElementId("displaynone"));
}

// Tests that the compositor gets a scroll node for a non-composited (due to
// PaintLayerScrollableArea::PrefersNonCompositedScrolling()) scrollable input
// box.
TEST_P(UnifiedScrollingSimTest, ScrollNodeForInputBox) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        input {
          width: 50px;
        }
      </style>
      <input id="textinput" type="text" value="some overflowing text"/>
  )HTML");
  Compositor().BeginFrame();

  auto* scrollable_area = ScrollableAreaByDOMElementId("textinput");
  const auto* scroll_node = ScrollNodeForScrollableArea(scrollable_area);
  ASSERT_TRUE(scroll_node);
  EXPECT_EQ(cc::MainThreadScrollingReason::kPreferNonCompositedScrolling,
            scroll_node->main_thread_repaint_reasons);
  EXPECT_FALSE(scroll_node->is_composited);
}

class ScrollingSimTest : public SimTest {
 public:
  ScrollingSimTest() = default;

  void SetUp() override {
    was_threaded_animation_enabled_ =
        content::TestBlinkWebUnitTestSupport::SetThreadedAnimationEnabled(true);

    SimTest::SetUp();
    SetPreferCompositingToLCDText(true);
    ResizeView(gfx::Size(1000, 1000));
    WebView().MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  void TearDown() override {
    SimTest::TearDown();
    feature_list_.Reset();

    content::TestBlinkWebUnitTestSupport::SetThreadedAnimationEnabled(
        was_threaded_animation_enabled_);
  }

  WebGestureEvent GenerateGestureEvent(WebInputEvent::Type type,
                                       int delta_x = 0,
                                       int delta_y = 0) {
    WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests(),
                          WebGestureDevice::kTouchscreen);
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

  WebCoalescedInputEvent GenerateCoalescedGestureEvent(WebInputEvent::Type type,
                                                       int delta_x = 0,
                                                       int delta_y = 0) {
    return WebCoalescedInputEvent(GenerateGestureEvent(type, delta_x, delta_y),
                                  ui::LatencyInfo());
  }

  unsigned NumObjectsNeedingLayout() {
    bool is_partial = false;
    unsigned num_objects_need_layout = 0;
    unsigned total_objects = 0;
    GetDocument().View()->CountObjectsNeedingLayout(num_objects_need_layout,
                                                    total_objects, is_partial);
    return num_objects_need_layout;
  }

  cc::LayerTreeHostImpl* GetLayerTreeHostImpl() {
    return static_cast<cc::SingleThreadProxy*>(
               GetWebFrameWidget().LayerTreeHostForTesting()->proxy())
        ->LayerTreeHostImplForTesting();
  }

  gfx::PointF GetActiveScrollOffset(PaintLayerScrollableArea* scroller) {
    return GetLayerTreeHostImpl()->GetScrollTree().current_scroll_offset(
        scroller->GetScrollElementId());
  }

 protected:
  base::test::ScopedFeatureList feature_list_;
  bool was_threaded_animation_enabled_;
};

TEST_F(ScrollingSimTest, BasicScroll) {
  String kUrl = "https://example.com/test.html";
  SimRequest request(kUrl, "text/html");
  LoadURL(kUrl);

  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #s { overflow: scroll; width: 300px; height: 300px; }
      #sp { width: 600px; height: 600px; }
    </style>
    <div id=s><div id=sp>hello</div></div>
  )HTML");

  Compositor().BeginFrame();

  auto& widget = GetWebFrameWidget();
  widget.DispatchThroughCcInputHandler(
      GenerateGestureEvent(WebInputEvent::Type::kGestureScrollBegin, 0, -100));
  widget.DispatchThroughCcInputHandler(
      GenerateGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -100));
  widget.DispatchThroughCcInputHandler(
      GenerateGestureEvent(WebInputEvent::Type::kGestureScrollEnd));

  Compositor().BeginFrame();

  Element* scroller = GetDocument().getElementById(AtomicString("s"));
  LayoutBox* box = To<LayoutBox>(scroller->GetLayoutObject());
  EXPECT_EQ(100, box->ScrolledContentOffset().top);
}

TEST_F(ScrollingSimTest, ImmediateCompositedScroll) {
  String kUrl = "https://example.com/test.html";
  SimRequest request(kUrl, "text/html");
  LoadURL(kUrl);

  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #s { overflow: scroll; width: 300px; height: 300px; background: white }
      #sp { width: 600px; height: 600px; }
    </style>
    <div id=s><div id=sp>hello</div></div>
  )HTML");

  Compositor().BeginFrame();
  Element* scroller = GetDocument().getElementById(AtomicString("s"));
  LayoutBox* box = To<LayoutBox>(scroller->GetLayoutObject());
  EXPECT_EQ(0, GetActiveScrollOffset(box->GetScrollableArea()).y());

  WebGestureEvent scroll_begin(
      WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_begin.SetPositionInWidget(gfx::PointF(100, 100));
  scroll_begin.data.scroll_begin.delta_y_hint = -100;

  WebGestureEvent scroll_update(
      WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_update.SetPositionInWidget(gfx::PointF(100, 100));
  scroll_update.data.scroll_update.delta_y = -100;

  WebGestureEvent scroll_end(
      WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_end.SetPositionInWidget(gfx::PointF(100, 100));

  auto& widget = GetWebFrameWidget();
  widget.DispatchThroughCcInputHandler(scroll_begin);
  widget.DispatchThroughCcInputHandler(scroll_update);
  widget.DispatchThroughCcInputHandler(scroll_end);

  // The scroll is applied immediately in the active tree.
  EXPECT_EQ(100, GetActiveScrollOffset(box->GetScrollableArea()).y());

  // Blink sees the scroll after the main thread lifecycle update.
  EXPECT_EQ(0, box->ScrolledContentOffset().top);
  Compositor().BeginFrame();
  EXPECT_EQ(100, box->ScrolledContentOffset().top);
}

TEST_F(ScrollingSimTest, CompositedScrollDeferredWithLinkedAnimation) {
  ScopedScrollTimelineForTest scroll_timeline_enabled(true);

  String kUrl = "https://example.com/test.html";
  SimRequest request(kUrl, "text/html");
  LoadURL(kUrl);

  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #s { overflow: scroll; width: 300px; height: 300px;
           background: white; position: relative; }
      #sp { width: 600px; height: 600px; }
      #align { width: 100%; height: 20px; position: absolute; background: blue;
               will-change: transform; animation: a linear 10s;
               animation-timeline: scroll(); }
      @keyframes a {
        0% { transform: translateY(0); }
        100% { transform: translateY(100px); }
      }
    </style>
    <div id=s><div id=sp><div id=align></div>hello</div></div>
  )HTML");

  Compositor().BeginFrame();

  // Slight hack: SimTest sets LayerTreeSettings::commit_to_active_tree == true,
  // so there is no pending tree, but AnimationHost doesn't understand that.
  // Simulate part of activation to get cc::ScrollTimeline::active_id_ set.
  GetLayerTreeHostImpl()
      ->mutator_host()
      ->PromoteScrollTimelinesPendingToActive();

  Element* scroller = GetDocument().getElementById(AtomicString("s"));
  LayoutBox* box = To<LayoutBox>(scroller->GetLayoutObject());

  WebGestureEvent scroll_begin(
      WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_begin.SetPositionInWidget(gfx::PointF(100, 100));
  scroll_begin.data.scroll_begin.delta_y_hint = -100;

  WebGestureEvent scroll_update(
      WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_update.SetPositionInWidget(gfx::PointF(100, 100));
  scroll_update.data.scroll_update.delta_y = -100;

  WebGestureEvent scroll_end(
      WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_end.SetPositionInWidget(gfx::PointF(100, 100));

  auto& widget = GetWebFrameWidget();
  widget.DispatchThroughCcInputHandler(scroll_begin);
  widget.DispatchThroughCcInputHandler(scroll_update);
  widget.DispatchThroughCcInputHandler(scroll_end);

  // Due to the scroll-linked animation, the scroll is NOT applied immediately
  // in the active tree. (Compare with ImmediateCompositedScroll test case.)
  EXPECT_EQ(0, GetActiveScrollOffset(box->GetScrollableArea()).y());

  // The scroll is applied to the active tree in LTHI::WillBeginImplFrame.
  Compositor().BeginFrame();
  EXPECT_EQ(100, GetActiveScrollOffset(box->GetScrollableArea()).y());
  EXPECT_EQ(100, box->ScrolledContentOffset().top);
}

TEST_F(ScrollingSimTest, CompositedStickyTracksMainRepaintScroll) {
  SetPreferCompositingToLCDText(false);

  String kUrl = "https://example.com/test.html";
  SimRequest request(kUrl, "text/html");
  LoadURL(kUrl);

  request.Complete(R"HTML(
    <style>
    .spincont { position: absolute;
                width: 10px; height: 10px; left: 50px; top: 20px; }
    .spinner { animation: spin 1s linear infinite; }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .scroller { position: absolute; overflow: scroll;
                left: 10px; top: 50px; width: 750px; height: 400px;
                border: 10px solid #ccc; }
    .spacer { position: absolute; width: 9000px; height: 100px; }
    .sticky { position: sticky; background: #eee;
              left: 50px; top: 50px; width: 600px; height: 200px; }
    .bluechip { position: absolute; background: blue; color: white;
                left: 100px; top: 50px; width: 200px; height: 30px; }
    </style>
    <div class="spincont"><div class="spinner">X</div></div>
    <div class="scroller">
      <div class="spacer">scrolling</div>
      <div class="sticky"><div class="bluechip">sticky?</div></div>
    </div>
  )HTML");

  Compositor().BeginFrame(0.016, /* raster */ true);
  Element* scroller = GetDocument().QuerySelector(AtomicString(".scroller"));
  LayoutBox* box = To<LayoutBox>(scroller->GetLayoutObject());
  EXPECT_EQ(0, GetActiveScrollOffset(box->GetScrollableArea()).y());

  WebGestureEvent scroll_begin(
      WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_begin.SetPositionInWidget(gfx::PointF(200, 200));
  scroll_begin.data.scroll_begin.delta_x_hint = -100;

  WebGestureEvent scroll_update(
      WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_update.SetPositionInWidget(gfx::PointF(200, 200));
  scroll_update.data.scroll_update.delta_x = -100;

  WebGestureEvent scroll_end(
      WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  scroll_end.SetPositionInWidget(gfx::PointF(200, 200));

  auto& widget = GetWebFrameWidget();
  widget.DispatchThroughCcInputHandler(scroll_begin);
  widget.DispatchThroughCcInputHandler(scroll_update);
  widget.DispatchThroughCcInputHandler(scroll_end);

  // Scroll applied immediately in the scroll tree.
  EXPECT_EQ(100, GetActiveScrollOffset(box->GetScrollableArea()).x());

  // Tick impl animation to dirty draw properties.
  static_cast<cc::SingleThreadProxy*>(
      GetWebFrameWidget().LayerTreeHostForTesting()->proxy())
      ->BeginImplFrameForTest(Compositor().LastFrameTime() +
                              base::Seconds(0.016));

  // Update draw properties.
  cc::LayerTreeHostImpl::FrameData frame;
  auto* lthi = GetLayerTreeHostImpl();
  lthi->PrepareToDraw(&frame);

  Element* sticky = GetDocument().QuerySelector(AtomicString(".sticky"));
  cc::ElementId sticky_translation = CompositorElementIdFromUniqueObjectId(
      sticky->GetLayoutObject()->UniqueId(),
      CompositorElementIdNamespace::kStickyTranslation);
  auto* transform_node = lthi->active_tree()
                             ->property_trees()
                             ->transform_tree()
                             .FindNodeFromElementId(sticky_translation);

  // Sticky translation should NOT reflect the updated scroll, since the scroll
  // is main-repainted and we haven't had a main frame yet.
  EXPECT_EQ(50, transform_node->to_parent.To2dTranslation().x());
}

TEST_F(ScrollingSimTest, ScrollTimelineActiveAtBoundary) {
  String kUrl = "https://example.com/test.html";
  SimRequest request(kUrl, "text/html");
  LoadURL(kUrl);

  request.Complete(R"HTML(
    <style>
      #s { overflow-y: scroll; width: 300px; height: 200px;
           position: relative; background: white; }
      #sp { width: 100px; height: 1000px; }
      #align { width: 100%; height: 20px; position: absolute; background: blue;
               will-change: transform; animation: a linear 10s;
               animation-timeline: scroll(); }
      @keyframes a {
        0% { transform: translateY(0); }
        100% { transform: translateY(800px); }
      }
    </style>
    <div id=s><div id=sp><div id=align></div>hello</div></div>
  )HTML");

  cc::AnimationHost* impl_host =
      static_cast<cc::AnimationHost*>(GetLayerTreeHostImpl()->mutator_host());

  // First frame: Initial commit creates the cc::Animation etc.
  Compositor().BeginFrame();

  blink::Animation* animation =
      GetDocument().getElementById(AtomicString("align"))->getAnimations()[0];
  cc::Animation* cc_animation =
      animation->GetCompositorAnimation()->CcAnimation();
```