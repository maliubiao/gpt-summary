Response:
The user wants me to analyze a C++ source code file for the Chromium Blink engine.
Specifically, the file is `paint_layer_scrollable_area_test.cc`.

I need to:
1. **Summarize the file's functionality.**  Based on the file name and included headers, it seems to be a test suite for the `PaintLayerScrollableArea` class. This class likely deals with how scrollable areas are painted and composited.
2. **Explain its relationship to JavaScript, HTML, and CSS.** Scrollable areas are directly influenced by CSS properties like `overflow`, `width`, `height`, and `transform`. JavaScript can also programmatically manipulate scrolling. HTML elements like `div` with `overflow: scroll` create scrollable areas.
3. **Provide examples of logical reasoning with input/output.** This will involve looking at specific test cases and inferring the expected behavior.
4. **Illustrate common user/programming errors.** These might relate to misunderstandings of how compositing works or how CSS properties affect scrollable areas.
5. **Describe how a user interaction might lead to this code being executed.** This involves tracing the rendering pipeline from user actions to the paint and compositing stages.
6. **Provide a concise summary of the file's functionality.**

Let's break down the code:

*   **Includes:** The included headers give strong clues about the file's purpose:
    *   `paint_layer_scrollable_area.h`: The class being tested.
    *   `cc/layers/picture_layer.h`: Indicates involvement with compositing.
    *   `testing/gmock/include/gmock/gmock.h`:  Shows it's a test file using Google Mock.
    *   `renderer/core/animation/scroll_timeline.h`:  Suggests interaction with scroll-linked animations.
    *   `renderer/core/css/...`:  Confirms involvement with CSS.
    *   `renderer/core/frame/...`:  Indicates interaction with the browser frame.
    *   `renderer/core/layout/...`:  Shows interaction with the layout engine.
    *   `renderer/core/paint/...`:  Confirms it's related to the painting process.
    *   `renderer/core/scroll/...`:  Directly related to scrolling functionality.

*   **Test Structure:** The `PaintLayerScrollableAreaTest` class inherits from `PaintControllerPaintTest`, which likely provides a testing framework for paint-related functionalities. The use of `TEST_P` suggests it's a parameterized test suite.

*   **Individual Tests:** The names of the individual tests reveal the specific features being tested, such as compositing behavior under different conditions (opaque layers, transforms, `will-change`), interaction with tooltips, and handling of different scrollbar types.

**Hypothesized Functionality:** This file contains unit tests for the `PaintLayerScrollableArea` class. This class is responsible for managing the painting and compositing of elements that have scrollable overflow. The tests verify that the correct compositing decisions are made based on CSS properties and element types, and that scrolling-related features like tooltips and scrollbar behavior work as expected.
```
这是目录为blink/renderer/core/paint/paint_layer_scrollable_area_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"

#include "build/build_config.h"
#include "cc/layers/picture_layer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"

using testing::_;

namespace blink {
namespace {

class ScrollableAreaMockChromeClient : public RenderingTestChromeClient {
 public:
  MOCK_METHOD3(MockUpdateTooltipUnderCursor,
               void(LocalFrame*, const String&, TextDirection));
  void UpdateTooltipUnderCursor(LocalFrame& frame,
                                const String& tooltip_text,
                                TextDirection dir) override {
    MockUpdateTooltipUnderCursor(&frame, tooltip_text, dir);
  }
};

}  // namespace

class PaintLayerScrollableAreaTest : public PaintControllerPaintTest {
 public:
  PaintLayerScrollableAreaTest()
      : PaintControllerPaintTest(MakeGarbageCollected<EmptyLocalFrameClient>()),
        chrome_client_(MakeGarbageCollected<ScrollableAreaMockChromeClient>()) {
  }

  ~PaintLayerScrollableAreaTest() override {
    testing::Mock::VerifyAndClearExpectations(&GetChromeClient());
  }

  ScrollableAreaMockChromeClient& GetChromeClient() const override {
    return *chrome_client_;
  }

  bool HasDirectCompositingReasons(const LayoutObject* scroller) {
    const auto* paint_properties = scroller->FirstFragment().PaintProperties();
    return paint_properties && paint_properties->Transform() &&
           paint_properties->Transform()->HasDirectCompositingReasons();
  }

  bool UsesCompositedScrolling(const LayoutBox* scroller) {
    // TODO(crbug.com/1414885): The tests no longer test
    // PaintLayerScrollableArea. We should probably move them into
    // scrolling_test.cc.
    if (auto* scrollable_area = scroller->GetScrollableArea()) {
      const auto* property_trees =
          GetFrame().View()->RootCcLayer()->layer_tree_host()->property_trees();
      if (const auto* scroll_node =
              property_trees->scroll_tree().FindNodeFromElementId(
                  scrollable_area->GetScrollElementId())) {
        return scroll_node->is_composited;
      }
    }
    return false;
  }

  // Default browser preferred color scheme is light. The method sets both
  // browser-based and the OS-based preferred color schemes to dark.
  void SetPreferredColorSchemesToDark(ColorSchemeHelper& color_scheme_helper) {
    color_scheme_helper.SetPreferredRootScrollbarColorScheme(
        mojom::blink::PreferredColorScheme::kDark);
    color_scheme_helper.SetPreferredColorScheme(
        mojom::blink::PreferredColorScheme::kDark);
  }

  void AssertDefaultPreferredColorSchemes() const {
    ASSERT_EQ(GetDocument().GetPreferredColorScheme(),
              mojom::blink::PreferredColorScheme::kLight);
    ASSERT_EQ(
        GetDocument().GetSettings()->GetPreferredRootScrollbarColorScheme(),
        mojom::blink::PreferredColorScheme::kLight);
  }

  void ExpectEqAllScrollControlsNeedPaintInvalidation(
      const PaintLayerScrollableArea* area,
      bool expectation) const {
    EXPECT_EQ(area->VerticalScrollbarNeedsPaintInvalidation(), expectation);
    EXPECT_EQ(area->HorizontalScrollbarNeedsPaintInvalidation(), expectation);
    EXPECT_EQ(area->ScrollCornerNeedsPaintInvalidation(), expectation);
  }

 private:
  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }

  Persistent<ScrollableAreaMockChromeClient> chrome_client_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(PaintLayerScrollableAreaTest);

TEST_P(PaintLayerScrollableAreaTest, OpaqueContainedLayersPromoted) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px;
    contain: paint; background: white local content-box;
    border: 10px solid rgba(0, 255, 0, 0.5); }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  EXPECT_TRUE(UsesCompositedScrolling(GetLayoutBoxByElementId("scroller")));
}

TEST_P(PaintLayerScrollableAreaTest, NonStackingContextScrollerPromoted) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px;
    background: white local content-box;
    border: 10px solid rgba(0, 255, 0, 0.5); }
    #scrolled { height: 300px; }
    #positioned { position: relative; }
    </style>
    <div id="scroller">
      <div id="positioned">Not contained by scroller.</div>
      <div id="scrolled"></div>
    </div>
  )HTML");

  EXPECT_TRUE(UsesCompositedScrolling(GetLayoutBoxByElementId("scroller")));
}

TEST_P(PaintLayerScrollableAreaTest, TransparentLayersNotPromoted) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    rgba(0, 255, 0, 0.5) local content-box; border: 10px solid rgba(0, 255,
    0, 0.5); contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  EXPECT_FALSE(UsesCompositedScrolling(GetLayoutBoxByElementId("scroller")));
}

TEST_P(PaintLayerScrollableAreaTest, OpaqueLayersDepromotedOnStyleChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    white local content-box; contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the background to transparent
  scroller->setAttribute(
      html_names::kStyleAttr,
      AtomicString("background: rgba(255,255,255,0.5) local content-box;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

TEST_P(PaintLayerScrollableAreaTest, OpaqueLayersPromotedOnStyleChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    rgba(255,255,255,0.5) local content-box; contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the background to opaque
  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("background: white local content-box;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

// Tests that a transform on the scroller or an ancestor doesn't prevent
// promotion.
TEST_P(PaintLayerScrollableAreaTest,
       TransformDoesNotPreventCompositedScrolling) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    white local content-box; contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="parent">
      <div id="scroller"><div id="scrolled"></div></div>
    </div>
  )HTML");

  Element* parent = GetDocument().getElementById(AtomicString("parent"));
  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the parent to have a transform.
  parent->setAttribute(html_names::kStyleAttr,
                       AtomicString("transform: translate(1px, 0);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the parent to have no transform again.
  parent->removeAttribute(html_names::kStyleAttr);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Apply a transform to the scroller directly.
  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("transform: translate(1px, 0);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

TEST_P(PaintLayerScrollableAreaTest,
       PromoteLayerRegardlessOfSelfAndAncestorOpacity) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    white local content-box; contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="parent">
      <div id="scroller"><div id="scrolled"></div></div>
    </div>
  )HTML");

  Element* parent = GetDocument().getElementById(AtomicString("parent"));
  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the parent to be partially translucent.
  parent->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.5;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the parent to be opaque again.
  parent->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 1;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Make the scroller translucent.
  scroller->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.5"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

// Test that will-change: transform applied to the scroller will cause the
// scrolling contents layer to be promoted.
TEST_P(PaintLayerScrollableAreaTest, CompositedScrollOnWillChangeTransform) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; height: 100px; width: 100px; }
      #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("will-change: transform"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  scroller->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

// Test that will-change: transform applied to the scroller will cause the
// scrolling contents layer to be promoted.
TEST_P(PaintLayerScrollableAreaTest, ScrollLayerOnPointerEvents) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; height: 100px; width: 100px; }
      #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // pointer-events: none does not affect whether composited scrolling is
  // present.
  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("pointer-events: none"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // visibility: hidden causes the scroller to be invisible for hit testing,
  // so ScrollsOverflow becomes false on the PaintLayerScrollableArea, and hence
  // composited scrolling is not present.
  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("visibility: hidden"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  scroller->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

// Test that <input> elements don't use composited scrolling even with
// "will-change:transform".
TEST_P(PaintLayerScrollableAreaTest, InputElementPromotionTest) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
     .composited { will-change: transform; }
    </style>
    <input id='input' width=10 style='font-size:40pt;'/>
  )HTML");

  Element* element = GetDocument().getElementById(AtomicString("input"));
  EXPECT_FALSE(HasDirectCompositingReasons(element->GetLayoutObject()));
  EXPECT_FALSE(UsesCompositedScrolling(element->GetLayoutBox()));

  element->setAttribute(html_names::kClassAttr, AtomicString("composited"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(HasDirectCompositingReasons(element->GetLayoutObject()));
  EXPECT_FALSE(UsesCompositedScrolling(element->GetLayoutBox()));
}

// Test that <select> elements use composited scrolling with
// "will-change:transform".
TEST_P(PaintLayerScrollableAreaTest, SelectElementPromotionTest) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
     .composited { will-change: transform; }
    </style>
    <select id='select' size='2'>
      <option> value 1</option>
      <option> value 2</option>
      <option> value 3</option>
      <option> value 4</option>
    </select>
  )HTML");

  Element* element = GetDocument().getElementById(AtomicString("select"));
  EXPECT_FALSE(HasDirectCompositingReasons(element->GetLayoutObject()));
  EXPECT_FALSE(UsesCompositedScrolling(element->GetLayoutBox()));

  element->setAttribute(html_names::kClassAttr, AtomicString("composited"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(HasDirectCompositingReasons(element->GetLayoutObject()));
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  // <select> implementation is different and not scrollable on Android and iOS.
  EXPECT_FALSE(UsesCompositedScrolling(element->GetLayoutBox()));
#else
  EXPECT_TRUE(UsesCompositedScrolling(element->GetLayoutBox()));
#endif
}

// Ensure OverlayScrollbarColorTheme get updated when page load
TEST_P(PaintLayerScrollableAreaTest, OverlayScrollbarColorThemeUpdated) {
  SetBodyInnerHTML(R"HTML(
    <style>
    div { overflow: scroll; }
    #white { background-color: white; }
    #black { background-color: black; }
    </style>
    <div id="none">a</div>
    <div id="white">b</div>
    <div id="black">c</div>
  )HTML");

  PaintLayer* none_layer = GetPaintLayerByElementId("none");
  PaintLayer* white_layer = GetPaintLayerByElementId("white");
  PaintLayer* black_layer = GetPaintLayerByElementId("black");

  ASSERT_TRUE(none_layer);
  ASSERT_TRUE(white_layer);
  ASSERT_TRUE(black_layer);

  ASSERT_EQ(mojom::blink::ColorScheme::kLight,
            none_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  ASSERT_EQ(mojom::blink::ColorScheme::kLight,
            white_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  ASSERT_EQ(mojom::blink::ColorScheme::kDark,
            black_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
}

TEST_P(PaintLayerScrollableAreaTest,
       RecalculatesScrollbarOverlayIfBackgroundChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        width: 10px;
        height: 10px;
        overflow: scroll;
      }
      .forcescroll { height: 1000px; }
    </style>
    <div id="scroller">
      <div class="forcescroll"></div>
    </div>
  )HTML");
  PaintLayer* scroll_paint_layer = GetPaintLayerByElementId("scroller");
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            scroll_paint_layer->GetScrollableArea()
                ->GetOverlayScrollbarColorScheme());

  GetElementById("scroller")
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("background: rgb(34, 85, 51);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            scroll_paint_layer->GetScrollableArea()
                ->GetOverlayScrollbarColorScheme());

  GetElementById("scroller")
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("background: rgb(236, 143, 185);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            scroll_paint_layer->GetScrollableArea()
                ->GetOverlayScrollbarColorScheme());
}

// The scrollbar overlay color theme should follow the used color scheme when a
// background color is not available on the scroller itself.
TEST_P(PaintLayerScrollableAreaTest, PreferredOverlayScrollbarColorTheme) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  SetBodyInnerHTML(R"HTML(
    <meta name="color-scheme" content="light dark">
    <style>
      .scroller {
        width: 10px;
        height: 10px;
        overflow: scroll;
      }
      #white { background-color: white; }
      #black { background-color: black; }
      .forcescroll { height: 1000px; }
    </style>
    <div class="scroller" id="none">
      <div class="forcescroll"></div>
    </div>
    <div class="scroller" id="white">
      <div class="forcescroll"></div>
    </div>
    <div class="scroller" id="black">
      <div class="forcescroll"></div>
    </div>
  )HTML");

  PaintLayer* none_layer = GetPaintLayerByElementId("none");
  PaintLayer* white_layer = GetPaintLayerByElementId("white");
  PaintLayer* black_layer = GetPaintLayerByElementId("black");
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            none_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            white_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            black_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            none_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            white_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            black_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
}

TEST_P(PaintLayerScrollableAreaTest, HideTooltipWhenScrollPositionChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { width: 100px; height: 100px; overflow: scroll; }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  PaintLayerScrollableArea* scrollable_area =
      scroller->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);

  EXPECT_CALL(GetChromeClient(), MockUpdateTooltipUnderCursor(
                                     GetDocument().GetFrame(), String(), _))
      .Times(1);
  scrollable_area->SetScrollOffset(ScrollOffset(1, 1),
                                   mojom::blink::ScrollType::kUser);

  // Programmatic scrolling should not dismiss the tooltip, so
  // UpdateTooltipUnderCursor should not be called for this invocation.
  EXPECT_CALL(GetChromeClient(), MockUpdateTooltipUnderCursor(
                                     GetDocument().GetFrame(), String(), _))
      .Times(0);
  scrollable_area->SetScrollOffset(ScrollOffset(2, 2),
                                   mojom::blink::ScrollType::kProgrammatic);
}

TEST_P(PaintLayerScrollableAreaTest, IncludeOverlayScrollbarsInVisibleWidth) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: overlay; height: 100px; width: 100px; }
    #scrolled { width: 100px; height: 200px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  ASSERT_TRUE(scroller);
  PaintLayerScrollableArea* scrollable_area =
      scroller->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  scrollable_area->SetScrollOffset(ScrollOffset(100, 0),
                                   mojom::blink::ScrollType::kClamping);
  EXPECT_EQ(scrollable_area->GetScrollOffset().x(), 15);
}

TEST_P(PaintLayerScrollableAreaTest, ShowAutoScrollbarsForVisibleContent) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <style>
    #outerDiv {
      width: 15px;
      height: 100px;
      overflow-y: auto;
      overflow-x: hidden;
    }
    #innerDiv {
      height:300px;
      width: 1px;
    }
    </style>
    <div id='outerDiv'>
      <div id='innerDiv'></div>
    </div>
  )HTML");

  Element* outer_div = GetDocument().getElementById(AtomicString("outerDiv"));
  ASSERT_TRUE(outer_div);
  outer_div->GetLayoutBox()->SetNeedsLayout("test");
  UpdateAllLifecyclePhasesForTest();
  PaintLayerScrollableArea* scrollable_area =
      outer_div->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_TRUE(scrollable_area->HasVerticalScrollbar());
}

TEST_P(PaintLayerScrollableAreaTest, FloatOverflowInRtlContainer) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      width: 200px;
      overflow-x: auto;
      overflow-y: scroll;
      direction: rtl;
    }
    </style>
    <div id='container'>
      <div style='float:left'>
    lorem ipsum
      </div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);
  PaintLayerScrollableArea* scrollable_area =
      container->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_FALSE(scrollable_area->HasHorizontalScrollbar());
}

TEST_P(PaintLayerScrollableAreaTest, ScrollOriginInRtlContainer) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      width: 200px;
      overflow: auto;
      direction: rtl;
    }
    #content {
      width: 300px;
    }
    </style>
    <div id='container'>
      <div id='content'>
    lorem ipsum
      <div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);
  PaintLayerScrollableArea* scrollable_area =
      container->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_EQ(scrollable_area->ScrollOrigin().x(), 100);
}

TEST_P(PaintLayerScrollableAreaTest, OverflowHiddenScrollOffsetInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller {
      overflow: hidden;
      height: 200px;
      width: 200px;
    }
    </style>
    <div id='scroller'>
      <div id='forceScroll' style='height: 2000px;'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();

  const auto* properties = scroller->FirstFragment().PaintProperties();

  // No scroll offset translation is needed when scroll offset is zero.
  EXPECT_EQ(nullptr, properties->ScrollTranslation());
  EXPECT_EQ(ScrollOffset(0, 0), scrollable_area->GetScrollOffset());

  // A property update is needed when scroll offset changes.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(scroller->NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(scroller->PaintingLayer()->SelfNeedsRepaint());

  // A scroll offset translation is needed when scroll offset is non-zero.
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
  EXPECT_NE(nullptr, properties->ScrollTranslation());

  UpdateAllLifecyclePhasesForTest();

  scrollable_area->SetScrollOffset(ScrollOffset(0, 2),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(scroller->NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(scroller->PaintingLayer()->SelfNeedsRepaint());

  // A scroll offset translation is still needed when scroll offset is non-zero.
  EXPECT_EQ(ScrollOffset(0, 2), scrollable_area->GetScrollOffset());
  EXPECT_NE(nullptr, properties->ScrollTranslation());

  UpdateAllLifecyclePhasesForTest();

  
### 提示词
```
这是目录为blink/renderer/core/paint/paint_layer_scrollable_area_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"

#include "build/build_config.h"
#include "cc/layers/picture_layer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"

using testing::_;

namespace blink {
namespace {

class ScrollableAreaMockChromeClient : public RenderingTestChromeClient {
 public:
  MOCK_METHOD3(MockUpdateTooltipUnderCursor,
               void(LocalFrame*, const String&, TextDirection));
  void UpdateTooltipUnderCursor(LocalFrame& frame,
                                const String& tooltip_text,
                                TextDirection dir) override {
    MockUpdateTooltipUnderCursor(&frame, tooltip_text, dir);
  }
};

}  // namespace

class PaintLayerScrollableAreaTest : public PaintControllerPaintTest {
 public:
  PaintLayerScrollableAreaTest()
      : PaintControllerPaintTest(MakeGarbageCollected<EmptyLocalFrameClient>()),
        chrome_client_(MakeGarbageCollected<ScrollableAreaMockChromeClient>()) {
  }

  ~PaintLayerScrollableAreaTest() override {
    testing::Mock::VerifyAndClearExpectations(&GetChromeClient());
  }

  ScrollableAreaMockChromeClient& GetChromeClient() const override {
    return *chrome_client_;
  }

  bool HasDirectCompositingReasons(const LayoutObject* scroller) {
    const auto* paint_properties = scroller->FirstFragment().PaintProperties();
    return paint_properties && paint_properties->Transform() &&
           paint_properties->Transform()->HasDirectCompositingReasons();
  }

  bool UsesCompositedScrolling(const LayoutBox* scroller) {
    // TODO(crbug.com/1414885): The tests no longer test
    // PaintLayerScrollableArea. We should probably move them into
    // scrolling_test.cc.
    if (auto* scrollable_area = scroller->GetScrollableArea()) {
      const auto* property_trees =
          GetFrame().View()->RootCcLayer()->layer_tree_host()->property_trees();
      if (const auto* scroll_node =
              property_trees->scroll_tree().FindNodeFromElementId(
                  scrollable_area->GetScrollElementId())) {
        return scroll_node->is_composited;
      }
    }
    return false;
  }

  // Default browser preferred color scheme is light. The method sets both
  // browser-based and the OS-based preferred color schemes to dark.
  void SetPreferredColorSchemesToDark(ColorSchemeHelper& color_scheme_helper) {
    color_scheme_helper.SetPreferredRootScrollbarColorScheme(
        mojom::blink::PreferredColorScheme::kDark);
    color_scheme_helper.SetPreferredColorScheme(
        mojom::blink::PreferredColorScheme::kDark);
  }

  void AssertDefaultPreferredColorSchemes() const {
    ASSERT_EQ(GetDocument().GetPreferredColorScheme(),
              mojom::blink::PreferredColorScheme::kLight);
    ASSERT_EQ(
        GetDocument().GetSettings()->GetPreferredRootScrollbarColorScheme(),
        mojom::blink::PreferredColorScheme::kLight);
  }

  void ExpectEqAllScrollControlsNeedPaintInvalidation(
      const PaintLayerScrollableArea* area,
      bool expectation) const {
    EXPECT_EQ(area->VerticalScrollbarNeedsPaintInvalidation(), expectation);
    EXPECT_EQ(area->HorizontalScrollbarNeedsPaintInvalidation(), expectation);
    EXPECT_EQ(area->ScrollCornerNeedsPaintInvalidation(), expectation);
  }

 private:
  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }

  Persistent<ScrollableAreaMockChromeClient> chrome_client_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(PaintLayerScrollableAreaTest);

TEST_P(PaintLayerScrollableAreaTest, OpaqueContainedLayersPromoted) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px;
    contain: paint; background: white local content-box;
    border: 10px solid rgba(0, 255, 0, 0.5); }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  EXPECT_TRUE(UsesCompositedScrolling(GetLayoutBoxByElementId("scroller")));
}

TEST_P(PaintLayerScrollableAreaTest, NonStackingContextScrollerPromoted) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px;
    background: white local content-box;
    border: 10px solid rgba(0, 255, 0, 0.5); }
    #scrolled { height: 300px; }
    #positioned { position: relative; }
    </style>
    <div id="scroller">
      <div id="positioned">Not contained by scroller.</div>
      <div id="scrolled"></div>
    </div>
  )HTML");

  EXPECT_TRUE(UsesCompositedScrolling(GetLayoutBoxByElementId("scroller")));
}

TEST_P(PaintLayerScrollableAreaTest, TransparentLayersNotPromoted) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    rgba(0, 255, 0, 0.5) local content-box; border: 10px solid rgba(0, 255,
    0, 0.5); contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  EXPECT_FALSE(UsesCompositedScrolling(GetLayoutBoxByElementId("scroller")));
}

TEST_P(PaintLayerScrollableAreaTest, OpaqueLayersDepromotedOnStyleChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    white local content-box; contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the background to transparent
  scroller->setAttribute(
      html_names::kStyleAttr,
      AtomicString("background: rgba(255,255,255,0.5) local content-box;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

TEST_P(PaintLayerScrollableAreaTest, OpaqueLayersPromotedOnStyleChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    rgba(255,255,255,0.5) local content-box; contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the background to opaque
  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("background: white local content-box;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

// Tests that a transform on the scroller or an ancestor doesn't prevent
// promotion.
TEST_P(PaintLayerScrollableAreaTest,
       TransformDoesNotPreventCompositedScrolling) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    white local content-box; contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="parent">
      <div id="scroller"><div id="scrolled"></div></div>
    </div>
  )HTML");

  Element* parent = GetDocument().getElementById(AtomicString("parent"));
  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the parent to have a transform.
  parent->setAttribute(html_names::kStyleAttr,
                       AtomicString("transform: translate(1px, 0);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the parent to have no transform again.
  parent->removeAttribute(html_names::kStyleAttr);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Apply a transform to the scroller directly.
  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("transform: translate(1px, 0);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

TEST_P(PaintLayerScrollableAreaTest,
       PromoteLayerRegardlessOfSelfAndAncestorOpacity) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: scroll; height: 200px; width: 200px; background:
    white local content-box; contain: paint; }
    #scrolled { height: 300px; }
    </style>
    <div id="parent">
      <div id="scroller"><div id="scrolled"></div></div>
    </div>
  )HTML");

  Element* parent = GetDocument().getElementById(AtomicString("parent"));
  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the parent to be partially translucent.
  parent->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.5;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Change the parent to be opaque again.
  parent->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 1;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // Make the scroller translucent.
  scroller->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.5"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

// Test that will-change: transform applied to the scroller will cause the
// scrolling contents layer to be promoted.
TEST_P(PaintLayerScrollableAreaTest, CompositedScrollOnWillChangeTransform) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; height: 100px; width: 100px; }
      #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("will-change: transform"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  scroller->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

// Test that will-change: transform applied to the scroller will cause the
// scrolling contents layer to be promoted.
TEST_P(PaintLayerScrollableAreaTest, ScrollLayerOnPointerEvents) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; height: 100px; width: 100px; }
      #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // pointer-events: none does not affect whether composited scrolling is
  // present.
  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("pointer-events: none"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  // visibility: hidden causes the scroller to be invisible for hit testing,
  // so ScrollsOverflow becomes false on the PaintLayerScrollableArea, and hence
  // composited scrolling is not present.
  scroller->setAttribute(html_names::kStyleAttr,
                         AtomicString("visibility: hidden"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(UsesCompositedScrolling(scroller->GetLayoutBox()));

  scroller->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(UsesCompositedScrolling(scroller->GetLayoutBox()));
}

// Test that <input> elements don't use composited scrolling even with
// "will-change:transform".
TEST_P(PaintLayerScrollableAreaTest, InputElementPromotionTest) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
     .composited { will-change: transform; }
    </style>
    <input id='input' width=10 style='font-size:40pt;'/>
  )HTML");

  Element* element = GetDocument().getElementById(AtomicString("input"));
  EXPECT_FALSE(HasDirectCompositingReasons(element->GetLayoutObject()));
  EXPECT_FALSE(UsesCompositedScrolling(element->GetLayoutBox()));

  element->setAttribute(html_names::kClassAttr, AtomicString("composited"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(HasDirectCompositingReasons(element->GetLayoutObject()));
  EXPECT_FALSE(UsesCompositedScrolling(element->GetLayoutBox()));
}

// Test that <select> elements use composited scrolling with
// "will-change:transform".
TEST_P(PaintLayerScrollableAreaTest, SelectElementPromotionTest) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
     .composited { will-change: transform; }
    </style>
    <select id='select' size='2'>
      <option> value 1</option>
      <option> value 2</option>
      <option> value 3</option>
      <option> value 4</option>
    </select>
  )HTML");

  Element* element = GetDocument().getElementById(AtomicString("select"));
  EXPECT_FALSE(HasDirectCompositingReasons(element->GetLayoutObject()));
  EXPECT_FALSE(UsesCompositedScrolling(element->GetLayoutBox()));

  element->setAttribute(html_names::kClassAttr, AtomicString("composited"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(HasDirectCompositingReasons(element->GetLayoutBox()));
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  // <select> implementation is different and not scrollable on Android and iOS.
  EXPECT_FALSE(UsesCompositedScrolling(element->GetLayoutBox()));
#else
  EXPECT_TRUE(UsesCompositedScrolling(element->GetLayoutBox()));
#endif
}

// Ensure OverlayScrollbarColorTheme get updated when page load
TEST_P(PaintLayerScrollableAreaTest, OverlayScrollbarColorThemeUpdated) {
  SetBodyInnerHTML(R"HTML(
    <style>
    div { overflow: scroll; }
    #white { background-color: white; }
    #black { background-color: black; }
    </style>
    <div id="none">a</div>
    <div id="white">b</div>
    <div id="black">c</div>
  )HTML");

  PaintLayer* none_layer = GetPaintLayerByElementId("none");
  PaintLayer* white_layer = GetPaintLayerByElementId("white");
  PaintLayer* black_layer = GetPaintLayerByElementId("black");

  ASSERT_TRUE(none_layer);
  ASSERT_TRUE(white_layer);
  ASSERT_TRUE(black_layer);

  ASSERT_EQ(mojom::blink::ColorScheme::kLight,
            none_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  ASSERT_EQ(mojom::blink::ColorScheme::kLight,
            white_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  ASSERT_EQ(mojom::blink::ColorScheme::kDark,
            black_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
}

TEST_P(PaintLayerScrollableAreaTest,
       RecalculatesScrollbarOverlayIfBackgroundChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        width: 10px;
        height: 10px;
        overflow: scroll;
      }
      .forcescroll { height: 1000px; }
    </style>
    <div id="scroller">
      <div class="forcescroll"></div>
    </div>
  )HTML");
  PaintLayer* scroll_paint_layer = GetPaintLayerByElementId("scroller");
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            scroll_paint_layer->GetScrollableArea()
                ->GetOverlayScrollbarColorScheme());

  GetElementById("scroller")
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("background: rgb(34, 85, 51);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            scroll_paint_layer->GetScrollableArea()
                ->GetOverlayScrollbarColorScheme());

  GetElementById("scroller")
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("background: rgb(236, 143, 185);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            scroll_paint_layer->GetScrollableArea()
                ->GetOverlayScrollbarColorScheme());
}

// The scrollbar overlay color theme should follow the used color scheme when a
// background color is not available on the scroller itself.
TEST_P(PaintLayerScrollableAreaTest, PreferredOverlayScrollbarColorTheme) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  SetBodyInnerHTML(R"HTML(
    <meta name="color-scheme" content="light dark">
    <style>
      .scroller {
        width: 10px;
        height: 10px;
        overflow: scroll;
      }
      #white { background-color: white; }
      #black { background-color: black; }
      .forcescroll { height: 1000px; }
    </style>
    <div class="scroller" id="none">
      <div class="forcescroll"></div>
    </div>
    <div class="scroller" id="white">
      <div class="forcescroll"></div>
    </div>
    <div class="scroller" id="black">
      <div class="forcescroll"></div>
    </div>
  )HTML");

  PaintLayer* none_layer = GetPaintLayerByElementId("none");
  PaintLayer* white_layer = GetPaintLayerByElementId("white");
  PaintLayer* black_layer = GetPaintLayerByElementId("black");
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            none_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            white_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            black_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            none_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            white_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            black_layer->GetScrollableArea()->GetOverlayScrollbarColorScheme());
}

TEST_P(PaintLayerScrollableAreaTest, HideTooltipWhenScrollPositionChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { width: 100px; height: 100px; overflow: scroll; }
    #scrolled { height: 300px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  PaintLayerScrollableArea* scrollable_area =
      scroller->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);

  EXPECT_CALL(GetChromeClient(), MockUpdateTooltipUnderCursor(
                                     GetDocument().GetFrame(), String(), _))
      .Times(1);
  scrollable_area->SetScrollOffset(ScrollOffset(1, 1),
                                   mojom::blink::ScrollType::kUser);

  // Programmatic scrolling should not dismiss the tooltip, so
  // UpdateTooltipUnderCursor should not be called for this invocation.
  EXPECT_CALL(GetChromeClient(), MockUpdateTooltipUnderCursor(
                                     GetDocument().GetFrame(), String(), _))
      .Times(0);
  scrollable_area->SetScrollOffset(ScrollOffset(2, 2),
                                   mojom::blink::ScrollType::kProgrammatic);
}

TEST_P(PaintLayerScrollableAreaTest, IncludeOverlayScrollbarsInVisibleWidth) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: overlay; height: 100px; width: 100px; }
    #scrolled { width: 100px; height: 200px; }
    </style>
    <div id="scroller"><div id="scrolled"></div></div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  ASSERT_TRUE(scroller);
  PaintLayerScrollableArea* scrollable_area =
      scroller->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  scrollable_area->SetScrollOffset(ScrollOffset(100, 0),
                                   mojom::blink::ScrollType::kClamping);
  EXPECT_EQ(scrollable_area->GetScrollOffset().x(), 15);
}

TEST_P(PaintLayerScrollableAreaTest, ShowAutoScrollbarsForVisibleContent) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <style>
    #outerDiv {
      width: 15px;
      height: 100px;
      overflow-y: auto;
      overflow-x: hidden;
    }
    #innerDiv {
      height:300px;
      width: 1px;
    }
    </style>
    <div id='outerDiv'>
      <div id='innerDiv'></div>
    </div>
  )HTML");

  Element* outer_div = GetDocument().getElementById(AtomicString("outerDiv"));
  ASSERT_TRUE(outer_div);
  outer_div->GetLayoutBox()->SetNeedsLayout("test");
  UpdateAllLifecyclePhasesForTest();
  PaintLayerScrollableArea* scrollable_area =
      outer_div->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_TRUE(scrollable_area->HasVerticalScrollbar());
}

TEST_P(PaintLayerScrollableAreaTest, FloatOverflowInRtlContainer) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      width: 200px;
      overflow-x: auto;
      overflow-y: scroll;
      direction: rtl;
    }
    </style>
    <div id='container'>
      <div style='float:left'>
    lorem ipsum
      </div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);
  PaintLayerScrollableArea* scrollable_area =
      container->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_FALSE(scrollable_area->HasHorizontalScrollbar());
}

TEST_P(PaintLayerScrollableAreaTest, ScrollOriginInRtlContainer) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    #container {
      width: 200px;
      overflow: auto;
      direction: rtl;
    }
    #content {
      width: 300px;
    }
    </style>
    <div id='container'>
      <div id='content'>
    lorem ipsum
      <div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);
  PaintLayerScrollableArea* scrollable_area =
      container->GetLayoutBox()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  EXPECT_EQ(scrollable_area->ScrollOrigin().x(), 100);
}

TEST_P(PaintLayerScrollableAreaTest, OverflowHiddenScrollOffsetInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller {
      overflow: hidden;
      height: 200px;
      width: 200px;
    }
    </style>
    <div id='scroller'>
      <div id='forceScroll' style='height: 2000px;'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();

  const auto* properties = scroller->FirstFragment().PaintProperties();

  // No scroll offset translation is needed when scroll offset is zero.
  EXPECT_EQ(nullptr, properties->ScrollTranslation());
  EXPECT_EQ(ScrollOffset(0, 0), scrollable_area->GetScrollOffset());

  // A property update is needed when scroll offset changes.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(scroller->NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(scroller->PaintingLayer()->SelfNeedsRepaint());

  // A scroll offset translation is needed when scroll offset is non-zero.
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
  EXPECT_NE(nullptr, properties->ScrollTranslation());

  UpdateAllLifecyclePhasesForTest();

  scrollable_area->SetScrollOffset(ScrollOffset(0, 2),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(scroller->NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(scroller->PaintingLayer()->SelfNeedsRepaint());

  // A scroll offset translation is still needed when scroll offset is non-zero.
  EXPECT_EQ(ScrollOffset(0, 2), scrollable_area->GetScrollOffset());
  EXPECT_NE(nullptr, properties->ScrollTranslation());

  UpdateAllLifecyclePhasesForTest();

  scrollable_area->SetScrollOffset(ScrollOffset(0, 0),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(scroller->NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(scroller->PaintingLayer()->SelfNeedsRepaint());

  // No scroll offset translation is needed when scroll offset is zero.
  EXPECT_EQ(nullptr, properties->ScrollTranslation());
  EXPECT_EQ(ScrollOffset(0, 0), scrollable_area->GetScrollOffset());
}

TEST_P(PaintLayerScrollableAreaTest, ScrollDoesNotInvalidate) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        overflow: scroll;
        height: 200px;
        width: 200px;
        background: linear-gradient(black, white);
      }
    </style>
    <div id='scroller'>
      <div id='forceScroll' style='height: 2000px;'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();

  const auto* properties = scroller->FirstFragment().PaintProperties();
  // Scroll offset translation is needed even when scroll offset is zero.
  EXPECT_NE(nullptr, properties->ScrollTranslation());
  EXPECT_EQ(ScrollOffset(0, 0), scrollable_area->GetScrollOffset());

  // Changing the scroll offset should not require paint invalidation.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_FALSE(scroller->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(scroller->NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
  EXPECT_NE(nullptr, properties->ScrollTranslation());
}

TEST_P(PaintLayerScrollableAreaTest, ScrollWithStickyNeedsCompositingUpdate) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0;
      }
      body {
        height: 610px;
        width: 820px;
      }
      #sticky {
        height: 10px;
        left: 50px;
        position: sticky;
        top: 50px;
        width: 10px;
      }
    </style>
    <div id=sticky></div>
  )HTML");

  auto* scrollable_area = GetLayoutView().GetScrollableArea();
  EXPECT_EQ(ScrollOffset(0, 0), scrollable_area->GetScrollOffset());

  // Changing the scroll offset requires a compositing update to rerun overlap
  // testing.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                   mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(
      GetDocument().View()->GetPaintArtifactCompositor()->NeedsUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
}

TEST_P(PaintLayerScrollableAreaTest,
       ScrollWithFixedDoesNotNeedCompositingUpdate) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0;
      }
      body {
        height: 610px;
        width: 820px;
      }
      #fixed {
        height: 10px;
        left: 50px;
        position: fixed;
        top: 50px;
        width: 10px;
      }
    </style>
    <div id=fixed></div>
  )HTML");

  auto* scrollable_area = GetLayoutView().GetScrollableArea();
  EXPECT_EQ(ScrollOffset(0, 0), scrollable_area->GetScrollOffset());

  // Changing the scroll offset should not require a compositing update even
  // though fixed-pos content is present as fixed bounds is already expanded to
  // include all possible scroll offsets.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                   mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(
      GetDocument().View()->GetPaintArtifactCompositor()->NeedsUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
}

TEST_P(PaintLayerScrollableAreaTest,
       ScrollWithLocalAttachmentBackgroundInScrollingContents) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        overflow: scroll;
        height: 200px;
        width: 200px;
        background: linear-gradient(black, white);
        background-attachment: local;
      }
    </style>
    <div id='scroller'>
      <div id='forceScroll' style='height: 2000px;'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();
  EXPECT_EQ(kBackgroundPaintInContentsSpace,
            scroller->GetBackgroundPaintLocation());
  EXPECT_FALSE(scrollable_area->BackgroundNeedsRepaintOnScroll());
  EXPECT_TRUE(UsesCompositedScrolling(scroller));

  // Programmatically changing the scroll offset.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                   mojom::blink::ScrollType::kProgrammatic);
  // No paint invalidation because it uses composited scrolling.
  EXPECT_FALSE(scroller->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(scroller->BackgroundNeedsFullPaintInvalidation());

  EXPECT_TRUE(scroller->NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
  const auto* properties = scroller->FirstFragment().PaintProperties();
  EXPECT_NE(nullptr, properties->ScrollTranslation());
}

TEST_P(PaintLayerScrollableAreaTest, ScrollWith3DPreserveParent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        overflow-y: scroll;
        height: 200px;
        width: 200px;
        background: white;
        /* TODO(crbug.com/1256990): This is to work around the issue of
           unexpected effect node on a non-self-painting PaintLayer. */
        position: relative;
      }
    </style>
    <div style='transform-style: preserve-3d;'>
      <div id='scroller'>
        <div style='height: 2000px;'></div>
      </div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            scroller->GetBackgroundPaintLocation());
}

TEST_P(PaintLayerScrollableAreaTest,
       ScrollWithLocalAttachmentBackgroundInMainLayer) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        overflow: scroll;
        height: 200px;
        width: 200px;
        border: 10px dashed black;
        background: linear-gradient(black, white) local, yellow;
      }
    </style>
    <div id='scroller'>
      <div id='forceScroll' style='height: 2000px;'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* scrollable_area = scroller->GetScrollableArea();
  EXPECT_EQ(kBackgroundPaintInBothSpaces,
            scroller->GetBackgroundPaintLocation());
  EXPECT_TRUE(scrollable_area->BackgroundNeedsRepaintOnScroll());

  // Programmatically changing the scroll offset.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 1),
                                   mojom::blink::ScrollType::kProgrammatic);
  // No invalidation because the background paints into the main layer.
  EXPECT_TRUE(scroller->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(scroller->BackgroundNeedsFullPaintInvalidation());
  EXPECT_TRUE(scroller->NeedsPaintPropertyUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
  const auto* properties = scroller->FirstFragment().PaintProperties();
  EXPECT_NE(nullptr, properties->ScrollTranslation());
}

TEST_P(PaintLayerScrollableAreaTest, ViewScrollWithFixedAttachmentBackground) {
  SetBodyInnerHTML(R"HT
```