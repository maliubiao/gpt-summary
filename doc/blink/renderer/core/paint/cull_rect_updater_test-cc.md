Response:
The user wants to understand the functionality of the `cull_rect_updater_test.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet to identify its purpose and relate it to web technologies like JavaScript, HTML, and CSS if applicable. I should also consider scenarios involving user interaction and potential errors. Finally, I need to summarize the functionality of this first part of the file.

Here's a breakdown of how to address the user's request:

1. **Identify the core purpose of the file:** The filename and the presence of `TEST_F` macros from `gtest` strongly suggest this file contains unit tests. The tests likely focus on the `CullRectUpdater` class.

2. **Analyze the test cases:** Each `TEST_F` block represents a specific test scenario. By examining the HTML snippets and the `EXPECT_EQ`/`EXPECT_TRUE`/`EXPECT_FALSE` assertions, I can infer what aspects of the `CullRectUpdater` are being tested. Key areas to look for include:
    * Basic cull rect calculation for elements with different dimensions and positioning.
    * Impact of CSS properties like `position`, `width`, `height`, `transform`, `writing-mode`, `overflow`, `clip-path`, and `contain`.
    * Behavior in scrolling scenarios, including regular scrolling and scrolling within elements (`overflow: scroll`).
    * Effects of transforms (scale, rotate, 3D transforms, perspective).
    * Handling of fixed-position elements.
    * Logic related to elements being off-screen.
    * Optimization techniques (e.g., for non-composited transforms).
    * Interaction with SVG elements.
    * Scenarios involving `will-change`.
    * Tests related to overriding cull rects.

3. **Relate to web technologies:**
    * **HTML:** The tests use HTML to create the DOM structure and elements whose cull rects are being examined. I need to identify how different HTML elements (divs, SVGs) are used in the tests.
    * **CSS:** The tests heavily rely on CSS to style and position elements. I need to note which CSS properties are being tested and how they influence the cull rect.
    * **JavaScript:** While the test file itself is C++, some tests involve simulating user interactions like scrolling using JavaScript API calls (`scrollTo`, `scrollBy`). I need to point out these instances.

4. **Provide examples and hypothetical scenarios:**
    * **Assumptions and Outputs:** For certain tests (especially those involving transformations and scrolling), I can provide hypothetical input values (e.g., specific transform values, scroll offsets) and the expected output cull rects based on the test assertions.
    * **Common Errors:** I can anticipate common mistakes developers might make when working with CSS properties that affect rendering and culling, such as incorrect `transform-origin`, forgetting to set `will-change` when needed, or misunderstanding how `position: fixed` interacts with scrolling.

5. **Explain user operations and debugging:**  I should describe how a user's actions in a web browser (e.g., scrolling, resizing the window, applying transformations via CSS or JavaScript) could lead to the execution of the code being tested. This is crucial for understanding the context of the tests.

6. **Summarize the functionality of part 1:**  Based on the analysis of the test cases in the first part of the file, I need to provide a concise summary of its overall purpose.

**Plan:**

* Read through each test case and understand its objective.
* Group the test cases by the feature or CSS property being tested.
* Identify relationships with HTML, CSS, and JavaScript.
* Formulate examples and potential errors.
* Describe user interactions that trigger the tested logic.
* Write the summary.
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"

namespace blink {

class CullRectUpdaterTest : public PaintControllerPaintTestBase {
 protected:
  CullRect GetCullRect(const char* id) {
    return GetLayoutObjectByElementId(id)->FirstFragment().GetCullRect();
  }

  CullRect GetCullRect(const PaintLayer& layer) {
    return layer.GetLayoutObject().FirstFragment().GetCullRect();
  }

  CullRect GetContentsCullRect(const char* id) {
    return GetLayoutObjectByElementId(id)
        ->FirstFragment()
        .GetContentsCullRect();
  }

  CullRect GetContentsCullRect(const PaintLayer& layer) {
    return layer.GetLayoutObject().FirstFragment().GetContentsCullRect();
  }
};

TEST_F(CullRectUpdaterTest, SimpleCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 200px; position: relative'>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, TallLayerCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 10000px; position: relative'>
    </div>
  )HTML");

  // Viewport rect (0, 0, 800, 600) expanded by 4000 for scrolling then clipped
  // by the contents rect.
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, WideLayerCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 10000px; height: 200px; position: relative'>
    </div>
  )HTML");

  // Same as TallLayerCullRect.
  EXPECT_EQ(gfx::Rect(0, 0, 4800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, VerticalRLWritingModeDocument) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { writing-mode: vertical-rl; }
      body { margin: 0; }
    </style>
    <div id='target' style='width: 10000px; height: 200px; position: relative'>
    </div>
  )HTML");

  GetDocument().domWindow()->scrollTo(-5000, 0);
  UpdateAllLifecyclePhasesForTest();

  // A scroll by -5000px is equivalent to a scroll by (10000 - 5000 - 800)px =
  // 4200px in non-RTL mode. Expanding the resulting rect by 4000px in each
  // direction and clipping by the contents rect yields this result.
  EXPECT_EQ(gfx::Rect(200, 0, 8800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, VerticalRLWritingModeScrollDiv) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { writing-mode: vertical-rl; }
    </style>
    <div id="scroller" style="width: 200px; height: 200px; overflow: scroll;
                              background: white">
      <div style="width: 10000px; height: 200px"></div>
    </div>
  )HTML");

  GetDocument().getElementById(AtomicString("scroller"))->scrollTo(-5000, 0);
  UpdateAllLifecyclePhasesForTest();

  // Similar to the previous test case.
  EXPECT_EQ(gfx::Rect(800, 0, 8200, 200),
            GetContentsCullRect("scroller").Rect());
}

TEST_F(CullRectUpdaterTest, ScaledCullRect) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                transform: scaleX(2) scaleY(0.75); transform-origin: 0 0'>
    </div>
  )HTML");

  // The expansion is 4000 / max(scaleX, scaleY).
  EXPECT_EQ(gfx::Rect(-2000, -2000, 4400, 4800), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, ScaledCullRectUnderCompositedScroller) {
  SetBodyInnerHTML(R"HTML(
    <div style='width: 200px; height: 300px; overflow: scroll; background: blue;
                transform: scaleX(2) scaleY(0.75); transform-origin: 0 0'>
      <div id='target' style='height: 400px; position: relative'></div>
      <div style='width: 10000px; height: 9600px'></div>
    </div>
  )HTML");

  // The expansion is calculated based on 4000 / max(scaleX, scaleY).
  EXPECT_EQ(gfx::Rect(0, 0, 1224, 1324), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, ScaledAndRotatedCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                transform: scaleX(3) scaleY(0.5) rotateZ(45deg)'>
    </div>
  )HTML");

  // The expansion 6599 is 4000 * max_dimension(1x1 rect projected from screen
  // to local).
  EXPECT_EQ(gfx::Rect(-6748, -6836, 14236, 14236),
            GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, ScaledAndRotatedCullRectUnderCompositedScroller) {
  SetBodyInnerHTML(R"HTML(
    <div style='width: 200px; height: 300px; overflow: scroll; background: blue;
                transform: scaleX(3) scaleY(0.5) rotateZ(45deg)'>
      <div id='target' style='height: 400px; position: relative;
               will-change: transform'></div>
      <div style='width: 10000px; height: 10000px'></div>
    </div>
  )HTML");

  // The expansion 6599 is 4000 * max_dimension(1x1 rect projected from screen
  // to local).
  EXPECT_EQ(gfx::Rect(-6599, -6599, 16697, 16797),
            GetCullRect("target").Rect());
  EXPECT_EQ(gfx::Rect(-6599, -6599, 16697, 16797),
            GetContentsCullRect("target").Rect());
}

// This is a testcase for https://crbug.com/1227907 where repeated cull rect
// updates are expensive on the motionmark microbenchmark.
TEST_F(CullRectUpdaterTest, OptimizeNonCompositedTransformUpdate) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        width: 50px;
        height: 50px;
        background: green;
        transform: translate(-8px, -8px);
      }
    </style>
    <div id='target'></div>
  )HTML");

  // The cull rect should be correctly calculated on first paint.
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect("target").Rect());

  // On subsequent paints, fall back to an infinite cull rect.
  GetDocument()
      .getElementById(AtomicString("target"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("transform: rotate(10deg);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(GetCullRect("target").IsInfinite());
}

TEST_F(CullRectUpdaterTest, 3DRotated90DegreesCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                transform: rotateY(90deg)'>
    </div>
  )HTML");

  EXPECT_TRUE(GetCullRect("target").Rect().Contains(gfx::Rect(0, 0, 200, 300)));
}

TEST_F(CullRectUpdaterTest, 3DRotatedNear90DegreesCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                transform: rotateY(89.9999deg)'>
    </div>
  )HTML");

  EXPECT_TRUE(GetCullRect("target").Rect().Contains(gfx::Rect(0, 0, 200, 300)));
}

TEST_F(CullRectUpdaterTest, PerspectiveCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id=target style='transform: perspective(1000px) rotateX(-100deg);'>
      <div style='width: 2000px; height: 3000px></div>
    </div>
  )HTML");

  EXPECT_TRUE(
      GetCullRect("target").Rect().Contains(gfx::Rect(0, 0, 2000, 3000)));
}

TEST_F(CullRectUpdaterTest, 3D60DegRotatedTallCullRect) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id='target'
         style='width: 200px; height: 10000px; transform: rotateY(60deg)'>
    </div>
  )HTML");

  // The cull rect is expanded in the y direction for the root scroller, and
  // x direction for |target| itself.
  EXPECT_EQ(gfx::Rect(-4100, 0, 9600, 4600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, FixedPositionInNonScrollableViewCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width: 1000px; height: 2000px;
                            position: fixed; top: 100px; left: 200px;'>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(-200, -100, 800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, FixedPositionInScrollableViewCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width: 1000px; height: 2000px;
                            position: fixed; top: 100px; left: 200px;'>
    </div>
    <div style='height: 3000px'></div>
  )HTML");

  EXPECT_EQ(gfx::Rect(-200, -100, 800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, LayerOffscreenNearCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                position: absolute; top: 3000px; left: 0px;'>
    </div>
  )HTML");

  auto cull_rect = GetCullRect("target").Rect();
  EXPECT_TRUE(cull_rect.Contains(gfx::Rect(0, 0, 200, 300)));
}

TEST_F(CullRectUpdaterTest, LayerOffscreenFarCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                position: absolute; top: 9000px'>
    </div>
  )HTML");

  // The layer is too far away from the viewport.
  EXPECT_FALSE(
      GetCullRect("target").Rect().Intersects(gfx::Rect(0, 0, 200, 300)));
}

TEST_F(CullRectUpdaterTest, ScrollingLayerCullRect) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div::-webkit-scrollbar { width: 5px; }
    </style>
    <div style='width: 200px; height: 200px; overflow: scroll;
                background: blue'>
      <div id='target'
           style='width: 100px; height: 10000px; position: relative'>
      </div>
    </div>
  )HTML");

  // In screen space, the scroller is (8, 8, 195, 193) (because of overflow clip
  // of 'target', scrollbar and root margin).
  // Applying the viewport clip of the root has no effect because
  // the clip is already small. Mapping it down into the graphics layer
  // space yields (0, 0, 195, 193). This is then expanded by 4000px and clipped
  // by the contents rect.
  EXPECT_EQ(gfx::Rect(0, 0, 195, 4193), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, NonCompositedScrollingLayerCullRect) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <style>
      div::-webkit-scrollbar { width: 5px; }
    </style>
    <div style='width: 200px; height: 200px; overflow: scroll'>
      <div id='target'
           style='width: 100px; height: 10000px; position: relative'>
      </div>
    </div>
  )HTML");

  // See ScrollingLayerCullRect for the calculation.
  EXPECT_EQ(gfx::Rect(0, 0, 195, 4193), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, ClippedBigLayer) {
  SetBodyInnerHTML(R"HTML(
    <div style='width: 1px; height: 1px; overflow: hidden'>
      <div id='target'
           style='width: 10000px; height: 10000px; position: relative'>
      </div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(8, 8, 1, 1), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, TallScrolledLayerCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width: 200px; height: 12000px; position: relative'>
    </div>
  )HTML");

  // Viewport rect (0, 0, 800, 600) expanded by 4000 for scrolling then clipped
  // by the contents rect.
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetCullRect("target").Rect());

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 4000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 800, 8600), GetCullRect("target").Rect());

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 4500), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  // Used the previous cull rect because the scroll amount is small.
  EXPECT_EQ(gfx::Rect(0, 0, 800, 8600), GetCullRect("target").Rect());

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 4600), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  // Used new cull rect.
  EXPECT_EQ(gfx::Rect(0, 600, 800, 8600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, WholeDocumentCullRect) {
  SetPreferCompositingToLCDText(true);
  GetDocument().GetSettings()->SetMainFrameClipsContent(false);
  SetBodyInnerHTML(R"HTML(
    <style>
      div { background: blue; }
      ::-webkit-scrollbar { display: none; }
    </style>
    <div id='relative'
         style='width: 200px; height: 10000px; position: relative'>
    </div>
    <div id='fixed' style='width: 200px; height: 200px; position: fixed'>
    </div>
    <div id='scroll' style='width: 200px; height: 200px; overflow: scroll'>
      <div id='below-scroll' style='height: 5000px; position: relative'></div>
      <div style='height: 200px'>Should not paint</div>
    </div>
    <div id='normal' style='width: 200px; height: 200px'></div>
  )HTML");

  // Viewport clipping is disabled.
  EXPECT_TRUE(GetCullRect(*GetLayoutView().Layer()).IsInfinite());
  EXPECT_TRUE(GetCullRect("relative").IsInfinite());
  EXPECT_TRUE(GetCullRect("fixed").IsInfinite());
  EXPECT_TRUE(GetCullRect("scroll").IsInfinite());

  // Cull rect is normal for contents below scroll other than the viewport.
  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetCullRect("below-scroll").Rect());

  EXPECT_EQ(7u, ContentDisplayItems().size());
}

TEST_F(CullRectUpdaterTest, FixedPositionUnderClipPath) {
  GetDocument().View()->Resize(800, 600);
  SetBodyInnerHTML(R"HTML(
    <div style="height: 100vh"></div>
    <div style="width: 100px; height: 100px; clip-path: inset(0 0 0 0)">
      <div id="fixed" style="position: fixed; top: 0; left: 0; width: 1000px;
                             height: 1000px"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect("fixed").Rect());

  GetDocument().GetFrame()->DomWindow()->scrollTo(0, 1000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect("fixed").Rect());

  GetDocument().View()->Resize(800, 1000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 800, 1000), GetCullRect("fixed").Rect());
}

TEST_F(CullRectUpdaterTest, FixedPositionUnderClipPathWillChangeTransform) {
  GetDocument().View()->Resize(800, 600);
  SetBodyInnerHTML(R"HTML(
    <div style="height: 100vh"></div>
    <div style="width: 100px; height: 100px; clip-path: inset(0 0 0 0)">
      <div id="fixed" style="position: fixed; top: 0; left: 0; width: 1000px;
                             height: 1000px; will-change: transform"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(-4000, -4000, 8800, 8600), GetCullRect("fixed").Rect());

  GetDocument().GetFrame()->DomWindow()->scrollTo(0, 1000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(-4000, -4000, 8800, 8600), GetCullRect("fixed").Rect());

  GetDocument().View()->Resize(800, 2000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(-4000, -4000, 8800, 10000), GetCullRect("fixed").Rect());
}

TEST_F(CullRectUpdaterTest, AbsolutePositionUnderNonContainingStackingContext) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 200px; height: 200px; overflow: auto;
                              position: relative">
      <div style="height: 0; overflow: hidden; opacity: 0.5; margin: 250px">
        <div id="absolute"
             style="width: 100px; height: 100px; position: absolute;
                    background: green"></div>
      </div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 500, 500), GetCullRect("absolute").Rect());

  GetDocument().getElementById(AtomicString("scroller"))->scrollTo(200, 200);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 500, 500), GetCullRect("absolute").Rect());
}

TEST_F(CullRectUpdaterTest, StackedChildOfNonStackingContextScroller) {
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 200px; height: 200px; overflow: auto;
                              background: white">
      <div id="child" style="height: 7000px; position: relative"></div>
    </div>
  )HTML");

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));

  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetCullRect("child").Rect());

  for (int i = 1000; i < 7000; i += 1000) {
    scroller->scrollTo(0, i);
    UpdateAllLifecyclePhasesForTest();
  }
  // When scrolled to 3800, the cull rect covers the whole scrolling contents.
  // Then we use this full cull rect on further scroll to avoid repaint.
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetCullRect("child").Rect());

  // The full cull rect still applies when the scroller scrolls to the top.
  scroller->scrollTo(0, 0);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetCullRect("child").Rect());

  // CullRectUpdater won't update |child|'s cull rect even it needs repaint
  // because its container's cull rect doesn't change.
  GetPaintLayerByElementId("child")->SetNeedsRepaint();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetCullRect("child").Rect());

  // Setting |scroller| needs repaint will lead to proactive update for it,
  // and for |child| because |scroller|'s cull rect changes.
  GetPaintLayerByElementId("scroller")->SetNeedsRepaint();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetCullRect("child").Rect());
}

TEST_F(CullRectUpdaterTest, ContentsCullRectCoveringWholeContentsRect) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 400px; height: 400px; overflow: scroll">
      <div style="height: 7000px"></div>
      <div id="child" style="will-change: transform; height: 20px"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 400, 4400), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 4400), GetCullRect("child").Rect());

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->scrollTo(0, 2500);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 400, 6900), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 6900), GetCullRect("child").Rect());

  scroller->scrollTo(0, 2800);
  UpdateAllLifecyclePhasesForTest();
  // Cull rects are not updated with a small scroll delta.
  EXPECT_EQ(gfx::Rect(0, 0, 400, 6900), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 6900), GetCullRect("child").Rect());

  scroller->scrollTo(0, 3100);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 400, 7020), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 7020), GetCullRect("child").Rect());

  // We will use the same cull rects that cover the whole contents on further
  // scroll.
  scroller->scrollTo(0, 4000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 400, 7020), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 7020), GetCullRect("child").Rect());

  scroller->scrollTo(0, 0);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 400, 7020), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 7020), GetCullRect("child").Rect());
}

TEST_F(CullRectUpdaterTest, SVGForeignObject) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 100px; height: 100px; overflow: scroll">
      <svg id="svg" style="width: 100px;
### 提示词
```
这是目录为blink/renderer/core/paint/cull_rect_updater_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"

namespace blink {

class CullRectUpdaterTest : public PaintControllerPaintTestBase {
 protected:
  CullRect GetCullRect(const char* id) {
    return GetLayoutObjectByElementId(id)->FirstFragment().GetCullRect();
  }

  CullRect GetCullRect(const PaintLayer& layer) {
    return layer.GetLayoutObject().FirstFragment().GetCullRect();
  }

  CullRect GetContentsCullRect(const char* id) {
    return GetLayoutObjectByElementId(id)
        ->FirstFragment()
        .GetContentsCullRect();
  }

  CullRect GetContentsCullRect(const PaintLayer& layer) {
    return layer.GetLayoutObject().FirstFragment().GetContentsCullRect();
  }
};

TEST_F(CullRectUpdaterTest, SimpleCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 200px; position: relative'>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, TallLayerCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 10000px; position: relative'>
    </div>
  )HTML");

  // Viewport rect (0, 0, 800, 600) expanded by 4000 for scrolling then clipped
  // by the contents rect.
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, WideLayerCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 10000px; height: 200px; position: relative'>
    </div>
  )HTML");

  // Same as TallLayerCullRect.
  EXPECT_EQ(gfx::Rect(0, 0, 4800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, VerticalRLWritingModeDocument) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { writing-mode: vertical-rl; }
      body { margin: 0; }
    </style>
    <div id='target' style='width: 10000px; height: 200px; position: relative'>
    </div>
  )HTML");

  GetDocument().domWindow()->scrollTo(-5000, 0);
  UpdateAllLifecyclePhasesForTest();

  // A scroll by -5000px is equivalent to a scroll by (10000 - 5000 - 800)px =
  // 4200px in non-RTL mode. Expanding the resulting rect by 4000px in each
  // direction and clipping by the contents rect yields this result.
  EXPECT_EQ(gfx::Rect(200, 0, 8800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, VerticalRLWritingModeScrollDiv) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { writing-mode: vertical-rl; }
    </style>
    <div id="scroller" style="width: 200px; height: 200px; overflow: scroll;
                              background: white">
      <div style="width: 10000px; height: 200px"></div>
    </div>
  )HTML");

  GetDocument().getElementById(AtomicString("scroller"))->scrollTo(-5000, 0);
  UpdateAllLifecyclePhasesForTest();

  // Similar to the previous test case.
  EXPECT_EQ(gfx::Rect(800, 0, 8200, 200),
            GetContentsCullRect("scroller").Rect());
}

TEST_F(CullRectUpdaterTest, ScaledCullRect) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                transform: scaleX(2) scaleY(0.75); transform-origin: 0 0'>
    </div>
  )HTML");

  // The expansion is 4000 / max(scaleX, scaleY).
  EXPECT_EQ(gfx::Rect(-2000, -2000, 4400, 4800), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, ScaledCullRectUnderCompositedScroller) {
  SetBodyInnerHTML(R"HTML(
    <div style='width: 200px; height: 300px; overflow: scroll; background: blue;
                transform: scaleX(2) scaleY(0.75); transform-origin: 0 0'>
      <div id='target' style='height: 400px; position: relative'></div>
      <div style='width: 10000px; height: 9600px'></div>
    </div>
  )HTML");

  // The expansion is calculated based on 4000 / max(scaleX, scaleY).
  EXPECT_EQ(gfx::Rect(0, 0, 1224, 1324), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, ScaledAndRotatedCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                transform: scaleX(3) scaleY(0.5) rotateZ(45deg)'>
    </div>
  )HTML");

  // The expansion 6599 is 4000 * max_dimension(1x1 rect projected from screen
  // to local).
  EXPECT_EQ(gfx::Rect(-6748, -6836, 14236, 14236),
            GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, ScaledAndRotatedCullRectUnderCompositedScroller) {
  SetBodyInnerHTML(R"HTML(
    <div style='width: 200px; height: 300px; overflow: scroll; background: blue;
                transform: scaleX(3) scaleY(0.5) rotateZ(45deg)'>
      <div id='target' style='height: 400px; position: relative;
               will-change: transform'></div>
      <div style='width: 10000px; height: 10000px'></div>
    </div>
  )HTML");

  // The expansion 6599 is 4000 * max_dimension(1x1 rect projected from screen
  // to local).
  EXPECT_EQ(gfx::Rect(-6599, -6599, 16697, 16797),
            GetCullRect("target").Rect());
  EXPECT_EQ(gfx::Rect(-6599, -6599, 16697, 16797),
            GetContentsCullRect("target").Rect());
}

// This is a testcase for https://crbug.com/1227907 where repeated cull rect
// updates are expensive on the motionmark microbenchmark.
TEST_F(CullRectUpdaterTest, OptimizeNonCompositedTransformUpdate) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        width: 50px;
        height: 50px;
        background: green;
        transform: translate(-8px, -8px);
      }
    </style>
    <div id='target'></div>
  )HTML");

  // The cull rect should be correctly calculated on first paint.
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect("target").Rect());

  // On subsequent paints, fall back to an infinite cull rect.
  GetDocument()
      .getElementById(AtomicString("target"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("transform: rotate(10deg);"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(GetCullRect("target").IsInfinite());
}

TEST_F(CullRectUpdaterTest, 3DRotated90DegreesCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                transform: rotateY(90deg)'>
    </div>
  )HTML");

  EXPECT_TRUE(GetCullRect("target").Rect().Contains(gfx::Rect(0, 0, 200, 300)));
}

TEST_F(CullRectUpdaterTest, 3DRotatedNear90DegreesCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                transform: rotateY(89.9999deg)'>
    </div>
  )HTML");

  EXPECT_TRUE(GetCullRect("target").Rect().Contains(gfx::Rect(0, 0, 200, 300)));
}

TEST_F(CullRectUpdaterTest, PerspectiveCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id=target style='transform: perspective(1000px) rotateX(-100deg);'>
      <div style='width: 2000px; height: 3000px></div>
    </div>
  )HTML");

  EXPECT_TRUE(
      GetCullRect("target").Rect().Contains(gfx::Rect(0, 0, 2000, 3000)));
}

TEST_F(CullRectUpdaterTest, 3D60DegRotatedTallCullRect) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id='target'
         style='width: 200px; height: 10000px; transform: rotateY(60deg)'>
    </div>
  )HTML");

  // The cull rect is expanded in the y direction for the root scroller, and
  // x direction for |target| itself.
  EXPECT_EQ(gfx::Rect(-4100, 0, 9600, 4600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, FixedPositionInNonScrollableViewCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width: 1000px; height: 2000px;
                            position: fixed; top: 100px; left: 200px;'>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(-200, -100, 800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, FixedPositionInScrollableViewCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width: 1000px; height: 2000px;
                            position: fixed; top: 100px; left: 200px;'>
    </div>
    <div style='height: 3000px'></div>
  )HTML");

  EXPECT_EQ(gfx::Rect(-200, -100, 800, 600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, LayerOffscreenNearCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                position: absolute; top: 3000px; left: 0px;'>
    </div>
  )HTML");

  auto cull_rect = GetCullRect("target").Rect();
  EXPECT_TRUE(cull_rect.Contains(gfx::Rect(0, 0, 200, 300)));
}

TEST_F(CullRectUpdaterTest, LayerOffscreenFarCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
         style='width: 200px; height: 300px; will-change: transform;
                position: absolute; top: 9000px'>
    </div>
  )HTML");

  // The layer is too far away from the viewport.
  EXPECT_FALSE(
      GetCullRect("target").Rect().Intersects(gfx::Rect(0, 0, 200, 300)));
}

TEST_F(CullRectUpdaterTest, ScrollingLayerCullRect) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div::-webkit-scrollbar { width: 5px; }
    </style>
    <div style='width: 200px; height: 200px; overflow: scroll;
                background: blue'>
      <div id='target'
           style='width: 100px; height: 10000px; position: relative'>
      </div>
    </div>
  )HTML");

  // In screen space, the scroller is (8, 8, 195, 193) (because of overflow clip
  // of 'target', scrollbar and root margin).
  // Applying the viewport clip of the root has no effect because
  // the clip is already small. Mapping it down into the graphics layer
  // space yields (0, 0, 195, 193). This is then expanded by 4000px and clipped
  // by the contents rect.
  EXPECT_EQ(gfx::Rect(0, 0, 195, 4193), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, NonCompositedScrollingLayerCullRect) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <style>
      div::-webkit-scrollbar { width: 5px; }
    </style>
    <div style='width: 200px; height: 200px; overflow: scroll'>
      <div id='target'
           style='width: 100px; height: 10000px; position: relative'>
      </div>
    </div>
  )HTML");

  // See ScrollingLayerCullRect for the calculation.
  EXPECT_EQ(gfx::Rect(0, 0, 195, 4193), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, ClippedBigLayer) {
  SetBodyInnerHTML(R"HTML(
    <div style='width: 1px; height: 1px; overflow: hidden'>
      <div id='target'
           style='width: 10000px; height: 10000px; position: relative'>
      </div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(8, 8, 1, 1), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, TallScrolledLayerCullRect) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width: 200px; height: 12000px; position: relative'>
    </div>
  )HTML");

  // Viewport rect (0, 0, 800, 600) expanded by 4000 for scrolling then clipped
  // by the contents rect.
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetCullRect("target").Rect());

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 4000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 800, 8600), GetCullRect("target").Rect());

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 4500), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  // Used the previous cull rect because the scroll amount is small.
  EXPECT_EQ(gfx::Rect(0, 0, 800, 8600), GetCullRect("target").Rect());

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 4600), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  // Used new cull rect.
  EXPECT_EQ(gfx::Rect(0, 600, 800, 8600), GetCullRect("target").Rect());
}

TEST_F(CullRectUpdaterTest, WholeDocumentCullRect) {
  SetPreferCompositingToLCDText(true);
  GetDocument().GetSettings()->SetMainFrameClipsContent(false);
  SetBodyInnerHTML(R"HTML(
    <style>
      div { background: blue; }
      ::-webkit-scrollbar { display: none; }
    </style>
    <div id='relative'
         style='width: 200px; height: 10000px; position: relative'>
    </div>
    <div id='fixed' style='width: 200px; height: 200px; position: fixed'>
    </div>
    <div id='scroll' style='width: 200px; height: 200px; overflow: scroll'>
      <div id='below-scroll' style='height: 5000px; position: relative'></div>
      <div style='height: 200px'>Should not paint</div>
    </div>
    <div id='normal' style='width: 200px; height: 200px'></div>
  )HTML");

  // Viewport clipping is disabled.
  EXPECT_TRUE(GetCullRect(*GetLayoutView().Layer()).IsInfinite());
  EXPECT_TRUE(GetCullRect("relative").IsInfinite());
  EXPECT_TRUE(GetCullRect("fixed").IsInfinite());
  EXPECT_TRUE(GetCullRect("scroll").IsInfinite());

  // Cull rect is normal for contents below scroll other than the viewport.
  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetCullRect("below-scroll").Rect());

  EXPECT_EQ(7u, ContentDisplayItems().size());
}

TEST_F(CullRectUpdaterTest, FixedPositionUnderClipPath) {
  GetDocument().View()->Resize(800, 600);
  SetBodyInnerHTML(R"HTML(
    <div style="height: 100vh"></div>
    <div style="width: 100px; height: 100px; clip-path: inset(0 0 0 0)">
      <div id="fixed" style="position: fixed; top: 0; left: 0; width: 1000px;
                             height: 1000px"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect("fixed").Rect());

  GetDocument().GetFrame()->DomWindow()->scrollTo(0, 1000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect("fixed").Rect());

  GetDocument().View()->Resize(800, 1000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 800, 1000), GetCullRect("fixed").Rect());
}

TEST_F(CullRectUpdaterTest, FixedPositionUnderClipPathWillChangeTransform) {
  GetDocument().View()->Resize(800, 600);
  SetBodyInnerHTML(R"HTML(
    <div style="height: 100vh"></div>
    <div style="width: 100px; height: 100px; clip-path: inset(0 0 0 0)">
      <div id="fixed" style="position: fixed; top: 0; left: 0; width: 1000px;
                             height: 1000px; will-change: transform"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(-4000, -4000, 8800, 8600), GetCullRect("fixed").Rect());

  GetDocument().GetFrame()->DomWindow()->scrollTo(0, 1000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(-4000, -4000, 8800, 8600), GetCullRect("fixed").Rect());

  GetDocument().View()->Resize(800, 2000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(-4000, -4000, 8800, 10000), GetCullRect("fixed").Rect());
}

TEST_F(CullRectUpdaterTest, AbsolutePositionUnderNonContainingStackingContext) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 200px; height: 200px; overflow: auto;
                              position: relative">
      <div style="height: 0; overflow: hidden; opacity: 0.5; margin: 250px">
        <div id="absolute"
             style="width: 100px; height: 100px; position: absolute;
                    background: green"></div>
      </div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 500, 500), GetCullRect("absolute").Rect());

  GetDocument().getElementById(AtomicString("scroller"))->scrollTo(200, 200);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 500, 500), GetCullRect("absolute").Rect());
}

TEST_F(CullRectUpdaterTest, StackedChildOfNonStackingContextScroller) {
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 200px; height: 200px; overflow: auto;
                              background: white">
      <div id="child" style="height: 7000px; position: relative"></div>
    </div>
  )HTML");

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));

  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetCullRect("child").Rect());

  for (int i = 1000; i < 7000; i += 1000) {
    scroller->scrollTo(0, i);
    UpdateAllLifecyclePhasesForTest();
  }
  // When scrolled to 3800, the cull rect covers the whole scrolling contents.
  // Then we use this full cull rect on further scroll to avoid repaint.
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetCullRect("child").Rect());

  // The full cull rect still applies when the scroller scrolls to the top.
  scroller->scrollTo(0, 0);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetCullRect("child").Rect());

  // CullRectUpdater won't update |child|'s cull rect even it needs repaint
  // because its container's cull rect doesn't change.
  GetPaintLayerByElementId("child")->SetNeedsRepaint();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 7000), GetCullRect("child").Rect());

  // Setting |scroller| needs repaint will lead to proactive update for it,
  // and for |child| because |scroller|'s cull rect changes.
  GetPaintLayerByElementId("scroller")->SetNeedsRepaint();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 200, 4200), GetCullRect("child").Rect());
}

TEST_F(CullRectUpdaterTest, ContentsCullRectCoveringWholeContentsRect) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 400px; height: 400px; overflow: scroll">
      <div style="height: 7000px"></div>
      <div id="child" style="will-change: transform; height: 20px"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 400, 4400), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 4400), GetCullRect("child").Rect());

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->scrollTo(0, 2500);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 400, 6900), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 6900), GetCullRect("child").Rect());

  scroller->scrollTo(0, 2800);
  UpdateAllLifecyclePhasesForTest();
  // Cull rects are not updated with a small scroll delta.
  EXPECT_EQ(gfx::Rect(0, 0, 400, 6900), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 6900), GetCullRect("child").Rect());

  scroller->scrollTo(0, 3100);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 400, 7020), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 7020), GetCullRect("child").Rect());

  // We will use the same cull rects that cover the whole contents on further
  // scroll.
  scroller->scrollTo(0, 4000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 400, 7020), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 7020), GetCullRect("child").Rect());

  scroller->scrollTo(0, 0);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 400, 7020), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -7000, 8400, 7020), GetCullRect("child").Rect());
}

TEST_F(CullRectUpdaterTest, SVGForeignObject) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 100px; height: 100px; overflow: scroll">
      <svg id="svg" style="width: 100px; height: 4000px">
        <foreignObject id="foreign" style="width: 500px; height: 1000px">
          <div id="child" style="position: relative">Child</div>
        </foreignObject>
      </svg>
    </div>
  )HTML");

  auto* child = GetPaintLayerByElementId("child");
  auto* foreign = GetPaintLayerByElementId("foreign");
  auto* svg = GetPaintLayerByElementId("svg");
  EXPECT_FALSE(child->NeedsCullRectUpdate());
  EXPECT_FALSE(foreign->DescendantNeedsCullRectUpdate());
  EXPECT_FALSE(svg->DescendantNeedsCullRectUpdate());

  GetDocument().getElementById(AtomicString("scroller"))->scrollTo(0, 500);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(child->NeedsCullRectUpdate());
  EXPECT_FALSE(foreign->DescendantNeedsCullRectUpdate());
  EXPECT_FALSE(svg->DescendantNeedsCullRectUpdate());

  child->SetNeedsCullRectUpdate();
  EXPECT_TRUE(child->NeedsCullRectUpdate());
  EXPECT_TRUE(foreign->DescendantNeedsCullRectUpdate());
  EXPECT_TRUE(svg->DescendantNeedsCullRectUpdate());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(child->NeedsCullRectUpdate());
  EXPECT_FALSE(foreign->DescendantNeedsCullRectUpdate());
  EXPECT_FALSE(svg->DescendantNeedsCullRectUpdate());
}

TEST_F(CullRectUpdaterTest, LayerUnderSVGHiddenContainer) {
  SetBodyInnerHTML(R"HTML(
    <div id="div" style="display: contents">
      <svg id="svg1"></svg>
    </div>
    <svg id="svg2">
      <defs id="defs"/>
    </svg>
  )HTML");

  EXPECT_FALSE(GetCullRect("svg1").Rect().IsEmpty());

  GetDocument()
      .getElementById(AtomicString("defs"))
      ->appendChild(GetDocument().getElementById(AtomicString("div")));
  // This should not crash.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetLayoutObjectByElementId("svg1"));
}

TEST_F(CullRectUpdaterTest, PerspectiveDescendants) {
  SetBodyInnerHTML(R"HTML(
    <div style="perspective: 1000px">
      <div style="height: 300px; transform-style: preserve-3d; contain: strict">
        <div id="target" style="transform: rotateX(20deg)">TARGET</div>
      </div>
    </div>
  )HTML");
  EXPECT_TRUE(GetCullRect("target").IsInfinite());
}

// Test case for crbug.com/1382842.
TEST_F(CullRectUpdaterTest, UpdateOnCompositedScrollingStatusChange) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <style>body {position: absolute}</style>
    <div id="scroller" style="width: 100px; height: 100px;
                              overflow: auto; position: relative">
      <div style="height: 1000px">TEXT</div>
    <div>
  )HTML");

  EXPECT_EQ(gfx::Rect(100, 1000), GetContentsCullRect("scroller").Rect());

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->SetInlineStyleProperty(CSSPropertyID::kBackgroundColor, "yellow");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(100, 1000), GetContentsCullRect("scroller").Rect());

  scroller->RemoveInlineStyleProperty(CSSPropertyID::kBackgroundColor);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(100, 1000), GetContentsCullRect("scroller").Rect());
}

TEST_F(CullRectUpdaterTest, StickyPositionInCompositedScroller) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 300px; height: 300px; overflow: scroll">
      <div style="height: 600px"></div>
      <div id="sticky1" style="position: sticky; top: 10px; height: 50px"></div>
      <div id="clipper" style="overflow: clip; height: 200px">
        <div style="height: 300px"></div>
        <div id="sticky2" style="position: sticky; bottom: 0; height: 50px">
        </div>
      </div>
      <div style="height: 10000px"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 300, 4300), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -600, 8300, 4300), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4000, 8300, 8200), GetCullRect("sticky2").Rect());

  // Cull rects should be updated when the scroller has scrolled enough (on the
  // 2nd and the 4th scrolls, but not in the 1st and the 3rd scrolls). `sticky2`
  // always uses expanded cull rect from the contents cull rect of the
  // additional clip.
  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->scrollBy(0, 300);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 300, 4300), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -600, 8300, 4300), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4000, 8300, 8200), GetCullRect("sticky2").Rect());

  scroller->scrollBy(0, 300);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 300, 4900), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -610, 8300, 4900), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4200, 8300, 8200), GetCullRect("sticky2").Rect());

  scroller->scrollBy(0, 300);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 300, 4900), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -610, 8300, 4900), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4200, 8300, 8200), GetCullRect("sticky2").Rect());

  scroller->scrollBy(0, 300);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 300, 5500), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -1210, 8300, 5500), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4300, 8300, 8200), GetCullRect("sticky2").Rect());

  scroller->scrollBy(0, 6000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 3200, 300, 7650),
            GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4010, 8300, 7650), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(), GetCullRect("sticky2").Rect());
}

TEST_F(CullRectUpdaterTest, StickyPositionInNonCompositedScroller) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width: 300px; height: 300px; overflow: scroll">
      <div style="height: 600px"></div>
      <div id="sticky1" style="position: sticky; top: 10px; height: 50px"></div>
      <div id="clipper" style="overflow: clip; height: 200px">
        <div style="height: 300px"></div>
        <div id="sticky2" style="position: sticky; bottom: 0; height: 50px">
        </div>
      </div>
      <div style="height: 10000px"></div>
    </div>
  )HTML");

  EXPECT_EQ(gfx::Rect(0, 0, 300, 4300), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -600, 8300, 4300), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4000, 8300, 8200), GetCullRect("sticky2").Rect());

  // All cull rects should be updated on each non-composited scroll.
  // We always composite and expand cull rect for sticky elements regardless
  // whether the scroller is composited.
  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->scrollBy(0, 300);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 300, 4300), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -600, 8300, 4300), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4000, 8300, 8200), GetCullRect("sticky2").Rect());

  scroller->scrollBy(0, 300);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 300, 4900), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -610, 8300, 4900), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4200, 8300, 8200), GetCullRect("sticky2").Rect());

  scroller->scrollBy(0, 300);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 300, 4900), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -610, 8300, 4900), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4200, 8300, 8200), GetCullRect("sticky2").Rect());

  scroller->scrollBy(0, 300);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 300, 5500), GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -1210, 8300, 5500), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4300, 8300, 8200), GetCullRect("sticky2").Rect());

  scroller->scrollBy(0, 6000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 3200, 300, 7650),
            GetContentsCullRect("scroller").Rect());
  EXPECT_EQ(gfx::Rect(-4000, -4010, 8300, 7650), GetCullRect("sticky1").Rect());
  EXPECT_EQ(gfx::Rect(), GetCullRect("sticky2").Rect());
}

TEST_F(CullRectUpdaterTest, NestedOverriddenCullRectScopes) {
  SetBodyInnerHTML(R"HTML(
    <div id="div1" style="contain: paint; height: 100px"></div>
    <div id="div2" style="contain: paint; height: 100px"></div>
  )HTML");

  auto& layer1 = *GetPaintLayerByElementId("div1");
  auto& layer2 = *GetPaintLayerByElementId("div2");
  CullRect cull_rect1 = GetCullRect(layer1);
  CullRect cull_rect2 = GetCullRect(layer2);
  CullRect special_cull_rect1(gfx::Rect(12, 34, 56, 78));
  CullRect special_cull_rect2(gfx::Rect(87, 65, 43, 21));
  const bool disable_expansion = false;

  {
    OverriddenCullRectScope scope1(layer1, cull_rect1, disable_expansion);
    {
      OverriddenCullRectScope scope2(layer2, cull_rect2, disable_expansion);
      EXPECT_EQ(cull_rect2, GetCullRect(layer2));
    }
    EXPECT_EQ(cull_rect1, GetCullRect(layer1));
  }
  EXPECT_EQ(cull_rect1, GetCullRect(layer1));
  EXPECT_EQ(cull_rect2, GetCullRect(layer2));

  {
    OverriddenCullRectScope scope1(layer1, special_cull_rect1,
                                   disable_expansion);
    {
      OverriddenCullRectScope scope2(layer2, cull_rect2, disable_expansion);
      EXPECT_EQ(cull_rect2, GetCullRect(layer2));
    }
    EXPECT_EQ(special_cull_rect1, GetCullRect(layer1));
  }
  EXPECT_EQ(cull_rect1, GetCullRect(layer1));
  EXPECT_EQ(cull_rect2, GetCullRect(layer2));

  {
    OverriddenCullRectScope scope1(layer1, cull_rect1, disable_expansion);
    {
      OverriddenCullRectScope scope2(layer2, special_cull_rect2,
                                     disable_expansion);
      EXPECT_EQ(special_cull_rect2, GetCullRect(layer2));
    }
    EXPECT_EQ(cull_rect1, GetCullRect(layer1));
  }
  EXPECT_EQ(cull_rect1, GetCullRect(layer1));
  EXPECT_EQ(cull_rect2, GetCullRect(layer2));

  {
    OverriddenCullRectScope scope1(layer1, special_cull_rect1,
                                   disable_expansion);
    {
      OverriddenCullRectScope scope2(layer2, special_cull_rect2,
                                     disable_expansion);
      EXPECT_EQ(special_cull_rect2, GetCullRect(layer2));
    }
    EXPECT_EQ(special_cull_rect1, GetCullRect(layer1));
  }
  EXPECT_EQ(cull_rect1, GetCullRect(layer1));
  EXPECT_EQ(cull_rect2, GetCullRect(layer2));
}

TEST_F(CullRectUpdaterTest, OverriddenCullRectWithoutExpansion) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id="clip" style="width: 300px; height: 300px; overflow: hidden">
      <div id="scroller" style="width: 1000px; height: 1000px;
                                overflow: scroll; will-change: scroll-position">
        <div style="width: 2000px; height: 2000px"></div>
      <div>
    </div>
  )HTML");

  auto& clip = *GetPaintLayerByElementId("clip");
  auto& scroller = *GetPaintLayerByElementId("scroller");
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect(clip).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 300), GetContentsCullRect(clip).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 300), GetCullRect(scroller).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 1300, 1300), GetContentsCullRect(scroller).Rect());

  {
    const bool disable_expansion = true;
    OverriddenCullRectScope scope(*GetLayoutView().Layer(),
                                  CullRect(gfx::Rect(100, 100, 400, 400)),
                                  disable_expansion);
    EXPECT_EQ(gfx::Rect(100, 100, 400, 400), GetCullRect(clip).Rect());
    EXPECT_EQ(gfx::Rect(100, 100, 200, 200), GetContentsCullRect(clip).Rect());
    EXPECT_EQ(gfx::Rect(100, 100, 200, 200), GetCullRect(scroller).Rect());
    EXPECT_EQ(gfx::Rect(100, 100, 200, 200),
              GetContentsCullRect(scroller).Rect());
  }

  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), GetCullRect(clip).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 300), GetContentsCullRect(clip).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 300), GetCullRect(scroller).Rect());
  EXPECT_EQ(gfx::Rect(0, 0, 1300, 1300), GetContentsCullRect(scroller).Rect());
}

TEST_F(CullRectUpdaterTest, LimitedDynamicCullRectExpansionY) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id="clip" style="width: 300px; height: 300px; overflow: hidden">
      <div id="scroller" style="width: 1000px; height: 1000px;
                                overflow: scroll; will-change: scroll-position">
        <div style="width: 1000px; height: 2000px"></div>
      <div>
    </div>
  )HTML");

  auto& clip = *GetPaintLayerByE
```