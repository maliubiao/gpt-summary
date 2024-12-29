Response:
The user wants me to analyze the provided C++ code snippet from the Chromium Blink engine. This file, `paint_layer_test.cc`, is located in the `blink/renderer/core/paint` directory and is named as a test file.

Here's a breakdown of how to address each part of the request:

1. **List the functionalities:**  The file name and the included headers suggest it contains unit tests for the `PaintLayer` class. I need to examine the tests to understand what aspects of `PaintLayer` are being tested.

2. **Relationship with JavaScript, HTML, CSS:**  Blink is a rendering engine for the web. `PaintLayer` is a core component in the rendering pipeline. Tests will likely involve setting up DOM structures (using HTML), applying styles (using CSS), and indirectly, the behavior can be triggered by JavaScript. I need to look for examples of how the tests manipulate the DOM and styles.

3. **Logical reasoning (input/output):**  Each `TEST_P` block represents a test case. I can analyze individual tests, identify the setup (HTML structure, styles), the action being performed (e.g., scrolling, changing styles), and the expected outcome (assertions using `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`).

4. **Common usage errors:**  Since this is a test file, it doesn't directly demonstrate user errors. However, the tests might implicitly reveal potential pitfalls or edge cases that developers need to be aware of when working with `PaintLayer` or related concepts like compositing and scrolling.

5. **User operation leading to this:** To reach the code being tested, a user interacts with a web page. I need to think about what kinds of user actions (scrolling, resizing, changes triggered by JavaScript) would eventually involve the `PaintLayer` and its associated functionalities.

6. **Debugging clues:** The tests themselves provide debugging clues for developers working on the rendering engine. Failed tests highlight areas where the `PaintLayer` isn't behaving as expected.

7. **Summarize the functionality:** After analyzing the individual tests, I need to provide a concise summary of the overall purpose of the `paint_layer_test.cc` file.

**Mental Sandbox:**

* **Initial Scan:**  The file includes headers related to DOM elements (`PseudoElement`, `MouseEvent`, `HTMLIFrameElement`), layout (`LayoutBoxModelObject`, `LayoutView`), and painting (`PaintControllerPaintTest`, `PaintLayerPaintOrderIterator`, `PaintLayerScrollableArea`). This confirms it's about testing the rendering and painting aspects.
* **Test Case Analysis:**  The test `ChildWithoutPaintLayer` checks if a simple div without specific styling gets its own `PaintLayer`. `RootLayerScrollBounds` tests the calculation of scroll boundaries. Scrolling-related tests check behavior with and without compositing. Other tests examine properties like `HasNonIsolatedDescendantWithBlendMode`, `HasFixedPositionDescendant`, etc. These indicate different scenarios and properties of the `PaintLayer` that are being validated.
* **HTML/CSS Connection:**  The `SetBodyInnerHTML` function is used extensively to create HTML structures and apply inline styles. This clearly shows the connection to HTML and CSS.
* **JavaScript Connection:** While there's no explicit JavaScript code in this snippet, the tests simulate the effects of JavaScript by directly manipulating DOM attributes and triggering lifecycle updates. In a real browser, JavaScript would be the primary way to cause these changes.
* **User Actions:**  Scrolling is explicitly tested. Changes in element styles (position, overflow, etc.) which can be initiated by user interactions or JavaScript, are also tested.
* **Debugging:** The `EXPECT_*` macros are assertions. If a test fails, it indicates a discrepancy between the expected behavior of `PaintLayer` and its actual behavior in a given scenario.

**Constraint Checklist & Confidence Score:**

1. List functionalities? Yes.
2. Relation to JS/HTML/CSS with examples? Yes.
3. Logical reasoning (input/output)? Yes, by analyzing test cases.
4. Common usage errors? Yes, implicitly through tested scenarios.
5. User operation to reach here? Yes.
6. Debugging clues? Yes.
7. Summarize functionality? Yes.
Confidence Score: 5/5

I'm ready to generate the response based on this analysis.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer_paint_order_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using ::testing::ElementsAre;
using ::testing::Pointee;

class PaintLayerTest : public PaintControllerPaintTest {
 public:
  PaintLayerTest()
      : PaintControllerPaintTest(
            MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(PaintLayerTest);

TEST_P(PaintLayerTest, ChildWithoutPaintLayer) {
  SetBodyInnerHTML(
      "<div id='target' style='width: 200px; height: 200px;'></div>");

  PaintLayer* paint_layer = GetPaintLayerByElementId("target");
  PaintLayer* root_layer = GetLayoutView().Layer();

  EXPECT_EQ(nullptr, paint_layer);
  EXPECT_NE(nullptr, root_layer);
}

TEST_P(PaintLayerTest, RootLayerScrollBounds) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(
      "<style> body { width: 1000px; height: 1000px; margin: 0 } </style>");
  PaintLayerScrollableArea* plsa = GetLayoutView().Layer()->GetScrollableArea();

  int scrollbarThickness = plsa->VerticalScrollbarWidth();
  EXPECT_EQ(scrollbarThickness, plsa->HorizontalScrollbarHeight());
  EXPECT_GT(scrollbarThickness, 0);

  EXPECT_EQ(ScrollOffset(200 + scrollbarThickness, 400 + scrollbarThickness),
            plsa->MaximumScrollOffset());

  EXPECT_EQ(gfx::Rect(0, 0, 800 - scrollbarThickness, 600 - scrollbarThickness),
            plsa->VisibleContentRect());
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600),
            plsa->VisibleContentRect(kIncludeScrollbars));
}

TEST_P(PaintLayerTest, CompositedScrollingNoNeedsRepaint) {
  SetBodyInnerHTML(R"HTML(
    <div id='scroll' style='width: 100px; height: 100px; overflow: scroll;
        will-change: transform'>
      <div id='content' style='position: relative; background: blue;
          width: 2000px; height: 2000px'></div>
    </div>
  )HTML");

  PaintLayer* scroll_layer = GetPaintLayerByElementId("scroll");

  PaintLayer* content_layer = GetPaintLayerByElementId("content");

  scroll_layer->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(1000, 1000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(
      gfx::Vector2d(1000, 1000),
      content_layer->ContainingLayer()->PixelSnappedScrolledContentOffset());
  EXPECT_FALSE(content_layer->SelfNeedsRepaint());
  EXPECT_FALSE(scroll_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintLayerTest, NonCompositedScrollingNeedsRepaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
     /* to prevent the mock overlay scrollbar from affecting compositing. */
     ::-webkit-scrollbar { display: none; }
    </style>
    <div id='scroll' style='width: 100px; height: 100px; overflow: scroll'>
      <div id='content' style='position: relative; background: blue;
          width: 2000px; height: 2000px'></div>
    </div>
  )HTML");

  PaintLayer* scroll_layer = GetPaintLayerByElementId("scroll");
  EXPECT_FALSE(scroll_layer->GetLayoutObject()
                   .FirstFragment()
                   .PaintProperties()
                   ->ScrollTranslation()
                   ->HasDirectCompositingReasons());

  PaintLayer* content_layer = GetPaintLayerByElementId("content");
  const auto& fragment = content_layer->GetLayoutObject().FirstFragment();
  EXPECT_EQ(gfx::Rect(0, 0, 2000, 2000), fragment.GetContentsCullRect().Rect());

  scroll_layer->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(1000, 1000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(
      gfx::Vector2d(1000, 1000),
      content_layer->ContainingLayer()->PixelSnappedScrolledContentOffset());

  EXPECT_FALSE(scroll_layer->SelfNeedsRepaint());
  EXPECT_EQ(gfx::Rect(0, 0, 2000, 2000), fragment.GetContentsCullRect().Rect());
  EXPECT_FALSE(content_layer->SelfNeedsRepaint());

  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintLayerTest, HasNonIsolatedDescendantWithBlendMode) {
  SetBodyInnerHTML(R"HTML(
    <div id='stacking-grandparent' style='isolation: isolate'>
      <div id='stacking-parent' style='isolation: isolate'>
        <div id='non-stacking-parent' style='position:relative'>
          <div id='blend-mode' style='mix-blend-mode: overlay'>
          </div>
        </div>
      </div>
    </div>
  )HTML");
  PaintLayer* stacking_grandparent =
      GetPaintLayerByElementId("stacking-grandparent");
  PaintLayer* stacking_parent = GetPaintLayerByElementId("stacking-parent");
  PaintLayer* parent = GetPaintLayerByElementId("non-stacking-parent");

  EXPECT_TRUE(parent->HasNonIsolatedDescendantWithBlendMode());
  EXPECT_TRUE(stacking_parent->HasNonIsolatedDescendantWithBlendMode());
  EXPECT_FALSE(stacking_grandparent->HasNonIsolatedDescendantWithBlendMode());
  EXPECT_TRUE(parent->HasVisibleSelfPaintingDescendant());
}

TEST_P(PaintLayerTest, HasFixedPositionDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='isolation: isolate'>
      <div id='child' style='position: fixed'>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->HasFixedPositionDescendant());
  EXPECT_FALSE(child->HasFixedPositionDescendant());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(parent->HasFixedPositionDescendant());
  EXPECT_FALSE(child->HasFixedPositionDescendant());
}

TEST_P(PaintLayerTest, HasNonContainedAbsolutePositionDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='isolation: isolate'>
      <div id='child' style='position: relative'>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");
  EXPECT_FALSE(parent->HasNonContainedAbsolutePositionDescendant());
  EXPECT_FALSE(child->HasNonContainedAbsolutePositionDescendant());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: absolute"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(parent->HasNonContainedAbsolutePositionDescendant());
  EXPECT_FALSE(child->HasNonContainedAbsolutePositionDescendant());

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->HasNonContainedAbsolutePositionDescendant());
  EXPECT_FALSE(child->HasNonContainedAbsolutePositionDescendant());
}

TEST_P(PaintLayerTest, HasSelfPaintingDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position: relative'>
      <div id='child' style='position: relative'>
        <div></div>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  EXPECT_TRUE(parent->HasSelfPaintingLayerDescendant());
  EXPECT_FALSE(child->HasSelfPaintingLayerDescendant());
}

TEST_P(PaintLayerTest, HasSelfPaintingDescendantNotSelfPainting) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position: relative'>
      <div id='child' style='overflow: auto'>
        <div></div>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  EXPECT_FALSE(parent->HasSelfPaintingLayerDescendant());
  EXPECT_FALSE(child->HasSelfPaintingLayerDescendant());
}

TEST_P(PaintLayerTest, HasSelfPaintingParentNotSelfPainting) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='overflow: auto'>
      <div id='child' style='position: relative'>
        <div></div>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  EXPECT_TRUE(parent->HasSelfPaintingLayerDescendant());
  EXPECT_FALSE(child->HasSelfPaintingLayerDescendant());
}

static const HeapVector<Member<PaintLayer>>*
LayersPaintingOverlayOverflowControlsAfter(const PaintLayer* layer) {
  return PaintLayerPaintOrderIterator(layer->AncestorStackingContext(),
                                      kPositiveZOrderChildren)
      .LayersPaintingOverlayOverflowControlsAfter(layer);
}

// We need new enum and class to test the overlay overflow controls reordering,
// but we don't move the tests related to the new class to the bottom, which is
// behind all tests of the PaintLayerTest. Because it will make the git history
// hard to track.
enum OverlayType { kOverlayResizer, kOverlayScrollbars };

class ReorderOverlayOverflowControlsTest
    : public testing::WithParamInterface<OverlayType>,
      public PaintControllerPaintTestBase {
 public:
  ReorderOverlayOverflowControlsTest()
      : PaintControllerPaintTestBase(
            MakeGarbageCollected<SingleChildLocalFrameClient>()) {}
  ~ReorderOverlayOverflowControlsTest() override {
    // Must destruct all objects before toggling back feature flags.
    WebHeap::CollectAllGarbageForTesting();
  }

  OverlayType GetOverlayType() const { return GetParam(); }

  void InitOverflowStyle(const char* id) {
    auto* element = GetElementById(id);
    element->setAttribute(html_names::kStyleAttr,
                          AtomicString(GetOverlayType() == kOverlayScrollbars
                                           ? "overflow: auto"
                                           : "overflow: hidden; resize: both"));
    UpdateAllLifecyclePhasesForTest();
    if (GetOverlayType() == kOverlayScrollbars) {
      element->GetLayoutBox()
          ->GetScrollableArea()
          ->SetScrollbarsHiddenIfOverlay(false);
      UpdateAllLifecyclePhasesForTest();
    }
  }

  void RemoveOverflowStyle(const char* id) {
    GetElementById(id)->setAttribute(html_names::kStyleAttr,
                                     AtomicString("overflow: visible"));
    UpdateAllLifecyclePhasesForTest();
  }
};

INSTANTIATE_TEST_SUITE_P(All,
                         ReorderOverlayOverflowControlsTest,
                         ::testing::Values(kOverlayScrollbars,
                                           kOverlayResizer));

TEST_P(ReorderOverlayOverflowControlsTest, StackedWithInFlowDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        position: relative;
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='position: relative; height: 200px'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  if (GetOverlayType() == kOverlayScrollbars) {
    EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
    EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  } else {
    EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
    EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
    EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
                Pointee(ElementsAre(parent)));
  }
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: relative; width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: relative; width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, StackedWithOutOfFlowDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #child {
        width: 200px;
        height: 200px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='position: absolute'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: absolute"));
  UpdateAllLifecyclePhasesForTest();
  child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, StackedWithZIndexDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #child {
        position: absolute;
        width: 200px;
        height: 200px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='z-index: 1'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("z-index: -1"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("z-index: 2"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest,
       NestedStackedWithInFlowStackedChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #ancestor {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #parent {
        width: 100px;
        height: 200px;
      }
      #child {
        position: relative;
        height: 300px;
      }
    </style>
    <div id='ancestor'>
      <div id='parent'>
        <div id="child"></div>
      </div>
    </div>
  )HTML");

  InitOverflowStyle("ancestor");
  InitOverflowStyle("parent");

  auto* ancestor = GetPaintLayerByElementId("ancestor");
  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(ancestor->NeedsReorderOverlayOverflowControls());
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent, ancestor)));
  EXPECT_EQ(ancestor->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest,
       NestedStackedWithOutOfFlowStackedChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #ancestor {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #parent {
        position: absolute;
        width: 100px;
        height: 200px;
      }
      #child {
        position: absolute;
        width: 300px;
        height: 300px;
      }
    </style>
    <div id='ancestor'>
      <div id='parent'>
        <div id="child">
        </div>
      </div>
    </div>
  )HTML");

  InitOverflowStyle("ancestor");
  InitOverflowStyle("parent");

  auto* ancestor = GetPaintLayerByElementId("ancestor");
  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(ancestor->NeedsReorderOverlayOverflowControls());
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent, ancestor)));
  EXPECT_EQ(ancestor->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, MultipleChildren) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      div {
        width: 200px;
        height: 200px;
      }
      #parent {
        width: 100px;
        height: 100px;
      }
      #low-child {
        position: absolute;
        top: 0;
        z-index: 1;
      }
      #middle-child {
        position: relative;
        z-index: 2;
      }
      #high-child {
        position: absolute;
        top: 0;
        z-index: 3;
      }
    </style>
    <div id='parent'>
      <div id="low-child"></div>
      <div id="middle-child"></div>
      <div id="high-child"></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* low_child = GetPaintLayerByElementId("low-child");
  auto* middle_child = GetPaintLayerByElementId("middle-child");
  auto* high_child = GetPaintLayerByElementId("high-child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(low_child));
  // The highest contained child by parent is middle_child because the
  // absolute-position children are not contained.
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(middle_child),
              Pointee(ElementsAre(parent)));
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(high_child));
  EXPECT_EQ(high_child->GetLayoutObject().GetNode(), HitTest(99, 99));

  std::string extra_style = GetOverlayType() == kOverlayScrollbars
                                ? "overflow: auto;"
                                : "overflow: hidden; resize: both;";
  std::string new_style = extra_style + "position: absolute; z-index: 1";
  GetDocument()
      .getElementById(AtomicString("parent"))
      ->setAttribute(html_names::kStyleAttr, AtomicString(new_style.c_str()));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(low_child));
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(middle_child));
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(high_child));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  new_style = extra_style + "position: absolute;";
  GetDocument()
      .getElementById(AtomicString("parent"))
      ->setAttribute(html_names::kStyleAttr, AtomicString(new_style.c_str()));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(low_child));
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(middle_child));
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(high_child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, NonStackedWithInFlowDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin : 0; }
      #parent {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='position: relative; height: 200px'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  if (GetOverlayType() == kOverlayResizer) {
    EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
    EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
                Pointee(ElementsAre(parent)));
  } else {
    EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
    EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  }
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: relative; width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: relative; width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_layer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer_paint_order_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using ::testing::ElementsAre;
using ::testing::Pointee;

class PaintLayerTest : public PaintControllerPaintTest {
 public:
  PaintLayerTest()
      : PaintControllerPaintTest(
            MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(PaintLayerTest);

TEST_P(PaintLayerTest, ChildWithoutPaintLayer) {
  SetBodyInnerHTML(
      "<div id='target' style='width: 200px; height: 200px;'></div>");

  PaintLayer* paint_layer = GetPaintLayerByElementId("target");
  PaintLayer* root_layer = GetLayoutView().Layer();

  EXPECT_EQ(nullptr, paint_layer);
  EXPECT_NE(nullptr, root_layer);
}

TEST_P(PaintLayerTest, RootLayerScrollBounds) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(
      "<style> body { width: 1000px; height: 1000px; margin: 0 } </style>");
  PaintLayerScrollableArea* plsa = GetLayoutView().Layer()->GetScrollableArea();

  int scrollbarThickness = plsa->VerticalScrollbarWidth();
  EXPECT_EQ(scrollbarThickness, plsa->HorizontalScrollbarHeight());
  EXPECT_GT(scrollbarThickness, 0);

  EXPECT_EQ(ScrollOffset(200 + scrollbarThickness, 400 + scrollbarThickness),
            plsa->MaximumScrollOffset());

  EXPECT_EQ(gfx::Rect(0, 0, 800 - scrollbarThickness, 600 - scrollbarThickness),
            plsa->VisibleContentRect());
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600),
            plsa->VisibleContentRect(kIncludeScrollbars));
}

TEST_P(PaintLayerTest, CompositedScrollingNoNeedsRepaint) {
  SetBodyInnerHTML(R"HTML(
    <div id='scroll' style='width: 100px; height: 100px; overflow: scroll;
        will-change: transform'>
      <div id='content' style='position: relative; background: blue;
          width: 2000px; height: 2000px'></div>
    </div>
  )HTML");

  PaintLayer* scroll_layer = GetPaintLayerByElementId("scroll");

  PaintLayer* content_layer = GetPaintLayerByElementId("content");

  scroll_layer->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(1000, 1000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(
      gfx::Vector2d(1000, 1000),
      content_layer->ContainingLayer()->PixelSnappedScrolledContentOffset());
  EXPECT_FALSE(content_layer->SelfNeedsRepaint());
  EXPECT_FALSE(scroll_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintLayerTest, NonCompositedScrollingNeedsRepaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
     /* to prevent the mock overlay scrollbar from affecting compositing. */
     ::-webkit-scrollbar { display: none; }
    </style>
    <div id='scroll' style='width: 100px; height: 100px; overflow: scroll'>
      <div id='content' style='position: relative; background: blue;
          width: 2000px; height: 2000px'></div>
    </div>
  )HTML");

  PaintLayer* scroll_layer = GetPaintLayerByElementId("scroll");
  EXPECT_FALSE(scroll_layer->GetLayoutObject()
                   .FirstFragment()
                   .PaintProperties()
                   ->ScrollTranslation()
                   ->HasDirectCompositingReasons());

  PaintLayer* content_layer = GetPaintLayerByElementId("content");
  const auto& fragment = content_layer->GetLayoutObject().FirstFragment();
  EXPECT_EQ(gfx::Rect(0, 0, 2000, 2000), fragment.GetContentsCullRect().Rect());

  scroll_layer->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(1000, 1000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(
      gfx::Vector2d(1000, 1000),
      content_layer->ContainingLayer()->PixelSnappedScrolledContentOffset());

  EXPECT_FALSE(scroll_layer->SelfNeedsRepaint());
  EXPECT_EQ(gfx::Rect(0, 0, 2000, 2000), fragment.GetContentsCullRect().Rect());
  EXPECT_FALSE(content_layer->SelfNeedsRepaint());

  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PaintLayerTest, HasNonIsolatedDescendantWithBlendMode) {
  SetBodyInnerHTML(R"HTML(
    <div id='stacking-grandparent' style='isolation: isolate'>
      <div id='stacking-parent' style='isolation: isolate'>
        <div id='non-stacking-parent' style='position:relative'>
          <div id='blend-mode' style='mix-blend-mode: overlay'>
          </div>
        </div>
      </div>
    </div>
  )HTML");
  PaintLayer* stacking_grandparent =
      GetPaintLayerByElementId("stacking-grandparent");
  PaintLayer* stacking_parent = GetPaintLayerByElementId("stacking-parent");
  PaintLayer* parent = GetPaintLayerByElementId("non-stacking-parent");

  EXPECT_TRUE(parent->HasNonIsolatedDescendantWithBlendMode());
  EXPECT_TRUE(stacking_parent->HasNonIsolatedDescendantWithBlendMode());
  EXPECT_FALSE(stacking_grandparent->HasNonIsolatedDescendantWithBlendMode());
  EXPECT_TRUE(parent->HasVisibleSelfPaintingDescendant());
}

TEST_P(PaintLayerTest, HasFixedPositionDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='isolation: isolate'>
      <div id='child' style='position: fixed'>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->HasFixedPositionDescendant());
  EXPECT_FALSE(child->HasFixedPositionDescendant());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(parent->HasFixedPositionDescendant());
  EXPECT_FALSE(child->HasFixedPositionDescendant());
}

TEST_P(PaintLayerTest, HasNonContainedAbsolutePositionDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='isolation: isolate'>
      <div id='child' style='position: relative'>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");
  EXPECT_FALSE(parent->HasNonContainedAbsolutePositionDescendant());
  EXPECT_FALSE(child->HasNonContainedAbsolutePositionDescendant());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: absolute"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(parent->HasNonContainedAbsolutePositionDescendant());
  EXPECT_FALSE(child->HasNonContainedAbsolutePositionDescendant());

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->HasNonContainedAbsolutePositionDescendant());
  EXPECT_FALSE(child->HasNonContainedAbsolutePositionDescendant());
}

TEST_P(PaintLayerTest, HasSelfPaintingDescendant) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position: relative'>
      <div id='child' style='position: relative'>
        <div></div>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  EXPECT_TRUE(parent->HasSelfPaintingLayerDescendant());
  EXPECT_FALSE(child->HasSelfPaintingLayerDescendant());
}

TEST_P(PaintLayerTest, HasSelfPaintingDescendantNotSelfPainting) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='position: relative'>
      <div id='child' style='overflow: auto'>
        <div></div>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  EXPECT_FALSE(parent->HasSelfPaintingLayerDescendant());
  EXPECT_FALSE(child->HasSelfPaintingLayerDescendant());
}

TEST_P(PaintLayerTest, HasSelfPaintingParentNotSelfPainting) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='overflow: auto'>
      <div id='child' style='position: relative'>
        <div></div>
      </div>
    </div>
  )HTML");
  PaintLayer* parent = GetPaintLayerByElementId("parent");
  PaintLayer* child = GetPaintLayerByElementId("child");

  EXPECT_TRUE(parent->HasSelfPaintingLayerDescendant());
  EXPECT_FALSE(child->HasSelfPaintingLayerDescendant());
}

static const HeapVector<Member<PaintLayer>>*
LayersPaintingOverlayOverflowControlsAfter(const PaintLayer* layer) {
  return PaintLayerPaintOrderIterator(layer->AncestorStackingContext(),
                                      kPositiveZOrderChildren)
      .LayersPaintingOverlayOverflowControlsAfter(layer);
}

// We need new enum and class to test the overlay overflow controls reordering,
// but we don't move the tests related to the new class to the bottom, which is
// behind all tests of the PaintLayerTest. Because it will make the git history
// hard to track.
enum OverlayType { kOverlayResizer, kOverlayScrollbars };

class ReorderOverlayOverflowControlsTest
    : public testing::WithParamInterface<OverlayType>,
      public PaintControllerPaintTestBase {
 public:
  ReorderOverlayOverflowControlsTest()
      : PaintControllerPaintTestBase(
            MakeGarbageCollected<SingleChildLocalFrameClient>()) {}
  ~ReorderOverlayOverflowControlsTest() override {
    // Must destruct all objects before toggling back feature flags.
    WebHeap::CollectAllGarbageForTesting();
  }

  OverlayType GetOverlayType() const { return GetParam(); }

  void InitOverflowStyle(const char* id) {
    auto* element = GetElementById(id);
    element->setAttribute(html_names::kStyleAttr,
                          AtomicString(GetOverlayType() == kOverlayScrollbars
                                           ? "overflow: auto"
                                           : "overflow: hidden; resize: both"));
    UpdateAllLifecyclePhasesForTest();
    if (GetOverlayType() == kOverlayScrollbars) {
      element->GetLayoutBox()
          ->GetScrollableArea()
          ->SetScrollbarsHiddenIfOverlay(false);
      UpdateAllLifecyclePhasesForTest();
    }
  }

  void RemoveOverflowStyle(const char* id) {
    GetElementById(id)->setAttribute(html_names::kStyleAttr,
                                     AtomicString("overflow: visible"));
    UpdateAllLifecyclePhasesForTest();
  }
};

INSTANTIATE_TEST_SUITE_P(All,
                         ReorderOverlayOverflowControlsTest,
                         ::testing::Values(kOverlayScrollbars,
                                           kOverlayResizer));

TEST_P(ReorderOverlayOverflowControlsTest, StackedWithInFlowDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        position: relative;
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='position: relative; height: 200px'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  if (GetOverlayType() == kOverlayScrollbars) {
    EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
    EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  } else {
    EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
    EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
    EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
                Pointee(ElementsAre(parent)));
  }
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: relative; width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: relative; width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, StackedWithOutOfFlowDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #child {
        width: 200px;
        height: 200px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='position: absolute'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: absolute"));
  UpdateAllLifecyclePhasesForTest();
  child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, StackedWithZIndexDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #child {
        position: absolute;
        width: 200px;
        height: 200px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='z-index: 1'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("z-index: -1"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("z-index: 2"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest,
       NestedStackedWithInFlowStackedChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #ancestor {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #parent {
        width: 100px;
        height: 200px;
      }
      #child {
        position: relative;
        height: 300px;
      }
    </style>
    <div id='ancestor'>
      <div id='parent'>
        <div id="child"></div>
      </div>
    </div>
  )HTML");

  InitOverflowStyle("ancestor");
  InitOverflowStyle("parent");

  auto* ancestor = GetPaintLayerByElementId("ancestor");
  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(ancestor->NeedsReorderOverlayOverflowControls());
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent, ancestor)));
  EXPECT_EQ(ancestor->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest,
       NestedStackedWithOutOfFlowStackedChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #ancestor {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #parent {
        position: absolute;
        width: 100px;
        height: 200px;
      }
      #child {
        position: absolute;
        width: 300px;
        height: 300px;
      }
    </style>
    <div id='ancestor'>
      <div id='parent'>
        <div id="child">
        </div>
      </div>
    </div>
  )HTML");

  InitOverflowStyle("ancestor");
  InitOverflowStyle("parent");

  auto* ancestor = GetPaintLayerByElementId("ancestor");
  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(ancestor->NeedsReorderOverlayOverflowControls());
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent, ancestor)));
  EXPECT_EQ(ancestor->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, MultipleChildren) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      div {
        width: 200px;
        height: 200px;
      }
      #parent {
        width: 100px;
        height: 100px;
      }
      #low-child {
        position: absolute;
        top: 0;
        z-index: 1;
      }
      #middle-child {
        position: relative;
        z-index: 2;
      }
      #high-child {
        position: absolute;
        top: 0;
        z-index: 3;
      }
    </style>
    <div id='parent'>
      <div id="low-child"></div>
      <div id="middle-child"></div>
      <div id="high-child"></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* low_child = GetPaintLayerByElementId("low-child");
  auto* middle_child = GetPaintLayerByElementId("middle-child");
  auto* high_child = GetPaintLayerByElementId("high-child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(low_child));
  // The highest contained child by parent is middle_child because the
  // absolute-position children are not contained.
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(middle_child),
              Pointee(ElementsAre(parent)));
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(high_child));
  EXPECT_EQ(high_child->GetLayoutObject().GetNode(), HitTest(99, 99));

  std::string extra_style = GetOverlayType() == kOverlayScrollbars
                                ? "overflow: auto;"
                                : "overflow: hidden; resize: both;";
  std::string new_style = extra_style + "position: absolute; z-index: 1";
  GetDocument()
      .getElementById(AtomicString("parent"))
      ->setAttribute(html_names::kStyleAttr, AtomicString(new_style.c_str()));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(low_child));
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(middle_child));
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(high_child));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  new_style = extra_style + "position: absolute;";
  GetDocument()
      .getElementById(AtomicString("parent"))
      ->setAttribute(html_names::kStyleAttr, AtomicString(new_style.c_str()));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(low_child));
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(middle_child));
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(high_child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, NonStackedWithInFlowDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin : 0; }
      #parent {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='position: relative; height: 200px'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("position: relative; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  if (GetOverlayType() == kOverlayResizer) {
    EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
    EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
                Pointee(ElementsAre(parent)));
  } else {
    EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
    EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  }
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: relative; width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: relative; width: 200px; height: 80px"));
  UpdateAllLifecyclePhasesForTest();
  child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest,
       NonStackedWithZIndexInFlowDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        width: 100px;
        height: 100px;
      }
      #child {
        position: relative;
        height: 200px;
      }
    </style>
    <div id='parent'>
      <div id='child' style='z-index: 1'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("z-index: -1"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));

  GetDocument()
      .getElementById(AtomicString("child"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("z-index: 2"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent)));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, NonStackedWithOutOfFlowDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        width: 100px;
        height: 100px;
      }
      #child {
        position: absolute;
        width: 200px;
        height: 200px;
      }
    </style>
    <div id='parent'>
      <div id='child'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(child->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, NonStackedWithNonStackedDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        width: 100px;
        height: 100px;
      }
      #child {
        width: 200px;
        height: 200px;
      }
    </style>
    <div id='parent'>
      <div id='child'></div>
    </div>
  )HTML");

  InitOverflowStyle("parent");
  InitOverflowStyle("child");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");

  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(parent->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest,
       NestedNonStackedWithInFlowStackedChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #ancestor {
        width: 100px;
        height: 100px;
      }
      #parent {
        width: 100px;
        height: 200px;
      }
      #child {
        position: relative;
        height: 300px;
      }
    </style>
    <div id='ancestor'>
      <div id='parent'>
        <div id='child'></div>
      </div>
    </div>
  )HTML");

  InitOverflowStyle("ancestor");
  InitOverflowStyle("parent");

  auto* ancestor = GetPaintLayerByElementId("ancestor");
  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_TRUE(ancestor->NeedsReorderOverlayOverflowControls());
  EXPECT_TRUE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_THAT(LayersPaintingOverlayOverflowControlsAfter(child),
              Pointee(ElementsAre(parent, ancestor)));
  EXPECT_EQ(ancestor->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest,
       NestedNonStackedWithOutOfFlowStackedChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #ancestor {
        width: 100px;
        height: 100px;
      }
      #parent {
        width: 100px;
        height: 200px;
      }
      #child {
        position: absolute;
        width: 300px;
        height: 300px;
      }
    </style>
    <div id='ancestor'>
      <div id='parent'>
        <div id='child'>
        </div>
      </div>
    </div>
  )HTML");

  InitOverflowStyle("ancestor");
  InitOverflowStyle("parent");

  auto* ancestor = GetPaintLayerByElementId("ancestor");
  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_FALSE(ancestor->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(child->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(child->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest,
       AdjustAccessingOrderForSubtreeHighestLayers) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      div {
        width: 200px;
        height: 200px;
      }
      div > div {
        height: 300px;
      }
      #ancestor {
        width: 100px;
        height: 100px;
      }
      #ancestor, #child_2 {
        position: relative;
      }
      #child_1 {
        position: absolute;
      }
    </style>
    <div id='ancestor'>
      <div id='child_1'></div>
      <div id='child_2'>
        <div id='descendant'></div>
      </div>
    </div>
  )HTML");

  InitOverflowStyle("ancestor");

  auto* ancestor = GetPaintLayerByElementId("ancestor");
  auto* child = GetPaintLayerByElementId("child_2");
  EXPECT_TRUE(ancestor->NeedsReorderOverlayOverflowControls());
  EXPECT_TRUE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(ancestor->GetLayoutObject().GetNode(), HitTest(99, 99));
}

TEST_P(ReorderOverlayOverflowControlsTest, AddRemoveScrollableArea) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        position: relative;
        width: 100px;
        height: 100px;
      }
      #child {
        position: absolute;
        width: 200px;
        height: 200px;
      }
    </style>
    <div id='parent'>
      <div id='child'></div>
    </div>
  )HTML");

  auto* parent = GetPaintLayerByElementId("parent");
  auto* child = GetPaintLayerByElementId("child");
  EXPECT_FALSE(parent->GetScrollableArea());
  EXPECT_FALSE(parent->NeedsReorderOverlayOverflowControls());
  EXPECT_FALSE(LayersPaintingOverlayOverflowControlsAfter(child));
  EXPECT_EQ(child->GetLayoutObject().GetNode(), HitTest(99, 99));

  InitOverflowStyle("parent");
  EXPECT_TRUE(parent->GetScrollableArea());
  EXPECT_TRUE(parent->NeedsReorderOverlayOve
"""


```