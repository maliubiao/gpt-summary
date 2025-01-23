Response:
Let's break down the thought process to analyze the provided C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the test file, its relationship to web technologies, logical reasoning (if any), common user/programming errors it might catch, and how a user might trigger the code being tested.

2. **Identify the Core Class:** The filename `pre_paint_tree_walk_test.cc` and the `TEST_P(PrePaintTreeWalkTest, ...)` macros immediately point to the central class being tested: `PrePaintTreeWalk`. The namespace `blink` confirms this is part of the Blink rendering engine.

3. **Analyze the Includes:** The included headers provide valuable clues:
    * `pre_paint_tree_walk.h`: This is the header file for the class being tested, so the tests are about its behavior.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates the use of Google Test framework for unit testing.
    * `renderer/core/dom/...`, `renderer/core/frame/...`, `renderer/core/layout/...`, `renderer/core/paint/...`: These point to the core areas of the Blink rendering engine that `PrePaintTreeWalk` interacts with. Specifically, `layout` and `paint` are key.
    * `platform/graphics/paint/...`:  Shows interaction with the graphics and painting parts of the platform layer.

4. **Examine the `PrePaintTreeWalkTest` Class:**
    * It inherits from `PaintControllerPaintTest`, suggesting it's a test fixture focused on paint-related functionality.
    * `FramePreTranslation()` and `FrameScrollTranslation()`: These methods access properties related to the main frame's transformation and scrolling. This hints at tests involving frame-level transformations and scrolling.
    * `SetUp()`: Enables compositing, indicating tests likely involve composited layers.

5. **Analyze Individual Tests (the `TEST_P` blocks):** For each test, identify the setup, the action, and the assertion:

    * **`PropertyTreesRebuiltWithBorderInvalidation`:**
        * **Setup:** Creates a styled `div` with a `transform`.
        * **Action:** Artificially clears the transform property, then adds a border (causing a paint invalidation).
        * **Assertion:** Checks if the transform property is correctly restored after the update. This tests if changes triggering a repaint correctly rebuild the paint property trees.

    * **`PropertyTreesRebuiltWithFrameScroll`:**
        * **Setup:** Creates a tall body to enable scrolling.
        * **Action:** Programmatically scrolls the document.
        * **Assertion:** Checks if the frame's scroll translation property is updated correctly.

    * **`PropertyTreesRebuiltWithCSSTransformInvalidation`:**
        * **Setup:** Creates a `div` with `will-change: transform` and initially one transform class.
        * **Action:** Changes the class, applying a different transform.
        * **Assertion:** Checks if the transform property reflects the new CSS rule.

    * **`PropertyTreesRebuiltWithOpacityInvalidation`:** Similar to the transform test, but for the `opacity` property.

    * **`ClearSubsequenceCachingClipChange`, `ClearSubsequenceCachingClipChange2DTransform`, `ClearSubsequenceCachingClipChangePosAbs`, `ClearSubsequenceCachingClipChangePosFixed`:**
        * **Setup:**  Sets up nested `div` elements, one with `isolation: isolate` (important for paint invalidation boundaries).
        * **Action:** Adds a CSS class that introduces `overflow: hidden` on a parent.
        * **Assertion:** Checks if a descendant paint layer needs repaint. These tests focus on how changes to clipping contexts propagate invalidations. Notice the variations test different scenarios like 2D transforms and absolute/fixed positioning.

    * **`ClipChangeRepaintsDescendants`:**  Tests if a change to a parent's height (affecting clipping) triggers a repaint in a distant descendant.

    * **`ClipChangeHasRadius`:**  Tests if adding `border-radius` triggers a repaint, and importantly, *doesn't* cause a crash.

    * **`InsideBlockingTouchEventHandlerUpdate`:**
        * **Setup:** Creates nested divs.
        * **Action:** Attaches a touchstart event listener.
        * **Assertion:** Checks flags related to blocking touch event handlers on the elements in the hierarchy. This tests if Blink correctly identifies elements involved in blocking touch events.

    * **`EffectiveTouchActionStyleUpdate`:** Tests how applying a `touch-action` style affects related flags on elements.

    * **`InsideBlockingWheelEventHandlerUpdate`:** Similar to the touch event handler test, but for wheel events.

    * **`CullRectUpdateOnSVGTransformChange`:**
        * **Setup:** Creates an SVG structure with a `foreignObject`.
        * **Action:** Applies transforms to SVG elements.
        * **Assertion:** Checks if the cull rect of the `foreignObject` is updated correctly.

    * **`InlineOutlineWithContinuationPaintInvalidation`:**
        * **Setup:** Creates an inline element with an outline and a continuation (block-level child).
        * **Action:** Changes a style on an inner inline element.
        * **Assertion:** Primarily checks for crashes, ensuring paint invalidation with continuations works correctly.

    * **`ScrollTranslationNodeForNonZeroScrollPosition`:** Tests if a scroll translation node is created even when the scroll position is initially non-zero (due to RTL layout). It also tests scrolling to the end of content.

6. **Synthesize the Functionality:** Based on the individual test analysis, the file's main function is to test the `PrePaintTreeWalk` class, which is responsible for traversing the render tree before painting to update paint properties and identify what needs repainting.

7. **Relate to Web Technologies (JavaScript, HTML, CSS):** Connect the test cases to how changes in these technologies trigger repaints and affect paint properties. For example:
    * **HTML:** Changing attributes (`class`, `style`) triggers layout and paint updates.
    * **CSS:** Changes to CSS properties (`transform`, `opacity`, `border`, `overflow`, `touch-action`, `outline`) are central to the tests.
    * **JavaScript:**  `scrollTo()` is used to simulate user scrolling. Adding event listeners in JavaScript directly impacts event handling logic tested here.

8. **Identify Logical Reasoning:** While these are tests, there's implicit logic being tested. For instance, when a parent's `overflow` changes, the `PrePaintTreeWalk` logic should correctly identify which descendants need repainting due to the changed clipping.

9. **Consider User/Programming Errors:** Think about what mistakes developers might make that these tests would catch. For example, a bug in the `PrePaintTreeWalk` logic might:
    * Fail to update paint properties correctly after a style change.
    * Incorrectly determine which elements need repainting, leading to visual glitches or performance issues.
    * Crash in specific scenarios involving complex layouts or paint invalidations.

10. **Trace User Operations:** Imagine the steps a user would take to cause the tested scenarios. For example:
    * **Scrolling:** The user scrolls the webpage.
    * **CSS Changes:**  JavaScript dynamically modifies CSS classes or styles.
    * **Interactions:** The user interacts with elements that have touch or wheel event listeners.

11. **Structure the Answer:** Organize the findings logically, starting with the overall functionality and then diving into specifics, examples, and potential errors. Use clear language and provide concrete examples where possible.
This C++ source code file, `pre_paint_tree_walk_test.cc`, is a **unit test file** for the Blink rendering engine. Specifically, it tests the functionality of the `PrePaintTreeWalk` class.

Here's a breakdown of its functions and relationships:

**Core Functionality:**

The primary goal of these tests is to verify that the `PrePaintTreeWalk` class correctly updates and maintains the **paint property trees** in response to various changes in the DOM, CSS, and user interactions. The `PrePaintTreeWalk` is a crucial step in the rendering pipeline, occurring before the actual painting of elements. It analyzes the layout tree and determines the necessary paint properties (like transforms, clips, effects) for each element.

**Relationship to JavaScript, HTML, and CSS:**

This test file is heavily intertwined with JavaScript, HTML, and CSS, as these are the fundamental technologies that define the structure, style, and behavior of web pages that Blink renders. The tests simulate scenarios where changes in these technologies trigger updates in the rendering pipeline.

**Examples:**

* **CSS Transform Changes:**
    * **HTML:** `<div id='transformed' class='transformA'></div>`
    * **CSS:**
        ```css
        .transformA { transform: translate(100px, 100px); }
        .transformB { transform: translate(200px, 200px); }
        #transformed { will-change: transform; }
        ```
    * **JavaScript (simulated in the test):**  `transformed_element->setAttribute(html_names::kClassAttr, AtomicString("transformB"));`
    * **Test:** The `PropertyTreesRebuiltWithCSSTransformInvalidation` test verifies that when the CSS `transform` property changes, the `PrePaintTreeWalk` correctly updates the `TransformPaintPropertyNode` for the affected element.

* **CSS Opacity Changes:**
    * **HTML:** `<div id='transparent' class='opacityA'></div>`
    * **CSS:**
        ```css
        .opacityA { opacity: 0.9; }
        .opacityB { opacity: 0.4; }
        ```
    * **JavaScript (simulated in the test):** `transparent_element->setAttribute(html_names::kClassAttr, AtomicString("opacityB"));`
    * **Test:** The `PropertyTreesRebuiltWithOpacityInvalidation` test checks if changes to the CSS `opacity` property lead to the correct update of the `EffectPaintPropertyNode`.

* **Scroll Changes:**
    * **HTML:** `<style> body { height: 10000px; } </style>` (creates a scrollable document)
    * **JavaScript (simulated in the test):** `GetDocument().domWindow()->scrollTo(0, 100);`
    * **Test:** The `PropertyTreesRebuiltWithFrameScroll` test ensures that when the user scrolls the page, the `PrePaintTreeWalk` updates the `ScrollPaintPropertyNode` for the frame.

* **Changes to Clipping:**
    * **HTML:**
        ```html
        <div id='parent' style='transform: translateZ(0); width: 100px; height: 100px;'>
          <div id='child' style='isolation: isolate'>content</div>
        </div>
        ```
    * **CSS (added dynamically in the test):** `.clip { overflow: hidden }`
    * **JavaScript (simulated in the test):** `parent->setAttribute(html_names::kClassAttr, AtomicString("clip"));`
    * **Test:** Tests like `ClearSubsequenceCachingClipChange` verify that adding `overflow: hidden` (which creates a new clipping context) triggers necessary repaints on descendant elements.

* **Event Handlers (Touch and Wheel):**
    * **HTML:**  Simple divs.
    * **JavaScript (simulated in the test):** `handler_element->addEventListener(event_type_names::kTouchstart, callback);`
    * **Test:** The `InsideBlockingTouchEventHandlerUpdate` and `InsideBlockingWheelEventHandlerUpdate` tests check how the presence of blocking touch and wheel event handlers affects flags during the pre-paint tree walk. This is important for optimizing input handling and preventing jank.

**Logical Reasoning with Assumptions and Outputs:**

Let's take the `PropertyTreesRebuiltWithBorderInvalidation` test as an example of logical reasoning:

* **Assumption (Input):** An HTML element has a CSS `transform` applied to it.
* **Action:**
    1. The transform property node is initially checked.
    2. The transform property node is artificially cleared.
    3. An attribute change (adding a `border`) is triggered, causing a paint invalidation and thus running the `PrePaintTreeWalk` again.
* **Expected Output:** After the update, the original transform property node should be rebuilt correctly. This assumes the `PrePaintTreeWalk` correctly detects the invalidation and re-evaluates the CSS to reconstruct the paint property tree.

**User or Programming Common Usage Errors:**

These tests help prevent various errors, including:

* **Incorrect Paint Property Updates:** If the `PrePaintTreeWalk` has a bug, it might not update paint properties correctly after certain changes (e.g., a transform might not be applied, opacity might be wrong). This would lead to visual rendering errors.
* **Unnecessary Repaints:**  If the `PrePaintTreeWalk` incorrectly identifies elements that need repainting, it can lead to performance problems (jank) as the browser spends time repainting parts of the page unnecessarily. The tests involving clipping contexts are particularly relevant here.
* **Crashes:** In more severe cases, bugs in the paint pipeline could lead to crashes. The `InlineOutlineWithContinuationPaintInvalidation` test specifically checks for crashes in a complex scenario.
* **Incorrect Event Handling Logic:** The tests related to touch and wheel event handlers ensure that Blink correctly tracks which elements have blocking event listeners. If this information is incorrect, it could lead to unresponsive behavior or incorrect event dispatch.

**User Operations and Debugging Clues:**

These tests provide insights into how user actions can trigger the `PrePaintTreeWalk`:

1. **Page Load:** When a web page is initially loaded, the rendering engine performs a `PrePaintTreeWalk` to establish the initial paint properties.
2. **Scrolling:**  When a user scrolls the page (using the scrollbar, mouse wheel, or touch gestures), this can trigger updates to scroll-related paint properties.
3. **CSS Changes (Dynamic Updates):**  JavaScript code can dynamically modify CSS styles or classes of elements. This will invalidate parts of the render tree and trigger a new `PrePaintTreeWalk`.
    * **Example:** A user interaction (like hovering over a button) might trigger a JavaScript function that changes the button's `transform` or `opacity`.
4. **Attribute Changes:** Modifying HTML attributes (like `class`, `style`) can also trigger style recalculation and a `PrePaintTreeWalk`.
    * **Example:** A user clicking a checkbox might toggle a CSS class that changes the appearance of other elements.
5. **Animation and Transitions:** CSS animations and transitions involve continuous changes to CSS properties, leading to repeated executions of the `PrePaintTreeWalk`.
6. **Resizing the Browser Window:**  Resizing the window can trigger layout changes, which in turn require the paint properties to be recalculated.

**Debugging Clues:**

If a web page exhibits rendering issues (incorrect transformations, missing effects, visual glitches during scrolling or animations), a developer might investigate the `PrePaintTreeWalk` as a potential source of the problem. Debugging tools within the browser (like the Chrome DevTools' "Layers" tab and "Performance" tab) can help visualize the paint layers and identify performance bottlenecks related to painting. The tests in this file provide a microcosm of these scenarios, allowing developers to pinpoint and fix issues within the Blink rendering engine itself.

In summary, `pre_paint_tree_walk_test.cc` is a critical part of the Blink rendering engine's testing infrastructure, ensuring the correctness and efficiency of the process that determines how web page elements should be painted based on their HTML structure, CSS styles, and user interactions.

### 提示词
```
这是目录为blink/renderer/core/paint/pre_paint_tree_walk_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/pre_paint_tree_walk.h"

#include "base/test/scoped_feature_list.h"
#include "cc/base/features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/layout/layout_tree_as_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_property_tree_printer.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/scroll_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"

namespace blink {

class PrePaintTreeWalkTest : public PaintControllerPaintTest {
 public:
  const TransformPaintPropertyNode* FramePreTranslation() {
    return GetDocument()
        .View()
        ->GetLayoutView()
        ->FirstFragment()
        .PaintProperties()
        ->PaintOffsetTranslation();
  }

  const TransformPaintPropertyNode* FrameScrollTranslation() {
    return GetDocument()
        .View()
        ->GetLayoutView()
        ->FirstFragment()
        .PaintProperties()
        ->ScrollTranslation();
  }

 private:
  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(PrePaintTreeWalkTest);

TEST_P(PrePaintTreeWalkTest, PropertyTreesRebuiltWithBorderInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #transformed { transform: translate(100px, 100px); }
      .border { border: 10px solid black; }
    </style>
    <div id='transformed'></div>
  )HTML");

  auto* transformed_element =
      GetDocument().getElementById(AtomicString("transformed"));
  const auto* transformed_properties =
      transformed_element->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(100, 100),
            transformed_properties->Transform()->Get2dTranslation());

  // Artifically change the transform node.
  const_cast<ObjectPaintProperties*>(transformed_properties)->ClearTransform();
  EXPECT_EQ(nullptr, transformed_properties->Transform());

  // Cause a paint invalidation.
  transformed_element->setAttribute(html_names::kClassAttr,
                                    AtomicString("border"));
  UpdateAllLifecyclePhasesForTest();

  // Should have changed back.
  EXPECT_EQ(gfx::Vector2dF(100, 100),
            transformed_properties->Transform()->Get2dTranslation());
}

TEST_P(PrePaintTreeWalkTest, PropertyTreesRebuiltWithFrameScroll) {
  SetBodyInnerHTML("<style> body { height: 10000px; } </style>");
  EXPECT_TRUE(FrameScrollTranslation()->IsIdentity());

  // Cause a scroll invalidation and ensure the translation is updated.
  GetDocument().domWindow()->scrollTo(0, 100);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(gfx::Vector2dF(0, -100),
            FrameScrollTranslation()->Get2dTranslation());
}

TEST_P(PrePaintTreeWalkTest, PropertyTreesRebuiltWithCSSTransformInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .transformA { transform: translate(100px, 100px); }
      .transformB { transform: translate(200px, 200px); }
      #transformed { will-change: transform; }
    </style>
    <div id='transformed' class='transformA'></div>
  )HTML");

  auto* transformed_element =
      GetDocument().getElementById(AtomicString("transformed"));
  const auto* transformed_properties =
      transformed_element->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(100, 100),
            transformed_properties->Transform()->Get2dTranslation());

  // Invalidate the CSS transform property.
  transformed_element->setAttribute(html_names::kClassAttr,
                                    AtomicString("transformB"));
  UpdateAllLifecyclePhasesForTest();

  // The transform should have changed.
  EXPECT_EQ(gfx::Vector2dF(200, 200),
            transformed_properties->Transform()->Get2dTranslation());
}

TEST_P(PrePaintTreeWalkTest, PropertyTreesRebuiltWithOpacityInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .opacityA { opacity: 0.9; }
      .opacityB { opacity: 0.4; }
    </style>
    <div id='transparent' class='opacityA'></div>
  )HTML");

  auto* transparent_element =
      GetDocument().getElementById(AtomicString("transparent"));
  const auto* transparent_properties =
      transparent_element->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(0.9f, transparent_properties->Effect()->Opacity());

  // Invalidate the opacity property.
  transparent_element->setAttribute(html_names::kClassAttr,
                                    AtomicString("opacityB"));
  UpdateAllLifecyclePhasesForTest();

  // The opacity should have changed.
  EXPECT_EQ(0.4f, transparent_properties->Effect()->Opacity());
}

TEST_P(PrePaintTreeWalkTest, ClearSubsequenceCachingClipChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .clip { overflow: hidden }
    </style>
    <div id='parent' style='transform: translateZ(0); width: 100px;
      height: 100px;'>
      <div id='child' style='isolation: isolate'>
        content
      </div>
    </div>
  )HTML");

  auto* parent = GetDocument().getElementById(AtomicString("parent"));
  auto* child_paint_layer = GetPaintLayerByElementId("child");
  EXPECT_FALSE(child_paint_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_paint_layer->NeedsPaintPhaseFloat());

  parent->setAttribute(html_names::kClassAttr, AtomicString("clip"));
  UpdateAllLifecyclePhasesExceptPaint();

  EXPECT_TRUE(child_paint_layer->SelfNeedsRepaint());
}

TEST_P(PrePaintTreeWalkTest, ClearSubsequenceCachingClipChange2DTransform) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .clip { overflow: hidden }
    </style>
    <div id='parent' style='transform: translateX(0); width: 100px;
      height: 100px;'>
      <div id='child' style='isolation: isolate'>
        content
      </div>
    </div>
  )HTML");

  auto* parent = GetDocument().getElementById(AtomicString("parent"));
  auto* child_paint_layer = GetPaintLayerByElementId("child");
  EXPECT_FALSE(child_paint_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_paint_layer->NeedsPaintPhaseFloat());

  parent->setAttribute(html_names::kClassAttr, AtomicString("clip"));
  UpdateAllLifecyclePhasesExceptPaint();

  EXPECT_TRUE(child_paint_layer->SelfNeedsRepaint());
}

TEST_P(PrePaintTreeWalkTest, ClearSubsequenceCachingClipChangePosAbs) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .clip { overflow: hidden }
    </style>
    <div id='parent' style='transform: translateZ(0); width: 100px;
      height: 100px; position: absolute'>
      <div id='child' style='overflow: hidden; position: relative;
          z-index: 0; width: 50px; height: 50px'>
        content
      </div>
    </div>
  )HTML");

  auto* parent = GetDocument().getElementById(AtomicString("parent"));
  auto* child_paint_layer = GetPaintLayerByElementId("child");
  EXPECT_FALSE(child_paint_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_paint_layer->NeedsPaintPhaseFloat());

  // This changes clips for absolute-positioned descendants of "child" but not
  // normal-position ones, which are already clipped to 50x50.
  parent->setAttribute(html_names::kClassAttr, AtomicString("clip"));
  UpdateAllLifecyclePhasesExceptPaint();

  EXPECT_TRUE(child_paint_layer->SelfNeedsRepaint());
}

TEST_P(PrePaintTreeWalkTest, ClearSubsequenceCachingClipChangePosFixed) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .clip { overflow: hidden }
    </style>
    <div id='parent' style='transform: translateZ(0); width: 100px;
      height: 100px;'>
      <div id='child' style='overflow: hidden; z-index: 0;
          position: absolute; width: 50px; height: 50px'>
        content
      </div>
    </div>
  )HTML");

  auto* parent = GetDocument().getElementById(AtomicString("parent"));
  auto* child_paint_layer = GetPaintLayerByElementId("child");
  EXPECT_FALSE(child_paint_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_paint_layer->NeedsPaintPhaseFloat());

  // This changes clips for absolute-positioned descendants of "child" but not
  // normal-position ones, which are already clipped to 50x50.
  parent->setAttribute(html_names::kClassAttr, AtomicString("clip"));
  UpdateAllLifecyclePhasesExceptPaint();

  EXPECT_TRUE(child_paint_layer->SelfNeedsRepaint());
}

TEST_P(PrePaintTreeWalkTest, ClipChangeRepaintsDescendants) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent { position: relative; width: 100px; }
      #child { overflow: hidden; width: 10%; height: 100%; position: relative; }
      #greatgrandchild {
        width: 100px; height: 100px; z-index: 100; position: relative;
      }
    </style>
    <div id='parent' style='height: 10px'>
      <div id='child'>
        <div id='grandchild'>
          <div id='greatgrandchild'></div>
        </div>
      </div>
    </div>
  )HTML");

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 100px"));
  UpdateAllLifecyclePhasesExceptPaint();

  auto* paint_layer = GetPaintLayerByElementId("greatgrandchild");
  EXPECT_TRUE(paint_layer->SelfNeedsRepaint());
}

TEST_P(PrePaintTreeWalkTest, ClipChangeHasRadius) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        position: absolute;
        z-index: 0;
        overflow: hidden;
        width: 50px;
        height: 50px;
      }
    </style>
    <div id='target'></div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* target_object = To<LayoutBoxModelObject>(target->GetLayoutObject());
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("border-radius: 5px"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(target_object->Layer()->SelfNeedsRepaint());
  // And should not trigger any assert failure.
  UpdateAllLifecyclePhasesForTest();
}

namespace {
class PrePaintTreeWalkMockEventListener final : public NativeEventListener {
 public:
  void Invoke(ExecutionContext*, Event*) final {}
};
}  // namespace

TEST_P(PrePaintTreeWalkTest, InsideBlockingTouchEventHandlerUpdate) {
  SetBodyInnerHTML(R"HTML(
    <div id='ancestor' style='width: 100px; height: 100px;'>
      <div id='handler' style='width: 100px; height: 100px;'>
        <div id='descendant' style='width: 100px; height: 100px;'>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  auto& ancestor = *GetLayoutObjectByElementId("ancestor");
  auto& handler = *GetLayoutObjectByElementId("handler");
  auto& descendant = *GetLayoutObjectByElementId("descendant");

  EXPECT_FALSE(ancestor.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor.InsideBlockingTouchEventHandler());
  EXPECT_FALSE(handler.InsideBlockingTouchEventHandler());
  EXPECT_FALSE(descendant.InsideBlockingTouchEventHandler());

  PrePaintTreeWalkMockEventListener* callback =
      MakeGarbageCollected<PrePaintTreeWalkMockEventListener>();
  auto* handler_element = GetDocument().getElementById(AtomicString("handler"));
  handler_element->addEventListener(event_type_names::kTouchstart, callback);

  EXPECT_FALSE(ancestor.EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(handler.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.EffectiveAllowedTouchActionChanged());

  EXPECT_TRUE(ancestor.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.DescendantEffectiveAllowedTouchActionChanged());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor.InsideBlockingTouchEventHandler());
  EXPECT_TRUE(handler.InsideBlockingTouchEventHandler());
  EXPECT_TRUE(descendant.InsideBlockingTouchEventHandler());
}

TEST_P(PrePaintTreeWalkTest, EffectiveTouchActionStyleUpdate) {
  SetBodyInnerHTML(R"HTML(
    <style> .touchaction { touch-action: none; } </style>
    <div id='ancestor' style='width: 100px; height: 100px;'>
      <div id='touchaction' style='width: 100px; height: 100px;'>
        <div id='descendant' style='width: 100px; height: 100px;'>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  auto& ancestor = *GetLayoutObjectByElementId("ancestor");
  auto& touchaction = *GetLayoutObjectByElementId("touchaction");
  auto& descendant = *GetLayoutObjectByElementId("descendant");

  EXPECT_FALSE(ancestor.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(touchaction.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(ancestor.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(touchaction.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.DescendantEffectiveAllowedTouchActionChanged());

  GetDocument()
      .getElementById(AtomicString("touchaction"))
      ->setAttribute(html_names::kClassAttr, AtomicString("touchaction"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(ancestor.EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(touchaction.EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(descendant.EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(ancestor.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(touchaction.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.DescendantEffectiveAllowedTouchActionChanged());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(touchaction.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(ancestor.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(touchaction.DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant.DescendantEffectiveAllowedTouchActionChanged());
}

TEST_P(PrePaintTreeWalkTest, InsideBlockingWheelEventHandlerUpdate) {
  SetBodyInnerHTML(R"HTML(
    <div id='ancestor' style='width: 100px; height: 100px;'>
      <div id='handler' style='width: 100px; height: 100px;'>
        <div id='descendant' style='width: 100px; height: 100px;'>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  auto& ancestor = *GetLayoutObjectByElementId("ancestor");
  auto& handler = *GetLayoutObjectByElementId("handler");
  auto& descendant = *GetLayoutObjectByElementId("descendant");

  EXPECT_FALSE(ancestor.BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler.BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant.BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor.DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler.DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant.DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor.InsideBlockingWheelEventHandler());
  EXPECT_FALSE(handler.InsideBlockingWheelEventHandler());
  EXPECT_FALSE(descendant.InsideBlockingWheelEventHandler());

  PrePaintTreeWalkMockEventListener* callback =
      MakeGarbageCollected<PrePaintTreeWalkMockEventListener>();
  auto* handler_element = GetDocument().getElementById(AtomicString("handler"));
  handler_element->addEventListener(event_type_names::kWheel, callback);

  EXPECT_FALSE(ancestor.BlockingWheelEventHandlerChanged());
  EXPECT_TRUE(handler.BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant.BlockingWheelEventHandlerChanged());

  EXPECT_TRUE(ancestor.DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler.DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant.DescendantBlockingWheelEventHandlerChanged());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor.BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler.BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant.BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor.DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler.DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant.DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor.InsideBlockingWheelEventHandler());
  EXPECT_TRUE(handler.InsideBlockingWheelEventHandler());
  EXPECT_TRUE(descendant.InsideBlockingWheelEventHandler());
}

TEST_P(PrePaintTreeWalkTest, CullRectUpdateOnSVGTransformChange) {
  SetBodyInnerHTML(R"HTML(
    <svg style="width: 200px; height: 200px">
      <rect id="rect"/>
      <g id="g"><foreignObject id="foreign"/></g>
    </svg>
  )HTML");

  auto& foreign = *GetLayoutObjectByElementId("foreign");
  EXPECT_EQ(gfx::Rect(0, 0, 200, 200),
            foreign.FirstFragment().GetCullRect().Rect());

  GetDocument()
      .getElementById(AtomicString("rect"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("transform: translateX(20px)"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 200),
            foreign.FirstFragment().GetCullRect().Rect());

  GetDocument()
      .getElementById(AtomicString("g"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("transform: translateY(20px)"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_EQ(gfx::Rect(0, -20, 200, 200),
            foreign.FirstFragment().GetCullRect().Rect());
}

TEST_P(PrePaintTreeWalkTest, InlineOutlineWithContinuationPaintInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <div>
      <span style="outline: 1px solid black">
        <span id="child-span">span</span>
        <div>continuation</div>
      </span>
    </div>
  )HTML");

  // This test passes if the following doesn't crash.
  GetDocument()
      .getElementById(AtomicString("child-span"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("color: blue"));
  UpdateAllLifecyclePhasesForTest();
}

TEST_P(PrePaintTreeWalkTest, ScrollTranslationNodeForNonZeroScrollPosition) {
  SetBodyInnerHTML(R"HTML(
    <div id="div" style="overflow:hidden;max-width:5ch;direction:rtl">
      loremipsumdolorsitamet
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* scroller = GetDocument().getElementById(AtomicString("div"));
  auto* object = To<LayoutBoxModelObject>(scroller->GetLayoutObject());
  auto* scrollable_area = object->GetScrollableArea();

  ASSERT_EQ(ScrollOffset(), scrollable_area->GetScrollOffset());
  ASSERT_NE(gfx::PointF(), scrollable_area->ScrollPosition());
  EXPECT_TRUE(object->FirstFragment().PaintProperties()->ScrollTranslation());

  // When the scroll is scrolled all the way to the end of content it should
  // still get a scroll node.
  scroller->scrollBy(-10000, 0);
  UpdateAllLifecyclePhasesForTest();
  ASSERT_NE(ScrollOffset(), scrollable_area->GetScrollOffset());
  ASSERT_EQ(gfx::PointF(), scrollable_area->ScrollPosition());
  EXPECT_TRUE(object->FirstFragment().PaintProperties()->ScrollTranslation());
}

}  // namespace blink
```