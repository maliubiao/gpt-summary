Response:
The user wants a summary of the functionality of the `paint_layer_painter_test.cc` file in the Chromium Blink engine. I need to identify the main purpose of the tests and how they relate to rendering web pages. Specifically, I need to look for connections to JavaScript, HTML, and CSS, provide examples, analyze logical reasoning with hypothetical inputs and outputs, highlight common usage errors, and explain how a user action might lead to the execution of this code.

Based on the file name and the included headers, it seems this file contains unit tests for the `PaintLayerPainter` class. This class is likely responsible for generating display items and paint chunks for a given paint layer, which are then used for the actual rendering of elements on the screen.

Here's a breakdown of the functionalities I can infer from the tests:

- **Caching of Paint Operations:** The tests with "CachedSubsequence" in their names indicate that the tests verify the caching mechanism for paint operations to optimize rendering performance.
- **Handling Backgrounds:** Some tests explicitly deal with elements having background colors, suggesting the tests cover how backgrounds are painted and cached.
- **Cull Rect Optimization:** Tests involving "CullRect" indicate that the tests check how the painting is optimized based on the visible area (cull rect).
- **Paint Phases:** Tests with "PaintPhaseOutline" and "PaintPhaseFloat" suggest that the tests cover the rendering order of outlines and floated elements.
- **Display Items and Paint Chunks:** The tests use functions like `ContentDisplayItems()` and `ContentPaintChunks()`, indicating they verify the correct generation of these rendering primitives.
- **Interaction with Layout:** The tests access `LayoutObject` and `PaintLayer`, showing that the painter interacts with the layout information of elements.
- **Hit Testing:** The test involving `HitTestOpaquenessEnabled` implies the painter is involved in generating information for hit testing (determining which element is clicked).

Now, let's connect these functionalities to JavaScript, HTML, and CSS:

- **HTML:** The tests set up the DOM structure using `SetBodyInnerHTML()`. The structure of the HTML directly affects the layout and painting order. For example, the nesting of `div` elements with different `position` values will create different paint layers.
- **CSS:** CSS styles are applied through the `style` attribute in the HTML. Changes in CSS properties like `background-color`, `position`, `z-index`, `overflow`, `outline`, and `float` directly trigger different painting behaviors and are tested here.
- **JavaScript:**  While this specific test file doesn't directly execute JavaScript, it tests the rendering behavior *after* JavaScript might have modified the DOM or CSS. For example, a JavaScript animation that changes the `top` property of an element would indirectly trigger the painting logic tested here.

For logical reasoning with input and output, consider the "CachedSubsequenceAndChunksWithBackgrounds" test.

**Hypothetical Input:**

- Initial HTML structure with several divs having background colors and specific positioning.
- Initial CSS setting the colors and dimensions.

**Hypothetical Output:**

- The test verifies that `ContentDisplayItems()` and `ContentPaintChunks()` return specific sequences of display items and paint chunks representing the background painting order.
- After changing the background color of one of the divs and re-painting, the test verifies that some painting operations are cached, and the display items and paint chunks are updated accordingly.

Common user or programming errors that might lead to issues in this area include:

- **Incorrect `z-index` usage:**  Mistakes in setting `z-index` can lead to elements being painted in the wrong order, which these tests aim to prevent.
- **Forgetting to trigger a repaint:** After modifying the DOM or CSS via JavaScript, failing to trigger a repaint (implicitly or explicitly) might lead to the UI not updating. These tests ensure that when a repaint *does* occur, the painting is done correctly and efficiently.
- **Performance bottlenecks due to excessive repaints:**  Inefficient JavaScript code might cause too many unnecessary repaints. The caching mechanisms tested here are crucial for mitigating such performance issues.

Regarding user actions to reach this code:

1. **User loads a web page:** The browser parses the HTML, CSS, and executes JavaScript.
2. **JavaScript modifies the DOM or CSS:**  An animation, user interaction, or a dynamic update changes the style or structure of elements.
3. **The browser's rendering engine needs to repaint:** Based on the changes, the browser invalidates parts of the rendering tree.
4. **The `PaintLayerPainter` is invoked:**  The rendering engine iterates through the paint layers and uses the `PaintLayerPainter` to generate the necessary display items and paint chunks for the invalidated regions.
5. **The tests in this file verify the correctness of step 4:** If a developer makes a change to the `PaintLayerPainter`, these tests ensure that the changes don't introduce regressions or bugs in the painting logic.

Finally, let's summarize the functionality of this first part of the file. It primarily focuses on testing the caching mechanisms within the `PaintLayerPainter` and how it handles elements with backgrounds and different stacking contexts. The tests verify the correct generation of display items and paint chunks, ensuring that repaints are optimized by reusing previously painted content when possible.
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

using testing::Contains;
using testing::ElementsAre;
using testing::UnorderedElementsAre;

namespace blink {

class PaintLayerPainterTest : public PaintControllerPaintTest {
  USING_FAST_MALLOC(PaintLayerPainterTest);

 public:
  CullRect GetCullRect(const PaintLayer& layer) {
    return layer.GetLayoutObject().FirstFragment().GetCullRect();
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(PaintLayerPainterTest);

TEST_P(PaintLayerPainterTest, CachedSubsequenceAndChunksWithBackgrounds) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id='container1' style='position: relative; z-index: 1;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content1' style='position: absolute; width: 100px;
          height: 100px; background-color: red'></div>
    </div>
    <div id='filler1' style='position: relative; z-index: 2;
        width: 20px; height: 20px; background-color: gray'></div>
    <div id='container2' style='position: relative; z-index: 3;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content2' style='position: absolute; width: 100px;
          height: 100px; background-color: green;'></div>
    </div>
    <div id='filler2' style='position: relative; z-index: 4;
        width: 20px; height: 20px; background-color: gray'></div>
  )HTML");

  auto* container1 = GetLayoutObjectByElementId("container1");
  auto* content1 = GetLayoutObjectByElementId("content1");
  auto* filler1 = GetLayoutObjectByElementId("filler1");
  auto* container2 = GetLayoutObjectByElementId("container2");
  auto* content2 = GetLayoutObjectByElementId("content2");
  auto* filler2 = GetLayoutObjectByElementId("filler2");

  auto* container1_layer = To<LayoutBoxModelObject>(container1)->Layer();
  auto* content1_layer = To<LayoutBoxModelObject>(content1)->Layer();
  auto* filler1_layer = To<LayoutBoxModelObject>(filler1)->Layer();
  auto* container2_layer = To<LayoutBoxModelObject>(container2)->Layer();
  auto* content2_layer = To<LayoutBoxModelObject>(content2)->Layer();
  auto* filler2_layer = To<LayoutBoxModelObject>(filler2)->Layer();
  auto chunk_state = GetLayoutView().FirstFragment().ContentsProperties();

  auto check_results = [&]() {
    EXPECT_THAT(
        ContentDisplayItems(),
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
            IsSameId(GetDisplayItemClientFromLayoutObject(container1)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(content1)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(filler1)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(container2)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(content2)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(filler2)->Id(),
                     kBackgroundType)));

    // Check that new paint chunks were forced for the layers.
    auto chunks = ContentPaintChunks();
    auto chunk_it = chunks.begin();
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container1_layer, chunk_it + 1, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content1_layer, chunk_it + 2, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler1_layer, chunk_it + 3, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container2_layer, chunk_it + 4, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content2_layer, chunk_it + 5, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler2_layer, chunk_it + 6, 1);

    EXPECT_THAT(
        chunks,
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(1, 2,
                         PaintChunk::Id(container1_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         chunk_state, nullptr, gfx::Rect(0, 0, 200, 200)),
            IsPaintChunk(
                2, 3,
                PaintChunk::Id(content1_layer->Id(), DisplayItem::kLayerChunk),
                chunk_state, nullptr, gfx::Rect(0, 0, 100, 100)),
            IsPaintChunk(
                3, 4,
                PaintChunk::Id(filler1_layer->Id(), DisplayItem::kLayerChunk),
                chunk_state, nullptr, gfx::Rect(0, 200, 20, 20)),
            IsPaintChunk(4, 5,
                         PaintChunk::Id(container2_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         chunk_state, nullptr, gfx::Rect(0, 220, 200, 200)),
            IsPaintChunk(
                5, 6,
                PaintChunk::Id(content2_layer->Id(), DisplayItem::kLayerChunk),
                chunk_state, nullptr, gfx::Rect(0, 220, 100, 100)),
            IsPaintChunk(
                6, 7,
                PaintChunk::Id(filler2_layer->Id(), DisplayItem::kLayerChunk),
                chunk_state, nullptr, gfx::Rect(0, 420, 20, 20))));
  };

  check_results();

  To<HTMLElement>(content1->GetNode())
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: absolute; width: 100px; height: 100px; "
                       "background-color: green"));
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(6u, counter.num_cached_items);
  EXPECT_EQ(4u, counter.num_cached_subsequences);

  // We should still have the paint chunks forced by the cached subsequences.
  check_results();
}

TEST_P(PaintLayerPainterTest, CachedSubsequenceAndChunksWithoutBackgrounds) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      ::-webkit-scrollbar { display: none }
    </style>
    <div id='container' style='position: relative; z-index: 0;
        width: 150px; height: 150px; overflow: scroll'>
      <div id='content' style='position: relative; z-index: 1;
          width: 200px; height: 100px'>
        <div id='inner-content'
             style='position: absolute; width: 100px; height: 100px'></div>
      </div>
      <div id='filler' style='position: relative; z-index: 2;
          width: 300px; height: 300px'></div>
    </div>
  )HTML");

  auto* container = GetLayoutObjectByElementId("container");
  auto* content = GetLayoutObjectByElementId("content");
  auto* inner_content = GetLayoutObjectByElementId("inner-content");
  auto* filler = GetLayoutObjectByElementId("filler");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  auto* container_layer = To<LayoutBoxModelObject>(container)->Layer();
  auto* content_layer = To<LayoutBoxModelObject>(content)->Layer();
  auto* inner_content_layer = To<LayoutBoxModelObject>(inner_content)->Layer();
  auto* filler_layer = To<LayoutBoxModelObject>(filler)->Layer();

  auto chunks = ContentPaintChunks();
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container_layer, chunks.begin() + 1, 6);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content_layer, chunks.begin() + 4, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*inner_content_layer, chunks.begin() + 5, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler_layer, chunks.begin() + 6, 1);
  } else {
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container_layer, chunks.begin() + 1, 5);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content_layer, chunks.begin() + 3, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*inner_content_layer, chunks.begin() + 4, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler_layer, chunks.begin() + 5, 1);
  }

  auto container_properties =
      container->FirstFragment().LocalBorderBoxProperties();
  auto content_properties = container->FirstFragment().ContentsProperties();
  auto* scroll_hit_test = MakeGarbageCollected<HitTestData>();
  scroll_hit_test->scroll_translation =
      container->FirstFragment().PaintProperties()->ScrollTranslation();
  scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 150, 150);

  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_THAT(
        chunks,
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container_layer->Id(), DisplayItem::kLayerChunk),
                container_properties, nullptr, gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), DisplayItem::kScrollHitTest),
                container_properties, scroll_hit_test,
                gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), kScrollingBackgroundChunkType),
                content_properties, nullptr, gfx::Rect(0, 0, 300, 400)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(content_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 0, 200, 100)),
            IsPaintChunk(1, 1,
                         PaintChunk::Id(inner_content_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         content_properties, nullptr,
                         gfx::Rect(0, 0, 100, 100)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(filler_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 100, 300, 300))));
  } else {
    EXPECT_THAT(
        chunks,
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container_layer->Id(), DisplayItem::kLayerChunk),
                container_properties, nullptr, gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), DisplayItem::kScrollHitTest),
                container_properties, scroll_hit_test,
                gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(content_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 0, 200, 100)),
            IsPaintChunk(1, 1,
                         PaintChunk::Id(inner_content_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         content_properties, nullptr,
                         gfx::Rect(0, 0, 100, 100)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(filler_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 100, 300, 300))));
  }

  To<HTMLElement>(inner_content->GetNode())
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: absolute; width: 100px; height: 100px; "
                       "top: 100px; background-color: green"));
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(1u, counter.num_cached_items);         // view background.
  EXPECT_EQ(1u, counter.num_cached_subsequences);  // filler layer.

  EXPECT_THAT(
      ContentDisplayItems(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
          IsSameId(GetDisplayItemClientFromLayoutObject(inner_content)->Id(),
                   kBackgroundType)));

  chunks = ContentPaintChunks();
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container_layer, chunks.begin() + 1, 6);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content_layer, chunks.begin() + 4, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*inner_content_layer, chunks.begin() + 5, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler_layer, chunks.begin() + 6, 1);

    EXPECT_THAT(
        ContentPaintChunks(),
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container_layer->Id(), DisplayItem::kLayerChunk),
                container_properties, nullptr, gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), DisplayItem::kScrollHitTest),
                container_properties, scroll_hit_test,
                gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), kScrollingBackgroundChunkType),
                content_properties, nullptr, gfx::Rect(0, 0, 300, 400)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(content_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 0, 200, 100)),
            IsPaintChunk(1, 2,
                         PaintChunk::Id(inner_content_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         content_properties, nullptr,
                         gfx::Rect(0, 100, 100, 100)),
            IsPaintChunk(
                2, 2,
                PaintChunk::Id(filler_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 100, 300, 300))));
  } else {
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container_layer, chunks.begin() + 1, 5);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content_layer, chunks.begin() + 3, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*inner_content_layer, chunks.begin() + 4, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler_layer, chunks.begin() + 5, 1);

    EXPECT_THAT(
        ContentPaintChunks(),
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container_layer->Id(), DisplayItem::kLayerChunk),
                container_properties, nullptr, gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), DisplayItem::kScrollHitTest),
                container_properties, scroll_hit_test,
                gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(content_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 0, 200, 100)),
            IsPaintChunk(1, 2,
                         PaintChunk::Id(inner_content_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         content_properties, nullptr,
                         gfx::Rect(0, 100, 100, 100)),
            IsPaintChunk(
                2, 2,
                PaintChunk::Id(filler_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 100, 300, 300))));
  }
}

TEST_P(PaintLayerPainterTest, CachedSubsequenceOnCullRectChange) {
  SetBodyInnerHTML(R"HTML(
    <div id='container1' style='position: relative; z-index: 1;
       width: 200px; height: 200px; background-color: blue'>
      <div id='content1' style='position: absolute; width: 100px;
          height: 100px; background-color: green'></div>
    </div>
    <div id='container2' style='position: relative; z-index: 1;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content2a' style='position: absolute; width: 100px;
          height: 100px; background-color: green'></div>
      <div id='content2b' style='position: absolute; top: 200px;
          width: 100px; height: 100px; background-color: green'></div>
    </div>
    <div id='container3' style='position: absolute; z-index: 2;
        left: 300px; top: 0; width: 200px; height: 200px;
        background-color: blue'>
      <div id='content3' style='position: absolute; width: 200px;
          height: 200px; background-color: green'></div>
    </div>
  )HTML");
  InvalidateAll();

  const DisplayItemClient& container1 =
      *GetDisplayItemClientFromElementId("container1");
  const DisplayItemClient& content1 =
      *GetDisplayItemClientFromElementId("content1");
  const DisplayItemClient& container2 =
      *GetDisplayItemClientFromElementId("container2");
  const DisplayItemClient& content2a =
      *GetDisplayItemClientFromElementId("content2a");
  const DisplayItemClient& content2b =
      *GetDisplayItemClientFromElementId("content2b");
  const DisplayItemClient& container3 =
      *GetDisplayItemClientFromElementId("container3");
  const DisplayItemClient& content3 =
      *GetDisplayItemClientFromElementId("content3");

  UpdateAllLifecyclePhasesExceptPaint();
  PaintContents(gfx::Rect(0, 0, 400, 300));

  // Container1 is fully in the interest rect;
  // Container2 is partly (including its stacking chidren) in the interest rect;
  // Content2b is out of the interest rect and output nothing;
  // Container3 is partly in the interest rect.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(container3.Id(), kBackgroundType),
                          IsSameId(content3.Id(), kBackgroundType)));

  UpdateAllLifecyclePhasesExceptPaint();
  PaintController::CounterForTesting counter;
  PaintContents(gfx::Rect(0, 100, 300, 1000));
  // Container1 becomes partly in the interest rect, but uses cached subsequence
  // because it was fully painted before;
  // Container2's intersection with the interest rect changes;
  // Content2b is out of the interest rect and outputs nothing;
  // Container3 becomes out of the interest rect and outputs nothing.
  EXPECT_EQ(5u, counter.num_cached_items);
  EXPECT_EQ(2u, counter.num_cached_subsequences);

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(content2b.Id(), kBackgroundType)));
}

TEST_P(PaintLayerPainterTest,
       CachedSubsequenceOnCullRectChangeUnderInvalidationChecking) {
  ScopedPaintUnderInvalidationCheckingForTest under_invalidation_checking(true);

  SetBodyInnerHTML(R"HTML(
    <style>p { width: 200px; height: 50px; background: green }</style>
    <div id='target' style='position: relative; z-index: 1'>
      <p></p><p></p><p></p><p></p>
    </div>
  )HTML");
  InvalidateAll();

  // |target| will be fully painted.
  UpdateAllLifecyclePhasesExceptPaint();
  PaintContents(gfx::Rect(0, 0, 400, 300));

  // |target| will be partially painted. Should not trigger under-invalidation
  // checking DCHECKs.
  UpdateAllLifecyclePhasesExceptPaint();
  PaintContents(gfx::Rect(0, 100, 300, 1000));
}

TEST_P(PaintLayerPainterTest,
       CachedSubsequenceOnStyleChangeWithCullRectClipping) {
  SetBodyInnerHTML(R"HTML(
    <div id='container1' style='position: relative; z-index: 1;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content1' style='overflow: hidden; width: 100px;
          height: 100px; background-color: red'></div>
    </div>
    <div id='container2' style='position: relative; z-index: 1;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content2' style='overflow: hidden; width: 100px;
          height: 100px; background-color: green'></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesExceptPaint();
  // PaintResult of all subsequences will be MayBeClippedByCullRect.
  PaintContents(gfx::Rect(0, 0, 50, 300));

  const DisplayItemClient& container1 =
      *GetDisplayItemClientFromElementId("container1");
  const DisplayItemClient& content1 =
      *GetDisplayItemClientFromElementId("content1");
  const DisplayItemClient& container2 =
      *GetDisplayItemClientFromElementId("container2");
  const DisplayItemClient& content2 =
      *GetDisplayItemClientFromElementId("content2");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType)));

  To<HTMLElement>(GetElementById("content1"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: absolute; width: 100px; height: 100px; "
                       "background-color: green"));
  UpdateAllLifecyclePhasesExceptPaint();
  PaintController::CounterForTesting counter;
  PaintContents(gfx::Rect(0, 0, 50, 300));
  EXPECT_EQ(4u, counter.num_cached_items);

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType)));
}

TEST_P(PaintLayerPainterTest, CachedSubsequenceRetainsPreviousPaintResult) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html, body { height: 100%; margin: 0 }
      ::-webkit-scrollbar { display:none }
    </style>
    <div id="target" style="height: 8000px; contain: paint">
      <div id="content1" style="height: 100px; background: blue"></div>
      <div style="height: 6000px"></div>
      <div id="content2" style="height: 100px; background: blue"></div>
    </div>
    <div id="change" style="display: none"></div>
  )HTML");

  const auto* target = GetLayoutBoxByElementId("target");
  const auto* target_layer = target->Layer();
  const auto* content1 = GetLayoutObjectByElementId("content1");
  const auto* content2 = GetLayoutObjectByElementId("content2");
  // |target| is partially painted.
  EXPECT_EQ(kMayBeClippedByCullRect, target_layer->PreviousPaintResult());
  // |content2| is out of the cull rect.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(content1->Id(), kBackgroundType)));
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetCullRect(*target_layer).Rect());
  auto chunks = ContentPaintChunks();
  // |target| still created subsequence (cached).
  EXPECT_SUBSEQUENCE_FROM_CHUNK(*target_layer, chunks.begin() + 1, 2);
  EXPECT_THAT(chunks, ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                                  IsPaintChunk(1, 1), IsPaintChunk(1, 2)));

  // Change something that triggers a repaint but |target| should use cached
  // subsequence.
  GetDocument()
      .getElementById(AtomicString("change"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("display: block"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT
### 提示词
```
这是目录为blink/renderer/core/paint/paint_layer_painter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

using testing::Contains;
using testing::ElementsAre;
using testing::UnorderedElementsAre;

namespace blink {

class PaintLayerPainterTest : public PaintControllerPaintTest {
  USING_FAST_MALLOC(PaintLayerPainterTest);

 public:
  CullRect GetCullRect(const PaintLayer& layer) {
    return layer.GetLayoutObject().FirstFragment().GetCullRect();
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(PaintLayerPainterTest);

TEST_P(PaintLayerPainterTest, CachedSubsequenceAndChunksWithBackgrounds) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id='container1' style='position: relative; z-index: 1;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content1' style='position: absolute; width: 100px;
          height: 100px; background-color: red'></div>
    </div>
    <div id='filler1' style='position: relative; z-index: 2;
        width: 20px; height: 20px; background-color: gray'></div>
    <div id='container2' style='position: relative; z-index: 3;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content2' style='position: absolute; width: 100px;
          height: 100px; background-color: green;'></div>
    </div>
    <div id='filler2' style='position: relative; z-index: 4;
        width: 20px; height: 20px; background-color: gray'></div>
  )HTML");

  auto* container1 = GetLayoutObjectByElementId("container1");
  auto* content1 = GetLayoutObjectByElementId("content1");
  auto* filler1 = GetLayoutObjectByElementId("filler1");
  auto* container2 = GetLayoutObjectByElementId("container2");
  auto* content2 = GetLayoutObjectByElementId("content2");
  auto* filler2 = GetLayoutObjectByElementId("filler2");

  auto* container1_layer = To<LayoutBoxModelObject>(container1)->Layer();
  auto* content1_layer = To<LayoutBoxModelObject>(content1)->Layer();
  auto* filler1_layer = To<LayoutBoxModelObject>(filler1)->Layer();
  auto* container2_layer = To<LayoutBoxModelObject>(container2)->Layer();
  auto* content2_layer = To<LayoutBoxModelObject>(content2)->Layer();
  auto* filler2_layer = To<LayoutBoxModelObject>(filler2)->Layer();
  auto chunk_state = GetLayoutView().FirstFragment().ContentsProperties();

  auto check_results = [&]() {
    EXPECT_THAT(
        ContentDisplayItems(),
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
            IsSameId(GetDisplayItemClientFromLayoutObject(container1)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(content1)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(filler1)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(container2)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(content2)->Id(),
                     kBackgroundType),
            IsSameId(GetDisplayItemClientFromLayoutObject(filler2)->Id(),
                     kBackgroundType)));

    // Check that new paint chunks were forced for the layers.
    auto chunks = ContentPaintChunks();
    auto chunk_it = chunks.begin();
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container1_layer, chunk_it + 1, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content1_layer, chunk_it + 2, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler1_layer, chunk_it + 3, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container2_layer, chunk_it + 4, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content2_layer, chunk_it + 5, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler2_layer, chunk_it + 6, 1);

    EXPECT_THAT(
        chunks,
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(1, 2,
                         PaintChunk::Id(container1_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         chunk_state, nullptr, gfx::Rect(0, 0, 200, 200)),
            IsPaintChunk(
                2, 3,
                PaintChunk::Id(content1_layer->Id(), DisplayItem::kLayerChunk),
                chunk_state, nullptr, gfx::Rect(0, 0, 100, 100)),
            IsPaintChunk(
                3, 4,
                PaintChunk::Id(filler1_layer->Id(), DisplayItem::kLayerChunk),
                chunk_state, nullptr, gfx::Rect(0, 200, 20, 20)),
            IsPaintChunk(4, 5,
                         PaintChunk::Id(container2_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         chunk_state, nullptr, gfx::Rect(0, 220, 200, 200)),
            IsPaintChunk(
                5, 6,
                PaintChunk::Id(content2_layer->Id(), DisplayItem::kLayerChunk),
                chunk_state, nullptr, gfx::Rect(0, 220, 100, 100)),
            IsPaintChunk(
                6, 7,
                PaintChunk::Id(filler2_layer->Id(), DisplayItem::kLayerChunk),
                chunk_state, nullptr, gfx::Rect(0, 420, 20, 20))));
  };

  check_results();

  To<HTMLElement>(content1->GetNode())
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: absolute; width: 100px; height: 100px; "
                       "background-color: green"));
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(6u, counter.num_cached_items);
  EXPECT_EQ(4u, counter.num_cached_subsequences);

  // We should still have the paint chunks forced by the cached subsequences.
  check_results();
}

TEST_P(PaintLayerPainterTest, CachedSubsequenceAndChunksWithoutBackgrounds) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      ::-webkit-scrollbar { display: none }
    </style>
    <div id='container' style='position: relative; z-index: 0;
        width: 150px; height: 150px; overflow: scroll'>
      <div id='content' style='position: relative; z-index: 1;
          width: 200px; height: 100px'>
        <div id='inner-content'
             style='position: absolute; width: 100px; height: 100px'></div>
      </div>
      <div id='filler' style='position: relative; z-index: 2;
          width: 300px; height: 300px'></div>
    </div>
  )HTML");

  auto* container = GetLayoutObjectByElementId("container");
  auto* content = GetLayoutObjectByElementId("content");
  auto* inner_content = GetLayoutObjectByElementId("inner-content");
  auto* filler = GetLayoutObjectByElementId("filler");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  auto* container_layer = To<LayoutBoxModelObject>(container)->Layer();
  auto* content_layer = To<LayoutBoxModelObject>(content)->Layer();
  auto* inner_content_layer = To<LayoutBoxModelObject>(inner_content)->Layer();
  auto* filler_layer = To<LayoutBoxModelObject>(filler)->Layer();

  auto chunks = ContentPaintChunks();
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container_layer, chunks.begin() + 1, 6);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content_layer, chunks.begin() + 4, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*inner_content_layer, chunks.begin() + 5, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler_layer, chunks.begin() + 6, 1);
  } else {
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container_layer, chunks.begin() + 1, 5);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content_layer, chunks.begin() + 3, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*inner_content_layer, chunks.begin() + 4, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler_layer, chunks.begin() + 5, 1);
  }

  auto container_properties =
      container->FirstFragment().LocalBorderBoxProperties();
  auto content_properties = container->FirstFragment().ContentsProperties();
  auto* scroll_hit_test = MakeGarbageCollected<HitTestData>();
  scroll_hit_test->scroll_translation =
      container->FirstFragment().PaintProperties()->ScrollTranslation();
  scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 150, 150);

  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_THAT(
        chunks,
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container_layer->Id(), DisplayItem::kLayerChunk),
                container_properties, nullptr, gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), DisplayItem::kScrollHitTest),
                container_properties, scroll_hit_test,
                gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), kScrollingBackgroundChunkType),
                content_properties, nullptr, gfx::Rect(0, 0, 300, 400)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(content_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 0, 200, 100)),
            IsPaintChunk(1, 1,
                         PaintChunk::Id(inner_content_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         content_properties, nullptr,
                         gfx::Rect(0, 0, 100, 100)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(filler_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 100, 300, 300))));
  } else {
    EXPECT_THAT(
        chunks,
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container_layer->Id(), DisplayItem::kLayerChunk),
                container_properties, nullptr, gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), DisplayItem::kScrollHitTest),
                container_properties, scroll_hit_test,
                gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(content_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 0, 200, 100)),
            IsPaintChunk(1, 1,
                         PaintChunk::Id(inner_content_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         content_properties, nullptr,
                         gfx::Rect(0, 0, 100, 100)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(filler_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 100, 300, 300))));
  }

  To<HTMLElement>(inner_content->GetNode())
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: absolute; width: 100px; height: 100px; "
                       "top: 100px; background-color: green"));
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(1u, counter.num_cached_items);         // view background.
  EXPECT_EQ(1u, counter.num_cached_subsequences);  // filler layer.

  EXPECT_THAT(
      ContentDisplayItems(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
          IsSameId(GetDisplayItemClientFromLayoutObject(inner_content)->Id(),
                   kBackgroundType)));

  chunks = ContentPaintChunks();
  if (RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container_layer, chunks.begin() + 1, 6);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content_layer, chunks.begin() + 4, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*inner_content_layer, chunks.begin() + 5, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler_layer, chunks.begin() + 6, 1);

    EXPECT_THAT(
        ContentPaintChunks(),
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container_layer->Id(), DisplayItem::kLayerChunk),
                container_properties, nullptr, gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), DisplayItem::kScrollHitTest),
                container_properties, scroll_hit_test,
                gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), kScrollingBackgroundChunkType),
                content_properties, nullptr, gfx::Rect(0, 0, 300, 400)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(content_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 0, 200, 100)),
            IsPaintChunk(1, 2,
                         PaintChunk::Id(inner_content_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         content_properties, nullptr,
                         gfx::Rect(0, 100, 100, 100)),
            IsPaintChunk(
                2, 2,
                PaintChunk::Id(filler_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 100, 300, 300))));
  } else {
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*container_layer, chunks.begin() + 1, 5);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*content_layer, chunks.begin() + 3, 2);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*inner_content_layer, chunks.begin() + 4, 1);
    EXPECT_SUBSEQUENCE_FROM_CHUNK(*filler_layer, chunks.begin() + 5, 1);

    EXPECT_THAT(
        ContentPaintChunks(),
        ElementsAre(
            VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container_layer->Id(), DisplayItem::kLayerChunk),
                container_properties, nullptr, gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(container->Id(), DisplayItem::kScrollHitTest),
                container_properties, scroll_hit_test,
                gfx::Rect(0, 0, 150, 150)),
            IsPaintChunk(
                1, 1,
                PaintChunk::Id(content_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 0, 200, 100)),
            IsPaintChunk(1, 2,
                         PaintChunk::Id(inner_content_layer->Id(),
                                        DisplayItem::kLayerChunk),
                         content_properties, nullptr,
                         gfx::Rect(0, 100, 100, 100)),
            IsPaintChunk(
                2, 2,
                PaintChunk::Id(filler_layer->Id(), DisplayItem::kLayerChunk),
                content_properties, nullptr, gfx::Rect(0, 100, 300, 300))));
  }
}

TEST_P(PaintLayerPainterTest, CachedSubsequenceOnCullRectChange) {
  SetBodyInnerHTML(R"HTML(
    <div id='container1' style='position: relative; z-index: 1;
       width: 200px; height: 200px; background-color: blue'>
      <div id='content1' style='position: absolute; width: 100px;
          height: 100px; background-color: green'></div>
    </div>
    <div id='container2' style='position: relative; z-index: 1;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content2a' style='position: absolute; width: 100px;
          height: 100px; background-color: green'></div>
      <div id='content2b' style='position: absolute; top: 200px;
          width: 100px; height: 100px; background-color: green'></div>
    </div>
    <div id='container3' style='position: absolute; z-index: 2;
        left: 300px; top: 0; width: 200px; height: 200px;
        background-color: blue'>
      <div id='content3' style='position: absolute; width: 200px;
          height: 200px; background-color: green'></div>
    </div>
  )HTML");
  InvalidateAll();

  const DisplayItemClient& container1 =
      *GetDisplayItemClientFromElementId("container1");
  const DisplayItemClient& content1 =
      *GetDisplayItemClientFromElementId("content1");
  const DisplayItemClient& container2 =
      *GetDisplayItemClientFromElementId("container2");
  const DisplayItemClient& content2a =
      *GetDisplayItemClientFromElementId("content2a");
  const DisplayItemClient& content2b =
      *GetDisplayItemClientFromElementId("content2b");
  const DisplayItemClient& container3 =
      *GetDisplayItemClientFromElementId("container3");
  const DisplayItemClient& content3 =
      *GetDisplayItemClientFromElementId("content3");

  UpdateAllLifecyclePhasesExceptPaint();
  PaintContents(gfx::Rect(0, 0, 400, 300));

  // Container1 is fully in the interest rect;
  // Container2 is partly (including its stacking chidren) in the interest rect;
  // Content2b is out of the interest rect and output nothing;
  // Container3 is partly in the interest rect.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(container3.Id(), kBackgroundType),
                          IsSameId(content3.Id(), kBackgroundType)));

  UpdateAllLifecyclePhasesExceptPaint();
  PaintController::CounterForTesting counter;
  PaintContents(gfx::Rect(0, 100, 300, 1000));
  // Container1 becomes partly in the interest rect, but uses cached subsequence
  // because it was fully painted before;
  // Container2's intersection with the interest rect changes;
  // Content2b is out of the interest rect and outputs nothing;
  // Container3 becomes out of the interest rect and outputs nothing.
  EXPECT_EQ(5u, counter.num_cached_items);
  EXPECT_EQ(2u, counter.num_cached_subsequences);

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(content2b.Id(), kBackgroundType)));
}

TEST_P(PaintLayerPainterTest,
       CachedSubsequenceOnCullRectChangeUnderInvalidationChecking) {
  ScopedPaintUnderInvalidationCheckingForTest under_invalidation_checking(true);

  SetBodyInnerHTML(R"HTML(
    <style>p { width: 200px; height: 50px; background: green }</style>
    <div id='target' style='position: relative; z-index: 1'>
      <p></p><p></p><p></p><p></p>
    </div>
  )HTML");
  InvalidateAll();

  // |target| will be fully painted.
  UpdateAllLifecyclePhasesExceptPaint();
  PaintContents(gfx::Rect(0, 0, 400, 300));

  // |target| will be partially painted. Should not trigger under-invalidation
  // checking DCHECKs.
  UpdateAllLifecyclePhasesExceptPaint();
  PaintContents(gfx::Rect(0, 100, 300, 1000));
}

TEST_P(PaintLayerPainterTest,
       CachedSubsequenceOnStyleChangeWithCullRectClipping) {
  SetBodyInnerHTML(R"HTML(
    <div id='container1' style='position: relative; z-index: 1;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content1' style='overflow: hidden; width: 100px;
          height: 100px; background-color: red'></div>
    </div>
    <div id='container2' style='position: relative; z-index: 1;
        width: 200px; height: 200px; background-color: blue'>
      <div id='content2' style='overflow: hidden; width: 100px;
          height: 100px; background-color: green'></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesExceptPaint();
  // PaintResult of all subsequences will be MayBeClippedByCullRect.
  PaintContents(gfx::Rect(0, 0, 50, 300));

  const DisplayItemClient& container1 =
      *GetDisplayItemClientFromElementId("container1");
  const DisplayItemClient& content1 =
      *GetDisplayItemClientFromElementId("content1");
  const DisplayItemClient& container2 =
      *GetDisplayItemClientFromElementId("container2");
  const DisplayItemClient& content2 =
      *GetDisplayItemClientFromElementId("content2");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType)));

  To<HTMLElement>(GetElementById("content1"))
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: absolute; width: 100px; height: 100px; "
                       "background-color: green"));
  UpdateAllLifecyclePhasesExceptPaint();
  PaintController::CounterForTesting counter;
  PaintContents(gfx::Rect(0, 0, 50, 300));
  EXPECT_EQ(4u, counter.num_cached_items);

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType)));
}

TEST_P(PaintLayerPainterTest, CachedSubsequenceRetainsPreviousPaintResult) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html, body { height: 100%; margin: 0 }
      ::-webkit-scrollbar { display:none }
    </style>
    <div id="target" style="height: 8000px; contain: paint">
      <div id="content1" style="height: 100px; background: blue"></div>
      <div style="height: 6000px"></div>
      <div id="content2" style="height: 100px; background: blue"></div>
    </div>
    <div id="change" style="display: none"></div>
  )HTML");

  const auto* target = GetLayoutBoxByElementId("target");
  const auto* target_layer = target->Layer();
  const auto* content1 = GetLayoutObjectByElementId("content1");
  const auto* content2 = GetLayoutObjectByElementId("content2");
  // |target| is partially painted.
  EXPECT_EQ(kMayBeClippedByCullRect, target_layer->PreviousPaintResult());
  // |content2| is out of the cull rect.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(content1->Id(), kBackgroundType)));
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetCullRect(*target_layer).Rect());
  auto chunks = ContentPaintChunks();
  // |target| still created subsequence (cached).
  EXPECT_SUBSEQUENCE_FROM_CHUNK(*target_layer, chunks.begin() + 1, 2);
  EXPECT_THAT(chunks, ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                                  IsPaintChunk(1, 1), IsPaintChunk(1, 2)));

  // Change something that triggers a repaint but |target| should use cached
  // subsequence.
  GetDocument()
      .getElementById(AtomicString("change"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("display: block"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(target_layer->SelfNeedsRepaint());
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2u, counter.num_cached_items);
  EXPECT_EQ(1u, counter.num_cached_subsequences);

  // |target| is still partially painted.
  EXPECT_EQ(kMayBeClippedByCullRect, target_layer->PreviousPaintResult());
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(content1->Id(), kBackgroundType)));
  EXPECT_EQ(gfx::Rect(0, 0, 800, 4600), GetCullRect(*target_layer).Rect());
  chunks = ContentPaintChunks();
  EXPECT_EQ(CullRect(gfx::Rect(0, 0, 800, 4600)), GetCullRect(*target_layer));
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(content1->Id(), kBackgroundType)));
  // |target| still created subsequence (cached).
  EXPECT_SUBSEQUENCE_FROM_CHUNK(*target_layer, chunks.begin() + 1, 2);
  EXPECT_THAT(chunks, ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                                  IsPaintChunk(1, 1), IsPaintChunk(1, 2)));

  // Scroll the view so that both |content1| and |content2| are in the interest
  // rect.
  GetLayoutView().GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 3000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesExceptPaint();
  // The layer needs repaint when its contents cull rect changes.
  EXPECT_TRUE(target_layer->SelfNeedsRepaint());

  counter.Reset();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2u, counter.num_cached_items);
  EXPECT_EQ(0u, counter.num_cached_subsequences);

  // |target| is still partially painted.
  EXPECT_EQ(kMayBeClippedByCullRect, target_layer->PreviousPaintResult());
  // Painted result should include both |content1| and |content2|.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(content1->Id(), kBackgroundType),
                          IsSameId(content2->Id(), kBackgroundType)));
  EXPECT_EQ(gfx::Rect(0, 0, 800, 7600), GetCullRect(*target_layer).Rect());
  chunks = ContentPaintChunks();
  EXPECT_EQ(CullRect(gfx::Rect(0, 0, 800, 7600)), GetCullRect(*target_layer));
  // |target| still created subsequence (repainted).
  EXPECT_SUBSEQUENCE_FROM_CHUNK(*target_layer, chunks.begin() + 1, 2);
  EXPECT_THAT(chunks, ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                                  IsPaintChunk(1, 1), IsPaintChunk(1, 3)));
}

TEST_P(PaintLayerPainterTest, PaintPhaseOutline) {
  AtomicString style_without_outline(
      "width: 50px; height: 50px; background-color: green");
  AtomicString style_with_outline("outline: 1px solid blue; " +
                                  style_without_outline);
  SetBodyInnerHTML(R"HTML(
    <div id='self-painting-layer' style='position: absolute'>
      <div id='non-self-painting-layer' style='overflow: hidden'>
        <div>
          <div id='outline'></div>
        </div>
      </div>
    </div>
  )HTML");
  LayoutObject& outline_div =
      *GetDocument().getElementById(AtomicString("outline"))->GetLayoutObject();
  To<HTMLElement>(outline_div.GetNode())
      ->setAttribute(html_names::kStyleAttr, style_without_outline);
  UpdateAllLifecyclePhasesForTest();

  auto& self_painting_layer_object = *To<LayoutBoxModelObject>(
      GetDocument()
          .getElementById(AtomicString("self-painting-layer"))
          ->GetLayoutObject());
  PaintLayer& self_painting_layer = *self_painting_layer_object.Layer();
  ASSERT_TRUE(self_painting_layer.IsSelfPaintingLayer());
  auto& non_self_painting_layer =
      *GetPaintLayerByElementId("non-self-painting-layer");
  ASSERT_FALSE(non_self_painting_layer.IsSelfPaintingLayer());
  ASSERT_TRUE(&non_self_painting_layer == outline_div.EnclosingLayer());

  EXPECT_FALSE(self_painting_layer.NeedsPaintPhaseDescendantOutlines());
  EXPECT_FALSE(non_self_painting_layer.NeedsPaintPhaseDescendantOutlines());

  // Outline on the self-painting-layer node itself doesn't affect
  // PaintPhaseDescendantOutlines.
  To<HTMLElement>(self_painting_layer_object.GetNode())
      ->setAttribute(
          html_names::kStyleAttr,
          AtomicString("position: absolute; outline: 1px solid green"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(self_painting_layer.NeedsPaintPhaseDescendantOutlines());
  EXPECT_FALSE(non_self_painting_layer.NeedsPaintPhaseDescendantOutlines());
  EXPECT_THAT(ContentDisplayItems(),
              Contains(IsSameId(self_painting_layer_object.Id(),
                                DisplayItem::PaintPhaseToDrawingType(
                                    PaintPhase::kSelfOutlineOnly))));

  // needsPaintPhaseDescendantOutlines should be set when any descendant on the
  // same layer has outline.
  To<HTMLElement>(outline_div.GetNode())
      ->setAttribute(html_names::kStyleAttr, style_with_outline);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(self_painting_layer.NeedsPaintPhaseDescendantOutlines());
  EXPECT_FALSE(non_self_painting_layer.NeedsPaintPhaseDescendantOutlines());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(
      ContentDisplayItems(),
      Contains(IsSameId(outline_div.Id(), DisplayItem::PaintPhaseToDrawingType(
                                              PaintPhase::kSelfOutlineOnly))));

  // needsPaintPhaseDescendantOutlines should be reset when no outline is
  // actually painted.
  To<HTMLElement>(outline_div.GetNode())
      ->setAttribute(html_names::kStyleAttr, style_without_outline);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(self_painting_layer.NeedsPaintPhaseDescendantOutlines());
}

TEST_P(PaintLayerPainterTest, PaintPhaseFloat) {
  AtomicString style_without_float(
      "width: 50px; height: 50px; background-color: green");
  AtomicString style_with_float("float: left; " + style_without_float);
  SetBodyInnerHTML(R"HTML(
    <div id='self-painting-layer' style='position: absolute'>
      <div id='non-self-painting-layer' style='overflow: hidden'>
        <div>
          <div id='float' style='width: 10px; height: 10px;
              background-color: blue'></div>
        </div>
      </div>
    </div>
  )HTML");
  LayoutObject& float_div =
      *GetDocument().getElementById(AtomicString("float"))->GetLayoutObject();
  To<HTMLElement>(float_div.GetNode())
      ->setAttribute(html_names::kStyleAttr, style_without_float);
  UpdateAllLifecyclePhasesForTest();

  auto& self_painting_layer_object = *To<LayoutBoxModelObject>(
      GetDocument()
          .getElementById(AtomicString("self-painting-layer"))
          ->GetLayoutObject());
  PaintLayer& self_painting_layer = *self_painting_layer_object.Layer();
  ASSERT_TRUE(self_painting_layer.IsSelfPaintingLayer());
  auto& non_self_painting_layer =
      *GetPaintLayerByElementId("non-self-painting-layer");
  ASSERT_FALSE(non_self_painting_layer.IsSelfPaintingLayer());
  ASSERT_TRUE(&non_self_painting_layer == float_div.EnclosingLayer());

  EXPECT_FALSE(self_painting_layer.NeedsPaintPhaseFloat());
  EXPECT_FALSE(non_self_painting_layer.NeedsPaintPhaseFloat());

  // needsPaintPhaseFloat should be set when any descendant on the same layer
  // has float.
  To<HTMLElement>(float_div.GetNode())
      ->setAttribute(html_names::kStyleAttr, style_with_float);
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(self_painting_layer.NeedsPaintPhaseFloat());
  EXPECT_FALSE(non_self_painting_layer.NeedsPaintPhaseFloat());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              Contains(IsSameId(float_div.Id(),
                                DisplayItem::kBoxDecorationBackground)));

  // needsPaintPhaseFloat should be reset when there is no float actually
  // painted.
  To<HTMLElement>(float_div.GetNode())
      ->setAttribute(html_names::kStyleAttr, style_without_float);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(self_painting_layer.NeedsPaintPhaseFloat());
}

TEST_P(PaintLayerPainterTest, PaintPhaseFloatUnderInlineLayer) {
  SetBodyInnerHTML(R"HTML(
    <div id='self-painting-layer' style='position: absolute'>
      <div id='non-self-painting-layer' style='overflow: hidden'>
        <span id='span' style='position: relative'>
          <div id='float' style='width: 10px; height: 10px;
              background-color: blue; float: left'></div>
        </span>
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  LayoutObject& float_div =
      *GetDocument().getElementById(AtomicString("float"))->GetLayoutObject();
  PaintLayer& span_layer = *GetPaintLayerByElementId("span");
  ASSERT_TRUE(&span_layer == float_div.EnclosingLayer());
  ASSERT_TRUE(span_layer.NeedsPaintPhaseFloat
```