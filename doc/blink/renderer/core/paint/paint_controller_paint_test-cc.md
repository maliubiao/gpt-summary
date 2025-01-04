Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Context:** The filename `paint_controller_paint_test.cc` and the directory `blink/renderer/core/paint/` immediately suggest this file contains tests for the `PaintController` specifically related to painting in the Blink rendering engine. The `_test.cc` suffix is a common convention for test files.

2. **Identify Key Components:** Scan the `#include` directives. These reveal the major areas the tests interact with:
    * `editing/`:  `FrameCaret`, `FrameSelection`, `InlineCursor` -  imply tests related to text input and selection.
    * `layout/`: `LayoutText`, `InlineCursor` - points towards testing how layout affects painting, especially inline elements.
    * `page/`: `FocusController` - suggests tests might touch on how focus impacts rendering.
    * `paint/`: `ObjectPaintProperties`, `PaintLayerPainter` -  explicitly confirms the focus on painting and related concepts like paint properties and layers.
    * `platform/graphics/`: `GraphicsContext`, `DrawingDisplayItem`, `DrawingRecorder` - these are lower-level graphics primitives used for recording and replaying paint operations.

3. **Recognize the Testing Framework:**  `using testing::_;` and `using testing::ElementsAre;` point to the Google Test framework being used. `INSTANTIATE_PAINT_TEST_SUITE_P` indicates this is a parameterized test suite. `TEST_P` defines individual parameterized tests.

4. **Analyze Individual Tests (Iterative Process):** Go through each `TEST_P` function and try to deduce its purpose:

    * **`InlineRelayout`:** The name suggests testing how painting behaves when inline elements are relaid out. The code manipulates the width of a `div`, forcing a relayout of the inline text within. The `EXPECT_THAT(ContentDisplayItems(), ElementsAre(...))` checks the sequence of display items *before* and *after* the relayout. This likely confirms that the paint system correctly updates the display items when inline text wraps. The use of `InlineCursor` further strengthens this interpretation.

    * **`ChunkIdClientCacheFlag`:**  The name hints at testing how caching mechanisms interact with paint chunks. The test sets up a scenario with nested divs and opacity. `ClientCacheIsValid` checks the validity of the paint cache. This test likely verifies that the cache is invalidated correctly when properties like opacity are involved.

    * **`CompositingNoFold`:** "Compositing" suggests testing how layers are composited for rendering. "NoFold" is less obvious but might refer to situations where layers don't get folded or merged in the compositing process. The simple structure with a div and a child div likely tests a basic compositing scenario.

    * **`FrameScrollingContents`:** The name directly indicates testing painting during document scrolling. The test creates several divs positioned far down the page. It then scrolls the document and checks which divs are painted and which paint chunks are generated based on the viewport. This test focuses on culling and optimizing paint operations during scrolling. The `HitTestData` and `PaintChunk` checks are key here.

    * **`BlockScrollingNonLayeredContents`:** Similar to the previous test, but focusing on scrolling within a block element that *creates its own scrolling context* (due to `overflow: scroll` and `will-change: transform`). This tests how nested scrolling contexts are handled by the paint system.

    * **`ScrollHitTestOrder`:** This test is about the order in which elements are considered for hit testing during scrolling. It sets up a nested scrolling container and checks the order of `DisplayItem`s and `PaintChunk`s, specifically looking for the scroll hit test elements.

    * **`NonStackingScrollHitTestOrder`:** Similar to the previous test, but with a non-stacking context (`z-index: auto`). This tests how hit testing works when elements don't create a new stacking context. The negative z-index element is crucial here.

    * **`StackingScrollHitTestOrder`:**  Similar to the above, but with a stacking context (`z-index: 0`). This tests the hit testing order in a stacking context, where elements with different z-indices are involved.

    * **`NonStackingScrollHitTestOrderWithoutBackground`:**  A variation of the non-stacking test where the scrolling container has a transparent background. This likely tests if the absence of a background affects the scroll hit test order.

    * **`PaintChunkIsSolidColor`:**  This test checks a specific optimization: whether the paint system correctly identifies when a paint chunk has a solid background color. It tests various background scenarios (solid color, text content, gradients, transparent backgrounds with children).

5. **Relate to Web Technologies (HTML, CSS, JavaScript):** For each test, consider how the tested scenario is triggered or influenced by web technologies:

    * **HTML:** The structure of the DOM, element IDs, and the nesting of elements are all defined in HTML. The tests use `SetBodyInnerHTML` to set up the HTML structure.
    * **CSS:**  CSS styles (`style` attribute or `<style>` tags) control the visual presentation (width, height, background color, opacity, overflow, `will-change`, `z-index`, etc.). These styles are the primary drivers for the painting behavior being tested.
    * **JavaScript:** While not directly present in *this* test file,  JavaScript can dynamically modify the DOM and CSS styles, which would trigger the paint operations being tested. The `setAttribute` call in `InlineRelayout` simulates a JavaScript-driven change.

6. **Consider User Actions and Debugging:** Think about how a user interaction in a browser could lead to the scenarios tested:

    * **Typing text:**  The `InlineRelayout` test is relevant when a user types text in an inline element, causing it to wrap.
    * **Resizing the window:**  Could trigger relayouts and repaints.
    * **Scrolling:** The `FrameScrollingContents` and `BlockScrollingNonLayeredContents` tests directly relate to scrolling actions.
    * **Mouse interaction:** The hit-testing tests (`ScrollHitTestOrder`, etc.) are crucial for correct behavior when a user clicks on a scrollable area.
    * **Dynamic style changes:** JavaScript animations or user interactions that change CSS properties like `opacity` or `z-index` can lead to the scenarios tested in other functions.

7. **Identify Potential Errors:** Based on the tests, think about common developer mistakes:

    * **Incorrectly assuming paint order:** The hit-testing tests highlight the importance of understanding how stacking contexts and z-index affect paint and hit-test order.
    * **Not considering scrolling performance:** The scrolling tests emphasize the need for efficient paint strategies to avoid jank during scrolling.
    * **Over-invalidating the paint cache:** The `ChunkIdClientCacheFlag` test suggests potential issues if the paint cache is not managed correctly.

8. **Refine and Organize:**  Structure the findings logically, grouping related functionalities together (e.g., tests related to scrolling, tests related to hit testing). Provide clear examples and explanations for each point.

This detailed breakdown, going from the high-level purpose of the file down to the specifics of each test and its implications, is the key to understanding the functionality of a complex piece of code like this Chromium test file.
这个文件 `paint_controller_paint_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `PaintController` 类的绘画 (paint) 相关功能。 `PaintController` 负责协调和管理渲染过程中将内容绘制到屏幕上的过程。

以下是该文件的主要功能点：

**1. 测试 PaintController 的核心绘画逻辑：**

   - 这个文件包含了一系列单元测试，用于验证 `PaintController` 在不同场景下是否正确地执行了绘画操作。
   - 它模拟了各种 HTML、CSS 结构和属性，并断言绘画操作的输出是否符合预期。
   - 这些测试覆盖了诸如元素布局变化、滚动、层叠上下文、背景绘制等多种绘画场景。

**2. 验证 DisplayItem 和 PaintChunk 的生成和管理：**

   - `DisplayItem` 是 Blink 中用于记录绘画操作的基本单元。
   - `PaintChunk` 是将相关的 `DisplayItem` 组合在一起的结构，用于优化绘画过程。
   - 这些测试会检查在不同的布局和样式变化后，`PaintController` 是否生成了正确的 `DisplayItem` 和 `PaintChunk`，以及它们的属性是否正确。

**3. 确保绘画顺序和层叠的正确性：**

   - CSS 的层叠 (stacking) 和绘画顺序 (painting order) 是渲染引擎中非常重要的概念。
   - 某些测试会专门验证在存在 `z-index`、`position` 等属性时，元素的绘画顺序是否符合 CSS 规范。

**4. 测试滚动相关的绘画优化：**

   - 浏览器需要高效地处理滚动事件，避免重新绘制整个页面。
   - 一些测试会模拟滚动场景，并验证 `PaintController` 是否进行了正确的裁剪 (culling) 和优化，只绘制可见区域的内容。

**5. 验证绘画缓存的有效性：**

   - Blink 使用缓存来避免不必要的重绘。
   - 一些测试会检查在某些操作后，绘画缓存是否正确地被标记为有效或无效。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件直接测试由 HTML、CSS 定义的视觉效果的渲染过程，并且某些测试会通过 JavaScript 操作 DOM 和 CSS 来触发渲染。

**举例说明：**

* **HTML:**  测试使用 `SetBodyInnerHTML` 来设置 HTML 结构，例如：
   ```c++
   SetBodyInnerHTML(
       "<div id='div' style='width:100px; height: 200px'>AAAAAAAAAA "
       "BBBBBBBBBB</div>");
   ```
   这个 HTML 创建了一个带有特定 ID 和样式的 `div` 元素。测试会观察 `PaintController` 如何绘制这个 `div` 及其包含的文本。

* **CSS:**  CSS 样式通过 `style` 属性或 `<style>` 标签应用，例如：
   ```c++
   div.setAttribute(html_names::kStyleAttr,
                    AtomicString("width: 10px; height: 200px"));
   ```
   或者在 HTML 中直接定义：
   ```html
   <div id='div' style='width: 200px; height: 200px; opacity: 0.5'>
       ...
   </div>
   ```
   测试会验证 `PaintController` 是否正确地处理了 `width`, `height`, `opacity`, `background-color`, `overflow`, `z-index`, `position` 等 CSS 属性对绘画的影响。

* **JavaScript:** 虽然这个测试文件本身是 C++ 代码，但它模拟了 JavaScript 对 DOM 和 CSS 的操作。例如，`InlineRelayout` 测试通过 `setAttribute` 修改了 `div` 的 `width` 属性，这相当于 JavaScript 代码修改元素样式。测试会验证这种修改后 `PaintController` 的行为。

**逻辑推理及假设输入与输出：**

以 `InlineRelayout` 测试为例：

* **假设输入:**
    * 初始 HTML: `<div id='div' style='width:100px; height: 200px'>AAAAAAAAAA BBBBBBBBBB</div>`
    * 初始布局：`div` 元素宽度为 100px，文本在一行内显示。
    * JavaScript 操作：将 `div` 的 `width` 修改为 10px。
* **逻辑推理:**  当 `div` 的宽度变小后，文本将无法在一行内显示，需要发生回流 (relayout) 并换行。`PaintController` 应该生成新的 `DisplayItem` 来表示换行后的文本布局。
* **预期输出:**
    * 在修改宽度之前，`ContentDisplayItems()` 应该只包含一个与文本相关的 `DisplayItem`。
    * 在修改宽度之后，`ContentDisplayItems()` 应该包含至少两个与文本相关的 `DisplayItem`，分别对应换行后的两部分文本。

**用户或编程常见的使用错误及举例说明：**

这个测试文件主要关注 Blink 引擎内部的实现，但它可以帮助开发者理解一些可能导致渲染问题的常见错误：

* **过度使用 `will-change`:** 虽然 `will-change` 可以提示浏览器进行优化，但过度使用可能会导致内存占用增加。某些测试可能会间接验证 `will-change` 对绘画过程的影响。
* **不理解层叠上下文:**  开发者可能会错误地设置 `z-index` 导致元素层叠顺序不符合预期。`StackingScrollHitTestOrder` 等测试验证了在不同层叠上下文下的绘画行为，有助于理解这些概念。
* **滚动性能问题:**  在处理大量内容滚动时，如果没有进行适当的优化，可能会导致页面卡顿。`FrameScrollingContents` 和 `BlockScrollingNonLayeredContents` 测试了滚动时的绘画优化，提醒开发者注意滚动性能。

**用户操作如何一步步到达这里作为调试线索：**

虽然用户不会直接与这个 C++ 测试文件交互，但以下用户操作可能会触发与 `PaintController` 相关的代码执行，从而可能暴露出 `PaintController` 中的 bug，最终导致开发者需要查看和调试这些测试：

1. **加载网页:** 当用户在浏览器中打开一个网页时，Blink 引擎会解析 HTML、CSS 并进行布局和绘画，`PaintController` 在这个过程中起着核心作用。
2. **滚动页面:** 用户滚动页面时，`PaintController` 需要决定哪些部分需要重绘。如果滚动过程中出现闪烁或性能问题，可能是 `PaintController` 的滚动优化存在问题。
3. **修改页面样式 (通过开发者工具或 JavaScript):** 用户或开发者通过开发者工具修改元素的 CSS 属性，或者 JavaScript 代码动态修改样式，都会触发重新布局和重绘，`PaintController` 会处理这些变化。
4. **进行文本编辑:** 在可编辑的区域输入或删除文本，会导致文本布局变化，需要 `PaintController` 更新文本的绘制。
5. **触发动画或过渡:** CSS 动画和过渡会导致元素属性的动态变化，`PaintController` 需要在每一帧更新元素的绘制。

**作为调试线索:**

当 Chromium 开发者在渲染过程中发现 bug 时，例如：

* **元素绘制不正确或消失。**
* **滚动时出现性能问题或视觉错误。**
* **元素的层叠顺序不符合预期。**

他们可能会：

1. **重现 Bug:** 尝试通过特定的用户操作或网页内容来重现该 bug。
2. **分析渲染流程:** 使用 Chromium 的开发者工具或其他调试手段来分析渲染流程，查看 `PaintController` 的行为。
3. **查找相关测试:** 在 `paint_controller_paint_test.cc` 中查找与该 bug 相关的测试场景。如果没有找到，可能需要添加新的测试用例来覆盖该 bug。
4. **运行测试:** 运行相关的测试用例，查看是否会失败。
5. **调试代码:** 如果测试失败，开发者会深入 `PaintController` 的代码中进行调试，找出 bug 的根源。
6. **修复 Bug 并添加测试:** 修复 bug 后，确保添加或修改测试用例，以防止该 bug 再次出现。

总而言之，`paint_controller_paint_test.cc` 是一个至关重要的测试文件，用于确保 Chromium Blink 引擎的绘画功能正确、高效地运行，涵盖了各种与 HTML、CSS 和用户交互相关的渲染场景。开发者可以通过分析这些测试用例来理解 `PaintController` 的工作原理，并作为调试渲染问题的线索。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_controller_paint_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"

#include "third_party/blink/renderer/core/editing/frame_caret.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"

using testing::_;
using testing::ElementsAre;

namespace blink {

INSTANTIATE_PAINT_TEST_SUITE_P(PaintControllerPaintTest);

TEST_P(PaintControllerPaintTest, InlineRelayout) {
  SetBodyInnerHTML(
      "<div id='div' style='width:100px; height: 200px'>AAAAAAAAAA "
      "BBBBBBBBBB</div>");
  auto& div = *To<Element>(GetDocument().body()->firstChild());
  auto& div_block =
      *To<LayoutBlock>(GetDocument().body()->firstChild()->GetLayoutObject());
  auto& text = *To<LayoutText>(div_block.FirstChild());
  InlineCursor cursor;
  cursor.MoveTo(text);
  const DisplayItemClient* first_text_box =
      cursor.Current().GetDisplayItemClient();
  wtf_size_t first_text_box_fragment_id = cursor.Current().FragmentId();

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(first_text_box->Id(), kForegroundType,
                                   first_text_box_fragment_id)));

  div.setAttribute(html_names::kStyleAttr,
                   AtomicString("width: 10px; height: 200px"));
  UpdateAllLifecyclePhasesForTest();

  cursor = InlineCursor();
  cursor.MoveTo(text);
  const DisplayItemClient* new_first_text_box =
      cursor.Current().GetDisplayItemClient();
  cursor.MoveToNextForSameLayoutObject();
  const DisplayItemClient* second_text_box =
      cursor.Current().GetDisplayItemClient();
  wtf_size_t second_text_box_fragment_id = cursor.Current().FragmentId();

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(new_first_text_box->Id(), kForegroundType,
                                   first_text_box_fragment_id),
                          IsSameId(second_text_box->Id(), kForegroundType,
                                   second_text_box_fragment_id)));
}

TEST_P(PaintControllerPaintTest, ChunkIdClientCacheFlag) {
  SetBodyInnerHTML(R"HTML(
    <div id='div' style='width: 200px; height: 200px; opacity: 0.5'>
      <div style='width: 100px; height: 100px; background-color:
    blue'></div>
      <div style='width: 100px; height: 100px; background-color:
    blue'></div>
    </div>
  )HTML");
  auto& div = *To<LayoutBlock>(GetLayoutObjectByElementId("div"));
  LayoutObject& sub_div = *div.FirstChild();
  LayoutObject& sub_div2 = *sub_div.NextSibling();

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(sub_div.Id(), kBackgroundType),
                          IsSameId(sub_div2.Id(), kBackgroundType)));

  EXPECT_FALSE(div.Layer()->IsJustCreated());
  // Client used by only paint chunks and non-cachaeable display items but not
  // by any cacheable display items won't be marked as validly cached.
  EXPECT_TRUE(ClientCacheIsValid(*div.Layer()));
  EXPECT_FALSE(ClientCacheIsValid(div));
  EXPECT_TRUE(ClientCacheIsValid(sub_div));
}

TEST_P(PaintControllerPaintTest, CompositingNoFold) {
  SetBodyInnerHTML(R"HTML(
    <div id='div' style='width: 200px; height: 200px; opacity: 0.5'>
      <div style='width: 100px; height: 100px; background-color:
    blue'></div>
    </div>
  )HTML");
  auto& div = *To<LayoutBlock>(GetLayoutObjectByElementId("div"));
  LayoutObject& sub_div = *div.FirstChild();

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(sub_div.Id(), kBackgroundType)));
}

TEST_P(PaintControllerPaintTest, FrameScrollingContents) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none }
      body { margin: 0; }
      div { position: absolute; width: 100px; height: 100px;
            background: blue; }
    </style>
    <div id='div1' style='top: 0'></div>
    <div id='div2' style='top: 3000px'></div>
    <div id='div3' style='top: 6000px'></div>
    <div id='div4' style='top: 9000px'></div>
  )HTML");

  const auto& div1 = To<LayoutBox>(*GetLayoutObjectByElementId("div1"));
  const auto& div2 = To<LayoutBox>(*GetLayoutObjectByElementId("div2"));
  const auto& div3 = To<LayoutBox>(*GetLayoutObjectByElementId("div3"));
  const auto& div4 = To<LayoutBox>(*GetLayoutObjectByElementId("div4"));

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(div1.Id(), kBackgroundType),
                          IsSameId(div2.Id(), kBackgroundType)));
  auto* view_scroll_hit_test = MakeGarbageCollected<HitTestData>();
  view_scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 800, 600);
  view_scroll_hit_test->scroll_translation =
      GetLayoutView().FirstFragment().PaintProperties()->ScrollTranslation();
  view_scroll_hit_test->scrolling_contents_cull_rect =
      gfx::Rect(0, 0, 800, 4600);
  EXPECT_THAT(
      GetPersistentData().GetPaintChunks()[0],
      IsPaintChunk(
          0, 0,
          PaintChunk::Id(GetLayoutView().Id(), DisplayItem::kScrollHitTest),
          GetLayoutView().FirstFragment().LocalBorderBoxProperties(),
          view_scroll_hit_test, gfx::Rect(0, 0, 800, 600)));
  auto contents_properties =
      GetLayoutView().FirstFragment().ContentsProperties();
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                          IsPaintChunk(1, 2,
                                       PaintChunk::Id(div1.Layer()->Id(),
                                                      DisplayItem::kLayerChunk),
                                       contents_properties),
                          IsPaintChunk(2, 3,
                                       PaintChunk::Id(div2.Layer()->Id(),
                                                      DisplayItem::kLayerChunk),
                                       contents_properties)));

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 5000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(div2.Id(), kBackgroundType),
                          IsSameId(div3.Id(), kBackgroundType),
                          IsSameId(div4.Id(), kBackgroundType)));
  view_scroll_hit_test->scrolling_contents_cull_rect =
      gfx::Rect(0, 1000, 800, 8100);
  EXPECT_THAT(
      GetPersistentData().GetPaintChunks()[0],
      IsPaintChunk(
          0, 0,
          PaintChunk::Id(GetLayoutView().Id(), DisplayItem::kScrollHitTest),
          GetLayoutView().FirstFragment().LocalBorderBoxProperties(),
          view_scroll_hit_test, gfx::Rect(0, 0, 800, 600)));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                          // html and div1 are out of the cull rect.
                          IsPaintChunk(1, 2,
                                       PaintChunk::Id(div2.Layer()->Id(),
                                                      DisplayItem::kLayerChunk),
                                       contents_properties),
                          IsPaintChunk(2, 3,
                                       PaintChunk::Id(div3.Layer()->Id(),
                                                      DisplayItem::kLayerChunk),
                                       contents_properties),
                          IsPaintChunk(3, 4,
                                       PaintChunk::Id(div4.Layer()->Id(),
                                                      DisplayItem::kLayerChunk),
                                       contents_properties)));
}

TEST_P(PaintControllerPaintTest, BlockScrollingNonLayeredContents) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none }
      body { margin: 0 }
      div { width: 100px; height: 100px; background: blue; }
      container { display: block; width: 200px; height: 200px;
                  overflow: scroll; will-change: transform; }
    </style>
    <container id='container'>
      <div id='div1'></div>
      <div id='div2' style='margin-top: 1200px; margin-left: 1300px'></div>
      <div id='div3' style='margin-top: 1200px; margin-left: 2600px'></div>
      <div id='div4' style='margin-top: 1200px; margin-left: 3900px;
                            width: 8000px; height: 8000px'></div>
    </container>
  )HTML");

  auto& container = *To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto& div1 = *GetLayoutObjectByElementId("div1");
  auto& div2 = *GetLayoutObjectByElementId("div2");
  auto& div3 = *GetLayoutObjectByElementId("div3");
  auto& div4 = *GetLayoutObjectByElementId("div4");

  EXPECT_EQ(gfx::Rect(0, 0, 2200, 2200),
            container.FirstFragment().GetContentsCullRect().Rect());
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(div1.Id(), kBackgroundType),
                          IsSameId(div2.Id(), kBackgroundType)));
  auto* container_scroll_hit_test = MakeGarbageCollected<HitTestData>();
  container_scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 200, 200);
  container_scroll_hit_test->scroll_translation =
      container.FirstFragment().PaintProperties()->ScrollTranslation();
  container_scroll_hit_test->scrolling_contents_cull_rect =
      gfx::Rect(0, 0, 2200, 2200);
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(
              1, 1,
              PaintChunk::Id(container.Layer()->Id(), DisplayItem::kLayerChunk),
              container.FirstFragment().LocalBorderBoxProperties(), nullptr,
              gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              1, 1, PaintChunk::Id(container.Id(), DisplayItem::kScrollHitTest),
              container.FirstFragment().LocalBorderBoxProperties(),
              container_scroll_hit_test, gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              1, 3,
              PaintChunk::Id(container.Id(),
                             RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
                                 ? kScrollingBackgroundChunkType
                                 : kClippedContentsBackgroundChunkType),
              container.FirstFragment().ContentsProperties())));

  container.GetScrollableArea()->SetScrollOffset(
      ScrollOffset(4000, 4000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(gfx::Rect(2000, 2000, 4200, 4200),
            container.FirstFragment().GetContentsCullRect().Rect());
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(div3.Id(), kBackgroundType),
                          IsSameId(div4.Id(), kBackgroundType)));
  container_scroll_hit_test->scrolling_contents_cull_rect =
      gfx::Rect(2000, 2000, 4200, 4200);
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(
              1, 1,
              PaintChunk::Id(container.Layer()->Id(), DisplayItem::kLayerChunk),
              container.FirstFragment().LocalBorderBoxProperties(), nullptr,
              gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              1, 1, PaintChunk::Id(container.Id(), DisplayItem::kScrollHitTest),
              container.FirstFragment().LocalBorderBoxProperties(),
              container_scroll_hit_test, gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              1, 3,
              PaintChunk::Id(container.Id(),
                             RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
                                 ? kScrollingBackgroundChunkType
                                 : kClippedContentsBackgroundChunkType),
              container.FirstFragment().ContentsProperties())));
}

TEST_P(PaintControllerPaintTest, ScrollHitTestOrder) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none }
      body { margin: 0 }
      #container { width: 200px; height: 200px;
                  overflow: scroll; background: red; }
      #child { width: 100px; height: 300px; background: green; }
      #forceDocumentScroll { height: 1000px; }
    </style>
    <div id='container'>
      <div id='child'></div>
    </div>
    <div id='forceDocumentScroll'/>
  )HTML");

  auto& container = *To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto& child = *GetLayoutObjectByElementId("child");

  // The container's items should all be after the document's scroll hit test
  // to ensure the container is hit before the document. Similarly, the child's
  // items should all be after the container's scroll hit test.
  EXPECT_THAT(
      ContentDisplayItems(),
      ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                  IsSameId(container.Id(), kBackgroundType),
                  IsSameId(container.GetScrollableArea()
                               ->GetScrollingBackgroundDisplayItemClient()
                               .Id(),
                           kBackgroundType),
                  IsSameId(child.Id(), kBackgroundType)));
  auto* view_scroll_hit_test = MakeGarbageCollected<HitTestData>();
  view_scroll_hit_test->scroll_translation =
      GetLayoutView().FirstFragment().PaintProperties()->ScrollTranslation();
  view_scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 800, 600);
  auto* container_scroll_hit_test = MakeGarbageCollected<HitTestData>();
  container_scroll_hit_test->scroll_translation =
      container.FirstFragment().PaintProperties()->ScrollTranslation();
  container_scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 200, 200);
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(1, 2,
                       PaintChunk::Id(container.Id(), kBackgroundChunkType),
                       container.FirstFragment().LocalBorderBoxProperties(),
                       nullptr, gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              2, 2, PaintChunk::Id(container.Id(), DisplayItem::kScrollHitTest),
              container.FirstFragment().LocalBorderBoxProperties(),
              container_scroll_hit_test, gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              2, 4,
              PaintChunk::Id(container.Id(), kScrollingBackgroundChunkType),
              container.FirstFragment().ContentsProperties()),
          // Hit test chunk for forceDocumentScroll.
          IsPaintChunk(4, 4)));
}

TEST_P(PaintControllerPaintTest, NonStackingScrollHitTestOrder) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none }
      body { margin: 0 }
      #container { width: 200px; height: 200px;
                  overflow: scroll; background: blue;
                  position: relative; z-index: auto; }
      #child { width: 80px; height: 20px; background: white; }
      #negZChild { width: 60px; height: 300px; background: purple;
                   position: absolute; z-index: -1; top: 0; }
      #posZChild { width: 40px; height: 300px; background: yellow;
                   position: absolute; z-index: 1; top: 0; }
    </style>
    <div id='container'>
      <div id='child'></div>
      <div id='negZChild'></div>
      <div id='posZChild'></div>
    </div>
  )HTML");

  auto& html = *GetDocument().documentElement()->GetLayoutBox();
  auto& container = *GetLayoutBoxByElementId("container");
  auto& child = *GetLayoutObjectByElementId("child");
  auto& neg_z_child = *GetLayoutBoxByElementId("negZChild");
  auto& pos_z_child = *GetLayoutBoxByElementId("posZChild");

  // Container is not a stacking context because no z-index is auto.
  // Negative z-index descendants are painted before the background and
  // positive z-index descendants are painted after the background. Scroll hit
  // testing should hit positive descendants, the container, and then negative
  // descendants so the scroll hit test should be immediately after the
  // background.
  EXPECT_THAT(
      ContentDisplayItems(),
      ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                  IsSameId(neg_z_child.Id(), kBackgroundType),
                  IsSameId(container.Id(), kBackgroundType),
                  IsSameId(container.GetScrollableArea()
                               ->GetScrollingBackgroundDisplayItemClient()
                               .Id(),
                           kBackgroundType),
                  IsSameId(child.Id(), kBackgroundType),
                  IsSameId(pos_z_child.Id(), kBackgroundType)));
  auto* container_scroll_hit_test = MakeGarbageCollected<HitTestData>();
  container_scroll_hit_test->scroll_translation =
      container.FirstFragment().PaintProperties()->ScrollTranslation();
  container_scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 200, 200);
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(1, 2,
                       PaintChunk::Id(neg_z_child.Layer()->Id(),
                                      DisplayItem::kLayerChunk),
                       neg_z_child.FirstFragment().LocalBorderBoxProperties()),
          IsPaintChunk(2, 2,
                       PaintChunk::Id(html.Layer()->Id(),
                                      DisplayItem::kLayerChunkForeground),
                       html.FirstFragment().LocalBorderBoxProperties(), nullptr,
                       gfx::Rect(0, 0, 800, 200)),
          IsPaintChunk(
              2, 3,
              PaintChunk::Id(container.Layer()->Id(), DisplayItem::kLayerChunk),
              container.FirstFragment().LocalBorderBoxProperties(), nullptr,
              gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              3, 3, PaintChunk::Id(container.Id(), DisplayItem::kScrollHitTest),
              container.FirstFragment().LocalBorderBoxProperties(),
              container_scroll_hit_test, gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              3, 5,
              PaintChunk::Id(container.Id(), kScrollingBackgroundChunkType),
              container.FirstFragment().ContentsProperties()),
          IsPaintChunk(
              5, 6,
              PaintChunk::Id(pos_z_child.Layer()->Id(),
                             DisplayItem::kLayerChunk),
              pos_z_child.FirstFragment().LocalBorderBoxProperties())));
}

TEST_P(PaintControllerPaintTest, StackingScrollHitTestOrder) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none }
      body { margin: 0 }
      #container { width: 200px; height: 200px;
                  overflow: scroll; background: blue;
                  position: relative; z-index: 0; }
      #child { width: 80px; height: 20px; background: white; }
      #negZChild { width: 60px; height: 300px; background: purple;
                   position: absolute; z-index: -1; top: 0; }
      #posZChild { width: 40px; height: 300px; background: yellow;
                   position: absolute; z-index: 1; top: 0; }
    </style>
    <div id='container'>
      <div id='child'></div>
      <div id='negZChild'></div>
      <div id='posZChild'></div>
    </div>
  )HTML");

  auto& container = *GetLayoutBoxByElementId("container");
  auto& child = *GetLayoutObjectByElementId("child");
  auto& neg_z_child = *GetLayoutBoxByElementId("negZChild");
  auto& pos_z_child = *GetLayoutBoxByElementId("posZChild");

  // Container is a stacking context because z-index is non-auto.
  // Both positive and negative z-index descendants are painted after the
  // background. The scroll hit test should be after the background but before
  // the z-index descendants to ensure hit test order is correct.
  EXPECT_THAT(
      ContentDisplayItems(),
      ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                  IsSameId(container.Id(), kBackgroundType),
                  IsSameId(container.GetScrollableArea()
                               ->GetScrollingBackgroundDisplayItemClient()
                               .Id(),
                           kBackgroundType),
                  IsSameId(neg_z_child.Id(), kBackgroundType),
                  IsSameId(child.Id(), kBackgroundType),
                  IsSameId(pos_z_child.Id(), kBackgroundType)));
  auto* container_scroll_hit_test = MakeGarbageCollected<HitTestData>();
  container_scroll_hit_test->scroll_translation =
      container.FirstFragment().PaintProperties()->ScrollTranslation();
  container_scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 200, 200);
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(
              1, 2,
              PaintChunk::Id(container.Layer()->Id(), DisplayItem::kLayerChunk),
              container.FirstFragment().LocalBorderBoxProperties(), nullptr,
              gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              2, 2, PaintChunk::Id(container.Id(), DisplayItem::kScrollHitTest),
              container.FirstFragment().LocalBorderBoxProperties(),
              container_scroll_hit_test, gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              2, 3,
              PaintChunk::Id(container.Id(), kScrollingBackgroundChunkType),
              container.FirstFragment().ContentsProperties()),
          IsPaintChunk(3, 4,
                       PaintChunk::Id(neg_z_child.Layer()->Id(),
                                      DisplayItem::kLayerChunk),
                       neg_z_child.FirstFragment().LocalBorderBoxProperties()),
          IsPaintChunk(4, 5,
                       PaintChunk::Id(container.Id(),
                                      kClippedContentsBackgroundChunkType),
                       container.FirstFragment().ContentsProperties()),
          IsPaintChunk(
              5, 6,
              PaintChunk::Id(pos_z_child.Layer()->Id(),
                             DisplayItem::kLayerChunk),
              pos_z_child.FirstFragment().LocalBorderBoxProperties())));
}

TEST_P(PaintControllerPaintTest,
       NonStackingScrollHitTestOrderWithoutBackground) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none }
      body { margin: 0 }
      #container { width: 200px; height: 200px;
                  overflow: scroll; background: transparent;
                  position: relative; z-index: auto; }
      #child { width: 80px; height: 20px; background: white; }
      #negZChild { width: 60px; height: 300px; background: purple;
                   position: absolute; z-index: -1; top: 0; }
      #posZChild { width: 40px; height: 300px; background: yellow;
                   position: absolute; z-index: 1; top: 0; }
    </style>
    <div id='container'>
      <div id='child'></div>
      <div id='negZChild'></div>
      <div id='posZChild'></div>
    </div>
  )HTML");

  auto& html = *GetDocument().documentElement()->GetLayoutBox();
  auto& container = *GetLayoutBoxByElementId("container");
  auto& child = *GetLayoutObjectByElementId("child");
  auto& neg_z_child = *GetLayoutBoxByElementId("negZChild");
  auto& pos_z_child = *GetLayoutBoxByElementId("posZChild");

  // Even though container does not paint a background, the scroll hit test
  // should still be between the negative z-index child and the regular child.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(neg_z_child.Id(), kBackgroundType),
                          IsSameId(child.Id(), kBackgroundType),
                          IsSameId(pos_z_child.Id(), kBackgroundType)));
  auto* container_scroll_hit_test = MakeGarbageCollected<HitTestData>();
  container_scroll_hit_test->scroll_translation =
      container.FirstFragment().PaintProperties()->ScrollTranslation();
  container_scroll_hit_test->scroll_hit_test_rect = gfx::Rect(0, 0, 200, 200);
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(1, 2,
                       PaintChunk::Id(neg_z_child.Layer()->Id(),
                                      DisplayItem::kLayerChunk),
                       neg_z_child.FirstFragment().LocalBorderBoxProperties()),
          IsPaintChunk(2, 2,
                       PaintChunk::Id(html.Layer()->Id(),
                                      DisplayItem::kLayerChunkForeground),
                       html.FirstFragment().LocalBorderBoxProperties(), nullptr,
                       gfx::Rect(0, 0, 800, 200)),
          IsPaintChunk(
              2, 2,
              PaintChunk::Id(container.Layer()->Id(), DisplayItem::kLayerChunk),
              container.FirstFragment().LocalBorderBoxProperties(), nullptr,
              gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              2, 2, PaintChunk::Id(container.Id(), DisplayItem::kScrollHitTest),
              container.FirstFragment().LocalBorderBoxProperties(),
              container_scroll_hit_test, gfx::Rect(0, 0, 200, 200)),
          IsPaintChunk(
              2, 3,
              PaintChunk::Id(container.Id(),
                             RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
                                 ? kScrollingBackgroundChunkType
                                 : kClippedContentsBackgroundChunkType),
              container.FirstFragment().ContentsProperties()),
          IsPaintChunk(
              3, 4,
              PaintChunk::Id(pos_z_child.Layer()->Id(),
                             DisplayItem::kLayerChunk),
              pos_z_child.FirstFragment().LocalBorderBoxProperties())));
}

TEST_P(PaintControllerPaintTest, PaintChunkIsSolidColor) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .target {
        width: 50px;
        height: 50px;
        background-color: blue;
        position: relative;
      }
    </style>
    <div id="target1" class="target"></div>
    <div id="target2" class="target">TEXT</div>
    <div id="target3" class="target"
         style="background-image: linear-gradient(red, blue)"></div>
    <div id="target4" class="target" style="background-color: transparent">
      <div style="width: 200px; height: 40px; background: blue"></div>
    </div>
    <div id="target5" class="target" style="background-color: transparent">
      <div style="width: 200px; height: 60px; background: blue"></div>
    </div>
  )HTML");

  auto chunks = ContentPaintChunks();
  ASSERT_EQ(6u, chunks.size());
  // View background.
  EXPECT_TRUE(chunks[0].background_color.is_solid_color);
  EXPECT_EQ(SkColors::kWhite, chunks[0].background_color.color);
  // target1.
  EXPECT_TRUE(chunks[1].background_color.is_solid_color);
  EXPECT_EQ(SkColors::kBlue, chunks[1].background_color.color);
  // target2.
  EXPECT_FALSE(chunks[2].background_color.is_solid_color);
  EXPECT_EQ(SkColors::kBlue, chunks[2].background_color.color);
  // target3.
  EXPECT_FALSE(chunks[3].background_color.is_solid_color);
  EXPECT_EQ(SkColors::kBlue, chunks[3].background_color.color);
  // target4.
  EXPECT_FALSE(chunks[4].background_color.is_solid_color);
  EXPECT_EQ(SkColors::kBlue, chunks[4].background_color.color);
  // target5.
  EXPECT_TRUE(chunks[5].background_color.is_solid_color);
  EXPECT_EQ(SkColors::kBlue, chunks[5].background_color.color);
}

}  // namespace blink

"""

```