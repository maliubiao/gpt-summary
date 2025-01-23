Response:
Let's break down the thought process for analyzing the `block_painter_test.cc` file.

1. **Identify the Core Purpose:** The filename `block_painter_test.cc` immediately suggests this is a testing file. The `_test.cc` suffix is a strong convention in C++ projects. The `block_painter` part hints at the area of code being tested: the rendering of block-level elements.

2. **Examine the Includes:** The included headers provide valuable context:
    * `base/test/scoped_feature_list.h`: Likely for enabling/disabling Chromium features during tests.
    * `cc/base/features.h`:  Related to Chromium Compositor (cc) features. This suggests the testing might involve how painting interacts with the compositor.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`: Confirms this is a unit testing file using Google Test and Google Mock frameworks.
    * `third_party/blink/renderer/core/frame/local_frame_view.h`: Implies interaction with the frame structure of a web page.
    * `third_party/blink/renderer/core/paint/paint_controller_paint_test.h`: This is a key include, indicating the test suite builds upon a more general paint testing framework.
    * `third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h` and `third_party/blink/renderer/platform/graphics/paint/paint_chunk.h`: These point to the core data structures used in Blink's paint system. Display items represent individual paint operations, and paint chunks group them.
    * `third_party/blink/renderer/platform/testing/paint_property_test_helpers.h`:  Suggests helper functions for asserting properties of paint objects.

3. **Analyze the Test Suite Setup:**
    * `using BlockPainterTest = PaintControllerPaintTest;`:  The test suite is aliased to `BlockPainterTest`, but it's actually using the more general `PaintControllerPaintTest` framework. The comment `// TODO(1229581): Rename this. It's not testing BlockPainter anymore.` is crucial. It reveals that the test suite's name is a bit misleading and its scope has likely broadened.
    * `INSTANTIATE_PAINT_TEST_SUITE_P(BlockPainterTest);`: This is a Google Test macro that likely allows running the tests with different parameterizations (the `P` likely stands for parameterized). This isn't directly about the *functionality* being tested, but how the tests are structured.

4. **Examine Individual Tests:**  This is where the real understanding of the functionality comes in. Look for the `TEST_P` macro, which defines individual test cases. Analyze the name of each test and the code within it.
    * **`BlockingWheelRectsWithoutPaint`:**  Focuses on scenarios where adding or removing a wheel event listener affects the "hit test data" (rectangles where the browser checks for wheel events). The "without paint" part suggests it's testing whether this data is updated even without a full repaint.
    * **`BlockingWheelEventRectSubsequenceCaching` and `WheelEventRectPaintCaching`:** These test caching mechanisms related to wheel event rectangles. `SubsequenceCaching` checks if entire sequences of paint operations can be reused. `PaintCaching` checks if individual paint items related to wheel events are cached correctly when other parts of the page change.
    * **`BlockingWheelRectOverflowingContents` and `BlockingWheelRectScrollingContents`:** Explore how wheel event hit test rectangles are calculated for elements with overflowing content and scrollable elements, respectively.
    * **`WheelEventRectPaintChunkChanges`:** Tests how paint chunks (groups of paint operations) are affected when wheel event listeners are added or removed.
    * The tests related to `TouchActionRects` and `TouchHandlerRects` follow a similar pattern, but focus on touch interactions and the `touch-action` CSS property. They examine the generation and caching of hit test data for touch events.
    * **`ScrolledHitTestChunkProperties`:**  Specifically checks the properties of paint chunks for scrollable elements that have touch actions defined, paying attention to how scrolling transforms are applied to the hit test areas.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**  As you analyze the tests, look for how they relate to web standards.
    * **HTML:** The `SetBodyInnerHTML` function is used extensively to create HTML structures for testing. The tests manipulate HTML attributes like `id`, `class`, and `style`.
    * **CSS:**  CSS properties like `width`, `height`, `visibility`, `display`, `position`, `z-index`, `overflow`, `touch-action`, and `background-color` are used to style the test elements and trigger different rendering behaviors.
    * **JavaScript:** The `SetWheelEventListener` function demonstrates the connection to JavaScript event handling. The tests check how adding JavaScript event listeners affects the paint process.

6. **Infer Logical Reasoning and Assumptions:**  Based on the test names and code, you can deduce the underlying logic being tested. For example, the caching tests assume that reusing previous paint information can improve performance. The tests involving `visibility: hidden` and `display: none` make assumptions about how these CSS properties affect hit testing.

7. **Identify Potential User/Programming Errors:** Consider how a web developer might misuse these features and how the tests might catch those errors. For instance, forgetting to set `touch-action: none` on a draggable element could lead to unexpected scrolling behavior.

8. **Trace User Operations (Debugging Clues):** Think about the user interactions that might lead to the code being executed. Scrolling with a mouse wheel or touching the screen are direct triggers for the scenarios tested here. The tests involving `visibility: hidden` and `display: none` highlight how those CSS properties affect interaction.

9. **Structure the Output:** Organize the findings into clear categories like "Functionality," "Relationship to Web Technologies," "Logical Reasoning," "User Errors," and "Debugging Clues." Use examples from the code to illustrate each point.

**Self-Correction/Refinement During Analysis:**

* **Initial Assumption Correction:** Initially, I might have focused heavily on the `BlockPainter`. However, the comment and the variety of tests related to scrolling and touch events quickly indicate that the test suite's scope is broader than just block painting.
* **Clarifying Terminology:** I need to be precise with terms like "paint chunks," "display items," and "hit test data."  Referring back to the included headers helps here.
* **Connecting the Dots:**  Realizing that the `HitTestData` structure is central to how the tests verify the effects of wheel and touch events is important. Understanding what information this structure holds (e.g., `wheel_event_rects`, `touch_action_rects`) is key.
* **Iterative Understanding:** My understanding deepens as I go through more tests. For example, after seeing the wheel event tests, the touch event tests become easier to grasp because they follow a similar pattern.

By following this systematic approach, combining code analysis with knowledge of web technologies and testing principles, one can effectively understand the purpose and implications of a file like `block_painter_test.cc`.
这个文件 `block_painter_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试与块级元素绘制相关的代码。 尽管文件名中包含 `BlockPainter`，但根据代码中的注释 `// TODO(1229581): Rename this. It's not testing BlockPainter anymore.`，我们可以知道它实际上已经扩展到测试更广泛的绘制相关功能，尤其关注与事件处理（例如鼠标滚轮事件、触摸事件）相关的 hit-testing 行为。

以下是该文件的功能列表：

1. **测试鼠标滚轮事件的阻挡区域 (Blocking Wheel Rects):**
   - 验证当元素上添加了会阻止默认滚轮行为的事件监听器时，渲染引擎是否正确地记录了这些元素及其子元素的区域，以便进行 hit-testing。
   - 测试了不同 visibility 和 display 属性的子元素是否会被正确包含或排除在阻挡区域之外。
   - 验证了添加和移除事件监听器后，hit-testing 数据是否会相应更新。
   - 测试了阻挡滚轮事件的元素的溢出内容是否也被包含在 hit-testing 区域内。
   - 测试了可滚动元素的阻挡滚轮事件区域的计算。
   - 测试了与滚轮事件相关的 paint chunk 是否会根据事件监听器的添加或移除而发生变化。
   - 测试了滚轮事件阻挡区域的缓存机制，以避免不必要的重新计算。

2. **测试触摸动作区域 (Touch Action Rects):**
   - 验证当元素设置了 `touch-action` CSS 属性时，渲染引擎是否正确地记录了这些元素及其子元素的区域，用于确定如何处理触摸事件。
   - 测试了不同 `touch-action` 属性值（例如 `none`, `pinch-zoom`）对 hit-testing 区域的影响。
   - 验证了添加和移除 `touch-action` 属性后，hit-testing 数据是否会相应更新。
   - 测试了可滚动元素中 `touch-action` 区域的计算。
   - 测试了与触摸动作相关的 paint chunk 是否会根据 `touch-action` 属性的改变而发生变化。
   - 测试了触摸动作区域的缓存机制。

3. **测试触摸处理程序区域 (Touch Handler Rects):**
   - 验证当元素上添加了触摸事件监听器（例如 `touchstart`) 时，渲染引擎是否正确地记录了这些元素及其子元素的区域，用于进行 hit-testing。
   - 测试了添加和移除触摸事件监听器后，hit-testing 数据是否会相应更新。

4. **测试跨绘制变化的触摸动作区域 (Touch Action Rects Across Paint Changes):**
   - 验证在发生绘制变化（例如，修改元素的背景色）时，与 `touch-action` 相关的 hit-testing 数据是否仍然正确。

5. **测试滚动元素的 Hit-Test Chunk 属性 (Scrolled HitTest Chunk Properties):**
   - 验证对于设置了 `touch-action` 的可滚动元素，其 hit-test 相关的 paint chunk 的属性是否正确，特别是与滚动相关的变换 (transform) 是否被正确应用。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关联了 JavaScript 的事件处理机制、HTML 的元素结构以及 CSS 的样式属性。

**举例说明：**

* **JavaScript:** `SetWheelEventListener("parent")` 函数模拟了在 ID 为 `parent` 的元素上添加滚轮事件监听器。这会触发引擎计算该元素及其子元素的滚轮事件阻挡区域。
* **HTML:**  `SetBodyInnerHTML(R"HTML(...)HTML")` 函数用于设置测试页面的 HTML 结构，包括各种 `div` 元素，并设置它们的 ID 和类名。测试会根据这些 HTML 结构来验证绘制和 hit-testing 的行为。例如，`#parent`, `#childVisible`, `#childHidden`, `#childDisplayNone` 等元素用于测试不同可见性状态下的 hit-testing。
* **CSS:**  `<style>` 标签内的 CSS 规则定义了元素的样式，例如 `width`, `height`, `visibility`, `display`, `touch-action` 等。测试会验证这些 CSS 属性如何影响绘制和 hit-testing。例如，`touch-action: none;` 用于指定元素不应响应任何触摸手势。

**逻辑推理、假设输入与输出：**

**假设输入（对于 `BlockingWheelRectsWithoutPaint` 测试）：**

```html
<div id='parent'>
  <div id='childVisible'></div>
  <div id='childHidden'></div>
</div>
```

初始状态，没有滚轮事件监听器。

**输出：**

ContentPaintChunks() 应该只包含 `VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON`，表示没有特殊的 hit-testing 数据。

**假设输入（对于 `BlockingWheelRectsWithoutPaint` 测试，添加事件监听器后）：**

使用 JavaScript `SetWheelEventListener("parent");` 添加滚轮事件监听器到 `#parent` 元素。

**输出：**

ContentPaintChunks() 应该包含一个带有 `HitTestData` 的 `VIEW_SCROLLING_BACKGROUND_CHUNK`，其中 `wheel_event_rects` 包含 `#parent` 和 `#childVisible` 的矩形区域，但不包含 `#childHidden`（因为 `visibility: hidden`）。

**用户或编程常见的使用错误：**

1. **忘记设置 `touch-action: none` 导致意外的滚动或缩放：**  开发者可能希望禁用某个区域的触摸滚动或缩放，但忘记设置 `touch-action: none`，导致用户在该区域进行触摸操作时仍然会触发滚动或缩放。这个测试文件中的相关测试可以帮助发现这种错误，因为如果 `touch-action` 没有被正确处理，hit-testing 数据就不会包含预期的区域。

   **示例：**

   ```html
   <div id="draggable" style="width: 100px; height: 100px; background: red; position: absolute;"></div>
   <script>
     document.getElementById('draggable').addEventListener('touchstart', (e) => { /* 开始拖动逻辑 */ });
     document.getElementById('draggable').addEventListener('touchmove', (e) => { /* 拖动逻辑 */ });
     document.getElementById('draggable').addEventListener('touchend', (e) => { /* 结束拖动逻辑 */ });
   </script>
   ```

   如果开发者忘记添加 `touch-action: none;` 到 `#draggable` 的样式中，用户在尝试拖动元素时，可能会意外触发页面的滚动。

2. **错误地假设 `visibility: hidden` 的元素不会接收任何事件：** 开发者可能认为设置了 `visibility: hidden` 的元素完全不会参与事件处理。虽然这些元素在视觉上是隐藏的，但它们仍然可以接收某些事件，并可能影响 hit-testing。这个测试文件验证了 `visibility: hidden` 的元素不会被包含在滚轮事件的阻挡区域内，帮助开发者理解其行为。

3. **依赖默认的滚轮行为而没有添加必要的事件监听器：**  开发者可能期望某个区域能够滚动，但忘记添加相应的事件监听器或者设置 `overflow` 属性。这个测试文件虽然不直接测试这种情况，但它强调了事件监听器和 hit-testing 之间的关系。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户滚动页面 (鼠标滚轮或触控板)：** 当用户使用鼠标滚轮或触控板滚动页面时，浏览器会触发滚轮事件。浏览器需要确定哪个元素应该处理这个事件。`BlockingWheelRectsWithoutPaint` 等测试确保了当页面上有元素通过 JavaScript 添加了滚轮事件监听器时，浏览器能正确识别这些元素及其子元素的区域，以便进行事件分发。

2. **用户触摸屏幕进行交互 (触摸或滑动)：** 当用户触摸屏幕时，浏览器会触发各种触摸事件 (例如 `touchstart`, `touchmove`, `touchend`)。`TouchActionRectsWithoutPaint` 和 `TouchHandlerRectsWithoutPaint` 等测试确保了浏览器能正确识别设置了 `touch-action` 属性或添加了触摸事件监听器的元素区域，以便正确处理触摸手势，例如阻止滚动或允许缩放。

3. **页面布局或样式发生变化：** 当页面的 HTML 结构或 CSS 样式发生变化时，渲染引擎需要重新计算页面的布局和绘制信息。`TouchActionRectsAcrossPaintChanges` 等测试确保了即使在发生绘制变化后，与事件处理相关的 hit-testing 数据仍然保持正确。

**调试线索：**

如果开发者在实现自定义的滚动或触摸交互时遇到问题，例如：

* 滚轮事件没有在预期的元素上触发。
* 触摸手势没有按预期工作（例如，本应禁止滚动的区域仍然可以滚动）。
* 在动态修改页面结构或样式后，事件处理出现异常。

那么，就可以参考 `block_painter_test.cc` 中的测试用例，来理解 Blink 引擎是如何处理这些情况的。例如，可以关注以下几点：

* **检查是否有元素意外地阻止了事件传播：** 某些事件监听器可能会阻止事件冒泡或捕获，导致事件无法到达预期的目标元素。
* **检查 `touch-action` 属性的设置是否正确：** 确保在需要自定义触摸行为的元素上正确设置了 `touch-action` 属性。
* **检查元素的 `visibility` 和 `display` 属性：** 这些属性会影响元素的可见性和是否参与布局和事件处理。
* **利用浏览器的开发者工具查看事件监听器：** 开发者工具可以显示元素上注册的事件监听器，帮助理解事件是如何被处理的。

总之，`block_painter_test.cc` 是一个重要的测试文件，它验证了 Blink 引擎在处理与块级元素绘制相关的事件 hit-testing 逻辑的正确性，涵盖了鼠标滚轮事件和触摸事件，并与 JavaScript、HTML 和 CSS 的功能紧密相关。通过分析这些测试用例，开发者可以更好地理解浏览器引擎的工作原理，并避免常见的用户或编程错误。

### 提示词
```
这是目录为blink/renderer/core/paint/block_painter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"
#include "cc/base/features.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_chunk.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"

using testing::ElementsAre;

namespace blink {

// TODO(1229581): Rename this. It's not testing BlockPainter anymore.
using BlockPainterTest = PaintControllerPaintTest;

INSTANTIATE_PAINT_TEST_SUITE_P(BlockPainterTest);

TEST_P(BlockPainterTest, BlockingWheelRectsWithoutPaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body { margin: 0; }
      #parent { width: 100px; height: 100px; }
      #childVisible { width: 200px; height: 25px; }
      #childHidden { width: 200px; height: 30px; visibility: hidden; }
      #childDisplayNone { width: 200px; height: 30px; display: none; }
    </style>
    <div id='parent'>
      <div id='childVisible'></div>
      <div id='childHidden'></div>
    </div>
  )HTML");

  // Initially there should be no hit test data because there is no blocking
  // wheel handler.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));

  // Add a blocking wheel event handler to parent and ensure that hit test data
  // are created for both the parent and the visible child.
  SetWheelEventListener("parent");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->wheel_event_rects = {{gfx::Rect(0, 0, 100, 100)},
                                      {gfx::Rect(0, 0, 200, 25)}};
  ContentPaintChunks(),
      ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(1, hit_test_data));

  // Remove the blocking wheel event handler from parent and ensure no hit test
  // data are left.
  auto* parent_element = GetElementById("parent");
  parent_element->RemoveAllEventListeners();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));
}

TEST_P(BlockPainterTest, BlockingWheelEventRectSubsequenceCaching) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #stacking-context {
        position: absolute;
        z-index: 1;
      }
      #wheelhandler {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='stacking-context'>
      <div id='wheelhandler'></div>
    </div>
  )HTML");

  SetWheelEventListener("wheelhandler");

  const auto* wheelhandler = GetLayoutObjectByElementId("wheelhandler");
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  const auto& hit_test_client = *GetPaintLayerByElementId("stacking-context");
  EXPECT_SUBSEQUENCE_FROM_CHUNK(hit_test_client,
                                ContentPaintChunks().begin() + 1, 1);

  PaintChunk::Id hit_test_chunk_id(hit_test_client.Id(),
                                   DisplayItem::kLayerChunk);
  auto hit_test_chunk_properties = wheelhandler->EnclosingLayer()
                                       ->GetLayoutObject()
                                       .FirstFragment()
                                       .ContentsProperties();
  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->wheel_event_rects = {{gfx::Rect(0, 0, 100, 100)}};

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                          IsPaintChunk(1, 1, hit_test_chunk_id,
                                       hit_test_chunk_properties, hit_test_data,
                                       gfx::Rect(0, 0, 100, 100))));

  // Trigger a repaint with the whole stacking-context subsequence cached.
  GetLayoutView().Layer()->SetNeedsRepaint();
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1u, counter.num_cached_items);
  EXPECT_EQ(1u, counter.num_cached_subsequences);

  EXPECT_SUBSEQUENCE_FROM_CHUNK(hit_test_client,
                                ContentPaintChunks().begin() + 1, 1);

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                          IsPaintChunk(1, 1, hit_test_chunk_id,
                                       hit_test_chunk_properties, hit_test_data,
                                       gfx::Rect(0, 0, 100, 100))));
}

TEST_P(BlockPainterTest, WheelEventRectPaintCaching) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #wheelhandler {
        width: 100px;
        height: 100px;
      }
      #sibling {
        width: 100px;
        height: 100px;
        background: blue;
      }
    </style>
    <div id='wheelhandler'></div>
    <div id='sibling'></div>
  )HTML");

  SetWheelEventListener("wheelhandler");

  auto* sibling_element = GetElementById("sibling");
  const auto* sibling = sibling_element->GetLayoutObject();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(sibling->Id(), kBackgroundType)));

  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->wheel_event_rects = {{gfx::Rect(0, 0, 100, 100)}};

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(2, hit_test_data)));

  sibling_element->setAttribute(html_names::kStyleAttr,
                                AtomicString("background: green;"));
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();
  // Only the background display item of the sibling should be invalidated.
  EXPECT_EQ(1u, counter.num_cached_items);

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(2, hit_test_data)));
}

TEST_P(BlockPainterTest, BlockingWheelRectOverflowingContents) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #parent {
        width: 100px;
        height: 100px;
        background-color: blue;
        position: absolute;
      }
      #child {
        width: 10px;
        height: 400px;
      }
    </style>
    <div id='parent'>
      <div id='child'></div>
    </div>
  )HTML");

  SetWheelEventListener("parent");

  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->wheel_event_rects = {gfx::Rect(0, 0, 100, 100),
                                      gfx::Rect(0, 0, 10, 400)};
  auto* parent = GetLayoutBoxByElementId("parent");
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                  IsPaintChunk(1, 2,
                               PaintChunk::Id(parent->Layer()->Id(),
                                              DisplayItem::kLayerChunk),
                               parent->FirstFragment().ContentsProperties(),
                               hit_test_data, gfx::Rect(0, 0, 100, 400))));
}

TEST_P(BlockPainterTest, BlockingWheelRectScrollingContents) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body { margin: 0; }
      #scroller {
        width: 100px;
        height: 100px;
        overflow: scroll;
        will-change: transform;
        background-color: blue;
      }
      #child {
        width: 10px;
        height: 400px;
      }
    </style>
    <div id='scroller'>
      <div id='child'></div>
    </div>
  )HTML");

  auto* scroller_element = GetElementById("scroller");
  auto* scroller =
      To<LayoutBoxModelObject>(scroller_element->GetLayoutObject());
  const auto& scroller_scrolling_client =
      scroller->GetScrollableArea()->GetScrollingBackgroundDisplayItemClient();

  SetWheelEventListener("scroller");

  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->wheel_event_rects = {gfx::Rect(0, 0, 100, 400)};
  EXPECT_THAT(
      ContentDisplayItems(),
      ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                  IsSameId(scroller->Id(), kBackgroundType),
                  IsSameId(scroller_scrolling_client.Id(), kBackgroundType)));
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(1, 2),  // scroller background.
          IsPaintChunk(2, 2),  // scroller scroll hit test.
          IsPaintChunk(
              2, 3,
              PaintChunk::Id(scroller->Id(), kScrollingBackgroundChunkType),
              scroller->FirstFragment().ContentsProperties(), hit_test_data)));
}

TEST_P(BlockPainterTest, WheelEventRectPaintChunkChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #wheelevent {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='wheelevent'></div>
  )HTML");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));

  SetWheelEventListener("wheelevent");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->wheel_event_rects = {{gfx::Rect(0, 0, 100, 100)}};

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(1, hit_test_data)));

  GetElementById("wheelevent")->RemoveAllEventListeners();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));
}

TEST_P(BlockPainterTest, TouchActionRectsWithoutPaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body { margin: 0; }
      #parent { width: 100px; height: 100px; }
      .touchActionNone { touch-action: none; }
      #childVisible { width: 200px; height: 25px; }
      #childHidden { width: 200px; height: 30px; visibility: hidden; }
      #childDisplayNone { width: 200px; height: 30px; display: none; }
    </style>
    <div id='parent'>
      <div id='childVisible'></div>
      <div id='childHidden'></div>
    </div>
  )HTML");

  // Initially there should be no hit test data because there is no touch
  // action.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));

  // Add a touch action to parent and ensure that hit test data are created
  // for both the parent and the visible child.
  auto* parent_element = GetElementById("parent");
  parent_element->setAttribute(html_names::kClassAttr,
                               AtomicString("touchActionNone"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->touch_action_rects = {{gfx::Rect(0, 0, 100, 100)},
                                       {gfx::Rect(0, 0, 200, 25)}};
  ContentPaintChunks(),
      ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(1, hit_test_data));

  // Remove the touch action from parent and ensure no hit test data are left.
  parent_element->removeAttribute(html_names::kClassAttr);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));
}

TEST_P(BlockPainterTest, TouchActionRectSubsequenceCaching) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #stacking-context {
        position: absolute;
        z-index: 1;
      }
      #touchaction {
        width: 100px;
        height: 100px;
        touch-action: none;
      }
    </style>
    <div id='stacking-context'>
      <div id='touchaction'></div>
    </div>
  )HTML");

  const auto* touchaction = GetLayoutObjectByElementId("touchaction");
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  const auto& hit_test_client = *GetPaintLayerByElementId("stacking-context");
  EXPECT_SUBSEQUENCE_FROM_CHUNK(hit_test_client,
                                ContentPaintChunks().begin() + 1, 1);

  PaintChunk::Id hit_test_chunk_id(hit_test_client.Id(),
                                   DisplayItem::kLayerChunk);
  auto hit_test_chunk_properties = touchaction->EnclosingLayer()
                                       ->GetLayoutObject()
                                       .FirstFragment()
                                       .ContentsProperties();
  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->touch_action_rects = {{gfx::Rect(0, 0, 100, 100)}};

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                          IsPaintChunk(1, 1, hit_test_chunk_id,
                                       hit_test_chunk_properties, hit_test_data,
                                       gfx::Rect(0, 0, 100, 100))));

  // Trigger a repaint with the whole stacking-context subsequence cached.
  GetLayoutView().Layer()->SetNeedsRepaint();
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1u, counter.num_cached_items);
  EXPECT_EQ(1u, counter.num_cached_subsequences);

  EXPECT_SUBSEQUENCE_FROM_CHUNK(hit_test_client,
                                ContentPaintChunks().begin() + 1, 1);

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
                          IsPaintChunk(1, 1, hit_test_chunk_id,
                                       hit_test_chunk_properties, hit_test_data,
                                       gfx::Rect(0, 0, 100, 100))));
}

TEST_P(BlockPainterTest, TouchActionRectPaintCaching) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #touchaction {
        width: 100px;
        height: 100px;
        touch-action: none;
      }
      #sibling {
        width: 100px;
        height: 100px;
        background: blue;
      }
    </style>
    <div id='touchaction'></div>
    <div id='sibling'></div>
  )HTML");

  auto* sibling_element = GetElementById("sibling");
  const auto* sibling = sibling_element->GetLayoutObject();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(sibling->Id(), kBackgroundType)));

  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->touch_action_rects = {{gfx::Rect(0, 0, 100, 100)}};

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(2, hit_test_data)));

  sibling_element->setAttribute(html_names::kStyleAttr,
                                AtomicString("background: green;"));
  PaintController::CounterForTesting counter;
  UpdateAllLifecyclePhasesForTest();
  // Only the background display item of the sibling should be invalidated.
  EXPECT_EQ(1u, counter.num_cached_items);

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(2, hit_test_data)));
}

TEST_P(BlockPainterTest, TouchActionRectScrollingContents) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body { margin: 0; }
      #scroller {
        width: 100px;
        height: 100px;
        overflow: scroll;
        touch-action: pinch-zoom;
        will-change: transform;
        background-color: blue;
      }
      #child1, #child2 {
        width: 10px;
        height: 200px;
      }
      #child2 {
        touch-action: none;
      }
    </style>
    <div id='scroller'>
      <div id="child1"></div>
      <div id='child2'></div>
    </div>
  )HTML");

  auto* scroller_element = GetElementById("scroller");
  auto* scroller =
      To<LayoutBoxModelObject>(scroller_element->GetLayoutObject());
  const auto& scroller_scrolling_client =
      scroller->GetScrollableArea()->GetScrollingBackgroundDisplayItemClient();
  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->touch_action_rects = {
      {gfx::Rect(0, 0, 100, 400), TouchAction::kPinchZoom},
      {gfx::Rect(0, 200, 10, 200), TouchAction::kNone}};
  EXPECT_THAT(
      ContentDisplayItems(),
      ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                  IsSameId(scroller->Id(), kBackgroundType),
                  IsSameId(scroller_scrolling_client.Id(), kBackgroundType)));
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(1, 2),  // scroller background.
          IsPaintChunk(2, 2),  // scroller scroll hit test.
          IsPaintChunk(
              2, 3,
              PaintChunk::Id(scroller->Id(), kScrollingBackgroundChunkType),
              scroller->FirstFragment().ContentsProperties(), hit_test_data)));
}

TEST_P(BlockPainterTest, TouchActionRectPaintChunkChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #touchaction {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='touchaction'></div>
  )HTML");

  auto* touchaction_element = GetElementById("touchaction");
  auto* touchaction = touchaction_element->GetLayoutObject();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));

  touchaction_element->setAttribute(html_names::kStyleAttr,
                                    AtomicString("touch-action: none;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  PaintChunk::Id hit_test_chunk_id(touchaction->EnclosingLayer()->Id(),
                                   kHitTestChunkType);
  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->touch_action_rects = {{gfx::Rect(0, 0, 100, 100)}};

  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(1, hit_test_data)));

  touchaction_element->removeAttribute(html_names::kStyleAttr);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));
}

namespace {
class BlockPainterMockEventListener final : public NativeEventListener {
 public:
  void Invoke(ExecutionContext*, Event*) final {}
};
}  // namespace

TEST_P(BlockPainterTest, TouchHandlerRectsWithoutPaint) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body { margin: 0; }
      #parent { width: 100px; height: 100px; }
      #child { width: 200px; height: 50px; }
    </style>
    <div id='parent'>
      <div id='child'></div>
    </div>
  )HTML");

  // Initially there should be no hit test data because there are no event
  // handlers.
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  // Add an event listener to parent and ensure that hit test data are created
  // for both the parent and child.
  BlockPainterMockEventListener* callback =
      MakeGarbageCollected<BlockPainterMockEventListener>();
  auto* parent_element = GetElementById("parent");
  parent_element->addEventListener(event_type_names::kTouchstart, callback);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->touch_action_rects = {{gfx::Rect(0, 0, 100, 100)},
                                       {gfx::Rect(0, 0, 200, 50)}};
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(1, hit_test_data)));

  // Remove the event handler from parent and ensure no hit test data are left.
  parent_element->RemoveAllEventListeners();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));
}

TEST_P(BlockPainterTest, TouchActionRectsAcrossPaintChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body { margin: 0; }
      #parent { width: 100px; height: 100px; touch-action: none; }
      #child { width: 200px; height: 50px; }
    </style>
    <div id='parent'>
      <div id='child'></div>
    </div>
  )HTML");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  auto* hit_test_data = MakeGarbageCollected<HitTestData>();
  hit_test_data->touch_action_rects = {{gfx::Rect(0, 0, 100, 100)},
                                       {gfx::Rect(0, 0, 200, 50)}};
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(
                  1, hit_test_data, gfx::Rect(0, 0, 800, 600))));

  auto* child_element = GetElementById("child");
  child_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("background: blue;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(child_element->GetLayoutObject()->Id(),
                                   kBackgroundType)));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK(2, hit_test_data)));
}

TEST_P(BlockPainterTest, ScrolledHitTestChunkProperties) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body { margin: 0; }
      #scroller {
        width: 100px;
        height: 100px;
        overflow: scroll;
        touch-action: none;
      }
      #child {
        width: 200px;
        height: 50px;
        touch-action: none;
      }
    </style>
    <div id='scroller'>
      <div id='child'></div>
    </div>
  )HTML");

  const auto* scroller =
      To<LayoutBlock>(GetLayoutObjectByElementId("scroller"));
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));

  auto* scroller_touch_action_hit_test_data =
      MakeGarbageCollected<HitTestData>();
  scroller_touch_action_hit_test_data->touch_action_rects = {
      {gfx::Rect(0, 0, 100, 100)}};
  auto* scroll_hit_test_data = MakeGarbageCollected<HitTestData>();
  scroll_hit_test_data->scroll_translation =
      scroller->FirstFragment().PaintProperties()->ScrollTranslation();
  scroll_hit_test_data->scroll_hit_test_rect = gfx::Rect(0, 0, 100, 100);
  auto* scrolled_hit_test_data = MakeGarbageCollected<HitTestData>();
  scrolled_hit_test_data->touch_action_rects = {
      {RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
           ? gfx::Rect(0, 0, 200, 100)
           : gfx::Rect(0, 0, 200, 50)}};

  const auto& paint_chunks = ContentPaintChunks();
  EXPECT_THAT(
      paint_chunks,
      ElementsAre(
          VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON,
          IsPaintChunk(
              1, 1, PaintChunk::Id(scroller->Id(), kBackgroundChunkType),
              scroller->FirstFragment().LocalBorderBoxProperties(),
              scroller_touch_action_hit_test_data, gfx::Rect(0, 0, 100, 100)),
          IsPaintChunk(
              1, 1, PaintChunk::Id(scroller->Id(), DisplayItem::kScrollHitTest),
              scroller->FirstFragment().LocalBorderBoxProperties(),
              scroll_hit_test_data, gfx::Rect(0, 0, 100, 100)),
          IsPaintChunk(
              1, 1,
              PaintChunk::Id(scroller->Id(),
                             RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
                                 ? kScrollingBackgroundChunkType
                                 : kClippedContentsBackgroundChunkType),
              scroller->FirstFragment().ContentsProperties(),
              scrolled_hit_test_data,
              RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
                  ? gfx::Rect(0, 0, 200, 100)
                  : gfx::Rect(0, 0, 200, 50))));

  const auto& scroller_paint_chunk = paint_chunks[1];
  // The hit test rect for the scroller itself should not be scrolled.
  EXPECT_FALSE(
      ToUnaliased(scroller_paint_chunk.properties.Transform()).ScrollNode());

  const auto& scrolled_paint_chunk = paint_chunks[3];
  // The hit test rect for the scrolled contents should be scrolled.
  EXPECT_TRUE(
      ToUnaliased(scrolled_paint_chunk.properties.Transform()).ScrollNode());
}

}  // namespace blink
```