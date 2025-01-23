Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding of the File's Purpose:**

The filename `view_painter_test.cc` immediately suggests that this file contains tests related to the `ViewPainter` class in the Chromium Blink rendering engine. The `_test.cc` suffix is a common convention for unit test files. The directory `blink/renderer/core/paint/` further confirms that these tests are focused on the painting aspects of the rendering process.

**2. Examining the Includes:**

The included headers provide valuable clues about the file's functionality:

* `#include "third_party/blink/renderer/core/paint/view_painter.h"`: This is the core header being tested. It tells us the tests are directly interacting with the `ViewPainter` class.
* `#include <gtest/gtest.h>`: Indicates the use of Google Test framework for writing and running tests.
* `#include "cc/test/paint_op_matchers.h"`:  Suggests that the tests are verifying the sequence and properties of paint operations (drawing commands). The `cc` namespace often relates to the Chromium Compositor.
* `#include "third_party/blink/renderer/core/frame/local_dom_window.h"`: Implies interaction with the browser window and its properties.
* `#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"`:  Indicates the use of a test fixture (`PaintControllerPaintTest`) that sets up the necessary environment for paint-related tests.
* `#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"`: Hints at verifying the creation and properties of display items, which are higher-level rendering instructions.
* `#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"`: Shows that the tests are examining paint properties like transforms and clips.
* `#include "ui/gfx/geometry/skia_conversions.h"`: Suggests interaction with Skia, the graphics library used by Chromium.

**3. Analyzing the Test Structure:**

The file uses the Google Test framework's conventions:

* `TEST_P`: Parameterized tests, allowing the same test logic to be run with different input parameters.
* `INSTANTIATE_PAINT_TEST_SUITE_P`:  Used to instantiate the parameterized tests.
* `class ViewPainterFixedBackgroundTest : public PaintControllerPaintTest`: Defines a test fixture specifically for testing fixed background scenarios.
* `using ViewPainterTest = PaintControllerPaintTest`: Creates an alias for another test fixture.
* `SetBodyInnerHTML(R"HTML(...)HTML")`:  A common pattern in Blink layout/paint tests to set up the HTML content for testing.
* `GetDocument().View()`: Accessing the frame view, a key object for layout and painting.
* `layout_viewport->SetScrollOffset(...)`:  Simulating user scrolling.
* `GetPersistentData().GetDisplayItemList()`: Accessing the list of display items generated during the paint process.
* `EXPECT_THAT(...)`: Assertions to verify expected behavior. The use of matchers like `IsSameId`, `ElementsAre`, `AllOf`, and `PaintOpIs` is characteristic of Blink's testing style.

**4. Focusing on Key Test Cases:**

Examining the individual test functions reveals specific functionalities being tested:

* `DocumentFixedBackgroundNotPreferCompositing` and `DocumentFixedBackgroundPreferCompositing`: Test how fixed background images are handled with and without compositor optimization. The key here is verifying the correct paint operations and their associated rectangles, taking scrolling into account.
* `DocumentBackgroundWithScroll`: Tests how the document background is painted when the page is scrollable, focusing on the `ScrollHitTest` display item and associated paint chunks.
* `FrameScrollHitTestProperties`:  Examines the properties of the `ScrollHitTest` paint chunk and how it interacts with the scrolling content's paint chunk (transforms, clips, and scroll nodes).
* `TouchActionRect`: Tests how `touch-action` CSS property is translated into hit-testing information, including different `touch-action` values on different elements.

**5. Identifying Relationships with Web Technologies (HTML, CSS, JavaScript):**

Based on the HTML and CSS snippets within the tests, the connections become clear:

* **HTML:** The tests manipulate the DOM structure using `SetBodyInnerHTML`. Elements like `<div>`, `body`, and `html` are used.
* **CSS:** The tests use inline styles and `<style>` blocks to apply CSS properties such as `background`, `width`, `height`, `margin`, `display`, and `touch-action`. The `fixed` keyword for `background-attachment` is specifically tested. Pseudo-elements like `::-webkit-scrollbar` are also used.
* **JavaScript (Indirect):** While no explicit JavaScript code is present in the test file, the tests implicitly verify how the rendering engine responds to CSS properties that can be dynamically controlled by JavaScript. For example, changing the `touch-action` property via JavaScript would affect the behavior tested in `TouchActionRect`. Scrolling, simulated in the tests, is a common user interaction often driven by JavaScript.

**6. Inferring Logic and Assumptions:**

The tests make assumptions about how the rendering engine *should* behave. For instance:

* **Fixed Background Logic:** The tests assume that a `fixed` background should remain in the viewport regardless of scrolling, and that the paint operations reflect this behavior, potentially differing based on whether compositing is preferred.
* **Scroll Hit Testing:** The tests assume that a `ScrollHitTest` display item and paint chunk are created for scrollable areas to handle user input related to scrolling. They also assume the order and properties of these chunks.
* **Touch Action Handling:** The tests assume that the `touch-action` property correctly generates hit-test data to control touch interactions like panning and zooming.

**7. Considering User and Programming Errors:**

Based on the test scenarios:

* **User Errors (Indirect):** The tests don't directly catch *user* errors, but they ensure the browser correctly handles CSS, which a user might author incorrectly. For example, a user might accidentally set a very large `touch-action: none` area, which the `TouchActionRect` test implicitly verifies the handling of.
* **Programming Errors (Within Blink):** These tests are designed to catch errors in the Blink rendering engine's implementation of painting and hit testing. For example, if the `ViewPainter` incorrectly calculates the paint rect for a fixed background during scrolling, the assertions in `DocumentFixedBackgroundTest` would fail. Or, if the `ScrollHitTest` chunk isn't correctly positioned or sized, `FrameScrollHitTestProperties` would fail.

**8. Tracing User Operations to the Code:**

The tests simulate user actions like scrolling. Here's how a user action could lead to this code being executed:

1. **User Loads a Webpage:** The browser starts parsing HTML, CSS, and JavaScript.
2. **CSS Parsing and Style Calculation:** The browser interprets CSS rules, including those related to background, scrolling, and `touch-action`.
3. **Layout:** The browser determines the position and size of elements based on the CSS.
4. **Painting (The Relevant Part):**
   * The `ViewPainter` class is responsible for painting the viewport and its contents.
   * If the page has a fixed background (as in the tests), the `ViewPainter` will need to handle it specially.
   * If the page is scrollable, the `ViewPainter` will create a `ScrollHitTest` area.
   * If `touch-action` is specified, the `ViewPainter` (or related components) will generate touch action rectangles.
5. **Compositing (Potentially):** If the browser uses compositor optimizations, the paint operations might be different (as tested in the "PreferCompositing" cases).
6. **User Scrolls:**  This triggers a repaint. The `ViewPainter` is invoked again, and the tests verify that the fixed background remains fixed and the scroll hit test area is correctly positioned.
7. **User Touches/Gestures:** The touch action rectangles generated (and tested) determine how the browser responds to touch events like panning and zooming.

By stepping through these stages and understanding the role of `ViewPainter`, we can connect user actions to the execution of the code being tested.
这个文件 `view_painter_test.cc` 是 Chromium Blink 引擎中用于测试 `ViewPainter` 类的单元测试文件。`ViewPainter` 类的主要职责是负责渲染浏览器的视口（viewport），包括文档的背景、滚动条以及处理滚动相关的 hit-testing。

以下是 `view_painter_test.cc` 的功能详解：

**1. 测试 `ViewPainter` 的核心功能：**

* **绘制文档背景：** 测试在不同情况下（例如，有滚动、固定背景）文档背景的绘制是否正确。
* **处理固定背景 (`background-attachment: fixed`)：**  测试当文档背景设置为 `fixed` 时，在滚动过程中背景是否保持在视口的固定位置。
* **创建滚动 hit-test 区域：** 测试当页面内容超出视口需要滚动时，是否创建了正确的滚动 hit-test 区域，用于接收用户的滚动操作。
* **管理触摸操作区域 (`touch-action`)：** 测试 `touch-action` CSS 属性是否正确地生成了相应的触摸操作区域，用于控制触摸手势的行为（如缩放、平移）。

**2. 使用 Google Test 框架进行测试：**

* 该文件使用了 `gtest` 框架来编写和运行测试用例。
* 使用 `TEST_P` 定义参数化测试，允许使用不同的参数运行相同的测试逻辑。
* 使用 `EXPECT_THAT` 进行断言，验证实际的绘制结果是否符合预期。
* 使用 matchers (如 `PaintOpIs`, `ElementsAre`, `IsSameId`) 来精确匹配绘制操作和显示列表项。

**3. 与 JavaScript, HTML, CSS 的关系及举例说明：**

`ViewPainter` 的功能与 HTML、CSS 息息相关，因为它负责将 HTML 结构和 CSS 样式渲染到屏幕上。虽然它不直接涉及 JavaScript 的执行，但 JavaScript 可以动态修改 HTML 和 CSS，从而影响 `ViewPainter` 的行为。

* **HTML:** 测试用例通过 `SetBodyInnerHTML` 方法设置 HTML 内容，模拟不同的文档结构。例如，在 `DocumentBackgroundWithScroll` 测试中，创建了一个高度很高的 `div` 来触发滚动。
    ```c++
    SetBodyInnerHTML(R"HTML(
      <style>::-webkit-scrollbar { display: none }</style>
      <div style='height: 5000px'></div>
    )HTML");
    ```
    这个 HTML 片段创建了一个没有滚动条并且内部有一个高度为 5000 像素的 `div` 元素，使得文档内容超出视口高度，从而触发滚动行为。

* **CSS:** 测试用例使用内联样式或 `<style>` 标签来设置 CSS 属性，以验证 `ViewPainter` 对不同样式规则的处理。
    * **`background-attachment: fixed`:** 在 `ViewPainterFixedBackgroundTest` 中，测试了当 `body` 的背景设置为 `fixed` 时，滚动后背景的绘制情况。
        ```c++
        SetBodyInnerHTML(R"HTML(
          <style>
            ::-webkit-scrollbar { display: none; }
            body {
              margin: 0;
              width: 1200px;
              height: 900px;
              background: radial-gradient(
                circle at 100px 100px, blue, transparent 200px) fixed;
            }
          </style>
        )HTML");
        ```
        这里使用了 `background: radial-gradient(...) fixed;` 来设置一个固定定位的径向渐变背景。
    * **`touch-action`:** 在 `TouchActionRect` 测试中，验证了 `touch-action` 属性如何影响触摸操作区域的生成。
        ```c++
        SetBodyInnerHTML(R"HTML(
          <style>
            ::-webkit-scrollbar { display: none; }
            html {
              background: radial-gradient(
                circle at 100px 100px, blue, transparent 200px) fixed;
              touch-action: pinch-zoom;
            }
            body {
              margin: 0;
            }
          </style>
          <div id='child' style='width: 10px; height: 100px; touch-action: none'>
          </div>
          <div id='forcescroll' style='width: 0; height: 2900px;'></div>
        )HTML");
        ```
        这里 `html` 元素设置了 `touch-action: pinch-zoom;`，而 `div#child` 设置了 `touch-action: none;`，测试验证了不同元素的 `touch-action` 属性是否被正确处理。

* **JavaScript (间接影响):** 虽然测试代码本身不包含 JavaScript，但 `ViewPainter` 的最终输出会受到 JavaScript 的影响。例如，如果 JavaScript 动态修改了元素的 `scrollTop` 属性，`ViewPainter` 会根据新的滚动位置重新绘制。测试中的 `layout_viewport->SetScrollOffset` 方法模拟了 JavaScript 设置滚动偏移的行为。

**4. 逻辑推理、假设输入与输出：**

**示例 1: `DocumentFixedBackgroundTest`**

* **假设输入:**
    * HTML 中 `body` 元素设置了 `background-attachment: fixed` 的背景图片或渐变。
    * 用户进行了滚动操作。
* **逻辑推理:**  `ViewPainter` 在绘制背景时，需要确保固定背景相对于视口的位置保持不变，即使文档内容滚动。这通常意味着在绘制固定背景时会使用不同的坐标系统或进行特殊的变换处理。是否启用 compositor (图形合成器) 也会影响其实现方式。
* **预期输出:**
    * 当 `prefer_compositing_to_lcd_text` 为 `false` 时，绘制的矩形应该与滚动的偏移量相关。背景绘制在相对于文档起始位置的偏移位置。
    * 当 `prefer_compositing_to_lcd_text` 为 `true` 时，绘制的矩形应该相对于视口，从 (0, 0) 开始。背景绘制在视口的固定位置。
* **具体假设输入与输出 (以 `DocumentFixedBackgroundNotPreferCompositing` 为例):**
    * **假设 HTML:**  如上面 CSS 示例所示，`body` 有固定背景。
    * **假设滚动偏移:**  滚动了 (200, 150)。
    * **预期输出:**  背景绘制操作 `DrawRectOp` 的矩形应该是 `SkRect::MakeXYWH(200, 150, 800, 600)`，因为没有启用 compositor，背景是相对于文档滚动的。

**示例 2: `DocumentBackgroundWithScroll`**

* **假设输入:**
    * HTML 内容高度超出视口，导致出现滚动条。
* **逻辑推理:**  当内容可滚动时，`ViewPainter` 需要创建一个 `ScrollHitTest` 显示列表项和 PaintChunk，用于处理用户的滚动交互。这个 hit-test 区域应该覆盖整个视口，并且在内容滚动之前。
* **预期输出:**
    * `GetPersistentData().GetPaintChunks()[0]` 应该是 `DisplayItem::kScrollHitTest` 类型的 PaintChunk。
    * `ContentDisplayItems()` 应该包含 `VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM`。
    * `ContentPaintChunks()` 应该包含 `VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON`。

**5. 用户或编程常见的使用错误及举例说明：**

虽然这个测试文件主要关注引擎内部的正确性，但它可以间接反映出用户或开发者在使用 HTML 和 CSS 时可能遇到的问题：

* **固定背景预期行为混淆:**  用户可能不理解 `background-attachment: fixed` 的工作原理，认为背景会随着内容滚动。测试用例验证了引擎是否正确实现了 `fixed` 的行为。如果引擎实现有误，用户可能会看到不符合预期的背景滚动效果。
* **`touch-action` 的错误使用:**  开发者可能会错误地设置 `touch-action` 属性，导致页面无法滚动或缩放。`TouchActionRect` 测试验证了引擎是否正确解析和应用了 `touch-action` 属性，如果引擎实现有误，开发者设置的 `touch-action` 可能不会生效，导致用户交互体验不佳。
* **滚动 hit-test 问题:**  如果引擎没有正确创建或定位滚动 hit-test 区域，用户可能会发现无法滚动页面或滚动行为不流畅。`DocumentBackgroundWithScroll` 和 `FrameScrollHitTestProperties` 测试确保了滚动 hit-test 机制的正确性。

**6. 用户操作如何一步步到达这里，作为调试线索：**

当开发者在 Chromium 渲染引擎中调试与视口绘制、滚动或触摸交互相关的问题时，`view_painter_test.cc` 中的测试用例可以作为重要的参考和调试线索：

1. **用户加载一个包含特定 CSS 属性的网页:** 例如，网页的 `body` 元素设置了 `background-attachment: fixed`，或者某个元素设置了特定的 `touch-action` 值。
2. **用户执行操作:** 例如，用户滚动页面、进行触摸滑动或捏合缩放等操作。
3. **渲染引擎的绘制流程被触发:**  当页面需要更新显示时，渲染引擎会执行布局、绘制等一系列操作。`ViewPainter` 类在这个过程中负责绘制视口的内容。
4. **`ViewPainter::Paint` 方法被调用 (大致流程):**  根据当前的布局和样式信息，`ViewPainter` 会生成一系列的绘制指令 (Paint Operations)，例如绘制背景、边框、内容等。
5. **测试用例模拟了这些场景:**  `view_painter_test.cc` 中的测试用例通过设置特定的 HTML 和 CSS，并模拟用户滚动等操作，来验证 `ViewPainter` 在这些场景下的行为是否正确。
6. **调试线索:**
    * **绘制输出不符合预期:**  如果用户看到的页面渲染效果与预期不符（例如，固定背景没有固定，或者触摸手势无法正常工作），开发者可以查看 `view_painter_test.cc` 中相关的测试用例，了解预期的绘制行为。
    * **排查 `ViewPainter` 的实现逻辑:**  如果某个测试用例失败，表明 `ViewPainter` 的实现可能存在 bug。开发者可以深入研究 `ViewPainter` 的源代码，结合测试用例的场景，分析问题所在。
    * **验证修复方案:**  在修复了 `ViewPainter` 中的 bug 后，可以重新运行相关的测试用例，确保修复方案的正确性。

总而言之，`view_painter_test.cc` 是一个关键的测试文件，它确保了 Chromium 渲染引擎能够正确地绘制视口内容，处理滚动和触摸交互，对于保证浏览器的稳定性和用户体验至关重要。 开发者可以通过分析这些测试用例，更好地理解 `ViewPainter` 的工作原理，并有效地调试相关的渲染问题。

### 提示词
```
这是目录为blink/renderer/core/paint/view_painter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/paint/view_painter.h"

#include <gtest/gtest.h>
#include "cc/test/paint_op_matchers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {
namespace {

using ::cc::PaintOpIs;
using ::testing::_;
using ::testing::AllOf;
using ::testing::ElementsAre;
using ::testing::ResultOf;

class ViewPainterFixedBackgroundTest : public PaintControllerPaintTest {
 protected:
  void RunFixedBackgroundTest(bool prefer_compositing_to_lcd_text);
};

INSTANTIATE_PAINT_TEST_SUITE_P(ViewPainterFixedBackgroundTest);

void ViewPainterFixedBackgroundTest::RunFixedBackgroundTest(
    bool prefer_compositing_to_lcd_text) {
  SetPreferCompositingToLCDText(prefer_compositing_to_lcd_text);
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body {
        margin: 0;
        width: 1200px;
        height: 900px;
        background: radial-gradient(
          circle at 100px 100px, blue, transparent 200px) fixed;
      }
    </style>
  )HTML");

  LocalFrameView* frame_view = GetDocument().View();
  ScrollableArea* layout_viewport = frame_view->LayoutViewport();

  ScrollOffset scroll_offset(200, 150);
  layout_viewport->SetScrollOffset(scroll_offset,
                                   mojom::blink::ScrollType::kUser);
  frame_view->UpdateAllLifecyclePhasesForTest();

  const auto& display_items = GetPersistentData().GetDisplayItemList();
  const auto& background_client = prefer_compositing_to_lcd_text
                                      ? GetLayoutView()
                                      : ViewScrollingBackgroundClient();
  const DisplayItem* background_display_item = &display_items[0];
  EXPECT_THAT(
      *background_display_item,
      IsSameId(background_client.Id(), DisplayItem::kDocumentBackground));

  PaintRecord record =
      To<DrawingDisplayItem>(background_display_item)->GetPaintRecord();

  SkRect expected_rect =
      prefer_compositing_to_lcd_text
          ? SkRect::MakeXYWH(0, 0, 800, 600)
          : SkRect::MakeXYWH(scroll_offset.x(), scroll_offset.y(), 800, 600);
  EXPECT_THAT(
      record,
      ElementsAre(
          _, AllOf(PaintOpIs<cc::DrawRectOp>(),
                   ResultOf(
                       [](const cc::PaintOp& op) {
                         return static_cast<const cc::DrawRectOp&>(op).rect;
                       },
                       expected_rect))));
}

TEST_P(ViewPainterFixedBackgroundTest,
       DocumentFixedBackgroundNotPreferCompositing) {
  RunFixedBackgroundTest(false);
}

TEST_P(ViewPainterFixedBackgroundTest,
       DocumentFixedBackgroundPreferCompositing) {
  RunFixedBackgroundTest(true);
}

using ViewPainterTest = PaintControllerPaintTest;

INSTANTIATE_PAINT_TEST_SUITE_P(ViewPainterTest);

TEST_P(ViewPainterTest, DocumentBackgroundWithScroll) {
  SetBodyInnerHTML(R"HTML(
    <style>::-webkit-scrollbar { display: none }</style>
    <div style='height: 5000px'></div>
  )HTML");

  auto* scroll_hit_test_data = MakeGarbageCollected<HitTestData>();
  scroll_hit_test_data->scroll_hit_test_rect = gfx::Rect(0, 0, 800, 600);
  scroll_hit_test_data->scroll_translation =
      GetLayoutView().FirstFragment().PaintProperties()->ScrollTranslation();
  scroll_hit_test_data->scrolling_contents_cull_rect =
      gfx::Rect(0, 0, 800, 4600);
  // The scroll hit test should be before the scrolled contents to ensure the
  // hit test does not prevent the background squashing with the scrolling
  // contents.
  EXPECT_THAT(
      GetPersistentData().GetPaintChunks()[0],
      IsPaintChunk(
          0, 0,
          PaintChunk::Id(GetLayoutView().Id(), DisplayItem::kScrollHitTest),
          GetLayoutView().FirstFragment().LocalBorderBoxProperties(),
          scroll_hit_test_data, gfx::Rect(0, 0, 800, 600)));
  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM));
  EXPECT_THAT(ContentPaintChunks(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_CHUNK_COMMON));
}

TEST_P(ViewPainterTest, FrameScrollHitTestProperties) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      body { margin: 0; }
      #child { width: 100px; height: 2000px; background: green; }
    </style>
    <div id='child'></div>
  )HTML");

  auto& child = *GetLayoutObjectByElementId("child");

  EXPECT_THAT(ContentDisplayItems(),
              ElementsAre(VIEW_SCROLLING_BACKGROUND_DISPLAY_ITEM,
                          IsSameId(child.Id(), kBackgroundType)));

  const auto& paint_chunks = GetPersistentData().GetPaintChunks();
  auto* scroll_hit_test_data = MakeGarbageCollected<HitTestData>();
  scroll_hit_test_data->scroll_translation =
      GetLayoutView().FirstFragment().PaintProperties()->ScrollTranslation();
  scroll_hit_test_data->scroll_hit_test_rect = gfx::Rect(0, 0, 800, 600);
  // The scroll hit test should be before the scrolled contents to ensure the
  // hit test does not prevent the background squashing with the scrolling
  // contents.
  const auto& scroll_hit_test_chunk = paint_chunks[0];
  const auto& contents_chunk = paint_chunks[1];
  EXPECT_THAT(
      scroll_hit_test_chunk,
      IsPaintChunk(
          0, 0,
          PaintChunk::Id(GetLayoutView().Id(), DisplayItem::kScrollHitTest),
          GetLayoutView().FirstFragment().LocalBorderBoxProperties(),
          scroll_hit_test_data));
  EXPECT_THAT(contents_chunk, VIEW_SCROLLING_BACKGROUND_CHUNK(2, nullptr));

  // The scroll hit test should not be scrolled and should not be clipped.
  const auto& scroll_hit_test_transform =
      ToUnaliased(scroll_hit_test_chunk.properties.Transform());
  EXPECT_EQ(nullptr, scroll_hit_test_transform.ScrollNode());
  const auto& scroll_hit_test_clip =
      ToUnaliased(scroll_hit_test_chunk.properties.Clip());
  EXPECT_EQ(gfx::RectF(InfiniteIntRect()),
            scroll_hit_test_clip.PaintClipRect().Rect());

  // The scrolled contents should be scrolled and clipped.
  const auto& contents_transform =
      ToUnaliased(contents_chunk.properties.Transform());
  const auto* contents_scroll = contents_transform.ScrollNode();
  EXPECT_EQ(gfx::Rect(0, 0, 800, 2000), contents_scroll->ContentsRect());
  EXPECT_EQ(gfx::Rect(0, 0, 800, 600), contents_scroll->ContainerRect());
  const auto& contents_clip = ToUnaliased(contents_chunk.properties.Clip());
  EXPECT_EQ(gfx::RectF(0, 0, 800, 600), contents_clip.PaintClipRect().Rect());

  // The scroll hit test paint chunk maintains a reference to a scroll offset
  // translation node and the contents should be scrolled by this node.
  EXPECT_EQ(&contents_transform,
            scroll_hit_test_chunk.hit_test_data->scroll_translation);
}

TEST_P(ViewPainterTest, TouchActionRect) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { display: none; }
      html {
        background: radial-gradient(
          circle at 100px 100px, blue, transparent 200px) fixed;
        touch-action: pinch-zoom;
      }
      body {
        margin: 0;
      }
    </style>
    <div id='child' style='width: 10px; height: 100px; touch-action: none'>
    </div>
    <div id='forcescroll' style='width: 0; height: 2900px;'></div>
  )HTML");

  GetFrame().DomWindow()->scrollBy(0, 100);
  UpdateAllLifecyclePhasesForTest();

  auto* view = &GetLayoutView();
  auto non_scrolling_properties =
      view->FirstFragment().LocalBorderBoxProperties();
  auto* view_hit_test_data = MakeGarbageCollected<HitTestData>();
  view_hit_test_data->touch_action_rects = {
      {gfx::Rect(0, 0, 800, 600), TouchAction::kPinchZoom}};
  auto* html = GetDocument().documentElement()->GetLayoutBox();
  auto scrolling_properties = view->FirstFragment().ContentsProperties();
  auto* scrolling_hit_test_data = MakeGarbageCollected<HitTestData>();
  scrolling_hit_test_data->touch_action_rects = {
      {gfx::Rect(0, 0, 800, 3000), TouchAction::kPinchZoom},
      {gfx::Rect(0, 0, 10, 100), TouchAction::kNone}};

  auto* scroll_hit_test_data = MakeGarbageCollected<HitTestData>();
  scroll_hit_test_data->scroll_translation =
      GetLayoutView().FirstFragment().PaintProperties()->ScrollTranslation();
  scroll_hit_test_data->scroll_hit_test_rect = gfx::Rect(0, 0, 800, 600);
  EXPECT_THAT(
      GetPersistentData().GetPaintChunks()[0],
      IsPaintChunk(
          0, 1, PaintChunk::Id(view->Layer()->Id(), DisplayItem::kLayerChunk),
          non_scrolling_properties, view_hit_test_data,
          gfx::Rect(0, 0, 800, 600)));
  EXPECT_THAT(GetPersistentData().GetPaintChunks()[1],
              IsPaintChunk(
                  1, 1, PaintChunk::Id(view->Id(), DisplayItem::kScrollHitTest),
                  non_scrolling_properties, scroll_hit_test_data,
                  gfx::Rect(0, 0, 800, 600)));
  EXPECT_THAT(
      ContentPaintChunks(),
      ElementsAre(IsPaintChunk(
          1, 1,
          RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
              ? PaintChunk::Id(view->GetScrollableArea()
                                   ->GetScrollingBackgroundDisplayItemClient()
                                   .Id(),
                               DisplayItem::kDocumentBackground)
              : PaintChunk::Id(html->Layer()->Id(), DisplayItem::kLayerChunk),
          scrolling_properties, scrolling_hit_test_data,
          gfx::Rect(0, 0, 800, 3000))));
}

}  // namespace
}  // namespace blink
```