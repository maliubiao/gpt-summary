Response:
The user wants a summary of the functionality of the provided C++ code snippet from `layout_box_test.cc`. I need to identify the core purpose of the tests, relate them to web technologies (JavaScript, HTML, CSS), provide examples of how these tests work with hypothetical inputs and outputs, and illustrate common usage errors.

**Functionality Breakdown:**

1. **Invalidation Tests:** The first few tests focus on how changes to images trigger repaints. This is relevant to how browsers update the display when image resources change.
2. **Scrollable Overflow Rect Test:**  This checks how the overflow area of a list marker is calculated, involving layout and potentially scrolling.
3. **Geometry Tests with Scrollbars:** A large portion of the code tests the calculation of element positions and dimensions (border box, padding box, content box, scrollable overflow) in various scenarios involving scrollbars and different writing modes (horizontal-tb, vertical-lr, vertical-rl, and right-to-left). These tests cover different positioning schemes (absolute, static/in-flow, relative, float).

**Relating to Web Technologies:**

*   **HTML:** The tests heavily rely on setting up HTML structures to create different layout scenarios.
*   **CSS:** CSS properties like `background-image`, `background-size`, `overflow`, `width`, `height`, `padding`, `border`, `position`, `top`, `left`, `direction`, `writing-mode`, and `float` are crucial for defining the layout contexts being tested.
*   **JavaScript:** While the tests themselves are in C++, they are verifying behavior that JavaScript can trigger (e.g., scrolling via `window.scrollBy`).

**Hypothetical Input/Output Examples:**

For the image invalidation test:

*   **Input:** An `<img>` element with a `src` pointing to an animated GIF. The GIF's frames change.
*   **Output:** The test verifies that the `LayoutObject` associated with the `<img>` is correctly marked for repaint, and the type of invalidation is appropriate (e.g., `PaintInvalidationReason::kImage`).

For the absolute positioning with scrollbars test:

*   **Input:** An HTML structure with a relatively positioned container having scrollbars and an absolutely positioned child element with `top` and `left` styles.
*   **Output:** The test verifies that the `PhysicalLocation()` of the child element is calculated correctly, taking into account the container's border, padding, and the presence/position of scrollbars.

**Common Usage Errors (from a developer's perspective interacting with the layout system):**

*   **Incorrectly assuming element positions:**  Developers might incorrectly calculate the position of absolutely positioned elements within scrollable containers without considering scrollbar offsets.
*   **Forgetting about writing modes:**  Failing to account for different writing modes (like RTL or vertical writing) can lead to layout bugs, especially when dealing with positioning and scrolling.
*   **Not understanding box-sizing:**  Confusion between `content-box` and `border-box` can lead to miscalculations of element dimensions, which these tests aim to prevent.

**Overall Goal of the Tests:**

The primary goal of these tests is to ensure the accuracy and correctness of the Blink layout engine's calculations related to element positioning, sizing, and repaint invalidation, particularly in complex scenarios involving scrollbars and different writing modes. They aim to catch bugs and regressions in the layout logic.
这是 `blink/renderer/core/layout/layout_box_test.cc` 文件的第二部分，主要延续了第一部分的测试内容，专注于 **LayoutBox** 类的各种功能测试，特别是与布局计算和几何属性相关的测试。

**本部分的主要功能归纳如下：**

1. **验证图片更改时的延迟失效机制 (Delayed Invalidation):**
    *   测试了 `LayoutObject` 在图片资源更改时，根据 `CanDeferInvalidation` 的设置，是否正确触发全量重绘或延迟重绘。
    *   模拟了图片更改通知，并检查了 `ShouldDoFullPaintInvalidation` 和 `ShouldDelayFullPaintInvalidation` 等标志的状态。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **HTML:** 测试中使用了 `<img>` 标签（虽然代码中是模拟的图片更改，但实际场景中与 `<img>` 标签相关）。
        *   **CSS:**  `background-image` 和 `background-size` 属性被用来测试 `LayoutView` 的背景图片更改时的失效机制。
        *   **JavaScript:** 当 JavaScript 代码修改图片的 `src` 属性时，会触发类似的图片更改通知，从而影响浏览器的重绘行为。

    *   **假设输入与输出:**
        *   **假设输入:** 一个带有背景图片的 `<body>` 元素，背景图片是一个动画 GIF。
        *   **输出:** 测试验证当 GIF 动画帧改变时，`LayoutView` 会被标记为需要重绘，并且在滚动后会立即触发重绘。

2. **测试 Marker Container 的可滚动溢出矩形 (MarkerContainerScrollableOverflowRect):**
    *   验证了列表项的 marker container 的 `ScrollableOverflowRect` 属性计算是否正确，特别是当内容溢出时。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **HTML:** 使用了 `<div>` 标签并设置了 `display: list-item;` 来模拟列表项。
        *   **CSS:** 使用了 `overflow: hidden;` 和 `line-height` 等属性来控制内容溢出。

    *   **假设输入与输出:**
        *   **假设输入:** 一个 `display: list-item;` 的 `<div>` 元素，其内部包含溢出的内容。
        *   **输出:** 测试断言 marker container 的 `ScrollableOverflowRect` 的底部位置大于某个预期的值。

3. **测试带有滚动条的容器中绝对定位子元素的位置 (LocationOfAbsoluteChildWithContainerScrollbars):**
    *   详细测试了在不同书写模式（从左到右、从右到左、垂直从上到下、垂直从下到上）下，当容器存在滚动条时，绝对定位子元素的 `PhysicalLocation()` 计算是否正确。
    *   涵盖了多种情况，包括容器和子元素的不同书写模式组合。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **HTML:** 使用了嵌套的 `<div>` 结构来模拟容器和子元素。
        *   **CSS:** 关键 CSS 属性包括 `position: relative;` (容器), `position: absolute;` (子元素), `overflow: scroll;`, `direction: rtl;`, `writing-mode: vertical-lr;` 等。
        *   **JavaScript:** 虽然测试是 C++ 的，但开发者在使用 JavaScript 操作 DOM 元素的 style 属性时，这些 CSS 属性会直接影响元素的布局和位置。

    *   **假设输入与输出:**
        *   **假设输入:**  一个 `position: relative;` 且 `overflow: scroll;` 的容器，内部包含一个 `position: absolute;` 的子元素，并设置了 `top` 和 `left` 属性。容器可能具有不同的书写模式。
        *   **输出:** 测试断言子元素的 `PhysicalLocation()` 返回的 `PhysicalOffset` 与预期值一致，考虑了容器的边框、内边距以及滚动条的影响。

4. **测试带有滚动条的容器中自动定位的绝对定位子元素的位置 (LocationOfAbsoluteAutoTopLeftChildWithContainerScrollbars):**
    *   类似于上一个测试，但子元素没有设置 `top` 和 `left` 属性，依赖浏览器的默认自动定位行为。
    *   测试了在不同书写模式下，自动定位的绝对定位子元素的位置计算。
    *   **与 JavaScript, HTML, CSS 的关系:** 类似上一个测试。

    *   **假设输入与输出:**
        *   **假设输入:** 一个 `position: relative;` 且 `overflow: scroll;` 的容器，内部包含一个 `position: absolute;` 的子元素（没有设置 `top` 和 `left`）。
        *   **输出:** 测试断言子元素的 `PhysicalLocation()` 返回的 `PhysicalOffset` 与预期值一致，考虑了容器的边框、内边距以及滚动条的影响。

5. **测试带有滚动条的容器中内联流子元素的位置 (LocationOfInFlowChildWithContainerScrollbars):**
    *   测试了在不同书写模式下，普通内联流子元素的 `PhysicalLocation()` 计算。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **HTML:** 使用了嵌套的 `<div>` 结构。
        *   **CSS:** 关键属性包括 `overflow: scroll;`, `direction: rtl;`, `writing-mode: vertical-lr;`，以及用于偏移的 `.offset` 元素的样式。

    *   **假设输入与输出:**
        *   **假设输入:** 一个 `position: relative;` 且 `overflow: scroll;` 的容器，内部包含一个普通内联流的子元素。
        *   **输出:** 测试断言子元素的 `PhysicalLocation()` 返回的 `PhysicalOffset` 与预期值一致。

6. **测试带有滚动条的容器中相对定位子元素的位置 (LocationOfRelativeChildWithContainerScrollbars):**
    *   测试了在不同书写模式下，相对定位子元素的 `PhysicalLocation()` 计算。
    *   **与 JavaScript, HTML, CSS 的关系:** 类似上一个测试，但子元素使用了 `position: relative;` 并设置了 `top` 和 `left` 来进行相对偏移。

    *   **假设输入与输出:**
        *   **假设输入:** 一个 `position: relative;` 且 `overflow: scroll;` 的容器，内部包含一个 `position: relative;` 的子元素，并设置了 `top` 和 `left` 属性。
        *   **输出:** 测试断言子元素的 `PhysicalLocation()` 返回的 `PhysicalOffset` 与预期值一致。

7. **测试带有滚动条的容器中浮动子元素的位置 (LocationOfFloatLeftChildWithContainerScrollbars 和 LocationOfFloatRightChildWithContainerScrollbars):**
    *   分别测试了左浮动和右浮动子元素在不同书写模式下的 `PhysicalLocation()` 计算。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **HTML:** 使用了嵌套的 `<div>` 结构。
        *   **CSS:** 关键属性包括 `overflow: scroll;`, `direction: rtl;`, `writing-mode: vertical-lr;` 和 `float: left;` 或 `float: right;`。

    *   **假设输入与输出:**
        *   **假设输入:** 一个 `position: relative;` 且 `overflow: scroll;` 的容器，内部包含一个 `float: left;` 或 `float: right;` 的子元素。
        *   **输出:** 测试断言子元素的 `PhysicalLocation()` 返回的 `PhysicalOffset` 与预期值一致。

8. **测试带有滚动条的容器的几何属性 (GeometriesWithScrollbarsNonScrollable 和 GeometriesWithScrollbarsScrollable):**
    *   测试了当容器没有足够内容滚动时和有足够内容滚动时，各种几何属性的计算，包括：
        *   `ScrolledContentOffset()`: 内容滚动偏移。
        *   `OriginAdjustmentForScrollbars()`: 由于滚动条导致的坐标调整。
        *   `PhysicalBorderBoxRect()`: 边框盒子的物理矩形。
        *   `NoOverflowRect()`: 没有溢出的矩形。
        *   `PhysicalPaddingBoxRect()`: 内边距盒子的物理矩形。
        *   `PhysicalContentBoxRect()`: 内容盒子的物理矩形。
        *   `ScrollableOverflowRect()`: 可滚动溢出矩形。
        *   `MaximumScrollOffsetInt()`: 最大滚动偏移。
        *   `MinimumScrollOffsetInt()`: 最小滚动偏移。
        *   `ScrollOrigin()`: 滚动原点。
        *   `ScrollPosition()`: 滚动位置。
    *   覆盖了不同书写模式。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **HTML:** 使用了嵌套的 `<div>` 结构。
        *   **CSS:**  关键属性包括 `overflow: scroll;`, `direction: rtl;`, `writing-mode: vertical-lr;`, `width`, `height`, `padding`, `border`, `box-sizing` 等。
        *   **JavaScript:** JavaScript 可以读取和修改这些几何属性，例如通过 `element.getBoundingClientRect()` 获取元素的边界矩形，或者通过 `element.scrollLeft` 和 `element.scrollTop` 获取滚动偏移。

    *   **假设输入与输出:**
        *   **假设输入:**  一个 `overflow: scroll;` 的容器，内部包含内容，可能足以触发滚动条，也可能不足以触发。容器可能具有不同的书写模式。
        *   **输出:** 测试断言各种几何属性的计算结果与预期值一致。

**常见的使用错误举例说明:**

*   **对于图片失效:** 开发者可能错误地认为修改图片的某些元数据（而不是图片内容本身）也会立即触发全量重绘，而实际上可能只会触发部分重绘或延迟重绘。
*   **对于绝对定位:** 开发者在计算绝对定位元素的最终位置时，可能会忘记考虑包含块的内边距、边框以及滚动条的存在和位置，导致布局偏差。
*   **对于浮动元素:** 开发者可能不理解在不同书写模式下，浮动元素的行为差异，例如在 RTL 模式下，左浮动元素会靠右排列。
*   **对于滚动条:** 开发者可能在计算元素尺寸时，没有考虑到滚动条所占据的空间，尤其是在设置了 `box-sizing: border-box;` 的情况下。

总而言之，这部分测试用例深入地验证了 `LayoutBox` 类在处理各种布局场景时的几何计算和失效机制，确保了 Blink 渲染引擎能够正确地渲染网页内容。这些测试覆盖了 HTML 结构、CSS 样式以及它们在不同书写模式下的组合效果。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_box_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
dation::kYes);
  EXPECT_FALSE(obj->ShouldDoFullPaintInvalidation());
  EXPECT_EQ(obj->PaintInvalidationReasonForPrePaint(),
            PaintInvalidationReason::kImage);
  EXPECT_TRUE(obj->ShouldDelayFullPaintInvalidation());

  // CanDeferInvalidation::kNo results in a immediate invalidation.
  obj->ImageChanged(image, ImageResourceObserver::CanDeferInvalidation::kNo);
  EXPECT_TRUE(obj->ShouldDoFullPaintInvalidation());
  EXPECT_EQ(obj->PaintInvalidationReasonForPrePaint(),
            PaintInvalidationReason::kImage);
  EXPECT_FALSE(obj->ShouldDelayFullPaintInvalidation());
}

TEST_F(LayoutBoxTest, DelayedInvalidationLayoutViewScrolled) {
  SetHtmlInnerHTML(R"HTML(
    <body style="
      background-image: url(data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==);
      background-size: cover;
    ">
      <div style="height: 20000px"></div>
    </body>
  )HTML");

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  auto* layout_view = GetDocument().GetLayoutView();
  EXPECT_FALSE(layout_view->ShouldDelayFullPaintInvalidation());

  // The background-image will be painted by the LayoutView. Get a reference to
  // it from there.
  auto* background_image =
      layout_view->StyleRef().BackgroundLayers().GetImage();
  ASSERT_TRUE(background_image);
  auto* image_resource_content = background_image->CachedImage();
  ASSERT_TRUE(image_resource_content);
  ASSERT_TRUE(image_resource_content->GetImage()->MaybeAnimated());

  // Simulate an image change notification.
  static_cast<ImageObserver*>(image_resource_content)
      ->Changed(image_resource_content->GetImage());
  EXPECT_TRUE(layout_view->MayNeedPaintInvalidationAnimatedBackgroundImage());

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(layout_view->ShouldDelayFullPaintInvalidation());

  static_cast<ImageObserver*>(image_resource_content)
      ->Changed(image_resource_content->GetImage());
  EXPECT_TRUE(layout_view->MayNeedPaintInvalidationAnimatedBackgroundImage());

  // Scroll down at least by a viewport height.
  GetDocument().domWindow()->scrollBy(0, 10000);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(layout_view->ShouldDelayFullPaintInvalidation());
}

TEST_F(LayoutBoxTest, MarkerContainerScrollableOverflowRect) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
    </style>
    <div id='target' style='display: list-item;'>
      <div style='overflow: hidden; line-height:100px;'>hello</div>
    </div>
  )HTML");

  auto* marker_container =
      To<LayoutBox>(GetLayoutObjectByElementId("target")->SlowFirstChild());
  EXPECT_GE(marker_container->PhysicalLocation().top +
                marker_container->ScrollableOverflowRect().Bottom(),
            LayoutUnit(50));
}

static String CommonStyleForGeometryWithScrollbarTests() {
  return R"HTML(
    <style>
      ::-webkit-scrollbar { width: 15px; height: 16px; background: yellow; }
      .rtl { direction: rtl; }
      .htb { writing-mode: horizontal-tb; }
      .vlr { writing-mode: vertical-lr; }
      .vrl { writing-mode: vertical-rl; }
      .container {
        overflow: scroll;
        width: 400px;
        height: 300px;
        padding: 10px 20px 30px 40px;
        border-width: 20px 30px 40px 50px;
        border-style: solid;
      }
      .child {
        width: 50px;
        height: 80px;
        border: 40px solid blue;
        padding: 10px;
      }
    </style>
  )HTML";
}

TEST_F(LayoutBoxTest, LocationOfAbsoluteChildWithContainerScrollbars) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>
      .container { position: relative; }
      .child { position: absolute; top: 70px; left: 100px; }
    </style>
    <div class="container">
      <div id="normal" class="child"></div>
    </div>
    <div class="container vlr">
      <div id="vlr" class="child"></div>
    </div>
    <div class="container vrl">
      <div id="vrl" class="child"></div>
    </div>
    <div class="container rtl">
      <div id="rtl" class="child"></div>
    </div>
    <div class="container rtl vlr">
      <div id="rtl-vlr" class="child"></div>
    </div>
    <div class="container rtl vrl">
      <div id="rtl-vrl" class="child"></div>
    </div>
  )HTML");

  const auto* normal = GetLayoutBoxByElementId("normal");
  // In non-flipped writing mode, child's Location is the location of the
  // top-left corner of its border box relative the top-left corner of its
  // containing box's border box.
  // 150 = absolute_left (100) + container_border_left (50)
  // 90 = absolute_top (70) + container_border_top (20)
  EXPECT_EQ(PhysicalOffset(150, 90), normal->PhysicalLocation());

  // Same as "normal".
  const auto* vlr = GetLayoutBoxByElementId("vlr");
  EXPECT_EQ(PhysicalOffset(150, 90), vlr->PhysicalLocation());

  const auto* vrl = GetLayoutBoxByElementId("vrl");
  // The physical location is still about the top-left corners.
  EXPECT_EQ(PhysicalOffset(150, 90), vrl->PhysicalLocation());

  // In horizontal rtl mode, there is scrollbar on the left, so the child is
  // shifted to the right by the width of the scrollbar.
  const auto* rtl = GetLayoutBoxByElementId("rtl");
  EXPECT_EQ(PhysicalOffset(165, 90), rtl->PhysicalLocation());

  // Same as "vlr".
  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  EXPECT_EQ(PhysicalOffset(150, 90), rtl_vlr->PhysicalLocation());

  // Same as "vrl".
  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");
  EXPECT_EQ(PhysicalOffset(150, 90), rtl_vrl->PhysicalLocation());
}

TEST_F(LayoutBoxTest,
       LocationOfAbsoluteChildWithContainerScrollbarsDifferentWritingModes) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>
      .container { position: relative; }
      .child { position: absolute; top: 70px; left: 100px; }
    </style>
    <div class="container">
      <div id="vlr-in-htb" class="child vlr"></div>
    </div>
    <div class="container">
      <div id="vrl-in-htb" class="child vrl"></div>
    </div>
    <div class="container vlr">
      <div id="htb-in-vlr" class="child htb"></div>
    </div>
    <div class="container vlr">
      <div id="vrl-in-vlr" class="child vrl"></div>
    </div>
    <div class="container vrl">
      <div id="htb-in-vrl" class="child htb"></div>
    </div>
    <div class="container vrl">
      <div id="vlr-in-vrl" class="child vlr"></div>
    </div>
  )HTML");

  // The following expected values are just what the current system produces,
  // and we haven't fully verified their correctness.

  const auto* vlr_in_htb = GetLayoutBoxByElementId("vlr-in-htb");
  EXPECT_EQ(PhysicalOffset(150, 90), vlr_in_htb->PhysicalLocation());

  const auto* vrl_in_htb = GetLayoutBoxByElementId("vrl-in-htb");
  EXPECT_EQ(PhysicalOffset(150, 90), vrl_in_htb->PhysicalLocation());

  const auto* htb_in_vlr = GetLayoutBoxByElementId("htb-in-vlr");
  EXPECT_EQ(PhysicalOffset(150, 90), htb_in_vlr->PhysicalLocation());

  const auto* vrl_in_vlr = GetLayoutBoxByElementId("vrl-in-vlr");
  EXPECT_EQ(PhysicalOffset(150, 90), vrl_in_vlr->PhysicalLocation());

  const auto* htb_in_vrl = GetLayoutBoxByElementId("htb-in-vrl");
  EXPECT_EQ(PhysicalOffset(150, 90), htb_in_vrl->PhysicalLocation());

  const auto* vlr_in_vrl = GetLayoutBoxByElementId("vlr-in-vrl");
  EXPECT_EQ(PhysicalOffset(150, 90), vlr_in_vrl->PhysicalLocation());
}

TEST_F(LayoutBoxTest,
       LocationOfAbsoluteAutoTopLeftChildWithContainerScrollbars) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>
      .container { position: relative; }
      .child { position: absolute; }
    </style>
    <div class="container">
      <div id="normal" class="child"></div>
    </div>
    <div class="container vlr">
      <div id="vlr" class="child"></div>
    </div>
    <div class="container vrl">
      <div id="vrl" class="child"></div>
    </div>
    <div class="container rtl">
      <div id="rtl" class="child"></div>
    </div>
    <div class="container rtl vlr">
      <div id="rtl-vlr" class="child"></div>
    </div>
    <div class="container rtl vrl">
      <div id="rtl-vrl" class="child"></div>
    </div>
  )HTML");

  const auto* normal = GetLayoutBoxByElementId("normal");
  // In non-flipped writing mode, child's Location is the location of the
  // top-left corner of its border box relative the top-left corner of its
  // containing box's border box.
  // 90 = container_border_left (50) + container_padding_left (40)
  // 30 = container_border_top (20) + container_padding_top (10)
  EXPECT_EQ(PhysicalOffset(90, 30), normal->PhysicalLocation());

  // Same as "normal".
  const auto* vlr = GetLayoutBoxByElementId("vlr");
  EXPECT_EQ(PhysicalOffset(90, 30), vlr->PhysicalLocation());

  const auto* vrl = GetLayoutBoxByElementId("vrl");
  // The physical location is still about the top-left corners.
  // 65 = container_border_right (30) + container_padding_right (20) +
  //      vertical_scrollbar_width (15)
  // 325 = total_container_width (540) - child_x (65) - total_child_width (150)
  EXPECT_EQ(PhysicalOffset(325, 30), vrl->PhysicalLocation());

  const auto* rtl = GetLayoutBoxByElementId("rtl");
  // 340 = total_container_width (540) - container_border_right (30) -
  //       container_padding_right (20) - total_child_width (150)
  EXPECT_EQ(PhysicalOffset(340, 30), rtl->PhysicalLocation());

  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  // 90 is the same as "vlr".
  // 134 = total_container_height (400) - container_border_bottom (40) -
  //       container_padding_bottom (30) - horizontal_scrollbar_height (16) -
  //       total_child_height (150)
  EXPECT_EQ(PhysicalOffset(90, 134), rtl_vlr->PhysicalLocation());

  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");
  // Horizontal is the same as "vrl".
  // Vertical is the same as "rtl_vlr".
  EXPECT_EQ(PhysicalOffset(325, 134), rtl_vrl->PhysicalLocation());
}

TEST_F(LayoutBoxTest,
       LocationOfAbsoluteAutoTopLeftGrandChildWithContainerScrollbars) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>
      .container { position: relative; }
      .intermediate { width: 200%; height: 200%; }
      .child { position: absolute; }
    </style>
    <div class="container">
      <div class="intermediate">
        <div id="normal" class="child"></div>
      </div>
    </div>
    <div class="container vlr">
      <div class="intermediate">
        <div id="vlr" class="child"></div>
      </div>
    </div>
    <div class="container vrl">
      <div class="intermediate">
        <div id="vrl" class="child"></div>
      </div>
    </div>
    <div class="container rtl">
      <div class="intermediate">
        <div id="rtl" class="child"></div>
      </div>
    </div>
    <div class="container rtl vlr">
      <div class="intermediate">
        <div id="rtl-vlr" class="child"></div>
      </div>
    </div>
    <div class="container rtl vrl">
      <div class="intermediate">
        <div id="rtl-vrl" class="child"></div>
      </div>
    </div>
  )HTML");

  // All locations are the same as
  // LocationOfAbsoluteAutoTopLeftChildWithContainerScrollbars.

  const auto* normal = GetLayoutBoxByElementId("normal");
  EXPECT_EQ(PhysicalOffset(90, 30), normal->PhysicalLocation());

  const auto* vlr = GetLayoutBoxByElementId("vlr");
  EXPECT_EQ(PhysicalOffset(90, 30), vlr->PhysicalLocation());

  const auto* vrl = GetLayoutBoxByElementId("vrl");
  EXPECT_EQ(PhysicalOffset(325, 30), vrl->PhysicalLocation());

  const auto* rtl = GetLayoutBoxByElementId("rtl");
  EXPECT_EQ(PhysicalOffset(340, 30), rtl->PhysicalLocation());

  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  EXPECT_EQ(PhysicalOffset(90, 134), rtl_vlr->PhysicalLocation());

  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");
  EXPECT_EQ(PhysicalOffset(325, 134), rtl_vrl->PhysicalLocation());
}

TEST_F(LayoutBoxTest, LocationOfInFlowChildWithContainerScrollbars) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>.offset { width: 100px; height: 70px; }</style>
    <div class="container">
      <div class="offset"></div>
      <div id="normal" class="child"></div>
    </div>
    <div class="container vlr">
      <div class="offset"></div>
      <div id="vlr" class="child"></div>
    </div>
    <div class="container vrl">
      <div class="offset"></div>
      <div id="vrl" class="child"></div>
    </div>
    <div class="container rtl">
      <div class="offset"></div>
      <div id="rtl" class="child"></div>
    </div>
    <div class="container rtl vlr">
      <div class="offset"></div>
      <div id="rtl-vlr" class="child"></div>
    </div>
    <div class="container rtl vrl">
      <div class="offset"></div>
      <div id="rtl-vrl" class="child"></div>
    </div>
  )HTML");

  const auto* normal = GetLayoutBoxByElementId("normal");
  // In non-flipped writing mode, child's Location is the location of the
  // top-left corner of its border box relative the top-left corner of its
  // containing box's border box.
  // 90 = container_border_left (50) + container_padding_left (40)
  // 100 = container_border_top (20) + container_padding_top (10) +
  //      offset_height (70)
  EXPECT_EQ(PhysicalOffset(90, 100), normal->PhysicalLocation());

  // 190 = container_border_left (50) + container_padding_left (40) +
  //       offset_width (100)
  // 30 = container_border_top (20) + container_padding_top (10)
  const auto* vlr = GetLayoutBoxByElementId("vlr");
  EXPECT_EQ(PhysicalOffset(190, 30), vlr->PhysicalLocation());

  const auto* vrl = GetLayoutBoxByElementId("vrl");
  // The physical location is still about the top-left corners.
  // 225 = total_container_width (540) - total_child_width (150) - 165
  // 30 = container_border_top (20) + container_padding_left (10)
  EXPECT_EQ(PhysicalOffset(225, 30), vrl->PhysicalLocation());

  const auto* rtl = GetLayoutBoxByElementId("rtl");
  // 340 = total_container_width (540) - total_child_width (150) -
  //       container_border_right (30) - contaienr_padding_right (20)
  // 100 is the same as "normal"
  EXPECT_EQ(PhysicalOffset(340, 100), rtl->PhysicalLocation());

  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  // 190 is the same as "normal"
  // 134 = total_container_height (400) - total_child_width (180) -
  //       horizontal_scrollber_height (16) -
  //       container_border_bottom (40) - contaienr_padding_bottom (30)
  EXPECT_EQ(PhysicalOffset(190, 134), rtl_vlr->PhysicalLocation());

  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");
  // Horizontal is the same as "vrl"
  // Vertical is the same as "rtl_vlr"
  EXPECT_EQ(PhysicalOffset(225, 134), rtl_vrl->PhysicalLocation());
}

TEST_F(LayoutBoxTest, LocationOfRelativeChildWithContainerScrollbars) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>
      .offset { width: 100px; height: 70px; }
      .child { position: relative; top: 77px; left: 88px; }
    </style>
    <div class="container">
      <div class="offset"></div>
      <div id="normal" class="child"></div>
    </div>
    <div class="container vlr">
      <div class="offset"></div>
      <div id="vlr" class="child"></div>
    </div>
    <div class="container vrl">
      <div class="offset"></div>
      <div id="vrl" class="child"></div>
    </div>
    <div class="container rtl">
      <div class="offset"></div>
      <div id="rtl" class="child"></div>
    </div>
    <div class="container rtl vlr">
      <div class="offset"></div>
      <div id="rtl-vlr" class="child"></div>
    </div>
    <div class="container rtl vrl">
      <div class="offset"></div>
      <div id="rtl-vrl" class="child"></div>
    </div>
  )HTML");

  // All locations are the same as LocationOfInFlowChildWithContainerScrollbars
  // because relative offset doesn't contribute to box location.

  const auto* normal = GetLayoutBoxByElementId("normal");
  const auto* vlr = GetLayoutBoxByElementId("vlr");
  const auto* vrl = GetLayoutBoxByElementId("vrl");
  const auto* rtl = GetLayoutBoxByElementId("rtl");
  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");

  EXPECT_EQ(PhysicalOffset(178, 177), normal->PhysicalLocation());

  EXPECT_EQ(PhysicalOffset(278, 107), vlr->PhysicalLocation());

  EXPECT_EQ(PhysicalOffset(313, 107), vrl->PhysicalLocation());

  EXPECT_EQ(PhysicalOffset(428, 177), rtl->PhysicalLocation());

  EXPECT_EQ(PhysicalOffset(278, 211), rtl_vlr->PhysicalLocation());

  EXPECT_EQ(PhysicalOffset(313, 211), rtl_vrl->PhysicalLocation());
}

TEST_F(LayoutBoxTest, LocationOfFloatLeftChildWithContainerScrollbars) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>.child { float: left; }</style>
    <div class="container">
      <div id="normal" class="child"></div>
    </div>
    <div class="container vlr">
      <div id="vlr" class="child"></div>
    </div>
    <div class="container vrl">
      <div id="vrl" class="child"></div>
    </div>
    <div class="container rtl">
      <div id="rtl" class="child"></div>
    </div>
    <div class="container rtl vlr">
      <div id="rtl-vlr" class="child"></div>
    </div>
    <div class="container rtl vrl">
      <div id="rtl-vrl" class="child"></div>
    </div>
  )HTML");

  const auto* normal = GetLayoutBoxByElementId("normal");
  // In non-flipped writing mode, child's Location is the location of the
  // top-left corner of its border box relative the top-left corner of its
  // containing box's border box.
  // 90 = container_border_left (50) + container_padding_left (40)
  // 30 = container_border_top (20) + container_padding_top (10)
  EXPECT_EQ(PhysicalOffset(90, 30), normal->PhysicalLocation());

  // Same as "normal".
  const auto* vlr = GetLayoutBoxByElementId("vlr");
  EXPECT_EQ(PhysicalOffset(90, 30), vlr->PhysicalLocation());

  const auto* vrl = GetLayoutBoxByElementId("vrl");
  // The physical location is still about the top-left corners.
  // 65 = container_border_right (30) + container_padding_right (20) +
  //      vertical_scrollbar_width (15)
  // 325 = total_container_width (540) - child_x (65) - total_child_width (150)
  EXPECT_EQ(PhysicalOffset(325, 30), vrl->PhysicalLocation());

  // In horizontal rtl mode, there is scrollbar on the left, so the child is
  // shifted to the right by the width of the scrollbar.
  const auto* rtl = GetLayoutBoxByElementId("rtl");
  EXPECT_EQ(PhysicalOffset(105, 30), rtl->PhysicalLocation());

  // Same as "vlr".
  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  EXPECT_EQ(PhysicalOffset(90, 30), rtl_vlr->PhysicalLocation());

  // Same as "vrl".
  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");
  EXPECT_EQ(PhysicalOffset(325, 30), rtl_vrl->PhysicalLocation());
}

TEST_F(LayoutBoxTest, LocationOfFloatRightChildWithContainerScrollbars) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>.child { float: right; }</style>
    <div class="container">
      <div id="normal" class="child"></div>
    </div>
    <div class="container vlr">
      <div id="vlr" class="child"></div>
    </div>
    <div class="container vrl">
      <div id="vrl" class="child"></div>
    </div>
    <div class="container rtl">
      <div id="rtl" class="child"></div>
    </div>
    <div class="container rtl vlr">
      <div id="rtl-vlr" class="child"></div>
    </div>
    <div class="container rtl vrl">
      <div id="rtl-vrl" class="child"></div>
    </div>
  )HTML");

  const auto* normal = GetLayoutBoxByElementId("normal");
  // In non-flipped writing mode, child's Location is the location of the
  // top-left corner of its border box relative the top-left corner of its
  // containing box's border box.
  // 325 = total_container_width (540) - child_x (65) - total_child_width (150)
  // 30 = container_border_top (20) + container_padding_top (10)
  EXPECT_EQ(PhysicalOffset(325, 30), normal->PhysicalLocation());

  // Same as "normal".
  const auto* vlr = GetLayoutBoxByElementId("vlr");
  // 90 = container_border_left (50) + container_padding_left (40)
  // 134 = total_container_height (400) - total_child_width (180) -
  //       horizontal_scrollber_height (16) -
  //       container_border_bottom (40) - contaienr_padding_bottom (30)
  EXPECT_EQ(PhysicalOffset(90, 134), vlr->PhysicalLocation());

  const auto* vrl = GetLayoutBoxByElementId("vrl");
  // The physical location is still about the top-left corners.
  // 65 = container_border_right (30) + container_padding_right (20) +
  //      vertical_scrollbar_width (15)
  // 325 = total_container_width (540) - child_x (65) - total_child_width (150)
  EXPECT_EQ(PhysicalOffset(325, 134), vrl->PhysicalLocation());

  // In horizontal rtl mode, there is scrollbar on the left, so the child is
  // shifted to the right by the width of the scrollbar.
  const auto* rtl = GetLayoutBoxByElementId("rtl");
  EXPECT_EQ(PhysicalOffset(340, 30), rtl->PhysicalLocation());

  // Same as "vlr".
  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  EXPECT_EQ(PhysicalOffset(90, 134), rtl_vlr->PhysicalLocation());

  // Same as "vrl".
  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");
  EXPECT_EQ(PhysicalOffset(325, 134), rtl_vrl->PhysicalLocation());
}

TEST_F(LayoutBoxTest, GeometriesWithScrollbarsNonScrollable) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <div id="normal" class="container">
      <div class="child"></div>
    </div>
    <div id="vlr" class="container vlr">
      <div class="child"></div>
    </div>
    <div id="vrl" class="container vrl">
      <div class="child"></div>
    </div>
    <div id="rtl" class="container rtl">
      <div class="child"></div>
    </div>
    <div id="rtl-vlr" class="container rtl vlr">
      <div class="child"></div>
    </div>
    <div id="rtl-vrl" class="container rtl vrl">
      <div class="child"></div>
    </div>
  )HTML");

#define EXPECT_ZERO_SCROLL(box)                                            \
  do {                                                                     \
    EXPECT_EQ(PhysicalOffset(), box->ScrolledContentOffset());             \
    const auto* scrollable_area = box->GetScrollableArea();                \
    EXPECT_EQ(gfx::Vector2d(), scrollable_area->ScrollOffsetInt());        \
    EXPECT_EQ(gfx::Point(), scrollable_area->ScrollOrigin());              \
    EXPECT_EQ(gfx::PointF(), scrollable_area->ScrollPosition());           \
    EXPECT_EQ(gfx::Vector2d(), scrollable_area->MaximumScrollOffsetInt()); \
    EXPECT_EQ(gfx::Vector2d(), scrollable_area->MinimumScrollOffsetInt()); \
  } while (false)

  const auto* normal = GetLayoutBoxByElementId("normal");
  EXPECT_ZERO_SCROLL(normal);
  EXPECT_EQ(gfx::Vector2d(), normal->OriginAdjustmentForScrollbars());
  // 540 = border_left + padding_left + width + padding_right + border_right
  // 400 = border_top + padding_top + height + padding_bottom + border_bottom
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), normal->PhysicalBorderBoxRect());
  // 50 = border_left, 20 = border_top
  // 445 = padding_left + (width - scrollbar_width) + padding_right
  // 324 = padding_top + (height - scrollbar_height) + padding_bottom
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), normal->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), normal->PhysicalPaddingBoxRect());
  // 90 = border_left + padding_left, 30 = border_top + padding_top
  // 385 = width - scrollbar_width, 284 = height - scrollbar_height
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), normal->PhysicalContentBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), normal->ScrollableOverflowRect());

  const auto* vlr = GetLayoutBoxByElementId("vlr");
  // Same as "normal"
  EXPECT_ZERO_SCROLL(vlr);
  EXPECT_EQ(gfx::Vector2d(), vlr->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), vlr->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vlr->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vlr->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), vlr->PhysicalContentBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vlr->ScrollableOverflowRect());

  const auto* vrl = GetLayoutBoxByElementId("vrl");
  // Same as "normal".
  EXPECT_ZERO_SCROLL(vrl);
  EXPECT_EQ(gfx::Vector2d(), vrl->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), vrl->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vrl->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vrl->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), vrl->PhysicalContentBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vrl->ScrollableOverflowRect());

  const auto* rtl = GetLayoutBoxByElementId("rtl");
  EXPECT_ZERO_SCROLL(rtl);
  // The scrollbar is on the left, shifting padding box and content box to the
  // right by 15px.
  EXPECT_EQ(gfx::Vector2d(15, 0), rtl->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), rtl->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(65, 20, 445, 324), rtl->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(65, 20, 445, 324), rtl->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(105, 30, 385, 284), rtl->PhysicalContentBoxRect());
  EXPECT_EQ(PhysicalRect(65, 20, 445, 324), rtl->ScrollableOverflowRect());

  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  // Same as "vlr".
  EXPECT_ZERO_SCROLL(rtl_vlr);
  EXPECT_EQ(gfx::Vector2d(), rtl_vlr->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), rtl_vlr->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vlr->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vlr->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), rtl_vlr->PhysicalContentBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vlr->ScrollableOverflowRect());

  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");
  // Same as "vrl".
  EXPECT_ZERO_SCROLL(rtl_vrl);
  EXPECT_EQ(gfx::Vector2d(), rtl_vrl->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), rtl_vrl->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vrl->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vrl->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), rtl_vrl->PhysicalContentBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vrl->ScrollableOverflowRect());
}

TEST_F(LayoutBoxTest, GeometriesWithScrollbarsScrollable) {
  SetBodyInnerHTML(CommonStyleForGeometryWithScrollbarTests() + R"HTML(
    <style>
      .child { width: 2000px; height: 1000px; box-sizing: border-box;}
    </style>
    <div id="normal" class="container">
      <div class="child"></div>
    </div>
    <div id="vlr" class="container vlr">
      <div class="child"></div>
    </div>
    <div id="vrl" class="container vrl">
      <div class="child"></div>
    </div>
    <div id="rtl" class="container rtl">
      <div class="child"></div>
    </div>
    <div id="rtl-vlr" class="container rtl vlr">
      <div class="child"></div>
    </div>
    <div id="rtl-vrl" class="container rtl vrl">
      <div class="child"></div>
    </div>
  )HTML");

  const auto* normal = GetLayoutBoxByElementId("normal");
  const auto* scrollable_area = normal->GetScrollableArea();
  EXPECT_EQ(PhysicalOffset(), normal->ScrolledContentOffset());
  EXPECT_EQ(gfx::Vector2d(), normal->OriginAdjustmentForScrollbars());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->ScrollOffsetInt());
  EXPECT_EQ(PhysicalRect(50, 20, 2060, 1040), normal->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 716),
            scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(), scrollable_area->ScrollPosition());
  // These are the same as in the NonScrollable test.
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), normal->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), normal->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), normal->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), normal->PhysicalContentBoxRect());

  const auto* vlr = GetLayoutBoxByElementId("vlr");
  scrollable_area = vlr->GetScrollableArea();
  EXPECT_EQ(PhysicalOffset(), vlr->ScrolledContentOffset());
  EXPECT_EQ(gfx::Vector2d(), vlr->OriginAdjustmentForScrollbars());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->ScrollOffsetInt());
  EXPECT_EQ(PhysicalRect(50, 20, 2060, 1040), vlr->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 716),
            scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(), scrollable_area->ScrollPosition());
  // These are the same as in the NonScrollable test.
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), vlr->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vlr->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vlr->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), vlr->PhysicalContentBoxRect());

  const auto* vrl = GetLayoutBoxByElementId("vrl");
  scrollable_area = vrl->GetScrollableArea();
  EXPECT_EQ(PhysicalOffset(), vrl->ScrolledContentOffset());
  EXPECT_EQ(gfx::Vector2d(), vrl->OriginAdjustmentForScrollbars());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->ScrollOffsetInt());
  // Same as "vlr" except for flipping.
  EXPECT_EQ(PhysicalRect(-1565, 20, 2060, 1040), vrl->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(0, 716), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(-1615, 0), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(1615, 0), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(1615, 0), scrollable_area->ScrollPosition());
  // These are the same as in the NonScrollable test.
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), vrl->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vrl->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), vrl->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), vrl->PhysicalContentBoxRect());

  const auto* rtl = GetLayoutBoxByElementId("rtl");
  scrollable_area = rtl->GetScrollableArea();
  EXPECT_EQ(PhysicalOffset(), rtl->ScrolledContentOffset());
  EXPECT_EQ(gfx::Vector2d(15, 0), rtl->OriginAdjustmentForScrollbars());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->ScrollOffsetInt());
  EXPECT_EQ(PhysicalRect(-1550, 20, 2060, 1040), rtl->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(0, 716), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(-1615, 0), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(1615, 0), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(1615, 0), scrollable_area->ScrollPosition());
  // These are the same as in the NonScrollable test.
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), rtl->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(65, 20, 445, 324), rtl->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(65, 20, 445, 324), rtl->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(105, 30, 385, 284), rtl->PhysicalContentBoxRect());

  const auto* rtl_vlr = GetLayoutBoxByElementId("rtl-vlr");
  scrollable_area = rtl_vlr->GetScrollableArea();
  EXPECT_EQ(PhysicalOffset(), rtl_vlr->ScrolledContentOffset());
  EXPECT_EQ(gfx::Vector2d(), rtl_vlr->OriginAdjustmentForScrollbars());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->ScrollOffsetInt());
  EXPECT_EQ(PhysicalRect(50, -696, 2060, 1040),
            rtl_vlr->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 0), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(0, -716), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(0, 716), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(0, 716), scrollable_area->ScrollPosition());
  // These are the same as in the NonScrollable test.
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), rtl_vlr->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vlr->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vlr->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), rtl_vlr->PhysicalContentBoxRect());

  const auto* rtl_vrl = GetLayoutBoxByElementId("rtl-vrl");
  scrollable_area = rtl_vrl->GetScrollableArea();
  EXPECT_EQ(PhysicalOffset(), rtl_vrl->ScrolledContentOffset());
  EXPECT_EQ(gfx::Vector2d(), rtl_vr
```