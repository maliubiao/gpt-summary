Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of a test file for the Blink rendering engine. The specific instructions are:

1. **List functionalities:**  Identify what aspects of the layout engine are being tested.
2. **Relate to web technologies (JavaScript, HTML, CSS):** Explain how the tested functionalities connect to these web standards with examples.
3. **Provide logical reasoning with examples:**  If a test involves a conditional behavior, give hypothetical input and expected output.
4. **Illustrate common user/programming errors:** If a test prevents or demonstrates a potential mistake, provide an example of that error.
5. **Summarize the overall functionality:** Give a concise overview of the purpose of the code snippet.

Let's break down the code and address each point.

**Code Analysis and Functionality Identification:**

The code consists of several `TEST_F` functions within a `LayoutBoxTest` class. Each `TEST_F` focuses on a specific aspect of how `LayoutBox` objects behave within the Blink rendering engine. Here's a breakdown of the individual tests:

* **Scroll Offset and Rectangles with RTL:** Tests how scroll offsets, scrollable overflow rects, and other related properties are calculated for right-to-left (RTL) content with different writing modes (vertical-lr and vertical-rl).
* **Thick Scrollbar Subpixel Size Margin No Dirty Layout After Layout:** Checks that the layout system doesn't get into a loop when dealing with thick scrollbars and subpixel margins, ensuring a single layout pass is sufficient.
* **MenuListIntrinsicBlockSize:**  Verifies that a menu list (select element) with `content-visibility: hidden` doesn't cause a crash during layout.
* **HasReflection:**  Checks which elements create compositing layers and have reflections when `-webkit-box-reflect` is applied.
* **PhysicalVisualOverflowRectIncludingFilters:** Tests the calculation of the visual overflow rectangle, considering CSS filters and zoom.
* **SetNeedsOverflowRecalcLayoutBox/FlexBox:**  Tests whether applying a transform triggers a recalculation of scrollable overflow for regular layout boxes and flex containers.
* **ScrollsWithViewportRelativePosition/FixedPosition/FixedPositionInsideTransform:**  Checks if a layout box is considered "fixed to the viewport" based on its `position` style and the presence of ancestor transforms.
* **HitTestResizerWithTextAreaChild/StackedWithTextAreaChild:** Tests the hit-testing behavior of resizable elements when they contain a textarea. It verifies that clicks on the resizer are correctly attributed to the resizer, not the textarea.
* **AnchorInFragmentedContainingBlock/InlineContainingBlock/InlineContainingBlockWithNameConflicts:** Tests the behavior of CSS anchors (`anchor-name` and `anchor`) within different types of containing blocks (multicol, inline) and when there are multiple anchors with the same name.
* **IsUserScrollable/IsUserScrollableLayoutView:** Tests whether an element or the viewport is considered user-scrollable based on its `overflow` style and content size.
* **LogicalTopLogicalLeft:** Tests the calculation of logical top and left offsets for elements within containers with different writing modes.
* **LayoutBoxBackgroundPaintLocationTest (multiple tests):** A series of tests focused on when and where the background of a scrollable element is painted (either in the content space or the border box space), considering factors like `background-clip`, `background-attachment`, borders, box shadows, and custom scrollbars.

**Relating to Web Technologies:**

* **HTML:** The tests use HTML elements like `div`, `table`, `select`, `textarea`, `img`, and `svg` to create the layout structures being tested. For example, the "MenuListIntrinsicBlockSize" test directly involves the `<select>` element. The "AnchorIn..." tests use `<div>` and `<span>` elements with specific IDs.
* **CSS:**  CSS properties like `width`, `height`, `margin`, `overflow`, `resize`, `transform`, `position`, `writing-mode`, `content-visibility`, `-webkit-box-reflect`, `filter`, `anchor-name`, `anchor`, `background`, `border`, `box-shadow`, `border-image`, and custom scrollbar styling (`::-webkit-scrollbar`) are heavily used to set up the test scenarios. For instance, the "PhysicalVisualOverflowRectIncludingFilters" test uses `filter: blur(2px)` and `zoom: 2`. The "IsUserScrollable" tests manipulate the `overflow` property.
* **JavaScript (indirectly):** While the test file is C++, it validates the behavior of the rendering engine that interprets and applies JavaScript's effects on the DOM and CSSOM. For example, JavaScript could dynamically change the `style` attribute or add/remove classes, and these tests ensure the layout engine responds correctly. The test "SetNeedsOverflowRecalcLayoutBox" adds and removes a CSS class using `element->classList().Add/Remove()`, simulating a JavaScript interaction.

**Logical Reasoning with Examples:**

* **Scroll Offset and Rectangles with RTL:**
    * **Hypothetical Input:** A `div` with `direction: rtl`, `overflow: scroll`, and a child element that overflows both horizontally and vertically. Different `writing-mode` values (`vertical-lr`, `vertical-rl`) are applied.
    * **Expected Output:** The test asserts specific values for `ScrollableOverflowRect`, `MaximumScrollOffsetInt`, `MinimumScrollOffsetInt`, `ScrollOrigin`, and `ScrollPosition`. The exact values depend on the dimensions and writing mode, demonstrating how RTL and vertical writing modes affect scroll behavior.
* **PhysicalVisualOverflowRectIncludingFilters:**
    * **Hypothetical Input:** A `div` with `filter: blur(2px)` and `zoom: 2`.
    * **Expected Output:** The `VisualOverflowRectIncludingFilters` will be larger than the element's content box due to the blur effect expanding the rendering area and the zoom scaling it. The test expects a specific `PhysicalRect`.
* **AnchorInInlineContainingBlockWithNameConflicts:**
    * **Hypothetical Input:** Three `span` elements, each with `position: relative` and containing an anchor with the same `anchor-name: --a` and a target element that references that anchor.
    * **Expected Output:**  Each target element will correctly resolve to the *nearest* preceding anchor with the matching name within its containing block. This demonstrates the scoping rules for CSS anchors.

**Common User/Programming Errors:**

* **Thick Scrollbar Subpixel Size Margin No Dirty Layout After Layout:** This test prevents an infinite layout loop. A common error could be setting styles that cause the appearance of scrollbars to change after the initial layout, potentially triggering another layout and so on. This test ensures the engine handles this gracefully.
* **HitTestResizerWithTextAreaChild/StackedWithTextAreaChild:**  These tests prevent a scenario where a user intends to interact with a resizable element's handle, but the click is incorrectly captured by a child element (the textarea). A common user error would be trying to resize the container but inadvertently focusing the textarea instead.
* **AnchorInInlineContainingBlockWithNameConflicts:**  This highlights a potential pitfall in using CSS anchors. If developers use the same `anchor-name` multiple times within the same scope, they need to be aware that the target will resolve to the first matching anchor encountered in the DOM tree. A common programming error would be assuming a target will link to a *specific* anchor when multiple anchors share the same name.

**Summary of Functionality:**

This code snippet is a collection of unit tests for the `LayoutBox` class in the Chromium Blink rendering engine. It comprehensively tests various aspects of how layout boxes are positioned, sized, scrolled, and rendered, particularly focusing on edge cases and interactions with different CSS properties, including those related to internationalization (RTL), overflow, transforms, compositing, hit-testing, and CSS anchors. The tests aim to ensure the layout engine behaves correctly and robustly under a variety of conditions, preventing crashes and layout inconsistencies. The tests also cover scenarios that could lead to common developer errors or unexpected behavior.

这是对 `blink/renderer/core/layout/layout_box_test.cc` 文件第三部分的分析归纳。结合前两部分（未提供），我们可以推断出整个文件的目的是对 `LayoutBox` 类的各种功能进行全面的单元测试。

**这部分的功能归纳:**

这部分主要集中在测试 `LayoutBox` 中与以下方面相关的功能：

1. **滚动行为和属性 (RTL 环境):**  继续测试在从右到左 (RTL) 的书写模式下，`LayoutBox` 的滚动行为，包括滚动区域的计算、最大/最小滚动偏移量、滚动原点和滚动位置。它验证了 `vertical-lr` 和 `vertical-rl` 这两种垂直书写模式下的行为。
    * **例子:**  测试用例 `TEST_F(LayoutBoxTest, ScrollOffsetAndRectangles)` 针对 `rtl_vrl` (RTL, vertical-rl) 的 `LayoutBox`，验证了其 `ScrollableOverflowRect()`， `MaximumScrollOffsetInt()`， `MinimumScrollOffsetInt()`， `ScrollOrigin()` 和 `ScrollPosition()` 等属性的正确计算。

2. **滚动条和布局更新:**  测试在出现需要滚动条的情况时，特别是在涉及到亚像素尺寸和边距时，布局系统是否能够正确处理，避免不必要的重复布局 (dirty layout)。
    * **例子:** `TEST_F(LayoutBoxTest, ThickScrollbarSubpixelSizeMarginNoDirtyLayoutAfterLayout)` 模拟了一个水平溢出导致垂直滚动条出现的情况，并检查在布局后是否还有未完成的脏布局。

3. **`content-visibility: hidden` 对菜单列表的影响:**  测试当一个菜单列表 (`<select>`) 设置了 `content-visibility: hidden` 属性时，布局系统是否能够正常工作，避免崩溃。
    * **例子:** `TEST_F(LayoutBoxTest, MenuListIntrinsicBlockSize)` 测试了这种情况，如果程序没有崩溃，则测试通过。

4. **元素反射:**  测试 `-webkit-box-reflect` CSS 属性对不同 HTML 元素（如 `<table>`, `<tr>`, `<colgroup>`, `<col>`, `<td>`, `<svg>`, `<text>`）的影响，验证哪些元素会创建层并具有反射效果。
    * **例子:** `TEST_F(LayoutBoxTest, HasReflection)` 测试了应用 `-webkit-box-reflect: above;` 后，不同元素 `HasLayer()` 和 `HasReflection()` 的返回值是否符合预期。

5. **包含滤镜的视觉溢出矩形:**  测试当元素应用了 CSS 滤镜 (如 `blur`) 和缩放 (`zoom`) 时，视觉溢出矩形的计算是否正确。
    * **例子:** `TEST_F(LayoutBoxTest, PhysicalVisualOverflowRectIncludingFilters)` 测试了一个应用了 `filter: blur(2px)` 和 `zoom: 2` 的 `div` 元素的 `VisualOverflowRectIncludingFilters()` 的值。

6. **触发溢出重计算:**  测试通过 JavaScript 修改元素的 CSS 属性 (如 `transform`)，是否能够正确触发布局对象 (包括普通 `LayoutBox` 和 Flexbox) 的溢出重计算。
    * **例子:** `TEST_F(LayoutBoxTest, SetNeedsOverflowRecalcLayoutBox)` 和 `TEST_F(LayoutBoxTest, SetNeedsOverflowRecalcFlexBox)` 通过添加和移除 CSS `transform` 属性，验证 `NeedsVisualOverflowRecalc()` 标志的设置。

7. **元素是否固定在视口:**  测试不同 `position` 属性值 (`relative`, `fixed`) 以及父元素存在 `transform` 属性时，`LayoutBox` 是否被认为是固定在视口。
    * **例子:** `TEST_F(LayoutBoxTest, ScrollsWithViewportFixedPositionInsideTransform)` 测试了当一个 `position: fixed` 的元素位于一个设置了 `transform` 的父元素内时，其 `IsFixedToView()` 的返回值。

8. **命中测试和可调整大小元素:**  测试当一个可调整大小的元素 (`resize: both`) 包含一个 `textarea` 子元素时，命中测试是否能够正确识别调整大小的边框。
    * **例子:** `TEST_F(LayoutBoxTest, HitTestResizerWithTextAreaChild)` 和 `TEST_F(LayoutBoxTest, HitTestResizerStackedWithTextAreaChild)` 验证了点击调整大小的边框时，命中测试返回的是父元素 (可调整大小的 `div`)，而不是子元素 (`textarea`)。

9. **CSS 锚点:**  测试 CSS 锚点 (`anchor-name` 和 `anchor` 属性) 在不同类型的包含块 (分栏布局、行内布局) 中的工作方式，以及当存在同名锚点时的解析规则。
    * **例子:** `TEST_F(LayoutBoxTest, AnchorInFragmentedContainingBlock)` 测试了在分栏布局中，锚点和目标元素的正确关联。 `TEST_F(LayoutBoxTest, AnchorInInlineContainingBlockWithNameConflicts)` 测试了当多个锚点具有相同名称时，目标元素如何解析锚点。

10. **用户是否可以滚动:**  测试基于 `overflow` CSS 属性和内容大小，`LayoutBox` 和 `LayoutView` 是否被认为是用户可滚动的。
    * **例子:** `TEST_F(LayoutBoxTest, IsUserScrollable)` 和 `TEST_F(LayoutBoxTest, IsUserScrollableLayoutView)` 通过修改 `overflow` 属性和内容高度，验证 `ScrollsOverflow()` 和 `IsUserScrollable()` 的返回值。

11. **逻辑上的上边距和左边距:**  测试在不同的书写模式下，`LayoutBox` 的逻辑上边距 (`LogicalTop()`) 和左边距 (`LogicalLeft()`) 的计算方式。
    * **例子:** `TEST_F(LayoutBoxTest, LogicalTopLogicalLeft)` 测试了在不同 `writing-mode` 的容器中，子元素的 `LogicalTop()` 和 `LogicalLeft()` 的值，并考虑了边距的影响。

12. **背景绘制位置:**  通过一系列 `LayoutBoxBackgroundPaintLocationTest` 测试用例，详细测试了 `LayoutBox` 背景的绘制位置 (在内容盒空间还是边框盒空间)，并考虑了 `background-clip`, `background-attachment`, 边框样式、盒阴影和自定义滚动条等多种因素的影响。
    * **例子:**  `TEST_P(LayoutBoxBackgroundPaintLocationTest, ContentBoxClipZeroPadding)` 测试了当 `background-clip` 设置为 `content-box` 且没有内边距时，背景的绘制位置。`TEST_P(LayoutBoxBackgroundPaintLocationTest, BorderBoxClipColorTranslucentBorder)` 测试了当边框是半透明时背景的绘制位置。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:** 测试代码中使用了大量的 HTML 元素，如 `<div>`, `<select>`, `<table>`, `<img>` 等，来构建测试场景。例如，`SetBodyInnerHTML(R"HTML(<div id="target" style="width: 100px; height: 100px; overflow: auto;">...</div>)HTML");` 创建了一个具有特定样式和 ID 的 `div` 元素。
* **CSS:**  测试用例通过设置元素的 `style` 属性或者插入 `<style>` 标签来应用 CSS 样式。例如，`element->classList().Add(AtomicString("transform"));` 模拟了 JavaScript 添加 CSS 类，而 `InsertStyleElement(R"CSS(#multicol { column-count: 3; ... })CSS");` 则直接插入了 CSS 规则。测试覆盖了各种 CSS 属性，如 `width`, `height`, `overflow`, `transform`, `position`, `writing-mode`, `background`, `border`, `box-shadow`, `anchor-name`, `anchor` 等。
* **JavaScript:**  虽然测试代码本身是 C++，但它模拟了 JavaScript 对 DOM 和 CSSOM 的操作。例如，通过 `element->classList().Add()` 和 `element->setAttribute()` 修改元素样式，这与 JavaScript 中的 `element.classList.add()` 和 `element.setAttribute()` 功能类似。测试验证了在这些动态修改下，布局引擎的行为是否符合预期。

**假设输入与输出的例子:**

* **`TEST_F(LayoutBoxTest, ScrollsWithViewportFixedPosition)`:**
    * **假设输入:** HTML 代码 `<div id='target' style='position: fixed'></div>`
    * **预期输出:** `GetLayoutBoxByElementId("target")->IsFixedToView()` 返回 `true`。

* **`TEST_F(LayoutBoxTest, PhysicalVisualOverflowRectIncludingFilters)`:**
    * **假设输入:** HTML 代码 `<div id="target" style="filter: blur(2px); width: 100px; height: 100px">`，父元素 `zoom: 2`。
    * **预期输出:** `GetLayoutBoxByElementId("target")->VisualOverflowRectIncludingFilters()` 返回 `PhysicalRect(-12, -12, 224, 424)`。 (这个结果是通过滤镜的模糊范围和缩放比例计算出来的)

**涉及用户或者编程常见的使用错误举例:**

* **`TEST_F(LayoutBoxTest, ThickScrollbarSubpixelSizeMarginNoDirtyLayoutAfterLayout)`:**  这个测试防止了由于滚动条的出现和亚像素尺寸导致的无限布局循环。用户可能错误地设置了某些样式，导致滚动条在布局过程中反复出现和消失，从而引发性能问题。
* **`TEST_F(LayoutBoxTest, AnchorInInlineContainingBlockWithNameConflicts)`:**  这个测试展示了当在同一个作用域内使用重复的 `anchor-name` 时，锚点的解析规则。用户可能会错误地认为所有同名锚点都能被链接到，而实际上只有第一个会被匹配到。
* **背景绘制位置相关的测试:**  这些测试覆盖了各种复杂的背景绘制场景，例如半透明边框和背景的组合，自定义滚动条等。开发者可能会对这些情况下背景的绘制位置感到困惑，而这些测试可以帮助确保 Blink 引擎在这种复杂情况下也能正确渲染。

总而言之，这部分测试延续了对 `LayoutBox` 类的细致测试，涵盖了滚动、布局更新、特殊 CSS 属性（如 `content-visibility`, `-webkit-box-reflect`, 锚点）、用户可滚动性以及复杂的背景绘制场景。它旨在确保 Blink 引擎在处理各种 HTML 和 CSS 组合时都能提供稳定和符合预期的布局行为。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_box_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
l->OriginAdjustmentForScrollbars());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->ScrollOffsetInt());
  // Same as "vlr" except for flipping.
  EXPECT_EQ(PhysicalRect(-1565, -696, 2060, 1040),
            rtl_vrl->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(-1615, -716),
            scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(1615, 716), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(1615, 716), scrollable_area->ScrollPosition());
  EXPECT_EQ(gfx::Vector2d(), rtl_vrl->OriginAdjustmentForScrollbars());
  // These are the same as in the NonScrollable test.
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), rtl_vrl->PhysicalBorderBoxRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vrl->NoOverflowRect());
  EXPECT_EQ(PhysicalRect(50, 20, 445, 324), rtl_vrl->PhysicalPaddingBoxRect());
  EXPECT_EQ(PhysicalRect(90, 30, 385, 284), rtl_vrl->PhysicalContentBoxRect());
}

TEST_F(LayoutBoxTest,
       ThickScrollbarSubpixelSizeMarginNoDirtyLayoutAfterLayout) {
  // |target| creates horizontal scrollbar during layout because the contents
  // overflow horizontally, which causes vertical overflow because the
  // horizontal scrollbar reduces available height. For now we suppress
  // creation of the vertical scrollbar because otherwise we would need another
  // layout. The subpixel margin and size cause change of pixel snapped border
  // size after layout which requires repositioning of the overflow controls.
  // This test ensures there is no left-over dirty layout.
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar {
        width: 100px;
        height: 100px;
        background: blue;
      }
    </style>
    <div id="target"
         style="width: 150.3px; height: 150.3px; margin: 10.4px;
                font-size: 30px; overflow: auto">
      <div style="width: 200px; height: 80px"></div>
    </div>
  )HTML");

  DCHECK(!GetLayoutObjectByElementId("target")->NeedsLayout());
}

// crbug.com/1108270
TEST_F(LayoutBoxTest, MenuListIntrinsicBlockSize) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden; }
    </style>
    <select id=container class=hidden>
  )HTML");
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason ::kTest);
  // The test passes if no crash.
}

TEST_F(LayoutBoxTest, HasReflection) {
  SetBodyInnerHTML(R"HTML(
    <style>* { -webkit-box-reflect: above; }</style>
    <table id="table">
      <colgroup id="colgroup">
        <col id="col">
      </colgroup>
      <tr id="tr"><td id="td">TD</td></tr>
    </table>
    <svg id="svg">
      <text id="svg-text">SVG text</text>
    </svg>
  )HTML");

  auto check_has_layer_and_reflection = [&](const char* element_id,
                                            bool expected) {
    auto* object = GetLayoutObjectByElementId(element_id);
    EXPECT_EQ(expected, object->HasLayer()) << element_id;
    EXPECT_EQ(expected, object->HasReflection()) << element_id;
  };
  check_has_layer_and_reflection("table", true);
  check_has_layer_and_reflection("tr", true);
  check_has_layer_and_reflection("colgroup", false);
  check_has_layer_and_reflection("col", false);
  check_has_layer_and_reflection("td", true);
  check_has_layer_and_reflection("svg", true);
  check_has_layer_and_reflection("svg-text", false);
}

TEST_F(LayoutBoxTest, PhysicalVisualOverflowRectIncludingFilters) {
  SetBodyInnerHTML(R"HTML(
    <div style="zoom: 2">
      <div id="target" style="filter: blur(2px); width: 100px; height: 100px">
        <!-- An overflowing self-painting child -->
        <div style="position: relative; height: 200px"></div>
      </div>
    </div>
  )HTML");

  // 12: blur(2) * blur-extent-ratio(3) * zoom(2)
  EXPECT_EQ(
      PhysicalRect(-12, -12, 224, 424),
      GetLayoutBoxByElementId("target")->VisualOverflowRectIncludingFilters());
}

TEST_F(LayoutBoxTest, SetNeedsOverflowRecalcLayoutBox) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .transform { transform: translateX(10px); }
    </style>
    <img id="img">
  )HTML");
  Element* element = GetElementById("img");
  LayoutObject* target = element->GetLayoutObject();
  EXPECT_FALSE(target->SelfNeedsScrollableOverflowRecalc());

  element->classList().Add(AtomicString("transform"));
  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_TRUE(target->PaintingLayer()->NeedsVisualOverflowRecalc());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->SelfNeedsScrollableOverflowRecalc());

  element->classList().Remove(AtomicString("transform"));
  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_TRUE(target->PaintingLayer()->NeedsVisualOverflowRecalc());
}

TEST_F(LayoutBoxTest, SetNeedsOverflowRecalcFlexBox) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .transform { transform: translateX(10px); }
    </style>
    <div id="flex" style="display: flex"></div>
  )HTML");
  Element* element = GetElementById("flex");
  LayoutObject* target = element->GetLayoutObject();
  EXPECT_FALSE(target->SelfNeedsScrollableOverflowRecalc());

  element->classList().Add(AtomicString("transform"));
  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_TRUE(target->PaintingLayer()->NeedsVisualOverflowRecalc());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->SelfNeedsScrollableOverflowRecalc());

  element->classList().Remove(AtomicString("transform"));
  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EXPECT_TRUE(target->PaintingLayer()->NeedsVisualOverflowRecalc());
}

TEST_F(LayoutBoxTest, ScrollsWithViewportRelativePosition) {
  SetBodyInnerHTML("<div id='target' style='position: relative'></div>");
  EXPECT_FALSE(GetLayoutBoxByElementId("target")->IsFixedToView());
}

TEST_F(LayoutBoxTest, ScrollsWithViewportFixedPosition) {
  SetBodyInnerHTML("<div id='target' style='position: fixed'></div>");
  EXPECT_TRUE(GetLayoutBoxByElementId("target")->IsFixedToView());
}

TEST_F(LayoutBoxTest, ScrollsWithViewportFixedPositionInsideTransform) {
  SetBodyInnerHTML(R"HTML(
    <div style='transform: translateZ(0)'>
      <div id='target' style='position: fixed'></div>
    </div>
    <div style='width: 10px; height: 1000px'></div>
  )HTML");
  EXPECT_FALSE(GetLayoutBoxByElementId("target")->IsFixedToView());
}

TEST_F(LayoutBoxTest, HitTestResizerWithTextAreaChild) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id="target"
         style="width: 100px; height: 100px; overflow: auto; resize: both">
      <textarea id="textarea"
          style="width: 100%; height: 100%; resize: none"></textarea>
    </div>
  )HTML");

  EXPECT_EQ(GetElementById("target"), HitTest(99, 99));
  EXPECT_TRUE(HitTest(1, 1)->IsDescendantOrShadowDescendantOf(
      GetElementById("textarea")));
}

TEST_F(LayoutBoxTest, HitTestResizerStackedWithTextAreaChild) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id="target" style="position: relative; width: 100px; height: 100px;
                            overflow: auto; resize: both">
      <textarea id="textarea"
          style="width: 100%; height: 100%; resize: none"></textarea>
    </div>
  )HTML");

  EXPECT_EQ(GetElementById("target"), HitTest(99, 99));
  EXPECT_TRUE(HitTest(1, 1)->IsDescendantOrShadowDescendantOf(
      GetElementById("textarea")));
}

TEST_F(LayoutBoxTest, AnchorInFragmentedContainingBlock) {
  // Create a 3-column multicol layout with a fragmented containing block,
  // and a fragmented anchor element that starts from the second fragment.
  InsertStyleElement(R"CSS(
    #multicol {
      column-count: 3;
      column-width: 90px;
      column-gap: 10px;
      width: 300px;
      height: 100px;
    }
    #cb {
      position: relative;
      height: 300px;
    }
    #spacer {
      height: 110px;
    }
    #anchor {
      height: 120px;
      anchor-name: --a;
    }
    #target {
      position: absolute;
    }
  )CSS");
  SetBodyInnerHTML(R"HTML(
    <div id="multicol">
      <div id="cb">
        <div id="spacer"></div>
        <div id="anchor"></div>
        <div id="target" anchor="anchor"></div>
      </div>
    </div>
  )HTML");

  const LayoutBox* target = To<LayoutBox>(GetLayoutObjectByElementId("target"));
  EXPECT_EQ(GetLayoutObjectByElementId("anchor"),
            target->FindTargetAnchor(*MakeGarbageCollected<ScopedCSSName>(
                AtomicString("--a"), &GetDocument())));
  EXPECT_EQ(GetLayoutObjectByElementId("anchor"),
            target->AcceptableImplicitAnchor());
}

TEST_F(LayoutBoxTest, AnchorInInlineContainingBlock) {
  SetBodyInnerHTML(R"HTML(
    <div>
      <span id="not-implicit-anchor">not implicit anchor</span>
      <span style="position: relative">
        <span id="anchor" style="anchor-name: --a">anchor</span>
        <div id="target" anchor="not-implicit-anchor"
             style="position: absolute; top: anchor(--a top)"></div>
      </span>
      some text
    </div>
  )HTML");

  const LayoutBox* target = To<LayoutBox>(GetLayoutObjectByElementId("target"));
  EXPECT_EQ(GetLayoutObjectByElementId("anchor"),
            target->FindTargetAnchor(*MakeGarbageCollected<ScopedCSSName>(
                AtomicString("--a"), &GetDocument())));
  EXPECT_FALSE(target->AcceptableImplicitAnchor());
}

TEST_F(LayoutBoxTest, AnchorInInlineContainingBlockWithNameConflicts) {
  SetBodyInnerHTML(R"HTML(
    <div>
      <span style="position: relative">
        <span id="anchor1" style="anchor-name: --a">anchor</span>
        <div id="target1" style="position: absolute;top: anchor(--a top)"></div>
      </span>
      <span style="position: relative">
        <span id="anchor2" style="anchor-name: --a">anchor</span>
        <div id="target2" style="position: absolute;top: anchor(--a top)"></div>
      </span>
      <span style="position: relative">
        <span id="anchor3" style="anchor-name: --a">anchor</span>
        <div id="target3" style="position: absolute;top: anchor(--a top)"></div>
      </span>
    </div>
  )HTML");

  const ScopedCSSName& anchor_name =
      *MakeGarbageCollected<ScopedCSSName>(AtomicString("--a"), &GetDocument());

  const LayoutBox* target1 =
      To<LayoutBox>(GetLayoutObjectByElementId("target1"));
  EXPECT_EQ(GetLayoutObjectByElementId("anchor1"),
            target1->FindTargetAnchor(anchor_name));

  const LayoutBox* target2 =
      To<LayoutBox>(GetLayoutObjectByElementId("target2"));
  EXPECT_EQ(GetLayoutObjectByElementId("anchor2"),
            target2->FindTargetAnchor(anchor_name));

  const LayoutBox* target3 =
      To<LayoutBox>(GetLayoutObjectByElementId("target3"));
  EXPECT_EQ(GetLayoutObjectByElementId("anchor3"),
            target3->FindTargetAnchor(anchor_name));
}

TEST_F(LayoutBoxTest, IsUserScrollable) {
  SetBodyInnerHTML(R"HTML("
    <style>
      #target { width: 100px; height: 100px; overflow: auto; }
    </style>
    <div id="target">
      <div id="content" style="height: 200px"></div>
    </div>
  )HTML");

  auto* target_element = GetElementById("target");
  auto* target = target_element->GetLayoutBox();
  EXPECT_TRUE(target->ScrollsOverflow());
  EXPECT_TRUE(target->IsUserScrollable());

  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("overflow: hidden"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->ScrollsOverflow());
  EXPECT_FALSE(target->IsUserScrollable());

  target_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  GetElementById("content")->setAttribute(html_names::kStyleAttr,
                                          AtomicString("height: 0"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(target->ScrollsOverflow());
  EXPECT_FALSE(target->IsUserScrollable());
}

TEST_F(LayoutBoxTest, IsUserScrollableLayoutView) {
  SetBodyInnerHTML(R"HTML("
    <div id="content" style="height: 2000px"></div>
  )HTML");

  EXPECT_TRUE(GetLayoutView().ScrollsOverflow());
  EXPECT_TRUE(GetLayoutView().IsUserScrollable());

  GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                     AtomicString("overflow: hidden"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetLayoutView().ScrollsOverflow());
  EXPECT_FALSE(GetLayoutView().IsUserScrollable());

  GetDocument().body()->setAttribute(html_names::kStyleAttr, g_empty_atom);
  GetElementById("content")->setAttribute(html_names::kStyleAttr,
                                          AtomicString("height: 0"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(GetLayoutView().ScrollsOverflow());
  EXPECT_FALSE(GetLayoutView().IsUserScrollable());
}

TEST_F(LayoutBoxTest, LogicalTopLogicalLeft) {
  SetBodyInnerHTML(R"HTML("
    <style>
    .c { contain: layout; }
    .t { width: 1px; height:1px; margin: 3px 5px 7px 11px; }
    .htb { writing-mode: horizontal-tb; }
    .vlr { writing-mode: vertical-lr; }
    .vrl { writing-mode: vertical-rl; }
    </style>
    <div class="c htb"><div id="htb-htb" class="t htb"></div></div>
    <div class="c htb"><div id="htb-vrl" class="t vrl"></div></div>
    <div class="c htb"><div id="htb-vlr" class="t vlr"></div></div>
    <div class="c vlr"><div id="vlr-htb" class="t htb"></div></div>
    <div class="c vlr"><div id="vlr-vrl" class="t vrl"></div></div>
    <div class="c vlr"><div id="vlr-vlr" class="t vlr"></div></div>
    <div class="c vrl"><div id="vrl-htb" class="t htb"></div></div>
    <div class="c vrl"><div id="vrl-vrl" class="t vrl"></div></div>
    <div class="c vrl"><div id="vrl-vlr" class="t vlr"></div></div>
  )HTML");
  constexpr LayoutUnit kTopMargin(3);
  constexpr LayoutUnit kRightMargin(5);
  constexpr LayoutUnit kLeftMargin(11);

  // Target DIVs are placed at (3, 11) from its container top-left.
  LayoutBox* target = GetLayoutBoxByElementId("htb-htb");
  EXPECT_EQ(kTopMargin, target->LogicalTop());
  EXPECT_EQ(kLeftMargin, target->LogicalLeft());
  target = GetLayoutBoxByElementId("htb-vrl");
  EXPECT_EQ(kLeftMargin, target->LogicalTop());
  EXPECT_EQ(kTopMargin, target->LogicalLeft());
  target = GetLayoutBoxByElementId("htb-vlr");
  EXPECT_EQ(kLeftMargin, target->LogicalTop());
  EXPECT_EQ(kTopMargin, target->LogicalLeft());

  // Container's writing-mode doesn't matter if it is vertical-lr.
  target = GetLayoutBoxByElementId("vlr-htb");
  EXPECT_EQ(kTopMargin, target->LogicalTop());
  EXPECT_EQ(kLeftMargin, target->LogicalLeft());
  target = GetLayoutBoxByElementId("vlr-vrl");
  EXPECT_EQ(kLeftMargin, target->LogicalTop());
  EXPECT_EQ(kTopMargin, target->LogicalLeft());
  target = GetLayoutBoxByElementId("vlr-vlr");
  EXPECT_EQ(kLeftMargin, target->LogicalTop());
  EXPECT_EQ(kTopMargin, target->LogicalLeft());

  // In a vertical-rl container, LogicalTop() and LogicalLeft() return
  // flipped-block offsets.
  target = GetLayoutBoxByElementId("vrl-htb");
  EXPECT_EQ(kTopMargin, target->LogicalTop());
  EXPECT_EQ(kRightMargin, target->LogicalLeft());
  target = GetLayoutBoxByElementId("vrl-vrl");
  EXPECT_EQ(kRightMargin, target->LogicalTop());
  EXPECT_EQ(kTopMargin, target->LogicalLeft());
  target = GetLayoutBoxByElementId("vrl-vlr");
  EXPECT_EQ(kRightMargin, target->LogicalTop());
  EXPECT_EQ(kTopMargin, target->LogicalLeft());
}

class LayoutBoxBackgroundPaintLocationTest : public RenderingTest,
                                             public PaintTestConfigurations {
 protected:
  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }

  BackgroundPaintLocation ScrollerBackgroundPaintLocation() {
    return GetLayoutBoxByElementId("scroller")->GetBackgroundPaintLocation();
  }

  const String kCommonStyle = R"HTML(
    <style>
      #scroller {
        overflow: scroll;
        width: 300px;
        height: 300px;
        will-change: transform;
      }
      .spacer { height: 1000px; }
    </style>
  )HTML";
};

INSTANTIATE_PAINT_TEST_SUITE_P(LayoutBoxBackgroundPaintLocationTest);

TEST_P(LayoutBoxBackgroundPaintLocationTest, ContentBoxClipZeroPadding) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller' style='background: white content-box; padding: 10px;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller cannot paint background into scrolling contents layer because it
  // has a content-box clip without local attachment.
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest,
       AttachmentLocalContentBoxClipNonZeroPadding) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
         style='background: white local content-box; padding: 10px;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller can paint background into scrolling contents layer because it
  // has local attachment.
  EXPECT_EQ(kBackgroundPaintInContentsSpace, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, NonLocalImage) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
        style='background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg),
                           white local;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller cannot paint background into scrolling contents layer because
  // the background image is not locally attached.
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, LocalImageAndColor) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
        style='background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg)
                           local, white local;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller can paint background into scrolling contents layer because both
  // the image and color are locally attached.
  EXPECT_EQ(kBackgroundPaintInContentsSpace, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest,
       LocalImageAndNonLocalClipPaddingColor) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
        style='background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg)
                           local, white padding-box;
               padding: 10px;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller can paint background into scrolling contents layer because the
  // image is locally attached and even though the color is not, it is filled to
  // the padding box so it will be drawn the same as a locally attached
  // background.
  EXPECT_EQ(kBackgroundPaintInContentsSpace, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest,
       LocalImageAndNonLocalClipContentColorNonZeroPadding) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
        style='background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg)
                           local, white content-box; padding: 10px;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller cannot paint background into scrolling contents layer because
  // the color is filled to the content box and we have padding so it is not
  // equivalent to a locally attached background.
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, BorderBoxClipColorNoBorder) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller' class='scroller' style='background: white border-box;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller can paint background into scrolling contents layer because its
  // border-box is equivalent to its padding box since it has no border.
  EXPECT_EQ(kBackgroundPaintInContentsSpace, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, BorderBoxClipColorSolidBorder) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
         style='background: white border-box; border: 10px solid black;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller can paint background into scrolling contents layer because its
  // border is opaque so it completely covers the background outside of the
  // padding-box.
  EXPECT_EQ(kBackgroundPaintInContentsSpace, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest,
       BorderBoxClipColorTranslucentBorder) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
         style='background: white border-box;
                border: 10px solid rgba(0, 0, 0, 0.5);'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller paints the background into both layers because its border is
  // partially transparent so the background must be drawn to the
  // border-box edges.
  EXPECT_EQ(kBackgroundPaintInBothSpaces, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, BorderBoxClipColorDashedBorder) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
         style='background: white; border: 5px dashed black;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller can be painted in both layers because the background is a
  // solid color, it must be because the dashed border reveals the background
  // underneath it.
  EXPECT_EQ(kBackgroundPaintInBothSpaces, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, ContentClipColorZeroPadding) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller' style='background: white content-box;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller can paint background into scrolling contents layer because its
  // content-box is equivalent to its padding box since it has no padding.
  EXPECT_EQ(kBackgroundPaintInContentsSpace, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, ContentClipColorNonZeroPadding) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller' style='background: white content-box; padding: 10px;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller cannot paint background into scrolling contents layer because
  // it has padding so its content-box is not equivalent to its padding-box.
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, CustomScrollbar) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <style>
      #scroller::-webkit-scrollbar {
        width: 13px;
        height: 13px;
      }
    </style>
    <div id='scroller' style='background: white border-box;'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller paints the background into both layers because it has a custom
  // scrollbar which the background may need to draw under.
  EXPECT_EQ(kBackgroundPaintInBothSpaces, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest,
       TranslucentColorAndTranslucentBorder) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
         style='background: rgba(255, 255, 255, 0.5) border-box;
                border: 5px solid rgba(0, 0, 0, 0.5);'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // #scroller17 can only be painted once as it is translucent, and it must
  // be painted in the border box space to be under the translucent border.
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest,
       LocalImageTranslucentColorAndTransparentBorder) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
        style='background: local linear-gradient(blue, red),
                           rgba(0, 128, 0, 0.5);
               border: 10px solid transparent'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // https://crbug.com/1241801: The background with translucent background color
  // should not be painted twice.
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, InsetBoxShadow) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
         style='background: white; box-shadow: 10px 10px black inset'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // Background with inset box shadow can only be painted in the main graphics
  // layer because the shadow can't scroll.
  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, OutsetBoxShadow) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller' style='background: white; box-shadow: 10px 10px black'>
      <div class='spacer'></div>
    </div>
  )HTML");

  // Outset box shadow doesn't affect background paint location.
  EXPECT_EQ(kBackgroundPaintInContentsSpace, ScrollerBackgroundPaintLocation());
}

TEST_P(LayoutBoxBackgroundPaintLocationTest, BorderImage) {
  SetBodyInnerHTML(kCommonStyle + R"HTML(
    <div id='scroller'
         style='background: white; border: 2px solid; border-image-width: 5px;
                border-image-source: linear-gradient(blue, red)'>
      <div class='spacer'></div>
    </div>
  )HTML");

  EXPECT_EQ(kBackgroundPaintInBorderBoxSpace,
            ScrollerBackgroundPaintLocation());
}

}  // namespace blink

"""


```