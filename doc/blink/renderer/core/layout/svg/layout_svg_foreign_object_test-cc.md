Response:
Let's break down the thought process for analyzing this test file.

1. **Understand the Core Purpose:** The filename `layout_svg_foreign_object_test.cc` immediately tells us this file is about testing the layout behavior of SVG `<foreignObject>` elements in the Blink rendering engine. The "test" suffix confirms it's a unit test file.

2. **Identify Key Concepts:**  The code itself uses terms like `LayoutSVGForeignObjectTest`, `RenderingTest`, `SetBodyInnerHTML`, `GetElementById`, `GetLayoutObjectByElementId`, `HitTest`, `RectBasedHitTest`, `MapToVisualRectInAncestorSpace`, `LocalToAncestorPoint`, `AncestorToLocalPoint`, `ObjectBoundingBox`, `LocalSVGTransform`, `LocalToSVGParentTransform`. These terms point to the core functionality being tested: how the layout engine positions, sizes, and handles hit-testing for content within a `<foreignObject>`.

3. **Analyze Individual Tests:**  Go through each `TEST_F` block. For each test:

    * **Read the Test Name:** The name often gives a high-level overview of what's being tested (e.g., `DivInForeignObject`, `IframeInForeignObject`, `HitTestZoomedForeignObject`).
    * **Examine `SetBodyInnerHTML`:** This is crucial. It sets up the HTML structure being tested. Look at the SVG, the `<foreignObject>`, and the content inside it (divs, iframes). Pay attention to attributes like `x`, `y`, `width`, `height`, `style`, and any transforms.
    * **Identify Key Elements:** The code usually retrieves references to specific elements using `GetElementById` and `GetLayoutObjectByElementId`. These are the elements whose layout behavior is being checked.
    * **Understand the Assertions (`EXPECT_EQ`, `EXPECT_TRUE`):**  These are the core of the tests. They check specific properties or behaviors. For example:
        * `EXPECT_EQ(gfx::RectF(...), foreign_object.ObjectBoundingBox())`: Checks the calculated bounding box.
        * `EXPECT_EQ(..., foreign_object.LocalSVGTransform())`: Checks the local SVG transform.
        * `EXPECT_EQ(..., HitTest(x, y))`: Checks which element is hit at a specific coordinate.
        * `EXPECT_TRUE(div.MapToVisualRectInAncestorSpace(...))`: Checks the transformation of a rectangle between coordinate spaces.
    * **Look for Specific Functionality Tests:**  Tests with names like `MapToVisualRectInAncestorSpace`, `LocalToAncestorPoint`, `AncestorToLocalPoint`, and various `HitTest` scenarios indicate focused testing of coordinate transformations and hit-testing logic.
    * **Note Edge Cases:** Tests involving zooming (`HitTestZoomedForeignObject`), viewbox (`HitTestViewBoxForeignObject`), clipping (`HitTestUnderClipPath`), transformations (`HitTestUnderTransformedForeignObjectDescendant`), and scrolling (`HitTestUnderScrollingAncestor`) highlight areas where the layout logic might be complex.
    * **Identify Regression Tests:** Tests with names like `crbug.com/1335655` or `crbug.com/1372886` indicate tests added to prevent regressions for specific previously reported bugs.

4. **Relate to Web Technologies:** After understanding the individual tests, connect them to broader web concepts:

    * **HTML:** The `<foreignObject>` element itself is an HTML construct within SVG. The content *inside* the `<foreignObject>` is treated as standard HTML (divs, iframes, etc.).
    * **CSS:**  CSS styles are applied to both the SVG elements and the HTML content within the `<foreignObject>`. This includes properties like `width`, `height`, `margin`, `transform`, `overflow`, `zoom`, and `clip-path`.
    * **JavaScript:** While this specific test file doesn't directly execute JavaScript, the layout calculations being tested are fundamental to how JavaScript interacts with the DOM and CSSOM to manipulate element positions and sizes. For example, JavaScript-based animations or user interactions rely on accurate layout information.

5. **Consider Assumptions and Inputs/Outputs:** For tests involving coordinate transformations, think about the expected input (coordinates in one space) and the asserted output (coordinates in another space). For hit-testing, consider the input coordinates and the expected output (the element hit).

6. **Identify Potential User Errors:**  Think about common mistakes developers might make when using `<foreignObject>`:
    * Not setting `width` and `height` on the `<foreignObject>`.
    * Incorrectly applying transforms.
    * Not understanding how coordinate systems work between SVG and HTML content.
    * Issues with stacking contexts and z-index within the `<foreignObject>`.

7. **Structure the Explanation:** Organize the findings into logical sections covering functionality, relationships to web technologies, logic/assumptions, and common errors. Use clear language and provide concrete examples.

8. **Review and Refine:**  Read through the explanation to ensure clarity, accuracy, and completeness. Are there any ambiguities?  Could the examples be more illustrative?

**(Self-Correction Example During the Process):**  Initially, I might focus too much on the specific pixel values in the hit-testing assertions. However, it's more important to understand *why* those values are expected. The key is the relative positioning and sizing of the elements and how hit-testing traverses the DOM tree. I would then adjust my explanation to emphasize these underlying principles. Similarly, for coordinate transformations, the focus should be on understanding the transformation matrices and how they are applied, rather than just memorizing the specific output values.
这个C++源代码文件 `layout_svg_foreign_object_test.cc` 是 Chromium Blink 渲染引擎中的一个单元测试文件。它的主要功能是 **测试 `<foreignObject>` SVG 元素在布局（Layout）阶段的行为和特性**。  `<foreignObject>` 允许在 SVG 图形中嵌入来自不同 XML 命名空间的元素，最常见的是嵌入 HTML 内容。

以下是对其功能的详细列举，并结合 JavaScript、HTML 和 CSS 的关系进行说明：

**核心功能：测试 `<foreignObject>` 的布局行为**

1. **基本渲染测试:** 验证 `<foreignObject>` 及其内部的 HTML 内容能否正确渲染和布局。
   * **例子 (对应 `DivInForeignObject` 测试):**  测试在 `<foreignObject>` 内部放置一个 `<div>` 元素，并检查其位置、大小和变换是否正确计算。
      * **HTML:**  `<foreignObject x='100' y='100' width='300' height='200'><div style='margin: 50px; width: 200px; height: 100px'></div></foreignObject>`
      * **测试点:** 验证 `foreign_object.ObjectBoundingBox()` 是否正确反映了 `<foreignObject>` 的位置和尺寸，以及内部 `div` 元素的布局位置（通过 `MapToVisualRectInAncestorSpace`, `LocalToAncestorPoint`, `AncestorToLocalPoint` 等方法）。

2. **坐标空间转换:** 测试在 `<foreignObject>` 内部的 HTML 内容与外部 SVG 元素的坐标空间之间的转换是否正确。
   * **例子 (对应 `DivInForeignObject` 测试):**
      * **假设输入:**  内部 `div` 元素局部坐标系中的一个点 `PhysicalOffset(0, 0)`。
      * **预期输出:**  通过 `div.LocalToAncestorPoint(&GetLayoutView(), ...)` 转换后，该点在整个视图坐标系中的位置 `PhysicalOffset(150, 150)`。这考虑了 `<foreignObject>` 的 `x` 和 `y` 属性以及 `div` 的 `margin`。
      * **反向转换:**  通过 `div.AncestorToLocalPoint(&GetLayoutView(), PhysicalOffset(), ...)` 测试反向转换。

3. **命中测试 (Hit Testing):** 测试鼠标点击事件发生在 `<foreignObject>` 内部或外部时，能否正确识别命中的元素。
   * **例子 (对应 `DivInForeignObject` 测试):**
      * **假设输入:**  鼠标点击屏幕上的不同坐标点，例如 `(1, 1)`, `(149, 149)`, `(150, 150)` 等。
      * **预期输出:**  `HitTest(x, y)` 方法返回对应的 DOM 节点，例如点击 `<foreignObject>` 外部返回 `<svg>` 元素，点击 `<foreignObject>` 内部 `div` 元素返回该 `div` 的节点。
   * **矩形命中测试:**  测试一个矩形区域与 `<foreignObject>` 及其内部元素是否相交。

4. **处理 `<iframe>`:** 测试在 `<foreignObject>` 内部嵌入 `<iframe>` 元素的情况，包括跨文档的命中测试和坐标转换。
   * **例子 (对应 `IframeInForeignObject` 测试):**  验证嵌入的 `<iframe>` 的内容是否正确布局，并且点击事件可以正确地穿透到 `<iframe>` 内部的元素。

5. **缩放 (Zoom) 的影响:** 测试浏览器缩放或元素自身缩放对 `<foreignObject>` 及其内部元素布局和命中测试的影响。
   * **例子 (对应 `HitTestZoomedForeignObject` 测试):**  测试当父元素或自身应用 `zoom` 属性时，坐标转换和命中测试是否仍然准确。
      * **假设输入:**  应用 `zoom: 150%` 后，点击内部 `div` 的不同角落。
      * **预期输出:**  `HitTest()` 方法能够正确返回 `div` 元素，即使坐标因为缩放而发生了变化。

6. **`viewBox` 属性的影响:** 测试 SVG 的 `viewBox` 属性对 `<foreignObject>` 内部元素坐标的影响。
   * **例子 (对应 `HitTestViewBoxForeignObject` 测试):**  当 SVG 元素设置了 `viewBox` 属性时，其内部的坐标系统会被缩放和平移，测试确保 `<foreignObject>` 内部的命中测试能够正确映射到屏幕坐标。

7. **剪切路径 (Clip Path) 的影响:** 测试当 `<foreignObject>` 被剪切路径裁剪时，命中测试的行为。
   * **例子 (对应 `HitTestUnderClipPath` 测试):**  当点击被剪切路径裁剪掉的 `<foreignObject>` 区域时，应该命中下方的 SVG 元素。

8. **定位和变换 (Transform) 的影响:** 测试当 `<foreignObject>` 或其内部元素应用了定位 (`position: relative`) 或变换 (`transform`) 时，命中测试的准确性。
   * **例子 (对应 `HitTestUnderTransformedForeignObjectDescendant` 测试):**  测试当 `<foreignObject>` 应用了 `transform: translate(30)` 后，点击其内部定位元素的行为。

9. **滚动 (Scrolling) 的影响:** 测试当 `<foreignObject>` 位于可滚动的祖先元素内时，命中测试的行为。
   * **例子 (对应 `HitTestUnderScrollingAncestor` 测试):**  即使父元素发生了滚动，点击 `<foreignObject>` 内部元素仍然应该能够正确命中。

10. **边界框 (Bounding Box) 的计算:** 测试 `<foreignObject>` 及其父元素的边界框计算是否正确，特别是在应用了缩放的情况下。
    * **例子 (对应 `BBoxPropagationZoomed` 测试):** 验证在设置了页面缩放的情况下，`ObjectBoundingBox()` 和 `DecoratedBoundingBox()` 方法返回的矩形是否符合预期。

11. **其他边缘情况和 Bug 修复:**  测试一些特定的边缘情况或之前发现的 bug，例如 `SetNeedsCollectInlines` 和 `SubtreeLayoutCrash` 测试，这些测试通常是为了防止回归问题。

12. **`content-visibility: auto` 的影响:** 测试 `content-visibility: auto` CSS 属性对 `<foreignObject>` 布局的影响。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**  `<foreignObject>` 本身就是一个 HTML 元素，尽管它存在于 SVG 命名空间中。测试中通过 `SetBodyInnerHTML` 设置包含 `<foreignObject>` 的 HTML 结构。
* **CSS:**  测试文件会利用 CSS 来设置元素的样式，例如大小、边距、定位、变换、缩放和剪切路径。这些样式会直接影响 `<foreignObject>` 及其内部 HTML 内容的布局。测试会验证布局引擎是否正确地应用了这些 CSS 样式。
   * **例子:**  `style='width: 500px; height: 400px'` 设置了 SVG 元素的尺寸。 `style='margin: 50px; width: 200px; height: 100px'` 设置了内部 `div` 元素的样式。
* **JavaScript:**  虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的布局逻辑，但这些布局逻辑最终会影响到 JavaScript 与 DOM 的交互。例如，当 JavaScript 代码获取元素的位置和尺寸时（例如使用 `getBoundingClientRect()`），Blink 引擎的布局计算结果会被使用。此外，JavaScript 触发的重排（reflow）和重绘（repaint）也会依赖于正确的布局信息。

**逻辑推理的假设输入与输出：**

上面在描述每个测试的功能时，已经列举了一些假设输入和预期输出的例子，主要围绕坐标转换和命中测试展开。

**用户或编程常见的使用错误举例：**

1. **未设置 `<foreignObject>` 的 `width` 和 `height`：** 如果没有明确设置 `<foreignObject>` 的宽度和高度，其内部的 HTML 内容可能无法正确布局或显示。浏览器可能无法确定 `<foreignObject>` 应该占据的空间大小。

   ```html
   <svg>
     <foreignObject>  <!-- 缺少 width 和 height -->
       <div>This might not render correctly.</div>
     </foreignObject>
   </svg>
   ```

2. **不理解 `<foreignObject>` 的坐标系统：**  `<foreignObject>` 继承了 SVG 的坐标系统，但其内部的 HTML 内容使用自己的坐标系统。在进行坐标转换时，需要考虑 SVG 的变换和 `<foreignObject>` 的位置。开发者可能会错误地假设内部 HTML 元素的坐标与外部 SVG 元素直接对应。

3. **在 `<foreignObject>` 内部使用不支持的 HTML 元素或特性：**  虽然 `<foreignObject>` 允许嵌入 HTML，但某些特定的浏览器功能或复杂的 HTML 结构可能无法完全按预期工作。

4. **忘记设置 XML 命名空间：**  在 `<foreignObject>` 内部使用 HTML 元素时，通常需要在根元素上声明 XHTML 的命名空间。

   ```html
   <svg>
     <foreignObject width="200" height="100">
       <body xmlns="http://www.w3.org/1999/xhtml">  <!-- 缺少命名空间可能导致问题 -->
         <div>Some content</div>
       </body>
     </foreignObject>
   </svg>
   ```

5. **z-index 的问题：**  在 `<foreignObject>` 内部的 HTML 内容的 z-index 与外部 SVG 元素的 z-index 的交互可能不如预期。开发者可能需要使用 stacking context 等概念来正确控制元素的层叠顺序。

总而言之，`layout_svg_foreign_object_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎正确处理 SVG 中嵌入 HTML 内容的布局和交互，这对于构建复杂的、包含 SVG 和 HTML 混合内容的 Web 页面至关重要。

Prompt: 
```
这是目录为blink/renderer/core/layout/svg/layout_svg_foreign_object_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class LayoutSVGForeignObjectTest : public RenderingTest {
 public:
  LayoutSVGForeignObjectTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}
};

TEST_F(LayoutSVGForeignObjectTest, DivInForeignObject) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <svg id='svg' style='width: 500px; height: 400px'>
      <foreignObject id='foreign' x='100' y='100' width='300' height='200'>
        <div id='div' style='margin: 50px; width: 200px; height: 100px'>
        </div>
      </foreignObject>
    </svg>
  )HTML");

  const auto& svg = *GetElementById("svg");
  const auto& foreign = *GetElementById("foreign");
  const auto& foreign_object = *GetLayoutObjectByElementId("foreign");
  const auto& div = *GetLayoutObjectByElementId("div");

  EXPECT_EQ(gfx::RectF(100, 100, 300, 200), foreign_object.ObjectBoundingBox());
  EXPECT_EQ(AffineTransform(), foreign_object.LocalSVGTransform());
  EXPECT_EQ(AffineTransform(), foreign_object.LocalToSVGParentTransform());

  // MapToVisualRectInAncestorSpace
  PhysicalRect div_rect(0, 0, 100, 50);
  EXPECT_TRUE(div.MapToVisualRectInAncestorSpace(&GetLayoutView(), div_rect));
  EXPECT_EQ(PhysicalRect(150, 150, 100, 50), div_rect);

  // LocalToAncestorPoint
  EXPECT_EQ(PhysicalOffset(150, 150),
            div.LocalToAncestorPoint(PhysicalOffset(), &GetLayoutView(),
                                     kTraverseDocumentBoundaries));

  // MapAncestorToLocal
  EXPECT_EQ(PhysicalOffset(-150, -150),
            div.AncestorToLocalPoint(&GetLayoutView(), PhysicalOffset(),
                                     kTraverseDocumentBoundaries));

  // Hit testing
  EXPECT_EQ(svg, HitTest(1, 1));
  EXPECT_EQ(foreign, HitTest(149, 149));
  EXPECT_EQ(div.GetNode(), HitTest(150, 150));
  EXPECT_EQ(div.GetNode(), HitTest(349, 249));
  EXPECT_EQ(foreign, HitTest(350, 250));
  EXPECT_EQ(svg, HitTest(450, 350));

  // Rect based hit testing
  auto results = RectBasedHitTest(PhysicalRect(0, 0, 300, 300));
  int count = 0;
  EXPECT_EQ(3u, results.size());
  for (auto result : results) {
    Node* node = result.Get();
    if (node == svg || node == div.GetNode() || node == foreign) {
      count++;
    }
  }
  EXPECT_EQ(3, count);
}

TEST_F(LayoutSVGForeignObjectTest, IframeInForeignObject) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <svg id='svg' style='width: 500px; height: 450px'>
      <foreignObject id='foreign' x='100' y='100' width='300' height='250'>
        <iframe id=iframe style='border: none; margin: 30px;
             width: 240px; height: 190px'></iframe>
      </foreignObject>
    </svg>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      body { margin: 0 }
      * { background: white; }
    </style>
    <div id='div' style='margin: 70px; width: 100px; height: 50px'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const auto& svg = *GetElementById("svg");
  const auto& foreign = *GetElementById("foreign");
  const auto& foreign_object = *GetLayoutObjectByElementId("foreign");
  const auto& iframe = *GetElementById("iframe");
  const auto& div =
      *ChildDocument().getElementById(AtomicString("div"))->GetLayoutObject();

  EXPECT_EQ(gfx::RectF(100, 100, 300, 250), foreign_object.ObjectBoundingBox());
  EXPECT_EQ(AffineTransform(), foreign_object.LocalSVGTransform());
  EXPECT_EQ(AffineTransform(), foreign_object.LocalToSVGParentTransform());

  // MapToVisualRectInAncestorSpace
  PhysicalRect div_rect(0, 0, 100, 50);
  EXPECT_TRUE(div.MapToVisualRectInAncestorSpace(&GetLayoutView(), div_rect));
  EXPECT_EQ(PhysicalRect(200, 200, 100, 50), div_rect);

  // LocalToAncestorPoint
  EXPECT_EQ(PhysicalOffset(200, 200),
            div.LocalToAncestorPoint(PhysicalOffset(), &GetLayoutView(),
                                     kTraverseDocumentBoundaries));

  // AncestorToLocalPoint
  EXPECT_EQ(PhysicalOffset(-200, -200),
            div.AncestorToLocalPoint(&GetLayoutView(), PhysicalOffset(),
                                     kTraverseDocumentBoundaries));

  // Hit testing
  EXPECT_EQ(svg, HitTest(90, 90));
  EXPECT_EQ(foreign, HitTest(129, 129));
  EXPECT_EQ(ChildDocument().documentElement(), HitTest(130, 130));
  EXPECT_EQ(ChildDocument().documentElement(), HitTest(199, 199));
  EXPECT_EQ(div.GetNode(), HitTest(200, 200));
  EXPECT_EQ(div.GetNode(), HitTest(299, 249));
  EXPECT_EQ(ChildDocument().documentElement(), HitTest(300, 250));
  EXPECT_EQ(ChildDocument().documentElement(), HitTest(369, 319));
  EXPECT_EQ(foreign, HitTest(370, 320));
  EXPECT_EQ(svg, HitTest(450, 400));

  // Rect based hit testing
  auto results = RectBasedHitTest(PhysicalRect(0, 0, 300, 300));
  int count = 0;
  EXPECT_EQ(7u, results.size());
  for (auto result : results) {
    Node* node = result.Get();
    if (node == svg || node == div.GetNode() || node == foreign ||
        node == iframe) {
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(LayoutSVGForeignObjectTest, HitTestZoomedForeignObject) {
  SetBodyInnerHTML(R"HTML(
    <style>* { margin: 0; zoom: 150% }</style>
    <svg id='svg' style='width: 200px; height: 200px'>
      <foreignObject id='foreign' x='10' y='10' width='100' height='150'
                     style='overflow: visible'>
        <div id='div' style='margin: 50px; width: 50px; height: 50px'></div>
      </foreignObject>
    </svg>
  )HTML");

  const auto& svg = *GetElementById("svg");
  const auto& foreign = *GetElementById("foreign");
  const auto& foreign_object = *GetLayoutObjectByElementId("foreign");
  const auto& div = *GetElementById("div");

  EXPECT_EQ(gfx::RectF(10, 10, 100, 150), foreign_object.ObjectBoundingBox());
  EXPECT_EQ(AffineTransform(), foreign_object.LocalSVGTransform());
  AffineTransform zoom;
  zoom.Scale(1 / foreign_object.StyleRef().EffectiveZoom());
  EXPECT_EQ(zoom, foreign_object.LocalToSVGParentTransform());

  // MapToVisualRectInAncestorSpace
  PhysicalRect div_rect(0, 0, 100, 50);
  EXPECT_TRUE(div.GetLayoutObject()->MapToVisualRectInAncestorSpace(
      &GetLayoutView(), div_rect));
  // Origin at x=y=(50 * 1.5 + 10) * 1.5 * 1.5 * 1.5 = 286.875
  // Dimensions will be subjected to scaling with 1/1.5 because the
  // accumulated zoom on the <fO> is one more than that of its parent <svg>.
  EXPECT_EQ(PhysicalRect(286, 286, 68, 35), div_rect);

  PhysicalOffset div_offset(LayoutUnit(286.875), LayoutUnit(286.875));
  // LocalToAncestorPoint
  EXPECT_EQ(div_offset, div.GetLayoutObject()->LocalToAncestorPoint(
                            PhysicalOffset(), &GetLayoutView(),
                            kTraverseDocumentBoundaries));

  // AncestorToLocalPoint
  EXPECT_EQ(PhysicalOffset(),
            div.GetLayoutObject()->AncestorToLocalPoint(
                &GetLayoutView(), div_offset, kTraverseDocumentBoundaries));

  EXPECT_EQ(svg, HitTest(20, 20));
  EXPECT_EQ(foreign, HitTest(280, 280));
  // Check all corners of the <div>.
  EXPECT_EQ(div, HitTest(290, 290));
  EXPECT_EQ(div, HitTest(290, 286 + 250));
  EXPECT_EQ(div, HitTest(286 + 250, 290));
  EXPECT_EQ(div, HitTest(286 + 250, 286 + 250));
  // Check (just) outside the <div>.
  EXPECT_EQ(svg, HitTest(286 + 256, 290));
  EXPECT_EQ(svg, HitTest(290, 286 + 256));

  // Rect based hit testing
  auto results = RectBasedHitTest(PhysicalRect(0, 0, 300, 300));
  int count = 0;
  EXPECT_EQ(3u, results.size());
  for (auto result : results) {
    Node* node = result.Get();
    if (node == svg || node == &div || node == foreign) {
      count++;
    }
  }
  EXPECT_EQ(3, count);
}

TEST_F(LayoutSVGForeignObjectTest, HitTestViewBoxForeignObject) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg' style='width: 200px; height: 200px' viewBox='0 0 100 100'>
      <foreignObject id='foreign' x='10' y='10' width='100' height='150'>
        <div id='div' style='margin: 50px; width: 50px; height: 50px'>
        </div>
      </foreignObject>
    </svg>
  )HTML");

  const auto& svg = *GetElementById("svg");
  const auto& foreign = *GetElementById("foreign");
  const auto& div = *GetElementById("div");

  // LocalToAncestorPoint
  EXPECT_EQ(
      PhysicalOffset(128, 128),
      div.GetLayoutObject()->LocalToAncestorPoint(
          PhysicalOffset(), &GetLayoutView(), kTraverseDocumentBoundaries));

  // AncestorToLocalPoint
  EXPECT_EQ(PhysicalOffset(), div.GetLayoutObject()->AncestorToLocalPoint(
                                  &GetLayoutView(), PhysicalOffset(128, 128),
                                  kTraverseDocumentBoundaries));

  EXPECT_EQ(svg, HitTest(20, 20));
  EXPECT_EQ(foreign, HitTest(120, 110));
  EXPECT_EQ(div, HitTest(160, 160));
}

TEST_F(LayoutSVGForeignObjectTest, HitTestUnderClipPath) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0
      }
      #target {
         width: 500px;
         height: 500px;
         background-color: blue;
      }
      #target:hover {
        background-color: green;
      }
    </style>
    <svg id="svg" style="width: 500px; height: 500px">
      <clipPath id="c">
        <circle cx="250" cy="250" r="200"/>
      </clipPath>
      <g clip-path="url(#c)">
        <foreignObject id="foreignObject" width="100%" height="100%">
        </foreignObject>
      </g>
    </svg>
  )HTML");

  const auto& svg = *GetElementById("svg");
  const auto& foreignObject = *GetElementById("foreignObject");

  // The fist and the third return |svg| because the circle clip-path
  // clips out the foreignObject.
  EXPECT_EQ(svg, GetDocument().ElementFromPoint(20, 20));
  EXPECT_EQ(foreignObject, GetDocument().ElementFromPoint(250, 250));
  EXPECT_EQ(svg, GetDocument().ElementFromPoint(400, 400));
}

TEST_F(LayoutSVGForeignObjectTest,
       HitTestUnderClippedPositionedForeignObjectDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0
      }
    </style>
    <svg id="svg" style="width: 600px; height: 600px">
      <foreignObject id="foreignObject" x="200" y="200" width="100"
          height="100">
        <div id="target" style="overflow: hidden; position: relative;
            width: 100px; height: 50px; left: 5px"></div>
      </foreignObject>
    </svg>
  )HTML");

  const auto& svg = *GetElementById("svg");
  const auto& target = *GetElementById("target");
  const auto& foreignObject = *GetElementById("foreignObject");

  EXPECT_EQ(svg, GetDocument().ElementFromPoint(1, 1));
  EXPECT_EQ(foreignObject, GetDocument().ElementFromPoint(201, 201));
  EXPECT_EQ(target, GetDocument().ElementFromPoint(206, 206));
  EXPECT_EQ(foreignObject, GetDocument().ElementFromPoint(205, 255));

  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location((PhysicalOffset(206, 206)));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(206, 206), result.PointInInnerNodeFrame());
}

TEST_F(LayoutSVGForeignObjectTest,
       HitTestUnderTransformedForeignObjectDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0
      }
    </style>
    <svg id="svg" style="width: 600px; height: 600px">
      <foreignObject id="foreignObject" x="200" y="200" width="100"
          height="100" transform="translate(30)">
        <div id="target" style="overflow: hidden; position: relative;
            width: 100px; height: 50px; left: 5px"></div>
      </foreignObject>
    </svg>
  )HTML");

  const auto& svg = *GetElementById("svg");
  const auto& target = *GetElementById("target");
  const auto& foreign_object = *GetElementById("foreignObject");

  EXPECT_EQ(svg, GetDocument().ElementFromPoint(1, 1));
  EXPECT_EQ(foreign_object, GetDocument().ElementFromPoint(231, 201));
  EXPECT_EQ(target, GetDocument().ElementFromPoint(236, 206));
  EXPECT_EQ(foreign_object, GetDocument().ElementFromPoint(235, 255));

  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location((PhysicalOffset(236, 206)));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(236, 206), result.PointInInnerNodeFrame());
}

TEST_F(LayoutSVGForeignObjectTest, HitTestUnderScrollingAncestor) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0
      }
    </style>
    <div id=scroller style="width: 500px; height: 500px; overflow: auto">
      <svg width="3000" height="3000">
        <foreignObject width="3000" height="3000">
          <div id="target" style="width: 3000px; height: 3000px; background: red">
          </div>
        </foreignObject>
      </svg>
    </div>
  )HTML");

  auto& scroller = *GetElementById("scroller");
  const auto& target = *GetElementById("target");

  EXPECT_EQ(target, GetDocument().ElementFromPoint(450, 450));

  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location((PhysicalOffset(450, 450)));
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(450, 450), result.PointInInnerNodeFrame());

  scroller.setScrollTop(3000);

  EXPECT_EQ(target, GetDocument().ElementFromPoint(450, 450));

  GetDocument().GetLayoutView()->HitTest(location, result);
  EXPECT_EQ(target, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(450, 450), result.PointInInnerNodeFrame());
}

TEST_F(LayoutSVGForeignObjectTest, BBoxPropagationZoomed) {
  GetFrame().SetLayoutZoomFactor(2);
  SetBodyInnerHTML(R"HTML(
    <svg>
      <g>
        <foreignObject x="6" y="5" width="100" height="50" id="target"/>
      </g>
    </svg>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  const auto& target = *GetLayoutObjectByElementId("target");
  ASSERT_EQ(target.StyleRef().EffectiveZoom(), 2);

  EXPECT_EQ(target.ObjectBoundingBox(), gfx::RectF(6, 5, 100, 50));
  EXPECT_EQ(target.DecoratedBoundingBox(), gfx::RectF(12, 10, 200, 100));
  const auto& parent_g = *target.Parent();
  EXPECT_EQ(parent_g.ObjectBoundingBox(), gfx::RectF(6, 5, 100, 50));
  EXPECT_EQ(parent_g.DecoratedBoundingBox(), gfx::RectF(6, 5, 100, 50));
}

// crbug.com/1335655
TEST_F(LayoutSVGForeignObjectTest, SetNeedsCollectInlines) {
  SetBodyInnerHTML(R"HTML(
    <svg><foreignObject id="target">abc</foreignObject></svg>)HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* target = GetElementById("target");
  target->setAttribute(svg_names::kUnicodeBidiAttr,
                       AtomicString("bidi-override"));
  GetDocument().body()->innerText();
  // Pass if no crash.
}

// crbug.com/1372886
TEST_F(LayoutSVGForeignObjectTest, SubtreeLayoutCrash) {
  SetBodyInnerHTML(R"HTML(
<svg style="position:absolute;">
  <svg></svg>
  <foreignObject>
    <div id="in-foreign"></div>
  </foreignObject>
</svg>
<div></div>
<span></span>
<div id="sibling-div"></div>
<svg><pattern id="pat"></pattern>
</svg>)HTML");
  UpdateAllLifecyclePhasesForTest();
  GetElementById("in-foreign")
      ->setAttribute(svg_names::kStyleAttr,
                     AtomicString("display: inline-block"));
  UpdateAllLifecyclePhasesForTest();
  GetElementById("pat")->setAttribute(svg_names::kViewBoxAttr,
                                      AtomicString("972 815 1088 675"));
  UpdateAllLifecyclePhasesForTest();
  GetElementById("sibling-div")
      ->setAttribute(svg_names::kStyleAttr, AtomicString("display: none"));
  UpdateAllLifecyclePhasesForTest();
  // Pass if no crashes.
}

TEST_F(LayoutSVGForeignObjectTest, ZoomChangesInvalidatePaintProperties) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0; } </style>
    <svg id="svg" xmlns="http://www.w3.org/2000/svg" width="100px"
        height="100px" viewBox="-1 -1 100 100">
      <foreignObject id="foreign" xmlns="http://www.w3.org/2000/svg"
          width="100px" height="100px" style="overflow: visible;" />
    </svg>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  // Initially, the svg replaced contents transform should have no scale, and
  // there should be no foreign object transform paint property.
  LayoutObject* svg = GetLayoutObjectByElementId("svg");
  const TransformPaintPropertyNode* svg_replaced_contents =
      svg->FirstFragment().PaintProperties()->ReplacedContentTransform();
  EXPECT_EQ(gfx::Vector2dF(1, 1), svg_replaced_contents->Get2dTranslation());
  LayoutObject* foreign = GetLayoutObjectByElementId("foreign");
  EXPECT_FALSE(foreign->FirstFragment().PaintProperties());

  // Update zoom and ensure the foreign object is marked as needing a paint
  // property update prior to updating paint properties.
  GetDocument().documentElement()->setAttribute(svg_names::kStyleAttr,
                                                AtomicString("zoom: 2"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(foreign->NeedsPaintPropertyUpdate());

  UpdateAllLifecyclePhasesForTest();

  // The svg replaced contents transform should contain the zoom, but the
  // foreign object's transform should unapply it.
  EXPECT_EQ(gfx::Vector2dF(2, 2), svg_replaced_contents->Matrix().To2dScale());
  const TransformPaintPropertyNode* foreign_transform =
      foreign->FirstFragment().PaintProperties()->Transform();
  EXPECT_EQ(gfx::Vector2dF(0.5, 0.5), foreign_transform->Matrix().To2dScale());
}

TEST_F(LayoutSVGForeignObjectTest, DisplayLocked) {
  GetDocument().body()->setInnerHTML(R"HTML(<style>
foreignObject {
  content-visibility: auto;
}
</style>
<div style="height:300vh"></div>
<svg>
<foreignObject id="foreign">
<body xmlns="http://www.w3.org/1999/xhtml"></body>
</foreignObject>
</svg>)HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  GetLayoutBoxByElementId("foreign")->SetChildNeedsLayout();
  UpdateAllLifecyclePhasesForTest();
  // Pass if no DCHECK failures.
}

TEST_F(LayoutSVGForeignObjectTest, LocalToAncestorPoint) {
  SetBodyInnerHTML(R"HTML(
<style>body { margin:0; }</style>
<div style="height:3px"></div>
<svg width="200" height="100">
<foreignObject id="foreign" width="200" height="100">
<body xmlns="http://www.w3.org/1999/xhtml">
<div style="height:17px"></div>
<div id="target">b</div>
</body>
</foreignObject>
</svg>)HTML");
  LayoutObject* target = GetLayoutObjectByElementId("target");
  LayoutBox* foreign = GetLayoutBoxByElementId("foreign");
  EXPECT_NE(target->LocalToAbsolutePoint(PhysicalOffset()),
            target->LocalToAncestorPoint(PhysicalOffset(), foreign));
}

}  // namespace blink

"""

```