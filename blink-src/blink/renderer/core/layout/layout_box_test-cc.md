Response:
The user wants a summary of the provided C++ code snippet, which is a test file for the `LayoutBox` class in the Chromium Blink rendering engine. I need to identify the functionalities being tested and explain their relevance to web development concepts (HTML, CSS, JavaScript).

Here's a breakdown of the code and its functionalities:

1. **Includes:** The file includes headers for testing (`gtest`), DOM manipulation (`DOMTokenList`, `LocalDOMWindow`), HTML elements (`HTMLBodyElement`, `HTMLElement`), layout objects (`LayoutBox`, `LayoutImage`), and painting (`PaintLayer`, `PaintLayerScrollableArea`). This suggests the file tests how layout boxes interact with the DOM and painting.

2. **`LayoutBoxTest` Class:** This class inherits from `RenderingTest`, indicating it's a unit test environment specifically for rendering-related components.

3. **`ForegroundIsKnownToBeOpaqueInRect` Helper:** This private method is used within the tests to check if the foreground of a layout box is opaque within a given rectangle.

4. **`BackgroundIsKnownToBeObscured` Test:** This test checks if a layout box's background is completely hidden by its children. It uses CSS properties like `background`, `position`, `overflow`, and `border-radius`.

5. **`BackgroundNotObscuredWithCssClippedChild` and `BackgroundNotObscuredWithCssClippedGrandChild` Tests:** These tests examine scenarios where a child or grandchild of a layout box is clipped using the CSS `clip` property. They verify that the parent's background is not considered obscured even if a child is clipped.

6. **`ForegroundIsKnownToBeOpaqueInRect` Test:** This test explores different scenarios to determine if the foreground of a layout box is opaque within a specific rectangle. It considers factors like child elements with opaque and translucent backgrounds, and the effect of positioned elements.

7. **`ForegroundIsKnownToBeOpaqueInRectVerticalRL` Test:** This is similar to the previous test but focuses on layout boxes with `writing-mode: vertical-rl`.

8. **`BackgroundRect` Test:** This comprehensive test evaluates how different CSS `background` properties (`background-image`, `background-color`, `background-clip`, `background-blend-mode`, `background-attachment`) affect the reported background rectangles (opaque area and painted extent).

9. **`LocationContainer` Test:** This test verifies the concept of a "location container" for different types of layout boxes (div, inline elements, images, table elements). The location container determines the coordinate system for the box's position.

10. **`TopLeftLocationFlipped` Test:** This test checks the calculation of the top-left position of layout boxes when the parent has `writing-mode: vertical-rl`.

11. **`TableRowCellTopLeftLocationFlipped` Test:** This test specifically examines the positioning of table rows and cells within a `vertical-rl` context, considering quirks mode.

12. **`LocationContainerOfSVG` Test:** This test focuses on how layout boxes within SVG elements (specifically foreignObject) determine their location containers, considering the impact of SVG's writing mode.

13. **`ControlClip` Test:** This test verifies the clipping behavior of form controls (like `<input type='button'>`), checking properties like `HasControlClip`, `HasClipRelatedProperty`, and `ShouldClipOverflowAlongEitherAxis`.

14. **`VisualOverflowRectWithBlockChild` and `VisualOverflowRectWithLegacyChild` Tests:** These tests calculate the visual overflow rectangle of a layout box when it contains a larger block-level child or a legacy element (SVG).

15. **`VisualOverflowRectWithMask`, `VisualOverflowRectWithMaskAndOverflowHidden`, `VisualOverflowRectWithMaskWithOutset`, `VisualOverflowRectWithMaskWithOutsetAndOverflowHidden` Tests:** These tests investigate how CSS masking (`-webkit-mask-image`, `-webkit-mask-box-image-source`, `-webkit-mask-box-image-outset`) interacts with visual overflow and the `overflow` property.

16. **`VisualOverflowRectOverflowHidden` and `VisualOverflowRectOverflowClip` Tests:** These tests focus on the effect of `overflow: hidden` and `overflow: clip` on the visual overflow rectangle.

17. **`VisualOverflowRectWithOverflowClipMargin` Test:** This test examines the impact of the `overflow-clip-margin` property on the visual overflow rectangle.

18. **`ContentsVisualOverflowPropagation` Test:** This test explores how visual overflow propagates up the layout tree, especially with different writing modes.

19. **`HitTestOverflowClipMargin` and `HitTestContainPaint` Tests:** These tests examine how hit-testing (determining which element is clicked) works in scenarios with `overflow-clip-margin` and `contain: paint`.

20. **`OverflowRectsContainPaint` and `OverflowRectsOverflowHidden` Tests:** These tests compare the different overflow rectangles (scrollable, visual, self-visual, content-visual, clip) when using `contain: paint` and `overflow: hidden`.

21. **`SetTextFieldIntrinsicInlineSize` Test:** This test checks the calculation of the intrinsic inline size of text fields (`<input type='number'>`), considering the influence of the inner spin buttons.

22. **`DelayedInvalidation` Test:** This test is related to the optimization of repainting. It checks how changes to animated images trigger or defer invalidation (repainting) of the layout box.
这个 blink 引擎源代码文件 `layout_box_test.cc` 的主要功能是**测试 `LayoutBox` 类的各项功能和属性是否按预期工作**。`LayoutBox` 是 Blink 渲染引擎中表示布局对象的关键类，它对应于 HTML 元素在渲染树中的表示。

以下是该测试文件中涉及到的主要功能，以及它们与 JavaScript、HTML 和 CSS 的关系：

**1. 背景是否被遮挡 (Background Obscuration):**

*   **功能:** 测试在不同 CSS 样式下，一个 `LayoutBox` 的背景是否被其子元素完全遮挡。
*   **与 CSS 的关系:**  测试使用了 CSS 属性如 `background`, `position`, `overflow`, `border-radius`, `clip` 等来创建不同的遮挡场景。
*   **假设输入与输出:**
    *   **假设输入 (HTML/CSS):** 一个 `div` 元素（id='target'）设置了白色背景和 `overflow: hidden`，其内部包含一个高度更高的黑色背景 `div`。
    *   **预期输出:** `target->BackgroundIsKnownToBeObscured()` 返回 `true`，因为黑色背景完全覆盖了白色背景。
    *   **假设输入 (HTML/CSS):** 一个父 `div` (id='parent') 和一个子 `div` (id='child')，子 `div` 使用 `clip` 属性裁剪了一部分区域。
    *   **预期输出:** `child->BackgroundIsKnownToBeObscured()` 和 `parent->BackgroundIsKnownToBeObscured()` 都返回 `false`，即使子元素被裁剪，父元素的背景也不认为是被完全遮挡。
*   **逻辑推理:**  渲染引擎需要准确判断背景是否被遮挡，以优化绘制过程，避免绘制不可见的区域。CSS 的布局和裁剪属性直接影响遮挡关系。

**2. 前景是否不透明 (Foreground Opacity):**

*   **功能:** 测试在给定矩形区域内，`LayoutBox` 的前景是否完全不透明。这考虑了子元素的背景颜色和透明度。
*   **与 CSS 的关系:** 测试使用了 CSS 属性如 `background` 和 `opacity` 来设置子元素的样式，从而影响父元素的前景不透明度。
*   **假设输入与输出:**
    *   **假设输入 (HTML/CSS):** 一个父 `div` (id='target') 包含一个蓝色背景的子 `div` 和一个半透明红色背景的子 `div`。
    *   **预期输出:**
        *   `ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 0, 10, 10))` 返回 `true` (被蓝色不透明子元素覆盖)。
        *   `ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 10, 10, 10))` 返回 `false` (被半透明红色子元素覆盖)。
*   **逻辑推理:** 判断前景是否不透明对于优化绘制也很重要。如果已知前景不透明，可以跳过对被覆盖区域的绘制。

**3. 背景矩形 (Background Rect):**

*   **功能:** 测试在不同的 `background` 属性设置下，`LayoutBox` 的背景绘制区域 (例如，不透明背景区域和实际绘制的区域) 计算是否正确。
*   **与 CSS 的关系:** 测试使用了各种 `background` 相关的 CSS 属性，包括 `background-image`, `background-color`, `background-clip`, `background-blend-mode`, `background-attachment` 等。
*   **假设输入与输出:**
    *   **假设输入 (HTML/CSS):** 一个 `div` 元素 (id='target1') 设置了 `background: url(...) border-box, green content-box;`。
    *   **预期输出:**
        *   `layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect)` 返回内容盒子的矩形 (绿色背景是不透明的)。
        *   `layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent)` 返回边框盒子的矩形 (图片延伸到边框)。
*   **逻辑推理:**  浏览器需要根据不同的 `background` 属性准确计算背景的绘制范围，这直接影响页面的视觉呈现。

**4. 定位容器 (Location Container):**

*   **功能:** 测试确定 `LayoutBox` 的定位容器是否正确。定位容器决定了元素的坐标系。
*   **与 CSS 的关系:** 元素的定位上下文受到 CSS `position` 属性的影响。
*   **假设输入与输出:**
    *   **假设输入 (HTML):** 一个 `div` 包含一个 `img` 元素。
    *   **预期输出:** `img->LocationContainer()` 返回包含它的 `div` 的 `LayoutBox`。
*   **逻辑推理:**  正确的定位容器是元素定位和布局计算的基础。

**5. 翻转后的位置 (Top Left Location Flipped):**

*   **功能:** 测试在 `writing-mode: vertical-rl` 的情况下，`LayoutBox` 的左上角位置计算是否正确。
*   **与 CSS 的关系:** 涉及到 CSS 的 `writing-mode` 属性。
*   **假设输入与输出:**
    *   **假设输入 (HTML/CSS):** 一个设置了 `writing-mode: vertical-rl` 的 `div` 包含两个子 `div`。
    *   **预期输出:** 子 `div` 的 `PhysicalLocation()` 将根据垂直书写模式进行计算。
*   **逻辑推理:** 垂直书写模式会影响元素的布局方向和位置计算。

**6. SVG 元素的定位容器 (Location Container of SVG):**

*   **功能:** 测试 SVG 元素及其内部元素的定位容器。
*   **与 HTML/SVG 的关系:** 涉及到 HTML 中的 SVG 元素和 SVG 特有的元素，例如 `foreignObject`。
*   **假设输入与输出:**
    *   **假设输入 (HTML/SVG):** 一个 SVG 元素包含一个 `foreignObject`，`foreignObject` 内部包含一个 `div`。
    *   **预期输出:**  `foreign->LocationContainer()` 返回 `nullptr` (其定位不受 SVG 根元素的影响)，而 `child->LocationContainer()` 返回 `foreign` 对象的 `LayoutBox`。
*   **逻辑推理:** SVG 元素的定位规则与普通的 HTML 元素有所不同。

**7. 控制剪切 (Control Clip):**

*   **功能:** 测试表单控件（例如 `<input type='button'>`）的剪切行为。
*   **与 HTML 的关系:** 涉及到 HTML 表单控件。
*   **假设输入与输出:**
    *   **假设输入 (HTML):** 一个 `<input type='button'>` 元素。
    *   **预期输出:** `target->HasControlClip()` 返回 `true`，并且 `target->ClippingRect()` 返回预期的剪切矩形。
*   **逻辑推理:** 表单控件通常有默认的剪切行为，以确保其内容在边界内。

**8. 可视溢出矩形 (Visual Overflow Rect):**

*   **功能:** 测试 `LayoutBox` 的可视溢出矩形计算。这包括自身溢出和子元素造成的溢出。
*   **与 CSS 的关系:**  涉及到 CSS 的 `overflow`, `mask`, `contain` 等属性。
*   **假设输入与输出:**
    *   **假设输入 (HTML/CSS):** 一个固定大小的父 `div` 包含一个尺寸更大的子 `div`。
    *   **预期输出:** `target->VisualOverflowRect()` 返回包含子元素的可视区域的矩形。
    *   **假设输入 (HTML/CSS):** 一个设置了 `-webkit-mask-image` 的 `div`。
    *   **预期输出:**  `target->VisualOverflowRect()` 将受到 mask 的影响。
*   **逻辑推理:** 可视溢出矩形用于确定哪些部分需要绘制，以及滚动条的行为。

**9. 内容可视溢出 (Contents Visual Overflow):**

*   **功能:** 测试内容可视溢出的计算，它考虑了子元素的溢出并向上冒泡。
*   **与 CSS 的关系:** 与布局和 `writing-mode` 等属性相关。
*   **假设输入与输出:**  涉及多个嵌套的 `div` 元素，可能具有不同的 `writing-mode` 和 margin。测试会验证内容可视溢出是否正确向上累积。
*   **逻辑推理:**  理解内容可视溢出对于正确处理布局和绘制至关重要。

**10. 点击测试和溢出剪切 (Hit Test and Overflow Clip Margin):**

*   **功能:** 测试在存在 `overflow-clip-margin` 和 `contain: paint` 的情况下，点击测试（确定点击发生在哪个元素上）是否正确。
*   **与 CSS 的关系:**  涉及到 CSS 的 `overflow-clip-margin` 和 `contain` 属性。
*   **假设输入与输出:**
    *   **假设输入 (HTML/CSS):** 一个父 `div` 设置了 `overflow: clip` 和 `overflow-clip-margin`，内部包含一个溢出的子 `div`。
    *   **预期输出:**  在溢出剪切边缘内点击应该命中子元素，超出边缘则不应该。
*   **逻辑推理:**  点击测试需要考虑元素的剪切区域。

**11. 溢出矩形和 Contain Paint (Overflow Rects and Contain Paint):**

*   **功能:** 测试当使用 `contain: paint` 和 `overflow: hidden` 时，各种溢出矩形的计算结果。
*   **与 CSS 的关系:**  涉及到 CSS 的 `contain` 和 `overflow` 属性。
*   **假设输入与输出:**  一个设置了 `contain: paint` 或 `overflow: hidden` 的容器 `div`，内部包含一个溢出的子 `div`。测试会验证 `ScrollableOverflowRect`, `VisualOverflowRect`, `SelfVisualOverflowRect`, `ContentsVisualOverflowRect`, `OverflowClipRect` 的值。
*   **逻辑推理:**  `contain: paint` 属性会限制元素的渲染范围，影响溢出行为。

**12. 设置文本字段的固有内联大小 (Set TextField Intrinsic Inline Size):**

*   **功能:** 测试计算文本输入框 (`<input type='number'>`) 的默认固有内联大小，这会受到内部 spin button 的影响。
*   **与 HTML/CSS 的关系:** 涉及到 HTML 的表单控件和 CSS 的 appearance 属性以及伪元素。
*   **假设输入与输出:**  不同配置的 `<input type='number'>` 元素，包括设置了不同宽度的 `::-webkit-inner-spin-button`。测试会验证 `DefaultIntrinsicContentInlineSize()` 的返回值。
*   **逻辑推理:**  固有内联大小是浏览器布局计算的重要因素。

**13. 延迟失效 (Delayed Invalidation):**

*   **功能:** 测试对于动画图片，渲染失效（需要重新绘制）是否可以被延迟。这是一种性能优化。
*   **与 HTML 的关系:**  涉及到 HTML 的 `<img>` 元素。
*   **假设输入与输出:**  一个 `<img>` 元素加载了一个动画图片。测试会模拟图片内容改变，并检查是否触发了延迟失效。
*   **逻辑推理:**  对于频繁变化的动画，延迟失效可以减少不必要的重绘。

**常见的使用错误 (与编程相关):**

虽然这个文件是测试代码，但它反映了在编写 CSS 和 JavaScript 时可能遇到的布局相关的错误：

*   **错误理解 `clip` 属性:** 开发者可能认为使用 `clip` 属性会影响父元素的背景遮挡判断，但测试表明并非如此。
*   **混淆不同类型的背景矩形:** 开发者可能不清楚 `border-box`, `padding-box`, `content-box` 对于背景绘制范围的影响。
*   **不理解定位容器:**  在进行绝对定位时，错误地假设元素的定位容器，导致元素位置错误。
*   **忽略 `writing-mode` 的影响:**  在垂直书写模式下进行布局时，可能会忘记坐标轴的翻转。
*   **错误地假设 `contain: paint` 的作用范围:** 开发者可能认为 `contain: paint` 会影响所有子元素的渲染，但实际上它主要限制了自身及其后代的绘制范围。
*   **不了解表单控件的默认样式和行为:**  例如，不清楚 spin button 会影响数字输入框的固有大小。
*   **过度依赖立即失效:**  对于动画等频繁变化的元素，不了解浏览器可能进行的延迟失效优化。

**总结一下 `layout_box_test.cc` 的功能:**

该测试文件全面地测试了 `LayoutBox` 类的各种核心功能，涵盖了背景遮挡、前景不透明度、背景绘制范围、元素定位、溢出处理、剪切行为以及与特定 HTML 元素（如表单控件和 SVG）的交互。这些测试确保了 Blink 渲染引擎能够正确地解释和应用 CSS 样式，并准确地计算元素的布局和绘制信息，最终保证网页的正确呈现。

这是第 1 部分的分析和归纳，主要涵盖了文件的前半部分内容。后续部分可能会涉及更多 `LayoutBox` 的功能测试。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_box_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_box.h"

#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/graphics/test/stub_image.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"

namespace blink {

class LayoutBoxTest : public RenderingTest {
 public:
  LayoutBoxTest() = default;

 protected:
  bool ForegroundIsKnownToBeOpaqueInRect(const LayoutBox& box,
                                         const PhysicalRect& rect) {
    return box.ForegroundIsKnownToBeOpaqueInRect(rect, 10);
  }
};

TEST_F(LayoutBoxTest, BackgroundIsKnownToBeObscured) {
  SetBodyInnerHTML(R"HTML(
    <style>.column { width: 295.4px; padding-left: 10.4px; }
    .white-background { background: red; position: relative; overflow:
    hidden; border-radius: 1px; }
    .black-background { height: 100px; background: black; color: white; }
    </style>
    <div class='column'> <div> <div id='target' class='white-background'>
    <div class='black-background'></div> </div> </div> </div>
  )HTML");
  const auto* target = GetLayoutBoxByElementId("target");
  EXPECT_TRUE(target->BackgroundIsKnownToBeObscured());
}

TEST_F(LayoutBoxTest, BackgroundNotObscuredWithCssClippedChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        position: relative;
        width: 200px;
        height: 200px;
        background-color: green;
      }
      #child {
        position: absolute;
        width: 100%;
        height: 100%;
        background-color: blue;
        /* clip the 200x200 box to a centered, 100x100 square. */
        clip: rect(50px, 150px, 150px, 50px);
      }
    </style>
    <div id="parent">
      <div id="child"></div>
    </div>
  )HTML");
  auto* child = GetLayoutBoxByElementId("child");
  EXPECT_FALSE(child->BackgroundIsKnownToBeObscured());

  auto* parent = GetLayoutBoxByElementId("parent");
  EXPECT_FALSE(parent->BackgroundIsKnownToBeObscured());
}

TEST_F(LayoutBoxTest, BackgroundNotObscuredWithCssClippedGrandChild) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        position: relative;
        width: 200px;
        height: 200px;
        background-color: green;
      }
      #child {
        position: absolute;
        width: 100%;
        height: 100%;
        /* clip the 200x200 box to a centered, 100x100 square. */
        clip: rect(50px, 150px, 150px, 50px);
      }
      #grandchild {
        position: absolute;
        width: 100%;
        height: 100%;
        background-color: blue;
      }
    </style>
    <div id="parent">
      <div id="child">
        <div id="grandchild"></div>
      </div>
    </div>
  )HTML");
  auto* grandchild = GetLayoutBoxByElementId("grandchild");
  EXPECT_FALSE(grandchild->BackgroundIsKnownToBeObscured());

  auto* child = GetLayoutBoxByElementId("child");
  EXPECT_FALSE(child->BackgroundIsKnownToBeObscured());

  auto* parent = GetLayoutBoxByElementId("parent");
  EXPECT_FALSE(parent->BackgroundIsKnownToBeObscured());
}

TEST_F(LayoutBoxTest, ForegroundIsKnownToBeOpaqueInRect) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="width: 30px; height: 30px">
      <div style="width: 10px; height: 10px; background: blue"></div>
      <div>
        <div style="width: 10px; height: 10px; opacity: 0.5; background: red">
        </div>
        <div style="width: 10px; height: 10px; background: green;
                    position: relative; left: 20px">
      </div>
    </div>
  )HTML");

  auto& target = *GetLayoutBoxByElementId("target");
  // Covered by the first child which is opaque.
  EXPECT_TRUE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 0, 10, 10)));
  // Covered by the first child of the second child is translucent.
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 10, 10, 10)));
  // Though covered by the second child of the second child which is opaque,
  // we ignore child layers.
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(20, 20, 10, 10)));
  // Not covered by any child.
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 20, 10, 10)));
  // Partly covered by opaque children.
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 0, 30, 30)));
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 0, 10, 30)));
}

TEST_F(LayoutBoxTest, ForegroundIsKnownToBeOpaqueInRectVerticalRL) {
  SetBodyInnerHTML(R"HTML(
    <div id="target"
         style="width: 30px; height: 30px; writing-mode: vertical-rl">
      <div style="width: 10px; height: 10px; background: blue"></div>
      <div>
        <div style="width: 10px; height: 10px; opacity: 0.5; background: red">
        </div>
        <div style="width: 10px; height: 10px; background: green;
                    position: relative; top: 20px">
      </div>
    </div>
  )HTML");

  auto& target = *GetLayoutBoxByElementId("target");
  // Covered by the first child which is opaque.
  EXPECT_TRUE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(20, 0, 10, 10)));
  // Covered by the first child of the second child is translucent.
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(10, 0, 10, 10)));
  // Covered by the second child of the second child which is opaque.
  // However, the algorithm is optimized for horizontal-tb writing mode and has
  // false-negative (which is allowed) in this case.
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 20, 10, 10)));
  // Not covered by any child.
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 0, 10, 10)));
  // Partly covered by opaque children.
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(0, 0, 30, 30)));
  EXPECT_FALSE(
      ForegroundIsKnownToBeOpaqueInRect(target, PhysicalRect(20, 0, 30, 10)));
}

TEST_F(LayoutBoxTest, BackgroundRect) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div { position: absolute; width: 100px; height: 100px;
            padding: 10px; border: 10px solid black; overflow: scroll; }
      #target1a, #target7a { border: 10px dashed black; }
      #target1, #target1a {
        background:
            url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg) border-box,
            green content-box;
      }
      #target1b {
        background:
            url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg) border-box;
      }
      #target2 {
        background:
            url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg) content-box,
            green local border-box;
      }
      #target2b {
        background:
            url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg) content-box;
      }
      #target3 {
        background:
            url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg) content-box,
            rgba(0, 255, 0, 0.5) border-box;
      }
      #target4 {
        background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg),
                          none;
        background-clip: content-box, border-box;
        background-blend-mode: normal, multiply;
        background-color: green;
      }
      #target5 { background: none border-box, green content-box;}
      #target6 { background: green content-box local; }
      #target7, #target7a {
        background-color: green;
        -webkit-background-clip: text;
      }
      #target8 { background: transparent; }
      #target9 { background: none; }
    </style>
    <div id='target1'></div>
    <div id='target1a'></div>
    <div id='target1b'></div>
    <div id='target2'></div>
    <div id='target2b'></div>
    <div id='target3'></div>
    <div id='target4'></div>
    <div id='target5'></div>
    <div id='target6'></div>
    <div id='target7'></div>
    <div id='target7a'></div>
    <div id='target8'></div>
    <div id='target9'></div>
  )HTML");

  // #target1's opaque background color only fills the content box but its
  // translucent image extends to the borders.
  LayoutBox* layout_box = GetLayoutBoxByElementId("target1");
  EXPECT_EQ(PhysicalRect(20, 20, 100, 100),
            layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect));
  // The opaque border covers the translucent image outside of the padding box.
  EXPECT_EQ(PhysicalRect(10, 10, 120, 120),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target1a is the same as #target1 except that the border is not opaque.
  layout_box = GetLayoutBoxByElementId("target1a");
  EXPECT_EQ(PhysicalRect(20, 20, 100, 100),
            layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect));
  EXPECT_EQ(PhysicalRect(0, 0, 140, 140),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target1b is the same as #target1 except no background color.
  layout_box = GetLayoutBoxByElementId("target1b");
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect).IsEmpty());
  EXPECT_EQ(PhysicalRect(10, 10, 120, 120),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target2's background color is opaque but only fills the padding-box
  // because it has local attachment. This eclipses the content-box image.
  layout_box = GetLayoutBoxByElementId("target2");
  EXPECT_EQ(PhysicalRect(10, 10, 120, 120),
            layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect));
  EXPECT_EQ(PhysicalRect(10, 10, 120, 120),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target2b is the same as #target2 except no background color.
  layout_box = GetLayoutBoxByElementId("target2b");
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect).IsEmpty());
  EXPECT_EQ(PhysicalRect(20, 20, 100, 100),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target3's background color is not opaque.
  layout_box = GetLayoutBoxByElementId("target3");
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect).IsEmpty());
  EXPECT_EQ(PhysicalRect(10, 10, 120, 120),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target4's background color has a blend mode so it isn't opaque.
  layout_box = GetLayoutBoxByElementId("target4");
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect).IsEmpty());
  EXPECT_EQ(PhysicalRect(10, 10, 120, 120),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target5's solid background only covers the content-box but it has a "none"
  // background covering the border box.
  layout_box = GetLayoutBoxByElementId("target5");
  EXPECT_EQ(PhysicalRect(20, 20, 100, 100),
            layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect));
  EXPECT_EQ(PhysicalRect(20, 20, 100, 100),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // Because it can scroll due to local attachment, the opaque local background
  // in #target6 is treated as padding box for the clip rect, but remains the
  // content box for the known opaque rect.
  layout_box = GetLayoutBoxByElementId("target6");
  EXPECT_EQ(PhysicalRect(20, 20, 100, 100),
            layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect));
  EXPECT_EQ(PhysicalRect(10, 10, 120, 120),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target7 has background-clip:text. The background may extend to the border
  // box.
  layout_box = GetLayoutBoxByElementId("target7");
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect).IsEmpty());
  EXPECT_EQ(PhysicalRect(10, 10, 120, 120),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // #target7a is the same as #target1 except that the border is not opaque.
  layout_box = GetLayoutBoxByElementId("target7a");
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect).IsEmpty());
  EXPECT_EQ(PhysicalRect(0, 0, 140, 140),
            layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent));

  // background: none
  layout_box = GetLayoutBoxByElementId("target8");
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect).IsEmpty());
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent).IsEmpty());

  // background: transparent
  layout_box = GetLayoutBoxByElementId("target9");
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundKnownOpaqueRect).IsEmpty());
  EXPECT_TRUE(
      layout_box->PhysicalBackgroundRect(kBackgroundPaintedExtent).IsEmpty());
}

TEST_F(LayoutBoxTest, LocationContainer) {
  SetBodyInnerHTML(R"HTML(
    <div id='div'>
      <b>Inline content<img id='img'></b>
    </div>
    <table id='table'>
      <tbody id='tbody'>
        <tr id='row'>
          <td id='cell' style='width: 100px; height: 80px'></td>
        </tr>
      </tbody>
    </table>
  )HTML");

  const LayoutBox* body = GetDocument().body()->GetLayoutBox();
  const LayoutBox* div = GetLayoutBoxByElementId("div");
  const LayoutBox* img = GetLayoutBoxByElementId("img");
  const LayoutBox* table = GetLayoutBoxByElementId("table");
  const LayoutBox* tbody = GetLayoutBoxByElementId("tbody");
  const LayoutBox* row = GetLayoutBoxByElementId("row");
  const LayoutBox* cell = GetLayoutBoxByElementId("cell");

  EXPECT_EQ(body, div->LocationContainer());
  EXPECT_EQ(div, img->LocationContainer());
  EXPECT_EQ(body, table->LocationContainer());
  EXPECT_EQ(table, tbody->LocationContainer());
  EXPECT_EQ(tbody, row->LocationContainer());
  EXPECT_EQ(row, cell->LocationContainer());
}

TEST_F(LayoutBoxTest, TopLeftLocationFlipped) {
  SetBodyInnerHTML(R"HTML(
    <div style='width: 600px; height: 200px; writing-mode: vertical-rl'>
      <div id='box1' style='width: 100px'></div>
      <div id='box2' style='width: 200px'></div>
    </div>
  )HTML");

  const LayoutBox* box1 = GetLayoutBoxByElementId("box1");
  EXPECT_EQ(PhysicalOffset(500, 0), box1->PhysicalLocation());

  const LayoutBox* box2 = GetLayoutBoxByElementId("box2");
  EXPECT_EQ(PhysicalOffset(300, 0), box2->PhysicalLocation());
}

TEST_F(LayoutBoxTest, TableRowCellTopLeftLocationFlipped) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetBodyInnerHTML(R"HTML(
    <div style='writing-mode: vertical-rl'>
      <table style='border-spacing: 0'>
        <thead><tr><td style='width: 50px'></td></tr></thead>
        <tbody>
          <tr id='row1'>
            <td id='cell1' style='width: 100px; height: 80px'></td>
          </tr>
          <tr id='row2'>
            <td id='cell2' style='width: 300px; height: 80px'></td>
          </tr>
        </tbody>
      </table>
    </div>
  )HTML");

  // location and physicalLocation of a table row or a table cell should be
  // relative to the containing section.

  const LayoutBox* row1 = GetLayoutBoxByElementId("row1");
  EXPECT_EQ(PhysicalOffset(300, 0), row1->PhysicalLocation());

  const LayoutBox* cell1 = GetLayoutBoxByElementId("cell1");
  EXPECT_EQ(PhysicalOffset(0, 0), cell1->PhysicalLocation());

  const LayoutBox* row2 = GetLayoutBoxByElementId("row2");
  EXPECT_EQ(PhysicalOffset(0, 0), row2->PhysicalLocation());

  const LayoutBox* cell2 = GetLayoutBoxByElementId("cell2");
  EXPECT_EQ(PhysicalOffset(0, 0), cell2->PhysicalLocation());
}

TEST_F(LayoutBoxTest, LocationContainerOfSVG) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg' style='writing-mode:vertical-rl' width='500' height='500'>
      <foreignObject x='44' y='77' width='100' height='80' id='foreign'>
        <div id='child' style='width: 33px; height: 55px'>
        </div>
      </foreignObject>
    </svg>
  )HTML");
  const LayoutBox* svg_root = GetLayoutBoxByElementId("svg");
  const LayoutBox* foreign = GetLayoutBoxByElementId("foreign");
  const LayoutBox* child = GetLayoutBoxByElementId("child");

  EXPECT_EQ(GetDocument().body()->GetLayoutObject(),
            svg_root->LocationContainer());

  // The foreign object's location is not affected by SVGRoot's writing-mode.
  EXPECT_FALSE(foreign->LocationContainer());
  EXPECT_EQ(PhysicalSize(100, 80), foreign->Size());
  EXPECT_EQ(PhysicalOffset(44, 77), foreign->PhysicalLocation());
  // The writing mode style should be still be inherited.
  EXPECT_TRUE(foreign->HasFlippedBlocksWritingMode());

  // The child of the foreign object is affected by writing-mode.
  EXPECT_EQ(foreign, child->LocationContainer());
  EXPECT_EQ(PhysicalSize(33, 55), child->Size());
  EXPECT_EQ(PhysicalOffset(67, 0), child->PhysicalLocation());
  EXPECT_TRUE(child->HasFlippedBlocksWritingMode());
}

TEST_F(LayoutBoxTest, ControlClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #target {
        position: relative;
        width: 100px; height: 50px;
      }
    </style>
    <input id='target' type='button' value='some text'/>
  )HTML");
  LayoutBox* target = GetLayoutBoxByElementId("target");
  EXPECT_TRUE(target->HasControlClip());
  EXPECT_TRUE(target->HasClipRelatedProperty());
  EXPECT_TRUE(target->ShouldClipOverflowAlongEitherAxis());
  EXPECT_EQ(PhysicalRect(2, 2, 96, 46), target->ClippingRect(PhysicalOffset()));
}

TEST_F(LayoutBoxTest, VisualOverflowRectWithBlockChild) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width: 100px; height: 100px; baground: blue'>
      <div style='width: 300px; height: 300px; background: green'></div>
    </div>
  )HTML");

  LayoutBox* target = GetLayoutBoxByElementId("target");
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), target->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 300, 300), target->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, VisualOverflowRectWithLegacyChild) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='width: 100px; height: 100px; baground: blue'>
      <svg height='300' width='300' style='display: block'></svg>
    </div>
  )HTML");

  LayoutBox* target = GetLayoutBoxByElementId("target");
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), target->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 300, 300), target->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, VisualOverflowRectWithMask) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='-webkit-mask-image: url(#a);
         width: 100px; height: 100px; baground: blue'>
      <div style='width: 300px; height: 300px; background: green'></div>
    </div>
  )HTML");

  LayoutBox* target = GetLayoutBoxByElementId("target");
  EXPECT_TRUE(target->HasMask());
  EXPECT_FALSE(target->IsScrollContainer());
  EXPECT_FALSE(target->ShouldClipOverflowAlongEitherAxis());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), target->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), target->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, VisualOverflowRectWithMaskAndOverflowHidden) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='-webkit-mask-image: url(#a); overflow: hidden;
         width: 100px; height: 100px; background: blue'>
      <div style='width: 300px; height: 300px; background: green'></div>
    </div>
  )HTML");

  LayoutBox* target = GetLayoutBoxByElementId("target");
  EXPECT_TRUE(target->HasMask());
  EXPECT_TRUE(target->IsScrollContainer());
  EXPECT_TRUE(target->ShouldClipOverflowAlongBothAxis());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), target->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), target->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, VisualOverflowRectWithMaskWithOutset) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='-webkit-mask-box-image-source: url(#a);
    -webkit-mask-box-image-outset: 10px 20px;
         width: 100px; height: 100px; background: blue'>
      <div style='width: 300px; height: 300px; background: green'></div>
    </div>
  )HTML");

  LayoutBox* target = GetLayoutBoxByElementId("target");
  EXPECT_TRUE(target->HasMask());
  EXPECT_FALSE(target->IsScrollContainer());
  EXPECT_FALSE(target->ShouldClipOverflowAlongEitherAxis());
  EXPECT_EQ(PhysicalRect(-20, -10, 140, 120), target->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(-20, -10, 140, 120), target->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, VisualOverflowRectWithMaskWithOutsetAndOverflowHidden) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='-webkit-mask-box-image-source: url(#a);
    -webkit-mask-box-image-outset: 10px 20px; overflow: hidden;
         width: 100px; height: 100px; background: blue'>
      <div style='width: 300px; height: 300px; background: green'></div>
    </div>
  )HTML");

  LayoutBox* target = GetLayoutBoxByElementId("target");
  EXPECT_TRUE(target->HasMask());
  EXPECT_TRUE(target->IsScrollContainer());
  EXPECT_TRUE(target->ShouldClipOverflowAlongBothAxis());
  EXPECT_EQ(PhysicalRect(-20, -10, 140, 120), target->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(-20, -10, 140, 120), target->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, VisualOverflowRectOverflowHidden) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='overflow: hidden;
         width: 100px; height: 100px; background: blue'>
      <div style='width: 300px; height: 300px; background: green'></div>
    </div>
  )HTML");

  LayoutBox* target = GetLayoutBoxByElementId("target");
  EXPECT_TRUE(target->IsScrollContainer());
  EXPECT_TRUE(target->ShouldClipOverflowAlongBothAxis());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), target->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), target->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, VisualOverflowRectOverflowClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .parent { width: 100px; height: 50px; }
      .child { width: 300px; height: 300px; }
    </style>
    <div id="clip" style="overflow: clip" class="parent">
      <div class="child"></div>
    </div>
    <div id="clip-x" style="overflow-x: clip" class="parent">
      <div class="child"></div>
    </div>
    <div id="clip-y" style="overflow-y: clip" class="parent">
      <div class="child"></div>
    </div>
  )HTML");

  LayoutBox* clip = GetLayoutBoxByElementId("clip");
  EXPECT_FALSE(clip->IsScrollContainer());
  EXPECT_TRUE(clip->ShouldClipOverflowAlongBothAxis());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 50), clip->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 50), clip->VisualOverflowRect());

  LayoutBox* clip_x = GetLayoutBoxByElementId("clip-x");
  EXPECT_FALSE(clip_x->IsScrollContainer());
  EXPECT_EQ(kOverflowClipX, clip_x->GetOverflowClipAxes());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 50), clip_x->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 300), clip_x->VisualOverflowRect());

  LayoutBox* clip_y = GetLayoutBoxByElementId("clip-y");
  EXPECT_FALSE(clip_y->IsScrollContainer());
  EXPECT_EQ(kOverflowClipY, clip_y->GetOverflowClipAxes());
  EXPECT_EQ(PhysicalRect(0, 0, 100, 50), clip_y->SelfVisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 300, 50), clip_y->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, VisualOverflowRectWithOverflowClipMargin) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .parent { width: 100px; height: 50px; overflow: clip; }
      .parent2 { width: 100px; height: 50px; contain: paint; }
      .child { width: 110px; height: 55px; }
    </style>
    <div id="clip1" style="overflow-clip-margin: 4px" class="parent">
      <div class="child"></div>
    </div>
    <div id="clip2" style="overflow-clip-margin: 11px" class="parent">
      <div class="child"></div>
    </div>
    <div id="clip3" style="overflow-clip-margin: 11px" class="parent2">
      <div class="child"></div>
    </div>
  )HTML");

  LayoutBox* clip1 = GetLayoutBoxByElementId("clip1");
  EXPECT_FALSE(clip1->IsScrollContainer());
  EXPECT_TRUE(clip1->ShouldClipOverflowAlongBothAxis());
  EXPECT_EQ(PhysicalRect(0, 0, 104, 54), clip1->VisualOverflowRect());

  LayoutBox* clip2 = GetLayoutBoxByElementId("clip2");
  EXPECT_FALSE(clip2->IsScrollContainer());
  EXPECT_TRUE(clip2->ShouldClipOverflowAlongBothAxis());
  EXPECT_EQ(PhysicalRect(0, 0, 110, 55), clip2->VisualOverflowRect());

  LayoutBox* clip3 = GetLayoutBoxByElementId("clip3");
  EXPECT_FALSE(clip3->IsScrollContainer());
  EXPECT_TRUE(clip3->ShouldClipOverflowAlongBothAxis());
  EXPECT_EQ(PhysicalRect(0, 0, 110, 55), clip3->VisualOverflowRect());
}

// |InkOverflow| stopped storing visual overflow contained by |BorderBoxRect|
// because they are not useful, and they are inconsistent when fully contained
// and partially contained.
// TODO(crbug.com/1144203): Change this to "if (NG)" when NG always use
// fragment-based ink overflow. Then, remove this when legacy is gone.
#define EXPECT_CONTENTS_VISUAL_OVERFLOW(rect, layout_box)           \
  if (layout_box->CanUseFragmentsForVisualOverflow()) {             \
    EXPECT_EQ(UnionRect(rect, layout_box->PhysicalBorderBoxRect()), \
              layout_box->ContentsVisualOverflowRect());            \
  } else {                                                          \
    EXPECT_EQ(rect, layout_box->ContentsVisualOverflowRect());      \
  }

TEST_F(LayoutBoxTest, ContentsVisualOverflowPropagation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div { width: 100px; height: 100px }
    </style>
    <div id='a'>
      <div style='height: 50px'></div>
      <div id='b' style='writing-mode: vertical-rl; margin-left: 60px'>
        <div style='width: 30px'></div>
        <div id='c' style='margin-top: 40px'>
          <div style='width: 10px'></div>
          <div style='margin-top: 20px; margin-left: 10px'></div>
        </div>
        <div id='d' style='writing-mode: vertical-lr; margin-top: 40px'>
          <div style='width: 10px'></div>
          <div style='margin-top: 20px'></div>
        </div>
      </div>
    </div>
  )HTML");

  const int kCContentsLeft = -10;
  auto* c = GetLayoutBoxByElementId("c");
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), c->SelfVisualOverflowRect());
  EXPECT_CONTENTS_VISUAL_OVERFLOW(PhysicalRect(kCContentsLeft, 20, 100, 100),
                                  c);
  EXPECT_EQ(PhysicalRect(kCContentsLeft, 0, 110, 120), c->VisualOverflowRect());

  auto* d = GetLayoutBoxByElementId("d");
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), d->SelfVisualOverflowRect());
  EXPECT_CONTENTS_VISUAL_OVERFLOW(PhysicalRect(10, 20, 100, 100), d);
  EXPECT_EQ(PhysicalRect(0, 0, 110, 120), d->VisualOverflowRect());

  auto* b = GetLayoutBoxByElementId("b");
  const int kBContentsLeft = -130;
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), b->SelfVisualOverflowRect());
  // Union of VisualOverflowRectForPropagations offset by locations of c and d.
  EXPECT_CONTENTS_VISUAL_OVERFLOW(PhysicalRect(kBContentsLeft, 40, 200, 120),
                                  b);
  EXPECT_EQ(PhysicalRect(kBContentsLeft, 0, 230, 160), b->VisualOverflowRect());

  auto* a = GetLayoutBoxByElementId("a");
  EXPECT_EQ(PhysicalRect(0, 0, 100, 100), a->SelfVisualOverflowRect());
  EXPECT_CONTENTS_VISUAL_OVERFLOW(PhysicalRect(-70, 50, 230, 160), a);
  EXPECT_EQ(PhysicalRect(-70, 0, 230, 210), a->VisualOverflowRect());
}

TEST_F(LayoutBoxTest, HitTestOverflowClipMargin) {
  SetBodyInnerHTML(R"HTML(
    <div id="container" style="width: 200px; height: 200px; overflow: clip;
                               overflow-clip-margin: 50px">
      <div id="child" style="width: 300px; height: 100px"></div>
    </div>
  )HTML");

  auto* container = GetElementById("container");
  auto* child = GetElementById("child");
  // In child overflowing container but within the overflow clip.
  EXPECT_EQ(child, HitTest(230, 50));
  // Outside of the overflow clip, would be in child without the clip.
  EXPECT_EQ(GetDocument().body(), HitTest(280, 50));
  // In container's border box rect, not in child.
  EXPECT_EQ(container, HitTest(100, 150));
  // In the bottom clip margin, but there is nothing.
  EXPECT_EQ(GetDocument().documentElement(), HitTest(100, 230));
}

TEST_F(LayoutBoxTest, HitTestContainPaint) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='width: 100px; height: 200px; contain: paint'>
      <div id='child' style='width: 300px; height: 400px;'></div>
    </div>
  )HTML");

  auto* child = GetElementById("child");
  EXPECT_EQ(GetDocument().documentElement(), HitTest(1, 1));
  EXPECT_EQ(child, HitTest(10, 10));
  EXPECT_EQ(GetDocument().FirstBodyElement(), HitTest(150, 10));
  EXPECT_EQ(GetDocument().documentElement(), HitTest(10, 250));
}

TEST_F(LayoutBoxTest, OverflowRectsContainPaint) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='width: 100px; height: 200px; contain: paint;
                               border: 10px solid blue'>
      <div id='child' style='width: 300px; height: 400px;'></div>
    </div>
  )HTML");

  auto* container = GetLayoutBoxByElementId("container");
  EXPECT_TRUE(container->ShouldClipOverflowAlongEitherAxis());
  EXPECT_EQ(PhysicalRect(10, 10, 300, 400),
            container->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 120, 220), container->VisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 120, 220), container->SelfVisualOverflowRect());
  EXPECT_CONTENTS_VISUAL_OVERFLOW(PhysicalRect(10, 10, 300, 400), container);
  EXPECT_EQ(PhysicalRect(10, 10, 100, 200),
            container->OverflowClipRect(PhysicalOffset()));
}

TEST_F(LayoutBoxTest, OverflowRectsOverflowHidden) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='width: 100px; height: 200px; overflow: hidden;
                               border: 10px solid blue'>
      <div id='child' style='width: 300px; height: 400px;'></div>
    </div>
  )HTML");

  auto* container = GetLayoutBoxByElementId("container");
  EXPECT_TRUE(container->ShouldClipOverflowAlongEitherAxis());
  EXPECT_EQ(PhysicalRect(10, 10, 300, 400),
            container->ScrollableOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 120, 220), container->VisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 120, 220), container->SelfVisualOverflowRect());
  EXPECT_CONTENTS_VISUAL_OVERFLOW(PhysicalRect(10, 10, 300, 400), container);
  EXPECT_EQ(PhysicalRect(10, 10, 100, 200),
            container->OverflowClipRect(PhysicalOffset()));
}

TEST_F(LayoutBoxTest, SetTextFieldIntrinsicInlineSize) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
   <style>
     input { font: 10px Ahem; }
     #a::-webkit-inner-spin-button{ width: 50%; appearance: none; }
     #b::-webkit-inner-spin-button{ width: 50px; appearance: none; }
     #c::-webkit-inner-spin-button{ width: 100%; appearance: none; }
   </style>
   <input id='a' type='number' min='100' max='100' step='1'/>
   <input id='b' type='number' min='100' max='100' step='1'/>
   <input id='c' type='number' min='100' max='100' step='1'/>
  )HTML");

  LayoutBox* a = GetLayoutBoxByElementId("a");
  EXPECT_EQ(LayoutUnit(60), a->DefaultIntrinsicContentInlineSize());

  LayoutBox* b = GetLayoutBoxByElementId("b");
  EXPECT_EQ(LayoutUnit(80), b->DefaultIntrinsicContentInlineSize());

  LayoutBox* c = GetLayoutBoxByElementId("c");
  EXPECT_EQ(LayoutUnit(30), c->DefaultIntrinsicContentInlineSize());
}

class AnimatedImage : public StubImage {
 public:
  bool MaybeAnimated() override { return true; }
};

TEST_F(LayoutBoxTest, DelayedInvalidation) {
  SetBodyInnerHTML("<img id='image' style='width: 100px; height: 100px;'/>");
  auto* obj = GetLayoutBoxByElementId("image");
  ASSERT_TRUE(obj);

  // Inject an animated image since deferred invalidations are only done for
  // animated images.
  auto* image =
      ImageResourceContent::CreateLoaded(base::AdoptRef(new AnimatedImage()));
  To<LayoutImage>(obj)->ImageResource()->SetImageResource(image);
  ASSERT_TRUE(To<LayoutImage>(obj)->CachedImage()->GetImage()->MaybeAnimated());

  obj->ClearPaintInvalidationFlags();
  EXPECT_FALSE(obj->ShouldDoFullPaintInvalidation());
  EXPECT_EQ(obj->PaintInvalidationReasonForPrePaint(),
            PaintInvalidationReason::kNone);
  EXPECT_FALSE(obj->ShouldDelayFullPaintInvalidation());

  // CanDeferInvalidation::kYes results in a deferred invalidation.
  obj->ImageChanged(image, ImageResourceObserver::CanDeferInvali
"""


```