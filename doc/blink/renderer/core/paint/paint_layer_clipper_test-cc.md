Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The request is to analyze a Chromium Blink test file (`paint_layer_clipper_test.cc`) and describe its functionality, its relationship to web technologies (HTML, CSS, JavaScript), potential user errors, and debugging clues.

2. **Identify the Core Subject:** The file name `paint_layer_clipper_test.cc` and the `#include "third_party/blink/renderer/core/paint/paint_layer_clipper.h"` clearly indicate the test is about the `PaintLayerClipper` class. This class is responsible for calculating clipping rectangles for paint layers.

3. **Examine the Test Structure:** The file uses the standard Google Test framework (`TEST_F`). Each `TEST_F` function focuses on a specific aspect of `PaintLayerClipper`'s behavior. This gives a good high-level overview of what the class does.

4. **Analyze Individual Tests:**  Go through each `TEST_F` one by one and understand its purpose:

    * **`ParentBackgroundClipRectSubpixelAccumulation` & `BackgroundClipRectSubpixelAccumulation` & `SVGBackgroundClipRectSubpixelAccumulation`:** These tests are related to how sub-pixel offsets are handled when calculating the background clip rectangle. This is important for rendering accuracy. Note the HTML structure used in each test to understand the context.

    * **`LayoutSVGRoot`:** This test deals with clipping in the context of an SVG root element. It verifies the calculated background and foreground rectangles.

    * **`ControlClip`:** This test focuses on how form controls (like `<input type=button>`) are clipped. It distinguishes between the overall layer clip and the specific "control clip".

    * **`RoundedClip` & `RoundedClipNested`:** These tests examine clipping when `border-radius` is applied. The key point is that the foreground clip often incorporates the rounding for descendant clipping.

    * **`ControlClipSelect`:** This test is specific to `<select>` elements and how their content is clipped, especially when the content is longer than the visible area.

    * **`LayoutSVGRootChild`:** This test checks clipping for elements inside an SVG `foreignObject`.

    * **`ContainPaintClip` & `NestedContainPaintClip`:**  These tests are about the CSS `contain: paint` property and how it affects clipping. `contain: paint` creates a new paint containment context, leading to different clipping behavior.

    * **`CSSClip`:** This test directly examines the effect of the CSS `clip` and `clip-path` properties on clipping.

    * **`Filter`:** This test explores how CSS filters (`drop-shadow`) influence the calculated clipping rectangles, considering both the layer's own clipping and when mapped to the root layer.

    * **`IgnoreRootLayerClipWith...` (CSSClip, OverflowClip, BothClip):** These tests verify that certain clipping properties on the root element are ignored when calculating clips for its descendants. This is often an optimization or intended behavior in the rendering engine.

    * **`Fragmentation`:** This test deals with how clipping works in the context of CSS fragmentation (like multi-column layouts). It checks the clipping for different fragments of the same element.

    * **`ScrollbarClipBehavior...`:** These tests focus on how scrollbars (especially overlay scrollbars) affect clipping. They test different scenarios, such as clipping the child of a scrollable element and clipping the scrollable element itself.

5. **Identify Relationships to Web Technologies:**  While the code is C++, the tests directly manipulate and inspect the results of rendering HTML and CSS.

    * **HTML:**  The `SetBodyInnerHTML` function is used to set up the DOM structure for each test. The HTML elements (div, input, svg, select, etc.) and their attributes are crucial for understanding the test scenarios.
    * **CSS:** The `style` attributes within the HTML and the `<style>` blocks demonstrate how CSS properties like `overflow`, `width`, `height`, `position`, `border-radius`, `contain`, `clip`, `clip-path`, `filter`, `columns`, and `column-gap` influence the clipping behavior being tested.
    * **JavaScript:**  While this specific test file doesn't *directly* use JavaScript, the rendering engine it's testing is responsible for interpreting JavaScript that might manipulate the DOM and styles, thus indirectly relating to JavaScript's impact on rendering.

6. **Infer Functionality of `PaintLayerClipper`:** Based on the tests, the `PaintLayerClipper` class seems responsible for:

    * Calculating rectangles used to clip the painting of different parts of a `PaintLayer` (background, foreground).
    * Considering various CSS properties that affect clipping.
    * Handling sub-pixel offsets.
    * Dealing with different types of elements (standard block elements, SVG, form controls).
    * Taking into account CSS containment.
    * Managing clipping in the presence of filters.
    * Correctly handling clipping in fragmented contexts.
    * Adapting clipping based on the presence and type of scrollbars.
    * Distinguishing between clipping at the layer's level and when mapped to ancestor layers.

7. **Consider User/Developer Errors:** Think about common mistakes developers make with CSS that could relate to the clipping behavior being tested:

    * Incorrectly assuming `overflow: hidden` will always clip as expected, without considering other factors like filters or transforms.
    * Not understanding the implications of `contain: paint` on clipping.
    * Using `clip` or `clip-path` incorrectly, leading to unexpected masking.
    * Forgetting that rounded corners affect clipping of descendants.
    * Not accounting for scrollbar width when designing layouts.

8. **Formulate Debugging Clues:** How might a developer end up in this code or use it for debugging?

    * Visual rendering issues:  Something is not being drawn correctly or is being clipped unexpectedly.
    * Performance problems: Investigating overdraw or unnecessary rendering.
    * Layout bugs involving scrolling or fixed positioning.
    * When inspecting the paint records or layer tree in the DevTools.

9. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt: Functionality, Relationship to Web Technologies, Logical Reasoning (with examples), Common Errors, and Debugging Clues. Use clear and concise language.

10. **Refine and Review:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any missing connections or areas that could be explained better. For the logical reasoning part, invent simple examples based on the test cases to illustrate the input and output.
这个文件 `paint_layer_clipper_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `PaintLayerClipper` 类的功能。`PaintLayerClipper` 类的核心职责是计算用于裁剪（clipping）绘制层（PaintLayer）的各种矩形区域。

以下是它详细的功能分解：

**1. 测试 `PaintLayerClipper` 的核心功能：**

* **计算背景裁剪矩形 (Background Clip Rect):** 测试在不同场景下，如何计算用于裁剪背景绘制的矩形区域。这涉及到考虑元素的 `overflow` 属性、`border-radius`、父元素的裁剪、以及子像素偏移等因素。
* **计算前景裁剪矩形 (Foreground Clip Rect):** 测试如何计算用于裁剪前景内容（例如文本、边框）的矩形区域。这同样需要考虑多种 CSS 属性的影响。
* **计算图层偏移 (Layer Offset):**  测试在裁剪过程中，如何计算图层的偏移量，这对于正确定位绘制内容至关重要。
* **处理各种 CSS 裁剪属性：** 测试 `clip` 和 `clip-path` CSS 属性对裁剪的影响。
* **处理 `overflow` 属性：** 测试 `overflow: hidden`, `overflow: scroll`, `overflow: auto` 等属性如何影响裁剪。
* **处理 `border-radius`：** 测试圆角边框对裁剪区域的塑造。
* **处理 CSS `contain` 属性：** 特别是 `contain: paint` 属性，它会创建新的绘制上下文，影响裁剪行为。
* **处理 CSS 过滤器 (Filter)：** 测试 CSS 过滤器（如 `drop-shadow`）如何影响裁剪区域的计算。
* **处理 SVG 元素：** 测试在 SVG 环境下，裁剪的计算是否正确。
* **处理表单控件 (Form Controls)：** 测试像 `<input type="button">` 和 `<select>` 这样的表单控件的特殊裁剪行为。
* **处理 CSS 分栏布局 (Fragmentation)：** 测试在使用了 `columns` 属性的多栏布局中，如何针对不同的片段 (Fragment) 进行裁剪。
* **处理滚动条 (Scrollbar)：** 测试滚动条的存在和类型（特别是覆盖滚动条）如何影响裁剪区域的计算。
* **处理子像素偏移 (Subpixel Accumulation)：** 测试在存在子像素偏移的情况下，裁剪区域的计算是否准确。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明：**

该测试文件虽然是 C++ 代码，但它直接验证了浏览器引擎如何解释和应用 HTML 和 CSS 的渲染效果。

* **HTML:**  测试用 `SetBodyInnerHTML()` 方法动态创建 HTML 结构，这些结构模拟了各种需要进行裁剪的场景。例如：
    * **`<div style="overflow: hidden; width: 300px;">`:**  使用 `overflow: hidden` 创建一个裁剪上下文。
    * **`<svg id=target width=200 height=300>`:** 创建一个 SVG 元素，测试 SVG 相关的裁剪。
    * **`<input id=target type=button>`:** 创建一个按钮，测试表单控件的裁剪。
    * **`<div style='contain: paint; ...'>`:** 使用 `contain: paint` 属性。

* **CSS:**  测试通过内联样式 (`style="..."`) 或 `<style>` 标签来设置 CSS 属性，这些属性直接影响裁剪行为。例如：
    * **`width`, `height`:**  定义元素的尺寸，这是裁剪的基础。
    * **`position: absolute`, `position: relative`:**  影响元素的定位和裁剪上下文。
    * **`overflow: hidden`, `overflow: scroll`:**  定义如何处理溢出内容。
    * **`border-radius: 1px`:**  创建圆角。
    * **`clip: rect(0, 50px, 100px, 0)`:**  使用 `clip` 属性定义裁剪区域。
    * **`clip-path: inset(0%)`:** 使用 `clip-path` 属性定义裁剪路径。
    * **`filter: drop-shadow(...)`:** 应用 CSS 过滤器。
    * **`columns: 2`, `column-gap: 0`:** 创建分栏布局。

* **JavaScript:**  虽然这个测试文件本身不包含 JavaScript 代码，但它测试的渲染逻辑是为了正确处理 JavaScript 对 DOM 和 CSS 的动态修改。例如，JavaScript 可以动态改变元素的 `style` 属性，从而触发不同的裁剪行为。这个测试保证了引擎在这些动态变化后仍然能正确计算裁剪。

**3. 逻辑推理、假设输入与输出：**

以下以 `ParentBackgroundClipRectSubpixelAccumulation` 测试为例进行逻辑推理：

* **假设输入 (HTML & CSS):**
  ```html
  <!DOCTYPE html>
  <div style="overflow: hidden; width: 300px;">
    <div id=target style='position: relative; width: 200px; height: 300px'>
  </div>
  ```
  以及 `ClipRectsContext` 的 `PhysicalOffset(LayoutUnit(0.25), LayoutUnit(0.35))`。这个偏移代表了潜在的子像素级别的偏移。

* **逻辑推理:**
    * 父元素设置了 `overflow: hidden`，意味着它的边界会裁剪子元素。
    * `PaintLayerClipper` 需要计算 `target` 元素的背景裁剪矩形。
    * 由于存在父元素的裁剪，背景裁剪矩形不会无限大。
    * `ClipRectsContext` 提供的偏移量 (0.25, 0.35) 需要被考虑在内，这会影响最终裁剪矩形的精确位置。
    * 浏览器渲染通常会进行一定的像素对齐，但子像素信息会累积并影响后续的计算。

* **预期输出 (裁剪矩形):**
  `PhysicalRect(LayoutUnit(8.25), LayoutUnit(8.34375), LayoutUnit(300), LayoutUnit(300))`

    * `(8.25, 8.34375)` 是考虑了初始偏移和潜在的内部布局偏移后的左上角坐标。 这里的 `8` 可能是浏览器默认的边距，而小数部分来自于子像素偏移的累积。
    * `(300, 300)` 是父元素的宽度和高度，因为 `overflow: hidden` 裁剪了子元素的背景到父元素的边界。

**4. 涉及用户或编程常见的使用错误：**

* **误解 `overflow: hidden` 的作用范围：** 用户可能认为 `overflow: hidden` 可以阻止所有子元素溢出，但它主要影响的是元素的背景和边框的绘制以及滚动条的行为。对于绝对定位的元素，溢出行为可能不同。
    * **示例：**  如果子元素使用了 `position: absolute` 并设置了很大的偏移，即使父元素有 `overflow: hidden`，子元素仍然可能超出父元素的视觉边界。

* **忽略 `border-radius` 对裁剪的影响：** 用户可能忘记拥有 `border-radius` 和 `overflow: hidden` 的元素会以圆角的方式裁剪子元素。
    * **示例：**  子元素的某些部分可能因为父元素的圆角而被裁剪掉。

* **不理解 `contain: paint` 的含义：** 开发者可能不清楚 `contain: paint` 会创建一个独立的绘制上下文，这会影响祖先元素的裁剪行为。
    * **示例：**  一个设置了 `contain: paint` 的元素，其祖先的 `overflow: hidden` 可能不会裁剪到这个元素的内容。

* **错误使用 `clip` 属性：** `clip` 属性只能用于绝对定位的元素，并且其语法较为严格，容易出错。
    * **示例：**  在非绝对定位的元素上使用 `clip` 属性不会生效。

* **不考虑子像素渲染带来的细微差异：**  在进行像素级别的精确布局时，子像素渲染可能导致意想不到的显示差异，`PaintLayerClipperTest` 也在测试这方面的准确性。

**5. 用户操作如何一步步的到达这里，作为调试线索：**

当开发者遇到与渲染裁剪相关的 bug 时，可能会逐步深入到 Blink 引擎的渲染代码进行调试。以下是一些可能的操作步骤：

1. **用户发现渲染问题：** 用户在浏览器中看到网页元素的显示不正确，例如内容被意外裁剪、圆角裁剪不符合预期、滚动容器的内容显示异常等。

2. **开发者检查 HTML 和 CSS：** 开发者首先会检查相关的 HTML 结构和 CSS 样式，确认是否有明显的样式错误导致裁剪问题。

3. **使用浏览器开发者工具：**
    * **Elements 面板：** 检查元素的盒模型、应用的样式，特别是与 `overflow`、`clip`、`clip-path`、`border-radius`、`contain` 相关的属性。
    * **Computed 面板：** 查看最终计算出的样式值，确认是否有意外的样式覆盖。
    * **Layers 面板 (或 Rendering 面板中的 Layer Borders)：** 查看页面的分层情况，了解哪些元素创建了新的绘制层，以及可能的裁剪关系。
    * **Paint flashing 或 Composited layer borders：**  帮助开发者可视化哪些区域被重绘或哪些层被合成。

4. **尝试修改 CSS 属性：** 开发者可能会尝试修改相关的 CSS 属性，例如调整 `overflow` 的值、移除 `clip` 属性、修改 `border-radius` 等，观察问题的变化。

5. **怀疑是浏览器引擎 Bug：** 如果开发者排除了 CSS 样式问题，并且问题在不同浏览器或特定场景下出现，可能会怀疑是浏览器引擎的渲染 bug。

6. **查找 Blink 渲染代码：**  开发者可能会根据问题的现象，在 Blink 引擎的源代码中搜索相关的代码。例如，搜索 "clip"、"overflow"、"paint layer" 等关键词。

7. **定位到 `PaintLayerClipper` 相关代码：**  如果问题与裁剪有关，开发者可能会找到 `PaintLayerClipper` 类及其相关的测试文件 `paint_layer_clipper_test.cc`。

8. **阅读测试代码：**  阅读测试代码可以帮助开发者理解 `PaintLayerClipper` 的预期行为和各种裁剪场景的处理方式。测试用例覆盖了各种 CSS 属性和布局情况，可以作为理解引擎内部实现的重要参考。

9. **运行本地测试或调试 Blink 引擎：**  高级开发者可能会尝试在本地编译并运行 Blink 引擎的测试，或者使用调试器逐步执行渲染代码，以便更深入地了解裁剪的计算过程。`paint_layer_clipper_test.cc` 提供的测试用例可以作为调试的起点，验证引擎在特定情况下的行为是否符合预期。

总之，`paint_layer_clipper_test.cc` 是 Blink 引擎中用于保证裁剪功能正确性的重要测试文件，它涵盖了多种 CSS 属性和布局场景下的裁剪计算逻辑，对于理解浏览器如何渲染网页以及调试相关的渲染问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_layer_clipper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer_clipper.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/fragment_data_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class PaintLayerClipperTest : public RenderingTest {
 public:
  PaintLayerClipperTest()
      : RenderingTest(MakeGarbageCollected<EmptyLocalFrameClient>()) {}
};

TEST_F(PaintLayerClipperTest, ParentBackgroundClipRectSubpixelAccumulation) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div style="overflow: hidden; width: 300px;">
      <div id=target style='position: relative; width: 200px; height: 300px'>
    </div>
  )HTML");

  PaintLayer* target_paint_layer = GetPaintLayerByElementId("target");
  ClipRectsContext context(GetDocument().GetLayoutView()->Layer(),
                           &GetDocument().GetLayoutView()->FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip,
                           PhysicalOffset(LayoutUnit(0.25), LayoutUnit(0.35)));

  ClipRect background_rect_gm;
  target_paint_layer->Clipper().CalculateBackgroundClipRect(context,
                                                            background_rect_gm);

  EXPECT_EQ(PhysicalRect(LayoutUnit(8.25), LayoutUnit(8.34375), LayoutUnit(300),
                         LayoutUnit(300)),
            background_rect_gm.Rect());
}

TEST_F(PaintLayerClipperTest, BackgroundClipRectSubpixelAccumulation) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id=target width=200 height=300 style='position: relative'>
  )HTML");

  PaintLayer* target_paint_layer = GetPaintLayerByElementId("target");
  ClipRectsContext context(GetDocument().GetLayoutView()->Layer(),
                           &GetDocument().GetLayoutView()->FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip,
                           PhysicalOffset(LayoutUnit(0.25), LayoutUnit(0.35)));

  ClipRect background_rect_gm;
  target_paint_layer->Clipper().CalculateBackgroundClipRect(context,
                                                            background_rect_gm);

  EXPECT_TRUE(background_rect_gm.IsInfinite()) << background_rect_gm;
}

TEST_F(PaintLayerClipperTest, SVGBackgroundClipRectSubpixelAccumulation) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <svg id=target width=200 height=300 style='position: relative'>
      <rect width=400 height=500 fill='blue'/>
    </svg>
  )HTML");

  PaintLayer* target_paint_layer = GetPaintLayerByElementId("target");
  ClipRectsContext context(GetDocument().GetLayoutView()->Layer(),
                           &GetDocument().GetLayoutView()->FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip,
                           PhysicalOffset(LayoutUnit(0.25), LayoutUnit(0.35)));

  ClipRect background_rect_gm;
  target_paint_layer->Clipper().CalculateBackgroundClipRect(context,
                                                            background_rect_gm);

  EXPECT_TRUE(background_rect_gm.IsInfinite()) << background_rect_gm;
}

TEST_F(PaintLayerClipperTest, LayoutSVGRoot) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <svg id=target width=200 height=300 style='position: relative'>
      <rect width=400 height=500 fill='blue'/>
    </svg>
  )HTML");

  PaintLayer* target_paint_layer = GetPaintLayerByElementId("target");
  // When RLS is enabled, the LayoutView will have a composited scrolling layer,
  // so don't apply an overflow clip.
  ClipRectsContext context(GetDocument().GetLayoutView()->Layer(),
                           &GetDocument().GetLayoutView()->FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip,
                           PhysicalOffset(LayoutUnit(0.25), LayoutUnit(0.35)));
  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  target_paint_layer->Clipper().CalculateRects(
      context, target_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);

  EXPECT_EQ(PhysicalRect(LayoutUnit(8.25), LayoutUnit(8.35), LayoutUnit(200),
                         LayoutUnit(300)),
            background_rect.Rect());
  EXPECT_EQ(PhysicalRect(LayoutUnit(8.25), LayoutUnit(8.35), LayoutUnit(200),
                         LayoutUnit(300)),
            foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(LayoutUnit(8.25), LayoutUnit(8.35)), layer_offset);
}

TEST_F(PaintLayerClipperTest, ControlClip) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <input id=target style='position:absolute; width: 200px; height: 300px'
        type=button>
  )HTML");

  PaintLayer* target_paint_layer = GetPaintLayerByElementId("target");
  // When RLS is enabled, the LayoutView will have a composited scrolling layer,
  // so don't apply an overflow clip.
  ClipRectsContext context(GetDocument().GetLayoutView()->Layer(),
                           &GetDocument().GetLayoutView()->FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip);
  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  target_paint_layer->Clipper().CalculateRects(
      context, target_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);
  // If the PaintLayer clips overflow, the background rect is intersected with
  // the PaintLayer bounds...
  EXPECT_EQ(PhysicalRect(8, 8, 200, 300), background_rect.Rect());
  // and the foreground rect is intersected with the control clip in this case.
  EXPECT_EQ(PhysicalRect(10, 10, 196, 296), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(8, 8), layer_offset);
}

TEST_F(PaintLayerClipperTest, RoundedClip) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id='target' style='position:absolute; width: 200px; height: 300px;
        overflow: hidden; border-radius: 1px'>
    </div>
  )HTML");

  PaintLayer* target_paint_layer = GetPaintLayerByElementId("target");
  ClipRectsContext context(GetDocument().GetLayoutView()->Layer(),
                           &GetDocument().GetLayoutView()->FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip);

  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  target_paint_layer->Clipper().CalculateRects(
      context, target_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);

  // Only the foreground rect gets hasRadius set for overflow clipping
  // of descendants.
  EXPECT_EQ(PhysicalRect(8, 8, 200, 300), background_rect.Rect());
  EXPECT_FALSE(background_rect.HasRadius());
  EXPECT_EQ(PhysicalRect(8, 8, 200, 300), foreground_rect.Rect());
  EXPECT_TRUE(foreground_rect.HasRadius());
  EXPECT_EQ(PhysicalOffset(8, 8), layer_offset);
}

TEST_F(PaintLayerClipperTest, RoundedClipNested) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id='parent' style='position:absolute; width: 200px; height: 300px;
        overflow: hidden; border-radius: 1px'>
      <div id='child' style='position: relative; width: 500px;
           height: 500px'>
      </div>
    </div>
  )HTML");

  PaintLayer* parent_paint_layer = GetPaintLayerByElementId("parent");

  PaintLayer* child_paint_layer = GetPaintLayerByElementId("child");

  ClipRectsContext context(
      parent_paint_layer,
      &parent_paint_layer->GetLayoutObject().FirstFragment());

  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  child_paint_layer->Clipper().CalculateRects(
      context, child_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);

  EXPECT_EQ(PhysicalRect(0, 0, 200, 300), background_rect.Rect());
  EXPECT_TRUE(background_rect.HasRadius());
  EXPECT_EQ(PhysicalRect(0, 0, 200, 300), foreground_rect.Rect());
  EXPECT_TRUE(foreground_rect.HasRadius());
  EXPECT_EQ(PhysicalOffset(), layer_offset);
}

TEST_F(PaintLayerClipperTest, ControlClipSelect) {
  SetBodyInnerHTML(R"HTML(
    <select id='target' style='position: relative; width: 100px;
        background: none; border: none; padding: 0px 15px 0px 5px;'>
      <option>
        Test long texttttttttttttttttttttttttttttttt
      </option>
    </select>
  )HTML");
  LayoutBox* target = GetLayoutBoxByElementId("target");
  PaintLayer* target_paint_layer = target->Layer();
  ClipRectsContext context(GetDocument().GetLayoutView()->Layer(),
                           &GetDocument().GetLayoutView()->FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip);

  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  target_paint_layer->Clipper().CalculateRects(
      context, target_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);

  PhysicalRect content_box_rect = target->PhysicalContentBoxRect();
  EXPECT_GT(foreground_rect.Rect().X(),
            content_box_rect.X() + target->PhysicalLocation().left);
  EXPECT_LE(foreground_rect.Rect().Width(), content_box_rect.Width());
}

TEST_F(PaintLayerClipperTest, LayoutSVGRootChild) {
  SetBodyInnerHTML(R"HTML(
    <svg width=200 height=300 style='position: relative'>
      <foreignObject width=400 height=500>
        <div id=target xmlns='http://www.w3.org/1999/xhtml'
    style='position: relative'></div>
      </foreignObject>
    </svg>
  )HTML");

  PaintLayer* target_paint_layer = GetPaintLayerByElementId("target");
  ClipRectsContext context(GetDocument().GetLayoutView()->Layer(),
                           &GetDocument().GetLayoutView()->FirstFragment());
  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  target_paint_layer->Clipper().CalculateRects(
      context, target_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);
  EXPECT_EQ(PhysicalRect(8, 8, 200, 300), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(8, 8, 200, 300), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(8, 8), layer_offset);
}

TEST_F(PaintLayerClipperTest, ContainPaintClip) {
  SetBodyInnerHTML(R"HTML(
    <div id='target'
        style='contain: paint; width: 200px; height: 200px; overflow: auto'>
      <div style='height: 400px'></div>
    </div>
  )HTML");

  PaintLayer* layer = GetPaintLayerByElementId("target");
  ClipRectsContext context(layer, &layer->GetLayoutObject().FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip);
  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  layer->Clipper().CalculateRects(
      context, layer->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);
  EXPECT_TRUE(background_rect.IsInfinite()) << background_rect;
  EXPECT_EQ(background_rect.Rect(), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(), layer_offset);

  ClipRectsContext context_clip(layer,
                                &layer->GetLayoutObject().FirstFragment());

  layer->Clipper().CalculateRects(
      context_clip, layer->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);
  EXPECT_EQ(PhysicalRect(0, 0, 200, 200), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(0, 0, 200, 200), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(), layer_offset);
}

TEST_F(PaintLayerClipperTest, NestedContainPaintClip) {
  SetBodyInnerHTML(R"HTML(
    <div style='contain: paint; width: 200px; height: 200px; overflow:
    auto'>
      <div id='target' style='contain: paint; height: 400px'>
      </div>
    </div>
  )HTML");

  PaintLayer* layer = GetPaintLayerByElementId("target");
  ClipRectsContext context(layer->Parent(),
                           &layer->Parent()->GetLayoutObject().FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip);
  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  layer->Clipper().CalculateRects(
      context, layer->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);
  EXPECT_EQ(PhysicalRect(0, 0, 200, 400), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(0, 0, 200, 400), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(), layer_offset);

  ClipRectsContext context_clip(
      layer->Parent(), &layer->Parent()->GetLayoutObject().FirstFragment());

  layer->Clipper().CalculateRects(
      context_clip, layer->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);
  EXPECT_EQ(PhysicalRect(0, 0, 200, 200), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(0, 0, 200, 200), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(), layer_offset);
}

TEST_F(PaintLayerClipperTest, CSSClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        width: 400px; height: 400px; position: absolute;
        clip: rect(0, 50px, 100px, 0);
        clip-path: inset(0%);
      }
    </style>
    <div id='target'></div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");
  ClipRectsContext context(target, &target->GetLayoutObject().FirstFragment());
  PhysicalRect infinite_rect(InfiniteIntRect());
  PhysicalOffset layer_offset = infinite_rect.offset;
  ClipRect background_rect(infinite_rect);
  ClipRect foreground_rect(infinite_rect);
  target->Clipper().CalculateRects(
      context, target->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);

  EXPECT_EQ(PhysicalRect(0, 0, 50, 100), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(0, 0, 50, 100), foreground_rect.Rect());
}

TEST_F(PaintLayerClipperTest, Filter) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0 }
      #target {
        filter: drop-shadow(0 3px 4px #333); overflow: hidden;
        width: 100px; height: 200px; border: 40px solid blue; margin: 50px;
      }
    </style>
    <div id='target'></div>
  )HTML");

  PaintLayer* target = GetPaintLayerByElementId("target");

  // First test clip rects in the target layer itself.
  ClipRectsContext context(target, &target->GetLayoutObject().FirstFragment());
  PhysicalRect infinite_rect(InfiniteIntRect());
  PhysicalOffset layer_offset = infinite_rect.offset;
  ClipRect background_rect(infinite_rect);
  ClipRect foreground_rect(infinite_rect);
  target->Clipper().CalculateRects(
      context, target->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);

  // The background rect is used to clip stacking context (layer) output.
  // In this case, nothing is above us, thus the infinite rect. However we do
  // clip to the layer's after-filter visual rect as an optimization.
  EXPECT_EQ(PhysicalRect(-12, -9, 204, 304), background_rect.Rect());
  // The foreground rect is used to clip the normal flow contents of the
  // stacking context (layer) thus including the overflow clip.
  EXPECT_EQ(PhysicalRect(40, 40, 100, 200), foreground_rect.Rect());

  // Test mapping to the root layer.
  ClipRectsContext root_context(GetLayoutView().Layer(),
                                &GetLayoutView().FirstFragment());
  background_rect = infinite_rect;
  foreground_rect = infinite_rect;
  target->Clipper().CalculateRects(
      root_context, target->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);
  // This includes the filter effect because it's applied before mapping the
  // background rect to the root layer.
  EXPECT_EQ(PhysicalRect(38, 41, 204, 304), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(90, 90, 100, 200), foreground_rect.Rect());
}

TEST_F(PaintLayerClipperTest, IgnoreRootLayerClipWithCSSClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #root {
        width: 400px; height: 400px;
        position: absolute; clip: rect(0, 50px, 100px, 0);
      }
      #target {
        position: relative;
      }
    </style>
    <div id='root'>
      <div id='target'></div>
    </div>
  )HTML");

  PaintLayer* root = GetPaintLayerByElementId("root");
  PaintLayer* target = GetPaintLayerByElementId("target");
  ClipRectsContext context(root, &root->GetLayoutObject().FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip);
  PhysicalRect infinite_rect(InfiniteIntRect());
  PhysicalOffset layer_offset = infinite_rect.offset;
  ClipRect background_rect(infinite_rect);
  ClipRect foreground_rect(infinite_rect);
  target->Clipper().CalculateRects(
      context, target->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);

  EXPECT_TRUE(background_rect.IsInfinite());
  EXPECT_TRUE(foreground_rect.IsInfinite());
}

TEST_F(PaintLayerClipperTest, IgnoreRootLayerClipWithOverflowClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #root {
        width: 400px; height: 400px;
        overflow: hidden;
      }
      #target {
        position: relative;
      }
    </style>
    <div id='root'>
      <div id='target'></div>
    </div>
  )HTML");

  PaintLayer* root = GetPaintLayerByElementId("root");
  PaintLayer* target = GetPaintLayerByElementId("target");
  ClipRectsContext context(root, &root->GetLayoutObject().FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip);
  PhysicalOffset layer_offset(InfiniteIntRect().origin());
  ClipRect background_rect;
  ClipRect foreground_rect;
  target->Clipper().CalculateRects(
      context, target->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);

  EXPECT_TRUE(background_rect.IsInfinite());
  EXPECT_TRUE(foreground_rect.IsInfinite());
}

TEST_F(PaintLayerClipperTest, IgnoreRootLayerClipWithBothClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #root {
        width: 400px; height: 400px;
        position: absolute; clip: rect(0, 50px, 100px, 0);
        overflow: hidden;
      }
      #target {
        position: relative;
      }
    </style>
    <div id='root'>
      <div id='target'></div>
    </div>
  )HTML");

  PaintLayer* root = GetPaintLayerByElementId("root");
  PaintLayer* target = GetPaintLayerByElementId("target");
  ClipRectsContext context(root, &root->GetLayoutObject().FirstFragment(),
                           kIgnoreOverlayScrollbarSize, kIgnoreOverflowClip);
  PhysicalRect infinite_rect(InfiniteIntRect());
  PhysicalOffset layer_offset = infinite_rect.offset;
  ClipRect background_rect(infinite_rect);
  ClipRect foreground_rect(infinite_rect);
  target->Clipper().CalculateRects(
      context, target->GetLayoutObject().FirstFragment(), layer_offset,
      background_rect, foreground_rect);

  EXPECT_TRUE(background_rect.IsInfinite());
  EXPECT_TRUE(foreground_rect.IsInfinite());
}

TEST_F(PaintLayerClipperTest, Fragmentation) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id=root style='position: relative; width: 200px; height: 100px;
                        columns: 2; column-gap: 0'>
      <div id=target style='width: 100px; height: 200px;
          background: lightblue; position: relative'>
      </div
    </div>
  )HTML");

  PaintLayer* root_paint_layer = GetPaintLayerByElementId("root");
  ClipRectsContext context(root_paint_layer,
                           &root_paint_layer->GetLayoutObject().FirstFragment(),
                           kIgnoreOverlayScrollbarSize);
  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;

  PaintLayer* target_paint_layer = GetPaintLayerByElementId("target");
  FragmentDataIterator iterator(target_paint_layer->GetLayoutObject());
  ASSERT_TRUE(iterator.Advance());
  const FragmentData* second_fragment = iterator.GetFragmentData();
  EXPECT_FALSE(iterator.Advance());

  target_paint_layer->Clipper().CalculateRects(
      context, target_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);

  EXPECT_TRUE(background_rect.IsInfinite());
  EXPECT_TRUE(foreground_rect.IsInfinite());
  EXPECT_EQ(PhysicalOffset(), layer_offset);

  target_paint_layer->Clipper().CalculateRects(context, *second_fragment,
                                               layer_offset, background_rect,
                                               foreground_rect);

  EXPECT_TRUE(background_rect.IsInfinite());
  EXPECT_TRUE(foreground_rect.IsInfinite());
  EXPECT_EQ(PhysicalOffset(100, 0), layer_offset);
}

TEST_F(PaintLayerClipperTest, ScrollbarClipBehaviorChild) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id='parent' style='position:absolute; width: 200px; height: 300px;
        overflow: scroll;'>
      <div id='child' style='position: relative; width: 500px;
           height: 500px'>
      </div>
    </div>
  )HTML");

  PaintLayer* parent_paint_layer = GetPaintLayerByElementId("parent");
  PaintLayer* child_paint_layer = GetPaintLayerByElementId("child");
  parent_paint_layer->GetScrollableArea()->SetScrollbarsHiddenIfOverlay(false);
  UpdateAllLifecyclePhasesForTest();

  ClipRectsContext context(
      parent_paint_layer,
      &parent_paint_layer->GetLayoutObject().FirstFragment(),
      kExcludeOverlayScrollbarSizeForHitTesting);

  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;
  child_paint_layer->Clipper().CalculateRects(
      context, child_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);

  // The background and foreground rect are clipped by the scrollbar size.
  EXPECT_EQ(PhysicalRect(0, 0, 193, 293), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(0, 0, 193, 293), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(), layer_offset);
}

TEST_F(PaintLayerClipperTest, ScrollbarClipBehaviorChildScrollBetween) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id='parent' style='position:absolute; width: 200px; height: 300px;
        overflow: scroll;'>
      <div id='child' style='position: relative; width: 500px;
           height: 500px'>
      </div>
    </div>
  )HTML");

  Element* parent = GetDocument().getElementById(AtomicString("parent"));
  PaintLayer* root_paint_layer = parent->GetLayoutObject()->View()->Layer();
  PaintLayer* child_paint_layer = GetPaintLayerByElementId("child");
  parent->GetLayoutBox()->GetScrollableArea()->SetScrollbarsHiddenIfOverlay(
      false);
  UpdateAllLifecyclePhasesForTest();

  ClipRectsContext context(root_paint_layer,
                           &root_paint_layer->GetLayoutObject().FirstFragment(),
                           kExcludeOverlayScrollbarSizeForHitTesting);

  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;
  child_paint_layer->Clipper().CalculateRects(
      context, child_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);

  // The background and foreground rect are clipped by the scrollbar size.
  EXPECT_EQ(PhysicalRect(8, 8, 193, 293), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(8, 8, 193, 293), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(8, 8), layer_offset);
}

TEST_F(PaintLayerClipperTest, ScrollbarClipBehaviorParent) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id='parent' style='position:absolute; width: 200px; height: 300px;
        overflow: scroll;'>
      <div id='child' style='position: relative; width: 500px;
           height: 500px'>
      </div>
    </div>
  )HTML");

  PaintLayer* parent_paint_layer = GetPaintLayerByElementId("parent");
  parent_paint_layer->GetScrollableArea()->SetScrollbarsHiddenIfOverlay(false);
  UpdateAllLifecyclePhasesForTest();

  ClipRectsContext context(
      parent_paint_layer,
      &parent_paint_layer->GetLayoutObject().FirstFragment(),
      kExcludeOverlayScrollbarSizeForHitTesting);

  PhysicalOffset layer_offset;
  ClipRect background_rect, foreground_rect;
  parent_paint_layer->Clipper().CalculateRects(
      context, parent_paint_layer->GetLayoutObject().FirstFragment(),
      layer_offset, background_rect, foreground_rect);

  // Only the foreground is clipped by the scrollbar size, because we
  // called CalculateRects on the root layer.
  EXPECT_EQ(PhysicalRect(0, 0, 200, 300), background_rect.Rect());
  EXPECT_EQ(PhysicalRect(0, 0, 193, 293), foreground_rect.Rect());
  EXPECT_EQ(PhysicalOffset(), layer_offset);
}

}  // namespace blink

"""

```