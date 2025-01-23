Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine test file. Specifically, they are interested in:

1. A summary of the file's purpose.
2. Connections to web technologies like JavaScript, HTML, and CSS, with examples.
3. Logical inferences with example inputs and outputs.
4. Common user or programming errors the code might relate to.
5. How a user's actions could lead to this code being executed (debugging clues).
6. A final overall summary of the file's purpose, building on the first part's analysis.

Let's break down the code snippet and address each of these points.

**Code Analysis:**

The code consists of several test cases (using `TEST_P` and `TEST_F`) within a C++ testing framework. Each test case focuses on specific scenarios related to paint and raster invalidation within the Blink rendering engine. The tests generally involve:

*   Setting up a simple HTML structure using `SetBodyInnerHTML`.
*   Manipulating the DOM (Document Object Model) using methods like `getElementById`, `setAttribute`, and setting inline styles.
*   Updating the rendering lifecycle using `UpdateAllLifecyclePhasesForTest` and `UpdateAllLifecyclePhasesExceptPaint`.
*   Asserting conditions about paint invalidation, raster invalidation, and layer properties using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and `EXPECT_THAT`.
*   Tracking raster invalidations using `GetDocument().View()->SetTracksRasterInvalidations(true)` and checking the results with `GetRasterInvalidationTracking()->Invalidations()`.

**Connecting to Web Technologies:**

*   **HTML:** The `SetBodyInnerHTML` function directly manipulates the HTML structure of the document being tested. The tests often target specific HTML elements using their IDs. Examples include the use of `<div>`, `<style>`, `<svg>`, `<rect>`, `<mask>`, and `<clipPath>` elements.
*   **CSS:**  The tests modify CSS styles, both inline (using `setAttribute('style', ...)`) and through CSS rules defined within `<style>` tags. They examine how changes to CSS properties like `transform`, `opacity`, `visibility`, `background-image`, `overflow`, `position: sticky`, and `clip-path` trigger (or don't trigger) paint and raster invalidations.
*   **JavaScript:** While there's no explicit JavaScript code within this snippet, the actions performed by the C++ code simulate the effects of JavaScript manipulating the DOM and CSS. For example, `container->setAttribute(html_names::kStyleAttr, AtomicString("transform: translateY(1000px);"));` is analogous to a JavaScript operation like `document.getElementById('container').style.transform = 'translateY(1000px)';`. Similarly, scrolling using `GetDocument().domWindow()->scrollTo(0, 4000);` mimics JavaScript's `window.scrollTo()`.

**Logical Inferences with Examples:**

Let's take the `RecalcOverflowInvalidatesBackground` test as an example:

*   **Hypothesis:** Changing a style that affects overflow (without a full layout) might require a paint invalidation because newly scrollable areas could reveal background content.
*   **Input:** An HTML structure with a container having `will-change: transform` and initial dimensions filling the viewport. The container's `transform` style is then changed to shift it down, making more content scrollable.
*   **Output:**  `scrollable_area->MaximumScrollOffset().y()` becomes 1000 (the amount of the transform), and `GetDocument().GetLayoutView()->ShouldCheckForPaintInvalidation()` becomes `true`.

**Common User or Programming Errors:**

*   **Incorrect understanding of paint invalidation triggers:** A developer might assume that certain style changes are cheap and won't cause repaints, leading to performance issues. For example, constantly changing `transform` values on an element without understanding the implications for raster invalidation. The tests help verify these assumptions.
*   **Unexpected repaint behavior after DOM manipulation:**  A developer might change an element's attributes or styles and be surprised by the amount of repainting that occurs. These tests explore various scenarios to make the repaint behavior predictable.
*   **Over-reliance on `will-change`:**  While `will-change` can be a performance optimization, misusing it (e.g., applying it to too many elements) can actually hinder performance. The tests involving `will-change` help ensure it's working as intended.

**User Operations and Debugging Clues:**

A user's actions that could lead to this code being relevant during debugging include:

1. **Scrolling:**  The `DelayedFullPaintInvalidation` and `ScrollingInvalidatesStickyOffset` tests relate to scrolling behavior and how it triggers paint invalidation. If a user reports visual glitches or performance problems during scrolling, these tests provide insights.
2. **Applying CSS styles (through author stylesheets or developer tools):**  Many tests focus on how CSS changes affect paint invalidation. If a user reports that a specific style change causes unexpected repainting, tests like `RecalcOverflowInvalidatesBackground`, `PaintPropertyChange`, and `VisibilityChange` are relevant.
3. **Interacting with SVG elements:** Tests like `SVGHiddenContainer` and `SVGWithFilterNoOpStyleUpdate` are relevant when debugging issues related to SVG rendering and how changes to SVG attributes or styles trigger repaints.
4. **Resizing elements:** The `ResizeContainerOfFixedSizeSVG` and `ResizeElementWhichHasNonCustomResizer` tests cover resizing scenarios. If a user encounters rendering problems when resizing elements, these tests can offer guidance.
5. **Hovering over scrollbars:** The `RepaintScrollbarThumbOnHover` test deals with scrollbar rendering. Issues related to scrollbar appearance could point to this area.
6. **Dynamic changes to image sources (especially animated GIFs):** The `DelayedInvalidationImageChangedFromAnimatedToStatic` test handles scenarios where image sources change. Problems with image updates might relate to this logic.

**Overall Summary (Part 2):**

This second part of the `paint_and_raster_invalidation_test.cc` file continues to rigorously test the paint and raster invalidation mechanisms within the Blink rendering engine. It focuses on more complex scenarios, including:

*   **Overflow changes:** Ensuring that changes affecting scrollable areas correctly trigger paint invalidation.
*   **Delayed paint invalidation:**  Verifying the logic for optimizing paint invalidation, especially when dealing with elements that might not be immediately visible.
*   **SVG-specific scenarios:** Testing paint invalidation behavior for SVG elements, including masking and filters.
*   **Paint property changes:**  Examining how changes to paint properties (like transforms) trigger raster invalidation.
*   **Resizing behavior:** Analyzing how resizing elements, including those containing SVGs or having resizers, affects paint invalidation.
*   **Sticky positioning:**  Confirming that scrolling correctly updates the paint properties of sticky elements.
*   **Floating-point precision:**  Testing for potential issues caused by floating-point inaccuracies in transformations.
*   **Visibility changes:**  Ensuring that hiding and showing elements triggers the appropriate invalidations.
*   **Image source changes:**  Specifically testing the case where an animated image is replaced with a static one.
*   **Scrollbar repainting:**  Verifying that scrollbar thumb hovering triggers a repaint.
*   **Optimization for clip paths:** Testing an optimization to avoid unnecessary full paint invalidations when styling elements with clip paths.
*   **Invalidation through ChromeClient:**  Testing scenarios where invalidations are communicated through the `ChromeClient` interface, which is relevant for non-composited rendering.

In essence, this part of the test file delves deeper into nuanced paint and raster invalidation scenarios, covering a wider range of CSS properties, HTML elements, and user interactions. It ensures that Blink's rendering engine correctly and efficiently identifies what needs to be repainted and re-rasterized when visual changes occur.

这是`blink/renderer/core/paint/paint_and_raster_invalidation_test.cc`文件的第二部分，延续了第一部分的功能，即**测试Blink渲染引擎中关于绘制和栅格化失效的机制**。

它通过一系列的单元测试来验证在不同的场景下，哪些元素会被标记为需要重绘（paint invalidation）或重新栅格化（raster invalidation）。这些测试覆盖了各种DOM操作、样式更改和用户交互，旨在确保Blink的失效机制能够正确高效地工作。

**归纳一下它的功能，可以概括为：**

1. **深入测试更复杂的失效场景：**  这部分测试相比第一部分，覆盖了更多细致和复杂的失效场景，例如：
    *   **`RecalcOverflowInvalidatesBackground`**:  测试当样式改变导致溢出区域变化时，背景是否会正确失效。
    *   **`DelayedFullPaintInvalidation`**:  测试延迟全量重绘失效的机制，用于优化性能。
    *   **`SVGHiddenContainer`**:  测试SVG中隐藏容器的失效行为。
    *   **`SVGWithFilterNoOpStyleUpdate`**:  测试当SVG滤镜存在但样式更新不影响其输出时，是否会产生不必要的失效。
    *   **`PaintPropertyChange`**:  测试修改绘制属性（如transform）如何触发失效。
    *   **`ResizeContainerOfFixedSizeSVG`**:  测试调整包含固定尺寸SVG的容器大小时的失效行为。
    *   **`ScrollingInvalidatesStickyOffset`**:  测试滚动如何使 `position: sticky` 元素的偏移失效。
    *   **`NoDamageDueToFloatingPointError`**:  测试避免因浮点误差导致不必要的失效。
    *   **`ResizeElementWhichHasNonCustomResizer`**:  测试调整带有默认尺寸调整器的元素大小时的失效情况。
    *   **`VisibilityChange`**:  测试元素可见性变化时的失效行为。
    *   **`DelayedInvalidationImageChangedFromAnimatedToStatic`**:  测试当动画图片变为静态图片时，延迟失效的机制。
    *   **`RepaintScrollbarThumbOnHover`**:  测试鼠标悬停在滚动条滑块上时是否会触发重绘。
    *   **`StyleChangesWithClipPathDoNotInvalidate`**:  测试带有 `clip-path` 的元素样式改变是否会触发不必要的全量重绘。
    *   **`NonCompositedInvalidationChangeOpacity` 和 `NoInvalidationRepeatedUpdateLifecyleExceptPaint`**:  针对非合成情况下的失效进行测试，并验证避免重复触发失效的机制。

2. **验证特定优化和边缘情况：**  这些测试不仅覆盖了基本的功能，还深入到了一些性能优化和边缘情况，例如延迟失效、带有 `clip-path` 元素的样式更改以及浮点误差的处理。

3. **模拟用户交互和DOM操作：**  测试代码通过设置HTML内容、修改元素属性和样式、模拟滚动等操作，来触发不同的渲染流程，并验证失效机制是否按预期工作。

4. **使用断言验证失效状态：**  每个测试用例都使用 `EXPECT_TRUE`、`EXPECT_FALSE` 和 `EXPECT_THAT` 等断言来检查特定的元素是否被标记为需要重绘或重新栅格化，以及失效的原因和区域是否正确。

**与 JavaScript, HTML, CSS 的关系以及举例说明：**

这些测试都围绕着网页的渲染过程，而 JavaScript、HTML 和 CSS 是构建网页的基础。

*   **HTML:** 测试用例通过 `SetBodyInnerHTML` 函数创建 HTML 结构，例如：
    ```c++
    SetBodyInnerHTML(R"HTML(
      <div id='container'></div>
    )HTML");
    ```
    这模拟了网页加载时 HTML 的解析和构建。测试会操作这些 HTML 元素，例如通过 ID 获取元素：
    ```c++
    Element* container = GetDocument().getElementById(AtomicString("container"));
    ```

*   **CSS:** 测试用例会修改元素的 CSS 样式，例如通过 `setAttribute` 设置 `style` 属性：
    ```c++
    container->setAttribute(html_names::kStyleAttr,
                            AtomicString("transform: translateY(1000px);"));
    ```
    或者通过 `<style>` 标签定义 CSS 规则。测试会验证样式更改如何触发失效，例如 `RecalcOverflowInvalidatesBackground` 测试中，修改 `transform` 可能会影响滚动区域，从而导致背景失效。

*   **JavaScript:** 虽然测试代码是用 C++ 编写的，但它模拟了 JavaScript 对 DOM 和 CSS 的操作。例如，`GetDocument().domWindow()->scrollTo(0, 4000);` 模拟了 JavaScript 代码 `window.scrollTo(0, 4000)` 的效果。测试验证了这些操作如何影响渲染失效。

**逻辑推理、假设输入与输出：**

以 `RecalcOverflowInvalidatesBackground` 测试为例：

*   **假设输入:** 一个 `div` 元素 (`#container`)，其 `will-change: transform;` 且初始时充满视口。
*   **操作:** 通过 JavaScript (模拟) 将 `#container` 的 `transform` 属性设置为 `translateY(1000px)`。
*   **逻辑推理:** 由于 `will-change: transform` 可能会创建新的合成层，改变 `transform` 不会触发布局。但是，`translateY` 的改变可能会使原本不可见的背景区域进入视口，因此需要触发重绘失效。
*   **预期输出:** `scrollable_area->MaximumScrollOffset().y()` 的值变为 `1000`，并且 `GetDocument().GetLayoutView()->ShouldCheckForPaintInvalidation()` 返回 `true`。

**用户或编程常见的使用错误举例说明：**

*   **错误地认为某些样式更改是“廉价的”：**  开发者可能认为修改 `transform` 或 `opacity` 等属性不会引起大的性能问题。但测试用例如 `PaintPropertyChange` 证明，即使是这些属性的改变，也可能触发栅格化失效，尤其是在有复杂图层结构的情况下。
*   **不理解 `will-change` 的作用和副作用：** 开发者可能滥用 `will-change`，认为它可以随意优化性能。但实际上，过度使用 `will-change` 会增加内存消耗。测试用例中对 `will-change` 的使用也在验证其预期行为。
*   **意外的重绘区域：** 开发者可能修改了一个元素的样式，但发现页面上其他不相关的区域也发生了重绘。测试用例帮助理解不同操作引起的失效范围，例如 `SVGHiddenContainer` 测试表明修改隐藏 SVG 容器的属性可能会影响到其相关的其他元素。

**用户操作是如何一步步的到达这里，作为调试线索：**

当用户进行以下操作时，可能会触发 Blink 渲染引擎的绘制和栅格化失效逻辑，而这些测试用例就是为了验证这些逻辑的正确性：

1. **滚动页面:** `ScrollingInvalidatesStickyOffset` 测试与滚动相关，当用户滚动页面时，`position: sticky` 元素的偏移会发生变化，触发重绘。
2. **修改元素的 CSS 样式 (通过开发者工具或 JavaScript):** 许多测试用例都模拟了修改 CSS 属性的情况，例如改变 `transform`、`visibility`、`opacity` 等。用户在开发者工具中修改样式或 JavaScript 代码动态修改样式都可能触发这些失效逻辑。
3. **调整浏览器窗口大小:** `ResizeContainerOfFixedSizeSVG` 和 `ResizeElementWhichHasNonCustomResizer` 测试了调整窗口大小时的失效情况。
4. **与 SVG 元素交互:** `SVGHiddenContainer` 和 `SVGWithFilterNoOpStyleUpdate` 测试了与 SVG 元素相关的操作，例如修改 SVG 元素的属性。
5. **鼠标悬停在元素上:** `RepaintScrollbarThumbOnHover` 测试了鼠标悬停在滚动条上的情况。
6. **动态加载图片或改变图片源:** `DelayedInvalidationImageChangedFromAnimatedToStatic` 测试了图片资源变化的情况。

作为调试线索，当开发者遇到以下问题时，可以参考这些测试用例来理解失效机制：

*   **页面渲染性能问题:**  频繁的重绘或重新栅格化会导致页面卡顿。开发者可以参考这些测试用例，分析哪些操作会触发昂贵的失效，并尝试优化。
*   **视觉渲染错误:**  某些元素没有正确地重绘或重新栅格化，导致显示不正确。开发者可以参考这些测试用例，检查失效机制是否按预期工作。
*   **内存泄漏或资源占用过高:** 不必要的失效可能导致资源浪费。开发者可以参考这些测试用例，找出可能导致过度失效的原因。

总而言之，这部分测试用例是 Blink 渲染引擎的重要组成部分，它确保了渲染失效机制的正确性和效率，从而保证了网页的正常渲染和性能表现。开发者可以通过研究这些测试用例，更深入地理解浏览器的渲染原理。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_and_raster_invalidation_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
fo{
                  client.Id(), client.DebugName(), gfx::Rect(50, 0, 50, 500),
                  PaintInvalidationReason::kIncremental}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

// Changing style in a way that changes overflow without layout should cause
// the layout view to possibly need a paint invalidation since we may have
// revealed additional background that can be scrolled into view.
TEST_P(PaintAndRasterInvalidationTest, RecalcOverflowInvalidatesBackground) {
  GetDocument().GetPage()->GetSettings().SetViewportEnabled(true);
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style type='text/css'>
      body, html {
        width: 100%;
        height: 100%;
        margin: 0px;
      }
      #container {
        will-change: transform;
        width: 100%;
        height: 100%;
      }
    </style>
    <div id='container'></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  ScrollableArea* scrollable_area = GetDocument().View()->LayoutViewport();
  ASSERT_EQ(scrollable_area->MaximumScrollOffset().y(), 0);
  EXPECT_FALSE(
      GetDocument().GetLayoutView()->ShouldCheckForPaintInvalidation());

  Element* container = GetDocument().getElementById(AtomicString("container"));
  container->setAttribute(html_names::kStyleAttr,
                          AtomicString("transform: translateY(1000px);"));
  GetDocument().UpdateStyleAndLayoutTree();

  EXPECT_EQ(scrollable_area->MaximumScrollOffset().y(), 1000);
  EXPECT_TRUE(GetDocument().GetLayoutView()->ShouldCheckForPaintInvalidation());
}

TEST_P(PaintAndRasterInvalidationTest, DelayedFullPaintInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div style='height: 4000px'></div>
    <div id='target' style='width: 100px; height: 100px; background: blue'>
    </div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  target->SetShouldDoFullPaintInvalidationWithoutLayoutChange(
      PaintInvalidationReason::kStyle);
  target->SetShouldDelayFullPaintInvalidation();
  EXPECT_FALSE(target->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(target->ShouldDelayFullPaintInvalidation());
  EXPECT_EQ(PaintInvalidationReason::kStyle,
            target->PaintInvalidationReasonForPrePaint());
  EXPECT_FALSE(target->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(target->ShouldCheckForPaintInvalidation());
  EXPECT_TRUE(target->Parent()->ShouldCheckForPaintInvalidation());

  GetDocument().View()->SetTracksRasterInvalidations(true);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetRasterInvalidationTracking()->HasInvalidations());
  EXPECT_FALSE(target->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(target->ShouldDelayFullPaintInvalidation());
  EXPECT_EQ(PaintInvalidationReason::kStyle,
            target->PaintInvalidationReasonForPrePaint());
  EXPECT_FALSE(target->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(target->ShouldCheckForPaintInvalidation());
  EXPECT_TRUE(target->Parent()->ShouldCheckForPaintInvalidation());
  GetDocument().View()->SetTracksRasterInvalidations(false);

  GetDocument().View()->SetTracksRasterInvalidations(true);
  // Scroll target into view.
  GetDocument().domWindow()->scrollTo(0, 4000);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(RasterInvalidationInfo{
          target->Id(), target->DebugName(), gfx::Rect(0, 4000, 100, 100),
          PaintInvalidationReason::kStyle}));
  EXPECT_EQ(PaintInvalidationReason::kNone,
            target->PaintInvalidationReasonForPrePaint());
  EXPECT_FALSE(target->ShouldDelayFullPaintInvalidation());
  EXPECT_FALSE(target->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(target->Parent()->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(target->ShouldCheckLayoutForPaintInvalidation());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, SVGHiddenContainer) {
  SetBodyInnerHTML(R"HTML(
    <svg style='position: absolute; top: 100px; left: 100px'>
      <mask id='mask'>
        <g transform='scale(2)'>
          <rect id='mask-rect' x='11' y='22' width='33' height='44'/>
        </g>
      </mask>
      <rect id='real-rect' x='55' y='66' width='7' height='8'
          mask='url(#mask)'/>
    </svg>
  )HTML");

  auto* mask_rect = GetLayoutObjectByElementId("mask-rect");
  auto* real_rect = GetLayoutObjectByElementId("real-rect");

  GetDocument().View()->SetTracksRasterInvalidations(true);
  To<Element>(mask_rect->GetNode())
      ->setAttribute(svg_names::kXAttr, AtomicString("20"));
  UpdateAllLifecyclePhasesForTest();

  // Should invalidate raster for real_rect only.
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(
          RasterInvalidationInfo{real_rect->Id(), real_rect->DebugName(),
                                 gfx::Rect(155, 166, 7, 8),
                                 PaintInvalidationReason::kImage},
          RasterInvalidationInfo{real_rect->Id(), real_rect->DebugName(),
                                 gfx::Rect(154, 165, 9, 10),
                                 PaintInvalidationReason::kImage}));

  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, SVGWithFilterNoOpStyleUpdate) {
  SetBodyInnerHTML(R"HTML(
    <svg>
      <filter id="f">
        <feGaussianBlur stdDeviation="5"/>
      </filter>
      <rect width="100" height="100" style="filter: url(#f)"/>
    </svg>
  )HTML");

  GetDocument().View()->SetTracksRasterInvalidations(true);
  GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                     AtomicString("--x: 42"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(GetRasterInvalidationTracking()->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, PaintPropertyChange) {
  SetUpHTML(*this);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutObject();
  target->setAttribute(html_names::kClassAttr, AtomicString("solid transform"));
  UpdateAllLifecyclePhasesForTest();

  auto* layer = To<LayoutBoxModelObject>(object)->Layer();
  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("transform: scale(3)"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(layer->SelfNeedsRepaint());
  const auto* transform =
      object->FirstFragment().PaintProperties()->Transform();
  EXPECT_TRUE(transform->Changed(
      PaintPropertyChangeType::kChangedOnlySimpleValues, *transform->Parent()));

  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(
          RasterInvalidationInfo{layer->Id(), layer->DebugName(),
                                 gfx::Rect(0, 0, 100, 200),
                                 PaintInvalidationReason::kPaintProperty},
          RasterInvalidationInfo{layer->Id(), layer->DebugName(),
                                 gfx::Rect(0, 0, 150, 300),
                                 PaintInvalidationReason::kPaintProperty}));
  EXPECT_FALSE(transform->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                  *transform->Parent()));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, ResizeContainerOfFixedSizeSVG) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="width: 100px; height: 100px">
      <svg viewBox="0 0 200 200" width="100" height="100">
        <rect id="rect" width="100%" height="100%"/>
      </svg>
    </div>
  )HTML");

  Element* target = GetDocument().getElementById(AtomicString("target"));
  LayoutObject* rect = GetLayoutObjectByElementId("rect");
  EXPECT_TRUE(static_cast<const DisplayItemClient*>(rect)->IsValid());

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("width: 200px; height: 200px"));
  UpdateAllLifecyclePhasesExceptPaint();

  // We don't invalidate paint of the SVG rect.
  EXPECT_TRUE(static_cast<const DisplayItemClient*>(rect)->IsValid());

  UpdateAllLifecyclePhasesForTest();
  // No raster invalidations because the resized-div doesn't paint anything by
  // itself, and the svg is fixed sized.
  EXPECT_FALSE(GetRasterInvalidationTracking()->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, ScrollingInvalidatesStickyOffset) {
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="width:300px; height:200px; overflow:scroll">
      <div id="sticky" style="position:sticky; top:50px;
          width:50px; height:100px; background:red;">
        <div id="inner" style="width:100px; height:50px; background:red;">
        </div>
      </div>
      <div style="height:1000px;"></div>
    </div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->setScrollTop(100);

  const auto* sticky = GetLayoutObjectByElementId("sticky");
  EXPECT_TRUE(sticky->NeedsPaintPropertyUpdate());
  EXPECT_EQ(PhysicalOffset(), sticky->FirstFragment().PaintOffset());
  EXPECT_EQ(gfx::Vector2dF(0, 50), sticky->FirstFragment()
                                       .PaintProperties()
                                       ->StickyTranslation()
                                       ->Get2dTranslation());
  const auto* inner = GetLayoutObjectByElementId("inner");
  EXPECT_EQ(PhysicalOffset(), inner->FirstFragment().PaintOffset());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(sticky->NeedsPaintPropertyUpdate());
  EXPECT_EQ(PhysicalOffset(), sticky->FirstFragment().PaintOffset());
  EXPECT_EQ(gfx::Vector2dF(0, 150), sticky->FirstFragment()
                                        .PaintProperties()
                                        ->StickyTranslation()
                                        ->Get2dTranslation());
  EXPECT_EQ(PhysicalOffset(), inner->FirstFragment().PaintOffset());
}

TEST_P(PaintAndRasterInvalidationTest, NoDamageDueToFloatingPointError) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #canvas {
          position: absolute;
          top: 0;
          left: 0;
          width: 0;
          height: 0;
          will-change: transform;
          transform-origin: top left;
          transform: scale(1.8);
        }
        #tile {
          position: absolute;
          will-change: transform;
          transform-origin: top left;
          transform: translateX(49px) translateY(100px) scale(0.555555555556);
        }
        #tileInner {
          transform-origin: top left;
          transform: scale(1.8);
          width: 200px;
          height: 200px;
          background: lightblue;
        }
      </style>
      <div id="canvas" class="initial">
        <div id="tile">
          <div id="tileInner"></div>
        </div>
      </div>
  )HTML");

  auto* canvas = GetDocument().getElementById(AtomicString("canvas"));
  for (double x = 0; x < 200; x += 1) {
    GetDocument().View()->SetTracksRasterInvalidations(true);
    canvas->setAttribute(
        html_names::kStyleAttr,
        AtomicString(String::Format("transform: translateX(%lfpx) scale(1.8)",
                                    x / 1.8)));
    UpdateAllLifecyclePhasesForTest();
    EXPECT_FALSE(GetRasterInvalidationTracking(0, "tile")->HasInvalidations());
    GetDocument().View()->SetTracksRasterInvalidations(false);
  }
}

TEST_P(PaintAndRasterInvalidationTest, ResizeElementWhichHasNonCustomResizer) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      * { margin: 0;}
      div {
        width: 100px;
        height: 100px;
        background-color: red;
        overflow: hidden;
        resize: both;
      }
    </style>
    <div id='target'></div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* object = target->GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);

  target->setAttribute(html_names::kStyleAttr, AtomicString("width: 200px"));
  UpdateAllLifecyclePhasesForTest();

  Vector<RasterInvalidationInfo> invalidations;
  // This is for DisplayItem::kResizerScrollHitTest.
  invalidations.push_back(RasterInvalidationInfo{
      object->Id(), object->DebugName(), gfx::Rect(100, 0, 100, 100),
      PaintInvalidationReason::kIncremental});
  const auto& scroll_corner = To<LayoutBoxModelObject>(object)
                                  ->GetScrollableArea()
                                  ->GetScrollCornerDisplayItemClient();
  invalidations.push_back(RasterInvalidationInfo{
      scroll_corner.Id(), scroll_corner.DebugName(), gfx::Rect(93, 93, 7, 7),
      PaintInvalidationReason::kLayout});
  invalidations.push_back(RasterInvalidationInfo{
      scroll_corner.Id(), scroll_corner.DebugName(), gfx::Rect(193, 93, 7, 7),
      PaintInvalidationReason::kLayout});
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAreArray(invalidations));

  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, VisibilityChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
      /* Make the view not solid color so that we can track raster
         invalidations. */
      body { background: linear-gradient(red, blue); }
      #target { width: 100px; height: 100px; background: blue; }
    </style>
    <div id="target"></div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  const DisplayItemClient* client = target->GetLayoutObject();

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("visibility: hidden"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  client->Id(), client->DebugName(), gfx::Rect(8, 8, 100, 100),
                  PaintInvalidationReason::kDisappeared}));
  GetDocument().View()->SetTracksRasterInvalidations(false);

  GetDocument().View()->SetTracksRasterInvalidations(true);
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("visibility: visible"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(GetRasterInvalidationTracking()->Invalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  client->Id(), client->DebugName(), gfx::Rect(8, 8, 100, 100),
                  PaintInvalidationReason::kAppeared}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest,
       DelayedInvalidationImageChangedFromAnimatedToStatic) {
  const String kStaticImage =
      "data:image/"
      "png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQMAAAAl21bKAAAAA1BMVEUA/"
      "wA0XsCoAAAACklEQVQIHWNgAAAAAgABz8g15QAAAABJRU5ErkJggg==";
  SetBodyInnerHTML(R"HTML(
    <div id="spacer" style="background-image:
      url()HTML" + kStaticImage +
                   R"HTML()">
    </div>
    <div style="height: 2250px"></div>
    <div id="target" style="
      background-image: url(data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==);
      width: 100px;
      height: 100px">
    </div>
  )HTML");

  auto* target_element = GetElementById("target");
  auto* spacer_element = GetElementById("spacer");
  auto* target = GetLayoutObjectByElementId("target");
  EXPECT_FALSE(target->ShouldDelayFullPaintInvalidation());

  // Simulate an image change notification on #target.
  auto* anim_background_image =
      target->StyleRef().BackgroundLayers().GetImage();
  ASSERT_TRUE(anim_background_image);
  auto* anim_image_resource_content = anim_background_image->CachedImage();
  ASSERT_TRUE(anim_image_resource_content);
  ASSERT_TRUE(anim_image_resource_content->GetImage()->MaybeAnimated());
  static_cast<ImageObserver*>(anim_image_resource_content)
      ->Changed(anim_image_resource_content->GetImage());
  EXPECT_TRUE(target->MayNeedPaintInvalidationAnimatedBackgroundImage());

  // Change the paint offset of #target to get a layout/geometry paint
  // invalidation reason.
  spacer_element->SetInlineStyleProperty(CSSPropertyID::kHeight, 100,
                                         CSSPrimitiveValue::UnitType::kPixels);

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(target->ShouldDelayFullPaintInvalidation());

  GetDocument().View()->SetTracksRasterInvalidations(true);

  // Update #target's style to point to a non-animated image.
  target_element->SetInlineStyleProperty(
      CSSPropertyID::kBackgroundImage,
      AtomicString("url(" + kStaticImage + ")"));

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(RasterInvalidationInfo{
          target->Id(), target->DebugName(), gfx::Rect(8, 2358, 100, 100),
          PaintInvalidationReason::kBackground}));
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

TEST_P(PaintAndRasterInvalidationTest, RepaintScrollbarThumbOnHover) {
  // In RasterInducingScroll the scrollbar is composited, not using blink
  // raster invalidation.
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    return;
  }

  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <style>body {margin: 0}</style>
    <div id="target" style="width: 100px; height: 100px; overflow-y: auto">
      <div style="height: 200px"></div>
    </div>
  )HTML");

  GetDocument().View()->SetTracksRasterInvalidations(true);
  Scrollbar* scrollbar = GetLayoutBoxByElementId("target")
                             ->GetScrollableArea()
                             ->VerticalScrollbar();
  scrollbar->SetHoveredPart(kThumbPart);
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_THAT(
      GetRasterInvalidationTracking()->Invalidations(),
      UnorderedElementsAre(RasterInvalidationInfo{
          scrollbar->Id(), scrollbar->DebugName(), scrollbar->FrameRect(),
          PaintInvalidationReason::kScrollControl}));
}

// This tests an optimization for motionmark suits, where changing styles of
// elements with a clip path should not, by itself, require a full paint
// invalidation. For example, transform changes can skip paint invalidation.
TEST_P(PaintAndRasterInvalidationTest,
       StyleChangesWithClipPathDoNotInvalidate) {
  SetBodyInnerHTML(R"HTML(
    <svg width='300' height='300'>
      <defs>
        <clipPath id='c' clipPathUnits='objectBoundingBox'>
          <rect />
        </clipPath>
      </defs>
      <rect id='rect'
          width='100'
          height='100'
          transform='translate(100,100)'
          clip-path='url(#c)' />
    </svg>
  )HTML");

  auto* rect = GetDocument().getElementById(AtomicString("rect"));
  EXPECT_FALSE(rect->GetLayoutObject()->ShouldDoFullPaintInvalidation());
  rect->setAttribute(svg_names::kTransformAttr,
                     AtomicString("translate(200,100)"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(rect->GetLayoutObject()->ShouldDoFullPaintInvalidation());
}

class PaintInvalidatorTestClient : public RenderingTestChromeClient {
 public:
  void InvalidateContainer() override { invalidation_recorded_ = true; }

  bool InvalidationRecorded() { return invalidation_recorded_; }

  void ResetInvalidationRecorded() { invalidation_recorded_ = false; }

 private:
  bool invalidation_recorded_ = false;
};

class PaintInvalidatorCustomClientTest : public RenderingTest {
 public:
  PaintInvalidatorCustomClientTest()
      : RenderingTest(MakeGarbageCollected<EmptyLocalFrameClient>()),
        chrome_client_(MakeGarbageCollected<PaintInvalidatorTestClient>()) {}

  PaintInvalidatorTestClient& GetChromeClient() const override {
    return *chrome_client_;
  }

  bool InvalidationRecorded() { return chrome_client_->InvalidationRecorded(); }

  void ResetInvalidationRecorded() {
    chrome_client_->ResetInvalidationRecorded();
  }

 private:
  Persistent<PaintInvalidatorTestClient> chrome_client_;
};

TEST_F(PaintInvalidatorCustomClientTest,
       NonCompositedInvalidationChangeOpacity) {
  // This test runs in a non-composited mode, so invalidations should
  // be issued via InvalidateChromeClient.
  SetBodyInnerHTML("<div id=target style='opacity: 0.99'></div>");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  ResetInvalidationRecorded();

  target->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.98"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(InvalidationRecorded());
}

TEST_F(PaintInvalidatorCustomClientTest,
       NoInvalidationRepeatedUpdateLifecyleExceptPaint) {
  SetBodyInnerHTML("<div id=target style='opacity: 0.99'></div>");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  ResetInvalidationRecorded();

  target->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.98"));
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  // Only paint property change doesn't need repaint.
  EXPECT_FALSE(
      GetDocument().View()->GetLayoutView()->Layer()->DescendantNeedsRepaint());
  // Just needs to invalidate the chrome client.
  EXPECT_TRUE(InvalidationRecorded());

  ResetInvalidationRecorded();
  // Let PrePaintTreeWalk do something instead of no-op, without any real
  // change.
  GetDocument().View()->SetNeedsPaintPropertyUpdate();
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(
      GetDocument().View()->GetLayoutView()->Layer()->DescendantNeedsRepaint());
  EXPECT_FALSE(InvalidationRecorded());
}

}  // namespace blink
```