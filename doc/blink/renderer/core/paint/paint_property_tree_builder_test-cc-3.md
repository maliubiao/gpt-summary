Response:
The user wants to understand the functionality of the `paint_property_tree_builder_test.cc` file in the Chromium Blink engine.

I need to explain what this file does, its relation to web technologies (JavaScript, HTML, CSS), provide examples with hypothetical inputs and outputs, illustrate common user errors, and detail how a user's action could lead to this code being executed during debugging.

This is part 4 of a 10-part explanation, so I should focus on summarizing the functionality based on the provided code snippet.

Based on the code, this file contains unit tests for the `PaintPropertyTreeBuilder`. The tests verify how the paint property tree is constructed for different CSS properties and HTML structures. It checks things like:

* **Positioning:** How `absolute`, `fixed`, and `relative` positioning affect the paint properties.
* **Clipping:** How `clip` and `overflow` properties interact.
* **Transforms:** How CSS `transform` affects the paint properties, including 2D and 3D transforms, and the concept of rendering contexts.
* **Paint Offsets:** How subpixel offsets and pixel snapping are handled.
* **Column Spanning:** How `column-span` affects paint properties.
* **Will-change and Animations:** How these properties impact the paint property tree, particularly regarding compositing and subpixel offsets.
* **SVG:** How paint properties are constructed for SVG elements, including pixel snapping.
* **Visual Rects:** Verifying the computed visual rectangles of elements.

In essence, this file tests the correctness of the logic that translates the HTML structure and CSS styles into a tree of paint properties, which is crucial for the rendering process in the browser.
这是 `blink/renderer/core/paint/paint_property_tree_builder_test.cc` 文件功能的第4部分归纳：

**功能归纳：**

这个文件主要包含了一系列的单元测试，用于验证 Blink 渲染引擎中 `PaintPropertyTreeBuilder` 类的功能是否正确。 `PaintPropertyTreeBuilder` 的作用是根据 HTML 结构和 CSS 样式，构建用于绘制的“绘制属性树”（Paint Property Tree）。这个树形结构优化了渲染流程，因为它将影响绘制的属性（如变换、裁剪、遮罩等）组织起来，使得渲染引擎可以更高效地进行绘制操作。

**具体来说，根据提供的代码片段，这个文件中的测试用例主要关注以下功能点：**

* **验证不同 CSS 定位 (position) 属性对绘制属性树的影响：**  测试了 `absolute` 和 `fixed` 定位元素及其祖先元素的裁剪 (clip) 属性的设置和继承关系，以及滚动偏移 (scroll translation) 的处理。
* **验证列跨越 (column-span) 属性在特定定位上下文中的行为：** 测试了 `column-span: all` 的元素在相对定位的父元素下的绘制偏移 (paint offset)。
* **验证处理亚像素 (fractional) 绘制偏移的能力：** 测试了元素通过 `left` 和 `top` 属性设置亚像素值时，绘制属性树中偏移量的精确计算。
* **验证像素对齐 (pixel snapping) 机制对绘制偏移的影响：**  测试了在应用 `transform: translateZ(0)` 等触发硬件加速的变换时，为了避免模糊，浏览器如何对元素的绘制位置进行像素对齐，以及这种对齐如何影响子元素的绘制偏移。测试了不同情况下（如存在非平移变换、`will-change: transform`、变换动画等）像素对齐机制是否会重置亚像素偏移。
* **验证嵌套的变换对像素对齐的影响：** 测试了多层嵌套的元素都应用了变换的情况下，像素对齐和绘制偏移的计算方式。
* **验证固定定位 (fixed position) 元素在像素对齐上下文中的行为：** 测试了固定定位元素及其子元素在父元素应用像素对齐时，绘制偏移的计算方式。
* **验证 SVG 元素的像素对齐和绘制偏移：** 测试了带有变换的 SVG 元素以及其内部元素的绘制属性树构建，特别是像素对齐的处理。
* **验证 SVG 根元素和 ForeignObject 的像素对齐：** 测试了 SVG 根元素和 ForeignObject 元素的绘制偏移计算，以及 ForeignObject 内子元素的偏移累积。
* **验证 `transform-style: preserve-3d` 属性创建共享渲染上下文的行为：**  测试了当父元素设置 `transform-style: preserve-3d` 时，具有 3D 变换的子元素是否会被分配到同一个渲染上下文 (rendering context)，以便进行正确的 3D 渲染。
* **验证阻止共享渲染上下文的中间元素：** 测试了在设置了 `transform-style: preserve-3d` 的父元素和具有 3D 变换的子元素之间，如果存在没有设置 `transform-style: preserve-3d` 的中间元素或者具有其他绘制属性的中间元素时，是否会阻止子元素共享父元素的渲染上下文。
* **验证 `transform-style: flat` 属性结束渲染上下文的行为：** 测试了即使父元素设置了 `transform-style: preserve-3d`，如果子元素设置了 `transform-style: flat`，那么该子元素不会参与到父元素的 3D 渲染上下文中。
* **验证嵌套渲染上下文的行为：** 测试了当嵌套的元素都设置了 `transform-style: preserve-3d` 和 3D 变换时，会创建独立的渲染上下文。
* **验证 `transform-style: flat` 属性对子元素的传递性：** 测试了当一个元素设置了 `transform-style: flat`，其子元素即使有 3D 变换也不会创建新的渲染上下文。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关联着 CSS 的视觉格式化模型和合成 (compositing) 机制。

* **CSS 属性：** 文件中的测试用例使用了大量的 CSS 属性，例如 `position`、`clip`、`overflow`、`transform`、`transform-style`、`left`、`top`、`column-span`、`will-change`、`animation` 等。测试的目标就是验证这些 CSS 属性如何影响最终的渲染结果。
* **HTML 结构：**  测试用例通过构建不同的 HTML 结构来模拟各种布局场景，例如嵌套的 `div` 元素、带有 `id` 属性的元素等。`PaintPropertyTreeBuilder` 需要根据 HTML 的层级关系来构建绘制属性树。
* **JavaScript (间接关系)：** 虽然这个测试文件本身是用 C++ 编写的，不包含 JavaScript 代码，但 JavaScript 可以动态地修改 HTML 结构和 CSS 样式。这些修改最终会触发重新布局和重新构建绘制属性树的过程。因此，`PaintPropertyTreeBuilder` 的正确性对于 JavaScript 操作 DOM 和 CSS 后的渲染结果至关重要。

**举例说明：**

**假设输入 (HTML & CSS):**

```html
<div style="position: relative; left: 10.5px; top: 20.3px;">
  <div style="transform: translateZ(0); width: 50px; height: 50px;"></div>
</div>
```

**逻辑推理与输出 (基于测试用例):**

测试用例 `PaintOffsetWithBasicPixelSnapping` 会验证上述场景。

* **推理：** 父元素相对定位，左偏移 10.5px，上偏移 20.3px。子元素应用了 `transform: translateZ(0)`，这会触发硬件加速和像素对齐。像素对齐会将子元素的绘制位置对齐到最近的整数像素边界。
* **预期输出 (绘制属性):** 子元素的 `PaintOffsetTranslation` 可能会被设置为 `(11, 20)` (向上或向下取整，具体取决于浏览器的实现细节)，而子元素的 `PaintOffset` 将会是剩余的亚像素偏移，例如 `(-0.5, 0.3)` 或 `(-0.5, -0.7)`。测试会断言这些属性的值是否符合预期。

**用户或编程常见的使用错误举例：**

* **误解像素对齐的影响：** 开发者可能期望元素正好定位在非整数像素位置，但由于像素对齐，实际渲染位置可能会有细微偏差，导致视觉上的不精确。例如，开发者设置 `left: 0.3px;`，但由于像素对齐，元素可能被渲染在 `left: 0px;` 或 `left: 1px;` 的位置。
* **过度使用 `transform: translateZ(0)`：**  开发者可能为了触发硬件加速而随意添加 `transform: translateZ(0)`，但没有意识到这可能会引入像素对齐，从而影响元素的亚像素定位。
* **对 `transform-style: preserve-3d` 的误用：**  开发者可能错误地认为只要设置了 `transform-style: preserve-3d`，所有子元素都会在 3D 空间中渲染，而忽略了中间元素或其他属性可能会阻止共享渲染上下文。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户打开一个网页：** 用户在浏览器中打开一个包含复杂 CSS 布局和动画的网页。
2. **页面渲染异常：** 网页的某些元素的位置、大小或者 3D 效果渲染不正确，例如出现模糊、抖动或者层叠错误。
3. **开发者使用开发者工具：** 开发者打开浏览器的开发者工具，检查元素的样式和布局。
4. **检查合成层 (Compositing Layers)：** 开发者可能会在 “Layers” 面板中查看页面的合成层结构，发现某些元素没有被提升为独立的合成层，或者合成层的组织结构不符合预期。
5. **怀疑绘制属性树构建错误：** 开发者可能会怀疑是渲染引擎在构建绘制属性树的过程中出现了错误，导致合成层的创建和属性设置不正确。
6. **查看 Blink 源代码：**  为了深入了解问题，开发者可能会查看 Blink 引擎的源代码，特别是与绘制和合成相关的部分，例如 `PaintPropertyTreeBuilder` 的代码。
7. **运行或调试测试用例：** 开发者可能会尝试运行 `paint_property_tree_builder_test.cc` 中的相关测试用例，或者设置断点来调试 `PaintPropertyTreeBuilder` 的构建过程，以便找出导致渲染异常的具体原因。例如，如果怀疑是 `transform-style: preserve-3d` 的问题，可能会重点关注 `Preserve3DCreatesSharedRenderingContext` 相关的测试用例。

总而言之，`paint_property_tree_builder_test.cc` 是一个关键的测试文件，用于确保 Blink 渲染引擎能够正确地将 HTML 和 CSS 转换为用于高效渲染的绘制属性树，这直接影响着用户最终看到的网页呈现效果。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
position: absolute;
        left: 123px;
        top: 456px;
        clip: rect(10px, 80px, 70px, 40px);
        width: 100px;
        height: 100px;
      }
      #fixed {
        position: fixed;
        left: 654px;
        top: 321px;
      }
    </style>
    <div id='overflow'><div id='clip'><div id='fixed'></div></div></div>
  )HTML");
  PhysicalRect local_clip_rect(40, 10, 40, 60);
  PhysicalRect absolute_clip_rect = local_clip_rect;
  absolute_clip_rect.offset += PhysicalOffset(123, 456);

  LayoutObject& overflow = *GetLayoutObjectByElementId("overflow");
  const ObjectPaintProperties* overflow_properties =
      overflow.FirstFragment().PaintProperties();
  EXPECT_EQ(DocContentClip(), overflow_properties->OverflowClip()->Parent());
  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            overflow_properties->ScrollTranslation()->Parent()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 50, 50), &overflow,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* clip = GetLayoutObjectByElementId("clip");
  const ObjectPaintProperties* clip_properties =
      clip->FirstFragment().PaintProperties();
  EXPECT_EQ(overflow_properties->OverflowClip(),
            clip_properties->CssClip()->Parent());
  EXPECT_EQ(overflow_properties->ScrollTranslation(),
            &clip_properties->CssClip()->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(gfx::RectF(absolute_clip_rect)),
                   clip_properties->CssClip());
  EXPECT_EQ(DocContentClip(),
            clip_properties->CssClipFixedPosition()->Parent());
  EXPECT_EQ(overflow_properties->ScrollTranslation(),
            &clip_properties->CssClipFixedPosition()->LocalTransformSpace());
  EXPECT_CLIP_RECT(FloatRoundedRect(gfx::RectF(absolute_clip_rect)),
                   clip_properties->CssClipFixedPosition());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(), clip,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* fixed = GetLayoutObjectByElementId("fixed");
  EXPECT_EQ(clip_properties->CssClipFixedPosition(),
            &fixed->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(fixed->FirstFragment().PaintProperties()->PaintOffsetTranslation(),
            &fixed->FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(PhysicalOffset(0, 0), fixed->FirstFragment().PaintOffset());
  CHECK_VISUAL_RECT(PhysicalRect(), fixed,
                    GetDocument().View()->GetLayoutView(),
                    // TODO(crbug.com/599939): CSS clip of fixed-position
                    // descendants is broken in geometry mapping.
                    LayoutUnit::Max());
}

TEST_P(PaintPropertyTreeBuilderTest, ColumnSpannerUnderRelativePositioned) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #spanner {
        column-span: all;
        opacity: 0.5;
        width: 100px;
        height: 100px;
      }
    </style>
    <div style='columns: 3; position: absolute; top: 44px; left: 55px;'>
      <div style='position: relative; top: 100px; left: 100px'>
        <div id='spanner'></div>
      </div>
    </div>
  )HTML");

  LayoutObject* spanner = GetLayoutObjectByElementId("spanner");
  EXPECT_EQ(PhysicalOffset(55, 44), spanner->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(55, 44, 100, 100), spanner,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, FractionalPaintOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      div { position: absolute; }
      #a {
        width: 70px;
        height: 70px;
        left: 0.1px;
        top: 0.3px;
      }
      #b {
        width: 40px;
        height: 40px;
        left: 0.5px;
        top: 11.1px;
      }
    </style>
    <div id='a'>
      <div id='b'></div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  PhysicalOffset a_paint_offset(LayoutUnit(0.1), LayoutUnit(0.3));
  EXPECT_EQ(a_paint_offset, a->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(LayoutUnit(0.1), LayoutUnit(0.3),
                                       LayoutUnit(70), LayoutUnit(70)),
                          a, frame_view->GetLayoutView());

  LayoutObject* b = GetLayoutObjectByElementId("b");
  PhysicalOffset b_paint_offset =
      a_paint_offset + PhysicalOffset(LayoutUnit(0.5), LayoutUnit(11.1));
  EXPECT_EQ(b_paint_offset, b->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(LayoutUnit(0.1), LayoutUnit(0.3),
                                       LayoutUnit(70), LayoutUnit(70)),
                          a, frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, PaintOffsetWithBasicPixelSnapping) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      div { position: relative; }
      #a {
        width: 70px;
        height: 70px;
        left: 0.3px;
        top: 0.3px;
      }
      #b {
        width: 40px;
        height: 40px;
        transform: translateZ(0);
      }
      #c {
        width: 40px;
        height: 40px;
       left: 0.1px;
       top: 0.1px;
      }
    </style>
    <div id='a'>
      <div id='b'>
        <div id='c'></div>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  EXPECT_TRUE(b_properties->Transform()->IsIdentity());
  // The paint offset transform should be snapped from (0.3,0.3) to (0,0).
  EXPECT_TRUE(ToUnaliased(*b_properties->Transform()->Parent()).IsIdentity());
  // The residual subpixel adjustment should be (0.3,0.3) - (0,0) = (0.3,0.3).
  PhysicalOffset subpixel_accumulation(LayoutUnit(0.3), LayoutUnit(0.3));
  EXPECT_EQ(subpixel_accumulation, b->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(LayoutUnit(0.3), LayoutUnit(0.3),
                                       LayoutUnit(40), LayoutUnit(40)),
                          b, frame_view->GetLayoutView());

  // c's painted should start at subpixelAccumulation + (0.1,0.1) = (0.4,0.4).
  LayoutObject* c = GetLayoutObjectByElementId("c");
  PhysicalOffset c_paint_offset =
      subpixel_accumulation + PhysicalOffset(LayoutUnit(0.1), LayoutUnit(0.1));
  EXPECT_EQ(c_paint_offset, c->FirstFragment().PaintOffset());
  // Visual rects via the non-paint properties system use enclosingIntRect
  // before applying transforms, because they are computed bottom-up and
  // therefore can't apply pixel snapping. Therefore apply a slop of 1px.
  CHECK_VISUAL_RECT(PhysicalRect(LayoutUnit(0.4), LayoutUnit(0.4),
                                 LayoutUnit(40), LayoutUnit(40)),
                    c, frame_view->GetLayoutView(), 1);
}

TEST_P(PaintPropertyTreeBuilderTest,
       PaintOffsetWithPixelSnappingThroughTransform) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      div { position: relative; }
      #a {
        width: 70px;
        height: 70px;
        left: 0.7px;
        top: 0.7px;
      }
      #b {
        width: 40px;
        height: 40px;
        transform: translateZ(0);
      }
      #c {
        width: 40px;
        height: 40px;
        left: 0.7px;
        top: 0.7px;
      }
    </style>
    <div id='a'>
      <div id='b'>
        <div id='c'></div>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  EXPECT_TRUE(b_properties->Transform()->IsIdentity());
  // The paint offset transform should be snapped from (0.7,0.7) to (1,1).
  EXPECT_EQ(
      gfx::Vector2dF(1, 1),
      ToUnaliased(*b_properties->Transform()->Parent()).Get2dTranslation());
  // The residual subpixel adjustment should be (0.7,0.7) - (1,1) = (-0.3,-0.3).
  PhysicalOffset subpixel_accumulation =
      PhysicalOffset(LayoutUnit(0.7), LayoutUnit(0.7)) - PhysicalOffset(1, 1);
  EXPECT_EQ(subpixel_accumulation, b->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(LayoutUnit(0.7), LayoutUnit(0.7),
                                       LayoutUnit(40), LayoutUnit(40)),
                          b, frame_view->GetLayoutView());

  // c's painting should start at subpixelAccumulation + (0.7,0.7) = (0.4,0.4).
  LayoutObject* c = GetLayoutObjectByElementId("c");
  PhysicalOffset c_paint_offset =
      subpixel_accumulation + PhysicalOffset(LayoutUnit(0.7), LayoutUnit(0.7));
  EXPECT_EQ(c_paint_offset, c->FirstFragment().PaintOffset());
  // Visual rects via the non-paint properties system use enclosingIntRect
  // before applying transforms, because they are computed bottom-up and
  // therefore can't apply pixel snapping. Therefore apply a slop of 1px.
  CHECK_VISUAL_RECT(PhysicalRect(LayoutUnit(0.7) + LayoutUnit(0.7),
                                 LayoutUnit(0.7) + LayoutUnit(0.7),
                                 LayoutUnit(40), LayoutUnit(40)),
                    c, frame_view->GetLayoutView(), 1);
}

TEST_P(PaintPropertyTreeBuilderTest,
       NonTranslationTransformShouldResetSubpixelPaintOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      div { position: relative; }
      #a {
        width: 70px;
        height: 70px;
        left: 0.9px;
        top: 0.9px;
      }
      #b {
        width: 40px;
        height: 40px;
        transform: scale(10);
        transform-origin: 0 0;
      }
      #c {
        width: 40px;
        height: 40px;
        left: 0.6px;
        top: 0.6px;
      }
    </style>
    <div id='a'>
      <div id='b'>
        <div id='c'></div>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  EXPECT_EQ(MakeScaleMatrix(10), b_properties->Transform()->Matrix());
  // The paint offset transform should not be snapped.
  EXPECT_EQ(
      gfx::Vector2dF(1, 1),
      ToUnaliased(*b_properties->Transform()->Parent()).Get2dTranslation());
  EXPECT_EQ(PhysicalOffset(), b->FirstFragment().PaintOffset());
  // Visual rects via the non-paint properties system use enclosingIntRect
  // before applying transforms, because they are computed bottom-up and
  // therefore can't apply pixel snapping. Therefore apply a slop of 1px.
  CHECK_VISUAL_RECT(PhysicalRect(LayoutUnit(1), LayoutUnit(1), LayoutUnit(400),
                                 LayoutUnit(400)),
                    b, frame_view->GetLayoutView(), 1);

  // c's painting should start at c_offset.
  LayoutObject* c = GetLayoutObjectByElementId("c");
  LayoutUnit c_offset = LayoutUnit(0.6);
  EXPECT_EQ(PhysicalOffset(c_offset, c_offset),
            c->FirstFragment().PaintOffset());
  // Visual rects via the non-paint properties system use enclosingIntRect
  // before applying transforms, because they are computed bottom-up and
  // therefore can't apply pixel snapping. Therefore apply a slop of 1px
  // in the transformed space (c_offset * 10 in view space) and 1px in the
  // view space.
  CHECK_VISUAL_RECT(PhysicalRect(c_offset * 10 + 1, c_offset * 10 + 1,
                                 LayoutUnit(400), LayoutUnit(400)),
                    c, frame_view->GetLayoutView(), c_offset * 10 + 1);
}

TEST_P(PaintPropertyTreeBuilderTest,
       WillChangeTransformShouldResetSubpixelPaintOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      div { position: relative; }
      #a {
        width: 70px;
        height: 70px;
        left: 0.9px;
        top: 0.9px;
      }
      #b {
        width: 40px;
        height: 40px;
        will-change: transform;
      }
      #c {
        width: 40px;
        height: 40px;
        left: 0.6px;
        top: 0.6px;
      }
    </style>
    <div id='a'>
      <div id='b'>
        <div id='c'></div>
      </div>
    </div>
  )HTML");

  auto* b = GetLayoutObjectByElementId("b");
  const auto* b_properties = b->FirstFragment().PaintProperties();
  EXPECT_TRUE(
      b_properties->Transform()->RequiresCompositingForWillChangeTransform());
  // The paint offset transform should not be snapped.
  EXPECT_EQ(
      gfx::Vector2dF(1, 1),
      ToUnaliased(*b_properties->Transform()->Parent()).Get2dTranslation());
  EXPECT_EQ(PhysicalOffset(), b->FirstFragment().PaintOffset());
  // c's painting should start at c_offset.
  auto* c = GetLayoutObjectByElementId("c");
  LayoutUnit c_offset = LayoutUnit(0.6);
  EXPECT_EQ(PhysicalOffset(c_offset, c_offset),
            c->FirstFragment().PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest,
       TransformAnimationShouldResetSubpixelPaintOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      div { position: relative; }
      #a {
        width: 70px;
        height: 70px;
        left: 0.9px;
        top: 0.9px;
      }
      #b {
        width: 40px;
        height: 40px;
        animation: spin 2s infinite;
      }
      @keyframes spin {
        from { transform: rotate(0deg) }
        to { transform: rotate(360deg) }
      }
      #c {
        width: 40px;
        height: 40px;
        left: 0.6px;
        top: 0.6px;
      }
    </style>
    <div id='a'>
      <div id='b'>
        <div id='c'></div>
      </div>
    </div>
  )HTML");

  auto* b = GetLayoutObjectByElementId("b");
  const auto* b_properties = b->FirstFragment().PaintProperties();
  EXPECT_TRUE(b_properties->Transform()->HasActiveTransformAnimation());
  // The paint offset transform should not be snapped.
  EXPECT_EQ(
      gfx::Vector2dF(1, 1),
      ToUnaliased(*b_properties->Transform()->Parent()).Get2dTranslation());
  EXPECT_EQ(PhysicalOffset(), b->FirstFragment().PaintOffset());
  // c's painting should start at c_offset.
  auto* c = GetLayoutObjectByElementId("c");
  LayoutUnit c_offset = LayoutUnit(0.6);
  EXPECT_EQ(PhysicalOffset(c_offset, c_offset),
            c->FirstFragment().PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest,
       PaintOffsetWithPixelSnappingThroughMultipleTransforms) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      div { position: relative; }
      #a {
        width: 70px;
        height: 70px;
        left: 0.7px;
        top: 0.7px;
      }
      #b {
        width: 40px;
        height: 40px;
        transform: translate3d(5px, 7px, 0);
      }
      #c {
        width: 40px;
        height: 40px;
        transform: translate3d(11px, 13px, 0);
      }
      #d {
        width: 40px;
        height: 40px;
        left: 0.7px;
        top: 0.7px;
      }
    </style>
    <div id='a'>
      <div id='b'>
        <div id='c'>
          <div id='d'></div>
        </div>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(5, 7),
            b_properties->Transform()->Get2dTranslation());
  // The paint offset transform should be snapped from (0.7,0.7) to (1,1).
  EXPECT_EQ(
      gfx::Vector2dF(1, 1),
      ToUnaliased(*b_properties->Transform()->Parent()).Get2dTranslation());
  // The residual subpixel adjustment should be (0.7,0.7) - (1,1) = (-0.3,-0.3).
  PhysicalOffset subpixel_accumulation =
      PhysicalOffset(LayoutUnit(0.7), LayoutUnit(0.7)) - PhysicalOffset(1, 1);
  EXPECT_EQ(subpixel_accumulation, b->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(LayoutUnit(5.7), LayoutUnit(7.7),
                                       LayoutUnit(40), LayoutUnit(40)),
                          b, frame_view->GetLayoutView());

  LayoutObject* c = GetLayoutObjectByElementId("c");
  const ObjectPaintProperties* c_properties =
      c->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(11, 13),
            c_properties->Transform()->Get2dTranslation());
  // The paint offset should be (-0.3,-0.3) but the paint offset transform
  // should still be at (0,0) because it should be snapped.
  EXPECT_EQ(
      gfx::Vector2dF(),
      ToUnaliased(*c_properties->Transform()->Parent()).Get2dTranslation());
  // The residual subpixel adjustment should still be (-0.3,-0.3).
  EXPECT_EQ(subpixel_accumulation, c->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(LayoutUnit(16.7), LayoutUnit(20.7),
                                       LayoutUnit(40), LayoutUnit(40)),
                          c, frame_view->GetLayoutView());

  // d should be painted starting at subpixelAccumulation + (0.7,0.7) =
  // (0.4,0.4).
  LayoutObject* d = GetLayoutObjectByElementId("d");
  PhysicalOffset d_paint_offset =
      subpixel_accumulation + PhysicalOffset(LayoutUnit(0.7), LayoutUnit(0.7));
  EXPECT_EQ(d_paint_offset, d->FirstFragment().PaintOffset());
  // Visual rects via the non-paint properties system use enclosingIntRect
  // before applying transforms, because they are computed bottom-up and
  // therefore can't apply pixel snapping. Therefore apply a slop of 1px.
  CHECK_VISUAL_RECT(PhysicalRect(LayoutUnit(16.7) + LayoutUnit(0.7),
                                 LayoutUnit(20.7) + LayoutUnit(0.7),
                                 LayoutUnit(40), LayoutUnit(40)),
                    d, frame_view->GetLayoutView(), 1);
}

TEST_P(PaintPropertyTreeBuilderTest, PaintOffsetWithPixelSnappingWithFixedPos) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #a {
        width: 70px;
        height: 70px;
        left: 0.7px;
        position: relative;
      }
      #b {
        width: 40px;
        height: 40px;
        transform: translateZ(0);
        position: relative;
      }
      #fixed {
        width: 40px;
        height: 40px;
        position: fixed;
      }
      #d {
        width: 40px;
        height: 40px;
        left: 0.7px;
        position: relative;
      }
    </style>
    <div id='a'>
      <div id='b'>
        <div id='fixed'>
          <div id='d'></div>
        </div>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(), b_properties->Transform()->Get2dTranslation());
  // The paint offset transform should be snapped from (0.7,0) to (1,0).
  EXPECT_EQ(
      gfx::Vector2dF(1, 0),
      ToUnaliased(*b_properties->Transform()->Parent()).Get2dTranslation());
  // The residual subpixel adjustment should be (0.7,0) - (1,0) = (-0.3,0).
  PhysicalOffset subpixel_accumulation =
      PhysicalOffset(LayoutUnit(0.7), LayoutUnit()) - PhysicalOffset(1, 0);
  EXPECT_EQ(subpixel_accumulation, b->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(LayoutUnit(0.7), LayoutUnit(0),
                                       LayoutUnit(40), LayoutUnit(40)),
                          b, frame_view->GetLayoutView());

  LayoutObject* fixed = GetLayoutObjectByElementId("fixed");
  // The residual subpixel adjustment should still be (-0.3,0).
  EXPECT_EQ(subpixel_accumulation, fixed->FirstFragment().PaintOffset());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(LayoutUnit(0.7), LayoutUnit(0),
                                       LayoutUnit(40), LayoutUnit(40)),
                          fixed, frame_view->GetLayoutView());

  // d should be painted starting at subpixelAccumulation + (0.7,0) = (0.4,0).
  LayoutObject* d = GetLayoutObjectByElementId("d");
  PhysicalOffset d_paint_offset =
      subpixel_accumulation + PhysicalOffset(LayoutUnit(0.7), LayoutUnit());
  EXPECT_EQ(d_paint_offset, d->FirstFragment().PaintOffset());
  // Visual rects via the non-paint properties system use enclosingIntRect
  // before applying transforms, because they are computed bottom-up and
  // therefore can't apply pixel snapping. Therefore apply a slop of 1px.
  CHECK_VISUAL_RECT(PhysicalRect(LayoutUnit(0.7) + LayoutUnit(0.7),
                                 LayoutUnit(), LayoutUnit(40), LayoutUnit(40)),
                    d, frame_view->GetLayoutView(), 1);
}

TEST_P(PaintPropertyTreeBuilderTest, SvgPixelSnappingShouldResetPaintOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #svg {
        position: relative;
        left: 0.1px;
        transform: matrix(1, 0, 0, 1, 0, 0);
      }
    </style>
    <svg id='svg'>
        <rect id='rect' transform='translate(1, 1)'/>
    </svg>
  )HTML");

  LayoutObject& svg_with_transform = *GetLayoutObjectByElementId("svg");
  const ObjectPaintProperties* svg_with_transform_properties =
      svg_with_transform.FirstFragment().PaintProperties();
  EXPECT_TRUE(svg_with_transform_properties->Transform()->IsIdentity());
  EXPECT_EQ(PhysicalOffset(LayoutUnit(0.1), LayoutUnit()),
            svg_with_transform.FirstFragment().PaintOffset());
  EXPECT_TRUE(svg_with_transform_properties->ReplacedContentTransform() ==
              nullptr);

  LayoutObject& rect_with_transform = *GetLayoutObjectByElementId("rect");
  const ObjectPaintProperties* rect_with_transform_properties =
      rect_with_transform.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(1, 1),
            rect_with_transform_properties->Transform()->Get2dTranslation());

  // Ensure there is no PaintOffset transform between the rect and the svg's
  // transform.
  EXPECT_EQ(svg_with_transform_properties->Transform(),
            rect_with_transform_properties->Transform()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SvgRootAndForeignObjectPixelSnapping) {
  SetBodyInnerHTML(R"HTML(
    <svg id=svg style='position: relative; left: 0.6px; top: 0.3px'>
      <foreignObject id=foreign x='3.5' y='5.4' transform='translate(1, 1)'>
        <div id=div style='position: absolute; left: 5.6px; top: 7.3px'>
        </div>
      </foreignObject>
    </svg>
  )HTML");

  const auto* svg = GetLayoutObjectByElementId("svg");
  const auto* svg_properties = svg->FirstFragment().PaintProperties();
  // The paint offset of (8.6, 8.3) is rounded off here. The fractional part
  // remains PaintOffset.
  EXPECT_EQ(gfx::Vector2dF(9, 8),
            svg_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(PhysicalOffset(LayoutUnit(-0.40625), LayoutUnit(0.3)),
            svg->FirstFragment().PaintOffset());
  EXPECT_EQ(nullptr, svg_properties->ReplacedContentTransform());
  const auto* foreign_object = GetLayoutObjectByElementId("foreign");
  const auto* foreign_object_properties =
      foreign_object->FirstFragment().PaintProperties();
  EXPECT_EQ(nullptr, foreign_object_properties->PaintOffsetTranslation());

  PhysicalOffset fo_translation(LayoutUnit(3.5f), LayoutUnit(5.4f));
  EXPECT_EQ(fo_translation, foreign_object->FirstFragment().PaintOffset());

  const auto* div = GetLayoutObjectByElementId("div");
  // Paint offset of descendant of foreignObject accumulates on paint offset
  // of foreignObject.
  PhysicalOffset div_offset(LayoutUnit(5.6f), LayoutUnit(7.3f));
  EXPECT_EQ(fo_translation + div_offset, div->FirstFragment().PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest, NoRenderingContextByDefault) {
  SetBodyInnerHTML("<div style='transform: translateZ(0)'></div>");

  const ObjectPaintProperties* properties = GetDocument()
                                                .body()
                                                ->firstChild()
                                                ->GetLayoutObject()
                                                ->FirstFragment()
                                                .PaintProperties();
  ASSERT_TRUE(properties->Transform());
  EXPECT_FALSE(properties->Transform()->HasRenderingContext());
}

TEST_P(PaintPropertyTreeBuilderTest, Preserve3DCreatesSharedRenderingContext) {
  SetBodyInnerHTML(R"HTML(
    <div style='transform-style: preserve-3d'>
      <div id='a' style='transform: translateZ(0); width: 30px; height: 40px'>
      </div>
      <div id='b' style='transform: translateZ(0); width: 20px; height: 10px'>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  const ObjectPaintProperties* a_properties =
      a->FirstFragment().PaintProperties();
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  ASSERT_TRUE(a_properties->Transform() && b_properties->Transform());
  EXPECT_NE(a_properties->Transform(), b_properties->Transform());

  EXPECT_TRUE(a_properties->Transform()->HasRenderingContext());
  EXPECT_FALSE(a_properties->Transform()->FlattensInheritedTransform());
  EXPECT_TRUE(b_properties->Transform()->HasRenderingContext());
  EXPECT_FALSE(b_properties->Transform()->FlattensInheritedTransform());
  EXPECT_EQ(a_properties->Transform()->RenderingContextId(),
            b_properties->Transform()->RenderingContextId());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 30, 40), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 48, 20, 10), b,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest,
       IntermediateElementPreventsSharedRenderingContext) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='transform-style: preserve-3d'>
      <div>
        <div id='a' style='transform: translateZ(0); width: 30px; height: 40px'>
        </div>
      </div>
      <div id='b' style='transform: translateZ(0); width: 20px; height: 10px'>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  const ObjectPaintProperties* a_properties =
      a->FirstFragment().PaintProperties();
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  ASSERT_TRUE(a_properties->Transform() && b_properties->Transform());
  EXPECT_NE(a_properties->Transform(), b_properties->Transform());

  const ObjectPaintProperties* parent_properties =
      b->FirstFragment().PaintProperties();

  EXPECT_FALSE(a_properties->Transform()->HasRenderingContext());
  EXPECT_TRUE(a_properties->Transform()->FlattensInheritedTransform());
  EXPECT_TRUE(b_properties->Transform()->HasRenderingContext());
  EXPECT_FALSE(b_properties->Transform()->FlattensInheritedTransform());
  EXPECT_NE(a_properties->Transform()->RenderingContextId(),
            b_properties->Transform()->RenderingContextId());

  EXPECT_EQ(parent_properties->Transform()->RenderingContextId(),
            b_properties->Transform()->RenderingContextId());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 30, 40), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 48, 20, 10), b,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest,
       IntermediateElementWithPropertiesPreventsSharedRenderingContext) {
  SetBodyInnerHTML(R"HTML(
    <div id='parent' style='transform-style: preserve-3d'>
      <div style="overflow: hidden">
        <div id='a' style='transform: translateZ(0); width: 30px; height: 40px'>
        </div>
      </div>
      <div id='b' style='transform: translateZ(0); width: 20px; height: 10px'>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  const ObjectPaintProperties* a_properties =
      a->FirstFragment().PaintProperties();
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  ASSERT_TRUE(a_properties->Transform() && b_properties->Transform());
  EXPECT_NE(a_properties->Transform(), b_properties->Transform());

  const ObjectPaintProperties* parent_properties =
      b->FirstFragment().PaintProperties();

  EXPECT_FALSE(a_properties->Transform()->HasRenderingContext());
  EXPECT_TRUE(a_properties->Transform()->FlattensInheritedTransform());
  EXPECT_TRUE(b_properties->Transform()->HasRenderingContext());
  EXPECT_FALSE(b_properties->Transform()->FlattensInheritedTransform());
  EXPECT_NE(a_properties->Transform()->RenderingContextId(),
            b_properties->Transform()->RenderingContextId());

  EXPECT_EQ(parent_properties->Transform()->RenderingContextId(),
            b_properties->Transform()->RenderingContextId());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 30, 40), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 48, 20, 10), b,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, FlatTransformStyleEndsRenderingContext) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #a {
        transform: translateZ(0);
        width: 30px;
        height: 40px;
      }
      #b {
        transform: translateZ(0);
        width: 10px;
        height: 20px;
      }
    </style>
    <div style='transform-style: preserve-3d'>
      <div id='a'>
        <div id='b'></div>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  const ObjectPaintProperties* a_properties =
      a->FirstFragment().PaintProperties();
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  ASSERT_FALSE(a->StyleRef().Preserves3D());

  ASSERT_TRUE(a_properties->Transform() && b_properties->Transform());

  // #a should participate in a rendering context (due to its parent), but its
  // child #b should not.
  EXPECT_TRUE(a_properties->Transform()->HasRenderingContext());
  EXPECT_FALSE(b_properties->Transform()->HasRenderingContext());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 30, 40), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 10, 20), b,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, NestedRenderingContexts) {
  SetBodyInnerHTML(R"HTML(
    <div style='transform-style: preserve-3d'>
      <div id='a' style='transform: translateZ(0); width: 50px; height: 60px'>
        <div style='transform-style: preserve-3d; width: 30px; height: 40px'>
          <div id='b'
              style='transform: translateZ(0); width: 10px; height: 20px'>
          </div>
        </div>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  const ObjectPaintProperties* a_properties =
      a->FirstFragment().PaintProperties();
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  ASSERT_FALSE(a->StyleRef().Preserves3D());
  ASSERT_TRUE(a_properties->Transform() && b_properties->Transform());

  // #a should participate in a rendering context (due to its parent). Its child
  //  does preserve 3D, but since #a does not, #a's rendering context is not
  //  passed on to its children. Thus #b ends up in a separate rendering
  //  context rooted at its parent.
  EXPECT_TRUE(a_properties->Transform()->HasRenderingContext());
  EXPECT_TRUE(b_properties->Transform()->HasRenderingContext());
  EXPECT_NE(a_properties->Transform()->RenderingContextId(),
            b_properties->Transform()->RenderingContextId());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 50, 60), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 10, 20), b,
                          frame_view->GetLayoutView());
}

// Returns true if some node will flatten the transform due to |node| before it
// is inherited by |node| (including if node->flattensInheritedTransform()).
static bool SomeNodeFlattensTransform(
    const TransformPaintPropertyNode* node,
    const TransformPaintPropertyNode* ancestor) {
  while (node != ancestor) {
    if (node->FlattensInheritedTransform())
      return true;
    node = node->UnaliasedParent();
  }
  return false;
}

TEST_P(PaintPropertyTreeBuilderTest, FlatTransformStylePropagatesToChildren) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #a {
        transform: translateZ(0);
        transform-style: flat;
        width: 30px;
        height: 40px;
```