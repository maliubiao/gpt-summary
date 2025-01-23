Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file (`paint_property_tree_builder_test.cc`). I need to analyze the code, explain its purpose, and relate it to web technologies like JavaScript, HTML, and CSS if applicable. I should also provide examples of logical reasoning with input/output, common user/programming errors, and how a user might trigger this code. Finally, I need to summarize the functionality of this specific part of the file, considering it's the 8th out of 10 parts.

**Plan:**

1. **Overall Purpose:**  The file `paint_property_tree_builder_test.cc` contains unit tests for the `PaintPropertyTreeBuilder`. This class is responsible for building the paint property tree, which is a crucial structure in the rendering pipeline. It determines how elements are painted, considering properties like transforms, clips, masks, and effects.

2. **Analyze Code Snippet:**  Go through each test case in the provided snippet and understand what aspect of the `PaintPropertyTreeBuilder` it's testing.

3. **Relate to Web Technologies:** Identify how the tested CSS properties or HTML structures relate to user-facing web features and how they might be manipulated via JavaScript.

4. **Logical Reasoning (Hypothetical Input/Output):** For specific tests, if a clear logical flow exists, create a simple scenario with a specific HTML/CSS input and the expected output of the `PaintPropertyTreeBuilder` (e.g., the presence or configuration of a specific paint property node).

5. **Common Errors:** Think about situations where developers might misuse the tested features or encounter unexpected behavior.

6. **User Actions:** Describe the sequence of user interactions in a browser that would lead to the rendering engine processing the specific HTML and CSS tested in the snippet.

7. **Summarize Functionality (Part 8 of 10):** Based on the analyzed tests, summarize the specific areas of the `PaintPropertyTreeBuilder` that this section is focused on.

**Detailed Analysis of the Snippet:**

* **`ClipPathMask` tests:**  Verify that applying `clip-path` or `-webkit-mask` to an element correctly creates the corresponding `ClipPathMask` object in the paint property tree.
* **`EmptyClipPathSubpixelOffset` and `EmptyMaskSubpixelOffset`:** Check how subpixel offsets on elements with empty clip paths or masks are handled.
* **`RootHasCompositedScrolling` and `IframeDoesNotRequireCompositedScrolling`:**  Examine the conditions under which the root document and iframes require composited scrolling and the corresponding reasons in the paint property tree.
* **`ClipHitTestChangeDoesNotCauseFullRepaint`:** Test that changing the scrollbar visibility using CSS classes doesn't trigger a full repaint of unrelated elements.
* **`ClipPathInheritanceWithoutMutation`:** Verify that applying a clip path on a parent element is correctly inherited by the child even when the child's paint properties are updated without the clip path needing changes.
* **`CompositedLayerSkipsFragmentClip`:**  Check if composited layers correctly bypass fragment clips.
* **`CompositedLayerUnderClipUnderMulticol`:** Test the paint property tree structure for composited elements nested under a clip in a multicolumn layout.
* **`RepeatingFixedPositionInPagedMedia` and `RepeatingFixedPositionWithTransformInPagedMedia`:**  Verify how fixed-position elements are handled during printing, including the creation of multiple fragments for each page and the application of transforms.
* **`FloatPaintOffsetInContainerWithScrollbars`:**  Examine the paint offsets of floated elements within scrollable containers with different writing modes and directions.
* **`PaintOffsetForTextareaWithResizer`:**  Test if a textarea with a resizer has a paint offset translation.
* **`SubpixelPositionedScrollNode`:**  Check how subpixel positioning affects the `ContainerRect` and `ContentsRect` of a scroll node.
* **`LayoutMenuListHasOverlowAndLocalBorderBoxProperties`:**  Ensure that a `LayoutMenuList` has both overflow and local border box properties.
* **`EmptyClipFragments`:** Test the fragmentation of elements with column spans.
* **`StickyConstraintChain`, `StickyUnderOverflowHidden`, `StickyUnderScrollerWithoutOverflow`:**  Verify the creation and configuration of sticky constraints for nested sticky positioned elements under various overflow conditions.
* **`WillChangeOpacityInducesAnEffectNode`:**  Confirm that using `will-change: opacity` creates an effect node in the paint property tree.
* **`EffectOutputClipWithFixedDescendant`:** Test the output clip of effect nodes when they have fixed-position descendants.
* **`TableColOpacity`:** Check if `opacity` is supported on table column elements.
* **`MainFrameDoesntClipContent`:** Verify the behavior of clipping content in the main frame based on a WebView setting.
* **`SVGRootCompositedClipPathSimple` and `SVGRootCompositedClipPathComplex`:** Test the paint property tree structure for composited SVG root elements with simple and complex clip paths.
* **`SimpleOpacityChangeDoesNotCausePacUpdate`:** Ensure that a simple opacity change doesn't trigger an unnecessary update of the Paint Artifact Compositor.
这是 `blink/renderer/core/paint/paint_property_tree_builder_test.cc` 文件的第 8 部分，主要功能是测试 `PaintPropertyTreeBuilder` 的各种功能，特别是涉及到以下方面：

**归纳一下它的功能:**

这部分主要测试了 `PaintPropertyTreeBuilder` 在处理以下 CSS 属性和场景时的正确性：

* **Clip-path 和 Mask:**  验证了 `clip-path` 和 `-webkit-mask` 属性如何创建 `ClipPathMask` 节点，以及子像素偏移对这些属性的影响。
* **滚动:** 测试了根元素和 iframe 的滚动 compositing 行为，以及滚动条样式变化对重绘的影响。
* **Clip-path 继承:** 验证了 `clip-path` 的继承机制，即使子元素只需要更新 paint 属性。
* **Compositing 和 Clip:** 测试了 composited layer 如何跳过 fragment clip，以及 composited layer 在 clip 和 multicolumn 布局下的行为。
* **固定定位元素在分页媒体中的重复:** 验证了 `position: fixed` 的元素在打印时如何在每个页面上重复出现，包括带有 transform 的情况。
* **浮动元素和滚动条:** 测试了带有滚动条的容器中浮动元素的 paint offset 计算，包括不同的 writing-mode 和 direction。
* **Textarea 的 Paint Offset:** 验证了带有 resizer 的 textarea 是否有 paint offset。
* **滚动容器的子像素定位:** 测试了子像素定位的滚动容器的滚动节点属性。
* **LayoutMenuList 的属性:** 确保 `LayoutMenuList` 拥有 overflow 和 local border box 属性。
* **空 Clip Fragments:** 测试了带有 `column-span: all` 属性的元素在多列布局下的 fragment 分割。
* **Sticky 定位:** 深入测试了 `position: sticky` 的各种场景，包括嵌套的 sticky 元素，在 `overflow: hidden` 容器下以及没有 overflow 的滚动容器下的行为，以及 sticky constraint 链的建立。
* **`will-change: opacity`:** 验证了使用 `will-change: opacity` 会创建一个 effect 节点。
* **Effect 节点的输出 Clip 和固定定位子元素:** 测试了 effect 节点的输出 clip 在有固定定位子元素时的行为。
* **Table Col 的 Opacity:**  测试了 `opacity` 属性在 `<table>` 的 `<col>` 元素上的应用 (目前似乎不支持)。
* **主 Frame 的内容裁剪:** 测试了 WebView API 中控制主 Frame 是否裁剪内容的功能。
* **SVG 根元素的 Clip-path:** 测试了 composited 的 SVG 根元素应用 clip-path 时的 paint 属性树结构，包括简单和复杂的 clip-path。
* **简单的 Opacity 改变不会导致 PAC 更新:** 验证了简单的 `opacity` 改变是否会触发不必要的 Paint Artifact Compositor (PAC) 更新。

**与 javascript, html, css 的功能关系以及举例说明:**

这些测试直接关联着 HTML 结构和 CSS 样式，并且这些样式可以通过 JavaScript 进行动态修改。

* **HTML:**  测试用例中使用了各种 HTML 元素，例如 `<div>`, `<iframe>`, `<table>`, `<textarea>`, `<select>`, `<svg>` 等，来模拟不同的布局场景。
* **CSS:**  测试的核心在于各种 CSS 属性，例如 `clip-path`, `-webkit-mask`, `position`, `overflow`, `columns`, `transform`, `opacity`, `will-change`, `writing-mode`, `direction` 等。
* **JavaScript:** JavaScript 可以用来动态修改 HTML 结构和 CSS 样式，从而触发 `PaintPropertyTreeBuilder` 的运行。例如：
    * **假设输入:** 用户通过 JavaScript 修改一个元素的 `clip-path` 属性:
      ```javascript
      document.getElementById('target').style.clipPath = 'circle()';
      ```
    * **预期输出:** `PaintPropertyTreeBuilder` 会为该元素创建一个 `ClipPathMask` 节点，其中包含圆形 clip-path 的信息。相关的测试用例，例如 `TEST_P(PaintPropertyTreeBuilderTest, ClipPathMask)`，就验证了这种行为。

**逻辑推理与假设输入输出:**

* **假设输入:**  一个 HTML 结构如下：
  ```html
  <div style="position: relative; top: 10px;">
    <div style="position: sticky; top: 20px;">Hello</div>
  </div>
  ```
* **逻辑推理:**  内部的 `div` 元素设置了 `position: sticky`，它会相对于其最近的具有滚动机制的祖先元素（或视口）进行固定。`PaintPropertyTreeBuilder` 需要识别出这个 sticky 元素，并创建相应的 `StickyTranslation` 节点。
* **预期输出:**  内部的 `div` 元素在 paint 属性树中会有一个 `StickyTranslation` 节点，其 `Get2dTranslation()` 的值会根据滚动位置而变化，并且可能包含指向其约束的 `StickyConstraint` 信息，如 `TEST_P(PaintPropertyTreeBuilderTest, StickyConstraintChain)` 所测试的。

**用户或编程常见的使用错误举例说明:**

* **错误使用 `will-change`:** 开发者可能会滥用 `will-change` 属性，将其应用到不必要优化的属性上，导致浏览器分配过多的资源，反而降低性能。 例如，对一个静态文本内容应用 `will-change: transform` 可能并不会带来性能提升，反而会增加内存消耗。
* **忘记考虑滚动容器对 sticky 定位的影响:**  开发者可能认为 `position: sticky` 总是在视口中固定，但实际上它是在其最近的具有滚动机制的祖先元素内固定。如果父元素没有设置 `overflow: scroll` 或 `overflow: auto`，sticky 定位的行为可能会出乎意料。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载一个包含复杂 CSS 样式的网页。** 例如，网页使用了 `clip-path` 来创建特殊的元素形状，或者使用了 `position: sticky` 来实现吸顶效果。
2. **浏览器开始解析 HTML 和 CSS。**
3. **布局引擎 (Layout Engine) 计算出网页元素的几何属性。**
4. **`PaintPropertyTreeBuilder` 被调用来构建 paint 属性树。** 这个过程会根据元素的 CSS 属性，创建相应的 paint 属性节点，例如 `ClipPathMask`, `ScrollTranslation`, `StickyTranslation`, `Effect` 等。
5. **如果用户操作涉及到滚动、元素样式改变（例如通过 JavaScript 修改），或者触发了打印，那么 `PaintPropertyTreeBuilder` 可能会被重新调用来更新 paint 属性树。**
6. **在调试过程中，开发者可能会关注 `paint_property_tree_builder_test.cc` 中的测试用例，来理解特定 CSS 属性是如何影响 paint 属性树的构建的。**  如果他们遇到了与 clip-path 或 sticky 定位相关的问题，那么这部分代码的测试用例就能提供有价值的参考。

总而言之，这部分测试用例覆盖了 `PaintPropertyTreeBuilder` 在处理各种重要的 CSS 属性和布局场景时的核心逻辑，确保了渲染引擎能够正确地构建 paint 属性树，从而保证网页的正确渲染和性能。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
es()->ClipPathMask());
  }
}

TEST_P(PaintPropertyTreeBuilderTest, EmptyClipPathSubpixelOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id="target"
         style="clip-path: polygon(0 0, 100% 0, 100% 100%, 0 100%, 0 0);
                position: relative; top: 0.75px; left: 0.25px; width: 0">
    </div>
  )HTML");

  const auto* target = GetLayoutObjectByElementId("target");
  ASSERT_TRUE(target->FirstFragment().PaintProperties());
  const auto* clip_path_clip =
      target->FirstFragment().PaintProperties()->ClipPathClip();
  ASSERT_TRUE(clip_path_clip);
  EXPECT_EQ(gfx::RectF(0.25, 0.75, 0, 0),
            clip_path_clip->LayoutClipRect().Rect());
  EXPECT_EQ(FloatRoundedRect(), clip_path_clip->PaintClipRect());
}

TEST_P(PaintPropertyTreeBuilderTest, EmptyMaskSubpixelOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id="target"
         style="-webkit-mask: linear-gradient(blue, white);
                position: relative; top: 0.75px; left: 0.25px; width: 0">
    </div>
  )HTML");

  const auto* target = GetLayoutObjectByElementId("target");
  ASSERT_TRUE(target->FirstFragment().PaintProperties());
  const auto* mask_clip = target->FirstFragment().PaintProperties()->MaskClip();
  ASSERT_TRUE(mask_clip);
  EXPECT_EQ(gfx::RectF(0.25, 0.75, 0, 0), mask_clip->LayoutClipRect().Rect());
  EXPECT_EQ(FloatRoundedRect(), mask_clip->PaintClipRect());
}

TEST_P(PaintPropertyTreeBuilderTest, RootHasCompositedScrolling) {
  SetBodyInnerHTML(R"HTML(
    <div id='forceScroll' style='height: 2000px'></div>
  )HTML");

  // When the root scrolls, there should be direct compositing reasons.
  EXPECT_TRUE(DocScrollTranslation()->HasDirectCompositingReasons());

  // Remove scrolling from the root.
  Element* force_scroll_element =
      GetDocument().getElementById(AtomicString("forceScroll"));
  force_scroll_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesExceptPaint();
  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
}

TEST_P(PaintPropertyTreeBuilderTest, IframeDoesNotRequireCompositedScrolling) {
  SetBodyInnerHTML(R"HTML(
    <iframe style='width: 200px; height: 200px;'></iframe>
    <div id='forceScroll' style='height: 2000px'></div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <div id='forceInnerScroll' style='height: 2000px'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(DocScrollTranslation()->HasDirectCompositingReasons());

  // When the child iframe scrolls, there should not be direct compositing
  // reasons because only the root frame needs scrolling compositing reasons.
  EXPECT_FALSE(
      DocScrollTranslation(&ChildDocument())->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest, ClipHitTestChangeDoesNotCauseFullRepaint) {
  SetBodyInnerHTML(R"HTML(
    <html>
      <body>
        <style>
          .noscrollbars::-webkit-scrollbar { display: none; }
        </style>
        <div id="child" style="width: 10px; height: 10px; position: absolute;">
        </div>
        <div id="forcescroll" style="height: 1000px;"></div>
      </body>
    </html>
  )HTML");
  CHECK(GetDocument().GetPage()->GetScrollbarTheme().UsesOverlayScrollbars());
  UpdateAllLifecyclePhasesForTest();

  auto* child_layer = GetPaintLayerByElementId("child");
  EXPECT_FALSE(child_layer->SelfNeedsRepaint());

  GetDocument().body()->setAttribute(html_names::kClassAttr,
                                     AtomicString("noscrollbars"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(child_layer->SelfNeedsRepaint());
}

TEST_P(PaintPropertyTreeBuilderTest, ClipPathInheritanceWithoutMutation) {
  // This test verifies we properly included the path-based clip-path in
  // context when the clipping element didn't need paint property update.
  SetBodyInnerHTML(R"HTML(
    <div style="clip-path:circle();">
      <div id="child" style="position:relative; width:100px; height:100px;
          background:green;"></div>
    </div>
  )HTML");

  auto* child = GetLayoutBoxByElementId("child");
  const auto& old_clip_state =
      child->FirstFragment().LocalBorderBoxProperties().Clip();

  child->SetNeedsPaintPropertyUpdate();
  UpdateAllLifecyclePhasesForTest();

  const auto& new_clip_state =
      child->FirstFragment().LocalBorderBoxProperties().Clip();
  EXPECT_EQ(&old_clip_state, &new_clip_state);
}

TEST_P(PaintPropertyTreeBuilderTest, CompositedLayerSkipsFragmentClip) {
  SetBodyInnerHTML(R"HTML(
    <div id="columns" style="columns: 2">
      <div id="composited-with-clip"
           style="height: 100px; will-change: transform; overflow: hidden">
        <div id="child-clipped" style="height: 120px; position: relative"></div>
      </div>
      <div id="composited-without-clip"
           style="height: 100px; will-change: transform">
        <div id="child-unclipped" style="height: 100%; position: relative">
        </div>
      </div>
    </div>
  )HTML");

  const auto* composited_with_clip_properties =
      PaintPropertiesForElement("composited-with-clip");
  EXPECT_EQ(DocContentClip(),
            composited_with_clip_properties->OverflowClip()->Parent());
  EXPECT_EQ(composited_with_clip_properties->OverflowClip(),
            &GetLayoutObjectByElementId("child-clipped")
                 ->FirstFragment()
                 .LocalBorderBoxProperties()
                 .Clip());

  EXPECT_EQ(DocContentClip(),
            &GetLayoutObjectByElementId("composited-without-clip")
                 ->FirstFragment()
                 .LocalBorderBoxProperties()
                 .Clip());
  EXPECT_EQ(DocContentClip(), &GetLayoutObjectByElementId("child-unclipped")
                                   ->FirstFragment()
                                   .LocalBorderBoxProperties()
                                   .Clip());
}

TEST_P(PaintPropertyTreeBuilderTest, CompositedLayerUnderClipUnderMulticol) {
  SetBodyInnerHTML(R"HTML(
    <div id="multicol" style="columns: 2">
      <div id="clip" style="height: 100px; overflow: hidden">
        <div id="composited"
             style="width: 200px; height: 200px; will-change: transform">
        </div>
      </div>
    </div>
  )HTML");

  const auto* clip_properties = PaintPropertiesForElement("clip");
  const auto* composited = GetLayoutObjectByElementId("composited");
  EXPECT_EQ(clip_properties->OverflowClip(),
            &composited->FirstFragment().LocalBorderBoxProperties().Clip());
}

TEST_P(PaintPropertyTreeBuilderTest, RepeatingFixedPositionInPagedMedia) {
  SetBodyInnerHTML(R"HTML(
    <div id="fixed" style="position: fixed; top: 20px; left: 20px">
      <div id="fixed-child" style="position: relative; top: 10px"></div>
    </div>
    <div id="normal" style="height: 1000px"></div>
  )HTML");
  GetDocument().domWindow()->scrollTo(0, 200);
  UpdateAllLifecyclePhasesForTest();

  const auto* fixed = GetLayoutObjectByElementId("fixed");
  EXPECT_EQ(1u, NumFragments(fixed));

  const auto* fixed_child = GetLayoutObjectByElementId("fixed-child");
  EXPECT_EQ(1u, NumFragments(fixed_child));

  const auto* normal = GetLayoutObjectByElementId("normal");
  EXPECT_EQ(1u, NumFragments(normal));

  gfx::SizeF page_size(300, 400);
  GetFrame().StartPrinting(WebPrintParams(page_size));
  GetDocument().View()->UpdateLifecyclePhasesForPrinting();
  fixed = GetLayoutObjectByElementId("fixed");
  fixed_child = GetLayoutObjectByElementId("fixed-child");
  normal = GetLayoutObjectByElementId("normal");

  // "fixed" should create fragments to repeat in each printed page.
  EXPECT_EQ(3u, NumFragments(fixed));
  for (int i = 0; i < 3; i++) {
    const auto& fragment = FragmentAt(fixed, i);
    auto* properties = fragment.PaintProperties();
    ASSERT_TRUE(properties);
    ASSERT_TRUE(properties->PaintOffsetTranslation());
    EXPECT_EQ(gfx::Vector2dF(20, 20 + 400 * i),
              properties->PaintOffsetTranslation()->Get2dTranslation());
    EXPECT_EQ(PhysicalOffset(), fragment.PaintOffset());
  }

  EXPECT_EQ(3u, NumFragments(fixed_child));
  for (int i = 0; i < 3; i++) {
    const auto& fragment = FragmentAt(fixed_child, i);
    EXPECT_EQ(FragmentAt(fixed, i).PaintOffset() + PhysicalOffset(0, 10),
              fragment.PaintOffset());
  }

  EXPECT_EQ(3u, NumFragments(normal));

  GetFrame().EndPrinting();
  UpdateAllLifecyclePhasesForTest();
  fixed = GetLayoutObjectByElementId("fixed");
  fixed_child = GetLayoutObjectByElementId("fixed-child");
  normal = GetLayoutObjectByElementId("normal");
  EXPECT_EQ(1u, NumFragments(fixed));
  EXPECT_EQ(1u, NumFragments(fixed_child));
  EXPECT_EQ(1u, NumFragments(normal));
}

TEST_P(PaintPropertyTreeBuilderTest,
       RepeatingFixedPositionWithTransformInPagedMedia) {
  SetBodyInnerHTML(R"HTML(
    <div id="fixed" style="position: fixed; top: 20px; left: 20px;
        transform: translateX(10px)">
      <div id="fixed-child" style="position: relative; top: 10px"></div>
    </div>
    <div id="normal" style="height: 1000px"></div>
  )HTML");
  GetDocument().domWindow()->scrollTo(0, 200);
  UpdateAllLifecyclePhasesForTest();

  const auto* fixed = GetLayoutObjectByElementId("fixed");
  EXPECT_EQ(1u, NumFragments(fixed));

  const auto* fixed_child = GetLayoutObjectByElementId("fixed-child");
  EXPECT_EQ(1u, NumFragments(fixed_child));

  gfx::SizeF page_size(300, 400);
  GetFrame().StartPrinting(WebPrintParams(page_size));
  GetDocument().View()->UpdateLifecyclePhasesForPrinting();
  fixed = GetLayoutObjectByElementId("fixed");
  fixed_child = GetLayoutObjectByElementId("fixed-child");

  // "fixed" should create fragments to repeat in each printed page.
  EXPECT_EQ(3u, NumFragments(fixed));
  for (wtf_size_t i = 0; i < 3; i++) {
    const FragmentData& fragment = FragmentAt(fixed, i);
    EXPECT_EQ(PhysicalOffset(), fragment.PaintOffset());
    const auto* properties = fragment.PaintProperties();
    EXPECT_EQ(gfx::Vector2dF(20, 20 + i * 400),
              properties->PaintOffsetTranslation()->Get2dTranslation());
    EXPECT_EQ(gfx::Vector2dF(10, 0),
              properties->Transform()->Get2dTranslation());
    EXPECT_EQ(properties->PaintOffsetTranslation(),
              properties->Transform()->Parent());
    EXPECT_EQ(fragment.FragmentID(), i);
  }

  for (wtf_size_t i = 0; i < 3; i++) {
    const FragmentData& fragment = FragmentAt(fixed_child, i);
    EXPECT_EQ(PhysicalOffset(0, 10), fragment.PaintOffset());
    EXPECT_EQ(FragmentAt(fixed, i).PaintProperties()->Transform(),
              &fragment.LocalBorderBoxProperties().Transform());
    EXPECT_EQ(fragment.FragmentID(), i);
  }

  GetFrame().EndPrinting();
  UpdateAllLifecyclePhasesForTest();
  fixed = GetLayoutObjectByElementId("fixed");
  fixed_child = GetLayoutObjectByElementId("fixed-child");
  EXPECT_EQ(1u, NumFragments(fixed));
  EXPECT_EQ(1u, NumFragments(fixed_child));
}

TEST_P(PaintPropertyTreeBuilderTest,
       FloatPaintOffsetInContainerWithScrollbars) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar {width: 15px; height: 15px}
      .container {
        position: absolute; width: 200px; height: 200px; overflow: scroll;
      }
      .float-left {float: left; width: 100px; height: 100px;}
      .float-right {float: right; width: 100px; height: 100px;}
    </style>
    <div class="container">
      <div id="float-left" class="float-left"></div>
      <div id="float-right" class="float-right"></div>
    </div>
    <div class="container" style="direction: rtl">
      <div id="float-left-rtl" class="float-left"></div>
      <div id="float-right-rtl" class="float-right"></div>
    </div>
    <div class="container" style="writing-mode: vertical-rl">
      <div id="float-left-vrl" class="float-left"></div>
      <div id="float-right-vrl" class="float-right"></div>
    </div>
    <div class="container" style="writing-mode: vertical-rl; direction: rtl">
      <div id="float-left-rtl-vrl" class="float-left"></div>
      <div id="float-right-rtl-vrl" class="float-right"></div>
    </div>
    <div class="container" style="writing-mode: vertical-lr">
      <div id="float-left-vlr" class="float-left"></div>
      <div id="float-right-vlr" class="float-right"></div>
    </div>
    <div class="container" style="writing-mode: vertical-lr; direction: rtl">
      <div id="float-left-rtl-vlr" class="float-left"></div>
      <div id="float-right-rtl-vlr" class="float-right"></div>
    </div>
  )HTML");

  auto paint_offset = [this](const char* id) {
    return GetLayoutObjectByElementId(id)->FirstFragment().PaintOffset();
  };
  EXPECT_EQ(PhysicalOffset(), paint_offset("float-left"));
  EXPECT_EQ(PhysicalOffset(85, 100), paint_offset("float-right"));
  EXPECT_EQ(PhysicalOffset(15, 0), paint_offset("float-left-rtl"));
  EXPECT_EQ(PhysicalOffset(100, 100), paint_offset("float-right-rtl"));
  EXPECT_EQ(PhysicalOffset(100, 0), paint_offset("float-left-vrl"));
  EXPECT_EQ(PhysicalOffset(0, 85), paint_offset("float-right-vrl"));
  EXPECT_EQ(PhysicalOffset(100, 0), paint_offset("float-left-rtl-vrl"));
  EXPECT_EQ(PhysicalOffset(0, 85), paint_offset("float-right-rtl-vrl"));
  EXPECT_EQ(PhysicalOffset(), paint_offset("float-left-vlr"));
  EXPECT_EQ(PhysicalOffset(100, 85), paint_offset("float-right-vlr"));
  EXPECT_EQ(PhysicalOffset(), paint_offset("float-left-rtl-vlr"));
  EXPECT_EQ(PhysicalOffset(100, 85), paint_offset("float-right-rtl-vlr"));
}

TEST_P(PaintPropertyTreeBuilderTest, PaintOffsetForTextareaWithResizer) {
  GetPage().GetSettings().SetTextAreasAreResizable(true);
  SetBodyInnerHTML(R"HTML(
    <!doctype HTML>
    <style>
      div {
        width: 100%;
        height: 100px;
      }
      textarea {
        width: 200px;
        height: 100px;
      }
      ::-webkit-resizer {
        background-color: red;
      }
    </style>
    <div></div>
    <textarea id="target"></textarea>
  )HTML");

  const auto* box = GetLayoutBoxByElementId("target");
  const auto& fragment = box->FirstFragment();
  ASSERT_TRUE(fragment.PaintProperties());
  EXPECT_NE(fragment.PaintProperties()->PaintOffsetTranslation(), nullptr);
  EXPECT_EQ(PhysicalOffset(), fragment.PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest, SubpixelPositionedScrollNode) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #scroller {
        position: relative;
        top: 0.5625px;
        width: 200px;
        height: 200.8125px;
        overflow: auto;
      }
      #space {
        width: 1000px;
        height: 200.8125px;
      }
    </style>
    <div id="scroller">
      <div id="space"></div>
    </div>
  )HTML");

  const auto* properties = PaintPropertiesForElement("scroller");
  const auto* scroll_node = properties->ScrollTranslation()->ScrollNode();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 200), scroll_node->ContainerRect());
  EXPECT_EQ(gfx::Rect(0, 0, 1000, 200), scroll_node->ContentsRect());
}

TEST_P(PaintPropertyTreeBuilderTest,
       LayoutMenuListHasOverlowAndLocalBorderBoxProperties) {
  SetBodyInnerHTML(R"HTML(
    <!doctype HTML>
    <select id="selection" style="width: 80px;">
      <option>lorem ipsum dolor</option>
    </select>
  )HTML");

  const auto& fragment = GetDocument()
                             .getElementById(AtomicString("selection"))
                             ->GetLayoutObject()
                             ->FirstFragment();

  EXPECT_TRUE(fragment.PaintProperties());
  EXPECT_TRUE(fragment.PaintProperties()->OverflowClip());
  ASSERT_TRUE(fragment.HasLocalBorderBoxProperties());
  EXPECT_EQ(&fragment.ContentsProperties().Clip(),
            fragment.PaintProperties()->OverflowClip());
}

TEST_P(PaintPropertyTreeBuilderTest, EmptyClipFragments) {
  SetBodyInnerHTML(R"HTML(
    <!doctype HTML>
    <style>h4 { column-span: all; }</style>
    <div id="container" style="columns:1;">
      <div id="wrapper">
        lorem
        <h4>hi</h4>
        <div><h4>hello</h4></div>
        ipsum
      </div>
    </div>
  )HTML");

  const auto* wrapper =
      GetDocument().getElementById(AtomicString("wrapper"))->GetLayoutObject();

  ASSERT_EQ(3u, NumFragments(wrapper));
  ASSERT_EQ(0u, FragmentAt(wrapper, 0).FragmentID());
  ASSERT_EQ(1u, FragmentAt(wrapper, 1).FragmentID());
  ASSERT_EQ(2u, FragmentAt(wrapper, 2).FragmentID());
}

TEST_P(PaintPropertyTreeBuilderTest, StickyConstraintChain) {
  // This test verifies the property tree builder set up sticky constraint
  // chain properly in case of nested sticky positioned elements.
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="overflow:scroll; width:300px; height:200px;">
      <div id="outer" style="position:sticky; top:10px;">
        <div style="height:300px;">
          <span id="middle" style="position:sticky; top:25px;">
            <span id="inner" style="position:sticky; top:45px;"></span>
          </span>
        </div>
      </div>
      <div style="height:1000px;"></div>
    </div>
  )HTML");
  GetDocument().getElementById(AtomicString("scroller"))->setScrollTop(50);
  UpdateAllLifecyclePhasesForTest();

  const auto* outer_properties = PaintPropertiesForElement("outer");
  ASSERT_TRUE(outer_properties && outer_properties->StickyTranslation());
  EXPECT_TRUE(outer_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 60),
            outer_properties->StickyTranslation()->Get2dTranslation());
  ASSERT_NE(nullptr,
            outer_properties->StickyTranslation()->GetStickyConstraint());
  EXPECT_EQ(CompositorElementId(), outer_properties->StickyTranslation()
                                       ->GetStickyConstraint()
                                       ->nearest_element_shifting_sticky_box);
  EXPECT_EQ(CompositorElementId(),
            outer_properties->StickyTranslation()
                ->GetStickyConstraint()
                ->nearest_element_shifting_containing_block);

  const auto* middle_properties = PaintPropertiesForElement("middle");
  ASSERT_TRUE(middle_properties && middle_properties->StickyTranslation());
  EXPECT_TRUE(middle_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 15),
            middle_properties->StickyTranslation()->Get2dTranslation());
  ASSERT_NE(nullptr,
            middle_properties->StickyTranslation()->GetStickyConstraint());
  EXPECT_EQ(CompositorElementId(), middle_properties->StickyTranslation()
                                       ->GetStickyConstraint()
                                       ->nearest_element_shifting_sticky_box);
  EXPECT_EQ(outer_properties->StickyTranslation()->GetCompositorElementId(),
            middle_properties->StickyTranslation()
                ->GetStickyConstraint()
                ->nearest_element_shifting_containing_block);

  const auto* inner_properties = PaintPropertiesForElement("inner");
  ASSERT_TRUE(inner_properties && inner_properties->StickyTranslation());
  EXPECT_TRUE(inner_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 20),
            inner_properties->StickyTranslation()->Get2dTranslation());
  ASSERT_NE(nullptr,
            inner_properties->StickyTranslation()->GetStickyConstraint());
  EXPECT_EQ(middle_properties->StickyTranslation()->GetCompositorElementId(),
            inner_properties->StickyTranslation()
                ->GetStickyConstraint()
                ->nearest_element_shifting_sticky_box);
  EXPECT_EQ(outer_properties->StickyTranslation()->GetCompositorElementId(),
            inner_properties->StickyTranslation()
                ->GetStickyConstraint()
                ->nearest_element_shifting_containing_block);
}

TEST_P(PaintPropertyTreeBuilderTest, StickyUnderOverflowHidden) {
  // This test verifies the property tree builder applies sticky offset
  // correctly when the scroll container doesn't have a scroll node, and
  // does not emit sticky constraints.
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="overflow:hidden; width:300px; height:200px;">
      <div id="outer" style="position:sticky; top:10px;">
        <div style="height:300px;">
          <span id="middle" style="position:sticky; top:25px;">
            <span id="inner" style="position:sticky; top:45px;"></span>
          </span>
        </div>
      </div>
      <div style="height:1000px;"></div>
    </div>
  )HTML");

  const auto* outer_properties = PaintPropertiesForElement("outer");
  ASSERT_TRUE(outer_properties && outer_properties->StickyTranslation());
  // We still composite the element for better performance programmatic scroll
  // offset animation.
  EXPECT_TRUE(outer_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 10),
            outer_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_EQ(nullptr,
            outer_properties->StickyTranslation()->GetStickyConstraint());

  const auto* middle_properties = PaintPropertiesForElement("middle");
  ASSERT_TRUE(middle_properties && middle_properties->StickyTranslation());
  EXPECT_TRUE(middle_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 15),
            middle_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_EQ(nullptr,
            middle_properties->StickyTranslation()->GetStickyConstraint());

  const auto* inner_properties = PaintPropertiesForElement("inner");
  ASSERT_TRUE(inner_properties && inner_properties->StickyTranslation());
  EXPECT_TRUE(inner_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 20),
            inner_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_EQ(nullptr,
            inner_properties->StickyTranslation()->GetStickyConstraint());

  // The overflow:hidden scroller will create a scroll node when the scroll
  // offset is not zero.
  GetDocument().getElementById(AtomicString("scroller"))->setScrollTop(50);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(outer_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 60),
            outer_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_NE(nullptr,
            outer_properties->StickyTranslation()->GetStickyConstraint());

  ASSERT_TRUE(middle_properties && middle_properties->StickyTranslation());
  EXPECT_TRUE(middle_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 15),
            middle_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_NE(nullptr,
            middle_properties->StickyTranslation()->GetStickyConstraint());

  ASSERT_TRUE(inner_properties && inner_properties->StickyTranslation());
  EXPECT_TRUE(inner_properties->StickyTranslation()
                  ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 20),
            inner_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_NE(nullptr,
            inner_properties->StickyTranslation()->GetStickyConstraint());
}

TEST_P(PaintPropertyTreeBuilderTest, StickyUnderScrollerWithoutOverflow) {
  // This test verifies the property tree builder applies sticky offset
  // correctly when the scroll container doesn't have overflow, and does not
  // emit compositing reasons or sticky constraints.
  SetBodyInnerHTML(R"HTML(
    <div id="scroller" style="overflow:scroll; width:300px; height:400px;">
      <div id="outer" style="position:sticky; top:10px;">
        <div style="height:300px;">
          <span id="middle" style="position:sticky; top:25px;">
            <span id="inner" style="position:sticky; top:45px;"></span>
          </span>
        </div>
      </div>
    </div>
  )HTML");

  const auto* outer_properties = PaintPropertiesForElement("outer");
  ASSERT_TRUE(outer_properties && outer_properties->StickyTranslation());
  EXPECT_FALSE(outer_properties->StickyTranslation()
                   ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 10),
            outer_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_EQ(nullptr,
            outer_properties->StickyTranslation()->GetStickyConstraint());

  const auto* middle_properties = PaintPropertiesForElement("middle");
  ASSERT_TRUE(middle_properties && middle_properties->StickyTranslation());
  EXPECT_FALSE(middle_properties->StickyTranslation()
                   ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 15),
            middle_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_EQ(nullptr,
            middle_properties->StickyTranslation()->GetStickyConstraint());

  const auto* inner_properties = PaintPropertiesForElement("inner");
  ASSERT_TRUE(inner_properties && inner_properties->StickyTranslation());
  EXPECT_FALSE(inner_properties->StickyTranslation()
                   ->RequiresCompositingForStickyPosition());
  EXPECT_EQ(gfx::Vector2dF(0, 20),
            inner_properties->StickyTranslation()->Get2dTranslation());
  EXPECT_EQ(nullptr,
            inner_properties->StickyTranslation()->GetStickyConstraint());
}

TEST_P(PaintPropertyTreeBuilderTest, WillChangeOpacityInducesAnEffectNode) {
  SetBodyInnerHTML(R"HTML(
    <style>.transluscent { opacity: 0.5; }</style>
    <div id="div" style="width:10px; height:10px; will-change: opacity;"></div>
  )HTML");

  const auto* properties = PaintPropertiesForElement("div");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->Effect());
  EXPECT_FLOAT_EQ(properties->Effect()->Opacity(), 1.f);

  auto* div = GetDocument().getElementById(AtomicString("div"));
  div->setAttribute(html_names::kClassAttr, AtomicString("transluscent"));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(
      To<LayoutBox>(div->GetLayoutObject())->Layer()->SelfNeedsRepaint());

  ASSERT_TRUE(properties->Effect());
  EXPECT_FLOAT_EQ(properties->Effect()->Opacity(), 0.5f);
}

TEST_P(PaintPropertyTreeBuilderTest, EffectOutputClipWithFixedDescendant) {
  SetBodyInnerHTML(R"HTML(
    <!-- Case 1: No clip. -->
    <div id="target1" style="opacity: 0.1">
      <div style="position: fixed"></div>
    </div>
    <!-- Case 2: Clip under the container of fixed-position (the LayoutView) -->
    <div style="overflow: hidden">
      <div id="target2" style="opacity: 0.1">
        <div style="position: fixed"></div>
      </div>
    </div>
    <!-- Case 3: Clip above the container of fixed-position. -->
    <div id="clip3" style="overflow: hidden">
      <div style="transform: translateY(0)">
        <div id="target3" style="opacity: 0.1">
          <div style="position: fixed"></div>
        </div>
      </div>
    </div>
    <!-- Case 4: Clip on the container of fixed-position. -->
    <div id="clip4" style="overflow: hidden; transform: translateY(0)">
      <div id="target4" style="opacity: 0.1">
        <div style="position: fixed"></div>
      </div>
    </div>
    <!-- Case 5: The container of fixed-position is not a LayoutBlock. -->
    <table>
      <tr style="transform: translateY(0)">
        <td id="target5" style="opacity: 0.1">
          <div style="position: fixed"></div>
        </td>
      </tr>
    </table>
  )HTML");

  EXPECT_EQ(DocContentClip(),
            PaintPropertiesForElement("target1")->Effect()->OutputClip());
  // OutputClip is null because the fixed descendant escapes the effect's
  // current clip.
  EXPECT_EQ(nullptr,
            PaintPropertiesForElement("target2")->Effect()->OutputClip());
  EXPECT_EQ(PaintPropertiesForElement("clip3")->OverflowClip(),
            PaintPropertiesForElement("target3")->Effect()->OutputClip());
  EXPECT_EQ(PaintPropertiesForElement("clip4")->OverflowClip(),
            PaintPropertiesForElement("target4")->Effect()->OutputClip());
  EXPECT_EQ(DocContentClip(),
            PaintPropertiesForElement("target5")->Effect()->OutputClip());
}

TEST_P(PaintPropertyTreeBuilderTest, TableColOpacity) {
  SetBodyInnerHTML(R"HTML(
    <table>
      <col id="col" style="opacity: 0.5">
    </table>
  )HTML");

  // TODO(crbug.com/892734): For now table col doesn't support effects.
  EXPECT_EQ(nullptr, PaintPropertiesForElement("col"));
}

// Test the WebView API that allows rendering the whole page. In this case, we
// shouldn't create a clip node for the main frame.
TEST_P(PaintPropertyTreeBuilderTest, MainFrameDoesntClipContent) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      body,html {
        margin: 0;
        width: 100%;
        height: 100%;
      }
    </style>
  )HTML");

  EXPECT_TRUE(
      GetLayoutView().FirstFragment().PaintProperties()->OverflowClip());

  GetPage().GetSettings().SetMainFrameClipsContent(false);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(
      GetLayoutView().FirstFragment().PaintProperties()->OverflowClip());

  GetPage().GetSettings().SetMainFrameClipsContent(true);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(
      GetLayoutView().FirstFragment().PaintProperties()->OverflowClip());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootCompositedClipPathSimple) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg' style='clip-path: circle(); will-change: opacity'></svg>
  )HTML");

  const auto* properties = PaintPropertiesForElement("svg");

  const auto* transform = properties->PaintOffsetTranslation();
  ASSERT_NE(nullptr, transform);
  EXPECT_EQ(nullptr, properties->MaskClip());

  const auto* clip_path_clip = properties->ClipPathClip();
  ASSERT_NE(nullptr, clip_path_clip);
  EXPECT_EQ(DocContentClip(), clip_path_clip->Parent());
  EXPECT_CLIP_RECT(FloatRoundedRect(gfx::RectF(75, 0, 150, 150), 75),
                   clip_path_clip);
  EXPECT_EQ(transform, &clip_path_clip->LocalTransformSpace());
  EXPECT_FALSE(clip_path_clip->ClipPath());

  const auto* overflow_clip = properties->OverflowClip();
  ASSERT_NE(nullptr, overflow_clip);
  EXPECT_EQ(clip_path_clip, overflow_clip->Parent());
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 300, 150), overflow_clip);
  EXPECT_EQ(transform, &overflow_clip->LocalTransformSpace());

  const auto* effect = properties->Effect();
  ASSERT_NE(nullptr, effect);
  EXPECT_EQ(DocEffect(), effect->Parent());
  EXPECT_EQ(transform, &effect->LocalTransformSpace());
  EXPECT_EQ(clip_path_clip, effect->OutputClip());
  EXPECT_EQ(SkBlendMode::kSrcOver, effect->BlendMode());

  EXPECT_EQ(nullptr, properties->Mask());
  EXPECT_EQ(nullptr, properties->ClipPathMask());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootCompositedClipPathComplex) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg'
         style='clip-path: polygon(75px 0, 225px 150px, 75px 150px, 75px 0);
                will-change: opacity'></svg>
  )HTML");

  const auto* properties = PaintPropertiesForElement("svg");

  const auto* transform = properties->PaintOffsetTranslation();
  ASSERT_NE(nullptr, transform);
  EXPECT_EQ(nullptr, properties->MaskClip());

  const auto* clip_path_clip = properties->ClipPathClip();
  ASSERT_NE(nullptr, clip_path_clip);
  EXPECT_EQ(DocContentClip(), clip_path_clip->Parent());
  EXPECT_CLIP_RECT(gfx::RectF(75, 0, 150, 150), clip_path_clip);
  EXPECT_EQ(transform, &clip_path_clip->LocalTransformSpace());
  EXPECT_TRUE(clip_path_clip->ClipPath());

  const auto* overflow_clip = properties->OverflowClip();
  ASSERT_NE(nullptr, overflow_clip);
  EXPECT_EQ(clip_path_clip, overflow_clip->Parent());
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 300, 150), overflow_clip);
  EXPECT_EQ(transform, &overflow_clip->LocalTransformSpace());

  const auto* effect = properties->Effect();
  ASSERT_NE(nullptr, effect);
  EXPECT_TRUE(effect->HasDirectCompositingReasons());
  EXPECT_EQ(DocEffect(), effect->Parent());
  EXPECT_EQ(transform, &effect->LocalTransformSpace());
  EXPECT_EQ(clip_path_clip, effect->OutputClip());
  EXPECT_EQ(SkBlendMode::kSrcOver, effect->BlendMode());

  EXPECT_EQ(nullptr, properties->Mask());
  EXPECT_EQ(nullptr, properties->ClipPathMask());
}

TEST_P(PaintPropertyTreeBuilderTest, SimpleOpacityChangeDoesNotCausePacUpdate) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      div {
        width: 100px;
        height: 100px;
        opacity: 0.5;
        will-change: opacity;
      }
    </style>
    <div id="element"></div>
  )HTML");

  auto* pac = GetDocument().View()->GetPaintArtifactCompositor();
  ASSERT_TRUE(pac);

  const auto* properties = PaintPropertiesForElement("element");
  ASSERT_TRUE(properties);
  ASSERT_TRUE(properties->Effect());
  EXPECT_FLOAT_EQ(properties->Effect()->Opacity(), 0.5f);
  EXPECT_FALSE(pac->NeedsUpdate());

  cc::EffectNode* c
```