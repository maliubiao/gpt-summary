Response:
The user wants a summary of the functionality of the C++ code provided. This file seems to be a test suite for `PaintPropertyTreeBuilder` in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `paint_property_tree_builder_test.cc` clearly indicates it's a test file for something called `PaintPropertyTreeBuilder`. The `TEST_P` macros confirm this is a parameterized test suite.

2. **Understand what `PaintPropertyTreeBuilder` does:** Based on the test names and the operations within them, the `PaintPropertyTreeBuilder` is responsible for creating and managing the "paint property tree". This tree likely represents how visual properties (like transforms, opacity, clips, etc.) are applied to elements in the rendering process.

3. **Analyze the test cases:** Go through the individual `TEST_P` blocks and identify the specific features or scenarios being tested. Look for patterns in the test names and the HTML/CSS snippets used. Here are some observations:
    * Tests involving `Transform`:  Various scenarios like basic transforms, transforms with perspective, animated transforms, `will-change: transform`.
    * Tests involving `Opacity`:  Basic opacity, animated opacity, nested opacity, opacity across stacking contexts, opacity in SVG.
    * Tests involving `will-change`:  `will-change: transform` and `will-change: contents`.
    * Tests involving SVG:  Transforms in SVG, viewBox transformations, paint offsets in SVG, nested SVGs.
    * Tests involving compositing:  Checking for `HasDirectCompositingReasons`.
    * Tests involving stacking contexts.
    * Tests involving masking (foreignObject).

4. **Connect to web technologies (HTML, CSS, JavaScript):** The test cases use HTML and CSS to set up scenarios. The tests verify how the `PaintPropertyTreeBuilder` interprets these styles. JavaScript's role is implicit in the animation tests, as animations are typically triggered or controlled via JavaScript, even if the test setup doesn't directly show the JS code.

5. **Identify potential user/developer errors:**  Based on the tests, errors might arise from:
    * Incorrectly using `will-change` (or not using it when needed for performance).
    * Misunderstanding how transforms and opacity interact.
    * Incorrectly applying transforms in SVG, especially with `viewBox`.
    * Issues with stacking contexts and how they affect paint properties.

6. **Infer debugging scenarios:**  The tests themselves act as a form of debugging. If a visual rendering issue occurs related to transforms or opacity, these tests (or similar ones) would be used to isolate the problem and verify the behavior of the `PaintPropertyTreeBuilder`.

7. **Structure the summary:** Organize the findings into logical categories (core function, relationship to web technologies, examples, logic, errors, debugging).

8. **Address the "Part 2 of 10" instruction:** Explicitly state that this is a summary of the provided code snippet and that further functionality might be present in the other parts.

**(Self-Correction during thought process):**

* **Initial thought:**  Focus solely on the explicit properties being tested (transform, opacity).
* **Correction:** Realize the tests also implicitly cover compositing, stacking contexts, and how different types of elements (HTML vs. SVG) are handled. Expand the summary to include these aspects.
* **Initial thought:** Only consider explicit JavaScript in the test code.
* **Correction:** Acknowledge JavaScript's role in triggering animations, even if not directly shown in the snippet.
* **Initial thought:**  Focus on individual tests in isolation.
* **Correction:** Recognize the overarching goal of the tests is to validate the correctness and completeness of the `PaintPropertyTreeBuilder`.

By following these steps, we can arrive at a comprehensive and accurate summary of the provided code snippet's functionality.
这是 `blink/renderer/core/paint/paint_property_tree_builder_test.cc` 文件的第二部分，它延续了第一部分的测试用例，主要目的是为了测试 `PaintPropertyTreeBuilder` 类的功能。`PaintPropertyTreeBuilder` 负责根据 HTML、CSS 样式以及一些渲染相关的因素，构建用于描述元素绘制属性的树形结构（Paint Property Tree）。

**本部分的功能归纳如下：**

这部分代码主要集中在测试以下 `PaintPropertyTreeBuilder` 在处理 **transform（变换）** 和 **effect（特效，主要指 opacity 透明度）** 属性时的行为，以及它们与 **SVG** 的交互。具体来说，它测试了：

1. **Transform 相关的测试：**
   - 当元素设置了 `perspective` 属性时，是否正确创建 Transform 节点，并且包含直接合成的原因。
   - 当元素拥有激活的 transform 动画时，是否正确创建 Transform 节点，并且包含直接合成的原因。
   - Transform 动画是否会额外创建 Effect 和 Filter 节点。
   - 当使用 `will-change: transform` 时，是否即使在没有实际 transform 变换的情况下也会创建 Transform 节点，以及后续移除 `will-change` 后节点的移除。
   - `will-change: contents` 是否会阻止 Paint Properties 的创建。
   - 在具有 3D 子元素的父元素上设置 `backface-visibility: hidden` 时，子元素是否需要 Transform 节点来表示其背面可见性。
   - 对于非堆叠上下文的元素设置 `will-change: right` 和 `backface-visibility: hidden` 时，Effect 和 Filter 节点是否不会被创建。
   - 相对定位的 inline 元素是否正确计算 Paint Offset Translation。

2. **Effect (Opacity) 相关的测试：**
   - Opacity 动画是否会额外创建 Transform 和 Filter 节点。
   - 当元素拥有激活的 opacity 动画时，是否正确创建 Effect 节点，并且包含直接合成的原因。
   - 测试嵌套的 opacity 效果，确保父元素的 opacity 会影响子元素，并且正确创建 Effect 节点。
   - 验证 Transform 节点的存在不会影响 Effect 节点的创建和属性。
   - 测试 Effect 节点在跨越堆叠上下文时的行为。

3. **SVG 相关的测试：**
   - 测试 SVG 元素上的 opacity 效果，包括 `<g>`, `<rect>`, `<text>`, `<tspan>` 等元素。
   - 测试 HTML 和 SVG 元素之间 opacity 效果的传递和独立性。
   - 测试 SVG 元素上的 Transform 效果，包括 `transform` 属性和 `transform-origin` 属性。
   - 测试 SVG 的 `viewBox` 属性对 Transform 的影响。
   - 测试 SVG 根元素的 Paint Offset Translation 节点的创建。
   - 测试 SVG 根元素的 Local to Border Box Transform 节点，并验证子元素的 Transform 是否是其子节点。
   - 测试 SVG 根元素在特定情况下进行像素对齐缩放的场景。
   - 测试嵌套 SVG 的 `viewBox` 属性对 Transform 的影响。
   - 测试 HTML 和 SVG 元素之间 Transform 效果的传递。
   - 测试 `foreignObject` 元素上的 Transform 和 Offset 属性。
   - 测试 `foreignObject` 元素上的 Mask 属性。
   - 测试 SVG 和 HTML 元素边界之间的 Paint Offset Translation。
   - 测试 SVG 视口容器的行为。

**与 JavaScript, HTML, CSS 功能的关系：**

- **HTML:** 测试用例通过 `SetBodyInnerHTML` 方法加载 HTML 结构，定义了元素的层级关系和 ID，为后续的 CSS 样式应用和属性检查提供了基础。例如，`<div id='perspective' style='perspective: 800px;'>` 定义了一个设置了 `perspective` 属性的 div 元素。
- **CSS:** 测试用例使用内联样式或者加载外部 CSS 文件来设置元素的视觉属性，例如 `style='opacity: 0.5;'` 设置了元素的透明度，`style='transform: translate3d(10px, 10px, 0px);'` 设置了元素的 3D 变换。`will-change` 属性也是 CSS 的一部分，用于告知浏览器哪些属性将会被动画或频繁修改。
- **JavaScript:**  虽然这段代码没有直接的 JavaScript 代码，但其中的一些测试用例涉及到动画 (`transform-animation.html`, `opacity-animation.html`)。这些动画通常是通过 JavaScript 或者 CSS transitions/animations 来驱动的。`PaintPropertyTreeBuilder` 需要能够正确处理动画过程中属性的变化。

**逻辑推理的假设输入与输出：**

假设输入是一个包含以下 HTML 和 CSS 的文档：

```html
<div id="target" style="opacity: 0.7; transform: translateX(50px);">Hello</div>
```

`PaintPropertyTreeBuilder` 会遍历这个文档的渲染树，并根据 CSS 样式计算出每个元素的绘制属性。

**假设输出：**

对于 `id="target"` 的 `LayoutObject`，会创建一个对应的 `ObjectPaintProperties` 对象，其中：

- `Effect()` 会返回一个 `EffectPaintPropertyNode` 对象，其 `Opacity()` 值为 `0.7`。
- `Transform()` 会返回一个 `TransformPaintPropertyNode` 对象，其表示一个 X 方向的 50px 的平移。
- 这些节点会正确地链接到父节点的相应属性节点上。

**涉及用户或者编程常见的使用错误：**

- **过度使用 `will-change`:**  用户可能会为了“优化性能”而在不必要的情况下对很多元素使用 `will-change`，这实际上可能会导致浏览器分配更多资源，反而影响性能。例如：
  ```html
  <div style="will-change: top, left, width, height, transform, opacity, ...;">
    <!-- 内容 -->
  </div>
  ```
  `PaintPropertyTreeBuilder` 的测试用例会验证在哪些情况下 `will-change` 会触发 Paint Property 节点的创建。
- **误解 transform-origin 对 SVG 元素的影响:**  在 HTML 元素中，`transform-origin` 是相对于元素自身的内容盒子的。但在 SVG 中，它的行为可能有所不同，测试用例 `TransformNodesInSVG` 就验证了这一点。用户可能会因为对二者的理解不一致而导致意想不到的变换效果。
- **不理解 stacking context 对 paint property tree 的影响:** 堆叠上下文会影响 paint property tree 的构建，例如，拥有 `opacity` 属性的元素会创建一个新的堆叠上下文。用户如果不理解这一点，可能会在设置 opacity 时遇到一些渲染上的困惑。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 HTML、CSS 和可能的 JavaScript 代码。**
2. **用户在浏览器中打开该网页。**
3. **浏览器开始解析 HTML 和 CSS，构建 DOM 树和 CSSOM 树。**
4. **布局（Layout）阶段：** 浏览器根据 DOM 树和 CSSOM 树计算出每个元素的位置和大小。在这个阶段会创建 LayoutObject。
5. **绘制（Paint）阶段：** `PaintPropertyTreeBuilder` 被调用，遍历 LayoutObject 树，根据元素的 CSS 属性（如 `transform`, `opacity` 等）以及其他渲染因素，构建 Paint Property Tree。
6. **合成（Composite）阶段：**  浏览器根据 Paint Property Tree 将不同的绘制层合成到屏幕上。

如果在绘制或合成阶段出现问题，例如元素变换不正确、透明度异常等，开发者可能会怀疑是 Paint Property Tree 构建出了问题。这时，他们可能会查看 `PaintPropertyTreeBuilder` 的相关代码和测试用例，例如本文件，来理解属性树的构建逻辑，并尝试复现问题，或者编写新的测试用例来验证他们的假设。

**总结来说，这部分 `paint_property_tree_builder_test.cc` 文件专注于测试 `PaintPropertyTreeBuilder` 在处理 transform 和 effect 属性，以及它们与 SVG 交互时的正确性，确保浏览器能够准确地根据 CSS 样式构建用于绘制的属性树。**

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共10部分，请归纳一下它的功能

"""
>
      </div>
    </div>
  )HTML");

  Element* perspective =
      GetDocument().getElementById(AtomicString("perspective"));
  const ObjectPaintProperties* perspective_properties =
      perspective->GetLayoutObject()->FirstFragment().PaintProperties();

  EXPECT_TRUE(perspective_properties->Transform());
  EXPECT_TRUE(
      perspective_properties->Transform()->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest,
       TransformNodeWithActiveAnimationHasDirectCompositingReason) {
  LoadTestData("transform-animation.html");
  EXPECT_TRUE(PaintPropertiesForElement("target")
                  ->Transform()
                  ->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest,
       TransformAnimationDoesNotCreateEffectAndFilterNodes) {
  LoadTestData("transform-animation.html");
  EXPECT_NE(nullptr, PaintPropertiesForElement("target")->Transform());
  EXPECT_EQ(nullptr, PaintPropertiesForElement("target")->Effect());
  EXPECT_EQ(nullptr, PaintPropertiesForElement("target")->Filter());
}

TEST_P(PaintPropertyTreeBuilderTest,
       OpacityAnimationDoesNotCreateTransformAndFilterNodes) {
  LoadTestData("opacity-animation.html");
  EXPECT_EQ(nullptr, PaintPropertiesForElement("target")->Transform());
  EXPECT_NE(nullptr, PaintPropertiesForElement("target")->Effect());
  EXPECT_EQ(nullptr, PaintPropertiesForElement("target")->Filter());
}

TEST_P(PaintPropertyTreeBuilderTest,
       EffectNodeWithActiveAnimationHasDirectCompositingReason) {
  LoadTestData("opacity-animation.html");
  EXPECT_TRUE(PaintPropertiesForElement("target")
                  ->Effect()
                  ->HasDirectCompositingReasons());
}

TEST_P(PaintPropertyTreeBuilderTest, WillChangeTransform) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0 } </style>
    <div id='transform' style='margin-left: 50px; margin-top: 100px;
        width: 400px; height: 300px;
        will-change: transform'>
    </div>
  )HTML");

  Element* transform = GetDocument().getElementById(AtomicString("transform"));
  const ObjectPaintProperties* transform_properties =
      transform->GetLayoutObject()->FirstFragment().PaintProperties();

  EXPECT_TRUE(transform_properties->Transform()->IsIdentity());
  EXPECT_EQ(gfx::Vector2dF(),
            transform_properties->Transform()->Get2dTranslation());
  EXPECT_EQ(gfx::Point3F(), transform_properties->Transform()->Origin());
  EXPECT_EQ(gfx::Vector2dF(50, 100),
            transform_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_TRUE(transform_properties->Transform()->HasDirectCompositingReasons());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(50, 100, 400, 300),
                          transform->GetLayoutObject(),
                          GetDocument().View()->GetLayoutView());

  transform->setAttribute(html_names::kStyleAttr,
                          AtomicString("margin-left: 50px; margin-top: 100px; "
                                       "width: 400px; height: 300px;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(nullptr,
            transform->GetLayoutObject()->FirstFragment().PaintProperties());

  transform->setAttribute(
      html_names::kStyleAttr,
      AtomicString(
          "margin-left: 50px; margin-top: 100px; width: 400px; height: 300px; "
          "will-change: transform"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(transform->GetLayoutObject()
                  ->FirstFragment()
                  .PaintProperties()
                  ->Transform()
                  ->IsIdentity());
}

TEST_P(PaintPropertyTreeBuilderTest, WillChangeContents) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0 } </style>
    <div id='transform' style='margin-left: 50px; margin-top: 100px;
        width: 400px; height: 300px;
        will-change: transform, contents'>
    </div>
  )HTML");

  Element* transform = GetDocument().getElementById(AtomicString("transform"));
  EXPECT_EQ(nullptr,
            transform->GetLayoutObject()->FirstFragment().PaintProperties());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(50, 100, 400, 300),
                          transform->GetLayoutObject(),
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest,
       BackfaceVisibilityWithPseudoStacking3DChildren) {
  ScopedBackfaceVisibilityInteropForTest bfi_enabled(true);
  SetBodyInnerHTML(R"HTML(
    <div style="backface-visibility: hidden; transform-style: preserve-3d">
      <div id=child style="isolation: isolate"></div>
    </div>
  )HTML");

  // The child needs a transform node to communicate that it is backface
  // visible to the compositor.
  EXPECT_NE(nullptr, PaintPropertiesForElement("child")->Transform());
  EXPECT_EQ(PaintPropertiesForElement("child")
                ->Transform()
                ->GetBackfaceVisibilityForTesting(),
            TransformPaintPropertyNode::BackfaceVisibility::kVisible);
}

TEST_P(PaintPropertyTreeBuilderTest, NoEffectAndFilterForNonStackingContext) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="will-change: right; backface-visibility: hidden">
    </div>
  )HTML");
  EXPECT_NE(nullptr, PaintPropertiesForElement("target")->Transform());
  EXPECT_EQ(nullptr, PaintPropertiesForElement("target")->Effect());
  EXPECT_EQ(nullptr, PaintPropertiesForElement("target")->Filter());
}

TEST_P(PaintPropertyTreeBuilderTest, RelativePositionInline) {
  LoadTestData("relative-position-inline.html");

  Element* inline_block =
      GetDocument().getElementById(AtomicString("inline-block"));
  const ObjectPaintProperties* inline_block_properties =
      inline_block->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(
      gfx::Vector2dF(135, 490),
      inline_block_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            inline_block_properties->PaintOffsetTranslation()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(135, 490, 10, 20),
                          inline_block->GetLayoutObject(),
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, NestedOpacityEffect) {
  SetBodyInnerHTML(R"HTML(
    <div id='nodeWithoutOpacity' style='width: 100px; height: 200px'>
      <div id='childWithOpacity'
          style='opacity: 0.5; width: 50px; height: 60px;'>
        <div id='grandChildWithoutOpacity'
            style='width: 20px; height: 30px'>
          <div id='greatGrandChildWithOpacity'
              style='opacity: 0.2; width: 10px; height: 15px'></div>
        </div>
      </div>
    </div>
  )HTML");

  LayoutObject* node_without_opacity =
      GetLayoutObjectByElementId("nodeWithoutOpacity");
  const auto* data_without_opacity_properties =
      node_without_opacity->FirstFragment().PaintProperties();
  EXPECT_EQ(nullptr, data_without_opacity_properties);
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 100, 200), node_without_opacity,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* child_with_opacity =
      GetLayoutObjectByElementId("childWithOpacity");
  const ObjectPaintProperties* child_with_opacity_properties =
      child_with_opacity->FirstFragment().PaintProperties();
  EXPECT_EQ(0.5f, child_with_opacity_properties->Effect()->Opacity());
  // childWithOpacity is the root effect node.
  EXPECT_NE(nullptr, child_with_opacity_properties->Effect()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 50, 60), child_with_opacity,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* grand_child_without_opacity =
      GetDocument()
          .getElementById(AtomicString("grandChildWithoutOpacity"))
          ->GetLayoutObject();
  EXPECT_EQ(nullptr,
            grand_child_without_opacity->FirstFragment().PaintProperties());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 20, 30),
                          grand_child_without_opacity,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* great_grand_child_with_opacity =
      GetDocument()
          .getElementById(AtomicString("greatGrandChildWithOpacity"))
          ->GetLayoutObject();
  const ObjectPaintProperties* great_grand_child_with_opacity_properties =
      great_grand_child_with_opacity->FirstFragment().PaintProperties();
  EXPECT_EQ(0.2f,
            great_grand_child_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(child_with_opacity_properties->Effect(),
            great_grand_child_with_opacity_properties->Effect()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 10, 15),
                          great_grand_child_with_opacity,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, TransformNodeDoesNotAffectEffectNodes) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #nodeWithOpacity {
        opacity: 0.6;
        width: 100px;
        height: 200px;
      }
      #childWithTransform {
        transform: translate3d(10px, 10px, 0px);
        width: 50px;
        height: 60px;
      }
      #grandChildWithOpacity {
        opacity: 0.4;
        width: 20px;
        height: 30px;
      }
    </style>
    <div id='nodeWithOpacity'>
      <div id='childWithTransform'>
        <div id='grandChildWithOpacity'></div>
      </div>
    </div>
  )HTML");

  LayoutObject* node_with_opacity =
      GetLayoutObjectByElementId("nodeWithOpacity");
  const ObjectPaintProperties* node_with_opacity_properties =
      node_with_opacity->FirstFragment().PaintProperties();
  EXPECT_EQ(0.6f, node_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(DocContentClip(),
            node_with_opacity_properties->Effect()->OutputClip());
  EXPECT_NE(nullptr, node_with_opacity_properties->Effect()->Parent());
  EXPECT_EQ(nullptr, node_with_opacity_properties->Transform());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 100, 200), node_with_opacity,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* child_with_transform =
      GetLayoutObjectByElementId("childWithTransform");
  const ObjectPaintProperties* child_with_transform_properties =
      child_with_transform->FirstFragment().PaintProperties();
  EXPECT_EQ(nullptr, child_with_transform_properties->Effect());
  EXPECT_EQ(gfx::Vector2dF(10, 10),
            child_with_transform_properties->Transform()->Get2dTranslation());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(18, 18, 50, 60), child_with_transform,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* grand_child_with_opacity =
      GetLayoutObjectByElementId("grandChildWithOpacity");
  const ObjectPaintProperties* grand_child_with_opacity_properties =
      grand_child_with_opacity->FirstFragment().PaintProperties();
  EXPECT_EQ(0.4f, grand_child_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(DocContentClip(),
            grand_child_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(node_with_opacity_properties->Effect(),
            grand_child_with_opacity_properties->Effect()->Parent());
  EXPECT_EQ(nullptr, grand_child_with_opacity_properties->Transform());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(18, 18, 20, 30),
                          grand_child_with_opacity,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, EffectNodesAcrossStackingContext) {
  SetBodyInnerHTML(R"HTML(
    <div id='nodeWithOpacity'
        style='opacity: 0.6; width: 100px; height: 200px'>
      <div id='childWithStackingContext'
          style='position:absolute; width: 50px; height: 60px;'>
        <div id='grandChildWithOpacity'
            style='opacity: 0.4; width: 20px; height: 30px'></div>
      </div>
    </div>
  )HTML");

  LayoutObject* node_with_opacity =
      GetLayoutObjectByElementId("nodeWithOpacity");
  const ObjectPaintProperties* node_with_opacity_properties =
      node_with_opacity->FirstFragment().PaintProperties();
  EXPECT_EQ(0.6f, node_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(DocContentClip(),
            node_with_opacity_properties->Effect()->OutputClip());
  EXPECT_NE(nullptr, node_with_opacity_properties->Effect()->Parent());
  EXPECT_EQ(nullptr, node_with_opacity_properties->Transform());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 100, 200), node_with_opacity,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* child_with_stacking_context =
      GetDocument()
          .getElementById(AtomicString("childWithStackingContext"))
          ->GetLayoutObject();
  const ObjectPaintProperties* child_with_stacking_context_properties =
      child_with_stacking_context->FirstFragment().PaintProperties();
  EXPECT_EQ(nullptr, child_with_stacking_context_properties);
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 50, 60),
                          child_with_stacking_context,
                          GetDocument().View()->GetLayoutView());

  LayoutObject* grand_child_with_opacity =
      GetLayoutObjectByElementId("grandChildWithOpacity");
  const ObjectPaintProperties* grand_child_with_opacity_properties =
      grand_child_with_opacity->FirstFragment().PaintProperties();
  EXPECT_EQ(0.4f, grand_child_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(DocContentClip(),
            grand_child_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(node_with_opacity_properties->Effect(),
            grand_child_with_opacity_properties->Effect()->Parent());
  EXPECT_EQ(nullptr, grand_child_with_opacity_properties->Transform());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 20, 30), grand_child_with_opacity,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, EffectNodesInSVG) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svgRoot'>
      <g id='groupWithOpacity' opacity='0.6'>
        <rect id='rectWithoutOpacity' />
        <rect id='rectWithOpacity' opacity='0.4' />
        <text id='textWithOpacity' opacity='0.2'>
          <tspan id='tspanWithOpacity' opacity='0.1' />
        </text>
      </g>
    </svg>
  )HTML");

  const auto* svg_clip = PaintPropertiesForElement("svgRoot")->OverflowClip();

  const auto* group_with_opacity_properties =
      PaintPropertiesForElement("groupWithOpacity");
  EXPECT_EQ(0.6f, group_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(svg_clip, group_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(DocEffect(), group_with_opacity_properties->Effect()->Parent());

  EXPECT_EQ(nullptr, PaintPropertiesForElement("rectWithoutOpacity"));

  const auto* rect_with_opacity_properties =
      PaintPropertiesForElement("rectWithOpacity");
  EXPECT_EQ(0.4f, rect_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(svg_clip, rect_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(group_with_opacity_properties->Effect(),
            rect_with_opacity_properties->Effect()->Parent());

  // Ensure that opacity nodes are created for LayoutSVGText which inherits from
  // LayoutSVGBlock instead of LayoutSVGModelObject.
  const auto* text_with_opacity_properties =
      PaintPropertiesForElement("textWithOpacity");
  EXPECT_EQ(0.2f, text_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(svg_clip, text_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(group_with_opacity_properties->Effect(),
            text_with_opacity_properties->Effect()->Parent());

  // Ensure that opacity nodes are created for LayoutSVGTSpan which inherits
  // from LayoutSVGInline instead of LayoutSVGModelObject.
  const auto* tspan_with_opacity_properties =
      PaintPropertiesForElement("tspanWithOpacity");
  EXPECT_EQ(0.1f, tspan_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(svg_clip, tspan_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(text_with_opacity_properties->Effect(),
            tspan_with_opacity_properties->Effect()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, EffectNodesAcrossHTMLSVGBoundary) {
  SetBodyInnerHTML(R"HTML(
    <div id='divWithOpacity' style='opacity: 0.2;'>
      <svg id='svgRootWithOpacity' style='opacity: 0.3;'>
        <rect id='rectWithOpacity' opacity='0.4' />
      </svg>
    </div>
  )HTML");

  const auto* div_with_opacity_properties =
      PaintPropertiesForElement("divWithOpacity");
  EXPECT_EQ(0.2f, div_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(DocContentClip(),
            div_with_opacity_properties->Effect()->OutputClip());
  EXPECT_NE(nullptr, div_with_opacity_properties->Effect()->Parent());

  const auto* svg_root_with_opacity_properties =
      PaintPropertiesForElement("svgRootWithOpacity");
  EXPECT_EQ(0.3f, svg_root_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(DocContentClip(),
            svg_root_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(div_with_opacity_properties->Effect(),
            svg_root_with_opacity_properties->Effect()->Parent());

  const auto* rect_with_opacity_properties =
      PaintPropertiesForElement("rectWithOpacity");
  EXPECT_EQ(0.4f, rect_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(svg_root_with_opacity_properties->OverflowClip(),
            rect_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(svg_root_with_opacity_properties->Effect(),
            rect_with_opacity_properties->Effect()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, EffectNodesAcrossSVGHTMLBoundary) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svgRootWithOpacity' style='opacity: 0.3;'>
      <foreignObject id='foreignObjectWithOpacity' opacity='0.4' style='overflow: visible;'>
        <body>
          <span id='spanWithOpacity' style='opacity: 0.5'/>
        </body>
      </foreignObject>
    </svg>
  )HTML");

  const auto* svg_root_with_opacity_properties =
      PaintPropertiesForElement("svgRootWithOpacity");
  EXPECT_EQ(0.3f, svg_root_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(DocContentClip(),
            svg_root_with_opacity_properties->Effect()->OutputClip());
  EXPECT_NE(nullptr, svg_root_with_opacity_properties->Effect()->Parent());

  const auto* foreign_object_with_opacity_properties =
      PaintPropertiesForElement("foreignObjectWithOpacity");
  EXPECT_EQ(0.4f, foreign_object_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(svg_root_with_opacity_properties->OverflowClip(),
            foreign_object_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(svg_root_with_opacity_properties->Effect(),
            foreign_object_with_opacity_properties->Effect()->Parent());

  const auto* span_with_opacity_properties =
      PaintPropertiesForElement("spanWithOpacity");
  EXPECT_EQ(0.5f, span_with_opacity_properties->Effect()->Opacity());
  EXPECT_EQ(svg_root_with_opacity_properties->OverflowClip(),
            span_with_opacity_properties->Effect()->OutputClip());
  EXPECT_EQ(foreign_object_with_opacity_properties->Effect(),
            span_with_opacity_properties->Effect()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, TransformNodesInSVG) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0px;
      }
      svg {
        margin-left: 50px;
        transform: translate3d(1px, 2px, 3px);
        position: absolute;
        left: 20px;
        top: 25px;
      }
      rect {
        transform: translate(100px, 100px) rotate(45deg);
        transform-origin: 50px 25px;
      }
    </style>
    <svg id='svgRootWith3dTransform' width='100px' height='100px'>
      <rect id='rectWith2dTransform' width='100px' height='100px' />
    </svg>
  )HTML");

  LayoutObject& svg_root_with3d_transform =
      *GetDocument()
           .getElementById(AtomicString("svgRootWith3dTransform"))
           ->GetLayoutObject();
  const ObjectPaintProperties* svg_root_with3d_transform_properties =
      svg_root_with3d_transform.FirstFragment().PaintProperties();
  EXPECT_EQ(MakeTranslationMatrix(1, 2, 3),
            svg_root_with3d_transform_properties->Transform()->Matrix());
  EXPECT_EQ(gfx::Point3F(50, 50, 0),
            svg_root_with3d_transform_properties->Transform()->Origin());
  EXPECT_EQ(svg_root_with3d_transform_properties->PaintOffsetTranslation(),
            svg_root_with3d_transform_properties->Transform()->Parent());
  EXPECT_EQ(gfx::Vector2dF(70, 25),
            svg_root_with3d_transform_properties->PaintOffsetTranslation()
                ->Get2dTranslation());
  EXPECT_EQ(
      DocScrollTranslation(),
      svg_root_with3d_transform_properties->PaintOffsetTranslation()->Parent());

  LayoutObject& rect_with2d_transform =
      *GetLayoutObjectByElementId("rectWith2dTransform");
  const ObjectPaintProperties* rect_with2d_transform_properties =
      rect_with2d_transform.FirstFragment().PaintProperties();
  gfx::Transform matrix;
  matrix.Translate(100, 100);
  matrix.Rotate(45);
  // SVG's transform origin is baked into the transform.
  matrix.ApplyTransformOrigin(50, 25, 0);
  EXPECT_EQ(matrix, rect_with2d_transform_properties->Transform()->Matrix());
  EXPECT_EQ(gfx::Point3F(0, 0, 0),
            rect_with2d_transform_properties->Transform()->Origin());
  // SVG does not use paint offset.
  EXPECT_EQ(nullptr,
            rect_with2d_transform_properties->PaintOffsetTranslation());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGViewBoxTransform) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0px;
      }
      #svgWithViewBox {
        transform: translate3d(1px, 2px, 3px);
        position: absolute;
        width: 100px;
        height: 100px;
      }
      #rect {
        transform: translate(100px, 100px);
        width: 100px;
        height: 100px;
      }
    </style>
    <svg id='svgWithViewBox' viewBox='50 50 100 100'>
      <rect id='rect' />
    </svg>
  )HTML");

  LayoutObject& svg_with_view_box =
      *GetLayoutObjectByElementId("svgWithViewBox");
  const ObjectPaintProperties* svg_with_view_box_properties =
      svg_with_view_box.FirstFragment().PaintProperties();
  EXPECT_EQ(MakeTranslationMatrix(1, 2, 3),
            svg_with_view_box_properties->Transform()->Matrix());
  EXPECT_EQ(gfx::Vector2dF(-50, -50),
            svg_with_view_box_properties->ReplacedContentTransform()
                ->Get2dTranslation());
  EXPECT_EQ(svg_with_view_box_properties->ReplacedContentTransform()->Parent(),
            svg_with_view_box_properties->Transform());

  LayoutObject& rect = *GetLayoutObjectByElementId("rect");
  const ObjectPaintProperties* rect_properties =
      rect.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(100, 100),
            rect_properties->Transform()->Get2dTranslation());
  EXPECT_EQ(svg_with_view_box_properties->ReplacedContentTransform(),
            rect_properties->Transform()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootPaintOffsetTransformNode) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0px; }
      #svg {
        margin-left: 50px;
        margin-top: 25px;
        width: 100px;
        height: 100px;
      }
    </style>
    <svg id='svg' />
  )HTML");

  LayoutObject& svg = *GetLayoutObjectByElementId("svg");
  const ObjectPaintProperties* svg_properties =
      svg.FirstFragment().PaintProperties();
  EXPECT_TRUE(svg_properties->PaintOffsetTranslation());
  EXPECT_EQ(gfx::Vector2dF(50, 25),
            svg_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(nullptr, svg_properties->ReplacedContentTransform());
  EXPECT_EQ(DocScrollTranslation(),
            svg_properties->PaintOffsetTranslation()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootLocalToBorderBoxTransformNode) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0px; }
      svg {
        margin-left: 2px;
        margin-top: 3px;
        transform: translate(5px, 7px);
        border: 11px solid green;
      }
    </style>
    <svg id='svg' width='100px' height='100px' viewBox='0 0 13 13'>
      <rect id='rect' transform='translate(17 19)' />
    </svg>
  )HTML");

  LayoutObject& svg = *GetLayoutObjectByElementId("svg");
  const ObjectPaintProperties* svg_properties =
      svg.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(2, 3),
            svg_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(gfx::Vector2dF(5, 7),
            svg_properties->Transform()->Get2dTranslation());
  auto matrix = MakeTranslationMatrix(11, 11);
  matrix.Scale(100.0 / 13.0);
  EXPECT_TRANSFORM_EQ(matrix,
                      svg_properties->ReplacedContentTransform()->Matrix());
  EXPECT_EQ(svg_properties->PaintOffsetTranslation(),
            svg_properties->Transform()->Parent());
  EXPECT_EQ(svg_properties->Transform(),
            svg_properties->ReplacedContentTransform()->Parent());

  // Ensure the rect's transform is a child of the local to border box
  // transform.
  LayoutObject& rect = *GetLayoutObjectByElementId("rect");
  const ObjectPaintProperties* rect_properties =
      rect.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(17, 19),
            rect_properties->Transform()->Get2dTranslation());
  EXPECT_EQ(svg_properties->ReplacedContentTransform(),
            rect_properties->Transform()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootLocalToBorderBoxSnappingScale) {
  ScopedSvgInlineRootPixelSnappingScaleAdjustmentForTest snapscale_enabled(
      true);
  SetBodyInnerHTML(R"HTML(
    <style>
      svg {
        height: 99.99px;
        position: absolute;
        top: 0.5px;
        width: 100px;
      }
    </style>
    <div style="position: relative">
      <svg id="svg">
        <circle cx="50" cy="50" r="50"/>
      </svg>
    </div>
  )HTML");

  const LayoutObject& svg = *GetLayoutObjectByElementId("svg");
  const ObjectPaintProperties* svg_properties =
      svg.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(8, 9),
            svg_properties->PaintOffsetTranslation()->Get2dTranslation());
  const float snapped_height = 99;
  const float unsnapped_height = LayoutUnit(99.99f).ToFloat();
  ASSERT_NE(svg_properties->ReplacedContentTransform(), nullptr);
  EXPECT_TRANSFORM_EQ(MakeScaleMatrix(snapped_height / unsnapped_height),
                      svg_properties->ReplacedContentTransform()->Matrix());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGNestedViewboxTransforms) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0px; } </style>
    <svg id='svg' width='100px' height='100px' viewBox='0 0 50 50'
        style='transform: translate(11px, 11px);'>
      <svg id='nestedSvg' width='50px' height='50px' viewBox='0 0 5 5'>
        <rect id='rect' transform='translate(13 13)' />
      </svg>
    </svg>
  )HTML");

  LayoutObject& svg = *GetLayoutObjectByElementId("svg");
  const ObjectPaintProperties* svg_properties =
      svg.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(11, 11),
            svg_properties->Transform()->Get2dTranslation());
  EXPECT_EQ(MakeScaleMatrix(2),
            svg_properties->ReplacedContentTransform()->Matrix());

  LayoutObject& nested_svg = *GetLayoutObjectByElementId("nestedSvg");
  const ObjectPaintProperties* nested_svg_properties =
      nested_svg.FirstFragment().PaintProperties();
  EXPECT_EQ(MakeScaleMatrix(10), nested_svg_properties->Transform()->Matrix());
  EXPECT_EQ(nullptr, nested_svg_properties->ReplacedContentTransform());
  EXPECT_EQ(svg_properties->ReplacedContentTransform(),
            nested_svg_properties->Transform()->Parent());

  LayoutObject& rect = *GetLayoutObjectByElementId("rect");
  const ObjectPaintProperties* rect_properties =
      rect.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(13, 13),
            rect_properties->Transform()->Get2dTranslation());
  EXPECT_EQ(nested_svg_properties->Transform(),
            rect_properties->Transform()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, TransformNodesAcrossSVGHTMLBoundary) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0px; } </style>
    <svg id='svgWithTransform'
        style='transform: translate3d(1px, 2px, 3px);'>
      <foreignObject>
        <body>
          <div id='divWithTransform'
              style='transform: translate3d(3px, 4px, 5px);'></div>
        </body>
      </foreignObject>
    </svg>
  )HTML");

  LayoutObject& svg_with_transform =
      *GetLayoutObjectByElementId("svgWithTransform");
  const ObjectPaintProperties* svg_with_transform_properties =
      svg_with_transform.FirstFragment().PaintProperties();
  EXPECT_EQ(MakeTranslationMatrix(1, 2, 3),
            svg_with_transform_properties->Transform()->Matrix());

  LayoutObject& div_with_transform =
      *GetLayoutObjectByElementId("divWithTransform");
  const ObjectPaintProperties* div_with_transform_properties =
      div_with_transform.FirstFragment().PaintProperties();
  EXPECT_EQ(MakeTranslationMatrix(3, 4, 5),
            div_with_transform_properties->Transform()->Matrix());
  // Ensure the div's transform node is a child of the svg's transform node.
  EXPECT_EQ(svg_with_transform_properties->Transform(),
            div_with_transform_properties->Transform()->Parent()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, ForeignObjectWithTransformAndOffset) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0px; } </style>
    <svg id='svgWithTransform'>
      <foreignObject id="foreignObject"
          x="10" y="10" width="50" height="40" transform="scale(5)">
        <div id='div'></div>
      </foreignObject>
    </svg>
  )HTML");

  LayoutObject& foreign_object = *GetLayoutObjectByElementId("foreignObject");
  const ObjectPaintProperties* foreign_object_properties =
      foreign_object.FirstFragment().PaintProperties();
  EXPECT_EQ(MakeScaleMatrix(5),
            foreign_object_properties->Transform()->Matrix());
  EXPECT_EQ(PhysicalOffset(10, 10),
            foreign_object.FirstFragment().PaintOffset());
  EXPECT_EQ(nullptr, foreign_object_properties->PaintOffsetTranslation());

  LayoutObject& div = *GetLayoutObjectByElementId("div");
  EXPECT_EQ(PhysicalOffset(10, 10), div.FirstFragment().PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest, ForeignObjectWithMask) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0px; } </style>
    <svg id='svg' style='position; relative'>
      <foreignObject id="foreignObject"
          x="10" y="10" width="50" height="40"
          style="-webkit-mask:linear-gradient(red,red)">
        <div id='div'></div>
      </foreignObject>
    </svg>
  )HTML");

  LayoutObject& svg = *GetLayoutObjectByElementId("svg");
  LayoutObject& foreign_object = *GetLayoutObjectByElementId("foreignObject");
  const ObjectPaintProperties* foreign_object_properties =
      foreign_object.FirstFragment().PaintProperties();
  EXPECT_TRUE(foreign_object_properties->Mask());
  EXPECT_EQ(foreign_object_properties->MaskClip()->Parent(),
            foreign_object_properties->Mask()->OutputClip());
  EXPECT_EQ(&svg.FirstFragment().LocalBorderBoxProperties().Transform(),
            &foreign_object_properties->Mask()->LocalTransformSpace());
}

TEST_P(PaintPropertyTreeBuilderTest, PaintOffsetTranslationSVGHTMLBoundary) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg'
      <foreignObject>
        <body>
          <div id='divWithTransform'
              style='transform: translate3d(3px, 4px, 5px);'></div>
        </body>
      </foreignObject>
    </svg>
  )HTML");

  LayoutObject& svg = *GetLayoutObjectByElementId("svg");
  const ObjectPaintProperties* svg_properties =
      svg.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(8, 8),
            svg_properties->PaintOffsetTranslation()->Get2dTranslation());

  LayoutObject& div_with_transform =
      *GetLayoutObjectByElementId("divWithTransform");
  const ObjectPaintProperties* div_with_transform_properties =
      div_with_transform.FirstFragment().PaintProperties();
  EXPECT_EQ(MakeTranslationMatrix(3, 4, 5),
            div_with_transform_properties->Transform()->Matrix());
  EXPECT_EQ(gfx::Vector2dF(8, 158),
            div_with_transform_properties->PaintOffsetTranslation()
                ->Get2dTranslation());
  EXPECT_EQ(div_with_transform_properties->PaintOffsetTranslation(),
            div_with_transform_properties->Transform()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGViewportContainer) {
  SetBodyInnerHTML(R"HTML(
    <!-- border radius of inner svg elemnents should be ignored. -->
    <style>svg { border-radius: 10px }</style>
    <svg id='svg'>
      <svg id='container1' width='30' height='30'></svg>
      <svg id='container2'
          width='30' height='30' x='40' y='50' viewBox='0 0 60 60'></svg>
      <svg id='container3' overflow='visible' width='30' height='30'></svg>
 
"""


```