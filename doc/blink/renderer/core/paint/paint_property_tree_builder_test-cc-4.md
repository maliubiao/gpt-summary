Response:
The user is asking for a summary of the functionality of the `paint_property_tree_builder_test.cc` file in the Chromium Blink engine. They also want to know how it relates to web technologies like JavaScript, HTML, and CSS, including examples and debugging information.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `paint_property_tree_builder_test.cc` strongly suggests this file contains unit tests for the "Paint Property Tree Builder." This builder is a crucial component in the rendering pipeline.

2. **Understand the Paint Property Tree:**  Recall (or quickly look up) what the Paint Property Tree is. It's a hierarchical representation of painting-related properties (transformations, clips, effects, etc.) applied to elements. This tree optimizes rendering by allowing sharing and inheritance of these properties.

3. **Relate to web technologies:**
    * **CSS:**  The properties in the Paint Property Tree are directly derived from CSS styles (e.g., `transform`, `opacity`, `clip-path`, `overflow`).
    * **HTML:** The structure of the HTML document is the basis for building the Paint Property Tree. The relationships between elements (parent-child) are crucial for property inheritance.
    * **JavaScript:** While JavaScript doesn't directly build the tree, it can manipulate the DOM and CSS styles, which in turn triggers the rebuilding of the Paint Property Tree. Animation and dynamic style changes are good examples.

4. **Analyze the provided code snippets:** The code uses the Chromium testing framework (`TEST_P`, `ASSERT_TRUE`, `EXPECT_TRUE`, `CHECK_EXACT_VISUAL_RECT`). The tests primarily focus on verifying the structure and correctness of the Paint Property Tree under various CSS scenarios. Key CSS properties to watch for are `transform`, `transform-style`, `perspective`, `overflow`, `clip`, and `contain`.

5. **Identify key functionalities being tested:**  Based on the test names and the code within them, identify the specific aspects of the Paint Property Tree Builder being verified:
    * **Transform inheritance and flattening:** How `transform` properties are inherited and how certain properties or conditions (like `transform-style: flat`) can prevent inheritance.
    * **3D rendering contexts:** How `transform-style: preserve-3d` and `perspective` influence the creation of 3D rendering contexts in the tree.
    * **Property caching:**  How the builder reuses existing property nodes when styles change to improve performance.
    * **Scroll and clip behavior:** How `overflow` and `clip` properties create clip and scroll nodes in the tree, and how they interact with element content.
    * **Containment:** How the `contain` property affects the creation of isolation nodes in the tree.
    * **Replaced content (like SVG):** How transformations are applied to and handled for replaced content.

6. **Provide concrete examples:** For each functionality, extract relevant code snippets and explain how they illustrate the concept. Focus on the CSS and the assertions made in the tests.

7. **Infer logical reasoning (with assumptions):**  The tests implicitly make assumptions about the input (HTML/CSS) and the expected output (structure of the Paint Property Tree, visual rendering). Explicitly state these assumptions. For example, a test setting `transform: translateZ(0)` on a parent and child and then asserting on the ancestor relationship of the transform nodes is based on the assumption of default transform behavior.

8. **Consider common user/programming errors:** Think about how developers might misuse the CSS features being tested and how that would relate to the Paint Property Tree. For instance, misunderstanding `transform-style: preserve-3d` can lead to unexpected flattening of 3D effects. Incorrectly using `overflow: hidden` might unintentionally clip content.

9. **Explain the debugging path:** Describe how a developer might end up looking at this test file. This usually involves encountering rendering issues, suspecting a problem with how painting properties are being applied, and then looking at the tests to understand the expected behavior or to potentially debug the builder itself.

10. **Summarize the functionality (as requested):**  Condense the findings into a concise summary statement.

11. **Structure the answer clearly:** Use headings, bullet points, and code formatting to make the information easy to read and understand.

12. **Address the "part 5 of 10" instruction:**  Acknowledge this and reiterate the overall function of the file within the larger context of the rendering engine tests.
好的，根据您提供的代码片段，我来归纳一下 `paint_property_tree_builder_test.cc` 文件（第 5 部分）的功能：

**核心功能：**

这个文件的主要功能是 **测试 Blink 渲染引擎中 Paint Property Tree Builder 的正确性**。Paint Property Tree Builder 负责根据 DOM 结构和 CSS 样式计算并构建用于渲染的 Paint Property Tree。这个 Tree 结构优化了渲染流程，使得具有相同或相似绘制属性的元素可以共享属性节点，从而提高渲染效率。

**具体测试内容（基于提供的代码片段）：**

这部分测试主要关注以下几个方面与 Paint Property Tree 的构建：

1. **Transform 的继承与 Flattening (扁平化):**
   - 测试了当父元素设置了 `transform`，子元素也设置了 `transform` 时，Paint Property Tree 中 Transform 节点的父子关系以及是否会发生 transform 的扁平化。
   - 验证了 `transform-style: flat` 属性能够阻止 transform 的继承。
   - 验证了 `transform-style: preserve-3d` 属性允许 transform 传递到子元素。

2. **Perspective 的处理:**
   - 测试了 `perspective` 属性如何影响 Paint Property Tree 的构建。
   - 验证了应用 `perspective` 的节点及其子节点会保持 3D 效果，不会发生 transform 的扁平化。
   - 验证了 `perspective` 属性自身不会创建渲染上下文。

3. **Rendering Context 的建立:**
   - 测试了哪些 CSS 属性会建立新的渲染上下文，例如 `transform-style: preserve-3d`。
   - 验证了在 3D 上下文中，某些节点的 transform 可能会被扁平化。

4. **属性缓存 (Cached Properties):**
   - 测试了当元素的 CSS 属性（特别是 `transform`）发生变化时，Paint Property Tree Builder 如何复用和更新已有的属性节点。
   - 验证了修改中间元素的 `transform` 属性，只会影响该元素及其子元素的 Transform 节点，而父元素的节点保持不变。
   - 测试了添加和删除 `transform` 属性对 Paint Property Tree 的影响。

5. **Overflow 和 Clip 的处理:**
   - 测试了 `overflow: hidden` 如何创建 Overflow Clip 节点，并影响子元素的绘制范围。
   - 测试了在设置了 `contain: paint` 或 `contain: style layout` 的元素上，如何创建 Transform Isolation Node, Effect Isolation Node 和 Clip Isolation Node 来隔离其子元素的渲染属性。
   - 测试了 `overflow: scroll` 如何创建 Scroll Translation 和 Scroll 节点，并处理滚动偏移。
   - 测试了带有 `border-radius` 的可滚动元素如何创建 InnerBorderRadiusClip 和 OverflowClip 节点。
   - 测试了带有亚像素边框的可滚动元素在没有垂直溢出时，内容高度与容器高度的关系。
   - 测试了 CSS 的 `clip` 属性如何创建 CssClip 节点。

6. **Replaced Content 的 Transform 处理:**
   - 测试了对于像 SVG 这样的 replaced content，如何处理其 transform 属性。
   - 验证了带有 `viewBox` 属性的 SVG 会创建 ReplacedContentTransform 节点。
   - 验证了 ReplacedContentTransform 节点会扁平化继承的 transform。

7. **滚动属性 (Scroll Properties):**
   - 测试了 `overflow: hidden` 元素的滚动属性在不同滚动偏移下的状态。
   - 测试了 Frame (文档) 的 `overflow: hidden` 属性如何影响滚动。
   - 测试了嵌套的可滚动元素的滚动属性是如何构建的。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** HTML 结构定义了元素的层级关系，这是构建 Paint Property Tree 的基础。例如，`<div id='a'><div id='b'></div></div>` 的嵌套结构决定了 #b 的 Transform 节点可能继承 #a 的 Transform 节点。
* **CSS:** CSS 样式直接控制着元素的绘制属性，这些属性会被 Paint Property Tree Builder 解析并转化为 Paint Property Tree 中的节点。
    * **`transform: translateZ(0)` (CSS):**  这段 CSS 代码会被解析并创建一个 TransformPaintPropertyNode，用于在绘制时对元素进行 Z 轴平移。测试用例会验证这个节点在树中的位置和父子关系。
    * **`transform-style: preserve-3d` (CSS):**  这个 CSS 属性会影响 Transform 节点的 `HasRenderingContext()` 和 `FlattensInheritedTransform()` 属性，测试用例会验证这些属性的设置是否正确。
    * **`overflow: hidden` (CSS):** 这个 CSS 属性会导致 Paint Property Tree 中创建一个 ClipPaintPropertyNode（OverflowClip），用于裁剪超出元素边界的内容。测试用例会验证这个 Clip 节点的边界和作用范围。
* **JavaScript:** 虽然测试代码中没有直接体现 JavaScript 的交互，但在实际应用中，JavaScript 可以动态修改元素的样式和属性，从而触发 Paint Property Tree 的重建。
    * **例如：** JavaScript 代码 `document.getElementById('b').style.transform = 'rotate(45deg)';` 会修改 #b 元素的 `transform` 属性，这将导致 Paint Property Tree Builder 重新计算并更新 #b 及其相关节点的 Transform 属性。

**逻辑推理的假设输入与输出:**

假设输入一个包含以下 HTML 和 CSS 的文档：

```html
<div id='parent' style='transform: rotate(30deg);'>
  <div id='child' style='width: 100px; height: 100px;'></div>
</div>
```

假设 Paint Property Tree Builder 的逻辑是正确的，则输出的 Paint Property Tree 中，`#child` 的 Transform 节点应该是 `#parent` 的 Transform 节点的子节点，并且 `#child` 的绘制会受到 `#parent` 旋转变换的影响。测试用例 `Preserve3DTransformStyleWithoutFlattening` 和 `TransformStyleFlatDoesNotPropagate` 就是在验证类似的逻辑。

**用户或编程常见的使用错误及举例说明:**

* **误解 `transform-style: preserve-3d` 的作用:** 用户可能认为只要父元素设置了 3D transform，子元素就自动拥有 3D 上下文。但实际上，需要显式地在父元素上设置 `transform-style: preserve-3d` 才能让子元素也参与到 3D 渲染中。测试用例 `Preserve3DTransformStylePropagatesToChildren` 验证了这一点。
* **过度使用 `will-change` 导致不必要的隔离节点:**  开发者可能为了优化性能而对很多元素使用 `will-change: transform` 等属性，但这可能会导致 Paint Property Tree 中创建过多的隔离节点，反而影响性能。测试用例 `ReplacedSvgContentWithIsolation` 演示了 `will-change: transform` 可能导致创建 TransformIsolationNode。
* **不理解 `overflow: hidden` 的裁剪行为:** 用户可能认为 `overflow: hidden` 只是隐藏滚动条，而忽略了它还会裁剪超出元素边界的内容。这可能导致内容被意外截断。测试用例 `OverflowClipContentsTreeState` 和 `OverflowScrollContentsTreeState` 都在测试 `overflow` 属性的裁剪行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个网页。**
2. **浏览器开始解析 HTML、CSS 和 JavaScript。**
3. **渲染引擎（Blink）根据 HTML 结构创建 DOM 树。**
4. **渲染引擎解析 CSS 样式，计算出每个元素的样式信息。**
5. **Paint Property Tree Builder 根据 DOM 树和计算出的样式信息，构建 Paint Property Tree。**  这是本测试文件所关注的核心步骤。
6. **Layout 阶段根据 Paint Property Tree 计算出每个元素的位置和大小。**
7. **Paint 阶段根据 Paint Property Tree 将元素绘制到屏幕上。**

当开发者发现页面渲染出现问题，例如：

* **Transform 效果不符合预期 (例如，子元素没有继承父元素的 3D transform)。**
* **元素被意外裁剪。**
* **滚动行为异常。**

作为调试线索，开发者可能会：

1. **检查元素的 CSS 样式，确认 `transform`, `transform-style`, `overflow`, `clip` 等属性的设置是否正确。**
2. **使用浏览器的开发者工具查看元素的 Computed Style 和 Layers 面板，了解元素的渲染层叠关系和绘制属性。**
3. **如果怀疑是 Paint Property Tree 构建的问题，可能会查看 Blink 渲染引擎的源代码，特别是 `paint_property_tree_builder.cc` 相关的测试用例，来理解 Paint Property Tree 的构建逻辑和预期行为。**
4. **运行相关的单元测试，例如本文件中的测试，来验证 Paint Property Tree Builder 在特定场景下的行为是否正确。**
5. **如果发现测试失败，可能就需要深入调试 Paint Property Tree Builder 的代码，找出构建过程中出现错误的地方。**

**总结 `paint_property_tree_builder_test.cc` (第 5 部分) 的功能:**

总而言之，`paint_property_tree_builder_test.cc` 的第 5 部分专注于测试 Blink 渲染引擎中 Paint Property Tree Builder 在处理 **transform、perspective、渲染上下文、属性缓存、overflow、clip 和 replaced content** 等关键 CSS 属性时的正确性。这些测试用例通过模拟不同的 HTML 和 CSS 场景，验证了 Paint Property Tree 的构建逻辑是否符合预期，确保了网页渲染的正确性和性能。这部分测试对于理解 Blink 渲染引擎的工作原理以及排查渲染问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共10部分，请归纳一下它的功能

"""
     }
      #b {
        transform: translateZ(0);
        width: 10px;
        height: 10px;
      }
    </style>
    <div id='a'>
      <div id='b'></div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const auto* a_transform = a->FirstFragment().PaintProperties()->Transform();
  ASSERT_TRUE(a_transform);
  const auto* b_transform = b->FirstFragment().PaintProperties()->Transform();
  ASSERT_TRUE(b_transform);
  ASSERT_TRUE(a_transform->IsAncestorOf(*b_transform));

  // Some node must flatten the inherited transform from #a before it reaches
  // #b's transform.
  EXPECT_TRUE(SomeNodeFlattensTransform(b_transform, a_transform));
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 30, 40), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 10, 10), b,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest,
       Preserve3DTransformStylePropagatesToChildren) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #a {
        transform: translateZ(0);
        transform-style: preserve-3d;
        width: 30px;
        height: 40px;
      }
      #b {
        transform: translateZ(0);
        width: 10px;
        height: 10px;
      }
    </style>
    <div id='a'>
      <div id='b'></div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const auto* a_transform = a->FirstFragment().PaintProperties()->Transform();
  ASSERT_TRUE(a_transform);
  const auto* b_transform = b->FirstFragment().PaintProperties()->Transform();
  ASSERT_TRUE(b_transform);
  ASSERT_TRUE(a_transform->IsAncestorOf(*b_transform));

  // No node may flatten the inherited transform from #a before it reaches
  // #b's transform.
  EXPECT_FALSE(SomeNodeFlattensTransform(b_transform, a_transform));
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 30, 40), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 10, 10), b,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, PerspectiveIsNotFlattened) {
  // It's necessary to make nodes from the one that applies perspective to
  // ones that combine with it preserve 3D. Otherwise, the perspective doesn't
  // do anything.
  SetBodyInnerHTML(R"HTML(
    <div id='a' style='perspective: 800px; width: 30px; height: 40px'>
      <div id='b'
          style='transform: translateZ(0); width: 10px; height: 20px'></div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* a_properties =
      a->FirstFragment().PaintProperties();
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  const TransformPaintPropertyNode* a_perspective = a_properties->Perspective();
  ASSERT_TRUE(a_perspective);
  const TransformPaintPropertyNode* b_transform = b_properties->Transform();
  ASSERT_TRUE(b_transform);
  ASSERT_TRUE(a_perspective->IsAncestorOf(*b_transform));
  EXPECT_FALSE(SomeNodeFlattensTransform(b_transform, a_perspective));
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 30, 40), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 10, 20), b,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, FlatteningIn3DContext) {
  SetBodyInnerHTML(R"HTML(
    <div id="a" style="transform-style: preserve-3d">
      <div id="b" style="transform: translate3d(0, 0, 33px)">
        <div id="c" style="transform: translate3d(0, 0, -10px)">C</div>
      </div>
      <div id="d" style="transform: translate3d(0, -10px, 22px)">D</div>
    </div>
  )HTML");

  const auto* a_properties = PaintPropertiesForElement("a");
  ASSERT_NE(a_properties, nullptr);
  ASSERT_NE(a_properties->Transform(), nullptr);
  EXPECT_TRUE(a_properties->Transform()->IsIdentity());
  EXPECT_TRUE(a_properties->Transform()->HasRenderingContext());
  EXPECT_TRUE(a_properties->Transform()->FlattensInheritedTransform());
  EXPECT_EQ(a_properties->Effect(), nullptr);

  const auto* b_properties = PaintPropertiesForElement("b");
  ASSERT_NE(b_properties, nullptr);
  ASSERT_NE(b_properties->Transform(), nullptr);
  EXPECT_EQ(MakeTranslationMatrix(0, 0, 33),
            b_properties->Transform()->Matrix());
  EXPECT_EQ(a_properties->Transform()->RenderingContextId(),
            b_properties->Transform()->RenderingContextId());
  EXPECT_FALSE(b_properties->Transform()->FlattensInheritedTransform());
  // Force render surface with an effect node for |b| which is an 3D object in
  // its container while it flattens its contents.
  ASSERT_NE(b_properties->Effect(), nullptr);
  EXPECT_EQ(b_properties->Transform(),
            &b_properties->Effect()->LocalTransformSpace());

  const auto* c_properties = PaintPropertiesForElement("c");
  ASSERT_NE(c_properties, nullptr);
  ASSERT_NE(c_properties->Transform(), nullptr);
  EXPECT_EQ(MakeTranslationMatrix(0, 0, -10),
            c_properties->Transform()->Matrix());
  EXPECT_FALSE(c_properties->Transform()->HasRenderingContext());
  EXPECT_TRUE(c_properties->Transform()->FlattensInheritedTransform());
  EXPECT_EQ(c_properties->Filter(), nullptr);

  const auto* d_properties = PaintPropertiesForElement("d");
  ASSERT_NE(d_properties, nullptr);
  ASSERT_NE(d_properties->Transform(), nullptr);
  EXPECT_EQ(MakeTranslationMatrix(0, -10, 22),
            d_properties->Transform()->Matrix());
  EXPECT_EQ(a_properties->Transform()->RenderingContextId(),
            d_properties->Transform()->RenderingContextId());
  EXPECT_FALSE(d_properties->Transform()->FlattensInheritedTransform());
  EXPECT_NE(d_properties->Effect(), nullptr);
}

TEST_P(PaintPropertyTreeBuilderTest,
       PerspectiveDoesNotEstablishRenderingContext) {
  // It's necessary to make nodes from the one that applies perspective to
  // ones that combine with it preserve 3D. Otherwise, the perspective doesn't
  // do anything.
  SetBodyInnerHTML(R"HTML(
    <div id='a' style='perspective: 800px; width: 30px; height: 40px'>
      <div id='b'
          style='transform: translateZ(0); width: 10px; height: 20px'></div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* a = GetLayoutObjectByElementId("a");
  LayoutObject* b = GetLayoutObjectByElementId("b");
  const ObjectPaintProperties* a_properties =
      a->FirstFragment().PaintProperties();
  const ObjectPaintProperties* b_properties =
      b->FirstFragment().PaintProperties();
  const TransformPaintPropertyNode* a_perspective = a_properties->Perspective();
  ASSERT_TRUE(a_perspective);
  EXPECT_FALSE(a_perspective->HasRenderingContext());
  const TransformPaintPropertyNode* b_transform = b_properties->Transform();
  ASSERT_TRUE(b_transform);
  EXPECT_FALSE(b_transform->HasRenderingContext());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 30, 40), a,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 10, 20), b,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, CachedProperties) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id='a' style='transform: translate(33px, 44px); width: 50px;
        height: 60px'>
      <div id='b' style='transform: translate(55px, 66px); width: 30px;
          height: 40px'>
        <div id='c' style='transform: translate(77px, 88px); width: 10px;
            height: 20px'>C<div>
      </div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  Element* a = GetDocument().getElementById(AtomicString("a"));
  const ObjectPaintProperties* a_properties =
      a->GetLayoutObject()->FirstFragment().PaintProperties();
  const TransformPaintPropertyNode* a_transform_node =
      a_properties->Transform();
  EXPECT_EQ(gfx::Vector2dF(33, 44), a_transform_node->Get2dTranslation());

  Element* b = GetDocument().getElementById(AtomicString("b"));
  const ObjectPaintProperties* b_properties =
      b->GetLayoutObject()->FirstFragment().PaintProperties();
  const TransformPaintPropertyNode* b_transform_node =
      b_properties->Transform();
  EXPECT_EQ(gfx::Vector2dF(55, 66), b_transform_node->Get2dTranslation());

  Element* c = GetDocument().getElementById(AtomicString("c"));
  const ObjectPaintProperties* c_properties =
      c->GetLayoutObject()->FirstFragment().PaintProperties();
  const TransformPaintPropertyNode* c_transform_node =
      c_properties->Transform();
  EXPECT_EQ(gfx::Vector2dF(77, 88), c_transform_node->Get2dTranslation());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(33, 44, 50, 60), a->GetLayoutObject(),
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(88, 110, 30, 40), b->GetLayoutObject(),
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(165, 198, 10, 20), c->GetLayoutObject(),
                          frame_view->GetLayoutView());

  // Change transform of b. B's transform node should be a new node with the new
  // value, and a and c's transform nodes should be unchanged (with c's parent
  // adjusted).
  b->setAttribute(html_names::kStyleAttr,
                  AtomicString("transform: translate(111px, 222px)"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(a_properties,
            a->GetLayoutObject()->FirstFragment().PaintProperties());
  EXPECT_EQ(a_transform_node, a_properties->Transform());

  EXPECT_EQ(b_properties,
            b->GetLayoutObject()->FirstFragment().PaintProperties());
  b_transform_node = b_properties->Transform();
  EXPECT_EQ(gfx::Vector2dF(111, 222), b_transform_node->Get2dTranslation());
  EXPECT_EQ(a_transform_node, b_transform_node->Parent()->Parent());

  EXPECT_EQ(c_properties,
            c->GetLayoutObject()->FirstFragment().PaintProperties());
  EXPECT_EQ(c_transform_node, c_properties->Transform());
  EXPECT_EQ(b_transform_node, c_transform_node->Parent()->Parent());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(33, 44, 50, 60), a->GetLayoutObject(),
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(144, 266, 50, 20), b->GetLayoutObject(),
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(221, 354, 10, 20), c->GetLayoutObject(),
                          frame_view->GetLayoutView());

  // Remove transform from b. B's transform node should be removed from the
  // tree, and a and c's transform nodes should be unchanged (with c's parent
  // adjusted).
  b->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(a_properties,
            a->GetLayoutObject()->FirstFragment().PaintProperties());
  EXPECT_EQ(a_transform_node, a_properties->Transform());

  EXPECT_EQ(nullptr, b->GetLayoutObject()->FirstFragment().PaintProperties());

  EXPECT_EQ(c_properties,
            c->GetLayoutObject()->FirstFragment().PaintProperties());
  EXPECT_EQ(c_transform_node, c_properties->Transform());
  EXPECT_EQ(a_transform_node, c_transform_node->Parent()->Parent());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(33, 44, 50, 60), a->GetLayoutObject(),
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(33, 44, 50, 20), b->GetLayoutObject(),
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(110, 132, 10, 20), c->GetLayoutObject(),
                          frame_view->GetLayoutView());

  // Re-add transform to b. B's transform node should be inserted into the tree,
  // and a and c's transform nodes should be unchanged (with c's parent
  // adjusted).
  b->setAttribute(html_names::kStyleAttr,
                  AtomicString("transform: translate(4px, 5px)"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(a_properties,
            a->GetLayoutObject()->FirstFragment().PaintProperties());
  EXPECT_EQ(a_transform_node, a_properties->Transform());

  b_properties = b->GetLayoutObject()->FirstFragment().PaintProperties();
  EXPECT_EQ(b_properties,
            b->GetLayoutObject()->FirstFragment().PaintProperties());
  b_transform_node = b_properties->Transform();
  EXPECT_EQ(gfx::Vector2dF(4, 5), b_transform_node->Get2dTranslation());
  EXPECT_EQ(a_transform_node, b_transform_node->Parent()->Parent());

  EXPECT_EQ(c_properties,
            c->GetLayoutObject()->FirstFragment().PaintProperties());
  EXPECT_EQ(c_transform_node, c_properties->Transform());
  EXPECT_EQ(b_transform_node, c_transform_node->Parent()->Parent());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(33, 44, 50, 60), a->GetLayoutObject(),
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(37, 49, 50, 20), b->GetLayoutObject(),
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(114, 137, 10, 20), c->GetLayoutObject(),
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowClipContentsTreeState) {
  // This test verifies the tree builder correctly computes and records the
  // property tree context for a (pseudo) stacking context that is scrolled by a
  // containing block that is not one of the painting ancestors.
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 20px 30px; }</style>
    <div id='clipper'
        style='overflow: hidden; width: 400px; height: 300px;'>
      <div id='child'
          style='position: relative; width: 500px; height: 600px;'></div>
    </div>
  )HTML");

  LayoutBoxModelObject* clipper =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("clipper"));
  const ObjectPaintProperties* clip_properties =
      clipper->FirstFragment().PaintProperties();
  LayoutObject* child = GetLayoutObjectByElementId("child");

  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            &clipper->FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(DocContentClip(),
            &clipper->FirstFragment().LocalBorderBoxProperties().Clip());

  auto contents_properties = clipper->FirstFragment().ContentsProperties();
  EXPECT_EQ(PhysicalOffset(30, 20), clipper->FirstFragment().PaintOffset());

  EXPECT_EQ(DocScrollTranslation(), &contents_properties.Transform());
  EXPECT_EQ(clip_properties->OverflowClip(), &contents_properties.Clip());

  EXPECT_EQ(DocScrollTranslation(),
            &child->FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(clip_properties->OverflowClip(),
            &child->FirstFragment().LocalBorderBoxProperties().Clip());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 500, 600), child, clipper);
}

TEST_P(PaintPropertyTreeBuilderTest, ReplacedSvgContentWithIsolation) {
  SetBodyInnerHTML(R"HTML(
    <style>
    body { margin 0px; }
    </style>
    <svg id='replacedsvg'
        style='contain:paint; will-change:transform;' width="100px" height="200px"
        viewBox='50 50 100 100'>
    </svg>
  )HTML");

  LayoutBoxModelObject* svg =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("replacedsvg"));
  const ObjectPaintProperties* svg_properties =
      svg->FirstFragment().PaintProperties();

  EXPECT_TRUE(svg_properties->TransformIsolationNode());
  EXPECT_TRUE(svg_properties->ReplacedContentTransform());
  EXPECT_EQ(svg_properties->TransformIsolationNode()->Parent(),
            svg_properties->ReplacedContentTransform());
}

TEST_P(PaintPropertyTreeBuilderTest, ReplacedContentTransformFlattening) {
  SetBodyInnerHTML(R"HTML(
    <svg id="svg"
        style="transform: perspective(100px) rotateY(0deg);"
        width="100px"
        height="200px"
        viewBox="50 50 100 100">
    </svg>
  )HTML");

  const auto* svg = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("svg"));
  const auto* svg_properties = svg->FirstFragment().PaintProperties();

  const auto* replaced_transform = svg_properties->ReplacedContentTransform();
  EXPECT_TRUE(replaced_transform->FlattensInheritedTransform());
  EXPECT_TRUE(
      ToUnaliased(*replaced_transform->Parent()).FlattensInheritedTransform());
}

TEST_P(PaintPropertyTreeBuilderTest, ContainPaintOrStyleLayoutTreeState) {
  for (const char* containment : {"paint", "style layout"}) {
    SCOPED_TRACE(containment);
    SetBodyInnerHTML(String::Format(R"HTML(
      <style>body { margin: 20px 30px; }</style>
      <div id='clipper'
          style='contain: %s; width: 300px; height: 200px;'>
        <div id='child'
            style='position: relative; width: 400px; height: 500px;'></div>
      </div>
    )HTML",
                                    containment));

    auto* clipper =
        To<LayoutBoxModelObject>(GetLayoutObjectByElementId("clipper"));
    const ObjectPaintProperties* clip_properties =
        clipper->FirstFragment().PaintProperties();
    LayoutObject* child = GetLayoutObjectByElementId("child");
    const auto& clip_local_properties =
        clipper->FirstFragment().LocalBorderBoxProperties();

    // Verify that we created isolation nodes.
    EXPECT_TRUE(clip_properties->TransformIsolationNode());
    EXPECT_TRUE(clip_properties->HasTransformNode());
    EXPECT_TRUE(clip_properties->EffectIsolationNode());
    EXPECT_TRUE(clip_properties->HasEffectNode());
    EXPECT_TRUE(clip_properties->ClipIsolationNode());
    EXPECT_TRUE(clip_properties->HasClipNode());

    // Verify parenting:

    // Transform isolation node should be parented to the local border box
    // properties transform, which should be the paint offset translation.
    EXPECT_EQ(clip_properties->TransformIsolationNode()->Parent(),
              &clip_local_properties.Transform());
    EXPECT_EQ(clip_properties->TransformIsolationNode()->Parent(),
              clip_properties->PaintOffsetTranslation());
    // Similarly, effect isolation node is parented to the local border box
    // properties effect.
    EXPECT_EQ(clip_properties->EffectIsolationNode()->Parent(),
              &clip_local_properties.Effect());
    if (strcmp(containment, "paint") == 0) {
      // If we contain paint, then clip isolation node is parented to the
      // overflow clip, which is in turn parented to the local border box
      // properties clip.
      EXPECT_EQ(clip_properties->ClipIsolationNode()->Parent(),
                clip_properties->OverflowClip());
      EXPECT_EQ(clip_properties->OverflowClip()->Parent(),
                &clip_local_properties.Clip());
    } else {
      // Otherwise, the clip isolation node is parented to the local border box
      // properties clip directly.
      EXPECT_EQ(clip_properties->ClipIsolationNode()->Parent(),
                &clip_local_properties.Clip());
    }

    // Verify transform:

    EXPECT_TRUE(clip_properties->TransformIsolationNode()->IsParentAlias());

    // Always create scroll translation for layout view even the document does
    // not scroll (not enough content).
    EXPECT_TRUE(DocScrollTranslation());
    // Isolation induces paint offset translation, so the node should be
    // different from the doc node, but its parent is the same as the doc
    // node.
    EXPECT_EQ(DocScrollTranslation(), clipper->FirstFragment()
                                          .LocalBorderBoxProperties()
                                          .Transform()
                                          .Parent());

    // Verify clip:

    EXPECT_EQ(DocContentClip(),
              &clipper->FirstFragment().LocalBorderBoxProperties().Clip());
    EXPECT_TRUE(clip_properties->ClipIsolationNode()->IsParentAlias());

    // Verify contents properties and child properties:

    auto contents_properties = clipper->FirstFragment().ContentsProperties();
    // Since the clipper is isolated, its paint offset should be 0, 0.
    EXPECT_EQ(PhysicalOffset(), clipper->FirstFragment().PaintOffset());
    // Ensure that the contents properties match isolation nodes.
    EXPECT_EQ(clip_properties->TransformIsolationNode(),
              &contents_properties.Transform());
    EXPECT_EQ(clip_properties->ClipIsolationNode(),
              &contents_properties.Clip());
    EXPECT_EQ(clip_properties->EffectIsolationNode(),
              &contents_properties.Effect());

    // Child should be using isolation nodes as its local border box properties.
    EXPECT_EQ(&contents_properties.Transform(),
              &child->FirstFragment().LocalBorderBoxProperties().Transform());
    EXPECT_EQ(&contents_properties.Clip(),
              &child->FirstFragment().LocalBorderBoxProperties().Clip());
    EXPECT_EQ(&contents_properties.Effect(),
              &child->FirstFragment().LocalBorderBoxProperties().Effect());
    CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 400, 500), child, clipper);
  }
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollContentsTreeState) {
  // This test verifies the tree builder correctly computes and records the
  // property tree context for a (pseudo) stacking context that is scrolled by a
  // containing block that is not one of the painting ancestors.
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 20px 30px; }
      /* to prevent the mock overlay scrollbar from affecting compositing. */
      #clipper::-webkit-scrollbar { display: none; }
    </style>
    <div id='clipper' style='overflow:scroll; width:400px; height:300px;'>
      <div id='child'
          style='position:relative; width:500px; height: 600px;'></div>
      <div style='width: 200px; height: 10000px'></div>
    </div>
    <div id='forceScroll' style='height: 4000px;'></div>
  )HTML");

  Element* clipper_element =
      GetDocument().getElementById(AtomicString("clipper"));
  clipper_element->scrollTo(1, 2);

  auto* clipper = To<LayoutBoxModelObject>(clipper_element->GetLayoutObject());
  const ObjectPaintProperties* clip_properties =
      clipper->FirstFragment().PaintProperties();
  LayoutObject* child = GetLayoutObjectByElementId("child");

  EXPECT_EQ(
      DocScrollTranslation(),
      clipper->FirstFragment().LocalBorderBoxProperties().Transform().Parent());
  EXPECT_EQ(clip_properties->PaintOffsetTranslation(),
            &clipper->FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(DocContentClip(),
            &clipper->FirstFragment().LocalBorderBoxProperties().Clip());

  auto contents_properties = clipper->FirstFragment().ContentsProperties();
  EXPECT_EQ(gfx::Vector2dF(30, 20),
            clip_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(PhysicalOffset(), clipper->FirstFragment().PaintOffset());
  EXPECT_EQ(clip_properties->ScrollTranslation(),
            &contents_properties.Transform());
  EXPECT_EQ(clip_properties->OverflowClip(), &contents_properties.Clip());

  EXPECT_EQ(clip_properties->ScrollTranslation(),
            &child->FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(clip_properties->OverflowClip(),
            &child->FirstFragment().LocalBorderBoxProperties().Clip());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 500, 600), child, clipper);
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollWithRoundedRect) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      ::-webkit-scrollbar {
        width: 13px;
        height: 13px;
      }
      #roundedBox {
        width: 200px;
        height: 200px;
        border-radius: 100px;
        background-color: red;
        border: 50px solid green;
        overflow: scroll;
      }
      #roundedBoxChild {
        width: 200px;
        height: 200px;
        background-color: orange;
      }
    </style>
    <div id='roundedBox'>
      <div id='roundedBoxChild'></div>
    </div>
  )HTML");

  LayoutObject& rounded_box = *GetLayoutObjectByElementId("roundedBox");
  const ObjectPaintProperties* rounded_box_properties =
      rounded_box.FirstFragment().PaintProperties();
  EXPECT_CLIP_RECT(FloatRoundedRect(gfx::RectF(50, 50, 200, 200),
                                    FloatRoundedRect::Radii(50)),
                   rounded_box_properties->InnerBorderRadiusClip());

  // Unlike the inner border radius clip, the overflow clip is inset by the
  // scrollbars (13px).
  EXPECT_CLIP_RECT(FloatRoundedRect(50, 50, 187, 187),
                   rounded_box_properties->OverflowClip());
  EXPECT_EQ(DocContentClip(),
            rounded_box_properties->InnerBorderRadiusClip()->Parent());
  EXPECT_EQ(rounded_box_properties->InnerBorderRadiusClip(),
            rounded_box_properties->OverflowClip()->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowScrollWithSubpixelBorder) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #scroller {
          width: 200px;
          height: 201.594px;
          border: 2.8px solid blue;
          overflow: scroll;
        }
        #content {
          width: 600px;
          height: 201.594px;
        }
      </style>
      <div id="scroller">
        <div id="content"></div>
      </div>
    )HTML");

  PaintLayer* paint_layer = GetPaintLayerByElementId("scroller");
  ASSERT_FALSE(paint_layer->GetScrollableArea()->HasVerticalOverflow());

  // When there is no vertical overflow, the contents height should not be
  // larger than the container height.
  const auto* properties = PaintPropertiesForElement("scroller");
  const auto* scroll = properties->Scroll();
  EXPECT_EQ(scroll->ContentsRect().height(), scroll->ContainerRect().height());
}

TEST_P(PaintPropertyTreeBuilderTest, CssClipContentsTreeState) {
  // This test verifies the tree builder correctly computes and records the
  // property tree context for a (pseudo) stacking context that is scrolled by a
  // containing block that is not one of the painting ancestors.
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 20px 30px; }</style>
    <div id='clipper' style='position: absolute;
        clip: rect(10px, 80px, 70px, 40px); width:300px; height:200px;'>
      <div id='child' style='position:relative; width:400px; height: 500px;'>
      </div>
    </div>
  )HTML");

  auto* clipper =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("clipper"));
  const ObjectPaintProperties* clip_properties =
      clipper->FirstFragment().PaintProperties();
  LayoutObject* child = GetLayoutObjectByElementId("child");

  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            &clipper->FirstFragment().LocalBorderBoxProperties().Transform());
  // CSS clip on an element causes it to clip itself, not just descendants.
  EXPECT_EQ(clip_properties->CssClip(),
            &clipper->FirstFragment().LocalBorderBoxProperties().Clip());

  auto contents_properties = clipper->FirstFragment().ContentsProperties();
  EXPECT_EQ(PhysicalOffset(30, 20), clipper->FirstFragment().PaintOffset());
  EXPECT_EQ(DocScrollTranslation(), &contents_properties.Transform());
  EXPECT_EQ(clip_properties->CssClip(), &contents_properties.Clip());

  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 400, 500), child, clipper);
}

TEST_P(PaintPropertyTreeBuilderTest,
       ReplacedContentTransformContentsTreeState) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 20px 30px;
      }
      svg {
        position: absolute;
      }
      rect {
        transform: translate(100px, 100px);
      }
    </style>
    <svg id='svgWithViewBox' width='100px' height='100px'
        viewBox='50 50 100 100'>
      <rect id='rect' width='100px' height='100px' />
    </svg>
  )HTML");

  LayoutObject& svg_with_view_box =
      *GetLayoutObjectByElementId("svgWithViewBox");
  const auto* paint_offset_translation = svg_with_view_box.FirstFragment()
                                             .PaintProperties()
                                             ->PaintOffsetTranslation();
  EXPECT_EQ(paint_offset_translation, &svg_with_view_box.FirstFragment()
                                           .LocalBorderBoxProperties()
                                           .Transform());
  EXPECT_EQ(DocScrollTranslation(), paint_offset_translation->Parent());
  EXPECT_EQ(gfx::Vector2dF(30, 20),
            paint_offset_translation->Get2dTranslation());
  EXPECT_EQ(PhysicalOffset(), svg_with_view_box.FirstFragment().PaintOffset());

  const auto* replaced_content_transform = svg_with_view_box.FirstFragment()
                                               .PaintProperties()
                                               ->ReplacedContentTransform();
  EXPECT_EQ(
      replaced_content_transform,
      &svg_with_view_box.FirstFragment().ContentsProperties().Transform());
  EXPECT_EQ(paint_offset_translation, replaced_content_transform->Parent());
  EXPECT_EQ(gfx::Vector2dF(-50, -50),
            replaced_content_transform->Get2dTranslation());
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowHiddenScrollProperties) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0px;
      }
      #overflowHidden {
        overflow: hidden;
        width: 5px;
        height: 3px;
      }
      .forceScroll {
        height: 79px;
      }
    </style>
    <div id='overflowHidden'>
      <div class='forceScroll'></div>
    </div>
  )HTML");

  Element* overflow_hidden =
      GetDocument().getElementById(AtomicString("overflowHidden"));

  const ObjectPaintProperties* overflow_hidden_scroll_properties =
      overflow_hidden->GetLayoutObject()->FirstFragment().PaintProperties();

  // No scroll translation when the scroll offset is zero.
  EXPECT_EQ(nullptr, overflow_hidden_scroll_properties->ScrollTranslation());
  EXPECT_EQ(nullptr, overflow_hidden_scroll_properties->Scroll());

  // Both scroll translation and scroll nodes when the scroll offset is not
  // zero.
  overflow_hidden->setScrollTop(37);
  UpdateAllLifecyclePhasesForTest();
  auto* scroll_translation =
      overflow_hidden_scroll_properties->ScrollTranslation();
  ASSERT_NE(nullptr, scroll_translation);
  EXPECT_EQ(gfx::Vector2dF(0, -37), scroll_translation->Get2dTranslation());
  auto* scroll = scroll_translation->ScrollNode();
  ASSERT_NE(nullptr, scroll);
  EXPECT_EQ(scroll, overflow_hidden_scroll_properties->Scroll());
  EXPECT_FALSE(scroll->UserScrollableHorizontal());
  EXPECT_FALSE(scroll->UserScrollableVertical());
}

TEST_P(PaintPropertyTreeBuilderTest, FrameOverflowHiddenScrollProperties) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html {
        margin: 0px;
        overflow: hidden;
        width: 300px;
        height: 300px;
      }
      .forceScroll {
        height: 5000px;
      }
    </style>
    <div class='forceScroll'></div>
  )HTML");

  GetDocument().domWindow()->scrollTo(0, 37);

  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(gfx::Vector2dF(0, -37), DocScrollTranslation()->Get2dTranslation());
  EXPECT_TRUE(DocScrollTranslation()->ScrollNode());
  EXPECT_TRUE(DocScroll());
}

TEST_P(PaintPropertyTreeBuilderTest, NestedScrollProperties) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0px;
      }
      #overflowA {
        overflow: scroll;
        width: 5px;
        height: 3px;
      }
      #overflowB {
        overflow: scroll;
        width: 9px;
        height: 7px;
      }
      .forceScroll {
        height: 100px;
      }
    </style>
    <div id='overflowA'>
      <div id='overflowB'>
        <div class='forceScroll'></div>
      </div>
      <div class='forceScroll'></div>
    </div>
  )HTML");

  Element* overflow_a = GetDocument().getElementById(AtomicString("overflowA"));
  overflow_a->setScrollTop(37);
  Element* overflow_b = GetDocument().getElementById(AtomicString("overflowB"));
  overflow_b->setScrollTop(41);

  UpdateAllLifecyclePhasesForTest();

  const ObjectPaintProperties* overflow_a_scroll_properties =
      overflow_a->GetLayoutObject()->FirstFragment().PaintProperties();
  // Because the frameView is does not scroll, overflowA's scroll should be
  // under the root.
  auto* scroll_a_translation =
      overflow_a_scroll_properties->ScrollTranslation();
  auto* overflow_a_scroll_node = scroll_a_translation->ScrollNode();
  EXPECT_EQ(DocScroll(), overflow_a_scroll_node->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -37), scroll_a_translation->Get2dTranslation());
  EXPECT_EQ(gfx::Rect(0, 0, 5, 3), overflow_a_scroll_node->ContainerRect());
  // 107 i
"""


```