Response:
My thinking process to arrive at the summary of the provided code snippet goes like this:

1. **Understand the Context:** The initial prompt states the file is `paint_property_tree_builder_test.cc` within the Chromium Blink rendering engine. This immediately tells me the purpose of the file: it's a *test* file for the `PaintPropertyTreeBuilder`. The `PaintPropertyTreeBuilder` is a crucial component in how Blink handles rendering, specifically by creating a hierarchical structure (the paint property tree) that optimizes and organizes painting operations.

2. **Scan for Keywords and Patterns:** I quickly scan the code looking for recurring patterns and keywords. I see:
    * `TEST_P`: This confirms it's a parameterized test fixture in Google Test.
    * `PaintPropertyTreeBuilderTest`:  This reinforces the test target.
    * `SetBodyInnerHTML`: This indicates that the tests are setting up HTML structures within a test environment.
    * Identifiers like `svg`, `container`, `object`, `div`, `iframe`, `button`, `fixed`, `clip`, etc.: These suggest the tests are focused on various HTML elements and their styling.
    * CSS properties mentioned in inline styles like `overflow`, `transform`, `position: fixed`, `clip`, `border-radius`, `columns`, etc.: These pinpoint the CSS aspects being tested.
    * Assertions like `ASSERT_NE(nullptr, ...)`, `EXPECT_EQ(...)`, `EXPECT_CLIP_RECT(...)`, `CHECK_EXACT_VISUAL_RECT(...)`: These are standard Google Test assertions used to verify expected behavior.
    * Methods like `PaintPropertiesForElement`, `GetLayoutObjectByElementId`, `DocScrollTranslation`, `DocContentClip`: These hint at the internal APIs of Blink being used and tested.

3. **Identify Core Functionality Being Tested:** Based on the keywords and patterns, I can deduce the primary focus of these specific test cases:

    * **Overflow and Clipping:**  The tests extensively use `overflow: hidden/visible` and the `clip` CSS property. The assertions with `EXPECT_CLIP_RECT` confirm that the code is verifying the correct creation and behavior of clip nodes in the paint property tree based on these properties. The tests involving scrollbars further reinforce this.
    * **Transforms:** The repeated use of `transform` and assertions on `Transform()` nodes and their matrices (`MakeTranslationMatrix`) indicates a strong focus on testing how transforms are handled in the paint property tree. This includes 2D and 3D transforms and their parent-child relationships.
    * **SVG and Foreign Objects:** The presence of `<svg>` and `<foreignObject>` elements and tests specifically named with these terms indicates that the interaction of these elements with the paint property tree is being tested.
    * **Fixed Positioning:** Tests involving `position: fixed` are verifying how fixed-position elements are handled in the paint property tree, particularly in relation to clipping and transforms of their ancestors.
    * **Iframes and Isolation:** The tests with `<iframe>` elements and discussions of "isolation" point towards verifying that iframes create boundaries in the paint property tree, preventing certain properties from propagating across frame boundaries.
    * **Border Radius:** Tests with `border-radius` and assertions on `InnerBorderRadiusClip()` show that the creation and correctness of clip nodes for rounded borders are being validated.
    * **Table Cells:**  The test case related to table cells indicates verification of how the paint property tree handles the specific layout and positioning of elements within table cells.
    * **Subpixel Positioning:** The test case involving subpixel `left` values confirms that the paint property tree builder correctly handles fractional pixel values.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**  It's clear that the tests directly relate to HTML and CSS. The HTML structures are set up using `SetBodyInnerHTML`, and the CSS properties are applied inline. While JavaScript isn't directly present in *this* snippet, the functionality being tested (rendering behavior based on CSS) is fundamental to how JavaScript interacts with the DOM and styling through APIs like `element.style`.

5. **Infer Logic and Assumptions (Input/Output):** For tests like the overflow/clip tests, I can infer the following:

    * **Input:** A specific HTML structure with certain CSS properties applied (e.g., an element with `overflow: hidden`, dimensions, and potentially an offset).
    * **Expected Output:** The creation of specific `ClipPaintPropertyNode` objects in the paint property tree, with properties like the clip rectangle (`EXPECT_CLIP_RECT`) matching the expected visual clipping area. The parent-child relationships between these nodes are also being validated. Similarly, for transforms, the expected output is the creation of `TransformPaintPropertyNode` objects with the correct transformation matrices.

6. **Identify Potential User/Developer Errors:** Based on the tests, I can identify common errors:

    * **Incorrectly assuming `overflow: visible` elements don't create paint properties when offset:** The tests show that while `overflow: visible` alone doesn't create clip nodes, an offset will create a transform node.
    * **Misunderstanding how fixed positioning interacts with ancestor clipping:** The tests with fixed-position elements demonstrate the special handling required to escape ancestor clipping contexts.
    * **Not understanding how iframes create isolation boundaries:** Developers might incorrectly assume styles or transforms will automatically propagate across iframe boundaries.

7. **Trace User Actions (Debugging Clues):** While the tests themselves aren't user actions, they simulate the *result* of user actions. For instance:

    * A user viewing a webpage with elements styled with `overflow: hidden` and specific dimensions would trigger the creation of overflow clip nodes, as tested.
    * User interactions that cause layout changes (like resizing the window or changes in element dimensions/positioning) would trigger the `PaintPropertyTreeBuilder` to rebuild or update the tree.
    * The tests with iframes reflect the rendering process when a webpage embeds another webpage.

8. **Summarize the Functionality (for this part):**  Given the focus on overflow, clipping, transforms, SVG, iframes, and fixed positioning within this specific snippet, I can formulate the summary provided earlier. I emphasize that it's a subset of the overall file's functionality and that it's focused on testing the correct creation of the paint property tree nodes.

By following these steps, I can effectively analyze the code snippet, understand its purpose within the larger project, and extract meaningful information about its functionality and relationships to web technologies. The key is to combine code analysis with knowledge of web rendering principles and testing methodologies.
这是 `blink/renderer/core/paint/paint_property_tree_builder_test.cc` 文件的第三部分，它主要包含了一系列针对 `PaintPropertyTreeBuilder` 类的单元测试。 `PaintPropertyTreeBuilder` 的核心功能是根据 DOM 树和相关的 CSS 样式，构建用于高效渲染的 Paint Property Tree (绘制属性树)。

**本部分的主要功能归纳如下:**

1. **测试 overflow 属性对 SVG 元素的影响:**  测试了 `overflow: hidden` 和 `overflow: visible` 在 SVG 元素上的不同表现，以及非零偏移对 Paint Property Tree 的影响。验证了在 `overflow: hidden` 时会创建 `OverflowClip` 节点，而在 `overflow: visible` 且有偏移时会创建 `Transform` 节点。

2. **测试 SVG 中 `<foreignObject>` 元素的 overflow 行为:** 验证了 `<foreignObject>` 元素上的 `overflow: hidden` 会创建 `OverflowClip` 节点，而 `overflow: visible` 则不会。

3. **测试带有空的视觉溢出的 overflow clip:**  测试了当一个元素设置了 `overflow: scroll` 但实际内容没有溢出时，是否会创建 `OverflowClip` 节点，并验证了其裁剪区域的计算。

4. **测试跨越 SVG/HTML 边界的 PaintOffsetTranslation:**  验证了当元素跨越 SVG 和 HTML 边界时，`PaintOffsetTranslation` 的计算是否正确，尤其是在多列布局的情况下。

5. **测试跨越 SVG/HTML 边界的 fixed transform 祖先:** 测试了当固定定位的元素位于 SVG 的 `<foreignObject>` 中，其最近的 transform 容器是否正确地指向了 SVG 元素上的 transform 属性。

6. **测试表单控件 (Control) 的 Clip 属性:** 验证了表单控件（例如 button）是否会创建 `OverflowClip` 节点，并测试了其裁剪区域的计算，以及与文档滚动转换的关系。

7. **测试位于 `<foreignObject>` 内部的表单控件的 Clip 属性:**  验证了在特定布局下，位于 `<foreignObject>` 内部的表单控件的 `OverflowClip` 属性是否正确创建和计算。

8. **测试 BorderRadius 对 Clip 属性的影响:**  测试了 `border-radius` 属性是否会导致创建额外的 `Clip` 节点，并验证了该节点的裁剪区域的计算，特别是对于内外边框半径不同的情况。

9. **测试亚像素 BorderRadius 的 Clip 属性:**  验证了对于亚像素的 `border-radius`，`Clip` 节点的布局裁剪区域和绘制裁剪区域的计算是否正确。

10. **测试跨越子框架的 Transform 节点:** 验证了当带有 transform 属性的元素包含一个子框架时，父框架和子框架上的 transform 节点是如何连接的，以及它们之间的层级关系。

11. **测试框架建立隔离 (Isolation):** 验证了 `iframe` 元素会创建隔离的绘制上下文，阻止父框架的某些绘制属性影响子框架。即使父框架的 transform 属性发生变化，也不会影响子框架的 transform 属性（在 DCHECK 关闭的情况下进行了验证，因为在 DCHECK 开启时会因为状态不一致而触发断言）。

12. **测试已转换的子框架中的 Transform 节点:**  测试了当父框架和子框架都应用了 transform 属性时，`Transform` 节点的层级结构和变换矩阵的计算是否正确。

13. **测试非堆叠上下文的树上下文裁剪:** 验证了当一个元素被一个非其绘制祖先的容器滚动时，其 property tree 上下文的裁剪是否正确。

14. **测试从父堆叠上下文中取消裁剪:** 验证了当一个元素的滚动绘制祖先不是其包含块时，其 property tree 上下文的裁剪是否正确地取消了父堆叠上下文的裁剪。

15. **测试 TableCell 的布局位置:** 验证了表格单元格的边框盒空间是否被正确计算。

16. **测试 CSS Clip 对 fixed 定位后代的影响:** 验证了当一个绝对定位的元素使用 `clip` 属性进行裁剪时，其 `fixed` 定位的后代元素的裁剪属性是否正确指向该裁剪节点。

17. **测试 CSS Clip 对 absolute 定位后代的影响:**  类似于上一个测试，验证了 CSS Clip 对 `absolute` 定位的后代的影响。

18. **测试亚像素 CSS Clip:** 验证了对于亚像素定位的元素，其 CSS Clip 的布局裁剪区域和绘制裁剪区域的计算是否正确。

19. **测试 CSS Clip 对 fixed 定位后代的影响 (非共享):**  这个测试与之前的 `CSSClipFixedPositionDescendant` 类似，但增加了父元素 `overflow: scroll` 的情况，验证了 `fixed` 定位的后代是否能正确地“逃脱”父元素的溢出裁剪。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:** 测试代码使用 `SetBodyInnerHTML` 来设置 HTML 结构，这是浏览器渲染的基础。例如，测试中创建了 `<div>`, `<span>`, `<svg>`, `<foreignObject>`, `<iframe>`, `<input>`, `<table>` 等 HTML 元素。
* **CSS:** 测试代码中使用了大量的内联 CSS 样式来设置元素的视觉属性，例如 `overflow`, `transform`, `position`, `clip`, `border-radius`, `columns` 等。这些 CSS 属性直接影响了 `PaintPropertyTreeBuilder` 如何构建绘制属性树。
    * **例 1 (overflow):**  CSS 的 `overflow: hidden` 属性会导致 `PaintPropertyTreeBuilder` 为该元素创建一个 `OverflowClip` 节点，用于裁剪超出元素边界的内容。
    * **例 2 (transform):** CSS 的 `transform: translate(10px, 20px)` 属性会导致 `PaintPropertyTreeBuilder` 为该元素创建一个 `Transform` 节点，记录元素的变换信息。
    * **例 3 (clip):** CSS 的 `clip: rect(10px, 80px, 70px, 40px)` 属性会导致 `PaintPropertyTreeBuilder` 创建一个 `CssClip` 节点，定义元素的裁剪区域。
* **JavaScript:** 虽然这段测试代码本身不包含 JavaScript，但 `PaintPropertyTreeBuilder` 的工作直接影响了 JavaScript 操作 DOM 和 CSS 后的渲染结果。当 JavaScript 修改元素的样式（例如通过 `element.style.transform = '...'`）时，浏览器会重新运行布局和绘制流程，其中就包括 `PaintPropertyTreeBuilder` 重新构建绘制属性树。

**逻辑推理的假设输入与输出:**

**假设输入 (针对测试 SVGForeignObjectOverflowClip):**

```html
<svg id='svg'>
  <foreignObject id='object1' x='10' y='20' width='30' height='40'
      overflow='hidden'>
  </foreignObject>
  <foreignObject id='object2' x='50' y='60' width='30' height='40'
      overflow='visible'>
  </foreignObject>
</svg>
```

**输出:**

* 对于 id 为 `object1` 的元素，`PaintPropertiesForElement("object1")->OverflowClip()` 将返回一个非空的 `ClipPaintPropertyNode` 指针，并且其裁剪区域将是 `gfx::RectF(10, 20, 30, 40)`。
* 对于 id 为 `object2` 的元素，`PaintPropertiesForElement("object2")` 将返回 `nullptr`，因为 `overflow: visible` 不会创建绘制属性节点。

**用户或编程常见的使用错误举例说明:**

* **错误理解 `overflow: visible` 的作用:**  开发者可能认为设置了 `overflow: visible` 的元素永远不会创建任何裁剪效果。但测试 `SVGOverflowClip` 表明，即使是 `overflow: visible` 的元素，如果其父元素有 `overflow: hidden`，仍然会受到父元素的裁剪。
* **错误假设 fixed 定位元素的裁剪上下文:**  开发者可能认为 `fixed` 定位的元素总是相对于视口进行定位和裁剪。但测试 `CSSClipFixedPositionDescendant` 表明，如果 `fixed` 定位元素的祖先存在使用 `clip` 属性创建的裁剪上下文，`fixed` 定位的元素也会被该裁剪上下文裁剪。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个网页:** 这是所有渲染流程的起点。
2. **浏览器解析 HTML:**  浏览器将 HTML 代码解析成 DOM 树。
3. **浏览器解析 CSS:** 浏览器解析与网页关联的 CSS 样式表，并计算出每个元素的最终样式。
4. **计算布局 (Layout):**  浏览器根据 DOM 树和计算出的样式，计算出每个元素在页面上的位置和大小。
5. **构建绘制属性树 (Paint Property Tree):**  `PaintPropertyTreeBuilder` 根据布局信息和样式信息，构建用于优化的绘制属性树。这是本测试代码所关注的核心步骤。例如，如果一个 `div` 元素设置了 `overflow: hidden`，`PaintPropertyTreeBuilder` 会在这个阶段为该 `div` 创建一个 `OverflowClip` 节点。
6. **生成绘制命令 (Paint):**  浏览器根据绘制属性树，生成实际的绘制命令。
7. **栅格化 (Rasterization) 和合成 (Compositing):**  绘制命令被转换成像素，并最终显示在屏幕上。

**调试线索:** 如果在渲染过程中出现与裁剪、变换、固定定位等相关的错误，开发者可能会查看 `PaintPropertyTreeBuilder` 的输出来理解绘制属性树的结构是否正确。`paint_property_tree_builder_test.cc` 中的测试用例可以帮助开发者理解特定 CSS 属性组合下，绘制属性树的预期结构，从而定位问题。例如，如果一个固定定位的元素意外地被裁剪了，开发者可以参考 `CSSClipFixedPositionDescendant` 测试用例来分析绘制属性树中是否存在错误的裁剪节点。

总而言之，这部分测试代码专注于验证 `PaintPropertyTreeBuilder` 在处理各种 CSS 属性（特别是与裁剪和变换相关的属性）时，能否正确地构建绘制属性树，这是浏览器渲染流程中至关重要的一步。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共10部分，请归纳一下它的功能

"""
     <svg id='container4' overflow='visible'
          width='30' height='30' x='20' y='30'></svg>
    </svg>
  )HTML");

  const auto* svg_properties = PaintPropertiesForElement("svg");
  ASSERT_NE(nullptr, svg_properties);
  const auto* parent_transform = svg_properties->PaintOffsetTranslation();
  const auto* parent_clip = svg_properties->OverflowClip();

  // overflow: hidden and zero offset: OverflowClip only.
  const auto* properties1 = PaintPropertiesForElement("container1");
  ASSERT_NE(nullptr, properties1);
  const auto* clip = properties1->OverflowClip();
  const auto* transform = properties1->Transform();
  ASSERT_NE(nullptr, clip);
  EXPECT_EQ(nullptr, transform);
  EXPECT_EQ(parent_clip, clip->Parent());
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 30, 30), clip);
  EXPECT_EQ(parent_transform, &clip->LocalTransformSpace());

  // overflow: hidden and non-zero offset and viewport scale:
  // both Transform and OverflowClip.
  const auto* properties2 = PaintPropertiesForElement("container2");
  ASSERT_NE(nullptr, properties2);
  clip = properties2->OverflowClip();
  transform = properties2->Transform();
  ASSERT_NE(nullptr, clip);
  ASSERT_NE(nullptr, transform);
  EXPECT_EQ(parent_clip, clip->Parent());
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 60, 60), clip);
  EXPECT_EQ(transform, &clip->LocalTransformSpace());
  auto matrix = MakeTranslationMatrix(40, 50);
  matrix.Scale(0.5);
  EXPECT_EQ(matrix, transform->Matrix());
  EXPECT_EQ(parent_transform, transform->Parent());

  // overflow: visible and zero offset: no paint properties.
  const auto* properties3 = PaintPropertiesForElement("container3");
  EXPECT_EQ(nullptr, properties3);

  // overflow: visible and non-zero offset: Transform only.
  const auto* properties4 = PaintPropertiesForElement("container4");
  ASSERT_NE(nullptr, properties4);
  clip = properties4->OverflowClip();
  transform = properties4->Transform();
  EXPECT_EQ(nullptr, clip);
  ASSERT_NE(nullptr, transform);
  EXPECT_EQ(gfx::Vector2dF(20, 30), transform->Get2dTranslation());
  EXPECT_EQ(parent_transform, transform->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGForeignObjectOverflowClip) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg'>
      <foreignObject id='object1' x='10' y='20' width='30' height='40'
          overflow='hidden'>
      </foreignObject>
      <foreignObject id='object2' x='50' y='60' width='30' height='40'
          overflow='visible'>
      </foreignObject>
    </svg>
  )HTML");

  const auto* svg_properties = PaintPropertiesForElement("svg");
  ASSERT_NE(nullptr, svg_properties);
  const auto* parent_transform = svg_properties->PaintOffsetTranslation();
  const auto* parent_clip = svg_properties->OverflowClip();

  const auto* properties1 = PaintPropertiesForElement("object1");
  ASSERT_NE(nullptr, properties1);
  const auto* clip = properties1->OverflowClip();
  ASSERT_NE(nullptr, clip);
  EXPECT_EQ(parent_clip, clip->Parent());
  EXPECT_CLIP_RECT(gfx::RectF(10, 20, 30, 40), clip);
  EXPECT_EQ(parent_transform, &clip->LocalTransformSpace());

  const auto* properties2 = PaintPropertiesForElement("object2");
  EXPECT_EQ(nullptr, properties2);
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowClipWithEmptyVisualOverflow) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0 }
      ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
      }
    </style>
    <div id='container' style='width: 100px; height: 100px;
        will-change: transform; overflow: scroll; background: lightblue;'>
      <div id='forcescroll' style='width: 0; height: 400px;'></div>
    </div>
  )HTML");

  const auto* clip = PaintPropertiesForElement("container")->OverflowClip();
  EXPECT_NE(nullptr, clip);
  EXPECT_CLIP_RECT(gfx::RectF(0, 0, 90, 90), clip);
}

TEST_P(PaintPropertyTreeBuilderTest,
       PaintOffsetTranslationSVGHTMLBoundaryMulticol) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg'>
      <foreignObject>
        <body>
          <div id='divWithColumns' style='columns: 2'>
            <div style='width: 5px; height: 5px; background: blue'>
          </div>
        </body>
      </foreignObject>
    </svg>
  )HTML");

  LayoutObject& svg = *GetLayoutObjectByElementId("svg");
  const ObjectPaintProperties* svg_properties =
      svg.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(8, 8),
            svg_properties->PaintOffsetTranslation()->Get2dTranslation());
  LayoutObject& div_with_columns =
      *GetLayoutObjectByElementId("divWithColumns")->SlowFirstChild();
  EXPECT_EQ(PhysicalOffset(), div_with_columns.FirstFragment().PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest,
       FixedTransformAncestorAcrossSVGHTMLBoundary) {
  SetBodyInnerHTML(R"HTML(
    <style> body { margin: 0px; } </style>
    <svg id='svg' style='transform: translate3d(1px, 2px, 3px);'>
      <g id='container' transform='translate(20 30)'>
        <foreignObject>
          <body>
            <div id='fixed'
                style='position: fixed; left: 200px; top: 150px;'></div>
          </body>
        </foreignObject>
      </g>
    </svg>
  )HTML");

  LayoutObject& svg = *GetLayoutObjectByElementId("svg");
  const ObjectPaintProperties* svg_properties =
      svg.FirstFragment().PaintProperties();
  EXPECT_EQ(MakeTranslationMatrix(1, 2, 3),
            svg_properties->Transform()->Matrix());

  LayoutObject& container = *GetLayoutObjectByElementId("container");
  const ObjectPaintProperties* container_properties =
      container.FirstFragment().PaintProperties();
  EXPECT_EQ(gfx::Vector2dF(20, 30),
            container_properties->Transform()->Get2dTranslation());
  EXPECT_EQ(svg_properties->Transform(),
            container_properties->Transform()->Parent());

  Element* fixed = GetDocument().getElementById(AtomicString("fixed"));
  // Ensure the fixed position element is rooted at the nearest transform
  // container.
  EXPECT_EQ(container_properties->Transform(), &fixed->GetLayoutObject()
                                                    ->FirstFragment()
                                                    .LocalBorderBoxProperties()
                                                    .Transform());
}

TEST_P(PaintPropertyTreeBuilderTest, ControlClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
      }
      input {
        border-radius: 0;
        border-width: 5px;
        padding: 0;
      }
    </style>
    <input id='button' type='button'
        style='width:345px; height:123px' value='some text'/>
  )HTML");

  LayoutObject& button = *GetLayoutObjectByElementId("button");
  const ObjectPaintProperties* button_properties =
      button.FirstFragment().PaintProperties();
  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            &button_properties->OverflowClip()->LocalTransformSpace());

  EXPECT_CLIP_RECT(FloatRoundedRect(5, 5, 335, 113),
                   button_properties->OverflowClip());
  EXPECT_EQ(DocContentClip(), button_properties->OverflowClip()->Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 345, 123), &button,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, ControlClipInsideForeignObject) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetBodyInnerHTML(R"HTML(
    <div style='column-count:2;'>
      <div style='columns: 2'>
        <svg style='width: 500px; height: 500px;'>
          <foreignObject style='overflow: visible;'>
            <input id='button' style='width:345px; height:123px'
                 value='some text'/>
          </foreignObject>
        </svg>
      </div>
    </div>
  )HTML");

  LayoutObject& button = *GetLayoutObjectByElementId("button");
  const ObjectPaintProperties* button_properties =
      button.FirstFragment().PaintProperties();
  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_CLIP_RECT(FloatRoundedRect(2, 2, 341, 119),
                   button_properties->OverflowClip());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(8, 8, 345, 123), &button,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, BorderRadiusClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
     body {
       margin: 0px;
     }
     #div {
       border-radius: 12px 34px 56px 78px;
       border-top: 45px solid;
       border-right: 50px solid;
       border-bottom: 55px solid;
       border-left: 60px solid;
       width: 500px;
       height: 400px;
       overflow: scroll;
     }
    </style>
    <div id='div'></div>
  )HTML");

  LayoutObject& div = *GetLayoutObjectByElementId("div");
  const ObjectPaintProperties* div_properties =
      div.FirstFragment().PaintProperties();

  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            &div_properties->OverflowClip()->LocalTransformSpace());

  // The overflow clip rect includes only the padding box.
  // padding box = border box(500+60+50, 400+45+55) - border outset(60+50,
  // 45+55) - scrollbars(15, 15)
  EXPECT_CLIP_RECT(FloatRoundedRect(60, 45, 500, 400),
                   div_properties->OverflowClip());
  auto& border_radius_clip =
      ToUnaliased(*div_properties->OverflowClip()->Parent());
  EXPECT_EQ(DocScrollTranslation(), &border_radius_clip.LocalTransformSpace());

  // The border radius clip is the area enclosed by inner border edge, including
  // the scrollbars.  As the border-radius is specified in outer radius, the
  // inner radius is calculated by:
  //     inner radius = max(outer radius - border width, 0)
  // In the case that two adjacent borders have different width, the inner
  // radius of the corner may transition from one value to the other. i.e. being
  // an ellipse.
  // The following is border box(610, 500) - border outset(110, 100).
  gfx::RectF border_box_minus_border_outset(60, 45, 500, 400);
  EXPECT_CLIP_RECT(
      FloatRoundedRect(
          border_box_minus_border_outset,
          gfx::SizeF(),        // (top left) = max((12, 12) - (60, 45), (0, 0))
          gfx::SizeF(),        // (top right) = max((34, 34) - (50, 45), (0, 0))
          gfx::SizeF(18, 23),  // (bot left) = max((78, 78) - (60, 55), (0, 0))
          gfx::SizeF(6, 1)),   // (bot right) = max((56, 56) - (50, 55), (0, 0))
      &border_radius_clip);
  EXPECT_EQ(DocContentClip(), border_radius_clip.Parent());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 610, 500), &div,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, SubpixelBorderRadiusClip) {
  SetBodyInnerHTML(R"HTML(
    <style>
     body {
       margin: 0px;
     }
     #div {
       margin-top: 0.5px;
       width: 100px;
       height: 100px;
       overflow: hidden;
       border-radius: 50%;
     }
    </style>
    <div id='div'></div>
  )HTML");

  LayoutObject& div = *GetLayoutObjectByElementId("div");
  const ObjectPaintProperties* div_properties =
      div.FirstFragment().PaintProperties();

  const ClipPaintPropertyNode* border_radius_clip =
      div_properties->InnerBorderRadiusClip();
  FloatClipRect expected_layout_clip_rect(gfx::RectF(0, 0.5, 100, 100));
  expected_layout_clip_rect.SetHasRadius();
  EXPECT_EQ(expected_layout_clip_rect, border_radius_clip->LayoutClipRect());
  EXPECT_EQ(
      FloatRoundedRect(gfx::RectF(0, 1, 100, 100), FloatRoundedRect::Radii(50)),
      border_radius_clip->PaintClipRect());
}

TEST_P(PaintPropertyTreeBuilderTest, TransformNodesAcrossSubframes) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #divWithTransform {
        transform: translate3d(1px, 2px, 3px);
      }
    </style>
    <div id='divWithTransform'>
      <iframe id='iframe' style='border: 7px solid black'></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      body { margin: 0; }
      #innerDivWithTransform {
        transform: translate3d(4px, 5px, 6px);
        width: 100px;
        height: 200px;
      }
    </style>
    <div id='innerDivWithTransform'></div>
  )HTML");

  LocalFrameView* frame_view = GetDocument().View();
  frame_view->UpdateAllLifecyclePhasesForTest();

  LayoutObject* div_with_transform =
      GetLayoutObjectByElementId("divWithTransform");
  const ObjectPaintProperties* div_with_transform_properties =
      div_with_transform->FirstFragment().PaintProperties();
  EXPECT_EQ(MakeTranslationMatrix(1, 2, 3),
            div_with_transform_properties->Transform()->Matrix());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(1, 2, 800, 164), div_with_transform,
                          frame_view->GetLayoutView());

  LayoutObject* inner_div_with_transform =
      ChildDocument()
          .getElementById(AtomicString("innerDivWithTransform"))
          ->GetLayoutObject();
  const ObjectPaintProperties* inner_div_with_transform_properties =
      inner_div_with_transform->FirstFragment().PaintProperties();
  auto* inner_div_transform = inner_div_with_transform_properties->Transform();
  EXPECT_EQ(MakeTranslationMatrix(4, 5, 6), inner_div_transform->Matrix());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(12, 14, 100, 145),
                          inner_div_with_transform,
                          frame_view->GetLayoutView());

  // Ensure that the inner div's transform is correctly rooted in the root
  // frame's transform tree.
  // This asserts that we have the following tree structure:
  // Transform transform=translation=1.000000,2.000000,3.000000
  //   PreTranslation transform=translation=7.000000,7.000000,0.000000
  //     PaintOffsetTranslation transform=Identity
  //       ScrollTranslation transform=translation=0.000000,0.000000,0.000000
  //         Transform transform=translation=4.000000,5.000000,6.000000
  auto* inner_document_scroll_translation =
      inner_div_transform->UnaliasedParent();
  EXPECT_TRUE(inner_document_scroll_translation->IsIdentity());
  auto* paint_offset_translation =
      inner_document_scroll_translation->UnaliasedParent();
  auto* iframe_pre_translation = paint_offset_translation->UnaliasedParent();
  EXPECT_TRUE(paint_offset_translation->IsIdentity());
  EXPECT_EQ(gfx::Vector2dF(7, 7), iframe_pre_translation->Get2dTranslation());
  EXPECT_EQ(div_with_transform_properties->Transform(),
            iframe_pre_translation->Parent());
}

TEST_P(PaintPropertyTreeBuilderTest, FramesEstablishIsolation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      .transformed {
        transform: translateX(1px);
      }
      #parent {
        width: 100px;
        height: 100px;
        overflow: hidden;
      }
    </style>
    <div id='parent'>
      <iframe id='iframe'></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      body { margin: 0; }
      #child {
        transform: translateX(50px);
        width: 50px;
        height: 50px;
        overflow: hidden;
      }
    </style>
    <div id='child'></div>
  )HTML");

  LocalFrameView* frame_view = GetDocument().View();
  frame_view->UpdateAllLifecyclePhasesForTest();

  LayoutObject* frame = ChildFrame().View()->GetLayoutView();
  const auto& frame_contents_properties =
      frame->FirstFragment().ContentsProperties();

  LayoutObject* child =
      ChildDocument().getElementById(AtomicString("child"))->GetLayoutObject();
  const auto& child_local_border_box_properties =
      child->FirstFragment().LocalBorderBoxProperties();
  auto* child_properties =
      child->GetMutableForPainting().FirstFragment().PaintProperties();

  // From the frame content's properties, we have:
  //  - transform isolation node
  //    - paint offset translation
  //      - transform
  EXPECT_EQ(gfx::Vector2dF(50, 0),
            ToUnaliased(child_local_border_box_properties.Transform())
                .Get2dTranslation());
  EXPECT_EQ(child_local_border_box_properties.Transform().Parent(),
            child_properties->PaintOffsetTranslation());
  EXPECT_EQ(child_local_border_box_properties.Transform().Parent()->Parent(),
            &frame_contents_properties.Transform());
  // Verify it's a true isolation node (i.e. it has a parent and it is a parent
  // alias).
  EXPECT_TRUE(frame_contents_properties.Transform().Parent());
  EXPECT_TRUE(frame_contents_properties.Transform().IsParentAlias());

  // Do similar checks for clip and effect, although the child local border box
  // properties directly reference the alias, since they do not have their own
  // clip and effect.
  EXPECT_EQ(&child_local_border_box_properties.Clip(),
            &frame_contents_properties.Clip());
  EXPECT_TRUE(frame_contents_properties.Clip().Parent());
  EXPECT_TRUE(frame_contents_properties.Clip().IsParentAlias());

  EXPECT_EQ(&child_local_border_box_properties.Effect(),
            &frame_contents_properties.Effect());
  EXPECT_TRUE(frame_contents_properties.Effect().Parent());
  EXPECT_TRUE(frame_contents_properties.Effect().IsParentAlias());

// The following part of the code would cause a DCHECK, but we want to see if
// the pre-paint iteration doesn't touch child's state, due to isolation. Hence,
// this only runs if we don't have DCHECKs enabled.
#if !DCHECK_IS_ON()
  // Now clobber the child transform to something identifiable.
  TransformPaintPropertyNode::State state{{MakeTranslationMatrix(123, 321)}};
  child_properties->UpdateTransform(
      *child_local_border_box_properties.Transform().Parent(),
      std::move(state));
  // Verify that we clobbered it correctly.
  EXPECT_EQ(gfx::Vector2dF(123, 321),
            ToUnaliased(child_local_border_box_properties.Transform())
                .Get2dTranslation());

  // This causes a tree topology change which forces the subtree to be updated.
  // However, isolation stops this recursion.
  GetDocument()
      .getElementById(AtomicString("parent"))
      ->setAttribute(html_names::kClassAttr, AtomicString("transformed"));
  frame_view->UpdateAllLifecyclePhasesForTest();

  // Verify that our clobbered state is still clobbered.
  EXPECT_EQ(gfx::Vector2dF(123, 321),
            ToUnaliased(child_local_border_box_properties.Transform())
                .Get2dTranslation());
#endif  // !DCHECK_IS_ON()
}

TEST_P(PaintPropertyTreeBuilderTest, TransformNodesInTransformedSubframes) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #divWithTransform {
        transform: translate3d(1px, 2px, 3px);
      }
      iframe {
        transform: translate3d(4px, 5px, 6px);
        border: 42px solid;
        margin: 7px;
      }
    </style>
    <div id='divWithTransform'>
      <iframe></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      body { margin: 31px; }
      #transform {
        transform: translate3d(7px, 8px, 9px);
        width: 100px;
        height: 200px;
      }
    </style>
    <div id='transform'></div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->UpdateAllLifecyclePhasesForTest();

  // Assert that we have the following tree structure:
  // ...
  //   Transform transform=translation=1.000000,2.000000,3.000000
  //     PaintOffsetTranslation transform=translation=7.000000,7.000000,0.000000
  //       Transform transform=translation=4.000000,5.000000,6.000000
  //         PreTranslation transform=translation=42.000000,42.000000,0.000000
  //           ScrollTranslation transform=translation=0.000000,0.000000,0.00000
  //             PaintOffsetTranslation transform=translation=31.00,31.00,0.00
  //               Transform transform=translation=7.000000,8.000000,9.000000

  LayoutObject* inner_div_with_transform =
      ChildDocument()
          .getElementById(AtomicString("transform"))
          ->GetLayoutObject();
  auto* inner_div_transform =
      inner_div_with_transform->FirstFragment().PaintProperties()->Transform();
  EXPECT_EQ(MakeTranslationMatrix(7, 8, 9), inner_div_transform->Matrix());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(92, 95, 100, 111),
                          inner_div_with_transform,
                          frame_view->GetLayoutView());

  auto* inner_document_paint_offset_translation =
      inner_div_transform->UnaliasedParent();
  EXPECT_EQ(gfx::Vector2dF(31, 31),
            inner_document_paint_offset_translation->Get2dTranslation());
  auto* inner_document_scroll_translation =
      inner_document_paint_offset_translation->UnaliasedParent();
  EXPECT_TRUE(inner_document_scroll_translation->IsIdentity());
  auto* iframe_pre_translation =
      inner_document_scroll_translation->UnaliasedParent();
  EXPECT_EQ(gfx::Vector2dF(42, 42), iframe_pre_translation->Get2dTranslation());
  auto* iframe_transform = iframe_pre_translation->UnaliasedParent();
  EXPECT_EQ(MakeTranslationMatrix(4, 5, 6), iframe_transform->Matrix());
  auto* iframe_paint_offset_translation = iframe_transform->UnaliasedParent();
  EXPECT_EQ(gfx::Vector2dF(7, 7),
            iframe_paint_offset_translation->Get2dTranslation());
  auto* div_with_transform_transform =
      iframe_paint_offset_translation->UnaliasedParent();
  EXPECT_EQ(MakeTranslationMatrix(1, 2, 3),
            div_with_transform_transform->Matrix());

  LayoutObject* div_with_transform =
      GetLayoutObjectByElementId("divWithTransform");
  EXPECT_EQ(div_with_transform_transform,
            div_with_transform->FirstFragment().PaintProperties()->Transform());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(1, 2, 800, 248), div_with_transform,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, TreeContextClipByNonStackingContext) {
  // This test verifies the tree builder correctly computes and records the
  // property tree context for a (pseudo) stacking context that is scrolled by a
  // containing block that is not one of the painting ancestors.
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      /* to prevent the mock overlay scrollbar from affecting compositing. */
      #scroller::-webkit-scrollbar { display: none; }
    </style>
    <div id='scroller' style='overflow:scroll; width:400px; height:300px;'>
      <div id='child'
          style='position:relative; width:100px; height: 200px;'></div>
      <div style='height:10000px;'></div>
    </div>
  )HTML");
  LocalFrameView* frame_view = GetDocument().View();

  LayoutObject* scroller = GetLayoutObjectByElementId("scroller");
  const ObjectPaintProperties* scroller_properties =
      scroller->FirstFragment().PaintProperties();
  LayoutObject* child = GetLayoutObjectByElementId("child");

  EXPECT_EQ(scroller_properties->OverflowClip(),
            &child->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(scroller_properties->ScrollTranslation(),
            &child->FirstFragment().LocalBorderBoxProperties().Transform());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 400, 300), scroller,
                          frame_view->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 100, 200), child,
                          frame_view->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest,
       TreeContextUnclipFromParentStackingContext) {
  // This test verifies the tree builder correctly computes and records the
  // property tree context for a (pseudo) stacking context that has a scrolling
  // painting ancestor that is not its containing block (thus should not be
  // scrolled by it).

  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      #scroller {
        overflow:scroll;
        opacity:0.5;
      }
      #child {
        position:absolute;
        left:0;
        top:0;
        width: 100px;
        height: 200px;
      }
    </style>
    <div id='scroller'>
      <div id='child'></div>
      <div id='forceScroll' style='height:10000px;'></div>
    </div>
  )HTML");

  auto& scroller = *GetLayoutObjectByElementId("scroller");
  const ObjectPaintProperties* scroller_properties =
      scroller.FirstFragment().PaintProperties();
  LayoutObject& child = *GetLayoutObjectByElementId("child");

  EXPECT_EQ(DocContentClip(),
            &child.FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(DocScrollTranslation(),
            &child.FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(scroller_properties->Effect(),
            &child.FirstFragment().LocalBorderBoxProperties().Effect());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 800, 10000), &scroller,
                          GetDocument().View()->GetLayoutView());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(0, 0, 100, 200), &child,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, TableCellLayoutLocation) {
  // This test verifies that the border box space of a table cell is being
  // correctly computed.  Table cells have weird location adjustment in our
  // layout/paint implementation.
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
      }
      table {
        border-spacing: 0;
        margin: 20px;
        padding: 40px;
        border: 10px solid black;
      }
      td {
        width: 100px;
        height: 100px;
        padding: 0;
      }
      #target {
        position: relative;
        width: 100px;
        height: 100px;
      }
    </style>
    <table>
      <tr><td></td><td></td></tr>
      <tr><td></td><td><div id='target'></div></td></tr>
    </table>
  )HTML");

  LayoutObject& target = *GetLayoutObjectByElementId("target");
  EXPECT_EQ(PhysicalOffset(170, 170), target.FirstFragment().PaintOffset());
  EXPECT_EQ(DocScrollTranslation(),
            &target.FirstFragment().LocalBorderBoxProperties().Transform());
  CHECK_EXACT_VISUAL_RECT(PhysicalRect(170, 170, 100, 100), &target,
                          GetDocument().View()->GetLayoutView());
}

TEST_P(PaintPropertyTreeBuilderTest, CSSClipFixedPositionDescendant) {
  // This test verifies that clip tree hierarchy being generated correctly for
  // the hard case such that a fixed position element getting clipped by an
  // absolute position CSS clip.
  SetBodyInnerHTML(R"HTML(
    <style>
      #clip {
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
        width: 10px;
        height: 20px
      }
    </style>
    <div id='clip'><div id='fixed'></div></div>
  )HTML");
  PhysicalRect local_clip_rect(40, 10, 40, 60);
  PhysicalRect absolute_clip_rect = local_clip_rect;
  absolute_clip_rect.offset += PhysicalOffset(123, 456);

  LayoutObject& clip = *GetLayoutObjectByElementId("clip");
  const ObjectPaintProperties* clip_properties =
      clip.FirstFragment().PaintProperties();
  EXPECT_EQ(DocContentClip(), clip_properties->CssClip()->Parent());
  EXPECT_EQ(DocScrollTranslation(),
            &clip_properties->CssClip()->LocalTransformSpace());
  EXPECT_CLIP_RECT(gfx::RectF(absolute_clip_rect), clip_properties->CssClip());
  CHECK_VISUAL_RECT(absolute_clip_rect, &clip,
                    GetDocument().View()->GetLayoutView(),
                    // TODO(crbug.com/599939): mapToVisualRectInAncestorSpace()
                    // doesn't apply css clip on the object itself.
                    LayoutUnit::Max());

  LayoutObject* fixed = GetLayoutObjectByElementId("fixed");
  EXPECT_EQ(clip_properties->CssClip(),
            &fixed->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_EQ(fixed->FirstFragment().PaintProperties()->PaintOffsetTranslation(),
            &fixed->FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(PhysicalOffset(0, 0), fixed->FirstFragment().PaintOffset());
  CHECK_VISUAL_RECT(PhysicalRect(), fixed,
                    GetDocument().View()->GetLayoutView(),
                    // TODO(crbug.com/599939): CSS clip of fixed-position
                    // descendants is broken in
                    // mapToVisualRectInAncestorSpace().
                    LayoutUnit::Max());
}

TEST_P(PaintPropertyTreeBuilderTest, CSSClipAbsPositionDescendant) {
  // This test verifies that clip tree hierarchy being generated correctly for
  // the hard case such that a fixed position element getting clipped by an
  // absolute position CSS clip.
  SetBodyInnerHTML(R"HTML(
    <style>
      #clip {
        position: absolute;
        left: 123px;
        top: 456px;
        clip: rect(10px, 80px, 70px, 40px);
        width: 100px;
        height: 100px;
      }
      #absolute {
        position: absolute;
        left: 654px;
        top: 321px;
        width: 10px;
        heght: 20px
      }
    </style>
    <div id='clip'><div id='absolute'></div></div>
  )HTML");

  PhysicalRect local_clip_rect(40, 10, 40, 60);
  PhysicalRect absolute_clip_rect = local_clip_rect;
  absolute_clip_rect.offset += PhysicalOffset(123, 456);

  auto* clip = GetLayoutObjectByElementId("clip");
  const ObjectPaintProperties* clip_properties =
      clip->FirstFragment().PaintProperties();
  EXPECT_EQ(DocContentClip(), clip_properties->CssClip()->Parent());
  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            &clip_properties->CssClip()->LocalTransformSpace());
  EXPECT_CLIP_RECT(gfx::RectF(absolute_clip_rect), clip_properties->CssClip());
  CHECK_VISUAL_RECT(absolute_clip_rect, clip,
                    GetDocument().View()->GetLayoutView(),
                    // TODO(crbug.com/599939): mapToVisualRectInAncestorSpace()
                    // doesn't apply css clip on the object itself.
                    LayoutUnit::Max());

  auto* absolute = GetLayoutObjectByElementId("absolute");
  EXPECT_EQ(clip_properties->CssClip(),
            &absolute->FirstFragment().LocalBorderBoxProperties().Clip());
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            &absolute->FirstFragment().LocalBorderBoxProperties().Transform());
  EXPECT_EQ(PhysicalOffset(777, 777), absolute->FirstFragment().PaintOffset());
  CHECK_VISUAL_RECT(PhysicalRect(), absolute,
                    GetDocument().View()->GetLayoutView(),
                    // TODO(crbug.com/599939): CSS clip of fixed-position
                    // descendants is broken in
                    // mapToVisualRectInAncestorSpace().
                    LayoutUnit::Max());
}

TEST_P(PaintPropertyTreeBuilderTest, CSSClipSubpixel) {
  // This test verifies that clip tree hierarchy being generated correctly for
  // a subpixel-positioned element with CSS clip.
  SetBodyInnerHTML(R"HTML(
    <style>
      #clip {
        position: absolute;
        left: 123.5px;
        top: 456px;
        clip: rect(10px, 80px, 70px, 40px);
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='clip'></div>
  )HTML");

  PhysicalRect local_clip_rect(40, 10, 40, 60);
  PhysicalRect absolute_clip_rect = local_clip_rect;
  // Moved by 124 pixels due to pixel-snapping.
  absolute_clip_rect.offset +=
      PhysicalOffset(LayoutUnit(123.5), LayoutUnit(456));

  auto* clip = GetLayoutObjectByElementId("clip");
  const ObjectPaintProperties* clip_properties =
      clip->FirstFragment().PaintProperties();
  EXPECT_EQ(DocContentClip(), clip_properties->CssClip()->Parent());
  // Always create scroll translation for layout view even the document does
  // not scroll (not enough content).
  EXPECT_TRUE(DocScrollTranslation());
  EXPECT_EQ(DocScrollTranslation(),
            &clip_properties->CssClip()->LocalTransformSpace());
  EXPECT_EQ(FloatClipRect(gfx::RectF(absolute_clip_rect)),
            clip_properties->CssClip()->LayoutClipRect());
  EXPECT_EQ(FloatRoundedRect(ToPixelSnappedRect((absolute_clip_rect))),
            clip_properties->CssClip()->PaintClipRect());
}

TEST_P(PaintPropertyTreeBuilderTest, CSSClipFixedPositionDescendantNonShared) {
  // This test is similar to CSSClipFixedPositionDescendant above, except that
  // now we have a parent overflow clip that should be escaped by the fixed
  // descendant.
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
      }
      /* to prevent the mock overlay scrollbar from affecting compositing. */
      #overflow::-webkit-scrollbar {
        display: none;
      }
      #overflow {
        position: relative;
        width: 50px;
        height: 50px;
        overflow: scroll;
      }
      #clip {
   
"""


```