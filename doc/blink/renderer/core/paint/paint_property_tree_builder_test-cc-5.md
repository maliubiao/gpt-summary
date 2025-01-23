Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code snippet is part of a test file (`paint_property_tree_builder_test.cc`) for the Blink rendering engine, specifically for the paint property tree builder.

Here's a breakdown of the thought process:

1. **Identify the core functionality:** The filename itself gives a strong hint: `paint_property_tree_builder_test.cc`. This means the code is testing the `PaintPropertyTreeBuilder`. The `PaintPropertyTreeBuilder`'s job is to construct the paint property tree, which is a data structure that describes how elements should be painted.

2. **Analyze the test cases:** The code contains numerous `TEST_P` blocks. Each of these blocks sets up an HTML structure and then makes assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_CLIP_RECT`) about the resulting paint property tree. By examining these tests, we can deduce the features being tested.

3. **Categorize the tested features:** Group the tests based on the CSS properties and concepts they are exercising. Some clear categories emerge:
    * **Scrolling:** Tests involving `overflow: scroll`, `position: fixed`, `position: absolute`, and how scroll nodes are created and parented.
    * **Positioning:** Tests dealing with absolute and fixed positioning and how they interact with scrolling.
    * **SVG:** Tests specifically for how SVG elements create clipping nodes.
    * **Multi-column layouts:**  A significant number of tests focus on how paint properties are handled within multi-column contexts, including spanning elements, fragmentation, and interaction with fixed positioning and overflow.
    * **Filters and Reflections:** Tests checking how CSS filters and `-webkit-box-reflect` affect the paint property tree.
    * **`will-change`:** Tests verifying how the `will-change` property influences the creation of compositing layers and clip expanders.

4. **Connect to web technologies (JavaScript, HTML, CSS):** Since the paint property tree is built based on HTML, CSS, and their interactions, it's crucial to show how the tests relate to these technologies. Provide examples of the HTML and CSS being tested and the corresponding effects on the rendering.

5. **Infer logical reasoning:** The tests perform assertions based on the input HTML and CSS. We can infer the logic the `PaintPropertyTreeBuilder` is expected to implement by looking at the expected outcomes. For instance, when an absolutely positioned scrolling element is inside a normal scrolling element, the absolutely positioned scroller's scroll node is parented under the document's scroll node, not the parent's scroll node. This indicates a specific logic for handling nested scrolling contexts with absolute positioning.

6. **Identify potential user errors:** Consider scenarios where incorrect HTML or CSS usage might lead to unexpected results or trigger the code being tested. For example, misunderstanding how absolute and fixed positioning affect the scroll hierarchy is a common issue.

7. **Trace user actions to the code:** Think about the steps a user takes in a browser that would eventually trigger the paint property tree building process. This usually involves loading a web page with HTML and CSS, which the browser parses and then uses to construct the render tree and subsequently the paint property tree.

8. **Address the "part X of 10" instruction:**  Recognize that this is part of a larger file and the provided snippet likely represents a subset of the total functionality tested. Therefore, the summary should reflect that this is just a portion of the overall testing.

9. **Structure the answer:** Organize the findings into clear sections: functionality summary, relationships to web technologies, logical reasoning examples, common user errors, debugging clues, and a summary of this specific part.

**(Self-Correction during the process):** Initially, I might have just listed the tests without grouping them. However, realizing the need for a coherent summary, I would then refine the approach to categorize the tests by feature. Also, I'd make sure to explicitly connect the tests to the user-facing aspects of web development (HTML, CSS, JavaScript).
这是 `blink/renderer/core/paint/paint_property_tree_builder_test.cc` 文件的第 6 部分，该文件是 Chromium Blink 引擎的源代码，专门用于测试 **Paint Property Tree Builder** 的功能。

**它的主要功能是：**

验证 `PaintPropertyTreeBuilder` 类在各种复杂的布局和样式场景下，是否能正确构建 **Paint Property Tree**。Paint Property Tree 是渲染引擎内部用于优化绘制过程的关键数据结构，它将渲染对象（LayoutObject）的绘制属性组织成树状结构，以便进行高效的图层合成和绘制。

**与 JavaScript, HTML, CSS 的功能关系：**

这个测试文件直接测试的是渲染引擎根据 HTML 和 CSS 构建内部数据结构的过程。  它模拟了不同的 HTML 结构和 CSS 样式，然后断言生成的 Paint Property Tree 是否符合预期。

**举例说明：**

* **CSS `overflow: scroll`:**  测试用例 `NestedOverflowScroll` 和 `PositionedScrollerIsNotNested` 验证了当元素设置 `overflow: scroll` 时，`PaintPropertyTreeBuilder` 是否正确创建了 **Scroll Node**，并将其正确地连接到父节点的树中。这与用户通过 CSS 声明元素可以滚动有关。
    * **假设输入 (HTML/CSS):**
      ```html
      <div style="overflow: scroll; width: 100px; height: 100px;">
        <div style="height: 200px;"></div>
      </div>
      ```
    * **预期输出 (部分 Paint Property Tree):**  应该存在一个与该 `div` 关联的 Scroll Node，其 `ContentsRect` 应该能容纳内部超出范围的内容。

* **CSS `position: absolute` 和 `position: fixed`:**  测试用例 `PositionedScrollerIsNotNested` 和 `NestedPositionedScrollProperties`  验证了当滚动容器具有 `position: absolute` 或 `position: fixed` 时，其 Scroll Node 在 Paint Property Tree 中的位置。通常，绝对定位或固定定位的滚动容器的 Scroll Node 会直接挂载在文档的滚动节点下，而不是其 DOM 父节点的滚动节点下。这与用户通过 CSS 控制元素的定位方式有关。
    * **假设输入 (HTML/CSS):**
      ```html
      <div style="position: absolute; overflow: scroll; width: 100px; height: 100px;">
        <div style="height: 200px;"></div>
      </div>
      ```
    * **预期输出 (部分 Paint Property Tree):**  该 `div` 的 Scroll Node 的 Parent 应该是指向文档的滚动节点。

* **CSS `columns` (多列布局):**  大量的测试用例 (如 `PaintOffsetsUnderMultiColumnScrolled`, `FragmentsUnderMultiColumn`, `CompositedUnderMultiColumn` 等) 验证了在多列布局下，`PaintPropertyTreeBuilder` 如何处理元素的 **Paint Offset** 和 **Fragment**。这与用户通过 CSS 创建多列布局有关。
    * **假设输入 (HTML/CSS):**
      ```html
      <div style="columns: 2; width: 200px;">
        <div>Column 1</div>
        <div>Column 2</div>
      </div>
      ```
    * **预期输出 (部分 Paint Property Tree):**  第二个 `div` 的 Paint Offset 的 X 坐标应该大约为 100px（假设没有 column-gap）。

* **CSS Filters 和 Reflections:** 测试用例 `Reflection`, `SimpleFilter`, `PixelMovingFilter` 等验证了 CSS 滤镜 (`filter`) 和反射 (`-webkit-box-reflect`) 属性如何影响 Paint Property Tree 的构建，例如创建 **Effect Node** 和 **Clip Node**。
    * **假设输入 (HTML/CSS):**
      ```html
      <div style="filter: blur(5px);">Content</div>
      ```
    * **预期输出 (部分 Paint Property Tree):**  应该存在一个与该 `div` 关联的 Effect Node，表示需要应用滤镜效果。

* **CSS `will-change`:** 测试用例 `SimpleFilterWithWillChangeTransform` 和 `WillChangeFilterCreatesClipExpander` 验证了 `will-change` 属性如何影响图层合成和 Paint Property Tree 的构建，例如可能创建独立的合成层。
    * **假设输入 (HTML/CSS):**
      ```html
      <div style="will-change: transform;">Content</div>
      ```
    * **预期输出 (部分 Paint Property Tree):**  该 `div` 可能会被提升为独立的合成层。

**逻辑推理 (假设输入与输出):**

大部分的测试都是直接断言 Paint Property Node 的属性值，例如 `Parent()`, `Get2dTranslation()`, `ContainerRect()`, `ContentsRect()`, `PaintOffset()`, `FragmentID()` 等。  测试会设置特定的 HTML 和 CSS，然后根据渲染引擎的逻辑，预期这些属性应该具有特定的值。

**涉及用户或者编程常见的使用错误：**

* **不理解 `position: absolute` 和 `position: fixed` 对滚动容器的影响:**  用户可能错误地认为，一个绝对定位的滚动容器的子元素会相对于该容器滚动。但实际上，其滚动行为更像是相对于视口或最近的定位祖先。测试用例可以帮助开发者理解这种行为。
* **错误地假设多列布局下的定位行为:**  用户可能不清楚在多列布局中，绝对定位元素的包含块是谁，以及 `column-span: all` 元素如何影响布局。测试用例 `FragmentsUnderMultiColumn` 就覆盖了这些场景。
* **不理解 CSS 滤镜和反射的图层合成行为:** 用户可能不清楚何时会创建合成层来应用滤镜或反射效果。测试用例帮助验证引擎在这方面的行为。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 HTML 和 CSS 代码:**  这是最开始的步骤，用户通过编写代码来描述网页的结构和样式。例如，用户可能会创建一个包含滚动条的 `div`，或者使用多列布局。
2. **浏览器加载并解析 HTML 和 CSS:**  当用户访问网页时，浏览器会下载 HTML 和 CSS 文件，并进行解析，构建 DOM 树和 CSSOM 树。
3. **构建 Render Tree (或 Layout Tree):**  浏览器将 DOM 树和 CSSOM 树结合，生成 Render Tree，也称为 Layout Tree。这个树描述了网页的可视化结构，包含了每个元素的位置和尺寸信息。
4. **运行 Style 和 Layout 阶段:**  浏览器会计算每个元素的最终样式，并进行布局计算，确定每个元素在页面上的确切位置和大小。
5. **构建 Paint Property Tree:**  在这个阶段，`PaintPropertyTreeBuilder` 类会被调用，它遍历 Render Tree，并根据元素的样式属性 (如 `overflow`, `position`, `transform`, `filter` 等) 构建 Paint Property Tree。
6. **图层合成 (Layer Composition):**  渲染引擎会根据 Paint Property Tree 的信息，决定哪些元素需要提升为独立的合成层，以便进行硬件加速渲染。
7. **绘制 (Painting):**  最终，渲染引擎将各个图层绘制到屏幕上。

当开发者发现页面渲染出现问题，例如滚动行为异常，或者滤镜效果没有正确应用时，他们可能会需要查看 Paint Property Tree 来进行调试。`paint_property_tree_builder_test.cc` 中的测试用例就是为了确保这个构建过程的正确性。如果测试失败，就意味着 `PaintPropertyTreeBuilder` 在某种情况下产生了错误的树结构，这可能会导致渲染错误。

**归纳一下它的功能 (针对提供的代码片段):**

这部分代码主要测试了 `PaintPropertyTreeBuilder` 在以下场景下的功能：

* **嵌套的滚动容器:** 验证在嵌套的滚动容器中，Scroll Node 的父子关系和滚动偏移是否正确。特别关注了内容区域 (ContentsRect) 的计算，以及用户是否可以滚动。
* **绝对定位和固定定位的滚动容器:**  验证了当滚动容器使用绝对定位或固定定位时，其 Scroll Node 如何正确地挂载到文档的滚动节点下，而不是 DOM 树的父节点。
* **嵌套的绝对定位滚动容器:**  进一步测试了嵌套的绝对定位滚动容器的 Scroll Node 的父子关系和滚动偏移。
* **SVG 根元素的裁剪:** 验证了 SVG 根元素是否会创建正确的裁剪节点 (ClipPaintPropertyNode)。
* **不需要滚动的背景固定元素:** 验证了当元素具有 `background-attachment: fixed` 但不需要滚动时，是否会正确处理。
* **多列布局下的 Paint Offset:**  测试了在多列布局中，元素的 Paint Offset 的计算。
* **多列布局下的元素 Fragment:**  详细测试了多列布局下，元素可能被分割成多个 Fragment，并验证了这些 Fragment 的 Paint Offset 和关联的 Paint Properties。涵盖了跨列元素 (`column-span: all`) 和溢出情况。
* **多列布局下的固定定位元素:**  测试了在多列布局中，固定定位元素的 Paint Offset。
* **多列布局下的图层合成和裁剪:**  测试了在多列布局中，包含 `overflow: hidden` 的元素以及声明了 `will-change` 属性的元素如何影响图层合成和裁剪。
* **多列布局与 iframe 的交互:** 测试了在多列布局中嵌套 iframe 的情况。
* **元素从被分割到不被分割的状态变化:** 测试了元素在多列布局中，由于样式改变导致不再需要分割时，Paint Property Tree 的更新情况。
* **CSS 反射 (`-webkit-box-reflect`) 的处理:** 验证了反射效果如何创建 Effect Node 和 Paint Offset Translation Node。
* **简单的 CSS 滤镜 (`filter`) 的处理:** 验证了简单的滤镜效果如何创建 Effect Node。
* **会移动像素的 CSS 滤镜 (如 `blur`) 的处理:** 验证了这类滤镜如何创建 Effect Node 和 Clip Expander Node。
* **带有 `will-change: transform` 的滤镜:** 验证了 `will-change` 对滤镜的影响。
* **带有 `will-change: filter` 的元素:** 验证了 `will-change: filter` 是否会创建 Clip Expander Node。
* **滤镜效果下的裁剪:**  验证了当元素同时具有滤镜和 `overflow: hidden` 时，Clip Node 和 Effect Node 的父子关系。

总而言之，这部分代码专注于测试 `PaintPropertyTreeBuilder` 在处理各种复杂的布局场景，特别是涉及到滚动、定位、多列布局、滤镜和反射等特性时，是否能够正确地构建 Paint Property Tree。这是确保渲染引擎正确渲染页面的关键一步。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
s the forceScroll element plus the height of the overflow scroll child
  // (overflowB).
  EXPECT_EQ(gfx::Rect(0, 0, 9, 107), overflow_a_scroll_node->ContentsRect());
  EXPECT_TRUE(overflow_a_scroll_node->UserScrollableHorizontal());
  EXPECT_TRUE(overflow_a_scroll_node->UserScrollableVertical());

  const ObjectPaintProperties* overflow_b_scroll_properties =
      overflow_b->GetLayoutObject()->FirstFragment().PaintProperties();
  // The overflow child's scroll node should be a child of the parent's
  // (overflowA) scroll node.
  auto* scroll_b_translation =
      overflow_b_scroll_properties->ScrollTranslation();
  auto* overflow_b_scroll_node = scroll_b_translation->ScrollNode();
  EXPECT_EQ(overflow_a_scroll_node, overflow_b_scroll_node->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -41), scroll_b_translation->Get2dTranslation());
  EXPECT_EQ(gfx::Rect(0, 0, 9, 7), overflow_b_scroll_node->ContainerRect());
  EXPECT_EQ(gfx::Rect(0, 0, 9, 100), overflow_b_scroll_node->ContentsRect());
  EXPECT_TRUE(overflow_b_scroll_node->UserScrollableHorizontal());
  EXPECT_TRUE(overflow_b_scroll_node->UserScrollableVertical());
}

TEST_P(PaintPropertyTreeBuilderTest, PositionedScrollerIsNotNested) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0px;
      }
      #overflow {
        overflow: scroll;
        width: 5px;
        height: 3px;
      }
      #absposOverflow {
        position: absolute;
        top: 0;
        left: 0;
        overflow: scroll;
        width: 9px;
        height: 7px;
      }
      #fixedOverflow {
        position: fixed;
        top: 0;
        left: 0;
        overflow: scroll;
        width: 13px;
        height: 11px;
      }
      .forceScroll {
        height: 4000px;
      }
    </style>
    <div id='overflow'>
      <div id='absposOverflow'>
        <div class='forceScroll'></div>
      </div>
      <div id='fixedOverflow'>
        <div class='forceScroll'></div>
      </div>
      <div class='forceScroll'></div>
    </div>
    <div class='forceScroll'></div>
  )HTML");

  Element* overflow = GetDocument().getElementById(AtomicString("overflow"));
  overflow->setScrollTop(37);
  Element* abspos_overflow =
      GetDocument().getElementById(AtomicString("absposOverflow"));
  abspos_overflow->setScrollTop(41);
  Element* fixed_overflow =
      GetDocument().getElementById(AtomicString("fixedOverflow"));
  fixed_overflow->setScrollTop(43);

  UpdateAllLifecyclePhasesForTest();

  // The frame should scroll due to the "forceScroll" element.
  EXPECT_NE(nullptr, DocScroll());

  const ObjectPaintProperties* overflow_scroll_properties =
      overflow->GetLayoutObject()->FirstFragment().PaintProperties();
  auto* scroll_translation = overflow_scroll_properties->ScrollTranslation();
  auto* overflow_scroll_node = scroll_translation->ScrollNode();
  EXPECT_EQ(
      DocScroll(),
      overflow_scroll_properties->ScrollTranslation()->ScrollNode()->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -37), scroll_translation->Get2dTranslation());
  EXPECT_EQ(gfx::Rect(0, 0, 5, 3), overflow_scroll_node->ContainerRect());
  // The height should be 4000px because the (dom-order) overflow children are
  // positioned and do not contribute to the height. Only the 4000px
  // "forceScroll" height is present.
  EXPECT_EQ(gfx::Rect(0, 0, 5, 4000), overflow_scroll_node->ContentsRect());

  const ObjectPaintProperties* abspos_overflow_scroll_properties =
      abspos_overflow->GetLayoutObject()->FirstFragment().PaintProperties();
  auto* abspos_scroll_translation =
      abspos_overflow_scroll_properties->ScrollTranslation();
  auto* abspos_overflow_scroll_node = abspos_scroll_translation->ScrollNode();
  // The absolute position overflow scroll node is parented under the frame, not
  // the dom-order parent.
  EXPECT_EQ(DocScroll(), abspos_overflow_scroll_node->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -41),
            abspos_scroll_translation->Get2dTranslation());
  EXPECT_EQ(gfx::Rect(0, 0, 9, 7),
            abspos_overflow_scroll_node->ContainerRect());
  EXPECT_EQ(gfx::Rect(0, 0, 9, 4000),
            abspos_overflow_scroll_node->ContentsRect());

  const ObjectPaintProperties* fixed_overflow_scroll_properties =
      fixed_overflow->GetLayoutObject()->FirstFragment().PaintProperties();
  auto* fixed_scroll_translation =
      fixed_overflow_scroll_properties->ScrollTranslation();
  auto* fixed_overflow_scroll_node = fixed_scroll_translation->ScrollNode();
  // The fixed position overflow scroll node is parented under the frame, not
  // the dom-order parent.
  EXPECT_EQ(DocScroll(), fixed_overflow_scroll_node->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -43),
            fixed_scroll_translation->Get2dTranslation());
  EXPECT_EQ(gfx::Rect(0, 0, 13, 11),
            fixed_overflow_scroll_node->ContainerRect());
  EXPECT_EQ(gfx::Rect(0, 0, 13, 4000),
            fixed_overflow_scroll_node->ContentsRect());
}

TEST_P(PaintPropertyTreeBuilderTest, NestedPositionedScrollProperties) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * {
        margin: 0px;
      }
      #overflowA {
        position: absolute;
        top: 7px;
        left: 11px;
        overflow: scroll;
        width: 20px;
        height: 20px;
      }
      #overflowB {
        position: absolute;
        top: 1px;
        left: 3px;
        overflow: scroll;
        width: 5px;
        height: 3px;
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
  EXPECT_EQ(gfx::Rect(0, 0, 20, 20), overflow_a_scroll_node->ContainerRect());
  // 100 is the forceScroll element's height because the overflow child does not
  // contribute to the height.
  EXPECT_EQ(gfx::Rect(0, 0, 20, 100), overflow_a_scroll_node->ContentsRect());
  EXPECT_TRUE(overflow_a_scroll_node->UserScrollableHorizontal());
  EXPECT_TRUE(overflow_a_scroll_node->UserScrollableVertical());

  const ObjectPaintProperties* overflow_b_scroll_properties =
      overflow_b->GetLayoutObject()->FirstFragment().PaintProperties();
  // The overflow child's scroll node should be a child of the parent's
  // (overflowA) scroll node.
  auto* scroll_b_translation =
      overflow_b_scroll_properties->ScrollTranslation();
  auto* overflow_b_scroll_node = scroll_b_translation->ScrollNode();
  EXPECT_EQ(overflow_a_scroll_node, overflow_b_scroll_node->Parent());
  EXPECT_EQ(gfx::Vector2dF(0, -41), scroll_b_translation->Get2dTranslation());
  EXPECT_EQ(gfx::Rect(0, 0, 5, 3), overflow_b_scroll_node->ContainerRect());
  EXPECT_EQ(gfx::Rect(0, 0, 5, 100), overflow_b_scroll_node->ContentsRect());
  EXPECT_TRUE(overflow_b_scroll_node->UserScrollableHorizontal());
  EXPECT_TRUE(overflow_b_scroll_node->UserScrollableVertical());
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootClip) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg' style="width: 100px; height: 100.5px">
      <rect width='200' height='200' fill='red' />
    </svg>
  )HTML");

  const ClipPaintPropertyNode* clip = GetLayoutObjectByElementId("svg")
                                          ->FirstFragment()
                                          .PaintProperties()
                                          ->OverflowClip();
  EXPECT_EQ(DocContentClip(), clip->Parent());
  EXPECT_EQ(gfx::Vector2dF(8, 8), GetLayoutObjectByElementId("svg")
                                      ->FirstFragment()
                                      .PaintProperties()
                                      ->PaintOffsetTranslation()
                                      ->Get2dTranslation());
  // TODO(crbug.com/1248598): For now we pixel snap both layout clip rect and
  // paint clip rect for replaced elements.
  EXPECT_CLIP_RECT(FloatRoundedRect(0, 0, 100, 101), clip);
}

TEST_P(PaintPropertyTreeBuilderTest, SVGRootNoClip) {
  SetBodyInnerHTML(R"HTML(
    <svg id='svg' xmlns='http://www.w3.org/2000/svg' width='100px'
        height='100px' style='overflow: visible'>
      <rect width='200' height='200' fill='red' />
    </svg>
  )HTML");

  EXPECT_FALSE(GetLayoutObjectByElementId("svg")
                   ->FirstFragment()
                   .PaintProperties()
                   ->OverflowClip());
}

TEST_P(PaintPropertyTreeBuilderTest, MainThreadScrollReasonsWithoutScrolling) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #overflow {
        overflow: scroll;
        width: 100px;
        height: 100px;
      }
      .backgroundAttachmentFixed {
        background-image: url('foo');
        background-attachment: fixed;
        width: 10px;
        height: 10px;
      }
      .forceScroll {
        height: 4000px;
      }
    </style>
    <div id='overflow'>
      <div class='backgroundAttachmentFixed'></div>
    </div>
    <div class='forceScroll'></div>
  )HTML");
  Element* overflow = GetDocument().getElementById(AtomicString("overflow"));
  EXPECT_TRUE(DocScroll()->RequiresMainThreadForBackgroundAttachmentFixed());
  // No scroll node is needed.
  EXPECT_EQ(overflow->GetLayoutObject()
                ->FirstFragment()
                .PaintProperties()
                ->ScrollTranslation(),
            nullptr);
}

TEST_P(PaintPropertyTreeBuilderTest, PaintOffsetsUnderMultiColumnScrolled) {
  SetBodyInnerHTML(R"HTML(
    <!doctype HTML>
    <div style='columns: 1;'>
       <div id=scroller style='height: 400px; width: 400px; overflow: auto;'>
         <div style='width: 50px; height: 1000px; background: lightgray'>
       </div>
     </div>
    </div>
  )HTML");

  LayoutBox* scroller = GetLayoutBoxByElementId("scroller");
  scroller->GetScrollableArea()->ScrollBy(ScrollOffset(0, 300),
                                          mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(gfx::Vector2dF(8, 8), scroller->FirstFragment()
                                      .PaintProperties()
                                      ->PaintOffsetTranslation()
                                      ->Get2dTranslation());
}

TEST_P(PaintPropertyTreeBuilderTest,
       PaintOffsetsUnderMultiColumnWithVisualOverflow) {
  SetBodyInnerHTML(R"HTML(
    <div style='columns: 2; width: 300px; column-gap: 0; height: 100px'>
      <div id=target1 style='outline: 2px solid black; width: 100px;
          height: 100px'></div>
      <div id=target2 style='outline: 2px solid black; width: 100px;
          height: 100px'></div>
    </div>
  )HTML");

  LayoutObject* target1 = GetLayoutObjectByElementId("target1");

  // Outline does not affect paint offset, since it is positioned to the
  // top-left of the border box.
  EXPECT_EQ(PhysicalOffset(8, 8), target1->FirstFragment().PaintOffset());
  // |target1| is only in the first column.
  EXPECT_FALSE(target1->IsFragmented());

  LayoutObject* target2 = GetLayoutObjectByElementId("target2");
  EXPECT_EQ(PhysicalOffset(158, 8), target2->FirstFragment().PaintOffset());
  // |target2| is only in the second column.
  EXPECT_FALSE(target2->IsFragmented());
}

TEST_P(PaintPropertyTreeBuilderTest,
       PaintOffsetsUnderMultiColumnWithScrollableOverflow) {
  SetBodyInnerHTML(R"HTML(
    <div style='columns: 2; width: 300px; column-gap: 0; height: 100px'>
      <div id='parent' style='outline: 2px solid black;
          width: 100px; height: 100px'>
        <div id='child' style='width: 100px; height: 200px'></div>
      </div>
    </div>
  )HTML");

  const LayoutBox* parent = GetLayoutBoxByElementId("parent");

  // The parent will need to generate 2 fragments, to hold child fragments
  // that contribute to scrollable overflow.
  ASSERT_EQ(2u, NumFragments(parent));
  EXPECT_EQ(PhysicalOffset(158, 8), FragmentAt(parent, 1).PaintOffset());
  // But since the #parent doesn't take up any space on its own in the second
  // fragment, the block-size should be 0.
  ASSERT_EQ(2u, parent->PhysicalFragmentCount());
  EXPECT_EQ(LayoutUnit(100), parent->GetPhysicalFragment(0)->Size().height);
  EXPECT_EQ(LayoutUnit(), parent->GetPhysicalFragment(1)->Size().height);
  EXPECT_EQ(PhysicalOffset(8, 8), FragmentAt(parent, 0).PaintOffset());

  LayoutObject* child = GetLayoutObjectByElementId("child");
  ASSERT_EQ(2u, NumFragments(child));
  EXPECT_EQ(PhysicalOffset(8, 8), FragmentAt(child, 0).PaintOffset());
  EXPECT_EQ(PhysicalOffset(158, 8), FragmentAt(child, 1).PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest, SpanFragmentsLimitedToSize) {
  SetBodyInnerHTML(R"HTML(
    <div style='columns: 10; height: 100px; width: 5000px'>
      <div style='width: 50px; height: 5000px'>
        <span id=target>Text</span>
      </div>
    </div>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  EXPECT_EQ(1u, NumFragments(target));
}

TEST_P(PaintPropertyTreeBuilderTest,
       PaintOffsetUnderMulticolumnScrollFixedPos) {
  SetBodyInnerHTML(R"HTML(
    <div id=fixed style='position: fixed; columns: 2; column-gap: 20px; width: 120px;'>
      <div id="first" style='height: 20px; background: lightblue'></div>
      <div id="second" style='height: 20px; background: lightgray'></div>
    </div>
    <div style='height: 2000px'></div>
  )HTML");

  auto test = [&]() {
    LayoutObject* first = GetLayoutObjectByElementId("first");
    LayoutObject* second = GetLayoutObjectByElementId("second");
    EXPECT_EQ(PhysicalOffset(), first->FirstFragment().PaintOffset());
    EXPECT_FALSE(first->IsFragmented());
    EXPECT_EQ(PhysicalOffset(70, 0), second->FirstFragment().PaintOffset());
    EXPECT_FALSE(second->IsFragmented());
  };

  test();

  GetDocument().View()->LayoutViewport()->ScrollBy(
      ScrollOffset(0, 25), mojom::blink::ScrollType::kUser);
  UpdateAllLifecyclePhasesForTest();

  test();
}

TEST_P(PaintPropertyTreeBuilderTest, FragmentsUnderMultiColumn) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      .space { height: 30px; }
      .abs { position: absolute; width: 20px; height: 20px; }
    </style>
    <div style='position:relative; width:400px; height:400px;'>
      <div style='columns:2; width: 200px; column-gap: 0'>
        <div id=relpos style='position: relative'>
          <div id=space1 class=space></div>
          <div id=space2 class=space></div>
          <div id=spanner style='column-span: all'>
            <div id=normal style='height: 50px'></div>
            <div id=top-left class=abs style='top: 0; left: 0'></div>
            <div id=bottom-right class=abs style='bottom: 0; right: 0'></div>
          </div>
          <div id=space3 class=space></div>
          <div id=space4 class=space></div>
        </div>
      </div>
    </div>
  )HTML");

  const auto* relpos = GetLayoutObjectByElementId("relpos");
  EXPECT_EQ(4u, NumFragments(relpos));

  EXPECT_EQ(PhysicalOffset(), FragmentAt(relpos, 0).PaintOffset());
  EXPECT_EQ(0u, FragmentAt(relpos, 0).FragmentID());
  EXPECT_EQ(nullptr, FragmentAt(relpos, 0).PaintProperties());

  EXPECT_EQ(PhysicalOffset(100, 0), FragmentAt(relpos, 1).PaintOffset());
  EXPECT_EQ(1u, FragmentAt(relpos, 1).FragmentID());
  EXPECT_EQ(nullptr, FragmentAt(relpos, 1).PaintProperties());

  EXPECT_EQ(PhysicalOffset(0, 80), FragmentAt(relpos, 2).PaintOffset());
  EXPECT_EQ(2u, FragmentAt(relpos, 2).FragmentID());
  EXPECT_EQ(nullptr, FragmentAt(relpos, 2).PaintProperties());

  EXPECT_EQ(PhysicalOffset(100, 80), FragmentAt(relpos, 3).PaintOffset());
  EXPECT_EQ(3u, FragmentAt(relpos, 3).FragmentID());
  EXPECT_EQ(nullptr, FragmentAt(relpos, 3).PaintProperties());

  // Above the spanner.
  // Column 1.
  const auto* space1 = GetLayoutObjectByElementId("space1");
  EXPECT_EQ(1u, NumFragments(space1));
  EXPECT_EQ(nullptr, space1->FirstFragment().PaintProperties());
  EXPECT_EQ(PhysicalOffset(), space1->FirstFragment().PaintOffset());
  const auto* space2 = GetLayoutObjectByElementId("space2");
  EXPECT_EQ(1u, NumFragments(space2));
  EXPECT_EQ(nullptr, space2->FirstFragment().PaintProperties());
  EXPECT_EQ(PhysicalOffset(100, 0), space2->FirstFragment().PaintOffset());

  // The spanner's normal flow.
  LayoutObject* spanner = GetLayoutObjectByElementId("spanner");
  EXPECT_EQ(1u, NumFragments(spanner));
  EXPECT_EQ(nullptr, spanner->FirstFragment().PaintProperties());
  EXPECT_EQ(PhysicalOffset(0, 30), spanner->FirstFragment().PaintOffset());
  LayoutObject* normal = GetLayoutObjectByElementId("normal");
  EXPECT_EQ(1u, NumFragments(normal));
  EXPECT_EQ(nullptr, normal->FirstFragment().PaintProperties());
  EXPECT_EQ(PhysicalOffset(0, 30), normal->FirstFragment().PaintOffset());

  // Below the spanner.
  const auto* space3 = GetLayoutObjectByElementId("space3");
  EXPECT_EQ(1u, NumFragments(space3));
  EXPECT_EQ(nullptr, space3->FirstFragment().PaintProperties());
  EXPECT_EQ(PhysicalOffset(0, 80), space3->FirstFragment().PaintOffset());
  const auto* space4 = GetLayoutObjectByElementId("space4");
  EXPECT_EQ(1u, NumFragments(space4));
  EXPECT_EQ(nullptr, space4->FirstFragment().PaintProperties());
  EXPECT_EQ(PhysicalOffset(100, 80), space4->FirstFragment().PaintOffset());

  // Out-of-flow positioned descendants of the spanner. They are laid out in
  // the relative-position container.

  // "top-left" should be aligned to the top-left corner of space1.
  const auto* top_left = GetLayoutObjectByElementId("top-left");
  EXPECT_EQ(1u, NumFragments(top_left));
  EXPECT_EQ(PhysicalOffset(), top_left->FirstFragment().PaintOffset());

  const auto* bottom_right = GetLayoutObjectByElementId("bottom-right");
  EXPECT_EQ(1u, NumFragments(bottom_right));
  // According to the spec the containing block of a spanner is the multicol
  // container. Therefore, any OOF descendants of a spanner will ignore any
  // containing blocks inside the multicol container.
  EXPECT_EQ(PhysicalOffset(380, 380),
            bottom_right->FirstFragment().PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest,
       FragmentsUnderMultiColumnVerticalRLWithOverflow) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='multicol' style='columns:2; column-fill:auto; column-gap: 0;
        width: 200px; height: 200px; writing-mode: vertical-rl'>
      <div id='container' style='width: 100px'>
        <div id='content' style='width: 400px'></div>
      </div>
    </div>
  )HTML");

  LayoutObject* thread =
      GetLayoutObjectByElementId("multicol")->SlowFirstChild();
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_TRUE(thread->IsLayoutFlowThread());
  ASSERT_EQ(2u, NumFragments(container));
  EXPECT_EQ(PhysicalOffset(100, 0), FragmentAt(container, 0).PaintOffset());
  EXPECT_EQ(0u, FragmentAt(container, 0).FragmentID());
  EXPECT_EQ(PhysicalOffset(200, 100), FragmentAt(container, 1).PaintOffset());
  EXPECT_EQ(1u, FragmentAt(container, 1).FragmentID());

  LayoutObject* content = GetLayoutObjectByElementId("content");
  EXPECT_EQ(2u, NumFragments(content));

    EXPECT_EQ(PhysicalOffset(), FragmentAt(content, 0).PaintOffset());
    EXPECT_EQ(0u, FragmentAt(content, 0).FragmentID());
    EXPECT_EQ(PhysicalOffset(0, 100), FragmentAt(content, 1).PaintOffset());
    EXPECT_EQ(1u, FragmentAt(content, 1).FragmentID());
}

TEST_P(PaintPropertyTreeBuilderTest, LayerUnderOverflowClipUnderMultiColumn) {
  SetBodyInnerHTML(R"HTML(
    <div id='multicol' style='columns:2'>
      <div id='wrapper'>
        <div id='clip' style='height: 200px; overflow: hidden'>
          <div id='layer' style='position: relative; height: 800px'></div>
        </div>
        <div style='height: 200px'></div>
      </div>
    </div>
  )HTML");

  const auto* wrapper = GetLayoutObjectByElementId("wrapper");
  EXPECT_EQ(2u, NumFragments(wrapper));
  EXPECT_EQ(1u, NumFragments(GetLayoutObjectByElementId("clip")));
  EXPECT_EQ(1u, NumFragments(GetLayoutObjectByElementId("layer")));
}

TEST_P(PaintPropertyTreeBuilderTest, OverflowClipUnderMultiColumn) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div style='columns: 4; height: 100px; column-fill: auto; column-gap: 0'>
      <div id='clip' style='height: 200px; overflow: clip'>
        <div id='child1' style='height: 400px'></div>
        <div id='child2' style='height: 400px'></div>
      </div>
    </div>
  )HTML");

  const auto* clip = GetLayoutObjectByElementId("clip");
  const auto* child1 = GetLayoutObjectByElementId("child1");
  const auto* child2 = GetLayoutObjectByElementId("child2");
  ASSERT_EQ(2u, NumFragments(clip));
  ASSERT_EQ(2u, NumFragments(child1));
  ASSERT_EQ(1u, NumFragments(child2));
  EXPECT_EQ(PhysicalOffset(), FragmentAt(clip, 0).PaintOffset());
  EXPECT_EQ(0u, FragmentAt(clip, 0).FragmentID());
  EXPECT_EQ(PhysicalOffset(200, 0), FragmentAt(clip, 1).PaintOffset());
  EXPECT_EQ(1u, FragmentAt(clip, 1).FragmentID());
  EXPECT_EQ(PhysicalOffset(), FragmentAt(child1, 0).PaintOffset());
  EXPECT_EQ(0u, FragmentAt(child1, 0).FragmentID());
  EXPECT_EQ(PhysicalOffset(200, 0), FragmentAt(child1, 1).PaintOffset());
  EXPECT_EQ(1u, FragmentAt(child1, 1).FragmentID());
  EXPECT_EQ(PhysicalOffset(200, 300), FragmentAt(child2, 0).PaintOffset());
  EXPECT_EQ(1u, FragmentAt(child2, 0).FragmentID());
}

TEST_P(PaintPropertyTreeBuilderTest, CompositedUnderMultiColumn) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='multicol' style='columns:3; column-fill:auto; column-gap: 0;
        width: 300px; height: 200px'>
      <div id='wrapper'>
        <div style='height: 300px'></div>
        <div id='composited' style='will-change: transform; height: 300px'>
          <div id='non-composited-child' style='height: 150px'></div>
          <div id='composited-child'
               style='will-change: transform; height: 150px'></div>
        </div>
      </div>
    </div>
  )HTML");

  LayoutObject* wrapper = GetLayoutObjectByElementId("wrapper");
  ASSERT_EQ(3u, NumFragments(wrapper));
  EXPECT_EQ(PhysicalOffset(0, 0), FragmentAt(wrapper, 0).PaintOffset());
  EXPECT_EQ(0u, FragmentAt(wrapper, 0).FragmentID());
  EXPECT_EQ(PhysicalOffset(100, 0), FragmentAt(wrapper, 1).PaintOffset());
  EXPECT_EQ(1u, FragmentAt(wrapper, 1).FragmentID());
  EXPECT_EQ(PhysicalOffset(200, 0), FragmentAt(wrapper, 2).PaintOffset());
  EXPECT_EQ(2u, FragmentAt(wrapper, 2).FragmentID());

  LayoutObject* composited = GetLayoutObjectByElementId("composited");
  LayoutObject* non_composited_child =
      GetLayoutObjectByElementId("non-composited-child");
  LayoutObject* composited_child =
      GetLayoutObjectByElementId("composited-child");

  EXPECT_EQ(2u, NumFragments(composited));
  EXPECT_EQ(PhysicalOffset(0, 0), FragmentAt(composited, 0).PaintOffset());
  EXPECT_EQ(1u, FragmentAt(composited, 0).FragmentID());
  EXPECT_EQ(PhysicalOffset(0, 0), FragmentAt(composited, 1).PaintOffset());
  EXPECT_EQ(2u, FragmentAt(composited, 1).FragmentID());
  EXPECT_EQ(2u, NumFragments(non_composited_child));
  EXPECT_EQ(PhysicalOffset(0, 0),
            FragmentAt(non_composited_child, 0).PaintOffset());
  EXPECT_EQ(1u, FragmentAt(non_composited_child, 0).FragmentID());
  EXPECT_EQ(PhysicalOffset(0, 0),
            FragmentAt(non_composited_child, 1).PaintOffset());
  EXPECT_EQ(2u, FragmentAt(non_composited_child, 1).FragmentID());
  EXPECT_EQ(1u, NumFragments(composited_child));
  EXPECT_EQ(PhysicalOffset(0, 0),
            FragmentAt(composited_child, 0).PaintOffset());
  EXPECT_EQ(2u, FragmentAt(composited_child, 0).FragmentID());
}

// Ensures no crash with multi-column containing relative-position inline with
// spanner with absolute-position children.
TEST_P(PaintPropertyTreeBuilderTest,
       MultiColumnInlineRelativeAndSpannerAndAbsPos) {
  SetBodyInnerHTML(R"HTML(
    <div style='columns:2; width: 200px; column-gap: 0'>
      <span style='position: relative'>
        <span id=spanner style='column-span: all'>
          <div id=absolute style='position: absolute'>absolute</div>
        </span>
      </span>
    </div>
  )HTML");
  // The "spanner" isn't a real spanner because it's an inline.
  EXPECT_FALSE(GetLayoutObjectByElementId("spanner")->IsColumnSpanAll());

  SetBodyInnerHTML(R"HTML(
    <div style='columns:2; width: 200px; column-gap: 0'>
      <span style='position: relative'>
        <div id=spanner style='column-span: all'>
          <div id=absolute style='position: absolute'>absolute</div>
        </div>
      </span>
    </div>
  )HTML");
  // There should be anonymous block created containing the inline "relative",
  // serving as the container of "absolute".
  EXPECT_TRUE(
      GetLayoutObjectByElementId("absolute")->Container()->IsLayoutBlock());
}

TEST_P(PaintPropertyTreeBuilderTest, FrameUnderMulticol) {
  SetBodyInnerHTML(R"HTML(
    <div style='columns: 2; width: 200px; height: 100px; coloum-gap: 0'>
      <iframe style='width: 50px; height: 150px'></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      body { margin: 0; }
      div { height: 60px; }
    </style>
    <div id='div1' style='background: blue'></div>
    <div id='div2' style='background: green'></div>
  )HTML");

  // This should not crash on duplicated subsequences in the iframe.
  UpdateAllLifecyclePhasesForTest();

  // TODO(crbug.com/797779): Add code to verify fragments under the iframe.
}

TEST_P(PaintPropertyTreeBuilderTest, CompositedMulticolFrameUnderMulticol) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div style='columns: 3; column-gap: 0; column-fill: auto;
        width: 300px; height: 200px'>
      <div style='height: 300px'></div>
      <iframe id='iframe' style='will-change: transform;
          width: 90px; height: 300px; border: none; background: green'></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div style='columns: 2; column-gap: 0; column-fill: auto;
        width: 80px; height: 100px'>
      <div id="multicolContent" style='height: 200px; background: blue'></div>
    </div>
  )HTML");

  // This should not crash on duplicated subsequences in the iframe.
  UpdateAllLifecyclePhasesForTest();

  // TODO(crbug.com/797779): Add code to verify fragments under the iframe.
}

// Test that becoming unfragmented correctly updates FragmentData. This means
// clearing the fragment ID. Also check the paint offset, for good measure.
TEST_P(PaintPropertyTreeBuilderTest, BecomingUnfragmented) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
         width: 30px; height: 20px; position: relative;
      }
    </style>
    <div style='columns:2; column-fill:auto; column-gap:0; height:20px; width:400px;'>
       <div style='height: 20px'></div>
       <div id=target></div>
     </div>
    </div>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  EXPECT_EQ(1u, target->FirstFragment().FragmentID());
  EXPECT_EQ(PhysicalOffset(LayoutUnit(208), LayoutUnit(8)),
            target->FirstFragment().PaintOffset());
  Element* target_element =
      GetDocument().getElementById(AtomicString("target"));

  target_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("position: absolute"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(0u, target->FirstFragment().FragmentID());
  EXPECT_EQ(PhysicalOffset(LayoutUnit(8), LayoutUnit(28)),
            target->FirstFragment().PaintOffset());
}

TEST_P(PaintPropertyTreeBuilderTest, Reflection) {
  SetBodyInnerHTML(
      "<div id='filter' style='-webkit-box-reflect: below; height:1000px;'>"
      "</div>");
  const ObjectPaintProperties* filter_properties =
      GetLayoutObjectByElementId("filter")->FirstFragment().PaintProperties();
  EXPECT_EQ(DocScrollTranslation(),
            filter_properties->PaintOffsetTranslation()->Parent());
  EXPECT_EQ(gfx::Vector2dF(8, 8),
            filter_properties->PaintOffsetTranslation()->Get2dTranslation());
  EXPECT_EQ(filter_properties->Filter()->Parent(), DocEffect());
  EXPECT_EQ(filter_properties->PaintOffsetTranslation(),
            &filter_properties->Filter()->LocalTransformSpace());
  EXPECT_EQ(DocContentClip(), filter_properties->Filter()->OutputClip());
}

TEST_P(PaintPropertyTreeBuilderTest, SimpleFilter) {
  SetBodyInnerHTML(
      "<div id='filter' style='filter:opacity(0.5); height:1000px;'>"
      "</div>");
  const ObjectPaintProperties* filter_properties =
      GetLayoutObjectByElementId("filter")->FirstFragment().PaintProperties();
  EXPECT_FALSE(filter_properties->PaintOffsetTranslation());
  EXPECT_EQ(filter_properties->Filter()->Parent(), DocEffect());
  EXPECT_FALSE(filter_properties->PixelMovingFilterClipExpander());
  EXPECT_EQ(DocScrollTranslation(),
            &filter_properties->Filter()->LocalTransformSpace());
  EXPECT_EQ(DocContentClip(), filter_properties->Filter()->OutputClip());
}

TEST_P(PaintPropertyTreeBuilderTest, PixelMovingFilter) {
  SetBodyInnerHTML(
      "<div id='filter' style='filter:blur(10px); height:1000px;'>"
      "</div>");
  const ObjectPaintProperties* filter_properties =
      GetLayoutObjectByElementId("filter")->FirstFragment().PaintProperties();
  EXPECT_FALSE(filter_properties->PaintOffsetTranslation());

  auto* filter = filter_properties->Filter();
  ASSERT_TRUE(filter);
  EXPECT_EQ(filter->Parent(), DocEffect());
  EXPECT_TRUE(filter->HasFilterThatMovesPixels());
  EXPECT_EQ(DocScrollTranslation(), &filter->LocalTransformSpace());
  EXPECT_EQ(DocContentClip(), filter->OutputClip());

  auto* clip = filter_properties->PixelMovingFilterClipExpander();
  ASSERT_TRUE(clip);
  EXPECT_EQ(filter->OutputClip(), clip->Parent());
  EXPECT_EQ(&clip->LocalTransformSpace(), &filter->LocalTransformSpace());
  EXPECT_EQ(filter, clip->PixelMovingFilter());
  EXPECT_TRUE(clip->LayoutClipRect().IsInfinite());
  EXPECT_EQ(gfx::RectF(InfiniteIntRect()), clip->PaintClipRect().Rect());
}

TEST_P(PaintPropertyTreeBuilderTest, SimpleFilterWithWillChangeTransform) {
  SetBodyInnerHTML(R"HTML(
    <div id='filter' style='filter:opacity(0.5); height:1000px;
                            will-change: transform'>"
    </div>
  )HTML");

  auto* properties = PaintPropertiesForElement("filter");
  ASSERT_TRUE(properties);
  auto* filter = properties->Filter();
  ASSERT_TRUE(filter);
  EXPECT_TRUE(filter->HasDirectCompositingReasons());
  EXPECT_FALSE(properties->PixelMovingFilterClipExpander());
}

TEST_P(PaintPropertyTreeBuilderTest, WillChangeFilterCreatesClipExpander) {
  SetBodyInnerHTML(
      "<div id='filter' style='height:1000px; will-change: filter'>");

  auto* properties = PaintPropertiesForElement("filter");
  ASSERT_TRUE(properties);
  auto* filter = properties->Filter();
  ASSERT_TRUE(filter);
  EXPECT_TRUE(filter->HasDirectCompositingReasons());
  auto* clip_expander = properties->PixelMovingFilterClipExpander();
  ASSERT_TRUE(clip_expander);
  EXPECT_EQ(filter, clip_expander->PixelMovingFilter());
}

TEST_P(PaintPropertyTreeBuilderTest, FilterReparentClips) {
  SetBodyInnerHTML(R"HTML(
    <div id='clip' style='overflow:hidden;'>
      <div id='filter' style='filter:opacity(0.5); height:1000px;'>
        <div id='child' style='position:fixed;'></div>
      </div>
    </div>
  )HTML");
  const ObjectPaintProperties* clip_properties =
      GetLayoutObjectByElementId("clip")->FirstFragment().PaintProperties();
  const ObjectPaintProperties* filter_properties =
      GetLayoutObjectByElementId("filter")->FirstFragment().PaintProperties();
  EXPECT_TRUE(DocEffect());
  EXPECT_EQ(clip_properties->OverflowClip(),
            filter_properties->Filter()->OutputClip());
  EXPECT_EQ(DocScrollTranslation(),
            &filter_properties->Filter()->LocalTransformSpace());

  const auto& child_paint_state = GetLayoutObjectByElementId("child")
                                      ->FirstFragment()
                                      .LocalBorderBoxProperties();

  // This will change once we added clip expansion node.
  EXPECT_EQ(filter_properties->Filter()->OutputClip(),
            &child_paint_state.Clip());
  EXPECT_EQ(filter_properties->Filter(), &chil
```