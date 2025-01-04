Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a test file for the Chromium Blink rendering engine. The file appears to test coordinate mapping between different layout objects. I need to analyze the test cases and identify the core functionality being tested.

The tests cover various scenarios of coordinate mapping:
- Basic cases with nested divs.
- Cases involving multi-column layouts.
- Cases with different positioning schemes (relative, absolute).
- Cases with right-to-left text direction.
- Cases with large borders.
- Cases involving writing modes (vertical-rl).
- Cases involving tables.
- Cases involving CSS transforms.
- Cases involving SVG elements and transformations.
- Cases involving foreign objects within SVG.
- A test case related to local to absolute transformations.

The primary function tested is likely related to methods like `MapLocalToAncestor` and `MapAncestorToLocal`, which are used to convert coordinates between different elements in the layout tree.
这个blink/renderer/core/layout/map_coordinates_test.cc文件的第2部分主要包含了一系列的单元测试，用于验证blink渲染引擎在各种复杂的布局场景下进行坐标映射的功能是否正确。

**核心功能归纳：**

这部分测试的核心是验证 `MapLocalToAncestor` 和 `MapAncestorToLocal` 这两个函数在不同布局上下文中的正确性。这两个函数用于在布局树的不同元素之间转换坐标。

**具体测试场景包括：**

* **多列布局 (Multicol):**  测试在多列布局中元素与其祖先元素之间的坐标映射，包括简单多列、带有块级子元素的多列、嵌套多列等情况。
* **定位元素 (Positioning):** 测试包含相对定位和绝对定位元素的复杂多列布局中的坐标映射。
* **书写模式 (Writing Mode):** 测试在垂直书写模式 (`vertical-rl`) 下的坐标映射，包括包含文本、inline元素和block元素的情况。
* **表格 (Table):** 测试在表格布局中元素及其不同层级的祖先元素（如 td, tr, tbody, table）之间的坐标映射。
* **CSS 变换 (Transforms):** 测试应用了 CSS `transform` 属性的元素之间的坐标映射，包括旋转变换。
* **SVG (Scalable Vector Graphics):** 测试 SVG 元素及其包含的图形元素（如 `rect`）在应用 `transform` 属性和 `viewBox` 属性时的坐标映射。
* **SVG ForeignObject:** 测试 SVG 中的 `foreignObject` 元素（用于嵌入非 SVG 内容）与其祖先元素之间的坐标映射。
* **局部到绝对变换 (Local to Absolute Transform):** 包含一个测试用例，可能用于测试从局部坐标系到绝对坐标系的变换。

**与 JavaScript, HTML, CSS 的关系：**

这些测试直接关联到 HTML 结构和 CSS 样式如何影响元素的布局和坐标。JavaScript 可以通过 DOM API 获取元素的坐标信息，而这些测试确保了引擎计算出的坐标与预期一致。

**举例说明：**

* **HTML:**  测试用例中使用了各种 HTML 结构，例如 `<div>`, `<span>`, `<table>`, `<svg>`, `<foreignObject>` 等，来模拟不同的布局场景。例如，多列布局的测试用例使用了 `-webkit-columns` CSS 属性来创建多列容器。
* **CSS:**  测试用例使用了各种 CSS 属性来控制元素的定位、尺寸、边框、内边距、变换等。例如，`position: relative` 和 `position: absolute` 用于测试不同定位方式下的坐标映射，`transform: rotate(45deg)` 用于测试 CSS 变换。
* **JavaScript:** 虽然测试代码是用 C++ 写的，但它模拟了 JavaScript 可能执行的操作，例如获取元素的布局信息。如果这些坐标映射不正确，JavaScript 获取到的元素位置信息也会有误，导致页面交互或动画出现问题。

**逻辑推理与假设输入输出：**

以 `TEST_F(MapCoordinatesTest, Multicol)` 这个测试为例：

* **假设输入 (HTML 和 CSS):**
  ```html
  <div id='multicol' style='columns:2; column-gap:20px; width:400px; line-height:50px; padding:5px;'>
      <span id='target'><br>text</span>
  </div>
  ```
* **逻辑推理:**  `target` 元素位于多列容器的第一列。我们想知道 `target` 元素内的点 (10, 70) 映射到 `multicol` 容器坐标系下的位置。 由于 `line-height` 是 50px，`<br>` 会占据一行，因此文本 "text" 的起始 y 坐标大概是 50px。 加上 `padding: 5px`，所以 `target` 内部的 y=70 应该对应于 `multicol` 内部的 70 + 5 = 75 左右的位置。 由于是第一列，x 坐标应该与 `target` 内部的 x 坐标接近，加上容器的 `padding`。
* **预期输出:** `MapLocalToAncestor(target, multicol, PhysicalOffset(10, 70))` 应该接近 `PhysicalOffset(15, 75)` (实际测试结果是 `PhysicalOffset(225, 25)`, 说明我的推理可能忽略了多列的布局机制，它将内容均匀分布在列中)。  反向映射 `MapAncestorToLocal` 应该将 `PhysicalOffset(225, 25)` 映射回 `PhysicalOffset(10, 70)`。

**用户或编程常见的使用错误：**

* **假设父元素的坐标系：**  开发者在使用 JavaScript 获取元素坐标时，可能会错误地假设元素的坐标是相对于某个特定的父元素，而没有考虑到中间可能存在的定位上下文或变换。这些测试帮助确保浏览器引擎正确处理这些复杂的上下文。
* **忽略滚动偏移：** 在有滚动的情况下，元素的视觉位置和布局位置是不同的。坐标映射函数需要正确处理滚动偏移。虽然这个文件中的测试没有直接涉及到滚动，但在实际应用中这是一个常见的错误来源。
* **不理解 `transform-origin`:** 当使用 CSS `transform` 时，`transform-origin` 属性会影响变换的中心点。如果开发者不理解这一点，可能会在坐标转换时出错。 `TEST_F(MapCoordinatesTest, Transforms)` 这个测试验证了变换的正确性。

**总结本部分的功能:**

这部分代码主要用于测试 Chromium Blink 引擎在各种复杂的 HTML 和 CSS 布局场景下，进行精确的坐标映射功能。它通过创建不同的布局结构，并使用 `MapLocalToAncestor` 和 `MapAncestorToLocal` 函数进行正向和反向的坐标转换，以此验证引擎的坐标计算逻辑是否正确。这对于确保网页元素在不同布局下的正确渲染和交互至关重要。

Prompt: 
```
这是目录为blink/renderer/core/layout/map_coordinates_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
' style='columns:2; column-gap:20px; width:400px;
    line-height:50px; padding:5px; orphans:1; widows:1;'>
        <span id='target'><br>text</span>
    </div>
  )HTML");

  auto* const multicol =
      To<LayoutBlockFlow>(GetLayoutBoxByElementId("multicol"));
  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* const flow_thread = multicol->MultiColumnFlowThread();

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, flow_thread, PhysicalOffset(10, 70));
  EXPECT_EQ(PhysicalOffset(10, 70), mapped_point);
  mapped_point = MapAncestorToLocal(target, flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 70), mapped_point);

  mapped_point =
      MapLocalToAncestor(flow_thread, multicol, PhysicalOffset(10, 70));
  EXPECT_EQ(PhysicalOffset(225, 25), mapped_point);
  mapped_point = MapAncestorToLocal(flow_thread, multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 70), mapped_point);
}

TEST_F(MapCoordinatesTest, MulticolWithBlock) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='-webkit-columns:3; -webkit-column-gap:0;
    column-fill:auto; width:300px; height:100px; border:8px solid;
    padding:7px;'>
        <div style='height:110px;'></div>
        <div id='target' style='margin:10px; border:13px;
    padding:13px;'></div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(125, 35), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  LayoutBox* flow_thread = target->ParentBox();
  ASSERT_TRUE(flow_thread->IsLayoutFlowThread());

  mapped_point = MapLocalToAncestor(target, flow_thread, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(10, 120), mapped_point);
  mapped_point = MapAncestorToLocal(target, flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point =
      MapLocalToAncestor(flow_thread, container, PhysicalOffset(10, 120));
  EXPECT_EQ(PhysicalOffset(125, 35), mapped_point);
  mapped_point = MapAncestorToLocal(flow_thread, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 120), mapped_point);
}

TEST_F(MapCoordinatesTest, MulticolWithBlockAbove) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='columns:3; column-gap:0;
    column-fill:auto; width:300px; height:200px;'>
        <div id='target' style='margin-top:-50px; height:100px;'></div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(0, -50), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  LayoutBox* flow_thread = target->ParentBox();
  ASSERT_TRUE(flow_thread->IsLayoutFlowThread());

  mapped_point = MapLocalToAncestor(target, flow_thread, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(0, -50), mapped_point);
  mapped_point = MapAncestorToLocal(target, flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point =
      MapLocalToAncestor(flow_thread, container, PhysicalOffset(0, -50));
  EXPECT_EQ(PhysicalOffset(0, -50), mapped_point);
  mapped_point = MapAncestorToLocal(flow_thread, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(0, -50), mapped_point);
}

TEST_F(MapCoordinatesTest, NestedMulticolWithBlock) {
  SetBodyInnerHTML(R"HTML(
    <div id='outerMulticol' style='columns:2; column-gap:0;
    column-fill:auto; width:560px; height:215px; border:8px solid;
    padding:7px;'>
        <div style='height:10px;'></div>
        <div id='innerMulticol' style='columns:2; column-gap:0; border:8px
    solid; padding:7px;'>
            <div style='height:630px;'></div>
            <div id='target' style='width:50px; height:50px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* outer_multicol = GetLayoutBoxByElementId("outerMulticol");
  auto* inner_multicol = GetLayoutBoxByElementId("innerMulticol");
  LayoutBox* inner_flow_thread = target->ParentBox();
  ASSERT_TRUE(inner_flow_thread->IsLayoutFlowThread());
  LayoutBox* outer_flow_thread = inner_multicol->ParentBox();
  ASSERT_TRUE(outer_flow_thread->IsLayoutFlowThread());

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, outer_multicol, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(435, 115), mapped_point);
  mapped_point = MapAncestorToLocal(target, outer_multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  mapped_point =
      MapLocalToAncestor(target, inner_flow_thread, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(0, 630), mapped_point);
  mapped_point = MapAncestorToLocal(target, inner_flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point = MapLocalToAncestor(inner_flow_thread, inner_multicol,
                                    PhysicalOffset(0, 630));
  EXPECT_EQ(PhysicalOffset(140, 305), mapped_point);
  mapped_point =
      MapAncestorToLocal(inner_flow_thread, inner_multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(0, 630), mapped_point);

  mapped_point = MapLocalToAncestor(inner_multicol, outer_flow_thread,
                                    PhysicalOffset(140, 305));
  EXPECT_EQ(PhysicalOffset(140, 315), mapped_point);
  mapped_point =
      MapAncestorToLocal(inner_multicol, outer_flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(140, 305), mapped_point);

  mapped_point = MapLocalToAncestor(outer_flow_thread, outer_multicol,
                                    PhysicalOffset(140, 315));
  EXPECT_EQ(PhysicalOffset(435, 115), mapped_point);
  mapped_point =
      MapAncestorToLocal(outer_flow_thread, outer_multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(140, 315), mapped_point);
}

TEST_F(MapCoordinatesTest, MulticolWithAbsPosInRelPos) {
  SetBodyInnerHTML(R"HTML(
    <div id='multicol' style='-webkit-columns:3; -webkit-column-gap:0;
    column-fill:auto; width:300px; height:100px; border:8px solid;
    padding:7px;'>
        <div style='height:110px;'></div>
        <div id='relpos' style='position:relative; left:4px; top:4px;'>
            <div id='target' style='position:absolute; left:15px; top:15px;
    margin:10px; border:13px; padding:13px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* multicol = GetLayoutBoxByElementId("multicol");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, multicol, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(144, 54), mapped_point);
  mapped_point = MapAncestorToLocal(target, multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  auto* relpos = GetLayoutBoxByElementId("relpos");
  LayoutBox* flow_thread = relpos->ParentBox();
  ASSERT_TRUE(flow_thread->IsLayoutFlowThread());

  mapped_point = MapLocalToAncestor(target, relpos, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(25, 25), mapped_point);
  mapped_point = MapAncestorToLocal(target, relpos, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point =
      MapLocalToAncestor(relpos, flow_thread, PhysicalOffset(25, 25));
  EXPECT_EQ(PhysicalOffset(29, 139), mapped_point);
  mapped_point = MapAncestorToLocal(relpos, flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(25, 25), mapped_point);

  mapped_point =
      MapLocalToAncestor(flow_thread, multicol, PhysicalOffset(29, 139));
  EXPECT_EQ(PhysicalOffset(144, 54), mapped_point);
  mapped_point = MapAncestorToLocal(flow_thread, multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(29, 139), mapped_point);
}

TEST_F(MapCoordinatesTest, MulticolWithAbsPosInInlineRelPos) {
  SetBodyInnerHTML(R"HTML(
    <div id='multicol' style='columns:3; column-gap:0; column-fill:auto;
    width:300px; height:100px; border:8px solid; padding:7px;'>
        <div style='height:110px;'></div>
        <div id='container'>
          <span id='relpos' style='position:relative; left:4px; top:4px;'>
              <div id='target' style='position:absolute; left:15px; top:15px;
               margin:10px; border:13px; padding:13px;'></div>
          </span>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* multicol = GetLayoutBoxByElementId("multicol");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, multicol, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(144, 54), mapped_point);
  mapped_point = MapAncestorToLocal(target, multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  auto* container = GetLayoutBoxByElementId("container");
  LayoutBox* flow_thread = container->ParentBox();
  ASSERT_TRUE(flow_thread->IsLayoutFlowThread());

  mapped_point = MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(29, 29), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point =
      MapLocalToAncestor(container, flow_thread, PhysicalOffset(25, 25));
  EXPECT_EQ(PhysicalOffset(25, 135), mapped_point);
  mapped_point = MapAncestorToLocal(container, flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(25, 25), mapped_point);

  mapped_point =
      MapLocalToAncestor(flow_thread, multicol, PhysicalOffset(29, 139));
  EXPECT_EQ(PhysicalOffset(144, 54), mapped_point);
  mapped_point = MapAncestorToLocal(flow_thread, multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(29, 139), mapped_point);
}

TEST_F(MapCoordinatesTest, MulticolWithAbsPosNotContained) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position:relative; margin:666px; border:7px
    solid; padding:3px;'>
        <div id='multicol' style='-webkit-columns:3; -webkit-column-gap:0;
    column-fill:auto; width:300px; height:100px; border:8px solid;
    padding:7px;'>
            <div style='height:110px;'></div>
            <div id='target' style='position:absolute; left:-1px; top:-1px;
    margin:10px; border:13px; padding:13px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  // The multicol container isn't in the containing block chain of the abspos
  // #target.
  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(16, 16), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  auto* multicol = GetLayoutBoxByElementId("multicol");
  LayoutBox* flow_thread = target->ParentBox();
  ASSERT_TRUE(flow_thread->IsLayoutFlowThread());

  mapped_point = MapLocalToAncestor(target, flow_thread, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(-9, -9), mapped_point);

  mapped_point = MapLocalToAncestor(flow_thread, multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(6, 6), mapped_point);

  mapped_point = MapLocalToAncestor(multicol, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(16, 16), mapped_point);

  mapped_point = MapAncestorToLocal(multicol, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(6, 6), mapped_point);

  mapped_point = MapAncestorToLocal(flow_thread, multicol, mapped_point);
  EXPECT_EQ(PhysicalOffset(-9, -9), mapped_point);

  mapped_point = MapAncestorToLocal(target, flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, MulticolRtl) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='columns:3; column-gap:0; column-fill:auto;
    width:300px; height:200px; direction:rtl;'>
        <div style='height:200px;'></div>
        <div id='target' style='height:50px;'></div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(100, 0), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  LayoutBox* flow_thread = target->ParentBox();
  ASSERT_TRUE(flow_thread->IsLayoutFlowThread());

  mapped_point = MapLocalToAncestor(target, flow_thread, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(0, 200), mapped_point);
  mapped_point = MapAncestorToLocal(target, flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point =
      MapLocalToAncestor(flow_thread, container, PhysicalOffset(0, 200));
  EXPECT_EQ(PhysicalOffset(100, 0), mapped_point);
  mapped_point = MapAncestorToLocal(flow_thread, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(0, 200), mapped_point);
}

TEST_F(MapCoordinatesTest, MulticolWithLargeBorder) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='columns:3; column-gap:0; column-fill:auto;
    width:300px; height:200px; border:200px solid;'>
        <div style='height:200px;'></div>
        <div id='target' style='height:50px;'></div>
        <div style='height:200px;'></div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(300, 200), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  LayoutBox* flow_thread = target->ParentBox();
  ASSERT_TRUE(flow_thread->IsLayoutFlowThread());

  mapped_point = MapLocalToAncestor(target, flow_thread, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(0, 200), mapped_point);
  mapped_point = MapAncestorToLocal(target, flow_thread, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point =
      MapLocalToAncestor(flow_thread, container, PhysicalOffset(0, 200));
  EXPECT_EQ(PhysicalOffset(300, 200), mapped_point);
  mapped_point = MapAncestorToLocal(flow_thread, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(0, 200), mapped_point);
}

TEST_F(MapCoordinatesTest, FlippedBlocksWritingModeWithText) {
  SetBodyInnerHTML(R"HTML(
    <div style='-webkit-writing-mode:vertical-rl;'>
        <div style='width:13px;'></div>
        <div style='width:200px; height:400px; line-height:50px;'>
            <br id='sibling'>text
        </div>
        <div style='width:5px;'></div>
    </div>
  )HTML");

  LayoutObject* br = GetLayoutObjectByElementId("sibling");
  LayoutObject* text = br->NextSibling();
  ASSERT_TRUE(text->IsText());

  // Map to the nearest container. Nothing special should happen because
  // everything is in physical coordinates.
  PhysicalOffset mapped_point =
      MapLocalToAncestor(text, text->ContainingBlock(), PhysicalOffset(75, 10));
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);
  mapped_point =
      MapAncestorToLocal(text, text->ContainingBlock(), mapped_point);
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);

  // Map to a container further up in the tree.
  mapped_point = MapLocalToAncestor(
      text, text->ContainingBlock()->ContainingBlock(), PhysicalOffset(75, 10));
  EXPECT_EQ(PhysicalOffset(80, 10), mapped_point);
  mapped_point = MapAncestorToLocal(
      text, text->ContainingBlock()->ContainingBlock(), mapped_point);
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);
}

TEST_F(MapCoordinatesTest, FlippedBlocksWritingModeWithInline) {
  SetBodyInnerHTML(R"HTML(
    <div style='-webkit-writing-mode:vertical-rl;'>
        <div style='width:13px;'></div>
        <div style='width:200px; height:400px; line-height:50px;'>
            <span>
                <span id='target'><br>text</span>
            </span>
        </div>
        <div style='width:7px;'></div>
    </div>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  ASSERT_TRUE(target);

  // First map to the parent SPAN. Nothing special should happen.
  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, To<LayoutBoxModelObject>(target->Parent()),
                         PhysicalOffset(75, 10));
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);
  mapped_point = MapAncestorToLocal(
      target, To<LayoutBoxModelObject>(target->Parent()), mapped_point);
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);

  // Continue to the nearest container. Nothing special should happen because
  // everything is in physical coordinates.
  mapped_point =
      MapLocalToAncestor(To<LayoutBoxModelObject>(target->Parent()),
                         target->ContainingBlock(), PhysicalOffset(75, 10));
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);
  mapped_point = MapAncestorToLocal(To<LayoutBoxModelObject>(target->Parent()),
                                    target->ContainingBlock(), mapped_point);
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);

  // Now map from the innermost inline to the nearest container in one go.
  mapped_point = MapLocalToAncestor(target, target->ContainingBlock(),
                                    PhysicalOffset(75, 10));
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);
  mapped_point =
      MapAncestorToLocal(target, target->ContainingBlock(), mapped_point);
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);

  // Map to a container further up in the tree.
  mapped_point =
      MapLocalToAncestor(target, target->ContainingBlock()->ContainingBlock(),
                         PhysicalOffset(75, 10));
  EXPECT_EQ(PhysicalOffset(82, 10), mapped_point);
  mapped_point = MapAncestorToLocal(
      target, target->ContainingBlock()->ContainingBlock(), mapped_point);
  EXPECT_EQ(PhysicalOffset(75, 10), mapped_point);
}

TEST_F(MapCoordinatesTest, FlippedBlocksWritingModeWithBlock) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='-webkit-writing-mode:vertical-rl; border:8px
    solid; padding:7px; width:200px; height:200px;'>
        <div id='middle' style='border:1px solid;'>
            <div style='width:30px;'></div>
            <div id='target' style='margin:6px; width:25px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(153, 22), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  auto* middle = GetLayoutBoxByElementId("middle");

  mapped_point = MapLocalToAncestor(target, middle, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(7, 7), mapped_point);
  mapped_point = MapAncestorToLocal(target, middle, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point = MapLocalToAncestor(middle, container, PhysicalOffset(7, 7));
  EXPECT_EQ(PhysicalOffset(153, 22), mapped_point);
  mapped_point = MapAncestorToLocal(middle, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(7, 7), mapped_point);
}

TEST_F(MapCoordinatesTest, Table) {
  SetBodyInnerHTML(R"HTML(
    <style>td { padding: 2px; }</style>
    <div id='container' style='border:3px solid;'>
        <table style='margin:9px; border:5px solid; border-spacing:10px;'>
            <thead>
                <tr>
                    <td>
                        <div style='width:100px; height:100px;'></div>
                    </td>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>
                        <div style='width:100px; height:100px;'></div>
                     </td>
                </tr>
                <tr>
                    <td>
                         <div style='width:100px; height:100px;'></div>
                    </td>
                    <td>
                        <div id='target' style='width:100px;
    height:10px;'></div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(143, 302), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  LayoutBox* td = target->ParentBox();
  ASSERT_TRUE(td->IsTableCell());
  mapped_point = MapLocalToAncestor(target, td, PhysicalOffset());
  // Cells are middle-aligned by default.
  EXPECT_EQ(PhysicalOffset(2, 47), mapped_point);
  mapped_point = MapAncestorToLocal(target, td, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  LayoutBox* tr = td->ParentBox();
  ASSERT_TRUE(tr->IsTableRow());
  mapped_point = MapLocalToAncestor(td, tr, PhysicalOffset(2, 47));
  EXPECT_EQ(PhysicalOffset(116, 47), mapped_point);
  mapped_point = MapAncestorToLocal(td, tr, mapped_point);
  EXPECT_EQ(PhysicalOffset(2, 47), mapped_point);

  LayoutBox* tbody = tr->ParentBox();
  ASSERT_TRUE(tbody->IsTableSection());
  mapped_point = MapLocalToAncestor(tr, tbody, PhysicalOffset(126, 47));
  EXPECT_EQ(PhysicalOffset(126, 161), mapped_point);
  mapped_point = MapAncestorToLocal(tr, tbody, mapped_point);
  EXPECT_EQ(PhysicalOffset(126, 47), mapped_point);

  LayoutBox* table = tbody->ParentBox();
  ASSERT_TRUE(table->IsTable());
  mapped_point = MapLocalToAncestor(tbody, table, PhysicalOffset(126, 161));
  EXPECT_EQ(PhysicalOffset(141, 290), mapped_point);
  mapped_point = MapAncestorToLocal(tbody, table, mapped_point);
  EXPECT_EQ(PhysicalOffset(126, 161), mapped_point);

  mapped_point = MapLocalToAncestor(table, container, PhysicalOffset(131, 290));
  EXPECT_EQ(PhysicalOffset(143, 302), mapped_point);
  mapped_point = MapAncestorToLocal(table, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(131, 290), mapped_point);
}

static bool FloatValuesAlmostEqual(float expected, float actual) {
  return fabs(expected - actual) < 0.01;
}

static bool QuadsAlmostEqual(const gfx::QuadF& expected,
                             const gfx::QuadF& actual) {
  return FloatValuesAlmostEqual(expected.p1().x(), actual.p1().x()) &&
         FloatValuesAlmostEqual(expected.p1().y(), actual.p1().y()) &&
         FloatValuesAlmostEqual(expected.p2().x(), actual.p2().x()) &&
         FloatValuesAlmostEqual(expected.p2().y(), actual.p2().y()) &&
         FloatValuesAlmostEqual(expected.p3().x(), actual.p3().x()) &&
         FloatValuesAlmostEqual(expected.p3().y(), actual.p3().y()) &&
         FloatValuesAlmostEqual(expected.p4().x(), actual.p4().x()) &&
         FloatValuesAlmostEqual(expected.p4().y(), actual.p4().y());
}

// If comparison fails, pretty-print the error using EXPECT_EQ()
#define EXPECT_QUADF_EQ(expected, actual)      \
  do {                                         \
    if (!QuadsAlmostEqual(expected, actual)) { \
      EXPECT_EQ(expected, actual);             \
    }                                          \
  } while (false)

TEST_F(MapCoordinatesTest, Transforms) {
  SetBodyInnerHTML(R"HTML(
    <div id='container'>
        <div id='outerTransform' style='transform:rotate(45deg);
    width:200px; height:200px;'>
            <div id='innerTransform' style='transform:rotate(45deg);
    width:200px; height:200px;'>
                <div id='target' style='width:200px; height:200px;'></div>
            </div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  gfx::QuadF initial_quad(gfx::PointF(0, 0), gfx::PointF(200, 0),
                          gfx::PointF(200, 200), gfx::PointF(0, 200));
  gfx::QuadF mapped_quad = MapLocalToAncestor(target, container, initial_quad);
  EXPECT_QUADF_EQ(gfx::QuadF(gfx::PointF(200, 0), gfx::PointF(200, 200),
                             gfx::PointF(0, 200), gfx::PointF(0, 0)),
                  mapped_quad);
  mapped_quad = MapAncestorToLocal(target, container, mapped_quad);
  EXPECT_QUADF_EQ(initial_quad, mapped_quad);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  auto* inner_transform = GetLayoutBoxByElementId("innerTransform");
  auto* outer_transform = GetLayoutBoxByElementId("outerTransform");

  mapped_quad = MapLocalToAncestor(target, inner_transform, initial_quad);
  EXPECT_QUADF_EQ(gfx::QuadF(gfx::PointF(0, 0), gfx::PointF(200, 0),
                             gfx::PointF(200, 200), gfx::PointF(0, 200)),
                  mapped_quad);
  mapped_quad = MapAncestorToLocal(target, inner_transform, mapped_quad);
  EXPECT_QUADF_EQ(initial_quad, mapped_quad);

  initial_quad = gfx::QuadF(gfx::PointF(0, 0), gfx::PointF(200, 0),
                            gfx::PointF(200, 200), gfx::PointF(0, 200));
  mapped_quad =
      MapLocalToAncestor(inner_transform, outer_transform, initial_quad);
  // Clockwise rotation by 45 degrees.
  EXPECT_QUADF_EQ(
      gfx::QuadF(gfx::PointF(100, -41.42), gfx::PointF(241.42, 100),
                 gfx::PointF(100, 241.42), gfx::PointF(-41.42, 100)),
      mapped_quad);
  mapped_quad =
      MapAncestorToLocal(inner_transform, outer_transform, mapped_quad);
  EXPECT_QUADF_EQ(initial_quad, mapped_quad);

  initial_quad = gfx::QuadF(gfx::PointF(100, -41.42), gfx::PointF(241.42, 100),
                            gfx::PointF(100, 241.42), gfx::PointF(-41.42, 100));
  mapped_quad = MapLocalToAncestor(outer_transform, container, initial_quad);
  // Another clockwise rotation by 45 degrees. So now 90 degrees in total.
  EXPECT_QUADF_EQ(gfx::QuadF(gfx::PointF(200, 0), gfx::PointF(200, 200),
                             gfx::PointF(0, 200), gfx::PointF(0, 0)),
                  mapped_quad);
  mapped_quad = MapAncestorToLocal(outer_transform, container, mapped_quad);
  EXPECT_QUADF_EQ(initial_quad, mapped_quad);
}

TEST_F(MapCoordinatesTest, SVGShape) {
  SetBodyInnerHTML(R"HTML(
    <svg id='container'>
        <g transform='translate(100 200)'>
            <rect id='target' width='100' height='100'/>
        </g>
    </svg>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(100, 200), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, SVGShapeScale) {
  SetBodyInnerHTML(R"HTML(
    <svg id='container'>
        <g transform='scale(2) translate(50 40)'>
            <rect id='target' transform='translate(50 80)' x='66' y='77'
    width='100' height='100'/>
        </g>
    </svg>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(200, 240), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, SVGShapeWithViewBoxWithoutScale) {
  SetBodyInnerHTML(R"HTML(
    <svg id='container' viewBox='0 0 200 200' width='400' height='200'>
        <g transform='translate(100 50)'>
            <rect id='target' width='100' height='100'/>
        </g>
    </svg>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(200, 50), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, SVGShapeWithViewBoxWithScale) {
  SetBodyInnerHTML(R"HTML(
    <svg id='container' viewBox='0 0 100 100' width='400' height='200'>
        <g transform='translate(50 50)'>
            <rect id='target' width='100' height='100'/>
        </g>
    </svg>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(200, 100), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, SVGShapeWithViewBoxWithNonZeroOffset) {
  SetBodyInnerHTML(R"HTML(
    <svg id='container' viewBox='100 100 200 200' width='400' height='200'>
        <g transform='translate(100 50)'>
            <rect id='target' transform='translate(100 100)' width='100'
    height='100'/>
        </g>
    </svg>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(200, 50), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, SVGShapeWithViewBoxWithNonZeroOffsetAndScale) {
  SetBodyInnerHTML(R"HTML(
    <svg id='container' viewBox='100 100 100 100' width='400' height='200'>
        <g transform='translate(50 50)'>
            <rect id='target' transform='translate(100 100)' width='100'
    height='100'/>
        </g>
    </svg>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(200, 100), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, SVGForeignObject) {
  SetBodyInnerHTML(R"HTML(
    <svg id='container' viewBox='0 0 100 100' width='400' height='200'>
        <g transform='translate(50 50)'>
            <foreignObject transform='translate(-25 -25)'>
                <div xmlns='http://www.w3.org/1999/xhtml' id='target'
    style='margin-left: 50px; border: 42px; padding: 84px; width: 50px;
    height: 50px'>
                </div>
            </foreignObject>
        </g>
    </svg>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(250, 50), mapped_point);
  // <svg>
  mapped_point = MapAncestorToLocal(target->Parent()->Parent()->Parent(),
                                    container, PhysicalOffset(250, 50));
  EXPECT_EQ(PhysicalOffset(250, 50), mapped_point);
  // <g>
  mapped_point = MapAncestorToLocal(target->Parent()->Parent(), container,
                                    PhysicalOffset(250, 50));
  EXPECT_EQ(PhysicalOffset(25, -25), mapped_point);
  // <foreignObject>
  mapped_point =
      MapAncestorToLocal(target->Parent(), container, PhysicalOffset(250, 50));
  EXPECT_EQ(PhysicalOffset(50, 0), mapped_point);
  // <div>
  mapped_point = MapAncestorToLocal(target, container, PhysicalOffset(250, 50));
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, LocalToAbsoluteTransform) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position: absolute; left: 0; top: 0;'>
      <div id='scale' style='transform: scale(2.0); transform-origin: left
    top;'>
        <
"""


```