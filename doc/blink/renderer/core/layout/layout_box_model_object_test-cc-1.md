Response:
The user wants a summary of the functionality of the provided C++ code snippet from `layout_box_model_object_test.cc`. This file appears to contain unit tests for the `LayoutBoxModelObject` class in the Chromium Blink engine. These tests specifically focus on how layout objects are modeled, especially concerning:

1. **Sticky positioning:** How sticky elements are positioned within their scrolling containers, including nested sticky elements and interactions with tables and inline elements.
2. **Containing block and stacking context:** How layout objects determine their containing blocks and how stacking contexts are affected by properties like `position: relative` and `backface-visibility`.
3. **Paint invalidation:** How changes to properties like `filter`, `backdrop-filter`, and `will-change` trigger paint invalidation and the creation/removal of paint layers.
4. **Containment:** How the `contain` CSS property affects sticky positioning.

I need to go through the test cases and categorize their functionalities and their relations to web technologies (HTML, CSS, JavaScript). I should also identify potential user or programming errors the tests might be catching.
这是 `blink/renderer/core/layout/layout_box_model_object_test.cc` 文件的一部分，主要功能是**测试 `LayoutBoxModelObject` 类的各种行为和属性，特别是与定位（positioning）、滚动（scrolling）、层叠上下文（stacking context）以及渲染（painting）相关的特性。**

以下是更具体的归纳：

**主要功能归纳:**

* **测试粘性定位（`position: sticky`）：**
    * **查找正确的包含块（Containing Block）：** 测试在各种复杂的 DOM 结构下，粘性定位元素能否正确找到其包含块，包括有滚动容器、根元素、表格等情况。
    * **计算正确的偏移量（Offsets）：** 测试嵌套的粘性定位元素在滚动时，其偏移量是否按照 CSS 规范计算正确，涵盖了父子元素之间不同 `top` 值的场景，以及子元素超出父元素范围的情况。
    * **与表格的交互：** 特别测试粘性定位在表格中的行为，因为表格的包含块规则比较特殊。
    * **与行内元素的交互：** 测试粘性定位在行内元素中的行为。
    * **与 `position: fixed` 元素的交互：** 测试当粘性定位元素遇到中间的固定定位元素时，其行为是否正确。
* **测试层叠上下文（Stacking Context）：**
    * **`IsStacked()` 和 `IsStackingContext()` 的变化：**  测试当元素的层叠状态（是否参与层叠）或是否创建新的层叠上下文发生变化时，相关属性是否更新正确。
    * **`backface-visibility` 属性的影响：** 测试 `backface-visibility` 属性的改变是否会触发正确的重绘。
* **测试渲染（Painting）的失效（Invalidation）：**
    * **`filter` 和 `backdrop-filter` 属性：** 测试当添加或移除 `filter` 或 `backdrop-filter` 属性时，是否会触发必要的重绘。
    * **`will-change` 属性：** 测试 `will-change` 属性对 `filter` 和 `backdrop-filter` 的影响，即使用了 `will-change` 时，某些属性的改变可能不需要立即触发重绘。
* **测试 `option` 元素的层叠上下文：**  测试 `select` 元素中的 `option` 元素在特定情况下是否会创建层叠上下文。
* **测试 CSS Containment 对粘性定位的影响：** 测试 `contain: strict` 属性如何影响粘性定位元素的包含滚动容器的查找。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 代码中通过 `SetBodyInnerHTML()` 函数设置 HTML 结构，模拟各种复杂的 DOM 树，例如嵌套的 `div`、带有 `thead` 和 `tbody` 的 `table`、行内元素等。这些 HTML 结构是测试用例的基础。
    * **举例：** `<div id='stickyParent'><div><div id='stickyGrandchild'></div></div></div>`  定义了一个嵌套的 `div` 结构，用于测试粘性定位的包含块查找。
* **CSS:** 代码中通过 `<style>` 标签设置 CSS 样式，用于定义元素的定位方式（`position: sticky`, `position: fixed`）、滚动行为 (`overflow-y: auto`)、层叠属性 (`position: relative`)、渲染属性 (`filter`, `backdrop-filter`, `backface-visibility`) 以及 CSS Containment (`contain: strict`) 等。
    * **举例：** `#stickyParent { position: sticky; top: 0;}` 定义了一个 `id` 为 `stickyParent` 的 `div` 元素为粘性定位，并设置了 `top` 值为 0。
* **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的内部逻辑，但它模拟了浏览器在处理 HTML 和 CSS 时会发生的各种情况。开发者可以通过 JavaScript 来设置元素的样式和属性，从而触发这里测试的各种布局和渲染行为。
    * **举例：**  在测试 `InvalidatePaintLayerOnStackedChange` 功能时，代码模拟了通过 JavaScript 修改元素的 `class` 属性，从而改变其层叠状态。这等价于在 JavaScript 中执行 `target_element.setAttribute('class', 'non-stacked')`。

**逻辑推理的假设输入与输出:**

以下是一些测试用例中隐含的逻辑推理和假设：

* **假设输入 (StickyPositionNested):**
    * HTML 结构包含一个可滚动的 `div` (`#scroller`)，其中嵌套了一个父粘性定位元素 (`#stickyParent`) 和一个子粘性定位元素 (`#stickyChild`)。
    * CSS 设置父元素和子元素的 `top` 值为 0。
    * 滚动容器向下滚动了 100 像素。
* **预期输出 (StickyPositionNested):**
    * 父粘性定位元素的 `StickyPositionOffset()` 应该是 `PhysicalOffset(0, 50)`，因为它需要向下偏移 50 像素才能贴在滚动容器顶部。
    * 子粘性定位元素的 `StickyPositionOffset()` 应该是 `PhysicalOffset(0, 0)`，因为它相对于其粘性定位的父元素进行定位。

* **假设输入 (StickyPositionFindsCorrectContainingBlockShiftingAncestorTable):**
    * HTML 结构包含一个可滚动的 `div` (`#scroller`)，其中嵌套了一个粘性定位的 `div` (`#stickyOuter`)，该 `div` 包含一个 `table`，表格的 `thead` 中有一个粘性定位的 `th` (`#stickyTh`)。
* **预期输出 (StickyPositionFindsCorrectContainingBlockShiftingAncestorTable):**
    *  `#stickyTh` 的 `nearest_sticky_layer_shifting_containing_block` 应该指向 `#stickyOuter` 的 `LayoutBox` 对象。因为在表格中，`<table>` 元素是其所有子元素的包含块，需要向上查找具有滚动属性的祖先元素。

**涉及用户或者编程常见的使用错误:**

虽然这个测试文件是测试引擎内部逻辑的，但它覆盖了一些开发者在使用 CSS 时可能遇到的常见问题：

* **误解粘性定位的包含块：** 开发者可能不清楚粘性定位元素会相对于哪个祖先元素进行粘性吸附。例如，在表格中，直接父元素可能不是预期的包含块。测试用例 `StickyPositionFindsCorrectContainingBlockShiftingAncestorTable` 就覆盖了这种情况，如果开发者错误地认为 `#stickyTh` 会相对于 `<table>` 进行粘性定位，就会出现问题。
* **嵌套粘性定位的偏移量计算错误：**  开发者可能难以正确预测嵌套的粘性定位元素的最终位置，尤其是当父子元素的 `top` 值不同时。测试用例如 `StickyPositionNested`, `StickyPositionChildHasLargerTop`, `StickyPositionParentHasLargerTop` 等都旨在验证引擎是否能正确处理这些情况，避免开发者因手动计算错误而导致布局问题。
* **不了解 `will-change` 的作用：** 开发者可能不清楚 `will-change` 属性对于性能优化的作用，以及它如何影响浏览器的渲染行为。测试用例 `ChangingFilterWithWillChange`, `ChangingWillChangeFilter` 等展示了 `will-change` 可以避免一些不必要的重绘操作。
* **对 CSS Containment 的理解不足：** 开发者可能不清楚 `contain` 属性对布局和渲染的影响，特别是对粘性定位等复杂布局的影响。测试用例 `StickyParentContainStrictChangeOverflowProperty` 和 `RemoveStickyUnderContain` 就关注了 `contain` 属性如何改变粘性定位元素的行为。

总而言之，这个测试文件通过大量的单元测试，细致地检验了 Blink 引擎在处理各种复杂的 CSS 布局特性时的正确性，确保了浏览器能够按照 CSS 规范渲染网页，并帮助开发者避免在使用这些特性时可能遇到的陷阱。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_box_model_object_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
aining_block);
}

// Verifies that the correct containing-block shifting ancestor is found when
// computing the sticky constraints, in the case where the overflow ancestor is
// the page itself. This is a special-case version of the test above, as we
// often treat the root page as special when it comes to scroll logic. It should
// not make a difference for containing-block shifting ancestor calculations.
TEST_P(LayoutBoxModelObjectTest,
       StickyPositionFindsCorrectContainingBlockShiftingAncestorRoot) {
  SetBodyInnerHTML(R"HTML(
    <style>#stickyParent { position: sticky; top: 0;}
    #stickyGrandchild { position: sticky; top: 0;}</style>
    <div id='stickyParent'><div><div id='stickyGrandchild'></div></div>
    </div>
  )HTML");

  LayoutBox* sticky_parent = GetLayoutBoxByElementId("stickyParent");
  LayoutBox* sticky_grandchild = GetLayoutBoxByElementId("stickyGrandchild");

  PaintLayerScrollableArea* scrollable_area =
      sticky_parent->Layer()
          ->ContainingScrollContainerLayer()
          ->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);

  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky_parent));
  EXPECT_TRUE(sticky_parent->StickyConstraints());

  ASSERT_TRUE(HasStickyLayer(scrollable_area, sticky_grandchild));
  auto* grandchild_constraints = sticky_grandchild->StickyConstraints();
  ASSERT_TRUE(grandchild_constraints);

  // The grandchild sticky should detect the parent as its containing-block
  // shifting ancestor.
  EXPECT_EQ(
      sticky_parent,
      grandchild_constraints->nearest_sticky_layer_shifting_containing_block);
}

// Verifies that the correct containing-block shifting ancestor is found when
// computing the sticky constraints, in the case of tables. Tables are unusual
// because the containing block for all table elements is the <table> itself, so
// we have to skip over elements to find the correct ancestor.
TEST_P(LayoutBoxModelObjectTest,
       StickyPositionFindsCorrectContainingBlockShiftingAncestorTable) {
  SetBodyInnerHTML(R"HTML(
    <style>#scroller { overflow-y: scroll; }
    #stickyOuter { position: sticky; top: 0;}
    #stickyTh { position: sticky; top: 0;}</style>
    <div id='scroller'><div id='stickyOuter'><table><thead><tr>
    <th id='stickyTh'></th></tr></thead></table></div></div>
  )HTML");

  LayoutBox* scroller = GetLayoutBoxByElementId("scroller");
  LayoutBox* sticky_outer = GetLayoutBoxByElementId("stickyOuter");
  LayoutBox* sticky_th = GetLayoutBoxByElementId("stickyTh");

  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  ASSERT_FALSE(HasStickyLayer(scrollable_area, scroller));
  EXPECT_FALSE(scroller->StickyConstraints());

  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky_outer));
  EXPECT_TRUE(sticky_outer->StickyConstraints());

  ASSERT_TRUE(HasStickyLayer(scrollable_area, sticky_th));
  auto* th_constraints = sticky_th->StickyConstraints();
  ASSERT_TRUE(th_constraints);

  // The table cell should detect the outer <div> as its containing-block
  // shifting ancestor.
  EXPECT_EQ(sticky_outer,
            th_constraints->nearest_sticky_layer_shifting_containing_block);
}

// Verifies that the calculated position:sticky offsets are correct when we have
// a simple case of nested sticky elements.
TEST_P(LayoutBoxModelObjectTest, StickyPositionNested) {
  SetBodyInnerHTML(R"HTML(
    <style>#scroller { height: 100px; width: 100px; overflow-y: auto; }
    #prePadding { height: 50px }
    #stickyParent { position: sticky; top: 0; height: 50px; }
    #stickyChild { position: sticky; top: 0; height: 25px; }
    #postPadding { height: 200px }</style>
    <div id='scroller'><div id='prePadding'></div><div id='stickyParent'>
    <div id='stickyChild'></div></div><div id='postPadding'></div></div>
  )HTML");

  auto* sticky_parent = GetLayoutBoxModelObjectByElementId("stickyParent");
  auto* sticky_child = GetLayoutBoxModelObjectByElementId("stickyChild");

  // Scroll the page down.
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 100));
  ASSERT_EQ(100.0, scrollable_area->ScrollPosition().y());

  // Both the parent and child sticky divs are attempting to place themselves at
  // the top of the scrollable area. To achieve this the parent must offset on
  // the y-axis against its starting position. The child is offset relative to
  // its parent so should not move at all.
  EXPECT_EQ(PhysicalOffset(0, 50), sticky_parent->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 0), sticky_child->StickyPositionOffset());
}

// Verifies that the calculated position:sticky offsets are correct when the
// child has a larger edge constraint value than the parent.
TEST_P(LayoutBoxModelObjectTest, StickyPositionChildHasLargerTop) {
  SetBodyInnerHTML(R"HTML(
    <style>#scroller { height: 100px; width: 100px; overflow-y: auto; }
    #prePadding { height: 50px }
    #stickyParent { position: sticky; top: 0; height: 50px; }
    #stickyChild { position: sticky; top: 25px; height: 25px; }
    #postPadding { height: 200px }</style>
    <div id='scroller'><div id='prePadding'></div><div id='stickyParent'>
    <div id='stickyChild'></div></div><div id='postPadding'></div></div>
  )HTML");

  auto* sticky_parent = GetLayoutBoxModelObjectByElementId("stickyParent");
  auto* sticky_child = GetLayoutBoxModelObjectByElementId("stickyChild");

  // Scroll the page down.
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 100));
  ASSERT_EQ(100.0, scrollable_area->ScrollPosition().y());

  // The parent is attempting to place itself at the top of the scrollable area,
  // whilst the child is attempting to be 25 pixels from the top. To achieve
  // this both must offset on the y-axis against their starting positions, but
  // note the child is offset relative to the parent.
  EXPECT_EQ(PhysicalOffset(0, 50), sticky_parent->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 25), sticky_child->StickyPositionOffset());
}

// Verifies that the calculated position:sticky offsets are correct when the
// child has a smaller edge constraint value than the parent.
TEST_P(LayoutBoxModelObjectTest, StickyPositionParentHasLargerTop) {
  SetBodyInnerHTML(R"HTML(
    <style>#scroller { height: 100px; width: 100px; overflow-y: auto; }
    #prePadding { height: 50px }
    #stickyParent { position: sticky; top: 25px; height: 50px; }
    #stickyChild { position: sticky; top: 0; height: 25px; }
    #postPadding { height: 200px }</style>
    <div id='scroller'><div id='prePadding'></div><div id='stickyParent'>
    <div id='stickyChild'></div></div><div id='postPadding'></div></div>
  )HTML");

  auto* sticky_parent = GetLayoutBoxModelObjectByElementId("stickyParent");
  auto* sticky_child = GetLayoutBoxModelObjectByElementId("stickyChild");

  // Scroll the page down.
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 100));
  ASSERT_EQ(100.0, scrollable_area->ScrollPosition().y());

  // The parent is attempting to place itself 25 pixels from the top of the
  // scrollable area, whilst the child is attempting to be at the top. However,
  // the child must stay contained within the parent, so it should be pushed
  // down to the same height. As always, the child offset is relative.
  EXPECT_EQ(PhysicalOffset(0, 75), sticky_parent->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 0), sticky_child->StickyPositionOffset());
}

// Verifies that the calculated position:sticky offsets are correct when the
// child has a large enough edge constraint value to push outside of its parent.
TEST_P(LayoutBoxModelObjectTest, StickyPositionChildPushingOutsideParent) {
  SetBodyInnerHTML(R"HTML(
    <style> #scroller { height: 100px; width: 100px; overflow-y: auto; }
    #prePadding { height: 50px; }
    #stickyParent { position: sticky; top: 0; height: 50px; }
    #stickyChild { position: sticky; top: 50px; height: 25px; }
    #postPadding { height: 200px }</style>
    <div id='scroller'><div id='prePadding'></div><div id='stickyParent'>
    <div id='stickyChild'></div></div><div id='postPadding'></div></div>
  )HTML");

  auto* sticky_parent = GetLayoutBoxModelObjectByElementId("stickyParent");
  auto* sticky_child = GetLayoutBoxModelObjectByElementId("stickyChild");

  // Scroll the page down.
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 100));
  ASSERT_EQ(100.0, scrollable_area->ScrollPosition().y());

  // The parent is attempting to place itself at the top of the scrollable area,
  // whilst the child is attempting to be 50 pixels from the top. However, there
  // is only 25 pixels of space for the child to move into, so it should be
  // capped by that offset. As always, the child offset is relative.
  EXPECT_EQ(PhysicalOffset(0, 50), sticky_parent->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 25), sticky_child->StickyPositionOffset());
}

// Verifies that the calculated position:sticky offsets are correct in the case
// of triple nesting. Triple (or more) nesting must be tested as the grandchild
// sticky must correct both its sticky box constraint rect and its containing
// block constaint rect.
TEST_P(LayoutBoxModelObjectTest, StickyPositionTripleNestedDiv) {
  SetBodyInnerHTML(R"HTML(
    <style>#scroller { height: 200px; width: 100px; overflow-y: auto; }
    #prePadding { height: 50px; }
    #outmostSticky { position: sticky; top: 0; height: 100px; }
    #middleSticky { position: sticky; top: 0; height: 75px; }
    #innerSticky { position: sticky; top: 25px; height: 25px; }
    #postPadding { height: 400px }</style>
    <div id='scroller'><div id='prePadding'></div><div id='outmostSticky'>
    <div id='middleSticky'><div id='innerSticky'></div></div></div>
    <div id='postPadding'></div></div>
  )HTML");

  auto* outmost_sticky = GetLayoutBoxModelObjectByElementId("outmostSticky");
  auto* middle_sticky = GetLayoutBoxModelObjectByElementId("middleSticky");
  auto* inner_sticky = GetLayoutBoxModelObjectByElementId("innerSticky");

  // Scroll the page down.
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 100));
  ASSERT_EQ(100.0, scrollable_area->ScrollPosition().y());

  // The grandparent and parent divs are attempting to place themselves at the
  // top of the scrollable area. The child div is attempting to place itself at
  // an offset of 25 pixels to the top of the scrollable area. The result of
  // this sticky offset calculation is quite simple, but internally the child
  // offset has to offset both its sticky box constraint rect and its containing
  // block constraint rect.
  EXPECT_EQ(PhysicalOffset(0, 50), outmost_sticky->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 0), middle_sticky->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 25), inner_sticky->StickyPositionOffset());
}

// Verifies that the calculated position:sticky offsets are correct in the case
// of tables. Tables are special as the containing block for table elements is
// always the root level <table>.
TEST_P(LayoutBoxModelObjectTest, StickyPositionNestedStickyTable) {
  SetBodyInnerHTML(R"HTML(
    <style>table { border-collapse: collapse; }
    td, th { height: 25px; width: 25px; padding: 0; }
    #scroller { height: 100px; width: 100px; overflow-y: auto; }
    #prePadding { height: 50px; }
    #stickyDiv { position: sticky; top: 0; height: 200px; }
    #stickyTh { position: sticky; top: 0; }
    #postPadding { height: 200px; }</style>
    <div id='scroller'><div id='prePadding'></div><div id='stickyDiv'>
    <table><thead><tr><th id='stickyTh'></th></tr></thead><tbody><tr><td>
    </td></tr><tr><td></td></tr><tr><td></td></tr><tr><td></td></tr></tbody>
    </table></div><div id='postPadding'></div></div>
  )HTML");

  auto* sticky_div = GetLayoutBoxModelObjectByElementId("stickyDiv");
  auto* sticky_th = GetLayoutBoxModelObjectByElementId("stickyTh");

  // Scroll the page down.
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 150));
  ASSERT_EQ(150.0, scrollable_area->ScrollPosition().y());

  // All sticky elements are attempting to stick to the top of the scrollable
  // area. For the root sticky div, this requires an offset. All the other
  // descendant sticky elements are positioned relatively so don't need offset.
  EXPECT_EQ(PhysicalOffset(0, 100), sticky_div->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 0), sticky_th->StickyPositionOffset());

  // If we now scroll to the point where the overall sticky div starts to move,
  // the table headers should continue to stick to the top of the scrollable
  // area until they run out of <table> space to move in.

  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 275));
  ASSERT_EQ(275.0, scrollable_area->ScrollPosition().y());

  EXPECT_EQ(PhysicalOffset(0, 200), sticky_div->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 25), sticky_th->StickyPositionOffset());

  // Finally, if we scroll so that the table is off the top of the page, the
  // sticky header should travel as far as it can (i.e. the table height) then
  // move off the top with it.
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 350));
  ASSERT_EQ(350.0, scrollable_area->ScrollPosition().y());

  EXPECT_EQ(PhysicalOffset(0, 200), sticky_div->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 100), sticky_th->StickyPositionOffset());
}

// Verifies that the calculated position:sticky offsets are correct in the case
// where a particular position:sticky element is used both as a sticky-box
// shifting ancestor as well as a containing-block shifting ancestor.
//
// This is a rare case that can be replicated by nesting tables so that a sticky
// cell contains another table that has sticky elements. See the HTML below.
TEST_P(LayoutBoxModelObjectTest, StickyPositionComplexTableNesting) {
  SetBodyInnerHTML(R"HTML(
    <style>table { border-collapse: collapse; }
    td, th { height: 25px; width: 25px; padding: 0; }
    #scroller { height: 100px; width: 100px; overflow-y: auto; }
    #prePadding { height: 50px; }
    #outerStickyTh { height: 50px; position: sticky; top: 0; }
    #innerStickyTh { position: sticky; top: 25px; }
    #postPadding { height: 200px; }</style>
    <div id='scroller'><div id='prePadding'></div>
    <table><thead><tr><th id='outerStickyTh'><table><thead><tr>
    <th id='innerStickyTh'></th></tr></thead><tbody><tr><td></td></tr>
    </tbody></table></th></tr></thead><tbody><tr><td></td></tr><tr><td></td>
    </tr><tr><td></td></tr><tr><td></td></tr></tbody></table>
    <div id='postPadding'></div></div>
  )HTML");

  auto* outer_sticky_th = GetLayoutBoxModelObjectByElementId("outerStickyTh");
  auto* inner_sticky_th = GetLayoutBoxModelObjectByElementId("innerStickyTh");

  // Scroll the page down.
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 150));
  ASSERT_EQ(150.0, scrollable_area->ScrollPosition().y());

  EXPECT_EQ(PhysicalOffset(0, 100), outer_sticky_th->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 25), inner_sticky_th->StickyPositionOffset());
}

// Verifies that the calculated position:sticky offsets are correct in the case
// of nested inline elements.
TEST_P(LayoutBoxModelObjectTest, StickyPositionNestedInlineElements) {
  SetBodyInnerHTML(R"HTML(
    <style>#scroller { width: 100px; height: 100px; overflow-y: scroll; }
    #paddingBefore { height: 50px; }
    #outerInline { display: inline; position: sticky; top: 0; }
    #unanchoredSticky { position: sticky; display: inline; }
    .inline {display: inline;}
    #innerInline { display: inline; position: sticky; top: 25px; }
    #paddingAfter { height: 200px; }</style>
    <div id='scroller'>
      <div id='paddingBefore'></div>
      <div id='outerInline'>
        <div id='unanchoredSticky'>
          <div class='inline'>
            <div id='innerInline'></div>
          </div>
        </div>
      </div>
      <div id='paddingAfter'></div>
    </div>
  )HTML");

  auto* outer_inline = GetLayoutBoxModelObjectByElementId("outerInline");
  auto* inner_inline = GetLayoutBoxModelObjectByElementId("innerInline");

  // Scroll the page down.
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  ASSERT_EQ(50.0, scrollable_area->ScrollPosition().y());

  EXPECT_EQ(PhysicalOffset(0, 0), outer_inline->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 25), inner_inline->StickyPositionOffset());
}

// Verifies that the calculated position:sticky offsets are correct in the case
// of an intermediate position:fixed element.
TEST_P(LayoutBoxModelObjectTest, StickyPositionNestedFixedPos) {
  SetBodyInnerHTML(R"HTML(
    <style>
      ::-webkit-scrollbar { width: 0; height: 0; }
      body { margin: 0; }
      #scroller { height: 200px; width: 100px; overflow-y: auto; }
      #outerSticky { position: sticky; top: 0; height: 50px; }
      #fixedDiv { position: fixed; top: 0; left: 300px; height: 1000px;
                  width: 100px; }
      #innerStickyTop { position: sticky; top: 25px; height: 25px; }
      #innerStickyBottom { position: sticky; bottom: 25px; height: 25px; }
      .padding { height: 600px; }
    </style>
    <div id='scroller'>
      <div id='outerSticky'>
        <div id='fixedDiv'>
          <div id='innerStickyTop'></div>
          <div class='padding'></div>
          <div id='innerStickyBottom'></div>
        </div>
      </div>
      <div class='padding'></div>
    </div>
    <div class='padding'></div>
  )HTML");

  // The view size is set by the base class. This test depends on it.
  ASSERT_EQ(PhysicalSize(800, 600), GetLayoutView().Size());

  auto* outer_sticky = GetLayoutBoxModelObjectByElementId("outerSticky");
  auto* inner_sticky_top = GetLayoutBoxModelObjectByElementId("innerStickyTop");
  auto* inner_sticky_bottom =
      GetLayoutBoxModelObjectByElementId("innerStickyBottom");

  auto* view_scrollable_area = GetLayoutView().GetScrollableArea();
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  auto* scroller_scrollable_area = scroller->GetScrollableArea();

  // outerSticky is contained by the scroller.
  ASSERT_FALSE(HasStickyLayer(view_scrollable_area, outer_sticky));
  bool is_fixed_to_view = false;
  ASSERT_EQ(
      scroller->Layer(),
      outer_sticky->Layer()->ContainingScrollContainerLayer(&is_fixed_to_view));
  ASSERT_FALSE(is_fixed_to_view);
  ASSERT_TRUE(HasStickyLayer(scroller_scrollable_area, outer_sticky));

  // innerSticky* are not contained by the scroller, but by the LayoutView
  ASSERT_TRUE(HasStickyLayer(view_scrollable_area, inner_sticky_top));
  ASSERT_EQ(GetLayoutView().Layer(),
            inner_sticky_top->Layer()->ContainingScrollContainerLayer(
                &is_fixed_to_view));
  ASSERT_TRUE(is_fixed_to_view);
  ASSERT_FALSE(HasStickyLayer(scroller_scrollable_area, inner_sticky_top));
  ASSERT_TRUE(HasStickyLayer(view_scrollable_area, inner_sticky_top));
  ASSERT_EQ(GetLayoutView().Layer(),
            inner_sticky_bottom->Layer()->ContainingScrollContainerLayer(
                &is_fixed_to_view));
  ASSERT_TRUE(is_fixed_to_view);
  ASSERT_FALSE(HasStickyLayer(scroller_scrollable_area, inner_sticky_top));
  ASSERT_TRUE(HasStickyLayer(view_scrollable_area, inner_sticky_top));

  // innerSticky* should not detect the outer one as any sort of ancestor.
  auto* inner_constraints_top = inner_sticky_top->StickyConstraints();
  ASSERT_TRUE(inner_constraints_top);
  EXPECT_FALSE(inner_constraints_top->nearest_sticky_layer_shifting_sticky_box);
  EXPECT_FALSE(
      inner_constraints_top->nearest_sticky_layer_shifting_containing_block);
  auto* inner_constraints_bottom = inner_sticky_bottom->StickyConstraints();
  ASSERT_TRUE(inner_constraints_bottom);
  EXPECT_FALSE(
      inner_constraints_bottom->nearest_sticky_layer_shifting_sticky_box);
  EXPECT_FALSE(
      inner_constraints_bottom->nearest_sticky_layer_shifting_containing_block);

  // Scroll the scroller down.
  scroller_scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scroller_scrollable_area->ScrollPosition().x(), 100));
  ASSERT_EQ(100.0, scroller_scrollable_area->ScrollPosition().y());

  EXPECT_EQ(PhysicalOffset(0, 100), outer_sticky->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 25), inner_sticky_top->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, -75),
            inner_sticky_bottom->StickyPositionOffset());

  // Scroll the page down. No StickyPositionOffset() should change because
  // none of the sticky elements scroll with the view.
  view_scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(view_scrollable_area->ScrollPosition().x(), 100));
  ASSERT_EQ(100.0, view_scrollable_area->ScrollPosition().y());

  EXPECT_EQ(PhysicalOffset(0, 100), outer_sticky->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, 25), inner_sticky_top->StickyPositionOffset());
  EXPECT_EQ(PhysicalOffset(0, -75),
            inner_sticky_bottom->StickyPositionOffset());
}

TEST_P(LayoutBoxModelObjectTest, InvalidatePaintLayerOnStackedChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .stacked { background: red; position: relative; height: 2000px; }
      .non-stacked { all: inherit }
    </style>
    <div style='height: 100px; backface-visibility: hidden'>
      <div id='target' class='stacked'></div>
    </div>
  )HTML");

  auto* target_element = GetElementById("target");
  auto* target = target_element->GetLayoutBoxModelObject();
  auto* parent = target->Parent();
  auto* original_compositing_container =
      target->Layer()->CompositingContainer();
  EXPECT_FALSE(target->IsStackingContext());
  EXPECT_TRUE(target->IsStacked());
  EXPECT_FALSE(parent->IsStacked());
  EXPECT_NE(parent, original_compositing_container->GetLayoutObject());

  target_element->setAttribute(html_names::kClassAttr,
                               AtomicString("non-stacked"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  EXPECT_FALSE(target->IsStacked());
  EXPECT_TRUE(target->Layer()->SelfNeedsRepaint());
  EXPECT_TRUE(original_compositing_container->DescendantNeedsRepaint());
  auto* new_compositing_container = target->Layer()->CompositingContainer();
  EXPECT_EQ(parent, new_compositing_container->GetLayoutObject());

  UpdateAllLifecyclePhasesForTest();
  target_element->setAttribute(html_names::kClassAttr, AtomicString("stacked"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  EXPECT_TRUE(target->IsStacked());
  EXPECT_TRUE(target->Layer()->SelfNeedsRepaint());
  EXPECT_TRUE(new_compositing_container->DescendantNeedsRepaint());
  EXPECT_EQ(original_compositing_container,
            target->Layer()->CompositingContainer());
}

TEST_P(LayoutBoxModelObjectTest, BackfaceVisibilityChange) {
  AtomicString base_style(
      "width: 100px; height: 100px; background: blue; position: absolute");
  SetBodyInnerHTML("<div id='target' style='" + base_style + "'></div>");

  auto* target = GetElementById("target");
  auto* target_layer =
      To<LayoutBoxModelObject>(target->GetLayoutObject())->Layer();
  ASSERT_NE(nullptr, target_layer);
  EXPECT_FALSE(target_layer->SelfNeedsRepaint());

  target->setAttribute(
      html_names::kStyleAttr,
      AtomicString(base_style + "; backface-visibility: hidden"));
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(target_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target_layer->SelfNeedsRepaint());

  target->setAttribute(html_names::kStyleAttr, base_style);
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(target_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target_layer->SelfNeedsRepaint());
}

TEST_P(LayoutBoxModelObjectTest, ChangingFilterWithWillChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        width: 100px;
        height: 100px;
        will-change: filter;
      }
    </style>
    <div id="target"></div>
  )HTML");

  // Adding a filter should not need to check for paint invalidation because
  // will-change: filter is present.
  auto* target = GetElementById("target");
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("filter: grayscale(1)"));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());

  // Removing a filter should not need to check for paint invalidation because
  // will-change: filter is present.
  target->removeAttribute(html_names::kStyleAttr);
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
}

TEST_P(LayoutBoxModelObjectTest, ChangingWillChangeFilter) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .willChange {
        will-change: filter;
      }
      #filter {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id="target"></div>
  )HTML");

  // Adding will-change: filter should check for paint invalidation and create
  // a PaintLayer.
  auto* target = GetElementById("target");
  target->classList().Add(AtomicString("willChange"));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  EXPECT_TRUE(To<LayoutBoxModelObject>(target->GetLayoutObject())->Layer());

  // A lifecycle update should clear dirty bits.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  EXPECT_TRUE(To<LayoutBoxModelObject>(target->GetLayoutObject())->Layer());

  // Removing will-change: filter should check for paint invalidation and remove
  // the PaintLayer.
  target->classList().Remove(AtomicString("willChange"));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(To<LayoutBoxModelObject>(target->GetLayoutObject())->Layer());
}

TEST_P(LayoutBoxModelObjectTest, ChangingBackdropFilterWithWillChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        width: 100px;
        height: 100px;
        will-change: backdrop-filter;
      }
    </style>
    <div id="target"></div>
  )HTML");

  // Adding a backdrop-filter should not need to check for paint invalidation
  // because will-change: backdrop-filter is present.
  auto* target = GetElementById("target");
  target->setAttribute(html_names::kStyleAttr,
                       AtomicString("backdrop-filter: grayscale(1)"));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());

  // Removing a backdrop-filter should not need to check for paint invalidation
  // because will-change: backdrop-filter is present.
  target->removeAttribute(html_names::kStyleAttr);
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
}

TEST_P(LayoutBoxModelObjectTest, ChangingWillChangeBackdropFilter) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .willChange {
        will-change: backdrop-filter;
      }
      #filter {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id="target"></div>
  )HTML");

  // Adding will-change: backdrop-filter should check for paint invalidation and
  // create a PaintLayer.
  auto* target = GetElementById("target");
  target->classList().Add(AtomicString("willChange"));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  EXPECT_TRUE(To<LayoutBoxModelObject>(target->GetLayoutObject())->Layer());

  // A lifecycle update should clear dirty bits.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  EXPECT_TRUE(To<LayoutBoxModelObject>(target->GetLayoutObject())->Layer());

  // Removing will-change: backdrop-filter should check for paint invalidation
  // and remove the PaintLayer.
  target->classList().Remove(AtomicString("willChange"));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(target->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(To<LayoutBoxModelObject>(target->GetLayoutObject())->Layer());
}

TEST_P(LayoutBoxModelObjectTest, UpdateStackingContextForOption) {
  // We do not create LayoutObject for option elements inside multiple selects
  // on platforms where DelegatesMenuListRendering() returns true like Android.
  if (LayoutTheme::GetTheme().DelegatesMenuListRendering())
    return;

  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes op {
        0% { opacity: 0 }
        100% { opacity: 1 }
      }
      option {
        animation: op 0.001s;
      }
    </style>
    <select multiple size=1>
      <option id=opt>PASS</option>
    </select>
  )HTML");

  auto* option_element = GetElementById("opt");
  auto* option_layout = option_element->GetLayoutObject();
  ASSERT_TRUE(option_layout);
  EXPECT_TRUE(option_layout->IsStackingContext());
  EXPECT_TRUE(option_layout->StyleRef().HasCurrentOpacityAnimation());
}

TEST_P(LayoutBoxModelObjectTest,
       StickyParentContainStrictChangeOverflowProperty) {
  SetBodyInnerHTML(R"HTML(
    <style>html, body { contain: strict; }</style>
    <div id="sticky" style="position: sticky; top: 1px"></div>
  )HTML");

  auto* sticky = GetLayoutBoxByElementId("sticky");
  auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_EQ(&GetLayoutView(),
            &constraints->containing_scroll_container_layer->GetLayoutObject());

  GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                     AtomicString("overflow: hidden"));
  UpdateAllLifecyclePhasesForTest();
  constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_EQ(GetDocument().body()->GetLayoutObject(),
            &constraints->containing_scroll_container_layer->GetLayoutObject());

  GetDocument().body()->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_EQ(&GetLayoutView(),
            &constraints->containing_scroll_container_layer->GetLayoutObject());
}

TEST_P(LayoutBoxModelObjectTest, RemoveStickyUnderContain) {
  SetBodyInnerHTML(R"HTML(
    <div id="contain" style="contain: strict; width: 100px; height: 2000px">
      <div id="parent">
        <div id="sticky" style="top: 100px; position: sticky">STICKY</div>
      </div>
    </div>
  )HTML");

  auto* scrollable_area = GetLayoutView().GetScrollableArea();
  auto* sticky = GetLayoutBoxByElementId("sticky");
  EXPECT_TRUE(HasStickyLayer(scrollab
"""


```