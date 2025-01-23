Response:
The user wants to understand the functionality of the `map_coordinates_test.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and identify its core purpose. Then, I need to explain its relevance to web technologies (JavaScript, HTML, CSS) with concrete examples. If the code involves logical calculations, I should demonstrate this with input and output scenarios. Finally, I should point out potential pitfalls or common mistakes developers might encounter when dealing with coordinate mapping.

Here's a breakdown of how to approach each part:

1. **Core Functionality:** The file name and the included headers strongly suggest that this file contains unit tests for coordinate mapping within the Blink rendering engine. It likely tests functions that convert coordinates between different layout objects in the rendering tree.

2. **Relationship to JavaScript, HTML, and CSS:**
    * **HTML:** The structure of the DOM (Document Object Model) directly influences the layout tree. The tests use HTML snippets to create specific layout scenarios.
    * **CSS:** CSS properties like `position`, `transform`, `margin`, `padding`, `border`, `overflow`, and `columns` affect the positioning and visual presentation of elements, and thus, the coordinate mapping between them.
    * **JavaScript:** While not directly present in this test file, JavaScript often triggers layout changes (e.g., by manipulating CSS properties or the DOM structure). The coordinate mapping functions tested here are crucial for JavaScript APIs like `getBoundingClientRect()` or event handling, where determining the position of elements is essential.

3. **Logical Reasoning with Input and Output:**  The test cases themselves provide examples of input (HTML structure, initial coordinates) and expected output (mapped coordinates). I can highlight a few of these and explain the transformations involved based on CSS properties.

4. **Common User/Programming Errors:**  Misunderstanding how different CSS properties affect coordinate systems is a common issue. For example, forgetting about the impact of `position: relative` or `transform` on the coordinate origin. Incorrectly assuming the coordinate system of a parent element without considering transformations or scrolling is another potential error.

5. **Summary of Functionality:**  Based on the above points, I can summarize the file's purpose as testing the accuracy of coordinate mapping functions within Blink's layout engine, ensuring that points and rectangles can be correctly translated between different elements in various layout scenarios defined by HTML and CSS.
这是 `blink/renderer/core/layout/map_coordinates_test.cc` 文件的第一部分，其主要功能是 **测试 Blink 渲染引擎中布局对象之间坐标映射的准确性**。

更具体地说，这个文件包含了一系列的单元测试，用于验证 `LayoutObject` 类及其子类中用于在不同的父元素之间转换坐标的方法（例如 `LocalToAncestorPoint` 和 `AncestorToLocalPoint` 等）。这些测试覆盖了各种常见的 HTML 和 CSS 布局场景，以确保坐标转换在这些场景下能够正确工作。

**它与 JavaScript, HTML, CSS 的功能有很强的关系：**

* **HTML:**  测试用例通过 `SetBodyInnerHTML()` 函数设置不同的 HTML 结构。这些 HTML 结构定义了被测试的布局对象以及它们之间的父子关系。例如，`<div id='container'>...</div>` 创建了一个容器元素，其 ID 为 `container`，可以在后续的测试中被引用。

* **CSS:**  测试用例中使用了内联 CSS 样式来设置元素的布局属性，例如 `position`（relative, absolute, fixed）、`margin`、`border`、`padding`、`transform`、`overflow` 和 `columns` 等。这些 CSS 属性直接影响元素的最终位置和尺寸，从而影响坐标映射的结果。例如，`style='position:relative; left:7px; top:4px;'`  会使元素相对于其正常位置偏移。

* **JavaScript:**  虽然这个文件本身是 C++ 代码，用于测试 Blink 引擎的内部实现，但这些被测试的坐标映射功能是 JavaScript API 的基础。例如，JavaScript 中的 `element.getBoundingClientRect()` 方法依赖于这些底层的坐标映射机制来确定元素在视口中的位置和大小。  当 JavaScript 需要判断鼠标点击的位置是否在某个元素内部，或者需要将一个元素移动到另一个元素的相对位置时，都会用到这些坐标转换。

**逻辑推理的假设输入与输出举例：**

考虑 `TEST_F(MapCoordinatesTest, SimpleBlock)` 这个测试用例：

**假设输入:**

* **HTML:**
  ```html
  <div style='margin:666px; border:8px solid; padding:7px;'>
      <div id='target' style='margin:10px; border:666px; padding:666px;'></div>
  </div>
  ```
* **执行的映射操作:**  `MapLocalToAncestor(target, To<LayoutBoxModelObject>(target->Parent()), PhysicalOffset(100, 100))`

**逻辑推理:**

1. `target` 元素相对于其自身的内容边缘有一个局部坐标系。`PhysicalOffset(100, 100)` 指的是 `target` 元素自身坐标系下的 (100, 100) 这个点。
2. `target` 的父元素有一个边框 (border) 为 8px，内边距 (padding) 为 7px。
3. 因此，`target` 元素左上角的全局坐标相对于其父元素的**内容边缘**偏移了父元素的 `border-left` (8px) + `padding-left` (7px) + `target` 的 `margin-left` (10px) = 25px。垂直方向同理。
4. 所以，`target` 元素自身坐标系下的 (100, 100) 这个点，映射到其父元素的坐标系下，应该是 (100 + 25, 100 + 25) = (125, 125)。

**预期输出:**

* `EXPECT_EQ(PhysicalOffset(125, 125), mapped_point);`

**用户或者编程常见的使用错误举例：**

1. **忽略 `position: relative` 的影响:**  开发者可能认为 `position: relative` 不会影响坐标映射，但它会改变元素的定位上下文。例如，在一个 `position: relative` 的父元素内部，子元素的绝对定位是相对于父元素的内容边缘，而不是文档的初始包含块。`TEST_F(MapCoordinatesTest, TextInRelPosInline)` 和 `TEST_F(MapCoordinatesTest, RelposInline)` 等测试用例就是在验证这种情况下的坐标映射。

   **错误示例 (JavaScript):** 假设有一个 `position: relative` 的 div 容器和一个 `position: absolute` 的子元素，开发者错误地认为子元素的偏移是相对于文档左上角计算的，而没有考虑到父元素的偏移。

2. **混淆元素自身的坐标系和父元素的坐标系:**  开发者可能会忘记 `MapLocalToAncestor` 和 `MapAncestorToLocal` 方法需要在哪个坐标系下指定输入点。例如，在 `TEST_F(MapCoordinatesTest, SimpleInline)` 中，传递给 `MapLocalToAncestor` 的 `PhysicalOffset(10, 10)` 是 `target` 元素自身的局部坐标。

3. **没有考虑到 `transform` 属性:**  CSS 的 `transform` 属性可以改变元素的视觉位置，但不会改变其在普通布局流中的位置。进行坐标映射时，必须考虑 `transform` 的影响。虽然这个文件的第一部分没有直接展示 `transform` 的测试用例，但从引入的头文件 `transform_state.h` 可以推断后续部分会包含这方面的测试。

4. **忽略滚动的影响:**  在包含滚动条的元素中进行坐标映射时，需要考虑滚动的偏移量。`TEST_F(MapCoordinatesTest, OverflowClip)`  这个测试用例就演示了在 `overflow: scroll` 的情况下，坐标映射需要考虑滚动偏移。

**归纳一下它的功能 (第1部分):**

这部分代码主要定义了一个名为 `MapCoordinatesTest` 的 GTest 测试套件，并包含了多个针对基本 HTML 结构和简单 CSS 样式的坐标映射测试用例。这些测试用例涵盖了以下场景：

* **简单文本节点和块级元素的坐标映射。**
* **内联元素的坐标映射。**
* **设置了 `margin`、`border` 和 `padding` 的块级元素的坐标映射。**
* **包含 `overflow: scroll` 的容器中元素的坐标映射。**
* **`position: relative` 的内联元素及其包含的文本节点的坐标映射。**

总而言之，这部分是 `map_coordinates_test.cc` 的基础部分，旨在验证在一些最简单的布局场景下，Blink 的坐标映射功能是否能够正确工作，为后续更复杂的布局场景测试奠定基础。

### 提示词
```
这是目录为blink/renderer/core/layout/map_coordinates_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/layout/geometry/transform_state.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class MapCoordinatesTest : public RenderingTest {
 public:
  MapCoordinatesTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  void SetUp() override {
    // This is required to test 3d transforms.
    EnableCompositing();
    RenderingTest::SetUp();
  }

  PhysicalOffset MapLocalToAncestor(const LayoutObject*,
                                    const LayoutBoxModelObject* ancestor,
                                    PhysicalOffset,
                                    MapCoordinatesFlags = 0) const;
  gfx::QuadF MapLocalToAncestor(const LayoutObject*,
                                const LayoutBoxModelObject* ancestor,
                                gfx::QuadF,
                                MapCoordinatesFlags = 0) const;
  PhysicalOffset MapAncestorToLocal(const LayoutObject*,
                                    const LayoutBoxModelObject* ancestor,
                                    PhysicalOffset,
                                    MapCoordinatesFlags = 0) const;
  gfx::QuadF MapAncestorToLocal(const LayoutObject*,
                                const LayoutBoxModelObject* ancestor,
                                gfx::QuadF,
                                MapCoordinatesFlags = 0) const;

  // Adjust point by the scroll offset of the LayoutView.  This only has an
  // effect if root layer scrolling is enabled.  The only reason for doing
  // this here is so the test expected values can be the same whether or not
  // root layer scrolling is enabled.  This is analogous to what
  // LayoutGeometryMapTest does; for more context, see:
  // https://codereview.chromium.org/2417103002/#msg11
  PhysicalOffset AdjustForFrameScroll(const PhysicalOffset&) const;
};

// One note about tests here that operate on LayoutInline and LayoutText
// objects: mapLocalToAncestor() expects such objects to pass their static
// location and size (relatively to the border edge of their container) to
// mapLocalToAncestor() via the TransformState argument. mapLocalToAncestor() is
// then only expected to make adjustments for relative-positioning,
// container-specific characteristics (such as writing mode roots, multicol),
// and so on. This in contrast to LayoutBox objects, where the TransformState
// passed is relative to the box itself, not the container.

PhysicalOffset MapCoordinatesTest::AdjustForFrameScroll(
    const PhysicalOffset& point) const {
  PhysicalOffset result(point);
  LayoutView* layout_view = GetDocument().GetLayoutView();
  if (layout_view->IsScrollContainer())
    result -= PhysicalOffset(layout_view->ScrolledContentOffset());
  return result;
}

PhysicalOffset MapCoordinatesTest::MapLocalToAncestor(
    const LayoutObject* object,
    const LayoutBoxModelObject* ancestor,
    PhysicalOffset point,
    MapCoordinatesFlags mode) const {
  return object->LocalToAncestorPoint(point, ancestor, mode);
}

gfx::QuadF MapCoordinatesTest::MapLocalToAncestor(
    const LayoutObject* object,
    const LayoutBoxModelObject* ancestor,
    gfx::QuadF quad,
    MapCoordinatesFlags mode) const {
  return object->LocalToAncestorQuad(quad, ancestor, mode);
}

PhysicalOffset MapCoordinatesTest::MapAncestorToLocal(
    const LayoutObject* object,
    const LayoutBoxModelObject* ancestor,
    PhysicalOffset point,
    MapCoordinatesFlags mode) const {
  return object->AncestorToLocalPoint(ancestor, point, mode);
}

gfx::QuadF MapCoordinatesTest::MapAncestorToLocal(
    const LayoutObject* object,
    const LayoutBoxModelObject* ancestor,
    gfx::QuadF quad,
    MapCoordinatesFlags mode) const {
  return object->AncestorToLocalQuad(ancestor, quad, mode);
}

TEST_F(MapCoordinatesTest, SimpleText) {
  SetBodyInnerHTML("<div id='container'><br>text</div>");

  auto* container = GetLayoutBoxByElementId("container");
  LayoutObject* text = To<LayoutBlockFlow>(container)->LastChild();
  ASSERT_TRUE(text->IsText());
  PhysicalOffset mapped_point =
      MapLocalToAncestor(text, container, PhysicalOffset(10, 30));
  EXPECT_EQ(PhysicalOffset(10, 30), mapped_point);
  mapped_point = MapAncestorToLocal(text, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 30), mapped_point);
}

TEST_F(MapCoordinatesTest, SimpleInline) {
  SetBodyInnerHTML("<div><span id='target'>text</span></div>");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, To<LayoutBoxModelObject>(target->Parent()),
                         PhysicalOffset(10, 10));
  EXPECT_EQ(PhysicalOffset(10, 10), mapped_point);
  mapped_point = MapAncestorToLocal(
      target, To<LayoutBoxModelObject>(target->Parent()), mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 10), mapped_point);
}

TEST_F(MapCoordinatesTest, SimpleBlock) {
  SetBodyInnerHTML(R"HTML(
    <div style='margin:666px; border:8px solid; padding:7px;'>
        <div id='target' style='margin:10px; border:666px;
    padding:666px;'></div>
    </div>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, To<LayoutBoxModelObject>(target->Parent()),
                         PhysicalOffset(100, 100));
  EXPECT_EQ(PhysicalOffset(125, 125), mapped_point);
  mapped_point = MapAncestorToLocal(
      target, To<LayoutBoxModelObject>(target->Parent()), mapped_point);
  EXPECT_EQ(PhysicalOffset(100, 100), mapped_point);
}

TEST_F(MapCoordinatesTest, OverflowClip) {
  SetBodyInnerHTML(R"HTML(
    <div id='overflow' style='height: 100px; width: 100px; border:8px
    solid; padding:7px; overflow:scroll'>
        <div style='height:200px; width:200px'></div>
        <div id='target' style='margin:10px; border:666px;
    padding:666px;'></div>
    </div>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  LayoutObject* overflow = GetLayoutObjectByElementId("overflow");
  To<Element>(overflow->GetNode())
      ->GetLayoutBoxForScrolling()
      ->GetScrollableArea()
      ->ScrollToAbsolutePosition(gfx::PointF(32, 54));

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, To<LayoutBoxModelObject>(target->Parent()),
                         PhysicalOffset(100, 100));
  EXPECT_EQ(PhysicalOffset(93, 271), mapped_point);
  mapped_point = MapAncestorToLocal(
      target, To<LayoutBoxModelObject>(target->Parent()), mapped_point);
  EXPECT_EQ(PhysicalOffset(100, 100), mapped_point);
}

TEST_F(MapCoordinatesTest, TextInRelPosInline) {
  SetBodyInnerHTML(
      "<div><span style='position:relative; left:7px; top:4px;'><br "
      "id='sibling'>text</span></div>");

  LayoutObject* br = GetLayoutObjectByElementId("sibling");
  LayoutObject* text = br->NextSibling();
  ASSERT_TRUE(text->IsText());
  PhysicalOffset mapped_point =
      MapLocalToAncestor(text, text->ContainingBlock(), PhysicalOffset(10, 30));
  EXPECT_EQ(PhysicalOffset(10, 30), mapped_point);
  mapped_point =
      MapAncestorToLocal(text, text->ContainingBlock(), mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 30), mapped_point);
}

TEST_F(MapCoordinatesTest, RelposInline) {
  SetBodyInnerHTML(
      "<span id='target' style='position:relative; left:50px; "
      "top:100px;'>text</span>");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, To<LayoutBoxModelObject>(target->Parent()),
                         PhysicalOffset(10, 10));
  EXPECT_EQ(PhysicalOffset(10, 10), mapped_point);
  mapped_point = MapAncestorToLocal(
      target, To<LayoutBoxModelObject>(target->Parent()), mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 10), mapped_point);
}

TEST_F(MapCoordinatesTest, RelposInlineInRelposInline) {
  SetBodyInnerHTML(R"HTML(
    <div style='padding-left:10px;'>
        <span style='position:relative; left:5px; top:6px;'>
            <span id='target' style='position:relative; left:50px;
    top:100px;'>text</span>
        </span>
    </div>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  auto* parent = To<LayoutInline>(target->Parent());
  auto* containing_block = To<LayoutBlockFlow>(parent->Parent());

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, containing_block, PhysicalOffset(20, 10));
  EXPECT_EQ(PhysicalOffset(20, 10), mapped_point);
  mapped_point = MapAncestorToLocal(target, containing_block, mapped_point);
  EXPECT_EQ(PhysicalOffset(20, 10), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  mapped_point = MapLocalToAncestor(target, parent, PhysicalOffset(20, 10));
  EXPECT_EQ(PhysicalOffset(20, 10), mapped_point);

  mapped_point = MapLocalToAncestor(parent, containing_block, mapped_point);
  EXPECT_EQ(PhysicalOffset(20, 10), mapped_point);

  mapped_point = MapAncestorToLocal(parent, containing_block, mapped_point);
  EXPECT_EQ(PhysicalOffset(20, 10), mapped_point);

  mapped_point = MapAncestorToLocal(target, parent, mapped_point);
  EXPECT_EQ(PhysicalOffset(20, 10), mapped_point);
}

TEST_F(MapCoordinatesTest, RelPosBlock) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='margin:666px; border:8px solid;
    padding:7px;'>
        <div id='middle' style='margin:30px; border:1px solid;'>
            <div id='target' style='position:relative; left:50px; top:50px;
    margin:10px; border:666px; padding:666px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(106, 106), mapped_point);
  mapped_point =
      MapAncestorToLocal(target, container, PhysicalOffset(110, 110));
  EXPECT_EQ(PhysicalOffset(4, 4), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  auto* middle = GetLayoutBoxByElementId("middle");

  mapped_point = MapLocalToAncestor(target, middle, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(61, 61), mapped_point);

  mapped_point = MapLocalToAncestor(middle, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(106, 106), mapped_point);

  mapped_point = MapAncestorToLocal(middle, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(61, 61), mapped_point);

  mapped_point = MapAncestorToLocal(target, middle, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, AbsPos) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position:relative; margin:666px; border:8px
    solid; padding:7px;'>
        <div id='staticChild' style='margin:30px; padding-top:666px;'>
            <div style='padding-top:666px;'></div>
            <div id='target' style='position:absolute; left:-1px; top:-1px;
    margin:10px; border:666px; padding:666px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(17, 17), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, PhysicalOffset(18, 18));
  EXPECT_EQ(PhysicalOffset(1, 1), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  auto* static_child = GetLayoutBoxByElementId("staticChild");

  mapped_point = MapLocalToAncestor(target, static_child, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(-28, -28), mapped_point);

  mapped_point = MapLocalToAncestor(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(17, 17), mapped_point);

  mapped_point = MapAncestorToLocal(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(-28, -28), mapped_point);

  mapped_point = MapAncestorToLocal(target, static_child, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, AbsPosAuto) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position:absolute; margin:666px; border:8px
    solid; padding:7px;'>
        <div id='staticChild' style='margin:30px; padding-top:5px;'>
            <div style='padding-top:20px;'></div>
            <div id='target' style='position:absolute; margin:10px;
    border:666px; padding:666px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(55, 80), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, PhysicalOffset(56, 82));
  EXPECT_EQ(PhysicalOffset(1, 2), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  auto* static_child = GetLayoutBoxByElementId("staticChild");

  mapped_point = MapLocalToAncestor(target, static_child, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(10, 35), mapped_point);

  mapped_point = MapLocalToAncestor(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(55, 80), mapped_point);

  mapped_point = MapAncestorToLocal(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 35), mapped_point);

  mapped_point = MapAncestorToLocal(target, static_child, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, FixedPos) {
  // Assuming BODY margin of 8px.
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position:absolute; margin:4px; border:5px
    solid; padding:7px;'>
        <div id='staticChild' style='padding-top:666px;'>
            <div style='padding-top:666px;'></div>
            <div id='target' style='position:fixed; left:-1px; top:-1px;
    margin:10px; border:666px; padding:666px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* static_child = GetLayoutBoxByElementId("staticChild");
  auto* container = GetLayoutBoxByElementId("container");
  LayoutBox* body = container->ParentBox();
  LayoutBox* html = body->ParentBox();
  LayoutBox* view = html->ParentBox();
  ASSERT_TRUE(IsA<LayoutView>(view));

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, view, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(9, 9), mapped_point);
  mapped_point = MapAncestorToLocal(target, view, PhysicalOffset(10, 11));
  EXPECT_EQ(PhysicalOffset(1, 2), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  mapped_point = MapLocalToAncestor(target, static_child, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(-15, -15), mapped_point);

  mapped_point = MapLocalToAncestor(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(-3, -3), mapped_point);

  mapped_point = MapLocalToAncestor(container, body, mapped_point);
  EXPECT_EQ(PhysicalOffset(1, 1), mapped_point);

  mapped_point = MapLocalToAncestor(body, html, mapped_point);
  EXPECT_EQ(PhysicalOffset(9, 9), mapped_point);

  mapped_point = MapLocalToAncestor(html, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(9, 9), mapped_point);

  mapped_point = MapAncestorToLocal(html, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(9, 9), mapped_point);

  mapped_point = MapAncestorToLocal(body, html, mapped_point);
  EXPECT_EQ(PhysicalOffset(1, 1), mapped_point);

  mapped_point = MapAncestorToLocal(container, body, mapped_point);
  EXPECT_EQ(PhysicalOffset(-3, -3), mapped_point);

  mapped_point = MapAncestorToLocal(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(-15, -15), mapped_point);

  mapped_point = MapAncestorToLocal(target, static_child, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, FixedPosAuto) {
  // Assuming BODY margin of 8px.
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position:absolute; margin:3px; border:8px
    solid; padding:7px;'>
        <div id='staticChild' style='padding-top:5px;'>
            <div style='padding-top:20px;'></div>
            <div id='target' style='position:fixed; margin:10px;
    border:666px; padding:666px;'></div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* static_child = GetLayoutBoxByElementId("staticChild");
  auto* container = GetLayoutBoxByElementId("container");
  LayoutBox* body = container->ParentBox();
  LayoutBox* html = body->ParentBox();
  LayoutBox* view = html->ParentBox();
  ASSERT_TRUE(IsA<LayoutView>(view));

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, target->ContainingBlock(), PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(36, 61), mapped_point);
  mapped_point = MapAncestorToLocal(target, target->ContainingBlock(),
                                    PhysicalOffset(36, 61));
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  mapped_point = MapLocalToAncestor(target, static_child, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(10, 35), mapped_point);

  mapped_point = MapLocalToAncestor(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(25, 50), mapped_point);

  mapped_point = MapLocalToAncestor(container, body, mapped_point);
  EXPECT_EQ(PhysicalOffset(28, 53), mapped_point);

  mapped_point = MapLocalToAncestor(body, html, mapped_point);
  EXPECT_EQ(PhysicalOffset(36, 61), mapped_point);

  mapped_point = MapLocalToAncestor(html, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(36, 61), mapped_point);

  mapped_point = MapAncestorToLocal(html, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(36, 61), mapped_point);

  mapped_point = MapAncestorToLocal(body, html, mapped_point);
  EXPECT_EQ(PhysicalOffset(28, 53), mapped_point);

  mapped_point = MapAncestorToLocal(container, body, mapped_point);
  EXPECT_EQ(PhysicalOffset(25, 50), mapped_point);

  mapped_point = MapAncestorToLocal(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(10, 35), mapped_point);

  mapped_point = MapAncestorToLocal(target, static_child, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, FixedPosInFixedPos) {
  // Assuming BODY margin of 8px.
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position:absolute; margin:4px; border:5px
    solid; padding:7px;'>
        <div id='staticChild' style='padding-top:666px;'>
            <div style='padding-top:666px;'></div>
            <div id='outerFixed' style='position:fixed; left:100px;
    top:100px; margin:10px; border:666px; padding:666px;'>
                <div id='target' style='position:fixed; left:-1px;
    top:-1px; margin:10px; border:666px; padding:666px;'></div>
            </div>
        </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* outer_fixed = GetLayoutBoxByElementId("outerFixed");
  auto* static_child = GetLayoutBoxByElementId("staticChild");
  auto* container = GetLayoutBoxByElementId("container");
  LayoutBox* body = container->ParentBox();
  LayoutBox* html = body->ParentBox();
  LayoutBox* view = html->ParentBox();
  ASSERT_TRUE(IsA<LayoutView>(view));

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, view, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(9, 9), mapped_point);
  mapped_point = MapAncestorToLocal(target, view, PhysicalOffset(9, 9));
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  // Walk each ancestor in the chain separately, to verify each step on the way.
  mapped_point = MapLocalToAncestor(target, outer_fixed, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(-101, -101), mapped_point);

  mapped_point = MapLocalToAncestor(outer_fixed, static_child, mapped_point);
  EXPECT_EQ(PhysicalOffset(-15, -15), mapped_point);

  mapped_point = MapLocalToAncestor(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(-3, -3), mapped_point);

  mapped_point = MapLocalToAncestor(container, body, mapped_point);
  EXPECT_EQ(PhysicalOffset(1, 1), mapped_point);

  mapped_point = MapLocalToAncestor(body, html, mapped_point);
  EXPECT_EQ(PhysicalOffset(9, 9), mapped_point);

  mapped_point = MapLocalToAncestor(html, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(9, 9), mapped_point);

  mapped_point = MapAncestorToLocal(html, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(9, 9), mapped_point);

  mapped_point = MapAncestorToLocal(body, html, mapped_point);
  EXPECT_EQ(PhysicalOffset(1, 1), mapped_point);

  mapped_point = MapAncestorToLocal(container, body, mapped_point);
  EXPECT_EQ(PhysicalOffset(-3, -3), mapped_point);

  mapped_point = MapAncestorToLocal(static_child, container, mapped_point);
  EXPECT_EQ(PhysicalOffset(-15, -15), mapped_point);

  mapped_point = MapAncestorToLocal(outer_fixed, static_child, mapped_point);
  EXPECT_EQ(PhysicalOffset(-101, -101), mapped_point);

  mapped_point = MapAncestorToLocal(target, outer_fixed, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, FixedPosInFixedPosScrollView) {
  SetBodyInnerHTML(R"HTML(
    <div style='height: 4000px'></div>
    <div id='container' style='position:fixed; top: 100px; left: 100px'>
      <div id='target' style='position:fixed; top: 200px; left: 200px'>
      </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");
  LayoutBox* body = container->ParentBox();
  LayoutBox* html = body->ParentBox();
  LayoutBox* view = html->ParentBox();
  ASSERT_TRUE(IsA<LayoutView>(view));

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0.0, 50), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(50, GetDocument().View()->LayoutViewport()->ScrollOffsetInt().y());

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, view, PhysicalOffset());
  EXPECT_EQ(AdjustForFrameScroll(PhysicalOffset(200, 250)), mapped_point);
  mapped_point = MapAncestorToLocal(target, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point = MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(100, 100), mapped_point);
  mapped_point =
      MapAncestorToLocal(target, container, PhysicalOffset(100, 100));
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, FixedPosInAbsolutePosScrollView) {
  SetBodyInnerHTML(R"HTML(
    <div style='height: 4000px'></div>
    <div id='container' style='position:absolute; top: 100px; left: 100px'>
      <div id='target' style='position:fixed; top: 200px; left: 200px'>
      </div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");
  LayoutBox* body = container->ParentBox();
  LayoutBox* html = body->ParentBox();
  LayoutBox* view = html->ParentBox();
  ASSERT_TRUE(IsA<LayoutView>(view));

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0.0, 50), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(50, GetDocument().View()->LayoutViewport()->ScrollOffsetInt().y());

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, view, PhysicalOffset());
  EXPECT_EQ(AdjustForFrameScroll(PhysicalOffset(200, 250)), mapped_point);
  mapped_point = MapAncestorToLocal(target, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point = MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(100, 150), mapped_point);
  mapped_point =
      MapAncestorToLocal(target, container, PhysicalOffset(100, 150));
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, FixedPosInTransform) {
  SetBodyInnerHTML(R"HTML(
    <style>#container { transform: translateY(100px); position: absolute;
    left: 0; top: 100px; }
    .fixed { position: fixed; top: 0; }
    .spacer { height: 2000px; } </style>
    <div id='container'><div class='fixed' id='target'></div></div>
    <div class='spacer'></div>
  )HTML");

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0.0, 50), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(50, GetDocument().View()->LayoutViewport()->ScrollOffsetInt().y());

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");
  LayoutBox* body = container->ParentBox();
  LayoutBox* html = body->ParentBox();
  LayoutBox* view = html->ParentBox();
  ASSERT_TRUE(IsA<LayoutView>(view));

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, view, PhysicalOffset());
  EXPECT_EQ(AdjustForFrameScroll(PhysicalOffset(0, 200)), mapped_point);
  mapped_point = MapAncestorToLocal(target, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point = MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, PhysicalOffset(0, 0));
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point = MapLocalToAncestor(container, view, PhysicalOffset());
  EXPECT_EQ(AdjustForFrameScroll(PhysicalOffset(0, 200)), mapped_point);
  mapped_point = MapAncestorToLocal(container, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

TEST_F(MapCoordinatesTest, FixedPosInContainPaint) {
  SetBodyInnerHTML(R"HTML(
    <style>#container { contain: paint; position: absolute; left: 0; top:
    100px; }
    .fixed { position: fixed; top: 0; }
    .spacer { height: 2000px; } </style>
    <div id='container'><div class='fixed' id='target'></div></div>
    <div class='spacer'></div>
  )HTML");

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0.0, 50), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(50, GetDocument().View()->LayoutViewport()->ScrollOffsetInt().y());

  auto* target = GetLayoutBoxByElementId("target");
  auto* container = GetLayoutBoxByElementId("container");
  LayoutBox* body = container->ParentBox();
  LayoutBox* html = body->ParentBox();
  LayoutBox* view = html->ParentBox();
  ASSERT_TRUE(IsA<LayoutView>(view));

  PhysicalOffset mapped_point =
      MapLocalToAncestor(target, view, PhysicalOffset());
  EXPECT_EQ(AdjustForFrameScroll(PhysicalOffset(0, 100)), mapped_point);
  mapped_point = MapAncestorToLocal(target, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point = MapLocalToAncestor(target, container, PhysicalOffset());
  EXPECT_EQ(PhysicalOffset(0, 0), mapped_point);
  mapped_point = MapAncestorToLocal(target, container, PhysicalOffset(0, 0));
  EXPECT_EQ(PhysicalOffset(), mapped_point);

  mapped_point = MapLocalToAncestor(container, view, PhysicalOffset());
  EXPECT_EQ(AdjustForFrameScroll(PhysicalOffset(0, 100)), mapped_point);
  mapped_point = MapAncestorToLocal(container, view, mapped_point);
  EXPECT_EQ(PhysicalOffset(), mapped_point);
}

// TODO(chrishtr): add more multi-frame tests.
TEST_F(MapCoordinatesTest, FixedPosInIFrameWhenMainFrameScrolled) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div style='width: 200; height: 8000px'></div>
    <iframe src='http://test.com' width='500' height='500'
    frameBorder='0'>
    </iframe>
  )HTML");
  SetChildFrameHTML(
      "<style>body { margin: 0; } #target { width: 200px; height: 200px; "
      "position:fixed}</style><div id=target></div>");

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0.0, 1000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  Element* target = ChildDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  PhysicalOffset mapped_point =
      MapAncestorToLocal(target->GetLayoutObject(), nullptr,
                         PhysicalOffset(10, 70), kTraverseDocumentBoundaries);

  // y = 70 - 8000, since the iframe is offset by 8000px from the main frame.
  // The scroll is not taken into account because the element is not fixed to
  // the root LayoutView, and the space of the root LayoutView does not include
  // scroll.
  EXPECT_EQ(PhysicalOffset(10, -7930), AdjustForFrameScroll(mapped_point));
}

TEST_F(MapCoordinatesTest, IFrameTransformed) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <iframe style='transform: scale(2)' src='http://test.com'
    width='500' height='500' frameBorder='0'>
    </iframe>
  )HTML");
  SetChildFrameHTML(
      "<style>body { margin: 0; } #target { width: 200px; "
      "height: 8000px}</style><div id=target></div>");

  UpdateAllLifecyclePhasesForTest();

  ChildDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0.0, 1000), mojom::blink::ScrollType::kProgrammatic);
  ChildDocument().View()->UpdateAllLifecyclePhasesForTest();

  Element* target = ChildDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  PhysicalOffset mapped_point =
      MapAncestorToLocal(target->GetLayoutObject(), nullptr,
                         PhysicalOffset(200, 200), kTraverseDocumentBoundaries);

  // Derivation:
  // (200, 200) -> (-50, -50)  (Adjust for transform origin of scale, which is
  //                           at the center of the 500x500 iframe)
  // (-50, -50) -> (-25, -25)  (Divide by 2 to invert the scale)
  // (-25, -25) -> (225, 225)  (Add the origin back in)
  // (225, 225) -> (225, 1225) (Adjust by scroll offset of y=1000)
  EXPECT_EQ(PhysicalOffset(225, 1225), mapped_point);
}

TEST_F(MapCoordinatesTest, FixedPosInScrolledIFrameWithTransform) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>* { margin: 0; }</style>
    <div style='position: absolute; left: 0px; top: 0px; width: 1024px;
    height: 768px; transform-origin: 0 0; transform: scale(0.5, 0.5);'>
        <iframe frameborder=0 src='http://test.com'
    sandbox='allow-same-origin' width='1024' height='768'></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>* { margin: 0; } #target { width: 200px; height: 200px;
    position:fixed}</style><div id=target></div>
    <div style='width: 200; height: 8000px'></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  ChildDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0.0, 1000), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  Element* target = ChildDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  PhysicalOffset mapped_point =
      MapAncestorToLocal(target->GetLayoutObject(), nullptr,
                         PhysicalOffset(0, 0), kTraverseDocumentBoundaries);

  EXPECT_EQ(PhysicalOffset(0, 0), mapped_point);
}

TEST_F(MapCoordinatesTest, MulticolWithText) {
  SetBodyInnerHTML(R"HTML(
    <div id='multicol' style='columns:2; column-gap:20px; width:400px;
    line-height:50px; padding:5px; orphans:1; widows:1;'>
        <br id='sibling'>
        text
    </div>
  )HTML");

  auto* const multicol =
      To<LayoutBlockFlow>(GetLayoutBoxByElementId("multicol"));
  LayoutObject* target = GetLayoutObjectByElementId("sibling")->NextSibling();
  ASSERT_TRUE(target->IsText());
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

TEST_F(MapCoordinatesTest, MulticolWithInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='multicol
```