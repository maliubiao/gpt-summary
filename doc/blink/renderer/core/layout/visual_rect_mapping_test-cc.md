Response:
The user wants to understand the functionality of the `visual_rect_mapping_test.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose of the test file.**  Based on the name and included headers, it's likely testing how layout objects map their bounding boxes (rects) to different coordinate spaces, especially in the context of visual representation.
2. **Explain the relationship to web technologies (JavaScript, HTML, CSS).**  Visual rect mapping is crucial for features like hit testing, element positioning, and understanding the visual layout defined by HTML and CSS. JavaScript can trigger layout changes, making these mappings dynamic.
3. **Provide examples of logical reasoning with input and output.** This will involve scenarios where transformations, scrolling, or other layout properties affect how rects are mapped.
4. **Illustrate common usage errors.** These might involve incorrect assumptions about coordinate systems or how different layout properties interact.
5. **Summarize the file's overall function.**

Let's break down each of these points based on the provided code:

* **Core Purpose:** The file contains a series of tests (`TEST_P`) within the `VisualRectMappingTest` class. These tests use functions like `MapToVisualRectInAncestorSpace` to verify the correctness of rect transformations between layout objects. The inclusion of `GeometryMapper` suggests testing optimized mapping strategies.

* **Relationship to Web Technologies:**
    * **HTML:** The tests manipulate the DOM structure using `SetBodyInnerHTML`, creating elements like `div`, `span`, `img`, and `iframe`. The layout of these elements is governed by HTML.
    * **CSS:**  The tests extensively use inline styles (`style='...'`) to define properties like `margin`, `overflow`, `width`, `height`, `writing-mode`, `box-shadow`, `position`, `opacity`, `will-change`, etc. These CSS properties directly influence the layout and visual representation, which is what the rect mapping tests are verifying.
    * **JavaScript:** While not explicitly present in the provided code snippet, JavaScript would be the primary way to interact with and dynamically modify the layout that these tests are exercising. For example, JavaScript could change element styles or scroll positions.

* **Logical Reasoning Examples:**
    * **Scenario:** A `div` with `overflow: scroll` and a child element. When the scroll position changes, the visual rect of the child relative to the parent will also change.
    * **Input:**  A child element's local rect, the parent `div` layout object, the parent's scroll position.
    * **Output:** The visual rect of the child in the parent's coordinate space after applying the scroll offset.

* **Common Usage Errors:**
    * **Incorrectly assuming local coordinates are the same as visual coordinates.**  The tests highlight that `LayoutText`'s "local coordinate space" is different.
    * **Not considering transformations or writing modes.**  The tests specifically cover `writing-mode` to demonstrate its impact on rect mapping.
    * **Ignoring the effect of `overflow` properties.**  The tests for `overflow: scroll` and `overflow: hidden` show how clipping affects the visual rect.

* **Summary:** The `visual_rect_mapping_test.cc` file is designed to thoroughly test the `MapToVisualRectInAncestorSpace` function and related mechanisms within the Blink layout engine. It ensures that layout objects can correctly determine their visual bounding boxes in different coordinate spaces, accounting for various CSS properties and layout scenarios. This is critical for accurate rendering and interaction within a web page.
这是 `blink/renderer/core/layout/visual_rect_mapping_test.cc` 文件的第一部分，其主要功能是**测试 Blink 渲染引擎中布局对象的可视矩形映射功能**。

更具体地说，这个文件测试了 `LayoutObject` 类及其子类中的 `MapToVisualRectInAncestorSpace` 方法。这个方法用于将一个局部坐标系下的矩形（`PhysicalRect`）映射到其祖先元素的坐标系下，得到其在祖先元素中的可视位置和大小。

以下是该文件功能的详细归纳：

**核心功能:**

* **测试 `MapToVisualRectInAncestorSpace` 方法:**  这是测试的重点，验证该方法在各种布局场景下是否能正确计算出目标矩形在祖先元素坐标系下的可视矩形。
* **覆盖多种布局对象:**  测试涵盖了 `LayoutText`, `LayoutInline`, `LayoutView` (iframe 的内容), `LayoutBlock` 等不同的布局对象，确保映射功能对各种类型的元素都适用。
* **模拟多种 CSS 属性的影响:**  测试用例考虑了 `overflow`, `writing-mode`, `position`, `box-shadow`, `border`, `opacity`, `will-change` 等 CSS 属性对可视矩形映射的影响。
* **处理滚动情况:**  测试了在容器设置了 `overflow: scroll` 时，滚动偏移如何影响子元素的可视矩形映射。
* **测试不同的书写模式 (`writing-mode`):**  测试了容器和目标元素具有相同或不同的书写模式时，矩形映射的正确性。
* **验证几何映射器 (`GeometryMapper`):**  代码中使用了 `kUseGeometryMapper` 标志，表明测试也包含了对使用几何映射器进行优化的矩形映射路径的验证。
* **测试 `PaintInvalidationVisualRect` 功能:**  虽然主要关注矩形映射，但测试用例也间接验证了计算出的可视矩形是否能正确用于后续的重绘失效（paint invalidation）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  测试用例通过 `SetBodyInnerHTML` 设置 HTML 结构，创建各种包含不同元素的布局场景，例如 `div`, `span`, `img`, `iframe`。
    ```html
    <div id='container' style='overflow: scroll; width: 50px; height: 50px'>
      <span><img style='width: 20px; height: 100px'></span>
      <span id='leaf'></span>
    </div>
    ```
    在这个例子中，HTML 结构定义了容器 `div` 和内部的 `span` 以及 `img` 元素，它们的布局将影响后续的可视矩形映射。

* **CSS:**  测试用例大量使用内联样式来控制元素的布局和视觉属性。这些 CSS 属性直接影响 `MapToVisualRectInAncestorSpace` 的计算结果。
    * **`overflow: scroll`:**  影响子元素在父元素中的可视区域，滚动后可视矩形会发生变化。
        ```html
        <div id='container' style='overflow: scroll; width: 50px; height: 50px'>...</div>
        ```
    * **`writing-mode: vertical-rl`:**  改变元素的书写方向，会影响坐标系的转换和矩形映射。
        ```html
        <div id='container' style='writing-mode: vertical-rl; ...'>...</div>
        ```
    * **`position: absolute`:**  绝对定位的元素相对于其包含块进行定位，影响其在父元素中的可视位置。
        ```html
        <div id='absolute' style='position: absolute; top: 111px; left: 222px; ...'></div>
        ```
    * **`box-shadow`:**  阴影会扩展元素的可视边界，因此在计算可视矩形时需要考虑阴影的偏移。
        ```html
        <div id='target' style='box-shadow: 40px 20px black; ...'></div>
        ```

* **JavaScript:** 虽然这段代码没有直接涉及 JavaScript，但 `visual_rect_mapping_test.cc` 测试的是 Blink 引擎的核心布局功能，这些功能为 JavaScript 操作 DOM 和获取元素位置信息提供了基础。例如，JavaScript 可以通过 `getBoundingClientRect()` 方法获取元素在视口中的位置，而这个方法的底层实现就依赖于类似的矩形映射机制。

**逻辑推理的假设输入与输出示例:**

假设有以下 HTML 和 CSS：

```html
<div id='container' style='position: absolute; top: 100px; left: 50px; width: 200px; height: 100px; overflow: scroll;'>
  <div id='target' style='width: 150px; height: 80px; margin-top: 20px; margin-left: 10px;'></div>
</div>
```

并且容器 `container` 的滚动位置为 `scrollTop: 10px`, `scrollLeft: 5px`。

**假设输入:**

* 目标对象: `target` 的布局对象
* 祖先对象: `container` 的布局对象
* 目标对象的局部矩形 (相对自身): `PhysicalRect(0, 0, 150, 80)` （假设取的是内容区域）

**逻辑推理:**

1. `target` 相对于 `container` 的初始位置是 `(10, 20)` (考虑了 margin)。
2. 由于 `container` 存在滚动，需要减去滚动偏移。
3. 可视矩形的 x 坐标: `10 - 5 = 5`
4. 可视矩形的 y 坐标: `20 - 10 = 10`

**预期输出:**

调用 `target->MapToVisualRectInAncestorSpace(container, local_rect)` 后，`local_rect` 的值应变为 `PhysicalRect(5, 10, 150, 80)`。

**用户或编程常见的使用错误示例:**

* **错误地假设局部坐标就是相对于父元素的坐标:**  开发者可能会忘记考虑父元素的 `padding`, `border`, `transform`, `scroll` 等属性对子元素位置的影响，直接使用子元素的局部坐标进行计算。
* **在滚动容器中计算子元素位置时，忘记减去滚动偏移:**  在 `overflow: scroll` 的容器中，子元素的视觉位置会受到滚动的影响，如果没有考虑滚动偏移，计算出的位置会不准确。
* **忽略 `writing-mode` 对坐标系的影响:**  在垂直书写模式下，元素的物理尺寸和逻辑尺寸会发生互换，如果按照水平书写模式的逻辑进行坐标计算，会导致错误。
* **没有考虑到 `transform` 属性:**  如果祖先元素应用了 `transform` 属性，会改变其坐标系，子元素的视觉位置需要进行相应的变换。

**总结:**

`visual_rect_mapping_test.cc` 的第一部分集中测试了 Blink 渲染引擎中布局对象将自身局部矩形映射到祖先元素坐标系的能力。它通过构建各种 HTML 结构和应用不同的 CSS 属性，模拟了复杂的布局场景，并验证了 `MapToVisualRectInAncestorSpace` 方法在这些场景下的正确性。这对于确保浏览器能够准确地计算元素在页面上的视觉位置至关重要，并为 JavaScript 提供的各种位置相关的 API 奠定了基础。

### 提示词
```
这是目录为blink/renderer/core/layout/visual_rect_mapping_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/paint_property_tree_printer.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

inline PaintLayerScrollableArea* GetScrollableArea(
    const LayoutBlock* container) {
  return To<Element>(container->GetNode())
      ->GetLayoutBoxForScrolling()
      ->GetScrollableArea();
}

}  // namespace

class VisualRectMappingTest : public PaintTestConfigurations,
                              public RenderingTest {
 public:
  VisualRectMappingTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

 protected:
  enum Flags { kContainsToEnclosingRect = 1 << 0 };

  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }

  LayoutView& GetLayoutView() const { return *GetDocument().GetLayoutView(); }

  void CheckPaintInvalidationVisualRect(
      const LayoutObject& object,
      const LayoutBoxModelObject& ancestor,
      const PhysicalRect& expected_visual_rect_in_ancestor) {
    CheckVisualRect(object, ancestor, LocalVisualRect(object),
                    expected_visual_rect_in_ancestor);
  }

  void CheckVisualRect(const LayoutObject& object,
                       const LayoutBoxModelObject& ancestor,
                       const PhysicalRect& local_rect,
                       const PhysicalRect& expected_visual_rect_in_ancestor,
                       unsigned flags = 0) {
    auto slow_map_rect = local_rect;
    object.MapToVisualRectInAncestorSpace(&ancestor, slow_map_rect);

    FloatClipRect geometry_mapper_rect((gfx::RectF(local_rect)));
    const FragmentData& fragment_data = object.FirstFragment();
    if (fragment_data.HasLocalBorderBoxProperties()) {
      auto local_rect_copy = local_rect;
      object.MapToVisualRectInAncestorSpace(&ancestor, local_rect_copy,
                                            kUseGeometryMapper);
      geometry_mapper_rect.SetRect(gfx::RectF(local_rect_copy));
    }

    if (expected_visual_rect_in_ancestor.IsEmpty()) {
      EXPECT_TRUE(slow_map_rect.IsEmpty());
      if (fragment_data.HasLocalBorderBoxProperties())
        EXPECT_TRUE(geometry_mapper_rect.Rect().IsEmpty());
      return;
    }

    if (flags & kContainsToEnclosingRect) {
      EXPECT_TRUE(
          ToEnclosingRect(slow_map_rect)
              .Contains(ToEnclosingRect(expected_visual_rect_in_ancestor)));

      if (object.FirstFragment().HasLocalBorderBoxProperties()) {
        EXPECT_TRUE(
            gfx::ToEnclosingRect(geometry_mapper_rect.Rect())
                .Contains(ToEnclosingRect(expected_visual_rect_in_ancestor)));
      }
    } else {
      EXPECT_EQ(expected_visual_rect_in_ancestor, slow_map_rect);
      if (object.FirstFragment().HasLocalBorderBoxProperties()) {
        EXPECT_EQ(expected_visual_rect_in_ancestor,
                  PhysicalRect::EnclosingRect(geometry_mapper_rect.Rect()));
      }
    }
  }

  // Checks the result of MapToVisualRectInAncestorSpace with and without
  // geometry mapper.
  void CheckMapToVisualRectInAncestorSpace(const PhysicalRect& rect,
                                           const PhysicalRect& expected,
                                           const LayoutObject* object,
                                           const LayoutBoxModelObject* ancestor,
                                           VisualRectFlags flags,
                                           bool expected_retval) {
    PhysicalRect result = rect;
    EXPECT_EQ(expected_retval,
              object->MapToVisualRectInAncestorSpace(ancestor, result, flags));
    EXPECT_EQ(result, expected);
    result = rect;
    EXPECT_EQ(expected_retval,
              object->MapToVisualRectInAncestorSpace(
                  ancestor, result,
                  static_cast<VisualRectFlags>(flags | kUseGeometryMapper)));
    EXPECT_EQ(result, expected);
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(VisualRectMappingTest);

TEST_P(VisualRectMappingTest, LayoutText) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='container' style='vertical-align: bottom; overflow: scroll;
        width: 50px; height: 50px'>
      <span><img style='width: 20px; height: 100px'></span>
      <span id='text'>text text text text text text text</span>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* text = GetLayoutObjectByElementId("text")->SlowFirstChild();

  auto* scrollable_area = GetScrollableArea(container);
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  UpdateAllLifecyclePhasesForTest();

  PhysicalRect original_rect(0, 60, 20, 80);
  PhysicalRect rect = original_rect;
  // For a LayoutText, the "local coordinate space" is actually the contents
  // coordinate space of the containing block, so the following mappings are
  // only affected by the geometry of the container, not related to where the
  // text is laid out.
  EXPECT_TRUE(text->MapToVisualRectInAncestorSpace(container, rect));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 20, 80));

  rect = original_rect;
  EXPECT_TRUE(text->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 20, 40));

  rect = PhysicalRect(0, 60, 80, 0);
  EXPECT_TRUE(
      text->MapToVisualRectInAncestorSpace(container, rect, kEdgeInclusive));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 80, 0));
}

TEST_P(VisualRectMappingTest, LayoutTextContainerFlippedWritingMode) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='container' style='vertical-align: bottom; overflow: scroll;
        width: 50px; height: 50px; writing-mode: vertical-rl'>
      <span><img style='width: 20px; height: 100px'></span>
      <span id='text'>text text text text text text text</span>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* text = GetLayoutObjectByElementId("text")->SlowFirstChild();

  auto* scrollable_area = GetScrollableArea(container);
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  UpdateAllLifecyclePhasesForTest();

  // All results are the same as VisualRectMappingTest.LayoutText because all
  // rects are in physical coordinates of the container's contents space.
  PhysicalRect original_rect(0, 60, 20, 80);
  PhysicalRect rect = original_rect;
  EXPECT_TRUE(text->MapToVisualRectInAncestorSpace(container, rect));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 20, 80));

  rect = original_rect;
  EXPECT_TRUE(text->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 20, 40));

  rect = PhysicalRect(0, 60, 80, 0);
  EXPECT_TRUE(
      text->MapToVisualRectInAncestorSpace(container, rect, kEdgeInclusive));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 80, 0));
}

TEST_P(VisualRectMappingTest, LayoutInline) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='container' style='overflow: scroll; width: 50px; height: 50px'>
      <span><img style='width: 20px; height: 100px'></span>
      <span id='leaf'></span>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  LayoutObject* leaf = container->LastChild();

  auto* scrollable_area = GetScrollableArea(container);
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  UpdateAllLifecyclePhasesForTest();

  PhysicalRect original_rect(0, 60, 20, 80);
  PhysicalRect rect = original_rect;
  EXPECT_TRUE(leaf->MapToVisualRectInAncestorSpace(container, rect));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 20, 80));

  rect = original_rect;
  EXPECT_TRUE(leaf->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 20, 40));

  // The span is empty.
  CheckPaintInvalidationVisualRect(*leaf, GetLayoutView(), PhysicalRect());

  rect = PhysicalRect(0, 60, 80, 0);
  EXPECT_TRUE(
      leaf->MapToVisualRectInAncestorSpace(container, rect, kEdgeInclusive));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 80, 0));
}

TEST_P(VisualRectMappingTest, LayoutInlineContainerFlippedWritingMode) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='container' style='overflow: scroll; width: 50px; height: 50px;
        writing-mode: vertical-rl'>
      <span><img style='width: 20px; height: 100px'></span>
      <span id='leaf'></span>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  LayoutObject* leaf = container->LastChild();

  auto* scrollable_area = GetScrollableArea(container);
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  UpdateAllLifecyclePhasesForTest();

  // All results are the same as VisualRectMappingTest.LayoutInline because all
  // rects are in physical coordinates.
  PhysicalRect original_rect(0, 60, 20, 80);
  PhysicalRect rect = original_rect;
  EXPECT_TRUE(leaf->MapToVisualRectInAncestorSpace(container, rect));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 20, 80));

  rect = original_rect;
  EXPECT_TRUE(leaf->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 20, 40));

  // The span is empty.
  CheckPaintInvalidationVisualRect(*leaf, GetLayoutView(), PhysicalRect());

  rect = PhysicalRect(0, 60, 80, 0);
  EXPECT_TRUE(
      leaf->MapToVisualRectInAncestorSpace(container, rect, kEdgeInclusive));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  EXPECT_EQ(rect, PhysicalRect(0, 10, 80, 0));
}

TEST_P(VisualRectMappingTest, LayoutView) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id=frameContainer>
      <iframe src='http://test.com' width='50' height='50'
          frameBorder='0'></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(
      "<style>body { margin: 0; }</style>"
      "<span><img style='width: 20px; height: 100px'></span>text text text");
  UpdateAllLifecyclePhasesForTest();

  auto* frame_container =
      To<LayoutBlock>(GetLayoutObjectByElementId("frameContainer"));
  auto* frame_body = To<LayoutBlock>(ChildDocument().body()->GetLayoutObject());
  auto* frame_text = To<LayoutText>(frame_body->LastChild());

  // This case involves clipping: frame height is 50, y-coordinate of result
  // rect is 13, so height should be clipped to (50 - 13) == 37.
  ChildDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 47), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  PhysicalRect original_rect(4, 60, 20, 80);
  PhysicalRect rect = original_rect;
  EXPECT_TRUE(
      frame_text->MapToVisualRectInAncestorSpace(frame_container, rect));
  EXPECT_EQ(rect, PhysicalRect(4, 13, 20, 37));

  rect = original_rect;
  EXPECT_TRUE(
      frame_text->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(rect, PhysicalRect(4, 13, 20, 37));

  CheckPaintInvalidationVisualRect(*frame_text, GetLayoutView(),
                                   PhysicalRect());

  rect = PhysicalRect(4, 60, 0, 80);
  EXPECT_TRUE(frame_text->MapToVisualRectInAncestorSpace(frame_container, rect,
                                                         kEdgeInclusive));
  EXPECT_EQ(rect, PhysicalRect(4, 13, 0, 37));
}

TEST_P(VisualRectMappingTest, LayoutViewSubpixelRounding) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id=frameContainer style='position: relative; left: 0.5px'>
      <iframe style='position: relative; left: 0.5px' width='200'
          height='200' src='http://test.com' frameBorder='0'></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id='target' style='position: relative; width: 100px; height: 100px;
        left: 0.5px'></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* frame_container =
      To<LayoutBlock>(GetLayoutObjectByElementId("frameContainer"));
  LayoutObject* target =
      ChildDocument().getElementById(AtomicString("target"))->GetLayoutObject();
  PhysicalRect rect(0, 0, 100, 100);
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(frame_container, rect));
  // When passing from the iframe to the parent frame, the rect of (0.5, 0, 100,
  // 100) is expanded to (0, 0, 100, 100), and then offset by the 0.5 offset of
  // frameContainer.
  EXPECT_EQ(PhysicalRect(LayoutUnit(0.5), LayoutUnit(), LayoutUnit(101),
                         LayoutUnit(100)),
            rect);
}

TEST_P(VisualRectMappingTest, LayoutViewDisplayNone) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0; }</style>
    <div id=frameContainer>
      <iframe id='frame' src='http://test.com' width='50' height='50'
          frameBorder='0'></iframe>
    </div>
  )HTML");
  SetChildFrameHTML(
      "<style>body { margin: 0; }</style>"
      "<div style='width:100px;height:100px;'></div>");
  UpdateAllLifecyclePhasesForTest();

  auto* frame_container =
      To<LayoutBlock>(GetLayoutObjectByElementId("frameContainer"));
  auto* frame_body = To<LayoutBlock>(ChildDocument().body()->GetLayoutObject());
  auto* frame_div = To<LayoutBlock>(frame_body->LastChild());

  // This part is copied from the LayoutView test, just to ensure that the
  // mapped rect is valid before display:none is set on the iframe.
  ChildDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 47), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  PhysicalRect original_rect(4, 60, 20, 80);
  PhysicalRect rect = original_rect;
  EXPECT_TRUE(frame_div->MapToVisualRectInAncestorSpace(frame_container, rect));
  EXPECT_EQ(rect, PhysicalRect(4, 13, 20, 37));

  Element* frame_element = GetElementById("frame");
  frame_element->SetInlineStyleProperty(CSSPropertyID::kDisplay, "none");
  UpdateAllLifecyclePhasesForTest();

  frame_body = To<LayoutBlock>(ChildDocument().body()->GetLayoutObject());
  EXPECT_EQ(nullptr, frame_body);
}

TEST_P(VisualRectMappingTest, SelfFlippedWritingMode) {
  SetBodyInnerHTML(R"HTML(
    <div id='target' style='writing-mode: vertical-rl;
        box-shadow: 40px 20px black; width: 100px; height: 50px;
        position: absolute; top: 111px; left: 222px'>
    </div>
  )HTML");

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect local_visual_rect = LocalVisualRect(*target);
  // 140 = width(100) + box_shadow_offset_x(40)
  // 70 = height(50) + box_shadow_offset_y(20)
  EXPECT_EQ(PhysicalRect(0, 0, 140, 70), local_visual_rect);

  PhysicalRect rect = local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(target, rect));
  // This rect is in physical coordinates of target.
  EXPECT_EQ(PhysicalRect(0, 0, 140, 70), rect);

  CheckPaintInvalidationVisualRect(*target, GetLayoutView(),
                                   PhysicalRect(222, 111, 140, 70));
}

TEST_P(VisualRectMappingTest, ContainerFlippedWritingMode) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='writing-mode: vertical-rl;
        position: absolute; top: 111px; left: 222px'>
      <div id='target' style='box-shadow: 40px 20px black; width: 100px;
          height: 90px'></div>
      <div style='width: 100px; height: 100px'></div>
    </div>
  )HTML");

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect target_local_visual_rect = LocalVisualRect(*target);
  // 140 = width(100) + box_shadow_offset_x(40)
  // 110 = height(90) + box_shadow_offset_y(20)
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), target_local_visual_rect);

  PhysicalRect rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(target, rect));
  // This rect is in physical coordinates of target.
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), rect);

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(container, rect));
  // 100 is the physical x location of target in container.
  EXPECT_EQ(PhysicalRect(100, 0, 140, 110), rect);

  CheckPaintInvalidationVisualRect(*target, GetLayoutView(),
                                   PhysicalRect(322, 111, 140, 110));

  PhysicalRect container_local_visual_rect = LocalVisualRect(*container);
  EXPECT_EQ(PhysicalRect(0, 0, 200, 100), container_local_visual_rect);
  rect = container_local_visual_rect;
  EXPECT_TRUE(container->MapToVisualRectInAncestorSpace(container, rect));
  EXPECT_EQ(PhysicalRect(0, 0, 200, 100), rect);
  rect = container_local_visual_rect;
  EXPECT_TRUE(
      container->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(PhysicalRect(222, 111, 200, 100), rect);
}

TEST_P(VisualRectMappingTest, ContainerOverflowScroll) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position: absolute; top: 111px; left: 222px;
        border: 10px solid red; overflow: scroll; width: 50px;
        height: 80px'>
      <div id='target' style='box-shadow: 40px 20px black; width: 100px;
          height: 90px'></div>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* scrollable_area = GetScrollableArea(container);
  EXPECT_EQ(0, scrollable_area->ScrollPosition().y());
  EXPECT_EQ(0, scrollable_area->ScrollPosition().x());
  scrollable_area->ScrollToAbsolutePosition(gfx::PointF(8, 7));
  UpdateAllLifecyclePhasesForTest();

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect target_local_visual_rect = LocalVisualRect(*target);
  // 140 = width(100) + box_shadow_offset_x(40)
  // 110 = height(90) + box_shadow_offset_y(20)
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), target_local_visual_rect);
  PhysicalRect rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(target, rect));
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), rect);

  rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(container, rect));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  // 2 = target_x(0) + container_border_left(10) - scroll_left(8)
  // 3 = target_y(0) + container_border_top(10) - scroll_top(7)
  // Rect is not clipped by container's overflow clip because of
  // overflow:scroll.
  EXPECT_EQ(PhysicalRect(2, 3, 140, 110), rect);

  // (2, 3, 140, 100) is first clipped by container's overflow clip, to
  // (10, 10, 50, 80), then is by added container's offset in LayoutView
  // (222, 111).
  CheckPaintInvalidationVisualRect(*target, GetLayoutView(),
                                   PhysicalRect(232, 121, 50, 80));

  PhysicalRect container_local_visual_rect = LocalVisualRect(*container);
  // Because container has overflow clip, its visual overflow doesn't include
  // overflow from children.
  // 70 = width(50) + border_left_width(10) + border_right_width(10)
  // 100 = height(80) + border_top_width(10) + border_bottom_width(10)
  EXPECT_EQ(PhysicalRect(0, 0, 70, 100), container_local_visual_rect);
  rect = container_local_visual_rect;
  EXPECT_TRUE(container->MapToVisualRectInAncestorSpace(container, rect));
  // Container should not apply overflow clip on its own overflow rect.
  EXPECT_EQ(PhysicalRect(0, 0, 70, 100), rect);

  CheckPaintInvalidationVisualRect(*container, GetLayoutView(),
                                   PhysicalRect(222, 111, 70, 100));
}

TEST_P(VisualRectMappingTest, ContainerFlippedWritingModeAndOverflowScroll) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='writing-mode: vertical-rl;
        position: absolute; top: 111px; left: 222px; border: solid red;
        border-width: 10px 20px 30px 40px; overflow: scroll; width: 50px;
        height: 80px'>
      <div id='target' style='box-shadow: 40px 20px black; width: 100px;
          height: 90px'></div>
      <div style='width: 100px; height: 100px'></div>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* scrollable_area = GetScrollableArea(container);
  EXPECT_EQ(0, scrollable_area->ScrollPosition().y());
  // The initial scroll offset is to the left-most because of flipped blocks
  // writing mode.
  // 150 = total_scrollable_overflow(100 + 100) - width(50)
  EXPECT_EQ(150, scrollable_area->ScrollPosition().x());
  // Scroll to the right by 8 pixels.
  scrollable_area->ScrollToAbsolutePosition(gfx::PointF(142, 7));
  UpdateAllLifecyclePhasesForTest();

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect target_local_visual_rect = LocalVisualRect(*target);
  // 140 = width(100) + box_shadow_offset_x(40)
  // 110 = height(90) + box_shadow_offset_y(20)
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), target_local_visual_rect);

  PhysicalRect rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(target, rect));
  // This rect is in physical coordinates of target.
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), rect);

  rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(container, rect));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  // -2 = target_physical_x(100) + container_border_left(40) - scroll_left(142)
  // 3 = target_y(0) + container_border_top(10) - scroll_top(7)
  // Rect is clipped by container's overflow clip because of overflow:scroll.
  EXPECT_EQ(PhysicalRect(-2, 3, 140, 110), rect);

  // (-2, 3, 140, 100) is first clipped by container's overflow clip, to
  // (40, 10, 50, 80), then is added by container's offset in LayoutView
  // (222, 111).

  PhysicalRect expectation(262, 121, 50, 80);
  CheckPaintInvalidationVisualRect(*target, GetLayoutView(), expectation);

  PhysicalRect container_local_visual_rect = LocalVisualRect(*container);
  // Because container has overflow clip, its visual overflow doesn't include
  // overflow from children.
  // 110 = width(50) + border_left_width(40) + border_right_width(20)
  // 120 = height(80) + border_top_width(10) + border_bottom_width(30)
  EXPECT_EQ(PhysicalRect(0, 0, 110, 120), container_local_visual_rect);

  rect = container_local_visual_rect;
  EXPECT_TRUE(container->MapToVisualRectInAncestorSpace(container, rect));
  EXPECT_EQ(PhysicalRect(0, 0, 110, 120), rect);

  expectation = PhysicalRect(222, 111, 110, 120);
  CheckPaintInvalidationVisualRect(*container, GetLayoutView(), expectation);
}

TEST_P(VisualRectMappingTest, ContainerOverflowHidden) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position: absolute; top: 111px; left: 222px;
        border: 10px solid red; overflow: hidden; width: 50px;
        height: 80px;'>
      <div id='target' style='box-shadow: 40px 20px black; width: 100px;
          height: 90px'></div>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* scrollable_area = GetScrollableArea(container);
  EXPECT_EQ(0, scrollable_area->ScrollPosition().y());
  EXPECT_EQ(0, scrollable_area->ScrollPosition().x());
  scrollable_area->ScrollToAbsolutePosition(gfx::PointF(28, 27));
  UpdateAllLifecyclePhasesForTest();

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  auto target_local_visual_rect = LocalVisualRect(*target);
  // 140 = width(100) + box_shadow_offset_x(40)
  // 110 = height(90) + box_shadow_offset_y(20)
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), target_local_visual_rect);
  auto rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(target, rect));
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), rect);

  rect = target_local_visual_rect;
  // Rect is not clipped by container's overflow clip.
  CheckVisualRect(*target, *container, rect, PhysicalRect(10, 10, 140, 110));
}

TEST_P(VisualRectMappingTest, ContainerFlippedWritingModeAndOverflowHidden) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='writing-mode: vertical-rl;
        position: absolute; top: 111px; left: 222px; border: solid red;
        border-width: 10px 20px 30px 40px; overflow: hidden; width: 50px;
        height: 80px'>
      <div id='target' style='box-shadow: 40px 20px black; width: 100px;
          height: 90px'></div>
      <div style='width: 100px; height: 100px'></div>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* scrollable_area = GetScrollableArea(container);
  EXPECT_EQ(0, scrollable_area->ScrollPosition().y());
  // The initial scroll offset is to the left-most because of flipped blocks
  // writing mode.
  // 150 = total_scrollable_overflow(100 + 100) - width(50)
  EXPECT_EQ(150, scrollable_area->ScrollPosition().x());
  scrollable_area->ScrollToAbsolutePosition(gfx::PointF(82, 7));
  UpdateAllLifecyclePhasesForTest();

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect target_local_visual_rect = LocalVisualRect(*target);
  // 140 = width(100) + box_shadow_offset_x(40)
  // 110 = height(90) + box_shadow_offset_y(20)
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), target_local_visual_rect);

  PhysicalRect rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(target, rect));
  // This rect is in physical coordinates of target.
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), rect);

  rect = target_local_visual_rect;
  // 58 = target_physical_x(100) + container_border_left(40) - scroll_left(58)
  CheckVisualRect(*target, *container, rect, PhysicalRect(-10, 10, 140, 110));
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(container, rect));
}

TEST_P(VisualRectMappingTest, ContainerAndTargetDifferentFlippedWritingMode) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='writing-mode: vertical-rl;
        position: absolute; top: 111px; left: 222px; border: solid red;
        border-width: 10px 20px 30px 40px; overflow: scroll; width: 50px;
        height: 80px'>
      <div id='target' style='writing-mode: vertical-lr; width: 100px;
          height: 90px; box-shadow: 40px 20px black'></div>
      <div style='width: 100px; height: 100px'></div>
    </div>
  )HTML");

  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* scrollable_area = GetScrollableArea(container);
  EXPECT_EQ(0, scrollable_area->ScrollPosition().y());
  // The initial scroll offset is to the left-most because of flipped blocks
  // writing mode.
  // 150 = total_scrollable_overflow(100 + 100) - width(50)
  EXPECT_EQ(150, scrollable_area->ScrollPosition().x());
  // Scroll to the right by 8 pixels.
  scrollable_area->ScrollToAbsolutePosition(gfx::PointF(142, 7));
  UpdateAllLifecyclePhasesForTest();

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect target_local_visual_rect = LocalVisualRect(*target);
  // 140 = width(100) + box_shadow_offset_x(40)
  // 110 = height(90) + box_shadow_offset_y(20)
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), target_local_visual_rect);

  PhysicalRect rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(target, rect));
  // This rect is in physical coordinates of target.
  EXPECT_EQ(PhysicalRect(0, 0, 140, 110), rect);

  rect = target_local_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(container, rect));
  rect.Move(-PhysicalOffset(container->ScrolledContentOffset()));
  // -2 = target_physical_x(100) + container_border_left(40) - scroll_left(142)
  // 3 = target_y(0) + container_border_top(10) - scroll_top(7)
  // Rect is not clipped by container's overflow clip.
  EXPECT_EQ(PhysicalRect(-2, 3, 140, 110), rect);
}

TEST_P(VisualRectMappingTest,
       DifferentPaintInvalidaitionContainerForAbsolutePosition) {
  SetPreferCompositingToLCDText(true);

  SetBodyInnerHTML(R"HTML(
    <div id='stacking-context' style='opacity: 0.9; background: blue;
        will-change: transform'>
      <div id='scroller' style='overflow: scroll; width: 80px;
          height: 80px'>
        <div id='absolute' style='position: absolute; top: 111px;
            left: 222px; width: 50px; height: 50px; background: green'>
        </div>
        <div id='normal-flow' style='width: 2000px; height: 2000px;
            background: yellow'></div>
      </div>
    </div>
  )HTML");

  auto* scroller = To<LayoutBlock>(GetLayoutObjectByElementId("scroller"));
  GetScrollableArea(scroller)->ScrollToAbsolutePosition(gfx::PointF(88, 77));
  UpdateAllLifecyclePhasesForTest();

  auto* normal_flow =
      To<LayoutBlock>(GetLayoutObjectByElementId("normal-flow"));
  PhysicalRect normal_flow_visual_rect = LocalVisualRect(*normal_flow);
  EXPECT_EQ(PhysicalRect(0, 0, 2000, 2000), normal_flow_visual_rect);
  PhysicalRect rect = normal_flow_visual_rect;
  EXPECT_TRUE(normal_flow->MapToVisualRectInAncestorSpace(scroller, rect));
  EXPECT_EQ(PhysicalRect(0, 0, 2000, 2000), rect);

  auto* stacking_context =
      To<LayoutBlock>(GetLayoutObjectByElementId("stacking-context"));
  auto* absolute = To<LayoutBlock>(GetLayoutObjectByElementId("absolute"));
  EXPECT_EQ(stacking_context, absolute->Container());

  EXPECT_EQ(PhysicalRect(0, 0, 50, 50), LocalVisualRect(*absolute));
  CheckPaintInvalidationVisualRect(*absolute, *stacking_context,
                                   PhysicalRect(222, 111, 50, 50));
}

TEST_P(VisualRectMappingTest,
       ContainerOfAbsoluteAbovePaintInvalidationContainer) {
  SetPreferCompositingToLCDText(true);

  SetBodyInnerHTML(
      "<div id='container' style='position: absolute; top: 88px; left: 99px'>"
      "  <div style='height: 222px'></div>"
      // This div makes stacking-context composited.
      "  <div style='position: absolute; width: 1px; height: 1px; "
      "      background:yellow; will-change: transform'></div>"
      // This stacking context is paintInvalidationContainer of the absolute
      // child, but not a container of it.
      "  <div id='stacking-context' style='opacity: 0.9'>"
      "    <div id='absolute' style='position: absolute; top: 50px; left: 50px;"
      "        width: 50px; height: 50px; background: green'></div>"
      "  </div>"
      "</div>");

  auto* stacking_context =
      To<LayoutBlock>(GetLayoutObjectByElementId("stacking-context"));
  auto* absolute = To<LayoutBlock>(GetLayoutObjectByElementId("absolute"));
  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  EXPECT_EQ(container, absolute->Container());

  PhysicalRect absolute_visual_rect = LocalVisualRect(*absolute);
  EXPECT_EQ(PhysicalRect(0, 0, 50, 50), absolute_visual_rect);
  PhysicalRect rect = absolute_visual_rect;
  EXPECT_TRUE(absolute->MapToVisualRectInAncestorSpace(stacking_context, rect));
  // -172 = top(50) - y_offset_of_stacking_context(222)
  EXPECT_EQ(PhysicalRect(50, -172, 50, 50), rect);
  // Call checkPaintInvalidationVisualRect to deal with layer squashing.
  CheckPaintInvalidationVisualRect(*absolute, GetLayoutView(),
                                   PhysicalRect(149, 138, 50, 50));
}

TEST_P(VisualRectMappingTest, CSSClip) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='
```