Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This snippet is a test file for the `MapCoordinates` functionality in the Chromium Blink rendering engine. I need to identify what aspects of coordinate mapping are being tested and how they relate to web technologies like JavaScript, HTML, and CSS.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The file name `map_coordinates_test.cc` and the various test case names strongly suggest the code is testing the transformation of coordinates between different elements in the layout tree.

2. **Analyze Individual Test Cases:**  Go through each `TEST_F` and determine what specific scenario is being tested. Look for the HTML structure being set up and the assertions being made.

3. **Relate to Web Technologies:**  Connect the tested scenarios to corresponding features in HTML, CSS, and JavaScript. For example, tests involving `transform` and `transform-origin` directly relate to CSS transformations. Tests involving scrolling relate to browser behavior and JavaScript's ability to manipulate scroll positions.

4. **Identify Logic and Assumptions:**  Where calculations are involved (e.g., with rotations), try to infer the expected input and output of the coordinate mapping functions based on the transformations applied.

5. **Consider Potential Errors:** Think about common mistakes developers might make when dealing with coordinate systems and transformations in web development.

6. **Synthesize a Summary:** Combine the findings from the individual test cases into a concise overview of the file's purpose.
这是对`blink/renderer/core/layout/map_coordinates_test.cc`文件功能的总结，延续了前两个部分的内容。

**归纳总结 `map_coordinates_test.cc` 的功能:**

这个测试文件主要用于验证 Blink 渲染引擎中 `MapCoordinates` 相关功能的正确性。其核心目标是确保在各种复杂的布局场景下，能够准确地将一个元素的局部坐标映射到其祖先元素或绝对坐标系中。  这些测试覆盖了多种 CSS 属性和布局特性对坐标映射的影响，包括：

* **CSS Transforms (2D 和 3D):** 测试了 `transform` 属性 (例如 `rotate`, `translateZ`) 和 `transform-origin` 对坐标映射的影响。特别是验证了 `localToAbsoluteTransform` 和 `localToAncestorTransform` 函数在存在 2D 和 3D 变换时的正确行为，以及 3D 变换的扁平化处理。
* **滚动 (Scrolling):**  测试了在存在滚动容器的情况下，如何将子元素的坐标映射到滚动容器或其祖先。重点是验证 `kIgnoreScrollOffset` 标志的作用，它可以让坐标映射忽略滚动偏移量，得到元素在滚动前的原始位置。这对于某些需要知道元素在未滚动状态下位置的场景非常重要。
* **固定定位 (Fixed Positioning):** 测试了 `position: fixed` 元素在滚动时的坐标映射行为。验证了固定定位元素相对于视口的位置保持不变，不受滚动偏移的影响（除非父元素有 `will-change: transform` 等属性）。
* **书写模式 (Writing Modes):** 测试了在使用了 `writing-mode: vertical-rl` 等垂直书写模式的情况下，滚动和坐标映射的正确性。
* **滚动条 (Scrollbars):**  测试了在非覆盖滚动条存在的情况下，滚动条的宽度对元素坐标映射的影响，并验证了 `kIgnoreScrollOffset` 在这种场景下的作用。

**与 JavaScript, HTML, CSS 功能的关系举例说明:**

* **JavaScript:**  JavaScript 代码经常需要获取和操作页面元素的坐标信息。例如，事件处理程序可能需要知道鼠标点击的位置相对于某个元素的位置，或者动画可能需要根据元素的位置进行调整。 `MapCoordinates` 保证了 JavaScript 通过 Blink 提供的接口（例如 `getBoundingClientRect`) 获取到的坐标是准确的。

    * **假设输入:**  一个 JavaScript 事件监听器获取了鼠标点击事件的客户端坐标 `(clientX, clientY)`。
    * **逻辑推理:**  为了判断点击是否发生在一个特定的 `<div>` 元素内，浏览器需要将客户端坐标映射到该 `<div>` 元素的局部坐标系。`MapCoordinates` 负责执行这个映射。
    * **预期输出:**  该 `<div>` 元素的局部坐标 `(localX, localY)`。

* **HTML:** HTML 结构定义了元素的层级关系，而 `MapCoordinates` 的目标就是理解和处理这种层级关系中的坐标映射。不同的 HTML 结构会影响坐标的计算。

    * **举例说明:** 上述代码中的 HTML 片段 `<div id='container'><div id='child'></div></div>`  定义了一个父子元素的结构，测试了 `child` 相对于 `container` 的坐标映射。

* **CSS:** CSS 属性，特别是布局相关的属性 (如 `position`, `transform`, `overflow`, `writing-mode`) 直接影响元素的渲染位置和坐标系统。 `MapCoordinates` 负责处理这些 CSS 属性带来的复杂性。

    * **举例说明:**  `transform: rotate(45deg)` CSS 规则会旋转元素，`MapCoordinates` 需要计算旋转后的元素坐标。 `overflow: scroll` 会创建一个滚动容器，`MapCoordinates` 需要考虑滚动偏移。

**用户或编程常见的使用错误举例说明:**

* **混淆局部坐标和绝对坐标:** 开发者可能会错误地认为一个元素的 `offsetLeft` 和 `offsetTop` 总是相对于文档的左上角，但实际上它们是相对于其 `offsetParent` 的。 `MapCoordinates` 确保了 Blink 内部对这些概念的正确处理，从而为开发者提供可靠的坐标信息。
* **不考虑 CSS Transforms:** 在使用 JavaScript 获取元素位置时，开发者可能会忘记考虑 CSS 变换带来的影响，导致计算错误。 `MapCoordinates` 确保了即使存在复杂的变换，坐标映射也是准确的。
* **没有处理滚动偏移:**  在需要获取元素在未滚动状态下的位置时，开发者可能会忘记减去滚动偏移量。 `MapCoordinates` 提供的 `kIgnoreScrollOffset` 选项可以方便地获取这种位置信息。

**总结 `map_coordinates_test.cc` 的功能 (整合三部分):**

总而言之，`blink/renderer/core/layout/map_coordinates_test.cc` 文件是一个全面的测试套件，旨在确保 Blink 渲染引擎在处理各种复杂的 CSS 布局和变换时，能够准确地进行坐标映射。 它涵盖了 2D/3D 变换、滚动、固定定位、书写模式和滚动条等多种场景，保证了浏览器在内部计算和向 JavaScript 提供元素坐标信息时的准确性和一致性。 这对于确保网页的正确渲染和交互至关重要。

### 提示词
```
这是目录为blink/renderer/core/layout/map_coordinates_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
div id='child'></div>
      </div>
    </div>
  )HTML");
  auto* container =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("container"));
  gfx::Transform container_matrix = container->LocalToAbsoluteTransform();
  EXPECT_TRUE(container_matrix.IsIdentity());

  LayoutObject* child = GetLayoutObjectByElementId("child");
  gfx::Transform child_matrix = child->LocalToAbsoluteTransform();
  EXPECT_FALSE(child_matrix.IsIdentityOrTranslation());
  EXPECT_TRUE(child_matrix.Is2dTransform());
  EXPECT_EQ(gfx::PointF(), child_matrix.ProjectPoint(gfx::PointF()));
  EXPECT_EQ(gfx::PointF(20.0f, 40.0f),
            child_matrix.ProjectPoint(gfx::PointF(10.0f, 20.0f)));
}

TEST_F(MapCoordinatesTest, LocalToAncestorTransform) {
  SetBodyInnerHTML(R"HTML(
    <div id='container'>
      <div id='rotate1' style='transform: rotate(45deg); transform-origin:
    left top;'>
        <div id='rotate2' style='transform: rotate(90deg);
    transform-origin: left top;'>
          <div id='child'></div>
        </div>
      </div>
    </div>
  )HTML");
  auto* container =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("container"));
  auto* rotate1 =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("rotate1"));
  auto* rotate2 =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("rotate2"));
  LayoutObject* child = GetLayoutObjectByElementId("child");
  gfx::Transform matrix;

  matrix = child->LocalToAncestorTransform(rotate2);
  EXPECT_TRUE(matrix.IsIdentity());

  // Rotate (100, 0) 90 degrees to (0, 100)
  matrix = child->LocalToAncestorTransform(rotate1);
  EXPECT_FALSE(matrix.IsIdentity());
  EXPECT_TRUE(matrix.Is2dTransform());
  EXPECT_NEAR(0.0, matrix.ProjectPoint(gfx::PointF(100.0, 0.0)).x(),
              LayoutUnit::Epsilon());
  EXPECT_NEAR(100.0, matrix.ProjectPoint(gfx::PointF(100.0, 0.0)).y(),
              LayoutUnit::Epsilon());

  // Rotate (100, 0) 135 degrees to (-70.7, 70.7)
  matrix = child->LocalToAncestorTransform(container);
  EXPECT_FALSE(matrix.IsIdentity());
  EXPECT_TRUE(matrix.Is2dTransform());
  EXPECT_NEAR(-100.0 * sqrt(2.0) / 2.0,
              matrix.ProjectPoint(gfx::PointF(100.0, 0.0)).x(),
              LayoutUnit::Epsilon());
  EXPECT_NEAR(100.0 * sqrt(2.0) / 2.0,
              matrix.ProjectPoint(gfx::PointF(100.0, 0.0)).y(),
              LayoutUnit::Epsilon());
}

TEST_F(MapCoordinatesTest, LocalToAbsoluteTransformFlattens) {
  SetBodyInnerHTML(R"HTML(
    <div style='position: absolute; left: 0; top: 0;'>
      <div style='transform: rotateY(45deg); transform-style: preserve-3d;'>
        <div style='transform: rotateY(-45deg); transform-style: preserve-3d;'>
          <div id='child1'></div>
        </div>
      </div>
      <div style='transform: rotateY(45deg);'>
        <div style='transform: rotateY(-45deg);'>
          <div id='child2'></div>
        </div>
      </div>
    </div>
  )HTML");
  LayoutObject* child1 = GetLayoutObjectByElementId("child1");
  LayoutObject* child2 = GetLayoutObjectByElementId("child2");
  gfx::Transform matrix;

  matrix = child1->LocalToAbsoluteTransform();

  // With child1, the rotations cancel and points should map basically back to
  // themselves.
  EXPECT_NEAR(100.0, matrix.MapPoint(gfx::PointF(100.0, 50.0)).x(),
              LayoutUnit::Epsilon());
  EXPECT_NEAR(50.0, matrix.MapPoint(gfx::PointF(100.0, 50.0)).y(),
              LayoutUnit::Epsilon());
  EXPECT_NEAR(50.0, matrix.MapPoint(gfx::PointF(50.0, 100.0)).x(),
              LayoutUnit::Epsilon());
  EXPECT_NEAR(100.0, matrix.MapPoint(gfx::PointF(50.0, 100.0)).y(),
              LayoutUnit::Epsilon());

  // With child2, each rotation gets flattened and the end result is
  // approximately a scale(1.0, 0.5).
  matrix = child2->LocalToAbsoluteTransform();
  EXPECT_NEAR(50.0, matrix.MapPoint(gfx::PointF(100.0, 50.0)).x(),
              LayoutUnit::Epsilon());
  EXPECT_NEAR(50.0, matrix.MapPoint(gfx::PointF(100.0, 50.0)).y(),
              LayoutUnit::Epsilon());
  EXPECT_NEAR(25.0, matrix.MapPoint(gfx::PointF(50.0, 100.0)).x(),
              LayoutUnit::Epsilon());
  EXPECT_NEAR(100.0, matrix.MapPoint(gfx::PointF(50.0, 100.0)).y(),
              LayoutUnit::Epsilon());
}

TEST_F(MapCoordinatesTest, Transform3DWithOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
    </style>
    <div style="perspective: 400px; width: 0; height: 0">
      <div>
        <div style="height: 100px"></div>
        <div style="transform-style: preserve-3d; transform: rotateY(0deg)">
          <div id="target" style="width: 100px; height: 100px;
                                  transform: translateZ(200px)">
          </div>
        </div>
      </div>
    </div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  EXPECT_EQ(gfx::QuadF(gfx::RectF(0, 100, 100, 100)),
            MapLocalToAncestor(target, nullptr,
                               gfx::QuadF(gfx::RectF(0, 0, 100, 100))));
}

TEST_F(MapCoordinatesTest, Transform3DWithOffset2) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
    </style>
    <div style="perspective: 400px; width: 0; height: 0">
      <div style="transform-style: preserve-3d">
        <div style="height: 100px"></div>
        <div style="transform-style: preserve-3d; transform: rotateY(0deg)">
          <div id="target" style="width: 100px; height: 100px;
                                  transform: translateZ(200px)">
          </div>
        </div>
      </div>
    </div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  EXPECT_EQ(gfx::QuadF(gfx::RectF(0, 200, 200, 200)),
            MapLocalToAncestor(target, nullptr,
                               gfx::QuadF(gfx::RectF(0, 0, 100, 100))));
}

// This test verifies that the mapped location of a div within a scroller
// remains the same after scroll when ignoring scroll offset.
TEST_F(MapCoordinatesTest, IgnoreScrollOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      .scroller { overflow: scroll; height: 100px; width: 100px;
        top: 100px; position: absolute; }
      .box { width: 10px; height: 10px; top: 10px; position: absolute; }
      .spacer { height: 2000px; }
    </style>
    <div class='scroller' id='scroller'>
      <div class='box' id='box'></div>
      <div class='spacer'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* box = GetLayoutBoxByElementId("box");

  EXPECT_EQ(PhysicalOffset(0, 10),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(0, 10),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));

  To<Element>(scroller->GetNode())
      ->GetLayoutBoxForScrolling()
      ->GetScrollableArea()
      ->ScrollToAbsolutePosition(gfx::PointF(0, 50));

  EXPECT_EQ(PhysicalOffset(0, -40),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(0, 10),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));
}

// This test verifies that the mapped location of an inline div within a
// scroller remains the same after scroll when ignoring scroll offset.
TEST_F(MapCoordinatesTest, IgnoreScrollOffsetForInline) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      .scroller { overflow: scroll; width: 100px; height: 100px; top: 100px;
        position: absolute; }
      .box { width: 10px; height: 10px; top: 10px; position: sticky; }
      .inline { display: inline; }
      .spacer { height: 2000px; }
    </style>
    <div class='scroller' id='scroller'>
      <div class='inline box' id='box'></div>
      <div class='spacer'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* box = To<LayoutInline>(GetLayoutObjectByElementId("box"));

  EXPECT_EQ(PhysicalOffset(0, 10),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(0, 10),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));

  To<Element>(scroller->GetNode())
      ->GetLayoutBoxForScrolling()
      ->GetScrollableArea()
      ->ScrollToAbsolutePosition(gfx::PointF(0, 50));

  EXPECT_EQ(PhysicalOffset(0, 10),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(0, 60),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));
}

// This test verifies that ignoring scroll offset works with writing modes.
TEST_F(MapCoordinatesTest, IgnoreScrollOffsetWithWritingModes) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      .scroller { writing-mode: vertical-rl; overflow: scroll; height: 100px;
        width: 100px; top: 100px; position: absolute; }
      .box { width: 10px; height: 10px; top: 10px; position: absolute; }
      .spacer { width: 2000px; height: 2000px; }
    </style>
    <div class='scroller' id='scroller'>
      <div class='box' id='box'></div>
      <div class='spacer'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* box = GetLayoutBoxByElementId("box");
  auto* scroll_element = To<Element>(scroller->GetNode());

  EXPECT_EQ(PhysicalOffset(90, 10),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(1990, 10),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));

  scroll_element->GetLayoutBoxForScrolling()
      ->GetScrollableArea()
      ->ScrollToAbsolutePosition(gfx::PointF(0, 50));

  EXPECT_EQ(PhysicalOffset(1990, -40),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(1990, 10),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));

  scroll_element->GetLayoutBoxForScrolling()
      ->GetScrollableArea()
      ->ScrollToAbsolutePosition(gfx::PointF(1900, 50));

  EXPECT_EQ(PhysicalOffset(90, -40),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(1990, 10),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));
}

TEST_F(MapCoordinatesTest, FixedPositionWithScrollOffset) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="position: fixed; top: 200px; left: 100px"></div>
    <div style="height: 10000px"></div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  PhysicalOffset expected(100, 200);
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset()));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset()));
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset(),
                                         kIgnoreScrollOffset));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset(),
                               kIgnoreScrollOffset));

  // Scroll offset doesn't affect MapLocalToAncestor(), regardless of
  // kIgnoreScrollOffset.
  GetLayoutView().GetScrollableArea()->ScrollToAbsolutePosition(
      gfx::PointF(0, 400));
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset()));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset()));
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset(),
                                         kIgnoreScrollOffset));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset(),
                               kIgnoreScrollOffset));
}

TEST_F(MapCoordinatesTest, FixedPositionWithScrollOffsetVerticalRL) {
  SetBodyInnerHTML(R"HTML(
    <style>body { writing-mode: vertical-rl; margin: 0; }</style>
    <div id="target" style="position: fixed; top: 200px; left: 100px"></div>
    <div style="width: 10000px"></div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  PhysicalOffset expected(100, 200);
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset()));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset()));
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset(),
                                         kIgnoreScrollOffset));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset(),
                               kIgnoreScrollOffset));

  // Scroll offset doesn't affect MapLocalToAncestor(), regardless of
  // kIgnoreScrollOffset.
  GetLayoutView().GetScrollableArea()->ScrollToAbsolutePosition(
      gfx::PointF(400, 0));
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset()));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset()));
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset(),
                                         kIgnoreScrollOffset));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset(),
                               kIgnoreScrollOffset));
}

TEST_F(MapCoordinatesTest, FixedPositionUnderTransformWithScrollOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div style="will-change: transform">
      <div id="target" style="position: fixed; top: 200px; left: 100px"></div>
    </div>
    <div style="height: 10000px"></div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  PhysicalOffset expected(100, 200);
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset()));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset()));
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset(),
                                         kIgnoreScrollOffset));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset(),
                               kIgnoreScrollOffset));

  // Fixed position under transform is treated like absolute position, so is
  // affected by scroll offset.
  GetLayoutView().GetScrollableArea()->ScrollToAbsolutePosition(
      gfx::PointF(0, 400));
  PhysicalOffset expected_scrolled(100, -200);
  EXPECT_EQ(expected_scrolled,
            MapLocalToAncestor(target, nullptr, PhysicalOffset()));
  EXPECT_EQ(expected_scrolled,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset()));
  EXPECT_EQ(expected, MapLocalToAncestor(target, nullptr, PhysicalOffset(),
                                         kIgnoreScrollOffset));
  EXPECT_EQ(expected,
            MapLocalToAncestor(target, &GetLayoutView(), PhysicalOffset(),
                               kIgnoreScrollOffset));
}

// This test verifies that ignoring scroll offset works with writing modes and
// non-overlay scrollbar.
TEST_F(MapCoordinatesTest,
       IgnoreScrollOffsetWithWritingModesAndNonOverlayScrollbar) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      .scroller { writing-mode: vertical-rl; overflow: scroll; height: 100px;
        width: 100px; top: 100px; position: absolute; }
      .box { width: 10px; height: 10px; top: 10px; position: absolute; }
      .spacer { width: 2000px; height: 2000px; }
    </style>
    <div class='scroller' id='scroller'>
      <div class='box' id='box'></div>
      <div class='spacer'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  auto* box = GetLayoutBoxByElementId("box");

  // The box is on the left of the scrollbar so the width of the scrollbar
  // affects the location of the box.
  EXPECT_EQ(PhysicalOffset(75, 10),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(1990, 10),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));

  To<Element>(scroller->GetNode())
      ->GetLayoutBoxForScrolling()
      ->GetScrollableArea()
      ->ScrollToAbsolutePosition(gfx::PointF(0, 0));

  // The box is now on the right of the scrollbar therefore there is nothing
  // between the box and the right border of the content.
  EXPECT_EQ(PhysicalOffset(1990, 10),
            MapLocalToAncestor(box, scroller, PhysicalOffset()));
  EXPECT_EQ(
      PhysicalOffset(1990, 10),
      MapLocalToAncestor(box, scroller, PhysicalOffset(), kIgnoreScrollOffset));
}

}  // namespace blink
```