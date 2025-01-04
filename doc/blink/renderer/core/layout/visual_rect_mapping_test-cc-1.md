Response:
The user wants a summary of the provided C++ code for a test file in the Chromium Blink rendering engine.

**Plan:**

1. Identify the purpose of the test file based on its name and content.
2. List the specific functionalities being tested.
3. Analyze the provided HTML snippets and relate them to web technologies (JavaScript, HTML, CSS).
4. For each test case, if applicable:
    *   Identify the assumption made for the input.
    *   Determine the expected output based on the test logic.
5. Look for potential user or programming errors the tests might be preventing.
6. Provide a concise summary of the file's overall purpose.
这是 blink 渲染引擎中 `visual_rect_mapping_test.cc` 文件的第二部分，延续了第一部分的功能，主要用于测试在不同布局和 CSS 属性影响下，元素的可视矩形（visual rect）的映射和计算是否正确。

**归纳一下它的功能：**

这部分测试文件主要针对以下方面的元素可视矩形映射：

1. **`clip` 属性的影响:** 测试 `clip` 属性如何裁剪元素的可视区域，以及在父元素有 `clip` 属性时，子元素的可视矩形映射到父元素空间的结果。
2. **`contain: paint` 属性的影响:** 测试 `contain: paint` 属性如何限制元素的渲染边界，以及子元素的可视矩形映射到包含块空间的结果。
3. **浮动元素 (`float`) 在内联元素下的映射:** 测试浮动元素在内联元素内部时，其可视矩形映射到视口和父元素坐标系的结果，需要考虑内联元素的相对定位影响。
4. **内联块元素 (`display: inline-block`) 的映射:** 测试内联块元素的可视矩形映射到视口和父元素坐标系的结果。
5. **绝对定位元素 (`position: absolute`) 在相对定位内联元素下的映射:** 测试绝对定位元素在相对定位的内联元素内部时，其可视矩形映射到视口和父元素坐标系的结果，需要考虑父元素的相对偏移。
6. **书写模式 (`writing-mode: vertical-rl`) 的影响:**  重复了浮动、内联块和绝对定位元素的测试，但加入了 `writing-mode: vertical-rl` 属性，测试垂直书写模式下可视矩形的映射情况。
7. **CSS `transform` 属性 (`transform-style: preserve-3d`, `perspective`) 的影响:** 测试在应用 3D 变换和透视效果时，元素的可视矩形映射到视口空间的结果，包括嵌套的情况。
8. **包含滚动容器 (`overflow: scroll`) 和 `perspective` 的组合:** 测试在包含滚动条的透视容器中，元素的可视矩形映射是否正确，并考虑滚动偏移的影响。
9. **跨 iframe 的固定定位元素 (`position: fixed`) 的映射:** 测试固定定位元素在 iframe 中，映射到顶层视口时的位置是否正确，即使在 iframe 发生滚动时也应保持位置不变。
10. **包含滚动偏移的固定定位元素:** 测试固定定位元素在有滚动偏移的祖先元素下，映射到该祖先元素空间的可视矩形是否考虑了滚动偏移。
11. **在视口下带有滚动偏移的固定定位元素:** 测试固定定位元素映射到其自身视口空间时，视口的滚动偏移是否被正确计算。
12. **边缘包含 (`kEdgeInclusive`) 的交集测试:** 测试可视矩形映射时，使用 `kEdgeInclusive` 标志后，边缘相交的情况是否被认为是相交。
13. **透视 (`perspective`) 对可视矩形映射的影响:**  进一步测试 `perspective` 属性对元素可视矩形映射到祖先元素的影响。
14. **带有匿名表格的透视 (`perspective`) 效果:** 测试在包含匿名表格布局和透视效果的情况下，子元素的可视矩形映射是否正确。
15. **锚点定位 (`anchor-name`, `position-anchor`) 和滚动:** 测试在使用 CSS 锚点定位时，滚动容器的滚动会如何影响被锚定元素的可视矩形。
16. **忽略滤镜 (`kIgnoreFilters`) 的影响:** 测试在进行可视矩形映射时，是否可以忽略 CSS 滤镜 (`filter`) 带来的影响，即映射未应用滤镜时的原始矩形。

**与 JavaScript, HTML, CSS 的关系举例：**

*   **HTML:**  所有测试用例都使用了 HTML 结构来创建需要测试的 DOM 元素，例如 `<div id='target'></div>` 定义了一个 ID 为 `target` 的 div 元素。
*   **CSS:**  测试用例广泛使用了 CSS 属性来控制元素的布局和渲染效果，例如 `position: absolute`, `top: 0px`, `left: 0px`, `width: 400px`, `height: 400px`, `clip: rect(0px, 200px, 200px, 0px)`, `contain: paint`, `float: left`, `display: inline-block`, `writing-mode: vertical-rl`, `transform: rotateX(-45deg)`, `perspective: 100px`, `filter: blur(1px)`,  `anchor-name: --anchor`, `position-anchor: --anchor` 等。
*   **JavaScript (间接):** 虽然测试代码本身是 C++，但它模拟了浏览器渲染引擎在处理 HTML 和 CSS 时进行的布局计算。这些计算最终会影响到 JavaScript 中获取元素位置和大小的 API（如 `getBoundingClientRect()`）。例如，如果一个元素应用了 `transform`，`getBoundingClientRect()` 返回的矩形会受到变换的影响，而这些测试正是验证了渲染引擎计算这种变换后矩形的能力。

**逻辑推理的假设输入与输出举例：**

以 `TEST_P(VisualRectMappingTest, ClipPaint)` 为例：

*   **假设输入:**  一个 HTML 结构，其中包含一个父 div 和一个子 div。父 div 设置了 `position: absolute` 和 `clip` 属性，限定了其可视区域为 `rect(0px, 200px, 200px, 0px)`。子 div 的尺寸大于父 div 的可视区域。
*   **预期输出:**
    *   `LocalVisualRect(*target)` 应该返回子 div 自身的完整尺寸 `PhysicalRect(0, 0, 400, 400)`，因为它计算的是子 div 在其自身坐标系下的可视矩形。
    *   `CheckPaintInvalidationVisualRect(*target, GetLayoutView(), PhysicalRect(0, 0, 200, 200))`  会断言子 div 需要重绘的区域是父 div `clip` 属性定义的区域 `PhysicalRect(0, 0, 200, 200)`，因为父元素的裁剪会限制子元素的渲染范围。

以 `TEST_P(VisualRectMappingTest, FloatUnderInline)` 为例：

*   **假设输入:**  一个 HTML 结构，包含一个绝对定位的父 div，一个相对定位的 span，以及一个浮动 (左浮动) 的 div 作为 span 的子元素。各个元素都设置了不同的 `top` 和 `left` 值。
*   **预期输出:**
    *   `LocalVisualRect(*target)` 应该返回浮动 div 自身的尺寸 `PhysicalRect(0, 0, 33, 44)`。
    *   `target->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect)`  会将 `rect` 从浮动 div 的局部坐标系映射到视口坐标系，由于浮动元素相对于其包含块（这里是 span）进行定位，并受到父元素的偏移影响，最终 `rect` 的值应该为 `PhysicalRect(266, 155, 33, 44)` (66 + 200, 55 + 100)。
    *   `CheckVisualRect(*target, *span, rect, PhysicalRect(200, 100, 33, 44))`  会将 `rect` 从浮动 div 映射到其父元素 span 的坐标系，所以结果应该只包含 span 的相对偏移 `PhysicalRect(200, 100, 33, 44)`。

**涉及用户或者编程常见的使用错误举例：**

*   **误解 `clip` 属性的作用范围:** 开发者可能认为 `clip` 属性会影响元素的布局大小，但实际上它只影响元素的可视区域。测试用例 `ClipPaint` 强调了这一点，即使子元素的实际内容超出父元素的 `clip` 区域，子元素的局部尺寸仍然不变。
*   **混淆绝对定位和相对定位的基准:**  开发者在进行绝对定位时，可能会错误地认为它是相对于视口定位，而忘记了它实际上是相对于最近的已定位祖先元素定位。`AbsoluteUnderRelativeInline` 等测试用例验证了在有相对定位父元素的情况下，绝对定位子元素的计算方式。
*   **忽略 `transform` 的影响:**  开发者在计算元素在页面上的位置时，如果没有考虑到可能存在的 CSS `transform` 属性，可能会得到错误的结果。 `ShouldAccountForPreserve3d` 和 `ShouldAccountForPerspective` 等测试用例确保了 Blink 引擎在进行可视矩形映射时能够正确处理各种 `transform` 效果。
*   **忘记固定定位元素的特性:** 开发者可能会忘记固定定位元素是相对于视口定位的，不会随页面滚动而移动。`FixedContentsInIframe` 和相关的测试用例验证了固定定位元素在滚动场景下的行为。
*   **不理解锚点定位的工作方式:** 开发者可能不清楚锚点定位元素的具体位置会如何随着锚点元素的位置变化而变化，尤其是在滚动容器中。`AnchorPositionScroll` 测试用例帮助验证了这种场景下的计算逻辑。

总而言之，这个测试文件通过大量的单元测试，细致地验证了 Blink 渲染引擎在各种复杂的 CSS 布局场景下，计算和映射元素可视矩形的正确性，这对于确保网页的正确渲染至关重要。

Prompt: 
```
这是目录为blink/renderer/core/layout/visual_rect_mapping_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
position: absolute; top: 0px; left: 0px;
        clip: rect(0px, 200px, 200px, 0px)'>
      <div id='target' style='width: 400px; height: 400px'></div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");

  EXPECT_EQ(PhysicalRect(0, 0, 400, 400), LocalVisualRect(*target));
  CheckPaintInvalidationVisualRect(*target, GetLayoutView(),
                                   PhysicalRect(0, 0, 200, 200));
}

TEST_P(VisualRectMappingTest, ContainPaint) {
  SetBodyInnerHTML(R"HTML(
    <div id='container' style='position: absolute; top: 0px; left: 0px;
        width: 200px; height: 200px; contain: paint'>
      <div id='target' style='width: 400px; height: 400px'></div>
    </div>
  )HTML");

  auto* target = GetLayoutBoxByElementId("target");

  EXPECT_EQ(PhysicalRect(0, 0, 400, 400), LocalVisualRect(*target));
  CheckPaintInvalidationVisualRect(*target, GetLayoutView(),
                                   PhysicalRect(0, 0, 200, 200));
}

TEST_P(VisualRectMappingTest, FloatUnderInline) {
  SetBodyInnerHTML(R"HTML(
    <div style='position: absolute; top: 55px; left: 66px'>
      <span id='span' style='position: relative; top: 100px; left: 200px'>
        <div id='target' style='float: left; width: 33px; height: 44px'>
        </div>
      </span>
    </div>
  )HTML");

  auto* span = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("span"));
  auto* target = GetLayoutBoxByElementId("target");

  PhysicalRect target_visual_rect = LocalVisualRect(*target);
  EXPECT_EQ(PhysicalRect(0, 0, 33, 44), target_visual_rect);

  PhysicalRect rect = target_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  // Inline-level floats are children of their inline-level containers. As such
  // they are positioned relative to their inline-level container, (and shifted
  // by an additional 200,100 in this case).
  EXPECT_EQ(PhysicalRect(266, 155, 33, 44), rect);

  rect = target_visual_rect;

  CheckVisualRect(*target, *span, rect, PhysicalRect(200, 100, 33, 44));
}

TEST_P(VisualRectMappingTest, FloatUnderInlineVerticalRL) {
  SetBodyInnerHTML(R"HTML(
    <div style='position: absolute; writing-mode: vertical-rl;
                top: 55px; left: 66px; width: 600px; height: 400px'>
      <span id='span' style='position: relative; top: 100px; left: -200px'>
        <div id='target' style='float: left; width: 33px; height: 44px'>
        </div>
      </span>
    </div>
  )HTML");

  auto* span = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("span"));
  auto* target = GetLayoutBoxByElementId("target");

  auto target_visual_rect = LocalVisualRect(*target);
  EXPECT_EQ(PhysicalRect(0, 0, 33, 44), target_visual_rect);

  auto rect = target_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  // Inline-level floats are children of their inline-level containers. As such
  // they are positioned relative to their inline-level container, (and shifted
  // by an additional 200,100 in this case).
  EXPECT_EQ(PhysicalRect(66 + 600 - 200 - 33, 55 + 100, 33, 44), rect);

  // An inline object's coordinate space is its containing block's coordinate
  // space shifted by the inline's relative offset. |target|'s left is 100 from
  // the right edge of the coordinate space whose width is 600.
  rect = target_visual_rect;
  CheckVisualRect(*target, *span, rect, PhysicalRect(367, 100, 33, 44));
}

TEST_P(VisualRectMappingTest, InlineBlock) {
  SetBodyInnerHTML(R"HTML(
    <div style="position: absolute; top: 55px; left: 66px">
      <span id="span" style="position: relative; top: 100px; left: 200px">
        <div id="target"
             style="display: inline-block; width: 33px; height: 44px">
        </div>
      </span>
    </div>
  )HTML");

  auto* span = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("span"));
  auto* target = GetLayoutBoxByElementId("target");

  auto target_visual_rect = LocalVisualRect(*target);
  EXPECT_EQ(PhysicalRect(0, 0, 33, 44), target_visual_rect);

  auto rect = target_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(PhysicalRect(266, 155, 33, 44), rect);

  rect = target_visual_rect;
  CheckVisualRect(*target, *span, rect, PhysicalRect(200, 100, 33, 44));
}

TEST_P(VisualRectMappingTest, InlineBlockVerticalRL) {
  SetBodyInnerHTML(R"HTML(
    <div style='position: absolute; writing-mode: vertical-rl;
                top: 55px; left: 66px; width: 600px; height: 400px'>
      <span id="span" style="position: relative; top: 100px; left: -200px">
        <div id="target"
             style="display: inline-block; width: 33px; height: 44px">
        </div>
      </span>
    </div>
  )HTML");

  auto* span = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("span"));
  auto* target = GetLayoutBoxByElementId("target");

  auto target_visual_rect = LocalVisualRect(*target);
  EXPECT_EQ(PhysicalRect(0, 0, 33, 44), target_visual_rect);

  auto rect = target_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(PhysicalRect(66 + 600 - 200 - 33, 155, 33, 44), rect);

  // An inline object's coordinate space is its containing block's coordinate
  // space shifted by the inline's relative offset. |target|'s left is -33 from
  // the right edge of the coordinate space whose width is 600.
  rect = target_visual_rect;
  CheckVisualRect(*target, *span, rect, PhysicalRect(367, 100, 33, 44));
}

TEST_P(VisualRectMappingTest, AbsoluteUnderRelativeInline) {
  SetBodyInnerHTML(R"HTML(
    <div style='position: absolute; top: 55px; left: 66px'>
      <span id='span' style='position: relative; top: 100px; left: 200px'>
        <div id='target' style='position: absolute; top: 50px; left: 100px;
                                width: 33px; height: 44px'>
        </div>
      </span>
    </div>
  )HTML");

  auto* span = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("span"));
  auto* target = GetLayoutBoxByElementId("target");

  auto target_visual_rect = LocalVisualRect(*target);
  EXPECT_EQ(PhysicalRect(0, 0, 33, 44), target_visual_rect);

  auto rect = target_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(PhysicalRect(66 + 200 + 100, 55 + 100 + 50, 33, 44), rect);

  rect = target_visual_rect;
  CheckVisualRect(*target, *span, rect, PhysicalRect(300, 150, 33, 44));
}

TEST_P(VisualRectMappingTest, AbsoluteUnderRelativeInlineVerticalRL) {
  SetBodyInnerHTML(R"HTML(
    <div style='position: absolute; writing-mode: vertical-rl;
                top: 55px; left: 66px; width: 600px; height: 400px'>
      <span id='span' style='position: relative; top: 100px; left: -200px'>
        <div id='target' style='position: absolute; top: 50px; left: 100px;
                                width: 33px; height: 44px'>
        </div>
      </span>
    </div>
  )HTML");

  auto* span = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("span"));
  auto* target = GetLayoutBoxByElementId("target");

  auto target_visual_rect = LocalVisualRect(*target);
  EXPECT_EQ(PhysicalRect(0, 0, 33, 44), target_visual_rect);

  auto rect = target_visual_rect;
  EXPECT_TRUE(target->MapToVisualRectInAncestorSpace(&GetLayoutView(), rect));
  EXPECT_EQ(PhysicalRect(66 + 600 - 200 + 100, 55 + 100 + 50, 33, 44), rect);

  // An inline object's coordinate space is its containing block's coordinate
  // space shifted by the inline's relative offset. |target|'s left is 100 from
  // the right edge of the coordinate space whose width is 600.
  rect = target_visual_rect;
  CheckVisualRect(*target, *span, rect, PhysicalRect(500, 150, 33, 44));
}

TEST_P(VisualRectMappingTest, ShouldAccountForPreserve3d) {
  SetBodyInnerHTML(R"HTML(
    <style>
    * { margin: 0; }
    #container {
      transform: rotateX(-45deg);
      width: 100px; height: 100px;
    }
    #target {
      transform-style: preserve-3d; transform: rotateX(45deg);
      background: lightblue;
      width: 100px; height: 100px;
    }
    </style>
    <div id='container'><div id='target'></div></div>
  )HTML");
  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect original_rect(0, 0, 100, 100);
  // Multiply both matrices together before flattening.
  gfx::Transform matrix = container->Layer()->CurrentTransform();
  matrix.Flatten();
  matrix *= target->Layer()->CurrentTransform();
  PhysicalRect output =
      PhysicalRect::EnclosingRect(matrix.MapRect(gfx::RectF(original_rect)));

  CheckVisualRect(*target, *target->View(), original_rect, output,
                  kContainsToEnclosingRect);
}

TEST_P(VisualRectMappingTest, ShouldAccountForPreserve3dNested) {
  SetBodyInnerHTML(R"HTML(
    <style>
    * { margin: 0; }
    #container {
      transform-style: preserve-3d;
      transform: rotateX(-45deg);
      width: 100px; height: 100px;
    }
    #target {
      transform-style: preserve-3d; transform: rotateX(45deg);
      background: lightblue;
      width: 100px; height: 100px;
    }
    </style>
    <div id='container'><div id='target'></div></div>
  )HTML");
  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect original_rect(0, 0, 100, 100);
  // Multiply both matrices together before flattening.
  gfx::Transform matrix = container->Layer()->CurrentTransform();
  matrix *= target->Layer()->CurrentTransform();
  PhysicalRect output =
      PhysicalRect::EnclosingRect(matrix.MapRect(gfx::RectF(original_rect)));

  CheckVisualRect(*target, *target->View(), original_rect, output);
}

TEST_P(VisualRectMappingTest, ShouldAccountForPerspective) {
  SetBodyInnerHTML(R"HTML(
    <style>
    * { margin: 0; }
    #container {
      transform: rotateX(-45deg); perspective: 100px;
      width: 100px; height: 100px;
    }
    #target {
      transform-style: preserve-3d; transform: rotateX(45deg);
      background: lightblue;
      width: 100px; height: 100px;
    }
    </style>
    <div id='container'><div id='target'></div></div>
  )HTML");
  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect original_rect(0, 0, 100, 100);
  gfx::Transform matrix = container->Layer()->CurrentTransform();
  matrix.Flatten();
  gfx::Transform target_matrix;
  // GetTransformfromContainer includes transform and perspective matrix
  // of the container.
  target->GetTransformFromContainer(container, PhysicalOffset(), target_matrix);
  matrix *= target_matrix;
  PhysicalRect output =
      PhysicalRect::EnclosingRect(matrix.MapRect(gfx::RectF(original_rect)));

  CheckVisualRect(*target, *target->View(), original_rect, output,
                  kContainsToEnclosingRect);
}

TEST_P(VisualRectMappingTest, ShouldAccountForPerspectiveNested) {
  SetBodyInnerHTML(R"HTML(
    <style>
    * { margin: 0; }
    #container {
      transform-style: preserve-3d;
      transform: rotateX(-45deg); perspective: 100px;
      width: 100px; height: 100px;
    }
    #target {
      transform-style: preserve-3d; transform: rotateX(45deg);
      background: lightblue;
      width: 100px; height: 100px;
    }
    </style>
    <div id='container'><div id='target'></div></div>
  )HTML");
  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect original_rect(0, 0, 100, 100);
  gfx::Transform matrix = container->Layer()->CurrentTransform();
  gfx::Transform target_matrix;
  // GetTransformfromContainer includes transform and perspective matrix
  // of the container.
  target->GetTransformFromContainer(container, PhysicalOffset(), target_matrix);
  matrix *= target_matrix;
  PhysicalRect output =
      PhysicalRect::EnclosingRect(matrix.MapRect(gfx::RectF(original_rect)));

  CheckVisualRect(*target, *target->View(), original_rect, output);
}

TEST_P(VisualRectMappingTest, PerspectivePlusScroll) {
  SetBodyInnerHTML(R"HTML(
    <style>
    * { margin: 0; }
    #container {
      perspective: 100px;
      width: 100px; height: 100px;
      overflow: scroll;
    }
    #target {
      transform: rotatex(45eg);
      background: lightblue;
      width: 100px; height: 100px;
    }
    #spacer {
      width: 10px; height:2000px;
    }
    </style>
    <div id='container'>
      <div id='target'></div>
      <div id='spacer'></div>
    </div>
  )HTML");
  auto* container = To<LayoutBlock>(GetLayoutObjectByElementId("container"));
  To<Element>(container->GetNode())->scrollTo(0, 5);
  UpdateAllLifecyclePhasesForTest();

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));
  PhysicalRect originalRect(0, 0, 100, 100);
  gfx::Transform transform;
  target->GetTransformFromContainer(
      container, target->OffsetFromContainer(container), transform);
  transform.Flatten();

  PhysicalRect output =
      PhysicalRect::EnclosingRect(transform.MapRect(gfx::RectF(originalRect)));
  output.Intersect(container->ClippingRect(PhysicalOffset()));
  CheckVisualRect(*target, *target->View(), originalRect, output);
}

TEST_P(VisualRectMappingTest, FixedContentsInIframe) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style> * { margin:0; } </style>
    <iframe src='http://test.com' width='500' height='500' frameBorder='0'>
    </iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>body { margin:0; } ::-webkit-scrollbar { display:none; }</style>
    <div id='forcescroll' style='height:6000px;'></div>
    <div id='fixed' style='
        position:fixed; top:0; left:0; width:400px; height:300px;'>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  auto* fixed =
      ChildDocument().getElementById(AtomicString("fixed"))->GetLayoutObject();
  auto* root_view = fixed->View();
  while (root_view->GetFrame()->OwnerLayoutObject())
    root_view = root_view->GetFrame()->OwnerLayoutObject()->View();

  CheckMapToVisualRectInAncestorSpace(PhysicalRect(0, 0, 400, 300),
                                      PhysicalRect(0, 0, 400, 300), fixed,
                                      root_view, kDefaultVisualRectFlags, true);

  ChildDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 50), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  // The fixed element should not scroll so the mapped visual rect should not
  // have changed.
  CheckMapToVisualRectInAncestorSpace(PhysicalRect(0, 0, 400, 300),
                                      PhysicalRect(0, 0, 400, 300), fixed,
                                      root_view, kDefaultVisualRectFlags, true);
}

TEST_P(VisualRectMappingTest, FixedContentsWithScrollOffset) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; } ::-webkit-scrollbar { display:none; }</style>
    <div id='space' style='height:10px;'></div>
    <div id='ancestor'>
      <div id='fixed' style='
          position:fixed; top:0; left:0; width:400px; height:300px;'>
      </div>
    </div>
    <div id='forcescroll' style='height:1000px;'></div>
  )HTML");

  auto* ancestor = GetLayoutBoxByElementId("ancestor");
  auto* fixed = GetLayoutObjectByElementId("fixed");

  CheckMapToVisualRectInAncestorSpace(PhysicalRect(0, 0, 400, 300),
                                      PhysicalRect(0, -10, 400, 300), fixed,
                                      ancestor, kDefaultVisualRectFlags, true);

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 50), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  // The fixed element does not scroll but the ancestor does which changes the
  // visual rect.
  CheckMapToVisualRectInAncestorSpace(PhysicalRect(0, 0, 400, 300),
                                      PhysicalRect(0, 40, 400, 300), fixed,
                                      ancestor, kDefaultVisualRectFlags, true);
}

TEST_P(VisualRectMappingTest, FixedContentsUnderViewWithScrollOffset) {
  SetPreferCompositingToLCDText(true);
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; } ::-webkit-scrollbar { display:none; }</style>
    <div id='fixed' style='
        position:fixed; top:0; left:0; width:400px; height:300px;'>
    </div>
    <div id='forcescroll' style='height:1000px;'></div>
  )HTML");

  auto* fixed = GetLayoutObjectByElementId("fixed");

  CheckMapToVisualRectInAncestorSpace(
      PhysicalRect(0, 0, 400, 300), PhysicalRect(0, 0, 400, 300), fixed,
      fixed->View(), kDefaultVisualRectFlags, true);

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 50), mojom::blink::ScrollType::kProgrammatic);
  UpdateAllLifecyclePhasesForTest();

  // Results of mapping to ancestor are in absolute coordinates of the
  // ancestor. Therefore a fixed-position element is (reverse) offset by scroll.
  CheckMapToVisualRectInAncestorSpace(
      PhysicalRect(0, 0, 400, 300), PhysicalRect(0, 50, 400, 300), fixed,
      fixed->View(), kDefaultVisualRectFlags, true);
}

TEST_P(VisualRectMappingTest, InclusiveIntersect) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div id='ancestor' style='position: relative'>
      <div style='width: 50px; height: 50px; overflow: hidden'>
        <div id='child' style='width: 10px; height: 10px; position: relative; left: 50px'></div>
      </div>
    </div>
  )HTML");

  auto* ancestor = GetLayoutBoxByElementId("ancestor");
  auto* child = GetLayoutBoxByElementId("child");

  CheckMapToVisualRectInAncestorSpace(PhysicalRect(0, 0, 10, 10),
                                      PhysicalRect(50, 0, 0, 10), child,
                                      ancestor, kEdgeInclusive, true);

  CheckMapToVisualRectInAncestorSpace(PhysicalRect(1, 1, 10, 10),
                                      PhysicalRect(), child, ancestor,
                                      kEdgeInclusive, false);

  CheckMapToVisualRectInAncestorSpace(PhysicalRect(1, 1, 10, 10),
                                      PhysicalRect(1, 1, 10, 10), child, child,
                                      kEdgeInclusive, true);

  CheckMapToVisualRectInAncestorSpace(PhysicalRect(0, 0, 10, 10),
                                      PhysicalRect(), child, ancestor,
                                      kDefaultVisualRectFlags, false);
}

TEST_P(VisualRectMappingTest, Perspective) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div id='ancestor' style='perspective: 100px'>
      <div>
        <div id='child' style='width: 10px; height: 10px;
            transform: rotateY(45deg); position: absolute'></div>
      </div>
    </div>
  )HTML");

  auto* ancestor = GetLayoutBoxByElementId("ancestor");
  auto* child = GetLayoutBoxByElementId("child");

  PhysicalRect rect(0, 0, 10, 10);
  child->MapToVisualRectInAncestorSpace(ancestor, rect);
  EXPECT_EQ(gfx::Rect(1, 0, 8, 10), ToEnclosingRect(rect));
}

TEST_P(VisualRectMappingTest, PerspectiveWithAnonymousTable) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>body { margin:0; }</style>
    <div id='ancestor' style='display: table; perspective: 100px; width: 10px;
        height: 10px;'>
      <div id='child' style='display: table-cell; width: 10px; height: 10px;
          transform: rotateY(45deg); position: absolute'></div>
    </table>
  )HTML");

  auto* ancestor = GetLayoutBoxByElementId("ancestor");
  auto* child = GetLayoutBoxByElementId("child");

  PhysicalRect rect(0, 0, 10, 10);
  child->MapToVisualRectInAncestorSpace(ancestor, rect);
  EXPECT_EQ(gfx::Rect(1, -1, 8, 12), ToEnclosingRect(rect));
}

TEST_P(VisualRectMappingTest, AnchorPositionScroll) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(
    <style>
      #cb {
        position: relative;
        overflow: hidden;
        width: min-content;
        height: min-content;
      }

      #scroller {
        overflow: scroll;
        width: 300px;
        height: 300px;
      }

      #anchor {
        anchor-name: --anchor;
        margin-top: 100px;
        margin-left: 500px;
        margin-right: 500px;
        width: 50px;
        height: 50px;
      }

      #anchored {
        position: absolute;
        left: anchor(--anchor left);
        bottom: anchor(--anchor top);
        width: 50px;
        height: 50px;
        position-anchor: --anchor;
      }
    </style>
    <div id=cb>
      <div id=scroller>
        <div id=anchor></div>
      </div>
      <div id=anchored></div>
   </div>
  )HTML");

  LayoutBox& ancestor = *To<LayoutBox>(GetDocument().body()->GetLayoutObject());
  LayoutBox& anchored = *GetLayoutBoxByElementId("anchored");

  // #anchored is fully clipped by #cb at the initial scroll position
  CheckVisualRect(anchored, ancestor, PhysicalRect(0, 0, 50, 50),
                  PhysicalRect());

  auto* scrollable_area =
      GetScrollableArea(To<LayoutBlock>(GetLayoutBoxByElementId("scroller")));
  scrollable_area->ScrollToAbsolutePosition(gfx::PointF(400, 0));

  // Simulates a frame to update snapshotted scroll offset.
  GetPage().Animator().ServiceScriptedAnimations(
      GetAnimationClock().CurrentTime() + base::Milliseconds(100));
  UpdateAllLifecyclePhasesForTest();

  // #anchored is moved into view and should have a non-empty visual rect
  CheckVisualRect(anchored, ancestor, PhysicalRect(0, 0, 50, 50),
                  PhysicalRect(100, 50, 50, 50));
}

TEST_P(VisualRectMappingTest, IgnoreFilters) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <div id="filter" style="filter: blur(1px)">
        <div id="child"></div>
      </div>
    </div>
  )HTML");

  auto* parent = GetLayoutBoxByElementId("parent");
  auto* filter = GetLayoutBoxByElementId("filter");
  auto* child = GetLayoutBoxByElementId("child");
  PhysicalRect input(0, 0, 50, 50);
  PhysicalRect expected_without_filter = input;
  PhysicalRect expected_with_filter(-3, -3, 56, 56);
  CheckMapToVisualRectInAncestorSpace(input, expected_without_filter, child,
                                      filter, kDefaultVisualRectFlags, true);
  CheckMapToVisualRectInAncestorSpace(input, expected_without_filter, child,
                                      filter, kIgnoreFilters, true);
  CheckMapToVisualRectInAncestorSpace(input, expected_with_filter, child,
                                      parent, kDefaultVisualRectFlags, true);
  CheckMapToVisualRectInAncestorSpace(input, expected_without_filter, child,
                                      parent, kIgnoreFilters, true);
  CheckMapToVisualRectInAncestorSpace(input, expected_with_filter, filter,
                                      parent, kDefaultVisualRectFlags, true);
  CheckMapToVisualRectInAncestorSpace(input, expected_without_filter, filter,
                                      parent, kIgnoreFilters, true);
}

}  // namespace blink

"""


```