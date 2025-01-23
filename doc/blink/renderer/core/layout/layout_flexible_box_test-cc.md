Response:
My thinking process to analyze the provided C++ test file went something like this:

1. **Identify the Core Purpose:**  The filename `layout_flexible_box_test.cc` immediately suggests this file contains tests related to the "flexible box" layout model in the Chromium/Blink rendering engine. This is often referred to as "Flexbox" in web development.

2. **Recognize the Testing Framework:** The presence of `#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"` and the class `LayoutFlexibleBoxTest` inheriting from `RenderingTest` strongly indicates that this is a unit test file within the Blink testing infrastructure. The `TEST_F` macro further confirms this.

3. **Scan for Key Concepts:**  I looked for terms and patterns associated with Flexbox:
    * `display: flex;`
    * `flex-direction: row;`, `flex-direction: column;`, `flex-direction: row-reverse;`, `flex-direction: column-reverse;`
    * `gap:`, `row-gap:`
    * The IDs "flex-box" and "child" suggest a parent-child relationship, common in layout scenarios.
    * `overflow: auto;` hints at testing scrollbar behavior.
    * `writing-mode:` suggests tests involving different text flow directions.
    * `rtl` indicates testing right-to-left layouts.

4. **Analyze the Helper Functions:** The `CommonStyle()` function is a clear setup for common CSS styles used across multiple tests. The `CheckFlexBoxPhysicalGeometries()` function is a crucial helper that performs assertions about the dimensions and positions of the flex container. This suggests a primary focus on the geometric aspects of Flexbox layout.

5. **Examine Individual Tests:** I then looked at the individual `TEST_F` functions. The naming pattern is highly informative:
    * `GeometriesWithScrollbars...` strongly suggests tests specifically focusing on how scrollbars interact with Flexbox layout and how the dimensions and offsets are calculated.
    * The variations in the names (e.g., `RowHTB`, `RowVLR`, `RowReverseVRL`, `RTLRowHTB`) indicate a systematic testing of different combinations of `flex-direction`, `writing-mode`, and directionality (`rtl`).

6. **Connect to Web Technologies (HTML, CSS, JavaScript):** Based on the CSS styles used in the tests, I could directly relate the tests to HTML and CSS features. The tests manipulate the HTML structure (`SetBodyInnerHTML`) and assert the resulting layout. While JavaScript isn't directly present in *this* file, I know that layout calculations are a critical part of how the browser renders web pages, and JavaScript can trigger layout recalculations by manipulating the DOM or CSS styles. The test `ResizedFlexChildRequiresVisualOverflowRecalc` is a prime example of a test that indirectly involves JavaScript's ability to trigger layout changes.

7. **Infer Functionality and Testing Goals:** Based on the above points, I concluded that this file primarily tests the correctness of the Flexbox layout algorithm in Blink, particularly focusing on:
    * Correct calculation of the dimensions (border box, padding box, content box).
    * Accurate positioning of flex items.
    * Proper handling of overflow and scrollbars in different flex configurations and writing modes.
    * Correct behavior in right-to-left layouts.
    * Tracking the usage of the `gap` property.

8. **Construct Examples and Hypotheses:**  To illustrate the connection to web technologies and potential errors, I considered how the CSS properties in the tests would affect the layout in a browser. I formulated hypothetical inputs (CSS properties) and predicted outputs (dimensions, positions). I also thought about common developer errors when working with Flexbox, such as incorrect use of `flex-direction`, misunderstanding how `overflow` interacts with Flexbox, or forgetting about writing modes.

9. **Review and Refine:** Finally, I reviewed my analysis to ensure it was accurate, comprehensive, and addressed all aspects of the prompt. I made sure the examples were clear and relevant to the test cases.

Essentially, I approached the analysis like reverse engineering. I looked at the code, recognized patterns and known concepts, and then pieced together the purpose and functionality of the file within the broader context of web development and the Blink rendering engine.

这是一个名为 `layout_flexible_box_test.cc` 的 C++ 源代码文件，属于 Chromium Blink 引擎。它位于 `blink/renderer/core/layout` 目录下，表明它专注于测试 Blink 引擎中负责 **Flexbox 布局** 的代码。

**主要功能:**

该文件包含了针对 Blink 引擎中 Flexbox 布局功能的单元测试。它通过创建不同的 HTML 结构和 CSS 样式，然后断言布局计算的结果是否符合预期。测试覆盖了各种 Flexbox 的特性和场景，包括：

* **不同的 `flex-direction` 值:** `row`, `column`, `row-reverse`, `column-reverse`。
* **不同的 `writing-mode` 值:** `horizontal-tb`, `vertical-lr`, `vertical-rl` (影响文本流方向，进而影响 Flexbox 的主轴方向)。
* **滚动条:** 测试 Flexbox 容器在出现滚动条时的布局计算，包括滚动区域、滚动偏移等。
* **RTL (Right-to-Left) 布局:** 测试在 `direction: rtl` 下 Flexbox 的布局行为。
* **`gap` 属性:**  测试 `gap`, `row-gap` 属性的使用和计算，并跟踪这些特性的使用情况。
* **布局盒子的几何属性:** 测试 Flexbox 容器及其子元素的物理位置、边框盒、内边距盒、内容盒的矩形区域。
* **视觉溢出 (Visual Overflow):** 测试当 Flexbox 子元素尺寸变化时，是否需要重新计算视觉溢出。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关联到 HTML 和 CSS 的功能，因为 Flexbox 本身就是 CSS 的一个布局模块。

* **HTML:** 测试用例通过 `SetBodyInnerHTML()` 函数动态创建 HTML 结构，用于模拟不同的 Flexbox 布局场景。例如，创建包含一个 Flexbox 容器 (`#flex-box`) 和一个子元素 (`#child`) 的简单结构。
* **CSS:** 测试用例使用内联样式或 `<style>` 标签定义 CSS 样式，来配置 Flexbox 容器的属性，例如 `display: flex;`、`flex-direction`、`width`、`height`、`overflow`、`padding`、`border`、`writing-mode`、`direction` 和 `gap` 等。
* **JavaScript:** 虽然这个测试文件本身是 C++ 代码，但它测试的 Flexbox 功能最终会被 JavaScript 代码所触发和影响。当 JavaScript 修改 DOM 结构或 CSS 样式时，Blink 引擎会重新计算布局，而这些 C++ 测试保证了布局计算的正确性。例如，`ResizedFlexChildRequiresVisualOverflowRecalc` 这个测试模拟了 JavaScript 修改子元素样式后，Flexbox 布局的更新行为。

**举例说明:**

1. **`flex-direction: row;` (CSS) 对布局的影响:**
   * **假设输入:**
     ```html
     <div id="flex-box" class="row htb">
       <div id="child"></div>
     </div>
     ```
     CSS 中 `.row { flex-direction: row; }`。
   * **输出 (部分):**  测试会断言子元素 `#child` 相对于父元素 `#flex-box` 的物理位置 (例如，通过 `child->PhysicalLocation()`)。当 `flex-direction` 为 `row` 时，子元素会沿着水平方向排列。

2. **`overflow: auto;` (CSS) 对滚动条和布局的影响:**
   * **假设输入:**
     ```html
     <div id="flex-box" class="row htb" style="overflow: auto; width: 400px; height: 300px;">
       <div id="child" style="width: 2000px; height: 1000px;"></div>
     </div>
     ```
   * **输出 (部分):** 测试会断言 Flexbox 容器的滚动区域 (`flex_box->ScrollableOverflowRect()`)、最大滚动偏移 (`scrollable_area->MaximumScrollOffsetInt()`) 等属性。由于子元素尺寸大于容器，会出现滚动条，测试会验证滚动相关的计算是否正确。

3. **`direction: rtl;` (CSS) 对布局的影响:**
   * **假设输入:**
     ```html
     <div id="flex-box" class="rtl row htb">
       <div id="child"></div>
     </div>
     ```
     CSS 中 `.rtl { direction: rtl; }`。
   * **输出 (部分):**  测试会断言在 RTL 布局下，子元素的起始位置会发生变化，例如，子元素会从父元素的右侧开始排列。

4. **`gap: 20%;` (CSS) 对布局的影响:**
   * **假设输入:**
     ```html
     <div id="flex-box" style="gap: 20%;"></div>
     ```
   * **输出:** 测试会验证 `gap` 属性是否被正确解析和应用，并会记录该特性的使用情况 (通过 `GetDocument().IsUseCounted()`)。

**逻辑推理的假设输入与输出:**

以 `GeometriesWithScrollbarsRowHTB` 测试为例：

* **假设输入 (HTML/CSS):**
  ```html
  <style>
    /* ... CommonStyle ... */
  </style>
  <div id="flex-box" class="row htb">
    <div id="child"></div>
  </div>
  ```
  其中 `CommonStyle` 定义了 Flexbox 容器和子元素的默认样式。
* **预期输出 (部分):**
    * `flex_box->PhysicalBorderBoxRect()` 应该等于 `PhysicalRect(0, 0, 540, 400)` (考虑了边框)。
    * `flex_box->PhysicalPaddingBoxRect()` 应该等于 `PhysicalRect(50, 20, 445, 324)` (考虑了内边距)。
    * `child->PhysicalLocation()` 应该等于 `PhysicalOffset(90, 30)` (子元素相对于父元素的偏移)。
    * `scrollable_area->MaximumScrollOffsetInt()` 应该等于 `gfx::Vector2d(1615, 716)` (最大滚动距离)。

**用户或编程常见的使用错误举例:**

1. **未设置 `display: flex;`:**  如果忘记在父元素上设置 `display: flex;`，子元素的 `flex-*` 属性将不会生效，导致布局与预期不符。测试用例确保了在设置了 `display: flex;` 的情况下，布局行为是正确的。

2. **对 `flex-direction` 的理解错误:** 开发者可能混淆 `row` 和 `column`，或者不清楚 `row-reverse` 和 `column-reverse` 的作用，导致元素排列方向错误。测试用例针对不同的 `flex-direction` 进行了覆盖。

3. **不理解 `overflow` 对 Flexbox 的影响:**  当 Flexbox 容器没有足够的空间容纳所有子元素时，`overflow` 属性决定了如何处理溢出。开发者可能没有正确设置 `overflow`，导致内容被裁剪或出现不希望的滚动条。测试用例专门测试了带有 `overflow: auto;` 的 Flexbox 布局。

4. **RTL 布局下的混淆:** 在处理多语言网站时，开发者可能对 RTL 布局下 Flexbox 的行为感到困惑，例如主轴方向的反转。测试用例覆盖了 RTL 场景，帮助确保 Blink 引擎在 RTL 布局下的正确性。

5. **`gap` 属性的兼容性问题:**  虽然 `gap` 属性现在被广泛支持，但在一些旧版本的浏览器中可能不支持。测试用例跟踪了 `gap` 属性的使用情况，这可能与 Chromium 的特性使用统计有关。

总而言之，`layout_flexible_box_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中 Flexbox 布局功能的正确性和稳定性，为开发者提供可靠的布局能力。这些测试涵盖了 Flexbox 的各种特性和边缘情况，有助于及早发现和修复潜在的 bug。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_flexible_box_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class LayoutFlexibleBoxTest : public RenderingTest {
 public:
  LayoutFlexibleBoxTest() = default;

 protected:
  void ExpectSameAsRowHTB();
  void ExpectSameAsRowVLR();
  void ExpectSameAsRowVRL();
  void ExpectSameAsRowReverseVLR();
  void ExpectSameAsRowReverseVRL();
  void ExpectSameAsRTLRowHTB();
};

static String CommonStyle() {
  return R"HTML(
    <style>
      ::-webkit-scrollbar { width: 15px; height: 16px; background: yellow; }
      .rtl { direction: rtl; }
      .htb { writing-mode: horizontal-tb; }
      .vlr { writing-mode: vertical-lr; }
      .vrl { writing-mode: vertical-rl; }
      .row { flex-direction: row; }
      .row-reverse { flex-direction: row-reverse; }
      .column { flex-direction: column; }
      .column-reverse { flex-direction: column-reverse; }
      #flex-box {
        display: flex;
        width: 400px;
        height: 300px;
        overflow: auto;
        padding: 10px 20px 30px 40px;
        border-width: 20px 30px 40px 50px;
        border-style: solid;
      }
      #child {
        width: 2000px;
        height: 1000px;
        flex: none;
      }
    </style>
  )HTML";
}

static void CheckFlexBoxPhysicalGeometries(const LayoutBox* flex_box) {
  // 540 = border_left + padding_left + width + padding_right + border_right
  // 400 = border_top + padding_top + height + padding_bottom + border_bottom
  EXPECT_EQ(PhysicalRect(0, 0, 540, 400), flex_box->PhysicalBorderBoxRect());
  if (!flex_box->ShouldPlaceVerticalScrollbarOnLeft()) {
    // This excludes borders and scrollbars from BorderBoxRect.
    EXPECT_EQ(PhysicalRect(50, 20, 445, 324),
              flex_box->PhysicalPaddingBoxRect());
    // This excludes paddings from PhysicalPaddingBoxRect.
    EXPECT_EQ(PhysicalRect(90, 30, 385, 284),
              flex_box->PhysicalContentBoxRect());
  } else {
    // There is scrollbar on the left, so shift content to the right.
    EXPECT_EQ(PhysicalRect(65, 20, 445, 324),
              flex_box->PhysicalPaddingBoxRect());
    EXPECT_EQ(PhysicalRect(105, 30, 385, 284),
              flex_box->PhysicalContentBoxRect());
  }

  EXPECT_EQ(PhysicalOffset(), flex_box->ScrolledContentOffset());
  EXPECT_EQ(ScrollOffset(), flex_box->GetScrollableArea()->GetScrollOffset());
}

void LayoutFlexibleBoxTest::ExpectSameAsRowHTB() {
  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  // 1040 = child_height (1000) + padding_top (10) + padding_bottom (30)
  EXPECT_EQ(PhysicalRect(50, 20, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 716),
            scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(90, 30), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRowHTB) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="row htb">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowHTB();
}

void LayoutFlexibleBoxTest::ExpectSameAsRowVLR() {
  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(50, 20, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 716),
            scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(90, 30), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRowVLR) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="row vlr">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowVLR();
}

void LayoutFlexibleBoxTest::ExpectSameAsRowVRL() {
  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(-1565, 20, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(0, 716), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(-1615, 0), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(1615, 0), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(1615, 0), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  // 65 = border_right (30) + padding_right (20) + vertical_scrollbar_width (15)
  // -1525 = full_flex_box_width (540) - 65 - child_width (2000))
  EXPECT_EQ(PhysicalOffset(-1525, 30), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRowVRL) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="row vrl">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowVRL();
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRowReverseHTB) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="row-reverse htb">
      <div id="child"></div>
    </div>
  )HTML");

  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(-1565, 20, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(0, 716), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(-1615, 0), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(1615, 0), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(1615, 0), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(-1525, 30), child->PhysicalLocation());
}

void LayoutFlexibleBoxTest::ExpectSameAsRowReverseVLR() {
  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(50, -696, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 0), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(0, -716), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(0, 716), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(0, 716), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(90, -686), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRowReverseVLR) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="row-reverse vlr">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowReverseVLR();
}

void LayoutFlexibleBoxTest::ExpectSameAsRowReverseVRL() {
  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(-1565, -696, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(-1615, -716),
            scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(1615, 716), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(1615, 716), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  // 65 = border_right (30) + padding_right (20) + vertical_scrollbar_width (15)
  // -1525 = full_flex_box_width (540) - 65 - child_width (2000))
  EXPECT_EQ(PhysicalOffset(-1525, -686), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRowReverseVRL) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="row-reverse vrl">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowReverseVRL();
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsColumnHTB) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="column htb">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowHTB();
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsColumnVLR) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="column vlr">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowVLR();
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsColumnVRL) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="column vrl">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowVRL();
}

// The numbers in the following tests are just different combinations of the
// numbers in the above tests. See the explanation of the same number in the
// above tests for the steps of calculations.

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsColumnReverseHTB) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="column-reverse htb">
      <div id="child"></div>
    </div>
  )HTML");

  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(50, -696, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 0), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(0, -716), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(0, 716), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(0, 716), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(90, -686), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsColumnReverseVLR) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="column-reverse vlr">
      <div id="child"></div>
    </div>
  )HTML");

  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(-1565, 20, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(0, 716), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(-1615, 0), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(1615, 0), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(1615, 0), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(-1525, 30), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsColumnReverseVRL) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="column-reverse vrl">
      <div id="child"></div>
    </div>
  )HTML");

  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  EXPECT_EQ(gfx::Vector2d(), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(50, 20, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 716),
            scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(90, 30), child->PhysicalLocation());
}

void LayoutFlexibleBoxTest::ExpectSameAsRTLRowHTB() {
  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  // Additional origin due to the scrollbar on the left.
  EXPECT_EQ(gfx::Vector2d(15, 0), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(-1550, 20, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(0, 716), scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(-1615, 0), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(1615, 0), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(1615, 0), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(-1510, 30), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRTLRowHTB) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="rtl row htb">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRTLRowHTB();
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRTLRowVLR) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="rtl row vlr">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowReverseVLR();
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRTLRowVRL) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="rtl row vrl">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowReverseVRL();
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRTLRowReverseHTB) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="rtl row-reverse htb">
      <div id="child"></div>
    </div>
  )HTML");

  const auto* flex_box = GetLayoutBoxByElementId("flex-box");
  const auto* scrollable_area = flex_box->GetScrollableArea();
  CheckFlexBoxPhysicalGeometries(flex_box);

  // Additional origin due to the scrollbar on the left.
  EXPECT_EQ(gfx::Vector2d(15, 0), flex_box->OriginAdjustmentForScrollbars());
  EXPECT_EQ(PhysicalRect(65, 20, 2060, 1040),
            flex_box->ScrollableOverflowRect());
  EXPECT_EQ(gfx::Vector2d(1615, 716),
            scrollable_area->MaximumScrollOffsetInt());
  EXPECT_EQ(gfx::Vector2d(0, 0), scrollable_area->MinimumScrollOffsetInt());
  EXPECT_EQ(gfx::Point(0, 0), scrollable_area->ScrollOrigin());
  EXPECT_EQ(gfx::PointF(0, 0), scrollable_area->ScrollPosition());

  const auto* child = GetLayoutBoxByElementId("child");
  EXPECT_EQ(PhysicalOffset(105, 30), child->PhysicalLocation());
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRTLRowReverseVLR) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="rtl row-reverse vlr">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowVLR();
}

TEST_F(LayoutFlexibleBoxTest, GeometriesWithScrollbarsRTLRowReverseVRL) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" class="rtl row-reverse vrl">
      <div id="child"></div>
    </div>
  )HTML");
  ExpectSameAsRowVRL();
}

TEST_F(LayoutFlexibleBoxTest, ResizedFlexChildRequiresVisualOverflowRecalc) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        display: flex;
        flex-direction: column;
        width: 100px;
        height: 1000px;
      }
      #child1 {
        flex-grow: 1;
        width: 100px;
        will-change: transform;
      }
      #overflow-child {
        width: 100px;
        height: 950px;
        box-shadow: 5px 10px;
      }
      #child2 {
        width: 100px;
      }
    </style>
    <div id="parent">
      <div id="child1">
        <div id="overflow-child"></div>
      </div>
      <div id="child2"></div>
    </div>
  )HTML");
  auto* child1_element = GetElementById("child1");
  auto* child2_element = GetElementById("child2");
  child2_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("height: 100px;"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  auto* child1_box = To<LayoutBox>(child1_element->GetLayoutObject());
  ASSERT_TRUE(child1_box->HasSelfPaintingLayer());
  EXPECT_TRUE(child1_box->Layer()->NeedsVisualOverflowRecalc());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(child1_box->VisualOverflowRect(), PhysicalRect(0, 0, 105, 960));
}

TEST_F(LayoutFlexibleBoxTest, PercentDefiniteGapUseCounter) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div id="flex-box" style="gap: 20%;"></div>
  )HTML");
  RunDocumentLifecycle();

  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kFlexGapPositive));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kFlexGapSpecified));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kFlexRowGapPercent));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kFlexRowGapPercentIndefinite));
}

TEST_F(LayoutFlexibleBoxTest, PercentIndefiniteGapUseCounter) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div style="display: flex; row-gap: 20%;"></div>
  )HTML");
  RunDocumentLifecycle();

  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kFlexGapPositive));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kFlexGapSpecified));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kFlexRowGapPercent));
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kFlexRowGapPercentIndefinite));
}

TEST_F(LayoutFlexibleBoxTest, ZeroGapUseCounter) {
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div style="display: flex; gap: 0;"></div>
  )HTML");
  RunDocumentLifecycle();

  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kFlexGapPositive));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kFlexGapSpecified));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kFlexRowGapPercent));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kFlexRowGapPercentIndefinite));
}

TEST_F(LayoutFlexibleBoxTest, NormalGapUseCounter) {
  // 'normal' is the initial value. It resolves to non-zero for multi-col but 0
  // for flex.
  SetBodyInnerHTML(CommonStyle() + R"HTML(
    <div style="display: flex; gap: normal"></div>
    <div style="display: flex; gap: auto"></div>
    <div style="display: flex; gap: initial"></div>
    <div style="display: flex; gap: -10px"></div>
    <div style="display: flex; gap: 1hz"></div>
  )HTML");
  RunDocumentLifecycle();

  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kFlexGapPositive));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kFlexGapSpecified));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kFlexRowGapPercent));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kFlexRowGapPercentIndefinite));
}

}  // namespace blink
```