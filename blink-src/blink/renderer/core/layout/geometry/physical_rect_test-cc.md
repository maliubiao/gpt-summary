Response:
The user wants to understand the functionality of the `physical_rect_test.cc` file in the Chromium Blink engine. This file is a unit test file for the `PhysicalRect` class. I need to go through each test case and explain what it's testing. I should also look for connections to web technologies (JavaScript, HTML, CSS) and common usage errors.

**Breakdown of the request:**

1. **List the functionalities:** I will describe what each test case in the file verifies about the `PhysicalRect` class.
2. **Relate to JavaScript, HTML, CSS:** I will consider how the `PhysicalRect` class might be used in the rendering process and connect it to these web technologies.
3. **Logical Reasoning (Input/Output):** For test cases involving calculations or comparisons, I can explain the logic and provide example inputs and expected outputs.
4. **Common Usage Errors:** I need to think about how developers might misuse the `PhysicalRect` class or related concepts.

**Specific Tests and their functionalities:**

*   `AddOffset`: Tests adding a `PhysicalOffset` to a `PhysicalRect`.
*   `PhysicalRectUniteTest`: Tests the `Unite` method, which calculates the smallest rectangle containing two given rectangles.
*   `SquaredDistanceTo`: Tests calculating the squared distance between a point (`PhysicalOffset`) and a rectangle.
*   `InclusiveIntersect`: Tests the `InclusiveIntersect` method, which modifies a rectangle to be the intersection with another, including cases where they only touch.
*   `IntersectsInclusively`: Tests the `IntersectsInclusively` method, which checks if two rectangles intersect, including cases where they only touch.
*   `ToEnclosingRect`: Tests converting a `PhysicalRect` (which can have fractional values) to an enclosing `gfx::Rect` (which uses integer values).
*   `EdgesOnPixelBoundaries`: Tests whether the edges of a `PhysicalRect` align with pixel boundaries.
*   `ExpandEdgesToPixelBoundaries`: Tests the `ExpandEdgesToPixelBoundaries` method, which modifies a rectangle to have edges aligned with pixel boundaries.
*   `InfiniteIntRect`: Tests the interaction of `PhysicalRect` with infinite rectangles.

**Connecting to Web Technologies:**

*   Layout: The core purpose of `PhysicalRect` is to represent the position and size of elements during layout. This directly relates to how HTML elements are positioned and sized on the page. CSS properties like `top`, `left`, `width`, `height`, `margin`, `padding`, and `border` influence the dimensions and positions that `PhysicalRect` objects represent.
*   JavaScript Manipulation: JavaScript can read and sometimes modify the layout properties of elements (e.g., using `getBoundingClientRect()`). The values returned by such methods are conceptually related to what `PhysicalRect` stores.
*   Hit Testing: Methods like `SquaredDistanceTo` and intersection checks are relevant for event handling. The browser needs to determine if a mouse click or touch event occurred within the bounds of a specific element.

**Identifying Potential Errors:**

*   Mixing integer and fractional values:  Care needs to be taken when converting between `PhysicalRect` (fractional) and `gfx::Rect` (integer) to avoid precision loss or unexpected rounding.
*   Incorrectly calculating intersections: Misunderstanding the inclusive nature of intersection checks could lead to errors in hit testing or visibility calculations.
*   Assuming pixel alignment: Not all layout units correspond directly to pixels, especially on high-DPI screens. Methods like `EdgesOnPixelBoundaries` highlight the importance of considering device pixel ratios.

Now I can proceed with generating the detailed explanation.
这个文件 `physical_rect_test.cc` 是 Chromium Blink 引擎中用于测试 `PhysicalRect` 类的单元测试文件。 `PhysicalRect` 类在 Blink 渲染引擎中用于表示屏幕上的一个矩形区域，它的坐标和尺寸可以是非整数值（使用 `LayoutUnit` 类型）。

以下是该文件中的各个测试用例及其功能：

**核心功能测试:**

1. **`TEST(PhysicalRectTest, AddOffset)`**: 测试 `PhysicalRect` 对象与 `PhysicalOffset` 对象相加的功能。
    *   **功能:** 验证将一个偏移量添加到矩形的坐标后，矩形的位置是否正确更新。
    *   **假设输入与输出:**
        *   **假设输入:** `PhysicalRect` 对象 `(1, 2, 3, 4)`，`PhysicalOffset` 对象 `(5, 6)`
        *   **预期输出:**  新的 `PhysicalRect` 对象 `(6, 8, 3, 4)` (只有 x 和 y 坐标被偏移)

2. **`TEST_P(PhysicalRectUniteTest, Data)` 和相关的 `physical_offset_rect_unite_test_data`**: 测试 `PhysicalRect` 对象的 `Unite` 方法，该方法计算包含两个矩形的最小矩形。
    *   **功能:** 验证计算两个矩形并集的逻辑是否正确，包括各种边缘情况，如空矩形和饱和尺寸的情况。
    *   **与 HTML/CSS 的关系:** 当浏览器需要确定包含多个元素或区域的最小边界时，可能会用到这种计算。例如，计算包含多个 inline 元素的 bounding box，或者计算由于某些动画或变换而扩展的元素的最终边界。
    *   **假设输入与输出 (以 `a larger` 为例):**
        *   **假设输入:** `PhysicalRect a(100, 50, 300, 200)`, `PhysicalRect b(200, 50, 200, 200)`
        *   **预期输出:** `PhysicalRect(100, 50, 300, 200)` (因为 a 包含了 b)
    *   **假设输入与输出 (以 `saturated width` 为例):**
        *   **假设输入:** `PhysicalRect a(-1000, 0, 200, 200)`, `PhysicalRect b(33554402, 500, 30, 100)`
        *   **预期输出:** `PhysicalRect(0, 0, 99999999, 600)` (测试宽度饱和的情况，最大宽度会被限制)

3. **`TEST(PhysicalRectTest, SquaredDistanceTo)`**: 测试计算一个点到 `PhysicalRect` 的平方距离的功能。
    *   **功能:** 验证计算点到矩形不同位置（角落、边缘、内部）的平方距离是否正确。
    *   **与 JavaScript 的关系:**  在事件处理中，例如判断鼠标点击是否在一个元素的特定区域附近时，这种距离计算可能被用到。
    *   **假设输入与输出 (以 `over the top-left corner` 为例):**
        *   **假设输入:** `PhysicalRect rect(0, 0, 200, 200)`, `PhysicalOffset(-10, -10)`
        *   **预期输出:** `200` (计算点 (-10, -10) 到矩形 (0, 0, 200, 200) 左上角的平方距离)
    *   **假设输入与输出 (以 `contained` 为例):**
        *   **假设输入:** `PhysicalRect rect(0, 0, 200, 200)`, `PhysicalOffset(10, 190)`
        *   **预期输出:** `0` (因为点 (10, 190) 在矩形内部，距离为 0)

4. **`TEST(PhysicalRectTest, InclusiveIntersect)`**: 测试 `PhysicalRect` 对象的 `InclusiveIntersect` 方法，该方法计算与另一个矩形的交集，包括边缘和角落接触的情况。
    *   **功能:** 验证计算两个矩形的包含性交集是否正确。如果两个矩形只是边缘或角落接触，也算作相交。
    *   **与 HTML/CSS 的关系:**  在布局计算和碰撞检测中很有用。例如，判断两个元素是否重叠或接触。
    *   **假设输入与输出 (以 `rect(11, 12, 0, 0)` 和 `PhysicalRect(11, 12, 13, 14)` 为例):**
        *   **假设输入:** `PhysicalRect rect(11, 12, 0, 0)`, `PhysicalRect(11, 12, 13, 14)`
        *   **预期输出:** `rect` 仍然是 `PhysicalRect(11, 12, 0, 0)`，因为空矩形与任何矩形的交集都是空矩形。但是 `InclusiveIntersect` 方法会返回 `true`，表示存在包含性交集（因为它们共享一个点）。

5. **`TEST(PhysicalRectTest, IntersectsInclusively)`**: 测试 `PhysicalRect` 对象的 `IntersectsInclusively` 方法，该方法检查两个矩形是否包含性相交（包括边缘和角落接触的情况）。
    *   **功能:** 验证判断两个矩形是否包含性相交的逻辑是否正确。
    *   **与 HTML/CSS 的关系:**  类似于 `InclusiveIntersect`，用于布局和碰撞检测。
    *   **假设输入与输出 (以 `a(10, 10, 10, 10)` 和 `b(20, 20, 10, 10)` 为例):**
        *   **假设输入:** `PhysicalRect a(10, 10, 10, 10)`, `PhysicalRect b(20, 20, 10, 10)`
        *   **预期输出:** `true` (因为这两个矩形在点 (20, 20) 处接触)
    *   **假设输入与输出 (以两个不接触的空矩形为例):**
        *   **假设输入:** `PhysicalRect a(11, 12, 0, 0)`, `PhysicalRect b(20, 21, 0, 0)`
        *   **预期输出:** `false` (因为这两个空矩形没有接触)

6. **`TEST(PhysicalRectTest, ToEnclosingRect)`**: 测试将 `PhysicalRect` 转换为 `gfx::Rect` 的功能，`gfx::Rect` 使用整数坐标，因此需要进行包围处理。
    *   **功能:** 验证将可能包含浮点数值的 `PhysicalRect` 转换为包含它的最小整数矩形是否正确。
    *   **与 CSS 的关系:**  CSS 中的布局计算可能会产生浮点数，最终渲染到屏幕上的像素时需要转换为整数。
    *   **假设输入与输出 (以 `small_dimensions_rect` 为例):**
        *   **假设输入:** `PhysicalRect small_dimensions_rect(LayoutUnit(42.5f), LayoutUnit(84.5f), small, small)` (假设 `small` 的值为 1)
        *   **预期输出:** `gfx::Rect(42, 84, 1, 1)` (浮点数坐标向下取整，尺寸不变)
    *   **假设输入与输出 (以 `fractional_pos_rect` 为例):**
        *   **假设输入:** `PhysicalRect fractional_pos_rect(LayoutUnit(100.6f), LayoutUnit(150.8f), LayoutUnit(200), LayoutUnit(350))`
        *   **预期输出:** `gfx::Rect(100, 150, 201, 351)` (浮点数坐标向下取整，为了包围原始矩形，尺寸需要向上调整)

7. **`TEST(PhysicalRectTest, EdgesOnPixelBoundaries)`**: 测试判断 `PhysicalRect` 的边缘是否与像素边界对齐的功能。
    *   **功能:** 验证判断矩形的边缘坐标是否为整数。
    *   **与 CSS 的关系:**  在渲染过程中，判断元素是否对齐像素边界对于避免模糊和提高渲染效率很重要。
    *   **假设输入与输出:**
        *   **假设输入:** `PhysicalRect(1, 1, 1, 1)`
        *   **预期输出:** `true`
        *   **假设输入:** `PhysicalRect(LayoutUnit(9.3f), LayoutUnit(5), LayoutUnit(10), LayoutUnit(3))`
        *   **预期输出:** `false`

8. **`TEST(PhysicalRectTest, ExpandEdgesToPixelBoundaries)`**: 测试将 `PhysicalRect` 的边缘扩展到最近的像素边界的功能。
    *   **功能:** 验证将矩形的坐标和尺寸调整为整数，使其边缘与像素边界对齐。
    *   **与 CSS 的关系:**  在某些情况下，为了获得清晰的渲染效果，需要将元素的边界对齐到像素边界。
    *   **假设输入与输出 (以 `fractional_pos_rect` 为例):**
        *   **假设输入:** `PhysicalRect fractional_pos_rect(LayoutUnit(100.6f), LayoutUnit(150.8f), LayoutUnit(200), LayoutUnit(350))`
        *   **预期输出:** `PhysicalRect(100, 150, 201, 351)` (与 `ToEnclosingRect` 类似)

9. **`TEST(PhysicalRectTest, InfiniteIntRect)`**: 测试 `PhysicalRect` 与无限大的整数矩形的交互。
    *   **功能:** 验证 `PhysicalRect` 可以处理无限大的矩形，并且可以无损地在 `PhysicalRect` 和 `gfx::Rect` 之间转换。
    *   **与 HTML/CSS 的关系:**  虽然实际的元素不会是无限大的，但在某些内部计算或特殊情况下，可能会使用无限大的矩形作为初始值或边界。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript 和 `getBoundingClientRect()`:** JavaScript 可以使用 `element.getBoundingClientRect()` 方法获取元素相对于视口的矩形信息。这个方法返回的 `DOMRect` 对象包含 `top`, `left`, `right`, `bottom`, `width`, `height` 等属性，这些属性的概念与 `PhysicalRect` 表示的矩形信息非常相似。例如，`getBoundingClientRect()` 返回的坐标可能是浮点数，类似于 `PhysicalRect` 可以处理非整数值。

*   **CSS 布局:** CSS 样式决定了 HTML 元素的布局和尺寸。例如，一个 `div` 元素的 CSS 属性 `width: 100px; height: 50px; top: 20px; left: 30px;` 会在渲染引擎内部被转换为类似于 `PhysicalRect(30, 20, 100, 50)` 的表示。

*   **CSS 变换和动画:** 当使用 CSS 变换 (如 `transform: translate(10.5px, 20.3px)`) 或动画时，元素的最终位置和尺寸可能包含小数。`PhysicalRect` 可以精确地表示这些带有小数的矩形信息。

**逻辑推理的假设输入与输出 (更详细的例子):**

*   **`SquaredDistanceTo` - 假设点在矩形内部:**
    *   **假设输入:** `PhysicalRect rect(10, 10, 100, 100)`, `PhysicalOffset(50, 50)`
    *   **逻辑推理:** 点 (50, 50) 在矩形 (10, 10, 100, 100) 内部，因此到矩形的距离为 0。
    *   **预期输出:** `0`

*   **`InclusiveIntersect` - 假设两个矩形边缘接触:**
    *   **假设输入:** `PhysicalRect rect1(0, 0, 10, 10)`, `PhysicalRect rect2(10, 0, 5, 5)`
    *   **逻辑推理:** `rect1` 的右边缘与 `rect2` 的左边缘重合。`InclusiveIntersect` 会将 `rect1` 修改为它们的交集，即一个宽度为 0 的矩形。
    *   **预期输出:** `rect1` 变为 `PhysicalRect(10, 0, 0, 5)`，方法返回 `true`。

**涉及用户或者编程常见的使用错误:**

1. **精度丢失:** 在将 `PhysicalRect` 转换为整数矩形 (如 `gfx::Rect`) 时，如果没有正确处理浮点数，可能会导致精度丢失，尤其是在进行多次转换或计算后。例如，多次使用 `ToEnclosingRect` 可能会累积误差。

2. **不理解包含性交集:** 开发者可能错误地认为只有当两个矩形有面积重叠时才算相交，而忽略了边缘或角落接触的情况。这可能导致在处理元素边界或碰撞检测时出现逻辑错误。例如，在判断鼠标是否悬停在两个相邻元素之间的边界上时，需要考虑包含性交集。

3. **混淆 `PhysicalRect` 和像素坐标:** 开发者可能会错误地将 `PhysicalRect` 中的值直接当作像素坐标使用，而忽略了设备像素比 (DPR) 等因素。`PhysicalRect` 使用的是逻辑单位，可能需要进行转换才能得到实际的像素坐标。

4. **不恰当的饱和处理:** 在处理非常大的矩形时，可能会遇到饱和的情况。如果开发者没有意识到 `Unite` 等操作可能会导致尺寸饱和，可能会导致意外的布局或渲染问题。

总而言之，`physical_rect_test.cc` 文件通过各种测试用例，确保 `PhysicalRect` 类在处理矩形相关的操作时能够正确地工作，这对于 Blink 引擎的布局和渲染功能至关重要。这些功能直接影响着网页在浏览器中的呈现效果和用户交互。

Prompt: 
```
这是目录为blink/renderer/core/layout/geometry/physical_rect_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/geometry/infinite_int_rect.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

namespace {

TEST(PhysicalRectTest, AddOffset) {
  test::TaskEnvironment task_environment;
  EXPECT_EQ(PhysicalRect(1, 2, 3, 4) + PhysicalOffset(5, 6),
            PhysicalRect(6, 8, 3, 4));
}

struct PhysicalOffsetRectUniteTestData {
  const char* test_case;
  PhysicalRect a;
  PhysicalRect b;
  PhysicalRect expected;
} physical_offset_rect_unite_test_data[] = {
    {"all_empty", {}, {}, {}},
    {"a empty", {}, {1, 2, 3, 4}, {1, 2, 3, 4}},
    {"b empty", {1, 2, 3, 4}, {}, {1, 2, 3, 4}},
    {"a larger", {100, 50, 300, 200}, {200, 50, 200, 200}, {100, 50, 300, 200}},
    {"b larger", {200, 50, 200, 200}, {100, 50, 300, 200}, {100, 50, 300, 200}},
    {"saturated width",
     {-1000, 0, 200, 200},
     {33554402, 500, 30, 100},
     {0, 0, 99999999, 600}},
    {"saturated height",
     {0, -1000, 200, 200},
     {0, 33554402, 100, 30},
     {0, 0, 200, 99999999}},
};

std::ostream& operator<<(std::ostream& os,
                         const PhysicalOffsetRectUniteTestData& data) {
  return os << "Unite " << data.test_case;
}

class PhysicalRectUniteTest
    : public testing::Test,
      public testing::WithParamInterface<PhysicalOffsetRectUniteTestData> {};

INSTANTIATE_TEST_SUITE_P(
    GeometryUnitsTest,
    PhysicalRectUniteTest,
    testing::ValuesIn(physical_offset_rect_unite_test_data));

TEST_P(PhysicalRectUniteTest, Data) {
  const auto& data = GetParam();
  PhysicalRect actual = data.a;
  actual.Unite(data.b);
  auto expected = data.expected;
  constexpr int kExtraForSaturation = 2000;
  // On arm, you cannot actually get the true saturated value just by
  // setting via LayoutUnit constructor. Instead, add to the expected
  // value to actually get a saturated expectation (which is what happens in
  // the Unite operation).
  if (data.expected.size.width == GetMaxSaturatedSetResultForTesting()) {
    expected.size.width += kExtraForSaturation;
  }

  if (data.expected.size.height == GetMaxSaturatedSetResultForTesting()) {
    expected.size.height += kExtraForSaturation;
  }
  EXPECT_EQ(expected, actual);
}

TEST(PhysicalRectTest, SquaredDistanceTo) {
  test::TaskEnvironment task_environment;
  PhysicalRect rect(0, 0, 200, 200);
  EXPECT_EQ(200, rect.SquaredDistanceTo(PhysicalOffset(-10, -10)))
      << "over the top-left corner";
  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(0, 0)))
      << "on the top-left corner";
  EXPECT_EQ(100, rect.SquaredDistanceTo(PhysicalOffset(10, -10)))
      << "over the top edge";
  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(10, 0)))
      << "on the top edge";
  EXPECT_EQ(200, rect.SquaredDistanceTo(PhysicalOffset(210, -10)))
      << "over the top-right corner";
  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(200, 0)))
      << "on the top-right corner";
  EXPECT_EQ(100, rect.SquaredDistanceTo(PhysicalOffset(210, 10)))
      << "over the right edge";
  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(200, 10)))
      << "on the right edge";
  EXPECT_EQ(200, rect.SquaredDistanceTo(PhysicalOffset(210, 210)))
      << "over the bottom-right corner";
  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(200, 200)))
      << "on the bottom-right corner";
  EXPECT_EQ(10000, rect.SquaredDistanceTo(PhysicalOffset(100, 300)))
      << "over the bottom edge";
  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(100, 200)))
      << "on the bottom edge";
  EXPECT_EQ(401, rect.SquaredDistanceTo(PhysicalOffset(-20, 201)))
      << "over the bottom-left corner";
  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(0, 200)))
      << "on the bottom-left corner";
  EXPECT_EQ(9, rect.SquaredDistanceTo(PhysicalOffset(-3, 100)))
      << "over the left edge";
  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(0, 3)))
      << "on the left edge";

  EXPECT_EQ(0, rect.SquaredDistanceTo(PhysicalOffset(10, 190))) << "contained";

  // Huge size
  rect = PhysicalRect(LayoutUnit(500), LayoutUnit(), LayoutUnit::Max(),
                      LayoutUnit());
  EXPECT_GT(rect.SquaredDistanceTo(PhysicalOffset(10, 0)), 0);

  // Negative size
  rect = PhysicalRect(LayoutUnit(500), LayoutUnit(), LayoutUnit(-100),
                      LayoutUnit());
  EXPECT_EQ(1, rect.SquaredDistanceTo(PhysicalOffset(501, 0)));
}

TEST(PhysicalRectTest, InclusiveIntersect) {
  test::TaskEnvironment task_environment;
  PhysicalRect rect(11, 12, 0, 0);
  EXPECT_TRUE(rect.InclusiveIntersect(PhysicalRect(11, 12, 13, 14)));
  EXPECT_EQ(rect, PhysicalRect(11, 12, 0, 0));

  rect = PhysicalRect(11, 12, 13, 14);
  EXPECT_TRUE(rect.InclusiveIntersect(PhysicalRect(24, 8, 0, 7)));
  EXPECT_EQ(rect, PhysicalRect(24, 12, 0, 3));

  rect = PhysicalRect(11, 12, 13, 14);
  EXPECT_TRUE(rect.InclusiveIntersect(PhysicalRect(9, 15, 4, 0)));
  EXPECT_EQ(rect, PhysicalRect(11, 15, 2, 0));

  rect = PhysicalRect(11, 12, 0, 14);
  EXPECT_FALSE(rect.InclusiveIntersect(PhysicalRect(12, 13, 15, 16)));
  EXPECT_EQ(rect, PhysicalRect());
}

TEST(PhysicalRectTest, IntersectsInclusively) {
  test::TaskEnvironment task_environment;
  PhysicalRect a(11, 12, 0, 0);
  PhysicalRect b(11, 12, 13, 14);
  // An empty rect can have inclusive intersection.
  EXPECT_TRUE(a.IntersectsInclusively(b));
  EXPECT_TRUE(b.IntersectsInclusively(a));

  a = PhysicalRect(11, 12, 13, 14);
  b = PhysicalRect(24, 8, 0, 7);
  // Intersecting left side is sufficient for inclusive intersection.
  EXPECT_TRUE(a.IntersectsInclusively(b));
  EXPECT_TRUE(b.IntersectsInclusively(a));

  a = PhysicalRect(11, 12, 13, 14);
  b = PhysicalRect(0, 26, 13, 8);
  // Intersecting bottom side is sufficient for inclusive intersection.
  EXPECT_TRUE(a.IntersectsInclusively(b));
  EXPECT_TRUE(b.IntersectsInclusively(a));

  a = PhysicalRect(11, 12, 0, 0);
  b = PhysicalRect(11, 12, 0, 0);
  // Two empty rects can intersect inclusively.
  EXPECT_TRUE(a.IntersectsInclusively(b));
  EXPECT_TRUE(b.IntersectsInclusively(a));

  a = PhysicalRect(10, 10, 10, 10);
  b = PhysicalRect(20, 20, 10, 10);
  // Two rects can intersect inclusively at a single point.
  EXPECT_TRUE(a.IntersectsInclusively(b));
  EXPECT_TRUE(b.IntersectsInclusively(a));

  a = PhysicalRect(11, 12, 0, 0);
  b = PhysicalRect(20, 21, 0, 0);
  // Two empty rects that do not touch do not intersect.
  EXPECT_FALSE(a.IntersectsInclusively(b));
  EXPECT_FALSE(b.IntersectsInclusively(a));

  a = PhysicalRect(11, 12, 5, 5);
  b = PhysicalRect(20, 21, 0, 0);
  // A rect that does not touch a point does not intersect.
  EXPECT_FALSE(a.IntersectsInclusively(b));
  EXPECT_FALSE(b.IntersectsInclusively(a));
}

TEST(PhysicalRectTest, ToEnclosingRect) {
  test::TaskEnvironment task_environment;
  LayoutUnit small;
  small.SetRawValue(1);
  PhysicalRect small_dimensions_rect(LayoutUnit(42.5f), LayoutUnit(84.5f),
                                     small, small);
  EXPECT_EQ(gfx::Rect(42, 84, 1, 1), ToEnclosingRect(small_dimensions_rect));

  PhysicalRect integral_rect(100, 150, 200, 350);
  EXPECT_EQ(gfx::Rect(100, 150, 200, 350), ToEnclosingRect(integral_rect));

  PhysicalRect fractional_pos_rect(LayoutUnit(100.6f), LayoutUnit(150.8f),
                                   LayoutUnit(200), LayoutUnit(350));
  EXPECT_EQ(gfx::Rect(100, 150, 201, 351),
            ToEnclosingRect(fractional_pos_rect));

  PhysicalRect fractional_dimensions_rect(
      LayoutUnit(100), LayoutUnit(150), LayoutUnit(200.6f), LayoutUnit(350.4f));
  EXPECT_EQ(gfx::Rect(100, 150, 201, 351),
            ToEnclosingRect(fractional_dimensions_rect));

  PhysicalRect fractional_both_rect1(LayoutUnit(100.6f), LayoutUnit(150.8f),
                                     LayoutUnit(200.4f), LayoutUnit(350.2f));
  EXPECT_EQ(gfx::Rect(100, 150, 201, 351),
            ToEnclosingRect(fractional_both_rect1));

  PhysicalRect fractional_both_rect2(LayoutUnit(100.5f), LayoutUnit(150.7f),
                                     LayoutUnit(200.3f), LayoutUnit(350.3f));
  EXPECT_EQ(gfx::Rect(100, 150, 201, 351),
            ToEnclosingRect(fractional_both_rect2));

  PhysicalRect fractional_both_rect3(LayoutUnit(100.3f), LayoutUnit(150.2f),
                                     LayoutUnit(200.8f), LayoutUnit(350.9f));
  EXPECT_EQ(gfx::Rect(100, 150, 202, 352),
            ToEnclosingRect(fractional_both_rect3));

  PhysicalRect fractional_negpos_rect1(LayoutUnit(-100.4f), LayoutUnit(-150.8f),
                                       LayoutUnit(200), LayoutUnit(350));
  EXPECT_EQ(gfx::Rect(-101, -151, 201, 351),
            ToEnclosingRect(fractional_negpos_rect1));

  PhysicalRect fractional_negpos_rect2(LayoutUnit(-100.5f), LayoutUnit(-150.7f),
                                       LayoutUnit(199.4f), LayoutUnit(350.3f));
  EXPECT_EQ(gfx::Rect(-101, -151, 200, 351),
            ToEnclosingRect(fractional_negpos_rect2));

  PhysicalRect fractional_negpos_rect3(LayoutUnit(-100.3f), LayoutUnit(-150.2f),
                                       LayoutUnit(199.6f), LayoutUnit(350.3f));
  EXPECT_EQ(gfx::Rect(-101, -151, 201, 352),
            ToEnclosingRect(fractional_negpos_rect3));
}

TEST(PhysicalRectTest, EdgesOnPixelBoundaries) {
  test::TaskEnvironment task_environment;
  EXPECT_TRUE(PhysicalRect().EdgesOnPixelBoundaries());
  EXPECT_TRUE(PhysicalRect(1, 1, 1, 1).EdgesOnPixelBoundaries());
  EXPECT_TRUE(PhysicalRect(1, -1, 1, 1).EdgesOnPixelBoundaries());
  EXPECT_TRUE(PhysicalRect(-1, 10, 10, 0).EdgesOnPixelBoundaries());
  EXPECT_TRUE(PhysicalRect(-5, -7, 10, 7).EdgesOnPixelBoundaries());
  EXPECT_TRUE(PhysicalRect(10, 5, -2, -3).EdgesOnPixelBoundaries());
  EXPECT_TRUE(PhysicalRect(LayoutUnit(1.0f), LayoutUnit(5), LayoutUnit(10),
                           LayoutUnit(3))
                  .EdgesOnPixelBoundaries());

  EXPECT_FALSE(PhysicalRect(LayoutUnit(9.3f), LayoutUnit(5), LayoutUnit(10),
                            LayoutUnit(3))
                   .EdgesOnPixelBoundaries());
  EXPECT_FALSE(PhysicalRect(LayoutUnit(0.5f), LayoutUnit(5), LayoutUnit(10),
                            LayoutUnit(3))
                   .EdgesOnPixelBoundaries());
  EXPECT_FALSE(PhysicalRect(LayoutUnit(-0.5f), LayoutUnit(-5), LayoutUnit(10),
                            LayoutUnit(3))
                   .EdgesOnPixelBoundaries());
  EXPECT_FALSE(PhysicalRect(LayoutUnit(-0.5f), LayoutUnit(-2), LayoutUnit(10),
                            LayoutUnit(3))
                   .EdgesOnPixelBoundaries());
  EXPECT_FALSE(PhysicalRect(LayoutUnit(-0.5f), LayoutUnit(5.1f), LayoutUnit(10),
                            LayoutUnit(3))
                   .EdgesOnPixelBoundaries());
  EXPECT_FALSE(PhysicalRect(LayoutUnit(3), LayoutUnit(5.1f), LayoutUnit(10),
                            LayoutUnit(3))
                   .EdgesOnPixelBoundaries());
  EXPECT_FALSE(PhysicalRect(LayoutUnit(3), LayoutUnit(5), LayoutUnit(10.2f),
                            LayoutUnit(3))
                   .EdgesOnPixelBoundaries());
  EXPECT_FALSE(PhysicalRect(LayoutUnit(3), LayoutUnit(5), LayoutUnit(10),
                            LayoutUnit(0.3f))
                   .EdgesOnPixelBoundaries());
}

TEST(PhysicalRectTest, ExpandEdgesToPixelBoundaries) {
  test::TaskEnvironment task_environment;
  LayoutUnit small;
  small.SetRawValue(1);
  PhysicalRect small_dimensions_rect(LayoutUnit(42.5f), LayoutUnit(84.5f),
                                     small, small);
  small_dimensions_rect.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(42, 84, 1, 1), small_dimensions_rect);

  PhysicalRect integral_rect(100, 150, 200, 350);
  integral_rect.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(100, 150, 200, 350), integral_rect);

  PhysicalRect fractional_pos_rect(LayoutUnit(100.6f), LayoutUnit(150.8f),
                                   LayoutUnit(200), LayoutUnit(350));
  fractional_pos_rect.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(100, 150, 201, 351), fractional_pos_rect);

  PhysicalRect fractional_dimensions_rect(
      LayoutUnit(100), LayoutUnit(150), LayoutUnit(200.6f), LayoutUnit(350.4f));
  fractional_dimensions_rect.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(100, 150, 201, 351), fractional_dimensions_rect);

  PhysicalRect fractional_both_rect1(LayoutUnit(100.6f), LayoutUnit(150.8f),
                                     LayoutUnit(200.4f), LayoutUnit(350.2f));
  fractional_both_rect1.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(100, 150, 201, 351), fractional_both_rect1);

  PhysicalRect fractional_both_rect2(LayoutUnit(100.5f), LayoutUnit(150.7f),
                                     LayoutUnit(200.3f), LayoutUnit(350.3f));
  fractional_both_rect2.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(100, 150, 201, 351), fractional_both_rect2);

  PhysicalRect fractional_both_rect3(LayoutUnit(100.3f), LayoutUnit(150.2f),
                                     LayoutUnit(200.8f), LayoutUnit(350.9f));
  fractional_both_rect3.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(100, 150, 202, 352), fractional_both_rect3);

  PhysicalRect fractional_negpos_rect1(LayoutUnit(-100.4f), LayoutUnit(-150.8f),
                                       LayoutUnit(200), LayoutUnit(350));
  fractional_negpos_rect1.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(-101, -151, 201, 351), fractional_negpos_rect1);

  PhysicalRect fractional_negpos_rect2(LayoutUnit(-100.5f), LayoutUnit(-150.7f),
                                       LayoutUnit(199.4f), LayoutUnit(350.3f));
  fractional_negpos_rect2.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(-101, -151, 200, 351), fractional_negpos_rect2);

  PhysicalRect fractional_negpos_rect3(LayoutUnit(-100.3f), LayoutUnit(-150.2f),
                                       LayoutUnit(199.6f), LayoutUnit(350.3f));
  fractional_negpos_rect3.ExpandEdgesToPixelBoundaries();
  EXPECT_EQ(PhysicalRect(-101, -151, 201, 352), fractional_negpos_rect3);
}

TEST(PhysicalRectTest, InfiniteIntRect) {
  test::TaskEnvironment task_environment;
  gfx::Rect r = InfiniteIntRect();
  EXPECT_TRUE(r.Contains(gfx::Rect(-8000000, -8000000, 16000000, 16000000)));

  // The rect can be converted to PhysicalRect and back without loss of
  // accuracy.
  EXPECT_EQ(ToEnclosingRect(PhysicalRect(r)), r);
  EXPECT_EQ(ToPixelSnappedRect(PhysicalRect(r)), r);
  for (int i = 0; i < 50; i++) {
    // Modified rect with visible right/bottom can be converted to gfx::RectF
    // or PhysicalRect and back without loss of accuracy.
    r.set_width(r.x() + i);
    r.set_height(r.y() + i + 2000);
    EXPECT_EQ(gfx::ToEnclosingRect(gfx::RectF(r)), r);
    EXPECT_EQ(gfx::ToEnclosedRect(gfx::RectF(r)), r);
    EXPECT_EQ(ToEnclosingRect(PhysicalRect(r)), r);
    EXPECT_EQ(ToPixelSnappedRect(PhysicalRect(r)), r);
  }
}

}  // namespace

}  // namespace blink

"""

```