Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `float_rounded_rect_test.cc` and the included header `float_rounded_rect.h` immediately tell us this file is testing the `FloatRoundedRect` class.

2. **Recognize the Testing Framework:** The inclusion of `testing/gtest/include/gtest/gtest.h` indicates the use of Google Test, a common C++ testing framework. This means the structure will involve `TEST` macros defining individual test cases.

3. **Understand the Purpose of Testing:** Test files verify the correctness of the code they target. The goal is to check that `FloatRoundedRect` behaves as expected under various conditions.

4. **Scan for Key Functionality:**  Read through the test cases and identify the methods of `FloatRoundedRect` being tested. Look for calls to member functions and how the results are being checked (using `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_FLOAT_EQ`). Initial scan reveals tests for:
    * Construction (with and without radii)
    * Accessors (e.g., `Rect()`, `GetRadii()`, `TopLeftCorner()`)
    * Boolean checks (`IsRounded()`, `IsEmpty()`)
    * Intersection calculations (`XInterceptsAtY()`, `IntersectsQuad()`)
    * Modifiers (`Outset()`, `Inset()`, `ConstrainRadii()`, `OutsetForMarginOrShadow()`, `OutsetForShapeMargin()`)
    * Conversions (to `gfx::RRectF`, `SkRRect`)
    * String representation (`ToString()`)

5. **Analyze Individual Test Cases:** Go through each `TEST` block and understand its specific purpose.
    * **`zeroRadii`:** Tests the behavior when the rounded rectangle has no rounding (zero radii). Checks basic properties and that `Outset` and `Inset` don't introduce rounding.
    * **`circle`:** Tests a fully rounded rectangle (a circle). Verifies radii, rounded status, and `XInterceptsAtY` for different y-coordinates.
    * **`ellipticalCorners`:** Tests rounded rectangles with different radii for each corner. Focuses on `XInterceptsAtY` with non-uniform rounding.
    * **`IntersectsQuadIsInclusive`:**  Thoroughly tests the `IntersectsQuad` method, covering cases where a quad is inside, outside, touching edges, and interacting with the rounded corners.
    * **`ConstrainRadii`:** Checks how the `ConstrainRadii` method limits radii based on the rectangle's dimensions to prevent visual artifacts.
    * **`OutsetRect` and `InsetRect`:** Test the basic `Outset` and `Inset` methods for expanding and shrinking the rectangle without affecting radii.
    * **`OutsetWithRadii` and `InsetWithRadii`:** Test `Outset` and `Inset` when rounded corners are present. Pay attention to how radii are affected.
    * **`InsetWithPartialZeroRadii`:**  Specifically tests the behavior of `Inset` when some corners are sharp (zero radii).
    * **`OutsetForMarginOrShadow`:** Tests a specific outset variant likely used for visual effects.
    * **`InsetToBeNonRenderable`:** Checks how insetting can make a rounded rectangle non-renderable (likely due to radii becoming too large).
    * **`OutsetForShapeMargin`:** Tests an outset variant potentially related to CSS `shape-margin`.
    * **`IntersectsQuadEnclosing`:** Tests `IntersectsQuad` with a quad that encloses the rounded rectangle, ensuring intersection even without direct overlap.
    * **`Conversion`:** Tests the ability to convert `FloatRoundedRect` to and from other related types (`gfx::RRectF`, `SkRRect`).
    * **`ToString`:** Checks the string representation of `FloatRoundedRect` for debugging and logging.

6. **Identify Connections to Web Technologies:**  Think about how rounded rectangles are used in web development:
    * **CSS `border-radius`:** This is the most obvious connection. Rounded corners are a fundamental part of CSS styling.
    * **CSS `margin` and `box-shadow`:**  The `OutsetForMarginOrShadow` test case directly hints at these CSS properties.
    * **CSS `shape-margin`:** The `OutsetForShapeMargin` test case points to this CSS property used with CSS Shapes.
    * **HTML elements:** While not directly manipulated by this class, rounded rectangles are used to style various HTML elements (divs, buttons, etc.).
    * **JavaScript:** JavaScript can manipulate the styles of HTML elements, including `border-radius`, thus indirectly affecting the `FloatRoundedRect` representation in the rendering engine.

7. **Infer Logic and Assumptions:** For tests like `XInterceptsAtY`, deduce the underlying geometric calculations being performed. For `ConstrainRadii`, understand the logic behind limiting radii to prevent overlap.

8. **Consider Potential User/Programming Errors:** Think about how a developer using `FloatRoundedRect` might misuse it or encounter unexpected behavior. This can often be related to incorrect parameter values or misunderstanding the effects of certain methods.

9. **Structure the Output:** Organize the findings into clear categories (functionality, relationship to web technologies, logic/assumptions, usage errors) for readability. Provide specific examples where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the intercept tests are just checking simple rectangle boundaries. **Correction:**  Realize the presence of radii means the intercepts need to handle curved edges, requiring more complex calculations.
* **Initial thought:** The `IntersectsQuad` tests seem repetitive. **Refinement:** Recognize that each test case targets a specific scenario (inside, outside, touching edges, corners), ensuring thorough coverage of the intersection logic.
* **Overlooking details:** Initially might miss the significance of zero radii in `Outset` and `Inset`. **Correction:** Note that these methods preserve sharp corners.
* **Vague connections:** Initially might just say "relates to CSS". **Refinement:**  Be specific about the CSS properties involved (e.g., `border-radius`, `margin`, `box-shadow`, `shape-margin`).

By following this structured approach and constantly refining understanding through analysis of the code and its context, a comprehensive explanation of the test file's functionality can be generated.
这个文件 `blink/renderer/platform/geometry/float_rounded_rect_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `FloatRoundedRect` 类的单元测试文件。`FloatRoundedRect` 类用于表示带有圆角的矩形，其坐标和尺寸使用浮点数表示。

**文件功能列表:**

1. **测试 `FloatRoundedRect` 的构造函数:** 验证使用不同参数（例如，只有矩形信息，或同时包含矩形和圆角半径信息）创建 `FloatRoundedRect` 对象是否正确。
2. **测试访问器方法:** 验证能够正确获取 `FloatRoundedRect` 对象的各种属性，如矩形边界 (`Rect()`)、圆角半径 (`GetRadii()`)、各个角的位置和大小 (`TopLeftCorner()`, `TopRightCorner()`, `BottomLeftCorner()`, `BottomRightCorner()`)。
3. **测试布尔值判断方法:** 验证 `IsRounded()`（是否是圆角矩形）、`IsEmpty()`（是否为空矩形）等方法是否按预期工作。
4. **测试 `XInterceptsAtY()` 方法:**  验证给定 Y 坐标时，计算圆角矩形与该水平线相交的最小和最大 X 坐标值是否正确。这对于渲染引擎来说很重要，因为它需要知道形状在特定扫描线上的覆盖范围。
5. **测试 `IntersectsQuad()` 方法:** 验证判断圆角矩形是否与给定的四边形相交的功能是否正确。这在布局和层叠上下文中用于判断元素是否重叠。
6. **测试 `ConstrainRadii()` 方法:** 验证限制圆角半径大小，使其不超过矩形尺寸一半的功能是否正确。这可以防止圆角半径过大导致渲染问题。
7. **测试 `Outset()` 和 `Inset()` 方法:** 验证放大和缩小圆角矩形的功能是否正确，包括只改变矩形大小以及同时调整圆角半径的情况。
8. **测试 `OutsetForMarginOrShadow()` 方法:**  验证针对外边距或阴影效果进行特定方式放大的功能。这种放大可能不是简单的等比例放大，而是考虑到圆角的平滑过渡。
9. **测试 `OutsetForShapeMargin()` 方法:** 验证针对 CSS `shape-margin` 属性进行放大的功能。
10. **测试与非渲染状态相关的行为:** 验证当圆角半径过大导致图形无法正常渲染时，`IsRenderable()` 方法的返回结果。
11. **测试类型转换:** 验证 `FloatRoundedRect` 可以正确转换为 `gfx::RRectF` 和 `SkRRect` 类型（Skia 图形库中的圆角矩形表示）。
12. **测试 `ToString()` 方法:** 验证将 `FloatRoundedRect` 对象转换为字符串表示的功能，这通常用于调试和日志记录。

**与 JavaScript, HTML, CSS 的关系:**

`FloatRoundedRect` 类是 Blink 渲染引擎内部使用的，它直接影响着浏览器如何渲染网页上的元素。

* **CSS `border-radius`:** 这是最直接的关联。CSS 的 `border-radius` 属性允许开发者为 HTML 元素设置圆角。当浏览器解析 CSS 并渲染元素时，会使用类似 `FloatRoundedRect` 的数据结构来表示元素的形状。例如，如果一个 `div` 元素的 CSS 样式包含 `border-radius: 10px;`，那么在渲染过程中，引擎可能会创建一个 `FloatRoundedRect` 对象来描述这个带有圆角的矩形。

   **例子:**
   ```html
   <div style="width: 100px; height: 50px; border-radius: 10px;"></div>
   ```
   在 Blink 内部，会创建一个 `FloatRoundedRect` 对象，其矩形边界可能是 (0, 0, 100, 50)，四个角的半径都是 (10, 10)。

* **CSS `margin` 和 `box-shadow`:**  `OutsetForMarginOrShadow()` 方法表明 `FloatRoundedRect` 可以用于计算应用外边距或阴影后的形状。外边距和阴影也会影响元素的最终渲染形状和占据的空间。

   **例子:**
   ```html
   <div style="width: 100px; height: 50px; border-radius: 10px; margin: 5px; box-shadow: 2px 2px 5px gray;"></div>
   ```
   Blink 会使用 `FloatRoundedRect` 以及相关的 outset 操作来计算包含边框、圆角、外边距和阴影的最终渲染区域。

* **CSS Shapes (`shape-margin`):** `OutsetForShapeMargin()` 方法表明 `FloatRoundedRect` 也参与了 CSS Shapes 的实现。`shape-margin` 属性用于定义形状周围的空白区域。

   **例子:**
   ```html
   <div style="width: 100px; height: 100px; border-radius: 50%; float: left; shape-margin: 10px;"></div>
   <p style="float: left;">This text will flow around the circle with a margin.</p>
   ```
   当渲染带有 `shape-margin` 的圆形或其他形状时，Blink 会使用 `FloatRoundedRect` 或类似机制来计算文本应该如何围绕这个带外边距的形状流动。

* **JavaScript 操作样式:** JavaScript 可以动态地修改元素的 CSS 样式，包括 `border-radius` 等属性。当 JavaScript 修改这些样式时，渲染引擎会重新计算元素的 `FloatRoundedRect` 并进行重绘。

   **例子:**
   ```javascript
   const div = document.querySelector('div');
   div.style.borderRadius = '20px';
   ```
   这段 JavaScript 代码会修改 `div` 元素的 `border-radius`，导致 Blink 内部与该元素相关的 `FloatRoundedRect` 对象被更新。

**逻辑推理、假设输入与输出:**

以 `TEST_INTERCEPTS` 宏为例，它测试 `XInterceptsAtY()` 方法：

**假设输入:**

* `roundedRect`: 一个 `FloatRoundedRect` 对象，例如：矩形边界为 (0, 0, 100, 100)，所有角半径为 (20, 20)。
* `yCoordinate`: 一个浮点数 Y 坐标，例如：50。

**逻辑推理:**

`XInterceptsAtY()` 方法会计算在给定的 `yCoordinate` 水平线上，圆角矩形的左右边界的 X 坐标。对于一个中心对称的圆角矩形，当 `yCoordinate` 等于矩形的中心 Y 坐标时，交点应该位于矩形的左右边缘。当 `yCoordinate` 接近矩形的顶部或底部时，交点会受到圆角的影响。

**预期输出:**

如果 `roundedRect` 是一个矩形边界为 (0, 0, 100, 100)，所有角半径为 (20, 20) 的圆角矩形，并且 `yCoordinate` 为 50，那么 `XInterceptsAtY()` 应该返回 `true`，并且：

* `expectedMinXIntercept` 接近 20 (左侧圆角的起始 X 坐标)。
* `expectedMaxXIntercept` 接近 80 (右侧圆角的结束 X 坐标)。

具体的数值取决于圆角的曲线方程。对于 `TEST(FloatRoundedRectTest, circle)` 中的例子：

* 输入 `r`:  矩形 (0, 0, 100, 100)，半径 (50, 50)。
* 输入 `yCoordinate`: 25。
* 输出 `expectedMinXIntercept`: 6.69873, `expectedMaxXIntercept`: 93.3013。 这是通过椭圆方程计算出来的。

**用户或编程常见的使用错误:**

1. **未考虑圆角半径限制:**  用户可能会设置过大的圆角半径，导致渲染出现异常。`ConstrainRadii()` 方法就是为了防止这种情况。例如，对于一个 50x50 的矩形，如果设置 `border-radius: 50px;`，某些实现可能会将其限制为 25px，以避免完全变成圆形。Blink 的 `ConstrainRadii()` 就做了类似的事情。

   **例子:**
   ```cpp
   FloatRoundedRect r(gfx::RectF(0, 0, 50, 50), gfx::SizeF(50, 50)); // 理论上是圆形
   r.ConstrainRadii(); // 可能会将半径限制为 (25, 25)
   ```

2. **错误的坐标或尺寸:** 在创建 `FloatRoundedRect` 时，如果提供了错误的坐标、宽度或高度（例如，负数宽度），可能会导致未定义的行为或渲染错误。测试用例中也包含了对空矩形和带有负坐标的矩形的测试。

   **例子:**
   ```cpp
   FloatRoundedRect r(gfx::RectF(10, 20, -5, 30)); // 负宽度，可能导致问题
   ```

3. **假设圆角半径总是相等的:** 用户可能会错误地认为设置一个 `border-radius` 值会应用到所有四个角，但实际上 CSS 允许为每个角设置不同的半径。`FloatRoundedRect` 类也支持不同的角半径，测试用例中也有针对不同半径的测试。

4. **忽略浮点精度问题:**  由于 `FloatRoundedRect` 使用浮点数，进行比较时需要考虑精度问题。测试用例中使用 `EXPECT_FLOAT_EQ` 而不是 `EXPECT_EQ` 来比较浮点数。

总而言之，`float_rounded_rect_test.cc` 文件通过大量的单元测试，确保 `FloatRoundedRect` 类在各种场景下都能正确地表示和操作带有圆角的矩形，这对于 Blink 渲染引擎正确渲染网页内容至关重要。它直接关联到 CSS 的圆角、外边距、阴影和 CSS Shapes 等特性，并间接地受到 JavaScript 对样式操作的影响。

### 提示词
```
这是目录为blink/renderer/platform/geometry/float_rounded_rect_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Adobe Systems Incorporated. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/geometry/float_rounded_rect.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/geometry/infinite_int_rect.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/quad_f.h"

namespace blink {

#define TEST_INTERCEPTS(roundedRect, yCoordinate, expectedMinXIntercept, \
                        expectedMaxXIntercept)                           \
  {                                                                      \
    float min_x_intercept;                                               \
    float max_x_intercept;                                               \
    EXPECT_TRUE(roundedRect.XInterceptsAtY(yCoordinate, min_x_intercept, \
                                           max_x_intercept));            \
    EXPECT_FLOAT_EQ(expectedMinXIntercept, min_x_intercept);             \
    EXPECT_FLOAT_EQ(expectedMaxXIntercept, max_x_intercept);             \
  }

TEST(FloatRoundedRectTest, zeroRadii) {
  FloatRoundedRect r = FloatRoundedRect(1, 2, 3, 4);

  EXPECT_EQ(gfx::RectF(1, 2, 3, 4), r.Rect());
  EXPECT_EQ(gfx::SizeF(), r.GetRadii().TopLeft());
  EXPECT_EQ(gfx::SizeF(), r.GetRadii().TopRight());
  EXPECT_EQ(gfx::SizeF(), r.GetRadii().BottomLeft());
  EXPECT_EQ(gfx::SizeF(), r.GetRadii().BottomRight());
  EXPECT_TRUE(r.GetRadii().IsZero());
  EXPECT_FALSE(r.IsRounded());
  EXPECT_FALSE(r.IsEmpty());

  EXPECT_EQ(gfx::RectF(1, 2, 0, 0), r.TopLeftCorner());
  EXPECT_EQ(gfx::RectF(4, 2, 0, 0), r.TopRightCorner());
  EXPECT_EQ(gfx::RectF(4, 6, 0, 0), r.BottomRightCorner());
  EXPECT_EQ(gfx::RectF(1, 6, 0, 0), r.BottomLeftCorner());

  TEST_INTERCEPTS(r, 2, r.Rect().x(), r.Rect().right());
  TEST_INTERCEPTS(r, 4, r.Rect().x(), r.Rect().right());
  TEST_INTERCEPTS(r, 6, r.Rect().x(), r.Rect().right());

  float min_x_intercept;
  float max_x_intercept;

  EXPECT_FALSE(r.XInterceptsAtY(1, min_x_intercept, max_x_intercept));
  EXPECT_FALSE(r.XInterceptsAtY(7, min_x_intercept, max_x_intercept));

  // The FloatRoundedRect::Outset() and Inset() don't change zero radii.
  r.Outset(20);
  EXPECT_TRUE(r.GetRadii().IsZero());
  r.Inset(10);
  EXPECT_TRUE(r.GetRadii().IsZero());
}

TEST(FloatRoundedRectTest, circle) {
  gfx::SizeF corner_radii(50, 50);
  FloatRoundedRect r(gfx::RectF(0, 0, 100, 100), corner_radii, corner_radii,
                     corner_radii, corner_radii);

  EXPECT_EQ(gfx::RectF(0, 0, 100, 100), r.Rect());
  EXPECT_EQ(corner_radii, r.GetRadii().TopLeft());
  EXPECT_EQ(corner_radii, r.GetRadii().TopRight());
  EXPECT_EQ(corner_radii, r.GetRadii().BottomLeft());
  EXPECT_EQ(corner_radii, r.GetRadii().BottomRight());
  EXPECT_FALSE(r.GetRadii().IsZero());
  EXPECT_TRUE(r.IsRounded());
  EXPECT_FALSE(r.IsEmpty());

  EXPECT_EQ(gfx::RectF(0, 0, 50, 50), r.TopLeftCorner());
  EXPECT_EQ(gfx::RectF(50, 0, 50, 50), r.TopRightCorner());
  EXPECT_EQ(gfx::RectF(0, 50, 50, 50), r.BottomLeftCorner());
  EXPECT_EQ(gfx::RectF(50, 50, 50, 50), r.BottomRightCorner());

  TEST_INTERCEPTS(r, 0, 50, 50);
  TEST_INTERCEPTS(r, 25, 6.69873, 93.3013);
  TEST_INTERCEPTS(r, 50, 0, 100);
  TEST_INTERCEPTS(r, 75, 6.69873, 93.3013);
  TEST_INTERCEPTS(r, 100, 50, 50);

  float min_x_intercept;
  float max_x_intercept;

  EXPECT_FALSE(r.XInterceptsAtY(-1, min_x_intercept, max_x_intercept));
  EXPECT_FALSE(r.XInterceptsAtY(101, min_x_intercept, max_x_intercept));
}

/*
 * FloatRoundedRect geometry for this test. Corner radii are in parens, x and y
 * intercepts for the elliptical corners are noted. The rectangle itself is at
 * 0,0 with width and height 100.
 *
 *         (10, 15)  x=10      x=90 (10, 20)
 *                (--+---------+--)
 *           y=15 +--|         |-+ y=20
 *                |               |
 *                |               |
 *           y=85 + -|         |- + y=70
 *                (--+---------+--)
 *       (25, 15)  x=25      x=80  (20, 30)
 */
TEST(FloatRoundedRectTest, ellipticalCorners) {
  FloatRoundedRect::Radii corner_radii;
  corner_radii.SetTopLeft(gfx::SizeF(10, 15));
  corner_radii.SetTopRight(gfx::SizeF(10, 20));
  corner_radii.SetBottomLeft(gfx::SizeF(25, 15));
  corner_radii.SetBottomRight(gfx::SizeF(20, 30));

  FloatRoundedRect r(gfx::RectF(0, 0, 100, 100), corner_radii);

  EXPECT_EQ(r.GetRadii(),
            FloatRoundedRect::Radii(gfx::SizeF(10, 15), gfx::SizeF(10, 20),
                                    gfx::SizeF(25, 15), gfx::SizeF(20, 30)));
  EXPECT_EQ(r, FloatRoundedRect(gfx::RectF(0, 0, 100, 100), corner_radii));

  EXPECT_EQ(gfx::RectF(0, 0, 10, 15), r.TopLeftCorner());
  EXPECT_EQ(gfx::RectF(90, 0, 10, 20), r.TopRightCorner());
  EXPECT_EQ(gfx::RectF(0, 85, 25, 15), r.BottomLeftCorner());
  EXPECT_EQ(gfx::RectF(80, 70, 20, 30), r.BottomRightCorner());

  TEST_INTERCEPTS(r, 5, 2.5464401, 96.61438);
  TEST_INTERCEPTS(r, 15, 0, 99.682457);
  TEST_INTERCEPTS(r, 20, 0, 100);
  TEST_INTERCEPTS(r, 50, 0, 100);
  TEST_INTERCEPTS(r, 70, 0, 100);
  TEST_INTERCEPTS(r, 85, 0, 97.320511);
  TEST_INTERCEPTS(r, 95, 6.3661003, 91.05542);

  float min_x_intercept;
  float max_x_intercept;

  EXPECT_FALSE(r.XInterceptsAtY(-1, min_x_intercept, max_x_intercept));
  EXPECT_FALSE(r.XInterceptsAtY(101, min_x_intercept, max_x_intercept));
}

TEST(FloatRoundedRectTest, IntersectsQuadIsInclusive) {
  FloatRoundedRect::Radii corner_radii(5);

  // A rect at (10, 10) with dimensions 20x20 and radii of size 5x5.
  FloatRoundedRect r(gfx::RectF(10, 10, 20, 20), corner_radii);

  // A quad fully inside the rounded rect should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(11, 11, 8, 8))));

  // A quad fully outside the rounded rect should not intersect.
  EXPECT_FALSE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(0, 0, 1, 1))));

  // A quad touching the top edge of the rounded rect should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(15, 9, 5, 1))));

  // A quad touching the right edge of the rounded rect should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(30, 15, 1, 1))));

  // A quad touching the bottom edge of the rounded rect should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(15, 30, 1, 1))));

  // A quad touching the left edge of the rounded rect should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(9, 15, 1, 1))));

  // A quad outside the top-left arc should not intersect.
  EXPECT_FALSE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(10, 10, 1, 1))));

  // A quad inside the top-left arc should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(13, 13, 1, 1))));

  // A quad outside the top-right arc should not intersect.
  EXPECT_FALSE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(29, 10, 1, 1))));

  // A quad inside the top-right arc should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(26, 13, 1, 1))));

  // A quad outside the bottom-right arc should not intersect.
  EXPECT_FALSE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(29, 29, 1, 1))));

  // A quad inside the bottom-right arc should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(26, 26, 1, 1))));

  // A quad outside the bottom-left arc should not intersect.
  EXPECT_FALSE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(10, 29, 1, 1))));

  // A quad inside the bottom-left arc should intersect.
  EXPECT_TRUE(r.IntersectsQuad(gfx::QuadF(gfx::RectF(13, 26, 1, 1))));
}

TEST(FloatRoundedrectTest, ConstrainRadii) {
  FloatRoundedRect empty;
  empty.ConstrainRadii();
  EXPECT_EQ(FloatRoundedRect(), empty);

  FloatRoundedRect r1(-100, -100, 200, 200);
  r1.ConstrainRadii();
  EXPECT_EQ(FloatRoundedRect(-100, -100, 200, 200), r1);

  FloatRoundedRect r2(gfx::RectF(-100, -100, 200, 200), 10);
  r2.ConstrainRadii();
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(-100, -100, 200, 200), 10), r2);

  FloatRoundedRect r3(gfx::RectF(-100, -100, 200, 200), 100);
  r3.ConstrainRadii();
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(-100, -100, 200, 200), 100), r3);

  FloatRoundedRect r4(gfx::RectF(-100, -100, 200, 200), 160);
  r4.ConstrainRadii();
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(-100, -100, 200, 200), 100), r4);

  FloatRoundedRect r5(gfx::RectF(-100, -100, 200, 200), gfx::SizeF(10, 20),
                      gfx::SizeF(100, 250), gfx::SizeF(200, 60),
                      gfx::SizeF(50, 150));
  r5.ConstrainRadii();
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(-100, -100, 200, 200),
                             gfx::SizeF(5, 10), gfx::SizeF(50, 125),
                             gfx::SizeF(100, 30), gfx::SizeF(25, 75)),
            r5);

  FloatRoundedRect r6(gfx::RectF(-100, -100, 200, 200), gfx::SizeF(10, 20),
                      gfx::SizeF(60, 200), gfx::SizeF(250, 100),
                      gfx::SizeF(150, 50));
  r6.ConstrainRadii();
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(-100, -100, 200, 200),
                             gfx::SizeF(5, 10), gfx::SizeF(30, 100),
                             gfx::SizeF(125, 50), gfx::SizeF(75, 25)),
            r6);

  FloatRoundedRect r7(gfx::RectF(0, 0, 85089, 21377),
                      gfx::SizeF(1388.89, 1388.89),
                      gfx::SizeF(58711.2, 14750.3), gfx::SizeF(0, 13467.7),
                      gfx::SizeF(85088.6, 21377.3));
  r7.ConstrainRadii();
  EXPECT_TRUE(r7.IsRenderable());
}

TEST(FloatRoundedRectTest, OutsetRect) {
  FloatRoundedRect r(gfx::RectF(0, 0, 100, 100));
  r.Outset(gfx::OutsetsF().set_top(1).set_right(2).set_bottom(3).set_left(4));
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(-4, -1, 106, 104)), r);
  r.Outset(
      gfx::OutsetsF().set_top(-1).set_right(-2).set_bottom(-3).set_left(-4));
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(0, 0, 100, 100)), r);
}

TEST(FloatRoundedRectTest, InsetRect) {
  FloatRoundedRect r(gfx::RectF(0, 0, 100, 100));
  r.Inset(gfx::InsetsF().set_top(1).set_right(2).set_bottom(3).set_left(4));
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(4, 1, 94, 96)), r);
  r.Inset(gfx::InsetsF().set_top(-1).set_right(-2).set_bottom(-3).set_left(-4));
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(0, 0, 100, 100)), r);
}

TEST(FloatRoundedRectTest, OutsetWithRadii) {
  FloatRoundedRect r(gfx::RectF(0, 0, 100, 100), gfx::SizeF(5, 10),
                     gfx::SizeF(15, 20), gfx::SizeF(0, 30), gfx::SizeF(35, 0));
  r.Outset(
      gfx::OutsetsF().set_top(40).set_right(30).set_bottom(20).set_left(10));
  // Zero components of radii should be kept unchanged to ensure sharp corners
  // are still sharp.
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(-10, -40, 140, 160), gfx::SizeF(15, 50),
                             gfx::SizeF(45, 60), gfx::SizeF(0, 50),
                             gfx::SizeF(65, 0)),
            r);
}

TEST(FloatRoundedRectTest, InsetWithRadii) {
  FloatRoundedRect r(gfx::RectF(0, 0, 100, 100), gfx::SizeF(20, 30),
                     gfx::SizeF(40, 50), gfx::SizeF(0, 60), gfx::SizeF(70, 0));
  r.Inset(gfx::InsetsF().set_top(40).set_right(30).set_bottom(20).set_left(10));
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(10, 40, 60, 40), gfx::SizeF(10, 0),
                             gfx::SizeF(10, 10), gfx::SizeF(0, 40),
                             gfx::SizeF(40, 0)),
            r);
}

// Outset() should keep zero components in radii to ensure sharp corners are
// still sharp.
TEST(FloatRoundedRectTest, InsetWithPartialZeroRadii) {
  FloatRoundedRect r(gfx::RectF(0, 0, 100, 100), gfx::SizeF(5, 0),
                     gfx::SizeF(0, 20), gfx::SizeF(0, 30), gfx::SizeF(35, 0));
  r.Inset(10);
  EXPECT_EQ(
      FloatRoundedRect(gfx::RectF(10, 10, 80, 80), gfx::SizeF(0, 0),
                       gfx::SizeF(0, 10), gfx::SizeF(0, 20), gfx::SizeF(25, 0)),
      r);
}

TEST(FloatRoundedRectTest, OutsetForMarginOrShadow) {
  FloatRoundedRect r(gfx::RectF(0, 0, 200, 200), gfx::SizeF(4, 8),
                     gfx::SizeF(12, 16), gfx::SizeF(0, 32), gfx::SizeF(64, 0));
  r.OutsetForMarginOrShadow(32);
  EXPECT_EQ(FloatRoundedRect(
                gfx::RectF(-32, -32, 264, 264), gfx::SizeF(14.5625f, 26.5f),
                gfx::SizeF(36.1875f, 44), gfx::SizeF(0, 64), gfx::SizeF(96, 0)),
            r);
}

TEST(FloatRoundedRectTest, InsetToBeNonRenderable) {
  FloatRoundedRect pie(gfx::RectF(0, 0, 100, 100), gfx::SizeF(100, 100),
                       gfx::SizeF(), gfx::SizeF(), gfx::SizeF());
  EXPECT_TRUE(pie.IsRenderable());
  FloatRoundedRect small_pie = pie;
  small_pie.Inset(20);
  EXPECT_EQ(FloatRoundedRect(gfx::RectF(20, 20, 60, 60), gfx::SizeF(80, 80),
                             gfx::SizeF(), gfx::SizeF(), gfx::SizeF()),
            small_pie);
  EXPECT_FALSE(small_pie.IsRenderable());
  small_pie.Outset(20);
  EXPECT_EQ(pie, small_pie);
}

TEST(FloatRoundedRectTest, OutsetForShapeMargin) {
  FloatRoundedRect r(gfx::RectF(0, 0, 100, 100), gfx::SizeF(5, 10),
                     gfx::SizeF(15, 0), gfx::SizeF(0, 30), gfx::SizeF(0, 0));
  r.OutsetForShapeMargin(0);
  EXPECT_EQ(
      FloatRoundedRect(gfx::RectF(0, 0, 100, 100), gfx::SizeF(5, 10),
                       gfx::SizeF(15, 0), gfx::SizeF(0, 30), gfx::SizeF(0, 0)),
      r);
  r.OutsetForShapeMargin(5);
  EXPECT_EQ(
      FloatRoundedRect(gfx::RectF(-5, -5, 110, 110), gfx::SizeF(10, 15),
                       gfx::SizeF(20, 5), gfx::SizeF(5, 35), gfx::SizeF(5, 5)),
      r);
}

TEST(FloatRoundedRectTest, IntersectsQuadEnclosing) {
  gfx::SizeF one_radii(20, 20);
  FloatRoundedRect::Radii corner_radii;
  corner_radii.SetTopLeft(one_radii);
  corner_radii.SetTopRight(one_radii);
  corner_radii.SetBottomLeft(one_radii);
  corner_radii.SetBottomRight(one_radii);
  // A rect at (100, 25) with dimensions 100x100 and radii of size 20x20.
  FloatRoundedRect r(gfx::RectF(100, 25, 100, 100), corner_radii);

  // Encloses `r` without intersecting any of the geometry (corners or base
  // rectangle).
  gfx::QuadF fully_outside(gfx::PointF(150, -30), gfx::PointF(255, 75),
                           gfx::PointF(150, 180), gfx::PointF(45, 75));
  EXPECT_TRUE(r.IntersectsQuad(fully_outside));

  // Encloses `r`, touching at the corners of the base rectangle.
  gfx::QuadF touching(gfx::PointF(150, -25), gfx::PointF(250, 75),
                      gfx::PointF(150, 175), gfx::PointF(50, 75));
  EXPECT_TRUE(r.IntersectsQuad(touching));

  // Encloses `r`, crossing through the rounded corners (without intersecting
  // them).
  gfx::QuadF crossing_corners(gfx::PointF(150, -15), gfx::PointF(240, 75),
                              gfx::PointF(150, 165), gfx::PointF(60, 75));
  EXPECT_TRUE(r.IntersectsQuad(crossing_corners));
}

TEST(FloatRoundedRectTest, Conversion) {
  FloatRoundedRect r(gfx::RectF(100, 200, 300, 400), gfx::SizeF(5, 6),
                     gfx::SizeF(7, 8), gfx::SizeF(9, 10), gfx::SizeF(11, 12));
  gfx::RRectF gfx_r(r);
  SkRRect sk_r(r);
  EXPECT_EQ(r, FloatRoundedRect(gfx_r));
  EXPECT_EQ(r, FloatRoundedRect(sk_r));
}

TEST(FloatRoundedRectTest, ToString) {
  gfx::SizeF corner_rect(1, 2);
  FloatRoundedRect rounded_rect(
      gfx::RectF(3, 5, 7, 11),
      FloatRoundedRect::Radii(corner_rect, corner_rect, corner_rect,
                              corner_rect));
  EXPECT_EQ("3,5 7x11 radii:(tl:1x2; tr:1x2; bl:1x2; br:1x2)",
            rounded_rect.ToString());

  FloatRoundedRect infinite((gfx::RectF(InfiniteIntRect())));
  EXPECT_EQ("InfiniteIntRect", infinite.ToString());

  FloatRoundedRect rect_without_radii(gfx::RectF(1, 3, 5, 7));
  EXPECT_EQ("1,3 5x7", rect_without_radii.ToString());
}

}  // namespace blink
```