Response:
Let's break down the thought process for analyzing this C++ source code and generating the explanation.

1. **Understand the Goal:** The request is to analyze the `physical_rect.cc` file in the Chromium Blink engine. The specific goals are:
    * Describe its functionality.
    * Explain its relation to JavaScript, HTML, and CSS, providing examples.
    * Explain any logical reasoning involved, including hypothetical inputs and outputs.
    * Highlight common user/programming errors.

2. **Initial Code Scan (High-Level):**  Quickly read through the code, noting the included headers (`box_strut.h`, `logical_rect.h`, math, string). This immediately suggests the code deals with rectangular geometry and has conversions or relationships with logical rectangles. The namespace `blink` confirms it's part of the Blink rendering engine.

3. **Focus on the Class:** The core of the file is the `PhysicalRect` class. Identify its member variables (implicitly `offset` and `size`, based on usage) and the methods it defines.

4. **Analyze Each Method:**  Go through each method one by one, understanding its purpose:

    * **`DistanceAsSize`:**  Calculates the distance from the rectangle to a target point, treating the distance as a size. Consider edge cases (point inside, outside, on the edge).

    * **`SquaredDistanceTo`:**  Calculates the squared distance from the rectangle to a point. The clamping logic is important here – it finds the closest point *on* the rectangle.

    * **`Contains`:** Checks if one rectangle fully encloses another. The boundary conditions (`<=`, `>=`) are crucial.

    * **`Intersects`:** Checks for overlap between two rectangles. The emptiness check (`!IsEmpty()`) is key, and the strict inequality (`<`) is for proper intersection.

    * **`IntersectsInclusively`:** Similar to `Intersects`, but includes touching edges. Note the difference in inequality (`<=`). The "TODO" comment is worth noting as a potential area for confusion or future changes.

    * **`Unite`:**  Calculates the smallest rectangle that contains both. Handles the case where one or both rectangles are empty.

    * **`UniteIfNonZero`:**  Similar to `Unite`, but ignores zero-sized rectangles.

    * **`UniteEvenIfEmpty`:**  The core uniting logic, used by the other `Unite` methods. The handling of potentially saturated width/height is a more advanced detail, but worth understanding.

    * **`Expand`:**  Increases the size of the rectangle by the given strut values.

    * **`ExpandEdgesToPixelBoundaries`:**  Rounds the rectangle's edges to the nearest pixel boundaries. This is crucial for rendering.

    * **`Contract`:** Decreases the size of the rectangle.

    * **`Intersect`:** Calculates the overlapping area. Handles non-intersecting cases by returning an empty rectangle.

    * **`InclusiveIntersect`:** Similar to `Intersect`, but returns `false` if there's no intersection.

    * **`ToString`:**  Returns a string representation of the rectangle.

    * **`UnionRect` (free function):**  Calculates the union of a vector of rectangles.

    * **`UnionRectEvenIfEmpty` (free function):** Similar, but handles empty rectangles.

    * **`operator<<`:**  Overloads the output stream operator for easy printing.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** This is where the connection to the user-facing side comes in.

    * **CSS:**  Think about CSS properties that define sizes and positions: `width`, `height`, `top`, `left`, `margin`, `padding`, `border`. These directly influence the values stored in `PhysicalRect`.

    * **HTML:**  HTML elements generate boxes. The geometry of these boxes is represented (in part) by `PhysicalRect`.

    * **JavaScript:**  JavaScript APIs that deal with element geometry are key here: `getBoundingClientRect()`, `offsetTop`, `offsetLeft`, `offsetWidth`, `offsetHeight`. These APIs often return information that corresponds to or is derived from `PhysicalRect` data.

    Provide concrete examples of how each method might be used in the rendering process related to these technologies.

6. **Logical Reasoning and Examples:** For each method, consider:

    * **Inputs:** What kind of `PhysicalRect` objects or points would be passed in?
    * **Process:** How does the method manipulate these inputs?
    * **Outputs:** What `PhysicalRect` or scalar value is returned?

    Create simple scenarios to illustrate the behavior of the methods. For example, for `Intersects`, show two overlapping and two non-overlapping rectangles.

7. **Common Errors:** Think about how developers might misuse or misunderstand these concepts:

    * **Confusing `Intersects` and `IntersectsInclusively`:**  Highlight the subtle difference in edge cases.
    * **Incorrectly assuming pixel precision:**  Emphasize that `LayoutUnit` is a floating-point type, and the pixel boundary conversion is explicit.
    * **Misunderstanding the behavior of `Unite` with empty rectangles:** Explain how it handles these cases.
    * **Off-by-one errors:** This is a classic geometry problem, especially when dealing with inclusive vs. exclusive boundaries.

8. **Structure and Language:** Organize the information clearly, using headings and bullet points. Use precise language but avoid overly technical jargon where possible. Explain concepts in a way that's understandable to someone familiar with web development.

9. **Review and Refine:**  Read through the entire explanation to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For example, initially, I might forget to explicitly mention the member variables are implicitly `offset` and `size`, but on review, realize that should be stated. Also, make sure the examples are easy to follow.

This step-by-step approach, combined with a good understanding of basic geometry and web development concepts, allows for a comprehensive and accurate analysis of the `physical_rect.cc` file.
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"

#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

PhysicalSize PhysicalRect::DistanceAsSize(PhysicalOffset target) const {
  target -= offset;
  PhysicalSize distance;
  if (target.left < 0)
    distance.width = -target.left;
  else if (target.left > size.width)
    distance.width = target.left - size.width;
  if (target.top < 0)
    distance.height = -target.top;
  else if (target.top > size.height)
    distance.height = target.top - size.height;
  return distance;
}

LayoutUnit PhysicalRect::SquaredDistanceTo(const PhysicalOffset& point) const {
  LayoutUnit x1 = X(), x2 = Right();
  if (x1 > x2)
    std::swap(x1, x2);
  LayoutUnit diff_x = point.left - ClampTo<LayoutUnit>(point.left, x1, x2);
  LayoutUnit y1 = Y(), y2 = Bottom();
  if (y1 > y2)
    std::swap(y1, y2);
  LayoutUnit diff_y = point.top - ClampTo<LayoutUnit>(point.top, y1, y2);
  return diff_x * diff_x + diff_y * diff_y;
}

bool PhysicalRect::Contains(const PhysicalRect& other) const {
  return offset.left <= other.offset.left && offset.top <= other.offset.top &&
         Right() >= other.Right() && Bottom() >= other.Bottom();
}

bool PhysicalRect::Intersects(const PhysicalRect& other) const {
  // Checking emptiness handles negative widths as well as zero.
  return !IsEmpty() && !other.IsEmpty() && offset.left < other.Right() &&
         other.offset.left < Right() && offset.top < other.Bottom() &&
         other.offset.top < Bottom();
}

bool PhysicalRect::IntersectsInclusively(const PhysicalRect& other) const {
  // TODO(pdr): How should negative widths or heights be handled?
  return offset.left <= other.Right() && other.offset.left <= Right() &&
         offset.top <= other.Bottom() && other.offset.top <= Bottom();
}

void PhysicalRect::Unite(const PhysicalRect& other) {
  if (other.IsEmpty())
    return;
  if (IsEmpty()) {
    *this = other;
    return;
  }

  UniteEvenIfEmpty(other);
}

void PhysicalRect::UniteIfNonZero(const PhysicalRect& other) {
  if (other.size.IsZero())
    return;
  if (size.IsZero()) {
    *this = other;
    return;
  }

  UniteEvenIfEmpty(other);
}

void PhysicalRect::UniteEvenIfEmpty(const PhysicalRect& other) {
  LayoutUnit left = std::min(offset.left, other.offset.left);
  LayoutUnit top = std::min(offset.top, other.offset.top);
  LayoutUnit right = std::max(Right(), other.Right());
  LayoutUnit bottom = std::max(Bottom(), other.Bottom());
  size = {right - left, bottom - top};

  // If either width or height are not saturated, right - width == left and
  // bottom - height == top. If they are saturated, instead of using left/top
  // directly for the offset, the subtraction results in the united rect to
  // favor content in the positive directions.
  // Note that this is just a heuristic as the true rect would normally be
  // larger than the max LayoutUnit value.
  offset = {right - size.width, bottom - size.height};
}

void PhysicalRect::Expand(const PhysicalBoxStrut& strut) {
  ExpandEdges(strut.top, strut.right, strut.bottom, strut.left);
}

void PhysicalRect::ExpandEdgesToPixelBoundaries() {
  int left = FloorToInt(offset.left);
  int top = FloorToInt(offset.top);
  int max_right = (offset.left + size.width).Ceil();
  int max_bottom = (offset.top + size.height).Ceil();
  offset.left = LayoutUnit(left);
  offset.top = LayoutUnit(top);
  size.width = LayoutUnit(max_right - left);
  size.height = LayoutUnit(max_bottom - top);
}

void PhysicalRect::Contract(const PhysicalBoxStrut& strut) {
  ExpandEdges(-strut.top, -strut.right, -strut.bottom, -strut.left);
}

void PhysicalRect::Intersect(const PhysicalRect& other) {
  PhysicalOffset new_offset(std::max(X(), other.X()), std::max(Y(), other.Y()));
  PhysicalOffset new_max_point(std::min(Right(), other.Right()),
                               std::min(Bottom(), other.Bottom()));

  // Return a clean empty rectangle for non-intersecting cases.
  if (new_offset.left >= new_max_point.left ||
      new_offset.top >= new_max_point.top) {
    new_offset = PhysicalOffset();
    new_max_point = PhysicalOffset();
  }

  offset = new_offset;
  size = {new_max_point.left - new_offset.left,
          new_max_point.top - new_offset.top};
}

bool PhysicalRect::InclusiveIntersect(const PhysicalRect& other) {
  PhysicalOffset new_offset(std::max(X(), other.X()), std::max(Y(), other.Y()));
  PhysicalOffset new_max_point(std::min(Right(), other.Right()),
                               std::min(Bottom(), other.Bottom()));

  if (new_offset.left > new_max_point.left ||
      new_offset.top > new_max_point.top) {
    *this = PhysicalRect();
    return false;
  }

  offset = new_offset;
  size = {new_max_point.left - new_offset.left,
          new_max_point.top - new_offset.top};
  return true;
}

String PhysicalRect::ToString() const {
  return String::Format("%s %s", offset.ToString().Ascii().c_str(),
                        size.ToString().Ascii().c_str());
}

PhysicalRect UnionRect(const Vector<PhysicalRect>& rects) {
  PhysicalRect result;
  for (const auto& rect : rects)
    result.Unite(rect);
  return result;
}

PhysicalRect UnionRectEvenIfEmpty(const Vector<PhysicalRect>& rects) {
  wtf_size_t count = rects.size();
  if (!count)
    return PhysicalRect();

  PhysicalRect result = rects[0];
  for (wtf_size_t i = 1; i < count; ++i)
    result.UniteEvenIfEmpty(rects[i]);

  return result;
}

std::ostream& operator<<(std::ostream& os, const PhysicalRect& value) {
  return os << value.ToString();
}

}  // namespace blink
```

### 功能列表:

`physical_rect.cc` 文件定义了 `PhysicalRect` 类，该类在 Chromium Blink 渲染引擎中用于表示屏幕上的一个物理矩形区域。其主要功能包括：

1. **表示和操作矩形:**  存储矩形的左上角坐标 (`offset`) 和尺寸 (`size`)，并提供访问这些属性的方法（例如 `X()`, `Y()`, `Right()`, `Bottom()`).

2. **计算距离:**
   - `DistanceAsSize(PhysicalOffset target)`: 计算从矩形到目标点的距离，并将该距离表示为一个 `PhysicalSize` 对象。
   - `SquaredDistanceTo(const PhysicalOffset& point)`: 计算矩形到给定点的平方距离。

3. **包含性判断:**
   - `Contains(const PhysicalRect& other)`: 判断当前矩形是否完全包含另一个矩形。

4. **相交性判断:**
   - `Intersects(const PhysicalRect& other)`: 判断当前矩形是否与另一个矩形相交（不包括边缘重合）。
   - `IntersectsInclusively(const PhysicalRect& other)`: 判断当前矩形是否与另一个矩形相交或边缘重合。

5. **矩形合并:**
   - `Unite(const PhysicalRect& other)`:  将当前矩形与另一个矩形合并，得到能包含两者的最小矩形。
   - `UniteIfNonZero(const PhysicalRect& other)`: 类似于 `Unite`，但如果另一个矩形的尺寸为零，则不进行合并。
   - `UniteEvenIfEmpty(const PhysicalRect& other)`: 无条件地将当前矩形与另一个矩形合并。

6. **矩形扩展和收缩:**
   - `Expand(const PhysicalBoxStrut& strut)`:  根据 `PhysicalBoxStrut` 对象的值扩展矩形的边缘。
   - `ExpandEdgesToPixelBoundaries()`: 将矩形的边缘扩展到最接近的像素边界。
   - `Contract(const PhysicalBoxStrut& strut)`: 根据 `PhysicalBoxStrut` 对象的值收缩矩形的边缘。

7. **矩形相交:**
   - `Intersect(const PhysicalRect& other)`: 计算当前矩形与另一个矩形的交集，如果无交集则返回一个空的矩形。
   - `InclusiveIntersect(const PhysicalRect& other)`: 计算当前矩形与另一个矩形的交集，如果无交集则将当前矩形置为空并返回 `false`。

8. **字符串表示:**
   - `ToString()`: 返回矩形的字符串表示形式。

9. **静态工具函数:**
   - `UnionRect(const Vector<PhysicalRect>& rects)`: 计算一组矩形的并集。
   - `UnionRectEvenIfEmpty(const Vector<PhysicalRect>& rects)`: 计算一组矩形的并集，即使其中包含空矩形。

10. **输出流操作符重载:**
    - `operator<<(std::ostream& os, const PhysicalRect& value)`:  允许将 `PhysicalRect` 对象直接输出到 `std::ostream`。

### 与 JavaScript, HTML, CSS 的关系及举例说明:

`PhysicalRect` 类是渲染引擎内部用于布局和绘制计算的核心类之一，它直接反映了网页元素的几何属性，因此与 JavaScript, HTML, 和 CSS 都有着密切的关系。

**HTML:**

- **关系:** HTML 元素在渲染树中会被表示为各种类型的盒子（如块级盒子、行内盒子）。`PhysicalRect` 用于存储这些盒子在屏幕上的最终物理位置和尺寸。
- **举例:**  一个 `<div>` 元素在渲染完成后，其在屏幕上的实际位置和大小会被计算出来并存储在一个 `PhysicalRect` 对象中。

**CSS:**

- **关系:** CSS 属性（如 `width`, `height`, `top`, `left`, `margin`, `padding`, `border` 等）直接影响 `PhysicalRect` 对象的值。渲染引擎会根据 CSS 样式计算出每个元素的 `PhysicalRect`。
- **举例:**
  ```html
  <div style="width: 100px; height: 50px; margin-left: 20px; margin-top: 10px; position: absolute; left: 30px; top: 40px;"></div>
  ```
  这个 `div` 元素的 `PhysicalRect` 的 `offset.left` 可能为 30px（`left` 属性），`offset.top` 可能为 40px（`top` 属性），`size.width` 为 100px，`size.height` 为 50px。 `margin` 属性会影响其在布局计算中的位置。

**JavaScript:**

- **关系:** JavaScript 可以通过 DOM API 获取元素的几何信息，这些信息通常与渲染引擎内部的 `PhysicalRect` 相关联。
- **举例:**
  - 使用 `element.getBoundingClientRect()` 方法会返回一个 `DOMRect` 对象，其属性（`x`, `y`, `width`, `height`, `top`, `right`, `bottom`, `left`) 对应于元素的 `PhysicalRect` 的信息。
  - 使用 `element.offsetWidth` 和 `element.offsetHeight` 可以获取元素的物理尺寸，这与 `PhysicalRect` 的 `size.width` 和 `size.height` 相关。
  - 使用 `element.offsetLeft` 和 `element.offsetTop` 可以获取元素相对于其 `offsetParent` 的偏移量，这与 `PhysicalRect` 的 `offset` 信息相关。

### 逻辑推理及假设输入与输出:

**假设输入:**

```
PhysicalRect rect1(PhysicalOffset(10, 20), PhysicalSize(100, 50)); // 左上角 (10, 20)，宽度 100，高度 50
PhysicalRect rect2(PhysicalOffset(50, 40), PhysicalSize(80, 60));  // 左上角 (50, 40)，宽度 80，高度 60
PhysicalOffset point(30, 30);
```

**逻辑推理与输出:**

1. **`DistanceAsSize(point)` (对于 `rect1`):**
   - 目标点在矩形内部，所以距离为 0。
   - 输出: `PhysicalSize(0, 0)`

2. **`SquaredDistanceTo(point)` (对于 `rect1`):**
   - 目标点在矩形内部，所以最近的点就是目标点本身，距离为 0。
   - 输出: `0`

3. **`Contains(rect2)` (对于 `rect1`):**
   - `rect1` 的右边界是 110，下边界是 70。
   - `rect2` 的左上角是 (50, 40)，右下角是 (130, 100)。
   - `rect1` 不能完全包含 `rect2`。
   - 输出: `false`

4. **`Intersects(rect2)` (对于 `rect1`):**
   - `rect1` 的右边界是 110，下边界是 70。
   - `rect2` 的左边界 50 < 110，`rect1` 的左边界 10 < 130。
   - `rect2` 的上边界 40 < 70，`rect1` 的上边界 20 < 100。
   - 两个矩形相交。
   - 输出: `true`

5. **`Unite(rect2)` (对于 `rect1`):**
   - 合并后的矩形的左上角是 `min(10, 50)` 和 `min(20, 40)`，即 (10, 20)。
   - 合并后的矩形的右下角是 `max(10+100, 50+80)` 和 `max(20+50, 40+60)`，即 (130, 100)。
   - 合并后的尺寸是 (130 - 10, 100 - 20) = (120, 80)。
   - 输出: `PhysicalRect` 对象，其 `offset` 为 `(10, 20)`，`size` 为 `(120, 80)`。

6. **`Intersect(rect2)` (对于 `rect1`):**
   - 交集的左上角是 `max(10, 50)` 和 `max(20, 40)`，即 (50, 40)。
   - 交集的右下角是 `min(10+100, 50+80)` 和 `min(20+50, 40+60)`，即 (110, 70)。
   - 交集的尺寸是 (110 - 50, 70 - 40) = (60, 30)。
   - 输出: `PhysicalRect` 对象，其 `offset` 为 `(50, 40)`，`size` 为 `(60, 30)`。

### 用户或编程常见的使用错误:

1. **混淆 `Intersects` 和 `IntersectsInclusively`:**
   - **错误:**  在需要判断两个矩形是否真正重叠时使用了 `IntersectsInclusively`，导致边缘接触的矩形也被认为是相交的。
   - **正确做法:**  如果只关注严格的重叠，应使用 `Intersects`。如果边缘接触也算作相交，则使用 `IntersectsInclusively`。

2. **假设 `PhysicalRect` 使用整数坐标:**
   - **错误:**  直接将 `PhysicalRect` 的坐标和尺寸用于需要整数像素值的场景，而没有进行适当的取整或转换。
   - **正确做法:**  `PhysicalRect` 使用 `LayoutUnit` 类型，它可以是浮点数。在需要像素边界时，应使用 `FloorToInt`, `CeilToInt` 等方法进行转换，例如 `ExpandEdgesToPixelBoundaries()` 所做的那样。

3. **误解 `Unite` 操作:**
   - **错误:**  认为 `Unite` 操作会返回两个矩形的交集，实际上它是返回能包含这两个矩形的最小矩形。
   - **正确做法:**  如果要获取交集，应使用 `Intersect` 方法。

4. **未考虑空矩形的情况:**
   - **错误:**  在处理一组矩形时，没有考虑到其中可能存在尺寸为零的空矩形，导致逻辑错误，尤其是在使用 `Unite` 等操作时。
   - **正确做法:**  在必要时检查矩形是否为空 (`IsEmpty()`)，或者使用像 `UniteIfNonZero` 这样的方法。

5. **在需要包含性判断时使用相交性判断:**
   - **错误:**  需要判断一个元素是否完全包含另一个元素时，错误地使用了 `Intersects` 或 `IntersectsInclusively`。
   - **正确做法:**  使用 `Contains` 方法来判断一个矩形是否完全包含另一个矩形。

理解 `PhysicalRect` 及其相关操作对于理解 Blink 渲染引擎的布局和绘制机制至关重要。避免上述常见错误可以提高代码的准确性和效率。

### 提示词
```
这是目录为blink/renderer/core/layout/geometry/physical_rect.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"

#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

PhysicalSize PhysicalRect::DistanceAsSize(PhysicalOffset target) const {
  target -= offset;
  PhysicalSize distance;
  if (target.left < 0)
    distance.width = -target.left;
  else if (target.left > size.width)
    distance.width = target.left - size.width;
  if (target.top < 0)
    distance.height = -target.top;
  else if (target.top > size.height)
    distance.height = target.top - size.height;
  return distance;
}

LayoutUnit PhysicalRect::SquaredDistanceTo(const PhysicalOffset& point) const {
  LayoutUnit x1 = X(), x2 = Right();
  if (x1 > x2)
    std::swap(x1, x2);
  LayoutUnit diff_x = point.left - ClampTo<LayoutUnit>(point.left, x1, x2);
  LayoutUnit y1 = Y(), y2 = Bottom();
  if (y1 > y2)
    std::swap(y1, y2);
  LayoutUnit diff_y = point.top - ClampTo<LayoutUnit>(point.top, y1, y2);
  return diff_x * diff_x + diff_y * diff_y;
}

bool PhysicalRect::Contains(const PhysicalRect& other) const {
  return offset.left <= other.offset.left && offset.top <= other.offset.top &&
         Right() >= other.Right() && Bottom() >= other.Bottom();
}

bool PhysicalRect::Intersects(const PhysicalRect& other) const {
  // Checking emptiness handles negative widths as well as zero.
  return !IsEmpty() && !other.IsEmpty() && offset.left < other.Right() &&
         other.offset.left < Right() && offset.top < other.Bottom() &&
         other.offset.top < Bottom();
}

bool PhysicalRect::IntersectsInclusively(const PhysicalRect& other) const {
  // TODO(pdr): How should negative widths or heights be handled?
  return offset.left <= other.Right() && other.offset.left <= Right() &&
         offset.top <= other.Bottom() && other.offset.top <= Bottom();
}

void PhysicalRect::Unite(const PhysicalRect& other) {
  if (other.IsEmpty())
    return;
  if (IsEmpty()) {
    *this = other;
    return;
  }

  UniteEvenIfEmpty(other);
}

void PhysicalRect::UniteIfNonZero(const PhysicalRect& other) {
  if (other.size.IsZero())
    return;
  if (size.IsZero()) {
    *this = other;
    return;
  }

  UniteEvenIfEmpty(other);
}

void PhysicalRect::UniteEvenIfEmpty(const PhysicalRect& other) {
  LayoutUnit left = std::min(offset.left, other.offset.left);
  LayoutUnit top = std::min(offset.top, other.offset.top);
  LayoutUnit right = std::max(Right(), other.Right());
  LayoutUnit bottom = std::max(Bottom(), other.Bottom());
  size = {right - left, bottom - top};

  // If either width or height are not saturated, right - width == left and
  // bottom - height == top. If they are saturated, instead of using left/top
  // directly for the offset, the subtraction results in the united rect to
  // favor content in the positive directions.
  // Note that this is just a heuristic as the true rect would normally be
  // larger than the max LayoutUnit value.
  offset = {right - size.width, bottom - size.height};
}

void PhysicalRect::Expand(const PhysicalBoxStrut& strut) {
  ExpandEdges(strut.top, strut.right, strut.bottom, strut.left);
}

void PhysicalRect::ExpandEdgesToPixelBoundaries() {
  int left = FloorToInt(offset.left);
  int top = FloorToInt(offset.top);
  int max_right = (offset.left + size.width).Ceil();
  int max_bottom = (offset.top + size.height).Ceil();
  offset.left = LayoutUnit(left);
  offset.top = LayoutUnit(top);
  size.width = LayoutUnit(max_right - left);
  size.height = LayoutUnit(max_bottom - top);
}

void PhysicalRect::Contract(const PhysicalBoxStrut& strut) {
  ExpandEdges(-strut.top, -strut.right, -strut.bottom, -strut.left);
}

void PhysicalRect::Intersect(const PhysicalRect& other) {
  PhysicalOffset new_offset(std::max(X(), other.X()), std::max(Y(), other.Y()));
  PhysicalOffset new_max_point(std::min(Right(), other.Right()),
                               std::min(Bottom(), other.Bottom()));

  // Return a clean empty rectangle for non-intersecting cases.
  if (new_offset.left >= new_max_point.left ||
      new_offset.top >= new_max_point.top) {
    new_offset = PhysicalOffset();
    new_max_point = PhysicalOffset();
  }

  offset = new_offset;
  size = {new_max_point.left - new_offset.left,
          new_max_point.top - new_offset.top};
}

bool PhysicalRect::InclusiveIntersect(const PhysicalRect& other) {
  PhysicalOffset new_offset(std::max(X(), other.X()), std::max(Y(), other.Y()));
  PhysicalOffset new_max_point(std::min(Right(), other.Right()),
                               std::min(Bottom(), other.Bottom()));

  if (new_offset.left > new_max_point.left ||
      new_offset.top > new_max_point.top) {
    *this = PhysicalRect();
    return false;
  }

  offset = new_offset;
  size = {new_max_point.left - new_offset.left,
          new_max_point.top - new_offset.top};
  return true;
}

String PhysicalRect::ToString() const {
  return String::Format("%s %s", offset.ToString().Ascii().c_str(),
                        size.ToString().Ascii().c_str());
}

PhysicalRect UnionRect(const Vector<PhysicalRect>& rects) {
  PhysicalRect result;
  for (const auto& rect : rects)
    result.Unite(rect);
  return result;
}

PhysicalRect UnionRectEvenIfEmpty(const Vector<PhysicalRect>& rects) {
  wtf_size_t count = rects.size();
  if (!count)
    return PhysicalRect();

  PhysicalRect result = rects[0];
  for (wtf_size_t i = 1; i < count; ++i)
    result.UniteEvenIfEmpty(rects[i]);

  return result;
}

std::ostream& operator<<(std::ostream& os, const PhysicalRect& value) {
  return os << value.ToString();
}

}  // namespace blink
```