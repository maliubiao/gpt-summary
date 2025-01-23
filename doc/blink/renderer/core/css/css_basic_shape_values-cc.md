Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The primary request is to understand the *functionality* of the `css_basic_shape_values.cc` file in the Chromium Blink engine. This means identifying what aspects of CSS it handles. The prompt also asks for connections to JavaScript, HTML, CSS, examples, logical reasoning, common errors, and debugging clues. This requires a multi-faceted analysis.

**2. Initial Code Scan (Keywords and Structure):**

My first step is to quickly scan the code for recognizable keywords and structural elements. I see:

* **`namespace blink::cssvalue`**: This immediately tells me it's related to CSS values within the Blink rendering engine.
* **`class CSSBasicShapeCircleValue`, `CSSBasicShapeEllipseValue`, `CSSBasicShapePolygonValue`, `CSSBasicShapeInsetValue`, `CSSBasicShapeRectValue`, `CSSBasicShapeXYWHValue`**: These class names strongly suggest that the file deals with defining and manipulating different types of CSS basic shapes.
* **`CustomCSSText()`**:  This method, present in each shape class, hints at how these shapes are serialized (converted to a string representation).
* **`Equals()`**: This suggests a comparison mechanism between shape objects.
* **`TraceAfterDispatch()`**: This is a Blink-specific mechanism for garbage collection and object tracing, indicating lifecycle management.
* **Helper functions like `BuildCircleString`, `BuildEllipseString`, `BuildPolygonString`, `BuildRectStringCommon`, `BuildXYWHString`**: These clearly handle the string construction for different shapes.
* **`BuildSerializablePositionOffset()`**:  This function looks important for handling the positioning of shapes, particularly the `at` keyword.
* **`CSSValuePair`**:  This type is used for representing pairs of CSS values, likely for properties like `center` positions or corner radii.
* **`CSSIdentifierValue`, `CSSNumericLiteralValue`, `CSSPrimitiveValue`**: These are fundamental CSS value types.
* **Keywords like `circle`, `ellipse`, `polygon`, `inset`, `rect`, `xywh`**: These directly correspond to CSS basic shape functions.

**3. Mapping Code to CSS Concepts:**

Based on the identified keywords and class names, I start mapping the code to known CSS concepts:

* **`CSSBasicShapeCircleValue`**:  Represents the `circle()` CSS function.
* **`CSSBasicShapeEllipseValue`**: Represents the `ellipse()` CSS function.
* **`CSSBasicShapePolygonValue`**: Represents the `polygon()` CSS function.
* **`CSSBasicShapeInsetValue`**: Represents the `inset()` CSS function (for `clip-path`).
* **`CSSBasicShapeRectValue`**:  Represents the older `rect()` CSS function (mostly deprecated but still potentially encountered).
* **`CSSBasicShapeXYWHValue`**: Represents the `xywh()` CSS function (often used in SVG).

**4. Analyzing Key Functions (Focus on `CustomCSSText()` and `Build...String`):**

The `CustomCSSText()` methods are crucial. They reveal how the internal representation of the shape is converted back into a CSS string. I examine the helper functions they call (`BuildCircleString`, etc.) to understand the specific formatting logic for each shape, including:

* **Parameters**: What properties are included (radius, center, points, etc.)?
* **Syntax**: How are these properties ordered and separated?
* **Keywords**:  The use of "at" for positioning.
* **Edge Cases**: How are optional parameters handled (e.g., implicit center)?

**5. Understanding `BuildSerializablePositionOffset()`:**

This function stands out as potentially complex. I analyze its logic to understand how it normalizes position values:

* **Handling Keywords**:  Recognizing `left`, `top`, `right`, `bottom`, and `center`.
* **Handling Percentages**:  Adjusting percentage values when used with `right` or `bottom`.
* **Default Values**:  Setting `center` to 50%.
* **Output**: Creating a `CSSValuePair` representing the normalized side and offset.

**6. Identifying Relationships with HTML, JavaScript, and CSS:**

* **CSS**: The most direct relationship. The code *implements* the functionality of CSS basic shapes.
* **HTML**: These shapes are used in CSS properties that affect the visual presentation of HTML elements (e.g., `clip-path`, `shape-outside`).
* **JavaScript**: JavaScript can manipulate the CSS properties that use these shapes, leading to dynamic visual effects.

**7. Constructing Examples:**

With a solid understanding of the code and its CSS counterparts, I can create concrete examples of how these shapes are used in CSS and how JavaScript might interact with them.

**8. Logical Reasoning (Assumptions and Outputs):**

I look for sections where the code performs transformations or normalizations, like `BuildSerializablePositionOffset()`. I can then create hypothetical inputs (e.g., different ways of specifying the center) and predict the output (the normalized `CSSValuePair`).

**9. Identifying Common Errors:**

By understanding how the code parses and serializes the shapes, I can infer common user errors, such as:

* Incorrect syntax (missing commas, wrong order of parameters).
* Using invalid units.
* Providing an incorrect number of points for a polygon.

**10. Debugging Clues (Tracing the Execution Flow):**

I consider how a developer might end up looking at this code during debugging. This involves thinking about the steps leading to the shape being rendered:

* The user writes CSS.
* The browser parses the CSS.
* Blink's CSS engine processes the `clip-path` or `shape-outside` property.
* The code in this file is used to create and manipulate the shape objects.
* If something goes wrong, a developer might set breakpoints in this code to inspect the values of the shape objects.

**11. Structuring the Answer:**

Finally, I organize my findings into a clear and structured answer, addressing each part of the original prompt. I use headings, bullet points, and code snippets to make the information easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file just *represents* the shapes.
* **Correction:** The `CustomCSSText()` functions indicate that it's also involved in *serializing* the shapes back to CSS strings.
* **Initial thought:**  The `Equals()` function is just for basic equality.
* **Refinement:** While basic, it's essential for caching and avoiding unnecessary recalculations within the rendering engine.
* **Ensuring clarity:**  Making sure the connection between the C++ code and the corresponding CSS syntax is explicit.

By following these steps, combining code analysis with knowledge of CSS and browser architecture, I can provide a comprehensive and accurate explanation of the functionality of `css_basic_shape_values.cc`.
这个文件 `blink/renderer/core/css/css_basic_shape_values.cc` 在 Chromium Blink 引擎中负责**表示和序列化 CSS Basic Shapes 的值**。

**功能列举:**

1. **定义 CSS Basic Shape 类的实现:**
   - 它实现了 `CSSBasicShapeCircleValue`, `CSSBasicShapeEllipseValue`, `CSSBasicShapePolygonValue`, `CSSBasicShapeInsetValue`, `CSSBasicShapeRectValue`, `CSSBasicShapeXYWHValue` 等类，这些类分别对应 CSS 中定义的 `circle()`, `ellipse()`, `polygon()`, `inset()`, `rect()`, 和 `xywh()` 基本形状函数。

2. **存储形状的属性值:**
   - 每个形状类都包含成员变量来存储该形状的属性值。例如，`CSSBasicShapeCircleValue` 存储圆的半径和中心点坐标。

3. **实现 `CustomCSSText()` 方法:**
   - 这个方法负责将形状对象转换为其对应的 CSS 文本表示形式。例如，一个 `CSSBasicShapeCircleValue` 对象会被转换为像 `"circle(50px at 100px 100px)"` 这样的字符串。这个过程也涉及到对一些属性值的规范化和序列化处理。

4. **实现 `Equals()` 方法:**
   - 这个方法用于比较两个相同类型的基本形状对象是否相等，通过比较它们的属性值来实现。

5. **实现 `TraceAfterDispatch()` 方法:**
   - 这是 Blink 引擎中用于垃圾回收的机制，用于标记对象及其引用的其他对象，以便垃圾回收器知道哪些内存需要保留。

6. **提供辅助函数用于构建和序列化:**
   - 文件中包含一些静态辅助函数，例如 `BuildCircleString`, `BuildEllipseString`, `BuildPolygonString`, `BuildRectStringCommon`, `BuildXYWHString`，用于简化不同形状的 CSS 字符串构建过程。
   - 还有 `BuildSerializablePositionOffset` 用于处理 `circle()` 和 `ellipse()` 的 `at` 位置参数的序列化。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件直接关联到 **CSS** 的功能，因为它负责处理 CSS basic shape 的值。当浏览器解析 CSS 样式时，如果遇到使用了 basic shape 函数的属性（例如 `clip-path`, `shape-outside`），就会创建这个文件中定义的相应对象来表示这些形状。

* **CSS:**
    - **举例:**  在 CSS 中使用 `clip-path` 属性来裁剪一个元素为圆形：
      ```css
      .my-element {
        clip-path: circle(50px at 100px 100px);
      }
      ```
      当浏览器解析这段 CSS 时，会创建一个 `CSSBasicShapeCircleValue` 对象，其半径属性为 50px，中心点 x 坐标为 100px，y 坐标为 100px。 `CustomCSSText()` 方法会将这个对象序列化为 `"circle(50px at 100px 100px)"` 这样的字符串。

* **HTML:**
    - **举例:** HTML 结构定义了应用 CSS 样式的元素：
      ```html
      <div class="my-element">这是一个被裁剪的元素</div>
      ```
      这个 HTML 元素通过 CSS 类名 `.my-element` 与上面提到的 CSS 规则关联起来。

* **JavaScript:**
    - **举例:** JavaScript 可以动态地修改元素的 CSS 样式，包括使用 basic shape：
      ```javascript
      const element = document.querySelector('.my-element');
      element.style.clipPath = 'ellipse(60px 40px at 50% 50%)';
      ```
      当这段 JavaScript 代码执行时，浏览器会重新解析 CSS 值，并创建一个新的 `CSSBasicShapeEllipseValue` 对象，并更新元素的渲染。

**逻辑推理 (假设输入与输出):**

假设我们有一个 `CSSBasicShapeCircleValue` 对象，其属性如下：

* `radius_`: 一个表示 50 像素的 `CSSPrimitiveValue` 对象。
* `center_x_`: 一个表示 100 像素的 `CSSPrimitiveValue` 对象。
* `center_y_`: 一个表示 100 像素的 `CSSPrimitiveValue` 对象。

**假设输入:**  调用这个对象的 `CustomCSSText()` 方法。

**预期输出:** 字符串 `"circle(50px at 100px 100px)"`。

再假设一个 `CSSBasicShapePolygonValue` 对象，表示一个三角形：

* `wind_rule_`: `RULE_NONZERO` (默认的填充规则)。
* `values_`: 一个包含六个 `CSSPrimitiveValue` 对象的向量，分别表示三角形的三个顶点的 x 和 y 坐标，例如：`[10px, 10px, 100px, 10px, 50px, 100px]`。

**假设输入:** 调用这个对象的 `CustomCSSText()` 方法。

**预期输出:** 字符串 `"polygon(10px 10px, 100px 10px, 50px 100px)"`。

**用户或编程常见的使用错误 (举例说明):**

1. **语法错误:**  在 CSS 中编写 basic shape 函数时，参数的顺序、分隔符可能会出错。
   - **错误示例:** `clip-path: circle(at 100px 100px 50px);`  (半径应该在 `at` 之前)
   - **Blink 的处理:**  Blink 的 CSS 解析器会尝试解析这个值，如果无法正确解析，可能会忽略该样式或使用默认值。在调试工具的 "Styles" 面板中可能会看到一个警告或错误。

2. **单位错误:**  忘记指定单位或使用了不合适的单位。
   - **错误示例:** `clip-path: circle(50 at 100 100);` (缺少单位)
   - **Blink 的处理:**  Blink 通常会认为没有单位的数值是像素值，但在某些情况下可能不会生效。

3. **`polygon()` 的点坐标错误:**  提供的坐标数量不是偶数，或者坐标值无效。
   - **错误示例:** `clip-path: polygon(10px 10px, 100px);` (缺少一个 y 坐标)
   - **Blink 的处理:**  Blink 会解析失败，导致 `clip-path` 效果不生效。

4. **`inset()` 的参数顺序错误:**  `inset()` 接受 top, right, bottom, left 的顺序。
   - **错误示例:** `clip-path: inset(10px 20px 30px);` (缺少 left 值，但会被解释为 top, right=left, bottom)
   - **Blink 的处理:**  Blink 会按照规范解析，但如果用户意图错误，会导致不期望的裁剪效果。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户编写 HTML 和 CSS 代码:**  用户在其 HTML 文件中创建元素，并在 CSS 文件或 `<style>` 标签中为这些元素添加使用了 basic shape 函数的样式规则（例如 `clip-path`, `shape-outside`）。

2. **浏览器加载和解析 HTML 和 CSS:**  当用户在浏览器中打开包含这些代码的网页时，浏览器开始解析 HTML 结构和 CSS 样式。

3. **CSS 引擎遇到 basic shape 函数:**  当 CSS 解析器遇到像 `clip-path: circle(50px at 100px 100px);` 这样的规则时，它会识别出 `circle()` 是一个 basic shape 函数。

4. **创建 CSSBasicShape 值对象:**  Blink 的 CSS 引擎会根据解析到的参数，创建对应的 `CSSBasicShapeCircleValue` 对象，并将解析到的半径和中心点信息存储到该对象的成员变量中。这个过程可能会调用 `css_basic_shape_values.cc` 文件中的相关代码。

5. **布局和渲染阶段使用 shape 对象:**  在布局和渲染阶段，Blink 使用这些 basic shape 对象来计算元素的裁剪路径或形状边界，最终将元素以指定的形状显示在屏幕上。

**作为调试线索:**

如果开发者在使用 CSS basic shape 时遇到问题（例如形状显示不正确、没有效果等），他们可能会进行以下调试步骤，其中就可能涉及到查看 `css_basic_shape_values.cc` 的代码：

1. **检查 CSS 语法:**  使用浏览器的开发者工具 (通常是 "Elements" 或 "Inspector" 面板) 查看应用的 CSS 规则，确认语法是否正确。如果浏览器解析 CSS 时遇到错误，可能会在此处显示警告或错误信息。

2. **查看计算后的样式:**  在开发者工具中查看元素的 "Computed" 样式，确认 `clip-path` 或 `shape-outside` 属性的值是否如预期。如果值为空或与预期不符，说明 CSS 解析或应用过程中可能出现了问题。

3. **断点调试 Blink 渲染引擎代码:**  对于更深入的调试，开发者可以使用 Chromium 的调试工具 (如 `gdb` 或 `lldb`)，在 Blink 渲染引擎的 CSS 相关代码中设置断点，例如在 `CSSBasicShapeCircleValue::CustomCSSText()` 或 `BuildCircleString()` 等函数中设置断点，来检查形状对象的属性值和序列化过程，从而定位问题所在。 这就需要他们了解 `css_basic_shape_values.cc` 文件的作用以及相关的类和函数。

总而言之，`css_basic_shape_values.cc` 是 Blink 引擎中处理 CSS basic shape 值的核心组件，它将 CSS 语法表示的形状转换为内部对象，并负责将这些对象序列化回 CSS 字符串，在浏览器的渲染过程中起着至关重要的作用。理解这个文件的功能有助于开发者理解 CSS basic shape 的工作原理，并进行更有效的调试。

### 提示词
```
这是目录为blink/renderer/core/css/css_basic_shape_values.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Adobe Systems Incorporated. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/css_basic_shape_values.h"

#include "base/check.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {
namespace cssvalue {

static String BuildCircleString(const String& radius,
                                const String& center_x,
                                const String& center_y,
                                bool has_explicit_center) {
  char at[] = "at";
  char separator[] = " ";
  StringBuilder result;
  result.Append("circle(");
  if (!radius.IsNull()) {
    result.Append(radius);
  }

  if (has_explicit_center) {
    if (!radius.IsNull()) {
      result.Append(separator);
    }
    result.Append(at);
    result.Append(separator);
    result.Append(center_x);
    result.Append(separator);
    result.Append(center_y);
  }
  result.Append(')');
  return result.ReleaseString();
}

static String SerializePositionOffset(const CSSValuePair& offset,
                                      const CSSValuePair& other) {
  if ((To<CSSIdentifierValue>(offset.First()).GetValueID() ==
           CSSValueID::kLeft &&
       To<CSSIdentifierValue>(other.First()).GetValueID() ==
           CSSValueID::kTop) ||
      (To<CSSIdentifierValue>(offset.First()).GetValueID() ==
           CSSValueID::kTop &&
       To<CSSIdentifierValue>(other.First()).GetValueID() ==
           CSSValueID::kLeft)) {
    return offset.Second().CssText();
  }
  return offset.CssText();
}

static CSSValuePair* BuildSerializablePositionOffset(CSSValue* offset,
                                                     CSSValueID default_side) {
  CSSValueID side = default_side;
  const CSSPrimitiveValue* amount = nullptr;

  if (!offset) {
    side = CSSValueID::kCenter;
  } else if (auto* offset_identifier_value =
                 DynamicTo<CSSIdentifierValue>(offset)) {
    side = offset_identifier_value->GetValueID();
  } else if (auto* offset_value_pair = DynamicTo<CSSValuePair>(offset)) {
    side = To<CSSIdentifierValue>(offset_value_pair->First()).GetValueID();
    amount = &To<CSSPrimitiveValue>(offset_value_pair->Second());
    if ((side == CSSValueID::kRight || side == CSSValueID::kBottom) &&
        amount->IsPercentage()) {
      side = default_side;
      amount = CSSNumericLiteralValue::Create(
          100 - amount->GetFloatValue(),
          CSSPrimitiveValue::UnitType::kPercentage);
    }
  } else {
    amount = To<CSSPrimitiveValue>(offset);
  }

  if (side == CSSValueID::kCenter) {
    side = default_side;
    amount = CSSNumericLiteralValue::Create(
        50, CSSPrimitiveValue::UnitType::kPercentage);
  } else if (!amount ||
             (amount->IsLength() &&
              amount->IsZero() == CSSPrimitiveValue::BoolStatus::kTrue)) {
    if (side == CSSValueID::kRight || side == CSSValueID::kBottom) {
      amount = CSSNumericLiteralValue::Create(
          100, CSSPrimitiveValue::UnitType::kPercentage);
    } else {
      amount = CSSNumericLiteralValue::Create(
          0, CSSPrimitiveValue::UnitType::kPercentage);
    }
    side = default_side;
  }

  return MakeGarbageCollected<CSSValuePair>(CSSIdentifierValue::Create(side),
                                            amount,
                                            CSSValuePair::kKeepIdenticalValues);
}

String CSSBasicShapeCircleValue::CustomCSSText() const {
  CSSValuePair* normalized_cx =
      BuildSerializablePositionOffset(center_x_, CSSValueID::kLeft);
  CSSValuePair* normalized_cy =
      BuildSerializablePositionOffset(center_y_, CSSValueID::kTop);

  String radius;
  auto* radius_identifier_value = DynamicTo<CSSIdentifierValue>(radius_.Get());
  if (radius_ &&
      !(radius_identifier_value &&
        radius_identifier_value->GetValueID() == CSSValueID::kClosestSide)) {
    radius = radius_->CssText();
  }

  return BuildCircleString(
      radius, SerializePositionOffset(*normalized_cx, *normalized_cy),
      SerializePositionOffset(*normalized_cy, *normalized_cx), center_x_);
}

bool CSSBasicShapeCircleValue::Equals(
    const CSSBasicShapeCircleValue& other) const {
  return base::ValuesEquivalent(center_x_, other.center_x_) &&
         base::ValuesEquivalent(center_y_, other.center_y_) &&
         base::ValuesEquivalent(radius_, other.radius_);
}

void CSSBasicShapeCircleValue::TraceAfterDispatch(
    blink::Visitor* visitor) const {
  visitor->Trace(center_x_);
  visitor->Trace(center_y_);
  visitor->Trace(radius_);
  CSSValue::TraceAfterDispatch(visitor);
}

static String BuildEllipseString(const String& radius_x,
                                 const String& radius_y,
                                 const String& center_x,
                                 const String& center_y,
                                 bool has_explicit_center) {
  char at[] = "at";
  char separator[] = " ";
  StringBuilder result;
  result.Append("ellipse(");
  bool needs_separator = false;
  if (!radius_x.IsNull()) {
    result.Append(radius_x);
    needs_separator = true;
  }
  if (!radius_y.IsNull()) {
    if (needs_separator) {
      result.Append(separator);
    }
    result.Append(radius_y);
    needs_separator = true;
  }

  if (has_explicit_center) {
    if (needs_separator) {
      result.Append(separator);
    }
    result.Append(at);
    result.Append(separator);
    result.Append(center_x);
    result.Append(separator);
    result.Append(center_y);
  }
  result.Append(')');
  return result.ReleaseString();
}

String CSSBasicShapeEllipseValue::CustomCSSText() const {
  CSSValuePair* normalized_cx =
      BuildSerializablePositionOffset(center_x_, CSSValueID::kLeft);
  CSSValuePair* normalized_cy =
      BuildSerializablePositionOffset(center_y_, CSSValueID::kTop);

  String radius_x;
  String radius_y;
  if (radius_x_) {
    DCHECK(radius_y_);

    auto* radius_x_identifier_value =
        DynamicTo<CSSIdentifierValue>(radius_x_.Get());
    bool radius_x_closest_side =
        (radius_x_identifier_value &&
         radius_x_identifier_value->GetValueID() == CSSValueID::kClosestSide);

    auto* radius_y_identifier_value =
        DynamicTo<CSSIdentifierValue>(radius_y_.Get());
    bool radius_y_closest_side =
        (radius_y_identifier_value &&
         radius_y_identifier_value->GetValueID() == CSSValueID::kClosestSide);

    if (!radius_x_closest_side || !radius_y_closest_side) {
      radius_x = radius_x_->CssText();
      radius_y = radius_y_->CssText();
    }
  }

  return BuildEllipseString(
      radius_x, radius_y,
      SerializePositionOffset(*normalized_cx, *normalized_cy),
      SerializePositionOffset(*normalized_cy, *normalized_cx), center_x_);
}

bool CSSBasicShapeEllipseValue::Equals(
    const CSSBasicShapeEllipseValue& other) const {
  return base::ValuesEquivalent(center_x_, other.center_x_) &&
         base::ValuesEquivalent(center_y_, other.center_y_) &&
         base::ValuesEquivalent(radius_x_, other.radius_x_) &&
         base::ValuesEquivalent(radius_y_, other.radius_y_);
}

void CSSBasicShapeEllipseValue::TraceAfterDispatch(
    blink::Visitor* visitor) const {
  visitor->Trace(center_x_);
  visitor->Trace(center_y_);
  visitor->Trace(radius_x_);
  visitor->Trace(radius_y_);
  CSSValue::TraceAfterDispatch(visitor);
}

static String BuildPolygonString(const WindRule& wind_rule,
                                 const Vector<String>& points) {
  DCHECK(!(points.size() % 2));

  StringBuilder result;
  const char kEvenOddOpening[] = "polygon(evenodd, ";
  const char kNonZeroOpening[] = "polygon(";
  const char kCommaSeparator[] = ", ";
  static_assert(sizeof(kEvenOddOpening) > sizeof(kNonZeroOpening),
                "polygon string openings should be the same length");

  // Compute the required capacity in advance to reduce allocations.
  wtf_size_t length = sizeof(kEvenOddOpening) - 1;
  for (wtf_size_t i = 0; i < points.size(); i += 2) {
    if (i) {
      length += (sizeof(kCommaSeparator) - 1);
    }
    // add length of two strings, plus one for the space separator.
    length += points[i].length() + 1 + points[i + 1].length();
  }
  result.ReserveCapacity(length);

  if (wind_rule == RULE_EVENODD) {
    result.Append(kEvenOddOpening);
  } else {
    result.Append(kNonZeroOpening);
  }

  for (wtf_size_t i = 0; i < points.size(); i += 2) {
    if (i) {
      result.Append(kCommaSeparator);
    }
    result.Append(points[i]);
    result.Append(' ');
    result.Append(points[i + 1]);
  }

  result.Append(')');
  return result.ReleaseString();
}

String CSSBasicShapePolygonValue::CustomCSSText() const {
  Vector<String> points;
  points.ReserveInitialCapacity(values_.size());

  for (wtf_size_t i = 0; i < values_.size(); ++i) {
    points.push_back(values_.at(i)->CssText());
  }

  return BuildPolygonString(wind_rule_, points);
}

bool CSSBasicShapePolygonValue::Equals(
    const CSSBasicShapePolygonValue& other) const {
  return wind_rule_ == other.wind_rule_ &&
         CompareCSSValueVector(values_, other.values_);
}

void CSSBasicShapePolygonValue::TraceAfterDispatch(
    blink::Visitor* visitor) const {
  visitor->Trace(values_);
  CSSValue::TraceAfterDispatch(visitor);
}

static bool BuildInsetRadii(Vector<String>& radii,
                            const String& top_left_radius,
                            const String& top_right_radius,
                            const String& bottom_right_radius,
                            const String& bottom_left_radius) {
  bool show_bottom_left = top_right_radius != bottom_left_radius;
  bool show_bottom_right =
      show_bottom_left || (bottom_right_radius != top_left_radius);
  bool show_top_right =
      show_bottom_right || (top_right_radius != top_left_radius);

  radii.push_back(top_left_radius);
  if (show_top_right) {
    radii.push_back(top_right_radius);
  }
  if (show_bottom_right) {
    radii.push_back(bottom_right_radius);
  }
  if (show_bottom_left) {
    radii.push_back(bottom_left_radius);
  }

  return radii.size() == 1 && radii[0] == "0px";
}

static void AppendRoundedCorners(const char* separator,
                                 const String& top_left_radius_width,
                                 const String& top_left_radius_height,
                                 const String& top_right_radius_width,
                                 const String& top_right_radius_height,
                                 const String& bottom_right_radius_width,
                                 const String& bottom_right_radius_height,
                                 const String& bottom_left_radius_width,
                                 const String& bottom_left_radius_height,
                                 StringBuilder& result) {
  char corners_separator[] = "round";
  if (!top_left_radius_width.IsNull() && !top_left_radius_height.IsNull()) {
    Vector<String> horizontal_radii;
    bool are_default_corner_radii = BuildInsetRadii(
        horizontal_radii, top_left_radius_width, top_right_radius_width,
        bottom_right_radius_width, bottom_left_radius_width);

    Vector<String> vertical_radii;
    are_default_corner_radii &= BuildInsetRadii(
        vertical_radii, top_left_radius_height, top_right_radius_height,
        bottom_right_radius_height, bottom_left_radius_height);

    if (!are_default_corner_radii) {
      result.Append(separator);
      result.Append(corners_separator);

      for (wtf_size_t i = 0; i < horizontal_radii.size(); ++i) {
        result.Append(separator);
        result.Append(horizontal_radii[i]);
      }
      if (horizontal_radii != vertical_radii) {
        result.Append(separator);
        result.Append('/');

        for (wtf_size_t i = 0; i < vertical_radii.size(); ++i) {
          result.Append(separator);
          result.Append(vertical_radii[i]);
        }
      }
    }
  }
}

static String BuildRectStringCommon(const char* opening,
                                    bool show_left_arg,
                                    const String& top,
                                    const String& right,
                                    const String& bottom,
                                    const String& left,
                                    const String& top_left_radius_width,
                                    const String& top_left_radius_height,
                                    const String& top_right_radius_width,
                                    const String& top_right_radius_height,
                                    const String& bottom_right_radius_width,
                                    const String& bottom_right_radius_height,
                                    const String& bottom_left_radius_width,
                                    const String& bottom_left_radius_height) {
  char separator[] = " ";
  StringBuilder result;
  result.Append(opening);
  result.Append(top);
  show_left_arg |= !left.IsNull() && left != right;
  bool show_bottom_arg = !bottom.IsNull() && (bottom != top || show_left_arg);
  bool show_right_arg = !right.IsNull() && (right != top || show_bottom_arg);
  if (show_right_arg) {
    result.Append(separator);
    result.Append(right);
  }
  if (show_bottom_arg) {
    result.Append(separator);
    result.Append(bottom);
  }
  if (show_left_arg) {
    result.Append(separator);
    result.Append(left);
  }

  AppendRoundedCorners(separator, top_left_radius_width, top_left_radius_height,
                       top_right_radius_width, top_right_radius_height,
                       bottom_right_radius_width, bottom_right_radius_height,
                       bottom_left_radius_width, bottom_left_radius_height,
                       result);

  result.Append(')');

  return result.ReleaseString();
}

static String BuildXYWHString(const String& x,
                              const String& y,
                              const String& width,
                              const String& height,
                              const String& top_left_radius_width,
                              const String& top_left_radius_height,
                              const String& top_right_radius_width,
                              const String& top_right_radius_height,
                              const String& bottom_right_radius_width,
                              const String& bottom_right_radius_height,
                              const String& bottom_left_radius_width,
                              const String& bottom_left_radius_height) {
  const char opening[] = "xywh(";
  char separator[] = " ";
  StringBuilder result;

  result.Append(opening);
  result.Append(x);

  result.Append(separator);
  result.Append(y);

  result.Append(separator);
  result.Append(width);

  result.Append(separator);
  result.Append(height);

  AppendRoundedCorners(separator, top_left_radius_width, top_left_radius_height,
                       top_right_radius_width, top_right_radius_height,
                       bottom_right_radius_width, bottom_right_radius_height,
                       bottom_left_radius_width, bottom_left_radius_height,
                       result);

  result.Append(')');

  return result.ReleaseString();
}

static inline void UpdateCornerRadiusWidthAndHeight(
    const CSSValuePair* corner_radius,
    String& width,
    String& height) {
  if (!corner_radius) {
    return;
  }

  width = corner_radius->First().CssText();
  height = corner_radius->Second().CssText();
}

String CSSBasicShapeInsetValue::CustomCSSText() const {
  String top_left_radius_width;
  String top_left_radius_height;
  String top_right_radius_width;
  String top_right_radius_height;
  String bottom_right_radius_width;
  String bottom_right_radius_height;
  String bottom_left_radius_width;
  String bottom_left_radius_height;

  UpdateCornerRadiusWidthAndHeight(TopLeftRadius(), top_left_radius_width,
                                   top_left_radius_height);
  UpdateCornerRadiusWidthAndHeight(TopRightRadius(), top_right_radius_width,
                                   top_right_radius_height);
  UpdateCornerRadiusWidthAndHeight(BottomRightRadius(),
                                   bottom_right_radius_width,
                                   bottom_right_radius_height);
  UpdateCornerRadiusWidthAndHeight(BottomLeftRadius(), bottom_left_radius_width,
                                   bottom_left_radius_height);

  return BuildRectStringCommon(
      "inset(", false, top_ ? top_->CssText() : String(),
      right_ ? right_->CssText() : String(),
      bottom_ ? bottom_->CssText() : String(),
      left_ ? left_->CssText() : String(), top_left_radius_width,
      top_left_radius_height, top_right_radius_width, top_right_radius_height,
      bottom_right_radius_width, bottom_right_radius_height,
      bottom_left_radius_width, bottom_left_radius_height);
}

bool CSSBasicShapeInsetValue::Equals(
    const CSSBasicShapeInsetValue& other) const {
  return base::ValuesEquivalent(top_, other.top_) &&
         base::ValuesEquivalent(right_, other.right_) &&
         base::ValuesEquivalent(bottom_, other.bottom_) &&
         base::ValuesEquivalent(left_, other.left_) &&
         base::ValuesEquivalent(top_left_radius_, other.top_left_radius_) &&
         base::ValuesEquivalent(top_right_radius_, other.top_right_radius_) &&
         base::ValuesEquivalent(bottom_right_radius_,
                                other.bottom_right_radius_) &&
         base::ValuesEquivalent(bottom_left_radius_, other.bottom_left_radius_);
}

void CSSBasicShapeInsetValue::TraceAfterDispatch(
    blink::Visitor* visitor) const {
  visitor->Trace(top_);
  visitor->Trace(right_);
  visitor->Trace(bottom_);
  visitor->Trace(left_);
  visitor->Trace(top_left_radius_);
  visitor->Trace(top_right_radius_);
  visitor->Trace(bottom_right_radius_);
  visitor->Trace(bottom_left_radius_);
  CSSValue::TraceAfterDispatch(visitor);
}

String CSSBasicShapeRectValue::CustomCSSText() const {
  String top_left_radius_width;
  String top_left_radius_height;
  String top_right_radius_width;
  String top_right_radius_height;
  String bottom_right_radius_width;
  String bottom_right_radius_height;
  String bottom_left_radius_width;
  String bottom_left_radius_height;

  UpdateCornerRadiusWidthAndHeight(TopLeftRadius(), top_left_radius_width,
                                   top_left_radius_height);
  UpdateCornerRadiusWidthAndHeight(TopRightRadius(), top_right_radius_width,
                                   top_right_radius_height);
  UpdateCornerRadiusWidthAndHeight(BottomRightRadius(),
                                   bottom_right_radius_width,
                                   bottom_right_radius_height);
  UpdateCornerRadiusWidthAndHeight(BottomLeftRadius(), bottom_left_radius_width,
                                   bottom_left_radius_height);

  return BuildRectStringCommon(
      "rect(", true, top_->CssText(), right_->CssText(), bottom_->CssText(),
      left_->CssText(), top_left_radius_width, top_left_radius_height,
      top_right_radius_width, top_right_radius_height,
      bottom_right_radius_width, bottom_right_radius_height,
      bottom_left_radius_width, bottom_left_radius_height);
}

bool CSSBasicShapeRectValue::Equals(const CSSBasicShapeRectValue& other) const {
  return base::ValuesEquivalent(top_, other.top_) &&
         base::ValuesEquivalent(right_, other.right_) &&
         base::ValuesEquivalent(bottom_, other.bottom_) &&
         base::ValuesEquivalent(left_, other.left_) &&
         base::ValuesEquivalent(top_left_radius_, other.top_left_radius_) &&
         base::ValuesEquivalent(top_right_radius_, other.top_right_radius_) &&
         base::ValuesEquivalent(bottom_right_radius_,
                                other.bottom_right_radius_) &&
         base::ValuesEquivalent(bottom_left_radius_, other.bottom_left_radius_);
}

void CSSBasicShapeRectValue::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(top_);
  visitor->Trace(right_);
  visitor->Trace(bottom_);
  visitor->Trace(left_);
  visitor->Trace(top_left_radius_);
  visitor->Trace(top_right_radius_);
  visitor->Trace(bottom_right_radius_);
  visitor->Trace(bottom_left_radius_);
  CSSValue::TraceAfterDispatch(visitor);
}

void CSSBasicShapeRectValue::Validate() const {
  auto validate_length = [](const CSSValue* length) {
    if (length->IsIdentifierValue()) {
      DCHECK(To<CSSIdentifierValue>(length)->GetValueID() == CSSValueID::kAuto);
      return;
    }
    DCHECK(length->IsPrimitiveValue());
  };

  validate_length(top_);
  validate_length(left_);
  validate_length(bottom_);
  validate_length(right_);
}

String CSSBasicShapeXYWHValue::CustomCSSText() const {
  String top_left_radius_width;
  String top_left_radius_height;
  String top_right_radius_width;
  String top_right_radius_height;
  String bottom_right_radius_width;
  String bottom_right_radius_height;
  String bottom_left_radius_width;
  String bottom_left_radius_height;

  UpdateCornerRadiusWidthAndHeight(TopLeftRadius(), top_left_radius_width,
                                   top_left_radius_height);
  UpdateCornerRadiusWidthAndHeight(TopRightRadius(), top_right_radius_width,
                                   top_right_radius_height);
  UpdateCornerRadiusWidthAndHeight(BottomRightRadius(),
                                   bottom_right_radius_width,
                                   bottom_right_radius_height);
  UpdateCornerRadiusWidthAndHeight(BottomLeftRadius(), bottom_left_radius_width,
                                   bottom_left_radius_height);

  return BuildXYWHString(x_->CssText(), y_->CssText(), width_->CssText(),
                         height_->CssText(), top_left_radius_width,
                         top_left_radius_height, top_right_radius_width,
                         top_right_radius_height, bottom_right_radius_width,
                         bottom_right_radius_height, bottom_left_radius_width,
                         bottom_left_radius_height);
}

bool CSSBasicShapeXYWHValue::Equals(const CSSBasicShapeXYWHValue& other) const {
  return base::ValuesEquivalent(x_, other.x_) &&
         base::ValuesEquivalent(y_, other.y_) &&
         base::ValuesEquivalent(width_, other.width_) &&
         base::ValuesEquivalent(height_, other.height_) &&
         base::ValuesEquivalent(top_left_radius_, other.top_left_radius_) &&
         base::ValuesEquivalent(top_right_radius_, other.top_right_radius_) &&
         base::ValuesEquivalent(bottom_right_radius_,
                                other.bottom_right_radius_) &&
         base::ValuesEquivalent(bottom_left_radius_, other.bottom_left_radius_);
}

void CSSBasicShapeXYWHValue::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(x_);
  visitor->Trace(y_);
  visitor->Trace(width_);
  visitor->Trace(height_);
  visitor->Trace(top_left_radius_);
  visitor->Trace(top_right_radius_);
  visitor->Trace(bottom_right_radius_);
  visitor->Trace(bottom_left_radius_);
  CSSValue::TraceAfterDispatch(visitor);
}

void CSSBasicShapeXYWHValue::Validate() const {
  DCHECK(x_);
  DCHECK(y_);
  DCHECK(width_);
  DCHECK(height_);

  // The spec requires non-negative width and height but we can only validate
  // numeric literals here.
  if (width_->IsNumericLiteralValue()) {
    DCHECK_GE(width_->GetFloatValue(), 0);
  }
  if (height_->IsNumericLiteralValue()) {
    DCHECK_GE(height_->GetFloatValue(), 0);
  }
}

}  // namespace cssvalue
}  // namespace blink
```