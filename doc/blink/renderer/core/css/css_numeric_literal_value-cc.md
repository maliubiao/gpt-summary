Response:
My thought process for analyzing the `CSSNumericLiteralValue.cc` file goes like this:

1. **Understand the Core Purpose:** The filename `css_numeric_literal_value.cc` immediately suggests this file deals with representing numeric values in CSS. The "literal" part implies these are directly written numbers, not calculated or symbolic values.

2. **Examine the Class Definition:**  The code defines `CSSNumericLiteralValue` inheriting from `CSSPrimitiveValue`. This tells me it's a fundamental building block for CSS values. The private member `num_` (a double) and `numeric_literal_unit_type_` (an unsigned) confirm that it stores a number and its associated unit.

3. **Analyze the `Create` Static Method:** This is the primary way to create `CSSNumericLiteralValue` objects. The code has important optimizations:
    * **Caching:** For common integer values of pixels, percentages, and unitless numbers, it uses a cache (`CSSValuePool`). This avoids creating many identical objects, improving performance. This is a *very* common optimization in rendering engines.
    * **Handling Edge Cases:** It explicitly handles `NaN` (Not a Number) and infinity, ensuring they are correctly represented. It also deals with negative zero.
    * **Type Specific Caching:**  The caching logic is different based on the `UnitType`.

4. **Investigate the Accessor/Computation Methods:** The numerous `Compute...()` methods are crucial. They demonstrate how the stored numeric value is interpreted and converted to different units:
    * **Unit Conversions:** `ComputeSeconds`, `ComputeDegrees`, `ComputeDotsPerPixel`, `ComputeInCanonicalUnit` show how values are converted between different units of the same category (time, angle, resolution, length). The `ConversionToCanonicalUnitsScaleFactor` function (likely defined elsewhere) is used for these conversions.
    * **Length Resolution:** `ComputeLengthPx` uses a `CSSLengthResolver` to calculate pixel values for length units. This highlights the dependency on the layout context for resolving relative length units like `em` or `rem`.
    * **Integer/Number/Percentage:** `ComputeInteger`, `ComputeNumber`, `ComputePercentage` provide access to the raw numeric value, potentially clamping it to the expected range.

5. **Look at `AccumulateLengthArray` and `AccumulateLengthUnitTypes`:** These methods are related to how layout calculations are done. They collect information about the lengths used in a style rule, potentially for optimization or dependency tracking.

6. **Understand `IsComputationallyIndependent`:** This method checks if a numeric value can be calculated without needing information from the layout or other elements. This is important for performance optimizations in CSS style resolution. Viewport percentage lengths are considered computationally independent (their value depends on the viewport, not the element itself).

7. **Examine `CustomCSSText`:** This method is responsible for converting the numeric value back into its CSS string representation (e.g., "10px", "50%"). It handles formatting, including special cases for infinity and NaN.

8. **Analyze `Equals` and `CustomHash`:** These are standard methods for comparing `CSSNumericLiteralValue` objects and generating hash codes, essential for using these objects in collections and for equality checks. Note the specific handling of floating-point comparisons.

9. **Consider `CanonicalUnit` and `CreateCanonicalUnitValue`:** These methods relate to normalizing values to a standard unit within their category. For example, converting all time values to seconds.

10. **Connect to Web Concepts (JavaScript, HTML, CSS):**
    * **CSS:** This is the most direct connection. The class represents fundamental CSS numeric values. Examples in the "Explanation" section illustrate how these values are used in CSS properties.
    * **JavaScript:**  JavaScript interacts with CSS through the CSSOM (CSS Object Model). JavaScript code can read and modify CSS property values, and these values are often represented internally using classes like `CSSNumericLiteralValue`. The examples in the "Explanation" section show how JavaScript can get and set these values.
    * **HTML:**  HTML provides the structure to which CSS styles are applied. While `CSSNumericLiteralValue` doesn't directly manipulate HTML, it's a crucial part of the rendering pipeline that determines how HTML elements are displayed.

11. **Think About User and Programming Errors:** The caching mechanism is designed to prevent the creation of many identical objects, which could be a subtle performance issue if not handled correctly. The potential for `NaN` or infinity also represents cases where calculations or input values are invalid.

12. **Consider Debugging:** The explanation of how a user action (like setting a CSS style) can lead to the creation of a `CSSNumericLiteralValue` provides valuable debugging context. Understanding the creation process and the internal representation is key to troubleshooting CSS-related issues.

By following these steps, I can piece together the functionality of the `CSSNumericLiteralValue.cc` file and understand its role within the broader Chromium rendering engine. The key is to break down the code into smaller, manageable parts and then connect those parts to the bigger picture of web technologies.
`blink/renderer/core/css/css_numeric_literal_value.cc` 文件是 Chromium Blink 引擎中负责表示 CSS 数字字面量值的类 `CSSNumericLiteralValue` 的实现。 它的主要功能是：

**核心功能：表示 CSS 中的数字值及其单位**

* **存储数值和单位:**  `CSSNumericLiteralValue` 对象存储一个双精度浮点数 (`num_`) 和一个枚举类型的单位 (`numeric_literal_unit_type_`)。这允许它表示各种 CSS 中的数值，例如 `10px`, `50%`, `2s`, `90deg` 等。
* **类型区分:**  它继承自 `CSSPrimitiveValue` 并拥有一个特定的类型 `kNumericLiteralClass`，用于在 CSS 值的类型系统中进行区分。
* **创建和缓存:**  提供了静态方法 `Create` 用于创建 `CSSNumericLiteralValue` 对象。为了优化性能，对于一些常用的整数值（例如像素、百分比和无单位数字），它使用了缓存机制 (`CSSValuePool`)，避免重复创建相同的对象。这是一种常见的享元模式应用。
* **单位转换:**  提供了一系列 `Compute...` 方法，用于将数值转换为不同的单位或进行单位间的转换。例如：
    * `ComputeSeconds()`: 将时间值转换为秒。
    * `ComputeDegrees()`: 将角度值转换为度。
    * `ComputeDotsPerPixel()`: 计算每像素的点数（用于分辨率）。
    * `ComputeInCanonicalUnit()`: 将值转换为其规范单位（例如，将 `px` 转换为标准长度单位）。
    * `ComputeLengthPx()`:  结合 `CSSLengthResolver` 将长度值计算为像素值，这涉及到视口大小、字体大小等因素。
* **数值提取:** 提供 `ComputeInteger()`, `ComputeNumber()`, `ComputePercentage()` 等方法来获取不同类型的数值表示。
* **参与长度计算:** 提供了 `AccumulateLengthArray` 和 `AccumulateLengthUnitTypes` 方法，用于在 CSS 布局计算中累积长度值和单位类型。
* **判断计算独立性:** `IsComputationallyIndependent()` 方法判断该数值是否独立于布局计算，这对于优化渲染过程非常重要。例如，绝对长度单位是独立的，而相对长度单位（如 `em`）则不是。
* **生成 CSS 文本:** `CustomCSSText()` 方法将 `CSSNumericLiteralValue` 对象转换回其对应的 CSS 文本表示形式。
* **比较和哈希:** 提供了 `Equals()` 方法用于比较两个 `CSSNumericLiteralValue` 对象是否相等，以及 `CustomHash()` 方法用于计算哈希值，方便在集合中使用。
* **获取规范单位:** `CanonicalUnit()` 和 `CreateCanonicalUnitValue()` 方法用于获取和创建具有规范单位的 `CSSNumericLiteralValue` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  `CSSNumericLiteralValue` 直接对应 CSS 中的数字值。
    * **例子:** 在 CSS 样式规则中，例如 `width: 100px;`, `font-size: 16px;`, `margin-left: 20%;`, `animation-duration: 1s;`，这些 `100px`, `16px`, `20%`, `1s` 等值都会被解析成 `CSSNumericLiteralValue` 对象。
    * **内部表示:** 当浏览器解析 CSS 样式时，遇到数字值时，会创建相应的 `CSSNumericLiteralValue` 对象来表示这些值。

* **JavaScript:** JavaScript 可以通过 CSSOM (CSS Object Model) 与 CSS 交互。
    * **例子:**  使用 JavaScript 获取元素的 CSS 样式：
      ```javascript
      const element = document.getElementById('myElement');
      const width = getComputedStyle(element).width; // width 可能是一个 "100px" 字符串
      ```
      当 JavaScript 获取到像 `width` 这样的属性值时，浏览器内部可能已经将其表示为 `CSSNumericLiteralValue` 对象。虽然 JavaScript 通常返回字符串形式的 CSS 值，但在引擎内部，`CSSNumericLiteralValue` 起着关键作用。
    * **设置样式:** 当 JavaScript 设置元素的 CSS 样式时：
      ```javascript
      element.style.width = '200px';
      ```
      浏览器解析这个赋值操作时，会创建一个新的 `CSSNumericLiteralValue` 对象来表示 `200px`。

* **HTML:** HTML 提供了结构，CSS 负责样式。`CSSNumericLiteralValue` 主要参与 CSS 的处理，间接地影响 HTML 元素的渲染。
    * **例子:** HTML 元素 `<div style="padding: 10px;"></div>` 中的 `padding: 10px;` 属性，其值 `10px` 会被解析为 `CSSNumericLiteralValue` 对象，最终决定了 `div` 元素的内边距大小。

**逻辑推理的假设输入与输出:**

假设输入一个 CSS 长度值字符串 "10em"，并且当前的字体大小是 16px。

* **输入:** 字符串 "10em"，当前字体大小 16px。
* **过程:**
    1. CSS 解析器遇到 "10em"。
    2. 创建一个 `CSSNumericLiteralValue` 对象，存储数值 10 和单位 `kEms`。
    3. 在布局计算阶段，需要将 "10em" 转换为像素值。
    4. 调用 `ComputeLengthPx` 方法，并传入 `CSSLengthResolver` 对象（其中包含了当前的字体大小信息）。
    5. `ComputeLengthPx` 内部计算 `10 * 16px = 160px`。
* **输出:**  逻辑上输出的是 160 像素值，但在 `CSSNumericLiteralValue` 的上下文中，输出的是经过计算后可能用于布局的像素值，或者可以创建一个新的 `CSSNumericLiteralValue` 对象表示 160px。

**用户或编程常见的错误:**

* **单位错误或缺失:**
    * **错误:**  `width: 100;` (缺少单位)
    * **说明:** CSS 属性通常需要单位，缺少单位可能导致样式失效或浏览器使用默认行为。这可能不会直接导致 `CSSNumericLiteralValue` 的错误，但在解析阶段会产生问题。
* **使用不兼容的单位:**
    * **错误:** `animation-duration: 100px;` (时间属性使用了长度单位)
    * **说明:**  不同的 CSS 属性接受不同类型的单位。使用了错误的单位会导致样式无效。
* **JavaScript 中设置错误的类型:**
    * **错误:** `element.style.width = 100;` (尝试将数字直接赋值给需要带单位的属性)
    * **说明:**  通过 JavaScript 设置样式时，通常需要提供带有单位的字符串。直接赋值数字可能不会被正确解析。
* **数值超出范围:**
    * **错误:**  `opacity: 2;` (opacity 值应该在 0 到 1 之间)
    * **说明:**  某些 CSS 属性对数值有特定的范围限制。超出范围的值可能会被截断或导致意外行为。虽然 `CSSNumericLiteralValue` 可以存储超出范围的数值，但在应用样式时可能会受到限制。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在 HTML 文件中编写 CSS 样式:** 例如，在 `<style>` 标签或外部 CSS 文件中编写 `width: 200px;`。
2. **浏览器加载 HTML 文件并解析 CSS:**  当浏览器解析到这条 CSS 规则时，CSS 解析器会识别出 `width` 属性和值 `200px`。
3. **创建 CSSOM 树:**  解析器会将 CSS 规则转换为 CSSOM (CSS Object Model) 树，其中 `width` 属性的值会被表示为一个 `CSSNumericLiteralValue` 对象，存储数值 `200` 和单位 `kPixels`。
4. **布局计算:** 当浏览器进行布局计算时，需要确定元素的最终尺寸。此时，会使用到 `CSSNumericLiteralValue` 对象中的数值和单位信息。`ComputeLengthPx` 等方法会被调用，结合视口大小、字体大小等信息，将 `200px` 转换为实际的像素值。
5. **渲染:**  最终，渲染引擎会根据布局计算的结果绘制页面。

**调试线索:**

如果开发者在调试 CSS 样式问题时遇到了与数值相关的问题，可以关注以下几点：

* **检查 CSS 样式规则:**  确认 CSS 规则中数值和单位是否正确。
* **使用开发者工具查看计算后的样式:** 浏览器开发者工具的 "Elements" 面板可以查看元素的 "Computed" 样式，这显示了经过浏览器计算后的最终样式值。虽然这里显示的是最终的像素值或其他计算后的值，但理解这些值来源于 `CSSNumericLiteralValue` 的处理过程是有帮助的。
* **断点调试 Blink 渲染引擎源码:**  对于更深入的调试，开发者可以在 Blink 引擎的源代码中设置断点，例如在 `CSSNumericLiteralValue::Create` 或 `CSSNumericLiteralValue::ComputeLengthPx` 等方法中，来查看 `CSSNumericLiteralValue` 对象的创建和计算过程，从而理解数值是如何被解析、存储和使用的。
* **检查 JavaScript 代码中对样式的操作:** 如果样式是通过 JavaScript 动态设置的，需要检查 JavaScript 代码中对数值和单位的处理是否正确。

总而言之，`CSSNumericLiteralValue.cc` 中实现的 `CSSNumericLiteralValue` 类是 Blink 渲染引擎中表示和处理 CSS 数字值的核心组件，它连接了 CSS 解析、样式计算和最终的页面渲染过程。理解它的功能对于理解浏览器如何处理 CSS 样式至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/css_numeric_literal_value.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/core/css/css_length_resolver.h"
#include "third_party/blink/renderer/core/css/css_value_pool.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

struct SameSizeAsCSSNumericLiteralValue : CSSPrimitiveValue {
  double num;
};
ASSERT_SIZE(CSSNumericLiteralValue, SameSizeAsCSSNumericLiteralValue);

void CSSNumericLiteralValue::TraceAfterDispatch(blink::Visitor* visitor) const {
  CSSPrimitiveValue::TraceAfterDispatch(visitor);
}

CSSNumericLiteralValue::CSSNumericLiteralValue(double num, UnitType type)
    : CSSPrimitiveValue(kNumericLiteralClass), num_(num) {
  DCHECK_NE(UnitType::kUnknown, type);
  numeric_literal_unit_type_ = static_cast<unsigned>(type);
}

// static
CSSNumericLiteralValue* CSSNumericLiteralValue::Create(double value,
                                                       UnitType type) {
  // NOTE: This will also deal with NaN and infinities.
  // Writing value < 0 || value > ... is not equivalent.
  if (!(value >= 0 && value <= CSSValuePool::kMaximumCacheableIntegerValue)) {
    return MakeGarbageCollected<CSSNumericLiteralValue>(value, type);
  }

  // At this point, we know that value is in a small range,
  // so we can use a simple cast instead of ClampTo<int>.
  int int_value = static_cast<int>(value);
  // To handle negative zero, detect signed zero
  // https://en.wikipedia.org/wiki/Signed_zero
  if (value != int_value || (value == 0 && std::signbit(value))) {
    return MakeGarbageCollected<CSSNumericLiteralValue>(value, type);
  }

  CSSValuePool& pool = CssValuePool();
  CSSNumericLiteralValue* result = nullptr;
  switch (type) {
    case CSSPrimitiveValue::UnitType::kPixels:
      result = pool.PixelCacheValue(int_value);
      if (!result) {
        result = pool.SetPixelCacheValue(
            int_value,
            MakeGarbageCollected<CSSNumericLiteralValue>(value, type));
      }
      return result;
    case CSSPrimitiveValue::UnitType::kPercentage:
      result = pool.PercentCacheValue(int_value);
      if (!result) {
        result = pool.SetPercentCacheValue(
            int_value,
            MakeGarbageCollected<CSSNumericLiteralValue>(value, type));
      }
      return result;
    case CSSPrimitiveValue::UnitType::kNumber:
    case CSSPrimitiveValue::UnitType::kInteger:
      result = pool.NumberCacheValue(int_value);
      if (!result) {
        result = pool.SetNumberCacheValue(
            int_value, MakeGarbageCollected<CSSNumericLiteralValue>(
                           value, CSSPrimitiveValue::UnitType::kInteger));
      }
      return result;
    default:
      return MakeGarbageCollected<CSSNumericLiteralValue>(value, type);
  }
}

double CSSNumericLiteralValue::ComputeSeconds() const {
  DCHECK(IsTime());
  UnitType current_type = GetType();
  if (current_type == UnitType::kSeconds) {
    return num_;
  }
  if (current_type == UnitType::kMilliseconds) {
    return num_ / 1000;
  }
  NOTREACHED();
}

double CSSNumericLiteralValue::ComputeDegrees() const {
  DCHECK(IsAngle());
  UnitType current_type = GetType();
  switch (current_type) {
    case UnitType::kDegrees:
      return num_;
    case UnitType::kRadians:
      return Rad2deg(num_);
    case UnitType::kGradians:
      return Grad2deg(num_);
    case UnitType::kTurns:
      return Turn2deg(num_);
    default:
      NOTREACHED();
  }
}

double CSSNumericLiteralValue::ComputeDotsPerPixel() const {
  DCHECK(IsResolution());
  return DoubleValue() * ConversionToCanonicalUnitsScaleFactor(GetType());
}

double CSSNumericLiteralValue::ComputeInCanonicalUnit() const {
  return DoubleValue() *
         CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(GetType());
}

double CSSNumericLiteralValue::ComputeInCanonicalUnit(
    const CSSLengthResolver& length_resolver) const {
  if (IsLength()) {
    return ComputeLengthPx(length_resolver);
  }
  return DoubleValue() *
         CSSPrimitiveValue::ConversionToCanonicalUnitsScaleFactor(GetType());
}

double CSSNumericLiteralValue::ComputeLengthPx(
    const CSSLengthResolver& length_resolver) const {
  DCHECK(IsLength());
  return length_resolver.ZoomedComputedPixels(num_, GetType());
}

int CSSNumericLiteralValue::ComputeInteger() const {
  DCHECK(IsNumber());
  return ClampTo<int>(num_);
}

double CSSNumericLiteralValue::ComputeNumber() const {
  DCHECK(IsNumber());
  return ClampTo<double>(num_);
}

double CSSNumericLiteralValue::ComputePercentage() const {
  DCHECK(IsPercentage());
  return ClampTo<double>(num_);
}

bool CSSNumericLiteralValue::AccumulateLengthArray(CSSLengthArray& length_array,
                                                   double multiplier) const {
  LengthUnitType length_type;
  bool conversion_success = UnitTypeToLengthUnitType(GetType(), length_type);
  DCHECK(conversion_success);
  if (length_type >= CSSLengthArray::kSize) {
    return false;
  }
  length_array.values[length_type] +=
      num_ * ConversionToCanonicalUnitsScaleFactor(GetType()) * multiplier;
  length_array.type_flags.set(length_type);
  return true;
}

void CSSNumericLiteralValue::AccumulateLengthUnitTypes(
    LengthTypeFlags& types) const {
  if (!IsLength()) {
    return;
  }
  LengthUnitType length_type;
  bool conversion_success = UnitTypeToLengthUnitType(GetType(), length_type);
  DCHECK(conversion_success);
  types.set(length_type);
}

bool CSSNumericLiteralValue::IsComputationallyIndependent() const {
  if (!IsLength()) {
    return true;
  }
  if (IsViewportPercentageLength()) {
    return true;
  }
  return !IsRelativeUnit(GetType());
}

static String FormatNumber(double number, const char* suffix) {
#if BUILDFLAG(IS_WIN) && _MSC_VER < 1900
  unsigned oldFormat = _set_output_format(_TWO_DIGIT_EXPONENT);
#endif
  String result = String::Format("%.6g%s", number, suffix);
#if BUILDFLAG(IS_WIN) && _MSC_VER < 1900
  _set_output_format(oldFormat);
#endif
  return result;
}

static String FormatInfinityOrNaN(double number, const char* suffix) {
  String result;
  if (std::isinf(number)) {
    if (number > 0) {
      result = "infinity";
    } else {
      result = "-infinity";
    }

  } else {
    DCHECK(std::isnan(number));
    result = "NaN";
  }

  if (strlen(suffix) > 0) {
    result = result + String::Format(" * 1%s", suffix);
  }
  return result;
}

String CSSNumericLiteralValue::CustomCSSText() const {
  String text;
  switch (GetType()) {
    case UnitType::kUnknown:
      // FIXME
      break;
    case UnitType::kInteger:
      text = String::Number(ComputeInteger());
      break;
    case UnitType::kNumber:
    case UnitType::kPercentage:
    case UnitType::kEms:
    case UnitType::kQuirkyEms:
    case UnitType::kExs:
    case UnitType::kRexs:
    case UnitType::kRems:
    case UnitType::kRchs:
    case UnitType::kRics:
    case UnitType::kChs:
    case UnitType::kIcs:
    case UnitType::kCaps:
    case UnitType::kRcaps:
    case UnitType::kLhs:
    case UnitType::kRlhs:
    case UnitType::kPixels:
    case UnitType::kCentimeters:
    case UnitType::kDotsPerPixel:
    case UnitType::kX:
    case UnitType::kDotsPerInch:
    case UnitType::kDotsPerCentimeter:
    case UnitType::kMillimeters:
    case UnitType::kQuarterMillimeters:
    case UnitType::kInches:
    case UnitType::kPoints:
    case UnitType::kPicas:
    case UnitType::kUserUnits:
    case UnitType::kDegrees:
    case UnitType::kRadians:
    case UnitType::kGradians:
    case UnitType::kMilliseconds:
    case UnitType::kSeconds:
    case UnitType::kHertz:
    case UnitType::kKilohertz:
    case UnitType::kTurns:
    case UnitType::kFlex:
    case UnitType::kViewportWidth:
    case UnitType::kViewportHeight:
    case UnitType::kViewportInlineSize:
    case UnitType::kViewportBlockSize:
    case UnitType::kViewportMin:
    case UnitType::kViewportMax:
    case UnitType::kSmallViewportWidth:
    case UnitType::kSmallViewportHeight:
    case UnitType::kSmallViewportInlineSize:
    case UnitType::kSmallViewportBlockSize:
    case UnitType::kSmallViewportMin:
    case UnitType::kSmallViewportMax:
    case UnitType::kLargeViewportWidth:
    case UnitType::kLargeViewportHeight:
    case UnitType::kLargeViewportInlineSize:
    case UnitType::kLargeViewportBlockSize:
    case UnitType::kLargeViewportMin:
    case UnitType::kLargeViewportMax:
    case UnitType::kDynamicViewportWidth:
    case UnitType::kDynamicViewportHeight:
    case UnitType::kDynamicViewportInlineSize:
    case UnitType::kDynamicViewportBlockSize:
    case UnitType::kDynamicViewportMin:
    case UnitType::kDynamicViewportMax:
    case UnitType::kContainerWidth:
    case UnitType::kContainerHeight:
    case UnitType::kContainerInlineSize:
    case UnitType::kContainerBlockSize:
    case UnitType::kContainerMin:
    case UnitType::kContainerMax: {
      // The following integers are minimal and maximum integers which can
      // be represented in non-exponential format with 6 digit precision.
      constexpr int kMinInteger = -999999;
      constexpr int kMaxInteger = 999999;
      double value = DoubleValue();
      // If the value is small integer, go the fast path.
      if (value < kMinInteger || value > kMaxInteger ||
          std::trunc(value) != value) {
        if (!std::isfinite(value)) {
          text = FormatInfinityOrNaN(value, UnitTypeToString(GetType()));
        } else {
          text = FormatNumber(value, UnitTypeToString(GetType()));
        }
      } else {
        StringBuilder builder;
        int int_value = value;
        const char* unit_type = UnitTypeToString(GetType());
        builder.AppendNumber(int_value);
        builder.Append(StringView(unit_type));
        text = builder.ReleaseString();
      }
    } break;
    default:
      NOTREACHED();
  }
  return text;
}

bool CSSNumericLiteralValue::Equals(const CSSNumericLiteralValue& other) const {
  if (GetType() != other.GetType()) {
    return false;
  }

  switch (GetType()) {
    case UnitType::kUnknown:
      return false;
    case UnitType::kNumber:
    case UnitType::kInteger:
    case UnitType::kPercentage:
    case UnitType::kEms:
    case UnitType::kExs:
    case UnitType::kRems:
    case UnitType::kRexs:
    case UnitType::kRchs:
    case UnitType::kRics:
    case UnitType::kPixels:
    case UnitType::kCentimeters:
    case UnitType::kDotsPerPixel:
    case UnitType::kX:
    case UnitType::kDotsPerInch:
    case UnitType::kDotsPerCentimeter:
    case UnitType::kMillimeters:
    case UnitType::kQuarterMillimeters:
    case UnitType::kInches:
    case UnitType::kPoints:
    case UnitType::kPicas:
    case UnitType::kUserUnits:
    case UnitType::kDegrees:
    case UnitType::kRadians:
    case UnitType::kGradians:
    case UnitType::kMilliseconds:
    case UnitType::kSeconds:
    case UnitType::kHertz:
    case UnitType::kKilohertz:
    case UnitType::kTurns:
    case UnitType::kViewportWidth:
    case UnitType::kViewportHeight:
    case UnitType::kViewportMin:
    case UnitType::kViewportMax:
    case UnitType::kFlex:
      return num_ == other.num_;
    case UnitType::kQuirkyEms:
      return false;
    default:
      return false;
  }
}

unsigned CSSNumericLiteralValue::CustomHash() const {
  uint64_t val = base::bit_cast<uint64_t>(num_);
  return WTF::HashInts(static_cast<unsigned>(GetType()),
                       WTF::HashInts(val >> 32, val));
}

CSSPrimitiveValue::UnitType CSSNumericLiteralValue::CanonicalUnit() const {
  return CanonicalUnitTypeForCategory(UnitTypeToUnitCategory(GetType()));
}

CSSNumericLiteralValue* CSSNumericLiteralValue::CreateCanonicalUnitValue()
    const {
  return Create(ComputeInCanonicalUnit(), CanonicalUnit());
}

}  // namespace blink
```