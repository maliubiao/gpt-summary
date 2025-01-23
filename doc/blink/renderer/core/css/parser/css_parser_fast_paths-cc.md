Response:
The user wants a summary of the functionality of the `css_parser_fast_paths.cc` file, focusing on its relationship with CSS, HTML, and JavaScript. I need to identify the core purpose of this file by analyzing its included headers and the code within the provided snippet.

**Core Purpose:**  The file seems to contain "fast paths" for parsing CSS values. This means it likely implements optimized routines for parsing common CSS constructs, aiming for performance.

**Relationships with other technologies:**

*   **CSS:** The file directly deals with parsing CSS properties and values (e.g., lengths, colors, angles). I can find examples of how it handles different CSS units (px, %, deg, rad) and keywords (like `rgb`, `hsl`).
*   **HTML:** While not directly parsing HTML tags, the CSS being parsed is ultimately applied to HTML elements. The file might have some interaction with HTML parsing in terms of recognizing context (e.g., SVG attributes).
*   **JavaScript:** JavaScript can manipulate CSS styles. While this file doesn't directly execute JavaScript, its parsing of CSS ensures that styles set by JavaScript are correctly interpreted by the rendering engine.

**Logical Reasoning and Examples:** I can deduce the file's behavior by looking at functions like `ParseSimpleLength`, `ParseSimpleAngle`, and `FastParseColorInternal`. I can create hypothetical inputs for these functions and their expected outputs.

**User/Programming Errors:**  Common errors might involve providing invalid CSS syntax. I can illustrate how this file might handle such errors (e.g., returning null or a default value).

**Debugging Information:** I can speculate on how a user's action in a browser might lead to this code being executed. This usually involves applying or updating CSS styles on a web page.

**Structure of the Response:** Given that this is part 1 of 3, I should focus on summarizing the *overall* function without going into excessive detail about specific parsing logic. The subsequent parts might delve deeper into particular areas.

**Plan:**

1. State the primary function of the file.
2. Explain its connection to CSS, providing examples of CSS syntax it likely handles.
3. Explain its indirect connection to HTML and how it relates to styling HTML elements.
4. Explain its indirect connection to JavaScript and how it ensures correct interpretation of JavaScript-modified styles.
5. Provide a basic example of logical reasoning with a function like `ParseSimpleLength`.
6. Give an example of a common user error that this parser might encounter.
7. Describe a simple user action that could trigger this code.
8. Conclude with a summary of its overall role.
这是 `blink/renderer/core/css/parser/css_parser_fast_paths.cc` 文件的第一部分，其主要功能是**为 CSS 语法的解析提供优化的快速路径**。

这意味着该文件包含了用于快速解析常见和简单的 CSS 结构的代码，旨在提高 CSS 解析的性能。  当 CSS 语法符合某些预定义的模式时，解析器会尝试使用这些快速路径，避免执行更通用但可能更慢的解析逻辑。

**它与 javascript, html, css 的功能有关系：**

*   **CSS:** 这是最直接的关系。该文件处理 CSS 属性和值的解析。例如，它包含用于快速解析长度值（如 `10px`, `50%`）、颜色值（如 `#FFF`, `rgb(255, 0, 0)`）和角度值（如 `45deg`, `0.5turn`）的代码。
    *   **举例：**
        *   当解析器遇到 CSS 属性 `width: 100px;` 时，`ParseSimpleLengthValue` 函数会被调用来快速解析 `100px` 这个长度值。
        *   当解析器遇到 CSS 属性 `color: red;` 或者 `color: #FF0000;` 时，文件中可能包含快速路径来识别和处理这些常见的颜色表示。
*   **HTML:**  CSS 的解析结果最终会应用于 HTML 元素，以确定它们的样式。 虽然这个文件不直接处理 HTML 标签，但它负责解析用于定义这些元素样式的 CSS 代码。
    *   **举例：** 当浏览器解析包含 `<div style="width: 200px;"></div>` 的 HTML 时，CSS 解析器会调用 `css_parser_fast_paths.cc` 中的代码来解析 `width: 200px;` 这个内联样式。
*   **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式。 当 JavaScript 代码改变元素的样式时，例如 `element.style.width = '300px';`，浏览器需要重新解析新的 CSS 值。 `css_parser_fast_paths.cc` 中提供的快速路径同样可以加速对这些动态修改的 CSS 值的解析。
    *   **举例：**  如果 JavaScript 代码设置了 `element.style.backgroundColor = 'blue';`，CSS 解析器可能会使用该文件中的快速路径来解析 `'blue'` 这个颜色值。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们调用 `ParseSimpleLengthValue` 函数来解析 CSS 属性 `width` 的值。

*   **假设输入：**
    *   `property_id`: `CSSPropertyID::kWidth`
    *   `string`:  "150px"
    *   `css_parser_mode`: (可以是默认模式)
*   **逻辑推理：**
    1. `IsSimpleLengthPropertyID` 函数会检查 `kWidth` 是否是允许使用简单长度值的属性，结果为 `true`。
    2. `ParseSimpleLength` 函数会被调用，尝试解析 "150px"。
    3. 它会识别出 "px" 单位，并将数字部分 "150" 解析为 double 类型。
    4. 单位被设置为 `CSSPrimitiveValue::UnitType::kPixels`。
*   **预期输出：**  一个 `CSSNumericLiteralValue` 对象，表示 `150px`，其中 `value` 为 150，`unit` 为 `CSSPrimitiveValue::UnitType::kPixels`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

*   **用户错误 (CSS 编写错误):** 用户在编写 CSS 时可能会输入无效的值。
    *   **举例：**  用户可能会写 `width: abc;`。  `ParseSimpleLengthValue` 会尝试解析 "abc" 但无法识别为有效的数字，最终返回 `nullptr`。
    *   **举例：**  用户可能会写 `width: -10px;`，而 `width` 属性不允许负值。尽管可以解析出 `-10`，但后续的检查（`number < 0 && !accepts_negative_numbers`) 会导致返回 `nullptr`。
*   **编程错误 (Blink 引擎内部):** 虽然 `css_parser_fast_paths.cc` 旨在处理常见情况，但如果引擎内部逻辑错误地将不应使用快速路径解析的值传递给这些函数，也可能导致错误。例如，将包含复杂函数的值（如 `calc(100% - 20px)`）尝试用 `ParseSimpleLengthValue` 解析。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入网址并访问一个网页，或者点击了一个链接。**
2. **浏览器开始下载 HTML、CSS 和 JavaScript 等资源。**
3. **HTML 解析器解析 HTML 文档，构建 DOM 树。**
4. **当 HTML 解析器遇到 `<link>` 标签引入的外部 CSS 文件或 `<style>` 标签内的 CSS 代码，或者解析 HTML 元素的 `style` 属性时，CSS 解析器开始工作。**
5. **CSS 解析器读取 CSS 代码，并尝试将其分解为 tokens。**
6. **对于每个 CSS 属性和值，解析器会尝试使用快速路径进行解析。例如，当遇到 `width: 100px;` 时，会调用 `css_parser_fast_paths.cc` 中的 `ParseSimpleLengthValue` 函数。**
7. **如果快速路径无法解析，解析器会回退到更通用的解析逻辑。**

**作为调试线索：** 如果在调试 CSS 样式问题时，怀疑是解析器的问题，可以在 Blink 引擎的 CSS 解析代码中设置断点，例如在 `css_parser_fast_paths.cc` 中的相关函数入口处，观察传入的 CSS 字符串和属性 ID，以判断是否使用了快速路径，以及快速路径的解析结果是否正确。

**归纳一下它的功能：**

总而言之，`blink/renderer/core/css/parser/css_parser_fast_paths.cc` 文件的主要功能是**提供一组优化的函数，用于快速解析常见的简单 CSS 属性值，例如长度、颜色和角度等。** 它的目的是提高 Blink 引擎在解析 CSS 时的性能，从而提升网页加载和渲染速度。它与 CSS 直接相关，并间接地影响着 HTML 元素的样式呈现，也为 JavaScript 动态修改样式提供了高效的解析支持。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_fast_paths.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/parser/css_parser_fast_paths.h"

#ifdef __SSE2__
#include <immintrin.h>
#elif defined(__ARM_NEON__)
#include <arm_neon.h>
#endif

#include "build/build_config.h"
#include "third_party/blink/public/public_buildflags.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_function_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_inherited_value.h"
#include "third_party/blink/renderer/core/css/css_initial_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_revert_layer_value.h"
#include "third_party/blink/renderer/core/css/css_revert_value.h"
#include "third_party/blink/renderer/core/css/css_unset_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_clamping_utils.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_idioms.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_bitset.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"

namespace blink {

static unsigned ParsePositiveDouble(const LChar* string,
                                    const LChar* end,
                                    double& value);

static bool ParseDoubleWithPrefix(const LChar* string,
                                  const LChar* end,
                                  double& value);

static inline bool IsSimpleLengthPropertyID(CSSPropertyID property_id,
                                            bool& accepts_negative_numbers) {
  static CSSBitset properties{{
      CSSPropertyID::kBlockSize,
      CSSPropertyID::kInlineSize,
      CSSPropertyID::kMinBlockSize,
      CSSPropertyID::kMinInlineSize,
      CSSPropertyID::kFontSize,
      CSSPropertyID::kHeight,
      CSSPropertyID::kWidth,
      CSSPropertyID::kMinHeight,
      CSSPropertyID::kMinWidth,
      CSSPropertyID::kPaddingBottom,
      CSSPropertyID::kPaddingLeft,
      CSSPropertyID::kPaddingRight,
      CSSPropertyID::kPaddingTop,
      CSSPropertyID::kScrollPaddingBlockEnd,
      CSSPropertyID::kScrollPaddingBlockStart,
      CSSPropertyID::kScrollPaddingBottom,
      CSSPropertyID::kScrollPaddingInlineEnd,
      CSSPropertyID::kScrollPaddingInlineStart,
      CSSPropertyID::kScrollPaddingLeft,
      CSSPropertyID::kScrollPaddingRight,
      CSSPropertyID::kScrollPaddingTop,
      CSSPropertyID::kPaddingBlockEnd,
      CSSPropertyID::kPaddingBlockStart,
      CSSPropertyID::kPaddingInlineEnd,
      CSSPropertyID::kPaddingInlineStart,
      CSSPropertyID::kShapeMargin,
      CSSPropertyID::kR,
      CSSPropertyID::kRx,
      CSSPropertyID::kRy,
      CSSPropertyID::kBottom,
      CSSPropertyID::kCx,
      CSSPropertyID::kCy,
      CSSPropertyID::kLeft,
      CSSPropertyID::kMarginBottom,
      CSSPropertyID::kMarginLeft,
      CSSPropertyID::kMarginRight,
      CSSPropertyID::kMarginTop,
      CSSPropertyID::kOffsetDistance,
      CSSPropertyID::kRight,
      CSSPropertyID::kTop,
      CSSPropertyID::kMarginBlockEnd,
      CSSPropertyID::kMarginBlockStart,
      CSSPropertyID::kMarginInlineEnd,
      CSSPropertyID::kMarginInlineStart,
      CSSPropertyID::kX,
      CSSPropertyID::kY,
  }};
  // A subset of the above.
  static CSSBitset accept_negative{
      {CSSPropertyID::kBottom, CSSPropertyID::kCx, CSSPropertyID::kCy,
       CSSPropertyID::kLeft, CSSPropertyID::kMarginBottom,
       CSSPropertyID::kMarginLeft, CSSPropertyID::kMarginRight,
       CSSPropertyID::kMarginTop, CSSPropertyID::kOffsetDistance,
       CSSPropertyID::kRight, CSSPropertyID::kTop,
       CSSPropertyID::kMarginBlockEnd, CSSPropertyID::kMarginBlockStart,
       CSSPropertyID::kMarginInlineEnd, CSSPropertyID::kMarginInlineStart,
       CSSPropertyID::kX, CSSPropertyID::kY}};

  accepts_negative_numbers = accept_negative.Has(property_id);
  if (accepts_negative_numbers) {
    DCHECK(properties.Has(property_id));
  }
  return properties.Has(property_id);
}

ALWAYS_INLINE static bool ParseSimpleLength(const LChar* characters,
                                            unsigned length,
                                            CSSPrimitiveValue::UnitType& unit,
                                            double& number) {
  if (length > 2 && (characters[length - 2] | 0x20) == 'p' &&
      (characters[length - 1] | 0x20) == 'x') {
    length -= 2;
    unit = CSSPrimitiveValue::UnitType::kPixels;
  } else if (length > 1 && characters[length - 1] == '%') {
    length -= 1;
    unit = CSSPrimitiveValue::UnitType::kPercentage;
  }

  // We rely on ParseDoubleWithPrefix() for validation as well. The function
  // will return a length different from “length” if the entire passed-in
  // character range does not represent a double.
  if (!ParseDoubleWithPrefix(characters, characters + length, number)) {
    return false;
  }
  number = ClampTo<double>(number, -std::numeric_limits<float>::max(),
                           std::numeric_limits<float>::max());
  return true;
}

static CSSValue* ParseSimpleLengthValue(CSSPropertyID property_id,
                                        StringView string,
                                        CSSParserMode css_parser_mode) {
  DCHECK(!string.empty());
  bool accepts_negative_numbers = false;

  if (!IsSimpleLengthPropertyID(property_id, accepts_negative_numbers)) {
    return nullptr;
  }

  double number;
  CSSPrimitiveValue::UnitType unit = CSSPrimitiveValue::UnitType::kNumber;

  const bool parsed_simple_length =
      ParseSimpleLength(string.Characters8(), string.length(), unit, number);
  if (!parsed_simple_length) {
    return nullptr;
  }

  if (unit == CSSPrimitiveValue::UnitType::kNumber) {
    if (css_parser_mode == kSVGAttributeMode) {
      unit = CSSPrimitiveValue::UnitType::kUserUnits;
    } else if (!number) {
      unit = CSSPrimitiveValue::UnitType::kPixels;
    } else {
      return nullptr;
    }
  }

  if (number < 0 && !accepts_negative_numbers) {
    return nullptr;
  }

  return CSSNumericLiteralValue::Create(number, unit);
}

// Returns the length of the angle, or 0 if the parse failed.
ALWAYS_INLINE static unsigned ParseSimpleAngle(
    const LChar* characters,
    unsigned length,
    CSSPrimitiveValue::UnitType& unit,
    double& number) {
  int number_length;
  if (length > 0 && *characters == '-') {
    number_length =
        ParsePositiveDouble(characters + 1, characters + length, number);
    if (number_length == 0) {
      return number_length;
    }
    ++number_length;
    number = -std::min<double>(number, std::numeric_limits<float>::max());
  } else {
    number_length =
        ParsePositiveDouble(characters, characters + length, number);
    if (number_length == 0) {
      return number_length;
    }
    number = std::min<double>(number, std::numeric_limits<float>::max());
  }

  characters += number_length;
  length -= number_length;

  if (length >= 3 && (characters[0] | 0x20) == 'd' &&
      (characters[1] | 0x20) == 'e' && (characters[2] | 0x20) == 'g') {
    unit = CSSPrimitiveValue::UnitType::kDegrees;
    return number_length + 3;
  } else if (length >= 4 && (characters[0] | 0x20) == 'g' &&
             (characters[1] | 0x20) == 'r' && (characters[2] | 0x20) == 'a' &&
             (characters[3] | 0x20) == 'd') {
    unit = CSSPrimitiveValue::UnitType::kGradians;
    return number_length + 4;
  } else if (length >= 3 && (characters[0] | 0x20) == 'r' &&
             (characters[1] | 0x20) == 'a' && (characters[2] | 0x20) == 'd') {
    unit = CSSPrimitiveValue::UnitType::kRadians;
    return number_length + 3;
  } else if (length >= 4 && (characters[0] | 0x20) == 't' &&
             (characters[1] | 0x20) == 'u' && (characters[2] | 0x20) == 'r' &&
             (characters[3] | 0x20) == 'n') {
    unit = CSSPrimitiveValue::UnitType::kTurns;
    return number_length + 4;
  } else {
    // For rotate: Only valid for zero (we'll check that in the caller).
    // For hsl(): To be treated as angles (also done in the caller).
    unit = CSSPrimitiveValue::UnitType::kNumber;
    return number_length;
  }
}

static inline bool IsColorPropertyID(CSSPropertyID property_id) {
  static CSSBitset properties{{
      CSSPropertyID::kCaretColor,
      CSSPropertyID::kColor,
      CSSPropertyID::kBackgroundColor,
      CSSPropertyID::kBorderBottomColor,
      CSSPropertyID::kBorderLeftColor,
      CSSPropertyID::kBorderRightColor,
      CSSPropertyID::kBorderTopColor,
      CSSPropertyID::kFill,
      CSSPropertyID::kFloodColor,
      CSSPropertyID::kLightingColor,
      CSSPropertyID::kOutlineColor,
      CSSPropertyID::kStopColor,
      CSSPropertyID::kStroke,
      CSSPropertyID::kBorderBlockEndColor,
      CSSPropertyID::kBorderBlockStartColor,
      CSSPropertyID::kBorderInlineEndColor,
      CSSPropertyID::kBorderInlineStartColor,
      CSSPropertyID::kColumnRuleColor,
      CSSPropertyID::kTextEmphasisColor,
      CSSPropertyID::kWebkitTextFillColor,
      CSSPropertyID::kWebkitTextStrokeColor,
      CSSPropertyID::kTextDecorationColor,

      // -internal-visited for all of the above that have them.
      CSSPropertyID::kInternalVisitedCaretColor,
      CSSPropertyID::kInternalVisitedColor,
      CSSPropertyID::kInternalVisitedBackgroundColor,
      CSSPropertyID::kInternalVisitedBorderBottomColor,
      CSSPropertyID::kInternalVisitedBorderLeftColor,
      CSSPropertyID::kInternalVisitedBorderRightColor,
      CSSPropertyID::kInternalVisitedBorderTopColor,
      CSSPropertyID::kInternalVisitedFill,
      CSSPropertyID::kInternalVisitedOutlineColor,
      CSSPropertyID::kInternalVisitedStroke,
      CSSPropertyID::kInternalVisitedBorderBlockEndColor,
      CSSPropertyID::kInternalVisitedBorderBlockStartColor,
      CSSPropertyID::kInternalVisitedBorderInlineEndColor,
      CSSPropertyID::kInternalVisitedBorderInlineStartColor,
      CSSPropertyID::kInternalVisitedColumnRuleColor,
      CSSPropertyID::kInternalVisitedTextEmphasisColor,
      CSSPropertyID::kInternalVisitedTextDecorationColor,
  }};
  return properties.Has(property_id);
}

// https://quirks.spec.whatwg.org/#the-hashless-hex-color-quirk
static inline bool ColorPropertyAllowsQuirkyColor(CSSPropertyID property_id) {
  static CSSBitset properties{{
      CSSPropertyID::kColor,
      CSSPropertyID::kBackgroundColor,
      CSSPropertyID::kBorderBottomColor,
      CSSPropertyID::kBorderLeftColor,
      CSSPropertyID::kBorderRightColor,
      CSSPropertyID::kBorderTopColor,
  }};
  return properties.Has(property_id);
}

// Returns the number of initial characters which form a valid double.
static unsigned FindLengthOfValidDouble(const LChar* string, const LChar* end) {
  int length = static_cast<int>(end - string);
  if (length < 1) {
    return 0;
  }

  bool decimal_mark_seen = false;
  int valid_length = 0;
#if defined(__SSE2__) || defined(__ARM_NEON__)
  if (length >= 16) {
    uint8_t b __attribute__((vector_size(16)));
    memcpy(&b, string, sizeof(b));
    auto is_decimal_mask = (b >= '0' && b <= '9');
    auto is_mark_mask = (b == '.');
#ifdef __SSE2__
    uint16_t is_decimal_bits =
        _mm_movemask_epi8(reinterpret_cast<__m128i>(is_decimal_mask));
    uint16_t is_mark_bits =
        _mm_movemask_epi8(reinterpret_cast<__m128i>(is_mark_mask));

    // Only count the first decimal mark.
    is_mark_bits &= -is_mark_bits;

    if ((is_decimal_bits | is_mark_bits) == 0xffff) {
      decimal_mark_seen = (is_mark_bits != 0);
      valid_length = 16;
      // Do the rest of the parsing using the scalar loop below.
      // It's unlikely that numbers will be much more than 16 bytes,
      // so we don't bother with a loop (which would also need logic
      // for checking for two decimal marks in separate 16-byte chunks).
    } else {
      // Get rid of any stray final period; i.e., one that is not
      // followed by a decimal.
      is_mark_bits &= (is_decimal_bits >> 1);
      uint16_t accept_bits = is_decimal_bits | is_mark_bits;
      return __builtin_ctz(~accept_bits);
    }
#else  // __ARM_NEON__

    // https://community.arm.com/arm-community-blogs/b/infrastructure-solutions-blog/posts/porting-x86-vector-bitmask-optimizations-to-arm-neon
    uint64_t is_decimal_bits =
        vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(
                          vreinterpretq_u16_s8(is_decimal_mask), 4)),
                      0);
    uint64_t is_mark_bits = vget_lane_u64(
        vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_s8(is_mark_mask), 4)),
        0);

    // Only count the first decimal mark.
    is_mark_bits &= -is_mark_bits;
    is_mark_bits |= (is_mark_bits << 1);
    is_mark_bits |= (is_mark_bits << 2);

    if ((is_decimal_bits | is_mark_bits) == 0xffffffffffffffffULL) {
      decimal_mark_seen = (is_mark_bits != 0);
      valid_length = 16;
      // Do the rest of the parsing using the scalar loop below.
      // It's unlikely that numbers will be much more than 16 bytes,
      // so we don't bother with a loop (which would also need logic
      // for checking for two decimal marks in separate 16-byte chunks).
    } else {
      // Get rid of any stray final period; i.e., one that is not
      // followed by a decimal.
      is_mark_bits &= (is_decimal_bits >> 4);
      uint64_t accept_bits = is_decimal_bits | is_mark_bits;
      return __builtin_ctzll(~accept_bits) >> 2;
    }
#endif
  }
#endif  // defined(__SSE2__) || defined(__ARM_NEON__)

  for (; valid_length < length; ++valid_length) {
    if (!IsASCIIDigit(string[valid_length])) {
      if (!decimal_mark_seen && string[valid_length] == '.') {
        decimal_mark_seen = true;
      } else {
        break;
      }
    }
  }

  if (valid_length > 0 && string[valid_length - 1] == '.') {
    return 0;
  }

  return valid_length;
}

// If also_accept_whitespace is true: Checks whether string[pos] is the given
// character, _or_ an HTML space.
// Otherwise: Checks whether string[pos] is the given character.
// Returns false if pos is past the end of the string.
static bool ContainsCharAtPos(const LChar* string,
                              const LChar* end,
                              int pos,
                              char ch,
                              bool also_accept_whitespace) {
  DCHECK_GE(pos, 0);
  if (pos >= static_cast<int>(end - string)) {
    return false;
  }
  return string[pos] == ch ||
         (also_accept_whitespace && IsHTMLSpace(string[pos]));
}

// Like ParsePositiveDouble(), but also accepts initial whitespace and negative
// values. This is similar to CharactersToDouble(), but does not support
// trailing periods (e.g. “100.”), cf.
//
//   https://drafts.csswg.org/css-syntax/#consume-number
//   https://drafts.csswg.org/css-syntax/#number-token-diagram
//
// It also does not support exponential notation (e.g. “100e3”), which means
// that such cases go through the slow path.
static bool ParseDoubleWithPrefix(const LChar* string,
                                  const LChar* end,
                                  double& value) {
  while (string < end && IsHTMLSpace(*string)) {
    ++string;
  }
  if (string < end && *string == '-') {
    if (end - string == 1) {
      return false;
    }
    double v;
    if (ParsePositiveDouble(string + 1, end, v) !=
        static_cast<unsigned>(end - string - 1)) {
      return false;
    }
    value = -v;
    return true;
  } else if (string == end) {
    return false;
  } else {
    return ParsePositiveDouble(string, end, value) ==
           static_cast<unsigned>(end - string);
  }
}

// Returns the number of characters consumed for parsing a valid double,
// or 0 if the string did not start with a valid double.
//
// NOTE: Digits after the seventh decimal are ignored, potentially leading
// to accuracy issues. (All digits _before_ the decimal points are used.)
ALWAYS_INLINE static unsigned ParsePositiveDouble(const LChar* string,
                                                  const LChar* end,
                                                  double& value) {
  unsigned length = FindLengthOfValidDouble(string, end);
  if (length == 0) {
    return 0;
  }

  unsigned position = 0;
  double local_value = 0;

  // The consumed characters here are guaranteed to be
  // ASCII digits with or without a decimal mark
  for (; position < length; ++position) {
    if (string[position] == '.') {
      break;
    }
    local_value = local_value * 10 + (string[position] - '0');
  }

  if (++position >= length) {
    value = local_value;
    return length;
  }
  constexpr int kMaxDecimals = 7;
  int bytes_left = length - position;
  unsigned num_decimals = bytes_left > kMaxDecimals ? kMaxDecimals : bytes_left;

#ifdef __SSE2__
  // The closest double to 1e-7, rounded _up_ instead of to nearest.
  // We specifically don't want a value _smaller_ than 1e-7, because
  // we have specific midpoints (like 0.1) that we want specific values for
  // after rounding.
  static constexpr double kDiv1e7 = 0.000000100000000000000009;

  // If we have SSE2 and have a little bit of slop in our string,
  // we can parse all of our desired (up to) seven decimals
  // pretty much in one go. We subtract '0' from every digit,
  // widen to 16-bit, and then do multiplication with all the
  // digit weights in parallel. (This also blanks out characters
  // that are not digits.) Essentially what we want is
  //
  //   1000000 * d0 + 100000 * d1 + 10000 * d2 + ...
  //
  // Since we use PMADDWD (_mm_madd_epi16) for the multiplication,
  // we get pairwise addition of each of the products and automatic
  // widening to 32-bit for free, so that we do not get overflow
  // from the 16-bit values. Still, we need a little bit of care,
  // since we cannot store the largest weights directly; see below.
  if (end - (string + position) >= 7) {
    __m128i bytes = _mm_loadu_si64(string + position - 1);
    __m128i words = _mm_unpacklo_epi8(bytes, _mm_setzero_si128());
    words = _mm_sub_epi16(words, _mm_set1_epi16('0'));

    // NOTE: We cannot use _mm_setr_epi16(), as it is not constexpr.
    static constexpr __m128i kWeights[kMaxDecimals + 1] = {
        (__m128i)(__v8hi){0, 0, 0, 0, 0, 0, 0, 0},
        (__m128i)(__v8hi){0, 25000, 0, 0, 0, 0, 0, 0},
        (__m128i)(__v8hi){0, 25000, 2500, 0, 0, 0, 0, 0},
        (__m128i)(__v8hi){0, 25000, 2500, 250, 0, 0, 0, 0},
        (__m128i)(__v8hi){0, 25000, 2500, 250, 1000, 0, 0, 0},
        (__m128i)(__v8hi){0, 25000, 2500, 250, 1000, 100, 0, 0},
        (__m128i)(__v8hi){0, 25000, 2500, 250, 1000, 100, 10, 0},
        (__m128i)(__v8hi){0, 25000, 2500, 250, 1000, 100, 10, 1},
    };
    __m128i v = _mm_madd_epi16(words, kWeights[num_decimals]);

    // Now we have, ignoring scale factors:
    //
    //   {d0} {d1+d2} {d3+d4} {d5+d6}
    //
    // Do a standard SSE2 horizontal add of the neighboring pairs:
    v = _mm_add_epi32(v, _mm_shuffle_epi32(v, _MM_SHUFFLE(2, 3, 0, 1)));

    // Now we have:
    //
    //   {d0+d1+d2} {d0+d1+d2} {d3+d4+d5+d6} {d3+d4+d5+d6}
    //
    // We need to multiply the {d0+d1+d2} elements by 40 (we could not
    // fit 1000000 into a 16-bit int for kWeights[] above, and multiplication
    // with 40 can be done cheaply), before we do the final add,
    // conversion to float and scale.
    __v4si v_int = (__v4si)v;
    uint32_t fraction = v_int[0] * 40 + v_int[2];

    value = local_value + fraction * kDiv1e7;
    return length;
  }
#elif defined(__aarch64__) && defined(__ARM_NEON__)
  // See the SSE2 path.
  static constexpr double kDiv1e7 = 0.000000100000000000000009;

  // NEON is similar, but we don't have pairwise muladds, so we need to
  // structure with slightly more explicit widening, and an extra mul
  // by 10000. We can join the subtraction of '0' and the widening to
  // 16-bit into one operation, though, as NEON has widening subtraction.
  if (end - (string + position) >= 7) {
    uint8x8_t bytes = vld1_u8(string + position - 1);
    uint16x8_t words = vsubl_u8(bytes, vdup_n_u8('0'));
    static constexpr uint16x8_t kWeights[kMaxDecimals + 1] = {
        (uint16x8_t){0, 0, 0, 0, 0, 0, 0, 0},
        (uint16x8_t){0, 100, 0, 0, 0, 0, 0, 0},
        (uint16x8_t){0, 100, 10, 0, 0, 0, 0, 0},
        (uint16x8_t){0, 100, 10, 1, 0, 0, 0, 0},
        (uint16x8_t){0, 100, 10, 1, 1000, 0, 0, 0},
        (uint16x8_t){0, 100, 10, 1, 1000, 100, 0, 0},
        (uint16x8_t){0, 100, 10, 1, 1000, 100, 10, 0},
        (uint16x8_t){0, 100, 10, 1, 1000, 100, 10, 1},
    };
    uint32x4_t pairs = vpaddlq_u16(vmulq_u16(words, kWeights[num_decimals]));

    // Now we have:
    //
    //   {100*d0} {10*d1 + d2} {1000*d3 + 100*d4} + {10*d5 + d6}
    //
    // Multiply the first two lanes by 10000, and then sum all four
    // to get our final integer answer. (This final horizontal add
    // only exists on A64; thus the check for __aarch64__ and not
    // __ARM_NEON__.)
    static constexpr uint32x4_t kScaleFac{10000, 10000, 1, 1};
    uint32_t fraction = vaddvq_u32(vmulq_u32(pairs, kScaleFac));

    value = local_value + fraction * kDiv1e7;
    return length;
  }
#endif

  // OK, do it the slow, scalar way.
  double fraction = 0;
  double scale = 1;
  for (unsigned i = 0; i < num_decimals; ++i) {
    fraction = fraction * 10 + (string[position + i] - '0');
    scale *= 10;
  }

  value = local_value + fraction / scale;
  return length;
}

// Parse a float and clamp it upwards to max_value. Optimized for having
// no decimal part. Returns true if the parse was successful (though it
// may not consume the entire string; you'll need to check string != end
// yourself if that is the intention).
ALWAYS_INLINE static bool ParseFloatWithMaxValue(const LChar*& string,
                                                 const LChar* end,
                                                 int max_value,
                                                 double& value,
                                                 bool& negative) {
  value = 0.0;
  const LChar* current = string;
  while (current != end && IsHTMLSpace(*current)) {
    current++;
  }
  if (current != end && *current == '-') {
    negative = true;
    current++;
  } else {
    negative = false;
  }
  if (current == end || !IsASCIIDigit(*current)) {
    return false;
  }
  while (current != end && IsASCIIDigit(*current)) {
    double new_value = value * 10 + (*current++ - '0');
    if (new_value >= max_value) {
      // Clamp values at 255 or 100 (depending on the caller).
      value = max_value;
      while (current != end && IsASCIIDigit(*current)) {
        ++current;
      }
      break;
    }
    value = new_value;
  }

  if (current != end && *current == '.') {
    // We already parsed the integral part, try to parse
    // the fraction part.
    double fractional = 0;
    int num_characters_parsed = ParsePositiveDouble(current, end, fractional);
    if (num_characters_parsed == 0) {
      return false;
    }
    current += num_characters_parsed;
    value += fractional;
  }

  string = current;
  return true;
}

namespace {

enum TerminatorStatus {
  // List elements are delimited with whitespace,
  // e.g., rgb(10 20 30).
  kMustWhitespaceTerminate,

  // List elements are delimited with a given terminator,
  // and any whitespace before it should be skipped over,
  // e.g., rgb(10 , 20,30).
  kMustCharacterTerminate,

  // We are parsing the first element, so we could do either
  // variant -- and when it's an in/out argument, we set it
  // to one of the other values.
  kCouldWhitespaceTerminate,
};

}  // namespace

static bool SkipToTerminator(const LChar*& string,
                             const LChar* end,
                             const char terminator,
                             TerminatorStatus& terminator_status) {
  const LChar* current = string;

  while (current != end && IsHTMLSpace(*current)) {
    current++;
  }

  switch (terminator_status) {
    case kCouldWhitespaceTerminate:
      if (current != end && *current == terminator) {
        terminator_status = kMustCharacterTerminate;
        ++current;
        break;
      }
      terminator_status = kMustWhitespaceTerminate;
      [[fallthrough]];
    case kMustWhitespaceTerminate:
      // We must have skipped over at least one space before finding
      // something else (or the end).
      if (current == string) {
        return false;
      }
      break;
    case kMustCharacterTerminate:
      // We must have stopped at the given terminator character.
      if (current == end || *current != terminator) {
        return false;
      }
      ++current;  // Skip over the terminator.
      break;
  }

  string = current;
  return true;
}

static bool ParseColorNumberOrPercentage(const LChar*& string,
                                         const LChar* end,
                                         const char terminator,
                                         TerminatorStatus& terminator_status,
                                         CSSPrimitiveValue::UnitType& expect,
                                         int& value) {
  const LChar* current = string;
  double local_value;
  bool negative = false;
  if (!ParseFloatWithMaxValue(current, end, 255, local_value, negative)) {
    return false;
  }
  if (current == end) {
    return false;
  }

  if (expect == CSSPrimitiveValue::UnitType::kPercentage && *current != '%') {
    return false;
  }
  if (expect == CSSPrimitiveValue::UnitType::kNumber && *current == '%') {
    return false;
  }

  if (*current == '%') {
    expect = CSSPrimitiveValue::UnitType::kPercentage;
    local_value = local_value / 100.0 * 255.0;
    // Clamp values at 255 for percentages over 100%
    if (local_value > 255) {
      local_value = 255;
    }
    current++;
  } else {
    expect = CSSPrimitiveValue::UnitType::kNumber;
  }

  if (!SkipToTerminator(current, end, terminator, terminator_status)) {
    return false;
  }

  // Clamp negative values at zero.
  value = negative ? 0 : static_cast<int>(lround(local_value));
  string = current;
  return true;
}

// Parses a percentage (including the % sign), clamps it and converts it to
// 0.0..1.0.
ALWAYS_INLINE static bool ParsePercentage(const LChar*& string,
                                          const LChar* end,
                                          const char terminator,
                                          TerminatorStatus& terminator_status,
                                          double& value) {
  const LChar* current = string;
  bool negative = false;
  if (!ParseFloatWithMaxValue(current, end, 100, value, negative)) {
    return false;
  }

  if (current == end || *current != '%') {
    return false;
  }

  ++current;
  if (negative) {
    value = 0.0;
  } else {
    value = std::min(value * 0.01, 1.0);
  }

  if (!SkipToTerminator(current, end, terminator, terminator_status)) {
    return false;
  }

  string = current;
  return true;
}

static inline bool IsTenthAlpha(const LChar* string, const wtf_size_t length) {
  // "0.X"
  if (length == 3 && string[0] == '0' && string[1] == '.' &&
      IsASCIIDigit(string[2])) {
    return true;
  }

  // ".X"
  if (length == 2 && string[0] == '.' && IsASCIIDigit(string[1])) {
    return true;
  }

  return false;
}

ALWAYS_INLINE static bool ParseAlphaValue(const LChar*& string,
                                          const LChar* end,
                                          const char terminator,
                                          int& value) {
  while (string != end && IsHTMLSpace(*string)) {
    string++;
  }

  bool negative = false;

  if (string != end && *string == '-') {
    negative = true;
    string++;
  }

  value = 0;

  wtf_size_t length = static_cast<wtf_size_t>(end - string);
  if (length < 2) {
    return false;
  }

  if (string[length - 1] != terminator || !IsASCIIDigit(string[length - 2])) {
    return false;
  }

  if (string[0] != '0' && string[0] != '1' && string[0] != '.') {
    int double_length = FindLengthOfValidDouble(string, end);
    if (double_length > 0 &&
        ContainsCharAtPos(string, end, double_length, terminator,
                          /*also_accept_whitespace=*/false)) {
      value = negative ? 0 : 255;
      string = end;
      return true;
    }
    return false;
  }

  if (length == 2 && string[0] != '.') {
    value = !negative && string[0] == '1' ? 255 : 0;
    string = end;
    return true;
  }

  if (IsTenthAlpha(string, length - 1)) {
    // Fast conversions for 0.1 steps of alpha values between 0.0 and 0.9,
    // where 0.1 alpha is value 26 (25.5 rounded) and so on.
    static const int kTenthAlphaValues[] = {0,   26,  51,  77,  102,
                                            128, 153, 179, 204, 230};
    value = negative ? 0 : kTenthAlphaValues[string[length - 2] - '0'];
    string = end;
    return true;
  }

  double alpha = 0;
  int dbl_length = ParsePositiveDouble(string, end, alpha);
  if (dbl_length == 0 || !ContainsCharAtPos(string, end, dbl_length, terminator,
                                            /*also_accept_whitespace=*/false)) {
    return false;
  }
  value = negative ? 0 : static_cast<int>(lround(std::min(alpha, 1.0) * 255.0));
  string = end;
  return true;
}

// Fast for LChar, reasonable for UChar.
template <int N>
static inline bool MatchesLiteral(const LChar* a, const char (&b)[N]) {
  return memcmp(a, b, N - 1) == 0;
}

template <int N>
static inline bool MatchesLiteral(const UChar* a, const char (&b)[N]) {
  for (int i = 0; i < N - 1; ++i) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

// Right-hand side must already be lowercase.
static inline bool MatchesCaseInsensitiveLiteral4(const LChar* a,
                                                  const char (&b)[5]) {
  uint32_t av, bv;
  memcpy(&av, a, sizeof(av));
  memcpy(&bv, b, sizeof(bv));

  uint32_t mask = 0;
  if ((bv & 0xff) >= 'a' && (bv & 0xff) <= 'z') {
    mask |= 0x20;
  }
  if (((bv >> 8) & 0xff) >= 'a' && ((bv >> 8) & 0xff) <= 'z') {
    mask |= 0x2000;
  }
  if (((bv >> 16) & 0xff) >= 'a' && ((bv >> 16) & 0xff) <= 'z') {
    mask |= 0x200000;
  }
  if ((bv >> 24) >= 'a' && (bv >> 24) <= 'z') {
    mask |= 0x20000000;
  }

  return (av | mask) == bv;
}

static inline bool MatchesCaseInsensitiveLiteral2(const LChar* a,
                                                  const char (&b)[3]) {
  uint16_t av, bv;
  memcpy(&av, a, sizeof(av));
  memcpy(&bv, b, sizeof(bv));

  uint16_t mask = 0;
  if ((bv & 0xff) >= 'a' && (bv & 0xff) <= 'z') {
    mask |= 0x20;
  }
  if ((bv >> 8) >= 'a' && (bv >> 8) <= 'z') {
    mask |= 0x2000;
  }

  return (av | mask) == bv;
}

static inline bool MightBeRGBOrRGBA(const LChar* characters, unsigned length) {
  if (length < 5) {
    return false;
  }
  return MatchesLiteral(characters, "rgb") &&
         (characters[3] == '(' ||
          (characters[3] == 'a' && characters[4] == '('));
}

static inline bool MightBeHSLOrHSLA(const LChar* characters, unsigned length) {
  if (length < 5) {
    return false;
  }
  return MatchesLiteral(characters, "hsl") &&
         (characters[3] == '(' ||
          (characters[3] == 'a' && characters[4] == '('));
}

static bool FastParseColorInternal(Color& color,
                                   const LChar* characters,
                                   unsigned length,
                                   bool quirks_mode) {
  if (length >= 4 && characters[0] == '#') {
    return Color::ParseHexColor(base::span(characters + 1, length - 1), color);
  }

  if (quirks_mode && (length == 3 || length == 6)) {
    if (Color::ParseHexColor(base::span(characters, length), color)) {
      return true;
    }
  }

  // rgb() and rgba() have
```