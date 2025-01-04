Response:
The user wants a summary of the provided C++ code file `css_parsing_utils.cc` from the Chromium Blink engine. The summary should cover:

1. **Functionality:** What does this code do?
2. **Relationship to web technologies:** How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logic and input/output:** If there's logical processing, give examples of input and expected output.
4. **Common user/programming errors:** Identify potential mistakes.
5. **User journey for debugging:** How does a user action lead to this code being executed?
6. **Overall summary (for part 1):** A concise overview of the file's purpose.

**Plan:**

1. **Analyze the includes:** The included headers give a good overview of the data structures and functionalities the file interacts with (various CSS value types, parser components, etc.).
2. **Examine the namespace:** The code is in the `blink::css_parsing_utils` namespace, suggesting it contains utility functions for parsing CSS.
3. **Look at the defined functions:**  The initial functions (`IsLeftOrRightKeyword`, `IsAuto`, etc.) are basic checks on CSS identifier values. More complex functions like `ConsumeLinear`, `ConsumeSteps`, `ConsumeCubicBezier`, and the `ConsumeBasicShape*` functions suggest the core functionality is parsing specific CSS value types.
4. **Connect to web technologies:** Explain how these parsing functions are essential for interpreting CSS styles applied to HTML elements, potentially triggered by JavaScript modifications.
5. **Illustrate with examples:**  Provide CSS snippets and explain how the parsing functions would handle them.
6. **Identify potential errors:**  Think about incorrect CSS syntax that these functions would need to handle or report errors for.
7. **Outline the user journey:** Describe a scenario where a user interacts with a web page, causing CSS to be parsed.
8. **Summarize the findings:** Condense the information into a concise summary for part 1.
这是 `blink/renderer/core/css/properties/css_parsing_utils.cc` 文件的第一部分。从代码内容来看，这个文件主要包含了一系列用于解析 CSS 各种值类型的实用工具函数。它的功能是 **将 CSS 语法中的字符串（tokens）转换为 Blink 引擎内部表示的 CSS 值对象**。

以下是对其功能的详细解释和与 JavaScript、HTML、CSS 的关系：

**功能归纳:**

1. **CSS 值解析:** 提供了各种 `Consume...` 函数，用于解析不同类型的 CSS 值，例如：
    *   **基本类型:** 数字 (`ConsumeNumber`), 百分比 (`ConsumePercent`), 长度 (`ConsumeLength`), 角度 (`ConsumeAngle`) 等。
    *   **关键字:**  特定的 CSS 关键字，例如 `auto`, `left`, `right` 等。
    *   **函数:**  例如 `linear()`, `steps()`, `cubic-bezier()`, 各种形状函数 (`circle()`, `ellipse()`, `polygon()`, `inset()`, `rect()`, `xywh()`), 滤镜函数 (`drop-shadow`, `blur` 等)。
    *   **复杂类型:**  渐变 (`linear-gradient`, `radial-gradient` 等), 阴影 (`ParseSingleShadow`),  `light-dark()` 颜色方案等。
    *   **组合类型:** 例如边框图像重复方式 (`ConsumeBorderImageRepeatKeyword`)，图形的半径 (`ConsumeShapeRadius`)。

2. **辅助解析函数:** 提供了一些辅助函数来帮助解析，例如：
    *   `ConsumeCommaIncludingWhitespace`:  消耗逗号和周围的空白字符。
    *   `IsIdent`: 检查一个 CSS 值是否是特定的标识符。
    *   `ConsumeOverflowPositionKeyword`: 消耗溢出位置相关的关键字。

3. **错误处理和容错:** 虽然代码片段中没有明显的错误处理代码，但这些解析函数的设计目的是在遇到无效 CSS 语法时返回 `nullptr`，表示解析失败。Blink 引擎的其他部分会处理这些解析失败的情况。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **CSS:**  这个文件的核心功能是解析 CSS。当浏览器加载 HTML 页面并遇到 `<style>` 标签或外部 CSS 文件时，Blink 引擎的 CSS 解析器会调用这个文件中的函数来理解 CSS 规则中的各种属性值。
    *   **例子:** CSS 规则 `animation-timing-function: cubic-bezier(0.4, 0, 0.2, 1);`  中的 `cubic-bezier(0.4, 0, 0.2, 1)` 部分会由 `ConsumeCubicBezier` 函数解析，将其转换为 `CSSCubicBezierTimingFunctionValue` 对象。
    *   **例子:** CSS 规则 `background-image: linear-gradient(red, blue);` 中的 `linear-gradient(red, blue)` 部分会由相关的渐变解析函数（这里没有直接展示，但包含在引入的头文件中）进行解析。

*   **HTML:**  CSS 规则通过选择器与 HTML 元素关联。当浏览器解析 HTML 结构时，会根据 CSS 规则计算每个 HTML 元素的样式。`css_parsing_utils.cc` 中解析出的 CSS 值会用于渲染 HTML 元素。
    *   **例子:** 如果 HTML 中有 `<div style="width: 100px;"></div>`，那么 `ConsumeLength` 函数会被调用来解析 `100px`，并将其作为 `width` 属性的值。

*   **JavaScript:** JavaScript 可以动态地修改元素的样式。当使用 JavaScript 设置元素的 `style` 属性时，例如 `element.style.width = '200px';`，Blink 引擎的 CSS 解析器也会调用 `css_parsing_utils.cc` 中的函数来解析新的 CSS 值。
    *   **例子:**  如果 JavaScript 代码执行 `element.style.borderRadius = '5px 10px';`，那么相关的 `ConsumeLengthOrPercent` 函数会被调用两次来解析 `5px` 和 `10px`。

**逻辑推理的假设输入与输出:**

假设输入是一个 CSS 属性值字符串和一个 `CSSParserTokenStream` 对象。

*   **假设输入 (函数: `ConsumeNumber`):**
    *   `stream` 当前指向一个表示数字的 token，例如 "123"。
    *   `context` 是当前的解析上下文。
    *   `value_range` 可以是 `kAll`（允许任何数字）, `kNonNegative`（只允许非负数）等。
*   **预期输出:**
    *   如果 `stream` 指向有效的数字 token，则返回一个 `CSSNumericLiteralValue` 对象，其值为 123。
    *   如果 `stream` 指向的不是数字，则返回 `nullptr`。
    *   如果 `value_range` 是 `kNonNegative` 且 token 表示负数，则返回 `nullptr`。

*   **假设输入 (函数: `ConsumeCubicBezier`):**
    *   `stream` 当前指向 `cubic-bezier(`。
    *   紧随其后的是四个表示数字的 token，用逗号分隔，例如 "0.4, 0, 0.2, 1"。
    *   `context` 是当前的解析上下文。
*   **预期输出:**
    *   返回一个 `CSSCubicBezierTimingFunctionValue` 对象，其四个控制点的值分别为 0.4, 0, 0.2, 1。
    *   如果参数数量不对或参数不是有效的数字，则返回 `nullptr`。

**用户或编程常见的使用错误及举例:**

*   **CSS 语法错误:** 用户在编写 CSS 时可能会犯语法错误，导致解析失败。
    *   **例子:**  `animation-timing-function: cubic-bezier(0.4, 0, 0.2);` (缺少一个参数)。`ConsumeCubicBezier` 函数会返回 `nullptr`。
    *   **例子:**  `width: abc;` (不是有效的长度值)。相关的长度解析函数会返回 `nullptr`。

*   **JavaScript 设置无效的样式值:**  程序员可能在 JavaScript 中设置了无效的 CSS 属性值。
    *   **例子:** `element.style.width = 'invalid-value';`。相关的解析函数会返回 `nullptr`，浏览器通常会忽略这些无效的样式。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 文档。**
3. **当浏览器遇到 `<style>` 标签或 `<link>` 标签引用的 CSS 文件时，**CSS 解析器开始工作。
4. **CSS 解析器读取 CSS 规则和属性值。**
5. **对于每个 CSS 属性值，解析器需要将其从字符串转换为内部表示。** 这时，`css_parsing_utils.cc` 中的各种 `Consume...` 函数就会被调用。
    *   **例如，**如果 CSS 中有 `width: 100px;`，解析器会遇到 "100px" 这个 token。
    *   **解析器会调用相应的函数，例如 `ConsumeLength`，并传递 token 流和解析上下文。**
    *   `ConsumeLength` 函数会判断 token 是否是有效的长度值，并创建相应的 `CSSPrimitiveValue` 对象。

**作为第 1 部分的归纳总结:**

`blink/renderer/core/css/properties/css_parsing_utils.cc` 的第一部分定义了一系列基础的实用工具函数，专注于 **将 CSS 语法中的各种值类型（如数字、关键字、基本函数等）解析为 Blink 引擎内部使用的 CSS 值对象**。 这些函数是 CSS 解析过程中的核心组成部分，确保浏览器能够正确理解和应用网页的样式。它们直接关系到 CSS 的解析，间接地影响 HTML 元素的渲染和 JavaScript 对样式的动态修改。 该部分涵盖了基础的数值、关键字以及一些简单的函数解析，为后续更复杂 CSS 值的解析奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共9部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"

#include <cmath>
#include <memory>
#include <utility>

#include "third_party/blink/renderer/core/css/counter_style_map.h"
#include "third_party/blink/renderer/core/css/css_attr_value_tainting.h"
#include "third_party/blink/renderer/core/css/css_axis_value.h"
#include "third_party/blink/renderer/core/css/css_basic_shape_values.h"
#include "third_party/blink/renderer/core/css/css_border_image.h"
#include "third_party/blink/renderer/core/css/css_bracketed_value_list.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_color_mix_value.h"
#include "third_party/blink/renderer/core/css/css_content_distribution_value.h"
#include "third_party/blink/renderer/core/css/css_crossfade_value.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_font_feature_value.h"
#include "third_party/blink/renderer/core/css/css_font_style_range_value.h"
#include "third_party/blink/renderer/core/css/css_function_value.h"
#include "third_party/blink/renderer/core/css/css_gradient_value.h"
#include "third_party/blink/renderer/core/css/css_grid_auto_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_integer_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_template_areas_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_image_set_option_value.h"
#include "third_party/blink/renderer/core/css/css_image_set_type_value.h"
#include "third_party/blink/renderer/core/css/css_image_set_value.h"
#include "third_party/blink/renderer/core/css/css_image_value.h"
#include "third_party/blink/renderer/core/css/css_inherited_value.h"
#include "third_party/blink/renderer/core/css/css_initial_value.h"
#include "third_party/blink/renderer/core/css/css_light_dark_value_pair.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_paint_value.h"
#include "third_party/blink/renderer/core/css/css_palette_mix_value.h"
#include "third_party/blink/renderer/core/css/css_path_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value.h"
#include "third_party/blink/renderer/core/css/css_ratio_value.h"
#include "third_party/blink/renderer/core/css/css_ray_value.h"
#include "third_party/blink/renderer/core/css/css_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_revert_layer_value.h"
#include "third_party/blink/renderer/core/css/css_revert_value.h"
#include "third_party/blink/renderer/core/css/css_scoped_keyword_value.h"
#include "third_party/blink/renderer/core/css/css_scroll_value.h"
#include "third_party/blink/renderer/core/css/css_shadow_value.h"
#include "third_party/blink/renderer/core/css/css_string_value.h"
#include "third_party/blink/renderer/core/css/css_timing_function_value.h"
#include "third_party/blink/renderer/core/css/css_unset_value.h"
#include "third_party/blink/renderer/core/css/css_uri_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/css_variable_data.h"
#include "third_party/blink/renderer/core/css/css_view_value.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_fast_paths.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_idioms.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_mode.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_save_point.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_color_function_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/longhand.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/svg/svg_parsing_error.h"
#include "third_party/blink/renderer/core/svg/svg_path_byte_stream_builder.h"
#include "third_party/blink/renderer/core/svg/svg_path_utilities.h"
#include "third_party/blink/renderer/platform/animation/timing_function.h"
#include "third_party/blink/renderer/platform/fonts/font_selection_types.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/gfx/animation/keyframe/timing_function.h"
#include "ui/gfx/color_utils.h"

namespace blink {

using cssvalue::CSSBracketedValueList;
using cssvalue::CSSFontFeatureValue;

namespace css_parsing_utils {
namespace {

const char kTwoDashes[] = "--";

bool IsLeftOrRightKeyword(CSSValueID id) {
  return IdentMatches<CSSValueID::kLeft, CSSValueID::kRight>(id);
}

bool IsAuto(CSSValueID id) {
  return IdentMatches<CSSValueID::kAuto>(id);
}

bool IsNormalOrStretch(CSSValueID id) {
  return IdentMatches<CSSValueID::kNormal, CSSValueID::kStretch>(id);
}

bool IsContentDistributionKeyword(CSSValueID id) {
  return IdentMatches<CSSValueID::kSpaceBetween, CSSValueID::kSpaceAround,
                      CSSValueID::kSpaceEvenly, CSSValueID::kStretch>(id);
}

bool IsOverflowKeyword(CSSValueID id) {
  return IdentMatches<CSSValueID::kUnsafe, CSSValueID::kSafe>(id);
}

bool IsIdent(const CSSValue& value, CSSValueID id) {
  const auto* ident = DynamicTo<CSSIdentifierValue>(value);
  return ident && ident->GetValueID() == id;
}

CSSIdentifierValue* ConsumeOverflowPositionKeyword(
    CSSParserTokenStream& stream) {
  return IsOverflowKeyword(stream.Peek().Id()) ? ConsumeIdent(stream) : nullptr;
}

CSSValueID GetBaselineKeyword(CSSValue& value) {
  auto* value_pair = DynamicTo<CSSValuePair>(value);
  if (!value_pair) {
    DCHECK(To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kBaseline);
    return CSSValueID::kBaseline;
  }

  DCHECK(To<CSSIdentifierValue>(value_pair->First()).GetValueID() ==
         CSSValueID::kLast);
  DCHECK(To<CSSIdentifierValue>(value_pair->Second()).GetValueID() ==
         CSSValueID::kBaseline);
  return CSSValueID::kLastBaseline;
}

CSSValue* ConsumeFirstBaseline(CSSParserTokenStream& stream) {
  ConsumeIdent<CSSValueID::kFirst>(stream);
  return ConsumeIdent<CSSValueID::kBaseline>(stream);
}

CSSValue* ConsumeBaseline(CSSParserTokenStream& stream) {
  CSSIdentifierValue* preference =
      ConsumeIdent<CSSValueID::kFirst, CSSValueID::kLast>(stream);
  CSSIdentifierValue* baseline = ConsumeIdent<CSSValueID::kBaseline>(stream);
  if (!baseline) {
    return nullptr;
  }
  if (preference && preference->GetValueID() == CSSValueID::kLast) {
    return MakeGarbageCollected<CSSValuePair>(
        preference, baseline, CSSValuePair::kDropIdenticalValues);
  }
  return baseline;
}

std::optional<cssvalue::CSSLinearStop> ConsumeLinearStop(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  std::optional<double> number;
  std::optional<double> length_a;
  std::optional<double> length_b;
  while (!stream.AtEnd()) {
    if (stream.Peek().GetType() == kCommaToken) {
      break;
    }
    CSSPrimitiveValue* value =
        ConsumeNumber(stream, context, CSSPrimitiveValue::ValueRange::kAll);
    if (!number.has_value() && value && value->IsNumber()) {
      number = value->GetDoubleValue();
      continue;
    }
    value =
        ConsumePercent(stream, context, CSSPrimitiveValue::ValueRange::kAll);
    if (!length_a.has_value() && value && value->IsPercentage()) {
      length_a = value->GetDoubleValue();
      value =
          ConsumePercent(stream, context, CSSPrimitiveValue::ValueRange::kAll);
      if (value && value->IsPercentage()) {
        length_b = value->GetDoubleValue();
      }
      continue;
    }
    return {};
  }
  if (!number.has_value()) {
    return {};
  }
  return {{number.value(), length_a, length_b}};
}

CSSValue* ConsumeLinear(CSSParserTokenStream& stream,
                        const CSSParserContext& context) {
  CSSValue* result;

  // https://w3c.github.io/csswg-drafts/css-easing/#linear-easing-function-parsing
  DCHECK_EQ(stream.Peek().FunctionId(), CSSValueID::kLinear);
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    Vector<cssvalue::CSSLinearStop> stop_list{};
    std::optional<cssvalue::CSSLinearStop> linear_stop;
    do {
      linear_stop = ConsumeLinearStop(stream, context);
      if (!linear_stop.has_value()) {
        return nullptr;
      }
      stop_list.emplace_back(linear_stop.value());
    } while (ConsumeCommaIncludingWhitespace(stream));
    if (!stream.AtEnd()) {
      return nullptr;
    }
    // 1. Let function be a new linear easing function.
    // 2. Let largestInput be negative infinity.
    // 3. If there are less than two items in stopList, then return failure.
    if (stop_list.size() < 2) {
      return nullptr;
    }
    // 4. For each stop in stopList:
    double largest_input = std::numeric_limits<double>::lowest();
    Vector<gfx::LinearEasingPoint> points{};
    for (wtf_size_t i = 0; i < stop_list.size(); ++i) {
      const auto& stop = stop_list[i];
      // 4.1. Let point be a new linear easing point with its output set
      // to stop’s <number> as a number.
      gfx::LinearEasingPoint point{std::numeric_limits<double>::quiet_NaN(),
                                   stop.number};
      // 4.2. Append point to function’s points.
      points.emplace_back(point);
      // 4.3. If stop has a <linear-stop-length>, then:
      if (stop.length_a.has_value()) {
        // 4.3.1. Set point’s input to whichever is greater:
        // stop’s <linear-stop-length>'s first <percentage> as a number,
        // or largestInput.
        points.back().input = std::max(largest_input, stop.length_a.value());
        // 4.3.2. Set largestInput to point’s input.
        largest_input = points.back().input;
        // 4.3.3. If stop’s <linear-stop-length> has a second <percentage>,
        // then:
        if (stop.length_b.has_value()) {
          // 4.3.3.1. Let extraPoint be a new linear easing point with its
          // output set to stop’s <number> as a number.
          gfx::LinearEasingPoint extra_point{
              // 4.3.3.3. Set extraPoint’s input to whichever is greater:
              // stop’s <linear-stop-length>'s second <percentage>
              // as a number, or largestInput.
              std::max(largest_input, stop.length_b.value()), stop.number};
          // 4.3.3.2. Append extraPoint to function’s points.
          points.emplace_back(extra_point);
          // 4.3.3.4. Set largestInput to extraPoint’s input.
          largest_input = extra_point.input;
        }
        // 4.4. Otherwise, if stop is the first item in stopList, then:
      } else if (i == 0) {
        // 4.4.1. Set point’s input to 0.
        points.back().input = 0;
        // 4.4.2. Set largestInput to 0.
        largest_input = 0;
        // 4.5. Otherwise, if stop is the last item in stopList,
        // then set point’s input to whichever is greater: 1 or largestInput.
      } else if (i == stop_list.size() - 1) {
        points.back().input = std::max(100., largest_input);
      }
    }
    // 5. For runs of items in function’s points that have a null input, assign
    // a number to the input by linearly interpolating between the closest
    // previous and next points that have a non-null input.
    wtf_size_t upper_index = 0;
    for (wtf_size_t i = 1; i < points.size(); ++i) {
      if (std::isnan(points[i].input)) {
        if (i > upper_index) {
          const auto it = std::find_if(
              std::next(points.begin(), i + 1), points.end(),
              [](const auto& point) { return !std::isnan(point.input); });
          upper_index = static_cast<wtf_size_t>(it - points.begin());
        }
        points[i].input = points[i - 1].input +
                          (points[upper_index].input - points[i - 1].input) /
                              (upper_index - (i - 1));
      }
    }
    guard.Release();
    result = MakeGarbageCollected<cssvalue::CSSLinearTimingFunctionValue>(
        std::move(points));
  }
  stream.ConsumeWhitespace();

  context.Count(WebFeature::kCSSLinearEasing);

  // 6. Return function.
  return result;
}

CSSValue* ConsumeSteps(CSSParserTokenStream& stream,
                       const CSSParserContext& context) {
  CSSValue* result;

  DCHECK_EQ(stream.Peek().FunctionId(), CSSValueID::kSteps);
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();

    CSSPrimitiveValue* steps = ConsumePositiveInteger(stream, context);
    if (!steps) {
      return nullptr;
    }

    StepsTimingFunction::StepPosition position =
        StepsTimingFunction::StepPosition::END;
    if (ConsumeCommaIncludingWhitespace(stream)) {
      switch (stream.Peek().Id()) {
        case CSSValueID::kStart:
          position = StepsTimingFunction::StepPosition::START;
          break;

        case CSSValueID::kEnd:
          position = StepsTimingFunction::StepPosition::END;
          break;

        case CSSValueID::kJumpBoth:
          position = StepsTimingFunction::StepPosition::JUMP_BOTH;
          break;

        case CSSValueID::kJumpEnd:
          position = StepsTimingFunction::StepPosition::JUMP_END;
          break;

        case CSSValueID::kJumpNone:
          position = StepsTimingFunction::StepPosition::JUMP_NONE;
          break;

        case CSSValueID::kJumpStart:
          position = StepsTimingFunction::StepPosition::JUMP_START;
          break;

        default:
          return nullptr;
      }
      stream.ConsumeIncludingWhitespace();  // kIdentToken
    }

    if (!stream.AtEnd()) {
      return nullptr;
    }

    // Steps(n, jump-none) requires n >= 2.
    if (position == StepsTimingFunction::StepPosition::JUMP_NONE &&
        steps->GetIntValue() < 2) {
      return nullptr;
    }

    guard.Release();
    result = MakeGarbageCollected<cssvalue::CSSStepsTimingFunctionValue>(
        steps->GetIntValue(), position);
  }
  stream.ConsumeWhitespace();
  return result;
}

CSSValue* ConsumeCubicBezier(CSSParserTokenStream& stream,
                             const CSSParserContext& context) {
  DCHECK_EQ(stream.Peek().FunctionId(), CSSValueID::kCubicBezier);
  CSSValue* result = nullptr;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();

    double x1, y1, x2, y2;
    if (ConsumeNumberRaw(stream, context, x1) && x1 >= 0 && x1 <= 1 &&
        ConsumeCommaIncludingWhitespace(stream) &&
        ConsumeNumberRaw(stream, context, y1) &&
        ConsumeCommaIncludingWhitespace(stream) &&
        ConsumeNumberRaw(stream, context, x2) && x2 >= 0 && x2 <= 1 &&
        ConsumeCommaIncludingWhitespace(stream) &&
        ConsumeNumberRaw(stream, context, y2) && stream.AtEnd()) {
      guard.Release();
      result =
          MakeGarbageCollected<cssvalue::CSSCubicBezierTimingFunctionValue>(
              x1, y1, x2, y2);
    }
  }
  if (result) {
    stream.ConsumeWhitespace();
  }

  return result;
}

CSSIdentifierValue* ConsumeBorderImageRepeatKeyword(
    CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kStretch, CSSValueID::kRepeat,
                      CSSValueID::kSpace, CSSValueID::kRound>(stream);
}

bool ConsumeCSSValueId(CSSParserTokenStream& stream, CSSValueID& value) {
  CSSIdentifierValue* keyword = ConsumeIdent(stream);
  if (!keyword) {
    return false;
  }
  value = keyword->GetValueID();
  return true;
}

CSSValue* ConsumeShapeRadius(CSSParserTokenStream& args,
                             const CSSParserContext& context) {
  if (IdentMatches<CSSValueID::kClosestSide, CSSValueID::kFarthestSide>(
          args.Peek().Id())) {
    return ConsumeIdent(args);
  }
  return ConsumeLengthOrPercent(args, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative);
}

cssvalue::CSSBasicShapeCircleValue* ConsumeBasicShapeCircle(
    CSSParserTokenStream& args,
    const CSSParserContext& context) {
  // spec: https://drafts.csswg.org/css-shapes/#supported-basic-shapes
  // circle( [<shape-radius>]? [at <position>]? )
  auto* shape = MakeGarbageCollected<cssvalue::CSSBasicShapeCircleValue>();
  if (CSSValue* radius = ConsumeShapeRadius(args, context)) {
    shape->SetRadius(radius);
  }
  if (ConsumeIdent<CSSValueID::kAt>(args)) {
    CSSValue* center_x = nullptr;
    CSSValue* center_y = nullptr;
    if (!ConsumePosition(args, context, UnitlessQuirk::kForbid,
                         std::optional<WebFeature>(), center_x, center_y)) {
      return nullptr;
    }
    shape->SetCenterX(center_x);
    shape->SetCenterY(center_y);
  }
  return shape;
}

cssvalue::CSSBasicShapeEllipseValue* ConsumeBasicShapeEllipse(
    CSSParserTokenStream& args,
    const CSSParserContext& context) {
  // spec: https://drafts.csswg.org/css-shapes/#supported-basic-shapes
  // ellipse( [<shape-radius>{2}]? [at <position>]? )
  auto* shape = MakeGarbageCollected<cssvalue::CSSBasicShapeEllipseValue>();
  WebFeature feature = WebFeature::kBasicShapeEllipseNoRadius;
  if (CSSValue* radius_x = ConsumeShapeRadius(args, context)) {
    CSSValue* radius_y = ConsumeShapeRadius(args, context);
    if (!radius_y) {
      return nullptr;
    }
    shape->SetRadiusX(radius_x);
    shape->SetRadiusY(radius_y);
    feature = WebFeature::kBasicShapeEllipseTwoRadius;
  }
  if (ConsumeIdent<CSSValueID::kAt>(args)) {
    CSSValue* center_x = nullptr;
    CSSValue* center_y = nullptr;
    if (!ConsumePosition(args, context, UnitlessQuirk::kForbid,
                         std::optional<WebFeature>(), center_x, center_y)) {
      return nullptr;
    }
    shape->SetCenterX(center_x);
    shape->SetCenterY(center_y);
  }
  context.Count(feature);
  return shape;
}

cssvalue::CSSBasicShapePolygonValue* ConsumeBasicShapePolygon(
    CSSParserTokenStream& args,
    const CSSParserContext& context) {
  auto* shape = MakeGarbageCollected<cssvalue::CSSBasicShapePolygonValue>();
  if (IdentMatches<CSSValueID::kEvenodd, CSSValueID::kNonzero>(
          args.Peek().Id())) {
    shape->SetWindRule(args.ConsumeIncludingWhitespace().Id() ==
                               CSSValueID::kEvenodd
                           ? RULE_EVENODD
                           : RULE_NONZERO);
    if (!ConsumeCommaIncludingWhitespace(args)) {
      return nullptr;
    }
  }

  do {
    CSSPrimitiveValue* x_length = ConsumeLengthOrPercent(
        args, context, CSSPrimitiveValue::ValueRange::kAll);
    if (!x_length) {
      return nullptr;
    }
    CSSPrimitiveValue* y_length = ConsumeLengthOrPercent(
        args, context, CSSPrimitiveValue::ValueRange::kAll);
    if (!y_length) {
      return nullptr;
    }
    shape->AppendPoint(x_length, y_length);
  } while (ConsumeCommaIncludingWhitespace(args));
  return shape;
}

template <class U>
bool ConsumeBorderRadiusCommon(CSSParserTokenStream& args,
                               const CSSParserContext& context,
                               U* shape) {
  if (ConsumeIdent<CSSValueID::kRound>(args)) {
    std::array<CSSValue*, 4> horizontal_radii = {nullptr};
    std::array<CSSValue*, 4> vertical_radii = {nullptr};
    if (!ConsumeRadii(horizontal_radii, vertical_radii, args, context, false)) {
      return false;
    }
    shape->SetTopLeftRadius(MakeGarbageCollected<CSSValuePair>(
        horizontal_radii[0], vertical_radii[0],
        CSSValuePair::kDropIdenticalValues));
    shape->SetTopRightRadius(MakeGarbageCollected<CSSValuePair>(
        horizontal_radii[1], vertical_radii[1],
        CSSValuePair::kDropIdenticalValues));
    shape->SetBottomRightRadius(MakeGarbageCollected<CSSValuePair>(
        horizontal_radii[2], vertical_radii[2],
        CSSValuePair::kDropIdenticalValues));
    shape->SetBottomLeftRadius(MakeGarbageCollected<CSSValuePair>(
        horizontal_radii[3], vertical_radii[3],
        CSSValuePair::kDropIdenticalValues));
  }
  return true;
}

cssvalue::CSSBasicShapeInsetValue* ConsumeBasicShapeInset(
    CSSParserTokenStream& args,
    const CSSParserContext& context) {
  auto* shape = MakeGarbageCollected<cssvalue::CSSBasicShapeInsetValue>();
  CSSPrimitiveValue* top = ConsumeLengthOrPercent(
      args, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!top) {
    return nullptr;
  }
  CSSPrimitiveValue* right = ConsumeLengthOrPercent(
      args, context, CSSPrimitiveValue::ValueRange::kAll);
  CSSPrimitiveValue* bottom = nullptr;
  CSSPrimitiveValue* left = nullptr;
  if (right) {
    bottom = ConsumeLengthOrPercent(args, context,
                                    CSSPrimitiveValue::ValueRange::kAll);
    if (bottom) {
      left = ConsumeLengthOrPercent(args, context,
                                    CSSPrimitiveValue::ValueRange::kAll);
    }
  }
  if (left) {
    shape->UpdateShapeSize4Values(top, right, bottom, left);
  } else if (bottom) {
    shape->UpdateShapeSize3Values(top, right, bottom);
  } else if (right) {
    shape->UpdateShapeSize2Values(top, right);
  } else {
    shape->UpdateShapeSize1Value(top);
  }

  if (!ConsumeBorderRadiusCommon(args, context, shape)) {
    return nullptr;
  }

  return shape;
}

cssvalue::CSSBasicShapeRectValue* ConsumeBasicShapeRect(
    CSSParserTokenStream& args,
    const CSSParserContext& context) {
  CSSValue* lengths[4];
  for (auto*& length : lengths) {
    length = ConsumeLengthOrPercent(args, context,
                                    CSSPrimitiveValue::ValueRange::kAll);
    if (length) {
      continue;
    }

    if (args.Peek().Id() == CSSValueID::kAuto) {
      length = css_parsing_utils::ConsumeIdent(args);
    }

    if (!length) {
      return nullptr;
    }
  }

  auto* shape = MakeGarbageCollected<cssvalue::CSSBasicShapeRectValue>(
      lengths[0], lengths[1], lengths[2], lengths[3]);

  if (!ConsumeBorderRadiusCommon(args, context, shape)) {
    return nullptr;
  }

  return shape;
}

cssvalue::CSSBasicShapeXYWHValue* ConsumeBasicShapeXYWH(
    CSSParserTokenStream& args,
    const CSSParserContext& context) {
  std::array<CSSPrimitiveValue*, 4> lengths;
  for (size_t i = 0; i < 4; i++) {
    // The last 2 values are width/height which must be positive.
    auto value_range = i > 1 ? CSSPrimitiveValue::ValueRange::kNonNegative
                             : CSSPrimitiveValue::ValueRange::kAll;
    lengths[i] = ConsumeLengthOrPercent(args, context, value_range);
    if (!lengths[i]) {
      return nullptr;
    }
  }

  auto* shape = MakeGarbageCollected<cssvalue::CSSBasicShapeXYWHValue>(
      lengths[0], lengths[1], lengths[2], lengths[3]);

  if (!ConsumeBorderRadiusCommon(args, context, shape)) {
    return nullptr;
  }

  return shape;
}

bool ConsumeNumbers(CSSParserTokenStream& stream,
                    const CSSParserContext& context,
                    CSSFunctionValue*& transform_value,
                    unsigned number_of_arguments) {
  do {
    CSSValue* parsed_value =
        ConsumeNumber(stream, context, CSSPrimitiveValue::ValueRange::kAll);
    if (!parsed_value) {
      return false;
    }
    transform_value->Append(*parsed_value);
    if (--number_of_arguments && !ConsumeCommaIncludingWhitespace(stream)) {
      return false;
    }
  } while (number_of_arguments);
  return true;
}

bool ConsumeNumbersOrPercents(CSSParserTokenStream& stream,
                              const CSSParserContext& context,
                              CSSFunctionValue*& transform_value,
                              unsigned number_of_arguments) {
  do {
    CSSValue* parsed_value = ConsumeNumberOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kAll);
    if (!parsed_value) {
      return false;
    }
    transform_value->Append(*parsed_value);
    if (--number_of_arguments && !ConsumeCommaIncludingWhitespace(stream)) {
      return false;
    }
  } while (number_of_arguments);
  return true;
}

bool ConsumePerspective(CSSParserTokenStream& stream,
                        const CSSParserContext& context,
                        CSSFunctionValue*& transform_value,
                        bool use_legacy_parsing) {
  CSSValue* parsed_value = ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  if (!parsed_value) {
    parsed_value = ConsumeIdent<CSSValueID::kNone>(stream);
  }
  if (!parsed_value && use_legacy_parsing) {
    double perspective;
    if (!ConsumeNumberRaw(stream, context, perspective) || perspective < 0) {
      return false;
    }
    context.Count(WebFeature::kUnitlessPerspectiveInTransformProperty);
    parsed_value = CSSNumericLiteralValue::Create(
        perspective, CSSPrimitiveValue::UnitType::kPixels);
  }
  if (!parsed_value) {
    return false;
  }
  transform_value->Append(*parsed_value);
  return true;
}

bool ConsumeTranslate3d(CSSParserTokenStream& stream,
                        const CSSParserContext& context,
                        CSSFunctionValue*& transform_value) {
  unsigned number_of_arguments = 2;
  CSSValue* parsed_value = nullptr;
  do {
    parsed_value = ConsumeLengthOrPercent(stream, context,
                                          CSSPrimitiveValue::ValueRange::kAll);
    if (!parsed_value) {
      return false;
    }
    transform_value->Append(*parsed_value);
    if (!ConsumeCommaIncludingWhitespace(stream)) {
      return false;
    }
  } while (--number_of_arguments);
  parsed_value =
      ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!parsed_value) {
    return false;
  }
  transform_value->Append(*parsed_value);
  return true;
}

CSSFunctionValue* ConsumeFilterFunction(CSSParserTokenStream& stream,
                                        const CSSParserContext& context) {
  CSSValueID filter_type = stream.Peek().FunctionId();
  if (filter_type < CSSValueID::kInvert ||
      filter_type > CSSValueID::kDropShadow) {
    return nullptr;
  }

  CSSFunctionValue* filter_value;
  CSSValue* parsed_value = nullptr;
  bool no_arguments = false;
  {
    CSSParserTokenStream::BlockGuard guard(stream);
    stream.ConsumeWhitespace();
    filter_value = MakeGarbageCollected<CSSFunctionValue>(filter_type);

    if (filter_type == CSSValueID::kDropShadow) {
      parsed_value =
          ParseSingleShadow(stream, context, AllowInsetAndSpread::kForbid);
    } else {
      if (stream.AtEnd()) {
        context.Count(WebFeature::kCSSFilterFunctionNoArguments);
        no_arguments = true;
      } else if (filter_type == CSSValueID::kBrightness) {
        // FIXME (crbug.com/397061): Support calc expressions like
        // calc(10% + 0.5)
        parsed_value = ConsumePercent(stream, context,
                                      CSSPrimitiveValue::ValueRange::kAll);
        if (!parsed_value) {
          parsed_value = ConsumeNumber(
              stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
        }
      } else if (filter_type == CSSValueID::kHueRotate) {
        parsed_value =
            ConsumeAngle(stream, context, WebFeature::kUnitlessZeroAngleFilter);
      } else if (filter_type == CSSValueID::kBlur) {
        CSSParserContext::ParserModeOverridingScope scope(context,
                                                          kHTMLStandardMode);
        parsed_value = ConsumeLength(
            stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
      } else {
        // FIXME (crbug.com/397061): Support calc expressions like
        // calc(10% + 0.5)
        parsed_value = ConsumePercent(
            stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
        if (!parsed_value) {
          parsed_value = ConsumeNumber(
              stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
        }
        // NOTE: calc() values should not be attempted evaluated parse-time,
        // and will be clamped in
        // FilterOperationResolver::ResolveNumericArgumentForFunction() instead,
        // when we can resolve e.g. length units.
        if (parsed_value &&
            !To<CSSPrimitiveValue>(parsed_value)->IsCalculated() &&
            filter_type != CSSValueID::kSaturate &&
            filter_type != CSSValueID::kContrast) {
          bool is_percentage =
              To<CSSPrimitiveValue>(parsed_value)->IsPercentage();
          double max_allowed = is_percentage ? 100.0 : 1.0;
          if (To<CSSPrimitiveValue>(parsed_value)->GetDoubleValue() >
              max_allowed) {
            parsed_value = CSSNumericLiteralValue::Create(
                max_allowed, is_percentage
                                 ? CSSPrimitiveValue::UnitType::kPercentage
                                 : CSSPrimitiveValue::UnitType::kNumber);
          }
        }
      }
    }
    if (!no_arguments && (!parsed_value || !stream.AtEnd())) {
      return nullptr;
    }
  }
  stream.ConsumeWhitespace();
  if (parsed_value) {
    filter_value->Append(*parsed_value);
  }
  return filter_value;
}

template <typename Func>
CSSLightDarkValuePair* ConsumeLightDark(Func consume_value,
                                        CSSParserTokenStream& stream,
                                        const CSSParserContext& context) {
  if (stream.Peek().FunctionId() != CSSValueID::kLightDark) {
    return nullptr;
  }
  if (!IsUASheetBehavior(context.Mode())) {
    context.Count(WebFeature::kCSSLightDark);
  }

  CSSValue* light_value;
  CSSValue* dark_value;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    light_value = consume_value(stream, context);
    if (!light_value || !ConsumeCommaIncludingWhitespace(stream)) {
      return nullptr;
    }
    dark_value = consume_value(stream, context);
    if (!dark_value || !stream.AtEnd()) {
      return nullptr;
    }
    guard.Release();
  }
  stream.ConsumeWhitespace();
  return MakeGarbageCollected<CSSLightDarkValuePair>(light_value, dark_value);
}

// https://drafts.csswg.org/css-syntax/#typedef-any-value
bool IsTokenAllowedForAnyValue(const CSSParserToken& token) {
  switch (token.GetType()) {
    case kBadStringToken:
    case kEOFToken:
    case kBadUrlToken:
      return false;
    case kRightParenthesisToken:
    case kRightBracketToken:
    case kRightBraceToken:
      return token.GetBlockType() == CSSParserToken::kBlockEnd;
    default:
      return true;
  }
}

bool IsGeneratedImage(const CSSValueID id) {
  switch (id) {
    case CSSValueID::kLinearGradient:
    case CSSValueID::kRadialGradient:
    case CSSValueID::kConicGradient:
    case CSSValueID::kRepeatingLinearGradient:
    case CSSValueID::kRepeatingRadialGradient:
    case CSSValueID::kRepeatingConicGradient:
    case CSSValueID::kWebkitLinearGradient:
    case CSSValueID::kWebkitRadialGradient:
    case CSSValueID::kWebkitRepeatingLinearGradient:
    case CSSValueID::kWebkitRepeatingRadialGradient:
    case CSSValueID::
"""


```